//! Long-lived, durable validity prover for the production block-producer journal.
//!
//! The expensive block-chain, Falcon aggregation, aggregate-list and validity circuits are built
//! exactly once when this service is opened and then retained for the process lifetime. A
//! candidate proof never advances the finalized cursor: only an explicit L1 acknowledgement can
//! atomically promote it. Both cursors are bound to a semantically replayed producer-journal
//! generation, entry hash and extended-state commitment.

#![cfg(not(target_arch = "wasm32"))]

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd as _,
        unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use plonky2::{
    field::types::PrimeField64 as _,
    plonk::{circuit_data::VerifierCircuitData, proof::ProofWithPublicInputs},
};
use plonky2_keccak::utils::solidity_keccak256;
use serde::{Deserialize, Serialize};

use crate::{
    block_producer::ProductionBlockProducer,
    block_producer_service::{
        BlockProducerAnchor, BlockProducerReceipt, BlockProducerService, BlockProducerServiceError,
    },
    circuits::validity::block_hash_chain::{
        block_chain_pis::BlockChainPublicInputs,
        block_hash_chain_processor::BlockHashChainProcessor,
        ext_public_state::ExtendedPublicState,
        validity_circuit::{ValidityCircuit, ValidityPublicInputs},
    },
    common::u63::BlockNumber,
    ethereum_types::{
        address::Address,
        bytes32::{BYTES32_LEN, Bytes32},
        u32limb_trait::U32LimbTrait as _,
    },
    falcon_sig::{
        agg::{FalconAggCircuit, FalconAggWitness},
        agg_list::{AggListCircuit, agg_list_commitment},
    },
    l1_finality::{ANVIL_CHAIN_ID, L1FinalitySource, L1FinalizedCheckpoint},
    utils::{
        mle_prover::{export_mle_json, prove_with_mle, setup_mle_vk, verify_mle_proof},
        poseidon_hash_out::PoseidonHashOut,
        wrapper::WrapperCircuit,
    },
    wallet_core::{C, D, F},
};

const SNAPSHOT_MAGIC: &[u8; 16] = b"IMVALIDITYPROV03";
pub const VALIDITY_PROVER_SNAPSHOT_VERSION: u32 = 3;
const SNAPSHOT_HEADER_BYTES: usize = 16 + 4 + 8 + 32;
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_ACK_HISTORY: usize = 1_000_000;

type ValidityProof = ProofWithPublicInputs<F, C, D>;

#[derive(Debug, thiserror::Error)]
pub enum ValidityProverServiceError {
    #[error("invalid validity-prover configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid validity-prover request: {0}")]
    InvalidRequest(String),
    #[error("validity-prover request conflict: {0}")]
    Conflict(String),
    #[error("producer reconciliation failed: {0}")]
    ProducerReconciliation(String),
    #[error("validity proving failed: {0}")]
    Proving(String),
    #[error("validity snapshot verification failed: {0}")]
    Snapshot(String),
    #[error("validity snapshot is locked by another prover: {0}")]
    Locked(String),
    #[error("service is fail-closed after an uncertain persistence result; restart required")]
    Poisoned,
}

impl ValidityProverServiceError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfiguration(_) => "validity_invalid_configuration",
            Self::InvalidRequest(_) => "validity_invalid_request",
            Self::Conflict(_) => "validity_conflict",
            Self::ProducerReconciliation(_) => "validity_reconciliation_failed",
            Self::Proving(_) => "validity_proving_failed",
            Self::Snapshot(_) => "validity_snapshot_error",
            Self::Locked(_) => "validity_snapshot_locked",
            Self::Poisoned => "validity_service_poisoned",
        }
    }
}

impl From<BlockProducerServiceError> for ValidityProverServiceError {
    fn from(value: BlockProducerServiceError) -> Self {
        Self::ProducerReconciliation(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct L1ValidityAcknowledgement {
    pub chain_id: u64,
    pub transaction_hash: Bytes32,
    pub block_hash: Bytes32,
    pub block_number: u64,
    pub final_extended_state_commitment: Bytes32,
    pub finalized_checkpoint: L1FinalizedCheckpoint,
}

/// Immutable identity of the L1 contract whose finalized state is accepted by this prover.
///
/// Address and chain binding alone are insufficient for a release deployment: a mistaken or
/// substituted contract can expose the expected getters and events while implementing different
/// authorization semantics. The runtime-code hash is therefore process configuration and is
/// durably copied into snapshot v3 before any command is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct L1ValidityDeploymentBinding {
    pub chain_id: u64,
    pub rollup: Address,
    pub rollup_runtime_code_hash: Bytes32,
}

impl L1ValidityDeploymentBinding {
    fn validate(&self) -> Result<(), ValidityProverServiceError> {
        if self.chain_id == 0
            || self.rollup == Address::default()
            || self.rollup_runtime_code_hash == Bytes32::default()
        {
            return Err(ValidityProverServiceError::InvalidConfiguration(
                "L1 deployment binding requires a nonzero chain, rollup and runtime-code hash"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Operator-owned L1 read configuration. It is process configuration, never accepted from a
/// per-request JSON command, so a remote caller cannot substitute an RPC endpoint or rollup.
#[derive(Clone, Debug)]
pub struct L1FinalizationRpcConfig {
    pub rpc_url: String,
    pub expected_chain_id: u64,
    pub rollup: Address,
    /// Keccak-256 of the exact deployed rollup runtime bytecode. This is intentionally supplied
    /// out of band rather than learned from the same RPC whose state it authenticates.
    pub expected_rollup_runtime_code_hash: Bytes32,
    pub minimum_confirmations: u64,
    /// Explicit local-test escape. Production always requires the RPC `finalized` tag; this may
    /// select `latest` only when `expected_chain_id == 31337`.
    pub allow_unfinalized_devnet: bool,
}

impl L1FinalizationRpcConfig {
    pub fn validate(&self) -> Result<(), ValidityProverServiceError> {
        if self.rpc_url.trim().is_empty() {
            return Err(ValidityProverServiceError::InvalidConfiguration(
                "L1 RPC URL must not be empty".into(),
            ));
        }
        if self.rollup == Address::default() {
            return Err(ValidityProverServiceError::InvalidConfiguration(
                "L1 rollup address must be nonzero".into(),
            ));
        }
        if self.expected_rollup_runtime_code_hash == Bytes32::default() {
            return Err(ValidityProverServiceError::InvalidConfiguration(
                "expected L1 rollup runtime-code hash must be nonzero".into(),
            ));
        }
        if self.expected_chain_id == 0 {
            return Err(ValidityProverServiceError::InvalidConfiguration(
                "expected L1 chain id must be nonzero".into(),
            ));
        }
        if self.minimum_confirmations == 0 {
            return Err(ValidityProverServiceError::InvalidConfiguration(
                "minimum L1 confirmations must be at least one".into(),
            ));
        }
        if self.allow_unfinalized_devnet && self.expected_chain_id != ANVIL_CHAIN_ID {
            return Err(ValidityProverServiceError::InvalidConfiguration(format!(
                "unfinalized development mode is restricted to chain {ANVIL_CHAIN_ID}"
            )));
        }
        Ok(())
    }

    fn deployment_binding(&self) -> L1ValidityDeploymentBinding {
        L1ValidityDeploymentBinding {
            chain_id: self.expected_chain_id,
            rollup: self.rollup,
            rollup_runtime_code_hash: self.expected_rollup_runtime_code_hash,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityProofMetrics {
    pub block_count: u64,
    pub appended_signature_event_count: usize,
    pub block_chain_elapsed_ms: u64,
    pub aggregate_list_elapsed_ms: u64,
    pub validity_elapsed_ms: u64,
    pub total_elapsed_ms: u64,
    pub block_chain_proof_bytes: usize,
    pub aggregate_list_proof_bytes: usize,
    pub validity_proof_bytes: usize,
    pub block_chain_public_inputs: usize,
    pub aggregate_list_public_inputs: usize,
    pub validity_public_inputs: usize,
    pub peak_rss_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityCandidateReceipt {
    pub request_id: String,
    pub candidate_id: Bytes32,
    pub producer_anchor: BlockProducerAnchor,
    pub initial_block_number: u64,
    pub final_block_number: u64,
    pub initial_extended_state_commitment: Bytes32,
    pub final_extended_state_commitment: Bytes32,
    pub signature_event_count: usize,
    pub metrics: ValidityProofMetrics,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityFinalizationReceipt {
    pub request_id: String,
    pub candidate_id: Bytes32,
    pub producer_anchor: BlockProducerAnchor,
    pub finalized_block_number: u64,
    pub final_extended_state_commitment: Bytes32,
    /// Exact authoritative producer receipt promoted only after the L1 finalization was proven
    /// canonical and finalized. Downstream live settlement must consume this field verbatim; it
    /// must never fall back to the earlier non-authoritative prepared receipt.
    pub committed_producer_receipt: BlockProducerReceipt,
    pub l1_acknowledgement: L1ValidityAcknowledgement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityCandidateArtifact {
    pub receipt: ValidityCandidateReceipt,
    pub prover: Address,
    pub initial_extended_state: Vec<u64>,
    pub final_extended_state: Vec<u64>,
    pub validity_proof: Vec<u8>,
}

/// Exact public fields for one Rust small block. Solidity derives the two accumulator values from
/// the immutable pending-chain checkpoint selected beside `SubBlock`, so they MUST still travel
/// with the calldata fields. A posting driver must submit the proof-authenticated checkpoint and
/// must never replace it with a newer live pin; later deposits/registrations remain queued for the
/// next proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityPostingSubBlock {
    pub channel_id: u32,
    pub timestamp: u64,
    pub tx_tree_root: Bytes32,
    pub num_users: u32,
    pub key_ids: Vec<u32>,
    pub deposit_hash_chain: Bytes32,
    pub channel_reg_hash_chain: Bytes32,
}

/// Candidate-bound material needed to construct the L1 `SubBlock[]` argument. The proof payload
/// remains in [`ValidityFinalizeArtifact`]; keeping the two views tied to the same candidate id
/// lets an operator encode the large MLE object once without accepting caller-supplied blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityPostingArtifact {
    pub receipt: ValidityCandidateReceipt,
    pub sub_blocks: Vec<ValidityPostingSubBlock>,
    /// `keccak256(abi.encodePacked(finalDepositHashChain, finalChannelRegHashChain))`, naming the
    /// exact immutable `IntmaxRollup` checkpoint authenticated by this candidate. It may differ
    /// from the newer live `pendingChainsPin()`; that is a safe historical prefix, never a reason
    /// to substitute the live value or rebuild this proof.
    pub expected_pending_chains: Bytes32,
}

/// Everything `IntmaxRollup.finalize(id, stateRoot, vpis, mleProof)` needs for the current
/// candidate, produced in the resident prover so the validity circuit stays warm: the wrapped
/// MLE/WHIR proof and the `ValidityPublicInputs` JSON in the exact schema `FixtureLib` /
/// `RunPartialWithdrawalPayout` parse. The final state root the caller finalizes against is
/// `final_ext_commitment`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityFinalizeArtifact {
    pub final_state_root: Bytes32,
    pub vpis_json: String,
    pub validity_mle_json: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityProverStatus {
    pub snapshot_version: u32,
    pub circuit_fingerprint: Bytes32,
    pub circuit_construction_count: u64,
    pub circuit_build_elapsed_ms: u64,
    pub circuit_build_peak_rss_bytes: u64,
    pub prover: Address,
    pub finalized_anchor: BlockProducerAnchor,
    pub finalized_block_number: u64,
    pub finalized_extended_state_commitment: Bytes32,
    pub finalized_signature_event_count: usize,
    pub candidate: Option<ValidityCandidateReceipt>,
    pub acknowledgement_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FinalizedCheckpoint {
    anchor: BlockProducerAnchor,
    extended_state: Vec<u64>,
    signature_event_count: usize,
    aggregate_list_proof: Option<Vec<u8>>,
    last_span_initial_state: Option<Vec<u64>>,
    last_validity_proof: Option<Vec<u8>>,
    acknowledgement: Option<L1ValidityAcknowledgement>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CandidateCheckpoint {
    receipt: ValidityCandidateReceipt,
    initial_extended_state: Vec<u64>,
    final_extended_state: Vec<u64>,
    block_chain_proof: Vec<u8>,
    aggregate_list_proof: Option<Vec<u8>>,
    validity_proof: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcknowledgementRecord {
    request_id: String,
    request_fingerprint: Bytes32,
    candidate_id: Bytes32,
    previous_anchor: BlockProducerAnchor,
    finalized_anchor: BlockProducerAnchor,
    acknowledgement: L1ValidityAcknowledgement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidityProverSnapshot {
    supported_user_counts: Vec<u32>,
    prover: Address,
    circuit_fingerprint: Bytes32,
    /// Canonical L1 authority last checked by the production daemon. A newly initialized genesis
    /// snapshot is bound before the daemon accepts commands; every acknowledged snapshot must
    /// carry this field.
    l1_authority: Option<L1FinalizedCheckpoint>,
    /// Exact deployment identity paired with `l1_authority`. These fields are introduced together
    /// in snapshot v3, so an acknowledged snapshot can never silently inherit process-local
    /// authority after restart.
    l1_binding: Option<L1ValidityDeploymentBinding>,
    finalized: FinalizedCheckpoint,
    candidate: Option<CandidateCheckpoint>,
    acknowledgements: Vec<AcknowledgementRecord>,
}

struct ResidentCircuits {
    block_hash_chain: BlockHashChainProcessor<F, C, D>,
    aggregate: FalconAggCircuit<F, C, D>,
    aggregate_list: AggListCircuit<F, C, D>,
    validity: ValidityCircuit<F, C, D>,
    fingerprint: Bytes32,
}

/// One process owns one snapshot lock and one resident circuit set.
pub struct ValidityProverService {
    snapshot_path: PathBuf,
    _snapshot_lock: SnapshotLock,
    disk: ValidityProverSnapshot,
    circuits: ResidentCircuits,
    circuit_build_elapsed_ms: u64,
    circuit_build_peak_rss_bytes: u64,
    poisoned: bool,
}

impl ValidityProverService {
    /// Initialize a new prover at the producer journal's authenticated generation-zero state.
    pub fn initialize(
        snapshot_path: impl AsRef<Path>,
        supported_user_counts: &[u32],
        prover: Address,
        producer: &BlockProducerService,
    ) -> Result<Self, ValidityProverServiceError> {
        validate_supported_user_counts(supported_user_counts)?;
        let snapshot_path = prepare_snapshot_path(snapshot_path.as_ref())?;
        if snapshot_path.exists() {
            return Err(ValidityProverServiceError::InvalidConfiguration(format!(
                "snapshot {} already exists; use open()",
                snapshot_path.display()
            )));
        }
        let snapshot_lock = SnapshotLock::acquire(&snapshot_path)?;
        let (circuits, circuit_build_elapsed_ms, circuit_build_peak_rss_bytes) =
            build_resident_circuits(supported_user_counts)?;
        let genesis_anchor = producer.anchor_at_generation(0)?.ok_or_else(|| {
            ValidityProverServiceError::ProducerReconciliation(
                "producer journal has no generation-zero anchor".into(),
            )
        })?;
        let genesis =
            ProductionBlockProducer::new(supported_user_counts).current_extended_public_state();
        if genesis.commitment() != genesis_anchor.extended_state_commitment
            || genesis.inner.block_number.as_u64() != genesis_anchor.block_number
            || genesis.bp_sig_chain != genesis_anchor.bp_sig_chain
        {
            return Err(ValidityProverServiceError::ProducerReconciliation(
                "producer generation-zero anchor disagrees with the configured circuit genesis"
                    .into(),
            ));
        }
        let disk = ValidityProverSnapshot {
            supported_user_counts: supported_user_counts.to_vec(),
            prover,
            circuit_fingerprint: circuits.fingerprint,
            l1_authority: None,
            l1_binding: None,
            finalized: FinalizedCheckpoint {
                anchor: genesis_anchor,
                extended_state: genesis.to_u64_vec(),
                signature_event_count: 0,
                aggregate_list_proof: None,
                last_span_initial_state: None,
                last_validity_proof: None,
                acknowledgement: None,
            },
            candidate: None,
            acknowledgements: Vec::new(),
        };
        validate_snapshot(&disk, &circuits, producer)?;
        persist_snapshot(&snapshot_path, &disk)?;
        Ok(Self {
            snapshot_path,
            _snapshot_lock: snapshot_lock,
            disk,
            circuits,
            circuit_build_elapsed_ms,
            circuit_build_peak_rss_bytes,
            poisoned: false,
        })
    }

    /// Recover a durable checkpoint, verify every stored recursive proof, and reconcile both the
    /// finalized and candidate anchors against the producer's replayed journal.
    pub fn open(
        snapshot_path: impl AsRef<Path>,
        supported_user_counts: &[u32],
        prover: Address,
        producer: &BlockProducerService,
    ) -> Result<Self, ValidityProverServiceError> {
        validate_supported_user_counts(supported_user_counts)?;
        let snapshot_path = prepare_snapshot_path(snapshot_path.as_ref())?;
        if !snapshot_path.exists() {
            return Err(ValidityProverServiceError::InvalidConfiguration(format!(
                "snapshot {} does not exist; use initialize()",
                snapshot_path.display()
            )));
        }
        verify_private_mode(&snapshot_path, "snapshot")?;
        let snapshot_lock = SnapshotLock::acquire(&snapshot_path)?;
        let disk = read_snapshot(&snapshot_path)?;
        if disk.supported_user_counts != supported_user_counts {
            return Err(ValidityProverServiceError::InvalidConfiguration(format!(
                "snapshot circuit arities {:?} differ from requested {:?}",
                disk.supported_user_counts, supported_user_counts
            )));
        }
        if disk.prover != prover {
            return Err(ValidityProverServiceError::InvalidConfiguration(
                "snapshot prover address differs from the configured prover".into(),
            ));
        }
        let (circuits, circuit_build_elapsed_ms, circuit_build_peak_rss_bytes) =
            build_resident_circuits(supported_user_counts)?;
        validate_snapshot(&disk, &circuits, producer)?;
        Ok(Self {
            snapshot_path,
            _snapshot_lock: snapshot_lock,
            disk,
            circuits,
            circuit_build_elapsed_ms,
            circuit_build_peak_rss_bytes,
            poisoned: false,
        })
    }

    pub fn status(&self) -> Result<ValidityProverStatus, ValidityProverServiceError> {
        self.ensure_healthy()?;
        let finalized = decode_extended_state(&self.disk.finalized.extended_state)?;
        Ok(ValidityProverStatus {
            snapshot_version: VALIDITY_PROVER_SNAPSHOT_VERSION,
            circuit_fingerprint: self.disk.circuit_fingerprint,
            circuit_construction_count: 1,
            circuit_build_elapsed_ms: self.circuit_build_elapsed_ms,
            circuit_build_peak_rss_bytes: self.circuit_build_peak_rss_bytes,
            prover: self.disk.prover,
            finalized_anchor: self.disk.finalized.anchor.clone(),
            finalized_block_number: finalized.inner.block_number.as_u64(),
            finalized_extended_state_commitment: finalized.commitment(),
            finalized_signature_event_count: self.disk.finalized.signature_event_count,
            candidate: self
                .disk
                .candidate
                .as_ref()
                .map(|candidate| candidate.receipt.clone()),
            acknowledgement_count: self.disk.acknowledgements.len(),
        })
    }

    /// Re-run proof and producer-anchor reconciliation without mutating either service.
    pub fn reconcile(
        &self,
        producer: &BlockProducerService,
    ) -> Result<(), ValidityProverServiceError> {
        self.ensure_healthy()?;
        validate_snapshot(&self.disk, &self.circuits, producer)
    }

    /// Bind a fresh snapshot to L1, or revalidate the persisted authority before the daemon accepts
    /// commands.  Internal proof consistency is necessary but not sufficient after a restart: an
    /// old local snapshot must not become the fund-state authority when L1 finalized a different
    /// state, and a stored receipt must not survive an RPC-side canonical replacement.
    pub fn bind_or_revalidate_l1_authority(
        &mut self,
        l1: &L1FinalizationRpcConfig,
    ) -> Result<(), ValidityProverServiceError> {
        self.ensure_healthy()?;
        l1.validate()?;
        let expected_binding = l1.deployment_binding();
        expected_binding.validate()?;
        if let Some(stored) = self.disk.l1_binding {
            if stored != expected_binding {
                return Err(ValidityProverServiceError::InvalidConfiguration(format!(
                    "snapshot L1 deployment binding {stored:?} differs from configured {expected_binding:?}"
                )));
            }
        } else if self.disk.l1_authority.is_some()
            || !self.disk.acknowledgements.is_empty()
            || self.disk.finalized.acknowledgement.is_some()
        {
            return Err(ValidityProverServiceError::Snapshot(
                "L1-bound validity snapshot has no durable deployment identity".into(),
            ));
        }

        let current = read_l1_authority_checkpoint(l1)?;
        if let Some(stored) = self.disk.l1_authority {
            validate_stored_l1_checkpoint(l1, &stored, &current)?;
        } else if !self.disk.acknowledgements.is_empty()
            || self.disk.finalized.acknowledgement.is_some()
        {
            return Err(ValidityProverServiceError::Snapshot(
                "acknowledged validity snapshot has no durable L1 authority".into(),
            ));
        }

        // This check is deliberately unconditional. A fresh snapshot has no receipt yet, but it
        // is still untrusted local disk state: another prover may already have advanced the
        // rollup. Bind the local finalized cursor/root to the rollup at a stable finalized block
        // before this daemon accepts even its first command. There is one deliberately narrow
        // crash-recovery state: L1 may already expose the exact durable pending candidate as its
        // latest root. This only permits startup; it does not promote local state. The normal ACK
        // command must still prove the exact transaction receipt, event, canonicality and
        // finality before either the producer or validity snapshot advances.
        let finalized = decode_extended_state(&self.disk.finalized.extended_state)?;
        let pending_l1_candidate =
            self.disk
                .candidate
                .as_ref()
                .map(|candidate| PendingL1Candidate {
                    root: candidate.receipt.final_extended_state_commitment,
                    intmax_block: candidate.receipt.final_block_number,
                });
        let locally_bound = verify_local_finalized_state_at_l1(
            l1,
            &current,
            finalized.commitment(),
            finalized.inner.block_number.as_u64(),
            pending_l1_candidate,
        )?;

        let next_authority =
            if let Some(acknowledgement) = self.disk.finalized.acknowledgement.as_ref() {
                let reread = revalidate_historical_l1_finalization(
                    l1,
                    acknowledgement.transaction_hash,
                    acknowledgement.final_extended_state_commitment,
                    finalized.inner.block_number.as_u64(),
                )?;
                if reread.chain_id != acknowledgement.chain_id
                    || reread.transaction_hash != acknowledgement.transaction_hash
                    || reread.block_number != acknowledgement.block_number
                    || reread.block_hash != acknowledgement.block_hash
                    || reread.final_extended_state_commitment
                        != acknowledgement.final_extended_state_commitment
                {
                    return Err(l1_rejected(
                        "persisted finalization receipt changed or was orphaned after restart",
                    ));
                }
                validate_stored_l1_checkpoint(l1, &locally_bound, &reread.finalized_checkpoint)?;
                validate_checkpoint_progression(&locally_bound, &reread.finalized_checkpoint)?;
                reread.finalized_checkpoint
            } else {
                locally_bound
            };

        if self.disk.l1_authority == Some(next_authority)
            && self.disk.l1_binding == Some(expected_binding)
        {
            return Ok(());
        }
        let mut next_disk = self.disk.clone();
        next_disk.l1_authority = Some(next_authority);
        next_disk.l1_binding = Some(expected_binding);
        if let Err(error) = persist_snapshot(&self.snapshot_path, &next_disk) {
            self.poisoned = true;
            return Err(error);
        }
        self.disk = next_disk;
        Ok(())
    }

    /// Prove every producer block after the L1-finalized cursor up to the current journal head.
    /// Retrying the same request id returns the already durable candidate without rebuilding or
    /// reproving anything.
    pub fn prove_candidate(
        &mut self,
        request_id: String,
        producer: &BlockProducerService,
    ) -> Result<ValidityCandidateReceipt, ValidityProverServiceError> {
        self.ensure_healthy()?;
        validate_request_id(&request_id)?;
        if let Some(existing) = &self.disk.candidate {
            if existing.receipt.request_id == request_id {
                candidate_producer_for_anchor(producer, &existing.receipt.producer_anchor)?;
                return Ok(existing.receipt.clone());
            }
            return Err(ValidityProverServiceError::Conflict(format!(
                "candidate request {:?} is pending L1 acknowledgement",
                existing.receipt.request_id
            )));
        }

        verify_anchor(producer, &self.disk.finalized.anchor)?;
        // A terminal close is first persisted as a non-authoritative producer candidate. Prove
        // that exact frozen candidate; never silently fall back to the older authoritative head.
        // Ordinary non-terminal validity batches continue to target the committed head.
        let (target_anchor, target_producer) = producer_proof_target(producer)?;
        let initial_state = decode_extended_state(&self.disk.finalized.extended_state)?;
        let final_state = target_producer.current_extended_public_state();
        if final_state.commitment() != target_anchor.extended_state_commitment
            || final_state.inner.block_number.as_u64() != target_anchor.block_number
            || final_state.bp_sig_chain != target_anchor.bp_sig_chain
        {
            return Err(ValidityProverServiceError::ProducerReconciliation(
                "producer current witness state disagrees with its journal anchor".into(),
            ));
        }
        let initial_block = initial_state.inner.block_number.as_u64();
        let final_block = final_state.inner.block_number.as_u64();
        if final_block <= initial_block {
            return Err(ValidityProverServiceError::InvalidRequest(format!(
                "producer block {final_block} has not advanced past finalized block {initial_block}"
            )));
        }
        if target_anchor.generation <= self.disk.finalized.anchor.generation {
            return Err(ValidityProverServiceError::ProducerReconciliation(
                "producer target generation does not advance the finalized anchor".into(),
            ));
        }

        verify_event_prefix_core(
            target_producer,
            self.disk.finalized.signature_event_count,
            initial_state.bp_sig_chain,
        )?;

        let total_started = Instant::now();
        let block_started = Instant::now();
        let mut block_chain_proof: Option<ValidityProof> = None;
        for raw_block in initial_block + 1..=final_block {
            let block_number = BlockNumber::new(raw_block).map_err(|e| {
                ValidityProverServiceError::Proving(format!(
                    "invalid producer block number {raw_block}: {e}"
                ))
            })?;
            let witness = target_producer.block_witness(block_number).ok_or_else(|| {
                ValidityProverServiceError::ProducerReconciliation(format!(
                    "producer journal has no witness for block {raw_block}"
                ))
            })?;
            let span_initial = block_chain_proof.is_none().then(|| initial_state.clone());
            block_chain_proof = Some(
                self.circuits
                    .block_hash_chain
                    .prove_block(span_initial, block_chain_proof, &witness)
                    .map_err(|e| {
                        ValidityProverServiceError::Proving(format!(
                            "block {raw_block} recursive proof: {e}"
                        ))
                    })?,
            );
        }
        let block_chain_proof = block_chain_proof.ok_or_else(|| {
            ValidityProverServiceError::Proving("empty block span reached proving".into())
        })?;
        let block_chain_elapsed_ms = elapsed_ms(block_started);
        let block_pis = parse_block_chain_public_inputs(
            &block_chain_proof,
            &self.circuits.block_hash_chain.block_chain_vd(),
        )?;
        if block_pis.initial_ext_public_state.to_u64_vec() != initial_state.to_u64_vec()
            || block_pis.ext_public_state.to_u64_vec() != final_state.to_u64_vec()
        {
            return Err(ValidityProverServiceError::Proving(
                "block-chain proof does not expose the requested initial/final states".into(),
            ));
        }

        let list_started = Instant::now();
        let events = target_producer.signature_events();
        if self.disk.finalized.signature_event_count > events.len() {
            return Err(ValidityProverServiceError::ProducerReconciliation(
                "finalized signature cursor is ahead of producer history".into(),
            ));
        }
        let mut aggregate_list_proof = decode_optional_proof(
            self.disk.finalized.aggregate_list_proof.as_deref(),
            &self.circuits.aggregate_list.verifier_data(),
            "finalized aggregate-list proof",
        )?;
        let mut running_chain = initial_state.bp_sig_chain;
        for event in &events[self.disk.finalized.signature_event_count..] {
            let aggregate_proof = self
                .circuits
                .aggregate
                .prove(&FalconAggWitness {
                    message: event.digest,
                    active: event.witnesses.clone(),
                })
                .map_err(|e| {
                    ValidityProverServiceError::Proving(format!(
                        "Falcon aggregate proof for event {}: {e}",
                        event.digest
                    ))
                })?;
            aggregate_list_proof = Some(
                self.circuits
                    .aggregate_list
                    .prove_append(&aggregate_proof, running_chain, &aggregate_list_proof)
                    .map_err(|e| {
                        ValidityProverServiceError::Proving(format!(
                            "append aggregate-list event {}: {e}",
                            event.digest
                        ))
                    })?,
            );
            running_chain = aggregate_list_chain(
                aggregate_list_proof
                    .as_ref()
                    .expect("proof was installed above"),
            )?;
        }
        if running_chain != final_state.bp_sig_chain {
            return Err(ValidityProverServiceError::Proving(format!(
                "cumulative aggregate-list chain {running_chain} disagrees with final producer chain {}",
                final_state.bp_sig_chain
            )));
        }
        if final_state.bp_sig_chain == Bytes32::default() && aggregate_list_proof.is_some() {
            return Err(ValidityProverServiceError::Proving(
                "zero final signature chain unexpectedly has an aggregate-list proof".into(),
            ));
        }
        if final_state.bp_sig_chain != Bytes32::default() && aggregate_list_proof.is_none() {
            return Err(ValidityProverServiceError::Proving(
                "nonzero final signature chain has no aggregate-list proof".into(),
            ));
        }
        let aggregate_list_elapsed_ms = elapsed_ms(list_started);

        let validity_started = Instant::now();
        let validity_proof = self
            .circuits
            .validity
            .prove(
                &block_chain_proof,
                aggregate_list_proof.as_ref(),
                self.disk.prover,
            )
            .map_err(|e| ValidityProverServiceError::Proving(e.to_string()))?;
        self.circuits
            .validity
            .verify(&validity_proof)
            .map_err(|e| ValidityProverServiceError::Proving(e.to_string()))?;
        verify_validity_public_hash(
            &validity_proof,
            &initial_state,
            &final_state,
            self.disk.prover,
        )?;
        let validity_elapsed_ms = elapsed_ms(validity_started);

        let block_chain_proof_bytes = block_chain_proof.to_bytes();
        let aggregate_list_proof_bytes =
            aggregate_list_proof.as_ref().map(|proof| proof.to_bytes());
        let validity_proof_bytes = validity_proof.to_bytes();
        let metrics = ValidityProofMetrics {
            block_count: final_block - initial_block,
            appended_signature_event_count: events.len()
                - self.disk.finalized.signature_event_count,
            block_chain_elapsed_ms,
            aggregate_list_elapsed_ms,
            validity_elapsed_ms,
            total_elapsed_ms: elapsed_ms(total_started),
            block_chain_proof_bytes: block_chain_proof_bytes.len(),
            aggregate_list_proof_bytes: aggregate_list_proof_bytes.as_ref().map_or(0, Vec::len),
            validity_proof_bytes: validity_proof_bytes.len(),
            block_chain_public_inputs: block_chain_proof.public_inputs.len(),
            aggregate_list_public_inputs: aggregate_list_proof
                .as_ref()
                .map_or(0, |proof| proof.public_inputs.len()),
            validity_public_inputs: validity_proof.public_inputs.len(),
            peak_rss_bytes: peak_rss_bytes(),
        };
        let mut candidate = CandidateCheckpoint {
            receipt: ValidityCandidateReceipt {
                request_id,
                candidate_id: Bytes32::default(),
                producer_anchor: target_anchor,
                initial_block_number: initial_block,
                final_block_number: final_block,
                initial_extended_state_commitment: initial_state.commitment(),
                final_extended_state_commitment: final_state.commitment(),
                signature_event_count: events.len(),
                metrics,
            },
            initial_extended_state: initial_state.to_u64_vec(),
            final_extended_state: final_state.to_u64_vec(),
            block_chain_proof: block_chain_proof_bytes,
            aggregate_list_proof: aggregate_list_proof_bytes,
            validity_proof: validity_proof_bytes,
        };
        candidate.receipt.candidate_id = candidate_hash(&candidate)?;

        let mut next_disk = self.disk.clone();
        next_disk.candidate = Some(candidate.clone());
        if let Err(error) = persist_snapshot(&self.snapshot_path, &next_disk) {
            self.poisoned = true;
            return Err(error);
        }
        self.disk = next_disk;
        Ok(candidate.receipt)
    }

    pub fn candidate_artifact(
        &self,
    ) -> Result<Option<ValidityCandidateArtifact>, ValidityProverServiceError> {
        self.ensure_healthy()?;
        Ok(self
            .disk
            .candidate
            .as_ref()
            .map(|candidate| ValidityCandidateArtifact {
                receipt: candidate.receipt.clone(),
                prover: self.disk.prover,
                initial_extended_state: candidate.initial_extended_state.clone(),
                final_extended_state: candidate.final_extended_state.clone(),
                validity_proof: candidate.validity_proof.clone(),
            }))
    }

    /// Export only the public block span authenticated by the current durable candidate.
    ///
    /// Reconcile the candidate anchor against the replayed producer on every call. This prevents
    /// an API from pairing a persisted proof with blocks from another journal generation after a
    /// restart or concurrent producer advance. The returned span may contain more than one block
    /// for general tooling; terminal close funding applies a stricter one-block release gate at
    /// the JSONL/API boundary so pending deposit/registration accumulators cannot be misplaced.
    pub fn posting_artifact(
        &self,
        producer: &BlockProducerService,
    ) -> Result<Option<ValidityPostingArtifact>, ValidityProverServiceError> {
        self.ensure_healthy()?;
        let Some(candidate) = self.disk.candidate.as_ref() else {
            return Ok(None);
        };
        let candidate_producer =
            candidate_producer_for_anchor(producer, &candidate.receipt.producer_anchor)?;

        let expected_count = candidate
            .receipt
            .final_block_number
            .checked_sub(candidate.receipt.initial_block_number)
            .ok_or_else(|| {
                ValidityProverServiceError::Snapshot(
                    "candidate final block precedes its initial block".into(),
                )
            })?;
        if expected_count == 0 || expected_count != candidate.receipt.metrics.block_count {
            return Err(ValidityProverServiceError::Snapshot(format!(
                "candidate block span {expected_count} disagrees with proof metric {}",
                candidate.receipt.metrics.block_count
            )));
        }
        let capacity = usize::try_from(expected_count).map_err(|_| {
            ValidityProverServiceError::Snapshot(
                "candidate block span does not fit this platform".into(),
            )
        })?;
        let mut sub_blocks = Vec::with_capacity(capacity);
        for raw in candidate.receipt.initial_block_number + 1..=candidate.receipt.final_block_number
        {
            let block_number = BlockNumber::new(raw).map_err(|e| {
                ValidityProverServiceError::Snapshot(format!(
                    "candidate contains invalid block number {raw}: {e}"
                ))
            })?;
            let block = candidate_producer
                .public_block(block_number)
                .ok_or_else(|| {
                    ValidityProverServiceError::ProducerReconciliation(format!(
                        "producer journal has no public block {raw} for the candidate"
                    ))
                })?;
            if block.key_ids.len() != block.num_users as usize || block.key_ids.is_empty() {
                return Err(ValidityProverServiceError::ProducerReconciliation(format!(
                    "producer block {raw} has {} key ids for arity {}",
                    block.key_ids.len(),
                    block.num_users
                )));
            }
            sub_blocks.push(ValidityPostingSubBlock {
                channel_id: block.channel_id,
                timestamp: block.timestamp,
                tx_tree_root: block.tx_tree_root,
                num_users: block.num_users,
                key_ids: block.key_ids,
                deposit_hash_chain: block.deposit_hash_chain,
                channel_reg_hash_chain: block.channel_reg_hash_chain,
            });
        }
        if sub_blocks.len() != capacity {
            return Err(ValidityProverServiceError::Snapshot(
                "candidate public block export is incomplete".into(),
            ));
        }
        let final_block = sub_blocks.last().ok_or_else(|| {
            ValidityProverServiceError::Snapshot(
                "candidate public block export unexpectedly has no final block".into(),
            )
        })?;
        let mut pending_chain_words = final_block.deposit_hash_chain.to_u32_vec();
        pending_chain_words.extend(final_block.channel_reg_hash_chain.to_u32_vec());
        let expected_pending_chains =
            Bytes32::from_u32_slice(&solidity_keccak256(&pending_chain_words)).map_err(|e| {
                ValidityProverServiceError::Snapshot(format!(
                    "failed to encode candidate pending-chain pin: {e}"
                ))
            })?;
        Ok(Some(ValidityPostingArtifact {
            receipt: candidate.receipt.clone(),
            sub_blocks,
            expected_pending_chains,
        }))
    }

    /// Wrap the current candidate's validity proof for on-chain finalization. Reconstructs the
    /// `ValidityPublicInputs` from the candidate's own committed initial/final extended states
    /// (never re-proving), wraps + MLE/WHIRs the validity proof through the SAME rail the fixture
    /// generator uses, and returns the payload `finalize()` verifies. `final_state_root` is what
    /// `finalizedStateRoots` records — the value a later `withdrawNative` binds through
    /// `WithdrawalExtCommitmentMismatch`.
    pub fn finalize_artifact(
        &self,
    ) -> Result<Option<ValidityFinalizeArtifact>, ValidityProverServiceError> {
        self.ensure_healthy()?;
        let Some(candidate) = self.disk.candidate.as_ref() else {
            return Ok(None);
        };
        let initial = decode_extended_state(&candidate.initial_extended_state)?;
        let final_state = decode_extended_state(&candidate.final_extended_state)?;
        let vpis = ValidityPublicInputs::from_states(&initial, &final_state, self.disk.prover);

        let validity_proof = decode_proof(
            &candidate.validity_proof,
            &self.circuits.validity.data.verifier_data(),
            "validity finalize artifact",
        )?;
        let wrapper =
            WrapperCircuit::<F, C, C, D>::new(&self.circuits.validity.data.verifier_data());
        let wrapped = wrapper.prove(&validity_proof).map_err(|e| {
            ValidityProverServiceError::Proving(format!("wrap validity proof: {e}"))
        })?;
        wrapper.data.verify(wrapped).map_err(|e| {
            ValidityProverServiceError::Proving(format!("verify wrapped validity: {e}"))
        })?;
        let vk = setup_mle_vk::<F, C, D>(&wrapper.data);
        let mut pw = plonky2::iop::witness::PartialWitness::new();
        plonky2::iop::witness::WitnessWrite::set_proof_with_pis_target(
            &mut pw,
            &wrapper.wrap_proof,
            &validity_proof,
        )
        .map_err(|e| ValidityProverServiceError::Proving(format!("mle witness: {e}")))?;
        let mle = prove_with_mle::<F, C, D>(&wrapper.data, pw)
            .map_err(|e| ValidityProverServiceError::Proving(format!("mle prove: {e}")))?;
        verify_mle_proof(&wrapper.data, &vk, &mle.proof)
            .map_err(|e| ValidityProverServiceError::Proving(format!("mle verify: {e}")))?;
        let validity_mle_json = export_mle_json(&mle.proof, &wrapper.data.common)
            .map_err(|e| ValidityProverServiceError::Proving(format!("mle export: {e}")))?;

        let vpis_json = serde_json::to_string_pretty(&serde_json::json!({
            "initial_block_number": vpis.initial_block_number.as_u64(),
            "initial_block_chain": vpis.initial_block_chain.to_string(),
            "initial_ext_commitment": vpis.initial_ext_commitment.to_string(),
            "final_block_number": vpis.final_block_number.as_u64(),
            "final_block_chain": vpis.final_block_chain.to_string(),
            "final_ext_commitment": vpis.final_ext_commitment.to_string(),
            "prover": vpis.prover.to_string(),
        }))
        .map_err(|e| ValidityProverServiceError::Proving(format!("vpis json: {e}")))?;

        Ok(Some(ValidityFinalizeArtifact {
            final_state_root: vpis.final_ext_commitment,
            vpis_json,
            validity_mle_json,
        }))
    }

    /// Verify a finalization receipt against the operator-configured L1 RPC and atomically promote
    /// the candidate. This is the only acknowledgement method a production daemon may expose.
    pub fn acknowledge_candidate_from_l1(
        &mut self,
        request_id: String,
        candidate_id: Bytes32,
        transaction_hash: Bytes32,
        l1: &L1FinalizationRpcConfig,
        producer: &mut BlockProducerService,
    ) -> Result<ValidityFinalizationReceipt, ValidityProverServiceError> {
        self.ensure_healthy()?;
        validate_request_id(&request_id)?;
        // An idempotent acknowledgement is still a production command, not a trusted read from
        // local disk.  Revalidate the persisted finalized receipt, its canonical block, the
        // durable L1 head and the rollup's latest root before returning it.  Without this branch a
        // receipt orphaned while the daemon was running could be replayed forever merely because
        // its request id was already present in the snapshot.
        if let Some(existing) = self
            .disk
            .acknowledgements
            .iter()
            .find(|record| record.request_id == request_id)
            .cloned()
        {
            if existing.candidate_id != candidate_id
                || existing.acknowledgement.transaction_hash != transaction_hash
            {
                return Err(ValidityProverServiceError::Conflict(format!(
                    "acknowledgement request id {request_id:?} was reused for different content"
                )));
            }
            self.bind_or_revalidate_l1_authority(l1)?;
            let reread = verify_l1_finalization(
                l1,
                existing.acknowledgement.transaction_hash,
                existing.acknowledgement.final_extended_state_commitment,
                existing.finalized_anchor.block_number,
            )?;
            validate_replayed_acknowledgement(&existing.acknowledgement, &reread)?;
            validate_stored_l1_checkpoint(
                l1,
                &existing.acknowledgement.finalized_checkpoint,
                &reread.finalized_checkpoint,
            )?;
            validate_checkpoint_progression(
                &existing.acknowledgement.finalized_checkpoint,
                &reread.finalized_checkpoint,
            )?;
            verify_anchor(producer, &existing.finalized_anchor)?;
            let committed_producer_receipt = producer
                .committed_receipt_at_anchor(&existing.finalized_anchor)?
                .ok_or_else(|| {
                    ValidityProverServiceError::ProducerReconciliation(
                        "acknowledged producer anchor has no committed journal receipt".into(),
                    )
                })?;
            return Ok(finalization_receipt(&existing, committed_producer_receipt));
        }
        let candidate = self.disk.candidate.clone().ok_or_else(|| {
            ValidityProverServiceError::InvalidRequest(
                "there is no pending candidate to acknowledge".into(),
            )
        })?;
        if candidate.receipt.candidate_id != candidate_id {
            return Err(ValidityProverServiceError::Conflict(
                "candidate id does not match the pending proof".into(),
            ));
        }
        let acknowledgement = verify_l1_finalization(
            l1,
            transaction_hash,
            candidate.receipt.final_extended_state_commitment,
            candidate.receipt.final_block_number,
        )?;
        let stored_authority = self.disk.l1_authority.as_ref().ok_or_else(|| {
            ValidityProverServiceError::Snapshot(
                "production acknowledgement requires a startup-bound L1 authority".into(),
            )
        })?;
        validate_stored_l1_checkpoint(l1, stored_authority, &acknowledgement.finalized_checkpoint)?;
        validate_checkpoint_progression(stored_authority, &acknowledgement.finalized_checkpoint)?;

        // The close entry remains non-authoritative until this exact L1 result is canonical and
        // finalized. Commit by the proof-bound journal anchor only after every L1 check above.
        // If a crash happened after producer persistence but before the validity snapshot rename,
        // the committed-anchor lookup makes this retry converge without reapplying the close.
        if producer
            .committed_receipt_at_anchor(&candidate.receipt.producer_anchor)?
            .is_none()
        {
            producer.commit_prepared_close_funding_at_anchor(&candidate.receipt.producer_anchor)?;
        }
        self.acknowledge_candidate_unchecked_for_test(
            request_id,
            candidate_id,
            acknowledgement,
            l1.deployment_binding(),
            producer,
        )
    }

    /// Low-level persistence primitive used by deterministic tests after they have supplied their
    /// own verified L1 evidence. Production command surfaces MUST call
    /// [`Self::acknowledge_candidate_from_l1`] instead; caller-asserted acknowledgements are not an
    /// authentication boundary.
    #[doc(hidden)]
    pub fn acknowledge_candidate_unchecked_for_test(
        &mut self,
        request_id: String,
        candidate_id: Bytes32,
        acknowledgement: L1ValidityAcknowledgement,
        deployment_binding: L1ValidityDeploymentBinding,
        producer: &BlockProducerService,
    ) -> Result<ValidityFinalizationReceipt, ValidityProverServiceError> {
        self.ensure_healthy()?;
        validate_request_id(&request_id)?;
        deployment_binding.validate()?;
        if deployment_binding.chain_id != acknowledgement.chain_id {
            return Err(ValidityProverServiceError::InvalidRequest(
                "L1 acknowledgement chain differs from the deployment binding".into(),
            ));
        }
        if let Some(stored) = self.disk.l1_binding {
            if stored != deployment_binding {
                return Err(ValidityProverServiceError::Conflict(
                    "L1 deployment binding changed across validity acknowledgements".into(),
                ));
            }
        }
        let fingerprint = acknowledgement_fingerprint(candidate_id, &acknowledgement)?;
        if let Some(existing) = self
            .disk
            .acknowledgements
            .iter()
            .find(|record| record.request_id == request_id)
        {
            if existing.request_fingerprint != fingerprint {
                return Err(ValidityProverServiceError::Conflict(format!(
                    "acknowledgement request id {request_id:?} was reused for different content"
                )));
            }
            verify_anchor(producer, &existing.finalized_anchor)?;
            let committed_producer_receipt = producer
                .committed_receipt_at_anchor(&existing.finalized_anchor)?
                .ok_or_else(|| {
                    ValidityProverServiceError::ProducerReconciliation(
                        "acknowledged producer anchor has no committed journal receipt".into(),
                    )
                })?;
            return Ok(finalization_receipt(existing, committed_producer_receipt));
        }
        if acknowledgement.chain_id == 0 || acknowledgement.transaction_hash == Bytes32::default() {
            return Err(ValidityProverServiceError::InvalidRequest(
                "L1 acknowledgement requires a nonzero chainId and transactionHash".into(),
            ));
        }
        acknowledgement
            .finalized_checkpoint
            .covers_receipt(acknowledgement.block_number, acknowledgement.block_hash)
            .map_err(|error| {
                ValidityProverServiceError::InvalidRequest(format!(
                    "L1 acknowledgement lacks durable receipt coverage: {error}"
                ))
            })?;
        if acknowledgement.finalized_checkpoint.chain_id != acknowledgement.chain_id {
            return Err(ValidityProverServiceError::InvalidRequest(
                "L1 acknowledgement checkpoint belongs to a different chain".into(),
            ));
        }
        let candidate = self.disk.candidate.as_ref().ok_or_else(|| {
            ValidityProverServiceError::InvalidRequest(
                "there is no pending candidate to acknowledge".into(),
            )
        })?;
        if candidate.receipt.candidate_id != candidate_id {
            return Err(ValidityProverServiceError::Conflict(
                "candidate id does not match the pending proof".into(),
            ));
        }
        if acknowledgement.final_extended_state_commitment
            != candidate.receipt.final_extended_state_commitment
        {
            return Err(ValidityProverServiceError::InvalidRequest(
                "L1 acknowledgement commits to a different final extended state".into(),
            ));
        }
        verify_anchor(producer, &candidate.receipt.producer_anchor)?;
        let committed_producer_receipt = producer
            .committed_receipt_at_anchor(&candidate.receipt.producer_anchor)?
            .ok_or_else(|| {
                ValidityProverServiceError::ProducerReconciliation(
                    "candidate producer anchor is not authoritatively committed".into(),
                )
            })?;

        let record = AcknowledgementRecord {
            request_id,
            request_fingerprint: fingerprint,
            candidate_id,
            previous_anchor: self.disk.finalized.anchor.clone(),
            finalized_anchor: candidate.receipt.producer_anchor.clone(),
            acknowledgement: acknowledgement.clone(),
        };
        let next_authority = acknowledgement.finalized_checkpoint;
        let next_finalized = FinalizedCheckpoint {
            anchor: candidate.receipt.producer_anchor.clone(),
            extended_state: candidate.final_extended_state.clone(),
            signature_event_count: candidate.receipt.signature_event_count,
            aggregate_list_proof: candidate.aggregate_list_proof.clone(),
            last_span_initial_state: Some(candidate.initial_extended_state.clone()),
            last_validity_proof: Some(candidate.validity_proof.clone()),
            acknowledgement: Some(acknowledgement),
        };
        let mut next_disk = self.disk.clone();
        next_disk.l1_authority = Some(next_authority);
        next_disk.l1_binding = Some(deployment_binding);
        next_disk.finalized = next_finalized;
        next_disk.candidate = None;
        next_disk.acknowledgements.push(record.clone());
        if next_disk.acknowledgements.len() > MAX_ACK_HISTORY {
            return Err(ValidityProverServiceError::Snapshot(format!(
                "acknowledgement history exceeds {MAX_ACK_HISTORY} entries"
            )));
        }
        validate_snapshot(&next_disk, &self.circuits, producer)?;
        if let Err(error) = persist_snapshot(&self.snapshot_path, &next_disk) {
            self.poisoned = true;
            return Err(error);
        }
        self.disk = next_disk;
        Ok(finalization_receipt(&record, committed_producer_receipt))
    }

    fn ensure_healthy(&self) -> Result<(), ValidityProverServiceError> {
        if self.poisoned {
            Err(ValidityProverServiceError::Poisoned)
        } else {
            Ok(())
        }
    }
}

const FINALIZED_EVENT_TOPIC: &str =
    "0xa05a0e9561eff1f01a29e7a680d5957bb7312e5766a8da1f494b6d6ac18031f4";
const MAX_CAST_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedReceipt {
    transaction_hash: Bytes32,
    status: u64,
    block_number: u64,
    block_hash: Bytes32,
    to: Address,
    finalized_roots: Vec<Bytes32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedBlock {
    number: u64,
    hash: Bytes32,
    parent_hash: Bytes32,
}

#[derive(Clone, Debug)]
struct L1FinalizationEvidence {
    chain_id: u64,
    first_receipt: ParsedReceipt,
    second_receipt: ParsedReceipt,
    head_before: ParsedBlock,
    head_after: ParsedBlock,
    canonical_head_before: ParsedBlock,
    canonical_receipt_block: ParsedBlock,
    rollup_runtime_code_hash: Bytes32,
    root_membership: bool,
    latest_finalized_root: Bytes32,
    latest_finalized_block_number: u64,
}

/// Receipt-independent authority evidence used on every daemon start, including a brand-new
/// snapshot which has no acknowledgement yet.
#[derive(Clone, Debug)]
struct L1StateAuthorityEvidence {
    chain_id: u64,
    source: L1FinalitySource,
    head_before: ParsedBlock,
    canonical_head_before: ParsedBlock,
    head_after: ParsedBlock,
    rollup_runtime_code_hash: Bytes32,
    root_membership: bool,
    latest_finalized_root: Bytes32,
    latest_finalized_block_number: u64,
}

/// Exact durable candidate which may already be L1-latest across the
/// `finalize succeeded -> local acknowledgement persisted` crash boundary. Merely matching this
/// tuple never authorizes local promotion; [`ValidityProverService::acknowledge_candidate_from_l1`]
/// still verifies the finalization transaction independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingL1Candidate {
    root: Bytes32,
    intmax_block: u64,
}

fn verify_local_finalized_state_at_l1(
    config: &L1FinalizationRpcConfig,
    checkpoint: &L1FinalizedCheckpoint,
    expected_root: Bytes32,
    expected_intmax_block: u64,
    pending_candidate: Option<PendingL1Candidate>,
) -> Result<L1FinalizedCheckpoint, ValidityProverServiceError> {
    checkpoint
        .validate()
        .map_err(|error| l1_rejected(&format!("invalid initial L1 authority: {error}")))?;
    let block_tag = format!("0x{:x}", checkpoint.block_number);
    let code = run_cast(
        config,
        &["code", &config.rollup.to_string(), "--block", &block_tag],
    )?;
    let rollup_runtime_code_hash = runtime_code_hash(&code, "configured rollup")?;
    let root_membership = parse_bool_text(&run_cast(
        config,
        &[
            "call",
            &config.rollup.to_string(),
            "isFinalizedStateRoot(bytes32)(bool)",
            &expected_root.to_string(),
            "--block",
            &block_tag,
        ],
    )?)?;
    let latest_finalized_root = Bytes32::from_hex(
        run_cast(
            config,
            &[
                "call",
                &config.rollup.to_string(),
                "latestFinalizedStateRoot()(bytes32)",
                "--block",
                &block_tag,
            ],
        )?
        .trim(),
    )
    .map_err(|error| {
        l1_rejected(&format!(
            "parse latestFinalizedStateRoot authority read-back: {error}"
        ))
    })?;
    let latest_finalized_block_number = parse_quantity_text(
        &run_cast(
            config,
            &[
                "call",
                &config.rollup.to_string(),
                "latestFinalizedBlockNumber()(uint64)",
                "--block",
                &block_tag,
            ],
        )?,
        "latestFinalizedBlockNumber authority read-back",
    )?;
    let canonical_head_before = parse_block(
        &run_cast(
            config,
            &["rpc", "eth_getBlockByNumber", &block_tag, "false"],
        )?,
        "canonical L1 authority block",
    )?;
    let after = read_l1_authority_checkpoint(config)?;
    let evidence = L1StateAuthorityEvidence {
        chain_id: checkpoint.chain_id,
        source: checkpoint.source,
        head_before: ParsedBlock {
            number: checkpoint.block_number,
            hash: checkpoint.block_hash,
            parent_hash: checkpoint.parent_hash,
        },
        canonical_head_before,
        head_after: ParsedBlock {
            number: after.block_number,
            hash: after.block_hash,
            parent_hash: after.parent_hash,
        },
        rollup_runtime_code_hash,
        root_membership,
        latest_finalized_root,
        latest_finalized_block_number,
    };
    validate_l1_state_authority_evidence(
        &evidence,
        config,
        expected_root,
        expected_intmax_block,
        pending_candidate,
    )?;
    Ok(after)
}

fn validate_l1_state_authority_evidence(
    evidence: &L1StateAuthorityEvidence,
    config: &L1FinalizationRpcConfig,
    expected_root: Bytes32,
    expected_intmax_block: u64,
    pending_candidate: Option<PendingL1Candidate>,
) -> Result<(), ValidityProverServiceError> {
    if evidence.chain_id != config.expected_chain_id
        || evidence.source != configured_finality_source(config)
    {
        return Err(l1_rejected(
            "L1 state authority belongs to a different chain/finality mode",
        ));
    }
    if evidence.rollup_runtime_code_hash != config.expected_rollup_runtime_code_hash {
        return Err(l1_rejected(&format!(
            "configured rollup runtime-code hash mismatch: expected {}, observed {}",
            config.expected_rollup_runtime_code_hash, evidence.rollup_runtime_code_hash
        )));
    }
    if evidence.canonical_head_before != evidence.head_before {
        return Err(l1_rejected(
            "L1 authority block was replaced during state binding (reorg detected)",
        ));
    }
    // All rollup reads above were pinned to `head_before`. Do not label a newer head authoritative
    // without reading the state at that newer block too; retrying performs a clean new binding.
    if evidence.head_after != evidence.head_before {
        return Err(l1_rejected(
            "durable L1 head changed during state binding; retry against one stable finalized block",
        ));
    }
    if !evidence.root_membership {
        return Err(l1_rejected(
            "local finalized root is not a member of the rollup finalized-root set",
        ));
    }
    let latest_is_local = evidence.latest_finalized_block_number == expected_intmax_block
        && evidence.latest_finalized_root == expected_root;
    let latest_is_pending = pending_candidate.is_some_and(|pending| {
        pending.root != Bytes32::default()
            && pending.intmax_block > expected_intmax_block
            && evidence.latest_finalized_block_number == pending.intmax_block
            && evidence.latest_finalized_root == pending.root
    });
    if !latest_is_local && !latest_is_pending {
        return Err(l1_rejected(
            "rollup latest finalized state matches neither the local snapshot nor its exact durable pending candidate",
        ));
    }
    if expected_root == Bytes32::default() {
        return Err(l1_rejected("local finalized state root is zero"));
    }
    Ok(())
}

/// Read and cross-check the finalization twice. The transaction receipt is not trusted by itself:
/// the canonical receipt block hash, rollup event address, permanent root-membership getter,
/// latest finalized cursor and chain id must all agree after the read-back. Production uses the
/// RPC `finalized` tag; depth-based `latest` is restricted to an explicit chain-31337 escape.
fn verify_l1_finalization(
    config: &L1FinalizationRpcConfig,
    transaction_hash: Bytes32,
    expected_root: Bytes32,
    expected_intmax_block: u64,
) -> Result<L1ValidityAcknowledgement, ValidityProverServiceError> {
    verify_l1_finalization_with_position(
        config,
        transaction_hash,
        expected_root,
        expected_intmax_block,
        FinalizationPosition::Latest,
    )
}

fn revalidate_historical_l1_finalization(
    config: &L1FinalizationRpcConfig,
    transaction_hash: Bytes32,
    expected_root: Bytes32,
    expected_intmax_block: u64,
) -> Result<L1ValidityAcknowledgement, ValidityProverServiceError> {
    verify_l1_finalization_with_position(
        config,
        transaction_hash,
        expected_root,
        expected_intmax_block,
        FinalizationPosition::Historical,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalizationPosition {
    Latest,
    Historical,
}

fn verify_l1_finalization_with_position(
    config: &L1FinalizationRpcConfig,
    transaction_hash: Bytes32,
    expected_root: Bytes32,
    expected_intmax_block: u64,
    position: FinalizationPosition,
) -> Result<L1ValidityAcknowledgement, ValidityProverServiceError> {
    config.validate()?;
    if transaction_hash == Bytes32::default() {
        return Err(ValidityProverServiceError::InvalidRequest(
            "finalization transaction hash must be nonzero".into(),
        ));
    }
    let chain_id = parse_quantity_text(&run_cast(config, &["chain-id"])?, "cast chain-id")?;
    let (finality_tag, source) = if config.allow_unfinalized_devnet {
        ("latest", L1FinalitySource::DevnetLatest)
    } else {
        ("finalized", L1FinalitySource::RpcFinalized)
    };
    let first_receipt = parse_receipt(
        &run_cast(
            config,
            &[
                "rpc",
                "eth_getTransactionReceipt",
                &transaction_hash.to_string(),
            ],
        )?,
        config.rollup,
    )?;
    let head_before = parse_block(
        &run_cast(
            config,
            &["rpc", "eth_getBlockByNumber", finality_tag, "false"],
        )?,
        "durable head before finalization read-back",
    )?;
    let head_block_tag = format!("0x{:x}", head_before.number);
    let code = run_cast(
        config,
        &[
            "code",
            &config.rollup.to_string(),
            "--block",
            &head_block_tag,
        ],
    )?;
    let rollup_runtime_code_hash = runtime_code_hash(&code, "configured rollup")?;
    let root_membership = parse_bool_text(&run_cast(
        config,
        &[
            "call",
            &config.rollup.to_string(),
            "isFinalizedStateRoot(bytes32)(bool)",
            &expected_root.to_string(),
            "--block",
            &head_block_tag,
        ],
    )?)?;
    let latest_finalized_root = Bytes32::from_hex(
        run_cast(
            config,
            &[
                "call",
                &config.rollup.to_string(),
                "latestFinalizedStateRoot()(bytes32)",
                "--block",
                &head_block_tag,
            ],
        )?
        .trim(),
    )
    .map_err(|e| {
        ValidityProverServiceError::ProducerReconciliation(format!(
            "parse latestFinalizedStateRoot read-back: {e}"
        ))
    })?;
    let latest_finalized_block_number = parse_quantity_text(
        &run_cast(
            config,
            &[
                "call",
                &config.rollup.to_string(),
                "latestFinalizedBlockNumber()(uint64)",
                "--block",
                &head_block_tag,
            ],
        )?,
        "latestFinalizedBlockNumber read-back",
    )?;

    let receipt_block_tag = format!("0x{:x}", first_receipt.block_number);
    let canonical_receipt_block = parse_block(
        &run_cast(
            config,
            &["rpc", "eth_getBlockByNumber", &receipt_block_tag, "false"],
        )?,
        "canonical receipt block",
    )?;
    let canonical_head_before = parse_block(
        &run_cast(
            config,
            &["rpc", "eth_getBlockByNumber", &head_block_tag, "false"],
        )?,
        "canonical durable head read-back",
    )?;
    let second_receipt = parse_receipt(
        &run_cast(
            config,
            &[
                "rpc",
                "eth_getTransactionReceipt",
                &transaction_hash.to_string(),
            ],
        )?,
        config.rollup,
    )?;
    let head_after = parse_block(
        &run_cast(
            config,
            &["rpc", "eth_getBlockByNumber", finality_tag, "false"],
        )?,
        "durable head after finalization read-back",
    )?;
    let evidence = L1FinalizationEvidence {
        chain_id,
        first_receipt,
        second_receipt,
        head_before,
        head_after,
        canonical_head_before,
        canonical_receipt_block,
        rollup_runtime_code_hash,
        root_membership,
        latest_finalized_root,
        latest_finalized_block_number,
    };
    validate_l1_finalization_evidence_at_position(
        &evidence,
        config,
        transaction_hash,
        expected_root,
        expected_intmax_block,
        position,
    )?;
    Ok(L1ValidityAcknowledgement {
        chain_id: evidence.chain_id,
        transaction_hash,
        block_hash: evidence.first_receipt.block_hash,
        block_number: evidence.first_receipt.block_number,
        final_extended_state_commitment: expected_root,
        finalized_checkpoint: L1FinalizedCheckpoint {
            chain_id: evidence.chain_id,
            block_number: evidence.head_after.number,
            block_hash: evidence.head_after.hash,
            parent_hash: evidence.head_after.parent_hash,
            source,
        },
    })
}

fn validate_l1_finalization_evidence(
    evidence: &L1FinalizationEvidence,
    config: &L1FinalizationRpcConfig,
    transaction_hash: Bytes32,
    expected_root: Bytes32,
    expected_intmax_block: u64,
) -> Result<(), ValidityProverServiceError> {
    validate_l1_finalization_evidence_at_position(
        evidence,
        config,
        transaction_hash,
        expected_root,
        expected_intmax_block,
        FinalizationPosition::Latest,
    )
}

fn validate_l1_finalization_evidence_at_position(
    evidence: &L1FinalizationEvidence,
    config: &L1FinalizationRpcConfig,
    transaction_hash: Bytes32,
    expected_root: Bytes32,
    expected_intmax_block: u64,
    position: FinalizationPosition,
) -> Result<(), ValidityProverServiceError> {
    if evidence.chain_id != config.expected_chain_id {
        return Err(l1_rejected(&format!(
            "RPC chain id {} differs from configured {}",
            evidence.chain_id, config.expected_chain_id
        )));
    }
    if evidence.rollup_runtime_code_hash != config.expected_rollup_runtime_code_hash {
        return Err(l1_rejected(&format!(
            "configured rollup runtime-code hash mismatch: expected {}, observed {}",
            config.expected_rollup_runtime_code_hash, evidence.rollup_runtime_code_hash
        )));
    }
    let receipt = &evidence.first_receipt;
    if receipt != &evidence.second_receipt {
        return Err(l1_rejected(
            "transaction receipt changed during read-back (possible reorg)",
        ));
    }
    if receipt.transaction_hash != transaction_hash
        || receipt.status != 1
        || receipt.to != config.rollup
    {
        return Err(l1_rejected(
            "receipt hash/status/destination does not identify a successful direct rollup finalization",
        ));
    }
    if !receipt
        .finalized_roots
        .iter()
        .any(|root| *root == expected_root)
    {
        return Err(l1_rejected(
            "receipt has no Finalized event from the configured rollup for the candidate root",
        ));
    }
    if evidence.canonical_receipt_block.number != receipt.block_number
        || evidence.canonical_receipt_block.hash != receipt.block_hash
    {
        return Err(l1_rejected(
            "receipt block hash is no longer canonical (reorg detected)",
        ));
    }
    if evidence.canonical_head_before != evidence.head_before {
        return Err(l1_rejected(
            "durable L1 head was replaced during read-back (reorg detected)",
        ));
    }
    // Rollup state getters were pinned to `head_before`; persisting a different `head_after` as
    // authority would ascribe those answers to a block at which they were never read.
    if evidence.head_after != evidence.head_before {
        return Err(l1_rejected(
            "durable L1 head changed during receipt read-back; retry against one stable finalized block",
        ));
    }
    let source = if config.allow_unfinalized_devnet {
        L1FinalitySource::DevnetLatest
    } else {
        L1FinalitySource::RpcFinalized
    };
    for (label, head) in [
        ("initial", &evidence.head_before),
        ("final", &evidence.head_after),
    ] {
        L1FinalizedCheckpoint {
            chain_id: evidence.chain_id,
            block_number: head.number,
            block_hash: head.hash,
            parent_hash: head.parent_hash,
            source,
        }
        .covers_receipt(receipt.block_number, receipt.block_hash)
        .map_err(|error| {
            l1_rejected(&format!(
                "receipt is not covered by the {label} durable head: {error}"
            ))
        })?;
    }
    let confirmations = evidence
        .head_after
        .number
        .checked_sub(receipt.block_number)
        .and_then(|depth| depth.checked_add(1))
        .ok_or_else(|| l1_rejected("receipt block is ahead of the current L1 head"))?;
    if config.allow_unfinalized_devnet && confirmations < config.minimum_confirmations {
        return Err(l1_rejected(&format!(
            "finalization has {confirmations} confirmations; {} required",
            config.minimum_confirmations
        )));
    }
    if !evidence.root_membership {
        return Err(l1_rejected(
            "isFinalizedStateRoot(candidate) returned false",
        ));
    }
    match position {
        FinalizationPosition::Latest => {
            if evidence.latest_finalized_block_number != expected_intmax_block {
                return Err(l1_rejected(
                    "rollup latest finalized block differs from the local candidate (stale or divergent snapshot)",
                ));
            }
            if evidence.latest_finalized_root != expected_root {
                return Err(l1_rejected(
                    "rollup latest finalized root differs from the local candidate",
                ));
            }
        }
        FinalizationPosition::Historical => {
            if evidence.latest_finalized_block_number < expected_intmax_block {
                return Err(l1_rejected(
                    "rollup latest finalized block regressed behind the replayed acknowledgement",
                ));
            }
            if evidence.latest_finalized_block_number == expected_intmax_block
                && evidence.latest_finalized_root != expected_root
            {
                return Err(l1_rejected(
                    "rollup root at the replayed latest height differs from its acknowledgement",
                ));
            }
        }
    }
    if evidence.latest_finalized_root == Bytes32::default() {
        return Err(l1_rejected("rollup latest finalized root is zero"));
    }
    Ok(())
}

fn l1_rejected(message: &str) -> ValidityProverServiceError {
    ValidityProverServiceError::ProducerReconciliation(format!(
        "L1 finalization read-back rejected: {message}"
    ))
}

fn configured_finality_source(config: &L1FinalizationRpcConfig) -> L1FinalitySource {
    if config.allow_unfinalized_devnet {
        L1FinalitySource::DevnetLatest
    } else {
        L1FinalitySource::RpcFinalized
    }
}

fn read_l1_authority_checkpoint(
    config: &L1FinalizationRpcConfig,
) -> Result<L1FinalizedCheckpoint, ValidityProverServiceError> {
    config.validate()?;
    let chain_id = parse_quantity_text(&run_cast(config, &["chain-id"])?, "cast chain-id")?;
    if chain_id != config.expected_chain_id {
        return Err(l1_rejected(&format!(
            "RPC chain id {chain_id} differs from configured {}",
            config.expected_chain_id
        )));
    }
    let source = configured_finality_source(config);
    let tag = if source == L1FinalitySource::DevnetLatest {
        "latest"
    } else {
        "finalized"
    };
    let block = parse_block(
        &run_cast(config, &["rpc", "eth_getBlockByNumber", tag, "false"])?,
        "durable L1 authority",
    )?;
    let checkpoint = L1FinalizedCheckpoint {
        chain_id,
        block_number: block.number,
        block_hash: block.hash,
        parent_hash: block.parent_hash,
        source,
    };
    checkpoint
        .validate()
        .map_err(|error| l1_rejected(&format!("invalid durable L1 authority: {error}")))?;
    Ok(checkpoint)
}

fn validate_stored_l1_checkpoint(
    config: &L1FinalizationRpcConfig,
    stored: &L1FinalizedCheckpoint,
    current: &L1FinalizedCheckpoint,
) -> Result<(), ValidityProverServiceError> {
    stored
        .validate()
        .map_err(|error| l1_rejected(&format!("stored L1 authority is invalid: {error}")))?;
    if stored.chain_id != config.expected_chain_id
        || stored.source != configured_finality_source(config)
        || current.chain_id != stored.chain_id
        || current.source != stored.source
    {
        return Err(l1_rejected(
            "stored L1 authority differs from the configured chain/finality mode",
        ));
    }
    let block_tag = format!("0x{:x}", stored.block_number);
    let canonical = parse_block(
        &run_cast(
            config,
            &["rpc", "eth_getBlockByNumber", &block_tag, "false"],
        )?,
        "stored L1 authority block",
    )?;
    if canonical.number != stored.block_number
        || canonical.hash != stored.block_hash
        || canonical.parent_hash != stored.parent_hash
    {
        return Err(l1_rejected(
            "stored L1 authority block was replaced (reorg detected)",
        ));
    }
    if current.block_number < stored.block_number
        || (current.block_number == stored.block_number
            && (current.block_hash != stored.block_hash
                || current.parent_hash != stored.parent_hash))
    {
        return Err(l1_rejected(
            "current durable L1 head regressed or changed at the stored height",
        ));
    }
    Ok(())
}

fn validate_checkpoint_progression(
    earlier: &L1FinalizedCheckpoint,
    later: &L1FinalizedCheckpoint,
) -> Result<(), ValidityProverServiceError> {
    earlier
        .validate()
        .map_err(|error| l1_rejected(&format!("invalid earlier L1 checkpoint: {error}")))?;
    later
        .validate()
        .map_err(|error| l1_rejected(&format!("invalid later L1 checkpoint: {error}")))?;
    if later.chain_id != earlier.chain_id || later.source != earlier.source {
        return Err(l1_rejected(
            "durable L1 checkpoint changed chain/finality mode",
        ));
    }
    if later.block_number < earlier.block_number
        || (later.block_number == earlier.block_number
            && (later.block_hash != earlier.block_hash || later.parent_hash != earlier.parent_hash))
    {
        return Err(l1_rejected(
            "durable L1 checkpoint regressed or changed at the same height",
        ));
    }
    Ok(())
}

fn validate_replayed_acknowledgement(
    stored: &L1ValidityAcknowledgement,
    reread: &L1ValidityAcknowledgement,
) -> Result<(), ValidityProverServiceError> {
    if reread.chain_id != stored.chain_id
        || reread.transaction_hash != stored.transaction_hash
        || reread.block_number != stored.block_number
        || reread.block_hash != stored.block_hash
        || reread.final_extended_state_commitment != stored.final_extended_state_commitment
    {
        return Err(l1_rejected(
            "replayed acknowledgement receipt changed or was orphaned",
        ));
    }
    Ok(())
}

fn run_cast(
    config: &L1FinalizationRpcConfig,
    args: &[&str],
) -> Result<String, ValidityProverServiceError> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let output = Command::new("cast")
        .args(args)
        .args(["--rpc-timeout", "30"])
        // Do not inherit wallet/private-key variables into a read-only proof service child.
        .env_clear()
        .env("PATH", path)
        .env("ETH_RPC_URL", &config.rpc_url)
        .env("NO_COLOR", "1")
        .output()
        .map_err(|e| {
            ValidityProverServiceError::InvalidConfiguration(format!(
                "start read-only cast RPC client: {e}"
            ))
        })?;
    if !output.status.success() {
        return Err(l1_rejected(&format!(
            "read-only RPC command exited with status {}",
            output.status
        )));
    }
    if output.stdout.len() > MAX_CAST_OUTPUT_BYTES {
        return Err(l1_rejected("RPC response exceeds the 16 MiB bound"));
    }
    String::from_utf8(output.stdout)
        .map_err(|e| l1_rejected(&format!("RPC response is not UTF-8: {e}")))
}

fn parse_receipt(json: &str, rollup: Address) -> Result<ParsedReceipt, ValidityProverServiceError> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| l1_rejected(&format!("parse transaction receipt JSON: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| l1_rejected("transaction receipt is null or not an object"))?;
    let transaction_hash = parse_bytes32_field(object, "transactionHash")?;
    let status = parse_quantity_field(object, "status")?;
    let block_number = parse_quantity_field(object, "blockNumber")?;
    let block_hash = parse_bytes32_field(object, "blockHash")?;
    let to = object
        .get("to")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| l1_rejected("receipt has no direct destination address"))?
        .parse::<Address>()
        .map_err(|e| l1_rejected(&format!("parse receipt destination: {e}")))?;
    let logs = object
        .get("logs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| l1_rejected("receipt logs are absent or malformed"))?;
    let mut finalized_roots = Vec::new();
    for log in logs {
        let Some(log_object) = log.as_object() else {
            return Err(l1_rejected("receipt contains a malformed log"));
        };
        let Some(address) = log_object
            .get("address")
            .and_then(serde_json::Value::as_str)
        else {
            return Err(l1_rejected("receipt log has no address"));
        };
        let address = address
            .parse::<Address>()
            .map_err(|e| l1_rejected(&format!("parse receipt log address: {e}")))?;
        if address != rollup {
            continue;
        }
        let topics = log_object
            .get("topics")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| l1_rejected("receipt log topics are malformed"))?;
        let is_finalized = topics
            .first()
            .and_then(serde_json::Value::as_str)
            .is_some_and(|topic| topic.eq_ignore_ascii_case(FINALIZED_EVENT_TOPIC));
        if !is_finalized {
            continue;
        }
        if topics.len() != 2 {
            return Err(l1_rejected(
                "Finalized event does not have its canonical indexed-id topic layout",
            ));
        }
        let data = log_object
            .get("data")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| l1_rejected("Finalized event data is absent"))?;
        let root = Bytes32::from_hex(data)
            .map_err(|e| l1_rejected(&format!("parse Finalized event state root: {e}")))?;
        finalized_roots.push(root);
    }
    Ok(ParsedReceipt {
        transaction_hash,
        status,
        block_number,
        block_hash,
        to,
        finalized_roots,
    })
}

fn parse_block(json: &str, label: &str) -> Result<ParsedBlock, ValidityProverServiceError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| l1_rejected(&format!("parse {label} JSON: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| l1_rejected(&format!("{label} is null or not an object")))?;
    Ok(ParsedBlock {
        number: parse_quantity_field(object, "number")?,
        hash: parse_bytes32_field(object, "hash")?,
        parent_hash: parse_bytes32_field(object, "parentHash")?,
    })
}

fn parse_quantity_field(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<u64, ValidityProverServiceError> {
    let value = object
        .get(field)
        .ok_or_else(|| l1_rejected(&format!("RPC object has no {field} field")))?;
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    let text = value
        .as_str()
        .ok_or_else(|| l1_rejected(&format!("RPC {field} is not a quantity")))?;
    parse_quantity_text(text, field)
}

fn parse_quantity_text(text: &str, label: &str) -> Result<u64, ValidityProverServiceError> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .map_err(|e| l1_rejected(&format!("parse {label} hex quantity: {e}")))
    } else {
        text.parse::<u64>()
            .map_err(|e| l1_rejected(&format!("parse {label} decimal quantity: {e}")))
    }
}

fn parse_bytes32_field(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Bytes32, ValidityProverServiceError> {
    let text = object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| l1_rejected(&format!("RPC object has no {field} bytes32 field")))?;
    Bytes32::from_hex(text).map_err(|e| l1_rejected(&format!("parse RPC {field} bytes32: {e}")))
}

fn parse_bool_text(text: &str) -> Result<bool, ValidityProverServiceError> {
    match text.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(l1_rejected(&format!(
            "boolean read-back returned {other:?}"
        ))),
    }
}

fn runtime_code_hash(encoded: &str, label: &str) -> Result<Bytes32, ValidityProverServiceError> {
    let encoded = encoded.trim();
    let body = encoded
        .strip_prefix("0x")
        .or_else(|| encoded.strip_prefix("0X"))
        .ok_or_else(|| l1_rejected(&format!("{label} runtime code is not 0x-prefixed hex")))?;
    if body.is_empty() || body.len() % 2 != 0 {
        return Err(l1_rejected(&format!(
            "{label} runtime code is empty or malformed"
        )));
    }
    let bytes = hex::decode(body)
        .map_err(|error| l1_rejected(&format!("decode {label} runtime code: {error}")))?;
    if bytes.is_empty() {
        return Err(l1_rejected(&format!("{label} runtime code is empty")));
    }
    Bytes32::from_bytes_be(&keccak_hash::keccak(bytes).0)
        .map_err(|error| l1_rejected(&format!("construct {label} runtime-code hash: {error}")))
}

fn build_resident_circuits(
    supported_user_counts: &[u32],
) -> Result<(ResidentCircuits, u64, u64), ValidityProverServiceError> {
    let started = Instant::now();
    let block_hash_chain = BlockHashChainProcessor::<F, C, D>::new(supported_user_counts);
    let aggregate = FalconAggCircuit::<F, C, D>::new();
    let aggregate_list = AggListCircuit::<F, C, D>::new(&aggregate.verifier_data());
    let validity = ValidityCircuit::<F, C, D>::new(
        &block_hash_chain.block_chain_vd(),
        &aggregate_list.verifier_data(),
    );
    let fingerprint = circuit_fingerprint(
        supported_user_counts,
        &block_hash_chain.block_chain_vd(),
        &aggregate.verifier_data(),
        &aggregate_list.verifier_data(),
        &validity.data.verifier_data(),
    )?;
    Ok((
        ResidentCircuits {
            block_hash_chain,
            aggregate,
            aggregate_list,
            validity,
            fingerprint,
        },
        elapsed_ms(started),
        peak_rss_bytes(),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CircuitFingerprintMaterial {
    domain: &'static str,
    version: u32,
    supported_user_counts: Vec<u32>,
    block_hash_chain_digest: Bytes32,
    aggregate_digest: Bytes32,
    aggregate_list_digest: Bytes32,
    validity_digest: Bytes32,
    block_hash_chain_public_inputs: usize,
    aggregate_public_inputs: usize,
    aggregate_list_public_inputs: usize,
    validity_public_inputs: usize,
}

fn circuit_fingerprint(
    supported_user_counts: &[u32],
    block: &VerifierCircuitData<F, C, D>,
    aggregate: &VerifierCircuitData<F, C, D>,
    aggregate_list: &VerifierCircuitData<F, C, D>,
    validity: &VerifierCircuitData<F, C, D>,
) -> Result<Bytes32, ValidityProverServiceError> {
    hash_serializable(&CircuitFingerprintMaterial {
        domain: "INTMAX_VALIDITY_PROVER_CIRCUITS_V1",
        version: VALIDITY_PROVER_SNAPSHOT_VERSION,
        supported_user_counts: supported_user_counts.to_vec(),
        block_hash_chain_digest: circuit_digest(block),
        aggregate_digest: circuit_digest(aggregate),
        aggregate_list_digest: circuit_digest(aggregate_list),
        validity_digest: circuit_digest(validity),
        block_hash_chain_public_inputs: block.common.num_public_inputs,
        aggregate_public_inputs: aggregate.common.num_public_inputs,
        aggregate_list_public_inputs: aggregate_list.common.num_public_inputs,
        validity_public_inputs: validity.common.num_public_inputs,
    })
}

fn circuit_digest(vd: &VerifierCircuitData<F, C, D>) -> Bytes32 {
    PoseidonHashOut::from(vd.verifier_only.circuit_digest).into()
}

fn validate_acknowledgement_checkpoint(
    acknowledgement: &L1ValidityAcknowledgement,
) -> Result<(), ValidityProverServiceError> {
    if acknowledgement.chain_id == 0
        || acknowledgement.transaction_hash == Bytes32::default()
        || acknowledgement.block_hash == Bytes32::default()
        || acknowledgement.finalized_checkpoint.chain_id != acknowledgement.chain_id
    {
        return Err(ValidityProverServiceError::Snapshot(
            "L1 acknowledgement has zero or cross-chain receipt metadata".into(),
        ));
    }
    acknowledgement
        .finalized_checkpoint
        .covers_receipt(acknowledgement.block_number, acknowledgement.block_hash)
        .map_err(|error| {
            ValidityProverServiceError::Snapshot(format!(
                "L1 acknowledgement is outside its durable checkpoint: {error}"
            ))
        })
}

fn validate_snapshot(
    disk: &ValidityProverSnapshot,
    circuits: &ResidentCircuits,
    producer: &BlockProducerService,
) -> Result<(), ValidityProverServiceError> {
    if disk.circuit_fingerprint != circuits.fingerprint {
        return Err(ValidityProverServiceError::Snapshot(
            "snapshot circuit fingerprint differs from the resident circuits".into(),
        ));
    }
    if disk.acknowledgements.len() > MAX_ACK_HISTORY {
        return Err(ValidityProverServiceError::Snapshot(format!(
            "acknowledgement history exceeds {MAX_ACK_HISTORY} entries"
        )));
    }
    if let Some(binding) = disk.l1_binding {
        binding.validate().map_err(|error| {
            ValidityProverServiceError::Snapshot(format!(
                "invalid durable L1 deployment binding: {error}"
            ))
        })?;
    }
    if disk.l1_authority.is_some() != disk.l1_binding.is_some() {
        return Err(ValidityProverServiceError::Snapshot(
            "durable L1 authority and deployment binding must be present together".into(),
        ));
    }
    if let Some(authority) = disk.l1_authority {
        authority.validate().map_err(|error| {
            ValidityProverServiceError::Snapshot(format!("invalid durable L1 authority: {error}"))
        })?;
        if !matches!(
            disk.l1_binding,
            Some(binding) if binding.chain_id == authority.chain_id
        ) {
            return Err(ValidityProverServiceError::Snapshot(
                "durable L1 authority and deployment binding belong to different chains".into(),
            ));
        }
    } else if !disk.acknowledgements.is_empty() || disk.finalized.acknowledgement.is_some() {
        return Err(ValidityProverServiceError::Snapshot(
            "acknowledged snapshot has no durable L1 authority/deployment binding".into(),
        ));
    }
    verify_anchor(producer, &disk.finalized.anchor)?;
    let finalized = decode_extended_state(&disk.finalized.extended_state)?;
    verify_state_anchor(&finalized, &disk.finalized.anchor, "finalized")?;
    verify_event_prefix(
        producer,
        disk.finalized.signature_event_count,
        finalized.bp_sig_chain,
    )?;
    verify_aggregate_list_checkpoint(
        disk.finalized.aggregate_list_proof.as_deref(),
        finalized.bp_sig_chain,
        &circuits.aggregate_list.verifier_data(),
        "finalized",
    )?;

    match (
        disk.finalized.last_span_initial_state.as_deref(),
        disk.finalized.last_validity_proof.as_deref(),
        disk.finalized.acknowledgement.as_ref(),
    ) {
        (None, None, None) if disk.acknowledgements.is_empty() => {
            if disk.finalized.anchor.generation != 0 {
                return Err(ValidityProverServiceError::Snapshot(
                    "non-genesis finalized checkpoint has no acknowledged proof".into(),
                ));
            }
        }
        (Some(initial_values), Some(proof_bytes), Some(ack)) => {
            let initial = decode_extended_state(initial_values)?;
            let proof = decode_proof(
                proof_bytes,
                &circuits.validity.data.verifier_data(),
                "finalized validity proof",
            )?;
            verify_validity_public_hash(&proof, &initial, &finalized, disk.prover)?;
            if ack.final_extended_state_commitment != finalized.commitment() {
                return Err(ValidityProverServiceError::Snapshot(
                    "finalized L1 acknowledgement commits to a different state".into(),
                ));
            }
            validate_acknowledgement_checkpoint(ack)?;
        }
        _ => {
            return Err(ValidityProverServiceError::Snapshot(
                "finalized proof, initial state and L1 acknowledgement must be all present or all absent"
                    .into(),
            ));
        }
    }

    let mut previous_anchor = producer.anchor_at_generation(0)?.ok_or_else(|| {
        ValidityProverServiceError::ProducerReconciliation(
            "producer generation-zero anchor is absent".into(),
        )
    })?;
    let mut previous_l1_checkpoint: Option<L1FinalizedCheckpoint> = None;
    let mut request_ids = std::collections::HashSet::new();
    for (index, record) in disk.acknowledgements.iter().enumerate() {
        validate_request_id(&record.request_id).map_err(|e| {
            ValidityProverServiceError::Snapshot(format!(
                "acknowledgement {} request id: {e}",
                index + 1
            ))
        })?;
        if !request_ids.insert(record.request_id.clone()) {
            return Err(ValidityProverServiceError::Snapshot(format!(
                "duplicate acknowledgement request id {:?}",
                record.request_id
            )));
        }
        if record.request_fingerprint
            != acknowledgement_fingerprint(record.candidate_id, &record.acknowledgement)?
            || record.previous_anchor != previous_anchor
            || record.finalized_anchor.generation <= record.previous_anchor.generation
        {
            return Err(ValidityProverServiceError::Snapshot(format!(
                "acknowledgement {} breaks the finalized checkpoint chain",
                index + 1
            )));
        }
        validate_acknowledgement_checkpoint(&record.acknowledgement)?;
        if let Some(previous) = previous_l1_checkpoint {
            let current = record.acknowledgement.finalized_checkpoint;
            if current.chain_id != previous.chain_id
                || current.source != previous.source
                || current.block_number < previous.block_number
                || (current.block_number == previous.block_number
                    && (current.block_hash != previous.block_hash
                        || current.parent_hash != previous.parent_hash))
            {
                return Err(ValidityProverServiceError::Snapshot(format!(
                    "acknowledgement {} regresses or replaces its durable L1 checkpoint",
                    index + 1
                )));
            }
        }
        previous_l1_checkpoint = Some(record.acknowledgement.finalized_checkpoint);
        verify_anchor(producer, &record.finalized_anchor)?;
        previous_anchor = record.finalized_anchor.clone();
    }
    if !disk.acknowledgements.is_empty() && previous_anchor != disk.finalized.anchor {
        return Err(ValidityProverServiceError::Snapshot(
            "acknowledgement history tail differs from the finalized anchor".into(),
        ));
    }
    if let Some(tail) = previous_l1_checkpoint {
        let authority = disk.l1_authority.ok_or_else(|| {
            ValidityProverServiceError::Snapshot(
                "acknowledgement history has no snapshot L1 authority".into(),
            )
        })?;
        if authority.chain_id != tail.chain_id
            || authority.source != tail.source
            || authority.block_number < tail.block_number
            || (authority.block_number == tail.block_number
                && (authority.block_hash != tail.block_hash
                    || authority.parent_hash != tail.parent_hash))
        {
            return Err(ValidityProverServiceError::Snapshot(
                "snapshot L1 authority does not cover its acknowledgement history".into(),
            ));
        }
        if !matches!(
            disk.l1_binding,
            Some(binding) if binding.chain_id == tail.chain_id
        ) {
            return Err(ValidityProverServiceError::Snapshot(
                "snapshot deployment binding does not cover its acknowledgement history".into(),
            ));
        }
    }

    if let Some(candidate) = &disk.candidate {
        validate_request_id(&candidate.receipt.request_id)?;
        if candidate.receipt.candidate_id != candidate_hash(candidate)? {
            return Err(ValidityProverServiceError::Snapshot(
                "candidate id/hash mismatch".into(),
            ));
        }
        if candidate.receipt.producer_anchor.generation <= disk.finalized.anchor.generation
            || candidate.receipt.initial_extended_state_commitment != finalized.commitment()
            || candidate.initial_extended_state != disk.finalized.extended_state
        {
            return Err(ValidityProverServiceError::Snapshot(
                "candidate does not advance exactly from the finalized checkpoint".into(),
            ));
        }
        let candidate_producer =
            candidate_producer_for_anchor(producer, &candidate.receipt.producer_anchor)?;
        let final_state = decode_extended_state(&candidate.final_extended_state)?;
        verify_state_anchor(
            &final_state,
            &candidate.receipt.producer_anchor,
            "candidate",
        )?;
        if candidate.receipt.final_extended_state_commitment != final_state.commitment()
            || candidate.receipt.initial_block_number != finalized.inner.block_number.as_u64()
            || candidate.receipt.final_block_number != final_state.inner.block_number.as_u64()
            || candidate.receipt.final_block_number <= candidate.receipt.initial_block_number
            || candidate.receipt.signature_event_count < disk.finalized.signature_event_count
        {
            return Err(ValidityProverServiceError::Snapshot(
                "candidate receipt metadata disagrees with its state span".into(),
            ));
        }
        verify_event_prefix_core(
            candidate_producer,
            candidate.receipt.signature_event_count,
            final_state.bp_sig_chain,
        )?;
        let block_proof = decode_proof(
            &candidate.block_chain_proof,
            &circuits.block_hash_chain.block_chain_vd(),
            "candidate block-chain proof",
        )?;
        let block_pis = parse_block_chain_public_inputs(
            &block_proof,
            &circuits.block_hash_chain.block_chain_vd(),
        )?;
        if block_pis.initial_ext_public_state.to_u64_vec() != candidate.initial_extended_state
            || block_pis.ext_public_state.to_u64_vec() != candidate.final_extended_state
        {
            return Err(ValidityProverServiceError::Snapshot(
                "candidate block-chain proof exposes different states".into(),
            ));
        }
        verify_aggregate_list_checkpoint(
            candidate.aggregate_list_proof.as_deref(),
            final_state.bp_sig_chain,
            &circuits.aggregate_list.verifier_data(),
            "candidate",
        )?;
        let validity_proof = decode_proof(
            &candidate.validity_proof,
            &circuits.validity.data.verifier_data(),
            "candidate validity proof",
        )?;
        verify_validity_public_hash(&validity_proof, &finalized, &final_state, disk.prover)?;
        if candidate.receipt.metrics.block_chain_proof_bytes != candidate.block_chain_proof.len()
            || candidate.receipt.metrics.aggregate_list_proof_bytes
                != candidate.aggregate_list_proof.as_ref().map_or(0, Vec::len)
            || candidate.receipt.metrics.validity_proof_bytes != candidate.validity_proof.len()
            || candidate.receipt.metrics.block_chain_public_inputs
                != block_proof.public_inputs.len()
            || candidate.receipt.metrics.aggregate_list_public_inputs
                != candidate.aggregate_list_proof.as_ref().map_or(0, |_| {
                    circuits
                        .aggregate_list
                        .verifier_data()
                        .common
                        .num_public_inputs
                })
            || candidate.receipt.metrics.validity_public_inputs
                != validity_proof.public_inputs.len()
        {
            return Err(ValidityProverServiceError::Snapshot(
                "candidate proof metrics disagree with stored artifacts".into(),
            ));
        }
    }
    Ok(())
}

fn verify_state_anchor(
    state: &ExtendedPublicState,
    anchor: &BlockProducerAnchor,
    label: &str,
) -> Result<(), ValidityProverServiceError> {
    if state.commitment() != anchor.extended_state_commitment
        || state.inner.block_number.as_u64() != anchor.block_number
        || state.bp_sig_chain != anchor.bp_sig_chain
    {
        return Err(ValidityProverServiceError::Snapshot(format!(
            "{label} extended state disagrees with its producer anchor"
        )));
    }
    Ok(())
}

/// Select the exact producer state a new proof must target. A durable terminal close candidate
/// takes precedence over the authoritative head because the latter intentionally has not moved
/// yet. Returning a borrowed producer avoids cloning the large witness trees and therefore adds
/// no proof-size, proving-time, or peak-memory tax to the happy path.
fn producer_proof_target(
    producer: &BlockProducerService,
) -> Result<(BlockProducerAnchor, &ProductionBlockProducer), ValidityProverServiceError> {
    if let Some(anchor) = producer.prepared_anchor()? {
        let prepared = producer.prepared_producer()?.ok_or_else(|| {
            ValidityProverServiceError::ProducerReconciliation(
                "prepared journal entry has no semantically replayed producer".into(),
            )
        })?;
        return Ok((anchor, prepared));
    }
    Ok((producer.current_anchor()?, producer.producer()?))
}

/// Resolve a candidate anchor against either the authoritative journal prefix or the single
/// durable prepared close entry. Once L1 finalization commits that entry, the same anchor resolves
/// through the first branch, which is what makes crash recovery deterministic.
fn candidate_producer_for_anchor<'a>(
    producer: &'a BlockProducerService,
    supplied: &BlockProducerAnchor,
) -> Result<&'a ProductionBlockProducer, ValidityProverServiceError> {
    if let Some(canonical) = producer.anchor_at_generation(supplied.generation)? {
        if canonical != *supplied {
            return Err(ValidityProverServiceError::ProducerReconciliation(format!(
                "producer generation {} anchor mismatch (rollback, replacement, or corrupt checkpoint)",
                supplied.generation
            )));
        }
        return Ok(producer.producer()?);
    }
    if producer.prepared_anchor()?.as_ref() == Some(supplied) {
        return producer.prepared_producer()?.ok_or_else(|| {
            ValidityProverServiceError::ProducerReconciliation(
                "prepared candidate anchor has no semantically replayed producer".into(),
            )
        });
    }
    Err(ValidityProverServiceError::ProducerReconciliation(format!(
        "producer journal has neither committed nor prepared generation {}",
        supplied.generation
    )))
}

fn verify_anchor(
    producer: &BlockProducerService,
    supplied: &BlockProducerAnchor,
) -> Result<(), ValidityProverServiceError> {
    let canonical = producer
        .anchor_at_generation(supplied.generation)?
        .ok_or_else(|| {
            ValidityProverServiceError::ProducerReconciliation(format!(
                "producer journal has no generation {} (rollback or replacement)",
                supplied.generation
            ))
        })?;
    if &canonical != supplied {
        return Err(ValidityProverServiceError::ProducerReconciliation(format!(
            "producer generation {} anchor mismatch (rollback, replacement, or corrupt checkpoint)",
            supplied.generation
        )));
    }
    Ok(())
}

fn verify_event_prefix(
    producer: &BlockProducerService,
    event_count: usize,
    expected_chain: Bytes32,
) -> Result<(), ValidityProverServiceError> {
    verify_event_prefix_core(producer.producer()?, event_count, expected_chain)
}

fn verify_event_prefix_core(
    producer: &ProductionBlockProducer,
    event_count: usize,
    expected_chain: Bytes32,
) -> Result<(), ValidityProverServiceError> {
    let events = producer.signature_events();
    if event_count > events.len() {
        return Err(ValidityProverServiceError::ProducerReconciliation(format!(
            "signature cursor {event_count} is ahead of producer event count {}",
            events.len()
        )));
    }
    let entries: Vec<_> = events[..event_count]
        .iter()
        .map(|event| event.entry())
        .collect();
    let actual = agg_list_commitment(&entries);
    if actual != expected_chain {
        return Err(ValidityProverServiceError::ProducerReconciliation(format!(
            "signature-event prefix commits to {actual}, expected {expected_chain}"
        )));
    }
    Ok(())
}

fn verify_aggregate_list_checkpoint(
    proof_bytes: Option<&[u8]>,
    expected_chain: Bytes32,
    vd: &VerifierCircuitData<F, C, D>,
    label: &str,
) -> Result<(), ValidityProverServiceError> {
    match (proof_bytes, expected_chain == Bytes32::default()) {
        (None, true) => Ok(()),
        (Some(bytes), false) => {
            let proof = decode_proof(bytes, vd, &format!("{label} aggregate-list proof"))?;
            let actual = aggregate_list_chain(&proof)?;
            if actual != expected_chain {
                return Err(ValidityProverServiceError::Snapshot(format!(
                    "{label} aggregate-list proof commits to {actual}, expected {expected_chain}"
                )));
            }
            Ok(())
        }
        (None, false) => Err(ValidityProverServiceError::Snapshot(format!(
            "{label} nonzero signature chain has no aggregate-list proof"
        ))),
        (Some(_), true) => Err(ValidityProverServiceError::Snapshot(format!(
            "{label} zero signature chain unexpectedly has an aggregate-list proof"
        ))),
    }
}

fn parse_block_chain_public_inputs(
    proof: &ValidityProof,
    vd: &VerifierCircuitData<F, C, D>,
) -> Result<BlockChainPublicInputs<F, C, D>, ValidityProverServiceError> {
    let values: Vec<u64> = proof
        .public_inputs
        .iter()
        .map(|field| field.to_canonical_u64())
        .collect();
    let parsed = BlockChainPublicInputs::<F, C, D>::from_u64_slice(&values, &vd.common.config)
        .map_err(|e| {
            ValidityProverServiceError::Snapshot(format!(
                "parse block-chain proof public inputs: {e}"
            ))
        })?;
    if parsed.vd.circuit_digest != vd.verifier_only.circuit_digest {
        return Err(ValidityProverServiceError::Snapshot(
            "block-chain proof embeds verifier data for a different circuit".into(),
        ));
    }
    Ok(parsed)
}

fn verify_validity_public_hash(
    proof: &ValidityProof,
    initial: &ExtendedPublicState,
    final_state: &ExtendedPublicState,
    prover: Address,
) -> Result<(), ValidityProverServiceError> {
    let actual = public_bytes32(&proof.public_inputs, "validity public-input hash")?;
    let expected = ValidityPublicInputs::from_states(initial, final_state, prover).hash();
    if actual != expected {
        return Err(ValidityProverServiceError::Snapshot(format!(
            "validity proof public hash {actual} does not bind the stored span {expected}"
        )));
    }
    Ok(())
}

fn aggregate_list_chain(proof: &ValidityProof) -> Result<Bytes32, ValidityProverServiceError> {
    if proof.public_inputs.len() < BYTES32_LEN {
        return Err(ValidityProverServiceError::Snapshot(
            "aggregate-list proof has fewer than 8 public inputs".into(),
        ));
    }
    public_bytes32(
        &proof.public_inputs[..BYTES32_LEN],
        "aggregate-list commitment",
    )
}

fn public_bytes32(values: &[F], label: &str) -> Result<Bytes32, ValidityProverServiceError> {
    if values.len() != BYTES32_LEN {
        return Err(ValidityProverServiceError::Snapshot(format!(
            "{label} has {} limbs, expected {BYTES32_LEN}",
            values.len()
        )));
    }
    let limbs = values
        .iter()
        .map(|value| {
            u32::try_from(value.to_canonical_u64()).map_err(|_| {
                ValidityProverServiceError::Snapshot(format!(
                    "{label} contains a non-u32 field element"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Bytes32::from_u32_slice(&limbs)
        .map_err(|e| ValidityProverServiceError::Snapshot(format!("parse {label}: {e}")))
}

fn decode_extended_state(
    values: &[u64],
) -> Result<ExtendedPublicState, ValidityProverServiceError> {
    ExtendedPublicState::from_u64_slice(values).map_err(|e| {
        ValidityProverServiceError::Snapshot(format!("decode extended public state: {e}"))
    })
}

fn decode_optional_proof(
    bytes: Option<&[u8]>,
    vd: &VerifierCircuitData<F, C, D>,
    label: &str,
) -> Result<Option<ValidityProof>, ValidityProverServiceError> {
    bytes
        .map(|bytes| decode_proof(bytes, vd, label))
        .transpose()
}

fn decode_proof(
    bytes: &[u8],
    vd: &VerifierCircuitData<F, C, D>,
    label: &str,
) -> Result<ValidityProof, ValidityProverServiceError> {
    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(bytes.to_vec(), &vd.common)
        .map_err(|e| ValidityProverServiceError::Snapshot(format!("decode {label}: {e}")))?;
    vd.verify(proof.clone())
        .map_err(|e| ValidityProverServiceError::Snapshot(format!("verify {label}: {e}")))?;
    Ok(proof)
}

fn candidate_hash(candidate: &CandidateCheckpoint) -> Result<Bytes32, ValidityProverServiceError> {
    let mut material = candidate.clone();
    material.receipt.candidate_id = Bytes32::default();
    hash_serializable(&material)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcknowledgementFingerprint<'a> {
    domain: &'static str,
    candidate_id: Bytes32,
    acknowledgement: &'a L1ValidityAcknowledgement,
}

fn acknowledgement_fingerprint(
    candidate_id: Bytes32,
    acknowledgement: &L1ValidityAcknowledgement,
) -> Result<Bytes32, ValidityProverServiceError> {
    hash_serializable(&AcknowledgementFingerprint {
        domain: "INTMAX_VALIDITY_L1_ACK_V1",
        candidate_id,
        acknowledgement,
    })
}

fn finalization_receipt(
    record: &AcknowledgementRecord,
    committed_producer_receipt: BlockProducerReceipt,
) -> ValidityFinalizationReceipt {
    ValidityFinalizationReceipt {
        request_id: record.request_id.clone(),
        candidate_id: record.candidate_id,
        producer_anchor: record.finalized_anchor.clone(),
        finalized_block_number: record.finalized_anchor.block_number,
        final_extended_state_commitment: record.acknowledgement.final_extended_state_commitment,
        committed_producer_receipt,
        l1_acknowledgement: record.acknowledgement.clone(),
    }
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<Bytes32, ValidityProverServiceError> {
    let bytes = serde_json::to_vec(value).map_err(|e| {
        ValidityProverServiceError::Snapshot(format!("canonical checkpoint serialization: {e}"))
    })?;
    Bytes32::from_bytes_be(&keccak_hash::keccak(bytes).0)
        .map_err(|e| ValidityProverServiceError::Snapshot(format!("convert checkpoint hash: {e}")))
}

fn validate_supported_user_counts(counts: &[u32]) -> Result<(), ValidityProverServiceError> {
    if counts.is_empty()
        || counts.iter().any(|count| *count == 0)
        || counts.windows(2).any(|window| window[0] >= window[1])
    {
        return Err(ValidityProverServiceError::InvalidConfiguration(
            "supported user counts must be non-empty, non-zero and strictly increasing".into(),
        ));
    }
    Ok(())
}

fn validate_request_id(request_id: &str) -> Result<(), ValidityProverServiceError> {
    if request_id.is_empty()
        || request_id.len() > MAX_REQUEST_ID_BYTES
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ValidityProverServiceError::InvalidRequest(format!(
            "requestId must be 1..={MAX_REQUEST_ID_BYTES} ASCII identifier characters"
        )));
    }
    Ok(())
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn peak_rss_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` points to writable storage for `getrusage` to initialize.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return 0;
    }
    // SAFETY: `getrusage` returned success and initialized the structure.
    let max_rss = unsafe { usage.assume_init() }.ru_maxrss.max(0) as u64;
    #[cfg(target_os = "macos")]
    {
        max_rss
    }
    #[cfg(not(target_os = "macos"))]
    {
        max_rss.saturating_mul(1024)
    }
}

fn prepare_snapshot_path(path: &Path) -> Result<PathBuf, ValidityProverServiceError> {
    let path = path.to_path_buf();
    let parent = snapshot_parent(&path);
    fs::create_dir_all(parent).map_err(|e| {
        ValidityProverServiceError::Snapshot(format!(
            "create snapshot directory {}: {e}",
            parent.display()
        ))
    })?;
    reject_symlink(&path, "snapshot")?;
    Ok(path)
}

fn read_snapshot(path: &Path) -> Result<ValidityProverSnapshot, ValidityProverServiceError> {
    let metadata = fs::metadata(path).map_err(|e| {
        ValidityProverServiceError::Snapshot(format!("stat snapshot {}: {e}", path.display()))
    })?;
    if !metadata.is_file()
        || metadata.len() < SNAPSHOT_HEADER_BYTES as u64
        || metadata.len() > MAX_SNAPSHOT_BYTES
    {
        return Err(ValidityProverServiceError::Snapshot(format!(
            "snapshot {} size/type is invalid ({})",
            path.display(),
            metadata.len()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|e| {
            ValidityProverServiceError::Snapshot(format!("read snapshot {}: {e}", path.display()))
        })?;
    if &bytes[..16] != SNAPSHOT_MAGIC {
        return Err(ValidityProverServiceError::Snapshot(
            "snapshot magic mismatch".into(),
        ));
    }
    let version = u32::from_le_bytes(bytes[16..20].try_into().expect("fixed header"));
    if version != VALIDITY_PROVER_SNAPSHOT_VERSION {
        return Err(ValidityProverServiceError::Snapshot(format!(
            "unsupported snapshot version {version}"
        )));
    }
    let payload_len = u64::from_le_bytes(bytes[20..28].try_into().expect("fixed header"));
    if payload_len > MAX_SNAPSHOT_BYTES
        || SNAPSHOT_HEADER_BYTES
            .checked_add(payload_len as usize)
            .filter(|expected| *expected == bytes.len())
            .is_none()
    {
        return Err(ValidityProverServiceError::Snapshot(
            "snapshot payload length is truncated or has trailing data".into(),
        ));
    }
    let payload = &bytes[SNAPSHOT_HEADER_BYTES..];
    if keccak_hash::keccak(payload).0.as_slice() != &bytes[28..60] {
        return Err(ValidityProverServiceError::Snapshot(
            "snapshot checksum mismatch".into(),
        ));
    }
    let (disk, consumed) = bincode::serde::decode_from_slice::<ValidityProverSnapshot, _>(
        payload,
        bincode::config::standard(),
    )
    .map_err(|e| ValidityProverServiceError::Snapshot(format!("decode snapshot payload: {e}")))?;
    if consumed != payload.len() {
        return Err(ValidityProverServiceError::Snapshot(
            "snapshot bincode payload has trailing data".into(),
        ));
    }
    Ok(disk)
}

fn persist_snapshot(
    path: &Path,
    disk: &ValidityProverSnapshot,
) -> Result<(), ValidityProverServiceError> {
    let payload = bincode::serde::encode_to_vec(disk, bincode::config::standard())
        .map_err(|e| ValidityProverServiceError::Snapshot(format!("encode snapshot: {e}")))?;
    let total_len = SNAPSHOT_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| ValidityProverServiceError::Snapshot("snapshot size overflow".into()))?;
    if total_len as u64 > MAX_SNAPSHOT_BYTES {
        return Err(ValidityProverServiceError::Snapshot(format!(
            "serialized snapshot size {total_len} exceeds {MAX_SNAPSHOT_BYTES}"
        )));
    }
    let mut encoded = Vec::with_capacity(total_len);
    encoded.extend_from_slice(SNAPSHOT_MAGIC);
    encoded.extend_from_slice(&VALIDITY_PROVER_SNAPSHOT_VERSION.to_le_bytes());
    encoded.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    encoded.extend_from_slice(&keccak_hash::keccak(&payload).0);
    encoded.extend_from_slice(&payload);

    let parent = snapshot_parent(path);
    let file_name = path.file_name().ok_or_else(|| {
        ValidityProverServiceError::InvalidConfiguration(format!(
            "snapshot path {} has no file name",
            path.display()
        ))
    })?;
    let generation = disk.finalized.anchor.generation
        + disk
            .candidate
            .as_ref()
            .map_or(0, |candidate| candidate.receipt.producer_anchor.generation);
    let tmp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        file_name.to_string_lossy(),
        std::process::id(),
        generation
    ));
    reject_symlink(&tmp_path, "snapshot temporary file")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| {
            ValidityProverServiceError::Snapshot(format!(
                "create temporary snapshot {}: {e}",
                tmp_path.display()
            ))
        })?;
    let result = (|| {
        file.write_all(&encoded)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, path)?;
        File::open(parent)?.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&tmp_path);
        return Err(ValidityProverServiceError::Snapshot(format!(
            "atomically persist snapshot {}: {error}",
            path.display()
        )));
    }
    verify_private_mode(path, "snapshot")?;
    Ok(())
}

fn verify_private_mode(path: &Path, label: &str) -> Result<(), ValidityProverServiceError> {
    let mode = fs::metadata(path)
        .map_err(|e| ValidityProverServiceError::Snapshot(format!("stat {label}: {e}")))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(ValidityProverServiceError::Snapshot(format!(
            "{label} {} has mode {mode:o}; required 600",
            path.display()
        )));
    }
    Ok(())
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), ValidityProverServiceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ValidityProverServiceError::Snapshot(format!(
                "{label} {} must not be a symlink",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ValidityProverServiceError::Snapshot(format!(
            "inspect {label} {}: {error}",
            path.display()
        ))),
    }
}

fn snapshot_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

struct SnapshotLock {
    file: File,
}

impl SnapshotLock {
    fn acquire(snapshot_path: &Path) -> Result<Self, ValidityProverServiceError> {
        let mut lock_name = snapshot_path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        reject_symlink(&lock_path, "snapshot lock")?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| {
                ValidityProverServiceError::Snapshot(format!(
                    "open snapshot lock {}: {e}",
                    lock_path.display()
                ))
            })?;
        verify_private_mode(&lock_path, "snapshot lock")?;
        // SAFETY: `file` owns this descriptor for the lifetime of `SnapshotLock`.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(ValidityProverServiceError::Locked(format!(
                "{} ({})",
                lock_path.display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { file })
    }
}

impl Drop for SnapshotLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains valid until after this Drop implementation returns.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(test)]
mod l1_evidence_tests {
    use super::*;

    fn word(tag: u32) -> Bytes32 {
        Bytes32::from_u32_slice(&[tag; 8]).expect("bytes32")
    }

    fn rollup() -> Address {
        Address::from_u32_slice(&[0x1234_5678; 5]).expect("address")
    }

    fn config() -> L1FinalizationRpcConfig {
        L1FinalizationRpcConfig {
            rpc_url: "http://127.0.0.1:8545".into(),
            expected_chain_id: 11_155_111,
            rollup: rollup(),
            expected_rollup_runtime_code_hash: word(0x44),
            minimum_confirmations: 3,
            allow_unfinalized_devnet: false,
        }
    }

    fn evidence(root: Bytes32, tx: Bytes32) -> L1FinalizationEvidence {
        let receipt = ParsedReceipt {
            transaction_hash: tx,
            status: 1,
            block_number: 100,
            block_hash: word(100),
            to: rollup(),
            finalized_roots: vec![root],
        };
        L1FinalizationEvidence {
            chain_id: 11_155_111,
            first_receipt: receipt.clone(),
            second_receipt: receipt,
            head_before: ParsedBlock {
                number: 102,
                hash: word(102),
                parent_hash: word(101),
            },
            head_after: ParsedBlock {
                number: 102,
                hash: word(102),
                parent_hash: word(101),
            },
            canonical_head_before: ParsedBlock {
                number: 102,
                hash: word(102),
                parent_hash: word(101),
            },
            canonical_receipt_block: ParsedBlock {
                number: 100,
                hash: word(100),
                parent_hash: word(99),
            },
            rollup_runtime_code_hash: word(0x44),
            root_membership: true,
            latest_finalized_root: root,
            latest_finalized_block_number: 7,
        }
    }

    fn authority_evidence(root: Bytes32, intmax_block: u64) -> L1StateAuthorityEvidence {
        let head = ParsedBlock {
            number: 102,
            hash: word(102),
            parent_hash: word(101),
        };
        L1StateAuthorityEvidence {
            chain_id: 11_155_111,
            source: L1FinalitySource::RpcFinalized,
            head_before: head.clone(),
            canonical_head_before: head.clone(),
            head_after: head,
            rollup_runtime_code_hash: word(0x44),
            root_membership: true,
            latest_finalized_root: root,
            latest_finalized_block_number: intmax_block,
        }
    }

    #[test]
    fn canonical_finalization_evidence_is_accepted() {
        let root = word(7);
        let tx = word(9);
        validate_l1_finalization_evidence(&evidence(root, tx), &config(), tx, root, 7)
            .expect("complete evidence");
    }

    #[test]
    fn substituted_rollup_runtime_code_is_rejected() {
        let root = word(7);
        let tx = word(9);
        let mut substituted = evidence(root, tx);
        substituted.rollup_runtime_code_hash = word(0x45);
        assert!(validate_l1_finalization_evidence(&substituted, &config(), tx, root, 7).is_err());

        let mut substituted_authority = authority_evidence(root, 7);
        substituted_authority.rollup_runtime_code_hash = word(0x45);
        assert!(
            validate_l1_state_authority_evidence(&substituted_authority, &config(), root, 7, None,)
                .is_err()
        );
    }

    #[test]
    fn runtime_code_hash_rejects_empty_or_malformed_code() {
        assert_eq!(
            runtime_code_hash("0x6000", "rollup").expect("valid runtime code"),
            Bytes32::from_bytes_be(&keccak_hash::keccak([0x60, 0x00]).0).expect("bytes32")
        );
        assert!(runtime_code_hash("0x", "rollup").is_err());
        assert!(runtime_code_hash("6000", "rollup").is_err());
        assert!(runtime_code_hash("0x0", "rollup").is_err());
        assert!(runtime_code_hash("0xgg", "rollup").is_err());
    }

    #[test]
    fn fresh_snapshot_is_bound_to_current_rollup_state_without_an_acknowledgement() {
        let root = word(7);
        validate_l1_state_authority_evidence(
            &authority_evidence(root, 7),
            &config(),
            root,
            7,
            None,
        )
        .expect("fresh snapshot matches current finalized rollup state");

        // This is the attack path that receipt-only restart validation missed: local disk still
        // contains genesis/old state while another prover has advanced the rollup.
        let mut stale = authority_evidence(word(8), 8);
        assert!(validate_l1_state_authority_evidence(&stale, &config(), root, 7, None).is_err());

        stale.latest_finalized_root = root;
        stale.latest_finalized_block_number = 7;
        stale.root_membership = false;
        assert!(validate_l1_state_authority_evidence(&stale, &config(), root, 7, None).is_err());
    }

    #[test]
    fn startup_allows_only_the_exact_pending_candidate_without_promoting_it() {
        let local_root = word(7);
        let candidate_root = word(8);
        let pending = PendingL1Candidate {
            root: candidate_root,
            intmax_block: 8,
        };
        validate_l1_state_authority_evidence(
            &authority_evidence(candidate_root, 8),
            &config(),
            local_root,
            7,
            Some(pending),
        )
        .expect("exact durable pending candidate is a recoverable pre-ACK state");

        assert!(
            validate_l1_state_authority_evidence(
                &authority_evidence(word(9), 8),
                &config(),
                local_root,
                7,
                Some(pending),
            )
            .is_err(),
            "a sibling root at the candidate height must fail closed"
        );
        assert!(
            validate_l1_state_authority_evidence(
                &authority_evidence(candidate_root, 9),
                &config(),
                local_root,
                7,
                Some(pending),
            )
            .is_err(),
            "a later untracked state must fail closed"
        );
        let mut missing_local_history = authority_evidence(candidate_root, 8);
        missing_local_history.root_membership = false;
        assert!(
            validate_l1_state_authority_evidence(
                &missing_local_history,
                &config(),
                local_root,
                7,
                Some(pending),
            )
            .is_err(),
            "the predecessor must remain in the finalized-root set"
        );
    }

    #[test]
    fn state_binding_rejects_head_change_after_pinned_rollup_reads() {
        let root = word(7);
        let mut moved = authority_evidence(root, 7);
        moved.head_after = ParsedBlock {
            number: 103,
            hash: word(103),
            parent_hash: word(102),
        };
        assert!(validate_l1_state_authority_evidence(&moved, &config(), root, 7, None).is_err());
    }

    #[test]
    fn acknowledgement_cannot_regress_or_replace_startup_authority() {
        let earlier = L1FinalizedCheckpoint {
            chain_id: 11_155_111,
            block_number: 102,
            block_hash: word(102),
            parent_hash: word(101),
            source: L1FinalitySource::RpcFinalized,
        };
        let mut later = earlier;
        later.block_hash = word(999);
        assert!(validate_checkpoint_progression(&earlier, &later).is_err());

        later = earlier;
        later.block_number = 101;
        later.block_hash = word(101);
        later.parent_hash = word(100);
        assert!(validate_checkpoint_progression(&earlier, &later).is_err());

        later.block_number = 103;
        later.block_hash = word(103);
        later.parent_hash = word(102);
        validate_checkpoint_progression(&earlier, &later).expect("monotonic durable authority");
    }

    #[test]
    fn replayed_acknowledgement_must_match_its_exact_canonical_receipt() {
        let stored = L1ValidityAcknowledgement {
            chain_id: 11_155_111,
            transaction_hash: word(9),
            block_hash: word(100),
            block_number: 100,
            final_extended_state_commitment: word(7),
            finalized_checkpoint: L1FinalizedCheckpoint {
                chain_id: 11_155_111,
                block_number: 102,
                block_hash: word(102),
                parent_hash: word(101),
                source: L1FinalitySource::RpcFinalized,
            },
        };
        validate_replayed_acknowledgement(&stored, &stored).expect("exact receipt replay");

        let mut orphaned = stored.clone();
        orphaned.block_hash = word(999);
        assert!(validate_replayed_acknowledgement(&stored, &orphaned).is_err());

        let mut substituted = stored.clone();
        substituted.transaction_hash = word(10);
        assert!(validate_replayed_acknowledgement(&stored, &substituted).is_err());
    }

    #[test]
    fn historical_ack_replay_allows_later_roots_but_not_orphaned_membership_or_regression() {
        let root = word(7);
        let tx = word(9);
        let mut historical = evidence(root, tx);
        historical.latest_finalized_block_number = 8;
        historical.latest_finalized_root = word(8);
        assert!(
            validate_l1_finalization_evidence(&historical, &config(), tx, root, 7).is_err(),
            "a new acknowledgement must still be the latest rollup state"
        );
        validate_l1_finalization_evidence_at_position(
            &historical,
            &config(),
            tx,
            root,
            7,
            FinalizationPosition::Historical,
        )
        .expect("a canonical historical receipt remains replayable after later finalization");

        historical.root_membership = false;
        assert!(
            validate_l1_finalization_evidence_at_position(
                &historical,
                &config(),
                tx,
                root,
                7,
                FinalizationPosition::Historical,
            )
            .is_err()
        );
        historical.root_membership = true;
        historical.latest_finalized_block_number = 6;
        assert!(
            validate_l1_finalization_evidence_at_position(
                &historical,
                &config(),
                tx,
                root,
                7,
                FinalizationPosition::Historical,
            )
            .is_err()
        );
    }

    #[test]
    fn forged_ack_without_event_or_membership_is_rejected() {
        let root = word(7);
        let tx = word(9);
        let mut forged = evidence(root, tx);
        forged.first_receipt.finalized_roots.clear();
        forged.second_receipt.finalized_roots.clear();
        assert!(validate_l1_finalization_evidence(&forged, &config(), tx, root, 7).is_err());

        let mut forged = evidence(root, tx);
        forged.root_membership = false;
        assert!(validate_l1_finalization_evidence(&forged, &config(), tx, root, 7).is_err());

        let mut reverted = evidence(root, tx);
        reverted.first_receipt.status = 0;
        reverted.second_receipt.status = 0;
        assert!(validate_l1_finalization_evidence(&reverted, &config(), tx, root, 7).is_err());

        let mut wrong_chain = evidence(root, tx);
        wrong_chain.chain_id = 1;
        assert!(validate_l1_finalization_evidence(&wrong_chain, &config(), tx, root, 7).is_err());
    }

    #[test]
    fn reorged_or_not_yet_finalized_receipt_is_rejected() {
        let root = word(7);
        let tx = word(9);
        let mut reorged = evidence(root, tx);
        reorged.canonical_receipt_block.hash = word(101);
        assert!(validate_l1_finalization_evidence(&reorged, &config(), tx, root, 7).is_err());

        let mut above_finalized = evidence(root, tx);
        above_finalized.head_before.number = 99;
        above_finalized.head_before.hash = word(99);
        above_finalized.head_before.parent_hash = word(98);
        above_finalized.canonical_head_before = above_finalized.head_before.clone();
        assert!(
            validate_l1_finalization_evidence(&above_finalized, &config(), tx, root, 7).is_err()
        );
    }

    #[test]
    fn same_height_finalized_replacement_and_stale_local_snapshot_are_rejected() {
        let root = word(7);
        let tx = word(9);
        let mut replacement = evidence(root, tx);
        replacement.canonical_head_before.hash = word(999);
        assert!(validate_l1_finalization_evidence(&replacement, &config(), tx, root, 7).is_err());

        let mut stale = evidence(root, tx);
        stale.latest_finalized_block_number = 8;
        stale.latest_finalized_root = word(8);
        assert!(validate_l1_finalization_evidence(&stale, &config(), tx, root, 7).is_err());
    }

    #[test]
    fn unfinalized_escape_is_restricted_to_anvil() {
        let mut public = config();
        public.allow_unfinalized_devnet = true;
        assert!(public.validate().is_err());

        public.expected_chain_id = ANVIL_CHAIN_ID;
        assert!(public.validate().is_ok());
    }
}
