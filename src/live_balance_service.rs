//! Durable, wallet-owned base-layer balance IVC service.
//!
//! This is the production counterpart of the historical balance fixture harness. One process
//! keeps the spend and balance circuits resident, while the only durable secret state is a
//! versioned/checksummed snapshot protected by an exclusive process lock. Every producer receipt
//! is re-authenticated against the producer's semantically replayed journal before it can advance
//! the balance proof.

#![cfg(not(target_arch = "wasm32"))]

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd as _,
        unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
};

use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::{Deserialize, Serialize};

use crate::{
    block_producer::ProductionDepositRequest,
    block_producer_service::{
        BlockProducerReceipt, BlockProducerService, BlockProducerServiceError,
    },
    circuits::{
        balance::{
            balance_pis::BalanceFullPublicInputs, balance_processor::BalanceProcessor,
            common::recipient::calculate_recipient_from_user_id,
            spend_circuit::{SpendCircuit, SpendPublicInputs},
        },
        witness::balance_witness_generator::{
            BalanceWitnessGenerator, ReceiveDepositData, ReceiveTransferData, SendTxData,
            SingleWithdrawalData,
        },
        withdraw::{
            single_withdrawal_circuit::{
                SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN, SingleWithdawalCircuit,
                SingleWithdawalPublicInputs,
            },
            withdrawal_processor::WithdrawalProcessor,
            withdrawal_step::WithdrawalStepWitness,
        },
    },
    common::{
        balance_state::settled_tx_chain_push,
        channel::{ChannelRecord, ChannelState},
        channel_id::ChannelId,
        private_state::FullPrivateState,
        salt::Salt,
        trees::{transfer_tree::TransferTree, tx_tree::TxTree},
        tx::Tx,
        withdrawal::Withdrawal,
    },
    constants::BURN_CHANNEL_ID,
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
    utils::{
        conversion::ToU64 as _, poseidon_hash_out::PoseidonHashOut,
        serialize::serialize_verifier_data,
    },
    wallet_core::{
        C, ChannelBalanceAttestation, ChannelSnapshot, D, F, InterChannelDebitPayload,
        InterChannelTransferDescriptor, MemberInfo, canonical_inter_channel_base_transfer,
        inter_channel_tx_v2, verify_all_signatures, verify_inter_channel_credit_states,
        verify_inter_channel_descriptor_matches_debit, verify_snapshot,
    },
};

const SNAPSHOT_MAGIC: &[u8; 16] = b"IMLIVEBALANCE001";
// v2: `StoredInterChannelSendMaterial` gained `tx_leaf`, and `balance_proof` changed meaning
// from the POST-send head proof to the PRE-send proof a ReceiveTransfer can actually connect
// (receive_transfer_circuit.rs:263). v1 journals stored a proof that could never serve a
// receive, so they are rejected fail-closed by version rather than by a confusing serde error.
pub const LIVE_BALANCE_SNAPSHOT_VERSION: u32 = 2;
const SNAPSHOT_HEADER_BYTES: usize = 16 + 4 + 8 + 32;
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_APPLIED_TRANSITIONS: usize = 1_000_000;

type BalanceProof = ProofWithPublicInputs<F, C, D>;

#[derive(Debug, thiserror::Error)]
pub enum LiveBalanceServiceError {
    #[error("invalid live balance request: {0}")]
    InvalidRequest(String),
    #[error("producer reconciliation failed: {0}")]
    ProducerReconciliation(String),
    #[error("balance transition failed: {0}")]
    Transition(String),
    #[error("snapshot verification failed: {0}")]
    Snapshot(String),
    #[error("snapshot is locked by another live balance service: {0}")]
    Locked(String),
    #[error("service is fail-closed after an uncertain persistence result; restart required")]
    Poisoned,
}

impl LiveBalanceServiceError {
    /// Stable machine-readable code for the JSONL daemon's error envelope (the same contract the
    /// producer and validity services expose).
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "live_invalid_request",
            Self::ProducerReconciliation(_) => "live_producer_reconciliation",
            Self::Transition(_) => "live_transition",
            Self::Snapshot(_) => "live_snapshot",
            Self::Locked(_) => "live_locked",
            Self::Poisoned => "live_poisoned",
        }
    }
}

impl From<BlockProducerServiceError> for LiveBalanceServiceError {
    fn from(value: BlockProducerServiceError) -> Self {
        Self::ProducerReconciliation(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveBalanceReceipt {
    pub producer_request_id: String,
    pub producer_generation: u64,
    pub producer_entry_hash: Bytes32,
    pub producer_extended_state_commitment: Bytes32,
    pub balance_generation: u64,
    pub base_nonce: u32,
    pub private_commitment: PoseidonHashOut,
    pub settled_tx_chain: Bytes32,
    pub proof_size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveBalanceStatus {
    pub snapshot_version: u32,
    pub channel_id: ChannelId,
    pub balance_generation: u64,
    pub base_nonce: u32,
    pub private_commitment: PoseidonHashOut,
    pub settled_tx_chain: Bytes32,
    pub proof_size: usize,
    pub processed_producer_generation: Option<u64>,
    pub processed_producer_commitment: Option<Bytes32>,
    pub signed_head_digest: Option<Bytes32>,
    pub applied_transition_count: usize,
    pub awaiting_channel_binding: bool,
}

/// Public response from the production initializer. The two salts and every private tree remain
/// exclusively inside the 0600 live snapshot; callers only receive the deposit recipient they
/// must put on L1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveBalanceInitialization {
    pub channel_id: ChannelId,
    pub deposit_recipient: Bytes32,
}

/// Authenticated public base cursor projected to wallets before they build/co-sign a send. It
/// deliberately contains no `FullPrivateState`; the proof commitment authenticates that state
/// while the durable live service remains its sole owner.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveBaseHeadArtifact {
    pub snapshot_version: u32,
    pub channel_id: ChannelId,
    pub balance_generation: u64,
    pub base_nonce: u32,
    pub private_commitment: PoseidonHashOut,
    pub settled_tx_chain: Bytes32,
    pub proof_size: usize,
    pub producer_receipt: Option<BlockProducerReceipt>,
    pub signed_head_digest: Option<Bytes32>,
    pub awaiting_channel_binding: bool,
}

/// The proved L1 withdrawal leg of one settled burn: the final withdrawal-chain proof (the shape
/// `withdrawNative`/`withdrawERC20` verify after MLE wrapping) and the leaf READ FROM ITS PUBLIC
/// INPUTS. Not serialized as-is — the wrapping stage consumes it in-process.
#[derive(Debug)]
pub struct BurnWithdrawalProof {
    pub withdrawal: Withdrawal,
    pub withdrawal_prover: Address,
    pub proof: plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>,
    pub withdrawal_vd: plonky2::plonk::circuit_data::VerifierCircuitData<F, C, D>,
}

/// Public channel backing projection: a verifiable balance proof, its exact base cursor, and the
/// N-of-N channel head/record that the proof's settle chain must equal.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveChannelBackingArtifact {
    pub base_head: LiveBaseHeadArtifact,
    pub balance_attestation: ChannelBalanceAttestation,
    /// Canonical verifier-data bytes for the resident `BalanceProcessor`. Wallets can therefore
    /// verify the projected attestation without rebuilding a circuit or trusting a stale local
    /// `balance_vd.bin` fixture.
    pub balance_verifier_data: Vec<u8>,
    pub channel_record: ChannelRecord,
    pub signed_head: ChannelState,
}

/// Public proof material exported by a durable source send and consumed by the destination's
/// `ReceiveTransfer` proof. Both proofs are independently verified on import.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveInterChannelSendArtifact {
    pub producer_receipt: BlockProducerReceipt,
    pub source_backing: LiveChannelBackingArtifact,
    pub spend_proof: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppliedTransition {
    request_id: String,
    request_fingerprint: Bytes32,
    producer_receipt: BlockProducerReceipt,
    result: LiveBalanceReceipt,
    send_material: Option<StoredInterChannelSendMaterial>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredInterChannelSendMaterial {
    balance_proof: Vec<u8>,
    spend_proof: Vec<u8>,
    /// The leaf this send pushed onto the settled chain: the canonical base Transfer's
    /// `aux_data` — the tx leaf for a normal inter-channel send, the burn descriptor for a burn
    /// (`send_tx_circuit.rs:178-183` pushes exactly `transfer.aux_data`, and the wallet builder
    /// pushes the same value onto the channel head, wallet_core.rs:2567). Stored so every
    /// validation site can bind the PRE-send balance proof to the POST-send signed head with
    /// `settled_tx_chain_push(pre.settled_tx_chain, settled_leaf) == signed_head...chain` —
    /// the pre-send-correct form of the retired post-send chain comparison, and strictly
    /// stronger: it pins the transition CONTENT, not just the endpoint.
    settled_leaf: Bytes32,
    channel_record: ChannelRecord,
    signed_head: ChannelState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveBalanceSnapshot {
    channel_id: ChannelId,
    balance_generation: u64,
    balance_proof: Vec<u8>,
    full_private_state: FullPrivateState,
    /// Explicit base-account cursor. It is deliberately duplicated and checked against both the
    /// private state and sent-tx tree at every startup and before every send.
    base_nonce: u32,
    channel_record: Option<ChannelRecord>,
    channel_members: Option<Vec<MemberInfo>>,
    signed_head: Option<ChannelState>,
    /// True after a validity-backed deposit proof is durable but before the corresponding
    /// N-of-N genesis snapshot has been created and bound.
    awaiting_channel_binding: bool,
    /// Production setup deposit salt, generated by Rust's OS RNG and never exposed. It remains
    /// until `bind_signed_snapshot` succeeds so a crash between prove and bind is recoverable.
    pending_deposit_salt: Option<Salt>,
    applied: Vec<AppliedTransition>,
}

/// A live service owns one snapshot lock and one in-memory circuit set for its whole lifetime.
pub struct LiveBalanceService {
    snapshot_path: PathBuf,
    _snapshot_lock: SnapshotLock,
    disk: LiveBalanceSnapshot,
    spend: SpendCircuit<F, C, D>,
    balance: BalanceProcessor<F, C, D>,
    poisoned: bool,
}

impl LiveBalanceService {
    /// Create a fresh base account. This does not require channel registration: the intended
    /// launch sequence is L1 deposit -> balance receive -> deposit-backed signed genesis ->
    /// producer registration. The first receive binds the proof to that N-of-N signed snapshot.
    pub fn initialize(
        snapshot_path: impl AsRef<Path>,
        channel_id: ChannelId,
        salt: Salt,
    ) -> Result<Self, LiveBalanceServiceError> {
        Self::initialize_inner(snapshot_path.as_ref(), channel_id, salt, None)
    }

    /// Production initializer: generate both the private-account salt and the one-time deposit
    /// recipient salt from the operating system RNG. Only the derived recipient leaves this
    /// service; the salts are persisted under the snapshot's 0600/lock/checksum envelope.
    pub fn initialize_production(
        snapshot_path: impl AsRef<Path>,
        channel_id: ChannelId,
    ) -> Result<(Self, LiveBalanceInitialization), LiveBalanceServiceError> {
        let mut rng = rand::rngs::OsRng;
        let account_salt = Salt::rand(&mut rng);
        let deposit_salt = Salt::rand(&mut rng);
        let deposit_recipient = calculate_recipient_from_user_id(channel_id, deposit_salt);
        let service = Self::initialize_inner(
            snapshot_path.as_ref(),
            channel_id,
            account_salt,
            Some(deposit_salt),
        )?;
        Ok((
            service,
            LiveBalanceInitialization {
                channel_id,
                deposit_recipient,
            },
        ))
    }

    fn initialize_inner(
        snapshot_path: &Path,
        channel_id: ChannelId,
        salt: Salt,
        pending_deposit_salt: Option<Salt>,
    ) -> Result<Self, LiveBalanceServiceError> {
        let snapshot_path = prepare_snapshot_path(snapshot_path)?;
        if snapshot_path.exists() {
            return Err(LiveBalanceServiceError::InvalidRequest(format!(
                "snapshot {} already exists; use open()",
                snapshot_path.display()
            )));
        }
        let snapshot_lock = SnapshotLock::acquire(&snapshot_path)?;
        let (spend, balance) = build_circuits();
        let proof = balance
            .prove_initial(channel_id, salt)
            .map_err(|e| LiveBalanceServiceError::Transition(format!("initial proof: {e}")))?;
        let disk = LiveBalanceSnapshot {
            channel_id,
            balance_generation: 0,
            balance_proof: proof.to_bytes(),
            full_private_state: FullPrivateState::new(salt),
            base_nonce: 0,
            channel_record: None,
            channel_members: None,
            signed_head: None,
            awaiting_channel_binding: false,
            pending_deposit_salt,
            applied: Vec::new(),
        };
        verify_snapshot_semantics(&disk, &spend, &balance, None)?;
        persist_snapshot(&snapshot_path, &disk)?;
        Ok(Self {
            snapshot_path,
            _snapshot_lock: snapshot_lock,
            disk,
            spend,
            balance,
            poisoned: false,
        })
    }

    /// Recover a snapshot, verify its proof/private commitment/signed head, and reconcile its last
    /// producer checkpoint against the producer's independently replayed journal.
    pub fn open(
        snapshot_path: impl AsRef<Path>,
        producer: &BlockProducerService,
    ) -> Result<Self, LiveBalanceServiceError> {
        let snapshot_path = prepare_snapshot_path(snapshot_path.as_ref())?;
        if !snapshot_path.exists() {
            return Err(LiveBalanceServiceError::InvalidRequest(format!(
                "snapshot {} does not exist; use initialize()",
                snapshot_path.display()
            )));
        }
        verify_private_mode(&snapshot_path, "snapshot")?;
        let snapshot_lock = SnapshotLock::acquire(&snapshot_path)?;
        let disk = read_snapshot(&snapshot_path)?;
        let (spend, balance) = build_circuits();
        verify_snapshot_semantics(&disk, &spend, &balance, Some(producer))?;
        Ok(Self {
            snapshot_path,
            _snapshot_lock: snapshot_lock,
            disk,
            spend,
            balance,
            poisoned: false,
        })
    }

    pub fn status(&self) -> Result<LiveBalanceStatus, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        let proof = decode_balance_proof(&self.disk, &self.balance)?;
        let pis = balance_public_inputs(&proof, &self.balance)?;
        let last = self.disk.applied.last();
        Ok(LiveBalanceStatus {
            snapshot_version: LIVE_BALANCE_SNAPSHOT_VERSION,
            channel_id: self.disk.channel_id,
            balance_generation: self.disk.balance_generation,
            base_nonce: self.disk.base_nonce,
            private_commitment: pis.private_commitment,
            settled_tx_chain: pis.settled_tx_chain,
            proof_size: self.disk.balance_proof.len(),
            processed_producer_generation: last.map(|entry| entry.producer_receipt.generation),
            processed_producer_commitment: last
                .map(|entry| entry.producer_receipt.extended_state_commitment),
            signed_head_digest: self.disk.signed_head.as_ref().map(|state| state.digest),
            applied_transition_count: self.disk.applied.len(),
            awaiting_channel_binding: self.disk.awaiting_channel_binding,
        })
    }

    pub fn attestation(&self) -> Result<ChannelBalanceAttestation, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        Ok(ChannelBalanceAttestation {
            balance_proof: self.disk.balance_proof.clone(),
        })
    }

    pub fn base_nonce(&self) -> Result<u32, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        Ok(self.disk.base_nonce)
    }

    pub fn configured_deposit_recipient(&self) -> Result<Option<Bytes32>, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        Ok(self
            .disk
            .pending_deposit_salt
            .map(|salt| calculate_recipient_from_user_id(self.disk.channel_id, salt)))
    }

    /// Allocate and durably persist a fresh one-time deposit recipient for a later top-up. Only
    /// the derived public recipient is returned; its salt stays inside this service.
    pub fn prepare_deposit_recipient(&mut self) -> Result<Bytes32, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        if self.disk.awaiting_channel_binding {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "finish binding the current deposit before allocating another recipient".into(),
            ));
        }
        if let Some(recipient) = self.configured_deposit_recipient()? {
            return Ok(recipient);
        }
        let mut rng = rand::rngs::OsRng;
        let salt = Salt::rand(&mut rng);
        let recipient = calculate_recipient_from_user_id(self.disk.channel_id, salt);
        let mut candidate = self.disk.clone();
        candidate.pending_deposit_salt = Some(salt);
        self.commit(candidate)?;
        Ok(recipient)
    }

    pub fn base_head_artifact(&self) -> Result<LiveBaseHeadArtifact, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        let proof = decode_balance_proof(&self.disk, &self.balance)?;
        let pis = balance_public_inputs(&proof, &self.balance)?;
        Ok(LiveBaseHeadArtifact {
            snapshot_version: LIVE_BALANCE_SNAPSHOT_VERSION,
            channel_id: self.disk.channel_id,
            balance_generation: self.disk.balance_generation,
            base_nonce: self.disk.base_nonce,
            private_commitment: pis.private_commitment,
            settled_tx_chain: pis.settled_tx_chain,
            proof_size: self.disk.balance_proof.len(),
            producer_receipt: self
                .disk
                .applied
                .last()
                .map(|entry| entry.producer_receipt.clone()),
            signed_head_digest: self.disk.signed_head.as_ref().map(|head| head.digest),
            awaiting_channel_binding: self.disk.awaiting_channel_binding,
        })
    }

    pub fn channel_backing_artifact(
        &self,
    ) -> Result<LiveChannelBackingArtifact, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        let record = self.disk.channel_record.clone().ok_or_else(|| {
            LiveBalanceServiceError::InvalidRequest(
                "live balance proof is not yet bound to an N-of-N channel snapshot".into(),
            )
        })?;
        let signed_head = self.disk.signed_head.clone().ok_or_else(|| {
            LiveBalanceServiceError::InvalidRequest(
                "live balance proof has no bound N-of-N channel head".into(),
            )
        })?;
        Ok(LiveChannelBackingArtifact {
            base_head: self.base_head_artifact()?,
            balance_attestation: self.attestation()?,
            balance_verifier_data: serialize_verifier_data(&self.balance.balance_vd()).map_err(
                |error| {
                    LiveBalanceServiceError::Snapshot(format!(
                        "serialize resident balance verifier data: {error}"
                    ))
                },
            )?,
            channel_record: record,
            signed_head,
        })
    }

    /// Recover the crash-durable public proof bundle for any accepted source send. Destination
    /// settlement may lag later source sends, so this looks up the exact request rather than
    /// exporting only the current head.
    pub fn inter_channel_send_artifact(
        &self,
        producer_request_id: &str,
    ) -> Result<LiveInterChannelSendArtifact, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        let entry = self
            .disk
            .applied
            .iter()
            .find(|entry| entry.request_id == producer_request_id)
            .ok_or_else(|| {
                LiveBalanceServiceError::InvalidRequest(format!(
                    "unknown settled producer request {producer_request_id:?}"
                ))
            })?;
        let material = entry.send_material.as_ref().ok_or_else(|| {
            LiveBalanceServiceError::InvalidRequest(format!(
                "producer request {producer_request_id:?} is not an inter-channel send"
            ))
        })?;
        let (pis, proof_size) = verify_balance_proof_bytes(
            &material.balance_proof,
            &self.balance,
            "stored source send",
        )?;
        // `material.balance_proof` is the PRE-send proof (see the store site), so it cannot be
        // compared against the POST-send receipt/head directly. The equivalent binding is the
        // two-link chain through the co-stored spend proof, checked below once it is verified:
        //   pre.private_commitment == spend.prev_private_commitment   (the receive connect)
        //   spend.new_private_commitment == entry.result.private_commitment  (the settled head)
        // Together these pin the stored proof to this exact transition, which is what the
        // retired `settled_tx_chain`/`proof_size` comparisons against the head were doing.
        if pis.channel_id != material.channel_record.channel_id {
            return Err(LiveBalanceServiceError::Snapshot(
                "stored source-send proof diverges from its signed head/receipt".into(),
            ));
        }
        verify_all_signatures(&material.channel_record, &[], &material.signed_head).map_err(
            |e| LiveBalanceServiceError::Snapshot(format!("stored source-send N-of-N head: {e}")),
        )?;
        let spend_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
            material.spend_proof.clone(),
            &self.spend.data.common,
        )
        .map_err(|e| LiveBalanceServiceError::Snapshot(format!("stored spend proof: {e}")))?;
        let stored_spend_pis =
            SpendPublicInputs::from_pis_u64(&spend_proof.public_inputs.to_u64_vec()).map_err(
                |e| LiveBalanceServiceError::Snapshot(format!("stored spend pis: {e}")),
            )?;
        self.spend
            .data
            .verify(spend_proof)
            .map_err(|e| LiveBalanceServiceError::Snapshot(format!("verify stored spend: {e}")))?;
        if !stored_spend_pis.is_valid
            || pis.private_commitment != stored_spend_pis.prev_private_commitment
            || stored_spend_pis.new_private_commitment != entry.result.private_commitment
        {
            return Err(LiveBalanceServiceError::Snapshot(
                "stored source-send proof/spend/receipt chain is inconsistent".into(),
            ));
        }
        // The pre-send-correct form of the retired chain comparison: the stored proof's chain,
        // advanced by exactly this send's tx leaf, must be the N-of-N-signed head's chain. This
        // also re-binds `material.signed_head` to THIS transition (a validly signed head from a
        // different transition no longer passes).
        if settled_tx_chain_push(pis.settled_tx_chain, material.settled_leaf)
            != material.signed_head.balance_state.settled_tx_chain
        {
            return Err(LiveBalanceServiceError::Snapshot(
                "stored source-send chain does not advance to the signed head".into(),
            ));
        }
        Ok(LiveInterChannelSendArtifact {
            producer_receipt: entry.producer_receipt.clone(),
            source_backing: LiveChannelBackingArtifact {
                base_head: LiveBaseHeadArtifact {
                    snapshot_version: LIVE_BALANCE_SNAPSHOT_VERSION,
                    channel_id: pis.channel_id,
                    balance_generation: entry.result.balance_generation,
                    base_nonce: entry.result.base_nonce,
                    private_commitment: pis.private_commitment,
                    settled_tx_chain: pis.settled_tx_chain,
                    proof_size,
                    producer_receipt: Some(entry.producer_receipt.clone()),
                    signed_head_digest: Some(material.signed_head.digest),
                    awaiting_channel_binding: false,
                },
                balance_attestation: ChannelBalanceAttestation {
                    balance_proof: material.balance_proof.clone(),
                },
                balance_verifier_data: serialize_verifier_data(&self.balance.balance_vd())
                    .map_err(|error| {
                        LiveBalanceServiceError::Snapshot(format!(
                            "serialize resident balance verifier data: {error}"
                        ))
                    })?,
                channel_record: material.channel_record.clone(),
                signed_head: material.signed_head.clone(),
            },
            spend_proof: material.spend_proof.clone(),
        })
    }

    /// Compatibility one-shot API. Production uses the explicit two phases below so the
    /// validity-backed attestation can exist before members construct/sign genesis.
    pub fn receive_deposit(
        &mut self,
        producer: &BlockProducerService,
        producer_receipt: &BlockProducerReceipt,
        request: &ProductionDepositRequest,
        deposit_salt: Salt,
        signed_snapshot: &ChannelSnapshot,
    ) -> Result<LiveBalanceReceipt, LiveBalanceServiceError> {
        let result =
            self.receive_deposit_unbound(producer, producer_receipt, request, deposit_salt)?;
        self.bind_signed_snapshot(signed_snapshot)?;
        Ok(result)
    }

    /// Phase 1 of crash-safe deposit adoption: prove and durably persist the exact L1-reconciled
    /// deposit without requiring a channel head that cannot exist until this proof is exported.
    pub fn receive_deposit_unbound(
        &mut self,
        producer: &BlockProducerService,
        producer_receipt: &BlockProducerReceipt,
        request: &ProductionDepositRequest,
        deposit_salt: Salt,
    ) -> Result<LiveBalanceReceipt, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        let fingerprint = hash_serializable(&DepositFingerprint {
            domain: "INTMAX_LIVE_BALANCE_DEPOSIT_V1",
            producer_receipt,
            request,
            deposit_salt,
        })?;
        if let Some(receipt) = self.idempotent_result(&producer_receipt.request_id, fingerprint)? {
            verify_deposit_receipt(producer, producer_receipt, request)?;
            return Ok(receipt);
        }
        if self.disk.awaiting_channel_binding {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "bind the pending deposit proof to an N-of-N channel snapshot before another transition"
                    .into(),
            ));
        }
        verify_deposit_receipt(producer, producer_receipt, request)?;
        self.require_new_producer_generation(producer_receipt)?;

        let expected_receiver =
            calculate_recipient_from_user_id(self.disk.channel_id, deposit_salt);
        if request.recipient != expected_receiver {
            return Err(LiveBalanceServiceError::InvalidRequest(format!(
                "L1 deposit recipient {} is not channel {} with the supplied deposit salt",
                request.recipient,
                self.disk.channel_id.as_u64()
            )));
        }

        let mut generator = self.generator(producer)?;
        let witness = generator
            .receive_deposit_witness_at_index(
                &ReceiveDepositData {
                    receiver: expected_receiver,
                    deposit_salt,
                },
                request.deposit_index,
            )
            .map_err(|e| LiveBalanceServiceError::Transition(format!("deposit witness: {e}")))?;
        let deposit = &witness.deposit_witness.deposit;
        if deposit.deposit_index.as_u64() != request.deposit_index
            || deposit.depositor != request.depositor
            || deposit.recipient != request.recipient
            || deposit.token_index != request.token_index
            || deposit.amount != request.amount
            || deposit.aux_data != request.aux_data
        {
            return Err(LiveBalanceServiceError::ProducerReconciliation(
                "deposit witness leaf differs from the exact journaled L1 request".to_string(),
            ));
        }
        let new_proof = self.balance.prove_receive_deposit(&witness).map_err(|e| {
            LiveBalanceServiceError::Transition(format!("receive deposit proof: {e}"))
        })?;
        generator
            .commit_receive_deposit(&new_proof, &witness)
            .map_err(|e| LiveBalanceServiceError::Transition(format!("commit deposit: {e}")))?;

        let mut candidate = self.disk.clone();
        candidate.balance_generation =
            candidate.balance_generation.checked_add(1).ok_or_else(|| {
                LiveBalanceServiceError::Transition("balance generation overflow".into())
            })?;
        candidate.balance_proof = new_proof.to_bytes();
        candidate.full_private_state = generator.full_private_state;
        candidate.base_nonce = candidate.full_private_state.nonce;
        candidate.awaiting_channel_binding = true;
        let result = make_receipt(&candidate, producer_receipt, &self.balance)?;
        candidate.applied.push(AppliedTransition {
            request_id: producer_receipt.request_id.clone(),
            request_fingerprint: fingerprint,
            producer_receipt: producer_receipt.clone(),
            result: result.clone(),
            send_material: None,
        });
        verify_snapshot_semantics(&candidate, &self.spend, &self.balance, Some(producer))?;
        self.commit(candidate)?;
        Ok(result)
    }

    /// Production phase-1 convenience: use the OS-generated salt stored by
    /// `initialize_production`; the API never receives or returns that secret setup material.
    pub fn receive_configured_deposit_unbound(
        &mut self,
        producer: &BlockProducerService,
        producer_receipt: &BlockProducerReceipt,
        request: &ProductionDepositRequest,
    ) -> Result<LiveBalanceReceipt, LiveBalanceServiceError> {
        let salt = self.disk.pending_deposit_salt.ok_or_else(|| {
            LiveBalanceServiceError::InvalidRequest(
                "no configured deposit recipient is pending for this live balance".into(),
            )
        })?;
        self.receive_deposit_unbound(producer, producer_receipt, request, salt)
    }

    /// Phase 2 of deposit adoption: bind the already durable balance proof to the exact N-of-N
    /// channel snapshot members subsequently created. This phase makes no balance proof and is
    /// safe to retry after a crash.
    pub fn bind_signed_snapshot(
        &mut self,
        signed_snapshot: &ChannelSnapshot,
    ) -> Result<(), LiveBalanceServiceError> {
        self.ensure_healthy()?;
        verify_snapshot(signed_snapshot, None).map_err(|e| {
            LiveBalanceServiceError::InvalidRequest(format!(
                "deposit-backed channel snapshot is not fully valid/N-of-N signed: {e}"
            ))
        })?;
        if signed_snapshot.record.channel_id != self.disk.channel_id
            || signed_snapshot.state.channel_id != self.disk.channel_id
        {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "deposit-backed snapshot belongs to a different channel".to_string(),
            ));
        }
        if signed_snapshot.state.h2_tag != Bytes32::default() {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "an L1 deposit receive head must have h2_tag == 0".to_string(),
            ));
        }
        let proof = decode_balance_proof(&self.disk, &self.balance)?;
        let pis = balance_public_inputs(&proof, &self.balance)?;
        if pis.settled_tx_chain != signed_snapshot.state.balance_state.settled_tx_chain {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "signed snapshot settle chain differs from the pending live balance proof".into(),
            ));
        }
        if !self.disk.awaiting_channel_binding {
            if self
                .disk
                .channel_record
                .as_ref()
                .map(ChannelRecord::signing_digest)
                == Some(signed_snapshot.record.signing_digest())
                && self.disk.signed_head.as_ref().map(|head| head.digest)
                    == Some(signed_snapshot.state.digest)
            {
                return Ok(());
            }
            return Err(LiveBalanceServiceError::InvalidRequest(
                "there is no unbound deposit transition to attach to this snapshot".into(),
            ));
        }
        verify_record_and_head_continuity(
            self.disk.channel_record.as_ref(),
            self.disk.signed_head.as_ref(),
            &signed_snapshot.record,
            &signed_snapshot.state,
            true,
        )?;
        let mut candidate = self.disk.clone();
        candidate.channel_record = Some(signed_snapshot.record.clone());
        candidate.channel_members = Some(signed_snapshot.members.clone());
        candidate.signed_head = Some(signed_snapshot.state.clone());
        candidate.awaiting_channel_binding = false;
        candidate.pending_deposit_salt = None;
        verify_snapshot_semantics(&candidate, &self.spend, &self.balance, None)?;
        self.commit(candidate)
    }

    /// Settle the canonical base `SendTx` for a producer-admitted inter-channel send or burn.
    /// The exact descriptor body, N-of-N head, explicit base nonce, H2 opening, private commitment
    /// and resulting settle chain are all checked before the snapshot is made durable.
    pub fn settle_inter_channel(
        &mut self,
        producer: &BlockProducerService,
        producer_receipt: &BlockProducerReceipt,
        signed_state: &ChannelState,
        debit_payload: &InterChannelDebitPayload,
        descriptor: &InterChannelTransferDescriptor,
    ) -> Result<LiveBalanceReceipt, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        let fingerprint = hash_serializable(&SendFingerprint {
            domain: "INTMAX_LIVE_BALANCE_SEND_V1",
            producer_receipt,
            signed_state,
            debit_payload,
            descriptor,
        })?;
        if let Some(receipt) = self.idempotent_result(&producer_receipt.request_id, fingerprint)? {
            verify_inter_channel_receipt(
                producer,
                producer_receipt,
                signed_state,
                debit_payload,
                descriptor,
            )?;
            return Ok(receipt);
        }
        if self.disk.awaiting_channel_binding {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "bind the pending deposit proof before settling a send".into(),
            ));
        }
        verify_inter_channel_receipt(
            producer,
            producer_receipt,
            signed_state,
            debit_payload,
            descriptor,
        )?;
        self.require_new_producer_generation(producer_receipt)?;
        verify_inter_channel_descriptor_matches_debit(debit_payload, descriptor).map_err(|e| {
            LiveBalanceServiceError::InvalidRequest(format!(
                "canonical inter-channel descriptor/debit binding: {e}"
            ))
        })?;
        if debit_payload.proposed_next_state.digest != signed_state.digest {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "signed state differs from debit payload proposed state".to_string(),
            ));
        }
        let record = self.disk.channel_record.as_ref().ok_or_else(|| {
            LiveBalanceServiceError::InvalidRequest(
                "receive a deposit-backed signed snapshot before settling sends".to_string(),
            )
        })?;
        if debit_payload.record.signing_digest() != record.signing_digest() {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "debit record differs from the balance service's pinned channel record".into(),
            ));
        }
        verify_all_signatures(record, &[], signed_state).map_err(|e| {
            LiveBalanceServiceError::InvalidRequest(format!(
                "inter-channel head is not N-of-N signed: {e}"
            ))
        })?;
        verify_record_and_head_continuity(
            Some(record),
            self.disk.signed_head.as_ref(),
            record,
            signed_state,
            false,
        )?;
        verify_private_cursor(&self.disk)?;
        if descriptor.inter_channel_tx.base_nonce != self.disk.full_private_state.nonce
            || descriptor.tx_v2.nonce != self.disk.full_private_state.nonce
        {
            return Err(LiveBalanceServiceError::InvalidRequest(format!(
                "descriptor base nonce/TxV2 nonce ({}/{}) must equal live private nonce {}",
                descriptor.inter_channel_tx.base_nonce,
                descriptor.tx_v2.nonce,
                self.disk.full_private_state.nonce
            )));
        }

        let transfer =
            canonical_inter_channel_base_transfer(&descriptor.inter_channel_tx, descriptor.amount)
                .map_err(|e| {
                    LiveBalanceServiceError::InvalidRequest(format!(
                        "canonical inter-channel base transfer: {e}"
                    ))
                })?;
        let (canonical_tx_v2, canonical_tx_v2_tree) = inter_channel_tx_v2(
            self.disk.channel_id,
            &transfer,
            self.disk.full_private_state.nonce,
        );
        let canonical_h2 = Bytes32::from(canonical_tx_v2_tree.get_root());
        if descriptor.tx_v2 != canonical_tx_v2
            || descriptor.tx_tree_root != canonical_h2
            || descriptor
                .tx_v2_merkle_proof
                .get_root(&descriptor.tx_v2, self.disk.channel_id.as_u64())
                != canonical_tx_v2_tree.get_root()
        {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "descriptor does not open the canonical base Transfer/TxV2/H2".to_string(),
            ));
        }

        let mut generator = self.generator(producer)?;
        let spend_witness = generator
            .spend_witness(std::slice::from_ref(&transfer))
            .map_err(|e| LiveBalanceServiceError::Transition(format!("spend witness: {e}")))?;
        if spend_witness.tx_nonce != self.disk.base_nonce {
            return Err(LiveBalanceServiceError::Transition(
                "spend witness nonce diverged from durable base cursor".to_string(),
            ));
        }
        let spend_proof = self
            .spend
            .prove(&spend_witness)
            .map_err(|e| LiveBalanceServiceError::Transition(format!("spend proof: {e}")))?;

        let mut transfer_tree = TransferTree::init();
        transfer_tree.push(transfer.clone());
        if canonical_tx_v2.transfer_tree_root != transfer_tree.get_root() {
            return Err(LiveBalanceServiceError::Transition(
                "canonical TxV2 transfer root differs from locally reconstructed tree".into(),
            ));
        }
        let tx = Tx {
            transfer_tree_root: transfer_tree.get_root(),
            nonce: self.disk.base_nonce,
        };
        let mut legacy_tx_tree = TxTree::init();
        legacy_tx_tree.update(self.disk.channel_id.as_u64(), tx);
        let send_data = SendTxData {
            spend_proof: spend_proof.clone(),
            tx_tree_root: descriptor.tx_tree_root,
            tx,
            tx_merkle_proof: legacy_tx_tree.prove(self.disk.channel_id.as_u64()),
            tx_v2: Some(descriptor.tx_v2),
            tx_v2_merkle_proof: Some(descriptor.tx_v2_merkle_proof.clone()),
            transfer: transfer.clone(),
            transfer_merkle_proof: transfer_tree.prove(0),
        };
        let send_witness = generator
            .send_tx_witness(&send_data)
            .map_err(|e| LiveBalanceServiceError::Transition(format!("send witness: {e}")))?;
        let new_proof = self
            .balance
            .prove_send_tx(&send_witness)
            .map_err(|e| LiveBalanceServiceError::Transition(format!("send balance proof: {e}")))?;
        generator
            .commit_send_tx(&new_proof, &send_witness, &spend_witness)
            .map_err(|e| LiveBalanceServiceError::Transition(format!("commit send: {e}")))?;

        let mut candidate = self.disk.clone();
        candidate.balance_generation =
            candidate.balance_generation.checked_add(1).ok_or_else(|| {
                LiveBalanceServiceError::Transition("balance generation overflow".into())
            })?;
        candidate.balance_proof = new_proof.to_bytes();
        candidate.full_private_state = generator.full_private_state;
        candidate.base_nonce = candidate.full_private_state.nonce;
        candidate.signed_head = Some(signed_state.clone());
        let result = make_receipt(&candidate, producer_receipt, &self.balance)?;
        candidate.applied.push(AppliedTransition {
            request_id: producer_receipt.request_id.clone(),
            request_fingerprint: fingerprint,
            producer_receipt: producer_receipt.clone(),
            result: result.clone(),
            send_material: Some(StoredInterChannelSendMaterial {
                // The PRE-send balance proof: the one `send_tx_circuit` consumed as
                // `prev_balance_pis` (send_tx_circuit.rs:127). A ReceiveTransfer must connect
                // `sender_balance_pis.private_commitment == spend_pis.prev_private_commitment`
                // (receive_transfer_circuit.rs:263), and `prove_send_tx` returns a proof
                // committing `spend_pis.new_private_commitment` — the POST-send state — so the
                // head proof can never satisfy that connect. `self.disk` is still the pre-send
                // snapshot here; `candidate.balance_proof` has already been advanced.
                balance_proof: self.disk.balance_proof.clone(),
                spend_proof: spend_proof.to_bytes(),
                settled_leaf: transfer.aux_data,
                channel_record: record.clone(),
                signed_head: signed_state.clone(),
            }),
        });
        verify_snapshot_semantics(&candidate, &self.spend, &self.balance, Some(producer))?;
        self.commit(candidate)?;
        Ok(result)
    }

    /// Settle the destination side of one producer-admitted channel-to-channel transfer. The
    /// source's durable balance+spend proofs and both N-of-N destination credit states are
    /// verified before the destination private asset/nullifier trees advance.
    #[allow(clippy::too_many_arguments)]
    pub fn receive_inter_channel(
        &mut self,
        producer: &BlockProducerService,
        producer_receipt: &BlockProducerReceipt,
        debit_payload: &InterChannelDebitPayload,
        descriptor: &InterChannelTransferDescriptor,
        source_artifact: &LiveInterChannelSendArtifact,
        fund_import_state: &ChannelState,
        destination_snapshot: &ChannelSnapshot,
        level: crate::regev::RegevSecurityLevel,
    ) -> Result<LiveBalanceReceipt, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        let fingerprint = hash_serializable(&ReceiveTransferFingerprint {
            domain: "INTMAX_LIVE_BALANCE_RECEIVE_INTER_V1",
            producer_receipt,
            debit_payload,
            descriptor,
            source_artifact,
            fund_import_state,
            destination_snapshot,
        })?;
        if let Some(receipt) = self.idempotent_result(&producer_receipt.request_id, fingerprint)? {
            verify_inter_channel_receipt(
                producer,
                producer_receipt,
                &source_artifact.source_backing.signed_head,
                debit_payload,
                descriptor,
            )?;
            return Ok(receipt);
        }
        if self.disk.awaiting_channel_binding {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "bind the pending deposit proof before receiving an inter-channel transfer".into(),
            ));
        }
        verify_inter_channel_receipt(
            producer,
            producer_receipt,
            &source_artifact.source_backing.signed_head,
            debit_payload,
            descriptor,
        )?;
        self.require_new_producer_generation(producer_receipt)?;
        if source_artifact.producer_receipt != *producer_receipt
            || source_artifact
                .source_backing
                .base_head
                .producer_receipt
                .as_ref()
                != Some(producer_receipt)
        {
            return Err(LiveBalanceServiceError::ProducerReconciliation(
                "source proof artifact is anchored to a different producer receipt".into(),
            ));
        }
        verify_inter_channel_descriptor_matches_debit(debit_payload, descriptor).map_err(|e| {
            LiveBalanceServiceError::InvalidRequest(format!(
                "destination canonical descriptor/debit binding: {e}"
            ))
        })?;
        let source = &source_artifact.source_backing;
        if source.channel_record.signing_digest() != debit_payload.record.signing_digest()
            || source.signed_head.digest != debit_payload.proposed_next_state.digest
            || source.base_head.signed_head_digest != Some(source.signed_head.digest)
            || source.base_head.channel_id != descriptor.source_channel_id
        {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "source proof artifact does not describe the producer-admitted signed debit".into(),
            ));
        }
        verify_all_signatures(&source.channel_record, &[], &source.signed_head).map_err(|e| {
            LiveBalanceServiceError::InvalidRequest(format!(
                "source artifact head is not N-of-N signed: {e}"
            ))
        })?;
        let (source_pis, source_proof_size) = verify_balance_proof_bytes(
            &source.balance_attestation.balance_proof,
            &self.balance,
            "source receive artifact",
        )?;
        // The source artifact carries the PRE-send balance proof (the only one a ReceiveTransfer
        // can connect to the spend), so its `settled_tx_chain` is the chain BEFORE this send. It
        // is bound to the post-send `signed_head` in the pre-send-correct form: advancing it by
        // THIS send's tx leaf must land exactly on the N-of-N-signed head's chain.
        // The settled-chain leaf is the canonical base Transfer's aux_data (tx leaf for a
        // normal send, burn descriptor for a burn) — the value send_tx_circuit actually pushed.
        let source_settled_leaf =
            canonical_inter_channel_base_transfer(&descriptor.inter_channel_tx, descriptor.amount)
                .map_err(|e| {
                    LiveBalanceServiceError::InvalidRequest(format!("source settled leaf: {e}"))
                })?
                .aux_data;
        if source_pis.channel_id != descriptor.source_channel_id
            || source_pis.private_commitment != source.base_head.private_commitment
            || source_proof_size != source.base_head.proof_size
            || settled_tx_chain_push(source_pis.settled_tx_chain, source_settled_leaf)
                != source.signed_head.balance_state.settled_tx_chain
        {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "source balance proof public inputs diverge from its authenticated base/channel head"
                    .into(),
            ));
        }
        let sender_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
            source.balance_attestation.balance_proof.clone(),
            &self.balance.balance_vd().common,
        )
        .map_err(|e| {
            LiveBalanceServiceError::InvalidRequest(format!("decode source balance proof: {e}"))
        })?;
        let spend_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
            source_artifact.spend_proof.clone(),
            &self.spend.data.common,
        )
        .map_err(|e| {
            LiveBalanceServiceError::InvalidRequest(format!("decode source spend proof: {e}"))
        })?;
        self.spend.data.verify(spend_proof.clone()).map_err(|e| {
            LiveBalanceServiceError::InvalidRequest(format!("verify source spend proof: {e}"))
        })?;

        verify_snapshot(destination_snapshot, None).map_err(|e| {
            LiveBalanceServiceError::InvalidRequest(format!(
                "destination snapshot is not valid/N-of-N signed: {e}"
            ))
        })?;
        let record = self.disk.channel_record.as_ref().ok_or_else(|| {
            LiveBalanceServiceError::InvalidRequest(
                "destination must first bind a deposit-backed channel snapshot".into(),
            )
        })?;
        let members = self.disk.channel_members.as_ref().ok_or_else(|| {
            LiveBalanceServiceError::Snapshot(
                "bound destination snapshot is missing its authenticated members".into(),
            )
        })?;
        let prev = self.disk.signed_head.as_ref().ok_or_else(|| {
            LiveBalanceServiceError::Snapshot("bound destination has no signed head".into())
        })?;
        if destination_snapshot.record.signing_digest() != record.signing_digest()
            || hash_serializable(&destination_snapshot.members)? != hash_serializable(members)?
        {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "destination snapshot record/member set differs from the pinned channel".into(),
            ));
        }
        if fund_import_state.prev_digest != prev.digest
            || fund_import_state.epoch != prev.epoch + 1
            || fund_import_state.small_block_number != prev.small_block_number + 1
            || fund_import_state.balance_state.state_version != prev.balance_state.state_version + 1
            || destination_snapshot.state.prev_digest != fund_import_state.digest
            || destination_snapshot.state.epoch != fund_import_state.epoch + 1
            || destination_snapshot.state.small_block_number != fund_import_state.small_block_number
            || destination_snapshot.state.balance_state.state_version
                != fund_import_state.balance_state.state_version + 1
        {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "destination fund-import/bundle states skip, fork, or miscount the pinned head"
                    .into(),
            ));
        }
        verify_inter_channel_credit_states(
            prev,
            record,
            members,
            descriptor,
            &source.signed_head,
            &source.channel_record,
            fund_import_state,
            &destination_snapshot.state,
            level,
        )
        .map_err(|e| {
            LiveBalanceServiceError::InvalidRequest(format!(
                "destination two-state credit gate: {e}"
            ))
        })?;

        let transfer =
            canonical_inter_channel_base_transfer(&descriptor.inter_channel_tx, descriptor.amount)
                .map_err(|e| {
                    LiveBalanceServiceError::InvalidRequest(format!(
                        "canonical destination base transfer: {e}"
                    ))
                })?;
        let (canonical_tx_v2, canonical_tx_v2_tree) = inter_channel_tx_v2(
            descriptor.source_channel_id,
            &transfer,
            descriptor.inter_channel_tx.base_nonce,
        );
        if canonical_tx_v2 != descriptor.tx_v2
            || Bytes32::from(canonical_tx_v2_tree.get_root()) != descriptor.tx_tree_root
        {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "destination descriptor does not open canonical TxV2/H2".into(),
            ));
        }
        let mut transfer_tree = TransferTree::init();
        transfer_tree.push(transfer.clone());
        let tx = Tx {
            transfer_tree_root: transfer_tree.get_root(),
            nonce: descriptor.inter_channel_tx.base_nonce,
        };
        let mut legacy_tx_tree = TxTree::init();
        legacy_tx_tree.update(descriptor.source_channel_id.as_u64(), tx);
        let mut generator = self.generator(producer)?;
        let receive_data = ReceiveTransferData {
            to: self.disk.channel_id,
            transfer,
            sender_proof,
            spend_proof,
            tx_tree_root: descriptor.tx_tree_root,
            tx,
            tx_merkle_proof: legacy_tx_tree.prove(descriptor.source_channel_id.as_u64()),
            tx_v2: Some(descriptor.tx_v2),
            tx_v2_merkle_proof: Some(descriptor.tx_v2_merkle_proof.clone()),
            transfer_index: 0,
            transfer_merkle_proof: transfer_tree.prove(0),
            transfer_salt: descriptor.destination_base_transfer_salt,
        };
        let receive_witness = generator
            .receive_transfer_witness(&receive_data)
            .map_err(|e| {
                LiveBalanceServiceError::Transition(format!("receive-transfer witness: {e}"))
            })?;
        let new_proof = self
            .balance
            .prove_receive_transfer(&receive_witness)
            .map_err(|e| {
                LiveBalanceServiceError::Transition(format!("receive-transfer proof: {e}"))
            })?;
        generator
            .commit_receive_transfer(&new_proof, &receive_witness)
            .map_err(|e| {
                LiveBalanceServiceError::Transition(format!("commit receive-transfer: {e}"))
            })?;

        let mut candidate = self.disk.clone();
        candidate.balance_generation =
            candidate.balance_generation.checked_add(1).ok_or_else(|| {
                LiveBalanceServiceError::Transition("balance generation overflow".into())
            })?;
        candidate.balance_proof = new_proof.to_bytes();
        candidate.full_private_state = generator.full_private_state;
        candidate.base_nonce = candidate.full_private_state.nonce;
        candidate.channel_record = Some(destination_snapshot.record.clone());
        candidate.channel_members = Some(destination_snapshot.members.clone());
        candidate.signed_head = Some(destination_snapshot.state.clone());
        let result = make_receipt(&candidate, producer_receipt, &self.balance)?;
        candidate.applied.push(AppliedTransition {
            request_id: producer_receipt.request_id.clone(),
            request_fingerprint: fingerprint,
            producer_receipt: producer_receipt.clone(),
            result: result.clone(),
            send_material: None,
        });
        verify_snapshot_semantics(&candidate, &self.spend, &self.balance, Some(producer))?;
        self.commit(candidate)?;
        Ok(result)
    }

    /// Prove the L1 withdrawal leg of a SETTLED burn — against the LIVE base history, never a
    /// from-scratch chain (partial-withdrawal-payout-design P3-2; `build_channel_withdrawal` is
    /// deliberately not called anywhere on this path).
    ///
    /// The caller names a journaled producer request (the burn settle) and re-supplies its
    /// descriptor. Nothing in the descriptor is trusted: the canonical base `Transfer` is
    /// recomputed from it and then BOUND to the journaled transition three ways before any
    /// proving —
    ///   1. `transfer.aux_data == material.settled_leaf` (the leaf the settle actually pushed);
    ///   2. the reconstructed 1-transfer tree root equals the journaled spend proof's
    ///      `tx.transfer_tree_root` (the spend that debited the burn committed THIS transfer set);
    ///   3. the canonical `TxV2`/H2 match the producer-admitted block the settle was keyed on.
    /// A descriptor for any other transition fails one of the three.
    ///
    /// Returns the final withdrawal-chain proof plus the [`Withdrawal`] READ OUT OF THE PROOF'S
    /// PUBLIC INPUTS (P3-3: consumers must never recompute leaf fields), with the same
    /// keccak-refold sanity the fixture path performs.
    pub fn prove_burn_withdrawal(
        &self,
        producer: &BlockProducerService,
        producer_request_id: &str,
        descriptor: &InterChannelTransferDescriptor,
        withdrawal_prover: Address,
    ) -> Result<BurnWithdrawalProof, LiveBalanceServiceError> {
        self.ensure_healthy()?;
        let entry = self
            .disk
            .applied
            .iter()
            .find(|entry| entry.request_id == producer_request_id)
            .ok_or_else(|| {
                LiveBalanceServiceError::InvalidRequest(format!(
                    "unknown settled producer request {producer_request_id:?}"
                ))
            })?;
        let material = entry.send_material.as_ref().ok_or_else(|| {
            LiveBalanceServiceError::InvalidRequest(format!(
                "producer request {producer_request_id:?} is not an inter-channel send"
            ))
        })?;
        if descriptor.inter_channel_tx.destination_channel_id.channel_id() != BURN_CHANNEL_ID {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "request is not a burn: the destination is not BURN_CHANNEL_ID".into(),
            ));
        }

        // Canonical reconstruction + the three bindings.
        let transfer =
            canonical_inter_channel_base_transfer(&descriptor.inter_channel_tx, descriptor.amount)
                .map_err(|e| {
                    LiveBalanceServiceError::InvalidRequest(format!(
                        "canonical burn base transfer: {e}"
                    ))
                })?;
        if transfer.aux_data != material.settled_leaf {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "descriptor does not describe the journaled transition: aux_data != settled leaf"
                    .into(),
            ));
        }
        let spend_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
            material.spend_proof.clone(),
            &self.spend.data.common,
        )
        .map_err(|e| {
            LiveBalanceServiceError::Snapshot(format!("decode journaled burn spend proof: {e}"))
        })?;
        self.spend.data.verify(spend_proof.clone()).map_err(|e| {
            LiveBalanceServiceError::Snapshot(format!("verify journaled burn spend proof: {e}"))
        })?;
        let spend_pis =
            SpendPublicInputs::from_pis_u64(&spend_proof.public_inputs.to_u64_vec()).map_err(
                |e| LiveBalanceServiceError::Snapshot(format!("journaled burn spend pis: {e}")),
            )?;
        let burn_nonce = spend_pis.tx.nonce;

        let mut transfer_tree = TransferTree::init();
        transfer_tree.push(transfer.clone());
        let transfer_tree_root = transfer_tree.get_root();
        if spend_pis.tx.transfer_tree_root != transfer_tree_root {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "descriptor transfer set differs from the one the journaled spend committed".into(),
            ));
        }
        let (canonical_tx_v2, canonical_tx_v2_tree) =
            inter_channel_tx_v2(self.disk.channel_id, &transfer, burn_nonce);
        let tx_tree_root = Bytes32::from(canonical_tx_v2_tree.get_root());
        if descriptor.tx_v2 != canonical_tx_v2 || descriptor.tx_tree_root != tx_tree_root {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "descriptor does not open the canonical burn TxV2/H2".into(),
            ));
        }

        // Witness pieces, exactly the settled-transfer extraction recipe (c2c "Block 5"): the
        // legacy Tx tree exists only for its merkle proof; the block-authoritative root is H2.
        let transfer_index = 0u32;
        let transfer_merkle_proof = transfer_tree.prove(transfer_index as u64);
        let tx = Tx {
            transfer_tree_root,
            nonce: burn_nonce,
        };
        let mut tx_tree = TxTree::init();
        tx_tree.update(self.disk.channel_id.as_u64(), tx.clone());
        let tx_merkle_proof = tx_tree.prove(self.disk.channel_id.as_u64());
        let tx_v2_merkle_proof = canonical_tx_v2_tree.prove(self.disk.channel_id.as_u64());

        let generator = self.generator(producer)?;
        let single_withdrawal_data = SingleWithdrawalData {
            tx_tree_root,
            tx,
            tx_merkle_proof,
            tx_v2: Some(canonical_tx_v2),
            tx_v2_merkle_proof: Some(tx_v2_merkle_proof),
            transfer,
            transfer_index,
            transfer_merkle_proof,
        };
        let witness = generator
            .single_withdrawal_witness(&single_withdrawal_data)
            .map_err(|e| {
                LiveBalanceServiceError::Transition(format!("burn withdrawal witness: {e}"))
            })?;

        let single_withdrawal_circuit = SingleWithdawalCircuit::<F, C, D>::new(&self.balance.balance_vd());
        let single_withdrawal_vd = single_withdrawal_circuit.data.verifier_data();
        let single_proof = single_withdrawal_circuit.prove(&witness).map_err(|e| {
            LiveBalanceServiceError::Transition(format!("single withdrawal proof: {e}"))
        })?;
        single_withdrawal_circuit
            .data
            .verify(single_proof.clone())
            .map_err(|e| {
                LiveBalanceServiceError::Transition(format!("verify single withdrawal: {e}"))
            })?;
        // P3-3: the leaf the consumer will pay is read from the PROOF, never recomputed.
        let single_pis = SingleWithdawalPublicInputs::from_u64_slice(
            &single_proof.public_inputs[..SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN].to_u64_vec(),
        )
        .map_err(|e| LiveBalanceServiceError::Transition(format!("single withdrawal pis: {e}")))?;
        let withdrawal: Withdrawal = single_pis.withdrawal.clone();

        let withdrawal_processor = WithdrawalProcessor::<F, C, D>::new(&single_withdrawal_vd);
        let chain_proof = withdrawal_processor
            .prove_step(&WithdrawalStepWitness::<F, C, D> {
                prev_withdrawal_chain_proof: None,
                single_withdrawal_proof: single_proof,
                update_public_state: witness.update_public_state.clone(),
            })
            .map_err(|e| {
                LiveBalanceServiceError::Transition(format!("withdrawal chain proof: {e}"))
            })?;
        // Keccak-refold sanity: the chain the contract will fold equals the proof-committed one.
        let proof_withdrawal_hash = {
            let pis = chain_proof.public_inputs.to_u64_vec();
            Bytes32::from_u64_slice(&pis[0..8]).map_err(|e| {
                LiveBalanceServiceError::Transition(format!("withdrawal hash chain limbs: {e}"))
            })?
        };
        if withdrawal.hash_with_prev_hash(Bytes32::default()) != proof_withdrawal_hash {
            return Err(LiveBalanceServiceError::Transition(
                "withdrawal keccak chain re-fold mismatch".into(),
            ));
        }

        let ext_public_state = producer
            .producer()
            .map_err(|e| LiveBalanceServiceError::ProducerReconciliation(e.to_string()))?
            .witness_handle()
            .map_err(|e| LiveBalanceServiceError::ProducerReconciliation(e.to_string()))?
            .borrow()
            .current_extended_public_state();
        let final_proof = withdrawal_processor
            .prove_final(&chain_proof, withdrawal_prover, &ext_public_state)
            .map_err(|e| {
                LiveBalanceServiceError::Transition(format!("final withdrawal proof: {e}"))
            })?;
        withdrawal_processor
            .withdrawal_vd()
            .verify(final_proof.clone())
            .map_err(|e| {
                LiveBalanceServiceError::Transition(format!("verify final withdrawal: {e}"))
            })?;

        Ok(BurnWithdrawalProof {
            withdrawal,
            withdrawal_prover,
            proof: final_proof,
            withdrawal_vd: withdrawal_processor.withdrawal_vd(),
        })
    }

    fn generator(
        &self,
        producer: &BlockProducerService,
    ) -> Result<BalanceWitnessGenerator<F, C, D>, LiveBalanceServiceError> {
        let proof = decode_balance_proof(&self.disk, &self.balance)?;
        let handle = producer
            .producer()?
            .witness_handle()
            .map_err(|e| LiveBalanceServiceError::ProducerReconciliation(e.to_string()))?;
        Ok(BalanceWitnessGenerator {
            channel_id: self.disk.channel_id,
            salt: self.disk.full_private_state.salt,
            balance_proof: proof,
            full_private_state: self.disk.full_private_state.clone(),
            block_witness_generator: handle,
        })
    }

    fn idempotent_result(
        &self,
        request_id: &str,
        fingerprint: Bytes32,
    ) -> Result<Option<LiveBalanceReceipt>, LiveBalanceServiceError> {
        let Some(entry) = self
            .disk
            .applied
            .iter()
            .find(|entry| entry.request_id == request_id)
        else {
            return Ok(None);
        };
        if entry.request_fingerprint != fingerprint {
            return Err(LiveBalanceServiceError::InvalidRequest(format!(
                "producer request id {request_id:?} was already settled with different content"
            )));
        }
        Ok(Some(entry.result.clone()))
    }

    fn require_new_producer_generation(
        &self,
        receipt: &BlockProducerReceipt,
    ) -> Result<(), LiveBalanceServiceError> {
        if let Some(last) = self.disk.applied.last() {
            if receipt.generation <= last.producer_receipt.generation {
                return Err(LiveBalanceServiceError::ProducerReconciliation(format!(
                    "producer receipt generation {} is a rollback/non-advance from settled {}",
                    receipt.generation, last.producer_receipt.generation
                )));
            }
        }
        Ok(())
    }

    fn commit(&mut self, candidate: LiveBalanceSnapshot) -> Result<(), LiveBalanceServiceError> {
        if candidate.applied.len() > MAX_APPLIED_TRANSITIONS {
            return Err(LiveBalanceServiceError::Snapshot(format!(
                "applied transition count exceeds {MAX_APPLIED_TRANSITIONS}"
            )));
        }
        if let Err(error) = persist_snapshot(&self.snapshot_path, &candidate) {
            // A rename or parent-directory fsync failure has an indeterminate durable outcome.
            // Continuing from the in-memory predecessor could double-spend the base nonce.
            self.poisoned = true;
            return Err(error);
        }
        self.disk = candidate;
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), LiveBalanceServiceError> {
        if self.poisoned {
            Err(LiveBalanceServiceError::Poisoned)
        } else {
            Ok(())
        }
    }
}

#[derive(Serialize)]
struct DepositFingerprint<'a> {
    domain: &'static str,
    producer_receipt: &'a BlockProducerReceipt,
    request: &'a ProductionDepositRequest,
    deposit_salt: Salt,
}

#[derive(Serialize)]
struct SendFingerprint<'a> {
    domain: &'static str,
    producer_receipt: &'a BlockProducerReceipt,
    signed_state: &'a ChannelState,
    debit_payload: &'a InterChannelDebitPayload,
    descriptor: &'a InterChannelTransferDescriptor,
}

#[derive(Serialize)]
struct ReceiveTransferFingerprint<'a> {
    domain: &'static str,
    producer_receipt: &'a BlockProducerReceipt,
    debit_payload: &'a InterChannelDebitPayload,
    descriptor: &'a InterChannelTransferDescriptor,
    source_artifact: &'a LiveInterChannelSendArtifact,
    fund_import_state: &'a ChannelState,
    destination_snapshot: &'a ChannelSnapshot,
}

fn build_circuits() -> (SpendCircuit<F, C, D>, BalanceProcessor<F, C, D>) {
    let spend = SpendCircuit::<F, C, D>::new();
    let balance = BalanceProcessor::<F, C, D>::new(&spend.data.verifier_data());
    (spend, balance)
}

fn verify_deposit_receipt(
    producer: &BlockProducerService,
    receipt: &BlockProducerReceipt,
    request: &ProductionDepositRequest,
) -> Result<(), LiveBalanceServiceError> {
    let canonical = producer
        .receipt_for_deposit(&receipt.request_id, request)?
        .ok_or_else(|| {
            LiveBalanceServiceError::ProducerReconciliation(format!(
                "producer journal contains no deposit request {:?}",
                receipt.request_id
            ))
        })?;
    verify_exact_receipt(producer, receipt, &canonical)
}

fn verify_inter_channel_receipt(
    producer: &BlockProducerService,
    receipt: &BlockProducerReceipt,
    signed_state: &ChannelState,
    debit_payload: &InterChannelDebitPayload,
    descriptor: &InterChannelTransferDescriptor,
) -> Result<(), LiveBalanceServiceError> {
    let canonical = producer
        .receipt_for_inter_channel(&receipt.request_id, signed_state, debit_payload, descriptor)?
        .ok_or_else(|| {
            LiveBalanceServiceError::ProducerReconciliation(format!(
                "producer journal contains no matching inter-channel request {:?}",
                receipt.request_id
            ))
        })?;
    verify_exact_receipt(producer, receipt, &canonical)
}

fn verify_exact_receipt(
    producer: &BlockProducerService,
    supplied: &BlockProducerReceipt,
    canonical: &BlockProducerReceipt,
) -> Result<(), LiveBalanceServiceError> {
    if supplied != canonical {
        return Err(LiveBalanceServiceError::ProducerReconciliation(
            "supplied producer receipt differs from the journal-authenticated receipt".into(),
        ));
    }
    let status = producer.status()?;
    if supplied.generation == 0 || supplied.generation > status.generation {
        return Err(LiveBalanceServiceError::ProducerReconciliation(format!(
            "receipt generation {} is outside producer journal head {}",
            supplied.generation, status.generation
        )));
    }
    if supplied.generation == status.generation
        && (supplied.entry_hash != status.journal_head
            || supplied.extended_state_commitment != status.extended_state_commitment)
    {
        return Err(LiveBalanceServiceError::ProducerReconciliation(
            "head receipt disagrees with current producer journal/extended-state anchor".into(),
        ));
    }
    Ok(())
}

fn verify_record_and_head_continuity(
    old_record: Option<&ChannelRecord>,
    old_head: Option<&ChannelState>,
    new_record: &ChannelRecord,
    new_head: &ChannelState,
    allow_multi_step: bool,
) -> Result<(), LiveBalanceServiceError> {
    if let Some(old_record) = old_record {
        if old_record.signing_digest() != new_record.signing_digest() {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "channel record changed during one live balance lifetime".into(),
            ));
        }
    }
    if new_head.channel_id != new_record.channel_id {
        return Err(LiveBalanceServiceError::InvalidRequest(
            "signed head channel id differs from record".into(),
        ));
    }
    if let Some(old) = old_head {
        if new_head.close_freeze_nonce != old.close_freeze_nonce
            || new_head.epoch <= old.epoch
            || new_head.small_block_number <= old.small_block_number
            || new_head.balance_state.state_version <= old.balance_state.state_version
        {
            return Err(LiveBalanceServiceError::InvalidRequest(
                "signed channel head is stale, rolled back, or from another close era".into(),
            ));
        }
        if !allow_multi_step {
            if new_head.prev_digest != old.digest
                || new_head.epoch != old.epoch + 1
                || new_head.small_block_number != old.small_block_number + 1
                || new_head.balance_state.state_version != old.balance_state.state_version + 1
            {
                return Err(LiveBalanceServiceError::InvalidRequest(
                    "inter-channel signed head skips or forks the pinned head".into(),
                ));
            }
        }
    }
    Ok(())
}

fn make_receipt(
    disk: &LiveBalanceSnapshot,
    producer_receipt: &BlockProducerReceipt,
    balance: &BalanceProcessor<F, C, D>,
) -> Result<LiveBalanceReceipt, LiveBalanceServiceError> {
    let proof = decode_balance_proof(disk, balance)?;
    let pis = balance_public_inputs(&proof, balance)?;
    Ok(LiveBalanceReceipt {
        producer_request_id: producer_receipt.request_id.clone(),
        producer_generation: producer_receipt.generation,
        producer_entry_hash: producer_receipt.entry_hash,
        producer_extended_state_commitment: producer_receipt.extended_state_commitment,
        balance_generation: disk.balance_generation,
        base_nonce: disk.base_nonce,
        private_commitment: pis.private_commitment,
        settled_tx_chain: pis.settled_tx_chain,
        proof_size: disk.balance_proof.len(),
    })
}

fn verify_snapshot_semantics(
    disk: &LiveBalanceSnapshot,
    spend: &SpendCircuit<F, C, D>,
    balance: &BalanceProcessor<F, C, D>,
    producer: Option<&BlockProducerService>,
) -> Result<(), LiveBalanceServiceError> {
    if disk.applied.len() > MAX_APPLIED_TRANSITIONS
        || disk.balance_generation != disk.applied.len() as u64
    {
        return Err(LiveBalanceServiceError::Snapshot(format!(
            "balance generation {} disagrees with {} applied transitions",
            disk.balance_generation,
            disk.applied.len()
        )));
    }
    verify_private_cursor(disk)?;
    let proof = decode_balance_proof(disk, balance)?;
    balance
        .balance_vd()
        .verify(proof.clone())
        .map_err(|e| LiveBalanceServiceError::Snapshot(format!("balance proof verify: {e}")))?;
    let pis = balance_public_inputs(&proof, balance)?;
    if pis.channel_id != disk.channel_id {
        return Err(LiveBalanceServiceError::Snapshot(
            "balance proof channel id differs from snapshot".into(),
        ));
    }
    let actual_private_commitment = disk.full_private_state.to_private_state().commitment();
    if pis.private_commitment != actual_private_commitment {
        return Err(LiveBalanceServiceError::Snapshot(
            "balance proof private commitment differs from persisted private trees".into(),
        ));
    }
    match (
        &disk.channel_record,
        &disk.channel_members,
        &disk.signed_head,
    ) {
        (None, None, None) => {
            if disk.awaiting_channel_binding {
                if disk.applied.is_empty() {
                    return Err(LiveBalanceServiceError::Snapshot(
                        "awaiting channel binding without a durable deposit transition".into(),
                    ));
                }
            } else if pis.settled_tx_chain != Bytes32::default() || !disk.applied.is_empty() {
                return Err(LiveBalanceServiceError::Snapshot(
                    "unbound initial snapshot has a non-genesis settle chain/history".into(),
                ));
            }
        }
        (Some(record), Some(members), Some(head)) => {
            if record.channel_id != disk.channel_id || head.channel_id != disk.channel_id {
                return Err(LiveBalanceServiceError::Snapshot(
                    "pinned record/head channel differs from balance account".into(),
                ));
            }
            verify_snapshot(
                &ChannelSnapshot {
                    record: record.clone(),
                    state: head.clone(),
                    members: members.clone(),
                    settled_tx_accumulator: crate::wallet_core::default_settled_tx_accumulator(),
                },
                None,
            )
            .map_err(|e| {
                LiveBalanceServiceError::Snapshot(format!(
                    "pinned channel snapshot/member set: {e}"
                ))
            })?;
            if !disk.awaiting_channel_binding
                && pis.settled_tx_chain != head.balance_state.settled_tx_chain
            {
                return Err(LiveBalanceServiceError::Snapshot(
                    "balance proof settled_tx_chain differs from N-of-N signed head".into(),
                ));
            }
        }
        _ => {
            return Err(LiveBalanceServiceError::Snapshot(
                "channel record, member set, and signed head must be persisted together".into(),
            ));
        }
    }

    let mut previous_producer_generation = 0u64;
    let mut previous_balance_generation = 0u64;
    let mut seen_ids = std::collections::HashSet::new();
    for entry in &disk.applied {
        if entry.request_id != entry.producer_receipt.request_id
            || !seen_ids.insert(entry.request_id.as_str())
            || entry.producer_receipt.generation <= previous_producer_generation
            || entry.result.producer_generation != entry.producer_receipt.generation
            || entry.result.producer_entry_hash != entry.producer_receipt.entry_hash
            || entry.result.producer_extended_state_commitment
                != entry.producer_receipt.extended_state_commitment
            || entry.result.balance_generation != previous_balance_generation + 1
        {
            return Err(LiveBalanceServiceError::Snapshot(
                "applied transition journal is duplicated, non-monotone, or receipt-divergent"
                    .into(),
            ));
        }
        if let Some(material) = &entry.send_material {
            let (stored_pis, _) = verify_balance_proof_bytes(
                &material.balance_proof,
                balance,
                "journaled source send",
            )?;
            // PRE-send proof (see the store site): bound to the transition through the
            // co-journaled spend proof (checked once it is verified below) and by the chain
            // advance to the signed head here.
            if stored_pis.channel_id != disk.channel_id
                || material.channel_record.channel_id != disk.channel_id
                || settled_tx_chain_push(stored_pis.settled_tx_chain, material.settled_leaf)
                    != material.signed_head.balance_state.settled_tx_chain
            {
                return Err(LiveBalanceServiceError::Snapshot(
                    "journaled source-send proof/head/result binding is inconsistent".into(),
                ));
            }
            verify_all_signatures(
                &material.channel_record,
                &[],
                &material.signed_head,
            )
            .map_err(|e| {
                LiveBalanceServiceError::Snapshot(format!(
                    "journaled source-send signed head: {e}"
                ))
            })?;
            let spend_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
                material.spend_proof.clone(),
                &spend.data.common,
            )
            .map_err(|e| {
                LiveBalanceServiceError::Snapshot(format!(
                    "decode journaled source-send spend proof: {e}"
                ))
            })?;
            let journaled_spend_pis =
                SpendPublicInputs::from_pis_u64(&spend_proof.public_inputs.to_u64_vec()).map_err(
                    |e| {
                        LiveBalanceServiceError::Snapshot(format!(
                            "journaled source-send spend pis: {e}"
                        ))
                    },
                )?;
            spend.data.verify(spend_proof).map_err(|e| {
                LiveBalanceServiceError::Snapshot(format!(
                    "verify journaled source-send spend proof: {e}"
                ))
            })?;
            if !journaled_spend_pis.is_valid
                || stored_pis.private_commitment != journaled_spend_pis.prev_private_commitment
                || journaled_spend_pis.new_private_commitment != entry.result.private_commitment
            {
                return Err(LiveBalanceServiceError::Snapshot(
                    "journaled source-send proof/spend/receipt chain is inconsistent".into(),
                ));
            }
        }
        previous_producer_generation = entry.producer_receipt.generation;
        previous_balance_generation = entry.result.balance_generation;
    }
    if let Some(last) = disk.applied.last() {
        if last.result.balance_generation != disk.balance_generation
            || last.result.base_nonce != disk.base_nonce
            || last.result.private_commitment != pis.private_commitment
            || last.result.settled_tx_chain != pis.settled_tx_chain
            || last.result.proof_size != disk.balance_proof.len()
        {
            return Err(LiveBalanceServiceError::Snapshot(
                "snapshot head differs from its last applied transition receipt".into(),
            ));
        }
        if let Some(producer) = producer {
            let canonical = producer.receipt(&last.request_id)?.ok_or_else(|| {
                LiveBalanceServiceError::ProducerReconciliation(format!(
                    "processed producer request {:?} is absent after journal replay",
                    last.request_id
                ))
            })?;
            verify_exact_receipt(producer, &last.producer_receipt, &canonical)?;
        }
    }
    Ok(())
}

fn verify_private_cursor(disk: &LiveBalanceSnapshot) -> Result<(), LiveBalanceServiceError> {
    let sent_len = disk.full_private_state.sent_tx_tree.len();
    if sent_len > u32::MAX as usize
        || disk.base_nonce != disk.full_private_state.nonce
        || sent_len as u32 != disk.full_private_state.nonce
    {
        return Err(LiveBalanceServiceError::Snapshot(format!(
            "base nonce {}, private nonce {}, and sent-tx tree length {} diverge",
            disk.base_nonce, disk.full_private_state.nonce, sent_len
        )));
    }
    Ok(())
}

fn decode_balance_proof(
    disk: &LiveBalanceSnapshot,
    balance: &BalanceProcessor<F, C, D>,
) -> Result<BalanceProof, LiveBalanceServiceError> {
    ProofWithPublicInputs::<F, C, D>::from_bytes(
        disk.balance_proof.clone(),
        &balance.balance_vd().common,
    )
    .map_err(|e| LiveBalanceServiceError::Snapshot(format!("decode balance proof: {e}")))
}

fn verify_balance_proof_bytes(
    bytes: &[u8],
    balance: &BalanceProcessor<F, C, D>,
    label: &str,
) -> Result<
    (
        crate::circuits::balance::balance_pis::BalancePublicInputs,
        usize,
    ),
    LiveBalanceServiceError,
> {
    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
        bytes.to_vec(),
        &balance.balance_vd().common,
    )
    .map_err(|e| LiveBalanceServiceError::Snapshot(format!("decode {label} proof: {e}")))?;
    balance
        .balance_vd()
        .verify(proof.clone())
        .map_err(|e| LiveBalanceServiceError::Snapshot(format!("verify {label} proof: {e}")))?;
    Ok((balance_public_inputs(&proof, balance)?, bytes.len()))
}

fn balance_public_inputs(
    proof: &BalanceProof,
    balance: &BalanceProcessor<F, C, D>,
) -> Result<crate::circuits::balance::balance_pis::BalancePublicInputs, LiveBalanceServiceError> {
    let vd = balance.balance_vd();
    let inputs: Vec<u64> = proof.public_inputs.iter().map(|field| field.0).collect();
    let full = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(&inputs, &vd.common.config)
        .map_err(|e| LiveBalanceServiceError::Snapshot(format!("parse balance PIs: {e}")))?;
    if full.vd.circuit_digest != vd.verifier_only.circuit_digest {
        return Err(LiveBalanceServiceError::Snapshot(
            "balance proof embeds verifier data for a different circuit".into(),
        ));
    }
    Ok(full.pis)
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<Bytes32, LiveBalanceServiceError> {
    let bytes = serde_json::to_vec(value).map_err(|e| {
        LiveBalanceServiceError::Snapshot(format!("canonical transition serialization: {e}"))
    })?;
    Bytes32::from_bytes_be(&keccak_hash::keccak(bytes).0)
        .map_err(|e| LiveBalanceServiceError::Snapshot(format!("convert transition hash: {e}")))
}

fn prepare_snapshot_path(path: &Path) -> Result<PathBuf, LiveBalanceServiceError> {
    let path = path.to_path_buf();
    let parent = snapshot_parent(&path);
    fs::create_dir_all(parent).map_err(|e| {
        LiveBalanceServiceError::Snapshot(format!(
            "create snapshot directory {}: {e}",
            parent.display()
        ))
    })?;
    reject_symlink(&path, "snapshot")?;
    Ok(path)
}

fn read_snapshot(path: &Path) -> Result<LiveBalanceSnapshot, LiveBalanceServiceError> {
    let metadata = fs::metadata(path).map_err(|e| {
        LiveBalanceServiceError::Snapshot(format!("stat snapshot {}: {e}", path.display()))
    })?;
    if !metadata.is_file()
        || metadata.len() < SNAPSHOT_HEADER_BYTES as u64
        || metadata.len() > MAX_SNAPSHOT_BYTES
    {
        return Err(LiveBalanceServiceError::Snapshot(format!(
            "snapshot {} size/type is invalid ({})",
            path.display(),
            metadata.len()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|e| {
            LiveBalanceServiceError::Snapshot(format!("read snapshot {}: {e}", path.display()))
        })?;
    if &bytes[..16] != SNAPSHOT_MAGIC {
        return Err(LiveBalanceServiceError::Snapshot(
            "snapshot magic mismatch".into(),
        ));
    }
    let version = u32::from_le_bytes(bytes[16..20].try_into().expect("fixed header"));
    if version != LIVE_BALANCE_SNAPSHOT_VERSION {
        return Err(LiveBalanceServiceError::Snapshot(format!(
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
        return Err(LiveBalanceServiceError::Snapshot(
            "snapshot payload length is truncated or has trailing data".into(),
        ));
    }
    let expected_checksum = &bytes[28..60];
    let payload = &bytes[SNAPSHOT_HEADER_BYTES..];
    if keccak_hash::keccak(payload).0.as_slice() != expected_checksum {
        return Err(LiveBalanceServiceError::Snapshot(
            "snapshot checksum mismatch".into(),
        ));
    }
    let (disk, consumed) = bincode::serde::decode_from_slice::<LiveBalanceSnapshot, _>(
        payload,
        bincode::config::standard(),
    )
    .map_err(|e| LiveBalanceServiceError::Snapshot(format!("decode snapshot payload: {e}")))?;
    if consumed != payload.len() {
        return Err(LiveBalanceServiceError::Snapshot(
            "snapshot bincode payload has trailing data".into(),
        ));
    }
    Ok(disk)
}

fn persist_snapshot(
    path: &Path,
    disk: &LiveBalanceSnapshot,
) -> Result<(), LiveBalanceServiceError> {
    let payload = bincode::serde::encode_to_vec(disk, bincode::config::standard())
        .map_err(|e| LiveBalanceServiceError::Snapshot(format!("encode snapshot: {e}")))?;
    let total_len = SNAPSHOT_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| LiveBalanceServiceError::Snapshot("snapshot size overflow".into()))?;
    if total_len as u64 > MAX_SNAPSHOT_BYTES {
        return Err(LiveBalanceServiceError::Snapshot(format!(
            "serialized snapshot size {total_len} exceeds {MAX_SNAPSHOT_BYTES}"
        )));
    }
    let mut encoded = Vec::with_capacity(total_len);
    encoded.extend_from_slice(SNAPSHOT_MAGIC);
    encoded.extend_from_slice(&LIVE_BALANCE_SNAPSHOT_VERSION.to_le_bytes());
    encoded.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    encoded.extend_from_slice(&keccak_hash::keccak(&payload).0);
    encoded.extend_from_slice(&payload);

    let parent = snapshot_parent(path);
    let file_name = path.file_name().ok_or_else(|| {
        LiveBalanceServiceError::InvalidRequest(format!(
            "snapshot path {} has no file name",
            path.display()
        ))
    })?;
    let tmp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        file_name.to_string_lossy(),
        std::process::id(),
        disk.balance_generation
    ));
    reject_symlink(&tmp_path, "snapshot temporary file")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| {
            LiveBalanceServiceError::Snapshot(format!(
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
        return Err(LiveBalanceServiceError::Snapshot(format!(
            "atomically persist snapshot {}: {error}",
            path.display()
        )));
    }
    verify_private_mode(path, "snapshot")?;
    Ok(())
}

fn verify_private_mode(path: &Path, label: &str) -> Result<(), LiveBalanceServiceError> {
    let mode = fs::metadata(path)
        .map_err(|e| LiveBalanceServiceError::Snapshot(format!("stat {label}: {e}")))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(LiveBalanceServiceError::Snapshot(format!(
            "{label} {} has mode {mode:o}; required 600",
            path.display()
        )));
    }
    Ok(())
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), LiveBalanceServiceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(LiveBalanceServiceError::Snapshot(format!(
                "{label} {} must not be a symlink",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LiveBalanceServiceError::Snapshot(format!(
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
    fn acquire(snapshot_path: &Path) -> Result<Self, LiveBalanceServiceError> {
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
                LiveBalanceServiceError::Snapshot(format!(
                    "open snapshot lock {}: {e}",
                    lock_path.display()
                ))
            })?;
        verify_private_mode(&lock_path, "snapshot lock")?;
        // SAFETY: `file` owns this descriptor for the lifetime of SnapshotLock.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(LiveBalanceServiceError::Locked(format!(
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
