//! Durable, release-pinned publication of a keyless public close proof.
//!
//! `public_close_prover` deliberately has no L1 key.  This module is the narrow operator boundary
//! that consumes its immutable schema-3 bundle, builds the exact `attestSignedHeadBacking`,
//! `submitCloseIntent`, `finalizeCloseGuarded` and `materializeSignedHead` calldata (both proofs
//! travel as their canonical wire-v3 `.compactProof.bytes`) and publishes them with an encrypted
//! Foundry-keystore account.  Every signed transaction is fsynced before broadcast.  A restart
//! only ever resends those exact raw bytes.

#![cfg(not(target_arch = "wasm32"))]

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::{fd::AsRawFd as _, unix::fs::OpenOptionsExt as _, unix::fs::PermissionsExt as _};

use num_bigint::BigUint;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2_mle::{
    compact_v2::{decode_compact_v2, encode_compact_v2},
    fixture_v2::{
        MLE_VERIFIER_FIXTURE_SCHEMA_V2, MleProofV2Fixture, MleVerifierV2Fixture,
        SOLIDITY_MLE_PROOF_ENCODING_V2, SOLIDITY_MLE_VERIFICATION_CONFIG_ENCODING_V2,
        derive_whir_deployment_profile_v2, proof_encoding_size_upper_bound_v2,
        solidity_abi_encode_mle_proof_v2, solidity_abi_encode_verification_config_v2,
    },
    protocol_schema_v2::{
        CIRCUIT_DIGEST_LENGTH_V2, COMPACT_LAYOUT_HASH_V2, COMPACT_MAGIC_V2,
        MAX_COMPACT_PROOF_BYTES_V2, MAX_WHIR_HINT_BYTES_V2, MAX_WHIR_NARG_BYTES_V2,
        MLE_PROOF_ABI_SIGNATURE_V2, MLE_PROOF_LAYOUT_HASH_V2, MLE_PROTOCOL_VERSION_CURRENT,
        SCHEMA_VERSION_CURRENT,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    circuits::channel::{
        close_asset_backing_circuit::{
            CloseAssetBackingPublicInputs, CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN,
        },
        close_pis::{ChannelClosePublicInputs, CHANNEL_CLOSE_PUBLIC_INPUTS_LEN},
    },
    common::{
        channel::{close_member_set_commitment, token_funds_digest, CloseIntent},
        channel_id::ChannelId,
    },
    constants::MAX_SIG_CLUSTER,
    ethereum_types::{bytes32::Bytes32, u256::U256},
    l1_finality::{L1FinalitySource, L1FinalizedCheckpoint, ANVIL_CHAIN_ID},
    l1_signer_reservation::{self, SignerReservation},
    public_close_prover::PublicCloseIntentDescriptor,
};

/// Journal 6: the signed-head attestation/materialization stages (journal 5) over wire-v3 compact
/// proofs for BOTH statements (journal 4 was the close-only V2 cutover). Older journals, pending
/// closes or deployments cannot be reinterpreted; retire them under their original contracts.
const JOURNAL_VERSION: u32 = 6;
/// Must equal `public_close_prover::PUBLIC_CLOSE_BUNDLE_SCHEMA_VERSION`.
const PUBLIC_CLOSE_MANIFEST_VERSION: u32 =
    crate::public_close_prover::PUBLIC_CLOSE_BUNDLE_SCHEMA_VERSION;
/// Deployment manifest 4: the five constructor-pinned `PinnedMleVerifierV2` adapters (close,
/// withdrawal-claim, post-close-claim, cancel-close on the settlement verifier and CloseAssetBacking
/// on the materializer) with their core/config/WHIR pins, plus the signer-independent exit
/// selectors and topics. There is no mutable VK latch and no single shared MLE verifier any more.
pub const DEPLOYMENT_MANIFEST_VERSION: u32 = 4;
const PUBLICATION_VERSION: u32 = 3;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_INTENT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PUBLIC_INPUT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CLOSE_PROOF_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MLE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_BACKING_PROOF_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BACKING_MLE_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_BACKING_PUBLIC_INPUT_BYTES: u64 = 64 * 1024;
const MAX_JOURNAL_BYTES: u64 = 40 * 1024 * 1024;
const MAX_RAW_TRANSACTION_CHARS: usize = 40 * 1024 * 1024;
const MAX_RPC_JSON_BYTES: usize = 48 * 1024 * 1024;
const PUBLIC_CHALLENGE_PERIOD_FLOOR: u64 = 86_400;

/// Every proof argument is the canonical wire-v3 `bytes compactProof`; the typed encoders below
/// recompute each selector from these signatures and refuse to run if the pinned constant drifts.
pub const SUBMIT_CLOSE_SIGNATURE: &str = concat!(
    "submitCloseIntent(",
    "(uint64,uint64,uint64,uint64,bytes32,bytes32,uint256[10],uint32[10],uint8,bytes32,bytes32,bytes32,uint64,uint64,bytes32,bytes32),",
    "bytes",
    ")"
);
/// `cast sig "$SUBMIT_CLOSE_SIGNATURE"`.
pub const SUBMIT_CLOSE_SELECTOR: &str = "0xae819fa1";
pub const FINALIZE_CLOSE_GUARDED_SIGNATURE: &str = "finalizeCloseGuarded(bytes32,uint64)";
pub const ATTEST_SIGNED_HEAD_BACKING_SIGNATURE: &str = "attestSignedHeadBacking(address,bytes)";
/// `cast sig "attestSignedHeadBacking(address,bytes)"`.
pub const ATTEST_SIGNED_HEAD_BACKING_SELECTOR: &str = "0xeb9ee868";
pub const MATERIALIZE_SIGNED_HEAD_SIGNATURE: &str = "materializeSignedHead(address,bytes)";
/// `cast sig "materializeSignedHead(address,bytes)"`.
pub const MATERIALIZE_SIGNED_HEAD_SELECTOR: &str = "0x583dc4e1";
pub const CLOSE_SUBMITTED_EVENT: &str =
    "CloseSubmitted(bytes32,bytes32,uint64,uint64,uint64,uint256,uint64,uint64,bytes32)";
pub const CLOSE_FINALIZED_EVENT: &str =
    "CloseFinalized(bytes32,bytes32,uint64,uint256,uint64,bytes32)";
pub const SIGNED_HEAD_EXIT_MATERIALIZED_EVENT: &str =
    "SignedHeadExitMaterialized(uint32,address,bytes32,uint8)";
pub const SIGNED_HEAD_BACKING_ATTESTED_EVENT: &str =
    "SignedHeadBackingAttested(uint32,address,bytes32,bytes32,uint64,bytes32)";

#[derive(Debug, thiserror::Error)]
pub enum PublicClosePublisherError {
    #[error("invalid public-close configuration: {0}")]
    Configuration(String),
    #[error("invalid public-close bundle: {0}")]
    Bundle(String),
    #[error("public-close deployment evidence rejected: {0}")]
    Deployment(String),
    #[error("public-close journal conflict: {0}")]
    Conflict(String),
    #[error("public-close journal failure: {0}")]
    Journal(String),
    #[error("L1 command failed: {0}")]
    Command(String),
    #[error("L1 evidence rejected: {0}")]
    Evidence(String),
}

type Result<T> = std::result::Result<T, PublicClosePublisherError>;

#[derive(Clone, Debug)]
pub struct PublicClosePublisherConfig {
    pub bundle_dir: PathBuf,
    /// Independently authenticated final signed-head digest. The publisher rejects a coherent
    /// bundle for any other head before it creates or reuses a WAL entry.
    pub expected_final_channel_state_digest: String,
    pub deployment_manifest_path: PathBuf,
    /// Independent release-review pin for the exact deployment manifest bytes.
    pub deployment_manifest_sha256: String,
    pub journal_path: PathBuf,
    /// Directory used for the per-(chain, signer) nonce lock. It must be private to the operator.
    pub signer_lock_root: PathBuf,
    pub rpc_url: String,
    /// Foundry encrypted-keystore account selector. Raw private-key input is never supported.
    pub account: String,
    /// Only chain 31337 may substitute `latest` for an unavailable finalized tag.
    pub allow_unfinalized_devnet: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicClosePublication {
    pub schema_version: u32,
    pub chain_id: u64,
    pub rollup: String,
    pub manager: String,
    pub materializer: String,
    pub channel_id: u32,
    pub close_intent_digest: String,
    pub artifact_hash: String,
    pub attest_transaction_hash: String,
    pub submit_transaction_hash: Option<String>,
    pub finalize_transaction_hash: Option<String>,
    pub materialize_transaction_hash: String,
    pub finalized_checkpoint: L1FinalizedCheckpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "phase")]
pub enum PublicCloseProgress {
    AttestBroadcast {
        transaction_hash: String,
    },
    /// The exact backing proof was already attested permissionlessly and was adopted only after
    /// finalized event/getter read-back.
    AttestAdopted {
        transaction_hash: String,
    },
    AwaitingAttestReceipt {
        transaction_hash: String,
    },
    AwaitingAttestFinality {
        transaction_hash: String,
        receipt_block: u64,
    },
    AwaitingCloseRequest,
    AwaitingGrace {
        eligible_at: u64,
        durable_time: u64,
    },
    SubmitBroadcast {
        transaction_hash: String,
    },
    /// An independently submitted, exact proof was adopted from a canonical finalized event and
    /// full manager read-back. No local raw transaction is implied.
    SubmitAdopted {
        transaction_hash: String,
    },
    AwaitingSubmitReceipt {
        transaction_hash: String,
    },
    AwaitingSubmitFinality {
        transaction_hash: String,
        receipt_block: u64,
    },
    AwaitingChallengeDeadline {
        challenge_deadline: u64,
        durable_time: u64,
    },
    FinalizeBroadcast {
        transaction_hash: String,
    },
    AwaitingFinalizeReceipt {
        transaction_hash: String,
    },
    AwaitingFinalizeFinality {
        transaction_hash: String,
        receipt_block: u64,
    },
    MaterializeBroadcast {
        transaction_hash: String,
    },
    MaterializeAdopted {
        transaction_hash: String,
    },
    AwaitingMaterializeReceipt {
        transaction_hash: String,
    },
    AwaitingMaterializeFinality {
        transaction_hash: String,
        receipt_block: u64,
    },
    /// A permissionless semantic winner is already final, but this signer had durably prepared
    /// an exact one-shot transaction first. The loser must consume its reserved nonce before the
    /// signer lane can be released for another protocol action.
    AwaitingSupersededReceipt {
        local_step: String,
        transaction_hash: String,
    },
    AwaitingSupersededFinality {
        local_step: String,
        transaction_hash: String,
        receipt_block: u64,
    },
    Complete {
        publication: PublicClosePublication,
    },
}

impl PublicCloseProgress {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicCloseManifest {
    schema_version: u32,
    chain_id: u64,
    rollup: String,
    channel_id: ChannelId,
    balance_verifier_data_sha256: String,
    close_proof_file: String,
    close_proof_bytes: usize,
    close_proof_sha256: String,
    close_mle_file: String,
    close_mle_bytes: usize,
    close_mle_sha256: String,
    backing_proof_file: String,
    backing_proof_bytes: usize,
    backing_proof_sha256: String,
    backing_mle_file: String,
    backing_mle_bytes: usize,
    backing_mle_sha256: String,
    backing_mle_config_file: String,
    backing_mle_config_bytes: usize,
    backing_mle_config_sha256: String,
    backing_public_inputs_file: String,
    backing_public_input_count: usize,
    backing_public_inputs_sha256: String,
    backing_finalized_extended_state_commitment: Bytes32,
    backing_anchor_block_number: u64,
    close_intent_file: String,
    close_intent_sha256: String,
    close_intent_full_file: String,
    close_intent_full_sha256: String,
    close_public_inputs_file: String,
    close_public_input_count: usize,
    close_public_inputs_sha256: String,
    key_material_consumed: bool,
    self_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeploymentManifest {
    schema_version: u32,
    chain_id: u64,
    rollup: String,
    rollup_runtime_code_hash: String,
    manager: String,
    /// Release-reviewed first block for bounded, complete semantic-event discovery.
    manager_deployment_block: u64,
    manager_runtime_code_hash: String,
    close_funding_materializer: String,
    close_funding_materializer_runtime_code_hash: String,
    settlement_verifier: String,
    settlement_verifier_runtime_code_hash: String,
    close_mle_verifier: String,
    close_mle_verifier_runtime_code_hash: String,
    close_mle_verifier_core: String,
    close_mle_verifier_core_runtime_code_hash: String,
    close_mle_verification_config_digest: String,
    close_mle_circuit_config_digest: String,
    close_mle_whir_parameters_digest: String,
    close_mle_whir_protocol_id: String,
    close_mle_whir_session_id: String,
    withdrawal_claim_mle_verifier: String,
    withdrawal_claim_mle_verifier_runtime_code_hash: String,
    withdrawal_claim_mle_verifier_core: String,
    withdrawal_claim_mle_verifier_core_runtime_code_hash: String,
    withdrawal_claim_mle_verification_config_digest: String,
    withdrawal_claim_mle_circuit_config_digest: String,
    withdrawal_claim_mle_whir_parameters_digest: String,
    withdrawal_claim_mle_whir_protocol_id: String,
    withdrawal_claim_mle_whir_session_id: String,
    post_close_claim_mle_verifier: String,
    post_close_claim_mle_verifier_runtime_code_hash: String,
    post_close_claim_mle_verifier_core: String,
    post_close_claim_mle_verifier_core_runtime_code_hash: String,
    post_close_claim_mle_verification_config_digest: String,
    post_close_claim_mle_circuit_config_digest: String,
    post_close_claim_mle_whir_parameters_digest: String,
    post_close_claim_mle_whir_protocol_id: String,
    post_close_claim_mle_whir_session_id: String,
    cancel_close_mle_verifier: String,
    cancel_close_mle_verifier_runtime_code_hash: String,
    cancel_close_mle_verifier_core: String,
    cancel_close_mle_verifier_core_runtime_code_hash: String,
    cancel_close_mle_verification_config_digest: String,
    cancel_close_mle_circuit_config_digest: String,
    cancel_close_mle_whir_parameters_digest: String,
    cancel_close_mle_whir_protocol_id: String,
    cancel_close_mle_whir_session_id: String,
    /// The materializer's constructor-pinned CloseAssetBacking adapter (`backingMleVerifier()`),
    /// pinned exactly like the four settlement statements above.
    backing_mle_verifier: String,
    backing_mle_verifier_runtime_code_hash: String,
    backing_mle_verifier_core: String,
    backing_mle_verifier_core_runtime_code_hash: String,
    backing_mle_verification_config_digest: String,
    backing_mle_circuit_config_digest: String,
    backing_mle_whir_parameters_digest: String,
    backing_mle_whir_protocol_id: String,
    backing_mle_whir_session_id: String,
    balance_verifier_data_sha256: String,
    mle_fixture_schema: String,
    mle_protocol_version: u64,
    mle_proof_abi_signature: String,
    mle_proof_layout_hash: String,
    mle_compact_layout_hash: String,
    mle_compact_proof_encoding: String,
    attest_signed_head_backing_selector: String,
    submit_close_intent_selector: String,
    finalize_close_guarded_selector: String,
    materialize_signed_head_selector: String,
    close_submitted_topic: String,
    close_finalized_topic: String,
    signed_head_backing_attested_topic: String,
    signed_head_exit_materialized_topic: String,
}

#[derive(Clone, Copy)]
struct ManifestMlePin<'a> {
    label: &'static str,
    adapter: &'a str,
    adapter_runtime_code_hash: &'a str,
    core: &'a str,
    core_runtime_code_hash: &'a str,
    verification_config_digest: &'a str,
    circuit_config_digest: &'a str,
    whir_parameters_digest: &'a str,
    whir_protocol_id: &'a str,
    whir_session_id: &'a str,
}

/// Index of the CloseAssetBacking pin inside [`manifest_mle_pins`].
const BACKING_MLE_PIN_INDEX: usize = 4;

fn manifest_mle_pins(manifest: &DeploymentManifest) -> [ManifestMlePin<'_>; 5] {
    [
        ManifestMlePin {
            label: "close",
            adapter: &manifest.close_mle_verifier,
            adapter_runtime_code_hash: &manifest.close_mle_verifier_runtime_code_hash,
            core: &manifest.close_mle_verifier_core,
            core_runtime_code_hash: &manifest.close_mle_verifier_core_runtime_code_hash,
            verification_config_digest: &manifest.close_mle_verification_config_digest,
            circuit_config_digest: &manifest.close_mle_circuit_config_digest,
            whir_parameters_digest: &manifest.close_mle_whir_parameters_digest,
            whir_protocol_id: &manifest.close_mle_whir_protocol_id,
            whir_session_id: &manifest.close_mle_whir_session_id,
        },
        ManifestMlePin {
            label: "withdrawal-claim",
            adapter: &manifest.withdrawal_claim_mle_verifier,
            adapter_runtime_code_hash: &manifest.withdrawal_claim_mle_verifier_runtime_code_hash,
            core: &manifest.withdrawal_claim_mle_verifier_core,
            core_runtime_code_hash: &manifest.withdrawal_claim_mle_verifier_core_runtime_code_hash,
            verification_config_digest: &manifest.withdrawal_claim_mle_verification_config_digest,
            circuit_config_digest: &manifest.withdrawal_claim_mle_circuit_config_digest,
            whir_parameters_digest: &manifest.withdrawal_claim_mle_whir_parameters_digest,
            whir_protocol_id: &manifest.withdrawal_claim_mle_whir_protocol_id,
            whir_session_id: &manifest.withdrawal_claim_mle_whir_session_id,
        },
        ManifestMlePin {
            label: "post-close-claim",
            adapter: &manifest.post_close_claim_mle_verifier,
            adapter_runtime_code_hash: &manifest.post_close_claim_mle_verifier_runtime_code_hash,
            core: &manifest.post_close_claim_mle_verifier_core,
            core_runtime_code_hash: &manifest.post_close_claim_mle_verifier_core_runtime_code_hash,
            verification_config_digest: &manifest.post_close_claim_mle_verification_config_digest,
            circuit_config_digest: &manifest.post_close_claim_mle_circuit_config_digest,
            whir_parameters_digest: &manifest.post_close_claim_mle_whir_parameters_digest,
            whir_protocol_id: &manifest.post_close_claim_mle_whir_protocol_id,
            whir_session_id: &manifest.post_close_claim_mle_whir_session_id,
        },
        ManifestMlePin {
            label: "cancel-close",
            adapter: &manifest.cancel_close_mle_verifier,
            adapter_runtime_code_hash: &manifest.cancel_close_mle_verifier_runtime_code_hash,
            core: &manifest.cancel_close_mle_verifier_core,
            core_runtime_code_hash: &manifest.cancel_close_mle_verifier_core_runtime_code_hash,
            verification_config_digest: &manifest.cancel_close_mle_verification_config_digest,
            circuit_config_digest: &manifest.cancel_close_mle_circuit_config_digest,
            whir_parameters_digest: &manifest.cancel_close_mle_whir_parameters_digest,
            whir_protocol_id: &manifest.cancel_close_mle_whir_protocol_id,
            whir_session_id: &manifest.cancel_close_mle_whir_session_id,
        },
        ManifestMlePin {
            label: "backing",
            adapter: &manifest.backing_mle_verifier,
            adapter_runtime_code_hash: &manifest.backing_mle_verifier_runtime_code_hash,
            core: &manifest.backing_mle_verifier_core,
            core_runtime_code_hash: &manifest.backing_mle_verifier_core_runtime_code_hash,
            verification_config_digest: &manifest.backing_mle_verification_config_digest,
            circuit_config_digest: &manifest.backing_mle_circuit_config_digest,
            whir_parameters_digest: &manifest.backing_mle_whir_parameters_digest,
            whir_protocol_id: &manifest.backing_mle_whir_protocol_id,
            whir_session_id: &manifest.backing_mle_whir_session_id,
        },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedClose {
    close_nonce: u64,
    final_epoch: u64,
    final_small_block_number: u64,
    close_freeze_nonce: u64,
    final_channel_state_digest: String,
    final_balance_state_h1: String,
    channel_fund_amounts: [String; 10],
    token_registry: [u32; 10],
    token_count: u8,
    channel_fund_intmax_state_root: String,
    burn_tx_hash: String,
    close_withdrawal_digest: String,
    snapshot_medium_block_number: u64,
    final_state_version: u64,
    final_settled_tx_chain: String,
    final_settled_tx_accumulator_root: String,
    close_intent_digest: String,
    member_set_commitment: String,
    member_count: u8,
    delegate_count: u16,
    token_funds_digest: String,
}

#[derive(Clone, Debug)]
struct PreparedClose {
    chain_id: u64,
    rollup: String,
    channel_id: u32,
    balance_vd_sha256: String,
    expected: ExpectedClose,
    compact_proof_hash: String,
    compact_proof_length: u32,
    verification_config_digest: String,
    circuit_config_digest: String,
    whir_parameters_digest: String,
    whir_protocol_id: String,
    whir_session_id: String,
    submit_calldata: String,
    /// The CloseAssetBacking statement: its exact compact calldata bytes plus the immutable
    /// config/WHIR pins the materializer's adapter must carry.
    backing_mle: ValidatedMleV2Artifact,
    backing_compact_proof_hash: String,
    backing_compact_proof_length: u32,
    backing_public_inputs: CloseAssetBackingPublicInputs,
    artifact_hash: String,
    component_hashes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BackingAttestationIdentity {
    statement_key: String,
    proof_id: String,
    anchor_plus_one: u64,
}

#[derive(Clone, Debug)]
struct ValidatedMleV2Artifact {
    compact_proof: Vec<u8>,
    verification_config_digest: String,
    circuit_config_digest: String,
    whir_parameters_digest: String,
    whir_protocol_id: String,
    whir_session_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicationBinding {
    schema_version: u32,
    chain_id: u64,
    rollup: String,
    manager: String,
    materializer: String,
    channel_id: u32,
    /// Out-of-band authority supplied by the operator/delegate, not learned from the proof bundle.
    #[serde(default)]
    expected_final_channel_state_digest: String,
    close_intent_digest: String,
    artifact_hash: String,
    component_hashes: BTreeMap<String, String>,
    compact_proof_hash: String,
    compact_proof_length: u32,
    backing_compact_proof_hash: String,
    backing_compact_proof_length: u32,
    mle_fixture_schema: String,
    mle_protocol_version: u64,
    mle_proof_layout_hash: String,
    mle_compact_layout_hash: String,
    deployment_manifest_hash: String,
    attest_calldata_hash: String,
    submit_calldata_hash: String,
    materialize_calldata_hash: String,
    /// Canonical shared root prevents a restart from silently moving nonce coordination to a
    /// publisher-specific directory.
    signer_lock_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedTransaction {
    pub target: String,
    pub calldata_hash: String,
    pub nonce: u64,
    pub raw_signed_transaction: String,
    pub transaction_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FinalizedReceipt {
    transaction_hash: String,
    block_hash: String,
    block_number: u64,
    transaction_index: u64,
    finalized_checkpoint: L1FinalizedCheckpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionStep {
    transaction: SignedTransaction,
    confirmation: Option<FinalizedReceipt>,
    /// Canonical-finalized revert for a locally signed raw transaction which lost a
    /// permissionless semantic race. It is persisted before releasing the durable signer lease.
    #[serde(default)]
    superseded_confirmation: Option<FinalizedReceipt>,
}

/// Durable authority for one exact close-request era. The proof-derived close digest is not a
/// sufficient replay fence because `cancelClose` restores the proof-bound freeze nonce and the same
/// signed state can therefore produce the same digest in a later era. The Manager's monotone
/// `closeRequestGeneration` is read at one canonical durable checkpoint and encoded into the
/// guarded finalizer before signer material is touched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinalizeAuthorization {
    close_request_generation: u64,
    observation_checkpoint: L1FinalizedCheckpoint,
    calldata: String,
    calldata_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicationJournal {
    version: u32,
    binding: PublicationBinding,
    submitter: String,
    attest: Option<TransactionStep>,
    #[serde(default)]
    attest_observation: Option<FinalizedReceipt>,
    submit: Option<TransactionStep>,
    #[serde(default)]
    submit_observation: Option<FinalizedReceipt>,
    #[serde(default)]
    finalize_authorization: Option<FinalizeAuthorization>,
    finalize: Option<TransactionStep>,
    #[serde(default)]
    finalize_observation: Option<FinalizedReceipt>,
    materialize: Option<TransactionStep>,
    #[serde(default)]
    materialize_observation: Option<FinalizedReceipt>,
    completed: Option<PublicClosePublication>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockObservation {
    pub number: u64,
    pub hash: Bytes32,
    pub parent_hash: Bytes32,
    pub timestamp: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedMleVerifier {
    pub adapter: String,
    pub adapter_runtime_code_hash: String,
    pub core: String,
    pub core_runtime_code_hash: String,
    pub verification_config_digest: String,
    pub circuit_config_digest: String,
    pub whir_parameters_digest: String,
    pub whir_protocol_id: String,
    pub whir_session_id: String,
    pub adapter_allowed_chain_id: u64,
    pub core_allowed_chain_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedDeployment {
    pub rollup_runtime_code_hash: String,
    pub manager_runtime_code_hash: String,
    pub close_funding_materializer_runtime_code_hash: String,
    pub settlement_verifier_runtime_code_hash: String,
    pub manager_registry: String,
    pub manager_verifier: String,
    pub manager_close_funding_materializer: String,
    pub materializer_rollup: String,
    pub materializer_manager_of_channel: String,
    pub materializer_frozen_generation: u64,
    pub materializer_last_posted_block: u64,
    pub signed_head_backing_anchor_plus_one: u64,
    pub exact_backing_proof_attested: bool,
    pub signed_head_backing_current: bool,
    pub materialized_channel_exit: String,
    pub rollup_latest_finalized_block_number: u64,
    pub backing_root_finalized: bool,
    pub close_mle: ObservedMleVerifier,
    pub withdrawal_claim_mle: ObservedMleVerifier,
    pub post_close_claim_mle: ObservedMleVerifier,
    pub cancel_close_mle: ObservedMleVerifier,
    /// Read through `materializer.backingMleVerifier()`.
    pub backing_mle: ObservedMleVerifier,
    pub manager_channel_id: u32,
    pub challenge_period: u64,
    pub registered_member_set_commitment: String,
    pub active_member_count: u8,
    pub active_delegate_count: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedPendingClose {
    pub active: bool,
    pub close_nonce: u64,
    pub final_epoch: u64,
    pub final_small_block_number: u64,
    pub close_freeze_nonce: u64,
    pub challenge_deadline: u64,
    pub close_intent_digest: String,
    pub final_channel_state_digest: String,
    pub final_balance_state_h1: String,
    pub channel_fund_amounts: [String; 10],
    pub token_registry: [u32; 10],
    pub token_count: u8,
    pub channel_fund_intmax_state_root: String,
    pub burn_tx_hash: String,
    pub close_withdrawal_digest: String,
    pub snapshot_medium_block_number: u64,
    pub final_state_version: u64,
    pub final_settled_tx_chain: String,
    pub final_settled_tx_accumulator_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedFinalizedClose {
    pub close_intent_digest: String,
    pub final_channel_state_digest: String,
    pub final_balance_state_h1: String,
    pub burn_tx_hash: String,
    pub close_withdrawal_digest: String,
    pub channel_fund_intmax_state_root: String,
    pub final_settled_tx_chain: String,
    pub final_settled_tx_accumulator_root: String,
    pub final_epoch: u64,
    pub final_small_block_number: u64,
    pub final_state_version: u64,
    pub token_registry: [u32; 10],
    pub token_count: u8,
    /// Per-slot view of `finalizedChannelFundAmount[finalizedTokenRegistry[slot]]`.
    pub finalized_fund_caps: [String; 10],
    pub authorized_burn_snapshot_active: bool,
    pub authorized_burn_epoch: u64,
    pub authorized_burn_state_version: u64,
    /// Per-slot view of `authorizedBurnPostFundAmount[finalizedTokenRegistry[slot]]`.
    pub authorized_burn_post_funds: [String; 10],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagerObservation {
    /// 0 = Active, 1 = ClosePending, 2 = Closed.
    pub status: u8,
    pub current_close_freeze_nonce: u64,
    /// Monotone manager-lifetime close request identity. Unlike the proof nonce, cancellation
    /// never restores this value.
    pub close_request_generation: u64,
    pub close_requested_at: u64,
    pub close_challenge_horizon: u64,
    pub block_timestamp: u64,
    pub pending: Option<ObservedPendingClose>,
    pub finalized: Option<ObservedFinalizedClose>,
}

/// Narrow L1 interface used by the deterministic state machine. The production implementation is
/// `CastCloseBackend`; tests use a fault-injecting fake to exercise every WAL/broadcast boundary.
trait ClosePublisherBackend {
    fn chain_id(&mut self) -> Result<u64>;
    fn signer_address(&mut self, account: &str) -> Result<String>;
    fn durable_checkpoint(
        &mut self,
        allow_unfinalized_devnet: bool,
    ) -> Result<L1FinalizedCheckpoint>;
    fn block_at(&mut self, number: u64, source: L1FinalitySource) -> Result<BlockObservation>;
    fn observe_deployment(
        &mut self,
        manifest: &DeploymentManifest,
        prepared: &PreparedClose,
        block_number: u64,
    ) -> Result<ObservedDeployment>;
    fn observe_manager(&mut self, manager: &str, block_number: u64) -> Result<ManagerObservation>;
    fn sign_transaction(
        &mut self,
        account: &str,
        chain_id: u64,
        signer: &str,
        target: &str,
        calldata: &str,
    ) -> Result<SignedTransaction>;
    fn inspect_signed_transaction(
        &mut self,
        raw: &str,
        chain_id: u64,
        signer: &str,
        target: &str,
        calldata: &str,
    ) -> Result<SignedTransaction>;
    fn transaction_known(&mut self, transaction_hash: &str) -> Result<bool>;
    fn account_nonce(&mut self, signer: &str) -> Result<u64>;
    fn publish_raw(&mut self, raw: &str) -> Result<String>;
    fn receipt(&mut self, transaction_hash: &str) -> Result<Option<Value>>;
    fn event_transaction_hashes(
        &mut self,
        manager: &str,
        topic0: &str,
        indexed_digest: &str,
        from_block: u64,
        through_block: u64,
    ) -> Result<Vec<String>>;
}

#[derive(Clone, Debug)]
enum AbiKind {
    Address,
    Bool,
    Uint(usize),
    FixedBytes(usize),
    Bytes,
    Tuple(Vec<AbiField>),
    FixedArray(Box<AbiKind>, usize),
}

#[derive(Clone, Debug)]
struct AbiField {
    name: &'static str,
    kind: AbiKind,
}

impl AbiField {
    fn new(name: &'static str, kind: AbiKind) -> Self {
        Self { name, kind }
    }
}

fn uint(name: &'static str, bits: usize) -> AbiField {
    AbiField::new(name, AbiKind::Uint(bits))
}

fn bytes32(name: &'static str) -> AbiField {
    AbiField::new(name, AbiKind::FixedBytes(32))
}

fn close_intent_fields() -> Vec<AbiField> {
    vec![
        uint("closeNonce", 64),
        uint("finalEpoch", 64),
        uint("finalSmallBlockNumber", 64),
        uint("closeFreezeNonce", 64),
        bytes32("finalChannelStateDigest"),
        bytes32("finalBalanceStateH1"),
        AbiField::new(
            "channelFundAmounts",
            AbiKind::FixedArray(Box::new(AbiKind::Uint(256)), 10),
        ),
        AbiField::new(
            "tokenRegistry",
            AbiKind::FixedArray(Box::new(AbiKind::Uint(32)), 10),
        ),
        uint("tokenCount", 8),
        bytes32("channelFundIntmaxStateRoot"),
        bytes32("burnTxHash"),
        bytes32("closeWithdrawalDigest"),
        uint("snapshotMediumBlockNumber", 64),
        uint("finalStateVersion", 64),
        bytes32("finalSettledTxChain"),
        bytes32("finalSettledTxAccumulatorRoot"),
    ]
}

impl AbiKind {
    fn signature(&self) -> String {
        match self {
            Self::Address => "address".into(),
            Self::Bool => "bool".into(),
            Self::Uint(bits) => format!("uint{bits}"),
            Self::FixedBytes(size) => format!("bytes{size}"),
            Self::Bytes => "bytes".into(),
            Self::Tuple(fields) => format!(
                "({})",
                fields
                    .iter()
                    .map(|field| field.kind.signature())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::FixedArray(element, length) => format!("{}[{length}]", element.signature()),
        }
    }

    fn is_dynamic(&self) -> bool {
        match self {
            Self::Bytes => true,
            Self::Tuple(fields) => fields.iter().any(|field| field.kind.is_dynamic()),
            Self::FixedArray(element, _) => element.is_dynamic(),
            Self::Address | Self::Bool | Self::Uint(_) | Self::FixedBytes(_) => false,
        }
    }

    fn static_size(&self) -> std::result::Result<usize, String> {
        if self.is_dynamic() {
            return Err("dynamic ABI value has no static size".into());
        }
        match self {
            Self::Address | Self::Bool | Self::Uint(_) | Self::FixedBytes(_) => Ok(32),
            Self::Tuple(fields) => fields.iter().try_fold(0usize, |total, field| {
                total
                    .checked_add(field.kind.static_size()?)
                    .ok_or_else(|| "ABI static tuple size overflow".to_string())
            }),
            Self::FixedArray(element, length) => element
                .static_size()?
                .checked_mul(*length)
                .ok_or_else(|| "ABI fixed-array size overflow".into()),
            Self::Bytes => unreachable!("dynamic checked above"),
        }
    }
}

fn json_member<'a>(
    value: &'a Value,
    field: &AbiField,
    path: &str,
) -> std::result::Result<&'a Value, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{path} must be a JSON object"))?;
    object
        .get(field.name)
        .ok_or_else(|| format!("{path}.{} is missing", field.name))
}

fn parse_uint_value(
    value: &Value,
    bits: usize,
    path: &str,
) -> std::result::Result<BigUint, String> {
    let owned;
    let text = match value {
        Value::String(value) => value.as_str(),
        Value::Number(value) => {
            owned = value
                .as_u64()
                .ok_or_else(|| format!("{path} must be an unsigned integer"))?
                .to_string();
            owned.as_str()
        }
        _ => return Err(format!("{path} must be an unsigned integer")),
    };
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!(
            "{path} must be a canonical decimal unsigned integer"
        ));
    }
    let parsed = BigUint::parse_bytes(text.as_bytes(), 10)
        .ok_or_else(|| format!("{path} is not an unsigned integer"))?;
    if bits == 0 || bits > 256 || parsed >= (BigUint::from(1u8) << bits) {
        return Err(format!("{path} does not fit uint{bits}"));
    }
    Ok(parsed)
}

fn decode_hex(
    value: &str,
    exact: Option<usize>,
    path: &str,
) -> std::result::Result<Vec<u8>, String> {
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| format!("{path} must be 0x-prefixed hex"))?;
    if body.len() % 2 != 0 || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{path} is malformed hex"));
    }
    let decoded = hex::decode(body).map_err(|error| format!("decode {path}: {error}"))?;
    if let Some(expected) = exact {
        if decoded.len() != expected {
            return Err(format!(
                "{path} has {} bytes; expected exactly {expected}",
                decoded.len()
            ));
        }
    }
    Ok(decoded)
}

fn normalize_hex(value: &str, bytes: usize, path: &str) -> std::result::Result<String, String> {
    Ok(format!(
        "0x{}",
        hex::encode(decode_hex(value, Some(bytes), path)?)
    ))
}

fn normalize_nonzero_hex(
    value: &str,
    bytes: usize,
    path: &str,
) -> std::result::Result<String, String> {
    let normalized = normalize_hex(value, bytes, path)?;
    if decode_hex(&normalized, Some(bytes), path)?
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(format!("{path} must be nonzero"));
    }
    Ok(normalized)
}

fn same_hex(left: &str, right: &str) -> bool {
    left.trim_start_matches("0x")
        .eq_ignore_ascii_case(right.trim_start_matches("0x"))
}

fn abi_word_from_usize(value: usize) -> std::result::Result<Vec<u8>, String> {
    let value = u64::try_from(value).map_err(|_| "ABI length/offset does not fit u64")?;
    let mut word = vec![0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    Ok(word)
}

fn encode_sequence<'a>(
    values: impl IntoIterator<Item = (&'a AbiKind, &'a Value, String)>,
) -> std::result::Result<Vec<u8>, String> {
    let values: Vec<_> = values.into_iter().collect();
    let head_size = values.iter().try_fold(0usize, |total, (kind, _, _)| {
        let size = if kind.is_dynamic() {
            32
        } else {
            kind.static_size()?
        };
        total
            .checked_add(size)
            .ok_or_else(|| "ABI head size overflow".to_string())
    })?;
    let mut head = Vec::with_capacity(head_size);
    let mut tail = Vec::new();
    for (kind, value, path) in values {
        if kind.is_dynamic() {
            head.extend(abi_word_from_usize(
                head_size
                    .checked_add(tail.len())
                    .ok_or_else(|| "ABI offset overflow".to_string())?,
            )?);
            tail.extend(encode_value_body(kind, value, &path)?);
        } else {
            head.extend(encode_value_body(kind, value, &path)?);
        }
    }
    debug_assert_eq!(head.len(), head_size);
    head.extend(tail);
    Ok(head)
}

fn encode_value_body(
    kind: &AbiKind,
    value: &Value,
    path: &str,
) -> std::result::Result<Vec<u8>, String> {
    match kind {
        AbiKind::Address => {
            let bytes = decode_hex(
                value
                    .as_str()
                    .ok_or_else(|| format!("{path} must be a hex address"))?,
                Some(20),
                path,
            )?;
            if bytes.iter().all(|byte| *byte == 0) {
                return Err(format!("{path} must be a nonzero address"));
            }
            let mut word = vec![0u8; 32];
            word[12..].copy_from_slice(&bytes);
            Ok(word)
        }
        AbiKind::Bool => {
            let boolean = value
                .as_bool()
                .ok_or_else(|| format!("{path} must be a JSON boolean"))?;
            let mut word = vec![0u8; 32];
            word[31] = u8::from(boolean);
            Ok(word)
        }
        AbiKind::Uint(bits) => {
            let bytes = parse_uint_value(value, *bits, path)?.to_bytes_be();
            let mut word = vec![0u8; 32];
            word[32 - bytes.len()..].copy_from_slice(&bytes);
            Ok(word)
        }
        AbiKind::FixedBytes(size) => {
            let bytes = decode_hex(
                value
                    .as_str()
                    .ok_or_else(|| format!("{path} must be hex"))?,
                Some(*size),
                path,
            )?;
            let mut word = vec![0u8; 32];
            word[..*size].copy_from_slice(&bytes);
            Ok(word)
        }
        AbiKind::Bytes => {
            let bytes = decode_hex(
                value
                    .as_str()
                    .ok_or_else(|| format!("{path} must be hex"))?,
                None,
                path,
            )?;
            let padded = bytes
                .len()
                .checked_add(31)
                .ok_or_else(|| "ABI bytes length overflow".to_string())?
                / 32
                * 32;
            let mut encoded = abi_word_from_usize(bytes.len())?;
            encoded.resize(32 + padded, 0);
            encoded[32..32 + bytes.len()].copy_from_slice(&bytes);
            Ok(encoded)
        }
        AbiKind::Tuple(fields) => {
            let members = fields
                .iter()
                .map(|field| {
                    json_member(value, field, path)
                        .map(|member| (&field.kind, member, format!("{path}.{}", field.name)))
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            encode_sequence(members)
        }
        AbiKind::FixedArray(element, expected) => {
            let array = value
                .as_array()
                .ok_or_else(|| format!("{path} must be an array"))?;
            if array.len() != *expected {
                return Err(format!(
                    "{path} has {} elements; expected exactly {expected}",
                    array.len()
                ));
            }
            encode_sequence(
                array
                    .iter()
                    .enumerate()
                    .map(|(index, value)| (element.as_ref(), value, format!("{path}[{index}]"))),
            )
        }
    }
}

fn encode_function(
    name: &str,
    args: &[(&AbiKind, &Value, &str)],
) -> std::result::Result<String, String> {
    let signature = format!(
        "{name}({})",
        args.iter()
            .map(|(kind, _, _)| kind.signature())
            .collect::<Vec<_>>()
            .join(",")
    );
    let selector = keccak_hash::keccak(signature.as_bytes()).0;
    let mut calldata = selector[..4].to_vec();
    calldata
        .extend(encode_sequence(args.iter().map(|(kind, value, path)| {
            (*kind, *value, (*path).to_string())
        }))?);
    Ok(format!("0x{}", hex::encode(calldata)))
}

fn selector(signature: &str) -> String {
    format!(
        "0x{}",
        hex::encode(&keccak_hash::keccak(signature.as_bytes()).0[..4])
    )
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak_hash::keccak(bytes).0))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn close_signer_reservation(
    chain_id: u64,
    signer: &str,
    journal_path: &Path,
    binding: &PublicationBinding,
    phase: &str,
    target: &str,
    calldata_hash: &str,
    close_request_generation: Option<u64>,
) -> Result<SignerReservation> {
    let material = serde_json::json!({
        "schemaVersion": 1,
        "artifactHash": binding.artifact_hash,
        "closeIntentDigest": binding.close_intent_digest,
        "phase": phase,
        "target": normalize_hex(target, 20, "reservation target")
            .map_err(PublicClosePublisherError::Configuration)?,
        "calldataHash": normalize_hex(calldata_hash, 32, "reservation calldata hash")
            .map_err(PublicClosePublisherError::Configuration)?,
        "closeRequestGeneration": close_request_generation,
        "value": "0",
    });
    let intent_hash = sha256_hex(canonical_json(&material).as_bytes());
    SignerReservation::new(
        chain_id,
        signer,
        "public-close",
        journal_path,
        phase,
        &intent_hash,
    )
    .map_err(PublicClosePublisherError::Configuration)
}

fn claim_signer_reservation(root: &Path, reservation: &SignerReservation) -> Result<()> {
    l1_signer_reservation::claim(root, reservation).map_err(|error| {
        PublicClosePublisherError::Conflict(format!("signer reservation: {error}"))
    })
}

fn release_signer_reservation(root: &Path, reservation: &SignerReservation) -> Result<()> {
    l1_signer_reservation::release(root, reservation)
        .map_err(|error| PublicClosePublisherError::Journal(format!("signer reservation: {error}")))
}

fn release_exact_signer_reservation(root: &Path, reservation: &SignerReservation) -> Result<bool> {
    l1_signer_reservation::release_if_exact(root, reservation)
        .map_err(|error| PublicClosePublisherError::Journal(format!("signer reservation: {error}")))
}

fn sign_after_reservation<T>(
    root: &Path,
    reservation: &SignerReservation,
    sign: impl FnOnce() -> Result<T>,
) -> Result<T> {
    claim_signer_reservation(root, reservation)?;
    match sign() {
        Ok(value) => Ok(value),
        Err(sign_error) => match release_signer_reservation(root, reservation) {
            Ok(()) => Err(sign_error),
            Err(release_error) => Err(PublicClosePublisherError::Journal(format!(
                "offline signing failed ({sign_error}); reservation release also failed ({release_error})"
            ))),
        },
    }
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).expect("JSON scalar serialization")
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(object) => {
            let sorted: BTreeMap<&str, &Value> = object
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect();
            format!(
                "{{{}}}",
                sorted
                    .iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("JSON key serialization"),
                        canonical_json(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn fixed_bundle_path(root: &Path, actual: &str, required: &str) -> Result<PathBuf> {
    if actual != required {
        return Err(PublicClosePublisherError::Bundle(format!(
            "manifest names {actual:?}; required immutable filename is {required:?}"
        )));
    }
    Ok(root.join(required))
}

fn inspect_regular_file(path: &Path, maximum: u64, what: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        PublicClosePublisherError::Bundle(format!("inspect {what} {}: {error}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PublicClosePublisherError::Bundle(format!(
            "{what} {} must be a regular non-symlink file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(PublicClosePublisherError::Bundle(format!(
            "{what} {} exceeds {maximum} bytes",
            path.display()
        )));
    }
    Ok(metadata)
}

fn read_bounded(path: &Path, maximum: u64, what: &str) -> Result<Vec<u8>> {
    inspect_regular_file(path, maximum, what)?;
    let file = fs::File::open(path).map_err(|error| {
        PublicClosePublisherError::Bundle(format!("open {what} {}: {error}", path.display()))
    })?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            PublicClosePublisherError::Bundle(format!("read {what} {}: {error}", path.display()))
        })?;
    if bytes.len() as u64 > maximum {
        return Err(PublicClosePublisherError::Bundle(format!(
            "{what} exceeds {maximum} bytes"
        )));
    }
    Ok(bytes)
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], what: &str) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|error| PublicClosePublisherError::Bundle(format!("parse {what}: {error}")))
}

fn normalize_decimal(value: &str, bits: usize, path: &str) -> Result<String> {
    parse_uint_value(&Value::String(value.to_string()), bits, path)
        .map(|value| value.to_string())
        .map_err(PublicClosePublisherError::Bundle)
}

fn expect_hex(value: &str, bytes: usize, path: &str) -> Result<String> {
    normalize_hex(value, bytes, path).map_err(PublicClosePublisherError::Bundle)
}

fn generated_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Which statement a wire-v3 fixture must carry; decides the public-input width and the canonical
/// limb domain (`u32` limbs, except the CloseAssetBacking anchor block number which is `u63`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MleStatement {
    Close,
    Backing,
}

impl MleStatement {
    fn public_input_count(self) -> usize {
        match self {
            Self::Close => CHANNEL_CLOSE_PUBLIC_INPUTS_LEN,
            Self::Backing => CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN,
        }
    }

    fn public_input_file(self) -> &'static str {
        match self {
            Self::Close => "close_public_inputs.json",
            Self::Backing => "backing_public_inputs.json",
        }
    }

    fn limb_bound(self, index: usize) -> u64 {
        match self {
            Self::Close => 1u64 << 32,
            Self::Backing if index == CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN - 1 => 1u64 << 63,
            Self::Backing => 1u64 << 32,
        }
    }
}

fn validate_mle_public_inputs(
    statement: MleStatement,
    public_inputs: &[String],
    expected: &[u64],
) -> Result<()> {
    if public_inputs.len() != expected.len() {
        return Err(PublicClosePublisherError::Bundle(format!(
            "MLE proof public input count {} differs from {} {}",
            public_inputs.len(),
            statement.public_input_file(),
            expected.len()
        )));
    }
    for (index, (value, expected)) in public_inputs.iter().zip(expected).enumerate() {
        let digits = value.strip_prefix("0x").ok_or_else(|| {
            PublicClosePublisherError::Bundle(format!(
                "mleProof.publicInputs[{index}] must have a lowercase 0x prefix"
            ))
        })?;
        if digits.len() != 16
            || !digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PublicClosePublisherError::Bundle(format!(
                "mleProof.publicInputs[{index}] must be a canonical 64-bit Goldilocks limb"
            )));
        }
        let actual = u64::from_str_radix(digits, 16).map_err(|error| {
            PublicClosePublisherError::Bundle(format!(
                "decode mleProof.publicInputs[{index}]: {error}"
            ))
        })?;
        if actual >= statement.limb_bound(index) || actual != *expected {
            return Err(PublicClosePublisherError::Bundle(format!(
                "mleProof.publicInputs[{index}] is non-canonical or differs from {}",
                statement.public_input_file()
            )));
        }
    }
    Ok(())
}

/// Authenticate the strict full v2 artifact and return its one canonical compact byte stream.
/// The JSON proof and Solidity ABI record are consistency witnesses only; neither is accepted as
/// an alternate manager-calldata representation.
fn validated_compact_mle_v2_fixture(
    statement: MleStatement,
    json: &str,
    public_inputs: &[u64],
) -> Result<ValidatedMleV2Artifact> {
    let fail = |message: String| PublicClosePublisherError::Bundle(message);
    let fixture = MleVerifierV2Fixture::from_canonical_json(json)
        .map_err(|error| fail(format!("strict canonical MLE/WHIR v2 fixture: {error}")))?;
    fixture
        .config_fixture()
        .validate_self_consistency()
        .map_err(|error| fail(format!("self-consistent MLE/WHIR deployment config: {error}")))?;
    if fixture.schema != MLE_VERIFIER_FIXTURE_SCHEMA_V2
        || fixture.schema_version != SCHEMA_VERSION_CURRENT
        || fixture.protocol_version != MLE_PROTOCOL_VERSION_CURRENT
        || fixture.proof.protocol_version != MLE_PROTOCOL_VERSION_CURRENT
        || fixture.verification_key.protocol_version != MLE_PROTOCOL_VERSION_CURRENT
        || fixture.proof_abi_signature != MLE_PROOF_ABI_SIGNATURE_V2
        || fixture.proof_layout_hash != generated_hex(&MLE_PROOF_LAYOUT_HASH_V2)
    {
        return Err(fail(
            "MLE/WHIR v2 fixture schema/protocol/proof-layout identity mismatch".into(),
        ));
    }

    let proof = &fixture.proof;
    let vk = &fixture.verification_key;
    let config = &fixture.verification_config;
    let pinned = &fixture.pinned_verifier;
    let shape = fixture.compact_shape.decode();
    let expected_gate_round_degree = config
        .circuit
        .quotient_degree_factor
        .checked_add(2)
        .ok_or_else(|| fail("MLE/WHIR v2 gate round degree overflow".into()))?;
    if shape.circuit_digest_len != CIRCUIT_DIGEST_LENGTH_V2
        || shape.max_whir_narg_bytes != MAX_WHIR_NARG_BYTES_V2
        || shape.max_whir_hint_bytes != MAX_WHIR_HINT_BYTES_V2
        || shape.max_encoded_bytes != MAX_COMPACT_PROOF_BYTES_V2
        || shape.constituent_width != proof.constituent_width
        || shape.constituent_width != vk.constituent_width
        || shape.public_inputs_len != proof.public_inputs.len()
        || shape.public_inputs_len != statement.public_input_count()
        || shape.degree_bits != config.circuit.degree_bits
        || shape.public_inputs_len != config.circuit.num_public_inputs
        || shape.num_constants != config.circuit.num_constants
        || shape.num_routed_wires != config.circuit.num_routed_wires
        || shape.num_wires != config.circuit.num_wires
        || shape.gate_round_degree != expected_gate_round_degree
        || config.circuit.num_constants != vk.num_constants
        || config.circuit.num_routed_wires != vk.num_routed_wires
        || config.circuit.num_wires != vk.num_wires
        || config.circuit.num_selectors != vk.num_selectors
        || config.circuit.num_gate_constraints != vk.num_gate_constraints
        || config.circuit.quotient_degree_factor != vk.quotient_degree_factor
        || config.public_input_wire_map != vk.public_input_wire_map
        || config.k_is != vk.k_is
        || config.subgroup_gen_powers != vk.subgroup_gen_powers
        || config.gates != vk.gates
    {
        return Err(fail(
            "MLE/WHIR v2 fixture proof/VK/config/compact shape mismatch".into(),
        ));
    }
    if proof.circuit_digest.len() != CIRCUIT_DIGEST_LENGTH_V2
        || proof.circuit_digest != vk.circuit_digest
        || pinned.circuit_digest.as_slice() != vk.circuit_digest.as_slice()
        || proof.preprocessed_root != vk.preprocessed_commitment_root
        || pinned.preprocessed_commitment_root != vk.preprocessed_commitment_root
        || pinned.circuit_config_digest != vk.circuit_config_digest
        || pinned.whir_protocol_id != vk.whir_protocol_id
        || pinned.whir_session_id != vk.whir_session_id
    {
        return Err(fail(
            "MLE/WHIR v2 fixture proof/VK/pinned views disagree".into(),
        ));
    }
    vk.try_decode::<GoldilocksField>()
        .map_err(|error| fail(format!("canonical MLE/WHIR v2 verification key: {error}")))?;

    let recorded_solidity_abi = fixture
        .solidity_abi_proof
        .decode_and_validate(SOLIDITY_MLE_PROOF_ENCODING_V2)
        .map_err(|error| fail(format!("MLE/WHIR v2 Solidity proof record: {error}")))?;
    let expected_solidity_abi = solidity_abi_encode_mle_proof_v2(proof)
        .map_err(|error| fail(format!("canonical MLE/WHIR v2 Solidity proof: {error}")))?;
    if recorded_solidity_abi != expected_solidity_abi {
        return Err(fail(
            "MLE/WHIR v2 Solidity proof bytes disagree with the proof object".into(),
        ));
    }

    let recorded_config_abi = fixture
        .solidity_abi_verification_config
        .decode_and_validate(SOLIDITY_MLE_VERIFICATION_CONFIG_ENCODING_V2)
        .map_err(|error| fail(format!("MLE/WHIR v2 Solidity config record: {error}")))?;
    let expected_config_abi = solidity_abi_encode_verification_config_v2(config)
        .map_err(|error| fail(format!("canonical MLE/WHIR v2 Solidity config: {error}")))?;
    if recorded_config_abi != expected_config_abi
        || pinned.verification_config_digest != fixture.solidity_abi_verification_config.keccak256
    {
        return Err(fail(
            "MLE/WHIR v2 Solidity config bytes/digest disagree with pinned views".into(),
        ));
    }

    let compact_encoding = std::str::from_utf8(&COMPACT_MAGIC_V2).map_err(|error| {
        fail(format!(
            "generated compact-v2 encoding is not UTF-8: {error}"
        ))
    })?;
    let compact = fixture
        .compact_proof
        .decode_and_validate(compact_encoding)
        .map_err(|error| fail(format!("MLE/WHIR v2 compact proof record: {error}")))?;
    if compact.is_empty() || compact.len() > MAX_COMPACT_PROOF_BYTES_V2 {
        return Err(fail(format!(
            "MLE/WHIR v2 compact proof length {} is outside 1..={MAX_COMPACT_PROOF_BYTES_V2}",
            compact.len()
        )));
    }
    let decoded = decode_compact_v2::<GoldilocksField>(&compact, &shape)
        .map_err(|error| fail(format!("strict MLE/WHIR v2 compact decode: {error}")))?;
    if MleProofV2Fixture::encode(&decoded) != *proof {
        return Err(fail(
            "MLE/WHIR v2 compact bytes disagree with the proof object".into(),
        ));
    }
    let reencoded = encode_compact_v2(&decoded, &shape)
        .map_err(|error| fail(format!("canonical MLE/WHIR v2 compact encode: {error}")))?;
    if reencoded != compact {
        return Err(fail(
            "MLE/WHIR v2 compact proof is not canonically encoded".into(),
        ));
    }

    let profile = derive_whir_deployment_profile_v2(shape.degree_bits, shape.constituent_width)
        .map_err(|error| fail(format!("canonical MLE/WHIR v2 profile: {error}")))?;
    if config.whir != profile.params
        || vk.whir_protocol_id != generated_hex(&profile.protocol_id)
        || vk.whir_session_id != generated_hex(&profile.session_id)
        || pinned.whir_parameters_digest != generated_hex(&profile.parameters_digest)
    {
        return Err(fail(
            "MLE/WHIR v2 native WHIR profile or pinned identifiers drifted".into(),
        ));
    }
    let upper_bound = proof_encoding_size_upper_bound_v2(&shape)
        .map_err(|error| fail(format!("MLE/WHIR v2 size upper bound: {error}")))?;
    if fixture.size_upper_bound != upper_bound
        || !upper_bound.fits_whir_blob_caps
        || !upper_bound.fits_compact_cap
        || compact.len() > upper_bound.max_compact_bytes
        || recorded_solidity_abi.len() > upper_bound.max_solidity_abi_bytes
        || decoded.whir_eval_proof.narg_string.len() != upper_bound.max_whir_transcript_bytes
        || decoded.whir_eval_proof.hints.len() > upper_bound.max_whir_hint_bytes
        || fixture.stats.solidity_abi_bytes != recorded_solidity_abi.len()
        || fixture.stats.solidity_abi_verification_config_bytes != recorded_config_abi.len()
        || fixture.stats.compact_bytes != compact.len()
        || fixture.stats.whir_transcript_bytes != decoded.whir_eval_proof.narg_string.len()
        || fixture.stats.whir_hint_bytes != decoded.whir_eval_proof.hints.len()
    {
        return Err(fail(
            "MLE/WHIR v2 proof statistics or resource envelope mismatch".into(),
        ));
    }

    validate_mle_public_inputs(statement, &proof.public_inputs, public_inputs)?;
    Ok(ValidatedMleV2Artifact {
        compact_proof: compact,
        verification_config_digest: pinned.verification_config_digest.clone(),
        circuit_config_digest: pinned.circuit_config_digest.clone(),
        whir_parameters_digest: pinned.whir_parameters_digest.clone(),
        whir_protocol_id: pinned.whir_protocol_id.clone(),
        whir_session_id: pinned.whir_session_id.clone(),
    })
}

fn parse_public_input_array(value: &Value, path: &str) -> Result<Vec<u64>> {
    let array = value
        .as_array()
        .ok_or_else(|| PublicClosePublisherError::Bundle(format!("{path} must be an array")))?;
    array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let parsed = parse_uint_value(value, 32, &format!("{path}[{index}]"))
                .map_err(PublicClosePublisherError::Bundle)?;
            u64::try_from(parsed).map_err(|_| {
                PublicClosePublisherError::Bundle(format!("{path}[{index}] does not fit u64"))
            })
        })
        .collect()
}

/// The standalone backing PI payload is a strict JSON array of unsigned u64 numbers. It is not an
/// alternate textual encoding surface: the prover writes `Vec<u64>`, and schema 2 binds those exact
/// bytes. `CloseAssetBackingPublicInputs::from_u64_slice` subsequently enforces the narrower type
/// of each of the 26 positions (25 u32 limbs followed by one U63 anchor).
fn parse_backing_public_input_array(value: &Value, path: &str) -> Result<Vec<u64>> {
    let array = value
        .as_array()
        .ok_or_else(|| PublicClosePublisherError::Bundle(format!("{path} must be an array")))?;
    array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value.as_u64().ok_or_else(|| {
                PublicClosePublisherError::Bundle(format!(
                    "{path}[{index}] must be a JSON u64 number"
                ))
            })
        })
        .collect()
}

fn require_component_sha256(bytes: &[u8], declared: &str, what: &str) -> Result<()> {
    let declared = expect_hex(declared, 32, &format!("manifest.{what}Sha256"))?;
    let actual = sha256_hex(bytes);
    if declared != actual {
        return Err(PublicClosePublisherError::Bundle(format!(
            "{what} SHA-256 {actual} differs from manifest {declared}"
        )));
    }
    Ok(())
}

fn compare_close_public_inputs(
    descriptor: &PublicCloseIntentDescriptor,
    full: &CloseIntent,
    raw_inputs: &[u64],
) -> Result<(ExpectedClose, Value)> {
    let pis = ChannelClosePublicInputs::from_u64_slice(raw_inputs).map_err(|error| {
        PublicClosePublisherError::Bundle(format!("parse close public inputs: {error}"))
    })?;
    let fail = |field: &str| {
        PublicClosePublisherError::Bundle(format!(
            "close descriptor/full intent/public inputs disagree at {field}"
        ))
    };

    let state_digest = expect_hex(
        &descriptor.final_channel_state_digest,
        32,
        "finalChannelStateDigest",
    )?;
    let balance_h1 = expect_hex(
        &descriptor.final_balance_state_h1,
        32,
        "finalBalanceStateH1",
    )?;
    let fund_root = expect_hex(
        &descriptor.channel_fund_intmax_state_root,
        32,
        "channelFundIntmaxStateRoot",
    )?;
    let burn_tx_hash = expect_hex(&descriptor.burn_tx_hash, 32, "burnTxHash")?;
    let withdrawal_digest = expect_hex(
        &descriptor.close_withdrawal_digest,
        32,
        "closeWithdrawalDigest",
    )?;
    let settled_chain = expect_hex(
        &descriptor.final_settled_tx_chain,
        32,
        "finalSettledTxChain",
    )?;
    let accumulator_root = expect_hex(
        &descriptor.final_settled_tx_accumulator_root,
        32,
        "finalSettledTxAccumulatorRoot",
    )?;
    let intent_digest = expect_hex(&descriptor.close_intent_digest, 32, "closeIntentDigest")?;
    let member_commitment =
        expect_hex(&descriptor.member_set_commitment, 32, "memberSetCommitment")?;

    if descriptor.member_count < 2
        || usize::from(descriptor.member_count) > MAX_SIG_CLUSTER
        || descriptor.member_pk_gs.len() != usize::from(descriptor.member_count)
    {
        return Err(PublicClosePublisherError::Bundle(format!(
            "memberPkGs must contain exactly memberCount active cosigners (2..={MAX_SIG_CLUSTER})"
        )));
    }
    let mut member_pk_gs = [Bytes32::default(); MAX_SIG_CLUSTER];
    for (index, encoded) in descriptor.member_pk_gs.iter().enumerate() {
        let canonical = expect_hex(encoded, 32, &format!("memberPkGs[{index}]"))?;
        let pk_g = canonical.parse::<Bytes32>().map_err(|error| {
            PublicClosePublisherError::Bundle(format!(
                "parse memberPkGs[{index}] as Bytes32: {error}"
            ))
        })?;
        if pk_g == Bytes32::default()
            || member_pk_gs[..index]
                .iter()
                .any(|previous| *previous == pk_g)
        {
            return Err(PublicClosePublisherError::Bundle(format!(
                "memberPkGs[{index}] is zero or duplicates an earlier active cosigner"
            )));
        }
        member_pk_gs[index] = pk_g;
    }
    if close_member_set_commitment(&member_pk_gs, descriptor.member_count).to_string()
        != member_commitment
    {
        return Err(fail("memberPkGs/memberSetCommitment"));
    }

    if descriptor.channel_fund_amounts.len() != 10 || descriptor.token_registry.len() != 10 {
        return Err(PublicClosePublisherError::Bundle(
            "channelFundAmounts/tokenRegistry must each contain exactly ten entries".into(),
        ));
    }
    if descriptor.token_count == 0 || descriptor.token_count > 10 {
        return Err(PublicClosePublisherError::Bundle(
            "tokenCount must be in 1..=10".into(),
        ));
    }
    let amount_strings = descriptor
        .channel_fund_amounts
        .iter()
        .enumerate()
        .map(|(index, value)| {
            normalize_decimal(value, 256, &format!("channelFundAmounts[{index}]"))
        })
        .collect::<Result<Vec<_>>>()?;
    let amount_strings: [String; 10] = amount_strings
        .try_into()
        .map_err(|_| PublicClosePublisherError::Bundle("fund vector width changed".into()))?;
    let legacy_amount =
        normalize_decimal(&descriptor.channel_fund_amount, 256, "channelFundAmount")?;
    if legacy_amount != amount_strings[0] {
        return Err(fail("channelFundAmount/channelFundAmounts[0]"));
    }
    let token_registry: [u32; 10] =
        descriptor.token_registry.clone().try_into().map_err(|_| {
            PublicClosePublisherError::Bundle("token registry width changed".into())
        })?;
    for index in descriptor.token_count as usize..10 {
        if amount_strings[index] != "0" || token_registry[index] != 0 {
            return Err(PublicClosePublisherError::Bundle(format!(
                "inactive token slot {index} is not canonical zero padding"
            )));
        }
    }
    for index in 0..usize::from(descriptor.token_count) {
        if token_registry[..index]
            .iter()
            .any(|previous| *previous == token_registry[index])
        {
            return Err(PublicClosePublisherError::Bundle(format!(
                "active tokenRegistry[{index}] duplicates an earlier base-token index"
            )));
        }
    }
    let amounts_vec = amount_strings
        .iter()
        .map(|value| {
            value.parse::<U256>().map_err(|error| {
                PublicClosePublisherError::Bundle(format!("parse channel fund amount: {error}"))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let amounts: [U256; 10] = amounts_vec
        .try_into()
        .map_err(|_| PublicClosePublisherError::Bundle("fund vector width changed".into()))?;
    let funds_digest = token_funds_digest(&token_registry, descriptor.token_count, &amounts);

    let expected = ExpectedClose {
        close_nonce: descriptor.close_nonce,
        final_epoch: descriptor.final_epoch,
        final_small_block_number: descriptor.final_small_block_number,
        close_freeze_nonce: descriptor.close_freeze_nonce,
        final_channel_state_digest: state_digest.clone(),
        final_balance_state_h1: balance_h1.clone(),
        channel_fund_amounts: amount_strings.clone(),
        token_registry,
        token_count: descriptor.token_count,
        channel_fund_intmax_state_root: fund_root.clone(),
        burn_tx_hash: burn_tx_hash.clone(),
        close_withdrawal_digest: withdrawal_digest.clone(),
        snapshot_medium_block_number: descriptor.snapshot_medium_block_number,
        final_state_version: descriptor.final_state_version,
        final_settled_tx_chain: settled_chain.clone(),
        final_settled_tx_accumulator_root: accumulator_root.clone(),
        close_intent_digest: intent_digest.clone(),
        member_set_commitment: member_commitment.clone(),
        member_count: descriptor.member_count,
        delegate_count: descriptor.delegate_count,
        token_funds_digest: funds_digest.to_string(),
    };

    if descriptor.channel_id != pis.channel_id.channel_id()
        || descriptor.close_nonce != pis.close_nonce
        || descriptor.final_epoch != pis.final_epoch
        || descriptor.final_small_block_number != pis.final_small_block_number
        || descriptor.close_freeze_nonce != pis.close_freeze_nonce
        || state_digest != pis.final_channel_state_digest.to_string()
        || balance_h1 != pis.final_balance_state_h1.to_string()
        || amount_strings[0] != pis.channel_fund_amount.to_string()
        || fund_root != pis.channel_fund_intmax_state_root.to_string()
        || burn_tx_hash != pis.burn_tx_hash.to_string()
        || withdrawal_digest != pis.close_withdrawal_digest.to_string()
        || intent_digest != pis.close_intent_digest.to_string()
        || descriptor.snapshot_medium_block_number != pis.snapshot_medium_block_number
        || descriptor.final_state_version != pis.final_state_version
        || settled_chain != pis.final_settled_tx_chain.to_string()
        || accumulator_root != pis.final_settled_tx_accumulator_root.to_string()
        || member_commitment != pis.member_set_commitment.to_string()
        || descriptor.member_count != pis.member_count
        || descriptor.delegate_count != pis.delegate_count
        || funds_digest != pis.token_funds_digest
    {
        return Err(fail("proof-bound field vector"));
    }
    if descriptor.close_nonce != descriptor.close_freeze_nonce
        || descriptor.snapshot_medium_block_number != 0
        || burn_tx_hash != format!("0x{}", "00".repeat(32))
    {
        return Err(PublicClosePublisherError::Bundle(
            "close metadata is not in its canonical zero/nonce representation".into(),
        ));
    }
    if full.channel_id.channel_id() != descriptor.channel_id
        || full.channel_fund_snapshot.channel_id.channel_id() != descriptor.channel_id
        || full.close_nonce != descriptor.close_nonce
        || full.final_epoch != descriptor.final_epoch
        || full.final_small_block_number != descriptor.final_small_block_number
        || full.close_freeze_nonce != descriptor.close_freeze_nonce
        || full.final_channel_state_digest.to_string() != state_digest
        || full.final_balance_state_h1.to_string() != balance_h1
        || full.channel_fund_snapshot.amounts != amounts
        || full.channel_fund_snapshot.intmax_state_root.to_string() != fund_root
        || full.burn_tx_hash.to_string() != burn_tx_hash
        || full.close_withdrawal_digest.to_string() != withdrawal_digest
        || full.snapshot_medium_block_number != descriptor.snapshot_medium_block_number
        || full.final_state_version != descriptor.final_state_version
        || full.final_settled_tx_chain.to_string() != settled_chain
        || full.signing_digest().to_string() != intent_digest
    {
        return Err(fail("close_intent_full.json"));
    }

    let intent_json = serde_json::json!({
        "closeNonce": expected.close_nonce,
        "finalEpoch": expected.final_epoch,
        "finalSmallBlockNumber": expected.final_small_block_number,
        "closeFreezeNonce": expected.close_freeze_nonce,
        "finalChannelStateDigest": expected.final_channel_state_digest,
        "finalBalanceStateH1": expected.final_balance_state_h1,
        "channelFundAmounts": expected.channel_fund_amounts,
        "tokenRegistry": expected.token_registry,
        "tokenCount": expected.token_count,
        "channelFundIntmaxStateRoot": expected.channel_fund_intmax_state_root,
        "burnTxHash": expected.burn_tx_hash,
        "closeWithdrawalDigest": expected.close_withdrawal_digest,
        "snapshotMediumBlockNumber": expected.snapshot_medium_block_number,
        "finalStateVersion": expected.final_state_version,
        "finalSettledTxChain": expected.final_settled_tx_chain,
        "finalSettledTxAccumulatorRoot": expected.final_settled_tx_accumulator_root,
    });
    Ok((expected, intent_json))
}

fn finalize_calldata(expected: &ExpectedClose, close_request_generation: u64) -> Result<String> {
    if close_request_generation == 0 {
        return Err(PublicClosePublisherError::Evidence(
            "ClosePending/Closed manager reported zero closeRequestGeneration".into(),
        ));
    }
    let digest_kind = AbiKind::FixedBytes(32);
    let generation_kind = AbiKind::Uint(64);
    let digest_value = Value::String(expected.close_intent_digest.clone());
    let generation_value = Value::String(close_request_generation.to_string());
    let calldata = encode_function(
        "finalizeCloseGuarded",
        &[
            (&digest_kind, &digest_value, "expectedCloseIntentDigest"),
            (
                &generation_kind,
                &generation_value,
                "expectedCloseRequestGeneration",
            ),
        ],
    )
    .map_err(|error| {
        PublicClosePublisherError::Bundle(format!("encode finalize calldata: {error}"))
    })?;
    if !calldata.starts_with(&selector(FINALIZE_CLOSE_GUARDED_SIGNATURE)) {
        return Err(PublicClosePublisherError::Bundle(
            "typed guarded-finalize encoder diverged from the compiled release ABI".into(),
        ));
    }
    Ok(calldata)
}

fn signed_head_proof_calldata(
    function: &'static str,
    signature: &str,
    expected_selector: &str,
    manager: &str,
    backing_compact_proof: &[u8],
) -> Result<String> {
    let manager_kind = AbiKind::Address;
    let proof_kind = AbiKind::Bytes;
    let computed_signature = format!(
        "{function}({},{})",
        manager_kind.signature(),
        proof_kind.signature()
    );
    if computed_signature != signature || selector(&computed_signature) != expected_selector {
        return Err(PublicClosePublisherError::Bundle(format!(
            "typed {function} encoder diverged from the compiled release ABI ({computed_signature})"
        )));
    }
    let manager = Value::String(manager.to_string());
    let proof = Value::String(format!("0x{}", hex::encode(backing_compact_proof)));
    encode_function(
        function,
        &[
            (&manager_kind, &manager, "manager"),
            (&proof_kind, &proof, "backingProof"),
        ],
    )
    .map_err(|error| {
        PublicClosePublisherError::Bundle(format!("encode {function} calldata: {error}"))
    })
}

/// `materializeSignedHead(address manager, bytes backingProof)` over the exact compact bytes that
/// were attested; the materializer keys its receipt on `keccak256(proof)`, so any other encoding
/// of the same proof would be refused on chain.
fn materialize_calldata(manager: &str, backing_compact_proof: &[u8]) -> Result<String> {
    signed_head_proof_calldata(
        "materializeSignedHead",
        MATERIALIZE_SIGNED_HEAD_SIGNATURE,
        MATERIALIZE_SIGNED_HEAD_SELECTOR,
        manager,
        backing_compact_proof,
    )
}

/// `attestSignedHeadBacking(address manager, bytes backingProof)` over the canonical compact bytes.
fn attest_calldata(manager: &str, backing_compact_proof: &[u8]) -> Result<String> {
    signed_head_proof_calldata(
        "attestSignedHeadBacking",
        ATTEST_SIGNED_HEAD_BACKING_SIGNATURE,
        ATTEST_SIGNED_HEAD_BACKING_SELECTOR,
        manager,
        backing_compact_proof,
    )
}

/// Reproduce the two domain-separated Solidity `abi.encode` identities exactly. The statement
/// receipt is keyed by the complete signed economic state, while the proof receipt additionally
/// binds `keccak256(backingProof)` — the exact compact bytes that later `materializeSignedHead`
/// must reuse.
fn backing_attestation_identity(
    prepared: &PreparedClose,
    deployment: &DeploymentManifest,
) -> Result<BackingAttestationIdentity> {
    let domain_kind = AbiKind::FixedBytes(4);
    let chain_kind = AbiKind::Uint(256);
    let address_kind = AbiKind::Address;
    let channel_kind = AbiKind::Uint(32);
    let digest_kind = AbiKind::FixedBytes(32);
    let statement_domain = Value::String("0x494d4241".into());
    let proof_domain = Value::String("0x494d4250".into());
    let chain_id = Value::String(prepared.chain_id.to_string());
    let materializer = Value::String(deployment.close_funding_materializer.clone());
    let rollup = Value::String(prepared.rollup.clone());
    let manager = Value::String(deployment.manager.clone());
    let channel_id = Value::String(prepared.channel_id.to_string());
    let settled_chain = Value::String(prepared.expected.final_settled_tx_chain.clone());
    let funds_digest = Value::String(prepared.expected.token_funds_digest.clone());
    let proof_hash = Value::String(keccak_hex(&prepared.backing_mle.compact_proof));
    let statement = encode_sequence([
        (&domain_kind, &statement_domain, "statement.domain".into()),
        (&chain_kind, &chain_id, "statement.chainId".into()),
        (&address_kind, &materializer, "statement.materializer".into()),
        (&address_kind, &rollup, "statement.rollup".into()),
        (&address_kind, &manager, "statement.manager".into()),
        (&channel_kind, &channel_id, "statement.channelId".into()),
        (&digest_kind, &settled_chain, "statement.settledTxChain".into()),
        (&digest_kind, &funds_digest, "statement.tokenFundsDigest".into()),
    ])
    .map_err(|error| {
        PublicClosePublisherError::Bundle(format!("encode backing statement identity: {error}"))
    })?;
    let proof = encode_sequence([
        (&domain_kind, &proof_domain, "proof.domain".into()),
        (&chain_kind, &chain_id, "proof.chainId".into()),
        (&address_kind, &materializer, "proof.materializer".into()),
        (&address_kind, &rollup, "proof.rollup".into()),
        (&address_kind, &manager, "proof.manager".into()),
        (&digest_kind, &proof_hash, "proof.backingProofHash".into()),
    ])
    .map_err(|error| {
        PublicClosePublisherError::Bundle(format!("encode backing proof identity: {error}"))
    })?;
    let anchor_plus_one = prepared
        .backing_public_inputs
        .anchor_block_number
        .as_u64()
        .checked_add(1)
        .ok_or_else(|| {
            PublicClosePublisherError::Bundle("backing anchor plus one overflowed u64".into())
        })?;
    Ok(BackingAttestationIdentity {
        statement_key: keccak_hex(&statement),
        proof_id: keccak_hex(&proof),
        anchor_plus_one,
    })
}

fn prepare_bundle(
    bundle_dir: &Path,
    trusted_final_channel_state_digest: &str,
) -> Result<PreparedClose> {
    let trusted_final_channel_state_digest = normalize_hex(
        trusted_final_channel_state_digest,
        32,
        "trusted expected final channel state digest",
    )
    .map_err(PublicClosePublisherError::Configuration)?;
    let manifest_path = bundle_dir.join("public_close_manifest.json");
    let manifest_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES, "public-close manifest")?;
    let manifest: PublicCloseManifest = parse_json(&manifest_bytes, "public-close manifest")?;
    if manifest.schema_version != PUBLIC_CLOSE_MANIFEST_VERSION
        || manifest.chain_id == 0
        || manifest.channel_id.channel_id() == 0
        || !manifest.self_verified
        || manifest.key_material_consumed
    {
        return Err(PublicClosePublisherError::Bundle(
            "manifest version/context/self-verification/keyless flags are invalid".into(),
        ));
    }
    let rollup = expect_hex(&manifest.rollup, 20, "manifest.rollup")?;
    let balance_vd_sha256 = expect_hex(
        &manifest.balance_verifier_data_sha256,
        32,
        "manifest.balanceVerifierDataSha256",
    )?;
    let proof_path = fixed_bundle_path(bundle_dir, &manifest.close_proof_file, "close_proof.bin")?;
    let mle_path = fixed_bundle_path(
        bundle_dir,
        &manifest.close_mle_file,
        "close_intent_mle.json",
    )?;
    let backing_proof_path = fixed_bundle_path(
        bundle_dir,
        &manifest.backing_proof_file,
        "backing_proof.bin",
    )?;
    let backing_mle_path =
        fixed_bundle_path(bundle_dir, &manifest.backing_mle_file, "backing_mle.json")?;
    let backing_mle_config_path = fixed_bundle_path(
        bundle_dir,
        &manifest.backing_mle_config_file,
        "backing_mle_config.json",
    )?;
    let backing_inputs_path = fixed_bundle_path(
        bundle_dir,
        &manifest.backing_public_inputs_file,
        "backing_public_inputs.json",
    )?;
    let intent_path =
        fixed_bundle_path(bundle_dir, &manifest.close_intent_file, "close_intent.json")?;
    let full_path = fixed_bundle_path(
        bundle_dir,
        &manifest.close_intent_full_file,
        "close_intent_full.json",
    )?;
    let inputs_path = fixed_bundle_path(
        bundle_dir,
        &manifest.close_public_inputs_file,
        "close_public_inputs.json",
    )?;

    let proof = read_bounded(&proof_path, MAX_CLOSE_PROOF_BYTES, "close proof")?;
    let mle_bytes = read_bounded(&mle_path, MAX_MLE_BYTES, "close MLE proof")?;
    let backing_proof = read_bounded(
        &backing_proof_path,
        MAX_BACKING_PROOF_BYTES,
        "signed-head backing proof",
    )?;
    let backing_mle_bytes = read_bounded(
        &backing_mle_path,
        MAX_MLE_BYTES,
        "signed-head backing MLE proof",
    )?;
    let backing_mle_config_bytes = read_bounded(
        &backing_mle_config_path,
        MAX_BACKING_MLE_CONFIG_BYTES,
        "signed-head backing MLE deployment config",
    )?;
    let backing_input_bytes = read_bounded(
        &backing_inputs_path,
        MAX_BACKING_PUBLIC_INPUT_BYTES,
        "signed-head backing public inputs",
    )?;
    let intent_bytes = read_bounded(&intent_path, MAX_INTENT_BYTES, "close descriptor")?;
    let full_bytes = read_bounded(&full_path, MAX_INTENT_BYTES, "full close intent")?;
    let input_bytes = read_bounded(&inputs_path, MAX_PUBLIC_INPUT_BYTES, "close public inputs")?;
    if proof.is_empty()
        || proof.len() != manifest.close_proof_bytes
        || mle_bytes.len() != manifest.close_mle_bytes
        || backing_proof.is_empty()
        || backing_proof.len() != manifest.backing_proof_bytes
        || backing_mle_bytes.len() != manifest.backing_mle_bytes
        || backing_mle_config_bytes.len() != manifest.backing_mle_config_bytes
    {
        return Err(PublicClosePublisherError::Bundle(
            "close/backing proof or MLE size differs from manifest, or a proof is empty".into(),
        ));
    }
    require_component_sha256(&proof, &manifest.close_proof_sha256, "closeProof")?;
    require_component_sha256(&mle_bytes, &manifest.close_mle_sha256, "closeMle")?;
    require_component_sha256(
        &backing_proof,
        &manifest.backing_proof_sha256,
        "backingProof",
    )?;
    require_component_sha256(
        &backing_mle_bytes,
        &manifest.backing_mle_sha256,
        "backingMle",
    )?;
    require_component_sha256(
        &backing_mle_config_bytes,
        &manifest.backing_mle_config_sha256,
        "backingMleConfig",
    )?;
    require_component_sha256(
        &backing_input_bytes,
        &manifest.backing_public_inputs_sha256,
        "backingPublicInputs",
    )?;
    require_component_sha256(&intent_bytes, &manifest.close_intent_sha256, "closeIntent")?;
    require_component_sha256(
        &full_bytes,
        &manifest.close_intent_full_sha256,
        "closeIntentFull",
    )?;
    require_component_sha256(
        &input_bytes,
        &manifest.close_public_inputs_sha256,
        "closePublicInputs",
    )?;

    let backing_inputs_value: Value =
        parse_json(&backing_input_bytes, "signed-head backing public inputs")?;
    let backing_inputs =
        parse_backing_public_input_array(&backing_inputs_value, "backingPublicInputs")?;
    if backing_inputs.len() != CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN
        || backing_inputs.len() != manifest.backing_public_input_count
    {
        return Err(PublicClosePublisherError::Bundle(format!(
            "backing public input count {} != manifest {} / required {}",
            backing_inputs.len(),
            manifest.backing_public_input_count,
            CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN
        )));
    }
    let parsed_backing =
        CloseAssetBackingPublicInputs::from_u64_slice(&backing_inputs).map_err(|error| {
            PublicClosePublisherError::Bundle(format!(
                "parse signed-head backing public inputs: {error}"
            ))
        })?;
    if parsed_backing.finalized_extended_state_commitment
        != manifest.backing_finalized_extended_state_commitment
    {
        return Err(PublicClosePublisherError::Bundle(
            "backing public-input finalizedExtendedStateCommitment differs from manifest".into(),
        ));
    }
    if parsed_backing.anchor_block_number.as_u64() != manifest.backing_anchor_block_number {
        return Err(PublicClosePublisherError::Bundle(
            "backing public-input anchorBlockNumber differs from manifest".into(),
        ));
    }
    // The backing statement travels exactly like the close statement: one strict canonical
    // wire-v3 fixture whose `.compactProof.bytes` is the calldata, cross-checked against the
    // separately shipped proof-free deployment config the materializer's adapter was built from.
    let backing_mle_json = std::str::from_utf8(&backing_mle_bytes).map_err(|error| {
        PublicClosePublisherError::Bundle(format!(
            "signed-head backing MLE fixture is not UTF-8: {error}"
        ))
    })?;
    let backing_mle_config_json =
        std::str::from_utf8(&backing_mle_config_bytes).map_err(|error| {
            PublicClosePublisherError::Bundle(format!(
                "signed-head backing MLE deployment config is not UTF-8: {error}"
            ))
        })?;
    let backing_mle =
        validated_compact_mle_v2_fixture(MleStatement::Backing, backing_mle_json, &backing_inputs)
            .map_err(|error| {
                PublicClosePublisherError::Bundle(format!(
                    "inspect signed-head backing MLE fixture: {error}"
                ))
            })?;
    let backing_config_compact = crate::utils::mle_prover::validate_mle_v2_full_against_config_json(
        backing_mle_json,
        backing_mle_config_json,
    )
    .map_err(|error| {
        PublicClosePublisherError::Bundle(format!(
            "signed-head backing MLE fixture does not match backing_mle_config.json: {error}"
        ))
    })?;
    if backing_config_compact != backing_mle.compact_proof {
        return Err(PublicClosePublisherError::Bundle(
            "signed-head backing compact proof differs between its fixture and config views".into(),
        ));
    }
    let backing_compact_proof_hash = keccak_hex(&backing_mle.compact_proof);
    let backing_compact_proof_length =
        u32::try_from(backing_mle.compact_proof.len()).map_err(|_| {
            PublicClosePublisherError::Bundle(
                "backing compact proof length does not fit uint32".into(),
            )
        })?;
    let descriptor: PublicCloseIntentDescriptor = parse_json(&intent_bytes, "close descriptor")?;
    let full: CloseIntent = parse_json(&full_bytes, "full close intent")?;
    let public_inputs_value: Value = parse_json(&input_bytes, "close public inputs")?;
    let raw_inputs = parse_public_input_array(&public_inputs_value, "closePublicInputs")?;
    if raw_inputs.len() != CHANNEL_CLOSE_PUBLIC_INPUTS_LEN
        || raw_inputs.len() != manifest.close_public_input_count
    {
        return Err(PublicClosePublisherError::Bundle(format!(
            "close public input count {} != manifest {} / required {}",
            raw_inputs.len(),
            manifest.close_public_input_count,
            CHANNEL_CLOSE_PUBLIC_INPUTS_LEN
        )));
    }
    let mle_json = std::str::from_utf8(&mle_bytes).map_err(|error| {
        PublicClosePublisherError::Bundle(format!("close MLE fixture is not UTF-8: {error}"))
    })?;
    let mle_artifact = validated_compact_mle_v2_fixture(MleStatement::Close, mle_json, &raw_inputs)?;
    let (expected, intent_json) = compare_close_public_inputs(&descriptor, &full, &raw_inputs)?;
    if parsed_backing.channel_id.channel_id() != descriptor.channel_id {
        return Err(PublicClosePublisherError::Bundle(
            "backing public-input channelId differs from the signed close state".into(),
        ));
    }
    if !same_hex(
        &parsed_backing.settled_tx_chain.to_string(),
        &expected.final_settled_tx_chain,
    ) {
        return Err(PublicClosePublisherError::Bundle(
            "backing public-input settledTxChain differs from the signed close state".into(),
        ));
    }
    if !same_hex(
        &parsed_backing.token_funds_digest.to_string(),
        &expected.token_funds_digest,
    ) {
        return Err(PublicClosePublisherError::Bundle(
            "backing public-input tokenFundsDigest differs from the signed close state's complete asset vector"
                .into(),
        ));
    }
    if !same_hex(
        &expected.final_channel_state_digest,
        &trusted_final_channel_state_digest,
    ) {
        return Err(PublicClosePublisherError::Bundle(format!(
            "proof-bound finalChannelStateDigest {} differs from independently trusted {}; select the bundle for that authenticated signed head or regenerate it explicitly",
            expected.final_channel_state_digest, trusted_final_channel_state_digest
        )));
    }
    if descriptor.channel_id != manifest.channel_id.channel_id() {
        return Err(PublicClosePublisherError::Bundle(
            "manifest channelId differs from proof-derived descriptor".into(),
        ));
    }

    let intent_kind = AbiKind::Tuple(close_intent_fields());
    let proof_kind = AbiKind::Bytes;
    let computed_signature = format!(
        "submitCloseIntent({},{})",
        intent_kind.signature(),
        proof_kind.signature()
    );
    if selector(&computed_signature) != SUBMIT_CLOSE_SELECTOR {
        return Err(PublicClosePublisherError::Bundle(format!(
            "typed close ABI selector diverged from the release-compiled selector {SUBMIT_CLOSE_SELECTOR}: {computed_signature}"
        )));
    }
    let submit_calldata = encode_function(
        "submitCloseIntent",
        &[
            (&intent_kind, &intent_json, "closeIntent"),
            (
                &proof_kind,
                &Value::String(format!("0x{}", hex::encode(&mle_artifact.compact_proof))),
                "compactProof",
            ),
        ],
    )
    .map_err(|error| {
        PublicClosePublisherError::Bundle(format!("encode close calldata: {error}"))
    })?;
    let compact_proof_hash = keccak_hex(&mle_artifact.compact_proof);
    let compact_proof_length = u32::try_from(mle_artifact.compact_proof.len()).map_err(|_| {
        PublicClosePublisherError::Bundle("compact proof length does not fit uint32".into())
    })?;
    let components = [
        ("public_close_manifest.json", manifest_bytes.as_slice()),
        ("close_proof.bin", proof.as_slice()),
        ("close_intent_mle.json", mle_bytes.as_slice()),
        ("backing_proof.bin", backing_proof.as_slice()),
        ("backing_mle.json", backing_mle_bytes.as_slice()),
        ("backing_mle_config.json", backing_mle_config_bytes.as_slice()),
        ("backing_public_inputs.json", backing_input_bytes.as_slice()),
        ("close_intent.json", intent_bytes.as_slice()),
        ("close_intent_full.json", full_bytes.as_slice()),
        ("close_public_inputs.json", input_bytes.as_slice()),
    ];
    let component_hashes = components
        .iter()
        .map(|(name, bytes)| ((*name).to_string(), sha256_hex(bytes)))
        .collect::<BTreeMap<_, _>>();
    let artifact_description = serde_json::json!({
        "domain": "intmax-public-close-bundle-v3",
        "chainId": manifest.chain_id,
        "rollup": rollup,
        "channelId": manifest.channel_id.channel_id(),
        "closeIntentDigest": expected.close_intent_digest,
        "compactProofHash": compact_proof_hash.clone(),
        "compactProofLength": compact_proof_length,
        "backingCompactProofHash": backing_compact_proof_hash.clone(),
        "backingCompactProofLength": backing_compact_proof_length,
        "backingFinalizedExtendedStateCommitment": parsed_backing.finalized_extended_state_commitment.to_string(),
        "backingAnchorBlockNumber": parsed_backing.anchor_block_number.as_u64(),
        "mleFixtureSchema": MLE_VERIFIER_FIXTURE_SCHEMA_V2,
        "mleProtocolVersion": MLE_PROTOCOL_VERSION_CURRENT,
        "mleProofLayoutHash": generated_hex(&MLE_PROOF_LAYOUT_HASH_V2),
        "mleCompactLayoutHash": generated_hex(&COMPACT_LAYOUT_HASH_V2),
        "componentHashes": component_hashes,
    });
    let artifact_hash = sha256_hex(canonical_json(&artifact_description).as_bytes());
    Ok(PreparedClose {
        chain_id: manifest.chain_id,
        rollup,
        channel_id: manifest.channel_id.channel_id(),
        balance_vd_sha256,
        expected,
        compact_proof_hash,
        compact_proof_length,
        verification_config_digest: mle_artifact.verification_config_digest,
        circuit_config_digest: mle_artifact.circuit_config_digest,
        whir_parameters_digest: mle_artifact.whir_parameters_digest,
        whir_protocol_id: mle_artifact.whir_protocol_id,
        whir_session_id: mle_artifact.whir_session_id,
        submit_calldata,
        backing_mle,
        backing_compact_proof_hash,
        backing_compact_proof_length,
        backing_public_inputs: parsed_backing,
        artifact_hash,
        component_hashes,
    })
}

/// Parse deployment-manifest bytes with the publisher's exact strict schema (every field present,
/// no unknown field, current `schemaVersion`). Used by the manifest EXPORTER so a schema drift
/// between `channel_member export-close-deployment-manifest` and this consumer fails at export
/// time rather than at publication time.
pub fn validate_deployment_manifest_shape(bytes: &[u8]) -> std::result::Result<(), String> {
    let manifest: DeploymentManifest = serde_json::from_slice(bytes)
        .map_err(|error| format!("deployment manifest does not match the publisher schema: {error}"))?;
    if manifest.schema_version != DEPLOYMENT_MANIFEST_VERSION {
        return Err(format!(
            "deployment manifest schemaVersion {} != publisher schema {DEPLOYMENT_MANIFEST_VERSION}",
            manifest.schema_version
        ));
    }
    Ok(())
}

fn load_deployment_manifest(
    path: &Path,
    prepared: &PreparedClose,
    expected_sha256: &str,
) -> Result<(DeploymentManifest, String)> {
    let bytes = read_bounded(path, MAX_MANIFEST_BYTES, "close deployment manifest")?;
    let expected_sha256 = normalize_nonzero_hex(
        expected_sha256,
        32,
        "independently configured deployment manifest SHA-256",
    )
    .map_err(PublicClosePublisherError::Configuration)?;
    let manifest_hash = sha256_hex(&bytes);
    if !same_hex(&manifest_hash, &expected_sha256) {
        return Err(PublicClosePublisherError::Deployment(
            "deployment manifest bytes differ from the independently configured SHA-256 pin".into(),
        ));
    }
    // The exact raw bytes are authenticated before JSON parsing. Canonically equivalent JSON is
    // intentionally a different release artifact.
    let mut manifest: DeploymentManifest = parse_json(&bytes, "close deployment manifest")?;
    let fail = |message: String| PublicClosePublisherError::Configuration(message);
    macro_rules! normalize_pin {
        ($field:ident, $bytes:expr) => {
            manifest.$field = normalize_nonzero_hex(
                &manifest.$field,
                $bytes,
                concat!("deployment.", stringify!($field)),
            )
            .map_err(&fail)?;
        };
    }
    normalize_pin!(rollup, 20);
    normalize_pin!(rollup_runtime_code_hash, 32);
    normalize_pin!(manager, 20);
    normalize_pin!(manager_runtime_code_hash, 32);
    normalize_pin!(close_funding_materializer, 20);
    normalize_pin!(close_funding_materializer_runtime_code_hash, 32);
    normalize_pin!(settlement_verifier, 20);
    normalize_pin!(settlement_verifier_runtime_code_hash, 32);
    normalize_pin!(balance_verifier_data_sha256, 32);

    normalize_pin!(close_mle_verifier, 20);
    normalize_pin!(close_mle_verifier_runtime_code_hash, 32);
    normalize_pin!(close_mle_verifier_core, 20);
    normalize_pin!(close_mle_verifier_core_runtime_code_hash, 32);
    normalize_pin!(close_mle_verification_config_digest, 32);
    normalize_pin!(close_mle_circuit_config_digest, 32);
    normalize_pin!(close_mle_whir_parameters_digest, 32);
    normalize_pin!(close_mle_whir_protocol_id, 64);
    normalize_pin!(close_mle_whir_session_id, 32);

    normalize_pin!(withdrawal_claim_mle_verifier, 20);
    normalize_pin!(withdrawal_claim_mle_verifier_runtime_code_hash, 32);
    normalize_pin!(withdrawal_claim_mle_verifier_core, 20);
    normalize_pin!(withdrawal_claim_mle_verifier_core_runtime_code_hash, 32);
    normalize_pin!(withdrawal_claim_mle_verification_config_digest, 32);
    normalize_pin!(withdrawal_claim_mle_circuit_config_digest, 32);
    normalize_pin!(withdrawal_claim_mle_whir_parameters_digest, 32);
    normalize_pin!(withdrawal_claim_mle_whir_protocol_id, 64);
    normalize_pin!(withdrawal_claim_mle_whir_session_id, 32);

    normalize_pin!(post_close_claim_mle_verifier, 20);
    normalize_pin!(post_close_claim_mle_verifier_runtime_code_hash, 32);
    normalize_pin!(post_close_claim_mle_verifier_core, 20);
    normalize_pin!(post_close_claim_mle_verifier_core_runtime_code_hash, 32);
    normalize_pin!(post_close_claim_mle_verification_config_digest, 32);
    normalize_pin!(post_close_claim_mle_circuit_config_digest, 32);
    normalize_pin!(post_close_claim_mle_whir_parameters_digest, 32);
    normalize_pin!(post_close_claim_mle_whir_protocol_id, 64);
    normalize_pin!(post_close_claim_mle_whir_session_id, 32);

    normalize_pin!(cancel_close_mle_verifier, 20);
    normalize_pin!(cancel_close_mle_verifier_runtime_code_hash, 32);
    normalize_pin!(cancel_close_mle_verifier_core, 20);
    normalize_pin!(cancel_close_mle_verifier_core_runtime_code_hash, 32);
    normalize_pin!(cancel_close_mle_verification_config_digest, 32);
    normalize_pin!(cancel_close_mle_circuit_config_digest, 32);
    normalize_pin!(cancel_close_mle_whir_parameters_digest, 32);
    normalize_pin!(cancel_close_mle_whir_protocol_id, 64);
    normalize_pin!(cancel_close_mle_whir_session_id, 32);

    normalize_pin!(backing_mle_verifier, 20);
    normalize_pin!(backing_mle_verifier_runtime_code_hash, 32);
    normalize_pin!(backing_mle_verifier_core, 20);
    normalize_pin!(backing_mle_verifier_core_runtime_code_hash, 32);
    normalize_pin!(backing_mle_verification_config_digest, 32);
    normalize_pin!(backing_mle_circuit_config_digest, 32);
    normalize_pin!(backing_mle_whir_parameters_digest, 32);
    normalize_pin!(backing_mle_whir_protocol_id, 64);
    normalize_pin!(backing_mle_whir_session_id, 32);

    for (value, path, size) in [
        (
            &mut manifest.attest_signed_head_backing_selector,
            "deployment.attestSignedHeadBackingSelector",
            4,
        ),
        (
            &mut manifest.submit_close_intent_selector,
            "deployment.submitCloseIntentSelector",
            4,
        ),
        (
            &mut manifest.finalize_close_guarded_selector,
            "deployment.finalizeCloseGuardedSelector",
            4,
        ),
        (
            &mut manifest.materialize_signed_head_selector,
            "deployment.materializeSignedHeadSelector",
            4,
        ),
        (
            &mut manifest.close_submitted_topic,
            "deployment.closeSubmittedTopic",
            32,
        ),
        (
            &mut manifest.close_finalized_topic,
            "deployment.closeFinalizedTopic",
            32,
        ),
        (
            &mut manifest.signed_head_backing_attested_topic,
            "deployment.signedHeadBackingAttestedTopic",
            32,
        ),
        (
            &mut manifest.signed_head_exit_materialized_topic,
            "deployment.signedHeadExitMaterializedTopic",
            32,
        ),
    ] {
        *value = normalize_hex(value, size, path).map_err(&fail)?;
    }
    if manifest.schema_version != DEPLOYMENT_MANIFEST_VERSION
        || manifest.chain_id == 0
        || manifest.mle_fixture_schema != MLE_VERIFIER_FIXTURE_SCHEMA_V2
        || manifest.mle_protocol_version != MLE_PROTOCOL_VERSION_CURRENT
        || manifest.mle_proof_abi_signature != MLE_PROOF_ABI_SIGNATURE_V2
        || manifest.mle_proof_layout_hash != generated_hex(&MLE_PROOF_LAYOUT_HASH_V2)
        || manifest.mle_compact_layout_hash != generated_hex(&COMPACT_LAYOUT_HASH_V2)
        || manifest.mle_compact_proof_encoding
            != std::str::from_utf8(&COMPACT_MAGIC_V2).expect("generated compact-v2 magic is ASCII")
    {
        return Err(fail(
            "deployment manifest version/chain/MLE v2 protocol identity is invalid".into(),
        ));
    }
    if manifest.chain_id != prepared.chain_id
        || !same_hex(&manifest.rollup, &prepared.rollup)
        || !same_hex(
            &manifest.balance_verifier_data_sha256,
            &prepared.balance_vd_sha256,
        )
    {
        return Err(fail(
            "deployment manifest differs from bundle chain/rollup/balance-VD pin".into(),
        ));
    }
    let close_pin = manifest_mle_pins(&manifest)[0];
    if !same_hex(
        close_pin.verification_config_digest,
        &prepared.verification_config_digest,
    ) || !same_hex(
        close_pin.circuit_config_digest,
        &prepared.circuit_config_digest,
    ) || !same_hex(
        close_pin.whir_parameters_digest,
        &prepared.whir_parameters_digest,
    ) || !same_hex(close_pin.whir_protocol_id, &prepared.whir_protocol_id)
        || !same_hex(close_pin.whir_session_id, &prepared.whir_session_id)
    {
        return Err(fail(
            "close fixture immutable config/protocol/session pins differ from the close adapter manifest"
                .into(),
        ));
    }
    let backing_pin = manifest_mle_pins(&manifest)[BACKING_MLE_PIN_INDEX];
    if !same_hex(
        backing_pin.verification_config_digest,
        &prepared.backing_mle.verification_config_digest,
    ) || !same_hex(
        backing_pin.circuit_config_digest,
        &prepared.backing_mle.circuit_config_digest,
    ) || !same_hex(
        backing_pin.whir_parameters_digest,
        &prepared.backing_mle.whir_parameters_digest,
    ) || !same_hex(
        backing_pin.whir_protocol_id,
        &prepared.backing_mle.whir_protocol_id,
    ) || !same_hex(
        backing_pin.whir_session_id,
        &prepared.backing_mle.whir_session_id,
    ) {
        return Err(fail(
            "backing fixture immutable config/protocol/session pins differ from the materializer's backing adapter manifest"
                .into(),
        ));
    }
    let mle_pins = manifest_mle_pins(&manifest);
    let mle_addresses = [
        ("close adapter", mle_pins[0].adapter),
        ("close core", mle_pins[0].core),
        ("withdrawal-claim adapter", mle_pins[1].adapter),
        ("withdrawal-claim core", mle_pins[1].core),
        ("post-close-claim adapter", mle_pins[2].adapter),
        ("post-close-claim core", mle_pins[2].core),
        ("cancel-close adapter", mle_pins[3].adapter),
        ("cancel-close core", mle_pins[3].core),
        ("backing adapter", mle_pins[4].adapter),
        ("backing core", mle_pins[4].core),
    ];
    for first in 0..mle_addresses.len() {
        for second in first + 1..mle_addresses.len() {
            if same_hex(mle_addresses[first].1, mle_addresses[second].1) {
                return Err(fail(format!(
                    "{} and {} must be distinct MLE adapters and cores",
                    mle_addresses[first].0, mle_addresses[second].0
                )));
            }
        }
    }
    let expected_submit = SUBMIT_CLOSE_SELECTOR.to_string();
    let expected_finalize = selector(FINALIZE_CLOSE_GUARDED_SIGNATURE);
    let expected_attest = ATTEST_SIGNED_HEAD_BACKING_SELECTOR.to_string();
    let expected_materialize = MATERIALIZE_SIGNED_HEAD_SELECTOR.to_string();
    let expected_submitted_topic = keccak_hex(CLOSE_SUBMITTED_EVENT.as_bytes());
    let expected_finalized_topic = keccak_hex(CLOSE_FINALIZED_EVENT.as_bytes());
    let expected_attested_topic = keccak_hex(SIGNED_HEAD_BACKING_ATTESTED_EVENT.as_bytes());
    let expected_materialized_topic = keccak_hex(SIGNED_HEAD_EXIT_MATERIALIZED_EVENT.as_bytes());
    if !same_hex(
        &manifest.attest_signed_head_backing_selector,
        &expected_attest,
    ) || !same_hex(&manifest.submit_close_intent_selector, &expected_submit)
        || !same_hex(
            &manifest.finalize_close_guarded_selector,
            &expected_finalize,
        )
        || !same_hex(
            &manifest.materialize_signed_head_selector,
            &expected_materialize,
        )
        || !same_hex(&manifest.close_submitted_topic, &expected_submitted_topic)
        || !same_hex(&manifest.close_finalized_topic, &expected_finalized_topic)
        || !same_hex(
            &manifest.signed_head_backing_attested_topic,
            &expected_attested_topic,
        )
        || !same_hex(
            &manifest.signed_head_exit_materialized_topic,
            &expected_materialized_topic,
        )
    {
        return Err(fail(
            "deployment selector/event pins differ from the compiled release ABI".into(),
        ));
    }
    Ok((manifest, manifest_hash))
}

fn validate_deployment_observation(
    manifest: &DeploymentManifest,
    observed: &ObservedDeployment,
    prepared: &PreparedClose,
) -> Result<()> {
    if !same_hex(
        &observed.rollup_runtime_code_hash,
        &manifest.rollup_runtime_code_hash,
    ) || !same_hex(
        &observed.manager_runtime_code_hash,
        &manifest.manager_runtime_code_hash,
    ) || !same_hex(
        &observed.close_funding_materializer_runtime_code_hash,
        &manifest.close_funding_materializer_runtime_code_hash,
    ) || !same_hex(
        &observed.settlement_verifier_runtime_code_hash,
        &manifest.settlement_verifier_runtime_code_hash,
    ) {
        return Err(PublicClosePublisherError::Deployment(
            "runtime bytecode hash differs from release-reviewed deployment".into(),
        ));
    }
    if !same_hex(&observed.manager_registry, &manifest.rollup)
        || !same_hex(&observed.manager_verifier, &manifest.settlement_verifier)
        || !same_hex(
            &observed.manager_close_funding_materializer,
            &manifest.close_funding_materializer,
        )
        || !same_hex(&observed.materializer_rollup, &manifest.rollup)
        || !same_hex(&observed.materializer_manager_of_channel, &manifest.manager)
        || observed.manager_channel_id != prepared.channel_id
    {
        return Err(PublicClosePublisherError::Deployment(
            "manager/materializer/rollup/verifier linkage, channel, or materializer binding is invalid"
                .into(),
        ));
    }
    if observed.materializer_last_posted_block
        > prepared.backing_public_inputs.anchor_block_number.as_u64()
    {
        return Err(PublicClosePublisherError::Conflict(format!(
            "signed-head backing anchor {} is older than the channel's reorg-aware last posted block {}",
            prepared.backing_public_inputs.anchor_block_number.as_u64(),
            observed.materializer_last_posted_block
        )));
    }
    if !observed.backing_root_finalized
        || prepared.backing_public_inputs.anchor_block_number.as_u64()
            > observed.rollup_latest_finalized_block_number
    {
        return Err(PublicClosePublisherError::Evidence(format!(
            "backing root/anchor is not finalized: rootFinalized={}, anchor={}, latestFinalized={}",
            observed.backing_root_finalized,
            prepared.backing_public_inputs.anchor_block_number.as_u64(),
            observed.rollup_latest_finalized_block_number
        )));
    }
    let zero_digest = format!("0x{}", "00".repeat(32));
    if !same_hex(&observed.materialized_channel_exit, &zero_digest)
        && !same_hex(
            &observed.materialized_channel_exit,
            &prepared.expected.close_intent_digest,
        )
    {
        return Err(PublicClosePublisherError::Conflict(
            "channel was materialized for a different finalized close digest".into(),
        ));
    }
    let manifest_pins = manifest_mle_pins(manifest);
    let observed_pins = [
        &observed.close_mle,
        &observed.withdrawal_claim_mle,
        &observed.post_close_claim_mle,
        &observed.cancel_close_mle,
        &observed.backing_mle,
    ];
    for (expected, actual) in manifest_pins.iter().zip(observed_pins) {
        if !same_hex(actual.adapter.as_str(), expected.adapter)
            || !same_hex(
                actual.adapter_runtime_code_hash.as_str(),
                expected.adapter_runtime_code_hash,
            )
            || !same_hex(actual.core.as_str(), expected.core)
            || !same_hex(
                actual.core_runtime_code_hash.as_str(),
                expected.core_runtime_code_hash,
            )
            || !same_hex(
                actual.verification_config_digest.as_str(),
                expected.verification_config_digest,
            )
            || !same_hex(
                actual.circuit_config_digest.as_str(),
                expected.circuit_config_digest,
            )
            || !same_hex(
                actual.whir_parameters_digest.as_str(),
                expected.whir_parameters_digest,
            )
            || !same_hex(actual.whir_protocol_id.as_str(), expected.whir_protocol_id)
            || !same_hex(actual.whir_session_id.as_str(), expected.whir_session_id)
            || actual.adapter_allowed_chain_id != manifest.chain_id
            || actual.core_allowed_chain_id != manifest.chain_id
        {
            return Err(PublicClosePublisherError::Deployment(format!(
                "{} MLE adapter/core/code/config/protocol/session/chain identity differs from release manifest",
                expected.label
            )));
        }
    }
    if manifest.chain_id != ANVIL_CHAIN_ID
        && observed.challenge_period < PUBLIC_CHALLENGE_PERIOD_FLOOR
    {
        return Err(PublicClosePublisherError::Deployment(format!(
            "public-chain challenge period {} is below {PUBLIC_CHALLENGE_PERIOD_FLOOR}",
            observed.challenge_period
        )));
    }
    if observed.active_member_count != prepared.expected.member_count
        || observed.active_delegate_count != prepared.expected.delegate_count
        || !same_hex(
            &observed.registered_member_set_commitment,
            &prepared.expected.member_set_commitment,
        )
    {
        return Err(PublicClosePublisherError::Deployment(
            "registered member/delegate snapshot differs from the proof".into(),
        ));
    }
    Ok(())
}

fn backing_attestation_ready(
    observed: &ObservedDeployment,
    prepared: &PreparedClose,
) -> Result<bool> {
    let expected_anchor_plus_one = prepared
        .backing_public_inputs
        .anchor_block_number
        .as_u64()
        .checked_add(1)
        .ok_or_else(|| {
            PublicClosePublisherError::Evidence("backing anchor plus one overflowed u64".into())
        })?;
    if observed.signed_head_backing_current
        && observed.signed_head_backing_anchor_plus_one == 0
    {
        return Err(PublicClosePublisherError::Evidence(
            "materializer reports current signed-head backing without a statement anchor".into(),
        ));
    }
    if observed.exact_backing_proof_attested
        && observed.signed_head_backing_anchor_plus_one < expected_anchor_plus_one
    {
        return Err(PublicClosePublisherError::Evidence(format!(
            "exact backing proof is attested but statement anchor {} is below its proof-bound anchor {}",
            observed.signed_head_backing_anchor_plus_one, expected_anchor_plus_one
        )));
    }
    Ok(observed.exact_backing_proof_attested
        && observed.signed_head_backing_anchor_plus_one >= expected_anchor_plus_one
        && observed.signed_head_backing_current)
}

fn checkpoint_advances(
    earlier: &L1FinalizedCheckpoint,
    later: &L1FinalizedCheckpoint,
) -> std::result::Result<(), String> {
    earlier.validate()?;
    later.validate()?;
    if earlier.chain_id != later.chain_id || earlier.source != later.source {
        return Err("durable checkpoint changed chain or finality source".into());
    }
    if later.block_number < earlier.block_number {
        return Err("durable checkpoint regressed".into());
    }
    if later.block_number == earlier.block_number
        && (later.block_hash != earlier.block_hash || later.parent_hash != earlier.parent_hash)
    {
        return Err("durable checkpoint was replaced at the same height".into());
    }
    Ok(())
}

fn validate_checkpoint_block(
    checkpoint: &L1FinalizedCheckpoint,
    block: &BlockObservation,
) -> Result<()> {
    checkpoint
        .validate()
        .map_err(PublicClosePublisherError::Evidence)?;
    if block.number != checkpoint.block_number
        || block.hash != checkpoint.block_hash
        || block.parent_hash != checkpoint.parent_hash
    {
        return Err(PublicClosePublisherError::Evidence(format!(
            "durable checkpoint {} changed while being read",
            checkpoint.block_number
        )));
    }
    Ok(())
}

fn read_stable_context<B: ClosePublisherBackend>(
    backend: &mut B,
    manifest: &DeploymentManifest,
    prepared: &PreparedClose,
    allow_unfinalized_devnet: bool,
) -> Result<(
    ManagerObservation,
    ObservedDeployment,
    L1FinalizedCheckpoint,
)> {
    let before = backend.durable_checkpoint(allow_unfinalized_devnet)?;
    if before.chain_id != prepared.chain_id {
        return Err(PublicClosePublisherError::Evidence(
            "durable head belongs to another chain".into(),
        ));
    }
    if manifest.manager_deployment_block > before.block_number {
        return Err(PublicClosePublisherError::Deployment(format!(
            "manager deployment block {} is above durable head {}",
            manifest.manager_deployment_block, before.block_number
        )));
    }
    let block = backend.block_at(before.block_number, before.source)?;
    validate_checkpoint_block(&before, &block)?;
    let deployment = backend.observe_deployment(manifest, prepared, before.block_number)?;
    validate_deployment_observation(manifest, &deployment, prepared)?;
    let mut manager = backend.observe_manager(&manifest.manager, before.block_number)?;
    if manager.block_timestamp != block.timestamp {
        return Err(PublicClosePublisherError::Evidence(
            "manager snapshot timestamp differs from its pinned block".into(),
        ));
    }
    manager.block_timestamp = block.timestamp;
    let same_block = backend.block_at(before.block_number, before.source)?;
    validate_checkpoint_block(&before, &same_block)?;
    let after = backend.durable_checkpoint(allow_unfinalized_devnet)?;
    checkpoint_advances(&before, &after).map_err(PublicClosePublisherError::Evidence)?;
    if after != before {
        return Err(PublicClosePublisherError::Evidence(
            "durable head advanced during the pinned manager read; retry from the new head".into(),
        ));
    }
    Ok((manager, deployment, before))
}

fn pending_matches(actual: &ObservedPendingClose, expected: &ExpectedClose) -> bool {
    actual.active
        && actual.close_nonce == expected.close_nonce
        && actual.final_epoch == expected.final_epoch
        && actual.final_small_block_number == expected.final_small_block_number
        && actual.close_freeze_nonce == expected.close_freeze_nonce
        && same_hex(&actual.close_intent_digest, &expected.close_intent_digest)
        && same_hex(
            &actual.final_channel_state_digest,
            &expected.final_channel_state_digest,
        )
        && same_hex(
            &actual.final_balance_state_h1,
            &expected.final_balance_state_h1,
        )
        && actual.channel_fund_amounts == expected.channel_fund_amounts
        && actual.token_registry == expected.token_registry
        && actual.token_count == expected.token_count
        && same_hex(
            &actual.channel_fund_intmax_state_root,
            &expected.channel_fund_intmax_state_root,
        )
        && same_hex(&actual.burn_tx_hash, &expected.burn_tx_hash)
        && same_hex(
            &actual.close_withdrawal_digest,
            &expected.close_withdrawal_digest,
        )
        && actual.snapshot_medium_block_number == expected.snapshot_medium_block_number
        && actual.final_state_version == expected.final_state_version
        && same_hex(
            &actual.final_settled_tx_chain,
            &expected.final_settled_tx_chain,
        )
        && same_hex(
            &actual.final_settled_tx_accumulator_root,
            &expected.final_settled_tx_accumulator_root,
        )
}

fn finalized_matches(actual: &ObservedFinalizedClose, expected: &ExpectedClose) -> bool {
    let burn_is_newer = actual.authorized_burn_snapshot_active
        && (actual.authorized_burn_epoch > expected.final_epoch
            || (actual.authorized_burn_epoch == expected.final_epoch
                && actual.authorized_burn_state_version > expected.final_state_version));
    let exact_caps = (0..10).all(|index| {
        if index >= usize::from(expected.token_count) {
            return actual.finalized_fund_caps[index] == "0";
        }
        let mut cap = match expected.channel_fund_amounts[index].parse::<BigUint>() {
            Ok(value) => value,
            Err(_) => return false,
        };
        if burn_is_newer {
            let post_burn = match actual.authorized_burn_post_funds[index].parse::<BigUint>() {
                Ok(value) => value,
                Err(_) => return false,
            };
            cap = cap.min(post_burn);
        }
        actual.finalized_fund_caps[index] == cap.to_string()
    });

    exact_caps
        && same_hex(&actual.close_intent_digest, &expected.close_intent_digest)
        && same_hex(
            &actual.final_channel_state_digest,
            &expected.final_channel_state_digest,
        )
        && same_hex(
            &actual.final_balance_state_h1,
            &expected.final_balance_state_h1,
        )
        && same_hex(&actual.burn_tx_hash, &expected.burn_tx_hash)
        && same_hex(
            &actual.close_withdrawal_digest,
            &expected.close_withdrawal_digest,
        )
        && same_hex(
            &actual.channel_fund_intmax_state_root,
            &expected.channel_fund_intmax_state_root,
        )
        && same_hex(
            &actual.final_settled_tx_chain,
            &expected.final_settled_tx_chain,
        )
        && same_hex(
            &actual.final_settled_tx_accumulator_root,
            &expected.final_settled_tx_accumulator_root,
        )
        && actual.final_epoch == expected.final_epoch
        && actual.final_small_block_number == expected.final_small_block_number
        && actual.final_state_version == expected.final_state_version
        && actual.token_registry == expected.token_registry
        && actual.token_count == expected.token_count
}

fn can_replace_pending(actual: &ObservedPendingClose, expected: &ExpectedClose) -> bool {
    (expected.final_epoch, expected.final_state_version)
        > (actual.final_epoch, actual.final_state_version)
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn inspect_private_file(path: &Path, maximum: u64) -> Result<Option<fs::Metadata>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(PublicClosePublisherError::Journal(format!(
                "inspect {}: {error}",
                path.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PublicClosePublisherError::Journal(format!(
            "{} must be a regular non-symlink file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(PublicClosePublisherError::Journal(format!(
            "{} exceeds {maximum} bytes",
            path.display()
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            PublicClosePublisherError::Journal(format!(
                "repair {} permissions to 0600: {error}",
                path.display()
            ))
        })?;
    }
    Ok(Some(metadata))
}

fn ensure_private_directory(path: &Path) -> Result<PathBuf> {
    fs::create_dir_all(path).map_err(|error| {
        PublicClosePublisherError::Journal(format!("create {}: {error}", path.display()))
    })?;
    let canonical = fs::canonicalize(path).map_err(|error| {
        PublicClosePublisherError::Journal(format!("canonicalize {}: {error}", path.display()))
    })?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| {
        PublicClosePublisherError::Journal(format!("inspect {}: {error}", canonical.display()))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(PublicClosePublisherError::Journal(format!(
            "{} must be a real directory",
            canonical.display()
        )));
    }
    #[cfg(unix)]
    {
        fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700)).map_err(|error| {
            PublicClosePublisherError::Journal(format!(
                "set {} permissions to 0700: {error}",
                canonical.display()
            ))
        })?;
    }
    Ok(canonical)
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Resolve the directory once, then perform every subsequent operation through that stable
    // path. This prevents a caller-controlled symlinked parent from being swapped between the
    // permission check, temporary-file fsync, and atomic rename.
    let canonical_parent = ensure_private_directory(parent)?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            PublicClosePublisherError::Journal(format!("{} has no UTF-8 filename", path.display()))
        })?;
    let canonical_target = canonical_parent.join(filename);
    inspect_private_file(&canonical_target, u64::MAX)?;
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary =
        canonical_parent.join(format!(".{filename}.tmp.{}.{counter}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary).map_err(|error| {
        PublicClosePublisherError::Journal(format!(
            "create private temporary {}: {error}",
            temporary.display()
        ))
    })?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &canonical_target)?;
        #[cfg(unix)]
        fs::set_permissions(&canonical_target, fs::Permissions::from_mode(0o600))?;
        fs::File::open(&canonical_parent)?.sync_all()
    })();
    if let Err(error) = result {
        return Err(PublicClosePublisherError::Journal(format!(
            "durably replace {}: {error}; temporary retained at {}",
            path.display(),
            temporary.display()
        )));
    }
    Ok(())
}

fn write_journal(path: &Path, journal: &PublicationJournal) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).map_err(|error| {
        PublicClosePublisherError::Journal(format!("serialize journal: {error}"))
    })?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(PublicClosePublisherError::Journal(format!(
            "journal exceeds {MAX_JOURNAL_BYTES} bytes"
        )));
    }
    atomic_write_private(path, &bytes)
}

fn load_or_create_journal(
    path: &Path,
    binding: PublicationBinding,
    signer: &str,
) -> Result<PublicationJournal> {
    if inspect_private_file(path, MAX_JOURNAL_BYTES)?.is_some() {
        let file = fs::File::open(path).map_err(|error| {
            PublicClosePublisherError::Journal(format!("open {}: {error}", path.display()))
        })?;
        let mut bytes = Vec::new();
        file.take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                PublicClosePublisherError::Journal(format!("read {}: {error}", path.display()))
            })?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(PublicClosePublisherError::Journal(
                "journal is oversized".into(),
            ));
        }
        let journal: PublicationJournal = serde_json::from_slice(&bytes).map_err(|error| {
            PublicClosePublisherError::Journal(format!("parse {}: {error}", path.display()))
        })?;
        if journal.version != JOURNAL_VERSION
            || journal.binding != binding
            || !same_hex(&journal.submitter, signer)
            || journal.attest.as_ref().is_some_and(|step| {
                step.confirmation.is_some() && step.superseded_confirmation.is_some()
            })
            || journal.submit.as_ref().is_some_and(|step| {
                step.confirmation.is_some() && step.superseded_confirmation.is_some()
            })
            || journal.finalize.as_ref().is_some_and(|step| {
                step.confirmation.is_some() && step.superseded_confirmation.is_some()
            })
            || journal.materialize.as_ref().is_some_and(|step| {
                step.confirmation.is_some() && step.superseded_confirmation.is_some()
            })
            || ((journal.submit.is_some()
                || journal.submit_observation.is_some()
                || journal.finalize_authorization.is_some()
                || journal.finalize.is_some()
                || journal.finalize_observation.is_some()
                || journal.materialize.is_some()
                || journal.materialize_observation.is_some()
                || journal.completed.is_some())
                && journal.attest_observation.is_none())
            || (journal.finalize_authorization.is_some() && journal.submit_observation.is_none())
            || ((journal.finalize.is_some()
                || journal.finalize_observation.is_some()
                || journal.materialize.is_some()
                || journal.materialize_observation.is_some()
                || journal.completed.is_some())
                && journal.finalize_authorization.is_none())
            || ((journal.materialize.is_some()
                || journal.materialize_observation.is_some()
                || journal.completed.is_some())
                && journal.finalize_observation.is_none())
            || (journal.completed.is_some() && journal.materialize_observation.is_none())
        {
            return Err(PublicClosePublisherError::Conflict(
                "journal belongs to a sibling chain/deployment/artifact/signer".into(),
            ));
        }
        if let Some(submitted) = journal.submit_observation.as_ref() {
            require_after_attestation(&journal, submitted, "journaled CloseSubmitted")?;
        }
        if let Some(finalized) = journal.finalize_observation.as_ref() {
            require_after_attestation(&journal, finalized, "journaled CloseFinalized")?;
        }
        if let Some(completed) = journal.completed.as_ref() {
            if completed.schema_version != PUBLICATION_VERSION
                || !same_hex(
                    &completed.attest_transaction_hash,
                    &attested_lower_bound(&journal)?.transaction_hash,
                )
            {
                return Err(PublicClosePublisherError::Conflict(
                    "journaled completed publication does not match its attestation provenance"
                        .into(),
                ));
            }
        }
        return Ok(journal);
    }
    let journal = PublicationJournal {
        version: JOURNAL_VERSION,
        binding,
        submitter: signer.to_ascii_lowercase(),
        attest: None,
        attest_observation: None,
        submit: None,
        submit_observation: None,
        finalize_authorization: None,
        finalize: None,
        finalize_observation: None,
        materialize: None,
        materialize_observation: None,
        completed: None,
    };
    write_journal(path, &journal)?;
    Ok(journal)
}

#[cfg(unix)]
struct FileLock {
    _file: fs::File,
}

#[cfg(unix)]
impl FileLock {
    fn acquire(path: &Path) -> Result<Self> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let canonical_parent = ensure_private_directory(parent)?;
        let filename = path.file_name().ok_or_else(|| {
            PublicClosePublisherError::Journal(format!("{} has no lock filename", path.display()))
        })?;
        let canonical_path = canonical_parent.join(filename);
        inspect_private_file(&canonical_path, 4096)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&canonical_path)
            .map_err(|error| {
                PublicClosePublisherError::Journal(format!(
                    "open lock {}: {error}",
                    canonical_path.display()
                ))
            })?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(PublicClosePublisherError::Conflict(format!(
                "another publisher holds {}",
                canonical_path.display()
            )));
        }
        Ok(Self { _file: file })
    }
}

#[cfg(unix)]
fn journal_lock_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            PublicClosePublisherError::Configuration("journal path needs a UTF-8 filename".into())
        })?;
    Ok(path.with_file_name(format!("{name}.lock")))
}

#[cfg(unix)]
fn global_signer_lock_path(root: &Path, chain_id: u64, signer: &str) -> Result<PathBuf> {
    let root = ensure_private_directory(root)?;
    let signer =
        normalize_hex(signer, 20, "signer").map_err(PublicClosePublisherError::Configuration)?;
    Ok(root.join(format!(
        ".intmax-l1-signer-{chain_id}-{}.lock",
        signer.trim_start_matches("0x")
    )))
}

fn receipt_status(receipt: &Value) -> Result<bool> {
    let status =
        receipt_quantity(receipt, "status").map_err(PublicClosePublisherError::Evidence)?;
    match status {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(PublicClosePublisherError::Evidence(
            "receipt status is neither canonical zero nor one".into(),
        )),
    }
}

fn receipt_string<'a>(receipt: &'a Value, field: &str) -> std::result::Result<&'a str, String> {
    receipt
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("receipt has no string {field}"))
}

fn quantity_big(value: &str, what: &str) -> std::result::Result<BigUint, String> {
    let value = value.trim();
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |body| (body, 16));
    if digits.is_empty()
        || (radix == 10 && !digits.bytes().all(|byte| byte.is_ascii_digit()))
        || (radix == 16 && !digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(format!("{what} is not an unsigned quantity"));
    }
    BigUint::parse_bytes(digits.as_bytes(), radix).ok_or_else(|| format!("{what} is invalid"))
}

fn quantity_u64(value: &str, what: &str) -> std::result::Result<u64, String> {
    u64::try_from(quantity_big(value, what)?).map_err(|_| format!("{what} does not fit u64"))
}

fn receipt_quantity(receipt: &Value, field: &str) -> std::result::Result<u64, String> {
    match receipt.get(field) {
        Some(Value::String(value)) => quantity_u64(value, &format!("receipt {field}")),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("receipt {field} is not unsigned")),
        _ => Err(format!("receipt has no numeric {field}")),
    }
}

fn stable_receipt_fields(left: &Value, right: &Value) -> bool {
    [
        "transactionHash",
        "blockHash",
        "blockNumber",
        "transactionIndex",
        "status",
        "from",
        "to",
        "logs",
    ]
    .iter()
    .all(|field| left.get(field) == right.get(field))
}

fn validate_receipt_identity(
    receipt: &Value,
    transaction_hash: &str,
    signer: Option<&str>,
    target: Option<&str>,
    require_success: bool,
) -> Result<(String, Bytes32, u64, u64)> {
    if require_success && !receipt_status(receipt)? {
        return Err(PublicClosePublisherError::Evidence(format!(
            "transaction {transaction_hash} reverted"
        )));
    }
    let actual_hash =
        receipt_string(receipt, "transactionHash").map_err(PublicClosePublisherError::Evidence)?;
    if !same_hex(actual_hash, transaction_hash) {
        return Err(PublicClosePublisherError::Evidence(
            "receipt transactionHash differs from the requested transaction".into(),
        ));
    }
    for (field, expected) in [("from", signer), ("to", target)] {
        let Some(expected) = expected else {
            continue;
        };
        let actual = receipt_string(receipt, field).map_err(PublicClosePublisherError::Evidence)?;
        if !same_hex(actual, expected) {
            return Err(PublicClosePublisherError::Evidence(format!(
                "receipt {field} differs from the signed transaction"
            )));
        }
    }
    let block_hash_text = normalize_hex(
        receipt_string(receipt, "blockHash").map_err(PublicClosePublisherError::Evidence)?,
        32,
        "receipt.blockHash",
    )
    .map_err(PublicClosePublisherError::Evidence)?;
    let block_hash = block_hash_text.parse::<Bytes32>().map_err(|error| {
        PublicClosePublisherError::Evidence(format!("parse receipt block hash: {error}"))
    })?;
    let block_number =
        receipt_quantity(receipt, "blockNumber").map_err(PublicClosePublisherError::Evidence)?;
    let transaction_index = receipt_quantity(receipt, "transactionIndex")
        .map_err(PublicClosePublisherError::Evidence)?;
    Ok((block_hash_text, block_hash, block_number, transaction_index))
}

enum ReceiptState {
    Missing,
    Mined {
        block_number: u64,
    },
    Finalized {
        receipt: Value,
        confirmation: FinalizedReceipt,
    },
}

fn inspect_receipt_by_hash<B: ClosePublisherBackend>(
    backend: &mut B,
    transaction_hash: &str,
    signer: Option<&str>,
    target: Option<&str>,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
    require_success: bool,
) -> Result<ReceiptState> {
    let Some(receipt) = backend.receipt(transaction_hash)? else {
        return Ok(ReceiptState::Missing);
    };
    let (block_hash_text, block_hash, block_number, transaction_index) =
        validate_receipt_identity(&receipt, transaction_hash, signer, target, require_success)?;
    let durable_before = backend.durable_checkpoint(allow_unfinalized_devnet)?;
    if durable_before.chain_id != chain_id {
        return Err(PublicClosePublisherError::Evidence(
            "receipt finality head belongs to another chain".into(),
        ));
    }
    if block_number > durable_before.block_number {
        return Ok(ReceiptState::Mined { block_number });
    }
    let receipt_block = backend.block_at(block_number, durable_before.source)?;
    if receipt_block.number != block_number || receipt_block.hash != block_hash {
        return Err(PublicClosePublisherError::Evidence(format!(
            "transaction {} receipt is orphaned",
            transaction_hash
        )));
    }
    durable_before
        .covers_receipt(block_number, block_hash)
        .map_err(PublicClosePublisherError::Evidence)?;
    let second = backend.receipt(transaction_hash)?.ok_or_else(|| {
        PublicClosePublisherError::Evidence("receipt disappeared during final read-back".into())
    })?;
    if !stable_receipt_fields(&receipt, &second) {
        return Err(PublicClosePublisherError::Evidence(
            "receipt changed during final read-back".into(),
        ));
    }
    let durable_block = backend.block_at(durable_before.block_number, durable_before.source)?;
    validate_checkpoint_block(&durable_before, &durable_block)?;
    let durable_after = backend.durable_checkpoint(allow_unfinalized_devnet)?;
    checkpoint_advances(&durable_before, &durable_after)
        .map_err(PublicClosePublisherError::Evidence)?;
    durable_after
        .covers_receipt(block_number, block_hash)
        .map_err(PublicClosePublisherError::Evidence)?;
    Ok(ReceiptState::Finalized {
        receipt,
        confirmation: FinalizedReceipt {
            transaction_hash: transaction_hash.to_ascii_lowercase(),
            block_hash: block_hash_text,
            block_number,
            transaction_index,
            finalized_checkpoint: durable_after,
        },
    })
}

fn inspect_receipt<B: ClosePublisherBackend>(
    backend: &mut B,
    transaction: &SignedTransaction,
    signer: &str,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
) -> Result<ReceiptState> {
    inspect_receipt_by_hash(
        backend,
        &transaction.transaction_hash,
        Some(signer),
        Some(&transaction.target),
        chain_id,
        allow_unfinalized_devnet,
        true,
    )
}

fn validate_stored_confirmation(
    stored: &FinalizedReceipt,
    current: &FinalizedReceipt,
) -> Result<()> {
    stored
        .finalized_checkpoint
        .validate()
        .map_err(PublicClosePublisherError::Evidence)?;
    checkpoint_advances(&stored.finalized_checkpoint, &current.finalized_checkpoint)
        .map_err(PublicClosePublisherError::Evidence)?;
    if !same_hex(&stored.transaction_hash, &current.transaction_hash)
        || !same_hex(&stored.block_hash, &current.block_hash)
        || stored.block_number != current.block_number
        || stored.transaction_index != current.transaction_index
    {
        return Err(PublicClosePublisherError::Evidence(
            "stored transaction confirmation was replaced or orphaned".into(),
        ));
    }
    Ok(())
}

fn receipt_logs(receipt: &Value) -> std::result::Result<&Vec<Value>, String> {
    receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| "receipt has no logs array".into())
}

fn log_topics(log: &Value) -> std::result::Result<&Vec<Value>, String> {
    log.get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| "event log has no topics array".into())
}

fn log_topic(log: &Value, index: usize) -> std::result::Result<&str, String> {
    log_topics(log)?
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("event log has no string topic {index}"))
}

fn decode_log_data(log: &Value, words: usize, what: &str) -> Result<Vec<u8>> {
    let value = log
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| PublicClosePublisherError::Evidence(format!("{what} has no data")))?;
    decode_hex(value, Some(words * 32), what).map_err(PublicClosePublisherError::Evidence)
}

fn word_u64(bytes: &[u8], what: &str) -> Result<u64> {
    if bytes.len() != 32 || bytes[..24] != [0u8; 24] {
        return Err(PublicClosePublisherError::Evidence(format!(
            "{what} is not a canonical uint64 word"
        )));
    }
    Ok(u64::from_be_bytes(
        bytes[24..].try_into().expect("eight bytes"),
    ))
}

fn topic_u64(value: &str, what: &str) -> Result<u64> {
    let bytes = decode_hex(value, Some(32), what).map_err(PublicClosePublisherError::Evidence)?;
    word_u64(&bytes, what)
}

fn relevant_events<'a>(receipt: &'a Value, manager: &str, topic0: &str) -> Result<Vec<&'a Value>> {
    Ok(receipt_logs(receipt)
        .map_err(PublicClosePublisherError::Evidence)?
        .iter()
        .filter(|log| {
            !log.get("removed").and_then(Value::as_bool).unwrap_or(false)
                && log
                    .get("address")
                    .and_then(Value::as_str)
                    .is_some_and(|address| same_hex(address, manager))
                && log_topic(log, 0).is_ok_and(|topic| same_hex(topic, topic0))
        })
        .collect())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SubmittedEventIdentity {
    close_intent_digest: String,
    burn_tx_hash: String,
    close_nonce: u64,
    final_epoch: u64,
    close_freeze_nonce: u64,
    channel_fund_amount: String,
    challenge_deadline: u64,
    final_state_version: u64,
    final_settled_tx_chain: String,
}

fn decode_close_submitted_log(log: &Value) -> Result<SubmittedEventIdentity> {
    if log_topics(log)
        .map_err(PublicClosePublisherError::Evidence)?
        .len()
        != 4
    {
        return Err(PublicClosePublisherError::Evidence(
            "CloseSubmitted has a non-canonical indexed-field count".into(),
        ));
    }
    let data = decode_log_data(log, 6, "CloseSubmitted.data")?;
    Ok(SubmittedEventIdentity {
        close_intent_digest: normalize_hex(
            log_topic(log, 1).map_err(PublicClosePublisherError::Evidence)?,
            32,
            "CloseSubmitted.closeIntentDigest",
        )
        .map_err(PublicClosePublisherError::Evidence)?,
        burn_tx_hash: normalize_hex(
            log_topic(log, 2).map_err(PublicClosePublisherError::Evidence)?,
            32,
            "CloseSubmitted.burnTxHash",
        )
        .map_err(PublicClosePublisherError::Evidence)?,
        close_nonce: topic_u64(
            log_topic(log, 3).map_err(PublicClosePublisherError::Evidence)?,
            "CloseSubmitted.closeNonce",
        )?,
        final_epoch: word_u64(&data[0..32], "CloseSubmitted.finalEpoch")?,
        close_freeze_nonce: word_u64(&data[32..64], "CloseSubmitted.closeFreezeNonce")?,
        channel_fund_amount: BigUint::from_bytes_be(&data[64..96]).to_string(),
        challenge_deadline: word_u64(&data[96..128], "CloseSubmitted.challengeDeadline")?,
        final_state_version: word_u64(&data[128..160], "CloseSubmitted.finalStateVersion")?,
        final_settled_tx_chain: format!("0x{}", hex::encode(&data[160..192])),
    })
}

fn decode_close_submitted_events(
    receipt: &Value,
    manager: &str,
) -> Result<Vec<SubmittedEventIdentity>> {
    let topic0 = keccak_hex(CLOSE_SUBMITTED_EVENT.as_bytes());
    relevant_events(receipt, manager, &topic0)?
        .into_iter()
        .map(decode_close_submitted_log)
        .collect()
}

fn submitted_event_matches_pending(
    event: &SubmittedEventIdentity,
    pending: &ObservedPendingClose,
) -> bool {
    same_hex(&event.close_intent_digest, &pending.close_intent_digest)
        && same_hex(&event.burn_tx_hash, &pending.burn_tx_hash)
        && event.close_nonce == pending.close_nonce
        && event.final_epoch == pending.final_epoch
        && event.close_freeze_nonce == pending.close_freeze_nonce
        && event.channel_fund_amount == pending.channel_fund_amounts[0]
        && event.challenge_deadline == pending.challenge_deadline
        && event.final_state_version == pending.final_state_version
        && same_hex(
            &event.final_settled_tx_chain,
            &pending.final_settled_tx_chain,
        )
}

fn submitted_event_matches_expected(
    event: &SubmittedEventIdentity,
    expected: &ExpectedClose,
) -> bool {
    same_hex(&event.close_intent_digest, &expected.close_intent_digest)
        && same_hex(&event.burn_tx_hash, &expected.burn_tx_hash)
        && event.close_nonce == expected.close_nonce
        && event.final_epoch == expected.final_epoch
        && event.close_freeze_nonce == expected.close_freeze_nonce
        && event.channel_fund_amount == expected.channel_fund_amounts[0]
        && event.final_state_version == expected.final_state_version
        && same_hex(
            &event.final_settled_tx_chain,
            &expected.final_settled_tx_chain,
        )
}

fn unique_exact_event<T>(mut matching: Vec<T>, name: &str) -> Result<Option<T>> {
    if matching.len() > 1 {
        return Err(PublicClosePublisherError::Evidence(format!(
            "receipt has {} fully matching {name} events from the pinned manager; exact provenance is ambiguous",
            matching.len()
        )));
    }
    Ok(matching.pop())
}

fn exact_close_submitted_event<F>(
    receipt: &Value,
    manager: &str,
    predicate: F,
) -> Result<Option<SubmittedEventIdentity>>
where
    F: Fn(&SubmittedEventIdentity) -> bool,
{
    let matching = decode_close_submitted_events(receipt, manager)?
        .into_iter()
        .filter(|event| predicate(event))
        .collect();
    unique_exact_event(matching, "CloseSubmitted")
}

fn validate_close_submitted_event(
    receipt: &Value,
    manager: &str,
    pending: &ObservedPendingClose,
) -> Result<()> {
    exact_close_submitted_event(receipt, manager, |event| {
        submitted_event_matches_pending(event, pending)
    })?
    .ok_or_else(|| {
        PublicClosePublisherError::Evidence(
            "receipt has no CloseSubmitted event matching the complete proof-bound pending state"
                .into(),
        )
    })?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FinalizedEventIdentity {
    close_intent_digest: String,
    burn_tx_hash: String,
    final_epoch: u64,
    channel_fund_amount: String,
    final_state_version: u64,
    final_settled_tx_chain: String,
}

fn decode_close_finalized_log(log: &Value) -> Result<FinalizedEventIdentity> {
    if log_topics(log)
        .map_err(PublicClosePublisherError::Evidence)?
        .len()
        != 4
    {
        return Err(PublicClosePublisherError::Evidence(
            "CloseFinalized has a non-canonical indexed-field count".into(),
        ));
    }
    let data = decode_log_data(log, 3, "CloseFinalized.data")?;
    Ok(FinalizedEventIdentity {
        close_intent_digest: normalize_hex(
            log_topic(log, 1).map_err(PublicClosePublisherError::Evidence)?,
            32,
            "CloseFinalized.closeIntentDigest",
        )
        .map_err(PublicClosePublisherError::Evidence)?,
        burn_tx_hash: normalize_hex(
            log_topic(log, 2).map_err(PublicClosePublisherError::Evidence)?,
            32,
            "CloseFinalized.burnTxHash",
        )
        .map_err(PublicClosePublisherError::Evidence)?,
        final_epoch: topic_u64(
            log_topic(log, 3).map_err(PublicClosePublisherError::Evidence)?,
            "CloseFinalized.finalEpoch",
        )?,
        channel_fund_amount: BigUint::from_bytes_be(&data[0..32]).to_string(),
        final_state_version: word_u64(&data[32..64], "CloseFinalized.finalStateVersion")?,
        final_settled_tx_chain: format!("0x{}", hex::encode(&data[64..96])),
    })
}

fn finalized_event_matches_expected(
    event: &FinalizedEventIdentity,
    expected: &ExpectedClose,
) -> bool {
    same_hex(&event.close_intent_digest, &expected.close_intent_digest)
        && same_hex(&event.burn_tx_hash, &expected.burn_tx_hash)
        && event.final_epoch == expected.final_epoch
        && event.channel_fund_amount == expected.channel_fund_amounts[0]
        && event.final_state_version == expected.final_state_version
        && same_hex(
            &event.final_settled_tx_chain,
            &expected.final_settled_tx_chain,
        )
}

fn exact_close_finalized_event(
    receipt: &Value,
    manager: &str,
    expected: &ExpectedClose,
) -> Result<Option<FinalizedEventIdentity>> {
    let topic0 = keccak_hex(CLOSE_FINALIZED_EVENT.as_bytes());
    let matching = relevant_events(receipt, manager, &topic0)?
        .into_iter()
        .map(decode_close_finalized_log)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|event| finalized_event_matches_expected(event, expected))
        .collect();
    unique_exact_event(matching, "CloseFinalized")
}

fn validate_close_finalized_event(
    receipt: &Value,
    manager: &str,
    expected: &ExpectedClose,
) -> Result<()> {
    exact_close_finalized_event(receipt, manager, expected)?.ok_or_else(|| {
        PublicClosePublisherError::Evidence(
            "receipt has no CloseFinalized event matching the complete proof-bound close".into(),
        )
    })?;
    Ok(())
}

fn indexed_u32(value: u32) -> String {
    let mut word = [0u8; 32];
    word[28..].copy_from_slice(&value.to_be_bytes());
    format!("0x{}", hex::encode(word))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttestedEventIdentity {
    channel_id: u32,
    manager: String,
    statement_key: String,
    backing_root: String,
    anchor_block_number: u64,
    proof_id: String,
}

fn decode_attested_log(log: &Value) -> Result<AttestedEventIdentity> {
    if log_topics(log)
        .map_err(PublicClosePublisherError::Evidence)?
        .len()
        != 4
    {
        return Err(PublicClosePublisherError::Evidence(
            "SignedHeadBackingAttested has a non-canonical indexed-field count".into(),
        ));
    }
    let channel = topic_u64(
        log_topic(log, 1).map_err(PublicClosePublisherError::Evidence)?,
        "SignedHeadBackingAttested.channelId",
    )?;
    let channel_id = u32::try_from(channel).map_err(|_| {
        PublicClosePublisherError::Evidence(
            "SignedHeadBackingAttested.channelId is not a canonical uint32".into(),
        )
    })?;
    let manager_word = decode_hex(
        log_topic(log, 2).map_err(PublicClosePublisherError::Evidence)?,
        Some(32),
        "SignedHeadBackingAttested.manager",
    )
    .map_err(PublicClosePublisherError::Evidence)?;
    let manager = word_address(
        &manager_word.try_into().expect("topic length checked"),
        "SignedHeadBackingAttested.manager",
    )?;
    let statement_key = normalize_hex(
        log_topic(log, 3).map_err(PublicClosePublisherError::Evidence)?,
        32,
        "SignedHeadBackingAttested.statementKey",
    )
    .map_err(PublicClosePublisherError::Evidence)?;
    let data = decode_log_data(log, 3, "SignedHeadBackingAttested.data")?;
    Ok(AttestedEventIdentity {
        channel_id,
        manager,
        statement_key,
        backing_root: format!("0x{}", hex::encode(&data[0..32])),
        anchor_block_number: word_u64(
            &data[32..64],
            "SignedHeadBackingAttested.anchorBlockNumber",
        )?,
        proof_id: format!("0x{}", hex::encode(&data[64..96])),
    })
}

fn exact_attested_event(
    receipt: &Value,
    deployment: &DeploymentManifest,
    prepared: &PreparedClose,
) -> Result<Option<AttestedEventIdentity>> {
    let expected = backing_attestation_identity(prepared, deployment)?;
    let topic0 = keccak_hex(SIGNED_HEAD_BACKING_ATTESTED_EVENT.as_bytes());
    let matching = relevant_events(receipt, &deployment.close_funding_materializer, &topic0)?
        .into_iter()
        .map(decode_attested_log)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|event| {
            event.channel_id == prepared.channel_id
                && same_hex(&event.manager, &deployment.manager)
                && same_hex(&event.statement_key, &expected.statement_key)
                && same_hex(
                    &event.backing_root,
                    &prepared
                        .backing_public_inputs
                        .finalized_extended_state_commitment
                        .to_string(),
                )
                && event.anchor_block_number
                    == prepared.backing_public_inputs.anchor_block_number.as_u64()
                && same_hex(&event.proof_id, &expected.proof_id)
        })
        .collect();
    unique_exact_event(matching, "SignedHeadBackingAttested")
}

fn validate_attested_event(
    receipt: &Value,
    deployment: &DeploymentManifest,
    prepared: &PreparedClose,
) -> Result<()> {
    exact_attested_event(receipt, deployment, prepared)?.ok_or_else(|| {
        PublicClosePublisherError::Evidence(
            "receipt has no SignedHeadBackingAttested event for the exact backing proof".into(),
        )
    })?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MaterializedEventIdentity {
    channel_id: u32,
    manager: String,
    close_intent_digest: String,
    token_count: u8,
}

fn decode_materialized_log(log: &Value) -> Result<MaterializedEventIdentity> {
    if log_topics(log)
        .map_err(PublicClosePublisherError::Evidence)?
        .len()
        != 4
    {
        return Err(PublicClosePublisherError::Evidence(
            "SignedHeadExitMaterialized has a non-canonical indexed-field count".into(),
        ));
    }
    let channel = topic_u64(
        log_topic(log, 1).map_err(PublicClosePublisherError::Evidence)?,
        "SignedHeadExitMaterialized.channelId",
    )?;
    let channel_id = u32::try_from(channel).map_err(|_| {
        PublicClosePublisherError::Evidence(
            "SignedHeadExitMaterialized.channelId is not a canonical uint32".into(),
        )
    })?;
    let manager_word = decode_hex(
        log_topic(log, 2).map_err(PublicClosePublisherError::Evidence)?,
        Some(32),
        "SignedHeadExitMaterialized.manager",
    )
    .map_err(PublicClosePublisherError::Evidence)?;
    let manager = word_address(
        &manager_word.try_into().expect("topic length checked"),
        "SignedHeadExitMaterialized.manager",
    )?;
    let close_intent_digest = normalize_hex(
        log_topic(log, 3).map_err(PublicClosePublisherError::Evidence)?,
        32,
        "SignedHeadExitMaterialized.closeIntentDigest",
    )
    .map_err(PublicClosePublisherError::Evidence)?;
    let data = decode_log_data(log, 1, "SignedHeadExitMaterialized.data")?;
    let token_count = u8::try_from(word_u64(&data, "SignedHeadExitMaterialized.tokenCount")?)
        .map_err(|_| {
            PublicClosePublisherError::Evidence(
                "SignedHeadExitMaterialized.tokenCount is not a canonical uint8".into(),
            )
        })?;
    Ok(MaterializedEventIdentity {
        channel_id,
        manager,
        close_intent_digest,
        token_count,
    })
}

fn exact_materialized_event(
    receipt: &Value,
    deployment: &DeploymentManifest,
    prepared: &PreparedClose,
) -> Result<Option<MaterializedEventIdentity>> {
    let topic0 = keccak_hex(SIGNED_HEAD_EXIT_MATERIALIZED_EVENT.as_bytes());
    let matching = relevant_events(receipt, &deployment.close_funding_materializer, &topic0)?
        .into_iter()
        .map(decode_materialized_log)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|event| {
            event.channel_id == prepared.channel_id
                && same_hex(&event.manager, &deployment.manager)
                && same_hex(
                    &event.close_intent_digest,
                    &prepared.expected.close_intent_digest,
                )
                && event.token_count == prepared.expected.token_count
        })
        .collect();
    unique_exact_event(matching, "SignedHeadExitMaterialized")
}

fn validate_materialized_event(
    receipt: &Value,
    deployment: &DeploymentManifest,
    prepared: &PreparedClose,
) -> Result<()> {
    exact_materialized_event(receipt, deployment, prepared)?.ok_or_else(|| {
        PublicClosePublisherError::Evidence(
            "receipt has no SignedHeadExitMaterialized event matching the complete exact close"
                .into(),
        )
    })?;
    Ok(())
}

fn validate_transaction_step<B: ClosePublisherBackend>(
    backend: &mut B,
    step: &TransactionStep,
    chain_id: u64,
    signer: &str,
    target: &str,
    calldata: &str,
) -> Result<()> {
    let decoded = backend.inspect_signed_transaction(
        &step.transaction.raw_signed_transaction,
        chain_id,
        signer,
        target,
        calldata,
    )?;
    if decoded != step.transaction {
        return Err(PublicClosePublisherError::Conflict(
            "persisted signed transaction metadata or raw bytes were modified".into(),
        ));
    }
    Ok(())
}

fn publish_exact_raw<B: ClosePublisherBackend>(
    backend: &mut B,
    signer: &str,
    transaction: &SignedTransaction,
) -> Result<bool> {
    if backend.transaction_known(&transaction.transaction_hash)?
        || backend.receipt(&transaction.transaction_hash)?.is_some()
    {
        return Ok(false);
    }
    let nonce = backend.account_nonce(signer)?;
    if nonce > transaction.nonce {
        return Err(PublicClosePublisherError::Conflict(format!(
            "signer nonce {} was consumed while exact transaction {} is unknown; sibling replacement refused",
            transaction.nonce, transaction.transaction_hash
        )));
    }
    if nonce < transaction.nonce {
        return Err(PublicClosePublisherError::Conflict(format!(
            "signed nonce {} is ahead of signer latest nonce {nonce}; earlier operation missing",
            transaction.nonce
        )));
    }
    let published = backend.publish_raw(&transaction.raw_signed_transaction)?;
    if !same_hex(&published, &transaction.transaction_hash) {
        return Err(PublicClosePublisherError::Evidence(format!(
            "RPC reported transaction {published}; expected {}",
            transaction.transaction_hash
        )));
    }
    Ok(true)
}

enum SupersededReceiptState {
    AwaitingReceipt,
    AwaitingFinality(u64),
    Finalized(FinalizedReceipt),
}

/// A signed one-shot call may lose to a permissionless sibling after its raw bytes were fsynced.
/// The semantic winner does not consume this signer's nonce. Keep the durable signer reservation,
/// broadcast only the already-journaled loser, and require its canonical-finalized receipt before
/// permitting any later signature. One attestation race may be a successful idempotent no-op;
/// one-shot submit/finalize/materialize races must revert. This closes both the crash/restart and
/// dropped-mempool races.
fn settle_superseded_transaction<B: ClosePublisherBackend>(
    backend: &mut B,
    step: &TransactionStep,
    signer: &str,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
    allow_successful_noop: bool,
) -> Result<SupersededReceiptState> {
    if step.confirmation.is_some() {
        return Err(PublicClosePublisherError::Conflict(
            "one local transaction is recorded as both successful and superseded".into(),
        ));
    }
    match inspect_receipt_by_hash(
        backend,
        &step.transaction.transaction_hash,
        Some(signer),
        Some(&step.transaction.target),
        chain_id,
        allow_unfinalized_devnet,
        false,
    )? {
        ReceiptState::Missing => {
            if step.superseded_confirmation.is_some() {
                return Err(PublicClosePublisherError::Evidence(
                    "stored superseded receipt disappeared; refusing reservation-free replay"
                        .into(),
                ));
            }
            // `publish_exact_raw` rejects an already-consumed unknown nonce. If the sibling won
            // before our first broadcast, the exact guarded call is now guaranteed to revert.
            publish_exact_raw(backend, signer, &step.transaction)?;
            Ok(SupersededReceiptState::AwaitingReceipt)
        }
        ReceiptState::Mined { block_number } => {
            if step.superseded_confirmation.is_some() {
                return Err(PublicClosePublisherError::Evidence(
                    "stored superseded receipt lost canonical finality".into(),
                ));
            }
            Ok(SupersededReceiptState::AwaitingFinality(block_number))
        }
        ReceiptState::Finalized {
            receipt,
            confirmation,
        } => {
            if receipt_status(&receipt)? && !allow_successful_noop {
                return Err(PublicClosePublisherError::Conflict(
                    "local and permissionless transactions both claim one-shot success".into(),
                ));
            }
            if let Some(stored) = &step.superseded_confirmation {
                validate_stored_confirmation(stored, &confirmation)?;
            }
            Ok(SupersededReceiptState::Finalized(confirmation))
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClosePhase {
    Attest,
    Submit,
    Finalize,
    Materialize,
}

impl ClosePhase {
    fn label(self) -> &'static str {
        match self {
            Self::Attest => "attest",
            Self::Submit => "submit",
            Self::Finalize => "finalize",
            Self::Materialize => "materialize",
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn reconcile_semantic_winner<B: ClosePublisherBackend>(
    config: &PublicClosePublisherConfig,
    backend: &mut B,
    journal: &mut PublicationJournal,
    phase: ClosePhase,
    winner: &FinalizedReceipt,
    reservation: &SignerReservation,
    signer: &str,
) -> Result<Option<PublicCloseProgress>> {
    let mut step = match phase {
        ClosePhase::Attest => journal.attest.clone(),
        ClosePhase::Submit => journal.submit.clone(),
        ClosePhase::Finalize => journal.finalize.clone(),
        ClosePhase::Materialize => journal.materialize.clone(),
    };
    let Some(mut local) = step.take() else {
        // Also repairs a crash after intent reservation but before a raw transaction was written.
        release_exact_signer_reservation(&config.signer_lock_root, reservation)?;
        return Ok(None);
    };
    if same_hex(
        &local.transaction.transaction_hash,
        &winner.transaction_hash,
    ) {
        if local.superseded_confirmation.is_some() {
            return Err(PublicClosePublisherError::Conflict(
                "semantic winner was previously recorded as a superseded local transaction".into(),
            ));
        }
        if let Some(stored) = &local.confirmation {
            validate_stored_confirmation(stored, winner)?;
        }
        local.confirmation = Some(winner.clone());
        match phase {
            ClosePhase::Attest => journal.attest = Some(local),
            ClosePhase::Submit => journal.submit = Some(local),
            ClosePhase::Finalize => journal.finalize = Some(local),
            ClosePhase::Materialize => journal.materialize = Some(local),
        }
        write_journal(&config.journal_path, journal)?;
        release_exact_signer_reservation(&config.signer_lock_root, reservation)?;
        return Ok(None);
    }

    let needs_reservation = local.superseded_confirmation.is_none();
    if needs_reservation {
        claim_signer_reservation(&config.signer_lock_root, reservation)?;
    }
    match settle_superseded_transaction(
        backend,
        &local,
        signer,
        journal.binding.chain_id,
        config.allow_unfinalized_devnet,
        phase == ClosePhase::Attest,
    )? {
        SupersededReceiptState::AwaitingReceipt => {
            Ok(Some(PublicCloseProgress::AwaitingSupersededReceipt {
                local_step: phase.label().into(),
                transaction_hash: local.transaction.transaction_hash,
            }))
        }
        SupersededReceiptState::AwaitingFinality(receipt_block) => {
            Ok(Some(PublicCloseProgress::AwaitingSupersededFinality {
                local_step: phase.label().into(),
                transaction_hash: local.transaction.transaction_hash,
                receipt_block,
            }))
        }
        SupersededReceiptState::Finalized(confirmation) => {
            local.superseded_confirmation = Some(confirmation);
            match phase {
                ClosePhase::Attest => journal.attest = Some(local),
                ClosePhase::Submit => journal.submit = Some(local),
                ClosePhase::Finalize => journal.finalize = Some(local),
                ClosePhase::Materialize => journal.materialize = Some(local),
            }
            write_journal(&config.journal_path, journal)?;
            if needs_reservation {
                release_signer_reservation(&config.signer_lock_root, reservation)?;
            } else {
                release_exact_signer_reservation(&config.signer_lock_root, reservation)?;
            }
            Ok(None)
        }
    }
}

fn observation_at_receipt<B: ClosePublisherBackend>(
    backend: &mut B,
    manager: &str,
    confirmation: &FinalizedReceipt,
) -> Result<ManagerObservation> {
    let block = backend.block_at(
        confirmation.block_number,
        confirmation.finalized_checkpoint.source,
    )?;
    let expected_hash = confirmation
        .block_hash
        .parse::<Bytes32>()
        .map_err(|error| {
            PublicClosePublisherError::Evidence(format!("parse confirmation block hash: {error}"))
        })?;
    if block.number != confirmation.block_number || block.hash != expected_hash {
        return Err(PublicClosePublisherError::Evidence(
            "receipt block changed before manager read-back".into(),
        ));
    }
    let observation = backend.observe_manager(manager, confirmation.block_number)?;
    if observation.block_timestamp != block.timestamp {
        return Err(PublicClosePublisherError::Evidence(
            "manager read-back is not pinned to the receipt block".into(),
        ));
    }
    let second = backend.block_at(
        confirmation.block_number,
        confirmation.finalized_checkpoint.source,
    )?;
    if second != block {
        return Err(PublicClosePublisherError::Evidence(
            "receipt block changed during manager read-back".into(),
        ));
    }
    Ok(observation)
}

fn validate_account_name(account: &str) -> Result<()> {
    if account.is_empty()
        || account.len() > 128
        || !account
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        || !account.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        return Err(PublicClosePublisherError::Configuration(
            "Foundry account must be 1..128 ASCII alphanumeric/._- characters and begin alphanumeric"
                .into(),
        ));
    }
    Ok(())
}

fn validate_config(config: &PublicClosePublisherConfig) -> Result<()> {
    if config.rpc_url.trim().is_empty() {
        return Err(PublicClosePublisherError::Configuration(
            "RPC URL must not be empty".into(),
        ));
    }
    validate_account_name(config.account.trim())?;
    normalize_hex(
        &config.expected_final_channel_state_digest,
        32,
        "trusted expected final channel state digest",
    )
    .map_err(PublicClosePublisherError::Configuration)?;
    normalize_nonzero_hex(
        &config.deployment_manifest_sha256,
        32,
        "deployment manifest SHA-256",
    )
    .map_err(PublicClosePublisherError::Configuration)?;
    for forbidden in ["INTMAX_DEPOSIT_KEY", "INTMAX_L1_PRIVATE_KEY", "PRIVATE_KEY"] {
        if std::env::var(forbidden)
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(PublicClosePublisherError::Configuration(format!(
                "raw key environment {forbidden} is forbidden; use an encrypted Foundry account selector"
            )));
        }
    }
    if config.bundle_dir == config.deployment_manifest_path
        || config.bundle_dir == config.journal_path
        || config.bundle_dir == config.signer_lock_root
        || config.deployment_manifest_path == config.journal_path
        || config.deployment_manifest_path == config.signer_lock_root
        || config.journal_path == config.signer_lock_root
    {
        return Err(PublicClosePublisherError::Configuration(
            "bundle, deployment manifest, journal, and signer lock root must be distinct paths"
                .into(),
        ));
    }
    Ok(())
}

fn make_binding(
    prepared: &PreparedClose,
    deployment: &DeploymentManifest,
    deployment_manifest_hash: String,
    signer_lock_root: &Path,
) -> Result<PublicationBinding> {
    let attest = attest_calldata(&deployment.manager, &prepared.backing_mle.compact_proof)?;
    let attest_bytes = decode_hex(&attest, None, "attest calldata")
        .map_err(PublicClosePublisherError::Bundle)?;
    let submit_bytes = decode_hex(&prepared.submit_calldata, None, "submit calldata")
        .map_err(PublicClosePublisherError::Bundle)?;
    let materialize =
        materialize_calldata(&deployment.manager, &prepared.backing_mle.compact_proof)?;
    let materialize_bytes = decode_hex(&materialize, None, "materialize calldata")
        .map_err(PublicClosePublisherError::Bundle)?;
    let signer_lock_root = ensure_private_directory(signer_lock_root)?;
    let signer_lock_root = signer_lock_root.to_str().ok_or_else(|| {
        PublicClosePublisherError::Configuration(
            "canonical signer lock root must have a UTF-8 representation".into(),
        )
    })?;
    Ok(PublicationBinding {
        schema_version: JOURNAL_VERSION,
        chain_id: prepared.chain_id,
        rollup: prepared.rollup.clone(),
        manager: deployment.manager.clone(),
        materializer: deployment.close_funding_materializer.clone(),
        channel_id: prepared.channel_id,
        expected_final_channel_state_digest: prepared.expected.final_channel_state_digest.clone(),
        close_intent_digest: prepared.expected.close_intent_digest.clone(),
        artifact_hash: prepared.artifact_hash.clone(),
        component_hashes: prepared.component_hashes.clone(),
        compact_proof_hash: prepared.compact_proof_hash.clone(),
        compact_proof_length: prepared.compact_proof_length,
        backing_compact_proof_hash: prepared.backing_compact_proof_hash.clone(),
        backing_compact_proof_length: prepared.backing_compact_proof_length,
        mle_fixture_schema: MLE_VERIFIER_FIXTURE_SCHEMA_V2.into(),
        mle_protocol_version: MLE_PROTOCOL_VERSION_CURRENT,
        mle_proof_layout_hash: generated_hex(&MLE_PROOF_LAYOUT_HASH_V2),
        mle_compact_layout_hash: generated_hex(&COMPACT_LAYOUT_HASH_V2),
        deployment_manifest_hash,
        attest_calldata_hash: keccak_hex(&attest_bytes),
        submit_calldata_hash: keccak_hex(&submit_bytes),
        materialize_calldata_hash: keccak_hex(&materialize_bytes),
        signer_lock_root: signer_lock_root.to_string(),
    })
}

fn validate_manager_for_submit(
    manager: &ManagerObservation,
    deployment: &ObservedDeployment,
    expected: &ExpectedClose,
) -> Result<Option<PublicCloseProgress>> {
    match manager.status {
        0 => return Ok(Some(PublicCloseProgress::AwaitingCloseRequest)),
        1 => {}
        2 => {
            return Err(PublicClosePublisherError::Conflict(
                "manager is already Closed before the journaled exact finalizer was confirmed"
                    .into(),
            ));
        }
        value => {
            return Err(PublicClosePublisherError::Evidence(format!(
                "manager returned invalid lifecycle status {value}"
            )));
        }
    }
    if manager.current_close_freeze_nonce != expected.close_freeze_nonce {
        return Err(PublicClosePublisherError::Conflict(format!(
            "manager freeze nonce {} differs from proof nonce {}",
            manager.current_close_freeze_nonce, expected.close_freeze_nonce
        )));
    }
    if manager.close_request_generation == 0
        || deployment.materializer_frozen_generation != manager.close_request_generation
    {
        return Err(PublicClosePublisherError::Evidence(
            "materializer is not frozen for the Manager's exact close-request generation".into(),
        ));
    }
    if let Some(pending) = &manager.pending {
        if pending_matches(pending, expected) {
            return Ok(None);
        }
        if !can_replace_pending(pending, expected) {
            return Err(PublicClosePublisherError::Conflict(
                "a different equal-or-newer close is already pending; artifact is stale/conflicting"
                    .into(),
            ));
        }
        let response = deployment.challenge_period.min(3_600);
        let absolute_end = manager
            .close_challenge_horizon
            .checked_add(response)
            .ok_or_else(|| {
                PublicClosePublisherError::Evidence("close response horizon overflow".into())
            })?;
        if manager.block_timestamp > absolute_end {
            return Err(PublicClosePublisherError::Conflict(format!(
                "newer public artifact arrived after the bounded replacement tail {absolute_end}"
            )));
        }
        return Ok(None);
    }
    let eligible_at = manager.close_requested_at.checked_add(600).ok_or_else(|| {
        PublicClosePublisherError::Evidence("close grace timestamp overflow".into())
    })?;
    if manager.close_requested_at == 0 {
        return Err(PublicClosePublisherError::Evidence(
            "ClosePending manager has neither a request timestamp nor pending intent".into(),
        ));
    }
    if manager.block_timestamp < eligible_at {
        return Ok(Some(PublicCloseProgress::AwaitingGrace {
            eligible_at,
            durable_time: manager.block_timestamp,
        }));
    }
    Ok(None)
}

fn validate_manager_for_finalize(
    manager: &ManagerObservation,
    expected: &ExpectedClose,
    expected_close_request_generation: u64,
) -> Result<Option<PublicCloseProgress>> {
    if manager.close_request_generation != expected_close_request_generation {
        return Err(PublicClosePublisherError::Conflict(format!(
            "manager closeRequestGeneration {} differs from journaled finalizer era {}",
            manager.close_request_generation, expected_close_request_generation
        )));
    }
    if manager.status != 1 {
        return Err(PublicClosePublisherError::Conflict(
            "manager is not ClosePending for the exact guarded finalization".into(),
        ));
    }
    let pending = manager.pending.as_ref().ok_or_else(|| {
        PublicClosePublisherError::Evidence(
            "ClosePending manager has no active pending close".into(),
        )
    })?;
    if !pending_matches(pending, expected) {
        return Err(PublicClosePublisherError::Conflict(
            "pending close changed after proof submission; guarded finalizer will not be emitted"
                .into(),
        ));
    }
    if manager.block_timestamp <= pending.challenge_deadline {
        return Ok(Some(PublicCloseProgress::AwaitingChallengeDeadline {
            challenge_deadline: pending.challenge_deadline,
            durable_time: manager.block_timestamp,
        }));
    }
    Ok(None)
}

fn build_finalize_authorization(
    expected: &ExpectedClose,
    manager: &ManagerObservation,
    checkpoint: &L1FinalizedCheckpoint,
) -> Result<FinalizeAuthorization> {
    checkpoint
        .validate()
        .map_err(PublicClosePublisherError::Evidence)?;
    let calldata = finalize_calldata(expected, manager.close_request_generation)?;
    let calldata_bytes = decode_hex(&calldata, None, "guarded finalize calldata")
        .map_err(PublicClosePublisherError::Evidence)?;
    Ok(FinalizeAuthorization {
        close_request_generation: manager.close_request_generation,
        observation_checkpoint: checkpoint.clone(),
        calldata,
        calldata_hash: keccak_hex(&calldata_bytes),
    })
}

fn validate_finalize_authorization(
    authorization: &FinalizeAuthorization,
    expected: &ExpectedClose,
) -> Result<()> {
    authorization
        .observation_checkpoint
        .validate()
        .map_err(PublicClosePublisherError::Evidence)?;
    let expected_calldata = finalize_calldata(expected, authorization.close_request_generation)?;
    let expected_hash = keccak_hex(
        &decode_hex(&expected_calldata, None, "guarded finalize calldata")
            .map_err(PublicClosePublisherError::Evidence)?,
    );
    if !same_hex(&authorization.calldata, &expected_calldata)
        || !same_hex(&authorization.calldata_hash, &expected_hash)
    {
        return Err(PublicClosePublisherError::Conflict(
            "journaled finalizer generation/calldata/hash identity was modified".into(),
        ));
    }
    Ok(())
}

fn pin_finalize_authorization(
    config: &PublicClosePublisherConfig,
    journal: &mut PublicationJournal,
    expected: &ExpectedClose,
    manager: &ManagerObservation,
    checkpoint: &L1FinalizedCheckpoint,
) -> Result<FinalizeAuthorization> {
    let candidate = build_finalize_authorization(expected, manager, checkpoint)?;
    if let Some(stored) = journal.finalize_authorization.clone() {
        validate_finalize_authorization(&stored, expected)?;
        if stored.close_request_generation != candidate.close_request_generation {
            if journal.finalize.is_some() {
                return Err(PublicClosePublisherError::Conflict(format!(
                    "close request era advanced from journaled generation {} to {}; refusing to redirect a finalizer with raw WAL bytes",
                    stored.close_request_generation, candidate.close_request_generation
                )));
            }
            // An authorization alone is prepared metadata, not a signed action. Its exact signer
            // reservation can be abandoned only while no raw WAL exists, after which the new
            // monotone request era receives a distinct calldata/hash/action identity.
            let stale_reservation = close_signer_reservation(
                journal.binding.chain_id,
                &journal.submitter,
                &config.journal_path,
                &journal.binding,
                "finalize",
                &journal.binding.manager,
                &stored.calldata_hash,
                Some(stored.close_request_generation),
            )?;
            release_exact_signer_reservation(&config.signer_lock_root, &stale_reservation)?;
            journal.finalize_authorization = Some(candidate.clone());
            write_journal(&config.journal_path, journal)?;
            return Ok(candidate);
        }
        return Ok(stored);
    }
    journal.finalize_authorization = Some(candidate.clone());
    // PRE-SIGN boundary: the exact generation, canonical checkpoint, calldata and calldata hash are
    // fsynced before the signer-global reservation is claimed or the encrypted account is opened.
    write_journal(&config.journal_path, journal)?;
    Ok(candidate)
}

fn stored_finalize_authorization(
    journal: &PublicationJournal,
    expected: &ExpectedClose,
) -> Result<FinalizeAuthorization> {
    let authorization = journal.finalize_authorization.clone().ok_or_else(|| {
        PublicClosePublisherError::Conflict(
            "finalize transaction/receipt has no durable close-request generation pin".into(),
        )
    })?;
    validate_finalize_authorization(&authorization, expected)?;
    Ok(authorization)
}

fn revalidate_finalize_authorization<B: ClosePublisherBackend>(
    backend: &mut B,
    authorization: &FinalizeAuthorization,
    expected: &ExpectedClose,
    manager: &ManagerObservation,
    current_checkpoint: &L1FinalizedCheckpoint,
    require_current_generation: bool,
) -> Result<()> {
    validate_finalize_authorization(authorization, expected)?;
    let pinned_block = backend.block_at(
        authorization.observation_checkpoint.block_number,
        authorization.observation_checkpoint.source,
    )?;
    validate_checkpoint_block(&authorization.observation_checkpoint, &pinned_block)?;
    checkpoint_advances(&authorization.observation_checkpoint, current_checkpoint)
        .map_err(PublicClosePublisherError::Evidence)?;
    if require_current_generation
        && manager.close_request_generation != authorization.close_request_generation
    {
        return Err(PublicClosePublisherError::Conflict(format!(
            "close request era changed after durable authorization: pinned generation {}, current generation {}",
            authorization.close_request_generation, manager.close_request_generation
        )));
    }
    Ok(())
}

fn finalize_authorization_for_semantic_winner<B: ClosePublisherBackend>(
    config: &PublicClosePublisherConfig,
    backend: &mut B,
    journal: &mut PublicationJournal,
    expected: &ExpectedClose,
    manager: &ManagerObservation,
    checkpoint: &L1FinalizedCheckpoint,
) -> Result<FinalizeAuthorization> {
    if journal.finalize_authorization.is_some() {
        // Preserve the identity of an already-signed losing raw transaction. A later request era
        // may finalize the same proof digest; that semantic winner does not authorize rewriting the
        // local raw transaction or its signer reservation. The loser is broadcast to a canonical
        // revert before the signer lane is released.
        let authorization = stored_finalize_authorization(journal, expected)?;
        revalidate_finalize_authorization(
            backend,
            &authorization,
            expected,
            manager,
            checkpoint,
            false,
        )?;
        if authorization.close_request_generation != manager.close_request_generation
            && journal.finalize.is_none()
        {
            // No raw WAL exists, so `pin_finalize_authorization` may rotate the prepared metadata
            // and exact reservation to the semantic winner's actual generation.
            return pin_finalize_authorization(config, journal, expected, manager, checkpoint);
        }
        Ok(authorization)
    } else {
        pin_finalize_authorization(config, journal, expected, manager, checkpoint)
    }
}

fn step_receipt<B: ClosePublisherBackend>(
    backend: &mut B,
    step: &TransactionStep,
    signer: &str,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
) -> Result<ReceiptState> {
    let current = inspect_receipt(
        backend,
        &step.transaction,
        signer,
        chain_id,
        allow_unfinalized_devnet,
    )?;
    if let (Some(stored), ReceiptState::Finalized { confirmation, .. }) =
        (&step.confirmation, &current)
    {
        validate_stored_confirmation(stored, confirmation)?;
    } else if step.confirmation.is_some() {
        return Err(PublicClosePublisherError::Evidence(
            "a previously finalized receipt is no longer finalized/canonical".into(),
        ));
    }
    Ok(current)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SemanticCloseEvent {
    Submitted,
    Finalized,
}

impl SemanticCloseEvent {
    fn topic(self) -> String {
        match self {
            Self::Submitted => keccak_hex(CLOSE_SUBMITTED_EVENT.as_bytes()),
            Self::Finalized => keccak_hex(CLOSE_FINALIZED_EVENT.as_bytes()),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Submitted => "CloseSubmitted",
            Self::Finalized => "CloseFinalized",
        }
    }
}

fn semantic_evidence_by_hash<B: ClosePublisherBackend>(
    backend: &mut B,
    transaction_hash: &str,
    event: SemanticCloseEvent,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
) -> Result<(Value, FinalizedReceipt)> {
    let transaction_hash = normalize_hex(transaction_hash, 32, "semantic transaction hash")
        .map_err(PublicClosePublisherError::Evidence)?;
    let ReceiptState::Finalized {
        receipt,
        confirmation,
    } = inspect_receipt_by_hash(
        backend,
        &transaction_hash,
        None,
        None,
        chain_id,
        allow_unfinalized_devnet,
        true,
    )?
    else {
        return Err(PublicClosePublisherError::Evidence(format!(
            "{} semantic receipt is not covered by a durable head",
            event.label()
        )));
    };
    Ok((receipt, confirmation))
}

fn semantic_confirmation_by_hash<B: ClosePublisherBackend>(
    backend: &mut B,
    manager: &str,
    expected: &ExpectedClose,
    transaction_hash: &str,
    event: SemanticCloseEvent,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
) -> Result<FinalizedReceipt> {
    let (receipt, confirmation) = semantic_evidence_by_hash(
        backend,
        transaction_hash,
        event,
        chain_id,
        allow_unfinalized_devnet,
    )?;
    let observation = observation_at_receipt(backend, manager, &confirmation)?;
    match event {
        SemanticCloseEvent::Submitted => {
            let pending_match = if observation.status == 1 {
                if let Some(pending) = observation.pending.as_ref() {
                    pending_matches(pending, expected)
                        && exact_close_submitted_event(&receipt, manager, |event| {
                            submitted_event_matches_pending(event, pending)
                        })?
                        .is_some()
                } else {
                    false
                }
            } else {
                false
            };
            // eth_call at a block number observes end-of-block state. A permissionless submit and
            // guarded finalize may therefore share a block, in which case the submit receipt's
            // block read-back is already Closed. The exact finalized vector plus the fully decoded
            // submit event still binds that stored provenance without guessing an earlier era.
            let same_block_finalized = observation.status == 2
                && observation
                    .finalized
                    .as_ref()
                    .is_some_and(|value| finalized_matches(value, expected))
                && exact_close_submitted_event(&receipt, manager, |event| {
                    submitted_event_matches_expected(event, expected)
                })?
                .is_some();
            if !pending_match && !same_block_finalized {
                return Err(PublicClosePublisherError::Evidence(
                    "adopted submit receipt block does not bind the exact pending/finalized close"
                        .into(),
                ));
            }
        }
        SemanticCloseEvent::Finalized => {
            if observation.status != 2
                || !observation
                    .finalized
                    .as_ref()
                    .is_some_and(|value| finalized_matches(value, expected))
            {
                return Err(PublicClosePublisherError::Evidence(
                    "adopted finalize receipt block does not contain the full exact finalized close"
                        .into(),
                ));
            }
            validate_close_finalized_event(&receipt, manager, expected)?;
        }
    }
    Ok(confirmation)
}

fn semantic_position(confirmation: &FinalizedReceipt) -> (u64, u64) {
    (confirmation.block_number, confirmation.transaction_index)
}

fn same_semantic_receipt(left: &FinalizedReceipt, right: &FinalizedReceipt) -> bool {
    same_hex(&left.transaction_hash, &right.transaction_hash)
        && same_hex(&left.block_hash, &right.block_hash)
        && left.block_number == right.block_number
        && left.transaction_index == right.transaction_index
}

/// The durable attestation observation every later close-era event must be ordered after.
fn attested_lower_bound(journal: &PublicationJournal) -> Result<FinalizedReceipt> {
    journal.attest_observation.clone().ok_or_else(|| {
        PublicClosePublisherError::Conflict(
            "close state machine reached semantic adoption without a durable backing attestation observation"
                .into(),
        )
    })
}

/// A `CloseSubmitted`/`CloseFinalized` confirmation is authority for this close era only when its
/// canonical `(block, transaction index)` position is strictly after the exact backing attestation
/// this era depends on. Same-block ordering is decided by the transaction index.
fn require_after_attestation(
    journal: &PublicationJournal,
    confirmation: &FinalizedReceipt,
    label: &str,
) -> Result<()> {
    let attested = attested_lower_bound(journal)?;
    if semantic_position(confirmation) <= semantic_position(&attested) {
        return Err(PublicClosePublisherError::Evidence(format!(
            "{label} confirmation at block {} index {} is not ordered strictly after the backing attestation at block {} index {}",
            confirmation.block_number,
            confirmation.transaction_index,
            attested.block_number,
            attested.transaction_index
        )));
    }
    Ok(())
}

fn discover_semantic_confirmation<B: ClosePublisherBackend>(
    backend: &mut B,
    deployment: &DeploymentManifest,
    expected: &ExpectedClose,
    event: SemanticCloseEvent,
    current_pending: Option<&ObservedPendingClose>,
    strictly_before: Option<&FinalizedReceipt>,
    strictly_after: Option<&FinalizedReceipt>,
    checkpoint: &L1FinalizedCheckpoint,
    allow_unfinalized_devnet: bool,
) -> Result<FinalizedReceipt> {
    let hashes = backend.event_transaction_hashes(
        &deployment.manager,
        &event.topic(),
        &expected.close_intent_digest,
        deployment.manager_deployment_block,
        checkpoint.block_number,
    )?;
    if hashes.is_empty() {
        return Err(PublicClosePublisherError::Conflict(format!(
            "durable {} provenance is missing",
            event.label()
        )));
    }
    if let Some(pending) = current_pending {
        if !pending_matches(pending, expected) {
            return Err(PublicClosePublisherError::Conflict(
                "semantic discovery was given a pending close outside the exact proof era".into(),
            ));
        }
    }
    let mut matching = Vec::new();
    for hash in hashes {
        let (receipt, confirmation) = semantic_evidence_by_hash(
            backend,
            &hash,
            event,
            checkpoint.chain_id,
            allow_unfinalized_devnet,
        )?;
        let exact = match event {
            SemanticCloseEvent::Submitted => {
                if let Some(pending) = current_pending {
                    exact_close_submitted_event(&receipt, &deployment.manager, |submitted| {
                        submitted_event_matches_pending(submitted, pending)
                    })?
                    .is_some()
                } else {
                    exact_close_submitted_event(&receipt, &deployment.manager, |submitted| {
                        submitted_event_matches_expected(submitted, expected)
                    })?
                    .is_some()
                }
            }
            SemanticCloseEvent::Finalized => {
                exact_close_finalized_event(&receipt, &deployment.manager, expected)?.is_some()
            }
        };
        if !exact {
            continue;
        }
        if strictly_before
            .is_some_and(|upper| semantic_position(&confirmation) >= semantic_position(upper))
        {
            return Err(PublicClosePublisherError::Evidence(format!(
                "matching {} provenance is not ordered before guarded finalization",
                event.label()
            )));
        }
        if strictly_after
            .is_some_and(|lower| semantic_position(&confirmation) <= semantic_position(lower))
        {
            // The Manager only accepts this exact close after its whole-vector backing statement
            // is attested, so an exact-digest event at or before the attestation position is
            // evidence of an inconsistent chain view (stale event, reorg, or substituted RPC).
            return Err(PublicClosePublisherError::Evidence(format!(
                "matching {} provenance is not ordered strictly after the durable backing attestation",
                event.label()
            )));
        }
        checkpoint_advances(checkpoint, &confirmation.finalized_checkpoint)
            .map_err(PublicClosePublisherError::Evidence)?;
        matching.push(confirmation);
    }
    if matching.is_empty() {
        return Err(PublicClosePublisherError::Conflict(format!(
            "durable {} provenance has no event in the current exact close era",
            event.label()
        )));
    }
    if event == SemanticCloseEvent::Finalized && matching.len() != 1 {
        return Err(PublicClosePublisherError::Conflict(
            "durable CloseFinalized provenance is ambiguous".into(),
        ));
    }
    matching.sort_by_key(semantic_position);
    let selected = matching.pop().expect("nonempty checked");
    if matching
        .last()
        .is_some_and(|other| semantic_position(other) == semantic_position(&selected))
    {
        return Err(PublicClosePublisherError::Conflict(format!(
            "durable {} current-era provenance has an ambiguous latest transaction position",
            event.label()
        )));
    }
    // Historical same-digest eras are filtered by their decoded event before any historical
    // getter call. Only the canonically selected current-era receipt needs archive-state readback.
    let confirmation = semantic_confirmation_by_hash(
        backend,
        &deployment.manager,
        expected,
        &selected.transaction_hash,
        event,
        checkpoint.chain_id,
        allow_unfinalized_devnet,
    )?;
    if let Some(pending) = current_pending {
        let observation = observation_at_receipt(backend, &deployment.manager, &confirmation)?;
        if observation.status != 1 || observation.pending.as_ref() != Some(pending) {
            return Err(PublicClosePublisherError::Evidence(
                "latest matching CloseSubmitted receipt does not read back the current exact pending era"
                    .into(),
            ));
        }
    }
    Ok(confirmation)
}

fn revalidate_semantic_confirmation<B: ClosePublisherBackend>(
    backend: &mut B,
    manager: &str,
    expected: &ExpectedClose,
    stored: &FinalizedReceipt,
    event: SemanticCloseEvent,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
) -> Result<FinalizedReceipt> {
    let current = semantic_confirmation_by_hash(
        backend,
        manager,
        expected,
        &stored.transaction_hash,
        event,
        chain_id,
        allow_unfinalized_devnet,
    )?;
    validate_stored_confirmation(stored, &current)?;
    Ok(current)
}

fn validate_materializer_ready(
    manager: &ManagerObservation,
    observed: &ObservedDeployment,
    prepared: &PreparedClose,
    require_materialized: bool,
) -> Result<()> {
    if manager.status != 2
        || !manager
            .finalized
            .as_ref()
            .is_some_and(|value| finalized_matches(value, &prepared.expected))
    {
        return Err(PublicClosePublisherError::Evidence(
            "signed-head materialization requires the complete exact Closed manager state".into(),
        ));
    }
    if manager.close_request_generation == 0
        || observed.materializer_frozen_generation != manager.close_request_generation
    {
        return Err(PublicClosePublisherError::Evidence(
            "materializer frozen generation differs from the exact finalized close era".into(),
        ));
    }
    let materialized = same_hex(
        &observed.materialized_channel_exit,
        &prepared.expected.close_intent_digest,
    );
    if require_materialized && !materialized {
        return Err(PublicClosePublisherError::Evidence(
            "materializer did not persist the exact finalized close digest".into(),
        ));
    }
    if !require_materialized
        && !materialized
        && !same_hex(
            &observed.materialized_channel_exit,
            &format!("0x{}", "00".repeat(32)),
        )
    {
        return Err(PublicClosePublisherError::Conflict(
            "materializer contains a sibling finalized close digest".into(),
        ));
    }
    Ok(())
}

fn attestation_confirmation_by_hash<B: ClosePublisherBackend>(
    backend: &mut B,
    deployment: &DeploymentManifest,
    prepared: &PreparedClose,
    transaction_hash: &str,
    allow_unfinalized_devnet: bool,
) -> Result<FinalizedReceipt> {
    let transaction_hash = normalize_hex(transaction_hash, 32, "attestation transaction hash")
        .map_err(PublicClosePublisherError::Evidence)?;
    let ReceiptState::Finalized {
        receipt,
        confirmation,
    } = inspect_receipt_by_hash(
        backend,
        &transaction_hash,
        None,
        None,
        prepared.chain_id,
        allow_unfinalized_devnet,
        true,
    )?
    else {
        return Err(PublicClosePublisherError::Evidence(
            "SignedHeadBackingAttested receipt is not covered by a durable head".into(),
        ));
    };
    validate_attested_event(&receipt, deployment, prepared)?;
    let observed = backend.observe_deployment(deployment, prepared, confirmation.block_number)?;
    validate_deployment_observation(deployment, &observed, prepared)?;
    if !backing_attestation_ready(&observed, prepared)? {
        return Err(PublicClosePublisherError::Evidence(
            "attestation receipt block does not expose the exact current backing receipt".into(),
        ));
    }
    let stable_block = backend.block_at(
        confirmation.block_number,
        confirmation.finalized_checkpoint.source,
    )?;
    let expected_hash = confirmation
        .block_hash
        .parse::<Bytes32>()
        .map_err(|error| {
            PublicClosePublisherError::Evidence(format!(
                "parse attestation confirmation block hash: {error}"
            ))
        })?;
    if stable_block.hash != expected_hash || stable_block.number != confirmation.block_number {
        return Err(PublicClosePublisherError::Evidence(
            "attestation receipt block changed during pinned getter read-back".into(),
        ));
    }
    Ok(confirmation)
}

fn discover_attestation_confirmation<B: ClosePublisherBackend>(
    backend: &mut B,
    deployment: &DeploymentManifest,
    prepared: &PreparedClose,
    checkpoint: &L1FinalizedCheckpoint,
    allow_unfinalized_devnet: bool,
) -> Result<FinalizedReceipt> {
    let hashes = backend.event_transaction_hashes(
        &deployment.close_funding_materializer,
        &keccak_hex(SIGNED_HEAD_BACKING_ATTESTED_EVENT.as_bytes()),
        &indexed_u32(prepared.channel_id),
        deployment.manager_deployment_block,
        checkpoint.block_number,
    )?;
    let mut matching = Vec::new();
    for hash in hashes {
        let ReceiptState::Finalized { receipt, .. } = inspect_receipt_by_hash(
            backend,
            &hash,
            None,
            None,
            prepared.chain_id,
            allow_unfinalized_devnet,
            true,
        )?
        else {
            return Err(PublicClosePublisherError::Evidence(
                "attestation event search returned non-finalized provenance".into(),
            ));
        };
        if exact_attested_event(&receipt, deployment, prepared)?.is_none() {
            continue;
        }
        matching.push(attestation_confirmation_by_hash(
            backend,
            deployment,
            prepared,
            &hash,
            allow_unfinalized_devnet,
        )?);
    }
    if matching.len() != 1 {
        return Err(PublicClosePublisherError::Conflict(format!(
            "durable exact SignedHeadBackingAttested provenance count {} != 1",
            matching.len()
        )));
    }
    let confirmation = matching.pop().expect("one confirmation checked");
    checkpoint_advances(checkpoint, &confirmation.finalized_checkpoint)
        .map_err(PublicClosePublisherError::Evidence)?;
    Ok(confirmation)
}

fn revalidate_attestation_confirmation<B: ClosePublisherBackend>(
    backend: &mut B,
    deployment: &DeploymentManifest,
    prepared: &PreparedClose,
    stored: &FinalizedReceipt,
    allow_unfinalized_devnet: bool,
) -> Result<FinalizedReceipt> {
    let current = attestation_confirmation_by_hash(
        backend,
        deployment,
        prepared,
        &stored.transaction_hash,
        allow_unfinalized_devnet,
    )?;
    validate_stored_confirmation(stored, &current)?;
    Ok(current)
}

fn materialization_confirmation_by_hash<B: ClosePublisherBackend>(
    backend: &mut B,
    deployment: &DeploymentManifest,
    prepared: &PreparedClose,
    transaction_hash: &str,
    allow_unfinalized_devnet: bool,
) -> Result<FinalizedReceipt> {
    let transaction_hash = normalize_hex(transaction_hash, 32, "materialization transaction hash")
        .map_err(PublicClosePublisherError::Evidence)?;
    let ReceiptState::Finalized {
        receipt,
        confirmation,
    } = inspect_receipt_by_hash(
        backend,
        &transaction_hash,
        None,
        None,
        prepared.chain_id,
        allow_unfinalized_devnet,
        true,
    )?
    else {
        return Err(PublicClosePublisherError::Evidence(
            "SignedHeadExitMaterialized receipt is not covered by a durable head".into(),
        ));
    };
    validate_materialized_event(&receipt, deployment, prepared)?;
    let manager = observation_at_receipt(backend, &deployment.manager, &confirmation)?;
    let observed = backend.observe_deployment(deployment, prepared, confirmation.block_number)?;
    validate_deployment_observation(deployment, &observed, prepared)?;
    validate_materializer_ready(&manager, &observed, prepared, true)?;
    let stable_block = backend.block_at(
        confirmation.block_number,
        confirmation.finalized_checkpoint.source,
    )?;
    let expected_hash = confirmation
        .block_hash
        .parse::<Bytes32>()
        .map_err(|error| {
            PublicClosePublisherError::Evidence(format!(
                "parse materialization confirmation block hash: {error}"
            ))
        })?;
    if stable_block.hash != expected_hash || stable_block.number != confirmation.block_number {
        return Err(PublicClosePublisherError::Evidence(
            "materialization receipt block changed during pinned getter read-back".into(),
        ));
    }
    Ok(confirmation)
}

fn discover_materialization_confirmation<B: ClosePublisherBackend>(
    backend: &mut B,
    deployment: &DeploymentManifest,
    prepared: &PreparedClose,
    checkpoint: &L1FinalizedCheckpoint,
    allow_unfinalized_devnet: bool,
) -> Result<FinalizedReceipt> {
    let hashes = backend.event_transaction_hashes(
        &deployment.close_funding_materializer,
        &keccak_hex(SIGNED_HEAD_EXIT_MATERIALIZED_EVENT.as_bytes()),
        &indexed_u32(prepared.channel_id),
        deployment.manager_deployment_block,
        checkpoint.block_number,
    )?;
    let mut matching = Vec::new();
    for hash in hashes {
        let ReceiptState::Finalized { receipt, .. } = inspect_receipt_by_hash(
            backend,
            &hash,
            None,
            None,
            prepared.chain_id,
            allow_unfinalized_devnet,
            true,
        )?
        else {
            return Err(PublicClosePublisherError::Evidence(
                "materialization event search returned non-finalized provenance".into(),
            ));
        };
        if exact_materialized_event(&receipt, deployment, prepared)?.is_none() {
            continue;
        }
        matching.push(materialization_confirmation_by_hash(
            backend,
            deployment,
            prepared,
            &hash,
            allow_unfinalized_devnet,
        )?);
    }
    if matching.len() != 1 {
        return Err(PublicClosePublisherError::Conflict(format!(
            "durable exact SignedHeadExitMaterialized provenance count {} != 1",
            matching.len()
        )));
    }
    let confirmation = matching.pop().expect("one confirmation checked");
    checkpoint_advances(checkpoint, &confirmation.finalized_checkpoint)
        .map_err(PublicClosePublisherError::Evidence)?;
    Ok(confirmation)
}

fn revalidate_materialization_confirmation<B: ClosePublisherBackend>(
    backend: &mut B,
    deployment: &DeploymentManifest,
    prepared: &PreparedClose,
    stored: &FinalizedReceipt,
    allow_unfinalized_devnet: bool,
) -> Result<FinalizedReceipt> {
    let current = materialization_confirmation_by_hash(
        backend,
        deployment,
        prepared,
        &stored.transaction_hash,
        allow_unfinalized_devnet,
    )?;
    validate_stored_confirmation(stored, &current)?;
    Ok(current)
}

fn complete_from_materialization_confirmation(
    config: &PublicClosePublisherConfig,
    prepared: &PreparedClose,
    deployment: &DeploymentManifest,
    journal: &mut PublicationJournal,
    confirmation: FinalizedReceipt,
) -> Result<PublicCloseProgress> {
    if journal.attest_observation.is_none() || journal.finalize_observation.is_none() {
        return Err(PublicClosePublisherError::Conflict(
            "materialization cannot complete without durable attestation and guarded-finalize provenance"
                .into(),
        ));
    }
    journal.materialize_observation = Some(confirmation.clone());
    let finalize_transaction_hash = journal
        .finalize_observation
        .as_ref()
        .map(|value| value.transaction_hash.clone());
    let publication = PublicClosePublication {
        schema_version: PUBLICATION_VERSION,
        chain_id: prepared.chain_id,
        rollup: prepared.rollup.clone(),
        manager: deployment.manager.clone(),
        materializer: deployment.close_funding_materializer.clone(),
        channel_id: prepared.channel_id,
        close_intent_digest: prepared.expected.close_intent_digest.clone(),
        artifact_hash: prepared.artifact_hash.clone(),
        attest_transaction_hash: journal
            .attest_observation
            .as_ref()
            .expect("checked above")
            .transaction_hash
            .clone(),
        submit_transaction_hash: journal
            .submit_observation
            .as_ref()
            .map(|value| value.transaction_hash.clone()),
        finalize_transaction_hash,
        materialize_transaction_hash: confirmation.transaction_hash.clone(),
        finalized_checkpoint: confirmation.finalized_checkpoint,
    };
    journal.completed = Some(publication.clone());
    write_journal(&config.journal_path, journal)?;
    Ok(PublicCloseProgress::Complete { publication })
}

/// Make the exact whole-vector backing proof durably available on L1 before a close intent can
/// become the Manager's high-water mark. The call is permissionless and idempotent, but the
/// publisher still journals its exact signed bytes and reconciles the signer nonce when another
/// participant wins the semantic race.
#[allow(clippy::too_many_arguments)]
fn advance_attestation<B: ClosePublisherBackend>(
    config: &PublicClosePublisherConfig,
    backend: &mut B,
    prepared: &PreparedClose,
    deployment: &DeploymentManifest,
    journal: &mut PublicationJournal,
    signer: &str,
) -> Result<Option<PublicCloseProgress>> {
    let calldata = attest_calldata(&deployment.manager, &prepared.backing_mle.compact_proof)?;
    let calldata_bytes = decode_hex(&calldata, None, "attest calldata")
        .map_err(PublicClosePublisherError::Bundle)?;
    if !same_hex(
        &keccak_hex(&calldata_bytes),
        &journal.binding.attest_calldata_hash,
    ) {
        return Err(PublicClosePublisherError::Conflict(
            "attestation calldata differs from the durable artifact binding".into(),
        ));
    }
    let reservation = close_signer_reservation(
        prepared.chain_id,
        signer,
        &config.journal_path,
        &journal.binding,
        "attest",
        &deployment.close_funding_materializer,
        &journal.binding.attest_calldata_hash,
        None,
    )?;

    let (_, observed, checkpoint) = read_stable_context(
        backend,
        deployment,
        prepared,
        config.allow_unfinalized_devnet,
    )?;
    if backing_attestation_ready(&observed, prepared)? {
        let newly_adopted = journal.attest_observation.is_none();
        let confirmation = match journal.attest_observation.as_ref() {
            Some(stored) => revalidate_attestation_confirmation(
                backend,
                deployment,
                prepared,
                stored,
                config.allow_unfinalized_devnet,
            )?,
            None => discover_attestation_confirmation(
                backend,
                deployment,
                prepared,
                &checkpoint,
                config.allow_unfinalized_devnet,
            )?,
        };
        journal.attest_observation = Some(confirmation.clone());
        write_journal(&config.journal_path, journal)?;
        if let Some(waiting) = reconcile_semantic_winner(
            config,
            backend,
            journal,
            ClosePhase::Attest,
            &confirmation,
            &reservation,
            signer,
        )? {
            return Ok(Some(waiting));
        }
        if newly_adopted && journal.attest.is_none() {
            return Ok(Some(PublicCloseProgress::AttestAdopted {
                transaction_hash: confirmation.transaction_hash,
            }));
        }
        return Ok(None);
    }
    if journal.attest_observation.is_some() {
        return Err(PublicClosePublisherError::Evidence(
            "stored backing attestation lost its exact current canonical state".into(),
        ));
    }

    if let Some(mut step) = journal.attest.clone() {
        if step.superseded_confirmation.is_some() {
            return Err(PublicClosePublisherError::Conflict(
                "superseded attestation has no adopted semantic observation".into(),
            ));
        }
        let needs_reservation = step.confirmation.is_none();
        if needs_reservation {
            claim_signer_reservation(&config.signer_lock_root, &reservation)?;
        }
        validate_transaction_step(
            backend,
            &step,
            prepared.chain_id,
            signer,
            &deployment.close_funding_materializer,
            &calldata,
        )?;
        match step_receipt(
            backend,
            &step,
            signer,
            prepared.chain_id,
            config.allow_unfinalized_devnet,
        )? {
            ReceiptState::Missing if step.confirmation.is_none() => {
                let (_, fresh_observed, fresh_checkpoint) = read_stable_context(
                    backend,
                    deployment,
                    prepared,
                    config.allow_unfinalized_devnet,
                )?;
                if backing_attestation_ready(&fresh_observed, prepared)? {
                    let confirmation = discover_attestation_confirmation(
                        backend,
                        deployment,
                        prepared,
                        &fresh_checkpoint,
                        config.allow_unfinalized_devnet,
                    )?;
                    let hash = confirmation.transaction_hash.clone();
                    journal.attest_observation = Some(confirmation.clone());
                    write_journal(&config.journal_path, journal)?;
                    if let Some(waiting) = reconcile_semantic_winner(
                        config,
                        backend,
                        journal,
                        ClosePhase::Attest,
                        &confirmation,
                        &reservation,
                        signer,
                    )? {
                        return Ok(Some(waiting));
                    }
                    return Ok(Some(PublicCloseProgress::AttestAdopted {
                        transaction_hash: hash,
                    }));
                }
                let broadcast = publish_exact_raw(backend, signer, &step.transaction)?;
                return Ok(Some(if broadcast {
                    PublicCloseProgress::AttestBroadcast {
                        transaction_hash: step.transaction.transaction_hash,
                    }
                } else {
                    PublicCloseProgress::AwaitingAttestReceipt {
                        transaction_hash: step.transaction.transaction_hash,
                    }
                }));
            }
            ReceiptState::Mined { block_number } if step.confirmation.is_none() => {
                return Ok(Some(PublicCloseProgress::AwaitingAttestFinality {
                    transaction_hash: step.transaction.transaction_hash,
                    receipt_block: block_number,
                }));
            }
            ReceiptState::Finalized { confirmation, .. } => {
                let exact = attestation_confirmation_by_hash(
                    backend,
                    deployment,
                    prepared,
                    &confirmation.transaction_hash,
                    config.allow_unfinalized_devnet,
                )?;
                validate_stored_confirmation(&confirmation, &exact)?;
                step.confirmation = Some(exact.clone());
                journal.attest = Some(step);
                journal.attest_observation = Some(exact);
                write_journal(&config.journal_path, journal)?;
                if needs_reservation {
                    release_signer_reservation(&config.signer_lock_root, &reservation)?;
                } else {
                    release_exact_signer_reservation(&config.signer_lock_root, &reservation)?;
                }
                return Ok(None);
            }
            ReceiptState::Missing | ReceiptState::Mined { .. } => {
                return Err(PublicClosePublisherError::Evidence(
                    "stored attestation confirmation lost canonical finality".into(),
                ));
            }
        }
    }

    let transaction = sign_after_reservation(&config.signer_lock_root, &reservation, || {
        backend.sign_transaction(
            config.account.trim(),
            prepared.chain_id,
            signer,
            &deployment.close_funding_materializer,
            &calldata,
        )
    })?;
    let inspected = backend.inspect_signed_transaction(
        &transaction.raw_signed_transaction,
        prepared.chain_id,
        signer,
        &deployment.close_funding_materializer,
        &calldata,
    )?;
    if inspected != transaction {
        return Err(PublicClosePublisherError::Evidence(
            "attestation signer returned metadata inconsistent with raw bytes".into(),
        ));
    }
    journal.attest = Some(TransactionStep {
        transaction: transaction.clone(),
        confirmation: None,
        superseded_confirmation: None,
    });
    // Critical WAL boundary: exact raw attestation bytes are durable before publication.
    write_journal(&config.journal_path, journal)?;

    let (_, fresh_observed, fresh_checkpoint) = read_stable_context(
        backend,
        deployment,
        prepared,
        config.allow_unfinalized_devnet,
    )?;
    if backing_attestation_ready(&fresh_observed, prepared)? {
        let confirmation = discover_attestation_confirmation(
            backend,
            deployment,
            prepared,
            &fresh_checkpoint,
            config.allow_unfinalized_devnet,
        )?;
        let hash = confirmation.transaction_hash.clone();
        journal.attest_observation = Some(confirmation.clone());
        write_journal(&config.journal_path, journal)?;
        if let Some(waiting) = reconcile_semantic_winner(
            config,
            backend,
            journal,
            ClosePhase::Attest,
            &confirmation,
            &reservation,
            signer,
        )? {
            return Ok(Some(waiting));
        }
        return Ok(Some(PublicCloseProgress::AttestAdopted {
            transaction_hash: hash,
        }));
    }
    publish_exact_raw(backend, signer, &transaction)?;
    Ok(Some(PublicCloseProgress::AttestBroadcast {
        transaction_hash: transaction.transaction_hash,
    }))
}

#[allow(clippy::too_many_arguments)]
fn advance_materialization<B: ClosePublisherBackend>(
    config: &PublicClosePublisherConfig,
    backend: &mut B,
    prepared: &PreparedClose,
    deployment: &DeploymentManifest,
    journal: &mut PublicationJournal,
    signer: &str,
) -> Result<PublicCloseProgress> {
    let calldata =
        materialize_calldata(&deployment.manager, &prepared.backing_mle.compact_proof)?;
    let calldata_bytes = decode_hex(&calldata, None, "materialize calldata")
        .map_err(PublicClosePublisherError::Bundle)?;
    if !same_hex(
        &keccak_hex(&calldata_bytes),
        &journal.binding.materialize_calldata_hash,
    ) {
        return Err(PublicClosePublisherError::Conflict(
            "materialization calldata differs from the durable artifact binding".into(),
        ));
    }
    let generation =
        stored_finalize_authorization(journal, &prepared.expected)?.close_request_generation;
    let reservation = close_signer_reservation(
        prepared.chain_id,
        signer,
        &config.journal_path,
        &journal.binding,
        "materialize",
        &deployment.close_funding_materializer,
        &journal.binding.materialize_calldata_hash,
        Some(generation),
    )?;

    let (manager, observed, checkpoint) = read_stable_context(
        backend,
        deployment,
        prepared,
        config.allow_unfinalized_devnet,
    )?;
    validate_materializer_ready(&manager, &observed, prepared, false)?;
    if same_hex(
        &observed.materialized_channel_exit,
        &prepared.expected.close_intent_digest,
    ) {
        let confirmation = discover_materialization_confirmation(
            backend,
            deployment,
            prepared,
            &checkpoint,
            config.allow_unfinalized_devnet,
        )?;
        journal.materialize_observation = Some(confirmation.clone());
        write_journal(&config.journal_path, journal)?;
        if let Some(waiting) = reconcile_semantic_winner(
            config,
            backend,
            journal,
            ClosePhase::Materialize,
            &confirmation,
            &reservation,
            signer,
        )? {
            return Ok(waiting);
        }
        let hash = confirmation.transaction_hash.clone();
        let progress = complete_from_materialization_confirmation(
            config,
            prepared,
            deployment,
            journal,
            confirmation,
        )?;
        if journal.materialize.is_none() {
            return Ok(PublicCloseProgress::MaterializeAdopted {
                transaction_hash: hash,
            });
        }
        return Ok(progress);
    }
    if journal.materialize_observation.is_some() {
        return Err(PublicClosePublisherError::Evidence(
            "stored materialization confirmation lost its exact canonical state".into(),
        ));
    }

    if let Some(mut step) = journal.materialize.clone() {
        if step.superseded_confirmation.is_some() {
            return Err(PublicClosePublisherError::Conflict(
                "superseded materialization has no adopted semantic observation".into(),
            ));
        }
        let needs_reservation = step.confirmation.is_none();
        if needs_reservation {
            claim_signer_reservation(&config.signer_lock_root, &reservation)?;
        }
        validate_transaction_step(
            backend,
            &step,
            prepared.chain_id,
            signer,
            &deployment.close_funding_materializer,
            &calldata,
        )?;
        match step_receipt(
            backend,
            &step,
            signer,
            prepared.chain_id,
            config.allow_unfinalized_devnet,
        )? {
            ReceiptState::Missing if step.confirmation.is_none() => {
                let (fresh_manager, fresh_observed, fresh_checkpoint) = read_stable_context(
                    backend,
                    deployment,
                    prepared,
                    config.allow_unfinalized_devnet,
                )?;
                validate_materializer_ready(&fresh_manager, &fresh_observed, prepared, false)?;
                if same_hex(
                    &fresh_observed.materialized_channel_exit,
                    &prepared.expected.close_intent_digest,
                ) {
                    let confirmation = discover_materialization_confirmation(
                        backend,
                        deployment,
                        prepared,
                        &fresh_checkpoint,
                        config.allow_unfinalized_devnet,
                    )?;
                    journal.materialize_observation = Some(confirmation.clone());
                    write_journal(&config.journal_path, journal)?;
                    if let Some(waiting) = reconcile_semantic_winner(
                        config,
                        backend,
                        journal,
                        ClosePhase::Materialize,
                        &confirmation,
                        &reservation,
                        signer,
                    )? {
                        return Ok(waiting);
                    }
                    return complete_from_materialization_confirmation(
                        config,
                        prepared,
                        deployment,
                        journal,
                        confirmation,
                    );
                }
                let broadcast = publish_exact_raw(backend, signer, &step.transaction)?;
                return Ok(if broadcast {
                    PublicCloseProgress::MaterializeBroadcast {
                        transaction_hash: step.transaction.transaction_hash,
                    }
                } else {
                    PublicCloseProgress::AwaitingMaterializeReceipt {
                        transaction_hash: step.transaction.transaction_hash,
                    }
                });
            }
            ReceiptState::Mined { block_number } if step.confirmation.is_none() => {
                return Ok(PublicCloseProgress::AwaitingMaterializeFinality {
                    transaction_hash: step.transaction.transaction_hash,
                    receipt_block: block_number,
                });
            }
            ReceiptState::Finalized { confirmation, .. } => {
                let exact = materialization_confirmation_by_hash(
                    backend,
                    deployment,
                    prepared,
                    &confirmation.transaction_hash,
                    config.allow_unfinalized_devnet,
                )?;
                validate_stored_confirmation(&confirmation, &exact)?;
                step.confirmation = Some(exact.clone());
                journal.materialize = Some(step);
                journal.materialize_observation = Some(exact.clone());
                write_journal(&config.journal_path, journal)?;
                if needs_reservation {
                    release_signer_reservation(&config.signer_lock_root, &reservation)?;
                } else {
                    release_exact_signer_reservation(&config.signer_lock_root, &reservation)?;
                }
                return complete_from_materialization_confirmation(
                    config, prepared, deployment, journal, exact,
                );
            }
            ReceiptState::Missing | ReceiptState::Mined { .. } => {
                return Err(PublicClosePublisherError::Evidence(
                    "stored materialization confirmation lost canonical finality".into(),
                ));
            }
        }
    }

    let transaction = sign_after_reservation(&config.signer_lock_root, &reservation, || {
        backend.sign_transaction(
            config.account.trim(),
            prepared.chain_id,
            signer,
            &deployment.close_funding_materializer,
            &calldata,
        )
    })?;
    let inspected = backend.inspect_signed_transaction(
        &transaction.raw_signed_transaction,
        prepared.chain_id,
        signer,
        &deployment.close_funding_materializer,
        &calldata,
    )?;
    if inspected != transaction {
        return Err(PublicClosePublisherError::Evidence(
            "materialization signer returned metadata inconsistent with raw bytes".into(),
        ));
    }
    journal.materialize = Some(TransactionStep {
        transaction: transaction.clone(),
        confirmation: None,
        superseded_confirmation: None,
    });
    // Critical WAL boundary: exact raw materialization bytes are durable before publication.
    write_journal(&config.journal_path, journal)?;
    let (fresh_manager, fresh_observed, fresh_checkpoint) = read_stable_context(
        backend,
        deployment,
        prepared,
        config.allow_unfinalized_devnet,
    )?;
    validate_materializer_ready(&fresh_manager, &fresh_observed, prepared, false)?;
    if same_hex(
        &fresh_observed.materialized_channel_exit,
        &prepared.expected.close_intent_digest,
    ) {
        let confirmation = discover_materialization_confirmation(
            backend,
            deployment,
            prepared,
            &fresh_checkpoint,
            config.allow_unfinalized_devnet,
        )?;
        journal.materialize_observation = Some(confirmation.clone());
        write_journal(&config.journal_path, journal)?;
        if let Some(waiting) = reconcile_semantic_winner(
            config,
            backend,
            journal,
            ClosePhase::Materialize,
            &confirmation,
            &reservation,
            signer,
        )? {
            return Ok(waiting);
        }
        return complete_from_materialization_confirmation(
            config,
            prepared,
            deployment,
            journal,
            confirmation,
        );
    }
    publish_exact_raw(backend, signer, &transaction)?;
    Ok(PublicCloseProgress::MaterializeBroadcast {
        transaction_hash: transaction.transaction_hash,
    })
}

fn advance_with_backend<B: ClosePublisherBackend>(
    config: &PublicClosePublisherConfig,
    backend: &mut B,
) -> Result<PublicCloseProgress> {
    let prepared = prepare_bundle(
        &config.bundle_dir,
        &config.expected_final_channel_state_digest,
    )?;
    let (deployment, deployment_manifest_hash) = load_deployment_manifest(
        &config.deployment_manifest_path,
        &prepared,
        &config.deployment_manifest_sha256,
    )?;
    let observed_chain = backend.chain_id()?;
    if observed_chain != prepared.chain_id {
        return Err(PublicClosePublisherError::Evidence(format!(
            "RPC chain {observed_chain} differs from bundle chain {}",
            prepared.chain_id
        )));
    }
    if config.allow_unfinalized_devnet && observed_chain != ANVIL_CHAIN_ID {
        return Err(PublicClosePublisherError::Configuration(format!(
            "unfinalized-head escape is restricted to chain {ANVIL_CHAIN_ID}"
        )));
    }
    let signer = backend.signer_address(config.account.trim())?;
    let binding = make_binding(
        &prepared,
        &deployment,
        deployment_manifest_hash,
        &config.signer_lock_root,
    )?;
    let mut journal = load_or_create_journal(&config.journal_path, binding, &signer)?;
    // The Manager deliberately rejects a close proof until this exact whole-vector backing
    // statement is already durably attested. Advance that permissionless WAL first; only a
    // canonical finalized event plus pinned getter read-back permits the close state machine.
    if let Some(progress) = advance_attestation(
        config,
        backend,
        &prepared,
        &deployment,
        &mut journal,
        &signer,
    )? {
        return Ok(progress);
    }
    let submit_reservation = close_signer_reservation(
        prepared.chain_id,
        &signer,
        &config.journal_path,
        &journal.binding,
        "submit",
        &deployment.manager,
        &journal.binding.submit_calldata_hash,
        None,
    )?;

    // Completed journals are not trusted as a cache. Re-read the final receipt, its event, the
    // canonical finalized block and every persistent manager getter on every invocation.
    if let Some(completed) = journal.completed.clone() {
        let finalize_authorization = stored_finalize_authorization(&journal, &prepared.expected)?;
        let finalize_reservation = close_signer_reservation(
            prepared.chain_id,
            &signer,
            &config.journal_path,
            &journal.binding,
            "finalize",
            &deployment.manager,
            &finalize_authorization.calldata_hash,
            Some(finalize_authorization.close_request_generation),
        )?;
        let materialize_calldata =
            materialize_calldata(&deployment.manager, &prepared.backing_mle.compact_proof)?;
        let materialize_reservation = close_signer_reservation(
            prepared.chain_id,
            &signer,
            &config.journal_path,
            &journal.binding,
            "materialize",
            &deployment.close_funding_materializer,
            &journal.binding.materialize_calldata_hash,
            Some(finalize_authorization.close_request_generation),
        )?;
        if let Some(submit) = journal.submit.as_ref() {
            validate_transaction_step(
                backend,
                submit,
                prepared.chain_id,
                &signer,
                &deployment.manager,
                &prepared.submit_calldata,
            )?;
        }
        if let Some(finalize) = journal.finalize.as_ref() {
            validate_transaction_step(
                backend,
                finalize,
                prepared.chain_id,
                &signer,
                &deployment.manager,
                &finalize_authorization.calldata,
            )?;
        }
        if let Some(materialize) = journal.materialize.as_ref() {
            validate_transaction_step(
                backend,
                materialize,
                prepared.chain_id,
                &signer,
                &deployment.close_funding_materializer,
                &materialize_calldata,
            )?;
        }
        let stored_submit = journal.submit_observation.as_ref().ok_or_else(|| {
            PublicClosePublisherError::Conflict(
                "completed journal has no exact semantic submit confirmation".into(),
            )
        })?;
        let submit_confirmation = revalidate_semantic_confirmation(
            backend,
            &deployment.manager,
            &prepared.expected,
            stored_submit,
            SemanticCloseEvent::Submitted,
            prepared.chain_id,
            config.allow_unfinalized_devnet,
        )?;
        let stored_finalize = journal.finalize_observation.as_ref().ok_or_else(|| {
            PublicClosePublisherError::Conflict(
                "completed journal has no exact semantic finalize confirmation".into(),
            )
        })?;
        let finalize_confirmation = revalidate_semantic_confirmation(
            backend,
            &deployment.manager,
            &prepared.expected,
            stored_finalize,
            SemanticCloseEvent::Finalized,
            prepared.chain_id,
            config.allow_unfinalized_devnet,
        )?;
        let stored_materialize = journal.materialize_observation.as_ref().ok_or_else(|| {
            PublicClosePublisherError::Conflict(
                "completed journal has no exact semantic materialization confirmation".into(),
            )
        })?;
        let materialize_confirmation = revalidate_materialization_confirmation(
            backend,
            &deployment,
            &prepared,
            stored_materialize,
            config.allow_unfinalized_devnet,
        )?;
        if completed.schema_version != PUBLICATION_VERSION
            || completed.chain_id != prepared.chain_id
            || !same_hex(&completed.rollup, &prepared.rollup)
            || !same_hex(&completed.manager, &deployment.manager)
            || !same_hex(
                &completed.materializer,
                &deployment.close_funding_materializer,
            )
            || completed.channel_id != prepared.channel_id
            || !same_hex(
                &completed.close_intent_digest,
                &prepared.expected.close_intent_digest,
            )
            || completed.artifact_hash != prepared.artifact_hash
            || completed.submit_transaction_hash.as_deref()
                != Some(submit_confirmation.transaction_hash.as_str())
            || completed.finalize_transaction_hash.as_deref()
                != Some(finalize_confirmation.transaction_hash.as_str())
            || !same_hex(
                &completed.materialize_transaction_hash,
                &materialize_confirmation.transaction_hash,
            )
            || !same_hex(
                &completed.attest_transaction_hash,
                &attested_lower_bound(&journal)?.transaction_hash,
            )
        {
            return Err(PublicClosePublisherError::Conflict(
                "completed publication fields differ from semantic confirmations or bundle".into(),
            ));
        }
        // The attestation observation was revalidated on-chain by `advance_attestation` above;
        // the completed close/finalize provenance must still sit strictly after it.
        require_after_attestation(&journal, &submit_confirmation, "CloseSubmitted")?;
        require_after_attestation(&journal, &finalize_confirmation, "CloseFinalized")?;
        let (current, observed, checkpoint) = read_stable_context(
            backend,
            &deployment,
            &prepared,
            config.allow_unfinalized_devnet,
        )?;
        validate_materializer_ready(&current, &observed, &prepared, true)?;
        if current.status != 2
            || !current
                .finalized
                .as_ref()
                .is_some_and(|value| finalized_matches(value, &prepared.expected))
        {
            return Err(PublicClosePublisherError::Evidence(
                "current finalized manager state differs from completed journal".into(),
            ));
        }
        revalidate_finalize_authorization(
            backend,
            &finalize_authorization,
            &prepared.expected,
            &current,
            &checkpoint,
            !journal
                .finalize
                .as_ref()
                .is_some_and(|step| step.superseded_confirmation.is_some()),
        )?;
        checkpoint_advances(&completed.finalized_checkpoint, &checkpoint)
            .map_err(PublicClosePublisherError::Evidence)?;
        release_exact_signer_reservation(&config.signer_lock_root, &submit_reservation)?;
        release_exact_signer_reservation(&config.signer_lock_root, &finalize_reservation)?;
        release_exact_signer_reservation(&config.signer_lock_root, &materialize_reservation)?;
        return Ok(PublicCloseProgress::Complete {
            publication: completed,
        });
    }

    // Permissionless calls may be mined by a watchtower or another participant before our own
    // raw transaction. Adopt only a unique, finalized exact-digest event whose receipt-block and
    // current manager getters reproduce the complete intended state.
    let (semantic_manager, semantic_deployment, semantic_checkpoint) = read_stable_context(
        backend,
        &deployment,
        &prepared,
        config.allow_unfinalized_devnet,
    )?;
    if semantic_manager.status == 1
        && semantic_manager
            .pending
            .as_ref()
            .is_some_and(|pending| pending_matches(pending, &prepared.expected))
    {
        let attested = attested_lower_bound(&journal)?;
        let confirmation = discover_semantic_confirmation(
            backend,
            &deployment,
            &prepared.expected,
            SemanticCloseEvent::Submitted,
            semantic_manager.pending.as_ref(),
            None,
            Some(&attested),
            &semantic_checkpoint,
            config.allow_unfinalized_devnet,
        )?;
        if !journal
            .submit_observation
            .as_ref()
            .is_some_and(|stored| same_semantic_receipt(stored, &confirmation))
        {
            // A cancelled prior era may have emitted the same digest. Replace only with the
            // latest event whose full receipt-block pending vector equals the current manager
            // state; the old semantic receipt remains independently canonical but is no longer
            // authority for this freeze era.
            journal.submit_observation = Some(confirmation.clone());
            write_journal(&config.journal_path, &journal)?;
        }
        if let Some(waiting) = reconcile_semantic_winner(
            config,
            backend,
            &mut journal,
            ClosePhase::Submit,
            &confirmation,
            &submit_reservation,
            &signer,
        )? {
            return Ok(waiting);
        }
    }
    if semantic_manager.status == 2 {
        if !semantic_manager
            .finalized
            .as_ref()
            .is_some_and(|value| finalized_matches(value, &prepared.expected))
        {
            return Err(PublicClosePublisherError::Conflict(
                "manager is Closed with a finalized state different from the exact proof".into(),
            ));
        }
        let attested = attested_lower_bound(&journal)?;
        let final_confirmation = discover_semantic_confirmation(
            backend,
            &deployment,
            &prepared.expected,
            SemanticCloseEvent::Finalized,
            None,
            None,
            Some(&attested),
            &semantic_checkpoint,
            config.allow_unfinalized_devnet,
        )?;
        let attested = attested_lower_bound(&journal)?;
        let current_submit = discover_semantic_confirmation(
            backend,
            &deployment,
            &prepared.expected,
            SemanticCloseEvent::Submitted,
            None,
            Some(&final_confirmation),
            Some(&attested),
            &semantic_checkpoint,
            config.allow_unfinalized_devnet,
        )?;
        if !journal
            .submit_observation
            .as_ref()
            .is_some_and(|stored| same_semantic_receipt(stored, &current_submit))
        {
            journal.submit_observation = Some(current_submit.clone());
            write_journal(&config.journal_path, &journal)?;
        }
        if let Some(waiting) = reconcile_semantic_winner(
            config,
            backend,
            &mut journal,
            ClosePhase::Submit,
            &current_submit,
            &submit_reservation,
            &signer,
        )? {
            return Ok(waiting);
        }
        let finalize_authorization = finalize_authorization_for_semantic_winner(
            config,
            backend,
            &mut journal,
            &prepared.expected,
            &semantic_manager,
            &semantic_checkpoint,
        )?;
        let finalize_reservation = close_signer_reservation(
            prepared.chain_id,
            &signer,
            &config.journal_path,
            &journal.binding,
            "finalize",
            &deployment.manager,
            &finalize_authorization.calldata_hash,
            Some(finalize_authorization.close_request_generation),
        )?;
        journal.finalize_observation = Some(final_confirmation.clone());
        write_journal(&config.journal_path, &journal)?;
        if let Some(waiting) = reconcile_semantic_winner(
            config,
            backend,
            &mut journal,
            ClosePhase::Finalize,
            &final_confirmation,
            &finalize_reservation,
            &signer,
        )? {
            return Ok(waiting);
        }
        return advance_materialization(
            config,
            backend,
            &prepared,
            &deployment,
            &mut journal,
            &signer,
        );
    }

    if semantic_manager.status == 1
        && semantic_manager.pending.is_none()
        && journal.submit_observation.is_some()
    {
        // A finalized prior submission followed by a durable cancellation is not submission
        // authority for the new requested-only era. Do not carry it into finalization. A locally
        // signed/broadcast transaction is retained unless it is the already-finalized old event.
        validate_manager_for_submit(&semantic_manager, &semantic_deployment, &prepared.expected)?;
        if journal.finalize.is_some() {
            return Err(PublicClosePublisherError::Conflict(
                "a prior-era guarded finalizer remains journaled after cancellation; reconcile its signer nonce before re-submission"
                    .into(),
            ));
        }
        let old_observation = journal.submit_observation.as_ref().expect("checked above");
        if journal.submit.as_ref().is_some_and(|step| {
            same_hex(
                &step.transaction.transaction_hash,
                &old_observation.transaction_hash,
            )
        }) {
            // The exact local transaction is finalized and its nonce is consumed, so the single
            // active raw-transaction slot can rotate to this new freeze era.
            journal.submit = None;
            release_exact_signer_reservation(&config.signer_lock_root, &submit_reservation)?;
        }
        journal.submit_observation = None;
        write_journal(&config.journal_path, &journal)?;
    }

    // Recover or confirm a previously fsynced submission before considering any new signature.
    if journal.submit_observation.is_none() {
        if let Some(mut submit) = journal.submit.clone() {
            if submit.superseded_confirmation.is_some() {
                return Err(PublicClosePublisherError::Conflict(
                    "superseded submit has no adopted semantic observation".into(),
                ));
            }
            let submit_needs_reservation = submit.confirmation.is_none();
            if submit_needs_reservation {
                claim_signer_reservation(&config.signer_lock_root, &submit_reservation)?;
            }
            validate_transaction_step(
                backend,
                &submit,
                prepared.chain_id,
                &signer,
                &deployment.manager,
                &prepared.submit_calldata,
            )?;
            match step_receipt(
                backend,
                &submit,
                &signer,
                prepared.chain_id,
                config.allow_unfinalized_devnet,
            )? {
                ReceiptState::Missing if submit.confirmation.is_none() => {
                    let (manager, observed_deployment, checkpoint) = read_stable_context(
                        backend,
                        &deployment,
                        &prepared,
                        config.allow_unfinalized_devnet,
                    )?;
                    if let Some(waiting) = validate_manager_for_submit(
                        &manager,
                        &observed_deployment,
                        &prepared.expected,
                    )? {
                        return Ok(waiting);
                    }
                    if manager
                        .pending
                        .as_ref()
                        .is_some_and(|pending| pending_matches(pending, &prepared.expected))
                    {
                        let attested = attested_lower_bound(&journal)?;
                        let confirmation = discover_semantic_confirmation(
                            backend,
                            &deployment,
                            &prepared.expected,
                            SemanticCloseEvent::Submitted,
                            manager.pending.as_ref(),
                            None,
                            Some(&attested),
                            &checkpoint,
                            config.allow_unfinalized_devnet,
                        )?;
                        let hash = confirmation.transaction_hash.clone();
                        journal.submit_observation = Some(confirmation.clone());
                        write_journal(&config.journal_path, &journal)?;
                        if let Some(waiting) = reconcile_semantic_winner(
                            config,
                            backend,
                            &mut journal,
                            ClosePhase::Submit,
                            &confirmation,
                            &submit_reservation,
                            &signer,
                        )? {
                            return Ok(waiting);
                        }
                        return Ok(PublicCloseProgress::SubmitAdopted {
                            transaction_hash: hash,
                        });
                    }
                    let broadcast = publish_exact_raw(backend, &signer, &submit.transaction)?;
                    return Ok(if broadcast {
                        PublicCloseProgress::SubmitBroadcast {
                            transaction_hash: submit.transaction.transaction_hash,
                        }
                    } else {
                        PublicCloseProgress::AwaitingSubmitReceipt {
                            transaction_hash: submit.transaction.transaction_hash,
                        }
                    });
                }
                ReceiptState::Mined { block_number } if submit.confirmation.is_none() => {
                    return Ok(PublicCloseProgress::AwaitingSubmitFinality {
                        transaction_hash: submit.transaction.transaction_hash,
                        receipt_block: block_number,
                    });
                }
                ReceiptState::Finalized {
                    receipt,
                    confirmation,
                } => {
                    let at_receipt =
                        observation_at_receipt(backend, &deployment.manager, &confirmation)?;
                    let pending = at_receipt.pending.as_ref().ok_or_else(|| {
                        PublicClosePublisherError::Evidence(
                            "submit receipt block does not expose an active pending close".into(),
                        )
                    })?;
                    if at_receipt.status != 1 || !pending_matches(pending, &prepared.expected) {
                        return Err(PublicClosePublisherError::Evidence(
                            "submit receipt block manager getters differ from the proof".into(),
                        ));
                    }
                    validate_close_submitted_event(&receipt, &deployment.manager, pending)?;
                    require_after_attestation(&journal, &confirmation, "CloseSubmitted")?;
                    submit.confirmation = Some(confirmation.clone());
                    journal.submit = Some(submit);
                    journal.submit_observation = Some(confirmation);
                    write_journal(&config.journal_path, &journal)?;
                    if submit_needs_reservation {
                        release_signer_reservation(&config.signer_lock_root, &submit_reservation)?;
                    } else {
                        release_exact_signer_reservation(
                            &config.signer_lock_root,
                            &submit_reservation,
                        )?;
                    }
                }
                ReceiptState::Missing | ReceiptState::Mined { .. } => {
                    return Err(PublicClosePublisherError::Evidence(
                        "stored submit confirmation lost canonical finality".into(),
                    ));
                }
            }
        }
    }

    let (manager, observed_deployment, manager_checkpoint) = read_stable_context(
        backend,
        &deployment,
        &prepared,
        config.allow_unfinalized_devnet,
    )?;
    if journal.submit_observation.is_none() && journal.submit.is_none() {
        if let Some(waiting) =
            validate_manager_for_submit(&manager, &observed_deployment, &prepared.expected)?
        {
            return Ok(waiting);
        }
        if manager
            .pending
            .as_ref()
            .is_some_and(|pending| pending_matches(pending, &prepared.expected))
        {
            let attested = attested_lower_bound(&journal)?;
            let confirmation = discover_semantic_confirmation(
                backend,
                &deployment,
                &prepared.expected,
                SemanticCloseEvent::Submitted,
                manager.pending.as_ref(),
                None,
                Some(&attested),
                &manager_checkpoint,
                config.allow_unfinalized_devnet,
            )?;
            let hash = confirmation.transaction_hash.clone();
            journal.submit_observation = Some(confirmation.clone());
            write_journal(&config.journal_path, &journal)?;
            if let Some(waiting) = reconcile_semantic_winner(
                config,
                backend,
                &mut journal,
                ClosePhase::Submit,
                &confirmation,
                &submit_reservation,
                &signer,
            )? {
                return Ok(waiting);
            }
            return Ok(PublicCloseProgress::SubmitAdopted {
                transaction_hash: hash,
            });
        }
        let transaction =
            sign_after_reservation(&config.signer_lock_root, &submit_reservation, || {
                backend.sign_transaction(
                    config.account.trim(),
                    prepared.chain_id,
                    &signer,
                    &deployment.manager,
                    &prepared.submit_calldata,
                )
            })?;
        let inspected = backend.inspect_signed_transaction(
            &transaction.raw_signed_transaction,
            prepared.chain_id,
            &signer,
            &deployment.manager,
            &prepared.submit_calldata,
        )?;
        if inspected != transaction {
            return Err(PublicClosePublisherError::Evidence(
                "signer returned transaction metadata inconsistent with raw bytes".into(),
            ));
        }
        journal.submit = Some(TransactionStep {
            transaction: transaction.clone(),
            confirmation: None,
            superseded_confirmation: None,
        });
        // Critical WAL boundary: exact raw bytes are durable before publication.
        write_journal(&config.journal_path, &journal)?;
        let (fresh, fresh_deployment, fresh_checkpoint) = read_stable_context(
            backend,
            &deployment,
            &prepared,
            config.allow_unfinalized_devnet,
        )?;
        if let Some(waiting) =
            validate_manager_for_submit(&fresh, &fresh_deployment, &prepared.expected)?
        {
            return Ok(waiting);
        }
        if fresh
            .pending
            .as_ref()
            .is_some_and(|pending| pending_matches(pending, &prepared.expected))
        {
            let attested = attested_lower_bound(&journal)?;
            let confirmation = discover_semantic_confirmation(
                backend,
                &deployment,
                &prepared.expected,
                SemanticCloseEvent::Submitted,
                fresh.pending.as_ref(),
                None,
                Some(&attested),
                &fresh_checkpoint,
                config.allow_unfinalized_devnet,
            )?;
            let hash = confirmation.transaction_hash.clone();
            journal.submit_observation = Some(confirmation.clone());
            write_journal(&config.journal_path, &journal)?;
            if let Some(waiting) = reconcile_semantic_winner(
                config,
                backend,
                &mut journal,
                ClosePhase::Submit,
                &confirmation,
                &submit_reservation,
                &signer,
            )? {
                return Ok(waiting);
            }
            return Ok(PublicCloseProgress::SubmitAdopted {
                transaction_hash: hash,
            });
        }
        publish_exact_raw(backend, &signer, &transaction)?;
        return Ok(PublicCloseProgress::SubmitBroadcast {
            transaction_hash: transaction.transaction_hash,
        });
    }

    // A finalized submission receipt is mandatory before the permissionless finalization step.
    if journal.submit_observation.is_none() {
        return Err(PublicClosePublisherError::Evidence(
            "submit step reached finalization without a finalized confirmation".into(),
        ));
    }

    if let Some(mut finalize) = journal.finalize.clone() {
        let finalize_authorization = stored_finalize_authorization(&journal, &prepared.expected)?;
        let finalize_reservation = close_signer_reservation(
            prepared.chain_id,
            &signer,
            &config.journal_path,
            &journal.binding,
            "finalize",
            &deployment.manager,
            &finalize_authorization.calldata_hash,
            Some(finalize_authorization.close_request_generation),
        )?;
        if finalize.superseded_confirmation.is_some() && journal.finalize_observation.is_none() {
            return Err(PublicClosePublisherError::Conflict(
                "superseded finalizer has no adopted semantic observation".into(),
            ));
        }
        let finalize_needs_reservation =
            finalize.confirmation.is_none() && finalize.superseded_confirmation.is_none();
        if finalize_needs_reservation {
            claim_signer_reservation(&config.signer_lock_root, &finalize_reservation)?;
        }
        validate_transaction_step(
            backend,
            &finalize,
            prepared.chain_id,
            &signer,
            &deployment.manager,
            &finalize_authorization.calldata,
        )?;
        match step_receipt(
            backend,
            &finalize,
            &signer,
            prepared.chain_id,
            config.allow_unfinalized_devnet,
        )? {
            ReceiptState::Missing if finalize.confirmation.is_none() => {
                let (current, _, checkpoint) = read_stable_context(
                    backend,
                    &deployment,
                    &prepared,
                    config.allow_unfinalized_devnet,
                )?;
                if current.status == 2 {
                    if !current
                        .finalized
                        .as_ref()
                        .is_some_and(|value| finalized_matches(value, &prepared.expected))
                    {
                        return Err(PublicClosePublisherError::Conflict(
                            "permissionless finalizer closed a different state".into(),
                        ));
                    }
                    let attested = attested_lower_bound(&journal)?;
                    let confirmation = discover_semantic_confirmation(
                        backend,
                        &deployment,
                        &prepared.expected,
                        SemanticCloseEvent::Finalized,
                        None,
                        None,
                        Some(&attested),
                        &checkpoint,
                        config.allow_unfinalized_devnet,
                    )?;
                    journal.finalize_observation = Some(confirmation.clone());
                    write_journal(&config.journal_path, &journal)?;
                    if let Some(waiting) = reconcile_semantic_winner(
                        config,
                        backend,
                        &mut journal,
                        ClosePhase::Finalize,
                        &confirmation,
                        &finalize_reservation,
                        &signer,
                    )? {
                        return Ok(waiting);
                    }
                    return advance_materialization(
                        config,
                        backend,
                        &prepared,
                        &deployment,
                        &mut journal,
                        &signer,
                    );
                }
                revalidate_finalize_authorization(
                    backend,
                    &finalize_authorization,
                    &prepared.expected,
                    &current,
                    &checkpoint,
                    true,
                )?;
                if let Some(waiting) = validate_manager_for_finalize(
                    &current,
                    &prepared.expected,
                    finalize_authorization.close_request_generation,
                )? {
                    return Ok(waiting);
                }
                let broadcast = publish_exact_raw(backend, &signer, &finalize.transaction)?;
                return Ok(if broadcast {
                    PublicCloseProgress::FinalizeBroadcast {
                        transaction_hash: finalize.transaction.transaction_hash,
                    }
                } else {
                    PublicCloseProgress::AwaitingFinalizeReceipt {
                        transaction_hash: finalize.transaction.transaction_hash,
                    }
                });
            }
            ReceiptState::Mined { block_number } if finalize.confirmation.is_none() => {
                return Ok(PublicCloseProgress::AwaitingFinalizeFinality {
                    transaction_hash: finalize.transaction.transaction_hash,
                    receipt_block: block_number,
                });
            }
            ReceiptState::Finalized {
                receipt,
                confirmation,
            } => {
                validate_close_finalized_event(&receipt, &deployment.manager, &prepared.expected)?;
                let at_receipt =
                    observation_at_receipt(backend, &deployment.manager, &confirmation)?;
                if at_receipt.status != 2
                    || at_receipt.close_request_generation
                        != finalize_authorization.close_request_generation
                    || !at_receipt
                        .finalized
                        .as_ref()
                        .is_some_and(|value| finalized_matches(value, &prepared.expected))
                {
                    return Err(PublicClosePublisherError::Evidence(
                        "finalize receipt block getters differ from the exact close".into(),
                    ));
                }
                finalize.confirmation = Some(confirmation.clone());
                journal.finalize = Some(finalize);
                journal.finalize_observation = Some(confirmation);
                write_journal(&config.journal_path, &journal)?;
                if finalize_needs_reservation {
                    release_signer_reservation(&config.signer_lock_root, &finalize_reservation)?;
                } else {
                    release_exact_signer_reservation(
                        &config.signer_lock_root,
                        &finalize_reservation,
                    )?;
                }
                return advance_materialization(
                    config,
                    backend,
                    &prepared,
                    &deployment,
                    &mut journal,
                    &signer,
                );
            }
            ReceiptState::Missing | ReceiptState::Mined { .. } => {
                return Err(PublicClosePublisherError::Evidence(
                    "stored finalize confirmation lost canonical finality".into(),
                ));
            }
        }
    }

    let (current, _, current_checkpoint) = read_stable_context(
        backend,
        &deployment,
        &prepared,
        config.allow_unfinalized_devnet,
    )?;
    if current.status == 2 {
        if !current
            .finalized
            .as_ref()
            .is_some_and(|value| finalized_matches(value, &prepared.expected))
        {
            return Err(PublicClosePublisherError::Conflict(
                "permissionless finalizer closed a different state".into(),
            ));
        }
        let attested = attested_lower_bound(&journal)?;
        let confirmation = discover_semantic_confirmation(
            backend,
            &deployment,
            &prepared.expected,
            SemanticCloseEvent::Finalized,
            None,
            None,
            Some(&attested),
            &current_checkpoint,
            config.allow_unfinalized_devnet,
        )?;
        let finalize_authorization = finalize_authorization_for_semantic_winner(
            config,
            backend,
            &mut journal,
            &prepared.expected,
            &current,
            &current_checkpoint,
        )?;
        let finalize_reservation = close_signer_reservation(
            prepared.chain_id,
            &signer,
            &config.journal_path,
            &journal.binding,
            "finalize",
            &deployment.manager,
            &finalize_authorization.calldata_hash,
            Some(finalize_authorization.close_request_generation),
        )?;
        journal.finalize_observation = Some(confirmation.clone());
        write_journal(&config.journal_path, &journal)?;
        if let Some(waiting) = reconcile_semantic_winner(
            config,
            backend,
            &mut journal,
            ClosePhase::Finalize,
            &confirmation,
            &finalize_reservation,
            &signer,
        )? {
            return Ok(waiting);
        }
        return advance_materialization(
            config,
            backend,
            &prepared,
            &deployment,
            &mut journal,
            &signer,
        );
    }
    if let Some(waiting) = validate_manager_for_finalize(
        &current,
        &prepared.expected,
        current.close_request_generation,
    )? {
        return Ok(waiting);
    }
    let finalize_authorization = pin_finalize_authorization(
        config,
        &mut journal,
        &prepared.expected,
        &current,
        &current_checkpoint,
    )?;
    let finalize_reservation = close_signer_reservation(
        prepared.chain_id,
        &signer,
        &config.journal_path,
        &journal.binding,
        "finalize",
        &deployment.manager,
        &finalize_authorization.calldata_hash,
        Some(finalize_authorization.close_request_generation),
    )?;
    // A durable authorization is not a license to sign later. Re-read the canonical durable head
    // and every manager field immediately before opening the encrypted signer, then require the
    // monotone generation and exact pending close to remain unchanged.
    let (pre_sign, _, pre_sign_checkpoint) = read_stable_context(
        backend,
        &deployment,
        &prepared,
        config.allow_unfinalized_devnet,
    )?;
    revalidate_finalize_authorization(
        backend,
        &finalize_authorization,
        &prepared.expected,
        &pre_sign,
        &pre_sign_checkpoint,
        true,
    )?;
    if let Some(waiting) = validate_manager_for_finalize(
        &pre_sign,
        &prepared.expected,
        finalize_authorization.close_request_generation,
    )? {
        return Ok(waiting);
    }
    let transaction =
        sign_after_reservation(&config.signer_lock_root, &finalize_reservation, || {
            backend.sign_transaction(
                config.account.trim(),
                prepared.chain_id,
                &signer,
                &deployment.manager,
                &finalize_authorization.calldata,
            )
        })?;
    let inspected = backend.inspect_signed_transaction(
        &transaction.raw_signed_transaction,
        prepared.chain_id,
        &signer,
        &deployment.manager,
        &finalize_authorization.calldata,
    )?;
    if inspected != transaction {
        return Err(PublicClosePublisherError::Evidence(
            "finalize signer returned metadata inconsistent with raw bytes".into(),
        ));
    }
    journal.finalize = Some(TransactionStep {
        transaction: transaction.clone(),
        confirmation: None,
        superseded_confirmation: None,
    });
    write_journal(&config.journal_path, &journal)?;
    // The guarded selector is load-bearing: even if a newer close races this read, the contract
    // reverts instead of finalizing a sibling digest.
    let (fresh, _, fresh_checkpoint) = read_stable_context(
        backend,
        &deployment,
        &prepared,
        config.allow_unfinalized_devnet,
    )?;
    if fresh.status == 2 {
        if !fresh
            .finalized
            .as_ref()
            .is_some_and(|value| finalized_matches(value, &prepared.expected))
        {
            return Err(PublicClosePublisherError::Conflict(
                "permissionless finalizer raced with a different state".into(),
            ));
        }
        let attested = attested_lower_bound(&journal)?;
        let confirmation = discover_semantic_confirmation(
            backend,
            &deployment,
            &prepared.expected,
            SemanticCloseEvent::Finalized,
            None,
            None,
            Some(&attested),
            &fresh_checkpoint,
            config.allow_unfinalized_devnet,
        )?;
        journal.finalize_observation = Some(confirmation.clone());
        write_journal(&config.journal_path, &journal)?;
        if let Some(waiting) = reconcile_semantic_winner(
            config,
            backend,
            &mut journal,
            ClosePhase::Finalize,
            &confirmation,
            &finalize_reservation,
            &signer,
        )? {
            return Ok(waiting);
        }
        return advance_materialization(
            config,
            backend,
            &prepared,
            &deployment,
            &mut journal,
            &signer,
        );
    }
    revalidate_finalize_authorization(
        backend,
        &finalize_authorization,
        &prepared.expected,
        &fresh,
        &fresh_checkpoint,
        true,
    )?;
    if let Some(waiting) = validate_manager_for_finalize(
        &fresh,
        &prepared.expected,
        finalize_authorization.close_request_generation,
    )? {
        return Ok(waiting);
    }
    publish_exact_raw(backend, &signer, &transaction)?;
    Ok(PublicCloseProgress::FinalizeBroadcast {
        transaction_hash: transaction.transaction_hash,
    })
}

struct CastCloseBackend {
    rpc_url: String,
}

impl CastCloseBackend {
    fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
        }
    }

    fn output(&self, args: &[&str], what: &str, maximum: usize) -> Result<String> {
        let mut command = Command::new("cast");
        command.args(args);
        checked_output(command, what, maximum)
    }

    fn rpc_block(&self, tag: &str) -> Result<Value> {
        let output = self.output(
            &[
                "rpc",
                "eth_getBlockByNumber",
                tag,
                "false",
                "--rpc-url",
                &self.rpc_url,
            ],
            &format!("read L1 block {tag}"),
            MAX_RPC_JSON_BYTES,
        )?;
        let value: Value = serde_json::from_str(output.trim()).map_err(|error| {
            PublicClosePublisherError::Evidence(format!("parse L1 block {tag}: {error}"))
        })?;
        if !value.is_object() {
            return Err(PublicClosePublisherError::Evidence(format!(
                "L1 block {tag} is null or not an object"
            )));
        }
        Ok(value)
    }

    fn parse_block(&self, value: &Value) -> Result<BlockObservation> {
        let string = |name: &str| {
            value.get(name).and_then(Value::as_str).ok_or_else(|| {
                PublicClosePublisherError::Evidence(format!("block has no string {name}"))
            })
        };
        let number = quantity_u64(string("number")?, "block number")
            .map_err(PublicClosePublisherError::Evidence)?;
        let hash = normalize_hex(string("hash")?, 32, "block hash")
            .map_err(PublicClosePublisherError::Evidence)?
            .parse::<Bytes32>()
            .map_err(|error| PublicClosePublisherError::Evidence(format!("block hash: {error}")))?;
        let parent_hash = normalize_hex(string("parentHash")?, 32, "block parentHash")
            .map_err(PublicClosePublisherError::Evidence)?
            .parse::<Bytes32>()
            .map_err(|error| {
                PublicClosePublisherError::Evidence(format!("block parent hash: {error}"))
            })?;
        let timestamp = quantity_u64(string("timestamp")?, "block timestamp")
            .map_err(PublicClosePublisherError::Evidence)?;
        Ok(BlockObservation {
            number,
            hash,
            parent_hash,
            timestamp,
        })
    }

    fn call_raw(&self, target: &str, calldata: &str, block_number: u64) -> Result<Vec<u8>> {
        let block = format!("0x{block_number:x}");
        let output = self.output(
            &[
                "call",
                target,
                "--data",
                calldata,
                "--block",
                &block,
                "--rpc-url",
                &self.rpc_url,
            ],
            "read pinned contract view",
            MAX_RPC_JSON_BYTES,
        )?;
        decode_hex(output.trim(), None, "eth_call result")
            .map_err(PublicClosePublisherError::Evidence)
    }

    fn noarg(&self, target: &str, signature: &str, block_number: u64) -> Result<Vec<u8>> {
        self.call_raw(target, &selector(signature), block_number)
    }

    fn one_uint(
        &self,
        target: &str,
        name: &str,
        bits: usize,
        value: u64,
        block_number: u64,
    ) -> Result<Vec<u8>> {
        let kind = AbiKind::Uint(bits);
        let value = Value::String(value.to_string());
        let calldata = encode_function(name, &[(&kind, &value, "argument")])
            .map_err(PublicClosePublisherError::Evidence)?;
        self.call_raw(target, &calldata, block_number)
    }

    fn one_bytes32(
        &self,
        target: &str,
        name: &str,
        value: &str,
        block_number: u64,
    ) -> Result<Vec<u8>> {
        let kind = AbiKind::FixedBytes(32);
        let value = Value::String(value.to_string());
        let calldata = encode_function(name, &[(&kind, &value, "argument")])
            .map_err(PublicClosePublisherError::Evidence)?;
        self.call_raw(target, &calldata, block_number)
    }

    fn one_word(&self, target: &str, signature: &str, block_number: u64) -> Result<[u8; 32]> {
        let raw = self.noarg(target, signature, block_number)?;
        if raw.len() != 32 {
            return Err(PublicClosePublisherError::Evidence(format!(
                "{signature} returned {} bytes; expected one ABI word",
                raw.len()
            )));
        }
        Ok(raw.try_into().expect("length checked"))
    }

    fn runtime_code_hash(&self, address: &str, block_number: u64) -> Result<String> {
        let block = format!("0x{block_number:x}");
        let output = self.output(
            &[
                "code",
                address,
                "--block",
                &block,
                "--rpc-url",
                &self.rpc_url,
            ],
            "read deployed runtime code",
            MAX_RPC_JSON_BYTES,
        )?;
        let bytes = decode_hex(output.trim(), None, "runtime code")
            .map_err(PublicClosePublisherError::Evidence)?;
        if bytes.is_empty() {
            return Err(PublicClosePublisherError::Deployment(format!(
                "no runtime code at {address}"
            )));
        }
        Ok(keccak_hex(&bytes))
    }

    fn observe_mle_verifier(
        &self,
        adapter: &str,
        block_number: u64,
    ) -> Result<ObservedMleVerifier> {
        let core = word_address(
            &self.one_word(adapter, "core()", block_number)?,
            "MLE adapter.core",
        )?;
        let protocol_first =
            word_bytes32(&self.one_word(&core, "whirProtocolIdFirst()", block_number)?);
        let protocol_second =
            word_bytes32(&self.one_word(&core, "whirProtocolIdSecond()", block_number)?);
        Ok(ObservedMleVerifier {
            adapter: adapter.to_ascii_lowercase(),
            adapter_runtime_code_hash: self.runtime_code_hash(adapter, block_number)?,
            core: core.clone(),
            core_runtime_code_hash: self.runtime_code_hash(&core, block_number)?,
            verification_config_digest: word_bytes32(&self.one_word(
                &core,
                "verificationConfigDigest()",
                block_number,
            )?),
            circuit_config_digest: word_bytes32(&self.one_word(
                &core,
                "circuitConfigDigest()",
                block_number,
            )?),
            whir_parameters_digest: word_bytes32(&self.one_word(
                &core,
                "whirParametersDigest()",
                block_number,
            )?),
            whir_protocol_id: format!(
                "0x{}{}",
                protocol_first.trim_start_matches("0x"),
                protocol_second.trim_start_matches("0x")
            ),
            whir_session_id: word_bytes32(&self.one_word(
                &core,
                "whirSessionId()",
                block_number,
            )?),
            adapter_allowed_chain_id: word_uint(
                &self.one_word(adapter, "allowedChainId()", block_number)?,
                8,
                "MLE adapter allowedChainId",
            )?,
            core_allowed_chain_id: word_uint(
                &self.one_word(&core, "allowedChainId()", block_number)?,
                8,
                "MLE core allowedChainId",
            )?,
        })
    }
}

fn checked_output(mut command: Command, what: &str, maximum: usize) -> Result<String> {
    let output = command
        .output()
        .map_err(|error| PublicClosePublisherError::Command(format!("start {what}: {error}")))?;
    if !output.status.success() {
        return Err(PublicClosePublisherError::Command(format!(
            "{what} returned {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    if output.stdout.len() > maximum {
        return Err(PublicClosePublisherError::Command(format!(
            "{what} output exceeds {maximum} bytes"
        )));
    }
    String::from_utf8(output.stdout).map_err(|error| {
        PublicClosePublisherError::Command(format!("{what} output is not UTF-8: {error}"))
    })
}

fn word_bool(word: &[u8; 32], what: &str) -> Result<bool> {
    if word[..31] != [0u8; 31] || word[31] > 1 {
        return Err(PublicClosePublisherError::Evidence(format!(
            "{what} is not a canonical ABI bool"
        )));
    }
    Ok(word[31] == 1)
}

fn word_uint(word: &[u8; 32], bytes: usize, what: &str) -> Result<u64> {
    if bytes == 0 || bytes > 8 || word[..32 - bytes] != vec![0u8; 32 - bytes] {
        return Err(PublicClosePublisherError::Evidence(format!(
            "{what} is not a canonical uint{}",
            bytes * 8
        )));
    }
    let mut tail = [0u8; 8];
    tail[8 - bytes..].copy_from_slice(&word[32 - bytes..]);
    Ok(u64::from_be_bytes(tail))
}

fn word_address(word: &[u8; 32], what: &str) -> Result<String> {
    if word[..12] != [0u8; 12] || word[12..] == [0u8; 20] {
        return Err(PublicClosePublisherError::Evidence(format!(
            "{what} is not a nonzero ABI address"
        )));
    }
    Ok(format!("0x{}", hex::encode(&word[12..])))
}

fn word_bytes32(word: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(word))
}

fn decode_words(raw: &[u8], expected: usize, what: &str) -> Result<Vec<[u8; 32]>> {
    if raw.len() != expected * 32 {
        return Err(PublicClosePublisherError::Evidence(format!(
            "{what} returned {} ABI words; expected {expected}",
            raw.len() / 32
        )));
    }
    Ok(raw
        .chunks_exact(32)
        .map(|word| word.try_into().expect("chunk size"))
        .collect())
}

fn decode_signed_transaction(raw: &str) -> Result<Value> {
    let raw = raw.trim();
    if raw.len() < 4
        || raw.len() > MAX_RAW_TRANSACTION_CHARS
        || !raw.starts_with("0x")
        || !raw[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(PublicClosePublisherError::Evidence(
            "signed transaction is malformed or oversized".into(),
        ));
    }
    let mut child = Command::new("cast")
        .args(["decode-transaction", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            PublicClosePublisherError::Command(format!("start cast decode-transaction: {error}"))
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| PublicClosePublisherError::Command("decoder stdin missing".into()))?
        .write_all(raw.as_bytes())
        .map_err(|error| {
            PublicClosePublisherError::Command(format!("write decoder stdin: {error}"))
        })?;
    let output = child.wait_with_output().map_err(|error| {
        PublicClosePublisherError::Command(format!("wait for transaction decoder: {error}"))
    })?;
    if !output.status.success() || output.stdout.len() > MAX_RPC_JSON_BYTES {
        return Err(PublicClosePublisherError::Evidence(format!(
            "cast rejected signed transaction: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        PublicClosePublisherError::Evidence(format!("parse decoded transaction: {error}"))
    })
}

fn validate_decoded_transaction(
    decoded: &Value,
    chain_id: u64,
    signer: &str,
    target: &str,
    calldata: &str,
) -> Result<(String, u64)> {
    let field = |name: &str| {
        decoded.get(name).and_then(Value::as_str).ok_or_else(|| {
            PublicClosePublisherError::Evidence(format!("decoded transaction has no string {name}"))
        })
    };
    if quantity_u64(field("chainId")?, "transaction chainId")
        .map_err(PublicClosePublisherError::Evidence)?
        != chain_id
        || !same_hex(field("signer")?, signer)
        || !same_hex(field("to")?, target)
        || quantity_big(field("value")?, "transaction value")
            .map_err(PublicClosePublisherError::Evidence)?
            != BigUint::from(0u8)
        || !same_hex(field("input")?, calldata)
    {
        return Err(PublicClosePublisherError::Evidence(
            "signed transaction chain/signer/target/value/calldata differs from request".into(),
        ));
    }
    let transaction_type = field("type")?;
    if transaction_type == "0x3" || transaction_type == "0x03" {
        return Err(PublicClosePublisherError::Evidence(
            "close publisher unexpectedly produced a blob transaction".into(),
        ));
    }
    let hash = normalize_hex(field("hash")?, 32, "transaction hash")
        .map_err(PublicClosePublisherError::Evidence)?;
    let nonce = quantity_u64(field("nonce")?, "transaction nonce")
        .map_err(PublicClosePublisherError::Evidence)?;
    Ok((hash, nonce))
}

impl ClosePublisherBackend for CastCloseBackend {
    fn chain_id(&mut self) -> Result<u64> {
        let output = self.output(
            &["chain-id", "--rpc-url", &self.rpc_url],
            "read L1 chain id",
            4096,
        )?;
        quantity_u64(output.trim(), "L1 chain id").map_err(PublicClosePublisherError::Evidence)
    }

    fn signer_address(&mut self, account: &str) -> Result<String> {
        let output = self.output(
            &["wallet", "address", "--account", account],
            "resolve encrypted-keystore signer",
            4096,
        )?;
        normalize_hex(output.trim(), 20, "signer address")
            .map_err(PublicClosePublisherError::Command)
    }

    fn durable_checkpoint(
        &mut self,
        allow_unfinalized_devnet: bool,
    ) -> Result<L1FinalizedCheckpoint> {
        let chain_id = self.chain_id()?;
        let (block, source) = match self.rpc_block("finalized") {
            Ok(block) => (block, L1FinalitySource::RpcFinalized),
            Err(error) if chain_id == ANVIL_CHAIN_ID && allow_unfinalized_devnet => {
                let _ = error;
                (self.rpc_block("latest")?, L1FinalitySource::DevnetLatest)
            }
            Err(error) => return Err(error),
        };
        let block = self.parse_block(&block)?;
        let checkpoint = L1FinalizedCheckpoint {
            chain_id,
            block_number: block.number,
            block_hash: block.hash,
            parent_hash: block.parent_hash,
            source,
        };
        checkpoint
            .validate()
            .map_err(PublicClosePublisherError::Evidence)?;
        Ok(checkpoint)
    }

    fn block_at(&mut self, number: u64, _source: L1FinalitySource) -> Result<BlockObservation> {
        self.parse_block(&self.rpc_block(&format!("0x{number:x}"))?)
    }

    fn observe_deployment(
        &mut self,
        manifest: &DeploymentManifest,
        prepared: &PreparedClose,
        block_number: u64,
    ) -> Result<ObservedDeployment> {
        let attestation = backing_attestation_identity(prepared, manifest)?;
        let manager_registry = word_address(
            &self.one_word(&manifest.manager, "registry()", block_number)?,
            "manager.registry",
        )?;
        let manager_verifier = word_address(
            &self.one_word(&manifest.manager, "verifier()", block_number)?,
            "manager.verifier",
        )?;
        let manager_close_funding_materializer = word_address(
            &self.one_word(
                &manifest.manager,
                "closeFundingMaterializer()",
                block_number,
            )?,
            "manager.closeFundingMaterializer",
        )?;
        let materializer_rollup = word_address(
            &self.one_word(
                &manifest.close_funding_materializer,
                "rollup()",
                block_number,
            )?,
            "materializer.rollup",
        )?;
        let backing_mle_verifier = word_address(
            &self.one_word(
                &manifest.close_funding_materializer,
                "backingMleVerifier()",
                block_number,
            )?,
            "materializer.backingMleVerifier",
        )?;
        let channel_word = self.one_word(&manifest.manager, "channelId()", block_number)?;
        if channel_word[4..] != [0u8; 28] {
            return Err(PublicClosePublisherError::Evidence(
                "manager.channelId is not canonical bytes4".into(),
            ));
        }
        let channel_id = u32::from_be_bytes(channel_word[..4].try_into().expect("four bytes"));
        let materializer_manager_of_channel = word_address(
            &decode_words(
                &self.one_uint(
                    &manifest.close_funding_materializer,
                    "managerOfChannel",
                    32,
                    u64::from(channel_id),
                    block_number,
                )?,
                1,
                "materializer.managerOfChannel",
            )?[0],
            "materializer.managerOfChannel",
        )?;
        let close_mle_verifier = word_address(
            &self.one_word(
                &manifest.settlement_verifier,
                "closeMleVerifier()",
                block_number,
            )?,
            "settlementVerifier.closeMleVerifier",
        )?;
        let signed_head_backing_anchor_plus_one = word_uint(
            &decode_words(
                &self.one_bytes32(
                    &manifest.close_funding_materializer,
                    "signedHeadBackingAnchorPlusOne",
                    &attestation.statement_key,
                    block_number,
                )?,
                1,
                "materializer.signedHeadBackingAnchorPlusOne",
            )?[0],
            8,
            "materializer.signedHeadBackingAnchorPlusOne",
        )?;
        let exact_backing_proof_attested = word_bool(
            &decode_words(
                &self.one_bytes32(
                    &manifest.close_funding_materializer,
                    "attestedBackingProof",
                    &attestation.proof_id,
                    block_number,
                )?,
                1,
                "materializer.attestedBackingProof",
            )?[0],
            "materializer.attestedBackingProof",
        )?;
        let address_kind = AbiKind::Address;
        let channel_kind = AbiKind::Uint(32);
        let digest_kind = AbiKind::FixedBytes(32);
        let bool_kind = AbiKind::Bool;
        let manager_value = Value::String(manifest.manager.clone());
        let channel_value = Value::String(prepared.channel_id.to_string());
        let settled_value = Value::String(prepared.expected.final_settled_tx_chain.clone());
        let funds_value = Value::String(prepared.expected.token_funds_digest.clone());
        let require_current = Value::Bool(true);
        let current_calldata = encode_function(
            "hasSignedHeadBacking",
            &[
                (&address_kind, &manager_value, "manager"),
                (&channel_kind, &channel_value, "channelId"),
                (&digest_kind, &settled_value, "settledTxChain"),
                (&digest_kind, &funds_value, "tokenFundsDigest"),
                (&bool_kind, &require_current, "requireCurrent"),
            ],
        )
        .map_err(PublicClosePublisherError::Evidence)?;
        let signed_head_backing_current = word_bool(
            &decode_words(
                &self.call_raw(
                    &manifest.close_funding_materializer,
                    &current_calldata,
                    block_number,
                )?,
                1,
                "materializer.hasSignedHeadBacking",
            )?[0],
            "materializer.hasSignedHeadBacking",
        )?;
        let withdrawal_claim_mle_verifier = word_address(
            &self.one_word(
                &manifest.settlement_verifier,
                "withdrawalClaimMleVerifier()",
                block_number,
            )?,
            "settlementVerifier.withdrawalClaimMleVerifier",
        )?;
        let post_close_claim_mle_verifier = word_address(
            &self.one_word(
                &manifest.settlement_verifier,
                "postCloseClaimMleVerifier()",
                block_number,
            )?,
            "settlementVerifier.postCloseClaimMleVerifier",
        )?;
        let cancel_close_mle_verifier = word_address(
            &self.one_word(
                &manifest.settlement_verifier,
                "cancelCloseMleVerifier()",
                block_number,
            )?,
            "settlementVerifier.cancelCloseMleVerifier",
        )?;
        Ok(ObservedDeployment {
            rollup_runtime_code_hash: self.runtime_code_hash(&manifest.rollup, block_number)?,
            manager_runtime_code_hash: self.runtime_code_hash(&manifest.manager, block_number)?,
            close_funding_materializer_runtime_code_hash: self
                .runtime_code_hash(&manifest.close_funding_materializer, block_number)?,
            settlement_verifier_runtime_code_hash: self
                .runtime_code_hash(&manifest.settlement_verifier, block_number)?,
            manager_registry,
            manager_verifier,
            manager_close_funding_materializer,
            materializer_rollup,
            materializer_manager_of_channel,
            materializer_frozen_generation: word_uint(
                &decode_words(
                    &self.one_uint(
                        &manifest.close_funding_materializer,
                        "frozenGeneration",
                        32,
                        u64::from(channel_id),
                        block_number,
                    )?,
                    1,
                    "materializer.frozenGeneration",
                )?[0],
                8,
                "materializer.frozenGeneration",
            )?,
            materializer_last_posted_block: word_uint(
                &decode_words(
                    &self.one_uint(
                        &manifest.close_funding_materializer,
                        "lastPostedBlock",
                        32,
                        u64::from(channel_id),
                        block_number,
                    )?,
                    1,
                    "materializer.lastPostedBlock",
                )?[0],
                8,
                "materializer.lastPostedBlock",
            )?,
            signed_head_backing_anchor_plus_one,
            exact_backing_proof_attested,
            signed_head_backing_current,
            materialized_channel_exit: word_bytes32(
                &decode_words(
                    &self.one_uint(
                        &manifest.close_funding_materializer,
                        "materializedChannelExit",
                        32,
                        u64::from(channel_id),
                        block_number,
                    )?,
                    1,
                    "materializer.materializedChannelExit",
                )?[0],
            ),
            rollup_latest_finalized_block_number: word_uint(
                &self.one_word(
                    &manifest.rollup,
                    "latestFinalizedBlockNumber()",
                    block_number,
                )?,
                8,
                "rollup.latestFinalizedBlockNumber",
            )?,
            backing_root_finalized: word_bool(
                &decode_words(
                    &self.one_bytes32(
                        &manifest.rollup,
                        "isFinalizedStateRoot",
                        &prepared
                            .backing_public_inputs
                            .finalized_extended_state_commitment
                            .to_string(),
                        block_number,
                    )?,
                    1,
                    "rollup.isFinalizedStateRoot",
                )?[0],
                "rollup.isFinalizedStateRoot",
            )?,
            close_mle: self.observe_mle_verifier(&close_mle_verifier, block_number)?,
            withdrawal_claim_mle: self
                .observe_mle_verifier(&withdrawal_claim_mle_verifier, block_number)?,
            post_close_claim_mle: self
                .observe_mle_verifier(&post_close_claim_mle_verifier, block_number)?,
            cancel_close_mle: self
                .observe_mle_verifier(&cancel_close_mle_verifier, block_number)?,
            backing_mle: self.observe_mle_verifier(&backing_mle_verifier, block_number)?,
            manager_channel_id: channel_id,
            challenge_period: word_uint(
                &self.one_word(&manifest.manager, "challengePeriod()", block_number)?,
                8,
                "manager.challengePeriod",
            )?,
            registered_member_set_commitment: word_bytes32(&self.one_word(
                &manifest.manager,
                "registeredMemberSetCommitment()",
                block_number,
            )?),
            active_member_count: u8::try_from(word_uint(
                &self.one_word(&manifest.manager, "activeMemberCount()", block_number)?,
                1,
                "manager.activeMemberCount",
            )?)
            .expect("one-byte bound"),
            active_delegate_count: u16::try_from(word_uint(
                &self.one_word(&manifest.manager, "activeDelegateCount()", block_number)?,
                2,
                "manager.activeDelegateCount",
            )?)
            .expect("two-byte bound"),
        })
    }

    fn observe_manager(&mut self, manager: &str, block_number: u64) -> Result<ManagerObservation> {
        let status = u8::try_from(word_uint(
            &self.one_word(manager, "channelStatus()", block_number)?,
            1,
            "manager.channelStatus",
        )?)
        .expect("one-byte bound");
        let current_close_freeze_nonce = word_uint(
            &self.one_word(manager, "currentCloseFreezeNonce()", block_number)?,
            8,
            "manager.currentCloseFreezeNonce",
        )?;
        let close_request_generation = word_uint(
            &self.one_word(manager, "closeRequestGeneration()", block_number)?,
            8,
            "manager.closeRequestGeneration",
        )?;
        let close_requested_at = word_uint(
            &self.one_word(manager, "closeRequestedAt()", block_number)?,
            8,
            "manager.closeRequestedAt",
        )?;
        let close_challenge_horizon = word_uint(
            &self.one_word(manager, "closeChallengeHorizon()", block_number)?,
            8,
            "manager.closeChallengeHorizon",
        )?;
        let raw_pending = self.noarg(manager, "getPendingClose()", block_number)?;
        let words = decode_words(&raw_pending, 37, "getPendingClose")?;
        let active = word_bool(&words[0], "pendingClose.active")?;
        let pending = if active {
            let mut cursor = 1usize;
            let next_u64 = |cursor: &mut usize, what: &str| -> Result<u64> {
                let value = word_uint(&words[*cursor], 8, what)?;
                *cursor += 1;
                Ok(value)
            };
            let close_nonce = next_u64(&mut cursor, "pending.closeNonce")?;
            let final_epoch = next_u64(&mut cursor, "pending.finalEpoch")?;
            let final_small_block_number = next_u64(&mut cursor, "pending.finalSmallBlockNumber")?;
            let close_freeze_nonce = next_u64(&mut cursor, "pending.closeFreezeNonce")?;
            let challenge_deadline = next_u64(&mut cursor, "pending.challengeDeadline")?;
            let close_intent_digest = word_bytes32(&words[cursor]);
            cursor += 1;
            let final_channel_state_digest = word_bytes32(&words[cursor]);
            cursor += 1;
            let final_balance_state_h1 = word_bytes32(&words[cursor]);
            cursor += 1;
            let mut channel_fund_amounts: [String; 10] = std::array::from_fn(|_| String::new());
            for amount in &mut channel_fund_amounts {
                *amount = BigUint::from_bytes_be(&words[cursor]).to_string();
                cursor += 1;
            }
            let mut token_registry = [0u32; 10];
            for token in &mut token_registry {
                *token = u32::try_from(word_uint(&words[cursor], 4, "pending.tokenRegistry")?)
                    .expect("four-byte bound");
                cursor += 1;
            }
            let token_count = u8::try_from(word_uint(&words[cursor], 1, "pending.tokenCount")?)
                .expect("one-byte bound");
            cursor += 1;
            let channel_fund_intmax_state_root = word_bytes32(&words[cursor]);
            cursor += 1;
            let burn_tx_hash = word_bytes32(&words[cursor]);
            cursor += 1;
            let close_withdrawal_digest = word_bytes32(&words[cursor]);
            cursor += 1;
            let snapshot_medium_block_number =
                next_u64(&mut cursor, "pending.snapshotMediumBlockNumber")?;
            let final_state_version = next_u64(&mut cursor, "pending.finalStateVersion")?;
            let final_settled_tx_chain = word_bytes32(&words[cursor]);
            cursor += 1;
            let final_settled_tx_accumulator_root = word_bytes32(&words[cursor]);
            cursor += 1;
            debug_assert_eq!(cursor, 37);
            Some(ObservedPendingClose {
                active,
                close_nonce,
                final_epoch,
                final_small_block_number,
                close_freeze_nonce,
                challenge_deadline,
                close_intent_digest,
                final_channel_state_digest,
                final_balance_state_h1,
                channel_fund_amounts,
                token_registry,
                token_count,
                channel_fund_intmax_state_root,
                burn_tx_hash,
                close_withdrawal_digest,
                snapshot_medium_block_number,
                final_state_version,
                final_settled_tx_chain,
                final_settled_tx_accumulator_root,
            })
        } else {
            None
        };
        let block = self.parse_block(&self.rpc_block(&format!("0x{block_number:x}"))?)?;
        let finalized = if status == 2 {
            let get_bytes = |backend: &Self, signature: &str| -> Result<String> {
                Ok(word_bytes32(&backend.one_word(
                    manager,
                    signature,
                    block_number,
                )?))
            };
            let mut token_registry = [0u32; 10];
            for (index, token) in token_registry.iter_mut().enumerate() {
                let raw = self.one_uint(
                    manager,
                    "finalizedTokenRegistry",
                    256,
                    index as u64,
                    block_number,
                )?;
                let word = decode_words(&raw, 1, "finalizedTokenRegistry")?[0];
                *token = u32::try_from(word_uint(&word, 4, "finalizedTokenRegistry")?)
                    .expect("four-byte bound");
            }
            let token_count = u8::try_from(word_uint(
                &self.one_word(manager, "finalizedTokenCount()", block_number)?,
                1,
                "finalizedTokenCount",
            )?)
            .expect("one-byte bound");
            if token_count == 0 || token_count > 10 {
                return Err(PublicClosePublisherError::Evidence(format!(
                    "finalizedTokenCount {token_count} is outside 1..=10"
                )));
            }
            let authorized_burn_snapshot_active = word_bool(
                &self.one_word(manager, "authorizedBurnSnapshotActive()", block_number)?,
                "authorizedBurnSnapshotActive",
            )?;
            let authorized_burn_epoch = word_uint(
                &self.one_word(manager, "authorizedBurnEpoch()", block_number)?,
                8,
                "authorizedBurnEpoch",
            )?;
            let authorized_burn_state_version = word_uint(
                &self.one_word(manager, "authorizedBurnStateVersion()", block_number)?,
                8,
                "authorizedBurnStateVersion",
            )?;
            let mut finalized_fund_caps: [String; 10] = std::array::from_fn(|_| "0".to_string());
            let mut authorized_burn_post_funds: [String; 10] =
                std::array::from_fn(|_| "0".to_string());
            for index in 0..usize::from(token_count) {
                let base_token = u64::from(token_registry[index]);
                let raw_cap = self.one_uint(
                    manager,
                    "finalizedChannelFundAmount",
                    32,
                    base_token,
                    block_number,
                )?;
                finalized_fund_caps[index] = BigUint::from_bytes_be(
                    &decode_words(&raw_cap, 1, "finalizedChannelFundAmount")?[0],
                )
                .to_string();
                let raw_post = self.one_uint(
                    manager,
                    "authorizedBurnPostFundAmount",
                    32,
                    base_token,
                    block_number,
                )?;
                authorized_burn_post_funds[index] = BigUint::from_bytes_be(
                    &decode_words(&raw_post, 1, "authorizedBurnPostFundAmount")?[0],
                )
                .to_string();
            }
            Some(ObservedFinalizedClose {
                close_intent_digest: get_bytes(self, "finalizedCloseIntentDigest()")?,
                final_channel_state_digest: get_bytes(self, "finalizedChannelStateDigest()")?,
                final_balance_state_h1: get_bytes(self, "finalizedBalanceStateH1()")?,
                burn_tx_hash: get_bytes(self, "finalizedBurnTxHash()")?,
                close_withdrawal_digest: get_bytes(self, "finalizedCloseWithdrawalDigest()")?,
                channel_fund_intmax_state_root: get_bytes(
                    self,
                    "finalizedChannelFundIntmaxStateRoot()",
                )?,
                final_settled_tx_chain: get_bytes(self, "finalizedSettledTxChain()")?,
                final_settled_tx_accumulator_root: get_bytes(
                    self,
                    "finalizedSettledTxAccumulatorRoot()",
                )?,
                final_epoch: word_uint(
                    &self.one_word(manager, "finalizedEpoch()", block_number)?,
                    8,
                    "finalizedEpoch",
                )?,
                final_small_block_number: word_uint(
                    &self.one_word(manager, "finalizedSmallBlockNumber()", block_number)?,
                    8,
                    "finalizedSmallBlockNumber",
                )?,
                final_state_version: word_uint(
                    &self.one_word(manager, "finalizedStateVersion()", block_number)?,
                    8,
                    "finalizedStateVersion",
                )?,
                token_registry,
                token_count,
                finalized_fund_caps,
                authorized_burn_snapshot_active,
                authorized_burn_epoch,
                authorized_burn_state_version,
                authorized_burn_post_funds,
            })
        } else {
            None
        };
        Ok(ManagerObservation {
            status,
            current_close_freeze_nonce,
            close_request_generation,
            close_requested_at,
            close_challenge_horizon,
            block_timestamp: block.timestamp,
            pending,
            finalized,
        })
    }

    fn sign_transaction(
        &mut self,
        account: &str,
        chain_id: u64,
        signer: &str,
        target: &str,
        calldata: &str,
    ) -> Result<SignedTransaction> {
        let mut command = Command::new("cast");
        command.args([
            "mktx",
            target,
            calldata,
            "--rpc-url",
            &self.rpc_url,
            "--account",
            account,
            "--json",
        ]);
        let raw = checked_output(command, "sign close transaction", MAX_RAW_TRANSACTION_CHARS)?
            .trim()
            .to_string();
        self.inspect_signed_transaction(&raw, chain_id, signer, target, calldata)
    }

    fn inspect_signed_transaction(
        &mut self,
        raw: &str,
        chain_id: u64,
        signer: &str,
        target: &str,
        calldata: &str,
    ) -> Result<SignedTransaction> {
        let decoded = decode_signed_transaction(raw)?;
        let (transaction_hash, nonce) =
            validate_decoded_transaction(&decoded, chain_id, signer, target, calldata)?;
        let calldata_bytes = decode_hex(calldata, None, "signed calldata")
            .map_err(PublicClosePublisherError::Evidence)?;
        Ok(SignedTransaction {
            target: target.to_ascii_lowercase(),
            calldata_hash: keccak_hex(&calldata_bytes),
            nonce,
            raw_signed_transaction: raw.trim().to_string(),
            transaction_hash,
        })
    }

    fn transaction_known(&mut self, transaction_hash: &str) -> Result<bool> {
        let output = self.output(
            &[
                "rpc",
                "eth_getTransactionByHash",
                transaction_hash,
                "--rpc-url",
                &self.rpc_url,
            ],
            "query transaction hash",
            MAX_RPC_JSON_BYTES,
        )?;
        let value: Value = serde_json::from_str(output.trim()).map_err(|error| {
            PublicClosePublisherError::Evidence(format!("parse transaction lookup: {error}"))
        })?;
        Ok(!value.is_null())
    }

    fn account_nonce(&mut self, signer: &str) -> Result<u64> {
        let output = self.output(
            &[
                "nonce",
                signer,
                "--block",
                "latest",
                "--rpc-url",
                &self.rpc_url,
            ],
            "read signer nonce",
            4096,
        )?;
        quantity_u64(output.trim(), "signer nonce").map_err(PublicClosePublisherError::Evidence)
    }

    fn publish_raw(&mut self, raw: &str) -> Result<String> {
        self.output(
            &["publish", raw, "--async", "--rpc-url", &self.rpc_url],
            "publish exact raw close transaction",
            4096,
        )
        .map(|value| value.trim().to_string())
    }

    fn receipt(&mut self, transaction_hash: &str) -> Result<Option<Value>> {
        let output = Command::new("cast")
            .args([
                "receipt",
                transaction_hash,
                "--json",
                "--async",
                "--rpc-url",
                &self.rpc_url,
            ])
            .output()
            .map_err(|error| {
                PublicClosePublisherError::Command(format!("start receipt query: {error}"))
            })?;
        if !output.status.success() || output.stdout.is_empty() {
            return Ok(None);
        }
        if output.stdout.len() > MAX_RPC_JSON_BYTES {
            return Err(PublicClosePublisherError::Evidence(
                "receipt JSON exceeds size limit".into(),
            ));
        }
        let value: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
            PublicClosePublisherError::Evidence(format!("parse receipt: {error}"))
        })?;
        Ok((!value.is_null()).then_some(value))
    }

    fn event_transaction_hashes(
        &mut self,
        manager: &str,
        topic0: &str,
        indexed_digest: &str,
        from_block: u64,
        through_block: u64,
    ) -> Result<Vec<String>> {
        if from_block > through_block {
            return Err(PublicClosePublisherError::Evidence(
                "event search starts above its durable end block".into(),
            ));
        }
        let filter = canonical_json(&serde_json::json!({
            "address": manager,
            "fromBlock": format!("0x{from_block:x}"),
            "toBlock": format!("0x{through_block:x}"),
            "topics": [topic0, indexed_digest],
        }));
        let output = self.output(
            &["rpc", "eth_getLogs", &filter, "--rpc-url", &self.rpc_url],
            "discover exact close event",
            MAX_RPC_JSON_BYTES,
        )?;
        let logs: Vec<Value> = serde_json::from_str(output.trim()).map_err(|error| {
            PublicClosePublisherError::Evidence(format!("parse exact close event search: {error}"))
        })?;
        let mut hashes = BTreeMap::<String, ()>::new();
        for log in logs {
            if log.get("removed").and_then(Value::as_bool).unwrap_or(false) {
                return Err(PublicClosePublisherError::Evidence(
                    "finalized close event search returned a removed log".into(),
                ));
            }
            let log_address = log.get("address").and_then(Value::as_str).ok_or_else(|| {
                PublicClosePublisherError::Evidence(
                    "close event search returned a log without address".into(),
                )
            })?;
            let topics = log.get("topics").and_then(Value::as_array).ok_or_else(|| {
                PublicClosePublisherError::Evidence(
                    "close event search returned a log without topics".into(),
                )
            })?;
            if !same_hex(log_address, manager)
                || topics.len() < 2
                || !topics[0]
                    .as_str()
                    .is_some_and(|value| same_hex(value, topic0))
                || !topics[1]
                    .as_str()
                    .is_some_and(|value| same_hex(value, indexed_digest))
            {
                return Err(PublicClosePublisherError::Evidence(
                    "close event search returned a log outside its exact filter".into(),
                ));
            }
            let number = log
                .get("blockNumber")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PublicClosePublisherError::Evidence(
                        "close event search returned a log without blockNumber".into(),
                    )
                })?;
            let number = quantity_u64(number, "event blockNumber")
                .map_err(PublicClosePublisherError::Evidence)?;
            if number < from_block || number > through_block {
                return Err(PublicClosePublisherError::Evidence(
                    "close event search returned an out-of-range block".into(),
                ));
            }
            let hash = log
                .get("transactionHash")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PublicClosePublisherError::Evidence(
                        "close event search returned a log without transactionHash".into(),
                    )
                })?;
            hashes.insert(
                normalize_hex(hash, 32, "event.transactionHash")
                    .map_err(PublicClosePublisherError::Evidence)?,
                (),
            );
        }
        Ok(hashes.into_keys().collect())
    }
}

/// Advance the publication state by one durable boundary. The command is intentionally
/// restart-driven: callers may invoke it periodically until `Complete`; no process must stay alive
/// while waiting for a receipt, finality, grace period, or challenge deadline.
pub fn advance_public_close(config: &PublicClosePublisherConfig) -> Result<PublicCloseProgress> {
    validate_config(config)?;
    #[cfg(not(unix))]
    return Err(PublicClosePublisherError::Configuration(
        "release publisher requires Unix flock/fsync semantics".into(),
    ));
    #[cfg(unix)]
    {
        let journal_lock = journal_lock_path(&config.journal_path)?;
        let _journal_guard = FileLock::acquire(&journal_lock)?;
        let mut backend = CastCloseBackend::new(&config.rpc_url);
        let chain_id = backend.chain_id()?;
        let signer = backend.signer_address(config.account.trim())?;
        let signer_lock = global_signer_lock_path(&config.signer_lock_root, chain_id, &signer)?;
        let _signer_guard = FileLock::acquire(&signer_lock)?;
        advance_with_backend(config, &mut backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::types::Field as _,
        iop::witness::{PartialWitness, WitnessWrite as _},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
        util::timing::TimingTree,
    };
    use plonky2_mle::fixture_v2::try_prove_and_export_mle_v2;
    use std::{
        collections::{BTreeSet, VecDeque},
        sync::OnceLock,
    };

    use crate::common::{channel::ChannelFund, u63::BlockNumber};

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "intmax-public-close-publisher-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create isolated test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        _directory: TestDirectory,
        config: PublicClosePublisherConfig,
        prepared: PreparedClose,
        deployment: DeploymentManifest,
    }

    fn repeated(byte: u8) -> String {
        format!("0x{}", format!("{byte:02x}").repeat(32))
    }

    fn repeated64(byte: u8) -> String {
        format!("0x{}", format!("{byte:02x}").repeat(64))
    }

    fn address(byte: u8) -> String {
        format!("0x{}", format!("{byte:02x}").repeat(20))
    }

    fn word(byte: u8) -> Bytes32 {
        repeated(byte).parse().expect("valid Bytes32")
    }

    /// Prove a tiny circuit whose only job is to register exactly `public_inputs`, and export it
    /// as a strict canonical wire-v3 fixture. Not cached: every distinct vector is a new proof.
    fn mle_fixture_for(public_inputs: &[u64]) -> MleVerifierV2Fixture {
        let mut builder =
            CircuitBuilder::<GoldilocksField, 2>::new(CircuitConfig::standard_recursion_config());
        let targets = (0..public_inputs.len())
            .map(|_| {
                let target = builder.add_virtual_target();
                builder.register_public_input(target);
                target
            })
            .collect::<Vec<_>>();
        let circuit = builder.build::<PoseidonGoldilocksConfig>();
        let mut witness = PartialWitness::new();
        for (target, value) in targets.iter().zip(public_inputs) {
            witness
                .set_target(*target, GoldilocksField::from_canonical_u64(*value))
                .unwrap();
        }
        try_prove_and_export_mle_v2(&circuit, witness, &mut TimingTree::default())
            .unwrap()
            .fixture
    }

    fn close_mle_fixture(public_inputs: &[u64]) -> MleVerifierV2Fixture {
        static FIXTURE: OnceLock<(Vec<u64>, MleVerifierV2Fixture)> = OnceLock::new();
        let (expected, fixture) =
            FIXTURE.get_or_init(|| (public_inputs.to_vec(), mle_fixture_for(public_inputs)));
        assert_eq!(expected, public_inputs);
        fixture.clone()
    }

    fn backing_mle_fixture(public_inputs: &[u64]) -> MleVerifierV2Fixture {
        static FIXTURE: OnceLock<(Vec<u64>, MleVerifierV2Fixture)> = OnceLock::new();
        let (expected, fixture) =
            FIXTURE.get_or_init(|| (public_inputs.to_vec(), mle_fixture_for(public_inputs)));
        assert_eq!(expected, public_inputs);
        fixture.clone()
    }

    fn write_json(path: &Path, value: &impl Serialize) {
        fs::write(
            path,
            serde_json::to_vec_pretty(value).expect("serialize fixture"),
        )
        .expect("write fixture");
    }

    fn mutate_manifest(bundle_dir: &Path, mutate: impl FnOnce(&mut Value)) {
        let path = bundle_dir.join("public_close_manifest.json");
        let mut manifest: Value = serde_json::from_slice(&fs::read(&path).expect("read manifest"))
            .expect("parse manifest");
        mutate(&mut manifest);
        write_json(&path, &manifest);
    }

    fn refresh_manifest_hash(bundle_dir: &Path, field: &str, file: &str) {
        let hash = sha256_hex(&fs::read(bundle_dir.join(file)).expect("read bundle component"));
        mutate_manifest(bundle_dir, |manifest| {
            manifest[field] = Value::String(hash);
        });
    }

    fn file_sha256(path: &Path) -> String {
        sha256_hex(&fs::read(path).expect("read fixture file for SHA-256"))
    }

    /// Replace the bundle's backing statement by a freshly proved wire-v3 fixture over `inputs`
    /// (plus the matching separate public-input file) and re-pin every affected manifest field.
    fn rewrite_backing_statement(bundle_dir: &Path, inputs: &[u64]) {
        let mle = mle_fixture_for(inputs);
        let mle_bytes = mle.to_canonical_json().unwrap().into_bytes();
        let config_bytes = mle.config_fixture().to_canonical_json().unwrap().into_bytes();
        let inputs_path = bundle_dir.join("backing_public_inputs.json");
        write_json(&inputs_path, &inputs);
        fs::write(bundle_dir.join("backing_mle.json"), &mle_bytes).expect("write backing MLE");
        fs::write(bundle_dir.join("backing_mle_config.json"), &config_bytes)
            .expect("write backing MLE config");
        let inputs_bytes = fs::read(&inputs_path).expect("read rewritten backing PIs");
        mutate_manifest(bundle_dir, |manifest| {
            manifest["backingMleBytes"] = serde_json::json!(mle_bytes.len());
            manifest["backingMleSha256"] = Value::String(sha256_hex(&mle_bytes));
            manifest["backingMleConfigBytes"] = serde_json::json!(config_bytes.len());
            manifest["backingMleConfigSha256"] = Value::String(sha256_hex(&config_bytes));
            manifest["backingPublicInputsSha256"] = Value::String(sha256_hex(&inputs_bytes));
        });
    }

    fn fixture(label: &str) -> Fixture {
        let directory = TestDirectory::new(label);
        let bundle_dir = directory.0.join("bundle");
        fs::create_dir_all(&bundle_dir).expect("create bundle");

        let channel_id = ChannelId::new(7).expect("channel id");
        let mut amounts = [U256::default(); 10];
        amounts[0] = U256::from(100u64);
        amounts[1] = U256::from(40u64);
        let token_registry = [0, 17, 0, 0, 0, 0, 0, 0, 0, 0];
        let token_count = 2;
        let full = CloseIntent {
            channel_id,
            close_nonce: 2,
            final_epoch: 5,
            final_small_block_number: 9,
            close_freeze_nonce: 2,
            final_channel_state_digest: word(1),
            final_balance_state_h1: word(2),
            channel_fund_snapshot: ChannelFund {
                channel_id,
                amounts,
                intmax_state_root: word(3),
            },
            burn_tx_hash: Bytes32::default(),
            close_withdrawal_digest: word(4),
            snapshot_medium_block_number: 0,
            final_state_version: 6,
            final_settled_tx_chain: word(5),
        };
        let member_hashes = [word(21), word(22)];
        let mut padded_members = [Bytes32::default(); MAX_SIG_CLUSTER];
        padded_members[..member_hashes.len()].copy_from_slice(&member_hashes);
        let member_set_commitment =
            close_member_set_commitment(&padded_members, member_hashes.len() as u8);
        let token_funds_digest = token_funds_digest(&token_registry, token_count, &amounts);
        let backing_finalized_extended_state_commitment = word(0x08);
        // Exercise the backing parser's U63 anchor position rather than accidentally retaining
        // the close parser's u32-only behavior.
        let backing_anchor_block_number = BlockNumber::new((1u64 << 40) + 9).expect("U63 anchor");
        let backing_public_inputs = CloseAssetBackingPublicInputs {
            channel_id,
            settled_tx_chain: full.final_settled_tx_chain,
            token_funds_digest,
            finalized_extended_state_commitment: backing_finalized_extended_state_commitment,
            anchor_block_number: backing_anchor_block_number,
        }
        .to_u64_vec();
        assert_eq!(
            backing_public_inputs.len(),
            CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN
        );
        let accumulator_root = word(6);
        let public_inputs = ChannelClosePublicInputs {
            channel_id,
            close_nonce: full.close_nonce,
            final_epoch: full.final_epoch,
            final_small_block_number: full.final_small_block_number,
            close_freeze_nonce: full.close_freeze_nonce,
            final_channel_state_digest: full.final_channel_state_digest,
            final_balance_state_h1: full.final_balance_state_h1,
            channel_fund_amount: amounts[0],
            channel_fund_intmax_state_root: full.channel_fund_snapshot.intmax_state_root,
            burn_tx_hash: full.burn_tx_hash,
            close_withdrawal_digest: full.close_withdrawal_digest,
            close_intent_digest: full.signing_digest(),
            snapshot_medium_block_number: full.snapshot_medium_block_number,
            final_state_version: full.final_state_version,
            final_settled_tx_chain: full.final_settled_tx_chain,
            final_settled_tx_accumulator_root: accumulator_root,
            member_set_commitment,
            member_count: 2,
            delegate_count: 1,
            token_funds_digest,
        }
        .to_u64_vec();
        assert_eq!(public_inputs.len(), CHANNEL_CLOSE_PUBLIC_INPUTS_LEN);

        let descriptor = PublicCloseIntentDescriptor {
            channel_id: channel_id.channel_id(),
            close_nonce: full.close_nonce,
            final_epoch: full.final_epoch,
            final_small_block_number: full.final_small_block_number,
            close_freeze_nonce: full.close_freeze_nonce,
            final_channel_state_digest: full.final_channel_state_digest.to_string(),
            final_balance_state_h1: full.final_balance_state_h1.to_string(),
            channel_fund_amount: amounts[0].to_string(),
            channel_fund_intmax_state_root: full
                .channel_fund_snapshot
                .intmax_state_root
                .to_string(),
            burn_tx_hash: full.burn_tx_hash.to_string(),
            close_withdrawal_digest: full.close_withdrawal_digest.to_string(),
            snapshot_medium_block_number: full.snapshot_medium_block_number,
            final_state_version: full.final_state_version,
            final_settled_tx_chain: full.final_settled_tx_chain.to_string(),
            final_settled_tx_accumulator_root: accumulator_root.to_string(),
            close_intent_digest: full.signing_digest().to_string(),
            member_set_commitment: member_set_commitment.to_string(),
            member_count: 2,
            delegate_count: 1,
            member_pk_gs: member_hashes.iter().map(ToString::to_string).collect(),
            channel_fund_amounts: amounts.iter().map(ToString::to_string).collect(),
            token_registry: token_registry.to_vec(),
            token_count,
        };

        let mle = close_mle_fixture(&public_inputs);
        let proof = vec![0x51, 0x4b, 0x50];
        let mle_bytes = mle
            .to_canonical_json()
            .expect("serialize canonical MLE v2 fixture")
            .into_bytes();
        let backing_proof = vec![0x42, 0x41, 0x43, 0x4b];
        let backing_mle = backing_mle_fixture(&backing_public_inputs);
        let backing_mle_bytes = backing_mle
            .to_canonical_json()
            .expect("serialize canonical backing MLE v2 fixture")
            .into_bytes();
        let backing_mle_config_bytes = backing_mle
            .config_fixture()
            .to_canonical_json()
            .expect("serialize canonical backing MLE v2 config")
            .into_bytes();
        let backing_public_input_bytes =
            serde_json::to_vec_pretty(&backing_public_inputs).expect("serialize backing PIs");
        let intent_bytes = serde_json::to_vec_pretty(&descriptor).expect("serialize descriptor");
        let full_bytes = serde_json::to_vec_pretty(&full).expect("serialize full intent");
        let public_input_bytes =
            serde_json::to_vec_pretty(&public_inputs).expect("serialize close PIs");
        fs::write(bundle_dir.join("close_proof.bin"), &proof).expect("write proof");
        fs::write(bundle_dir.join("close_intent_mle.json"), &mle_bytes).expect("write MLE");
        fs::write(bundle_dir.join("backing_proof.bin"), &backing_proof)
            .expect("write backing proof");
        fs::write(bundle_dir.join("backing_mle.json"), &backing_mle_bytes)
            .expect("write backing MLE");
        fs::write(
            bundle_dir.join("backing_mle_config.json"),
            &backing_mle_config_bytes,
        )
        .expect("write backing MLE config");
        fs::write(
            bundle_dir.join("backing_public_inputs.json"),
            &backing_public_input_bytes,
        )
        .expect("write backing PIs");
        fs::write(bundle_dir.join("close_intent.json"), &intent_bytes).expect("write descriptor");
        fs::write(bundle_dir.join("close_intent_full.json"), &full_bytes)
            .expect("write full intent");
        fs::write(
            bundle_dir.join("close_public_inputs.json"),
            &public_input_bytes,
        )
        .expect("write close PIs");

        let rollup = address(0x11);
        let balance_vd = repeated(0x77);
        write_json(
            &bundle_dir.join("public_close_manifest.json"),
            &PublicCloseManifest {
                schema_version: PUBLIC_CLOSE_MANIFEST_VERSION,
                chain_id: ANVIL_CHAIN_ID,
                rollup: rollup.clone(),
                channel_id,
                balance_verifier_data_sha256: balance_vd.clone(),
                close_proof_file: "close_proof.bin".into(),
                close_proof_bytes: proof.len(),
                close_proof_sha256: sha256_hex(&proof),
                close_mle_file: "close_intent_mle.json".into(),
                close_mle_bytes: mle_bytes.len(),
                close_mle_sha256: sha256_hex(&mle_bytes),
                backing_proof_file: "backing_proof.bin".into(),
                backing_proof_bytes: backing_proof.len(),
                backing_proof_sha256: sha256_hex(&backing_proof),
                backing_mle_file: "backing_mle.json".into(),
                backing_mle_bytes: backing_mle_bytes.len(),
                backing_mle_sha256: sha256_hex(&backing_mle_bytes),
                backing_mle_config_file: "backing_mle_config.json".into(),
                backing_mle_config_bytes: backing_mle_config_bytes.len(),
                backing_mle_config_sha256: sha256_hex(&backing_mle_config_bytes),
                backing_public_inputs_file: "backing_public_inputs.json".into(),
                backing_public_input_count: backing_public_inputs.len(),
                backing_public_inputs_sha256: sha256_hex(&backing_public_input_bytes),
                backing_finalized_extended_state_commitment,
                backing_anchor_block_number: backing_anchor_block_number.as_u64(),
                close_intent_file: "close_intent.json".into(),
                close_intent_sha256: sha256_hex(&intent_bytes),
                close_intent_full_file: "close_intent_full.json".into(),
                close_intent_full_sha256: sha256_hex(&full_bytes),
                close_public_inputs_file: "close_public_inputs.json".into(),
                close_public_input_count: public_inputs.len(),
                close_public_inputs_sha256: sha256_hex(&public_input_bytes),
                key_material_consumed: false,
                self_verified: true,
            },
        );

        let expected_final_channel_state_digest = full.final_channel_state_digest.to_string();
        let prepared = prepare_bundle(&bundle_dir, &expected_final_channel_state_digest)
            .expect("prepare fixture bundle");
        let deployment = DeploymentManifest {
            schema_version: DEPLOYMENT_MANIFEST_VERSION,
            chain_id: ANVIL_CHAIN_ID,
            rollup,
            rollup_runtime_code_hash: repeated(0x31),
            manager: address(0x22),
            manager_deployment_block: 1,
            manager_runtime_code_hash: repeated(0x32),
            close_funding_materializer: address(0x45),
            close_funding_materializer_runtime_code_hash: repeated(0x36),
            settlement_verifier: address(0x33),
            settlement_verifier_runtime_code_hash: repeated(0x34),
            close_mle_verifier: address(0x44),
            close_mle_verifier_runtime_code_hash: repeated(0x35),
            close_mle_verifier_core: address(0x45),
            close_mle_verifier_core_runtime_code_hash: repeated(0x36),
            close_mle_verification_config_digest: mle
                .pinned_verifier
                .verification_config_digest
                .clone(),
            close_mle_circuit_config_digest: mle.pinned_verifier.circuit_config_digest.clone(),
            close_mle_whir_parameters_digest: mle.pinned_verifier.whir_parameters_digest.clone(),
            close_mle_whir_protocol_id: mle.pinned_verifier.whir_protocol_id.clone(),
            close_mle_whir_session_id: mle.pinned_verifier.whir_session_id.clone(),
            withdrawal_claim_mle_verifier: address(0x46),
            withdrawal_claim_mle_verifier_runtime_code_hash: repeated(0x37),
            withdrawal_claim_mle_verifier_core: address(0x47),
            withdrawal_claim_mle_verifier_core_runtime_code_hash: repeated(0x38),
            withdrawal_claim_mle_verification_config_digest: repeated(0x39),
            withdrawal_claim_mle_circuit_config_digest: repeated(0x3a),
            withdrawal_claim_mle_whir_parameters_digest: repeated(0x3b),
            withdrawal_claim_mle_whir_protocol_id: repeated64(0x3c),
            withdrawal_claim_mle_whir_session_id: repeated(0x3d),
            post_close_claim_mle_verifier: address(0x48),
            post_close_claim_mle_verifier_runtime_code_hash: repeated(0x3e),
            post_close_claim_mle_verifier_core: address(0x49),
            post_close_claim_mle_verifier_core_runtime_code_hash: repeated(0x4a),
            post_close_claim_mle_verification_config_digest: repeated(0x4b),
            post_close_claim_mle_circuit_config_digest: repeated(0x4c),
            post_close_claim_mle_whir_parameters_digest: repeated(0x4d),
            post_close_claim_mle_whir_protocol_id: repeated64(0x4e),
            post_close_claim_mle_whir_session_id: repeated(0x4f),
            cancel_close_mle_verifier: address(0x50),
            cancel_close_mle_verifier_runtime_code_hash: repeated(0x51),
            cancel_close_mle_verifier_core: address(0x52),
            cancel_close_mle_verifier_core_runtime_code_hash: repeated(0x53),
            cancel_close_mle_verification_config_digest: repeated(0x54),
            cancel_close_mle_circuit_config_digest: repeated(0x55),
            cancel_close_mle_whir_parameters_digest: repeated(0x56),
            cancel_close_mle_whir_protocol_id: repeated64(0x57),
            cancel_close_mle_whir_session_id: repeated(0x58),
            backing_mle_verifier: address(0x60),
            backing_mle_verifier_runtime_code_hash: repeated(0x61),
            backing_mle_verifier_core: address(0x62),
            backing_mle_verifier_core_runtime_code_hash: repeated(0x63),
            backing_mle_verification_config_digest: backing_mle
                .pinned_verifier
                .verification_config_digest
                .clone(),
            backing_mle_circuit_config_digest: backing_mle
                .pinned_verifier
                .circuit_config_digest
                .clone(),
            backing_mle_whir_parameters_digest: backing_mle
                .pinned_verifier
                .whir_parameters_digest
                .clone(),
            backing_mle_whir_protocol_id: backing_mle.pinned_verifier.whir_protocol_id.clone(),
            backing_mle_whir_session_id: backing_mle.pinned_verifier.whir_session_id.clone(),
            balance_verifier_data_sha256: balance_vd,
            mle_fixture_schema: MLE_VERIFIER_FIXTURE_SCHEMA_V2.into(),
            mle_protocol_version: MLE_PROTOCOL_VERSION_CURRENT,
            mle_proof_abi_signature: MLE_PROOF_ABI_SIGNATURE_V2.into(),
            mle_proof_layout_hash: generated_hex(&MLE_PROOF_LAYOUT_HASH_V2),
            mle_compact_layout_hash: generated_hex(&COMPACT_LAYOUT_HASH_V2),
            mle_compact_proof_encoding: String::from_utf8(COMPACT_MAGIC_V2.to_vec()).unwrap(),
            attest_signed_head_backing_selector: selector(ATTEST_SIGNED_HEAD_BACKING_SIGNATURE),
            submit_close_intent_selector: selector(SUBMIT_CLOSE_SIGNATURE),
            finalize_close_guarded_selector: selector(FINALIZE_CLOSE_GUARDED_SIGNATURE),
            materialize_signed_head_selector: selector(MATERIALIZE_SIGNED_HEAD_SIGNATURE),
            close_submitted_topic: keccak_hex(CLOSE_SUBMITTED_EVENT.as_bytes()),
            close_finalized_topic: keccak_hex(CLOSE_FINALIZED_EVENT.as_bytes()),
            signed_head_backing_attested_topic: keccak_hex(
                SIGNED_HEAD_BACKING_ATTESTED_EVENT.as_bytes(),
            ),
            signed_head_exit_materialized_topic: keccak_hex(
                SIGNED_HEAD_EXIT_MATERIALIZED_EVENT.as_bytes(),
            ),
        };
        let deployment_manifest_path = directory.0.join("deployment.json");
        write_json(&deployment_manifest_path, &deployment);
        let deployment_manifest_sha256 =
            sha256_hex(&fs::read(&deployment_manifest_path).expect("read deployment manifest"));
        let config = PublicClosePublisherConfig {
            bundle_dir,
            expected_final_channel_state_digest,
            deployment_manifest_path,
            deployment_manifest_sha256,
            journal_path: directory.0.join("private/journal.json"),
            signer_lock_root: directory.0.join("locks"),
            rpc_url: "fake://close".into(),
            account: "release-close-account".into(),
            allow_unfinalized_devnet: true,
        };
        Fixture {
            _directory: directory,
            config,
            prepared,
            deployment,
        }
    }

    fn block(number: u64, timestamp: u64) -> BlockObservation {
        BlockObservation {
            number,
            hash: word(u8::try_from(number).expect("small block")),
            parent_hash: word(u8::try_from(number - 1).expect("small parent")),
            timestamp,
        }
    }

    fn requested(expected: &ExpectedClose, timestamp: u64) -> ManagerObservation {
        ManagerObservation {
            status: 1,
            current_close_freeze_nonce: expected.close_freeze_nonce,
            close_request_generation: 1,
            close_requested_at: 100,
            close_challenge_horizon: 2_000,
            block_timestamp: timestamp,
            pending: None,
            finalized: None,
        }
    }

    fn pending(expected: &ExpectedClose, timestamp: u64, deadline: u64) -> ManagerObservation {
        ManagerObservation {
            status: 1,
            current_close_freeze_nonce: expected.close_freeze_nonce,
            close_request_generation: 1,
            close_requested_at: 100,
            close_challenge_horizon: 2_000,
            block_timestamp: timestamp,
            pending: Some(ObservedPendingClose {
                active: true,
                close_nonce: expected.close_nonce,
                final_epoch: expected.final_epoch,
                final_small_block_number: expected.final_small_block_number,
                close_freeze_nonce: expected.close_freeze_nonce,
                challenge_deadline: deadline,
                close_intent_digest: expected.close_intent_digest.clone(),
                final_channel_state_digest: expected.final_channel_state_digest.clone(),
                final_balance_state_h1: expected.final_balance_state_h1.clone(),
                channel_fund_amounts: expected.channel_fund_amounts.clone(),
                token_registry: expected.token_registry,
                token_count: expected.token_count,
                channel_fund_intmax_state_root: expected.channel_fund_intmax_state_root.clone(),
                burn_tx_hash: expected.burn_tx_hash.clone(),
                close_withdrawal_digest: expected.close_withdrawal_digest.clone(),
                snapshot_medium_block_number: expected.snapshot_medium_block_number,
                final_state_version: expected.final_state_version,
                final_settled_tx_chain: expected.final_settled_tx_chain.clone(),
                final_settled_tx_accumulator_root: expected
                    .final_settled_tx_accumulator_root
                    .clone(),
            }),
            finalized: None,
        }
    }

    fn closed(expected: &ExpectedClose, timestamp: u64) -> ManagerObservation {
        ManagerObservation {
            status: 2,
            current_close_freeze_nonce: expected.close_freeze_nonce,
            close_request_generation: 1,
            close_requested_at: 0,
            close_challenge_horizon: 0,
            block_timestamp: timestamp,
            pending: None,
            finalized: Some(ObservedFinalizedClose {
                close_intent_digest: expected.close_intent_digest.clone(),
                final_channel_state_digest: expected.final_channel_state_digest.clone(),
                final_balance_state_h1: expected.final_balance_state_h1.clone(),
                burn_tx_hash: expected.burn_tx_hash.clone(),
                close_withdrawal_digest: expected.close_withdrawal_digest.clone(),
                channel_fund_intmax_state_root: expected.channel_fund_intmax_state_root.clone(),
                final_settled_tx_chain: expected.final_settled_tx_chain.clone(),
                final_settled_tx_accumulator_root: expected
                    .final_settled_tx_accumulator_root
                    .clone(),
                final_epoch: expected.final_epoch,
                final_small_block_number: expected.final_small_block_number,
                final_state_version: expected.final_state_version,
                token_registry: expected.token_registry,
                token_count: expected.token_count,
                finalized_fund_caps: expected.channel_fund_amounts.clone(),
                authorized_burn_snapshot_active: false,
                authorized_burn_epoch: 0,
                authorized_burn_state_version: 0,
                authorized_burn_post_funds: std::array::from_fn(|_| "0".into()),
            }),
        }
    }

    fn observed_mle(pin: ManifestMlePin<'_>) -> ObservedMleVerifier {
        ObservedMleVerifier {
            adapter: pin.adapter.into(),
            adapter_runtime_code_hash: pin.adapter_runtime_code_hash.into(),
            core: pin.core.into(),
            core_runtime_code_hash: pin.core_runtime_code_hash.into(),
            verification_config_digest: pin.verification_config_digest.into(),
            circuit_config_digest: pin.circuit_config_digest.into(),
            whir_parameters_digest: pin.whir_parameters_digest.into(),
            whir_protocol_id: pin.whir_protocol_id.into(),
            whir_session_id: pin.whir_session_id.into(),
            adapter_allowed_chain_id: ANVIL_CHAIN_ID,
            core_allowed_chain_id: ANVIL_CHAIN_ID,
        }
    }

    fn observed_deployment(fixture: &Fixture) -> ObservedDeployment {
        let mle_pins = manifest_mle_pins(&fixture.deployment);
        ObservedDeployment {
            rollup_runtime_code_hash: fixture.deployment.rollup_runtime_code_hash.clone(),
            manager_runtime_code_hash: fixture.deployment.manager_runtime_code_hash.clone(),
            close_funding_materializer_runtime_code_hash: fixture
                .deployment
                .close_funding_materializer_runtime_code_hash
                .clone(),
            settlement_verifier_runtime_code_hash: fixture
                .deployment
                .settlement_verifier_runtime_code_hash
                .clone(),
            manager_registry: fixture.deployment.rollup.clone(),
            manager_verifier: fixture.deployment.settlement_verifier.clone(),
            manager_close_funding_materializer: fixture
                .deployment
                .close_funding_materializer
                .clone(),
            materializer_rollup: fixture.deployment.rollup.clone(),
            materializer_manager_of_channel: fixture.deployment.manager.clone(),
            materializer_frozen_generation: 1,
            materializer_last_posted_block: 9,
            signed_head_backing_anchor_plus_one: fixture
                .prepared
                .backing_public_inputs
                .anchor_block_number
                .as_u64()
                + 1,
            exact_backing_proof_attested: true,
            signed_head_backing_current: true,
            materialized_channel_exit: repeated(0),
            rollup_latest_finalized_block_number: fixture
                .prepared
                .backing_public_inputs
                .anchor_block_number
                .as_u64(),
            backing_root_finalized: true,
            close_mle: observed_mle(mle_pins[0]),
            withdrawal_claim_mle: observed_mle(mle_pins[1]),
            post_close_claim_mle: observed_mle(mle_pins[2]),
            cancel_close_mle: observed_mle(mle_pins[3]),
            backing_mle: observed_mle(mle_pins[BACKING_MLE_PIN_INDEX]),
            manager_channel_id: fixture.prepared.channel_id,
            challenge_period: 900,
            registered_member_set_commitment: fixture
                .prepared
                .expected
                .member_set_commitment
                .clone(),
            active_member_count: fixture.prepared.expected.member_count,
            active_delegate_count: fixture.prepared.expected.delegate_count,
        }
    }

    fn abi_word_decimal(value: &str) -> Vec<u8> {
        let encoded = value
            .parse::<BigUint>()
            .expect("decimal word")
            .to_bytes_be();
        let mut word = vec![0u8; 32];
        word[32 - encoded.len()..].copy_from_slice(&encoded);
        word
    }

    fn abi_word_u64(value: u64) -> Vec<u8> {
        abi_word_decimal(&value.to_string())
    }

    fn abi_usize(word: &[u8]) -> usize {
        assert_eq!(word.len(), 32);
        word.iter().fold(0usize, |value, byte| {
            value
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .expect("ABI word fits usize")
        })
    }

    fn indexed_u64(value: u64) -> String {
        format!("0x{}", hex::encode(abi_word_u64(value)))
    }

    fn event_data(words: impl IntoIterator<Item = Vec<u8>>) -> String {
        let bytes = words.into_iter().flatten().collect::<Vec<_>>();
        format!("0x{}", hex::encode(bytes))
    }

    fn submit_event(manager: &str, expected: &ExpectedClose, deadline: u64) -> Value {
        serde_json::json!({
            "address": manager,
            "removed": false,
            "topics": [
                keccak_hex(CLOSE_SUBMITTED_EVENT.as_bytes()),
                expected.close_intent_digest,
                expected.burn_tx_hash,
                indexed_u64(expected.close_nonce)
            ],
            "data": event_data([
                abi_word_u64(expected.final_epoch),
                abi_word_u64(expected.close_freeze_nonce),
                abi_word_decimal(&expected.channel_fund_amounts[0]),
                abi_word_u64(deadline),
                abi_word_u64(expected.final_state_version),
                decode_hex(&expected.final_settled_tx_chain, Some(32), "settled chain").unwrap(),
            ])
        })
    }

    fn finalize_event(manager: &str, expected: &ExpectedClose) -> Value {
        serde_json::json!({
            "address": manager,
            "removed": false,
            "topics": [
                keccak_hex(CLOSE_FINALIZED_EVENT.as_bytes()),
                expected.close_intent_digest,
                expected.burn_tx_hash,
                indexed_u64(expected.final_epoch)
            ],
            "data": event_data([
                abi_word_decimal(&expected.channel_fund_amounts[0]),
                abi_word_u64(expected.final_state_version),
                decode_hex(&expected.final_settled_tx_chain, Some(32), "settled chain").unwrap(),
            ])
        })
    }

    fn indexed_address(value: &str) -> String {
        let address = decode_hex(value, Some(20), "indexed address").unwrap();
        let mut word = vec![0u8; 12];
        word.extend(address);
        format!("0x{}", hex::encode(word))
    }

    fn attestation_event(fixture: &Fixture) -> Value {
        let identity = backing_attestation_identity(&fixture.prepared, &fixture.deployment)
            .expect("attestation identity");
        serde_json::json!({
            "address": fixture.deployment.close_funding_materializer,
            "removed": false,
            "topics": [
                keccak_hex(SIGNED_HEAD_BACKING_ATTESTED_EVENT.as_bytes()),
                indexed_u32(fixture.prepared.channel_id),
                indexed_address(&fixture.deployment.manager),
                identity.statement_key,
            ],
            "data": event_data([
                decode_hex(
                    &fixture
                        .prepared
                        .backing_public_inputs
                        .finalized_extended_state_commitment
                        .to_string(),
                    Some(32),
                    "backing root",
                )
                .unwrap(),
                abi_word_u64(
                    fixture
                        .prepared
                        .backing_public_inputs
                        .anchor_block_number
                        .as_u64(),
                ),
                decode_hex(&identity.proof_id, Some(32), "proof id").unwrap(),
            ]),
        })
    }

    fn materialize_event(fixture: &Fixture) -> Value {
        serde_json::json!({
            "address": fixture.deployment.close_funding_materializer,
            "removed": false,
            "topics": [
                keccak_hex(SIGNED_HEAD_EXIT_MATERIALIZED_EVENT.as_bytes()),
                indexed_u32(fixture.prepared.channel_id),
                indexed_address(&fixture.deployment.manager),
                fixture.prepared.expected.close_intent_digest,
            ],
            "data": event_data([abi_word_u64(u64::from(
                fixture.prepared.expected.token_count,
            ))]),
        })
    }

    fn receipt(
        transaction: &SignedTransaction,
        signer: &str,
        block: &BlockObservation,
        event: Value,
    ) -> Value {
        receipt_with_events(transaction, signer, block, vec![event])
    }

    fn receipt_with_events(
        transaction: &SignedTransaction,
        signer: &str,
        block: &BlockObservation,
        events: Vec<Value>,
    ) -> Value {
        receipt_with_events_at(transaction, signer, block, 0, events)
    }

    fn receipt_with_events_at(
        transaction: &SignedTransaction,
        signer: &str,
        block: &BlockObservation,
        transaction_index: u64,
        events: Vec<Value>,
    ) -> Value {
        serde_json::json!({
            "transactionHash": transaction.transaction_hash,
            "blockHash": block.hash.to_string(),
            "blockNumber": format!("0x{:x}", block.number),
            "transactionIndex": format!("0x{transaction_index:x}"),
            "status": "0x1",
            "from": signer,
            "to": transaction.target,
            "logs": events
        })
    }

    struct FakeBackend {
        signer: String,
        deployment: ObservedDeployment,
        head: u64,
        blocks: BTreeMap<u64, BlockObservation>,
        managers: BTreeMap<u64, ManagerObservation>,
        manager_sequences: BTreeMap<u64, VecDeque<ManagerObservation>>,
        checkpoint_sequence: VecDeque<L1FinalizedCheckpoint>,
        signed: BTreeMap<String, SignedTransaction>,
        known: BTreeSet<String>,
        receipts: BTreeMap<String, Value>,
        nonce: u64,
        sign_count: usize,
        publish_attempts: Vec<String>,
        fail_publish_attempts: BTreeSet<usize>,
        journal_path: PathBuf,
    }

    impl FakeBackend {
        fn new(fixture: &Fixture) -> Self {
            let mut blocks = BTreeMap::new();
            blocks.insert(10, block(10, 1_000));
            let mut managers = BTreeMap::new();
            managers.insert(10, requested(&fixture.prepared.expected, 1_000));
            let mut backend = Self {
                signer: address(0x55),
                deployment: observed_deployment(fixture),
                head: 10,
                blocks,
                managers,
                manager_sequences: BTreeMap::new(),
                checkpoint_sequence: VecDeque::new(),
                signed: BTreeMap::new(),
                known: BTreeSet::new(),
                receipts: BTreeMap::new(),
                nonce: 0,
                sign_count: 0,
                publish_attempts: Vec::new(),
                fail_publish_attempts: BTreeSet::new(),
                journal_path: fixture.config.journal_path.clone(),
            };
            // The exact whole-vector backing statement is already attested by another watchtower
            // in the head block, at a non-zero transaction index so that same-block ordering
            // against later close events is meaningful.
            install_attestation_receipt(fixture, &mut backend, 10, EXTERNAL_ATTESTATION_INDEX);
            backend
        }

        fn checkpoint(&self) -> L1FinalizedCheckpoint {
            let block = self.blocks.get(&self.head).expect("head block");
            L1FinalizedCheckpoint {
                chain_id: ANVIL_CHAIN_ID,
                block_number: block.number,
                block_hash: block.hash,
                parent_hash: block.parent_hash,
                source: L1FinalitySource::DevnetLatest,
            }
        }

        fn transaction(&self, index: usize) -> SignedTransaction {
            self.signed
                .values()
                .find(|transaction| {
                    transaction.raw_signed_transaction == format!("0x{:02x}", index + 1)
                })
                .expect("signed transaction")
                .clone()
        }
    }

    impl ClosePublisherBackend for FakeBackend {
        fn chain_id(&mut self) -> Result<u64> {
            Ok(ANVIL_CHAIN_ID)
        }

        fn signer_address(&mut self, account: &str) -> Result<String> {
            if account != "release-close-account" {
                return Err(PublicClosePublisherError::Command("wrong account".into()));
            }
            Ok(self.signer.clone())
        }

        fn durable_checkpoint(
            &mut self,
            _allow_unfinalized_devnet: bool,
        ) -> Result<L1FinalizedCheckpoint> {
            Ok(self
                .checkpoint_sequence
                .pop_front()
                .unwrap_or_else(|| self.checkpoint()))
        }

        fn block_at(&mut self, number: u64, _source: L1FinalitySource) -> Result<BlockObservation> {
            self.blocks.get(&number).cloned().ok_or_else(|| {
                PublicClosePublisherError::Evidence(format!("fake has no block {number}"))
            })
        }

        fn observe_deployment(
            &mut self,
            _manifest: &DeploymentManifest,
            _prepared: &PreparedClose,
            _block_number: u64,
        ) -> Result<ObservedDeployment> {
            Ok(self.deployment.clone())
        }

        fn observe_manager(
            &mut self,
            _manager: &str,
            block_number: u64,
        ) -> Result<ManagerObservation> {
            if let Some(observation) = self
                .manager_sequences
                .get_mut(&block_number)
                .and_then(VecDeque::pop_front)
            {
                return Ok(observation);
            }
            self.managers.get(&block_number).cloned().ok_or_else(|| {
                PublicClosePublisherError::Evidence(format!(
                    "fake has no manager snapshot at {block_number}"
                ))
            })
        }

        fn sign_transaction(
            &mut self,
            account: &str,
            chain_id: u64,
            signer: &str,
            target: &str,
            calldata: &str,
        ) -> Result<SignedTransaction> {
            if account != "release-close-account"
                || chain_id != ANVIL_CHAIN_ID
                || !same_hex(signer, &self.signer)
            {
                return Err(PublicClosePublisherError::Command(
                    "fake signing context mismatch".into(),
                ));
            }
            let index = self.sign_count;
            self.sign_count += 1;
            let raw = format!("0x{:02x}", index + 1);
            let transaction = SignedTransaction {
                target: target.to_ascii_lowercase(),
                calldata_hash: keccak_hex(
                    &decode_hex(calldata, None, "fake calldata")
                        .map_err(PublicClosePublisherError::Evidence)?,
                ),
                nonce: self.nonce,
                raw_signed_transaction: raw.clone(),
                transaction_hash: repeated(0xa0 + u8::try_from(index).expect("few transactions")),
            };
            self.signed.insert(raw, transaction.clone());
            Ok(transaction)
        }

        fn inspect_signed_transaction(
            &mut self,
            raw: &str,
            chain_id: u64,
            signer: &str,
            target: &str,
            calldata: &str,
        ) -> Result<SignedTransaction> {
            let transaction = self.signed.get(raw).cloned().ok_or_else(|| {
                PublicClosePublisherError::Evidence("fake raw transaction is unknown".into())
            })?;
            let calldata = decode_hex(calldata, None, "fake calldata")
                .map_err(PublicClosePublisherError::Evidence)?;
            if chain_id != ANVIL_CHAIN_ID
                || !same_hex(signer, &self.signer)
                || !same_hex(target, &transaction.target)
                || transaction.calldata_hash != keccak_hex(&calldata)
            {
                return Err(PublicClosePublisherError::Evidence(
                    "fake decoded transaction mismatch".into(),
                ));
            }
            Ok(transaction)
        }

        fn transaction_known(&mut self, transaction_hash: &str) -> Result<bool> {
            Ok(self.known.contains(transaction_hash))
        }

        fn account_nonce(&mut self, _signer: &str) -> Result<u64> {
            Ok(self.nonce)
        }

        fn publish_raw(&mut self, raw: &str) -> Result<String> {
            let journal = fs::read_to_string(&self.journal_path).map_err(|error| {
                PublicClosePublisherError::Journal(format!(
                    "fake observed broadcast before journal: {error}"
                ))
            })?;
            if !journal.contains(raw) {
                return Err(PublicClosePublisherError::Journal(
                    "fake observed raw broadcast before exact bytes were fsynced".into(),
                ));
            }
            self.publish_attempts.push(raw.to_string());
            let attempt = self.publish_attempts.len();
            if self.fail_publish_attempts.remove(&attempt) {
                return Err(PublicClosePublisherError::Command(
                    "injected post-WAL broadcast failure".into(),
                ));
            }
            let transaction = self.signed.get(raw).cloned().ok_or_else(|| {
                PublicClosePublisherError::Evidence("published unknown raw bytes".into())
            })?;
            self.nonce = self.nonce.max(transaction.nonce + 1);
            self.known.insert(transaction.transaction_hash.clone());
            Ok(transaction.transaction_hash)
        }

        fn receipt(&mut self, transaction_hash: &str) -> Result<Option<Value>> {
            Ok(self.receipts.get(transaction_hash).cloned())
        }

        fn event_transaction_hashes(
            &mut self,
            manager: &str,
            topic0: &str,
            indexed_digest: &str,
            from_block: u64,
            through_block: u64,
        ) -> Result<Vec<String>> {
            let mut hashes = BTreeSet::new();
            for (hash, receipt) in &self.receipts {
                let number = receipt_quantity(receipt, "blockNumber")
                    .map_err(PublicClosePublisherError::Evidence)?;
                if !(from_block..=through_block).contains(&number) {
                    continue;
                }
                for log in receipt_logs(receipt).map_err(PublicClosePublisherError::Evidence)? {
                    if log
                        .get("address")
                        .and_then(Value::as_str)
                        .is_some_and(|value| same_hex(value, manager))
                        && log_topic(log, 0).is_ok_and(|value| same_hex(value, topic0))
                        && log_topic(log, 1).is_ok_and(|value| same_hex(value, indexed_digest))
                    {
                        hashes.insert(hash.clone());
                    }
                }
            }
            Ok(hashes.into_iter().collect())
        }
    }

    const EXTERNAL_ATTESTATION_INDEX: u64 = 1;

    fn external_attestation(fixture: &Fixture) -> SignedTransaction {
        SignedTransaction {
            target: fixture.deployment.close_funding_materializer.clone(),
            calldata_hash: String::new(),
            nonce: 0,
            raw_signed_transaction: String::new(),
            transaction_hash: repeated(0xbb),
        }
    }

    fn install_attestation_receipt(
        fixture: &Fixture,
        backend: &mut FakeBackend,
        block_number: u64,
        transaction_index: u64,
    ) {
        let block = backend
            .blocks
            .get(&block_number)
            .expect("attestation block")
            .clone();
        let external = external_attestation(fixture);
        backend.receipts.insert(
            external.transaction_hash.clone(),
            receipt_with_events_at(
                &external,
                &address(0x77),
                &block,
                transaction_index,
                vec![attestation_event(fixture)],
            ),
        );
    }

    /// A backend whose permissionless attestation has already been adopted into the journal, so
    /// the next `advance_with_backend` call enters the close state machine.
    fn attested_backend(fixture: &Fixture) -> FakeBackend {
        let mut backend = FakeBackend::new(fixture);
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend)
                .expect("adopt permissionless attestation"),
            PublicCloseProgress::AttestAdopted { .. }
        ));
        assert_eq!(backend.sign_count, 0);
        let journal: PublicationJournal =
            serde_json::from_slice(&fs::read(&fixture.config.journal_path).unwrap()).unwrap();
        let attested = journal.attest_observation.expect("durable attestation observation");
        assert_eq!(attested.transaction_hash, repeated(0xbb));
        assert_eq!(
            (attested.block_number, attested.transaction_index),
            (10, EXTERNAL_ATTESTATION_INDEX)
        );
        backend
    }

    fn read_journal(fixture: &Fixture) -> PublicationJournal {
        serde_json::from_slice(&fs::read(&fixture.config.journal_path).unwrap()).unwrap()
    }

    fn install_submit_receipt(fixture: &Fixture, backend: &mut FakeBackend, event: Value) {
        let block = block(11, 1_001);
        let transaction = backend.transaction(0);
        backend.blocks.insert(11, block.clone());
        backend.managers.insert(
            11,
            pending(&fixture.prepared.expected, block.timestamp, 1_100),
        );
        backend.receipts.insert(
            transaction.transaction_hash.clone(),
            receipt(&transaction, &backend.signer, &block, event),
        );
        backend.head = 11;
    }

    fn submit_and_confirm(fixture: &Fixture, backend: &mut FakeBackend) {
        assert!(matches!(
            advance_with_backend(&fixture.config, backend).expect("broadcast submit"),
            PublicCloseProgress::SubmitBroadcast { .. }
        ));
        let event = submit_event(
            &fixture.deployment.manager,
            &fixture.prepared.expected,
            1_100,
        );
        install_submit_receipt(fixture, backend, event);
        assert!(matches!(
            advance_with_backend(&fixture.config, backend).expect("confirm submit"),
            PublicCloseProgress::AwaitingChallengeDeadline { .. }
        ));
    }

    fn make_finalize_eligible(fixture: &Fixture, backend: &mut FakeBackend) {
        let block = block(12, 1_101);
        backend.blocks.insert(12, block.clone());
        backend.managers.insert(
            12,
            pending(&fixture.prepared.expected, block.timestamp, 1_100),
        );
        backend.head = 12;
    }

    fn confirm_finalize_and_begin_materialization(
        fixture: &Fixture,
        backend: &mut FakeBackend,
    ) -> SignedTransaction {
        let finalized_block = block(13, 1_102);
        let finalize = backend.transaction(1);
        backend.blocks.insert(13, finalized_block.clone());
        backend.managers.insert(
            13,
            closed(&fixture.prepared.expected, finalized_block.timestamp),
        );
        backend.receipts.insert(
            finalize.transaction_hash.clone(),
            receipt(
                &finalize,
                &backend.signer,
                &finalized_block,
                finalize_event(&fixture.deployment.manager, &fixture.prepared.expected),
            ),
        );
        backend.head = 13;
        assert!(matches!(
            advance_with_backend(&fixture.config, backend)
                .expect("confirm finalize and begin materialization"),
            PublicCloseProgress::MaterializeBroadcast { .. }
        ));
        backend.transaction(2)
    }

    #[test]
    fn guarded_finalize_calldata_binds_the_monotone_request_generation() {
        let fixture = fixture("finalize-generation-calldata");
        let first = finalize_calldata(&fixture.prepared.expected, 1).expect("generation one");
        let second = finalize_calldata(&fixture.prepared.expected, 2).expect("generation two");
        assert_ne!(
            first, second,
            "a later close era must have a distinct action"
        );

        let bytes = decode_hex(&first, Some(68), "guarded finalize calldata").unwrap();
        assert_eq!(
            &bytes[..4],
            &keccak_hash::keccak(FINALIZE_CLOSE_GUARDED_SIGNATURE.as_bytes()).0[..4]
        );
        assert_eq!(
            &bytes[4..36],
            decode_hex(
                &fixture.prepared.expected.close_intent_digest,
                Some(32),
                "close digest"
            )
            .unwrap()
        );
        assert_eq!(word_u64(&bytes[36..68], "generation").unwrap(), 1);
        assert!(finalize_calldata(&fixture.prepared.expected, 0)
            .unwrap_err()
            .to_string()
            .contains("zero closeRequestGeneration"));
    }

    #[test]
    fn signer_lane_is_durable_before_offline_signing_and_sign_failure_releases_it() {
        let fixture = fixture("pre-sign-reservation");
        ensure_private_directory(
            fixture
                .config
                .journal_path
                .parent()
                .expect("journal parent"),
        )
        .expect("private journal parent");
        let binding = make_binding(
            &fixture.prepared,
            &fixture.deployment,
            fixture.config.deployment_manifest_sha256.clone(),
            &fixture.config.signer_lock_root,
        )
        .expect("publication binding");
        let signer = address(0x55);
        let submit = close_signer_reservation(
            ANVIL_CHAIN_ID,
            &signer,
            &fixture.config.journal_path,
            &binding,
            "submit",
            &fixture.deployment.manager,
            &binding.submit_calldata_hash,
            None,
        )
        .expect("submit reservation");
        let finalize_calldata =
            finalize_calldata(&fixture.prepared.expected, 1).expect("guarded finalize calldata");
        let finalize_calldata_hash =
            keccak_hex(&decode_hex(&finalize_calldata, None, "guarded finalize calldata").unwrap());
        let sibling = close_signer_reservation(
            ANVIL_CHAIN_ID,
            &signer,
            &fixture.config.journal_path,
            &binding,
            "finalize",
            &fixture.deployment.manager,
            &finalize_calldata_hash,
            Some(1),
        )
        .expect("sibling reservation");

        let mut callback_observed_reservation = false;
        sign_after_reservation(&fixture.config.signer_lock_root, &submit, || {
            callback_observed_reservation = true;
            assert!(
                l1_signer_reservation::claim(&fixture.config.signer_lock_root, &sibling).is_err(),
                "a sibling intent must be excluded before the signing callback starts"
            );
            Ok(())
        })
        .expect("successful signing callback");
        assert!(callback_observed_reservation);
        assert!(
            l1_signer_reservation::claim(&fixture.config.signer_lock_root, &sibling).is_err(),
            "a successful signature keeps its lease until finalized journal evidence"
        );
        release_signer_reservation(&fixture.config.signer_lock_root, &submit)
            .expect("test releases successful lease");

        let error = sign_after_reservation::<()>(&fixture.config.signer_lock_root, &submit, || {
            Err(PublicClosePublisherError::Command(
                "injected signing failure".into(),
            ))
        })
        .unwrap_err();
        assert!(error.to_string().contains("injected signing failure"));
        l1_signer_reservation::claim(&fixture.config.signer_lock_root, &sibling)
            .expect("failed signing released the exact lease");
        l1_signer_reservation::release(&fixture.config.signer_lock_root, &sibling)
            .expect("release sibling test lease");
    }

    #[test]
    fn permissionless_winner_cannot_release_lane_until_local_loser_finally_reverts() {
        let fixture = fixture("permissionless-loser-reservation");
        ensure_private_directory(
            fixture
                .config
                .journal_path
                .parent()
                .expect("journal parent"),
        )
        .expect("private journal parent");
        let mut backend = FakeBackend::new(&fixture);
        let signer = backend.signer.clone();
        let binding = make_binding(
            &fixture.prepared,
            &fixture.deployment,
            fixture.config.deployment_manifest_sha256.clone(),
            &fixture.config.signer_lock_root,
        )
        .expect("publication binding");
        let reservation = close_signer_reservation(
            ANVIL_CHAIN_ID,
            &signer,
            &fixture.config.journal_path,
            &binding,
            "submit",
            &fixture.deployment.manager,
            &binding.submit_calldata_hash,
            None,
        )
        .expect("submit reservation");
        let finalize_calldata =
            finalize_calldata(&fixture.prepared.expected, 1).expect("guarded finalize calldata");
        let finalize_calldata_hash =
            keccak_hex(&decode_hex(&finalize_calldata, None, "guarded finalize calldata").unwrap());
        let sibling = close_signer_reservation(
            ANVIL_CHAIN_ID,
            &signer,
            &fixture.config.journal_path,
            &binding,
            "finalize",
            &fixture.deployment.manager,
            &finalize_calldata_hash,
            Some(1),
        )
        .expect("sibling reservation");
        let transaction = backend
            .sign_transaction(
                &fixture.config.account,
                ANVIL_CHAIN_ID,
                &signer,
                &fixture.deployment.manager,
                &fixture.prepared.submit_calldata,
            )
            .expect("local losing transaction");
        let mut journal = PublicationJournal {
            version: JOURNAL_VERSION,
            binding,
            submitter: signer.clone(),
            attest: None,
            attest_observation: None,
            submit: Some(TransactionStep {
                transaction: transaction.clone(),
                confirmation: None,
                superseded_confirmation: None,
            }),
            submit_observation: None,
            finalize_authorization: None,
            finalize: None,
            finalize_observation: None,
            materialize: None,
            materialize_observation: None,
            completed: None,
        };
        write_journal(&fixture.config.journal_path, &journal).expect("persist local raw first");
        let winning_block = backend.blocks.get(&10).expect("winning block").clone();
        let winner = FinalizedReceipt {
            transaction_hash: repeated(0xee),
            block_hash: winning_block.hash.to_string(),
            block_number: winning_block.number,
            transaction_index: 0,
            finalized_checkpoint: backend.checkpoint(),
        };

        let progress = reconcile_semantic_winner(
            &fixture.config,
            &mut backend,
            &mut journal,
            ClosePhase::Submit,
            &winner,
            &reservation,
            &signer,
        )
        .expect("publish exact losing raw")
        .expect("losing raw still needs its receipt");
        assert!(matches!(
            progress,
            PublicCloseProgress::AwaitingSupersededReceipt { .. }
        ));
        assert_eq!(
            backend.publish_attempts,
            [transaction.raw_signed_transaction.clone()]
        );
        assert!(
            l1_signer_reservation::claim(&fixture.config.signer_lock_root, &sibling).is_err(),
            "the winner cannot free a nonce whose local losing raw is still unsettled"
        );

        let losing_block = block(11, 1_001);
        backend.blocks.insert(11, losing_block.clone());
        backend.head = 11;
        let mut failed_receipt =
            receipt_with_events(&transaction, &signer, &losing_block, Vec::new());
        failed_receipt["status"] = Value::String("0x0".into());
        backend
            .receipts
            .insert(transaction.transaction_hash.clone(), failed_receipt);
        assert!(reconcile_semantic_winner(
            &fixture.config,
            &mut backend,
            &mut journal,
            ClosePhase::Submit,
            &winner,
            &reservation,
            &signer,
        )
        .expect("canonical-finalized loser revert")
        .is_none());
        assert!(
            journal
                .submit
                .as_ref()
                .and_then(|step| step.superseded_confirmation.as_ref())
                .is_some(),
            "the failed receipt is durable before lease release"
        );
        l1_signer_reservation::claim(&fixture.config.signer_lock_root, &sibling)
            .expect("later signer work may proceed only after the loser is finalized");
        l1_signer_reservation::release(&fixture.config.signer_lock_root, &sibling)
            .expect("release sibling test lease");
    }

    #[test]
    fn full_lifecycle_uses_guarded_finalize_and_revalidates_completion() {
        let fixture = fixture("lifecycle");
        let mut backend = attested_backend(&fixture);
        submit_and_confirm(&fixture, &mut backend);
        make_finalize_eligible(&fixture, &mut backend);
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("broadcast finalize"),
            PublicCloseProgress::FinalizeBroadcast { .. }
        ));
        assert_eq!(backend.sign_count, 2);
        assert_eq!(backend.publish_attempts, ["0x01", "0x02"]);
        let journal: PublicationJournal =
            serde_json::from_slice(&fs::read(&fixture.config.journal_path).unwrap()).unwrap();
        let authorization = journal
            .finalize_authorization
            .expect("durable finalize authorization");
        assert_eq!(authorization.close_request_generation, 1);
        assert!(authorization
            .calldata
            .starts_with(&selector(FINALIZE_CLOSE_GUARDED_SIGNATURE)));
        assert!(!authorization
            .calldata
            .starts_with(&selector("finalizeClose()")));

        let finalized_block = block(13, 1_102);
        let transaction = backend.transaction(1);
        backend.blocks.insert(13, finalized_block.clone());
        backend.managers.insert(
            13,
            closed(&fixture.prepared.expected, finalized_block.timestamp),
        );
        backend.receipts.insert(
            transaction.transaction_hash.clone(),
            receipt(
                &transaction,
                &backend.signer,
                &finalized_block,
                finalize_event(&fixture.deployment.manager, &fixture.prepared.expected),
            ),
        );
        backend.head = 13;
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend)
                .expect("confirm close and broadcast signed-head materialization"),
            PublicCloseProgress::MaterializeBroadcast { .. }
        ));
        assert_eq!(backend.sign_count, 3);
        assert_eq!(backend.publish_attempts, ["0x01", "0x02", "0x03"]);
        let materialized_block = block(14, 1_103);
        let materialize = backend.transaction(2);
        backend.blocks.insert(14, materialized_block.clone());
        backend.managers.insert(
            14,
            closed(&fixture.prepared.expected, materialized_block.timestamp),
        );
        backend.receipts.insert(
            materialize.transaction_hash.clone(),
            receipt(
                &materialize,
                &backend.signer,
                &materialized_block,
                materialize_event(&fixture),
            ),
        );
        backend.deployment.materialized_channel_exit =
            fixture.prepared.expected.close_intent_digest.clone();
        backend.head = 14;
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("complete materialization"),
            PublicCloseProgress::Complete { .. }
        ));
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("revalidate completed WAL"),
            PublicCloseProgress::Complete { .. }
        ));
    }

    #[test]
    fn materialize_broadcast_failure_restarts_with_exact_fsynced_raw_bytes() {
        let fixture = fixture("materialize-restart");
        let mut backend = attested_backend(&fixture);
        submit_and_confirm(&fixture, &mut backend);
        make_finalize_eligible(&fixture, &mut backend);
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("broadcast finalize"),
            PublicCloseProgress::FinalizeBroadcast { .. }
        ));
        backend.fail_publish_attempts.insert(3);

        let finalized_block = block(13, 1_102);
        let finalize = backend.transaction(1);
        backend.blocks.insert(13, finalized_block.clone());
        backend.managers.insert(
            13,
            closed(&fixture.prepared.expected, finalized_block.timestamp),
        );
        backend.receipts.insert(
            finalize.transaction_hash.clone(),
            receipt(
                &finalize,
                &backend.signer,
                &finalized_block,
                finalize_event(&fixture.deployment.manager, &fixture.prepared.expected),
            ),
        );
        backend.head = 13;
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(error.to_string().contains("injected post-WAL"));
        assert_eq!(backend.sign_count, 3);
        assert!(fs::read_to_string(&fixture.config.journal_path)
            .unwrap()
            .contains("0x03"));

        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend)
                .expect("replay exact materialization"),
            PublicCloseProgress::MaterializeBroadcast { .. }
        ));
        assert_eq!(
            backend.sign_count, 3,
            "restart must not sign replacement bytes"
        );
        assert_eq!(backend.publish_attempts, ["0x01", "0x02", "0x03", "0x03"]);
    }

    #[test]
    fn permissionless_materialization_is_adopted_without_local_signature() {
        let fixture = fixture("adopt-materialize");
        let mut backend = attested_backend(&fixture);
        submit_and_confirm(&fixture, &mut backend);
        make_finalize_eligible(&fixture, &mut backend);
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("broadcast finalize"),
            PublicCloseProgress::FinalizeBroadcast { .. }
        ));
        let finalized_block = block(13, 1_102);
        let finalize = backend.transaction(1);
        backend.blocks.insert(13, finalized_block.clone());
        backend.managers.insert(
            13,
            closed(&fixture.prepared.expected, finalized_block.timestamp),
        );
        backend.receipts.insert(
            finalize.transaction_hash.clone(),
            receipt(
                &finalize,
                &backend.signer,
                &finalized_block,
                finalize_event(&fixture.deployment.manager, &fixture.prepared.expected),
            ),
        );
        let external = SignedTransaction {
            target: fixture.deployment.close_funding_materializer.clone(),
            calldata_hash: String::new(),
            nonce: 77,
            raw_signed_transaction: String::new(),
            transaction_hash: repeated(0xe1),
        };
        backend.receipts.insert(
            external.transaction_hash.clone(),
            receipt(
                &external,
                &address(0x66),
                &finalized_block,
                materialize_event(&fixture),
            ),
        );
        backend.deployment.materialized_channel_exit =
            fixture.prepared.expected.close_intent_digest.clone();
        backend.head = 13;

        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend)
                .expect("adopt exact permissionless materialization"),
            PublicCloseProgress::MaterializeAdopted { .. }
        ));
        assert_eq!(
            backend.sign_count, 2,
            "no materialization signature may be created"
        );
        let PublicCloseProgress::Complete { publication } =
            advance_with_backend(&fixture.config, &mut backend).expect("revalidate adoption")
        else {
            panic!("expected completed adopted materialization");
        };
        assert_eq!(
            publication.materialize_transaction_hash,
            external.transaction_hash
        );
    }

    #[test]
    fn completed_materialization_fails_closed_when_its_receipt_disappears() {
        let fixture = fixture("materialize-reorg");
        let mut backend = attested_backend(&fixture);
        submit_and_confirm(&fixture, &mut backend);
        make_finalize_eligible(&fixture, &mut backend);
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("broadcast finalize"),
            PublicCloseProgress::FinalizeBroadcast { .. }
        ));
        let materialize = confirm_finalize_and_begin_materialization(&fixture, &mut backend);
        let materialized_block = block(14, 1_103);
        backend.blocks.insert(14, materialized_block.clone());
        backend.managers.insert(
            14,
            closed(&fixture.prepared.expected, materialized_block.timestamp),
        );
        backend.receipts.insert(
            materialize.transaction_hash.clone(),
            receipt(
                &materialize,
                &backend.signer,
                &materialized_block,
                materialize_event(&fixture),
            ),
        );
        backend.deployment.materialized_channel_exit =
            fixture.prepared.expected.close_intent_digest.clone();
        backend.head = 14;
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("complete materialization"),
            PublicCloseProgress::Complete { .. }
        ));

        backend.receipts.remove(&materialize.transaction_hash);
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(error.to_string().contains("not covered by a durable head"));
    }

    #[test]
    fn submit_broadcast_failure_restarts_with_exact_fsynced_raw_bytes() {
        let fixture = fixture("submit-restart");
        let mut backend = attested_backend(&fixture);
        backend.fail_publish_attempts.insert(1);
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(error.to_string().contains("injected post-WAL"));
        assert_eq!(backend.sign_count, 1);
        assert!(fs::read_to_string(&fixture.config.journal_path)
            .unwrap()
            .contains("0x01"));
        let journal: PublicationJournal =
            serde_json::from_slice(&fs::read(&fixture.config.journal_path).unwrap()).unwrap();
        assert_eq!(
            journal.binding.expected_final_channel_state_digest,
            fixture.config.expected_final_channel_state_digest
        );
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("exact submit replay"),
            PublicCloseProgress::SubmitBroadcast { .. }
        ));
        assert_eq!(backend.sign_count, 1);
        assert_eq!(backend.publish_attempts, ["0x01", "0x01"]);
    }

    #[test]
    fn finalize_broadcast_failure_restarts_with_exact_guarded_transaction() {
        let fixture = fixture("finalize-restart");
        let mut backend = attested_backend(&fixture);
        submit_and_confirm(&fixture, &mut backend);
        make_finalize_eligible(&fixture, &mut backend);
        backend.fail_publish_attempts.insert(2);
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(error.to_string().contains("injected post-WAL"));
        assert_eq!(backend.sign_count, 2);
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("exact finalize replay"),
            PublicCloseProgress::FinalizeBroadcast { .. }
        ));
        assert_eq!(backend.sign_count, 2);
        assert_eq!(backend.publish_attempts, ["0x01", "0x02", "0x02"]);
    }

    #[test]
    fn request_generation_change_after_durable_pin_aborts_before_finalize_signing() {
        let fixture = fixture("finalize-pre-sign-generation-race");
        let mut backend = attested_backend(&fixture);
        submit_and_confirm(&fixture, &mut backend);
        make_finalize_eligible(&fixture, &mut backend);

        let first_era = pending(&fixture.prepared.expected, 1_101, 1_100);
        let mut second_era = first_era.clone();
        second_era.close_request_generation = 2;
        backend.managers.insert(12, second_era.clone());
        // The first pinned read belongs to the attestation revalidation that precedes the close
        // state machine on every invocation; the era rotates only at the pre-sign re-read.
        backend.manager_sequences.insert(
            12,
            [
                first_era.clone(),
                first_era.clone(),
                first_era.clone(),
                first_era,
                second_era,
            ]
            .into_iter()
            .collect(),
        );

        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("close request era changed after durable authorization"),
            "unexpected error: {error}"
        );
        assert_eq!(
            backend.sign_count, 1,
            "only the earlier submit may have been signed"
        );
        let journal: PublicationJournal =
            serde_json::from_slice(&fs::read(&fixture.config.journal_path).unwrap()).unwrap();
        assert_eq!(
            journal
                .finalize_authorization
                .as_ref()
                .expect("pre-sign authorization is durable")
                .close_request_generation,
            1
        );
        assert!(journal.finalize.is_none(), "no finalize raw WAL may exist");

        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend)
                .expect("rotate unsigned authorization to the new request era"),
            PublicCloseProgress::FinalizeBroadcast { .. }
        ));
        assert_eq!(backend.sign_count, 2);
        let journal: PublicationJournal =
            serde_json::from_slice(&fs::read(&fixture.config.journal_path).unwrap()).unwrap();
        assert_eq!(
            journal
                .finalize_authorization
                .expect("replacement authorization")
                .close_request_generation,
            2
        );
        assert!(journal.finalize.is_some(), "new era raw is durable");
    }

    #[test]
    fn journaled_finalize_raw_is_never_replayed_into_a_later_same_digest_era() {
        let fixture = fixture("finalize-generation-replay");
        let mut backend = attested_backend(&fixture);
        submit_and_confirm(&fixture, &mut backend);
        make_finalize_eligible(&fixture, &mut backend);
        backend.fail_publish_attempts.insert(2);
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(error.to_string().contains("injected post-WAL"));
        assert_eq!(backend.sign_count, 2);
        assert_eq!(backend.publish_attempts, ["0x01", "0x02"]);

        let mut later_era = pending(&fixture.prepared.expected, 1_101, 1_100);
        later_era.close_request_generation = 2;
        backend.managers.insert(12, later_era);
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(
            error.to_string().contains("pinned generation 1")
                && error.to_string().contains("current generation 2"),
            "unexpected error: {error}"
        );
        assert_eq!(backend.sign_count, 2, "retry must not sign another raw");
        assert_eq!(
            backend.publish_attempts,
            ["0x01", "0x02"],
            "generation-one raw must not be treated as the generation-two action"
        );
        let journal: PublicationJournal =
            serde_json::from_slice(&fs::read(&fixture.config.journal_path).unwrap()).unwrap();
        let authorization = journal
            .finalize_authorization
            .expect("original generation remains immutable");
        assert_eq!(authorization.close_request_generation, 1);
        assert!(
            journal.finalize.is_some(),
            "exact raw WAL remains recoverable"
        );
    }

    #[test]
    fn exact_permissionless_submit_is_adopted_without_local_signing() {
        let fixture = fixture("adopt-submit");
        let mut backend = attested_backend(&fixture);
        let submitted_block = block(11, 1_001);
        let external = SignedTransaction {
            // The permissionless call may be routed through a watchtower/batch wrapper. Its outer
            // transaction target is not authority; the pinned Manager event and block getters are.
            target: address(0x98),
            calldata_hash: String::new(),
            nonce: 77,
            raw_signed_transaction: String::new(),
            transaction_hash: repeated(0xd0),
        };
        let mut unrelated = fixture.prepared.expected.clone();
        unrelated.final_state_version += 1;
        backend.blocks.insert(11, submitted_block.clone());
        backend.managers.insert(
            11,
            pending(&fixture.prepared.expected, submitted_block.timestamp, 1_100),
        );
        backend.receipts.insert(
            external.transaction_hash.clone(),
            receipt_with_events(
                &external,
                &address(0x66),
                &submitted_block,
                vec![
                    submit_event(&fixture.deployment.manager, &unrelated, 1_050),
                    submit_event(
                        &fixture.deployment.manager,
                        &fixture.prepared.expected,
                        1_100,
                    ),
                ],
            ),
        );
        backend.head = 11;
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("adopt exact submit"),
            PublicCloseProgress::AwaitingChallengeDeadline { .. }
        ));
        assert_eq!(backend.sign_count, 0);
        let journal: PublicationJournal =
            serde_json::from_slice(&fs::read(&fixture.config.journal_path).unwrap()).unwrap();
        assert_eq!(
            journal.submit_observation.unwrap().transaction_hash,
            external.transaction_hash
        );
    }

    #[test]
    fn cancelled_same_digest_history_adopts_only_latest_current_freeze_era() {
        let fixture = fixture("adopt-current-era");
        let mut backend = attested_backend(&fixture);
        // `cancelClose` restores the freeze counter, so the next request can submit the byte-for-
        // byte same proof/digest/freeze nonce. The newly computed deadline and full receipt-block
        // pending vector are the remaining current-era discriminator.
        let old_expected = fixture.prepared.expected.clone();
        let old_block = block(11, 1_001);
        let old = SignedTransaction {
            target: fixture.deployment.manager.clone(),
            calldata_hash: String::new(),
            nonce: 70,
            raw_signed_transaction: String::new(),
            transaction_hash: repeated(0xc0),
        };
        backend.blocks.insert(11, old_block.clone());
        backend
            .managers
            .insert(11, pending(&old_expected, old_block.timestamp, 1_050));
        backend.receipts.insert(
            old.transaction_hash.clone(),
            receipt(
                &old,
                &address(0x61),
                &old_block,
                submit_event(&fixture.deployment.manager, &old_expected, 1_050),
            ),
        );
        backend.head = 11;
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("adopt prior era"),
            PublicCloseProgress::AwaitingChallengeDeadline { .. }
        ));

        let cancelled_block = block(12, 1_010);
        backend.blocks.insert(12, cancelled_block.clone());
        backend.managers.insert(
            12,
            ManagerObservation {
                status: 0,
                current_close_freeze_nonce: old_expected.close_freeze_nonce,
                close_request_generation: 1,
                close_requested_at: 0,
                close_challenge_horizon: 0,
                block_timestamp: cancelled_block.timestamp,
                pending: None,
                finalized: None,
            },
        );

        let current_block = block(13, 1_020);
        let current = SignedTransaction {
            target: fixture.deployment.manager.clone(),
            calldata_hash: String::new(),
            nonce: 71,
            raw_signed_transaction: String::new(),
            transaction_hash: repeated(0xc1),
        };
        backend.blocks.insert(13, current_block.clone());
        let mut current_pending =
            pending(&fixture.prepared.expected, current_block.timestamp, 1_200);
        current_pending.close_request_generation = 2;
        backend.managers.insert(13, current_pending);
        backend.receipts.insert(
            current.transaction_hash.clone(),
            receipt(
                &current,
                &address(0x62),
                &current_block,
                submit_event(
                    &fixture.deployment.manager,
                    &fixture.prepared.expected,
                    1_200,
                ),
            ),
        );
        backend.head = 13;

        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("adopt current era"),
            PublicCloseProgress::AwaitingChallengeDeadline { .. }
        ));
        assert_eq!(backend.sign_count, 0);
        let journal: PublicationJournal =
            serde_json::from_slice(&fs::read(&fixture.config.journal_path).unwrap()).unwrap();
        assert_eq!(
            journal.submit_observation.unwrap().transaction_hash,
            current.transaction_hash
        );
    }

    #[test]
    fn ambiguous_latest_current_era_position_fails_closed() {
        let fixture = fixture("ambiguous-current-era");
        let mut backend = attested_backend(&fixture);
        let submitted_block = block(11, 1_001);
        backend.blocks.insert(11, submitted_block.clone());
        backend.managers.insert(
            11,
            pending(&fixture.prepared.expected, submitted_block.timestamp, 1_100),
        );
        for (hash_byte, signer_byte) in [(0xc2, 0x63), (0xc3, 0x64)] {
            let external = SignedTransaction {
                target: fixture.deployment.manager.clone(),
                calldata_hash: String::new(),
                nonce: u64::from(hash_byte),
                raw_signed_transaction: String::new(),
                transaction_hash: repeated(hash_byte),
            };
            backend.receipts.insert(
                external.transaction_hash.clone(),
                receipt(
                    &external,
                    &address(signer_byte),
                    &submitted_block,
                    submit_event(
                        &fixture.deployment.manager,
                        &fixture.prepared.expected,
                        1_100,
                    ),
                ),
            );
        }
        backend.head = 11;
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(error
            .to_string()
            .contains("ambiguous latest transaction position"));
        assert_eq!(backend.sign_count, 0);
    }

    #[test]
    fn exact_permissionless_finalize_is_adopted_without_local_finalizer() {
        let fixture = fixture("adopt-finalize");
        let mut backend = attested_backend(&fixture);
        submit_and_confirm(&fixture, &mut backend);
        let finalized_block = block(13, 1_102);
        let external = SignedTransaction {
            target: address(0x99),
            calldata_hash: String::new(),
            nonce: 88,
            raw_signed_transaction: String::new(),
            transaction_hash: repeated(0xd1),
        };
        let mut unrelated = fixture.prepared.expected.clone();
        unrelated.final_state_version += 1;
        backend.blocks.insert(13, finalized_block.clone());
        backend.managers.insert(
            13,
            closed(&fixture.prepared.expected, finalized_block.timestamp),
        );
        backend.receipts.insert(
            external.transaction_hash.clone(),
            receipt_with_events(
                &external,
                &address(0x67),
                &finalized_block,
                vec![
                    finalize_event(&fixture.deployment.manager, &unrelated),
                    finalize_event(&fixture.deployment.manager, &fixture.prepared.expected),
                ],
            ),
        );
        backend.head = 13;
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("adopt exact finalize"),
            PublicCloseProgress::MaterializeBroadcast { .. }
        ));
        assert_eq!(
            backend.sign_count, 2,
            "only submit and materialize may be signed"
        );
        let materialized_block = block(14, 1_103);
        let materialize = backend.transaction(1);
        backend.blocks.insert(14, materialized_block.clone());
        backend.managers.insert(
            14,
            closed(&fixture.prepared.expected, materialized_block.timestamp),
        );
        backend.receipts.insert(
            materialize.transaction_hash.clone(),
            receipt(
                &materialize,
                &backend.signer,
                &materialized_block,
                materialize_event(&fixture),
            ),
        );
        backend.deployment.materialized_channel_exit =
            fixture.prepared.expected.close_intent_digest.clone();
        backend.head = 14;
        let PublicCloseProgress::Complete { publication } =
            advance_with_backend(&fixture.config, &mut backend)
                .expect("complete exact materialization")
        else {
            panic!("expected complete publication");
        };
        assert_eq!(
            publication.finalize_transaction_hash,
            Some(external.transaction_hash)
        );
        assert_eq!(
            publication.materialize_transaction_hash,
            materialize.transaction_hash
        );
    }

    #[test]
    fn permissionless_attestation_winner_is_adopted_and_local_raw_is_superseded() {
        let fixture = fixture("attest-race");
        let mut backend = FakeBackend::new(&fixture);
        let external = external_attestation(&fixture);
        backend.receipts.remove(&external.transaction_hash);
        backend.deployment.exact_backing_proof_attested = false;
        backend.deployment.signed_head_backing_current = false;
        backend.deployment.signed_head_backing_anchor_plus_one = 0;
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend)
                .expect("broadcast the local attestation"),
            PublicCloseProgress::AttestBroadcast { .. }
        ));
        assert_eq!(backend.sign_count, 1);
        assert_eq!(backend.publish_attempts, ["0x01"]);
        let local = backend.transaction(0);
        let journal = read_journal(&fixture);
        assert!(journal.attest.is_some(), "raw attestation bytes are durable");
        assert!(journal.attest_observation.is_none());

        // Another watchtower's attestation of the same exact statement is finalized first.
        let winning_block = block(11, 1_001);
        backend.blocks.insert(11, winning_block.clone());
        backend
            .managers
            .insert(11, requested(&fixture.prepared.expected, 1_001));
        backend.head = 11;
        backend.deployment = observed_deployment(&fixture);
        install_attestation_receipt(&fixture, &mut backend, 11, 0);
        let progress = advance_with_backend(&fixture.config, &mut backend)
            .expect("adopt the permissionless attestation winner");
        assert!(
            matches!(
                progress,
                PublicCloseProgress::AwaitingSupersededReceipt { .. }
            ),
            "the local loser must settle before its nonce lane is released: {progress:?}"
        );
        let journal = read_journal(&fixture);
        assert_eq!(
            journal
                .attest_observation
                .as_ref()
                .expect("winner adopted")
                .transaction_hash,
            external.transaction_hash
        );
        assert_eq!(backend.sign_count, 1, "no second attestation is signed");

        // The local loser finally reverts on-chain; only then does the close machine continue.
        let losing_block = block(12, 1_002);
        backend.blocks.insert(12, losing_block.clone());
        backend
            .managers
            .insert(12, requested(&fixture.prepared.expected, 1_002));
        let signer = backend.signer.clone();
        let mut failed = receipt_with_events(&local, &signer, &losing_block, Vec::new());
        failed["status"] = Value::String("0x0".into());
        backend
            .receipts
            .insert(local.transaction_hash.clone(), failed);
        backend.head = 12;
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend)
                .expect("settle the loser and sign the close submission"),
            PublicCloseProgress::SubmitBroadcast { .. }
        ));
        let journal = read_journal(&fixture);
        assert!(journal
            .attest
            .as_ref()
            .and_then(|step| step.superseded_confirmation.as_ref())
            .is_some());
        assert_eq!(backend.sign_count, 2);
        assert_eq!(backend.publish_attempts, ["0x01", "0x02"]);
    }

    #[test]
    fn close_submitted_in_the_attestation_block_must_follow_the_attestation_index() {
        let fixture = fixture("attest-same-block-order");
        let mut backend = attested_backend(&fixture);
        let head_block = backend.blocks.get(&10).expect("head block").clone();
        backend.managers.insert(
            10,
            pending(&fixture.prepared.expected, head_block.timestamp, 1_100),
        );
        let external = SignedTransaction {
            target: fixture.deployment.manager.clone(),
            calldata_hash: String::new(),
            nonce: 77,
            raw_signed_transaction: String::new(),
            transaction_hash: repeated(0xd4),
        };
        // Same block as the attestation, but mined before it.
        backend.receipts.insert(
            external.transaction_hash.clone(),
            receipt_with_events_at(
                &external,
                &address(0x69),
                &head_block,
                EXTERNAL_ATTESTATION_INDEX - 1,
                vec![submit_event(
                    &fixture.deployment.manager,
                    &fixture.prepared.expected,
                    1_100,
                )],
            ),
        );
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not ordered strictly after the durable backing attestation"),
            "unexpected error: {error}"
        );
        assert_eq!(backend.sign_count, 0);
        assert!(read_journal(&fixture).submit_observation.is_none());

        // Same block, strictly later transaction index: canonical.
        backend
            .receipts
            .get_mut(&external.transaction_hash)
            .unwrap()["transactionIndex"] =
            Value::String(format!("0x{:x}", EXTERNAL_ATTESTATION_INDEX + 1));
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend)
                .expect("adopt the later same-block submission"),
            PublicCloseProgress::AwaitingChallengeDeadline { .. }
        ));
        let submitted = read_journal(&fixture)
            .submit_observation
            .expect("adopted submission");
        assert_eq!(submitted.transaction_hash, external.transaction_hash);
        assert_eq!(
            (submitted.block_number, submitted.transaction_index),
            (10, EXTERNAL_ATTESTATION_INDEX + 1)
        );
    }

    #[test]
    fn local_submit_receipt_ordered_before_the_attestation_is_rejected() {
        let fixture = fixture("local-submit-before-attest");
        let mut backend = attested_backend(&fixture);
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("broadcast submit"),
            PublicCloseProgress::SubmitBroadcast { .. }
        ));
        // A substituted RPC view claims our own submission landed before the attestation.
        let head_block = backend.blocks.get(&10).expect("head block").clone();
        backend.managers.insert(
            10,
            pending(&fixture.prepared.expected, head_block.timestamp, 1_100),
        );
        let transaction = backend.transaction(0);
        let signer = backend.signer.clone();
        backend.receipts.insert(
            transaction.transaction_hash.clone(),
            receipt_with_events_at(
                &transaction,
                &signer,
                &head_block,
                EXTERNAL_ATTESTATION_INDEX - 1,
                vec![submit_event(
                    &fixture.deployment.manager,
                    &fixture.prepared.expected,
                    1_100,
                )],
            ),
        );
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(
            error.to_string().contains("not ordered strictly after"),
            "unexpected error: {error}"
        );
        assert!(read_journal(&fixture).submit_observation.is_none());
        assert_eq!(backend.sign_count, 1);
    }

    #[test]
    fn adopted_attestation_is_revalidated_and_fails_closed_after_reorg() {
        let fixture = fixture("attest-reorg");
        let mut backend = attested_backend(&fixture);
        backend.blocks.get_mut(&10).unwrap().hash = word(0xec);
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(
            error.to_string().contains("orphaned"),
            "unexpected error: {error}"
        );
        assert_eq!(backend.sign_count, 0);
    }

    #[test]
    fn foreign_attestation_events_are_filtered_and_duplicate_exact_attestations_fail_closed() {
        let fixture = fixture("attest-foreign");
        let mut backend = FakeBackend::new(&fixture);
        let head_block = backend.blocks.get(&10).expect("head block").clone();
        // Same channel topic, different statement key: not this exact backing statement.
        let mut foreign = attestation_event(&fixture);
        foreign["topics"][3] = Value::String(repeated(0xdf));
        let stranger = SignedTransaction {
            target: fixture.deployment.close_funding_materializer.clone(),
            calldata_hash: String::new(),
            nonce: 5,
            raw_signed_transaction: String::new(),
            transaction_hash: repeated(0xbc),
        };
        backend.receipts.insert(
            stranger.transaction_hash.clone(),
            receipt_with_events_at(&stranger, &address(0x78), &head_block, 0, vec![foreign]),
        );
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend)
                .expect("the exact attestation remains unique"),
            PublicCloseProgress::AttestAdopted { .. }
        ));
        assert_eq!(
            read_journal(&fixture)
                .attest_observation
                .expect("adopted")
                .transaction_hash,
            repeated(0xbb)
        );

        let fixture = self::fixture("attest-duplicate");
        let mut backend = FakeBackend::new(&fixture);
        let head_block = backend.blocks.get(&10).expect("head block").clone();
        let duplicate = SignedTransaction {
            target: fixture.deployment.close_funding_materializer.clone(),
            calldata_hash: String::new(),
            nonce: 6,
            raw_signed_transaction: String::new(),
            transaction_hash: repeated(0xbd),
        };
        backend.receipts.insert(
            duplicate.transaction_hash.clone(),
            receipt_with_events_at(
                &duplicate,
                &address(0x79),
                &head_block,
                2,
                vec![attestation_event(&fixture)],
            ),
        );
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(
            error.to_string().contains("provenance count 2 != 1"),
            "unexpected error: {error}"
        );
        assert_eq!(backend.sign_count, 0);
    }

    #[test]
    fn completed_publication_attestation_provenance_and_schema_are_revalidated() {
        let fixture = fixture("completed-attest-provenance");
        let mut backend = attested_backend(&fixture);
        submit_and_confirm(&fixture, &mut backend);
        make_finalize_eligible(&fixture, &mut backend);
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend).expect("broadcast finalize"),
            PublicCloseProgress::FinalizeBroadcast { .. }
        ));
        let materialize = confirm_finalize_and_begin_materialization(&fixture, &mut backend);
        let materialized_block = block(14, 1_103);
        backend.blocks.insert(14, materialized_block.clone());
        backend.managers.insert(
            14,
            closed(&fixture.prepared.expected, materialized_block.timestamp),
        );
        let signer = backend.signer.clone();
        backend.receipts.insert(
            materialize.transaction_hash.clone(),
            receipt(
                &materialize,
                &signer,
                &materialized_block,
                materialize_event(&fixture),
            ),
        );
        backend.deployment.materialized_channel_exit =
            fixture.prepared.expected.close_intent_digest.clone();
        backend.head = 14;
        let PublicCloseProgress::Complete { publication } =
            advance_with_backend(&fixture.config, &mut backend).expect("complete materialization")
        else {
            panic!("expected complete publication");
        };
        assert_eq!(publication.schema_version, PUBLICATION_VERSION);
        assert_eq!(publication.attest_transaction_hash, repeated(0xbb));

        let path = &fixture.config.journal_path;
        let original = fs::read(path).unwrap();
        let mut tampered: Value = serde_json::from_slice(&original).unwrap();
        tampered["completed"]["attestTransactionHash"] = Value::String(repeated(0xcc));
        fs::write(path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(
            error.to_string().contains("attestation provenance"),
            "unexpected error: {error}"
        );

        let mut tampered: Value = serde_json::from_slice(&original).unwrap();
        tampered["completed"]["schemaVersion"] = Value::from(PUBLICATION_VERSION - 1);
        fs::write(path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(
            error.to_string().contains("attestation provenance"),
            "unexpected error: {error}"
        );

        fs::write(path, &original).unwrap();
        assert!(matches!(
            advance_with_backend(&fixture.config, &mut backend)
                .expect("the exact completed journal revalidates"),
            PublicCloseProgress::Complete { .. }
        ));
        assert_eq!(backend.sign_count, 3);
    }

    #[test]
    fn journal_load_rejects_close_provenance_at_or_before_the_attestation() {
        let fixture = fixture("journal-attest-order");
        ensure_private_directory(
            fixture
                .config
                .journal_path
                .parent()
                .expect("journal parent"),
        )
        .expect("private journal parent");
        let backend = FakeBackend::new(&fixture);
        let signer = backend.signer.clone();
        let binding = make_binding(
            &fixture.prepared,
            &fixture.deployment,
            fixture.config.deployment_manifest_sha256.clone(),
            &fixture.config.signer_lock_root,
        )
        .expect("publication binding");
        let head_block = backend.blocks.get(&10).expect("head block").clone();
        let attested = FinalizedReceipt {
            transaction_hash: repeated(0xbb),
            block_hash: head_block.hash.to_string(),
            block_number: head_block.number,
            transaction_index: EXTERNAL_ATTESTATION_INDEX,
            finalized_checkpoint: backend.checkpoint(),
        };
        let mut submitted = attested.clone();
        submitted.transaction_hash = repeated(0xd5);
        let mut journal = PublicationJournal {
            version: JOURNAL_VERSION,
            binding: binding.clone(),
            submitter: signer.clone(),
            attest: None,
            attest_observation: Some(attested),
            submit: None,
            submit_observation: Some(submitted.clone()),
            finalize_authorization: None,
            finalize: None,
            finalize_observation: None,
            materialize: None,
            materialize_observation: None,
            completed: None,
        };
        write_journal(&fixture.config.journal_path, &journal).expect("persist journal");
        let error =
            load_or_create_journal(&fixture.config.journal_path, binding.clone(), &signer)
                .unwrap_err();
        assert!(
            error.to_string().contains("not ordered strictly after"),
            "unexpected error: {error}"
        );

        submitted.transaction_index = EXTERNAL_ATTESTATION_INDEX + 1;
        journal.submit_observation = Some(submitted);
        write_journal(&fixture.config.journal_path, &journal).expect("persist journal");
        load_or_create_journal(&fixture.config.journal_path, binding, &signer)
            .expect("a strictly later same-block submission loads");
    }

    #[test]
    fn duplicate_fully_matching_manager_events_are_ambiguous() {
        let fixture = fixture("duplicate-exact-events");
        let block = block(11, 1_001);
        let external = SignedTransaction {
            target: address(0x97),
            calldata_hash: String::new(),
            nonce: 90,
            raw_signed_transaction: String::new(),
            transaction_hash: repeated(0xd3),
        };
        let pending = pending(&fixture.prepared.expected, block.timestamp, 1_100)
            .pending
            .expect("pending close");
        let submit = submit_event(
            &fixture.deployment.manager,
            &fixture.prepared.expected,
            1_100,
        );
        let submit_receipt = receipt_with_events(
            &external,
            &address(0x65),
            &block,
            vec![submit.clone(), submit],
        );
        let error =
            validate_close_submitted_event(&submit_receipt, &fixture.deployment.manager, &pending)
                .unwrap_err();
        assert!(error.to_string().contains("exact provenance is ambiguous"));

        let finalized = finalize_event(&fixture.deployment.manager, &fixture.prepared.expected);
        let finalize_receipt = receipt_with_events(
            &external,
            &address(0x65),
            &block,
            vec![finalized.clone(), finalized],
        );
        let error = validate_close_finalized_event(
            &finalize_receipt,
            &fixture.deployment.manager,
            &fixture.prepared.expected,
        )
        .unwrap_err();
        assert!(error.to_string().contains("exact provenance is ambiguous"));
    }

    #[test]
    fn adopted_submit_is_revalidated_and_fails_closed_after_reorg() {
        let fixture = fixture("adopt-reorg");
        let mut backend = attested_backend(&fixture);
        let submitted_block = block(11, 1_001);
        let external = SignedTransaction {
            target: fixture.deployment.manager.clone(),
            calldata_hash: String::new(),
            nonce: 77,
            raw_signed_transaction: String::new(),
            transaction_hash: repeated(0xd2),
        };
        backend.blocks.insert(11, submitted_block.clone());
        backend.managers.insert(
            11,
            pending(&fixture.prepared.expected, submitted_block.timestamp, 1_100),
        );
        backend.receipts.insert(
            external.transaction_hash.clone(),
            receipt(
                &external,
                &address(0x68),
                &submitted_block,
                submit_event(
                    &fixture.deployment.manager,
                    &fixture.prepared.expected,
                    1_100,
                ),
            ),
        );
        backend.head = 11;
        advance_with_backend(&fixture.config, &mut backend).expect("adopt submit");
        backend.blocks.get_mut(&11).unwrap().hash = word(0xed);
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        // The reorg is detected either by the attestation revalidation (the durable checkpoint it
        // was confirmed under was replaced at the same height) or by the orphaned submit receipt;
        // both stop the publisher before any further signing.
        assert!(
            error.to_string().contains("receipt is orphaned")
                || error
                    .to_string()
                    .contains("replaced at the same height"),
            "unexpected error: {error}"
        );
        assert_eq!(backend.sign_count, 0);
        assert!(read_journal(&fixture).finalize_authorization.is_none());
    }

    #[test]
    fn orphaned_submit_receipt_is_rejected() {
        let fixture = fixture("orphan");
        let mut backend = attested_backend(&fixture);
        advance_with_backend(&fixture.config, &mut backend).expect("submit");
        let event = submit_event(
            &fixture.deployment.manager,
            &fixture.prepared.expected,
            1_100,
        );
        install_submit_receipt(&fixture, &mut backend, event);
        let transaction = backend.transaction(0);
        backend
            .receipts
            .get_mut(&transaction.transaction_hash)
            .unwrap()["blockHash"] = Value::String(repeated(0xee));
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(error.to_string().contains("receipt is orphaned"));
    }

    #[test]
    fn wrong_submit_event_and_wrong_receipt_block_getter_are_rejected() {
        let event_fixture = fixture("event-getter");
        let mut backend = attested_backend(&event_fixture);
        advance_with_backend(&event_fixture.config, &mut backend).expect("submit");
        let mut event = submit_event(
            &event_fixture.deployment.manager,
            &event_fixture.prepared.expected,
            1_100,
        );
        event["topics"][1] = Value::String(repeated(0xdd));
        install_submit_receipt(&event_fixture, &mut backend, event);
        let error = advance_with_backend(&event_fixture.config, &mut backend).unwrap_err();
        assert!(error.to_string().contains("provenance is missing"));

        let fixture = fixture("getter");
        let mut backend = attested_backend(&fixture);
        advance_with_backend(&fixture.config, &mut backend).expect("submit");
        install_submit_receipt(
            &fixture,
            &mut backend,
            submit_event(
                &fixture.deployment.manager,
                &fixture.prepared.expected,
                1_100,
            ),
        );
        backend
            .managers
            .get_mut(&11)
            .unwrap()
            .pending
            .as_mut()
            .unwrap()
            .final_balance_state_h1 = repeated(0xcc);
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(error.to_string().contains("getters differ"));
    }

    #[test]
    fn finalized_per_token_payout_cap_mismatch_is_rejected() {
        let fixture = fixture("payout-cap");
        let mut backend = attested_backend(&fixture);
        submit_and_confirm(&fixture, &mut backend);
        make_finalize_eligible(&fixture, &mut backend);
        advance_with_backend(&fixture.config, &mut backend).expect("finalize");
        let finalized_block = block(13, 1_102);
        let transaction = backend.transaction(1);
        let mut manager = closed(&fixture.prepared.expected, finalized_block.timestamp);
        manager.finalized.as_mut().unwrap().finalized_fund_caps[1] = "39".into();
        backend.blocks.insert(13, finalized_block.clone());
        backend.managers.insert(13, manager);
        backend.receipts.insert(
            transaction.transaction_hash.clone(),
            receipt(
                &transaction,
                &backend.signer,
                &finalized_block,
                finalize_event(&fixture.deployment.manager, &fixture.prepared.expected),
            ),
        );
        backend.head = 13;
        let error = advance_with_backend(&fixture.config, &mut backend).unwrap_err();
        assert!(error.to_string().contains("different"));
    }

    #[test]
    fn same_height_durable_head_replacement_is_rejected() {
        let fixture = fixture("reorg");
        let mut backend = FakeBackend::new(&fixture);
        let canonical = backend.checkpoint();
        let replacement = L1FinalizedCheckpoint {
            block_hash: word(0xef),
            parent_hash: word(0xee),
            ..canonical
        };
        backend.checkpoint_sequence.push_back(canonical);
        backend.checkpoint_sequence.push_back(replacement);
        let error = read_stable_context(&mut backend, &fixture.deployment, &fixture.prepared, true)
            .unwrap_err();
        assert!(error.to_string().contains("replaced at the same height"));
    }

    #[test]
    fn trusted_final_head_digest_rejects_coherent_stale_bundle_before_wal_or_signing() {
        let fixture = fixture("trusted-head-mismatch");
        let mut config = fixture.config.clone();
        config.expected_final_channel_state_digest = repeated(0xfe);
        let mut backend = FakeBackend::new(&fixture);

        let error = advance_with_backend(&config, &mut backend).unwrap_err();
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("proof-bound finalChannelStateDigest"));
        assert!(diagnostic.contains("independently trusted"));
        assert!(diagnostic.contains("regenerate it explicitly"));
        assert_eq!(backend.sign_count, 0);
        assert!(!config.journal_path.exists());
    }

    #[test]
    fn schema_v3_bundle_binds_every_backing_component() {
        let fixture = fixture("schema-v3-components");
        assert_eq!(fixture.prepared.component_hashes.len(), 10);
        for name in [
            "public_close_manifest.json",
            "close_proof.bin",
            "close_intent_mle.json",
            "backing_proof.bin",
            "backing_mle.json",
            "backing_mle_config.json",
            "backing_public_inputs.json",
            "close_intent.json",
            "close_intent_full.json",
            "close_public_inputs.json",
        ] {
            let bytes = fs::read(fixture.config.bundle_dir.join(name)).expect("read component");
            assert_eq!(
                fixture.prepared.component_hashes.get(name),
                Some(&sha256_hex(&bytes)),
                "component {name} must be bound into the durable artifact hash"
            );
        }
    }

    #[test]
    fn legacy_or_partial_backing_bundle_is_rejected_fail_closed() {
        let legacy = fixture("legacy-schema");
        mutate_manifest(&legacy.config.bundle_dir, |manifest| {
            manifest["schemaVersion"] = serde_json::json!(PUBLIC_CLOSE_MANIFEST_VERSION - 1);
        });
        let error = prepare_bundle(
            &legacy.config.bundle_dir,
            &legacy.config.expected_final_channel_state_digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("manifest version/context"));

        for (label, missing) in [
            ("missing-backing-proof", "backing_proof.bin"),
            ("missing-backing-mle", "backing_mle.json"),
            ("missing-backing-mle-config", "backing_mle_config.json"),
            ("missing-backing-pis", "backing_public_inputs.json"),
        ] {
            let fixture = fixture(label);
            fs::remove_file(fixture.config.bundle_dir.join(missing)).expect("remove component");
            let error = prepare_bundle(
                &fixture.config.bundle_dir,
                &fixture.config.expected_final_channel_state_digest,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("inspect signed-head backing"),
                "unexpected {missing} diagnostic: {error}"
            );
        }
    }

    #[test]
    fn backing_hash_size_root_and_anchor_are_manifest_pinned() {
        let hash_fixture = fixture("backing-hash");
        let path = hash_fixture.config.bundle_dir.join("backing_proof.bin");
        let mut proof = fs::read(&path).expect("read backing proof");
        proof[0] ^= 1;
        fs::write(&path, proof).expect("same-length proof tamper");
        let error = prepare_bundle(
            &hash_fixture.config.bundle_dir,
            &hash_fixture.config.expected_final_channel_state_digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("backingProof SHA-256"));

        let size_fixture = fixture("backing-size");
        mutate_manifest(&size_fixture.config.bundle_dir, |manifest| {
            manifest["backingProofBytes"] = serde_json::json!(999);
        });
        let error = prepare_bundle(
            &size_fixture.config.bundle_dir,
            &size_fixture.config.expected_final_channel_state_digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("size differs from manifest"));

        let root_fixture = fixture("backing-root");
        mutate_manifest(&root_fixture.config.bundle_dir, |manifest| {
            manifest["backingFinalizedExtendedStateCommitment"] = Value::String(repeated(0xee));
        });
        let error = prepare_bundle(
            &root_fixture.config.bundle_dir,
            &root_fixture.config.expected_final_channel_state_digest,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("finalizedExtendedStateCommitment differs from manifest"));

        let anchor_fixture = fixture("backing-anchor");
        mutate_manifest(&anchor_fixture.config.bundle_dir, |manifest| {
            manifest["backingAnchorBlockNumber"] = serde_json::json!(17);
        });
        let error = prepare_bundle(
            &anchor_fixture.config.bundle_dir,
            &anchor_fixture.config.expected_final_channel_state_digest,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("anchorBlockNumber differs from manifest"));
    }

    #[test]
    fn backing_public_inputs_require_exact_typed_26_limb_vector_and_mle_equality() {
        let count_fixture = fixture("backing-pi-count");
        let path = count_fixture
            .config
            .bundle_dir
            .join("backing_public_inputs.json");
        let mut inputs: Vec<u64> =
            serde_json::from_slice(&fs::read(&path).expect("read backing PIs"))
                .expect("parse backing PIs");
        inputs.pop();
        write_json(&path, &inputs);
        refresh_manifest_hash(
            &count_fixture.config.bundle_dir,
            "backingPublicInputsSha256",
            "backing_public_inputs.json",
        );
        let error = prepare_bundle(
            &count_fixture.config.bundle_dir,
            &count_fixture.config.expected_final_channel_state_digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("required 26"));

        let type_fixture = fixture("backing-pi-type");
        let path = type_fixture
            .config
            .bundle_dir
            .join("backing_public_inputs.json");
        let mut inputs: Value = serde_json::from_slice(&fs::read(&path).expect("read backing PIs"))
            .expect("parse backing PIs");
        inputs[1] = serde_json::json!(u64::from(u32::MAX) + 1);
        write_json(&path, &inputs);
        refresh_manifest_hash(
            &type_fixture.config.bundle_dir,
            "backingPublicInputsSha256",
            "backing_public_inputs.json",
        );
        let error = prepare_bundle(
            &type_fixture.config.bundle_dir,
            &type_fixture.config.expected_final_channel_state_digest,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("parse signed-head backing public inputs"));

        let json_type_fixture = fixture("backing-pi-json-type");
        let path = json_type_fixture
            .config
            .bundle_dir
            .join("backing_public_inputs.json");
        let mut inputs: Value = serde_json::from_slice(&fs::read(&path).expect("read backing PIs"))
            .expect("parse backing PIs");
        inputs[0] = Value::String("7".into());
        write_json(&path, &inputs);
        refresh_manifest_hash(
            &json_type_fixture.config.bundle_dir,
            "backingPublicInputsSha256",
            "backing_public_inputs.json",
        );
        let error = prepare_bundle(
            &json_type_fixture.config.bundle_dir,
            &json_type_fixture.config.expected_final_channel_state_digest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("must be a JSON u64 number"));

        // A wire-v3 fixture cannot be edited in place: any byte change breaks strict canonical
        // parsing, and a re-proved fixture over other limbs differs from the separate PI file.
        let mle_fixture = fixture("backing-mle-pis");
        let path = mle_fixture.config.bundle_dir.join("backing_mle.json");
        let mut mle: Value = serde_json::from_slice(&fs::read(&path).expect("read backing MLE"))
            .expect("parse backing MLE");
        mle["proof"]["publicInputs"][0] = Value::String("0x0000000000000008".into());
        write_json(&path, &mle);
        let rewritten_len = fs::read(&path).expect("read rewritten backing MLE").len();
        mutate_manifest(&mle_fixture.config.bundle_dir, |manifest| {
            manifest["backingMleBytes"] = serde_json::json!(rewritten_len);
        });
        refresh_manifest_hash(
            &mle_fixture.config.bundle_dir,
            "backingMleSha256",
            "backing_mle.json",
        );
        let error = prepare_bundle(
            &mle_fixture.config.bundle_dir,
            &mle_fixture.config.expected_final_channel_state_digest,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("inspect signed-head backing MLE fixture"),
            "unexpected diagnostic: {error}"
        );

        let reproved_fixture = fixture("backing-mle-reproved");
        let inputs_path = reproved_fixture
            .config
            .bundle_dir
            .join("backing_public_inputs.json");
        let original_inputs: Vec<u64> =
            serde_json::from_slice(&fs::read(&inputs_path).expect("read backing PIs"))
                .expect("parse backing PIs");
        let mut other_inputs = original_inputs.clone();
        other_inputs[0] = 8;
        rewrite_backing_statement(&reproved_fixture.config.bundle_dir, &other_inputs);
        // Restore the separate PI file to the signed vector: the fixture now disagrees with it.
        write_json(&inputs_path, &original_inputs);
        refresh_manifest_hash(
            &reproved_fixture.config.bundle_dir,
            "backingPublicInputsSha256",
            "backing_public_inputs.json",
        );
        let error = prepare_bundle(
            &reproved_fixture.config.bundle_dir,
            &reproved_fixture.config.expected_final_channel_state_digest,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("differs from backing_public_inputs.json"),
            "unexpected diagnostic: {error}"
        );

        let config_fixture = fixture("backing-mle-config");
        let config_path = config_fixture
            .config
            .bundle_dir
            .join("backing_mle_config.json");
        let mut config: Value =
            serde_json::from_slice(&fs::read(&config_path).expect("read backing MLE config"))
                .expect("parse backing MLE config");
        config["pinnedVerifier"]["whirSessionId"] = Value::String(repeated(0xab));
        write_json(&config_path, &config);
        let rewritten_len = fs::read(&config_path).expect("read rewritten config").len();
        mutate_manifest(&config_fixture.config.bundle_dir, |manifest| {
            manifest["backingMleConfigBytes"] = serde_json::json!(rewritten_len);
        });
        refresh_manifest_hash(
            &config_fixture.config.bundle_dir,
            "backingMleConfigSha256",
            "backing_mle_config.json",
        );
        let error = prepare_bundle(
            &config_fixture.config.bundle_dir,
            &config_fixture.config.expected_final_channel_state_digest,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match backing_mle_config.json"),
            "unexpected diagnostic: {error}"
        );
    }

    #[test]
    fn backing_public_inputs_must_compose_with_the_complete_signed_close_vector() {
        for (label, index, replacement, diagnostic) in [
            ("backing-channel", 0usize, 8u64, "channelId differs"),
            (
                "backing-settled-chain",
                1usize,
                u64::from(0x0606_0606u32),
                "settledTxChain differs",
            ),
            (
                "backing-funds",
                9usize,
                u64::from(0x0707_0707u32),
                "tokenFundsDigest differs",
            ),
        ] {
            let case_fixture = fixture(label);
            let inputs_path = case_fixture
                .config
                .bundle_dir
                .join("backing_public_inputs.json");
            let mut inputs: Vec<u64> =
                serde_json::from_slice(&fs::read(&inputs_path).expect("read backing PIs"))
                    .expect("parse backing PIs");
            inputs[index] = replacement;
            rewrite_backing_statement(&case_fixture.config.bundle_dir, &inputs);

            let error = prepare_bundle(
                &case_fixture.config.bundle_dir,
                &case_fixture.config.expected_final_channel_state_digest,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains(diagnostic),
                "unexpected {label} diagnostic: {error}"
            );
        }
    }

    #[test]
    fn bundle_cross_checks_member_set_legacy_amount_and_full_fund_channel() {
        for (label, mutate) in [
            (
                "member",
                (
                    "member_pk_gs",
                    serde_json::json!([repeated(0x99), repeated(0x16)]),
                ),
            ),
            ("amount", ("channel_fund_amount", serde_json::json!("101"))),
        ] {
            let fixture = fixture(label);
            let path = fixture.config.bundle_dir.join("close_intent.json");
            let mut descriptor: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            descriptor[mutate.0] = mutate.1;
            write_json(&path, &descriptor);
            assert!(prepare_bundle(
                &fixture.config.bundle_dir,
                &fixture.config.expected_final_channel_state_digest,
            )
            .is_err());
        }

        let fixture = fixture("fund-channel");
        let path = fixture.config.bundle_dir.join("close_intent_full.json");
        let mut full: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        full["channelFundSnapshot"]["channelId"] = serde_json::json!(8);
        write_json(&path, &full);
        assert!(prepare_bundle(
            &fixture.config.bundle_dir,
            &fixture.config.expected_final_channel_state_digest,
        )
        .is_err());
    }

    #[test]
    fn attestation_abi_event_and_readback_identity_are_exact() {
        let fixture = fixture("attestation-identity");
        let calldata = attest_calldata(
            &fixture.deployment.manager,
            &fixture.prepared.backing_mle.compact_proof,
        )
        .expect("attestation calldata");
        assert!(calldata.starts_with(ATTEST_SIGNED_HEAD_BACKING_SELECTOR));
        let calldata_bytes = decode_hex(&calldata, None, "attestation calldata").unwrap();
        // (address manager, bytes backingProof): head = 2 words, then length-prefixed bytes.
        assert_eq!(abi_usize(&calldata_bytes[4 + 32..4 + 64]), 64);
        let proof_length = abi_usize(&calldata_bytes[4 + 64..4 + 96]);
        assert_eq!(proof_length, fixture.prepared.backing_mle.compact_proof.len());
        assert_eq!(
            &calldata_bytes[4 + 96..4 + 96 + proof_length],
            fixture.prepared.backing_mle.compact_proof.as_slice()
        );
        let materialize = materialize_calldata(
            &fixture.deployment.manager,
            &fixture.prepared.backing_mle.compact_proof,
        )
        .expect("materialization calldata");
        assert!(materialize.starts_with(MATERIALIZE_SIGNED_HEAD_SELECTOR));
        assert_eq!(materialize[10..], calldata[10..]);
        assert_eq!(
            fixture.prepared.backing_compact_proof_hash,
            keccak_hex(&fixture.prepared.backing_mle.compact_proof)
        );
        assert_eq!(
            selector(ATTEST_SIGNED_HEAD_BACKING_SIGNATURE),
            ATTEST_SIGNED_HEAD_BACKING_SELECTOR
        );
        assert_eq!(
            selector(MATERIALIZE_SIGNED_HEAD_SIGNATURE),
            MATERIALIZE_SIGNED_HEAD_SELECTOR
        );
        assert_eq!(selector(SUBMIT_CLOSE_SIGNATURE), SUBMIT_CLOSE_SELECTOR);
        assert_eq!(
            keccak_hex(SIGNED_HEAD_BACKING_ATTESTED_EVENT.as_bytes()),
            "0x0d2bcc34a2ee92e5cbf5f9d10da1d0fdaf7684882364d237d6fca57f5a9f2091"
        );

        let event = attestation_event(&fixture);
        let transaction = SignedTransaction {
            target: fixture.deployment.close_funding_materializer.clone(),
            calldata_hash: keccak_hex(
                &decode_hex(&calldata, None, "attestation calldata").unwrap(),
            ),
            nonce: 0,
            raw_signed_transaction: "0x01".into(),
            transaction_hash: repeated(0x71),
        };
        let attestation_receipt = receipt(
            &transaction,
            &address(0x55),
            &block(9, 999),
            event.clone(),
        );
        assert!(exact_attested_event(
            &attestation_receipt,
            &fixture.deployment,
            &fixture.prepared,
        )
            .expect("decode exact attestation")
            .is_some());

        let mut crossed = event;
        crossed["topics"][3] = Value::String(repeated(0xee));
        let crossed_receipt = receipt(
            &transaction,
            &address(0x55),
            &block(9, 999),
            crossed,
        );
        assert!(exact_attested_event(
            &crossed_receipt,
            &fixture.deployment,
            &fixture.prepared,
        )
        .expect("decode crossed attestation")
        .is_none());

        let ready = observed_deployment(&fixture);
        assert!(backing_attestation_ready(&ready, &fixture.prepared).unwrap());
        let mut impossible = ready;
        impossible.signed_head_backing_anchor_plus_one = 0;
        assert!(backing_attestation_ready(&impossible, &fixture.prepared).is_err());
    }

    #[test]
    fn close_accepts_only_canonical_full_v2_and_submits_exact_compact_bytes() {
        let fixture = fixture("strict-mle-v2");
        let mle_path = fixture.config.bundle_dir.join("close_intent_mle.json");
        let canonical = String::from_utf8(fs::read(&mle_path).unwrap()).unwrap();
        let mle = MleVerifierV2Fixture::from_canonical_json(&canonical).unwrap();
        let public_inputs = parse_public_input_array(
            &serde_json::from_slice::<Value>(
                &fs::read(fixture.config.bundle_dir.join("close_public_inputs.json")).unwrap(),
            )
            .unwrap(),
            "close public inputs",
        )
        .unwrap();
        let expected_compact = mle
            .compact_proof
            .decode_and_validate(std::str::from_utf8(&COMPACT_MAGIC_V2).unwrap())
            .unwrap();
        let validated = validated_compact_mle_v2_fixture(MleStatement::Close, &canonical, &public_inputs).unwrap();
        assert_eq!(validated.compact_proof, expected_compact);

        let calldata = decode_hex(&fixture.prepared.submit_calldata, None, "submit calldata")
            .expect("decode submit calldata");
        assert_eq!(
            &calldata[..4],
            decode_hex(&selector(SUBMIT_CLOSE_SIGNATURE), Some(4), "selector")
                .unwrap()
                .as_slice()
        );
        let arguments = &calldata[4..];
        let intent_size = AbiKind::Tuple(close_intent_fields()).static_size().unwrap();
        let proof_offset = abi_usize(&arguments[intent_size..intent_size + 32]);
        assert_eq!(proof_offset, intent_size + 32);
        let proof_length = abi_usize(&arguments[proof_offset..proof_offset + 32]);
        let proof_start = proof_offset + 32;
        let proof_end = proof_start + proof_length;
        assert_eq!(&arguments[proof_start..proof_end], expected_compact);
        assert!(arguments[proof_end..].iter().all(|byte| *byte == 0));
        assert_eq!(
            fixture.prepared.compact_proof_length,
            u32::try_from(expected_compact.len()).unwrap()
        );
        assert_eq!(
            fixture.prepared.compact_proof_hash,
            keccak_hex(&expected_compact)
        );

        let binding = make_binding(
            &fixture.prepared,
            &fixture.deployment,
            fixture.config.deployment_manifest_sha256.clone(),
            &fixture.config.signer_lock_root,
        )
        .unwrap();
        assert_eq!(binding.compact_proof_hash, keccak_hex(&expected_compact));
        assert_eq!(binding.compact_proof_length, expected_compact.len() as u32);
        assert_eq!(binding.mle_fixture_schema, MLE_VERIFIER_FIXTURE_SCHEMA_V2);
        assert_eq!(binding.mle_protocol_version, MLE_PROTOCOL_VERSION_CURRENT);

        let legacy_proof_only = format!("{}\n", serde_json::to_string_pretty(&mle.proof).unwrap());
        assert!(validated_compact_mle_v2_fixture(MleStatement::Close, &legacy_proof_only, &public_inputs).is_err());
        assert!(validated_compact_mle_v2_fixture(MleStatement::Close, canonical.trim_end(), &public_inputs).is_err());

        let mut wrong_layout = mle.clone();
        wrong_layout.proof_layout_hash = repeated(0x99);
        assert!(
            validated_compact_mle_v2_fixture(
                MleStatement::Close,
                &wrong_layout.to_canonical_json().unwrap(),
                &public_inputs,
            )
            .is_err()
        );
        let mut wrong_compact_hash = mle.clone();
        wrong_compact_hash.compact_proof.keccak256 = repeated(0x98);
        assert!(
            validated_compact_mle_v2_fixture(
                MleStatement::Close,
                &wrong_compact_hash.to_canonical_json().unwrap(),
                &public_inputs,
            )
            .is_err()
        );
        let mut wrong_config_map = mle.clone();
        let mut map = hex::decode(
            wrong_config_map
                .verification_config
                .public_input_wire_map
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        map[0] ^= 1;
        wrong_config_map.verification_config.public_input_wire_map =
            format!("0x{}", hex::encode(map));
        assert!(
            validated_compact_mle_v2_fixture(
                MleStatement::Close,
                &wrong_config_map.to_canonical_json().unwrap(),
                &public_inputs,
            )
            .is_err(),
            "publisher must bind the Solidity config PI map to the VK PI map"
        );
        let mut wrong_public_inputs = public_inputs;
        wrong_public_inputs[0] ^= 1;
        assert!(validated_compact_mle_v2_fixture(MleStatement::Close, &canonical, &wrong_public_inputs).is_err());
    }

    #[test]
    fn manifest_and_checkpoint_observation_pin_all_four_v2_verifiers() {
        let fixture = fixture("four-mle-pins");

        let mut duplicate = fixture.deployment.clone();
        duplicate.cancel_close_mle_verifier = duplicate.close_mle_verifier.clone();
        write_json(&fixture.config.deployment_manifest_path, &duplicate);
        let error = load_deployment_manifest(
            &fixture.config.deployment_manifest_path,
            &fixture.prepared,
            &file_sha256(&fixture.config.deployment_manifest_path),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("distinct MLE adapters and cores")
        );

        let mut legacy: Value = serde_json::to_value(&fixture.deployment).unwrap();
        legacy["mleProofAbiVersion"] = serde_json::json!(2);
        write_json(&fixture.config.deployment_manifest_path, &legacy);
        assert!(
            load_deployment_manifest(
                &fixture.config.deployment_manifest_path,
                &fixture.prepared,
                &file_sha256(&fixture.config.deployment_manifest_path),
            )
            .is_err()
        );

        let mut observed = observed_deployment(&fixture);
        observed.withdrawal_claim_mle.core_runtime_code_hash = repeated(0xfe);
        let error =
            validate_deployment_observation(&fixture.deployment, &observed, &fixture.prepared)
                .unwrap_err();
        assert!(error.to_string().contains("withdrawal-claim MLE"));

        let mut observed = observed_deployment(&fixture);
        observed.post_close_claim_mle.whir_protocol_id = repeated64(0xfd);
        let error =
            validate_deployment_observation(&fixture.deployment, &observed, &fixture.prepared)
                .unwrap_err();
        assert!(error.to_string().contains("post-close-claim MLE"));

        let mut observed = observed_deployment(&fixture);
        observed.cancel_close_mle.core_allowed_chain_id = 1;
        let error =
            validate_deployment_observation(&fixture.deployment, &observed, &fixture.prepared)
                .unwrap_err();
        assert!(error.to_string().contains("cancel-close MLE"));
    }

    #[test]
    fn manifest_rejects_unguarded_finalize_and_lock_name_is_global() {
        let fixture = fixture("pins");
        let mut wrong_pin = fixture.config.clone();
        wrong_pin.deployment_manifest_sha256 = repeated(0xfe);
        let error = advance_with_backend(&wrong_pin, &mut FakeBackend::new(&fixture)).unwrap_err();
        assert!(error
            .to_string()
            .contains("independently configured SHA-256"));

        let mut deployment = fixture.deployment.clone();
        deployment.finalize_close_guarded_selector = selector("finalizeClose()");
        write_json(&fixture.config.deployment_manifest_path, &deployment);
        let error = load_deployment_manifest(
            &fixture.config.deployment_manifest_path,
            &fixture.prepared,
            &file_sha256(&fixture.config.deployment_manifest_path),
        )
        .unwrap_err();
        assert!(error.to_string().contains("selector/event pins"));

        let path = global_signer_lock_path(
            &fixture.config.signer_lock_root,
            ANVIL_CHAIN_ID,
            &address(0x55),
        )
        .expect("global lock path");
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            format!(
                ".intmax-l1-signer-{ANVIL_CHAIN_ID}-{}.lock",
                "55".repeat(20)
            )
        );
    }
}
