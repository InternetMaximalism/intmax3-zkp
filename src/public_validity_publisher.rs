//! Crash-safe public-L1 publisher for a resident validity prover artifact.
//!
//! The API/prover is intentionally keyless. This module is the narrow operator-owned boundary
//! that turns its candidate-bound posting/finalization envelope into three L1 writes:
//! `postBlockAndSubmitGuarded` (EIP-4844), `attestProofData`, and `finalize`. Every write is signed
//! persisted as a raw transaction before publication. A restart can therefore only replay the
//! exact transaction; it can never guess whether an unjournaled write escaped.

#![cfg(not(target_arch = "wasm32"))]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::{
    fd::AsRawFd as _,
    unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
};

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    ethereum_types::bytes32::Bytes32,
    l1_finality::{ANVIL_CHAIN_ID, L1FinalitySource, L1FinalizedCheckpoint},
    l1_signer_reservation::{self, SignerReservation},
    proof_da::{
        DecodedBlobTransaction, ValidatedBlobSidecars, submitted_id_from_receipt,
        validate_decoded_blob_transaction,
    },
};

const JOURNAL_VERSION: u32 = 1;
const ENVELOPE_SCHEMA_VERSION: u32 = 2;
const POST_STAKE_WEI: u64 = 1_000_000_000_000_000_000;
const MAX_ENVELOPE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RAW_TRANSACTION_CHARS: usize = 4 * 1024 * 1024;
const MAX_RPC_JSON_BYTES: usize = 16 * 1024 * 1024;
const EVENT_LOG_BLOCK_SPAN: u64 = 10_000;
const POST_SIGNATURE: &str = "postBlockAndSubmitGuarded((uint32,uint64,bytes32,uint32[])[],bytes32,uint32,bytes32,bytes32,uint64,bytes32)";
const ATTEST_SIGNATURE: &str = "attestProofData(uint256,bytes,bytes)";
const ANVIL_PUBLIC_DEV_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
static PRIVATE_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum PublicValidityPublisherError {
    #[error("invalid public-validity configuration: {0}")]
    Configuration(String),
    #[error("invalid validity envelope: {0}")]
    Envelope(String),
    #[error("public-validity journal conflict: {0}")]
    Conflict(String),
    #[error("public-validity journal failure: {0}")]
    Journal(String),
    #[error("L1 command failed: {0}")]
    Command(String),
    #[error("L1 evidence rejected: {0}")]
    Evidence(String),
    #[error("L1 finality timeout: {0}")]
    Timeout(String),
}

type Result<T> = std::result::Result<T, PublicValidityPublisherError>;

#[derive(Clone, Debug)]
pub struct PublicValidityPublisherConfig {
    pub envelope_path: PathBuf,
    /// Release-reviewed deployment pin. Code hashes and ABI selectors are checked before stake.
    pub deployment_manifest_path: PathBuf,
    /// Independently supplied SHA-256 of the exact deployment-manifest bytes.
    pub deployment_manifest_sha256: String,
    pub journal_path: PathBuf,
    /// Canonical operator-owned directory used for signer-global nonce exclusion.
    /// Every publisher instance using the signer must use this same root.
    pub lock_root: PathBuf,
    pub rpc_url: String,
    /// Foundry encrypted-keystore account name. This is a selector, never key material.
    pub account: Option<String>,
    pub finality_timeout: Duration,
    /// Development-only escape. This is rejected unless the RPC itself reports chain 31337.
    pub allow_unfinalized_devnet: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicValidityPublication {
    pub schema_version: u32,
    pub chain_id: u64,
    pub rollup: String,
    pub candidate_id: String,
    pub candidate_request_id: String,
    pub artifact_hash: String,
    pub proof_hash: String,
    pub proof_length: u32,
    pub submission_id: String,
    pub finalization_transaction_hash: String,
    pub finalized_checkpoint: L1FinalizedCheckpoint,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidityEnvelope {
    schema_version: u32,
    channel_id: u32,
    chain_id: u64,
    rollup: String,
    manager: String,
    verifier: String,
    proposal_hash: String,
    producer_request_id: String,
    candidate_request_id: String,
    candidate_receipt: Value,
    posting_artifact: PostingArtifact,
    finalize_artifact: FinalizeArtifact,
    artifact_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PostingArtifact {
    receipt: Value,
    sub_blocks: Vec<PostingSubBlock>,
    expected_pending_chains: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PostingSubBlock {
    channel_id: u32,
    timestamp: u64,
    tx_tree_root: String,
    num_users: u32,
    key_ids: Vec<u32>,
    deposit_hash_chain: String,
    channel_reg_hash_chain: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FinalizeArtifact {
    final_state_root: String,
    vpis_json: String,
    validity_mle_json: String,
}

#[derive(Clone, Debug)]
struct PreparedEnvelope {
    envelope: ValidityEnvelope,
    candidate_id: String,
    initial_block_number: u64,
    initial_block_chain: String,
    initial_ext_commitment: String,
    final_block_number: u64,
    proof_abi_version: u8,
    proof_payload: Vec<u8>,
    proof_hash: String,
    proof_length: u32,
    post_calldata: String,
    post_cast_sub_blocks: String,
    final_state_root: String,
    expected_pending_chains: String,
    vpis: Value,
    mle_proof: Value,
    binding_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CandidateBinding {
    schema_version: u32,
    chain_id: u64,
    rollup: String,
    channel_id: u32,
    manager: String,
    verifier: String,
    proposal_hash: String,
    producer_request_id: String,
    candidate_request_id: String,
    candidate_id: String,
    artifact_hash: String,
    deployment_manifest_hash: String,
    rollup_runtime_code_hash: String,
    mle_verifier: String,
    mle_verifier_runtime_code_hash: String,
    kzg_verifier: String,
    kzg_verifier_runtime_code_hash: String,
    proof_abi_version: u8,
    proof_hash: String,
    proof_length: u32,
    final_state_root: String,
    final_block_number: u64,
    expected_pending_chains: String,
    post_calldata_hash: String,
    binding_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeploymentManifest {
    schema_version: u32,
    chain_id: u64,
    rollup: String,
    rollup_runtime_code_hash: String,
    mle_verifier: String,
    mle_verifier_runtime_code_hash: String,
    /// Release-reviewed proof-DA satellite selected by `IntmaxRollup.kzgVerifier()`.
    /// This pins deployment identity only; the KZG ceremony remains an explicit trust assumption.
    kzg_verifier: String,
    kzg_verifier_runtime_code_hash: String,
    mle_proof_abi_version: u8,
    post_block_and_submit_guarded_selector: String,
    attest_proof_data_selector: String,
    finalize_selector: String,
}

#[derive(Clone, Debug)]
struct CheckedDeployment {
    manifest: DeploymentManifest,
    manifest_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedDeploymentIdentity {
    rollup_runtime_code_hash: String,
    mle_verifier: String,
    mle_verifier_runtime_code_hash: String,
    kzg_verifier: String,
    kzg_verifier_runtime_code_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FinalizedReceipt {
    transaction_hash: String,
    block_hash: String,
    block_number: u64,
    finalized_checkpoint: L1FinalizedCheckpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawTransactionStep {
    target: String,
    calldata_hash: String,
    value: u64,
    nonce: u64,
    raw_signed_transaction: String,
    transaction_hash: String,
    confirmation: Option<FinalizedReceipt>,
    /// Canonical-finalized receipt for a local raw finalize transaction that lost a
    /// permissionless race. This is fsynced before the signer reservation is released.
    #[serde(default)]
    superseded_confirmation: Option<FinalizedReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlobPostStep {
    transaction: RawTransactionStep,
    blob_versioned_hashes: Vec<String>,
    compact_sidecars: String,
    submission_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicationJournal {
    version: u32,
    binding: CandidateBinding,
    submitter: String,
    signer_lock_root: String,
    post: Option<BlobPostStep>,
    attest: Option<RawTransactionStep>,
    finalize: Option<RawTransactionStep>,
    /// A permissionless finalizer may execute the exact candidate through a relayer or wrapper.
    /// The outer transaction is not authority; this record is accepted only after exact event and
    /// receipt-block state reconciliation.
    #[serde(default)]
    adopted_finalize: Option<AdoptedFinalization>,
    completed: Option<PublicValidityPublication>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdoptedFinalization {
    submission_id: String,
    state_root: String,
    confirmation: FinalizedReceipt,
}

#[derive(Clone, Debug)]
enum AbiKind {
    Uint(usize),
    Address,
    FixedBytes(usize),
    Bytes,
    Tuple(Vec<AbiField>),
    DynamicArray(Box<AbiKind>),
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

fn uint_array(name: &'static str) -> AbiField {
    AbiField::new(name, AbiKind::DynamicArray(Box::new(AbiKind::Uint(256))))
}

fn ext3(name: &'static str) -> AbiField {
    AbiField::new(
        name,
        AbiKind::Tuple(vec![uint("c0", 64), uint("c1", 64), uint("c2", 64)]),
    )
}

fn sumcheck(name: &'static str) -> AbiField {
    AbiField::new(
        name,
        AbiKind::Tuple(vec![AbiField::new(
            "roundPolys",
            AbiKind::DynamicArray(Box::new(AbiKind::Tuple(vec![uint_array("evals")]))),
        )]),
    )
}

fn gate_kind() -> AbiKind {
    AbiKind::Tuple(vec![
        uint("gateId", 8),
        uint("selectorIndex", 8),
        uint("groupStart", 8),
        uint("groupEnd", 8),
        uint("gateRowIndex", 8),
        uint("numConstraints", 16),
        uint("numOrConsts", 16),
        uint("param2", 16),
        uint("param3", 16),
    ])
}

fn mle_v1_fields() -> Vec<AbiField> {
    vec![
        uint_array("circuitDigest"),
        AbiField::new("whirTranscript", AbiKind::Bytes),
        AbiField::new("whirHints", AbiKind::Bytes),
        bytes32("preprocessedRoot"),
        bytes32("witnessRoot"),
        bytes32("auxCommitmentRoot"),
        uint("preprocessedEvalValue", 256),
        uint("preprocessedBatchR", 256),
        uint_array("preprocessedIndividualEvals"),
        uint("witnessEvalValue", 256),
        uint("witnessBatchR", 256),
        uint_array("witnessIndividualEvals"),
        uint("auxBatchR", 256),
        uint("auxConstraintEval", 256),
        uint("auxPermEval", 256),
        uint("auxEvalValue", 256),
        sumcheck("combinedProof"),
        uint_array("publicInputs"),
        uint("alpha", 256),
        uint("beta", 256),
        uint("gamma", 256),
        uint("mu", 256),
        ext3("preprocessedWhirEval"),
        ext3("witnessWhirEval"),
        ext3("auxWhirEval"),
        bytes32("inverseHelpersCommitmentRoot"),
        uint("inverseHelpersBatchR", 256),
        sumcheck("invSumcheckProof"),
        sumcheck("hSumcheckProof"),
        uint("lambdaInv", 256),
        uint("muInv", 256),
        uint("lambdaH", 256),
        uint_array("witnessIndividualEvalsAtRInv"),
        uint_array("preprocessedIndividualEvalsAtRInv"),
        uint_array("inverseHelpersEvalsAtRInv"),
        uint_array("inverseHelpersEvalsAtRH"),
        uint("gSubEvalAtRInv", 256),
        uint("witnessEvalValueAtRInv", 256),
        uint("preprocessedEvalValueAtRInv", 256),
        ext3("inverseHelpersWhirEvalAtRGate"),
        ext3("preprocessedWhirEvalAtRInv"),
        ext3("witnessWhirEvalAtRInv"),
        ext3("auxWhirEvalAtRInv"),
        ext3("inverseHelpersWhirEvalAtRInv"),
        ext3("preprocessedWhirEvalAtRH"),
        ext3("witnessWhirEvalAtRH"),
        ext3("auxWhirEvalAtRH"),
        ext3("inverseHelpersWhirEvalAtRH"),
        uint("extChallenge", 256),
        sumcheck("gateSumcheckProof"),
        uint_array("witnessIndividualEvalsAtRGateV2"),
        uint_array("preprocessedIndividualEvalsAtRGateV2"),
        uint("witnessEvalValueAtRGateV2", 256),
        uint("preprocessedEvalValueAtRGateV2", 256),
        ext3("preprocessedWhirEvalAtRGateV2"),
        ext3("witnessWhirEvalAtRGateV2"),
        ext3("auxWhirEvalAtRGateV2"),
        ext3("inverseHelpersWhirEvalAtRGateV2"),
        uint("quotientDegreeFactor", 256),
        uint("numSelectors", 256),
        uint("numGateConstraints", 256),
        AbiField::new("gates", AbiKind::DynamicArray(Box::new(gate_kind()))),
        AbiField::new(
            "publicInputsHash",
            AbiKind::FixedArray(Box::new(AbiKind::Uint(256)), 4),
        ),
    ]
}

fn mle_fields(version: u8) -> Vec<AbiField> {
    let v1 = mle_v1_fields();
    if version == 1 {
        return v1;
    }
    const REMOVED: &[&str] = &[
        "preprocessedWhirEval",
        "witnessWhirEval",
        "auxWhirEval",
        "lambdaH",
        "inverseHelpersWhirEvalAtRGate",
        "preprocessedWhirEvalAtRInv",
        "witnessWhirEvalAtRInv",
        "auxWhirEvalAtRInv",
        "inverseHelpersWhirEvalAtRInv",
        "preprocessedWhirEvalAtRH",
        "witnessWhirEvalAtRH",
        "auxWhirEvalAtRH",
        "inverseHelpersWhirEvalAtRH",
        "preprocessedWhirEvalAtRGateV2",
        "witnessWhirEvalAtRGateV2",
        "auxWhirEvalAtRGateV2",
        "inverseHelpersWhirEvalAtRGateV2",
    ];
    let mut fields = vec![uint("protocolVersion", 256), uint("constituentWidth", 256)];
    fields.extend(
        v1.into_iter()
            .filter(|field| !REMOVED.contains(&field.name)),
    );
    fields
}

fn vpis_fields() -> Vec<AbiField> {
    vec![
        uint("initialBlockNumber", 64),
        bytes32("initialBlockChain"),
        bytes32("initialExtCommitment"),
        uint("finalBlockNumber", 64),
        bytes32("finalBlockChain"),
        bytes32("finalExtCommitment"),
        AbiField::new("prover", AbiKind::Address),
    ]
}

fn post_sub_block_kind() -> AbiKind {
    AbiKind::Tuple(vec![
        uint("channelId", 32),
        uint("timestamp", 64),
        bytes32("txTreeRoot"),
        AbiField::new("keyIds", AbiKind::DynamicArray(Box::new(AbiKind::Uint(32)))),
    ])
}

impl AbiKind {
    fn signature(&self) -> String {
        match self {
            Self::Uint(bits) => format!("uint{bits}"),
            Self::Address => "address".into(),
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
            Self::DynamicArray(element) => format!("{}[]", element.signature()),
            Self::FixedArray(element, length) => format!("{}[{length}]", element.signature()),
        }
    }

    fn is_dynamic(&self) -> bool {
        match self {
            Self::Bytes | Self::DynamicArray(_) => true,
            Self::Tuple(fields) => fields.iter().any(|field| field.kind.is_dynamic()),
            Self::FixedArray(element, _) => element.is_dynamic(),
            Self::Uint(_) | Self::Address | Self::FixedBytes(_) => false,
        }
    }

    fn static_size(&self) -> std::result::Result<usize, String> {
        if self.is_dynamic() {
            return Err("dynamic ABI value has no static size".into());
        }
        match self {
            Self::Uint(_) | Self::Address | Self::FixedBytes(_) => Ok(32),
            Self::Tuple(fields) => fields.iter().try_fold(0usize, |total, field| {
                total
                    .checked_add(field.kind.static_size()?)
                    .ok_or_else(|| "ABI static tuple size overflow".to_string())
            }),
            Self::FixedArray(element, length) => element
                .static_size()?
                .checked_mul(*length)
                .ok_or_else(|| "ABI fixed-array size overflow".into()),
            Self::Bytes | Self::DynamicArray(_) => unreachable!("checked dynamic above"),
        }
    }
}

fn json_member<'a>(
    value: &'a Value,
    field: &AbiField,
    path: &str,
) -> std::result::Result<&'a Value, String> {
    // The Rust exporter names these two roots after their commitments. Solidity's struct uses the
    // shorter names. Validity public inputs are separately serialized in snake_case.
    let alias = match field.name {
        "preprocessedRoot" => Some("preprocessedCommitmentRoot"),
        "witnessRoot" => Some("witnessCommitmentRoot"),
        "initialBlockNumber" => Some("initial_block_number"),
        "initialBlockChain" => Some("initial_block_chain"),
        "initialExtCommitment" => Some("initial_ext_commitment"),
        "finalBlockNumber" => Some("final_block_number"),
        "finalBlockChain" => Some("final_block_chain"),
        "finalExtCommitment" => Some("final_ext_commitment"),
        _ => None,
    };
    let object = value
        .as_object()
        .ok_or_else(|| format!("{path} must be a JSON object"))?;
    object
        .get(field.name)
        .or_else(|| alias.and_then(|name| object.get(name)))
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
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "{path} must be a canonical decimal unsigned integer"
        ));
    }
    let parsed = BigUint::parse_bytes(text.as_bytes(), 10)
        .ok_or_else(|| format!("{path} is not an unsigned integer"))?;
    if bits == 0 || bits > 256 || &parsed >= &(BigUint::from(1u8) << bits) {
        return Err(format!("{path} does not fit uint{bits}"));
    }
    Ok(parsed)
}

fn decode_hex(
    value: &Value,
    exact: Option<usize>,
    path: &str,
) -> std::result::Result<Vec<u8>, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{path} must be 0x-prefixed hex"))?;
    let body = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
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
        AbiKind::Uint(bits) => {
            let bytes = parse_uint_value(value, *bits, path)?.to_bytes_be();
            let mut word = vec![0u8; 32];
            word[32 - bytes.len()..].copy_from_slice(&bytes);
            Ok(word)
        }
        AbiKind::Address => {
            let bytes = decode_hex(value, Some(20), path)?;
            if bytes == [0u8; 20] {
                return Err(format!("{path} must not be the zero address"));
            }
            let mut word = vec![0u8; 32];
            word[12..].copy_from_slice(&bytes);
            Ok(word)
        }
        AbiKind::FixedBytes(size) => {
            let bytes = decode_hex(value, Some(*size), path)?;
            let mut word = vec![0u8; 32];
            word[..*size].copy_from_slice(&bytes);
            Ok(word)
        }
        AbiKind::Bytes => {
            let bytes = decode_hex(value, None, path)?;
            let padded = bytes
                .len()
                .checked_add(31)
                .ok_or_else(|| "ABI byte length overflow".to_string())?
                / 32
                * 32;
            let mut encoded = abi_word_from_usize(bytes.len())?;
            encoded.resize(32 + padded, 0);
            encoded[32..32 + bytes.len()].copy_from_slice(&bytes);
            Ok(encoded)
        }
        AbiKind::Tuple(fields) => {
            // Exported sumcheck rounds are arrays directly, while Solidity wraps each one in a
            // one-field `RoundPoly { evals }` tuple.
            if let Some(_array) = value.as_array() {
                if fields.len() == 1 && fields[0].name == "evals" {
                    return encode_sequence([(&fields[0].kind, value, format!("{path}.evals"))]);
                }
            }
            encode_sequence(
                fields
                    .iter()
                    .map(|field| {
                        json_member(value, field, path)
                            .map(|member| (&field.kind, member, format!("{path}.{}", field.name)))
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            )
        }
        AbiKind::DynamicArray(element) => {
            let array = value
                .as_array()
                .ok_or_else(|| format!("{path} must be an array"))?;
            let mut encoded = abi_word_from_usize(array.len())?;
            encoded.extend(encode_sequence(array.iter().enumerate().map(
                |(index, value)| (element.as_ref(), value, format!("{path}[{index}]")),
            ))?);
            Ok(encoded)
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

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).expect("serializing JSON scalar cannot fail")
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
                        serde_json::to_string(key).expect("JSON key"),
                        canonical_json(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak_hash::keccak(bytes).0))
}

fn validity_signer_reservation(
    chain_id: u64,
    signer: &str,
    journal_path: &Path,
    binding: &CandidateBinding,
    phase: &str,
    target: &str,
    calldata_hash: &str,
    value: u64,
) -> Result<SignerReservation> {
    let material = serde_json::json!({
        "schemaVersion": 1,
        "bindingDigest": normalize_hex(&binding.binding_digest, 32, "reservation binding digest")
            .map_err(PublicValidityPublisherError::Configuration)?,
        "phase": phase,
        "target": normalize_hex(target, 20, "reservation target")
            .map_err(PublicValidityPublisherError::Configuration)?,
        "calldataHash": normalize_hex(calldata_hash, 32, "reservation calldata hash")
            .map_err(PublicValidityPublisherError::Configuration)?,
        "value": value.to_string(),
    });
    let intent_hash = sha256_hex(canonical_json(&material).as_bytes());
    SignerReservation::new(
        chain_id,
        signer,
        "public-validity",
        journal_path,
        phase,
        &intent_hash,
    )
    .map_err(PublicValidityPublisherError::Configuration)
}

fn claim_signer_reservation(root: &Path, reservation: &SignerReservation) -> Result<()> {
    l1_signer_reservation::claim(root, reservation).map_err(|error| {
        PublicValidityPublisherError::Conflict(format!("signer reservation: {error}"))
    })
}

fn release_signer_reservation(root: &Path, reservation: &SignerReservation) -> Result<()> {
    l1_signer_reservation::release(root, reservation).map_err(|error| {
        PublicValidityPublisherError::Journal(format!("signer reservation: {error}"))
    })
}

fn release_exact_signer_reservation(root: &Path, reservation: &SignerReservation) -> Result<bool> {
    l1_signer_reservation::release_if_exact(root, reservation).map_err(|error| {
        PublicValidityPublisherError::Journal(format!("signer reservation: {error}"))
    })
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
            Err(release_error) => Err(PublicValidityPublisherError::Journal(format!(
                "offline signing failed ({sign_error}); reservation release also failed ({release_error})"
            ))),
        },
    }
}

fn normalize_hex(value: &str, bytes: usize, path: &str) -> std::result::Result<String, String> {
    let decoded = decode_hex(&Value::String(value.to_string()), Some(bytes), path)?;
    Ok(format!("0x{}", hex::encode(decoded)))
}

fn validate_nonzero_hex(value: &str, bytes: usize, path: &str) -> std::result::Result<(), String> {
    let decoded = decode_hex(&Value::String(value.to_string()), Some(bytes), path)?;
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(format!("{path} must be nonzero"));
    }
    Ok(())
}

fn same_hex(left: &str, right: &str) -> bool {
    left.trim_start_matches("0x")
        .eq_ignore_ascii_case(right.trim_start_matches("0x"))
}

fn object_field<'a>(
    value: &'a Value,
    name: &str,
    path: &str,
) -> std::result::Result<&'a Value, String> {
    value
        .as_object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| format!("{path}.{name} is missing"))
}

fn string_field<'a>(
    value: &'a Value,
    name: &str,
    path: &str,
) -> std::result::Result<&'a str, String> {
    object_field(value, name, path)?
        .as_str()
        .ok_or_else(|| format!("{path}.{name} must be a string"))
}

fn u64_field(value: &Value, name: &str, path: &str) -> std::result::Result<u64, String> {
    object_field(value, name, path)?
        .as_u64()
        .ok_or_else(|| format!("{path}.{name} must be a JSON-safe unsigned integer"))
}

fn validate_account_name(account: &str) -> std::result::Result<(), String> {
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
        return Err(
            "Foundry account must be 1..128 ASCII alphanumeric/._- characters and begin alphanumeric"
                .into(),
        );
    }
    Ok(())
}

fn validate_v2_constituent_width(proof: &Value) -> std::result::Result<(), String> {
    if parse_uint_value(
        object_field(proof, "protocolVersion", "mleProof")?,
        256,
        "mleProof.protocolVersion",
    )? != BigUint::from(1u8)
    {
        return Err("mleProof.protocolVersion must equal the supported PCS version 1".into());
    }
    let mut width = 2usize;
    for field in [
        "preprocessedIndividualEvals",
        "witnessIndividualEvals",
        "inverseHelpersEvalsAtRInv",
        "inverseHelpersEvalsAtRH",
        "preprocessedIndividualEvalsAtRGateV2",
        "witnessIndividualEvalsAtRGateV2",
    ] {
        width = width.max(
            object_field(proof, field, "mleProof")?
                .as_array()
                .ok_or_else(|| format!("mleProof.{field} must be an array"))?
                .len(),
        );
    }
    let declared = parse_uint_value(
        object_field(proof, "constituentWidth", "mleProof")?,
        256,
        "mleProof.constituentWidth",
    )?;
    if declared != BigUint::from(width) {
        return Err(format!(
            "mleProof.constituentWidth {declared} != canonical constituent vector width {width}"
        ));
    }
    Ok(())
}

fn proof_abi_version(proof: &Value, chain_id: u64) -> std::result::Result<u8, String> {
    let object = proof
        .as_object()
        .ok_or_else(|| "validityMleJson must decode to an object".to_string())?;
    let has_protocol = object.contains_key("protocolVersion");
    let has_width = object.contains_key("constituentWidth");
    if has_protocol != has_width {
        return Err(
            "MLE proof must carry both protocolVersion and constituentWidth or neither".into(),
        );
    }
    if !has_protocol {
        if chain_id != ANVIL_CHAIN_ID {
            return Err(format!(
                "legacy MLE ABI v1 is restricted to local chain {ANVIL_CHAIN_ID}"
            ));
        }
        return Ok(1);
    }
    validate_v2_constituent_width(proof)?;
    Ok(2)
}

fn packed_validity_public_inputs(vpis: &Value) -> std::result::Result<Vec<u8>, String> {
    // IntmaxRollup._computeValidityPIHash uses abi.encodePacked with these exact Solidity widths;
    // this is deliberately *not* the standard-ABI tuple encoding used by finalize calldata.
    let mut encoded = Vec::with_capacity(164);
    for field in vpis_fields() {
        let value = json_member(vpis, &field, "validityPIs")?;
        match field.kind {
            AbiKind::Uint(64) => {
                let value = u64::try_from(parse_uint_value(
                    value,
                    64,
                    &format!("validityPIs.{}", field.name),
                )?)
                .map_err(|_| format!("validityPIs.{} does not fit uint64", field.name))?;
                encoded.extend(value.to_be_bytes());
            }
            AbiKind::FixedBytes(32) => encoded.extend(decode_hex(
                value,
                Some(32),
                &format!("validityPIs.{}", field.name),
            )?),
            AbiKind::Address => encoded.extend(decode_hex(
                value,
                Some(20),
                &format!("validityPIs.{}", field.name),
            )?),
            _ => unreachable!("ValidityPublicInputs schema is fixed"),
        }
    }
    debug_assert_eq!(encoded.len(), 164);
    Ok(encoded)
}

fn validate_public_inputs_hash(proof: &Value, vpis: &Value) -> std::result::Result<(), String> {
    let expected = keccak_hash::keccak(packed_validity_public_inputs(vpis)?).0;
    let public_inputs = object_field(proof, "publicInputs", "mleProof")?
        .as_array()
        .ok_or_else(|| "mleProof.publicInputs must be an array".to_string())?;
    if public_inputs.len() != 8 {
        return Err("mleProof.publicInputs must contain exactly eight VPI-hash limbs".into());
    }
    let mut actual = [0u8; 32];
    for (index, value) in public_inputs[..8].iter().enumerate() {
        let limb = parse_uint_value(value, 32, &format!("mleProof.publicInputs[{index}]"))?;
        let bytes = limb.to_bytes_be();
        actual[index * 4 + (4 - bytes.len())..index * 4 + 4].copy_from_slice(&bytes);
    }
    if actual != expected {
        return Err(
            "mleProof.publicInputs[0..8] does not encode keccak256(ValidityPublicInputs)".into(),
        );
    }
    Ok(())
}

fn posted_block_hash(
    previous: &str,
    block: &PostingSubBlock,
) -> std::result::Result<String, String> {
    // Byte-for-byte mirror of IntmaxRollup._computeBlockHash and Block::hash_with_prev_hash.
    let mut material = decode_hex(
        &Value::String(previous.to_string()),
        Some(32),
        "previous block hash chain",
    )?;
    material.extend(block.channel_id.to_be_bytes());
    material.extend(block.timestamp.to_be_bytes());
    for key_id in &block.key_ids {
        material.extend(key_id.to_be_bytes());
    }
    for (value, label) in [
        (&block.tx_tree_root, "sub-block tx tree root"),
        (&block.deposit_hash_chain, "sub-block deposit hash chain"),
        (
            &block.channel_reg_hash_chain,
            "sub-block registration hash chain",
        ),
    ] {
        material.extend(decode_hex(&Value::String(value.clone()), Some(32), label)?);
    }
    Ok(keccak_hex(&material))
}

fn stable_artifact_hash(raw: &Value) -> std::result::Result<String, String> {
    let body = serde_json::json!({
        "candidateReceipt": object_field(raw, "candidateReceipt", "envelope")?,
        "postingArtifact": object_field(raw, "postingArtifact", "envelope")?,
        "finalizeArtifact": object_field(raw, "finalizeArtifact", "envelope")?,
    });
    let digest = Sha256::digest(canonical_json(&body).as_bytes());
    Ok(format!(
        "close-funding-validity-artifact:{}",
        hex::encode(digest)
    ))
}

fn prepare_envelope(bytes: &[u8]) -> Result<PreparedEnvelope> {
    let raw: Value = serde_json::from_slice(bytes)
        .map_err(|error| PublicValidityPublisherError::Envelope(format!("parse JSON: {error}")))?;
    let envelope: ValidityEnvelope = serde_json::from_value(raw.clone()).map_err(|error| {
        PublicValidityPublisherError::Envelope(format!("parse validity fields: {error}"))
    })?;
    let fail = |message: String| PublicValidityPublisherError::Envelope(message);

    if envelope.schema_version != ENVELOPE_SCHEMA_VERSION {
        return Err(fail(format!(
            "schemaVersion {} != required {ENVELOPE_SCHEMA_VERSION}",
            envelope.schema_version
        )));
    }
    if envelope.chain_id == 0 {
        return Err(fail("chainId must be nonzero".into()));
    }
    let rollup = normalize_hex(&envelope.rollup, 20, "rollup").map_err(&fail)?;
    let manager = normalize_hex(&envelope.manager, 20, "manager").map_err(&fail)?;
    let verifier = normalize_hex(&envelope.verifier, 20, "verifier").map_err(&fail)?;
    if same_hex(&rollup, &format!("0x{}", "00".repeat(20)))
        || same_hex(&manager, &format!("0x{}", "00".repeat(20)))
        || same_hex(&verifier, &format!("0x{}", "00".repeat(20)))
    {
        return Err(fail(
            "rollup/manager/verifier must be nonzero addresses".into(),
        ));
    }
    let proposal_hash =
        normalize_hex(&envelope.proposal_hash, 32, "proposalHash").map_err(&fail)?;
    if envelope.producer_request_id.is_empty()
        || envelope.producer_request_id.len() > 256
        || envelope.candidate_request_id.is_empty()
        || envelope.candidate_request_id.len() > 256
    {
        return Err(fail(
            "producerRequestId/candidateRequestId must be nonempty and at most 256 bytes".into(),
        ));
    }
    if envelope.posting_artifact.receipt != envelope.candidate_receipt {
        return Err(fail(
            "postingArtifact.receipt differs from candidateReceipt".into(),
        ));
    }
    let candidate_id = normalize_hex(
        string_field(
            &envelope.candidate_receipt,
            "candidateId",
            "candidateReceipt",
        )
        .map_err(&fail)?,
        32,
        "candidateReceipt.candidateId",
    )
    .map_err(&fail)?;
    if string_field(&envelope.candidate_receipt, "requestId", "candidateReceipt").map_err(&fail)?
        != envelope.candidate_request_id
    {
        return Err(fail(
            "candidateReceipt.requestId differs from candidateRequestId".into(),
        ));
    }
    let initial_block_number = u64_field(
        &envelope.candidate_receipt,
        "initialBlockNumber",
        "candidateReceipt",
    )
    .map_err(&fail)?;
    let final_block_number = u64_field(
        &envelope.candidate_receipt,
        "finalBlockNumber",
        "candidateReceipt",
    )
    .map_err(&fail)?;
    let block_count = object_field(&envelope.candidate_receipt, "metrics", "candidateReceipt")
        .and_then(|metrics| u64_field(metrics, "blockCount", "candidateReceipt.metrics"))
        .map_err(&fail)?;
    let span = final_block_number
        .checked_sub(initial_block_number)
        .ok_or_else(|| fail("candidate block span regresses".into()))?;
    if span == 0
        || span != block_count
        || usize::try_from(span).ok() != Some(envelope.posting_artifact.sub_blocks.len())
    {
        return Err(fail(
            "candidate block span/metrics do not match postingArtifact.subBlocks".into(),
        ));
    }
    if envelope.posting_artifact.sub_blocks.len() != 1 {
        return Err(fail(
            "terminal close publication must contain exactly one prepared producer block".into(),
        ));
    }
    for (index, block) in envelope.posting_artifact.sub_blocks.iter().enumerate() {
        if block.channel_id != envelope.channel_id
            || block.num_users == 0
            || usize::try_from(block.num_users).ok() != Some(block.key_ids.len())
        {
            return Err(fail(format!(
                "postingArtifact.subBlocks[{index}] has wrong channel or arity"
            )));
        }
        normalize_hex(
            &block.tx_tree_root,
            32,
            &format!("subBlocks[{index}].txTreeRoot"),
        )
        .map_err(&fail)?;
        normalize_hex(
            &block.deposit_hash_chain,
            32,
            &format!("subBlocks[{index}].depositHashChain"),
        )
        .map_err(&fail)?;
        normalize_hex(
            &block.channel_reg_hash_chain,
            32,
            &format!("subBlocks[{index}].channelRegHashChain"),
        )
        .map_err(&fail)?;
    }
    let final_block = envelope
        .posting_artifact
        .sub_blocks
        .last()
        .expect("nonempty checked");
    let mut pending_words = decode_hex(
        &Value::String(final_block.deposit_hash_chain.clone()),
        Some(32),
        "final depositHashChain",
    )
    .map_err(&fail)?;
    pending_words.extend(
        decode_hex(
            &Value::String(final_block.channel_reg_hash_chain.clone()),
            Some(32),
            "final channelRegHashChain",
        )
        .map_err(&fail)?,
    );
    let expected_pending_chains = normalize_hex(
        &envelope.posting_artifact.expected_pending_chains,
        32,
        "postingArtifact.expectedPendingChains",
    )
    .map_err(&fail)?;
    if !same_hex(&expected_pending_chains, &keccak_hex(&pending_words)) {
        return Err(fail(
            "expectedPendingChains does not name the final sub-block checkpoint".into(),
        ));
    }

    let final_state_root = normalize_hex(
        &envelope.finalize_artifact.final_state_root,
        32,
        "finalizeArtifact.finalStateRoot",
    )
    .map_err(&fail)?;
    let receipt_root = normalize_hex(
        string_field(
            &envelope.candidate_receipt,
            "finalExtendedStateCommitment",
            "candidateReceipt",
        )
        .map_err(&fail)?,
        32,
        "candidateReceipt.finalExtendedStateCommitment",
    )
    .map_err(&fail)?;
    if !same_hex(&final_state_root, &receipt_root) {
        return Err(fail(
            "finalizeArtifact.finalStateRoot differs from candidate receipt".into(),
        ));
    }
    let vpis: Value = serde_json::from_str(&envelope.finalize_artifact.vpis_json)
        .map_err(|error| fail(format!("parse finalizeArtifact.vpisJson: {error}")))?;
    let initial_block_chain = normalize_hex(
        string_field(&vpis, "initial_block_chain", "validityPIs").map_err(&fail)?,
        32,
        "validityPIs.initial_block_chain",
    )
    .map_err(&fail)?;
    let initial_ext_commitment = normalize_hex(
        string_field(&vpis, "initial_ext_commitment", "validityPIs").map_err(&fail)?,
        32,
        "validityPIs.initial_ext_commitment",
    )
    .map_err(&fail)?;
    let final_block_chain = normalize_hex(
        string_field(&vpis, "final_block_chain", "validityPIs").map_err(&fail)?,
        32,
        "validityPIs.final_block_chain",
    )
    .map_err(&fail)?;
    let receipt_initial_root = normalize_hex(
        string_field(
            &envelope.candidate_receipt,
            "initialExtendedStateCommitment",
            "candidateReceipt",
        )
        .map_err(&fail)?,
        32,
        "candidateReceipt.initialExtendedStateCommitment",
    )
    .map_err(&fail)?;
    if u64_field(&vpis, "initial_block_number", "validityPIs").map_err(&fail)?
        != initial_block_number
        || u64_field(&vpis, "final_block_number", "validityPIs").map_err(&fail)?
            != final_block_number
        || !same_hex(
            string_field(&vpis, "final_ext_commitment", "validityPIs").map_err(&fail)?,
            &final_state_root,
        )
        || !same_hex(&initial_ext_commitment, &receipt_initial_root)
    {
        return Err(fail(
            "ValidityPublicInputs block span/final commitment differs from candidate".into(),
        ));
    }
    let predicted_final_block_chain = posted_block_hash(&initial_block_chain, final_block)
        .map_err(|error| fail(format!("predict posted block hash chain: {error}")))?;
    if !same_hex(&final_block_chain, &predicted_final_block_chain) {
        return Err(fail(format!(
            "ValidityPublicInputs final block chain differs from the guarded post; expected {predicted_final_block_chain}"
        )));
    }
    // Force exact width/address validation now, before a potentially expensive blob signing call.
    let vpis_kind = AbiKind::Tuple(vpis_fields());
    encode_sequence([(&vpis_kind, &vpis, "validityPIs".to_string())]).map_err(&fail)?;

    let mle_proof: Value = serde_json::from_str(&envelope.finalize_artifact.validity_mle_json)
        .map_err(|error| fail(format!("parse validityMleJson: {error}")))?;
    let proof_abi_version = proof_abi_version(&mle_proof, envelope.chain_id).map_err(&fail)?;
    validate_public_inputs_hash(&mle_proof, &vpis).map_err(&fail)?;
    let proof_kind = AbiKind::Tuple(mle_fields(proof_abi_version));
    let proof_payload = encode_sequence([(&proof_kind, &mle_proof, "mleProof".to_string())])
        .map_err(|error| fail(format!("canonical abi.encode(MleProof): {error}")))?;
    crate::proof_da::encode_simple_coder_blobs(&proof_payload)
        .map_err(|error| fail(format!("proof DA payload: {error}")))?;
    let proof_length = u32::try_from(proof_payload.len())
        .map_err(|_| fail("canonical proof payload exceeds uint32".into()))?;
    let proof_hash = keccak_hex(&proof_payload);

    let sub_blocks_value = serde_json::to_value(&envelope.posting_artifact.sub_blocks)
        .map_err(|error| fail(format!("serialize sub-blocks: {error}")))?;
    let proof_hash_value = Value::String(proof_hash.clone());
    let proof_length_value = Value::Number(proof_length.into());
    let final_root_value = Value::String(final_state_root.clone());
    let pending_value = Value::String(expected_pending_chains.clone());
    let initial_number_value = Value::Number(initial_block_number.into());
    let initial_chain_value = Value::String(initial_block_chain.clone());
    let sub_blocks_kind = AbiKind::DynamicArray(Box::new(post_sub_block_kind()));
    let bytes32_kind = AbiKind::FixedBytes(32);
    let u32_kind = AbiKind::Uint(32);
    let post_calldata = encode_function(
        "postBlockAndSubmitGuarded",
        &[
            (&sub_blocks_kind, &sub_blocks_value, "subBlocks"),
            (&bytes32_kind, &proof_hash_value, "proofHash"),
            (&u32_kind, &proof_length_value, "proofLength"),
            (&bytes32_kind, &final_root_value, "stateRoot"),
            (&bytes32_kind, &pending_value, "expectedPendingChains"),
            (
                &AbiKind::Uint(64),
                &initial_number_value,
                "expectedBlockNumber",
            ),
            (
                &bytes32_kind,
                &initial_chain_value,
                "expectedBlockHashChain",
            ),
        ],
    )
    .map_err(|error| fail(format!("encode postBlockAndSubmit: {error}")))?;
    let post_cast_sub_blocks = format!(
        "[{}]",
        envelope
            .posting_artifact
            .sub_blocks
            .iter()
            .map(|block| format!(
                "({},{},{},[{}])",
                block.channel_id,
                block.timestamp,
                block.tx_tree_root,
                block
                    .key_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ))
            .collect::<Vec<_>>()
            .join(",")
    );

    let expected_artifact_hash = stable_artifact_hash(&raw).map_err(&fail)?;
    if envelope.artifact_hash != expected_artifact_hash {
        return Err(fail(format!(
            "artifactHash mismatch: expected {expected_artifact_hash}"
        )));
    }
    let binding_material = serde_json::json!({
        "schemaVersion": envelope.schema_version,
        "chainId": envelope.chain_id,
        "rollup": rollup,
        "channelId": envelope.channel_id,
        "manager": manager,
        "verifier": verifier,
        "proposalHash": proposal_hash,
        "producerRequestId": envelope.producer_request_id,
        "candidateRequestId": envelope.candidate_request_id,
        "candidateId": candidate_id,
        "artifactHash": envelope.artifact_hash,
        "proofAbiVersion": proof_abi_version,
        "proofHash": proof_hash,
        "proofLength": proof_length,
        "finalStateRoot": final_state_root,
        "finalBlockNumber": final_block_number,
        "expectedPendingChains": expected_pending_chains,
        "postCalldataHash": keccak_hex(&decode_hex(&Value::String(post_calldata.clone()), None, "post calldata").map_err(&fail)?),
    });
    let binding_digest = sha256_hex(canonical_json(&binding_material).as_bytes());

    Ok(PreparedEnvelope {
        envelope,
        candidate_id,
        initial_block_number,
        initial_block_chain,
        initial_ext_commitment,
        final_block_number,
        proof_abi_version,
        proof_payload,
        proof_hash,
        proof_length,
        post_calldata,
        post_cast_sub_blocks,
        final_state_root,
        expected_pending_chains,
        vpis,
        mle_proof,
        binding_digest,
    })
}

impl PreparedEnvelope {
    fn binding(&self, deployment: &CheckedDeployment) -> CandidateBinding {
        let binding_digest =
            sha256_hex(format!("{}:{}", self.binding_digest, deployment.manifest_hash).as_bytes());
        CandidateBinding {
            schema_version: self.envelope.schema_version,
            chain_id: self.envelope.chain_id,
            rollup: self.envelope.rollup.to_ascii_lowercase(),
            channel_id: self.envelope.channel_id,
            manager: self.envelope.manager.to_ascii_lowercase(),
            verifier: self.envelope.verifier.to_ascii_lowercase(),
            proposal_hash: self.envelope.proposal_hash.to_ascii_lowercase(),
            producer_request_id: self.envelope.producer_request_id.clone(),
            candidate_request_id: self.envelope.candidate_request_id.clone(),
            candidate_id: self.candidate_id.clone(),
            artifact_hash: self.envelope.artifact_hash.clone(),
            deployment_manifest_hash: deployment.manifest_hash.clone(),
            rollup_runtime_code_hash: deployment.manifest.rollup_runtime_code_hash.clone(),
            mle_verifier: deployment.manifest.mle_verifier.clone(),
            mle_verifier_runtime_code_hash: deployment
                .manifest
                .mle_verifier_runtime_code_hash
                .clone(),
            kzg_verifier: deployment.manifest.kzg_verifier.clone(),
            kzg_verifier_runtime_code_hash: deployment
                .manifest
                .kzg_verifier_runtime_code_hash
                .clone(),
            proof_abi_version: self.proof_abi_version,
            proof_hash: self.proof_hash.clone(),
            proof_length: self.proof_length,
            final_state_root: self.final_state_root.clone(),
            final_block_number: self.final_block_number,
            expected_pending_chains: self.expected_pending_chains.clone(),
            post_calldata_hash: keccak_hex(
                &hex::decode(self.post_calldata.trim_start_matches("0x"))
                    .expect("prepared calldata was validated"),
            ),
            binding_digest,
        }
    }

    fn finalize_calldata(&self, submission_id: &str) -> std::result::Result<String, String> {
        let id = Value::String(quantity_to_decimal(submission_id, "submission id")?.to_string());
        let root = Value::String(self.final_state_root.clone());
        let id_kind = AbiKind::Uint(256);
        let root_kind = AbiKind::FixedBytes(32);
        let vpis_kind = AbiKind::Tuple(vpis_fields());
        let proof_kind = AbiKind::Tuple(mle_fields(self.proof_abi_version));
        encode_function(
            "finalize",
            &[
                (&id_kind, &id, "submissionId"),
                (&root_kind, &root, "stateRoot"),
                (&vpis_kind, &self.vpis, "validityPIs"),
                (&proof_kind, &self.mle_proof, "mleProof"),
            ],
        )
    }

    fn attest_calldata(
        &self,
        submission_id: &str,
        compact_sidecars: &str,
    ) -> std::result::Result<String, String> {
        let id = Value::String(quantity_to_decimal(submission_id, "submission id")?.to_string());
        let proof = Value::String(format!("0x{}", hex::encode(&self.proof_payload)));
        let sidecars = Value::String(compact_sidecars.to_string());
        let id_kind = AbiKind::Uint(256);
        let bytes_kind = AbiKind::Bytes;
        encode_function(
            "attestProofData",
            &[
                (&id_kind, &id, "submissionId"),
                (&bytes_kind, &proof, "proofBytes"),
                (&bytes_kind, &sidecars, "blobProofs"),
            ],
        )
    }
}

#[derive(Clone, Debug)]
enum L1Signer {
    /// The well-known Anvil account zero key. It has no value outside the local test chain.
    AnvilPublicDevKey,
    FoundryAccount(String),
}

impl L1Signer {
    fn resolve(chain_id: u64, configured: Option<&str>) -> Result<Self> {
        if std::env::var("INTMAX_DEPOSIT_KEY")
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(PublicValidityPublisherError::Configuration(
                "INTMAX_DEPOSIT_KEY/raw key input is forbidden; select an encrypted Foundry account"
                    .into(),
            ));
        }
        if let Some(account) = configured.map(str::trim).filter(|value| !value.is_empty()) {
            validate_account_name(account).map_err(PublicValidityPublisherError::Configuration)?;
            return Ok(Self::FoundryAccount(account.to_string()));
        }
        if chain_id == ANVIL_CHAIN_ID {
            return Ok(Self::AnvilPublicDevKey);
        }
        Err(PublicValidityPublisherError::Configuration(format!(
            "a Foundry encrypted-keystore account is required on chain {chain_id}; set --account or INTMAX_L1_ACCOUNT"
        )))
    }

    fn append(&self, command: &mut Command) {
        match self {
            Self::AnvilPublicDevKey => {
                command.arg("--private-key").arg(ANVIL_PUBLIC_DEV_KEY);
            }
            Self::FoundryAccount(account) => {
                command.arg("--account").arg(account);
            }
        }
    }

    fn address(&self) -> Result<String> {
        let mut command = Command::new("cast");
        command.args(["wallet", "address"]);
        self.append(&mut command);
        let output = checked_output(command, "resolve Foundry signer address", 4096)?;
        normalize_hex(output.trim(), 20, "signer address")
            .map_err(PublicValidityPublisherError::Command)
    }
}

fn checked_output(mut command: Command, what: &str, limit: usize) -> Result<String> {
    let output = command
        .output()
        .map_err(|error| PublicValidityPublisherError::Command(format!("start {what}: {error}")))?;
    if !output.status.success() {
        return Err(PublicValidityPublisherError::Command(format!(
            "{what} returned {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    if output.stdout.len() > limit {
        return Err(PublicValidityPublisherError::Command(format!(
            "{what} output exceeds {limit} bytes"
        )));
    }
    String::from_utf8(output.stdout).map_err(|error| {
        PublicValidityPublisherError::Command(format!("{what} output is not UTF-8: {error}"))
    })
}

fn cast_output(args: &[&str], what: &str, limit: usize) -> Result<String> {
    let mut command = Command::new("cast");
    command.args(args);
    checked_output(command, what, limit)
}

fn quantity_to_decimal(value: &str, what: &str) -> std::result::Result<BigUint, String> {
    let value = value.trim();
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |body| (body, 16));
    if digits.is_empty()
        || (radix == 10 && !digits.bytes().all(|byte| byte.is_ascii_digit()))
        || (radix == 16 && !digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(format!("{what} is not a canonical unsigned quantity"));
    }
    BigUint::parse_bytes(digits.as_bytes(), radix)
        .ok_or_else(|| format!("{what} is not an unsigned quantity"))
}

fn quantity_u64(value: &str, what: &str) -> std::result::Result<u64, String> {
    u64::try_from(quantity_to_decimal(value, what)?).map_err(|_| format!("{what} does not fit u64"))
}

fn decode_signed_transaction(raw: &str) -> Result<Value> {
    let raw = raw.trim();
    if raw.len() < 4
        || raw.len() > MAX_RAW_TRANSACTION_CHARS
        || !raw.starts_with("0x")
        || !raw[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(PublicValidityPublisherError::Evidence(
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
            PublicValidityPublisherError::Command(format!("start cast decode-transaction: {error}"))
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| PublicValidityPublisherError::Command("decoder stdin is absent".into()))?
        .write_all(raw.as_bytes())
        .map_err(|error| {
            PublicValidityPublisherError::Command(format!("write decoder stdin: {error}"))
        })?;
    let output = child.wait_with_output().map_err(|error| {
        PublicValidityPublisherError::Command(format!("wait for transaction decoder: {error}"))
    })?;
    if !output.status.success() || output.stdout.len() > MAX_RPC_JSON_BYTES {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "cast rejected signed transaction: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        PublicValidityPublisherError::Evidence(format!(
            "decoded signed transaction JSON is invalid: {error}"
        ))
    })
}

fn decoded_string<'a>(decoded: &'a Value, field: &str) -> std::result::Result<&'a str, String> {
    decoded
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("decoded transaction has no string {field}"))
}

fn validate_common_decoded_transaction(
    decoded: &Value,
    chain_id: u64,
    signer: &str,
    target: &str,
    value: u64,
    calldata: &str,
) -> std::result::Result<(String, u64), String> {
    if quantity_u64(decoded_string(decoded, "chainId")?, "transaction chainId")? != chain_id {
        return Err("signed transaction targets another chain".into());
    }
    if !same_hex(decoded_string(decoded, "signer")?, signer) {
        return Err("signed transaction has another signer".into());
    }
    if !same_hex(decoded_string(decoded, "to")?, target) {
        return Err("signed transaction has another target".into());
    }
    if quantity_u64(decoded_string(decoded, "value")?, "transaction value")? != value {
        return Err("signed transaction has another value".into());
    }
    if !same_hex(decoded_string(decoded, "input")?, calldata) {
        return Err("signed transaction has different calldata".into());
    }
    let hash = normalize_hex(decoded_string(decoded, "hash")?, 32, "transaction hash")?;
    let nonce = quantity_u64(decoded_string(decoded, "nonce")?, "transaction nonce")?;
    Ok((hash, nonce))
}

fn sign_normal_transaction(
    rpc: &str,
    signer: &L1Signer,
    signer_address: &str,
    chain_id: u64,
    target: &str,
    calldata: &str,
) -> Result<RawTransactionStep> {
    let mut command = Command::new("cast");
    command.args(["mktx", target, calldata, "--rpc-url", rpc, "--json"]);
    signer.append(&mut command);
    let raw = checked_output(
        command,
        "sign raw L1 transaction",
        MAX_RAW_TRANSACTION_CHARS,
    )?
    .trim()
    .to_string();
    let decoded = decode_signed_transaction(&raw)?;
    let tx_type =
        decoded_string(&decoded, "type").map_err(PublicValidityPublisherError::Evidence)?;
    if tx_type == "0x3" || tx_type == "0x03" {
        return Err(PublicValidityPublisherError::Evidence(
            "attest/finalize unexpectedly signed as a blob transaction".into(),
        ));
    }
    let (transaction_hash, nonce) = validate_common_decoded_transaction(
        &decoded,
        chain_id,
        signer_address,
        target,
        0,
        calldata,
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    Ok(RawTransactionStep {
        target: target.to_ascii_lowercase(),
        calldata_hash: keccak_hex(
            &hex::decode(calldata.trim_start_matches("0x"))
                .map_err(|error| PublicValidityPublisherError::Evidence(error.to_string()))?,
        ),
        value: 0,
        nonce,
        raw_signed_transaction: raw,
        transaction_hash,
        confirmation: None,
        superseded_confirmation: None,
    })
}

fn sign_blob_transaction(
    prepared: &PreparedEnvelope,
    rpc: &str,
    signer: &L1Signer,
    signer_address: &str,
    proof_path: &Path,
) -> Result<BlobPostStep> {
    let proof_path = proof_path.to_str().ok_or_else(|| {
        PublicValidityPublisherError::Configuration("proof path is not UTF-8".into())
    })?;
    let proof_length = prepared.proof_length.to_string();
    let mut command = Command::new("cast");
    command.args([
        "mktx",
        &prepared.envelope.rollup,
        POST_SIGNATURE,
        &prepared.post_cast_sub_blocks,
        &prepared.proof_hash,
        &proof_length,
        &prepared.final_state_root,
        &prepared.expected_pending_chains,
        &prepared.initial_block_number.to_string(),
        &prepared.initial_block_chain,
        "--value",
        "1ether",
        "--blob",
        "--path",
        proof_path,
        "--rpc-url",
        rpc,
        "--json",
    ]);
    signer.append(&mut command);
    let raw = checked_output(
        command,
        "sign EIP-4844 validity post",
        MAX_RAW_TRANSACTION_CHARS,
    )?
    .trim()
    .to_string();
    let decoded_value = decode_signed_transaction(&raw)?;
    let decoded: DecodedBlobTransaction =
        serde_json::from_value(decoded_value.clone()).map_err(|error| {
            PublicValidityPublisherError::Evidence(format!("decode EIP-4844 fields: {error}"))
        })?;
    let checked = validate_decoded_blob_transaction(
        &decoded,
        &prepared.proof_payload,
        prepared.envelope.chain_id,
        signer_address,
        &prepared.envelope.rollup,
        POST_STAKE_WEI,
        &prepared.post_calldata,
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    let nonce = quantity_u64(
        decoded_string(&decoded_value, "nonce").map_err(PublicValidityPublisherError::Evidence)?,
        "blob transaction nonce",
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    Ok(BlobPostStep {
        transaction: RawTransactionStep {
            target: prepared.envelope.rollup.to_ascii_lowercase(),
            calldata_hash: keccak_hex(
                &hex::decode(prepared.post_calldata.trim_start_matches("0x"))
                    .expect("prepared calldata is hex"),
            ),
            value: POST_STAKE_WEI,
            nonce,
            raw_signed_transaction: raw,
            transaction_hash: checked.transaction_hash,
            confirmation: None,
            superseded_confirmation: None,
        },
        blob_versioned_hashes: checked.blob_versioned_hashes,
        compact_sidecars: checked.compact_sidecars,
        submission_id: None,
    })
}

fn validate_persisted_normal_step(
    step: &RawTransactionStep,
    chain_id: u64,
    signer: &str,
    target: &str,
    calldata: &str,
) -> Result<()> {
    let decoded = decode_signed_transaction(&step.raw_signed_transaction)?;
    let (hash, nonce) =
        validate_common_decoded_transaction(&decoded, chain_id, signer, target, 0, calldata)
            .map_err(PublicValidityPublisherError::Evidence)?;
    let calldata_hash = keccak_hex(
        &hex::decode(calldata.trim_start_matches("0x"))
            .map_err(|error| PublicValidityPublisherError::Evidence(error.to_string()))?,
    );
    if !same_hex(&step.target, target)
        || step.value != 0
        || !same_hex(&step.transaction_hash, &hash)
        || step.nonce != nonce
        || !same_hex(&step.calldata_hash, &calldata_hash)
    {
        return Err(PublicValidityPublisherError::Conflict(
            "persisted raw transaction metadata was modified".into(),
        ));
    }
    Ok(())
}

fn validate_persisted_blob_step(
    step: &BlobPostStep,
    prepared: &PreparedEnvelope,
    signer: &str,
) -> Result<()> {
    let decoded_value = decode_signed_transaction(&step.transaction.raw_signed_transaction)?;
    let decoded: DecodedBlobTransaction =
        serde_json::from_value(decoded_value.clone()).map_err(|error| {
            PublicValidityPublisherError::Evidence(format!(
                "decode persisted EIP-4844 fields: {error}"
            ))
        })?;
    let checked: ValidatedBlobSidecars = validate_decoded_blob_transaction(
        &decoded,
        &prepared.proof_payload,
        prepared.envelope.chain_id,
        signer,
        &prepared.envelope.rollup,
        POST_STAKE_WEI,
        &prepared.post_calldata,
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    let nonce = quantity_u64(
        decoded_string(&decoded_value, "nonce").map_err(PublicValidityPublisherError::Evidence)?,
        "persisted blob transaction nonce",
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    let calldata_hash = keccak_hex(
        &hex::decode(prepared.post_calldata.trim_start_matches("0x"))
            .expect("prepared post calldata is valid hex"),
    );
    if !same_hex(&step.transaction.target, &prepared.envelope.rollup)
        || step.transaction.value != POST_STAKE_WEI
        || !same_hex(&step.transaction.calldata_hash, &calldata_hash)
        || step.transaction.nonce != nonce
        || !same_hex(
            &step.transaction.transaction_hash,
            &checked.transaction_hash,
        )
        || step.blob_versioned_hashes != checked.blob_versioned_hashes
        || !same_hex(&step.compact_sidecars, &checked.compact_sidecars)
    {
        return Err(PublicValidityPublisherError::Conflict(
            "persisted EIP-4844 sidecar/transaction metadata was modified".into(),
        ));
    }
    Ok(())
}

fn inspect_private_file(path: &Path, maximum: u64) -> Result<Option<fs::Metadata>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(PublicValidityPublisherError::Journal(format!(
                "inspect {}: {error}",
                path.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PublicValidityPublisherError::Journal(format!(
            "{} must be a regular non-symlink file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(PublicValidityPublisherError::Journal(format!(
            "{} exceeds {maximum} bytes",
            path.display()
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            PublicValidityPublisherError::Journal(format!(
                "repair {} permissions to 0600: {error}",
                path.display()
            ))
        })?;
    }
    Ok(Some(metadata))
}

fn ensure_private_lock_root(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(PublicValidityPublisherError::Configuration(
            "lock root must be an absolute path shared by every publisher using the signer".into(),
        ));
    }
    fs::create_dir_all(path).map_err(|error| {
        PublicValidityPublisherError::Journal(format!(
            "create signer lock root {}: {error}",
            path.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        PublicValidityPublisherError::Journal(format!(
            "inspect signer lock root {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PublicValidityPublisherError::Configuration(format!(
            "signer lock root {} must be a non-symlink directory",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(PublicValidityPublisherError::Configuration(format!(
                "signer lock root {} is not owned by the current operator",
                path.display()
            )));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
                PublicValidityPublisherError::Journal(format!(
                    "repair signer lock root {} permissions to 0700: {error}",
                    path.display()
                ))
            })?;
        }
    }
    // Resolve aliases before deriving the signer filename. Two invocations may spell an ancestor
    // differently, but they must still contend on the same inode-backed lock directory.
    fs::canonicalize(path).map_err(|error| {
        PublicValidityPublisherError::Journal(format!(
            "canonicalize signer lock root {}: {error}",
            path.display()
        ))
    })
}

fn signer_lock_base(lock_root: &Path, chain_id: u64, signer: &str) -> Result<PathBuf> {
    let signer = normalize_hex(signer, 20, "signer lock address")
        .map_err(PublicValidityPublisherError::Configuration)?;
    Ok(lock_root.join(format!(
        ".intmax-l1-signer-{chain_id}-{}",
        signer.trim_start_matches("0x")
    )))
}

fn read_bounded(path: &Path, maximum: u64, what: &str) -> Result<Vec<u8>> {
    inspect_private_file(path, maximum)?.ok_or_else(|| {
        PublicValidityPublisherError::Configuration(format!(
            "{what} does not exist: {}",
            path.display()
        ))
    })?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        PublicValidityPublisherError::Journal(format!("open {}: {error}", path.display()))
    })?;
    let opened = file.metadata().map_err(|error| {
        PublicValidityPublisherError::Journal(format!("inspect opened {}: {error}", path.display()))
    })?;
    if !opened.is_file() || opened.len() > maximum {
        return Err(PublicValidityPublisherError::Journal(format!(
            "opened {what} is not a bounded regular file"
        )));
    }
    let capacity = usize::try_from(maximum.min(8 * 1024 * 1024)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            PublicValidityPublisherError::Journal(format!("read {}: {error}", path.display()))
        })?;
    if bytes.len() as u64 > maximum {
        return Err(PublicValidityPublisherError::Journal(format!(
            "{what} exceeds {maximum} bytes"
        )));
    }
    Ok(bytes)
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        PublicValidityPublisherError::Journal(format!("create {}: {error}", parent.display()))
    })?;
    if let Some(metadata) = inspect_private_file(path, u64::MAX)? {
        if metadata.file_type().is_symlink() {
            unreachable!("inspect_private_file rejects symlinks")
        }
    }
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            PublicValidityPublisherError::Journal(format!(
                "{} has no UTF-8 filename",
                path.display()
            ))
        })?;
    let temporary = parent.join(format!(
        ".{filename}.tmp.{}.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        PRIVATE_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary).map_err(|error| {
        PublicValidityPublisherError::Journal(format!(
            "create private temporary {}: {error}",
            temporary.display()
        ))
    })?;
    let write_result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let directory = fs::File::open(parent)?;
        directory.sync_all()
    })();
    if let Err(error) = write_result {
        return Err(PublicValidityPublisherError::Journal(format!(
            "durably replace {}: {error}; temporary file retained at {}",
            path.display(),
            temporary.display()
        )));
    }
    Ok(())
}

fn write_journal(path: &Path, journal: &PublicationJournal) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).map_err(|error| {
        PublicValidityPublisherError::Journal(format!("serialize journal: {error}"))
    })?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(PublicValidityPublisherError::Journal(format!(
            "journal would exceed {MAX_JOURNAL_BYTES} bytes"
        )));
    }
    atomic_write_private(path, &bytes)
}

fn proof_payload_path(journal_path: &Path) -> Result<PathBuf> {
    let filename = journal_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            PublicValidityPublisherError::Configuration(
                "journal path must have a UTF-8 filename".into(),
            )
        })?;
    Ok(journal_path.with_file_name(format!("{filename}.proof.bin")))
}

fn load_or_create_journal(
    path: &Path,
    binding: CandidateBinding,
    submitter: &str,
    signer_lock_root: &Path,
) -> Result<PublicationJournal> {
    let signer_lock_root = signer_lock_root.to_str().ok_or_else(|| {
        PublicValidityPublisherError::Configuration(
            "canonical signer lock root must have a UTF-8 representation".into(),
        )
    })?;
    if inspect_private_file(path, MAX_JOURNAL_BYTES)?.is_some() {
        let bytes = read_bounded(path, MAX_JOURNAL_BYTES, "publication journal")?;
        let journal: PublicationJournal = serde_json::from_slice(&bytes).map_err(|error| {
            PublicValidityPublisherError::Journal(format!(
                "parse publication journal {}: {error}",
                path.display()
            ))
        })?;
        if journal.version != JOURNAL_VERSION {
            return Err(PublicValidityPublisherError::Conflict(format!(
                "journal version {} != supported {JOURNAL_VERSION}",
                journal.version
            )));
        }
        if journal.binding != binding
            || !same_hex(&journal.submitter, submitter)
            || journal.signer_lock_root != signer_lock_root
        {
            return Err(PublicValidityPublisherError::Conflict(
                "journal belongs to a sibling chain/rollup/candidate/artifact/signer/lock-root"
                    .into(),
            ));
        }
        return Ok(journal);
    }
    let journal = PublicationJournal {
        version: JOURNAL_VERSION,
        binding,
        submitter: submitter.to_ascii_lowercase(),
        signer_lock_root: signer_lock_root.to_string(),
        post: None,
        attest: None,
        finalize: None,
        adopted_finalize: None,
        completed: None,
    };
    write_journal(path, &journal)?;
    Ok(journal)
}

#[cfg(unix)]
struct JournalLock(fs::File);

#[cfg(unix)]
impl JournalLock {
    fn acquire(journal_path: &Path) -> Result<Self> {
        let filename = journal_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                PublicValidityPublisherError::Configuration(
                    "journal path must have a UTF-8 filename".into(),
                )
            })?;
        let lock_path = journal_path.with_file_name(format!("{filename}.lock"));
        let parent = lock_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            PublicValidityPublisherError::Journal(format!("create {}: {error}", parent.display()))
        })?;
        inspect_private_file(&lock_path, 4096)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|error| {
                PublicValidityPublisherError::Journal(format!(
                    "open journal lock {}: {error}",
                    lock_path.display()
                ))
            })?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(PublicValidityPublisherError::Conflict(format!(
                "another publisher holds {}",
                lock_path.display()
            )));
        }
        Ok(Self(file))
    }
}

fn rpc_chain_id(rpc: &str) -> Result<u64> {
    let output = cast_output(&["chain-id", "--rpc-url", rpc], "read L1 chain id", 4096)?;
    quantity_u64(output.trim(), "L1 chain id").map_err(PublicValidityPublisherError::Evidence)
}

fn rpc_block(rpc: &str, tag: &str) -> Result<Value> {
    let output = cast_output(
        &[
            "rpc",
            "eth_getBlockByNumber",
            tag,
            "false",
            "--rpc-url",
            rpc,
        ],
        &format!("read L1 block {tag}"),
        MAX_RPC_JSON_BYTES,
    )?;
    let value: Value = serde_json::from_str(output.trim()).map_err(|error| {
        PublicValidityPublisherError::Evidence(format!("parse L1 block {tag}: {error}"))
    })?;
    if !value.is_object() {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "L1 block {tag} is null or not an object"
        )));
    }
    Ok(value)
}

fn parse_checkpoint(
    block: &Value,
    chain_id: u64,
    source: L1FinalitySource,
) -> Result<L1FinalizedCheckpoint> {
    let number = decoded_string(block, "number")
        .and_then(|value| quantity_u64(value, "block number"))
        .map_err(PublicValidityPublisherError::Evidence)?;
    let block_hash = normalize_hex(
        decoded_string(block, "hash").map_err(PublicValidityPublisherError::Evidence)?,
        32,
        "block hash",
    )
    .map_err(PublicValidityPublisherError::Evidence)?
    .parse::<Bytes32>()
    .map_err(|error| {
        PublicValidityPublisherError::Evidence(format!("parse block hash: {error}"))
    })?;
    let parent_hash = normalize_hex(
        decoded_string(block, "parentHash").map_err(PublicValidityPublisherError::Evidence)?,
        32,
        "block parentHash",
    )
    .map_err(PublicValidityPublisherError::Evidence)?
    .parse::<Bytes32>()
    .map_err(|error| {
        PublicValidityPublisherError::Evidence(format!("parse block parent hash: {error}"))
    })?;
    let checkpoint = L1FinalizedCheckpoint {
        chain_id,
        block_number: number,
        block_hash,
        parent_hash,
        source,
    };
    checkpoint
        .validate()
        .map_err(PublicValidityPublisherError::Evidence)?;
    Ok(checkpoint)
}

fn read_durable_checkpoint(
    rpc: &str,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
) -> Result<L1FinalizedCheckpoint> {
    let observed = rpc_chain_id(rpc)?;
    if observed != chain_id {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "RPC chain id changed from {chain_id} to {observed}"
        )));
    }
    match rpc_block(rpc, "finalized")
        .and_then(|block| parse_checkpoint(&block, chain_id, L1FinalitySource::RpcFinalized))
    {
        Ok(checkpoint) => Ok(checkpoint),
        Err(_finalized_error) if chain_id == ANVIL_CHAIN_ID && allow_unfinalized_devnet => {
            rpc_block(rpc, "latest").and_then(|block| {
                parse_checkpoint(&block, chain_id, L1FinalitySource::DevnetLatest)
            })
        }
        Err(finalized_error) => Err(PublicValidityPublisherError::Evidence(format!(
            "RPC cannot provide a valid finalized head: {finalized_error}"
        ))),
    }
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

fn validate_deployment_checkpoint_window(
    before: &L1FinalizedCheckpoint,
    after: &L1FinalizedCheckpoint,
) -> Result<()> {
    checkpoint_advances(before, after).map_err(PublicValidityPublisherError::Evidence)?;
    after
        .covers_receipt(before.block_number, before.block_hash)
        .map_err(PublicValidityPublisherError::Evidence)
}

fn revalidate_checkpoint(rpc: &str, checkpoint: &L1FinalizedCheckpoint) -> Result<()> {
    checkpoint
        .validate()
        .map_err(PublicValidityPublisherError::Evidence)?;
    let tag = format!("0x{:x}", checkpoint.block_number);
    let canonical = parse_checkpoint(
        &rpc_block(rpc, &tag)?,
        checkpoint.chain_id,
        checkpoint.source,
    )?;
    if canonical.block_hash != checkpoint.block_hash
        || canonical.parent_hash != checkpoint.parent_hash
        || canonical.block_number != checkpoint.block_number
    {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "stored durable checkpoint {} was reorged",
            checkpoint.block_number
        )));
    }
    Ok(())
}

fn rpc_receipt(rpc: &str, transaction_hash: &str) -> Result<Option<Value>> {
    let mut command = Command::new("cast");
    command.args([
        "receipt",
        transaction_hash,
        "--json",
        "--async",
        "--rpc-url",
        rpc,
    ]);
    let output = command.output().map_err(|error| {
        PublicValidityPublisherError::Command(format!("start receipt query: {error}"))
    })?;
    if !output.status.success() || output.stdout.is_empty() {
        return Ok(None);
    }
    if output.stdout.len() > MAX_RPC_JSON_BYTES {
        return Err(PublicValidityPublisherError::Evidence(
            "receipt JSON exceeds size limit".into(),
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        PublicValidityPublisherError::Evidence(format!("parse receipt: {error}"))
    })?;
    Ok((!value.is_null()).then_some(value))
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

fn receipt_status(receipt: &Value) -> std::result::Result<bool, String> {
    let status = receipt_quantity(receipt, "status")?;
    match status {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("receipt status is neither canonical zero nor one".into()),
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

fn validate_receipt_location(
    receipt: &Value,
    transaction_hash: &str,
    signer: Option<&str>,
    target: Option<&str>,
    require_success: bool,
) -> Result<(String, Bytes32, u64)> {
    let success = receipt_status(receipt).map_err(PublicValidityPublisherError::Evidence)?;
    if require_success && !success {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "transaction {transaction_hash} reverted"
        )));
    }
    let mut expected_fields = vec![("transactionHash", transaction_hash)];
    if let Some(signer) = signer {
        expected_fields.push(("from", signer));
    }
    if let Some(target) = target {
        expected_fields.push(("to", target));
    }
    for (field, expected) in expected_fields {
        let actual =
            decoded_string(receipt, field).map_err(PublicValidityPublisherError::Evidence)?;
        if !same_hex(actual, expected) {
            return Err(PublicValidityPublisherError::Evidence(format!(
                "receipt {field} differs from signed transaction"
            )));
        }
    }
    let block_hash_text = normalize_hex(
        decoded_string(receipt, "blockHash").map_err(PublicValidityPublisherError::Evidence)?,
        32,
        "receipt blockHash",
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    let block_hash = block_hash_text.parse::<Bytes32>().map_err(|error| {
        PublicValidityPublisherError::Evidence(format!("parse receipt blockHash: {error}"))
    })?;
    let block_number =
        receipt_quantity(receipt, "blockNumber").map_err(PublicValidityPublisherError::Evidence)?;
    Ok((block_hash_text, block_hash, block_number))
}

fn wait_for_finalized_receipt_with_identity(
    rpc: &str,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
    timeout: Duration,
    transaction_hash: &str,
    signer: Option<&str>,
    target: Option<&str>,
    require_success: bool,
) -> Result<(Value, FinalizedReceipt)> {
    let started = Instant::now();
    loop {
        if let Some(receipt) = rpc_receipt(rpc, transaction_hash)? {
            let (block_hash_text, block_hash, block_number) = validate_receipt_location(
                &receipt,
                transaction_hash,
                signer,
                target,
                require_success,
            )?;
            let durable_before = read_durable_checkpoint(rpc, chain_id, allow_unfinalized_devnet)?;
            if block_number <= durable_before.block_number {
                let tag = format!("0x{block_number:x}");
                let canonical =
                    parse_checkpoint(&rpc_block(rpc, &tag)?, chain_id, durable_before.source)?;
                if canonical.block_number != block_number || canonical.block_hash != block_hash {
                    return Err(PublicValidityPublisherError::Evidence(format!(
                        "transaction {transaction_hash} receipt block is not canonical"
                    )));
                }
                durable_before
                    .covers_receipt(block_number, block_hash)
                    .map_err(PublicValidityPublisherError::Evidence)?;
                let second = rpc_receipt(rpc, transaction_hash)?.ok_or_else(|| {
                    PublicValidityPublisherError::Evidence(
                        "receipt disappeared during final read-back".into(),
                    )
                })?;
                if !stable_receipt_fields(&receipt, &second) {
                    return Err(PublicValidityPublisherError::Evidence(
                        "receipt changed during final read-back".into(),
                    ));
                }
                revalidate_checkpoint(rpc, &durable_before)?;
                let durable_after =
                    read_durable_checkpoint(rpc, chain_id, allow_unfinalized_devnet)?;
                checkpoint_advances(&durable_before, &durable_after)
                    .map_err(PublicValidityPublisherError::Evidence)?;
                durable_after
                    .covers_receipt(block_number, block_hash)
                    .map_err(PublicValidityPublisherError::Evidence)?;
                revalidate_checkpoint(rpc, &durable_after)?;
                let canonical_after = parse_checkpoint(
                    &rpc_block(rpc, &format!("0x{block_number:x}"))?,
                    chain_id,
                    durable_after.source,
                )?;
                if canonical_after.block_number != block_number
                    || canonical_after.block_hash != block_hash
                {
                    return Err(PublicValidityPublisherError::Evidence(format!(
                        "transaction {transaction_hash} receipt block changed during durable-head read-back"
                    )));
                }
                return Ok((
                    receipt,
                    FinalizedReceipt {
                        transaction_hash: transaction_hash.to_ascii_lowercase(),
                        block_hash: block_hash_text,
                        block_number,
                        finalized_checkpoint: durable_after,
                    },
                ));
            }
        }
        if started.elapsed() >= timeout {
            return Err(PublicValidityPublisherError::Timeout(format!(
                "transaction {transaction_hash} is not covered by a canonical durable head after {}s; exact raw transaction remains journaled",
                timeout.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_secs(6));
    }
}

fn wait_for_finalized_receipt(
    rpc: &str,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
    timeout: Duration,
    transaction_hash: &str,
    signer: &str,
    target: &str,
) -> Result<(Value, FinalizedReceipt)> {
    wait_for_finalized_receipt_with_identity(
        rpc,
        chain_id,
        allow_unfinalized_devnet,
        timeout,
        transaction_hash,
        Some(signer),
        Some(target),
        true,
    )
}

fn transaction_known(rpc: &str, transaction_hash: &str) -> Result<bool> {
    let output = cast_output(
        &[
            "rpc",
            "eth_getTransactionByHash",
            transaction_hash,
            "--rpc-url",
            rpc,
        ],
        "query signed transaction hash",
        MAX_RPC_JSON_BYTES,
    )?;
    let value: Value = serde_json::from_str(output.trim()).map_err(|error| {
        PublicValidityPublisherError::Evidence(format!("parse transaction lookup: {error}"))
    })?;
    Ok(!value.is_null())
}

fn rpc_transaction(rpc: &str, transaction_hash: &str) -> Result<Option<Value>> {
    let output = cast_output(
        &[
            "rpc",
            "eth_getTransactionByHash",
            transaction_hash,
            "--rpc-url",
            rpc,
        ],
        "query transaction body",
        MAX_RPC_JSON_BYTES,
    )?;
    let value: Value = serde_json::from_str(output.trim()).map_err(|error| {
        PublicValidityPublisherError::Evidence(format!("parse transaction body: {error}"))
    })?;
    if value.is_null() {
        Ok(None)
    } else if value.is_object() {
        Ok(Some(value))
    } else {
        Err(PublicValidityPublisherError::Evidence(
            "transaction lookup returned neither object nor null".into(),
        ))
    }
}

fn object_quantity(value: &Value, field: &str, what: &str) -> std::result::Result<u64, String> {
    match value.get(field) {
        Some(Value::String(value)) => quantity_u64(value, what),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("{what} is not unsigned")),
        _ => Err(format!("{what} is missing or not numeric")),
    }
}

fn object_uint256(value: &Value, field: &str, what: &str) -> std::result::Result<BigUint, String> {
    let quantity = match value.get(field) {
        Some(Value::String(value)) => quantity_to_decimal(value, what)?,
        Some(Value::Number(value)) => BigUint::from(
            value
                .as_u64()
                .ok_or_else(|| format!("{what} is not unsigned"))?,
        ),
        _ => return Err(format!("{what} is missing or not numeric")),
    };
    if quantity.to_bytes_be().len() > 32 {
        return Err(format!("{what} does not fit uint256"));
    }
    Ok(quantity)
}

/// Bind the transaction body to its receipt/inclusion only. The sender, outer target, calldata,
/// value and nonce are deliberately not compared to the local finalize call: a watchtower may
/// route a permissionless finalize through a batch wrapper. Exact Rollup events and same-block
/// getters provide semantic authority instead.
fn validate_semantic_transaction(
    transaction: &Value,
    receipt: &Value,
    transaction_hash: &str,
    block_hash: &str,
    block_number: u64,
) -> std::result::Result<(), String> {
    for (field, expected) in [("hash", transaction_hash), ("blockHash", block_hash)] {
        if !transaction
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|actual| same_hex(actual, expected))
        {
            return Err(format!(
                "semantic finalization transaction {field} differs from its receipt/log"
            ));
        }
    }
    let from = transaction
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| "semantic finalization transaction lacks sender".to_string())?;
    validate_nonzero_hex(from, 20, "semantic finalization sender")?;
    let receipt_from = receipt
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| "semantic finalization receipt lacks sender".to_string())?;
    if !same_hex(from, receipt_from) {
        return Err("semantic finalization sender differs between transaction and receipt".into());
    }
    let transaction_to = transaction.get("to").unwrap_or(&Value::Null);
    let receipt_to = receipt.get("to").unwrap_or(&Value::Null);
    let same_to = match (transaction_to.as_str(), receipt_to.as_str()) {
        (Some(left), Some(right)) => {
            normalize_hex(left, 20, "semantic finalization outer target")?;
            same_hex(left, right)
        }
        (None, None) => transaction_to.is_null() && receipt_to.is_null(),
        _ => false,
    };
    let input = transaction
        .get("input")
        .and_then(Value::as_str)
        .ok_or_else(|| "semantic finalization transaction lacks input".to_string())?;
    decode_hex(
        &Value::String(input.to_string()),
        None,
        "semantic finalization outer calldata",
    )?;
    object_uint256(transaction, "value", "semantic finalization value")?;
    object_quantity(transaction, "nonce", "semantic finalization nonce")?;
    let transaction_index = object_quantity(
        transaction,
        "transactionIndex",
        "semantic finalization transactionIndex",
    )?;
    let receipt_index = object_quantity(
        receipt,
        "transactionIndex",
        "semantic finalization receipt transactionIndex",
    )?;
    if object_quantity(
        transaction,
        "blockNumber",
        "semantic finalization blockNumber",
    )? != block_number
        || !same_to
        || transaction_index != receipt_index
    {
        return Err(
            "semantic finalization transaction inclusion differs from its receipt/log".into(),
        );
    }
    Ok(())
}

fn stable_transaction_fields(left: &Value, right: &Value) -> bool {
    [
        "hash",
        "from",
        "to",
        "input",
        "value",
        "nonce",
        "blockHash",
        "blockNumber",
        "transactionIndex",
    ]
    .iter()
    .all(|field| left.get(field) == right.get(field))
}

fn account_nonce(rpc: &str, address: &str) -> Result<u64> {
    let output = cast_output(
        &["nonce", address, "--block", "latest", "--rpc-url", rpc],
        "read signer nonce",
        4096,
    )?;
    quantity_u64(output.trim(), "signer latest nonce")
        .map_err(PublicValidityPublisherError::Evidence)
}

fn exact_publish_needed(
    transaction_is_known: bool,
    current_nonce: u64,
    step: &RawTransactionStep,
) -> Result<bool> {
    if transaction_is_known {
        return Ok(false);
    }
    if current_nonce > step.nonce {
        return Err(PublicValidityPublisherError::Conflict(format!(
            "signer nonce {} was consumed while exact transaction {} is unknown; refusing a sibling replacement",
            step.nonce, step.transaction_hash
        )));
    }
    if current_nonce < step.nonce {
        return Err(PublicValidityPublisherError::Conflict(format!(
            "signed transaction nonce {} is ahead of signer latest nonce {current_nonce}; an earlier operation is missing",
            step.nonce
        )));
    }
    Ok(true)
}

fn publish_exact_raw(rpc: &str, signer: &str, step: &RawTransactionStep) -> Result<()> {
    let transaction_is_known = transaction_known(rpc, &step.transaction_hash)?
        || rpc_receipt(rpc, &step.transaction_hash)?.is_some();
    let current_nonce = if transaction_is_known {
        step.nonce
    } else {
        account_nonce(rpc, signer)?
    };
    if !exact_publish_needed(transaction_is_known, current_nonce, step)? {
        return Ok(());
    }
    let mut command = Command::new("cast");
    command.args([
        "publish",
        &step.raw_signed_transaction,
        "--async",
        "--rpc-url",
        rpc,
    ]);
    let output = command.output().map_err(|error| {
        PublicValidityPublisherError::Command(format!("start raw transaction publish: {error}"))
    })?;
    if !output.status.success() {
        if transaction_known(rpc, &step.transaction_hash)? {
            return Ok(());
        }
        return Err(PublicValidityPublisherError::Command(format!(
            "publish exact raw transaction failed after durable journaling: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let published = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !same_hex(&published, &step.transaction_hash) {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "RPC reported transaction {published}, expected {}",
            step.transaction_hash
        )));
    }
    Ok(())
}

fn revalidate_stored_confirmation(
    rpc: &str,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
    timeout: Duration,
    step: &RawTransactionStep,
    signer: &str,
) -> Result<(Value, FinalizedReceipt)> {
    let (receipt, current) = wait_for_finalized_receipt(
        rpc,
        chain_id,
        allow_unfinalized_devnet,
        timeout,
        &step.transaction_hash,
        signer,
        &step.target,
    )?;
    if let Some(stored) = &step.confirmation {
        revalidate_checkpoint(rpc, &stored.finalized_checkpoint)?;
        checkpoint_advances(&stored.finalized_checkpoint, &current.finalized_checkpoint)
            .map_err(PublicValidityPublisherError::Evidence)?;
        if !same_hex(&stored.transaction_hash, &current.transaction_hash)
            || !same_hex(&stored.block_hash, &current.block_hash)
            || stored.block_number != current.block_number
        {
            return Err(PublicValidityPublisherError::Evidence(
                "stored transaction receipt was replaced or orphaned".into(),
            ));
        }
    }
    Ok((receipt, current))
}

fn validate_stored_receipt_progress(
    rpc: &str,
    stored: &FinalizedReceipt,
    current: &FinalizedReceipt,
) -> Result<()> {
    revalidate_checkpoint(rpc, &stored.finalized_checkpoint)?;
    checkpoint_advances(&stored.finalized_checkpoint, &current.finalized_checkpoint)
        .map_err(PublicValidityPublisherError::Evidence)?;
    if !same_hex(&stored.transaction_hash, &current.transaction_hash)
        || !same_hex(&stored.block_hash, &current.block_hash)
        || stored.block_number != current.block_number
    {
        return Err(PublicValidityPublisherError::Evidence(
            "stored transaction receipt was replaced or orphaned".into(),
        ));
    }
    Ok(())
}

fn log_topics(log: &Value) -> std::result::Result<&Vec<Value>, String> {
    log.get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| "event log has no topics array".into())
}

fn log_topic<'a>(log: &'a Value, index: usize) -> std::result::Result<&'a str, String> {
    log_topics(log)?
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("event log has no string topic {index}"))
}

fn receipt_logs(receipt: &Value) -> std::result::Result<&Vec<Value>, String> {
    receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| "receipt has no logs array".into())
}

fn indexed_address_matches(topic: &str, expected: &str) -> std::result::Result<bool, String> {
    let topic = decode_hex(
        &Value::String(topic.to_string()),
        Some(32),
        "indexed address",
    )?;
    let address = decode_hex(
        &Value::String(expected.to_string()),
        Some(20),
        "expected indexed address",
    )?;
    Ok(topic[..12] == [0u8; 12] && topic[12..] == address)
}

fn topic_quantity(topic: &str, what: &str) -> std::result::Result<BigUint, String> {
    let bytes = decode_hex(&Value::String(topic.to_string()), Some(32), what)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

fn proof_attestation_digest(
    proof_hash: &str,
    proof_length: u32,
) -> std::result::Result<Vec<u8>, String> {
    let mut encoded = Vec::with_capacity(96);
    encoded.extend(keccak_hash::keccak(b"INTMAX3_PROOF_ATTESTATION_V1").0);
    encoded.extend(decode_hex(
        &Value::String(proof_hash.to_string()),
        Some(32),
        "proof hash",
    )?);
    encoded.extend([0u8; 28]);
    encoded.extend(proof_length.to_be_bytes());
    Ok(keccak_hash::keccak(encoded).0.to_vec())
}

fn validate_attestation_event(
    receipt: &Value,
    kzg: &str,
    rollup: &str,
    submission_id: &str,
    commitment: &str,
    proof_hash: &str,
    proof_length: u32,
) -> Result<()> {
    let topic0 = keccak_hex(b"ProofDataAttested(address,uint256,bytes32,bytes32,bytes32,uint32)");
    let expected_id = quantity_to_decimal(submission_id, "submission id")
        .map_err(PublicValidityPublisherError::Evidence)?;
    let logs = receipt_logs(receipt).map_err(PublicValidityPublisherError::Evidence)?;
    let relevant: Vec<_> = logs
        .iter()
        .filter(|log| {
            !log.get("removed").and_then(Value::as_bool).unwrap_or(false)
                && log
                    .get("address")
                    .and_then(Value::as_str)
                    .is_some_and(|address| same_hex(address, kzg))
                && log_topic(log, 0).is_ok_and(|topic| same_hex(topic, &topic0))
        })
        .collect();
    if relevant.len() != 1 {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "attestation receipt has {} ProofDataAttested events; expected exactly one",
            relevant.len()
        )));
    }
    let log = relevant[0];
    if log_topics(log)
        .map_err(PublicValidityPublisherError::Evidence)?
        .len()
        != 4
        || !indexed_address_matches(
            log_topic(log, 1).map_err(PublicValidityPublisherError::Evidence)?,
            rollup,
        )
        .map_err(PublicValidityPublisherError::Evidence)?
        || topic_quantity(
            log_topic(log, 2).map_err(PublicValidityPublisherError::Evidence)?,
            "ProofDataAttested.submissionId",
        )
        .map_err(PublicValidityPublisherError::Evidence)?
            != expected_id
        || !same_hex(
            log_topic(log, 3).map_err(PublicValidityPublisherError::Evidence)?,
            commitment,
        )
    {
        return Err(PublicValidityPublisherError::Evidence(
            "ProofDataAttested indexed fields differ from candidate".into(),
        ));
    }
    let data = decode_hex(
        log.get("data").unwrap_or(&Value::Null),
        Some(96),
        "ProofDataAttested data",
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    if data[..32]
        != proof_attestation_digest(proof_hash, proof_length)
            .map_err(PublicValidityPublisherError::Evidence)?
        || data[32..64]
            != decode_hex(
                &Value::String(proof_hash.to_string()),
                Some(32),
                "proof hash",
            )
            .map_err(PublicValidityPublisherError::Evidence)?
        || data[64..92] != [0u8; 28]
        || u32::from_be_bytes(data[92..96].try_into().expect("four bytes")) != proof_length
    {
        return Err(PublicValidityPublisherError::Evidence(
            "ProofDataAttested data differs from proof payload".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalizationReceiptSemantic {
    Finalized,
    Rejected,
    None,
}

fn validate_event_log_location(log: &Value, receipt: &Value) -> std::result::Result<(), String> {
    for (log_field, receipt_field) in [
        ("transactionHash", "transactionHash"),
        ("blockHash", "blockHash"),
    ] {
        let log_value = log
            .get(log_field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("finalization event lacks {log_field}"))?;
        let receipt_value = receipt
            .get(receipt_field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("finalization receipt lacks {receipt_field}"))?;
        if !same_hex(log_value, receipt_value) {
            return Err(format!(
                "finalization event {log_field} differs from its receipt"
            ));
        }
    }
    for field in ["blockNumber", "transactionIndex"] {
        if object_quantity(log, field, &format!("finalization event {field}"))?
            != object_quantity(receipt, field, &format!("finalization receipt {field}"))?
        {
            return Err(format!(
                "finalization event {field} differs from its receipt"
            ));
        }
    }
    Ok(())
}

fn classify_finalization_events(
    receipt: &Value,
    rollup: &str,
    submission_id: &str,
    state_root: &str,
) -> Result<FinalizationReceiptSemantic> {
    let finalized_topic = keccak_hex(b"Finalized(uint256,bytes32)");
    let rejected_topic = keccak_hex(b"FinalizeRejected(uint256,bytes4)");
    let expected_id = quantity_to_decimal(submission_id, "submission id")
        .map_err(PublicValidityPublisherError::Evidence)?;
    let expected_root = decode_hex(
        &Value::String(state_root.to_string()),
        Some(32),
        "final state root",
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    let mut finalized = 0usize;
    let mut rejected = 0usize;
    for log in receipt_logs(receipt).map_err(PublicValidityPublisherError::Evidence)? {
        if !log
            .get("address")
            .and_then(Value::as_str)
            .is_some_and(|address| same_hex(address, rollup))
        {
            continue;
        }
        let topic0 = log_topic(log, 0).map_err(PublicValidityPublisherError::Evidence)?;
        if same_hex(topic0, &rejected_topic) {
            if log_topics(log)
                .map_err(PublicValidityPublisherError::Evidence)?
                .len()
                != 2
            {
                return Err(PublicValidityPublisherError::Evidence(
                    "FinalizeRejected event has malformed indexed fields".into(),
                ));
            }
            let rejected_id = topic_quantity(
                log_topic(log, 1).map_err(PublicValidityPublisherError::Evidence)?,
                "FinalizeRejected.id",
            )
            .map_err(PublicValidityPublisherError::Evidence)?;
            if rejected_id == expected_id {
                if log.get("removed").and_then(Value::as_bool).unwrap_or(false) {
                    return Err(PublicValidityPublisherError::Evidence(
                        "exact FinalizeRejected event is marked removed".into(),
                    ));
                }
                validate_event_log_location(log, receipt)
                    .map_err(PublicValidityPublisherError::Evidence)?;
                decode_hex(
                    log.get("data").unwrap_or(&Value::Null),
                    Some(32),
                    "FinalizeRejected data",
                )
                .map_err(PublicValidityPublisherError::Evidence)?;
                rejected += 1;
            }
        }
        if same_hex(topic0, &finalized_topic) {
            if log_topics(log)
                .map_err(PublicValidityPublisherError::Evidence)?
                .len()
                != 2
            {
                return Err(PublicValidityPublisherError::Evidence(
                    "Finalized event has malformed indexed fields".into(),
                ));
            }
            let finalized_id = topic_quantity(
                log_topic(log, 1).map_err(PublicValidityPublisherError::Evidence)?,
                "Finalized.id",
            )
            .map_err(PublicValidityPublisherError::Evidence)?;
            if finalized_id == expected_id {
                if log.get("removed").and_then(Value::as_bool).unwrap_or(false) {
                    return Err(PublicValidityPublisherError::Evidence(
                        "exact Finalized event is marked removed".into(),
                    ));
                }
                validate_event_log_location(log, receipt)
                    .map_err(PublicValidityPublisherError::Evidence)?;
                let data = decode_hex(
                    log.get("data").unwrap_or(&Value::Null),
                    Some(32),
                    "Finalized data",
                )
                .map_err(PublicValidityPublisherError::Evidence)?;
                if data != expected_root {
                    return Err(PublicValidityPublisherError::Evidence(
                        "Finalized event for exact submission has a different state root".into(),
                    ));
                }
                finalized += 1;
            }
        }
    }
    match (finalized, rejected) {
        (1, 0) => Ok(FinalizationReceiptSemantic::Finalized),
        (0, 1) => Ok(FinalizationReceiptSemantic::Rejected),
        (0, 0) => Ok(FinalizationReceiptSemantic::None),
        _ => Err(PublicValidityPublisherError::Evidence(format!(
            "finalization receipt has {finalized} exact Finalized and {rejected} exact FinalizeRejected events; expected one unambiguous result"
        ))),
    }
}

fn validate_finalization_events(
    receipt: &Value,
    rollup: &str,
    submission_id: &str,
    state_root: &str,
) -> Result<()> {
    match classify_finalization_events(receipt, rollup, submission_id, state_root)? {
        FinalizationReceiptSemantic::Finalized => Ok(()),
        FinalizationReceiptSemantic::Rejected => Err(PublicValidityPublisherError::Evidence(
            "finalize returned false and emitted FinalizeRejected".into(),
        )),
        FinalizationReceiptSemantic::None => Err(PublicValidityPublisherError::Evidence(
            "finalize receipt has no exact Finalized event".into(),
        )),
    }
}

fn call_view_at(
    rpc: &str,
    target: &str,
    signature: &str,
    args: &[&str],
    from: Option<&str>,
    block_number: u64,
) -> Result<String> {
    let block = format!("0x{block_number:x}");
    call_view_at_tag(rpc, target, signature, args, from, &block)
}

fn call_view_at_tag(
    rpc: &str,
    target: &str,
    signature: &str,
    args: &[&str],
    from: Option<&str>,
    block: &str,
) -> Result<String> {
    let mut command = Command::new("cast");
    command.arg("call").arg(target).arg(signature).args(args);
    if let Some(from) = from {
        command.arg("--from").arg(from);
    }
    command.args(["--block", &block, "--rpc-url", rpc]);
    Ok(checked_output(command, signature, 1024 * 1024)?
        .trim()
        .to_string())
}

fn runtime_code_hash_at(rpc: &str, address: &str, block_number: u64) -> Result<String> {
    let block = format!("0x{block_number:x}");
    let code = cast_output(
        &["code", address, "--block", &block, "--rpc-url", rpc],
        "read deployed runtime code",
        MAX_RPC_JSON_BYTES,
    )?;
    let bytes = decode_hex(
        &Value::String(code.trim().to_string()),
        None,
        "deployed runtime code",
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    if bytes.is_empty() {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "no deployed runtime code at {address}"
        )));
    }
    Ok(keccak_hex(&bytes))
}

fn validate_deployment_identity(
    manifest: &DeploymentManifest,
    observed: &ObservedDeploymentIdentity,
) -> Result<()> {
    if !same_hex(
        &observed.rollup_runtime_code_hash,
        &manifest.rollup_runtime_code_hash,
    ) {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "rollup runtime code hash {} differs from release manifest",
            observed.rollup_runtime_code_hash
        )));
    }
    if !same_hex(&observed.mle_verifier, &manifest.mle_verifier) {
        return Err(PublicValidityPublisherError::Evidence(
            "rollup.mleVerifier differs from release manifest".into(),
        ));
    }
    if !same_hex(
        &observed.mle_verifier_runtime_code_hash,
        &manifest.mle_verifier_runtime_code_hash,
    ) {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "MLE verifier runtime code hash {} differs from release manifest",
            observed.mle_verifier_runtime_code_hash
        )));
    }
    if !same_hex(&observed.kzg_verifier, &manifest.kzg_verifier) {
        return Err(PublicValidityPublisherError::Evidence(
            "rollup.kzgVerifier differs from release manifest".into(),
        ));
    }
    if !same_hex(
        &observed.kzg_verifier_runtime_code_hash,
        &manifest.kzg_verifier_runtime_code_hash,
    ) {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "KZG verifier runtime code hash {} differs from release manifest",
            observed.kzg_verifier_runtime_code_hash
        )));
    }
    Ok(())
}

fn validate_deployment_manifest_identity_pins(
    manifest: &DeploymentManifest,
) -> std::result::Result<(), String> {
    for (value, bytes, label) in [
        (&manifest.rollup, 20, "manifest rollup"),
        (&manifest.mle_verifier, 20, "manifest MLE verifier"),
        (&manifest.kzg_verifier, 20, "manifest KZG verifier"),
        (
            &manifest.rollup_runtime_code_hash,
            32,
            "manifest rollup runtime code hash",
        ),
        (
            &manifest.mle_verifier_runtime_code_hash,
            32,
            "manifest MLE verifier runtime code hash",
        ),
        (
            &manifest.kzg_verifier_runtime_code_hash,
            32,
            "manifest KZG verifier runtime code hash",
        ),
    ] {
        validate_nonzero_hex(value, bytes, label)?;
    }
    Ok(())
}

fn validate_deployment_manifest_raw_hash(bytes: &[u8], expected_sha256: &str) -> Result<String> {
    let expected = normalize_hex(expected_sha256, 32, "deployment manifest SHA-256 pin")
        .map_err(PublicValidityPublisherError::Configuration)?;
    validate_nonzero_hex(&expected, 32, "deployment manifest SHA-256 pin")
        .map_err(PublicValidityPublisherError::Configuration)?;
    let actual = sha256_hex(bytes);
    if !same_hex(&actual, &expected) {
        return Err(PublicValidityPublisherError::Configuration(format!(
            "deployment manifest raw-byte SHA-256 {actual} differs from independent pin {expected}"
        )));
    }
    Ok(actual)
}

fn load_and_validate_deployment_manifest(
    path: &Path,
    prepared: &PreparedEnvelope,
    expected_sha256: &str,
) -> Result<CheckedDeployment> {
    let bytes = read_bounded(path, 1024 * 1024, "deployment manifest")?;
    // Authenticate the exact file bytes before parsing, WAL creation, or any signing call.
    // Canonically equivalent JSON is intentionally a different release artifact.
    let manifest_hash = validate_deployment_manifest_raw_hash(&bytes, expected_sha256)?;
    let manifest: DeploymentManifest = serde_json::from_slice(&bytes).map_err(|error| {
        PublicValidityPublisherError::Configuration(format!(
            "parse deployment manifest {}: {error}",
            path.display()
        ))
    })?;
    if manifest.schema_version != 1
        || manifest.chain_id != prepared.envelope.chain_id
        || !same_hex(&manifest.rollup, &prepared.envelope.rollup)
        || manifest.mle_proof_abi_version != prepared.proof_abi_version
    {
        return Err(PublicValidityPublisherError::Configuration(
            "deployment manifest schema/chain/rollup/MLE ABI differs from envelope".into(),
        ));
    }
    for (value, bytes, label) in [
        (&manifest.rollup, 20, "manifest rollup"),
        (&manifest.mle_verifier, 20, "manifest MLE verifier"),
        (&manifest.kzg_verifier, 20, "manifest KZG verifier"),
        (
            &manifest.rollup_runtime_code_hash,
            32,
            "manifest rollup runtime code hash",
        ),
        (
            &manifest.mle_verifier_runtime_code_hash,
            32,
            "manifest MLE verifier runtime code hash",
        ),
        (
            &manifest.kzg_verifier_runtime_code_hash,
            32,
            "manifest KZG verifier runtime code hash",
        ),
        (
            &manifest.post_block_and_submit_guarded_selector,
            4,
            "manifest post selector",
        ),
        (
            &manifest.attest_proof_data_selector,
            4,
            "manifest attest selector",
        ),
        (&manifest.finalize_selector, 4, "manifest finalize selector"),
    ] {
        normalize_hex(value, bytes, label).map_err(PublicValidityPublisherError::Configuration)?;
    }
    validate_deployment_manifest_identity_pins(&manifest)
        .map_err(PublicValidityPublisherError::Configuration)?;
    let post_selector = &prepared.post_calldata[..10];
    let attest_selector = format!(
        "0x{}",
        hex::encode(&keccak_hash::keccak(ATTEST_SIGNATURE.as_bytes()).0[..4])
    );
    let finalize_selector = prepared
        .finalize_calldata("0")
        .map_err(PublicValidityPublisherError::Configuration)?[..10]
        .to_string();
    if !same_hex(
        &manifest.post_block_and_submit_guarded_selector,
        post_selector,
    ) || !same_hex(&manifest.attest_proof_data_selector, &attest_selector)
        || !same_hex(&manifest.finalize_selector, &finalize_selector)
    {
        return Err(PublicValidityPublisherError::Configuration(format!(
            "deployment ABI selector mismatch: expected post={post_selector}, attest={attest_selector}, finalize={finalize_selector}"
        )));
    }
    Ok(CheckedDeployment {
        manifest,
        manifest_hash,
    })
}

fn validate_deployment_on_l1(
    rpc: &str,
    prepared: &PreparedEnvelope,
    deployment: &CheckedDeployment,
    signer: &str,
    allow_unfinalized_devnet: bool,
) -> Result<()> {
    let checkpoint =
        read_durable_checkpoint(rpc, prepared.envelope.chain_id, allow_unfinalized_devnet)?;
    let actual_rollup_hash =
        runtime_code_hash_at(rpc, &prepared.envelope.rollup, checkpoint.block_number)?;
    let actual_mle = view_address_at(
        rpc,
        &prepared.envelope.rollup,
        "mleVerifier()(address)",
        checkpoint.block_number,
    )?;
    let actual_mle_hash = runtime_code_hash_at(rpc, &actual_mle, checkpoint.block_number)?;
    let actual_kzg = view_address_at(
        rpc,
        &prepared.envelope.rollup,
        "kzgVerifier()(address)",
        checkpoint.block_number,
    )?;
    let actual_kzg_hash = runtime_code_hash_at(rpc, &actual_kzg, checkpoint.block_number)?;
    validate_deployment_identity(
        &deployment.manifest,
        &ObservedDeploymentIdentity {
            rollup_runtime_code_hash: actual_rollup_hash,
            mle_verifier: actual_mle.clone(),
            mle_verifier_runtime_code_hash: actual_mle_hash,
            kzg_verifier: actual_kzg,
            kzg_verifier_runtime_code_hash: actual_kzg_hash,
        },
    )?;
    let allowed = call_view_at(
        rpc,
        &actual_mle,
        "allowedChainId()(uint256)",
        &[],
        None,
        checkpoint.block_number,
    )?;
    let allowed_word = decode_abi_word(&allowed, "allowedChainId")
        .map_err(PublicValidityPublisherError::Evidence)?;
    let allowed_chain = BigUint::from_bytes_be(&allowed_word);
    if allowed_chain != BigUint::from(prepared.envelope.chain_id) {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "MLE verifier allowedChainId {allowed_chain} != envelope chain {}",
            prepared.envelope.chain_id
        )));
    }

    // All deployment reads above use one historical durable block. Re-read that exact block and
    // then the durable head before consulting `latest`, so a replaced/regressed head cannot splice
    // a reviewed Rollup/MLE/KZG identity together from different canonical histories.
    revalidate_checkpoint(rpc, &checkpoint)?;
    let checkpoint_after =
        read_durable_checkpoint(rpc, prepared.envelope.chain_id, allow_unfinalized_devnet)?;
    validate_deployment_checkpoint_window(&checkpoint, &checkpoint_after)?;

    // The latest-head preflight catches stale work before signing. The guarded posting calldata
    // independently carries this predecessor, so a producer race after the read reverts before
    // the contract accepts the stake or mutates its block chain.
    let block_number_raw = call_view_at_tag(
        rpc,
        &prepared.envelope.rollup,
        "blockNumber()(uint64)",
        &[],
        None,
        "latest",
    )?;
    let block_number_word = decode_abi_word(&block_number_raw, "blockNumber")
        .map_err(PublicValidityPublisherError::Evidence)?;
    if block_number_word[..24] != [0u8; 24] {
        return Err(PublicValidityPublisherError::Evidence(
            "rollup blockNumber does not fit u64".into(),
        ));
    }
    let block_number = u64::from_be_bytes(block_number_word[24..].try_into().expect("eight bytes"));
    let block_chain_raw = call_view_at_tag(
        rpc,
        &prepared.envelope.rollup,
        "blockHashChain()(bytes32)",
        &[],
        None,
        "latest",
    )?;
    let block_chain = format!(
        "0x{}",
        hex::encode(
            decode_abi_word(&block_chain_raw, "blockHashChain")
                .map_err(PublicValidityPublisherError::Evidence)?
        )
    );
    let latest_root_raw = call_view_at_tag(
        rpc,
        &prepared.envelope.rollup,
        "latestFinalizedStateRoot()(bytes32)",
        &[],
        None,
        "latest",
    )?;
    let latest_root = format!(
        "0x{}",
        hex::encode(
            decode_abi_word(&latest_root_raw, "latestFinalizedStateRoot")
                .map_err(PublicValidityPublisherError::Evidence)?
        )
    );
    let finalized_number_raw = call_view_at_tag(
        rpc,
        &prepared.envelope.rollup,
        "latestFinalizedBlockNumber()(uint64)",
        &[],
        None,
        "latest",
    )?;
    let finalized_number_word =
        decode_abi_word(&finalized_number_raw, "latestFinalizedBlockNumber")
            .map_err(PublicValidityPublisherError::Evidence)?;
    if finalized_number_word[..24] != [0u8; 24] {
        return Err(PublicValidityPublisherError::Evidence(
            "latestFinalizedBlockNumber does not fit u64".into(),
        ));
    }
    let finalized_number =
        u64::from_be_bytes(finalized_number_word[24..].try_into().expect("eight bytes"));
    if block_number != prepared.initial_block_number
        || finalized_number != prepared.initial_block_number
        || !same_hex(&block_chain, &prepared.initial_block_chain)
        || !same_hex(&latest_root, &prepared.initial_ext_commitment)
    {
        return Err(PublicValidityPublisherError::Conflict(format!(
            "rollup head advanced away from candidate predecessor: block={block_number}, finalized={finalized_number}, chain={block_chain}, root={latest_root}"
        )));
    }
    let is_producer = {
        let raw = call_view_at_tag(
            rpc,
            &prepared.envelope.rollup,
            "isBlockProducer(address)(bool)",
            &[signer],
            None,
            "latest",
        )?;
        let word = decode_abi_word(&raw, "isBlockProducer")
            .map_err(PublicValidityPublisherError::Evidence)?;
        word[..31] == [0u8; 31] && word[31] == 1
    };
    let admin_raw = call_view_at_tag(
        rpc,
        &prepared.envelope.rollup,
        "blockProducerAdmin()(address)",
        &[],
        None,
        "latest",
    )?;
    let admin_word = decode_abi_word(&admin_raw, "blockProducerAdmin")
        .map_err(PublicValidityPublisherError::Evidence)?;
    let admin = format!("0x{}", hex::encode(&admin_word[12..]));
    if !is_producer && !same_hex(&admin, signer) {
        return Err(PublicValidityPublisherError::Evidence(
            "selected signer is not an authorized block producer".into(),
        ));
    }
    Ok(())
}

fn decode_abi_word(raw: &str, what: &str) -> std::result::Result<Vec<u8>, String> {
    decode_hex(&Value::String(raw.trim().to_string()), Some(32), what)
}

fn view_bytes32_at(
    rpc: &str,
    target: &str,
    signature: &str,
    args: &[&str],
    block_number: u64,
) -> Result<String> {
    let raw = call_view_at(rpc, target, signature, args, None, block_number)?;
    Ok(format!(
        "0x{}",
        hex::encode(
            decode_abi_word(&raw, signature).map_err(PublicValidityPublisherError::Evidence)?
        )
    ))
}

fn view_address_at(rpc: &str, target: &str, signature: &str, block_number: u64) -> Result<String> {
    let raw = call_view_at(rpc, target, signature, &[], None, block_number)?;
    let word = decode_abi_word(&raw, signature).map_err(PublicValidityPublisherError::Evidence)?;
    if word[..12] != [0u8; 12] || word[12..] == [0u8; 20] {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "{signature} returned an invalid address"
        )));
    }
    Ok(format!("0x{}", hex::encode(&word[12..])))
}

fn view_bool_at(
    rpc: &str,
    target: &str,
    signature: &str,
    args: &[&str],
    from: Option<&str>,
    block_number: u64,
) -> Result<bool> {
    let raw = call_view_at(rpc, target, signature, args, from, block_number)?;
    let word = decode_abi_word(&raw, signature).map_err(PublicValidityPublisherError::Evidence)?;
    if word[..31] != [0u8; 31] || word[31] > 1 {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "{signature} returned a noncanonical bool"
        )));
    }
    Ok(word[31] == 1)
}

fn view_u64_at(rpc: &str, target: &str, signature: &str, block_number: u64) -> Result<u64> {
    let raw = call_view_at(rpc, target, signature, &[], None, block_number)?;
    let word = decode_abi_word(&raw, signature).map_err(PublicValidityPublisherError::Evidence)?;
    if word[..24] != [0u8; 24] {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "{signature} does not fit u64"
        )));
    }
    Ok(u64::from_be_bytes(
        word[24..].try_into().expect("eight bytes"),
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedSubmission {
    commitment: String,
    submitter: String,
    finalized: bool,
    submitted_at_block: u64,
    state_root: String,
}

fn decode_submission(raw: &str) -> std::result::Result<ObservedSubmission, String> {
    let bytes = decode_hex(
        &Value::String(raw.trim().to_string()),
        Some(5 * 32),
        "getSubmission result",
    )?;
    if bytes[32..44] != [0u8; 12] {
        return Err("getSubmission submitter is not a canonical address".into());
    }
    if bytes[64..95] != [0u8; 31] || bytes[95] > 1 {
        return Err("getSubmission finalized is not a canonical bool".into());
    }
    if bytes[96..120] != [0u8; 24] {
        return Err("getSubmission submittedAtBlock does not fit uint64".into());
    }
    Ok(ObservedSubmission {
        commitment: format!("0x{}", hex::encode(&bytes[..32])),
        submitter: format!("0x{}", hex::encode(&bytes[44..64])),
        finalized: bytes[95] == 1,
        submitted_at_block: u64::from_be_bytes(
            bytes[120..128].try_into().expect("eight-byte uint64"),
        ),
        state_root: format!("0x{}", hex::encode(&bytes[128..160])),
    })
}

fn validate_submission_readback(
    observed: &ObservedSubmission,
    expected_submitter: &str,
    expected_submitted_at_block: u64,
    expected_state_root: &str,
) -> std::result::Result<(), String> {
    validate_nonzero_hex(&observed.commitment, 32, "submission commitment")?;
    if !same_hex(&observed.submitter, expected_submitter) {
        return Err("getSubmission submitter differs from the exact posting signer".into());
    }
    if !observed.finalized {
        return Err("getSubmission finalized flag is false".into());
    }
    if observed.submitted_at_block != expected_submitted_at_block {
        return Err(format!(
            "getSubmission submittedAtBlock {} differs from posting receipt block {expected_submitted_at_block}",
            observed.submitted_at_block
        ));
    }
    if !same_hex(&observed.state_root, expected_state_root) {
        return Err("getSubmission stateRoot differs from the candidate".into());
    }
    Ok(())
}

fn view_submission_at(
    rpc: &str,
    rollup: &str,
    submission_id: &str,
    block_number: u64,
) -> Result<ObservedSubmission> {
    let raw = call_view_at(
        rpc,
        rollup,
        "getSubmission(uint256)",
        &[submission_id],
        None,
        block_number,
    )?;
    decode_submission(&raw).map_err(PublicValidityPublisherError::Evidence)
}

fn validate_finalization_checkpoint_sequence(
    stored: &L1FinalizedCheckpoint,
    fresh: &L1FinalizedCheckpoint,
    receipt_block_number: u64,
    receipt_block_hash: Bytes32,
) -> std::result::Result<(), String> {
    checkpoint_advances(stored, fresh)?;
    fresh.covers_receipt(receipt_block_number, receipt_block_hash)
}

/// Close the historical-read window only after every receipt-block getter has completed. Both the
/// durable checkpoint and receipt block are re-read, so same-height head/block substitution cannot
/// be stitched across the event and state observations.
fn finalize_checkpoint_after_readback(
    rpc: &str,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
    confirmation: &FinalizedReceipt,
) -> Result<L1FinalizedCheckpoint> {
    let receipt_hash = confirmation
        .block_hash
        .parse::<Bytes32>()
        .map_err(|error| {
            PublicValidityPublisherError::Evidence(format!(
                "parse finalization block hash: {error}"
            ))
        })?;
    revalidate_checkpoint(rpc, &confirmation.finalized_checkpoint)?;
    let before = parse_checkpoint(
        &rpc_block(rpc, &format!("0x{:x}", confirmation.block_number))?,
        chain_id,
        confirmation.finalized_checkpoint.source,
    )?;
    if before.block_number != confirmation.block_number || before.block_hash != receipt_hash {
        return Err(PublicValidityPublisherError::Evidence(
            "finalization receipt block changed after getter read-back".into(),
        ));
    }
    let fresh = read_durable_checkpoint(rpc, chain_id, allow_unfinalized_devnet)?;
    validate_finalization_checkpoint_sequence(
        &confirmation.finalized_checkpoint,
        &fresh,
        confirmation.block_number,
        receipt_hash,
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    revalidate_checkpoint(rpc, &fresh)?;
    let after = parse_checkpoint(
        &rpc_block(rpc, &format!("0x{:x}", confirmation.block_number))?,
        chain_id,
        fresh.source,
    )?;
    if after != before {
        return Err(PublicValidityPublisherError::Evidence(
            "finalization receipt block was replaced during final checkpoint read-back".into(),
        ));
    }
    Ok(fresh)
}

fn validate_attestation_readback(
    rpc: &str,
    rollup: &str,
    deployment: &CheckedDeployment,
    submission_id: &str,
    proof_hash: &str,
    proof_length: u32,
    receipt: &Value,
    confirmation: &FinalizedReceipt,
) -> Result<()> {
    let id_decimal = quantity_to_decimal(submission_id, "submission id")
        .map_err(PublicValidityPublisherError::Evidence)?
        .to_string();
    let commitment = view_bytes32_at(
        rpc,
        rollup,
        "getCommitment(uint256)(bytes32)",
        &[&id_decimal],
        confirmation.block_number,
    )?;
    if same_hex(&commitment, &format!("0x{}", "00".repeat(32))) {
        return Err(PublicValidityPublisherError::Evidence(
            "submission commitment is zero at attestation receipt block".into(),
        ));
    }
    let kzg = view_address_at(
        rpc,
        rollup,
        "kzgVerifier()(address)",
        confirmation.block_number,
    )?;
    if !same_hex(&kzg, &deployment.manifest.kzg_verifier) {
        return Err(PublicValidityPublisherError::Evidence(
            "attestation receipt block rollup.kzgVerifier differs from release manifest".into(),
        ));
    }
    let kzg_runtime_code_hash = runtime_code_hash_at(rpc, &kzg, confirmation.block_number)?;
    if !same_hex(
        &kzg_runtime_code_hash,
        &deployment.manifest.kzg_verifier_runtime_code_hash,
    ) {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "attestation receipt block KZG verifier runtime code hash {kzg_runtime_code_hash} differs from release manifest"
        )));
    }
    validate_attestation_event(
        receipt,
        &kzg,
        rollup,
        submission_id,
        &commitment,
        proof_hash,
        proof_length,
    )?;
    let length = proof_length.to_string();
    if !view_bool_at(
        rpc,
        &kzg,
        "isProofDataAttested(uint256,bytes32,bytes32,uint256)(bool)",
        &[&id_decimal, &commitment, proof_hash, &length],
        Some(rollup),
        confirmation.block_number,
    )? {
        return Err(PublicValidityPublisherError::Evidence(
            "proof-DA attestation read-back is false at its receipt block".into(),
        ));
    }
    // The receipt was already required to be finalized. Re-read its finalized checkpoint after
    // the historical KZG getter/code/state reads so a concurrent RPC reorg cannot validate a
    // stitched attestation observation.
    revalidate_checkpoint(rpc, &confirmation.finalized_checkpoint)?;
    Ok(())
}

fn validate_finalization_readback(
    rpc: &str,
    rollup: &str,
    deployment: &CheckedDeployment,
    submission_id: &str,
    expected_submitter: &str,
    submitted_at_block: u64,
    state_root: &str,
    final_block_number: u64,
    receipt: &Value,
    confirmation: &FinalizedReceipt,
    allow_unfinalized_devnet: bool,
) -> Result<L1FinalizedCheckpoint> {
    validate_finalization_events(receipt, rollup, submission_id, state_root)?;
    let id_decimal = quantity_to_decimal(submission_id, "submission id")
        .map_err(PublicValidityPublisherError::Evidence)?
        .to_string();
    let rollup_runtime_code_hash = runtime_code_hash_at(rpc, rollup, confirmation.block_number)?;
    if !same_hex(
        &rollup_runtime_code_hash,
        &deployment.manifest.rollup_runtime_code_hash,
    ) {
        return Err(PublicValidityPublisherError::Evidence(
            "finalization receipt-block Rollup runtime code differs from deployment manifest"
                .into(),
        ));
    }
    let submission = view_submission_at(rpc, rollup, &id_decimal, confirmation.block_number)?;
    validate_submission_readback(
        &submission,
        expected_submitter,
        submitted_at_block,
        state_root,
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    if !view_bool_at(
        rpc,
        rollup,
        "isFinalized(uint256)(bool)",
        &[&id_decimal],
        None,
        confirmation.block_number,
    )? {
        return Err(PublicValidityPublisherError::Evidence(
            "isFinalized(submissionId) is false at finalization receipt block".into(),
        ));
    }
    let latest_root = view_bytes32_at(
        rpc,
        rollup,
        "latestFinalizedStateRoot()(bytes32)",
        &[],
        confirmation.block_number,
    )?;
    let latest_number = view_u64_at(
        rpc,
        rollup,
        "latestFinalizedBlockNumber()(uint64)",
        confirmation.block_number,
    )?;
    if !same_hex(&latest_root, state_root) || latest_number != final_block_number {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "latest finalized getter mismatch at receipt block: root={latest_root}, block={latest_number}"
        )));
    }
    finalize_checkpoint_after_readback(
        rpc,
        confirmation.finalized_checkpoint.chain_id,
        allow_unfinalized_devnet,
        confirmation,
    )
}

fn uint256_topic(value: &str, what: &str) -> std::result::Result<String, String> {
    let value = quantity_to_decimal(value, what)?;
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(format!("{what} does not fit uint256"));
    }
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(format!("0x{}", hex::encode(word)))
}

fn semantic_finalization_logs(
    rpc: &str,
    rollup: &str,
    submission_id: &str,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Value>> {
    if from_block > to_block {
        return Ok(Vec::new());
    }
    let topics = vec![
        keccak_hex(b"Finalized(uint256,bytes32)"),
        uint256_topic(submission_id, "submission id")
            .map_err(PublicValidityPublisherError::Evidence)?,
    ];
    let mut all = Vec::new();
    let mut start = from_block;
    loop {
        let end = start
            .saturating_add(EVENT_LOG_BLOCK_SPAN.saturating_sub(1))
            .min(to_block);
        let filter = serde_json::json!({
            "fromBlock": format!("0x{start:x}"),
            "toBlock": format!("0x{end:x}"),
            "address": rollup,
            "topics": topics,
        })
        .to_string();
        let raw = cast_output(
            &["rpc", "eth_getLogs", &filter, "--rpc-url", rpc],
            "discover permissionless finalization",
            MAX_RPC_JSON_BYTES,
        )?;
        let mut logs: Vec<Value> = serde_json::from_str(raw.trim()).map_err(|error| {
            PublicValidityPublisherError::Evidence(format!(
                "parse permissionless finalization logs: {error}"
            ))
        })?;
        if all.len().saturating_add(logs.len()) > 100_000 {
            return Err(PublicValidityPublisherError::Evidence(
                "permissionless finalization log result exceeds safety limit".into(),
            ));
        }
        all.append(&mut logs);
        if end == to_block {
            break;
        }
        start = end.checked_add(1).ok_or_else(|| {
            PublicValidityPublisherError::Evidence(
                "permissionless finalization event range overflowed".into(),
            )
        })?;
    }
    Ok(all)
}

fn validate_discovered_finalization_log(
    log: &Value,
    rollup: &str,
    submission_id: &str,
    state_root: &str,
) -> Result<String> {
    if log.get("removed").and_then(Value::as_bool).unwrap_or(false) {
        return Err(PublicValidityPublisherError::Evidence(
            "finalized-range Finalized log is marked removed".into(),
        ));
    }
    if !log
        .get("address")
        .and_then(Value::as_str)
        .is_some_and(|actual| same_hex(actual, rollup))
    {
        return Err(PublicValidityPublisherError::Evidence(
            "permissionless Finalized log came from another address".into(),
        ));
    }
    let topics = log_topics(log).map_err(PublicValidityPublisherError::Evidence)?;
    if topics.len() != 2
        || !same_hex(
            log_topic(log, 0).map_err(PublicValidityPublisherError::Evidence)?,
            &keccak_hex(b"Finalized(uint256,bytes32)"),
        )
        || topic_quantity(
            log_topic(log, 1).map_err(PublicValidityPublisherError::Evidence)?,
            "Finalized.id",
        )
        .map_err(PublicValidityPublisherError::Evidence)?
            != quantity_to_decimal(submission_id, "submission id")
                .map_err(PublicValidityPublisherError::Evidence)?
    {
        return Err(PublicValidityPublisherError::Evidence(
            "permissionless Finalized log differs from its exact filter".into(),
        ));
    }
    let root = decode_hex(
        log.get("data").unwrap_or(&Value::Null),
        Some(32),
        "Finalized data",
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    if root
        != decode_hex(
            &Value::String(state_root.to_string()),
            Some(32),
            "candidate state root",
        )
        .map_err(PublicValidityPublisherError::Evidence)?
    {
        return Err(PublicValidityPublisherError::Evidence(
            "Finalized log for exact submission has a different state root".into(),
        ));
    }
    validate_nonzero_hex(
        log.get("blockHash")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        32,
        "permissionless Finalized block hash",
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    object_quantity(log, "blockNumber", "permissionless Finalized block number")
        .map_err(PublicValidityPublisherError::Evidence)?;
    object_quantity(
        log,
        "transactionIndex",
        "permissionless Finalized transaction index",
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    let transaction_hash = normalize_hex(
        log.get("transactionHash")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        32,
        "permissionless Finalized transaction hash",
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    validate_nonzero_hex(
        &transaction_hash,
        32,
        "permissionless Finalized transaction hash",
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    Ok(transaction_hash)
}

#[allow(clippy::too_many_arguments)]
fn confirm_semantic_finalization(
    config: &PublicValidityPublisherConfig,
    deployment: &CheckedDeployment,
    chain_id: u64,
    rollup: &str,
    submission_id: &str,
    expected_submitter: &str,
    submitted_at_block: u64,
    state_root: &str,
    final_block_number: u64,
    transaction_hash: &str,
) -> Result<AdoptedFinalization> {
    let first_transaction =
        rpc_transaction(&config.rpc_url, transaction_hash)?.ok_or_else(|| {
            PublicValidityPublisherError::Evidence(format!(
                "permissionless finalization transaction {transaction_hash} disappeared"
            ))
        })?;
    let (receipt, mut confirmation) = wait_for_finalized_receipt_with_identity(
        &config.rpc_url,
        chain_id,
        config.allow_unfinalized_devnet,
        config.finality_timeout,
        transaction_hash,
        None,
        None,
        true,
    )?;
    validate_semantic_transaction(
        &first_transaction,
        &receipt,
        transaction_hash,
        &confirmation.block_hash,
        confirmation.block_number,
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    confirmation.finalized_checkpoint = validate_finalization_readback(
        &config.rpc_url,
        rollup,
        deployment,
        submission_id,
        expected_submitter,
        submitted_at_block,
        state_root,
        final_block_number,
        &receipt,
        &confirmation,
        config.allow_unfinalized_devnet,
    )?;
    let second_transaction =
        rpc_transaction(&config.rpc_url, transaction_hash)?.ok_or_else(|| {
            PublicValidityPublisherError::Evidence(
                "permissionless finalization transaction disappeared during read-back".into(),
            )
        })?;
    if !stable_transaction_fields(&first_transaction, &second_transaction) {
        return Err(PublicValidityPublisherError::Evidence(
            "permissionless finalization transaction changed during read-back".into(),
        ));
    }
    Ok(AdoptedFinalization {
        submission_id: submission_id.to_string(),
        state_root: state_root.to_ascii_lowercase(),
        confirmation,
    })
}

#[allow(clippy::too_many_arguments)]
fn discover_semantic_finalization(
    config: &PublicValidityPublisherConfig,
    deployment: &CheckedDeployment,
    chain_id: u64,
    rollup: &str,
    submission_id: &str,
    expected_submitter: &str,
    submitted_at_block: u64,
    state_root: &str,
    final_block_number: u64,
) -> Result<Option<AdoptedFinalization>> {
    let durable =
        read_durable_checkpoint(&config.rpc_url, chain_id, config.allow_unfinalized_devnet)?;
    let logs = semantic_finalization_logs(
        &config.rpc_url,
        rollup,
        submission_id,
        submitted_at_block,
        durable.block_number,
    )?;
    let mut hashes = BTreeSet::new();
    for log in logs {
        let block_number =
            object_quantity(&log, "blockNumber", "permissionless Finalized block number")
                .map_err(PublicValidityPublisherError::Evidence)?;
        if block_number < submitted_at_block || block_number > durable.block_number {
            return Err(PublicValidityPublisherError::Evidence(
                "permissionless Finalized log lies outside the requested durable range".into(),
            ));
        }
        hashes.insert(validate_discovered_finalization_log(
            &log,
            rollup,
            submission_id,
            state_root,
        )?);
    }
    // A stable negative scan is important too: do not sign on a range assembled under a replaced
    // durable head. A later winner is still safe because `finalize` is one-shot and its rejection
    // path is reconciled below.
    revalidate_checkpoint(&config.rpc_url, &durable)?;
    let after =
        read_durable_checkpoint(&config.rpc_url, chain_id, config.allow_unfinalized_devnet)?;
    checkpoint_advances(&durable, &after).map_err(PublicValidityPublisherError::Evidence)?;
    if hashes.len() > 1 {
        return Err(PublicValidityPublisherError::Conflict(
            "multiple transactions emitted the exact Finalized(submissionId,stateRoot) event"
                .into(),
        ));
    }
    let Some(transaction_hash) = hashes.pop_first() else {
        return Ok(None);
    };
    confirm_semantic_finalization(
        config,
        deployment,
        chain_id,
        rollup,
        submission_id,
        expected_submitter,
        submitted_at_block,
        state_root,
        final_block_number,
        &transaction_hash,
    )
    .map(Some)
}

#[allow(clippy::too_many_arguments)]
fn revalidate_adopted_finalization(
    config: &PublicValidityPublisherConfig,
    deployment: &CheckedDeployment,
    chain_id: u64,
    rollup: &str,
    submission_id: &str,
    expected_submitter: &str,
    submitted_at_block: u64,
    state_root: &str,
    final_block_number: u64,
    stored: &AdoptedFinalization,
) -> Result<AdoptedFinalization> {
    if quantity_to_decimal(&stored.submission_id, "stored adopted submission id")
        .map_err(PublicValidityPublisherError::Conflict)?
        != quantity_to_decimal(submission_id, "submission id")
            .map_err(PublicValidityPublisherError::Conflict)?
        || !same_hex(&stored.state_root, state_root)
    {
        return Err(PublicValidityPublisherError::Conflict(
            "stored adopted finalization belongs to another submission/root".into(),
        ));
    }
    revalidate_checkpoint(&config.rpc_url, &stored.confirmation.finalized_checkpoint)?;
    let current = confirm_semantic_finalization(
        config,
        deployment,
        chain_id,
        rollup,
        submission_id,
        expected_submitter,
        submitted_at_block,
        state_root,
        final_block_number,
        &stored.confirmation.transaction_hash,
    )?;
    if !same_hex(
        &stored.confirmation.transaction_hash,
        &current.confirmation.transaction_hash,
    ) || !same_hex(
        &stored.confirmation.block_hash,
        &current.confirmation.block_hash,
    ) || stored.confirmation.block_number != current.confirmation.block_number
    {
        return Err(PublicValidityPublisherError::Evidence(
            "stored adopted finalization receipt was orphaned or replaced".into(),
        ));
    }
    checkpoint_advances(
        &stored.confirmation.finalized_checkpoint,
        &current.confirmation.finalized_checkpoint,
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    Ok(current)
}

fn validate_superseded_finalize_receipt(
    receipt: &Value,
    rollup: &str,
    submission_id: &str,
    state_root: &str,
) -> Result<()> {
    match (
        receipt_status(receipt).map_err(PublicValidityPublisherError::Evidence)?,
        classify_finalization_events(receipt, rollup, submission_id, state_root)?,
    ) {
        (false, FinalizationReceiptSemantic::None)
        | (true, FinalizationReceiptSemantic::Rejected) => Ok(()),
        (true, FinalizationReceiptSemantic::Finalized) => {
            Err(PublicValidityPublisherError::Conflict(
                "local and adopted transactions both claim the one-shot finalization".into(),
            ))
        }
        _ => Err(PublicValidityPublisherError::Evidence(
            "superseded local finalize receipt has an unexpected semantic result".into(),
        )),
    }
}

fn ensure_superseded_finalize_settled(
    config: &PublicValidityPublisherConfig,
    chain_id: u64,
    signer: &str,
    rollup: &str,
    submission_id: &str,
    state_root: &str,
    step: &RawTransactionStep,
) -> Result<FinalizedReceipt> {
    if step.superseded_confirmation.is_some()
        && rpc_receipt(&config.rpc_url, &step.transaction_hash)?.is_none()
    {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "stored superseded receipt for {} disappeared; refusing reservation-free replay",
            step.transaction_hash
        )));
    }
    if rpc_receipt(&config.rpc_url, &step.transaction_hash)?.is_none() {
        publish_exact_raw(&config.rpc_url, signer, step)?;
    }
    let (receipt, current) = wait_for_finalized_receipt_with_identity(
        &config.rpc_url,
        chain_id,
        config.allow_unfinalized_devnet,
        config.finality_timeout,
        &step.transaction_hash,
        Some(signer),
        Some(&step.target),
        false,
    )?;
    validate_superseded_finalize_receipt(&receipt, rollup, submission_id, state_root)?;
    if let Some(stored) = &step.superseded_confirmation {
        revalidate_checkpoint(&config.rpc_url, &stored.finalized_checkpoint)?;
        checkpoint_advances(&stored.finalized_checkpoint, &current.finalized_checkpoint)
            .map_err(PublicValidityPublisherError::Evidence)?;
        if !same_hex(&stored.transaction_hash, &current.transaction_hash)
            || !same_hex(&stored.block_hash, &current.block_hash)
            || stored.block_number != current.block_number
        {
            return Err(PublicValidityPublisherError::Evidence(
                "stored superseded finalize receipt was orphaned or replaced".into(),
            ));
        }
    }
    Ok(current)
}

fn ensure_proof_payload(path: &Path, expected: &[u8]) -> Result<()> {
    if inspect_private_file(path, 1024 * 1024)?.is_some() {
        let actual = read_bounded(path, 1024 * 1024, "canonical proof payload")?;
        if actual != expected {
            return Err(PublicValidityPublisherError::Conflict(format!(
                "persisted canonical proof payload {} differs from the candidate",
                path.display()
            )));
        }
        return Ok(());
    }
    atomic_write_private(path, expected)
}

/// Publish one candidate-bound API validity envelope to L1.
///
/// The returned object deliberately exposes only the finalization transaction plus candidate
/// binding. Posting/attestation transaction hashes and all raw transactions remain in the 0600
/// operator journal; callers of the keyless API need neither intermediate mutation handle.
pub fn publish_public_validity(
    config: &PublicValidityPublisherConfig,
) -> Result<PublicValidityPublication> {
    if config.rpc_url.trim().is_empty() {
        return Err(PublicValidityPublisherError::Configuration(
            "RPC URL must not be empty".into(),
        ));
    }
    if config.finality_timeout.is_zero() || config.finality_timeout > Duration::from_secs(86_400) {
        return Err(PublicValidityPublisherError::Configuration(
            "finality timeout must be in 1..=86400 seconds".into(),
        ));
    }
    if config.envelope_path == config.journal_path
        || config.deployment_manifest_path == config.journal_path
        || config.deployment_manifest_path == config.envelope_path
        || config.lock_root == config.envelope_path
        || config.lock_root == config.deployment_manifest_path
        || config.lock_root == config.journal_path
    {
        return Err(PublicValidityPublisherError::Configuration(
            "envelope, deployment manifest, journal, and signer lock-root paths must differ".into(),
        ));
    }
    let lock_root = ensure_private_lock_root(&config.lock_root)?;
    let _journal_lock = JournalLock::acquire(&config.journal_path)?;
    let envelope_bytes = read_bounded(
        &config.envelope_path,
        MAX_ENVELOPE_BYTES,
        "validity envelope",
    )?;
    let prepared = prepare_envelope(&envelope_bytes)?;
    let observed_chain_id = rpc_chain_id(&config.rpc_url)?;
    if observed_chain_id != prepared.envelope.chain_id {
        return Err(PublicValidityPublisherError::Evidence(format!(
            "validity envelope chain {} != RPC chain {observed_chain_id}",
            prepared.envelope.chain_id
        )));
    }
    if config.allow_unfinalized_devnet && observed_chain_id != ANVIL_CHAIN_ID {
        return Err(PublicValidityPublisherError::Configuration(format!(
            "unfinalized-head escape is restricted to chain {ANVIL_CHAIN_ID}"
        )));
    }
    let environment_account = std::env::var("INTMAX_L1_ACCOUNT").ok();
    let account = config.account.as_deref().or(environment_account.as_deref());
    let signer = L1Signer::resolve(observed_chain_id, account)?;
    let signer_address = signer.address()?;
    let signer_lock_base = signer_lock_base(&lock_root, observed_chain_id, &signer_address)?;
    let _signer_lock = JournalLock::acquire(&signer_lock_base)?;
    let deployment = load_and_validate_deployment_manifest(
        &config.deployment_manifest_path,
        &prepared,
        &config.deployment_manifest_sha256,
    )?;
    validate_deployment_on_l1(
        &config.rpc_url,
        &prepared,
        &deployment,
        &signer_address,
        config.allow_unfinalized_devnet,
    )?;

    let mut journal = load_or_create_journal(
        &config.journal_path,
        prepared.binding(&deployment),
        &signer_address,
        &lock_root,
    )?;
    let proof_path = proof_payload_path(&config.journal_path)?;
    ensure_proof_payload(&proof_path, &prepared.proof_payload)?;

    let post_reservation = validity_signer_reservation(
        observed_chain_id,
        &signer_address,
        &config.journal_path,
        &journal.binding,
        "post",
        &prepared.envelope.rollup,
        &journal.binding.post_calldata_hash,
        POST_STAKE_WEI,
    )?;
    let post_needs_reservation = journal
        .post
        .as_ref()
        .map(|post| post.transaction.confirmation.is_none())
        .unwrap_or(true);
    if journal.post.is_none() {
        let post = sign_after_reservation(&lock_root, &post_reservation, || {
            sign_blob_transaction(
                &prepared,
                &config.rpc_url,
                &signer,
                &signer_address,
                &proof_path,
            )
        })?;
        journal.post = Some(post);
        // The next externally observable action is publication. Raw type-3 bytes and every
        // commitment/proof/versioned hash are durable before crossing that boundary.
        write_journal(&config.journal_path, &journal)?;
    } else if post_needs_reservation {
        // A crash after WAL fsync releases `flock`, but not this signer-global lease. Reclaim only
        // the exact journal/phase/intent before replaying its byte-identical raw transaction.
        claim_signer_reservation(&lock_root, &post_reservation)?;
    }
    let mut post = journal.post.clone().expect("created above");
    validate_persisted_blob_step(&post, &prepared, &signer_address)?;
    // Re-read immediately after potentially expensive blob construction and durable persistence.
    // This narrows (but cannot eliminate) the predecessor race in the current Solidity ABI.
    validate_deployment_on_l1(
        &config.rpc_url,
        &prepared,
        &deployment,
        &signer_address,
        config.allow_unfinalized_devnet,
    )?;
    if post_needs_reservation {
        publish_exact_raw(&config.rpc_url, &signer_address, &post.transaction)?;
    }
    let (post_receipt, post_confirmation) = revalidate_stored_confirmation(
        &config.rpc_url,
        observed_chain_id,
        config.allow_unfinalized_devnet,
        config.finality_timeout,
        &post.transaction,
        &signer_address,
    )?;
    let submission_id = submitted_id_from_receipt(
        &post_receipt,
        &prepared.envelope.rollup,
        &signer_address,
        &prepared.proof_hash,
        prepared.proof_length,
        &prepared.final_state_root,
    )
    .map_err(PublicValidityPublisherError::Evidence)?;
    if let Some(stored) = &post.submission_id {
        if !same_hex(stored, &submission_id) {
            return Err(PublicValidityPublisherError::Evidence(
                "persisted Submitted id changed on replay".into(),
            ));
        }
    }
    post.submission_id = Some(submission_id.clone());
    post.transaction.confirmation = Some(post_confirmation);
    journal.post = Some(post.clone());
    write_journal(&config.journal_path, &journal)?;
    if post_needs_reservation {
        release_signer_reservation(&lock_root, &post_reservation)?;
    } else {
        release_exact_signer_reservation(&lock_root, &post_reservation)?;
    }

    let attest_calldata = prepared
        .attest_calldata(&submission_id, &post.compact_sidecars)
        .map_err(|error| {
            PublicValidityPublisherError::Envelope(format!("encode attestProofData: {error}"))
        })?;
    let attest_calldata_hash = keccak_hex(
        &hex::decode(attest_calldata.trim_start_matches("0x")).map_err(|error| {
            PublicValidityPublisherError::Envelope(format!("decode attest calldata: {error}"))
        })?,
    );
    let attest_reservation = validity_signer_reservation(
        observed_chain_id,
        &signer_address,
        &config.journal_path,
        &journal.binding,
        "attest",
        &prepared.envelope.rollup,
        &attest_calldata_hash,
        0,
    )?;
    let attest_needs_reservation = journal
        .attest
        .as_ref()
        .map(|step| step.confirmation.is_none())
        .unwrap_or(true);
    if journal.attest.is_none() {
        let attest = sign_after_reservation(&lock_root, &attest_reservation, || {
            sign_normal_transaction(
                &config.rpc_url,
                &signer,
                &signer_address,
                observed_chain_id,
                &prepared.envelope.rollup,
                &attest_calldata,
            )
        })?;
        journal.attest = Some(attest);
        write_journal(&config.journal_path, &journal)?;
    } else if attest_needs_reservation {
        claim_signer_reservation(&lock_root, &attest_reservation)?;
    }
    let mut attest = journal.attest.clone().expect("created above");
    validate_persisted_normal_step(
        &attest,
        observed_chain_id,
        &signer_address,
        &prepared.envelope.rollup,
        &attest_calldata,
    )?;
    if attest_needs_reservation {
        publish_exact_raw(&config.rpc_url, &signer_address, &attest)?;
    }
    let (attest_receipt, attest_confirmation) = revalidate_stored_confirmation(
        &config.rpc_url,
        observed_chain_id,
        config.allow_unfinalized_devnet,
        config.finality_timeout,
        &attest,
        &signer_address,
    )?;
    validate_attestation_readback(
        &config.rpc_url,
        &prepared.envelope.rollup,
        &deployment,
        &submission_id,
        &prepared.proof_hash,
        prepared.proof_length,
        &attest_receipt,
        &attest_confirmation,
    )?;
    attest.confirmation = Some(attest_confirmation);
    journal.attest = Some(attest);
    write_journal(&config.journal_path, &journal)?;
    if attest_needs_reservation {
        release_signer_reservation(&lock_root, &attest_reservation)?;
    } else {
        release_exact_signer_reservation(&lock_root, &attest_reservation)?;
    }

    let finalize_calldata = prepared
        .finalize_calldata(&submission_id)
        .map_err(|error| {
            PublicValidityPublisherError::Envelope(format!("encode finalize: {error}"))
        })?;
    let finalize_calldata_hash = keccak_hex(
        &hex::decode(finalize_calldata.trim_start_matches("0x")).map_err(|error| {
            PublicValidityPublisherError::Envelope(format!("decode finalize calldata: {error}"))
        })?,
    );
    let finalize_reservation = validity_signer_reservation(
        observed_chain_id,
        &signer_address,
        &config.journal_path,
        &journal.binding,
        "finalize",
        &prepared.envelope.rollup,
        &finalize_calldata_hash,
        0,
    )?;
    let submitted_at_block = journal
        .post
        .as_ref()
        .and_then(|post| post.transaction.confirmation.as_ref())
        .map(|confirmation| confirmation.block_number)
        .ok_or_else(|| {
            PublicValidityPublisherError::Journal(
                "finalization reached without a durable posting confirmation".into(),
            )
        })?;

    if let Some(finalize) = journal.finalize.as_ref() {
        validate_persisted_normal_step(
            finalize,
            observed_chain_id,
            &signer_address,
            &prepared.envelope.rollup,
            &finalize_calldata,
        )?;
        if finalize.confirmation.is_some() && finalize.superseded_confirmation.is_some() {
            return Err(PublicValidityPublisherError::Conflict(
                "local finalize is recorded as both winner and superseded".into(),
            ));
        }
    }

    let adopted = if let Some(stored) = journal.adopted_finalize.as_ref() {
        Some(revalidate_adopted_finalization(
            config,
            &deployment,
            observed_chain_id,
            &prepared.envelope.rollup,
            &submission_id,
            &signer_address,
            submitted_at_block,
            &prepared.final_state_root,
            prepared.final_block_number,
            stored,
        )?)
    } else {
        let discovered = discover_semantic_finalization(
            config,
            &deployment,
            observed_chain_id,
            &prepared.envelope.rollup,
            &submission_id,
            &signer_address,
            submitted_at_block,
            &prepared.final_state_root,
            prepared.final_block_number,
        )?;
        match discovered {
            Some(discovered)
                if journal.finalize.as_ref().is_some_and(|local| {
                    same_hex(
                        &local.transaction_hash,
                        &discovered.confirmation.transaction_hash,
                    )
                }) =>
            {
                None
            }
            Some(discovered) => {
                // The semantic winner is durable before we begin settling any losing local raw.
                journal.adopted_finalize = Some(discovered.clone());
                write_journal(&config.journal_path, &journal)?;
                Some(discovered)
            }
            None => None,
        }
    };

    let (finalization_transaction_hash, finalize_confirmation) = if let Some(winner) = adopted {
        if let Some(mut local) = journal.finalize.clone() {
            if same_hex(
                &local.transaction_hash,
                &winner.confirmation.transaction_hash,
            ) {
                return Err(PublicValidityPublisherError::Conflict(
                    "adopted finalization duplicates the journaled local transaction".into(),
                ));
            }
            let needs_reservation = local.superseded_confirmation.is_none();
            if needs_reservation {
                claim_signer_reservation(&lock_root, &finalize_reservation)?;
            }
            let settled = ensure_superseded_finalize_settled(
                config,
                observed_chain_id,
                &signer_address,
                &prepared.envelope.rollup,
                &submission_id,
                &prepared.final_state_root,
                &local,
            )?;
            local.superseded_confirmation = Some(settled);
            journal.finalize = Some(local);
            journal.adopted_finalize = Some(winner.clone());
            // Both the winner and the nonce-consuming loser are durable before releasing the lane.
            write_journal(&config.journal_path, &journal)?;
        } else {
            journal.adopted_finalize = Some(winner.clone());
        }
        (
            winner.confirmation.transaction_hash.clone(),
            winner.confirmation.clone(),
        )
    } else {
        let finalize_needs_reservation = journal
            .finalize
            .as_ref()
            .map(|step| step.confirmation.is_none() && step.superseded_confirmation.is_none())
            .unwrap_or(true);
        if journal.finalize.is_none() {
            let finalize = sign_after_reservation(&lock_root, &finalize_reservation, || {
                sign_normal_transaction(
                    &config.rpc_url,
                    &signer,
                    &signer_address,
                    observed_chain_id,
                    &prepared.envelope.rollup,
                    &finalize_calldata,
                )
            })?;
            journal.finalize = Some(finalize);
            write_journal(&config.journal_path, &journal)?;
        } else if finalize_needs_reservation {
            claim_signer_reservation(&lock_root, &finalize_reservation)?;
        }
        let mut finalize = journal.finalize.clone().expect("created above");
        if finalize.superseded_confirmation.is_some() {
            return Err(PublicValidityPublisherError::Conflict(
                "superseded local finalize has no adopted semantic winner".into(),
            ));
        }
        validate_persisted_normal_step(
            &finalize,
            observed_chain_id,
            &signer_address,
            &prepared.envelope.rollup,
            &finalize_calldata,
        )?;
        if finalize_needs_reservation {
            publish_exact_raw(&config.rpc_url, &signer_address, &finalize)?;
        }
        let (finalize_receipt, mut confirmation) = wait_for_finalized_receipt_with_identity(
            &config.rpc_url,
            observed_chain_id,
            config.allow_unfinalized_devnet,
            config.finality_timeout,
            &finalize.transaction_hash,
            Some(&signer_address),
            Some(&finalize.target),
            false,
        )?;
        if let Some(stored) = &finalize.confirmation {
            validate_stored_receipt_progress(&config.rpc_url, stored, &confirmation)?;
        }
        let success =
            receipt_status(&finalize_receipt).map_err(PublicValidityPublisherError::Evidence)?;
        let semantic = classify_finalization_events(
            &finalize_receipt,
            &prepared.envelope.rollup,
            &submission_id,
            &prepared.final_state_root,
        )?;
        if success && semantic == FinalizationReceiptSemantic::Finalized {
            confirmation.finalized_checkpoint = validate_finalization_readback(
                &config.rpc_url,
                &prepared.envelope.rollup,
                &deployment,
                &submission_id,
                &signer_address,
                submitted_at_block,
                &prepared.final_state_root,
                prepared.final_block_number,
                &finalize_receipt,
                &confirmation,
                config.allow_unfinalized_devnet,
            )?;
            finalize.confirmation = Some(confirmation.clone());
            journal.finalize = Some(finalize.clone());
            write_journal(&config.journal_path, &journal)?;
            (finalize.transaction_hash.clone(), confirmation)
        } else {
            let discovered = discover_semantic_finalization(
                config,
                &deployment,
                observed_chain_id,
                &prepared.envelope.rollup,
                &submission_id,
                &signer_address,
                submitted_at_block,
                &prepared.final_state_root,
                prepared.final_block_number,
            )?
            .ok_or_else(|| {
                PublicValidityPublisherError::Evidence(
                    "local finalize did not complete and no exact permissionless winner exists"
                        .into(),
                )
            })?;
            if same_hex(
                &discovered.confirmation.transaction_hash,
                &finalize.transaction_hash,
            ) {
                return Err(PublicValidityPublisherError::Evidence(
                    "local finalize receipt contradicts its discovered Finalized event".into(),
                ));
            }
            journal.adopted_finalize = Some(discovered.clone());
            write_journal(&config.journal_path, &journal)?;
            validate_superseded_finalize_receipt(
                &finalize_receipt,
                &prepared.envelope.rollup,
                &submission_id,
                &prepared.final_state_root,
            )?;
            finalize.superseded_confirmation = Some(confirmation);
            journal.finalize = Some(finalize);
            write_journal(&config.journal_path, &journal)?;
            (
                discovered.confirmation.transaction_hash.clone(),
                discovered.confirmation,
            )
        }
    };

    let output = PublicValidityPublication {
        schema_version: 1,
        chain_id: observed_chain_id,
        rollup: prepared.envelope.rollup.to_ascii_lowercase(),
        candidate_id: prepared.candidate_id,
        candidate_request_id: prepared.envelope.candidate_request_id,
        artifact_hash: prepared.envelope.artifact_hash,
        proof_hash: prepared.proof_hash,
        proof_length: prepared.proof_length,
        submission_id,
        finalization_transaction_hash,
        finalized_checkpoint: finalize_confirmation.finalized_checkpoint,
    };
    if let Some(stored) = &journal.completed {
        if stored.chain_id != output.chain_id
            || !same_hex(&stored.rollup, &output.rollup)
            || !same_hex(&stored.candidate_id, &output.candidate_id)
            || stored.candidate_request_id != output.candidate_request_id
            || stored.artifact_hash != output.artifact_hash
            || !same_hex(
                &stored.finalization_transaction_hash,
                &output.finalization_transaction_hash,
            )
        {
            return Err(PublicValidityPublisherError::Conflict(
                "persisted completion belongs to another candidate/finalization".into(),
            ));
        }
    }
    journal.completed = Some(output.clone());
    write_journal(&config.journal_path, &journal)?;
    // This is idempotent for an externally adopted winner with no local raw. When a local raw
    // exists, completion and (if needed) its superseded receipt are already fsynced above.
    release_exact_signer_reservation(&lock_root, &finalize_reservation)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn word(byte: u8) -> String {
        format!("0x{}", format!("{byte:02x}").repeat(32))
    }

    fn address(byte: u8) -> String {
        format!("0x{}", format!("{byte:02x}").repeat(20))
    }

    fn topic_u64(value: u64) -> String {
        format!("0x{:064x}", value)
    }

    fn finalization_receipt(status: u8, mut logs: Vec<Value>) -> Value {
        let transaction_hash = word(0xa1);
        let block_hash = word(0xb1);
        for (index, log) in logs.iter_mut().enumerate() {
            log["transactionHash"] = Value::String(transaction_hash.clone());
            log["blockHash"] = Value::String(block_hash.clone());
            log["blockNumber"] = Value::String("0x64".into());
            log["transactionIndex"] = Value::String("0x2".into());
            log["logIndex"] = Value::String(format!("0x{index:x}"));
            log["removed"] = Value::Bool(false);
        }
        serde_json::json!({
            "transactionHash": transaction_hash,
            "blockHash": block_hash,
            "blockNumber": "0x64",
            "transactionIndex": "0x2",
            "status": format!("0x{status:x}"),
            "from": address(0x91),
            "to": address(0x92),
            "logs": logs,
        })
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "intmax-public-validity-{}-{}-{name}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn checkpoint(height: u64, byte: u8) -> L1FinalizedCheckpoint {
        L1FinalizedCheckpoint {
            chain_id: 1,
            block_number: height,
            block_hash: word(byte).parse().unwrap(),
            parent_hash: word(byte.wrapping_sub(1)).parse().unwrap(),
            source: L1FinalitySource::RpcFinalized,
        }
    }

    fn sample_binding(candidate_byte: u8) -> CandidateBinding {
        CandidateBinding {
            schema_version: 2,
            chain_id: 1,
            rollup: address(0x11),
            channel_id: 7,
            manager: address(0x22),
            verifier: address(0x33),
            proposal_hash: word(0x44),
            producer_request_id: "producer:one".into(),
            candidate_request_id: "candidate:one".into(),
            candidate_id: word(candidate_byte),
            artifact_hash: format!("close-funding-validity-artifact:{}", "55".repeat(32)),
            deployment_manifest_hash: word(0x56),
            rollup_runtime_code_hash: word(0x57),
            mle_verifier: address(0x58),
            mle_verifier_runtime_code_hash: word(0x59),
            kzg_verifier: address(0x5a),
            kzg_verifier_runtime_code_hash: word(0x5b),
            proof_abi_version: 2,
            proof_hash: word(0x66),
            proof_length: 1234,
            final_state_root: word(0x77),
            final_block_number: 9,
            expected_pending_chains: word(0x88),
            post_calldata_hash: word(0x99),
            binding_digest: word(0xaa),
        }
    }

    fn sample_deployment_manifest() -> DeploymentManifest {
        DeploymentManifest {
            schema_version: 1,
            chain_id: 1,
            rollup: address(0x11),
            rollup_runtime_code_hash: word(0x21),
            mle_verifier: address(0x12),
            mle_verifier_runtime_code_hash: word(0x22),
            kzg_verifier: address(0x13),
            kzg_verifier_runtime_code_hash: word(0x23),
            mle_proof_abi_version: 2,
            post_block_and_submit_guarded_selector: "0x01020304".into(),
            attest_proof_data_selector: "0x05060708".into(),
            finalize_selector: "0x090a0b0c".into(),
        }
    }

    fn matching_deployment_identity(manifest: &DeploymentManifest) -> ObservedDeploymentIdentity {
        ObservedDeploymentIdentity {
            rollup_runtime_code_hash: manifest.rollup_runtime_code_hash.clone(),
            mle_verifier: manifest.mle_verifier.clone(),
            mle_verifier_runtime_code_hash: manifest.mle_verifier_runtime_code_hash.clone(),
            kzg_verifier: manifest.kzg_verifier.clone(),
            kzg_verifier_runtime_code_hash: manifest.kzg_verifier_runtime_code_hash.clone(),
        }
    }

    fn sample_raw_step(nonce: u64, transaction_byte: u8) -> RawTransactionStep {
        RawTransactionStep {
            target: address(0x11),
            calldata_hash: word(0x22),
            value: 0,
            nonce,
            raw_signed_transaction: format!("0x03{}", "ab".repeat(64)),
            transaction_hash: word(transaction_byte),
            confirmation: None,
            superseded_confirmation: None,
        }
    }

    fn synthetic_abi_value(
        kind: &AbiKind,
        counter: &mut u8,
        large_transcript: bool,
        field_name: &str,
    ) -> Value {
        *counter = counter.wrapping_add(1).max(1);
        match kind {
            AbiKind::Uint(_) => Value::String(u64::from((*counter % 7) + 1).to_string()),
            AbiKind::Address => Value::String(address(*counter)),
            AbiKind::FixedBytes(size) => {
                Value::String(format!("0x{}", format!("{:02x}", *counter).repeat(*size)))
            }
            AbiKind::Bytes => {
                if large_transcript && field_name == "whirTranscript" {
                    Value::String(format!("0x{}", "ab".repeat(127_000)))
                } else {
                    Value::String(format!("0x{:02x}{:02x}{:02x}", *counter, 2, 3))
                }
            }
            AbiKind::Tuple(fields) => Value::Object(
                fields
                    .iter()
                    .map(|field| {
                        (
                            field.name.to_string(),
                            synthetic_abi_value(&field.kind, counter, large_transcript, field.name),
                        )
                    })
                    .collect(),
            ),
            AbiKind::DynamicArray(element) => Value::Array(
                (0..2)
                    .map(|_| synthetic_abi_value(element, counter, large_transcript, field_name))
                    .collect(),
            ),
            AbiKind::FixedArray(element, length) => Value::Array(
                (0..*length)
                    .map(|_| synthetic_abi_value(element, counter, large_transcript, field_name))
                    .collect(),
            ),
        }
    }

    fn synthetic_mle_proof(version: u8, large_transcript: bool) -> Value {
        let mut counter = 0u8;
        let mut proof: serde_json::Map<String, Value> = mle_fields(version)
            .iter()
            .map(|field| {
                (
                    field.name.to_string(),
                    synthetic_abi_value(&field.kind, &mut counter, large_transcript, field.name),
                )
            })
            .collect();
        if version == 2 {
            proof.insert("protocolVersion".into(), Value::String("1".into()));
            proof.insert("constituentWidth".into(), Value::String("2".into()));
        }
        Value::Object(proof)
    }

    fn synthetic_vpis() -> Value {
        serde_json::json!({
            "initialBlockNumber": "3",
            "initialBlockChain": word(0x31),
            "initialExtCommitment": word(0x32),
            "finalBlockNumber": "4",
            "finalBlockChain": word(0x33),
            "finalExtCommitment": word(0x34),
            "prover": address(0x35),
        })
    }

    fn node_mle_reference(version: u8, proof: &Value, vpis: &Value) -> (Vec<u8>, String) {
        const SCRIPT: &str = r#"
const fs = require('fs');
const { AbiCoder, Interface } = require('./node/node_modules/ethers');
const settlement = require('./node/delegate/claim-settlement');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const components = input.version === 1
  ? settlement.MLE_PROOF_V1_COMPONENTS
  : settlement.MLE_PROOF_V2_COMPONENTS;
const proof = settlement.normalizeMleProof(input.proof, { allowLegacyMle: true });
const vpisComponents = [
  { name: 'initialBlockNumber', type: 'uint64' },
  { name: 'initialBlockChain', type: 'bytes32' },
  { name: 'initialExtCommitment', type: 'bytes32' },
  { name: 'finalBlockNumber', type: 'uint64' },
  { name: 'finalBlockChain', type: 'bytes32' },
  { name: 'finalExtCommitment', type: 'bytes32' },
  { name: 'prover', type: 'address' },
];
const proofBytes = AbiCoder.defaultAbiCoder().encode(
  [{ name: 'proof', type: 'tuple', components }],
  [proof],
);
const finalize = new Interface([{
  type: 'function',
  name: 'finalize',
  stateMutability: 'nonpayable',
  inputs: [
    { name: 'submissionId', type: 'uint256' },
    { name: 'stateRoot', type: 'bytes32' },
    { name: 'vpis', type: 'tuple', components: vpisComponents },
    { name: 'mleProof', type: 'tuple', components },
  ],
  outputs: [{ name: '', type: 'bool' }],
}]).encodeFunctionData('finalize', [input.submissionId, input.stateRoot, input.vpis, proof]);
process.stdout.write(JSON.stringify({ proofBytes, finalize }));
"#;
        let input = serde_json::to_vec(&serde_json::json!({
            "version": version,
            "proof": proof,
            "submissionId": "7",
            "stateRoot": word(0x41),
            "vpis": vpis,
        }))
        .unwrap();
        let mut child = Command::new("node")
            .arg("-e")
            .arg(SCRIPT)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Node.js is required for the independent ABI differential test");
        child.stdin.take().unwrap().write_all(&input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "independent ethers ABI encoder failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output: Value = serde_json::from_slice(&output.stdout).unwrap();
        let proof_bytes = hex::decode(
            output["proofBytes"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let finalize = output["finalize"].as_str().unwrap().to_string();
        (proof_bytes, finalize)
    }

    fn node_guarded_post_reference(input: &Value) -> String {
        const SCRIPT: &str = r#"
const fs = require('fs');
const { Interface } = require('./node/node_modules/ethers');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const subBlockComponents = [
  { name: 'channelId', type: 'uint32' },
  { name: 'timestamp', type: 'uint64' },
  { name: 'txTreeRoot', type: 'bytes32' },
  { name: 'keyIds', type: 'uint32[]' },
];
const calldata = new Interface([{
  type: 'function',
  name: 'postBlockAndSubmitGuarded',
  stateMutability: 'payable',
  inputs: [
    { name: 'subBlocks', type: 'tuple[]', components: subBlockComponents },
    { name: 'proofHash', type: 'bytes32' },
    { name: 'proofLength', type: 'uint32' },
    { name: 'stateRoot', type: 'bytes32' },
    { name: 'expectedPendingChains', type: 'bytes32' },
    { name: 'expectedBlockNumber', type: 'uint64' },
    { name: 'expectedBlockHashChain', type: 'bytes32' },
  ],
  outputs: [],
}]).encodeFunctionData('postBlockAndSubmitGuarded', [
  input.subBlocks,
  input.proofHash,
  input.proofLength,
  input.stateRoot,
  input.expectedPendingChains,
  input.expectedBlockNumber,
  input.expectedBlockHashChain,
]);
process.stdout.write(calldata);
"#;
        let mut child = Command::new("node")
            .arg("-e")
            .arg(SCRIPT)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Node.js is required for the independent ABI differential test");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(input).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "independent ethers guarded-post encoder failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    #[test]
    fn abi_encoder_matches_solidity_head_tail_rules() {
        let uint_kind = AbiKind::Uint(256);
        let bytes_kind = AbiKind::Bytes;
        let number = Value::String("291".into());
        let bytes = Value::String("0xaabb".into());
        let calldata = encode_function(
            "f",
            &[
                (&uint_kind, &number, "number"),
                (&bytes_kind, &bytes, "bytes"),
            ],
        )
        .unwrap();
        let selector = hex::encode(&keccak_hash::keccak(b"f(uint256,bytes)").0[..4]);
        let expected = format!(
            "0x{selector}{:064x}{:064x}{:064x}aabb{}",
            291,
            64,
            2,
            "00".repeat(30)
        );
        assert_eq!(calldata, expected);

        let tuple = AbiKind::Tuple(vec![
            uint("scalar", 256),
            AbiField::new("items", AbiKind::DynamicArray(Box::new(AbiKind::Uint(256)))),
        ]);
        let value = serde_json::json!({"scalar": "7", "items": ["8", "9"]});
        let encoded = encode_sequence([(&tuple, &value, "tuple".into())]).unwrap();
        let expected = format!(
            "{}{}{}{}{}{}",
            format!("{:064x}", 32),
            format!("{:064x}", 7),
            format!("{:064x}", 64),
            format!("{:064x}", 2),
            format!("{:064x}", 8),
            format!("{:064x}", 9),
        );
        assert_eq!(hex::encode(encoded), expected);
    }

    #[test]
    fn guarded_post_abi_order_matches_independent_ethers_encoder() {
        let sub_blocks = serde_json::json!([{
            "channelId": 7,
            "timestamp": 1000,
            "txTreeRoot": word(0xef),
            "keyIds": [1, 0],
        }]);
        let proof_hash = Value::String(word(0x11));
        let proof_length = Value::from(131_872u32);
        let state_root = Value::String(word(0x22));
        let pending = Value::String(word(0x33));
        let expected_number = Value::from(9u64);
        let expected_chain = Value::String(word(0x44));
        let sub_blocks_kind = AbiKind::DynamicArray(Box::new(post_sub_block_kind()));
        let bytes32_kind = AbiKind::FixedBytes(32);
        let rust = encode_function(
            "postBlockAndSubmitGuarded",
            &[
                (&sub_blocks_kind, &sub_blocks, "subBlocks"),
                (&bytes32_kind, &proof_hash, "proofHash"),
                (&AbiKind::Uint(32), &proof_length, "proofLength"),
                (&bytes32_kind, &state_root, "stateRoot"),
                (&bytes32_kind, &pending, "expectedPendingChains"),
                (&AbiKind::Uint(64), &expected_number, "expectedBlockNumber"),
                (&bytes32_kind, &expected_chain, "expectedBlockHashChain"),
            ],
        )
        .unwrap();
        let ethers = node_guarded_post_reference(&serde_json::json!({
            "subBlocks": sub_blocks,
            "proofHash": proof_hash,
            "proofLength": proof_length,
            "stateRoot": state_root,
            "expectedPendingChains": pending,
            "expectedBlockNumber": expected_number,
            "expectedBlockHashChain": expected_chain,
        }));
        assert_eq!(rust, ethers);
        assert_eq!(&rust[..10], "0xe913eaa3");
        assert_eq!(
            &format!(
                "0x{}",
                hex::encode(&keccak_hash::keccak(POST_SIGNATURE.as_bytes()).0[..4])
            ),
            &rust[..10]
        );
    }

    #[test]
    fn full_mle_v1_and_v2_abi_and_finalize_match_independent_ethers_encoder() {
        let vpis = synthetic_vpis();
        for version in [1u8, 2u8] {
            let proof = synthetic_mle_proof(version, false);
            let proof_kind = AbiKind::Tuple(mle_fields(version));
            let rust_proof = encode_sequence([(&proof_kind, &proof, "mleProof".into())]).unwrap();
            let id_kind = AbiKind::Uint(256);
            let root_kind = AbiKind::FixedBytes(32);
            let vpis_kind = AbiKind::Tuple(vpis_fields());
            let id = Value::String("7".into());
            let root = Value::String(word(0x41));
            let rust_finalize = encode_function(
                "finalize",
                &[
                    (&id_kind, &id, "submissionId"),
                    (&root_kind, &root, "stateRoot"),
                    (&vpis_kind, &vpis, "validityPIs"),
                    (&proof_kind, &proof, "mleProof"),
                ],
            )
            .unwrap();
            let (ethers_proof, ethers_finalize) = node_mle_reference(version, &proof, &vpis);
            assert_eq!(rust_proof, ethers_proof, "MLE ABI v{version}");
            assert_eq!(rust_finalize, ethers_finalize, "finalize ABI v{version}");
            let (golden_length, golden_proof_hash, golden_finalize_hash) = match version {
                1 => (
                    6_400,
                    "0xb3ff456226c76f6ce0b41bf512173b1079479eb3ea1d23d30be118ec31ec99cb",
                    "0xe7febb7cf02f4f309323bac7928f62b1b9e0d193c9de8939762e32813f4e31ac",
                ),
                2 => (
                    4_896,
                    "0xa887d0f3926acd5462ce366e1e8d0b7dc5e92ab2c683a5ce75128a548a87de10",
                    "0x516a981f5e782e2b09a6267316f316066fa7228987997ff27cc6ac7333492663",
                ),
                _ => unreachable!(),
            };
            assert_eq!(rust_proof.len(), golden_length);
            assert_eq!(keccak_hex(&rust_proof), golden_proof_hash);
            assert_eq!(
                keccak_hex(&hex::decode(rust_finalize.trim_start_matches("0x")).unwrap()),
                golden_finalize_hash
            );
        }
    }

    #[test]
    fn full_mle_payload_hash_length_and_two_blob_boundary_match_ethers() {
        let version = 2u8;
        let proof = synthetic_mle_proof(version, true);
        let proof_kind = AbiKind::Tuple(mle_fields(version));
        let rust_proof = encode_sequence([(&proof_kind, &proof, "mleProof".into())]).unwrap();
        let (ethers_proof, ethers_finalize) =
            node_mle_reference(version, &proof, &synthetic_vpis());
        assert_eq!(rust_proof, ethers_proof);
        assert_eq!(rust_proof.len(), 131_872);
        assert_eq!(
            keccak_hex(&rust_proof),
            "0x6b68738d1001c7ba077b074293d284bb00e02933e6b84cb36b2e8b2646109cd6"
        );
        assert_eq!(
            keccak_hex(&hex::decode(ethers_finalize.trim_start_matches("0x")).unwrap()),
            "0xa5a306b8a5eb12e50b5c1e3493e43e128f5a77df69ca54321724eaf4e28a3264"
        );
        assert!(rust_proof.len() > crate::proof_da::ONE_BLOB_CAPACITY);
        assert!(rust_proof.len() <= crate::proof_da::TWO_BLOB_CAPACITY);
        assert_eq!(
            crate::proof_da::encode_simple_coder_blobs(&rust_proof)
                .unwrap()
                .len(),
            2
        );
        let proof_length = u32::try_from(rust_proof.len()).unwrap();
        assert_eq!(usize::try_from(proof_length).unwrap(), rust_proof.len());
        assert_eq!(keccak_hex(&rust_proof), keccak_hex(&ethers_proof));
        // The independent finalize encoding includes the exact same large proof bytes rather than
        // a hash-only surrogate; a truncation or alternate tuple layout changes this calldata.
        assert!(ethers_finalize.len() > 2 * rust_proof.len());

        assert_eq!(
            crate::proof_da::encode_simple_coder_blobs(&vec![
                0u8;
                crate::proof_da::ONE_BLOB_CAPACITY
            ])
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            crate::proof_da::encode_simple_coder_blobs(&vec![
                0u8;
                crate::proof_da::ONE_BLOB_CAPACITY + 1
            ])
            .unwrap()
            .len(),
            2
        );
    }

    #[test]
    fn mle_schema_never_silently_switches_and_v1_is_dev_only() {
        assert_eq!(
            proof_abi_version(&serde_json::json!({}), ANVIL_CHAIN_ID).unwrap(),
            1
        );
        assert!(
            proof_abi_version(&serde_json::json!({}), 1)
                .unwrap_err()
                .contains("restricted")
        );
        assert!(
            proof_abi_version(&serde_json::json!({"protocolVersion": 1}), ANVIL_CHAIN_ID)
                .unwrap_err()
                .contains("both")
        );
        let mut v2 = serde_json::json!({
            "protocolVersion": 1,
            "constituentWidth": 3,
            "preprocessedIndividualEvals": ["1", "2", "3"],
            "witnessIndividualEvals": [],
            "inverseHelpersEvalsAtRInv": [],
            "inverseHelpersEvalsAtRH": [],
            "preprocessedIndividualEvalsAtRGateV2": [],
            "witnessIndividualEvalsAtRGateV2": [],
        });
        assert_eq!(proof_abi_version(&v2, 1).unwrap(), 2);
        v2["constituentWidth"] = Value::from(4);
        assert!(proof_abi_version(&v2, 1).unwrap_err().contains("canonical"));
    }

    #[test]
    fn vpi_hash_and_guarded_post_chain_match_solidity_packed_goldens() {
        let vpis = synthetic_vpis();
        let packed = packed_validity_public_inputs(&vpis).unwrap();
        assert_eq!(packed.len(), 164);
        let hash = keccak_hash::keccak(&packed).0;
        assert_eq!(
            format!("0x{}", hex::encode(hash)),
            "0x0c5a9bafe6c36d7b0abc8d0d0e4ede7b4e652fc87396b761185f71ed792018aa"
        );
        let public_inputs = hash
            .chunks_exact(4)
            .map(|limb| Value::String(u32::from_be_bytes(limb.try_into().unwrap()).to_string()))
            .collect::<Vec<_>>();
        let proof = serde_json::json!({ "publicInputs": public_inputs });
        validate_public_inputs_hash(&proof, &vpis).unwrap();
        let mut extra_limb = proof;
        extra_limb["publicInputs"]
            .as_array_mut()
            .unwrap()
            .push(Value::String("0".into()));
        assert!(validate_public_inputs_hash(&extra_limb, &vpis).is_err());

        let block = PostingSubBlock {
            channel_id: 7,
            timestamp: 1_000,
            tx_tree_root: word(0xef),
            num_users: 2,
            key_ids: vec![1, 0],
            deposit_hash_chain: word(0x55),
            channel_reg_hash_chain: word(0x66),
        };
        assert_eq!(
            posted_block_hash(&word(0x31), &block).unwrap(),
            "0x0b597d4488d0ffe1db2e92c58d3f76ba40eaa9e403b14f0e6e01da52304c0bf1"
        );
    }

    #[test]
    fn exact_journal_replay_succeeds_but_sibling_candidate_conflicts() {
        let directory = temp_path("journal");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("publication.json");
        let lock_root = directory.join("locks");
        let signer = address(0x12);
        let binding = sample_binding(0x01);
        let mut first =
            load_or_create_journal(&path, binding.clone(), &signer, &lock_root).unwrap();
        let mut blob_transaction = sample_raw_step(17, 0xa1);
        blob_transaction.value = POST_STAKE_WEI;
        first.post = Some(BlobPostStep {
            transaction: blob_transaction,
            blob_versioned_hashes: vec![word(0xb1), word(0xb2)],
            compact_sidecars: "0x1234".into(),
            submission_id: Some("23".into()),
        });
        first.attest = Some(sample_raw_step(18, 0xa2));
        first.finalize = Some(sample_raw_step(19, 0xa3));
        first.finalize.as_mut().unwrap().superseded_confirmation = Some(FinalizedReceipt {
            transaction_hash: word(0xa3),
            block_hash: word(0xc1),
            block_number: 24,
            finalized_checkpoint: checkpoint(25, 0xc2),
        });
        first.adopted_finalize = Some(AdoptedFinalization {
            submission_id: "23".into(),
            state_root: binding.final_state_root.clone(),
            confirmation: FinalizedReceipt {
                transaction_hash: word(0xa4),
                block_hash: word(0xc3),
                block_number: 23,
                finalized_checkpoint: checkpoint(25, 0xc2),
            },
        });
        write_journal(&path, &first).unwrap();

        let replay = load_or_create_journal(&path, binding.clone(), &signer, &lock_root).unwrap();
        assert_eq!(
            first, replay,
            "restart must preserve every exact raw artifact"
        );
        assert!(matches!(
            load_or_create_journal(&path, sample_binding(0x02), &signer, &lock_root),
            Err(PublicValidityPublisherError::Conflict(_))
        ));
        assert!(matches!(
            load_or_create_journal(&path, binding, &signer, &directory.join("other-locks")),
            Err(PublicValidityPublisherError::Conflict(_))
        ));
        #[cfg(unix)]
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn exact_replay_never_authorizes_a_sibling_nonce_replacement() {
        let step = sample_raw_step(17, 0xa1);
        assert!(!exact_publish_needed(true, 17, &step).unwrap());
        assert!(exact_publish_needed(false, 17, &step).unwrap());
        assert!(matches!(
            exact_publish_needed(false, 18, &step),
            Err(PublicValidityPublisherError::Conflict(_))
        ));
        assert!(matches!(
            exact_publish_needed(false, 16, &step),
            Err(PublicValidityPublisherError::Conflict(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn signer_lock_is_global_across_distinct_journal_directories() {
        let directory = temp_path("global-signer-lock");
        let journal_a = directory.join("candidate-a/publication.json");
        let journal_b = directory.join("candidate-b/publication.json");
        fs::create_dir_all(journal_a.parent().unwrap()).unwrap();
        fs::create_dir_all(journal_b.parent().unwrap()).unwrap();
        assert_ne!(journal_a.parent(), journal_b.parent());

        let lock_root = ensure_private_lock_root(&directory.join("operator-locks")).unwrap();
        let base_a = signer_lock_base(&lock_root, 1, &address(0x12)).unwrap();
        let base_b = signer_lock_base(&lock_root, 1, &address(0x12)).unwrap();
        assert_eq!(base_a, base_b);

        let first = JournalLock::acquire(&base_a).unwrap();
        assert!(matches!(
            JournalLock::acquire(&base_b),
            Err(PublicValidityPublisherError::Conflict(_))
        ));
        // The same account on another chain and another account on the same chain do not share a
        // nonce space and therefore use distinct lock files.
        let other_chain =
            JournalLock::acquire(&signer_lock_base(&lock_root, 2, &address(0x12)).unwrap())
                .unwrap();
        let other_signer =
            JournalLock::acquire(&signer_lock_base(&lock_root, 1, &address(0x13)).unwrap())
                .unwrap();
        drop((first, other_chain, other_signer));
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn signer_reservation_precedes_sign_and_survives_the_raw_wal_crash_boundary() {
        let directory = temp_path("signer-reservation-boundaries");
        let journal = directory.join("candidate/publication.json");
        fs::create_dir_all(journal.parent().unwrap()).unwrap();
        let lock_root = ensure_private_lock_root(&directory.join("operator-locks")).unwrap();
        let binding = sample_binding(0x41);
        let post = validity_signer_reservation(
            1,
            &address(0x12),
            &journal,
            &binding,
            "post",
            &binding.rollup,
            &binding.post_calldata_hash,
            POST_STAKE_WEI,
        )
        .unwrap();
        let attest = validity_signer_reservation(
            1,
            &address(0x12),
            &journal,
            &binding,
            "attest",
            &binding.rollup,
            &word(0x42),
            0,
        )
        .unwrap();

        let raw = sign_after_reservation(&lock_root, &post, || {
            assert!(l1_signer_reservation::claim(&lock_root, &attest).is_err());
            Ok("0xsigned")
        })
        .unwrap();
        assert_eq!(raw, "0xsigned");
        // Returning raw bytes models the boundary before their journal fsync. The lease is not an
        // RAII process lock: a crash leaves it durable and only the exact owner may resume.
        assert!(l1_signer_reservation::claim(&lock_root, &attest).is_err());
        l1_signer_reservation::claim(&lock_root, &post).unwrap();
        l1_signer_reservation::release(&lock_root, &post).unwrap();

        let signing_error = sign_after_reservation::<()>(&lock_root, &attest, || {
            Err(PublicValidityPublisherError::Command(
                "offline signer failed".into(),
            ))
        })
        .unwrap_err();
        assert!(signing_error.to_string().contains("offline signer failed"));
        l1_signer_reservation::claim(&lock_root, &post).unwrap();
        l1_signer_reservation::release(&lock_root, &post).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn deployment_manifest_requires_nonzero_kzg_address_and_runtime_hash() {
        let manifest = sample_deployment_manifest();
        validate_deployment_manifest_identity_pins(&manifest).unwrap();

        let mut missing = serde_json::to_value(&manifest).unwrap();
        missing.as_object_mut().unwrap().remove("kzgVerifier");
        assert!(serde_json::from_value::<DeploymentManifest>(missing).is_err());
        let mut missing_hash = serde_json::to_value(&manifest).unwrap();
        missing_hash
            .as_object_mut()
            .unwrap()
            .remove("kzgVerifierRuntimeCodeHash");
        assert!(serde_json::from_value::<DeploymentManifest>(missing_hash).is_err());

        let mut zero_address = manifest.clone();
        zero_address.kzg_verifier = format!("0x{}", "00".repeat(20));
        assert!(
            validate_deployment_manifest_identity_pins(&zero_address)
                .unwrap_err()
                .contains("KZG verifier must be nonzero")
        );

        let mut zero_hash = manifest;
        zero_hash.kzg_verifier_runtime_code_hash = format!("0x{}", "00".repeat(32));
        assert!(
            validate_deployment_manifest_identity_pins(&zero_hash)
                .unwrap_err()
                .contains("KZG verifier runtime code hash must be nonzero")
        );
    }

    #[test]
    fn deployment_manifest_pin_authenticates_exact_raw_bytes_before_parsing() {
        let raw = br#"{"schemaVersion":1,"chainId":1}"#;
        let pin = sha256_hex(raw);
        assert_eq!(
            validate_deployment_manifest_raw_hash(raw, &pin).unwrap(),
            pin
        );

        let mut whitespace_variant = raw.to_vec();
        whitespace_variant.push(b'\n');
        assert!(
            validate_deployment_manifest_raw_hash(&whitespace_variant, &pin)
                .unwrap_err()
                .to_string()
                .contains("raw-byte SHA-256")
        );
        assert!(validate_deployment_manifest_raw_hash(raw, "0x1234").is_err());
        assert!(
            validate_deployment_manifest_raw_hash(raw, &format!("0x{}", "00".repeat(32)))
                .unwrap_err()
                .to_string()
                .contains("must be nonzero")
        );
    }

    #[test]
    fn deployment_identity_rejects_kzg_getter_or_runtime_code_substitution() {
        let manifest = sample_deployment_manifest();
        let exact = matching_deployment_identity(&manifest);
        validate_deployment_identity(&manifest, &exact).unwrap();

        let mut wrong_address = exact.clone();
        wrong_address.kzg_verifier = address(0x99);
        assert!(
            validate_deployment_identity(&manifest, &wrong_address)
                .unwrap_err()
                .to_string()
                .contains("rollup.kzgVerifier")
        );

        let mut wrong_hash = exact;
        wrong_hash.kzg_verifier_runtime_code_hash = word(0x99);
        assert!(
            validate_deployment_identity(&manifest, &wrong_hash)
                .unwrap_err()
                .to_string()
                .contains("KZG verifier runtime code hash")
        );
    }

    #[test]
    fn durable_checkpoint_reorg_and_regression_are_rejected() {
        let original = checkpoint(10, 10);
        let advanced = checkpoint(11, 11);
        validate_deployment_checkpoint_window(&original, &advanced).unwrap();
        assert!(
            validate_deployment_checkpoint_window(&advanced, &original)
                .unwrap_err()
                .to_string()
                .contains("regressed")
        );
        let replacement = checkpoint(10, 12);
        assert!(
            validate_deployment_checkpoint_window(&original, &replacement)
                .unwrap_err()
                .to_string()
                .contains("replaced")
        );
        let changed_parent = L1FinalizedCheckpoint {
            parent_hash: word(0x77).parse().unwrap(),
            ..original
        };
        assert!(
            validate_deployment_checkpoint_window(&original, &changed_parent)
                .unwrap_err()
                .to_string()
                .contains("replaced")
        );

        let receipt = serde_json::json!({
            "transactionHash": word(0x01),
            "blockHash": word(0x02),
            "blockNumber": "0xa",
            "status": "0x1",
            "from": address(0x03),
            "to": address(0x04),
            "logs": [{"topics": [word(0x05)], "data": "0x"}],
        });
        assert!(stable_receipt_fields(&receipt, &receipt));
        let mut reorged = receipt.clone();
        reorged["blockHash"] = Value::String(word(0x06));
        assert!(!stable_receipt_fields(&receipt, &reorged));
        let mut rewritten_logs = receipt.clone();
        rewritten_logs["logs"][0]["data"] = Value::String("0x01".into());
        assert!(!stable_receipt_fields(&receipt, &rewritten_logs));
    }

    #[test]
    fn finalize_success_requires_exact_event_and_rejects_false_return_event() {
        let rollup = address(0x11);
        let state_root = word(0x22);
        let finalized_topic = keccak_hex(b"Finalized(uint256,bytes32)");
        let rejected_topic = keccak_hex(b"FinalizeRejected(uint256,bytes4)");
        let valid = finalization_receipt(
            1,
            vec![serde_json::json!({
                "address": rollup,
                "topics": [finalized_topic, topic_u64(7)],
                "data": state_root,
            })],
        );
        validate_finalization_events(&valid, &address(0x11), "7", &word(0x22)).unwrap();

        let rejected = finalization_receipt(
            1,
            vec![serde_json::json!({
                "address": address(0x11),
                "topics": [rejected_topic, topic_u64(7)],
                "data": format!("0x{}", "00".repeat(32)),
            })],
        );
        assert!(
            validate_finalization_events(&rejected, &address(0x11), "7", &word(0x22))
                .unwrap_err()
                .to_string()
                .contains("returned false")
        );
    }

    #[test]
    fn wrapper_finalize_allows_unrelated_events_but_rejects_ambiguous_exact_evidence() {
        let rollup = address(0x11);
        let finalized_topic = keccak_hex(b"Finalized(uint256,bytes32)");
        let exact = serde_json::json!({
            "address": rollup,
            "topics": [finalized_topic, topic_u64(7)],
            "data": word(0x22),
        });
        let unrelated = serde_json::json!({
            "address": address(0x11),
            "topics": [keccak_hex(b"Finalized(uint256,bytes32)"), topic_u64(8)],
            "data": word(0x99),
        });
        let wrapped = finalization_receipt(1, vec![unrelated, exact.clone()]);
        validate_finalization_events(&wrapped, &address(0x11), "7", &word(0x22)).unwrap();

        let duplicate = finalization_receipt(1, vec![exact.clone(), exact.clone()]);
        assert!(
            validate_finalization_events(&duplicate, &address(0x11), "7", &word(0x22)).is_err()
        );

        let mut wrong_root = exact.clone();
        wrong_root["data"] = Value::String(word(0x23));
        assert!(
            validate_finalization_events(
                &finalization_receipt(1, vec![wrong_root]),
                &address(0x11),
                "7",
                &word(0x22),
            )
            .unwrap_err()
            .to_string()
            .contains("different state root")
        );

        let mut removed_receipt = finalization_receipt(1, vec![exact]);
        removed_receipt["logs"][0]["removed"] = Value::Bool(true);
        assert!(
            validate_finalization_events(&removed_receipt, &address(0x11), "7", &word(0x22))
                .is_err()
        );

        let mut stitched_receipt = wrapped;
        stitched_receipt["logs"][1]["transactionHash"] = Value::String(word(0xff));
        assert!(
            validate_finalization_events(&stitched_receipt, &address(0x11), "7", &word(0x22))
                .unwrap_err()
                .to_string()
                .contains("differs from its receipt")
        );
    }

    #[test]
    fn permissionless_wrapper_outer_fields_are_not_semantic_authority() {
        let transaction_hash = word(0xa1);
        let block_hash = word(0xb1);
        let transaction = serde_json::json!({
            "hash": transaction_hash,
            "from": address(0x91),
            "to": address(0x99),
            "input": "0xdeadbeef",
            "value": format!("0x1{}", "00".repeat(16)),
            "nonce": "0x4",
            "blockHash": block_hash,
            "blockNumber": "0x64",
            "transactionIndex": "0x2",
        });
        let mut receipt = finalization_receipt(1, vec![]);
        receipt["to"] = Value::String(address(0x99));
        validate_semantic_transaction(&transaction, &receipt, &word(0xa1), &word(0xb1), 100)
            .unwrap();

        let mut mismatched = transaction;
        mismatched["to"] = Value::String(address(0x98));
        assert!(
            validate_semantic_transaction(&mismatched, &receipt, &word(0xa1), &word(0xb1), 100,)
                .is_err()
        );
    }

    #[test]
    fn submission_tuple_binds_submitter_post_block_finalized_flag_and_root() {
        let mut encoded = vec![0u8; 160];
        encoded[..32].fill(0x41);
        encoded[44..64].fill(0x52);
        encoded[95] = 1;
        encoded[120..128].copy_from_slice(&77u64.to_be_bytes());
        encoded[128..].fill(0x63);
        let observed = decode_submission(&format!("0x{}", hex::encode(&encoded))).unwrap();
        validate_submission_readback(&observed, &address(0x52), 77, &word(0x63)).unwrap();

        let mut wrong = observed.clone();
        wrong.submitter = address(0x53);
        assert!(validate_submission_readback(&wrong, &address(0x52), 77, &word(0x63)).is_err());
        wrong = observed.clone();
        wrong.finalized = false;
        assert!(validate_submission_readback(&wrong, &address(0x52), 77, &word(0x63)).is_err());
        wrong = observed.clone();
        wrong.submitted_at_block = 78;
        assert!(validate_submission_readback(&wrong, &address(0x52), 77, &word(0x63)).is_err());
        wrong = observed.clone();
        wrong.state_root = word(0x64);
        assert!(validate_submission_readback(&wrong, &address(0x52), 77, &word(0x63)).is_err());
        wrong = observed;
        wrong.commitment = word(0x00);
        assert!(validate_submission_readback(&wrong, &address(0x52), 77, &word(0x63)).is_err());

        let mut noncanonical = encoded;
        noncanonical[64] = 1;
        assert!(decode_submission(&format!("0x{}", hex::encode(&noncanonical))).is_err());
    }

    #[test]
    fn final_getter_window_rejects_same_height_head_and_receipt_substitution() {
        let stored = checkpoint(100, 0x64);
        let advanced = checkpoint(101, 0x65);
        validate_finalization_checkpoint_sequence(
            &stored,
            &advanced,
            100,
            word(0x64).parse().unwrap(),
        )
        .unwrap();

        let replacement = checkpoint(100, 0x66);
        assert!(
            validate_finalization_checkpoint_sequence(
                &stored,
                &replacement,
                100,
                word(0x64).parse().unwrap(),
            )
            .is_err()
        );
        assert!(
            validate_finalization_checkpoint_sequence(
                &stored,
                &stored,
                100,
                word(0x67).parse().unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn superseded_finalize_accepts_only_revert_or_exact_rejection() {
        let rejected = finalization_receipt(
            1,
            vec![serde_json::json!({
                "address": address(0x11),
                "topics": [keccak_hex(b"FinalizeRejected(uint256,bytes4)"), topic_u64(7)],
                "data": format!("0x{}", "00".repeat(32)),
            })],
        );
        validate_superseded_finalize_receipt(&rejected, &address(0x11), "7", &word(0x22)).unwrap();
        validate_superseded_finalize_receipt(
            &finalization_receipt(0, vec![]),
            &address(0x11),
            "7",
            &word(0x22),
        )
        .unwrap();
        assert!(
            validate_superseded_finalize_receipt(
                &finalization_receipt(1, vec![]),
                &address(0x11),
                "7",
                &word(0x22),
            )
            .is_err()
        );
    }

    #[test]
    fn attestation_event_binds_rollup_submission_commitment_and_payload() {
        let kzg = address(0x11);
        let rollup = address(0x22);
        let commitment = word(0x33);
        let proof_hash = word(0x44);
        let topic0 =
            keccak_hex(b"ProofDataAttested(address,uint256,bytes32,bytes32,bytes32,uint32)");
        let mut data = vec![0u8; 96];
        data[..32].copy_from_slice(&proof_attestation_digest(&proof_hash, 130_592).unwrap());
        data[32..64].copy_from_slice(&hex::decode(proof_hash.trim_start_matches("0x")).unwrap());
        data[64..92].fill(0);
        data[92..96].copy_from_slice(&130_592u32.to_be_bytes());
        let receipt = serde_json::json!({
            "logs": [{
                "address": kzg,
                "topics": [
                    topic0,
                    format!("0x{}{}", "00".repeat(12), rollup.trim_start_matches("0x")),
                    topic_u64(9),
                    commitment,
                ],
                "data": format!("0x{}", hex::encode(data)),
            }]
        });
        validate_attestation_event(
            &receipt,
            &address(0x11),
            &address(0x22),
            "9",
            &word(0x33),
            &word(0x44),
            130_592,
        )
        .unwrap();
        assert!(
            validate_attestation_event(
                &receipt,
                &address(0x11),
                &address(0x22),
                "10",
                &word(0x33),
                &word(0x44),
                130_592,
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_json_matches_api_recursive_key_sorting() {
        let left = serde_json::json!({"z": [{"b": 2, "a": 1}], "a": "x"});
        let right = serde_json::json!({"a": "x", "z": [{"a": 1, "b": 2}]});
        assert_eq!(canonical_json(&left), canonical_json(&right));
        assert_eq!(
            Sha256::digest(canonical_json(&left).as_bytes()),
            Sha256::digest(canonical_json(&right).as_bytes())
        );
    }
}

#[cfg(unix)]
impl Drop for JournalLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(not(unix))]
struct JournalLock;

#[cfg(not(unix))]
impl JournalLock {
    fn acquire(_journal_path: &Path) -> Result<Self> {
        Err(PublicValidityPublisherError::Configuration(
            "public validity publisher requires an OS advisory file lock".into(),
        ))
    }
}
