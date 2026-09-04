//! Crash-safe public-L1 publisher for terminal channel backing.
//!
//! This module is intentionally separate from the proof producer. It consumes only the public
//! `full_close_funding_payout.json` artifact and the validity acknowledgement that made its
//! producer anchor authoritative. For each nonempty asset lane it durably performs one atomic
//! proof materialization through the pinned `CloseFundingMaterializer`, followed by the Manager's
//! amount-scoped pull for each funded token. Every signed transaction is decoded, compared with
//! its pinned chain/target/value/calldata, and fsynced before broadcast.

#![cfg(not(target_arch = "wasm32"))]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr as _,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::{fd::AsRawFd as _, unix::fs::OpenOptionsExt as _, unix::fs::PermissionsExt as _};

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    circuits::withdraw::withdrawal_circuit::WithdrawalProofPublicInputs,
    close_funding::close_funding_aux_data,
    common::{
        channel::token_funds_digest, channel_id::ChannelId, u63::BlockNumber,
        withdrawal::Withdrawal,
    },
    constants::MAX_CHANNEL_TOKENS,
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    l1_finality::{ANVIL_CHAIN_ID, L1FinalitySource, L1FinalizedCheckpoint},
    l1_signer_reservation::{self, SignerReservation},
    partial_withdrawal_payout::PartialWithdrawalLane,
    wallet_core::partial_withdrawal_auth_digest,
};

const JOURNAL_VERSION: u32 = 3;
const ENVELOPE_SCHEMA_VERSION: u32 = 2;
const MANIFEST_SCHEMA_VERSION: u32 = 2;
const MAX_ENVELOPE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ACK_BYTES: u64 = 32 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 96 * 1024 * 1024;
const MAX_RAW_TRANSACTION_CHARS: usize = 64 * 1024 * 1024;
const MAX_RPC_JSON_BYTES: usize = 32 * 1024 * 1024;
const MAX_CALLDATA_CHARS: usize = 64 * 1024 * 1024;
/// Keep `eth_getLogs` requests inside the conservative range accepted by common public RPCs.
const EVENT_LOG_BLOCK_SPAN: u64 = 10_000;
const ANVIL_PUBLIC_DEV_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PULL_NATIVE_SIGNATURE: &str = "pullChannelFunds()";
const PULL_ERC20_SIGNATURE: &str = "pullChannelTokenFunds(uint32)";
const ROLLUP_PULL_NATIVE_SIGNATURE: &str = "withdraw(uint256)";
const ROLLUP_PULL_ERC20_SIGNATURE: &str = "withdrawToken(uint32,uint256)";
// Release MLE-proof-v2 selectors from `forge inspect CloseFundingMaterializer methodIdentifiers`.
// Keeping these in the binary makes both lanes manifest-authoritative even when an artifact uses
// only one lane; the generated calldata is checked against the same values below.
const MATERIALIZE_NATIVE_SELECTOR: &str = "0x1361d7b3";
const MATERIALIZE_ERC20_SELECTOR: &str = "0x70718fa0";
const MATERIALIZED_EVENT_SIGNATURE: &str =
    "CloseFundingMaterialized(address,uint8,bytes32,bytes32)";
static PRIVATE_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum CloseFundingPublisherError {
    #[error("invalid close-funding publisher configuration: {0}")]
    Configuration(String),
    #[error("invalid close-funding artifact: {0}")]
    Artifact(String),
    #[error("close-funding publisher conflict: {0}")]
    Conflict(String),
    #[error("close-funding journal failure: {0}")]
    Journal(String),
    #[error("L1 command failed: {0}")]
    Command(String),
    #[error("L1 evidence rejected: {0}")]
    Evidence(String),
    #[error("L1 finality timeout: {0}")]
    Timeout(String),
}

type Result<T> = std::result::Result<T, CloseFundingPublisherError>;

#[derive(Clone, Debug)]
pub struct CloseFundingPublisherConfig {
    pub payout_envelope_path: PathBuf,
    /// The durable `close_funding_validity_acknowledgement.json` named by the payout envelope.
    pub validity_acknowledgement_path: PathBuf,
    /// Release-reviewed chain, runtime-code, token-code, proof ABI, and selector pins.
    pub deployment_manifest_path: PathBuf,
    /// Independently authenticated SHA-256 of the exact manifest bytes, not merely its path.
    pub deployment_manifest_sha256: String,
    /// Private 0600 WAL. The identical path must be reused after every crash/restart.
    pub journal_path: PathBuf,
    /// Canonical private root shared by every process which uses this signer.
    pub lock_root: PathBuf,
    pub rpc_url: String,
    /// Foundry encrypted-keystore account name. This is never raw key material.
    pub account: Option<String>,
    pub finality_timeout: Duration,
    /// Development-only escape; accepted only when the RPC reports chain id 31337.
    pub allow_unfinalized_devnet: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseFundingPublication {
    pub schema_version: u32,
    pub chain_id: u64,
    pub channel_id: u32,
    pub rollup: String,
    pub manager: String,
    pub materializer: String,
    pub payout_artifact_hash: String,
    pub validity_acknowledgement_hash: String,
    pub binding_digest: String,
    pub transactions: Vec<String>,
    pub finalized_checkpoint: L1FinalizedCheckpoint,
    /// Always false here. A real public-chain E2E is an operator/runbook claim, not something a
    /// unit-tested publisher can infer merely from having exercised its production code path.
    pub public_e2e_attested: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayoutEnvelope {
    schema_version: u32,
    channel_id: u32,
    chain_id: u64,
    rollup: String,
    manager: String,
    verifier: String,
    proposal_hash: String,
    producer_request_id: String,
    validity_acknowledgement_hash: String,
    withdrawal_prover: String,
    artifact_hash: String,
    artifacts: PayoutArtifacts,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayoutArtifacts {
    plan_digest: String,
    funding_aux_data: String,
    lanes: Vec<PayoutLane>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayoutLane {
    lane: PartialWithdrawalLane,
    withdrawals: Vec<PayoutWithdrawal>,
    withdrawal_prover: String,
    payout_json: String,
    withdrawal_mle_json: String,
    producer_anchor: PayoutAnchor,
    metrics: PayoutMetrics,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayoutWithdrawal {
    recipient: String,
    token_index: u32,
    amount: U256,
    nullifier: String,
    aux_data: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayoutAnchor {
    generation: u64,
    entry_hash: String,
    block_number: u64,
    timestamp: u64,
    extended_state_commitment: String,
    bp_sig_chain: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayoutMetrics {
    single_withdrawal_millis: u64,
    withdrawal_chain_millis: u64,
    withdrawal_final_millis: u64,
    wrap_mle_millis: u64,
    single_withdrawal_proof_bytes: usize,
    withdrawal_chain_proof_bytes: usize,
    withdrawal_final_proof_bytes: usize,
    mle_json_bytes: usize,
    peak_rss_bytes: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayoutJson {
    withdrawals: Vec<PayoutJsonWithdrawal>,
    withdrawal_prover: String,
    block_number: u64,
    ext_commitment: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayoutJsonWithdrawal {
    recipient: String,
    token_index: u32,
    amount: U256,
    nullifier: String,
    aux_data: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TokenDeployment {
    token_index: u32,
    token: String,
    runtime_code_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeploymentManifest {
    schema_version: u32,
    chain_id: u64,
    rollup: String,
    rollup_runtime_code_hash: String,
    manager: String,
    /// Release-reviewed inclusive lower bound for complete semantic-event discovery. This must be
    /// at or before the Rollup, Manager, and materializer deployments; using a recent convenience
    /// block can hide a permissionlessly completed action and is therefore not accepted
    /// operationally.
    event_scan_start_block: u64,
    manager_runtime_code_hash: String,
    materializer: String,
    materializer_runtime_code_hash: String,
    verifier: String,
    verifier_runtime_code_hash: String,
    mle_verifier: String,
    mle_verifier_runtime_code_hash: String,
    mle_proof_abi_version: u8,
    mle_protocol_version: u32,
    mle_constituent_width: u32,
    materialize_native_selector: String,
    materialize_erc20_selector: String,
    pull_channel_funds_selector: String,
    pull_channel_token_funds_selector: String,
    rollup_withdraw_exact_selector: String,
    rollup_withdraw_token_exact_selector: String,
    tokens: Vec<TokenDeployment>,
}

#[derive(Clone, Debug)]
struct CheckedManifest {
    value: DeploymentManifest,
    hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenPlan {
    token_index: u32,
    amount: String,
    nullifier: String,
    auth_digest: String,
    lane: PartialWithdrawalLane,
}

#[derive(Clone, Debug)]
struct PreparedLane {
    lane: PartialWithdrawalLane,
    withdrawals: Vec<Withdrawal>,
    calldata: String,
    calldata_hash: String,
}

#[derive(Clone, Debug)]
struct PreparedPayout {
    envelope: PayoutEnvelope,
    anchor: PayoutAnchor,
    funding_aux_data: Bytes32,
    token_plans: BTreeMap<u32, TokenPlan>,
    lanes: Vec<PreparedLane>,
    acknowledgement: Value,
    acknowledgement_checkpoint: L1FinalizedCheckpoint,
    manifest: CheckedManifest,
    binding: PublicationBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicationBinding {
    schema_version: u32,
    chain_id: u64,
    channel_id: u32,
    rollup: String,
    manager: String,
    materializer: String,
    verifier: String,
    mle_verifier: String,
    withdrawal_prover: String,
    proposal_hash: String,
    producer_request_id: String,
    payout_artifact_hash: String,
    validity_acknowledgement_hash: String,
    plan_digest: String,
    funding_aux_data: String,
    producer_anchor: PayoutAnchor,
    deployment_manifest_hash: String,
    token_plans: Vec<TokenPlan>,
    native_calldata_hash: Option<String>,
    erc20_calldata_hash: Option<String>,
    binding_digest: String,
}

fn normalize_hex(
    value: &str,
    byte_length: usize,
    what: &str,
) -> std::result::Result<String, String> {
    let value = value.trim();
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| format!("{what} must start with 0x"))?;
    if body.len() != byte_length * 2 || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{what} must contain exactly {byte_length} bytes"));
    }
    Ok(format!("0x{}", body.to_ascii_lowercase()))
}

fn decode_hex(
    value: &str,
    byte_length: Option<usize>,
    what: &str,
) -> std::result::Result<Vec<u8>, String> {
    let normalized = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .ok_or_else(|| format!("{what} must start with 0x"))?;
    if normalized.len() % 2 != 0 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{what} is not canonical hex"));
    }
    if byte_length.is_some_and(|expected| normalized.len() != expected * 2) {
        return Err(format!("{what} has the wrong byte length"));
    }
    hex::decode(normalized).map_err(|error| format!("decode {what}: {error}"))
}

fn same_hex(left: &str, right: &str) -> bool {
    left.trim_start_matches("0x")
        .trim_start_matches("0X")
        .eq_ignore_ascii_case(right.trim_start_matches("0x").trim_start_matches("0X"))
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak_hash::keccak(bytes).0))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn validate_manifest_sha256(bytes: &[u8], expected: &str) -> Result<String> {
    let expected = normalize_hex(expected, 32, "deployment manifest SHA-256")
        .map_err(CloseFundingPublisherError::Configuration)?;
    let actual = sha256_hex(bytes);
    if !same_hex(&actual, &expected) {
        return Err(CloseFundingPublisherError::Configuration(
            "deployment manifest bytes differ from the independently configured SHA-256 pin".into(),
        ));
    }
    Ok(actual)
}

fn selector(signature: &str) -> String {
    let digest = keccak_hash::keccak(signature.as_bytes()).0;
    format!("0x{}", hex::encode(&digest[..4]))
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.to_string(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|key| format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("map key serialization cannot fail"),
                        canonical_json(&values[key])
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn stable_request_id(kind: &str, value: &Value) -> String {
    let digest = Sha256::digest(canonical_json(value).as_bytes());
    format!("{kind}:{}", hex::encode(digest))
}

fn require_nonzero_hex(
    value: &str,
    bytes: usize,
    what: &str,
) -> std::result::Result<String, String> {
    let value = normalize_hex(value, bytes, what)?;
    if value[2..].bytes().all(|byte| byte == b'0') {
        return Err(format!("{what} must be nonzero"));
    }
    Ok(value)
}

fn parse_address(value: &str, what: &str) -> std::result::Result<Address, String> {
    let value = require_nonzero_hex(value, 20, what)?;
    Address::from_str(&value).map_err(|error| format!("parse {what}: {error}"))
}

fn parse_bytes32(value: &str, what: &str) -> std::result::Result<Bytes32, String> {
    let value = normalize_hex(value, 32, what)?;
    Bytes32::from_str(&value).map_err(|error| format!("parse {what}: {error}"))
}

fn value_u64(value: &Value, what: &str) -> std::result::Result<u64, String> {
    match value {
        Value::String(value) => quantity_u64(value, what),
        Value::Number(value) => value.as_u64().ok_or_else(|| format!("{what} is not u64")),
        _ => Err(format!("{what} is not an unsigned quantity")),
    }
}

fn quantity_biguint(value: &str, what: &str) -> std::result::Result<BigUint, String> {
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
    u64::try_from(quantity_biguint(value, what)?).map_err(|_| format!("{what} does not fit u64"))
}

fn exact_object_keys(value: &Value, keys: &[&str], what: &str) -> std::result::Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{what} must be an object"))?;
    let expected = keys.iter().copied().collect::<BTreeSet<_>>();
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{what} fields differ: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn checked_manifest(bytes: &[u8], envelope: &PayoutEnvelope) -> Result<CheckedManifest> {
    let raw: Value = serde_json::from_slice(bytes).map_err(|error| {
        CloseFundingPublisherError::Configuration(format!("parse deployment manifest: {error}"))
    })?;
    let mut manifest: DeploymentManifest =
        serde_json::from_value(raw.clone()).map_err(|error| {
            CloseFundingPublisherError::Configuration(format!(
                "deployment manifest schema is not exact: {error}"
            ))
        })?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION
        || manifest.chain_id != envelope.chain_id
        || !same_hex(&manifest.rollup, &envelope.rollup)
        || !same_hex(&manifest.manager, &envelope.manager)
        || !same_hex(&manifest.verifier, &envelope.verifier)
    {
        return Err(CloseFundingPublisherError::Configuration(
            "deployment manifest schema/chain/rollup/manager/verifier differs from payout envelope"
                .into(),
        ));
    }
    // The current FixtureLib/MleVerifier tuple is the release v2 ABI. Accepting an operator label
    // for another layout while compiling calldata against v2 would make the manifest meaningless.
    if manifest.mle_proof_abi_version != 2 {
        return Err(CloseFundingPublisherError::Configuration(
            "close-funding publisher supports only the current MLE proof ABI version 2".into(),
        ));
    }
    if manifest.mle_protocol_version == 0 || manifest.mle_constituent_width == 0 {
        return Err(CloseFundingPublisherError::Configuration(
            "MLE protocol version and constituent width must be nonzero".into(),
        ));
    }

    for (field, bytes, label) in [
        (&mut manifest.rollup, 20, "manifest rollup"),
        (&mut manifest.manager, 20, "manifest manager"),
        (&mut manifest.materializer, 20, "manifest materializer"),
        (&mut manifest.verifier, 20, "manifest verifier"),
        (&mut manifest.mle_verifier, 20, "manifest MLE verifier"),
        (
            &mut manifest.rollup_runtime_code_hash,
            32,
            "rollup runtime code hash",
        ),
        (
            &mut manifest.manager_runtime_code_hash,
            32,
            "manager runtime code hash",
        ),
        (
            &mut manifest.materializer_runtime_code_hash,
            32,
            "materializer runtime code hash",
        ),
        (
            &mut manifest.verifier_runtime_code_hash,
            32,
            "verifier runtime code hash",
        ),
        (
            &mut manifest.mle_verifier_runtime_code_hash,
            32,
            "MLE verifier runtime code hash",
        ),
        (
            &mut manifest.materialize_native_selector,
            4,
            "materializeNative selector",
        ),
        (
            &mut manifest.materialize_erc20_selector,
            4,
            "materializeERC20 selector",
        ),
        (
            &mut manifest.pull_channel_funds_selector,
            4,
            "pullChannelFunds selector",
        ),
        (
            &mut manifest.pull_channel_token_funds_selector,
            4,
            "pullChannelTokenFunds selector",
        ),
        (
            &mut manifest.rollup_withdraw_exact_selector,
            4,
            "Rollup exact native pull selector",
        ),
        (
            &mut manifest.rollup_withdraw_token_exact_selector,
            4,
            "Rollup exact token pull selector",
        ),
    ] {
        *field = require_nonzero_hex(field, bytes, label)
            .map_err(CloseFundingPublisherError::Configuration)?;
    }
    let deployment_addresses = [
        &manifest.rollup,
        &manifest.manager,
        &manifest.materializer,
        &manifest.verifier,
        &manifest.mle_verifier,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if deployment_addresses.len() != 5 {
        return Err(CloseFundingPublisherError::Configuration(
            "rollup, manager, materializer, verifier, and MLE verifier addresses must be distinct"
                .into(),
        ));
    }
    for (actual, expected, label) in [
        (
            &manifest.materialize_native_selector,
            MATERIALIZE_NATIVE_SELECTOR.to_owned(),
            "materializeNative(MleProof-v2)",
        ),
        (
            &manifest.materialize_erc20_selector,
            MATERIALIZE_ERC20_SELECTOR.to_owned(),
            "materializeERC20(MleProof-v2)",
        ),
        (
            &manifest.pull_channel_funds_selector,
            selector(PULL_NATIVE_SIGNATURE),
            PULL_NATIVE_SIGNATURE,
        ),
        (
            &manifest.pull_channel_token_funds_selector,
            selector(PULL_ERC20_SIGNATURE),
            PULL_ERC20_SIGNATURE,
        ),
        (
            &manifest.rollup_withdraw_exact_selector,
            selector(ROLLUP_PULL_NATIVE_SIGNATURE),
            ROLLUP_PULL_NATIVE_SIGNATURE,
        ),
        (
            &manifest.rollup_withdraw_token_exact_selector,
            selector(ROLLUP_PULL_ERC20_SIGNATURE),
            ROLLUP_PULL_ERC20_SIGNATURE,
        ),
    ] {
        if !same_hex(actual, &expected) {
            return Err(CloseFundingPublisherError::Configuration(format!(
                "manifest selector for {label} is {actual}, expected {expected}"
            )));
        }
    }
    let mut indices = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    for token in &mut manifest.tokens {
        if token.token_index == 0 || !indices.insert(token.token_index) {
            return Err(CloseFundingPublisherError::Configuration(
                "manifest ERC-20 token indices must be nonzero and unique".into(),
            ));
        }
        token.token = require_nonzero_hex(&token.token, 20, "manifest token address")
            .map_err(CloseFundingPublisherError::Configuration)?;
        token.runtime_code_hash = require_nonzero_hex(
            &token.runtime_code_hash,
            32,
            "manifest token runtime code hash",
        )
        .map_err(CloseFundingPublisherError::Configuration)?;
        if !addresses.insert(token.token.clone()) {
            return Err(CloseFundingPublisherError::Configuration(
                "manifest maps multiple indices to one token address".into(),
            ));
        }
    }
    Ok(CheckedManifest {
        value: manifest,
        hash: sha256_hex(bytes),
    })
}

fn normalized_anchor(
    mut anchor: PayoutAnchor,
    what: &str,
) -> std::result::Result<PayoutAnchor, String> {
    anchor.entry_hash = require_nonzero_hex(&anchor.entry_hash, 32, &format!("{what} entry hash"))?;
    anchor.extended_state_commitment = require_nonzero_hex(
        &anchor.extended_state_commitment,
        32,
        &format!("{what} extended state commitment"),
    )?;
    anchor.bp_sig_chain = require_nonzero_hex(
        &anchor.bp_sig_chain,
        32,
        &format!("{what} BP signature chain"),
    )?;
    if anchor.generation == 0 || anchor.block_number == 0 || anchor.timestamp == 0 {
        return Err(format!(
            "{what} must be a non-genesis production anchor with a nonzero timestamp"
        ));
    }
    Ok(anchor)
}

fn strict_anchor_from_value(
    value: &Value,
    what: &str,
) -> std::result::Result<PayoutAnchor, String> {
    exact_object_keys(
        value,
        &[
            "generation",
            "entryHash",
            "blockNumber",
            "timestamp",
            "extendedStateCommitment",
            "bpSigChain",
        ],
        what,
    )?;
    let anchor: PayoutAnchor =
        serde_json::from_value(value.clone()).map_err(|error| format!("parse {what}: {error}"))?;
    normalized_anchor(anchor, what)
}

fn parse_mle_public_inputs(
    mle_json: &str,
    manifest: &DeploymentManifest,
    expected: &WithdrawalProofPublicInputs,
) -> std::result::Result<(), String> {
    let mle: Value = serde_json::from_str(mle_json)
        .map_err(|error| format!("withdrawal MLE JSON is invalid: {error}"))?;
    let object = mle
        .as_object()
        .ok_or_else(|| "withdrawal MLE JSON must be an object".to_string())?;
    let protocol = object
        .get("protocolVersion")
        .ok_or_else(|| "withdrawal MLE JSON lacks protocolVersion".to_string())?;
    let width = object
        .get("constituentWidth")
        .ok_or_else(|| "withdrawal MLE JSON lacks constituentWidth".to_string())?;
    if value_u64(protocol, "MLE protocolVersion")? != u64::from(manifest.mle_protocol_version)
        || value_u64(width, "MLE constituentWidth")? != u64::from(manifest.mle_constituent_width)
    {
        return Err("withdrawal MLE protocol/constituent schema differs from manifest".into());
    }
    let inputs = object
        .get("publicInputs")
        .and_then(Value::as_array)
        .ok_or_else(|| "withdrawal MLE JSON lacks publicInputs array".to_string())?;
    if inputs.len() != 17 {
        return Err(format!(
            "withdrawal MLE publicInputs length is {}, expected 17",
            inputs.len()
        ));
    }
    let mut expected_values = expected
        .hash()
        .to_u32_vec()
        .into_iter()
        .map(u64::from)
        .collect::<Vec<_>>();
    expected_values.extend(
        expected
            .ext_public_state_commitment
            .to_u32_vec()
            .into_iter()
            .map(u64::from),
    );
    expected_values.push(expected.block_number.as_u64());
    for (index, (actual, expected)) in inputs.iter().zip(expected_values).enumerate() {
        if value_u64(actual, &format!("MLE publicInputs[{index}]"))? != expected {
            return Err(format!(
                "withdrawal MLE publicInputs[{index}] differs from payout leaf/anchor binding"
            ));
        }
    }
    Ok(())
}

fn parse_and_validate_payout(
    bytes: &[u8],
    manifest_bytes: &[u8],
) -> Result<(
    PayoutEnvelope,
    CheckedManifest,
    PayoutAnchor,
    Address,
    Bytes32,
    BTreeMap<u32, TokenPlan>,
    Vec<(PartialWithdrawalLane, Vec<Withdrawal>)>,
)> {
    let raw: Value = serde_json::from_slice(bytes).map_err(|error| {
        CloseFundingPublisherError::Artifact(format!("parse payout envelope: {error}"))
    })?;
    let raw_artifacts = raw.get("artifacts").ok_or_else(|| {
        CloseFundingPublisherError::Artifact("payout envelope lacks artifacts".into())
    })?;
    let mut envelope: PayoutEnvelope = serde_json::from_value(raw.clone()).map_err(|error| {
        CloseFundingPublisherError::Artifact(format!(
            "payout envelope schema is not exact: {error}"
        ))
    })?;
    if envelope.schema_version != ENVELOPE_SCHEMA_VERSION
        || envelope.channel_id == 0
        || envelope.chain_id == 0
    {
        return Err(CloseFundingPublisherError::Artifact(
            "payout schema, channel id, and chain id must be production values".into(),
        ));
    }
    let expected_artifact_hash = stable_request_id("close-funding-payout", raw_artifacts);
    if envelope.artifact_hash != expected_artifact_hash {
        return Err(CloseFundingPublisherError::Artifact(format!(
            "payout artifact hash mismatch: expected {expected_artifact_hash}"
        )));
    }
    envelope.rollup = require_nonzero_hex(&envelope.rollup, 20, "payout rollup")
        .map_err(CloseFundingPublisherError::Artifact)?;
    envelope.manager = require_nonzero_hex(&envelope.manager, 20, "payout manager")
        .map_err(CloseFundingPublisherError::Artifact)?;
    envelope.verifier = require_nonzero_hex(&envelope.verifier, 20, "payout verifier")
        .map_err(CloseFundingPublisherError::Artifact)?;
    envelope.withdrawal_prover =
        require_nonzero_hex(&envelope.withdrawal_prover, 20, "payout withdrawal prover")
            .map_err(CloseFundingPublisherError::Artifact)?;
    if envelope.proposal_hash.trim().is_empty()
        || envelope.producer_request_id.trim().is_empty()
        || !envelope
            .validity_acknowledgement_hash
            .starts_with("close-funding-validity-acknowledgement-v2:")
    {
        return Err(CloseFundingPublisherError::Artifact(
            "payout proposal/producer/validity acknowledgement identity is malformed".into(),
        ));
    }
    envelope.artifacts.plan_digest = require_nonzero_hex(
        &envelope.artifacts.plan_digest,
        32,
        "close-funding plan digest",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    envelope.artifacts.funding_aux_data = require_nonzero_hex(
        &envelope.artifacts.funding_aux_data,
        32,
        "close-funding aux data",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    let withdrawal_prover = parse_address(&envelope.withdrawal_prover, "withdrawal prover")
        .map_err(CloseFundingPublisherError::Artifact)?;
    let funding_aux_data = parse_bytes32(&envelope.artifacts.funding_aux_data, "funding aux data")
        .map_err(CloseFundingPublisherError::Artifact)?;
    let manager = parse_address(&envelope.manager, "manager")
        .map_err(CloseFundingPublisherError::Artifact)?;
    let manifest = checked_manifest(manifest_bytes, &envelope)?;

    if envelope.artifacts.lanes.is_empty() || envelope.artifacts.lanes.len() > 2 {
        return Err(CloseFundingPublisherError::Artifact(
            "payout must contain one or two asset-class lanes".into(),
        ));
    }
    let mut saw_native = false;
    let mut saw_erc20 = false;
    let mut common_anchor = None;
    let mut token_plans = BTreeMap::new();
    let mut nullifiers = BTreeSet::new();
    let mut validated_lanes = Vec::new();
    for (lane_index, lane) in envelope.artifacts.lanes.iter_mut().enumerate() {
        match lane.lane {
            PartialWithdrawalLane::Native if saw_native => {
                return Err(CloseFundingPublisherError::Artifact(
                    "payout contains duplicate native lanes".into(),
                ));
            }
            PartialWithdrawalLane::Native => saw_native = true,
            PartialWithdrawalLane::Erc20 if saw_erc20 => {
                return Err(CloseFundingPublisherError::Artifact(
                    "payout contains duplicate ERC-20 lanes".into(),
                ));
            }
            PartialWithdrawalLane::Erc20 => saw_erc20 = true,
        }
        if lane.withdrawals.is_empty() || lane.withdrawals.len() > MAX_CHANNEL_TOKENS {
            return Err(CloseFundingPublisherError::Artifact(format!(
                "payout lane {lane_index} has an invalid withdrawal count"
            )));
        }
        lane.withdrawal_prover = require_nonzero_hex(
            &lane.withdrawal_prover,
            20,
            &format!("lane {lane_index} withdrawal prover"),
        )
        .map_err(CloseFundingPublisherError::Artifact)?;
        if !same_hex(&lane.withdrawal_prover, &envelope.withdrawal_prover) {
            return Err(CloseFundingPublisherError::Artifact(format!(
                "lane {lane_index} withdrawal prover differs from envelope"
            )));
        }
        lane.producer_anchor = normalized_anchor(
            lane.producer_anchor.clone(),
            &format!("lane {lane_index} producer anchor"),
        )
        .map_err(CloseFundingPublisherError::Artifact)?;
        if let Some(anchor) = &common_anchor {
            if anchor != &lane.producer_anchor {
                return Err(CloseFundingPublisherError::Artifact(
                    "payout lanes name different producer anchors".into(),
                ));
            }
        } else {
            common_anchor = Some(lane.producer_anchor.clone());
        }
        if lane.metrics.mle_json_bytes != lane.withdrawal_mle_json.len()
            || lane.metrics.single_withdrawal_proof_bytes == 0
            || lane.metrics.withdrawal_chain_proof_bytes == 0
            || lane.metrics.withdrawal_final_proof_bytes == 0
        {
            return Err(CloseFundingPublisherError::Artifact(format!(
                "lane {lane_index} proof metrics do not describe its artifacts"
            )));
        }
        let payout: PayoutJson = serde_json::from_str(&lane.payout_json).map_err(|error| {
            CloseFundingPublisherError::Artifact(format!(
                "lane {lane_index} payout JSON schema is not exact: {error}"
            ))
        })?;
        if payout.withdrawals.len() != lane.withdrawals.len()
            || !same_hex(&payout.withdrawal_prover, &envelope.withdrawal_prover)
            || payout.block_number != lane.producer_anchor.block_number
            || !same_hex(
                &payout.ext_commitment,
                &lane.producer_anchor.extended_state_commitment,
            )
        {
            return Err(CloseFundingPublisherError::Artifact(format!(
                "lane {lane_index} payout JSON diverges from lane/prover/anchor"
            )));
        }
        let mut withdrawals = Vec::with_capacity(lane.withdrawals.len());
        let mut withdrawal_hash = Bytes32::default();
        for (withdrawal_index, (outer, inner)) in lane
            .withdrawals
            .iter_mut()
            .zip(&payout.withdrawals)
            .enumerate()
        {
            outer.recipient = require_nonzero_hex(
                &outer.recipient,
                20,
                &format!("lane {lane_index} withdrawal {withdrawal_index} recipient"),
            )
            .map_err(CloseFundingPublisherError::Artifact)?;
            outer.nullifier = require_nonzero_hex(
                &outer.nullifier,
                32,
                &format!("lane {lane_index} withdrawal {withdrawal_index} nullifier"),
            )
            .map_err(CloseFundingPublisherError::Artifact)?;
            outer.aux_data = require_nonzero_hex(
                &outer.aux_data,
                32,
                &format!("lane {lane_index} withdrawal {withdrawal_index} aux data"),
            )
            .map_err(CloseFundingPublisherError::Artifact)?;
            if outer.amount == U256::zero()
                || !same_hex(&outer.recipient, &envelope.manager)
                || !same_hex(&outer.aux_data, &envelope.artifacts.funding_aux_data)
                || outer.token_index != inner.token_index
                || outer.amount != inner.amount
                || !same_hex(&outer.recipient, &inner.recipient)
                || !same_hex(&outer.nullifier, &inner.nullifier)
                || !same_hex(&outer.aux_data, &inner.aux_data)
                || (lane.lane == PartialWithdrawalLane::Native && outer.token_index != 0)
                || (lane.lane == PartialWithdrawalLane::Erc20 && outer.token_index == 0)
            {
                return Err(CloseFundingPublisherError::Artifact(format!(
                    "lane {lane_index} withdrawal {withdrawal_index} diverges from exact terminal leaf/JSON"
                )));
            }
            if token_plans.contains_key(&outer.token_index)
                || !nullifiers.insert(outer.nullifier.clone())
            {
                return Err(CloseFundingPublisherError::Artifact(
                    "payout token indices and nullifiers must both be globally unique".into(),
                ));
            }
            let withdrawal = Withdrawal {
                recipient: manager,
                token_index: outer.token_index,
                amount: outer.amount,
                nullifier: parse_bytes32(&outer.nullifier, "withdrawal nullifier")
                    .map_err(CloseFundingPublisherError::Artifact)?,
                aux_data: funding_aux_data,
            };
            withdrawal_hash = withdrawal.hash_with_prev_hash(withdrawal_hash);
            let auth_digest = partial_withdrawal_auth_digest(&withdrawal).to_string();
            token_plans.insert(
                outer.token_index,
                TokenPlan {
                    token_index: outer.token_index,
                    amount: outer.amount.to_string(),
                    nullifier: outer.nullifier.clone(),
                    auth_digest,
                    lane: lane.lane,
                },
            );
            withdrawals.push(withdrawal);
        }
        let expected_pis = WithdrawalProofPublicInputs {
            withdrawal_hash,
            withdrawal_prover,
            ext_public_state_commitment: parse_bytes32(
                &lane.producer_anchor.extended_state_commitment,
                "producer anchor commitment",
            )
            .map_err(CloseFundingPublisherError::Artifact)?,
            block_number: BlockNumber::new(lane.producer_anchor.block_number).map_err(|error| {
                CloseFundingPublisherError::Artifact(format!(
                    "producer anchor block number is outside circuit range: {error}"
                ))
            })?,
        };
        parse_mle_public_inputs(&lane.withdrawal_mle_json, &manifest.value, &expected_pis)
            .map_err(CloseFundingPublisherError::Artifact)?;
        validated_lanes.push((lane.lane, withdrawals));
    }
    if token_plans.is_empty() || token_plans.len() > MAX_CHANNEL_TOKENS {
        return Err(CloseFundingPublisherError::Artifact(
            "payout token set is empty or exceeds the channel limit".into(),
        ));
    }
    let manifest_tokens = manifest
        .value
        .tokens
        .iter()
        .map(|token| token.token_index)
        .collect::<BTreeSet<_>>();
    let payout_tokens = token_plans
        .keys()
        .filter(|token| **token != 0)
        .copied()
        .collect::<BTreeSet<_>>();
    if manifest_tokens != payout_tokens {
        return Err(CloseFundingPublisherError::Configuration(format!(
            "manifest ERC-20 token set {manifest_tokens:?} differs from payout {payout_tokens:?}"
        )));
    }
    Ok((
        envelope,
        manifest,
        common_anchor.expect("nonempty lanes establish an anchor"),
        withdrawal_prover,
        funding_aux_data,
        token_plans,
        validated_lanes,
    ))
}

fn validate_acknowledgement(
    bytes: &[u8],
    envelope: &PayoutEnvelope,
    anchor: &PayoutAnchor,
) -> Result<(Value, L1FinalizedCheckpoint)> {
    let mut value: Value = serde_json::from_slice(bytes).map_err(|error| {
        CloseFundingPublisherError::Artifact(format!("parse validity acknowledgement: {error}"))
    })?;
    exact_object_keys(
        &value,
        &[
            "schemaVersion",
            "channelId",
            "chainId",
            "rollup",
            "manager",
            "verifier",
            "proposalHash",
            "producerRequestId",
            "acknowledgementRequestId",
            "candidateId",
            "transactionHash",
            "receipt",
            "artifactHash",
        ],
        "validity acknowledgement",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    let object = value.as_object_mut().expect("exact object check");
    let artifact_hash = object
        .remove("artifactHash")
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or_else(|| {
            CloseFundingPublisherError::Artifact(
                "validity acknowledgement artifactHash is not a string".into(),
            )
        })?;
    let expected_hash = stable_request_id(
        "close-funding-validity-acknowledgement-v2",
        &Value::Object(object.clone()),
    );
    object.insert("artifactHash".into(), Value::String(artifact_hash.clone()));
    if artifact_hash != expected_hash || artifact_hash != envelope.validity_acknowledgement_hash {
        return Err(CloseFundingPublisherError::Artifact(
            "validity acknowledgement hash differs from its content/payout envelope".into(),
        ));
    }
    let number = |field: &str| -> std::result::Result<u64, String> {
        value
            .get(field)
            .ok_or_else(|| format!("acknowledgement lacks {field}"))
            .and_then(|value| value_u64(value, field))
    };
    let string = |field: &str| -> std::result::Result<&str, String> {
        value
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("acknowledgement lacks string {field}"))
    };
    let acknowledgement_request_id =
        string("acknowledgementRequestId").map_err(CloseFundingPublisherError::Artifact)?;
    let candidate_id = require_nonzero_hex(
        string("candidateId").map_err(CloseFundingPublisherError::Artifact)?,
        32,
        "validity acknowledgement candidateId",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    let transaction_hash = require_nonzero_hex(
        string("transactionHash").map_err(CloseFundingPublisherError::Artifact)?,
        32,
        "validity acknowledgement transactionHash",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    let expected_request_id = stable_request_id(
        "close-funding-validity-ack-v2",
        &serde_json::json!({
            "channelId": envelope.channel_id,
            "proposalHash": envelope.proposal_hash,
            "producerRequestId": envelope.producer_request_id,
            "candidateId": candidate_id,
            "transactionHash": transaction_hash,
        }),
    );
    if acknowledgement_request_id != expected_request_id {
        return Err(CloseFundingPublisherError::Artifact(
            "validity acknowledgement request id differs from its exact candidate/transaction binding"
                .into(),
        ));
    }
    if number("schemaVersion").map_err(CloseFundingPublisherError::Artifact)?
        != u64::from(ENVELOPE_SCHEMA_VERSION)
        || number("channelId").map_err(CloseFundingPublisherError::Artifact)?
            != u64::from(envelope.channel_id)
        || number("chainId").map_err(CloseFundingPublisherError::Artifact)? != envelope.chain_id
        || !same_hex(
            string("rollup").map_err(CloseFundingPublisherError::Artifact)?,
            &envelope.rollup,
        )
        || !same_hex(
            string("manager").map_err(CloseFundingPublisherError::Artifact)?,
            &envelope.manager,
        )
        || !same_hex(
            string("verifier").map_err(CloseFundingPublisherError::Artifact)?,
            &envelope.verifier,
        )
        || string("proposalHash").map_err(CloseFundingPublisherError::Artifact)?
            != envelope.proposal_hash
        || string("producerRequestId").map_err(CloseFundingPublisherError::Artifact)?
            != envelope.producer_request_id
    {
        return Err(CloseFundingPublisherError::Artifact(
            "validity acknowledgement belongs to another chain/channel/deployment/terminal proposal"
                .into(),
        ));
    }
    let receipt = value.get("receipt").ok_or_else(|| {
        CloseFundingPublisherError::Artifact("validity acknowledgement lacks receipt".into())
    })?;
    exact_object_keys(
        receipt,
        &[
            "requestId",
            "candidateId",
            "producerAnchor",
            "finalizedBlockNumber",
            "finalExtendedStateCommitment",
            "committedProducerReceipt",
            "l1Acknowledgement",
        ],
        "validity acknowledgement receipt",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    let receipt_anchor = strict_anchor_from_value(
        receipt.get("producerAnchor").unwrap_or(&Value::Null),
        "acknowledgement producer anchor",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    if receipt
        .get("requestId")
        .and_then(Value::as_str)
        .is_none_or(|request| request != acknowledgement_request_id)
        || receipt
            .get("candidateId")
            .and_then(Value::as_str)
            .is_none_or(|candidate| !same_hex(candidate, &candidate_id))
    {
        return Err(CloseFundingPublisherError::Artifact(
            "validity receipt request/candidate identity differs from its acknowledgement".into(),
        ));
    }
    let committed = receipt.get("committedProducerReceipt").ok_or_else(|| {
        CloseFundingPublisherError::Artifact(
            "acknowledgement lacks committed producer receipt".into(),
        )
    })?;
    exact_object_keys(
        committed,
        &[
            "requestId",
            "generation",
            "entryHash",
            "blockNumber",
            "timestamp",
            "extendedStateCommitment",
            "bpSigChain",
        ],
        "committed producer receipt",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    let committed_object = committed.as_object().expect("exact object check");
    let mut committed_anchor_object = committed_object.clone();
    let committed_request = committed_anchor_object
        .remove("requestId")
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or_else(|| {
            CloseFundingPublisherError::Artifact(
                "committed producer receipt requestId is malformed".into(),
            )
        })?;
    let committed_anchor = strict_anchor_from_value(
        &Value::Object(committed_anchor_object),
        "committed producer receipt anchor",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    if receipt_anchor != *anchor
        || committed_anchor != *anchor
        || committed_request != envelope.producer_request_id
        || value_u64(
            receipt.get("finalizedBlockNumber").unwrap_or(&Value::Null),
            "acknowledgement finalizedBlockNumber",
        )
        .map_err(CloseFundingPublisherError::Artifact)?
            != anchor.block_number
        || !receipt
            .get("finalExtendedStateCommitment")
            .and_then(Value::as_str)
            .is_some_and(|root| same_hex(root, &anchor.extended_state_commitment))
    {
        return Err(CloseFundingPublisherError::Artifact(
            "validity acknowledgement does not finalize the exact payout producer anchor".into(),
        ));
    }
    let l1 = receipt.get("l1Acknowledgement").ok_or_else(|| {
        CloseFundingPublisherError::Artifact("validity receipt lacks L1 acknowledgement".into())
    })?;
    exact_object_keys(
        l1,
        &[
            "chainId",
            "transactionHash",
            "blockHash",
            "blockNumber",
            "finalExtendedStateCommitment",
            "finalizedCheckpoint",
        ],
        "L1 validity acknowledgement",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    let l1_object = l1.as_object().expect("exact object check");
    if value_u64(
        l1_object.get("chainId").unwrap_or(&Value::Null),
        "L1 acknowledgement chainId",
    )
    .map_err(CloseFundingPublisherError::Artifact)?
        != envelope.chain_id
        || !l1_object
            .get("transactionHash")
            .and_then(Value::as_str)
            .is_some_and(|hash| {
                value
                    .get("transactionHash")
                    .and_then(Value::as_str)
                    .is_some_and(|outer| same_hex(hash, outer))
            })
        || !l1_object
            .get("finalExtendedStateCommitment")
            .and_then(Value::as_str)
            .is_some_and(|root| same_hex(root, &anchor.extended_state_commitment))
    {
        return Err(CloseFundingPublisherError::Artifact(
            "L1 validity acknowledgement differs from exact transaction/chain/anchor".into(),
        ));
    }
    let checkpoint: L1FinalizedCheckpoint = serde_json::from_value(
        l1_object
            .get("finalizedCheckpoint")
            .cloned()
            .ok_or_else(|| {
                CloseFundingPublisherError::Artifact(
                    "L1 acknowledgement lacks finalized checkpoint".into(),
                )
            })?,
    )
    .map_err(|error| {
        CloseFundingPublisherError::Artifact(format!(
            "parse L1 acknowledgement checkpoint: {error}"
        ))
    })?;
    checkpoint
        .validate()
        .map_err(CloseFundingPublisherError::Artifact)?;
    let receipt_block = value_u64(
        l1_object.get("blockNumber").unwrap_or(&Value::Null),
        "L1 acknowledgement blockNumber",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    let receipt_hash = parse_bytes32(
        l1_object
            .get("blockHash")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "L1 acknowledgement block hash",
    )
    .map_err(CloseFundingPublisherError::Artifact)?;
    checkpoint
        .covers_receipt(receipt_block, receipt_hash)
        .map_err(CloseFundingPublisherError::Artifact)?;
    Ok((value, checkpoint))
}

fn inspect_regular_file(path: &Path, maximum: u64, private: bool) -> Result<Option<fs::Metadata>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CloseFundingPublisherError::Journal(format!(
                "inspect {}: {error}",
                path.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CloseFundingPublisherError::Journal(format!(
            "{} must be a regular non-symlink file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(CloseFundingPublisherError::Journal(format!(
            "{} exceeds {maximum} bytes",
            path.display()
        )));
    }
    #[cfg(unix)]
    if private && metadata.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            CloseFundingPublisherError::Journal(format!(
                "repair {} permissions to 0600: {error}",
                path.display()
            ))
        })?;
    }
    Ok(Some(metadata))
}

fn read_bounded(path: &Path, maximum: u64, what: &str, private: bool) -> Result<Vec<u8>> {
    inspect_regular_file(path, maximum, private)?.ok_or_else(|| {
        CloseFundingPublisherError::Configuration(format!(
            "{what} does not exist: {}",
            path.display()
        ))
    })?;
    let file = fs::File::open(path).map_err(|error| {
        CloseFundingPublisherError::Journal(format!("open {}: {error}", path.display()))
    })?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CloseFundingPublisherError::Journal(format!("read {}: {error}", path.display()))
        })?;
    if bytes.len() as u64 > maximum {
        return Err(CloseFundingPublisherError::Journal(format!(
            "{what} exceeds {maximum} bytes"
        )));
    }
    Ok(bytes)
}

fn ensure_private_directory(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(CloseFundingPublisherError::Configuration(format!(
            "private directory must be absolute: {}",
            path.display()
        )));
    }
    fs::create_dir_all(path).map_err(|error| {
        CloseFundingPublisherError::Journal(format!("create {}: {error}", path.display()))
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CloseFundingPublisherError::Journal(format!("inspect {}: {error}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CloseFundingPublisherError::Configuration(format!(
            "{} must be a non-symlink directory",
            path.display()
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            CloseFundingPublisherError::Journal(format!(
                "repair {} permissions to 0700: {error}",
                path.display()
            ))
        })?;
    }
    fs::canonicalize(path).map_err(|error| {
        CloseFundingPublisherError::Journal(format!("canonicalize {}: {error}", path.display()))
    })
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        CloseFundingPublisherError::Journal(format!("create {}: {error}", parent.display()))
    })?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            CloseFundingPublisherError::Journal(format!("{} has no UTF-8 filename", path.display()))
        })?;
    if let Some(metadata) = inspect_regular_file(path, u64::MAX, true)? {
        if metadata.file_type().is_symlink() {
            unreachable!("regular-file inspection rejects symlinks")
        }
    }
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
        CloseFundingPublisherError::Journal(format!(
            "create temporary {}: {error}",
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
        fs::File::open(parent)?.sync_all()
    })();
    if let Err(error) = write_result {
        return Err(CloseFundingPublisherError::Journal(format!(
            "durably replace {}: {error}; temporary retained at {}",
            path.display(),
            temporary.display()
        )));
    }
    Ok(())
}

fn ensure_exact_private_file(path: &Path, bytes: &[u8], what: &str) -> Result<()> {
    if inspect_regular_file(path, bytes.len() as u64 + 1, true)?.is_some() {
        let actual = read_bounded(path, bytes.len() as u64 + 1, what, true)?;
        if actual != bytes {
            return Err(CloseFundingPublisherError::Conflict(format!(
                "persisted {what} differs from exact payout artifact: {}",
                path.display()
            )));
        }
        return Ok(());
    }
    atomic_write_private(path, bytes)
}

fn checked_output(mut command: Command, what: &str, limit: usize) -> Result<String> {
    let output = command
        .output()
        .map_err(|error| CloseFundingPublisherError::Command(format!("start {what}: {error}")))?;
    if !output.status.success() {
        return Err(CloseFundingPublisherError::Command(format!(
            "{what} returned {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    if output.stdout.len() > limit {
        return Err(CloseFundingPublisherError::Command(format!(
            "{what} output exceeds {limit} bytes"
        )));
    }
    String::from_utf8(output.stdout).map_err(|error| {
        CloseFundingPublisherError::Command(format!("{what} output is not UTF-8: {error}"))
    })
}

fn materialize_lane_calldata(
    artifact_hash: &str,
    lane_index: usize,
    lane: &PayoutLane,
    manifest: &DeploymentManifest,
) -> Result<(String, String)> {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let artifact_component = artifact_hash
        .split_once(':')
        .map(|(_, digest)| digest)
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            CloseFundingPublisherError::Artifact(
                "payout artifact hash has no SHA-256 suffix".into(),
            )
        })?;
    let staging = repository
        .join("proof-da-output")
        .join("close-funding-publisher")
        .join(artifact_component);
    let staging = ensure_private_directory(&staging)?;
    let payout_path = staging.join(format!("lane-{lane_index}-payout.json"));
    let mle_path = staging.join(format!("lane-{lane_index}-mle.json"));
    let calldata_path = staging.join(format!("lane-{lane_index}-calldata.hex"));
    ensure_exact_private_file(
        &payout_path,
        lane.payout_json.as_bytes(),
        "lane payout JSON",
    )?;
    ensure_exact_private_file(
        &mle_path,
        lane.withdrawal_mle_json.as_bytes(),
        "lane withdrawal MLE JSON",
    )?;

    let contracts = repository.join("contracts");
    let lane_name = match lane.lane {
        PartialWithdrawalLane::Native => "native",
        PartialWithdrawalLane::Erc20 => "erc20",
    };
    let mut command = Command::new("forge");
    command
        .current_dir(&contracts)
        .args([
            "script",
            "script/MaterializeCloseFundingPayout.s.sol:MaterializeCloseFundingPayout",
            "--sig",
            "run()",
            "--silent",
        ])
        .env("CF_PAYOUT_PATH", &payout_path)
        .env("CF_MLE_PATH", &mle_path)
        .env("CF_CALLDATA_OUT", &calldata_path)
        .env("CF_WITHDRAWAL_COUNT", lane.withdrawals.len().to_string())
        .env("CF_LANE", lane_name)
        .env("CF_MANAGER", &manifest.manager);
    checked_output(
        command,
        "materialize close-funding proof calldata",
        1024 * 1024,
    )?;
    let calldata_bytes = read_bounded(
        &calldata_path,
        MAX_CALLDATA_CHARS as u64,
        "materialized proof calldata",
        true,
    )?;
    let calldata = String::from_utf8(calldata_bytes).map_err(|error| {
        CloseFundingPublisherError::Evidence(format!(
            "materialized proof calldata is not UTF-8: {error}"
        ))
    })?;
    let calldata = calldata.trim().to_ascii_lowercase();
    let decoded = decode_hex(&calldata, None, "materialized proof calldata")
        .map_err(CloseFundingPublisherError::Evidence)?;
    if decoded.len() < 4 || calldata.len() > MAX_CALLDATA_CHARS {
        return Err(CloseFundingPublisherError::Evidence(
            "materialized proof calldata is empty or oversized".into(),
        ));
    }
    let expected_selector = match lane.lane {
        PartialWithdrawalLane::Native => &manifest.materialize_native_selector,
        PartialWithdrawalLane::Erc20 => &manifest.materialize_erc20_selector,
    };
    if !same_hex(&calldata[..10], expected_selector) {
        return Err(CloseFundingPublisherError::Configuration(format!(
            "materialized {lane_name} selector {} differs from manifest {expected_selector}",
            &calldata[..10]
        )));
    }
    Ok((calldata, keccak_hex(&decoded)))
}

fn prepare_payout(config: &CloseFundingPublisherConfig) -> Result<PreparedPayout> {
    let envelope_bytes = read_bounded(
        &config.payout_envelope_path,
        MAX_ENVELOPE_BYTES,
        "close-funding payout envelope",
        false,
    )?;
    let manifest_bytes = read_bounded(
        &config.deployment_manifest_path,
        MAX_MANIFEST_BYTES,
        "close-funding deployment manifest",
        false,
    )?;
    validate_manifest_sha256(&manifest_bytes, &config.deployment_manifest_sha256)?;
    let (
        envelope,
        manifest,
        anchor,
        _withdrawal_prover,
        funding_aux_data,
        token_plans,
        validated_lanes,
    ) = parse_and_validate_payout(&envelope_bytes, &manifest_bytes)?;
    let acknowledgement_bytes = read_bounded(
        &config.validity_acknowledgement_path,
        MAX_ACK_BYTES,
        "terminal validity acknowledgement",
        false,
    )?;
    let (acknowledgement, acknowledgement_checkpoint) =
        validate_acknowledgement(&acknowledgement_bytes, &envelope, &anchor)?;

    let mut lanes = Vec::with_capacity(envelope.artifacts.lanes.len());
    for (index, (lane, (_, withdrawals))) in envelope
        .artifacts
        .lanes
        .iter()
        .zip(validated_lanes)
        .enumerate()
    {
        let (calldata, calldata_hash) =
            materialize_lane_calldata(&envelope.artifact_hash, index, lane, &manifest.value)?;
        lanes.push(PreparedLane {
            lane: lane.lane,
            withdrawals,
            calldata,
            calldata_hash,
        });
    }
    let native_calldata_hash = lanes
        .iter()
        .find(|lane| lane.lane == PartialWithdrawalLane::Native)
        .map(|lane| lane.calldata_hash.clone());
    let erc20_calldata_hash = lanes
        .iter()
        .find(|lane| lane.lane == PartialWithdrawalLane::Erc20)
        .map(|lane| lane.calldata_hash.clone());
    let mut binding = PublicationBinding {
        schema_version: 2,
        chain_id: envelope.chain_id,
        channel_id: envelope.channel_id,
        rollup: envelope.rollup.clone(),
        manager: envelope.manager.clone(),
        materializer: manifest.value.materializer.clone(),
        verifier: envelope.verifier.clone(),
        mle_verifier: manifest.value.mle_verifier.clone(),
        withdrawal_prover: envelope.withdrawal_prover.clone(),
        proposal_hash: envelope.proposal_hash.clone(),
        producer_request_id: envelope.producer_request_id.clone(),
        payout_artifact_hash: envelope.artifact_hash.clone(),
        validity_acknowledgement_hash: envelope.validity_acknowledgement_hash.clone(),
        plan_digest: envelope.artifacts.plan_digest.clone(),
        funding_aux_data: envelope.artifacts.funding_aux_data.clone(),
        producer_anchor: anchor.clone(),
        deployment_manifest_hash: manifest.hash.clone(),
        token_plans: token_plans.values().cloned().collect(),
        native_calldata_hash,
        erc20_calldata_hash,
        binding_digest: String::new(),
    };
    let binding_value = serde_json::to_value(&binding).map_err(|error| {
        CloseFundingPublisherError::Artifact(format!("serialize payout binding: {error}"))
    })?;
    binding.binding_digest =
        stable_request_id("close-funding-publication-binding-v2", &binding_value);
    Ok(PreparedPayout {
        envelope,
        anchor,
        funding_aux_data,
        token_plans,
        lanes,
        acknowledgement,
        acknowledgement_checkpoint,
        manifest,
        binding,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum PublicationAction {
    MaterializeNative,
    MaterializeErc20,
    PullNative,
    PullErc20 { token_index: u32 },
}

impl PublicationAction {
    fn id(&self) -> String {
        match self {
            Self::MaterializeNative => "materialize:native".into(),
            Self::MaterializeErc20 => "materialize:erc20".into(),
            Self::PullNative => "pull:0".into(),
            Self::PullErc20 { token_index } => format!("pull:{token_index}"),
        }
    }
}

#[derive(Clone, Debug)]
struct ActionSpec {
    action: PublicationAction,
    target: String,
    calldata: String,
    calldata_hash: String,
    token_indices: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinalizedReceipt {
    transaction_hash: String,
    block_hash: String,
    block_number: u64,
    finalized_checkpoint: L1FinalizedCheckpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawTransactionStep {
    action: PublicationAction,
    target: String,
    selector: String,
    calldata_hash: String,
    value: String,
    nonce: u64,
    raw_signed_transaction: String,
    transaction_hash: String,
    preflight_checkpoint: L1FinalizedCheckpoint,
    preflight_state_digest: String,
    confirmation: Option<StepConfirmation>,
    /// Canonical-finalized reverted receipt for a local raw transaction that lost a
    /// permissionless semantic race. This must be fsynced before its signer reservation is freed.
    #[serde(default)]
    superseded_confirmation: Option<FinalizedReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StepConfirmation {
    receipt: FinalizedReceipt,
    receipt_evidence_digest: String,
    post_state_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationJournal {
    version: u32,
    binding: PublicationBinding,
    signer: String,
    signer_lock_root: String,
    steps: BTreeMap<String, RawTransactionStep>,
    /// Exact protocol effects may be submitted by any account. These records contain no local raw
    /// transaction. They bind the expected semantic intent to a canonical finalized exact event
    /// and receipt-block getters; a relayer's outer target/calldata/value are deliberately not
    /// treated as authority.
    adopted_steps: BTreeMap<String, AdoptedActionStep>,
    completed: Option<CloseFundingPublication>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdoptedActionStep {
    action: PublicationAction,
    target: String,
    selector: String,
    calldata_hash: String,
    value: String,
    confirmation: StepConfirmation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenChainState {
    token_index: u32,
    cap: String,
    received: String,
    total_credited_out: String,
    authorization: bool,
    nullifier_used: bool,
    pending_rollup_credit: String,
    manager_asset_balance: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChainSnapshot {
    checkpoint: L1FinalizedCheckpoint,
    channel_status: u8,
    close_freeze_nonce: u64,
    anchor_finalized: bool,
    tokens: BTreeMap<u32, TokenChainState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResumeDecision {
    SignNew,
    ReplayExact,
    RevalidateConfirmed,
    RevalidateAdopted,
}

fn resume_decision(
    step: Option<&RawTransactionStep>,
    adopted: Option<&AdoptedActionStep>,
) -> ResumeDecision {
    match (step, adopted) {
        (_, Some(_)) => ResumeDecision::RevalidateAdopted,
        (None, None) => ResumeDecision::SignNew,
        (Some(step), None) if step.confirmation.is_none() => ResumeDecision::ReplayExact,
        (Some(_), None) => ResumeDecision::RevalidateConfirmed,
    }
}

fn journal_action_finalized(journal: &PublicationJournal, id: &str) -> bool {
    journal.adopted_steps.contains_key(id)
        || journal
            .steps
            .get(id)
            .is_some_and(|step| step.confirmation.is_some())
}

fn validate_journal_prerequisites(
    journal: &PublicationJournal,
    prepared: &PreparedPayout,
    spec: &ActionSpec,
) -> std::result::Result<(), String> {
    let mut required: BTreeSet<String> = BTreeSet::new();
    match spec.action {
        PublicationAction::MaterializeNative | PublicationAction::MaterializeErc20 => {}
        PublicationAction::PullNative | PublicationAction::PullErc20 { .. } => {
            for token_index in &spec.token_indices {
                let lane = prepared
                    .token_plans
                    .get(token_index)
                    .ok_or_else(|| format!("payout plan lacks token {token_index}"))?
                    .lane;
                required.insert(match lane {
                    PartialWithdrawalLane::Native => "materialize:native".into(),
                    PartialWithdrawalLane::Erc20 => "materialize:erc20".into(),
                });
            }
        }
    }
    let missing = required
        .into_iter()
        .filter(|id| !journal_action_finalized(journal, id))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "action {} lacks finalized exact prerequisites {missing:?}",
            spec.action.id()
        ));
    }
    Ok(())
}

fn encode_u32_word(value: u32) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[28..].copy_from_slice(&value.to_be_bytes());
    word
}

fn encode_pull_calldata(token_index: u32) -> String {
    if token_index == 0 {
        return selector(PULL_NATIVE_SIGNATURE);
    }
    let mut bytes = decode_hex(&selector(PULL_ERC20_SIGNATURE), Some(4), "pull selector")
        .expect("computed selector is canonical");
    bytes.extend_from_slice(&encode_u32_word(token_index));
    format!("0x{}", hex::encode(bytes))
}

fn action_specs(prepared: &PreparedPayout) -> Vec<ActionSpec> {
    let mut specs = Vec::new();
    let mut ordered_lanes = prepared.lanes.iter().collect::<Vec<_>>();
    ordered_lanes.sort_by_key(|lane| match lane.lane {
        PartialWithdrawalLane::Native => 0,
        PartialWithdrawalLane::Erc20 => 1,
    });
    for lane in ordered_lanes {
        let mut token_indices = lane
            .withdrawals
            .iter()
            .map(|withdrawal| withdrawal.token_index)
            .collect::<Vec<_>>();
        token_indices.sort_unstable();
        specs.push(ActionSpec {
            action: match lane.lane {
                PartialWithdrawalLane::Native => PublicationAction::MaterializeNative,
                PartialWithdrawalLane::Erc20 => PublicationAction::MaterializeErc20,
            },
            target: prepared.manifest.value.materializer.clone(),
            calldata: lane.calldata.clone(),
            calldata_hash: lane.calldata_hash.clone(),
            token_indices: token_indices.clone(),
        });
        for token_index in token_indices {
            let calldata = encode_pull_calldata(token_index);
            specs.push(ActionSpec {
                action: if token_index == 0 {
                    PublicationAction::PullNative
                } else {
                    PublicationAction::PullErc20 { token_index }
                },
                target: prepared.envelope.manager.clone(),
                calldata_hash: keccak_hex(
                    &decode_hex(&calldata, None, "pull calldata")
                        .expect("locally encoded calldata is canonical"),
                ),
                calldata,
                token_indices: vec![token_index],
            });
        }
    }
    specs
}

fn close_funding_signer_reservation(
    chain_id: u64,
    signer: &str,
    journal_path: &Path,
    binding: &PublicationBinding,
    spec: &ActionSpec,
) -> Result<SignerReservation> {
    let action_id = spec.action.id();
    let material = serde_json::json!({
        "schemaVersion": 1,
        "bindingDigest": binding.binding_digest,
        "actionId": action_id,
        "target": normalize_hex(&spec.target, 20, "reservation target")
            .map_err(CloseFundingPublisherError::Configuration)?,
        "calldataHash": normalize_hex(&spec.calldata_hash, 32, "reservation calldata hash")
            .map_err(CloseFundingPublisherError::Configuration)?,
        "value": "0",
    });
    let intent_hash = format!(
        "0x{}",
        hex::encode(Sha256::digest(canonical_json(&material).as_bytes()))
    );
    SignerReservation::new(
        chain_id,
        signer,
        "close-funding",
        journal_path,
        &spec.action.id(),
        &intent_hash,
    )
    .map_err(CloseFundingPublisherError::Configuration)
}

fn claim_signer_reservation(root: &Path, reservation: &SignerReservation) -> Result<()> {
    l1_signer_reservation::claim(root, reservation).map_err(|error| {
        CloseFundingPublisherError::Conflict(format!("signer reservation: {error}"))
    })
}

fn release_signer_reservation(root: &Path, reservation: &SignerReservation) -> Result<()> {
    l1_signer_reservation::release(root, reservation).map_err(|error| {
        CloseFundingPublisherError::Journal(format!("signer reservation: {error}"))
    })
}

fn release_exact_signer_reservation(root: &Path, reservation: &SignerReservation) -> Result<bool> {
    l1_signer_reservation::release_if_exact(root, reservation).map_err(|error| {
        CloseFundingPublisherError::Journal(format!("signer reservation: {error}"))
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
            Err(release_error) => Err(CloseFundingPublisherError::Journal(format!(
                "offline signing failed ({sign_error}); reservation release also failed ({release_error})"
            ))),
        },
    }
}

fn snapshot_digest(snapshot: &ChainSnapshot) -> Result<String> {
    let value = serde_json::to_value(snapshot).map_err(|error| {
        CloseFundingPublisherError::Evidence(format!("serialize chain snapshot: {error}"))
    })?;
    Ok(stable_request_id("close-funding-chain-snapshot-v1", &value))
}

fn assert_backing_invariant(state: &TokenChainState) -> std::result::Result<(), String> {
    let received = quantity_biguint(&state.received, "manager received funds")?;
    let credited = quantity_biguint(&state.total_credited_out, "manager total credited out")?;
    let balance = quantity_biguint(&state.manager_asset_balance, "manager asset balance")?;
    if credited > received {
        return Err(format!(
            "token {} credited-out value exceeds received backing",
            state.token_index
        ));
    }
    if balance < received - credited {
        return Err(format!(
            "token {} manager balance is below received-minus-credited backing",
            state.token_index
        ));
    }
    Ok(())
}

fn validate_preflight_action(
    spec: &ActionSpec,
    snapshot: &ChainSnapshot,
    prepared: &PreparedPayout,
) -> std::result::Result<(), String> {
    if snapshot.channel_status != 2 || !snapshot.anchor_finalized {
        return Err("manager is not Closed or payout proof anchor is not finalized".into());
    }
    for token_index in &spec.token_indices {
        let state = snapshot
            .tokens
            .get(token_index)
            .ok_or_else(|| format!("chain snapshot lacks token {token_index}"))?;
        let plan = prepared
            .token_plans
            .get(token_index)
            .ok_or_else(|| format!("payout plan lacks token {token_index}"))?;
        if quantity_biguint(&state.cap, "manager cap")?
            != quantity_biguint(&plan.amount, "payout amount")?
        {
            return Err(format!(
                "token {token_index} manager cap differs from payout"
            ));
        }
        assert_backing_invariant(state)?;
        match spec.action {
            PublicationAction::MaterializeNative | PublicationAction::MaterializeErc20 => {
                if state.received != "0" || state.authorization || state.nullifier_used {
                    return Err(format!(
                        "token {token_index} is not in pristine pre-materialization state; missing/sibling WAL"
                    ));
                }
            }
            PublicationAction::PullNative | PublicationAction::PullErc20 { .. } => {
                let pending =
                    quantity_biguint(&state.pending_rollup_credit, "pending Rollup credit")?;
                let amount = quantity_biguint(&plan.amount, "payout amount")?;
                if state.received != "0" || state.authorization || pending < amount {
                    return Err(format!(
                        "token {token_index} is not atomically materialized with enough pending credit for exact pull"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn cast_output(args: &[&str], what: &str, limit: usize) -> Result<String> {
    let mut command = Command::new("cast");
    command.args(args);
    checked_output(command, what, limit)
}

fn rpc_chain_id(rpc: &str) -> Result<u64> {
    let output = cast_output(&["chain-id", "--rpc-url", rpc], "read L1 chain id", 4096)?;
    quantity_u64(output.trim(), "L1 chain id").map_err(CloseFundingPublisherError::Evidence)
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
        CloseFundingPublisherError::Evidence(format!("parse L1 block {tag}: {error}"))
    })?;
    if !value.is_object() {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "L1 block {tag} is null or not an object"
        )));
    }
    Ok(value)
}

fn json_string<'a>(value: &'a Value, field: &str) -> std::result::Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("JSON object lacks string {field}"))
}

fn parse_checkpoint(
    block: &Value,
    chain_id: u64,
    source: L1FinalitySource,
) -> Result<L1FinalizedCheckpoint> {
    let block_number = quantity_u64(
        json_string(block, "number").map_err(CloseFundingPublisherError::Evidence)?,
        "block number",
    )
    .map_err(CloseFundingPublisherError::Evidence)?;
    let block_hash = parse_bytes32(
        json_string(block, "hash").map_err(CloseFundingPublisherError::Evidence)?,
        "block hash",
    )
    .map_err(CloseFundingPublisherError::Evidence)?;
    let parent_hash = parse_bytes32(
        json_string(block, "parentHash").map_err(CloseFundingPublisherError::Evidence)?,
        "block parent hash",
    )
    .map_err(CloseFundingPublisherError::Evidence)?;
    let checkpoint = L1FinalizedCheckpoint {
        chain_id,
        block_number,
        block_hash,
        parent_hash,
        source,
    };
    checkpoint
        .validate()
        .map_err(CloseFundingPublisherError::Evidence)?;
    Ok(checkpoint)
}

fn read_durable_checkpoint(
    rpc: &str,
    chain_id: u64,
    allow_unfinalized_devnet: bool,
) -> Result<L1FinalizedCheckpoint> {
    let observed = rpc_chain_id(rpc)?;
    if observed != chain_id {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "RPC chain id {observed} differs from pinned chain {chain_id}"
        )));
    }
    match rpc_block(rpc, "finalized")
        .and_then(|block| parse_checkpoint(&block, chain_id, L1FinalitySource::RpcFinalized))
    {
        Ok(checkpoint) => Ok(checkpoint),
        Err(_) if chain_id == ANVIL_CHAIN_ID && allow_unfinalized_devnet => {
            rpc_block(rpc, "latest").and_then(|block| {
                parse_checkpoint(&block, chain_id, L1FinalitySource::DevnetLatest)
            })
        }
        Err(error) => Err(CloseFundingPublisherError::Evidence(format!(
            "RPC cannot provide a valid finalized head: {error}"
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

fn revalidate_checkpoint(rpc: &str, checkpoint: &L1FinalizedCheckpoint) -> Result<()> {
    checkpoint
        .validate()
        .map_err(CloseFundingPublisherError::Evidence)?;
    let tag = format!("0x{:x}", checkpoint.block_number);
    let canonical = parse_checkpoint(
        &rpc_block(rpc, &tag)?,
        checkpoint.chain_id,
        checkpoint.source,
    )?;
    if canonical != *checkpoint {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "stored durable checkpoint {} was replaced/reorged",
            checkpoint.block_number
        )));
    }
    Ok(())
}

fn call_view_at(
    rpc: &str,
    target: &str,
    signature: &str,
    args: &[&str],
    block_number: u64,
) -> Result<String> {
    let block = format!("0x{block_number:x}");
    let mut command = Command::new("cast");
    command
        .arg("call")
        .arg(target)
        .arg(signature)
        .args(args)
        .args(["--block", &block, "--rpc-url", rpc]);
    Ok(checked_output(command, signature, 1024 * 1024)?
        .trim()
        .to_string())
}

fn decode_abi_word(raw: &str, what: &str) -> std::result::Result<[u8; 32], String> {
    decode_hex(raw.trim(), Some(32), what)?
        .try_into()
        .map_err(|_| format!("{what} is not one ABI word"))
}

fn view_word_at(
    rpc: &str,
    target: &str,
    signature: &str,
    args: &[&str],
    block_number: u64,
) -> Result<[u8; 32]> {
    let raw = call_view_at(rpc, target, signature, args, block_number)?;
    decode_abi_word(&raw, signature).map_err(CloseFundingPublisherError::Evidence)
}

fn view_address_at(
    rpc: &str,
    target: &str,
    signature: &str,
    args: &[&str],
    block_number: u64,
) -> Result<String> {
    let word = view_word_at(rpc, target, signature, args, block_number)?;
    if word[..12] != [0u8; 12] || word[12..] == [0u8; 20] {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "{signature} returned a zero/noncanonical address"
        )));
    }
    Ok(format!("0x{}", hex::encode(&word[12..])))
}

fn view_bool_at(
    rpc: &str,
    target: &str,
    signature: &str,
    args: &[&str],
    block_number: u64,
) -> Result<bool> {
    let word = view_word_at(rpc, target, signature, args, block_number)?;
    if word[..31] != [0u8; 31] || word[31] > 1 {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "{signature} returned a noncanonical bool"
        )));
    }
    Ok(word[31] == 1)
}

fn view_u64_at(
    rpc: &str,
    target: &str,
    signature: &str,
    args: &[&str],
    block_number: u64,
) -> Result<u64> {
    let word = view_word_at(rpc, target, signature, args, block_number)?;
    if word[..24] != [0u8; 24] {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "{signature} does not fit u64"
        )));
    }
    Ok(u64::from_be_bytes(
        word[24..].try_into().expect("eight bytes"),
    ))
}

fn view_u256_at(
    rpc: &str,
    target: &str,
    signature: &str,
    args: &[&str],
    block_number: u64,
) -> Result<BigUint> {
    Ok(BigUint::from_bytes_be(&view_word_at(
        rpc,
        target,
        signature,
        args,
        block_number,
    )?))
}

fn view_channel_id_at(rpc: &str, target: &str, block_number: u64) -> Result<u32> {
    let word = view_word_at(rpc, target, "channelId()(bytes4)", &[], block_number)?;
    if word[4..] != [0u8; 28] {
        return Err(CloseFundingPublisherError::Evidence(
            "manager channelId returned noncanonical bytes4".into(),
        ));
    }
    Ok(u32::from_be_bytes(
        word[..4].try_into().expect("four bytes"),
    ))
}

fn runtime_code_hash_at(rpc: &str, address: &str, block_number: u64) -> Result<String> {
    let block = format!("0x{block_number:x}");
    let code = cast_output(
        &["code", address, "--block", &block, "--rpc-url", rpc],
        "read deployed runtime code",
        MAX_RPC_JSON_BYTES,
    )?;
    let code = decode_hex(code.trim(), None, "deployed runtime code")
        .map_err(CloseFundingPublisherError::Evidence)?;
    if code.is_empty() {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "no runtime code at {address}"
        )));
    }
    Ok(keccak_hex(&code))
}

fn native_balance_at(rpc: &str, address: &str, block_number: u64) -> Result<BigUint> {
    let block = format!("0x{block_number:x}");
    let raw = cast_output(
        &["balance", address, "--block", &block, "--rpc-url", rpc],
        "read manager native balance",
        4096,
    )?;
    quantity_biguint(raw.trim(), "manager native balance")
        .map_err(CloseFundingPublisherError::Evidence)
}

fn token_deployment<'a>(
    manifest: &'a DeploymentManifest,
    token_index: u32,
) -> std::result::Result<&'a TokenDeployment, String> {
    manifest
        .tokens
        .iter()
        .find(|token| token.token_index == token_index)
        .ok_or_else(|| format!("manifest lacks token index {token_index}"))
}

fn manager_asset_balance_at(
    rpc: &str,
    prepared: &PreparedPayout,
    token_index: u32,
    block_number: u64,
) -> Result<BigUint> {
    if token_index == 0 {
        return native_balance_at(rpc, &prepared.envelope.manager, block_number);
    }
    let token = token_deployment(&prepared.manifest.value, token_index)
        .map_err(CloseFundingPublisherError::Evidence)?;
    view_u256_at(
        rpc,
        &token.token,
        "balanceOf(address)(uint256)",
        &[&prepared.envelope.manager],
        block_number,
    )
}

fn read_chain_snapshot_at(
    config: &CloseFundingPublisherConfig,
    prepared: &PreparedPayout,
    checkpoint: L1FinalizedCheckpoint,
) -> Result<ChainSnapshot> {
    let block = checkpoint.block_number;
    let status = view_u64_at(
        &config.rpc_url,
        &prepared.envelope.manager,
        "channelStatus()(uint8)",
        &[],
        block,
    )?;
    let channel_status = u8::try_from(status).map_err(|_| {
        CloseFundingPublisherError::Evidence("manager channelStatus does not fit u8".into())
    })?;
    let close_freeze_nonce = view_u64_at(
        &config.rpc_url,
        &prepared.envelope.manager,
        "currentCloseFreezeNonce()(uint64)",
        &[],
        block,
    )?;
    let anchor_finalized = view_bool_at(
        &config.rpc_url,
        &prepared.envelope.rollup,
        "isFinalizedStateRoot(bytes32)(bool)",
        &[&prepared.anchor.extended_state_commitment],
        block,
    )?;
    let mut tokens = BTreeMap::new();
    for (token_index, plan) in &prepared.token_plans {
        let token_arg = token_index.to_string();
        let cap = view_u256_at(
            &config.rpc_url,
            &prepared.envelope.manager,
            "finalizedChannelFundAmount(uint32)(uint256)",
            &[&token_arg],
            block,
        )?;
        let received = view_u256_at(
            &config.rpc_url,
            &prepared.envelope.manager,
            "receivedChannelFunds(uint32)(uint256)",
            &[&token_arg],
            block,
        )?;
        let total_credited_out = view_u256_at(
            &config.rpc_url,
            &prepared.envelope.manager,
            "totalCreditedOut(uint32)(uint256)",
            &[&token_arg],
            block,
        )?;
        let authorization = view_bool_at(
            &config.rpc_url,
            &prepared.envelope.rollup,
            "partialWithdrawalAuthorized(bytes32)(bool)",
            &[&plan.auth_digest],
            block,
        )?;
        let nullifier_used = view_bool_at(
            &config.rpc_url,
            &prepared.envelope.rollup,
            "withdrawalNullifierUsed(bytes32)(bool)",
            &[&plan.nullifier],
            block,
        )?;
        let pending_rollup_credit = if *token_index == 0 {
            view_u256_at(
                &config.rpc_url,
                &prepared.envelope.rollup,
                "pendingWithdrawals(address)(uint256)",
                &[&prepared.envelope.manager],
                block,
            )?
        } else {
            view_u256_at(
                &config.rpc_url,
                &prepared.envelope.rollup,
                "pendingTokenWithdrawals(uint32,address)(uint256)",
                &[&token_arg, &prepared.envelope.manager],
                block,
            )?
        };
        let manager_asset_balance =
            manager_asset_balance_at(&config.rpc_url, prepared, *token_index, block)?;
        tokens.insert(
            *token_index,
            TokenChainState {
                token_index: *token_index,
                cap: cap.to_string(),
                received: received.to_string(),
                total_credited_out: total_credited_out.to_string(),
                authorization,
                nullifier_used,
                pending_rollup_credit: pending_rollup_credit.to_string(),
                manager_asset_balance: manager_asset_balance.to_string(),
            },
        );
    }
    revalidate_checkpoint(&config.rpc_url, &checkpoint)?;
    Ok(ChainSnapshot {
        checkpoint,
        channel_status,
        close_freeze_nonce,
        anchor_finalized,
        tokens,
    })
}

fn validate_deployment_at(
    config: &CloseFundingPublisherConfig,
    prepared: &PreparedPayout,
    checkpoint: &L1FinalizedCheckpoint,
) -> Result<()> {
    let rpc = &config.rpc_url;
    let block = checkpoint.block_number;
    let manifest = &prepared.manifest.value;
    for (address, expected, what) in [
        (
            &manifest.rollup,
            &manifest.rollup_runtime_code_hash,
            "Rollup",
        ),
        (
            &manifest.manager,
            &manifest.manager_runtime_code_hash,
            "Manager",
        ),
        (
            &manifest.materializer,
            &manifest.materializer_runtime_code_hash,
            "close-funding materializer",
        ),
        (
            &manifest.verifier,
            &manifest.verifier_runtime_code_hash,
            "settlement verifier",
        ),
        (
            &manifest.mle_verifier,
            &manifest.mle_verifier_runtime_code_hash,
            "MLE verifier",
        ),
    ] {
        let actual = runtime_code_hash_at(rpc, address, block)?;
        if !same_hex(&actual, expected) {
            return Err(CloseFundingPublisherError::Evidence(format!(
                "{what} runtime code hash {actual} differs from manifest {expected}"
            )));
        }
    }
    if view_channel_id_at(rpc, &manifest.manager, block)? != prepared.envelope.channel_id
        || !same_hex(
            &view_address_at(rpc, &manifest.manager, "registry()(address)", &[], block)?,
            &manifest.rollup,
        )
        || !same_hex(
            &view_address_at(rpc, &manifest.manager, "verifier()(address)", &[], block)?,
            &manifest.verifier,
        )
        || !same_hex(
            &view_address_at(
                rpc,
                &manifest.manager,
                "closeFundingMaterializer()(address)",
                &[],
                block,
            )?,
            &manifest.materializer,
        )
        || !same_hex(
            &view_address_at(rpc, &manifest.materializer, "rollup()(address)", &[], block)?,
            &manifest.rollup,
        )
        || !same_hex(
            &view_address_at(rpc, &manifest.rollup, "mleVerifier()(address)", &[], block)?,
            &manifest.mle_verifier,
        )
    {
        return Err(CloseFundingPublisherError::Evidence(
            "deployed channel/registry/materializer/verifier/MLE immutable binding differs from artifact/manifest"
                .into(),
        ));
    }
    let allowed_chain = view_u256_at(
        rpc,
        &manifest.mle_verifier,
        "allowedChainId()(uint256)",
        &[],
        block,
    )?;
    if allowed_chain != BigUint::from(manifest.chain_id) {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "MLE verifier allowedChainId {allowed_chain} differs from {}",
            manifest.chain_id
        )));
    }
    if !view_bool_at(
        rpc,
        &manifest.rollup,
        "withdrawalVkInitialized()(bool)",
        &[],
        block,
    )? || !view_bool_at(
        rpc,
        &manifest.rollup,
        "isRegisteredSettlementManager(address)(bool)",
        &[&manifest.manager],
        block,
    )? {
        return Err(CloseFundingPublisherError::Evidence(
            "withdrawal VK is unset or Manager is not registered on the pinned Rollup".into(),
        ));
    }
    if !view_bool_at(
        rpc,
        &manifest.rollup,
        "isFinalizedStateRoot(bytes32)(bool)",
        &[&prepared.anchor.extended_state_commitment],
        block,
    )? || view_u64_at(
        rpc,
        &manifest.rollup,
        "latestFinalizedBlockNumber()(uint64)",
        &[],
        block,
    )? < prepared.anchor.block_number
    {
        return Err(CloseFundingPublisherError::Evidence(
            "terminal payout proof anchor is not a finalized Rollup state".into(),
        ));
    }

    let token_count = view_u64_at(
        rpc,
        &manifest.manager,
        "finalizedTokenCount()(uint8)",
        &[],
        block,
    )?;
    let token_count = usize::try_from(token_count).map_err(|_| {
        CloseFundingPublisherError::Evidence("finalized token count does not fit usize".into())
    })?;
    if token_count == 0 || token_count > MAX_CHANNEL_TOKENS {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "finalized token count {token_count} is outside 1..={MAX_CHANNEL_TOKENS}"
        )));
    }
    let mut registry = [0u32; MAX_CHANNEL_TOKENS];
    let mut amounts = [U256::zero(); MAX_CHANNEL_TOKENS];
    let mut funded = BTreeMap::new();
    let mut unique = BTreeSet::new();
    for slot in 0..MAX_CHANNEL_TOKENS {
        let slot_arg = slot.to_string();
        let token = view_u64_at(
            rpc,
            &manifest.manager,
            "finalizedTokenRegistry(uint256)(uint32)",
            &[&slot_arg],
            block,
        )?;
        let token = u32::try_from(token).map_err(|_| {
            CloseFundingPublisherError::Evidence("finalized token index does not fit u32".into())
        })?;
        registry[slot] = token;
        if slot >= token_count {
            if token != 0 {
                return Err(CloseFundingPublisherError::Evidence(
                    "finalized token registry has nonzero padding past tokenCount".into(),
                ));
            }
            continue;
        }
        if !unique.insert(token) {
            return Err(CloseFundingPublisherError::Evidence(
                "finalized token registry contains a duplicate base token index".into(),
            ));
        }
        let token_arg = token.to_string();
        let amount = view_u256_at(
            rpc,
            &manifest.manager,
            "finalizedChannelFundAmount(uint32)(uint256)",
            &[&token_arg],
            block,
        )?;
        let amount_u256 = U256::try_from(amount.clone()).map_err(|error| {
            CloseFundingPublisherError::Evidence(format!(
                "manager cap for token {token} does not fit U256: {error}"
            ))
        })?;
        amounts[slot] = amount_u256;
        if amount != BigUint::from(0u8) {
            funded.insert(token, amount);
        }
    }
    let expected_funded = prepared
        .token_plans
        .iter()
        .map(|(token, plan)| {
            quantity_biguint(&plan.amount, "payout amount").map(|amount| (*token, amount))
        })
        .collect::<std::result::Result<BTreeMap<_, _>, _>>()
        .map_err(CloseFundingPublisherError::Evidence)?;
    if funded != expected_funded {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "on-chain finalized nonzero fund vector {funded:?} differs from payout {expected_funded:?}"
        )));
    }
    let funds_digest = token_funds_digest(&registry, token_count as u8, &amounts);
    let channel_id = ChannelId::new(u64::from(prepared.envelope.channel_id)).map_err(|error| {
        CloseFundingPublisherError::Artifact(format!("invalid payout channel id: {error}"))
    })?;
    let close_freeze_nonce = view_u64_at(
        rpc,
        &manifest.manager,
        "currentCloseFreezeNonce()(uint64)",
        &[],
        block,
    )?;
    let expected_aux = close_funding_aux_data(
        manifest.chain_id,
        parse_address(&manifest.rollup, "manifest rollup")
            .map_err(CloseFundingPublisherError::Configuration)?,
        parse_address(&manifest.manager, "manifest manager")
            .map_err(CloseFundingPublisherError::Configuration)?,
        channel_id,
        close_freeze_nonce,
        funds_digest,
    );
    if expected_aux != prepared.funding_aux_data {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "funding aux data {} does not match on-chain chain/rollup/manager/channel/freeze/fund vector {}",
            prepared.funding_aux_data, expected_aux
        )));
    }

    for token in &manifest.tokens {
        let token_arg = token.token_index.to_string();
        let actual = view_address_at(
            rpc,
            &manifest.rollup,
            "tokenAddressOf(uint32)(address)",
            &[&token_arg],
            block,
        )?;
        let actual_hash = runtime_code_hash_at(rpc, &actual, block)?;
        if !same_hex(&actual, &token.token) || !same_hex(&actual_hash, &token.runtime_code_hash) {
            return Err(CloseFundingPublisherError::Evidence(format!(
                "Rollup token {} address/code differs from manifest",
                token.token_index
            )));
        }
    }
    revalidate_checkpoint(rpc, checkpoint)
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
        CloseFundingPublisherError::Command(format!("start receipt query: {error}"))
    })?;
    if !output.status.success() || output.stdout.is_empty() {
        return Ok(None);
    }
    if output.stdout.len() > MAX_RPC_JSON_BYTES {
        return Err(CloseFundingPublisherError::Evidence(
            "receipt JSON exceeds size limit".into(),
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        CloseFundingPublisherError::Evidence(format!("parse receipt JSON: {error}"))
    })?;
    Ok((!value.is_null()).then_some(value))
}

fn receipt_quantity(receipt: &Value, field: &str) -> std::result::Result<u64, String> {
    receipt
        .get(field)
        .ok_or_else(|| format!("receipt lacks {field}"))
        .and_then(|value| value_u64(value, &format!("receipt {field}")))
}

fn receipt_success(receipt: &Value) -> bool {
    receipt
        .get("status")
        .is_some_and(|value| value_u64(value, "receipt status").ok() == Some(1))
}

fn receipt_logs(receipt: &Value) -> std::result::Result<&Vec<Value>, String> {
    receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| "receipt lacks logs array".into())
}

fn log_topics(log: &Value) -> std::result::Result<&Vec<Value>, String> {
    log.get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| "event log lacks topics array".into())
}

fn log_topic(log: &Value, index: usize) -> std::result::Result<&str, String> {
    log_topics(log)?
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("event log lacks topic {index}"))
}

fn log_data(log: &Value, bytes: usize, what: &str) -> std::result::Result<Vec<u8>, String> {
    decode_hex(
        log.get("data").and_then(Value::as_str).unwrap_or_default(),
        Some(bytes),
        what,
    )
}

fn relevant_logs<'a>(
    receipt: &'a Value,
    address: &str,
    topic0: &str,
) -> std::result::Result<Vec<&'a Value>, String> {
    Ok(receipt_logs(receipt)?
        .iter()
        .filter(|log| {
            !log.get("removed").and_then(Value::as_bool).unwrap_or(false)
                && log
                    .get("address")
                    .and_then(Value::as_str)
                    .is_some_and(|actual| same_hex(actual, address))
                && log_topic(log, 0).is_ok_and(|actual| same_hex(actual, topic0))
        })
        .collect())
}

fn stable_receipt_fields(left: &Value, right: &Value) -> bool {
    [
        "transactionHash",
        "blockHash",
        "blockNumber",
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
    target: Option<&str>,
    signer: Option<&str>,
) -> Result<(String, Bytes32, u64)> {
    if !receipt
        .get("transactionHash")
        .and_then(Value::as_str)
        .is_some_and(|actual| same_hex(actual, transaction_hash))
    {
        return Err(CloseFundingPublisherError::Evidence(
            "receipt transactionHash differs from queried transaction".into(),
        ));
    }
    if let Some(target) = target {
        if !receipt
            .get("to")
            .and_then(Value::as_str)
            .is_some_and(|actual| same_hex(actual, target))
        {
            return Err(CloseFundingPublisherError::Evidence(
                "receipt target differs from signed/pinned transaction".into(),
            ));
        }
    }
    if let Some(signer) = signer {
        if !receipt
            .get("from")
            .and_then(Value::as_str)
            .is_some_and(|actual| same_hex(actual, signer))
        {
            return Err(CloseFundingPublisherError::Evidence(
                "receipt sender differs from signed transaction".into(),
            ));
        }
    }
    let block_hash_text = require_nonzero_hex(
        receipt
            .get("blockHash")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        32,
        "receipt block hash",
    )
    .map_err(CloseFundingPublisherError::Evidence)?;
    let block_hash = parse_bytes32(&block_hash_text, "receipt block hash")
        .map_err(CloseFundingPublisherError::Evidence)?;
    let block_number =
        receipt_quantity(receipt, "blockNumber").map_err(CloseFundingPublisherError::Evidence)?;
    Ok((block_hash_text, block_hash, block_number))
}

fn validate_receipt_identity(
    receipt: &Value,
    transaction_hash: &str,
    target: Option<&str>,
    signer: Option<&str>,
) -> Result<(String, Bytes32, u64)> {
    let location = validate_receipt_location(receipt, transaction_hash, target, signer)?;
    if !receipt_success(receipt) {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "transaction {transaction_hash} reverted"
        )));
    }
    Ok(location)
}

fn validate_acknowledgement_on_l1(
    config: &CloseFundingPublisherConfig,
    prepared: &PreparedPayout,
) -> Result<()> {
    revalidate_checkpoint(&config.rpc_url, &prepared.acknowledgement_checkpoint)?;
    let current = read_durable_checkpoint(
        &config.rpc_url,
        prepared.envelope.chain_id,
        config.allow_unfinalized_devnet,
    )?;
    checkpoint_advances(&prepared.acknowledgement_checkpoint, &current)
        .map_err(CloseFundingPublisherError::Evidence)?;
    let receipt_value = prepared
        .acknowledgement
        .get("receipt")
        .and_then(|receipt| receipt.get("l1Acknowledgement"))
        .ok_or_else(|| {
            CloseFundingPublisherError::Artifact("acknowledgement L1 receipt disappeared".into())
        })?;
    let transaction_hash = receipt_value
        .get("transactionHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CloseFundingPublisherError::Artifact(
                "acknowledgement transaction hash is absent".into(),
            )
        })?;
    let expected_block_hash = receipt_value
        .get("blockHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CloseFundingPublisherError::Artifact("acknowledgement block hash is absent".into())
        })?;
    let expected_block_number = receipt_value
        .get("blockNumber")
        .ok_or_else(|| {
            CloseFundingPublisherError::Artifact("acknowledgement block number is absent".into())
        })
        .and_then(|value| {
            value_u64(value, "acknowledgement block number")
                .map_err(CloseFundingPublisherError::Artifact)
        })?;
    let receipt = rpc_receipt(&config.rpc_url, transaction_hash)?.ok_or_else(|| {
        CloseFundingPublisherError::Evidence(
            "terminal validity acknowledgement transaction is no longer available".into(),
        )
    })?;
    let (block_hash_text, block_hash, block_number) = validate_receipt_identity(
        &receipt,
        transaction_hash,
        Some(&prepared.envelope.rollup),
        None,
    )?;
    if block_number != expected_block_number || !same_hex(&block_hash_text, expected_block_hash) {
        return Err(CloseFundingPublisherError::Evidence(
            "terminal validity receipt differs from durable acknowledgement".into(),
        ));
    }
    current
        .covers_receipt(block_number, block_hash)
        .map_err(CloseFundingPublisherError::Evidence)?;
    let canonical = parse_checkpoint(
        &rpc_block(&config.rpc_url, &format!("0x{block_number:x}"))?,
        prepared.envelope.chain_id,
        current.source,
    )?;
    if canonical.block_hash != block_hash {
        return Err(CloseFundingPublisherError::Evidence(
            "terminal validity receipt block is not canonical".into(),
        ));
    }
    let historical_rollup_hash =
        runtime_code_hash_at(&config.rpc_url, &prepared.envelope.rollup, block_number)?;
    if !same_hex(
        &historical_rollup_hash,
        &prepared.manifest.value.rollup_runtime_code_hash,
    ) {
        return Err(CloseFundingPublisherError::Evidence(
            "terminal validity receipt was emitted by unpinned historical Rollup code".into(),
        ));
    }
    let second = rpc_receipt(&config.rpc_url, transaction_hash)?.ok_or_else(|| {
        CloseFundingPublisherError::Evidence(
            "terminal validity receipt disappeared during read-back".into(),
        )
    })?;
    if !stable_receipt_fields(&receipt, &second) {
        return Err(CloseFundingPublisherError::Evidence(
            "terminal validity receipt changed during read-back".into(),
        ));
    }
    let topic0 = keccak_hex(b"Finalized(uint256,bytes32)");
    let events = relevant_logs(&receipt, &prepared.envelope.rollup, &topic0)
        .map_err(CloseFundingPublisherError::Evidence)?;
    if events.len() != 1
        || log_topics(events[0])
            .map_err(CloseFundingPublisherError::Evidence)?
            .len()
            != 2
        || decode_hex(
            log_topic(events[0], 1).map_err(CloseFundingPublisherError::Evidence)?,
            Some(32),
            "Finalized submission id",
        )
        .map_err(CloseFundingPublisherError::Evidence)?
        .len()
            != 32
        || !same_hex(
            &format!(
                "0x{}",
                hex::encode(
                    log_data(events[0], 32, "Finalized state root")
                        .map_err(CloseFundingPublisherError::Evidence)?
                )
            ),
            &prepared.anchor.extended_state_commitment,
        )
    {
        return Err(CloseFundingPublisherError::Evidence(
            "terminal validity receipt lacks one exact Finalized(root) event".into(),
        ));
    }
    if !view_bool_at(
        &config.rpc_url,
        &prepared.envelope.rollup,
        "isFinalizedStateRoot(bytes32)(bool)",
        &[&prepared.anchor.extended_state_commitment],
        current.block_number,
    )? {
        return Err(CloseFundingPublisherError::Evidence(
            "terminal state root is no longer recognized as finalized".into(),
        ));
    }
    revalidate_checkpoint(&config.rpc_url, &current)
}

#[derive(Clone, Debug)]
enum L1Signer {
    AnvilPublicDevKey,
    FoundryAccount(String),
}

impl L1Signer {
    fn resolve(chain_id: u64, configured: Option<&str>) -> Result<Self> {
        for variable in [
            "INTMAX_DEPOSIT_KEY",
            "INTMAX_L1_PRIVATE_KEY",
            "ETH_PRIVATE_KEY",
            "PRIVATE_KEY",
        ] {
            if std::env::var(variable)
                .ok()
                .is_some_and(|value| !value.trim().is_empty())
            {
                return Err(CloseFundingPublisherError::Configuration(format!(
                    "raw key environment {variable} is forbidden; use an encrypted Foundry account"
                )));
            }
        }
        let configured = configured
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| {
                std::env::var("INTMAX_L1_ACCOUNT")
                    .ok()
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
            });
        if let Some(account) = configured {
            if account.len() > 128
                || !account
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            {
                return Err(CloseFundingPublisherError::Configuration(
                    "Foundry account name contains unsafe characters".into(),
                ));
            }
            return Ok(Self::FoundryAccount(account));
        }
        if chain_id == ANVIL_CHAIN_ID {
            return Ok(Self::AnvilPublicDevKey);
        }
        Err(CloseFundingPublisherError::Configuration(format!(
            "an encrypted Foundry account is required on chain {chain_id}"
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
        require_nonzero_hex(output.trim(), 20, "signer address")
            .map_err(CloseFundingPublisherError::Command)
    }
}

fn decode_signed_transaction(raw: &str) -> Result<Value> {
    let raw = raw.trim();
    if raw.len() < 4
        || raw.len() > MAX_RAW_TRANSACTION_CHARS
        || !raw.starts_with("0x")
        || !raw[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(CloseFundingPublisherError::Evidence(
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
            CloseFundingPublisherError::Command(format!("start cast decode-transaction: {error}"))
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| CloseFundingPublisherError::Command("decoder stdin is absent".into()))?
        .write_all(raw.as_bytes())
        .map_err(|error| {
            CloseFundingPublisherError::Command(format!("write decoder stdin: {error}"))
        })?;
    let output = child.wait_with_output().map_err(|error| {
        CloseFundingPublisherError::Command(format!("wait for transaction decoder: {error}"))
    })?;
    if !output.status.success() || output.stdout.len() > MAX_RPC_JSON_BYTES {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "cast rejected signed transaction: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        CloseFundingPublisherError::Evidence(format!(
            "decoded signed transaction JSON is invalid: {error}"
        ))
    })
}

fn validate_decoded_transaction(
    decoded: &Value,
    chain_id: u64,
    signer: &str,
    target: &str,
    calldata: &str,
) -> std::result::Result<(String, u64), String> {
    if quantity_u64(json_string(decoded, "chainId")?, "transaction chainId")? != chain_id {
        return Err("signed transaction targets another chain".into());
    }
    if !same_hex(json_string(decoded, "signer")?, signer)
        || !same_hex(json_string(decoded, "to")?, target)
        || !same_hex(json_string(decoded, "input")?, calldata)
    {
        return Err("signed transaction signer/target/calldata differs from pinned action".into());
    }
    if quantity_biguint(json_string(decoded, "value")?, "transaction value")? != BigUint::from(0u8)
    {
        return Err("close-funding transaction must carry zero msg.value".into());
    }
    let tx_type = json_string(decoded, "type")?;
    if tx_type == "0x3" || tx_type == "0x03" {
        return Err("close-funding call unexpectedly signed as a blob transaction".into());
    }
    let hash = require_nonzero_hex(json_string(decoded, "hash")?, 32, "transaction hash")?;
    let nonce = quantity_u64(json_string(decoded, "nonce")?, "transaction nonce")?;
    Ok((hash, nonce))
}

fn sign_transaction(
    config: &CloseFundingPublisherConfig,
    signer: &L1Signer,
    signer_address: &str,
    spec: &ActionSpec,
    preflight: &ChainSnapshot,
) -> Result<RawTransactionStep> {
    let mut command = Command::new("cast");
    command.args([
        "mktx",
        &spec.target,
        &spec.calldata,
        "--rpc-url",
        &config.rpc_url,
        "--json",
    ]);
    signer.append(&mut command);
    let raw = checked_output(
        command,
        "sign close-funding raw transaction",
        MAX_RAW_TRANSACTION_CHARS,
    )?
    .trim()
    .to_string();
    let decoded = decode_signed_transaction(&raw)?;
    let (transaction_hash, nonce) = validate_decoded_transaction(
        &decoded,
        config_chain_id(config, preflight),
        signer_address,
        &spec.target,
        &spec.calldata,
    )
    .map_err(CloseFundingPublisherError::Evidence)?;
    Ok(RawTransactionStep {
        action: spec.action.clone(),
        target: spec.target.clone(),
        selector: spec.calldata[..10].to_ascii_lowercase(),
        calldata_hash: spec.calldata_hash.clone(),
        value: "0".into(),
        nonce,
        raw_signed_transaction: raw,
        transaction_hash,
        preflight_checkpoint: preflight.checkpoint,
        preflight_state_digest: snapshot_digest(preflight)?,
        confirmation: None,
        superseded_confirmation: None,
    })
}

fn config_chain_id(_config: &CloseFundingPublisherConfig, snapshot: &ChainSnapshot) -> u64 {
    snapshot.checkpoint.chain_id
}

fn validate_persisted_step(
    step: &RawTransactionStep,
    spec: &ActionSpec,
    chain_id: u64,
    signer: &str,
) -> Result<()> {
    if step.action != spec.action
        || !same_hex(&step.target, &spec.target)
        || !same_hex(&step.selector, &spec.calldata[..10])
        || !same_hex(&step.calldata_hash, &spec.calldata_hash)
        || step.value != "0"
        || step.preflight_checkpoint.chain_id != chain_id
    {
        return Err(CloseFundingPublisherError::Conflict(format!(
            "persisted step {} differs from exact action binding",
            spec.action.id()
        )));
    }
    step.preflight_checkpoint
        .validate()
        .map_err(CloseFundingPublisherError::Conflict)?;
    let decoded = decode_signed_transaction(&step.raw_signed_transaction)?;
    let (hash, nonce) =
        validate_decoded_transaction(&decoded, chain_id, signer, &spec.target, &spec.calldata)
            .map_err(CloseFundingPublisherError::Conflict)?;
    if !same_hex(&hash, &step.transaction_hash) || nonce != step.nonce {
        return Err(CloseFundingPublisherError::Conflict(
            "persisted raw transaction hash/nonce metadata was modified".into(),
        ));
    }
    Ok(())
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
        "query exact signed transaction",
        MAX_RPC_JSON_BYTES,
    )?;
    let value: Value = serde_json::from_str(output.trim()).map_err(|error| {
        CloseFundingPublisherError::Evidence(format!("parse transaction lookup: {error}"))
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
        CloseFundingPublisherError::Evidence(format!("parse transaction body: {error}"))
    })?;
    if value.is_null() {
        Ok(None)
    } else if value.is_object() {
        Ok(Some(value))
    } else {
        Err(CloseFundingPublisherError::Evidence(
            "transaction lookup returned neither object nor null".into(),
        ))
    }
}

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
                "semantic completion transaction {field} differs from its receipt/log"
            ));
        }
    }
    require_nonzero_hex(
        transaction
            .get("from")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        20,
        "semantic completion sender",
    )?;
    let transaction_from = transaction
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| "semantic completion transaction lacks sender".to_string())?;
    let receipt_from = receipt
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| "semantic completion receipt lacks sender".to_string())?;
    let transaction_to = transaction.get("to").unwrap_or(&Value::Null);
    let receipt_to = receipt.get("to").unwrap_or(&Value::Null);
    let same_to = match (transaction_to.as_str(), receipt_to.as_str()) {
        (Some(left), Some(right)) => same_hex(left, right),
        (None, None) => transaction_to.is_null() && receipt_to.is_null(),
        _ => false,
    };
    if transaction
        .get("blockNumber")
        .ok_or_else(|| "semantic completion transaction lacks blockNumber".to_string())
        .and_then(|value| value_u64(value, "semantic completion blockNumber"))?
        != block_number
        || !same_hex(transaction_from, receipt_from)
        || !same_to
        || transaction
            .get("transactionIndex")
            .ok_or_else(|| "semantic completion transaction lacks transactionIndex".to_string())
            .and_then(|value| value_u64(value, "semantic completion transactionIndex"))?
            != receipt
                .get("transactionIndex")
                .ok_or_else(|| "semantic completion receipt lacks transactionIndex".to_string())
                .and_then(|value| value_u64(value, "semantic completion receipt index"))?
    {
        return Err(
            "semantic completion transaction inclusion differs from its receipt/log".into(),
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
    quantity_u64(output.trim(), "signer latest nonce").map_err(CloseFundingPublisherError::Evidence)
}

fn publish_exact_raw(rpc: &str, signer: &str, step: &RawTransactionStep) -> Result<()> {
    if transaction_known(rpc, &step.transaction_hash)?
        || rpc_receipt(rpc, &step.transaction_hash)?.is_some()
    {
        return Ok(());
    }
    let nonce = account_nonce(rpc, signer)?;
    if nonce > step.nonce {
        return Err(CloseFundingPublisherError::Conflict(format!(
            "signer nonce {} was consumed while exact transaction {} is unknown; refusing sibling replacement",
            step.nonce, step.transaction_hash
        )));
    }
    if nonce < step.nonce {
        return Err(CloseFundingPublisherError::Conflict(format!(
            "signed nonce {} is ahead of signer nonce {nonce}; an earlier operation is missing",
            step.nonce
        )));
    }
    let output = Command::new("cast")
        .args([
            "publish",
            &step.raw_signed_transaction,
            "--async",
            "--rpc-url",
            rpc,
        ])
        .output()
        .map_err(|error| {
            CloseFundingPublisherError::Command(format!("start raw transaction publish: {error}"))
        })?;
    if !output.status.success() {
        if transaction_known(rpc, &step.transaction_hash)? {
            return Ok(());
        }
        return Err(CloseFundingPublisherError::Command(format!(
            "exact raw transaction publish failed after WAL fsync: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let published = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !same_hex(&published, &step.transaction_hash) {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "RPC returned transaction {published}, expected {}",
            step.transaction_hash
        )));
    }
    Ok(())
}

/// Once another account wins a permissionless race, do not sign the next nonce until our already
/// broadcast raw transaction has itself become a canonical-finalized revert. Otherwise a dropped
/// transaction at the same nonce could later reappear, or a replacement would violate exact-replay
/// discipline. This deliberately spends only the already-journaled raw transaction; it never
/// manufactures a cancellation or sibling transaction.
fn ensure_superseded_raw_settled(
    config: &CloseFundingPublisherConfig,
    expected_chain_id: u64,
    signer: &str,
    step: &RawTransactionStep,
) -> Result<FinalizedReceipt> {
    let Some(receipt) = rpc_receipt(&config.rpc_url, &step.transaction_hash)? else {
        // A stored superseded confirmation means the signer reservation was already released.
        // If that receipt later disappears, re-broadcasting here would cross a network boundary
        // without an active reservation and could also resurrect a transaction from an orphaned
        // fork. Fail closed; a later run must first re-establish the exact reservation under the
        // signer lock before any exact-raw replay is permitted.
        if step.superseded_confirmation.is_some() {
            return Err(CloseFundingPublisherError::Evidence(format!(
                "stored superseded receipt for {} disappeared; refusing reservation-free replay",
                step.transaction_hash
            )));
        }
        let nonce = account_nonce(&config.rpc_url, signer)?;
        if nonce > step.nonce && !transaction_known(&config.rpc_url, &step.transaction_hash)? {
            return Err(CloseFundingPublisherError::Conflict(format!(
                "superseded signer nonce {} was consumed but exact transaction {} is unknown",
                step.nonce, step.transaction_hash
            )));
        }
        // If the front-run landed between WAL fsync and our first broadcast, publish the already
        // journaled bytes now. The one-shot semantic guard makes them revert, consuming exactly
        // their recorded nonce without inventing a cancellation/replacement.
        publish_exact_raw(&config.rpc_url, signer, step)?;
        return Err(CloseFundingPublisherError::Timeout(format!(
            "external action is finalized, but superseded exact transaction {} has no finalized receipt; retry after its nonce settles",
            step.transaction_hash
        )));
    };
    let (block_hash_text, block_hash, block_number) = validate_receipt_location(
        &receipt,
        &step.transaction_hash,
        Some(&step.target),
        Some(signer),
    )?;
    if receipt_success(&receipt) {
        return Err(CloseFundingPublisherError::Conflict(format!(
            "local transaction {} and a different adopted transaction both report success for one-shot action {}",
            step.transaction_hash,
            step.action.id()
        )));
    }
    let before = read_durable_checkpoint(
        &config.rpc_url,
        expected_chain_id,
        config.allow_unfinalized_devnet,
    )?;
    if block_number > before.block_number {
        return Err(CloseFundingPublisherError::Timeout(format!(
            "superseded exact transaction {} reverted but is not finalized",
            step.transaction_hash
        )));
    }
    let canonical = parse_checkpoint(
        &rpc_block(&config.rpc_url, &format!("0x{block_number:x}"))?,
        before.chain_id,
        before.source,
    )?;
    if canonical.block_hash != block_hash {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "superseded exact transaction {} is noncanonical",
            step.transaction_hash
        )));
    }
    before
        .covers_receipt(block_number, block_hash)
        .map_err(CloseFundingPublisherError::Evidence)?;
    let second = rpc_receipt(&config.rpc_url, &step.transaction_hash)?.ok_or_else(|| {
        CloseFundingPublisherError::Evidence(
            "superseded exact transaction receipt disappeared during read-back".into(),
        )
    })?;
    if !stable_receipt_fields(&receipt, &second) {
        return Err(CloseFundingPublisherError::Evidence(
            "superseded exact transaction receipt changed during read-back".into(),
        ));
    }
    revalidate_checkpoint(&config.rpc_url, &before)?;
    let after = read_durable_checkpoint(
        &config.rpc_url,
        expected_chain_id,
        config.allow_unfinalized_devnet,
    )?;
    checkpoint_advances(&before, &after).map_err(CloseFundingPublisherError::Evidence)?;
    after
        .covers_receipt(block_number, block_hash)
        .map_err(CloseFundingPublisherError::Evidence)?;
    if block_number < step.preflight_checkpoint.block_number {
        return Err(CloseFundingPublisherError::Evidence(
            "superseded receipt predates its signed preflight".into(),
        ));
    }
    let current = FinalizedReceipt {
        transaction_hash: step.transaction_hash.to_ascii_lowercase(),
        block_hash: block_hash_text,
        block_number,
        finalized_checkpoint: after,
    };
    if let Some(stored) = &step.superseded_confirmation {
        revalidate_checkpoint(&config.rpc_url, &stored.finalized_checkpoint)?;
        if !same_hex(&stored.transaction_hash, &current.transaction_hash)
            || !same_hex(&stored.block_hash, &current.block_hash)
            || stored.block_number != current.block_number
        {
            return Err(CloseFundingPublisherError::Evidence(format!(
                "superseded exact transaction {} changed its canonical receipt",
                step.transaction_hash
            )));
        }
        checkpoint_advances(&stored.finalized_checkpoint, &current.finalized_checkpoint)
            .map_err(CloseFundingPublisherError::Evidence)?;
    }
    Ok(current)
}

fn wait_for_finalized_receipt(
    config: &CloseFundingPublisherConfig,
    expected_chain_id: u64,
    transaction_hash: &str,
    signer: Option<&str>,
    target: Option<&str>,
) -> Result<(Value, FinalizedReceipt)> {
    let started = Instant::now();
    loop {
        if let Some(receipt) = rpc_receipt(&config.rpc_url, transaction_hash)? {
            let (block_hash_text, block_hash, block_number) =
                validate_receipt_identity(&receipt, transaction_hash, target, signer)?;
            let before = read_durable_checkpoint(
                &config.rpc_url,
                expected_chain_id,
                config.allow_unfinalized_devnet,
            )?;
            if block_number <= before.block_number {
                let canonical = parse_checkpoint(
                    &rpc_block(&config.rpc_url, &format!("0x{block_number:x}"))?,
                    before.chain_id,
                    before.source,
                )?;
                if canonical.block_hash != block_hash {
                    return Err(CloseFundingPublisherError::Evidence(format!(
                        "transaction {transaction_hash} receipt block is noncanonical"
                    )));
                }
                before
                    .covers_receipt(block_number, block_hash)
                    .map_err(CloseFundingPublisherError::Evidence)?;
                let second = rpc_receipt(&config.rpc_url, transaction_hash)?.ok_or_else(|| {
                    CloseFundingPublisherError::Evidence(
                        "receipt disappeared during finalized read-back".into(),
                    )
                })?;
                if !stable_receipt_fields(&receipt, &second) {
                    return Err(CloseFundingPublisherError::Evidence(
                        "receipt changed during finalized read-back".into(),
                    ));
                }
                revalidate_checkpoint(&config.rpc_url, &before)?;
                let after = read_durable_checkpoint(
                    &config.rpc_url,
                    before.chain_id,
                    config.allow_unfinalized_devnet,
                )?;
                checkpoint_advances(&before, &after)
                    .map_err(CloseFundingPublisherError::Evidence)?;
                after
                    .covers_receipt(block_number, block_hash)
                    .map_err(CloseFundingPublisherError::Evidence)?;
                return Ok((
                    receipt,
                    FinalizedReceipt {
                        transaction_hash: transaction_hash.to_ascii_lowercase(),
                        block_hash: block_hash_text,
                        block_number,
                        finalized_checkpoint: after,
                    },
                ));
            }
        }
        if started.elapsed() >= config.finality_timeout {
            return Err(CloseFundingPublisherError::Timeout(format!(
                "transaction {transaction_hash} is not canonical-finalized after {}s; exact raw transaction remains in the WAL",
                config.finality_timeout.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_secs(6));
    }
}

fn topic_matches_word(topic: &str, expected: &str) -> std::result::Result<bool, String> {
    Ok(decode_hex(topic, Some(32), "event topic")?
        == decode_hex(expected, Some(32), "expected event word")?)
}

fn topic_matches_address(topic: &str, expected: &str) -> std::result::Result<bool, String> {
    let topic = decode_hex(topic, Some(32), "indexed address")?;
    let address = decode_hex(expected, Some(20), "expected address")?;
    Ok(topic[..12] == [0u8; 12] && topic[12..] == address)
}

fn topic_u32(topic: &str, what: &str) -> std::result::Result<u32, String> {
    let word = decode_hex(topic, Some(32), what)?;
    if word[..28] != [0u8; 28] {
        return Err(format!("{what} is not a canonical uint32 topic"));
    }
    Ok(u32::from_be_bytes(
        word[28..].try_into().expect("four bytes"),
    ))
}

fn topic_u8(topic: &str, what: &str) -> std::result::Result<u8, String> {
    let word = decode_hex(topic, Some(32), what)?;
    if word[..31] != [0u8; 31] {
        return Err(format!("{what} is not a canonical uint8 topic"));
    }
    Ok(word[31])
}

fn data_u256(data: &[u8], word: usize) -> BigUint {
    BigUint::from_bytes_be(&data[word * 32..(word + 1) * 32])
}

fn data_u64(data: &[u8], word: usize, what: &str) -> std::result::Result<u64, String> {
    let word = &data[word * 32..(word + 1) * 32];
    if word[..24] != [0u8; 24] {
        return Err(format!("{what} is not a canonical uint64"));
    }
    Ok(u64::from_be_bytes(
        word[24..].try_into().expect("eight bytes"),
    ))
}

fn materialization_lane(action: &PublicationAction) -> std::result::Result<(bool, u8), String> {
    match action {
        PublicationAction::MaterializeNative => Ok((true, 0)),
        PublicationAction::MaterializeErc20 => Ok((false, 1)),
        _ => Err("materialization validator called for non-materialize action".into()),
    }
}

/// Validate the pinned materializer's terminal marker and return its receipt-log position.
///
/// `withdrawalSetDigest` is deliberately diagnostic: IPW2 authenticates the complete terminal
/// economics but not a proof-private nullifier or withdrawal order. A different valid proof may
/// therefore win the permissionless race safely. Manager/lane/IMCF are exact indexed authority;
/// the receipt-block complete-lane state below proves the resulting credits.
fn validate_materialization_event(
    receipt: &Value,
    prepared: &PreparedPayout,
    spec: &ActionSpec,
) -> std::result::Result<usize, String> {
    let (_, expected_lane) = materialization_lane(&spec.action)?;
    let topic0 = keccak_hex(MATERIALIZED_EVENT_SIGNATURE.as_bytes());
    let mut exact = Vec::new();
    for (index, log) in receipt_logs(receipt)?.iter().enumerate() {
        if log.get("removed").and_then(Value::as_bool).unwrap_or(false)
            || !log
                .get("address")
                .and_then(Value::as_str)
                .is_some_and(|actual| same_hex(actual, &prepared.manifest.value.materializer))
            || !log_topic(log, 0).is_ok_and(|actual| same_hex(actual, &topic0))
        {
            continue;
        }
        if log_topics(log)?.len() != 4 {
            return Err(
                "CloseFundingMaterialized event has a malformed indexed-field count".into(),
            );
        }
        let diagnostic_digest = log_data(log, 32, "CloseFundingMaterialized withdrawalSetDigest")?;
        if topic_matches_address(log_topic(log, 1)?, &prepared.envelope.manager)?
            && topic_u8(log_topic(log, 2)?, "CloseFundingMaterialized.lane")? == expected_lane
            && topic_matches_word(log_topic(log, 3)?, &prepared.binding.funding_aux_data)?
        {
            // Reading the exact one-word payload above is intentional even though its value is
            // diagnostic; malformed dynamic/trailing encodings must not be accepted.
            debug_assert_eq!(diagnostic_digest.len(), 32);
            exact.push(index);
        }
    }
    if exact.len() != 1 {
        return Err(format!(
            "materialize receipt has {} exact Manager/lane/IMCF completion events; expected one",
            exact.len()
        ));
    }
    Ok(exact[0])
}

fn validate_payout_events(
    receipt: &Value,
    prepared: &PreparedPayout,
    spec: &ActionSpec,
    materialized_log_index: usize,
) -> std::result::Result<(), String> {
    let (native, _) = materialization_lane(&spec.action)?;
    let topic0 = if native {
        keccak_hex(b"NativeWithdrawn(address,uint256,bytes32,uint64)")
    } else {
        keccak_hex(b"Erc20Withdrawn(address,uint32,uint256,bytes32,uint64)")
    };
    let mut unmatched = spec.token_indices.iter().copied().collect::<BTreeSet<_>>();
    for (log_index, log) in receipt_logs(receipt)?.iter().enumerate() {
        if log.get("removed").and_then(Value::as_bool).unwrap_or(false)
            || !log
                .get("address")
                .and_then(Value::as_str)
                .is_some_and(|actual| same_hex(actual, &prepared.envelope.rollup))
            || !log_topic(log, 0).is_ok_and(|actual| same_hex(actual, &topic0))
        {
            continue;
        }
        let topics = log_topics(log)?;
        let expected_topics = if native { 3 } else { 4 };
        if topics.len() != expected_topics {
            return Err("payout event has wrong indexed-field count".into());
        }
        let token_index = if native {
            0
        } else {
            topic_u32(log_topic(log, 2)?, "Erc20Withdrawn.tokenIndex")?
        };
        let data = log_data(log, 64, "withdrawal payout event data")?;
        if !topic_matches_address(log_topic(log, 1)?, &prepared.envelope.manager)? {
            continue;
        }
        let Some(plan) = prepared.token_plans.get(&token_index) else {
            continue;
        };
        if !spec.token_indices.contains(&token_index) {
            continue;
        }
        // The indexed nullifier is required to be one canonical word but is not compared with
        // the local artifact. A competing valid proof may choose a different proof-private
        // nullifier while funding the same complete terminal lane.
        decode_hex(
            log_topic(log, if native { 2 } else { 3 })?,
            Some(32),
            "withdrawal payout nullifier",
        )?;
        if data_u256(&data, 0) != quantity_biguint(&plan.amount, "payout amount")?
            || data_u64(&data, 1, "withdrawal payout blockNumber")? != prepared.anchor.block_number
        {
            return Err("terminal-lane payout event has the wrong amount or proof block".into());
        }
        if log_index >= materialized_log_index {
            return Err(
                "terminal withdrawal event does not precede its materialization marker".into(),
            );
        }
        if !unmatched.remove(&token_index) {
            return Err("materialize receipt repeats one terminal token withdrawal".into());
        }
    }
    if !unmatched.is_empty() {
        return Err(format!(
            "materialize receipt omits complete-lane tokens {unmatched:?}"
        ));
    }
    Ok(())
}

fn validate_pull_event(
    receipt: &Value,
    prepared: &PreparedPayout,
    token_index: u32,
) -> std::result::Result<(), String> {
    let topic0 = keccak_hex(b"ChannelFundsPulled(uint32,uint256,uint256)");
    let logs = relevant_logs(receipt, &prepared.envelope.manager, &topic0)?;
    let plan = prepared
        .token_plans
        .get(&token_index)
        .ok_or_else(|| format!("payout plan lacks token {token_index}"))?;
    let amount = quantity_biguint(&plan.amount, "payout amount")?;
    let mut exact = 0usize;
    for log in logs {
        if log_topics(log)?.len() != 2 {
            return Err("ChannelFundsPulled event has a malformed indexed-field count".into());
        }
        let event_token = topic_u32(log_topic(log, 1)?, "ChannelFundsPulled.tokenIndex")?;
        let data = log_data(log, 64, "ChannelFundsPulled data")?;
        if event_token != token_index {
            continue;
        }
        if data_u256(&data, 0) != amount || data_u256(&data, 1) != amount {
            return Err("ChannelFundsPulled event for the exact token has wrong amounts".into());
        }
        exact += 1;
    }
    if exact != 1 {
        return Err(format!(
            "pull receipt has {exact} exact token/amount/cap events; expected one"
        ));
    }
    Ok(())
}

fn validate_post_state(
    prepared: &PreparedPayout,
    spec: &ActionSpec,
    snapshot: &ChainSnapshot,
) -> std::result::Result<(), String> {
    if snapshot.channel_status != 2 || !snapshot.anchor_finalized {
        return Err("post-transaction Manager/anchor state is no longer closed/finalized".into());
    }
    for token_index in &spec.token_indices {
        let plan = prepared
            .token_plans
            .get(token_index)
            .ok_or_else(|| format!("payout plan lacks token {token_index}"))?;
        let state = snapshot
            .tokens
            .get(token_index)
            .ok_or_else(|| format!("post-state lacks token {token_index}"))?;
        let amount = quantity_biguint(&plan.amount, "payout amount")?;
        let cap = quantity_biguint(&state.cap, "manager cap")?;
        let received = quantity_biguint(&state.received, "manager received")?;
        if cap != amount || (received != BigUint::from(0u8) && received != cap) {
            return Err(format!(
                "token {token_index} post-state has wrong cap/partial received amount"
            ));
        }
        assert_backing_invariant(state)?;
        match spec.action {
            PublicationAction::MaterializeNative | PublicationAction::MaterializeErc20 => {
                if state.authorization {
                    return Err(format!(
                        "token {token_index} materialization left its one-shot authorization live"
                    ));
                }
                if received == BigUint::from(0u8)
                    && quantity_biguint(&state.pending_rollup_credit, "pending Rollup credit")?
                        < amount
                {
                    return Err(format!(
                        "token {token_index} materialization event is not backed by pending Rollup credit"
                    ));
                }
            }
            PublicationAction::PullNative | PublicationAction::PullErc20 { .. } => {
                if state.authorization || received != cap {
                    return Err(format!(
                        "token {token_index} exact pull did not set received cap"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_action_evidence(
    config: &CloseFundingPublisherConfig,
    prepared: &PreparedPayout,
    spec: &ActionSpec,
    receipt: &Value,
    finalized: &FinalizedReceipt,
) -> Result<(String, String)> {
    match spec.action {
        PublicationAction::MaterializeNative | PublicationAction::MaterializeErc20 => {
            let marker = validate_materialization_event(receipt, prepared, spec)
                .map_err(CloseFundingPublisherError::Evidence)?;
            validate_payout_events(receipt, prepared, spec, marker)
        }
        PublicationAction::PullNative => validate_pull_event(receipt, prepared, 0),
        PublicationAction::PullErc20 { token_index } => {
            validate_pull_event(receipt, prepared, token_index)
        }
    }
    .map_err(CloseFundingPublisherError::Evidence)?;
    let receipt_block = parse_checkpoint(
        &rpc_block(&config.rpc_url, &format!("0x{:x}", finalized.block_number))?,
        prepared.envelope.chain_id,
        finalized.finalized_checkpoint.source,
    )?;
    if !same_hex(&receipt_block.block_hash.to_string(), &finalized.block_hash) {
        return Err(CloseFundingPublisherError::Evidence(
            "receipt block changed before getter reconciliation".into(),
        ));
    }
    // A historical event emitted by different code at a recycled/proxied address is not evidence
    // for the release-reviewed protocol. Pin every implementation again at the receipt block.
    validate_deployment_at(config, prepared, &receipt_block)?;
    let post = read_chain_snapshot_at(config, prepared, receipt_block)?;
    validate_post_state(prepared, spec, &post).map_err(CloseFundingPublisherError::Evidence)?;
    let evidence = serde_json::json!({
        "action": spec.action,
        "transactionHash": finalized.transaction_hash,
        "blockHash": finalized.block_hash,
        "blockNumber": finalized.block_number,
        "logs": receipt.get("logs").cloned().unwrap_or(Value::Null),
    });
    Ok((
        stable_request_id("close-funding-receipt-evidence-v2", &evidence),
        snapshot_digest(&post)?,
    ))
}

fn semantic_event_filter(prepared: &PreparedPayout, spec: &ActionSpec) -> (String, Vec<String>) {
    match spec.action {
        PublicationAction::MaterializeNative | PublicationAction::MaterializeErc20 => (
            prepared.manifest.value.materializer.clone(),
            vec![
                keccak_hex(MATERIALIZED_EVENT_SIGNATURE.as_bytes()),
                format!(
                    "0x{}{}",
                    "00".repeat(12),
                    prepared.envelope.manager.trim_start_matches("0x")
                ),
                format!(
                    "0x{:064x}",
                    match spec.action {
                        PublicationAction::MaterializeNative => 0,
                        PublicationAction::MaterializeErc20 => 1,
                        _ => unreachable!("materialize arm"),
                    }
                ),
                prepared.binding.funding_aux_data.clone(),
            ],
        ),
        PublicationAction::PullNative => (
            prepared.envelope.manager.clone(),
            vec![
                keccak_hex(b"ChannelFundsPulled(uint32,uint256,uint256)"),
                format!("0x{:064x}", 0),
            ],
        ),
        PublicationAction::PullErc20 { token_index } => (
            prepared.envelope.manager.clone(),
            vec![
                keccak_hex(b"ChannelFundsPulled(uint32,uint256,uint256)"),
                format!("0x{token_index:064x}"),
            ],
        ),
    }
}

fn semantic_event_logs(
    rpc: &str,
    address: &str,
    topics: &[String],
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Value>> {
    if from_block > to_block {
        return Ok(Vec::new());
    }
    let mut all = Vec::new();
    let mut start = from_block;
    loop {
        let end = start
            .saturating_add(EVENT_LOG_BLOCK_SPAN.saturating_sub(1))
            .min(to_block);
        let filter = serde_json::json!({
            "fromBlock": format!("0x{start:x}"),
            "toBlock": format!("0x{end:x}"),
            "address": address,
            "topics": topics,
        })
        .to_string();
        let raw = cast_output(
            &["rpc", "eth_getLogs", &filter, "--rpc-url", rpc],
            "discover semantic completion events",
            MAX_RPC_JSON_BYTES,
        )?;
        let mut logs: Vec<Value> = serde_json::from_str(raw.trim()).map_err(|error| {
            CloseFundingPublisherError::Evidence(format!(
                "parse semantic completion event logs: {error}"
            ))
        })?;
        if all.len().saturating_add(logs.len()) > 100_000 {
            return Err(CloseFundingPublisherError::Evidence(
                "semantic completion event result exceeds safety limit".into(),
            ));
        }
        all.append(&mut logs);
        if end == to_block {
            break;
        }
        start = end.checked_add(1).ok_or_else(|| {
            CloseFundingPublisherError::Evidence(
                "semantic completion event range overflowed".into(),
            )
        })?;
    }
    Ok(all)
}

fn validate_stored_confirmation(
    action: &PublicationAction,
    stored: &StepConfirmation,
    current: &StepConfirmation,
) -> Result<()> {
    checkpoint_advances(
        &stored.receipt.finalized_checkpoint,
        &current.receipt.finalized_checkpoint,
    )
    .map_err(CloseFundingPublisherError::Evidence)?;
    if !same_hex(
        &stored.receipt.transaction_hash,
        &current.receipt.transaction_hash,
    ) || !same_hex(&stored.receipt.block_hash, &current.receipt.block_hash)
        || stored.receipt.block_number != current.receipt.block_number
        || stored.receipt_evidence_digest != current.receipt_evidence_digest
        || stored.post_state_digest != current.post_state_digest
    {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "stored confirmation for {} was orphaned or changed",
            action.id()
        )));
    }
    Ok(())
}

fn confirm_semantic_transaction(
    config: &CloseFundingPublisherConfig,
    prepared: &PreparedPayout,
    spec: &ActionSpec,
    transaction_hash: &str,
) -> Result<StepConfirmation> {
    let first_transaction =
        rpc_transaction(&config.rpc_url, transaction_hash)?.ok_or_else(|| {
            CloseFundingPublisherError::Evidence(format!(
                "semantic completion transaction {transaction_hash} disappeared"
            ))
        })?;
    let (receipt, finalized) = wait_for_finalized_receipt(
        config,
        prepared.envelope.chain_id,
        transaction_hash,
        None,
        None,
    )?;
    validate_semantic_transaction(
        &first_transaction,
        &receipt,
        transaction_hash,
        &finalized.block_hash,
        finalized.block_number,
    )
    .map_err(CloseFundingPublisherError::Evidence)?;
    let (receipt_evidence_digest, post_state_digest) =
        validate_action_evidence(config, prepared, spec, &receipt, &finalized)?;
    let second_transaction =
        rpc_transaction(&config.rpc_url, transaction_hash)?.ok_or_else(|| {
            CloseFundingPublisherError::Evidence(
                "semantic completion transaction disappeared during read-back".into(),
            )
        })?;
    if !stable_transaction_fields(&first_transaction, &second_transaction) {
        return Err(CloseFundingPublisherError::Evidence(
            "semantic completion transaction changed during read-back".into(),
        ));
    }
    Ok(StepConfirmation {
        receipt: finalized,
        receipt_evidence_digest,
        post_state_digest,
    })
}

fn discover_semantic_completion(
    config: &CloseFundingPublisherConfig,
    prepared: &PreparedPayout,
    spec: &ActionSpec,
) -> Result<Option<AdoptedActionStep>> {
    let durable = read_durable_checkpoint(
        &config.rpc_url,
        prepared.envelope.chain_id,
        config.allow_unfinalized_devnet,
    )?;
    let from_block = prepared.manifest.value.event_scan_start_block;
    if from_block > durable.block_number {
        return Err(CloseFundingPublisherError::Configuration(format!(
            "eventScanStartBlock {from_block} is above durable head {}",
            durable.block_number
        )));
    }
    let (address, topics) = semantic_event_filter(prepared, spec);
    let logs = semantic_event_logs(
        &config.rpc_url,
        &address,
        &topics,
        from_block,
        durable.block_number,
    )?;
    let mut hashes = BTreeSet::new();
    for log in logs {
        if log.get("removed").and_then(Value::as_bool).unwrap_or(false) {
            continue;
        }
        let hash = require_nonzero_hex(
            log.get("transactionHash")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            32,
            "semantic event transaction hash",
        )
        .map_err(CloseFundingPublisherError::Evidence)?;
        hashes.insert(hash);
    }
    let mut matches = Vec::new();
    for transaction_hash in hashes {
        let confirmation =
            match confirm_semantic_transaction(config, prepared, spec, &transaction_hash) {
                Ok(confirmation) => confirmation,
                // The topic filter intentionally matches other channels/tokens in the same
                // contracts. They are non-candidates; an exact candidate is
                // accepted only after every validator.
                Err(CloseFundingPublisherError::Evidence(_)) => continue,
                Err(error) => return Err(error),
            };
        matches.push(AdoptedActionStep {
            action: spec.action.clone(),
            target: spec.target.clone(),
            selector: spec.calldata[..10].to_ascii_lowercase(),
            calldata_hash: spec.calldata_hash.clone(),
            value: "0".into(),
            confirmation,
        });
    }
    if matches.len() > 1 {
        return Err(CloseFundingPublisherError::Conflict(format!(
            "multiple exact finalized transactions claim semantic action {}",
            spec.action.id()
        )));
    }
    Ok(matches.pop())
}

fn validate_adopted_step(
    config: &CloseFundingPublisherConfig,
    prepared: &PreparedPayout,
    spec: &ActionSpec,
    adopted: &AdoptedActionStep,
) -> Result<StepConfirmation> {
    validate_adopted_binding(spec, adopted).map_err(CloseFundingPublisherError::Conflict)?;
    revalidate_checkpoint(
        &config.rpc_url,
        &adopted.confirmation.receipt.finalized_checkpoint,
    )?;
    let current = confirm_semantic_transaction(
        config,
        prepared,
        spec,
        &adopted.confirmation.receipt.transaction_hash,
    )?;
    validate_stored_confirmation(&spec.action, &adopted.confirmation, &current)?;
    Ok(current)
}

fn validate_adopted_binding(
    spec: &ActionSpec,
    adopted: &AdoptedActionStep,
) -> std::result::Result<(), String> {
    if adopted.action != spec.action
        || !same_hex(&adopted.target, &spec.target)
        || !same_hex(&adopted.selector, &spec.calldata[..10])
        || !same_hex(&adopted.calldata_hash, &spec.calldata_hash)
        || adopted.value != "0"
    {
        return Err(format!(
            "adopted step {} differs from exact action binding",
            spec.action.id()
        ));
    }
    Ok(())
}

fn confirm_or_revalidate_step(
    config: &CloseFundingPublisherConfig,
    prepared: &PreparedPayout,
    signer: &str,
    spec: &ActionSpec,
    step: &RawTransactionStep,
) -> Result<StepConfirmation> {
    let (receipt, finalized) = wait_for_finalized_receipt(
        config,
        prepared.envelope.chain_id,
        &step.transaction_hash,
        Some(signer),
        Some(&step.target),
    )?;
    let (receipt_evidence_digest, post_state_digest) =
        validate_action_evidence(config, prepared, spec, &receipt, &finalized)?;
    let current = StepConfirmation {
        receipt: finalized,
        receipt_evidence_digest,
        post_state_digest,
    };
    if let Some(stored) = &step.confirmation {
        revalidate_checkpoint(&config.rpc_url, &stored.receipt.finalized_checkpoint)?;
        validate_stored_confirmation(&spec.action, stored, &current)?;
    }
    Ok(current)
}

fn write_journal(path: &Path, journal: &PublicationJournal) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).map_err(|error| {
        CloseFundingPublisherError::Journal(format!("serialize close-funding WAL: {error}"))
    })?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(CloseFundingPublisherError::Journal(format!(
            "close-funding WAL exceeds {MAX_JOURNAL_BYTES} bytes"
        )));
    }
    atomic_write_private(path, &bytes)
}

fn validate_binding_digest(binding: &PublicationBinding) -> std::result::Result<(), String> {
    if binding.schema_version != 2 {
        return Err("publication binding uses a retired pre-materializer schema".into());
    }
    let mut unsigned = binding.clone();
    let actual = unsigned.binding_digest.clone();
    unsigned.binding_digest.clear();
    let value = serde_json::to_value(&unsigned)
        .map_err(|error| format!("serialize publication binding: {error}"))?;
    let expected = stable_request_id("close-funding-publication-binding-v2", &value);
    if actual != expected {
        return Err("publication binding digest does not match its fields".into());
    }
    Ok(())
}

fn load_or_create_journal(
    path: &Path,
    binding: &PublicationBinding,
    signer: &str,
    signer_lock_root: &str,
    specs: &[ActionSpec],
) -> Result<PublicationJournal> {
    if !path.is_absolute() {
        return Err(CloseFundingPublisherError::Configuration(
            "journal path must be absolute".into(),
        ));
    }
    if inspect_regular_file(path, MAX_JOURNAL_BYTES, true)?.is_some() {
        let bytes = read_bounded(path, MAX_JOURNAL_BYTES, "close-funding WAL", true)?;
        let journal: PublicationJournal = serde_json::from_slice(&bytes).map_err(|error| {
            CloseFundingPublisherError::Journal(format!(
                "parse close-funding WAL {}: {error}",
                path.display()
            ))
        })?;
        validate_binding_digest(&journal.binding).map_err(CloseFundingPublisherError::Conflict)?;
        if journal.version != JOURNAL_VERSION
            || journal.binding != *binding
            || !same_hex(&journal.signer, signer)
            || journal.signer_lock_root != signer_lock_root
        {
            return Err(CloseFundingPublisherError::Conflict(
                "WAL belongs to a sibling chain/channel/deployment/artifact/signer/lock root"
                    .into(),
            ));
        }
        let allowed = specs
            .iter()
            .map(|spec| spec.action.id())
            .collect::<BTreeSet<_>>();
        if journal.steps.keys().any(|key| !allowed.contains(key))
            || journal
                .steps
                .iter()
                .any(|(key, step)| *key != step.action.id())
            || journal
                .adopted_steps
                .keys()
                .any(|key| !allowed.contains(key))
            || journal
                .adopted_steps
                .iter()
                .any(|(key, step)| *key != step.action.id())
            || journal.steps.iter().any(|(key, step)| {
                (step.confirmation.is_some() && step.superseded_confirmation.is_some())
                    || (step.superseded_confirmation.is_some()
                        && !journal.adopted_steps.contains_key(key))
            })
        {
            return Err(CloseFundingPublisherError::Conflict(
                "WAL contains an unknown, mis-keyed, or contradictory action".into(),
            ));
        }
        return Ok(journal);
    }
    validate_binding_digest(binding).map_err(CloseFundingPublisherError::Artifact)?;
    let journal = PublicationJournal {
        version: JOURNAL_VERSION,
        binding: binding.clone(),
        signer: signer.to_ascii_lowercase(),
        signer_lock_root: signer_lock_root.into(),
        steps: BTreeMap::new(),
        adopted_steps: BTreeMap::new(),
        completed: None,
    };
    write_journal(path, &journal)?;
    Ok(journal)
}

#[cfg(unix)]
struct AdvisoryLock {
    _file: fs::File,
}

#[cfg(unix)]
impl AdvisoryLock {
    fn acquire(base: &Path) -> Result<Self> {
        let filename = base
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                CloseFundingPublisherError::Configuration(format!(
                    "lock base {} has no UTF-8 filename",
                    base.display()
                ))
            })?;
        let lock_path = base.with_file_name(format!("{filename}.lock"));
        let parent = lock_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            CloseFundingPublisherError::Journal(format!("create {}: {error}", parent.display()))
        })?;
        inspect_regular_file(&lock_path, 4096, true)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|error| {
                CloseFundingPublisherError::Journal(format!(
                    "open lock {}: {error}",
                    lock_path.display()
                ))
            })?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(CloseFundingPublisherError::Conflict(format!(
                "another publisher holds {}",
                lock_path.display()
            )));
        }
        Ok(Self { _file: file })
    }
}

#[cfg(not(unix))]
struct AdvisoryLock;

#[cfg(not(unix))]
impl AdvisoryLock {
    fn acquire(_base: &Path) -> Result<Self> {
        Err(CloseFundingPublisherError::Configuration(
            "production close-funding publisher requires Unix advisory file locks".into(),
        ))
    }
}

fn journal_lock_base(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(CloseFundingPublisherError::Configuration(
            "journal path must be absolute".into(),
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            CloseFundingPublisherError::Configuration(
                "absolute journal path has no parent directory".into(),
            )
        })?;
    let filename = path.file_name().ok_or_else(|| {
        CloseFundingPublisherError::Configuration("journal path has no filename".into())
    })?;
    Ok(ensure_private_directory(parent)?.join(filename))
}

fn signer_lock_base(lock_root: &Path, chain_id: u64, signer: &str) -> Result<PathBuf> {
    let signer = normalize_hex(signer, 20, "signer lock address")
        .map_err(CloseFundingPublisherError::Configuration)?;
    Ok(lock_root.join(format!(
        ".intmax-l1-signer-{chain_id}-{}",
        signer.trim_start_matches("0x")
    )))
}

fn revalidate_preflight(
    config: &CloseFundingPublisherConfig,
    prepared: &PreparedPayout,
    spec: &ActionSpec,
    step: &RawTransactionStep,
) -> Result<()> {
    revalidate_checkpoint(&config.rpc_url, &step.preflight_checkpoint)?;
    validate_deployment_at(config, prepared, &step.preflight_checkpoint)?;
    let snapshot = read_chain_snapshot_at(config, prepared, step.preflight_checkpoint)?;
    validate_preflight_action(spec, &snapshot, prepared)
        .map_err(CloseFundingPublisherError::Conflict)?;
    if snapshot_digest(&snapshot)? != step.preflight_state_digest {
        return Err(CloseFundingPublisherError::Conflict(format!(
            "historical preflight for {} differs from WAL",
            spec.action.id()
        )));
    }
    Ok(())
}

fn validate_completed_state(
    prepared: &PreparedPayout,
    snapshot: &ChainSnapshot,
) -> std::result::Result<(), String> {
    if snapshot.channel_status != 2 || !snapshot.anchor_finalized {
        return Err("completion state is not Closed/finalized".into());
    }
    for (token_index, plan) in &prepared.token_plans {
        let state = snapshot
            .tokens
            .get(token_index)
            .ok_or_else(|| format!("completion state lacks token {token_index}"))?;
        let amount = quantity_biguint(&plan.amount, "payout amount")?;
        if quantity_biguint(&state.cap, "manager cap")? != amount
            || quantity_biguint(&state.received, "manager received")? != amount
            || state.authorization
        {
            return Err(format!(
                "token {token_index} is not atomically materialized and cap-funded"
            ));
        }
        assert_backing_invariant(state)?;
    }
    Ok(())
}

/// Publish one exact terminal close-funding artifact. Safe retries must reuse the same journal.
pub fn publish_close_funding(
    config: &CloseFundingPublisherConfig,
) -> Result<CloseFundingPublication> {
    if config.rpc_url.trim().is_empty() || config.finality_timeout.is_zero() {
        return Err(CloseFundingPublisherError::Configuration(
            "RPC URL must be nonempty and finality timeout must be positive".into(),
        ));
    }
    let journal_path = journal_lock_base(&config.journal_path)?;
    let _journal_lock = AdvisoryLock::acquire(&journal_path)?;
    let prepared = prepare_payout(config)?;
    let observed_chain = rpc_chain_id(&config.rpc_url)?;
    if observed_chain != prepared.envelope.chain_id {
        return Err(CloseFundingPublisherError::Evidence(format!(
            "RPC chain {observed_chain} differs from payout chain {}",
            prepared.envelope.chain_id
        )));
    }
    let signer = L1Signer::resolve(observed_chain, config.account.as_deref())?;
    let signer_address = signer.address()?;
    let signer_lock_root = ensure_private_directory(&config.lock_root)?;
    let signer_lock_root_text = signer_lock_root.to_str().ok_or_else(|| {
        CloseFundingPublisherError::Configuration(
            "canonical signer lock root is not a UTF-8 path".into(),
        )
    })?;
    let _signer_lock = AdvisoryLock::acquire(&signer_lock_base(
        &signer_lock_root,
        observed_chain,
        &signer_address,
    )?)?;
    let specs = action_specs(&prepared);
    let mut journal = load_or_create_journal(
        &journal_path,
        &prepared.binding,
        &signer_address,
        signer_lock_root_text,
        &specs,
    )?;

    validate_acknowledgement_on_l1(config, &prepared)?;
    for spec in &specs {
        let id = spec.action.id();
        let reservation = close_funding_signer_reservation(
            prepared.envelope.chain_id,
            &signer_address,
            &journal_path,
            &journal.binding,
            spec,
        )?;
        validate_journal_prerequisites(&journal, &prepared, spec)
            .map_err(CloseFundingPublisherError::Conflict)?;
        let decision = resume_decision(journal.steps.get(&id), journal.adopted_steps.get(&id));

        if decision == ResumeDecision::RevalidateAdopted {
            let adopted = journal.adopted_steps.get(&id).cloned().ok_or_else(|| {
                CloseFundingPublisherError::Journal(format!("WAL lost adopted action {id}"))
            })?;
            let confirmation = validate_adopted_step(config, &prepared, spec, &adopted)?;
            let mut journal_changed = false;
            let mut local_raw_needs_reservation = false;
            if let Some(step) = journal.steps.get(&id) {
                validate_persisted_step(step, spec, prepared.envelope.chain_id, &signer_address)?;
                if same_hex(
                    &step.transaction_hash,
                    &adopted.confirmation.receipt.transaction_hash,
                ) {
                    return Err(CloseFundingPublisherError::Conflict(format!(
                        "action {id} is recorded as both local and adopted with the same transaction"
                    )));
                }
                local_raw_needs_reservation = step.superseded_confirmation.is_none();
                if local_raw_needs_reservation {
                    claim_signer_reservation(&signer_lock_root, &reservation)?;
                }
                let superseded = ensure_superseded_raw_settled(
                    config,
                    prepared.envelope.chain_id,
                    &signer_address,
                    step,
                )?;
                if step.superseded_confirmation.as_ref() != Some(&superseded) {
                    journal
                        .steps
                        .get_mut(&id)
                        .expect("local superseded step remains present")
                        .superseded_confirmation = Some(superseded);
                    journal_changed = true;
                }
            }
            if adopted.confirmation != confirmation {
                journal
                    .adopted_steps
                    .get_mut(&id)
                    .expect("adopted step remains present")
                    .confirmation = confirmation;
                journal_changed = true;
            }
            if journal_changed {
                // Both the adopted semantic winner and any canonical-finalized local loser are
                // durable before the signer lane can advance to the next action.
                write_journal(&journal_path, &journal)?;
            }
            if local_raw_needs_reservation {
                release_signer_reservation(&signer_lock_root, &reservation)?;
            } else {
                release_exact_signer_reservation(&signer_lock_root, &reservation)?;
            }
            continue;
        }

        if decision != ResumeDecision::RevalidateConfirmed {
            if let Some(step) = journal.steps.get(&id) {
                claim_signer_reservation(&signer_lock_root, &reservation)?;
                validate_persisted_step(step, spec, prepared.envelope.chain_id, &signer_address)?;
                revalidate_preflight(config, &prepared, spec, step)?;
            }
            if let Some(adopted) = discover_semantic_completion(config, &prepared, spec)? {
                if let Some(step) = journal.steps.get(&id) {
                    if same_hex(
                        &step.transaction_hash,
                        &adopted.confirmation.receipt.transaction_hash,
                    ) {
                        // Generic discovery may find our own already-finalized transaction after a
                        // crash. Re-run the signer-pinned path and keep it as a local confirmation.
                        let confirmation = confirm_or_revalidate_step(
                            config,
                            &prepared,
                            &signer_address,
                            spec,
                            step,
                        )?;
                        journal
                            .steps
                            .get_mut(&id)
                            .expect("local step remains present")
                            .confirmation = Some(confirmation);
                        write_journal(&journal_path, &journal)?;
                        release_signer_reservation(&signer_lock_root, &reservation)?;
                        continue;
                    }
                }
                journal.adopted_steps.insert(id.clone(), adopted);
                // Persist external semantic evidence before resolving an already-signed loser.
                // A crash here is harmless: discovery is deterministic and finalized-only.
                write_journal(&journal_path, &journal)?;
                if let Some(step) = journal.steps.get(&id) {
                    let superseded = ensure_superseded_raw_settled(
                        config,
                        prepared.envelope.chain_id,
                        &signer_address,
                        step,
                    )?;
                    journal
                        .steps
                        .get_mut(&id)
                        .expect("local superseded step remains present")
                        .superseded_confirmation = Some(superseded);
                    write_journal(&journal_path, &journal)?;
                    release_signer_reservation(&signer_lock_root, &reservation)?;
                } else {
                    // This also cleans up an exact reservation left by a crash after claim but
                    // before raw signing/WAL. A foreign phase is never removed.
                    release_exact_signer_reservation(&signer_lock_root, &reservation)?;
                }
                continue;
            }
        }

        match decision {
            ResumeDecision::SignNew => {
                let checkpoint = read_durable_checkpoint(
                    &config.rpc_url,
                    prepared.envelope.chain_id,
                    config.allow_unfinalized_devnet,
                )?;
                validate_deployment_at(config, &prepared, &checkpoint)?;
                let snapshot = read_chain_snapshot_at(config, &prepared, checkpoint)?;
                validate_preflight_action(spec, &snapshot, &prepared)
                    .map_err(CloseFundingPublisherError::Conflict)?;
                let step = sign_after_reservation(&signer_lock_root, &reservation, || {
                    sign_transaction(config, &signer, &signer_address, spec, &snapshot)
                })?;
                // THE irreversible boundary: persist and fsync the complete raw transaction
                // before any network API is allowed to observe it.
                journal.steps.insert(id.clone(), step);
                write_journal(&journal_path, &journal)?;
            }
            ResumeDecision::ReplayExact | ResumeDecision::RevalidateConfirmed => {}
            ResumeDecision::RevalidateAdopted => unreachable!("handled above"),
        }
        let step =
            journal.steps.get(&id).cloned().ok_or_else(|| {
                CloseFundingPublisherError::Journal(format!("WAL lost action {id}"))
            })?;
        validate_persisted_step(&step, spec, prepared.envelope.chain_id, &signer_address)?;
        revalidate_preflight(config, &prepared, spec, &step)?;
        if decision != ResumeDecision::RevalidateConfirmed {
            publish_exact_raw(&config.rpc_url, &signer_address, &step)?;
        }
        let confirmation =
            confirm_or_revalidate_step(config, &prepared, &signer_address, spec, &step)?;
        if step.confirmation.as_ref() != Some(&confirmation) {
            journal
                .steps
                .get_mut(&id)
                .expect("step remains present")
                .confirmation = Some(confirmation);
            write_journal(&journal_path, &journal)?;
        }
        if decision == ResumeDecision::RevalidateConfirmed {
            release_exact_signer_reservation(&signer_lock_root, &reservation)?;
        } else {
            release_signer_reservation(&signer_lock_root, &reservation)?;
        }
    }

    let checkpoint = read_durable_checkpoint(
        &config.rpc_url,
        prepared.envelope.chain_id,
        config.allow_unfinalized_devnet,
    )?;
    validate_deployment_at(config, &prepared, &checkpoint)?;
    let snapshot = read_chain_snapshot_at(config, &prepared, checkpoint)?;
    validate_completed_state(&prepared, &snapshot).map_err(CloseFundingPublisherError::Evidence)?;
    let publication = CloseFundingPublication {
        schema_version: 2,
        chain_id: prepared.envelope.chain_id,
        channel_id: prepared.envelope.channel_id,
        rollup: prepared.envelope.rollup.clone(),
        manager: prepared.envelope.manager.clone(),
        materializer: prepared.manifest.value.materializer.clone(),
        payout_artifact_hash: prepared.envelope.artifact_hash.clone(),
        validity_acknowledgement_hash: prepared.envelope.validity_acknowledgement_hash.clone(),
        binding_digest: prepared.binding.binding_digest.clone(),
        transactions: specs
            .iter()
            .map(|spec| {
                let id = spec.action.id();
                journal
                    .adopted_steps
                    .get(&id)
                    .map(|step| step.confirmation.receipt.transaction_hash.clone())
                    .or_else(|| {
                        journal
                            .steps
                            .get(&id)
                            .map(|step| step.transaction_hash.clone())
                    })
                    .ok_or_else(|| {
                        CloseFundingPublisherError::Journal(format!(
                            "completed publication lacks semantic action {id}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>>>()?,
        finalized_checkpoint: checkpoint,
        public_e2e_attested: false,
    };
    if let Some(stored) = &journal.completed {
        let mut normalized_current = publication.clone();
        normalized_current.finalized_checkpoint = stored.finalized_checkpoint;
        checkpoint_advances(
            &stored.finalized_checkpoint,
            &publication.finalized_checkpoint,
        )
        .map_err(CloseFundingPublisherError::Evidence)?;
        if stored != &normalized_current {
            return Err(CloseFundingPublisherError::Conflict(
                "stored completion differs from current canonical evidence".into(),
            ));
        }
    }
    if journal.completed.as_ref() != Some(&publication) {
        journal.completed = Some(publication.clone());
        write_journal(&journal_path, &journal)?;
    }
    Ok(publication)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_word(tag: u8) -> String {
        format!("0x{}", hex::encode([tag; 32]))
    }

    fn hex_address(tag: u8) -> String {
        format!("0x{}", hex::encode([tag; 20]))
    }

    fn checkpoint(block_number: u64, tag: u8) -> L1FinalizedCheckpoint {
        L1FinalizedCheckpoint {
            chain_id: 1,
            block_number,
            block_hash: Bytes32::from_str(&hex_word(tag)).unwrap(),
            parent_hash: Bytes32::from_str(&hex_word(tag.wrapping_sub(1).max(1))).unwrap(),
            source: L1FinalitySource::RpcFinalized,
        }
    }

    fn mle_json(withdrawals: &[Withdrawal], prover: Address, anchor: &PayoutAnchor) -> String {
        let mut withdrawal_hash = Bytes32::default();
        for withdrawal in withdrawals {
            withdrawal_hash = withdrawal.hash_with_prev_hash(withdrawal_hash);
        }
        let inputs = WithdrawalProofPublicInputs {
            withdrawal_hash,
            withdrawal_prover: prover,
            ext_public_state_commitment: Bytes32::from_str(&anchor.extended_state_commitment)
                .unwrap(),
            block_number: BlockNumber::new(anchor.block_number).unwrap(),
        };
        let mut public_inputs = inputs
            .hash()
            .to_u32_vec()
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        public_inputs.extend(
            inputs
                .ext_public_state_commitment
                .to_u32_vec()
                .into_iter()
                .map(|value| value.to_string()),
        );
        public_inputs.push(inputs.block_number.as_u64().to_string());
        serde_json::json!({
            "protocolVersion": 1,
            "constituentWidth": 160,
            "publicInputs": public_inputs,
        })
        .to_string()
    }

    fn lane_value(
        lane: PartialWithdrawalLane,
        token_index: u32,
        amount: u64,
        nullifier_tag: u8,
        manager: &str,
        prover: &str,
        aux: &str,
        anchor: &PayoutAnchor,
    ) -> Value {
        let withdrawal = Withdrawal {
            recipient: Address::from_str(manager).unwrap(),
            token_index,
            amount: U256::from(amount),
            nullifier: Bytes32::from_str(&hex_word(nullifier_tag)).unwrap(),
            aux_data: Bytes32::from_str(aux).unwrap(),
        };
        let payout = serde_json::json!({
            "withdrawals": [{
                "recipient": manager,
                "token_index": token_index,
                "amount": amount.to_string(),
                "nullifier": hex_word(nullifier_tag),
                "aux_data": aux,
            }],
            "withdrawal_prover": prover,
            "block_number": anchor.block_number,
            "ext_commitment": anchor.extended_state_commitment,
        })
        .to_string();
        let mle = mle_json(&[withdrawal], Address::from_str(prover).unwrap(), anchor);
        serde_json::json!({
            "lane": match lane { PartialWithdrawalLane::Native => "native", PartialWithdrawalLane::Erc20 => "erc20" },
            "withdrawals": [{
                "recipient": manager,
                "tokenIndex": token_index,
                "amount": amount.to_string(),
                "nullifier": hex_word(nullifier_tag),
                "auxData": aux,
            }],
            "withdrawalProver": prover,
            "payoutJson": payout,
            "withdrawalMleJson": mle,
            "producerAnchor": anchor,
            "metrics": {
                "singleWithdrawalMillis": 1,
                "withdrawalChainMillis": 1,
                "withdrawalFinalMillis": 1,
                "wrapMleMillis": 1,
                "singleWithdrawalProofBytes": 1,
                "withdrawalChainProofBytes": 1,
                "withdrawalFinalProofBytes": 1,
                "mleJsonBytes": mle.len(),
                "peakRssBytes": null,
            },
        })
    }

    fn manifest_value(chain_id: u64, rollup: &str, manager: &str, verifier: &str) -> Value {
        serde_json::json!({
            "schemaVersion": 2,
            "chainId": chain_id,
            "rollup": rollup,
            "rollupRuntimeCodeHash": hex_word(0x31),
            "manager": manager,
            "eventScanStartBlock": 1,
            "managerRuntimeCodeHash": hex_word(0x32),
            "materializer": hex_address(0x66),
            "materializerRuntimeCodeHash": hex_word(0x36),
            "verifier": verifier,
            "verifierRuntimeCodeHash": hex_word(0x33),
            "mleVerifier": hex_address(0x44),
            "mleVerifierRuntimeCodeHash": hex_word(0x34),
            "mleProofAbiVersion": 2,
            "mleProtocolVersion": 1,
            "mleConstituentWidth": 160,
            "materializeNativeSelector": MATERIALIZE_NATIVE_SELECTOR,
            "materializeErc20Selector": MATERIALIZE_ERC20_SELECTOR,
            "pullChannelFundsSelector": selector(PULL_NATIVE_SIGNATURE),
            "pullChannelTokenFundsSelector": selector(PULL_ERC20_SIGNATURE),
            "rollupWithdrawExactSelector": selector(ROLLUP_PULL_NATIVE_SIGNATURE),
            "rollupWithdrawTokenExactSelector": selector(ROLLUP_PULL_ERC20_SIGNATURE),
            "tokens": [{
                "tokenIndex": 7,
                "token": hex_address(0x77),
                "runtimeCodeHash": hex_word(0x37),
            }],
        })
    }

    fn artifact_value() -> (Value, Value) {
        let chain_id = 1;
        let manager = hex_address(0x22);
        let rollup = hex_address(0x11);
        let verifier = hex_address(0x33);
        let prover = hex_address(0x55);
        let aux = hex_word(0xa1);
        let anchor = PayoutAnchor {
            generation: 9,
            entry_hash: hex_word(0x91),
            block_number: 10,
            timestamp: 1000,
            extended_state_commitment: hex_word(0x92),
            bp_sig_chain: hex_word(0x93),
        };
        let artifacts = serde_json::json!({
            "planDigest": hex_word(0xa2),
            "fundingAuxData": aux,
            "lanes": [
                lane_value(PartialWithdrawalLane::Native, 0, 30, 0xb0, &manager, &prover, &aux, &anchor),
                lane_value(PartialWithdrawalLane::Erc20, 7, 40, 0xb7, &manager, &prover, &aux, &anchor),
            ],
        });
        let artifact_hash = stable_request_id("close-funding-payout", &artifacts);
        let envelope = serde_json::json!({
            "schemaVersion": 2,
            "channelId": 5,
            "chainId": chain_id,
            "rollup": rollup,
            "manager": manager,
            "verifier": verifier,
            "proposalHash": "close-funding-proposal:test",
            "producerRequestId": "close-funding-commit:test",
            "validityAcknowledgementHash": format!("close-funding-validity-acknowledgement-v2:{}", "aa".repeat(32)),
            "withdrawalProver": prover,
            "artifactHash": artifact_hash,
            "artifacts": artifacts,
        });
        (
            envelope,
            manifest_value(chain_id, &rollup, &manager, &verifier),
        )
    }

    fn rehash_artifact(value: &mut Value) {
        let hash = stable_request_id("close-funding-payout", &value["artifacts"]);
        value["artifactHash"] = Value::String(hash);
    }

    fn acknowledgement_fixture() -> (PayoutEnvelope, PayoutAnchor, Value) {
        let (artifact, _) = artifact_value();
        let mut envelope: PayoutEnvelope = serde_json::from_value(artifact).unwrap();
        let anchor = envelope.artifacts.lanes[0].producer_anchor.clone();
        let candidate_id = hex_word(0xc1);
        let transaction_hash = hex_word(0xc2);
        let acknowledgement_request_id = stable_request_id(
            "close-funding-validity-ack-v2",
            &serde_json::json!({
                "channelId": envelope.channel_id,
                "proposalHash": envelope.proposal_hash,
                "producerRequestId": envelope.producer_request_id,
                "candidateId": candidate_id,
                "transactionHash": transaction_hash,
            }),
        );
        let committed = serde_json::json!({
            "requestId": envelope.producer_request_id,
            "generation": anchor.generation,
            "entryHash": anchor.entry_hash,
            "blockNumber": anchor.block_number,
            "timestamp": anchor.timestamp,
            "extendedStateCommitment": anchor.extended_state_commitment,
            "bpSigChain": anchor.bp_sig_chain,
        });
        let mut acknowledgement = serde_json::json!({
            "schemaVersion": ENVELOPE_SCHEMA_VERSION,
            "channelId": envelope.channel_id,
            "chainId": envelope.chain_id,
            "rollup": envelope.rollup,
            "manager": envelope.manager,
            "verifier": envelope.verifier,
            "proposalHash": envelope.proposal_hash,
            "producerRequestId": envelope.producer_request_id,
            "acknowledgementRequestId": acknowledgement_request_id,
            "candidateId": candidate_id,
            "transactionHash": transaction_hash,
            "receipt": {
                "requestId": acknowledgement_request_id,
                "candidateId": candidate_id,
                "producerAnchor": anchor,
                "finalizedBlockNumber": anchor.block_number,
                "finalExtendedStateCommitment": anchor.extended_state_commitment,
                "committedProducerReceipt": committed,
                "l1Acknowledgement": {
                    "chainId": envelope.chain_id,
                    "transactionHash": transaction_hash,
                    "blockHash": hex_word(0xc3),
                    "blockNumber": 11,
                    "finalExtendedStateCommitment": anchor.extended_state_commitment,
                    "finalizedCheckpoint": checkpoint(12, 0xc4),
                },
            },
        });
        let artifact_hash = stable_request_id(
            "close-funding-validity-acknowledgement-v2",
            &acknowledgement,
        );
        acknowledgement["artifactHash"] = Value::String(artifact_hash.clone());
        envelope.validity_acknowledgement_hash = artifact_hash;
        (envelope, anchor, acknowledgement)
    }

    fn rehash_acknowledgement(value: &mut Value) -> String {
        let mut unsigned = value.clone();
        unsigned
            .as_object_mut()
            .expect("acknowledgement fixture is an object")
            .remove("artifactHash");
        let hash = stable_request_id("close-funding-validity-acknowledgement-v2", &unsigned);
        value["artifactHash"] = Value::String(hash.clone());
        hash
    }

    fn parsed_test_prepared() -> PreparedPayout {
        let (artifact, manifest) = artifact_value();
        let (envelope, manifest, anchor, _withdrawal_prover, funding_aux_data, token_plans, lanes) =
            parse_and_validate_payout(
                serde_json::to_string(&artifact).unwrap().as_bytes(),
                serde_json::to_string(&manifest).unwrap().as_bytes(),
            )
            .unwrap();
        let prepared_lanes = envelope
            .artifacts
            .lanes
            .iter()
            .zip(lanes)
            .map(|(lane, (_, withdrawals))| {
                let calldata: String = if lane.lane == PartialWithdrawalLane::Native {
                    MATERIALIZE_NATIVE_SELECTOR.into()
                } else {
                    MATERIALIZE_ERC20_SELECTOR.into()
                };
                let calldata_hash =
                    keccak_hex(&decode_hex(&calldata, None, "fixture payout calldata").unwrap());
                PreparedLane {
                    lane: lane.lane,
                    withdrawals,
                    calldata,
                    calldata_hash,
                }
            })
            .collect::<Vec<_>>();
        let native_calldata_hash = prepared_lanes
            .iter()
            .find(|lane| lane.lane == PartialWithdrawalLane::Native)
            .map(|lane| lane.calldata_hash.clone());
        let erc20_calldata_hash = prepared_lanes
            .iter()
            .find(|lane| lane.lane == PartialWithdrawalLane::Erc20)
            .map(|lane| lane.calldata_hash.clone());
        let mut binding = PublicationBinding {
            schema_version: 2,
            chain_id: envelope.chain_id,
            channel_id: envelope.channel_id,
            rollup: envelope.rollup.clone(),
            manager: envelope.manager.clone(),
            materializer: manifest.value.materializer.clone(),
            verifier: envelope.verifier.clone(),
            mle_verifier: manifest.value.mle_verifier.clone(),
            withdrawal_prover: envelope.withdrawal_prover.clone(),
            proposal_hash: envelope.proposal_hash.clone(),
            producer_request_id: envelope.producer_request_id.clone(),
            payout_artifact_hash: envelope.artifact_hash.clone(),
            validity_acknowledgement_hash: envelope.validity_acknowledgement_hash.clone(),
            plan_digest: envelope.artifacts.plan_digest.clone(),
            funding_aux_data: envelope.artifacts.funding_aux_data.clone(),
            producer_anchor: anchor.clone(),
            deployment_manifest_hash: manifest.hash.clone(),
            token_plans: token_plans.values().cloned().collect(),
            native_calldata_hash,
            erc20_calldata_hash,
            binding_digest: String::new(),
        };
        binding.binding_digest = stable_request_id(
            "close-funding-publication-binding-v2",
            &serde_json::to_value(&binding).unwrap(),
        );
        PreparedPayout {
            envelope,
            anchor,
            funding_aux_data,
            token_plans,
            lanes: prepared_lanes,
            acknowledgement: Value::Null,
            acknowledgement_checkpoint: checkpoint(100, 100),
            manifest,
            binding,
        }
    }

    fn topic_address(address: &str) -> String {
        format!("0x{}{}", "00".repeat(12), address.trim_start_matches("0x"))
    }

    fn topic_u32_value(value: u32) -> String {
        format!("0x{}{}", "00".repeat(28), hex::encode(value.to_be_bytes()))
    }

    fn topic_u8_value(value: u8) -> String {
        format!("0x{}{:02x}", "00".repeat(31), value)
    }

    fn materialized_log(prepared: &PreparedPayout, lane: u8, digest: &str) -> Value {
        log(
            &prepared.manifest.value.materializer,
            vec![
                keccak_hex(MATERIALIZED_EVENT_SIGNATURE.as_bytes()),
                topic_address(&prepared.envelope.manager),
                topic_u8_value(lane),
                prepared.binding.funding_aux_data.clone(),
            ],
            digest.to_owned(),
        )
    }

    fn data_words(first: u64, second: u64) -> String {
        format!("0x{:064x}{:064x}", first, second)
    }

    fn log(address: &str, topics: Vec<String>, data: String) -> Value {
        serde_json::json!({
            "address": address,
            "topics": topics,
            "data": data,
            "removed": false,
        })
    }

    fn receipt(logs: Vec<Value>) -> Value {
        serde_json::json!({ "logs": logs })
    }

    fn token_state(
        token_index: u32,
        amount: u64,
        authorization: bool,
        nullifier_used: bool,
        received: u64,
        pending: u64,
        balance: u64,
    ) -> TokenChainState {
        TokenChainState {
            token_index,
            cap: amount.to_string(),
            received: received.to_string(),
            total_credited_out: "0".into(),
            authorization,
            nullifier_used,
            pending_rollup_credit: pending.to_string(),
            manager_asset_balance: balance.to_string(),
        }
    }

    fn snapshot(states: Vec<TokenChainState>) -> ChainSnapshot {
        ChainSnapshot {
            checkpoint: checkpoint(101, 101),
            channel_status: 2,
            close_freeze_nonce: 3,
            anchor_finalized: true,
            tokens: states
                .into_iter()
                .map(|state| (state.token_index, state))
                .collect(),
        }
    }

    fn spec(action: PublicationAction, token_indices: Vec<u32>) -> ActionSpec {
        ActionSpec {
            action,
            target: hex_address(1),
            calldata: "0x11111111".into(),
            calldata_hash: hex_word(1),
            token_indices,
        }
    }

    #[test]
    fn strict_artifact_binds_native_and_erc20_mle_public_inputs() {
        let (artifact, manifest) = artifact_value();
        let (_, _, _, _, _, tokens, lanes) = parse_and_validate_payout(
            serde_json::to_string(&artifact).unwrap().as_bytes(),
            serde_json::to_string(&manifest).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(tokens.keys().copied().collect::<Vec<_>>(), vec![0, 7]);
        assert_eq!(lanes.len(), 2);
    }

    #[test]
    fn deployment_manifest_requires_an_independent_raw_byte_hash_pin() {
        let (_, manifest) = artifact_value();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let pin = sha256_hex(&bytes);
        assert_eq!(validate_manifest_sha256(&bytes, &pin).unwrap(), pin);

        let mut semantically_identical = bytes.clone();
        semantically_identical.push(b'\n');
        assert!(validate_manifest_sha256(&semantically_identical, &pin).is_err());
        assert!(validate_manifest_sha256(&bytes, &hex_word(0xff)).is_err());
    }

    #[test]
    fn retired_pre_materializer_manifest_schema_is_rejected() {
        let (artifact, mut manifest) = artifact_value();
        manifest["schemaVersion"] = Value::from(1);
        assert!(
            parse_and_validate_payout(
                serde_json::to_string(&artifact).unwrap().as_bytes(),
                serde_json::to_string(&manifest).unwrap().as_bytes(),
            )
            .is_err()
        );
    }

    #[test]
    fn manifest_requires_nonzero_materializer_identity_and_both_lane_selectors() {
        let (artifact, manifest) = artifact_value();
        for (field, zero) in [
            ("materializer", format!("0x{}", "00".repeat(20))),
            ("materializerRuntimeCodeHash", hex_word(0)),
            ("materializeNativeSelector", "0x00000000".into()),
            ("materializeErc20Selector", "0x00000000".into()),
        ] {
            let mut invalid = manifest.clone();
            invalid[field] = Value::String(zero);
            assert!(
                parse_and_validate_payout(
                    serde_json::to_string(&artifact).unwrap().as_bytes(),
                    serde_json::to_string(&invalid).unwrap().as_bytes(),
                )
                .is_err(),
                "zero {field} was accepted"
            );
        }
    }

    #[test]
    fn artifact_tamper_cannot_be_hidden_by_rehashing_envelope() {
        let (artifact, manifest) = artifact_value();
        for path in ["recipient", "amount", "nullifier", "auxData"] {
            let mut tampered = artifact.clone();
            tampered["artifacts"]["lanes"][0]["withdrawals"][0][path] = match path {
                "recipient" => Value::String(hex_address(0x66)),
                "amount" => Value::String("31".into()),
                "nullifier" => Value::String(hex_word(0xcc)),
                _ => Value::String(hex_word(0xdd)),
            };
            // Keep the redundant payout JSON consistent and recompute the transport hash. The MLE
            // PI binding (or exact Manager/aux rule) must still catch the semantic mutation.
            let mut payout: Value = serde_json::from_str(
                tampered["artifacts"]["lanes"][0]["payoutJson"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            let inner = match path {
                "auxData" => "aux_data",
                other => other,
            };
            payout["withdrawals"][0][inner] =
                tampered["artifacts"]["lanes"][0]["withdrawals"][0][path].clone();
            tampered["artifacts"]["lanes"][0]["payoutJson"] = Value::String(payout.to_string());
            rehash_artifact(&mut tampered);
            assert!(
                parse_and_validate_payout(
                    serde_json::to_string(&tampered).unwrap().as_bytes(),
                    serde_json::to_string(&manifest).unwrap().as_bytes(),
                )
                .is_err(),
                "tampered {path} was accepted"
            );
        }
    }

    #[test]
    fn validity_acknowledgement_binds_request_candidate_and_transaction() {
        let (mut envelope, anchor, mut acknowledgement) = acknowledgement_fixture();
        validate_acknowledgement(
            serde_json::to_string(&acknowledgement).unwrap().as_bytes(),
            &envelope,
            &anchor,
        )
        .unwrap();

        acknowledgement["receipt"]["candidateId"] = Value::String(hex_word(0xee));
        envelope.validity_acknowledgement_hash = rehash_acknowledgement(&mut acknowledgement);
        assert!(
            validate_acknowledgement(
                serde_json::to_string(&acknowledgement).unwrap().as_bytes(),
                &envelope,
                &anchor,
            )
            .is_err()
        );

        let (mut envelope, anchor, mut acknowledgement) = acknowledgement_fixture();
        acknowledgement["acknowledgementRequestId"] = Value::String("sibling-request".into());
        acknowledgement["receipt"]["requestId"] = Value::String("sibling-request".into());
        envelope.validity_acknowledgement_hash = rehash_acknowledgement(&mut acknowledgement);
        assert!(
            validate_acknowledgement(
                serde_json::to_string(&acknowledgement).unwrap().as_bytes(),
                &envelope,
                &anchor,
            )
            .is_err()
        );
    }

    #[test]
    fn artifact_rejects_wrong_chain_address_anchor_and_transport_hash() {
        let (artifact, manifest) = artifact_value();
        let mut cases = Vec::new();
        let mut wrong_chain = artifact.clone();
        wrong_chain["chainId"] = Value::from(2);
        cases.push(wrong_chain);
        let mut wrong_manager = artifact.clone();
        wrong_manager["manager"] = Value::String(hex_address(0x99));
        cases.push(wrong_manager);
        let mut wrong_anchor = artifact.clone();
        wrong_anchor["artifacts"]["lanes"][0]["producerAnchor"]["blockNumber"] = Value::from(11);
        rehash_artifact(&mut wrong_anchor);
        cases.push(wrong_anchor);
        let mut wrong_hash = artifact.clone();
        wrong_hash["artifactHash"] = Value::String("close-funding-payout:00".into());
        cases.push(wrong_hash);
        for case in cases {
            assert!(
                parse_and_validate_payout(
                    serde_json::to_string(&case).unwrap().as_bytes(),
                    serde_json::to_string(&manifest).unwrap().as_bytes(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn complete_native_and_front_run_erc20_materialization_events_are_accepted() {
        let prepared = parsed_test_prepared();
        let native_plan = &prepared.token_plans[&0];
        let native_spec = spec(PublicationAction::MaterializeNative, vec![0]);
        let native_receipt = receipt(vec![
            log(
                &prepared.envelope.rollup,
                vec![
                    keccak_hex(b"NativeWithdrawn(address,uint256,bytes32,uint64)"),
                    topic_address(&prepared.envelope.manager),
                    native_plan.nullifier.clone(),
                ],
                data_words(30, prepared.anchor.block_number),
            ),
            materialized_log(&prepared, 0, &hex_word(0xd0)),
        ]);
        let native_marker =
            validate_materialization_event(&native_receipt, &prepared, &native_spec).unwrap();
        validate_payout_events(&native_receipt, &prepared, &native_spec, native_marker).unwrap();

        let erc_plan = &prepared.token_plans[&7];
        let erc_spec = spec(PublicationAction::MaterializeErc20, vec![7]);
        let erc_receipt = receipt(vec![
            log(
                &prepared.envelope.rollup,
                vec![
                    keccak_hex(b"Erc20Withdrawn(address,uint32,uint256,bytes32,uint64)"),
                    topic_address(&prepared.envelope.manager),
                    topic_u32_value(7),
                    // A front-run proof may use a different proof-private nullifier.
                    hex_word(0xee),
                ],
                data_words(40, prepared.anchor.block_number),
            ),
            materialized_log(&prepared, 1, &hex_word(0xd1)),
        ]);
        let erc_marker =
            validate_materialization_event(&erc_receipt, &prepared, &erc_spec).unwrap();
        validate_payout_events(&erc_receipt, &prepared, &erc_spec, erc_marker).unwrap();
        assert_ne!(erc_plan.nullifier, hex_word(0xee));
    }

    #[test]
    fn wrong_recipient_amount_token_anchor_or_log_order_is_rejected() {
        let prepared = parsed_test_prepared();
        let plan = &prepared.token_plans[&7];
        let base_topics = vec![
            keccak_hex(b"Erc20Withdrawn(address,uint32,uint256,bytes32,uint64)"),
            topic_address(&prepared.envelope.manager),
            topic_u32_value(7),
            plan.nullifier.clone(),
        ];
        let mut variants = Vec::new();
        let mut wrong_recipient = base_topics.clone();
        wrong_recipient[1] = topic_address(&hex_address(0x99));
        variants.push((wrong_recipient, data_words(40, 10)));
        let mut wrong_token = base_topics.clone();
        wrong_token[2] = topic_u32_value(8);
        variants.push((wrong_token, data_words(40, 10)));
        variants.push((base_topics.clone(), data_words(41, 10)));
        variants.push((base_topics, data_words(40, 11)));
        for (topics, data) in variants {
            let candidate = receipt(vec![
                log(&prepared.envelope.rollup, topics, data),
                materialized_log(&prepared, 1, &hex_word(0xd1)),
            ]);
            assert!(
                validate_payout_events(
                    &candidate,
                    &prepared,
                    &spec(PublicationAction::MaterializeErc20, vec![7]),
                    1,
                )
                .is_err()
            );
        }
        let reversed = receipt(vec![
            materialized_log(&prepared, 1, &hex_word(0xd1)),
            log(
                &prepared.envelope.rollup,
                vec![
                    keccak_hex(b"Erc20Withdrawn(address,uint32,uint256,bytes32,uint64)"),
                    topic_address(&prepared.envelope.manager),
                    topic_u32_value(7),
                    hex_word(0xee),
                ],
                data_words(40, prepared.anchor.block_number),
            ),
        ]);
        assert!(
            validate_payout_events(
                &reversed,
                &prepared,
                &spec(PublicationAction::MaterializeErc20, vec![7]),
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn materializer_and_exact_pull_events_bind_authoritative_fields() {
        let prepared = parsed_test_prepared();
        let materialize = spec(PublicationAction::MaterializeErc20, vec![7]);
        let (filter_address, filter_topics) = semantic_event_filter(&prepared, &materialize);
        assert!(same_hex(
            &filter_address,
            &prepared.manifest.value.materializer
        ));
        assert_eq!(filter_topics.len(), 4);
        assert!(same_hex(
            &filter_topics[3],
            &prepared.binding.funding_aux_data
        ));
        let marker = receipt(vec![materialized_log(&prepared, 1, &hex_word(0xd1))]);
        validate_materialization_event(&marker, &prepared, &materialize).unwrap();
        let alternate_proof_digest = receipt(vec![materialized_log(&prepared, 1, &hex_word(0xd2))]);
        validate_materialization_event(&alternate_proof_digest, &prepared, &materialize).unwrap();

        let wrong_lane = materialized_log(&prepared, 0, &hex_word(0xd1));
        assert!(
            validate_materialization_event(
                &receipt(vec![wrong_lane.clone()]),
                &prepared,
                &materialize
            )
            .is_err()
        );
        let mut wrong_manager = materialized_log(&prepared, 1, &hex_word(0xd1));
        wrong_manager["topics"][1] = Value::String(topic_address(&hex_address(0x99)));
        assert!(
            validate_materialization_event(&receipt(vec![wrong_manager]), &prepared, &materialize)
                .is_err()
        );
        let mut wrong_aux = materialized_log(&prepared, 1, &hex_word(0xd1));
        wrong_aux["topics"][3] = Value::String(hex_word(0xfa));
        assert!(
            validate_materialization_event(&receipt(vec![wrong_aux]), &prepared, &materialize)
                .is_err()
        );
        let mut wrong_emitter = materialized_log(&prepared, 1, &hex_word(0xd1));
        wrong_emitter["address"] = Value::String(prepared.envelope.rollup.clone());
        assert!(
            validate_materialization_event(&receipt(vec![wrong_emitter]), &prepared, &materialize)
                .is_err()
        );
        let mut malformed = materialized_log(&prepared, 1, &hex_word(0xd1));
        malformed["data"] = Value::String("0x01".into());
        assert!(
            validate_materialization_event(&receipt(vec![malformed]), &prepared, &materialize)
                .is_err()
        );

        let pull = receipt(vec![log(
            &prepared.envelope.manager,
            vec![
                keccak_hex(b"ChannelFundsPulled(uint32,uint256,uint256)"),
                topic_u32_value(7),
            ],
            data_words(40, 40),
        )]);
        validate_pull_event(&pull, &prepared, 7).unwrap();

        let wrong_total = receipt(vec![log(
            &prepared.envelope.manager,
            vec![
                keccak_hex(b"ChannelFundsPulled(uint32,uint256,uint256)"),
                topic_u32_value(7),
            ],
            data_words(40, 41),
        )]);
        assert!(validate_pull_event(&wrong_total, &prepared, 7).is_err());
    }

    #[test]
    fn semantic_event_validation_accepts_bundles_but_rejects_duplicate_exact_effects() {
        let prepared = parsed_test_prepared();
        let erc = &prepared.token_plans[&7];
        let materialize_spec = spec(PublicationAction::MaterializeErc20, vec![7]);
        let payout_logs = vec![
            log(
                &prepared.envelope.rollup,
                vec![
                    keccak_hex(b"Erc20Withdrawn(address,uint32,uint256,bytes32,uint64)"),
                    topic_address(&prepared.envelope.manager),
                    topic_u32_value(8),
                    hex_word(0xee),
                ],
                data_words(1, prepared.anchor.block_number),
            ),
            log(
                &prepared.envelope.rollup,
                vec![
                    keccak_hex(b"Erc20Withdrawn(address,uint32,uint256,bytes32,uint64)"),
                    topic_address(&prepared.envelope.manager),
                    topic_u32_value(7),
                    erc.nullifier.clone(),
                ],
                data_words(40, prepared.anchor.block_number),
            ),
            materialized_log(&prepared, 1, &hex_word(0xd1)),
        ];
        let bundled = receipt(payout_logs.clone());
        let marker =
            validate_materialization_event(&bundled, &prepared, &materialize_spec).unwrap();
        validate_payout_events(&bundled, &prepared, &materialize_spec, marker).unwrap();
        let mut duplicate_marker = payout_logs.clone();
        duplicate_marker.push(materialized_log(&prepared, 1, &hex_word(0xd2)));
        assert!(
            validate_materialization_event(
                &receipt(duplicate_marker),
                &prepared,
                &materialize_spec,
            )
            .is_err()
        );
        let mut duplicate_payout = payout_logs;
        duplicate_payout.insert(2, duplicate_payout[1].clone());
        assert!(
            validate_payout_events(&receipt(duplicate_payout), &prepared, &materialize_spec, 3,)
                .is_err()
        );

        let pull_logs = vec![
            log(
                &prepared.envelope.manager,
                vec![
                    keccak_hex(b"ChannelFundsPulled(uint32,uint256,uint256)"),
                    topic_u32_value(0),
                ],
                data_words(50, 50),
            ),
            log(
                &prepared.envelope.manager,
                vec![
                    keccak_hex(b"ChannelFundsPulled(uint32,uint256,uint256)"),
                    topic_u32_value(7),
                ],
                data_words(40, 40),
            ),
        ];
        validate_pull_event(&receipt(pull_logs.clone()), &prepared, 7).unwrap();
        let mut duplicate_pull = pull_logs;
        duplicate_pull.push(duplicate_pull[1].clone());
        assert!(validate_pull_event(&receipt(duplicate_pull), &prepared, 7).is_err());
    }

    #[test]
    fn partial_erc20_lane_cannot_be_adopted_from_event_or_receipt_block_state() {
        let mut prepared = parsed_test_prepared();
        let mut second = prepared.token_plans[&7].clone();
        second.token_index = 8;
        second.amount = "30".into();
        second.nullifier = hex_word(0xb8);
        second.auth_digest = hex_word(0xa8);
        prepared.token_plans.insert(8, second);
        let materialize = spec(PublicationAction::MaterializeErc20, vec![7, 8]);

        let receipt = receipt(vec![
            log(
                &prepared.envelope.rollup,
                vec![
                    keccak_hex(b"Erc20Withdrawn(address,uint32,uint256,bytes32,uint64)"),
                    topic_address(&prepared.envelope.manager),
                    topic_u32_value(7),
                    hex_word(0xe7),
                ],
                data_words(40, prepared.anchor.block_number),
            ),
            materialized_log(&prepared, 1, &hex_word(0xd1)),
        ]);
        let marker = validate_materialization_event(&receipt, &prepared, &materialize).unwrap();
        assert!(validate_payout_events(&receipt, &prepared, &materialize, marker).is_err());

        assert!(
            validate_post_state(
                &prepared,
                &materialize,
                &snapshot(vec![
                    token_state(7, 40, false, false, 0, 40, 0),
                    token_state(8, 30, false, false, 0, 0, 0),
                ]),
            )
            .is_err()
        );
        validate_post_state(
            &prepared,
            &materialize,
            &snapshot(vec![
                token_state(7, 40, false, false, 0, 140, 0),
                token_state(8, 30, false, false, 0, 30, 0),
            ]),
        )
        .unwrap();
    }

    #[test]
    fn pending_surplus_is_not_a_dos_but_partial_or_unbacked_manager_state_is() {
        let prepared = parsed_test_prepared();
        let payout = spec(PublicationAction::MaterializeErc20, vec![7]);
        validate_post_state(
            &prepared,
            &payout,
            // A winning proof may use a different nullifier than the local artifact. The pinned
            // materializer event plus complete-lane credits are the authority.
            &snapshot(vec![token_state(7, 40, false, false, 0, 140, 0)]),
        )
        .unwrap();
        let pull = spec(PublicationAction::PullErc20 { token_index: 7 }, vec![7]);
        // Amount-scoped pull leaves unrelated Rollup credit behind.
        validate_post_state(
            &prepared,
            &pull,
            &snapshot(vec![token_state(7, 40, false, true, 40, 100, 40)]),
        )
        .unwrap();
        assert!(
            validate_post_state(
                &prepared,
                &pull,
                &snapshot(vec![token_state(7, 40, false, true, 20, 120, 20)]),
            )
            .is_err()
        );
        assert!(
            validate_post_state(
                &prepared,
                &pull,
                &snapshot(vec![token_state(7, 40, false, true, 40, 100, 39)]),
            )
            .is_err()
        );
    }

    fn dummy_confirmation() -> StepConfirmation {
        StepConfirmation {
            receipt: FinalizedReceipt {
                transaction_hash: hex_word(2),
                block_hash: hex_word(11),
                block_number: 11,
                finalized_checkpoint: checkpoint(12, 12),
            },
            receipt_evidence_digest: "evidence:test".into(),
            post_state_digest: "post:test".into(),
        }
    }

    fn dummy_step(confirmed: bool) -> RawTransactionStep {
        RawTransactionStep {
            action: PublicationAction::MaterializeNative,
            target: hex_address(1),
            selector: "0x11111111".into(),
            calldata_hash: hex_word(1),
            value: "0".into(),
            nonce: 1,
            raw_signed_transaction: "0x01".into(),
            transaction_hash: hex_word(2),
            preflight_checkpoint: checkpoint(10, 10),
            preflight_state_digest: "snapshot:test".into(),
            confirmation: confirmed.then(dummy_confirmation),
            superseded_confirmation: None,
        }
    }

    fn dummy_adopted(action: PublicationAction, spec: &ActionSpec) -> AdoptedActionStep {
        AdoptedActionStep {
            action,
            target: spec.target.clone(),
            selector: spec.calldata[..10].into(),
            calldata_hash: spec.calldata_hash.clone(),
            value: "0".into(),
            confirmation: dummy_confirmation(),
        }
    }

    fn empty_journal(prepared: &PreparedPayout) -> PublicationJournal {
        PublicationJournal {
            version: JOURNAL_VERSION,
            binding: prepared.binding.clone(),
            signer: hex_address(0x70),
            signer_lock_root: "/private/operator/l1-signer-locks".into(),
            steps: BTreeMap::new(),
            adopted_steps: BTreeMap::new(),
            completed: None,
        }
    }

    #[test]
    fn every_crash_boundary_has_one_deterministic_resume_action() {
        // Before signing: a new raw tx may be created. After signing+fsync: only exact replay.
        // After confirmation fsync: only canonical revalidation. The same rule applies to all
        // native/ERC20 materialization and native/ERC20 pull action classes.
        for _action in [
            PublicationAction::MaterializeNative,
            PublicationAction::MaterializeErc20,
            PublicationAction::PullNative,
            PublicationAction::PullErc20 { token_index: 7 },
        ] {
            assert_eq!(resume_decision(None, None), ResumeDecision::SignNew);
            assert_eq!(
                resume_decision(Some(&dummy_step(false)), None),
                ResumeDecision::ReplayExact
            );
            assert_eq!(
                resume_decision(Some(&dummy_step(true)), None),
                ResumeDecision::RevalidateConfirmed
            );
            let adopted_spec = spec(_action.clone(), vec![7]);
            let adopted = dummy_adopted(_action, &adopted_spec);
            assert_eq!(
                resume_decision(Some(&dummy_step(false)), Some(&adopted)),
                ResumeDecision::RevalidateAdopted
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn signer_reservation_is_durable_before_sign_and_released_on_clean_sign_failure() {
        let prepared = parsed_test_prepared();
        let specs = action_specs(&prepared);
        let directory = std::env::temp_dir().join(format!(
            "intmax-close-funding-reservation-{}-{}",
            std::process::id(),
            PRIVATE_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal = directory.join("candidate/publication.json");
        fs::create_dir_all(journal.parent().unwrap()).unwrap();
        let lock_root = ensure_private_directory(&directory.join("operator-locks")).unwrap();
        let signer = hex_address(0x70);
        let first = close_funding_signer_reservation(
            prepared.envelope.chain_id,
            &signer,
            &journal,
            &prepared.binding,
            &specs[0],
        )
        .unwrap();
        let sibling = close_funding_signer_reservation(
            prepared.envelope.chain_id,
            &signer,
            &journal,
            &prepared.binding,
            &specs[1],
        )
        .unwrap();
        assert_ne!(first, sibling);

        let signed = sign_after_reservation(&lock_root, &first, || {
            assert!(l1_signer_reservation::claim(&lock_root, &sibling).is_err());
            Ok("0xsigned")
        })
        .unwrap();
        assert_eq!(signed, "0xsigned");
        // Model a crash after offline signing but before the raw WAL write: the exact phase may
        // resume, while a sibling action remains unable to allocate that signer's nonce.
        l1_signer_reservation::claim(&lock_root, &first).unwrap();
        assert!(l1_signer_reservation::claim(&lock_root, &sibling).is_err());
        l1_signer_reservation::release(&lock_root, &first).unwrap();

        let signing_error = sign_after_reservation::<()>(&lock_root, &sibling, || {
            Err(CloseFundingPublisherError::Command(
                "offline signer failed".into(),
            ))
        })
        .unwrap_err();
        assert!(signing_error.to_string().contains("offline signer failed"));
        l1_signer_reservation::claim(&lock_root, &first).unwrap();
        l1_signer_reservation::release(&lock_root, &first).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn permissionless_wrapper_front_run_needs_exact_semantic_evidence() {
        let prepared = parsed_test_prepared();
        let action = spec(PublicationAction::PullErc20 { token_index: 7 }, vec![7]);
        let transaction_hash = hex_word(0xc1);
        let block_hash = hex_word(0xc2);
        let base = serde_json::json!({
            "hash": transaction_hash,
            "from": hex_address(0x91),
            "to": action.target,
            "input": action.calldata,
            "value": "0x0",
            "nonce": "0x4",
            "blockHash": block_hash,
            "blockNumber": "0x65",
            "transactionIndex": "0x0",
        });
        let inclusion_receipt = serde_json::json!({
            "transactionHash": transaction_hash,
            "from": hex_address(0x91),
            "to": action.target,
            "blockHash": block_hash,
            "blockNumber": "0x65",
            "transactionIndex": "0x0",
        });
        validate_semantic_transaction(
            &base,
            &inclusion_receipt,
            &transaction_hash,
            &block_hash,
            101,
        )
        .unwrap();
        // A wrapper/relayer may bundle several permissionless phases. The outer target, calldata,
        // sender and value are not adoption authority; the pinned contracts' exact events and
        // same-block getters are. Changing those outer fields must therefore remain adoptable.
        let mut wrapped = base.clone();
        wrapped["to"] = Value::String(hex_address(0x99));
        wrapped["input"] = Value::String("0x22222222".into());
        wrapped["value"] = Value::String("0x1".into());
        let mut wrapped_receipt = inclusion_receipt.clone();
        wrapped_receipt["to"] = wrapped["to"].clone();
        validate_semantic_transaction(
            &wrapped,
            &wrapped_receipt,
            &transaction_hash,
            &block_hash,
            101,
        )
        .unwrap();

        for field in ["hash", "from", "blockHash", "blockNumber"] {
            let mut tampered = base.clone();
            tampered[field] = match field {
                "hash" => Value::String(hex_word(0x98)),
                "from" => Value::String(hex_address(0)),
                "blockHash" => Value::String(hex_word(0x99)),
                _ => Value::String("0x66".into()),
            };
            assert!(
                validate_semantic_transaction(
                    &tampered,
                    &inclusion_receipt,
                    &transaction_hash,
                    &block_hash,
                    101,
                )
                .is_err()
            );
        }

        let mut adopted = dummy_adopted(action.action.clone(), &action);
        validate_adopted_binding(&action, &adopted).unwrap();
        adopted.calldata_hash = hex_word(0xff);
        assert!(validate_adopted_binding(&action, &adopted).is_err());

        // Aggregate donated credit is not protocol authority by itself: the durable journal must
        // first contain a canonical exact materializer event. Once it does, a competing proof's
        // different nullifier is intentionally acceptable and the amount-scoped Manager pull is
        // still constrained to this channel cap.
        let materialize = spec(PublicationAction::MaterializeErc20, vec![7]);
        let mut journal = empty_journal(&prepared);
        assert!(validate_journal_prerequisites(&journal, &prepared, &action).is_err());
        journal.adopted_steps.insert(
            materialize.action.id(),
            dummy_adopted(materialize.action.clone(), &materialize),
        );
        validate_journal_prerequisites(&journal, &prepared, &action).unwrap();
        validate_preflight_action(
            &action,
            &snapshot(vec![token_state(7, 40, false, false, 0, 400, 0)]),
            &prepared,
        )
        .unwrap();
    }

    #[test]
    fn semantic_adoption_preserves_materialize_then_pull_order() {
        let prepared = parsed_test_prepared();
        let materialize = spec(PublicationAction::MaterializeErc20, vec![7]);
        let pull = spec(PublicationAction::PullErc20 { token_index: 7 }, vec![7]);
        let mut journal = empty_journal(&prepared);

        validate_journal_prerequisites(&journal, &prepared, &materialize).unwrap();
        assert!(validate_journal_prerequisites(&journal, &prepared, &pull).is_err());

        journal.adopted_steps.insert(
            materialize.action.id(),
            dummy_adopted(materialize.action.clone(), &materialize),
        );
        validate_journal_prerequisites(&journal, &prepared, &pull).unwrap();
    }

    #[test]
    fn action_plan_is_atomic_materialize_then_exact_pulls() {
        let prepared = parsed_test_prepared();
        let actions = action_specs(&prepared);
        assert_eq!(
            actions
                .iter()
                .map(|action| action.action.id())
                .collect::<Vec<_>>(),
            vec![
                "materialize:native",
                "pull:0",
                "materialize:erc20",
                "pull:7",
            ]
        );
        for action in &actions {
            let expected = match action.action {
                PublicationAction::MaterializeNative => MATERIALIZE_NATIVE_SELECTOR.into(),
                PublicationAction::MaterializeErc20 => MATERIALIZE_ERC20_SELECTOR.into(),
                PublicationAction::PullNative => selector(PULL_NATIVE_SIGNATURE),
                PublicationAction::PullErc20 { .. } => selector(PULL_ERC20_SIGNATURE),
            };
            assert!(same_hex(&action.calldata[..10], &expected));
            let expected_target = match action.action {
                PublicationAction::MaterializeNative | PublicationAction::MaterializeErc20 => {
                    &prepared.manifest.value.materializer
                }
                PublicationAction::PullNative | PublicationAction::PullErc20 { .. } => {
                    &prepared.envelope.manager
                }
            };
            assert!(same_hex(&action.target, expected_target));
            assert_eq!(
                action.calldata_hash,
                keccak_hex(&decode_hex(&action.calldata, None, "test calldata").unwrap())
            );
        }
    }

    #[test]
    fn journal_schema_rejects_uncommitted_fields() {
        let prepared = parsed_test_prepared();
        let journal = empty_journal(&prepared);
        let mut encoded = serde_json::to_value(journal).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("unexpectedAuthority".into(), Value::Bool(true));
        assert!(serde_json::from_value::<PublicationJournal>(encoded).is_err());
    }

    #[test]
    fn adopted_confirmation_rejects_reorg_or_evidence_mutation() {
        let action = PublicationAction::MaterializeNative;
        let stored = dummy_confirmation();
        let mut advanced = stored.clone();
        advanced.receipt.finalized_checkpoint = checkpoint(13, 13);
        validate_stored_confirmation(&action, &stored, &advanced).unwrap();

        let mut replaced = stored.clone();
        replaced.receipt.finalized_checkpoint = checkpoint(12, 99);
        assert!(validate_stored_confirmation(&action, &stored, &replaced).is_err());
        let mut changed_event = advanced;
        changed_event.receipt_evidence_digest = "evidence:sibling".into();
        assert!(validate_stored_confirmation(&action, &stored, &changed_event).is_err());
    }

    #[test]
    fn unfinalized_or_orphaned_checkpoint_cannot_advance() {
        let finalized = checkpoint(100, 100);
        let regressed = checkpoint(99, 99);
        let replaced = checkpoint(100, 101);
        assert!(checkpoint_advances(&finalized, &regressed).is_err());
        assert!(checkpoint_advances(&finalized, &replaced).is_err());
        let mut wrong_source = checkpoint(101, 101);
        wrong_source.source = L1FinalitySource::DevnetLatest;
        assert!(checkpoint_advances(&finalized, &wrong_source).is_err());
    }

    #[test]
    fn wrong_getter_or_anchor_state_fails_closed() {
        let prepared = parsed_test_prepared();
        let materialize = spec(PublicationAction::MaterializeNative, vec![0]);
        let mut wrong = snapshot(vec![token_state(0, 30, true, false, 0, 30, 0)]);
        assert!(validate_post_state(&prepared, &materialize, &wrong).is_err());
        wrong.tokens.get_mut(&0).unwrap().authorization = false;
        wrong.anchor_finalized = false;
        assert!(validate_post_state(&prepared, &materialize, &wrong).is_err());
    }
}
