//! Keyless close proving from the public live-balance projection.
//!
//! This is the native consumer of `GET /api/v1/channel/:id/backing` schema version 2.  It never
//! accepts wallet seeds, Falcon secret keys, or Regev secret keys: the close circuit consumes the
//! N-of-N signatures already carried by the signed head.  All transport bindings are checked
//! before either expensive close circuit is built.

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{
        circuit_data::VerifierCircuitData, config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    circuits::{
        balance::balance_pis::BalanceFullPublicInputs,
        channel::close_pis::{CHANNEL_CLOSE_PUBLIC_INPUTS_LEN, ChannelClosePublicInputs},
    },
    common::{
        channel::{CloseIntent, CloseWithdrawal},
        channel_id::ChannelId,
    },
    ethereum_types::{address::Address, bytes32::Bytes32},
    live_balance_service::{LIVE_BALANCE_SNAPSHOT_VERSION, LiveChannelBackingArtifact},
    utils::serialize::{deserialize_verifier_data, serialize_verifier_data},
    wallet_core::{CloseProver, verify_all_signatures, verify_channel_backing},
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

/// Only this chain id is treated as a local development network. Every other chain requires an
/// operator-pinned balance verifier-data digest.
pub const LOCAL_DEVELOPMENT_CHAIN_ID: u64 = 31_337;
pub const PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION: u32 = 2;
pub const PUBLIC_CLOSE_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// JSON expands byte arrays substantially. Bound the complete download before serde allocates it.
pub const MAX_PUBLIC_BACKING_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;
/// These are deliberately much larger than current balance VD/proofs, but finite before parsing.
pub const MAX_BALANCE_VERIFIER_DATA_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BALANCE_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CLOSE_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CLOSE_MLE_JSON_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum PublicCloseError {
    #[error("{kind} is {actual} bytes, above the {maximum}-byte safety limit")]
    SizeLimit {
        kind: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("invalid public backing envelope: {0}")]
    InvalidEnvelope(String),
    #[error("public backing context mismatch: {0}")]
    Context(String),
    #[error("public backing verification failed: {0}")]
    Backing(String),
    #[error("public close proving failed: {0}")]
    Proving(String),
}

pub type PublicCloseResult<T> = Result<T, PublicCloseError>;

/// Exact schema returned by the public backing endpoint. `flatten` is intentional: API v2 places
/// the `LiveChannelBackingArtifact` fields beside its transport metadata rather than under a
/// second `artifact` object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicCloseBackingEnvelope {
    pub schema_version: u32,
    pub source: String,
    pub chain_id: u64,
    pub rollup: Address,
    #[serde(flatten)]
    pub backing: LiveChannelBackingArtifact,
}

/// Values the delegate/operator obtains independently of the downloaded API response. Without
/// these expectations, HTTPS/DNS compromise could simply substitute a complete artifact for a
/// different deployment.
#[derive(Clone, Debug)]
pub struct PublicCloseExpectations {
    pub channel_id: ChannelId,
    pub chain_id: u64,
    pub rollup: Address,
    /// SHA-256 over the exact canonical `serialize_verifier_data` bytes. Mandatory off chain
    /// 31337, optional (but still checked when supplied) on local development.
    pub balance_verifier_data_sha256: Option<[u8; 32]>,
}

/// Self-verified keyless result. The native binary writes the large fields separately, while
/// library consumers may forward them directly to their transaction builder.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicCloseProofBundle {
    pub schema_version: u32,
    pub chain_id: u64,
    pub rollup: Address,
    pub channel_id: ChannelId,
    pub balance_verifier_data_sha256: String,
    pub close_proof: Vec<u8>,
    pub close_public_inputs: Vec<u64>,
    pub close_mle_json: String,
    pub close_descriptor: PublicCloseIntentDescriptor,
    pub close_intent: CloseIntent,
}

/// The exact snake_case schema consumed by `contracts/script/RunClose.s.sol`. Every scalar comes
/// from the self-verified close proof's public inputs; the arrays come from the same signed head
/// the proof recursively binds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicCloseIntentDescriptor {
    pub channel_id: u32,
    pub close_nonce: u64,
    pub final_epoch: u64,
    pub final_small_block_number: u64,
    pub close_freeze_nonce: u64,
    pub final_channel_state_digest: String,
    pub final_balance_state_h1: String,
    pub channel_fund_amount: String,
    pub channel_fund_intmax_state_root: String,
    pub burn_tx_hash: String,
    pub close_withdrawal_digest: String,
    pub snapshot_medium_block_number: u64,
    pub final_state_version: u64,
    pub final_settled_tx_chain: String,
    pub final_settled_tx_accumulator_root: String,
    pub close_intent_digest: String,
    pub member_set_commitment: String,
    pub member_count: u8,
    pub delegate_count: u16,
    pub member_pk_gs: Vec<String>,
    pub channel_fund_amounts: Vec<String>,
    pub token_registry: Vec<u32>,
    pub token_count: u8,
}

struct ValidatedPublicBacking {
    vd: VerifierCircuitData<F, C, D>,
    balance_proof: ProofWithPublicInputs<F, C, D>,
    vd_sha256: [u8; 32],
}

/// Compact receipt returned after cryptographically checking a public backing artifact without
/// constructing either close circuit. Delegates use this at archive time so a coordinator cannot
/// make an invalid balance proof "available" and withhold the only valid one later.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicBackingVerification {
    pub schema_version: u32,
    pub chain_id: u64,
    pub rollup: Address,
    pub channel_id: ChannelId,
    pub signed_head_digest: Bytes32,
    pub balance_verifier_data_sha256: String,
    pub balance_proof_bytes: usize,
    pub self_verified: bool,
}

#[derive(Clone, Copy, Debug)]
struct PublicBackingBindings {
    snapshot_version: u32,
    base_channel_id: ChannelId,
    record_channel_id: ChannelId,
    state_channel_id: ChannelId,
    fund_channel_id: ChannelId,
    balance_channel_id: ChannelId,
    base_settled_tx_chain: Bytes32,
    state_settled_tx_chain: Bytes32,
    base_signed_head_digest: Option<Bytes32>,
    state_digest: Bytes32,
    awaiting_channel_binding: bool,
}

impl PublicBackingBindings {
    fn from_artifact(artifact: &LiveChannelBackingArtifact) -> Self {
        Self {
            snapshot_version: artifact.base_head.snapshot_version,
            base_channel_id: artifact.base_head.channel_id,
            record_channel_id: artifact.channel_record.channel_id,
            state_channel_id: artifact.signed_head.channel_id,
            fund_channel_id: artifact.signed_head.channel_fund.channel_id,
            balance_channel_id: artifact.signed_head.balance_state.channel_id,
            base_settled_tx_chain: artifact.base_head.settled_tx_chain,
            state_settled_tx_chain: artifact.signed_head.balance_state.settled_tx_chain,
            base_signed_head_digest: artifact.base_head.signed_head_digest,
            state_digest: artifact.signed_head.digest,
            awaiting_channel_binding: artifact.base_head.awaiting_channel_binding,
        }
    }

    fn validate(&self, expected_channel: ChannelId) -> PublicCloseResult<()> {
        if self.snapshot_version != LIVE_BALANCE_SNAPSHOT_VERSION {
            return Err(PublicCloseError::Backing(format!(
                "live snapshot version {} is not supported version {}",
                self.snapshot_version, LIVE_BALANCE_SNAPSHOT_VERSION
            )));
        }
        if self.awaiting_channel_binding {
            return Err(PublicCloseError::Backing(
                "live balance head is awaiting N-of-N channel binding".into(),
            ));
        }
        for (name, actual) in [
            ("baseHead.channelId", self.base_channel_id),
            ("channelRecord.channelId", self.record_channel_id),
            ("signedHead.channelId", self.state_channel_id),
            ("signedHead.channelFund.channelId", self.fund_channel_id),
            ("signedHead.balanceState.channelId", self.balance_channel_id),
        ] {
            if actual != expected_channel {
                return Err(PublicCloseError::Context(format!(
                    "{name} {:?} is not expected channel {:?}",
                    actual, expected_channel
                )));
            }
        }
        if self.base_settled_tx_chain != self.state_settled_tx_chain {
            return Err(PublicCloseError::Backing(
                "baseHead.settledTxChain differs from the N-of-N signed head".into(),
            ));
        }
        if self.base_signed_head_digest != Some(self.state_digest) {
            return Err(PublicCloseError::Backing(
                "baseHead.signedHeadDigest is absent or differs from signedHead.digest".into(),
            ));
        }
        Ok(())
    }
}

fn enforce_size(kind: &'static str, actual: usize, maximum: usize) -> PublicCloseResult<()> {
    if actual > maximum {
        return Err(PublicCloseError::SizeLimit {
            kind,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn validate_vd_pin(expected: &PublicCloseExpectations, actual: [u8; 32]) -> PublicCloseResult<()> {
    if expected.chain_id != LOCAL_DEVELOPMENT_CHAIN_ID
        && expected.balance_verifier_data_sha256.is_none()
    {
        return Err(PublicCloseError::Context(
            "production close requires an independently pinned balance verifier-data SHA-256"
                .into(),
        ));
    }
    if let Some(pin) = expected.balance_verifier_data_sha256 {
        if pin != actual {
            return Err(PublicCloseError::Context(format!(
                "balance verifier-data SHA-256 0x{} does not match expected 0x{}",
                hex::encode(actual),
                hex::encode(pin)
            )));
        }
    }
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(sha256(bytes)))
}

pub fn parse_sha256_pin(value: &str) -> PublicCloseResult<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|error| {
        PublicCloseError::InvalidEnvelope(format!("invalid verifier-data SHA-256 hex: {error}"))
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        PublicCloseError::InvalidEnvelope(format!(
            "verifier-data SHA-256 is {} bytes; expected 32",
            bytes.len()
        ))
    })
}

/// Parse the API response with a pre-serde transport cap.
pub fn parse_public_close_backing_envelope(
    json: &[u8],
) -> PublicCloseResult<PublicCloseBackingEnvelope> {
    enforce_size(
        "public backing envelope",
        json.len(),
        MAX_PUBLIC_BACKING_ENVELOPE_BYTES,
    )?;
    serde_json::from_slice(json)
        .map_err(|error| PublicCloseError::InvalidEnvelope(error.to_string()))
}

fn validate_transport_context(
    envelope: &PublicCloseBackingEnvelope,
    expected: &PublicCloseExpectations,
) -> PublicCloseResult<()> {
    validate_transport_values(
        envelope.schema_version,
        &envelope.source,
        envelope.chain_id,
        envelope.rollup,
        expected,
    )
}

fn validate_transport_values(
    schema_version: u32,
    source: &str,
    chain_id: u64,
    rollup: Address,
    expected: &PublicCloseExpectations,
) -> PublicCloseResult<()> {
    if schema_version != PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION {
        return Err(PublicCloseError::InvalidEnvelope(format!(
            "schemaVersion {} is not supported version {}",
            schema_version, PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION
        )));
    }
    if source != "liveBalanceService" {
        return Err(PublicCloseError::InvalidEnvelope(format!(
            "source {:?} is not liveBalanceService",
            source
        )));
    }
    if expected.chain_id == 0 || chain_id != expected.chain_id {
        return Err(PublicCloseError::Context(format!(
            "chainId {} does not equal independently expected chainId {}",
            chain_id, expected.chain_id
        )));
    }
    if expected.rollup == Address::default() || rollup != expected.rollup {
        return Err(PublicCloseError::Context(format!(
            "rollup {} does not equal independently expected rollup {}",
            rollup, expected.rollup
        )));
    }
    // Reject a missing production pin before parsing any of the large artifact components. The
    // exact digest comparison runs as soon as the raw canonical VD bytes are available below.
    if expected.chain_id != LOCAL_DEVELOPMENT_CHAIN_ID
        && expected.balance_verifier_data_sha256.is_none()
    {
        return Err(PublicCloseError::Context(
            "production close requires an independently pinned balance verifier-data SHA-256"
                .into(),
        ));
    }
    Ok(())
}

fn validate_public_backing(
    envelope: &PublicCloseBackingEnvelope,
    expected: &PublicCloseExpectations,
) -> PublicCloseResult<ValidatedPublicBacking> {
    validate_transport_context(envelope, expected)?;
    let artifact = &envelope.backing;

    enforce_size(
        "balance verifier data",
        artifact.balance_verifier_data.len(),
        MAX_BALANCE_VERIFIER_DATA_BYTES,
    )?;
    enforce_size(
        "balance proof",
        artifact.balance_attestation.balance_proof.len(),
        MAX_BALANCE_PROOF_BYTES,
    )?;
    if artifact.balance_attestation.balance_proof.is_empty() {
        return Err(PublicCloseError::Backing("balance proof is empty".into()));
    }
    if artifact.base_head.proof_size != artifact.balance_attestation.balance_proof.len() {
        return Err(PublicCloseError::Backing(format!(
            "baseHead.proofSize {} differs from the {}-byte balance proof",
            artifact.base_head.proof_size,
            artifact.balance_attestation.balance_proof.len()
        )));
    }
    PublicBackingBindings::from_artifact(artifact).validate(expected.channel_id)?;

    artifact
        .channel_record
        .validate()
        .map_err(|error| PublicCloseError::Backing(format!("invalid channel record: {error:?}")))?;
    artifact
        .signed_head
        .balance_state
        .validate()
        .map_err(|error| PublicCloseError::Backing(format!("invalid balance state: {error:?}")))?;
    verify_all_signatures(&artifact.channel_record, &[], &artifact.signed_head)
        .map_err(|error| PublicCloseError::Backing(format!("N-of-N head: {error}")))?;

    let vd_sha256 = sha256(&artifact.balance_verifier_data);
    validate_vd_pin(expected, vd_sha256)?;

    let vd = deserialize_verifier_data::<F, C, D>(&artifact.balance_verifier_data)
        .map_err(|error| PublicCloseError::Backing(format!("deserialize balance VD: {error}")))?;
    let canonical_vd = serialize_verifier_data(&vd)
        .map_err(|error| PublicCloseError::Backing(format!("re-serialize balance VD: {error}")))?;
    if canonical_vd != artifact.balance_verifier_data {
        return Err(PublicCloseError::Backing(
            "balance verifier data is not in canonical serialization".into(),
        ));
    }

    verify_channel_backing(
        &artifact.channel_record,
        &artifact.signed_head,
        Some(&artifact.balance_attestation),
        &vd,
    )
    .map_err(|error| PublicCloseError::Backing(error.to_string()))?;

    let balance_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
        artifact.balance_attestation.balance_proof.clone(),
        &vd.common,
    )
    .map_err(|error| PublicCloseError::Backing(format!("decode balance proof: {error}")))?;
    let pi_u64 = balance_proof
        .public_inputs
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    let full = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(&pi_u64, &vd.common.config)
        .map_err(|error| PublicCloseError::Backing(format!("parse balance PIs: {error}")))?;
    if full.pis.private_commitment != artifact.base_head.private_commitment {
        return Err(PublicCloseError::Backing(
            "baseHead.privateCommitment differs from the verified balance proof".into(),
        ));
    }

    Ok(ValidatedPublicBacking {
        vd,
        balance_proof,
        vd_sha256,
    })
}

/// Verify the exact N-of-N head, canonical/pinned balance verifier data and recursive balance
/// proof, but deliberately do not construct/prove the close circuits. This is the inexpensive
/// receive-time gate used before a participant commits the immutable backing archive.
pub fn verify_public_backing(
    envelope: &PublicCloseBackingEnvelope,
    expected: &PublicCloseExpectations,
) -> PublicCloseResult<PublicBackingVerification> {
    let validated = validate_public_backing(envelope, expected)?;
    Ok(PublicBackingVerification {
        schema_version: PUBLIC_CLOSE_BUNDLE_SCHEMA_VERSION,
        chain_id: envelope.chain_id,
        rollup: envelope.rollup,
        channel_id: expected.channel_id,
        signed_head_digest: envelope.backing.signed_head.digest,
        balance_verifier_data_sha256: format!("0x{}", hex::encode(validated.vd_sha256)),
        balance_proof_bytes: envelope.backing.balance_attestation.balance_proof.len(),
        self_verified: true,
    })
}

fn verify_mle_public_inputs(mle_json: &str, expected: &[u64]) -> PublicCloseResult<()> {
    let value: serde_json::Value = serde_json::from_str(mle_json)
        .map_err(|error| PublicCloseError::Proving(format!("parse generated MLE JSON: {error}")))?;
    let actual = value
        .get("publicInputs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            PublicCloseError::Proving("generated MLE JSON has no publicInputs array".into())
        })?;
    if actual.len() != expected.len() {
        return Err(PublicCloseError::Proving(format!(
            "generated MLE carries {} public inputs; close proof carries {}",
            actual.len(),
            expected.len()
        )));
    }
    for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        let parsed = match actual {
            serde_json::Value::String(value) => value.parse::<u64>().ok(),
            serde_json::Value::Number(value) => value.as_u64(),
            _ => None,
        }
        .ok_or_else(|| {
            PublicCloseError::Proving(format!(
                "generated MLE publicInputs[{index}] is not a canonical u64"
            ))
        })?;
        if parsed != *expected {
            return Err(PublicCloseError::Proving(format!(
                "generated MLE publicInputs[{index}] differs from the close proof"
            )));
        }
    }
    Ok(())
}

/// Build a close proof and its MLE artifact entirely from public data. This function has no key
/// parameter by design. Both generated proofs are verified before the bundle is returned.
pub fn prove_public_close(
    envelope: &PublicCloseBackingEnvelope,
    expected: &PublicCloseExpectations,
) -> PublicCloseResult<PublicCloseProofBundle> {
    let validated = validate_public_backing(envelope, expected)?;
    let artifact = &envelope.backing;

    let prover = CloseProver::new(&validated.vd);
    let witness = prover
        .build_full_witness_from_signatures(
            &artifact.channel_record,
            &artifact.signed_head,
            &artifact.signed_head.member_signatures,
            validated.balance_proof,
        )
        .map_err(|error| PublicCloseError::Proving(error.to_string()))?;
    let close_proof = prover
        .prove(&witness)
        .map_err(|error| PublicCloseError::Proving(error.to_string()))?;
    let close_vd = prover.close_vd();

    let close_proof_bytes = close_proof.to_bytes();
    enforce_size(
        "close proof",
        close_proof_bytes.len(),
        MAX_CLOSE_PROOF_BYTES,
    )?;
    let roundtrip = ProofWithPublicInputs::<F, C, D>::from_bytes(
        close_proof_bytes.clone(),
        &close_vd.common,
    )
    .map_err(|error| PublicCloseError::Proving(format!("close proof round-trip: {error}")))?;
    // Verify only the serialized round trip: this proves both cryptographic validity and that the
    // exact bytes we return decode to that proof, without paying for a redundant second verify.
    close_vd.verify(roundtrip).map_err(|error| {
        PublicCloseError::Proving(format!("serialized close proof verification: {error:?}"))
    })?;

    let close_public_inputs = close_proof
        .public_inputs
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    if close_public_inputs.len() < CHANNEL_CLOSE_PUBLIC_INPUTS_LEN {
        return Err(PublicCloseError::Proving(format!(
            "close proof has {} public inputs; expected at least {}",
            close_public_inputs.len(),
            CHANNEL_CLOSE_PUBLIC_INPUTS_LEN
        )));
    }
    let close_pis = ChannelClosePublicInputs::from_u64_slice(
        &close_public_inputs[..CHANNEL_CLOSE_PUBLIC_INPUTS_LEN],
    )
    .map_err(|error| PublicCloseError::Proving(format!("parse close PIs: {error:?}")))?;

    let close_mle_json = prover
        .prove_mle(&close_proof)
        .map_err(|error| PublicCloseError::Proving(error.to_string()))?;
    enforce_size(
        "close MLE JSON",
        close_mle_json.len(),
        MAX_CLOSE_MLE_JSON_BYTES,
    )?;
    verify_mle_public_inputs(&close_mle_json, &close_public_inputs)?;

    let state = &artifact.signed_head;
    let close_tx = CloseWithdrawal {
        channel_id: state.channel_id,
        final_channel_state_digest: state.digest,
        final_balance_state_h1: state.balance_state.h1(),
        intmax_state_root: state.channel_fund.intmax_state_root,
        burn_tx_hash: Bytes32::default(),
        burn_amount: state.channel_fund.amounts[0],
        zkp: Vec::new(),
    };
    let close_intent = CloseIntent::new(state, &close_tx)
        .map_err(|error| PublicCloseError::Proving(format!("rebuild close intent: {error:?}")))?;
    if close_intent.signing_digest() != close_pis.close_intent_digest {
        return Err(PublicCloseError::Proving(
            "reconstructed public close intent digest differs from the self-verified close proof"
                .into(),
        ));
    }
    let close_descriptor = PublicCloseIntentDescriptor {
        channel_id: close_pis.channel_id.channel_id(),
        close_nonce: close_pis.close_nonce,
        final_epoch: close_pis.final_epoch,
        final_small_block_number: close_pis.final_small_block_number,
        close_freeze_nonce: close_pis.close_freeze_nonce,
        final_channel_state_digest: close_pis.final_channel_state_digest.to_string(),
        final_balance_state_h1: close_pis.final_balance_state_h1.to_string(),
        channel_fund_amount: close_pis.channel_fund_amount.to_string(),
        channel_fund_intmax_state_root: close_pis.channel_fund_intmax_state_root.to_string(),
        burn_tx_hash: close_pis.burn_tx_hash.to_string(),
        close_withdrawal_digest: close_pis.close_withdrawal_digest.to_string(),
        snapshot_medium_block_number: close_pis.snapshot_medium_block_number,
        final_state_version: close_pis.final_state_version,
        final_settled_tx_chain: close_pis.final_settled_tx_chain.to_string(),
        final_settled_tx_accumulator_root: close_pis.final_settled_tx_accumulator_root.to_string(),
        close_intent_digest: close_pis.close_intent_digest.to_string(),
        member_set_commitment: close_pis.member_set_commitment.to_string(),
        member_count: close_pis.member_count,
        delegate_count: close_pis.delegate_count,
        member_pk_gs: witness
            .member_auth
            .iter()
            .map(|auth| auth.pk_g.to_string())
            .collect(),
        channel_fund_amounts: state
            .channel_fund
            .amounts
            .iter()
            .map(ToString::to_string)
            .collect(),
        token_registry: state.balance_state.token_registry.to_vec(),
        token_count: state.balance_state.token_count,
    };

    Ok(PublicCloseProofBundle {
        schema_version: PUBLIC_CLOSE_BUNDLE_SCHEMA_VERSION,
        chain_id: envelope.chain_id,
        rollup: envelope.rollup,
        channel_id: state.channel_id,
        balance_verifier_data_sha256: format!("0x{}", hex::encode(validated.vd_sha256)),
        close_proof: close_proof_bytes,
        close_public_inputs,
        close_mle_json,
        close_descriptor,
        close_intent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_types::u32limb_trait::U32LimbTrait as _;

    fn channel(id: u64) -> ChannelId {
        ChannelId::new(id).expect("valid channel")
    }

    fn address(last: u32) -> Address {
        use crate::ethereum_types::u32limb_trait::U32LimbTrait as _;
        Address::from_u32_slice(&[0, 0, 0, 0, last]).expect("address")
    }

    fn bindings() -> PublicBackingBindings {
        PublicBackingBindings {
            snapshot_version: LIVE_BALANCE_SNAPSHOT_VERSION,
            base_channel_id: channel(7),
            record_channel_id: channel(7),
            state_channel_id: channel(7),
            fund_channel_id: channel(7),
            balance_channel_id: channel(7),
            base_settled_tx_chain: Bytes32::default(),
            state_settled_tx_chain: Bytes32::default(),
            base_signed_head_digest: Some(
                Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 9]).expect("digest"),
            ),
            state_digest: Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 9]).expect("digest"),
            awaiting_channel_binding: false,
        }
    }

    #[test]
    fn public_bindings_reject_every_wrong_channel_and_unbound_head() {
        let expected = channel(7);
        bindings().validate(expected).expect("valid bindings");

        for mutate in 0..5 {
            let mut value = bindings();
            match mutate {
                0 => value.base_channel_id = channel(8),
                1 => value.record_channel_id = channel(8),
                2 => value.state_channel_id = channel(8),
                3 => value.fund_channel_id = channel(8),
                4 => value.balance_channel_id = channel(8),
                _ => unreachable!(),
            }
            assert!(matches!(
                value.validate(expected),
                Err(PublicCloseError::Context(_))
            ));
        }

        let mut unbound = bindings();
        unbound.awaiting_channel_binding = true;
        assert!(unbound.validate(expected).is_err());
    }

    #[test]
    fn public_bindings_reject_settle_chain_and_signed_digest_substitution() {
        let expected = channel(7);
        let mut wrong_chain = bindings();
        wrong_chain.base_settled_tx_chain =
            Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 1]).expect("chain");
        assert!(wrong_chain.validate(expected).is_err());

        let mut missing_digest = bindings();
        missing_digest.base_signed_head_digest = None;
        assert!(missing_digest.validate(expected).is_err());

        let mut wrong_digest = bindings();
        wrong_digest.state_digest = Bytes32::default();
        assert!(wrong_digest.validate(expected).is_err());
    }

    #[test]
    fn production_requires_exact_vd_pin_and_transport_context() {
        let pin = sha256(b"canonical-vd");
        let mut expected = PublicCloseExpectations {
            channel_id: channel(7),
            chain_id: 1,
            rollup: address(1),
            balance_verifier_data_sha256: None,
        };
        assert!(
            validate_transport_values(
                PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION,
                "liveBalanceService",
                1,
                address(1),
                &expected,
            )
            .is_err()
        );
        assert!(
            validate_transport_values(
                PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION + 1,
                "liveBalanceService",
                1,
                address(1),
                &expected,
            )
            .is_err()
        );

        expected.balance_verifier_data_sha256 = Some(pin);
        validate_transport_values(
            PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION,
            "liveBalanceService",
            1,
            address(1),
            &expected,
        )
        .expect("pinned production context");
        validate_vd_pin(&expected, pin).expect("exact pin");
        assert!(validate_vd_pin(&expected, sha256(b"substituted-vd")).is_err());
        assert!(
            validate_transport_values(
                PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION,
                "liveBalanceService",
                2,
                address(1),
                &expected,
            )
            .is_err()
        );
        assert!(
            validate_transport_values(
                PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION,
                "liveBalanceService",
                1,
                address(2),
                &expected,
            )
            .is_err()
        );
        assert!(
            validate_transport_values(
                PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION,
                "setupTimeFile",
                1,
                address(1),
                &expected,
            )
            .is_err()
        );

        let parsed = parse_sha256_pin(&format!("0x{}", hex::encode(pin))).expect("pin");
        assert_eq!(parsed, pin);
        assert!(parse_sha256_pin("0x01").is_err());
        assert!(parse_sha256_pin("not-hex").is_err());
    }

    #[test]
    fn generated_mle_public_inputs_must_exactly_match_close_proof() {
        verify_mle_public_inputs(r#"{"publicInputs":["1","2",3]}"#, &[1, 2, 3])
            .expect("exact public inputs");
        assert!(verify_mle_public_inputs(r#"{"publicInputs":["1","2"]}"#, &[1, 2, 3]).is_err());
        assert!(verify_mle_public_inputs(r#"{"publicInputs":["1","9",3]}"#, &[1, 2, 3]).is_err());
        assert!(verify_mle_public_inputs(r#"{"publicInputs":["1","-2",3]}"#, &[1, 2, 3]).is_err());
    }

    #[test]
    fn all_untrusted_binary_components_have_finite_caps() {
        assert!(
            enforce_size(
                "vd",
                MAX_BALANCE_VERIFIER_DATA_BYTES,
                MAX_BALANCE_VERIFIER_DATA_BYTES
            )
            .is_ok()
        );
        assert!(matches!(
            enforce_size(
                "vd",
                MAX_BALANCE_VERIFIER_DATA_BYTES + 1,
                MAX_BALANCE_VERIFIER_DATA_BYTES
            ),
            Err(PublicCloseError::SizeLimit { .. })
        ));
        assert!(matches!(
            enforce_size(
                "proof",
                MAX_BALANCE_PROOF_BYTES + 1,
                MAX_BALANCE_PROOF_BYTES
            ),
            Err(PublicCloseError::SizeLimit { .. })
        ));
        assert!(matches!(
            enforce_size("close", MAX_CLOSE_PROOF_BYTES + 1, MAX_CLOSE_PROOF_BYTES),
            Err(PublicCloseError::SizeLimit { .. })
        ));
    }
}
