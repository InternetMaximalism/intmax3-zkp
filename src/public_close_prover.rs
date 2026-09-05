//! Keyless close proving from the public live-balance projection.
//!
//! This is the native consumer of `GET /api/v1/channel/:id/backing` schema version 3. It never
//! accepts wallet seeds, Falcon secret keys, or Regev secret keys: the close circuit consumes the
//! N-of-N signatures already carried by the signed head. All transport bindings are checked
//! before proving or exporting any new artifact.

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::{PartialWitness, WitnessWrite as _},
    plonk::{
        circuit_data::VerifierCircuitData, config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};
use plonky2_mle::fixture_v2::MleVerifierV2Fixture;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    circuits::{
        balance::balance_pis::BalanceFullPublicInputs,
        channel::{
            close_asset_backing_circuit::{
                CloseAssetBackingCircuit, CloseAssetBackingPublicInputs,
                CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN,
            },
            close_pis::{ChannelClosePublicInputs, CHANNEL_CLOSE_PUBLIC_INPUTS_LEN},
        },
    },
    common::{
        channel::{token_funds_digest, CloseIntent, CloseWithdrawal},
        channel_id::ChannelId,
    },
    ethereum_types::{address::Address, bytes32::Bytes32},
    live_balance_service::{
        LiveChannelBackingArtifact, LIVE_BALANCE_SNAPSHOT_VERSION,
        SIGNED_HEAD_EXIT_KIT_SCHEMA_VERSION,
    },
    utils::{
        mle_prover::{
            export_mle_v2_config_json, export_mle_v2_json, prove_with_mle_v2, setup_mle_vk_v2,
            validate_mle_v2_full_against_config_json, verify_mle_proof_v2,
        },
        serialize::{deserialize_verifier_data, serialize_verifier_data},
        wrapper::WrapperCircuit,
    },
    wallet_core::{verify_all_signatures, verify_channel_backing, CloseProver},
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

/// Only this chain id is treated as a local development network. Every other chain requires an
/// operator-pinned balance verifier-data digest.
pub const LOCAL_DEVELOPMENT_CHAIN_ID: u64 = 31_337;
pub const PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION: u32 = 3;
/// Bundle schema 3: both MLE artifacts are strict canonical wire-v3 (`compact-v2`) fixtures whose
/// `.compactProof.bytes` is the exact calldata, and the CloseAssetBacking statement additionally
/// ships its proof-free deployment config (`backing_mle_config.json`) so the materializer's
/// constructor-pinned adapter can be deployed from the same bundle that is later attested.
pub const PUBLIC_CLOSE_BUNDLE_SCHEMA_VERSION: u32 = 3;

/// JSON expands byte arrays substantially. Bound the complete download before serde allocates it.
pub const MAX_PUBLIC_BACKING_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;
/// These are deliberately much larger than current balance VD/proofs, but finite before parsing.
pub const MAX_BALANCE_VERIFIER_DATA_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BALANCE_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BACKING_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CLOSE_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CLOSE_MLE_JSON_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_BACKING_MLE_JSON_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_BACKING_MLE_CONFIG_JSON_BYTES: usize = 4 * 1024 * 1024;

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

/// Exact schema returned by the public backing endpoint. `flatten` is intentional: API v3 places
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
    /// Canonical inner proof from the signed-head exit kit. Retaining it keeps the output bundle
    /// independently re-wrappable even if the original public backing endpoint later disappears.
    pub backing_proof: Vec<u8>,
    /// Exactly 26 raw Goldilocks limbs, in `CloseAssetBackingPublicInputs` wire order.
    pub backing_public_inputs: Vec<u64>,
    pub backing_mle_json: String,
    /// Proof-free wire-v3 deployment config of the wrapped CloseAssetBacking circuit: the exact
    /// `PinnedMleVerifierV2` constructor input the materializer must be bound to. Derived from the
    /// pinned Balance VD alone, and cross-checked against `backing_mle_json` before export.
    pub backing_mle_config_json: String,
    pub backing_finalized_extended_state_commitment: Bytes32,
    pub backing_anchor_block_number: u64,
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
    backing_circuit: CloseAssetBackingCircuit<F, C, D>,
    backing_proof: ProofWithPublicInputs<F, C, D>,
    backing_public_inputs: CloseAssetBackingPublicInputs,
    vd_sha256: [u8; 32],
}

/// Compact receipt returned after cryptographically checking a public backing artifact without
/// generating a new close proof or MLE proof. Delegates use this at archive time so a coordinator
/// cannot make an invalid exit kit "available" and withhold the only valid one later.
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
    pub signed_head_exit_kit_schema_version: u32,
    pub backing_proof_bytes: usize,
    pub backing_public_inputs: Vec<u64>,
    pub backing_finalized_extended_state_commitment: Bytes32,
    pub backing_anchor_block_number: u64,
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

fn validate_signed_head_backing_composition(
    backing: &CloseAssetBackingPublicInputs,
    signed_channel_id: ChannelId,
    signed_settled_tx_chain: Bytes32,
    signed_token_funds_digest: Bytes32,
) -> PublicCloseResult<()> {
    if backing.channel_id != signed_channel_id {
        return Err(PublicCloseError::Backing(
            "verified backing proof channelId differs from signed H".into(),
        ));
    }
    if backing.settled_tx_chain != signed_settled_tx_chain {
        return Err(PublicCloseError::Backing(
            "verified backing proof settledTxChain differs from signed H".into(),
        ));
    }
    if backing.token_funds_digest != signed_token_funds_digest {
        return Err(PublicCloseError::Backing(
            "verified backing proof tokenFundsDigest differs from signed H's complete asset vector"
                .into(),
        ));
    }
    Ok(())
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

/// Whose authority the envelope's `signed_head` carries.
#[derive(Clone, Copy, Debug)]
enum HeadAuthority {
    /// The complete N-of-N; the ordinary public close/backing artifact.
    SignedNofN,
    /// A PROPOSED successor that no member has signed yet: the exact digest the signer is about
    /// to sign, carried unsigned. Used only for the pre-sign exit-kit receipt.
    Proposed { digest: Bytes32 },
}

fn validate_public_backing(
    envelope: &PublicCloseBackingEnvelope,
    expected: &PublicCloseExpectations,
) -> PublicCloseResult<ValidatedPublicBacking> {
    validate_public_backing_with(envelope, expected, HeadAuthority::SignedNofN)
}

fn validate_public_backing_with(
    envelope: &PublicCloseBackingEnvelope,
    expected: &PublicCloseExpectations,
    authority: HeadAuthority,
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
    match authority {
        HeadAuthority::SignedNofN => {
            verify_all_signatures(&artifact.channel_record, &[], &artifact.signed_head)
                .map_err(|error| PublicCloseError::Backing(format!("N-of-N head: {error}")))?;
        }
        HeadAuthority::Proposed { digest } => {
            let head = &artifact.signed_head;
            if head.digest != digest {
                return Err(PublicCloseError::Backing(format!(
                    "prepared exit kit is for head {} rather than the proposed successor {digest}",
                    head.digest
                )));
            }
            if head.digest != head.signing_digest() {
                return Err(PublicCloseError::Backing(
                    "a prepared exit kit must carry the proposed successor with its exact signing digest"
                        .into(),
                ));
            }
        }
    }

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

    let kit = artifact.signed_head_exit_kit.as_ref().ok_or_else(|| {
        PublicCloseError::Backing(
            "signedHeadExitKit is absent; this signed head is not independently exit-capable"
                .into(),
        )
    })?;
    if kit.schema_version != SIGNED_HEAD_EXIT_KIT_SCHEMA_VERSION {
        return Err(PublicCloseError::Backing(format!(
            "signedHeadExitKit schemaVersion {} is not supported version {}",
            kit.schema_version, SIGNED_HEAD_EXIT_KIT_SCHEMA_VERSION
        )));
    }
    enforce_size(
        "close asset backing proof",
        kit.backing_proof.len(),
        MAX_BACKING_PROOF_BYTES,
    )?;
    if kit.backing_proof.is_empty() {
        return Err(PublicCloseError::Backing(
            "signedHeadExitKit backing proof is empty".into(),
        ));
    }

    // The backing circuit is a deterministic function of the independently pinned, canonical
    // Balance VD. A downloaded circuit/VK is never accepted from the coordinator.
    let backing_circuit = CloseAssetBackingCircuit::<F, C, D>::new(&vd);
    let backing_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
        kit.backing_proof.clone(),
        &backing_circuit.data.common,
    )
    .map_err(|error| PublicCloseError::Backing(format!("decode backing proof: {error}")))?;
    if backing_proof.to_bytes() != kit.backing_proof {
        return Err(PublicCloseError::Backing(
            "signedHeadExitKit backing proof is not in canonical serialization".into(),
        ));
    }
    backing_circuit
        .data
        .verify(backing_proof.clone())
        .map_err(|error| {
            PublicCloseError::Backing(format!("verify signed-head backing proof: {error:?}"))
        })?;
    let backing_public_inputs =
        CloseAssetBackingPublicInputs::from_pis(&backing_proof.public_inputs).map_err(|error| {
            PublicCloseError::Backing(format!("parse signed-head backing PIs: {error}"))
        })?;
    let raw_backing_public_inputs = backing_proof
        .public_inputs
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    if raw_backing_public_inputs.len() != CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN {
        return Err(PublicCloseError::Backing(format!(
            "signed-head backing proof has {} public inputs; expected exactly {}",
            raw_backing_public_inputs.len(),
            CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN
        )));
    }
    if raw_backing_public_inputs != kit.backing_public_inputs.to_u64_vec() {
        return Err(PublicCloseError::Backing(
            "signedHeadExitKit declared public inputs differ from its verified proof".into(),
        ));
    }

    // These are the only composition keys shared by the independently generated backing proof
    // and the N-of-N signed H. The digest covers the complete fixed-width registry/count/amount
    // vector, so no token-wise choice between stale V and newer B exists at this boundary.
    let state = &artifact.signed_head;
    let expected_token_funds_digest = token_funds_digest(
        &state.balance_state.token_registry,
        state.balance_state.token_count,
        &state.channel_fund.amounts,
    );
    validate_signed_head_backing_composition(
        &backing_public_inputs,
        state.channel_id,
        state.balance_state.settled_tx_chain,
        expected_token_funds_digest,
    )?;

    Ok(ValidatedPublicBacking {
        vd,
        balance_proof,
        backing_circuit,
        backing_proof,
        backing_public_inputs,
        vd_sha256,
    })
}

/// Verify the exact N-of-N head, canonical/pinned Balance verifier data, Balance proof and
/// signer-independent backing proof, but do not generate a close or MLE proof. This is the
/// receive-time gate used before a participant commits the immutable backing archive.
pub fn verify_public_backing(
    envelope: &PublicCloseBackingEnvelope,
    expected: &PublicCloseExpectations,
) -> PublicCloseResult<PublicBackingVerification> {
    let validated = validate_public_backing(envelope, expected)?;
    verification_from(envelope, expected, validated)
}

/// Verify a PRE-SIGN exit kit: the same canonical Balance VD, Balance proof and backing proof
/// checks as [`verify_public_backing`], for an envelope whose head is the unsigned successor with
/// exactly `proposed_head_digest`. This is the only place a head without its N-of-N is accepted,
/// and it never yields a close artifact — only the signer's receipt that the kit it holds backs
/// the state it is about to sign.
pub fn verify_public_backing_proposed(
    envelope: &PublicCloseBackingEnvelope,
    expected: &PublicCloseExpectations,
    proposed_head_digest: Bytes32,
) -> PublicCloseResult<PublicBackingVerification> {
    let validated = validate_public_backing_with(
        envelope,
        expected,
        HeadAuthority::Proposed {
            digest: proposed_head_digest,
        },
    )?;
    verification_from(envelope, expected, validated)
}

fn verification_from(
    envelope: &PublicCloseBackingEnvelope,
    expected: &PublicCloseExpectations,
    validated: ValidatedPublicBacking,
) -> PublicCloseResult<PublicBackingVerification> {
    let backing_public_inputs = validated.backing_public_inputs.to_u64_vec();
    Ok(PublicBackingVerification {
        schema_version: PUBLIC_CLOSE_BUNDLE_SCHEMA_VERSION,
        chain_id: envelope.chain_id,
        rollup: envelope.rollup,
        channel_id: expected.channel_id,
        signed_head_digest: envelope.backing.signed_head.digest,
        balance_verifier_data_sha256: format!("0x{}", hex::encode(validated.vd_sha256)),
        balance_proof_bytes: envelope.backing.balance_attestation.balance_proof.len(),
        signed_head_exit_kit_schema_version: SIGNED_HEAD_EXIT_KIT_SCHEMA_VERSION,
        backing_proof_bytes: envelope
            .backing
            .signed_head_exit_kit
            .as_ref()
            .expect("validated exit-kit presence")
            .backing_proof
            .len(),
        backing_public_inputs,
        backing_finalized_extended_state_commitment: validated
            .backing_public_inputs
            .finalized_extended_state_commitment,
        backing_anchor_block_number: validated.backing_public_inputs.anchor_block_number.as_u64(),
        self_verified: true,
    })
}

/// Decode one exported wire-v3 public-input limb (`0x` + 16 lowercase hex digits).
fn decode_mle_v2_public_input_limb(value: &str, index: usize) -> PublicCloseResult<u64> {
    let digits = value.strip_prefix("0x").ok_or_else(|| {
        PublicCloseError::Proving(format!(
            "generated MLE publicInputs[{index}] must have a lowercase 0x prefix"
        ))
    })?;
    if digits.len() != 16
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PublicCloseError::Proving(format!(
            "generated MLE publicInputs[{index}] is not a canonical 64-bit Goldilocks limb"
        )));
    }
    u64::from_str_radix(digits, 16).map_err(|error| {
        PublicCloseError::Proving(format!(
            "decode generated MLE publicInputs[{index}]: {error}"
        ))
    })
}

/// The raw public-input limbs a strict canonical wire-v3 full fixture carries (`proof.publicInputs`).
/// The JSON is re-parsed by the strict canonical parser, so a hand-edited or re-serialized file is
/// refused here rather than at submission time.
pub fn mle_v2_public_inputs(mle_json: &str) -> PublicCloseResult<Vec<u64>> {
    let fixture = MleVerifierV2Fixture::from_canonical_json(mle_json).map_err(|error| {
        PublicCloseError::Proving(format!(
            "generated MLE JSON is not a strict canonical wire-v3 fixture: {error}"
        ))
    })?;
    fixture
        .proof
        .public_inputs
        .iter()
        .enumerate()
        .map(|(index, value)| decode_mle_v2_public_input_limb(value, index))
        .collect()
}

fn verify_mle_public_inputs(
    actual: &[u64],
    expected: &[u64],
    proof_kind: &'static str,
) -> PublicCloseResult<()> {
    if actual.len() != expected.len() {
        return Err(PublicCloseError::Proving(format!(
            "generated {proof_kind} MLE carries {} public inputs; inner proof carries {}",
            actual.len(),
            expected.len()
        )));
    }
    for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        if actual != expected {
            return Err(PublicCloseError::Proving(format!(
                "generated {proof_kind} MLE publicInputs[{index}] differs from the inner proof"
            )));
        }
    }
    Ok(())
}

/// The wire-v3 artifact pair of one wrapped CloseAssetBacking proof.
#[derive(Clone, Debug)]
pub struct BackingMleArtifacts {
    /// Strict canonical full fixture (`export_mle_v2_json`): proof, VK, config and the one
    /// `.compactProof.bytes` calldata record.
    pub mle_json: String,
    /// Proof-free deployment config (`export_mle_v2_config_json`) of the same wrapper circuit.
    pub mle_config_json: String,
    /// The compact calldata bytes re-derived from `mle_json` against `mle_config_json`; exactly
    /// what `CloseFundingMaterializer.attestSignedHeadBacking(manager, bytes)` consumes.
    pub compact_proof: Vec<u8>,
}

/// Proof-free wire-v3 deployment config of the wrapped CloseAssetBacking circuit. This is a pure
/// function of the pinned Balance VD (the backing circuit is deterministic in it), so the
/// materializer's `PinnedMleVerifierV2` adapter can be deployed before any exit kit exists and
/// every later backing proof must match it.
pub fn export_backing_mle_config(
    backing_circuit: &CloseAssetBackingCircuit<F, C, D>,
) -> PublicCloseResult<String> {
    let wrapper = WrapperCircuit::<F, C, C, D>::new(&backing_circuit.data.verifier_data());
    export_mle_v2_config_json(&wrapper.data).map_err(|error| {
        PublicCloseError::Proving(format!("export backing MLE deployment config: {error:?}"))
    })
}

/// Recursively wrap the already self-verified backing proof and generate the exact wire-v3 PCS
/// artifact consumed by `CloseFundingMaterializer`. The wrapper re-registers the inner proof's 26
/// public inputs verbatim; checking the exported JSON again prevents serialization or pipeline
/// drift from weakening the Solidity strict-limb binding.
///
/// `pub` so the close-fixture co-generator (`generate_close_fixture`) emits the checked-in
/// `close_asset_backing_mle.json` / `close_asset_backing_mle_config.json` through this ONE path —
/// the same wrap + MLE + config cross-check a live `public_close_prover` bundle carries, so the
/// Solidity readers see one artifact shape.
pub fn wrap_and_export_backing_mle(
    backing_circuit: &CloseAssetBackingCircuit<F, C, D>,
    backing_proof: &ProofWithPublicInputs<F, C, D>,
) -> PublicCloseResult<BackingMleArtifacts> {
    let wrapper = WrapperCircuit::<F, C, C, D>::new(&backing_circuit.data.verifier_data());
    let wrapped = wrapper
        .prove(backing_proof)
        .map_err(|error| PublicCloseError::Proving(format!("wrap backing proof: {error:?}")))?;
    wrapper.data.verify(wrapped).map_err(|error| {
        PublicCloseError::Proving(format!("self-verify wrapped backing proof: {error:?}"))
    })?;

    let mle_config_json = export_mle_v2_config_json(&wrapper.data).map_err(|error| {
        PublicCloseError::Proving(format!("export backing MLE deployment config: {error:?}"))
    })?;
    let vk = setup_mle_vk_v2::<F, C, D>(&wrapper.data);
    let mut witness = PartialWitness::new();
    witness
        .set_proof_with_pis_target(&wrapper.wrap_proof, backing_proof)
        .map_err(|error| {
            PublicCloseError::Proving(format!("bind backing wrapper witness: {error:?}"))
        })?;
    let mle = prove_with_mle_v2::<F, C, D>(&wrapper.data, witness)
        .map_err(|error| PublicCloseError::Proving(format!("prove backing MLE: {error:?}")))?;
    verify_mle_proof_v2(&wrapper.data, &vk, &mle.proof).map_err(|error| {
        PublicCloseError::Proving(format!("self-verify backing MLE: {error:?}"))
    })?;
    let mle_json = export_mle_v2_json(&mle.proof, &vk, &wrapper.data)
        .map_err(|error| PublicCloseError::Proving(format!("export backing MLE: {error:?}")))?;
    let compact_proof = validate_mle_v2_full_against_config_json(&mle_json, &mle_config_json)
        .map_err(|error| {
            PublicCloseError::Proving(format!(
                "backing MLE full fixture does not match its deployment config: {error:?}"
            ))
        })?;
    Ok(BackingMleArtifacts {
        mle_json,
        mle_config_json,
        compact_proof,
    })
}

/// Build a close proof and its MLE artifact entirely from public data. This function has no key
/// parameter by design. Both generated proofs are verified before the bundle is returned.
pub fn prove_public_close(
    envelope: &PublicCloseBackingEnvelope,
    expected: &PublicCloseExpectations,
) -> PublicCloseResult<PublicCloseProofBundle> {
    let validated = validate_public_backing(envelope, expected)?;
    let artifact = &envelope.backing;

    let backing_public_inputs = validated
        .backing_proof
        .public_inputs
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    if backing_public_inputs.len() != CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN {
        return Err(PublicCloseError::Proving(format!(
            "verified backing proof has {} public inputs; expected exactly {}",
            backing_public_inputs.len(),
            CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN
        )));
    }
    let backing_mle =
        wrap_and_export_backing_mle(&validated.backing_circuit, &validated.backing_proof)?;
    enforce_size(
        "backing MLE JSON",
        backing_mle.mle_json.len(),
        MAX_BACKING_MLE_JSON_BYTES,
    )?;
    enforce_size(
        "backing MLE deployment config JSON",
        backing_mle.mle_config_json.len(),
        MAX_BACKING_MLE_CONFIG_JSON_BYTES,
    )?;
    verify_mle_public_inputs(
        &mle_v2_public_inputs(&backing_mle.mle_json)?,
        &backing_public_inputs,
        "backing",
    )?;
    let backing_proof_bytes = validated.backing_proof.to_bytes();
    enforce_size(
        "backing proof",
        backing_proof_bytes.len(),
        MAX_BACKING_PROOF_BYTES,
    )?;

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
    verify_mle_public_inputs(
        &mle_v2_public_inputs(&close_mle_json)?,
        &close_public_inputs,
        "close",
    )?;

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
        backing_proof: backing_proof_bytes,
        backing_public_inputs,
        backing_mle_json: backing_mle.mle_json,
        backing_mle_config_json: backing_mle.mle_config_json,
        backing_finalized_extended_state_commitment: validated
            .backing_public_inputs
            .finalized_extended_state_commitment,
        backing_anchor_block_number: validated.backing_public_inputs.anchor_block_number.as_u64(),
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

    fn backing_inputs() -> CloseAssetBackingPublicInputs {
        CloseAssetBackingPublicInputs {
            channel_id: channel(7),
            settled_tx_chain: Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8])
                .expect("settled chain"),
            token_funds_digest: Bytes32::from_u32_slice(&[8, 7, 6, 5, 4, 3, 2, 1])
                .expect("fund digest"),
            finalized_extended_state_commitment: Bytes32::from_u32_slice(&[9; 8])
                .expect("state commitment"),
            anchor_block_number: crate::common::u63::BlockNumber::new(42).expect("anchor"),
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
    fn backing_composition_requires_one_exact_signed_h_vector() {
        let inputs = backing_inputs();
        assert_eq!(CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN, 26);
        assert_eq!(inputs.to_u64_vec().len(), 26);
        validate_signed_head_backing_composition(
            &inputs,
            inputs.channel_id,
            inputs.settled_tx_chain,
            inputs.token_funds_digest,
        )
        .expect("exact signed H composition");

        let mut substituted = inputs;
        substituted.channel_id = channel(8);
        assert!(validate_signed_head_backing_composition(
            &substituted,
            inputs.channel_id,
            inputs.settled_tx_chain,
            inputs.token_funds_digest,
        )
        .is_err());
        substituted = inputs;
        substituted.settled_tx_chain = Bytes32::default();
        assert!(validate_signed_head_backing_composition(
            &substituted,
            inputs.channel_id,
            inputs.settled_tx_chain,
            inputs.token_funds_digest,
        )
        .is_err());
        substituted = inputs;
        substituted.token_funds_digest = Bytes32::default();
        assert!(validate_signed_head_backing_composition(
            &substituted,
            inputs.channel_id,
            inputs.settled_tx_chain,
            inputs.token_funds_digest,
        )
        .is_err());
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
        assert!(validate_transport_values(
            PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION,
            "liveBalanceService",
            1,
            address(1),
            &expected,
        )
        .is_err());
        assert!(validate_transport_values(
            PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION + 1,
            "liveBalanceService",
            1,
            address(1),
            &expected,
        )
        .is_err());

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
        assert!(validate_transport_values(
            PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION,
            "liveBalanceService",
            2,
            address(1),
            &expected,
        )
        .is_err());
        assert!(validate_transport_values(
            PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION,
            "liveBalanceService",
            1,
            address(2),
            &expected,
        )
        .is_err());
        assert!(validate_transport_values(
            PUBLIC_CLOSE_ENVELOPE_SCHEMA_VERSION,
            "setupTimeFile",
            1,
            address(1),
            &expected,
        )
        .is_err());

        let parsed = parse_sha256_pin(&format!("0x{}", hex::encode(pin))).expect("pin");
        assert_eq!(parsed, pin);
        assert!(parse_sha256_pin("0x01").is_err());
        assert!(parse_sha256_pin("not-hex").is_err());
    }

    #[test]
    fn generated_mle_public_inputs_must_exactly_match_close_proof() {
        verify_mle_public_inputs(&[1, 2, 3], &[1, 2, 3], "test").expect("exact public inputs");
        assert!(verify_mle_public_inputs(&[1, 2], &[1, 2, 3], "test").is_err());
        assert!(verify_mle_public_inputs(&[1, 9, 3], &[1, 2, 3], "test").is_err());

        assert_eq!(
            decode_mle_v2_public_input_limb("0x0000000000000007", 0).expect("canonical limb"),
            7
        );
        assert_eq!(
            decode_mle_v2_public_input_limb("0x00000000ffffffff", 0).expect("canonical limb"),
            u64::from(u32::MAX)
        );
        for malformed in ["7", "0x7", "0x0000000000000007 ", "0X0000000000000007", "0x00000000000000G7"] {
            assert!(decode_mle_v2_public_input_limb(malformed, 0).is_err(), "{malformed}");
        }
        assert!(mle_v2_public_inputs(r#"{"publicInputs":["1","2"]}"#).is_err());
    }

    #[test]
    fn all_untrusted_binary_components_have_finite_caps() {
        assert!(enforce_size(
            "vd",
            MAX_BALANCE_VERIFIER_DATA_BYTES,
            MAX_BALANCE_VERIFIER_DATA_BYTES
        )
        .is_ok());
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
            enforce_size(
                "backing proof",
                MAX_BACKING_PROOF_BYTES + 1,
                MAX_BACKING_PROOF_BYTES
            ),
            Err(PublicCloseError::SizeLimit { .. })
        ));
        assert!(matches!(
            enforce_size("close", MAX_CLOSE_PROOF_BYTES + 1, MAX_CLOSE_PROOF_BYTES),
            Err(PublicCloseError::SizeLimit { .. })
        ));
    }
}
