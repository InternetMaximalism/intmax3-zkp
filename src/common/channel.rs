use plonky2_keccak::utils::solidity_keccak256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// SECURITY: re-export the canonical `ChannelId` so the channel layer and every downstream module
// share ONE channel identifier type with identical keccak digest semantics.
pub use crate::common::channel_id::ChannelId;
use crate::{
    common::{
        balance_state::{BalanceState, tx_leaf_hash},
        channel_id::ChannelId as PackedUserId,
    },
    constants::CHANNEL_MEMBERS,
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    regev::RegevCiphertext,
};

pub type SignatureBytes = Vec<u8>;

const CHANNEL_STATE_DOMAIN: u32 = 0x494d4348; // "IMCH"
const PAY_DOMAIN: u32 = 0x494d5041; // "IMPA"
// pub(crate): the validity circuits recompute the IMSB signing digest in-circuit
// (`circuits::validity::block_hash_chain::sphincs_sig`) and must use the SAME domain limb.
pub(crate) const SMALL_BLOCK_DOMAIN: u32 = 0x494d5342; // "IMSB"
const SIGNED_SMALL_BLOCK_DOMAIN: u32 = 0x494d5353; // "IMSS"
const INTER_CHANNEL_TX_DOMAIN: u32 = 0x494d4954; // "IMIT"
const CLOSE_TX_DOMAIN: u32 = 0x494d434c; // "IMCL"
const CLOSE_INTENT_DOMAIN: u32 = 0x494d4349; // "IMCI"
const SPECIAL_CLOSE_DOMAIN: u32 = 0x494d5343; // "IMSC"
const CANCEL_CLOSE_DOMAIN: u32 = 0x494d434e; // "IMCN"
const POST_CLOSE_CLAIM_DOMAIN: u32 = 0x494d4350; // "IMCP"
const WITHDRAWAL_CLAIM_DOMAIN: u32 = 0x494d4357; // "IMCW"
const CHANNEL_BALANCE_LEAF_DOMAIN: u32 = 0x494d5546; // "IMUF"
const CHANNEL_RECORD_DOMAIN: u32 = 0x494d4352; // "IMCR"
const KEY_RECORD_DOMAIN: u32 = 0x494d4b52; // "IMKR"
pub const MAX_CLOSE_TRANSFERS: usize = 16;
pub const SPECIAL_CLOSE_MEDIUM_BLOCK_WINDOW: u64 = 5;
// NOTE: `SMALL_BLOCK_SIGNATURE_TIMEOUT_SECS` is superseded by `constants::SIGN_TIMEOUT_SECS`
// (abstract2 §2.5, 180s) and `MAX_DUMMY_DELTA_AMOUNT` is retired with the dummy-delta
// machinery (detail2 §A-1: receiver set visibility is the documented v2 privacy boundary).

#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("invalid identifier length: expected {expected}, got {actual}")]
    InvalidIdLength { expected: usize, actual: usize },

    #[error("invalid identifier value: {0}")]
    InvalidIdValue(String),

    #[error("invalid close binding: {0}")]
    InvalidCloseBinding(String),

    #[error("invalid channel record: {0}")]
    InvalidChannelRecord(String),

    #[error("invalid signature set: {0}")]
    InvalidSignatureSet(String),

    #[error("invalid balance state: {0}")]
    InvalidBalanceState(String),

    #[error("invalid inter-channel tx: {0}")]
    InvalidInterChannelTx(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelStatus {
    Active,
    ClosePending,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBackend {
    Plonky2,
    Plonky3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionProofRole {
    ChannelStateUpdate,
    IntmaxTransport,
    ChannelCloseSettlement,
    SpecialCloseSettlement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelTransitionKind {
    InChannelTransfer,
    InterChannelSend,
    InterChannelFundImport,
    ReceiverBundleApply,
    BalanceRefresh,
    ChannelClose,
    SpecialClose,
}

impl ChannelTransitionKind {
    pub const fn required_state_backend(self) -> Option<ProofBackend> {
        match self {
            Self::InChannelTransfer
            | Self::InterChannelSend
            | Self::ReceiverBundleApply
            | Self::BalanceRefresh => Some(ProofBackend::Plonky3),
            Self::InterChannelFundImport | Self::ChannelClose | Self::SpecialClose => None,
        }
    }

    pub const fn required_transport_backend(self) -> Option<ProofBackend> {
        match self {
            Self::InterChannelSend
            | Self::InterChannelFundImport
            | Self::ChannelClose
            | Self::SpecialClose => Some(ProofBackend::Plonky2),
            Self::InChannelTransfer | Self::ReceiverBundleApply | Self::BalanceRefresh => None,
        }
    }
}

/// Transport envelope for a transition proof: a role + backend tag around opaque proof bytes.
/// Lives here (not in the circuits layer) because the channel-layer transaction types
/// (`ChannelTx.channel_tx_zkp`, `InterChannelTx.channel_update_zkp`) carry it directly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelProofEnvelope {
    pub role: TransitionProofRole,
    pub backend: ProofBackend,
    pub proof: Vec<u8>,
}

impl ChannelProofEnvelope {
    /// Canonical u32-word encoding of the envelope for keccak signing preimages:
    /// `[role, backend, proof.len(), bytes_to_u32_words(proof)…]`.
    ///
    /// SECURITY: role and backend tags are part of every digest that embeds an envelope, so a
    /// proof signed for one (role, backend) slot cannot be replayed into another.
    pub fn to_digest_words(&self) -> Vec<u32> {
        [
            vec![
                self.role as u32,
                self.backend as u32,
                self.proof.len() as u32,
            ],
            bytes_to_u32_words(&self.proof),
        ]
        .concat()
    }
}

// SECURITY: `ChannelId` is the canonical unified channel identifier defined in
// `crate::common::channel_id`. The channel layer reuses the BASE type so a channel id has ONE
// representation across both layers. Its `to_u32_vec`/`as_bytes`/`as_u64` outputs are
// byte-identical to the legacy `[u8;4]`-backed type, so every keccak `signing_digest` preimage
// below is unchanged.

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId([u8; 4]);

impl KeyId {
    pub fn new(value: u64) -> Result<Self, ChannelError> {
        if value > u32::MAX as u64 {
            return Err(ChannelError::InvalidIdValue(format!(
                "key id {value} does not fit in 4 bytes"
            )));
        }
        Ok(Self((value as u32).to_be_bytes()))
    }

    pub fn from_bytes(bytes: [u8; 4]) -> Result<Self, ChannelError> {
        let out = Self(bytes);
        if out.as_u64() == 0 {
            return Err(ChannelError::InvalidIdValue(
                "key id 0 is reserved".to_string(),
            ));
        }
        Ok(out)
    }

    pub fn as_bytes(&self) -> [u8; 4] {
        self.0
    }

    pub fn as_u64(&self) -> u64 {
        u32::from_be_bytes(self.0) as u64
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        bytes_to_u32_words(&self.0)
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        self.to_u32_vec()
            .into_iter()
            .map(|value| value as u64)
            .collect()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, ChannelError> {
        let bytes = fixed_bytes_from_u32_word_slice(values, 4)?;
        Self::from_bytes(bytes.try_into().expect("slice len 4"))
    }
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId([u8; 8]);

impl UserId {
    pub fn from_parts(channel_id: ChannelId, key_id: KeyId) -> Self {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&channel_id.as_bytes());
        out[4..8].copy_from_slice(&key_id.as_bytes());
        Self(out)
    }

    pub fn as_bytes(&self) -> [u8; 8] {
        self.0
    }

    pub fn channel_id(&self) -> ChannelId {
        // SECURITY: the member id is `channel_id || key_id`; the channel_id component is a
        // nonzero 4-byte big-endian value, so `from_bytes` (which rejects the reserved 0 id)
        // never fails for a well-formed member id.
        ChannelId::from_bytes(self.0[..4].try_into().expect("slice len 4"))
            .expect("member id channel_id component must be nonzero")
    }

    pub fn key_id(&self) -> KeyId {
        KeyId(self.0[4..8].try_into().expect("slice len 4"))
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        bytes_to_u32_words(&self.0)
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        self.to_u32_vec()
            .into_iter()
            .map(|value| value as u64)
            .collect()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, ChannelError> {
        let bytes = fixed_bytes_from_u32_word_slice(values, 8)?;
        Ok(Self(bytes.try_into().expect("slice len 8")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRecord {
    pub key_id: KeyId,
    pub sphincs_pubkey_hashes_root: Bytes32,
    pub threshold: u32,
    pub num_keys: u32,
}

impl KeyRecord {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![KEY_RECORD_DOMAIN],
                self.key_id.to_u32_vec(),
                self.sphincs_pubkey_hashes_root.to_u32_vec(),
                vec![self.threshold, self.num_keys],
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelRecord {
    pub channel_id: ChannelId,
    pub bp_key_id: KeyId,
    pub member_key_ids: Vec<KeyId>,
    pub member_key_ids_root: Bytes32,
    pub special_close_penalty: U256,
    pub close_freeze_nonce: u64,
    pub status: ChannelStatus,
    /// Root over the members' Regev public keys (`regev::regev_pk_root`, member order).
    ///
    /// SECURITY: anchoring this root in the L1-signed channel record defeats key-substitution on
    /// `publishRegevPk` (adversarial review F9-A / detail2 §H-1): a balance ciphertext only
    /// counts if its key digest hangs under this root at the member's slot.
    pub regev_pk_root: Bytes32,
}

impl ChannelRecord {
    pub fn validate(&self) -> Result<(), ChannelError> {
        // abstract2 §2.1: channel membership is fixed at exactly CHANNEL_MEMBERS (= 3).
        if self.member_key_ids.len() != CHANNEL_MEMBERS {
            return Err(ChannelError::InvalidChannelRecord(format!(
                "member_key_ids must contain exactly {CHANNEL_MEMBERS} entries, got {}",
                self.member_key_ids.len()
            )));
        }
        if self.regev_pk_root == Bytes32::default() {
            return Err(ChannelError::InvalidChannelRecord(
                "regev_pk_root must be set (zero root would unanchor the member Regev keys)"
                    .to_string(),
            ));
        }
        let mut prev: Option<KeyId> = None;
        for key_id in &self.member_key_ids {
            if let Some(previous) = prev {
                if previous.as_u64() >= key_id.as_u64() {
                    return Err(ChannelError::InvalidChannelRecord(
                        "member_key_ids must be strictly ordered and unique".to_string(),
                    ));
                }
            }
            prev = Some(*key_id);
        }
        if !self.member_key_ids.contains(&self.bp_key_id) {
            return Err(ChannelError::InvalidChannelRecord(
                "bp_key_id must belong to member_key_ids".to_string(),
            ));
        }
        Ok(())
    }

    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CHANNEL_RECORD_DOMAIN],
                self.channel_id.to_u32_vec(),
                self.bp_key_id.to_u32_vec(),
                split_u64(self.close_freeze_nonce),
                vec![self.status as u32, self.member_key_ids.len() as u32],
                self.member_key_ids
                    .iter()
                    .flat_map(KeyId::to_u32_vec)
                    .collect::<Vec<_>>(),
                self.member_key_ids_root.to_u32_vec(),
                self.special_close_penalty.to_u32_vec(),
                // Appended at the END of the legacy IMCR preimage (detail2 §H-1).
                self.regev_pk_root.to_u32_vec(),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleInclusionProof {
    pub siblings: Vec<Bytes32>,
    pub leaf_index: U256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmallBlockRootMessage {
    pub channel_id: ChannelId,
    pub bp_key_id: KeyId,
    pub small_block_number: u64,
    pub prev_small_block_root: Bytes32,
    pub tx_tree_root: Bytes32,
    pub state_commitment_root: Bytes32,
    pub medium_epoch_hint: u64,
    pub close_freeze_nonce: u64,
}

impl SmallBlockRootMessage {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![SMALL_BLOCK_DOMAIN],
                self.channel_id.to_u32_vec(),
                self.bp_key_id.to_u32_vec(),
                split_u64(self.small_block_number),
                self.prev_small_block_root.to_u32_vec(),
                self.tx_tree_root.to_u32_vec(),
                self.state_commitment_root.to_u32_vec(),
                split_u64(self.medium_epoch_hint),
                split_u64(self.close_freeze_nonce),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberSignature {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub signature: SignatureBytes,
    pub key_condition_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedSmallBlock {
    pub message: SmallBlockRootMessage,
    pub signatures: Vec<MemberSignature>,
    pub aggregated_signature_proof: Vec<u8>,
    pub medium_block_number: u64,
    pub confirmation_proof: Vec<u8>,
}

impl SignedSmallBlock {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![SIGNED_SMALL_BLOCK_DOMAIN],
                self.message.signing_digest().to_u32_vec(),
                split_u64(self.medium_block_number),
                vec![self.signatures.len() as u32],
                self.signatures
                    .iter()
                    .flat_map(|signature| {
                        [
                            signature.key_id.to_u32_vec(),
                            signature.user_id.to_u32_vec(),
                            vec![signature.signature.len() as u32],
                            bytes_to_u32_words(&signature.signature),
                            vec![signature.key_condition_proof.len() as u32],
                            bytes_to_u32_words(&signature.key_condition_proof),
                        ]
                        .concat()
                    })
                    .collect::<Vec<_>>(),
                vec![self.aggregated_signature_proof.len() as u32],
                bytes_to_u32_words(&self.aggregated_signature_proof),
                vec![self.confirmation_proof.len() as u32],
                bytes_to_u32_words(&self.confirmation_proof),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelFund {
    pub channel_id: ChannelId,
    pub amount: U256,
    pub intmax_state_root: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelBalance {
    pub channel_id: ChannelId,
    pub user_id: UserId,
    /// The member's hidden balance, encrypted to their own `RegevPk` (detail2 §C-4).
    pub balance_ciphertext: RegevCiphertext,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelMember {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub l1_withdrawal_recipient: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelState {
    pub channel_id: ChannelId,
    pub epoch: u64,
    pub small_block_number: u64,
    pub close_freeze_nonce: u64,
    pub channel_fund: ChannelFund,
    /// The full hidden-balance state (detail2 §C-3: the state carries the `BalanceState` body;
    /// L1 submissions and signing preimages use its `h1()`).
    pub balance_state: BalanceState,
    /// H2 tag this version was finalized with: `0x00…00` for in-channel updates, the own small
    /// block's `tx_tree_root` for an inter-channel send (detail2 §C-2/§D).
    ///
    /// SECURITY: `H2 = 0` is reserved for in-channel updates — inter-channel paths MUST reject
    /// `tx_tree_root == 0` (the keccak-based tx tree has a nonzero empty root, detail2 §C-2).
    pub h2_tag: Bytes32,
    pub shared_native_nullifier_root: Bytes32,
    pub unallocated_confirmed_incoming: U256,
    pub prev_digest: Bytes32,
    pub digest: Bytes32,
    pub member_signatures: Vec<MemberSignature>,
}

impl ChannelState {
    /// IMCH signing digest. The legacy `channel_balance_root` slot now carries
    /// `balance_state.h1()`, and `h2_tag` + `split_u64(balance_state.state_version)` are
    /// appended at the END of the legacy preimage.
    ///
    /// SECURITY: this digest internalizes abstract2's `hash(H1, H2)` — `member_signatures` over
    /// this digest ARE the three-member `hash(H1, H2)` signatures of abstract2 §3.1 (detail2
    /// §C-3/§D). There is no signing target that covers H1 without H2 or vice versa, which is the
    /// structural atomicity argument of detail2 §D-3.
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CHANNEL_STATE_DOMAIN],
                self.channel_id.to_u32_vec(),
                split_u64(self.epoch),
                split_u64(self.small_block_number),
                split_u64(self.close_freeze_nonce),
                self.channel_fund.channel_id.to_u32_vec(),
                self.channel_fund.amount.to_u32_vec(),
                self.channel_fund.intmax_state_root.to_u32_vec(),
                self.balance_state.h1().to_u32_vec(),
                self.shared_native_nullifier_root.to_u32_vec(),
                self.unallocated_confirmed_incoming.to_u32_vec(),
                self.prev_digest.to_u32_vec(),
                self.h2_tag.to_u32_vec(),
                split_u64(self.balance_state.state_version),
            ]
            .concat(),
        )
    }

    pub fn with_computed_digest(mut self) -> Self {
        self.digest = self.signing_digest();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reject {
    pub proposal_digest: Bytes32,
    pub rejecting_user_id: UserId,
    pub reason: RejectReason,
    pub detail: Vec<u8>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    InvalidZkp,
    InvalidSignature,
    InvalidPrevState,
    InvalidEpoch,
    InvalidStateTransition,
    InsufficientBalance,
    InvalidIntmaxProof,
    AlreadyUsedNullifier,
    InvalidReceiver,
    InvalidSender,
    InvalidDigest,
    Other,
}

/// In-channel transfer (detail2 §C-5, abstract2 §2.2). The amount is visible only to the
/// recipient (decryption) and to the co-signers via the mandatory `channel_tx_zkp` (E-1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelTx {
    pub recipient_user_id: UserId,
    /// Transfer amount encrypted to the recipient's `RegevPk`.
    pub enc_amount: RegevCiphertext,
    /// One-time random value, making otherwise-identical transfers distinguishable.
    pub nonce: Bytes32,
    /// Mandatory E-1 channelTxZKP — co-signers MUST refuse to sign without it.
    pub channel_tx_zkp: ChannelProofEnvelope,
    pub sender_user_id: UserId,
    pub sender_signature: SignatureBytes,
}

impl ChannelTx {
    /// IMPA signing digest (detail2 §C-5):
    /// `[PAY_DOMAIN, channel_id, prev_state_digest, enc_amount.digest(), nonce,
    /// sender_user_id, recipient_user_id]`.
    ///
    /// SECURITY: the ZKP envelope is deliberately NOT part of this digest — the sender authorizes
    /// the transfer (prev state, hidden amount ciphertext, parties); the proof object is
    /// transport material that each co-signer verifies independently against the same statement.
    pub fn signing_digest(
        channel_id: ChannelId,
        prev_state_digest: Bytes32,
        enc_amount: &RegevCiphertext,
        nonce: Bytes32,
        sender_user_id: UserId,
        recipient_user_id: UserId,
    ) -> Bytes32 {
        hash_words(
            &[
                vec![PAY_DOMAIN],
                channel_id.to_u32_vec(),
                prev_state_digest.to_u32_vec(),
                enc_amount.digest().to_u32_vec(),
                nonce.to_u32_vec(),
                sender_user_id.to_u32_vec(),
                recipient_user_id.to_u32_vec(),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiverBalanceDelta {
    pub receiver_key_id: KeyId,
    pub receiver_user_id: UserId,
    /// Positive delta encrypted to the receiver's `RegevPk` (detail2 §C-6).
    pub amount: RegevCiphertext,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterChannelTx {
    pub tx_inclusion_proof: MerkleInclusionProof,
    pub signed_small_block: SignedSmallBlock,
    /// Sender-side balance delta encrypted to the sender's own `RegevPk` (detail2 §C-6;
    /// magnitude = the public amount, the negative sign is positional).
    pub sender_delta_ct: RegevCiphertext,
    pub source_channel_id: ChannelId,
    pub destination_channel_id: ChannelId,
    pub source_key_id: KeyId,
    pub source_user_id: UserId,
    pub seal: Bytes32,
    pub tx_hash: Bytes32,
    pub intmax_transfer_commitment: Bytes32,
    pub recipient_memo: Vec<u8>,
    pub receiver_deltas: Vec<ReceiverBalanceDelta>,
    /// Single E-2 channelUpdateZKP covering the sender rebind AND both deltas (detail2 §C-6;
    /// unifies the retired `receiver_update_proof` / `sender_balance_update_proof` pair).
    pub channel_update_zkp: ChannelProofEnvelope,
    pub transport_proof: Vec<u8>,
}

impl InterChannelTx {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![INTER_CHANNEL_TX_DOMAIN],
                self.signed_small_block.signing_digest().to_u32_vec(),
                self.sender_delta_ct.digest().to_u32_vec(),
                self.source_channel_id.to_u32_vec(),
                self.destination_channel_id.to_u32_vec(),
                self.source_key_id.to_u32_vec(),
                self.source_user_id.to_u32_vec(),
                self.seal.to_u32_vec(),
                self.tx_hash.to_u32_vec(),
                self.intmax_transfer_commitment.to_u32_vec(),
                vec![self.recipient_memo.len() as u32],
                bytes_to_u32_words(&self.recipient_memo),
                vec![self.receiver_deltas.len() as u32],
                self.receiver_deltas
                    .iter()
                    .flat_map(|delta| {
                        [
                            delta.receiver_key_id.to_u32_vec(),
                            delta.receiver_user_id.to_u32_vec(),
                            delta.amount.digest().to_u32_vec(),
                        ]
                        .concat()
                    })
                    .collect::<Vec<_>>(),
                // The two legacy proof-bytes segments are replaced by ONE envelope segment.
                self.channel_update_zkp.to_digest_words(),
                vec![self.transport_proof.len() as u32],
                bytes_to_u32_words(&self.transport_proof),
            ]
            .concat(),
        )
    }

    /// `TxLeafHash` of this transfer (detail2 §C-6): both wings bind user id + delta ciphertext
    /// digest. detail2 §A-2: 1 tx = 1 real receiver, so `receiver_deltas[0]` is THE receiver;
    /// an empty delta list is a malformed tx.
    pub fn tx_leaf_hash(&self) -> Result<Bytes32, ChannelError> {
        let receiver = self.receiver_deltas.first().ok_or_else(|| {
            ChannelError::InvalidInterChannelTx(
                "receiver_deltas must contain exactly one receiver (detail2 §A-2)".to_string(),
            )
        })?;
        Ok(tx_leaf_hash(
            self.source_user_id,
            self.sender_delta_ct.digest(),
            receiver.receiver_user_id,
            receiver.amount.digest(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseWithdrawal {
    pub channel_id: ChannelId,
    pub final_channel_state_digest: Bytes32,
    /// `h1()` of the final `BalanceState` (rename of the legacy `final_channel_balance_root`;
    /// occupies the same IMCL preimage position).
    pub final_balance_state_h1: Bytes32,
    pub intmax_state_root: Bytes32,
    pub burn_tx_hash: Bytes32,
    pub burn_amount: U256,
    pub zkp: Vec<u8>,
}

impl CloseWithdrawal {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CLOSE_TX_DOMAIN],
                self.channel_id.to_u32_vec(),
                self.final_channel_state_digest.to_u32_vec(),
                self.final_balance_state_h1.to_u32_vec(),
                self.intmax_state_root.to_u32_vec(),
                self.burn_tx_hash.to_u32_vec(),
                self.burn_amount.to_u32_vec(),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseIntent {
    pub channel_id: ChannelId,
    pub close_nonce: u64,
    pub final_epoch: u64,
    pub final_small_block_number: u64,
    pub close_freeze_nonce: u64,
    pub final_channel_state_digest: Bytes32,
    /// `h1()` of the final `BalanceState` (rename of the legacy `final_channel_balance_root`).
    pub final_balance_state_h1: Bytes32,
    pub channel_fund_snapshot: ChannelFund,
    pub burn_tx_hash: Bytes32,
    pub close_withdrawal_digest: Bytes32,
    pub snapshot_medium_block_number: u64,
    /// `state_version` of the final balance state — L1 challenge ordering compares
    /// `(final_epoch, final_state_version)` (detail2 §H-4).
    pub final_state_version: u64,
    /// `settled_tx_chain` of the final balance state — matched on L1 against the final balance
    /// proof's exposed chain (detail2 §H-2; the v2 chain-binding core).
    pub final_settled_tx_chain: Bytes32,
}

impl CloseIntent {
    pub fn new(
        close_nonce: u64,
        final_channel_state: &ChannelState,
        close_withdrawal: &CloseWithdrawal,
        snapshot_medium_block_number: u64,
    ) -> Result<Self, ChannelError> {
        if final_channel_state.channel_id != close_withdrawal.channel_id {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final state channel_id {:?} != close withdrawal channel_id {:?}",
                final_channel_state.channel_id, close_withdrawal.channel_id
            )));
        }
        if final_channel_state.digest != close_withdrawal.final_channel_state_digest {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final state digest {:?} != close withdrawal digest {:?}",
                final_channel_state.digest, close_withdrawal.final_channel_state_digest
            )));
        }
        if final_channel_state.balance_state.h1() != close_withdrawal.final_balance_state_h1 {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final balance state h1 {:?} != close withdrawal final_balance_state_h1 {:?}",
                final_channel_state.balance_state.h1(),
                close_withdrawal.final_balance_state_h1
            )));
        }
        if final_channel_state.channel_fund.intmax_state_root != close_withdrawal.intmax_state_root
        {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final intmax state root {:?} != close withdrawal intmax_state_root {:?}",
                final_channel_state.channel_fund.intmax_state_root,
                close_withdrawal.intmax_state_root
            )));
        }
        if final_channel_state.channel_fund.amount != close_withdrawal.burn_amount {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final channel fund amount {:?} != close withdrawal burn_amount {:?}",
                final_channel_state.channel_fund.amount, close_withdrawal.burn_amount
            )));
        }
        if final_channel_state.unallocated_confirmed_incoming != U256::zero() {
            return Err(ChannelError::InvalidCloseBinding(
                "close requires unallocated_confirmed_incoming = 0".to_string(),
            ));
        }
        Ok(Self {
            channel_id: final_channel_state.channel_id,
            close_nonce,
            final_epoch: final_channel_state.epoch,
            final_small_block_number: final_channel_state.small_block_number,
            close_freeze_nonce: final_channel_state.close_freeze_nonce + 1,
            final_channel_state_digest: final_channel_state.digest,
            final_balance_state_h1: final_channel_state.balance_state.h1(),
            channel_fund_snapshot: final_channel_state.channel_fund.clone(),
            burn_tx_hash: close_withdrawal.burn_tx_hash,
            close_withdrawal_digest: close_withdrawal.signing_digest(),
            snapshot_medium_block_number,
            final_state_version: final_channel_state.balance_state.state_version,
            final_settled_tx_chain: final_channel_state.balance_state.settled_tx_chain,
        })
    }

    /// IMCI signing digest. `final_state_version` and `final_settled_tx_chain` are appended at
    /// the END of the legacy preimage (detail2 §C-8).
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CLOSE_INTENT_DOMAIN],
                self.channel_id.to_u32_vec(),
                split_u64(self.close_nonce),
                split_u64(self.final_epoch),
                split_u64(self.final_small_block_number),
                split_u64(self.close_freeze_nonce),
                self.final_channel_state_digest.to_u32_vec(),
                self.final_balance_state_h1.to_u32_vec(),
                self.channel_fund_snapshot.channel_id.to_u32_vec(),
                self.channel_fund_snapshot.amount.to_u32_vec(),
                self.channel_fund_snapshot.intmax_state_root.to_u32_vec(),
                self.burn_tx_hash.to_u32_vec(),
                self.close_withdrawal_digest.to_u32_vec(),
                split_u64(self.snapshot_medium_block_number),
                split_u64(self.final_state_version),
                self.final_settled_tx_chain.to_u32_vec(),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalClaim {
    pub close_intent_digest: Bytes32,
    pub user_id: UserId,
    pub l1_recipient: Address,
    /// The member's final balance ciphertext (their slot of the final `BalanceState`); the
    /// `claim_proof` (E-3 withdrawClaimZKP) proves it decrypts to the public withdrawal amount.
    pub user_amount_ct: RegevCiphertext,
    pub withdrawal_nullifier: Bytes32,
    pub claim_proof: Vec<u8>,
}

impl WithdrawalClaim {
    pub fn derive_nullifier(close_intent_digest: Bytes32, user_id: UserId) -> Bytes32 {
        hash_words(
            &[
                vec![WITHDRAWAL_CLAIM_DOMAIN],
                close_intent_digest.to_u32_vec(),
                user_id.to_u32_vec(),
            ]
            .concat(),
        )
    }

    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![WITHDRAWAL_CLAIM_DOMAIN],
                self.close_intent_digest.to_u32_vec(),
                self.user_id.to_u32_vec(),
                self.l1_recipient.to_u32_vec(),
                self.user_amount_ct.digest().to_u32_vec(),
                self.withdrawal_nullifier.to_u32_vec(),
                vec![self.claim_proof.len() as u32],
                bytes_to_u32_words(&self.claim_proof),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecialClose {
    pub channel_id: ChannelId,
    pub offending_bp_key_id: KeyId,
    pub fully_signed_small_block_root: Bytes32,
    pub small_block_number: u64,
    pub signed_medium_block_number: u64,
    pub latest_finalized_medium_block_number: u64,
    pub non_inclusion_proof: Vec<u8>,
    pub aggregated_signature_proof: Vec<u8>,
}

impl SpecialClose {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![SPECIAL_CLOSE_DOMAIN],
                self.channel_id.to_u32_vec(),
                self.offending_bp_key_id.to_u32_vec(),
                self.fully_signed_small_block_root.to_u32_vec(),
                split_u64(self.small_block_number),
                split_u64(self.signed_medium_block_number),
                split_u64(self.latest_finalized_medium_block_number),
                vec![self.non_inclusion_proof.len() as u32],
                bytes_to_u32_words(&self.non_inclusion_proof),
                vec![self.aggregated_signature_proof.len() as u32],
                bytes_to_u32_words(&self.aggregated_signature_proof),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelClose {
    pub close_intent_digest: Bytes32,
    pub revived_small_block_root: Bytes32,
    pub revived_inter_channel_tx_digest: Bytes32,
    pub revived_tx_hash: Bytes32,
    pub revived_seal: Bytes32,
    pub cancel_proof: Vec<u8>,
}

impl CancelClose {
    pub fn new(
        close_intent: &CloseIntent,
        revived_tx: &InterChannelTx,
        cancel_proof: Vec<u8>,
    ) -> Self {
        Self {
            close_intent_digest: close_intent.signing_digest(),
            revived_small_block_root: revived_tx.signed_small_block.message.signing_digest(),
            revived_inter_channel_tx_digest: revived_tx.signing_digest(),
            revived_tx_hash: revived_tx.tx_hash,
            revived_seal: revived_tx.seal,
            cancel_proof,
        }
    }

    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CANCEL_CLOSE_DOMAIN],
                self.close_intent_digest.to_u32_vec(),
                self.revived_small_block_root.to_u32_vec(),
                self.revived_inter_channel_tx_digest.to_u32_vec(),
                self.revived_tx_hash.to_u32_vec(),
                self.revived_seal.to_u32_vec(),
                vec![self.cancel_proof.len() as u32],
                bytes_to_u32_words(&self.cancel_proof),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostCloseIncomingClaim {
    pub close_intent_digest: Bytes32,
    pub incoming_tx_hash: Bytes32,
    pub receiver_user_id: UserId,
    pub l1_recipient: Address,
    /// The receiver's delta ciphertext from the late inbound tx; the `claim_proof` (E-3) proves
    /// it decrypts to the public claim amount.
    pub receiver_amount: RegevCiphertext,
    pub shared_native_nullifier: Bytes32,
    pub recipient_memo: Vec<u8>,
    pub claim_proof: Vec<u8>,
}

impl PostCloseIncomingClaim {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![POST_CLOSE_CLAIM_DOMAIN],
                self.close_intent_digest.to_u32_vec(),
                self.incoming_tx_hash.to_u32_vec(),
                self.receiver_user_id.to_u32_vec(),
                self.l1_recipient.to_u32_vec(),
                self.receiver_amount.digest().to_u32_vec(),
                self.shared_native_nullifier.to_u32_vec(),
                vec![self.recipient_memo.len() as u32],
                bytes_to_u32_words(&self.recipient_memo),
                vec![self.claim_proof.len() as u32],
                bytes_to_u32_words(&self.claim_proof),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChannelTransition {
    InChannelTransfer(ChannelTx),
    InterChannelSend(InterChannelTx),
    InterChannelFundImport(InterChannelTx),
    ReceiverBundleApply(InterChannelTx),
    /// detail2 §B-3 refresh: a member replaces their own slot with a fresh re-encryption,
    /// resetting their `pending_adds` counter. The payload is the BalanceRefresh proof envelope.
    BalanceRefresh(ChannelProofEnvelope),
    ChannelClose(CloseWithdrawal),
    SpecialClose(SpecialClose),
}

impl ChannelTransition {
    pub const fn kind(&self) -> ChannelTransitionKind {
        match self {
            Self::InChannelTransfer(_) => ChannelTransitionKind::InChannelTransfer,
            Self::InterChannelSend(_) => ChannelTransitionKind::InterChannelSend,
            Self::InterChannelFundImport(_) => ChannelTransitionKind::InterChannelFundImport,
            Self::ReceiverBundleApply(_) => ChannelTransitionKind::ReceiverBundleApply,
            Self::BalanceRefresh(_) => ChannelTransitionKind::BalanceRefresh,
            Self::ChannelClose(_) => ChannelTransitionKind::ChannelClose,
            Self::SpecialClose(_) => ChannelTransitionKind::SpecialClose,
        }
    }

    pub const fn required_state_backend(&self) -> Option<ProofBackend> {
        self.kind().required_state_backend()
    }

    pub const fn required_transport_backend(&self) -> Option<ProofBackend> {
        self.kind().required_transport_backend()
    }
}

pub fn validate_all_member_signatures(
    record: &ChannelRecord,
    channel_id: ChannelId,
    signatures: &[MemberSignature],
) -> Result<(), ChannelError> {
    record.validate()?;
    if signatures.len() != record.member_key_ids.len() {
        return Err(ChannelError::InvalidSignatureSet(format!(
            "expected {} member signatures, got {}",
            record.member_key_ids.len(),
            signatures.len()
        )));
    }
    for (expected_key_id, actual) in record.member_key_ids.iter().zip(signatures) {
        if actual.key_id != *expected_key_id {
            return Err(ChannelError::InvalidSignatureSet(format!(
                "signature key {:?} does not match expected key {:?}",
                actual.key_id, expected_key_id
            )));
        }
        if actual.user_id != UserId::from_parts(channel_id, *expected_key_id) {
            return Err(ChannelError::InvalidSignatureSet(
                "user_id must equal channel_id || key_id".to_string(),
            ));
        }
        if actual.signature.is_empty() {
            return Err(ChannelError::InvalidSignatureSet(
                "signature bytes must not be empty".to_string(),
            ));
        }
        if actual.key_condition_proof.is_empty() {
            return Err(ChannelError::InvalidSignatureSet(
                "key condition proof must not be empty".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn channel_balance_leaf_digest(
    channel_id: ChannelId,
    user_id: UserId,
    balance_ciphertext: &RegevCiphertext,
) -> Bytes32 {
    hash_words(
        &[
            vec![CHANNEL_BALANCE_LEAF_DOMAIN],
            channel_id.to_u32_vec(),
            user_id.to_u32_vec(),
            balance_ciphertext.digest().to_u32_vec(),
        ]
        .concat(),
    )
}

pub fn user_fund_leaf_digest(
    channel_id: ChannelId,
    user_id: UserId,
    balance_ciphertext: &RegevCiphertext,
) -> Bytes32 {
    channel_balance_leaf_digest(channel_id, user_id, balance_ciphertext)
}

pub fn merkle_root_from_proof(leaf: Bytes32, proof: &MerkleInclusionProof) -> Bytes32 {
    let mut current = leaf;
    let bits = proof.leaf_index.to_u32_vec();
    for (depth, sibling) in proof.siblings.iter().enumerate() {
        let limb = bits[bits.len() - 1 - (depth / 32)];
        let bit = (limb >> (depth % 32)) & 1;
        let pair = if bit == 0 {
            [current.to_u32_vec(), sibling.to_u32_vec()].concat()
        } else {
            [sibling.to_u32_vec(), current.to_u32_vec()].concat()
        };
        current = hash_words(&pair);
    }
    current
}

pub fn bridge_user_to_channel_id(user_id: PackedUserId) -> Result<ChannelId, ChannelError> {
    // SECURITY: the canonical `ChannelId::new` now returns `ChannelIdError`; surface it through
    // the channel layer's `ChannelError` so callers keep a single error type at this boundary.
    ChannelId::new(user_id.channel_id() as u64)
        .map_err(|e| ChannelError::InvalidIdValue(e.to_string()))
}

// NOTE (two-layer identity): `bridge_user_to_key_id` was removed. The base-layer `ChannelId`
// carries ONLY the channel id (4 bytes); per-member `key_id` exists exclusively in the channel
// layer and can no longer be derived from a base identifier.

pub(crate) fn split_u64(value: u64) -> Vec<u32> {
    vec![(value >> 32) as u32, value as u32]
}

fn bytes_to_u32_words(bytes: &[u8]) -> Vec<u32> {
    let mut words = Vec::with_capacity(bytes.len().div_ceil(4));
    for chunk in bytes.chunks(4) {
        let mut padded = [0u8; 4];
        padded[..chunk.len()].copy_from_slice(chunk);
        words.push(u32::from_be_bytes(padded));
    }
    words
}

fn fixed_bytes_from_u32_word_slice(values: &[u64], len: usize) -> Result<Vec<u8>, ChannelError> {
    let expected_words = len.div_ceil(4);
    if values.len() != expected_words {
        return Err(ChannelError::InvalidIdLength {
            expected: expected_words,
            actual: values.len(),
        });
    }
    let mut out = Vec::with_capacity(expected_words * 4);
    for word in values {
        if *word > u32::MAX as u64 {
            return Err(ChannelError::InvalidIdValue(format!(
                "u32 limb out of range: {word}"
            )));
        }
        out.extend_from_slice(&(u32::try_from(*word).unwrap()).to_be_bytes());
    }
    out.truncate(len);
    Ok(out)
}

pub(crate) fn hash_words(words: &[u32]) -> Bytes32 {
    Bytes32::from_u32_slice(&solidity_keccak256(words)).expect("keccak output must be bytes32")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ethereum_types::u32limb_trait::U32LimbTrait,
        regev::{REGEV_N, REGEV_Q},
    };

    /// Deterministic canonical ciphertext (raw seed-derived coefficients < q). Not decryptable —
    /// digest-level tests only need canonical, distinct ring elements.
    fn ciphertext(seed: u32) -> RegevCiphertext {
        RegevCiphertext {
            c1: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(2_654_435_761).wrapping_add(i)) % REGEV_Q)
                .collect(),
            c2: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(40_503).wrapping_add(1000 + i)) % REGEV_Q)
                .collect(),
        }
    }

    fn envelope(role: TransitionProofRole, seed: u8) -> ChannelProofEnvelope {
        ChannelProofEnvelope {
            role,
            backend: ProofBackend::Plonky3,
            proof: vec![seed; 5],
        }
    }

    fn sample_channel_id() -> ChannelId {
        ChannelId::new(7).unwrap()
    }

    fn sample_key_id(value: u64) -> KeyId {
        KeyId::new(value).unwrap()
    }

    fn sample_user_id(value: u64) -> UserId {
        UserId::from_parts(sample_channel_id(), sample_key_id(value))
    }

    fn sample_balance_state(version: u64) -> BalanceState {
        BalanceState {
            channel_id: sample_channel_id(),
            enc_balances: [ciphertext(1), ciphertext(2), ciphertext(3)],
            settled_tx_chain: Bytes32::default(),
            state_version: version,
            pending_adds: [0, 0, 0],
        }
    }

    fn sample_state() -> ChannelState {
        ChannelState {
            channel_id: sample_channel_id(),
            epoch: 3,
            small_block_number: 11,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id: sample_channel_id(),
                amount: U256::from(15u32),
                intmax_state_root: Bytes32::default(),
            },
            balance_state: sample_balance_state(4),
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::from_u32_slice(&[5, 6, 7, 8, 0, 0, 0, 0])
                .unwrap(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![
                MemberSignature {
                    key_id: sample_key_id(10),
                    user_id: sample_user_id(10),
                    signature: vec![1],
                    key_condition_proof: vec![2],
                },
                MemberSignature {
                    key_id: sample_key_id(11),
                    user_id: sample_user_id(11),
                    signature: vec![3],
                    key_condition_proof: vec![4],
                },
                MemberSignature {
                    key_id: sample_key_id(12),
                    user_id: sample_user_id(12),
                    signature: vec![5],
                    key_condition_proof: vec![6],
                },
            ],
        }
        .with_computed_digest()
    }

    fn sample_record(member_key_ids: Vec<KeyId>) -> ChannelRecord {
        ChannelRecord {
            channel_id: sample_channel_id(),
            bp_key_id: sample_key_id(10),
            member_key_ids,
            member_key_ids_root: Bytes32::default(),
            special_close_penalty: U256::from(5u32),
            close_freeze_nonce: 0,
            status: ChannelStatus::Active,
            regev_pk_root: Bytes32::from_u32_slice(&[9, 9, 9, 9, 0, 0, 0, 0]).unwrap(),
        }
    }

    fn sample_close_withdrawal(state: &ChannelState) -> CloseWithdrawal {
        CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_balance_state_h1: state.balance_state.h1(),
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[9, 1, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: state.channel_fund.amount,
            zkp: vec![1, 2, 3],
        }
    }

    #[test]
    fn user_id_roundtrip() {
        let channel_id = ChannelId::new(0x01020304).unwrap();
        let key_id = KeyId::new(0x06070809).unwrap();
        let user_id = UserId::from_parts(channel_id, key_id);
        assert_eq!(user_id.channel_id(), channel_id);
        assert_eq!(user_id.key_id(), key_id);
        assert_eq!(
            UserId::from_u64_slice(&user_id.to_u64_vec()).unwrap(),
            user_id
        );
    }

    #[test]
    fn close_intent_is_stable_and_carries_balance_state_bindings() {
        let state = sample_state();
        let close_tx = sample_close_withdrawal(&state);
        let intent_a = CloseIntent::new(9, &state, &close_tx, 123).unwrap();
        let intent_b = CloseIntent::new(9, &state, &close_tx, 123).unwrap();
        assert_eq!(intent_a, intent_b);
        assert_eq!(
            intent_a.final_state_version,
            state.balance_state.state_version
        );
        assert_eq!(
            intent_a.final_settled_tx_chain,
            state.balance_state.settled_tx_chain
        );

        // The appended IMCI fields are signature-binding.
        let mut tampered = intent_a.clone();
        tampered.final_state_version += 1;
        assert_ne!(tampered.signing_digest(), intent_a.signing_digest());
        let mut tampered = intent_a.clone();
        tampered.final_settled_tx_chain =
            Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(tampered.signing_digest(), intent_a.signing_digest());
    }

    /// Shared Rust<->Solidity test vector: the SAME fully-populated `CloseIntent` is hashed by
    /// `ChannelSettlementManager.computeCloseIntentDigest` /
    /// `ChannelSettlementVerifier.closePIHash` (inner keccak) in
    /// contracts/test/ChannelSettlementManager.t.sol
    /// (`test_close_intent_digest_matches_rust_shared_vector`) and MUST produce the same
    /// constant. If the two sides disagree, the Solidity `abi.encodePacked` mirror of the IMCI
    /// preimage is stale — fix Solidity, not this digest.
    #[test]
    fn close_intent_digest_matches_solidity_shared_vector() {
        let words = |base: u32| -> Vec<u32> { (base..base + 8).collect() };
        let intent = CloseIntent {
            channel_id: ChannelId::new(9).unwrap(),
            close_nonce: 0x1111_1111_2222_2222,
            final_epoch: 0x3333_3333_4444_4444,
            final_small_block_number: 0x5555_5555_6666_6666,
            close_freeze_nonce: 0x7777_7777_8888_8888,
            final_channel_state_digest: Bytes32::from_u32_slice(&words(1)).unwrap(),
            final_balance_state_h1: Bytes32::from_u32_slice(&words(9)).unwrap(),
            channel_fund_snapshot: ChannelFund {
                channel_id: ChannelId::new(9).unwrap(),
                amount: U256::from_u32_slice(&words(17)).unwrap(),
                intmax_state_root: Bytes32::from_u32_slice(&words(25)).unwrap(),
            },
            burn_tx_hash: Bytes32::from_u32_slice(&words(33)).unwrap(),
            close_withdrawal_digest: Bytes32::from_u32_slice(&words(41)).unwrap(),
            snapshot_medium_block_number: 0x9999_9999_aaaa_aaaa,
            final_state_version: 0xbbbb_bbbb_cccc_cccc,
            final_settled_tx_chain: Bytes32::from_u32_slice(&words(49)).unwrap(),
        };
        let expected =
            Bytes32::from_hex("0xa2679bf7c2d9c08c45b6fdd39202456707cbdcf3e1667a45fb493a717b37d264")
                .unwrap();
        assert_eq!(intent.signing_digest(), expected);
    }

    #[test]
    fn close_intent_rejects_mismatched_balance_state_h1() {
        let state = sample_state();
        let mut close_tx = sample_close_withdrawal(&state);
        close_tx.final_balance_state_h1 =
            Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert!(matches!(
            CloseIntent::new(9, &state, &close_tx, 123),
            Err(ChannelError::InvalidCloseBinding(_))
        ));
    }

    #[test]
    fn two_member_channel_records_are_rejected() {
        // CHANNEL_MEMBERS = 3 is mandatory (abstract2 §2.1): the legacy 2-member record that the
        // old test accepted must now FAIL validation.
        let record = sample_record(vec![sample_key_id(10), sample_key_id(11)]);
        assert!(matches!(
            record.validate(),
            Err(ChannelError::InvalidChannelRecord(_))
        ));
        assert!(
            validate_all_member_signatures(
                &record,
                sample_channel_id(),
                &sample_state().member_signatures,
            )
            .is_err()
        );
    }

    #[test]
    fn three_member_record_with_pk_root_validates_signatures() {
        let record = sample_record(vec![
            sample_key_id(10),
            sample_key_id(11),
            sample_key_id(12),
        ]);
        record.validate().unwrap();
        validate_all_member_signatures(
            &record,
            sample_channel_id(),
            &sample_state().member_signatures,
        )
        .unwrap();

        // A zero regev_pk_root unanchors the member keys and must be rejected.
        let mut unanchored = record.clone();
        unanchored.regev_pk_root = Bytes32::default();
        assert!(matches!(
            unanchored.validate(),
            Err(ChannelError::InvalidChannelRecord(_))
        ));

        // regev_pk_root is signature-binding (IMCR preimage tail).
        let mut other_root = record.clone();
        other_root.regev_pk_root = Bytes32::from_u32_slice(&[8, 8, 8, 8, 0, 0, 0, 0]).unwrap();
        assert_ne!(other_root.signing_digest(), record.signing_digest());
    }

    #[test]
    fn channel_state_signing_digest_internalizes_h1_and_h2() {
        let state = sample_state();
        let digest = state.signing_digest();

        // H1 components are binding through balance_state.h1().
        let mut s = state.clone();
        s.balance_state.enc_balances[1] = ciphertext(42);
        assert_ne!(s.signing_digest(), digest);
        let mut s = state.clone();
        s.balance_state.pending_adds[0] += 1;
        assert_ne!(s.signing_digest(), digest);

        // The appended H2 tag and state_version are binding.
        let mut s = state.clone();
        s.h2_tag = Bytes32::from_u32_slice(&[3, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(s.signing_digest(), digest);
        let mut s = state.clone();
        s.balance_state.state_version += 1;
        assert_ne!(s.signing_digest(), digest);
    }

    fn sample_inter_channel_tx(state: &ChannelState) -> InterChannelTx {
        let small_block = SignedSmallBlock {
            message: SmallBlockRootMessage {
                channel_id: sample_channel_id(),
                bp_key_id: sample_key_id(10),
                small_block_number: 12,
                prev_small_block_root: Bytes32::default(),
                tx_tree_root: Bytes32::from_u32_slice(&[4, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
                state_commitment_root: Bytes32::default(),
                medium_epoch_hint: 3,
                close_freeze_nonce: 0,
            },
            signatures: state.member_signatures.clone(),
            aggregated_signature_proof: vec![1],
            medium_block_number: 4,
            confirmation_proof: vec![2],
        };
        InterChannelTx {
            tx_inclusion_proof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::zero(),
            },
            signed_small_block: small_block,
            sender_delta_ct: ciphertext(31),
            source_channel_id: sample_channel_id(),
            destination_channel_id: ChannelId::new(8).unwrap(),
            source_key_id: sample_key_id(10),
            source_user_id: sample_user_id(10),
            seal: Bytes32::default(),
            tx_hash: Bytes32::from_u32_slice(&[3, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![],
            receiver_deltas: vec![ReceiverBalanceDelta {
                receiver_key_id: KeyId::new(21).unwrap(),
                receiver_user_id: UserId::from_parts(
                    ChannelId::new(8).unwrap(),
                    KeyId::new(21).unwrap(),
                ),
                amount: ciphertext(32),
            }],
            channel_update_zkp: envelope(TransitionProofRole::ChannelStateUpdate, 7),
            transport_proof: vec![3],
        }
    }

    #[test]
    fn cancel_close_binds_small_block_root() {
        let state = sample_state();
        let tx = sample_inter_channel_tx(&state);
        let close_tx = sample_close_withdrawal(&state);
        let close_intent = CloseIntent::new(1, &state, &close_tx, 5).unwrap();
        let cancel = CancelClose::new(&close_intent, &tx, vec![9]);
        assert_eq!(
            cancel.revived_small_block_root,
            tx.signed_small_block.message.signing_digest()
        );
    }

    #[test]
    fn inter_channel_tx_digest_binds_envelope_and_delta() {
        let state = sample_state();
        let tx = sample_inter_channel_tx(&state);
        let digest = tx.signing_digest();

        let mut tampered = tx.clone();
        tampered.sender_delta_ct = ciphertext(99);
        assert_ne!(tampered.signing_digest(), digest);

        // The unified channel_update_zkp envelope segment is digest-binding: proof bytes,
        // role tag, and backend tag each matter.
        let mut tampered = tx.clone();
        tampered.channel_update_zkp.proof = vec![9; 5];
        assert_ne!(tampered.signing_digest(), digest);
        let mut tampered = tx.clone();
        tampered.channel_update_zkp.role = TransitionProofRole::IntmaxTransport;
        assert_ne!(tampered.signing_digest(), digest);
        let mut tampered = tx.clone();
        tampered.channel_update_zkp.backend = ProofBackend::Plonky2;
        assert_ne!(tampered.signing_digest(), digest);
    }

    #[test]
    fn inter_channel_tx_leaf_hash_requires_a_receiver() {
        let state = sample_state();
        let tx = sample_inter_channel_tx(&state);
        let leaf = tx.tx_leaf_hash().unwrap();
        assert_eq!(
            leaf,
            tx_leaf_hash(
                tx.source_user_id,
                tx.sender_delta_ct.digest(),
                tx.receiver_deltas[0].receiver_user_id,
                tx.receiver_deltas[0].amount.digest(),
            )
        );

        let mut empty = tx.clone();
        empty.receiver_deltas.clear();
        assert!(matches!(
            empty.tx_leaf_hash(),
            Err(ChannelError::InvalidInterChannelTx(_))
        ));
    }

    #[test]
    fn channel_tx_signing_digest_binds_all_components_except_zkp() {
        let state = sample_state();
        let enc_amount = ciphertext(50);
        let nonce = Bytes32::from_u32_slice(&[6, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let digest = ChannelTx::signing_digest(
            state.channel_id,
            state.digest,
            &enc_amount,
            nonce,
            sample_user_id(10),
            sample_user_id(11),
        );
        // Sensitive to amount ciphertext, nonce, parties, prev state.
        assert_ne!(
            digest,
            ChannelTx::signing_digest(
                state.channel_id,
                state.digest,
                &ciphertext(51),
                nonce,
                sample_user_id(10),
                sample_user_id(11),
            )
        );
        assert_ne!(
            digest,
            ChannelTx::signing_digest(
                state.channel_id,
                state.digest,
                &enc_amount,
                Bytes32::default(),
                sample_user_id(10),
                sample_user_id(11),
            )
        );
        assert_ne!(
            digest,
            ChannelTx::signing_digest(
                state.channel_id,
                state.digest,
                &enc_amount,
                nonce,
                sample_user_id(11),
                sample_user_id(10),
            )
        );
        assert_ne!(
            digest,
            ChannelTx::signing_digest(
                state.channel_id,
                Bytes32::default(),
                &enc_amount,
                nonce,
                sample_user_id(10),
                sample_user_id(11),
            )
        );
    }

    #[test]
    fn withdrawal_nullifier_depends_on_user_id() {
        let close_digest = Bytes32::from_u32_slice(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let a = WithdrawalClaim::derive_nullifier(close_digest, sample_user_id(10));
        let b = WithdrawalClaim::derive_nullifier(close_digest, sample_user_id(11));
        assert_ne!(a, b);
    }
}
