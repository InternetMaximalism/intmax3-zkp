use plonky2_keccak::utils::solidity_keccak256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// SECURITY: re-export the canonical `ChannelId` so the channel layer and every downstream module
// share ONE channel identifier type with identical keccak digest semantics.
pub use crate::common::channel_id::ChannelId;
use crate::{
    common::balance_state::{BalanceState, tx_leaf_hash},
    constants::MAX_CHANNEL_MEMBERS,
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
// "IMCM" — domain separator for the close-circuit member-set commitment. The full channel-close
// circuit exposes `member_set_commitment = keccak([IMCM, sphincs_pk_hash_0..2])` as a public input;
// L1 (`ChannelSettlementManager`) matches it against `keccak([IMCM, registered
// member_pk_gs])` so the 3 verified signing keys are bound to the channel's
// registered member set (no non-member-key substitution). See `close_member_set_commitment`.
const CLOSE_MEMBER_SET_DOMAIN: u32 = 0x494d434d; // "IMCM"
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelRecord {
    pub channel_id: ChannelId,
    /// Number of ACTIVE members (2..=MAX_CHANNEL_MEMBERS). Active members occupy slots
    /// `0..member_count`; slots `member_count..MAX_CHANNEL_MEMBERS` are padding
    /// (`Bytes32::default()` pubkey hashes). Pad-to-MAX deviation D6.
    pub member_count: u8,
    /// Ordered member identities = SPHINCS+ pubkey hashes, slot order 0..MAX_CHANNEL_MEMBERS.
    /// Active slots (`< member_count`) are nonzero and pairwise-distinct; padding slots are
    /// `Bytes32::default()`.
    pub member_pk_gs: [Bytes32; MAX_CHANNEL_MEMBERS],
    /// L1/keccak digest form of the channel's member tree root. The in-circuit
    /// `ChannelLeaf.member_pubkeys_root` is a Poseidon root (different representation, DB); this
    /// keccak form anchors the same member set at the L1 boundary.
    pub member_pubkeys_root: Bytes32,
    /// The slot whose member acts as block-proposer (replaces `bp_key_id`). Must be `<
    /// member_count`.
    pub bp_member_slot: u8,
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
        if self.regev_pk_root == Bytes32::default() {
            return Err(ChannelError::InvalidChannelRecord(
                "regev_pk_root must be set (zero root would unanchor the member Regev keys)"
                    .to_string(),
            ));
        }
        let count = self.member_count as usize;
        if count < 2 || count > MAX_CHANNEL_MEMBERS {
            return Err(ChannelError::InvalidChannelRecord(format!(
                "member_count {count} out of range (must be 2..={MAX_CHANNEL_MEMBERS})"
            )));
        }
        if (self.bp_member_slot as usize) >= count {
            return Err(ChannelError::InvalidChannelRecord(format!(
                "bp_member_slot {} out of range (must be < member_count {count})",
                self.bp_member_slot
            )));
        }
        // One SPHINCS+ key per member: the ACTIVE pubkey hashes (slots 0..member_count) must be
        // nonzero and pairwise distinct (no shared-key / duplicate-member forgery); PADDING slots
        // (>= member_count) must be Bytes32::default().
        for (i, hash) in self.member_pk_gs.iter().enumerate() {
            if i < count {
                if *hash == Bytes32::default() {
                    return Err(ChannelError::InvalidChannelRecord(format!(
                        "member_pk_gs[{i}] (active) must be nonzero"
                    )));
                }
                for (j, other) in self
                    .member_pk_gs
                    .iter()
                    .enumerate()
                    .skip(i + 1)
                {
                    if j < count && hash == other {
                        return Err(ChannelError::InvalidChannelRecord(
                            "active member_pk_gs must be pairwise distinct"
                                .to_string(),
                        ));
                    }
                }
            } else if *hash != Bytes32::default() {
                return Err(ChannelError::InvalidChannelRecord(format!(
                    "member_pk_gs[{i}] is a padding slot (>= member_count {count}) \
                     and must be Bytes32::default()"
                )));
            }
        }
        Ok(())
    }

    /// IMCR signing digest (pad-to-MAX D6). Member segment = `bp_member_slot`(1) +
    /// `status`(1) + `member_count`(1) + ALL `MAX_CHANNEL_MEMBERS` pubkey hashes (16*8 = 128
    /// limbs, padding slots contribute their `Bytes32::default()` zero limbs) +
    /// `member_pubkeys_root`(8). `regev_pk_root` stays at the END of the preimage (detail2 §H-1).
    ///
    /// PREIMAGE (exact): `[IMCR, channel_id(1), bp_member_slot(1), split_u64(close_freeze_nonce),
    /// status(1), member_count(1), member_hashes(16*8), member_pubkeys_root(8),
    /// special_close_penalty(8), regev_pk_root(8)]`. The `member_count` limb replaces the legacy
    /// `CHANNEL_MEMBERS` constant limb in the same position; hashing all 16 hashes (not just the
    /// active ones) fixes the active/padding split under the member signatures.
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CHANNEL_RECORD_DOMAIN],
                self.channel_id.to_u32_vec(),
                vec![self.bp_member_slot as u32],
                split_u64(self.close_freeze_nonce),
                vec![self.status as u32, self.member_count as u32],
                self.member_pk_gs
                    .iter()
                    .flat_map(Bytes32::to_u32_vec)
                    .collect::<Vec<_>>(),
                self.member_pubkeys_root.to_u32_vec(),
                self.special_close_penalty.to_u32_vec(),
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
    /// Block-producer member slot (0..member_count) and its SPHINCS+ pubkey hash.
    pub bp_member_slot: u8,
    pub bp_pk_g: Bytes32,
    pub small_block_number: u64,
    pub prev_small_block_root: Bytes32,
    pub tx_tree_root: Bytes32,
    pub state_commitment_root: Bytes32,
    pub medium_epoch_hint: u64,
    pub close_freeze_nonce: u64,
}

impl SmallBlockRootMessage {
    /// IMSB signing digest. Member segment = `bp_member_slot`(1) + `bp_pk_g`(8).
    /// MUST match the in-circuit recompute in
    /// `circuits::validity::block_hash_chain::sphincs_sig` limb-for-limb.
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![SMALL_BLOCK_DOMAIN],
                self.channel_id.to_u32_vec(),
                vec![self.bp_member_slot as u32],
                self.bp_pk_g.to_u32_vec(),
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
    /// Member slot (0..member_count) — array index into the channel's active member list.
    pub member_slot: u8,
    /// The signing member's SPHINCS+ pubkey hash (their identity).
    pub pk_g: Bytes32,
    pub signature: SignatureBytes,
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
                            vec![signature.member_slot as u32],
                            signature.pk_g.to_u32_vec(),
                            vec![signature.signature.len() as u32],
                            bytes_to_u32_words(&signature.signature),
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
    pub pk_g: Bytes32,
    /// The member's hidden balance, encrypted to their own `RegevPk` (detail2 §C-4).
    pub balance_ciphertext: RegevCiphertext,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelMember {
    pub pk_g: Bytes32,
    pub member_slot: u8,
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
    pub rejecting_member_pubkey_hash: Bytes32,
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
    pub recipient_pk_g: Bytes32,
    /// Transfer amount encrypted to the recipient's `RegevPk`.
    pub enc_amount: RegevCiphertext,
    /// One-time random value, making otherwise-identical transfers distinguishable.
    pub nonce: Bytes32,
    /// Mandatory E-1 channelTxZKP — co-signers MUST refuse to sign without it.
    pub channel_tx_zkp: ChannelProofEnvelope,
    pub sender_pk_g: Bytes32,
    /// P3 sender authorization: the Poseidon2-BabyBear hash-signature STARK proof bytes over the
    /// IMPA `signing_digest` (replaces the legacy SPHINCS+ `sender_signature`). The proof's public
    /// values are `[pk_b(8) ‖ m(16)]`; the off-chain verifier binds `m == decompose(signing_digest)`
    /// and `pk_b == sender_pk_b`, and confirms `(sender_pk_g, sender_pk_b, sender_regev_pk)` is one
    /// registered `MemberLeaf` (A11). The IMPA `signing_digest` preimage is UNCHANGED.
    pub sender_hash_sig: Vec<u8>,
    /// The sender's BabyBear hash-sig public key `pk_b` (canonical `Bytes32` digest), bound to the
    /// proof's `pk_b` public value and to the sender's registered `MemberLeaf` (A11).
    pub sender_pk_b: Bytes32,
}

impl ChannelTx {
    /// IMPA signing digest (detail2 §C-5):
    /// `[PAY_DOMAIN, channel_id, prev_state_digest, enc_amount.digest(), nonce,
    /// sender_pubkey_hash(8), recipient_pubkey_hash(8)]`.
    ///
    /// SECURITY: the ZKP envelope is deliberately NOT part of this digest — the sender authorizes
    /// the transfer (prev state, hidden amount ciphertext, parties); the proof object is
    /// transport material that each co-signer verifies independently against the same statement.
    pub fn signing_digest(
        channel_id: ChannelId,
        prev_state_digest: Bytes32,
        enc_amount: &RegevCiphertext,
        nonce: Bytes32,
        sender_pk_g: Bytes32,
        recipient_pk_g: Bytes32,
    ) -> Bytes32 {
        hash_words(
            &[
                vec![PAY_DOMAIN],
                channel_id.to_u32_vec(),
                prev_state_digest.to_u32_vec(),
                enc_amount.digest().to_u32_vec(),
                nonce.to_u32_vec(),
                sender_pk_g.to_u32_vec(),
                recipient_pk_g.to_u32_vec(),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiverBalanceDelta {
    pub receiver_pk_g: Bytes32,
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
    pub source_pk_g: Bytes32,
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
                self.source_pk_g.to_u32_vec(),
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
                            delta.receiver_pk_g.to_u32_vec(),
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
            self.source_pk_g,
            self.sender_delta_ct.digest(),
            receiver.receiver_pk_g,
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
    pub member_pk_g: Bytes32,
    pub l1_recipient: Address,
    /// The member's final balance ciphertext (their slot of the final `BalanceState`); the
    /// `claim_proof` (E-3 withdrawClaimZKP) proves it decrypts to the public withdrawal amount.
    pub user_amount_ct: RegevCiphertext,
    pub withdrawal_nullifier: Bytes32,
    pub claim_proof: Vec<u8>,
}

impl WithdrawalClaim {
    /// Nullifier `[IMCW, close_intent_digest(8), member_pk_g(8)]`.
    ///
    /// SECURITY: `close_intent_digest` embeds `channel_id`, so the (channel, close, member) tuple
    /// is unique even though a bare pubkey hash is channel-independent (plan §7 collision-freedom).
    pub fn derive_nullifier(
        close_intent_digest: Bytes32,
        member_pk_g: Bytes32,
    ) -> Bytes32 {
        hash_words(
            &[
                vec![WITHDRAWAL_CLAIM_DOMAIN],
                close_intent_digest.to_u32_vec(),
                member_pk_g.to_u32_vec(),
            ]
            .concat(),
        )
    }

    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![WITHDRAWAL_CLAIM_DOMAIN],
                self.close_intent_digest.to_u32_vec(),
                self.member_pk_g.to_u32_vec(),
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
    pub offending_bp_member_slot: u8,
    pub offending_bp_pk_g: Bytes32,
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
                vec![self.offending_bp_member_slot as u32],
                self.offending_bp_pk_g.to_u32_vec(),
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
    pub receiver_pk_g: Bytes32,
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
                self.receiver_pk_g.to_u32_vec(),
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

/// Validate the N-of-N member signature set against the channel's ACTIVE member pubkey hashes by
/// slot (pad-to-MAX D6: exactly `member_count` signatures, one per active slot).
///
/// One SPHINCS+ key per member (N-of-N, no threshold): `signatures[i].member_slot == i` and
/// `signatures[i].pk_g == record.member_pk_gs[i]` for every active
/// slot `i in 0..member_count`.
pub fn validate_all_member_signatures(
    record: &ChannelRecord,
    signatures: &[MemberSignature],
) -> Result<(), ChannelError> {
    record.validate()?;
    let count = record.member_count as usize;
    if signatures.len() != count {
        return Err(ChannelError::InvalidSignatureSet(format!(
            "expected {count} member signatures (member_count), got {}",
            signatures.len()
        )));
    }
    for (slot, actual) in signatures.iter().enumerate() {
        if actual.member_slot as usize != slot {
            return Err(ChannelError::InvalidSignatureSet(format!(
                "signature {slot} has member_slot {}, expected {slot}",
                actual.member_slot
            )));
        }
        if actual.pk_g != record.member_pk_gs[slot] {
            return Err(ChannelError::InvalidSignatureSet(format!(
                "signature pubkey hash at slot {slot} does not match the channel member"
            )));
        }
        if actual.signature.is_empty() {
            return Err(ChannelError::InvalidSignatureSet(
                "signature bytes must not be empty".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn channel_balance_leaf_digest(
    channel_id: ChannelId,
    pk_g: Bytes32,
    balance_ciphertext: &RegevCiphertext,
) -> Bytes32 {
    hash_words(
        &[
            vec![CHANNEL_BALANCE_LEAF_DOMAIN],
            channel_id.to_u32_vec(),
            pk_g.to_u32_vec(),
            balance_ciphertext.digest().to_u32_vec(),
        ]
        .concat(),
    )
}

pub fn user_fund_leaf_digest(
    channel_id: ChannelId,
    pk_g: Bytes32,
    balance_ciphertext: &RegevCiphertext,
) -> Bytes32 {
    channel_balance_leaf_digest(channel_id, pk_g, balance_ciphertext)
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

pub(crate) fn hash_words(words: &[u32]) -> Bytes32 {
    Bytes32::from_u32_slice(&solidity_keccak256(words)).expect("keccak output must be bytes32")
}

/// Close-circuit member-set commitment (detail2 §F-3, F5 soundness binding; pad-to-MAX D6).
///
/// `member_set_commitment = keccak([IMCM, member_count, h_0(8), …, h_{MAX-1}(8)])` over
/// `member_count` (single u32 limb right after the domain) and ALL `MAX_CHANNEL_MEMBERS` SPHINCS+
/// pubkey hashes in SLOT ORDER, where PADDING slots (`>= member_count`) contribute their
/// `Bytes32::default()` (zero) limbs. This preimage is FIXED-LENGTH.
///
/// SECURITY: this commits the active set INJECTIVELY — `member_count` fixes the active/padding
/// boundary and padding hashes are zero (the close circuit selects zero for `slot >= member_count`
/// and `ChannelRecord::validate` rejects nonzero padding hashes), so two different active sets
/// cannot collide. The full channel-close circuit recomputes this commitment in-circuit from the
/// SAME pubkeys whose SPHINCS+ signatures it verifies, and exposes it as a public input; L1 matches
/// it against the channel's registered member set, so a prover cannot substitute non-member signing
/// keys.
///
/// DESIGN NOTE (D6, forced): the preimage is fixed-length (member_count + all 16 hashes, padding
/// zeroed) rather than the "active-only" variable-length form, because the in-circuit keccak gadget
/// takes a build-time-fixed input length and cannot hash a `member_count`-dependent number of
/// words. The fixed form is cryptographically equivalent (member_count + zeroed padding is
/// injective on the active set). This native helper MUST agree byte-for-byte with the in-circuit
/// keccak (`ChannelCloseCircuit::new`) and the L1 mirror — all use the canonical big-endian
/// `solidity_keccak256` over one u32 word per limb.
pub fn close_member_set_commitment(
    hashes: &[Bytes32; MAX_CHANNEL_MEMBERS],
    member_count: u8,
) -> Bytes32 {
    let count = member_count as usize;
    let mut words = Vec::with_capacity(2 + MAX_CHANNEL_MEMBERS * 8);
    words.push(CLOSE_MEMBER_SET_DOMAIN);
    words.push(member_count as u32);
    for (i, hash) in hashes.iter().enumerate() {
        // Padding slots contribute zero limbs (matches the in-circuit select on slot_is_active).
        if i < count {
            words.extend_from_slice(&hash.to_u32_vec());
        } else {
            words.extend_from_slice(&Bytes32::default().to_u32_vec());
        }
    }
    hash_words(&words)
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

    /// A distinct, canonical member SPHINCS+ pubkey hash (Bytes32) per seed.
    fn pubkey_hash(seed: u32) -> Bytes32 {
        Bytes32::from_u32_slice(&[
            seed,
            seed + 1,
            seed + 2,
            seed + 3,
            seed + 4,
            seed + 5,
            seed + 6,
            seed + 7,
        ])
        .unwrap()
    }

    fn sample_balance_state(version: u64) -> BalanceState {
        BalanceState {
            channel_id: sample_channel_id(),
            member_count: 3,
            enc_balances: BalanceState::pad_enc_balances(&[
                ciphertext(1),
                ciphertext(2),
                ciphertext(3),
            ]),
            settled_tx_chain: Bytes32::default(),
            state_version: version,
            pending_adds: BalanceState::pad_pending_adds(&[0, 0, 0]),
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
                    member_slot: 0,
                    pk_g: pubkey_hash(10),
                    signature: vec![1],
                },
                MemberSignature {
                    member_slot: 1,
                    pk_g: pubkey_hash(11),
                    signature: vec![3],
                },
                MemberSignature {
                    member_slot: 2,
                    pk_g: pubkey_hash(12),
                    signature: vec![5],
                },
            ],
        }
        .with_computed_digest()
    }

    /// Pad an active prefix of member pubkey hashes to the full MAX_CHANNEL_MEMBERS array.
    fn pad_hashes(active: &[Bytes32]) -> [Bytes32; MAX_CHANNEL_MEMBERS] {
        std::array::from_fn(|i| active.get(i).copied().unwrap_or_default())
    }

    fn sample_record() -> ChannelRecord {
        ChannelRecord {
            channel_id: sample_channel_id(),
            member_count: 3,
            member_pk_gs: pad_hashes(&[
                pubkey_hash(10),
                pubkey_hash(11),
                pubkey_hash(12),
            ]),
            member_pubkeys_root: Bytes32::from_u32_slice(&[7, 7, 7, 7, 0, 0, 0, 0]).unwrap(),
            bp_member_slot: 0,
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

    /// Shared Rust<->Solidity test vector for the F7 close-circuit member-set commitment. The
    /// SAME 3 member pubkey hashes (h0 = limbs 1..8, h1 = 9..16, h2 = 17..24) are hashed by
    /// `ChannelSettlementVerifier.closeMemberSetCommitment` in
    /// contracts/test/ChannelSettlementManager.t.sol
    /// (`test_member_set_commitment_matches_rust_shared_vector`) and MUST produce the same
    /// constant. If the two sides disagree, the Solidity `abi.encodePacked` mirror of the IMCM
    /// preimage is stale — fix Solidity, not this digest.
    #[test]
    fn close_member_set_commitment_matches_solidity_shared_vector() {
        let words = |base: u32| -> Vec<u32> { (base..base + 8).collect() };
        // 3 ACTIVE member hashes padded to MAX_CHANNEL_MEMBERS. The commitment is the FIXED 16-slot
        // form (pad-to-MAX D6): keccak([IMCM, member_count, h_0..h_15]) with padding slots zeroed
        // (130 u32 words). This pinned constant is mirrored by the Foundry test
        // `test_member_set_commitment_matches_rust_shared_vector` in
        // contracts/test/ChannelSettlementManager.t.sol — if they disagree, fix Solidity, not this
        // digest.
        let active = vec![
            Bytes32::from_u32_slice(&words(1)).unwrap(),
            Bytes32::from_u32_slice(&words(9)).unwrap(),
            Bytes32::from_u32_slice(&words(17)).unwrap(),
        ];
        let hashes = pad_hashes(&active);
        let committed = close_member_set_commitment(&hashes, 3);
        let expected =
            Bytes32::from_hex("0x12450612c5f67b7ff613b705f6e5efccf4bdd43e647570fcb207076f447236cc")
                .unwrap();
        assert_eq!(committed, expected);
        // Padding slots (>= member_count) are zeroed INTERNALLY, so a nonzero padding slot in the
        // input array does NOT change the commitment — the value depends only on member_count and
        // the active hashes. This makes the FIXED-form commitment injective on the active set
        // (and `validate()` independently forbids nonzero padding on real records).
        let mut tampered_padding = hashes;
        tampered_padding[3] = Bytes32::from_u32_slice(&words(25)).unwrap();
        assert_eq!(
            close_member_set_commitment(&tampered_padding, 3),
            committed,
            "padding slots are zeroed internally and must not affect member_set_commitment"
        );
        // member_count is part of the preimage: a different count changes the value.
        assert_ne!(close_member_set_commitment(&hashes, 4), committed);
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
    fn duplicate_or_zero_member_pubkey_hashes_are_rejected() {
        // One key per member: the 3 pubkey hashes must be nonzero and pairwise distinct.
        let mut dup = sample_record();
        dup.member_pk_gs[1] = dup.member_pk_gs[0];
        assert!(matches!(
            dup.validate(),
            Err(ChannelError::InvalidChannelRecord(_))
        ));

        let mut zero = sample_record();
        zero.member_pk_gs[2] = Bytes32::default();
        assert!(matches!(
            zero.validate(),
            Err(ChannelError::InvalidChannelRecord(_))
        ));

        // bp_member_slot must be in range (< member_count, here 3).
        let mut bad_bp = sample_record();
        bad_bp.bp_member_slot = bad_bp.member_count;
        assert!(matches!(
            bad_bp.validate(),
            Err(ChannelError::InvalidChannelRecord(_))
        ));
    }

    /// Build a `ChannelRecord` with `count` ACTIVE members (distinct nonzero pubkey hashes in
    /// slots 0..count, padding = default) for the multi-N native `validate()` coverage below.
    fn record_with_members(count: u8) -> ChannelRecord {
        let active: Vec<Bytes32> = (0..count as u32)
            .map(|i| pubkey_hash(100 + i * 8))
            .collect();
        ChannelRecord {
            channel_id: sample_channel_id(),
            member_count: count,
            member_pk_gs: pad_hashes(&active),
            member_pubkeys_root: Bytes32::from_u32_slice(&[7, 7, 7, 7, 0, 0, 0, 0]).unwrap(),
            bp_member_slot: 0,
            special_close_penalty: U256::from(5u32),
            close_freeze_nonce: 0,
            status: ChannelStatus::Active,
            regev_pk_root: Bytes32::from_u32_slice(&[9, 9, 9, 9, 0, 0, 0, 0]).unwrap(),
        }
    }

    /// Multi-N (D6 pad-to-MAX): `ChannelRecord::validate()` ACCEPTS member_count = 2 / 8 / 16
    /// (the boundary and an interior value) when active slots are distinct + nonzero and padding
    /// slots are `Bytes32::default()`, and REJECTS the D6 boundary violations.
    #[test]
    fn channel_record_validate_multi_n() {
        // Accepts 2 (min), 8 (interior), 16 (max, all slots active, no padding).
        for count in [2u8, 8, 16] {
            record_with_members(count)
                .validate()
                .unwrap_or_else(|e| panic!("member_count {count} must validate: {e}"));
        }

        // member_count < 2 is rejected.
        let mut too_few = record_with_members(2);
        too_few.member_count = 1;
        // slot 1 is now a "padding" slot but nonzero — but the count check fires first regardless.
        assert!(matches!(
            too_few.validate(),
            Err(ChannelError::InvalidChannelRecord(_))
        ));

        // member_count > MAX_CHANNEL_MEMBERS is rejected.
        let mut too_many = record_with_members(16);
        too_many.member_count = (MAX_CHANNEL_MEMBERS + 1) as u8;
        assert!(matches!(
            too_many.validate(),
            Err(ChannelError::InvalidChannelRecord(_))
        ));

        // A nonzero PADDING slot (>= member_count) is rejected (would smuggle a non-member key).
        let mut nonzero_pad = record_with_members(8);
        nonzero_pad.member_pk_gs[8] = pubkey_hash(500);
        assert!(matches!(
            nonzero_pad.validate(),
            Err(ChannelError::InvalidChannelRecord(_))
        ));

        // A duplicate ACTIVE hash is rejected (no shared-key / duplicate-member forgery).
        let mut dup = record_with_members(8);
        dup.member_pk_gs[5] = dup.member_pk_gs[2];
        assert!(matches!(
            dup.validate(),
            Err(ChannelError::InvalidChannelRecord(_))
        ));

        // bp_member_slot >= member_count is rejected.
        let mut bad_bp = record_with_members(8);
        bad_bp.bp_member_slot = 8;
        assert!(matches!(
            bad_bp.validate(),
            Err(ChannelError::InvalidChannelRecord(_))
        ));

        // bp_member_slot < member_count (e.g. last active slot) is accepted.
        let mut ok_bp = record_with_members(8);
        ok_bp.bp_member_slot = 7;
        ok_bp.validate().unwrap();
    }

    /// `close_member_set_commitment` binds `member_count`: with the SAME 16-slot hash array, the
    /// digest for count = 2 differs from count = 3. Proves member_count is genuinely part of the
    /// preimage (not ignored), so two active sets that share a hash prefix cannot collide.
    #[test]
    fn close_member_set_commitment_binds_member_count() {
        let hashes = pad_hashes(&[
            pubkey_hash(10),
            pubkey_hash(20),
            pubkey_hash(30),
            pubkey_hash(40),
        ]);
        let c2 = close_member_set_commitment(&hashes, 2);
        let c3 = close_member_set_commitment(&hashes, 3);
        assert_ne!(
            c2, c3,
            "member_count must be bound into close_member_set_commitment (count=2 vs count=3)"
        );
        // And across the full supported range every adjacent count is distinct on the same array.
        for count in 2u8..MAX_CHANNEL_MEMBERS as u8 {
            assert_ne!(
                close_member_set_commitment(&hashes, count),
                close_member_set_commitment(&hashes, count + 1),
                "count {count} vs {} must differ",
                count + 1
            );
        }
    }

    #[test]
    fn three_member_record_validates_signatures() {
        let record = sample_record();
        record.validate().unwrap();
        validate_all_member_signatures(&record, &sample_state().member_signatures).unwrap();

        // A signature whose pubkey hash does not match the channel member at its slot is rejected.
        let mut sigs = sample_state().member_signatures;
        sigs[1].pk_g = pubkey_hash(99);
        assert!(validate_all_member_signatures(&record, &sigs).is_err());

        // A signature with the wrong slot index is rejected.
        let mut sigs = sample_state().member_signatures;
        sigs[2].member_slot = 0;
        assert!(validate_all_member_signatures(&record, &sigs).is_err());

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

        // The member pubkey hashes are signature-binding (IMCR member segment).
        let mut other_member = record.clone();
        other_member.member_pk_gs[0] = pubkey_hash(77);
        assert_ne!(other_member.signing_digest(), record.signing_digest());
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
                bp_member_slot: 0,
                bp_pk_g: pubkey_hash(10),
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
            source_pk_g: pubkey_hash(10),
            seal: Bytes32::default(),
            tx_hash: Bytes32::from_u32_slice(&[3, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![],
            receiver_deltas: vec![ReceiverBalanceDelta {
                receiver_pk_g: pubkey_hash(21),
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
                tx.source_pk_g,
                tx.sender_delta_ct.digest(),
                tx.receiver_deltas[0].receiver_pk_g,
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
            pubkey_hash(10),
            pubkey_hash(11),
        );
        // Sensitive to amount ciphertext, nonce, parties, prev state.
        assert_ne!(
            digest,
            ChannelTx::signing_digest(
                state.channel_id,
                state.digest,
                &ciphertext(51),
                nonce,
                pubkey_hash(10),
                pubkey_hash(11),
            )
        );
        assert_ne!(
            digest,
            ChannelTx::signing_digest(
                state.channel_id,
                state.digest,
                &enc_amount,
                Bytes32::default(),
                pubkey_hash(10),
                pubkey_hash(11),
            )
        );
        assert_ne!(
            digest,
            ChannelTx::signing_digest(
                state.channel_id,
                state.digest,
                &enc_amount,
                nonce,
                pubkey_hash(11),
                pubkey_hash(10),
            )
        );
        assert_ne!(
            digest,
            ChannelTx::signing_digest(
                state.channel_id,
                Bytes32::default(),
                &enc_amount,
                nonce,
                pubkey_hash(10),
                pubkey_hash(11),
            )
        );
    }

    #[test]
    fn withdrawal_nullifier_depends_on_member_pubkey_hash() {
        let close_digest = Bytes32::from_u32_slice(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let a = WithdrawalClaim::derive_nullifier(close_digest, pubkey_hash(10));
        let b = WithdrawalClaim::derive_nullifier(close_digest, pubkey_hash(11));
        assert_ne!(a, b);
        // The close-intent digest (which embeds channel_id) is part of the nullifier preimage.
        let other_close = Bytes32::from_u32_slice(&[8, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(
            a,
            WithdrawalClaim::derive_nullifier(other_close, pubkey_hash(10))
        );
    }
}
