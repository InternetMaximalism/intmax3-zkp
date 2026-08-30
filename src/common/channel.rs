use plonky2_keccak::utils::solidity_keccak256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// SECURITY: re-export the canonical `ChannelId` so the channel layer and every downstream module
// share ONE channel identifier type with identical keccak digest semantics.
pub use crate::common::channel_id::ChannelId;
use crate::{
    common::{
        balance_state::{BalanceState, settled_tx_chain_push, tx_leaf_hash},
        salt::Salt,
    },
    constants::{
        INTER_CHANNEL_TX_DOMAIN_V5, L1_DEPOSIT_IMPORT_DOMAIN_V2, MAX_CHANNEL_MEMBERS,
        MAX_CHANNEL_TOKENS, MAX_SIG_CLUSTER, PAY_DOMAIN_V2, TOKEN_FUNDS_DIGEST_DOMAIN,
        WITHDRAWAL_CLAIM_DOMAIN_V2,
    },
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    regev::RegevCiphertext,
};

pub type SignatureBytes = Vec<u8>;

// pub(crate): the validity circuits mirror the IMCH signing preimage limb-for-limb
// (`circuits::validity::block_hash_chain::channel_state_message`) and must use the SAME domain
// limb — a second literal would be a silent-drift hazard.
pub(crate) const CHANNEL_STATE_DOMAIN: u32 = 0x494d4348; // "IMCH"
// "IMPA" (0x494d5041), the v1 in-channel pay domain, is DELETED: `ChannelTx::signing_digest` is
// fully superseded by the IMPA-v2 preimage under `PAY_DOMAIN_V2` ("IMP2", detail2 §N-3), and no
// in-circuit recompute referenced it. Its value stays pinned (as a retired literal) in the
// repo-wide domain non-collision test so no future tag can collide with historic v1 digests.
// pub(crate): the validity circuits recompute the IMSB signing digest in-circuit
// (`circuits::validity::block_hash_chain::small_block_message`) and must use the SAME domain limb.
pub(crate) const SMALL_BLOCK_DOMAIN: u32 = 0x494d5342; // "IMSB"
const SIGNED_SMALL_BLOCK_DOMAIN: u32 = 0x494d5353; // "IMSS"
// "IMIT" and "IMI2" are retired inter-channel schemas. `InterChannelTx::signing_digest` uses
// IMI4, which binds the base token, independent base-account nonce, and destination transfer
// salt. No circuit or Solidity code recomputes this variable-tail preimage; native consumers
// share this method.
const CLOSE_TX_DOMAIN: u32 = 0x494d434c; // "IMCL"
const CLOSE_INTENT_DOMAIN: u32 = 0x494d4349; // "IMCI"
const SPECIAL_CLOSE_DOMAIN: u32 = 0x494d5343; // "IMSC"
const CANCEL_CLOSE_DOMAIN: u32 = 0x494d434e; // "IMCN"
const POST_CLOSE_CLAIM_DOMAIN: u32 = 0x494d4350; // "IMCP"
/// "IMD2" — channel- and nonce-bound partial-withdrawal burn descriptor v2.
pub const BURN_DESCRIPTOR_DOMAIN: u32 = 0x494d4432;
// "IMCK" — domain separator for the post-close shared-native nullifier (HAZARD #8 fix). MUST match
// the in-circuit derivation in `circuits::channel::post_close_claim_circuit` and the L1 mirror.
const POST_CLOSE_NULLIFIER_DOMAIN: u32 = 0x494d434b; // "IMCK"
const WITHDRAWAL_CLAIM_DOMAIN: u32 = 0x494d4357; // "IMCW"
const CHANNEL_BALANCE_LEAF_DOMAIN: u32 = 0x494d5546; // "IMUF"
const CHANNEL_RECORD_DOMAIN: u32 = 0x494d4352; // "IMCR"
// "IMCM" — domain separator for the close-circuit member-set commitment. The full channel-close
// circuit exposes `member_set_commitment = keccak([IMCM, sphincs_pk_hash_0..2])` as a public input;
// L1 (`ChannelSettlementManager`) matches it against `keccak([IMCM, registered
// member_pk_gs])` so the 3 verified signing keys are bound to the channel's
// registered member set (no non-member-key substitution). See `close_member_set_commitment`.
const CLOSE_MEMBER_SET_DOMAIN: u32 = 0x494d434d; // "IMCM"
// "IMLD" (0x494d4c44), the v1 L1 deposit-import domain, is DELETED: `l1_deposit_import_digest`
// is fully superseded by the IMLD-v2 preimage under `L1_DEPOSIT_IMPORT_DOMAIN_V2` ("IML2",
// detail2 §N-5), and no in-circuit recompute referenced it. Its value stays pinned (as a retired
// literal) in the repo-wide domain non-collision test.
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
    L1DepositImport,
    /// detail2 §N-1 (TM-1): append-only cosigned registration of a new BASE `token_index` at
    /// local token slot `token_count`. Header-only state change (all 10 ciphertext positions
    /// exist from genesis as canonical zeros); N-of-N cosigned like any transition.
    TokenRegister,
}

impl ChannelTransitionKind {
    pub const fn required_state_backend(self) -> Option<ProofBackend> {
        match self {
            Self::InChannelTransfer
            | Self::InterChannelSend
            | Self::ReceiverBundleApply
            | Self::BalanceRefresh => Some(ProofBackend::Plonky3),
            // TokenRegister carries no balance-state ZKP: it mutates no ciphertext (header-only,
            // §N-1); its safety argument is the cosigners' native
            // `BalanceState::verify_token_register_transition` check + the N-of-N signatures.
            Self::InterChannelFundImport
            | Self::ChannelClose
            | Self::SpecialClose
            | Self::L1DepositImport
            | Self::TokenRegister => None,
        }
    }

    pub const fn required_transport_backend(self) -> Option<ProofBackend> {
        match self {
            Self::InterChannelSend
            | Self::InterChannelFundImport
            | Self::ChannelClose
            | Self::SpecialClose => Some(ProofBackend::Plonky2),
            Self::InChannelTransfer
            | Self::ReceiverBundleApply
            | Self::BalanceRefresh
            | Self::L1DepositImport
            | Self::TokenRegister => None,
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
    /// Number of DELEGATE participants (send/receive/withdraw, NOT co-signing). Delegates occupy
    /// the contiguous slot region `member_count..member_count+delegate_count`; slots
    /// `member_count+delegate_count..MAX_CHANNEL_MEMBERS` are padding. Invariant: `member_count +
    /// delegate_count <= MAX_CHANNEL_MEMBERS`.
    ///
    /// SECURITY (delegate account, Phase 1): `delegate_count` is committed into the IMCR
    /// `signing_digest` IMMEDIATELY AFTER `member_count`, so the member/delegate/padding split is
    /// fixed under the members' channel-record signature. Delegate slots carry a real
    /// `MemberLeaf{pk_g, pk_b, regev_pk}` identity (so the delegate can send and withdraw); they
    /// are part of `member_pubkeys_root` exactly like members. The only difference is that
    /// delegates do NOT appear in the N-of-N co-sign set (those loops stay `0..member_count`;
    /// later phases).
    ///
    /// WIDTH: `u16` — delegates occupy BALANCE-SLOT space (up to `MAX_CHANNEL_MEMBERS = 1024 -
    /// member_count`), which does not fit in u8 (the 2026-07-18 storm capped joins at 256). The
    /// IMCR digest encodes this as a u32 limb, so the widening is digest-transparent.
    pub delegate_count: u16,
    /// Ordered member + delegate identities = SPHINCS+ pubkey hashes, slot order
    /// 0..MAX_CHANNEL_MEMBERS. Active slots (`< member_count+delegate_count`) are nonzero and
    /// pairwise-distinct; padding slots are `Bytes32::default()`.
    // MAX_CHANNEL_MEMBERS > 32: std serde only derives arrays up to 32, so use serde-big-array.
    #[serde(with = "serde_big_array::BigArray")]
    pub member_pk_gs: [Bytes32; MAX_CHANNEL_MEMBERS],
    /// Bytes32 form of the wallet's LIVE-membership tree root
    /// (`wallet_core::member_pubkeys_root`, height `WALLET_MEMBER_TREE_HEIGHT`, cosigners +
    /// delegates — evolves with delegate joins).
    ///
    /// SECURITY (Option B divergence — INTENTIONAL): this is NOT the on-chain REGISTERED root.
    /// `ChannelLeaf.member_pubkeys_root` (validity side, height `MEMBER_TREE_HEIGHT`) covers only
    /// the genesis COSIGNERS and never changes; the two are different trees and are never
    /// compared. This root anchors the off-chain P4-1/A11 member set that peers verify.
    pub member_pubkeys_root: Bytes32,
    /// detail2 §Q: strictly monotone member-set version — genesis registration = 0, +1 per
    /// applied `MemberSetUpdate` (AddCosigner / RotateKey). Delegate joins do NOT bump it (they
    /// change only the wallet-tree membership, not the registered co-signer set). serde-default
    /// so pre-§Q records parse as version 0.
    #[serde(default)]
    pub set_version: u64,
    /// The slot whose member acts as block-proposer (replaces `bp_key_id`). Must be `<
    /// member_count`.
    ///
    /// WIDTH: u8 is sufficient — this is COSIGNER-slot space (`< member_count <= MAX_SIG_CLUSTER =
    /// 8`), never a delegate/balance slot (audited 2026-07-18, u16 slot widening).
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
        // SECURITY (abstract2-1 §2.6): BURN_CHANNEL_ID is the reserved partial-withdrawal L1-exit
        // destination — no real channel may occupy it (mirrors the on-chain `registerChannel`
        // guard).
        if self.channel_id.channel_id() == crate::constants::BURN_CHANNEL_ID {
            return Err(ChannelError::InvalidChannelRecord(
                "channel_id equals reserved BURN_CHANNEL_ID (partial-withdrawal burn destination)"
                    .to_string(),
            ));
        }
        // member_count = COSIGNERS (N-of-N close signers), capped at MAX_SIG_CLUSTER. The total
        // active participants (members + delegates) are separately bounded by MAX_CHANNEL_MEMBERS
        // below.
        let count = self.member_count as usize;
        if count < 2 || count > MAX_SIG_CLUSTER {
            return Err(ChannelError::InvalidChannelRecord(format!(
                "member_count {count} out of range (must be 2..={MAX_SIG_CLUSTER})"
            )));
        }
        if (self.bp_member_slot as usize) >= count {
            return Err(ChannelError::InvalidChannelRecord(format!(
                "bp_member_slot {} out of range (must be < member_count {count})",
                self.bp_member_slot
            )));
        }
        // Delegate account regions: members `0..member_count`, delegates
        // `member_count..member_count+delegate_count`, padding `member_count+delegate_count..MAX`.
        // Active = members + delegates. `delegate_count` may be 0; `member_count + delegate_count`
        // must not exceed MAX (no overflow / over-allocation).
        let delegate_count = self.delegate_count as usize;
        let active = count
            .checked_add(delegate_count)
            .filter(|&a| a <= MAX_CHANNEL_MEMBERS)
            .ok_or_else(|| {
                ChannelError::InvalidChannelRecord(format!(
                    "member_count {count} + delegate_count {delegate_count} exceeds \
                     MAX_CHANNEL_MEMBERS = {MAX_CHANNEL_MEMBERS}"
                ))
            })?;
        // One SPHINCS+ key per ACTIVE participant: the ACTIVE pubkey hashes (members + delegates,
        // slots `0..member_count+delegate_count`) must be nonzero and pairwise distinct (no
        // shared-key / duplicate-participant forgery, across members AND delegates); PADDING slots
        // (`>= member_count+delegate_count`) must be Bytes32::default().
        for (i, hash) in self.member_pk_gs.iter().enumerate() {
            if i < active {
                if *hash == Bytes32::default() {
                    return Err(ChannelError::InvalidChannelRecord(format!(
                        "member_pk_gs[{i}] (active) must be nonzero"
                    )));
                }
                for (j, other) in self.member_pk_gs.iter().enumerate().skip(i + 1) {
                    if j < active && hash == other {
                        return Err(ChannelError::InvalidChannelRecord(
                            "active member_pk_gs must be pairwise distinct".to_string(),
                        ));
                    }
                }
            } else if *hash != Bytes32::default() {
                return Err(ChannelError::InvalidChannelRecord(format!(
                    "member_pk_gs[{i}] is a padding slot (>= member_count+delegate_count {active}) \
                     and must be Bytes32::default()"
                )));
            }
        }
        Ok(())
    }

    /// IMCR signing digest (pad-to-MAX D6). Member segment = `bp_member_slot`(1) +
    /// `status`(1) + `member_count`(1) + ALL `MAX_CHANNEL_MEMBERS` pubkey hashes (1024*8 = 8192
    /// limbs, padding slots contribute their `Bytes32::default()` zero limbs) +
    /// `member_pubkeys_root`(8). `regev_pk_root` stays at the END of the preimage (detail2 §H-1).
    ///
    /// PREIMAGE (exact): `[IMCR, channel_id(1), bp_member_slot(1), split_u64(close_freeze_nonce),
    /// status(1), member_count(1), delegate_count(1), member_hashes(1024*8), member_pubkeys_root(8),
    /// special_close_penalty(8), regev_pk_root(8)]`. The `member_count` limb replaces the legacy
    /// `CHANNEL_MEMBERS` constant limb in the same position; `delegate_count` is a single u32 limb
    /// IMMEDIATELY AFTER `member_count` (delegate account). Hashing all 1024 hashes (not just the
    /// active ones) plus both counts fixes the member/delegate/padding split under the member
    /// signatures.
    ///
    /// NOTE: this IMCR digest is NATIVE-ONLY (it has no in-circuit or Solidity recompute twin), so
    /// `delegate_count` is threaded here only.
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CHANNEL_RECORD_DOMAIN],
                self.channel_id.to_u32_vec(),
                vec![self.bp_member_slot as u32],
                split_u64(self.close_freeze_nonce),
                // §Q: the member-set version is part of the record identity (native-only digest —
                // this preimage has no circuit/Solidity twin, see the note above this fn).
                split_u64(self.set_version),
                vec![
                    self.status as u32,
                    self.member_count as u32,
                    self.delegate_count as u32,
                ],
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
    /// `circuits::validity::block_hash_chain::small_block_message` limb-for-limb.
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
    ///
    /// WIDTH: u8 is sufficient — state co-signing is COSIGNER-only (`member_count <=
    /// MAX_SIG_CLUSTER = 8`); delegates never produce a `MemberSignature` (audited 2026-07-18).
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
    /// Per-token channel funds (detail2 §N-6), ALIGNED TO the channel's `token_registry`:
    /// `amounts[t]` is the fund denominated in the base token `token_registry[t]`. Positions
    /// `t >= token_count` are zero. ALWAYS full `MAX_CHANNEL_TOKENS` width in memory and in
    /// every digest (TM-11).
    ///
    /// SECURITY (P2/P3): funds are NEVER summed across positions — each `amounts[t]` conserves
    /// and settles independently against its own base-token escrow.
    pub amounts: [U256; MAX_CHANNEL_TOKENS],
    pub intmax_state_root: Bytes32,
}

impl ChannelFund {
    /// Single-token convenience: `amount` at token slot 0 (the genesis token), zero elsewhere —
    /// the exact v1-state embedding of detail2 §N (owner decision 5).
    pub fn single_token_amounts(amount: U256) -> [U256; MAX_CHANNEL_TOKENS] {
        let mut amounts = [U256::zero(); MAX_CHANNEL_TOKENS];
        amounts[0] = amount;
        amounts
    }
}

/// `token_funds_digest` (detail2 §N-6, TM-11): the close-side commitment to the per-token fund
/// vector and its registry alignment,
///
/// `keccak([TOKEN_FUNDS_DIGEST_DOMAIN, token_registry (10 canonical u32 limbs, zero-padded),
///          token_count (1 limb), amounts (10 x U256 = 80 limbs, zero-padded)])`
///
/// — a FIXED 92-word preimage. ALWAYS full width regardless of `token_count`: omitting unused
/// entries would make the preimage variable-length and alias distinct `(registry, amounts)`
/// pairs (TM-11). Pinned byte-for-byte by `token_funds_digest_golden_vector`; the Solidity
/// recompute (`ChannelSettlementVerifier`, Phase 3) must match it exactly.
pub fn token_funds_digest(
    registry: &[u32; MAX_CHANNEL_TOKENS],
    token_count: u8,
    amounts: &[U256; MAX_CHANNEL_TOKENS],
) -> Bytes32 {
    let mut words = Vec::with_capacity(2 + MAX_CHANNEL_TOKENS * 9);
    words.push(TOKEN_FUNDS_DIGEST_DOMAIN);
    words.extend_from_slice(registry);
    words.push(token_count as u32);
    for amount in amounts {
        words.extend(amount.to_u32_vec());
    }
    hash_words(&words)
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
    /// BALANCE-SLOT index (`0..member_count+delegate_count`, up to `MAX_CHANNEL_MEMBERS = 1024`) —
    /// delegates withdraw at close too, so this is NOT bounded by `MAX_SIG_CLUSTER`; u16.
    pub member_slot: u16,
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
    ///
    /// SECURITY (multitoken, TM-11): the former single 8-limb `channel_fund.amount` segment is
    /// widened IN PLACE to the flat, ALWAYS-full-width 80-limb `amounts[0..10]` vector (10 x
    /// U256, zero-padded). The preimage stays fixed-width injective; the registry alignment of
    /// the vector is bound through `balance_state.h1()` (which commits `token_registry` +
    /// `token_count`, TM-9) inside this same preimage. detail2 §N/§G-2 fix the new-domain set to
    /// the six changed leaf/nullifier/pay/import/header/TFD preimages and do NOT re-version
    /// IMCH; keccak collision resistance over the differing fixed widths rules out v1<->v2
    /// preimage aliasing, and the v3 reset retires all v1-signed digests.
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CHANNEL_STATE_DOMAIN],
                self.channel_id.to_u32_vec(),
                split_u64(self.epoch),
                split_u64(self.small_block_number),
                split_u64(self.close_freeze_nonce),
                self.channel_fund.channel_id.to_u32_vec(),
                self.channel_fund
                    .amounts
                    .iter()
                    .flat_map(U256::to_u32_vec)
                    .collect(),
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
    /// LOCAL token slot this transfer moves (detail2 §N-3): index into the channel's
    /// `token_registry`, `< token_count`. Travels in cleartext (accepted privacy deviation
    /// TM-12/§N-8).
    ///
    /// SECURITY (TM-2, P1 binding triple): this field is bound into the IMPA-v2 signing digest
    /// as its OWN canonical limb; the Phase 2 transition verifier must force it equal to the
    /// leaf one-hot select and to the ONLY mutated ciphertext position on both leaves.
    pub token_slot: u8,
    /// Transfer amount encrypted to the recipient's `RegevPk`.
    pub enc_amount: RegevCiphertext,
    /// One-time random value, making otherwise-identical transfers distinguishable.
    pub nonce: Bytes32,
    /// Mandatory E-1 channelTxZKP — co-signers MUST refuse to sign without it.
    pub channel_tx_zkp: ChannelProofEnvelope,
    pub sender_pk_g: Bytes32,
    /// P3 sender authorization: the Poseidon2-BabyBear hash-signature STARK proof bytes over the
    /// IMPA `signing_digest` (replaces the legacy SPHINCS+ `sender_signature`). The proof's public
    /// values are `[pk_b(8) ‖ m(16)]`; the off-chain verifier binds `m ==
    /// decompose(signing_digest)` and `pk_b == sender_pk_b`, and confirms `(sender_pk_g,
    /// sender_pk_b, sender_regev_pk)` is one registered `MemberLeaf` (A11). The IMPA
    /// `signing_digest` preimage is UNCHANGED.
    pub sender_hash_sig: Vec<u8>,
    /// The sender's BabyBear hash-sig public key `pk_b` (canonical `Bytes32` digest), bound to the
    /// proof's `pk_b` public value and to the sender's registered `MemberLeaf` (A11).
    pub sender_pk_b: Bytes32,
}

impl ChannelTx {
    /// IMPA-v2 signing digest (detail2 §C-5 + §N-3). EXACT LIMB LAYOUT (43 u32 words):
    /// `[PAY_DOMAIN_V2 (1), channel_id (1), prev_state_digest (8), enc_amount.digest() (8),
    /// nonce (8), token_slot (1), sender_pubkey_hash (8), recipient_pubkey_hash (8)]`.
    /// Pinned byte-for-byte by `impa_v2_digest_layout_golden` below.
    ///
    /// SECURITY (TM-2/TM-15): `token_slot` occupies its OWN canonical u32 limb between `nonce`
    /// and `sender_pk_g` — NEVER bit-packed into an existing word (e.g. NOT
    /// `(token_slot << 16) | x`), which would alias distinct pairs. Under the new "IMP2" domain
    /// no v1 IMPA digest can be replayed as a v2 one.
    ///
    /// SECURITY: the ZKP envelope is deliberately NOT part of this digest — the sender authorizes
    /// the transfer (prev state, hidden amount ciphertext, token slot, parties); the proof object
    /// is transport material that each co-signer verifies independently against the same
    /// statement.
    #[allow(clippy::too_many_arguments)]
    pub fn signing_digest(
        channel_id: ChannelId,
        prev_state_digest: Bytes32,
        enc_amount: &RegevCiphertext,
        nonce: Bytes32,
        token_slot: u8,
        sender_pk_g: Bytes32,
        recipient_pk_g: Bytes32,
    ) -> Bytes32 {
        hash_words(
            &[
                vec![PAY_DOMAIN_V2],
                channel_id.to_u32_vec(),
                prev_state_digest.to_u32_vec(),
                enc_amount.digest().to_u32_vec(),
                nonce.to_u32_vec(),
                vec![token_slot as u32],
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
    /// BASE-layer `token_index` this transfer moves (detail2 §N-4, TM-6) — NEVER a channel-local
    /// slot: source and destination registries map it to (possibly different) local slots, each
    /// side resolving against its OWN H1-committed registry (`registry[t] == token_index && t <
    /// token_count`, unregistered ⇒ reject fail-closed).
    ///
    /// SECURITY (TM-6/TM-15): bound into the IMI3 signing digest as its OWN canonical u32 limb
    /// (below) AND into the E-2 channelUpdateZKP transcript as its own public value under the
    /// "IMU2" domain — so neither the descriptor nor the proof can be replayed for a different
    /// token.
    ///
    /// SECURITY (IMCK structural re-check, Phase 1 carried obligation): ONE descriptor carries
    /// exactly ONE `token_index` (this scalar field) and exactly one receiver delta (`detail2
    /// §A-2`), so a C2C tx moves exactly one token — the type makes multi-token bundles
    /// structurally inexpressible. See `derive_shared_native_nullifier` for why the unversioned
    /// IMCK nullifier stays sound under this invariant.
    pub token_index: u32,
    /// The source base account's next send nonce.  It is intentionally independent of
    /// `signed_small_block.message.small_block_number`: receiving/importing channel transitions
    /// advance the channel counter without consuming a base sent-tx slot.  H2 commits the TxV2
    /// carrying this nonce, and IMI3 also binds this scalar directly for canonical reconstruction.
    pub base_nonce: u32,
    /// Salt for the normal base-layer UID recipient
    /// `UID(destination_channel_id, destination_base_transfer_salt)`. It is signed under IMI4
    /// and copied into the transfer descriptor so the destination can construct the exact
    /// `ReceiveTransfer` witness. Burns use an ADDRESS_TAG recipient and MUST carry zero here.
    pub destination_base_transfer_salt: Salt,
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
    /// detail2 §P-2: the SENDER's A11 Poseidon2-BabyBear hash-sig STARK proof over this tx's IMI5
    /// `signing_digest` — the per-leaf sender authorization that lets every member of every
    /// channel participating in an aggregated round check "no unsigned tx is in the tree I am
    /// about to sign" with only the leaf in hand. Excluded from the digest (it signs the digest),
    /// exactly like `ChannelTx::sender_hash_sig`; the (pk_g, pk_b) pairing is bound by the
    /// verifier against the source channel's authenticated member set, never taken from the wire.
    pub sender_hash_sig: Vec<u8>,
    /// The sender's BabyBear hash-sig public key `pk_b`, bound to the proof's public values and to
    /// the registered member leaf that owns `source_pk_g` (detail2 §P-2 / A11).
    pub sender_pk_b: Bytes32,
}

impl InterChannelTx {
    /// IMI5 signing digest (detail2 §P-2 — v4 layout under a fresh domain; this digest is the
    /// message of `sender_hash_sig`, so the sig fields are NOT part of the preimage).
    /// `token_index`, `base_nonce`, and all four 64-bit destination salt
    /// limbs occupy canonical words (never bit-packed); the fresh domain keeps schema separation
    /// independent of total-length alignment.
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![INTER_CHANNEL_TX_DOMAIN_V5],
                // A11 is created before the N-of-N round finishes. Bind the immutable block
                // message, not `SignedSmallBlock::signing_digest()`: the latter deliberately
                // includes the member signature/proof blobs that are attached later, which made
                // the sender's otherwise-valid proof fail on the final wire object. The message
                // already commits channel/sequence/H2/H1/era; those are the values the sender is
                // authorizing, while the later blobs authenticate that same message separately.
                self.signed_small_block.message.signing_digest().to_u32_vec(),
                self.sender_delta_ct.digest().to_u32_vec(),
                self.source_channel_id.to_u32_vec(),
                self.destination_channel_id.to_u32_vec(),
                vec![self.token_index],
                vec![self.base_nonce],
                self.destination_base_transfer_salt
                    .to_u64_vec()
                    .into_iter()
                    .flat_map(split_u64)
                    .collect::<Vec<_>>(),
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

    /// The CANONICAL token-bearing `tx_hash` recompute from this descriptor's OWN fields
    /// (detail2 §C-6 + §N-6, TM-16): `token_index` is single-sourced from `self.token_index` —
    /// the SAME field the registry resolutions and the E-2 IMU2 statement read (TM-16
    /// obligation 2, no second wire copy). Every absorb-time gate requires
    /// `self.tx_hash == self.compute_tx_hash()?` BEFORE chaining/accumulating it, so the
    /// accumulator leaf a post-close claim later opens commits the SAME base token the
    /// destination actually resolved and credited.
    pub fn compute_tx_hash(&self) -> Result<Bytes32, ChannelError> {
        Ok(inter_channel_tx_hash(
            self.source_channel_id,
            self.destination_channel_id,
            self.token_index,
            self.signed_small_block.message.tx_tree_root,
            self.tx_leaf_hash()?,
        ))
    }

    /// The token-FREE replay/consumed-ledger identity of this tx (TM-16 obligation 1,
    /// MATERIAL): `keccak-fold(ids_without_token, fold(tx_tree_root, tx_leaf))` — byte-identical
    /// to the pre-TM-16 v1 `tx_hash` formula. The A-side spent ledger and the B-side applied
    /// ledger MUST key on THIS value, never on the token-bearing `tx_hash`: a malicious sender
    /// can prove E-2 twice (token X and token Y) over the SAME deltas and present two IMI3-signed
    /// descriptors whose token-bearing hashes differ, so a `tx_hash`-keyed consumed set would
    /// double-credit one debit across two tokens. The identity strips the token limb, making the
    /// two descriptors collide in the ledger (second one refused fail-closed). Dest-binding
    /// (HIGH-1) is preserved: both channel ids stay in the fold.
    pub fn replay_identity(&self) -> Result<Bytes32, ChannelError> {
        Ok(inter_channel_tx_identity(
            self.source_channel_id,
            self.destination_channel_id,
            self.signed_small_block.message.tx_tree_root,
            self.tx_leaf_hash()?,
        ))
    }
}

/// Amount-committing descriptor stored in a burn Transfer's `aux_data`:
///
/// `keccak256(abi.encodePacked(bytes4("IMD2"), sourceChannelId, baseNonce, txLeaf, recipient,
/// tokenIndex, amount))`.
///
/// `recipient` is the 32-byte ADDRESS_TAG value as it appears in the base Transfer; `amount` is
/// the full uint256. `source_channel_id` and `base_nonce` are canonical single-u32 limbs, so two
/// otherwise identical burns from different channels or base-account slots cannot share an
/// authorization identity. Normal inter-channel sends do not use this descriptor and keep
/// aux_data zero.
pub fn burn_descriptor(
    source_channel_id: ChannelId,
    base_nonce: u32,
    tx_leaf: Bytes32,
    recipient: Bytes32,
    token_index: u32,
    amount: U256,
) -> Bytes32 {
    let words: Vec<u32> = [BURN_DESCRIPTOR_DOMAIN]
        .into_iter()
        .chain(source_channel_id.to_u32_vec())
        .chain([base_nonce])
        .chain(tx_leaf.to_u32_vec())
        .chain(recipient.to_u32_vec())
        .chain([token_index])
        .chain(amount.to_u32_vec())
        .collect();
    Bytes32::from_u32_slice(&solidity_keccak256(&words)).expect("keccak output must be bytes32")
}

/// `tx_hash` identifier for an inter-channel tx (the L1-settled identifier referenced by the fund
/// import chain, the settled-tx-accumulator leaf, and the `PostCloseIncomingClaim` anchor).
/// INTENTIONALLY SIMPLE: a domain-free keccak fold over
/// `(source_channel_id, destination_channel_id, token_index, tx_tree_root, tx_leaf)`.
///
/// SECURITY (TM-16, multi-token §N-6): the ids word is
/// `[0, 0, 0, 0, 0, token_index, destination_channel_id, source_channel_id]` — the descriptor's
/// BASE `token_index` (NEVER a channel-local slot) occupies its OWN canonical u32 limb (limb 5,
/// TM-15: no bit-packing). This is what makes the credited token PROVABLE post-close: the
/// accumulator leaf (this hash) is the only artifact of an absorbed incoming tx that the closed
/// channel's signed final state anchors, and before TM-16 none of its preimages carried the
/// token. The post-close claim circuit recomputes this exact fold and exposes the ids token limb
/// as the `token_index` public input. v1 leaves had ids limb 5 == 0, which reads as base token 0
/// (ETH) — backward-consistent, and moot under the v3 reset. The IMTC push domain is retained:
/// the preimage SHAPE is unchanged (two Bytes32 words per fold); a previously constant-zero limb
/// of the ids word gained meaning (documented here and in detail2 §G-2/§N-6).
///
/// SECURITY (HIGH-1, dest binding): the destination channel id is folded in so the identifier is
/// DEST-BOUND — the same (source, tx_tree_root, tx_leaf) tuple aimed at a different destination
/// hashes differently. The post-close claim additionally pins ids limb 6 to the CLOSED channel's
/// id, which excludes the source channel's own (outgoing) accumulator entries.
pub fn inter_channel_tx_hash(
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId,
    token_index: u32,
    tx_tree_root: Bytes32,
    tx_leaf: Bytes32,
) -> Bytes32 {
    let mixed = settled_tx_chain_push(tx_tree_root, tx_leaf);
    let mut w = [0u32; 8];
    w[7] = source_channel_id.as_u64() as u32;
    w[6] = destination_channel_id.as_u64() as u32;
    // TM-16: the base token_index in its own canonical limb (see the doc comment above).
    w[5] = token_index;
    let ids = Bytes32::from_u32_slice(&w).expect("8 u32 limbs are a valid Bytes32");
    settled_tx_chain_push(ids, mixed)
}

/// Token-FREE inter-channel tx identity for the replay/consumed ledgers (TM-16 obligation 1) —
/// the same fold as [`inter_channel_tx_hash`] with the token limb at ZERO, i.e. byte-identical
/// to the pre-TM-16 v1 `tx_hash`. See [`InterChannelTx::replay_identity`] for why ledgers MUST
/// key on this and never on the token-bearing hash.
pub fn inter_channel_tx_identity(
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId,
    tx_tree_root: Bytes32,
    tx_leaf: Bytes32,
) -> Bytes32 {
    inter_channel_tx_hash(
        source_channel_id,
        destination_channel_id,
        0,
        tx_tree_root,
        tx_leaf,
    )
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
    /// SECURITY (M-9, UNSIGNED): supplied by the closing coordinator at close time. It is NOT a
    /// field of `ChannelState`, so it is absent from the member-signed IMCH preimage, and L1
    /// only stores/emits it (`finalizedBurnTxHash` is written by `finalizeClose` and never
    /// read). See the `signing_digest` SECURITY block below.
    pub burn_tx_hash: Bytes32,
    /// SECURITY (M-9, UNSIGNED, transitively): IMCL is a function of the signed state EXCEPT for
    /// `burn_tx_hash`, so this digest inherits that field's freedom. Removing `burn_tx_hash` from
    /// the IMCI preimage alone would therefore NOT make IMCI a function of the signed state.
    pub close_withdrawal_digest: Bytes32,
    /// SECURITY (M-9, UNSIGNED): likewise coordinator-chosen and absent from IMCH. There is no
    /// on-chain block-number -> medium-block-state-root lookup to pin it against either
    /// (`IntmaxRollup` exposes only `isFinalizedStateRoot(bytes32)`).
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
        // SECURITY (multitoken §N-6, TM-3/TM-11 — per-token close semantics): the L2 close BURN
        // leg denominates ONLY the GENESIS token position (local slot 0): `burn_amount` must
        // equal `amounts[0]` exactly, and the close circuit connects `amounts[0]` to the
        // `channel_fund_amount` PI (Phase 2a). Non-genesis token funds (`amounts[1..]`) are NOT
        // burned — they settle via per-(member, token) withdrawal claims against the Manager's
        // per-base-token accounting: the FULL `amounts[0..10]` vector rides in this intent
        // (IMCI, 80 limbs) and is bound — with the registry and token_count — to the
        // member-signed close PI `token_funds_digest` by the verifier's on-chain recompute;
        // `finalizeClose` accrues `finalizedChannelFundAmount[registry[t]] += amounts[t]` per
        // token and `pullChannelTokenFunds(t)` moves the ERC-20 escrow (Phase 3, landed). The
        // former Phase-1/3 fail-closed refusal of nonzero non-genesis funds is LIFTED here
        // (Phase 4) together with the per-token claim builders, per the Phase 3 review's
        // condition ("lift the CloseIntent non-genesis-funds gate only WITH the per-token claim
        // builders").
        if final_channel_state.channel_fund.amounts[0] != close_withdrawal.burn_amount {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final channel fund amounts[0] {:?} != close withdrawal burn_amount {:?}",
                final_channel_state.channel_fund.amounts[0], close_withdrawal.burn_amount
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
    ///
    /// SECURITY (multitoken, TM-11): the former single 8-limb `channel_fund_snapshot.amount`
    /// segment is widened IN PLACE to the flat, ALWAYS-full-width 80-limb `amounts[0..10]`
    /// vector — same rationale as `ChannelState::signing_digest` (fixed-width injective; the
    /// registry alignment is bound via `final_balance_state_h1` in this same preimage; §N/§G-2
    /// do not re-version IMCI). The Solidity mirror (`computeCloseIntentDigest`) is updated in
    /// Phase 3; until then the shared-vector cross-check is `#[ignore]`d (see
    /// `close_intent_digest_matches_solidity_shared_vector`).
    ///
    /// SECURITY (M-9 — this digest is NOT a member-authorized commitment; audit28-08-2026 §M-9,
    /// `doc/tasks/close-detached-signing-design.md` T-5 / §8.3). The ONLY message any member ever
    /// signs on the close path is `ChannelState::signing_digest()` (IMCH). Three fields of this
    /// preimage are outside it and are chosen freely by whoever builds the close:
    ///   * `close_nonce`                    (close PI limbs 1..2)
    ///   * `burn_tx_hash`                   (close PI limbs 41..48, and, transitively, the
    ///                                       `close_withdrawal_digest` slot)
    ///   * `snapshot_medium_block_number`   (close PI limbs 65..66)
    /// The close circuit recomputes this keccak over them but constrains NONE of them against the
    /// signed state (`close_circuit.rs` block (d)), and `ChannelSettlementManager` only stores and
    /// emits them. So one N-of-N signature set over a single `ChannelState` yields UNBOUNDEDLY
    /// MANY distinct `close_intent_digest` values.
    ///
    /// CALLER OBLIGATION: do NOT treat `close_intent_digest` as a stable, N-of-N-authorized
    /// identity for a close. It is safe today ONLY because `_isNewer` is strict on
    /// `(finalEpoch, finalStateVersion)` and `closeFreezeNonce` — which IS inside IMCH — fences
    /// the era; both of those are properties of the SIGNED state, not of this digest. Any new
    /// digest-keyed replay/dedup or cancel-addressing logic must re-derive its fence from the
    /// signed state (`final_channel_state_digest` / `close_freeze_nonce`) rather than assume a
    /// fresh digest implies a fresh signature. Pinned by
    /// `m9_one_signature_set_mints_many_distinct_close_intent_digests`.
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
                self.channel_fund_snapshot
                    .amounts
                    .iter()
                    .flat_map(U256::to_u32_vec)
                    .collect(),
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
    /// LOCAL token slot this claim withdraws (detail2 §N-6): withdrawal claims are per
    /// (member slot, token slot). Bound into the claim's nullifier as its own limb.
    pub token_slot: u8,
    pub l1_recipient: Address,
    /// The member's final balance ciphertext at `token_slot` (that position of their slot row in
    /// the final `BalanceState`); the `claim_proof` (E-3 withdrawClaimZKP) proves it decrypts to
    /// the public withdrawal amount.
    pub user_amount_ct: RegevCiphertext,
    pub withdrawal_nullifier: Bytes32,
    pub claim_proof: Vec<u8>,
}

impl WithdrawalClaim {
    /// Nullifier v2 `[IMW2, close_intent_digest(8), slot_regev_pk_digest(8), token_slot(1)]`
    /// (18 limbs; detail2 §N-6, TM-5).
    ///
    /// SECURITY (B-2 blocker fix, tasks/reg-chain-1024-threat-model.md): the nullifier is keyed on
    /// the slot's LEAF-BOUND Regev pk digest (`Bytes32::from(RegevPk::poseidon_digest())`), NOT the
    /// slot-free `member_pk_g`. Under Option B a delegate has no L1 registration, so once the
    /// Manager admits delegate claims (B-2) `member_pk_g` is no longer tied to a registered
    /// cosigner; if it still keyed the nullifier, a slot owner could grind `member_pk_g` to
    /// mint unlimited distinct nullifiers and multi-withdraw the same slot up to the fund cap.
    /// `regev_pk_digest` is a field of the cosigner-signed slot leaf opened at `member_index`
    /// in the withdrawal-claim proof, so each signed slot yields EXACTLY ONE nullifier PER
    /// TOKEN SLOT and only the slot owner (who needs the Regev secret to decrypt) can produce
    /// it. Duplicate Regev keys across slots collapse to one withdrawal (self-loss, symmetric
    /// to the accepted duplicate-pk_g risk).
    ///
    /// SECURITY (TM-5, multitoken): `token_slot` is bound as its OWN canonical limb so each
    /// (slot, token) pair yields exactly one nullifier — WITHOUT it, one member's 10 per-token
    /// claims would collapse to a single nullifier (completeness break: only one token claimable
    /// per member); keyed on the grindable `member_pk_g` instead of the leaf-bound Regev pk
    /// digest, the B-2 multi-withdraw grinding attack would return x10. Both regression
    /// directions are covered by `withdrawal_nullifier_depends_on_slot_regev_digest`. The v2
    /// domain ("IMW2") makes v1 nullifiers unreplayable (TM-15).
    ///
    /// `close_intent_digest` embeds `channel_id`, so the (channel, close, slot-identity, token)
    /// tuple is unique even though a bare digest is channel-independent (plan §7
    /// collision-freedom).
    pub fn derive_nullifier(
        close_intent_digest: Bytes32,
        slot_regev_pk_digest: Bytes32,
        token_slot: u8,
    ) -> Bytes32 {
        hash_words(
            &[
                vec![WITHDRAWAL_CLAIM_DOMAIN_V2],
                close_intent_digest.to_u32_vec(),
                slot_regev_pk_digest.to_u32_vec(),
                vec![token_slot as u32],
            ]
            .concat(),
        )
    }

    /// IMCW claim signing digest. Multi-token (Phase 2, closing security-review MINOR 7 from
    /// Phase 1): `token_slot` occupies its OWN canonical u32 limb IMMEDIATELY AFTER
    /// `member_pk_g` (mirroring the struct field order), in addition to its transitive binding
    /// through the `withdrawal_nullifier` limbs — TM-15 own-limb discipline, no bit-packing.
    ///
    /// SECURITY (domain handling): the "IMCW" domain is RETAINED for this digest per detail2
    /// §G-2 ("IMCW remains for the claim signing_digest"; only the NULLIFIER re-versioned to
    /// "IMW2"). The in-place widening is sound by the same argument the Phase 1 review ACCEPTED
    /// for IMCH/IMCI: exactly one message type hashes under this domain, keccak collision
    /// resistance covers the differing fixed prefix widths, and the v3 reset retires every
    /// v1-signed claim digest. PRECISION (Phase 2a review note): because this preimage ends in a
    /// variable-length, length-prefixed `claim_proof` tail, a v1 and a v2 preimage CAN have
    /// equal total length (the v2 limb consuming one tail word under a realigned parse); for
    /// that equal-total-length realignment case the non-aliasing argument rests on the v3 reset
    /// ALONE, not on keccak collision resistance.
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![WITHDRAWAL_CLAIM_DOMAIN],
                self.close_intent_digest.to_u32_vec(),
                self.member_pk_g.to_u32_vec(),
                vec![self.token_slot as u32],
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
    /// Shared-native nullifier `keccak([IMCK, close_intent_digest(8), incoming_tx_hash(8),
    /// receiver_pk_g(8)])` (HAZARD #8 fix). Deriving it deterministically (rather than trusting an
    /// attacker-chosen claim field) closes the double-claim / cross-channel-replay surface.
    ///
    /// SECURITY: MUST stay byte-identical to the in-circuit derivation in
    /// `circuits::channel::post_close_claim_circuit` and to the L1 `usedSharedNativeNullifiers`
    /// key. `close_intent_digest` embeds `channel_id` and `incoming_tx_hash` is the unique
    /// source-tx hash, so the (close, tx, receiver) tuple is collision-free across channels.
    ///
    /// SECURITY (multitoken, TM-5 scope note): unlike `WithdrawalClaim::derive_nullifier`, this
    /// nullifier does NOT gain a `token_slot` limb in the §N change — it is keyed per late
    /// inbound TX (`incoming_tx_hash`), and one tx moves exactly one token (§N-3), so per-token
    /// separation is already implied by tx uniqueness: there is no per-(slot, token) collapse to
    /// fix and no completeness break.
    ///
    /// SECURITY (IMCK structural re-check, multitoken Phase 2b — closing the Phase 1 carried
    /// obligation): "one tx = one token" is now STRUCTURAL, not conventional. The C2C descriptor
    /// (`InterChannelTx`) carries exactly ONE scalar `token_index: u32` field (bound into the
    /// signed IMI2 digest and the E-2 "IMU2" transcript) and exactly one receiver delta (§A-2,
    /// enforced by every consuming verifier), and the receiver-side transition verifier proves
    /// the other 9 token positions of the credited row bit-identical — so a single
    /// `incoming_tx_hash` can never credit two token positions, and this unversioned per-tx
    /// nullifier cannot collapse a multi-token bundle (none is expressible). Covered by
    /// `receiver_bundle_apply_rejects_second_token_position_credit` in `state_update_verifier`.
    ///
    /// SECURITY (TM-16, Phase 5a — post-close token binding): `incoming_tx_hash` now commits the
    /// descriptor's base `token_index` (ids limb 5 of [`inter_channel_tx_hash`]), so this
    /// unversioned per-tx nullifier is TRANSITIVELY token-bound. A second post-close submission
    /// for the same absorbed tx with a DIFFERENT token cannot exist: its token-bearing hash
    /// differs, so it is a different accumulator leaf that was never absorbed (the identity-keyed
    /// replay ledger, TM-16 obligation 1, guarantees at most one token variant per debit is ever
    /// credited) — the claim fails the in-circuit accumulator inclusion, not merely the
    /// nullifier check. Covered by `post_close_claim_circuit_rejects_tampered_token_limb`.
    pub fn derive_shared_native_nullifier(
        close_intent_digest: Bytes32,
        incoming_tx_hash: Bytes32,
        receiver_pk_g: Bytes32,
    ) -> Bytes32 {
        hash_words(
            &[
                vec![POST_CLOSE_NULLIFIER_DOMAIN],
                close_intent_digest.to_u32_vec(),
                incoming_tx_hash.to_u32_vec(),
                receiver_pk_g.to_u32_vec(),
            ]
            .concat(),
        )
    }

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

/// detail2 §N-1: the payload of a cosigned `TokenRegister` transition — the BASE-layer
/// `token_index` to append at local token slot `token_count`.
///
/// SECURITY (TM-1): the apply/verify path is `BalanceState::apply_token_register` /
/// `BalanceState::verify_token_register_transition`, which enforce append-at-`token_count`,
/// `token_count + 1 <= MAX_CHANNEL_TOKENS`, injectivity of the new index against the active
/// registry, `state_version + 1`, and that balances/counters are UNTOUCHED. Cosigners MUST run
/// the verify check before signing the proposed post-state (whose H1 header commits the new
/// registry, TM-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRegister {
    pub token_index: u32,
}

/// The CANONICAL next `ChannelState` for a `TokenRegister(token_index)` transition (detail2
/// §N-1): `balance_state.apply_token_register` (append-at-`token_count`, injectivity,
/// `state_version`+1), `epoch`+1, `prev_digest` linkage, `h2_tag = 0` (no small block — a
/// registration is a header-only state change), signatures cleared for collection. EVERYTHING
/// ELSE — `channel_fund`, `small_block_number`, `close_freeze_nonce`,
/// `shared_native_nullifier_root`, `unallocated_confirmed_incoming`, every ciphertext/counter/
/// recipient, `settled_tx_chain`, `settled_tx_accumulator_root` — is carried over UNCHANGED by
/// the spreads.
///
/// SECURITY (TM-1/TM-9): this deterministic builder is shared by the proposer
/// (`wallet_core::build_token_register`) AND the cosigner gate
/// (`TokenRegisterUpdateWitness::verify` rebuild-equality), so a proposed registration that
/// touches ANYTHING beyond the registry append is refused by digest inequality — the
/// `l1_deposit_bundle_state` / `verify_token_register_transition` rebuild pattern.
pub fn token_register_next_state(
    prev: &ChannelState,
    token_index: u32,
) -> Result<ChannelState, ChannelError> {
    let mut balance_state = prev.balance_state.clone();
    balance_state.apply_token_register(token_index)?;
    Ok(ChannelState {
        epoch: prev.epoch + 1,
        balance_state,
        // §C-2: h2_tag = 0 for every non-small-block transition kind; `..prev.clone()` would
        // otherwise inherit a nonzero tag left by a preceding inter-channel send.
        h2_tag: Bytes32::default(),
        prev_digest: prev.digest,
        member_signatures: Vec::new(),
        ..prev.clone()
    }
    .with_computed_digest())
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
    /// detail2 §N-1: append-only cosigned token registration (see [`TokenRegister`]).
    TokenRegister(TokenRegister),
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
            Self::TokenRegister(_) => ChannelTransitionKind::TokenRegister,
        }
    }

    pub const fn required_state_backend(&self) -> Option<ProofBackend> {
        self.kind().required_state_backend()
    }

    pub const fn required_transport_backend(&self) -> Option<ProofBackend> {
        self.kind().required_transport_backend()
    }
}

/// A structurally well-formed, cryptographically MEANINGLESS cosign blob of exactly the Falcon
/// cosign length, for fixtures that exercise record/slot STRUCTURE and carry no real signature.
///
/// (Phase-4 review MINOR-3: an orphaned rustdoc paragraph from the retired
/// `validate_all_member_signatures` — still describing "one SPHINCS+ key per member" — had been
/// left attached to this function, so a helper whose ONE job is to be an explicit non-signature
/// was introduced by a paragraph about N-of-N signature validation. Removed.)
///
/// INTENTIONALLY NOT A SIGNATURE: it starts with the v1 version byte and has the exact cosign
/// length, so it passes the structural LENGTH gate in `validate_all_member_signatures` and
/// nothing else. Note that gate checks length only — the version byte is checked by the Falcon
/// decoder on the authenticating paths, not here. Every path that actually authenticates a
/// co-signature (`wallet_core::verify_all_signatures`, the close/cancel aggregation circuits)
/// recomputes the digest and verifies real Falcon signatures, and rejects this.
pub fn structural_cosign_placeholder(tag: u8) -> Vec<u8> {
    let mut v = vec![tag; crate::falcon_sig::FALCON_COSIGN_BLOB_BYTES];
    v[0] = crate::falcon_sig::FALCON_SIG_V1;
    v
}

/// Structural validation of a channel-STATE co-signature set: one signature per member slot, in
/// slot order, each carrying the registered `pk_g` and a blob of the FIXED Falcon cosign length.
///
/// SECURITY (TM-C8 / O-9, falcon-sig Phase 4): the length gate replaces the old "non-empty"
/// sanity check. It is a STRUCTURAL gate, not a cryptographic one — the real check is
/// `wallet_core::verify_all_signatures`, which verifies each signature against the registered
/// `pk_g` and the recomputed IMCH digest. Its value here is that a retired-scheme blob (~76 KB
/// `SingleSigCircuit` proof) cannot pass a check that only ever asked for "some bytes".
pub fn validate_all_member_signatures(
    record: &ChannelRecord,
    signatures: &[MemberSignature],
) -> Result<(), ChannelError> {
    validate_member_signature_slots(record, signatures)?;
    for (slot, actual) in signatures.iter().enumerate() {
        if actual.signature.len() != crate::falcon_sig::FALCON_COSIGN_BLOB_BYTES {
            return Err(ChannelError::InvalidSignatureSet(format!(
                "signature at slot {slot} is {} bytes, expected the fixed Falcon cosign encoding \
                 ({} bytes)",
                actual.signature.len(),
                crate::falcon_sig::FALCON_COSIGN_BLOB_BYTES
            )));
        }
    }
    Ok(())
}

/// Slot / identity structure only: one entry per member slot, in slot order, each carrying the
/// registered `pk_g` and a NON-EMPTY signature field.
///
/// Used where the `MemberSignature` entries are NOT channel-state co-signatures and so do not
/// carry the Falcon cosign encoding — currently only the `SignedSmallBlock` artifact, whose
/// signature bytes are a base-layer placeholder at this layer (the real small-block signature
/// check is the B-2 validity-proof path: the bp's Falcon signature verified in-circuit by the
/// list step and folded into `bp_sig_chain`). This is the check that function has always made;
/// [`validate_all_member_signatures`] adds the fixed-length gate on top for the co-sign path.
pub fn validate_member_signature_slots(
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
/// `member_set_commitment = keccak([IMCM, member_count, h_0(8), …, h_{MAX_SIG_CLUSTER-1}(8)])` over
/// `member_count` (single u32 limb right after the domain) and ALL `MAX_SIG_CLUSTER` COSIGNER
/// pubkey hashes in SLOT ORDER, where PADDING slots (`>= member_count`) contribute their
/// `Bytes32::default()` (zero) limbs. This preimage is FIXED-LENGTH.
///
/// SECURITY: this commits the active COSIGNER set INJECTIVELY — `member_count` fixes the
/// active/padding boundary and padding hashes are zero (the close circuit selects zero for `slot >=
/// member_count` and `ChannelRecord::validate` rejects nonzero padding hashes), so two different
/// active sets cannot collide. The full channel-close circuit recomputes this commitment in-circuit
/// from the SAME pubkeys whose SPHINCS+ signatures it verifies, and exposes it as a public input;
/// L1 matches it against the channel's registered cosigner set, so a prover cannot substitute
/// non-member signing keys.
///
/// SIZING (cosigner cap): the array holds the COSIGNERS only (`MAX_SIG_CLUSTER`), NOT the full
/// balance slot capacity (`MAX_CHANNEL_MEMBERS`). Delegates hold balances but do NOT co-sign the
/// close, so they never enter this commitment.
///
/// DESIGN NOTE (D6, forced): the preimage is fixed-length (member_count + all MAX_SIG_CLUSTER
/// hashes, padding zeroed) rather than the "active-only" variable-length form, because the
/// in-circuit keccak gadget takes a build-time-fixed input length and cannot hash a
/// `member_count`-dependent number of words. The fixed form is cryptographically equivalent
/// (member_count + zeroed padding is injective on the active set). This native helper MUST agree
/// byte-for-byte with the in-circuit keccak (`ChannelCloseCircuit::new`).
///
/// SOLIDITY MIRROR: `ChannelSettlementVerifier.closeMemberSetCommitment` pads the same fixed eight
/// cosigner slots (its internal constant retains the legacy `MAX_CHANNEL_MEMBERS` name but equals
/// Rust `MAX_SIG_CLUSTER = 8`). The Rust and Solidity preimages therefore have identical width.
pub fn close_member_set_commitment(hashes: &[Bytes32; MAX_SIG_CLUSTER], member_count: u8) -> Bytes32 {
    let count = member_count as usize;
    let mut words = Vec::with_capacity(2 + MAX_SIG_CLUSTER * 8);
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

/// IMLD-v2 L1 deposit-import digest (detail2 §N-5, TM-7). EXACT LIMB LAYOUT (14 u32 words):
/// `[L1_DEPOSIT_IMPORT_DOMAIN_V2 (1), channel_id (1), deposit_nullifier (8), token_index (1),
/// amount_lo (1), amount_hi (1), depositor_slot (1)]`.
/// Pinned byte-for-byte by `imld_v2_digest_layout_golden`.
///
/// SECURITY (TM-7/TM-15): the base deposit's `token_index` (spec.md §1.2 — no longer dropped)
/// occupies its OWN canonical limb between the nullifier and the amount — never bit-packed with
/// `depositor_slot` (packing would alias distinct `(token_index, slot)` pairs). The new "IML2"
/// domain makes v1 import digests unreplayable. The Phase 2 import transition must additionally
/// bind, in-circuit: `token_index ∈ registry` resolving to local slot t, `channel_fund.
/// amounts[t] += amount`, and the credited ciphertext being the depositor leaf's position-t
/// ciphertext (the three-way binding).
pub fn l1_deposit_import_digest(
    channel_id: ChannelId,
    deposit_nullifier: Bytes32,
    token_index: u32,
    amount: u64,
    depositor_slot: u16,
) -> Bytes32 {
    hash_words(
        &[
            vec![L1_DEPOSIT_IMPORT_DOMAIN_V2],
            channel_id.to_u32_vec(),
            deposit_nullifier.to_u32_vec(),
            vec![token_index],
            vec![amount as u32, (amount >> 32) as u32],
            vec![depositor_slot as u32],
        ]
        .concat(),
    )
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

    #[test]
    fn burn_descriptor_matches_frozen_cross_language_vector() {
        // Solidity: keccak256(abi.encodePacked(bytes4("IMD2"), uint32(1), uint32(9), txLeaf,
        //                                      baseRecipient, uint32(7), uint256(20))).
        let source_channel_id = ChannelId::new(1).unwrap();
        let base_nonce = 9;
        let tx_leaf =
            Bytes32::from_hex("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let base_recipient =
            Bytes32::from_hex("0x02000000000000000000000000000000000000000000000000000000000000aa")
                .unwrap();
        let expected =
            Bytes32::from_hex("0xb6753ec0eaf281f39942bbc2293983db8369713fc8a3f9446f6c86c8b5c737f5")
                .unwrap();
        assert_eq!(
            burn_descriptor(
                source_channel_id,
                base_nonce,
                tx_leaf,
                base_recipient,
                7,
                U256::from(20u64),
            ),
            expected
        );
    }

    #[test]
    fn burn_descriptor_v2_binds_source_channel_and_base_nonce() {
        let tx_leaf = Bytes32::from_u32_slice(&[1; 8]).unwrap();
        let recipient = Bytes32::from_u32_slice(&[2; 8]).unwrap();
        let amount = U256::from(20u64);
        let base = burn_descriptor(
            ChannelId::new(7).unwrap(),
            9,
            tx_leaf,
            recipient,
            3,
            amount,
        );
        assert_ne!(
            base,
            burn_descriptor(
                ChannelId::new(8).unwrap(),
                9,
                tx_leaf,
                recipient,
                3,
                amount,
            ),
            "source channel must bind the IMD2 identity"
        );
        assert_ne!(
            base,
            burn_descriptor(
                ChannelId::new(7).unwrap(),
                10,
                tx_leaf,
                recipient,
                3,
                amount,
            ),
            "base-account nonce must bind the IMD2 identity"
        );
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
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances_token0(&[
                ciphertext(1),
                ciphertext(2),
                ciphertext(3),
            ]),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
            // B-1b: nonzero per-active-slot L1 exit addresses (validate() rejects zero actives).
            recipients: BalanceState::pad_recipients(&[
                Address::from_u32_slice(&[11, 12, 13, 14, 15]).unwrap(),
                Address::from_u32_slice(&[21, 22, 23, 24, 25]).unwrap(),
                Address::from_u32_slice(&[31, 32, 33, 34, 35]).unwrap(),
            ]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
            state_version: version,
            pending_adds: BalanceState::pad_pending_adds_token0(&[0, 0, 0]),
            token_registry: BalanceState::single_token_registry(0),
            token_count: 1,
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
                amounts: ChannelFund::single_token_amounts(U256::from(15u32)),
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
                    signature: structural_cosign_placeholder(1),
                },
                MemberSignature {
                    member_slot: 1,
                    pk_g: pubkey_hash(11),
                    signature: structural_cosign_placeholder(3),
                },
                MemberSignature {
                    member_slot: 2,
                    pk_g: pubkey_hash(12),
                    signature: structural_cosign_placeholder(5),
                },
            ],
        }
        .with_computed_digest()
    }

    /// Pad an active prefix of member pubkey hashes to the full MAX_CHANNEL_MEMBERS array
    /// (the balance-slot capacity, used for `ChannelRecord.member_pk_gs`).
    fn pad_hashes(active: &[Bytes32]) -> [Bytes32; MAX_CHANNEL_MEMBERS] {
        std::array::from_fn(|i| active.get(i).copied().unwrap_or_default())
    }

    /// Pad an active prefix of COSIGNER pubkey hashes to the MAX_SIG_CLUSTER array (the cosigner cap,
    /// used for `close_member_set_commitment`).
    fn pad_cosigner_hashes(active: &[Bytes32]) -> [Bytes32; MAX_SIG_CLUSTER] {
        std::array::from_fn(|i| active.get(i).copied().unwrap_or_default())
    }

    fn sample_record() -> ChannelRecord {
        ChannelRecord {
            channel_id: sample_channel_id(),
            member_count: 3,
            delegate_count: 0,
            member_pk_gs: pad_hashes(&[pubkey_hash(10), pubkey_hash(11), pubkey_hash(12)]),
            member_pubkeys_root: Bytes32::from_u32_slice(&[7, 7, 7, 7, 0, 0, 0, 0]).unwrap(),
            set_version: 0,
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
            burn_amount: state.channel_fund.amounts[0],
            zkp: vec![1, 2, 3],
        }
    }

    /// M-9 CHARACTERIZATION (audit28-08-2026 §M-9; `close-detached-signing-design.md` T-5/§8.3).
    ///
    /// This test asserts the CURRENT, DEFECTIVE behaviour on purpose, so that M-9 is executable
    /// and so that whichever remediation lands (members sign IMCI — design-doc Option C — or an
    /// L1 pin of the three fields) breaks this test loudly and forces the assertions to be
    /// inverted. It is the "two witnesses differing only in `burn_tx_hash` /
    /// `snapshot_medium_block_number`" pair, at the native layer: the close circuit's IMCI
    /// recompute is byte-identical to `CloseIntent::signing_digest` and constrains none of these
    /// fields, so a native pair that produces distinct digests off ONE signed state is exactly a
    /// pair of circuit witnesses that both verify under the SAME member signatures.
    ///
    /// The load-bearing assertion is the first one: the members' ONLY message — the IMCH state
    /// digest — is byte-identical across every variant.
    #[test]
    fn m9_one_signature_set_mints_many_distinct_close_intent_digests() {
        let state = sample_state();
        let close_tx = sample_close_withdrawal(&state);
        let baseline = CloseIntent::new(5, &state, &close_tx, 123).unwrap();

        // Variant 1: `burn_tx_hash` only (this also moves `close_withdrawal_digest`, which is the
        // transitive half of the same freedom).
        let mut burn_tx = close_tx.clone();
        burn_tx.burn_tx_hash = Bytes32::from_u32_slice(&[0xdead, 0xbeef, 0, 0, 0, 0, 0, 0]).unwrap();
        let variant_burn = CloseIntent::new(5, &state, &burn_tx, 123).unwrap();

        // Variant 2: `snapshot_medium_block_number` only.
        let variant_mbn = CloseIntent::new(5, &state, &close_tx, 124).unwrap();

        // Variant 3: `close_nonce` only.
        let variant_nonce = CloseIntent::new(6, &state, &close_tx, 123).unwrap();

        // The ONLY message the members sign is the IMCH state digest, and it is identical for
        // every variant — so ONE N-of-N signature set authorizes all four.
        let imch = state.signing_digest();
        assert_eq!(state.digest, imch, "sample state's cached digest must be IMCH");
        for intent in [&baseline, &variant_burn, &variant_mbn, &variant_nonce] {
            assert_eq!(
                intent.final_channel_state_digest, imch,
                "M-9: every variant closes the SAME member-signed state"
            );
            assert_eq!(
                intent.close_freeze_nonce,
                state.close_freeze_nonce + 1,
                "M-9: the era fence is identical too — it comes from the signed state"
            );
        }

        // Yet all four close-intent digests differ. This is M-9: the digest the whole cancel lane
        // is addressed by is NOT a function of the member-signed state.
        let digests = [
            baseline.signing_digest(),
            variant_burn.signing_digest(),
            variant_mbn.signing_digest(),
            variant_nonce.signing_digest(),
        ];
        for i in 0..digests.len() {
            for j in (i + 1)..digests.len() {
                assert_ne!(
                    digests[i], digests[j],
                    "M-9 (expected while unremediated): variants {i} and {j} mint distinct \
                     close_intent_digests from ONE signature set. If this now FAILS, the fix has \
                     landed — invert this test to assert digest stability."
                );
            }
        }
    }

    /// M-9 positive control: the fences that DO hold are the ones carried by the signed state.
    /// A different `close_freeze_nonce` (era) or a different final state digest requires a
    /// genuinely different N-of-N signature set, because both live inside the IMCH preimage.
    /// This is what any digest-keyed logic must key its freshness off, not `close_intent_digest`.
    #[test]
    fn m9_era_and_state_fences_are_inside_the_signed_imch_preimage() {
        let state = sample_state();

        let mut next_era = state.clone();
        next_era.close_freeze_nonce += 1;
        let next_era = next_era.with_computed_digest();
        assert_ne!(
            next_era.digest, state.digest,
            "close_freeze_nonce IS inside IMCH: a new era needs a new signature set"
        );

        let mut next_version = state.clone();
        next_version.balance_state.state_version += 1;
        let next_version = next_version.with_computed_digest();
        assert_ne!(
            next_version.digest, state.digest,
            "state_version IS inside IMCH: a new version needs a new signature set"
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
    ///
    /// MULTITOKEN PHASE 3 RE-PIN (2026-07-27): the IMCI preimage carries the 80-limb
    /// `amounts[0..10]` vector (detail2 §N-6, in-place widening) and the Solidity mirror
    /// (`ChannelSettlementManager.computeCloseIntentDigest` /
    /// `ChannelSettlementVerifier._closeIntentDigest`) was updated to match. The constant below
    /// was REGENERATED FROM THIS RUST SIDE (the native layout is the source of truth) and is
    /// asserted by the Solidity twin — never re-pin by copying a Solidity result here.
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
                amounts: ChannelFund::single_token_amounts(
                    U256::from_u32_slice(&words(17)).unwrap(),
                ),
                intmax_state_root: Bytes32::from_u32_slice(&words(25)).unwrap(),
            },
            burn_tx_hash: Bytes32::from_u32_slice(&words(33)).unwrap(),
            close_withdrawal_digest: Bytes32::from_u32_slice(&words(41)).unwrap(),
            snapshot_medium_block_number: 0x9999_9999_aaaa_aaaa,
            final_state_version: 0xbbbb_bbbb_cccc_cccc,
            final_settled_tx_chain: Bytes32::from_u32_slice(&words(49)).unwrap(),
        };
        let expected =
            Bytes32::from_hex("0x9fc3ced58e9f82428e4b8a20f6e7755e1c0145facd2824f57d112cef86be42fb")
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
        // 3 ACTIVE member hashes padded to MAX_SIG_CLUSTER. The commitment is the FIXED 8-slot
        // form (pad-to-MAX D6): keccak([IMCM, member_count, h_0..h_7]) with padding slots zeroed
        // (66 u32 words). This pinned constant is mirrored by the Foundry test
        // `test_member_set_commitment_matches_rust_shared_vector` in
        // contracts/test/ChannelSettlementManager.t.sol — if they disagree, fix Solidity, not this
        // digest.
        let active = vec![
            Bytes32::from_u32_slice(&words(1)).unwrap(),
            Bytes32::from_u32_slice(&words(9)).unwrap(),
            Bytes32::from_u32_slice(&words(17)).unwrap(),
        ];
        let hashes = pad_cosigner_hashes(&active);
        let committed = close_member_set_commitment(&hashes, 3);
        let expected =
            Bytes32::from_hex("0x826fa6c83e36ef8f4537ce2bdd5873faa8e861dd7a4d3b072b77990cbfd7b886")
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
            delegate_count: 0,
            member_pk_gs: pad_hashes(&active),
            member_pubkeys_root: Bytes32::from_u32_slice(&[7, 7, 7, 7, 0, 0, 0, 0]).unwrap(),
            set_version: 0,
            bp_member_slot: 0,
            special_close_penalty: U256::from(5u32),
            close_freeze_nonce: 0,
            status: ChannelStatus::Active,
            regev_pk_root: Bytes32::from_u32_slice(&[9, 9, 9, 9, 0, 0, 0, 0]).unwrap(),
        }
    }

    /// Multi-N (D6 pad-to-MAX): `ChannelRecord::validate()` ACCEPTS member_count = 2 / 5 / 8
    /// (the boundary and an interior value) when active slots are distinct + nonzero and padding
    /// slots are `Bytes32::default()`, and REJECTS the D6 boundary violations.
    #[test]
    fn channel_record_validate_multi_n() {
        // Accepts 2 (min), 5 (interior), 8 (max, all slots active, no padding).
        // 16-era rot: the cap became MAX_SIG_CLUSTER = 8 in `fd467ea`, so the old `16` made this
        // test fail on its own first iteration — i.e. the max-width case was going UNTESTED, the
        // same defect class as the `..._n16` close-circuit test the 2026-08-28 audit found (§6).
        for count in [2u8, 5, MAX_SIG_CLUSTER as u8] {
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

        // member_count > MAX_SIG_CLUSTER is rejected (the old `(MAX_CHANNEL_MEMBERS + 1) as u8`
        // truncated to 1 at MAX=1024 and passed for the wrong reason — count 1 fails the `>= 2`
        // check, not the cap).
        let mut too_many = record_with_members(16);
        too_many.member_count = (MAX_SIG_CLUSTER + 1) as u8;
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

    /// `close_member_set_commitment` binds `member_count`: with the SAME 8-slot cosigner hash array, the
    /// digest for count = 2 differs from count = 3. Proves member_count is genuinely part of the
    /// preimage (not ignored), so two active sets that share a hash prefix cannot collide.
    #[test]
    fn close_member_set_commitment_binds_member_count() {
        let hashes = pad_cosigner_hashes(&[
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
        // And across the full supported COSIGNER range every adjacent count is distinct on the same
        // array. `hashes` above only fills 4 active slots, so counts beyond 4 hash extra zero
        // slots — still distinct preimages because `member_count` (the limb after the domain)
        // differs.
        for count in 2u8..MAX_SIG_CLUSTER as u8 {
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

        // SECURITY (TM-C8 / O-9, falcon-sig Phase 4): the structural gate is now a FIXED LENGTH,
        // not "non-empty". A retired-scheme blob (a ~76 KB `SingleSigCircuit` proof) and a
        // one-byte stub are both rejected here, before any crypto runs.
        let mut sigs = sample_state().member_signatures;
        sigs[1].signature = vec![1];
        assert!(
            validate_all_member_signatures(&record, &sigs).is_err(),
            "a short signature blob must fail the fixed-length structural gate"
        );
        let mut sigs = sample_state().member_signatures;
        sigs[1].signature = vec![0x52u8; 77_872];
        assert!(
            validate_all_member_signatures(&record, &sigs).is_err(),
            "a legacy-sized proof blob must fail the fixed-length structural gate"
        );
        // The slot-only variant is deliberately looser (the small-block artifact uses it).
        assert!(validate_member_signature_slots(&record, &sigs).is_ok());

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
        s.balance_state.enc_balances[1][0] = ciphertext(42);
        assert_ne!(s.signing_digest(), digest);
        let mut s = state.clone();
        s.balance_state.pending_adds[0][0] += 1;
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
            token_index: 0,
            base_nonce: 12,
            destination_base_transfer_salt: Salt::default(),
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
            sender_hash_sig: Vec::new(),
            sender_pk_b: Bytes32::default(),
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

    /// TM-6/TM-15: the IMI3 digest binds the base `token_index` in its own
    /// canonical limb — descriptors differing only in token_index have distinct digests, and the
    /// limb cannot alias its neighbors (own-limb discipline: swapping content between the
    /// token_index limb and an adjacent word changes the digest).
    #[test]
    fn inter_channel_tx_digest_binds_token_index_own_limb() {
        let state = sample_state();
        let tx = sample_inter_channel_tx(&state);
        let digest = tx.signing_digest();

        // token_index is digest-binding.
        let mut tampered = tx.clone();
        tampered.token_index = 5;
        assert_ne!(tampered.signing_digest(), digest);

        // Own-limb non-aliasing: moving the value into the adjacent source_pk_g word while
        // zeroing token_index (a bit-packing-style confusion) must NOT reproduce the digest.
        let mut aliased = tx.clone();
        aliased.token_index = 0;
        let mut pk_words = aliased.source_pk_g.to_u32_vec();
        pk_words[0] = 5;
        aliased.source_pk_g = Bytes32::from_u32_slice(&pk_words).unwrap();
        let mut original_with_token5 = tx.clone();
        original_with_token5.token_index = 5;
        assert_ne!(
            aliased.signing_digest(),
            original_with_token5.signing_digest()
        );
    }

    /// TM-16 (multitoken Phase 5a): the token-bearing `tx_hash` binds the base `token_index` in
    /// ids limb 5 (own canonical limb), while the replay-ledger identity is token-FREE — two
    /// descriptors over the SAME debit that differ only in token_index have DISTINCT anchored
    /// hashes (so a post-close claim proves the absorbed token) but the SAME ledger identity (so
    /// the second one is refused at the gate; the cross-token double-credit is structurally a
    /// replay). Also pins identity == hash-with-token-0 == the pre-TM-16 v1 formula (backward-
    /// consistent reading of v1 leaves, TM-16 note 6).
    #[test]
    fn inter_channel_tx_hash_binds_token_and_replay_identity_strips_it() {
        let state = sample_state();
        let mut tx = sample_inter_channel_tx(&state);
        tx.token_index = 55;
        let mut other_token = tx.clone();
        other_token.token_index = 7;

        // Token limb is hash-binding (the post-close claim's anchored token).
        let hash_55 = tx.compute_tx_hash().unwrap();
        let hash_7 = other_token.compute_tx_hash().unwrap();
        assert_ne!(hash_55, hash_7, "token_index must be tx_hash-binding");

        // The replay identity is token-free: both variants collide in the consumed ledger
        // (TM-16 obligation 1 — the double-credit across tokens is refused as a replay).
        assert_eq!(
            tx.replay_identity().unwrap(),
            other_token.replay_identity().unwrap(),
            "replay identity must be identical across token variants of the same debit"
        );

        // Identity == the token-0 hash == the v1 formula (limb 5 was constant zero in v1).
        let mut token0 = tx.clone();
        token0.token_index = 0;
        assert_eq!(
            tx.replay_identity().unwrap(),
            token0.compute_tx_hash().unwrap()
        );

        // Own-limb placement: the token limb (ids[5]) must not alias the destination id limb
        // (ids[6]) — a token value moved into the dest limb hashes differently.
        let leaf = tx.tx_leaf_hash().unwrap();
        let root = tx.signed_small_block.message.tx_tree_root;
        let confused = inter_channel_tx_hash(
            tx.source_channel_id,
            ChannelId::new(55).unwrap(),
            0,
            root,
            leaf,
        );
        assert_ne!(
            inter_channel_tx_hash(
                tx.source_channel_id,
                tx.destination_channel_id,
                55,
                root,
                leaf
            ),
            confused,
            "token limb must not alias the destination-id limb"
        );

        // Dest binding (HIGH-1) preserved in the identity.
        assert_ne!(
            inter_channel_tx_identity(tx.source_channel_id, tx.destination_channel_id, root, leaf),
            inter_channel_tx_identity(tx.source_channel_id, ChannelId::new(9).unwrap(), root, leaf),
        );
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
            1,
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
                1,
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
                1,
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
                1,
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
                1,
                pubkey_hash(10),
                pubkey_hash(11),
            )
        );
    }

    #[test]
    fn withdrawal_nullifier_depends_on_slot_regev_digest() {
        // B-2 blocker fix (regression direction 1): the nullifier keys on the slot's LEAF-BOUND
        // Regev pk digest (here stood in by distinct 32-byte values), NOT the slot-free
        // member_pk_g. Distinct slot identities ⇒ distinct nullifiers; a shared identity ⇒ the
        // SAME nullifier (double-spend guard) — see `WithdrawalClaim::derive_nullifier`.
        //
        // REGRESSION (TM-5): the preimage does NOT include `member_pk_g` — the function takes no
        // such argument, so grinding member_pk_g provably cannot mint fresh nullifiers
        // (type-level guarantee; any future signature change reintroducing a pk_g argument must
        // trip this comment in review).
        let close_digest = Bytes32::from_u32_slice(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let a = WithdrawalClaim::derive_nullifier(close_digest, pubkey_hash(10), 0);
        let b = WithdrawalClaim::derive_nullifier(close_digest, pubkey_hash(11), 0);
        assert_ne!(a, b);
        // Same slot identity + same close + same token ⇒ identical nullifier (one withdrawal
        // per (slot, token)).
        assert_eq!(
            a,
            WithdrawalClaim::derive_nullifier(close_digest, pubkey_hash(10), 0)
        );
        // The close-intent digest (which embeds channel_id) is part of the nullifier preimage.
        let other_close = Bytes32::from_u32_slice(&[8, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(
            a,
            WithdrawalClaim::derive_nullifier(other_close, pubkey_hash(10), 0)
        );
    }

    /// TM-5 (regression direction 2, per-(slot, token) separation): the SAME slot with two
    /// different token slots yields DISTINCT nullifiers (without this, only one of a member's 10
    /// tokens would be claimable per close — completeness break), and two different slots with
    /// the SAME token slot yield distinct nullifiers. Every token slot 0..10 is pairwise
    /// distinct for a fixed identity.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_nullifier_distinct_per_slot_and_token() {
        let close_digest = Bytes32::from_u32_slice(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        // Same slot identity, two tokens ⇒ distinct.
        let t0 = WithdrawalClaim::derive_nullifier(close_digest, pubkey_hash(10), 0);
        let t1 = WithdrawalClaim::derive_nullifier(close_digest, pubkey_hash(10), 1);
        assert_ne!(t0, t1, "same slot, different token must differ");
        // Two slots, same token ⇒ distinct.
        let other_slot = WithdrawalClaim::derive_nullifier(close_digest, pubkey_hash(11), 1);
        assert_ne!(t1, other_slot, "different slot, same token must differ");
        // All 10 token slots pairwise distinct for one identity.
        let all: Vec<Bytes32> = (0..MAX_CHANNEL_TOKENS as u8)
            .map(|t| WithdrawalClaim::derive_nullifier(close_digest, pubkey_hash(10), t))
            .collect();
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "token slots {i} and {j} must differ");
            }
        }
        // Exact 18-limb preimage layout: [IMW2, close(8), regev_pk_digest(8), token_slot].
        let expected = hash_words(
            &[
                vec![WITHDRAWAL_CLAIM_DOMAIN_V2],
                close_digest.to_u32_vec(),
                pubkey_hash(10).to_u32_vec(),
                vec![1u32],
            ]
            .concat(),
        );
        assert_eq!(t1, expected, "IMW2 nullifier preimage layout");
    }

    /// TM-15 own-limb discipline for the IMCW claim SIGNING digest (multitoken Phase 2, closing
    /// Phase 1 review MINOR 7): `token_slot` occupies its own canonical limb immediately after
    /// `member_pk_g`, so two claims differing ONLY in token_slot (identical nullifier field
    /// included — the adversarial aliasing shape) sign DIFFERENT digests, and the exact preimage
    /// layout is pinned.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn withdrawal_claim_signing_digest_binds_token_slot_own_limb() {
        let claim = |token_slot: u8| WithdrawalClaim {
            close_intent_digest: pubkey_hash(1),
            member_pk_g: pubkey_hash(2),
            token_slot,
            l1_recipient: Address::from_u32_slice(&[5, 6, 7, 8, 9]).unwrap(),
            user_amount_ct: ciphertext(3),
            // Deliberately the SAME nullifier bytes in both claims: token_slot must separate the
            // digests through its OWN limb, not merely transitively via the nullifier.
            withdrawal_nullifier: pubkey_hash(4),
            claim_proof: vec![1, 2, 3],
        };
        let d0 = claim(0).signing_digest();
        let d1 = claim(1).signing_digest();
        assert_ne!(
            d0, d1,
            "token_slot must alter the IMCW signing digest via its own limb"
        );
        // Exact preimage layout: [IMCW, close_intent(8), member_pk_g(8), token_slot(1),
        // l1_recipient(5), ct_digest(8), nullifier(8), proof_len, proof words].
        let c = claim(1);
        let expected = hash_words(
            &[
                vec![WITHDRAWAL_CLAIM_DOMAIN],
                c.close_intent_digest.to_u32_vec(),
                c.member_pk_g.to_u32_vec(),
                vec![1u32],
                c.l1_recipient.to_u32_vec(),
                c.user_amount_ct.digest().to_u32_vec(),
                c.withdrawal_nullifier.to_u32_vec(),
                vec![3u32],
                bytes_to_u32_words(&[1, 2, 3]),
            ]
            .concat(),
        );
        assert_eq!(d1, expected, "IMCW v2 signing-digest preimage layout");
    }

    /// GOLDEN (detail2 §N-3, TM-2/TM-15): IMPA-v2 exact 43-word preimage layout
    /// `[IMP2, channel_id, prev_state_digest(8), enc_amount.digest()(8), nonce(8),
    /// token_slot(1), sender_pk(8), recipient_pk(8)]`, and the own-limb aliasing negative: two
    /// distinct token_slot values produce distinct digests with everything else fixed.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn impa_v2_digest_layout_golden() {
        let channel_id = sample_channel_id();
        let prev = pubkey_hash(40);
        let enc = ciphertext(50);
        let nonce = Bytes32::from_u32_slice(&[6, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let sender = pubkey_hash(10);
        let recipient_pk = pubkey_hash(11);

        let expected_words = [
            vec![u32::from_be_bytes(*b"IMP2")],
            channel_id.to_u32_vec(),
            prev.to_u32_vec(),
            enc.digest().to_u32_vec(),
            nonce.to_u32_vec(),
            vec![3u32], // token_slot: its OWN limb, directly after the nonce
            sender.to_u32_vec(),
            recipient_pk.to_u32_vec(),
        ]
        .concat();
        assert_eq!(expected_words.len(), 43, "IMPA-v2 preimage is 43 u32 words");
        assert_eq!(
            ChannelTx::signing_digest(channel_id, prev, &enc, nonce, 3, sender, recipient_pk),
            hash_words(&expected_words),
            "IMPA-v2 layout must match the documented preimage exactly"
        );

        // Aliasing negative (TM-15): token_slot is binding on its own limb.
        let d3 = ChannelTx::signing_digest(channel_id, prev, &enc, nonce, 3, sender, recipient_pk);
        let d4 = ChannelTx::signing_digest(channel_id, prev, &enc, nonce, 4, sender, recipient_pk);
        assert_ne!(
            d3, d4,
            "distinct token_slot values must produce distinct digests"
        );
        // All 10 slots pairwise distinct.
        let all: Vec<Bytes32> = (0..MAX_CHANNEL_TOKENS as u8)
            .map(|t| {
                ChannelTx::signing_digest(channel_id, prev, &enc, nonce, t, sender, recipient_pk)
            })
            .collect();
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    /// GOLDEN (detail2 §N-5, TM-7/TM-15): IMLD-v2 exact 13-word preimage layout
    /// `[IML2, channel_id, deposit_nullifier(8), token_index, amount_lo, amount_hi,
    /// depositor_slot]`, plus the own-limb aliasing negatives: distinct `(token_index, slot)`
    /// pairs — including the swapped pair a bit-packed encoding would alias — produce distinct
    /// digests.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn imld_v2_digest_layout_golden() {
        let channel_id = sample_channel_id();
        let nullifier = pubkey_hash(60);
        let amount: u64 = 0x1234_5678_9abc_def0;

        let expected_words = [
            vec![u32::from_be_bytes(*b"IML2")],
            channel_id.to_u32_vec(),
            nullifier.to_u32_vec(),
            vec![7u32],                                 // token_index: its OWN limb
            vec![amount as u32, (amount >> 32) as u32], // amount_lo, amount_hi
            vec![2u32],                                 // depositor_slot
        ]
        .concat();
        assert_eq!(expected_words.len(), 14, "IMLD-v2 preimage is 14 u32 words");
        assert_eq!(
            l1_deposit_import_digest(channel_id, nullifier, 7, amount, 2),
            hash_words(&expected_words),
            "IMLD-v2 layout must match the documented preimage exactly"
        );

        // Aliasing negatives (TM-15): (token_index, depositor_slot) pairs are bound on separate
        // limbs — the swapped pair (2, 7) vs (7, 2), which `(token << 16) | slot`-style packing
        // could confuse with reordered fields, and single-coordinate changes, all differ.
        let base = l1_deposit_import_digest(channel_id, nullifier, 7, amount, 2);
        assert_ne!(
            base,
            l1_deposit_import_digest(channel_id, nullifier, 2, amount, 7),
            "swapped (token_index, slot) must differ"
        );
        assert_ne!(
            base,
            l1_deposit_import_digest(channel_id, nullifier, 8, amount, 2),
            "token_index is binding"
        );
        assert_ne!(
            base,
            l1_deposit_import_digest(channel_id, nullifier, 7, amount, 3),
            "depositor_slot is binding"
        );
    }

    /// GOLDEN (detail2 §N-6, TM-11): `token_funds_digest` exact 92-word preimage layout
    /// `[IMTF, registry(10), token_count, amounts(10 x 8)]`, ALWAYS full width — the omission
    /// negatives prove positions beyond `token_count` are still bound (no variable-length
    /// truncation), and registry/count/amounts are each binding.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn token_funds_digest_golden_vector() {
        let registry: [u32; MAX_CHANNEL_TOKENS] = std::array::from_fn(|t| 100 + t as u32);
        let amounts: [U256; MAX_CHANNEL_TOKENS] =
            std::array::from_fn(|t| U256::from(1000 + t as u32));
        let token_count = 4u8;

        let mut expected_words = vec![u32::from_be_bytes(*b"IMTF")];
        expected_words.extend_from_slice(&registry);
        expected_words.push(token_count as u32);
        for amount in &amounts {
            expected_words.extend(amount.to_u32_vec());
        }
        assert_eq!(expected_words.len(), 92, "TFD preimage is 92 u32 words");
        let digest = token_funds_digest(&registry, token_count, &amounts);
        assert_eq!(
            digest,
            hash_words(&expected_words),
            "TFD layout must match the documented preimage exactly"
        );
        // Rust<->Solidity shared vector (multitoken Phase 3, TM-11): the SAME (registry, count,
        // amounts) are hashed by `ChannelSettlementVerifier.tokenFundsDigest` in
        // contracts/test/MultiTokenSettlement.t.sol
        // (`test_tokenFundsDigest_matchesRustSharedVector`) and MUST produce this constant.
        // Generated FROM THIS RUST SIDE — if the two sides disagree, fix Solidity, not this
        // digest.
        assert_eq!(
            digest,
            Bytes32::from_hex("0x44987e3ca1c57257dfd4e9f5d6cc165f341cc4a9e5e0de7b6c06595105d27278")
                .unwrap(),
            "TFD Rust<->Solidity shared-vector constant"
        );

        // OMISSION NEGATIVE (TM-11): with token_count = 4, positions >= 4 are STILL hashed —
        // changing an "unused" registry limb or amount changes the digest (full-width preimage;
        // a variable-length encoding would ignore them and alias).
        let mut registry_tail = registry;
        registry_tail[7] = 9999;
        assert_ne!(
            digest,
            token_funds_digest(&registry_tail, token_count, &amounts),
            "registry position beyond token_count must still be bound (full width)"
        );
        let mut amounts_tail = amounts;
        amounts_tail[9] = U256::from(1u32);
        assert_ne!(
            digest,
            token_funds_digest(&registry, token_count, &amounts_tail),
            "amount position beyond token_count must still be bound (full width)"
        );
        // token_count itself is binding (same arrays, different active boundary).
        assert_ne!(digest, token_funds_digest(&registry, 5, &amounts));
        // And each active coordinate is binding.
        let mut registry_head = registry;
        registry_head[0] = 1;
        assert_ne!(
            digest,
            token_funds_digest(&registry_head, token_count, &amounts)
        );
        let mut amounts_head = amounts;
        amounts_head[0] = U256::from(1u32);
        assert_ne!(
            digest,
            token_funds_digest(&registry, token_count, &amounts_head)
        );
    }

    /// Multi-token close (§N-6, Phase 4 gate lift): `CloseIntent::new` now ACCEPTS a state
    /// carrying nonzero non-genesis-token funds — those settle via per-token withdrawal claims
    /// (Manager per-base-token accounting, Phase 3), NOT the burn leg. The intent must still
    /// (a) bind the burn amount to `amounts[0]` (the genesis-token burn denomination) and
    /// (b) snapshot the FULL fund vector into the IMCI preimage (TFD-bound on-chain).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn close_intent_accepts_nonzero_non_genesis_funds_and_binds_the_full_vector() {
        let mut state = sample_state();
        // Register a second token so amounts[1] is a REGISTERED position (§N-1 semantics).
        state.balance_state.apply_token_register(55).unwrap();
        state.channel_fund.amounts[1] = U256::from(5u32);
        let state = state.with_computed_digest();
        let close_tx = sample_close_withdrawal(&state);
        let intent = CloseIntent::new(9, &state, &close_tx, 123)
            .expect("multi-token close intent must build (per-token settlement landed, Phase 3)");
        // The full per-token vector is snapshotted (TFD/IMCI binding source).
        assert_eq!(
            intent.channel_fund_snapshot.amounts,
            state.channel_fund.amounts
        );
        // The burn leg still denominates EXACTLY amounts[0]: a burn_amount covering the non-
        // genesis fund too must be refused (the non-ETH funds are claim-settled, never burned).
        let mut bad_burn = sample_close_withdrawal(&state);
        bad_burn.burn_amount = state.channel_fund.amounts[0] + state.channel_fund.amounts[1];
        assert!(matches!(
            CloseIntent::new(9, &state, &bad_burn, 123),
            Err(ChannelError::InvalidCloseBinding(_))
        ));
        // And the two intents over different non-genesis funds hash differently (IMCI binds the
        // widened 80-limb vector).
        let mut state_b = sample_state();
        state_b.balance_state.apply_token_register(55).unwrap();
        state_b.channel_fund.amounts[1] = U256::from(6u32);
        let state_b = state_b.with_computed_digest();
        let close_tx_b = sample_close_withdrawal(&state_b);
        let intent_b = CloseIntent::new(9, &state_b, &close_tx_b, 123).unwrap();
        assert_ne!(intent.signing_digest(), intent_b.signing_digest());
    }

    /// detail2 §N-1: `token_register_next_state` is the canonical header-only registration step —
    /// registry append + `state_version`/`epoch` bump with EVERYTHING else frozen; duplicate and
    /// overflow registrations are refused by the underlying `apply_token_register` (TM-1).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn token_register_next_state_is_header_only_and_fail_closed() {
        let prev = sample_state();
        let next = token_register_next_state(&prev, 55).unwrap();
        assert_eq!(
            next.balance_state.token_count,
            prev.balance_state.token_count + 1
        );
        assert_eq!(
            next.balance_state.token_registry[prev.balance_state.token_count as usize],
            55
        );
        assert_eq!(next.epoch, prev.epoch + 1);
        assert_eq!(
            next.balance_state.state_version,
            prev.balance_state.state_version + 1
        );
        assert_eq!(next.prev_digest, prev.digest);
        assert_eq!(next.digest, next.signing_digest());
        assert!(next.member_signatures.is_empty());
        // Full freeze of everything else.
        assert_eq!(next.channel_fund, prev.channel_fund);
        assert_eq!(
            next.balance_state.enc_balances,
            prev.balance_state.enc_balances
        );
        assert_eq!(
            next.balance_state.pending_adds,
            prev.balance_state.pending_adds
        );
        assert_eq!(next.balance_state.recipients, prev.balance_state.recipients);
        assert_eq!(
            next.balance_state.settled_tx_chain,
            prev.balance_state.settled_tx_chain
        );
        assert_eq!(next.small_block_number, prev.small_block_number);
        assert_eq!(next.h2_tag, Bytes32::default());
        // Duplicate base index refused (the genesis registry already holds token 0).
        assert!(token_register_next_state(&prev, 0).is_err());
    }
}
