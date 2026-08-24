//! `BalanceState` — the hidden-balance core of the v2 channel layer
//! (abstract2 §2.1, detail2 §C-2/§C-6, approved deviation D3).
//!
//! Channel balances live in state only as Regev ciphertexts (one per member slot, in
//! member slot order). `H1 = h1()` commits to the full balance state WITHOUT any proof
//! object, so all three members can sign `hash(H1, H2)` at state-authoring time (audit finding 3:
//! no signing-time proof circularity). The settled-tx hash chain (`settled_tx_chain`) is the
//! mechanical link between a signed `BalanceState` and the balance proof that imported the same
//! settle history (detail2 §F-1).

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::builder::BuilderKeccak256 as _;
use serde::{Deserialize, Serialize};

use crate::{
    common::channel::{ChannelError, ChannelId, hash_words, split_u64},
    constants::{
        BALANCE_SLOT_LEAF_DOMAIN_V2, BALANCE_SLOT_TREE_HEIGHT, BALANCE_STATE_DOMAIN_V2,
        MAX_CHANNEL_MEMBERS, MAX_CHANNEL_TOKENS, MAX_SIG_CLUSTER,
    },
    ethereum_types::{
        address::Address,
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    regev::{MAX_HOMO_ADDS_BEFORE_REFRESH, RegevCiphertext},
    utils::{
        leafable_hasher::{LeafableHasher as _, PoseidonLeafableHasher},
        poseidon_hash_out::PoseidonHashOut,
        trees::incremental_merkle_tree::IncrementalMerkleTree,
    },
};

// NOTE (multitoken Phase 2): the RETIRED v1 domain constants "IMBS" (0x494d4253, v1 H1 header)
// and "IMSL" (0x494d534c, v1 23-element slot leaf) are DELETED — the in-circuit recompute
// (`circuits::channel::h1_gadget`) migrated to the v2 layouts ("IMB2"/"IMS2"), so no code path
// hashes under them anymore. Their values stay pinned in the repo-wide non-collision tests
// (`constants::tests::all_domain_constants_pairwise_distinct`,
// `poseidon_sig::tests::domain_constants_are_pairwise_distinct`) — same treatment as the retired
// "IMPA"/"IMLD" v1 constants (TM-15).
/// Domain separator for [`balance_state_hash`] ("IMBH").
pub const BALANCE_STATE_HASH_DOMAIN: u32 = 0x494d4248;
/// Domain separator for the two wings of [`tx_leaf_hash`] ("IMTL").
pub const TX_LEAF_DOMAIN: u32 = 0x494d544c;
/// Domain separator for [`settled_tx_chain_push`] ("IMTC").
pub const SETTLED_TX_CHAIN_DOMAIN: u32 = 0x494d5443;

/// Per-slot token-dimension row of balance ciphertexts: position `t` is the ciphertext for local
/// token slot `t` of the channel's `token_registry` (detail2 §N-2). ALWAYS full
/// `MAX_CHANNEL_TOKENS` width in memory and in every hash preimage; positions `t >= token_count`
/// are the canonical zero ciphertext (TM-8).
pub type TokenCiphertexts = [RegevCiphertext; MAX_CHANNEL_TOKENS];
/// Per-slot token-dimension row of homomorphic-add counters (D3, per (slot, token) — TM-13).
pub type TokenPendingAdds = [u32; MAX_CHANNEL_TOKENS];

/// The canonical zero ciphertext (`RegevCiphertext::padding()`), cached (heap shape is fixed).
pub fn zero_ciphertext() -> &'static RegevCiphertext {
    static ZERO_CT: std::sync::OnceLock<RegevCiphertext> = std::sync::OnceLock::new();
    ZERO_CT.get_or_init(RegevCiphertext::padding)
}

/// Canonical zero-ciphertext digest constant: `RegevCiphertext::padding().digest()`, computed
/// once. Every unused (slot, token) position contributes exactly this digest to its leaf.
///
/// SECURITY (TM-8): reusing ONE public constant for every unused position is safe because the
/// all-zero ciphertext decrypts to 0 under ANY Regev key — a claim opened against an unused
/// position provably yields amount 0 — and keccak collision resistance prevents any REAL nonzero
/// ciphertext from sharing this digest. `validate()` fail-closes the other direction: positions
/// `t >= token_count` MUST equal this canonical value (no hidden value smuggled into inactive
/// token positions).
pub fn zero_ciphertext_digest() -> Bytes32 {
    static ZERO_CT_DIGEST: std::sync::OnceLock<Bytes32> = std::sync::OnceLock::new();
    *ZERO_CT_DIGEST.get_or_init(|| zero_ciphertext().digest())
}

/// A full all-zero token row (`MAX_CHANNEL_TOKENS` canonical zero ciphertexts).
pub fn zero_token_row() -> TokenCiphertexts {
    std::array::from_fn(|_| zero_ciphertext().clone())
}

/// Compact snapshot-JSON encoding of the token-dimension matrices (detail2 §N-2: "storage MAY be
/// sparse, the hash layout is always full width"). On the WIRE each slot row is a map
/// `token_slot_index -> value` containing only non-canonical entries (non-zero ciphertexts /
/// non-zero counters), and trailing all-canonical slot rows may be omitted; ON LOAD every omitted
/// position is filled with the canonical zero (ciphertext / 0 counter), restoring the full
/// `MAX_CHANNEL_MEMBERS x MAX_CHANNEL_TOKENS` in-memory layout that all hashing operates on.
///
/// SECURITY: the compact form is an ENCODING of exactly one full-width state (canonical-zero
/// default on load, out-of-range keys/rows rejected), so it cannot alias two different states;
/// `validate()` then enforces the TM-8/TM-13 canonicality of the loaded matrix fail-closed.
mod token_matrix_serde {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

    use super::{
        MAX_CHANNEL_MEMBERS, MAX_CHANNEL_TOKENS, RegevCiphertext, TokenCiphertexts,
        TokenPendingAdds, zero_ciphertext, zero_token_row,
    };

    pub mod ciphertexts {
        use super::*;

        pub fn serialize<S: Serializer>(
            rows: &[TokenCiphertexts],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let mut sparse: Vec<BTreeMap<u8, &RegevCiphertext>> = rows
                .iter()
                .map(|row| {
                    row.iter()
                        .enumerate()
                        .filter(|(_, ct)| *ct != zero_ciphertext())
                        .map(|(t, ct)| (t as u8, ct))
                        .collect()
                })
                .collect();
            while sparse.last().is_some_and(BTreeMap::is_empty) {
                sparse.pop();
            }
            sparse.serialize(serializer)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<TokenCiphertexts>, D::Error> {
            let sparse: Vec<BTreeMap<u8, RegevCiphertext>> = Vec::deserialize(deserializer)?;
            if sparse.len() > MAX_CHANNEL_MEMBERS {
                return Err(D::Error::custom(format!(
                    "encBalances has {} slot rows (> MAX_CHANNEL_MEMBERS = {MAX_CHANNEL_MEMBERS})",
                    sparse.len()
                )));
            }
            let mut rows: Vec<TokenCiphertexts> = Vec::with_capacity(MAX_CHANNEL_MEMBERS);
            for (slot, mut row) in sparse.into_iter().enumerate() {
                if row.keys().any(|&t| t as usize >= MAX_CHANNEL_TOKENS) {
                    return Err(D::Error::custom(format!(
                        "encBalances[{slot}] has a token position >= MAX_CHANNEL_TOKENS = \
                         {MAX_CHANNEL_TOKENS}"
                    )));
                }
                rows.push(std::array::from_fn(|t| {
                    row.remove(&(t as u8))
                        .unwrap_or_else(|| zero_ciphertext().clone())
                }));
            }
            rows.resize_with(MAX_CHANNEL_MEMBERS, zero_token_row);
            Ok(rows)
        }
    }

    pub mod pending_adds {
        use super::*;

        pub fn serialize<S: Serializer>(
            rows: &[TokenPendingAdds],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let mut sparse: Vec<BTreeMap<u8, u32>> = rows
                .iter()
                .map(|row| {
                    row.iter()
                        .enumerate()
                        .filter(|(_, adds)| **adds != 0)
                        .map(|(t, adds)| (t as u8, *adds))
                        .collect()
                })
                .collect();
            while sparse.last().is_some_and(BTreeMap::is_empty) {
                sparse.pop();
            }
            sparse.serialize(serializer)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<TokenPendingAdds>, D::Error> {
            let sparse: Vec<BTreeMap<u8, u32>> = Vec::deserialize(deserializer)?;
            if sparse.len() > MAX_CHANNEL_MEMBERS {
                return Err(D::Error::custom(format!(
                    "pendingAdds has {} slot rows (> MAX_CHANNEL_MEMBERS = {MAX_CHANNEL_MEMBERS})",
                    sparse.len()
                )));
            }
            let mut rows: Vec<TokenPendingAdds> = Vec::with_capacity(MAX_CHANNEL_MEMBERS);
            for (slot, row) in sparse.into_iter().enumerate() {
                if row.keys().any(|&t| t as usize >= MAX_CHANNEL_TOKENS) {
                    return Err(D::Error::custom(format!(
                        "pendingAdds[{slot}] has a token position >= MAX_CHANNEL_TOKENS = \
                         {MAX_CHANNEL_TOKENS}"
                    )));
                }
                rows.push(std::array::from_fn(|t| {
                    row.get(&(t as u8)).copied().unwrap_or(0)
                }));
            }
            rows.resize(MAX_CHANNEL_MEMBERS, [0u32; MAX_CHANNEL_TOKENS]);
            Ok(rows)
        }
    }
}

/// abstract2 §2.1: `BalanceState { encBalances, settledTxChain, stateVersion }`, extended with
/// per-member homomorphic-add counters (approved deviation D3 from detail2 §C-2) and the
/// multi-token dimension (detail2 §N: per-(slot, token) ciphertexts + the channel-local token
/// registry).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceState {
    pub channel_id: ChannelId,
    /// Number of ACTIVE members (2..=MAX_CHANNEL_MEMBERS). Active members occupy slots
    /// `0..member_count`; slots `member_count..MAX_CHANNEL_MEMBERS` are padding
    /// (`RegevCiphertext::padding()` balances, zero `pending_adds`).
    ///
    /// SECURITY (D6 pad-to-MAX): `member_count` is part of the H1 preimage (see [`Self::h1`]) so
    /// the active/padding split is fixed by the same all-member signatures that bind the balances;
    /// a state could not silently re-interpret a padding slot as active or vice-versa.
    pub member_count: u8,
    /// Number of DELEGATE participants (send/receive/withdraw, but NOT co-signing the N-of-N
    /// state). Delegates occupy the contiguous slot region
    /// `member_count..member_count+delegate_count`; slots `member_count+delegate_count..MAX` are
    /// padding. Invariant: `member_count + delegate_count <= MAX_CHANNEL_MEMBERS`.
    ///
    /// SECURITY (delegate account, Phase 1): `delegate_count` is part of the H1 preimage (see
    /// [`Self::h1`]) IMMEDIATELY AFTER `member_count`, so the member/delegate/padding split is
    /// fixed by the same all-member signatures that bind the balances. A state could not
    /// silently re-interpret a delegate slot as a member (or vice-versa) or a padding slot as
    /// a delegate. Delegate slots are ACTIVE balance slots (non-padding ciphertexts) exactly
    /// like member slots.
    ///
    /// WIDTH: `u16` — delegates occupy BALANCE-SLOT space (up to `MAX_CHANNEL_MEMBERS = 1024 -
    /// member_count`), which does not fit in u8. The H1 preimage encodes this as a u64 field
    /// input, so the widening is digest-transparent.
    pub delegate_count: u16,
    /// One `MAX_CHANNEL_TOKENS`-wide row of balance ciphertexts per slot, in member slot order
    /// (detail2 §N-2): `enc_balances[slot][token_slot]`. Padding member slots (`>= member_count +
    /// delegate_count`) are all-zero rows; within active slots, positions `t >= token_count` are
    /// the canonical zero ciphertext (TM-8).
    ///
    /// INVARIANT: `len() == MAX_CHANNEL_MEMBERS` always (constructed via the `pad_*` helpers /
    /// the deserializer, re-checked fail-closed by [`Self::validate`]). Heap-backed `Vec` — a
    /// `[[RegevCiphertext; 10]; 1024]` by-value array would blow the stack.
    #[serde(with = "token_matrix_serde::ciphertexts")]
    pub enc_balances: Vec<TokenCiphertexts>,
    /// Decryption Stage 1: per-slot Regev public-key Poseidon digests, in member slot order.
    /// Active slots carry `Bytes32::from(RegevPk::poseidon_digest())` (the SAME injective
    /// encoding as the validity-side `MemberLeaf.regev_pk_digest`, so decryption Stage 2 can
    /// bind the witnessed `(a, b)` to this committed value via a one-hot select). Padding
    /// slots (`>= active`) carry `Bytes32::default()`.
    ///
    /// SECURITY: committed into [`Self::h1`] via slot leaf i of the balance-slot Poseidon tree
    /// (`balance_slot_leaf_hash`), so each member's registered Regev pk is bound by the same
    /// all-member signatures that bind the balances. This is the H1-commitment prerequisite that
    /// makes the decryption-core pk binding (MUST-FIX #1) satisfiable without deployer trust.
    #[serde(with = "serde_big_array::BigArray")]
    pub regev_pk_digests: [Bytes32; MAX_CHANNEL_MEMBERS],
    /// B-1b (Option B1, tasks/reg-chain-1024-threat-model.md): the per-slot L1 EXIT ADDRESS, in
    /// member slot order. Active slots carry the slot owner's L1 withdrawal recipient; padding
    /// slots (`>= member_count + delegate_count`) carry `Address::default()` (zero).
    ///
    /// SECURITY: committed into [`Self::h1`] via slot leaf i of the balance-slot Poseidon tree
    /// (`balance_slot_leaf_hash`), so each slot's payout address is bound under the SAME cosigner
    /// N-of-N signatures that bind the balances. Under Option B delegates have NO L1 registration
    /// (`registeredRecipientOf` never covers them), so this leaf binding is the ONLY thing that
    /// prevents a delegate's L1 payout from being redirected at claim time: the claim circuits
    /// open this field by slot-tree inclusion and connect it to the claim's `recipient` PI.
    /// Recipient changes are NOT a supported state transition — every transition verifier
    /// enforces `recipients` unchanged (see `state_update_verifier::verify_balance_state_common`).
    #[serde(with = "serde_big_array::BigArray")]
    pub recipients: [Address; MAX_CHANNEL_MEMBERS],
    /// Hash chain over the settles this state has absorbed (genesis = 0x00…00).
    pub settled_tx_chain: Bytes32,
    /// Stage 3 (post-close source-tx anchoring): the root of the per-channel settled-tx Merkle
    /// ACCUMULATOR — an `IncrementalMerkleTree<Bytes32>` of height `H = 20` whose leaves are the
    /// `tx_hash` of every settle this state has absorbed (genesis = the empty-tree root). Encoded
    /// as `Bytes32::from(IncrementalMerkleTree::get_root())` — the SAME injective
    /// Poseidon→Bytes32 encoding Stage 1 uses for `regev_pk_digests`.
    ///
    /// SECURITY: the accumulator and `settled_tx_chain` are INDEPENDENT commitments storing
    /// DIFFERENT leaves. The chain stores `tx_leaf` for send/bundle and `tx_hash` for fund-import;
    /// the accumulator stores `tx_hash` UNIFORMLY at every settle advancement, giving the
    /// post-close claim ONE canonical membership predicate (`incoming_tx_hash`). Folded into
    /// [`Self::h1`] (the signed preimage) IMMEDIATELY AFTER `settled_tx_chain`, so the
    /// accumulator root is attested by the same all-member signatures that bind the chain. The
    /// close circuit exposes it as a dedicated close PI (`final_settled_tx_accumulator_root`);
    /// L1 finalizes that value; the post-close claim binds a Merkle inclusion of
    /// `incoming_tx_hash` against the finalized root.
    pub settled_tx_accumulator_root: Bytes32,
    /// Monotone state counter, +1 on every in-channel AND inter-channel update. Independent of
    /// `epoch` / `small_block_number` (in-channel transfers produce no small block).
    pub state_version: u64,
    /// Homomorphic-add counters per (member slot, token slot) since that position's last fresh
    /// re-encryption (approved deviation D3 from detail2 §C-2; per-token per TM-13 — an
    /// unchecked counter would make that token permanently unexitable for that member).
    /// Co-signers must refuse adds at `MAX_HOMO_ADDS_BEFORE_REFRESH`. Padding member slots and
    /// inactive token positions (`t >= token_count`) are 0.
    ///
    /// INVARIANT: `len() == MAX_CHANNEL_MEMBERS` always (see `enc_balances`).
    #[serde(with = "token_matrix_serde::pending_adds")]
    pub pending_adds: Vec<TokenPendingAdds>,
    /// Channel-local token registry (detail2 §N-1): local token slot `t` -> BASE-layer
    /// `token_index: u32`, zero-padded beyond `token_count`. Append-only (cosigned
    /// `TokenRegister` transitions); injective on the active prefix `[0..token_count)` (TM-1).
    ///
    /// SECURITY (TM-9): committed in the H1 header (see [`Self::h1`]) as 10 canonical u32 limbs,
    /// ALWAYS full width — an unsigned registry would let existing signatures be reinterpreted
    /// over a different token mapping.
    pub token_registry: [u32; MAX_CHANNEL_TOKENS],
    /// Number of ACTIVE token slots, `1..=MAX_CHANNEL_TOKENS` (TM-8). Positions `>= token_count`
    /// of every slot row MUST be the canonical zero ciphertext with zero `pending_adds`
    /// (fail-closed in [`Self::validate`]).
    ///
    /// SECURITY (TM-9): committed in the H1 header IMMEDIATELY BEFORE the registry limbs,
    /// mirroring the `member_count`/`delegate_count` discipline — the active/unused token
    /// boundary is fixed under the same all-member signatures that bind the balances.
    pub token_count: u8,
}

impl BalanceState {
    /// Pad `active` full-width token rows (len = the active slot prefix) to the full
    /// `MAX_CHANNEL_MEMBERS`-length row vector, filling padding slots with all-zero rows.
    pub fn pad_enc_balances(active: &[TokenCiphertexts]) -> Vec<TokenCiphertexts> {
        let mut rows: Vec<TokenCiphertexts> = active.to_vec();
        assert!(
            rows.len() <= MAX_CHANNEL_MEMBERS,
            "active slot prefix exceeds MAX_CHANNEL_MEMBERS"
        );
        rows.resize_with(MAX_CHANNEL_MEMBERS, zero_token_row);
        rows
    }

    /// Single-token convenience: place each active ciphertext at TOKEN SLOT 0 of its member
    /// slot's row (all other token positions = canonical zero ct), padding member slots with
    /// all-zero rows. This is the exact v1-state embedding of detail2 §N (owner decision 5:
    /// "a v1 state is definitionally `registry=[ETH]`, all balances at token slot 0").
    pub fn pad_enc_balances_token0(active: &[RegevCiphertext]) -> Vec<TokenCiphertexts> {
        let rows: Vec<TokenCiphertexts> = active
            .iter()
            .map(|ct| {
                let mut row = zero_token_row();
                row[0] = ct.clone();
                row
            })
            .collect();
        Self::pad_enc_balances(&rows)
    }

    /// Pad `active` full-width per-token add-counter rows to the full `MAX_CHANNEL_MEMBERS`
    /// length, filling padding slots with all-zero rows.
    pub fn pad_pending_adds(active: &[TokenPendingAdds]) -> Vec<TokenPendingAdds> {
        let mut rows: Vec<TokenPendingAdds> = active.to_vec();
        assert!(
            rows.len() <= MAX_CHANNEL_MEMBERS,
            "active slot prefix exceeds MAX_CHANNEL_MEMBERS"
        );
        rows.resize(MAX_CHANNEL_MEMBERS, [0u32; MAX_CHANNEL_TOKENS]);
        rows
    }

    /// Single-token convenience: each active counter goes to token position 0 (see
    /// [`Self::pad_enc_balances_token0`]).
    pub fn pad_pending_adds_token0(active: &[u32]) -> Vec<TokenPendingAdds> {
        let rows: Vec<TokenPendingAdds> = active
            .iter()
            .map(|&adds| {
                let mut row = [0u32; MAX_CHANNEL_TOKENS];
                row[0] = adds;
                row
            })
            .collect();
        Self::pad_pending_adds(&rows)
    }

    /// The genesis single-token registry: `token_index` at local token slot 0, zero-padded
    /// (use with `token_count: 1`). ETH-only channels use `single_token_registry(0)`.
    pub fn single_token_registry(token_index: u32) -> [u32; MAX_CHANNEL_TOKENS] {
        let mut registry = [0u32; MAX_CHANNEL_TOKENS];
        registry[0] = token_index;
        registry
    }

    /// Decryption Stage 1: pad `active` Regev pk digests (len = `member_count + delegate_count`,
    /// each `Bytes32::from(RegevPk::poseidon_digest())`) to a full `MAX_CHANNEL_MEMBERS`-sized
    /// array, filling padding slots with `Bytes32::default()`.
    pub fn pad_regev_pk_digests(active: &[Bytes32]) -> [Bytes32; MAX_CHANNEL_MEMBERS] {
        std::array::from_fn(|i| active.get(i).copied().unwrap_or_default())
    }

    /// B-1b: pad `active` per-slot L1 exit addresses (len = `member_count + delegate_count`, each
    /// NONZERO) to a full `MAX_CHANNEL_MEMBERS`-sized array, filling padding slots with
    /// `Address::default()` (zero). Mirrors the other `pad_*` helpers; [`Self::validate`] enforces
    /// the nonzero-active / zero-padding split fail-closed.
    pub fn pad_recipients(active: &[Address]) -> [Address; MAX_CHANNEL_MEMBERS] {
        std::array::from_fn(|i| active.get(i).copied().unwrap_or_default())
    }

    /// The keccak digests of one slot's `MAX_CHANNEL_TOKENS` ciphertexts, reusing the canonical
    /// zero-ct digest for zero positions (pure memoization — equal to a per-position recompute).
    pub fn token_ct_digests(row: &TokenCiphertexts) -> [Bytes32; MAX_CHANNEL_TOKENS] {
        std::array::from_fn(|t| {
            if row[t] == *zero_ciphertext() {
                zero_ciphertext_digest()
            } else {
                row[t].digest()
            }
        })
    }

    /// The per-slot leaf hashes of the H1 balance-slot Poseidon Merkle tree, in member slot
    /// order (ALL `MAX_CHANNEL_MEMBERS` slots — the tree, and hence H1, is a function of the
    /// FULL slot array, exactly like the retired flat keccak).
    ///
    /// PERF: padding slots share one canonical `(default pk digest, all-zero ct digests, all-0
    /// adds, zero recipient)` leaf, and within active slots every zero token position reuses the
    /// cached zero-ct digest. Pure memoizations: the reused values equal the per-slot recompute.
    pub fn slot_leaf_hashes(&self) -> Vec<PoseidonHashOut> {
        assert_eq!(
            self.enc_balances.len(),
            MAX_CHANNEL_MEMBERS,
            "enc_balances must be full slot width"
        );
        assert_eq!(
            self.pending_adds.len(),
            MAX_CHANNEL_MEMBERS,
            "pending_adds must be full slot width"
        );
        let zero_row_digests: [Bytes32; MAX_CHANNEL_TOKENS] =
            std::array::from_fn(|_| zero_ciphertext_digest());
        let padding_leaf = balance_slot_leaf_hash(
            Bytes32::default(),
            &zero_row_digests,
            &[0u32; MAX_CHANNEL_TOKENS],
            Address::default(),
        );
        (0..MAX_CHANNEL_MEMBERS)
            .map(|i| {
                let is_padding_slot = self.regev_pk_digests[i] == Bytes32::default()
                    && self.pending_adds[i] == [0u32; MAX_CHANNEL_TOKENS]
                    && self.recipients[i] == Address::default()
                    && self.enc_balances[i]
                        .iter()
                        .all(|ct| ct == zero_ciphertext());
                if is_padding_slot {
                    padding_leaf
                } else {
                    balance_slot_leaf_hash(
                        self.regev_pk_digests[i],
                        &Self::token_ct_digests(&self.enc_balances[i]),
                        &self.pending_adds[i],
                        self.recipients[i],
                    )
                }
            })
            .collect()
    }

    /// The FULL balance-slot tree (height [`BALANCE_SLOT_TREE_HEIGHT`], all
    /// `MAX_CHANNEL_MEMBERS` leaves populated). Used by the claim witness builders to produce
    /// per-slot inclusion proofs; [`Self::slot_tree_root`] computes the same root without the
    /// tree bookkeeping.
    pub fn slot_tree(&self) -> IncrementalMerkleTree<PoseidonHashOut> {
        let mut tree = IncrementalMerkleTree::<PoseidonHashOut>::new(BALANCE_SLOT_TREE_HEIGHT);
        for leaf in self.slot_leaf_hashes() {
            tree.push(leaf);
        }
        tree
    }

    /// The balance-slot tree ROOT — the value committed inside [`Self::h1`]. Bottom-up fold
    /// (`PoseidonLeafableHasher::two_to_one`, the same node hash `slot_tree()` /
    /// `IncrementalMerkleProofTarget` use; equality is pinned by
    /// `slot_tree_root_matches_incremental_tree` below).
    pub fn slot_tree_root(&self) -> PoseidonHashOut {
        let mut level = self.slot_leaf_hashes();
        debug_assert_eq!(level.len(), 1 << BALANCE_SLOT_TREE_HEIGHT);
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| PoseidonLeafableHasher::two_to_one(pair[0], pair[1]))
                .collect();
        }
        level[0]
    }

    /// The FIXED-width v2 H1 header preimage (detail2 §N-1; 37 u64-encoded elements). Exposed so
    /// the width/layout golden tests pin it exactly. LAYOUT (in order — the pre-multi-token
    /// fields keep their relative v1 order; `token_count` + the registry slot in right after
    /// `delegate_count`, extending the count-discipline block):
    ///
    /// `[BALANCE_STATE_DOMAIN_V2, channel_id, member_count, delegate_count, token_count,
    ///   token_registry (10 canonical u32 limbs, zero-padded), slot_tree_root (4 Goldilocks
    ///   elements), settled_tx_chain (8 u32 limbs), settled_tx_accumulator_root (8 u32 limbs),
    ///   split_u64(state_version) (hi, lo)]`
    pub fn h1_header_preimage(&self) -> Vec<u64> {
        let root = self.slot_tree_root();
        let mut inputs: Vec<u64> = vec![
            BALANCE_STATE_DOMAIN_V2 as u64,
            self.channel_id.to_u32_vec()[0] as u64,
            self.member_count as u64,
            // delegate_count is committed IMMEDIATELY AFTER member_count, fixing the
            // member/delegate/padding region split under the member signatures.
            self.delegate_count as u64,
            // SECURITY (TM-9): token_count + the FULL zero-padded registry ride in the signed
            // header right after the member/delegate counts — the active/unused token boundary
            // and the local-slot -> base-token mapping are fixed under the same signatures that
            // bind the balances, mirroring the member_count/delegate_count discipline.
            self.token_count as u64,
        ];
        inputs.extend(self.token_registry.iter().map(|&t| t as u64));
        inputs.extend(root.elements);
        inputs.extend(self.settled_tx_chain.to_u32_vec().iter().map(|&w| w as u64));
        // Stage 3: the settled-tx accumulator root sits IMMEDIATELY AFTER settled_tx_chain and
        // BEFORE state_version, mirroring the retired keccak header order.
        inputs.extend(
            self.settled_tx_accumulator_root
                .to_u32_vec()
                .iter()
                .map(|&w| w as u64),
        );
        inputs.extend(split_u64(self.state_version).iter().map(|&w| w as u64));
        inputs
    }

    /// H1 v2 (detail2 §C-2 + D3, pad-to-MAX deviation D6, decryption Stage 1, Stage 3
    /// accumulator, multi-token §N-1; Poseidon-root form — see
    /// `tasks/h1-poseidon-root-threat-model.md`): the canonical `PoseidonHashOut → Bytes32`
    /// encoding of the FIXED-width 37-element Poseidon header [`Self::h1_header_preimage`],
    /// where `slot_tree_root` is the height-[`BALANCE_SLOT_TREE_HEIGHT`] Poseidon Merkle root
    /// over ALL `MAX_CHANNEL_MEMBERS` per-slot v2 leaves
    /// `balance_slot_leaf_hash(regev_pk_digests[i], ct_digests(enc_balances[i]),
    /// pending_adds[i], recipients[i])` (B-1b: the per-slot L1 exit address rides in the same
    /// cosigner-signed leaf).
    ///
    /// SECURITY: every value the v1 header bound remains bound — the per-slot data via the
    /// Merkle root (slot ORDER = Merkle position), the scalars via the header — and the header
    /// additionally binds `token_count` + the full `token_registry` (TM-9). The header and leaf
    /// encodings are injective (fixed width, canonical u32 limbs / canonical Goldilocks root
    /// elements, leading v2 domain constants).
    ///
    /// The in-circuit twin is `circuits::channel::h1_gadget::recompute_h1` (v2, migrated in
    /// multitoken Phase 2); parity is pinned by
    /// `h1_gadget::tests::recompute_h1_matches_native_balance_state_h1_randomized`.
    pub fn h1(&self) -> Bytes32 {
        Bytes32::from(PoseidonHashOut::hash_inputs_u64(&self.h1_header_preimage()))
    }

    /// Canonicality / budget check. MUST run on every balance state that crosses a trust
    /// boundary: each ciphertext must be canonical (otherwise its digest — and hence H1 — is
    /// malleable, F1-A) and every add counter must respect the D3 refresh budget. Also enforces
    /// the pad-to-MAX (D6) invariants (`2 <= member_count`, cosigner cap, padding slots
    /// default/empty) and the multi-token fail-closed invariants (TM-8/TM-13): `1 <= token_count
    /// <= MAX_CHANNEL_TOKENS`, registry injectivity over the active prefix, and — for EVERY slot
    /// — token positions `t >= token_count` equal to the canonical zero ciphertext with zero
    /// `pending_adds`, with ALL `MAX_CHANNEL_TOKENS` counters range-checked.
    pub fn validate(&self) -> Result<(), ChannelError> {
        // Fail-closed shape check: the in-memory token matrices must be full slot width (a
        // malformed snapshot must never reach the hashing paths, which assert the same).
        if self.enc_balances.len() != MAX_CHANNEL_MEMBERS
            || self.pending_adds.len() != MAX_CHANNEL_MEMBERS
        {
            return Err(ChannelError::InvalidBalanceState(format!(
                "enc_balances/pending_adds must have exactly MAX_CHANNEL_MEMBERS = \
                 {MAX_CHANNEL_MEMBERS} slot rows (got {} / {})",
                self.enc_balances.len(),
                self.pending_adds.len()
            )));
        }
        // TM-8: token_count bounds. token_count == 0 is invalid (a channel always has at least
        // its genesis token); token_count > MAX_CHANNEL_TOKENS would put "active" positions
        // outside the fixed-width leaf layout.
        let token_count = self.token_count as usize;
        if !(1..=MAX_CHANNEL_TOKENS).contains(&token_count) {
            return Err(ChannelError::InvalidBalanceState(format!(
                "token_count {token_count} out of range (must be 1..={MAX_CHANNEL_TOKENS})"
            )));
        }
        // TM-1 (defense in depth; the TokenRegister transition and the Phase 2 close circuit
        // enforce this at their own boundaries): the ACTIVE registry prefix must be injective on
        // base token_index — a duplicate would let one L1 escrow be counted twice. Inactive
        // positions must be zero-padded (canonical encoding; they are hashed into H1).
        for i in 0..token_count {
            for j in (i + 1)..token_count {
                if self.token_registry[i] == self.token_registry[j] {
                    return Err(ChannelError::InvalidBalanceState(format!(
                        "token_registry[{i}] == token_registry[{j}] == {} (active registry must \
                         be injective on base token_index, TM-1)",
                        self.token_registry[i]
                    )));
                }
            }
        }
        for (t, &index) in self.token_registry.iter().enumerate().skip(token_count) {
            if index != 0 {
                return Err(ChannelError::InvalidBalanceState(format!(
                    "token_registry[{t}] is an inactive position (>= token_count {token_count}) \
                     and must be zero-padded"
                )));
            }
        }
        // member_count = COSIGNERS (the N-of-N close signers), capped at MAX_SIG_CLUSTER — NOT the
        // balance-slot capacity MAX_CHANNEL_MEMBERS. Mirrors ChannelRecord::validate /
        // ChannelRegRecord::validate; the close/cancel circuits enforce the same cap in-circuit
        // via the MAX_SIG_CLUSTER-bit unary decomposition.
        let count = self.member_count as usize;
        if count < 2 || count > MAX_SIG_CLUSTER {
            return Err(ChannelError::InvalidBalanceState(format!(
                "member_count {count} out of range (must be 2..={MAX_SIG_CLUSTER} cosigners)"
            )));
        }
        // Delegate account regions: members occupy `0..member_count`, delegates occupy
        // `member_count..member_count+delegate_count`, padding occupies
        // `member_count+delegate_count..MAX`. Active = members + delegates. `delegate_count` may be
        // 0; `member_count + delegate_count` must not exceed MAX (no overflow / over-allocation).
        let delegate_count = self.delegate_count as usize;
        let active = count
            .checked_add(delegate_count)
            .filter(|&a| a <= MAX_CHANNEL_MEMBERS)
            .ok_or_else(|| {
                ChannelError::InvalidBalanceState(format!(
                    "member_count {count} + delegate_count {delegate_count} exceeds \
                     MAX_CHANNEL_MEMBERS = {MAX_CHANNEL_MEMBERS}"
                ))
            })?;
        for (index, row) in self.enc_balances.iter().enumerate() {
            for (t, ct) in row.iter().enumerate() {
                ct.validate().map_err(|err| {
                    ChannelError::InvalidBalanceState(format!(
                        "enc_balances[{index}][{t}] is not canonical: {err}"
                    ))
                })?;
                // Padding member slots MUST be all-zero across ALL token positions (D6 +
                // delegate account): a non-default padding slot would smuggle hidden value past
                // the active accounting. Active slots = members (`< member_count`) + delegates
                // (`member_count..member_count+delegate_count`). Padding = `>= active`.
                if index >= active && ct != zero_ciphertext() {
                    return Err(ChannelError::InvalidBalanceState(format!(
                        "enc_balances[{index}][{t}] is a padding slot (>= \
                         member_count+delegate_count {active}) and must be the canonical zero \
                         ciphertext"
                    )));
                }
                // TM-8 fail-closed per (slot, token): INACTIVE token positions (`t >=
                // token_count`) must be the canonical zero ciphertext on EVERY slot — the
                // zero-ct digest is the only value the active/unused token boundary admits, so
                // no hidden value can sit beyond the signed token_count.
                if t >= token_count && ct != zero_ciphertext() {
                    return Err(ChannelError::InvalidBalanceState(format!(
                        "enc_balances[{index}][{t}] is an inactive token position (>= \
                         token_count {token_count}) and must be the canonical zero ciphertext \
                         (TM-8)"
                    )));
                }
            }
        }
        // Decryption Stage 1: padding slots (`>= active`) must carry the default (zero) Regev pk
        // digest, mirroring the padding canonicality of `enc_balances`/`pending_adds`. A
        // non-default padding digest would be folded into H1 and could smuggle an
        // unregistered key past the active accounting. Active-slot digests are arbitrary
        // (the registered member pk digests).
        for (index, d) in self.regev_pk_digests.iter().enumerate() {
            if index >= active && *d != Bytes32::default() {
                return Err(ChannelError::InvalidBalanceState(format!(
                    "regev_pk_digests[{index}] is a padding slot (>= member_count+delegate_count \
                     {active}) and must be Bytes32::default()"
                )));
            }
        }
        // B-1b recipient split (fail-closed on BOTH sides):
        // - ACTIVE slots (`< member_count + delegate_count`) MUST carry a NONZERO recipient. Under
        //   Option B a delegate has NO L1 registration, so a zero recipient would make the slot
        //   permanently unexitable (the Manager cannot pay address(0)) — refuse at signing time,
        //   not at claim time.
        // - PADDING slots MUST carry the zero recipient, mirroring the ciphertext/pk-digest/adds
        //   padding canonicality: a nonzero padding recipient would smuggle routing data into H1
        //   past the active accounting.
        for (index, r) in self.recipients.iter().enumerate() {
            if index < active && *r == Address::default() {
                return Err(ChannelError::InvalidBalanceState(format!(
                    "recipients[{index}] is an ACTIVE slot (< member_count+delegate_count \
                     {active}) and must be a NONZERO L1 exit address (B-1b)"
                )));
            }
            if index >= active && *r != Address::default() {
                return Err(ChannelError::InvalidBalanceState(format!(
                    "recipients[{index}] is a padding slot (>= member_count+delegate_count \
                     {active}) and must be Address::default()"
                )));
            }
        }
        for (index, row) in self.pending_adds.iter().enumerate() {
            for (t, &adds) in row.iter().enumerate() {
                // TM-13: ALL MAX_CHANNEL_TOKENS counters are range-checked against the D3
                // refresh budget — active or not — so no position can silently accumulate past
                // the noise budget (which would make that (member, token) unexitable).
                if adds > MAX_HOMO_ADDS_BEFORE_REFRESH {
                    return Err(ChannelError::InvalidBalanceState(format!(
                        "pending_adds[{index}][{t}] = {adds} exceeds \
                         MAX_HOMO_ADDS_BEFORE_REFRESH = {MAX_HOMO_ADDS_BEFORE_REFRESH}"
                    )));
                }
                if index >= active && adds != 0 {
                    return Err(ChannelError::InvalidBalanceState(format!(
                        "pending_adds[{index}][{t}] is a padding slot (>= \
                         member_count+delegate_count {active}) and must be 0"
                    )));
                }
                // TM-8/TM-13 fail-closed per (slot, token): an inactive token position must
                // have a zero counter (a nonzero counter there would imply hidden adds beyond
                // the signed token_count).
                if t >= token_count && adds != 0 {
                    return Err(ChannelError::InvalidBalanceState(format!(
                        "pending_adds[{index}][{t}] is an inactive token position (>= \
                         token_count {token_count}) and must be 0 (TM-8/TM-13)"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Apply a cosigned `TokenRegister` transition (detail2 §N-1, TM-1): append `token_index` at
    /// position `token_count`, increment `token_count`, bump `state_version`. Balances, counters,
    /// pk digests, recipients, chain and accumulator are UNTOUCHED — registering a token is a
    /// header-only state change (all token positions exist from genesis as canonical zeros).
    ///
    /// SECURITY (TM-1): fail-closed checks BEFORE mutating — capacity (`token_count <
    /// MAX_CHANNEL_TOKENS`) and injectivity (`token_index` not already in the active registry
    /// prefix; a duplicate base index would let one L1 escrow back two local slots). Append-only
    /// at the current `token_count` is structural (this is the only registry-writing path, and
    /// it writes exactly at `token_count`); cross-state verification of a proposed transition is
    /// [`Self::verify_token_register_transition`].
    pub fn apply_token_register(&mut self, token_index: u32) -> Result<(), ChannelError> {
        let count = self.token_count as usize;
        if count >= MAX_CHANNEL_TOKENS {
            return Err(ChannelError::InvalidBalanceState(format!(
                "TokenRegister: registry full (token_count {count} == MAX_CHANNEL_TOKENS = \
                 {MAX_CHANNEL_TOKENS})"
            )));
        }
        if self.token_registry[..count].contains(&token_index) {
            return Err(ChannelError::InvalidBalanceState(format!(
                "TokenRegister: base token_index {token_index} already registered (active \
                 registry must stay injective, TM-1)"
            )));
        }
        self.token_registry[count] = token_index;
        self.token_count += 1;
        self.state_version += 1;
        Ok(())
    }

    /// Verify that `next` is EXACTLY `prev` + one `TokenRegister(token_index)` transition
    /// (detail2 §N-1, TM-1) — the cosigner-side check before signing a proposed registration:
    /// append-at-`prev.token_count` only, `token_count + 1`, injectivity of the new index
    /// against the active prefix, `state_version + 1`, and EVERYTHING ELSE (balances, counters,
    /// pk digests, recipients, member/delegate counts, chain, accumulator, channel id) untouched.
    pub fn verify_token_register_transition(
        prev: &Self,
        next: &Self,
        token_index: u32,
    ) -> Result<(), ChannelError> {
        // Recompute the expected post-state from prev; a single equality then covers ALL fields
        // (any balance/counter/registry/header divergence — including a registry write at the
        // wrong position or a reorder — makes the recompute differ).
        let mut expected = prev.clone();
        expected.apply_token_register(token_index)?;
        if *next != expected {
            return Err(ChannelError::InvalidBalanceState(
                "TokenRegister: next state is not prev + append(token_index) (registry must be \
                 append-only at token_count with balances untouched, TM-1)"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// The FIXED-width v2 balance-slot leaf preimage (detail2 §N-2; 104 u32 elements). Exposed so
/// the width/layout golden tests pin it exactly.
///
/// DEVIATION (flagged, multitoken Phase 1): detail2 §N-2 states "103 elems" counting
/// `recipient` as 4 elements, but the canonical `Address` encoding this repo uses everywhere
/// (20 bytes = FIVE canonical u32 limbs, unchanged since the D14 18→23 leaf) is 5 limbs, and
/// re-packing it into 4 limbs would bit-pack two limbs into one word — exactly what TM-15
/// forbids. The correct fixed width is therefore 1 + 8 + 80 + 10 + 5 = 104; the §N-2 "103" is
/// an arithmetic slip (its own "(was 23)" baseline already counts the recipient as 5).
pub fn balance_slot_leaf_preimage(
    regev_pk_digest: Bytes32,
    enc_balance_digests: &[Bytes32; MAX_CHANNEL_TOKENS],
    pending_adds: &[u32; MAX_CHANNEL_TOKENS],
    recipient: Address,
) -> Vec<u32> {
    let mut inputs = vec![BALANCE_SLOT_LEAF_DOMAIN_V2];
    inputs.extend(regev_pk_digest.to_u32_vec());
    for digest in enc_balance_digests {
        inputs.extend(digest.to_u32_vec());
    }
    inputs.extend_from_slice(pending_adds);
    inputs.extend(recipient.to_u32_vec());
    inputs
}

/// The per-slot v2 leaf of the H1 balance-slot Poseidon Merkle tree (member slot order; the leaf
/// INDEX is the Merkle position, so slot order is bound structurally):
///
/// `leaf_i = Poseidon([BALANCE_SLOT_LEAF_DOMAIN_V2, regev_pk_digest (8 u32 limbs),
///                     enc_balance_digest[0..10] (80 u32 limbs, one 8-limb keccak digest per
///                     token slot), pending_adds[0..10] (10 u32 limbs), recipient (5 u32
///                     limbs)])`
///
/// SECURITY: FIXED 104-element width with a leading v2 domain constant and canonical u32
/// payload limbs — injective on the `(regev_pk_digest, ct digests[10], pending_adds[10],
/// recipient)` tuple. The fixed-width discipline of the H1 threat model (T2/T3/T4,
/// tasks/h1-poseidon-root-threat-model.md) is preserved: the leaf width changes 23 → 104 for
/// ALL leaves simultaneously (padding included, TM-9/TM-15), so no variable-length ambiguity
/// and no cross-width aliasing against the 8-element node or 37-element header hashes is
/// introduced. Unused token positions carry [`zero_ciphertext_digest`] (TM-8; `validate()`
/// fail-closes them).
///
/// SECURITY (B-1b recipient binding): `recipient` is the slot's L1 exit address. Hashing it here
/// puts it under the cosigner N-of-N signatures via the slot-tree root inside H1 — the ONLY
/// binding that prevents payout redirection for delegates, which have no L1 registration under
/// Option B.
///
/// The in-circuit twin is `circuits::channel::h1_gadget::balance_slot_leaf_hash_circuit` (v2,
/// migrated in multitoken Phase 2, full 104-element width); the claim circuits layer the TM-2
/// one-hot token select on top of it.
pub fn balance_slot_leaf_hash(
    regev_pk_digest: Bytes32,
    enc_balance_digests: &[Bytes32; MAX_CHANNEL_TOKENS],
    pending_adds: &[u32; MAX_CHANNEL_TOKENS],
    recipient: Address,
) -> PoseidonHashOut {
    PoseidonHashOut::hash_inputs_u32(&balance_slot_leaf_preimage(
        regev_pk_digest,
        enc_balance_digests,
        pending_adds,
        recipient,
    ))
}

/// abstract2 §3.1 signing target: `balanceStateHash = hash(H1, H2)`.
///
/// NOTE: in this implementation the member signatures normally go over
/// `ChannelState::signing_digest()`, which internalizes `hash(H1, H2)` (detail2 §C-3/§D); this
/// standalone helper exists for components that bind H1/H2 directly.
pub fn balance_state_hash(h1: Bytes32, h2: Bytes32) -> Bytes32 {
    hash_words(
        &[
            vec![BALANCE_STATE_HASH_DOMAIN],
            h1.to_u32_vec(),
            h2.to_u32_vec(),
        ]
        .concat(),
    )
}

/// detail2 §C-6 `TxLeafHash`:
/// `hash( hash([TX_LEAF_DOMAIN, source_pubkey_hash(8), sender_delta_digest]),
///        hash([TX_LEAF_DOMAIN, receiver_pubkey_hash(8), receiver_delta_digest]) )`.
///
/// SECURITY: both wings carry the member SPHINCS+ pubkey hash AND the Regev delta-ciphertext
/// digest, so the chain leaf binds the sending member, the receiving member and both hidden
/// balance deltas. The leaf is computable at small-block signing time (flowSend1 step 6) — unlike
/// the base-layer nullifier, which embeds the (then unknown) block number.
pub fn tx_leaf_hash(
    source_pk_g: Bytes32,
    sender_delta_digest: Bytes32,
    receiver_pk_g: Bytes32,
    receiver_delta_digest: Bytes32,
) -> Bytes32 {
    let sender_wing = hash_words(
        &[
            vec![TX_LEAF_DOMAIN],
            source_pk_g.to_u32_vec(),
            sender_delta_digest.to_u32_vec(),
        ]
        .concat(),
    );
    let receiver_wing = hash_words(
        &[
            vec![TX_LEAF_DOMAIN],
            receiver_pk_g.to_u32_vec(),
            receiver_delta_digest.to_u32_vec(),
        ]
        .concat(),
    );
    hash_words(&[sender_wing.to_u32_vec(), receiver_wing.to_u32_vec()].concat())
}

/// detail2 §C-6 chain update: `chain' = keccak([SETTLED_TX_CHAIN_DOMAIN, chain, leaf])`.
/// Used with `leaf = tx_leaf_hash(…)` for inter-channel settles and `leaf = deposit hash` for
/// deposit/fund imports. In-channel transfers leave the chain unchanged.
pub fn settled_tx_chain_push(chain: Bytes32, leaf: Bytes32) -> Bytes32 {
    hash_words(
        &[
            vec![SETTLED_TX_CHAIN_DOMAIN],
            chain.to_u32_vec(),
            leaf.to_u32_vec(),
        ]
        .concat(),
    )
}

/// In-circuit twin of [`settled_tx_chain_push`] (detail2 §C-6/§F-1):
/// `chain' = keccak256([SETTLED_TX_CHAIN_DOMAIN, chain limbs, leaf limbs])` over solidity-packed
/// u32 words, mirroring the off-chain limb order exactly.
///
/// SECURITY: the preimage layout (domain constant, then the 8 chain limbs, then the 8 leaf limbs)
/// MUST stay byte-identical to `hash_words` in [`settled_tx_chain_push`]; any divergence makes
/// every in-circuit chain PI disagree with the signed off-chain `BalanceState.settled_tx_chain`.
/// Inputs must already be constrained to 32-bit limbs by the caller (the keccak gadget does not
/// range-check its inputs).
pub fn settled_tx_chain_push_circuit<F, C, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    chain: Bytes32Target,
    leaf: Bytes32Target,
) -> Bytes32Target
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let domain = builder.constant(F::from_canonical_u32(SETTLED_TX_CHAIN_DOMAIN));
    let inputs = [vec![domain], chain.to_vec(), leaf.to_vec()].concat();
    Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regev::{REGEV_N, REGEV_Q};

    /// Deterministic canonical ciphertext (raw seed-derived coefficients < q). These are not
    /// decryptable — digest/H1 tests only need canonical, distinct ring elements.
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

    /// A distinct NONZERO L1 recipient per seed (validate() rejects zero active recipients).
    fn recipient(seed: u32) -> Address {
        Address::from_u32_slice(&[seed + 1, seed + 2, seed + 3, seed + 4, seed + 5]).unwrap()
    }

    fn sample_state() -> BalanceState {
        BalanceState {
            channel_id: ChannelId::new(7).unwrap(),
            member_count: 3,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances_token0(&[
                ciphertext(1),
                ciphertext(2),
                ciphertext(3),
            ]),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
            recipients: BalanceState::pad_recipients(&[recipient(1), recipient(2), recipient(3)]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
            state_version: 5,
            pending_adds: BalanceState::pad_pending_adds_token0(&[0, 1, 2]),
            token_registry: BalanceState::single_token_registry(0),
            token_count: 1,
        }
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

    #[test]
    fn h1_is_deterministic_and_sensitive_to_every_field() {
        let base = sample_state();
        let h1 = base.h1();
        assert_eq!(h1, sample_state().h1(), "h1 must be deterministic");

        let mut s = sample_state();
        s.channel_id = ChannelId::new(8).unwrap();
        assert_ne!(h1, s.h1(), "channel_id must affect h1");

        // member_count is part of the H1 preimage (D6): changing it must change H1.
        let mut s = sample_state();
        s.member_count = 4;
        assert_ne!(h1, s.h1(), "member_count must affect h1");

        for slot in 0..sample_state().member_count as usize {
            let mut s = sample_state();
            s.enc_balances[slot][0] = ciphertext(99 + slot as u32);
            assert_ne!(h1, s.h1(), "enc_balances[{slot}][0] must affect h1");
        }

        let mut s = sample_state();
        s.settled_tx_chain = Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(h1, s.h1(), "settled_tx_chain must affect h1");

        // Stage 3: the accumulator root is part of the H1 preimage (signed) and distinct from the
        // chain — flipping it (while leaving the chain unchanged) must change H1.
        let mut s = sample_state();
        s.settled_tx_accumulator_root = Bytes32::from_u32_slice(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(
            h1,
            s.h1(),
            "settled_tx_accumulator_root must affect h1 (Stage 3)"
        );

        let mut s = sample_state();
        s.state_version += 1;
        assert_ne!(h1, s.h1(), "state_version must affect h1");

        for slot in 0..sample_state().member_count as usize {
            let mut s = sample_state();
            s.pending_adds[slot][0] += 1;
            assert_ne!(h1, s.h1(), "pending_adds[{slot}][0] must affect h1 (D3)");
        }

        // B-1b: each ACTIVE slot's L1 exit address rides in that slot's leaf — flipping it must
        // flip H1 (this is the whole recipient-redirection defense for delegates).
        for slot in 0..sample_state().member_count as usize {
            let mut s = sample_state();
            s.recipients[slot] = recipient(900 + slot as u32);
            assert_ne!(h1, s.h1(), "recipients[{slot}] must affect h1 (B-1b)");
        }
    }

    /// Build a `BalanceState` with `count` ACTIVE members (distinct canonical ciphertexts in
    /// slots 0..count, padding = `RegevCiphertext::padding()`) for multi-N coverage below.
    fn state_with_members(count: u8) -> BalanceState {
        let active: Vec<RegevCiphertext> = (0..count as u32).map(|i| ciphertext(1 + i)).collect();
        let recipients: Vec<Address> = (0..count as u32).map(|i| recipient(1 + i)).collect();
        BalanceState {
            channel_id: ChannelId::new(7).unwrap(),
            member_count: count,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances_token0(&active),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
            recipients: BalanceState::pad_recipients(&recipients),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
            state_version: 5,
            pending_adds: BalanceState::pad_pending_adds_token0(&vec![0u32; count as usize]),
            token_registry: BalanceState::single_token_registry(0),
            token_count: 1,
        }
    }

    /// Multi-N (D6 pad-to-MAX): `BalanceState::validate()` ACCEPTS member_count = 2 / 8 / 16 with
    /// canonical active ciphertexts + `RegevCiphertext::padding()` padding, and REJECTS the D6
    /// boundary violations (out-of-range count, nonzero padding slot, nonzero padding add-counter).
    #[test]
    fn balance_state_validate_multi_n() {
        for count in [2u8, 8, 16] {
            state_with_members(count)
                .validate()
                .unwrap_or_else(|e| panic!("member_count {count} must validate: {e}"));
        }

        // member_count < 2 rejected.
        let mut too_few = state_with_members(2);
        too_few.member_count = 1;
        assert!(matches!(
            too_few.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // member_count > MAX_SIG_CLUSTER rejected (cosigner cap, NOT the 1024 balance-slot
        // capacity — the old `(MAX_CHANNEL_MEMBERS + 1) as u8` truncated to 1 at MAX=1024 and
        // passed for the wrong reason).
        let mut too_many = state_with_members(16);
        too_many.member_count = (MAX_SIG_CLUSTER + 1) as u8;
        assert!(matches!(
            too_many.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // A non-default (nonzero) PADDING ciphertext slot is rejected (would smuggle hidden value).
        let mut nonzero_pad = state_with_members(8);
        nonzero_pad.enc_balances[8][0] = ciphertext(99);
        assert!(matches!(
            nonzero_pad.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // A nonzero PADDING add-counter is rejected.
        let mut nonzero_add = state_with_members(8);
        nonzero_add.pending_adds[8][0] = 1;
        assert!(matches!(
            nonzero_add.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // B-1b fail-closed: a ZERO recipient in an ACTIVE slot is rejected (the slot could never
        // exit on L1 — refuse at signing time).
        let mut zero_active_recipient = state_with_members(8);
        zero_active_recipient.recipients[3] = Address::default();
        assert!(matches!(
            zero_active_recipient.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // B-1b fail-closed: a NONZERO recipient in a PADDING slot is rejected (routing smuggling
        // past the active accounting).
        let mut nonzero_pad_recipient = state_with_members(8);
        nonzero_pad_recipient.recipients[8] = recipient(99);
        assert!(matches!(
            nonzero_pad_recipient.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));
    }

    /// Delegate account (Phase 1): `delegate_count` is part of the H1 preimage AND drives the
    /// active/padding region split. A state with delegates in `member_count..member_count+
    /// delegate_count` (active ciphertexts) validates; padding only begins at
    /// `member_count+delegate_count`. `member_count + delegate_count > MAX` is rejected, and a
    /// nonzero slot inside the would-be padding region (but now a delegate slot) is accepted.
    #[test]
    fn balance_state_delegate_count_regions_and_h1() {
        // Base: member_count = 3, delegate_count = 0.
        let base = state_with_members(3);
        let base_h1 = base.h1();

        // delegate_count is in the H1 preimage: bumping it (with a matching active delegate slot)
        // changes H1.
        let mut with_delegate = state_with_members(3);
        with_delegate.delegate_count = 2;
        with_delegate.enc_balances[3][0] = ciphertext(100);
        with_delegate.enc_balances[4][0] = ciphertext(101);
        with_delegate.recipients[3] = recipient(100);
        with_delegate.recipients[4] = recipient(101);
        assert_ne!(base_h1, with_delegate.h1(), "delegate_count must affect h1");
        with_delegate
            .validate()
            .expect("members + delegates + padding must validate");

        // The cosigner cap binds: member_count > MAX_SIG_CLUSTER is rejected even with delegates.
        let mut overflow = state_with_members(16);
        overflow.member_count = (MAX_SIG_CLUSTER + 1) as u8;
        overflow.delegate_count = 1;
        assert!(
            matches!(
                overflow.validate(),
                Err(ChannelError::InvalidBalanceState(_))
            ),
            "member_count > MAX_SIG_CLUSTER must be rejected"
        );
        // Slot-capacity check: with u16 delegate_count (2026-07-18 slot widening) the
        // `member_count + delegate_count > MAX_CHANNEL_MEMBERS` boundary is now REACHABLE
        // (it was dead code with u8 counts: 16 + 255 = 271 < 1024). Exercise it.
        let mut over_capacity = state_with_members(16);
        over_capacity.delegate_count = (MAX_CHANNEL_MEMBERS - MAX_SIG_CLUSTER + 1) as u16;
        assert!(
            matches!(
                over_capacity.validate(),
                Err(ChannelError::InvalidBalanceState(_))
            ),
            "member_count + delegate_count > MAX_CHANNEL_MEMBERS must be rejected"
        );
        // 16 cosigners + 1 active delegate is well within the 1024 balance slots and must
        // validate (the delegate slot 16 carries an active ciphertext).
        let mut full_members = state_with_members(16);
        full_members.delegate_count = 1;
        full_members.enc_balances[16][0] = ciphertext(60);
        full_members.recipients[16] = recipient(60);
        full_members
            .validate()
            .expect("16 cosigners + 1 active delegate must validate at MAX=1024 slots");

        // A slot inside the delegate region must be ACTIVE (non-padding): if a declared delegate
        // slot is left as padding it is fine (padding ct is canonical), but a slot BEYOND
        // member_count+delegate_count that is non-default is rejected.
        let mut bad_pad = state_with_members(3);
        bad_pad.delegate_count = 1; // active region = 0..4
        bad_pad.enc_balances[3][0] = ciphertext(50); // the single delegate slot
        bad_pad.recipients[3] = recipient(50);
        bad_pad.enc_balances[5][0] = ciphertext(51); // a padding slot (>= 4) — must be rejected
        assert!(
            matches!(
                bad_pad.validate(),
                Err(ChannelError::InvalidBalanceState(_))
            ),
            "non-default slot in the padding region (>= member_count+delegate_count) is rejected"
        );

        // The delegate region shifts the H1-committed split: same ciphertexts, different
        // member/delegate boundary => different H1.
        let mut split_a = state_with_members(2);
        split_a.delegate_count = 2;
        for s in 0..4u32 {
            split_a.enc_balances[s as usize][0] = ciphertext(200 + s);
            split_a.recipients[s as usize] = recipient(200 + s);
        }
        let mut split_b = split_a.clone();
        split_b.member_count = 3;
        split_b.delegate_count = 1; // same active span (4) but different member/delegate boundary
        assert_ne!(
            split_a.h1(),
            split_b.h1(),
            "moving the member/delegate boundary must change H1"
        );
    }

    /// `BalanceState::h1()` binds `member_count`: two states identical except for `member_count`
    /// (active prefix repadded to match) produce DIFFERENT H1 digests across the supported range.
    /// Proves member_count is genuinely part of the H1 preimage (D6), so the active/padding split
    /// cannot be silently reinterpreted under the all-member signatures.
    #[test]
    fn h1_binds_member_count_multi_n() {
        // Cosigner range 2..=MAX_SIG_CLUSTER (the old `..MAX_CHANNEL_MEMBERS as u8` became an EMPTY
        // range at MAX=1024 — `1024 as u8 == 0` — silently testing nothing).
        for count in 2u8..MAX_SIG_CLUSTER as u8 {
            assert_ne!(
                state_with_members(count).h1(),
                state_with_members(count + 1).h1(),
                "member_count {count} vs {} must change h1",
                count + 1
            );
        }
    }

    /// H1 Poseidon-root form: the fast bottom-up `slot_tree_root()` fold MUST equal the
    /// `IncrementalMerkleTree` root the claim witness builders prove inclusion against — if the
    /// two ever diverge, every claim inclusion proof would disagree with the signed H1 header.
    /// Also proves the padding-leaf memoization is a pure memoization (padding slots hash to the
    /// same leaf as a per-slot recompute) and that ACTIVE slot leaf data flips the root.
    #[test]
    fn slot_tree_root_matches_incremental_tree() {
        let state = sample_state();
        assert_eq!(
            state.slot_tree_root(),
            state.slot_tree().get_root(),
            "fold root must equal the IncrementalMerkleTree root"
        );

        // Explicit per-slot recompute (no padding memoization) — same leaves, same root.
        let naive: Vec<PoseidonHashOut> = (0..MAX_CHANNEL_MEMBERS)
            .map(|i| {
                // Per-position recompute WITHOUT the zero-ct digest memoization.
                let digests: [Bytes32; MAX_CHANNEL_TOKENS] =
                    std::array::from_fn(|t| state.enc_balances[i][t].digest());
                balance_slot_leaf_hash(
                    state.regev_pk_digests[i],
                    &digests,
                    &state.pending_adds[i],
                    state.recipients[i],
                )
            })
            .collect();
        assert_eq!(state.slot_leaf_hashes(), naive);

        // A pk digest / add-counter change in an ACTIVE slot flips the root (leaf binding).
        let mut s = sample_state();
        s.regev_pk_digests[1] = Bytes32::from_u32_slice(&[5, 0, 0, 0, 0, 0, 0, 1]).unwrap();
        assert_ne!(state.slot_tree_root(), s.slot_tree_root());
        assert_eq!(s.slot_tree_root(), s.slot_tree().get_root());
    }

    /// The new H1 is the CANONICAL `PoseidonHashOut → Bytes32` encoding of the header hash —
    /// it must round-trip through the canonical decode (the same property the claim circuits'
    /// `to_hash_out` round-trip check enforces for the accumulator root).
    #[test]
    fn h1_is_canonical_poseidon_bytes32_encoding() {
        let h1 = sample_state().h1();
        let decoded: PoseidonHashOut = h1
            .try_into()
            .expect("H1 must be a canonical Poseidon->Bytes32 encoding");
        assert_eq!(Bytes32::from(decoded), h1);
    }

    /// A distinct token-digest row per seed: position t carries pubkey_hash(seed + t).
    fn digest_row(seed: u32) -> [Bytes32; MAX_CHANNEL_TOKENS] {
        std::array::from_fn(|t| pubkey_hash(seed + t as u32 * 8))
    }

    /// Leaf-encoding injectivity (v2, 104 elems): each component of the slot leaf tuple is
    /// binding PER TOKEN POSITION, and the leaf carries its own domain constant. B-1b: the
    /// recipient (the slot's L1 exit address) is a binding component — an attacker cannot open
    /// the same leaf under a different payout address. TM-2 relevance: a change at ANY of the 10
    /// ciphertext-digest or pending-adds positions flips the leaf, which is what makes the
    /// "other 9 positions unchanged" obligation checkable against H1.
    #[test]
    fn balance_slot_leaf_hash_binds_every_component() {
        let pk = pubkey_hash(1);
        let digests = digest_row(100);
        let adds = [3u32; MAX_CHANNEL_TOKENS];
        let r = recipient(7);
        let leaf = balance_slot_leaf_hash(pk, &digests, &adds, r);
        assert_eq!(leaf, balance_slot_leaf_hash(pk, &digests, &adds, r));
        assert_ne!(
            leaf,
            balance_slot_leaf_hash(pubkey_hash(2), &digests, &adds, r)
        );
        // EVERY token position of the ct-digest vector and the adds vector is binding.
        for t in 0..MAX_CHANNEL_TOKENS {
            let mut tampered = digests;
            tampered[t] = pubkey_hash(900 + t as u32);
            assert_ne!(
                leaf,
                balance_slot_leaf_hash(pk, &tampered, &adds, r),
                "ct digest position {t} must be binding"
            );
            let mut tampered = adds;
            tampered[t] += 1;
            assert_ne!(
                leaf,
                balance_slot_leaf_hash(pk, &digests, &tampered, r),
                "pending_adds position {t} must be binding"
            );
        }
        // Swapping two token positions must change the leaf (position = token slot binding).
        let mut swapped = digests;
        swapped.swap(0, 5);
        assert_ne!(leaf, balance_slot_leaf_hash(pk, &swapped, &adds, r));
        // B-1b: flipping the recipient must flip the leaf (payout-redirection defense).
        assert_ne!(
            leaf,
            balance_slot_leaf_hash(pk, &digests, &adds, recipient(8))
        );
        assert_ne!(
            leaf,
            balance_slot_leaf_hash(pk, &digests, &adds, Address::default())
        );
    }

    #[test]
    fn validate_enforces_canonicality_and_add_budget() {
        sample_state().validate().unwrap();

        let mut s = sample_state();
        s.enc_balances[1][0].c1[0] = REGEV_Q; // non-canonical
        assert!(matches!(
            s.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        let mut s = sample_state();
        s.pending_adds[2][0] = MAX_HOMO_ADDS_BEFORE_REFRESH;
        s.validate().unwrap(); // at the bound is still representable…
        s.pending_adds[2][0] = MAX_HOMO_ADDS_BEFORE_REFRESH + 1;
        assert!(matches!(
            s.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        )); // …above it is not.
    }

    /// Golden vector pinning the chain-push preimage layout `[IMTC, chain, leaf]` over
    /// solidity-packed keccak. If this changes, every signed settled_tx_chain changes.
    #[test]
    fn settled_tx_chain_push_golden_vector() {
        let chain = Bytes32::default();
        let leaf = Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let pushed = settled_tx_chain_push(chain, leaf);
        assert_eq!(
            pushed.to_string(),
            "0xb6b0dc5967d87831d967413a5ce4e960d9a69f584d1d898f4abc25437925471a"
        );
        // Chaining is order-sensitive: push(push(0, a), b) != push(push(0, b), a).
        let other = Bytes32::from_u32_slice(&[8, 7, 6, 5, 4, 3, 2, 1]).unwrap();
        assert_ne!(
            settled_tx_chain_push(pushed, other),
            settled_tx_chain_push(settled_tx_chain_push(chain, other), leaf)
        );
    }

    /// Proves the in-circuit chain push is byte-identical to the off-chain fold for random
    /// inputs. This is the soundness anchor for the balance-circuit `settled_tx_chain` PI: if
    /// the two ever diverge, signed `BalanceState.settled_tx_chain` values would no longer match
    /// any provable balance proof PI (detail2 §F-1 equality check).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn settled_tx_chain_push_circuit_matches_off_chain() {
        use plonky2::{
            field::goldilocks_field::GoldilocksField,
            iop::witness::PartialWitness,
            plonk::{
                circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
                config::PoseidonGoldilocksConfig,
            },
        };

        use crate::ethereum_types::u32limb_trait::U32LimbTargetTrait as _;

        const D: usize = 2;
        type F = GoldilocksField;
        type C = PoseidonGoldilocksConfig;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let chain_t = Bytes32Target::new(&mut builder, true);
        let leaf_t = Bytes32Target::new(&mut builder, true);
        let pushed_t = settled_tx_chain_push_circuit::<F, C, D>(&mut builder, chain_t, leaf_t);
        builder.register_public_inputs(&pushed_t.to_vec());
        let data = builder.build::<C>();

        let mut rng = rand::thread_rng();
        for _ in 0..3 {
            let chain = Bytes32::rand(&mut rng);
            let leaf = Bytes32::rand(&mut rng);
            let expected = settled_tx_chain_push(chain, leaf);

            let mut pw = PartialWitness::<F>::new();
            chain_t.set_witness(&mut pw, chain);
            leaf_t.set_witness(&mut pw, leaf);
            let proof = data.prove(pw).expect("chain push circuit proof");
            data.verify(proof.clone()).expect("chain push verification");

            let actual_limbs = proof
                .public_inputs
                .iter()
                .map(|x| {
                    u32::try_from(plonky2::field::types::PrimeField64::to_canonical_u64(x))
                        .expect("PI limb must be u32")
                })
                .collect::<Vec<_>>();
            let actual = Bytes32::from_u32_slice(&actual_limbs).unwrap();
            assert_eq!(actual, expected, "circuit chain push must match off-chain");
        }
    }

    #[test]
    fn tx_leaf_hash_is_wing_order_sensitive() {
        let sender = pubkey_hash(10);
        let receiver = pubkey_hash(21);
        let d_send = ciphertext(11).digest();
        let d_recv = ciphertext(12).digest();

        let leaf = tx_leaf_hash(sender, d_send, receiver, d_recv);
        assert_eq!(leaf, tx_leaf_hash(sender, d_send, receiver, d_recv));
        // Swapping the wings (who sends / who receives) must change the leaf.
        assert_ne!(leaf, tx_leaf_hash(receiver, d_recv, sender, d_send));
        // Each component is binding.
        assert_ne!(
            leaf,
            tx_leaf_hash(pubkey_hash(11), d_send, receiver, d_recv)
        );
        assert_ne!(leaf, tx_leaf_hash(sender, d_recv, receiver, d_recv));
        assert_ne!(leaf, tx_leaf_hash(sender, d_send, pubkey_hash(22), d_recv));
        assert_ne!(leaf, tx_leaf_hash(sender, d_send, receiver, d_send));
    }

    #[test]
    fn balance_state_hash_binds_both_halves() {
        let h1 = sample_state().h1();
        let h2 = Bytes32::from_u32_slice(&[3, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let bound = balance_state_hash(h1, h2);
        assert_ne!(bound, balance_state_hash(h1, Bytes32::default()));
        assert_ne!(bound, balance_state_hash(Bytes32::default(), h2));
        assert_ne!(bound, balance_state_hash(h2, h1));
    }

    /// The canonical zero-ciphertext digest constant equals a fresh
    /// `RegevCiphertext::padding().digest()` recompute (TM-8: the memoization is pure).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn zero_ciphertext_digest_matches_padding_digest() {
        assert_eq!(
            zero_ciphertext_digest(),
            RegevCiphertext::padding().digest()
        );
        assert_eq!(zero_ciphertext(), &RegevCiphertext::padding());
    }

    /// GOLDEN (detail2 §N-2, TM-15): the v2 balance-slot leaf preimage is EXACTLY 104 u32
    /// elements — [IMS2(1), regev_pk_digest(8), ct_digest[0..10](80), pending_adds[0..10](10),
    /// recipient(5)] — with every field at its documented offset. If this changes, every signed
    /// H1 changes. (§N-2's "103" figure counts the recipient as 4 limbs; the canonical Address
    /// encoding is 5 limbs — see the flagged deviation note on `balance_slot_leaf_preimage`.)
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn balance_slot_leaf_preimage_width_and_layout_golden() {
        let pk = pubkey_hash(1);
        let digests = digest_row(100);
        let adds: [u32; MAX_CHANNEL_TOKENS] = std::array::from_fn(|t| 40 + t as u32);
        let r = recipient(7);
        let preimage = balance_slot_leaf_preimage(pk, &digests, &adds, r);
        assert_eq!(preimage.len(), 104, "v2 leaf preimage must be 104 elements");
        assert_eq!(preimage[0], BALANCE_SLOT_LEAF_DOMAIN_V2);
        assert_eq!(preimage[0], u32::from_be_bytes(*b"IMS2"));
        assert_eq!(&preimage[1..9], pk.to_u32_vec().as_slice());
        for t in 0..MAX_CHANNEL_TOKENS {
            assert_eq!(
                &preimage[9 + 8 * t..9 + 8 * (t + 1)],
                digests[t].to_u32_vec().as_slice(),
                "ct digest {t} offset"
            );
        }
        assert_eq!(&preimage[89..99], &adds);
        assert_eq!(&preimage[99..104], r.to_u32_vec().as_slice());
        // The hash is exactly the Poseidon of this preimage.
        assert_eq!(
            balance_slot_leaf_hash(pk, &digests, &adds, r),
            PoseidonHashOut::hash_inputs_u32(&preimage)
        );
    }

    /// GOLDEN (detail2 §N-1, TM-9/TM-15): the v2 H1 header preimage is EXACTLY 37 elements —
    /// [IMB2, channel_id, member_count, delegate_count, token_count, token_registry(10),
    /// slot_tree_root(4), settled_tx_chain(8), settled_tx_accumulator_root(8),
    /// state_version(2)] — with every field at its documented offset.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn h1_header_preimage_width_and_layout_golden() {
        let mut state = sample_state();
        state.token_registry = BalanceState::single_token_registry(0);
        state.token_registry[1] = 77;
        state.token_count = 2;
        let header = state.h1_header_preimage();
        assert_eq!(header.len(), 37, "v2 H1 header must be 37 elements");
        assert_eq!(header[0], BALANCE_STATE_DOMAIN_V2 as u64);
        assert_eq!(header[0], u32::from_be_bytes(*b"IMB2") as u64);
        assert_eq!(header[1], state.channel_id.to_u32_vec()[0] as u64);
        assert_eq!(header[2], state.member_count as u64);
        assert_eq!(header[3], state.delegate_count as u64);
        assert_eq!(header[4], state.token_count as u64);
        for t in 0..MAX_CHANNEL_TOKENS {
            assert_eq!(
                header[5 + t],
                state.token_registry[t] as u64,
                "registry {t}"
            );
        }
        assert_eq!(&header[15..19], &state.slot_tree_root().elements);
        let chain: Vec<u64> = state
            .settled_tx_chain
            .to_u32_vec()
            .iter()
            .map(|&w| w as u64)
            .collect();
        assert_eq!(&header[19..27], chain.as_slice());
        let acc: Vec<u64> = state
            .settled_tx_accumulator_root
            .to_u32_vec()
            .iter()
            .map(|&w| w as u64)
            .collect();
        assert_eq!(&header[27..35], acc.as_slice());
        assert_eq!(header[35], state.state_version >> 32);
        assert_eq!(header[36], state.state_version & 0xffff_ffff);
        assert_eq!(
            state.h1(),
            Bytes32::from(PoseidonHashOut::hash_inputs_u64(&header))
        );
    }

    /// TM-9: `token_count` and EVERY `token_registry` position are part of the signed H1 header —
    /// flipping any of them (balances untouched) must change H1, so the local-slot -> base-token
    /// mapping cannot be reinterpreted under existing signatures.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn h1_binds_token_registry_and_count() {
        let base = sample_state();
        let h1 = base.h1();

        let mut s = sample_state();
        s.token_count = 2;
        assert_ne!(h1, s.h1(), "token_count must affect h1");

        for t in 0..MAX_CHANNEL_TOKENS {
            let mut s = sample_state();
            s.token_registry[t] = 500 + t as u32;
            assert_ne!(h1, s.h1(), "token_registry[{t}] must affect h1");
        }
    }

    /// TM-8/TM-13 fail-closed `validate()` negatives, per (slot, token):
    /// - token_count 0 and MAX_CHANNEL_TOKENS+1 rejected;
    /// - a nonzero ciphertext at an INACTIVE token position (t >= token_count) rejected;
    /// - a nonzero pending_adds at an inactive position rejected;
    /// - a counter > MAX_HOMO_ADDS_BEFORE_REFRESH at ANY of the 10 positions rejected;
    /// - a duplicate ACTIVE registry index rejected; a nonzero INACTIVE registry limb rejected.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn validate_token_dimension_fail_closed() {
        // token_count bounds.
        let mut zero_count = sample_state();
        zero_count.token_count = 0;
        assert!(matches!(
            zero_count.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));
        let mut over_count = sample_state();
        over_count.token_count = (MAX_CHANNEL_TOKENS + 1) as u8;
        assert!(matches!(
            over_count.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // Nonzero ciphertext at an inactive token position of an ACTIVE slot (token_count = 1,
        // position 3): hidden value beyond the signed token boundary must be rejected.
        let mut smuggled_ct = sample_state();
        smuggled_ct.enc_balances[1][3] = ciphertext(99);
        assert!(matches!(
            smuggled_ct.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // Nonzero pending_adds at an inactive token position of an active slot.
        let mut smuggled_adds = sample_state();
        smuggled_adds.pending_adds[1][3] = 1;
        assert!(matches!(
            smuggled_adds.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // Budget: counter > MAX_HOMO_ADDS_BEFORE_REFRESH at EVERY one of the 10 positions is
        // rejected (all positions active: token_count = 10 with an injective registry).
        for t in 0..MAX_CHANNEL_TOKENS {
            let mut over_budget = sample_state();
            over_budget.token_registry = std::array::from_fn(|i| i as u32);
            over_budget.token_count = MAX_CHANNEL_TOKENS as u8;
            over_budget.pending_adds[0][t] = MAX_HOMO_ADDS_BEFORE_REFRESH + 1;
            assert!(
                matches!(
                    over_budget.validate(),
                    Err(ChannelError::InvalidBalanceState(_))
                ),
                "counter over budget at token position {t} must be rejected"
            );
            // At the bound it is still representable.
            over_budget.pending_adds[0][t] = MAX_HOMO_ADDS_BEFORE_REFRESH;
            over_budget.validate().unwrap();
        }

        // Registry injectivity (TM-1): duplicate ACTIVE base token_index rejected.
        let mut dup_registry = sample_state();
        dup_registry.token_registry = BalanceState::single_token_registry(5);
        dup_registry.token_registry[1] = 5;
        dup_registry.token_count = 2;
        assert!(matches!(
            dup_registry.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // Inactive registry limbs must be zero-padded (canonical H1 encoding).
        let mut dirty_registry = sample_state();
        dirty_registry.token_registry[5] = 9;
        assert!(matches!(
            dirty_registry.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));

        // Malformed matrix shape (fail-closed before any hashing path).
        let mut short_rows = sample_state();
        short_rows.enc_balances.pop();
        assert!(matches!(
            short_rows.validate(),
            Err(ChannelError::InvalidBalanceState(_))
        ));
    }

    /// TokenRegister (detail2 §N-1, TM-1): apply appends at `token_count`, increments the count
    /// and `state_version`, changes H1 (header-only), leaves balances untouched; duplicate
    /// indices, full registries, and non-append transitions are rejected.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn token_register_apply_and_verify() {
        let prev = sample_state();
        let mut next = prev.clone();
        next.apply_token_register(42).unwrap();
        assert_eq!(next.token_count, 2);
        assert_eq!(next.token_registry[1], 42);
        assert_eq!(next.state_version, prev.state_version + 1);
        assert_eq!(next.enc_balances, prev.enc_balances, "balances untouched");
        assert_eq!(next.pending_adds, prev.pending_adds, "counters untouched");
        assert_ne!(
            prev.h1(),
            next.h1(),
            "registration is a (signed) header change"
        );
        next.validate().unwrap();
        BalanceState::verify_token_register_transition(&prev, &next, 42).unwrap();

        // Duplicate base token_index rejected — both against the genesis entry (0) and against a
        // freshly appended entry.
        let mut dup = prev.clone();
        assert!(
            dup.apply_token_register(0).is_err(),
            "genesis index 0 is taken"
        );
        let mut dup2 = next.clone();
        assert!(
            dup2.apply_token_register(42).is_err(),
            "42 already registered"
        );

        // Registry full (token_count == 10) rejected.
        let mut full = prev.clone();
        for i in 1..MAX_CHANNEL_TOKENS as u32 {
            full.apply_token_register(i).unwrap();
        }
        assert_eq!(full.token_count as usize, MAX_CHANNEL_TOKENS);
        assert!(full.apply_token_register(1000).is_err(), "registry full");

        // Verify-side negatives: an append at the WRONG position (skipping a slot) is rejected.
        let mut wrong_pos = prev.clone();
        wrong_pos.token_registry[2] = 42; // should have been position 1 (= prev.token_count)
        wrong_pos.token_count = 2;
        wrong_pos.state_version += 1;
        assert!(
            BalanceState::verify_token_register_transition(&prev, &wrong_pos, 42).is_err(),
            "append at wrong position must be rejected"
        );

        // A transition that ALSO touches a balance is rejected (TokenRegister is header-only).
        let mut touched = prev.clone();
        touched.apply_token_register(42).unwrap();
        touched.enc_balances[0][1] = ciphertext(77);
        assert!(
            BalanceState::verify_token_register_transition(&prev, &touched, 42).is_err(),
            "balance mutation alongside TokenRegister must be rejected"
        );

        // A token_count jump (+2) is rejected.
        let mut jump = prev.clone();
        jump.token_registry[1] = 42;
        jump.token_registry[2] = 43;
        jump.token_count = 3;
        jump.state_version += 1;
        assert!(
            BalanceState::verify_token_register_transition(&prev, &jump, 42).is_err(),
            "token_count jump must be rejected"
        );

        // A wrong claimed index is rejected.
        let mut ok_next = prev.clone();
        ok_next.apply_token_register(42).unwrap();
        assert!(
            BalanceState::verify_token_register_transition(&prev, &ok_next, 43).is_err(),
            "claimed token_index must match the appended one"
        );
    }

    /// Snapshot serde (detail2 §N-2 sparse storage): the JSON wire form is COMPACT — per-slot
    /// maps carrying only non-canonical token positions, trailing all-canonical rows omitted —
    /// and loads back to the exact full-width in-memory state (canonical-zero default). Unknown
    /// token positions (>= MAX_CHANNEL_TOKENS) are rejected.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn token_matrix_serde_compact_roundtrip() {
        let mut state = sample_state();
        state.token_registry[1] = 42;
        state.token_count = 2;
        state.enc_balances[2][1] = ciphertext(55);
        state.pending_adds[2][1] = 3;

        let json = serde_json::to_string(&state).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Compact: only the 3 active member slots survive as rows (trailing padding rows
        // dropped), and each row holds only its non-zero positions.
        let enc_rows = value["encBalances"].as_array().unwrap();
        assert_eq!(enc_rows.len(), 3, "trailing all-zero slot rows are omitted");
        assert_eq!(enc_rows[0].as_object().unwrap().len(), 1); // token 0 only
        assert_eq!(enc_rows[2].as_object().unwrap().len(), 2); // tokens 0 and 1
        let adds_rows = value["pendingAdds"].as_array().unwrap();
        assert!(adds_rows.len() <= 3);

        // Round-trip restores the FULL-width in-memory layout exactly (h1 included).
        let loaded: BalanceState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded, state);
        assert_eq!(loaded.h1(), state.h1());
        loaded.validate().unwrap();

        // A token position key beyond MAX_CHANNEL_TOKENS is rejected at load.
        let mut bad: serde_json::Value = serde_json::from_str(&json).unwrap();
        let row = bad["encBalances"][0].as_object().unwrap().clone();
        let ct = row.values().next().unwrap().clone();
        bad["encBalances"][0]
            .as_object_mut()
            .unwrap()
            .insert(MAX_CHANNEL_TOKENS.to_string(), ct);
        assert!(
            serde_json::from_value::<BalanceState>(bad).is_err(),
            "token position >= MAX_CHANNEL_TOKENS must be rejected"
        );
    }
}
