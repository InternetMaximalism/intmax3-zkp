// General constants
pub const TOKEN_INDEX_BITS: usize = 32;

/// Token decimals (ETH-native). All amounts in the protocol are integer BASE UNITS (= wei); one
/// token = `10^TOKEN_DECIMALS` base units = 1 ETH. The protocol/circuits are decimal-agnostic
/// (they operate on u64 integers); this is the canonical display convention. A balance of
/// `100_000_000_000_000_000` base units renders as `0.1` (ETH).
pub const TOKEN_DECIMALS: u32 = 18;
/// Base units per whole token (`10^TOKEN_DECIMALS` = 1 ETH in wei).
pub const TOKEN_UNIT: u64 = 1_000_000_000_000_000_000;

// Public State
pub const BLOCK_NUMBER_BITS: usize = 63;
pub const PUBLIC_STATE_TREE_HEIGHT: usize = BLOCK_NUMBER_BITS;
pub const DEPOSIT_TREE_HEIGHT: usize = 63;
pub const CHANNEL_ID_BITS: usize = 32;
pub const SEND_TREE_HEIGHT: usize = 32;
// SECURITY: the BASE intmax native user IS the channel; base accounts are keyed by
// `channel_id` ALONE (key_id lives only in the channel layer). So the base channel id is 32 bits
// and the channel tree is indexed by channel_id.
pub const CHANNEL_TREE_HEIGHT: usize = CHANNEL_ID_BITS;
// `u64`, not `usize`: `1 << 32` overflows the 32-bit `usize` on the wasm32 target (fine on 64-bit
// native). This constant is informational (channel-id space size) and unused elsewhere, so widening
// the type is value-preserving on native and portable to wasm.
pub const MAX_NUM_CHANNELS: u64 = 1u64 << CHANNEL_ID_BITS;

/// SECURITY: reserved channel id for the **partial-withdrawal burn destination** (abstract2-1
/// §2.6). A base-layer transfer routed to this id is an L1 exit (settled as a `Withdrawal`), never
/// a channel credit. No real channel may register here — `ChannelRecord::validate` and the on-chain
/// `registerChannel` both reject it. The all-ones 32-bit sentinel stays disjoint from any
/// allocatable channel id. NOTE: the exclusivity that prevents a transfer from being both withdrawn
/// and credited is enforced by the recipient TAG (`ADDRESS_TAG` ⇔ withdraw-only; see
/// `tests/partial_withdrawal_exclusivity.rs`); `BURN_CHANNEL_ID` is the explicit routing marker.
pub const BURN_CHANNEL_ID: u32 = 0xFFFF_FFFF;

// Private State
pub const ASSET_TREE_HEIGHT: usize = TOKEN_INDEX_BITS;
pub const NULLIFIER_TREE_HEIGHT: usize = 32;
pub const SENT_TX_TREE_HEIGHT: usize = 32;

// Per-channel REGISTERED member tree (one Goldilocks signing key per member).
// `ChannelLeaf.member_pubkeys_root` commits the ordered member leaves
// `MemberLeaf { pk_g, pk_b, regev_pk_digest }`, indexed by member slot 0..MAX_COSIGNERS.
//
// SECURITY (Option B, tasks/reg-chain-1024-threat-model.md): L1 registration covers ONLY the
// <= MAX_COSIGNERS cosigners, so this tree — the root written at `channel_reg_step` and the root
// the validity `update_channel_tree` bp-slot inclusion opens against — holds exactly the
// MAX_COSIGNERS cosigner slots. A channel's `member_count` active COSIGNERS occupy slots
// 0..member_count; the remaining slots are empty leaves. Delegates are NOT in this tree: they are
// authenticated by the cosigner-signed H1 balance-slot tree (BALANCE_SLOT_TREE_HEIGHT), never by
// prior L1 registration. The bp is always a cosigner (`bp_member_slot < member_count`), so the
// validity-side inclusion never needs a delegate slot.
//
// This tree is DISTINCT from the wallet's LIVE-membership tree (see
// [`WALLET_MEMBER_TREE_HEIGHT`]) — do not conflate them: their roots are equal only for a channel
// with zero delegates.
//
// SECURITY/INVARIANT: 1 << MEMBER_TREE_HEIGHT == MAX_COSIGNERS (const-asserted below).
// `channel_reg_step` asserts `leaf_hashes.len() == 1 << MEMBER_TREE_HEIGHT`. If this height were
// smaller than log2(MAX_COSIGNERS), the incremental Merkle tree panics on the first slot index
// >= 2^height (incremental_merkle_tree.rs:72) — it never silently truncates.
pub const MEMBER_TREE_HEIGHT: usize = 4;
const _: () = assert!(
    1 << MEMBER_TREE_HEIGHT == MAX_COSIGNERS,
    "MEMBER_TREE_HEIGHT must be log2(MAX_COSIGNERS)"
);

/// Height of the WALLET-side LIVE membership tree (`wallet_core::member_pubkeys_root`): the
/// off-chain P4-1/A11 anchoring over ALL active participants — cosigners AND delegates — up to
/// `MAX_CHANNEL_MEMBERS` slots. This root lives in the member-signed `ChannelRecord` and EVOLVES
/// with every delegate join.
///
/// SECURITY (Option B divergence — INTENTIONAL): this is a DIFFERENT tree from the registered
/// member tree ([`MEMBER_TREE_HEIGHT`], cosigners-only, written once at registration). The wallet
/// root is never compared to the registered root anywhere; it anchors the off-chain member set
/// that peers verify (`verify_snapshot` / payload checks), while the registered root authenticates
/// the block producer in the validity circuit. Keeping the heights different (10 vs 4) makes
/// accidental conflation fail loudly (root mismatch / proof length mismatch) instead of silently.
pub const WALLET_MEMBER_TREE_HEIGHT: usize = 10;
const _: () = assert!(
    1 << WALLET_MEMBER_TREE_HEIGHT == MAX_CHANNEL_MEMBERS,
    "WALLET_MEMBER_TREE_HEIGHT must be log2(MAX_CHANNEL_MEMBERS)"
);

// Payment channels (detail2 §G-1 / abstract2 §2.1, §2.5)
/// Maximum channel membership under the pad-to-MAX (N-member) model. Every channel uses
/// arrays/circuits sized for this constant; a per-channel `member_count` (2..=MAX_CHANNEL_MEMBERS)
/// selects how many leading slots are active (slots `member_count..MAX_CHANNEL_MEMBERS` are
/// padding: default/empty ciphertexts, zero pending-adds, `Bytes32::default()` pubkey hashes).
/// `ChannelRecord`, `BalanceState.enc_balances` and `BalanceState.pending_adds` are all sized by
/// this constant.
///
/// SECURITY: this is a STATIC ZK-circuit size (the close circuit verifies MAX_CHANNEL_MEMBERS
/// SPHINCS+ slots, gating padding slots off). Deviation D6 from abstract2 §2.1 (which fixes 3
/// members) — see detail2-implementation-notes.md.
pub const MAX_CHANNEL_MEMBERS: usize = 1024;

/// Height of the per-channel BALANCE-SLOT Poseidon Merkle tree: the tree whose 1024 leaves are
/// `balance_slot_leaf_hash(regev_pk_digests[i], enc_balances[i].digest(), pending_adds[i])`
/// (member slot order) and whose ROOT rides in the `BalanceState::h1()` header. This is the
/// H1-commitment tree (see `tasks/h1-poseidon-root-threat-model.md`) — DISTINCT from
/// [`MEMBER_TREE_HEIGHT`] (the validity-side member pubkey tree), which merely happens to share
/// the same height because both are indexed by the slot space `0..MAX_CHANNEL_MEMBERS`.
///
/// SECURITY/INVARIANT: `1 << BALANCE_SLOT_TREE_HEIGHT == MAX_CHANNEL_MEMBERS` (const-asserted
/// below). The claim circuits allocate inclusion proofs of exactly this height and
/// `split_le(index, height)` bounds the opened slot index to `< MAX_CHANNEL_MEMBERS`; the native
/// `BalanceState::slot_tree()` populates ALL `MAX_CHANNEL_MEMBERS` leaves, so the root — and
/// hence H1 — remains a function of the FULL slot array exactly like the retired flat keccak.
pub const BALANCE_SLOT_TREE_HEIGHT: usize = 10;
const _: () = assert!(
    1 << BALANCE_SLOT_TREE_HEIGHT == MAX_CHANNEL_MEMBERS,
    "BALANCE_SLOT_TREE_HEIGHT must be log2(MAX_CHANNEL_MEMBERS)"
);

/// Cosigner cap = the N-of-N close SIGNERS. A channel closes / cancels-close via `member_count`
/// UNANIMOUS SPHINCS+ cosigner signatures; these are the ONLY participants whose `pk_g` feed the
/// close/cancel SIGNATURE work (member_set_commitment keccak, C' signature fold, A5 pk_g
/// distinctness, per-slot activeness gating). This is DISTINCT from [`MAX_CHANNEL_MEMBERS`], the
/// balance-slot capacity: a channel's balance state holds up to `MAX_CHANNEL_MEMBERS` slots
/// (cosigners + DELEGATES + padding), but delegates hold balances WITHOUT co-signing the close, so
/// the signature-side arrays/circuits are sized by this smaller cosigner cap while the balance /
/// H1 arrays stay sized by `MAX_CHANNEL_MEMBERS`.
///
/// SECURITY: this is a STATIC ZK-circuit size — the close/cancel circuits verify exactly
/// `MAX_COSIGNERS` SPHINCS+ cosigner slots (gating padding slots off via the active-bits unary
/// decomposition). `member_count` is range-checked `2..=MAX_COSIGNERS`; the invariant `member_count
/// + delegate_count <= MAX_CHANNEL_MEMBERS` still bounds the total active balance participants.
/// Sizing the SIGNATURE work to 16 (rather than 1024) is what keeps the close/cancel circuit degree
/// tractable — the H1 / balance-state work legitimately stays 1024 (delegates have balances).
pub const MAX_COSIGNERS: usize = 16;

/// Height of the in-circuit indexed-Merkle tree used to prove A5 pk_g distinctness over the active
/// COSIGNER set (close / cancel-close circuits). The close/cancel circuits insert each ACTIVE
/// cosigner's `pk_g` (as a U256 key) IN SLOT ORDER into an initially-empty `IndexedMerkleTree`; the
/// existing audited insertion gadget proves `prev_low.key < key < next_key` per insert =
/// non-membership = distinctness, so a duplicate key makes an insertion UNSATISFIABLE. This
/// replaces the former O(MAX_COSIGNERS^2) all-pairs equality loop with an O(MAX·height)
/// chain that proves the SAME property (no two active cosigner slots share a pk_g) without touching
/// slot order, the member_set_commitment, or the C' signature fold.
///
/// SIZING: the tree starts with ONE sentinel leaf (`IndexedMerkleTree::new` pushes
/// `IndexedMerkleLeaf::default()` at index 0) and then pushes up to `MAX_COSIGNERS` active
/// leaves, for at most `MAX_COSIGNERS + 1` occupied leaf slots. `IncrementalMerkleTree::push`
/// asserts `index < 2^height`, so we need `2^height >= MAX_COSIGNERS + 1`, i.e.
/// `height >= ceil(log2(MAX_COSIGNERS + 1))`. Derived from `MAX_COSIGNERS` (the distinctness tree
/// only holds COSIGNER keys now, not balance slots) so a later cap bump stays correct without a
/// manual edit. For MAX_COSIGNERS=16: `ceil(log2(17)) = 5` → 32 leaf slots.
///
/// SECURITY: the height only bounds tree CAPACITY; it does not affect WHICH keys are checked
/// (the active gating and key sourcing do). Over-sizing the tree is sound (it only adds unused
/// capacity); under-sizing it would panic at witness-generation time (`push` assert), never
/// silently skip a check.
pub const MEMBER_DISTINCTNESS_TREE_HEIGHT: usize = {
    // ceil(log2(MAX_COSIGNERS + 1)): smallest `height` with `2^height >= MAX_COSIGNERS+1`.
    let needed_leaves = (MAX_COSIGNERS + 1) as u64;
    let mut height = 0usize;
    let mut capacity = 1u64;
    while capacity < needed_leaves {
        capacity <<= 1;
        height += 1;
    }
    height
};

/// Co-signing timeout (abstract2 §2.5: 3 minutes). Replaces the retired
/// `SMALL_BLOCK_SIGNATURE_TIMEOUT_SECS = 60`.
pub const SIGN_TIMEOUT_SECS: u64 = 180;
/// Grace period between `requestClose` and the first close-intent submission
/// (abstract2 §2.5: 10 minutes; detail2 §H-2).
pub const GRACE_BEFORE_PROCESS_SECS: u64 = 600;
/// L1 close-challenge window (abstract2 §2.5: 1 day; detail2 §G-1).
pub const CHALLENGE_PERIOD_SECS: u64 = 86_400;

// Multi-token channels (detail2 §N)
/// Maximum number of tokens (currencies) a single channel can hold (detail2 §N-1). Every balance
/// slot leaf carries a FIXED `MAX_CHANNEL_TOKENS`-wide vector of independent Regev ciphertexts
/// (one per local token slot), and the channel-local `token_registry` maps each local token slot
/// `t < token_count` to a BASE-layer `token_index: u32`. Positions `t >= token_count` are always
/// the canonical zero ciphertext with zero `pending_adds` (TM-8 fail-closed).
///
/// SECURITY: this is a STATIC hash-layout width (leaf = 104 elems, H1 header = 37 elems,
/// token_funds_digest = fixed 92-word keccak preimage) — the in-memory and HASH layouts are
/// ALWAYS full width regardless of `token_count` (TM-11: variable-length preimages alias).
pub const MAX_CHANNEL_TOKENS: usize = 10;

// Multi-token v2 domain constants (detail2 §N-9 / §G-2, TM-15).
//
// SECURITY (TM-15 domain re-versioning): every preimage that gains a field in the multi-token
// change gets a NEW domain constant, so a v1-observed digest/nullifier can never be replayed as
// (or collide with) a v2 one. The v1 constants stay in place until the legacy paths (in-circuit
// recomputes, Phase 2) are migrated. All old + new tags are asserted pairwise distinct by
// `poseidon_sig::tests::domain_constants_are_pairwise_distinct` (the repo-wide non-collision
// check) and by `domain_constant_ascii_tags` below.

/// "IMB2" — v2 H1 header domain (detail2 §N-1, TM-9). Replaces "IMBS" (`BALANCE_STATE_DOMAIN`)
/// for the 37-element Poseidon header that now commits `token_count` + the full 10-limb
/// `token_registry`. See [`crate::common::balance_state::BalanceState::h1`].
pub const BALANCE_STATE_DOMAIN_V2: u32 = 0x494d4232;
/// "IMS2" — v2 balance-slot leaf domain (detail2 §N-2, TM-8/TM-15). Replaces "IMSL"
/// (`BALANCE_SLOT_LEAF_DOMAIN`) for the 104-element leaf carrying 10 ciphertext digests and 10
/// per-token add counters. See [`crate::common::balance_state::balance_slot_leaf_hash`].
pub const BALANCE_SLOT_LEAF_DOMAIN_V2: u32 = 0x494d5332;
/// "IMP2" — v2 in-channel pay domain (detail2 §N-3, TM-2/TM-15). Replaces "IMPA" (`PAY_DOMAIN`)
/// for the IMPA-v2 `ChannelTx` signing digest, which gains `token_slot` as its OWN canonical u32
/// limb (never bit-packed). See [`crate::common::channel::ChannelTx::signing_digest`].
pub const PAY_DOMAIN_V2: u32 = 0x494d5032;
/// "IML2" — v2 L1 deposit-import domain (detail2 §N-5, TM-7/TM-15). Replaces "IMLD"
/// (`L1_DEPOSIT_IMPORT_DOMAIN`); the digest gains the base `token_index` as its own limb.
/// See [`crate::common::channel::l1_deposit_import_digest`].
pub const L1_DEPOSIT_IMPORT_DOMAIN_V2: u32 = 0x494d4c32;
/// "IMW2" — v2 withdrawal-claim nullifier domain (detail2 §N-6, TM-5/TM-15). Replaces "IMCW"
/// (`WITHDRAWAL_CLAIM_DOMAIN`) for the per-(slot, token) claim nullifier
/// `[IMW2, close_intent_digest(8), slot_regev_pk_digest(8), token_slot]`.
/// See [`crate::common::channel::WithdrawalClaim::derive_nullifier`].
pub const WITHDRAWAL_CLAIM_DOMAIN_V2: u32 = 0x494d5732;
/// "IMU2" — v2 E-2 channelUpdateZKP PI domain (detail2 §N-4, TM-6/TM-15). Replaces "IMUZ"
/// (`CHANNEL_UPDATE_ZKP_DOMAIN`, retired): the E-2 public values gain the base `token_index` as
/// their own extra PV, so every E-2 transcript binds WHICH base token the update moves. Wired in
/// multitoken Phase 2b; see `regev::transfer_stark::{prove,verify}_channel_update`.
pub const CHANNEL_UPDATE_ZKP_DOMAIN_V2: u32 = 0x494d5532;
/// "IMI2" — v2 inter-channel tx (C2C descriptor) domain (detail2 §N-4, TM-6/TM-15). Replaces
/// "IMIT" (`INTER_CHANNEL_TX_DOMAIN`, retired): the `InterChannelTx` signing digest gains the
/// base `token_index` as its OWN canonical u32 limb.
///
/// SECURITY (domain decision, multitoken Phase 2b): a NEW domain (not an in-place widening) was
/// chosen because the IMIT preimage carries THREE variable-length, length-prefixed tails
/// (recipient_memo, receiver_deltas, transport_proof), so an in-place widening's
/// equal-total-length v1<->v2 realignment case would rest on the v3 reset alone (the same caveat
/// the Phase 2a review recorded for IMCW). The v1 "IMIT" preimage has exactly ONE hashing site
/// (`InterChannelTx::signing_digest`; the legacy cancel-close in-circuit IMIT recompute was
/// retired by the Finding-D statement correction, and no Solidity mirror exists), so the
/// re-version costs one constant and removes that reliance entirely. v1 value stays pinned in
/// `all_domain_constants_pairwise_distinct`.
pub const INTER_CHANNEL_TX_DOMAIN_V2: u32 = 0x494d4932;
/// "IMI3" — v3 inter-channel tx domain.  The descriptor gains an explicit base-account nonce
/// instead of deriving `TxV2.nonce` from the channel's small-block counter.  Those counters have
/// different semantics: incoming channel transitions advance the latter while only base sends
/// advance the former.  Keeping IMI2 while inserting a limb would reintroduce the variable-tail
/// realignment ambiguity documented above, so the schema change gets a fresh domain.
pub const INTER_CHANNEL_TX_DOMAIN_V3: u32 = 0x494d4933;
/// "IMI4" — v4 inter-channel tx domain. The canonical base-layer recipient for a normal
/// channel-to-channel transfer is now the UID-tagged recipient derived from the destination
/// channel id and an explicit transfer salt. The salt is part of the signed wire preimage; this
/// makes the same value available to the destination `ReceiveTransfer` circuit without conflating
/// it with the destination member's unrelated Regev/Falcon `pk_g`.
pub const INTER_CHANNEL_TX_DOMAIN_V4: u32 = 0x494d4934;

/// "IMI5" (detail2 §P-2): the `InterChannelTx` signing digest gains the per-leaf SENDER hash-sig
/// obligation — the digest itself is what `sender_hash_sig` (A11 Poseidon2-BabyBear) signs, so the
/// preimage layout is v4's but under a fresh domain: a v4 digest must never verify as the message
/// of a v5 sender signature (and vice versa). v3-reset policy: no dual-format acceptance window.
pub const INTER_CHANNEL_TX_DOMAIN_V5: u32 = 0x494d4935;

/// "IMMS" (detail2 §Q-1): the member-set-update digest — the message the PREVIOUS co-signer set's
/// N-of-N signs to authorize an AddCosigner / RotateKey transition. The single canonical update
/// commitment all three layers (channel gate, validity transition, L1 apply) verify.
pub const MEMBER_SET_UPDATE_DOMAIN: u32 = 0x494d4d53;

/// "IMKR" (detail2 §Q-1): rotation self-consent — signed by the rotated slot's CURRENT Falcon
/// key. Redundant with the member's own N-of-N vote today (N-of-N gives every member a veto) but
/// explicit, and survives any future sub-N threshold.
pub const KEY_ROTATION_CONSENT_DOMAIN: u32 = 0x494d4b52;

/// "IMJC" (detail2 §Q-1): joiner consent for AddCosigner — signed by the NEW member's Falcon key;
/// proves possession of the enrolled key and intent to join (no rogue-key enrollment).
pub const JOINER_CONSENT_DOMAIN: u32 = 0x494d4a43;
/// "IMTF" — token-funds digest domain (detail2 §N-6, TM-11). Domain of
/// `token_funds_digest = keccak([IMTF, registry(10 x u32, zero-padded), token_count,
/// amounts(10 x U256, zero-padded)])` — ALWAYS full width.
/// See [`crate::common::channel::token_funds_digest`].
pub const TOKEN_FUNDS_DIGEST_DOMAIN: u32 = 0x494d5446;

// Transactions
pub const TRANSFER_TREE_HEIGHT: usize = 6;
pub const MAX_NUM_TRANSFERS_PER_TX: usize = 1 << TRANSFER_TREE_HEIGHT;
// The base tx tree is indexed by channel_id (one base "user" = one channel).
pub const TX_TREE_HEIGHT: usize = CHANNEL_ID_BITS;

#[cfg(test)]
mod tests {
    use super::*;

    /// The v2 multi-token domain constants are exactly their documented ASCII tags (TM-15).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn multitoken_domain_constant_ascii_tags() {
        assert_eq!(BALANCE_STATE_DOMAIN_V2, u32::from_be_bytes(*b"IMB2"));
        assert_eq!(BALANCE_SLOT_LEAF_DOMAIN_V2, u32::from_be_bytes(*b"IMS2"));
        assert_eq!(PAY_DOMAIN_V2, u32::from_be_bytes(*b"IMP2"));
        assert_eq!(L1_DEPOSIT_IMPORT_DOMAIN_V2, u32::from_be_bytes(*b"IML2"));
        assert_eq!(WITHDRAWAL_CLAIM_DOMAIN_V2, u32::from_be_bytes(*b"IMW2"));
        assert_eq!(CHANNEL_UPDATE_ZKP_DOMAIN_V2, u32::from_be_bytes(*b"IMU2"));
        assert_eq!(INTER_CHANNEL_TX_DOMAIN_V2, u32::from_be_bytes(*b"IMI2"));
        assert_eq!(INTER_CHANNEL_TX_DOMAIN_V3, u32::from_be_bytes(*b"IMI3"));
        assert_eq!(INTER_CHANNEL_TX_DOMAIN_V4, u32::from_be_bytes(*b"IMI4"));
        assert_eq!(INTER_CHANNEL_TX_DOMAIN_V5, u32::from_be_bytes(*b"IMI5"));
        assert_eq!(MEMBER_SET_UPDATE_DOMAIN, u32::from_be_bytes(*b"IMMS"));
        assert_eq!(KEY_ROTATION_CONSENT_DOMAIN, u32::from_be_bytes(*b"IMKR"));
        assert_eq!(JOINER_CONSENT_DOMAIN, u32::from_be_bytes(*b"IMJC"));
        assert_eq!(TOKEN_FUNDS_DIGEST_DOMAIN, u32::from_be_bytes(*b"IMTF"));
    }

    /// Repo-wide domain-constant NON-COLLISION check (detail2 §G-2 / §N-9, TM-15): every domain
    /// separator defined anywhere in the codebase — old AND the new multi-token v2 ones — is
    /// pairwise distinct. Private constants (channel.rs, circuit-local twins) are pinned here as
    /// literals with their defining location, so an edit of a private constant that introduces a
    /// collision (or silently changes a pinned value) trips this test.
    ///
    /// SECURITY: domain separation is the only thing preventing a digest computed under one
    /// preimage schema from being replayed as another (cross-protocol confusion); a collision
    /// between any two tags voids that argument for the colliding pair.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn all_domain_constants_pairwise_distinct() {
        // (tag, value, defining site). Keep in sync with `grep -rn "0x494d\|0x4d42\|0x4348\|0x5549"
        // src --include='*.rs' | grep const` and detail2.md §G-2/§G-3.
        let domains: &[(&str, u32)] = &[
            ("IMCH CHANNEL_STATE_DOMAIN (channel.rs)", 0x494d_4348),
            (
                "IMPA PAY_DOMAIN v1 (retired; historic digests)",
                0x494d_5041,
            ),
            ("IMSB SMALL_BLOCK_DOMAIN (channel.rs)", 0x494d_5342),
            ("IMSS SIGNED_SMALL_BLOCK_DOMAIN (channel.rs)", 0x494d_5353),
            (
                "IMIT INTER_CHANNEL_TX_DOMAIN v1 (retired; historic digests)",
                0x494d_4954,
            ),
            ("IMCL CLOSE_TX_DOMAIN (channel.rs)", 0x494d_434c),
            ("IMCI CLOSE_INTENT_DOMAIN (channel.rs)", 0x494d_4349),
            ("IMSC SPECIAL_CLOSE_DOMAIN (channel.rs)", 0x494d_5343),
            ("IMCN CANCEL_CLOSE_DOMAIN (channel.rs)", 0x494d_434e),
            ("IMCP POST_CLOSE_CLAIM_DOMAIN (channel.rs)", 0x494d_4350),
            ("IMCK POST_CLOSE_NULLIFIER_DOMAIN (channel.rs)", 0x494d_434b),
            ("IMCW WITHDRAWAL_CLAIM_DOMAIN v1 (channel.rs)", 0x494d_4357),
            ("IMUF CHANNEL_BALANCE_LEAF_DOMAIN (channel.rs)", 0x494d_5546),
            ("IMCR CHANNEL_RECORD_DOMAIN (channel.rs)", 0x494d_4352),
            ("IMCM CLOSE_MEMBER_SET_DOMAIN (channel.rs)", 0x494d_434d),
            (
                "IMLD L1_DEPOSIT_IMPORT_DOMAIN v1 (retired; historic digests)",
                0x494d_4c44,
            ),
            (
                "IMBS BALANCE_STATE_DOMAIN v1 (retired; historic digests)",
                0x494d_4253,
            ),
            (
                "IMSL BALANCE_SLOT_LEAF_DOMAIN v1 (retired; historic digests)",
                0x494d_534c,
            ),
            (
                "IMBH BALANCE_STATE_HASH_DOMAIN (balance_state.rs)",
                0x494d_4248,
            ),
            ("IMTL TX_LEAF_DOMAIN (balance_state.rs)", 0x494d_544c),
            ("IMBD BURN_DESCRIPTOR_DOMAIN (channel.rs)", 0x494d_4244),
            (
                "IMTC SETTLED_TX_CHAIN_DOMAIN (balance_state.rs)",
                0x494d_5443,
            ),
            ("IMRC REGEV_CT_DOMAIN (regev/encrypt.rs)", 0x494d_5243),
            ("IMRK REGEV_PK_DOMAIN (regev/keys.rs)", 0x494d_524b),
            ("IMRR REGEV_PK_ROOT_DOMAIN (regev/keys.rs)", 0x494d_5252),
            ("IMRP REGEV_PK_POSEIDON_DOMAIN (regev/keys.rs)", 0x494d_5250),
            (
                "IMCZ CHANNEL_TX_ZKP_DOMAIN (transfer_stark.rs)",
                0x494d_435a,
            ),
            (
                "IMUZ E-2 channelUpdateZKP v1 (retired; historic transcripts)",
                0x494d_555a,
            ),
            (
                "IMWZ WITHDRAW_CLAIM_ZKP_DOMAIN (transfer_stark.rs)",
                0x494d_575a,
            ),
            (
                "IMRF BALANCE_REFRESH_ZKP_DOMAIN (transfer_stark.rs)",
                0x494d_5246,
            ),
            ("IMLL LIST_LEAF_DOMAIN (poseidon_sig/list.rs)", 0x494d_4c4c),
            ("IMPG DOMAIN_PK_G (poseidon_sig/mod.rs)", 0x494d_5047),
            ("IMSG DOMAIN_SIG_G (poseidon_sig/mod.rs)", 0x494d_5347),
            (
                "IMPW PARTIAL_WITHDRAWAL_DOMAIN (wallet_core.rs)",
                0x494d_5057,
            ),
            ("MBLF MEMBER_LEAF_DOMAIN (key_tree.rs)", 0x4d42_4c46),
            (
                "CHLF CHANNEL_LEAF_DOMAIN (trees/channel_tree.rs)",
                0x4348_4c46,
            ),
            (
                "UID\\0 USER_ID_DOMAIN (balance/common/recipient.rs)",
                0x5549_4400,
            ),
            // BabyBear Poseidon2 transcript domains + the channel wire magic (security-review
            // MINOR 4) — referenced via the pub consts so a drifting definition is caught.
            (
                "BPKB DOMAIN_PK_B (regev/hash_sig.rs)",
                crate::regev::hash_sig::DOMAIN_PK_B,
            ),
            (
                "BSGB DOMAIN_SIG_B (regev/hash_sig.rs)",
                crate::regev::hash_sig::DOMAIN_SIG_B,
            ),
            (
                "IMPC CHANNEL_MESSAGE_MAGIC (common/channel_message.rs)",
                crate::common::channel_message::CHANNEL_MESSAGE_MAGIC,
            ),
            // Multi-token v2 (this file) — referenced via the pub consts so a drifting
            // definition (not just a colliding one) is caught.
            ("IMB2 BALANCE_STATE_DOMAIN_V2", BALANCE_STATE_DOMAIN_V2),
            (
                "IMS2 BALANCE_SLOT_LEAF_DOMAIN_V2",
                BALANCE_SLOT_LEAF_DOMAIN_V2,
            ),
            ("IMP2 PAY_DOMAIN_V2", PAY_DOMAIN_V2),
            (
                "IML2 L1_DEPOSIT_IMPORT_DOMAIN_V2",
                L1_DEPOSIT_IMPORT_DOMAIN_V2,
            ),
            (
                "IMW2 WITHDRAWAL_CLAIM_DOMAIN_V2",
                WITHDRAWAL_CLAIM_DOMAIN_V2,
            ),
            (
                "IMU2 CHANNEL_UPDATE_ZKP_DOMAIN_V2",
                CHANNEL_UPDATE_ZKP_DOMAIN_V2,
            ),
            (
                "IMI2 INTER_CHANNEL_TX_DOMAIN_V2",
                INTER_CHANNEL_TX_DOMAIN_V2,
            ),
            (
                "IMI3 INTER_CHANNEL_TX_DOMAIN_V3",
                INTER_CHANNEL_TX_DOMAIN_V3,
            ),
            ("IMMS MEMBER_SET_UPDATE_DOMAIN", MEMBER_SET_UPDATE_DOMAIN),
            ("IMKR KEY_ROTATION_CONSENT_DOMAIN", KEY_ROTATION_CONSENT_DOMAIN),
            ("IMJC JOINER_CONSENT_DOMAIN", JOINER_CONSENT_DOMAIN),
            (
                "IMI5 INTER_CHANNEL_TX_DOMAIN_V5",
                INTER_CHANNEL_TX_DOMAIN_V5,
            ),
            (
                "IMI4 INTER_CHANNEL_TX_DOMAIN_V4",
                INTER_CHANNEL_TX_DOMAIN_V4,
            ),
            ("IMTF TOKEN_FUNDS_DIGEST_DOMAIN", TOKEN_FUNDS_DIGEST_DOMAIN),
            // Falcon-512/Poseidon signing key (falcon_sig/mod.rs, threat model
            // doc/tasks/falcon-sig-threat-model.md) — registry merge promised by the Phase-0
            // `falcon_domains_do_not_collide` test; referenced via the pub consts so a drifting
            // definition is caught.
            (
                "IMFH DOMAIN_FALCON_H2P (falcon_sig/mod.rs)",
                crate::falcon_sig::DOMAIN_FALCON_H2P,
            ),
            (
                "IMFK DOMAIN_FALCON_PK (falcon_sig/mod.rs)",
                crate::falcon_sig::DOMAIN_FALCON_PK,
            ),
            (
                "IMFG DOMAIN_FALCON_KEYGEN (falcon_sig/mod.rs)",
                crate::falcon_sig::DOMAIN_FALCON_KEYGEN,
            ),
            // N-of-N small-block fold (falcon_sig/agg_list.rs, design
            // doc/tasks/small-block-nofn-design.md §5.3). The widened
            // `(message, signer_count, pk_list_digest)` leaf is a DIFFERENT preimage schema than
            // the IMLL `(message, public_key)` leaf, and Poseidon here is a no-pad sponge, so it
            // needs its own tag rather than a reuse of IMLL.
            (
                "IMAL AGG_LIST_LEAF_DOMAIN (falcon_sig/agg_list.rs)",
                crate::falcon_sig::agg_list::AGG_LIST_LEAF_DOMAIN,
            ),
            (
                "IMPL AGG_PK_LIST_DOMAIN (falcon_sig/agg_list.rs)",
                crate::falcon_sig::agg_list::AGG_PK_LIST_DOMAIN,
            ),
            (
                "IMFB DOMAIN_FALCON_BATCH (falcon_sig/mod.rs)",
                crate::falcon_sig::DOMAIN_FALCON_BATCH,
            ),
        ];
        for (i, (name_a, a)) in domains.iter().enumerate() {
            for (name_b, b) in domains.iter().skip(i + 1) {
                assert_ne!(a, b, "domain collision: {name_a} == {name_b} ({a:#010x})");
            }
        }
    }
}
