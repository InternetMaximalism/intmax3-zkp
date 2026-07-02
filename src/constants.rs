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

// Per-channel member tree (one SPHINCS+ key per member, no multisig/threshold).
// `ChannelLeaf.member_pubkeys_root` commits the ordered member leaves
// `MemberLeaf { pk_g, regev_pk_digest }`, indexed by member slot
// 0..MAX_CHANNEL_MEMBERS. The tree MUST hold MAX_CHANNEL_MEMBERS leaf slots, so its height is
// log2(MAX_CHANNEL_MEMBERS): a channel's `member_count` active members occupy slots
// 0..member_count and the remaining slots are empty leaves.
//
// SECURITY/INVARIANT: 1 << MEMBER_TREE_HEIGHT == MAX_CHANNEL_MEMBERS. Genesis (`create_channel`)
// inserts every padded slot index (0..MAX_CHANNEL_MEMBERS) into this tree, and `channel_reg_step`
// asserts `leaf_hashes.len() == 1 << MEMBER_TREE_HEIGHT`. If this height is smaller than log2(MAX),
// the incremental Merkle tree panics on the first slot index >= 2^height
// (incremental_merkle_tree.rs:72). MAX=1024 => height 10.
pub const MEMBER_TREE_HEIGHT: usize = 10;

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

// Transactions
pub const TRANSFER_TREE_HEIGHT: usize = 6;
pub const MAX_NUM_TRANSFERS_PER_TX: usize = 1 << TRANSFER_TREE_HEIGHT;
// The base tx tree is indexed by channel_id (one base "user" = one channel).
pub const TX_TREE_HEIGHT: usize = CHANNEL_ID_BITS;
