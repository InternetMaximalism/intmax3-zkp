// General constants
pub const TOKEN_INDEX_BITS: usize = 32;

/// Token decimals (USDC-style). All amounts in the protocol are integer BASE UNITS; one token =
/// `10^TOKEN_DECIMALS` base units. The protocol/circuits are decimal-agnostic (they operate on
/// integers); this is the canonical display/representation convention. A balance of `1_000_000`
/// base units renders as `1.000000`.
pub const TOKEN_DECIMALS: u32 = 6;
/// Base units per whole token (`10^TOKEN_DECIMALS`).
pub const TOKEN_UNIT: u64 = 1_000_000;

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
// 0..MAX_CHANNEL_MEMBERS. Height 4 (16 leaf slots) covers the pad-to-MAX member set: a channel's
// `member_count` active members occupy slots 0..member_count and the remaining slots are empty
// leaves.
pub const MEMBER_TREE_HEIGHT: usize = 4;

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
pub const MAX_CHANNEL_MEMBERS: usize = 16;
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
