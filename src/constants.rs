// General constants
pub const TOKEN_INDEX_BITS: usize = 32;

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
pub const MAX_NUM_CHANNELS: usize = 1usize << CHANNEL_ID_BITS;

// Private State
pub const ASSET_TREE_HEIGHT: usize = TOKEN_INDEX_BITS;
pub const NULLIFIER_TREE_HEIGHT: usize = 32;
pub const SENT_TX_TREE_HEIGHT: usize = 32;

// Per-channel member tree (one SPHINCS+ key per member, no multisig/threshold).
// `ChannelLeaf.member_pubkeys_root` commits the ordered member leaves
// `MemberLeaf { sphincs_pk_hash, regev_pk_digest }`, indexed by member slot 0..CHANNEL_MEMBERS.
// Height 2 (4 leaf slots) is the smallest tree covering the 3 members + 1 empty slot.
pub const MEMBER_TREE_HEIGHT: usize = 2;

// Payment channels (detail2 §G-1 / abstract2 §2.1, §2.5)
/// Fixed channel membership (abstract2 §2.1: exactly 3 members per channel). `ChannelRecord`,
/// `BalanceState.enc_balances` and `BalanceState.pending_adds` are all sized by this constant.
pub const CHANNEL_MEMBERS: usize = 3;
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
