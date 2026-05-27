// General constants
pub const TOKEN_INDEX_BITS: usize = 32;

// Public State
pub const BLOCK_NUMBER_BITS: usize = 63;
pub const PUBLIC_STATE_TREE_HEIGHT: usize = BLOCK_NUMBER_BITS;
pub const DEPOSIT_TREE_HEIGHT: usize = 63;
pub const HUB_ID_BITS: usize = 31;
pub const ACCOUNT_NO_BITS: usize = 32;
pub const ACCOUNT_ID_BITS: usize = HUB_ID_BITS + ACCOUNT_NO_BITS;
pub const SEND_TREE_HEIGHT: usize = 32;
pub const ACCOUNT_TREE_HEIGHT: usize = ACCOUNT_ID_BITS;
pub const MAX_NUM_HUBS: usize = 1 << HUB_ID_BITS;

// Backward-compatible aliases while the rest of the codebase is migrated from
// aggregator/local naming to hub/account naming.
pub const AGGREGATOR_ID_BITS: usize = HUB_ID_BITS;
pub const LOCAL_ID_BITS: usize = ACCOUNT_NO_BITS;
pub const USER_ID_BITS: usize = ACCOUNT_ID_BITS;
pub const MAX_NUM_AGGREGATORS: usize = MAX_NUM_HUBS;

// Private State
pub const ASSET_TREE_HEIGHT: usize = TOKEN_INDEX_BITS;
pub const NULLIFIER_TREE_HEIGHT: usize = 32;
pub const SENT_TX_TREE_HEIGHT: usize = 32;

// Key Set (multi-sig)
pub const KEY_SET_TREE_HEIGHT: usize = 3; // max 8 keys per ID

// Transactions
pub const TRANSFER_TREE_HEIGHT: usize = 6;
pub const MAX_NUM_TRANSFERS_PER_TX: usize = 1 << TRANSFER_TREE_HEIGHT;
pub const TX_TREE_HEIGHT: usize = ACCOUNT_NO_BITS;
