pub(crate) const CYCLIC_CIRCUIT_PADDING_DEGREE: usize = 13;
pub const NULLIFIER_TREE_HEIGHT: usize = 32;
pub const DEPOSIT_TREE_HEIGHT: usize = 32;
pub const ASSET_TREE_HEIGHT: usize = 32;
pub const PUBLIC_STATE_TREE_HEIGHT: usize = 32;
pub const TRANSFER_TREE_HEIGHT: usize = 5;

pub const BLOCK_NUMBER_BITS: usize = 63;

pub const LOCAL_ID_BITS: usize = 32;
pub const AGGREGATOR_ID_BITS: usize = 31;
pub const USER_ID_BITS: usize = AGGREGATOR_ID_BITS + LOCAL_ID_BITS;
pub const ACCOUNT_TREE_HEIGHT: usize = USER_ID_BITS;
pub const MAX_NUM_AGGREGATORS: usize = 1 << AGGREGATOR_ID_BITS;

pub const MAX_NUM_USERS_PER_BLOCK: usize = 16;
pub const MAX_NUM_TRANSFERS_PER_TX: usize = 1 << TRANSFER_TREE_HEIGHT;
