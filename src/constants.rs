pub(crate) const CYCLIC_CIRCUIT_PADDING_DEGREE: usize = 13;
pub const NULLIFIER_TREE_HEIGHT: usize = 32;
pub const DEPOSIT_TREE_HEIGHT: usize = 32;
pub const ASSET_TREE_HEIGHT: usize = 32;
pub const PUBLIC_STATE_TREE_HEIGHT: usize = 32;
pub const TRANSFER_TREE_HEIGHT: usize = 5;

pub const MAX_NUM_USERS_PER_BLOCK: usize = 16;
pub const MAX_NUM_TRANSFERS_PER_TX: usize = 1 << TRANSFER_TREE_HEIGHT;
