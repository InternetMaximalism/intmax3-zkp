// General constants
pub const TOKEN_INDEX_BITS: usize = 32;

// Public State
pub const BLOCK_NUMBER_BITS: usize = 63;
pub const PUBLIC_STATE_TREE_HEIGHT: usize = BLOCK_NUMBER_BITS;
pub const DEPOSIT_TREE_HEIGHT: usize = 63;
pub const AGGREGATOR_ID_BITS: usize = 31;
pub const LOCAL_ID_BITS: usize = 32;
pub const USER_ID_BITS: usize = AGGREGATOR_ID_BITS + LOCAL_ID_BITS;
pub const SEND_TREE_HEIGHT: usize = 32;
pub const ACCOUNT_TREE_HEIGHT: usize = USER_ID_BITS;
pub const MAX_NUM_AGGREGATORS: usize = 1 << AGGREGATOR_ID_BITS;

// Private State
pub const ASSET_TREE_HEIGHT: usize = TOKEN_INDEX_BITS;
pub const NULLIFIER_TREE_HEIGHT: usize = 32;

// Transactions
pub const TRANSFER_TREE_HEIGHT: usize = 6;
pub const MAX_NUM_TRANSFERS_PER_TX: usize = 1 << TRANSFER_TREE_HEIGHT;
pub const TX_TREE_HEIGHT: usize = LOCAL_ID_BITS;

// Blocks
pub const NUM_USERS_BITS: [usize; 3] = [0, 2, 8]; // 1, 4, 256

pub fn get_num_users(len: usize) -> Option<u32> {
    let len_log2 = (len as f32).log2().ceil() as usize;
    let next_in_list = NUM_USERS_BITS.iter().cloned().find(|&x| x >= len_log2);
    next_in_list.map(|x| (1 << x) as u32)
}
