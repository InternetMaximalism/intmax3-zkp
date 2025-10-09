use std::collections::HashMap;

use crate::{
    circuits::validity::block_hash_chain::block_hash_chain_processor::BlockHashChainProcessorWitness,
    common::{
        block::{Block, BlockError},
        deposit::Deposit,
        trees::{
            account_tree::{AccountTree, SendLeaf},
            deposit_tree::DepositTree,
            public_state_tree::PublicStateTree,
        },
        u63::BlockNumber,
        user_id::{UserId, UserIdError},
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
};

#[derive(thiserror::Error, Debug)]
pub enum BlockWitnessGeneratorError {
    #[error("Too many local IDs: {0}")]
    TooManyLocalIds(usize),

    #[error("UserId error: {0}")]
    UserIdError(#[from] UserIdError),

    #[error("Block error: {0}")]
    BlockError(#[from] BlockError),
}

pub struct BlockWitnessGenerator {
    pub block_number: BlockNumber,
    pub account_tree: AccountTree,
    pub send_leaves: HashMap<UserId, Vec<SendLeaf>>,
    pub deposit_tree: DepositTree,
    pub public_state_tree: PublicStateTree,

    pub blocks: Vec<Block>,
    pub deposits: HashMap<BlockNumber, Vec<Deposit>>,
    pub block_hash_chain: Bytes32,
    pub deposit_hash_chain: Bytes32,

    pub block_chain_witness: HashMap<BlockNumber, BlockHashChainProcessorWitness>,
}

impl BlockWitnessGenerator {
    pub fn new() -> Self {
        Self {
            block_number: BlockNumber::default(),
            account_tree: AccountTree::init(),
            send_leaves: HashMap::new(),
            deposit_tree: DepositTree::init(),
            public_state_tree: PublicStateTree::init(),

            blocks: vec![Block::default()], // genesis block
            deposits: HashMap::new(),
            block_hash_chain: Bytes32::default(),
            deposit_hash_chain: Bytes32::default(),

            block_chain_witness: HashMap::new(), // no witness for genesis block
        }
    }

    pub fn add_block(
        &mut self,
        aggregator_id: u32,
        local_ids: &[u32],
        tx_tree_root: Bytes32,
    ) -> Result<(), BlockWitnessGeneratorError> {
        todo!()
    }

    pub fn add_deposit(
        &mut self,
        depositor: Address,
        recipient: Bytes32,
        token_index: u32,
        amount: U256,
        aux_data: Bytes32,
    ) -> Result<(), BlockWitnessGeneratorError> {
        todo!()
    }
}
