use crate::{
    common::{
        block::Block,
        block_number::BlockNumber,
        trees::account_tree::{AccountLeaf, AccountMerkleProof, SendMerkleProof},
    },
    ethereum_types::bytes32::Bytes32,
    utils::poseidon_hash_out::PoseidonHashOut,
};

#[derive(thiserror::Error, Debug)]
pub enum UpdateAccountTreeError {
    #[error("Invalid length: {0}")]
    InvalidLength(String),
}

#[derive(Clone, Debug)]
pub struct UpdateAccountPublicInputs {
    pub block_number: BlockNumber,
    pub prev_block_hash_chain: Bytes32,
    pub prev_account_tree_root: PoseidonHashOut,
    pub new_block_hash_chain: Bytes32,
    pub new_account_tree_root: PoseidonHashOut,
}

#[derive(Clone, Debug)]
pub struct UpdateAccountTree {
    pub prev_block_hash_chain: Bytes32,
    pub prev_account_tree_root: PoseidonHashOut,

    // block number that is being processed
    pub block_number: BlockNumber,

    // contains num_users, which is circuit constant
    pub block: Block,

    // account/send merkle proofs corresponding to local_ids in the block
    pub prev_account_leaves: Vec<AccountLeaf>,
    pub account_merkle_proofs: Vec<AccountMerkleProof>,
    pub send_merkle_proofs: Vec<SendMerkleProof>,
}

impl UpdateAccountTree {
    pub fn to_public_inputs(&self) -> Result<UpdateAccountPublicInputs, UpdateAccountTreeError> {
        todo!()
    }
}
