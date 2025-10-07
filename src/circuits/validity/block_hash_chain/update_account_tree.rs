use crate::{
    common::{
        block::Block,
        block_number::BlockNumber,
        trees::account_tree::{AccountLeaf, SendMerkleProof},
    },
    ethereum_types::bytes32::Bytes32,
};

#[derive(thiserror::Error, Debug)]
pub enum UpdateAccountTreeError {
    #[error("Invalid length: {0}")]
    InvalidLength(String),
}

pub struct UpdateAccountTree {
    pub prev_block_hash_chain: Bytes32,

    pub block: Block,

    pub block_number: BlockNumber,
    pub aggregator_id: u32,
    pub local_ids: Vec<u32>,

    pub prev_account_leaves: Vec<AccountLeaf>,
    pub send_merkle_proofs: Vec<SendMerkleProof>,
}

impl UpdateAccountTree {
    pub fn verify(&self) -> Result<(), UpdateAccountTreeError> {
        // if self.local_ids.len() != MAX_NUM_USERS_PER_BLOCK {
        //     return Err(UpdateAccountTreeError::InvalidLength(format!(
        //         "local_ids length is {}, expected {}",
        //         self.local_ids.len(),
        //         MAX_NUM_USERS_PER_BLOCK
        //     )));
        // }
        // if self.send_indices.len() != self.send_merkle_proofs.len() {
        //     return Err(UpdateAccountTreeError::InvalidLength(format!(
        //         "send_indices length is {}, but send_merkle_proofs length is {}",
        //         self.send_indices.len(),
        //         self.send_merkle_proofs.len()
        //     )));
        // }

        Ok(())
    }
}
