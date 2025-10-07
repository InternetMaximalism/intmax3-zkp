use crate::{
    common::{
        block::{Block, BlockError},
        block_number::BlockNumber,
        trees::account_tree::{AccountLeaf, AccountMerkleProof, SendLeaf, SendMerkleProof},
        user_id::{UserId, UserIdError},
    },
    ethereum_types::bytes32::Bytes32,
    utils::{leafable::Leafable as _, poseidon_hash_out::PoseidonHashOut},
};

#[derive(thiserror::Error, Debug)]
pub enum UpdateAccountTreeError {
    #[error("Invalid length: {0}")]
    InvalidLength(String),

    #[error("Block error: {0}")]
    BlockError(#[from] BlockError),

    #[error("User ID error: {0}")]
    UserIdError(#[from] UserIdError),

    #[error("Merkle proof error: {0}")]
    MerkleProofError(String),
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
        if self.prev_account_leaves.len() != self.block.num_users as usize
            || self.account_merkle_proofs.len() != self.block.num_users as usize
            || self.send_merkle_proofs.len() != self.block.num_users as usize
        {
            return Err(UpdateAccountTreeError::InvalidLength(format!(
                "prev_account_leaves length is {}, account_merkle_proofs length is {}, send_merkle_proofs length is {}, but block.num_users is {}",
                self.prev_account_leaves.len(),
                self.account_merkle_proofs.len(),
                self.send_merkle_proofs.len(),
                self.block.num_users,
            )));
        }
        // update hash chain
        let new_block_hash_chain = self.block.hash_with_prev_hash(self.prev_block_hash_chain)?;

        // update account tree
        let mut account_tree_root = self.prev_account_tree_root;
        let aggregator_id = self.block.aggregator_id;
        for (i, &local_id) in self.block.local_ids.iter().enumerate() {
            if local_id == 0 {
                // ignore zero local_id (padding or dummy)
                continue;
            }
            let user_id = UserId::new(aggregator_id, local_id)?;

            let prev_account_leaf = &self.prev_account_leaves[i];
            let account_merkle_proof = &self.account_merkle_proofs[i];
            let send_merkle_proof = &self.send_merkle_proofs[i];

            // verify the inclusion of prev_account_leaf in the account tree
            account_merkle_proof
                .verify(&prev_account_leaf, user_id.0, account_tree_root)
                .map_err(|e| {
                    UpdateAccountTreeError::MerkleProofError(format!(
                        "failed to verify account merkle proof for i {}: {}",
                        i, e
                    ))
                })?;

            // verify the inclusion of empty leaf in the send tree
            send_merkle_proof
                .verify(
                    &SendLeaf::empty_leaf(),
                    prev_account_leaf.index,
                    prev_account_leaf.send_tree_root,
                )
                .map_err(|e| {
                    UpdateAccountTreeError::MerkleProofError(format!(
                        "failed to verify send merkle proof for i {}: {}",
                        i, e
                    ))
                })?;

            // create new send leaf and compute new send tree root
            let new_send_leaf = SendLeaf {
                prev: prev_account_leaf.prev,
                cur: self.block_number,
                tx_tree_root: self.block.tx_tree_root,
            };
            let new_send_tree_root =
                send_merkle_proof.get_root(&new_send_leaf, prev_account_leaf.index);

            // create new account leaf and compute new account tree root
            let new_account_leaf = AccountLeaf {
                index: prev_account_leaf.index + 1,
                prev: self.block_number,
                send_tree_root: new_send_tree_root,
            };
            account_tree_root = account_merkle_proof.get_root(&new_account_leaf, user_id.0);
        }

        Ok(UpdateAccountPublicInputs {
            block_number: self.block_number,
            prev_block_hash_chain: self.prev_block_hash_chain,
            prev_account_tree_root: self.prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root: account_tree_root,
        })
    }
}
