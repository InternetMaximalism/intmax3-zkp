use crate::{
    common::transfer::{Transfer, TransferTarget},
    constants::TRANSFER_TREE_HEIGHT,
    utils::trees::incremental_merkle_tree::{
        IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
    },
};

pub type TransferTree = IncrementalMerkleTree<Transfer>;
pub type TransferMerkleProof = IncrementalMerkleProof<Transfer>;
pub type TransferMerkleProofTarget = IncrementalMerkleProofTarget<TransferTarget>;

impl TransferTree {
    pub fn init() -> Self {
        Self::new(TRANSFER_TREE_HEIGHT)
    }
}
