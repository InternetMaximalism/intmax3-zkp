use crate::{
    common::tx::{Tx, TxTarget},
    constants::SENT_TX_TREE_HEIGHT,
    utils::trees::incremental_merkle_tree::{
        IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
    },
};

pub type SentTxTree = IncrementalMerkleTree<Tx>;
pub type SentTxMerkleProof = IncrementalMerkleProof<Tx>;
pub type SentTxMerkleProofTarget = IncrementalMerkleProofTarget<TxTarget>;

impl SentTxTree {
    pub fn init() -> Self {
        Self::new(SENT_TX_TREE_HEIGHT)
    }
}
