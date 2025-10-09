use crate::{
    common::tx::{Tx, TxTarget},
    constants::TX_TREE_HEIGHT,
    utils::trees::sparse_merkle_tree::{
        SparseMerkleProof, SparseMerkleProofTarget, SparseMerkleTree,
    },
};

pub type TxTree = SparseMerkleTree<Tx>;
pub type TxMerkleProof = SparseMerkleProof<Tx>;
pub type TxMerkleProofTarget = SparseMerkleProofTarget<TxTarget>;

impl TxTree {
    pub fn init() -> Self {
        Self::new(TX_TREE_HEIGHT)
    }
}
