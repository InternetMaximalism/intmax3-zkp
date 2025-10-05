use crate::{
    common::tx::{Tx, TxTarget},
    utils::trees::incremental_merkle_tree::{
        IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
    },
};

pub type TxTree = IncrementalMerkleTree<Tx>;
pub type TxMerkleProof = IncrementalMerkleProof<Tx>;
pub type TxMerkleProofTarget = IncrementalMerkleProofTarget<TxTarget>;
