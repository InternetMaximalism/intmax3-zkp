use plonky2::iop::target::Target;

use crate::{
    ethereum_types::bytes32::{Bytes32, Bytes32Target},
    utils::{
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::{
            incremental_merkle_tree::{
                IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
            },
            sparse_merkle_tree::{SparseMerkleProof, SparseMerkleProofTarget, SparseMerkleTree},
        },
    },
};

/// SendTree is a Merkle tree where contains SendLeaf as leaves.
/// SendLeaf is added when user sends a transaction.
pub type SendTree = IncrementalMerkleTree<SendLeaf>;
pub type SendMerkleProof = IncrementalMerkleProof<SendLeaf>;
pub type SendMerkleProofTarget = IncrementalMerkleProofTarget<SendLeafTarget>;

#[derive(Clone, Debug)]
pub struct SendLeaf {
    pub prev: u32,
    pub cur: u32,
    pub tx_tree_root: Bytes32,
}

#[derive(Clone, Debug)]
pub struct SendLeafTarget {
    pub prev: Target,
    pub cur: Target,
    pub tx_tree_root: Bytes32Target,
}

#[derive(Clone, Debug)]
pub struct AccountLeaf {
    pub index: u32,                      // the next index of send leaf
    pub prev: u32,                       // the previous block number
    pub send_tree_root: PoseidonHashOut, // the root of send tree
}

#[derive(Clone, Debug)]
pub struct AccountLeafTarget {
    pub index: Target,                         // the next index of send leaf
    pub prev: Target,                          // the previous block number
    pub send_tree_root: PoseidonHashOutTarget, // the root of send tree
}

/// AccountTree is a Merkle tree where each leaf is an AccountLeaf.
/// The position of each leaf is determined by the global user id (concatenation of aggregator id
/// and account id).
pub type AccountTree = SparseMerkleTree<AccountLeaf>;
pub type AccountMerkleProof = SparseMerkleProof<AccountLeaf>;
pub type AccountMerkleProofTarget = SparseMerkleProofTarget<AccountLeafTarget>;
