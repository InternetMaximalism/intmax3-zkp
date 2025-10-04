use crate::{
    ethereum_types::u256::{U256, U256Target},
    utils::trees::sparse_merkle_tree::{
        SparseMerkleProof, SparseMerkleProofTarget, SparseMerkleTree,
    },
};

pub type AssetTree = SparseMerkleTree<U256>;
pub type AssetMerkleProof = SparseMerkleProof<U256>;
pub type AssetMerkleProofTarget = SparseMerkleProofTarget<U256Target>;
