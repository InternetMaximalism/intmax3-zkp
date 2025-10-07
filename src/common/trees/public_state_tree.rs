use crate::{
    common::public_state::{PublicState, PublicStateTarget},
    constants::PUBLIC_STATE_TREE_HEIGHT,
    utils::trees::incremental_merkle_tree::{
        IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
    },
};

pub type PublicStateTree = IncrementalMerkleTree<PublicState>;
pub type PublicStateMerkleProof = IncrementalMerkleProof<PublicState>;
pub type PublicStateMerkleProofTarget = IncrementalMerkleProofTarget<PublicStateTarget>;

impl PublicStateTree {
    pub fn init() -> Self {
        Self::new(PUBLIC_STATE_TREE_HEIGHT)
    }
}
