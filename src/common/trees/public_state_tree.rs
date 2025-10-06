use crate::{
    common::public_state::{PublicState, PublicStateTarget},
    utils::trees::incremental_merkle_tree::{
        IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
    },
};

pub type PublicStateTree = IncrementalMerkleTree<PublicState>;
pub type PublicStateMerkleProof = IncrementalMerkleProof<PublicState>;
pub type PublicStateMerkleProofTarget = IncrementalMerkleProofTarget<PublicStateTarget>;
