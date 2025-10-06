use crate::{
    common::{
        deposit::Deposit, salt::Salt, trees::deposit_tree::DepositMerkleProof, user_id::UserId,
    },
    utils::poseidon_hash_out::PoseidonHashOut,
};

#[derive(Debug, thiserror::Error)]
pub enum DepositWitnessError {
    #[error("Invalid deposit index: {0}")]
    InvalidDepositIndex(String),

    #[error("Invalid deposit merkle proof: {0}")]
    InvalidDepositMerkleProof(String),
}

#[derive(Clone, Debug)]
pub struct DepositWitness {
    pub user_id: UserId,
    pub deposit_tree_root: PoseidonHashOut,
    pub deposit_salt: Salt,
    pub deposit: Deposit,
    pub deposit_index: u64,
    pub deposit_merkle_proof: DepositMerkleProof,
}
