#[derive(Debug, thiserror::Error)]
pub enum CommonError {
    #[error("Failed to verify tx merkle proof: {0}")]
    TxMerkleProofVerificationFailed(String),

    #[error("Missing data: {0}")]
    MissingData(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Nullifier already exists: {0}")]
    NullifierAlreadyExists(String),

    #[error("Invalid spent value: {0}")]
    InvalidSpentValue(String),

    #[error("Genesis block is not allowed")]
    GenesisBlockNotAllowed,

    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),
}
