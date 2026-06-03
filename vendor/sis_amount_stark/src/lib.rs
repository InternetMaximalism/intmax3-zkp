pub mod air;
pub mod commitment;
pub mod config;
pub mod envelope;
pub mod params;
pub mod prove;
pub mod trace;
pub mod witness;

pub use air::AmountAir;
pub use commitment::{compute_commitment, compute_quotients};
pub use config::{
    ConfigError, DEFAULT_BETA, FriConfigOptions, PROOF_FORMAT_VERSION, PROTOCOL_ID,
    ProofSystemOptions, RangeParameters,
};
pub use envelope::ProofEnvelope;
pub use prove::{
    Error, PreparedSystem, Proof, deserialize_envelope, prepare_system, proof_size_bytes,
    prove_amount, prove_amount_prepared, prove_amount_with_options, serialize_envelope,
    verify_amount, verify_amount_prepared, verify_amount_with_options,
};
pub use trace::generate_trace;
pub use witness::{PublicInputs, Witness};

#[cfg(test)]
mod tests;
