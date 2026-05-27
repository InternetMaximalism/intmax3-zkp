pub mod conversion;
pub mod cyclic;
pub mod dummy;
pub mod error;
pub mod hash_chain;
pub mod leafable;
pub mod leafable_hasher;
pub mod logic;
pub mod poseidon_hash_out;
pub mod recursively_verifiable;
pub mod serialize;
pub mod serializer;
pub mod trees;
pub mod wrapper;

/// MLE-based Plonky2 prover — replaces FRI with multilinear PCS.
/// Uses plonky2_mle crate for proving and verification.
#[cfg(not(target_arch = "wasm32"))]
pub mod mle_prover;

/// Groth16 wrapper for Plonky2 proofs via gnark subprocess.
/// Not available on WASM targets.
#[cfg(not(target_arch = "wasm32"))]
pub mod groth16_wrapper;
