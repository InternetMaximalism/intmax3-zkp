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

/// WHIR-based Plonky2 prover — re-exported from plonky2-whir-verifier submodule.
/// Requires the `whir` cargo feature.
#[cfg(feature = "whir")]
pub use plonky2_whir_verifier::prover as whir_plonky2_prover;

/// Groth16 wrapper for Plonky2 proofs via gnark subprocess.
/// Not available on WASM targets.
#[cfg(not(target_arch = "wasm32"))]
pub mod groth16_wrapper;
