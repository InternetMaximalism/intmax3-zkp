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

/// WHIR-based Plonky2 prover — replaces FRI with WHIR as PCS.
/// This extracts actual polynomial coefficients from Plonky2's prover
/// and generates WHIR commitments + evaluation proofs over them,
/// providing cryptographically sound post-quantum verification.
/// Requires the `whir` cargo feature.
#[cfg(feature = "whir")]
pub mod whir_plonky2_prover;

/// Groth16 wrapper for Plonky2 proofs via gnark subprocess.
/// Not available on WASM targets.
#[cfg(not(target_arch = "wasm32"))]
pub mod groth16_wrapper;
