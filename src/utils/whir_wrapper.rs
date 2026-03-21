//! WHIR post-quantum wrapper for Plonky2 proofs.
//!
//! Converts a serialized Plonky2 proof into a WHIR polynomial commitment proof
//! suitable for on-chain verification via `sol-whir`.
//!
//! # Architecture
//!
//! ```text
//! Plonky2 proof bytes
//!   → proof_to_polynomial()   (pack 7 bytes per Goldilocks element)
//!   → whir_prove()            (commit + sumcheck proof)
//!   → WhirWrapResult          (proof bytes + transcript for Solidity)
//! ```
//!
//! # Feature gate
//!
//! This module is only available with the `whir` cargo feature:
//! ```toml
//! intmax3-zkp = { ..., features = ["whir"] }
//! ```

use std::borrow::Cow;
use std::time::{Duration, Instant};

use ark_ff::AdditiveGroup;
use whir::{
    algebra::{
        embedding::Basefield,
        fields::{Field64, Field64_3},
        linear_form::{Evaluate, LinearForm, MultilinearExtension},
    },
    hash,
    hash::HASH_COUNTER,
    parameters::ProtocolParameters,
    protocols::whir::Config as InternalWhirConfig,
    transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierState},
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// WHIR wrapping configuration.
///
/// Wraps `whir::parameters::ProtocolParameters` with a human-readable name
/// and sensible defaults for on-chain verification.
pub struct WhirWrapConfig {
    /// Human-readable name for this configuration.
    pub name: String,
    /// WHIR protocol parameters.
    pub params: ProtocolParameters,
}

impl WhirWrapConfig {
    /// Default configuration optimized for on-chain Keccak verification.
    ///
    /// - Keccak hash (native EVM opcode = cheapest on-chain)
    /// - No proof-of-work (PoW is prohibitively expensive on-chain)
    /// - List decoding (fewer queries needed)
    /// - 100-bit security level
    pub fn default_keccak() -> Self {
        Self {
            name: "keccak-rate2".to_string(),
            params: ProtocolParameters {
                security_level: 100,
                pow_bits: 0,
                initial_folding_factor: 4,
                folding_factor: 4,
                unique_decoding: false,
                starting_log_inv_rate: 2,
                batch_size: 1,
                hash_id: hash::KECCAK,
            },
        }
    }

    /// Lower security configuration (80-bit) for faster proofs / smaller proofs.
    pub fn keccak_sec80() -> Self {
        Self {
            name: "keccak-sec80".to_string(),
            params: ProtocolParameters {
                security_level: 80,
                pow_bits: 0,
                initial_folding_factor: 4,
                folding_factor: 4,
                unique_decoding: false,
                starting_log_inv_rate: 2,
                batch_size: 1,
                hash_id: hash::KECCAK,
            },
        }
    }

    /// Higher folding factor for potentially better tradeoffs.
    pub fn keccak_f8() -> Self {
        Self {
            name: "keccak-f8".to_string(),
            params: ProtocolParameters {
                security_level: 100,
                pow_bits: 0,
                initial_folding_factor: 8,
                folding_factor: 4,
                unique_decoding: false,
                starting_log_inv_rate: 1,
                batch_size: 1,
                hash_id: hash::KECCAK,
            },
        }
    }

    /// All predefined configurations for benchmarking.
    pub fn all_configs() -> Vec<Self> {
        vec![
            Self {
                name: "keccak-f4".to_string(),
                params: ProtocolParameters {
                    security_level: 100,
                    pow_bits: 0,
                    initial_folding_factor: 4,
                    folding_factor: 4,
                    unique_decoding: false,
                    starting_log_inv_rate: 1,
                    batch_size: 1,
                    hash_id: hash::KECCAK,
                },
            },
            Self::keccak_f8(),
            Self::default_keccak(),
            Self {
                name: "keccak-unique".to_string(),
                params: ProtocolParameters {
                    security_level: 100,
                    pow_bits: 0,
                    initial_folding_factor: 4,
                    folding_factor: 4,
                    unique_decoding: true,
                    starting_log_inv_rate: 1,
                    batch_size: 1,
                    hash_id: hash::KECCAK,
                },
            },
            Self {
                name: "keccak-rate3".to_string(),
                params: ProtocolParameters {
                    security_level: 100,
                    pow_bits: 0,
                    initial_folding_factor: 4,
                    folding_factor: 4,
                    unique_decoding: false,
                    starting_log_inv_rate: 3,
                    batch_size: 1,
                    hash_id: hash::KECCAK,
                },
            },
            Self::keccak_sec80(),
        ]
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of WHIR proof generation.
pub struct WhirWrapResult {
    /// Time to commit the polynomial.
    pub commit_time: Duration,
    /// Time to generate the WHIR proof (sumcheck).
    pub prove_time: Duration,
    /// Time to verify the proof (off-chain sanity check).
    pub verify_time: Duration,
    /// Size of the serialized proof in bytes.
    pub proof_size: usize,
    /// Number of variables in the multilinear polynomial (log2 of polynomial length).
    pub num_variables: usize,
    /// Number of hash invocations during verification (for gas estimation).
    pub verify_hashes: usize,
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Pack raw proof bytes into Goldilocks field elements.
///
/// Each element holds 7 bytes (56 bits), which is safely below the
/// Goldilocks modulus (2^64 - 2^32 + 1). The result is padded to a
/// power of 2 (minimum 2^8 = 256 elements).
pub fn proof_to_polynomial(proof_bytes: &[u8]) -> Vec<Field64> {
    const BYTES_PER_ELEM: usize = 7;

    let mut poly: Vec<Field64> = proof_bytes
        .chunks(BYTES_PER_ELEM)
        .map(|chunk| {
            let mut val = 0u64;
            for (i, &b) in chunk.iter().enumerate() {
                val |= (b as u64) << (8 * i);
            }
            Field64::from(val)
        })
        .collect();

    // Pad to next power of 2 (minimum 256)
    let target = poly.len().next_power_of_two().max(256);
    poly.resize(target, Field64::ZERO);
    poly
}

/// Generate a WHIR proof over a polynomial.
///
/// Performs commit → prove → verify (sanity check) and returns timing
/// information plus the proof size.
pub fn whir_prove(polynomial: &[Field64], config: &WhirWrapConfig) -> WhirWrapResult {
    let poly_size = polynomial.len();
    let num_variables = poly_size.trailing_zeros() as usize;

    let params = InternalWhirConfig::<Basefield<Field64_3>>::new(poly_size, &config.params);

    let ds = DomainSeparator::protocol(&params)
        .session(&format!("whir-{}", config.name))
        .instance(&Empty);

    // === COMMIT ===
    let t = Instant::now();
    let mut prover_state = ProverState::new_std(&ds);
    let witness = params.commit(&mut prover_state, &[polynomial]);
    let commit_time = t.elapsed();

    // Evaluation point
    let point: Vec<Field64_3> = (0..num_variables)
        .map(|i| Field64_3::from((i + 1) as u64))
        .collect();
    let lf = MultilinearExtension::new(point.clone());
    let eval = lf.evaluate(params.embedding(), polynomial);
    let evaluations = vec![eval];

    let prove_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
        vec![Box::new(MultilinearExtension::new(point.clone()))];

    // === PROVE ===
    let t = Instant::now();
    let _ = params.prove(
        &mut prover_state,
        vec![Cow::Owned(polynomial.to_vec())],
        vec![Cow::Owned(witness)],
        prove_lf,
        Cow::Borrowed(evaluations.as_slice()),
    );
    let prove_time = t.elapsed();

    let proof = prover_state.proof();
    let proof_size = proof.narg_string.len() + proof.hints.len();

    // === VERIFY (off-chain sanity check with hash counting) ===
    let verify_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
        vec![Box::new(MultilinearExtension::new(point.clone()))];

    HASH_COUNTER.reset();
    let t = Instant::now();
    let mut verifier_state = VerifierState::new_std(&ds, &proof);
    let commitment = params.receive_commitment(&mut verifier_state).unwrap();
    let final_claim = params
        .verify(&mut verifier_state, &[&commitment], &evaluations)
        .unwrap();
    final_claim
        .verify(
            verify_lf
                .iter()
                .map(|l| l.as_ref() as &dyn LinearForm<Field64_3>),
        )
        .unwrap();
    let verify_time = t.elapsed();
    let verify_hashes = HASH_COUNTER.get();

    WhirWrapResult {
        commit_time,
        prove_time,
        verify_time,
        proof_size,
        num_variables,
        verify_hashes,
    }
}

/// Estimate EVM gas cost for on-chain WHIR verification.
///
/// Components:
/// - Calldata: 16 gas per byte (worst case, all non-zero)
/// - Hash operations: Keccak=42, SHA256=84, other=10000 gas per call
/// - Fixed overhead: 5000 gas (base tx, field ops, sumcheck)
pub fn estimate_gas(result: &WhirWrapResult, hash_name: &str) -> u64 {
    let calldata_gas = result.proof_size as u64 * 16;

    let per_hash_gas: u64 = match hash_name {
        "keccak" => 42,
        "sha256" => 84,
        _ => 10_000,
    };
    let hash_gas = result.verify_hashes as u64 * per_hash_gas;

    let overhead = 5_000u64;

    calldata_gas + hash_gas + overhead
}

/// High-level convenience: wrap raw Plonky2 proof bytes into a WHIR proof.
///
/// Uses the default Keccak configuration optimized for on-chain verification.
/// Returns the wrap result including timing and proof size.
///
/// # Example
///
/// ```ignore
/// let proof_bytes = plonky2_proof.to_bytes();
/// let result = wrap_proof(&proof_bytes);
/// println!("WHIR proof size: {} bytes", result.proof_size);
/// println!("Estimated gas: {}K", estimate_gas(&result, "keccak") / 1000);
/// ```
pub fn wrap_proof(proof_bytes: &[u8]) -> WhirWrapResult {
    let config = WhirWrapConfig::default_keccak();
    let polynomial = proof_to_polynomial(proof_bytes);
    whir_prove(&polynomial, &config)
}

/// Benchmark all WHIR configurations and return results sorted by gas cost.
pub fn benchmark_all_configs(proof_bytes: &[u8]) -> Vec<(String, WhirWrapResult, u64)> {
    let polynomial = proof_to_polynomial(proof_bytes);
    let configs = WhirWrapConfig::all_configs();

    let mut results: Vec<(String, WhirWrapResult, u64)> = configs
        .iter()
        .map(|config| {
            let r = whir_prove(&polynomial, config);
            let hash_type = if config.name.starts_with("keccak") {
                "keccak"
            } else {
                "blake3"
            };
            let gas = estimate_gas(&r, hash_type);
            (config.name.clone(), r, gas)
        })
        .collect();

    results.sort_by_key(|(_, _, gas)| *gas);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_to_polynomial_basic() {
        // 14 bytes → 2 elements (7 bytes each), padded to 256
        let data = vec![0xAB; 14];
        let poly = proof_to_polynomial(&data);
        assert_eq!(poly.len(), 256); // padded to power of 2
    }

    #[test]
    fn test_proof_to_polynomial_packing() {
        // First 7 bytes: [1, 0, 0, 0, 0, 0, 0] → value 1
        let mut data = vec![0u8; 7];
        data[0] = 1;
        let poly = proof_to_polynomial(&data);
        assert_eq!(poly[0], Field64::from(1u64));
    }

    #[test]
    fn test_whir_wrap_roundtrip() {
        // Generate a small dummy "proof" (just random bytes)
        let dummy_proof = vec![42u8; 1024];
        let result = wrap_proof(&dummy_proof);

        assert!(result.proof_size > 0);
        assert!(result.num_variables > 0);
        assert!(result.verify_hashes > 0);
        // Verify completed without panic → proof is valid
    }

    #[test]
    fn test_estimate_gas() {
        let result = WhirWrapResult {
            commit_time: Duration::from_millis(100),
            prove_time: Duration::from_millis(200),
            verify_time: Duration::from_millis(50),
            proof_size: 10_000,
            num_variables: 14,
            verify_hashes: 500,
        };

        let gas = estimate_gas(&result, "keccak");
        // 10000 * 16 + 500 * 42 + 5000 = 160000 + 21000 + 5000 = 186000
        assert_eq!(gas, 186_000);
    }
}
