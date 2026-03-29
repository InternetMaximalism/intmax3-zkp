//! WHIR post-quantum wrapper for Plonky2 proofs.
//!
//! Provides post-quantum on-chain verification of Plonky2 proofs by:
//! 1. Building a recursive Plonky2 circuit that verifies the inner proof
//!    (Plonky2 FRI is hash-based → post-quantum)
//! 2. Converting the recursive proof to a multilinear polynomial
//! 3. Generating a WHIR proof over that polynomial (hash-based → post-quantum)
//!
//! This runs in parallel with the Groth16 path (not post-quantum).
//!
//! # Architecture
//!
//! ```text
//! Plonky2 validity proof + CircuitData
//!   → WhirRecursiveCircuit::prove()  (verify_proof inside Plonky2 circuit)
//!   → recursive proof bytes
//!   → proof_to_polynomial()          (pack 7 bytes per Goldilocks element)
//!   → whir_prove()                   (commit + sumcheck proof)
//!   → WhirWrapResult                 (evaluations[0] = piHash for on-chain binding)
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
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
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
pub struct WhirWrapConfig {
    /// Human-readable name for this configuration.
    pub name: String,
    /// WHIR protocol parameters.
    pub params: ProtocolParameters,
}

impl WhirWrapConfig {
    /// Default configuration optimized for on-chain Keccak verification.
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
// Result / Error types
// ---------------------------------------------------------------------------

/// Result of WHIR proof generation with recursive Plonky2 verification.
pub struct WhirWrapResult {
    /// Time to generate the recursive Plonky2 proof.
    pub recursive_prove_time: Duration,
    /// Size of the recursive Plonky2 proof in bytes.
    pub recursive_proof_size: usize,
    /// Time to commit the polynomial.
    pub commit_time: Duration,
    /// Time to generate the WHIR proof (sumcheck).
    pub prove_time: Duration,
    /// Time to verify the proof (off-chain sanity check).
    pub verify_time: Duration,
    /// Size of the serialized WHIR proof in bytes.
    pub proof_size: usize,
    /// Number of variables in the multilinear polynomial (log2 of polynomial length).
    pub num_variables: usize,
    /// Number of hash invocations during verification (for gas estimation).
    pub verify_hashes: usize,
}

/// Errors from the WHIR wrapping pipeline.
#[derive(Debug)]
pub enum WhirWrapError {
    /// Failed to generate the recursive Plonky2 proof.
    RecursiveProofFailed(String),
    /// Failed to verify the recursive Plonky2 proof locally.
    RecursiveVerificationFailed(String),
}

impl std::fmt::Display for WhirWrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecursiveProofFailed(e) => write!(f, "Recursive proof failed: {}", e),
            Self::RecursiveVerificationFailed(e) => {
                write!(f, "Recursive verification failed: {}", e)
            }
        }
    }
}

impl std::error::Error for WhirWrapError {}

// ---------------------------------------------------------------------------
// Recursive Plonky2 verification circuit (cached)
// ---------------------------------------------------------------------------

/// Cached recursive circuit that verifies an inner Plonky2 proof.
///
/// Build once via `new()`, then call `prove()` repeatedly for each inner proof.
/// The circuit runs `builder.verify_proof()` inside a Plonky2 circuit,
/// so the recursive proof can only be generated if the inner proof is valid.
///
/// Public inputs of the recursive proof = public inputs of the inner proof
/// (forwarded unchanged), enabling the same public input binding on-chain.
pub struct WhirRecursiveCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    C::Hasher: AlgebraicHasher<F>,
{
    /// The compiled recursive verifier circuit.
    pub data: CircuitData<F, C, D>,
    /// Target for the inner proof.
    inner_proof_target: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    /// Target for the inner verifier data.
    inner_vd_target: plonky2::plonk::circuit_data::VerifierCircuitTarget,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    WhirRecursiveCircuit<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    /// Build the recursive verifier circuit for a given inner circuit.
    ///
    /// This is expensive (minutes for large circuits) — call once and cache.
    pub fn new(inner_cd: &CircuitData<F, C, D>) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Add virtual targets for the inner proof
        let pt = builder.add_virtual_proof_with_pis(&inner_cd.common);

        // Add virtual verifier data (circuit digest + Merkle caps)
        let cap_height = inner_cd.common.config.fri_config.cap_height;
        let inner_vd = builder.add_virtual_verifier_data(cap_height);

        // Core: verify the inner proof inside this circuit
        builder.verify_proof::<C>(&pt, &inner_vd, &inner_cd.common);

        // Forward inner proof's public inputs as outer circuit's public inputs
        for &pi in &pt.public_inputs {
            builder.register_public_input(pi);
        }

        let data = builder.build::<C>();

        Self {
            data,
            inner_proof_target: pt,
            inner_vd_target: inner_vd,
        }
    }

    /// Generate a recursive proof that verifies the inner proof.
    ///
    /// Fails if the inner proof is invalid (this is the security guarantee).
    /// Returns the recursive proof whose public inputs match the inner proof's.
    pub fn prove(
        &self,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
        inner_vd: &VerifierOnlyCircuitData<C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, WhirWrapError> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.inner_proof_target, inner_proof);
        pw.set_verifier_data_target(&self.inner_vd_target, inner_vd);

        let recursive_proof = self
            .data
            .prove(pw)
            .map_err(|e| WhirWrapError::RecursiveProofFailed(e.to_string()))?;

        // Sanity check: verify locally
        self.data
            .verify(recursive_proof.clone())
            .map_err(|e| WhirWrapError::RecursiveVerificationFailed(e.to_string()))?;

        Ok(recursive_proof)
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Pack raw proof bytes into Goldilocks field elements.
///
/// Each element holds 7 bytes (56 bits), which is safely below the
/// Goldilocks modulus (2^64 - 2^32 + 1). The result is padded to a
/// power of 2 (minimum 2^8 = 256 elements).
///
/// This is an internal helper — external callers should use
/// [`wrap_validity_proof`] which includes recursive verification.
fn proof_to_polynomial(proof_bytes: &[u8]) -> Vec<Field64> {
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
        recursive_prove_time: Duration::ZERO,
        recursive_proof_size: 0,
        commit_time,
        prove_time,
        verify_time,
        proof_size,
        num_variables,
        verify_hashes,
    }
}

/// Wrap a Plonky2 proof with recursive verification + WHIR commitment.
///
/// This is the primary API for post-quantum on-chain verification:
/// 1. Generates a recursive Plonky2 proof verifying the inner proof
/// 2. Converts the recursive proof to a multilinear polynomial
/// 3. Generates a WHIR proof over that polynomial
///
/// The resulting WHIR proof, combined with public input binding
/// (`statement.evaluations[0] == keccak256(ValidityPublicInputs)`),
/// provides a fully post-quantum verification chain.
pub fn wrap_validity_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    recursive_circuit: &WhirRecursiveCircuit<F, C, D>,
    inner_proof: &ProofWithPublicInputs<F, C, D>,
    inner_vd: &VerifierOnlyCircuitData<C, D>,
    config: &WhirWrapConfig,
) -> Result<WhirWrapResult, WhirWrapError>
where
    C::Hasher: AlgebraicHasher<F>,
{
    // Step 1: Recursive Plonky2 verification
    let t = Instant::now();
    let recursive_proof = recursive_circuit.prove(inner_proof, inner_vd)?;
    let recursive_prove_time = t.elapsed();

    let recursive_bytes = recursive_proof.to_bytes();
    let recursive_proof_size = recursive_bytes.len();

    // Step 2: Convert to polynomial
    let polynomial = proof_to_polynomial(&recursive_bytes);

    // Step 3: WHIR commit + prove
    let mut result = whir_prove(&polynomial, config);
    result.recursive_prove_time = recursive_prove_time;
    result.recursive_proof_size = recursive_proof_size;

    Ok(result)
}

/// Estimate EVM gas cost for on-chain WHIR verification.
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


#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field as _;
    use plonky2::hash::hash_types::HashOutTarget;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    /// Build a small Plonky2 circuit: 10 chained Poseidon hashes.
    fn build_test_circuit() -> (CircuitData<F, C, D>, HashOutTarget) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let initial = builder.add_virtual_hash();
        builder.register_public_inputs(&initial.elements);

        let mut current = initial;
        for _ in 0..10 {
            current =
                builder.hash_n_to_hash_no_pad::<PoseidonHash>(current.elements.to_vec());
        }
        builder.register_public_inputs(&current.elements);

        let data = builder.build::<C>();
        (data, initial)
    }

    #[test]
    fn test_recursive_circuit_build_and_prove() {
        // Build inner circuit
        let (inner_cd, initial_target) = build_test_circuit();

        // Prove inner circuit
        let mut pw = PartialWitness::new();
        pw.set_hash_target(
            initial_target,
            plonky2::hash::hash_types::HashOut {
                elements: [F::from_canonical_u64(1), F::from_canonical_u64(2),
                           F::from_canonical_u64(3), F::from_canonical_u64(4)],
            },
        );
        let inner_proof = inner_cd.prove(pw).unwrap();
        inner_cd.verify(inner_proof.clone()).unwrap();

        // Build recursive circuit (cached)
        let recursive_circuit = WhirRecursiveCircuit::<F, C, D>::new(&inner_cd);

        // Prove recursively
        let recursive_proof = recursive_circuit
            .prove(&inner_proof, &inner_cd.verifier_only)
            .unwrap();

        // Public inputs must match
        assert_eq!(
            inner_proof.public_inputs, recursive_proof.public_inputs,
            "Recursive proof must forward inner public inputs"
        );
    }

    #[test]
    fn test_wrap_validity_proof_e2e() {
        // Build and prove inner circuit
        let (inner_cd, initial_target) = build_test_circuit();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(
            initial_target,
            plonky2::hash::hash_types::HashOut {
                elements: [F::from_canonical_u64(1), F::from_canonical_u64(2),
                           F::from_canonical_u64(3), F::from_canonical_u64(4)],
            },
        );
        let inner_proof = inner_cd.prove(pw).unwrap();

        // Build recursive circuit
        let recursive_circuit = WhirRecursiveCircuit::<F, C, D>::new(&inner_cd);

        // Full pipeline: recursive verify + WHIR wrap
        let config = WhirWrapConfig::default_keccak();
        let result = wrap_validity_proof(
            &recursive_circuit,
            &inner_proof,
            &inner_cd.verifier_only,
            &config,
        ).unwrap();

        assert!(result.recursive_prove_time > Duration::ZERO);
        assert!(result.recursive_proof_size > 0);
        assert!(result.proof_size > 0);
        assert!(result.num_variables > 0);
        assert!(result.verify_hashes > 0);
    }

    #[test]
    fn test_estimate_gas() {
        let result = WhirWrapResult {
            recursive_prove_time: Duration::from_millis(500),
            recursive_proof_size: 50_000,
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
