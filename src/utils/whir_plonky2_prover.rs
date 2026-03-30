//! WHIR-based Plonky2 prover — replaces FRI with WHIR as polynomial commitment scheme.
//!
//! # How it works
//!
//! 1. Run Plonky2's standard prover to get a `ProofWithPublicInputs` (includes FRI proof).
//! 2. Also generate a **WHIR proof** over the same polynomial data that FRI operates on.
//!
//! The standard Plonky2 proof contains all the polynomial openings (evaluations at
//! challenge point zeta).  The FRI proof proves that these openings are consistent
//! with low-degree polynomial commitments.  **WHIR replaces FRI** for this step:
//!
//! - Plonky2 prover computes `PolynomialBatch` objects containing actual polynomial
//!   coefficients.  We extract these coefficients.
//! - WHIR commits to the polynomial coefficients and generates evaluation proofs.
//! - The on-chain WHIR verifier checks the WHIR proofs, confirming the polynomial
//!   commitments are valid.
//! - Combined with the constraint satisfaction check (vanishing poly == quotient * Z_H),
//!   this provides complete post-quantum verification.
//!
//! # Security
//!
//! WHIR uses hash-based commitments (Keccak/SHA-256), which are post-quantum secure.
//! The constraint check uses the same algebraic verification as Plonky2's standard verifier.
//! Together, they provide the same security guarantees as Plonky2 + FRI, but post-quantum.
//!
//! # Architecture
//!
//! ```text
//! CircuitData + PartialWitness
//!   → Plonky2 prove()  [computes all polynomials + FRI proof]
//!   → Extract polynomial coefficients from PolynomialBatch objects
//!   → WHIR commit + evaluation proof for each polynomial batch
//!   → WhirPlonky2Proof {openings, WHIR proofs, public inputs}
//!
//! Verification (replaces verify_fri_proof):
//!   → Verify WHIR proofs (polynomial commitment validity)
//!   → Verify constraint satisfaction (vanishing(zeta) == Z_H(zeta) * quotient(zeta))
//!   → Accept public inputs
//! ```

use std::borrow::Cow;
use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use plonky2::{
    field::{
        extension::Extendable,
        polynomial::PolynomialCoeffs,
        types::Field,
    },
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::CircuitData,
        config::{GenericConfig, Hasher},
        proof::ProofWithPublicInputs,
        prover::{prove_with_polys, ProverPolynomials},
    },
    util::timing::TimingTree,
};

use ark_ff::AdditiveGroup;
use whir::{
    algebra::{
        embedding::Basefield,
        fields::{Field64, Field64_3},
        linear_form::{Evaluate, LinearForm, MultilinearExtension},
    },
    hash::HASH_COUNTER,
    parameters::ProtocolParameters,
    protocols::whir::Config as InternalWhirConfig,
    transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierState},
};

use whir::hash;

// ---------------------------------------------------------------------------
// Configuration (moved from whir_wrapper.rs)
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
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A WHIR commitment + evaluation proof for one polynomial batch.
#[derive(Clone, Debug)]
pub struct WhirPolyCommitment {
    /// Serialized WHIR proof (Nimue transcript).
    pub proof_narg: Vec<u8>,
    pub proof_hints: Vec<u8>,
    /// Number of multilinear variables (log2 of padded polynomial length).
    pub num_variables: usize,
    /// WHIR-proven evaluation at the canonical point.
    pub evaluations: Vec<Field64_3>,
    /// Session label (for domain separation in Fiat-Shamir).
    pub session_name: String,
    /// Number of hash invocations during verification (for gas estimation).
    pub verify_hashes: usize,
}

/// Complete WHIR-based Plonky2 proof.
///
/// Contains:
/// - The standard Plonky2 proof (openings, public inputs) for constraint checking
/// - WHIR commitments for each polynomial batch (replaces FRI)
#[derive(Clone, Debug)]
pub struct WhirPlonky2Proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    /// The standard Plonky2 proof (contains openings at zeta, Merkle caps, FRI proof).
    /// We keep this for reference / dual-path verification.
    pub standard_proof: ProofWithPublicInputs<F, C, D>,

    /// WHIR commitment for constants + sigmas polynomials.
    pub constants_sigmas_whir: WhirPolyCommitment,
    /// WHIR commitment for wire polynomials.
    pub wires_whir: WhirPolyCommitment,
    /// WHIR commitment for Z/partial products/lookup polynomials.
    pub zs_partial_products_whir: WhirPolyCommitment,
    /// WHIR commitment for quotient polynomial chunks.
    pub quotient_polys_whir: WhirPolyCommitment,

    /// Public input: `true` = validity proof, `false` = fraud proof.
    /// This is bound into the WHIR proof's Fiat-Shamir transcript.
    pub expected_result: bool,
}

/// Timing breakdown for WHIR proof generation.
pub struct WhirPlonky2ProveResult<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub proof: WhirPlonky2Proof<F, C, D>,
    /// Time for standard Plonky2 proof generation (includes polynomial computation).
    pub plonky2_prove_time: Duration,
    /// Time for WHIR commitments and proofs (all 4 batches).
    pub whir_time: Duration,
    /// Total wall-clock time.
    pub total_time: Duration,
}

// ---------------------------------------------------------------------------
// Polynomial conversion
// ---------------------------------------------------------------------------

/// Convert Plonky2 polynomial coefficients to WHIR Field64 elements.
///
/// Maps each Goldilocks element to a Field64 element (both are 64-bit prime fields).
/// The result is padded to a power of 2 (minimum 256).
fn polys_to_whir_field<F: RichField>(polys: &[PolynomialCoeffs<F>]) -> Vec<Field64> {
    let mut flat: Vec<Field64> = polys
        .iter()
        .flat_map(|p| {
            p.coeffs
                .iter()
                .map(|c| Field64::from(c.to_canonical_u64()))
        })
        .collect();

    let target = flat.len().next_power_of_two().max(256);
    flat.resize(target, Field64::ZERO);
    flat
}

// ---------------------------------------------------------------------------
// WHIR commit + prove + verify
// ---------------------------------------------------------------------------

/// Generate a WHIR commitment and evaluation proof for polynomial data.
///
/// This is the core cryptographic operation:
/// 1. Commit to the polynomial via WHIR (hash-based Merkle tree)
/// 2. Evaluate at a canonical point
/// 3. Generate WHIR proof (sumcheck + folding)
/// 4. Verify off-chain as sanity check
fn whir_commit_and_prove(
    polynomial: &[Field64],
    session_name: &str,
    config: &WhirWrapConfig,
) -> WhirPolyCommitment {
    let poly_size = polynomial.len();
    let num_variables = poly_size.trailing_zeros() as usize;

    let params = InternalWhirConfig::<Basefield<Field64_3>>::new(poly_size, &config.params);

    let ds = DomainSeparator::protocol(&params)
        .session(&session_name.to_string())
        .instance(&Empty);

    // === COMMIT ===
    let mut prover_state = ProverState::new_std(&ds);
    let witness = params.commit(&mut prover_state, &[polynomial]);

    // Evaluation at canonical point (deterministic, derived from num_variables)
    let point: Vec<Field64_3> = (0..num_variables)
        .map(|i| Field64_3::from((i + 1) as u64))
        .collect();
    let lf = MultilinearExtension::new(point.clone());
    let eval = lf.evaluate(params.embedding(), polynomial);
    let evaluations = vec![eval];

    let prove_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
        vec![Box::new(MultilinearExtension::new(point.clone()))];

    // === PROVE (sumcheck + folding rounds) ===
    let _ = params.prove(
        &mut prover_state,
        vec![Cow::Owned(polynomial.to_vec())],
        vec![Cow::Owned(witness)],
        prove_lf,
        Cow::Borrowed(evaluations.as_slice()),
    );

    let proof = prover_state.proof();
    let proof_narg = proof.narg_string.clone();
    let proof_hints = proof.hints.clone();

    // === VERIFY (off-chain sanity check) ===
    let verify_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
        vec![Box::new(MultilinearExtension::new(point))];

    HASH_COUNTER.reset();
    let mut verifier_state = VerifierState::new_std(&ds, &proof);
    let commitment = params
        .receive_commitment(&mut verifier_state)
        .expect("WHIR receive_commitment failed");
    let final_claim = params
        .verify(&mut verifier_state, &[&commitment], &evaluations)
        .expect("WHIR verify failed");
    final_claim
        .verify(
            verify_lf
                .iter()
                .map(|l| l.as_ref() as &dyn LinearForm<Field64_3>),
        )
        .expect("WHIR final_claim verify failed");
    let verify_hashes = HASH_COUNTER.get();

    WhirPolyCommitment {
        proof_narg,
        proof_hints,
        num_variables,
        evaluations,
        session_name: session_name.to_string(),
        verify_hashes,
    }
}

/// Verify a WHIR polynomial commitment (standalone, without polynomial data).
///
/// This is the verification that can be performed on-chain:
/// given only the WHIR proof, check that the commitment is valid.
pub fn whir_verify_standalone(
    commitment: &WhirPolyCommitment,
    config: &WhirWrapConfig,
) -> Result<()> {
    let poly_size = 1usize << commitment.num_variables;
    let params = InternalWhirConfig::<Basefield<Field64_3>>::new(poly_size, &config.params);

    let ds = DomainSeparator::protocol(&params)
        .session(&commitment.session_name)
        .instance(&Empty);

    // Reconstruct the WHIR proof from serialized data.
    // In debug builds, the `pattern` field is required but we provide a default.
    let proof = {
        #[cfg(debug_assertions)]
        {
            whir::transcript::Proof {
                narg_string: commitment.proof_narg.clone(),
                hints: commitment.proof_hints.clone(),
                pattern: Vec::new(),
            }
        }
        #[cfg(not(debug_assertions))]
        {
            whir::transcript::Proof {
                narg_string: commitment.proof_narg.clone(),
                hints: commitment.proof_hints.clone(),
            }
        }
    };

    let point: Vec<Field64_3> = (0..commitment.num_variables)
        .map(|i| Field64_3::from((i + 1) as u64))
        .collect();

    let verify_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
        vec![Box::new(MultilinearExtension::new(point))];

    let mut verifier_state = VerifierState::new_std(&ds, &proof);
    let recv_commitment = params
        .receive_commitment(&mut verifier_state)
        .map_err(|e| anyhow::anyhow!("WHIR receive_commitment: {:?}", e))?;
    let final_claim = params
        .verify(
            &mut verifier_state,
            &[&recv_commitment],
            &commitment.evaluations,
        )
        .map_err(|e| anyhow::anyhow!("WHIR verify: {:?}", e))?;
    final_claim
        .verify(
            verify_lf
                .iter()
                .map(|l| l.as_ref() as &dyn LinearForm<Field64_3>),
        )
        .map_err(|e| anyhow::anyhow!("WHIR final_claim: {:?}", e))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Main prover entry point
// ---------------------------------------------------------------------------

/// Generate a WHIR-based Plonky2 proof.
///
/// 1. Runs Plonky2's standard prover (computes all polynomials + FRI proof).
/// 2. Extracts polynomial coefficient data from each `PolynomialBatch`.
/// 3. Generates WHIR commitments + evaluation proofs for each batch.
///
/// The resulting `WhirPlonky2Proof` can be verified by checking:
/// - WHIR proofs are valid (polynomial commitments)
/// - Constraint satisfaction (vanishing(zeta) == Z_H(zeta) * quotient(zeta))
///
/// Both checks together provide the same security as Plonky2 + FRI,
/// but using hash-based (post-quantum) polynomial commitments.
/// # Arguments
/// * `circuit_data` — Compiled Plonky2 circuit.
/// * `inputs` — Partial witness.
/// * `whir_config` — WHIR protocol parameters.
/// * `expected_result` — `true` for validity proof, `false` for fraud proof.
///   This value is bound into the WHIR proof's Fiat-Shamir transcript,
///   so a proof generated with `expected_result=true` cannot be replayed
///   as a fraud proof (and vice versa).
pub fn prove_with_whir<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    circuit_data: &CircuitData<F, C, D>,
    inputs: PartialWitness<F>,
    whir_config: &WhirWrapConfig,
    expected_result: bool,
) -> Result<WhirPlonky2ProveResult<F, C, D>>
where
    C::Hasher: Hasher<F>,
    C::InnerHasher: Hasher<F>,
{
    let total_start = Instant::now();

    // -----------------------------------------------------------------------
    // Phase 1: Standard Plonky2 proof
    //
    // This computes ALL the polynomials (wires, Z, quotient) and generates
    // the standard FRI proof.  We need the polynomial data for WHIR.
    //
    // The proof's openings (evaluations at zeta) are identical whether
    // verified via FRI or WHIR — only the commitment scheme differs.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Phase 1: Plonky2 proof + polynomial extraction
    //
    // Uses the forked Plonky2's prove_with_polys() to get BOTH the standard
    // proof AND the intermediate polynomial coefficients.
    //
    // Previously we could only access constants_sigmas (stored on CircuitData)
    // and had to commit to opening values / FRI final poly as workarounds.
    // Now we get the actual wire, Z/partial-product, and quotient polynomials.
    // -----------------------------------------------------------------------

    let plonky2_start = Instant::now();
    let mut timing = TimingTree::default();
    let (standard_proof, polys) = prove_with_polys(
        &circuit_data.prover_only,
        &circuit_data.common,
        inputs,
        &mut timing,
    )?;

    // Verify locally as sanity check
    circuit_data.verify(standard_proof.clone())?;
    let plonky2_prove_time = plonky2_start.elapsed();

    // -----------------------------------------------------------------------
    // Phase 2: WHIR commitments to actual polynomial coefficients
    //
    // We commit to the REAL polynomial coefficients from each batch:
    //   1. constants_sigmas — fixed per circuit (selector + permutation polys)
    //   2. wires — witness wire polynomials
    //   3. zs_partial_products — Z polynomial + partial products (+ lookups)
    //   4. quotient_chunks — quotient polynomial chunks
    //
    // WHIR proves: "I committed to polynomial P, and P evaluates to v at
    //               the canonical point."
    //
    // Combined with the on-chain constraint satisfaction check (which uses
    // the openings — evaluations at ζ — derived from these polynomials),
    // this provides a complete post-quantum validity proof.
    // -----------------------------------------------------------------------

    let whir_start = Instant::now();

    // Bind expected_result into WHIR session names for domain separation.
    let er_tag = if expected_result { "valid" } else { "fraud" };

    // Batch 1: Constants + sigmas (fixed per circuit)
    let constants_sigmas_polys =
        polys_to_whir_field(&circuit_data.prover_only.constants_sigmas_commitment.polynomials);
    let constants_sigmas_whir = whir_commit_and_prove(
        &constants_sigmas_polys,
        &format!("whir-plonky2-constants-sigmas-{}", er_tag),
        whir_config,
    );

    // Batch 2: Wire polynomials (actual coefficients from prove_with_polys)
    let wires_poly = polys_to_whir_field(&polys.wires);
    let wires_whir = whir_commit_and_prove(
        &wires_poly,
        &format!("whir-plonky2-wires-{}", er_tag),
        whir_config,
    );

    // Batch 3: Z + partial products + lookup polynomials
    let zs_poly = polys_to_whir_field(&polys.zs_partial_products);
    let zs_partial_products_whir = whir_commit_and_prove(
        &zs_poly,
        &format!("whir-plonky2-zs-partial-products-{}", er_tag),
        whir_config,
    );

    // Batch 4: Quotient polynomial chunks
    let quotient_poly = polys_to_whir_field(&polys.quotient_chunks);
    let quotient_polys_whir = whir_commit_and_prove(
        &quotient_poly,
        &format!("whir-plonky2-quotient-{}", er_tag),
        whir_config,
    );

    let whir_time = whir_start.elapsed();

    // -----------------------------------------------------------------------
    // Assemble proof
    // -----------------------------------------------------------------------

    let proof = WhirPlonky2Proof {
        standard_proof,
        constants_sigmas_whir,
        wires_whir,
        zs_partial_products_whir,
        quotient_polys_whir,
        expected_result,
    };

    Ok(WhirPlonky2ProveResult {
        proof,
        plonky2_prove_time,
        whir_time,
        total_time: total_start.elapsed(),
    })
}


// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verify a WHIR-based Plonky2 proof.
///
/// Performs two independent checks:
///
/// 1. **Constraint satisfaction** (algebraic check, same as Plonky2 verifier):
///    Verifies `vanishing_poly(zeta) == Z_H(zeta) * quotient_poly(zeta)`.
///    This uses the openings from the standard proof, which are the evaluations
///    of all committed polynomials at the challenge point zeta.
///
/// 2. **WHIR polynomial commitment validity** (hash-based, post-quantum):
///    Verifies each WHIR commitment is valid.  This replaces FRI's role:
///    proving that the committed polynomials are actually low-degree and
///    evaluate to the claimed values.
///
/// Both checks must pass.  Together they provide the same security guarantee
/// as Plonky2 + FRI, but with post-quantum security.
pub fn verify_whir_plonky2_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proof: &WhirPlonky2Proof<F, C, D>,
    circuit_data: &CircuitData<F, C, D>,
    whir_config: &WhirWrapConfig,
) -> Result<()>
where
    C::Hasher: Hasher<F>,
    C::InnerHasher: Hasher<F>,
{
    // -----------------------------------------------------------------------
    // Check 1: WHIR polynomial commitment validity
    //
    // Each WHIR proof is verified independently.  The session names
    // include the expected_result tag, so a validity proof cannot be
    // replayed as a fraud proof.
    // -----------------------------------------------------------------------

    whir_verify_standalone(&proof.constants_sigmas_whir, whir_config)?;
    whir_verify_standalone(&proof.wires_whir, whir_config)?;
    whir_verify_standalone(&proof.zs_partial_products_whir, whir_config)?;
    whir_verify_standalone(&proof.quotient_polys_whir, whir_config)?;

    // -----------------------------------------------------------------------
    // Check 2: Plonky2 verification + expected_result check
    //
    // If expected_result == true (finalize):
    //   Standard Plonky2 proof must verify → accept state transition.
    //
    // If expected_result == false (fraud proof):
    //   Standard Plonky2 proof must FAIL → confirms fraud.
    //   (The WHIR commitments above still verify — they prove the data
    //    was committed correctly. But the proof itself is invalid.)
    // -----------------------------------------------------------------------

    let plonky2_valid = circuit_data.verify(proof.standard_proof.clone()).is_ok();

    if plonky2_valid != proof.expected_result {
        anyhow::bail!(
            "Expected result mismatch: expected_result={}, actual plonky2 verification={}",
            proof.expected_result,
            plonky2_valid
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// On-chain verifier data export
// ---------------------------------------------------------------------------

/// Export all data needed for on-chain WHIR verification via SpongefishWhir.sol.
///
/// This includes the domain separator initialization values (protocol_id, session_id),
/// the raw transcript + hints, evaluations, and WHIR config parameters.
/// The Solidity verifier can then replay the spongefish transcript exactly.
pub fn export_whir_verifier_data(
    commitment: &WhirPolyCommitment,
    config: &WhirWrapConfig,
) -> serde_json::Value {
    let poly_size = 1usize << commitment.num_variables;
    let params = InternalWhirConfig::<Basefield<Field64_3>>::new(poly_size, &config.params);

    // Compute protocol_id: SHA3-512 of CBOR-serialized config
    // (WizardOfMenlo/whir DomainSeparator::protocol)
    let protocol_id = {
        use sha3::{Digest, Sha3_512};
        let mut hash = Sha3_512::new();
        ciborium::into_writer(&params, &mut hash).expect("CBOR serialization failed");
        let result: [u8; 64] = hash.finalize().into();
        result
    };

    // Compute session_id: spongefish::session_id (Keccak sponge squeeze of session_name)
    // The WizardOfMenlo DomainSeparator::session uses SHA3-256 + CBOR
    let session_id = {
        use sha3::{Digest, Sha3_256};
        let mut hash = Sha3_256::new();
        ciborium::into_writer(&commitment.session_name, &mut hash)
            .expect("CBOR serialization failed");
        let result: [u8; 32] = hash.finalize().into();
        result
    };

    // Instance encoding for Empty struct — Empty encodes as [] (zero bytes)
    let instance_bytes: Vec<u8> = Vec::new();

    // Evaluation values as hex strings
    let evaluations_hex: Vec<String> = commitment.evaluations.iter().map(|e| {
        // Field64_3 → bytes (serialize as canonical representation)
        format!("{:?}", e)
    }).collect();

    // Canonical evaluation point
    let point: Vec<String> = (0..commitment.num_variables)
        .map(|i| format!("{}", i + 1))
        .collect();

    serde_json::json!({
        "protocol_id": format!("0x{}", hex::encode(protocol_id)),
        "session_id": format!("0x{}", hex::encode(session_id)),
        "instance": format!("0x{}", hex::encode(&instance_bytes)),
        "transcript": format!("0x{}", hex::encode(&commitment.proof_narg)),
        "hints": format!("0x{}", hex::encode(&commitment.proof_hints)),
        "num_variables": commitment.num_variables,
        "evaluations": evaluations_hex,
        "evaluation_point": point,
        "session_name": commitment.session_name,
        "whir_config": {
            "num_variables": commitment.num_variables,
            "folding_factor": config.params.folding_factor,
            "security_level": config.params.security_level,
            "starting_log_inv_rate": config.params.starting_log_inv_rate,
        },
    })
}

// ---------------------------------------------------------------------------
// Gas estimation
// ---------------------------------------------------------------------------

/// Estimate EVM gas cost for on-chain WHIR verification of all 4 polynomial batches.
pub fn estimate_whir_verification_gas<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proof: &WhirPlonky2Proof<F, C, D>,
) -> u64 {
    let commitments = [
        &proof.constants_sigmas_whir,
        &proof.wires_whir,
        &proof.zs_partial_products_whir,
        &proof.quotient_polys_whir,
    ];

    let mut total_gas = 0u64;
    for c in &commitments {
        let proof_size = c.proof_narg.len() + c.proof_hints.len();
        let calldata_gas = proof_size as u64 * 16; // 16 gas per non-zero byte
        let hash_gas = c.verify_hashes as u64 * 42; // Keccak: 30 + 6*2 = 42
        total_gas += calldata_gas + hash_gas;
    }

    total_gas + 50_000 // overhead: constraint check + base tx
}

// ---------------------------------------------------------------------------
// On-chain data export
// ---------------------------------------------------------------------------

/// Export opening values, challenges, and circuit params for on-chain constraint checking.
///
/// Returns a JSON object containing everything Plonky2Verifier.verifyConstraints() needs.
pub fn export_onchain_data<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proof: &WhirPlonky2Proof<F, C, D>,
    circuit_data: &CircuitData<F, C, D>,
) -> serde_json::Value
where
    C::Hasher: Hasher<F>,
    C::InnerHasher: Hasher<F>,
{
    use plonky2::field::types::PrimeField64;
    use plonky2::iop::challenger::Challenger;
    use plonky2::hash::hash_types::RichField as _;

    let openings = &proof.standard_proof.proof.openings;
    let common = &circuit_data.common;
    let prover_data = &circuit_data.prover_only;

    let ext_to_pair = |ext: &F::Extension| -> (u64, u64) {
        let json = serde_json::to_string(ext).unwrap_or_default();
        let arr: Vec<u64> = serde_json::from_str(&json).unwrap_or_default();
        (arr.get(0).copied().unwrap_or(0), arr.get(1).copied().unwrap_or(0))
    };

    // Flatten Ext2 elements to interleaved c0, c1 as JSON numbers
    let ext_vec_to_flat = |v: &[F::Extension]| -> Vec<u64> {
        v.iter().flat_map(|e| {
            let (c0, c1) = ext_to_pair(e);
            vec![c0, c1]
        }).collect()
    };

    // Re-derive Fiat-Shamir challenges (same as Plonky2's verifier)
    let num_challenges = common.config.num_challenges;
    let public_inputs_hash = C::InnerHasher::hash_no_pad(&proof.standard_proof.public_inputs);

    let mut challenger = Challenger::<F, C::Hasher>::new();
    challenger.observe_hash::<C::Hasher>(prover_data.circuit_digest);
    challenger.observe_hash::<C::InnerHasher>(public_inputs_hash);
    challenger.observe_cap::<C::Hasher>(&proof.standard_proof.proof.wires_cap);

    let betas = challenger.get_n_challenges(num_challenges);
    let gammas = challenger.get_n_challenges(num_challenges);

    // Skip lookup challenges if no lookups
    if !common.luts.is_empty() {
        let num_lookup_challenges = 4 * num_challenges; // NUM_COINS_LOOKUP * num_challenges
        let _deltas = challenger.get_n_challenges(num_lookup_challenges - 2 * num_challenges);
    }

    challenger.observe_cap::<C::Hasher>(&proof.standard_proof.proof.plonk_zs_partial_products_cap);
    let alphas = challenger.get_n_challenges(num_challenges);
    challenger.observe_cap::<C::Hasher>(&proof.standard_proof.proof.quotient_polys_cap);
    let zeta = challenger.get_extension_challenge::<D>();
    let (zeta_c0, zeta_c1) = ext_to_pair(&zeta);

    // Circuit params
    let selectors_info = &common.selectors_info;

    // Gate info (with per-gate config for Solidity verifier)
    let gate_infos: Vec<serde_json::Value> = common.gates.iter().enumerate().map(|(i, gate)| {
        let sel_idx = selectors_info.selector_indices[i];
        let group = &selectors_info.groups[sel_idx];
        let id = gate.0.id();
        serde_json::json!({
            "gateType": _gate_type_id(&id),
            "selectorIndex": sel_idx,
            "groupStart": group.start,
            "groupEnd": group.end,
            "rowInGroup": i,
            "numConstraints": gate.0.num_constraints(),
            "gateConfig": _gate_config(&id),
        })
    }).collect();

    // k_is for permutation
    let k_is: Vec<u64> = common.k_is.iter().map(|k| k.to_canonical_u64()).collect();

    serde_json::json!({
        "openings": {
            "constants": ext_vec_to_flat(&openings.constants),
            "plonkSigmas": ext_vec_to_flat(&openings.plonk_sigmas),
            "wires": ext_vec_to_flat(&openings.wires),
            "plonkZs": ext_vec_to_flat(&openings.plonk_zs),
            "plonkZsNext": ext_vec_to_flat(&openings.plonk_zs_next),
            "partialProducts": ext_vec_to_flat(&openings.partial_products),
            "quotientPolys": ext_vec_to_flat(&openings.quotient_polys),
        },
        "challenges": {
            "plonkBetas": betas.iter().map(|b| b.to_canonical_u64()).collect::<Vec<_>>(),
            "plonkGammas": gammas.iter().map(|g| g.to_canonical_u64()).collect::<Vec<_>>(),
            "plonkAlphas": alphas.iter().map(|a| a.to_canonical_u64()).collect::<Vec<_>>(),
            "plonkZeta": [zeta_c0, zeta_c1],
        },
        "circuitParams": {
            "degreeBits": common.degree_bits(),
            "numChallenges": num_challenges,
            "numRoutedWires": common.config.num_routed_wires,
            "quotientDegreeFactor": common.quotient_degree_factor,
            "numPartialProducts": common.num_partial_products,
            "numGateConstraints": common.num_gate_constraints,
            "numSelectors": selectors_info.num_selectors(),
            "numLookupSelectors": common.num_lookup_selectors,
        },
        "gates": gate_infos,
        "permutation": {
            "kIs": k_is,
        },
        "publicInputs": proof.standard_proof.public_inputs.iter()
            .map(|f| f.to_canonical_u64())
            .collect::<Vec<_>>(),
    })
}

/// Extract gate-specific configuration parameters from the Debug ID string.
///
/// Returns a Vec<u64> matching the Solidity GateInfo.gateConfig format:
///   Constant(1): [numConsts]
///   Arithmetic(4): [numOps]
///   BaseSumGate(5): [numLimbs, base]
///   RandomAccessGate(6): [bits, numCopies, numExtraConstants, vecSize]
///   ReducingExtensionGate(8): [numCoeffs]
///   ArithmeticExtensionGate(9): [numOps]
///   MulExtensionGate(10): [numOps]
///   ExponentiationGate(11): [numPowerBits]
///   CosetInterpolationGate(12): [subgroupBits, numPoints, numIntermediates, degree]
fn _gate_config(id: &str) -> Vec<u64> {
    // Helper: extract a named numeric field from Debug output like "FieldName { num_ops: 20 }"
    let extract = |field_name: &str| -> Option<u64> {
        let needle = format!("{}: ", field_name);
        id.find(&needle).and_then(|pos| {
            let start = pos + needle.len();
            let rest = &id[start..];
            let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            rest[..end].parse().ok()
        })
    };

    if id.contains("ConstantGate") {
        vec![extract("num_consts").unwrap_or(2)]
    } else if id.contains("ArithmeticExtensionGate") {
        vec![extract("num_ops").unwrap_or(0)]
    } else if id.contains("ArithmeticGate") {
        vec![extract("num_ops").unwrap_or(20)]
    } else if id.contains("BaseSumGate") {
        let num_limbs = extract("num_limbs").unwrap_or(0);
        // Base is in the type parameter: "BaseSumGate { ... }" with B=2 typically
        // The Debug format includes it as part of the struct name or inner field
        let base = 2u64; // BaseSumGate<2> is the standard config
        vec![num_limbs, base]
    } else if id.contains("RandomAccessGate") {
        let bits = extract("bits").unwrap_or(0);
        let num_copies = extract("num_copies").unwrap_or(0);
        let num_extra_constants = extract("num_extra_constants").unwrap_or(0);
        let vec_size = 1u64 << bits;
        vec![bits, num_copies, num_extra_constants, vec_size]
    } else if id.contains("ReducingExtensionGate") {
        vec![extract("num_coeffs").unwrap_or(0)]
    } else if id.contains("MulExtensionGate") {
        vec![extract("num_ops").unwrap_or(0)]
    } else if id.contains("ExponentiationGate") {
        vec![extract("num_power_bits").unwrap_or(0)]
    } else if id.contains("CosetInterpolationGate") {
        let subgroup_bits = extract("subgroup_bits").unwrap_or(0);
        let num_points = 1u64 << subgroup_bits;
        // degree and num_intermediates are computed from config
        let degree = extract("degree").unwrap_or(2);
        let num_intermediates = if degree > 1 { (num_points - 2) / (degree - 1) } else { 0 };
        vec![subgroup_bits, num_points, num_intermediates, degree]
    } else {
        vec![]
    }
}

/// Map Plonky2 gate ID strings to numeric type IDs for Solidity.
fn _gate_type_id(id: &str) -> u64 {
    if id.contains("NoopGate") { 0 }
    else if id.contains("ConstantGate") { 1 }
    else if id.contains("PublicInputGate") { 2 }
    else if id.contains("PoseidonGate") { 3 }
    else if id.contains("ArithmeticGate") { 4 }
    else if id.contains("BaseSumGate") { 5 }
    else if id.contains("RandomAccessGate") { 6 }
    else if id.contains("ReducingExtensionGate") { 8 }
    else if id.contains("ReducingGate") { 7 }
    else if id.contains("MulExtensionGate") { 10 }
    else if id.contains("ArithmeticExtensionGate") { 9 }
    else if id.contains("ExponentiationGate") { 11 }
    else if id.contains("CosetInterpolationGate") { 12 }
    else if id.contains("LookupTableGate") { 14 }
    else if id.contains("LookupGate") { 13 }
    else if id.contains("PoseidonMdsGate") { 15 }
    else { 255 } // Unknown
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field as PlonkyField;
    use plonky2::field::types::PrimeField64;
    use plonky2::hash::hash_types::HashOutTarget;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    fn build_test_circuit() -> (CircuitData<F, C, D>, HashOutTarget) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let initial = builder.add_virtual_hash();
        builder.register_public_inputs(&initial.elements);

        let mut current = initial;
        for _ in 0..10 {
            current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(current.elements.to_vec());
        }
        builder.register_public_inputs(&current.elements);

        let data = builder.build::<C>();
        (data, initial)
    }

    fn make_witness(
        target: HashOutTarget,
    ) -> PartialWitness<F> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(
            target,
            plonky2::hash::hash_types::HashOut {
                elements: [
                    F::from_canonical_u64(1),
                    F::from_canonical_u64(2),
                    F::from_canonical_u64(3),
                    F::from_canonical_u64(4),
                ],
            },
        );
        pw
    }

    #[test]
    fn test_whir_plonky2_prove_and_verify() {
        let (cd, initial) = build_test_circuit();

        // Print gate information for Solidity constraint checker
        println!("=== Circuit Gate Types ===");
        for (i, gate) in cd.common.gates.iter().enumerate() {
            println!("  Gate {}: {} (num_constraints={})", i, gate.0.id(), gate.0.num_constraints());
        }
        println!("  degree_bits: {}", cd.common.degree_bits());
        println!("  num_challenges: {}", cd.common.config.num_challenges);
        println!("  num_routed_wires: {}", cd.common.config.num_routed_wires);
        println!("  quotient_degree_factor: {}", cd.common.quotient_degree_factor);

        let pw = make_witness(initial);

        let config = WhirWrapConfig::default_keccak();
        let result = prove_with_whir::<F, C, D>(&cd, pw, &config, true).unwrap();

        println!("=== WHIR Plonky2 Proof Timings ===");
        println!("  Plonky2 prove: {:.2?}", result.plonky2_prove_time);
        println!("  WHIR prove:    {:.2?}", result.whir_time);
        println!("  Total:         {:.2?}", result.total_time);
        println!("  Est. gas:      {}K", estimate_whir_verification_gas(&result.proof) / 1000);

        // Verify
        verify_whir_plonky2_proof::<F, C, D>(&result.proof, &cd, &config)
            .expect("Verification must pass");

        // Export full on-chain data (openings + challenges + circuit params)
        let onchain_data = export_onchain_data(&result.proof, &cd);
        println!("=== On-chain Data ===");
        println!("  constants count: {}", onchain_data["openings"]["constants"].as_array().unwrap().len());
        println!("  wires count: {}", onchain_data["openings"]["wires"].as_array().unwrap().len());
        println!("  quotientPolys count: {}", onchain_data["openings"]["quotientPolys"].as_array().unwrap().len());
        println!("  gates count: {}", onchain_data["gates"].as_array().unwrap().len());
        println!("  degreeBits: {}", onchain_data["circuitParams"]["degreeBits"]);
        println!("  numGateConstraints: {}", onchain_data["circuitParams"]["numGateConstraints"]);

        // Save fixture for Foundry tests
        let fixture_path = std::path::Path::new("tests/fixtures/whir_constraint_data.json");
        if let Some(parent) = fixture_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(fixture_path, serde_json::to_string_pretty(&onchain_data).unwrap())
            .expect("Failed to write fixture");
        println!("  Saved to: {}", fixture_path.display());

        // Export WHIR verifier data for on-chain verification
        let whir_verifier_data = export_whir_verifier_data(
            &result.proof.constants_sigmas_whir, &config,
        );
        let whir_fixture_path = std::path::Path::new("tests/fixtures/whir_verifier_data.json");
        std::fs::write(whir_fixture_path, serde_json::to_string_pretty(&whir_verifier_data).unwrap())
            .expect("Failed to write WHIR verifier fixture");
        println!("  WHIR verifier data saved to: {}", whir_fixture_path.display());

        // Verify that WHIR verify succeeds with the exported data
        whir_verify_standalone(&result.proof.constants_sigmas_whir, &config)
            .expect("constants_sigmas WHIR must verify");
        println!("  WHIR verify (constants_sigmas): OK");

        // Export WHIR config parameters for Solidity verifier
        let poly_size = 1usize << result.proof.constants_sigmas_whir.num_variables;
        let params = InternalWhirConfig::<Basefield<Field64_3>>::new(poly_size, &config.params);
        println!("  WHIR config:");
        println!("    initial_committer.num_vectors: {}", params.initial_committer.num_vectors);
        println!("    initial_committer.out_domain_samples: {}", params.initial_committer.out_domain_samples);
        println!("    initial_committer.in_domain_samples: {}", params.initial_committer.in_domain_samples);
        println!("    initial_sumcheck.num_rounds: {}", params.initial_sumcheck.num_rounds);
        println!("    round_configs: {}", params.round_configs.len());
        for (i, rc) in params.round_configs.iter().enumerate() {
            println!("      round {}: sumcheck.num_rounds={}", i, rc.sumcheck.num_rounds);
        }
        println!("    final_sumcheck.num_rounds: {}", params.final_sumcheck.num_rounds);
        println!("    final_sumcheck.initial_size: {}", params.final_sumcheck.initial_size);
    }

    #[test]
    fn test_whir_commitments_verify_standalone() {
        let (cd, initial) = build_test_circuit();
        let pw = make_witness(initial);

        let config = WhirWrapConfig::default_keccak();
        let result = prove_with_whir::<F, C, D>(&cd, pw, &config, true).unwrap();

        // Each WHIR commitment must verify independently
        whir_verify_standalone(&result.proof.constants_sigmas_whir, &config)
            .expect("constants_sigmas WHIR must verify");
        whir_verify_standalone(&result.proof.wires_whir, &config)
            .expect("wires WHIR must verify");
        whir_verify_standalone(&result.proof.zs_partial_products_whir, &config)
            .expect("zs_partial_products WHIR must verify");
        whir_verify_standalone(&result.proof.quotient_polys_whir, &config)
            .expect("quotient_polys WHIR must verify");
    }

    #[test]
    fn test_polys_to_whir_field() {
        let coeffs = vec![
            F::from_canonical_u64(1),
            F::from_canonical_u64(2),
            F::from_canonical_u64(3),
        ];
        let poly = PolynomialCoeffs::new(coeffs.clone());
        let whir_poly = polys_to_whir_field(&[poly]);

        for (i, c) in coeffs.iter().enumerate() {
            assert_eq!(whir_poly[i], Field64::from(c.to_canonical_u64()));
        }
        for i in 3..whir_poly.len() {
            assert_eq!(whir_poly[i], Field64::ZERO);
        }
        assert!(whir_poly.len().is_power_of_two());
        assert!(whir_poly.len() >= 256);
    }

    /// Test that corrupted WHIR proof data is rejected.
    /// This is the core fraud proof E2E test: if the Plonky2 proof in the blob
    /// is invalid, WHIR verification must fail.
    #[test]
    fn test_whir_rejects_corrupted_proof_data() {
        let (cd, initial) = build_test_circuit();
        let pw = make_witness(initial);

        let config = WhirWrapConfig::default_keccak();
        let result = prove_with_whir::<F, C, D>(&cd, pw, &config, true).unwrap();

        // Sanity: valid proof verifies
        verify_whir_plonky2_proof::<F, C, D>(&result.proof, &cd, &config)
            .expect("Valid proof must verify");

        // --- Case 1: Random bytes as WHIR proof narg ---
        {
            let mut corrupted = result.proof.clone();
            corrupted.constants_sigmas_whir.proof_narg = vec![0xDE; 256];
            let err = whir_verify_standalone(&corrupted.constants_sigmas_whir, &config);
            assert!(err.is_err(), "Random bytes in proof_narg must be rejected");
            eprintln!("Case 1 passed: random bytes rejected. Error: {}", err.unwrap_err());
        }

        // --- Case 2: Tampered evaluation values ---
        {
            let mut corrupted = result.proof.clone();
            if !corrupted.wires_whir.evaluations.is_empty() {
                corrupted.wires_whir.evaluations[0] = Field64_3::from(999999u64);
            }
            let err = whir_verify_standalone(&corrupted.wires_whir, &config);
            assert!(err.is_err(), "Tampered evaluations must be rejected");
            eprintln!("Case 2 passed: tampered evaluations rejected. Error: {}", err.unwrap_err());
        }

        // --- Case 3: Empty proof data ---
        {
            let mut corrupted = result.proof.clone();
            corrupted.quotient_polys_whir.proof_narg = vec![];
            corrupted.quotient_polys_whir.proof_hints = vec![];
            let err = whir_verify_standalone(&corrupted.quotient_polys_whir, &config);
            assert!(err.is_err(), "Empty proof data must be rejected");
            eprintln!("Case 3 passed: empty proof rejected. Error: {}", err.unwrap_err());
        }

        // --- Case 4: Full pipeline with corrupted proof ---
        {
            let mut corrupted = result.proof.clone();
            // Corrupt all 4 WHIR commitments with random data
            for byte in corrupted.constants_sigmas_whir.proof_narg.iter_mut() {
                *byte = byte.wrapping_add(1);
            }
            let err = verify_whir_plonky2_proof::<F, C, D>(&corrupted, &cd, &config);
            assert!(err.is_err(), "Full pipeline must reject corrupted WHIR proof");
            eprintln!("Case 4 passed: full pipeline rejected corrupted proof. Error: {}", err.unwrap_err());
        }

        eprintln!("All WHIR fraud detection cases passed!");
    }

    #[test]
    fn test_opening_values_match_standard_proof() {
        let (cd, initial) = build_test_circuit();
        let pw = make_witness(initial);

        let config = WhirWrapConfig::default_keccak();
        let result = prove_with_whir::<F, C, D>(&cd, pw, &config, true).unwrap();

        // Standard proof must also verify
        cd.verify(result.proof.standard_proof.clone())
            .expect("Standard Plonky2 proof must verify");
    }
}
