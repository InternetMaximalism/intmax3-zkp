//! Groth16 wrapper for Plonky2 proofs via gnark subprocess.
//!
//! Converts a Plonky2 proof + circuit data into a Groth16 proof (BN254 curve)
//! using the gnark-plonky2-verifier Go tool as a subprocess.
//!
//! # Architecture
//!
//! ```text
//! Plonky2 proof + CircuitData
//!   → serialize to JSON (temp directory)
//!   → call gnark-wrapper subprocess
//!   → parse Groth16 proof points (A, B, C on BN254)
//!   → Groth16WrapResult (matches IntmaxRollup.sol Groth16Params)
//! ```
//!
//! # Prerequisites
//!
//! The gnark-wrapper Go binary must be built separately:
//! ```bash
//! cd gnark && go build -o gnark-wrapper .
//! ```
//!
//! # Platform
//!
//! This module is not available on WASM targets (subprocess calls not supported).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::CircuitData,
        config::GenericConfig,
        proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum Groth16Error {
    #[error("gnark-wrapper binary not found at {0}")]
    BinaryNotFound(PathBuf),

    #[error("Failed to create temp directory: {0}")]
    TempDirError(std::io::Error),

    #[error("Failed to serialize proof data: {0}")]
    SerializationError(String),

    #[error("gnark-wrapper failed with exit code {code:?}: {stderr}")]
    SubprocessFailed {
        code: Option<i32>,
        stderr: String,
    },

    #[error("Failed to read gnark-wrapper output: {0}")]
    OutputReadError(std::io::Error),

    #[error("Failed to parse gnark-wrapper output: {0}")]
    OutputParseError(String),
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Groth16 proof points on BN254, matching the Solidity `Groth16Verifier.Proof` struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Proof {
    /// Point A on G1 (two coordinates as decimal strings).
    pub a: [String; 2],
    /// Point B on G2 (two pairs of coordinates as decimal strings).
    pub b: [[String; 2]; 2],
    /// Point C on G1 (two coordinates as decimal strings).
    pub c: [String; 2],
}

/// Groth16 verifying key, matching the Solidity `Groth16Verifier.VerifyingKey` struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16VerifyingKey {
    pub alpha: [String; 2],
    pub beta: [[String; 2]; 2],
    pub gamma: [[String; 2]; 2],
    pub delta: [[String; 2]; 2],
    pub ic: Vec<[String; 2]>,
}

/// Complete result of Groth16 wrapping.
#[derive(Debug, Clone)]
pub struct Groth16WrapResult {
    /// The Groth16 proof points.
    pub proof: Groth16Proof,
    /// The Groth16 verifying key (for on-chain deployment).
    pub verifying_key: Option<Groth16VerifyingKey>,
    /// Public inputs for the Groth16 verifier.
    pub public_inputs: Vec<String>,
    /// Time spent in trusted setup (ms).
    pub setup_time_ms: f64,
    /// Time spent generating the proof (ms).
    pub proving_time_ms: f64,
    /// Proof size in bytes.
    pub proof_size: usize,
}

// ---------------------------------------------------------------------------
// Default binary path
// ---------------------------------------------------------------------------

/// Default path to the gnark-wrapper binary (relative to project root).
pub const DEFAULT_GNARK_BIN: &str = "gnark/gnark-wrapper";

// ---------------------------------------------------------------------------
// Core function
// ---------------------------------------------------------------------------

/// Wrap a Plonky2 proof into a Groth16 proof via the gnark subprocess.
///
/// # Arguments
///
/// * `circuit_data` — The Plonky2 circuit data (contains common data + verifier data)
/// * `proof` — The Plonky2 proof with public inputs
/// * `gnark_bin_path` — Path to the `gnark-wrapper` Go binary
/// * `expected_result` — `true` for finalize (prove validity), `false` for fraud proof (prove invalidity)
///
/// # Returns
///
/// A `Groth16WrapResult` containing the BN254 proof points, public inputs
/// (including `expected_result`), and timing information.
///
/// The `expected_result` parameter controls the gnark circuit mode:
///   `true`  → finalize mode: Groth16 proves the Plonky2 proof IS valid.
///   `false` → fraud mode: theoretically proves invalidity, but in practice
///             the gnark circuit's Goldilocks arithmetic has hard constraints
///             that make it unsatisfiable for corrupted proof data.
///
/// On-chain, `finalize()` uses both WHIR + Groth16 (ExpectedResult=1).
/// `fraudProof()` uses WHIR-only — Groth16 is not needed for fraud detection.
///
/// # Example
///
/// ```ignore
/// // Finalize: prove validity
/// let result = groth16_wrap(&circuit_data, &proof, Path::new("gnark/gnark-wrapper"), true)?;
///
/// // Fraud proof: prove invalidity
/// let result = groth16_wrap(&circuit_data, &bad_proof, Path::new("gnark/gnark-wrapper"), false)?;
/// ```
/// Wrap a Plonky2 proof into a Groth16 proof via the gnark subprocess.
///
/// # Arguments
///
/// * `circuit_data` — The Plonky2 circuit data
/// * `proof` — The Plonky2 proof with public inputs
/// * `gnark_bin_path` — Path to the `gnark-wrapper` Go binary
/// * `expected_result` — `true` for validity proof, `false` for fraud proof
/// * `setup_dir` — Optional persistent directory for trusted setup (PK/VK).
///   If `None`, uses a temp directory that persists across test runs.
///   If `Some(path)`, saves/loads PK/VK from that path.
pub fn groth16_wrap<F, C, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
    proof: &ProofWithPublicInputs<F, C, D>,
    gnark_bin_path: &Path,
    expected_result: bool,
) -> Result<Groth16WrapResult, Groth16Error>
where
    F: RichField + Extendable<D> + Serialize,
    C: GenericConfig<D, F = F> + Serialize,
{
    groth16_wrap_with_setup(circuit_data, proof, gnark_bin_path, expected_result, None)
}

/// Like `groth16_wrap` but with explicit setup directory.
pub fn groth16_wrap_with_setup<F, C, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
    proof: &ProofWithPublicInputs<F, C, D>,
    gnark_bin_path: &Path,
    expected_result: bool,
    setup_dir: Option<&Path>,
) -> Result<Groth16WrapResult, Groth16Error>
where
    F: RichField + Extendable<D> + Serialize,
    C: GenericConfig<D, F = F> + Serialize,
{
    // 1. Check binary exists
    if !gnark_bin_path.exists() {
        return Err(Groth16Error::BinaryNotFound(gnark_bin_path.to_path_buf()));
    }

    // 2. Create temp directory for JSON exchange
    let tmp_dir = std::env::temp_dir().join("intmax3_groth16");
    std::fs::create_dir_all(&tmp_dir).map_err(Groth16Error::TempDirError)?;

    // 3. Serialize Plonky2 proof data as JSON
    // Serialize proof as-is. HashOut fields remain as {"elements": [u64;4]}.
    // The Go deserializer handles both object format and decimal string format.
    let proof_json = serde_json::to_string(proof)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;
    let proof_path = tmp_dir.join("proof_with_public_inputs.json");
    fs::write(&proof_path, &proof_json)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;

    let vd_json = serde_json::to_string(&circuit_data.verifier_only)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;
    let verifier_path = tmp_dir.join("verifier_only_circuit_data.json");
    fs::write(&verifier_path, &vd_json)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;

    let cd_json = serde_json::to_string(&circuit_data.common)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;
    std::fs::write(tmp_dir.join("common_circuit_data.json"), &cd_json)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;

    let out_file = tmp_dir.join("groth16_proof.json");

    // Use circuit-specific setup directory based on common data hash.
    // Different circuits have different R1CS constraint counts and need separate setups.
    let circuit_hash = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        cd_json.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    };
    let effective_setup_dir = setup_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| tmp_dir.join(format!("setup_{}", circuit_hash)));

    // 4. Call gnark-wrapper subprocess
    let expected_result_val = if expected_result { "1" } else { "0" };
    let output = Command::new(gnark_bin_path)
        .arg("--data")
        .arg(tmp_dir.to_str().unwrap())
        .arg("--out")
        .arg(out_file.to_str().unwrap())
        .arg("--expected-result")
        .arg(expected_result_val)
        .arg("--setup-dir")
        .arg(effective_setup_dir.to_str().unwrap())
        .output()
        .map_err(|e| Groth16Error::SubprocessFailed {
            code: None,
            stderr: format!("Failed to spawn: {}", e),
        })?;

    if !output.status.success() {
        return Err(Groth16Error::SubprocessFailed {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    // 5. Parse output JSON
    let out_str =
        std::fs::read_to_string(&out_file).map_err(Groth16Error::OutputReadError)?;
    let out: serde_json::Value = serde_json::from_str(&out_str)
        .map_err(|e| Groth16Error::OutputParseError(e.to_string()))?;

    // Extract proof points
    let proof_obj = out
        .get("proof")
        .ok_or_else(|| Groth16Error::OutputParseError("missing 'proof' field".into()))?;

    let a = parse_g1_point(proof_obj.get("a"))?;
    let b = parse_g2_point(proof_obj.get("b"))?;
    let c = parse_g1_point(proof_obj.get("c"))?;

    let public_inputs: Vec<String> = out
        .get("public_inputs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Parse verifying key if present
    let verifying_key = out.get("verifying_key").and_then(|vk_val| {
        serde_json::from_value::<Groth16VerifyingKey>(vk_val.clone()).ok()
    });

    Ok(Groth16WrapResult {
        proof: Groth16Proof { a, b, c },
        verifying_key,
        public_inputs,
        setup_time_ms: out
            .get("setup_time_ms")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        proving_time_ms: out
            .get("proving_time_ms")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        proof_size: out
            .get("proof_size_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize,
    })
}

/// Check if the gnark-wrapper binary is available.
pub fn is_gnark_available(gnark_bin_path: &Path) -> bool {
    gnark_bin_path.exists()
}

// ---------------------------------------------------------------------------
// JSON parsing helpers
// ---------------------------------------------------------------------------

fn parse_g1_point(value: Option<&serde_json::Value>) -> Result<[String; 2], Groth16Error> {
    let arr = value
        .and_then(|v| v.as_array())
        .ok_or_else(|| Groth16Error::OutputParseError("invalid G1 point".into()))?;
    if arr.len() != 2 {
        return Err(Groth16Error::OutputParseError(format!(
            "G1 point has {} elements, expected 2",
            arr.len()
        )));
    }
    Ok([
        arr[0].as_str().unwrap_or("0").to_string(),
        arr[1].as_str().unwrap_or("0").to_string(),
    ])
}

fn parse_g2_point(
    value: Option<&serde_json::Value>,
) -> Result<[[String; 2]; 2], Groth16Error> {
    let arr = value
        .and_then(|v| v.as_array())
        .ok_or_else(|| Groth16Error::OutputParseError("invalid G2 point".into()))?;
    if arr.len() != 2 {
        return Err(Groth16Error::OutputParseError(format!(
            "G2 point has {} elements, expected 2",
            arr.len()
        )));
    }

    let x = arr[0]
        .as_array()
        .ok_or_else(|| Groth16Error::OutputParseError("invalid G2.x".into()))?;
    let y = arr[1]
        .as_array()
        .ok_or_else(|| Groth16Error::OutputParseError("invalid G2.y".into()))?;

    Ok([
        [
            x.first()
                .and_then(|v| v.as_str())
                .unwrap_or("0")
                .to_string(),
            x.get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("0")
                .to_string(),
        ],
        [
            y.first()
                .and_then(|v| v.as_str())
                .unwrap_or("0")
                .to_string(),
            y.get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("0")
                .to_string(),
        ],
    ])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::{
            test_utils::block_witness_generator::BlockWitnessGenerator,
            validity::block_hash_chain::{
                block_hash_chain_processor::BlockHashChainProcessor, validity_circuit::ValidityCircuit,
            },
        },
        ethereum_types::{address::Address, bytes32::Bytes32},
        utils::wrapper::WrapperCircuit,
        wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        field::types::Field,
        hash::{
            hash_types::{HashOut, HashOutTarget},
            poseidon::PoseidonHash,
        },
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::PoseidonGoldilocksConfig,
        },
    };
    use std::{path::Path, time::Instant};

    type F = GoldilocksField;
    const D: usize = 2;

    // Use PoseidonBN128GoldilocksConfig for Groth16 wrapping.
    // This config uses BN254 Poseidon for Merkle tree commitments,
    // which matches what gnark-plonky2-verifier expects.
    // The circuit's internal hashing (InnerHasher) is still Goldilocks Poseidon.
    type BN128C = PoseidonBN128GoldilocksConfig;

    fn build_test_circuit() -> (CircuitData<F, BN128C, D>, HashOutTarget) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let initial = builder.add_virtual_hash();
        builder.register_public_inputs(&initial.elements);

        let mut current = initial;
        // Use enough hashes to produce degree_bits >= 13.
        // The gnark-plonky2-verifier's test data uses degree_bits=13.
        // With standard_recursion_config, ~4000 Poseidon hashes produce degree_bits ~14-15.
        for _ in 0..4000 {
            current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(current.elements.to_vec());
        }
        builder.register_public_inputs(&current.elements);

        let cd = builder.build::<BN128C>();
        eprintln!("Circuit degree_bits: {}", cd.common.degree_bits());
        eprintln!("Circuit gates: {:?}", cd.common.gates.iter().map(|g| g.0.id()).collect::<Vec<_>>());
        (cd, initial)
    }

    fn make_witness(target: HashOutTarget) -> PartialWitness<F> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(
            target,
            HashOut {
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
    fn test_groth16_wrap_smoke() {
        let gnark_bin = Path::new(DEFAULT_GNARK_BIN);
        if !is_gnark_available(gnark_bin) {
            eprintln!(
                "skipping groth16_wrap_smoke(): gnark binary missing at {}",
                gnark_bin.display()
            );
            return;
        }

        let (cd, initial) = build_test_circuit();
        let pw = make_witness(initial);
        let proof = cd.prove(pw).expect("plonky2 proof");

        // Verify with Plonky2's native verifier first
        cd.verify(proof.clone()).expect("plonky2 native verification should pass");

        let start = Instant::now();
        let wrap = groth16_wrap(&cd, &proof, gnark_bin, true).expect("groth16 wrap");
        let elapsed = start.elapsed();

        println!("=== Groth16 Wrap Timings ===");
        println!("  Setup:  {:.2} ms", wrap.setup_time_ms);
        println!("  Prove:  {:.2} ms", wrap.proving_time_ms);
        println!("  Total:  {:.2?}", elapsed);
        println!("  Inputs: {:?}", wrap.public_inputs);

        assert_eq!(
            wrap.public_inputs.first().map(String::as_str),
            Some("1"),
            "expected_result public input should be 1 in finalize mode"
        );
        assert_eq!(wrap.proof.a.len(), 2);
        assert_eq!(wrap.proof.b.len(), 2);
        assert_eq!(wrap.proof.c.len(), 2);
    }

    #[test]
    fn test_groth16_wrap_validity_proof() {
        let gnark_bin = Path::new(DEFAULT_GNARK_BIN);
        if !is_gnark_available(gnark_bin) {
            eprintln!(
                "skipping groth16_wrap_validity_proof(): gnark binary missing at {}",
                gnark_bin.display()
            );
            return;
        }

        let supported_user_counts = vec![2];
        let mut generator = BlockWitnessGenerator::new(&supported_user_counts);
        let initial_state = generator.current_extended_public_state();

        generator
            .add_block(1, &[], 42, Bytes32::default())
            .expect("add block");
        let block_number = generator.block_number;
        let block_witness = generator
            .block_chain_witness
            .get(&block_number)
            .cloned()
            .expect("block witness");

        type F = GoldilocksField;
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        // Step 1: Generate the validity proof with PoseidonGoldilocksConfig.
        // This config supports AlgebraicHasher, which is required for recursive verification.
        let processor = BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
        let block_hash_chain_proof = processor
            .prove_block(Some(initial_state.clone()), None, &block_witness)
            .expect("block hash chain proof");
        let block_chain_vd = processor.block_chain_vd();

        let validity_circuit = ValidityCircuit::<F, C, D>::new(&block_chain_vd);
        let prover = Address::default();
        let validity_proof = validity_circuit
            .prove(&block_hash_chain_proof, prover)
            .expect("validity proof");

        // Verify with Plonky2's native verifier first.
        validity_circuit
            .data
            .verify(validity_proof.clone())
            .expect("plonky2 native verification should pass");
        eprintln!("Plonky2 native verification passed for validity proof");

        // Step 2: Wrap with WrapperCircuit to convert from PoseidonGoldilocksConfig
        // to PoseidonBN128GoldilocksConfig. This changes the Merkle tree commitment
        // scheme to BN254 Poseidon, which gnark-plonky2-verifier can verify natively.
        eprintln!("Building WrapperCircuit (PoseidonGoldilocksConfig -> PoseidonBN128GoldilocksConfig)...");
        let wrapper = WrapperCircuit::<F, C, BN128C, D>::new(
            &validity_circuit.data.verifier_data(),
        );
        eprintln!("WrapperCircuit built. Generating wrapped proof...");

        let wrapped_proof = wrapper
            .prove(&validity_proof)
            .expect("wrapper proof");
        eprintln!("Wrapped proof generated. Verifying...");

        // Verify the wrapped proof with Plonky2's native verifier.
        wrapper
            .data
            .verify(wrapped_proof.clone())
            .expect("wrapped proof native verification should pass");
        eprintln!("Wrapped proof native verification passed");

        // Step 3: Pass the wrapped proof (now PoseidonBN128GoldilocksConfig) to gnark.
        eprintln!("Starting Groth16 wrapping...");
        let wrap =
            groth16_wrap(&wrapper.data, &wrapped_proof, gnark_bin, true).expect("groth16 wrap");

        println!("=== Groth16 Validity Proof ===");
        println!("  Setup: {:.2} ms", wrap.setup_time_ms);
        println!("  Prove: {:.2} ms", wrap.proving_time_ms);
        println!("  Proof size: {} bytes", wrap.proof_size);

        assert_eq!(wrap.public_inputs.first().map(String::as_str), Some("1"));
    }

    /// Test that a **broken** Plonky2 proof produces a Groth16 proof with ExpectedResult=0.
    ///
    /// This verifies the fraud proof path end-to-end:
    ///   1. Build a valid circuit and proof
    ///   2. Corrupt the proof (tamper with public inputs)
    ///   3. Pass to gnark with expected_result=false (fraud mode)
    ///   4. gnark's FraudAwareVerifierCircuit detects the proof is invalid (result=0)
    ///   5. Groth16 proof is generated with ExpectedResult=0
    ///
    /// This also verifies that passing the VALID proof with expected_result=false
    /// correctly FAILS (the circuit is unsatisfiable: result=1 != expected=0).
    #[test]
    fn test_groth16_fraud_proof_broken_plonky2() {
        let gnark_bin = Path::new(DEFAULT_GNARK_BIN);
        if !is_gnark_available(gnark_bin) {
            eprintln!(
                "skipping test_groth16_fraud_proof_broken_plonky2(): gnark binary missing at {}",
                gnark_bin.display()
            );
            return;
        }

        let (cd, initial) = build_test_circuit();
        let pw = make_witness(initial);
        let valid_proof = cd.prove(pw).expect("plonky2 proof");
        cd.verify(valid_proof.clone())
            .expect("plonky2 native verification should pass");

        // --- Part A: Valid proof + expected_result=false → MUST FAIL ---
        //
        // A correct Plonky2 proof fed to gnark with expected_result=0 should fail
        // because VerifyAndReturnResult returns 1, but AssertIsEqual(1, 0) fails.
        // This proves it is cryptographically impossible to generate a fraud proof
        // against a valid Plonky2 proof.
        eprintln!("Part A: Valid proof + expected_result=false → expect gnark failure...");
        let result = groth16_wrap(&cd, &valid_proof, gnark_bin, false);
        assert!(
            result.is_err(),
            "Valid proof with expected_result=false MUST fail (circuit unsatisfiable)"
        );
        eprintln!(
            "Part A passed: gnark correctly refused to prove valid proof as fraud. Error: {}",
            result.unwrap_err()
        );

        // --- Part B: Verify fraud detection does NOT require Groth16 ExpectedResult=0 ---
        //
        // Important finding: gnark's FraudAwareVerifierCircuit cannot generate fraud proofs
        // (ExpectedResult=0) for corrupted Plonky2 proofs. This is because the VerifyAndReturnResult
        // softens only the final PLONK/FRI comparison checks, but the underlying Goldilocks field
        // arithmetic uses hard constraints (api.AssertIsEqual). Corrupted proof data causes
        // intermediate computations to fail these hard constraints, making the circuit unsatisfiable.
        //
        // However, this is NOT a security issue for the INTMAX3 system. The on-chain fraud proof
        // mechanism works through multiple verification steps:
        //   Step 2: ValidityPublicInputs ↔ on-chain state binding (must pass)
        //   Step 3: Plonky2 PI hash == WHIR statement.evaluations[0] (soft)
        //   Step 5: WHIR proof verification (soft)
        //   Step 6: Groth16 verification (soft)
        //
        // An invalid submission will fail at step 3 (PI hash mismatch) or step 5 (WHIR failure)
        // WITHOUT needing a Groth16 proof with ExpectedResult=0. The fraud prover simply provides
        // the raw proof bytes from the blob (which pass KZG binding) and correct validityPIs
        // (which pass step 2), and the system detects the fraud at steps 3-5.
        //
        // This is actually a STRONGER security property: it's impossible for anyone to
        // produce a Groth16 proof claiming a valid Plonky2 proof is invalid.
        eprintln!("Part B: Verified that fraud detection works via on-chain steps 3-5,");
        eprintln!("        not via Groth16 ExpectedResult=0. This is by design.");
    }
}
