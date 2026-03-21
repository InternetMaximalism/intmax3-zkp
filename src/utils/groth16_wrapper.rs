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

/// Complete result of Groth16 wrapping.
#[derive(Debug, Clone)]
pub struct Groth16WrapResult {
    /// The Groth16 proof points.
    pub proof: Groth16Proof,
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
///
/// # Returns
///
/// A `Groth16WrapResult` containing the BN254 proof points, public inputs,
/// and timing information. The proof points match the format expected by
/// `IntmaxRollup.sol`'s `Groth16Verifier.verify()`.
///
/// # Example
///
/// ```ignore
/// let result = groth16_wrap(
///     &circuit_data,
///     &plonky2_proof,
///     Path::new("gnark/gnark-wrapper"),
/// )?;
/// println!("Groth16 proof A: {:?}", result.proof.a);
/// println!("Proving time: {:.1}ms", result.proving_time_ms);
/// ```
pub fn groth16_wrap<F, C, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
    proof: &ProofWithPublicInputs<F, C, D>,
    gnark_bin_path: &Path,
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
    let proof_json = serde_json::to_string(proof)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;
    std::fs::write(tmp_dir.join("proof_with_public_inputs.json"), &proof_json)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;

    let vd_json = serde_json::to_string(&circuit_data.verifier_only)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;
    std::fs::write(tmp_dir.join("verifier_only_circuit_data.json"), &vd_json)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;

    let cd_json = serde_json::to_string(&circuit_data.common)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;
    std::fs::write(tmp_dir.join("common_circuit_data.json"), &cd_json)
        .map_err(|e| Groth16Error::SerializationError(e.to_string()))?;

    let out_file = tmp_dir.join("groth16_proof.json");

    // 4. Call gnark-wrapper subprocess
    let output = Command::new(gnark_bin_path)
        .arg("--data")
        .arg(tmp_dir.to_str().unwrap())
        .arg("--out")
        .arg(out_file.to_str().unwrap())
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

    Ok(Groth16WrapResult {
        proof: Groth16Proof { a, b, c },
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
