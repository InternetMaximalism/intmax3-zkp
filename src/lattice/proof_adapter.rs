use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    circuits::channel::state_update_verifier::{
        ChannelStateUpdateError, LatticeBindingVerifier, LatticeProofPurpose,
    },
    common::channel::{LatticeCommitment, LatticeOpening},
};

pub const Q: u64 = 8_380_417;
pub const M: usize = 128;
pub const N: usize = 256;
pub const DEFAULT_BETA: i64 = (1 << 17) - 1;

pub type LatticeCommitmentArray = [u64; M];
pub type LatticeRandomnessArray = [i64; N];

#[derive(Debug, Error)]
pub enum LatticeProofAdapterError {
    #[error("invalid commitment length: expected {expected} bytes, got {actual}")]
    InvalidCommitmentLength { expected: usize, actual: usize },

    #[error("invalid randomness length: expected {expected} bytes, got {actual}")]
    InvalidRandomnessLength { expected: usize, actual: usize },

    #[error("commitment mismatch")]
    CommitmentMismatch,

    #[error("helper build failed: {0}")]
    HelperBuildFailed(String),

    #[error("helper execution failed: {0}")]
    HelperExecutionFailed(String),

    #[error("helper returned no proof bytes")]
    MissingProofBytes,

    #[error("helper returned no commitment")]
    MissingCommitment,

    #[error("proof decoding failed: {0}")]
    ProofDecodingFailed(String),

    #[error("randomness coefficient outside [-beta, beta]")]
    RandomnessOutOfRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DualBetaBounds {
    pub transfer_randomness_beta: i64,
    pub balance_randomness_beta: i64,
}

impl DualBetaBounds {
    pub fn default_from_upstream() -> Self {
        let balance_randomness_beta = DEFAULT_BETA;
        let transfer_randomness_beta = core::cmp::max(1, balance_randomness_beta / 10_000);
        Self {
            transfer_randomness_beta,
            balance_randomness_beta,
        }
    }
}

pub struct DualBetaPreparedSystems {
    bounds: DualBetaBounds,
}

impl DualBetaPreparedSystems {
    pub fn new(bounds: DualBetaBounds) -> Result<Self, LatticeProofAdapterError> {
        Ok(Self { bounds })
    }

    fn beta_for(&self, purpose: LatticeProofPurpose) -> i64 {
        match purpose {
            LatticeProofPurpose::TransferAmount => self.bounds.transfer_randomness_beta,
            LatticeProofPurpose::BalanceOpening => self.bounds.balance_randomness_beta,
        }
    }
}

pub fn default_lattice_systems() -> &'static DualBetaPreparedSystems {
    static SYSTEMS: OnceLock<DualBetaPreparedSystems> = OnceLock::new();
    SYSTEMS.get_or_init(|| {
        DualBetaPreparedSystems::new(DualBetaBounds::default_from_upstream())
            .expect("default SIS proof systems must prepare")
    })
}

pub fn encode_commitment(commitment: &LatticeCommitmentArray) -> Vec<u8> {
    commitment
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

pub fn decode_commitment(bytes: &[u8]) -> Result<LatticeCommitmentArray, LatticeProofAdapterError> {
    let expected = M * 8;
    if bytes.len() != expected {
        return Err(LatticeProofAdapterError::InvalidCommitmentLength {
            expected,
            actual: bytes.len(),
        });
    }

    let mut out = [0u64; M];
    for (idx, chunk) in bytes.chunks_exact(8).enumerate() {
        out[idx] = u64::from_be_bytes(chunk.try_into().expect("chunk length fixed"));
    }
    Ok(out)
}

pub fn encode_randomness(randomness: &LatticeRandomnessArray) -> Vec<u8> {
    randomness
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

pub fn decode_randomness(bytes: &[u8]) -> Result<LatticeRandomnessArray, LatticeProofAdapterError> {
    let expected = N * 8;
    if bytes.len() != expected {
        return Err(LatticeProofAdapterError::InvalidRandomnessLength {
            expected,
            actual: bytes.len(),
        });
    }

    let mut out = [0i64; N];
    for (idx, chunk) in bytes.chunks_exact(8).enumerate() {
        out[idx] = i64::from_be_bytes(chunk.try_into().expect("chunk length fixed"));
    }
    Ok(out)
}

fn mod_q_i128(x: i128) -> u64 {
    let q = i128::from(Q);
    x.rem_euclid(q) as u64
}

fn g_coeff(row: usize, limb: usize) -> u64 {
    debug_assert!(row < M);
    debug_assert!(limb < 4);

    if row < 4 {
        return u64::from(row == limb);
    }

    let mix = ((row as u64 + 17) * (limb as u64 + 29) + 97) % Q;
    (mix + 1) % Q
}

fn b_coeff(row: usize, col: usize) -> u64 {
    debug_assert!(row < M);
    debug_assert!(col < N);

    let x = ((row as u64 + 1) << 32) ^ (col as u64 + 1);
    let mut z = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    let value = z ^ (z >> 31);
    value % Q
}

pub fn compute_commitment_array(
    amount: u64,
    randomness: &LatticeRandomnessArray,
) -> LatticeCommitmentArray {
    let amount_limbs = [
        (amount & 0xffff) as u16,
        ((amount >> 16) & 0xffff) as u16,
        ((amount >> 32) & 0xffff) as u16,
        ((amount >> 48) & 0xffff) as u16,
    ];
    let mut commitment = [0u64; M];
    for j in 0..M {
        let mut acc = 0i128;
        for (limb_idx, limb) in amount_limbs.iter().enumerate() {
            acc += i128::from(g_coeff(j, limb_idx)) * i128::from(*limb);
        }
        for (i, randomness_i) in randomness.iter().enumerate() {
            acc += i128::from(b_coeff(j, i)) * i128::from(*randomness_i);
        }
        commitment[j] = mod_q_i128(acc);
    }
    commitment
}

pub fn compute_commitment_from_opening(
    amount: u64,
    randomness: &LatticeRandomnessArray,
) -> LatticeCommitment {
    LatticeCommitment {
        commitment: encode_commitment(&compute_commitment_array(amount, randomness)),
    }
}

pub fn prove_opening(
    systems: &DualBetaPreparedSystems,
    purpose: LatticeProofPurpose,
    amount: u64,
    randomness: &LatticeRandomnessArray,
) -> Result<LatticeOpening, LatticeProofAdapterError> {
    validate_randomness_for_beta(randomness, systems.beta_for(purpose))?;

    let response = run_helper(HelperRequest::Prove {
        purpose: helper_purpose_name(purpose),
        amount,
        randomness: randomness.to_vec(),
    })?;

    Ok(LatticeOpening {
        amount,
        randomness: encode_randomness(randomness),
        proof: hex::decode(
            response
                .proof_hex
                .ok_or(LatticeProofAdapterError::MissingProofBytes)?,
        )
        .map_err(|err| LatticeProofAdapterError::ProofDecodingFailed(err.to_string()))?,
    })
}

pub fn verify_opening(
    systems: &DualBetaPreparedSystems,
    purpose: LatticeProofPurpose,
    commitment: &LatticeCommitment,
    opening: &LatticeOpening,
) -> Result<(), LatticeProofAdapterError> {
    let randomness = decode_randomness(&opening.randomness)?;
    validate_randomness_for_beta(&randomness, systems.beta_for(purpose))?;

    let recomputed = compute_commitment_array(opening.amount, &randomness);
    if encode_commitment(&recomputed) != commitment.commitment {
        return Err(LatticeProofAdapterError::CommitmentMismatch);
    }

    let response = run_helper(HelperRequest::Verify {
        purpose: helper_purpose_name(purpose),
        proof_hex: hex::encode(&opening.proof),
    })?;
    let proved = response
        .commitment
        .ok_or(LatticeProofAdapterError::MissingCommitment)?;
    if encode_commitment(&vec_to_commitment_array(&proved)?) != commitment.commitment {
        return Err(LatticeProofAdapterError::CommitmentMismatch);
    }

    Ok(())
}

fn validate_randomness_for_beta(
    randomness: &LatticeRandomnessArray,
    beta: i64,
) -> Result<(), LatticeProofAdapterError> {
    if randomness
        .iter()
        .any(|value| !(-beta..=beta).contains(value))
    {
        return Err(LatticeProofAdapterError::RandomnessOutOfRange);
    }
    Ok(())
}

pub struct RealLatticeBindingVerifier {
    systems: &'static DualBetaPreparedSystems,
}

impl Default for RealLatticeBindingVerifier {
    fn default() -> Self {
        Self {
            systems: default_lattice_systems(),
        }
    }
}

impl LatticeBindingVerifier for RealLatticeBindingVerifier {
    fn verify(
        &self,
        commitment: &LatticeCommitment,
        opening: &LatticeOpening,
        purpose: LatticeProofPurpose,
    ) -> Result<(), ChannelStateUpdateError> {
        verify_opening(self.systems, purpose, commitment, opening)
            .map_err(|err| ChannelStateUpdateError::ProofVerification(err.to_string()))
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum HelperRequest {
    Prove {
        purpose: &'static str,
        amount: u64,
        randomness: Vec<i64>,
    },
    Verify {
        purpose: &'static str,
        proof_hex: String,
    },
}

#[derive(Debug, Deserialize)]
struct HelperResponse {
    ok: bool,
    proof_hex: Option<String>,
    commitment: Option<Vec<u64>>,
    error: Option<String>,
}

fn helper_purpose_name(purpose: LatticeProofPurpose) -> &'static str {
    match purpose {
        LatticeProofPurpose::TransferAmount => "transfer_amount",
        LatticeProofPurpose::BalanceOpening => "balance_opening",
    }
}

fn helper_manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tools")
        .join("lattice-proof-helper")
        .join("Cargo.toml")
}

fn helper_binary_path() -> Result<&'static Path, LatticeProofAdapterError> {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    if let Some(path) = BIN.get() {
        return Ok(path.as_path());
    }

    if let Ok(path) = std::env::var("INTMAX_LATTICE_HELPER_BIN") {
        let path = PathBuf::from(path);
        let _ = BIN.set(path);
        return Ok(BIN.get().expect("helper path just set").as_path());
    }

    let manifest_path = helper_manifest_path();
    let status = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--quiet")
        .status()
        .map_err(|err| LatticeProofAdapterError::HelperBuildFailed(err.to_string()))?;
    if !status.success() {
        return Err(LatticeProofAdapterError::HelperBuildFailed(format!(
            "cargo build failed with status {status}",
        )));
    }

    let path = manifest_path
        .parent()
        .expect("manifest must have parent")
        .join("target")
        .join("release")
        .join("lattice-proof-helper");
    let _ = BIN.set(path);
    Ok(BIN.get().expect("helper path just set").as_path())
}

fn run_helper(request: HelperRequest) -> Result<HelperResponse, LatticeProofAdapterError> {
    let helper = helper_binary_path()?;
    let input = serde_json::to_vec(&request)
        .map_err(|err| LatticeProofAdapterError::HelperExecutionFailed(err.to_string()))?;
    let output = Command::new(helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .expect("stdin piped")
                .write_all(&input)?;
            child.wait_with_output()
        })
        .map_err(|err| LatticeProofAdapterError::HelperExecutionFailed(err.to_string()))?;

    if !output.status.success() {
        return Err(LatticeProofAdapterError::HelperExecutionFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    let response: HelperResponse = serde_json::from_slice(&output.stdout)
        .map_err(|err| LatticeProofAdapterError::HelperExecutionFailed(err.to_string()))?;
    if !response.ok {
        return Err(LatticeProofAdapterError::HelperExecutionFailed(
            response
                .error
                .unwrap_or_else(|| "unknown helper error".to_string()),
        ));
    }
    Ok(response)
}

fn vec_to_commitment_array(
    values: &[u64],
) -> Result<LatticeCommitmentArray, LatticeProofAdapterError> {
    values
        .try_into()
        .map_err(|_| LatticeProofAdapterError::MissingCommitment)
}
