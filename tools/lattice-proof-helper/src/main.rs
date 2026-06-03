use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use sis_amount_stark::{
    ProofSystemOptions, compute_commitment, config::DEFAULT_BETA, deserialize_envelope,
    prove_amount_with_options, serialize_envelope, verify_amount_with_options,
};

const N: usize = sis_amount_stark::params::N;

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum HelperRequest {
    Prove {
        purpose: String,
        amount: u64,
        randomness: Vec<i64>,
    },
    Verify {
        purpose: String,
        proof_hex: String,
    },
}

#[derive(Debug, Serialize)]
struct HelperResponse {
    ok: bool,
    proof_hex: Option<String>,
    commitment: Option<Vec<u64>>,
    error: Option<String>,
}

fn main() {
    if let Err(err) = run() {
        let response = HelperResponse {
            ok: false,
            proof_hex: None,
            commitment: None,
            error: Some(err),
        };
        let _ = serde_json::to_writer(std::io::stdout(), &response);
        let _ = std::io::stdout().write_all(b"\n");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .map_err(|err| err.to_string())?;
    let request: HelperRequest = serde_json::from_slice(&input).map_err(|err| err.to_string())?;

    let response = match request {
        HelperRequest::Prove {
            purpose,
            amount,
            randomness,
        } => {
            let options = options_for_purpose(&purpose)?;
            let randomness: [i64; N] = randomness
                .try_into()
                .map_err(|_| format!("invalid randomness length: expected {N}"))?;
            let (proof, public_inputs) = prove_amount_with_options(amount, randomness, &options)
                .map_err(|err| err.to_string())?;
            let envelope = serialize_envelope(&proof, &public_inputs, &options)
                .map_err(|err| err.to_string())?;
            HelperResponse {
                ok: true,
                proof_hex: Some(hex::encode(envelope)),
                commitment: Some(compute_commitment(amount, &randomness).to_vec()),
                error: None,
            }
        }
        HelperRequest::Verify { purpose, proof_hex } => {
            let proof_bytes = hex::decode(proof_hex).map_err(|err| err.to_string())?;
            let (proof, public_inputs, options) =
                deserialize_envelope(&proof_bytes).map_err(|err| err.to_string())?;
            let expected_options = options_for_purpose(&purpose)?;
            if options != expected_options {
                return Err("proof options mismatch".to_string());
            }
            verify_amount_with_options(&proof, &public_inputs, &options)
                .map_err(|err| err.to_string())?;
            HelperResponse {
                ok: true,
                proof_hex: None,
                commitment: Some(public_inputs.c.clone()),
                error: None,
            }
        }
    };

    serde_json::to_writer(std::io::stdout(), &response).map_err(|err| err.to_string())?;
    std::io::stdout()
        .write_all(b"\n")
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn options_for_purpose(purpose: &str) -> Result<ProofSystemOptions, String> {
    let beta = match purpose {
        "transfer_amount" => core::cmp::max(1, DEFAULT_BETA / 10_000),
        "balance_opening" => DEFAULT_BETA,
        _ => return Err(format!("unknown lattice proof purpose: {purpose}")),
    };
    Ok(ProofSystemOptions {
        beta,
        ..ProofSystemOptions::default()
    })
}
