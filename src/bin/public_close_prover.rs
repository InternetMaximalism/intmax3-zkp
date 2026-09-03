//! Offline/keyless close prover for the public `/backing` API artifact.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use intmax3_zkp::{
    common::channel_id::ChannelId,
    ethereum_types::{address::Address, bytes32::Bytes32},
    public_close_prover::{
        MAX_PUBLIC_BACKING_ENVELOPE_BYTES, PublicCloseExpectations,
        parse_public_close_backing_envelope, parse_sha256_pin, prove_public_close, sha256_hex,
        verify_public_backing,
    },
};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "public_close_prover",
    about = "Generate and self-verify a close proof from a public live-backing artifact (no wallet keys)"
)]
struct Arguments {
    /// File downloaded from GET /api/v1/channel/:id/backing (schemaVersion 3).
    #[arg(long)]
    input: PathBuf,
    /// Output directory for the close/backing proofs, both MLE JSON files, intent, and manifest.
    #[arg(long, required_unless_present = "verify_only")]
    output_dir: Option<PathBuf>,
    /// Verify the backing/signatures/VD/balance proof and print a compact JSON receipt without
    /// constructing the close circuits. Intended for participant archive admission.
    #[arg(long, default_value_t = false)]
    verify_only: bool,
    /// Channel id selected independently of the downloaded response.
    #[arg(long)]
    expected_channel_id: u32,
    /// Chain id selected independently of the downloaded response.
    #[arg(long)]
    expected_chain_id: u64,
    /// Rollup selected independently of the downloaded response.
    #[arg(long)]
    expected_rollup: String,
    /// SHA-256 of canonical balance verifier-data bytes. Mandatory unless chain id is 31337.
    #[arg(long)]
    expected_balance_vd_sha256: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputManifest<'a> {
    schema_version: u32,
    chain_id: u64,
    rollup: Address,
    channel_id: ChannelId,
    balance_verifier_data_sha256: &'a str,
    close_proof_file: &'static str,
    close_proof_bytes: usize,
    close_mle_file: &'static str,
    close_mle_bytes: usize,
    backing_proof_file: &'static str,
    backing_proof_bytes: usize,
    backing_mle_file: &'static str,
    backing_mle_bytes: usize,
    backing_public_inputs_file: &'static str,
    backing_public_input_count: usize,
    backing_finalized_extended_state_commitment: Bytes32,
    backing_anchor_block_number: u64,
    close_intent_file: &'static str,
    close_intent_full_file: &'static str,
    close_public_inputs_file: &'static str,
    close_public_input_count: usize,
    #[serde(flatten)]
    payload_hashes: PayloadHashes,
    key_material_consumed: bool,
    self_verified: bool,
}

/// SHA-256 over the exact bytes installed under each filename in the atomic output directory.
/// The manifest itself is intentionally excluded because a file cannot contain its own digest.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PayloadHashes {
    close_proof_sha256: String,
    close_mle_sha256: String,
    backing_proof_sha256: String,
    backing_mle_sha256: String,
    backing_public_inputs_sha256: String,
    close_intent_sha256: String,
    close_intent_full_sha256: String,
    close_public_inputs_sha256: String,
}

impl PayloadHashes {
    #[allow(clippy::too_many_arguments)]
    fn new(
        close_proof: &[u8],
        close_mle: &[u8],
        backing_proof: &[u8],
        backing_mle: &[u8],
        backing_public_inputs: &[u8],
        close_intent: &[u8],
        close_intent_full: &[u8],
        close_public_inputs: &[u8],
    ) -> Self {
        Self {
            close_proof_sha256: sha256_hex(close_proof),
            close_mle_sha256: sha256_hex(close_mle),
            backing_proof_sha256: sha256_hex(backing_proof),
            backing_mle_sha256: sha256_hex(backing_mle),
            backing_public_inputs_sha256: sha256_hex(backing_public_inputs),
            close_intent_sha256: sha256_hex(close_intent),
            close_intent_full_sha256: sha256_hex(close_intent_full),
            close_public_inputs_sha256: sha256_hex(close_public_inputs),
        }
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("output path {} has no parent", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create output directory {}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("output path {} has no UTF-8 filename", path.display()))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .with_context(|| format!("create temporary output {}", temporary.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write temporary output {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync temporary output {}", temporary.display()))?;
    drop(file);
    fs::rename(&temporary, path).with_context(|| {
        format!(
            "atomically install {} as {}",
            temporary.display(),
            path.display()
        )
    })?;
    sync_directory(parent)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .with_context(|| format!("open directory {} for fsync", path.display()))?
        .sync_all()
        .with_context(|| format!("fsync directory {}", path.display()))
}

fn pretty_json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(value).context("serialize public-close output")
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let input_size = fs::metadata(&arguments.input)
        .with_context(|| format!("stat public backing envelope {}", arguments.input.display()))?
        .len();
    if input_size > MAX_PUBLIC_BACKING_ENVELOPE_BYTES as u64 {
        anyhow::bail!(
            "public backing envelope is {input_size} bytes, above the {}-byte safety limit",
            MAX_PUBLIC_BACKING_ENVELOPE_BYTES
        );
    }
    let input = fs::read(&arguments.input)
        .with_context(|| format!("read public backing envelope {}", arguments.input.display()))?;
    let envelope = parse_public_close_backing_envelope(&input)?;
    let channel_id = ChannelId::new(arguments.expected_channel_id as u64)
        .map_err(|error| anyhow!("invalid expected channel id: {error:?}"))?;
    let rollup = arguments
        .expected_rollup
        .parse::<Address>()
        .map_err(|error| anyhow!("invalid expected rollup: {error}"))?;
    let vd_pin = arguments
        .expected_balance_vd_sha256
        .as_deref()
        .map(parse_sha256_pin)
        .transpose()?;
    let expected = PublicCloseExpectations {
        channel_id,
        chain_id: arguments.expected_chain_id,
        rollup,
        balance_verifier_data_sha256: vd_pin,
    };

    if arguments.verify_only {
        let verification = verify_public_backing(&envelope, &expected)?;
        println!("{}", serde_json::to_string(&verification)?);
        return Ok(());
    }

    let bundle = prove_public_close(&envelope, &expected)?;
    let output_dir = arguments
        .output_dir
        .as_ref()
        .ok_or_else(|| anyhow!("--output-dir is required unless --verify-only is selected"))?;
    const PROOF: &str = "close_proof.bin";
    const MLE: &str = "close_intent_mle.json";
    const BACKING_PROOF: &str = "backing_proof.bin";
    const BACKING_MLE: &str = "backing_mle.json";
    const BACKING_PIS: &str = "backing_public_inputs.json";
    const INTENT: &str = "close_intent.json";
    const INTENT_FULL: &str = "close_intent_full.json";
    const PIS: &str = "close_public_inputs.json";
    const MANIFEST: &str = "public_close_manifest.json";

    // Serialize every JSON payload once. The exact same byte slices are hashed and installed, so
    // the manifest cannot accidentally describe a semantically equivalent re-serialization.
    let close_mle_bytes = bundle.close_mle_json.as_bytes();
    let backing_mle_bytes = bundle.backing_mle_json.as_bytes();
    let backing_public_inputs_bytes = pretty_json(&bundle.backing_public_inputs)?;
    let close_intent_bytes = pretty_json(&bundle.close_descriptor)?;
    let close_intent_full_bytes = pretty_json(&bundle.close_intent)?;
    let close_public_inputs_bytes = pretty_json(&bundle.close_public_inputs)?;
    let payload_hashes = PayloadHashes::new(
        &bundle.close_proof,
        close_mle_bytes,
        &bundle.backing_proof,
        backing_mle_bytes,
        &backing_public_inputs_bytes,
        &close_intent_bytes,
        &close_intent_full_bytes,
        &close_public_inputs_bytes,
    );

    // Install the complete bundle as one directory commit. A crash leaves only the hidden
    // staging directory; it cannot make an older manifest point at a partially replaced proof.
    if output_dir.exists() {
        anyhow::bail!(
            "output directory {} already exists; choose a new directory so proof bundles cannot be mixed",
            output_dir.display()
        );
    }
    let output_parent = arguments
        .output_dir
        .as_ref()
        .expect("checked above")
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .or_else(|| Some(Path::new(".")))
        .ok_or_else(|| anyhow!("output directory {} has no parent", output_dir.display()))?;
    fs::create_dir_all(output_parent)
        .with_context(|| format!("create output parent {}", output_parent.display()))?;
    let output_name = arguments
        .output_dir
        .as_ref()
        .expect("checked above")
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("output directory has no UTF-8 filename"))?;
    let staging = output_parent.join(format!(".{output_name}.{}.tmp", std::process::id()));
    fs::create_dir(&staging).with_context(|| {
        format!(
            "create proof-bundle staging directory {}",
            staging.display()
        )
    })?;

    atomic_write(&staging.join(PROOF), &bundle.close_proof)?;
    atomic_write(&staging.join(MLE), close_mle_bytes)?;
    atomic_write(&staging.join(BACKING_PROOF), &bundle.backing_proof)?;
    atomic_write(&staging.join(BACKING_MLE), backing_mle_bytes)?;
    atomic_write(&staging.join(BACKING_PIS), &backing_public_inputs_bytes)?;
    atomic_write(&staging.join(INTENT), &close_intent_bytes)?;
    atomic_write(&staging.join(INTENT_FULL), &close_intent_full_bytes)?;
    atomic_write(&staging.join(PIS), &close_public_inputs_bytes)?;

    let manifest = OutputManifest {
        schema_version: bundle.schema_version,
        chain_id: bundle.chain_id,
        rollup: bundle.rollup,
        channel_id: bundle.channel_id,
        balance_verifier_data_sha256: &bundle.balance_verifier_data_sha256,
        close_proof_file: PROOF,
        close_proof_bytes: bundle.close_proof.len(),
        close_mle_file: MLE,
        close_mle_bytes: bundle.close_mle_json.len(),
        backing_proof_file: BACKING_PROOF,
        backing_proof_bytes: bundle.backing_proof.len(),
        backing_mle_file: BACKING_MLE,
        backing_mle_bytes: bundle.backing_mle_json.len(),
        backing_public_inputs_file: BACKING_PIS,
        backing_public_input_count: bundle.backing_public_inputs.len(),
        backing_finalized_extended_state_commitment: bundle
            .backing_finalized_extended_state_commitment,
        backing_anchor_block_number: bundle.backing_anchor_block_number,
        close_intent_file: INTENT,
        close_intent_full_file: INTENT_FULL,
        close_public_inputs_file: PIS,
        close_public_input_count: bundle.close_public_inputs.len(),
        payload_hashes,
        key_material_consumed: false,
        self_verified: true,
    };
    atomic_write(&staging.join(MANIFEST), &pretty_json(&manifest)?)?;
    fs::rename(&staging, output_dir).with_context(|| {
        format!(
            "atomically install proof bundle {} as {}",
            staging.display(),
            output_dir.display()
        )
    })?;
    // A successful rename alone is not durable across power loss. Persist the parent directory
    // before announcing the bundle so every manifest either remains absent or names every
    // already-fsynced payloads after restart.
    sync_directory(output_parent)?;

    println!(
        "generated keyless self-verified close artifacts for channel {} on chain {} in {} (balance VD {})",
        arguments.expected_channel_id,
        arguments.expected_chain_id,
        output_dir.display(),
        bundle.balance_verifier_data_sha256
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_manifest_hashes_bind_all_eight_exact_files() {
        let payloads: [&[u8]; 8] = [
            b"close-proof",
            b"close-mle",
            b"backing-proof",
            b"backing-mle",
            b"backing-pis",
            b"close-intent",
            b"close-intent-full",
            b"close-pis",
        ];
        let hashes = PayloadHashes::new(
            payloads[0],
            payloads[1],
            payloads[2],
            payloads[3],
            payloads[4],
            payloads[5],
            payloads[6],
            payloads[7],
        );
        let encoded = serde_json::to_value(&hashes).expect("serialize payload hashes");
        assert_eq!(encoded.as_object().expect("hash object").len(), 8);
        for (field, payload) in [
            ("closeProofSha256", payloads[0]),
            ("closeMleSha256", payloads[1]),
            ("backingProofSha256", payloads[2]),
            ("backingMleSha256", payloads[3]),
            ("backingPublicInputsSha256", payloads[4]),
            ("closeIntentSha256", payloads[5]),
            ("closeIntentFullSha256", payloads[6]),
            ("closePublicInputsSha256", payloads[7]),
        ] {
            let digest = encoded[field].as_str().expect("SHA-256 string");
            assert_eq!(digest, sha256_hex(payload));
            assert_eq!(digest.len(), 66);
            assert!(digest.starts_with("0x"));
            assert!(digest[2..].bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert_eq!(digest, &digest.to_ascii_lowercase());
        }
        assert_ne!(
            encoded["backingMleSha256"],
            serde_json::Value::String(sha256_hex(b"backing-mle-mutated"))
        );
    }
}
