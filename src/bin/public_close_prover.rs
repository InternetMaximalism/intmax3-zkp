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
    ethereum_types::address::Address,
    public_close_prover::{
        MAX_PUBLIC_BACKING_ENVELOPE_BYTES, PublicCloseExpectations,
        parse_public_close_backing_envelope, parse_sha256_pin, prove_public_close,
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
    /// File downloaded from GET /api/v1/channel/:id/backing (schemaVersion 2).
    #[arg(long)]
    input: PathBuf,
    /// Output directory for the close proof, MLE JSON, intent, and manifest.
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
    close_intent_file: &'static str,
    close_intent_full_file: &'static str,
    close_public_inputs_file: &'static str,
    close_public_input_count: usize,
    key_material_consumed: bool,
    self_verified: bool,
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
    const INTENT: &str = "close_intent.json";
    const INTENT_FULL: &str = "close_intent_full.json";
    const PIS: &str = "close_public_inputs.json";
    const MANIFEST: &str = "public_close_manifest.json";

    // Install the six-file bundle as one directory commit. A crash leaves only the hidden
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
    atomic_write(&staging.join(MLE), bundle.close_mle_json.as_bytes())?;
    atomic_write(
        &staging.join(INTENT),
        &pretty_json(&bundle.close_descriptor)?,
    )?;
    atomic_write(
        &staging.join(INTENT_FULL),
        &pretty_json(&bundle.close_intent)?,
    )?;
    atomic_write(
        &staging.join(PIS),
        &pretty_json(&bundle.close_public_inputs)?,
    )?;

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
        close_intent_file: INTENT,
        close_intent_full_file: INTENT_FULL,
        close_public_inputs_file: PIS,
        close_public_input_count: bundle.close_public_inputs.len(),
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
    // before announcing the bundle so every manifest either remains absent or names all five
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
