//! Restart-safe L1 publisher for `public_close_prover` output.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use clap::Parser;
use intmax3_zkp::public_close_publisher::{
    PublicCloseProgress, PublicClosePublisherConfig, advance_public_close,
};

#[derive(Debug, Parser)]
#[command(
    name = "public_close_publisher",
    about = "Durably submit and guarded-finalize a keyless public close proof"
)]
struct Arguments {
    /// Immutable directory produced by public_close_prover.
    #[arg(long)]
    bundle_dir: PathBuf,
    /// Independently authenticated final signed-head digest expected inside the proof bundle.
    #[arg(long)]
    expected_final_channel_state_digest: String,
    /// Release-reviewed deployment/codehash/ABI manifest.
    #[arg(long)]
    deployment_manifest: PathBuf,
    /// Independent SHA-256 pin of the exact deployment manifest bytes.
    #[arg(long)]
    deployment_manifest_sha256: String,
    /// Private crash-recovery WAL. Created/repaired as mode 0600.
    #[arg(long)]
    journal: PathBuf,
    /// Private common lock directory shared by every INTMAX L1 publisher using this signer.
    #[arg(long)]
    signer_lock_root: PathBuf,
    #[arg(long)]
    rpc_url: String,
    /// Foundry encrypted-keystore account name (not an address or raw key).
    #[arg(long)]
    account: String,
    /// Development-only fallback to latest when chain 31337 has no finalized RPC tag.
    #[arg(long, default_value_t = false)]
    allow_unfinalized_devnet: bool,
    /// Keep advancing until complete. Without this flag one durable transition is attempted.
    #[arg(long, default_value_t = false)]
    watch: bool,
    #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u64).range(1..=300))]
    poll_seconds: u64,
    #[arg(long, default_value_t = 86_400, value_parser = clap::value_parser!(u64).range(1..=604800))]
    timeout_seconds: u64,
}

fn main() -> Result<()> {
    let args = Arguments::parse();
    let config = PublicClosePublisherConfig {
        bundle_dir: args.bundle_dir,
        expected_final_channel_state_digest: args.expected_final_channel_state_digest,
        deployment_manifest_path: args.deployment_manifest,
        deployment_manifest_sha256: args.deployment_manifest_sha256,
        journal_path: args.journal,
        signer_lock_root: args.signer_lock_root,
        rpc_url: args.rpc_url,
        account: args.account,
        allow_unfinalized_devnet: args.allow_unfinalized_devnet,
    };
    let started = Instant::now();
    loop {
        let progress = advance_public_close(&config)?;
        println!("{}", serde_json::to_string(&progress)?);
        if matches!(progress, PublicCloseProgress::Complete { .. }) || !args.watch {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(args.timeout_seconds) {
            bail!(
                "public close did not complete within {} seconds; exact signed bytes remain in {}",
                args.timeout_seconds,
                config.journal_path.display()
            );
        }
        std::thread::sleep(Duration::from_secs(args.poll_seconds));
    }
}
