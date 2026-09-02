//! Operator-owned public L1 validity publication command.

use std::{path::PathBuf, process::ExitCode, time::Duration};

use clap::Parser;
use intmax3_zkp::public_validity_publisher::{
    PublicValidityPublisherConfig, publish_public_validity,
};

#[derive(Debug, Parser)]
#[command(
    name = "public_validity_publisher",
    about = "Durably publish one candidate-bound validity envelope to public L1"
)]
struct Args {
    /// Durable API validity envelope produced after prepareCloseFunding + proveValidity.
    #[arg(long)]
    artifact: PathBuf,

    /// Release-reviewed Rollup/MLE/KZG runtime-code and ABI-selector deployment manifest.
    #[arg(long)]
    deployment_manifest: PathBuf,

    /// Independently supplied SHA-256 of the exact deployment-manifest file bytes.
    #[arg(long)]
    deployment_manifest_sha256: String,

    /// Private 0600 write-ahead journal. Reuse this exact path after a crash.
    #[arg(long)]
    journal: PathBuf,

    /// Canonical private directory shared by every publisher using this L1 signer.
    #[arg(long)]
    lock_root: PathBuf,

    /// Canonical operator-owned L1 JSON-RPC endpoint.
    #[arg(long)]
    rpc_url: String,

    /// Foundry encrypted-keystore account name (or set INTMAX_L1_ACCOUNT).
    #[arg(long)]
    account: Option<String>,

    /// Maximum wait per transaction for canonical finalized coverage.
    #[arg(long, default_value_t = 3600)]
    finality_timeout_secs: u64,

    /// Chain-31337-only escape for RPCs without a `finalized` tag.
    #[arg(long, default_value_t = false)]
    allow_unfinalized_devnet: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let config = PublicValidityPublisherConfig {
        envelope_path: args.artifact,
        deployment_manifest_path: args.deployment_manifest,
        deployment_manifest_sha256: args.deployment_manifest_sha256,
        journal_path: args.journal,
        lock_root: args.lock_root,
        rpc_url: args.rpc_url,
        account: args.account,
        finality_timeout: Duration::from_secs(args.finality_timeout_secs),
        allow_unfinalized_devnet: args.allow_unfinalized_devnet,
    };
    match publish_public_validity(&config) {
        Ok(output) => match serde_json::to_string_pretty(&output) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("public validity output serialization failed: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("public validity publication failed: {error}");
            ExitCode::FAILURE
        }
    }
}
