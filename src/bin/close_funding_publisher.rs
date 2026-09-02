//! Operator-owned terminal close-funding L1 publication command.

use std::{path::PathBuf, process::ExitCode, time::Duration};

use clap::Parser;
use intmax3_zkp::close_funding_publisher::{CloseFundingPublisherConfig, publish_close_funding};

#[derive(Debug, Parser)]
#[command(
    name = "close_funding_publisher",
    about = "Durably materialize and pull one exact terminal channel fund vector"
)]
struct Args {
    /// Durable `full_close_funding_payout.json` produced only after terminal validity ACK/settle.
    #[arg(long)]
    artifact: PathBuf,

    /// Durable terminal `close_funding_validity_acknowledgement.json` named by the artifact.
    #[arg(long)]
    validity_acknowledgement: PathBuf,

    /// Release-reviewed runtime-code, token-code, proof-schema, and ABI-selector manifest.
    #[arg(long)]
    deployment_manifest: PathBuf,

    /// Independently authenticated SHA-256 of the exact deployment manifest bytes.
    #[arg(long)]
    deployment_manifest_sha256: String,

    /// Private 0600 write-ahead journal. Reuse this exact path after a crash.
    #[arg(long)]
    journal: PathBuf,

    /// Canonical private directory shared by every process which uses this L1 signer.
    #[arg(long)]
    lock_root: PathBuf,

    /// Operator-owned L1 JSON-RPC endpoint.
    #[arg(long)]
    rpc_url: String,

    /// Foundry encrypted-keystore account name (or set INTMAX_L1_ACCOUNT).
    #[arg(long)]
    account: Option<String>,

    /// Maximum wait per transaction for canonical finalized coverage.
    #[arg(long, default_value_t = 3600)]
    finality_timeout_secs: u64,

    /// Chain-31337-only escape for local RPCs without a `finalized` tag.
    #[arg(long, default_value_t = false)]
    allow_unfinalized_devnet: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let config = CloseFundingPublisherConfig {
        payout_envelope_path: args.artifact,
        validity_acknowledgement_path: args.validity_acknowledgement,
        deployment_manifest_path: args.deployment_manifest,
        deployment_manifest_sha256: args.deployment_manifest_sha256,
        journal_path: args.journal,
        lock_root: args.lock_root,
        rpc_url: args.rpc_url,
        account: args.account,
        finality_timeout: Duration::from_secs(args.finality_timeout_secs),
        allow_unfinalized_devnet: args.allow_unfinalized_devnet,
    };
    match publish_close_funding(&config) {
        Ok(publication) => match serde_json::to_string_pretty(&publication) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("close-funding publication output serialization failed: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("close-funding publication failed: {error}");
            ExitCode::FAILURE
        }
    }
}
