//! Restart-safe L1 publisher for `public_close_prover` output.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use clap::Parser;
use intmax3_zkp::public_close_publisher::{
    PublicCloseProgress, PublicClosePublisherConfig, PublicCloseReadinessConfig,
    advance_public_close, check_public_close_readiness,
};

#[derive(Debug, Parser)]
#[command(
    name = "public_close_publisher",
    about = "Durably submit and guarded-finalize a keyless public close proof"
)]
struct Arguments {
    /// Read exact-head L1 readiness only: no account, lock, WAL, or transaction is used.
    #[arg(long, default_value_t = false, conflicts_with_all = ["watch", "journal", "signer_lock_root", "account"])]
    check_readiness: bool,
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
    #[arg(long, required_unless_present = "check_readiness")]
    journal: Option<PathBuf>,
    /// Private common lock directory shared by every INTMAX L1 publisher using this signer.
    #[arg(long, required_unless_present = "check_readiness")]
    signer_lock_root: Option<PathBuf>,
    #[arg(long)]
    rpc_url: String,
    /// Foundry encrypted-keystore account name (not an address or raw key).
    #[arg(long, required_unless_present = "check_readiness")]
    account: Option<String>,
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
    if args.check_readiness {
        let readiness = check_public_close_readiness(&PublicCloseReadinessConfig {
            bundle_dir: args.bundle_dir,
            expected_final_channel_state_digest: args.expected_final_channel_state_digest,
            deployment_manifest_path: args.deployment_manifest,
            deployment_manifest_sha256: args.deployment_manifest_sha256,
            rpc_url: args.rpc_url,
            allow_unfinalized_devnet: args.allow_unfinalized_devnet,
        })?;
        println!("{}", serde_json::to_string(&readiness)?);
        return Ok(());
    }
    let config = PublicClosePublisherConfig {
        bundle_dir: args.bundle_dir,
        expected_final_channel_state_digest: args.expected_final_channel_state_digest,
        deployment_manifest_path: args.deployment_manifest,
        deployment_manifest_sha256: args.deployment_manifest_sha256,
        journal_path: args.journal.expect("clap requires a publishing journal"),
        signer_lock_root: args
            .signer_lock_root
            .expect("clap requires a publishing signer lock"),
        rpc_url: args.rpc_url,
        account: args.account.expect("clap requires a publishing account"),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn common_args() -> Vec<&'static str> {
        vec![
            "public_close_publisher",
            "--bundle-dir",
            "bundle",
            "--expected-final-channel-state-digest",
            "0x11",
            "--deployment-manifest",
            "deployment.json",
            "--deployment-manifest-sha256",
            "0x22",
            "--rpc-url",
            "http://localhost:8545",
        ]
    }

    #[test]
    fn readiness_cli_needs_no_signer_or_write_destination() {
        let mut args = common_args();
        args.push("--check-readiness");
        let parsed = Arguments::try_parse_from(args).expect("read-only arguments");
        assert!(parsed.check_readiness);
        assert!(parsed.account.is_none());
        assert!(parsed.journal.is_none());
        assert!(parsed.signer_lock_root.is_none());
    }

    #[test]
    fn readiness_cli_cannot_be_combined_with_publishing_authority() {
        for extra in [
            vec!["--account", "operator"],
            vec!["--journal", "journal.json"],
            vec!["--signer-lock-root", "locks"],
            vec!["--watch"],
        ] {
            let mut args = common_args();
            args.push("--check-readiness");
            args.extend(extra);
            assert!(Arguments::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn publication_still_requires_its_durable_signer_arguments() {
        assert!(Arguments::try_parse_from(common_args()).is_err());
        let mut args = common_args();
        args.extend([
            "--account",
            "operator",
            "--journal",
            "journal.json",
            "--signer-lock-root",
            "locks",
        ]);
        assert!(
            !Arguments::try_parse_from(args)
                .expect("publisher arguments")
                .check_readiness
        );
    }
}
