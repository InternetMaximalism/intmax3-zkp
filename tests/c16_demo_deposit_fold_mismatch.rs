//! C16 — demo-mode (real setup-backing deposit) x withdraw fold mismatch: fail-closed characterization.
//!
//! Scenario (`tests/scenarios/C-fund-loss.md` C16): the browser-demo default makes the REAL on-chain
//! `deposit()` during `setup-backing` (NOT deferred). The integrated `withdraw` then ALWAYS makes its
//! own `deposit()` between the registration and deposit blocks (channel_member.rs:1204-1242), modelling
//! a single deposit folded into block 2. With a PRE-EXISTING setup-backing deposit, the on-chain
//! deposit tree no longer matches the withdrawal/validity proof's fold model, so `finalize` is REJECTED
//! and the CLI dies — fail-closed.
//!
//! This test PINS that the demo combination fails FAIL-CLOSED: `withdraw` errors and the manager
//! receives NOTHING (`receivedChannelFunds == 0`), so no funds move on the mismatched path. It guards
//! against silently shipping a demo path that would either brick withdraw WITHOUT a clear failure, or
//! worse, move funds under a proof/onchain mismatch. The supported integrated path requires the
//! deferred-deposit mode (`SETUP_BACKING_NO_ONCHAIN_DEPOSIT=1`), which the close-lifecycle E2E uses.
//!
//! SECURITY: if `withdraw` were to SUCCEED here (paying the manager despite the fold mismatch), that
//! would be a soundness failure (a proof accepted against a non-matching on-chain deposit tree) — this
//! test would then FAIL, surfacing it. Per CLAUDE.md that is a STOP-and-escalate, not a test to relax.
//!
//! ABNORMALLY HEAVY: real proofs + anvil; the deploy alone can take ~7min+ under host load, and the
//! full run is ~10-15min. OPT-IN ONLY — gated behind `INTMAX_RUN_HEAVY_E2E` (in ADDITION to release +
//! #[ignore]), so even a blanket `cargo test -- --ignored` self-skips it. Run explicitly:
//!   INTMAX_RUN_HEAVY_E2E=1 cargo test --release --test c16_demo_deposit_fold_mismatch -- --ignored --nocapture
//!
//! VALIDATION STATUS (2026-06-22): VALIDATED LIVE on anvil (passed in 667s). Confirmed fail-closed:
//! `setup-backing` made the real on-chain deposit (140000000 wei), `withdraw` then made its own
//! deposit and `finalize` was REJECTED ("script failed: finalize returned false") because the
//! deposit fold no longer matched the validity proof's model; the CLI died at finalizeStep and
//! `manager.receivedChannelFunds` stayed 0 (no funds moved, no proof accepted against a mismatched
//! deposit tree). NOTE: under heavy host load the `forge DeployCloseCli` deploy ran pathologically
//! slowly (~7min for ~10 blocks vs <1min normally) — not a code hang; allow a generous deploy timeout
//! when running this (an over-eager <5min watchdog kills the still-progressing deploy).
#![cfg(not(debug_assertions))]

use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

const ANVIL0_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PORT: u16 = 8556; // distinct from close_lifecycle_cli_e2e (8554) for parallel test binaries
const CHANNEL: u32 = 7;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn data_dir() -> PathBuf {
    repo_root().join("contracts/test/data")
}
fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_channel_member"))
}

fn tool_present(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

struct AnvilGuard(Child);
impl Drop for AnvilGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Backs up the tracked `sepolia_*` fixtures the CLI clobbers when staging, restores them on drop, and
/// removes every scratch file — leaves the working tree exactly as found (copied from
/// close_lifecycle_cli_e2e.rs).
struct WorkspaceGuard {
    backups: Vec<(PathBuf, Option<Vec<u8>>)>,
}
impl WorkspaceGuard {
    fn new() -> Self {
        let staged_tracked = [
            "sepolia_lifecycle.json",
            "sepolia_lifecycle_validity_mle.json",
            "sepolia_withdrawal_mle.json",
            "sepolia_withdrawal_payout.json",
        ];
        let mut backups = Vec::new();
        for f in staged_tracked {
            let p = data_dir().join(f);
            let prev = std::fs::read(&p).ok();
            backups.push((p, prev));
        }
        Self { backups }
    }
}
impl Drop for WorkspaceGuard {
    fn drop(&mut self) {
        for (p, prev) in &self.backups {
            match prev {
                Some(bytes) => {
                    let _ = std::fs::write(p, bytes);
                }
                None => {
                    let _ = std::fs::remove_file(p);
                }
            }
        }
        for f in [
            "sepolia_close_intent.json",
            "sepolia_close_intent_mle.json",
            "sepolia_withdrawal_claim.json",
            "sepolia_withdrawal_claim_mle.json",
            "cli_reg_record.json",
        ] {
            let _ = std::fs::remove_file(data_dir().join(f));
        }
        for f in [
            "cli_reg_record.json",
            "channel_backing.json",
            "channel_attestation.bin",
            "balance_vd.bin",
            "contribution.json",
            "cli_state.json",
            "channel_snapshot.json",
            "close_intent.json",
            "close_intent_mle.json",
            "lifecycle.json",
            "lifecycle_validity_mle.json",
            "withdrawal_mle.json",
            "withdrawal_payout.json",
            "withdrawal_claim.json",
            "withdrawal_claim_mle.json",
            "blob.bin",
        ] {
            let _ = std::fs::remove_file(repo_root().join(f));
        }
    }
}

fn run(cmd: &mut Command, what: &str) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{what} failed:\n{s}");
    s
}

fn cast(rpc: &str, args: &[&str]) -> String {
    let mut c = Command::new("cast");
    c.args(args).args(["--rpc-url", rpc]);
    run(&mut c, "cast").trim().to_string()
}

fn cast_u128(rpc: &str, addr: &str, sig: &str) -> u128 {
    let out = cast(rpc, &["call", addr, sig]);
    out.split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("parse uint from `{out}`"))
}

fn cli(args: &[&str], env: &[(&str, &str)], what: &str) -> String {
    let mut c = Command::new(cli_bin());
    c.args(args)
        .current_dir(repo_root())
        .env("INTMAX_CHANNEL", CHANNEL.to_string());
    for (k, v) in env {
        c.env(k, v);
    }
    run(&mut c, what)
}

/// Run the CLI WITHOUT panicking; return (success, combined output). Used for the step we EXPECT to
/// fail fail-closed.
fn cli_try(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let mut c = Command::new(cli_bin());
    c.args(args)
        .current_dir(repo_root())
        .env("INTMAX_CHANNEL", CHANNEL.to_string());
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().expect("spawn cli");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

fn find_addr(out: &str, label: &str) -> String {
    out.lines()
        .find(|l| l.contains(label))
        .and_then(|l| l.split("0x").nth(1))
        .map(|s| format!("0x{}", &s.trim()[..40]))
        .unwrap_or_else(|| panic!("could not parse {label} from deploy output:\n{out}"))
}

#[test]
#[ignore = "heavy (~minutes, real proofs + anvil/forge/cast); run with --ignored"]
fn c16_demo_deposit_fold_mismatch_is_fail_closed() {
    // ABNORMALLY-HEAVY opt-in gate (policy: heavy E2E tests are NOT default, run only when specified).
    // Even with `--ignored`, this self-skips unless INTMAX_RUN_HEAVY_E2E is set, so a blanket
    // `cargo test -- --ignored` never accidentally launches a ~10-15min (deploy-can-stall) run.
    if std::env::var("INTMAX_RUN_HEAVY_E2E").is_err() {
        eprintln!(
            "[skip] abnormally-heavy E2E — set INTMAX_RUN_HEAVY_E2E=1 to run \
             c16_demo_deposit_fold_mismatch (deploy alone can take ~7min+ under host load)"
        );
        return;
    }
    if !(tool_present("anvil") && tool_present("forge") && tool_present("cast")) {
        eprintln!("[skip] foundry (anvil/forge/cast) not found");
        return;
    }
    for f in [
        "close_lifecycle.json",
        "close_lifecycle_validity_mle.json",
        "close_withdrawal_mle.json",
        "close_intent_mle.json",
        "withdrawal_claim_mle.json",
    ] {
        if !data_dir().join(f).exists() {
            eprintln!("[skip] missing fixture contracts/test/data/{f}");
            return;
        }
    }

    let _ws = WorkspaceGuard::new();
    let rpc = format!("http://127.0.0.1:{PORT}");

    let anvil = Command::new("anvil")
        .args(["--hardfork", "prague", "--port", &PORT.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn anvil");
    let _anvil = AnvilGuard(anvil);
    let mut up = false;
    for _ in 0..40 {
        if Command::new("cast")
            .args(["block-number", "--rpc-url", &rpc])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            up = true;
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    assert!(up, "anvil did not come up on {rpc}");
    drop(WorkspaceGuard::new()); // pre-clean stale scratch

    // ── deploy ──
    cli(&["export-reg-record"], &[], "export-reg-record");
    std::fs::copy(
        repo_root().join("cli_reg_record.json"),
        data_dir().join("cli_reg_record.json"),
    )
    .expect("stage cli_reg_record.json");
    let deploy = run(
        Command::new("forge")
            .current_dir(repo_root().join("contracts"))
            .args([
                "script", "script/DeployCloseCli.s.sol", "--sig", "run",
                "--rpc-url", &rpc, "--private-key", ANVIL0_KEY, "--broadcast",
                // `--slow` + `--skip-simulation`: send txs sequentially waiting for each receipt and
                // skip the on-chain simulation — avoids the intermittent forge<->anvil broadcast hang
                // observed in this environment (the deploy otherwise stalls with no block progress).
                "--slow", "--skip-simulation",
            ]),
        "forge DeployCloseCli",
    );
    let rollup = find_addr(&deploy, "IntmaxRollup:");
    let manager = find_addr(&deploy, "CLOSE_MANAGER_ADDRESS:");

    // ── setup-backing in DEMO MODE: real on-chain deposit (NO deferral flag) ──
    cli(&["setup-backing", &rpc, &rollup], &[], "setup-backing");
    cli(&["gen-contribution", "50", "1", "contribution.json"], &[], "gen-contribution");
    cli(&["init", "contribution.json", "channel_snapshot.json"], &[], "init");

    // Snapshot the manager's received funds before the (expected-failing) withdraw.
    let received_before = cast_u128(&rpc, &manager, "receivedChannelFunds()(uint256)");
    assert_eq!(received_before, 0, "precondition: manager holds no channel funds yet");

    // ── withdraw: EXPECTED to fail fail-closed (finalize rejects the polluted deposit fold) ──
    let (ok, out) = cli_try(&["withdraw", &manager, &rpc], &[("ROLLUP", &rollup)]);

    // The manager must have received NOTHING regardless of how withdraw failed — no funds move on the
    // mismatched path. This is the load-bearing safety assertion.
    let received_after = cast_u128(&rpc, &manager, "receivedChannelFunds()(uint256)");
    assert_eq!(
        received_after, 0,
        "FAIL-CLOSED VIOLATED: manager received {received_after} wei on a deposit-fold-mismatched withdraw\n{out}"
    );

    // Characterize: withdraw must NOT have succeeded in the demo (non-deferred) mode.
    assert!(
        !ok,
        "UNEXPECTED: demo-mode withdraw SUCCEEDED despite the pre-existing setup-backing deposit — \
         a proof was accepted against a non-matching on-chain deposit tree. STOP and escalate (this \
         is a soundness finding, not a test to relax).\n{out}"
    );

    eprintln!(
        "[c16] OK: demo-mode (real setup-backing deposit) withdraw failed fail-closed; \
         manager receivedChannelFunds stayed 0. Output tail:\n{}",
        out.lines().rev().take(8).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n")
    );
}
