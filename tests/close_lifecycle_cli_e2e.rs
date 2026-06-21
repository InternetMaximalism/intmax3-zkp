//! A-3 P5-B: full channel CLOSE-LIFECYCLE end-to-end, CLI-driven, on a live anvil with REAL proofs.
//!
//! Drives the `channel_member` release binary through the ENTIRE lifecycle against a freshly
//! deployed close stack (`DeployCloseCli.s.sol`):
//!
//!   export-reg-record → deploy → setup-backing → init → close → settle → withdraw → claim
//!
//! and asserts that REAL native ETH is deposited into the rollup and flows out to a member:
//!   - `withdraw` escrows `fund` wei via `deposit()`, posts the 3 blocks (EIP-4844 blobs), finalizes,
//!     `withdrawNative`s the channel's funds to the manager, then `pullChannelFunds` pulls them in;
//!   - `claim` proves a member's slot balance and pays it out (`claimWithdrawalCredit`).
//!
//! This is THE live verification point for the close lifecycle (the fixture-based `CloseLifecycleE2E`
//! Solidity test skips the close-intent section on a member-set mismatch; this exercises a channel
//! registered with the CLI's REAL members + delegate, so the close proof actually verifies on-chain).
//!
//! HEAVY: deploys + 3 real MLE/WHIR proofs (close, withdrawal, withdrawal-claim) + anvil; several
//! minutes. Release-only (`#![cfg(not(debug_assertions))]`) AND `#[ignore]` — run explicitly:
//!   cargo test --release --test close_lifecycle_cli_e2e -- --ignored --nocapture
//!
//! SECURITY: this only ORCHESTRATES; soundness is in-circuit + on-chain (the CLI builds real proofs;
//! finalize / withdrawNative / the close-intent verifier are fail-closed gates). It runs the CLI from
//! the repo root (the CLI uses relative `contracts/` paths) and STAGES into the shared
//! `contracts/test/data/sepolia_*`; a Drop guard backs up + restores the clobbered tracked fixtures
//! and removes all scratch so the working tree is left exactly as found.
#![cfg(not(debug_assertions))]

use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

// anvil dev account[0] — a PUBLIC throwaway key; its address is the broadcasting EOA / member-slot-0
// payout recipient (bound by DeployCloseCli) and the `claimWithdrawalCredit` caller.
const ANVIL0_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL0_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const PORT: u16 = 8554;
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

/// Spawn anvil (Prague) and kill it on drop.
struct AnvilGuard(Child);
impl Drop for AnvilGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Backs up the tracked `sepolia_*` fixtures the CLI clobbers when staging, restores them on drop,
/// and removes every scratch file the CLI writes to the repo root / data dir — so the test leaves the
/// working tree exactly as it found it (even on panic unwind).
struct WorkspaceGuard {
    backups: Vec<(PathBuf, Option<Vec<u8>>)>,
}
impl WorkspaceGuard {
    fn new() -> Self {
        // Tracked fixtures `withdraw` overwrites via staging (saved + restored).
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
        // Untracked staged artifacts (close intent + withdrawal-claim + the deploy's reg record).
        for f in [
            "sepolia_close_intent.json",
            "sepolia_close_intent_mle.json",
            "sepolia_withdrawal_claim.json",
            "sepolia_withdrawal_claim_mle.json",
            "cli_reg_record.json",
        ] {
            let _ = std::fs::remove_file(data_dir().join(f));
        }
        // Repo-root scratch the CLI commands write to their cwd.
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

/// Run a command, capture stdout+stderr, panic with the output on failure.
fn run(cmd: &mut Command, what: &str) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{what} failed:\n{s}");
    s
}

/// `cast <args>` (rpc appended), returns trimmed stdout.
fn cast(rpc: &str, args: &[&str]) -> String {
    let mut c = Command::new("cast");
    c.args(args).args(["--rpc-url", rpc]);
    run(&mut c, "cast").trim().to_string()
}

/// Read a uint return value from `cast call` (first whitespace token, drop any `[..]` annotation).
fn cast_u128(rpc: &str, addr: &str, sig: &str) -> u128 {
    let out = cast(rpc, &["call", addr, sig]);
    out.split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("parse uint from `{out}`"))
}

/// Run the `channel_member` CLI from the repo root (it uses relative `contracts/` paths), with the
/// given extra env. Panics on failure with the captured output.
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

fn find_addr(out: &str, label: &str) -> String {
    out.lines()
        .find(|l| l.contains(label))
        .and_then(|l| l.split("0x").nth(1))
        .map(|s| format!("0x{}", &s.trim()[..40]))
        .unwrap_or_else(|| panic!("could not parse {label} from deploy output:\n{out}"))
}

#[test]
#[ignore = "heavy (~minutes, real proofs + anvil/forge/cast); run with --ignored"]
fn close_lifecycle_cli_e2e() {
    if !(tool_present("anvil") && tool_present("forge") && tool_present("cast")) {
        eprintln!("[skip] foundry (anvil/forge/cast) not found — needed for the live close lifecycle");
        return;
    }
    // The deploy reads the (checked-in) close-stack VK fixtures; skip if absent.
    for f in [
        "close_lifecycle.json",
        "close_lifecycle_validity_mle.json",
        "close_withdrawal_mle.json",
        "close_intent_mle.json",
        "withdrawal_claim_mle.json",
    ] {
        if !data_dir().join(f).exists() {
            eprintln!("[skip] missing fixture contracts/test/data/{f} — run the close fixture generators first");
            return;
        }
    }

    let _ws = WorkspaceGuard::new();
    let rpc = format!("http://127.0.0.1:{PORT}");

    // ── anvil ────────────────────────────────────────────────────────────────────────────────
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

    // Pre-clean any stale CLI state from a prior aborted run (the guard cleans on exit too).
    drop(WorkspaceGuard::new());

    // ── export reg record + deploy (CLI-member registration + all VKs) ─────────────────────────
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
                "script",
                "script/DeployCloseCli.s.sol",
                "--sig",
                "run",
                "--rpc-url",
                &rpc,
                "--private-key",
                ANVIL0_KEY,
                "--broadcast",
            ]),
        "forge DeployCloseCli",
    );
    let rollup = find_addr(&deploy, "IntmaxRollup:");
    let manager = find_addr(&deploy, "CLOSE_MANAGER_ADDRESS:");
    let sv = find_addr(&deploy, "SettlementVerifier:");

    // ── setup-backing (no on-chain deposit; withdraw makes it) + init ──────────────────────────
    cli(
        &["setup-backing", &rpc, &rollup],
        &[("SETUP_BACKING_NO_ONCHAIN_DEPOSIT", "1")],
        "setup-backing",
    );
    cli(&["gen-contribution", "50", "1", "contribution.json"], &[], "gen-contribution");
    cli(&["init", "contribution.json", "channel_snapshot.json"], &[], "init");

    // ── close (advance past the 600s grace) ────────────────────────────────────────────────────
    let close_out = cli(
        &["close", &manager, &rpc],
        &[("CLOSE_SV", &sv), ("CLOSE_ADVANCE_TIME", "700")],
        "close",
    );
    assert!(
        close_out.contains("submitCloseIntent OK") || close_out.contains("close intent submitted"),
        "close did not submit on-chain:\n{close_out}"
    );

    // ── settle (elapse the challenge period, then finalizeClose) ───────────────────────────────
    cast(&rpc, &["rpc", "evm_increaseTime", "100"]);
    cast(&rpc, &["rpc", "evm_mine"]);
    cli(&["settle", &manager, &rpc], &[], "settle");
    assert_eq!(
        cast_u128(&rpc, &manager, "channelStatus()(uint8)"),
        2,
        "channel should be Closed after settle"
    );

    // ── withdraw (deposit real ETH → finalize → withdrawNative → pullChannelFunds) ─────────────
    let escrow_before = cast_u128(&rpc, &rollup, "totalEscrowed()(uint256)");
    cli(&["withdraw", &manager, &rpc], &[("ROLLUP", &rollup)], "withdraw");

    let manager_balance: u128 = cast(&rpc, &["balance", &manager])
        .parse()
        .expect("manager balance");
    let received = cast_u128(&rpc, &manager, "receivedChannelFunds()(uint256)");
    let escrow_after = cast_u128(&rpc, &rollup, "totalEscrowed()(uint256)");
    assert!(received > 0, "manager received nothing from the rollup");
    assert_eq!(manager_balance, received, "manager balance != receivedChannelFunds");
    // withdraw deposits `received` wei then withdrawNatives the same amount → net escrow unchanged.
    assert_eq!(escrow_after, escrow_before, "escrow should net to its pre-withdraw value");

    // ── claim (member slot 0 → the deploy EOA; pays out real ETH) ──────────────────────────────
    cli(
        &["claim", &manager, "0", &rpc],
        &[("CLAIM_RECIPIENT", ANVIL0_ADDR)],
        "claim",
    );
    let credited = cast_u128(&rpc, &manager, "totalCreditedOut()(uint256)");
    assert!(credited > 0, "no credit was paid out to the member");
    assert!(
        credited <= received,
        "GLOBAL SOLVENCY VIOLATED: totalCreditedOut {credited} > receivedChannelFunds {received}"
    );
    let manager_balance_after = cast(&rpc, &["balance", &manager])
        .parse::<u128>()
        .expect("manager balance after claim");
    assert_eq!(
        manager_balance_after,
        received - credited,
        "manager balance should drop by exactly the claimed credit"
    );

    eprintln!(
        "[close-lifecycle-e2e] OK: deposited+withdrew {received} wei into manager {manager}; \
         member claimed {credited} wei (channel {CHANNEL}, rollup {rollup})."
    );
}
