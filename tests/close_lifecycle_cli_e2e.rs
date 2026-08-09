//! A-3 P5-B: full channel CLOSE-LIFECYCLE end-to-end, CLI-driven, on a live anvil with REAL proofs.
//!
//! Drives the `channel_member` release binary through the ENTIRE lifecycle against a freshly
//! deployed close stack (`DeployCloseCli.s.sol`):
//!
//!   export-reg-record → deploy → setup-backing → init → close → settle → withdraw → claim
//!
//! and asserts that REAL native ETH is deposited into the rollup and flows out to a member:
//!   - `withdraw` escrows `fund` wei via `deposit()`, posts the 3 blocks (EIP-4844 blobs),
//!     finalizes, `withdrawNative`s the channel's funds to the manager, then `pullChannelFunds`
//!     pulls them in;
//!   - `claim` proves a member's slot balance and pays it out (`claimWithdrawalCredit`).
//!
//! This is THE live verification point for the close lifecycle (the fixture-based
//! `CloseLifecycleE2E` Solidity test skips the close-intent section on a member-set mismatch; this
//! exercises a channel registered with the CLI's REAL members + delegate, so the close proof
//! actually verifies on-chain).
//!
//! B-2 (doc/tasks/b2-delegate-close-threat-model.md, option (d)): this channel's live state carries
//! `delegate_count = 1` while the Option B (cosigners-only) L1 registration deploys the Manager
//! with `activeDelegateCount = 0`. Until B-2 that mismatch was refused by a strict equality on
//! close PI limb 94, so the `close` step below could not land for ANY channel this CLI creates.
//! Limb 94 is now bound by a one-sided range (floor = the registered count, ceiling = the
//! 1024-participant capacity), which `1 >= 0` satisfies, so the close asserted below is expected to
//! succeed. Limb 93 (`memberCount`) is UNCHANGED strict equality.
//!
//! HEAVY: deploys + 3 real MLE/WHIR proofs (close, withdrawal, withdrawal-claim) + anvil; several
//! minutes. Release-only (`#![cfg(not(debug_assertions))]`) AND `#[ignore]` — run explicitly:
//!   cargo test --release --test close_lifecycle_cli_e2e -- --ignored --nocapture
//!
//! SECURITY: this only ORCHESTRATES; soundness is in-circuit + on-chain (the CLI builds real
//! proofs; finalize / withdrawNative / the close-intent verifier are fail-closed gates). It runs
//! the CLI from the repo root (the CLI uses relative `contracts/` paths) and STAGES into the shared
//! `contracts/test/data/sepolia_*`; a Drop guard backs up + restores the clobbered tracked fixtures
//! and removes all scratch so the working tree is left exactly as found.
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    circuits::test_utils::block_witness_generator::test_recipient_for,
    ethereum_types::u32limb_trait::U32LimbTrait,
};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

// anvil dev account[0] — a PUBLIC throwaway key; its address is the broadcasting EOA /
// member-slot-0 payout recipient (bound by DeployCloseCli) and the `claimWithdrawalCredit` caller.
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
/// and removes every scratch file the CLI writes to the repo root / data dir — so the test leaves
/// the working tree exactly as it found it (even on panic unwind).
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

/// Like `cast_u128` but with one call argument (e.g. the per-token accounting getters).
fn cast_u128_arg(rpc: &str, addr: &str, sig: &str, arg: &str) -> u128 {
    let out = cast(rpc, &["call", addr, sig, arg]);
    out.split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("parse uint from `{out}`"))
}

/// `manager.withdrawalCredits(0, who)` — the accrued, not-yet-pulled ETH credit of an address.
/// This is the map `submitWithdrawalClaim` writes at the PROOF-BOUND `claim.recipient`, so it is
/// the direct observation of "where did the claim's money actually go".
fn credit_of(rpc: &str, manager: &str, who: &str) -> u128 {
    let out = cast(
        rpc,
        &[
            "call",
            manager,
            "withdrawalCredits(uint32,address)(uint256)",
            "0",
            who,
        ],
    );
    out.split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("parse uint from `{out}`"))
}

/// The amount the claim CLI actually PROVED, from its `… (amount N)` line. Read from the CLI (not
/// re-derived here) so the assertion compares the on-chain accounting against the proof's own
/// public input rather than against a second guess at the genesis balance.
fn parse_claim_amount(out: &str) -> u64 {
    out.lines()
        .find(|l| l.contains("[claim] wrote") && l.contains("(amount "))
        .and_then(|l| l.rsplit("(amount ").next())
        .and_then(|s| s.trim_end_matches(')').trim().parse().ok())
        .unwrap_or_else(|| panic!("could not parse the claimed amount from:\n{out}"))
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
        eprintln!(
            "[skip] foundry (anvil/forge/cast) not found — needed for the live close lifecycle"
        );
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
            eprintln!(
                "[skip] missing fixture contracts/test/data/{f} — run the close fixture generators first"
            );
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
    // SECURITY (A-1): the delegate's opening balance is 0, matching what `setup-backing` actually
    // funded (`Σ genesis_amount(cosigner slots) + DELEGATE_GENESIS`, `DELEGATE_GENESIS == 0`) and
    // what the production browser sends (`wallet-live.html` passes `toBase('0')`). This used to
    // pass "50", which made `Σ genesis balances` exceed the L1-backed `fund` by 50 base units —
    // the unbacked-contribution lane A-1 closed. `create_channel` now installs the canonical zero
    // regardless, so this argument no longer influences the state; it is corrected so the test
    // states the truth. This lifecycle never spends, withdraws or claims the delegate's slot (it
    // claims slot 0 only), so nothing here needed the delegate to be funded; a test that DID need
    // a funded delegate would fund it through `cosign-l1-deposit-import`, which moves
    // `channel_fund` and the slot leaf together (covered end-to-end by `itx_faucet_cli_e2e`).
    cli(
        &["gen-contribution", "0", "1", "contribution.json"],
        &[],
        "gen-contribution",
    );
    // B-1b: the CLAIM's recipient is the cosigner-signed balance-slot LEAF address, not anything
    // L1 registration says (`registeredRecipientOf` has no runtime read; `submitWithdrawalClaim`
    // credits the proof-bound `claim.recipient` and `claimWithdrawalCredit` pays `msg.sender`).
    // The genesis default `test_recipient_for(channel, slot)` is a SYNTHETIC address nobody holds
    // a key for, so a slot-0 claim would credit an address that can NEVER pull — the payout would
    // be permanently stranded. Route slot 0's LEAF (the only authoritative binding) to the anvil
    // EOA that later calls `claimWithdrawalCredit`, and assert below that the ETH actually lands.
    // Every other slot keeps the synthetic default.
    cli(
        &["init", "contribution.json", "channel_snapshot.json"],
        &[("CLI_RECIPIENT_SLOT_0", ANVIL0_ADDR)],
        "init",
    );

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
    cli(
        &["withdraw", &manager, &rpc],
        &[("ROLLUP", &rollup)],
        "withdraw",
    );

    let manager_balance: u128 = cast(&rpc, &["balance", &manager])
        .parse()
        .expect("manager balance");
    // Multitoken Phase 3: the manager's accounting is per BASE token — ETH is lane 0.
    let received = cast_u128_arg(&rpc, &manager, "receivedChannelFunds(uint32)(uint256)", "0");
    let escrow_after = cast_u128(&rpc, &rollup, "totalEscrowed()(uint256)");
    assert!(received > 0, "manager received nothing from the rollup");
    assert_eq!(
        manager_balance, received,
        "manager balance != receivedChannelFunds"
    );
    // withdraw deposits `received` wei then withdrawNatives the same amount → net escrow unchanged.
    assert_eq!(
        escrow_after, escrow_before,
        "escrow should net to its pre-withdraw value"
    );

    // ── claim (member slot 0 → the deploy EOA; pays out real ETH) ──────────────────────────────
    // The recipient MUST equal the genesis leaf recipient set at `init` (B-1b: the claim witness
    // fails closed with `RecipientMismatch` otherwise — it is the leaf, not L1 registration, that
    // binds the payout address).
    assert_eq!(
        credit_of(&rpc, &manager, ANVIL0_ADDR),
        0,
        "the claimant must start with no accrued credit"
    );
    let claim_out = cli(
        &["claim", &manager, "0", &rpc],
        &[("CLAIM_RECIPIENT", ANVIL0_ADDR)],
        "claim",
    );
    let claimed_amount = parse_claim_amount(&claim_out);
    let credited = cast_u128_arg(&rpc, &manager, "totalCreditedOut(uint32)(uint256)", "0");
    assert!(credited > 0, "no credit was paid out to the member");
    // THE PAYOUT ACTUALLY LANDED, not just "the claim proof verified". `submitWithdrawalClaim`
    // credits the PROOF-BOUND `claim.recipient` and `claimWithdrawalCredit` moves ETH to
    // `msg.sender` (the anvil EOA) only if that EOA is the credited address — so
    // `totalCreditedOut == the proved amount` can only hold if the credit accrued to an address
    // the test actually controls. This is the regression guard for the whole class: a claim
    // credited to the SYNTHETIC default recipient would revert the pull (NoWithdrawalCredit) and,
    // if it somehow did not, would leave the amount stranded there — asserted separately below.
    assert_eq!(
        credited, claimed_amount as u128,
        "totalCreditedOut != the proved claim amount — the credit did not reach the claimant"
    );
    assert_eq!(
        credit_of(&rpc, &manager, ANVIL0_ADDR),
        0,
        "the claimant's credit should be fully pulled"
    );
    // Nothing may be parked at the synthetic per-(channel, slot) default — no key exists for it,
    // so any credit there is permanently unclaimable.
    let synthetic_slot0 = test_recipient_for(CHANNEL, 0).to_hex();
    assert_eq!(
        credit_of(&rpc, &manager, &synthetic_slot0),
        0,
        "credit stranded at the unclaimable synthetic recipient {synthetic_slot0}"
    );
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
