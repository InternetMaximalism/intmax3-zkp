//! Multitoken Phase 5b: TWO-TOKEN (ETH + ERC-20) channel-lifecycle E2E, CLI-driven, on a live
//! anvil with REAL proofs (§N, doc/tasks/multitoken-todo.md Phase 5).
//!
//! Extends the single-token `close_lifecycle_cli_e2e` with the ERC-20 lane:
//!
//!   export-reg-record → DeployCloseCli → SimpleERC20 deploy + rollup.registerToken(1)
//!   → setup-backing → init (ETH genesis) → register-token 1 (mid-life TokenRegister, cosigned)
//!   → ETH send → CLOSE with the two-token header (registry [ETH, 1], token_count 2): the REAL
//!     close proof is built and submitted, and the Manager ACCEPTS it — the channel reaches
//!     ClosePending (see the B-2 note below) →
//!   → withdraw (real ETH deposit + REAL balanceOf-delta ERC-20 deposit → finalize →
//!      withdrawNative + withdrawERC20, each its own real withdrawal MLE chain →
//!      pullChannelFunds + pullChannelTokenFunds — REAL ETH and REAL tokens land in the manager)
//!   → per-token conservation: with no finalized close, NOTHING can be claimed out of either
//!     lane (`totalCreditedOut[t] == 0`), and both asset pools sit intact in the manager.
//!
//! SCOPE NOTE (deviations tracked in doc/tasks/multitoken-todo.md Phase 5b) — every fence below
//! is a pre-existing, in-repo-documented follow-up; none is weakened or bypassed here:
//!   - ON-CHAIN CLOSE (B-2, RESOLVED — doc/tasks/b2-delegate-close-threat-model.md option (d)):
//!     `init` always creates the channel with a browser DELEGATE, so the close PI carries
//!     `delegate_count = 1`, while Option B's cosigners-only L1 registration deploys the Manager
//!     with `activeDelegateCount = 0`. This USED TO be refused at limb 94 by a strict equality, and
//!     this E2E pinned that refusal as an EXPECTED negative. That equality was not a security
//!     control: limb 94 decommits a field of the cosigner-signed H1 (N-of-N Falcon authority),
//!     whereas the Manager's `activeDelegateCount` is a deployer assertion cross-checked against
//!     nothing — so it compared a stronger value against a weaker reference and produced only false
//!     negatives. It is now a ONE-SIDED RANGE bind (`delegateCount >= activeDelegateCount` and
//!     `memberCount + delegateCount <= 1024`), which this live delegate-bearing state satisfies, so
//!     the close is ACCEPTED here and the assertions below pin the POSITIVE outcome. The member
//!     half of the boundary (limb 93 + the IMCM registry cross-check) is UNCHANGED strict equality
//!     — `ChannelSettlementManager.t.sol::test_verifyClose_tamperedMemberCountLimb_stillStrict`
//!     pins that it was not collaterally loosened.
//!   - A close with NONZERO amounts[1] additionally needs `cosign-l1-deposit-import` first, whose
//!     `settled_tx_chain` push requires a regenerated base-layer attestation the CLI cannot produce
//!     yet (P1 re-attestation follow-up) — the close circuit's `BalanceBindingMismatch` fail-close
//!     refuses, verified during Phase 5b.
//!   - In-channel token-1 SENDS / the TM-14 mixed-token batch / the C2C ERC-20 leg / the TM-16
//!     post-close claim are not driven here — the CLI's deterministic balance-witness store is
//!     genesis-token-scoped (a token-1 E-1 witness only exists after a refresh of that position,
//!     which has no CLI payload builder yet). Covered by the native proving suites (`wallet_core`
//!     delegate_send_tests: mixed_token_batch_*, inter-channel token tests;
//!     `post_close_claim_circuit` TM-16 suite) and the Foundry proof-bound-token tests.
//!
//! HEAVY: several real MLE/WHIR proofs + anvil; release-only AND `#[ignore]` — run explicitly:
//!   cargo test --release --test two_token_cli_e2e -- --ignored --nocapture
//!
//! SECURITY: this only ORCHESTRATES; soundness is in-circuit + on-chain. The workspace guard
//! restores every tracked fixture it clobbers and removes all scratch.
#![cfg(not(debug_assertions))]

use std::{
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

mod anvil_harness;
use anvil_harness::AnvilNode;

// anvil dev account[0] — a PUBLIC throwaway key; the broadcasting EOA, member-slot-0 payout
// recipient (bound by DeployCloseCli), depositor, and claim caller.
const ANVIL0_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL0_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const PORT: u16 = 8557;
const CHANNEL: u32 = 7;
/// The L1-registered base token index of the test ERC-20.
const ERC20_INDEX: u32 = 1;
/// ERC-20 amount deposited into the rollup (balanceOf-delta path) and withdrawn to the manager
/// via the real `withdrawERC20` chain (== `receivedChannelFunds[1]` after the pull).
const ERC20_AMOUNT: u64 = 40;

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

/// Backs up the tracked `sepolia_*` fixtures the CLI clobbers when staging, restores them on
/// drop, and removes all scratch (repo root + data dir) — the tree is left exactly as found.
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
            "sepolia_erc20_withdrawal_mle.json",
            "sepolia_erc20_withdrawal_payout.json",
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
            "close_intent_full.json",
            "lifecycle.json",
            "lifecycle_validity_mle.json",
            "withdrawal_mle.json",
            "withdrawal_payout.json",
            "erc20_withdrawal_mle.json",
            "erc20_withdrawal_payout.json",
            "withdrawal_claim.json",
            "withdrawal_claim_mle.json",
            "token_register.json",
            "deposit_import.json",
            "payload.json",
            "cosigned_state.json",
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

/// `cast call` returning a uint (first whitespace token).
fn cast_uint(rpc: &str, addr: &str, sig: &str, args: &[&str]) -> u128 {
    let mut call = vec!["call", addr, sig];
    call.extend_from_slice(args);
    let out = cast(rpc, &call);
    out.split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("parse uint from `{out}`"))
}

fn cli(args: &[&str], env: &[(&str, &str)], what: &str) -> String {
    let mut c = Command::new(cli_bin());
    c.args(args)
        .current_dir(repo_root())
        .env("INTMAX_CHANNEL", CHANNEL.to_string())
        // SECURITY: explicitly opt IN to the publicly-derivable deterministic co-signer keys.
        // The CLI now FAILS CLOSED unless exactly one of INTMAX_COSIGNER_KEYFILE (production,
        // external secret) or this flag is set, so a production invocation can never silently
        // fall back to keys computable from the public source tree.
        // See doc/tasks/cosigner-key-provenance.md.
        .env("INTMAX_INSECURE_DETERMINISTIC_KEYS", "1");
    for (k, v) in env {
        c.env(k, v);
    }
    run(&mut c, what)
}

/// Like `cli` but tolerates a nonzero exit — returns (success, combined output). Used for the
/// zero-credit claim, whose final `claimWithdrawalCredit(bytes32)` pull CORRECTLY reverts
/// (`NoWithdrawalCredit`) after the claim proof itself was accepted on-chain.
///
/// B-2: its original caller (the pinned delegate-count close NEGATIVE) became a POSITIVE when the
/// limb-94 strict equality was replaced by the one-sided range bind. It is live again as the
/// backing-deposit-guard refusal check after `withdraw`.
fn cli_allow_fail(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let mut c = Command::new(cli_bin());
    c.args(args)
        .current_dir(repo_root())
        .env("INTMAX_CHANNEL", CHANNEL.to_string())
        // SECURITY: explicitly opt IN to the publicly-derivable deterministic co-signer keys.
        // The CLI now FAILS CLOSED unless exactly one of INTMAX_COSIGNER_KEYFILE (production,
        // external secret) or this flag is set, so a production invocation can never silently
        // fall back to keys computable from the public source tree.
        // See doc/tasks/cosigner-key-provenance.md.
        .env("INTMAX_INSECURE_DETERMINISTIC_KEYS", "1");
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
fn two_token_cli_e2e() {
    if !(tool_present("anvil") && tool_present("forge") && tool_present("cast")) {
        eprintln!("[skip] foundry (anvil/forge/cast) not found — needed for the two-token E2E");
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
            eprintln!(
                "[skip] missing fixture contracts/test/data/{f} — run the close fixture generators first"
            );
            return;
        }
    }

    let _ws = WorkspaceGuard::new();
    let rpc = format!("http://127.0.0.1:{PORT}");

    // ── anvil ──────────────────────────────────────────────────────────────────────────────
    // Automine + `--base-fee 0` + the UNSTICKER THREAD below: with foundry 1.5.1, the
    // close-stack deploy's burst of multi-M-gas VK-init txs reproducibly leaves one tx stuck
    // pending under automine (forge `wait_for_pending` hangs until a manual `evm_mine`;
    // interval mining is WORSE — the tx gets dropped outright and forge waits forever on a
    // receipt that cannot arrive). The unsticker polls `txpool_status` and force-mines whenever
    // anything sits pending. Orchestration-only; no verification semantics touched.
    // Spawns anvil and proves the node answering on PORT is the one we spawned (fresh chain,
    // our own process). See tests/anvil_harness/mod.rs for why a plain `cast block-number` poll
    // is not enough. Killed on drop.
    let _anvil = AnvilNode::spawn("two_token_cli_e2e", PORT, &["--base-fee", "0"]);

    drop(WorkspaceGuard::new()); // pre-clean stale CLI state from any prior aborted run

    // UNSTICKER (see the anvil note above): force-mine whenever a tx sits pending > ~2s.
    let stop_unsticker = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let unsticker = {
        let stop = stop_unsticker.clone();
        let rpc = rpc.clone();
        thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(2));
                let out = Command::new("cast")
                    .args(["rpc", "txpool_status", "--rpc-url", &rpc])
                    .output();
                if let Ok(o) = out {
                    let s = String::from_utf8_lossy(&o.stdout);
                    // {"pending":"0xN",...} — mine unless pending == 0x0.
                    if s.contains("\"pending\"") && !s.contains("\"pending\":\"0x0\"") {
                        let _ = Command::new("cast")
                            .args(["rpc", "evm_mine", "--rpc-url", &rpc])
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status();
                        eprintln!("[two-token-e2e] unsticker: force-mined a stuck pending tx");
                    }
                }
            }
        })
    };
    // Ensure the unsticker stops even on panic-unwind (join on a best-effort basis at the end).
    struct UnstickerGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for UnstickerGuard {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let _unsticker_guard = UnstickerGuard(stop_unsticker.clone());
    let _ = &unsticker;

    // ── deploy: reg record → close stack (all VKs) → SimpleERC20 → registerToken ───────────
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

    // SimpleERC20: deploy, register on the rollup's SET-ONCE registry (TM-10b), mint the
    // depositor's supply.
    let token_deploy = run(
        Command::new("forge")
            .current_dir(repo_root().join("contracts"))
            .args([
                "create",
                "test/tokens/TestTokens.sol:SimpleERC20",
                "--rpc-url",
                &rpc,
                "--private-key",
                ANVIL0_KEY,
                "--broadcast",
                // NOTE: constructor args must come LAST — `--constructor-args` consumes every
                // following token (it swallowed `--rpc-url` when placed earlier).
                "--constructor-args",
                "TwoTokenE2E",
            ]),
        "forge create SimpleERC20",
    );
    let token = find_addr(&token_deploy, "Deployed to:");
    cast(
        &rpc,
        &[
            "send",
            &rollup,
            "registerToken(uint32,address)",
            &ERC20_INDEX.to_string(),
            &token,
            "--private-key",
            ANVIL0_KEY,
        ],
    );
    cast(
        &rpc,
        &[
            "send",
            &token,
            "mint(address,uint256)",
            ANVIL0_ADDR,
            "1000",
            "--private-key",
            ANVIL0_KEY,
        ],
    );

    // ── channel: backing + genesis, then MID-LIFE TokenRegister (cosigned, TM-1) ───────────
    cli(
        &["setup-backing", &rpc, &rollup],
        &[("SETUP_BACKING_NO_ONCHAIN_DEPOSIT", "1")],
        "setup-backing",
    );
    // SECURITY (A-1): delegate opening balance 0 — see the same note in `close_lifecycle_cli_e2e`.
    // `setup-backing`'s `fund` excludes the delegate contribution (`DELEGATE_GENESIS == 0`), so
    // "50" here made `Σ genesis balances > fund`; `create_channel` now installs the canonical zero
    // regardless. This test's only value movement is an ETH send BETWEEN CLI COSIGNERS (slot 0 →
    // slot 1) and an ERC-20 leg on the cosigner slots, so the delegate never needed a balance.
    cli(
        &["gen-contribution", "0", "1", "contribution.json"],
        &[],
        "gen-contribution",
    );
    cli(
        &["init", "contribution.json", "channel_snapshot.json"],
        &[],
        "init",
    );

    let reg_out = cli(
        &[
            "register-token",
            &ERC20_INDEX.to_string(),
            "token_register.json",
        ],
        &[],
        "register-token",
    );
    assert!(
        reg_out.contains("register-token") || reg_out.contains("token_count"),
        "register-token produced no confirmation:\n{reg_out}"
    );

    // NO `cosign-l1-deposit-import` here (see the SCOPE NOTE): the import pushes
    // `settled_tx_chain`, and the CLI close would then correctly fail the close circuit's
    // fail-closed balance binding (a post-import close needs a regenerated base-layer
    // attestation — the pending P1 re-attestation follow-up). The import transition itself is
    // proof-covered natively (delegate_send_tests, token-55 import + cosigner gate).

    // ── an in-channel ETH send (genesis token) so the close state is not genesis-trivial ───
    cli(
        &["send", "0", "1", "5", "payload.json", "0"],
        &[],
        "send t0",
    );
    cli(
        &["cosign", "payload.json", "cosigned_state.json"],
        &[],
        "cosign t0 send",
    );

    // ── close with the TWO-token header (registry [ETH, 1], token_count 2) ─────────────────
    // B-2 (RESOLVED, see the SCOPE NOTE): the CLI builds the REAL two-token close proof for the
    // LIVE delegate-bearing state (`delegate_count == 1`) and the Manager — deployed by the
    // cosigners-only Option B registration with `activeDelegateCount == 0` — now ACCEPTS it,
    // because limb 94 is bound by the one-sided range `1 >= 0` and `3 + 1 <= 1024` instead of the
    // old strict equality against a deployer-asserted count.
    //
    // WHY THIS FLIPPED FROM A PINNED NEGATIVE TO A POSITIVE (it is NOT a weakened assertion): the
    // former refusal was a false negative, not a caught attack. Nothing that the equality
    // protected was lost — the delegate count is still PROOF-BOUND (the close circuit forces limb
    // 94 to equal the `delegate_count` inside the H1 that every cosigner's Falcon signature
    // covers, so no prover without the N-of-N keys can move it by one), the member count is still
    // STRICT-bound to the L1 registration (limb 93 + the IMCM registry cross-check), and payouts
    // remain per-slot authenticated and hard-capped. The negative direction is preserved and
    // covered on-chain: a close that would EXCLUDE an L1-registered delegate, or that exceeds the
    // 1024-participant capacity, still reverts with `CloseDelegateCountOutOfRange`
    // (`ChannelSettlementManager.t.sol::test_verifyClose_delegateCountBelowFloor_reverts` /
    // `..._delegateCountAboveCeiling_reverts`, and the same matrix on the partial-withdrawal lane
    // in `PartialWithdrawal.t.sol`).
    let close_out = cli(
        &["close", &manager, &rpc],
        &[("CLOSE_SV", &sv), ("CLOSE_ADVANCE_TIME", "700")],
        "close (two-token, delegate-bearing)",
    );
    assert!(
        close_out.contains("submitCloseIntent OK") || close_out.contains("close intent submitted"),
        "the delegate-bearing close must now be ACCEPTED on-chain (B-2 range bind), got:\n{close_out}"
    );
    // requestClose (freeze) AND the close intent both landed; the channel is ClosePending until
    // the challenge window elapses and `settle` finalizes it (NOT driven here — see below).
    assert_eq!(
        cast_uint(&rpc, &manager, "channelStatus()(uint8)", &[]),
        1,
        "channel should be ClosePending (requestClose + close intent landed, not yet finalized)"
    );
    // Nothing accrued on either lane — no finalized close.
    let accrued_eth = cast_uint(
        &rpc,
        &manager,
        "finalizedChannelFundAmount(uint32)(uint256)",
        &["0"],
    );
    let accrued_erc20 = cast_uint(
        &rpc,
        &manager,
        "finalizedChannelFundAmount(uint32)(uint256)",
        &[&ERC20_INDEX.to_string()],
    );
    assert_eq!(accrued_eth, 0, "no ETH accrual without a finalized close");
    assert_eq!(
        accrued_erc20, 0,
        "no ERC-20 accrual without a finalized close"
    );

    // ── withdraw: BOTH lanes with real value (ETH deposit + balanceOf-delta ERC-20 deposit,
    //    finalize, withdrawNative + withdrawERC20, pullChannelFunds + pullChannelTokenFunds) ──
    let rollup_token_before = cast_uint(&rpc, &token, "balanceOf(address)(uint256)", &[&rollup]);
    assert_eq!(rollup_token_before, 0);
    cli(
        &["withdraw", &manager, &rpc],
        &[
            ("ROLLUP", &rollup),
            ("WD_ERC20_TOKEN", &ERC20_INDEX.to_string()),
            ("WD_ERC20_AMOUNT", &ERC20_AMOUNT.to_string()),
            ("WD_ERC20_TOKEN_ADDR", &token),
        ],
        "withdraw (two lanes)",
    );

    let received_eth = cast_uint(
        &rpc,
        &manager,
        "receivedChannelFunds(uint32)(uint256)",
        &["0"],
    );
    let received_erc20 = cast_uint(
        &rpc,
        &manager,
        "receivedChannelFunds(uint32)(uint256)",
        &[&ERC20_INDEX.to_string()],
    );
    let manager_eth: u128 = cast(&rpc, &["balance", &manager]).parse().expect("bal");
    let manager_token = cast_uint(&rpc, &token, "balanceOf(address)(uint256)", &[&manager]);
    assert!(received_eth > 0, "manager received no ETH from the rollup");
    assert_eq!(
        manager_eth, received_eth,
        "manager ETH != receivedChannelFunds[0]"
    );
    assert_eq!(
        received_erc20, ERC20_AMOUNT as u128,
        "manager must have received the full ERC-20 lane"
    );
    assert_eq!(
        manager_token, ERC20_AMOUNT as u128,
        "manager ERC-20 balance != receivedChannelFunds[t]"
    );

    // ── BACKING-DEPOSIT GUARD, BOTH lanes (deposit-import-threat-model.md §10.4 Finding B) ──
    //
    // What this is intended to prove about security: `withdraw` makes TWO real deposits to the
    // channel's backing recipient here (native + ERC-20), and BOTH are already spoken for by the
    // withdrawal proof. Before the fix neither hash was recorded anywhere, and the import guard
    // compared against a single scalar — so both were importable, each one crediting the channel a
    // second time against one L1 escrow. This is the case that makes the recorded field a SET
    // rather than a scalar: a scalar could only ever refuse one of them.
    let backing: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("channel_backing.json"))
            .expect("read channel_backing.json"),
    )
    .expect("parse channel_backing.json");
    assert_eq!(
        backing["backing_deposit_status"]
            .as_str()
            .expect("channel_backing.json must record `backing_deposit_status`"),
        "landed",
        "after `withdraw` backing deposits ARE on-chain (this run's setup-backing deferred them)"
    );
    let backing_txs: Vec<String> = backing["backing_deposit_txs"]
        .as_array()
        .expect("channel_backing.json must record `backing_deposit_txs`")
        .iter()
        .map(|v| {
            v.as_str()
                .expect("backing_deposit_txs entries must be strings")
                .to_string()
        })
        .collect();
    assert_eq!(
        backing_txs.len(),
        2,
        "two lanes ⇒ TWO backing-recipient deposits must have been recorded; got {backing_txs:?}"
    );
    for tx in &backing_txs {
        let (ok, out) = cli_allow_fail(
            &[
                "cosign-l1-deposit-import",
                "0",
                tx,
                &rpc,
                "bad_backing_import.json",
                "--allow-unbound-depositor",
            ],
            &[],
        );
        assert!(
            !ok && out.contains("BACKING deposit"),
            "the deposit `withdraw` itself made ({tx}) MUST be refused on import:\n{out}"
        );
    }

    // ── per-token conservation with NO FINALIZED close (TM-3) ──────────────────────────────
    // B-2 note: the close INTENT is now on-chain (accepted above), but `finalizeClose` is NOT
    // driven by this test, so the channel is still ClosePending and no accrual exists. Every
    // assertion below therefore still holds for the SAME reason it held before (no finalized
    // close), not because the close was refused.
    // Without a finalized close there is no accrual, so NOTHING may leave either lane: both
    // proof/nullifier-scoped payout entry point refuses (`NoWithdrawalCredit`), the per-lane
    // paid-out accumulators stay zero, and both REAL asset pools sit intact in the manager.
    // (The positive per-token claim/payout path — per-token caps at payout and cross-token frame —
    // is covered by MultiTokenSettlement.t.sol and the native claim-proving suites; the on-chain
    // two-token close accrual is covered by CloseLifecycleE2E.)
    // Assert the SPECIFIC revert — `NoWithdrawalCredit()` selector 0xe10881ae (=
    // `cast sig "NoWithdrawalCredit()"`) — via eth_call revert data, so an unrelated failure
    // (wrong address, out-of-gas, a different guard) cannot satisfy the conservation check.
    let expect_no_credit_revert = |sig: &str, extra: &[&str], what: &str| {
        let mut args: Vec<&str> = vec!["call", manager.as_str(), sig];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--from", ANVIL0_ADDR, "--rpc-url", rpc.as_str()]);
        let out = Command::new("cast")
            .args(&args)
            .output()
            .expect("cast spawn");
        assert!(
            !out.status.success(),
            "{what} must refuse with no accrued credit"
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("0xe10881ae") || combined.contains("NoWithdrawalCredit"),
            "{what} must revert with NoWithdrawalCredit() (selector 0xe10881ae), got:\n{combined}"
        );
    };
    expect_no_credit_revert(
        "claimWithdrawalCredit(bytes32)",
        &["0x0000000000000000000000000000000000000000000000000000000000000001"],
        "claimWithdrawalCredit(missing ETH proof nullifier)",
    );
    expect_no_credit_revert(
        "claimWithdrawalCredit(bytes32)",
        &["0x0000000000000000000000000000000000000000000000000000000000000002"],
        "claimWithdrawalCredit(missing ERC-20 proof nullifier)",
    );

    let credited_eth = cast_uint(&rpc, &manager, "totalCreditedOut(uint32)(uint256)", &["0"]);
    let credited_erc20 = cast_uint(
        &rpc,
        &manager,
        "totalCreditedOut(uint32)(uint256)",
        &[&ERC20_INDEX.to_string()],
    );
    assert_eq!(
        credited_eth, 0,
        "nothing may be credited out of the ETH lane"
    );
    assert_eq!(
        credited_erc20, 0,
        "nothing may be credited out of the ERC-20 lane"
    );
    assert!(
        credited_eth <= received_eth && credited_erc20 <= received_erc20,
        "PER-TOKEN CAP VIOLATED"
    );
    // Both pools intact, per asset (no cross-token movement anywhere in the flow).
    let manager_eth_after: u128 = cast(&rpc, &["balance", &manager]).parse().expect("bal");
    let manager_token_after = cast_uint(&rpc, &token, "balanceOf(address)(uint256)", &[&manager]);
    assert_eq!(
        manager_eth_after, received_eth,
        "manager ETH pool must be intact"
    );
    assert_eq!(
        manager_token_after, ERC20_AMOUNT as u128,
        "manager ERC-20 pool must be intact"
    );

    eprintln!(
        "[two-token-e2e] OK: mid-life TokenRegister cosigned; delegate-bearing close ACCEPTED \
         on-chain (B-2 one-sided range bind on limb 94); ETH lane received {received_eth} and \
         ERC-20(token {ERC20_INDEX} @ {token}) lane received {received_erc20} REAL tokens via \
         withdrawNative/withdrawERC20 + pulls; conservation held on both lanes (channel \
         {CHANNEL}, rollup {rollup}, manager {manager})."
    );
}
