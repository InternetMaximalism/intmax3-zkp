//! Testnet $ITX faucet: FULL BOOTSTRAP + REPEATED DRIPS, CLI-driven, on a live anvil with REAL
//! proofs (multitoken §N; runbook `doc/tasks/regen-and-redeploy-runbook.md` Step 3c).
//!
//! This drives the operator sequence exactly as documented, then the relay's per-drip leg:
//!
//!   Deploy.s.sol (IntmaxRollup) → forge create IntmaxTestTokenITX → registerToken(ITX_INDEX, itx)
//!   → setup-backing → init (ETH genesis; slot 3 = the browser DELEGATE)
//!   → register-token ITX_INDEX      (cosigned TokenRegister → ITX gets LOCAL slot 1)
//!   → approve + deposit(recipient, ITX_INDEX, supply, 0) with msg.value 0
//!     (the rollup credits a MEASURED balanceOf delta — asserted on-chain)
//!   → cosign-l1-deposit-import FAUCET_SLOT <deposit_tx> <rpc> --allow-unbound-depositor
//!     (amount / depositor / token_index are read from the tx's on-chain `Deposited` log; the
//!      step is preceded by an adversarial battery of refusals — see the block at the call site)
//!   → [drip 1] refresh FAUCET_SLOT 1 ; send FAUCET_SLOT → DELEGATE ; cosign
//!   → [drip 2] refresh FAUCET_SLOT 1 ; send FAUCET_SLOT → COSIGNER 1 ; cosign
//!   → verify by DECRYPTION, not bookkeeping.
//!   → [bring your own $ITX — the BROWSER-SHAPED path] a MEMBER, signing from its own bound (B-1b)
//!     exit address, does approve(rollup, amt) → deposit(recipient, ITX_INDEX, amt, 0) with
//!     msg.value 0 → `cosign-l1-deposit-import <slot> <tx> <rpc> l1_import_cosigned.json` with the
//!     EXACT argv `/api/import-deposit` builds and NO `--allow-unbound-depositor`. The depositor's
//!     in-channel balance and the channel's per-token fund must each rise by exactly the deposit.
//!
//! WHAT IT IS MEANT TO PROVE
//!   1. THE MECHANISM EXISTS AT ALL. A homomorphically credited (the import) or just-spent (the
//!      previous drip) position is UNSPENDABLE — `send` refuses it fail-closed — and `refresh` is
//!      the value-preserving way out. Both halves are asserted, so a regression that quietly makes
//!      a stale witness "work" fails here.
//!   2. THE FAUCET CANNOT MINT. `channel_fund.amounts[ITX_SLOT]` is set once by the import and is
//!      INVARIANT across every drip: the drips only redistribute an already-deposited, escrowed
//!      supply. Asserted before and after.
//!   3. THE VALUE ACTUALLY MOVED, BY EXACTLY THE DRIP. `refresh` decrypts the position from the
//!      AUTHENTICATED state and prints the plaintext, so the recipient's `+DRIP` and the faucet's
//!      `-2·DRIP` are read out of the co-signed channel state, not out of CLI bookkeeping. Drip 2
//!      additionally goes to a CLI-controlled slot, so `cosign` itself runs the recipient
//!      decryption check in-protocol (`verify_send_transition` with the expected amount).
//!   4. THE FAUCET CAN DRIP REPEATEDLY — the property a one-shot demo member never needed.
//!
//! HEAVY: real Plonky3 E-1/Refresh STARKs at Production level + a base-layer balance proof +
//! anvil/forge/cast. Release-only AND `#[ignore]` — run explicitly:
//!   cargo test --release --test itx_faucet_cli_e2e -- --ignored --nocapture
//!
//! SECURITY: this only ORCHESTRATES. Soundness is in-circuit (RefreshAir value preservation, E-1,
//! the co-signer gates) and on-chain (the measured-delta ERC-20 escrow). The workspace guard
//! removes every scratch file it creates.
#![cfg(not(debug_assertions))]

use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

/// anvil dev account[0] — a PUBLIC throwaway key; deployer, ITX holder, depositor.
const ANVIL0_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL0_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const PORT: u16 = 8559;
const CHANNEL: u32 = 7;

/// The L1-registered base token index of $ITX (runbook default).
const ITX_INDEX: u32 = 1;
/// LOCAL registry position ITX lands on: genesis ETH occupies 0, the append puts ITX at 1.
const ITX_LOCAL_SLOT: u32 = 1;
/// The CLI CO-SIGNING member that holds the faucet supply (slot 0 is the BP/builder slot).
const FAUCET_SLOT: u32 = 2;
/// The browser DELEGATE `init` joins (3 CLI cosigners occupy 0..3).
const DELEGATE_SLOT: u32 = 3;
/// A second CLI cosigner, used as drip 2's recipient so `cosign` exercises the in-protocol
/// recipient-decryption check and the E2E can read the credited plaintext back.
const COSIGNER_RECIPIENT_SLOT: u32 = 1;

/// L1 supply of $ITX (uint256 — unconstrained). $ITX has 6 decimals, so 1 ITX = 1_000_000 base
/// units; this is 1,000,000,000 ITX.
const ITX_L1_SUPPLY: &str = "1000000000000000"; // 1e9 ITX
/// Deposited + imported into the channel. MUST fit u64: in-channel balances are u64 base units.
/// At 6 decimals the per-position ceiling is ~18.4 trillion ITX, so 1,000,000 ITX is far inside it
/// (it would have been 0.54 of u64::MAX at 18 decimals — see the contract's `decimals` note).
const FAUCET_SUPPLY: u64 = 1_000_000_000_000; // 1,000,000 ITX
/// One drip (runbook default `FAUCET_DRIP`).
const DRIP: u64 = 100_000_000; // 100 ITX

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
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

/// Removes every scratch file this test creates in the repo root, on drop. Nothing TRACKED is
/// touched (the faucet flow stages no repo fixtures).
struct WorkspaceGuard;
impl Drop for WorkspaceGuard {
    fn drop(&mut self) {
        for f in [
            "channel_backing.json",
            "channel_attestation.bin",
            "balance_vd.bin",
            "contribution.json",
            "cli_state.json",
            "channel_snapshot.json",
            "token_register.json",
            "itx_import.json",
            "faucet_refresh.json",
            "faucet_payload.json",
            "faucet_cosigned.json",
            "probe_refresh.json",
            "gen_send_a.json",
            "gen_send_b.json",
            "byo_import.json",
            "byo_refresh.json",
            "l1_import_cosigned.json",
            "bad_import.json",
            "replay_import.json",
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
        .env("INTMAX_CHANNEL", CHANNEL.to_string());
    for (k, v) in env {
        c.env(k, v);
    }
    run(&mut c, what)
}

/// Like `cli` but tolerates a nonzero exit — returns (success, combined output).
fn cli_allow_fail(args: &[&str]) -> (bool, String) {
    let mut c = Command::new(cli_bin());
    c.args(args)
        .current_dir(repo_root())
        .env("INTMAX_CHANNEL", CHANNEL.to_string());
    let out = c.output().expect("spawn cli");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

/// First line that mentions `label` AND carries an address. The `&& contains("0x")` matters:
/// `Deploy.s.sol` prints a `=== IntmaxRollup smoke deploy ===` banner before the address line.
fn find_addr(out: &str, label: &str) -> String {
    out.lines()
        .find(|l| l.contains(label) && l.contains("0x"))
        .and_then(|l| l.split("0x").nth(1))
        .map(|s| format!("0x{}", &s.trim()[..40]))
        .unwrap_or_else(|| panic!("could not parse {label} from output:\n{out}"))
}

/// `refresh <slot> <token_slot>` prints `… re-encrypted (value N, state_version V)`. The value is
/// DECRYPTED from the co-signed state by the refresh prover itself, so parsing it here reads the
/// authenticated channel balance rather than any CLI-side bookkeeping.
fn refresh_value(out: &str) -> u64 {
    out.split("(value ")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| panic!("could not parse the refreshed value from:\n{out}"))
}

/// The channel's per-token fund at `token_slot`, read from the co-signed snapshot.
fn fund_amount(token_slot: usize) -> u128 {
    let text = std::fs::read_to_string(repo_root().join("channel_snapshot.json"))
        .expect("read channel_snapshot.json");
    let v: serde_json::Value = serde_json::from_str(&text).expect("parse channel_snapshot.json");
    let amounts = v["state"]["channelFund"]["amounts"]
        .as_array()
        .unwrap_or_else(|| panic!("channelFund.amounts missing in the snapshot"));
    // Amounts serialize as decimal strings (u256) — never as JS numbers.
    let a = &amounts[token_slot];
    a.as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| a.as_u64().map(u128::from))
        .unwrap_or_else(|| panic!("could not read fund amount at token slot {token_slot}: {a}"))
}

#[test]
#[ignore = "heavy (~minutes, real proofs + anvil/forge/cast); run with --ignored"]
fn itx_faucet_cli_e2e() {
    if !(tool_present("anvil") && tool_present("forge") && tool_present("cast")) {
        eprintln!("[skip] foundry (anvil/forge/cast) not found — needed for the ITX faucet E2E");
        return;
    }

    let _ws = WorkspaceGuard;
    drop(WorkspaceGuard); // pre-clean any stale CLI state from an aborted run
    let rpc = format!("http://127.0.0.1:{PORT}");

    // ── anvil ──────────────────────────────────────────────────────────────────────────────
    let anvil = Command::new("anvil")
        .args([
            "--hardfork",
            "prague",
            "--base-fee",
            "0",
            "--port",
            &PORT.to_string(),
        ])
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

    // ── runbook 3c.1/3c.2: deploy the rollup, deploy $ITX, register it SET-ONCE ─────────────
    let deploy = run(
        Command::new("forge")
            .current_dir(repo_root().join("contracts"))
            .args([
                "script",
                "script/Deploy.s.sol",
                "--rpc-url",
                &rpc,
                "--private-key",
                ANVIL0_KEY,
                "--broadcast",
            ]),
        "forge Deploy.s.sol",
    );
    let rollup = find_addr(&deploy, "IntmaxRollup");

    let token_deploy = run(
        Command::new("forge")
            .current_dir(repo_root().join("contracts"))
            .args([
                "create",
                "test/tokens/IntmaxTestTokenITX.sol:IntmaxTestTokenITX",
                "--rpc-url",
                &rpc,
                "--private-key",
                ANVIL0_KEY,
                "--broadcast",
                // NOTE: constructor args must come LAST (`--constructor-args` consumes every
                // following token).
                "--constructor-args",
                ITX_L1_SUPPLY,
            ]),
        "forge create IntmaxTestTokenITX",
    );
    let itx = find_addr(&token_deploy, "Deployed to:");
    assert_eq!(
        cast(&rpc, &["call", &itx, "symbol()(string)"]).replace('"', ""),
        "ITX"
    );
    cast(
        &rpc,
        &[
            "send",
            &rollup,
            "registerToken(uint32,address)",
            &ITX_INDEX.to_string(),
            &itx,
            "--private-key",
            ANVIL0_KEY,
        ],
    );

    // ── runbook 3c: channel backing + genesis (slot 3 = the browser delegate) ───────────────
    cli(
        &["setup-backing", &rpc, &rollup],
        &[("SETUP_BACKING_NO_ONCHAIN_DEPOSIT", "1")],
        "setup-backing",
    );
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

    // ── `gen-send` randomness must be FRESH per invocation (security review item 1) ────────
    // Two gen-send calls against the SAME, still-untouched genesis state both pass the genesis-ct
    // guard — neither has been co-signed, so the guard cannot separate them. With the old
    // `seed`-derived RNG both replayed the same Regev `r`, which leaks the difference of the two
    // drafted amounts to anyone who sees both payloads. Fresh per-invocation randomness makes the
    // two payloads differ even for IDENTICAL inputs; a byte-identical pair here would mean the
    // reuse is back. Neither payload is co-signed, so the head is untouched.
    for out in ["gen_send_a.json", "gen_send_b.json"] {
        cli(
            &[
                "gen-send",
                "0",
                "1",
                "0",
                "0",
                "channel_snapshot.json",
                out,
                "0",
            ],
            &[],
            "gen-send (randomness-freshness probe)",
        );
    }
    let a = std::fs::read_to_string(repo_root().join("gen_send_a.json")).expect("gen_send_a");
    let b = std::fs::read_to_string(repo_root().join("gen_send_b.json")).expect("gen_send_b");
    assert_ne!(
        a, b,
        "two gen-send payloads built from identical inputs must NOT be byte-identical — identical \
         output means the encryption randomness is derived from `seed` again and is being replayed"
    );

    // ── runbook 3c.3: give ITX a LOCAL slot (cosigned, append-only TokenRegister) ───────────
    let reg_out = cli(
        &[
            "register-token",
            &ITX_INDEX.to_string(),
            "token_register.json",
        ],
        &[],
        "register-token",
    );
    assert!(
        reg_out.contains(&format!("registered at local slot {ITX_LOCAL_SLOT}")),
        "ITX must land at local slot {ITX_LOCAL_SLOT}:\n{reg_out}"
    );
    assert_eq!(
        fund_amount(ITX_LOCAL_SLOT as usize),
        0,
        "a TokenRegister is header-only — it must not fund anything"
    );

    // FAIL-CLOSED (1): an unfunded, never-witnessed position cannot send. The faucet member has
    // no ITX yet and no locally-reproducible ciphertext at that position.
    let (ok, out) = cli_allow_fail(&[
        "send",
        &FAUCET_SLOT.to_string(),
        &DELEGATE_SLOT.to_string(),
        &DRIP.to_string(),
        "faucet_payload.json",
        &ITX_LOCAL_SLOT.to_string(),
    ]);
    assert!(
        !ok,
        "a position with no balance witness must not send:\n{out}"
    );
    assert!(
        out.contains("no spendable balance witness"),
        "the refusal must name the missing witness, got:\n{out}"
    );

    // ── runbook 3c.4: escrow the faucet supply on L1 (msg.value 0, measured balanceOf delta) ─
    let deposit_recipient = {
        let text = std::fs::read_to_string(repo_root().join("channel_backing.json"))
            .expect("read channel_backing.json");
        let v: serde_json::Value = serde_json::from_str(&text).expect("parse backing");
        v["deposit_recipient"]
            .as_str()
            .expect("backing has no deposit_recipient")
            .to_string()
    };
    cast(
        &rpc,
        &[
            "send",
            &itx,
            "approve(address,uint256)",
            &rollup,
            &FAUCET_SUPPLY.to_string(),
            "--private-key",
            ANVIL0_KEY,
        ],
    );
    // `--json` so we can capture the REAL transaction hash: the import is now verified against
    // this transaction's on-chain `Deposited` log (deposit-import-threat-model.md).
    let deposit_send = cast(
        &rpc,
        &[
            "send",
            &rollup,
            "deposit(bytes32,uint32,uint256,bytes32)",
            &deposit_recipient,
            &ITX_INDEX.to_string(),
            &FAUCET_SUPPLY.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--value",
            "0",
            "--private-key",
            ANVIL0_KEY,
            "--json",
        ],
    );
    let deposit_tx = deposit_send
        .split("\"transactionHash\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or_else(|| panic!("no transactionHash in deposit output:\n{deposit_send}"))
        .to_string();
    // The escrow grew by exactly the deposit — the rollup measured the real balanceOf delta.
    assert_eq!(
        cast_uint(
            &rpc,
            &rollup,
            "escrowedByToken(uint32)(uint256)",
            &[&ITX_INDEX.to_string()]
        ),
        FAUCET_SUPPLY as u128,
        "the rollup must hold the full ITX deposit"
    );
    assert_eq!(
        cast_uint(&rpc, &itx, "balanceOf(address)(uint256)", &[&rollup]),
        FAUCET_SUPPLY as u128,
        "the rollup's real ITX balance must equal the escrow"
    );

    // ── runbook 3c.5: import the deposit to the FAUCET member (cosigned, TM-7 resolution) ───
    // ── deposit-import ADVERSARIAL BATTERY (deposit-import-threat-model.md) ─────────────────
    // These run against the LIVE anvil with a fully backed channel, immediately before the honest
    // import. Each one is a way an attacker previously minted unbacked in-channel balance (or
    // wedged the channel's exit forever) with a single unauthenticated request.
    //
    // A1 — a FABRICATED deposit: a tx hash that does not exist. This is the original one-curl
    // vulnerability. (It also pins `--async` on `cast receipt`: without it the CLI would BLOCK
    // forever here instead of refusing, so a hang in this assertion is a real regression.)
    let fake_tx = format!("0x{}", "ab".repeat(32));
    let (ok, out) = cli_allow_fail(&[
        "cosign-l1-deposit-import",
        &FAUCET_SLOT.to_string(),
        &fake_tx,
        &rpc,
        "bad_import.json",
        "--allow-unbound-depositor",
    ]);
    assert!(!ok, "a fabricated deposit tx must be refused:\n{out}");

    // A3/A5 — a REAL, successful transaction that carries no `Deposited` log for this channel
    // (the ERC-20 `approve` above). A tx hash alone must not be enough; the log must be there.
    let approve_send = cast(
        &rpc,
        &[
            "send",
            &itx,
            "approve(address,uint256)",
            &rollup,
            "1",
            "--private-key",
            ANVIL0_KEY,
            "--json",
        ],
    );
    let approve_tx = approve_send
        .split("\"transactionHash\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("approve tx hash")
        .to_string();
    let (ok, out) = cli_allow_fail(&[
        "cosign-l1-deposit-import",
        &FAUCET_SLOT.to_string(),
        &approve_tx,
        &rpc,
        "bad_import.json",
        "--allow-unbound-depositor",
    ]);
    assert!(
        !ok && out.contains("no `Deposited` log"),
        "a tx with no Deposited log must be refused:\n{out}"
    );

    // A4 — a REAL deposit into the SAME rollup but for a DIFFERENT `recipient`, i.e. value
    // escrowed for ANOTHER channel. Importing it here would credit this channel with someone
    // else's money.
    let other_recipient = format!("0x{}", "11".repeat(32));
    let other_send = cast(
        &rpc,
        &[
            "send",
            &rollup,
            "deposit(bytes32,uint32,uint256,bytes32)",
            &other_recipient,
            "0",
            "1000",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--value",
            "1000",
            "--private-key",
            ANVIL0_KEY,
            "--json",
        ],
    );
    let other_tx = other_send
        .split("\"transactionHash\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("other-channel deposit tx hash")
        .to_string();
    let (ok, out) = cli_allow_fail(&[
        "cosign-l1-deposit-import",
        &FAUCET_SLOT.to_string(),
        &other_tx,
        &rpc,
        "bad_import.json",
        "--allow-unbound-depositor",
    ]);
    assert!(
        !ok && out.contains("no `Deposited` log"),
        "a deposit made for a DIFFERENT channel must be refused:\n{out}"
    );

    // A6 — reorg safety: the confirmation floor is enforced even on a dev chain when the caller
    // asks for a depth the chain has not reached.
    let (ok, out) = cli_allow_fail(&[
        "cosign-l1-deposit-import",
        &FAUCET_SLOT.to_string(),
        &deposit_tx,
        &rpc,
        "bad_import.json",
        "100000",
        "--allow-unbound-depositor",
    ]);
    assert!(
        !ok && out.contains("confirmation"),
        "an under-confirmed deposit must be refused:\n{out}"
    );

    // A8 — credit binding, DEFAULT leg: without the explicit flag, a deposit from an address that
    // is not the slot's B-1b bound recipient is refused. This is what stops Mallory crediting
    // herself; the operator/faucet case must opt in visibly.
    let (ok, out) = cli_allow_fail(&[
        "cosign-l1-deposit-import",
        &FAUCET_SLOT.to_string(),
        &deposit_tx,
        &rpc,
        "bad_import.json",
    ]);
    assert!(
        !ok && out.contains("bound"),
        "an unbound depositor must be refused without the explicit flag:\n{out}"
    );

    // A8b — the UNCONDITIONAL leg, and the one that matters most: a deposit made BY an address
    // that IS some member's bound (B-1b) exit address can NEVER be credited to a different slot,
    // even with --allow-unbound-depositor. This is "Mallory imports Alice's genuine deposit into
    // Mallory's slot". We impersonate the faucet slot's own bound recipient on anvil so the
    // deposit is genuinely FROM a bound address.
    let bound_addr = {
        let text = std::fs::read_to_string(repo_root().join("channel_snapshot.json"))
            .expect("read channel_snapshot.json");
        let v: serde_json::Value = serde_json::from_str(&text).expect("parse snapshot");
        v["state"]["balanceState"]["recipients"][FAUCET_SLOT as usize]
            .as_str()
            .expect("recipients[FAUCET_SLOT]")
            .to_string()
    };
    cast(
        &rpc,
        &["rpc", "anvil_setBalance", &bound_addr, "0xde0b6b3a7640000"],
    );
    cast(&rpc, &["rpc", "anvil_impersonateAccount", &bound_addr]);
    let bound_send = cast(
        &rpc,
        &[
            "send",
            &rollup,
            "deposit(bytes32,uint32,uint256,bytes32)",
            &deposit_recipient,
            "0",
            "1000",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--value",
            "1000",
            "--from",
            &bound_addr,
            "--unlocked",
            "--json",
        ],
    );
    let bound_tx = bound_send
        .split("\"transactionHash\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("bound-depositor deposit tx hash")
        .to_string();
    cast(
        &rpc,
        &["rpc", "anvil_stopImpersonatingAccount", &bound_addr],
    );
    let (ok, out) = cli_allow_fail(&[
        "cosign-l1-deposit-import",
        &DELEGATE_SLOT.to_string(),
        &bound_tx,
        &rpc,
        "bad_import.json",
        "--allow-unbound-depositor",
    ]);
    assert!(
        !ok && out.contains("CREDIT MISDIRECTION REFUSED"),
        "a deposit from a BOUND address must never be credited elsewhere, flag or not:\n{out}"
    );

    // …and the channel's OWN backing deposit is not importable either (it is already counted in
    // the genesis fund; importing it would credit the channel twice against one L1 escrow).
    let backing_tx = {
        let text = std::fs::read_to_string(repo_root().join("channel_backing.json"))
            .expect("read channel_backing.json");
        let v: serde_json::Value = serde_json::from_str(&text).expect("parse backing");
        v["deposit_tx"].as_str().unwrap_or("").to_string()
    };
    if !backing_tx.is_empty() {
        let (ok, out) = cli_allow_fail(&[
            "cosign-l1-deposit-import",
            &FAUCET_SLOT.to_string(),
            &backing_tx,
            &rpc,
            "bad_import.json",
            "--allow-unbound-depositor",
        ]);
        assert!(
            !ok && out.contains("BACKING deposit"),
            "the channel's own backing deposit must not be importable:\n{out}"
        );
    }

    // `auto` must not invent a slot when the depositor is bound to none.
    let (ok, out) = cli_allow_fail(&[
        "cosign-l1-deposit-import",
        "auto",
        &deposit_tx,
        &rpc,
        "bad_import.json",
        "--allow-unbound-depositor",
    ]);
    assert!(
        !ok && out.contains("auto"),
        "`auto` must refuse an unbound depositor rather than guess:\n{out}"
    );

    // Every refusal above must have left the channel state UNTOUCHED (fail-closed, not
    // fail-partway): the ITX position is still empty before the honest import below.
    assert_eq!(
        fund_amount(ITX_LOCAL_SLOT as usize),
        0,
        "a refused import must not have moved the channel state"
    );

    // The import now takes <slot> <tx_hash> <rpc>: amount / depositor / token_index are read from
    // the on-chain `Deposited` log, so this asserts the REAL escrowed supply is what gets credited.
    // `--allow-unbound-depositor` is required here and ONLY here: the faucet slot's B-1b bound
    // recipient is the synthetic `test_recipient_for(channel, slot)` address, not the operator's
    // deployer account. The unconditional half of the binding still applies — if ANVIL0_ADDR were
    // some other member's bound recipient, this would refuse regardless of the flag.
    let import_out = cli(
        &[
            "cosign-l1-deposit-import",
            &FAUCET_SLOT.to_string(),
            &deposit_tx,
            &rpc,
            "itx_import.json",
            "--allow-unbound-depositor",
        ],
        &[],
        "cosign-l1-deposit-import",
    );
    // The depositor the CLI used came from the LOG, not from argv (it is no longer passable).
    assert!(
        import_out
            .to_lowercase()
            .contains(&ANVIL0_ADDR.to_lowercase()),
        "the import must report the on-chain depositor it read from the log:\n{import_out}"
    );
    assert_eq!(
        fund_amount(ITX_LOCAL_SLOT as usize),
        FAUCET_SUPPLY as u128,
        "the import must fund the ITX position at the REGISTRY-RESOLVED local slot"
    );

    // A7 — REPLAY: the same real deposit must never be credited twice. The channel layer has no
    // nullifier SET (the shared root is a keccak CHAIN, and re-folding an identical nullifier
    // always yields a DIFFERENT root, so the native gate's `ensure_different_root` passes on a
    // replay by construction). The CLI's consumed-deposit ledger is the only thing that refuses
    // this — see deposit-import-threat-model.md §4.
    let (ok, out) = cli_allow_fail(&[
        "cosign-l1-deposit-import",
        &FAUCET_SLOT.to_string(),
        &deposit_tx,
        &rpc,
        "replay_import.json",
        "--allow-unbound-depositor",
    ]);
    assert!(
        !ok && out.contains("REPLAY REFUSED"),
        "importing the same L1 deposit twice must be refused:\n{out}"
    );
    assert_eq!(
        fund_amount(ITX_LOCAL_SLOT as usize),
        FAUCET_SUPPLY as u128,
        "a refused replay must not have inflated the ITX position"
    );

    // FAIL-CLOSED (2): the freshly IMPORTED position is a HOMOMORPHIC credit — still unspendable.
    // This is the exact reason the faucet needs a refresh leg, pinned as a negative.
    let (ok, out) = cli_allow_fail(&[
        "send",
        &FAUCET_SLOT.to_string(),
        &DELEGATE_SLOT.to_string(),
        &DRIP.to_string(),
        "faucet_payload.json",
        &ITX_LOCAL_SLOT.to_string(),
    ]);
    assert!(
        !ok,
        "a homomorphically credited position must not be spendable:\n{out}"
    );

    // ── drip 1: the realistic path — faucet member → browser DELEGATE ───────────────────────
    let r1 = cli(
        &[
            "refresh",
            &FAUCET_SLOT.to_string(),
            &ITX_LOCAL_SLOT.to_string(),
            "faucet_refresh.json",
        ],
        &[],
        "refresh (drip 1)",
    );
    assert_eq!(
        refresh_value(&r1),
        FAUCET_SUPPLY,
        "the refresh must decrypt the FULL imported supply — value-preserving, no loss"
    );
    cli(
        &[
            "send",
            &FAUCET_SLOT.to_string(),
            &DELEGATE_SLOT.to_string(),
            &DRIP.to_string(),
            "faucet_payload.json",
            &ITX_LOCAL_SLOT.to_string(),
        ],
        &[],
        "send (drip 1)",
    );
    cli(
        &["cosign", "faucet_payload.json", "faucet_cosigned.json"],
        &[],
        "cosign (drip 1)",
    );

    // FAIL-CLOSED (3): the just-SPENT position is unspendable again until the next refresh — the
    // send's `after_ct` randomness is deliberately not recorded, so no stale witness survives.
    let (ok, out) = cli_allow_fail(&[
        "send",
        &FAUCET_SLOT.to_string(),
        &COSIGNER_RECIPIENT_SLOT.to_string(),
        &DRIP.to_string(),
        "faucet_payload.json",
        &ITX_LOCAL_SLOT.to_string(),
    ]);
    assert!(
        !ok,
        "a spent position must not send again without a refresh:\n{out}"
    );

    // ── drip 2: to a CLI-controlled slot, so `cosign` runs the in-protocol recipient
    //    decryption check (verify_send_transition with the expected amount) and the credited
    //    plaintext can be read back below. Also proves the faucet drips REPEATEDLY. ───────────
    let r2 = cli(
        &[
            "refresh",
            &FAUCET_SLOT.to_string(),
            &ITX_LOCAL_SLOT.to_string(),
            "faucet_refresh.json",
        ],
        &[],
        "refresh (drip 2)",
    );
    assert_eq!(
        refresh_value(&r2),
        FAUCET_SUPPLY - DRIP,
        "after one drip the faucet must hold exactly supply - DRIP (decrypted from the state)"
    );
    cli(
        &[
            "send",
            &FAUCET_SLOT.to_string(),
            &COSIGNER_RECIPIENT_SLOT.to_string(),
            &DRIP.to_string(),
            "faucet_payload.json",
            &ITX_LOCAL_SLOT.to_string(),
        ],
        &[],
        "send (drip 2)",
    );
    cli(
        &["cosign", "faucet_payload.json", "faucet_cosigned.json"],
        &[],
        "cosign (drip 2)",
    );

    // ── verify by DECRYPTION of the co-signed state ─────────────────────────────────────────
    // The recipient's credited position decrypts to EXACTLY one drip …
    let credited = cli(
        &[
            "refresh",
            &COSIGNER_RECIPIENT_SLOT.to_string(),
            &ITX_LOCAL_SLOT.to_string(),
            "probe_refresh.json",
        ],
        &[],
        "refresh (recipient probe)",
    );
    assert_eq!(
        refresh_value(&credited),
        DRIP,
        "the drip recipient must hold exactly the drip"
    );
    // … and the faucet's decreased by exactly the two drips.
    let remaining = cli(
        &[
            "refresh",
            &FAUCET_SLOT.to_string(),
            &ITX_LOCAL_SLOT.to_string(),
            "probe_refresh.json",
        ],
        &[],
        "refresh (faucet probe)",
    );
    assert_eq!(
        refresh_value(&remaining),
        FAUCET_SUPPLY - 2 * DRIP,
        "the faucet must have paid out exactly 2 drips and nothing else"
    );

    // NO MINTING: the per-token fund is untouched by in-channel drips, so every dripped balance is
    // still backed by the ONE real L1 deposit — and the ETH lane never moved.
    assert_eq!(
        fund_amount(ITX_LOCAL_SLOT as usize),
        FAUCET_SUPPLY as u128,
        "in-channel drips must NEVER change the per-token fund (no minting)"
    );
    assert_eq!(
        cast_uint(&rpc, &itx, "balanceOf(address)(uint256)", &[&rollup]),
        FAUCET_SUPPLY as u128,
        "the L1 escrow must be untouched by in-channel drips"
    );

    // ── BRING YOUR OWN $ITX: the BROWSER-SHAPED ERC-20 deposit ──────────────────────────────
    //
    // Everything above escrows the faucet's supply with the OPERATOR's key, which is bound to no
    // slot and therefore needs `--allow-unbound-depositor`. This block is the other path — the one
    // `wallet-live.html` drives from MetaMask:
    //
    //   approve(rollup, amount)  →  deposit(recipient, ITX_INDEX, amount, 0) with msg.value 0
    //   →  cosign-l1-deposit-import <slot> <txHash> <rpc> l1_import_cosigned.json
    //
    // and it is signed by the MEMBER'S OWN address, i.e. the slot's bound (B-1b) exit address. So
    // the argv below is EXACTLY what `/api/import-deposit` builds (wallet-relay.js /
    // wallet-relay-ec2.js): five positionals and NO flag. That is the point of the test — the
    // browser path must work with the credit binding fully armed. The browser sends only
    // { recipientSlot, txHash }; amount / depositor / token_index come from the `Deposited` log.
    //
    // The depositing slot is a CLI-controlled cosigner purely so the credited plaintext can be read
    // back with `refresh` (the browser delegate's key lives in the browser). Its bound recipient is
    // impersonated on anvil, which is what makes the depositor the slot's own address.
    const BYO_DEPOSIT: u64 = 250_000_000; // 250 ITX, in a token with 6 decimals

    let member_addr = {
        let text = std::fs::read_to_string(repo_root().join("channel_snapshot.json"))
            .expect("read channel_snapshot.json");
        let v: serde_json::Value = serde_json::from_str(&text).expect("parse snapshot");
        v["state"]["balanceState"]["recipients"][COSIGNER_RECIPIENT_SLOT as usize]
            .as_str()
            .expect("recipients[COSIGNER_RECIPIENT_SLOT]")
            .to_string()
    };
    let fund_before = fund_amount(ITX_LOCAL_SLOT as usize);
    let eth_fund_before = fund_amount(0);
    let escrow_before = cast_uint(
        &rpc,
        &rollup,
        "escrowedByToken(uint32)(uint256)",
        &[&ITX_INDEX.to_string()],
    );
    // The member's in-channel ITX balance right now, DECRYPTED from the co-signed state (this is
    // the `refresh (recipient probe)` above: exactly one drip).
    let balance_before = DRIP;

    // Give the member gas and the ITX it is about to bring in.
    cast(
        &rpc,
        &["rpc", "anvil_setBalance", &member_addr, "0xde0b6b3a7640000"],
    );
    cast(
        &rpc,
        &[
            "send",
            &itx,
            "transfer(address,uint256)",
            &member_addr,
            &BYO_DEPOSIT.to_string(),
            "--private-key",
            ANVIL0_KEY,
        ],
    );
    cast(&rpc, &["rpc", "anvil_impersonateAccount", &member_addr]);
    // Step 1 (browser: `approve` with spender = the ROLLUP, read from /api/deposit-info).
    cast(
        &rpc,
        &[
            "send",
            &itx,
            "approve(address,uint256)",
            &rollup,
            &BYO_DEPOSIT.to_string(),
            "--from",
            &member_addr,
            "--unlocked",
        ],
    );
    assert_eq!(
        cast_uint(
            &rpc,
            &itx,
            "allowance(address,address)(uint256)",
            &[&member_addr, &rollup]
        ),
        BYO_DEPOSIT as u128,
        "the approve must have set exactly the deposit allowance for the rollup"
    );
    // Step 2 (browser: `deposit` with tokenIndex != 0 and value 0 — the rollup credits a MEASURED
    // balanceOf delta and reverts on stray ETH).
    let byo_send = cast(
        &rpc,
        &[
            "send",
            &rollup,
            "deposit(bytes32,uint32,uint256,bytes32)",
            &deposit_recipient,
            &ITX_INDEX.to_string(),
            &BYO_DEPOSIT.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--value",
            "0",
            "--from",
            &member_addr,
            "--unlocked",
            "--json",
        ],
    );
    let byo_tx = byo_send
        .split("\"transactionHash\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or_else(|| panic!("no transactionHash in BYO deposit output:\n{byo_send}"))
        .to_string();
    cast(
        &rpc,
        &["rpc", "anvil_stopImpersonatingAccount", &member_addr],
    );
    assert_eq!(
        cast_uint(
            &rpc,
            &rollup,
            "escrowedByToken(uint32)(uint256)",
            &[&ITX_INDEX.to_string()]
        ),
        escrow_before + BYO_DEPOSIT as u128,
        "the per-token escrow must have grown by exactly the member's deposit"
    );
    // The allowance was consumed by the transfer — nothing stays approved after the deposit.
    assert_eq!(
        cast_uint(
            &rpc,
            &itx,
            "allowance(address,address)(uint256)",
            &[&member_addr, &rollup]
        ),
        0,
        "the deposit must have consumed the whole allowance"
    );

    // A deposit made BY a bound address may not be credited anywhere else — no flag can override
    // this, and the browser never passes one. (The faucet slot is a different active slot.)
    let (ok, out) = cli_allow_fail(&[
        "cosign-l1-deposit-import",
        &FAUCET_SLOT.to_string(),
        &byo_tx,
        &rpc,
        "byo_import.json",
        "--allow-unbound-depositor",
    ]);
    assert!(
        !ok && out.contains("CREDIT MISDIRECTION REFUSED"),
        "a member's own ERC-20 deposit must not be creditable to another slot:\n{out}"
    );

    // Step 3 — the import, with the EXACT argv `/api/import-deposit` builds. No flag: the binding
    // must resolve on its own because the depositor IS the slot's bound recipient.
    let byo_import = cli(
        &[
            "cosign-l1-deposit-import",
            &COSIGNER_RECIPIENT_SLOT.to_string(),
            &byo_tx,
            &rpc,
            "l1_import_cosigned.json",
        ],
        &[],
        "cosign-l1-deposit-import (browser-shaped ERC-20)",
    );
    assert!(
        byo_import.to_lowercase().contains(&member_addr.to_lowercase()),
        "the import must report the on-chain depositor it read from the log:\n{byo_import}"
    );
    assert!(
        byo_import.contains(&format!("token_index {ITX_INDEX}")),
        "the token index must have been read from the Deposited log:\n{byo_import}"
    );

    // The channel's per-token FUND rose by exactly the deposit …
    assert_eq!(
        fund_amount(ITX_LOCAL_SLOT as usize),
        fund_before + BYO_DEPOSIT as u128,
        "the channel's ITX fund must rise by exactly the member's deposit"
    );
    // … and so did the DEPOSITOR's own in-channel balance, read by DECRYPTION of the co-signed
    // state rather than from any bookkeeping. This is the end-to-end claim: my ERC-20 went in, and
    // it landed on MY slot, at the right magnitude (6-decimal base units, not 18).
    let byo_balance = cli(
        &[
            "refresh",
            &COSIGNER_RECIPIENT_SLOT.to_string(),
            &ITX_LOCAL_SLOT.to_string(),
            "byo_refresh.json",
        ],
        &[],
        "refresh (BYO depositor probe)",
    );
    assert_eq!(
        refresh_value(&byo_balance),
        balance_before + BYO_DEPOSIT,
        "the depositor's in-channel ITX balance must rise by exactly the deposited amount"
    );
    // The ETH lane is untouched by an ERC-20 deposit.
    assert_eq!(
        fund_amount(0),
        eth_fund_before,
        "an ERC-20 deposit must not move the native position"
    );
    // And the same deposit cannot be imported twice.
    let (ok, out) = cli_allow_fail(&[
        "cosign-l1-deposit-import",
        &COSIGNER_RECIPIENT_SLOT.to_string(),
        &byo_tx,
        &rpc,
        "byo_import.json",
    ]);
    assert!(
        !ok && out.contains("REPLAY REFUSED"),
        "a member's ERC-20 deposit must not be importable twice:\n{out}"
    );

    eprintln!(
        "[itx-faucet-e2e] browser-shaped ERC-20 deposit OK: slot {COSIGNER_RECIPIENT_SLOT} \
         approved + deposited {BYO_DEPOSIT} base units of $ITX (msg.value 0) from its OWN bound \
         address {member_addr}; imported with the relay's exact argv (no \
         --allow-unbound-depositor); balance {balance_before} -> {}, fund {fund_before} -> {}.",
        balance_before + BYO_DEPOSIT,
        fund_before + BYO_DEPOSIT as u128
    );

    eprintln!(
        "[itx-faucet-e2e] OK: $ITX {itx} registered at base index {ITX_INDEX} → local slot \
         {ITX_LOCAL_SLOT}; {FAUCET_SUPPLY} escrowed on L1 and imported to faucet slot \
         {FAUCET_SLOT}; two {DRIP} drips co-signed (delegate {DELEGATE_SLOT} + cosigner \
         {COSIGNER_RECIPIENT_SLOT}); faucet left with {} and the per-token fund unchanged \
         (channel {CHANNEL}, rollup {rollup}).",
        FAUCET_SUPPLY - 2 * DRIP
    );
}
