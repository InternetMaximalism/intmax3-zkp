//! EXIT-PATH REGRESSION TESTS — the two liveness defects in `doc/audit/exit-path-facade-sweep.md`
//! that cost an honest user their withdrawal.
//!
//! Scope frame: *"someone deposits money and can withdraw it again without losing it."* Nothing
//! here is about soundness. Every test below asserts that an honest user, driven the way the
//! PRODUCT drives the CLI, either gets through or is told precisely why not.
//!
//! **F4 — `contracts/` was resolved from the CWD.** `close`, `claim`, `cancel-close`,
//! `post-close-claim` and `withdraw` reached the Foundry checkout as `Path::new("contracts/…")` and
//! `Command::current_dir("contracts")`. All three product drivers (`api/lib/cli.js`,
//! `hosting/wallet/wallet-relay.js`, `hosting/wallet/wallet-relay-ec2.js`) spawn the binary with
//! `cwd = wallet-live-work/chN`, which has no `contracts/`. So every exit command aborted, and in
//! `close`/`withdraw` it aborted AFTER the multi-minute proof. **No test covered this**, because
//! every Rust E2E invokes the CLI with `cwd = repo_root()` — the one directory where the relative
//! path happens to resolve. `exit_commands_resolve_contracts_from_a_foreign_cwd` is that missing
//! test: it runs each of the five from a temp dir that is not under the repo at all.
//!
//! **F8 — `claim` derived the claimant's key from the OPERATOR's co-signer seed.** For a CLI
//! co-signer slot that is the right key; for a browser delegate — who generated its own Regev key
//! in the browser and whose secret never left it — it is a different key entirely, and the CLI
//! spent the whole heavy proof before the in-circuit slot-leaf bind rejected it, with an error that
//! named neither the cause nor the fact that the delegate has no working path at all.
//! `claim_refuses_a_slot_whose_key_this_host_does_not_hold` pins the refusal and its wording.
//!
//! WHY THESE TESTS ARE CHEAP: every assertion is about what happens BEFORE proving. That is not a
//! shortcut — "the check runs before the proof" is exactly the property F4 and F8 are about, so a
//! test that had to prove first could not express it.
#![cfg(not(debug_assertions))]

use std::{collections::HashSet, path::PathBuf, process::Command};

use intmax3_zkp::{
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    regev::{RegevCiphertext, encrypt_amount},
    wallet_core::{
        ChannelSnapshot, MemberInfo, MemberKeys, add_signature, assemble_genesis_state,
        build_record, default_settled_tx_accumulator, sign_state,
    },
};
use rand010::{SeedableRng, rngs::StdRng};
use serde::Serialize;

/// The compiled binary (cargo sets `CARGO_BIN_EXE_<name>` for integration tests).
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_channel_member"))
}

/// A temp dir OUTSIDE the repo — the shape of `wallet-live-work/chN`: a per-channel work dir with
/// no `contracts/` anywhere in it.
fn foreign_cwd(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "intmax3-exit-path-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).expect("create foreign cwd");
    assert!(
        !d.join("contracts").exists(),
        "the point of this dir is that it has NO contracts/"
    );
    d
}

/// Run a `channel_member` subcommand in `cwd`. Returns (success, stdout+stderr).
fn run(cwd: &std::path::Path, args: &[&str], envs: &[(&str, &str)]) -> (bool, String) {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .current_dir(cwd)
        .env("INTMAX_CHANNEL", "7")
        // SECURITY: explicit opt-in to the publicly-derivable deterministic co-signer keys. The
        // CLI fails closed unless exactly one provenance is configured; see
        // doc/tasks/cosigner-key-provenance.md.
        .env("INTMAX_INSECURE_DETERMINISTIC_KEYS", "1")
        // Do not inherit a CONTRACTS_DIR from the developer's shell: these tests are about what
        // the binary resolves ON ITS OWN.
        .env_remove("CONTRACTS_DIR")
        .env_remove("DELEGATE_SEED")
        .env_remove("CLAIM_KEYGEN_LABEL");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn channel_member");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

/// Pull the path out of the `[cmd] contracts dir: <path> (via …)` diagnostic.
fn reported_contracts_dir(out: &str) -> PathBuf {
    let line = out
        .lines()
        .find(|l| l.contains("contracts dir: "))
        .unwrap_or_else(|| panic!("no `contracts dir:` diagnostic in output:\n{out}"));
    let rest = line.split("contracts dir: ").nth(1).unwrap();
    let path = rest
        .rsplit_once(" (via ")
        .map(|(p, _)| p)
        .unwrap_or(rest)
        .trim();
    PathBuf::from(path)
}

/// The five commands F4 broke, with the minimum arguments/env each needs to REACH the contracts
/// resolution. Every one of them dies immediately after it (no state file in a foreign cwd, no
/// ROLLUP for `withdraw`), so none of these runs proves anything.
///
/// `CLAIM_RECIPIENT` is required by the two claim commands before the resolution; it is a
/// throwaway address here because these runs never get as far as using it.
const RECIPIENT: &str = "0x7e5700007e5700007e5700007e5700007e570000";

fn exit_commands() -> Vec<(
    &'static str,
    Vec<&'static str>,
    Vec<(&'static str, &'static str)>,
)> {
    let mgr = "0x00000000000000000000000000000000000000aa";
    vec![
        ("close", vec!["close", mgr], vec![]),
        (
            "claim",
            vec!["claim", mgr, "0"],
            vec![("CLAIM_RECIPIENT", RECIPIENT)],
        ),
        ("cancel-close", vec!["cancel-close", mgr], vec![]),
        (
            "post-close-claim",
            vec!["post-close-claim", mgr, "0", "0"],
            vec![("CLAIM_RECIPIENT", RECIPIENT)],
        ),
        ("withdraw", vec!["withdraw", mgr], vec![]),
    ]
}

/// **F4, THE MISSING TEST.** Run every exit command from a working directory that is not the repo
/// root — the exact condition all three product drivers create — and require that each one resolves
/// a real `contracts/` checkout anyway.
///
/// This fails if anyone reintroduces a CWD-relative `contracts/` lookup in any of the five: the
/// resolution diagnostic disappears, or the run dies with a staging/`No such file` error.
#[test]
fn exit_commands_resolve_contracts_from_a_foreign_cwd() {
    for (name, args, envs) in exit_commands() {
        let d = foreign_cwd(name);
        let (ok, out) = run(&d, &args, &envs);
        assert!(
            !ok,
            "`{name}` cannot SUCCEED here (no state, no chain) — the test is about HOW it \
             fails:\n{out}"
        );

        // 1. It resolved a checkout, and said which.
        let dir = reported_contracts_dir(&out);
        assert!(
            dir.is_absolute(),
            "`{name}` must resolve an ABSOLUTE contracts dir (a relative one is the F4 bug by \
             another name), got {dir:?}:\n{out}"
        );
        assert!(
            dir.join("test").join("data").is_dir(),
            "`{name}` resolved {dir:?}, which has no test/data staging dir:\n{out}"
        );
        assert!(
            dir.join("script").join("RunClose.s.sol").is_file(),
            "`{name}` resolved {dir:?}, which has no script/RunClose.s.sol:\n{out}"
        );

        // 2. It did NOT die on a contracts path. The specific F4 death was `stage
        //    close_intent.json: No such file or directory` from the `fs::copy` into a non-existent
        //    `<cwd>/contracts/test/data`.
        assert!(
            !out.contains("stage ") && !out.contains("is not a usable contracts checkout"),
            "`{name}` failed on the CONTRACTS PATH from a foreign cwd — F4 is back:\n{out}"
        );

        // 3. It failed on the next real precondition instead (which is what a healthy run in an
        //    empty dir should do).
        assert!(
            out.contains("cli_state.json") || out.contains("set ROLLUP="),
            "`{name}` should have got past the contracts check and died on its next real \
             precondition:\n{out}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// **F4, the "early and loudly" half.** A wrong `CONTRACTS_DIR` must be refused BEFORE the command
/// touches any state — i.e. before it could possibly have started proving. If this ever regresses
/// to a late failure, the run below would get as far as complaining about `cli_state.json`.
#[test]
fn a_wrong_contracts_dir_is_refused_before_any_state_is_loaded() {
    for (name, args, envs) in exit_commands() {
        let d = foreign_cwd(&format!("bogus-{name}"));
        let empty = d.join("not-a-contracts-checkout");
        std::fs::create_dir_all(&empty).unwrap();
        let mut envs = envs.clone();
        let empty_s = empty.to_string_lossy().to_string();
        envs.push(("CONTRACTS_DIR", empty_s.as_str()));
        let (ok, out) = run(&d, &args, &envs);
        assert!(!ok, "`{name}` must refuse a bogus CONTRACTS_DIR:\n{out}");
        assert!(
            out.contains("is not a usable contracts checkout"),
            "`{name}` must say the checkout is unusable:\n{out}"
        );
        assert!(
            out.contains("BEFORE PROVING"),
            "`{name}`'s refusal must state that it is refusing before the proof — that ordering \
             IS the fix:\n{out}"
        );
        assert!(
            !out.contains("cli_state.json") && !out.contains("set ROLLUP="),
            "`{name}` reached a LATER precondition than the contracts check; the check must be \
             the first thing that runs:\n{out}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// **F4, as a source-level lint — and the test that actually catches a reintroduction.**
///
/// VERIFIED BY MUTATION, not assumed: reverting `cmd_close`'s staging dir to
/// `Path::new("contracts/test/data")` leaves `exit_commands_resolve_contracts_from_a_foreign_cwd`
/// GREEN. It has to — from an empty work dir `close` dies at `load_state()` long before it reaches
/// the `fs::copy`, and getting there would require a full signed channel, a live chain and a real
/// close proof. So the point-of-use sites are unreachable by any cheap test, and this lint is the
/// only thing standing between them and a silent regression. Do not delete it as "just a grep":
/// with it removed, F4 can come back at any of the twelve sites with every suite still green.
///
/// It also covers what the functional tests structurally cannot: a relative path added at a NEW
/// site (a sixth exit command, a second `fs::copy` inside an existing one).
///
/// The allowed forms are `require_contracts_dir(...)` / `resolve_contracts_dir()` and the
/// `contracts_dir.join(...)` / `current_dir(&contracts_dir)` they feed.
#[test]
fn the_cli_never_reaches_contracts_through_the_working_directory() {
    let src = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bin/channel_member.rs"),
    )
    .expect("read channel_member.rs");
    for (line_no, line) in src.lines().enumerate() {
        let code = line.trim_start();
        // Skip doc/comment lines: the fix's own SECURITY notes quote the old broken forms.
        if code.starts_with("//") || code.starts_with("*") {
            continue;
        }
        assert!(
            !code.contains(r#"current_dir("contracts")"#),
            "channel_member.rs:{} runs forge with a CWD-RELATIVE `contracts` dir — F4. Use \
             `require_contracts_dir(cmd, &[script])` and `current_dir(&contracts_dir)`:\n  {line}",
            line_no + 1
        );
        assert!(
            !code.contains(r#"Path::new("contracts"#),
            "channel_member.rs:{} resolves a CWD-RELATIVE `contracts/...` path — F4. Use \
             `require_contracts_dir(cmd, &[script]).join(\"test/data\")`:\n  {line}",
            line_no + 1
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
//  F8 — the claimant's key must be the SLOT OWNER's, and the CLI must say so when it is not
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// The binary's CLI co-signer keygen labels (`CLI_COSIGNER_SEED_BASE + slot`). Under
/// `INTMAX_INSECURE_DETERMINISTIC_KEYS=1` a label seeds `StdRng` directly, which is what lets this
/// test reproduce the binary's co-signer identities exactly.
fn cli_keygen_label(slot: u16) -> u64 {
    0xC1_0000 + slot as u64
}
fn cli_keys(slot: u16) -> MemberKeys {
    MemberKeys::generate(&mut StdRng::seed_from_u64(cli_keygen_label(slot)))
}

/// A BROWSER delegate's keys: generated from a seed the CLI has no way to reach. This stands in for
/// `wasm_wallet::wallet_keygen`, whose Regev secret never leaves the browser at all — the test only
/// needs the resulting slot leaf to commit a key this host cannot derive, which is precisely the
/// real delegate's situation.
const BROWSER_ONLY_SEED: u64 = 0xB0B0_1234_5678;
fn browser_delegate_keys() -> MemberKeys {
    MemberKeys::generate(&mut StdRng::seed_from_u64(BROWSER_ONLY_SEED))
}

fn recipient_for(i: usize) -> Address {
    Address::from_u32_slice(&[0x7E57_0000u32.wrapping_add(i as u32); 5]).unwrap()
}

// Mirrors of the binary's private `cli_state.json` shape (the real types live in the BINARY crate
// and are not importable from an integration test). Only the fields `claim` reads are populated;
// the key set must match exactly, because the binary deserializes with `deny_unknown_fields` and
// refuses a file missing any replay-ledger key.
#[derive(Serialize)]
struct ControlledMemberMirror {
    slot: u16,
    keygen_seed: u64,
    balance_amount: u64,
    balance_seed: u64,
    has_witness: bool,
    token_witnesses: Vec<serde_json::Value>,
}
#[derive(Serialize)]
struct CliStateMirror {
    state_schema_version: u32,
    controlled: Vec<ControlledMemberMirror>,
    snapshot: ChannelSnapshot,
    applied_tx_identities: HashSet<Bytes32>,
    spent_tx_identities: HashSet<Bytes32>,
    imported_deposits: HashSet<String>,
}

/// Write a `cli_state.json` for a channel of 3 CLI co-signers (slots 0-2, whose keys this host CAN
/// derive) plus ONE browser delegate at slot 3 (whose key it CANNOT) — the live wallet's layout.
fn write_delegate_channel_state(cwd: &std::path::Path) {
    let channel_id = 7u32;
    let cosigners: Vec<MemberKeys> = (0..3u16).map(cli_keys).collect();
    let delegate = browser_delegate_keys();
    let all: Vec<&MemberKeys> = cosigners.iter().chain(std::iter::once(&delegate)).collect();

    let members: Vec<MemberInfo> = all
        .iter()
        .enumerate()
        .map(|(i, k)| MemberInfo {
            slot: i as u16,
            pk_g: k.pk_g(),
            pk_b: k.pk_b(),
            regev_pk: k.regev_pk.clone(),
        })
        .collect();
    // 4 active slots, 1 of them a delegate => member_count 3, delegate_count 1.
    let record = build_record(channel_id, &members, 0, 1).expect("record");

    let balances = [40u64, 30, 20, 10];
    let mut cts: Vec<RegevCiphertext> = Vec::new();
    for (i, k) in all.iter().enumerate() {
        let (ct, _w) = encrypt_amount(
            &mut StdRng::seed_from_u64(0xBA_0000 + i as u64),
            &k.regev_pk,
            balances[i],
        )
        .expect("encrypt genesis balance");
        cts.push(ct);
    }
    let regev_pk_digests: Vec<Bytes32> = all
        .iter()
        .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
        .collect();
    let recipients: Vec<Address> = (0..all.len()).map(recipient_for).collect();
    let fund: u64 = balances.iter().sum();

    let mut genesis = assemble_genesis_state(&record, &cts, &regev_pk_digests, &recipients, fund)
        .expect("genesis");
    // Only the CO-SIGNERS sign; the delegate does not (that is what makes it a delegate).
    for (i, k) in cosigners.iter().enumerate() {
        let s = sign_state(k, i as u8, &genesis).expect("sign genesis");
        add_signature(&mut genesis, s);
    }

    let controlled = (0..3u16)
        .map(|slot| ControlledMemberMirror {
            slot,
            keygen_seed: cli_keygen_label(slot),
            balance_amount: balances[slot as usize],
            balance_seed: 0xBA_0000 + slot as u64,
            has_witness: true,
            token_witnesses: Vec::new(),
        })
        .collect();

    let state = CliStateMirror {
        state_schema_version: 1,
        controlled,
        snapshot: ChannelSnapshot {
            record,
            state: genesis,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        },
        applied_tx_identities: HashSet::new(),
        spent_tx_identities: HashSet::new(),
        imported_deposits: HashSet::new(),
    };
    std::fs::write(
        cwd.join("cli_state.json"),
        serde_json::to_string(&state).unwrap(),
    )
    .unwrap();
}

/// **F8.** `claim <mgr> 3` names the BROWSER DELEGATE's slot. The CLI cannot hold that slot's Regev
/// secret, so it must refuse — before proving — and the refusal must name who can and cannot use
/// the command. The pre-fix code derived `keys_for(CLI_COSIGNER_SEED_BASE + 3)` regardless and
/// walked into a multi-minute proof that could never verify.
///
/// This test fails if the identity gate is removed, if it is moved after the proving, or if the
/// message stops explaining the browser-delegate case.
#[test]
fn claim_refuses_a_slot_whose_key_this_host_does_not_hold() {
    let d = foreign_cwd("f8-delegate");
    write_delegate_channel_state(&d);
    let mgr = "0x00000000000000000000000000000000000000aa";
    let delegate_recipient = recipient_for(3).to_hex();
    let (ok, out) = run(
        &d,
        &["claim", mgr, "3"],
        &[("CLAIM_RECIPIENT", delegate_recipient.as_str())],
    );
    assert!(
        !ok,
        "claiming for a slot this host holds no key for MUST fail:\n{out}"
    );
    assert!(
        out.contains("CANNOT CLAIM FOR BALANCE SLOT 3"),
        "the refusal must name the slot it cannot claim for:\n{out}"
    );
    assert!(
        out.contains("BROWSER DELEGATE"),
        "the refusal must name WHO CANNOT use this path — the browser delegate whose funds these \
         are — instead of leaving them to guess:\n{out}"
    );
    assert!(
        out.contains("wallet_keygen") && out.contains("wasm_wallet.rs"),
        "the refusal must point at the structural cause (the browser holds the key; there is no \
         wasm claim entry point):\n{out}"
    );
    // Refused BEFORE any proving: the claim prover announces itself with "(HEAVY)".
    assert!(
        !out.contains("HEAVY"),
        "the refusal must land BEFORE the heavy proof, not after it:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The POSITIVE control for the gate above: a slot this host DOES own must pass the identity check.
/// Without this, `claim_refuses_a_slot_whose_key_this_host_does_not_hold` would also pass if the
/// gate simply rejected everything.
///
/// The run is stopped immediately after the identity check by the recipient pre-check (also added
/// with the F8 fix: `CLAIM_RECIPIENT` must be the slot's cosigner-signed exit address, which the
/// claim circuit binds). Reaching THAT error proves the identity check accepted slot 0.
#[test]
fn claim_accepts_a_slot_this_host_does_own_and_then_checks_the_recipient() {
    let d = foreign_cwd("f8-cosigner");
    write_delegate_channel_state(&d);
    let mgr = "0x00000000000000000000000000000000000000aa";
    let wrong_recipient = "0x00000000000000000000000000000000000000bb";
    let (ok, out) = run(
        &d,
        &["claim", mgr, "0"],
        &[("CLAIM_RECIPIENT", wrong_recipient)],
    );
    assert!(!ok, "a mismatched CLAIM_RECIPIENT must be refused:\n{out}");
    assert!(
        out.contains("slot 0 identity confirmed against the signed slot leaf"),
        "slot 0 IS a CLI co-signer slot — the identity gate must accept it:\n{out}"
    );
    assert!(
        !out.contains("CANNOT CLAIM FOR BALANCE SLOT"),
        "the gate must not refuse a slot this host genuinely owns:\n{out}"
    );
    assert!(
        out.contains("is not slot 0's signed exit address"),
        "a CLAIM_RECIPIENT that is not the slot's signed exit address must be refused before \
         proving (the circuit binds that leaf field, so such a claim could never verify):\n{out}"
    );
    assert!(
        !out.contains("HEAVY"),
        "the recipient refusal must land BEFORE the heavy proof:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&d);
}
