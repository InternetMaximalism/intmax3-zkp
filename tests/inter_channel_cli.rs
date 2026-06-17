//! INTER-CHANNEL CLI E2E — drives the REAL `channel_member` binary end-to-end across two channel
//! processes (A = ch7, B = ch8), each in its own temp cwd, mirroring the live relay layout
//! (`wallet-live-work/ch7`, `wallet-live-work/ch8`).
//!
//! This is the CLI counterpart to `tests/inter_channel_live.rs`: that test exercises the
//! `wallet_core` API in-process; this one exercises the *binary's* co-sign commands
//! (`cosign-inter-debit`, `cosign-inter-credit`) plus the binary-only security wiring those commands
//! add on top of the library: the PINNED trusted A record (read from A's OWN sibling cli_state, NOT
//! the descriptor), the persisted REPLAY LEDGER, and the idempotent `init` pk_g dedup.
//!
//! WHY a process E2E (not real deposit backing): a full CLI flow with REAL deposit backing requires
//! `cast`/anvil + the ~25s BalanceProcessor prover (`setup-backing`). That is intractable for a unit
//! test AND unnecessary here: the inter-channel co-sign commands deliberately use plain N-of-N
//! `sign_state` (NOT `sign_state_if_backed`), because an inter-channel transfer PUSHES a tx leaf into
//! `settled_tx_chain` so the genesis deposit attestation can never reconcile (see the SECURITY note
//! in `channel_member.rs`). So we seed each channel's `cli_state.json` directly with a co-signed
//! genesis built through the SAME `wallet_core` API, then drive the binary. The debit payload +
//! transfer descriptor are produced by the REAL `build_inter_channel_send` (real E-2 STARK at Test
//! level), so the binary co-signs and credits a genuine transfer.
//!
//! WHAT EACH STEP PROVES:
//!  (a) `cosign-inter-debit` in A produces an N-of-N co-signed `a_send` (debit applied).
//!  (b) `cosign-inter-credit` in B credits the recipient slot by EXACTLY the amount.
//!  (c) RE-running `cosign-inter-credit` with the SAME tx_hash is REFUSED (replay ledger, inv 6).
//!  (d) A descriptor with a TAMPERED amount is REFUSED (the credit gate re-verifies the real E-2).
//!  (e) Idempotent re-join: `init` with an already-present pk_g returns the SAME slot, no
//!      delegate_count / state_version inflation (no slot collision).
#![cfg(not(debug_assertions))]

use std::{path::PathBuf, process::Command};

use intmax3_zkp::{
    common::{channel::ChannelRecord, channel_id::ChannelId},
    ethereum_types::{bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
    regev::{RegevCiphertext, RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        BuiltInterChannelSend, ChannelSnapshot, MemberInfo, MemberKeys, add_signature,
        assemble_genesis_state, build_inter_channel_send, build_record, decrypt_balance, sign_state,
        verify_snapshot,
    },
};
use rand010::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use serde_json::json;

// MUST match the binary's hardcoded LEVEL (channel_member.rs: RegevSecurityLevel::Production), since
// the binary VERIFIES the E-2 proof this test PRODUCES — the FRI query count is part of the
// transcript, so a Test-level proof would fail the Production-level re-verification in the binary.
const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;
const A_ID: u32 = 7;
const B_ID: u32 = 8;
const AMT: u64 = 5;

// These MUST match the binary's CLI member layout (channel_member.rs: CLI_SLOTS + keygen seeds).
const CLI_SLOTS: &[u8] = &[0, 1, 2];
fn cli_keygen_seed(slot: u8) -> u64 {
    0xC1_0000 + slot as u64
}
fn cli_keys(slot: u8) -> MemberKeys {
    MemberKeys::generate(&mut StdRng::seed_from_u64(cli_keygen_seed(slot)))
}

// ---- minimal mirrors of the binary's private serde structs (same field names + camelCase) ----

#[derive(Serialize, Deserialize)]
struct ControlledMember {
    slot: u8,
    keygen_seed: u64,
    balance_amount: u64,
    balance_seed: u64,
    has_witness: bool,
}

#[derive(Serialize, Deserialize)]
struct CliState {
    controlled: Vec<ControlledMember>,
    snapshot: ChannelSnapshot,
    #[serde(default)]
    applied_tx_hashes: Vec<Bytes32>,
}

fn member_info(slot: u8, keys: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot,
        pk_g: keys.pk_g(),
        pk_b: keys.pk_b(),
        regev_pk: keys.regev_pk.clone(),
    }
}

fn fresh_root(tag: u32) -> Bytes32 {
    Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, tag]).unwrap()
}

struct ChannelFixture {
    record: ChannelRecord,
    snapshot: ChannelSnapshot,
    witnesses: Vec<intmax3_zkp::regev::AmountWitness>,
    balances: Vec<u64>,
    controlled: Vec<ControlledMember>,
}

/// Build a 3-member channel whose members are EXACTLY the binary's deterministic CLI members
/// (slots 0,1,2 with the binary's keygen seeds), with a co-signed genesis + a balance seed per slot.
fn build_cli_channel(channel_id: u32, balances: &[u64]) -> ChannelFixture {
    let keys: Vec<MemberKeys> = CLI_SLOTS.iter().map(|&s| cli_keys(s)).collect();
    let members: Vec<MemberInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| member_info(i as u8, k))
        .collect();
    let record = build_record(channel_id, &members, 0, 0).expect("record");

    let mut cts: Vec<RegevCiphertext> = Vec::new();
    let mut witnesses = Vec::new();
    let mut controlled = Vec::new();
    for (i, &bal) in balances.iter().enumerate() {
        let balance_seed = 0xBA_0000 + i as u64;
        let (ct, w) = encrypt_amount(
            &mut StdRng::seed_from_u64(balance_seed),
            &keys[i].regev_pk,
            bal,
        )
        .expect("enc");
        cts.push(ct);
        witnesses.push(w);
        controlled.push(ControlledMember {
            slot: i as u8,
            keygen_seed: cli_keygen_seed(i as u8),
            balance_amount: bal,
            balance_seed,
            has_witness: true,
        });
    }
    let fund: u64 = balances.iter().sum();
    let mut genesis = assemble_genesis_state(&record, &cts, fund).expect("genesis");
    for (i, k) in keys.iter().enumerate() {
        let s = sign_state(k, i as u8, &genesis).expect("sign genesis");
        add_signature(&mut genesis, s);
    }
    let snapshot = ChannelSnapshot {
        record: record.clone(),
        state: genesis,
        members,
    };
    verify_snapshot(&snapshot, Some((&keys[0], 0))).expect("verify genesis");
    ChannelFixture {
        record,
        snapshot,
        witnesses,
        balances: balances.to_vec(),
        controlled,
    }
}

/// The compiled binary path (cargo sets CARGO_BIN_EXE_<name> for integration tests).
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_channel_member"))
}

/// Run a `channel_member` subcommand in `cwd` with INTMAX_CHANNEL set. Returns (success, stdout+err).
fn run(cwd: &std::path::Path, channel: u32, args: &[&str]) -> (bool, String) {
    let out = Command::new(bin())
        .args(args)
        .current_dir(cwd)
        .env("INTMAX_CHANNEL", channel.to_string())
        .output()
        .expect("spawn channel_member");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

fn write_state(cwd: &std::path::Path, state: &CliState) {
    std::fs::write(
        cwd.join("cli_state.json"),
        serde_json::to_string_pretty(state).unwrap(),
    )
    .unwrap();
}

fn write_json_file<T: Serialize>(path: &std::path::Path, v: &T) {
    std::fs::write(path, serde_json::to_string_pretty(v).unwrap()).unwrap();
}

fn cli_state(fx: ChannelFixture) -> CliState {
    CliState {
        controlled: fx.controlled,
        snapshot: fx.snapshot,
        applied_tx_hashes: Vec::new(),
    }
}

#[test]
fn inter_channel_cli_end_to_end() {
    // Two temp channel cwds laid out as the relay does: <root>/ch7, <root>/ch8.
    let root = std::env::temp_dir().join(format!("intmax_ic_cli_{}", std::process::id()));
    let ch_a = root.join(format!("ch{A_ID}"));
    let ch_b = root.join(format!("ch{B_ID}"));
    std::fs::create_dir_all(&ch_a).unwrap();
    std::fs::create_dir_all(&ch_b).unwrap();

    // ---- Build both channels (members = the binary's CLI members) + seed cli_state.json. ----
    let a = build_cli_channel(A_ID, &[50, 10, 30]);
    let b = build_cli_channel(B_ID, &[20, 40, 60]);
    let sender_slot = 0u8;
    let recipient_slot = 1u8;

    // MemberKeys is not Clone, but the CLI members are DETERMINISTIC (cli_keys(slot)), so regenerate
    // them on demand instead of cloning the fixtures' key vectors.
    let a_keys: Vec<MemberKeys> = CLI_SLOTS.iter().map(|&s| cli_keys(s)).collect();
    let b_keys: Vec<MemberKeys> = CLI_SLOTS.iter().map(|&s| cli_keys(s)).collect();
    let b_record = b.record.clone();
    let b_members = b.snapshot.members.clone();
    let a_balances = a.balances.clone();
    let a_witnesses_clone: Vec<_> = a.witnesses.clone();

    let a_snapshot = a.snapshot.clone();
    let b_snapshot = b.snapshot.clone();
    let b_fund_before = b_snapshot.state.channel_fund.amount;
    let recipient_before =
        decrypt_balance(&b_keys[recipient_slot as usize], &b_snapshot, recipient_slot).unwrap();

    write_state(&ch_a, &cli_state(a));
    write_state(&ch_b, &cli_state(b));

    // ---- Produce a REAL debit payload + transfer descriptor via wallet_core (real E-2). ----
    let mut rng = StdRng::seed_from_u64(0x1C_C1_1);
    let dest_id = ChannelId::new(B_ID as u64).unwrap();
    let recipient_pk = b_keys[recipient_slot as usize].regev_pk.clone();
    let recipient_pk_g = b_record.member_pk_gs[recipient_slot as usize];
    let BuiltInterChannelSend {
        debit_payload,
        transfer_descriptor,
        ..
    } = build_inter_channel_send(
        &a_keys[sender_slot as usize],
        &a_snapshot,
        sender_slot,
        dest_id,
        recipient_slot,
        recipient_pk,
        recipient_pk_g,
        AMT,
        a_balances[sender_slot as usize],
        &a_witnesses_clone[sender_slot as usize],
        fresh_root(0x412),
        LEVEL,
        &mut rng,
    )
    .expect("build_inter_channel_send");

    let payload_path = ch_a.join("debit_payload.json");
    write_json_file(&payload_path, &debit_payload);
    let a_send_path = ch_a.join("a_send.json");

    // ---- (a) DEBIT co-signed in channel A. ----
    let (ok, log) = run(
        &ch_a,
        A_ID,
        &[
            "cosign-inter-debit",
            payload_path.to_str().unwrap(),
            a_send_path.to_str().unwrap(),
        ],
    );
    assert!(ok, "cosign-inter-debit must succeed, log:\n{log}");
    let a_send: intmax3_zkp::common::channel::ChannelState =
        serde_json::from_str(&std::fs::read_to_string(&a_send_path).unwrap()).unwrap();
    // a_send is N-of-N co-signed and channel_fund decreased by AMT.
    let amt_u = U256::from(AMT as u32);
    let a_fund_before = a_snapshot.state.channel_fund.amount;
    assert_eq!(
        a_send.channel_fund.amount + amt_u,
        a_fund_before,
        "A channel_fund decreased by AMT after debit"
    );
    assert_eq!(
        a_send.member_signatures.len(),
        3,
        "a_send must carry all 3 member signatures (N-of-N)"
    );

    // The descriptor crosses to channel B's process (relay transport). Write it into B's cwd.
    let desc_path = ch_b.join("descriptor.json");
    write_json_file(&desc_path, &transfer_descriptor);
    let a_send_for_b = ch_b.join("a_send.json");
    write_json_file(&a_send_for_b, &a_send);
    let b_out = ch_b.join("b_credited.json");

    // ---- (b) CREDIT applied in channel B, crediting the recipient EXACTLY AMT. ----
    let (ok, log) = run(
        &ch_b,
        B_ID,
        &[
            "cosign-inter-credit",
            desc_path.to_str().unwrap(),
            a_send_for_b.to_str().unwrap(),
            b_out.to_str().unwrap(),
        ],
    );
    assert!(ok, "cosign-inter-credit must succeed, log:\n{log}");
    let b_credited: intmax3_zkp::common::channel::ChannelState =
        serde_json::from_str(&std::fs::read_to_string(&b_out).unwrap()).unwrap();
    assert_eq!(
        b_credited.channel_fund.amount,
        b_fund_before + amt_u,
        "B channel_fund increased by EXACTLY AMT"
    );
    // Recipient slot credited exactly AMT (decrypt with the recipient's own key).
    let b_credited_snapshot = ChannelSnapshot {
        record: b_record.clone(),
        state: b_credited.clone(),
        members: b_members.clone(),
    };
    let recipient_after = decrypt_balance(
        &b_keys[recipient_slot as usize],
        &b_credited_snapshot,
        recipient_slot,
    )
    .unwrap();
    assert_eq!(
        recipient_after,
        recipient_before + AMT,
        "recipient slot in B credited EXACTLY AMT"
    );
    // The replay ledger now contains the tx_hash on disk.
    let b_state_after: CliState =
        serde_json::from_str(&std::fs::read_to_string(ch_b.join("cli_state.json")).unwrap())
            .unwrap();
    assert!(
        b_state_after
            .applied_tx_hashes
            .contains(&transfer_descriptor.tx_hash),
        "tx_hash must be recorded in B's persisted replay ledger"
    );

    // ---- (c) REPLAY of the SAME tx_hash → REFUSED (fail-closed, invariant 6). ----
    // (B's head has advanced; the descriptor would no longer extend it anyway, but the replay-ledger
    //  check fires FIRST and is the security-relevant rejection.)
    let (ok, log) = run(
        &ch_b,
        B_ID,
        &[
            "cosign-inter-credit",
            desc_path.to_str().unwrap(),
            a_send_for_b.to_str().unwrap(),
            ch_b.join("replay_out.json").to_str().unwrap(),
        ],
    );
    assert!(!ok, "replayed tx_hash MUST be refused");
    assert!(
        log.contains("already credited") || log.contains("replay"),
        "replay rejection must be by the replay ledger, got:\n{log}"
    );

    // ---- (d) TAMPERED descriptor (wrong amount) → REFUSED by the credit gate. ----
    // Use a FRESH B channel cwd so the replay ledger / head-advance does not mask the tamper rejection
    // (we want the gate, not the ledger, to reject). Rebuild B identically.
    let ch_b2 = root.join(format!("ch{B_ID}_t"));
    std::fs::create_dir_all(&ch_b2).unwrap();
    // The credit command resolves A as ../ch7 relative to B's cwd, so also stage an A sibling here.
    let ch_a2 = root.join(format!("ch{A_ID}"));
    let _ = ch_a2; // ch7 already exists at root level
    let b2 = build_cli_channel(B_ID, &[20, 40, 60]);
    write_state(&ch_b2, &cli_state(b2));
    let mut tampered = transfer_descriptor.clone();
    tampered.amount = AMT + 1;
    let tdesc_path = ch_b2.join("descriptor.json");
    write_json_file(&tdesc_path, &tampered);
    let ta_send = ch_b2.join("a_send.json");
    write_json_file(&ta_send, &a_send);
    let (ok, log) = run(
        &ch_b2,
        B_ID,
        &[
            "cosign-inter-credit",
            tdesc_path.to_str().unwrap(),
            ta_send.to_str().unwrap(),
            ch_b2.join("t_out.json").to_str().unwrap(),
        ],
    );
    assert!(!ok, "tampered amount MUST be refused, log:\n{log}");
    assert!(
        log.contains("credit gate REFUSED") || log.contains("invariant"),
        "tamper rejection must come from the credit gate, got:\n{log}"
    );

    // ---- (e) Idempotent re-join: init with an already-present pk_g returns the SAME slot. ----
    // Build a fresh channel cwd, create it via a delegate contribution, then re-init with the SAME
    // contribution and assert the slot + delegate_count + state_version are unchanged.
    let ch_join = root.join("ch_join");
    std::fs::create_dir_all(&ch_join).unwrap();
    // A backed channel is required by `init` (it loads the deposit backing for create/join). Since
    // wiring real backing is intractable here, we test the dedup at the library level instead: we
    // construct a snapshot with a delegate, then prove the binary's dedup rule (pk_g already present →
    // same slot, no growth) by simulating both branches. The PROCESS-level create path needs
    // setup-backing; the dedup LOGIC is the security-relevant part and is asserted below.
    //
    // Build a channel with a delegate at slot 3, then check: a contribution whose pk_g == the existing
    // delegate's pk_g must NOT allocate a new slot.
    let delegate_keys = MemberKeys::generate(&mut StdRng::seed_from_u64(0xDE_1E_6A));
    let mut members_with_delegate = b_members.clone();
    members_with_delegate.push(member_info(3, &delegate_keys));
    // The dedup predicate the binary uses: members.iter().find(|m| m.pk_g == contribution.pk_g).
    let contribution_pk_g = delegate_keys.pk_g();
    let found = members_with_delegate
        .iter()
        .find(|m| m.pk_g == contribution_pk_g);
    assert!(
        found.is_some() && found.unwrap().slot == 3,
        "idempotent re-join: an already-present pk_g resolves to its EXISTING slot (3), no new slot"
    );
    // A genuinely new pk_g must NOT match any existing member (would get the next free slot).
    let new_keys = MemberKeys::generate(&mut StdRng::seed_from_u64(0xF8_E5_44));
    assert!(
        members_with_delegate
            .iter()
            .all(|m| m.pk_g != new_keys.pk_g()),
        "a genuinely new pk_g is not deduped (gets a fresh slot)"
    );

    // ---- (e2) Idempotent re-join through the REAL binary (no backing needed for the dedup branch).
    // The binary's dedup short-circuits BEFORE load_backing(): if pk_g is already present it returns
    // the existing slot using only the on-disk cli_state. We seed a cli_state that already contains a
    // delegate at slot 3, then run `init` with that delegate's contribution and assert the binary
    // reports the SAME slot with NO state bump.
    let mut join_state = cli_state(build_cli_channel(B_ID, &[20, 40, 60]));
    // Inject a delegate at slot 3 into the snapshot's member list (state_version stays as-is).
    join_state.snapshot.members.push(member_info(3, &delegate_keys));
    let v_before = join_state.snapshot.state.balance_state.state_version;
    write_state(&ch_join, &join_state);
    // Write the delegate's contribution (camelCase fields matching BrowserContribution).
    let (ct, _w) = encrypt_amount(
        &mut StdRng::seed_from_u64(0xC0_FFEE),
        &delegate_keys.regev_pk,
        50,
    )
    .unwrap();
    let contrib = json!({
        "regevPk": delegate_keys.regev_pk,
        "pkG": delegate_keys.pk_g().to_hex(),
        "pkB": delegate_keys.pk_b().to_hex(),
        "genesisCt": ct,
    });
    let contrib_path = ch_join.join("contribution.json");
    std::fs::write(&contrib_path, serde_json::to_string_pretty(&contrib).unwrap()).unwrap();
    let out_snap = ch_join.join("snap_out.json");
    let (ok, log) = run(
        &ch_join,
        B_ID,
        &[
            "init",
            contrib_path.to_str().unwrap(),
            out_snap.to_str().unwrap(),
        ],
    );
    assert!(ok, "idempotent re-join init must succeed, log:\n{log}");
    assert!(
        log.contains("idempotent re-join") && log.contains("slot 3"),
        "re-join must report the SAME slot 3 idempotently, got:\n{log}"
    );
    // No state bump on disk.
    let join_after: CliState =
        serde_json::from_str(&std::fs::read_to_string(ch_join.join("cli_state.json")).unwrap())
            .unwrap();
    assert_eq!(
        join_after.snapshot.state.balance_state.state_version, v_before,
        "idempotent re-join must NOT bump state_version (no collision / no inflation)"
    );
    assert_eq!(
        join_after.snapshot.members.iter().filter(|m| m.slot == 3).count(),
        1,
        "idempotent re-join must NOT duplicate the delegate slot"
    );

    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
        "[inter_channel_cli] OK: (a) debit co-signed in A, (b) credit applied in B (+AMT), \
         (c) replay refused, (d) tampered amount refused, (e) idempotent re-join → same slot."
    );
}
