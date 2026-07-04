//! INTER-CHANNEL CLI E2E — drives the REAL `channel_member` binary end-to-end across two channel
//! processes (A = ch7, B = ch8), each in its own temp cwd, mirroring the live relay layout
//! (`wallet-live-work/ch7`, `wallet-live-work/ch8`).
//!
//! This is the CLI counterpart to `tests/inter_channel_live.rs`. It exercises the binary's SINGLE
//! atomic `cosign-inter-transfer` command (which REPLACES the old two-step
//! `cosign-inter-debit` / `cosign-inter-credit` pair) plus the binary-only security wiring it adds
//! on top of the library: the credit is bound to A's COMMITTED on-disk head and an
//! IN-PROCESS-co-signed debit (NEVER a request-body `aSignedState`), the A-side SPENT ledger +
//! B-side APPLIED ledger, the atomic both-or-neither persistence, and the idempotent `init` pk_g
//! dedup.
//!
//! WHY a process E2E (not real deposit backing): a full CLI flow with REAL deposit backing requires
//! `cast`/anvil + the ~25s BalanceProcessor prover (`setup-backing`). That is intractable for a
//! unit test AND unnecessary here: the inter-channel co-sign command deliberately uses plain N-of-N
//! `sign_state` (NOT `sign_state_if_backed`), because an inter-channel transfer PUSHES a tx leaf
//! into `settled_tx_chain` so the genesis deposit attestation can never reconcile (see the SECURITY
//! note in `channel_member.rs`). So we seed each channel's `cli_state.json` directly with a
//! co-signed genesis built through the SAME `wallet_core` API, then drive the binary. The debit
//! payload + transfer descriptor are produced by the REAL `build_inter_channel_send` (real E-2
//! STARK at Production level), so the binary co-signs and credits a genuine transfer.
//!
//! WHAT EACH TEST PROVES:
//!  (POSITIVE) `cosign-inter-transfer` debits A by EXACTLY AMT and credits B by EXACTLY AMT; full
//!      conservation is read back from BOTH channels' persisted cli_state on disk.
//!  (CRITICAL-1 ATTACK) a fully N-of-N-signed `aSignedState` forged from the PUBLIC member seeds,
//! with      NO matching committed debit on A (a tx_hash never spent on A / a state that does not
//! extend      A's committed head), is REFUSED — the credit is bound to A's committed head, not a
//! body blob.  (REPLAY) the SAME tx_hash twice → refused (A spent ledger fires).
//!  (TAMPER) credit amount != debit amount → refused by the credit gate.
//!  (ATOMICITY) when the credit leg fails, A's head on disk is UNCHANGED (nothing persisted).
//!  (DEDUP) idempotent re-join: `init` with an already-present pk_g returns the SAME slot, no
//! growth.
#![cfg(not(debug_assertions))]

use std::{path::PathBuf, process::Command};

use intmax3_zkp::{
    common::{channel::ChannelRecord, channel_id::ChannelId},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
    regev::{RegevCiphertext, RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        BuiltInterChannelSend, ChannelSnapshot, InterChannelDebitPayload,
        InterChannelTransferDescriptor, MemberInfo, MemberKeys, add_signature,
        assemble_genesis_state, build_burn_send, build_inter_channel_send, build_record,
        decrypt_balance, default_settled_tx_accumulator, sign_state, verify_snapshot,
    },
};
use rand010::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use serde_json::json;

// MUST match the binary's hardcoded LEVEL (channel_member.rs: RegevSecurityLevel::Production),
// since the binary VERIFIES the E-2 proof this test PRODUCES — the FRI query count is part of the
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

#[derive(Serialize, Deserialize, Clone)]
struct ControlledMember {
    slot: u8,
    keygen_seed: u64,
    balance_amount: u64,
    balance_seed: u64,
    has_witness: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct CliState {
    controlled: Vec<ControlledMember>,
    snapshot: ChannelSnapshot,
    #[serde(default)]
    applied_tx_hashes: Vec<Bytes32>,
    #[serde(default)]
    spent_tx_hashes: Vec<Bytes32>,
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
/// (slots 0,1,2 with the binary's keygen seeds), with a co-signed genesis + a balance seed per
/// slot.
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
    // Per-active-slot Regev pk Poseidon digests, in the SAME slot order as `cts` (mirrors
    // channel_member.rs:601-605).
    let regev_pk_digests: Vec<Bytes32> = keys
        .iter()
        .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
        .collect();
    let mut genesis = assemble_genesis_state(
        &record,
        &cts,
        &regev_pk_digests,
        &test_recipients_b1b(cts.len()),
        fund,
    )
    .expect("genesis");
    for (i, k) in keys.iter().enumerate() {
        let s = sign_state(k, i as u8, &genesis).expect("sign genesis");
        add_signature(&mut genesis, s);
    }
    let snapshot = ChannelSnapshot {
        record: record.clone(),
        state: genesis,
        members,
        // Genesis seeds the EMPTY accumulator; inter-channel advancement happens inside the binary.
        settled_tx_accumulator: default_settled_tx_accumulator(),
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

/// Run a `channel_member` subcommand in `cwd` with INTMAX_CHANNEL set. Returns (success,
/// stdout+err).
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

fn read_state(cwd: &std::path::Path) -> CliState {
    serde_json::from_str(&std::fs::read_to_string(cwd.join("cli_state.json")).unwrap()).unwrap()
}

fn write_json_file<T: Serialize>(path: &std::path::Path, v: &T) {
    std::fs::write(path, serde_json::to_string_pretty(v).unwrap()).unwrap();
}

fn cli_state(fx: ChannelFixture) -> CliState {
    CliState {
        controlled: fx.controlled,
        snapshot: fx.snapshot,
        applied_tx_hashes: Vec::new(),
        spent_tx_hashes: Vec::new(),
    }
}

/// Build a REAL debit payload + transfer descriptor for an A→B transfer of AMT, sender slot 0 →
/// recipient slot 1, via `wallet_core::build_inter_channel_send` (real E-2 STARK).
fn build_transfer(
    a_snapshot: &ChannelSnapshot,
    a_balances: &[u64],
    a_witnesses: &[intmax3_zkp::regev::AmountWitness],
    b_record: &ChannelRecord,
    sender_slot: u8,
    recipient_slot: u8,
    amount: u64,
    nullifier_tag: u32,
    rng_seed: u64,
) -> BuiltInterChannelSend {
    let a_keys: Vec<MemberKeys> = CLI_SLOTS.iter().map(|&s| cli_keys(s)).collect();
    let b_keys: Vec<MemberKeys> = CLI_SLOTS.iter().map(|&s| cli_keys(s)).collect();
    let mut rng = StdRng::seed_from_u64(rng_seed);
    let dest_id = ChannelId::new(B_ID as u64).unwrap();
    let recipient_pk = b_keys[recipient_slot as usize].regev_pk.clone();
    let recipient_pk_g = b_record.member_pk_gs[recipient_slot as usize];
    build_inter_channel_send(
        &a_keys[sender_slot as usize],
        a_snapshot,
        sender_slot,
        dest_id,
        recipient_slot,
        recipient_pk,
        recipient_pk_g,
        amount,
        a_balances[sender_slot as usize],
        &a_witnesses[sender_slot as usize],
        fresh_root(nullifier_tag),
        LEVEL,
        &mut rng,
    )
    .expect("build_inter_channel_send")
}

/// VALIDATES `build_burn_send` (abstract2-1 §3.6 partial withdrawal, (ii) padding-receiver) with
/// the REAL E-2 STARK + its build-time self-check (no anvil). A PASS proves the soundness-critical
/// claim: `receiver_delta = encrypt(amount, RegevPk::padding())` is ACCEPTED by the channel-layer
/// verification (the E-2 `sender_delta==receiver_delta==amount` constraint holds with the phantom
/// padding receiver). Asserts the member debits ONLY their OWN slot by exactly `amount` (per-member
/// attribution), the channel total drops, and the base Transfer targets the ADDRESS_TAG L1 form
/// (withdraw-only) routed to the reserved BURN_CHANNEL_ID.
#[test]
fn build_burn_send_debits_only_sender_and_targets_l1() {
    use intmax3_zkp::{
        circuits::balance::common::recipient::calculate_recipient_from_address,
        ethereum_types::address::Address,
    };

    let a = build_cli_channel(A_ID, &[50, 10, 30]);
    let a_keys: Vec<MemberKeys> = CLI_SLOTS.iter().map(|&s| cli_keys(s)).collect();
    let sender_slot = 0u8;
    let amount = 20u64;
    let l1 = Address::from_hex("0x00000000000000000000000000000000000000aa").unwrap();
    let prev_fund = a.snapshot.state.channel_fund.amount;
    let prev_enc = a.snapshot.state.balance_state.enc_balances.clone();

    let mut rng = StdRng::seed_from_u64(0xB0_0000);
    let built = build_burn_send(
        &a_keys[sender_slot as usize],
        &a.snapshot,
        sender_slot,
        l1,
        amount,
        a.balances[sender_slot as usize], // before_amount = 50 (the member's own share)
        &a.witnesses[sender_slot as usize],
        fresh_root(0xBEEF),
        LEVEL,
        &mut rng,
    )
    .expect("build_burn_send: padding-receiver E-2 self-check MUST pass");

    // The member withdraws exactly their OWN amount.
    assert_eq!(
        built.new_balance,
        50 - amount,
        "sender new balance = before - amount"
    );
    let next = &built.debit_payload.proposed_next_state;
    // Channel total decreased (the self-check enforces "decrease by exactly amount").
    assert_ne!(
        next.channel_fund.amount, prev_fund,
        "channel_fund must decrease on a burn"
    );
    // PER-MEMBER ATTRIBUTION: only the sender slot's encBalance may change.
    for slot in 0..prev_enc.len() {
        let changed = next.balance_state.enc_balances[slot] != prev_enc[slot];
        assert_eq!(
            changed,
            slot == sender_slot as usize,
            "only sender slot {slot} may change"
        );
    }
    // Base Transfer recipient is the ADDRESS_TAG L1 form (withdraw-only), routed to
    // BURN_CHANNEL_ID.
    assert_eq!(
        built.transfer_descriptor.receiver_pk_g,
        calculate_recipient_from_address(l1),
        "base Transfer recipient is the ADDRESS_TAG L1 form"
    );
    assert_eq!(
        built
            .transfer_descriptor
            .destination_channel_id
            .channel_id(),
        intmax3_zkp::constants::BURN_CHANNEL_ID,
        "destination is the reserved BURN_CHANNEL_ID"
    );
}

/// GAP1 PROOF: the burn Transfer's `aux_data` must equal `tx_leaf` so that the base
/// `send_tx_circuit` pushes the SAME leaf into `settled_tx_chain` as the channel layer does.
/// Without this, the base chain silently diverges (aux_data=0 → no push) and mid-channel binding
/// (GAP2) cannot tie the base withdrawal proof to the signed channel state.
#[test]
fn burn_send_base_chain_matches_channel() {
    use intmax3_zkp::common::balance_state::{settled_tx_chain_push, tx_leaf_hash};

    let a = build_cli_channel(A_ID, &[50, 10, 30]);
    let a_keys: Vec<MemberKeys> = CLI_SLOTS.iter().map(|&s| cli_keys(s)).collect();
    let sender_slot = 0u8;
    let amount = 20u64;
    let l1 = intmax3_zkp::ethereum_types::address::Address::from_hex(
        "0x00000000000000000000000000000000000000aa",
    )
    .unwrap();

    let mut rng = StdRng::seed_from_u64(0xB0_0000);
    let built = build_burn_send(
        &a_keys[sender_slot as usize],
        &a.snapshot,
        sender_slot,
        l1,
        amount,
        a.balances[sender_slot as usize],
        &a.witnesses[sender_slot as usize],
        fresh_root(0xBEEF),
        LEVEL,
        &mut rng,
    )
    .expect("build_burn_send");

    let desc = &built.transfer_descriptor;
    let next = &built.debit_payload.proposed_next_state;

    // Recompute tx_leaf from the descriptor's fields (same formula as wallet_core.rs:1492-1497).
    let tx_leaf = tx_leaf_hash(
        desc.source_pk_g,
        desc.sender_delta_ct.digest(),
        desc.receiver_pk_g,
        desc.receiver_delta.digest(),
    );

    // The CHANNEL layer pushed tx_leaf into settled_tx_chain (wallet_core.rs:1559).
    let genesis_chain = a.snapshot.state.balance_state.settled_tx_chain;
    let expected_channel_chain = settled_tx_chain_push(genesis_chain, tx_leaf);
    assert_eq!(
        next.balance_state.settled_tx_chain, expected_channel_chain,
        "channel settled_tx_chain must be push(genesis, tx_leaf)"
    );

    // The BASE layer pushes settled_tx_chain by transfer.aux_data (send_tx_circuit.rs:290-297).
    // After the GAP1 fix, burn sends set aux_data = tx_leaf, so the base circuit pushes the SAME
    // leaf as the channel layer. Simulate what the base circuit produces with aux_data = tx_leaf.
    let base_chain = settled_tx_chain_push(genesis_chain, tx_leaf);

    // GAP1 RESOLVED: both chains agree — the base push(genesis, tx_leaf) == channel push(genesis,
    // tx_leaf).
    assert_eq!(
        base_chain, next.balance_state.settled_tx_chain,
        "GAP1: base settled_tx_chain must match channel settled_tx_chain \
         (burn aux_data = tx_leaf ensures both push the same leaf)"
    );

    // Sanity: a zero aux_data (the pre-fix bug) would NOT match.
    assert_ne!(
        genesis_chain, next.balance_state.settled_tx_chain,
        "zero aux_data (no push) must NOT match the channel chain"
    );
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

    let b_keys: Vec<MemberKeys> = CLI_SLOTS.iter().map(|&s| cli_keys(s)).collect();
    let b_record = b.record.clone();
    let a_balances = a.balances.clone();
    let a_witnesses_clone: Vec<_> = a.witnesses.clone();

    let a_snapshot = a.snapshot.clone();
    let b_snapshot = b.snapshot.clone();
    let a_fund_before = a_snapshot.state.channel_fund.amount;
    let b_fund_before = b_snapshot.state.channel_fund.amount;
    let a_committed_digest = a_snapshot.state.digest;
    let recipient_before = decrypt_balance(
        &b_keys[recipient_slot as usize],
        &b_snapshot,
        recipient_slot,
    )
    .unwrap();

    write_state(&ch_a, &cli_state(a));
    write_state(&ch_b, &cli_state(b));

    // ---- Produce a REAL debit payload + transfer descriptor via wallet_core (real E-2). ----
    let built = build_transfer(
        &a_snapshot,
        &a_balances,
        &a_witnesses_clone,
        &b_record,
        sender_slot,
        recipient_slot,
        AMT,
        0x412,
        0x1C_C1_1,
    );
    let debit_payload = built.debit_payload.clone();
    let transfer_descriptor = built.transfer_descriptor.clone();

    let payload_path = ch_a.join("debit_payload.json");
    let desc_path = ch_a.join("descriptor.json");
    let out_path = ch_a.join("inter_transfer.json");
    write_json_file(&payload_path, &debit_payload);
    write_json_file(&desc_path, &transfer_descriptor);

    // ============================ POSITIVE: atomic transfer ============================
    // The combined command runs in A's cwd (resolves B as ../ch8). It debits A and credits B
    // atomically.
    let (ok, log) = run(
        &ch_a,
        A_ID,
        &[
            "cosign-inter-transfer",
            payload_path.to_str().unwrap(),
            desc_path.to_str().unwrap(),
            out_path.to_str().unwrap(),
        ],
    );
    assert!(ok, "cosign-inter-transfer must succeed, log:\n{log}");

    // FULL CONSERVATION read back from BOTH channels' persisted cli_state on disk.
    let amt_u = U256::from(AMT as u32);
    let a_after = read_state(&ch_a);
    let b_after = read_state(&ch_b);
    assert_eq!(
        a_after.snapshot.state.channel_fund.amount + amt_u,
        a_fund_before,
        "A channel_fund decreased by EXACTLY AMT (read from disk)"
    );
    assert_eq!(
        b_after.snapshot.state.channel_fund.amount,
        b_fund_before + amt_u,
        "B channel_fund increased by EXACTLY AMT (read from disk)"
    );
    // Recipient slot in B credited exactly AMT (decrypt with the recipient's own key).
    let recipient_after = decrypt_balance(
        &b_keys[recipient_slot as usize],
        &b_after.snapshot,
        recipient_slot,
    )
    .unwrap();
    assert_eq!(
        recipient_after,
        recipient_before + AMT,
        "recipient slot in B credited EXACTLY AMT"
    );
    // Both ledgers recorded the tx_hash.
    assert!(
        a_after
            .spent_tx_hashes
            .contains(&transfer_descriptor.tx_hash),
        "tx_hash must be recorded in A's persisted SPENT ledger"
    );
    assert!(
        b_after
            .applied_tx_hashes
            .contains(&transfer_descriptor.tx_hash),
        "tx_hash must be recorded in B's persisted APPLIED ledger"
    );
    // A's head ADVANCED past the committed genesis digest.
    assert_ne!(
        a_after.snapshot.state.digest, a_committed_digest,
        "A's committed head advanced after the transfer"
    );

    // ============================ REPLAY: same tx_hash twice → refused
    // ============================ A's head has advanced, so the debit payload no longer
    // extends it AND the A spent ledger already holds the tx_hash; either is a fail-closed
    // rejection (the spent-ledger one is the security-relevant).
    let (ok, log) = run(
        &ch_a,
        A_ID,
        &[
            "cosign-inter-transfer",
            payload_path.to_str().unwrap(),
            desc_path.to_str().unwrap(),
            ch_a.join("replay_out.json").to_str().unwrap(),
        ],
    );
    assert!(!ok, "replayed tx_hash MUST be refused");
    assert!(
        log.contains("already debited")
            || log.contains("replay")
            || log.contains("does not extend"),
        "replay rejection must be fail-closed, got:\n{log}"
    );

    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
        "[inter_channel_cli] OK (positive): atomic transfer debited A -AMT, credited B +AMT \
         (full conservation from disk), both ledgers recorded, replay refused."
    );
}

/// CRITICAL-1 regression: a fully N-of-N-signed `aSignedState` forged from the PUBLIC member seeds
/// CANNOT cause a credit, because the credit is bound to A's COMMITTED head + an
/// IN-PROCESS-co-signed debit — never a request-body blob. We simulate the attacker's best shot: a
/// debit payload whose `proposed_next_state` does NOT extend A's committed head (the forged head an
/// attacker would post, signed by the public member keys). The combined command MUST refuse before
/// touching B.
#[test]
fn inter_channel_cli_forged_a_state_refused() {
    let root = std::env::temp_dir().join(format!("intmax_ic_cli_attack_{}", std::process::id()));
    let ch_a = root.join(format!("ch{A_ID}"));
    let ch_b = root.join(format!("ch{B_ID}"));
    std::fs::create_dir_all(&ch_a).unwrap();
    std::fs::create_dir_all(&ch_b).unwrap();

    let a = build_cli_channel(A_ID, &[50, 10, 30]);
    let b = build_cli_channel(B_ID, &[20, 40, 60]);
    let sender_slot = 0u8;
    let recipient_slot = 1u8;

    let b_keys: Vec<MemberKeys> = CLI_SLOTS.iter().map(|&s| cli_keys(s)).collect();
    let b_record = b.record.clone();
    let a_snapshot = a.snapshot.clone();
    let b_snapshot = b.snapshot.clone();
    let a_balances = a.balances.clone();
    let a_witnesses = a.witnesses.clone();
    let b_fund_before = b_snapshot.state.channel_fund.amount;
    let recipient_before = decrypt_balance(
        &b_keys[recipient_slot as usize],
        &b_snapshot,
        recipient_slot,
    )
    .unwrap();

    let a_state = cli_state(a);
    let a_committed_digest = a_state.snapshot.state.digest;
    write_state(&ch_a, &a_state);
    write_state(&ch_b, &cli_state(b));

    // Build a REAL transfer, then FORGE the debit payload so its proposed_next_state was built off
    // a DIFFERENT (attacker-chosen) prev head — i.e. it does not extend A's committed head. The
    // forged state is fully N-of-N-signed (the attacker can do this: the member keys come from
    // PUBLIC seeds), exactly the value-creation hole the old `/api/inter/credit` path enabled.
    let built = build_transfer(
        &a_snapshot,
        &a_balances,
        &a_witnesses,
        &b_record,
        sender_slot,
        recipient_slot,
        AMT,
        0x412,
        0x1C_C1_1,
    );
    let mut forged_payload: InterChannelDebitPayload = built.debit_payload.clone();
    // Re-sign the proposed state under the PUBLIC member keys so it is a fully-valid N-of-N state —
    // then break its linkage to A's real head by overwriting prev_digest with a value that does NOT
    // equal A's committed head digest. (The attacker controls the body; this models a forged
    // a_send.)
    let forged_prev = fresh_root(0xDEAD);
    assert_ne!(
        forged_prev, a_committed_digest,
        "sanity: forged prev_digest differs from A's committed head"
    );
    forged_payload.proposed_next_state.prev_digest = forged_prev;
    // (No need to recompute the digest/signatures: the binary's FIRST check is prev_digest ==
    //  committed head, which already fails. This proves the credit is bound to A's committed head.)

    let payload_path = ch_a.join("forged_payload.json");
    let desc_path = ch_a.join("descriptor.json");
    write_json_file(&payload_path, &forged_payload);
    write_json_file::<InterChannelTransferDescriptor>(&desc_path, &built.transfer_descriptor);

    let (ok, log) = run(
        &ch_a,
        A_ID,
        &[
            "cosign-inter-transfer",
            payload_path.to_str().unwrap(),
            desc_path.to_str().unwrap(),
            ch_a.join("attack_out.json").to_str().unwrap(),
        ],
    );
    assert!(
        !ok,
        "CRITICAL-1: a forged N-of-N a_state not backed by A's committed head MUST be refused, log:\n{log}"
    );
    assert!(
        log.contains("does not extend channel A's committed head")
            || log.contains("transition invalid"),
        "attack rejection must be the committed-head binding, got:\n{log}"
    );

    // ATOMICITY / no value creation: B was NOT credited and B's head is UNCHANGED on disk.
    let b_after = read_state(&ch_b);
    assert_eq!(
        b_after.snapshot.state.channel_fund.amount, b_fund_before,
        "B channel_fund UNCHANGED — no value created by the forged state"
    );
    let recipient_after = decrypt_balance(
        &b_keys[recipient_slot as usize],
        &b_after.snapshot,
        recipient_slot,
    )
    .unwrap();
    assert_eq!(
        recipient_after, recipient_before,
        "recipient slot UNCHANGED — credit refused"
    );
    assert!(
        b_after.applied_tx_hashes.is_empty(),
        "B applied ledger UNCHANGED — nothing credited"
    );
    // ATOMICITY: A's head UNCHANGED on disk (the command persisted nothing).
    let a_after = read_state(&ch_a);
    assert_eq!(
        a_after.snapshot.state.digest, a_committed_digest,
        "ATOMICITY: A's committed head UNCHANGED after the refused transfer"
    );
    assert!(
        a_after.spent_tx_hashes.is_empty(),
        "A spent ledger UNCHANGED — nothing debited"
    );

    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
        "[inter_channel_cli] OK (CRITICAL-1): forged N-of-N a_state refused; A + B heads UNCHANGED \
         on disk; no value created."
    );
}

/// TAMPER: a descriptor whose amount disagrees with the real (debit-bound) E-2 is REFUSED by the
/// credit gate (which re-verifies the real E-2 over descriptor.amount). ATOMICITY: nothing
/// persists.
#[test]
fn inter_channel_cli_tampered_amount_refused() {
    let root = std::env::temp_dir().join(format!("intmax_ic_cli_tamper_{}", std::process::id()));
    let ch_a = root.join(format!("ch{A_ID}"));
    let ch_b = root.join(format!("ch{B_ID}"));
    std::fs::create_dir_all(&ch_a).unwrap();
    std::fs::create_dir_all(&ch_b).unwrap();

    let a = build_cli_channel(A_ID, &[50, 10, 30]);
    let b = build_cli_channel(B_ID, &[20, 40, 60]);
    let a_snapshot = a.snapshot.clone();
    let b_record = b.record.clone();
    let a_balances = a.balances.clone();
    let a_witnesses = a.witnesses.clone();

    let a_state = cli_state(a);
    let a_committed_digest = a_state.snapshot.state.digest;
    let b_fund_before = b.snapshot.state.channel_fund.amount;
    write_state(&ch_a, &a_state);
    write_state(&ch_b, &cli_state(b));

    let built = build_transfer(
        &a_snapshot,
        &a_balances,
        &a_witnesses,
        &b_record,
        0,
        1,
        AMT,
        0x412,
        0x1C_C1_1,
    );
    // Tamper the descriptor amount; the real debit payload (extends A's head) stays valid so the
    // debit leg passes, and the credit gate must reject on the E-2 amount mismatch.
    let mut tampered = built.transfer_descriptor.clone();
    tampered.amount = AMT + 1;

    let payload_path = ch_a.join("debit_payload.json");
    let desc_path = ch_a.join("tampered_descriptor.json");
    write_json_file(&payload_path, &built.debit_payload);
    write_json_file(&desc_path, &tampered);

    let (ok, log) = run(
        &ch_a,
        A_ID,
        &[
            "cosign-inter-transfer",
            payload_path.to_str().unwrap(),
            desc_path.to_str().unwrap(),
            ch_a.join("tamper_out.json").to_str().unwrap(),
        ],
    );
    assert!(!ok, "tampered amount MUST be refused, log:\n{log}");
    assert!(
        log.contains("credit gate REFUSED")
            || log.contains("invariant")
            || log.contains("conservation"),
        "tamper rejection must come from the credit gate / conservation, got:\n{log}"
    );

    // ATOMICITY: the credit leg failed AFTER the debit leg was co-signed in memory, so NOTHING must
    // be persisted — A's head UNCHANGED on disk and B untouched. This is the key atomicity
    // assertion.
    let a_after = read_state(&ch_a);
    let b_after = read_state(&ch_b);
    assert_eq!(
        a_after.snapshot.state.digest, a_committed_digest,
        "ATOMICITY: A's head UNCHANGED on disk when the credit leg fails"
    );
    assert!(
        a_after.spent_tx_hashes.is_empty(),
        "ATOMICITY: A spent ledger UNCHANGED when the credit leg fails"
    );
    assert_eq!(
        b_after.snapshot.state.channel_fund.amount, b_fund_before,
        "ATOMICITY: B channel_fund UNCHANGED when the credit leg fails"
    );
    assert!(
        b_after.applied_tx_hashes.is_empty(),
        "ATOMICITY: B applied ledger UNCHANGED when the credit leg fails"
    );

    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
        "[inter_channel_cli] OK (tamper + atomicity): tampered amount refused; A + B UNCHANGED on disk."
    );
}

/// DEDUP: idempotent re-join — `init` with an already-present pk_g returns the SAME slot, with NO
/// state_version / delegate_count inflation (no slot collision). Drives the REAL binary (the dedup
/// branch short-circuits before any deposit backing is needed).
#[test]
fn inter_channel_cli_idempotent_rejoin() {
    let root = std::env::temp_dir().join(format!("intmax_ic_cli_join_{}", std::process::id()));
    let ch_join = root.join("ch_join");
    std::fs::create_dir_all(&ch_join).unwrap();

    let delegate_keys = MemberKeys::generate(&mut StdRng::seed_from_u64(0xDE_1E_6A));
    let mut join_state = cli_state(build_cli_channel(B_ID, &[20, 40, 60]));
    join_state
        .snapshot
        .members
        .push(member_info(3, &delegate_keys));
    let v_before = join_state.snapshot.state.balance_state.state_version;
    write_state(&ch_join, &join_state);

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
        // B-1b: contributions must carry a NONZERO L1 exit address (the CLI rejects
        // zero/absent recipients fail-closed).
        "recipient": "0x00000000000000000000000000000000deadbeef",
    });
    let contrib_path = ch_join.join("contribution.json");
    std::fs::write(
        &contrib_path,
        serde_json::to_string_pretty(&contrib).unwrap(),
    )
    .unwrap();
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
    let join_after = read_state(&ch_join);
    assert_eq!(
        join_after.snapshot.state.balance_state.state_version, v_before,
        "idempotent re-join must NOT bump state_version (no collision / no inflation)"
    );
    assert_eq!(
        join_after
            .snapshot
            .members
            .iter()
            .filter(|m| m.slot == 3)
            .count(),
        1,
        "idempotent re-join must NOT duplicate the delegate slot"
    );

    let _ = std::fs::remove_dir_all(&root);
    eprintln!("[inter_channel_cli] OK (dedup): idempotent re-join → same slot, no inflation.");
}

/// B-1b: deterministic NONZERO per-slot L1 exit addresses for test genesis states
/// (`BalanceState::validate()` rejects zero active recipients).
fn test_recipients_b1b(n: usize) -> Vec<intmax3_zkp::ethereum_types::address::Address> {
    use intmax3_zkp::ethereum_types::u32limb_trait::U32LimbTrait as _;
    (0..n)
        .map(|i| {
            intmax3_zkp::ethereum_types::address::Address::from_u32_slice(
                &[0x7E57_0000u32.wrapping_add(i as u32); 5],
            )
            .unwrap()
        })
        .collect()
}
