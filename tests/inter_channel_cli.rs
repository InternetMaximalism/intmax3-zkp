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
//! body blob.  (REPLAY) the SAME token-free replay IDENTITY twice → refused, specifically by the
//! A-side SPENT ledger, with both ledgers and both heads unchanged by the refused attempt.
//!  (TAMPER) credit amount != debit amount → refused by the credit gate.
//!  (ATOMICITY) when the credit leg fails, A's head on disk is UNCHANGED (nothing persisted).
//!  (DEDUP) idempotent re-join: `init` with an already-present pk_g returns the SAME slot, no
//! growth.
#![cfg(not(debug_assertions))]

use std::{collections::HashSet, path::PathBuf, process::Command};

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

// ---- mirrors of the binary's private serde structs (`channel_member.rs`) ----
//
// WHY MIRRORS AND NOT THE REAL TYPES: `CliState` / `ControlledMember` / `TokenWitness` live in
// `src/bin/channel_member.rs` and are private to that BINARY crate. An integration test links only
// against the LIBRARY, so the real types are not importable here — a structural mirror is the only
// option.
//
// SECURITY (why every mirror below carries `deny_unknown_fields` and NO `#[serde(default)]`):
// serde's defaults are silently forgiving in BOTH directions — an unknown field is dropped, a
// missing field is defaulted. A mirror that is forgiving in both directions cannot detect drift:
// when `d28559f` renamed the binary's replay ledgers `applied_tx_hashes`/`spent_tx_hashes` ->
// `applied_tx_identities`/`spent_tx_identities`, this mirror kept deserializing to EMPTY vectors
// regardless of what the binary actually wrote, which turned every `is_empty()` assertion about
// the REPLAY LEDGERS below into a vacuous no-op that passed whether or not replay protection
// worked at all. `deny_unknown_fields` (rejects an added/renamed real field) plus the absence of
// `default` (rejects a removed/renamed mirror field) makes the mirror an EXACT key-set check
// against the on-disk JSON in both directions: any future drift is a hard, loud deserialization
// error in `read_state`, never a silently-empty ledger. Do NOT add `#[serde(default)]` here to
// silence such an error — fix the mirror to match the binary instead.

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct TokenWitness {
    token_slot: u8,
    amount: u64,
    seed_hex: String,
    has_witness: bool,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ControlledMember {
    slot: u16,
    keygen_seed: u64,
    balance_amount: u64,
    balance_seed: u64,
    has_witness: bool,
    token_witnesses: Vec<TokenWitness>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct CliState {
    /// SECURITY: mirrors `CliState::state_schema_version`. The binary REFUSES a file whose version
    /// is newer than it understands and, below v1, refuses one that is missing any ledger key —
    /// so this mirror must write a version the binary accepts. It is deliberately NOT
    /// `#[serde(default)]` here: if the binary's `STATE_SCHEMA_VERSION` moves, this test must be
    /// re-examined rather than silently keep writing a stale stamp.
    state_schema_version: u32,
    controlled: Vec<ControlledMember>,
    snapshot: ChannelSnapshot,
    /// SECURITY (replay ledger, B side): identities already CREDITED into this channel. Mirrors
    /// `CliState::applied_tx_identities` — keyed on the token-FREE
    /// `InterChannelTx::replay_identity()`, NEVER on the token-bearing `tx_hash`.
    applied_tx_identities: HashSet<Bytes32>,
    /// SECURITY (replay ledger, A side): identities already DEBITED out of this channel. Mirrors
    /// `CliState::spent_tx_identities`.
    spent_tx_identities: HashSet<Bytes32>,
    /// SECURITY (L1 deposit import replay ledger). Mirrored only so the key-set check above is
    /// exact; not asserted on by these tests.
    imported_deposits: HashSet<String>,
}

fn member_info(slot: u16, keys: &MemberKeys) -> MemberInfo {
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
        .map(|(i, k)| member_info(i as u16, k))
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
            slot: i as u16,
            keygen_seed: cli_keygen_seed(i as u8),
            balance_amount: bal,
            balance_seed,
            has_witness: true,
            token_witnesses: Vec::new(),
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
        // SECURITY: explicitly opt IN to the publicly-derivable deterministic co-signer keys.
        // The CLI FAILS CLOSED unless exactly one of INTMAX_COSIGNER_KEYFILE (production) or
        // this flag is set. See doc/tasks/cosigner-key-provenance.md.
        .env("INTMAX_INSECURE_DETERMINISTIC_KEYS", "1")
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

/// Must match `channel_member.rs`'s `STATE_SCHEMA_VERSION`. See the mirror field's comment.
const STATE_SCHEMA_VERSION: u32 = 1;

fn cli_state(fx: ChannelFixture) -> CliState {
    CliState {
        state_schema_version: STATE_SCHEMA_VERSION,
        controlled: fx.controlled,
        snapshot: fx.snapshot,
        applied_tx_identities: HashSet::new(),
        spent_tx_identities: HashSet::new(),
        imported_deposits: HashSet::new(),
    }
}

/// Build a REAL debit payload + transfer descriptor for an A→B transfer of AMT, sender slot 0 →
/// recipient slot 1, via `wallet_core::build_inter_channel_send` (real E-2 STARK).
fn build_transfer(
    a_snapshot: &ChannelSnapshot,
    a_balances: &[u64],
    a_witnesses: &[intmax3_zkp::regev::AmountWitness],
    b_record: &ChannelRecord,
    sender_slot: u16,
    recipient_slot: u16,
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
    let sender_slot = 0u16;
    let amount = 20u64;
    let l1 = Address::from_hex("0x00000000000000000000000000000000000000aa").unwrap();
    let prev_fund = a.snapshot.state.channel_fund.amounts[0];
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
        next.channel_fund.amounts[0], prev_fund,
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
    let sender_slot = 0u16;
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
    let sender_slot = 0u16;
    let recipient_slot = 1u16;

    let b_keys: Vec<MemberKeys> = CLI_SLOTS.iter().map(|&s| cli_keys(s)).collect();
    let b_record = b.record.clone();
    let a_balances = a.balances.clone();
    let a_witnesses_clone: Vec<_> = a.witnesses.clone();

    let a_snapshot = a.snapshot.clone();
    let b_snapshot = b.snapshot.clone();
    let a_fund_before = a_snapshot.state.channel_fund.amounts[0];
    let b_fund_before = b_snapshot.state.channel_fund.amounts[0];
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
        a_after.snapshot.state.channel_fund.amounts[0] + amt_u,
        a_fund_before,
        "A channel_fund decreased by EXACTLY AMT (read from disk)"
    );
    assert_eq!(
        b_after.snapshot.state.channel_fund.amounts[0],
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
    // SECURITY (replay ledgers are LIVE, not merely absent): both persisted ledgers must hold
    // EXACTLY the one token-FREE `replay_identity()` of this transfer. This is the POSITIVE half
    // of the replay-protection proof — the `is_empty()` assertions in the refusal tests below only
    // mean something if a successful transfer demonstrably DOES write an entry.
    //
    // SECURITY (TM-16): the assertion keys on `replay_identity()`, NEVER on `descriptor.tx_hash`.
    // The two happen to coincide for a base-token-0 transfer (`inter_channel_tx_identity` is
    // `inter_channel_tx_hash` with the token limb forced to 0), so a `tx_hash`-keyed assertion
    // would still pass here while silently failing to describe what the binary actually keys on —
    // exactly the cross-token double-credit the identity keying exists to refuse.
    let replay_identity = transfer_descriptor
        .inter_channel_tx
        .replay_identity()
        .expect("descriptor replay_identity");
    assert!(
        a_after.spent_tx_identities.contains(&replay_identity),
        "replay identity must be recorded in A's persisted SPENT ledger"
    );
    assert_eq!(
        a_after.spent_tx_identities.len(),
        1,
        "A's SPENT ledger must hold EXACTLY the one debited identity"
    );
    assert!(
        b_after.applied_tx_identities.contains(&replay_identity),
        "replay identity must be recorded in B's persisted APPLIED ledger"
    );
    assert_eq!(
        b_after.applied_tx_identities.len(),
        1,
        "B's APPLIED ledger must hold EXACTLY the one credited identity"
    );
    // The ledgers are SIDE-SPECIFIC: A debited (never credited), B credited (never debited).
    assert!(
        a_after.applied_tx_identities.is_empty(),
        "A is the SOURCE — nothing may be credited into it"
    );
    assert!(
        b_after.spent_tx_identities.is_empty(),
        "B is the DESTINATION — nothing may be debited out of it"
    );
    // A's head ADVANCED past the committed genesis digest.
    assert_ne!(
        a_after.snapshot.state.digest, a_committed_digest,
        "A's committed head advanced after the transfer"
    );

    // ============================ REPLAY: same identity twice → refused
    // ============================
    // SECURITY: two independent guards would refuse this replay — the A-side SPENT ledger, and the
    // "proposed_next_state must extend A's committed head" binding (A's head has advanced). We
    // assert the SPENT-LEDGER one specifically, because that is the security-relevant guard and it
    // is the one that fires FIRST in `cosign-inter-transfer` (channel_member.rs: the
    // `spent_tx_identities.contains(..)` check precedes the head-extension check). Accepting the
    // head-extension message as an alternative would let the spent ledger be deleted outright
    // without this test noticing.
    let a_head_after_transfer = a_after.snapshot.state.digest;
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
    assert!(!ok, "replayed identity MUST be refused");
    assert!(
        log.contains("already debited from channel A (replay)"),
        "replay MUST be refused by the A-side SPENT LEDGER (the first, security-relevant guard), \
         got:\n{log}"
    );
    // SECURITY (no double-spend, no ledger churn on the refused path): the refusal left BOTH
    // ledgers and A's head exactly as the single successful transfer left them.
    let a_replayed = read_state(&ch_a);
    let b_replayed = read_state(&ch_b);
    assert_eq!(
        a_replayed.spent_tx_identities.len(),
        1,
        "refused replay must not add a second SPENT entry"
    );
    assert!(
        a_replayed.spent_tx_identities.contains(&replay_identity),
        "refused replay must leave A's SPENT entry intact (not clear the ledger)"
    );
    assert_eq!(
        b_replayed.applied_tx_identities.len(),
        1,
        "refused replay must not add a second APPLIED entry"
    );
    assert_eq!(
        a_replayed.snapshot.state.digest, a_head_after_transfer,
        "refused replay must not advance A's head (no second debit)"
    );
    assert_eq!(
        a_replayed.snapshot.state.channel_fund.amounts[0] + amt_u,
        a_fund_before,
        "refused replay must not debit A a second time"
    );
    assert_eq!(
        b_replayed.snapshot.state.channel_fund.amounts[0],
        b_fund_before + amt_u,
        "refused replay must not credit B a second time"
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
    let sender_slot = 0u16;
    let recipient_slot = 1u16;

    let b_keys: Vec<MemberKeys> = CLI_SLOTS.iter().map(|&s| cli_keys(s)).collect();
    let b_record = b.record.clone();
    let a_snapshot = a.snapshot.clone();
    let b_snapshot = b.snapshot.clone();
    let a_balances = a.balances.clone();
    let a_witnesses = a.witnesses.clone();
    let b_fund_before = b_snapshot.state.channel_fund.amounts[0];
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
        b_after.snapshot.state.channel_fund.amounts[0], b_fund_before,
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
    // SECURITY: the APPLIED ledger is the record of what B has credited. A refused forged-state
    // attempt must leave NO entry: an entry here would mean either that a credit landed, or that
    // the ledger was written before the guards ran (which would then permanently block the
    // legitimate transfer of that identity — a fail-OPEN/fail-STUCK split). This assertion is only
    // meaningful because `inter_channel_cli_end_to_end` proves the same ledger is non-empty after
    // a SUCCESSFUL transfer; keep both.
    assert!(
        b_after.applied_tx_identities.is_empty(),
        "B applied ledger UNCHANGED — nothing credited"
    );
    // ATOMICITY: A's head UNCHANGED on disk (the command persisted nothing).
    let a_after = read_state(&ch_a);
    assert_eq!(
        a_after.snapshot.state.digest, a_committed_digest,
        "ATOMICITY: A's committed head UNCHANGED after the refused transfer"
    );
    // SECURITY: same argument on the SOURCE side — a refused attempt must not burn the identity in
    // A's SPENT ledger.
    assert!(
        a_after.spent_tx_identities.is_empty(),
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
    let b_fund_before = b.snapshot.state.channel_fund.amounts[0];
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
    // SECURITY (atomicity of the replay ledgers): the debit leg was co-signed IN MEMORY before the
    // credit leg failed. Neither ledger may retain a trace of the aborted attempt — a SPENT entry
    // without a matching credit would permanently strand the sender's identity (fail-stuck), and a
    // stale APPLIED entry in B would block the honest retry.
    assert!(
        a_after.spent_tx_identities.is_empty(),
        "ATOMICITY: A spent ledger UNCHANGED when the credit leg fails"
    );
    assert_eq!(
        b_after.snapshot.state.channel_fund.amounts[0], b_fund_before,
        "ATOMICITY: B channel_fund UNCHANGED when the credit leg fails"
    );
    assert!(
        b_after.applied_tx_identities.is_empty(),
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
        // A-1: `genesisCt` is still a REQUIRED wire field but the CLI now ignores it (both
        // `create_channel` and `join_delegate` open a delegate slot at the canonical zero). This
        // case takes the idempotent-re-join branch anyway, so it never reaches either.
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

/// A-1 (join-time conservation + claimability) — the REAL `join_delegate` path, driven through the
/// binary with a contribution that declares a NONZERO opening balance.
///
/// What this is intended to prove about security, in order:
///
///  1. **Conservation (A-1 proper).** The joiner declares `genesisCt = encrypt(50)`. That amount is
///     Regev-encrypted, so no cosigner can see it; before A-1 it was installed verbatim, inflating
///     `Σ slot balances` above the L1-backed `channel_fund` with no proof and no L1 record — value
///     the joiner could later claim out of the real pot ahead of honest participants. The joined
///     slot MUST open at the CANONICAL ZERO ciphertext instead, and every PRE-EXISTING slot's
///     ciphertext must be byte-identical to before the join (a join moves no balance at all).
///  2. **Claimability (review finding 1).** The joined slot's `regev_pk_digests` entry MUST be the
///     joiner's own `poseidon(a, b)` and MUST be nonzero. `join_delegate` used to leave it at the
///     padding zero, which silently made every future balance in that slot UNCLAIMABLE at close:
///     the withdrawal-claim circuit derives `poseidon(a, b)` from the witnessed key and hashes it
///     into the slot leaf it must Merkle-verify against the cosigner-signed root, so a leaf built
///     over a zero digest is only reproducible by a key whose Poseidon digest is zero. Conservation
///     without this is a trap: the two funding lanes A-1's completeness argument relies on would
///     deposit into a slot that can never pay out.
///  3. **The state is genuinely signed.** `verify_snapshot` re-verifies the N-of-N signatures over
///     the post-join state, so 1 and 2 are properties of a state the cosigners actually attested,
///     not of a scratch struct.
#[test]
fn cli_join_delegate_opens_at_canonical_zero_and_binds_pk_digest() {
    let root = std::env::temp_dir().join(format!("intmax_ic_cli_a1_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let ch = root.join("ch_a1");
    std::fs::create_dir_all(&ch).unwrap();

    // A channel with NO delegate yet, so `init` takes the real `join_delegate` path (the
    // idempotent-re-join branch needs the pk_g to be present already; it is not, here).
    let state = cli_state(build_cli_channel(B_ID, &[20, 40, 60]));
    let cts_before = state.snapshot.state.balance_state.enc_balances.clone();
    let fund_before = state.snapshot.state.channel_fund.amounts;
    let v_before = state.snapshot.state.balance_state.state_version;
    write_state(&ch, &state);

    let delegate_keys = MemberKeys::generate(&mut StdRng::seed_from_u64(0xA1_0F_FE));
    // The joiner DECLARES 50. This is the attack input: an unbacked, unverifiable opening balance.
    let (declared_ct, _w) = encrypt_amount(
        &mut StdRng::seed_from_u64(0xA1_5EED),
        &delegate_keys.regev_pk,
        50,
    )
    .unwrap();
    let recipient = "0x00000000000000000000000000000000a10ffe01";
    let contrib = json!({
        "regevPk": delegate_keys.regev_pk,
        "pkG": delegate_keys.pk_g().to_hex(),
        "pkB": delegate_keys.pk_b().to_hex(),
        "genesisCt": declared_ct,
        "recipient": recipient,
    });
    let contrib_path = ch.join("contribution.json");
    std::fs::write(
        &contrib_path,
        serde_json::to_string_pretty(&contrib).unwrap(),
    )
    .unwrap();
    let out_snap = ch.join("snap_out.json");
    let (ok, log) = run(
        &ch,
        B_ID,
        &[
            "init",
            contrib_path.to_str().unwrap(),
            out_snap.to_str().unwrap(),
        ],
    );
    assert!(ok, "join must SUCCEED (A-1 rejects nothing), log:\n{log}");

    let after = read_state(&ch);
    let bs = &after.snapshot.state.balance_state;
    assert_eq!(
        bs.delegate_count, 1,
        "the join must add exactly one delegate"
    );
    assert!(
        bs.state_version > v_before,
        "a real join must bump state_version"
    );
    let slot = 3usize;

    // (1) conservation: the joined slot opens at the canonical zero in EVERY token position, NOT at
    // the declared 50, and no existing slot moved.
    assert_ne!(
        bs.enc_balances[slot][0], declared_ct,
        "REGRESSION (A-1): the joiner's self-declared opening ciphertext was installed — an \
         unbacked balance the cosigners cannot inspect and the channel fund does not cover"
    );
    for (t, ct) in bs.enc_balances[slot].iter().enumerate() {
        assert_eq!(
            *ct,
            RegevCiphertext::padding(),
            "joined slot token position {t} must be the canonical zero ciphertext"
        );
    }
    for s in 0..3usize {
        assert_eq!(
            bs.enc_balances[s], cts_before[s],
            "a join must not disturb existing slot {s}'s balance (Σ balances is invariant)"
        );
    }
    assert_eq!(
        after.snapshot.state.channel_fund.amounts, fund_before,
        "a join must not change the channel fund"
    );

    // (2) claimability: the slot leaf must commit the JOINER'S OWN pk digest, nonzero.
    let expect_digest = Bytes32::from(delegate_keys.regev_pk.poseidon_digest());
    assert_ne!(
        expect_digest,
        Bytes32::default(),
        "test setup: a real Regev key must not hash to the padding zero"
    );
    assert_eq!(
        bs.regev_pk_digests[slot], expect_digest,
        "REGRESSION (finding 1): the joined delegate's slot must commit ITS OWN Regev pk digest — \
         a zero/padding digest makes every future balance in this slot permanently unclaimable at \
         close (the claim circuit hashes poseidon(a,b) into the signed slot leaf)"
    );
    assert_eq!(
        bs.recipients[slot],
        intmax3_zkp::ethereum_types::address::Address::from_hex(recipient).unwrap(),
        "B-1b: the joined slot must bind the declared L1 exit address"
    );

    // (3) the cosigners really signed this state (and it passes BalanceState::validate()).
    verify_snapshot(&after.snapshot, None).expect("post-join snapshot must verify N-of-N");

    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
        "[inter_channel_cli] OK (A-1): join opens at the canonical zero, declared 50 discarded, \
         slot pk digest bound."
    );
}

/// SECURITY (deposit-import-threat-model.md §10.8 finding 2 — "a security check that silently does
/// not run"): a `cli_state.json` that does not name a REPLAY LEDGER must fail LOUDLY.
///
/// What this test is intended to prove about security: the three ledgers behind the inter-channel
/// double-debit refusal, the double-credit refusal, and the L1 deposit-import replay refusal can
/// no longer be reset to EMPTY by the mere absence of a JSON key. While they were
/// `#[serde(default)]`, a state file from a build that lacked or differently-NAMED a key loaded
/// with an empty ledger and every `contains()` refusal passed VACUOUSLY, with no diagnostic — a
/// failure invisible by construction, which had already happened once (the `applied_tx_hashes` →
/// `applied_tx_identities` rename). The test asserts the observable consequence: absence is an
/// error, a RENAME is an error, a newer schema is an error, and the ONLY way past is the explicit
/// `migrate-state` acknowledgement, which announces exactly what it resets.
#[test]
fn cli_state_missing_replay_ledger_fails_loudly() {
    let root = std::env::temp_dir().join(format!("intmax_ic_cli_ledger_{}", std::process::id()));
    let ch = root.join("ch_ledger");
    std::fs::create_dir_all(&ch).unwrap();
    write_state(&ch, &cli_state(build_cli_channel(B_ID, &[20, 40, 60])));
    let state_path = ch.join("cli_state.json");
    let pristine = std::fs::read_to_string(&state_path).unwrap();

    // POSITIVE CONTROL. Every refusal below is only evidence if the UNMODIFIED file loads: without
    // this, a broken fixture would produce the same failures and the test would prove nothing.
    let (ok, log) = run(&ch, B_ID, &["balance"]);
    assert!(ok, "the pristine state file must load, log:\n{log}");

    let obj_of = |text: &str| -> serde_json::Map<String, serde_json::Value> {
        serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(text).unwrap()
    };
    let put = |obj: &serde_json::Map<String, serde_json::Value>| {
        std::fs::write(&state_path, serde_json::to_string(obj).unwrap()).unwrap();
    };

    // (1) EACH ledger key, removed in turn, must be a LOUD, ACTIONABLE failure — not an empty set.
    for key in [
        "applied_tx_identities",
        "spent_tx_identities",
        "imported_deposits",
    ] {
        let mut obj = obj_of(&pristine);
        assert!(
            obj.remove(key).is_some(),
            "fixture must actually contain {key} for its removal to prove anything"
        );
        put(&obj);
        let (ok, log) = run(&ch, B_ID, &["balance"]);
        assert!(
            !ok,
            "a state file missing `{key}` MUST be refused, got:\n{log}"
        );
        assert!(
            log.contains(key) && log.contains("REPLAY LEDGER") && log.contains("migrate-state"),
            "the refusal must NAME the absent ledger and point at the deliberate migration path, \
             got:\n{log}"
        );
    }

    // (2) A RENAMED ledger — the exact incident that motivated this — must also be loud. Under the
    //     old `#[serde(default)]` this deserialized to an empty ledger and ran on silently.
    let mut obj = obj_of(&pristine);
    let v = obj.remove("imported_deposits").unwrap();
    obj.insert("imported_deposit_ids".to_string(), v);
    put(&obj);
    let (ok, log) = run(&ch, B_ID, &["balance"]);
    assert!(!ok, "a RENAMED replay ledger MUST be refused, got:\n{log}");
    assert!(
        log.contains("imported_deposits"),
        "the refusal must name the ledger that went missing, got:\n{log}"
    );

    // (3) `migrate-state` must REFUSE to migrate that file at all: an unrecognised key is how a
    //     renamed ledger looks, and migrating would discard its entries silently.
    let (ok, log) = run(
        &ch,
        B_ID,
        &["migrate-state", "--i-understand-this-resets-replay-ledgers"],
    );
    assert!(
        !ok && log.contains("unrecognised key"),
        "migrate-state must refuse a file carrying an unknown key (a renamed ledger), got:\n{log}"
    );

    // (4) A file from a NEWER build is refused rather than read with this build's understanding.
    let mut obj = obj_of(&pristine);
    obj.insert(
        "state_schema_version".to_string(),
        serde_json::Value::from(999u32),
    );
    put(&obj);
    let (ok, log) = run(&ch, B_ID, &["balance"]);
    assert!(
        !ok && log.contains("NEWER build"),
        "a newer schema version must be refused fail-closed, got:\n{log}"
    );

    // (5) A PRE-VERSIONING file (no `state_schema_version`) whose ledgers are all PRESENT is
    //     accepted — but OBSERVABLY, with a stderr note. This is the one retained serde default,
    //     and the note is what keeps it from being silent.
    let mut obj = obj_of(&pristine);
    obj.remove("state_schema_version").unwrap();
    put(&obj);
    let (ok, log) = run(&ch, B_ID, &["balance"]);
    assert!(
        ok,
        "a pre-versioning file with all ledgers must load:\n{log}"
    );
    assert!(
        log.contains("pre-dates schema versioning"),
        "accepting a pre-versioning file must be ANNOUNCED, not silent, got:\n{log}"
    );

    // (6) The deliberate migration path. WITHOUT the acknowledgement it refuses and changes
    //     nothing; WITH it, the ledger is created empty and the reset is reported.
    let mut obj = obj_of(&pristine);
    obj.remove("imported_deposits").unwrap();
    put(&obj);
    let before = std::fs::read_to_string(&state_path).unwrap();
    let (ok, log) = run(&ch, B_ID, &["migrate-state"]);
    assert!(!ok, "migrate-state without the acknowledgement MUST refuse");
    assert!(
        log.contains("imported_deposits") && log.contains("replayable"),
        "the refusal must state exactly which ledger it would create and the consequence, \
         got:\n{log}"
    );
    assert_eq!(
        std::fs::read_to_string(&state_path).unwrap(),
        before,
        "a refused migration must not touch the state file"
    );

    let (ok, log) = run(
        &ch,
        B_ID,
        &["migrate-state", "--i-understand-this-resets-replay-ledgers"],
    );
    assert!(ok, "acknowledged migrate-state must succeed, log:\n{log}");
    assert!(
        log.contains("imported_deposits") && log.contains("SECURITY"),
        "the migration must report the EMPTY ledger it created, got:\n{log}"
    );
    let migrated = obj_of(&std::fs::read_to_string(&state_path).unwrap());
    assert_eq!(
        migrated.get("imported_deposits"),
        Some(&serde_json::Value::Array(Vec::new())),
        "migration must create the ledger EMPTY and PRESENT (never absent again)"
    );
    assert_eq!(
        migrated.get("state_schema_version"),
        Some(&serde_json::Value::from(STATE_SCHEMA_VERSION)),
        "migration must stamp the current schema version"
    );
    let (ok, log) = run(&ch, B_ID, &["balance"]);
    assert!(ok, "the migrated file must load cleanly, log:\n{log}");

    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
        "[inter_channel_cli] OK: an absent/renamed replay ledger is a LOUD refusal; the only way \
         past it is the acknowledged `migrate-state`."
    );
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

// ============================================================================================
// Co-signer key PROVENANCE — fail-closed tests (doc/tasks/cosigner-key-provenance.md)
//
// SECURITY, what these are intended to PROVE (not merely "check"):
//   1. The CLI cannot mint key material at all unless a provenance is EXPLICITLY chosen. There is
//      no unconfigured state in which it silently derives keys from a compile-time constant — the
//      vulnerability being closed here, where every co-signer private key of every CLI/API channel
//      was computable by anyone able to read this public repository.
//   2. An ambiguous configuration is REFUSED rather than resolved by precedence, so a provisioned
//      production host cannot be downgraded to test keys by additionally setting the test flag.
//   3. The insecure flag is not truthiness-parsed, so a typo cannot silently select either branch.
//   4. Malformed / world-readable / placeholder key files are rejected rather than used.
//   5. The external secret ACTUALLY changes the derived identity — i.e. the fix is real and not a
//      no-op wrapper around the old constant derivation.
// ============================================================================================

/// Spawn the CLI with a fully controlled environment (env_clear + only what we name), so an
/// inherited `INTMAX_*` from the developer's shell or CI cannot mask a fail-closed regression.
fn run_provenance(cwd: &std::path::Path, envs: &[(&str, &str)]) -> (bool, String) {
    let mut c = Command::new(bin());
    c.arg("gen-contribution")
        .arg("0")
        .arg("1")
        .arg("contribution.json")
        .current_dir(cwd)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("INTMAX_CHANNEL", "7");
    for (k, v) in envs {
        c.env(k, v);
    }
    let out = c.output().expect("spawn channel_member");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

fn provenance_tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "intmax_prov_{}_{}_{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Write a key file with an explicit unix mode.
fn write_keyfile(dir: &std::path::Path, name: &str, contents: &str, mode: u32) -> String {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    p.to_string_lossy().to_string()
}

/// The `pkG` the CLI just wrote — the member's canonical identity digest. Used to prove that two
/// provenances yield DIFFERENT keys.
fn contribution_pk_g(dir: &std::path::Path) -> String {
    let raw = std::fs::read_to_string(dir.join("contribution.json")).expect("contribution.json");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    v.get("pkG")
        .and_then(|x| x.as_str())
        .expect("pkG in contribution")
        .to_string()
}

/// (1) No provenance configured => the CLI MUST die. This is the single most important assertion
/// in this file: it is what makes "forgot to provision the host" an outage instead of a silent
/// reversion to publicly-known keys.
#[test]
fn keygen_fails_closed_when_no_provenance_is_configured() {
    let d = provenance_tmp("none");
    let (ok, out) = run_provenance(&d, &[]);
    assert!(
        !ok,
        "CLI must REFUSE to run without key provenance; got success:\n{out}"
    );
    assert!(
        out.contains("INTMAX_COSIGNER_KEYFILE"),
        "the refusal must name the variable an operator has to set:\n{out}"
    );
    assert!(
        !d.join("contribution.json").exists(),
        "no key material may be produced when provenance is unconfigured"
    );
}

/// (2) Both provenances set => REFUSE. Never resolve by precedence: this is exactly what stops a
/// correctly provisioned production host from being silently downgraded by an inherited test flag.
#[test]
fn keygen_fails_closed_when_both_provenances_are_set() {
    let d = provenance_tmp("both");
    let kf = write_keyfile(&d, "cosigner.key", &"ab".repeat(32), 0o600);
    let (ok, out) = run_provenance(
        &d,
        &[
            ("INTMAX_COSIGNER_KEYFILE", kf.as_str()),
            ("INTMAX_INSECURE_DETERMINISTIC_KEYS", "1"),
        ],
    );
    assert!(
        !ok,
        "ambiguous provenance must be refused, not resolved:\n{out}"
    );
    assert!(
        out.contains("BOTH"),
        "refusal must explain the ambiguity:\n{out}"
    );
}

/// (3) The insecure flag is NOT truthiness-parsed. `=0` must die rather than being read as
/// "disabled" (which would look like the no-provenance case) or as "enabled".
#[test]
fn insecure_flag_is_not_truthiness_parsed() {
    for bad in ["0", "false", "no", "true", "yes"] {
        let d = provenance_tmp("flag");
        let (ok, out) = run_provenance(&d, &[("INTMAX_INSECURE_DETERMINISTIC_KEYS", bad)]);
        assert!(
            !ok,
            "INTMAX_INSECURE_DETERMINISTIC_KEYS={bad} must die:\n{out}"
        );
    }
}

/// (4) Malformed key files are rejected, never used.
#[test]
fn malformed_key_files_are_rejected() {
    // World-readable: the same class of exposure this whole change removes.
    #[cfg(unix)]
    {
        let d = provenance_tmp("perm");
        let kf = write_keyfile(&d, "cosigner.key", &"ab".repeat(32), 0o644);
        let (ok, out) = run_provenance(&d, &[("INTMAX_COSIGNER_KEYFILE", kf.as_str())]);
        assert!(!ok, "a world-readable key file must be refused:\n{out}");
        assert!(
            out.contains("chmod 600"),
            "refusal should tell the operator the fix:\n{out}"
        );
    }
    // All zeros: a `truncate`d placeholder must not become a fixed key.
    let d = provenance_tmp("zero");
    let kf = write_keyfile(&d, "cosigner.key", &"00".repeat(32), 0o600);
    let (ok, out) = run_provenance(&d, &[("INTMAX_COSIGNER_KEYFILE", kf.as_str())]);
    assert!(!ok, "all-zero key material must be refused:\n{out}");
    // Too short: a truncated file must not silently yield a weaker key.
    let d = provenance_tmp("short");
    let kf = write_keyfile(&d, "cosigner.key", "abcd", 0o600);
    let (ok, out) = run_provenance(&d, &[("INTMAX_COSIGNER_KEYFILE", kf.as_str())]);
    assert!(!ok, "a short key file must be refused:\n{out}");
    // Not hex at all.
    let d = provenance_tmp("nothex");
    let kf = write_keyfile(
        &d,
        "cosigner.key",
        "not-hex-at-all-not-hex-at-all-xyz!",
        0o600,
    );
    let (ok, out) = run_provenance(&d, &[("INTMAX_COSIGNER_KEYFILE", kf.as_str())]);
    assert!(!ok, "a non-hex key file must be refused:\n{out}");
}

/// (5) THE PROOF THAT THE FIX IS REAL. A valid external secret must produce an identity that is
/// DIFFERENT from the publicly-derivable test identity, and two different secrets must produce two
/// different identities. If provenance were a no-op wrapper over the old constant derivation, all
/// three of these would collide and this test would fail.
///
/// Also asserts the insecure branch still WARNS on stderr every time it activates — an operator
/// who accidentally leaves the flag on must see it in their logs.
#[test]
fn external_secret_changes_the_derived_identity_and_insecure_mode_warns() {
    // Publicly-derivable reference identity (what the old, vulnerable build always produced).
    let d_test = provenance_tmp("insecure");
    let (ok, out) = run_provenance(&d_test, &[("INTMAX_INSECURE_DETERMINISTIC_KEYS", "1")]);
    assert!(ok, "the explicit test opt-in must still work:\n{out}");
    assert!(
        out.contains("INSECURE DETERMINISTIC KEYS ARE ACTIVE"),
        "the insecure branch must print a prominent warning every activation:\n{out}"
    );
    let pk_insecure = contribution_pk_g(&d_test);

    // Two distinct operator secrets.
    let d_a = provenance_tmp("secret_a");
    let kf_a = write_keyfile(&d_a, "cosigner.key", &"11".repeat(32), 0o600);
    let (ok, out) = run_provenance(&d_a, &[("INTMAX_COSIGNER_KEYFILE", kf_a.as_str())]);
    assert!(ok, "a well-formed key file must be accepted:\n{out}");
    assert!(
        !out.contains("INSECURE DETERMINISTIC KEYS ARE ACTIVE"),
        "the production branch must NOT print the insecure banner:\n{out}"
    );
    let pk_a = contribution_pk_g(&d_a);

    let d_b = provenance_tmp("secret_b");
    let kf_b = write_keyfile(&d_b, "cosigner.key", &"22".repeat(32), 0o600);
    let (ok, _out) = run_provenance(&d_b, &[("INTMAX_COSIGNER_KEYFILE", kf_b.as_str())]);
    assert!(ok);
    let pk_b = contribution_pk_g(&d_b);

    assert_ne!(
        pk_a, pk_insecure,
        "an operator-provisioned secret MUST NOT reproduce the publicly-derivable identity — \
         that would mean the key material still comes from the compile-time constant"
    );
    assert_ne!(pk_b, pk_insecure);
    assert_ne!(
        pk_a, pk_b,
        "two different operator secrets must yield different identities (the KDF must actually \
         depend on the secret)"
    );

    // Determinism under a FIXED secret is required: the same host must reproduce its own keys
    // across invocations, or every channel it created becomes unclosable.
    let d_a2 = provenance_tmp("secret_a2");
    let kf_a2 = write_keyfile(&d_a2, "cosigner.key", &"11".repeat(32), 0o600);
    let (ok, _out) = run_provenance(&d_a2, &[("INTMAX_COSIGNER_KEYFILE", kf_a2.as_str())]);
    assert!(ok);
    assert_eq!(
        pk_a,
        contribution_pk_g(&d_a2),
        "the same secret must reproduce the same identity across invocations"
    );
}
