//! CLI companion for the browser wallet: runs the CO-SIGNING members so a full in-channel send can
//! complete end-to-end. Regev channel model, E-1 STARK at Production level.
//!
//! DELEGATE DEMO LAYOUT: slots 0,1,2 = three CLI-controlled CO-SIGNING MEMBERS; slot 3 = the browser,
//! a send-only DELEGATE (it has a balance + sends with its own BabyBear A11 hash-sig, but does NOT
//! co-sign channel state — the N-of-N is the three members). So `init` produces a FULLY-SIGNED
//! genesis (the 3 members sign; the delegate does not), and the browser imports it directly.
//!
//! State (`cli_state.json` in the cwd) stores only reproducible seeds + the public snapshot; the
//! controlled members' keys and their genesis balance witnesses are regenerated deterministically
//! each run (so nothing unserializable is persisted). Each CLI member sends at most once from its
//! fresh genesis balance, so no post-send witness ever needs reconstructing.
//!
//! Commands:
//!   init <browser_delegate_contribution.json> <out_signed_snapshot.json>
//!   add-genesis-sig <browser_member_sig.json> <out_snapshot.json>   (legacy member-mode; unused by the delegate demo)
//!   send <from_slot> <to_slot> <amount> <out_payload.json>
//!   cosign <payload_or_state.json> <out_state.json>
//!   finalize <fully_signed_state.json>
//!   balance

use std::{fs, process::exit};

use intmax3_zkp::{
    circuits::{
        balance::{
            balance_processor::BalanceProcessor,
            common::recipient::calculate_recipient_from_user_id, spend_circuit::SpendCircuit,
        },
        test_utils::{
            balance_witness_generator::{BalanceWitnessGenerator, ReceiveDepositData},
            block_witness_generator::{BlockWitnessGenerator, BlockWitnessGeneratorHandle},
        },
    },
    common::{
        channel::{ChannelRecord, ChannelState, MemberSignature},
        channel_id::ChannelId,
        salt::Salt,
    },
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{
        address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait as _,
    },
    regev::{RegevCiphertext, RegevPk, RegevSecurityLevel, encrypt_amount},
    utils::serialize::{deserialize_verifier_data, serialize_verifier_data},
    wallet_core::{
        BuiltSend, ChannelBalanceAttestation, ChannelSnapshot, MemberInfo, MemberKeys,
        RefreshPayload, SendPayload, add_signature, assemble_genesis_state_backed, build_record,
        build_send, decrypt_balance, sign_state_if_backed, verify_all_signatures,
        verify_refresh_transition, verify_send_transition, verify_snapshot,
    },
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{circuit_data::VerifierCircuitData, config::PoseidonGoldilocksConfig},
};
use rand010::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};

// Base-layer proof config (matches `BalanceProcessor` / `poseidon_sig::circuit`).
type BF = GoldilocksField;
type BC = PoseidonGoldilocksConfig;
const BD: usize = 2;

const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;
const STATE_FILE: &str = "cli_state.json";
const CHANNEL_ID: u32 = 7;
const BP_SLOT: u8 = 0;
// detail2 §F-1 deposit backing: produced ONCE by `setup-backing`, consumed by the co-sign gate.
const BACKING_FILE: &str = "channel_backing.json"; // settled_tx_chain / intmax_state_root / fund
const ATTESTATION_FILE: &str = "channel_attestation.bin"; // the channel's base-layer balance proof
const BALANCE_VD_FILE: &str = "balance_vd.bin"; // cached balance verifier data (the gate needs only this)
// Delegate demo: slots 0,1,2 = three CLI-controlled CO-SIGNING MEMBERS (with genesis balances);
// slot 3 = the browser, a send-only DELEGATE (delegate_count = 1).
const CLI_SLOTS: &[u8] = &[0, 1, 2];
const CLI_GENESIS: &[(u8, u64)] = &[(0, 40), (1, 30), (2, 20)];
const BROWSER_DELEGATE_SLOT: u8 = 3;
const DELEGATE_COUNT: u8 = 1;
// The first browser delegate's genesis allocation out of the deposited fund (so Σ balances == fund).
const DELEGATE_GENESIS: u64 = 50;

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
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserContribution {
    regev_pk: RegevPk,
    /// The browser member's Goldilocks signing public key `pk_g` (canonical Bytes32 hex, P4-2).
    pk_g: String,
    /// P3: the browser member's BabyBear hash-sig public key `pk_b` (canonical Bytes32 hex, A11).
    pk_b: String,
    genesis_ct: RegevCiphertext,
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    exit(1);
}

fn keys_for(seed: u64) -> MemberKeys {
    MemberKeys::generate(&mut StdRng::seed_from_u64(seed))
}

fn member_info_for(slot: u8, keys: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot,
        pk_g: keys.pk_g(),
        pk_b: keys.pk_b(),
        regev_pk: keys.regev_pk.clone(),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &str) -> T {
    let s = fs::read_to_string(path).unwrap_or_else(|e| die(format!("read {path}: {e}")));
    serde_json::from_str(&s).unwrap_or_else(|e| die(format!("parse {path}: {e}")))
}

fn write_json<T: Serialize>(path: &str, value: &T) {
    let s = serde_json::to_string_pretty(value).unwrap_or_else(|e| die(e));
    fs::write(path, s).unwrap_or_else(|e| die(format!("write {path}: {e}")));
}

fn load_state() -> CliState {
    read_json(STATE_FILE)
}
fn save_state(state: &CliState) {
    write_json(STATE_FILE, state);
}

/// Backed-genesis parameters produced once by `setup-backing` (detail2 §F-1).
#[derive(Serialize, Deserialize)]
struct ChannelBacking {
    /// hex of the deposit settle-history the channel's balance proof folded in (§F-1 reconciliation).
    settled_tx_chain: String,
    /// hex anchor of the channel fund to intmax state (close-time L1 check; NOT the §F-1 co-sign gate).
    intmax_state_root: String,
    /// the deposited native value backing the channel (== Σ genesis balances).
    fund: u64,
}

fn backing_exists() -> bool {
    std::path::Path::new(BACKING_FILE).exists()
        && std::path::Path::new(ATTESTATION_FILE).exists()
        && std::path::Path::new(BALANCE_VD_FILE).exists()
}

/// Load the cached deposit backing: the small `balance_vd` (the gate needs only this — not the
/// prover), the channel's balance-proof attestation, and the backed-genesis params.
fn load_backing() -> (VerifierCircuitData<BF, BC, BD>, ChannelBalanceAttestation, ChannelBacking) {
    if !backing_exists() {
        die("no deposit backing found: run `channel_member setup-backing` first (detail2 §F-1). \
             Refusing to operate an unbacked channel.");
    }
    let vd_bytes =
        fs::read(BALANCE_VD_FILE).unwrap_or_else(|e| die(format!("read {BALANCE_VD_FILE}: {e}")));
    let balance_vd = deserialize_verifier_data::<BF, BC, BD>(&vd_bytes)
        .unwrap_or_else(|e| die(format!("deserialize balance_vd: {e}")));
    let proof =
        fs::read(ATTESTATION_FILE).unwrap_or_else(|e| die(format!("read {ATTESTATION_FILE}: {e}")));
    let backing: ChannelBacking = read_json(BACKING_FILE);
    (balance_vd, ChannelBalanceAttestation { balance_proof: proof }, backing)
}

/// ONE-TIME setup: fund the channel with a REAL L1 deposit and cache its base-layer balance proof as
/// the channel's deposit backing (detail2 §F-1). Builds the `BalanceProcessor` (~25s), proves the
/// deposit, and writes the attestation + verifier data + backed-genesis params. Run BEFORE `init`.
/// `setup-backing [fund]` (default = Σ CLI member genesis balances).
fn cmd_setup_backing(args: &[String]) {
    use rand::{SeedableRng as _, rngs::StdRng as DepRng};
    let fund: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        CLI_GENESIS.iter().map(|(_, a)| *a).sum::<u64>() + DELEGATE_GENESIS
    });

    eprintln!("setup-backing: building the balance prover (one-time, ~25s)…");
    let spend = SpendCircuit::<BF, BC, BD>::new();
    let bp = BalanceProcessor::<BF, BC, BD>::new(&spend.data.verifier_data());
    let bwgen = BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&[1, 4, 512]));

    let mut rng = DepRng::seed_from_u64(0x00DE_C0DE ^ CHANNEL_ID as u64);
    let channel_id = ChannelId::new(CHANNEL_ID as u64).unwrap_or_else(|e| die(format!("{e:?}")));
    let salt = Salt::rand(&mut rng);
    let mut bwg = BalanceWitnessGenerator::new(channel_id, salt, bwgen.clone(), &bp)
        .unwrap_or_else(|e| die(format!("balance witness generator: {e:?}")));

    let deposit_salt = Salt::rand(&mut rng);
    let recipient = calculate_recipient_from_user_id(channel_id, deposit_salt);
    bwgen
        .borrow_mut()
        .add_deposit(
            Address::rand(&mut rng),
            recipient,
            0,
            U256::from(fund.min(u32::MAX as u64) as u32),
            Bytes32::default(),
        )
        .unwrap_or_else(|e| die(format!("queue deposit: {e:?}")));
    bwgen
        .borrow_mut()
        .add_block(0, &[], 0, Bytes32::default())
        .unwrap_or_else(|e| die(format!("apply deposit block: {e:?}")));

    let dw = bwg
        .receive_deposit_witness(&ReceiveDepositData { receiver: recipient, deposit_salt })
        .unwrap_or_else(|e| die(format!("receive deposit witness: {e:?}")));
    eprintln!("setup-backing: proving the deposit…");
    let proof = bp
        .prove_receive_deposit(&dw)
        .unwrap_or_else(|e| die(format!("prove deposit: {e:?}")));
    bwg.commit_receive_deposit(&proof, &dw)
        .unwrap_or_else(|e| die(format!("commit deposit: {e:?}")));
    let pis = bwg.get_public_inputs().unwrap_or_else(|e| die(format!("balance pis: {e:?}")));

    fs::write(ATTESTATION_FILE, proof.to_bytes())
        .unwrap_or_else(|e| die(format!("write {ATTESTATION_FILE}: {e}")));
    let vd_bytes = serialize_verifier_data(&bp.balance_vd())
        .unwrap_or_else(|e| die(format!("serialize balance_vd: {e}")));
    fs::write(BALANCE_VD_FILE, vd_bytes).unwrap_or_else(|e| die(format!("write {BALANCE_VD_FILE}: {e}")));
    write_json(
        BACKING_FILE,
        &ChannelBacking {
            settled_tx_chain: pis.settled_tx_chain.to_hex(),
            // L1-close anchor (registration-time procedure is detail2 §K-4, open); NOT the §F-1 gate.
            intmax_state_root: Bytes32::default().to_hex(),
            fund,
        },
    );
    println!(
        "setup-backing OK: deposited {fund} to channel {CHANNEL_ID}; settled_tx_chain={}. Now run `init`.",
        pis.settled_tx_chain.to_hex()
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    match cmd {
        "setup-backing" => cmd_setup_backing(&args),
        "init" => cmd_init(&args),
        "gen-contribution" => cmd_gen_contribution(&args), // dev/test: simulate a browser delegate
        "add-genesis-sig" => cmd_add_genesis_sig(&args),
        "send" => cmd_send(&args),
        "cosign" => cmd_cosign(&args),
        "cosign-refresh" => cmd_cosign_refresh(&args),
        "finalize" => cmd_finalize(&args),
        "balance" => cmd_balance(),
        _ => {
            eprintln!(
                "usage: channel_member <setup-backing|init|add-genesis-sig|send|cosign|finalize|balance> ..."
            );
            exit(2);
        }
    }
}

/// `init` = CREATE-OR-JOIN. The first call CREATES the channel (3 members + this delegate at slot 3,
/// genesis v0). Each later call JOINS the existing channel as a NEW delegate at the next free slot —
/// a state-PRESERVING membership add: the CURRENT balances and any sends already made are kept, the
/// new delegate's slot is added, `state_version` is bumped, and the 3 members re-sign. So joining
/// AFTER sends does NOT wipe them, and multiple browsers are DISTINCT delegates (slots 3,4,5,…) in
/// the SAME channel.
fn cmd_init(args: &[String]) {
    let contrib_path = args.get(1).unwrap_or_else(|| die("init needs <browser_contribution.json>"));
    let out_path = args.get(2).map(String::as_str).unwrap_or("channel_snapshot.json");
    let contrib: BrowserContribution = read_json(contrib_path);
    let new_delegate = MemberInfo {
        slot: 0, // assigned by create/join
        pk_g: Bytes32::from_hex(&contrib.pk_g)
            .unwrap_or_else(|e| die(format!("parse browser pk_g: {e:?}"))),
        pk_b: Bytes32::from_hex(&contrib.pk_b)
            .unwrap_or_else(|e| die(format!("parse browser pk_b: {e:?}"))),
        regev_pk: contrib.regev_pk.clone(),
    };
    let new_ct = contrib.genesis_ct.clone();

    let (record, state, members, controlled, slot) = if std::path::Path::new(STATE_FILE).exists() {
        join_delegate(new_delegate, new_ct)
    } else {
        create_channel(new_delegate, new_ct)
    };

    verify_all_signatures(&record, &members, &state)
        .unwrap_or_else(|e| die(format!("state not fully/validly member-signed: {e}")));
    let snapshot = ChannelSnapshot { record, state, members };
    let dc = snapshot.record.delegate_count;
    let v = snapshot.state.balance_state.state_version;
    save_state(&CliState { controlled, snapshot: snapshot.clone() });
    write_json(out_path, &snapshot);
    println!("delegate at slot {slot} (member_count=3, delegate_count={dc}, state_version={v}). Browser: wallet_import_channel(<{out_path}>).");
}

/// The three CLI co-signing members (deterministic keys + genesis balances).
fn cli_members() -> (Vec<MemberInfo>, Vec<(u8, RegevCiphertext)>, Vec<ControlledMember>) {
    let mut members = Vec::new();
    let mut enc = Vec::new();
    let mut controlled = Vec::new();
    for &slot in CLI_SLOTS {
        let keygen_seed = 0xC1_0000 + slot as u64;
        let keys = keys_for(keygen_seed);
        members.push(member_info_for(slot, &keys));
        let amount = CLI_GENESIS.iter().find(|(s, _)| *s == slot).map(|(_, a)| *a).unwrap();
        let balance_seed = 0xBA_0000 + slot as u64;
        let (ct, _w) = encrypt_amount(&mut StdRng::seed_from_u64(balance_seed), &keys.regev_pk, amount)
            .unwrap_or_else(|e| die(e));
        enc.push((slot, ct));
        controlled.push(ControlledMember { slot, keygen_seed, balance_amount: amount, balance_seed, has_witness: true });
    }
    (members, enc, controlled)
}

/// CREATE the channel: 3 members + this delegate at slot 3, genesis (v0), 3 members sign.
fn create_channel(
    mut nd: MemberInfo,
    new_ct: RegevCiphertext,
) -> (ChannelRecord, ChannelState, Vec<MemberInfo>, Vec<ControlledMember>, u8) {
    let _ = DELEGATE_COUNT; // (delegate_count is now dynamic; first channel has 1)
    nd.slot = BROWSER_DELEGATE_SLOT;
    let (mut members, mut enc, controlled) = cli_members();
    members.push(nd);
    enc.push((BROWSER_DELEGATE_SLOT, new_ct));
    members.sort_by_key(|m| m.slot);
    let record = build_record(CHANNEL_ID, &members, BP_SLOT, 1).unwrap_or_else(|e| die(e));
    enc.sort_by_key(|(s, _)| *s);
    let encs: Vec<RegevCiphertext> = enc.into_iter().map(|(_, c)| c).collect();

    // detail2 §F-1: the genesis is funded by the REAL L1 deposit backing (no self-minted fund).
    // `fund` == the deposited native value; `settled_tx_chain` ties the state to that deposit so the
    // co-sign gate reconciles. Σ(genesis balances) == fund (CLI members + delegate allocation).
    let (balance_vd, att, backing) = load_backing();
    let settled = Bytes32::from_hex(&backing.settled_tx_chain)
        .unwrap_or_else(|e| die(format!("backing settled_tx_chain: {e:?}")));
    let intmax_root = Bytes32::from_hex(&backing.intmax_state_root)
        .unwrap_or_else(|e| die(format!("backing intmax_state_root: {e:?}")));
    let mut state =
        assemble_genesis_state_backed(&record, &encs, backing.fund, settled, intmax_root)
            .unwrap_or_else(|e| die(e));

    // CHECK-AND-SIGN (detail2 §3.1, atomic): each member signs the genesis ONLY IF its
    // settled_tx_chain matches the held deposit backing — fail-closed otherwise (never signs).
    for c in &controlled {
        let sig = sign_state_if_backed(
            &keys_for(c.keygen_seed),
            c.slot,
            &record,
            &state,
            &att,
            &balance_vd,
        )
        .unwrap_or_else(|e| die(format!("REFUSING TO SIGN genesis — {e}")));
        add_signature(&mut state, sig);
    }
    (record, state, members, controlled, BROWSER_DELEGATE_SLOT)
}

/// JOIN the existing channel as a NEW delegate, PRESERVING the current state (balances + sends). The
/// new delegate's slot is added with its genesis ciphertext, `delegate_count` and `state_version` are
/// bumped, and the 3 members re-sign the new state. Existing delegates' ciphertexts are untouched, so
/// their browser send-witnesses stay valid.
fn join_delegate(
    mut nd: MemberInfo,
    new_ct: RegevCiphertext,
) -> (ChannelRecord, ChannelState, Vec<MemberInfo>, Vec<ControlledMember>, u8) {
    let prev = load_state();
    let existing = prev.snapshot.members.iter().filter(|m| m.slot >= BROWSER_DELEGATE_SLOT).count();
    let new_slot = BROWSER_DELEGATE_SLOT + existing as u8;
    if CLI_SLOTS.len() + existing + 1 > MAX_CHANNEL_MEMBERS {
        die("channel is full (member_count + delegate_count would exceed MAX_CHANNEL_MEMBERS)");
    }
    nd.slot = new_slot;
    let mut members = prev.snapshot.members.clone();
    members.push(nd);
    members.sort_by_key(|m| m.slot);
    let new_delegate_count = (existing + 1) as u8;
    let record = build_record(CHANNEL_ID, &members, BP_SLOT, new_delegate_count).unwrap_or_else(|e| die(e));

    // Membership add: keep the CURRENT balance state (preserving every slot's ciphertext + any sends),
    // add the new delegate's slot, bump delegate_count + state_version, clear sigs, members re-sign.
    let mut state = prev.snapshot.state.clone();
    state.prev_digest = state.digest;
    state.balance_state.delegate_count = new_delegate_count;
    state.balance_state.enc_balances[new_slot as usize] = new_ct;
    state.balance_state.pending_adds[new_slot as usize] = 0;
    state.balance_state.state_version += 1;
    state.member_signatures = Vec::new();
    let mut state = state.with_computed_digest();
    // CHECK-AND-SIGN (detail2 §3.1): a delegate join does not change settled_tx_chain, so each
    // member re-signs only if the existing deposit backing still reconciles. Fail-closed.
    let (balance_vd, att, _backing) = load_backing();
    for c in &prev.controlled {
        let sig = sign_state_if_backed(
            &keys_for(c.keygen_seed),
            c.slot,
            &record,
            &state,
            &att,
            &balance_vd,
        )
        .unwrap_or_else(|e| die(format!("REFUSING TO SIGN — {e}")));
        add_signature(&mut state, sig);
    }
    (record, state, members, prev.controlled, new_slot)
}

/// DEV/TEST ONLY: simulate the browser's `wallet_genesis_contribution` — generate a delegate's keys
/// + encrypt its opening balance, and emit a `BrowserContribution` JSON. Lets the relay flow be
/// driven headlessly. `gen-contribution <balance> <seed> <out.json>`.
fn cmd_gen_contribution(args: &[String]) {
    let balance: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(50);
    let seed: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let out = args.get(3).map(String::as_str).unwrap_or("contribution.json");
    let keys = MemberKeys::generate(&mut StdRng::seed_from_u64(seed));
    let (ct, _w) =
        encrypt_amount(&mut StdRng::seed_from_u64(seed ^ 0xA11CE), &keys.regev_pk, balance)
            .unwrap_or_else(|e| die(e));
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Contribution {
        regev_pk: RegevPk,
        pk_g: String,
        pk_b: String,
        genesis_ct: RegevCiphertext,
    }
    write_json(
        out,
        &Contribution {
            regev_pk: keys.regev_pk.clone(),
            pk_g: keys.pk_g().to_hex(),
            pk_b: keys.pk_b().to_hex(),
            genesis_ct: ct,
        },
    );
    println!("wrote {out} (delegate balance {balance}, seed {seed})");
}

fn cmd_add_genesis_sig(args: &[String]) {
    let sig_path = args.get(1).unwrap_or_else(|| die("needs <browser_sig.json>"));
    let out_path = args.get(2).map(String::as_str).unwrap_or("channel_snapshot.json");
    let sig: MemberSignature = read_json(sig_path);
    let mut state = load_state();
    add_signature(&mut state.snapshot.state, sig);
    verify_all_signatures(&state.snapshot.record, &state.snapshot.members, &state.snapshot.state)
        .unwrap_or_else(|e| die(format!("genesis not fully/validly signed: {e}")));
    save_state(&state);
    write_json(out_path, &state.snapshot);
    println!("genesis fully signed → {out_path}. Browser: wallet_import_channel(<{out_path}>).");
}

fn cmd_send(args: &[String]) {
    let from: u8 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or_else(|| die("send <from> <to> <amount> <out>"));
    let to: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or_else(|| die("bad <to>"));
    let amount: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or_else(|| die("bad <amount>"));
    let out_path = args.get(4).map(String::as_str).unwrap_or("payload.json");
    let mut state = load_state();

    let cm = state
        .controlled
        .iter()
        .find(|c| c.slot == from && c.has_witness)
        .unwrap_or_else(|| die(format!("slot {from} is not a CLI member with a spendable balance")));
    let keys = keys_for(cm.keygen_seed);
    // Reconstruct the sender's current balance witness deterministically.
    let (_ct, witness) =
        encrypt_amount(&mut StdRng::seed_from_u64(cm.balance_seed), &keys.regev_pk, cm.balance_amount)
            .unwrap_or_else(|e| die(e));
    let before_amount = cm.balance_amount;

    let mut rng = StdRng::seed_from_u64(0x5E_0000 + from as u64);
    let nonce = intmax3_zkp::ethereum_types::bytes32::Bytes32::default();
    let BuiltSend { payload, new_balance, .. } = build_send(
        &keys, &state.snapshot, from, to, amount, before_amount, &witness, nonce, LEVEL, &mut rng,
    )
    .unwrap_or_else(|e| die(e));

    // Mark this member as having spent (no reproducible witness for its new ciphertext; it will
    // not send again in this demo). Balance commits on finalize.
    if let Some(c) = state.controlled.iter_mut().find(|c| c.slot == from) {
        c.has_witness = false;
        c.balance_amount = new_balance;
    }
    save_state(&state);
    write_json(out_path, &payload);
    println!("built send {from}→{to} amount {amount} → {out_path} (proof generated). Now collect co-signatures.");
}

fn cmd_cosign(args: &[String]) {
    let in_path = args.get(1).unwrap_or_else(|| die("cosign <payload_or_state.json> <out>"));
    let out_path = args.get(2).map(String::as_str).unwrap_or("cosigned_state.json");
    let mut state = load_state();

    // SECURITY: require a SendPayload (which carries the ChannelTx + E-1 proof) so EVERY cosigner
    // re-verifies the transition before signing — never sign a bare state we did not validate.
    let payload: SendPayload = read_json(in_path);
    let mut next_state = payload.proposed_next_state.clone();

    if next_state.prev_digest != state.snapshot.state.digest {
        die("payload does not extend the current head");
    }

    // Verify the transition + E-1 proof once (with recipient decryption if a CLI slot receives).
    let recipient_is_cli = state.controlled.iter().find(|c| c.slot == payload.recipient_index);
    let (sk, expected) = if let Some(c) = recipient_is_cli {
        let keys = keys_for(c.keygen_seed);
        let amt = intmax3_zkp::regev::decrypt_amount(&keys.regev_sk, &payload.channel_tx.enc_amount)
            .unwrap_or_else(|e| die(e));
        (Some(keys.regev_sk), Some(amt))
    } else {
        (None, None)
    };
    verify_send_transition(
        &state.snapshot.state,
        &state.snapshot.record,
        &payload,
        LEVEL,
        sk.as_ref(),
        expected,
    )
    .unwrap_or_else(|e| die(format!("transition invalid: {e}")));

    // CHECK-AND-SIGN (detail2 §3.1): each member signs the next state ONLY IF its settled_tx_chain
    // matches the held intmax balance backing (invariant across in-channel sends, so the genesis
    // attestation backs every in-channel state). Fail-closed — refuse otherwise.
    let (balance_vd, att, _backing) = load_backing();
    for c in &state.controlled {
        let already = next_state.member_signatures.iter().any(|s| s.member_slot == c.slot);
        if already {
            continue;
        }
        let sig = sign_state_if_backed(
            &keys_for(c.keygen_seed),
            c.slot,
            &state.snapshot.record,
            &next_state,
            &att,
            &balance_vd,
        )
        .unwrap_or_else(|e| die(format!("REFUSING TO SIGN — {e}")));
        add_signature(&mut next_state, sig);
    }
    write_json(out_path, &next_state);

    let signed: Vec<u8> = next_state.member_signatures.iter().map(|s| s.member_slot).collect();
    println!("co-signed → {out_path}. Signatures now present for slots {signed:?} (need 0..{}).",
        state.snapshot.record.member_count);

    // DEMO: advance this CLI member's stored head to the just-cosigned state so SEQUENTIAL sends
    // work. Without this, cli_state stays at the genesis head and the 2nd send fails "payload does
    // not extend the current head". The browser finalizes exactly what we cosigned in this single
    // relay flow, so advancing optimistically is safe here; a real multi-party deployment would
    // advance only on confirmed finalization.
    state.snapshot.state = next_state;
    save_state(&state);
    // HEAD SYNC: publish the advanced head so `/api/snapshot` (the browsers' re-import source) is
    // current — otherwise a later re-import returns the stale init snapshot and the next send fails
    // "payload does not extend the current head".
    write_json("channel_snapshot.json", &state.snapshot);
}

/// Co-sign a balance-REFRESH payload (a delegate/member re-encrypting its own slot to clean digits so
/// it can send again after receiving). Each member re-verifies the value-preserving refresh transition
/// before signing; the head advances + is published exactly like cmd_cosign.
fn cmd_cosign_refresh(args: &[String]) {
    let in_path = args.get(1).unwrap_or_else(|| die("cosign-refresh <payload.json> <out>"));
    let out_path = args.get(2).map(String::as_str).unwrap_or("cosigned_state.json");
    let mut state = load_state();
    let payload: RefreshPayload = read_json(in_path);
    let mut next_state = payload.proposed_next_state.clone();
    if next_state.prev_digest != state.snapshot.state.digest {
        die("payload does not extend the current head");
    }
    verify_refresh_transition(&state.snapshot.state, &state.snapshot.record, &payload, LEVEL)
        .unwrap_or_else(|e| die(format!("refresh transition invalid: {e}")));
    // CHECK-AND-SIGN (detail2 §3.1): a balance-refresh preserves settled_tx_chain, so each member
    // signs only if the deposit backing still reconciles. Fail-closed.
    let (balance_vd, att, _backing) = load_backing();
    for c in &state.controlled {
        if next_state.member_signatures.iter().any(|s| s.member_slot == c.slot) {
            continue;
        }
        let sig = sign_state_if_backed(
            &keys_for(c.keygen_seed),
            c.slot,
            &state.snapshot.record,
            &next_state,
            &att,
            &balance_vd,
        )
        .unwrap_or_else(|e| die(format!("REFUSING TO SIGN — {e}")));
        add_signature(&mut next_state, sig);
    }
    write_json(out_path, &next_state);
    state.snapshot.state = next_state;
    save_state(&state);
    write_json("channel_snapshot.json", &state.snapshot);
    println!("balance-refresh co-signed for slot {} (head advanced).", payload.member_index);
}

fn cmd_finalize(args: &[String]) {
    let in_path = args.get(1).unwrap_or_else(|| die("finalize <fully_signed_state.json>"));
    let next_state: ChannelState = read_json(in_path);
    let mut state = load_state();
    if next_state.prev_digest != state.snapshot.state.digest {
        die("finalized state does not extend the current head");
    }
    verify_all_signatures(&state.snapshot.record, &state.snapshot.members, &next_state)
        .unwrap_or_else(|e| die(format!("not fully/validly signed: {e}")));
    state.snapshot.state = next_state;
    verify_snapshot(&state.snapshot, None).unwrap_or_else(|e| die(e));
    // Refresh controlled balances from the new state (recipients gain; senders already updated).
    for c in state.controlled.iter_mut() {
        let keys = keys_for(c.keygen_seed);
        if let Ok(bal) = decrypt_balance(&keys, &state.snapshot, c.slot) {
            if bal != c.balance_amount {
                // A receive (homomorphic add): balance changed, witness no longer reproducible.
                c.balance_amount = bal;
                c.has_witness = false;
            }
        }
    }
    save_state(&state);
    println!("finalized. New state_version = {}.", state.snapshot.state.balance_state.state_version);
    cmd_balance();
}

fn cmd_balance() {
    let state = load_state();
    for c in &state.controlled {
        let keys = keys_for(c.keygen_seed);
        match decrypt_balance(&keys, &state.snapshot, c.slot) {
            Ok(bal) => println!("  slot {} balance = {} (can_send={})", c.slot, bal, c.has_witness),
            Err(e) => println!("  slot {} balance = <decrypt error: {e}>", c.slot),
        }
    }
}
