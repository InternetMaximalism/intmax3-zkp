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
    common::channel::{ChannelState, MemberSignature},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
    regev::{RegevCiphertext, RegevPk, RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        BuiltSend, ChannelSnapshot, MemberInfo, MemberKeys, SendPayload, add_signature,
        assemble_genesis_state, build_record, build_send, decrypt_balance, sign_state,
        verify_all_signatures, verify_send_transition, verify_snapshot,
    },
};
use rand010::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};

const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;
const STATE_FILE: &str = "cli_state.json";
const CHANNEL_ID: u32 = 7;
const BP_SLOT: u8 = 0;
// Delegate demo: slots 0,1,2 = three CLI-controlled CO-SIGNING MEMBERS (with genesis balances);
// slot 3 = the browser, a send-only DELEGATE (delegate_count = 1).
const CLI_SLOTS: &[u8] = &[0, 1, 2];
const CLI_GENESIS: &[(u8, u64)] = &[(0, 40), (1, 30), (2, 20)];
const BROWSER_DELEGATE_SLOT: u8 = 3;
const DELEGATE_COUNT: u8 = 1;

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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    match cmd {
        "init" => cmd_init(&args),
        "add-genesis-sig" => cmd_add_genesis_sig(&args),
        "send" => cmd_send(&args),
        "cosign" => cmd_cosign(&args),
        "finalize" => cmd_finalize(&args),
        "balance" => cmd_balance(),
        _ => {
            eprintln!(
                "usage: channel_member <init|add-genesis-sig|send|cosign|finalize|balance> ..."
            );
            exit(2);
        }
    }
}

fn cmd_init(args: &[String]) {
    let contrib_path = args.get(1).unwrap_or_else(|| die("init needs <browser_contribution.json>"));
    // The browser is the DELEGATE, so init produces the FULLY-SIGNED snapshot directly (the delegate
    // does not sign the genesis — only the members do).
    let out_path = args.get(2).map(String::as_str).unwrap_or("channel_snapshot.json");
    let contrib: BrowserContribution = read_json(contrib_path);

    // Browser = the send-only DELEGATE at the highest active slot; CLI slots = co-signing members.
    let mut members = vec![MemberInfo {
        slot: BROWSER_DELEGATE_SLOT,
        pk_g: Bytes32::from_hex(&contrib.pk_g)
            .unwrap_or_else(|e| die(format!("parse browser pk_g: {e:?}"))),
        pk_b: Bytes32::from_hex(&contrib.pk_b)
            .unwrap_or_else(|e| die(format!("parse browser pk_b: {e:?}"))),
        regev_pk: contrib.regev_pk.clone(),
    }];
    let mut controlled = Vec::new();
    let mut enc_active: Vec<(u8, RegevCiphertext)> =
        vec![(BROWSER_DELEGATE_SLOT, contrib.genesis_ct.clone())];

    for &slot in CLI_SLOTS {
        let keygen_seed = 0xC1_0000 + slot as u64;
        let keys = keys_for(keygen_seed);
        members.push(member_info_for(slot, &keys));
        let amount = CLI_GENESIS.iter().find(|(s, _)| *s == slot).map(|(_, a)| *a).unwrap();
        let balance_seed = 0xBA_0000 + slot as u64;
        let (ct, _w) = encrypt_amount(&mut StdRng::seed_from_u64(balance_seed), &keys.regev_pk, amount)
            .unwrap_or_else(|e| die(e));
        enc_active.push((slot, ct));
        controlled.push(ControlledMember {
            slot,
            keygen_seed,
            balance_amount: amount,
            balance_seed,
            has_witness: true,
        });
    }

    members.sort_by_key(|m| m.slot);
    // 3 co-signing members (CLI_SLOTS) + 1 delegate (browser): member_count = 3, delegate_count = 1.
    let record = build_record(CHANNEL_ID, &members, BP_SLOT, DELEGATE_COUNT).unwrap_or_else(|e| die(e));
    enc_active.sort_by_key(|(s, _)| *s);
    let enc: Vec<RegevCiphertext> = enc_active.into_iter().map(|(_, c)| c).collect();
    let fund: u64 = CLI_GENESIS.iter().map(|(_, a)| *a).sum::<u64>() + 50; // +delegate (unknown plaintext; informational)
    let mut genesis = assemble_genesis_state(&record, &enc, fund).unwrap_or_else(|e| die(e));

    // The three MEMBERS co-sign the genesis (N-of-N). The DELEGATE (browser) does NOT sign state.
    for c in &controlled {
        let keys = keys_for(c.keygen_seed);
        let sig = sign_state(&keys, c.slot, &genesis).unwrap_or_else(|e| die(e));
        add_signature(&mut genesis, sig);
    }
    // Genesis is now fully member-signed; the delegate's slot is not a co-signer.
    verify_all_signatures(&record, &members, &genesis)
        .unwrap_or_else(|e| die(format!("genesis not fully/validly member-signed: {e}")));

    let snapshot = ChannelSnapshot {
        record,
        state: genesis,
        members,
    };
    save_state(&CliState { controlled, snapshot: snapshot.clone() });
    // Hand the FULLY-SIGNED snapshot to the browser to import as the delegate (no genesis sig needed).
    write_json(out_path, &snapshot);
    println!(
        "channel initialized (3 members signed genesis; browser is the delegate at slot {BROWSER_DELEGATE_SLOT}). \
         Browser: wallet_import_channel(<{out_path}>)."
    );
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

    // Add signatures for every controlled slot not yet signed.
    for c in &state.controlled {
        let already = next_state.member_signatures.iter().any(|s| s.member_slot == c.slot);
        if already {
            continue;
        }
        let keys = keys_for(c.keygen_seed);
        let sig = sign_state(&keys, c.slot, &next_state).unwrap_or_else(|e| die(e));
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
