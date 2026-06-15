//! Native end-to-end test of the wallet core: a 2-member channel where member 0 ("browser") and
//! member 1 ("CLI") each hold their own keys, build a genesis, then member 0 sends to member 1 and
//! the transfer is co-signed and verified — exercising the same code paths the wasm wallet + CLI
//! companion use. Runs the real E-1 STARK at `Test` level (fast).
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    ethereum_types::bytes32::Bytes32,
    regev::{
        RegevSecurityLevel, encrypt_amount,
        hash_sig::{BabyBearSecretKey, decompose_digest_to_limbs},
        prove_hash_sig,
    },
    wallet_core::{
        BuiltSend, ChannelSnapshot, MemberInfo, MemberKeys, add_signature, assemble_genesis_state,
        build_record, build_send, decrypt_balance, sign_state, verify_all_signatures,
        verify_send_transition, verify_snapshot,
    },
};
use rand010::{SeedableRng, rngs::StdRng};

const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Test;

fn member_info(slot: u8, keys: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot,
        pk_g: keys.pk_g(),
        pk_b: keys.pk_b(),
        regev_pk: keys.regev_pk.clone(),
    }
}

#[test]
fn wallet_core_in_channel_send_receive() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);

    // Two members, each with their own keys.
    let m0 = MemberKeys::generate(&mut rng); // "browser"
    let m1 = MemberKeys::generate(&mut rng); // "CLI"
    let members = vec![member_info(0, &m0), member_info(1, &m1)];

    let record = build_record(5, &members, 0).expect("record");

    // Each member encrypts their own genesis balance and KEEPS the witness.
    let (bal0, bal1) = (50u64, 30u64);
    let (ct0, w0) = encrypt_amount(&mut rng, &m0.regev_pk, bal0).expect("enc0");
    let (ct1, _w1) = encrypt_amount(&mut rng, &m1.regev_pk, bal1).expect("enc1");
    let mut genesis = assemble_genesis_state(&record, &[ct0, ct1], bal0 + bal1).expect("genesis");

    // Both members co-sign the genesis.
    let g0 = sign_state(&m0, 0, &genesis).expect("sign g0");
    add_signature(&mut genesis, g0);
    let g1 = sign_state(&m1, 1, &genesis).expect("sign g1");
    add_signature(&mut genesis, g1);

    let snapshot = ChannelSnapshot {
        record: record.clone(),
        state: genesis,
        members: members.clone(),
    };

    // Both members fully verify the signed genesis (real SingleSig proofs, roots, own-slot decrypt).
    verify_snapshot(&snapshot, Some((&m0, 0))).expect("m0 verify genesis");
    verify_snapshot(&snapshot, Some((&m1, 1))).expect("m1 verify genesis");
    assert_eq!(decrypt_balance(&m0, &snapshot, 0).unwrap(), bal0);
    assert_eq!(decrypt_balance(&m1, &snapshot, 1).unwrap(), bal1);

    // Member 0 (browser) sends 7 to member 1.
    let amount = 7u64;
    let nonce = intmax3_zkp::ethereum_types::bytes32::Bytes32::default();
    let BuiltSend {
        mut payload,
        new_balance,
        ..
    } = build_send(&m0, &snapshot, 0, 1, amount, bal0, &w0, nonce, LEVEL, &mut rng)
        .expect("build_send");
    assert_eq!(new_balance, bal0 - amount);

    // Member 1 (recipient) verifies the transition + E-1 proof and decrypts the incoming amount.
    verify_send_transition(&snapshot.state, &snapshot.record, &payload, LEVEL, Some(&m1.regev_sk), Some(amount))
        .expect("recipient verify transition");

    // Co-signing: member 1 adds its signature to complete the set.
    let m1_sig = sign_state(&m1, 1, &payload.proposed_next_state).expect("sign m1");
    add_signature(&mut payload.proposed_next_state, m1_sig);

    let final_snapshot = ChannelSnapshot {
        record,
        state: payload.proposed_next_state,
        members,
    };

    // Both sides verify the finalized state with the full real-signature set.
    verify_all_signatures(&final_snapshot.record, &final_snapshot.members, &final_snapshot.state)
        .expect("all sigs valid");
    verify_snapshot(&final_snapshot, Some((&m0, 0))).expect("m0 verify final");
    verify_snapshot(&final_snapshot, Some((&m1, 1))).expect("m1 verify final");

    // Balances reconcile.
    assert_eq!(decrypt_balance(&m0, &final_snapshot, 0).unwrap(), bal0 - amount);
    assert_eq!(decrypt_balance(&m1, &final_snapshot, 1).unwrap(), bal1 + amount);
}

/// P4-1 (A11 soundness, NEGATIVE): a malicious peer takes a legitimate send payload and swaps in an
/// ATTACKER `pk_b` at the sender slot — and forges a matching BabyBear hash-sig with the attacker's
/// own key so the inner hash-sig verification would PASS in isolation. With the P4-1 fix
/// (`member_pubkeys_root` = canonical Poseidon `MemberTree` root over `MemberLeaf{pk_g, pk_b,
/// regev_pk_digest}`, re-bound in `verify_send_transition`), the tampered `pk_b` no longer matches
/// the registered member set, so the transition MUST be rejected. Before the fix the attacker's
/// `pk_b` was read from the unauthenticated payload and accepted.
#[test]
fn p4_1_attacker_pk_b_swap_is_rejected() {
    let mut rng = StdRng::seed_from_u64(0xBADBEEF);

    let m0 = MemberKeys::generate(&mut rng);
    let m1 = MemberKeys::generate(&mut rng);
    let members = vec![member_info(0, &m0), member_info(1, &m1)];
    let record = build_record(9, &members, 0).expect("record");

    let (bal0, bal1) = (40u64, 20u64);
    let (ct0, w0) = encrypt_amount(&mut rng, &m0.regev_pk, bal0).expect("enc0");
    let (ct1, _w1) = encrypt_amount(&mut rng, &m1.regev_pk, bal1).expect("enc1");
    let mut genesis = assemble_genesis_state(&record, &[ct0, ct1], bal0 + bal1).expect("genesis");
    let g0 = sign_state(&m0, 0, &genesis).expect("sign g0");
    add_signature(&mut genesis, g0);
    let g1 = sign_state(&m1, 1, &genesis).expect("sign g1");
    add_signature(&mut genesis, g1);
    let snapshot = ChannelSnapshot {
        record: record.clone(),
        state: genesis,
        members: members.clone(),
    };

    // Sanity: the honest payload verifies.
    let amount = 5u64;
    let nonce = Bytes32::default();
    let BuiltSend { payload, .. } =
        build_send(&m0, &snapshot, 0, 1, amount, bal0, &w0, nonce, LEVEL, &mut rng)
            .expect("build_send");
    verify_send_transition(&snapshot.state, &snapshot.record, &payload, LEVEL, Some(&m1.regev_sk), Some(amount))
        .expect("honest payload must verify");

    // ── Attack: substitute the sender slot's pk_b with an attacker key and re-forge the hash-sig. ──
    // `BabyBearSecretKey::random` lives over `rand` 0.8 (the regev layer), so use a 0.8 `StdRng`.
    use rand::SeedableRng as _;
    let attacker_baby = BabyBearSecretKey::random(&mut rand::rngs::StdRng::seed_from_u64(0xA11));
    let attacker_pk_b = attacker_baby.public_key().to_bytes32();

    // Recompute the exact IMPA tx digest the verifier will check (sender->recipient pk_g unchanged).
    let tx_digest = intmax3_zkp::common::channel::ChannelTx::signing_digest(
        snapshot.state.channel_id,
        snapshot.state.digest,
        &payload.channel_tx.enc_amount,
        payload.channel_tx.nonce,
        payload.channel_tx.sender_pk_g,
        payload.channel_tx.recipient_pk_g,
    );
    let m = decompose_digest_to_limbs(&tx_digest);
    let (attacker_sig, _pvs) =
        prove_hash_sig(LEVEL, &attacker_baby, &m).expect("attacker forges a self-consistent hash-sig");

    let mut tampered = payload.clone();
    // The hash-sig itself is internally valid for the attacker's pk_b (so the failure is NOT just a
    // bad signature — it is the membership/anchoring check rejecting the unregistered pk_b).
    tampered.channel_tx.sender_pk_b = attacker_pk_b;
    tampered.channel_tx.sender_hash_sig = attacker_sig;
    // Swap the attacker pk_b into the payload's member list at the sender slot.
    for mi in tampered.members.iter_mut() {
        if mi.slot == 0 {
            mi.pk_b = attacker_pk_b;
        }
    }

    let res = verify_send_transition(
        &snapshot.state,
        &snapshot.record,
        &tampered,
        LEVEL,
        Some(&m1.regev_sk),
        Some(amount),
    );
    assert!(
        res.is_err(),
        "P4-1: a payload with an attacker pk_b (even with a matching hash-sig) MUST be rejected"
    );
    let msg = format!("{}", res.unwrap_err());
    assert!(
        msg.contains("member_pubkeys_root"),
        "rejection must come from the member-set anchoring check, got: {msg}"
    );
}

/// P4-1 (A11 caller-layer, NEGATIVE): a malicious peer supplies a fully SELF-CONSISTENT but FOREIGN
/// `payload.record` + `members` (an attacker member set with its own correctly-recomputed
/// `member_pubkeys_root`, same channel_id). The internal member-root recompute would PASS (the foreign
/// set is self-consistent), so the only thing that rejects it is binding `payload.record` to the
/// session's TRUSTED record. Confirms `verify_send_transition` rejects against the trusted record, not
/// the payload's own record.
#[test]
fn p4_1_foreign_self_consistent_record_is_rejected() {
    let mut rng = StdRng::seed_from_u64(0xF0E16);

    let m0 = MemberKeys::generate(&mut rng);
    let m1 = MemberKeys::generate(&mut rng);
    let members = vec![member_info(0, &m0), member_info(1, &m1)];
    let channel_id = 9u32;
    let record = build_record(channel_id, &members, 0).expect("record");

    let (bal0, bal1) = (40u64, 20u64);
    let (ct0, w0) = encrypt_amount(&mut rng, &m0.regev_pk, bal0).expect("enc0");
    let (ct1, _w1) = encrypt_amount(&mut rng, &m1.regev_pk, bal1).expect("enc1");
    let mut genesis = assemble_genesis_state(&record, &[ct0, ct1], bal0 + bal1).expect("genesis");
    let g0 = sign_state(&m0, 0, &genesis).expect("g0");
    add_signature(&mut genesis, g0);
    let g1 = sign_state(&m1, 1, &genesis).expect("g1");
    add_signature(&mut genesis, g1);
    let snapshot = ChannelSnapshot {
        record: record.clone(),
        state: genesis,
        members: members.clone(),
    };

    let amount = 5u64;
    let BuiltSend { payload, .. } = build_send(
        &m0, &snapshot, 0, 1, amount, bal0, &w0, Bytes32::default(), LEVEL, &mut rng,
    )
    .expect("build_send");

    // Attacker replaces slot 0 with their OWN member and rebuilds a self-consistent record over the
    // SAME channel_id (so member_pubkeys_root recompute over `members` matches `record`).
    let attacker = MemberKeys::generate(&mut rng);
    let foreign_members = vec![member_info(0, &attacker), member_info(1, &m1)];
    let foreign_record = build_record(channel_id, &foreign_members, 0).expect("foreign record");

    let mut tampered = payload.clone();
    tampered.record = foreign_record;
    tampered.members = foreign_members;

    let res = verify_send_transition(
        &snapshot.state,
        &snapshot.record, // the SESSION-TRUSTED record
        &tampered,
        LEVEL,
        Some(&m1.regev_sk),
        Some(amount),
    );
    assert!(res.is_err(), "a foreign self-consistent record MUST be rejected");
    let msg = format!("{}", res.unwrap_err());
    assert!(
        msg.contains("registered (trusted) record"),
        "rejection must come from the trusted-record binding, got: {msg}"
    );
}
