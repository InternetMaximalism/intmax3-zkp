//! Throwaway smoke test for the browser-as-delegate wallet-live demo flow: 3 co-signing members
//! (slots 0,1,2) + 1 browser DELEGATE (slot 3). Mirrors exactly what channel_member (init/cosign)
//! and the browser wasm (genesis_contribution / import / send / finalize) do, end-to-end.
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    ethereum_types::bytes32::Bytes32,
    regev::{RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        BuiltSend, ChannelSnapshot, MemberInfo, MemberKeys, add_signature, assemble_genesis_state,
        build_record, build_send, decrypt_balance, sign_state, verify_all_signatures,
        verify_send_transition, verify_snapshot,
    },
};
use rand010::{SeedableRng, rngs::StdRng};

const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;

fn info(slot: u8, k: &MemberKeys) -> MemberInfo {
    MemberInfo { slot, pk_g: k.pk_g(), pk_b: k.pk_b(), regev_pk: k.regev_pk.clone() }
}

#[test]
fn delegate_demo_three_members_plus_browser_delegate_send() {
    let mut rng = StdRng::seed_from_u64(0xDE1E_6A7E);

    // --- channel_member cmd_init: 3 CLI members (slots 0,1,2) + browser delegate (slot 3) ---
    let member_keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut rng)).collect();
    let delegate_keys = MemberKeys::generate(&mut rng); // the "browser"

    let mut members: Vec<MemberInfo> =
        member_keys.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect();
    members.push(info(3, &delegate_keys));

    // 3 members + 1 delegate: member_count = 3, delegate_count = 1, bp = member slot 0.
    let record = build_record(7, &members, 0, 1).expect("delegate record");
    assert_eq!((record.member_count, record.delegate_count), (3, 1));

    // Genesis balances: members 40/30/20, delegate (browser) 50. Keep the DELEGATE's witness (the
    // browser retains it from wallet_genesis_contribution) so it can later send.
    let mut cts = Vec::new();
    for (i, &bal) in [40u64, 30, 20].iter().enumerate() {
        cts.push(encrypt_amount(&mut rng, &member_keys[i].regev_pk, bal).unwrap().0);
    }
    let (delegate_ct, delegate_witness) =
        encrypt_amount(&mut rng, &delegate_keys.regev_pk, 50).unwrap();
    cts.push(delegate_ct);

    let mut genesis = assemble_genesis_state(&record, &cts, 140).expect("genesis");

    // Only the THREE MEMBERS co-sign the genesis (the delegate does NOT).
    for slot in 0..3u8 {
        let sig = sign_state(&member_keys[slot as usize], slot, &genesis).unwrap();
        add_signature(&mut genesis, sig);
    }
    verify_all_signatures(&record, &members, &genesis).expect("genesis fully member-signed");

    let snapshot = ChannelSnapshot { record: record.clone(), state: genesis, members: members.clone() };

    // --- browser wasm: import as the DELEGATE (slot 3), verify, decrypt own balance ---
    verify_snapshot(&snapshot, Some((&delegate_keys, 3))).expect("delegate imports snapshot");
    assert_eq!(decrypt_balance(&delegate_keys, &snapshot, 3).unwrap(), 50);

    // --- browser wasm wallet_send: the DELEGATE (slot 3) sends 7 to member slot 0 ---
    let amount = 7u64;
    let BuiltSend { payload, .. } = build_send(
        &delegate_keys, &snapshot, 3 /* delegate sender */, 0 /* member recipient */,
        amount, 50 /* delegate balance */, &delegate_witness, Bytes32::default(), LEVEL, &mut rng,
    )
    .expect("delegate build_send");

    // --- channel_member cmd_cosign: each member re-verifies the transition + co-signs ---
    verify_send_transition(
        &snapshot.state, &snapshot.record, &payload, LEVEL,
        Some(&member_keys[0].regev_sk), Some(amount),
    )
    .expect("members re-verify the delegate's send transition before co-signing");

    let mut next = payload.proposed_next_state.clone();
    assert_eq!(next.prev_digest, snapshot.state.digest, "extends the head");
    for slot in 0..3u8 {
        let sig = sign_state(&member_keys[slot as usize], slot, &next).unwrap();
        add_signature(&mut next, sig);
    }
    verify_all_signatures(&record, &members, &next).expect("next state fully member-signed");

    // --- browser wasm wallet_finalize: adopt the fully member-signed next state ---
    let final_snapshot = ChannelSnapshot { record, state: next, members };
    assert_eq!(
        decrypt_balance(&delegate_keys, &final_snapshot, 3).unwrap(),
        50 - amount,
        "delegate balance debited"
    );
    assert_eq!(
        decrypt_balance(&member_keys[0], &final_snapshot, 0).unwrap(),
        40 + amount,
        "member 0 credited"
    );
    let signers: Vec<u8> =
        final_snapshot.state.member_signatures.iter().map(|s| s.member_slot).collect();
    assert_eq!(signers, vec![0, 1, 2], "exactly the 3 members co-signed; delegate slot 3 did not");
}

/// Multi-delegate: 3 members (slots 0,1,2) + TWO delegates (slots 3,4) in the SAME channel. Delegate
/// 3 sends to delegate 4. Proves two distinct delegates coexist and a delegate-to-delegate transfer
/// is co-signed by the 3 members (neither delegate co-signs state).
#[test]
fn two_delegates_in_one_channel_delegate_to_delegate_send() {
    let mut rng = StdRng::seed_from_u64(0x2DE1_2DE1);
    let member_keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut rng)).collect();
    let d3 = MemberKeys::generate(&mut rng); // delegate slot 3
    let d4 = MemberKeys::generate(&mut rng); // delegate slot 4

    let mut members: Vec<MemberInfo> =
        member_keys.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect();
    members.push(info(3, &d3));
    members.push(info(4, &d4));

    let record = build_record(7, &members, 0, 2).expect("2-delegate record");
    assert_eq!((record.member_count, record.delegate_count), (3, 2));

    let mut cts = Vec::new();
    for (i, &bal) in [40u64, 30, 20].iter().enumerate() {
        cts.push(encrypt_amount(&mut rng, &member_keys[i].regev_pk, bal).unwrap().0);
    }
    let (c3, w3) = encrypt_amount(&mut rng, &d3.regev_pk, 50).unwrap();
    let (c4, _w4) = encrypt_amount(&mut rng, &d4.regev_pk, 60).unwrap();
    cts.push(c3);
    cts.push(c4);

    let mut genesis = assemble_genesis_state(&record, &cts, 200).expect("genesis");
    for slot in 0..3u8 {
        let sig = sign_state(&member_keys[slot as usize], slot, &genesis).unwrap();
        add_signature(&mut genesis, sig);
    }
    verify_all_signatures(&record, &members, &genesis).expect("3 members sign genesis");
    let snapshot = ChannelSnapshot { record: record.clone(), state: genesis, members: members.clone() };

    // Delegate 3 sends 9 to delegate 4.
    let BuiltSend { payload, .. } = build_send(
        &d3, &snapshot, 3, 4, 9, 50, &w3, Bytes32::default(), LEVEL, &mut rng,
    )
    .expect("delegate3 -> delegate4 send");
    verify_send_transition(
        &snapshot.state, &snapshot.record, &payload, LEVEL, Some(&d4.regev_sk), Some(9),
    )
    .expect("members re-verify delegate->delegate transition");

    let mut next = payload.proposed_next_state.clone();
    for slot in 0..3u8 {
        let sig = sign_state(&member_keys[slot as usize], slot, &next).unwrap();
        add_signature(&mut next, sig);
    }
    verify_all_signatures(&record, &members, &next).expect("3 members co-sign");
    let fin = ChannelSnapshot { record, state: next, members };
    assert_eq!(decrypt_balance(&d3, &fin, 3).unwrap(), 41, "delegate 3 debited");
    assert_eq!(decrypt_balance(&d4, &fin, 4).unwrap(), 69, "delegate 4 credited");
    let signers: Vec<u8> = fin.state.member_signatures.iter().map(|s| s.member_slot).collect();
    assert_eq!(signers, vec![0, 1, 2], "only the 3 members co-signed; neither delegate did");
}

/// Membership-add JOIN: a 1-delegate channel where a member has already SENT, then a 2nd delegate
/// joins via a state-PRESERVING add (the send survives), and BOTH delegates can import the new state
/// (mirrors channel_member's join_delegate). Proves "join after sending does not wipe; the new state
/// is importable by every delegate".
#[test]
fn delegate_join_preserves_send_and_is_importable() {
    use intmax3_zkp::common::channel::ChannelState;
    let mut rng = StdRng::seed_from_u64(0x10_1_E55);
    let mk: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut rng)).collect();
    let d3 = MemberKeys::generate(&mut rng);

    let mut members: Vec<MemberInfo> = mk.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect();
    members.push(info(3, &d3));
    let record = build_record(7, &members, 0, 1).unwrap();
    let mut cts = Vec::new();
    for (i, &b) in [40u64, 30, 20].iter().enumerate() {
        cts.push(encrypt_amount(&mut rng, &mk[i].regev_pk, b).unwrap().0);
    }
    let (c3, w3) = encrypt_amount(&mut rng, &d3.regev_pk, 50).unwrap();
    cts.push(c3);
    let mut state = assemble_genesis_state(&record, &cts, 200).unwrap();
    for s in 0..3u8 { let g = sign_state(&mk[s as usize], s, &state).unwrap(); add_signature(&mut state, g); }

    // Delegate 3 sends 8 to member 0 (v0 -> v1).
    let snap = ChannelSnapshot { record: record.clone(), state, members: members.clone() };
    let BuiltSend { payload, .. } = build_send(&d3, &snap, 3, 0, 8, 50, &w3, Bytes32::default(), LEVEL, &mut rng).unwrap();
    let mut v1 = payload.proposed_next_state.clone();
    for s in 0..3u8 { let g = sign_state(&mk[s as usize], s, &v1).unwrap(); add_signature(&mut v1, g); }
    assert_eq!(decrypt_balance(&d3, &ChannelSnapshot{record:record.clone(),state:v1.clone(),members:members.clone()}, 3).unwrap(), 42);

    // A 2nd delegate (slot 4) JOINS: state-preserving membership add on top of v1.
    let d4 = MemberKeys::generate(&mut rng);
    members.push(info(4, &d4));
    let record2 = build_record(7, &members, 0, 2).unwrap();
    let (c4, _w4) = encrypt_amount(&mut rng, &d4.regev_pk, 60).unwrap();
    let mut v2: ChannelState = v1.clone();
    v2.prev_digest = v2.digest;
    v2.balance_state.delegate_count = 2;
    v2.balance_state.enc_balances[4] = c4;
    v2.balance_state.pending_adds[4] = 0;
    v2.balance_state.state_version += 1;
    v2.member_signatures.clear();
    let mut v2 = v2.with_computed_digest();
    for s in 0..3u8 { let g = sign_state(&mk[s as usize], s, &v2).unwrap(); add_signature(&mut v2, g); }

    let joined = ChannelSnapshot { record: record2, state: v2, members };
    // BOTH delegates import the joined state; the earlier send is preserved (delegate 3 still 42).
    verify_snapshot(&joined, Some((&d3, 3))).expect("delegate 3 imports joined state");
    verify_snapshot(&joined, Some((&d4, 4))).expect("delegate 4 imports joined state");
    assert_eq!(decrypt_balance(&d3, &joined, 3).unwrap(), 42, "delegate 3 send survived the join");
    assert_eq!(decrypt_balance(&d4, &joined, 4).unwrap(), 60, "delegate 4 funded");
    assert_eq!(joined.state.balance_state.state_version, 2, "v1 send + join => v2");
}
