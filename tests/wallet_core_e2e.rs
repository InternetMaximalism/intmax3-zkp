//! Native end-to-end test of the wallet core: a 2-member channel where member 0 ("browser") and
//! member 1 ("CLI") each hold their own keys, build a genesis, then member 0 sends to member 1 and
//! the transfer is co-signed and verified — exercising the same code paths the wasm wallet + CLI
//! companion use. Runs the real E-1 STARK at `Test` level (fast).
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    regev::{RegevSecurityLevel, encrypt_amount},
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
        sphincs_pk_hex: keys
            .kp
            .pk_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
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
    let g0 = sign_state(&m0, 0, &genesis);
    add_signature(&mut genesis, g0);
    let g1 = sign_state(&m1, 1, &genesis);
    add_signature(&mut genesis, g1);

    let snapshot = ChannelSnapshot {
        record: record.clone(),
        state: genesis,
        members: members.clone(),
    };

    // Both members fully verify the signed genesis (real SPHINCS+ sigs, roots, own-slot decrypt).
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
    verify_send_transition(&snapshot.state, &payload, LEVEL, Some(&m1.regev_sk), Some(amount))
        .expect("recipient verify transition");

    // Co-signing: member 1 adds its signature to complete the set.
    let m1_sig = sign_state(&m1, 1, &payload.proposed_next_state);
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
