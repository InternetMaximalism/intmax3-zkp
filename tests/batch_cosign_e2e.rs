//! Native e2e test of the BATCHED intra-channel co-sign (abstract2-1 §3.2b / v2.1b):
//! a 3-member channel where m0→m2 and m1→m0 are built as ordinary solo `SendPayload`s against the
//! SAME anchor state, each verified with the full solo pipeline, then folded into ONE batch state
//! transition (`build_batch_next_state`) that all members co-sign. Exercises sender-as-recipient
//! (m0 both debits and is credited) and the R1 single-debit rejection. Real E-1 STARKs at `Test`
//! level.
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    ethereum_types::bytes32::Bytes32,
    regev::{RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        BuiltSend, ChannelSnapshot, MemberInfo, MemberKeys, add_signature, assemble_genesis_state,
        build_batch_next_state, build_record, build_send, decrypt_balance,
        default_settled_tx_accumulator, sign_state, verify_all_signatures, verify_send_transition,
        verify_snapshot,
    },
};
use rand010::{SeedableRng, rngs::StdRng};

const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Test;

fn member_info(slot: u16, keys: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot,
        pk_g: keys.pk_g(),
        pk_b: keys.pk_b(),
        regev_pk: keys.regev_pk.clone(),
    }
}

fn digests(keys: &[&MemberKeys]) -> Vec<Bytes32> {
    keys.iter()
        .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
        .collect()
}

/// B-1b: deterministic NONZERO per-slot L1 exit addresses for test genesis states.
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

#[test]
fn batched_cosign_two_sends_one_transition() {
    let mut rng = StdRng::seed_from_u64(0xBA7C4);

    let m0 = MemberKeys::generate(&mut rng);
    let m1 = MemberKeys::generate(&mut rng);
    let m2 = MemberKeys::generate(&mut rng);
    let members = vec![member_info(0, &m0), member_info(1, &m1), member_info(2, &m2)];
    let record = build_record(7, &members, 0, 0).expect("record");

    let (bal0, bal1, bal2) = (50u64, 30u64, 20u64);
    let (ct0, w0) = encrypt_amount(&mut rng, &m0.regev_pk, bal0).expect("enc0");
    let (ct1, w1) = encrypt_amount(&mut rng, &m1.regev_pk, bal1).expect("enc1");
    let (ct2, _w2) = encrypt_amount(&mut rng, &m2.regev_pk, bal2).expect("enc2");
    let mut genesis = assemble_genesis_state(
        &record,
        &[ct0, ct1, ct2],
        &digests(&[&m0, &m1, &m2]),
        &test_recipients_b1b(3),
        bal0 + bal1 + bal2,
    )
    .expect("genesis");
    for (slot, keys) in [(0u8, &m0), (1u8, &m1), (2u8, &m2)] {
        let sig = sign_state(keys, slot, &genesis).expect("sign genesis");
        add_signature(&mut genesis, sig);
    }
    let snapshot = ChannelSnapshot {
        record: record.clone(),
        state: genesis,
        members: members.clone(),
        settled_tx_accumulator: default_settled_tx_accumulator(),
    };
    verify_snapshot(&snapshot, Some((&m0, 0))).expect("genesis verifies");

    // Two solo payloads anchored at the SAME head: m0→m2 (7) and m1→m0 (5).
    // m0 both debits and is credited in the same batch (R2, fold-order soundness).
    let (amt_a, amt_b) = (7u64, 5u64);
    let BuiltSend { payload: pa, .. } = build_send(
        &m0, &snapshot, 0, 2, amt_a, bal0, &w0, Bytes32::default(), LEVEL, &mut rng,
    )
    .expect("build m0→m2");
    let BuiltSend { payload: pb, .. } = build_send(
        &m1, &snapshot, 1, 0, amt_b, bal1, &w1, Bytes32::default(), LEVEL, &mut rng,
    )
    .expect("build m1→m0");

    // Every co-signer verifies each tx with the FULL solo pipeline against the anchor
    // (independent proofs — the parallelizable step; here sequential for determinism).
    for (p, sk, expected) in [
        (&pa, Some(&m2.regev_sk), Some(amt_a)),
        (&pb, Some(&m0.regev_sk), Some(amt_b)),
    ] {
        verify_send_transition(&snapshot.state, &snapshot.record, p, LEVEL, sk, expected)
            .expect("solo verification against the anchor");
    }

    // Canonical batch fold: ONE state transition for both txs.
    let mut batch_state = build_batch_next_state(&snapshot.state, &[pa.clone(), pb.clone()])
        .expect("batch build");
    assert_eq!(
        batch_state.balance_state.state_version,
        snapshot.state.balance_state.state_version + 1,
        "one version bump for the whole batch"
    );
    // pending_adds: m0 debited (reset) then credited (+1); m1 debited (0); m2 credited (+1).
    assert_eq!(batch_state.balance_state.pending_adds[0], 1);
    assert_eq!(batch_state.balance_state.pending_adds[1], 0);
    assert_eq!(batch_state.balance_state.pending_adds[2], 1);

    // N-of-N agreement round over the batch state.
    for (slot, keys) in [(0u8, &m0), (1u8, &m1), (2u8, &m2)] {
        let sig = sign_state(keys, slot, &batch_state).expect("sign batch");
        add_signature(&mut batch_state, sig);
    }
    let final_snapshot = ChannelSnapshot {
        record,
        state: batch_state,
        members,
        settled_tx_accumulator: default_settled_tx_accumulator(),
    };
    verify_all_signatures(
        &final_snapshot.record,
        &final_snapshot.members,
        &final_snapshot.state,
    )
    .expect("all real signatures valid on the batch state");
    verify_snapshot(&final_snapshot, Some((&m2, 2))).expect("final snapshot verifies");

    // Conservation + per-slot balances (m0 = 50 − 7 + 5 = 48; m1 = 25; m2 = 27).
    assert_eq!(decrypt_balance(&m0, &final_snapshot, 0).unwrap(), 48);
    assert_eq!(decrypt_balance(&m1, &final_snapshot, 1).unwrap(), 25);
    assert_eq!(decrypt_balance(&m2, &final_snapshot, 2).unwrap(), 27);
}

#[test]
fn batch_rejects_double_debit_and_k1_matches_solo() {
    let mut rng = StdRng::seed_from_u64(0xD0B1E);

    let m0 = MemberKeys::generate(&mut rng);
    let m1 = MemberKeys::generate(&mut rng);
    let members = vec![member_info(0, &m0), member_info(1, &m1)];
    let record = build_record(8, &members, 0, 0).expect("record");

    let (bal0, bal1) = (40u64, 10u64);
    let (ct0, w0) = encrypt_amount(&mut rng, &m0.regev_pk, bal0).expect("enc0");
    let (ct1, _w1) = encrypt_amount(&mut rng, &m1.regev_pk, bal1).expect("enc1");
    let mut genesis = assemble_genesis_state(
        &record,
        &[ct0, ct1],
        &digests(&[&m0, &m1]),
        &test_recipients_b1b(2),
        bal0 + bal1,
    )
    .expect("genesis");
    for (slot, keys) in [(0u8, &m0), (1u8, &m1)] {
        let sig = sign_state(keys, slot, &genesis).expect("sign genesis");
        add_signature(&mut genesis, sig);
    }
    let snapshot = ChannelSnapshot {
        record,
        state: genesis,
        members,
        settled_tx_accumulator: default_settled_tx_accumulator(),
    };

    let BuiltSend { payload, .. } = build_send(
        &m0, &snapshot, 0, 1, 5, bal0, &w0, Bytes32::default(), LEVEL, &mut rng,
    )
    .expect("build_send");

    // R1: the same sender slot twice in one batch MUST be rejected (double-spend of one witness).
    let err = build_batch_next_state(&snapshot.state, &[payload.clone(), payload.clone()])
        .expect_err("double debit must be rejected");
    assert!(
        format!("{err}").contains("R1"),
        "rejection must cite the single-debit rule, got: {err}"
    );

    // K = 1: the batch state is field-identical to the solo proposal (same digest), so the
    // sender's pending witness still commits on finalize.
    let solo = build_batch_next_state(&snapshot.state, &[payload.clone()]).expect("K=1 batch");
    assert_eq!(
        solo.digest, payload.proposed_next_state.digest,
        "K=1 batch must reproduce the solo digest exactly"
    );
}
