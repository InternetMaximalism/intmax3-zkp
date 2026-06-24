//! LIVE inter-channel send E2E, driven entirely through the reusable `wallet_core` inter-channel
//! API.
//!
//! Two real channels — A (id 7) and B (id 8) — each with REAL `MemberKeys` + a co-signed genesis
//! MIRRORING `tests/inter_channel_unified_e2e.rs` (delegate_count = 0, handled by `build_record`'s
//! 4th arg). A member of A sends `AMT` to a member of B. The whole two-leg flow runs through the
//! new `wallet_core` functions ONLY (no reaching into circuit/test internals beyond key + genesis
//! setup):
//!   LEG A: `build_inter_channel_send` → `verify_inter_channel_send_transition` → A members
//! co-sign.   LEG B: `verify_inter_channel_credit_transition` (the fail-closed gate) →
//!          `build_inter_channel_credit`.
//!
//! Runs the REAL E-2 channelUpdate STARK at `Test` level (fast, 8-query) — the SAME prover/verifier
//! the production path uses, only the FRI query count differs.
//!
//! WHAT EACH ASSERTION PROVES ABOUT SECURITY
//! -----------------------------------------
//! POSITIVE:
//!  * `build_inter_channel_send` returning Ok proves the post-debit `a_send` PASSES the REAL
//!    `InterChannelSendUpdateWitness` (E-2 statement rebuilt from authenticated state; channel_fund
//!    -= amount; h2_tag == tx_tree_root != 0; sender slot rebound; nullifier advanced). [inv 5,2]
//!  * `verify_inter_channel_send_transition` Ok proves an A co-signer, binding the payload to the
//!    TRUSTED A record, independently re-verifies the same witness before signing. [trusted record]
//!  * `verify_all_signatures(a_send)` Ok proves the debit is N-of-N co-signed under A's record —
//!    the cross-channel root of trust B relies on. [inv 1]
//!  * `verify_inter_channel_credit_transition` Ok proves the fail-closed gate accepts a GENUINE
//!    transfer: A is co-signed (1), amount is consistent end-to-end incl. a REAL E-2 re-verify (2),
//!    receiver pk_g == B's recipient slot (3), channel ids bind A→B (4), A's small-block H1' ==
//!    a_send.h1() and tx_tree_root matches with the same recomputed tx leaf (5), TxV2 inclusion
//!    (7).
//!  * `build_inter_channel_credit` crediting B's recipient slot by EXACTLY `AMT` (decrypted with
//!    the recipient sk), with channel_fund conservation (A -= AMT, B += AMT) and the SAME tx leaf
//!    on both sides, proves the homomorphic credit and the dual-channel chain binding are correct.
//! NEGATIVE (each MUST be rejected by its OWN invariant — a vacuous gate proves nothing):
//!  * tampered credit amount (y != x) → E-2 re-verify / amount binding rejects. [inv 2]
//!  * wrong recipient_slot → receiver pk_g binding rejects. [inv 3]
//!  * A state with a missing AND a forged signature → the N-of-N gate rejects. [inv 1]
//!  * replayed/zero tx_tree_root → the H2-reservation + h1/tx_tree binding rejects. [inv 5]
//!  * wrong destination channel id → channel-id binding rejects. [inv 4]
//!  * wrong TxV2 leaf → TxV2 inclusion proof rejects. [inv 7]
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    common::{channel::ChannelState, channel_id::ChannelId},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    regev::{RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        BuiltInterChannelCredit, BuiltInterChannelSend, ChannelSnapshot, InterChannelDebitPayload,
        InterChannelTransferDescriptor, MemberInfo, MemberKeys, add_signature,
        assemble_genesis_state, build_inter_channel_credit, build_inter_channel_send, build_record,
        decrypt_balance, default_settled_tx_accumulator, sign_state, verify_all_signatures,
        verify_inter_channel_credit_transition, verify_inter_channel_send_transition,
        verify_snapshot,
    },
};
use rand010::{SeedableRng, rngs::StdRng};

const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Test;
const A_ID: u32 = 7;
const B_ID: u32 = 8;
const AMT: u64 = 5;

fn member_info(slot: u8, keys: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot,
        pk_g: keys.pk_g(),
        pk_b: keys.pk_b(),
        regev_pk: keys.regev_pk.clone(),
    }
}

/// A fresh nullifier root that differs from `prev` (the send/import/bundle steps each advance it).
fn fresh_root(tag: u32) -> Bytes32 {
    Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, tag]).unwrap()
}

struct ChannelFixture {
    record: intmax3_zkp::common::channel::ChannelRecord,
    snapshot: ChannelSnapshot,
    keys: Vec<MemberKeys>,
    /// genesis ciphertext witnesses, by slot (kept so the sender slot can prove its E-2 `before`).
    witnesses: Vec<intmax3_zkp::regev::AmountWitness>,
    balances: Vec<u64>,
}

/// Build a real `n`-member channel (delegate_count = 0) with a co-signed genesis, retaining each
/// slot's `AmountWitness`. Mirrors the genesis assembly in `inter_channel_unified_e2e.rs`.
fn build_channel(channel_id: u32, n: usize, balances: &[u64], rng: &mut StdRng) -> ChannelFixture {
    let keys: Vec<MemberKeys> = (0..n).map(|_| MemberKeys::generate(rng)).collect();
    let members: Vec<MemberInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| member_info(i as u8, k))
        .collect();
    // 4th arg = delegate_count = 0 (this branch's `build_record` signature).
    let record = build_record(channel_id, &members, 0, 0).expect("record");

    let mut cts = Vec::new();
    let mut witnesses = Vec::new();
    for (i, &bal) in balances.iter().enumerate() {
        let (ct, w) = encrypt_amount(rng, &keys[i].regev_pk, bal).expect("enc");
        cts.push(ct);
        witnesses.push(w);
    }
    let fund: u64 = balances.iter().sum();
    // Decryption Stage 1: per-active-slot Regev pk digests, in the SAME slot order as `cts`
    // (mirrors channel_member.rs:601-605).
    let regev_pk_digests: Vec<Bytes32> = keys
        .iter()
        .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
        .collect();
    let mut genesis =
        assemble_genesis_state(&record, &cts, &regev_pk_digests, fund).expect("genesis");
    for (i, k) in keys.iter().enumerate() {
        let s = sign_state(k, i as u8, &genesis).expect("sign genesis");
        add_signature(&mut genesis, s);
    }
    let snapshot = ChannelSnapshot {
        record: record.clone(),
        state: genesis,
        // Genesis seeds the EMPTY accumulator (intra-channel ops never advance it).
        settled_tx_accumulator: default_settled_tx_accumulator(),
        members,
    };
    verify_snapshot(&snapshot, Some((&keys[0], 0))).expect("verify genesis");
    ChannelFixture {
        record,
        snapshot,
        keys,
        witnesses,
        balances: balances.to_vec(),
    }
}

/// Co-sign `state` with ALL of `keys` (slot order) and return it (after replacing any prior sigs).
fn co_sign_all(mut state: ChannelState, keys: &[MemberKeys]) -> ChannelState {
    state.member_signatures.clear();
    // signatures are over signing_digest(), which excludes member_signatures, so the digest is
    // stable.
    for (i, k) in keys.iter().enumerate() {
        let s = sign_state(k, i as u8, &state).expect("co-sign");
        add_signature(&mut state, s);
    }
    state
}

/// Run a full positive send + credit through the wallet_core API; returns the descriptor, the fully
/// A-co-signed send state, and the resulting B credit, for the positive assertions + as a base the
/// negative cases tamper.
fn run_positive(
    a: &ChannelFixture,
    b: &ChannelFixture,
    sender_slot: u8,
    recipient_slot: u8,
    amount: u64,
    rng: &mut StdRng,
) -> (
    InterChannelTransferDescriptor,
    ChannelState,
    BuiltInterChannelCredit,
) {
    let dest_id = ChannelId::new(B_ID as u64).unwrap();
    let recipient_pk = b.keys[recipient_slot as usize].regev_pk.clone();
    let recipient_pk_g = b.record.member_pk_gs[recipient_slot as usize];

    let BuiltInterChannelSend {
        debit_payload,
        transfer_descriptor,
        ..
    } = build_inter_channel_send(
        &a.keys[sender_slot as usize],
        &a.snapshot,
        sender_slot,
        dest_id,
        recipient_slot,
        recipient_pk,
        recipient_pk_g,
        amount,
        a.balances[sender_slot as usize],
        &a.witnesses[sender_slot as usize],
        fresh_root(0x412),
        LEVEL,
        rng,
    )
    .expect("build_inter_channel_send (self-check passes)");

    // An A co-signer re-verifies before signing.
    verify_inter_channel_send_transition(&a.snapshot.state, &a.record, &debit_payload, LEVEL)
        .expect("A co-signer verify send transition");

    // A members co-sign the post-debit state → N-of-N.
    let a_send = co_sign_all(debit_payload.proposed_next_state.clone(), &a.keys);
    verify_all_signatures(&a.record, &[], &a_send).expect("a_send is N-of-N co-signed");

    // B's fail-closed gate.
    verify_inter_channel_credit_transition(
        &b.snapshot.state,
        &b.record,
        &transfer_descriptor,
        &a_send,
        &a.record,
        LEVEL,
    )
    .expect("B credit gate accepts the genuine transfer");

    // B builds the credit (the recipient member runs it so it gets the decryption check).
    let credit = build_inter_channel_credit(
        &b.keys[recipient_slot as usize],
        &b.snapshot,
        &transfer_descriptor,
        LEVEL,
        rng,
    )
    .expect("build_inter_channel_credit");

    (transfer_descriptor, a_send, credit)
}

#[test]
fn inter_channel_live_send_and_credit() {
    let mut rng = StdRng::seed_from_u64(0x1C_5E_4D);

    // Channel A (id 7): 3 members. Channel B (id 8): 3 members. Sender = A member 0, recipient = B
    // member 1 (a non-trivial slot, to prove slot routing).
    let a = build_channel(A_ID, 3, &[50, 10, 30], &mut rng);
    let b = build_channel(B_ID, 3, &[20, 40, 60], &mut rng);
    let sender_slot = 0u8;
    let recipient_slot = 1u8;

    let a_fund_before = a.snapshot.state.channel_fund.amount;
    let b_fund_before = b.snapshot.state.channel_fund.amount;
    let recipient_before = decrypt_balance(
        &b.keys[recipient_slot as usize],
        &b.snapshot,
        recipient_slot,
    )
    .unwrap();

    let (descriptor, a_send, credit) =
        run_positive(&a, &b, sender_slot, recipient_slot, AMT, &mut rng);

    // ---- POSITIVE assertions ----

    // Recipient slot credited EXACTLY AMT (decrypted with the recipient's own sk). This proves the
    // homomorphic credit landed in the right slot with the right plaintext.
    let b_credited_snapshot = ChannelSnapshot {
        record: b.record.clone(),
        state: credit.bundle_apply_state.clone(),
        members: b.snapshot.members.clone(),
        // The bundle-apply state advanced the accumulator (import tx_hash + bundle tx_hash). Thread
        // the tree the builder returned so its root matches
        // bundle_apply_state.balance_state.settled_tx_accumulator_root (wallet invariant).
        settled_tx_accumulator: credit.settled_tx_accumulator.clone(),
    };
    let recipient_after = decrypt_balance(
        &b.keys[recipient_slot as usize],
        &b_credited_snapshot,
        recipient_slot,
    )
    .unwrap();
    assert_eq!(
        recipient_after,
        recipient_before + AMT,
        "recipient slot in B credited EXACTLY AMT"
    );

    // channel_fund conservation: A -= AMT, B += AMT (across both legs). Proves value is conserved
    // end-to-end (no inflation / no loss).
    let amt_u256 = {
        use intmax3_zkp::ethereum_types::u256::U256;
        U256::from(AMT as u32)
    };
    assert_eq!(
        a_send.channel_fund.amount + amt_u256,
        a_fund_before,
        "A channel_fund decreased by AMT"
    );
    assert_eq!(
        credit.bundle_apply_state.channel_fund.amount,
        b_fund_before + amt_u256,
        "B channel_fund increased by AMT"
    );
    // The fund import leg is exactly the +AMT step; the bundle leg leaves the fund unchanged.
    assert_eq!(
        credit.fund_import_state.channel_fund.amount, credit.bundle_apply_state.channel_fund.amount,
        "bundle apply does not change channel_fund"
    );

    // The SAME tx leaf is chained on both sides (sender chained it into A's settled_tx_chain; B
    // recomputes it independently and chains it into the bundle-apply state). Proves the
    // dual-channel chain binding (F3-A multi-layer defense).
    let a_leaf = descriptor.inter_channel_tx.tx_leaf_hash().expect("tx leaf");
    use intmax3_zkp::common::balance_state::settled_tx_chain_push;
    let b_bundle_chain_expected = settled_tx_chain_push(
        credit.fund_import_state.balance_state.settled_tx_chain,
        a_leaf,
    );
    assert_eq!(
        credit.bundle_apply_state.balance_state.settled_tx_chain, b_bundle_chain_expected,
        "B bundle-apply chains the SAME tx leaf the sender chained"
    );

    // ---- NEGATIVE 1: tampered credit amount (y != x) → gate rejects (inv 2). ----
    // Proves the gate does not trust the descriptor's scalar amount: it re-verifies the REAL E-2,
    // so a different claimed public amount than the proof was minted for is rejected by the
    // transcript.
    {
        let mut bad = descriptor.clone();
        bad.amount = AMT + 1;
        let err = verify_inter_channel_credit_transition(
            &b.snapshot.state,
            &b.record,
            &bad,
            &a_send,
            &a.record,
            LEVEL,
        );
        assert!(
            err.is_err(),
            "tampered credit amount MUST be rejected (inv 2)"
        );
    }

    // ---- NEGATIVE 2: wrong recipient_slot → gate rejects (inv 3). ----
    // Proves the receiver-delta pk_g binding: the delta was minted for B member 1, so claiming a
    // different recipient slot (whose pk_g differs) is rejected.
    {
        let mut bad = descriptor.clone();
        bad.recipient_slot = 2;
        let err = verify_inter_channel_credit_transition(
            &b.snapshot.state,
            &b.record,
            &bad,
            &a_send,
            &a.record,
            LEVEL,
        );
        assert!(
            err.is_err(),
            "wrong recipient_slot MUST be rejected (inv 3)"
        );
    }

    // ---- NEGATIVE 3: A state with a missing AND a forged signature → credit gate rejects (inv 1).
    // Proves the cross-channel root of trust: B credits ONLY because A is fully N-of-N co-signed.
    {
        // (a) missing signature: drop A member 2's signature.
        let mut a_send_missing = a_send.clone();
        a_send_missing
            .member_signatures
            .retain(|s| s.member_slot != 2);
        let err = verify_inter_channel_credit_transition(
            &b.snapshot.state,
            &b.record,
            &descriptor,
            &a_send_missing,
            &a.record,
            LEVEL,
        );
        assert!(
            err.is_err(),
            "A state missing a co-signature MUST be rejected (inv 1)"
        );

        // (b) forged signature: replace A member 2's proof with member 0's (wrong (pk_g, m)
        // binding).
        let mut a_send_forged = a_send.clone();
        let sig0 = a_send_forged
            .member_signatures
            .iter()
            .find(|s| s.member_slot == 0)
            .unwrap()
            .signature
            .clone();
        if let Some(s2) = a_send_forged
            .member_signatures
            .iter_mut()
            .find(|s| s.member_slot == 2)
        {
            s2.signature = sig0; // member 0's proof under member 2's slot — wrong (pk_g, m) binding
        }
        let err = verify_inter_channel_credit_transition(
            &b.snapshot.state,
            &b.record,
            &descriptor,
            &a_send_forged,
            &a.record,
            LEVEL,
        );
        assert!(
            err.is_err(),
            "A state with a forged co-signature MUST be rejected (inv 1)"
        );
    }

    // ---- NEGATIVE 4: replayed/zero tx_tree_root → gate rejects (inv 5). ----
    // Proves the H2=0 reservation: an inter-channel send may not alias the in-channel signing
    // target (tx_tree_root == 0), and the H1'/tx_tree_root binding is enforced.
    {
        let mut bad = descriptor.clone();
        bad.tx_tree_root = Bytes32::default();
        let err = verify_inter_channel_credit_transition(
            &b.snapshot.state,
            &b.record,
            &bad,
            &a_send,
            &a.record,
            LEVEL,
        );
        assert!(
            err.is_err(),
            "zero tx_tree_root MUST be rejected (inv 5, H2 reservation)"
        );
    }

    // ---- NEGATIVE 5: wrong destination channel id → gate rejects (inv 4). ----
    // Proves the channel-id binding: a descriptor whose destination is not the trusted B id is
    // rejected (a tx cannot be re-routed to a foreign channel).
    {
        let mut bad = descriptor.clone();
        bad.destination_channel_id = ChannelId::new(9).unwrap();
        let err = verify_inter_channel_credit_transition(
            &b.snapshot.state,
            &b.record,
            &bad,
            &a_send,
            &a.record,
            LEVEL,
        );
        assert!(
            err.is_err(),
            "wrong destination channel id MUST be rejected (inv 4)"
        );
    }

    // ---- NEGATIVE 6: wrong TxV2 leaf → gate rejects (inv 7). ----
    // Proves the TxV2 inclusion check: a tampered TxV2 leaf no longer hashes to the committed
    // tx_tree_root, so the inclusion proof fails (flowReceive3-1).
    {
        let mut bad = descriptor.clone();
        bad.tx_v2.nonce = bad.tx_v2.nonce.wrapping_add(1);
        let err = verify_inter_channel_credit_transition(
            &b.snapshot.state,
            &b.record,
            &bad,
            &a_send,
            &a.record,
            LEVEL,
        );
        assert!(err.is_err(), "wrong TxV2 leaf MUST be rejected (inv 7)");
    }

    // ---- NEGATIVE 7: the send leg itself rejects a bogus debit payload (sanity on the A gate).
    // ---- Proves the A-side send transition is not vacuous: a debit that does not decrease
    // channel_fund by amount fails `InterChannelSendUpdateWitness`.
    {
        let _: &InterChannelDebitPayload; // type anchor for clarity
        let dest_id = ChannelId::new(B_ID as u64).unwrap();
        let recipient_pk = b.keys[recipient_slot as usize].regev_pk.clone();
        let recipient_pk_g = b.record.member_pk_gs[recipient_slot as usize];
        let built = build_inter_channel_send(
            &a.keys[sender_slot as usize],
            &a.snapshot,
            sender_slot,
            dest_id,
            recipient_slot,
            recipient_pk,
            recipient_pk_g,
            AMT,
            a.balances[sender_slot as usize],
            &a.witnesses[sender_slot as usize],
            fresh_root(0x999),
            LEVEL,
            &mut rng,
        )
        .expect("build send for tamper base");
        let mut bad_payload = built.debit_payload;
        // Corrupt the proposed next state so channel_fund no longer decreases by amount.
        bad_payload.proposed_next_state.channel_fund.amount = a.snapshot.state.channel_fund.amount;
        bad_payload.proposed_next_state = bad_payload
            .proposed_next_state
            .clone()
            .with_computed_digest();
        let err =
            verify_inter_channel_send_transition(&a.snapshot.state, &a.record, &bad_payload, LEVEL);
        assert!(
            err.is_err(),
            "a debit that does not decrease channel_fund by amount MUST be rejected"
        );
    }

    eprintln!(
        "[inter_channel_live] OK: A(7) member {sender_slot} → B(8) member {recipient_slot}, AMT={AMT}. \
         Positive (send self-check + A co-sign gate + N-of-N + B fail-closed gate + credit) and all \
         negative cases (amount, slot, missing/forged sig, zero tx_tree_root, bad dest id, bad TxV2, \
         bad debit) pass."
    );
}

#[test]
fn inter_channel_live_negative_error_provenance() {
    // SECURITY: a negative test that rejects for the WRONG reason proves nothing. This test asserts
    // each tampered input is rejected by the SPECIFIC invariant it targets (by error substring), so
    // a future refactor cannot silently turn a real gate into a vacuous one.
    let mut rng = StdRng::seed_from_u64(0xBEEF_77);
    let a = build_channel(A_ID, 3, &[50, 10, 30], &mut rng);
    let b = build_channel(B_ID, 3, &[20, 40, 60], &mut rng);
    let (descriptor, a_send, _credit) = run_positive(&a, &b, 0, 1, AMT, &mut rng);

    let gate = |d: &InterChannelTransferDescriptor, s: &ChannelState| {
        verify_inter_channel_credit_transition(&b.snapshot.state, &b.record, d, s, &a.record, LEVEL)
            .map_err(|e| e.0)
    };

    // inv 2 — tampered amount.
    let mut d = descriptor.clone();
    d.amount = AMT + 1;
    let e = gate(&d, &a_send).unwrap_err();
    assert!(e.contains("invariant 2"), "amount tamper hit: {e}");

    // inv 3 — wrong recipient slot.
    let mut d = descriptor.clone();
    d.recipient_slot = 2;
    let e = gate(&d, &a_send).unwrap_err();
    assert!(e.contains("invariant 3"), "slot tamper hit: {e}");

    // inv 5 — zero tx_tree_root.
    let mut d = descriptor.clone();
    d.tx_tree_root = Bytes32::default();
    let e = gate(&d, &a_send).unwrap_err();
    assert!(e.contains("invariant 5"), "zero root hit: {e}");

    // inv 4 — wrong destination id in the descriptor.
    let mut d = descriptor.clone();
    d.destination_channel_id = ChannelId::new(9).unwrap();
    let e = gate(&d, &a_send).unwrap_err();
    assert!(e.contains("invariant 4"), "dest id tamper hit: {e}");

    // inv 1 — drop a co-signature.
    let mut bad = a_send.clone();
    bad.member_signatures.retain(|s| s.member_slot != 2);
    let e = gate(&descriptor, &bad).unwrap_err();
    assert!(e.contains("invariant 1"), "missing sig hit: {e}");

    // inv 7 — wrong TxV2 leaf (the inclusion proof no longer matches the committed tx_tree_root).
    let mut d = descriptor.clone();
    d.tx_v2.nonce = d.tx_v2.nonce.wrapping_add(1);
    let e = gate(&d, &a_send).unwrap_err();
    assert!(e.contains("invariant 7"), "tx_v2 tamper hit: {e}");

    eprintln!(
        "[inter_channel_live] negative provenance OK: each tamper rejected by its own invariant."
    );
}
