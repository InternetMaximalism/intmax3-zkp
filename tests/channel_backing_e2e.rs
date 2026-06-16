//! detail2 §F-1 deposit-backing gate, end-to-end against a REAL deposit-backed balance proof.
//!
//! Proves the user-mandated fail-closed invariant: a co-signer accepts a channel state ONLY when
//! the channel's intmax NATIVE balance is attested by a real `balanceProof` whose `channel_id` and
//! `settled_tx_chain` reconcile with the signed `BalanceState` (detail2 §F-1 / §3.1). Every way the
//! backing can be absent, foreign, stale, or forged is rejected.
//!
//! This is the genuine base/native ↔ channel connection: the channel's own base-layer balance proof
//! (funded by an L1 deposit) is the backing; the Regev channel state is reconciled against it.
#![cfg(not(debug_assertions))]

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
    common::{channel_id::ChannelId, salt::Salt},
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
    regev::encrypt_amount,
    wallet_core::{
        ChannelBalanceAttestation, MemberInfo, MemberKeys, add_signature, assemble_genesis_state,
        assemble_genesis_state_backed, build_record, sign_state, sign_state_if_backed,
        verify_all_signatures, verify_channel_backing,
    },
};
use plonky2::{
    field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

const CHANNEL: u32 = 1; // base-layer user id == channel id (detail2 §A-2)

fn info(slot: u8, k: &MemberKeys) -> MemberInfo {
    MemberInfo { slot, pk_g: k.pk_g(), pk_b: k.pk_b(), regev_pk: k.regev_pk.clone() }
}

#[test]
fn deposit_backing_gate_reconciles_and_fails_closed() {
    // ---- 1. Fund the channel with a REAL L1 deposit → real base-layer balance proof ----------
    use rand::{SeedableRng as _, rngs::StdRng as RandStdRng};
    let supported_user_counts = vec![1, 4, 512];
    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
    let block_witness_generator =
        BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

    let mut brng = RandStdRng::seed_from_u64(42);
    let channel_id = ChannelId::new(CHANNEL as u64).unwrap();
    let salt = Salt::rand(&mut brng);
    let mut bwg =
        BalanceWitnessGenerator::new(channel_id, salt, block_witness_generator.clone(), &balance_processor)
            .unwrap();

    let deposit_salt = Salt::rand(&mut brng);
    let recipient = calculate_recipient_from_user_id(channel_id, deposit_salt);
    block_witness_generator
        .borrow_mut()
        .add_deposit(Address::rand(&mut brng), recipient, 0, U256::from(50), Bytes32::rand(&mut brng))
        .unwrap();
    block_witness_generator.borrow_mut().add_block(0, &[], 0, Bytes32::default()).unwrap();

    let deposit_data = ReceiveDepositData { receiver: recipient, deposit_salt };
    let dep_witness = bwg.receive_deposit_witness(&deposit_data).unwrap();
    let balance_proof = balance_processor.prove_receive_deposit(&dep_witness).unwrap();
    bwg.commit_receive_deposit(&balance_proof, &dep_witness).unwrap();

    let balance_vd = balance_processor.balance_vd();
    let backing_chain = bwg.get_public_inputs().unwrap().settled_tx_chain;
    let proof_bytes = balance_proof.to_bytes();
    let attestation = ChannelBalanceAttestation { balance_proof: proof_bytes.clone() };

    // ---- 2. Build a Regev channel (channel_id == 1) whose BalanceState carries that chain -------
    use rand010::{SeedableRng as _, rngs::StdRng as ChRng};
    let mut crng = ChRng::seed_from_u64(0xC0FFEE);
    let mkeys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut crng)).collect();
    let members: Vec<MemberInfo> = mkeys.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect();
    let record = build_record(CHANNEL, &members, 0, 0).expect("record");
    let cts: Vec<_> = mkeys
        .iter()
        .map(|k| encrypt_amount(&mut crng, &k.regev_pk, 0).unwrap().0)
        .collect();
    // BACKED genesis: its BalanceState absorbs the SAME settle history the balance proof folded
    // in (§F-1), so it reconciles with the attestation.
    let state =
        assemble_genesis_state_backed(&record, &cts, 50, backing_chain, Bytes32::default())
            .expect("backed genesis");

    // ---- 3. POSITIVE: genuine deposit backing → the gate accepts (co-sign allowed) -------------
    verify_channel_backing(&record, &state, Some(&attestation), &balance_vd)
        .expect("genuine deposit-backed channel must reconcile and be co-signable");

    // ---- 4. FAIL-CLOSED adversarial cases (each MUST refuse to sign) ---------------------------

    // (a) No attestation at all → unbacked channel → refuse.
    assert!(
        verify_channel_backing(&record, &state, None, &balance_vd).is_err(),
        "an UNBACKED channel (no attestation) must be refused"
    );

    // (b) Backing proof is for a DIFFERENT channel → refuse.
    let foreign_members: Vec<MemberInfo> =
        mkeys.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect();
    let foreign_record = build_record(CHANNEL + 1, &foreign_members, 0, 0).expect("foreign record");
    assert!(
        verify_channel_backing(&foreign_record, &state, Some(&attestation), &balance_vd).is_err(),
        "a balance proof for another channel_id must be refused"
    );

    // (c) settled_tx_chain mismatch (stale / wrong settle history) → refuse (§F-1 seam).
    let mut stale = state.clone();
    stale.balance_state.settled_tx_chain = Bytes32::default();
    assert!(
        verify_channel_backing(&record, &stale, Some(&attestation), &balance_vd).is_err(),
        "a BalanceState whose settled_tx_chain != balanceProof.settled_tx_chain must be refused"
    );

    // (d) Tampered proof bytes → deserialization/verification fails → refuse.
    let mut bad_bytes = proof_bytes.clone();
    let last = bad_bytes.len() - 1;
    bad_bytes[last] ^= 0xFF;
    let bad_att = ChannelBalanceAttestation { balance_proof: bad_bytes };
    assert!(
        verify_channel_backing(&record, &state, Some(&bad_att), &balance_vd).is_err(),
        "a tampered/forged backing proof must be refused"
    );

    // ---- 5. FULL PATH: gated co-sign. Each member checks backing BEFORE signing (the live rule) --
    // Backed genesis: gate passes → all 3 members sign → fully signed.
    let mut signed = state.clone();
    for (slot, k) in mkeys.iter().enumerate() {
        verify_channel_backing(&record, &signed, Some(&attestation), &balance_vd)
            .expect("co-signer verifies deposit backing before signing");
        let sig = sign_state(k, slot as u8, &signed).expect("sign");
        add_signature(&mut signed, sig);
    }
    verify_all_signatures(&record, &members, &signed)
        .expect("a genuinely deposit-backed genesis becomes fully member-signed");

    // ---- 6. FAIL-CLOSED at the live gate: an UNBACKED genesis is never signed -------------------
    // Same channel, but assembled WITHOUT deposit backing (settled_tx_chain = 0 ≠ balanceProof's).
    let unbacked = assemble_genesis_state(&record, &cts, 50).expect("unbacked genesis");
    assert!(
        verify_channel_backing(&record, &unbacked, Some(&attestation), &balance_vd).is_err(),
        "an UNBACKED genesis must fail the gate, so no honest member co-signs it"
    );

    // ---- 7. ATOMIC check-and-sign (detail2 §3.1): sign_state_if_backed signs ONLY when the state's
    // settled_tx_chain matches the held intmax balance backing, and never otherwise. ----------------
    assert!(
        sign_state_if_backed(&mkeys[0], 0, &record, &state, &attestation, &balance_vd).is_ok(),
        "check-and-sign must produce a signature for a backed state"
    );
    assert!(
        sign_state_if_backed(&mkeys[0], 0, &record, &unbacked, &attestation, &balance_vd).is_err(),
        "check-and-sign must REFUSE (no signature) when settled_tx_chain does not match the backing"
    );
}
