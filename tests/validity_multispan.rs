//! Regression coverage for independently finalized validity spans after the lifetime Falcon
//! signature chain becomes non-zero.
#![cfg(not(debug_assertions))]

use std::panic::{AssertUnwindSafe, catch_unwind};

use intmax3_zkp::{
    circuits::{
        test_utils::block_witness_generator::{BlockTxV2Witness, BlockWitnessGenerator},
        validity::block_hash_chain::{
            block_chain_pis::BlockChainPublicInputs,
            block_hash_chain_processor::BlockHashChainProcessor, validity_circuit::ValidityCircuit,
        },
    },
    common::{
        channel_id::ChannelId,
        trees::tx_v2_tree::TxV2Tree,
        tx::{TxClass, TxV2},
        u63::BlockNumber,
    },
    ethereum_types::{
        address::Address,
        bytes32::{BYTES32_LEN, Bytes32},
        u32limb_trait::U32LimbTrait,
    },
    falcon_sig::{
        agg::{FalconAggCircuit, FalconAggWitness},
        agg_list::{AggListCircuit, agg_list_commitment},
    },
    utils::{conversion::ToU64, poseidon_hash_out::PoseidonHashOut},
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

fn validity_rejects_list(
    circuit: &ValidityCircuit<F, C, D>,
    block_chain_proof: &ProofWithPublicInputs<F, C, D>,
    list_proof: &ProofWithPublicInputs<F, C, D>,
    prover: Address,
) -> bool {
    match catch_unwind(AssertUnwindSafe(|| {
        circuit.prove(block_chain_proof, Some(list_proof), prover)
    })) {
        Err(_) | Ok(Err(_)) => true,
        Ok(Ok(proof)) => circuit.verify(&proof).is_err(),
    }
}

fn agg_list_chain(proof: &ProofWithPublicInputs<F, C, D>) -> Bytes32 {
    Bytes32::from_u32_slice(
        &proof.public_inputs[0..BYTES32_LEN]
            .iter()
            .map(|value| value.0 as u32)
            .collect::<Vec<_>>(),
    )
    .expect("AggList commitment public inputs are a Bytes32")
}

fn tx_v2_witness(nonce: u32) -> (Bytes32, BlockTxV2Witness) {
    let channel = ChannelId::new(1).expect("channel id");
    let tx = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root: PoseidonHashOut::default(),
        nonce,
        channel_action_root: PoseidonHashOut::default(),
    };
    let mut tree = TxV2Tree::init();
    tree.update(channel.as_u64(), tx);
    let root = Bytes32::from(tree.get_root());
    let proof = tree.prove(channel.as_u64());
    (
        root,
        BlockTxV2Witness {
            tx_v2_indices: vec![channel.as_u64(), 0],
            tx_v2s: vec![tx, TxV2::default()],
            // The padding slot is gated off; retaining the real proof there matches the existing
            // fixture convention and avoids an unrelated synthetic tree opening.
            tx_v2_merkle_proofs: vec![proof.clone(), proof],
            new_member_leaves: None,
            // §Q-2: UserTransfer-only slot — no channel action to open.
            channel_action_indices: None,
            channel_actions: None,
            channel_action_merkle_proofs: None,
        },
    )
}

/// Finalized spans are independent recursive block-chain proofs, but `bp_sig_chain` and its
/// AggList proof are lifetime accumulators. Span two therefore starts from span one's non-zero
/// chain and supplies the genesis-rooted list proof extended by its new event. Prefix-only and
/// otherwise valid-but-wrong list proofs must fail the final-chain equality.
#[test]
fn two_independent_spans_bind_the_cumulative_agg_list() {
    let supported_user_counts = vec![2];
    let processor = BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
    let block_chain_vd = processor.block_chain_vd();
    let mut generator = BlockWitnessGenerator::new(&supported_user_counts);
    let genesis = generator.current_extended_public_state();

    // Block 1 registers real fixture members; block 2 is the first signed update.
    generator.add_channel_registration(1);
    generator
        .add_registration_block(1)
        .expect("registration block");
    let (first_tx_root, first_tx_witness) = tx_v2_witness(1);
    generator
        .add_block_with_tx_v2(1, &[1], 2, first_tx_root, Some(first_tx_witness))
        .expect("first signed block");
    assert_eq!(generator.bp_sig_events.len(), 1);

    let mut span_one_chain_proof = None;
    for index in 1..=generator.block_number.as_u64() {
        let block_number = BlockNumber::new(index).expect("block number");
        let witness = generator
            .block_chain_witness
            .get(&block_number)
            .cloned()
            .expect("span-one block witness");
        let initial = span_one_chain_proof.is_none().then(|| genesis.clone());
        span_one_chain_proof = Some(
            processor
                .prove_block(initial, span_one_chain_proof, &witness)
                .expect("span-one block-chain proof"),
        );
    }
    let span_one_chain_proof = span_one_chain_proof.expect("span-one final proof");
    let span_one_final = generator.current_extended_public_state();
    assert_ne!(span_one_final.bp_sig_chain, Bytes32::default());

    let agg = FalconAggCircuit::<F, C, D>::new();
    let agg_list = AggListCircuit::<F, C, D>::new(&agg.verifier_data());
    let event_one = generator.bp_sig_events[0].clone();
    let agg_one = agg
        .prove(&FalconAggWitness {
            message: event_one.digest,
            active: event_one.witnesses.clone(),
        })
        .expect("first Falcon aggregate proof");
    let list_one = agg_list
        .prove_append(&agg_one, Bytes32::default(), &None)
        .expect("first cumulative AggList proof");
    assert_eq!(agg_list_chain(&list_one), span_one_final.bp_sig_chain);

    let validity = ValidityCircuit::<F, C, D>::new(&block_chain_vd, &agg_list.verifier_data());
    let prover = Address::default();
    let span_one_validity = validity
        .prove(&span_one_chain_proof, Some(&list_one), prover)
        .expect("span-one validity proof");
    validity
        .verify(&span_one_validity)
        .expect("span-one validity proof verifies");

    // This is a NEW span: no previous cyclic block-chain proof is supplied. Its initial state is
    // exactly span one's finalized end, whose bp_sig_chain is intentionally non-zero.
    let (second_tx_root, second_tx_witness) = tx_v2_witness(2);
    generator
        .add_block_with_tx_v2(1, &[1], 3, second_tx_root, Some(second_tx_witness))
        .expect("second signed block");
    assert_eq!(generator.bp_sig_events.len(), 2);
    let second_witness = generator
        .block_chain_witness
        .get(&generator.block_number)
        .cloned()
        .expect("span-two block witness");
    let span_two_chain_proof = processor
        .prove_block(Some(span_one_final.clone()), None, &second_witness)
        .expect("independent span-two block-chain proof");

    let span_two_pis = BlockChainPublicInputs::<F, C, D>::from_u64_slice(
        &span_two_chain_proof.public_inputs.to_u64_vec(),
        &block_chain_vd.common.config,
    )
    .expect("parse span-two public inputs");
    assert_eq!(
        span_two_pis.initial_ext_public_state.commitment(),
        span_one_final.commitment(),
        "span two must start at span one's finalized state"
    );
    assert_eq!(
        span_two_pis.initial_ext_public_state.bp_sig_chain, span_one_final.bp_sig_chain,
        "the independent second span must preserve the non-zero lifetime chain"
    );

    let event_two = generator.bp_sig_events[1].clone();
    let agg_two = agg
        .prove(&FalconAggWitness {
            message: event_two.digest,
            active: event_two.witnesses.clone(),
        })
        .expect("second Falcon aggregate proof");
    let list_two = agg_list
        .prove_append(
            &agg_two,
            span_one_final.bp_sig_chain,
            &Some(list_one.clone()),
        )
        .expect("extend the genesis-rooted AggList proof");
    let expected_lifetime_chain = agg_list_commitment(&[event_one.entry(), event_two.entry()]);
    assert_eq!(agg_list_chain(&list_two), expected_lifetime_chain);
    assert_eq!(
        span_two_pis.ext_public_state.bp_sig_chain, expected_lifetime_chain,
        "the second span's final state must bind the complete lifetime list"
    );

    let span_two_validity = validity
        .prove(&span_two_chain_proof, Some(&list_two), prover)
        .expect("span-two validity proof with non-zero initial chain");
    validity
        .verify(&span_two_validity)
        .expect("span-two validity proof verifies");

    assert!(
        validity_rejects_list(&validity, &span_two_chain_proof, &list_one, prover),
        "a valid prefix proof truncated before span two must be rejected"
    );

    // This proof is independently valid at the AggList VK, but starts at genesis with event two
    // and omits event one. It tests the final-chain equality rather than malformed proof bytes.
    let wrong_suffix_only = agg_list
        .prove_append(&agg_two, Bytes32::default(), &None)
        .expect("valid but wrong suffix-only AggList proof");
    agg_list
        .verifier_data()
        .verify(wrong_suffix_only.clone())
        .expect("wrong-list precondition: proof itself is valid at the AggList VK");
    assert_ne!(agg_list_chain(&wrong_suffix_only), expected_lifetime_chain);
    assert!(
        validity_rejects_list(&validity, &span_two_chain_proof, &wrong_suffix_only, prover),
        "a valid AggList proof for the wrong lifetime history must be rejected"
    );
}
