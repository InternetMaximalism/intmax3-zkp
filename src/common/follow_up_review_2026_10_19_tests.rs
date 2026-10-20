//! Regressions for the follow-up soundness reviews of `src/common`, `src/utils` and
//! `src/ethereum_types` (reports dated 2026-10-17, consolidated 2026-10-19). One test per finding
//! that was still open on this branch; COMMON-01 (U63 ordering) is covered by
//! `common::u63::comparator_tests`.

use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig,
    },
};

use crate::{
    common::{
        channel_id::ChannelId,
        public_state::{FullPublicState, PublicState, PublicStateTarget},
        tx::{ChannelAction, ChannelActionKind, Tx, TxV2},
        u63::U63,
        withdrawal::Withdrawal,
    },
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        hash_chain::chain_end_circuit::ChainEndProofPublicInputs,
        leafable::Leafable as _,
        poseidon_hash_out::{GOLDILOCKS_ORDER, PoseidonHashOut},
        trees::{
            get_root::{get_merkle_root_from_leaves, get_merkle_root_from_leaves_circuit},
            incremental_merkle_tree::IncrementalMerkleTree,
            indexed_merkle_tree::IndexedMerkleTree,
        },
    },
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

/// COMMON-02: deserialization goes through `U63::new`.
#[test]
fn u63_json_rejects_values_the_constructor_rejects() {
    assert!(serde_json::from_str::<U63>("9223372036854775807").is_ok(), "2^63 - 1 is a U63");
    assert!(serde_json::from_str::<U63>("9223372036854775808").is_err(), "2^63 is not a U63");
    assert!(serde_json::from_str::<U63>("18446744073709551615").is_err(), "u64::MAX is not a U63");
    let max = U63::new((1u64 << 63) - 1).unwrap();
    let json = serde_json::to_string(&max).unwrap();
    assert_eq!(serde_json::from_str::<U63>(&json).unwrap(), max, "wire format unchanged");
}

/// COMMON-03: no `as u32` aliasing of `2^32` in the Tx / TxV2 / ChannelAction decoders.
#[test]
fn tx_numeric_decoders_reject_words_above_u32() {
    let mut tx = Tx::default().to_u64_vec();
    assert!(Tx::from_u64_slice(&tx).is_ok());
    tx[4] = 1u64 << 32;
    assert!(Tx::from_u64_slice(&tx).is_err(), "nonce 2^32 must not decode as 0");

    let mut v2 = TxV2::default().to_u64_vec();
    assert!(TxV2::from_u64_slice(&v2).is_ok());
    v2[0] = 1u64 << 32;
    assert!(TxV2::from_u64_slice(&v2).is_err(), "class 2^32 must not decode as UserTransfer");
    let mut v2 = TxV2::default().to_u64_vec();
    v2[5] = 1u64 << 32;
    assert!(TxV2::from_u64_slice(&v2).is_err(), "nonce 2^32 must not decode as 0");

    let mut action = ChannelAction {
        kind: ChannelActionKind::InterChannelSend,
        source_channel_id: ChannelId::new(5).unwrap(),
        destination_channel_id: ChannelId::new(7).unwrap(),
        ..ChannelAction::default()
    }
    .to_u64_vec();
    assert!(ChannelAction::from_u64_slice(&action).is_ok());
    action[0] = 1u64 << 32;
    assert!(
        ChannelAction::from_u64_slice(&action).is_err(),
        "kind 2^32 must not decode as InterChannelSend"
    );
}

/// COMMON-05: a ChannelClose action (zero destination sentinel) round-trips; a send with a zero
/// destination is still refused.
#[test]
fn channel_close_action_round_trips_and_zero_destination_sends_are_refused() {
    let close = ChannelAction {
        kind: ChannelActionKind::ChannelClose,
        source_channel_id: ChannelId::new(5).unwrap(),
        destination_channel_id: ChannelId::dummy(),
        ..ChannelAction::default()
    };
    let decoded = ChannelAction::from_u64_slice(&close.to_u64_vec())
        .expect("a valid close action must decode");
    assert_eq!(decoded.kind, ChannelActionKind::ChannelClose);
    assert_eq!(decoded.destination_channel_id, ChannelId::dummy());

    let mut nonzero_close = close.to_u64_vec();
    nonzero_close[2] = 9;
    assert!(
        ChannelAction::from_u64_slice(&nonzero_close).is_err(),
        "a close must carry the zero sentinel"
    );
    let mut send = close.to_u64_vec();
    send[0] = ChannelActionKind::InterChannelSend.as_u32() as u64;
    assert!(
        ChannelAction::from_u64_slice(&send).is_err(),
        "a send with destination 0 must still be refused"
    );
}

/// COMMON-04: native and circuit padded PublicState trees agree.
#[test]
fn public_state_padded_tree_roots_agree_between_native_and_circuit() {
    let leaf = PublicState::default();
    let leaves = vec![leaf.clone(), leaf.clone(), leaf.clone()];
    let native = get_merkle_root_from_leaves(2, &leaves).unwrap();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets: Vec<PublicStateTarget> = leaves
        .iter()
        .map(|l| PublicStateTarget::constant(&mut builder, l))
        .collect();
    let root_t = get_merkle_root_from_leaves_circuit::<F, C, D, PublicStateTarget>(
        &mut builder, 2, &targets,
    );
    builder.register_public_inputs(&root_t.elements);
    let data = builder.build::<C>();
    let proof = data.prove(PartialWitness::new()).unwrap();
    let circuit_root: Vec<u64> = proof.public_inputs.iter().map(|x| x.to_canonical_u64()).collect();
    assert_eq!(circuit_root, native.to_u64_vec(), "circuit padding must use the native empty leaf");
}

/// COMMON-06: the Result-returning decoder returns an error instead of asserting.
#[test]
fn withdrawal_from_u64_slice_returns_an_error_for_an_oversized_limb() {
    let mut words: Vec<u64> = Withdrawal::default()
        .to_u32_vec()
        .iter()
        .map(|&x| x as u64)
        .collect();
    assert!(Withdrawal::from_u64_slice(&words).is_ok());
    words[0] = 1u64 << 32;
    assert!(Withdrawal::from_u64_slice(&words).is_err());
}

/// COMMON-07: a refused block leaves the public state exactly as it was.
#[test]
fn full_public_state_add_block_err_is_atomic() {
    let mut state = FullPublicState::new(&[1]);
    let before = (
        state.block_number,
        state.blocks.len(),
        state.block_hash_chain,
        state.public_state_tree.get_root(),
    );
    assert!(
        state.add_block_with_channel(0, &[1], 0, Bytes32::default()).is_err(),
        "channel 0 with a nonzero key id must be refused"
    );
    let after = (
        state.block_number,
        state.blocks.len(),
        state.block_hash_chain,
        state.public_state_tree.get_root(),
    );
    assert_eq!(before, after, "an Err must not advance the public state");
}

/// UTILS-01 (indexed wrapper): a decoded indexed tree must carry its sentinel.
#[test]
fn indexed_merkle_tree_json_without_the_sentinel_is_rejected() {
    let fresh = IndexedMerkleTree::new(2);
    let json = serde_json::to_string(&fresh).unwrap();
    let decoded: IndexedMerkleTree = serde_json::from_str(&json).expect("constructor output decodes");
    assert_eq!(decoded.get_root(), fresh.get_root());
    assert!(
        serde_json::from_str::<IndexedMerkleTree>(r#"{"height":2,"leaves":[]}"#).is_err(),
        "a tree without the sentinel at index 0 is not a constructor-reachable state"
    );
}

/// UTILS-02: a proof does not verify at an index outside its domain.
#[test]
fn merkle_proof_rejects_an_index_outside_the_tree_domain() {
    let mut tree = IncrementalMerkleTree::<Bytes32>::new(2);
    let leaf = Bytes32::from_u32_slice(&[7; 8]).unwrap();
    tree.push(leaf);
    let root = tree.get_root();
    let proof = tree.prove(0);
    proof.verify(&leaf, 0, root).expect("in-domain index verifies");
    assert!(proof.verify(&leaf, 4, root).is_err(), "index 4 aliases index 0 in a height-2 tree");
}

/// UTILS-03: the numeric constructor requires canonical Goldilocks limbs.
#[test]
fn poseidon_hash_out_from_u64_slice_rejects_noncanonical_limbs() {
    assert!(PoseidonHashOut::from_u64_slice(&[GOLDILOCKS_ORDER - 1, 0, 0, 0]).is_ok());
    assert!(PoseidonHashOut::from_u64_slice(&[GOLDILOCKS_ORDER, 0, 0, 0]).is_err());
    assert!(PoseidonHashOut::from_u64_slice(&[0, 0, 0, u64::MAX]).is_err());
}

/// UTILS-04: the chain-end decoder returns an error instead of asserting.
#[test]
fn chain_end_public_inputs_from_u64_slice_returns_an_error_for_an_oversized_limb() {
    let mut words = vec![0u64; 13];
    assert!(ChainEndProofPublicInputs::from_u64_slice(&words).is_ok());
    words[0] = 1u64 << 32;
    assert!(ChainEndProofPublicInputs::from_u64_slice(&words).is_err());
}

/// ETH-02: witness extraction refuses an oversized limb instead of truncating it.
#[test]
fn get_witness_refuses_an_oversized_limb() {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let target = Bytes32Target::new(&mut builder, false);
    let mut pw = PartialWitness::new();
    for (i, t) in target.to_vec().iter().enumerate() {
        let value = if i == 7 { (1u64 << 32) + 7 } else { 0 };
        pw.set_target(*t, F::from_canonical_u64(value)).unwrap();
    }
    let extracted: Result<Bytes32, _> = target.get_witness(&pw);
    assert!(extracted.is_err(), "2^32 + 7 must not extract as 7");
}
