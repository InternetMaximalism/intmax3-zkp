//! B-2: the inter-channel small-block signature (`channelStateSig`) is verified by a REAL validity
//! proof — no structural placeholder.
//!
//! detail2 §D / §C-7 / §F-2, abstract2 §3.3.2/§3.3.5. A channel is registered with REAL member keys
//! (so the bp's `pk_g` is a genuine member of `member_pubkeys_root`), a block carrying the channel's
//! small block is posted with the post-debit `state_commitment_root = H1'` (detail2 §C-7) and
//! `tx_tree_root = H2`, and the validity proof's `bp_sig_chain` (recursive `ListCircuit` over the bp
//! IMSB single-sigs) VERIFIES the bp's signature over `hash(H1', tx_tree_root)` (the structural
//! atomicity D-3). The transport_proof is gone (abstract2 §3.4 note: the receiver verifies inclusion
//! on L1; inclusion liveness is by force-include) — what is verified here is the genuine
//! channelStateSig, not a `vec![9,9]` stand-in.
//!
//! (The block's tx payload uses the base TxV2 path for tractability; what B-2 proves is the bp IMSB
//! signature binding, which the validity circuit verifies regardless of the tx payload class.)
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    circuits::{
        test_utils::{
            block_witness_generator::{
                BlockTxV2Witness, BlockWitnessGenerator, BlockWitnessGeneratorHandle,
                ChannelMemberKeys,
            },
        },
        validity::block_hash_chain::{
            block_hash_chain_processor::BlockHashChainProcessor, validity_circuit::ValidityCircuit,
        },
    },
    common::{
        balance_state::BalanceState,
        channel_id::ChannelId,
        trees::{transfer_tree::TransferTree, tx_v2_tree::TxV2Tree},
        tx::{TxClass, TxV2},
        u63::BlockNumber,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    poseidon_sig::{circuit::SingleSigCircuit, list::ListCircuit},
    regev::encrypt_amount,
    utils::poseidon_hash_out::PoseidonHashOut,
    wallet_core::{MemberInfo, MemberKeys},
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const CHANNEL: u32 = 1;

fn info(slot: u8, k: &MemberKeys) -> MemberInfo {
    MemberInfo { slot, pk_g: k.pk_g(), pk_b: k.pk_b(), regev_pk: k.regev_pk.clone() }
}

#[test]
fn inter_channel_small_block_sig_is_validity_proven() {
    use rand::{SeedableRng as _, rngs::StdRng as RandRng};
    use rand010::SeedableRng as _;

    let supported = vec![2];
    let block_hash_chain_processor = BlockHashChainProcessor::<F, C, D>::new(&supported);
    let block_chain_vd = block_hash_chain_processor.block_chain_vd();
    let bwgen = BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported));
    let initial_ext_state = bwgen.borrow().current_extended_public_state();

    let channel_id = ChannelId::new(CHANNEL as u64).unwrap();

    // Channel members: REAL wallet keys. Register the channel with EXACTLY these keys so the bp's
    // pk_g the validity proof checks is a genuine member of member_pubkeys_root.
    let mut crng = rand010::rngs::StdRng::seed_from_u64(0xB2);
    let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut crng)).collect();
    let _members: Vec<MemberInfo> = keys.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect();
    let ck = ChannelMemberKeys::from_member_keys(&keys);

    // ----- Registration block (block 1): writes member_pubkeys_root into the channel tree -----
    {
        let mut g = bwgen.borrow_mut();
        g.add_channel_registration_keys(CHANNEL, ck.clone());
        g.add_registration_block(0).expect("registration block");
    }

    // ----- Post-debit H1' (detail2 §C-7): the sender (slot 0) debited `amount`. Build the real
    // post-debit BalanceState and take its h1(). -----
    let pks: Vec<_> = keys.iter().map(|k| k.regev_pk.clone()).collect();
    let post_bal = [45u64, 10, 30]; // slot0 50-5
    let enc: Vec<_> = (0..3).map(|i| encrypt_amount(&mut crng, &pks[i], post_bal[i]).unwrap().0).collect();
    // Decryption Stage 1: the real per-active-slot Regev pk digests (mirrors
    // channel_member.rs:601-605), so H1' matches what production would commit for these members.
    let regev_pk_digests: Vec<Bytes32> =
        keys.iter().map(|k| Bytes32::from(k.regev_pk.poseidon_digest())).collect();
    let post_balance_state = BalanceState {
        channel_id,
        member_count: 3,
        delegate_count: 0,
        enc_balances: BalanceState::pad_enc_balances(&enc),
        regev_pk_digests: BalanceState::pad_regev_pk_digests(&regev_pk_digests),
        settled_tx_chain: Bytes32::default(),
        // This synthetic post-debit state carries a genesis-like (default) settle chain, so its
        // accumulator root is the empty-tree root — keeping H1' internally consistent.
        settled_tx_accumulator_root:
            intmax3_zkp::wallet_core::empty_settled_tx_accumulator_root(),
        state_version: 1,
        pending_adds: BalanceState::pad_pending_adds(&[0, 0, 0]),
    };
    let h1: Bytes32 = post_balance_state.h1();

    // ----- The channel's small block (block 2): tx_tree_root = H2, IMSB state_commitment_root = H1'.
    let mut brng = RandRng::seed_from_u64(7);
    let mut transfer_tree = TransferTree::init();
    transfer_tree.push(intmax3_zkp::common::transfer::Transfer {
        recipient: Bytes32::rand(&mut brng),
        token_index: 0,
        amount: intmax3_zkp::ethereum_types::u256::U256::from(5u32),
        aux_data: Bytes32::default(),
    });
    let transfer_tree_root = transfer_tree.get_root();
    let tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root,
        nonce: 1,
        channel_action_root: PoseidonHashOut::default(),
    };
    let mut tx_v2_tree = TxV2Tree::init();
    tx_v2_tree.update(channel_id.as_u64(), tx_v2);
    let tx_v2_root_h = tx_v2_tree.get_root();
    let tx_tree_root: Bytes32 = tx_v2_root_h.into(); // = H2 (the small block's tx_tree_root)
    let tx_v2_proof = tx_v2_tree.prove(channel_id.as_u64());
    let tx_v2_witness = BlockTxV2Witness {
        tx_v2_indices: vec![channel_id.as_u64(), 0],
        tx_v2s: vec![tx_v2, TxV2::default()],
        tx_v2_merkle_proofs: vec![tx_v2_proof.clone(), tx_v2_proof.clone()],
    };
    {
        let mut g = bwgen.borrow_mut();
        // B-2: bind the REAL H1' into the IMSB the bp signs (hash(H1', tx_tree_root)).
        g.next_imsb_state_commitment_root = Some(h1);
        g.add_block_with_tx_v2(CHANNEL, &[1], 1, tx_tree_root, Some(tx_v2_witness))
            .expect("inter-channel small block");
    }

    // ----- REAL validity proof over [registration block, small block] -----
    let mut prev_block_proof = None;
    let mut last = None;
    {
        let g = bwgen.borrow();
        let total = g.block_number.as_u64();
        for idx in 1..=total {
            let bn = BlockNumber::new(idx).unwrap();
            let witness = g.block_chain_witness.get(&bn).cloned().expect("block witness");
            let init = if prev_block_proof.is_none() { Some(initial_ext_state.clone()) } else { None };
            let proof = block_hash_chain_processor
                .prove_block(init, prev_block_proof.clone(), &witness)
                .expect("block hash chain proof");
            prev_block_proof = Some(proof.clone());
            last = Some(proof);
        }
    }
    let final_block_chain_proof = last.expect("final block chain proof");

    // The bp IMSB signature must be present (non-zero bp_sig_chain) — the small block was signed.
    let bp_sig_chain = bwgen.borrow().current_bp_sig_chain();
    assert_ne!(bp_sig_chain, Bytes32::default(), "the small block's bp IMSB signature must be recorded");

    let single_sig = SingleSigCircuit::new();
    let list_circuit = ListCircuit::new(&single_sig.verifier_data());
    let list_proof = bwgen
        .borrow()
        .build_bp_sig_list_proof(&single_sig, &list_circuit)
        .expect("bp sig list proof");
    assert!(list_proof.is_some(), "a real bp IMSB signature list proof must exist");

    let validity_circuit = ValidityCircuit::<F, C, D>::new(&block_chain_vd, &list_circuit.verifier_data());
    let prover = Address::rand(&mut brng);
    let validity_proof = validity_circuit
        .prove(&final_block_chain_proof, list_proof.as_ref(), prover)
        .expect("validity proof");
    validity_circuit.verify(&validity_proof).expect("verify validity proof");

    // ----- flowReceive3-1 (receiver side): the inter-channel tx is INCLUDED in the small block
    // whose tx_tree_root (= H2) is bound in the validity-proven block — verified DIRECTLY (no
    // transport_proof; abstract2 §3.4 note). (The E-2 channelUpdateZKP + the sender's balanceProof /
    // §F-1 reconciliation are covered in tests/inter_channel_e2e.rs / channel_backing_e2e.rs.) -----
    tx_v2_proof
        .verify(&tx_v2, channel_id.as_u64(), tx_v2_root_h)
        .expect("receiver: TxV2 inclusion in the validity-proven small block (flowReceive3-1)");

    eprintln!(
        "[B-2] OK: REAL validity proof verifies the channel small-block bp signature over \
         hash(H1', tx_tree_root) — H1'={}, tx_tree_root={}.",
        h1.to_hex(),
        tx_tree_root.to_hex()
    );
}
