//! B-2 milestone: the channel small-block signature (`channelStateSig`) is verified by a REAL
//! validity proof — no structural placeholder.
//!
//! SCOPE (B-5d, honest naming): this is NOT a two-channel inter-channel transfer test and there is
//! NO E-2 transfer proof here. It proves exactly ONE thing over a SINGLE channel (CHANNEL = 1):
//! that the block-producer's IMSB small-block signature is bound and verified by the validity
//! circuit's `bp_sig_chain`. The file was previously named `inter_channel_validity_b2.rs`, which
//! read as a 2-channel ("b2") inter-channel test; it is renamed to `small_block_sig_validity.rs` to
//! match what it actually proves. Full two-channel inter-channel flows live in
//! `inter_channel_live.rs` / `inter_channel_cli.rs`.
//!
//! detail2 §D / §C-7 / §F-2, abstract2 §3.3.2/§3.3.5. A channel is registered with REAL member keys
//! (so the bp's `pk_g` is a genuine member of `member_pubkeys_root`), a block carrying the
//! channel's small block is posted with the post-debit `state_commitment_root = H1'` (detail2 §C-7)
//! and `tx_tree_root = H2`, and the validity proof's `bp_sig_chain` (recursive `AggListCircuit`
//! over the per-block N-of-N Falcon aggregates) VERIFIES that EVERY registered member signed the
//! channel's IMCH digest, whose `h2_tag` is this block's `tx_tree_root` (the structural atomicity
//! D-3). The transport_proof is gone (abstract2 §3.4 note: the receiver
//! verifies inclusion on L1; inclusion liveness is by force-include) — what is verified here is the
//! genuine channelStateSig, not a `vec![9,9]` stand-in.
//!
//! (The block's tx payload uses the base TxV2 path for tractability; what B-2 proves is the bp IMSB
//! signature binding, which the validity circuit verifies regardless of the tx payload class.)
#![cfg(not(debug_assertions))]

use std::panic::{AssertUnwindSafe, catch_unwind};

use intmax3_zkp::{
    circuits::{
        test_utils::block_witness_generator::{
            BlockTxV2Witness, BlockWitnessGenerator, BlockWitnessGeneratorHandle, ChannelMemberKeys,
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
    falcon_sig::{agg::FalconAggCircuit, agg_list::AggListCircuit},
    regev::encrypt_amount,
    utils::poseidon_hash_out::PoseidonHashOut,
    wallet_core::{MemberInfo, MemberKeys},
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const CHANNEL: u32 = 1;

fn info(slot: u16, k: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot,
        pk_g: k.pk_g(),
        pk_b: k.pk_b(),
        regev_pk: k.regev_pk.clone(),
    }
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
    let _members: Vec<MemberInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| info(i as u16, k))
        .collect();
    // falcon-sig Phase 4: the member identity registered on L1 is the FALCON pk_g, read off the
    // wallet's own `MemberKeys` (which now carries the single Falcon signing key).
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
    let enc: Vec<_> = (0..3)
        .map(|i| encrypt_amount(&mut crng, &pks[i], post_bal[i]).unwrap().0)
        .collect();
    // Decryption Stage 1: the real per-active-slot Regev pk digests (mirrors
    // channel_member.rs:601-605), so H1' matches what production would commit for these members.
    let regev_pk_digests: Vec<Bytes32> = keys
        .iter()
        .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
        .collect();
    let post_balance_state = BalanceState {
        channel_id,
        member_count: 3,
        delegate_count: 0,
        enc_balances: BalanceState::pad_enc_balances_token0(&enc),
        regev_pk_digests: BalanceState::pad_regev_pk_digests(&regev_pk_digests),
        // B-1b: nonzero per-active-slot L1 exit addresses (validate() rejects zero actives).
        recipients: BalanceState::pad_recipients(
            &(0..3u32)
                .map(|i| {
                    use intmax3_zkp::ethereum_types::u32limb_trait::U32LimbTrait as _;
                    intmax3_zkp::ethereum_types::address::Address::from_u32_slice(
                        &[0x7E57_0000u32 + i; 5],
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>(),
        ),
        settled_tx_chain: Bytes32::default(),
        // This synthetic post-debit state carries a genesis-like (default) settle chain, so its
        // accumulator root is the empty-tree root — keeping H1' internally consistent.
        settled_tx_accumulator_root: intmax3_zkp::wallet_core::empty_settled_tx_accumulator_root(),
        state_version: 1,
        pending_adds: BalanceState::pad_pending_adds_token0(&[0, 0, 0]),
        token_registry: BalanceState::single_token_registry(0),
        token_count: 1,
    };
    let h1: Bytes32 = post_balance_state.h1();

    // ----- The channel's small block (block 2): tx_tree_root = H2, IMSB state_commitment_root =
    // H1'.
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
        new_member_leaves: None,
        // §Q-2: UserTransfer-only slot — no channel action to open.
        channel_action_indices: None,
        channel_actions: None,
        channel_action_merkle_proofs: None,
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
            let witness = g
                .block_chain_witness
                .get(&bn)
                .cloned()
                .expect("block witness");
            let init = if prev_block_proof.is_none() {
                Some(initial_ext_state.clone())
            } else {
                None
            };
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
    assert_ne!(
        bp_sig_chain,
        Bytes32::default(),
        "the small block's bp IMSB signature must be recorded"
    );

    // Phase 4: the span's signature evidence is the REAL N-of-N aggregate list — one
    // `FalconAggCircuit` proof over ALL 3 members' Falcon signatures on the block's IMCH digest,
    // folded by one `AggListCircuit` step.
    let agg_circuit = FalconAggCircuit::<F, C, D>::new();
    let agg_list_circuit = AggListCircuit::<F, C, D>::new(&agg_circuit.verifier_data());
    let list_proof = bwgen
        .borrow()
        .build_agg_sig_list_proof(&agg_circuit, &agg_list_circuit)
        .expect("bp sig list proof");
    assert!(
        list_proof.is_some(),
        "a real N-of-N signature list proof must exist"
    );

    let validity_circuit =
        ValidityCircuit::<F, C, D>::new(&block_chain_vd, &agg_list_circuit.verifier_data());
    let prover = Address::rand(&mut brng);
    let validity_proof = validity_circuit
        .prove(&final_block_chain_proof, list_proof.as_ref(), prover)
        .expect("validity proof");
    validity_circuit
        .verify(&validity_proof)
        .expect("verify validity proof");

    // ----- Phase 4 acceptance (RE-TESTED, not assumed): the D3 gate is COMPUTED, so a prover that
    // applied a signed update cannot verify the span by claiming the signature list is empty.
    //
    // SECURITY: `should_verify_list = (final.bp_sig_chain != 0)` is derived from the block-hash-
    // chain proof's own public inputs, NOT from a prover-supplied flag. This span HAS a signing
    // block, so the gate is on and the dummy proof must fail BOTH the recursive verification at the
    // agg-list VK and the `C == final.bp_sig_chain` equality. If this ever starts succeeding, the
    // N-of-N signature check has become optional — which is exactly the hole §2.1 describes.
    assert_ne!(
        bwgen.borrow().current_bp_sig_chain(),
        Bytes32::default(),
        "precondition: the gate under test is only meaningful for a span that DID sign"
    );
    //
    // An unsatisfiable plonky2 witness surfaces as EITHER an `Err` or a panic inside proving, and
    // "it produced something" is not the question — "does it VERIFY" is. All three outcomes are
    // covered so the assertion cannot pass for the wrong reason.
    let dummy_path = catch_unwind(AssertUnwindSafe(|| {
        validity_circuit.prove(&final_block_chain_proof, None, prover)
    }));
    let rejected = match dummy_path {
        Err(_) => true,
        Ok(Err(_)) => true,
        Ok(Ok(proof)) => validity_circuit.verify(&proof).is_err(),
    };
    assert!(
        rejected,
        "a signed span must NOT be verifiable on the no-signature (dummy) path — the D3 gate is \
         computed from final.bp_sig_chain, so skipping the N-of-N list must be impossible"
    );

    // ----- flowReceive3-1 (receiver side): the inter-channel tx is INCLUDED in the small block
    // whose tx_tree_root (= H2) is bound in the validity-proven block — verified DIRECTLY (no
    // transport_proof; abstract2 §3.4 note). (The E-2 channelUpdateZKP + the sender's balanceProof
    // / §F-1 reconciliation are covered in tests/inter_channel_e2e.rs /
    // channel_backing_e2e.rs.) -----
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

/// Phase 6, block-producer half: the same span, but the producer holds NO key. It consumes the
/// members' existing IMCH cosignatures over the WALLET's own `ChannelState` instead of signing a
/// synthesized preimage locally — and the validity proof still verifies.
///
/// WHY THIS IS THE ACCEPTANCE TEST. Before Phase 6 the harness held every member's `FalconKeys`
/// and called `key.sign(digest)` over a PROJECTED preimage (`epoch: 0`, `close_freeze_nonce: 0`,
/// `state_version` = block number) that no wallet ever held. So the binding
/// "`ChannelState.h2_tag` == the block's `tx_tree_root`" had never been exercised against a real
/// state. Here the state is the real one, the signatures are the members' own, and the block is
/// accepted only if the digest the circuit recomputes from the projected limbs is byte-identical
/// to the one the members signed.
///
/// It also proves aggregation needs no key material: `next_channel_cosign` carries signature
/// blobs and nothing else, and the N-of-N aggregate is still produced and validity-proven.
#[test]
fn block_producer_consumes_real_member_cosignatures() {
    use intmax3_zkp::{
        block_producer::{ProductionBlockProducer, ProductionChannelRegistration},
        common::channel::{ChannelFund, ChannelState},
        wallet_core::{build_record, sign_state},
    };
    use rand::{SeedableRng as _, rngs::StdRng as RandRng};
    use rand010::SeedableRng as _;

    let supported = vec![2];
    let block_hash_chain_processor = BlockHashChainProcessor::<F, C, D>::new(&supported);
    let block_chain_vd = block_hash_chain_processor.block_chain_vd();
    let mut producer = ProductionBlockProducer::new(&supported);
    let initial_ext_state = producer.current_extended_public_state();
    let channel_id = ChannelId::new(CHANNEL as u64).unwrap();

    let mut crng = rand010::rngs::StdRng::seed_from_u64(0xB2);
    let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut crng)).collect();
    // Build the public registration envelope outside the producer, then drop the helper that
    // temporarily references the wallet's keys. The producer receives only the on-chain record
    // and Regev public keys; `holds_local_signing_keys` pins that no fixture fallback leaked in.
    let ck = ChannelMemberKeys::from_member_keys(&keys);
    let reg_record = ck.to_reg_record(CHANNEL);
    let registered_regev_pks = ck.regev_pks.clone();
    drop(ck);
    let public_members: Vec<MemberInfo> = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| MemberInfo {
            slot: slot as u16,
            pk_g: key.pk_g(),
            pk_b: key.pk_b(),
            regev_pk: key.regev_pk.clone(),
        })
        .collect();
    let channel_record = build_record(CHANNEL, &public_members, 0, 0).expect("channel record");
    producer
        .register_channel(
            ProductionChannelRegistration {
                channel_record: channel_record.clone(),
                validity_record: reg_record,
                regev_pks: registered_regev_pks,
            },
            0,
        )
        .expect("public-only production registration");
    assert!(
        !producer.holds_any_local_signing_keys(),
        "the production producer must hold zero member signing keys"
    );

    let pks: Vec<_> = keys.iter().map(|k| k.regev_pk.clone()).collect();
    let post_bal = [45u64, 10, 30];
    let enc: Vec<_> = (0..3)
        .map(|i| encrypt_amount(&mut crng, &pks[i], post_bal[i]).unwrap().0)
        .collect();
    let regev_pk_digests: Vec<Bytes32> = keys
        .iter()
        .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
        .collect();
    let post_balance_state = BalanceState {
        channel_id,
        member_count: 3,
        delegate_count: 0,
        enc_balances: BalanceState::pad_enc_balances_token0(&enc),
        regev_pk_digests: BalanceState::pad_regev_pk_digests(&regev_pk_digests),
        recipients: BalanceState::pad_recipients(
            &(0..3u32)
                .map(|i| Address::from_u32_slice(&[0x7E57_0000u32 + i; 5]).unwrap())
                .collect::<Vec<_>>(),
        ),
        settled_tx_chain: Bytes32::default(),
        settled_tx_accumulator_root: intmax3_zkp::wallet_core::empty_settled_tx_accumulator_root(),
        state_version: 1,
        pending_adds: BalanceState::pad_pending_adds_token0(&[0, 0, 0]),
        token_registry: BalanceState::single_token_registry(0),
        token_count: 1,
    };

    let mut brng = RandRng::seed_from_u64(7);
    let mut transfer_tree = TransferTree::init();
    transfer_tree.push(intmax3_zkp::common::transfer::Transfer {
        recipient: Bytes32::rand(&mut brng),
        token_index: 0,
        amount: intmax3_zkp::ethereum_types::u256::U256::from(5u32),
        aux_data: Bytes32::default(),
    });
    let tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root: transfer_tree.get_root(),
        nonce: 1,
        channel_action_root: PoseidonHashOut::default(),
    };
    let mut tx_v2_tree = TxV2Tree::init();
    tx_v2_tree.update(channel_id.as_u64(), tx_v2);
    let tx_v2_root_h = tx_v2_tree.get_root();
    let tx_tree_root: Bytes32 = tx_v2_root_h.into();
    let tx_v2_proof = tx_v2_tree.prove(channel_id.as_u64());
    let tx_v2_witness = BlockTxV2Witness {
        tx_v2_indices: vec![channel_id.as_u64(), 0],
        tx_v2s: vec![tx_v2, TxV2::default()],
        tx_v2_merkle_proofs: vec![tx_v2_proof.clone(), tx_v2_proof.clone()],
        new_member_leaves: None,
        // §Q-2: UserTransfer-only slot — no channel action to open.
        channel_action_indices: None,
        channel_actions: None,
        channel_action_merkle_proofs: None,
            };

    // THE WALLET'S OWN STATE. `h2_tag` IS this block's tx_tree_root — that equality is what makes
    // the members' signatures an authorization of THIS block. `small_block_number` is the block
    // being posted (2: registration was block 1).
    let wallet_state = ChannelState {
        channel_id,
        epoch: 0,
        small_block_number: 2,
        close_freeze_nonce: 0,
        channel_fund: ChannelFund {
            channel_id,
            amounts: Default::default(),
            intmax_state_root: Bytes32::default(),
        },
        balance_state: post_balance_state.clone(),
        h2_tag: tx_tree_root,
        shared_native_nullifier_root: Bytes32::default(),
        unallocated_confirmed_incoming: Default::default(),
        prev_digest: Bytes32::default(),
        digest: Bytes32::default(),
        member_signatures: Vec::new(),
    }
    .with_computed_digest();

    // The members co-sign it. This is the ONLY place a signing key appears in this test.
    let signatures: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(slot, k)| sign_state(k, slot as u8, &wallet_state).expect("member co-signs"))
        .collect();
    assert_eq!(signatures.len(), 3);

    let mut wallet_state = wallet_state;
    wallet_state.member_signatures = signatures.clone();
    producer
        .produce_cosigned_block(&wallet_state, &[1], 1, tx_tree_root, tx_v2_witness)
        .expect("small block backed by the wallet's own co-signed state");

    // The digest the producer folded is the one the MEMBERS signed — the equality the whole
    // binding rests on, now exercised through the generator rather than assumed.
    {
        let event = producer
            .signature_events()
            .last()
            .expect("a signing block was recorded");
        assert_eq!(
            event.digest,
            wallet_state.signing_digest(),
            "the folded IMCH digest must be the wallet state's own, not a projection"
        );
        assert_eq!(event.witnesses.len(), 3, "one gadget witness per member");
        for (slot, pk) in event.signer_pks.iter().enumerate() {
            assert_eq!(*pk, keys[slot].pk_g(), "slot {slot} identity");
        }
    }

    // ----- REAL validity proof over [registration block, small block] -----
    let mut prev_block_proof = None;
    let mut last = None;
    for idx in 1..=producer.block_number() {
        let bn = BlockNumber::new(idx).unwrap();
        let witness = producer.block_witness(bn).expect("witness");
        let init = if prev_block_proof.is_none() {
            Some(initial_ext_state.clone())
        } else {
            None
        };
        let proof = block_hash_chain_processor
            .prove_block(init, prev_block_proof.clone(), &witness)
            .expect("block hash chain proof");
        prev_block_proof = Some(proof.clone());
        last = Some(proof);
    }
    let final_block_chain_proof = last.expect("final block chain proof");

    let agg_circuit = FalconAggCircuit::<F, C, D>::new();
    let agg_list_circuit = AggListCircuit::<F, C, D>::new(&agg_circuit.verifier_data());
    let list_proof = producer
        .build_agg_sig_list_proof(&agg_circuit, &agg_list_circuit)
        .expect("bp sig list proof");
    assert!(
        list_proof.is_some(),
        "the members' OWN signatures must aggregate — no key material was available to the producer"
    );

    let validity_circuit =
        ValidityCircuit::<F, C, D>::new(&block_chain_vd, &agg_list_circuit.verifier_data());
    let prover = Address::rand(&mut brng);
    let validity_proof = validity_circuit
        .prove(&final_block_chain_proof, list_proof.as_ref(), prover)
        .expect("validity proof over a wallet-signed block");
    validity_circuit
        .verify(&validity_proof)
        .expect("verify validity proof");

    eprintln!(
        "[Phase 6] OK: block producer held NO key; the validity proof verifies the members' own \
         N-of-N over the wallet's ChannelState (h2_tag = tx_tree_root = {}).",
        tx_tree_root.to_hex()
    );
}
