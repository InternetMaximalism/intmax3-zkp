//! PHASE 5 — proof that the §2.1 hole is CLOSED (`doc/tasks/small-block-nofn-design.md` §9).
//!
//! Phases 0-4 showed the new constraints HOLD. That is a different claim from "the old attack is
//! dead", and only the second one justifies the change. This module makes the second claim, and it
//! is deliberately an END-TO-END construction rather than a unit test of a constraint: §2.1 is a
//! five-step chain, four of whose steps are *supposed* to remain unblocked, and a fix is only
//! interesting if it kills the one step it targets while the other four still work. A test that
//! merely showed "some proof failed somewhere" would not distinguish a fix from a regression.
//!
//! ## The two halves of the evidence, and where the other half lives
//!
//! Step 2 of the Phase 5 recipe — "on the PRE-change code path, assert the attack SUCCEEDS" —
//! cannot run here: Phase 3 (`2459aa6`) removed the code that had the hole. It was run against the
//! REAL old code in a `git worktree` at `c2b69fb` (the last commit before Phase 3), and the source
//! it was run with is kept verbatim at
//! `doc/tasks/small-block-nofn-phase5-pre-change-attack.rs`, with its reproduction recipe. RESULT
//! (2026-08-15, 108 s, 11.49 GB peak): the attack **succeeded** end to end — one cosigner, holding
//! only their own Falcon key and the channel's `prev_private_state`, produced a verifying
//! validity proof over a block they alone signed and a verifying withdrawal proof paying the
//! channel's entire 10-unit pool (6 deposited by member 1, 4 by member 2, 0 by the attacker) to an
//! L1 address of their choosing, with `aux_data = 0`.
//!
//! This module is the other half: the SAME construction, at HEAD, where step 3 must die.
//!
//! ## What "die" means, precisely, and why three cases
//!
//! The attacker holds one real Falcon key and can mint as many NEW keys as they like; what they
//! cannot do is produce the other members' signatures. There are exactly three shapes of signing
//! block available to them, and each is refused by a different named constraint:
//!
//! | shape | what it claims | refused by |
//! |---|---|---|
//! | A1 | `signer_count = 1` over the channel's real member set | `2 <= signer_count` (§5.4 item 2) |
//! | A2 | `signer_count = 2` over {attacker, a key the attacker just minted} — BOTH signatures genuinely producible | the member-root connect (§5.4 item 5) |
//! | A3 | `signer_count = 3` over the real set, without the signatures | `FalconAggCircuit`'s unconditional norm bound, and `C == final.bp_sig_chain` (`validity_circuit.rs`) |
//!
//! A2 is the load-bearing one. It is the shape the §2.1 attacker actually reaches for once a floor
//! exists, and nothing about the signatures stops it — the attacker really can sign twice. Only
//! the fact that the member set is RECOMPUTED and connected to the channel's committed
//! `member_pubkeys_root` refuses it. That is the constraint the whole change exists to add.
//!
//! ## Attribution discipline
//!
//! Every refusal below is pinned the way Phase 3 pins its negatives: the strict native mirror must
//! reject and its message must NAME the constraint, and then the circuit must ALSO reject when fed
//! the public inputs the UNCHECKED mirror produces — so the failure is attributable to the
//! in-circuit constraint and not to the native restatement, a public-input mismatch or a malformed
//! witness. Each case additionally asserts the isolation it depends on (that the OTHER rules are
//! satisfied by that witness), and the honest 3-of-3 control proves first, so a refusal can never
//! be blamed on the witness's shape.

use std::panic::{AssertUnwindSafe, catch_unwind};

use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    block_hash_chain_processor::{BlockHashChainProcessor, BlockHashChainProcessorWitness},
    ext_public_state::ExtendedPublicState,
    update_channel_tree::{UpdateUserCircuit, UpdateUserTree},
    validity_circuit::ValidityCircuit,
};
use crate::{
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
        trees::{
            key_tree::{MemberLeaf, MemberTree},
            transfer_tree::TransferTree,
            tx_tree::TxTree,
            tx_v2_tree::TxV2Tree,
        },
        tx::{Tx, TxClass, TxV2},
        u63::BlockNumber,
    },
    constants::MAX_SIG_CLUSTER,
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    falcon_sig::{
        FalconKeys,
        agg::{FalconAggCircuit, FalconAggWitness},
        agg_list::{AggListCircuit, AggListEntry, agg_list_commitment},
        gadget::FalconSigGadgetWitness,
    },
    utils::{conversion::ToU64 as _, poseidon_hash_out::PoseidonHashOut},
};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

/// The channel under attack: three registered cosigners, the attacker is slot 0.
const CHANNEL: u32 = 1;
const MEMBER1_FUNDS: u32 = 6;
const MEMBER2_FUNDS: u32 = 4;
/// The attacker contributed nothing; the theft is the whole pool.
const THEFT: u32 = MEMBER1_FUNDS + MEMBER2_FUNDS;

/// Rebuild the `UpdateUserTree` for a block EXACTLY as `BlockHashChainProcessor::prove_block`
/// does, so a case can tamper with one field of the attacker's own block rather than inventing a
/// synthetic one. Only used for signing blocks, whose witness carries every optional field.
fn update_tree_for(
    prev_ext: &ExtendedPublicState,
    w: &BlockHashChainProcessorWitness,
) -> UpdateUserTree {
    UpdateUserTree {
        prev_block_hash_chain: prev_ext.block_hash_chain,
        prev_account_tree_root: prev_ext.inner.account_tree_root,
        block_number: prev_ext.inner.block_number.add(1).expect("block number"),
        block: w.block.clone(),
        prev_account_leaves: w.prev_account_leaves.clone(),
        user_merkle_proofs: w.user_merkle_proofs.clone(),
        send_merkle_proofs: w.send_merkle_proofs.clone(),
        prev_bp_sig_chain: prev_ext.bp_sig_chain,
        member_leaves: w
            .member_leaves
            .clone()
            .expect("a signing block carries its member set"),
        signer_count: w
            .signer_count
            .expect("a signing block carries signer_count"),
        member_regev_pks: w.member_regev_pks.clone().expect("member regev pks"),
        channel_state_fields: w.channel_state_fields.clone().expect("IMCH limbs"),
        tx_v2_indices: w.tx_v2_indices.clone().expect("tx_v2 indices"),
        tx_v2s: w.tx_v2s.clone().expect("tx_v2s"),
        tx_v2_merkle_proofs: w.tx_v2_merkle_proofs.clone().expect("tx_v2 proofs"),
        channel_action_indices: vec![0; w.block.num_users as usize],
        channel_actions: vec![Default::default(); w.block.num_users as usize],
        channel_action_merkle_proofs: vec![
            crate::common::trees::tx_v2_tree::ChannelActionMerkleProof::dummy(
                crate::constants::TX_TREE_HEIGHT,
            );
            w.block.num_users as usize
        ],
    }
}

/// Assert the CIRCUIT refuses `tree`, without letting the native mirror's restatement of the same
/// rule mask it (the Phase-3 pattern, `update_channel_tree`'s `assert_refused`): the strict mirror
/// must reject NAMING `expected_reason`, and the circuit must then also refuse the witness when
/// handed the public inputs the unchecked mirror would have produced anyway.
fn assert_refused(
    circuit: &UpdateUserCircuit<F, C, D>,
    tree: &UpdateUserTree,
    expected_reason: &str,
) {
    let message = match tree.to_public_inputs() {
        Ok(_) => panic!("the native mirror accepted a witness the circuit must refuse"),
        Err(e) => e.to_string(),
    };
    assert!(
        message.contains(expected_reason),
        "native mirror refused for the wrong reason: got {message:?}, expected {expected_reason:?}"
    );
    let pis = tree
        .to_public_inputs_unchecked()
        .expect("the unchecked mirror computes public inputs for any witness");
    assert!(
        circuit.prove_with_public_inputs(tree, &pis).is_err(),
        "the CIRCUIT proved a witness it must refuse ({expected_reason})"
    );
}

/// True iff `tree`'s witnessed member leaves recompute to the channel's committed
/// `member_pubkeys_root` — the isolation predicate the cases below assert explicitly, so each
/// refusal can be attributed to one rule.
fn member_root_matches(tree: &UpdateUserTree) -> bool {
    let mut recomputed = MemberTree::init();
    for leaf in tree.member_leaves.iter() {
        recomputed.push(leaf.clone());
    }
    recomputed.get_root() == tree.prev_account_leaves[0].member_pubkeys_root
}

#[cfg_attr(debug_assertions, ignore = "run with --release")]
#[test]
fn the_2_1_attack_is_dead() {
    let t0 = std::time::Instant::now();
    let supported_user_counts = vec![2];

    let block_hash_chain_processor =
        BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
    let block_chain_vd = block_hash_chain_processor.block_chain_vd();
    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
    let balance_vd = balance_processor.balance_vd();
    let bwgen =
        BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

    let mut rng = StdRng::seed_from_u64(0x2_1_A7_7A);
    let channel_id = ChannelId::new(CHANNEL as u64).expect("channel id");
    let salt = Salt::rand(&mut rng);

    // The base-layer account of a channel IS the channel, and its `FullPrivateState` is the
    // `prev_private_state` that — per §2.1 — EVERY cosigner holds. One participant, holding this
    // state and their own Falcon key and nothing else.
    let mut attacker_state =
        BalanceWitnessGenerator::new(channel_id, salt, bwgen.clone(), &balance_processor)
            .expect("the attacker's copy of the channel's private state");
    let initial_ext_state = bwgen.borrow().current_extended_public_state();

    // ---- Block 1: registration, three cosigners. The attacker is slot 0. ----------------------
    let members = {
        let mut g = bwgen.borrow_mut();
        let keys = g.add_channel_registration(CHANNEL);
        g.add_registration_block(0).expect("registration block");
        keys
    };
    assert_eq!(
        members.falcon_keys.len(),
        3,
        "the attack is only interesting against a channel with other members to rob"
    );

    // ---- Block 2: the OTHER TWO members fund the channel. The attacker funds nothing. ---------
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

    // ---- §2.1 STEP 1 — STILL UNBLOCKED, and that is correct. ----------------------------------
    //
    // G4 says no existing check is weakened; it says nothing about ADDING one to the spend
    // circuit, and the design deliberately does not (§3: the fix is at the block, not the spend).
    // Asserting that step 1 still works is what makes the Phase 5 claim precise — the change kills
    // step 3 ONLY. `SpendWitness` still has no key target and no signature target
    // (`spend_circuit.rs:111-119`), and the sole economic constraint is `prev_balance >= amount`
    // per asset leaf, with the attacker choosing the leaves.
    let attacker_l1 = Address::from_u32_slice(&[0xdead_beef; 5]).expect("attacker L1 address");
    let theft = Transfer {
        recipient: calculate_recipient_from_address(attacker_l1),
        token_index: 0,
        amount: U256::from(THEFT),
        // SECURITY (§2.1): `aux_data = 0` disarms BOTH would-be second factors with one knob — the
        // IMPW gate at `IntmaxRollup.sol:1512` only fires when `auxData != 0`, and
        // `send_tx_circuit.rs:293` folds nothing into `settled_tx_chain` when it is zero, so the
        // close-time chain equality never sees the theft either. Unchanged by this phase; recorded
        // here because it is what makes the withdrawal below payable without any co-operation.
        aux_data: Bytes32::default(),
    };
    let spend_witness = attacker_state
        .spend_witness(&[theft.clone()])
        .expect("spend witness");
    let spend_proof = spend_circuit
        .prove(&spend_witness)
        .expect("STEP 1 is still unblocked — the fix is at step 3, not here");

    // ---- The theft block. -----------------------------------------------------------------
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

    // The ext state the theft block will be proved against — captured BEFORE the block is added,
    // so the `UpdateUserTree` rebuilt below is byte-for-byte the one `prove_block` assembles.
    let pre_theft_ext = bwgen.borrow().current_extended_public_state();
    {
        let mut g = bwgen.borrow_mut();
        // The generator now signs a signing block with EVERY member's real Falcon key. That is the
        // HONEST block: the one that exists if all three members agree. It is built here as the
        // control — the attacker's variants below differ from it only in the signer set.
        g.add_block_with_tx_v2(
            CHANNEL,
            &[1],
            1,
            theft_tx_tree_root,
            Some(BlockTxV2Witness {
                tx_v2_indices: vec![channel_id.as_u64(), 0],
                tx_v2s: vec![tx_v2, TxV2::default()],
                tx_v2_merkle_proofs: vec![tx_v2_merkle_proof.clone(), tx_v2_merkle_proof.clone()],
            }),
        )
        .expect("the theft block");
    }
    let theft_block_number = bwgen.borrow().block_number;
    let honest_witness = bwgen
        .borrow()
        .block_chain_witness
        .get(&theft_block_number)
        .cloned()
        .expect("the theft block's witness");
    let sig_event = bwgen.borrow().bp_sig_events[0].clone();
    assert_eq!(
        sig_event.witnesses.len(),
        3,
        "post-change a signing block carries N signatures, not one"
    );
    let imch_digest = sig_event.digest;

    // ---- §2.1 STEP 2 — STILL UNBLOCKED. -------------------------------------------------------
    let send_tx_witness = attacker_state
        .send_tx_witness(&SendTxData {
            spend_proof: spend_proof.clone(),
            tx_tree_root: theft_tx_tree_root,
            tx: tx.clone(),
            tx_merkle_proof: tx_merkle_proof.clone(),
            tx_v2: Some(tx_v2),
            tx_v2_merkle_proof: Some(tx_v2_merkle_proof.clone()),
            transfer: theft.clone(),
            transfer_merkle_proof: transfer_merkle_proof.clone(),
        })
        .expect("send tx witness");
    let balance_proof = balance_processor
        .prove_send_tx(&send_tx_witness)
        .expect("STEP 2 is still unblocked — no member signature is referenced here either");
    attacker_state
        .commit_send_tx(&balance_proof, &send_tx_witness, &spend_witness)
        .expect("commit send tx");

    // ---- §2.1 STEPS 4-5 — STILL UNBLOCKED, GIVEN a settled block. -----------------------------
    //
    // This is the part that makes the whole argument load-bearing rather than incidental: the
    // withdrawal machinery has NOT been taught to reject this theft, and it never will be. Given a
    // block carrying `theft_tx_tree_root`, it pays out. Everything therefore rests on step 3 being
    // unreachable, which is what the rest of this test establishes.
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
    let single_withdrawal_proof = single_withdrawal_circuit
        .prove(&single_withdrawal_witness)
        .expect("STEP 4 is still unblocked given a settled block");
    single_withdrawal_circuit
        .data
        .verify(single_withdrawal_proof.clone())
        .expect("STEP 4: verify");
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
        .expect("STEP 5 is still unblocked");
    withdrawal_processor
        .withdrawal_vd()
        .verify(withdrawal_proof)
        .expect("STEP 5: verify");
    let withdrawal = SingleWithdawalPublicInputs::from_u64_slice(
        &single_withdrawal_proof.public_inputs[..SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN].to_u64_vec(),
    )
    .expect("parse the withdrawal the proof authorizes")
    .withdrawal;
    assert_eq!(withdrawal.recipient, attacker_l1);
    assert_eq!(withdrawal.amount, U256::from(THEFT));
    assert_eq!(withdrawal.aux_data, Bytes32::default());

    // ══ §2.1 STEP 3 — where the attack now dies. ═══════════════════════════════════════════════

    let update_circuit = UpdateUserCircuit::<F, C, D>::new(2);
    let honest_tree = update_tree_for(&pre_theft_ext, &honest_witness);

    // CONTROL. The honest 3-of-3 block proves. Every refusal below therefore tracks the SIGNER SET
    // the attacker tampered with, and not the shape of this block, the theft transfer, the tx
    // binding, the Regev binding or the public-input layout.
    assert!(member_root_matches(&honest_tree));
    assert_eq!(honest_tree.signer_count, 3);
    honest_tree
        .to_public_inputs()
        .expect("control: the honest witness passes the native mirror");
    update_circuit
        .prove(&honest_tree)
        .expect("control: the honest 3-of-3 block proves");

    // ---- A1: `signer_count = 1` over the channel's real member set. ---------------------------
    //
    // The literal §2.1 block, restated in the post-change witness shape: ONE signature, the
    // channel's own registered members. NAMED CONSTRAINT: the `2 <= signer_count <= MAX_SIG_CLUSTER`
    // floor (`update_channel_tree.rs`, design §5.4 item 2) — asserted IN-CIRCUIT rather than
    // natively precisely so that the 1-of-N aggregate, which `FalconAggCircuit` itself permits, is
    // inapplicable to a block.
    //
    // ISOLATION, stated honestly: this witness ALSO violates the padding rule (slots 1 and 2 hold
    // real members at or above `signer_count = 1`), so the floor is not the only rule it breaks.
    // It cannot be isolated further — a one-member channel cannot be registered
    // (`channel_reg_step` range-checks `member_count` to `[2, 16]`), so there is no witness that
    // breaks the floor ALONE against a really-registered channel. The isolated form of the floor
    // is Phase 3's `a_single_signer_is_unprovable`, which fabricates a one-member channel for that
    // purpose. What matters here is that this shape — the attacker's actual shape — is refused,
    // and A2 below is the version with nothing left over.
    let mut a1 = honest_tree.clone();
    a1.signer_count = 1;
    assert!(
        member_root_matches(&a1),
        "A1 keeps the real member leaves, so the root connect is NOT what refuses it"
    );
    assert_refused(&update_circuit, &a1, "out of range 2..=16");

    // ---- A2: two signatures the attacker can genuinely produce. -------------------------------
    //
    // THE LOAD-BEARING CASE. Once a floor exists, a §2.1 attacker does not stop — they mint a
    // second key and sign twice. Both signatures below are REAL and are verified natively here, so
    // nothing about the signature machinery refuses this block: `FalconAggCircuit` would aggregate
    // them happily (it deliberately does not enforce membership or distinctness —
    // `falcon_sig::agg`: "Deduplication / pk-in-member-set checks are CONSUMER obligations").
    //
    // NAMED CONSTRAINT: the member-root connect (design §5.4 item 5) — the recomputed
    // `member_pubkeys_root` over the 16 witnessed leaves is connected to the channel leaf's
    // COMMITTED root. This is the constraint the whole change exists to add, and this case is
    // where the consumer obligation `falcon_sig::agg` delegates is discharged.
    //
    // ISOLATION: the floor is satisfied (2 is in range), the padding rule is satisfied (slots 0-1
    // carry keys, 2..16 are empty), the bp slot is an active slot and its Regev binding is
    // untouched. Only the root connect can refuse this witness, and it is asserted to differ.
    let sock_puppet = FalconKeys::from_seed([0x5c; 32]);
    let attacker_key = &members.falcon_keys[0];
    for (label, key) in [("attacker", &**attacker_key), ("sock puppet", &sock_puppet)] {
        let sig = key.sign(imch_digest);
        assert!(
            crate::falcon_sig::verify(&key.pk_coefficients(), imch_digest, &sig),
            "A2's premise: the attacker really can produce the {label} signature"
        );
    }
    let mut a2 = honest_tree.clone();
    a2.signer_count = 2;
    a2.member_leaves[1] = MemberLeaf {
        pk_g: sock_puppet.pk_g().try_into().expect("canonical pk_g"),
        pk_b: a2.member_leaves[1].pk_b,
        regev_pk_digest: a2.member_leaves[1].regev_pk_digest,
    };
    // Slot 2's real member must be blanked, or the padding rule (not the root connect) would be
    // the first thing to refuse — the isolation this case depends on.
    a2.member_leaves[2] = MemberLeaf::default();
    assert!(
        !member_root_matches(&a2),
        "A2's whole point: a member set the attacker controls is not the REGISTERED set"
    );
    assert!((2..=MAX_SIG_CLUSTER as u32).contains(&a2.signer_count));
    for (slot, leaf) in a2.member_leaves.iter().enumerate() {
        if slot < a2.signer_count as usize {
            assert_ne!(
                leaf.pk_g,
                PoseidonHashOut::default(),
                "A2 slot {slot} must be active"
            );
        } else {
            assert_eq!(*leaf, MemberLeaf::default(), "A2 slot {slot} must be empty");
        }
    }
    assert_refused(
        &update_circuit,
        &a2,
        "does not match the channel leaf's committed root",
    );

    // ---- A3: claim the true `signer_count = 3` and hope nobody checks the signatures. ---------
    //
    // `update_channel_tree` accepts this witness — it is the honest control above, and it MUST
    // accept, because that circuit does not see signatures at all; it only states what must be
    // proven elsewhere. The refusal is one layer up, and there are two of them.
    //
    // A3a. Aggregate with the victims' REAL public polynomials and signatures the attacker made
    //      with their OWN key. NAMED CONSTRAINT: `FalconLeafCircuit`'s UNCONDITIONAL Falcon norm
    //      bound (`falcon_sig::agg` — "there is no `verify` gate wire here at all"), so a leaf
    //      proof exists only if a genuine signature does. The control for this case is the honest
    //      aggregate built further down (`build_agg_sig_list_proof`), which runs the SAME
    //      `agg_circuit.prove` over the same three members and the same digest and succeeds — so
    //      the refusal here tracks the SIGNATURES and not the aggregate's shape or arity.
    let agg_circuit = FalconAggCircuit::<F, C, D>::new();
    let agg_list_circuit = AggListCircuit::<F, C, D>::new(&agg_circuit.verifier_data());
    let attacker_sig = attacker_key.sign(imch_digest);
    let forged = FalconAggWitness {
        message: imch_digest,
        active: (0..3)
            .map(|slot| {
                // The VICTIM's real public polynomial — publicly known, registered on L1 — under
                // the only signature the attacker possesses (their own). Slot 0 is genuine; slots
                // 1 and 2 are the forgery, and one bad leaf is enough.
                FalconSigGadgetWitness::for_signature(
                    &members.falcon_keys[slot].pk_coefficients(),
                    imch_digest,
                    &attacker_sig,
                )
            })
            .collect(),
    };
    let forged_result = catch_unwind(AssertUnwindSafe(|| agg_circuit.prove(&forged)));
    assert!(
        matches!(forged_result, Err(_) | Ok(Err(_))),
        "A3a: an aggregate must not exist over signatures the attacker did not have"
    );

    // A3b. A genuine 1-of-N aggregate over the SAME digest (design §9 Phase 5 step 4).
    //
    // HONEST FINDING, and it is why this case is stated at the CONSUMER: the aggregate itself IS
    // provable. `FalconAggCircuit` accepts `1..=MAX_SIG_CLUSTER` signers by design, and so does the
    // `AggListCircuit` step. Nothing in the signature stack refuses a 1-of-N statement. What
    // refuses it is that no BLOCK can fold such a statement: `update_channel_tree`'s floor (A1)
    // stops the block from committing to it, and the commitment a 1-of-N aggregate carries is a
    // different value from the one the block computed — which `validity_circuit.rs`'s
    // `C == final.bp_sig_chain` catches.
    let one_of_n = agg_circuit
        .prove(&FalconAggWitness {
            message: imch_digest,
            active: vec![sig_event.witnesses[0].clone()],
        })
        .expect("a 1-of-N aggregate IS provable — that is precisely why the block must refuse it");
    let one_of_n_list = agg_list_circuit
        .prove_append(&one_of_n, Bytes32::default(), &None)
        .expect("and it folds into a list proof just as happily");
    let honest_chain = bwgen.borrow().current_bp_sig_chain();
    assert_ne!(
        agg_list_commitment(&[AggListEntry {
            message: imch_digest,
            signer_pks: vec![attacker_key.pk_g()],
        }]),
        honest_chain,
        "a 1-of-N statement is not the statement the block folded"
    );

    // The span, proven honestly first (control), then with the 1-of-N evidence (must fail).
    let mut prev_block_proof = None;
    let mut last_block_proof = None;
    // The chain proof the theft block is proved ON TOP OF — what a prover replaying just that
    // block must supply, and what the `prove_block` cases at the end of this test need.
    let mut proof_before_theft = None;
    {
        let g = bwgen.borrow();
        for idx in 1..=g.block_number.as_u64() {
            let bn = BlockNumber::new(idx).expect("block number");
            if bn == theft_block_number {
                proof_before_theft = prev_block_proof.clone();
            }
            let witness = g.block_chain_witness.get(&bn).cloned().expect("witness");
            let init = if prev_block_proof.is_none() {
                Some(initial_ext_state.clone())
            } else {
                None
            };
            let proof = block_hash_chain_processor
                .prove_block(init, prev_block_proof.clone(), &witness)
                .expect("control: the honest N-of-N span proves");
            prev_block_proof = Some(proof.clone());
            last_block_proof = Some(proof);
        }
    }
    let proof_before_theft = proof_before_theft.expect("the theft block is not the span's first");
    let final_block_chain_proof = last_block_proof.expect("final block chain proof");
    let validity_circuit =
        ValidityCircuit::<F, C, D>::new(&block_chain_vd, &agg_list_circuit.verifier_data());
    let honest_list = bwgen
        .borrow()
        .build_agg_sig_list_proof(&agg_circuit, &agg_list_circuit)
        .expect("the honest N-of-N list proof");
    let control = validity_circuit
        .prove(&final_block_chain_proof, honest_list.as_ref(), attacker_l1)
        .expect("control: with all three signatures the span is provable");
    validity_circuit
        .verify(&control)
        .expect("control: and it verifies");

    // NAMED CONSTRAINT: `C == final.bp_sig_chain` (`validity_circuit.rs`), gated on the COMPUTED
    // chain rather than a prover flag. An unsatisfiable plonky2 witness surfaces as either an
    // `Err` or a panic, and "it produced something" is not the question — "does it VERIFY" is, so
    // all three outcomes are covered.
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        validity_circuit.prove(&final_block_chain_proof, Some(&one_of_n_list), attacker_l1)
    }));
    let rejected = match attempt {
        Err(_) => true,
        Ok(Err(_)) => true,
        Ok(Ok(proof)) => validity_circuit.verify(&proof).is_err(),
    };
    assert!(
        rejected,
        "A3b: a 1-of-N aggregate must not settle a block the channel did not authorize"
    );

    // ---- And the production entry point refuses the attacker's block, not just the circuit. ----
    //
    // `prove_block` is what a real prover calls. It must refuse A1 and A2 too — otherwise the
    // circuit-level results above would be a property of a path nobody takes.
    //
    // CONTROL FIRST, and it is not decoration: `prove_block` takes the block on top of a PREVIOUS
    // chain proof, and if `proof_before_theft` were the wrong link the two refusals below would
    // pass for a completely unrelated reason (a block-number or state mismatch) while proving
    // nothing about the signer set. Re-proving the honest block against the same inputs rules that
    // out.
    block_hash_chain_processor
        .prove_block(None, Some(proof_before_theft.clone()), &honest_witness)
        .expect("control: these exact inputs DO prove the honest block");
    for (label, signer_count, member_leaves) in [
        ("A1", 1u32, honest_tree.member_leaves.clone()),
        ("A2", 2u32, a2.member_leaves.clone()),
    ] {
        let mut w = honest_witness.clone();
        w.signer_count = Some(signer_count);
        w.member_leaves = Some(member_leaves);
        let attempt = catch_unwind(AssertUnwindSafe(|| {
            block_hash_chain_processor.prove_block(None, Some(proof_before_theft.clone()), &w)
        }));
        assert!(
            matches!(attempt, Err(_) | Ok(Err(_))),
            "{label}: the production block-proving path must refuse the attacker's block"
        );
    }

    println!(
        "[post-change] ATTACK DEAD in {:?}: steps 1, 2, 4 and 5 are unchanged and still work \
         (the withdrawal for {THEFT} to {} is still constructible GIVEN a settled block), but no \
         block carrying {} can be proven without all 3 registered members' signatures.",
        t0.elapsed(),
        attacker_l1.to_hex(),
        theft_tx_tree_root.to_hex(),
    );
}
