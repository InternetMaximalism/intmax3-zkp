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
                BalanceWitnessGenerator, ReceiveDepositData, ReceiveTransferData, SendTxData,
                SingleWithdrawalData,
            },
            block_witness_generator::{
                BlockTxV2Witness, BlockWitnessGenerator, BlockWitnessGeneratorHandle,
            },
        },
        validity::block_hash_chain::{
            block_hash_chain_processor::BlockHashChainProcessor, validity_circuit::ValidityCircuit,
        },
        withdraw::{
            single_withdrawal_circuit::SingleWithdawalCircuit,
            withdrawal_processor::WithdrawalProcessor, withdrawal_step::WithdrawalStepWitness,
        },
    },
    common::{
        channel_id::ChannelId as UserId,
        salt::Salt,
        transfer::Transfer,
        trees::{transfer_tree::TransferTree, tx_tree::TxTree, tx_v2_tree::TxV2Tree},
        tx::{Tx, TxClass, TxV2},
        u63::BlockNumber,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
    utils::poseidon_hash_out::PoseidonHashOut,
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Instant;

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

#[cfg_attr(debug_assertions, ignore = "run with --release")]
#[test]
fn e2e_deposit_validity_withdrawal() {
    let supported_user_counts = vec![2];

    let block_hash_chain_processor =
        BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
    let block_chain_vd = block_hash_chain_processor.block_chain_vd();

    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());

    let processor_bytes = balance_processor.to_bytes().unwrap();
    println!(
        "balance processor size: {} MB",
        processor_bytes.len() / 1_000_000
    );
    let balance_processor = BalanceProcessor::<F, C, D>::from_bytes(&processor_bytes).unwrap();

    let balance_vd = balance_processor.balance_vd();
    let block_witness_generator =
        BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

    let mut rng = StdRng::seed_from_u64(1);
    let user_id = UserId::new(1).expect("user id");
    let salt = Salt::rand(&mut rng);

    let mut balance_witness_generator = BalanceWitnessGenerator::new(
        user_id,
        salt,
        block_witness_generator.clone(),
        &balance_processor,
    )
    .expect("balance witness generator");

    let initial_ext_state = block_witness_generator
        .borrow()
        .current_extended_public_state();

    // ----- Channel registration phase (in-band, block 1) -----
    // Register channel 1's member set via a dedicated REGISTRATION block BEFORE its first updating
    // block. This populates the channel tree's `member_pubkeys_root` so the later updating blocks'
    // member-signature binding (live `update_channel_tree`) is satisfiable, and the validity proof
    // actually consumes the registration via the `channel_reg_step` chain. Without this, the
    // updating blocks would require a member-tree inclusion proof against an empty root — the
    // previously-RED full-stack gap this phase closes.
    {
        let mut generator = block_witness_generator.borrow_mut();
        generator.add_channel_registration(user_id.channel_id());
        generator
            .add_registration_block(0)
            .expect("apply channel registration block");
    }

    // ----- Deposit phase -----
    let deposit_salt = Salt::rand(&mut rng);
    let deposit_recipient = calculate_recipient_from_user_id(user_id, deposit_salt);
    {
        let mut generator = block_witness_generator.borrow_mut();
        generator
            .add_deposit(
                Address::rand(&mut rng),
                deposit_recipient,
                0,
                U256::from(10u32),
                Bytes32::default(),
            )
            .expect("queue deposit");
        generator
            .add_block(0, &[], 0, Bytes32::default())
            .expect("apply deposit block");
    }

    let deposit_data = ReceiveDepositData {
        receiver: deposit_recipient,
        deposit_salt,
    };
    let deposit_witness = balance_witness_generator
        .receive_deposit_witness(&deposit_data)
        .expect("receive deposit witness");
    let deposit_timer = Instant::now();
    let deposit_balance_proof = balance_processor
        .prove_receive_deposit(&deposit_witness)
        .expect("deposit proof");
    println!("deposit proof time: {:?}", deposit_timer.elapsed());
    balance_witness_generator
        .commit_receive_deposit(&deposit_balance_proof, &deposit_witness)
        .expect("commit deposit");

    // ----- Internal transfer & receive -----
    let sender_proof = balance_witness_generator.balance_proof.clone();
    let transfer_salt = Salt::rand(&mut rng);
    let user_id2 = UserId::new(2).expect("user id 2");
    let mut balance_witness_generator2 = BalanceWitnessGenerator::new(
        user_id2,
        Salt::rand(&mut rng),
        block_witness_generator.clone(),
        &balance_processor,
    )
    .expect("balance witness generator 2");

    let internal_transfer = Transfer {
        recipient: calculate_recipient_from_user_id(user_id2, transfer_salt),
        token_index: 0,
        amount: U256::from(3u32),
        aux_data: Bytes32::default(),
    };
    let internal_spend_witness = balance_witness_generator
        .spend_witness(&[internal_transfer.clone()])
        .expect("internal spend witness");
    let internal_spend_timer = Instant::now();
    let internal_spend_proof = spend_circuit
        .prove(&internal_spend_witness)
        .expect("internal spend proof");
    println!(
        "internal spend proof time: {:?}",
        internal_spend_timer.elapsed()
    );

    let mut internal_transfer_tree = TransferTree::init();
    internal_transfer_tree.push(internal_transfer.clone());
    let internal_transfer_index = 0u32;
    let internal_transfer_merkle_proof =
        internal_transfer_tree.prove(internal_transfer_index as u64);
    let internal_transfer_tree_root = internal_transfer_tree.get_root();

    let internal_tx = Tx {
        transfer_tree_root: internal_transfer_tree_root,
        nonce: balance_witness_generator.full_private_state.nonce,
    };

    // Legacy Tx tree retained for the (legacy) Tx merkle proof carried alongside the witness,
    // but the block's authoritative root is now a TxV2Tree root (the new tx_v2 model). The
    // single source of truth for the tx is `internal_tx_v2` below; balance (TxSettlement) and
    // validity (update_channel_tree) both open against the same TxV2Tree root.
    let mut internal_tx_tree = TxTree::init();
    internal_tx_tree.update(user_id.as_u64(), internal_tx.clone());
    let internal_tx_merkle_proof = internal_tx_tree.prove(user_id.as_u64());

    // Build the TxV2 (UserTransfer) for this block. `transfer_tree_root` MUST equal the transfer
    // tree the balance-side spend actually committed to (so balance and validity agree on the
    // same tx). channel_action_root == 0 for UserTransfer.
    let internal_tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root: internal_transfer_tree_root,
        nonce: internal_tx.nonce,
        channel_action_root: PoseidonHashOut::default(),
    };
    // TxV2Tree is indexed by channel_id (TX_TREE_HEIGHT == CHANNEL_ID_BITS), matching both
    // `TxSettlement::verify` and `update_channel_tree`'s per-slot tx_v2 index.
    let mut internal_tx_v2_tree = TxV2Tree::init();
    internal_tx_v2_tree.update(user_id.as_u64(), internal_tx_v2);
    let internal_tx_tree_root_bytes: Bytes32 = internal_tx_v2_tree.get_root().into();
    let internal_tx_v2_merkle_proof = internal_tx_v2_tree.prove(user_id.as_u64());

    // Per-slot tx_v2 witness for num_users = 2: slot 0 is the active channel (key_id 1), slot 1
    // is a zero-key_id padding slot (dummy values, skipped in-circuit).
    let internal_tx_v2_witness = BlockTxV2Witness {
        tx_v2_indices: vec![user_id.as_u64(), 0],
        tx_v2s: vec![internal_tx_v2, TxV2::default()],
        tx_v2_merkle_proofs: vec![
            internal_tx_v2_merkle_proof.clone(),
            internal_tx_v2_merkle_proof.clone(),
        ],
    };

    {
        let mut generator = block_witness_generator.borrow_mut();
        generator
            .add_block_with_tx_v2(
                user_id.channel_id(),
                &[1],
                1,
                internal_tx_tree_root_bytes,
                Some(internal_tx_v2_witness),
            )
            .expect("apply internal transfer block");
    }

    let internal_send_tx_data = SendTxData {
        spend_proof: internal_spend_proof.clone(),
        tx_tree_root: internal_tx_tree_root_bytes,
        tx: internal_tx.clone(),
        tx_merkle_proof: internal_tx_merkle_proof.clone(),
        tx_v2: Some(internal_tx_v2),
        tx_v2_merkle_proof: Some(internal_tx_v2_merkle_proof.clone()),
        transfer: internal_transfer.clone(),
        transfer_merkle_proof: internal_transfer_merkle_proof.clone(),
    };
    let internal_send_tx_witness = balance_witness_generator
        .send_tx_witness(&internal_send_tx_data)
        .expect("internal send tx witness");
    let internal_send_tx_timer = Instant::now();
    let internal_new_balance_proof = balance_processor
        .prove_send_tx(&internal_send_tx_witness)
        .expect("internal send tx proof");
    println!(
        "internal send tx proof time: {:?}",
        internal_send_tx_timer.elapsed()
    );
    balance_witness_generator
        .commit_send_tx(
            &internal_new_balance_proof,
            &internal_send_tx_witness,
            &internal_spend_witness,
        )
        .expect("commit internal send tx");

    let receive_transfer_data = ReceiveTransferData {
        to: user_id2,
        transfer: internal_transfer.clone(),
        sender_proof,
        spend_proof: internal_spend_proof,
        tx_tree_root: internal_tx_tree_root_bytes,
        tx: internal_tx,
        tx_merkle_proof: internal_tx_merkle_proof,
        transfer_index: internal_transfer_index,
        transfer_merkle_proof: internal_transfer_merkle_proof,
        transfer_salt,
        tx_v2: Some(internal_tx_v2),
        tx_v2_merkle_proof: Some(internal_tx_v2_merkle_proof),
    };
    let receive_transfer_witness = balance_witness_generator2
        .receive_transfer_witness(&receive_transfer_data)
        .expect("receive transfer witness");
    let receive_transfer_timer = Instant::now();
    let receive_transfer_proof = balance_processor
        .prove_receive_transfer(&receive_transfer_witness)
        .expect("receive transfer proof");
    println!(
        "receive transfer proof time: {:?}",
        receive_transfer_timer.elapsed()
    );
    balance_witness_generator2
        .commit_receive_transfer(&receive_transfer_proof, &receive_transfer_witness)
        .expect("commit receive transfer");

    // ----- Withdrawal transaction setup -----
    let withdrawal_address = Address::rand(&mut rng);
    let withdrawal_transfer = Transfer {
        recipient: calculate_recipient_from_address(withdrawal_address),
        token_index: 0,
        amount: U256::from(3u32),
        aux_data: Bytes32::default(),
    };
    let withdrawal_spend_witness = balance_witness_generator
        .spend_witness(&[withdrawal_transfer.clone()])
        .expect("withdrawal spend witness");
    let withdrawal_spend_timer = Instant::now();
    let withdrawal_spend_proof = spend_circuit
        .prove(&withdrawal_spend_witness)
        .expect("withdrawal spend proof");
    println!(
        "withdrawal spend proof time: {:?}",
        withdrawal_spend_timer.elapsed()
    );

    let mut withdrawal_transfer_tree = TransferTree::init();
    withdrawal_transfer_tree.push(withdrawal_transfer.clone());
    let withdrawal_transfer_index = 0u32;
    let withdrawal_transfer_merkle_proof =
        withdrawal_transfer_tree.prove(withdrawal_transfer_index as u64);
    let withdrawal_transfer_tree_root = withdrawal_transfer_tree.get_root();

    let withdrawal_tx = Tx {
        transfer_tree_root: withdrawal_transfer_tree_root,
        nonce: balance_witness_generator.full_private_state.nonce,
    };

    // Legacy Tx tree retained only for the legacy Tx merkle proof; the block's authoritative
    // root is the TxV2Tree root below (same single-source-of-truth pattern as the internal tx).
    let mut withdrawal_tx_tree = TxTree::init();
    withdrawal_tx_tree.update(user_id.as_u64(), withdrawal_tx.clone());
    let withdrawal_tx_merkle_proof = withdrawal_tx_tree.prove(user_id.as_u64());

    let withdrawal_tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root: withdrawal_transfer_tree_root,
        nonce: withdrawal_tx.nonce,
        channel_action_root: PoseidonHashOut::default(),
    };
    let mut withdrawal_tx_v2_tree = TxV2Tree::init();
    withdrawal_tx_v2_tree.update(user_id.as_u64(), withdrawal_tx_v2);
    let withdrawal_tx_tree_root_bytes: Bytes32 = withdrawal_tx_v2_tree.get_root().into();
    let withdrawal_tx_v2_merkle_proof = withdrawal_tx_v2_tree.prove(user_id.as_u64());

    let withdrawal_tx_v2_witness = BlockTxV2Witness {
        tx_v2_indices: vec![user_id.as_u64(), 0],
        tx_v2s: vec![withdrawal_tx_v2, TxV2::default()],
        tx_v2_merkle_proofs: vec![
            withdrawal_tx_v2_merkle_proof.clone(),
            withdrawal_tx_v2_merkle_proof.clone(),
        ],
    };

    {
        let mut generator = block_witness_generator.borrow_mut();
        generator
            .add_block_with_tx_v2(
                user_id.channel_id(),
                &[1],
                2,
                withdrawal_tx_tree_root_bytes,
                Some(withdrawal_tx_v2_witness),
            )
            .expect("apply withdrawal tx block");
    }

    let withdrawal_send_tx_data = SendTxData {
        spend_proof: withdrawal_spend_proof.clone(),
        tx_tree_root: withdrawal_tx_tree_root_bytes,
        tx: withdrawal_tx.clone(),
        tx_merkle_proof: withdrawal_tx_merkle_proof.clone(),
        tx_v2: Some(withdrawal_tx_v2),
        tx_v2_merkle_proof: Some(withdrawal_tx_v2_merkle_proof.clone()),
        transfer: withdrawal_transfer.clone(),
        transfer_merkle_proof: withdrawal_transfer_merkle_proof.clone(),
    };
    let withdrawal_send_tx_witness = balance_witness_generator
        .send_tx_witness(&withdrawal_send_tx_data)
        .expect("withdrawal send tx witness");
    let withdrawal_send_tx_timer = Instant::now();
    let withdrawal_balance_proof = balance_processor
        .prove_send_tx(&withdrawal_send_tx_witness)
        .expect("withdrawal send tx proof");
    println!(
        "withdrawal send tx proof time: {:?}",
        withdrawal_send_tx_timer.elapsed()
    );
    balance_witness_generator
        .commit_send_tx(
            &withdrawal_balance_proof,
            &withdrawal_send_tx_witness,
            &withdrawal_spend_witness,
        )
        .expect("commit send tx");

    // ----- Single withdrawal proof -----
    let single_withdrawal_data = SingleWithdrawalData {
        tx_tree_root: withdrawal_tx_tree_root_bytes,
        tx: withdrawal_tx.clone(),
        tx_merkle_proof: withdrawal_tx_merkle_proof.clone(),
        transfer: withdrawal_transfer.clone(),
        transfer_index: withdrawal_transfer_index,
        transfer_merkle_proof: withdrawal_transfer_merkle_proof.clone(),
        tx_v2: Some(withdrawal_tx_v2),
        tx_v2_merkle_proof: Some(withdrawal_tx_v2_merkle_proof.clone()),
    };
    let single_withdrawal_witness = balance_witness_generator
        .single_withdrawal_witness(&single_withdrawal_data)
        .expect("single withdrawal witness");
    let single_withdrawal_circuit = SingleWithdawalCircuit::<F, C, D>::new(&balance_vd);
    let single_withdrawal_vd = single_withdrawal_circuit.data.verifier_data();
    let single_withdrawal_timer = Instant::now();
    let single_withdrawal_proof = single_withdrawal_circuit
        .prove(&single_withdrawal_witness)
        .expect("single withdrawal proof");
    println!(
        "single withdrawal proof time: {:?}",
        single_withdrawal_timer.elapsed()
    );
    single_withdrawal_circuit
        .data
        .verify(single_withdrawal_proof.clone())
        .expect("verify single withdrawal proof");

    // ----- Withdrawal proofs -----
    let withdrawal_processor = WithdrawalProcessor::<F, C, D>::new(&single_withdrawal_vd);
    let withdrawal_chain_vd = withdrawal_processor.withdrawal_chain_vd();
    let step_witness = WithdrawalStepWitness::<F, C, D> {
        prev_withdrawal_chain_proof: None,
        single_withdrawal_proof: single_withdrawal_proof.clone(),
        update_public_state: single_withdrawal_witness.update_public_state.clone(),
    };
    let withdrawal_chain_timer = Instant::now();
    let withdrawal_chain_proof = withdrawal_processor
        .prove_step(&step_witness)
        .expect("withdrawal chain proof");
    println!(
        "withdrawal chain proof time: {:?}",
        withdrawal_chain_timer.elapsed()
    );
    withdrawal_chain_vd
        .verify(withdrawal_chain_proof.clone())
        .expect("verify withdrawal chain proof");

    let ext_public_state = block_witness_generator
        .borrow()
        .current_extended_public_state();
    let withdrawal_prover = Address::rand(&mut rng);
    let withdrawal_final_timer = Instant::now();
    let withdrawal_proof = withdrawal_processor
        .prove_final(
            &withdrawal_chain_proof,
            withdrawal_prover,
            &ext_public_state,
        )
        .expect("withdrawal proof");
    println!(
        "withdrawal final proof time: {:?}",
        withdrawal_final_timer.elapsed()
    );
    withdrawal_processor
        .withdrawal_vd()
        .verify(withdrawal_proof.clone())
        .expect("verify withdrawal proof");

    // ----- Block hash chain & validity proofs -----
    let mut prev_block_proof = None;
    let mut last_block_proof = None;
    {
        let guard = block_witness_generator.borrow();
        let total_blocks = guard.block_number.as_u64();
        for block_idx in 1..=total_blocks {
            let block_number = BlockNumber::new(block_idx).expect("block number");
            let witness = guard
                .block_chain_witness
                .get(&block_number)
                .cloned()
                .expect("block witness");
            let initial_state = if prev_block_proof.is_none() {
                Some(initial_ext_state.clone())
            } else {
                None
            };
            let chain_timer = Instant::now();
            let proof = block_hash_chain_processor
                .prove_block(initial_state, prev_block_proof.clone(), &witness)
                .expect("block hash chain proof");
            println!(
                "block hash chain proof for block {} time: {:?}",
                block_idx,
                chain_timer.elapsed()
            );
            prev_block_proof = Some(proof.clone());
            last_block_proof = Some(proof);
        }
    }

    let final_block_chain_proof = last_block_proof.expect("final block hash chain proof");

    // P2b: build the recursive ListCircuit proof over the span's bp IMSB single-sigs, and pass it to
    // the validity circuit (which verifies it conditionally on final.bp_sig_chain != 0, decision D3).
    let single_sig = intmax3_zkp::poseidon_sig::circuit::SingleSigCircuit::new();
    let list_circuit =
        intmax3_zkp::poseidon_sig::list::ListCircuit::new(&single_sig.verifier_data());
    let list_proof = block_witness_generator
        .borrow()
        .build_bp_sig_list_proof(&single_sig, &list_circuit)
        .expect("build bp sig list proof");

    let validity_circuit =
        ValidityCircuit::<F, C, D>::new(&block_chain_vd, &list_circuit.verifier_data());
    let validity_prover = Address::rand(&mut rng);
    let validity_timer = Instant::now();
    let validity_proof = validity_circuit
        .prove(&final_block_chain_proof, list_proof.as_ref(), validity_prover)
        .expect("validity proof");
    println!("validity proof time: {:?}", validity_timer.elapsed());
    validity_circuit
        .verify(&validity_proof)
        .expect("verify validity proof");
}
