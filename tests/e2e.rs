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
            block_witness_generator::BlockWitnessGenerator,
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
        salt::Salt,
        transfer::Transfer,
        trees::{transfer_tree::TransferTree, tx_tree::TxTree},
        tx::Tx,
        u63::BlockNumber,
        user_id::UserId,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use rand::{SeedableRng, rngs::StdRng};
use std::{
    sync::{Arc, RwLock},
    time::Instant,
};

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
    let block_witness_generator = Arc::new(RwLock::new(BlockWitnessGenerator::new(
        &supported_user_counts,
    )));

    let mut rng = StdRng::seed_from_u64(1);
    let user_id = UserId::new(0, 1).expect("user id");
    let salt = Salt::rand(&mut rng);

    let mut balance_witness_generator = BalanceWitnessGenerator::new(
        user_id,
        salt,
        block_witness_generator.clone(),
        &balance_processor,
    )
    .expect("balance witness generator");

    let initial_ext_state = {
        let guard = block_witness_generator
            .read()
            .expect("block generator lock");
        guard.current_extended_public_state()
    };

    // ----- Deposit phase -----
    let deposit_salt = Salt::rand(&mut rng);
    let deposit_recipient = calculate_recipient_from_user_id(user_id, deposit_salt);
    {
        let mut generator = block_witness_generator
            .write()
            .expect("block generator lock");
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
    let user_id2 = UserId::new(1, 1).expect("user id 2");
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

    let mut internal_tx_tree = TxTree::init();
    internal_tx_tree.update(user_id.local_id() as u64, internal_tx.clone());
    let internal_tx_tree_root = internal_tx_tree.get_root();
    let internal_tx_tree_root_bytes: Bytes32 = internal_tx_tree_root.into();
    let internal_tx_merkle_proof = internal_tx_tree.prove(user_id.local_id() as u64);

    {
        let mut generator = block_witness_generator
            .write()
            .expect("block generator lock");
        generator
            .add_block(
                user_id.aggregator_id(),
                &[user_id.local_id()],
                1,
                internal_tx_tree_root_bytes,
            )
            .expect("apply internal transfer block");
    }

    let internal_send_tx_data = SendTxData {
        spend_proof: internal_spend_proof.clone(),
        tx_tree_root: internal_tx_tree_root_bytes,
        tx: internal_tx.clone(),
        tx_merkle_proof: internal_tx_merkle_proof.clone(),
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

    let mut withdrawal_tx_tree = TxTree::init();
    withdrawal_tx_tree.update(user_id.local_id() as u64, withdrawal_tx.clone());
    let withdrawal_tx_tree_root = withdrawal_tx_tree.get_root();
    let withdrawal_tx_tree_root_bytes: Bytes32 = withdrawal_tx_tree_root.into();
    let withdrawal_tx_merkle_proof = withdrawal_tx_tree.prove(user_id.local_id() as u64);

    {
        let mut generator = block_witness_generator
            .write()
            .expect("block generator lock");
        generator
            .add_block(
                user_id.aggregator_id(),
                &[user_id.local_id()],
                2,
                withdrawal_tx_tree_root_bytes,
            )
            .expect("apply withdrawal tx block");
    }

    let withdrawal_send_tx_data = SendTxData {
        spend_proof: withdrawal_spend_proof.clone(),
        tx_tree_root: withdrawal_tx_tree_root_bytes,
        tx: withdrawal_tx.clone(),
        tx_merkle_proof: withdrawal_tx_merkle_proof.clone(),
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

    let withdrawal_aggregator = Address::rand(&mut rng);
    let withdrawal_final_timer = Instant::now();
    let withdrawal_proof = withdrawal_processor
        .prove_final(&withdrawal_chain_proof, withdrawal_aggregator)
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
        let guard = block_witness_generator
            .read()
            .expect("block generator lock");
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
    let validity_circuit = ValidityCircuit::<F, C, D>::new(&block_chain_vd);
    let validity_prover = Address::rand(&mut rng);
    let validity_timer = Instant::now();
    let validity_proof = validity_circuit
        .prove(&final_block_chain_proof, validity_prover)
        .expect("validity proof");
    println!("validity proof time: {:?}", validity_timer.elapsed());
    validity_circuit
        .verify(&validity_proof)
        .expect("verify validity proof");
}
