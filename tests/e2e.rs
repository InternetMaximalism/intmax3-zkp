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

    // ----- Withdrawal transaction setup -----
    let withdrawal_address = Address::rand(&mut rng);
    let transfer = Transfer {
        recipient: calculate_recipient_from_address(withdrawal_address),
        token_index: 0,
        amount: U256::from(3u32),
        aux_data: Bytes32::default(),
    };
    let spend_witness = balance_witness_generator
        .spend_witness(&[transfer.clone()])
        .expect("spend witness");
    let spend_timer = Instant::now();
    let spend_proof = spend_circuit.prove(&spend_witness).expect("spend proof");
    println!("spend proof time: {:?}", spend_timer.elapsed());

    let mut transfer_tree = TransferTree::init();
    transfer_tree.push(transfer.clone());
    let transfer_index = 0u32;
    let transfer_merkle_proof = transfer_tree.prove(transfer_index as u64);
    let transfer_tree_root = transfer_tree.get_root();

    let tx = Tx {
        transfer_tree_root,
        nonce: balance_witness_generator.full_private_state.nonce,
    };

    let mut tx_tree = TxTree::init();
    tx_tree.update(user_id.local_id() as u64, tx.clone());
    let tx_tree_root = tx_tree.get_root();
    let tx_tree_root_bytes: Bytes32 = tx_tree_root.into();
    let tx_merkle_proof = tx_tree.prove(user_id.local_id() as u64);

    {
        let mut generator = block_witness_generator
            .write()
            .expect("block generator lock");
        generator
            .add_block(
                user_id.aggregator_id(),
                &[user_id.local_id()],
                2,
                tx_tree_root_bytes,
            )
            .expect("apply withdrawal tx block");
    }

    let send_tx_data = SendTxData {
        spend_proof: spend_proof.clone(),
        tx_tree_root: tx_tree_root_bytes,
        tx: tx.clone(),
        tx_merkle_proof: tx_merkle_proof.clone(),
    };
    let send_tx_witness = balance_witness_generator
        .send_tx_witness(&send_tx_data)
        .expect("send tx witness");
    let send_tx_timer = Instant::now();
    let new_balance_proof = balance_processor
        .prove_send_tx(&send_tx_witness)
        .expect("send tx proof");
    println!("send tx proof time: {:?}", send_tx_timer.elapsed());
    balance_witness_generator
        .commit_send_tx(&new_balance_proof, &send_tx_witness, &spend_witness)
        .expect("commit send tx");

    // ----- Single withdrawal proof -----
    let single_withdrawal_data = SingleWithdrawalData {
        tx_tree_root: tx_tree_root_bytes,
        tx: tx.clone(),
        tx_merkle_proof: tx_merkle_proof.clone(),
        transfer: transfer.clone(),
        transfer_index,
        transfer_merkle_proof: transfer_merkle_proof.clone(),
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
