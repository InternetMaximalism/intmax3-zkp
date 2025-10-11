use criterion::{Criterion, black_box, criterion_group, criterion_main};
use intmax3_zkp::{
    circuits::{
        balance::{
            balance_processor::BalanceProcessor,
            common::recipient::{
                calculate_recipient_from_address, calculate_recipient_from_user_id,
            },
            receive_deposit_circuit::ReceiveDepositWitness,
            receive_transfer_circuit::ReceiveTransferWitness,
            send_tx_circuit::SendTxWitness,
            spend_circuit::SpendCircuit,
        },
        test_utils::{
            balance_witness_generator::{
                BalanceWitnessGenerator, ReceiveDepositData, ReceiveTransferData, SendTxData,
            },
            block_witness_generator::BlockWitnessGenerator,
        },
        validity::{
            block_hash_chain::block_hash_chain_processor::{
                BlockHashChainProcessor, BlockHashChainProcessorWitness,
            },
            deposit_hash_chain::{
                deposit_chain_processor::DepositChainProcessor, deposit_step::DepositStepWitness,
            },
        },
    },
    common::{
        deposit::Deposit,
        salt::Salt,
        transfer::Transfer,
        trees::{deposit_tree::DepositTree, transfer_tree::TransferTree, tx_tree::TxTree},
        tx::Tx,
        u63::U63,
        user_id::UserId,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::{Arc, RwLock};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

fn build_balance_initial_inputs() -> (BalanceProcessor<F, C, D>, UserId, Salt) {
    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
    let user_id = UserId::new(0, 1).expect("user id");
    let mut rng = StdRng::seed_from_u64(0);
    let salt = Salt::rand(&mut rng);
    (balance_processor, user_id, salt)
}

fn build_deposit_bench_inputs() -> (BalanceProcessor<F, C, D>, ReceiveDepositWitness<F, C, D>) {
    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());

    let supported_user_counts = vec![2];
    let block_witness_generator = Arc::new(RwLock::new(BlockWitnessGenerator::new(
        &supported_user_counts,
    )));

    let mut rng = StdRng::seed_from_u64(1);
    let user_id = UserId::new(0, 1).expect("user id");
    let salt = Salt::rand(&mut rng);

    let balance_witness_generator = BalanceWitnessGenerator::new(
        user_id,
        salt,
        block_witness_generator.clone(),
        &balance_processor,
    )
    .expect("balance witness generator");

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
        .expect("deposit witness");

    (balance_processor, deposit_witness)
}

fn build_send_tx_bench_inputs() -> (BalanceProcessor<F, C, D>, SendTxWitness<F, C, D>) {
    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());

    let supported_user_counts = vec![2];
    let block_witness_generator = Arc::new(RwLock::new(BlockWitnessGenerator::new(
        &supported_user_counts,
    )));

    let mut rng = StdRng::seed_from_u64(2);
    let user_id = UserId::new(0, 1).expect("user id");
    let salt = Salt::rand(&mut rng);
    let mut balance_witness_generator = BalanceWitnessGenerator::new(
        user_id,
        salt,
        block_witness_generator.clone(),
        &balance_processor,
    )
    .expect("balance witness generator");

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
        .expect("deposit witness");
    let deposit_proof = balance_processor
        .prove_receive_deposit(&deposit_witness)
        .expect("deposit proof");
    balance_witness_generator
        .commit_receive_deposit(&deposit_proof, &deposit_witness)
        .expect("commit deposit");

    let transfer = Transfer {
        recipient: calculate_recipient_from_address(Address::rand(&mut rng)),
        token_index: 0,
        amount: U256::from(3u32),
        aux_data: Bytes32::default(),
    };
    let spend_witness = balance_witness_generator
        .spend_witness(&[transfer.clone()])
        .expect("spend witness");
    let spend_proof = spend_circuit.prove(&spend_witness).expect("spend proof");

    let mut transfer_tree = TransferTree::init();
    transfer_tree.push(transfer.clone());
    let transfer_tree_root = transfer_tree.get_root();

    let tx = Tx {
        transfer_tree_root,
        nonce: balance_witness_generator.full_private_state.nonce,
    };

    let mut tx_tree = TxTree::init();
    tx_tree.update(user_id.local_id() as u64, tx.clone());
    let tx_tree_root = tx_tree.get_root();
    let tx_merkle_proof = tx_tree.prove(user_id.local_id() as u64);
    let tx_tree_root_bytes: Bytes32 = tx_tree_root.into();

    {
        let mut generator = block_witness_generator
            .write()
            .expect("block generator lock");
        generator
            .add_block(
                user_id.aggregator_id(),
                &[user_id.local_id()],
                1,
                tx_tree_root_bytes,
            )
            .expect("apply tx block");
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

    (balance_processor, send_tx_witness)
}

fn build_receive_transfer_bench_inputs()
-> (BalanceProcessor<F, C, D>, ReceiveTransferWitness<F, C, D>) {
    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());

    let supported_user_counts = vec![2];
    let block_witness_generator = Arc::new(RwLock::new(BlockWitnessGenerator::new(
        &supported_user_counts,
    )));

    let mut rng = StdRng::seed_from_u64(3);
    let user_id = UserId::new(0, 1).expect("user id");
    let salt = Salt::rand(&mut rng);
    let mut balance_witness_generator = BalanceWitnessGenerator::new(
        user_id,
        salt,
        block_witness_generator.clone(),
        &balance_processor,
    )
    .expect("balance witness generator");

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
        .expect("deposit witness");
    let deposit_proof = balance_processor
        .prove_receive_deposit(&deposit_witness)
        .expect("deposit proof");
    balance_witness_generator
        .commit_receive_deposit(&deposit_proof, &deposit_witness)
        .expect("commit deposit");

    let sender_proof = balance_witness_generator.balance_proof.clone();
    let transfer_salt = Salt::rand(&mut rng);
    let user_id2 = UserId::new(1, 1).expect("user id 2");
    let balance_witness_generator2 = BalanceWitnessGenerator::new(
        user_id2,
        Salt::rand(&mut rng),
        block_witness_generator.clone(),
        &balance_processor,
    )
    .expect("balance witness generator 2");

    let transfer = Transfer {
        recipient: calculate_recipient_from_user_id(user_id2, transfer_salt),
        token_index: 0,
        amount: U256::from(3u32),
        aux_data: Bytes32::default(),
    };
    let spend_witness = balance_witness_generator
        .spend_witness(&[transfer.clone()])
        .expect("spend witness");
    let spend_proof = spend_circuit.prove(&spend_witness).expect("spend proof");

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
    let tx_merkle_proof = tx_tree.prove(user_id.local_id() as u64);
    let tx_tree_root_bytes: Bytes32 = tx_tree_root.into();

    {
        let mut generator = block_witness_generator
            .write()
            .expect("block generator lock");
        generator
            .add_block(
                user_id.aggregator_id(),
                &[user_id.local_id()],
                1,
                tx_tree_root_bytes,
            )
            .expect("apply transfer block");
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
    let new_balance_proof = balance_processor
        .prove_send_tx(&send_tx_witness)
        .expect("send tx proof");
    balance_witness_generator
        .commit_send_tx(&new_balance_proof, &send_tx_witness, &spend_witness)
        .expect("commit send tx");

    let receive_transfer_data = ReceiveTransferData {
        to: user_id2,
        transfer,
        sender_proof,
        spend_proof,
        tx_tree_root: tx_tree_root_bytes,
        tx,
        tx_merkle_proof,
        transfer_index,
        transfer_merkle_proof,
        transfer_salt,
    };
    let receive_transfer_witness = balance_witness_generator2
        .receive_transfer_witness(&receive_transfer_data)
        .expect("receive transfer witness");

    (balance_processor, receive_transfer_witness)
}

fn deposit_chain_proof_bench(c: &mut Criterion) {
    let processor = DepositChainProcessor::<F, C, D>::new();
    let deposit_tree = DepositTree::init();

    let deposit = Deposit {
        deposit_index: U63::default(),
        block_number: U63::default(),
        depositor: Address::default(),
        recipient: Bytes32::default(),
        token_index: 0,
        amount: U256::from(10u32),
        aux_data: Bytes32::default(),
    };
    let deposit_merkle_proof = deposit_tree.prove(deposit.deposit_index.as_u64());

    let initial_value = Some((Bytes32::default(), deposit_tree.get_root(), U63::default()));

    let witness = DepositStepWitness::<F, C, D> {
        initial_value,
        prev_deposit_chain_proof: None,
        deposit,
        deposit_merkle_proof,
    };

    let mut group = c.benchmark_group("deposit_chain_proof");
    group.sample_size(10).bench_function("prove_step", |b| {
        b.iter(|| {
            let proof = processor
                .prove_step(black_box(&witness))
                .expect("deposit chain proof");
            black_box(proof);
        });
    });
    group.finish();
}

fn block_hash_chain_proof_bench(c: &mut Criterion) {
    let supported_user_counts = vec![2];
    let mut block_witness_generator = BlockWitnessGenerator::new(&supported_user_counts);
    let initial_state = block_witness_generator.current_extended_public_state();

    block_witness_generator
        .add_block(0, &[1], 0, Bytes32::default())
        .expect("add block");

    let block_number = block_witness_generator.block_number;
    let block_witness: BlockHashChainProcessorWitness = block_witness_generator
        .block_chain_witness
        .get(&block_number)
        .cloned()
        .expect("block witness");

    let processor = BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);

    let mut group = c.benchmark_group("block_hash_chain_proof");
    group.sample_size(10).bench_function("prove_block", |b| {
        b.iter(|| {
            let proof = processor
                .prove_block(
                    black_box(Some(initial_state.clone())),
                    None,
                    black_box(&block_witness),
                )
                .expect("block hash chain proof");
            black_box(proof);
        });
    });
    group.finish();
}

fn balance_processor_proof_benches(c: &mut Criterion) {
    let (initial_processor, user_id, salt) = build_balance_initial_inputs();
    let (deposit_processor, deposit_witness) = build_deposit_bench_inputs();
    let (send_processor, send_tx_witness) = build_send_tx_bench_inputs();
    let (receive_processor, receive_transfer_witness) = build_receive_transfer_bench_inputs();

    let mut group = c.benchmark_group("balance_processor_proofs");
    group.sample_size(10);

    let initial_processor = initial_processor;
    group.bench_function("prove_initial", move |b| {
        b.iter(|| {
            let proof = initial_processor
                .prove_initial(user_id, salt)
                .expect("initial proof");
            black_box(proof);
        });
    });

    let deposit_processor = deposit_processor;
    let deposit_witness = deposit_witness;
    group.bench_function("prove_receive_deposit", move |b| {
        b.iter(|| {
            let proof = deposit_processor
                .prove_receive_deposit(black_box(&deposit_witness))
                .expect("deposit proof");
            black_box(proof);
        });
    });

    let send_processor = send_processor;
    let send_tx_witness = send_tx_witness;
    group.bench_function("prove_send_tx", move |b| {
        b.iter(|| {
            let proof = send_processor
                .prove_send_tx(black_box(&send_tx_witness))
                .expect("send tx proof");
            black_box(proof);
        });
    });

    let receive_processor = receive_processor;
    let receive_transfer_witness = receive_transfer_witness;
    group.bench_function("prove_receive_transfer", move |b| {
        b.iter(|| {
            let proof = receive_processor
                .prove_receive_transfer(black_box(&receive_transfer_witness))
                .expect("receive transfer proof");
            black_box(proof);
        });
    });

    group.finish();
}

criterion_group!(
    proof_benches,
    deposit_chain_proof_bench,
    block_hash_chain_proof_bench,
    balance_processor_proof_benches
);
criterion_main!(proof_benches);
