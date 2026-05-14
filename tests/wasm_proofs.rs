#![cfg(target_arch = "wasm32")]

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
            block_witness_generator::{BlockWitnessGenerator, BlockWitnessGeneratorHandle},
        },
        withdraw::{
            single_withdrawal_circuit::SingleWithdawalCircuit,
            withdrawal_processor::{WithdrawalProcessor, WithdrawalProcessorError},
            withdrawal_step::WithdrawalStepWitness,
        },
    },
    common::{
        salt::Salt,
        transfer::Transfer,
        trees::{
            transfer_tree::{TransferMerkleProof, TransferTree},
            tx_tree::TxTree,
        },
        tx::Tx,
        user_id::UserId,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use rand::{SeedableRng, rngs::StdRng};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;
use web_time::Instant;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

const BALANCE_PROCESSOR_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/balance_processor.bin"
));
const SPEND_CIRCUIT_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/spend_circuit.bin"
));
const SINGLE_WITHDRAWAL_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/single_withdrawal_circuit.bin"
));

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(message: &str);
}

fn log_step(message: &str) {
    log(message);
}

fn log_proof_duration(step: &str, duration: web_time::Duration) {
    log(&format!(
        "{step} proof completed in {:.3}s",
        duration.as_secs_f64()
    ));
}

fn load_spend_circuit() -> SpendCircuit<F, C, D> {
    SpendCircuit::<F, C, D>::from_bytes(SPEND_CIRCUIT_BYTES)
        .expect("load spend circuit from bytes")
}

fn load_balance_processor() -> BalanceProcessor<F, C, D> {
    BalanceProcessor::<F, C, D>::from_bytes(BALANCE_PROCESSOR_BYTES)
        .expect("load balance processor from bytes")
}

fn load_single_withdrawal_circuit() -> SingleWithdawalCircuit<F, C, D> {
    SingleWithdawalCircuit::<F, C, D>::from_bytes(SINGLE_WITHDRAWAL_BYTES)
        .expect("load single withdrawal circuit from bytes")
}

struct BalanceScenario {
    spend_circuit: SpendCircuit<F, C, D>,
    balance_processor: BalanceProcessor<F, C, D>,
    block_witness_generator: BlockWitnessGeneratorHandle,
    user_id: UserId,
    balance_witness_generator: BalanceWitnessGenerator<F, C, D>,
}

struct SendTxOutcome {
    sender_balance_proof: ProofWithPublicInputs<F, C, D>,
    send_tx_data: SendTxData<F, C, D>,
    transfer: Transfer,
    transfer_index: u32,
    transfer_merkle_proof: TransferMerkleProof,
    transfer_salt: Salt,
}

impl BalanceScenario {
    fn new(supported_user_counts: &[u32], rng: &mut StdRng) -> Self {
        log_step("Initializing balance scenario");
        let spend_circuit = load_spend_circuit();
        let balance_processor = load_balance_processor();
        let block_witness_generator =
            BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(supported_user_counts));

        let user_id = UserId::new(0, 1).expect("user id");
        let salt = Salt::rand(rng);
        let balance_witness_generator = BalanceWitnessGenerator::new(
            user_id,
            salt,
            block_witness_generator.clone(),
            &balance_processor,
        )
        .expect("balance witness generator");

        log_step("Balance scenario ready");
        Self {
            spend_circuit,
            balance_processor,
            block_witness_generator,
            user_id,
            balance_witness_generator,
        }
    }
}

fn perform_deposit(scenario: &mut BalanceScenario, rng: &mut StdRng) -> SendTxOutcome {
    log_step("Starting deposit flow");
    let deposit_salt = Salt::rand(rng);
    let deposit_recipient = calculate_recipient_from_user_id(scenario.user_id, deposit_salt);
    {
        let mut generator = scenario.block_witness_generator.borrow_mut();
        generator
            .add_deposit(
                Address::rand(rng),
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
    let deposit_witness = scenario
        .balance_witness_generator
        .receive_deposit_witness(&deposit_data)
        .expect("deposit witness");
    log_step("Proving deposit");
    let deposit_timer = Instant::now();
    let deposit_proof = scenario
        .balance_processor
        .prove_receive_deposit(&deposit_witness)
        .expect("deposit proof");
    let deposit_elapsed = deposit_timer.elapsed();
    log_proof_duration("Deposit", deposit_elapsed);
    scenario
        .balance_witness_generator
        .commit_receive_deposit(&deposit_proof, &deposit_witness)
        .expect("commit deposit");
    log_step("Deposit committed");

    let transfer_recipient_salt = Salt::rand(rng);
    let recipient_user = UserId::new(1, 1).expect("recipient user id");
    let transfer = Transfer {
        recipient: calculate_recipient_from_user_id(recipient_user, transfer_recipient_salt),
        token_index: 0,
        amount: U256::from(3u32),
        aux_data: Bytes32::default(),
    };
    let sender_balance_proof = scenario.balance_witness_generator.balance_proof.clone();
    log_step("Building spend witness");
    let spend_witness = scenario
        .balance_witness_generator
        .spend_witness(&[transfer.clone()])
        .expect("spend witness");
    log_step("Proving spend");
    let spend_timer = Instant::now();
    let spend_proof = scenario
        .spend_circuit
        .prove(&spend_witness)
        .expect("spend proof");
    let spend_elapsed = spend_timer.elapsed();
    log_proof_duration("Spend", spend_elapsed);

    let mut transfer_tree = TransferTree::init();
    transfer_tree.push(transfer.clone());
    let transfer_tree_root = transfer_tree.get_root();
    let transfer_index = 0u32;
    let transfer_merkle_proof = transfer_tree.prove(transfer_index as u64);

    let tx = Tx {
        transfer_tree_root,
        nonce: scenario.balance_witness_generator.full_private_state.nonce,
    };
    let mut tx_tree = TxTree::init();
    tx_tree.update(scenario.user_id.local_id() as u64, tx.clone());
    let tx_tree_root = tx_tree.get_root();
    let tx_merkle_proof = tx_tree.prove(scenario.user_id.local_id() as u64);
    let tx_tree_root_bytes: Bytes32 = tx_tree_root.into();

    {
        let mut generator = scenario.block_witness_generator.borrow_mut();
        generator
            .add_block(
                scenario.user_id.aggregator_id(),
                &[scenario.user_id.local_id()],
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
    let send_tx_witness = scenario
        .balance_witness_generator
        .send_tx_witness(&send_tx_data)
        .expect("send tx witness");
    log_step("Proving send transaction");
    let send_timer = Instant::now();
    let balance_proof = scenario
        .balance_processor
        .prove_send_tx(&send_tx_witness)
        .expect("send tx proof");
    let send_elapsed = send_timer.elapsed();
    log_proof_duration("Send transaction", send_elapsed);
    scenario
        .balance_witness_generator
        .commit_send_tx(&balance_proof, &send_tx_witness, &spend_witness)
        .expect("commit send tx");
    log_step("Send transaction committed");

    SendTxOutcome {
        sender_balance_proof,
        send_tx_data,
        transfer,
        transfer_index,
        transfer_merkle_proof,
        transfer_salt: transfer_recipient_salt,
    }
}

#[wasm_bindgen_test]
fn wasm_balance_processor_flow() {
    log_step("=== wasm_balance_processor_flow start ===");
    let supported_user_counts = vec![2];
    let mut rng = StdRng::seed_from_u64(42);
    let mut scenario = BalanceScenario::new(&supported_user_counts, &mut rng);

    log_step("Performing deposit and send transaction setup");
    let outcome = perform_deposit(&mut scenario, &mut rng);
    log_step("Deposit flow completed, preparing receive transfer");

    // Produce a receive transfer witness for the recipient.
    let user_id2 = UserId::new(1, 1).expect("second user");
    let salt2 = Salt::rand(&mut rng);
    let mut receiver = BalanceWitnessGenerator::new(
        user_id2,
        salt2,
        scenario.block_witness_generator.clone(),
        &scenario.balance_processor,
    )
    .expect("receiver balance generator");

    let receive_transfer_data = ReceiveTransferData {
        to: user_id2,
        transfer: outcome.transfer.clone(),
        sender_proof: outcome.sender_balance_proof.clone(),
        spend_proof: outcome.send_tx_data.spend_proof.clone(),
        tx_tree_root: outcome.send_tx_data.tx_tree_root,
        tx: outcome.send_tx_data.tx.clone(),
        tx_merkle_proof: outcome.send_tx_data.tx_merkle_proof.clone(),
        transfer_index: outcome.transfer_index,
        transfer_merkle_proof: outcome.transfer_merkle_proof.clone(),
        transfer_salt: outcome.transfer_salt,
    };

    log_step("Building receive transfer witness");
    let receive_witness = receiver
        .receive_transfer_witness(&receive_transfer_data)
        .expect("receive transfer witness");
    log_step("Proving receive transfer");
    let receive_timer = Instant::now();
    let receive_proof = scenario
        .balance_processor
        .prove_receive_transfer(&receive_witness)
        .expect("receive transfer proof");
    let receive_elapsed = receive_timer.elapsed();
    log_proof_duration("Receive transfer", receive_elapsed);
    receiver
        .commit_receive_transfer(&receive_proof, &receive_witness)
        .expect("commit receive transfer");
    log_step("Receive transfer committed");
    log_step("=== wasm_balance_processor_flow end ===");
}

#[wasm_bindgen_test]
fn wasm_single_withdrawal_proof() {
    log_step("=== wasm_single_withdrawal_proof start ===");
    let supported_user_counts = vec![2];
    let mut rng = StdRng::seed_from_u64(1234);
    let mut scenario = BalanceScenario::new(&supported_user_counts, &mut rng);

    log_step("Preparing scenario deposit before withdrawal");
    let _outcome = perform_deposit(&mut scenario, &mut rng);

    // Prepare a withdrawal transfer to an external address.
    let withdrawal_address = Address::rand(&mut rng);
    let transfer = Transfer {
        recipient: calculate_recipient_from_address(withdrawal_address),
        token_index: 0,
        amount: U256::from(2u32),
        aux_data: Bytes32::default(),
    };
    log_step("Building withdrawal spend witness");
    let spend_witness = scenario
        .balance_witness_generator
        .spend_witness(&[transfer.clone()])
        .expect("withdrawal spend witness");
    log_step("Proving withdrawal spend");
    let spend_timer = Instant::now();
    let spend_proof = scenario
        .spend_circuit
        .prove(&spend_witness)
        .expect("withdrawal spend proof");
    let withdrawal_spend_elapsed = spend_timer.elapsed();
    log_proof_duration("Withdrawal spend", withdrawal_spend_elapsed);

    let mut transfer_tree = TransferTree::init();
    transfer_tree.push(transfer.clone());
    let transfer_index = 0u32;
    let transfer_merkle_proof = transfer_tree.prove(transfer_index as u64);
    let transfer_tree_root = transfer_tree.get_root();

    let tx = Tx {
        transfer_tree_root,
        nonce: scenario.balance_witness_generator.full_private_state.nonce,
    };
    let mut tx_tree = TxTree::init();
    tx_tree.update(scenario.user_id.local_id() as u64, tx.clone());
    let tx_tree_root = tx_tree.get_root();
    let tx_tree_root_bytes: Bytes32 = tx_tree_root.into();
    let tx_merkle_proof = tx_tree.prove(scenario.user_id.local_id() as u64);

    {
        let mut generator = scenario.block_witness_generator.borrow_mut();
        generator
            .add_block(
                scenario.user_id.aggregator_id(),
                &[scenario.user_id.local_id()],
                2,
                tx_tree_root_bytes,
            )
            .expect("apply withdrawal block");
    }

    let send_tx_data = SendTxData {
        spend_proof: spend_proof.clone(),
        tx_tree_root: tx_tree_root_bytes,
        tx: tx.clone(),
        tx_merkle_proof: tx_merkle_proof.clone(),
    };
    log_step("Building withdrawal send witness");
    let send_tx_witness = scenario
        .balance_witness_generator
        .send_tx_witness(&send_tx_data)
        .expect("withdrawal send witness");
    log_step("Proving withdrawal send transaction");
    let send_timer = Instant::now();
    let balance_proof = scenario
        .balance_processor
        .prove_send_tx(&send_tx_witness)
        .expect("withdrawal send proof");
    let withdrawal_send_elapsed = send_timer.elapsed();
    log_proof_duration("Withdrawal send transaction", withdrawal_send_elapsed);
    scenario
        .balance_witness_generator
        .commit_send_tx(&balance_proof, &send_tx_witness, &spend_witness)
        .expect("commit withdrawal send tx");
    log_step("Withdrawal send transaction committed");

    let withdrawal_data = SingleWithdrawalData {
        tx_tree_root: tx_tree_root_bytes,
        tx: tx.clone(),
        tx_merkle_proof,
        transfer: transfer.clone(),
        transfer_index,
        transfer_merkle_proof,
    };
    log_step("Building single withdrawal witness");
    let withdrawal_witness = scenario
        .balance_witness_generator
        .single_withdrawal_witness(&withdrawal_data)
        .expect("single withdrawal witness");

    let single_withdrawal_circuit = load_single_withdrawal_circuit();
    log_step("Proving single withdrawal circuit");
    let withdrawal_timer = Instant::now();
    let proof = single_withdrawal_circuit
        .prove(&withdrawal_witness)
        .expect("single withdrawal proof");
    let withdrawal_elapsed = withdrawal_timer.elapsed();
    log_proof_duration("Single withdrawal", withdrawal_elapsed);
    log_step("Verifying single withdrawal proof");
    single_withdrawal_circuit
        .data
        .verify(proof.clone())
        .expect("single withdrawal proof verifies");

    let withdrawal_processor =
        WithdrawalProcessor::<F, C, D>::new(&single_withdrawal_circuit.data.verifier_data());
    finalize_withdrawal_chain(
        &withdrawal_processor,
        proof,
        &withdrawal_witness.update_public_state,
        &scenario.block_witness_generator,
    )
    .expect("final withdrawal proof");
    log_step("=== wasm_single_withdrawal_proof end ===");
}

fn finalize_withdrawal_chain(
    withdrawal_processor: &WithdrawalProcessor<F, C, D>,
    single_withdrawal_proof: plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>,
    update_public_state: &intmax3_zkp::circuits::balance::common::update_public_state::UpdatePublicState,
    block_witness_generator: &BlockWitnessGeneratorHandle,
) -> Result<(), WithdrawalProcessorError> {
    log_step("Starting withdrawal chain finalization");
    let step_witness = WithdrawalStepWitness::<F, C, D> {
        prev_withdrawal_chain_proof: None,
        single_withdrawal_proof: single_withdrawal_proof.clone(),
        update_public_state: update_public_state.clone(),
    };
    log_step("Proving withdrawal chain step");
    let step_timer = Instant::now();
    let chain_proof = withdrawal_processor.prove_step(&step_witness)?;
    let step_elapsed = step_timer.elapsed();
    log_proof_duration("Withdrawal chain step", step_elapsed);

    let ext_public_state = block_witness_generator
        .borrow()
        .current_extended_public_state();
    let mut rng = StdRng::seed_from_u64(999);
    log_step("Proving withdrawal chain final");
    let final_timer = Instant::now();
    let final_proof = withdrawal_processor.prove_final(
        &chain_proof,
        Address::rand(&mut rng),
        &ext_public_state,
    )?;
    let final_elapsed = final_timer.elapsed();
    log_proof_duration("Withdrawal chain final", final_elapsed);
    log_step("Verifying final withdrawal proof");
    withdrawal_processor
        .withdrawal_vd()
        .verify(final_proof)
        .expect("final withdrawal verifies");
    log_step("Withdrawal chain finalization complete");
    Ok(())
}
