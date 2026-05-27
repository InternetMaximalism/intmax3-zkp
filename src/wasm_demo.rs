//! Browser demo entry points for running ZK proofs in WASM.
//!
//! WASM memory constraint: wasm32 has a 4GB hard limit on linear memory.
//! The proof pipeline uses ~4GB at peak. When adding new proof steps or holding
//! additional data, use explicit `drop()` to free circuit data, witnesses, and
//! proofs as soon as they are no longer needed.

use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use rand::{SeedableRng, rngs::StdRng};
use web_time::Instant;

use crate::{
    circuits::{
        balance::{
            balance_processor::BalanceProcessor,
            common::{
                recipient::{calculate_recipient_from_address, calculate_recipient_from_user_id},
                update_public_state::UpdatePublicState,
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
            withdrawal_processor::WithdrawalProcessor, withdrawal_step::WithdrawalStepWitness,
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

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

// TODO: fetch over HTTP for production instead of embedding ~711MB into the WASM binary
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

fn log(msg: &str) {
    web_sys::console::log_1(&msg.into());
}

fn log_bench(step: &str, duration: web_time::Duration) {
    log(&format!("[BENCH] {step}: {:.3}s", duration.as_secs_f64()));
}

// ---------------------------------------------------------------------------
// Shared helpers (async equivalents of helpers in tests/wasm_proofs.rs)
// ---------------------------------------------------------------------------

fn load_spend_circuit() -> Result<SpendCircuit<F, C, D>, JsValue> {
    SpendCircuit::<F, C, D>::from_bytes(SPEND_CIRCUIT_BYTES)
        .map_err(|e| JsValue::from_str(&format!("load spend circuit: {e}")))
}

fn load_balance_processor() -> Result<BalanceProcessor<F, C, D>, JsValue> {
    BalanceProcessor::<F, C, D>::from_bytes(BALANCE_PROCESSOR_BYTES)
        .map_err(|e| JsValue::from_str(&format!("load balance processor: {e}")))
}

fn load_single_withdrawal_circuit() -> Result<SingleWithdawalCircuit<F, C, D>, JsValue> {
    SingleWithdawalCircuit::<F, C, D>::from_bytes(SINGLE_WITHDRAWAL_BYTES)
        .map_err(|e| JsValue::from_str(&format!("load withdrawal circuit: {e}")))
}

/// Async equivalent of `BalanceScenario` in `tests/wasm_proofs.rs`.
struct BalanceScenarioAsync {
    spend_circuit: SpendCircuit<F, C, D>,
    balance_processor: BalanceProcessor<F, C, D>,
    block_witness_generator: BlockWitnessGeneratorHandle,
    user_id: UserId,
    balance_witness_generator: BalanceWitnessGenerator<F, C, D>,
}

impl BalanceScenarioAsync {
    async fn new(supported_user_counts: &[u32], rng: &mut StdRng) -> Result<Self, JsValue> {
        log("Loading circuits from fixtures...");
        let t = Instant::now();
        let spend_circuit = load_spend_circuit()?;
        let balance_processor = load_balance_processor()?;
        log_bench("Circuit loading", t.elapsed());

        let block_witness_generator =
            BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(supported_user_counts));

        let user_id = UserId::new(0, 1).map_err(|e| JsValue::from_str(&format!("user id: {e}")))?;
        let salt = Salt::rand(rng);

        log("Creating balance witness generator (async)...");
        let t = Instant::now();
        let balance_witness_generator = BalanceWitnessGenerator::new_async(
            user_id,
            salt,
            block_witness_generator.clone(),
            &balance_processor,
        )
        .await
        .map_err(|e| JsValue::from_str(&format!("balance witness generator: {e}")))?;
        log_bench("Balance witness generator init", t.elapsed());

        Ok(Self {
            spend_circuit,
            balance_processor,
            block_witness_generator,
            user_id,
            balance_witness_generator,
        })
    }
}

/// Outcome of `perform_deposit_async`, mirrors `SendTxOutcome` in `tests/wasm_proofs.rs`.
struct SendTxOutcome {
    sender_balance_proof: ProofWithPublicInputs<F, C, D>,
    send_tx_data: SendTxData<F, C, D>,
    transfer: Transfer,
    transfer_index: u32,
    transfer_merkle_proof: TransferMerkleProof,
    transfer_salt: Salt,
}

/// Async equivalent of `perform_deposit` in `tests/wasm_proofs.rs`.
/// Deposits 10 tokens, then performs an internal transfer of 3 tokens to user_id=(1,1).
async fn perform_deposit_async(
    scenario: &mut BalanceScenarioAsync,
    rng: &mut StdRng,
) -> Result<SendTxOutcome, JsValue> {
    log("Starting deposit flow");
    let deposit_salt = Salt::rand(rng);
    let deposit_recipient = calculate_recipient_from_user_id(scenario.user_id, deposit_salt);
    {
        let mut block_gen = scenario.block_witness_generator.borrow_mut();
        block_gen
            .add_deposit(
                Address::rand(rng),
                deposit_recipient,
                0,
                U256::from(10u32),
                Bytes32::default(),
            )
            .map_err(|e| JsValue::from_str(&format!("add deposit: {e}")))?;
        block_gen
            .add_block(0, &[], 0, Bytes32::default())
            .map_err(|e| JsValue::from_str(&format!("deposit block: {e}")))?;
    }

    let deposit_witness = scenario
        .balance_witness_generator
        .receive_deposit_witness(&ReceiveDepositData {
            receiver: deposit_recipient,
            deposit_salt,
        })
        .map_err(|e| JsValue::from_str(&format!("deposit witness: {e}")))?;

    log("Proving deposit");
    let t = Instant::now();
    let deposit_proof = scenario
        .balance_processor
        .prove_receive_deposit_async(&deposit_witness)
        .await
        .map_err(|e| JsValue::from_str(&format!("deposit prove: {e}")))?;
    log_bench("Deposit proof", t.elapsed());

    scenario
        .balance_witness_generator
        .commit_receive_deposit(&deposit_proof, &deposit_witness)
        .map_err(|e| JsValue::from_str(&format!("commit deposit: {e}")))?;
    log("Deposit committed");

    // Internal transfer: spend 3 tokens to user_id=(1,1)
    let transfer_recipient_salt = Salt::rand(rng);
    let recipient_user =
        UserId::new(1, 1).map_err(|e| JsValue::from_str(&format!("recipient user id: {e}")))?;
    let transfer = Transfer {
        recipient: calculate_recipient_from_user_id(recipient_user, transfer_recipient_salt),
        token_index: 0,
        amount: U256::from(3u32),
        aux_data: Bytes32::default(),
    };
    let sender_balance_proof = scenario.balance_witness_generator.balance_proof.clone();

    let spend_witness = scenario
        .balance_witness_generator
        .spend_witness(&[transfer.clone()])
        .map_err(|e| JsValue::from_str(&format!("spend witness: {e}")))?;

    log("Proving spend");
    let t = Instant::now();
    let spend_proof = scenario
        .spend_circuit
        .prove_async(&spend_witness)
        .await
        .map_err(|e| JsValue::from_str(&format!("spend prove: {e}")))?;
    log_bench("Spend proof", t.elapsed());

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
        let mut block_gen = scenario.block_witness_generator.borrow_mut();
        block_gen
            .add_block(
                scenario.user_id.aggregator_id(),
                &[scenario.user_id.local_id()],
                1,
                tx_tree_root_bytes,
            )
            .map_err(|e| JsValue::from_str(&format!("tx block: {e}")))?;
    }

    let send_tx_data = SendTxData {
        spend_proof: spend_proof.clone(),
        tx_tree_root: tx_tree_root_bytes,
        tx: tx.clone(),
        tx_merkle_proof: tx_merkle_proof.clone(),
        tx_v2: None,
        tx_v2_merkle_proof: None,
    };
    let send_tx_witness = scenario
        .balance_witness_generator
        .send_tx_witness(&send_tx_data)
        .map_err(|e| JsValue::from_str(&format!("send tx witness: {e}")))?;

    log("Proving send transaction");
    let t = Instant::now();
    let balance_proof = scenario
        .balance_processor
        .prove_send_tx_async(&send_tx_witness)
        .await
        .map_err(|e| JsValue::from_str(&format!("send tx prove: {e}")))?;
    log_bench("Send tx proof", t.elapsed());

    scenario
        .balance_witness_generator
        .commit_send_tx(&balance_proof, &send_tx_witness, &spend_witness)
        .map_err(|e| JsValue::from_str(&format!("commit send tx: {e}")))?;
    log("Send transaction committed");

    Ok(SendTxOutcome {
        sender_balance_proof,
        send_tx_data,
        transfer,
        transfer_index,
        transfer_merkle_proof,
        transfer_salt: transfer_recipient_salt,
    })
}

/// Async equivalent of `finalize_withdrawal_chain` in `tests/wasm_proofs.rs`.
async fn finalize_withdrawal_chain_async(
    withdrawal_processor: &WithdrawalProcessor<F, C, D>,
    single_withdrawal_proof: ProofWithPublicInputs<F, C, D>,
    update_public_state: &UpdatePublicState,
    block_witness_generator: &BlockWitnessGeneratorHandle,
) -> Result<(), JsValue> {
    log("Starting withdrawal chain finalization");
    let step_witness = WithdrawalStepWitness::<F, C, D> {
        prev_withdrawal_chain_proof: None,
        single_withdrawal_proof,
        update_public_state: update_public_state.clone(),
    };

    log("Proving withdrawal chain step");
    let t = Instant::now();
    let chain_proof = withdrawal_processor
        .prove_step_async(&step_witness)
        .await
        .map_err(|e| JsValue::from_str(&format!("chain step prove: {e}")))?;
    log_bench("Withdrawal chain step", t.elapsed());

    let ext_public_state = block_witness_generator
        .borrow()
        .current_extended_public_state();
    let mut rng = StdRng::seed_from_u64(999);

    log("Proving withdrawal chain final");
    let t = Instant::now();
    let final_proof = withdrawal_processor
        .prove_final_async(&chain_proof, Address::rand(&mut rng), &ext_public_state)
        .await
        .map_err(|e| JsValue::from_str(&format!("chain final prove: {e}")))?;
    log_bench("Withdrawal chain final", t.elapsed());

    log("Verifying final withdrawal proof");
    withdrawal_processor
        .withdrawal_vd()
        .verify(final_proof)
        .map_err(|e| JsValue::from_str(&format!("final verify: {e}")))?;
    log("Withdrawal chain finalization complete");

    Ok(())
}

// ---------------------------------------------------------------------------
// WASM entry points
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub async fn run_single_withdrawal_proof() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    let flow_start = Instant::now();

    let supported_user_counts = vec![2];
    let mut rng = StdRng::seed_from_u64(1234);
    let mut scenario = BalanceScenarioAsync::new(&supported_user_counts, &mut rng).await?;

    // Deposit + internal transfer (mirrors perform_deposit in wasm_proofs.rs)
    let _outcome = perform_deposit_async(&mut scenario, &mut rng).await?;

    // === Withdrawal spend ===
    let withdrawal_address = Address::rand(&mut rng);
    let transfer = Transfer {
        recipient: calculate_recipient_from_address(withdrawal_address),
        token_index: 0,
        amount: U256::from(2u32),
        aux_data: Bytes32::default(),
    };

    log("Building withdrawal spend witness");
    let spend_witness = scenario
        .balance_witness_generator
        .spend_witness(&[transfer.clone()])
        .map_err(|e| JsValue::from_str(&format!("withdrawal spend witness: {e}")))?;

    log("Proving withdrawal spend");
    let t = Instant::now();
    let spend_proof = scenario
        .spend_circuit
        .prove_async(&spend_witness)
        .await
        .map_err(|e| JsValue::from_str(&format!("withdrawal spend prove: {e}")))?;
    log_bench("Spend proof", t.elapsed());

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
        let mut block_gen = scenario.block_witness_generator.borrow_mut();
        block_gen
            .add_block(
                scenario.user_id.aggregator_id(),
                &[scenario.user_id.local_id()],
                2,
                tx_tree_root_bytes,
            )
            .map_err(|e| JsValue::from_str(&format!("withdrawal block: {e}")))?;
    }

    let send_tx_data = SendTxData {
        spend_proof: spend_proof.clone(),
        tx_tree_root: tx_tree_root_bytes,
        tx: tx.clone(),
        tx_merkle_proof: tx_merkle_proof.clone(),
        tx_v2: None,
        tx_v2_merkle_proof: None,
    };
    log("Building withdrawal send witness");
    let send_tx_witness = scenario
        .balance_witness_generator
        .send_tx_witness(&send_tx_data)
        .map_err(|e| JsValue::from_str(&format!("withdrawal send witness: {e}")))?;

    log("Proving withdrawal send transaction");
    let t = Instant::now();
    let balance_proof = scenario
        .balance_processor
        .prove_send_tx_async(&send_tx_witness)
        .await
        .map_err(|e| JsValue::from_str(&format!("withdrawal send prove: {e}")))?;
    log_bench("Send tx proof", t.elapsed());

    scenario
        .balance_witness_generator
        .commit_send_tx(&balance_proof, &send_tx_witness, &spend_witness)
        .map_err(|e| JsValue::from_str(&format!("commit withdrawal send tx: {e}")))?;
    log("Withdrawal send transaction committed");

    // === Single withdrawal ===
    let withdrawal_data = SingleWithdrawalData {
        tx_tree_root: tx_tree_root_bytes,
        tx: tx.clone(),
        tx_merkle_proof,
        tx_v2: None,
        tx_v2_merkle_proof: None,
        transfer: transfer.clone(),
        transfer_index,
        transfer_merkle_proof,
    };
    log("Building single withdrawal witness");
    let withdrawal_witness = scenario
        .balance_witness_generator
        .single_withdrawal_witness(&withdrawal_data)
        .map_err(|e| JsValue::from_str(&format!("withdrawal witness: {e}")))?;

    let single_withdrawal_circuit = load_single_withdrawal_circuit()?;

    log("Proving single withdrawal circuit");
    let t = Instant::now();
    let proof = single_withdrawal_circuit
        .prove_async(&withdrawal_witness)
        .await
        .map_err(|e| JsValue::from_str(&format!("withdrawal prove: {e}")))?;
    log_bench("Single withdrawal proof", t.elapsed());

    log("Verifying single withdrawal proof");
    single_withdrawal_circuit
        .data
        .verify(proof.clone())
        .map_err(|e| JsValue::from_str(&format!("withdrawal verify: {e}")))?;

    // === Withdrawal chain ===
    log("Building withdrawal processor...");
    let t = Instant::now();
    let withdrawal_processor =
        WithdrawalProcessor::<F, C, D>::new_async(&single_withdrawal_circuit.data.verifier_data())
            .await;
    log_bench("Withdrawal processor construction", t.elapsed());

    let update_public_state = withdrawal_witness.update_public_state.clone();
    let block_witness_generator = scenario.block_witness_generator.clone();

    // Drop data no longer needed before chain proving to avoid OOM
    drop(withdrawal_witness);
    drop(single_withdrawal_circuit);
    drop(scenario);

    finalize_withdrawal_chain_async(
        &withdrawal_processor,
        proof,
        &update_public_state,
        &block_witness_generator,
    )
    .await?;

    log_bench("Total flow", flow_start.elapsed());
    log("=== run_single_withdrawal_proof complete ===");
    Ok(())
}

#[wasm_bindgen]
pub async fn run_balance_processor_flow() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    let flow_start = Instant::now();

    log("=== run_balance_processor_flow start ===");

    let supported_user_counts = vec![2];
    let mut rng = StdRng::seed_from_u64(42);
    let mut scenario = BalanceScenarioAsync::new(&supported_user_counts, &mut rng).await?;

    // Deposit + internal transfer (mirrors perform_deposit in wasm_proofs.rs)
    let outcome = perform_deposit_async(&mut scenario, &mut rng).await?;

    // Destructure scenario to allow selective drops for OOM mitigation
    let BalanceScenarioAsync {
        spend_circuit,
        balance_processor,
        block_witness_generator,
        balance_witness_generator,
        ..
    } = scenario;

    // === Receive Transfer (second user) ===
    log("Setting up receiver...");
    let user_id2 =
        UserId::new(1, 1).map_err(|e| JsValue::from_str(&format!("second user id: {e}")))?;
    let salt2 = Salt::rand(&mut rng);

    // Drop spend_circuit before creating receiver to free memory
    drop(spend_circuit);

    let mut receiver = BalanceWitnessGenerator::new_async(
        user_id2,
        salt2,
        block_witness_generator.clone(),
        &balance_processor,
    )
    .await
    .map_err(|e| JsValue::from_str(&format!("receiver balance generator: {e}")))?;

    let receive_transfer_data = ReceiveTransferData {
        to: user_id2,
        transfer: outcome.transfer.clone(),
        sender_proof: outcome.sender_balance_proof,
        spend_proof: outcome.send_tx_data.spend_proof.clone(),
        tx_tree_root: outcome.send_tx_data.tx_tree_root,
        tx: outcome.send_tx_data.tx.clone(),
        tx_merkle_proof: outcome.send_tx_data.tx_merkle_proof.clone(),
        tx_v2: outcome.send_tx_data.tx_v2,
        tx_v2_merkle_proof: outcome.send_tx_data.tx_v2_merkle_proof.clone(),
        transfer_index: outcome.transfer_index,
        transfer_merkle_proof: outcome.transfer_merkle_proof,
        transfer_salt: outcome.transfer_salt,
    };

    // Drop data no longer needed
    drop(balance_witness_generator);

    log("Building receive transfer witness");
    let receive_witness = receiver
        .receive_transfer_witness(&receive_transfer_data)
        .map_err(|e| JsValue::from_str(&format!("receive transfer witness: {e}")))?;
    drop(receive_transfer_data);

    log("Proving receive transfer");
    let t = Instant::now();
    let receive_proof = balance_processor
        .prove_receive_transfer_async(&receive_witness)
        .await
        .map_err(|e| JsValue::from_str(&format!("receive transfer prove: {e}")))?;
    log_bench("Receive transfer proof", t.elapsed());

    receiver
        .commit_receive_transfer(&receive_proof, &receive_witness)
        .map_err(|e| JsValue::from_str(&format!("commit receive transfer: {e}")))?;
    log("Receive transfer committed");

    log_bench("Total flow", flow_start.elapsed());
    log("=== run_balance_processor_flow complete ===");
    Ok(())
}
