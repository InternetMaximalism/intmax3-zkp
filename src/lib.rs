// WASM memory constraint: wasm32 has a 4GB hard limit on linear memory.
// The proof pipeline uses ~4GB at peak. When adding new proof steps or holding
// additional data, use explicit `drop()` to free circuit data, witnesses, and
// proofs as soon as they are no longer needed. See `run_single_withdrawal_proof()`
// and `run_balance_processor_flow()` for examples.

pub mod circuits;
pub mod common;
pub mod constants;
pub mod ethereum_types;
pub mod utils;
pub mod wrapper_config;

pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(all(feature = "gpu_merkle", target_arch = "wasm32"))]
use plonky2::hash::merkle_tree_gpu;

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[wasm_bindgen]
pub async fn init_gpu_merkle() -> Result<(), JsValue> {
    #[cfg(all(feature = "gpu_merkle", target_arch = "wasm32"))]
    {
        merkle_tree_gpu::initialize()
            .await
            .map_err(|err| JsValue::from_str(&format!("GPU init failed: {err}")))?;
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
mod wasm_entry {
    use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::circuits::balance::balance_processor::BalanceProcessor;
    use crate::circuits::balance::common::recipient::calculate_recipient_from_address;
    use crate::circuits::balance::spend_circuit::SpendCircuit;
    use crate::circuits::test_utils::balance_witness_generator::{
        BalanceWitnessGenerator, ReceiveDepositData, ReceiveTransferData, SendTxData,
        SingleWithdrawalData,
    };
    use crate::circuits::balance::common::recipient::calculate_recipient_from_user_id;
    use crate::circuits::test_utils::block_witness_generator::{
        BlockWitnessGenerator, BlockWitnessGeneratorHandle,
    };
    use crate::circuits::withdraw::single_withdrawal_circuit::SingleWithdawalCircuit;
    use crate::circuits::withdraw::withdrawal_processor::WithdrawalProcessor;
    use crate::circuits::withdraw::withdrawal_step::WithdrawalStepWitness;
    use crate::common::salt::Salt;
    use crate::common::transfer::Transfer;
    use crate::common::trees::transfer_tree::{TransferMerkleProof, TransferTree};
    use crate::common::trees::tx_tree::TxTree;
    use crate::common::tx::Tx;
    use crate::common::user_id::UserId;
    use crate::ethereum_types::address::Address;
    use crate::ethereum_types::bytes32::Bytes32;
    use crate::ethereum_types::u32limb_trait::U32LimbTrait;
    use crate::ethereum_types::u256::U256;

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

    fn log(msg: &str) {
        web_sys::console::log_1(&msg.into());
    }

    fn log_duration(step: &str, duration: f64) {
        log(&format!("{step}: {duration:.3}s"));
    }

    #[wasm_bindgen]
    pub async fn run_single_withdrawal_proof() -> Result<(), JsValue> {
        console_error_panic_hook::set_once();

        log("Loading circuits from fixtures...");
        let start = js_sys::Date::now();
        let spend_circuit = SpendCircuit::<F, C, D>::from_bytes(SPEND_CIRCUIT_BYTES)
            .map_err(|e| JsValue::from_str(&format!("load spend circuit: {e}")))?;
        let balance_processor = BalanceProcessor::<F, C, D>::from_bytes(BALANCE_PROCESSOR_BYTES)
            .map_err(|e| JsValue::from_str(&format!("load balance processor: {e}")))?;
        let single_withdrawal_circuit =
            SingleWithdawalCircuit::<F, C, D>::from_bytes(SINGLE_WITHDRAWAL_BYTES)
                .map_err(|e| JsValue::from_str(&format!("load withdrawal circuit: {e}")))?;
        log_duration("Circuit loading", (js_sys::Date::now() - start) / 1000.0);

        log("Setting up scenario...");
        let supported_user_counts = vec![2];
        let mut rng = StdRng::seed_from_u64(1234);
        let block_witness_generator =
            BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

        let user_id = UserId::new(0, 1)
            .map_err(|e| JsValue::from_str(&format!("user id: {e}")))?;
        let salt = Salt::rand(&mut rng);
        log("Creating balance witness generator (async)...");
        let mut balance_witness_generator = BalanceWitnessGenerator::new_async(
            user_id,
            salt,
            block_witness_generator.clone(),
            &balance_processor,
        )
        .await
        .map_err(|e| JsValue::from_str(&format!("balance witness generator: {e}")))?;

        // Deposit
        log("Performing deposit...");
        let deposit_salt = Salt::rand(&mut rng);
        let deposit_recipient =
            crate::circuits::balance::common::recipient::calculate_recipient_from_user_id(
                user_id,
                deposit_salt,
            );
        {
            let mut block_gen = block_witness_generator.borrow_mut();
            block_gen.add_deposit(
                Address::rand(&mut rng),
                deposit_recipient,
                0,
                U256::from(10u32),
                Bytes32::default(),
            )
            .map_err(|e| JsValue::from_str(&format!("add deposit: {e}")))?;
            block_gen.add_block(0, &[], 0, Bytes32::default())
                .map_err(|e| JsValue::from_str(&format!("deposit block: {e}")))?;
        }

        let deposit_witness = balance_witness_generator
            .receive_deposit_witness(&ReceiveDepositData {
                receiver: deposit_recipient,
                deposit_salt,
            })
            .map_err(|e| JsValue::from_str(&format!("deposit witness: {e}")))?;

        let t = js_sys::Date::now();
        let deposit_proof = balance_processor
            .prove_receive_deposit_async(&deposit_witness)
            .await
            .map_err(|e| JsValue::from_str(&format!("deposit prove: {e}")))?;
        log_duration("Deposit proof", (js_sys::Date::now() - t) / 1000.0);

        balance_witness_generator
            .commit_receive_deposit(&deposit_proof, &deposit_witness)
            .map_err(|e| JsValue::from_str(&format!("commit deposit: {e}")))?;

        // Withdrawal spend
        log("Proving withdrawal spend...");
        let withdrawal_address = Address::rand(&mut rng);
        let transfer = Transfer {
            recipient: calculate_recipient_from_address(withdrawal_address),
            token_index: 0,
            amount: U256::from(2u32),
            aux_data: Bytes32::default(),
        };

        let spend_witness = balance_witness_generator
            .spend_witness(&[transfer.clone()])
            .map_err(|e| JsValue::from_str(&format!("spend witness: {e}")))?;

        let t = js_sys::Date::now();
        let spend_proof = spend_circuit
            .prove_async(&spend_witness)
            .await
            .map_err(|e| JsValue::from_str(&format!("spend prove: {e}")))?;
        log_duration("Spend proof", (js_sys::Date::now() - t) / 1000.0);

        // Build tx/transfer trees
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
            let mut block_gen = block_witness_generator.borrow_mut();
            block_gen.add_block(
                user_id.aggregator_id(),
                &[user_id.local_id()],
                2,
                tx_tree_root_bytes,
            )
            .map_err(|e| JsValue::from_str(&format!("withdrawal block: {e}")))?;
        }

        // Send tx
        log("Proving send transaction...");
        let send_tx_data = SendTxData {
            spend_proof: spend_proof.clone(),
            tx_tree_root: tx_tree_root_bytes,
            tx: tx.clone(),
            tx_merkle_proof: tx_merkle_proof.clone(),
        };
        let send_tx_witness = balance_witness_generator
            .send_tx_witness(&send_tx_data)
            .map_err(|e| JsValue::from_str(&format!("send tx witness: {e}")))?;

        let t = js_sys::Date::now();
        let balance_proof = balance_processor
            .prove_send_tx_async(&send_tx_witness)
            .await
            .map_err(|e| JsValue::from_str(&format!("send tx prove: {e}")))?;
        log_duration("Send tx proof", (js_sys::Date::now() - t) / 1000.0);

        balance_witness_generator
            .commit_send_tx(&balance_proof, &send_tx_witness, &spend_witness)
            .map_err(|e| JsValue::from_str(&format!("commit send tx: {e}")))?;

        // Single withdrawal
        log("Proving single withdrawal...");
        let withdrawal_data = SingleWithdrawalData {
            tx_tree_root: tx_tree_root_bytes,
            tx: tx.clone(),
            tx_merkle_proof,
            transfer: transfer.clone(),
            transfer_index,
            transfer_merkle_proof,
        };
        let withdrawal_witness = balance_witness_generator
            .single_withdrawal_witness(&withdrawal_data)
            .map_err(|e| JsValue::from_str(&format!("withdrawal witness: {e}")))?;

        let t = js_sys::Date::now();
        let proof = single_withdrawal_circuit
            .prove_async(&withdrawal_witness)
            .await
            .map_err(|e| JsValue::from_str(&format!("withdrawal prove: {e}")))?;
        log_duration("Single withdrawal proof", (js_sys::Date::now() - t) / 1000.0);

        single_withdrawal_circuit
            .data
            .verify(proof.clone())
            .map_err(|e| JsValue::from_str(&format!("withdrawal verify: {e}")))?;

        // Withdrawal chain
        log("Building withdrawal processor...");
        let t = js_sys::Date::now();
        let withdrawal_processor =
            WithdrawalProcessor::<F, C, D>::new_async(&single_withdrawal_circuit.data.verifier_data()).await;
        log_duration("Withdrawal processor construction", (js_sys::Date::now() - t) / 1000.0);

        let update_public_state = withdrawal_witness.update_public_state.clone();
        drop(withdrawal_witness);

        let step_witness = WithdrawalStepWitness::<F, C, D> {
            prev_withdrawal_chain_proof: None,
            single_withdrawal_proof: proof,
            update_public_state,
        };

        // Drop data no longer needed before proving
        drop(single_withdrawal_circuit);
        drop(balance_processor);
        drop(balance_witness_generator);
        drop(spend_circuit);

        log("Proving withdrawal chain step...");
        let t = js_sys::Date::now();
        let chain_proof = withdrawal_processor
            .prove_step_async(&step_witness)
            .await
            .map_err(|e| JsValue::from_str(&format!("chain step prove: {e}")))?;
        drop(step_witness);
        log_duration("Withdrawal chain step", (js_sys::Date::now() - t) / 1000.0);

        let ext_public_state = block_witness_generator
            .borrow()
            .current_extended_public_state();
        drop(block_witness_generator);
        let mut final_rng = StdRng::seed_from_u64(999);

        log("Proving withdrawal chain final...");
        let t = js_sys::Date::now();
        let final_proof = withdrawal_processor
            .prove_final_async(&chain_proof, Address::rand(&mut final_rng), &ext_public_state)
            .await
            .map_err(|e| JsValue::from_str(&format!("chain final prove: {e}")))?;
        drop(chain_proof);
        log_duration("Withdrawal chain final", (js_sys::Date::now() - t) / 1000.0);

        let withdrawal_vd = withdrawal_processor.withdrawal_vd().clone();
        drop(withdrawal_processor);
        withdrawal_vd
            .verify(final_proof)
            .map_err(|e| JsValue::from_str(&format!("final verify: {e}")))?;

        log("=== run_single_withdrawal_proof complete ===");
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn run_balance_processor_flow() -> Result<(), JsValue> {
        console_error_panic_hook::set_once();

        log("=== run_balance_processor_flow start ===");

        log("Loading circuits from fixtures...");
        let start = js_sys::Date::now();
        let spend_circuit = SpendCircuit::<F, C, D>::from_bytes(SPEND_CIRCUIT_BYTES)
            .map_err(|e| JsValue::from_str(&format!("load spend circuit: {e}")))?;
        let balance_processor = BalanceProcessor::<F, C, D>::from_bytes(BALANCE_PROCESSOR_BYTES)
            .map_err(|e| JsValue::from_str(&format!("load balance processor: {e}")))?;
        log_duration("Circuit loading", (js_sys::Date::now() - start) / 1000.0);

        log("Setting up scenario...");
        let supported_user_counts = vec![2];
        let mut rng = StdRng::seed_from_u64(42);
        let block_witness_generator =
            BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

        let user_id = UserId::new(0, 1)
            .map_err(|e| JsValue::from_str(&format!("user id: {e}")))?;
        let salt = Salt::rand(&mut rng);

        log("Creating balance witness generator (async)...");
        let mut balance_witness_generator = BalanceWitnessGenerator::new_async(
            user_id,
            salt,
            block_witness_generator.clone(),
            &balance_processor,
        )
        .await
        .map_err(|e| JsValue::from_str(&format!("balance witness generator: {e}")))?;

        // === Deposit ===
        log("Performing deposit...");
        let deposit_salt = Salt::rand(&mut rng);
        let deposit_recipient = calculate_recipient_from_user_id(user_id, deposit_salt);
        {
            let mut block_gen = block_witness_generator.borrow_mut();
            block_gen
                .add_deposit(
                    Address::rand(&mut rng),
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

        let deposit_witness = balance_witness_generator
            .receive_deposit_witness(&ReceiveDepositData {
                receiver: deposit_recipient,
                deposit_salt,
            })
            .map_err(|e| JsValue::from_str(&format!("deposit witness: {e}")))?;

        let t = js_sys::Date::now();
        let deposit_proof = balance_processor
            .prove_receive_deposit_async(&deposit_witness)
            .await
            .map_err(|e| JsValue::from_str(&format!("deposit prove: {e}")))?;
        log_duration("Deposit proof", (js_sys::Date::now() - t) / 1000.0);

        balance_witness_generator
            .commit_receive_deposit(&deposit_proof, &deposit_witness)
            .map_err(|e| JsValue::from_str(&format!("commit deposit: {e}")))?;
        log("Deposit committed");

        // === Spend + Send TX ===
        let transfer_recipient_salt = Salt::rand(&mut rng);
        let recipient_user = UserId::new(1, 1)
            .map_err(|e| JsValue::from_str(&format!("recipient user id: {e}")))?;
        let transfer = Transfer {
            recipient: calculate_recipient_from_user_id(recipient_user, transfer_recipient_salt),
            token_index: 0,
            amount: U256::from(3u32),
            aux_data: Bytes32::default(),
        };
        let sender_balance_proof = balance_witness_generator.balance_proof.clone();

        let spend_witness = balance_witness_generator
            .spend_witness(&[transfer.clone()])
            .map_err(|e| JsValue::from_str(&format!("spend witness: {e}")))?;

        log("Proving spend...");
        let t = js_sys::Date::now();
        let spend_proof = spend_circuit
            .prove_async(&spend_witness)
            .await
            .map_err(|e| JsValue::from_str(&format!("spend prove: {e}")))?;
        log_duration("Spend proof", (js_sys::Date::now() - t) / 1000.0);

        let mut transfer_tree = TransferTree::init();
        transfer_tree.push(transfer.clone());
        let transfer_tree_root = transfer_tree.get_root();
        let transfer_index = 0u32;
        let transfer_merkle_proof = transfer_tree.prove(transfer_index as u64);

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
            let mut block_gen = block_witness_generator.borrow_mut();
            block_gen
                .add_block(
                    user_id.aggregator_id(),
                    &[user_id.local_id()],
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
        };
        let send_tx_witness = balance_witness_generator
            .send_tx_witness(&send_tx_data)
            .map_err(|e| JsValue::from_str(&format!("send tx witness: {e}")))?;

        log("Proving send transaction...");
        let t = js_sys::Date::now();
        let balance_proof = balance_processor
            .prove_send_tx_async(&send_tx_witness)
            .await
            .map_err(|e| JsValue::from_str(&format!("send tx prove: {e}")))?;
        log_duration("Send tx proof", (js_sys::Date::now() - t) / 1000.0);

        balance_witness_generator
            .commit_send_tx(&balance_proof, &send_tx_witness, &spend_witness)
            .map_err(|e| JsValue::from_str(&format!("commit send tx: {e}")))?;
        log("Send transaction committed");

        // === Receive Transfer (second user) ===
        log("Setting up receiver...");
        let user_id2 = UserId::new(1, 1)
            .map_err(|e| JsValue::from_str(&format!("second user id: {e}")))?;
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
            transfer: transfer.clone(),
            sender_proof: sender_balance_proof,
            spend_proof: send_tx_data.spend_proof.clone(),
            tx_tree_root: send_tx_data.tx_tree_root,
            tx: send_tx_data.tx.clone(),
            tx_merkle_proof: send_tx_data.tx_merkle_proof.clone(),
            transfer_index,
            transfer_merkle_proof,
            transfer_salt: transfer_recipient_salt,
        };

        // Drop data no longer needed
        drop(send_tx_data);
        drop(balance_witness_generator);

        let receive_witness = receiver
            .receive_transfer_witness(&receive_transfer_data)
            .map_err(|e| JsValue::from_str(&format!("receive transfer witness: {e}")))?;
        drop(receive_transfer_data);

        log("Proving receive transfer...");
        let t = js_sys::Date::now();
        let receive_proof = balance_processor
            .prove_receive_transfer_async(&receive_witness)
            .await
            .map_err(|e| JsValue::from_str(&format!("receive transfer prove: {e}")))?;
        log_duration("Receive transfer proof", (js_sys::Date::now() - t) / 1000.0);

        receiver
            .commit_receive_transfer(&receive_proof, &receive_witness)
            .map_err(|e| JsValue::from_str(&format!("commit receive transfer: {e}")))?;
        log("Receive transfer committed");

        log("=== run_balance_processor_flow complete ===");
        Ok(())
    }
}
