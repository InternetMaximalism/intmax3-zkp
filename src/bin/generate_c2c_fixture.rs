//! Generate on-chain test fixtures for a CHANNEL-TO-CHANNEL (base-layer)
//! transfer where the RECEIVER channel withdraws.
//!
//! This binary mirrors the proof construction of the passing
//! `tests/e2e.rs::e2e_deposit_validity_withdrawal()` test FULLY (it keeps the
//! internal transfer + receive-transfer steps), but differs from it in two
//! ways:
//!   1. Channel 2 (the RECEIVER) is also REGISTERED (its own registration
//!      block), so its member set is committed into the channel tree.
//!   2. The final WITHDRAWAL is performed by channel 2 (the receiver) directly
//!      to an L1 address — NOT by channel 1 (the sender) as in e2e.rs.
//!
//! Chain built (5 blocks, two channels sharing one block generator):
//!   1. Registration block (ch1)   -> block 1
//!   2. Deposit block (ch1)         -> block 2
//!   3. Registration block (ch2)    -> block 3
//!   4. ch1 -> ch2 transfer block   -> block 4
//!   5. ch2 withdrawal tx block      -> block 5
//!
//! Two proofs are produced and each is wrapped (WrapperCircuit) + committed via
//! MLE (mirroring `src/bin/generate_withdrawal_fixture.rs`):
//!   - the ch2 withdrawal proof -> contracts/test/data/<prefix>withdrawal_mle.json
//!   - the validity proof       -> contracts/test/data/<prefix>lifecycle_validity_mle.json
//!
//! Plus two descriptor JSONs the Solidity test author consumes:
//!   - contracts/test/data/<prefix>lifecycle.json        (registration1/2, deposit, blocks, vpis)
//!   - contracts/test/data/<prefix>withdrawal_payout.json (the committed Withdrawal + prover)
//!
//! Usage:  cargo run --bin generate_c2c_fixture --release
//!
//! SECURITY: every exported value is pulled programmatically from the proved
//! objects (Block, ValidityPublicInputs, the single-withdrawal proof's public
//! inputs, the withdrawal-chain proof's committed hash). Nothing is hardcoded.
//! A Rust-side sanity re-fold of the withdrawal keccak chain proves the
//! on-chain fold will match BEFORE the human spends time on-chain.

use std::{fs, path::Path};

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
                ChannelMemberKeys, TEST_ACTIVE_MEMBERS,
            },
        },
        validity::block_hash_chain::{
            block_chain_pis::BlockChainPublicInputs,
            block_hash_chain_processor::BlockHashChainProcessor,
            validity_circuit::{ValidityCircuit, ValidityPublicInputs},
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
        channel_id::ChannelId as UserId,
        salt::Salt,
        transfer::Transfer,
        trees::{transfer_tree::TransferTree, tx_tree::TxTree, tx_v2_tree::TxV2Tree},
        tx::{Tx, TxClass, TxV2},
        u63::BlockNumber,
        withdrawal::Withdrawal,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
    utils::{
        conversion::ToU64,
        mle_prover::{export_mle_json, prove_with_mle, setup_mle_vk, verify_mle_proof},
        poseidon_hash_out::PoseidonHashOut,
        wrapper::WrapperCircuit,
    },
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::config::PoseidonGoldilocksConfig,
};
use rand::{SeedableRng, rngs::StdRng};
use serde::Serialize;

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

// ---------------------------------------------------------------------------
// Output JSON schemas
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct MemberFixture {
    channel_id: u32,
    bp_member_slot: u8,
    member_sphincs_pubkey_hashes: Vec<String>,
    regev_pk_digests: Vec<String>,
    recipients: Vec<String>,
}

#[derive(Serialize)]
struct DepositFixture {
    /// SECURITY: the on-chain `deposit()` folds `msg.sender` as the depositor into the deposit hash
    /// (IntmaxRollup `_computeDepositHash`). The Rust `Deposit` uses this exact address, so the
    /// Solidity test MUST `vm.prank(depositor)` when calling `deposit()` or the deposit hash (and
    /// hence block 2's hash) will not match the proved chain.
    depositor: String,
    recipient: String,
    token_index: u32,
    amount: String,
    aux_data: String,
}

#[derive(Serialize)]
struct BlockFixture {
    channel_id: u32,
    timestamp: u64,
    tx_tree_root: String,
    key_ids: Vec<u32>,
    block_number: u64,
}

#[derive(Serialize)]
struct VPIFixture {
    initial_block_number: u64,
    initial_block_chain: String,
    initial_ext_commitment: String,
    final_block_number: u64,
    final_block_chain: String,
    final_ext_commitment: String,
    prover: String,
}

#[derive(Serialize)]
struct LifecycleFixture {
    genesis_state_root: String,
    final_state_root: String,
    registration1: MemberFixture,
    registration2: MemberFixture,
    deposit: DepositFixture,
    blocks: Vec<BlockFixture>,
    vpis: VPIFixture,
    proof_hash: String,
    proof_length: u32,
}

#[derive(Serialize)]
struct WithdrawalEntryFixture {
    recipient: String,
    token_index: u32,
    amount: String,
    nullifier: String,
    aux_data: String,
}

#[derive(Serialize)]
struct WithdrawalPayoutFixture {
    withdrawals: Vec<WithdrawalEntryFixture>,
    withdrawal_prover: String,
    block_number: u64,
    ext_commitment: String,
}

/// Deterministic, dependency-free FNV-1a digest over a byte slice, placed in
/// the low 64 bits of a bytes32. Matches `generate_withdrawal_fixture.rs`. The
/// value is UNCONSTRAINED on-chain (finalize/fullVerify never re-derive the
/// submission commitment), so any deterministic value is sound; used only for
/// reproducibility.
fn fnv1a_bytes32(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("0x{:064x}", h as u128)
}

/// Parse a 20-byte hex address ("0x..." or bare) into an `Address` (5 big-endian u32 limbs).
fn parse_address_hex(hex: &str) -> Address {
    let s = hex.trim().trim_start_matches("0x");
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex byte"))
        .collect::<Vec<u8>>();
    assert_eq!(bytes.len(), 20, "address must be 20 bytes");
    let mut limbs = [0u32; 5];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = u32::from_be_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
    }
    Address::from_u32_slice(&limbs).expect("address from limbs")
}

/// Extract the member descriptor (sphincs hashes, regev digests, recipients)
/// from a channel's `ChannelMemberKeys`, EXACTLY as
/// `generate_withdrawal_fixture.rs` does (it replicates the private
/// `ChannelMemberKeys::to_reg_record(channel_id)`).
///
/// SECURITY: each active slot's sphincs_pk_hash / regev_pk_digest is the
/// canonical `Bytes32::from(PoseidonHashOut)` of the SAME Poseidon identity
/// stored in `member_tree` (the root committed into the channel leaf). The
/// recipient is the deterministic per-(channel, slot) test L1 address used by
/// `to_reg_record` (keccak preimage only). bp_member_slot = 0 by convention.
fn member_fixture(member_keys: &ChannelMemberKeys, channel_id_u32: u32) -> MemberFixture {
    let member_count = TEST_ACTIVE_MEMBERS;
    let bp_member_slot: u8 = 0;
    let mut member_sphincs_pubkey_hashes = Vec::with_capacity(member_count);
    let mut regev_pk_digests = Vec::with_capacity(member_count);
    let mut recipients = Vec::with_capacity(member_count);
    for i in 0..member_count {
        let leaf = member_keys.member_tree.get_leaf(i as u64);
        let sphincs_hash = Bytes32::from(leaf.sphincs_pk_hash);
        let regev_digest = Bytes32::from(leaf.regev_pk_digest);
        // Deterministic per-(channel, slot) recipient — identical formula to
        // `ChannelMemberKeys::to_reg_record`.
        let recipient = Address::from_u32_slice(
            &[0x3333_0000u32
                .wrapping_add(channel_id_u32.wrapping_mul(16))
                .wrapping_add(i as u32); 5],
        )
        .expect("address from u32 slice");
        member_sphincs_pubkey_hashes.push(sphincs_hash.to_string());
        regev_pk_digests.push(regev_digest.to_string());
        recipients.push(recipient.to_string());
    }
    MemberFixture {
        channel_id: channel_id_u32,
        bp_member_slot,
        member_sphincs_pubkey_hashes,
        regev_pk_digests,
        recipients,
    }
}

fn main() -> anyhow::Result<()> {
    let supported_user_counts = vec![2u32];

    // -----------------------------------------------------------------------
    // Circuit setup (mirrors e2e.rs lines 51-67)
    // -----------------------------------------------------------------------
    eprintln!("[c2c] Step 0: circuit setup");
    let block_hash_chain_processor =
        BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
    let block_chain_vd = block_hash_chain_processor.block_chain_vd();

    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
    let balance_vd = balance_processor.balance_vd();

    let block_witness_generator =
        BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

    // FIXED rng seed for deterministic / reproducible output.
    let mut rng = StdRng::seed_from_u64(1);
    let user_id = UserId::new(1).expect("user id");
    let salt = Salt::rand(&mut rng);

    // Channel 1 (the SENDER) balance witness generator.
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

    // -----------------------------------------------------------------------
    // Block 1: Channel 1 registration (mirrors e2e.rs lines 85-98)
    // -----------------------------------------------------------------------
    eprintln!("[c2c] Block 1: channel 1 registration");
    let channel1_id_u32 = user_id.channel_id();
    let member_keys1 = {
        let mut generator = block_witness_generator.borrow_mut();
        let keys = generator.add_channel_registration(channel1_id_u32);
        generator
            .add_registration_block(0)
            .expect("apply channel 1 registration block");
        keys
    };

    // -----------------------------------------------------------------------
    // Block 2: Deposit into channel 1 (mirrors e2e.rs lines 100-133)
    // -----------------------------------------------------------------------
    eprintln!("[c2c] Block 2: deposit (channel 1)");
    let deposit_salt = Salt::rand(&mut rng);
    let deposit_recipient = calculate_recipient_from_user_id(user_id, deposit_salt);
    // The depositor is folded into the on-chain deposit hash (= block 2's hash). On a real chain the
    // deposit tx's msg.sender IS the depositor, so for a Sepolia run set WD_DEPOSITOR to the EOA
    // that will send `deposit()`; otherwise a deterministic random address (local-test path uses
    // vm.prank to match).
    let depositor = match std::env::var("WD_DEPOSITOR") {
        Ok(hex) => parse_address_hex(&hex),
        Err(_) => Address::rand(&mut rng),
    };
    eprintln!("[c2c] depositor = {}", depositor.to_string());
    {
        let mut generator = block_witness_generator.borrow_mut();
        generator
            .add_deposit(
                depositor,
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
    let deposit_balance_proof = balance_processor
        .prove_receive_deposit(&deposit_witness)
        .expect("deposit proof");
    balance_witness_generator
        .commit_receive_deposit(&deposit_balance_proof, &deposit_witness)
        .expect("commit deposit");

    // -----------------------------------------------------------------------
    // Block 3: Channel 2 registration (RECEIVER). This is the channel-to-channel
    // addition relative to generate_withdrawal_fixture.rs: ch2's member set is
    // committed into the channel tree so its later receive/withdrawal blocks'
    // member-signature binding is satisfiable.
    // -----------------------------------------------------------------------
    eprintln!("[c2c] Block 3: channel 2 registration");
    let user_id2 = UserId::new(2).expect("user id 2");
    let channel2_id_u32 = user_id2.channel_id();
    let member_keys2 = {
        let mut generator = block_witness_generator.borrow_mut();
        let keys = generator.add_channel_registration(channel2_id_u32);
        generator
            .add_registration_block(0)
            .expect("apply channel 2 registration block");
        keys
    };

    // Channel 2 (the RECEIVER) balance witness generator, sharing the SAME
    // block witness generator handle.
    let mut balance_witness_generator2 = BalanceWitnessGenerator::new(
        user_id2,
        Salt::rand(&mut rng),
        block_witness_generator.clone(),
        &balance_processor,
    )
    .expect("balance witness generator 2");

    // -----------------------------------------------------------------------
    // Block 4: ch1 -> ch2 internal transfer (mirrors e2e.rs lines 135-281).
    // -----------------------------------------------------------------------
    eprintln!("[c2c] Block 4: ch1 -> ch2 internal transfer");
    // SECURITY: capture ch1's balance proof BEFORE the send (e2e.rs line 136).
    // The receiver's receive_transfer proof verifies against the SENDER's state
    // as it was BEFORE the send tx was applied.
    let sender_proof = balance_witness_generator.balance_proof.clone();
    let transfer_salt = Salt::rand(&mut rng);

    let internal_transfer = Transfer {
        recipient: calculate_recipient_from_user_id(user_id2, transfer_salt),
        token_index: 0,
        amount: U256::from(3u32),
        aux_data: Bytes32::default(),
    };
    let internal_spend_witness = balance_witness_generator
        .spend_witness(&[internal_transfer.clone()])
        .expect("internal spend witness");
    let internal_spend_proof = spend_circuit
        .prove(&internal_spend_witness)
        .expect("internal spend proof");

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

    // Legacy Tx tree retained only for the legacy Tx merkle proof; the block's
    // authoritative root is the TxV2Tree root below.
    let mut internal_tx_tree = TxTree::init();
    internal_tx_tree.update(user_id.as_u64(), internal_tx.clone());
    let internal_tx_merkle_proof = internal_tx_tree.prove(user_id.as_u64());

    let internal_tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root: internal_transfer_tree_root,
        nonce: internal_tx.nonce,
        channel_action_root: PoseidonHashOut::default(),
    };
    let mut internal_tx_v2_tree = TxV2Tree::init();
    internal_tx_v2_tree.update(user_id.as_u64(), internal_tx_v2);
    let internal_tx_tree_root_bytes: Bytes32 = internal_tx_v2_tree.get_root().into();
    let internal_tx_v2_merkle_proof = internal_tx_v2_tree.prove(user_id.as_u64());

    // Per-slot tx_v2 witness for num_users = 2: slot 0 is the active channel
    // (ch1), slot 1 is a zero-key_id padding slot (skipped in-circuit).
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
    let internal_new_balance_proof = balance_processor
        .prove_send_tx(&internal_send_tx_witness)
        .expect("internal send tx proof");
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
    let receive_transfer_proof = balance_processor
        .prove_receive_transfer(&receive_transfer_witness)
        .expect("receive transfer proof");
    balance_witness_generator2
        .commit_receive_transfer(&receive_transfer_proof, &receive_transfer_witness)
        .expect("commit receive transfer");

    // -----------------------------------------------------------------------
    // Block 5: Channel 2 (RECEIVER) withdrawal (mirrors e2e.rs lines 283-451 but
    // on `balance_witness_generator2` / channel 2).
    // -----------------------------------------------------------------------
    eprintln!("[c2c] Block 5: channel 2 withdrawal");
    // The withdrawal recipient (an L1 address). Pass via `WD_RECIPIENT=0x...20bytes`; otherwise a
    // deterministic random L1 address is used.
    let withdrawal_address = match std::env::var("WD_RECIPIENT") {
        Ok(hex) => parse_address_hex(&hex),
        Err(_) => Address::rand(&mut rng),
    };
    eprintln!(
        "[c2c] withdrawal recipient (L1) = {}",
        withdrawal_address.to_string()
    );
    let withdrawal_transfer = Transfer {
        recipient: calculate_recipient_from_address(withdrawal_address),
        token_index: 0,
        amount: U256::from(3u32),
        aux_data: Bytes32::default(),
    };
    let withdrawal_spend_witness = balance_witness_generator2
        .spend_witness(&[withdrawal_transfer.clone()])
        .expect("withdrawal spend witness");
    let withdrawal_spend_proof = spend_circuit
        .prove(&withdrawal_spend_witness)
        .expect("withdrawal spend proof");

    let mut withdrawal_transfer_tree = TransferTree::init();
    withdrawal_transfer_tree.push(withdrawal_transfer.clone());
    let withdrawal_transfer_index = 0u32;
    let withdrawal_transfer_merkle_proof =
        withdrawal_transfer_tree.prove(withdrawal_transfer_index as u64);
    let withdrawal_transfer_tree_root = withdrawal_transfer_tree.get_root();

    let withdrawal_tx = Tx {
        transfer_tree_root: withdrawal_transfer_tree_root,
        nonce: balance_witness_generator2.full_private_state.nonce,
    };

    // Legacy Tx tree retained only for the legacy Tx merkle proof; the block's
    // authoritative root is the TxV2Tree root below. Indexed by ch2.
    let mut withdrawal_tx_tree = TxTree::init();
    withdrawal_tx_tree.update(user_id2.as_u64(), withdrawal_tx.clone());
    let withdrawal_tx_merkle_proof = withdrawal_tx_tree.prove(user_id2.as_u64());

    let withdrawal_tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root: withdrawal_transfer_tree_root,
        nonce: withdrawal_tx.nonce,
        channel_action_root: PoseidonHashOut::default(),
    };
    let mut withdrawal_tx_v2_tree = TxV2Tree::init();
    withdrawal_tx_v2_tree.update(user_id2.as_u64(), withdrawal_tx_v2);
    let withdrawal_tx_tree_root_bytes: Bytes32 = withdrawal_tx_v2_tree.get_root().into();
    let withdrawal_tx_v2_merkle_proof = withdrawal_tx_v2_tree.prove(user_id2.as_u64());

    let withdrawal_tx_v2_witness = BlockTxV2Witness {
        tx_v2_indices: vec![user_id2.as_u64(), 0],
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
                user_id2.channel_id(),
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
    let withdrawal_send_tx_witness = balance_witness_generator2
        .send_tx_witness(&withdrawal_send_tx_data)
        .expect("withdrawal send tx witness");
    let withdrawal_balance_proof = balance_processor
        .prove_send_tx(&withdrawal_send_tx_witness)
        .expect("withdrawal send tx proof");
    balance_witness_generator2
        .commit_send_tx(
            &withdrawal_balance_proof,
            &withdrawal_send_tx_witness,
            &withdrawal_spend_witness,
        )
        .expect("commit send tx");

    // ----- Single withdrawal proof (channel 2) -----
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
    let single_withdrawal_witness = balance_witness_generator2
        .single_withdrawal_witness(&single_withdrawal_data)
        .expect("single withdrawal witness");
    let single_withdrawal_circuit = SingleWithdawalCircuit::<F, C, D>::new(&balance_vd);
    let single_withdrawal_vd = single_withdrawal_circuit.data.verifier_data();
    let single_withdrawal_proof = single_withdrawal_circuit
        .prove(&single_withdrawal_witness)
        .expect("single withdrawal proof");
    single_withdrawal_circuit
        .data
        .verify(single_withdrawal_proof.clone())
        .expect("verify single withdrawal proof");

    // ----- Withdrawal chain + final proofs -----
    let withdrawal_processor = WithdrawalProcessor::<F, C, D>::new(&single_withdrawal_vd);
    let withdrawal_chain_vd = withdrawal_processor.withdrawal_chain_vd();
    let step_witness = WithdrawalStepWitness::<F, C, D> {
        prev_withdrawal_chain_proof: None,
        single_withdrawal_proof: single_withdrawal_proof.clone(),
        update_public_state: single_withdrawal_witness.update_public_state.clone(),
    };
    let withdrawal_chain_proof = withdrawal_processor
        .prove_step(&step_witness)
        .expect("withdrawal chain proof");
    withdrawal_chain_vd
        .verify(withdrawal_chain_proof.clone())
        .expect("verify withdrawal chain proof");

    let ext_public_state = block_witness_generator
        .borrow()
        .current_extended_public_state();
    // FIXED seed so the withdrawal prover address is deterministic. Overridable via WD_PROVER_SEED:
    // the prover address is folded into the withdrawal pis_hash, so changing the seed re-rolls the
    // WHIR Fiat-Shamir query indices (hence the Merkle-path pruning) WITHOUT changing the proved
    // statement or the anchored state root — used to keep the ABI-encoded proof calldata under
    // Ethereum's 128 KiB (131072-byte) per-transaction mempool limit. Demo-neutral.
    // Default seed 1 is the value proven (2026-06-14 Sepolia run) to yield a withdrawal proof whose
    // ABI-encoded `withdrawNative` calldata (130084 B) fits under the 131072-byte tx limit; seed 777
    // produced 131012 B which the raw tx (131134 B) exceeded. Re-roll via WD_PROVER_SEED if a future
    // circuit change pushes the size over again.
    let prover_seed: u64 = std::env::var("WD_PROVER_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let mut prover_rng = StdRng::seed_from_u64(prover_seed);
    let withdrawal_prover = Address::rand(&mut prover_rng);
    let withdrawal_proof = withdrawal_processor
        .prove_final(&withdrawal_chain_proof, withdrawal_prover, &ext_public_state)
        .expect("withdrawal proof");
    withdrawal_processor
        .withdrawal_vd()
        .verify(withdrawal_proof.clone())
        .expect("verify withdrawal proof");

    // -----------------------------------------------------------------------
    // Block hash chain + validity proof (mirrors e2e.rs lines 453-495).
    // -----------------------------------------------------------------------
    eprintln!("[c2c] Validity: block hash chain + validity proof");
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
            let proof = block_hash_chain_processor
                .prove_block(initial_state, prev_block_proof.clone(), &witness)
                .expect("block hash chain proof");
            prev_block_proof = Some(proof.clone());
            last_block_proof = Some(proof);
        }
    }

    let final_block_chain_proof = last_block_proof.expect("final block hash chain proof");
    let validity_circuit = ValidityCircuit::<F, C, D>::new(&block_chain_vd);
    // FIXED validity prover address.
    let validity_prover = Address::default();
    let validity_proof = validity_circuit
        .prove(&final_block_chain_proof, validity_prover)
        .expect("validity proof");
    validity_circuit
        .verify(&validity_proof)
        .expect("verify validity proof");

    // Extract ValidityPublicInputs from the FINAL block-hash-chain proof.
    let block_chain_inputs = BlockChainPublicInputs::<F, C, D>::from_u64_slice(
        &final_block_chain_proof.public_inputs.to_u64_vec(),
        &block_chain_vd.common.config,
    )?;
    let vpis = ValidityPublicInputs::from_states(
        &block_chain_inputs.initial_ext_public_state,
        &block_chain_inputs.ext_public_state,
        validity_prover,
    );

    // -----------------------------------------------------------------------
    // Wrap + MLE for BOTH the withdrawal proof and the validity proof
    // (mirrors generate_withdrawal_fixture.rs).
    // -----------------------------------------------------------------------
    eprintln!("[c2c] Wrap + MLE (withdrawal proof)");
    let withdrawal_wrapper =
        WrapperCircuit::<F, C, C, D>::new(&withdrawal_processor.withdrawal_vd());
    let withdrawal_wrapped = withdrawal_wrapper.prove(&withdrawal_proof)?;
    withdrawal_wrapper.data.verify(withdrawal_wrapped.clone())?;
    let withdrawal_vk = setup_mle_vk::<F, C, D>(&withdrawal_wrapper.data);
    let mut wd_pw = PartialWitness::new();
    wd_pw.set_proof_with_pis_target(&withdrawal_wrapper.wrap_proof, &withdrawal_proof);
    let withdrawal_mle = prove_with_mle::<F, C, D>(&withdrawal_wrapper.data, wd_pw)?;
    verify_mle_proof(&withdrawal_wrapper.data, &withdrawal_vk, &withdrawal_mle.proof)?;
    let withdrawal_mle_json =
        export_mle_json(&withdrawal_mle.proof, &withdrawal_wrapper.data.common);

    eprintln!("[c2c] Wrap + MLE (validity proof)");
    let validity_wrapper =
        WrapperCircuit::<F, C, C, D>::new(&validity_circuit.data.verifier_data());
    let validity_wrapped = validity_wrapper.prove(&validity_proof)?;
    validity_wrapper.data.verify(validity_wrapped.clone())?;
    let validity_vk = setup_mle_vk::<F, C, D>(&validity_wrapper.data);
    let mut val_pw = PartialWitness::new();
    val_pw.set_proof_with_pis_target(&validity_wrapper.wrap_proof, &validity_proof);
    let validity_mle = prove_with_mle::<F, C, D>(&validity_wrapper.data, val_pw)?;
    verify_mle_proof(&validity_wrapper.data, &validity_vk, &validity_mle.proof)?;
    let validity_mle_json = export_mle_json(&validity_mle.proof, &validity_wrapper.data.common);

    // -----------------------------------------------------------------------
    // Extract the EXACT committed Withdrawal from the single-withdrawal proof PIs.
    // -----------------------------------------------------------------------
    let single_withdrawal_inputs = SingleWithdawalPublicInputs::from_u64_slice(
        &single_withdrawal_proof.public_inputs[..SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN].to_u64_vec(),
    )?;
    let committed_withdrawal: Withdrawal = single_withdrawal_inputs.withdrawal.clone();

    // -----------------------------------------------------------------------
    // SANITY CHECK: re-fold the ch2 withdrawal keccak chain ON THE RUST SIDE the
    // way the contract will (seed = Bytes32::default() = 0, fold each withdrawal
    // via Withdrawal::hash_with_prev_hash) and assert it equals the
    // withdrawal_hash the proof committed (PI[0..8]).
    // -----------------------------------------------------------------------
    let proof_withdrawal_hash = {
        let pis = withdrawal_chain_proof.public_inputs.to_u64_vec();
        Bytes32::from_u64_slice(&pis[0..8]).expect("withdrawal_hash_chain limbs")
    };
    let refolded = committed_withdrawal.hash_with_prev_hash(Bytes32::default());
    assert_eq!(
        refolded, proof_withdrawal_hash,
        "withdrawal keccak chain re-fold mismatch: refolded = {refolded:?}, \
         proof-committed withdrawal_hash = {proof_withdrawal_hash:?}. The on-chain \
         fold would NOT match the proof."
    );
    eprintln!("[c2c] withdrawal keccak chain re-fold sanity check PASSED");

    // SANITY: the withdrawal proof's ext_commitment must equal the validity
    // final state root (both anchored to the same final ExtendedPublicState).
    assert_eq!(
        ext_public_state.commitment(),
        vpis.final_ext_commitment,
        "withdrawal ext_commitment != validity final_ext_commitment"
    );

    // -----------------------------------------------------------------------
    // Write output files.
    // -----------------------------------------------------------------------
    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;

    // Output filename prefix: defaults to "c2c_" so this set does NOT overwrite
    // the plain P2 withdrawal fixtures.
    let prefix = std::env::var("WD_OUT_PREFIX").unwrap_or_else(|_| "c2c_".to_string());
    let name = |base: &str| format!("{prefix}{base}");

    // 1. <prefix>withdrawal_mle.json
    fs::write(out_dir.join(name("withdrawal_mle.json")), &withdrawal_mle_json)?;
    eprintln!(
        "[c2c] wrote contracts/test/data/{}",
        name("withdrawal_mle.json")
    );

    // 2. <prefix>lifecycle_validity_mle.json
    fs::write(
        out_dir.join(name("lifecycle_validity_mle.json")),
        &validity_mle_json,
    )?;
    eprintln!(
        "[c2c] wrote contracts/test/data/{}",
        name("lifecycle_validity_mle.json")
    );

    // 3. <prefix>lifecycle.json
    let blocks_fixture: Vec<BlockFixture> = {
        let guard = block_witness_generator.borrow();
        let total_blocks = guard.block_number.as_u64();
        let mut v = Vec::with_capacity(total_blocks as usize);
        for block_idx in 1..=total_blocks {
            let block_number = BlockNumber::new(block_idx).expect("block number");
            let witness = guard
                .block_chain_witness
                .get(&block_number)
                .expect("block witness");
            let block = &witness.block;
            v.push(BlockFixture {
                channel_id: block.channel_id,
                timestamp: block.timestamp,
                tx_tree_root: block.tx_tree_root.to_string(),
                key_ids: block.key_ids.clone(),
                block_number: block_idx,
            });
        }
        v
    };

    let lifecycle = LifecycleFixture {
        genesis_state_root: vpis.initial_ext_commitment.to_string(),
        final_state_root: vpis.final_ext_commitment.to_string(),
        registration1: member_fixture(&member_keys1, channel1_id_u32),
        registration2: member_fixture(&member_keys2, channel2_id_u32),
        deposit: DepositFixture {
            depositor: depositor.to_string(),
            recipient: deposit_recipient.to_string(),
            token_index: 0,
            amount: U256::from(10u32).to_string(),
            aux_data: Bytes32::default().to_string(),
        },
        blocks: blocks_fixture,
        vpis: VPIFixture {
            initial_block_number: vpis.initial_block_number.as_u64(),
            initial_block_chain: vpis.initial_block_chain.to_string(),
            initial_ext_commitment: vpis.initial_ext_commitment.to_string(),
            final_block_number: vpis.final_block_number.as_u64(),
            final_block_chain: vpis.final_block_chain.to_string(),
            final_ext_commitment: vpis.final_ext_commitment.to_string(),
            prover: vpis.prover.to_string(),
        },
        proof_hash: fnv1a_bytes32(validity_mle_json.as_bytes()),
        proof_length: validity_mle_json.len() as u32,
    };
    let lifecycle_json = serde_json::to_string_pretty(&lifecycle)?;
    fs::write(out_dir.join(name("lifecycle.json")), &lifecycle_json)?;
    eprintln!("[c2c] wrote contracts/test/data/{}", name("lifecycle.json"));

    // 4. <prefix>withdrawal_payout.json
    let payout = WithdrawalPayoutFixture {
        withdrawals: vec![WithdrawalEntryFixture {
            recipient: committed_withdrawal.recipient.to_string(),
            token_index: committed_withdrawal.token_index,
            amount: committed_withdrawal.amount.to_string(),
            nullifier: committed_withdrawal.nullifier.to_string(),
            aux_data: committed_withdrawal.aux_data.to_string(),
        }],
        withdrawal_prover: withdrawal_prover.to_string(),
        block_number: ext_public_state.inner.block_number.as_u64(),
        ext_commitment: ext_public_state.commitment().to_string(),
    };
    let payout_json = serde_json::to_string_pretty(&payout)?;
    fs::write(out_dir.join(name("withdrawal_payout.json")), &payout_json)?;
    eprintln!(
        "[c2c] wrote contracts/test/data/{}",
        name("withdrawal_payout.json")
    );

    eprintln!("[c2c] Done!");
    Ok(())
}
