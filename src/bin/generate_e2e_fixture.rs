//! Generate a complete E2E fixture for Solidity finalize() test.
//!
//! Pipeline: Plonky2 validity proof → 2x WrapperCircuit → MLE proof
//! Output:   contracts/test/data/mle_fixture.json
//!
//! Usage:    cargo run --bin generate_e2e_fixture --release

use std::{fs, path::Path};

use intmax3_zkp::{
    circuits::{
        test_utils::block_witness_generator::BlockWitnessGenerator,
        validity::block_hash_chain::{
            block_chain_pis::BlockChainPublicInputs,
            block_hash_chain_processor::BlockHashChainProcessor,
            validity_circuit::{ValidityCircuit, ValidityPublicInputs},
        },
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    utils::{
        conversion::ToU64,
        mle_prover::{export_mle_json, prove_with_mle, setup_mle_vk},
        wrapper::WrapperCircuit,
    },
    wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::config::PoseidonGoldilocksConfig,
};
use serde::Serialize;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
type BN128C = PoseidonBN128GoldilocksConfig;
const D: usize = 2;

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

/// Fixture describing the EXACT on-chain `postBlockAndSubmit` call that
/// reconstructs the empty block #1 the validity proof proved, plus the
/// finalize-binding values. Consumed by `contracts/test/MleFinalizeE2E.t.sol`
/// to exercise the full real on-chain path (postBlock → finalize with real
/// MLE verification ON).
///
/// SECURITY: every field is pulled programmatically from the proved `Block`
/// and the `ValidityPublicInputs`, never hardcoded — the on-chain block-hash
/// recomputation and PI-hash binding are what actually validate these.
#[derive(Serialize)]
struct BlockFixture {
    // --- SubBlock reconstruction (must reproduce Block::hash_with_prev_hash) ---
    channel_id: u32,
    timestamp: u64,
    tx_tree_root: String,
    // key_ids are padded to num_users in the proved Block; the on-chain SubBlock
    // MUST carry the identical padded vector or the block hash will not match.
    key_ids: Vec<u32>,
    block_deposit_hash_chain: String,
    block_channel_reg_hash_chain: String,
    // --- finalize() binding values (mirror of vpi_fixture, repeated for convenience) ---
    genesis_state_root: String,
    final_state_root: String,
    initial_block_number: u64,
    final_block_number: u64,
    initial_block_chain: String,
    final_block_chain: String,
    // --- _submit() commitment inputs (NOT re-checked by finalize/fullVerify; see note) ---
    // proofHash/proofLength only feed the submission commitment used by the FRAUD path,
    // which finalize does not touch. Deterministic values derived from the MLE proof bytes.
    proof_hash: String,
    proof_length: u32,
}

fn main() -> anyhow::Result<()> {
    // Accept `--skip-groth16` for backward compatibility with the WHIR-era
    // pipeline. The current MLE-based pipeline never invokes gnark/Groth16
    // (Groth16 fixtures are tracked separately), so the flag is effectively a
    // no-op here. We still accept it so existing scripts / README commands
    // continue to work, and we acknowledge it in the log output.
    let skip_groth16 = std::env::args().any(|a| a == "--skip-groth16");
    if skip_groth16 {
        eprintln!(
            "[e2e] --skip-groth16 accepted (no-op on MLE pipeline; Groth16 \
             fixtures are managed separately under contracts/test/data/e2e_groth16.json)"
        );
    }

    eprintln!("[e2e] Step 1: Generate Plonky2 validity proof");

    let supported_user_counts = vec![2u32];
    let mut generator = BlockWitnessGenerator::new(&supported_user_counts);
    let initial_state = generator.current_extended_public_state();

    generator.add_block(1, &[], 1, Bytes32::default())?;
    let block_number = generator.block_number;
    let block_witness = generator
        .block_chain_witness
        .get(&block_number)
        .cloned()
        .expect("block witness");

    let processor = BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
    let block_proof = processor.prove_block(Some(initial_state.clone()), None, &block_witness)?;
    let block_chain_vd = processor.block_chain_vd();

    let validity_circuit = ValidityCircuit::<F, C, D>::new(&block_chain_vd);
    let prover = Address::default();
    let validity_proof = validity_circuit.prove(&block_proof, prover)?;

    validity_circuit
        .data
        .verify(validity_proof.clone())
        .expect("plonky2 native verification");
    eprintln!("[e2e] Plonky2 validity proof verified");

    // Extract ValidityPublicInputs
    let block_chain_inputs = BlockChainPublicInputs::<F, C, D>::from_u64_slice(
        &block_proof.public_inputs.to_u64_vec(),
        &block_chain_vd.common.config,
    )?;
    let vpis = ValidityPublicInputs::from_states(
        &block_chain_inputs.initial_ext_public_state,
        &block_chain_inputs.ext_public_state,
        prover,
    );

    // -----------------------------------------------------------------------
    // Step 2: Wrap with WrapperCircuit (recursive proof compression)
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 2: Wrap with WrapperCircuit");

    let wrapper = WrapperCircuit::<F, C, C, D>::new(&validity_circuit.data.verifier_data());
    let wrapped_proof = wrapper.prove(&validity_proof)?;
    wrapper.data.verify(wrapped_proof.clone())?;
    let common = &wrapper.data.common;
    eprintln!(
        "[e2e] Wrapper proof verified (degree_bits={})",
        common.degree_bits()
    );

    // -----------------------------------------------------------------------
    // Step 3: Generate MLE proof
    // -----------------------------------------------------------------------
    // Setup: compute verification key (deterministic, once per circuit)
    let vk = setup_mle_vk::<F, C, D>(&wrapper.data);
    eprintln!(
        "[e2e] MLE VK computed (preprocessed_commitment_root: {} bytes)",
        vk.preprocessed_commitment_root.len()
    );

    eprintln!("[e2e] Step 3: Generate MLE proof");

    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&wrapper.wrap_proof, &validity_proof);

    let mle_result = prove_with_mle::<F, C, D>(&wrapper.data, pw)?;
    eprintln!("[e2e] MLE proof generated in {:?}", mle_result.prove_time);

    intmax3_zkp::utils::mle_prover::verify_mle_proof(&wrapper.data, &vk, &mle_result.proof)?;
    eprintln!("[e2e] MLE proof verified locally");

    // -----------------------------------------------------------------------
    // Step 4: Export fixture
    // -----------------------------------------------------------------------
    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;

    let mle_json = export_mle_json(&mle_result.proof, &wrapper.data.common);
    fs::write(out_dir.join("mle_fixture.json"), &mle_json)?;
    eprintln!("[e2e] MLE fixture written to contracts/test/data/mle_fixture.json");

    // Export validity public inputs
    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;
    let vpi_fixture = VPIFixture {
        initial_block_number: vpis.initial_block_number.as_u64(),
        initial_block_chain: vpis.initial_block_chain.to_string(),
        initial_ext_commitment: vpis.initial_ext_commitment.to_string(),
        final_block_number: vpis.final_block_number.as_u64(),
        final_block_chain: vpis.final_block_chain.to_string(),
        final_ext_commitment: vpis.final_ext_commitment.to_string(),
        prover: vpis.prover.to_string(),
    };
    let vpi_json = serde_json::to_string_pretty(&vpi_fixture)?;
    fs::write(out_dir.join("vpi_fixture.json"), &vpi_json)?;
    eprintln!("[e2e] VPI fixture written to contracts/test/data/vpi_fixture.json");

    // -----------------------------------------------------------------------
    // Step 5: Export the block fixture (full on-chain postBlock + finalize path)
    // -----------------------------------------------------------------------
    // Pull the EXACT fields the on-chain `_postBlock` folds into the block hash
    // from the proved Block. `key_ids` is already padded to `num_users` inside
    // `Block::new` (block.rs:136), so we serialize the padded vector verbatim —
    // the on-chain SubBlock must carry the identical vector for the recomputed
    // `_computeBlockHash` to equal `final_block_chain`.
    let block = &block_witness.block;

    // SANITY: recompute the block hash in Rust exactly as the validity proof did
    // (prev_hash = genesis blockHashChainAt[0] = 0). This must equal
    // vpis.final_block_chain; if not, the emitter and the proof disagree and the
    // on-chain test would fail — we fail loud here instead.
    let recomputed = block.hash_with_prev_hash(Bytes32::default())?;
    assert_eq!(
        recomputed.to_string(),
        vpis.final_block_chain.to_string(),
        "block hash sanity check failed: recomputed block hash != vpis.final_block_chain"
    );
    // Genesis deposit/reg chains carried by the empty block #1 must be zero
    // (no deposits, no channel registrations), matching the on-chain genesis state.
    assert_eq!(
        block.deposit_hash_chain,
        Bytes32::default(),
        "empty block #1 deposit_hash_chain must be zero"
    );
    assert_eq!(
        block.channel_reg_hash_chain,
        Bytes32::default(),
        "empty block #1 channel_reg_hash_chain must be zero"
    );

    // proofHash/proofLength feed ONLY the submission commitment used by the fraud
    // path; finalize()/fullVerify() never re-check them. Deterministic values
    // derived from the serialized MLE proof bytes.
    let proof_length = mle_json.len() as u32;
    let proof_hash = {
        // Deterministic, dependency-free FNV-1a digest over the MLE JSON, placed
        // in the low 64 bits of a bytes32. The value is UNCONSTRAINED on-chain
        // (finalize/fullVerify never re-derive the submission commitment), so any
        // deterministic value is sound; we use this only for reproducibility.
        let mut h: u64 = 0xcbf29ce484222325;
        for b in mle_json.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        format!("0x{:064x}", h as u128)
    };

    let block_fixture = BlockFixture {
        channel_id: block.channel_id,
        timestamp: block.timestamp,
        tx_tree_root: block.tx_tree_root.to_string(),
        key_ids: block.key_ids.clone(),
        block_deposit_hash_chain: block.deposit_hash_chain.to_string(),
        block_channel_reg_hash_chain: block.channel_reg_hash_chain.to_string(),
        genesis_state_root: vpis.initial_ext_commitment.to_string(),
        final_state_root: vpis.final_ext_commitment.to_string(),
        initial_block_number: vpis.initial_block_number.as_u64(),
        final_block_number: vpis.final_block_number.as_u64(),
        initial_block_chain: vpis.initial_block_chain.to_string(),
        final_block_chain: vpis.final_block_chain.to_string(),
        proof_hash,
        proof_length,
    };
    let block_json = serde_json::to_string_pretty(&block_fixture)?;
    fs::write(out_dir.join("block_fixture.json"), &block_json)?;
    eprintln!("[e2e] Block fixture written to contracts/test/data/block_fixture.json");

    eprintln!("[e2e] Done!");
    Ok(())
}
