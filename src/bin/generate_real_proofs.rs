use std::{fs, path::PathBuf};

use clap::{Parser, ValueEnum};
use intmax3_zkp::{
    circuits::{
        test_utils::block_witness_generator::BlockWitnessGenerator,
        validity::block_hash_chain::{
            block_chain_pis::BlockChainPublicInputs,
            block_hash_chain_processor::BlockHashChainProcessor,
            validity_circuit::{ValidityCircuit, ValidityPublicInputs},
        },
    },
    common::u63::BlockNumber,
    ethereum_types::{address::Address, bytes32::Bytes32},
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::config::PoseidonGoldilocksConfig,
};
use serde::Serialize;
use intmax3_zkp::{
    ethereum_types::u32limb_trait::U32LimbTrait,
    utils::conversion::ToU64,
};

const SUPPORTED_USER_COUNTS: &[u32] = &[2];
const DEFAULT_BLOB_HASH: &str = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const DEFAULT_PROVER: &str = "0x1234567890abcdef1234567890abcdef12345678";

#[derive(Parser, Debug)]
#[command(author, version, about = "Generate real INTMAX3 proof fixtures", long_about = None)]
struct Args {
    /// Output directory for the generated fixtures
    #[arg(long, default_value = "contracts/fixtures/real")] 
    output: PathBuf,

    /// Which fixtures to generate (valid submission, fraud submission)
    #[arg(long = "modes", value_enum, default_values_t = vec![FixtureMode::Valid, FixtureMode::Fraud])]
    modes: Vec<FixtureMode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum FixtureMode {
    Valid,
    Fraud,
}

#[derive(Clone, Serialize)]
struct ProofFixture {
    blob_versioned_hash: String,
    prover: String,
    plonky2_proof: String,
    state_root: String,
    validity_public_inputs: ValidityPublicInputsFixture,
    posting_round: PostingRoundFixture,
}

#[derive(Clone, Serialize)]
struct ValidityPublicInputsFixture {
    initial_block_number: u64,
    initial_block_hash_chain: String,
    initial_ext_commitment: String,
    final_block_number: u64,
    final_block_hash_chain: String,
    final_ext_commitment: String,
    prover: String,
}

#[derive(Clone, Serialize)]
struct PostingRoundFixture {
    sub_blocks: Vec<SubBlockFixture>,
}

#[derive(Clone, Serialize)]
struct SubBlockFixture {
    aggregator_id: u32,
    timestamp: u64,
    tx_tree_root: String,
    local_ids: Vec<u32>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.output)?;

    let base_artifacts = generate_base_artifacts()?;

    for mode in args.modes {
        let fixture = match mode {
            FixtureMode::Valid => base_artifacts.clone(),
            FixtureMode::Fraud => base_artifacts.clone(),
        };
        let file = match mode {
            FixtureMode::Valid => args.output.join("valid_submission.json"),
            FixtureMode::Fraud => args.output.join("fraud_submission.json"),
        };
        let json = serde_json::to_string_pretty(&fixture)?;
        fs::write(file, json)?;
    }

    Ok(())
}

fn generate_base_artifacts() -> anyhow::Result<ProofFixture> {
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    let mut generator = BlockWitnessGenerator::new(SUPPORTED_USER_COUNTS);
    let initial_state = generator.current_extended_public_state();

    // Simple posting round: single empty sub-block
    let aggregator_id = 1u32;
    let timestamp = 1u64;
    let tx_tree_root = Bytes32::default();
    generator.add_block(aggregator_id, &[], timestamp, tx_tree_root)?;

    let block_number = BlockNumber::new(1).expect("block number");
    let witness = generator
        .block_chain_witness
        .get(&block_number)
        .expect("block witness")
        .clone();

    let processor = BlockHashChainProcessor::<F, C, D>::new(SUPPORTED_USER_COUNTS);
    let proof = processor
        .prove_block(Some(initial_state.clone()), None, &witness)
        .expect("block hash chain proof");
    let block_chain_vd = processor.block_chain_vd();

    let validity_circuit = ValidityCircuit::<F, C, D>::new(&block_chain_vd);
    let prover = Address::from_hex(DEFAULT_PROVER).expect("valid prover address");
    let validity_proof = validity_circuit
        .prove(&proof, prover)
        .expect("validity proof");
    let plonky2_bytes = validity_proof.to_bytes();

    let block_chain_inputs = BlockChainPublicInputs::<F, C, D>::from_u64_slice(
        &proof.public_inputs.to_u64_vec(),
        &block_chain_vd.common.config,
    )
    .expect("parse block chain public inputs");
    let validity_inputs = ValidityPublicInputs::from_states(
        &block_chain_inputs.initial_ext_public_state,
        &block_chain_inputs.ext_public_state,
        prover,
    );

    let fixture = ProofFixture {
        blob_versioned_hash: DEFAULT_BLOB_HASH.to_string(),
        prover: DEFAULT_PROVER.to_string(),
        plonky2_proof: format!("0x{}", hex::encode(plonky2_bytes)),
        state_root: validity_inputs.final_ext_commitment.to_string(),
        validity_public_inputs: ValidityPublicInputsFixture {
            initial_block_number: validity_inputs.initial_block_number.as_u64(),
            initial_block_hash_chain: validity_inputs.initial_block_chain.to_string(),
            initial_ext_commitment: validity_inputs.initial_ext_commitment.to_string(),
            final_block_number: validity_inputs.final_block_number.as_u64(),
            final_block_hash_chain: validity_inputs.final_block_chain.to_string(),
            final_ext_commitment: validity_inputs.final_ext_commitment.to_string(),
            prover: validity_inputs.prover.to_string(),
        },
        posting_round: PostingRoundFixture {
            sub_blocks: vec![SubBlockFixture {
                aggregator_id,
                timestamp,
                tx_tree_root: tx_tree_root.to_string(),
                local_ids: vec![0; SUPPORTED_USER_COUNTS[0] as usize],
            }],
        },
    };

    Ok(fixture)
}
