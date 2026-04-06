//! Generate a complete E2E fixture for Solidity finalize() test.
//!
//! Pipeline: Plonky2 validity proof → WrapperCircuit → gnark Groth16
//! Output:   contracts/test/data/e2e_fixture.json
//!
//! Usage:    cargo run --bin generate_e2e_fixture --release --features whir

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
    ethereum_types::{address::Address, bytes32::Bytes32},
    utils::{
        groth16_wrapper::groth16_wrap,
        wrapper::WrapperCircuit,
        conversion::ToU64,
    },
};
use intmax3_zkp::ethereum_types::u32limb_trait::U32LimbTrait;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    plonk::config::PoseidonGoldilocksConfig,
};
use intmax3_zkp::wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig;
use serde::Serialize;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[derive(Serialize)]
struct E2EFixture {
    groth16_proof: Groth16ProofFixture,
    verifying_key: VKFixture,
    public_inputs: Vec<String>,
    validity_public_inputs: VPIFixture,
    pi_hash: String,
    pi_hash_reduced: String,
}

#[derive(Serialize)]
struct Groth16ProofFixture {
    a: [String; 2],
    b: [[String; 2]; 2],
    c: [String; 2],
}

#[derive(Serialize)]
struct VKFixture {
    alpha: [String; 2],
    beta: [[String; 2]; 2],
    gamma: [[String; 2]; 2],
    delta: [[String; 2]; 2],
    ic: Vec<[String; 2]>,
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

fn main() -> anyhow::Result<()> {
    let skip_groth16 = std::env::args().any(|a| a == "--skip-groth16");
    let gnark_bin = Path::new("gnark/gnark-wrapper");
    if !skip_groth16 && !gnark_bin.exists() {
        anyhow::bail!(
            "gnark-wrapper binary not found at {}. Build with: cd gnark && go build -o gnark-wrapper .\nOr use --skip-groth16 to skip Groth16 wrapping.",
            gnark_bin.display()
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
    let block_proof = processor
        .prove_block(Some(initial_state.clone()), None, &block_witness)?;
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

    eprintln!("[e2e] Step 2: Wrap with WrapperCircuit");

    type BN128C = PoseidonBN128GoldilocksConfig;

    let wrapper = WrapperCircuit::<F, C, BN128C, D>::new(
        &validity_circuit.data.verifier_data(),
    );
    let wrapped_proof = wrapper.prove(&validity_proof)?;
    wrapper.data.verify(wrapped_proof.clone())?;
    eprintln!("[e2e] Wrapper proof verified");

    if skip_groth16 {
        eprintln!("[e2e] Step 3: Skipping Groth16 (--skip-groth16)");
    }
    if !skip_groth16 {
    eprintln!("[e2e] Step 3: Groth16 wrapping via gnark");
    let wrap = groth16_wrap(&wrapper.data, &wrapped_proof, gnark_bin, true)?;
    eprintln!("[e2e] Groth16 proof generated");
    eprintln!("[e2e]   Setup:  {:.2} ms", wrap.setup_time_ms);
    eprintln!("[e2e]   Prove:  {:.2} ms", wrap.proving_time_ms);
    eprintln!("[e2e]   Size:   {} bytes", wrap.proof_size);
    eprintln!("[e2e]   Inputs: {:?}", wrap.public_inputs);

    // Compute piHash via the same solidity_keccak256 used on-chain
    let pi_hash_bytes32 = vpis.hash();
    let pi_hash_hex = pi_hash_bytes32.to_string();

    // piHash % BN254.R_MOD
    let pi_hash_bytes = pi_hash_bytes32.to_bytes_be();
    let r_mod_hex = b"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
    let r_mod = num_bigint::BigUint::parse_bytes(r_mod_hex, 16).unwrap();
    let pi_hash_int = num_bigint::BigUint::from_bytes_be(&pi_hash_bytes);
    let pi_hash_reduced = &pi_hash_int % &r_mod;
    let pi_hash_reduced_hex = format!("0x{:0>64}", pi_hash_reduced.to_str_radix(16));

    eprintln!("[e2e] piHash         = {}", pi_hash_hex);
    eprintln!("[e2e] piHashReduced  = {}", pi_hash_reduced_hex);

    let vk = wrap.verifying_key.as_ref().expect("VK should be available");

    let fixture = E2EFixture {
        groth16_proof: Groth16ProofFixture {
            a: wrap.proof.a.clone(),
            b: [
                [wrap.proof.b[0][0].clone(), wrap.proof.b[0][1].clone()],
                [wrap.proof.b[1][0].clone(), wrap.proof.b[1][1].clone()],
            ],
            c: wrap.proof.c.clone(),
        },
        verifying_key: VKFixture {
            alpha: vk.alpha.clone(),
            beta: [
                [vk.beta[0][0].clone(), vk.beta[0][1].clone()],
                [vk.beta[1][0].clone(), vk.beta[1][1].clone()],
            ],
            gamma: [
                [vk.gamma[0][0].clone(), vk.gamma[0][1].clone()],
                [vk.gamma[1][0].clone(), vk.gamma[1][1].clone()],
            ],
            delta: [
                [vk.delta[0][0].clone(), vk.delta[0][1].clone()],
                [vk.delta[1][0].clone(), vk.delta[1][1].clone()],
            ],
            ic: vk.ic.clone(),
        },
        public_inputs: wrap.public_inputs.clone(),
        validity_public_inputs: VPIFixture {
            initial_block_number: vpis.initial_block_number.as_u64(),
            initial_block_chain: vpis.initial_block_chain.to_string(),
            initial_ext_commitment: vpis.initial_ext_commitment.to_string(),
            final_block_number: vpis.final_block_number.as_u64(),
            final_block_chain: vpis.final_block_chain.to_string(),
            final_ext_commitment: vpis.final_ext_commitment.to_string(),
            prover: vpis.prover.to_string(),
        },
        pi_hash: pi_hash_hex,
        pi_hash_reduced: pi_hash_reduced_hex.clone(),
    };

    // Also export block data for Solidity test (SubBlock parameters)
    let block = generator
        .block_chain_witness
        .get(&generator.block_number)
        .map(|w| &w.block)
        .expect("block data");
    eprintln!("[e2e] Block data for Solidity:");
    eprintln!("[e2e]   num_users:      {}", block.num_users);
    eprintln!("[e2e]   aggregator_id:  {}", block.aggregator_id);
    eprintln!("[e2e]   timestamp:      {}", block.timestamp);
    eprintln!("[e2e]   local_ids:      {:?}", block.local_ids);
    eprintln!("[e2e]   tx_tree_root:   {}", block.tx_tree_root);
    eprintln!("[e2e]   deposit_hash:   {}", block.deposit_hash_chain);
    eprintln!("[e2e]   forced_tx_hash: {}", block.forced_tx_hash_chain);

    // Compute blockHashChain for verification
    let block_hash = block.hash_with_prev_hash(intmax3_zkp::ethereum_types::bytes32::Bytes32::default())
        .expect("block hash");
    eprintln!("[e2e]   blockHashChain: {}", block_hash);

    let out_dir2 = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir2)?;
    let json = serde_json::to_string_pretty(&fixture)?;
    fs::write(out_dir2.join("e2e_fixture.json"), &json)?;

    eprintln!("[e2e] Fixture written to contracts/test/data/e2e_fixture.json");
    eprintln!("[e2e] piHashReduced = {} (use for WHIR fixture generation)", pi_hash_reduced_hex);
    } // end if !skip_groth16

    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;

    // -----------------------------------------------------------------------
    // Step 4: Generate WHIR proof + constraint data for WrapperCircuit
    // -----------------------------------------------------------------------
    #[cfg(feature = "whir")]
    {
        use intmax3_zkp::utils::whir_plonky2_prover::{
            prove_with_whir, export_onchain_data, WhirWrapConfig,
        };
        use plonky2::iop::witness::{PartialWitness, WitnessWrite};

        eprintln!("[e2e] Step 4: Generate WHIR proof for WrapperCircuit");

        let whir_config = WhirWrapConfig::default_keccak();

        // Build the same PartialWitness as wrapper.prove()
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&wrapper.wrap_proof, &validity_proof);

        let whir_result = prove_with_whir::<F, BN128C, D>(
            &wrapper.data, pw, &whir_config, true,
        )?;
        eprintln!("[e2e] WHIR proof generated");
        eprintln!("[e2e]   Plonky2 time: {:?}", whir_result.plonky2_prove_time);
        eprintln!("[e2e]   WHIR time:    {:?}", whir_result.whir_time);
        eprintln!("[e2e]   Total time:   {:?}", whir_result.total_time);

        // Export on-chain constraint data
        let onchain_data = export_onchain_data(&whir_result.proof, &wrapper.data);
        let constraint_json = serde_json::to_string_pretty(&onchain_data)?;
        fs::write(
            out_dir.join("wrapper_constraint_data.json"),
            &constraint_json,
        )?;
        eprintln!("[e2e] Constraint data written to contracts/test/data/wrapper_constraint_data.json");

        // Export combined WHIR proof as spongefish-native format (transcript + hints)
        // SpongefishWhir.sol consumes these raw bytes directly.
        {
            let proof = &whir_result.proof;
            let whir_proof_fixture = serde_json::json!({
                "combined": {
                    "transcript": format!("0x{}", hex::encode(&proof.combined_whir.proof_narg)),
                    "hints": format!("0x{}", hex::encode(&proof.combined_whir.proof_hints)),
                    "num_variables": proof.combined_whir.num_variables,
                    "evaluations": proof.combined_whir.evaluations.iter()
                        .map(|e| format!("{:?}", e))
                        .collect::<Vec<_>>(),
                },
                "batch_sizes": proof.batch_sizes,
                "expected_result": proof.expected_result,
                "public_inputs": proof.standard_proof.public_inputs.iter()
                    .map(|f| f.to_canonical_u64())
                    .collect::<Vec<_>>(),
            });
            let whir_json = serde_json::to_string_pretty(&whir_proof_fixture)?;
            let whir_dir = out_dir.join("whir");
            fs::create_dir_all(&whir_dir)?;
            fs::write(whir_dir.join("wrapper_whir_proof.json"), &whir_json)?;
            eprintln!("[e2e] WHIR proof written to contracts/test/data/whir/wrapper_whir_proof.json");
            eprintln!("[e2e]   combined transcript: {} bytes", proof.combined_whir.proof_narg.len());
            eprintln!("[e2e]   batch_sizes: {:?}", proof.batch_sizes);
        }

        // Export combined WHIR verifier data (for SpongefishWhirVerify on-chain test)
        {
            use intmax3_zkp::utils::whir_plonky2_prover::export_whir_verifier_data;
            let whir_dir = out_dir.join("whir");
            let data = export_whir_verifier_data(&whir_result.proof.combined_whir, &whir_config);
            let path = whir_dir.join("wrapper_combined_verifier_data.json");
            fs::write(&path, serde_json::to_string_pretty(&data)?)?;
            eprintln!("[e2e] WHIR verifier data: {}", path.display());
        }
    }

    eprintln!("[e2e] Done!");

    Ok(())
}
