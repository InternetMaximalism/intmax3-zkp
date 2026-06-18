//! Generate the on-chain test fixture for a REAL cancelClose binding MLE/WHIR proof.
//!
//! Phase C1 (tasks/phase-c-challenge-stubs-threat-model.md, "CORRECTED cancelClose statement"):
//! `ChannelSettlementVerifier.verifyCancelClose` is turned into a REAL on-chain verification of the
//! plonky2 `CancelCloseCircuit` via the shared `@mle/MleVerifier.sol` rail. Produces:
//!
//!   - contracts/test/data/cancel_close_mle.json — the wrapped MLE proof + VK params.
//!   - contracts/test/data/cancel_close.json — a descriptor with every PI field value (channelId,
//!     closeIntentDigest, memberSetCommitment, revivedStateVersion, revivedChannelStateDigest) plus
//!     the member pk_g set, so the Solidity manager can fill the registered member-set commitment
//!     and bind the expected limbs.
//!
//! SECURITY: every exported value is pulled PROGRAMMATICALLY from the PROVED circuit public inputs
//! (the 27 raw Goldilocks limbs the circuit registers — `WrapperCircuit` re-registers verbatim).
//! `member_set_commitment` is the value the circuit derived from the verified signing keys; on L1
//! the manager injects `registeredMemberSetCommitment()` and the strict bind forces equality.
//!
//! Usage:  cargo run --release --features cancel-close-fixture-bin --bin
//! generate_cancel_close_fixture

use std::{fs, path::Path};

use intmax3_zkp::{
    circuits::channel::{
        cancel_close_circuit::test_fixture,
        cancel_close_pis::{CANCEL_CLOSE_PUBLIC_INPUTS_LEN, CancelClosePublicInputs},
    },
    utils::{
        conversion::ToU64,
        mle_prover::{export_mle_json, prove_with_mle, setup_mle_vk, verify_mle_proof},
        wrapper::WrapperCircuit,
    },
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::config::PoseidonGoldilocksConfig,
};
use serde::Serialize;

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

#[derive(Serialize)]
struct CancelCloseDescriptor {
    channel_id: u32,
    close_intent_digest: String,
    member_set_commitment: String,
    revived_state_version: u64,
    revived_channel_state_digest: String,
    /// The active members' signing pk_g hashes (slot order) — lets the Solidity test build the
    /// registered member set and confirm the manager-injected `registeredMemberSetCommitment()`
    /// equals the proven `member_set_commitment`.
    member_pk_gs: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    eprintln!("[cancel] Step 0: build cancel-close circuit");
    let circuit = test_fixture::circuit();

    eprintln!("[cancel] Step 1: build witness + prove");
    let witness = test_fixture::build_full_witness();
    let proof = circuit.prove(&witness)?;
    circuit.data.verify(proof.clone())?;
    eprintln!(
        "[cancel] base proof OK (degree bits {})",
        circuit.data.common.degree_bits()
    );

    let pi_limbs: Vec<u64> = proof.public_inputs[..CANCEL_CLOSE_PUBLIC_INPUTS_LEN].to_u64_vec();
    assert_eq!(pi_limbs.len(), CANCEL_CLOSE_PUBLIC_INPUTS_LEN);
    let pis = CancelClosePublicInputs::from_u64_slice(&pi_limbs).map_err(|e| anyhow::anyhow!(e))?;

    eprintln!("[cancel] Step 2: wrap + MLE");
    let wrapper = WrapperCircuit::<F, C, C, D>::new(&circuit.data.verifier_data());
    let wrapped = wrapper.prove(&proof)?;
    wrapper.data.verify(wrapped.clone())?;
    let vk = setup_mle_vk::<F, C, D>(&wrapper.data);
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&wrapper.wrap_proof, &proof);
    let mle = prove_with_mle::<F, C, D>(&wrapper.data, pw)?;
    verify_mle_proof(&wrapper.data, &vk, &mle.proof)?;
    let mle_json = export_mle_json(&mle.proof, &wrapper.data.common);

    {
        let parsed: serde_json::Value = serde_json::from_str(&mle_json)?;
        let mle_pis = parsed
            .get("publicInputs")
            .and_then(|v| v.as_array())
            .expect("MLE json must carry publicInputs");
        assert_eq!(mle_pis.len(), CANCEL_CLOSE_PUBLIC_INPUTS_LEN);
        for (i, (got, want)) in mle_pis.iter().zip(pi_limbs.iter()).enumerate() {
            let got_u64 = match got {
                serde_json::Value::String(s) => s.parse::<u64>().unwrap_or_else(|_| {
                    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("limb hex")
                }),
                serde_json::Value::Number(n) => n.as_u64().expect("limb number"),
                _ => panic!("unexpected limb json type at {i}"),
            };
            assert_eq!(got_u64, *want, "MLE publicInputs[{i}] != proved limb");
        }
        eprintln!("[cancel] MLE publicInputs == 27 raw limbs (sanity OK)");
    }

    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;
    fs::write(out_dir.join("cancel_close_mle.json"), &mle_json)?;
    eprintln!("[cancel] wrote contracts/test/data/cancel_close_mle.json");

    let descriptor = CancelCloseDescriptor {
        channel_id: pis.channel_id.channel_id(),
        close_intent_digest: pis.close_intent_digest.to_string(),
        member_set_commitment: pis.member_set_commitment.to_string(),
        revived_state_version: pis.revived_state_version,
        revived_channel_state_digest: pis.revived_channel_state_digest.to_string(),
        member_pk_gs: witness
            .member_auth
            .iter()
            .map(|a| a.pk_g.to_string())
            .collect(),
    };
    fs::write(
        out_dir.join("cancel_close.json"),
        serde_json::to_string_pretty(&descriptor)?,
    )?;
    eprintln!("[cancel] wrote contracts/test/data/cancel_close.json");
    eprintln!("[cancel] Done!");
    Ok(())
}
