//! Generate the on-chain test fixture for a REAL post-close-claim binding MLE/WHIR proof.
//!
//! Phase B-D (tasks/phase-b-claims-threat-model.md):
//! `ChannelSettlementVerifier.verifyPostCloseClaim` is turned into a REAL on-chain verification of
//! the plonky2 `PostCloseClaimCircuit` via the shared `@mle/MleVerifier.sol` rail. Produces:
//!
//!   - contracts/test/data/post_close_claim_mle.json — the wrapped MLE proof + VK params.
//!   - contracts/test/data/post_close_claim.json — a descriptor with every PI field value
//!     (closeIntentDigest, receiverChannelId, incomingTxHash, receiverPkG, recipient,
//!     sharedNativeNullifier, amount). The sharedNativeNullifier is DERIVED (hazard #8 fix) so the
//!     Solidity manager recomputes the SAME value.
//!
//! SECURITY: every exported value is pulled PROGRAMMATICALLY from the PROVED circuit public inputs
//! (the 40 raw Goldilocks limbs the circuit registers — `WrapperCircuit` re-registers verbatim).
//!
//! Usage:  cargo run --release --features post-close-claim-fixture-bin --bin
//! generate_post_close_claim_fixture

use std::{fs, path::Path};

use intmax3_zkp::{
    circuits::channel::{
        post_close_claim_circuit::test_fixture,
        post_close_claim_pis::{POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN, PostCloseClaimPublicInputs},
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
struct PostCloseClaimDescriptor {
    receiver_channel_id: u32,
    close_intent_digest: String,
    incoming_tx_hash: String,
    receiver_pk_g: String,
    recipient: String,
    shared_native_nullifier: String,
    amount: u64,
}

fn main() -> anyhow::Result<()> {
    eprintln!("[pcclaim] Step 0: build post-close-claim circuit");
    let circuit = test_fixture::circuit();

    eprintln!("[pcclaim] Step 1: build witness + prove");
    let witness = test_fixture::build_full_witness();
    let proof = circuit.prove(&witness)?;
    circuit.data.verify(proof.clone())?;
    eprintln!(
        "[pcclaim] base proof OK (degree bits {})",
        circuit.data.common.degree_bits()
    );

    let pi_limbs: Vec<u64> = proof.public_inputs[..POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN].to_u64_vec();
    assert_eq!(pi_limbs.len(), POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN);
    let pis =
        PostCloseClaimPublicInputs::from_u64_slice(&pi_limbs).map_err(|e| anyhow::anyhow!(e))?;

    eprintln!("[pcclaim] Step 3: wrap + MLE");
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
        assert_eq!(mle_pis.len(), POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN);
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
        eprintln!("[pcclaim] MLE publicInputs == 40 raw limbs (sanity OK)");
    }

    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;
    fs::write(out_dir.join("post_close_claim_mle.json"), &mle_json)?;
    eprintln!("[pcclaim] wrote contracts/test/data/post_close_claim_mle.json");

    let descriptor = PostCloseClaimDescriptor {
        receiver_channel_id: pis.receiver_channel_id.channel_id(),
        close_intent_digest: pis.close_intent_digest.to_string(),
        incoming_tx_hash: pis.incoming_tx_hash.to_string(),
        receiver_pk_g: pis.receiver_pk_g.to_string(),
        recipient: pis.recipient.to_string(),
        shared_native_nullifier: pis.shared_native_nullifier.to_string(),
        amount: pis.amount,
    };
    fs::write(
        out_dir.join("post_close_claim.json"),
        serde_json::to_string_pretty(&descriptor)?,
    )?;
    eprintln!("[pcclaim] wrote contracts/test/data/post_close_claim.json");
    eprintln!("[pcclaim] Done!");
    Ok(())
}
