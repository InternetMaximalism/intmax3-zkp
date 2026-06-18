//! Generate the on-chain test fixture for a REAL withdrawal-claim binding MLE/WHIR proof.
//!
//! Phase B-D (tasks/phase-b-claims-threat-model.md):
//! `ChannelSettlementVerifier.verifyWithdrawalClaim` is turned into a REAL on-chain verification of
//! the plonky2 `WithdrawalClaimCircuit` via the shared `@mle/MleVerifier.sol` rail (the SAME rail
//! proven by close/validity/withdrawal). Produces:
//!
//!   - contracts/test/data/withdrawal_claim_mle.json — the wrapped MLE proof + VK params, in the
//!     SAME JSON schema the validity/close fixtures use.
//!   - contracts/test/data/withdrawal_claim.json — a descriptor with every PI field value the
//!     Solidity test needs (closeIntentDigest, channelId, finalBalanceStateH1, memberPkG,
//!     recipient, userAmountDigest, withdrawalNullifier, amount).
//!
//! SECURITY: every exported value is pulled PROGRAMMATICALLY from the PROVED circuit public inputs
//! (the 48 raw Goldilocks limbs the circuit registers — `WrapperCircuit` re-registers them
//! verbatim). Nothing is hardcoded.
//!
//! Usage:  cargo run --release --features withdrawal-claim-fixture-bin --bin
//! generate_withdrawal_claim_fixture
//!
//! HEAVY COMPUTE: full circuit proof + WrapperCircuit recursion + MLE/WHIR commit-and-open. Run
//! explicitly; the Solidity tests skip until the JSON exists.

use std::{fs, path::Path};

use intmax3_zkp::{
    circuits::channel::{
        withdrawal_claim_circuit::test_fixture,
        withdrawal_claim_pis::{WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN, WithdrawalClaimPublicInputs},
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
struct WithdrawalClaimDescriptor {
    channel_id: u32,
    close_intent_digest: String,
    final_balance_state_h1: String,
    member_pk_g: String,
    recipient: String,
    user_amount_digest: String,
    withdrawal_nullifier: String,
    amount: u64,
}

fn main() -> anyhow::Result<()> {
    eprintln!("[wclaim] Step 0: build withdrawal-claim circuit");
    let circuit = test_fixture::circuit();

    eprintln!("[wclaim] Step 1: build witness + prove");
    let witness = test_fixture::build_full_witness();
    let proof = circuit.prove(&witness)?;
    circuit.data.verify(proof.clone())?;
    eprintln!(
        "[wclaim] base proof OK (degree bits {})",
        circuit.data.common.degree_bits()
    );

    let pi_limbs: Vec<u64> = proof.public_inputs[..WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN].to_u64_vec();
    assert_eq!(pi_limbs.len(), WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN);
    let pis =
        WithdrawalClaimPublicInputs::from_u64_slice(&pi_limbs).map_err(|e| anyhow::anyhow!(e))?;

    eprintln!("[wclaim] Step 3: wrap + MLE");
    let wrapper = WrapperCircuit::<F, C, C, D>::new(&circuit.data.verifier_data());
    let wrapped = wrapper.prove(&proof)?;
    wrapper.data.verify(wrapped.clone())?;
    let vk = setup_mle_vk::<F, C, D>(&wrapper.data);
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&wrapper.wrap_proof, &proof);
    let mle = prove_with_mle::<F, C, D>(&wrapper.data, pw)?;
    verify_mle_proof(&wrapper.data, &vk, &mle.proof)?;
    let mle_json = export_mle_json(&mle.proof, &wrapper.data.common);

    // SANITY: the MLE proof's publicInputs equal the 48 raw limbs the on-chain bind rebinds.
    {
        let parsed: serde_json::Value = serde_json::from_str(&mle_json)?;
        let mle_pis = parsed
            .get("publicInputs")
            .and_then(|v| v.as_array())
            .expect("MLE json must carry publicInputs");
        assert_eq!(mle_pis.len(), WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN);
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
        eprintln!("[wclaim] MLE publicInputs == 48 raw limbs (sanity OK)");
    }

    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;
    fs::write(out_dir.join("withdrawal_claim_mle.json"), &mle_json)?;
    eprintln!("[wclaim] wrote contracts/test/data/withdrawal_claim_mle.json");

    let descriptor = WithdrawalClaimDescriptor {
        channel_id: pis.channel_id.channel_id(),
        close_intent_digest: pis.close_intent_digest.to_string(),
        final_balance_state_h1: pis.final_balance_state_h1.to_string(),
        member_pk_g: pis.member_pk_g.to_string(),
        recipient: pis.recipient.to_string(),
        user_amount_digest: pis.user_amount_digest.to_string(),
        withdrawal_nullifier: pis.withdrawal_nullifier.to_string(),
        amount: pis.amount,
    };
    fs::write(
        out_dir.join("withdrawal_claim.json"),
        serde_json::to_string_pretty(&descriptor)?,
    )?;
    eprintln!("[wclaim] wrote contracts/test/data/withdrawal_claim.json");
    eprintln!("[wclaim] Done!");
    Ok(())
}
