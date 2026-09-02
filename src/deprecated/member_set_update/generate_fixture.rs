//! DEPRECATED: reproduce the historical direct member-set-update MLE/WHIR audit fixture
//! from the retired stage-Q3 prototype.
//!
//! Produces two artifacts retained for offline audit archaeology, in the same schema as the close
//! fixtures. The production `ChannelSettlementManager` has no `applyMemberSetUpdate` selector;
//! regression tests pin its pre-retirement selector as a literal.
//!
//!   - contracts/test/data/deprecated/member_set_update/member_set_update_mle.json — the wrapped
//!     MemberSetUpdateCircuit MLE proof + its VK params (`FixtureLib.parseProof` /
//!     `parseDeployData` schema).
//!   - contracts/test/data/deprecated/member_set_update/member_set_update.json — a descriptor with
//!     every value the Solidity test needs: channelId, setVersion, old/new IMCM commitments,
//!     old/new counts, the joiner recipient (zero — this fixture is a ROTATION of slot 1), and the
//!     old/new pk_g arrays the test registers / applies.
//!
//! SECURITY: every exported value is pulled PROGRAMMATICALLY from the PROVED circuit public
//! inputs (`MemberSetUpdatePublicInputs`, 26 limbs re-registered verbatim by `WrapperCircuit`).
//! The rotation itself goes through the REAL wallet gate (`verify_member_set_update` — IMKR
//! self-consent + the previous set's full N-of-N over IMMS) before anything is proved.
//!
//! Usage:  cargo run --release --features deprecated-msu --bin generate_member_set_update_fixture
//!
//! HEAVY COMPUTE: batch-aggregate prove + the update circuit (2^16) + WrapperCircuit + MLE/WHIR.

use std::{fs, path::Path};

use intmax3_zkp::{
    deprecated::member_set_update::circuit::{
        MEMBER_SET_UPDATE_PUBLIC_INPUTS_LEN, MemberSetUpdateCircuit, MemberSetUpdateCircuitWitness,
    },
    ethereum_types::{address::Address, u32limb_trait::U32LimbTrait as _},
    utils::{
        mle_prover::{export_mle_json, prove_with_mle, setup_mle_vk, verify_mle_proof},
        wrapper::WrapperCircuit,
    },
    wallet_core::{
        C, D, F, FalconProverContext, MemberInfo, MemberKeys, build_record,
        deprecated_member_set_update::{
            cosign_member_set_update, propose_rotate_key, prove_member_set_update_aggregate,
            verify_member_set_update,
        },
        registered_cosigner_leaves,
    },
};
use plonky2::{field::types::PrimeField64 as _, iop::witness::PartialWitness};
use rand010::SeedableRng as _;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberSetUpdateDescriptor {
    channel_id: u32,
    set_version: u64,
    old_commitment: String,
    new_commitment: String,
    old_count: u32,
    new_count: u32,
    recipient: String,
    old_member_pk_gs: Vec<String>,
    new_member_pk_gs: Vec<String>,
    /// The rotated slot (descriptor convenience for the test's assertions).
    rotated_slot: u8,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -----------------------------------------------------------------------
    // Step 1: a REAL rotation through the wallet gate. Deterministic fixture keys — these are
    // TEST keys for the Solidity fixture channel, the same class as every other fixture set.
    // -----------------------------------------------------------------------
    let mut rng = rand010::rngs::StdRng::seed_from_u64(0x51E7_F1C5);
    let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut rng)).collect();
    let members: Vec<MemberInfo> = keys
        .iter()
        .enumerate()
        .map(|(slot, k)| MemberInfo {
            slot: slot as u16,
            pk_g: k.pk_g(),
            pk_b: k.pk_b(),
            regev_pk: k.regev_pk.clone(),
        })
        .collect();
    let record = build_record(77, &members, 0, 0)?;

    let new_keys = MemberKeys::generate(&mut rng);
    let mut update = propose_rotate_key(&keys[1], &new_keys, &record, &members, 1)?;
    update.member_signatures = keys
        .iter()
        .enumerate()
        .map(|(slot, k)| cosign_member_set_update(k, slot as u8, &update))
        .collect();
    let (new_record, new_members) = verify_member_set_update(&record, &members, &update)?;
    eprintln!(
        "[msu] wallet gate accepted: set_version {} member_count {}",
        new_record.set_version, new_record.member_count
    );

    // -----------------------------------------------------------------------
    // Step 2: aggregate the previous set's N-of-N over IMMS, then prove the update circuit.
    // -----------------------------------------------------------------------
    let ctx = FalconProverContext::new();
    let artifact = prove_member_set_update_aggregate(&ctx, &record, &update)?;
    let agg_proof = ctx.proof_from_artifact(&record, update.signing_digest(), &artifact)?;

    let witness = MemberSetUpdateCircuitWitness {
        channel_id: record.channel_id,
        set_version: update.set_version,
        old_leaves: registered_cosigner_leaves(&record, &members)?,
        new_leaves: registered_cosigner_leaves(&new_record, &new_members)?,
        recipient: Address::default(),
        agg_proof,
    };
    let expected = witness
        .expected_public_inputs()
        .map_err(|e| format!("native mirror: {e}"))?;

    eprintln!("[msu] building MemberSetUpdateCircuit…");
    let circuit = MemberSetUpdateCircuit::<F, C, D>::new(&ctx.verifier_data());
    eprintln!(
        "[msu] degree=2^{} pis={} — proving…",
        circuit.data.common.degree_bits(),
        circuit.data.common.num_public_inputs
    );
    let proof = circuit.prove(&witness).map_err(|e| format!("{e}"))?;
    circuit.data.verify(proof.clone())?;
    let pi_limbs: Vec<u64> = proof.public_inputs[..MEMBER_SET_UPDATE_PUBLIC_INPUTS_LEN]
        .iter()
        .map(|f| f.to_canonical_u64())
        .collect();
    assert_eq!(
        pi_limbs,
        expected.to_u64_vec(),
        "proved limbs must equal the native mirror"
    );

    // -----------------------------------------------------------------------
    // Step 3: wrap + MLE (identical rail to the close/withdrawal fixtures).
    // -----------------------------------------------------------------------
    eprintln!("[msu] wrap + MLE…");
    let wrapper = WrapperCircuit::<F, C, C, D>::new(&circuit.data.verifier_data());
    let wrapped = wrapper.prove(&proof)?;
    wrapper.data.verify(wrapped.clone())?;
    let vk = setup_mle_vk::<F, C, D>(&wrapper.data);
    let mut pw = PartialWitness::new();
    use plonky2::iop::witness::WitnessWrite as _;
    let _ = pw.set_proof_with_pis_target(&wrapper.wrap_proof, &proof);
    let mle = prove_with_mle::<F, C, D>(&wrapper.data, pw)?;
    verify_mle_proof(&wrapper.data, &vk, &mle.proof)?;
    let mle_json = export_mle_json(&mle.proof, &wrapper.data.common)?;

    // SANITY: the MLE publicInputs must be the 26 raw limbs the on-chain bind re-reads.
    {
        let parsed: serde_json::Value = serde_json::from_str(&mle_json)?;
        let mle_pis = parsed
            .get("publicInputs")
            .and_then(|v| v.as_array())
            .expect("MLE json must carry publicInputs");
        assert_eq!(mle_pis.len(), MEMBER_SET_UPDATE_PUBLIC_INPUTS_LEN);
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
        eprintln!("[msu] MLE publicInputs == 26 raw limbs (sanity OK)");
    }

    // -----------------------------------------------------------------------
    // Step 4: write outputs.
    // -----------------------------------------------------------------------
    let out_dir = Path::new("contracts/test/data/deprecated/member_set_update");
    fs::create_dir_all(out_dir)?;
    fs::write(out_dir.join("member_set_update_mle.json"), &mle_json)?;
    eprintln!("[msu] wrote deprecated member_set_update_mle.json");

    let pk_gs = |ms: &[MemberInfo], count: usize| -> Vec<String> {
        (0..count).map(|i| ms[i].pk_g.to_hex()).collect()
    };
    let descriptor = MemberSetUpdateDescriptor {
        channel_id: expected.channel_id.channel_id(),
        set_version: expected.set_version,
        old_commitment: expected.old_commitment.to_hex(),
        new_commitment: expected.new_commitment.to_hex(),
        old_count: expected.old_count,
        new_count: expected.new_count,
        recipient: expected.recipient.to_hex(),
        old_member_pk_gs: pk_gs(&members, expected.old_count as usize),
        new_member_pk_gs: pk_gs(&new_members, expected.new_count as usize),
        rotated_slot: 1,
    };
    fs::write(
        out_dir.join("member_set_update.json"),
        serde_json::to_string_pretty(&descriptor)?,
    )?;
    eprintln!("[msu] wrote deprecated member_set_update.json");
    eprintln!("[msu] Done!");
    Ok(())
}
