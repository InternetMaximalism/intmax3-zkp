//! Generate the on-chain test fixture for a REAL channel-close-intent MLE/WHIR proof.
//!
//! Phase A (tasks/close-verifier-a1-plan.md): `ChannelSettlementVerifier.verifyCloseIntent` is
//! being turned into a REAL on-chain verification of the plonky2 `ChannelCloseCircuit` via the
//! shared `@mle/MleVerifier.sol` rail (the SAME rail proven by validity/withdrawal). This binary
//! produces the two artifacts the Solidity close tests consume:
//!
//!   - contracts/test/data/close_intent_mle.json — the wrapped-close MLE proof + its VK params
//!     (degreeBits / preprocessedCommitmentRoot / gatesDigest / kIs / subgroupGenPowers /
//!     whirParams / protocolId / sessionId), in the SAME JSON schema `FixtureLib.parseProof` /
//!     `FixtureLib.parseDeployData` already consume for the validity/withdrawal fixtures.
//!   - contracts/test/data/close_intent.json — a descriptor with EVERY `CloseProofFields` value the
//!     Solidity test needs (channelId, all digests, finalStateVersion, finalSettledTxChain,
//!     memberSetCommitment, memberCount, delegateCount, …) plus the close-intent fields the
//!     `CloseIntent` struct needs and the per-member `pk_g` hashes the channel must register so its
//!     `registeredMemberSetCommitment()` equals the proof's in-circuit `member_set_commitment`.
//!
//! SECURITY: every exported value is pulled PROGRAMMATICALLY from the PROVED close-circuit public
//! inputs (`ChannelClosePublicInputs::from_u64_slice` over the 87 raw Goldilocks limbs the close
//! circuit registers — `WrapperCircuit` re-registers them verbatim). Nothing is hardcoded. The
//! 87-limb public-input vector is what the on-chain `_bindCloseLimbsStrict` will re-bind
//! limb-by-limb, and `MleVerifier.verify` then re-checks the proof against the close VK.
//!
//! Usage:  cargo run --release --features close-fixture-bin --bin generate_close_fixture
//!
//! HEAVY COMPUTE: this runs a full close-circuit proof + a WrapperCircuit recursion + the MLE/WHIR
//! commit-and-open (degree 2^19+, minutes, multi-GB). It must be run explicitly by the user; the
//! Solidity close tests skip gracefully until `close_intent_mle.json` exists.

use std::{fs, path::Path};

use intmax3_zkp::{
    circuits::channel::{
        close_circuit::test_fixture,
        close_pis::{CHANNEL_CLOSE_PUBLIC_INPUTS_LEN, ChannelClosePublicInputs},
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

/// Descriptor JSON consumed by the Solidity close tests. Every field is derived from the PROVED
/// close public inputs (or the member auth that produced them) — see SECURITY note in the header.
#[derive(Serialize)]
struct CloseIntentDescriptor {
    /// `channel_id` as the bare u32 (the test reads it as `uint` then casts to `bytes4`).
    channel_id: u32,
    /// CloseIntent fields (`ChannelSettlementManager.CloseIntent`):
    close_nonce: u64,
    final_epoch: u64,
    final_small_block_number: u64,
    close_freeze_nonce: u64,
    final_channel_state_digest: String,
    final_balance_state_h1: String,
    /// `channelFundAmount` (uint256) as a 0x-prefixed hex string (`vm.parseJsonUint` accepts hex).
    channel_fund_amount: String,
    channel_fund_intmax_state_root: String,
    burn_tx_hash: String,
    close_withdrawal_digest: String,
    snapshot_medium_block_number: u64,
    final_state_version: u64,
    final_settled_tx_chain: String,
    /// Close-intent digest (IMCI), pulled from PI limbs 57..65. The Solidity
    /// `computeCloseIntentDigest` must reproduce this; emitted so the test can assert it.
    close_intent_digest: String,
    /// The proof's in-circuit `member_set_commitment` (PI limbs 77..85). The channel's
    /// `registeredMemberSetCommitment()` MUST equal this.
    member_set_commitment: String,
    member_count: u8,
    delegate_count: u8,
    /// The active members' `pk_g` hashes (slot order) that the close proof verified signatures
    /// for. The Solidity test registers the channel with EXACTLY these so its member-set
    /// commitment matches the proof's. Padding slots (>= member_count) are NOT emitted (zeroed
    /// on-chain).
    member_pk_gs: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    eprintln!("[close] Step 0: build close circuit fixture (balance + list + close circuits)");
    let fx = test_fixture::fixture();

    // -----------------------------------------------------------------------
    // Step 1: build a REAL self-consistent close witness and prove the close circuit.
    // Uses the SAME canonical builder the in-tree close-circuit tests exercise
    // (`test_fixture::build_close_full_witness_n`), un-gated for this binary via the
    // `close-fixture-bin` feature — so the fixture is the exact closable state the tests prove.
    // -----------------------------------------------------------------------
    let member_count = test_fixture::TEST_ACTIVE_MEMBERS;
    eprintln!("[close] Step 1: build close witness (member_count = {member_count}) + prove");
    let witness = test_fixture::build_close_full_witness_n(member_count);
    let close_proof = fx.close_circuit.prove(&witness)?;
    fx.close_circuit.data.verify(close_proof.clone())?;
    eprintln!(
        "[close] close proof OK (degree bits {})",
        fx.close_circuit.data.common.degree_bits()
    );

    // -----------------------------------------------------------------------
    // Step 2: reconstruct the 87-limb public inputs from the PROVED proof and decode them.
    // The close circuit registers exactly `CHANNEL_CLOSE_PUBLIC_INPUTS_LEN` raw Goldilocks limbs
    // (see ChannelClosePublicInputsTarget::to_vec); these are what the on-chain verifier re-binds.
    // -----------------------------------------------------------------------
    let pi_limbs: Vec<u64> =
        close_proof.public_inputs[..CHANNEL_CLOSE_PUBLIC_INPUTS_LEN].to_u64_vec();
    assert_eq!(
        pi_limbs.len(),
        CHANNEL_CLOSE_PUBLIC_INPUTS_LEN,
        "close proof must register exactly {CHANNEL_CLOSE_PUBLIC_INPUTS_LEN} public-input limbs"
    );
    let pis = ChannelClosePublicInputs::from_u64_slice(&pi_limbs)?;

    // -----------------------------------------------------------------------
    // Step 3: wrap (WrapperCircuit) + MLE/WHIR commit-open + verify. Mirrors
    // generate_withdrawal_fixture.rs "Step 5" exactly. WrapperCircuit re-registers the inner PIs
    // verbatim, so the wrapped proof's MLE `publicInputs` equal the 87 close limbs above.
    // -----------------------------------------------------------------------
    eprintln!("[close] Step 3: wrap + MLE (close proof)");
    let close_wrapper = WrapperCircuit::<F, C, C, D>::new(&fx.close_circuit.data.verifier_data());
    let close_wrapped = close_wrapper.prove(&close_proof)?;
    close_wrapper.data.verify(close_wrapped.clone())?;
    let close_vk = setup_mle_vk::<F, C, D>(&close_wrapper.data);
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&close_wrapper.wrap_proof, &close_proof);
    let close_mle = prove_with_mle::<F, C, D>(&close_wrapper.data, pw)?;
    verify_mle_proof(&close_wrapper.data, &close_vk, &close_mle.proof)?;
    let close_mle_json = export_mle_json(&close_mle.proof, &close_wrapper.data.common);

    // SANITY: the MLE proof's exported publicInputs must equal the 87 raw close limbs (this is the
    // exact vector the on-chain `_bindCloseLimbsStrict` rebinds). A mismatch here means the
    // on-chain bind would never match the proof, so fail loudly BEFORE the user spends gas.
    {
        let parsed: serde_json::Value = serde_json::from_str(&close_mle_json)?;
        let mle_pis = parsed
            .get("publicInputs")
            .and_then(|v| v.as_array())
            .expect("close MLE json must carry publicInputs");
        assert_eq!(
            mle_pis.len(),
            CHANNEL_CLOSE_PUBLIC_INPUTS_LEN,
            "MLE publicInputs length must be {CHANNEL_CLOSE_PUBLIC_INPUTS_LEN} (raw close limbs), got {}",
            mle_pis.len()
        );
        for (i, (got, want)) in mle_pis.iter().zip(pi_limbs.iter()).enumerate() {
            // The MLE json encodes limbs as decimal strings or numbers; normalize via u64 parse.
            let got_u64 = match got {
                serde_json::Value::String(s) => s.parse::<u64>().unwrap_or_else(|_| {
                    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("limb hex")
                }),
                serde_json::Value::Number(n) => n.as_u64().expect("limb number"),
                _ => panic!("unexpected limb json type at {i}"),
            };
            assert_eq!(got_u64, *want, "MLE publicInputs[{i}] != proved close limb");
        }
        eprintln!("[close] MLE publicInputs == 87 raw close limbs (sanity OK)");
    }

    // -----------------------------------------------------------------------
    // Step 4: write outputs.
    // -----------------------------------------------------------------------
    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;

    fs::write(out_dir.join("close_intent_mle.json"), &close_mle_json)?;
    eprintln!("[close] wrote contracts/test/data/close_intent_mle.json");

    let member_pk_gs: Vec<String> = witness
        .member_auth
        .iter()
        .map(|a| a.pk_g.to_string())
        .collect();

    let descriptor = CloseIntentDescriptor {
        channel_id: pis.channel_id.channel_id(),
        close_nonce: pis.close_nonce,
        final_epoch: pis.final_epoch,
        final_small_block_number: pis.final_small_block_number,
        close_freeze_nonce: pis.close_freeze_nonce,
        final_channel_state_digest: pis.final_channel_state_digest.to_string(),
        final_balance_state_h1: pis.final_balance_state_h1.to_string(),
        channel_fund_amount: pis.channel_fund_amount.to_string(),
        channel_fund_intmax_state_root: pis.channel_fund_intmax_state_root.to_string(),
        burn_tx_hash: pis.burn_tx_hash.to_string(),
        close_withdrawal_digest: pis.close_withdrawal_digest.to_string(),
        snapshot_medium_block_number: pis.snapshot_medium_block_number,
        final_state_version: pis.final_state_version,
        final_settled_tx_chain: pis.final_settled_tx_chain.to_string(),
        close_intent_digest: pis.close_intent_digest.to_string(),
        member_set_commitment: pis.member_set_commitment.to_string(),
        member_count: pis.member_count,
        delegate_count: pis.delegate_count,
        member_pk_gs,
    };
    let descriptor_json = serde_json::to_string_pretty(&descriptor)?;
    fs::write(out_dir.join("close_intent.json"), &descriptor_json)?;
    eprintln!("[close] wrote contracts/test/data/close_intent.json");

    eprintln!("[close] Done!");
    Ok(())
}
