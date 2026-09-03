//! Generate the on-chain test fixture for a REAL channel-close-intent MLE/WHIR proof.
//!
//! Phase A (tasks/close-verifier-a1-plan.md): `ChannelSettlementVerifier.verifyCloseIntent` is
//! being turned into a REAL on-chain verification of the plonky2 `ChannelCloseCircuit` via the
//! shared pinned compact-v2 MLE/WHIR rail (the SAME rail proven by validity/withdrawal). This
//! binary produces the proof-free deployment config and two artifacts the Solidity close tests
//! consume:
//!
//!   - contracts/test/data/close_intent_mle_config.json — strict proof-free V2 configuration.
//!   - contracts/test/data/close_intent_mle.json — the wrapped-close compact-v2 proof plus its
//!     pinned verification configuration, in the exact schema consumed by
//!     `FixtureLib.parseCompactProofV2` / `FixtureLib.deployPinnedMleV2`.
//!   - contracts/test/data/close_intent.json — a descriptor with EVERY `CloseProofFields` value the
//!     Solidity test needs (channelId, all digests, finalStateVersion, finalSettledTxChain,
//!     memberSetCommitment, memberCount, delegateCount, …) plus the close-intent fields the
//!     `CloseIntent` struct needs and the per-member `pk_g` hashes the channel must register so its
//!     `registeredMemberSetCommitment()` equals the proof's in-circuit `member_set_commitment`.
//!
//! SECURITY: every exported value is pulled PROGRAMMATICALLY from the PROVED close-circuit public
//! inputs (`ChannelClosePublicInputs::from_u64_slice` over the CHANNEL_CLOSE_PUBLIC_INPUTS_LEN
//! (103) raw Goldilocks limbs the close circuit registers — `WrapperCircuit` re-registers them
//! verbatim). Nothing is hardcoded. The 103-limb public-input vector is what the on-chain
//! `_bindCloseLimbsStrict` will re-bind limb-by-limb, and the circuit-specific pinned v2 adapter
//! then re-checks the proof against the close verification configuration.
//!
//! Usage:  cargo run --release --features close-fixture-bin --bin generate_close_fixture
//!
//! HEAVY COMPUTE: this runs a full close-circuit proof + a WrapperCircuit recursion + the MLE/WHIR
//! commit-and-open (degree 2^19+, minutes, multi-GB). It must be run explicitly by the user; the
//! Developer-facing Solidity close tests may skip while `close_intent_mle.json` is absent; the
//! non-skipping V2 fixture release manifest makes absence or a stale schema a release failure.

use std::{fs, path::Path};

use intmax3_zkp::{
    circuits::channel::{
        close_circuit::test_fixture,
        close_pis::{CHANNEL_CLOSE_PUBLIC_INPUTS_LEN, ChannelClosePublicInputs},
    },
    ethereum_types::u256::U256,
    utils::{
        conversion::ToU64,
        mle_prover::{
            export_mle_v2_config_json, export_mle_v2_json, mle_v2_config_only_requested,
            persist_or_validate_mle_v2_config_json, prove_with_mle_v2, setup_mle_vk_v2,
            validate_mle_v2_full_against_config_json, verify_mle_proof_v2,
        },
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
    /// Stage 3: `settled_tx_accumulator_root` of the final balance state (PI limbs 77..85). The
    /// Solidity `CloseLifecycleE2E` parses this into `CloseIntent.finalSettledTxAccumulatorRoot`.
    final_settled_tx_accumulator_root: String,
    /// Canonical close-state ID (IMCS), pulled from PI limbs 57..65. The Solidity
    /// `computeCloseIntentDigest` must reproduce this; emitted so the test can assert it.
    close_intent_digest: String,
    /// The proof's in-circuit `member_set_commitment` (PI limbs 85..93, shifted +8 by Stage 3).
    /// The channel's `registeredMemberSetCommitment()` MUST equal this.
    member_set_commitment: String,
    member_count: u8,
    // u16: delegate slots span the full 1024 balance-slot space (Option B) — matches the
    // `ChannelClosePublicInputs.delegate_count` width.
    delegate_count: u16,
    /// The active members' `pk_g` hashes (slot order) that the close proof verified signatures
    /// for. The Solidity test registers the channel with EXACTLY these so its member-set
    /// commitment matches the proof's. Padding slots (>= member_count) are NOT emitted (zeroed
    /// on-chain).
    member_pk_gs: Vec<String>,
    /// Multi-token (§N-6, Phase 5b): the FULL per-token fund vector of the proved final state
    /// (10 x 0x-hex U256, registry-aligned). These are the values the on-chain
    /// `ChannelSettlementVerifier.tokenFundsDigest` recompute binds to the member-signed
    /// `token_funds_digest` PI (limbs 95..103); `amounts[0]` equals the legacy
    /// `channel_fund_amount` scalar (the genesis burn leg).
    channel_fund_amounts: Vec<String>,
    /// Multi-token: the proved final state's base-token registry (10 x u32, active prefix =
    /// `token_count`).
    token_registry: Vec<u32>,
    /// Multi-token: number of ACTIVE registry slots (1..=10).
    token_count: u8,
    /// The proved `token_funds_digest` PI (limbs 95..103) — emitted for reference/assertions;
    /// the verifier RECOMPUTES it from the three fields above (never trusts this value).
    token_funds_digest: String,
}

fn main() -> anyhow::Result<()> {
    eprintln!("[close] Step 0: build close circuit fixture (balance + list + close circuits)");
    let fx = test_fixture::fixture();
    let close_wrapper = WrapperCircuit::<F, C, C, D>::new(&fx.close_circuit.data.verifier_data());
    let close_mle_config_json = export_mle_v2_config_json(&close_wrapper.data)?;
    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;
    persist_or_validate_mle_v2_config_json(
        out_dir.join("close_intent_mle_config.json"),
        &close_mle_config_json,
    )?;
    eprintln!("[close] wrote contracts/test/data/close_intent_mle_config.json");
    if mle_v2_config_only_requested() {
        eprintln!("[close] config-only mode: no witness or proof was constructed");
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Step 1: build a REAL self-consistent close witness and prove the close circuit.
    //
    // Multitoken Phase 5b (CO-GENERATION): the witness is built by
    // `test_fixture::build_close_full_witness_two_token` over
    //   - channel 1, signed by `test_fixture::deterministic_falcon_keys(1, N)`. The withdrawal
    //     generator uses the same deterministic Falcon identities for channel registration, so the
    //     close and `close_` withdrawal families must be regenerated together and are checked for
    //     exact member-set equality by the lifecycle E2E;
    //   - a TWO-token final state (registry [ETH, 7], amounts [77, 55]) so the fixture exercises
    //     the per-token settlement path (nonzero non-genesis fund), not just genesis.
    // -----------------------------------------------------------------------
    const CLOSE_FIXTURE_CHANNEL_ID: u32 = 1;
    const NON_GENESIS_TOKEN_INDEX: u32 = 7;
    let member_count = test_fixture::TEST_ACTIVE_MEMBERS;
    let member_keys =
        test_fixture::deterministic_falcon_keys(CLOSE_FIXTURE_CHANNEL_ID, member_count);
    eprintln!("[close] deterministic Falcon member set matches the co-generated withdrawal family");
    eprintln!(
        "[close] Step 1: build two-token close witness (channel {CLOSE_FIXTURE_CHANNEL_ID}, \
         member_count = {member_count}, registry [0, {NON_GENESIS_TOKEN_INDEX}]) + prove"
    );
    let witness = test_fixture::build_close_full_witness_two_token(
        CLOSE_FIXTURE_CHANNEL_ID,
        &member_keys,
        NON_GENESIS_TOKEN_INDEX,
        U256::from(55u32),
    );
    let close_proof = fx.close_circuit.prove(&witness)?;
    fx.close_circuit.data.verify(close_proof.clone())?;
    eprintln!(
        "[close] close proof OK (degree bits {})",
        fx.close_circuit.data.common.degree_bits()
    );

    // -----------------------------------------------------------------------
    // Step 2: reconstruct the 103-limb public inputs from the PROVED proof and decode them.
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
    // verbatim, so the wrapped proof's MLE `publicInputs` equal the 103 close limbs above.
    // -----------------------------------------------------------------------
    eprintln!("[close] Step 3: wrap + MLE (close proof)");
    let close_wrapped = close_wrapper.prove(&close_proof)?;
    close_wrapper.data.verify(close_wrapped.clone())?;
    let close_vk = setup_mle_vk_v2::<F, C, D>(&close_wrapper.data);
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&close_wrapper.wrap_proof, &close_proof)?;
    let close_mle = prove_with_mle_v2::<F, C, D>(&close_wrapper.data, pw)?;
    verify_mle_proof_v2(&close_wrapper.data, &close_vk, &close_mle.proof)?;
    let close_mle_json = export_mle_v2_json(&close_mle.proof, &close_vk, &close_wrapper.data)?;
    validate_mle_v2_full_against_config_json(&close_mle_json, &close_mle_config_json)?;

    // SANITY: the MLE proof's exported publicInputs must equal the 103 raw close limbs (this is the
    // exact vector the on-chain `_bindCloseLimbsStrict` rebinds). A mismatch here means the
    // on-chain bind would never match the proof, so fail loudly BEFORE the user spends gas.
    {
        let parsed: serde_json::Value = serde_json::from_str(&close_mle_json)?;
        let mle_pis = parsed
            .pointer("/proof/publicInputs")
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
        eprintln!("[close] MLE publicInputs == 103 raw close limbs (sanity OK)");
    }

    // -----------------------------------------------------------------------
    // Step 4: write outputs.
    // -----------------------------------------------------------------------
    fs::write(out_dir.join("close_intent_mle.json"), &close_mle_json)?;
    eprintln!("[close] wrote contracts/test/data/close_intent_mle.json");

    let member_pk_gs: Vec<String> = witness
        .member_auth
        .iter()
        .map(|a| a.pk_g.to_string())
        .collect();

    // Per-token descriptor fields from the PROVED final state (the SAME witnessed
    // registry/count/amounts the in-circuit token_funds_digest recompute — PI limbs 95..103 —
    // was computed over; the on-chain verifier re-binds them by recomputing the digest).
    let final_state = &witness.close.final_channel_state;
    let channel_fund_amounts: Vec<String> = final_state
        .channel_fund
        .amounts
        .iter()
        .map(|a| a.to_string())
        .collect();
    let token_registry: Vec<u32> = final_state.balance_state.token_registry.to_vec();
    let token_count = final_state.balance_state.token_count;

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
        final_settled_tx_accumulator_root: pis.final_settled_tx_accumulator_root.to_string(),
        close_intent_digest: pis.close_intent_digest.to_string(),
        member_set_commitment: pis.member_set_commitment.to_string(),
        member_count: pis.member_count,
        delegate_count: pis.delegate_count,
        member_pk_gs,
        channel_fund_amounts,
        token_registry,
        token_count,
        token_funds_digest: pis.token_funds_digest.to_string(),
    };
    let descriptor_json = serde_json::to_string_pretty(&descriptor)?;
    fs::write(out_dir.join("close_intent.json"), &descriptor_json)?;
    eprintln!("[close] wrote contracts/test/data/close_intent.json");

    eprintln!("[close] Done!");
    Ok(())
}
