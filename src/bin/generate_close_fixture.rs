//! Co-generate the on-chain CLOSE fixture family: the `close_` lifecycle, the REAL
//! channel-close-intent MLE/WHIR proof and the REAL whole-vector `CloseAssetBacking` proof.
//!
//! Phase A (tasks/close-verifier-a1-plan.md) turned `ChannelSettlementVerifier.verifyCloseIntent`
//! into a REAL on-chain verification of the plonky2 `ChannelCloseCircuit` via the shared pinned
//! compact-v2 MLE/WHIR rail (the SAME rail proven by validity/withdrawal). The signer-independent
//! exit then made `submitCloseIntent` ALSO require (`ChannelSettlementManager._checkCloseProof`):
//!   - `registry.isFinalizedStateRoot(intent.channelFundIntmaxStateRoot)` — the signed
//!     `intmax_state_root` must be a rollup state root the lifecycle actually finalized; and
//!   - `closeFundingMaterializer.requireSignedHeadBacking(channelId, finalSettledTxChain,
//!     tokenFundsDigest)` — an attested `CloseAssetBackingCircuit` proof over the SAME final
//!     balance proof, anchored at (>=) the channel's last posted block.
//! A close witness with a placeholder state root / genesis balance proof can therefore never be
//! submitted against the real contracts. This binary builds the WHOLE family from ONE lifecycle
//! so every cross-binding holds by construction:
//!
//!   0. Proof-free wire-v3 deployment configs of every close-family statement
//!      (`close_intent_mle_config.json`, `close_asset_backing_mle_config.json`,
//!      `close_lifecycle_validity_mle_config.json`, `close_withdrawal_mle_config.json`), each
//!      create-once/compare-later (`persist_or_validate_mle_v2_config_json`). With
//!      `--mle-config-only` the binary stops here: no witness or proof is constructed, which is
//!      how the Manager CREATE2 address printer gets its inputs BEFORE any proof exists.
//!   1. `wallet_core::build_channel_withdrawal` (channel 1, deposit 6 / withdraw 3, withdrawal
//!      recipient = the close manager's CREATE2 address from `WD_RECIPIENT`) → the four `close_`
//!      lifecycle files (`close_lifecycle.json`, `close_lifecycle_validity_mle.json`,
//!      `close_withdrawal_mle.json`, `close_withdrawal_payout.json`), exactly what
//!      `WD_OUT_PREFIX=close_ generate_withdrawal_fixture` used to write, PLUS its private
//!      internals (final balance proof, full private state, final `ExtendedPublicState`).
//!   2. A close witness over THAT balance proof: `intmax_state_root = final ext commitment`
//!      (== `close_lifecycle.json.final_state_root`), `settled_tx_chain` = the balance PI, fund
//!      vector = the private asset tree (`{ETH -> 3}`, single lane) →
//!      `close_intent_mle.json` (strict canonical full wire-v3 fixture whose `.compactProof.bytes`
//!      is the exact `submitCloseIntent` calldata, validated against its config) +
//!      `close_intent.json`.
//!   3. The backing proof over the same balance proof / private state / ext state →
//!      `close_asset_backing_mle.json` (full wire-v3 fixture, validated against
//!      `close_asset_backing_mle_config.json`), `close_asset_backing_public_inputs.json` (the bare
//!      26 raw limbs) and `close_asset_backing_manifest.json` (the `public_close_prover`
//!      `OutputManifest` shape `DeployCloseCli._readBackingMle` authenticates).
//!
//! SECURITY: every exported value is pulled PROGRAMMATICALLY from PROVED public inputs
//! (`ChannelClosePublicInputs::from_u64_slice` over the 103 raw close limbs,
//! `CloseAssetBackingPublicInputs::from_pis` over the 26 raw backing limbs). Nothing is hardcoded.
//! The generator additionally asserts the cross-bindings the contracts enforce (state root
//! finalized-by-this-lifecycle, anchor == last block, token_funds_digest / settled_tx_chain equal
//! between the two proofs) so a broken co-generation fails HERE, not at `submitCloseIntent`.
//!
//! Usage:
//!   cargo run --release --features close-fixture-bin --bin generate_close_fixture -- --mle-config-only
//!   forge test --match-test test_printCloseManagerAddress -vv   # in contracts/, needs the configs
//!   WD_RECIPIENT=0x<CLOSE_MANAGER_ADDRESS> \
//!     cargo run --release --features close-fixture-bin --bin generate_close_fixture
//!
//! Env:
//!   - WD_RECIPIENT=0x<20 bytes>        REQUIRED. The manager CREATE2 address baked as the L1
//!                                      withdrawal recipient (a wrong one is a hard E2E failure).
//!   - WD_DEPOSITOR=0x<20 bytes>        optional; default = deterministic RNG address.
//!   - CLOSE_BACKING_ROLLUP=0x<20 bytes> optional manifest `rollup` field (the CREATE2 rollup is
//!                                      not knowable here; default 0x00..00 — `DeployGuards`
//!                                      synthesizes its own manifest with the live address).
//!
//! HEAVY COMPUTE: a full 3-block lifecycle (balance / validity / withdrawal proving + two
//! wrap+MLE passes), a close-circuit proof + wrap + MLE, and a backing proof + wrap + MLE
//! (degree 2^17-2^19+, many minutes, multi-GB). Run explicitly; the developer-facing Solidity
//! close tests skip gracefully until the `close_*` files exist, while the non-skipping V2 fixture
//! release manifest makes absence or a stale schema a release failure.

use std::{fs, path::Path};

use intmax3_zkp::{
    circuits::{
        balance::balance_pis::BalanceFullPublicInputs,
        channel::{
            close_asset_backing_circuit::{
                CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN, CloseAssetBackingCircuit,
                CloseAssetBackingPublicInputs, CloseAssetBackingWitness,
            },
            close_circuit::test_fixture,
            close_pis::{CHANNEL_CLOSE_PUBLIC_INPUTS_LEN, ChannelClosePublicInputs},
        },
    },
    common::{balance_state::BalanceState, channel::ChannelFund, channel_id::ChannelId},
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256,
    },
    public_close_prover::{
        PUBLIC_CLOSE_BUNDLE_SCHEMA_VERSION, export_backing_mle_config, mle_v2_public_inputs,
        sha256_hex, wrap_and_export_backing_mle,
    },
    utils::{
        conversion::ToU64,
        mle_prover::{
            export_mle_v2_config_json, export_mle_v2_json, mle_v2_config_only_requested,
            persist_or_validate_mle_v2_config_json, prove_with_mle_v2, setup_mle_vk_v2,
            validate_mle_v2_full_against_config_json, verify_mle_proof_v2,
        },
        serialize::serialize_verifier_data,
        wrapper::WrapperCircuit,
    },
    wallet_core::{
        ChannelWithdrawalParams, build_channel_withdrawal, build_channel_withdrawal_mle_v2_configs,
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

/// The lifecycle this family closes. `deposit - withdrawal` is the channel's final ETH balance,
/// i.e. the ONE active leaf of the private asset tree the backing proof opens, and therefore
/// `channel_fund.amounts[0]`. `CloseLifecycleE2E` asserts the L1 withdrawal payout (3) equals
/// `finalizedChannelFundAmount(0) == amounts[0]`, so the two MUST stay `deposit - withdraw ==
/// withdraw`. `generate_withdrawal_fixture` (the plain set) uses the same numbers.
const CLOSE_FIXTURE_CHANNEL_ID: u32 = 1;
const CLOSE_FIXTURE_DEPOSIT: u64 = 6;
const CLOSE_FIXTURE_WITHDRAWAL: u64 = 3;
/// `31337`: the local devnet every checked-in fixture targets (`DeployCloseCli` requires
/// `manifest.chainId == block.chainid`).
const LOCAL_CHAIN_ID: u64 = 31_337;

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

/// `close_asset_backing_manifest.json`: the `public_close_prover` `OutputManifest` shape (same
/// camelCase field set, `src/bin/public_close_prover.rs`), so `DeployCloseCli._readBackingMle`
/// authenticates the checked-in backing artifact through the SAME reader a live bundle goes
/// through. Only the backing triple is materialized in `contracts/test/data` (under the
/// `close_asset_backing_*` names); the other payload hashes are computed over the in-memory
/// bytes of this run so the manifest is still a faithful description of ONE proof bundle.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FixtureBackingManifest {
    #[serde(rename = "_comment")]
    comment: &'static str,
    schema_version: u32,
    chain_id: u64,
    rollup: Address,
    channel_id: ChannelId,
    balance_verifier_data_sha256: String,
    close_proof_file: &'static str,
    close_proof_bytes: usize,
    close_mle_file: &'static str,
    close_mle_bytes: usize,
    backing_proof_file: &'static str,
    backing_proof_bytes: usize,
    backing_mle_file: &'static str,
    backing_mle_bytes: usize,
    backing_mle_config_file: &'static str,
    backing_mle_config_bytes: usize,
    backing_public_inputs_file: &'static str,
    backing_public_input_count: usize,
    backing_finalized_extended_state_commitment: Bytes32,
    backing_anchor_block_number: u64,
    close_intent_file: &'static str,
    close_intent_full_file: &'static str,
    close_public_inputs_file: &'static str,
    close_public_input_count: usize,
    close_proof_sha256: String,
    close_mle_sha256: String,
    backing_proof_sha256: String,
    backing_mle_sha256: String,
    backing_mle_config_sha256: String,
    backing_public_inputs_sha256: String,
    close_intent_sha256: String,
    close_intent_full_sha256: String,
    close_public_inputs_sha256: String,
    key_material_consumed: bool,
    self_verified: bool,
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

/// Assert the exported wire-v3 fixture's `proof.publicInputs` are EXACTLY `want` (the raw inner
/// limbs the on-chain strict-limb bind rebinds). A mismatch means the on-chain bind could never
/// match the proof, so fail loudly BEFORE the user spends gas.
fn assert_mle_public_inputs(tag: &str, mle_json: &str, want: &[u64]) -> anyhow::Result<()> {
    let mle_pis = mle_v2_public_inputs(mle_json)?;
    assert_eq!(
        mle_pis,
        want,
        "{tag} MLE publicInputs must equal the {} raw inner limbs",
        want.len()
    );
    eprintln!(
        "[close] {tag} MLE publicInputs == {} raw limbs (sanity OK)",
        want.len()
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;

    // -----------------------------------------------------------------------
    // Step 0 (proof-free): the wire-v3 deployment configs of both close-family statements this
    // binary proves. Circuit setup only — no witness, no proof — so the Manager CREATE2 printer
    // (`test_printCloseManagerAddress`) can run before the heavy passes, and so a later proof is
    // refused if it disagrees with the config a verifier was already deployed from.
    // -----------------------------------------------------------------------
    eprintln!("[close] Step 0: build close circuit fixture (balance + agg + close circuits)");
    let fx = test_fixture::fixture();
    let close_wrapper = WrapperCircuit::<F, C, C, D>::new(&fx.close_circuit.data.verifier_data());
    let close_mle_config_json = export_mle_v2_config_json(&close_wrapper.data)?;
    persist_or_validate_mle_v2_config_json(
        out_dir.join("close_intent_mle_config.json"),
        &close_mle_config_json,
    )?;
    eprintln!("[close] wrote/validated contracts/test/data/close_intent_mle_config.json");
    // The backing circuit is a deterministic function of the Balance VD alone (the same VD the
    // lifecycle below proves under; asserted once the lifecycle exists).
    let fixture_balance_vd = fx.balance_processor.balance_vd();
    let backing_circuit = CloseAssetBackingCircuit::<F, C, D>::new(&fixture_balance_vd);
    let backing_mle_config_json = export_backing_mle_config(&backing_circuit)?;
    persist_or_validate_mle_v2_config_json(
        out_dir.join("close_asset_backing_mle_config.json"),
        &backing_mle_config_json,
    )?;
    eprintln!("[close] wrote/validated contracts/test/data/close_asset_backing_mle_config.json");
    if mle_v2_config_only_requested() {
        // The `close_` lifecycle configs are circuit-derived too; emit them here so ONE
        // `--mle-config-only` pass yields every close-family deployment config.
        let lifecycle_configs = build_channel_withdrawal_mle_v2_configs()?;
        persist_or_validate_mle_v2_config_json(
            out_dir.join("close_lifecycle_validity_mle_config.json"),
            &lifecycle_configs.validity_mle_config_json,
        )?;
        persist_or_validate_mle_v2_config_json(
            out_dir.join("close_withdrawal_mle_config.json"),
            &lifecycle_configs.withdrawal_mle_config_json,
        )?;
        eprintln!(
            "[close] config-only mode: wrote/validated close_intent_mle_config.json, \
             close_asset_backing_mle_config.json, close_lifecycle_validity_mle_config.json and \
             close_withdrawal_mle_config.json; no witness or proof was constructed"
        );
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Step 0b: the lifecycle this family closes (the `close_` set, formerly written by
    // `WD_OUT_PREFIX=close_ generate_withdrawal_fixture`). Same deterministic keys / RNG seeds as
    // the plain set; only the baked withdrawal recipient (the manager) differs.
    // -----------------------------------------------------------------------
    let withdrawal_recipient = std::env::var("WD_RECIPIENT")
        .ok()
        .map(|h| parse_address_hex(&h))
        .expect(
            "WD_RECIPIENT is required: the close manager CREATE2 address (contracts: `forge test \
             --match-test test_printCloseManagerAddress -vv`) is baked into the close withdrawal \
             proof as the L1 recipient; without it the close set cannot pay the manager",
        );
    let params = ChannelWithdrawalParams {
        channel_id: CLOSE_FIXTURE_CHANNEL_ID,
        deposit_amount: CLOSE_FIXTURE_DEPOSIT,
        withdrawal_amount: CLOSE_FIXTURE_WITHDRAWAL,
        depositor: std::env::var("WD_DEPOSITOR")
            .ok()
            .map(|h| parse_address_hex(&h)),
        withdrawal_recipient: Some(withdrawal_recipient),
        deposit_salt: None,
        erc20_lane: None,
        burn_aux_data: None,
    };
    eprintln!(
        "[close] Step 0b: build the close_ lifecycle (channel {CLOSE_FIXTURE_CHANNEL_ID}, deposit \
         {CLOSE_FIXTURE_DEPOSIT}, withdraw {CLOSE_FIXTURE_WITHDRAWAL}, recipient = {}) — HEAVY",
        withdrawal_recipient
    );
    let artifacts = build_channel_withdrawal(&params, None)?;

    persist_or_validate_mle_v2_config_json(
        out_dir.join("close_lifecycle_validity_mle_config.json"),
        &artifacts.validity_mle_config_json,
    )?;
    persist_or_validate_mle_v2_config_json(
        out_dir.join("close_withdrawal_mle_config.json"),
        &artifacts.withdrawal_mle_config_json,
    )?;
    for (name, body) in [
        ("close_withdrawal_mle.json", &artifacts.withdrawal_mle_json),
        (
            "close_lifecycle_validity_mle.json",
            &artifacts.validity_mle_json,
        ),
        ("close_lifecycle.json", &artifacts.lifecycle_json),
        ("close_withdrawal_payout.json", &artifacts.payout_json),
    ] {
        fs::write(out_dir.join(name), body)?;
        eprintln!("[close] wrote contracts/test/data/{name}");
    }

    let lifecycle: serde_json::Value = serde_json::from_str(&artifacts.lifecycle_json)?;
    let lifecycle_final_state_root = lifecycle["final_state_root"]
        .as_str()
        .expect("lifecycle final_state_root")
        .to_string();
    let ext = artifacts.final_ext_public_state.clone();
    let final_state_root = ext.commitment();
    let anchor_block_number = ext.inner.block_number.as_u64();
    assert_eq!(
        final_state_root.to_string(),
        lifecycle_final_state_root,
        "final ExtendedPublicState commitment != close_lifecycle.json final_state_root"
    );
    assert_eq!(
        anchor_block_number,
        lifecycle["vpis"]["final_block_number"]
            .as_u64()
            .expect("vpis.final_block_number"),
        "anchor (final ext block number) != lifecycle vpis.final_block_number"
    );
    assert_eq!(
        anchor_block_number, 3,
        "the lifecycle is registration -> deposit -> withdrawal-tx: the backing anchor must be \
         block 3 (== the materializer's lastPostedBlock[channel] after the E2E chain)"
    );

    // The balance proof's public inputs: the close circuit binds `settled_tx_chain` and
    // `channel_id`; the backing circuit ALSO opens `private_commitment` and binds
    // `public_state == ext.inner`. Check all four natively first so a drift fails in ms.
    let balance_pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
        &artifacts.final_balance_proof.public_inputs.to_u64_vec(),
        &artifacts.balance_vd.common.config,
    )?
    .pis;
    assert_eq!(
        balance_pis.channel_id,
        ChannelId::new(CLOSE_FIXTURE_CHANNEL_ID as u64).unwrap(),
        "final balance proof channel id"
    );
    assert_eq!(
        balance_pis.public_state, ext.inner,
        "final balance proof public_state != final ExtendedPublicState.inner"
    );
    let private_state = artifacts.full_private_state.to_private_state();
    assert_eq!(
        balance_pis.private_commitment,
        private_state.commitment(),
        "final balance proof private_commitment != full private state commitment"
    );
    assert_ne!(
        balance_pis.settled_tx_chain,
        Bytes32::default(),
        "after a deposit the settled_tx_chain must have left genesis (deposit pushes)"
    );

    // The fund vector the close state signs and the backing proof rebuilds: the private asset
    // tree after `deposit - withdrawal` is the single ETH leaf.
    let final_eth_balance = U256::from(CLOSE_FIXTURE_DEPOSIT - CLOSE_FIXTURE_WITHDRAWAL);
    assert_eq!(
        artifacts.full_private_state.asset_tree.get_leaf(0),
        final_eth_balance,
        "private asset tree ETH leaf != deposit - withdrawal"
    );
    let token_registry = BalanceState::single_token_registry(0);
    let token_count: u8 = 1;
    let amounts = ChannelFund::single_token_amounts(final_eth_balance);

    // -----------------------------------------------------------------------
    // Step 1: build the close circuits and a self-consistent close witness OVER THE LIFECYCLE'S
    // balance proof, then prove the close circuit.
    //
    // falcon-sig Phase 3 / multitoken Phase 5b: signed by `deterministic_falcon_keys(1, N)`, the
    // SAME derivation `ChannelMemberKeys::deterministic(1)` registers inside
    // `build_channel_withdrawal`, so the proof's member-set commitment equals the registered one.
    // Asserted below against the lifecycle's own registration record rather than assumed.
    // -----------------------------------------------------------------------
    assert_eq!(
        fixture_balance_vd, artifacts.balance_vd,
        "close-fixture balance verifier data != the lifecycle's balance verifier data (the \
         balance circuit family is deterministic; a mismatch means two different circuit builds)"
    );
    let member_count = test_fixture::TEST_ACTIVE_MEMBERS;
    let member_keys =
        test_fixture::deterministic_falcon_keys(CLOSE_FIXTURE_CHANNEL_ID, member_count);
    {
        let registered: Vec<String> = lifecycle["registration"]["member_pk_gs"]
            .as_array()
            .expect("registration.member_pk_gs")
            .iter()
            .map(|v| v.as_str().expect("pk_g string").to_string())
            .collect();
        let signing: Vec<String> = member_keys.iter().map(|k| k.pk_g().to_string()).collect();
        assert_eq!(
            signing, registered,
            "close signing keys != the lifecycle's registered member pk_g set (co-generation broken)"
        );
    }
    eprintln!(
        "[close] Step 1: build single-lane close witness (channel {CLOSE_FIXTURE_CHANNEL_ID}, \
         member_count = {member_count}, intmax_state_root = {final_state_root}, amounts[0] = \
         {final_eth_balance}) + prove"
    );
    let witness = test_fixture::build_close_full_witness_over_balance_proof(
        CLOSE_FIXTURE_CHANNEL_ID,
        &member_keys,
        final_state_root,
        balance_pis.settled_tx_chain,
        token_registry,
        token_count,
        amounts,
        artifacts.final_balance_proof.clone(),
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
    assert_eq!(
        pis.channel_fund_intmax_state_root, final_state_root,
        "close PI channel_fund_intmax_state_root != lifecycle final_state_root"
    );
    assert_eq!(
        pis.final_settled_tx_chain, balance_pis.settled_tx_chain,
        "close PI final_settled_tx_chain != balance PI settled_tx_chain"
    );
    assert_eq!(
        pis.close_freeze_nonce, 1,
        "close PI close_freeze_nonce must be 1 (proved from a state with freeze nonce 0)"
    );

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
    let close_compact = validate_mle_v2_full_against_config_json(&close_mle_json, &close_mle_config_json)?;
    assert_mle_public_inputs("close", &close_mle_json, &pi_limbs)?;
    eprintln!(
        "[close] close compactProof = {} bytes (the exact submitCloseIntent calldata payload)",
        close_compact.len()
    );

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
    let descriptor_token_registry: Vec<u32> = final_state.balance_state.token_registry.to_vec();
    let descriptor_token_count = final_state.balance_state.token_count;

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
        token_registry: descriptor_token_registry,
        token_count: descriptor_token_count,
        token_funds_digest: pis.token_funds_digest.to_string(),
    };
    let descriptor_json = serde_json::to_string_pretty(&descriptor)?;
    fs::write(out_dir.join("close_intent.json"), &descriptor_json)?;
    eprintln!("[close] wrote contracts/test/data/close_intent.json");

    // -----------------------------------------------------------------------
    // Step 4: the whole-vector CloseAssetBacking proof over the SAME balance proof / private
    // state / ext state. `from_full_private_state_and_channel_state` re-verifies the balance
    // proof and every native mirror (private commitment opening, public_state == ext.inner,
    // settled chain / channel id vs the signed state, asset tree root == the fund vector).
    // -----------------------------------------------------------------------
    eprintln!("[close] Step 4: build + prove the CloseAssetBacking circuit (HEAVY)");
    let backing_witness = CloseAssetBackingWitness::<F, C, D>::from_full_private_state_and_channel_state(
        &artifacts.full_private_state,
        final_state,
        artifacts.final_balance_proof.clone(),
        ext.clone(),
        &artifacts.balance_vd,
    )?;
    let backing_proof = backing_circuit.prove(&backing_witness)?;
    backing_circuit.data.verify(backing_proof.clone())?;
    eprintln!(
        "[close] backing proof OK (degree bits {})",
        backing_circuit.data.common.degree_bits()
    );
    let backing_limbs: Vec<u64> =
        backing_proof.public_inputs[..CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN].to_u64_vec();
    let backing_pis = CloseAssetBackingPublicInputs::from_u64_slice(&backing_limbs)?;
    assert_eq!(
        backing_pis,
        backing_witness.public_inputs(&artifacts.balance_vd)?,
        "proved backing PIs != natively computed backing PIs"
    );

    // The cross-bindings `ChannelSettlementManager._checkCloseProof` +
    // `CloseFundingMaterializer` enforce on chain, asserted natively:
    //   pi[0] == channelId; pi[1..9] (settledTxChain) == intent.finalSettledTxChain;
    //   pi[9..17] (tokenFundsDigest) == close PI limbs 95..103; pi[17..25] (backingRoot) is a
    //   finalized state root == the lifecycle's final_state_root; pi[25] (anchor) == 3 ==
    //   lastPostedBlock[channel] <= latestFinalizedBlockNumber.
    assert_eq!(
        backing_pis.channel_id.channel_id(),
        CLOSE_FIXTURE_CHANNEL_ID,
        "backing PI channel id"
    );
    assert_eq!(
        backing_pis.settled_tx_chain, pis.final_settled_tx_chain,
        "backing PI settled_tx_chain != close PI final_settled_tx_chain"
    );
    assert_eq!(
        backing_pis.token_funds_digest, pis.token_funds_digest,
        "backing PI token_funds_digest != close PI token_funds_digest"
    );
    assert_eq!(
        backing_limbs[9..17],
        pi_limbs[95..103],
        "backing PI limbs 9..17 != close PI limbs 95..103 (tokenFundsDigest limb-for-limb)"
    );
    assert_eq!(
        backing_pis.finalized_extended_state_commitment, final_state_root,
        "backing PI finalized_extended_state_commitment != lifecycle final_state_root"
    );
    assert_eq!(
        backing_pis.finalized_extended_state_commitment.to_string(),
        lifecycle_final_state_root,
        "backing PI finalized_extended_state_commitment != close_lifecycle.json final_state_root"
    );
    assert_eq!(
        backing_pis.anchor_block_number.as_u64(),
        anchor_block_number,
        "backing PI anchor != final ext block number"
    );
    assert_eq!(backing_limbs[25], 3, "backing PI anchor must be block 3");
    eprintln!(
        "[close] backing PIs: channel {}, settled_tx_chain {}, token_funds_digest {}, \
         finalized_extended_state_commitment {}, anchor {}",
        backing_pis.channel_id.channel_id(),
        backing_pis.settled_tx_chain,
        backing_pis.token_funds_digest,
        backing_pis.finalized_extended_state_commitment,
        backing_pis.anchor_block_number.as_u64()
    );

    // -----------------------------------------------------------------------
    // Step 5: wrap + MLE the backing proof through the ONE production path
    // (`public_close_prover::wrap_and_export_backing_mle`: WrapperCircuit -> MLE -> self-verify ->
    // release envelope), then write the artifact triple + its manifest.
    // -----------------------------------------------------------------------
    eprintln!("[close] Step 5: wrap + MLE (backing proof)");
    let backing_mle = wrap_and_export_backing_mle(&backing_circuit, &backing_proof)?;
    assert_eq!(
        backing_mle.mle_config_json, backing_mle_config_json,
        "backing wrap config drifted between the proof-free Step 0 export and the proof pass"
    );
    let backing_mle_json = backing_mle.mle_json;
    assert_mle_public_inputs("backing", &backing_mle_json, &backing_limbs)?;
    eprintln!(
        "[close] backing compactProof = {} bytes (the exact attestSignedHeadBacking calldata payload)",
        backing_mle.compact_proof.len()
    );

    let backing_public_inputs_bytes = serde_json::to_vec_pretty(&backing_limbs)?;
    fs::write(
        out_dir.join("close_asset_backing_mle.json"),
        &backing_mle_json,
    )?;
    eprintln!("[close] wrote contracts/test/data/close_asset_backing_mle.json");
    fs::write(
        out_dir.join("close_asset_backing_public_inputs.json"),
        &backing_public_inputs_bytes,
    )?;
    eprintln!("[close] wrote contracts/test/data/close_asset_backing_public_inputs.json");

    let rollup = std::env::var("CLOSE_BACKING_ROLLUP")
        .ok()
        .map(|h| parse_address_hex(&h))
        .unwrap_or_default();
    let balance_vd_bytes = serialize_verifier_data(&artifacts.balance_vd)?;
    let close_proof_bytes = close_proof.to_bytes();
    let backing_proof_bytes = backing_proof.to_bytes();
    let close_intent_full_bytes = serde_json::to_vec_pretty(&witness.close.close_intent)?;
    let close_public_inputs_bytes = serde_json::to_vec_pretty(&pi_limbs)?;
    let manifest = FixtureBackingManifest {
        comment: "Checked-in stand-in for a `public_close_prover` bundle manifest, co-generated by \
                  `generate_close_fixture` with close_intent*.json / close_lifecycle*.json. Only \
                  the backing triple is materialized in this directory (backing_mle.json -> \
                  close_asset_backing_mle.json, backing_mle_config.json -> \
                  close_asset_backing_mle_config.json, backing_public_inputs.json -> \
                  close_asset_backing_public_inputs.json); the remaining payload hashes cover the \
                  in-memory bytes of the same run. `rollup` is the CLOSE_BACKING_ROLLUP env at \
                  generation time (0x0 when unset): DeployGuards synthesizes a manifest with its \
                  live rollup address.",
        schema_version: PUBLIC_CLOSE_BUNDLE_SCHEMA_VERSION,
        chain_id: LOCAL_CHAIN_ID,
        rollup,
        channel_id: backing_pis.channel_id,
        balance_verifier_data_sha256: sha256_hex(&balance_vd_bytes),
        close_proof_file: "close_proof.bin",
        close_proof_bytes: close_proof_bytes.len(),
        close_mle_file: "close_intent_mle.json",
        close_mle_bytes: close_mle_json.len(),
        backing_proof_file: "backing_proof.bin",
        backing_proof_bytes: backing_proof_bytes.len(),
        backing_mle_file: "backing_mle.json",
        backing_mle_bytes: backing_mle_json.len(),
        backing_mle_config_file: "backing_mle_config.json",
        backing_mle_config_bytes: backing_mle_config_json.len(),
        backing_public_inputs_file: "backing_public_inputs.json",
        backing_public_input_count: backing_limbs.len(),
        backing_finalized_extended_state_commitment: backing_pis
            .finalized_extended_state_commitment,
        backing_anchor_block_number: backing_pis.anchor_block_number.as_u64(),
        close_intent_file: "close_intent.json",
        close_intent_full_file: "close_intent_full.json",
        close_public_inputs_file: "close_public_inputs.json",
        close_public_input_count: pi_limbs.len(),
        close_proof_sha256: sha256_hex(&close_proof_bytes),
        close_mle_sha256: sha256_hex(close_mle_json.as_bytes()),
        backing_proof_sha256: sha256_hex(&backing_proof_bytes),
        backing_mle_sha256: sha256_hex(backing_mle_json.as_bytes()),
        backing_mle_config_sha256: sha256_hex(backing_mle_config_json.as_bytes()),
        backing_public_inputs_sha256: sha256_hex(&backing_public_inputs_bytes),
        close_intent_sha256: sha256_hex(descriptor_json.as_bytes()),
        close_intent_full_sha256: sha256_hex(&close_intent_full_bytes),
        close_public_inputs_sha256: sha256_hex(&close_public_inputs_bytes),
        key_material_consumed: false,
        self_verified: true,
    };
    fs::write(
        out_dir.join("close_asset_backing_manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    eprintln!("[close] wrote contracts/test/data/close_asset_backing_manifest.json");

    eprintln!(
        "[close] Done! final_state_root = {final_state_root}, anchor = {anchor_block_number}, \
         amounts[0] = {final_eth_balance}, settled_tx_chain = {}",
        pis.final_settled_tx_chain
    );
    Ok(())
}
