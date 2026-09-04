//! Generate on-chain test fixtures for a REAL native-ETH withdrawal payout.
//!
//! This binary is now a thin wrapper around `intmax3_zkp::wallet_core::build_channel_withdrawal`
//! (the single source of truth, shared with the `channel_member withdraw` CLI). It builds the
//! self-contained 3-block chain — registration → deposit → withdrawal-tx — and writes the 4
//! artifacts the Solidity tests / the live pipeline consume:
//!   - contracts/test/data/{prefix}withdrawal_mle_config.json   (proof-free deployment config)
//!   - contracts/test/data/{prefix}lifecycle_validity_mle_config.json (proof-free deploy config)
//!   - contracts/test/data/{prefix}withdrawal_mle.json          (withdrawal proof + VK)
//!   - contracts/test/data/{prefix}lifecycle_validity_mle.json  (validity proof + VK, for finalize)
//!   - contracts/test/data/{prefix}lifecycle.json               (registration/deposit/blocks/vpis)
//!   - contracts/test/data/{prefix}withdrawal_payout.json       (committed Withdrawal + prover)
//!
//! Usage:  cargo run --bin generate_withdrawal_fixture --release [-- --mle-config-only]
//!
//! Env overrides (all optional):
//!   - WD_DEPOSITOR=0x<20 bytes>  — pin the depositor (the on-chain `deposit()` msg.sender).
//!     Default = deterministic RNG address (local-test path uses `vm.prank`).
//!   - WD_RECIPIENT=0x<20 bytes>  — pin the withdrawal recipient (e.g. the close manager). Default
//!     = deterministic RNG address.
//!   - WD_OUT_PREFIX=close_       — filename prefix so a variant set does not overwrite the
//!     default.
//!
//! SECURITY: every exported value is pulled programmatically from the proved objects; the on-chain
//! block-hash recomputation, channel_reg keccak chain, and withdrawal keccak chain validate them.
//! `build_channel_withdrawal` performs a Rust-side re-fold sanity check before returning.

use std::{fs, path::Path};

use intmax3_zkp::{
    circuits::channel::close_circuit::CLOSE_FIXTURE_NATIVE_FUND_AMOUNT,
    close_funding::close_funding_aux_data,
    common::{channel::token_funds_digest, channel_id::ChannelId},
    constants::MAX_CHANNEL_TOKENS,
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
    utils::mle_prover::{mle_v2_config_only_requested, persist_or_validate_mle_v2_config_json},
    wallet_core::{
        ChannelWithdrawalParams, build_channel_withdrawal, build_channel_withdrawal_mle_v2_configs,
    },
};

const DEFAULT_DEPOSIT_AMOUNT: u64 = 10;
const DEFAULT_WITHDRAWAL_AMOUNT: u64 = 3;

/// The exact `close_` cohort represents a full native-fund close, so its independently generated
/// payout must equal the amount committed by the close-intent proof. Other fixture families retain
/// the ordinary partial-withdrawal scenario.
fn fixture_amounts(prefix: &str) -> (u64, u64) {
    if prefix == "close_" {
        (
            CLOSE_FIXTURE_NATIVE_FUND_AMOUNT,
            CLOSE_FIXTURE_NATIVE_FUND_AMOUNT,
        )
    } else {
        (DEFAULT_DEPOSIT_AMOUNT, DEFAULT_WITHDRAWAL_AMOUNT)
    }
}

/// The `close_` payout is consumed by `ChannelSettlementManager.pullChannelFunds`, which accepts a
/// withdrawal only if its `aux_data` equals `close_funding_aux_data(chainid, rollup, manager,
/// channel id, close freeze nonce, finalized token-funds digest)` (`CloseFundingAuxMismatch`
/// otherwise). Bind the fixture to the exact local-lifecycle pair printed by
/// `CloseLifecycleE2E.test_printCloseManagerAddress`:
///   - manager  = `WD_RECIPIENT` (the payout recipient is the Manager),
///   - rollup   = `WD_CLOSE_FUNDING_ROLLUP`,
///   - chain id = `WD_CHAIN_ID` (default 31337, the local Forge/Anvil chain),
///   - channel id, close freeze nonce and the token-funds vector from the co-generated
///     `close_intent.json` (the digest recorded there is recomputed here and must agree).
/// Generate the close intent BEFORE this `close_` pass; the close intent itself depends on this
/// family's `close_lifecycle.json` root, so the documented order is close_ -> close -> close_.
fn close_funding_aux_for_fixture(
    out_dir: &Path,
    withdrawal_recipient: Option<Address>,
) -> anyhow::Result<Bytes32> {
    let manager = withdrawal_recipient
        .ok_or_else(|| anyhow::anyhow!("close_ fixtures require WD_RECIPIENT=<Manager address>"))?;
    let rollup_hex = std::env::var("WD_CLOSE_FUNDING_ROLLUP").map_err(|_| {
        anyhow::anyhow!(
            "close_ fixtures require WD_CLOSE_FUNDING_ROLLUP=<Rollup address> \
             (printed as CLOSE_ROLLUP_ADDRESS by test_printCloseManagerAddress)"
        )
    })?;
    let rollup = parse_address_hex(&rollup_hex);
    let chain_id: u64 = match std::env::var("WD_CHAIN_ID") {
        Ok(v) => v.parse()?,
        Err(_) => 31337,
    };
    let intent_path = out_dir.join("close_intent.json");
    let intent: serde_json::Value = serde_json::from_str(&fs::read_to_string(&intent_path)?)?;
    let channel_id = ChannelId::new(
        intent["channel_id"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("close_intent.json: channel_id"))?,
    )
    .map_err(|e| anyhow::anyhow!("close_intent.json: channel_id: {e:?}"))?;
    let close_freeze_nonce = intent["close_freeze_nonce"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("close_intent.json: close_freeze_nonce"))?;
    let token_count = intent["token_count"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("close_intent.json: token_count"))?;
    let registry_json = intent["token_registry"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("close_intent.json: token_registry"))?;
    let amounts_json = intent["channel_fund_amounts"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("close_intent.json: channel_fund_amounts"))?;
    let mut registry = [0u32; MAX_CHANNEL_TOKENS];
    let mut amounts = [U256::zero(); MAX_CHANNEL_TOKENS];
    anyhow::ensure!(
        registry_json.len() == registry.len() && amounts_json.len() == amounts.len(),
        "close_intent.json: token vectors must be exactly {} wide",
        registry.len()
    );
    for (slot, value) in registry_json.iter().enumerate() {
        registry[slot] = u32::try_from(
            value
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("close_intent.json: token_registry[{slot}]"))?,
        )?;
    }
    for (slot, value) in amounts_json.iter().enumerate() {
        let text = value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("close_intent.json: channel_fund_amounts[{slot}]"))?;
        amounts[slot] = text.parse::<U256>().map_err(|e| {
            anyhow::anyhow!("close_intent.json: channel_fund_amounts[{slot}]: {e:?}")
        })?;
    }
    let funds_digest = token_funds_digest(&registry, u8::try_from(token_count)?, &amounts);
    let recorded = intent["token_funds_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("close_intent.json: token_funds_digest"))?;
    anyhow::ensure!(
        Bytes32::from_hex(recorded).map_err(|e| anyhow::anyhow!("{e:?}"))? == funds_digest,
        "close_intent.json token_funds_digest {recorded} != recomputed {funds_digest}"
    );
    let aux = close_funding_aux_data(
        chain_id,
        rollup,
        manager,
        channel_id,
        close_freeze_nonce,
        funds_digest,
    );
    eprintln!(
        "[wd] close_ funding aux = {aux} (chain {chain_id}, rollup {rollup}, manager {manager}, \
         channel {}, freeze nonce {close_freeze_nonce}, funds digest {funds_digest})",
        u64::from(channel_id)
    );
    Ok(aux)
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

fn main() -> anyhow::Result<()> {
    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;
    let prefix = std::env::var("WD_OUT_PREFIX").unwrap_or_default();
    let name = |base: &str| format!("{prefix}{base}");

    if mle_v2_config_only_requested() {
        let configs = build_channel_withdrawal_mle_v2_configs()?;
        persist_or_validate_mle_v2_config_json(
            out_dir.join(name("withdrawal_mle_config.json")),
            &configs.withdrawal_mle_config_json,
        )?;
        persist_or_validate_mle_v2_config_json(
            out_dir.join(name("lifecycle_validity_mle_config.json")),
            &configs.validity_mle_config_json,
        )?;
        eprintln!(
            "[wd] config-only mode: wrote {} and {}; no witness or proof was constructed",
            name("withdrawal_mle_config.json"),
            name("lifecycle_validity_mle_config.json")
        );
        return Ok(());
    }

    eprintln!("[wd] building channel withdrawal artifacts (HEAVY proving)…");
    let (deposit_amount, withdrawal_amount) = fixture_amounts(&prefix);
    eprintln!(
        "[wd] fixture amounts for prefix {:?}: deposit={}, withdrawal={}",
        prefix, deposit_amount, withdrawal_amount
    );
    let withdrawal_recipient = std::env::var("WD_RECIPIENT")
        .ok()
        .map(|h| parse_address_hex(&h));
    let burn_aux_data = if prefix == "close_" {
        Some(close_funding_aux_for_fixture(
            out_dir,
            withdrawal_recipient,
        )?)
    } else {
        None
    };
    let params = ChannelWithdrawalParams {
        channel_id: 1,
        deposit_amount,
        withdrawal_amount,
        depositor: std::env::var("WD_DEPOSITOR")
            .ok()
            .map(|h| parse_address_hex(&h)),
        withdrawal_recipient,
        deposit_salt: None,
        erc20_lane: None,
        burn_aux_data,
    };
    if let Some(d) = params.depositor {
        eprintln!("[wd] depositor = {}", d.to_string());
    }
    if let Some(r) = params.withdrawal_recipient {
        eprintln!("[wd] withdrawal recipient (L1) = {}", r.to_string());
    }

    let artifacts = build_channel_withdrawal(&params, None)?;

    persist_or_validate_mle_v2_config_json(
        out_dir.join(name("withdrawal_mle_config.json")),
        &artifacts.withdrawal_mle_config_json,
    )?;
    persist_or_validate_mle_v2_config_json(
        out_dir.join(name("lifecycle_validity_mle_config.json")),
        &artifacts.validity_mle_config_json,
    )?;

    fs::write(
        out_dir.join(name("withdrawal_mle.json")),
        &artifacts.withdrawal_mle_json,
    )?;
    fs::write(
        out_dir.join(name("lifecycle_validity_mle.json")),
        &artifacts.validity_mle_json,
    )?;
    fs::write(
        out_dir.join(name("lifecycle.json")),
        &artifacts.lifecycle_json,
    )?;
    fs::write(
        out_dir.join(name("withdrawal_payout.json")),
        &artifacts.payout_json,
    )?;

    for f in [
        "withdrawal_mle_config.json",
        "lifecycle_validity_mle_config.json",
        "withdrawal_mle.json",
        "lifecycle_validity_mle.json",
        "lifecycle.json",
        "withdrawal_payout.json",
    ] {
        eprintln!("[wd] wrote contracts/test/data/{}", name(f));
    }
    eprintln!("[wd] Done!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_close_prefix_selects_full_native_fund_payout() {
        assert_eq!(
            fixture_amounts("close_"),
            (
                CLOSE_FIXTURE_NATIVE_FUND_AMOUNT,
                CLOSE_FIXTURE_NATIVE_FUND_AMOUNT
            )
        );
        for prefix in ["", "sepolia_", "c2c_", "close", "close_extra_"] {
            assert_eq!(
                fixture_amounts(prefix),
                (DEFAULT_DEPOSIT_AMOUNT, DEFAULT_WITHDRAWAL_AMOUNT),
                "unexpected close amount selection for prefix {prefix:?}"
            );
        }
    }
}
