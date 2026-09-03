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
    ethereum_types::{address::Address, u32limb_trait::U32LimbTrait},
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
    let params = ChannelWithdrawalParams {
        channel_id: 1,
        deposit_amount,
        withdrawal_amount,
        depositor: std::env::var("WD_DEPOSITOR")
            .ok()
            .map(|h| parse_address_hex(&h)),
        withdrawal_recipient: std::env::var("WD_RECIPIENT")
            .ok()
            .map(|h| parse_address_hex(&h)),
        deposit_salt: None,
        erc20_lane: None,
        burn_aux_data: None,
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
