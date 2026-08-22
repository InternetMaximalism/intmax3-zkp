//! Generate on-chain test fixtures for a REAL partial-withdrawal (BURN) payout — the repo's first
//! payout artifact whose withdrawal leaf carries `aux_data != 0`.
//!
//! WHY THIS EXISTS (doc/tasks/partial-withdrawal-payout-design.md P3 HEAVY note / P4-3): every other
//! committed payout fixture (`withdrawal_payout.json`, `close_withdrawal_payout.json`,
//! `c2c_withdrawal_payout.json`, `sepolia_withdrawal_payout.json`) is a NORMAL withdrawal
//! (`aux_data == 0`). So `contracts/test/PartialWithdrawalPayout.t.sol` could only ever assert that
//! the burn branch fails on the proof binding (`test_burnLeafWithoutAuthorization_failsClosed`) —
//! it could never drive a REAL proved burn leaf THROUGH the proof binding and INTO the IMPW
//! authorization gate. This fixture closes that gap: it is a real 3-block lifecycle whose
//! withdrawal leaf is proved with a nonzero burn descriptor, so `withdrawNative` verifies the proof
//! and then reaches `if (w.auxData != 0) require(partialWithdrawalAuthorized[...])`.
//!
//! Same rail as `generate_withdrawal_fixture` (the shared `build_channel_withdrawal`), so the
//! validity/withdrawal proofs, block-hash chain and keccak re-fold are validated identically; only
//! `burn_aux_data` differs. Writes the `burn_` prefixed 4-artifact set under contracts/test/data/.
//!
//! Usage:  cargo run --bin generate_burn_withdrawal_fixture --release

use std::{fs, path::Path};

use intmax3_zkp::{
    common::channel::burn_descriptor,
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
    wallet_core::{ChannelWithdrawalParams, build_channel_withdrawal},
};

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
    eprintln!("[burn-wd] building BURN channel-withdrawal artifacts (HEAVY proving)…");

    let channel_id: u32 = 1;
    let withdrawal_amount: u64 = 3;
    let withdrawal_recipient = std::env::var("WD_RECIPIENT")
        .ok()
        .map(|h| parse_address_hex(&h))
        // A fixed, non-anvil L1 recipient so the fixture is self-describing and stable across runs.
        .unwrap_or_else(|| Address::from_u32_slice(&[0x00, 0x00, 0x00, 0x00, 0x0B0E_0000]).unwrap());

    // A real IMBD-shaped burn descriptor. On the payout side `withdrawNative` never re-derives it
    // (that binding is the Manager's job at submit time — Phase 0/2), so its exact preimage does not
    // affect what this fixture proves; we still compute a genuine `burn_descriptor(...)` value
    // rather than an arbitrary constant so the leaf reads as a faithful burn. The tx_leaf and
    // recipient limbs here are documentation stand-ins for the inter-channel burn structure a live
    // burn would carry.
    let burn_aux = burn_descriptor(
        Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0xB0E0]).unwrap(),
        Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0xB0E1]).unwrap(),
        0,
        U256::from(withdrawal_amount as u32),
    );
    assert_ne!(burn_aux, Bytes32::default(), "burn descriptor must be nonzero");

    let params = ChannelWithdrawalParams {
        channel_id,
        deposit_amount: 10,
        withdrawal_amount,
        depositor: std::env::var("WD_DEPOSITOR")
            .ok()
            .map(|h| parse_address_hex(&h)),
        withdrawal_recipient: Some(withdrawal_recipient),
        deposit_salt: None,
        erc20_lane: None,
        burn_aux_data: Some(burn_aux),
    };
    eprintln!(
        "[burn-wd] recipient (L1) = {}  aux_data = {}",
        withdrawal_recipient.to_string(),
        burn_aux.to_string()
    );

    let artifacts = build_channel_withdrawal(&params, None)?;

    // Falsifiable self-check: the emitted payout leaf really is a burn (aux != 0). A regression that
    // dropped the aux stamp would produce a normal leaf and silently defeat the whole fixture.
    {
        let payout: serde_json::Value = serde_json::from_str(&artifacts.payout_json)?;
        let aux = payout["withdrawals"][0]["aux_data"]
            .as_str()
            .expect("payout aux_data");
        anyhow::ensure!(
            aux == burn_aux.to_string(),
            "emitted payout aux_data {aux} != requested burn descriptor {}",
            burn_aux.to_string()
        );
        anyhow::ensure!(
            aux != Bytes32::default().to_string(),
            "burn fixture leaf must carry aux_data != 0"
        );
    }

    let out_dir = Path::new("contracts/test/data");
    fs::create_dir_all(out_dir)?;
    let prefix = std::env::var("WD_OUT_PREFIX").unwrap_or_else(|_| "burn_".to_string());
    let name = |base: &str| format!("{prefix}{base}");

    fs::write(
        out_dir.join(name("withdrawal_mle.json")),
        &artifacts.withdrawal_mle_json,
    )?;
    fs::write(
        out_dir.join(name("lifecycle_validity_mle.json")),
        &artifacts.validity_mle_json,
    )?;
    fs::write(out_dir.join(name("lifecycle.json")), &artifacts.lifecycle_json)?;
    fs::write(out_dir.join(name("withdrawal_payout.json")), &artifacts.payout_json)?;

    for f in [
        "withdrawal_mle.json",
        "lifecycle_validity_mle.json",
        "lifecycle.json",
        "withdrawal_payout.json",
    ] {
        eprintln!("[burn-wd] wrote contracts/test/data/{}", name(f));
    }
    eprintln!("[burn-wd] Done!");
    Ok(())
}
