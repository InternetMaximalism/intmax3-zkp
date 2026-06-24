//! KEYSTONE: the Rust deposit witness exactly mirrors a REAL on-chain ETH deposit.
//!
//! This pins the values produced by an actual `IntmaxRollup.deposit{value}` call on a local anvil
//! (real ETH escrowed: `totalEscrowed` 0 -> 140) and asserts the Rust
//! `Deposit::hash_with_prev_hash` reproduces the on-chain `Deposited.newDepositHashChain`
//! bit-for-bit. If this holds, a Rust balance proof built from these fields is backed by a deposit
//! that REALLY happened on-chain — not a `BlockWitnessGenerator` fabrication. (The self-driving
//! anvil version lives in the channel deposit-backing flow; this fast test locks the
//! contract<->Rust hash equivalence.)
//!
//! Captured from anvil (Foundry 1.5.1, IntmaxRollup @ 0xCf7E…0Fc9, tx 0x735a…56ad):
//!   deposit(recipient=0x1111…1111, tokenIndex=0, amount=140, aux=0) value=140 wei
//!   Deposited.newDepositHashChain =
//! 0x10e6fb6cab835cddf7de29b5e04d77060ae245ef825d86ab6c07d4ab4518c1cf

use intmax3_zkp::{
    common::deposit::Deposit,
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts")
}

/// Anvil child process that is killed when the guard drops (incl. on panic).
struct AnvilGuard(Child);
impl Drop for AnvilGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn tool_present(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_capture(cmd: &mut Command, label: &str) -> String {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("{label} failed to start: {e}"));
    if !out.status.success() {
        panic!(
            "{label} failed ({:?})\nstdout:\n{}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn cast(rpc: &str, args: &[&str], label: &str) -> String {
    let mut c = Command::new("cast");
    c.args(args).arg("--rpc-url").arg(rpc);
    run_capture(&mut c, label)
}

/// The 32-byte word at index `i` of an ABI-encoded hex data blob (no `0x`).
fn word(data: &str, i: usize) -> &str {
    &data[i * 64..(i + 1) * 64]
}

/// SELF-DRIVING keystone: spin up a fresh anvil, deploy IntmaxRollup, make a REAL ETH deposit, read
/// the `Deposited` event, and assert the Rust `Deposit` hash reproduces the on-chain
/// `depositHashChain` — with NO hardcoded values (everything is read back from the live chain).
#[cfg_attr(debug_assertions, ignore = "run with --release")]
#[test]
fn self_driving_real_anvil_deposit_matches_rust() {
    if !(tool_present("anvil") && tool_present("forge") && tool_present("cast")) {
        eprintln!(
            "[skip] foundry (anvil/forge/cast) not found — skipping on-chain deposit keystone"
        );
        return;
    }
    // anvil dev account[0] (public throwaway key; NEVER a real key).
    const ANVIL0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const PORT: u16 = 8549;
    let rpc = format!("http://127.0.0.1:{PORT}");

    let anvil = Command::new("anvil")
        .args(["--hardfork", "prague", "--port", &PORT.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn anvil");
    let _guard = AnvilGuard(anvil);

    // Wait for the RPC to come up.
    let mut up = false;
    for _ in 0..40 {
        if Command::new("cast")
            .args(["block-number", "--rpc-url", &rpc])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            up = true;
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    assert!(up, "anvil did not come up on {rpc}");

    // Deploy IntmaxRollup (FixtureLib reads contracts/test/data/*.json).
    let deploy_out = run_capture(
        Command::new("forge").current_dir(contracts_dir()).args([
            "script",
            "script/Deploy.s.sol",
            "--rpc-url",
            &rpc,
            "--private-key",
            ANVIL0,
            "--broadcast",
        ]),
        "forge deploy",
    );
    let rollup = deploy_out
        .lines()
        .find_map(|l| {
            l.split("IntmaxRollup")
                .nth(1)
                .and_then(|s| s.split("0x").nth(1))
        })
        .map(|s| format!("0x{}", &s.trim()[..40]))
        .expect("parse IntmaxRollup address from forge output");
    eprintln!("[keystone] IntmaxRollup @ {rollup}");

    // REAL ETH deposit: deposit{value:140}(recipient, ETH_TOKEN_INDEX=0, 140, aux=0).
    const RECIP: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
    const AMOUNT: u64 = 140;
    let esc_before = cast(
        &rpc,
        &["call", &rollup, "totalEscrowed()(uint256)"],
        "escrow before",
    );
    assert_eq!(esc_before.trim(), "0", "escrow must start at 0");

    let tx_json = run_capture(
        Command::new("cast").args([
            "send",
            &rollup,
            "deposit(bytes32,uint32,uint256,bytes32)",
            RECIP,
            "0",
            &AMOUNT.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--value",
            &AMOUNT.to_string(),
            "--private-key",
            ANVIL0,
            "--rpc-url",
            &rpc,
            "--json",
        ]),
        "cast deposit",
    );
    let txhash = tx_json
        .split("\"transactionHash\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("tx hash")
        .to_string();

    // REAL custody: totalEscrowed grew by the deposited ETH.
    let esc_after = cast(
        &rpc,
        &["call", &rollup, "totalEscrowed()(uint256)"],
        "escrow after",
    );
    assert_eq!(
        esc_after.trim(),
        AMOUNT.to_string(),
        "deposited ETH must be escrowed"
    );

    // Read the Deposited event back from the receipt (everything from the live chain).
    let receipt = cast(&rpc, &["receipt", &txhash, "--json"], "receipt");
    let data = receipt
        .split("\"data\":\"0x")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("log data");
    // event Deposited(uint64 indexed depositIndex, address depositor, bytes32 recipient,
    //   uint32 tokenIndex, uint256 amount, bytes32 auxData, bytes32 newDepositHashChain)
    let depositor = format!("0x{}", &word(data, 0)[24..]); // address = low 20 bytes
    let recipient = format!("0x{}", word(data, 1));
    let token_index = u32::from_str_radix(word(data, 2).trim_start_matches('0'), 16).unwrap_or(0);
    let amt_hex = word(data, 3).trim_start_matches('0');
    let amount: u64 = if amt_hex.is_empty() {
        0
    } else {
        u64::from_str_radix(amt_hex, 16).unwrap()
    };
    let aux = format!("0x{}", word(data, 4));
    let onchain_chain = format!("0x{}", word(data, 5));

    assert_eq!(amount, AMOUNT, "event amount");
    assert_eq!(recipient, RECIP, "event recipient");

    // Rebuild the Rust deposit from the LIVE-CHAIN fields and fold the chain — must equal on-chain.
    let d = Deposit {
        deposit_index: Default::default(),
        block_number: Default::default(),
        depositor: Address::from_hex(&depositor).unwrap(),
        recipient: Bytes32::from_hex(&recipient).unwrap(),
        token_index,
        amount: U256::from(amount as u32),
        aux_data: Bytes32::from_hex(&aux).unwrap(),
    };
    let rust_chain = d.hash_with_prev_hash(Bytes32::default());
    assert_eq!(
        rust_chain.to_hex(),
        onchain_chain,
        "Rust deposit_hash_chain must reproduce the LIVE on-chain depositHashChain (no simulation gap)"
    );
    eprintln!(
        "[keystone] OK: real ETH deposit escrowed {AMOUNT}; Rust hash == on-chain {onchain_chain}"
    );
}

#[test]
fn rust_deposit_hash_matches_onchain_eth_deposit() {
    let d = Deposit {
        // Not part of the hash (matches the contract: deposit_index/block_number excluded).
        deposit_index: Default::default(),
        block_number: Default::default(),
        depositor: Address::from_hex("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap(),
        recipient: Bytes32::from_hex(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap(),
        token_index: 0,
        amount: U256::from(140u32),
        aux_data: Bytes32::default(),
    };
    // Rust folds the deposit into the chain exactly as the contract's `_computeDepositHash`
    // (genesis prev = 0). This MUST equal the on-chain `Deposited.newDepositHashChain`.
    let chain = d.hash_with_prev_hash(Bytes32::default());
    assert_eq!(
        chain.to_hex(),
        "0x10e6fb6cab835cddf7de29b5e04d77060ae245ef825d86ab6c07d4ab4518c1cf",
        "Rust deposit_hash_chain must reproduce the REAL on-chain depositHashChain"
    );
}
