//! detail2 §F-1 deposit-backing gate, end-to-end against a REAL deposit-backed balance proof.
//!
//! Proves the user-mandated fail-closed invariant: a co-signer accepts a channel state ONLY when
//! the channel's intmax NATIVE balance is attested by a real `balanceProof` whose `channel_id` and
//! `settled_tx_chain` reconcile with the signed `BalanceState` (detail2 §F-1 / §3.1). Every way the
//! backing can be absent, foreign, stale, or forged is rejected.
//!
//! This is the genuine base/native ↔ channel connection: the channel's own base-layer balance proof
//! is the backing, and it is funded by a REAL ON-CHAIN ETH deposit — this test spins up anvil,
//! deploys IntmaxRollup, deposits real ETH to the channel recipient, reads the deposit back, and
//! asserts the Rust witness reproduces the on-chain depositHashChain (no fabrication). Skips if
//! foundry (anvil/forge/cast) is absent.
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    circuits::{
        balance::{
            balance_processor::BalanceProcessor,
            common::recipient::calculate_recipient_from_user_id, spend_circuit::SpendCircuit,
        },
        test_utils::{
            balance_witness_generator::{BalanceWitnessGenerator, ReceiveDepositData},
            block_witness_generator::{BlockWitnessGenerator, BlockWitnessGeneratorHandle},
        },
    },
    common::{channel_id::ChannelId, deposit::Deposit, salt::Salt},
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
    regev::encrypt_amount,
    wallet_core::{
        ChannelBalanceAttestation, MemberInfo, MemberKeys, add_signature, assemble_genesis_state,
        assemble_genesis_state_backed, build_record, sign_state, sign_state_if_backed,
        verify_all_signatures, verify_channel_backing,
    },
};
use plonky2::{
    field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

const CHANNEL: u32 = 1; // base-layer user id == channel id (detail2 §A-2)
// anvil dev account[0] (public throwaway key; NEVER a real key).
const ANVIL0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

fn info(slot: u8, k: &MemberKeys) -> MemberInfo {
    MemberInfo { slot, pk_g: k.pk_g(), pk_b: k.pk_b(), regev_pk: k.regev_pk.clone() }
}

struct AnvilGuard(Child);
impl Drop for AnvilGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn tool_present(bin: &str) -> bool {
    Command::new(bin).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status()
        .map(|s| s.success()).unwrap_or(false)
}
fn run_capture(cmd: &mut Command, label: &str) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("{label} failed to start: {e}"));
    assert!(out.status.success(), "{label} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).to_string()
}
fn cast(rpc: &str, args: &[&str], label: &str) -> String {
    run_capture(Command::new("cast").args(args).arg("--rpc-url").arg(rpc), label)
}
fn abi_word(data: &str, i: usize) -> &str {
    &data[i * 64..(i + 1) * 64]
}

#[test]
fn deposit_backing_gate_reconciles_and_fails_closed() {
    // ---- 1. Fund the channel with a REAL ON-CHAIN ETH deposit → real base-layer balance proof ----
    if !(tool_present("anvil") && tool_present("forge") && tool_present("cast")) {
        eprintln!("[skip] foundry (anvil/forge/cast) not found — this test needs a real on-chain deposit");
        return;
    }
    use rand::{SeedableRng as _, rngs::StdRng as RandStdRng};

    // Bring up a dedicated anvil + deploy IntmaxRollup.
    const PORT: u16 = 8550;
    let rpc = format!("http://127.0.0.1:{PORT}");
    let anvil = Command::new("anvil")
        .args(["--hardfork", "prague", "--port", &PORT.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn anvil");
    let _guard = AnvilGuard(anvil);
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
    let contracts = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts");
    let deploy_out = run_capture(
        Command::new("forge").current_dir(&contracts).args([
            "script", "script/Deploy.s.sol", "--rpc-url", &rpc, "--private-key", ANVIL0, "--broadcast",
        ]),
        "forge deploy",
    );
    let rollup = deploy_out
        .lines()
        .find_map(|l| l.split("IntmaxRollup").nth(1).and_then(|s| s.split("0x").nth(1)))
        .map(|s| format!("0x{}", &s.trim()[..40]))
        .expect("parse IntmaxRollup address");

    let supported_user_counts = vec![1, 4, 512];
    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
    let block_witness_generator =
        BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

    let mut brng = RandStdRng::seed_from_u64(42);
    let channel_id = ChannelId::new(CHANNEL as u64).unwrap();
    let salt = Salt::rand(&mut brng);
    let mut bwg =
        BalanceWitnessGenerator::new(channel_id, salt, block_witness_generator.clone(), &balance_processor)
            .unwrap();

    let deposit_salt = Salt::rand(&mut brng);
    let recipient = calculate_recipient_from_user_id(channel_id, deposit_salt);

    // REAL ETH deposit to the channel's recipient, then read it back from the live receipt.
    const AMOUNT: u64 = 50;
    let send_json = run_capture(
        Command::new("cast").args([
            "send", &rollup, "deposit(bytes32,uint32,uint256,bytes32)", &recipient.to_hex(), "0",
            &AMOUNT.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--value", &AMOUNT.to_string(), "--private-key", ANVIL0, "--rpc-url", &rpc, "--json",
        ]),
        "cast deposit",
    );
    let txhash = send_json
        .split("\"transactionHash\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("tx hash");
    let receipt = cast(&rpc, &["receipt", txhash, "--json"], "receipt");
    let data = receipt
        .split("\"data\":\"0x")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("Deposited log data");
    let depositor = Address::from_hex(&format!("0x{}", &abi_word(data, 0)[24..])).unwrap();
    let onchain_chain = Bytes32::from_hex(&format!("0x{}", abi_word(data, 5))).unwrap();

    // KEYSTONE: the Rust deposit reproduces the LIVE on-chain depositHashChain (no simulation gap).
    let onchain_deposit = Deposit {
        deposit_index: Default::default(),
        block_number: Default::default(),
        depositor,
        recipient,
        token_index: 0,
        amount: U256::from(AMOUNT as u32),
        aux_data: Bytes32::default(),
    };
    assert_eq!(
        onchain_deposit.hash_with_prev_hash(Bytes32::default()),
        onchain_chain,
        "Rust deposit hash must reproduce the on-chain depositHashChain"
    );

    // Feed the REAL on-chain deposit fields into the witness generator → real-deposit-backed proof.
    block_witness_generator
        .borrow_mut()
        .add_deposit(depositor, recipient, 0, U256::from(AMOUNT as u32), Bytes32::default())
        .unwrap();
    block_witness_generator.borrow_mut().add_block(0, &[], 0, Bytes32::default()).unwrap();

    let deposit_data = ReceiveDepositData { receiver: recipient, deposit_salt };
    let dep_witness = bwg.receive_deposit_witness(&deposit_data).unwrap();
    let balance_proof = balance_processor.prove_receive_deposit(&dep_witness).unwrap();
    bwg.commit_receive_deposit(&balance_proof, &dep_witness).unwrap();

    let balance_vd = balance_processor.balance_vd();
    let backing_chain = bwg.get_public_inputs().unwrap().settled_tx_chain;
    let proof_bytes = balance_proof.to_bytes();
    let attestation = ChannelBalanceAttestation { balance_proof: proof_bytes.clone() };

    // ---- 2. Build a Regev channel (channel_id == 1) whose BalanceState carries that chain -------
    use rand010::{SeedableRng as _, rngs::StdRng as ChRng};
    let mut crng = ChRng::seed_from_u64(0xC0FFEE);
    let mkeys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut crng)).collect();
    let members: Vec<MemberInfo> = mkeys.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect();
    let record = build_record(CHANNEL, &members, 0, 0).expect("record");
    let cts: Vec<_> = mkeys
        .iter()
        .map(|k| encrypt_amount(&mut crng, &k.regev_pk, 0).unwrap().0)
        .collect();
    // BACKED genesis: its BalanceState absorbs the SAME settle history the balance proof folded
    // in (§F-1), so it reconciles with the attestation.
    let state =
        assemble_genesis_state_backed(&record, &cts, 50, backing_chain, Bytes32::default())
            .expect("backed genesis");

    // ---- 3. POSITIVE: genuine deposit backing → the gate accepts (co-sign allowed) -------------
    verify_channel_backing(&record, &state, Some(&attestation), &balance_vd)
        .expect("genuine deposit-backed channel must reconcile and be co-signable");

    // ---- 4. FAIL-CLOSED adversarial cases (each MUST refuse to sign) ---------------------------

    // (a) No attestation at all → unbacked channel → refuse.
    assert!(
        verify_channel_backing(&record, &state, None, &balance_vd).is_err(),
        "an UNBACKED channel (no attestation) must be refused"
    );

    // (b) Backing proof is for a DIFFERENT channel → refuse.
    let foreign_members: Vec<MemberInfo> =
        mkeys.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect();
    let foreign_record = build_record(CHANNEL + 1, &foreign_members, 0, 0).expect("foreign record");
    assert!(
        verify_channel_backing(&foreign_record, &state, Some(&attestation), &balance_vd).is_err(),
        "a balance proof for another channel_id must be refused"
    );

    // (c) settled_tx_chain mismatch (stale / wrong settle history) → refuse (§F-1 seam).
    let mut stale = state.clone();
    stale.balance_state.settled_tx_chain = Bytes32::default();
    assert!(
        verify_channel_backing(&record, &stale, Some(&attestation), &balance_vd).is_err(),
        "a BalanceState whose settled_tx_chain != balanceProof.settled_tx_chain must be refused"
    );

    // (d) Tampered proof bytes → deserialization/verification fails → refuse.
    let mut bad_bytes = proof_bytes.clone();
    let last = bad_bytes.len() - 1;
    bad_bytes[last] ^= 0xFF;
    let bad_att = ChannelBalanceAttestation { balance_proof: bad_bytes };
    assert!(
        verify_channel_backing(&record, &state, Some(&bad_att), &balance_vd).is_err(),
        "a tampered/forged backing proof must be refused"
    );

    // ---- 5. FULL PATH: gated co-sign. Each member checks backing BEFORE signing (the live rule) --
    // Backed genesis: gate passes → all 3 members sign → fully signed.
    let mut signed = state.clone();
    for (slot, k) in mkeys.iter().enumerate() {
        verify_channel_backing(&record, &signed, Some(&attestation), &balance_vd)
            .expect("co-signer verifies deposit backing before signing");
        let sig = sign_state(k, slot as u8, &signed).expect("sign");
        add_signature(&mut signed, sig);
    }
    verify_all_signatures(&record, &members, &signed)
        .expect("a genuinely deposit-backed genesis becomes fully member-signed");

    // ---- 6. FAIL-CLOSED at the live gate: an UNBACKED genesis is never signed -------------------
    // Same channel, but assembled WITHOUT deposit backing (settled_tx_chain = 0 ≠ balanceProof's).
    let unbacked = assemble_genesis_state(&record, &cts, 50).expect("unbacked genesis");
    assert!(
        verify_channel_backing(&record, &unbacked, Some(&attestation), &balance_vd).is_err(),
        "an UNBACKED genesis must fail the gate, so no honest member co-signs it"
    );

    // ---- 7. ATOMIC check-and-sign (detail2 §3.1): sign_state_if_backed signs ONLY when the state's
    // settled_tx_chain matches the held intmax balance backing, and never otherwise. ----------------
    assert!(
        sign_state_if_backed(&mkeys[0], 0, &record, &state, &attestation, &balance_vd).is_ok(),
        "check-and-sign must produce a signature for a backed state"
    );
    assert!(
        sign_state_if_backed(&mkeys[0], 0, &record, &unbacked, &attestation, &balance_vd).is_err(),
        "check-and-sign must REFUSE (no signature) when settled_tx_chain does not match the backing"
    );
}
