//! GAP2 partial withdrawal anvil E2E: Rust wallet `build_burn_send` → on-chain
//! `submitPartialWithdrawalIntent` → `finalizePartialWithdrawal` → `withdrawNative` authorization.
//!
//! Cross-boundary parity: the test's primary value is verifying that Rust-computed
//! `settled_tx_chain_push`, `partial_withdrawal_auth_digest`, and `build_burn_send` outputs feed
//! correctly into the deployed Solidity contracts (same hash chains, same authDigest, same encoding).
//!
//! Skips gracefully if foundry (anvil/forge/cast) is not installed.
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
    common::{
        balance_state::{settled_tx_chain_push, tx_leaf_hash},
        channel::ChannelState,
        channel_id::ChannelId,
        deposit::Deposit,
        salt::Salt,
        withdrawal::Withdrawal,
    },
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256,
    },
    regev::{RegevCiphertext, RegevPk, RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        ChannelBalanceAttestation, MemberInfo, MemberKeys, add_signature,
        assemble_genesis_state_backed, build_burn_send, build_record,
        partial_withdrawal_auth_digest, sign_state, sign_state_if_backed, verify_all_signatures,
        verify_channel_backing,
    },
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{circuit_data::VerifierCircuitData, config::PoseidonGoldilocksConfig},
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
const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;
const ANVIL0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PORT: u16 = 8553;

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
    let out = cmd.output().unwrap_or_else(|e| panic!("{label}: {e}"));
    assert!(
        out.status.success(),
        "{label} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}
fn cast(rpc: &str, args: &[&str], label: &str) -> String {
    run_capture(
        Command::new("cast").args(args).arg("--rpc-url").arg(rpc),
        label,
    )
}
fn abi_word(data: &str, i: usize) -> &str {
    &data[i * 64..(i + 1) * 64]
}
fn info(slot: u8, k: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot,
        pk_g: k.pk_g(),
        pk_b: k.pk_b(),
        regev_pk: k.regev_pk.clone(),
    }
}
fn pks_array(keys: &[MemberKeys]) -> [RegevPk; intmax3_zkp::constants::MAX_CHANNEL_MEMBERS] {
    let mut arr: [RegevPk; intmax3_zkp::constants::MAX_CHANNEL_MEMBERS] =
        std::array::from_fn(|_| RegevPk::padding());
    for (i, k) in keys.iter().enumerate() {
        arr[i] = k.regev_pk.clone();
    }
    arr
}
fn u256(v: u64) -> U256 {
    U256::from_u32_slice(&[0, 0, 0, 0, 0, 0, (v >> 32) as u32, v as u32]).unwrap()
}
fn find_addr(out: &str, label: &str) -> String {
    out.lines()
        .find(|l| l.contains(label))
        .and_then(|l| l.split("0x").nth(1))
        .map(|s| format!("0x{}", &s.trim()[..40]))
        .unwrap_or_else(|| panic!("could not parse {label} from deploy output:\n{out}"))
}

fn real_onchain_deposit(
    rpc: &str,
    rollup: &str,
    recipient: Bytes32,
    amount: u64,
    prev_chain: Bytes32,
) -> Address {
    let send = run_capture(
        Command::new("cast").args([
            "send",
            rollup,
            "deposit(bytes32,uint32,uint256,bytes32)",
            &recipient.to_hex(),
            "0",
            &amount.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--value",
            &amount.to_string(),
            "--private-key",
            ANVIL0,
            "--rpc-url",
            rpc,
            "--json",
        ]),
        "cast deposit",
    );
    let txhash = send
        .split("\"transactionHash\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("tx");
    let receipt = cast(rpc, &["receipt", txhash, "--json"], "receipt");
    let data = receipt
        .split("\"data\":\"0x")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("log");
    let depositor = Address::from_hex(&format!("0x{}", &abi_word(data, 0)[24..])).unwrap();
    let onchain = Bytes32::from_hex(&format!("0x{}", abi_word(data, 5))).unwrap();
    let d = Deposit {
        deposit_index: Default::default(),
        block_number: Default::default(),
        depositor,
        recipient,
        token_index: 0,
        amount: U256::from(amount as u32),
        aux_data: Bytes32::default(),
    };
    assert_eq!(
        d.hash_with_prev_hash(prev_chain),
        onchain,
        "Rust deposit hash != on-chain chain"
    );
    depositor
}

#[allow(clippy::too_many_arguments)]
fn build_signed_genesis(
    record: &intmax3_zkp::common::channel::ChannelRecord,
    keys: &[MemberKeys],
    cts: &[RegevCiphertext],
    fund: u64,
    settled_tx_chain: Bytes32,
    att: &ChannelBalanceAttestation,
    balance_vd: &VerifierCircuitData<F, C, D>,
) -> ChannelState {
    let regev_pk_digests: Vec<Bytes32> = keys
        .iter()
        .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
        .collect();
    let mut state = assemble_genesis_state_backed(
        record,
        cts,
        &regev_pk_digests,
        fund,
        settled_tx_chain,
        Bytes32::default(),
    )
    .unwrap();
    for (slot, k) in keys.iter().enumerate() {
        let sig = sign_state_if_backed(k, slot as u8, record, &state, att, balance_vd)
            .expect("genesis check-and-sign");
        add_signature(&mut state, sig);
    }
    let members: Vec<MemberInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| info(i as u8, k))
        .collect();
    verify_all_signatures(record, &members, &state).expect("genesis fully signed");
    state
}

fn sign_real(state: &mut ChannelState, keys: &[MemberKeys]) {
    for (slot, k) in keys.iter().enumerate() {
        let sig = sign_state(k, slot as u8, state).expect("real member signature");
        add_signature(state, sig);
    }
}

#[test]
fn partial_withdrawal_e2e_anvil() {
    if !(tool_present("anvil") && tool_present("forge") && tool_present("cast")) {
        eprintln!("[skip] foundry not found — partial withdrawal E2E needs anvil/forge/cast");
        return;
    }

    use intmax3_zkp::wallet_core::ChannelSnapshot;
    use rand::SeedableRng as _;
    use rand010::SeedableRng as _;

    let rpc = format!("http://127.0.0.1:{PORT}");
    let anvil = Command::new("anvil")
        .args([
            "--hardfork", "prague",
            "--port", &PORT.to_string(),
            "--code-size-limit", "50000",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("anvil");
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
    assert!(up, "anvil down");

    // ── Phase A: Setup prover + keys ──────────────────────────────────────────────────────────
    let spend = SpendCircuit::<F, C, D>::new();
    let bp = BalanceProcessor::<F, C, D>::new(&spend.data.verifier_data());
    let bwgen = BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&[1, 4, 512]));
    let balance_vd = bp.balance_vd();

    let mut crng = rand010::rngs::StdRng::seed_from_u64(0xA553);
    let chan_id = ChannelId::new(42).unwrap();
    let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut crng)).collect();
    let members: Vec<MemberInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| info(i as u8, k))
        .collect();
    let record = build_record(42, &members, 0, 0).expect("channel record");
    let all_pks = pks_array(&keys);

    // ── Phase B: Write pw_reg.json + deploy ──────────────────────────────────────────────────
    let contracts = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts");
    let data_dir = contracts.join("test").join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    {
        let pk_gs: Vec<String> = keys.iter().map(|k| k.pk_g().to_hex()).collect();
        let pk_bs: Vec<String> = keys.iter().map(|k| k.pk_b().to_hex()).collect();
        let regev_digests: Vec<String> = keys
            .iter()
            .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()).to_hex())
            .collect();
        // Use anvil default addresses as recipients.
        let recipients = vec![
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
            "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
        ];
        let reg = serde_json::json!({
            "channel_id": 42,
            "bp_member_slot": 0,
            "member_count": 3,
            "delegate_count": 0,
            "member_pk_gs": pk_gs,
            "member_pk_bs": pk_bs,
            "regev_pk_digests": regev_digests,
            "recipients": recipients,
        });
        std::fs::write(data_dir.join("pw_reg.json"), serde_json::to_string_pretty(&reg).unwrap())
            .unwrap();
    }

    let deploy = run_capture(
        Command::new("forge").current_dir(&contracts).args([
            "script",
            "script/DeployPartialWithdrawalE2E.s.sol",
            "--tc",
            "DeployPartialWithdrawalE2E",
            "--rpc-url",
            &rpc,
            "--private-key",
            ANVIL0,
            "--broadcast",
            "--code-size-limit",
            "50000",
        ]),
        "forge deploy PW E2E",
    );
    let rollup = find_addr(&deploy, "IntmaxRollup:");
    let manager = find_addr(&deploy, "MANAGER:");
    let verifier_addr = find_addr(&deploy, "SettlementVerifier:");
    eprintln!("[PW E2E] rollup={rollup} manager={manager} verifier={verifier_addr}");

    // ── Phase C: Real ETH deposit + deposit-backed genesis ──────────────────────────────────
    let balances = [50u64, 10, 30];
    let fund: u64 = balances.iter().sum(); // 90

    let mut brng = rand::rngs::StdRng::seed_from_u64(0xDE_AD_BE_EF);
    let salt = Salt::rand(&mut brng);
    let recipient = calculate_recipient_from_user_id(chan_id, salt);
    let depositor = real_onchain_deposit(&rpc, &rollup, recipient, fund, Bytes32::default());

    bwgen
        .borrow_mut()
        .add_deposit(
            depositor,
            recipient,
            0,
            U256::from(fund as u32),
            Bytes32::default(),
        )
        .unwrap();
    bwgen
        .borrow_mut()
        .add_block(0, &[], 0, Bytes32::default())
        .unwrap();
    let mut bwg =
        BalanceWitnessGenerator::new(chan_id, Salt::rand(&mut brng), bwgen.clone(), &bp).unwrap();
    let dw = bwg
        .receive_deposit_witness(&ReceiveDepositData {
            receiver: recipient,
            deposit_salt: salt,
        })
        .unwrap();
    let proof = bp.prove_receive_deposit(&dw).unwrap();
    bwg.commit_receive_deposit(&proof, &dw).unwrap();
    let chain = bwg.get_public_inputs().unwrap().settled_tx_chain;
    let att = ChannelBalanceAttestation {
        balance_proof: proof.to_bytes(),
    };

    // Build genesis ciphertexts, retaining alice's witness (slot 0).
    let (ct0, w0) = encrypt_amount(&mut crng, &all_pks[0], balances[0]).unwrap();
    let ct1 = encrypt_amount(&mut crng, &all_pks[1], balances[1]).unwrap().0;
    let ct2 = encrypt_amount(&mut crng, &all_pks[2], balances[2]).unwrap().0;
    let cts = [ct0.clone(), ct1, ct2];

    let genesis = build_signed_genesis(&record, &keys, &cts, fund, chain, &att, &balance_vd);
    verify_channel_backing(&record, &genesis, Some(&att), &balance_vd).expect("§F-1 backing OK");
    let genesis_chain = genesis.balance_state.settled_tx_chain;
    eprintln!("[PW E2E] genesis OK, fund={fund}, chain={}", genesis_chain.to_hex());

    // ── Phase D: build_burn_send (alice burns 5 ETH) ────────────────────────────────────────
    let burn_amount = 5u64;
    let withdrawal_addr = Address::from_hex("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();
    let nullifier_root =
        Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0xBE01]).unwrap();

    let snapshot = ChannelSnapshot {
        record: record.clone(),
        state: genesis.clone(),
        members: members.clone(),
        settled_tx_accumulator: intmax3_zkp::wallet_core::default_settled_tx_accumulator(),
    };

    let built = build_burn_send(
        &keys[0],
        &snapshot,
        0, // sender_slot
        withdrawal_addr,
        burn_amount,
        balances[0], // before_amount
        &w0,
        nullifier_root,
        LEVEL,
        &mut crng,
    )
    .expect("build_burn_send");

    // Co-sign the post-burn state.
    let mut next_state = built.debit_payload.proposed_next_state.clone();
    sign_real(&mut next_state, &keys);
    verify_all_signatures(&record, &members, &next_state).expect("post-burn co-signed");

    // Verify fund decreased.
    let post_fund = {
        let a = next_state.channel_fund.amount;
        let limbs = a.to_u32_vec();
        limbs[7] as u64 | ((limbs[6] as u64) << 32)
    };
    assert_eq!(post_fund, fund - burn_amount, "channel fund must decrease by burn amount");
    eprintln!("[PW E2E] build_burn_send OK, post_fund={post_fund}");

    // Compute tx_leaf (the burn's settled_tx_chain leaf) = aux_data for the on-chain binding.
    let desc = &built.transfer_descriptor;
    let tx_leaf = tx_leaf_hash(
        desc.source_pk_g,
        desc.sender_delta_ct.digest(),
        desc.receiver_pk_g,
        desc.receiver_delta.digest(),
    );
    let expected_chain = settled_tx_chain_push(genesis_chain, tx_leaf);
    assert_eq!(
        next_state.balance_state.settled_tx_chain, expected_chain,
        "channel chain must be push(genesis, tx_leaf)"
    );
    eprintln!("[PW E2E] settled_tx_chain OK");

    // ── Phase E: Write pw_submit.json + on-chain settlement ─────────────────────────────────
    // Build the Withdrawal struct for authDigest computation.
    let withdrawal = Withdrawal {
        recipient: withdrawal_addr,
        token_index: 0,
        amount: u256(burn_amount),
        nullifier: Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0xBEEF]).unwrap(),
        aux_data: tx_leaf,
    };
    let rust_auth_digest = partial_withdrawal_auth_digest(&withdrawal);
    eprintln!("[PW E2E] Rust authDigest = {}", rust_auth_digest.to_hex());

    {
        let submit = serde_json::json!({
            "manager": manager,
            "verifier": verifier_addr,
            // CloseIntent fields.
            "close_nonce": 1u64,
            "final_epoch": next_state.epoch,
            "final_small_block_number": next_state.small_block_number,
            "close_freeze_nonce": 0u64,
            "final_channel_state_digest": next_state.digest.to_hex(),
            "final_balance_state_h1": next_state.balance_state.h1().to_hex(),
            "channel_fund_amount": post_fund,
            "channel_fund_intmax_state_root": next_state.channel_fund.intmax_state_root.to_hex(),
            "burn_tx_hash": Bytes32::default().to_hex(),
            "close_withdrawal_digest": Bytes32::default().to_hex(),
            "snapshot_medium_block_number": 0u64,
            "final_state_version": next_state.balance_state.state_version,
            "final_settled_tx_chain": next_state.balance_state.settled_tx_chain.to_hex(),
            "final_settled_tx_acc_root": next_state.balance_state.settled_tx_accumulator_root.to_hex(),
            // prevSettledTxChain (genesis chain before the burn push).
            "prev_settled_tx_chain": genesis_chain.to_hex(),
            // AuthorizedWithdrawal fields.
            "withdrawal_recipient": format!("0x{}", hex::encode(withdrawal_addr.to_bytes_be())),
            "withdrawal_token_index": 0u32,
            "withdrawal_amount": burn_amount,
            "withdrawal_nullifier": withdrawal.nullifier.to_hex(),
            "withdrawal_aux_data": tx_leaf.to_hex(),
        });
        std::fs::write(
            data_dir.join("pw_submit.json"),
            serde_json::to_string_pretty(&submit).unwrap(),
        )
        .unwrap();
    }

    let submit_out = run_capture(
        Command::new("forge").current_dir(&contracts).args([
            "script",
            "script/SubmitPartialWithdrawal.s.sol",
            "--rpc-url",
            &rpc,
            "--private-key",
            ANVIL0,
            "--broadcast",
        ]),
        "forge submit PW intent",
    );
    eprintln!("[PW E2E] submitPartialWithdrawalIntent succeeded");

    // Extract on-chain authDigest from the script's console2.logBytes32 output.
    let onchain_auth = submit_out
        .lines()
        .skip_while(|l| !l.contains("AUTH_DIGEST:"))
        .nth(1)
        .and_then(|l| l.trim().strip_prefix("0x").or_else(|| Some(l.trim())))
        .map(|s| format!("0x{}", s.trim_start_matches("0x")))
        .unwrap_or_else(|| panic!("could not parse AUTH_DIGEST from:\n{submit_out}"));
    let onchain_digest = Bytes32::from_hex(&onchain_auth)
        .unwrap_or_else(|_| panic!("bad hex: {onchain_auth}"));
    assert_eq!(
        rust_auth_digest, onchain_digest,
        "CRITICAL: Rust authDigest != Solidity authDigest — cross-boundary hash mismatch"
    );
    eprintln!("[PW E2E] authDigest PARITY OK: {}", rust_auth_digest.to_hex());

    // ── Phase F: Advance time + finalize ────────────────────────────────────────────────────
    cast(&rpc, &["rpc", "evm_increaseTime", "2"], "increase time");
    cast(&rpc, &["rpc", "evm_mine"], "mine");

    run_capture(
        Command::new("cast").args([
            "send",
            &manager,
            "finalizePartialWithdrawal()",
            "--private-key",
            ANVIL0,
            "--rpc-url",
            &rpc,
        ]),
        "finalize partial withdrawal",
    );

    // Check on-chain authorization.
    let auth_check = cast(
        &rpc,
        &[
            "call",
            &rollup,
            "partialWithdrawalAuthorized(bytes32)",
            &rust_auth_digest.to_hex(),
        ],
        "check auth",
    );
    let auth_result = auth_check.trim();
    assert!(
        auth_result.contains("true") || auth_result.ends_with("01"),
        "partialWithdrawalAuthorized must be true, got: {auth_result}"
    );
    eprintln!("[PW E2E] finalize + authorize OK");

    // ── Phase G: Adversarial — double-submit same chain key ─────────────────────────────────
    {
        // Re-submitting with the same finalSettledTxChain must revert with PartialWithdrawalChainUsed.
        let out = Command::new("forge")
            .current_dir(&contracts)
            .args([
                "script",
                "script/SubmitPartialWithdrawal.s.sol",
                "--rpc-url",
                &rpc,
                "--private-key",
                ANVIL0,
                "--broadcast",
            ])
            .output()
            .expect("re-submit spawn");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "re-submit with same chain key MUST fail"
        );
        assert!(
            stderr.contains("PartialWithdrawalChainUsed") || stderr.contains("revert"),
            "expected PartialWithdrawalChainUsed revert, got: {stderr}"
        );
        eprintln!("[PW E2E] adversarial: double-submit correctly rejected");
    }

    eprintln!(
        "[PW E2E] ALL PASSED: deposit → burn → submit → finalize → authorize, \
         authDigest cross-boundary parity verified, double-submit rejected."
    );
}
