//! GAP2 partial withdrawal anvil E2E: Rust wallet `build_burn_send` → on-chain
//! `submitPartialWithdrawalIntent` → `finalizePartialWithdrawal` → `withdrawNative` authorization.
//!
//! Cross-boundary parity: the test's primary value is verifying that Rust-computed
//! `settled_tx_chain_push`, `partial_withdrawal_auth_digest`, and `build_burn_send` outputs feed
//! correctly into the deployed Solidity contracts (same hash chains, same authDigest, same
//! encoding).
//!
//! Release-gate execution requires foundry (anvil/forge/cast); missing tooling is a hard failure so
//! CI cannot silently report an unexecuted payout path as passing.
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    circuits::{
        balance::{
            balance_processor::BalanceProcessor,
            common::recipient::calculate_recipient_from_user_id, spend_circuit::SpendCircuit,
        },
        channel::close_pis::{CHANNEL_CLOSE_PUBLIC_INPUTS_LEN, ChannelClosePublicInputs},
        test_utils::{
            balance_witness_generator::{BalanceWitnessGenerator, ReceiveDepositData, SendTxData},
            block_witness_generator::{BlockWitnessGenerator, BlockWitnessGeneratorHandle},
        },
    },
    common::{
        balance_state::{settled_tx_chain_push, tx_leaf_hash},
        channel::{ChannelState, burn_descriptor},
        channel_id::ChannelId,
        deposit::Deposit,
        salt::Salt,
        transfer::Transfer,
        trees::{transfer_tree::TransferTree, tx_tree::TxTree, tx_v2_tree::TxV2Tree},
        tx::{Tx, TxClass, TxV2},
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
    regev::{RegevCiphertext, RegevPk, RegevSecurityLevel, encrypt_amount},
    utils::{conversion::ToU64 as _, mle_prover::validate_mle_v2_full_against_config_json},
    wallet_core::{
        ChannelBalanceAttestation, CloseProver, MemberInfo, MemberKeys, add_signature,
        assemble_genesis_state_backed, build_burn_send, build_record, burn_withdrawal_leaf,
        inter_channel_base_transfer, partial_withdrawal_auth_digest, sign_state,
        sign_state_if_backed, verify_all_signatures, verify_channel_backing,
    },
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{circuit_data::VerifierCircuitData, config::PoseidonGoldilocksConfig},
};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::Instant,
};

mod anvil_harness;
use anvil_harness::AnvilNode;

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;
const ANVIL0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PORT: u16 = 8553;
const PRODUCTION_BLOCK_GAS_LIMIT: u64 = 20_000_000;

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
fn json_hex_quantity(value: &serde_json::Value, label: &str) -> u64 {
    let raw = value
        .as_str()
        .unwrap_or_else(|| panic!("{label} must be a JSON hex string, got {value}"));
    u64::from_str_radix(raw.strip_prefix("0x").unwrap_or(raw), 16)
        .unwrap_or_else(|e| panic!("invalid {label} hex quantity {raw}: {e}"))
}
fn info(slot: u16, k: &MemberKeys) -> MemberInfo {
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
    finalized_state_root: Bytes32,
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
        &test_recipients_b1b(cts.len()),
        fund,
        settled_tx_chain,
        finalized_state_root,
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
        .map(|(i, k)| info(i as u16, k))
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
    assert!(
        tool_present("anvil") && tool_present("forge") && tool_present("cast"),
        "partial-withdrawal release E2E requires anvil, forge, and cast"
    );

    use intmax3_zkp::wallet_core::ChannelSnapshot;
    use rand::SeedableRng as _;
    use rand010::SeedableRng as _;

    let rpc = format!("http://127.0.0.1:{PORT}");
    // Spawns anvil and proves the node answering on PORT is the one we spawned (fresh chain,
    // our own process). See tests/anvil_harness/mod.rs for why a plain `cast block-number` poll
    // is not enough. Killed on drop.
    let block_gas_limit = PRODUCTION_BLOCK_GAS_LIMIT.to_string();
    let _guard = AnvilNode::spawn(
        "partial_withdrawal_e2e_anvil",
        PORT,
        &[
            "--code-size-limit",
            "50000",
            "--gas-limit",
            &block_gas_limit,
        ],
    );

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
        .map(|(i, k)| info(i as u16, k))
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
            // Two INDEPENDENT counts (see `settlement_reg_json` in src/bin/channel_member.rs and
            // contracts/script/RegRecordLib.sol): `reg_delegate_count` is the L1 registration
            // record's — always 0, cosigner-only registration is a circuit constraint;
            // `active_delegate_count` is the live count the settlement manager binds. This driver's
            // channel has no delegates, so both are 0 here — for different reasons.
            "reg_delegate_count": 0,
            "active_delegate_count": 0,
            "member_pk_gs": pk_gs,
            "member_pk_bs": pk_bs,
            "regev_pk_digests": regev_digests,
            "recipients": recipients,
        });
        std::fs::write(
            data_dir.join("pw_reg.json"),
            serde_json::to_string_pretty(&reg).unwrap(),
        )
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
            // Foundry may batch signed transactions even against an automining Anvil. With the
            // large verifier deployment set that can leave a tail of otherwise-valid creations
            // pending while `forge script` waits forever for their receipts. Send each transaction
            // and await its receipt before advancing so this release E2E is deterministic in CI.
            "--slow",
            "--offline",
            "--code-size-limit",
            "50000",
        ]),
        "forge deploy PW E2E",
    );
    let rollup = find_addr(&deploy, "IntmaxRollup:");
    let manager = find_addr(&deploy, "MANAGER:");
    let verifier_addr = find_addr(&deploy, "SettlementVerifier:");
    eprintln!("[PW E2E] rollup={rollup} manager={manager} verifier={verifier_addr}");

    // The Manager deliberately refuses a close whose ChannelFund anchor is not a state root the
    // Rollup has finalized. Read the anchor from the LIVE deployment rather than using a fixture
    // placeholder: the constructor marks its nonzero genesis root finalized, and every member
    // below signs this exact value into ChannelState/close PIs. This does not weaken the separate
    // proof-backed payout requirement (withdrawNative still verifies its own finalized root).
    let finalized_state_root = Bytes32::from_hex(
        cast(
            &rpc,
            &["call", &rollup, "latestFinalizedStateRoot()"],
            "read live finalized state root",
        )
        .trim(),
    )
    .expect("parse live latestFinalizedStateRoot");
    assert_ne!(
        finalized_state_root,
        Bytes32::default(),
        "PW E2E deployment must install a nonzero finalized genesis root"
    );
    let finalized_membership = cast(
        &rpc,
        &[
            "call",
            &rollup,
            "isFinalizedStateRoot(bytes32)",
            &finalized_state_root.to_hex(),
        ],
        "check live finalized state-root membership",
    );
    assert!(
        finalized_membership.contains("true") || finalized_membership.trim().ends_with("01"),
        "latestFinalizedStateRoot must be present in isFinalizedStateRoot, got: {finalized_membership}"
    );

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
    let timer = Instant::now();
    let deposit_proof = bp.prove_receive_deposit(&dw).unwrap();
    eprintln!(
        "[PW BENCH] balance receive-deposit prove={:?} proof={} bytes",
        timer.elapsed(),
        deposit_proof.to_bytes().len()
    );
    bwg.commit_receive_deposit(&deposit_proof, &dw).unwrap();

    // Bootstrap nonce 0 with an actual zero-value base transaction. Channel burn TxV2 nonces use
    // the authenticated pre-block ChannelLeaf index, so the first burn is nonce 1; without this
    // real sent-tx-tree step the base account remains at nonce 0 and P2-4 correctly refuses the
    // burn as unprovable.
    let bootstrap_transfer = Transfer::default();
    let bootstrap_spend_witness = bwg.spend_witness(&[bootstrap_transfer.clone()]).unwrap();
    let timer = Instant::now();
    let bootstrap_spend_proof = spend.prove(&bootstrap_spend_witness).unwrap();
    eprintln!(
        "[PW BENCH] bootstrap spend prove={:?} proof={} bytes",
        timer.elapsed(),
        bootstrap_spend_proof.to_bytes().len()
    );
    let mut bootstrap_transfer_tree = TransferTree::init();
    bootstrap_transfer_tree.push(bootstrap_transfer.clone());
    let bootstrap_transfer_root = bootstrap_transfer_tree.get_root();
    let bootstrap_transfer_proof = bootstrap_transfer_tree.prove(0);
    let bootstrap_tx = Tx {
        transfer_tree_root: bootstrap_transfer_root,
        nonce: bwg.full_private_state.nonce,
    };
    let bootstrap_tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root: bootstrap_transfer_root,
        nonce: bootstrap_tx.nonce,
        channel_action_root: Default::default(),
    };
    let mut bootstrap_tx_tree = TxTree::init();
    bootstrap_tx_tree.update(chan_id.as_u64(), bootstrap_tx);
    let bootstrap_tx_proof = bootstrap_tx_tree.prove(chan_id.as_u64());
    let mut bootstrap_tx_v2_tree = TxV2Tree::init();
    bootstrap_tx_v2_tree.update(chan_id.as_u64(), bootstrap_tx_v2);
    let bootstrap_root: Bytes32 = bootstrap_tx_v2_tree.get_root().into();
    let bootstrap_tx_v2_proof = bootstrap_tx_v2_tree.prove(chan_id.as_u64());
    bwgen
        .borrow_mut()
        .add_block(chan_id.channel_id(), &[1], 0, bootstrap_root)
        .unwrap();
    let bootstrap_data = SendTxData {
        spend_proof: bootstrap_spend_proof,
        tx_tree_root: bootstrap_root,
        tx: bootstrap_tx,
        tx_merkle_proof: bootstrap_tx_proof,
        tx_v2: Some(bootstrap_tx_v2),
        tx_v2_merkle_proof: Some(bootstrap_tx_v2_proof),
        transfer: bootstrap_transfer,
        transfer_merkle_proof: bootstrap_transfer_proof,
    };
    let bootstrap_witness = bwg.send_tx_witness(&bootstrap_data).unwrap();
    let timer = Instant::now();
    let bootstrap_balance_proof = bp.prove_send_tx(&bootstrap_witness).unwrap();
    eprintln!(
        "[PW BENCH] bootstrap balance send-tx prove={:?} proof={} bytes",
        timer.elapsed(),
        bootstrap_balance_proof.to_bytes().len()
    );
    bwg.commit_send_tx(
        &bootstrap_balance_proof,
        &bootstrap_witness,
        &bootstrap_spend_witness,
    )
    .unwrap();
    assert_eq!(bwg.full_private_state.nonce, 1, "base nonce bootstrap");
    let chain = bwg.get_public_inputs().unwrap().settled_tx_chain;
    let att = ChannelBalanceAttestation {
        balance_proof: bootstrap_balance_proof.to_bytes(),
    };

    // Build genesis ciphertexts, retaining alice's witness (slot 0).
    let (ct0, w0) = encrypt_amount(&mut crng, &all_pks[0], balances[0]).unwrap();
    let ct1 = encrypt_amount(&mut crng, &all_pks[1], balances[1])
        .unwrap()
        .0;
    let ct2 = encrypt_amount(&mut crng, &all_pks[2], balances[2])
        .unwrap()
        .0;
    let cts = [ct0.clone(), ct1, ct2];

    let genesis = build_signed_genesis(
        &record,
        &keys,
        &cts,
        fund,
        chain,
        finalized_state_root,
        &att,
        &balance_vd,
    );
    verify_channel_backing(&record, &genesis, Some(&att), &balance_vd).expect("§F-1 backing OK");
    let genesis_chain = genesis.balance_state.settled_tx_chain;
    eprintln!(
        "[PW E2E] genesis OK, fund={fund}, chain={}",
        genesis_chain.to_hex()
    );

    // ── Phase D: build_burn_send (alice burns 5 ETH) ────────────────────────────────────────
    let burn_amount = 5u64;
    let withdrawal_addr = Address::from_hex("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();
    let nullifier_root = Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0xBE01]).unwrap();

    let snapshot = ChannelSnapshot {
        record: record.clone(),
        state: genesis.clone(),
        members: members.clone(),
        settled_tx_accumulator: intmax3_zkp::wallet_core::default_settled_tx_accumulator(),
    };

    let timer = Instant::now();
    let built = build_burn_send(
        &keys[0],
        &snapshot,
        1, // bootstrap base send advanced the authenticated ChannelLeaf index to one
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
    eprintln!(
        "[PW BENCH] E-2 burn build+prove={:?} proof={} bytes",
        timer.elapsed(),
        built
            .debit_payload
            .inter_channel_tx
            .channel_update_zkp
            .proof
            .len()
    );

    // Co-sign the post-burn state.
    let mut next_state = built.debit_payload.proposed_next_state.clone();
    sign_real(&mut next_state, &keys);
    verify_all_signatures(&record, &members, &next_state).expect("post-burn co-signed");

    // Verify fund decreased.
    let post_fund = {
        let a = next_state.channel_fund.amounts[0];
        let limbs = a.to_u32_vec();
        limbs[7] as u64 | ((limbs[6] as u64) << 32)
    };
    assert_eq!(
        post_fund,
        fund - burn_amount,
        "channel fund must decrease by burn amount"
    );
    eprintln!("[PW E2E] build_burn_send OK, post_fund={post_fund}");

    // Compute tx_leaf (the burn's settled_tx_chain leaf) = aux_data for the on-chain binding.
    let desc = &built.transfer_descriptor;
    let tx_leaf = tx_leaf_hash(
        desc.source_pk_g,
        desc.sender_delta_ct.digest(),
        desc.receiver_pk_g,
        desc.receiver_delta.digest(),
    );
    let burn_aux_data = burn_descriptor(
        desc.source_channel_id,
        desc.inter_channel_tx.base_nonce,
        tx_leaf,
        desc.receiver_pk_g,
        desc.inter_channel_tx.token_index,
        u256(burn_amount),
    );
    let expected_chain = settled_tx_chain_push(genesis_chain, burn_aux_data);
    assert_eq!(
        next_state.balance_state.settled_tx_chain, expected_chain,
        "channel chain must be push(genesis, IMD2 descriptor)"
    );
    eprintln!("[PW E2E] settled_tx_chain OK");

    // Settle the exact burn transfer into the persisted base balance IVC head. This is the proof
    // the close circuit recursively verifies; using the genesis attestation here would fail the
    // finalSettledTxChain equality and was the hidden reason the old E2E used mock close limbs.
    assert_eq!(
        bwg.full_private_state.nonce, desc.tx_v2.nonce,
        "P2-4: base next nonce and burn TxV2 nonce must be in lockstep"
    );
    let base_transfer = inter_channel_base_transfer(
        desc.receiver_pk_g,
        desc.inter_channel_tx.token_index,
        burn_amount,
        burn_aux_data,
    );
    let burn_spend_witness = bwg.spend_witness(&[base_transfer.clone()]).unwrap();
    let timer = Instant::now();
    let burn_spend_proof = spend.prove(&burn_spend_witness).unwrap();
    eprintln!(
        "[PW BENCH] burn spend prove={:?} proof={} bytes",
        timer.elapsed(),
        burn_spend_proof.to_bytes().len()
    );
    let mut burn_transfer_tree = TransferTree::init();
    burn_transfer_tree.push(base_transfer.clone());
    let burn_transfer_root = burn_transfer_tree.get_root();
    let burn_transfer_proof = burn_transfer_tree.prove(0);
    let burn_tx = Tx {
        transfer_tree_root: burn_transfer_root,
        nonce: desc.tx_v2.nonce,
    };
    assert_eq!(burn_tx.transfer_tree_root, desc.tx_v2.transfer_tree_root);
    let mut burn_tx_tree = TxTree::init();
    burn_tx_tree.update(chan_id.as_u64(), burn_tx);
    let burn_tx_proof = burn_tx_tree.prove(chan_id.as_u64());
    let mut burn_tx_v2_tree = TxV2Tree::init();
    burn_tx_v2_tree.update(chan_id.as_u64(), desc.tx_v2);
    let burn_root: Bytes32 = burn_tx_v2_tree.get_root().into();
    assert_eq!(burn_root, desc.tx_tree_root, "canonical base H2");
    let burn_tx_v2_proof = burn_tx_v2_tree.prove(chan_id.as_u64());
    bwgen
        .borrow_mut()
        .add_block(chan_id.channel_id(), &[1], 0, burn_root)
        .unwrap();
    let burn_send_data = SendTxData {
        spend_proof: burn_spend_proof,
        tx_tree_root: burn_root,
        tx: burn_tx,
        tx_merkle_proof: burn_tx_proof,
        tx_v2: Some(desc.tx_v2),
        tx_v2_merkle_proof: Some(burn_tx_v2_proof),
        transfer: base_transfer,
        transfer_merkle_proof: burn_transfer_proof,
    };
    let burn_send_witness = bwg.send_tx_witness(&burn_send_data).unwrap();
    let timer = Instant::now();
    let live_balance_proof = bp.prove_send_tx(&burn_send_witness).unwrap();
    eprintln!(
        "[PW BENCH] burn balance send-tx prove={:?} proof={} bytes",
        timer.elapsed(),
        live_balance_proof.to_bytes().len()
    );
    bwg.commit_send_tx(&live_balance_proof, &burn_send_witness, &burn_spend_witness)
        .unwrap();
    assert_eq!(
        bwg.get_public_inputs().unwrap().settled_tx_chain,
        expected_chain,
        "base balance IVC and N-of-N channel head must pin the same burn descriptor chain"
    );

    // P1: a real close proof and its real wrapped MLE/WHIR proof — no synthesized publicInputs.
    let timer = Instant::now();
    let close_prover = CloseProver::new(&balance_vd);
    eprintln!(
        "[PW BENCH] close circuit construction={:?}",
        timer.elapsed()
    );
    let timer = Instant::now();
    let close_witness = close_prover
        .build_full_witness_from_signatures(
            &record,
            &next_state,
            &next_state.member_signatures,
            live_balance_proof,
        )
        .expect("real PW close witness");
    eprintln!(
        "[PW BENCH] close signature aggregation+witness={:?}",
        timer.elapsed()
    );
    let timer = Instant::now();
    let close_proof = close_prover
        .prove(&close_witness)
        .expect("real PW close proof");
    eprintln!(
        "[PW BENCH] close Plonky2 prove={:?} proof={} bytes",
        timer.elapsed(),
        close_proof.to_bytes().len()
    );
    let timer = Instant::now();
    let close_mle = close_prover
        .prove_mle(&close_proof)
        .expect("real PW close MLE");
    eprintln!(
        "[PW BENCH] close wrap+MLE+self-verify={:?} JSON={} bytes",
        timer.elapsed(),
        close_mle.len()
    );
    let close_pis = ChannelClosePublicInputs::from_u64_slice(
        &close_proof.public_inputs[..CHANNEL_CLOSE_PUBLIC_INPUTS_LEN].to_u64_vec(),
    )
    .expect("decode real close PIs");
    let close_config = std::fs::read_to_string(data_dir.join("close_intent_mle_config.json"))
        .expect("read proof-free close MLE V2 config");
    validate_mle_v2_full_against_config_json(&close_mle, &close_config)
        .expect("PW close full proof must strictly match the deployed config and compact bytes");
    std::fs::write(data_dir.join("pw_close_intent_mle.json"), &close_mle).unwrap();

    // ── Phase E: Write pw_submit.json + on-chain settlement ─────────────────────────────────
    // The Withdrawal struct for authDigest computation.
    //
    // SECURITY (2026-08-13): this used to authorize a LITERAL `nullifier = 0xBEEF`, the third of
    // three disagreeing derivations (CLI `keccak(tx_leaf ‖ pre_burn_chain)`, this literal, and the
    // only real one — `SettledTransfer::nullifier()` in the withdrawal circuit). An E2E that
    // authorizes a nullifier no provable leaf carries cannot detect the stranding bug it walks
    // straight through, so it now derives the leaf from the burn artefact with the one shared
    // `burn_withdrawal_leaf`, exactly as `pw-submit` does.
    let withdrawal = burn_withdrawal_leaf(
        desc.source_channel_id,
        desc.receiver_pk_g,
        desc.inter_channel_tx.token_index,
        burn_amount,
        burn_aux_data,
        desc.tx_v2.nonce,
    )
    .expect("burn withdrawal leaf");
    assert_eq!(
        withdrawal.recipient, withdrawal_addr,
        "the burn's baked ADDRESS_TAG recipient must recover the L1 address it was built for"
    );
    assert_eq!(withdrawal.amount, u256(burn_amount));
    assert_eq!(withdrawal.aux_data, burn_aux_data);
    let rust_auth_digest = partial_withdrawal_auth_digest(&withdrawal);
    eprintln!("[PW E2E] Rust authDigest = {}", rust_auth_digest.to_hex());

    {
        let submit = serde_json::json!({
            "manager": manager,
            "verifier": verifier_addr,
            // CloseIntent fields decoded from the REAL close proof public inputs.
            "close_nonce": close_pis.close_nonce,
            "final_epoch": close_pis.final_epoch,
            "final_small_block_number": close_pis.final_small_block_number,
            "close_freeze_nonce": close_pis.close_freeze_nonce,
            "final_channel_state_digest": close_pis.final_channel_state_digest.to_hex(),
            "final_balance_state_h1": close_pis.final_balance_state_h1.to_hex(),
            "channel_fund_amounts": next_state.channel_fund.amounts.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
            "token_registry": next_state.balance_state.token_registry.to_vec(),
            "token_count": next_state.balance_state.token_count,
            "channel_fund_intmax_state_root": close_pis.channel_fund_intmax_state_root.to_hex(),
            "burn_tx_hash": close_pis.burn_tx_hash.to_hex(),
            "close_withdrawal_digest": close_pis.close_withdrawal_digest.to_hex(),
            "snapshot_medium_block_number": close_pis.snapshot_medium_block_number,
            "final_state_version": close_pis.final_state_version,
            "final_settled_tx_chain": close_pis.final_settled_tx_chain.to_hex(),
            "final_settled_tx_acc_root": close_pis.final_settled_tx_accumulator_root.to_hex(),
            // prevSettledTxChain (genesis chain before the burn push).
            "prev_settled_tx_chain": genesis_chain.to_hex(),
            // AuthorizedWithdrawal fields.
            "withdrawal_recipient": format!("0x{}", hex::encode(withdrawal.recipient.to_bytes_be())),
            "withdrawal_token_index": withdrawal.token_index,
            "withdrawal_amount": burn_amount,
            "withdrawal_nullifier": withdrawal.nullifier.to_hex(),
            "withdrawal_aux_data": burn_aux_data.to_hex(),
            "withdrawal_base_nonce": desc.inter_channel_tx.base_nonce,
            "burn_tx_leaf": tx_leaf.to_hex(),
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
            "--slow",
            "--offline",
        ]),
        "forge submit PW intent",
    );
    eprintln!("[PW E2E] submitPartialWithdrawalIntent succeeded");

    // Pin the operational liveness claim to the actual transaction, not Forge's in-process trace.
    // The script must bypass Foundry's conservative estimator with its explicit 20M limit, and the
    // node receipt must show that the real cold transaction consumed no more than that envelope.
    {
        let artifact_path = contracts
            .join("broadcast")
            .join("SubmitPartialWithdrawal.s.sol")
            .join("31337")
            .join("run-latest.json");
        let artifact: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&artifact_path)
                .unwrap_or_else(|e| panic!("read {}: {e}", artifact_path.display())),
        )
        .unwrap_or_else(|e| panic!("parse {}: {e}", artifact_path.display()));
        let tx = artifact["transactions"]
            .as_array()
            .and_then(|transactions| transactions.first())
            .expect("submit broadcast must contain one transaction");
        let receipt = artifact["receipts"]
            .as_array()
            .and_then(|receipts| receipts.first())
            .expect("submit broadcast must contain one receipt");
        let gas_limit = json_hex_quantity(&tx["transaction"]["gas"], "transaction gas limit");
        let gas_used = json_hex_quantity(&receipt["gasUsed"], "receipt gasUsed");
        let receipt_status = json_hex_quantity(&receipt["status"], "receipt status");
        assert_eq!(
            tx["isFixedGasLimit"].as_bool(),
            Some(true),
            "submit script must retain its explicit gas limit instead of estimator headroom"
        );
        assert_eq!(
            gas_limit, PRODUCTION_BLOCK_GAS_LIMIT,
            "submit transaction limit must equal the production block envelope"
        );
        assert_eq!(receipt_status, 1, "submit transaction reverted");
        assert!(
            gas_used <= PRODUCTION_BLOCK_GAS_LIMIT,
            "submit used {gas_used} gas, above the production envelope"
        );
        eprintln!(
            "[PW E2E] real submit gas: used={gas_used} limit={gas_limit} margin={}",
            gas_limit - gas_used
        );
    }

    // Extract on-chain authDigest from the script's console2.logBytes32 output.
    let onchain_auth = submit_out
        .lines()
        .skip_while(|l| !l.contains("AUTH_DIGEST:"))
        .nth(1)
        .and_then(|l| l.trim().strip_prefix("0x").or_else(|| Some(l.trim())))
        .map(|s| format!("0x{}", s.trim_start_matches("0x")))
        .unwrap_or_else(|| panic!("could not parse AUTH_DIGEST from:\n{submit_out}"));
    let onchain_digest =
        Bytes32::from_hex(&onchain_auth).unwrap_or_else(|_| panic!("bad hex: {onchain_auth}"));
    assert_eq!(
        rust_auth_digest, onchain_digest,
        "CRITICAL: Rust authDigest != Solidity authDigest — cross-boundary hash mismatch"
    );
    eprintln!(
        "[PW E2E] authDigest PARITY OK: {}",
        rust_auth_digest.to_hex()
    );

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

    // ── Phase F2: the proof-free claim must FAIL CLOSED ────────────────────────────────────
    //
    // REWRITTEN 2026-07-28 (doc/tasks/pw-auth-threat-model.md). This phase used to assert that
    // `claimAuthorizedWithdrawal` paid `burn_amount` ETH. That function has been REMOVED: it paid
    // the GLOBAL escrow against the authorization ALONE, with no withdrawal proof, and since
    // `submitPartialWithdrawalIntent` binds only `auxData`, the amount and recipient were
    // caller-chosen — one valid close proof for one's OWN channel drained every channel's ETH.
    //
    // Coverage is KEPT, not deleted: the phase now proves the payout is unreachable and, crucially,
    // that the escrow does not move. It is the E2E-level twin of
    // `contracts/test/PartialWithdrawalPayout.t.sol::test_authorizationAlone_cannotDrainEscrow`.
    {
        let recipient_hex = format!("0x{}", hex::encode(withdrawal_addr.to_bytes_be()));
        let before = cast(&rpc, &["balance", &recipient_hex], "balance before claim");
        let before_wei: u128 = before.trim().parse().unwrap_or(0);
        let escrow_before = cast(&rpc, &["call", &rollup, "totalEscrowed()"], "escrow before");

        // 1. The selector is gone — a raw call hits the (absent) fallback and reverts.
        let sig = "claimAuthorizedWithdrawal((address,uint32,uint256,bytes32,bytes32))";
        let arg = format!(
            "(0x{},{},{},{},{})",
            hex::encode(withdrawal_addr.to_bytes_be()),
            0u32,
            burn_amount,
            withdrawal.nullifier.to_hex(),
            withdrawal.aux_data.to_hex()
        );
        let out = Command::new("cast")
            .args([
                "send",
                &rollup,
                sig,
                &arg,
                "--private-key",
                ANVIL0,
                "--rpc-url",
                &rpc,
            ])
            .output()
            .expect("spawn cast send (claim must fail)");
        assert!(
            !out.status.success(),
            "SECURITY REGRESSION: claimAuthorizedWithdrawal succeeded. The proof-free partial-\n\
             withdrawal payout was removed because it drained the GLOBAL escrow against a\n\
             caller-chosen amount/recipient. If this call works, the hole is back.\n\
             stdout: {}",
            String::from_utf8_lossy(&out.stdout)
        );

        // 2. Nothing moved: neither the recipient's balance nor the global escrow.
        let after = cast(&rpc, &["balance", &recipient_hex], "balance after claim");
        let after_wei: u128 = after.trim().parse().unwrap_or(0);
        assert_eq!(
            after_wei, before_wei,
            "recipient balance must be unchanged — no proof-free payout may occur"
        );
        let escrow_after = cast(&rpc, &["call", &rollup, "totalEscrowed()"], "escrow after");
        assert_eq!(
            escrow_before.trim(),
            escrow_after.trim(),
            "totalEscrowed must be unchanged — the authorization alone must buy nothing"
        );

        eprintln!(
            "[PW E2E] claim correctly FAILED CLOSED: {} received nothing, escrow unchanged.\n\
             [PW E2E] The proof-backed payout (withdrawNative/withdrawERC20) needs\n\
             [PW E2E] `cmd_partial_withdraw`, which is not implemented (doc/tasks/todo.md:90).",
            hex::encode(withdrawal_addr.to_bytes_be())
        );
    }

    // ── Phase G: a finalized logical burn is single-use ──────────────────────────────────
    {
        // The broad `usedPartialWithdrawalChains[chainKey]` guard remains deleted: the correlation
        // key is not itself payout authority, and an unfinalized/cancelled burn stays recoverably
        // re-submittable. Once finalization atomically accounts this exact IMBK logical burn,
        // however, replay has no recovery purpose and must fail before it can re-enable the
        // one-shot IPW2 authorization or monopolize the singleton pending slot.
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
                "--slow",
                "--offline",
            ])
            .output()
            .expect("re-submit spawn");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && stderr.contains("PartialWithdrawalAlreadyAccounted()"),
            "finalized logical-burn replay must fail with PartialWithdrawalAlreadyAccounted; \
             status={} stderr={stderr}",
            out.status
        );

        let pending = cast(
            &rpc,
            &["call", &manager, "partialWithdrawalPending()(bool)"],
            "pending state after finalized-burn replay",
        );
        assert_eq!(
            pending.trim(),
            "false",
            "rejected finalized-burn replay must not recreate pending state"
        );
        eprintln!("[PW E2E] finalized logical-burn replay correctly rejected; state unchanged");
    }

    eprintln!(
        "[PW E2E] ALL PASSED: deposit → burn → submit → finalize → authorize, \
         authDigest cross-boundary parity verified, finalized logical-burn replay rejected."
    );
}

/// B-1b: deterministic NONZERO per-slot L1 exit addresses for test genesis states
/// (`BalanceState::validate()` rejects zero active recipients).
fn test_recipients_b1b(n: usize) -> Vec<intmax3_zkp::ethereum_types::address::Address> {
    use intmax3_zkp::ethereum_types::u32limb_trait::U32LimbTrait as _;
    (0..n)
        .map(|i| {
            intmax3_zkp::ethereum_types::address::Address::from_u32_slice(
                &[0x7E57_0000u32.wrapping_add(i as u32); 5],
            )
            .unwrap()
        })
        .collect()
}
