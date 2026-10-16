//! Partial-withdrawal anvil E2E: a burn is paid on L1 by its base withdrawal proof alone, through
//! the real `channel_member pw-finalize`.
//!
//! A partial withdrawal is an inter-channel send to the reserved BURN channel whose base transfer
//! names an L1 recipient. Like an inter-channel transfer consumed by a receive proof, it is paid by
//! `IntmaxRollup.withdrawNative` from the base withdrawal proof: the members' consent is the
//! validity of the N-of-N signed update that carried it. No settlement manager is deployed here;
//! the rollup alone (`script/Deploy.s.sol`) verifies and pays.
//!
//! Flow: Rust wallet burn builder (decrypted E-2) → N-of-N co-signed post-burn head → the burn's
//! base transfer settled into the base balance IVC head → registration, deposit, bootstrap and burn
//! blocks posted to anvil as EIP-4844 blob transactions (`cast mktx --blob`, validated with
//! `proof_da::validate_decoded_blob_transaction` exactly like the production CLI) and finalized
//! with their real 4-block validity MLE proof → the burn's single-withdrawal → withdrawal-chain →
//! final withdrawal proof wrapped into the deployed withdrawal adapter's MLE format, staged exactly
//! as the relay stages the daemon's `liveBurnPayoutArtifacts` response (with `channel_backing.json`
//! naming the rollup) → `pw-finalize`:
//!   * while the proof's anchor root is posted but not finalized it refuses with `payout anchor is
//!     not L1-finalized` and journals no payout transaction;
//!   * once the root is finalized it pays with `withdrawNative` and, the signer being the proved
//!     recipient, pulls the credit; the escrow drops by exactly the burned amount;
//!   * a re-run is idempotent, and a replayed payout reverts on the used nullifier.
//!
//! Release-gate execution requires foundry (anvil/forge/cast); missing tooling is a hard failure so
//! CI cannot silently report an unexecuted payout path as passing.
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    block_producer_service::{BlockProducerAnchor, BlockProducerReceipt},
    circuits::{
        balance::{
            balance_processor::BalanceProcessor,
            common::recipient::calculate_recipient_from_user_id, spend_circuit::SpendCircuit,
        },
        test_utils::{
            balance_witness_generator::{
                BalanceWitnessGenerator, ReceiveDepositData, SendTxData, SingleWithdrawalData,
            },
            block_witness_generator::{BlockWitnessGenerator, BlockWitnessGeneratorHandle},
        },
        validity::block_hash_chain::{
            block_chain_pis::BlockChainPublicInputs,
            block_hash_chain_processor::BlockHashChainProcessor,
            validity_circuit::{ValidityCircuit, ValidityPublicInputs},
        },
        withdraw::{
            single_withdrawal_circuit::{
                SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN, SingleWithdawalCircuit,
                SingleWithdawalPublicInputs,
            },
            withdrawal_processor::WithdrawalProcessor,
            withdrawal_step::WithdrawalStepWitness,
        },
        witness::block_witness_generator::{BlockTxV2Witness, ChannelMemberKeys},
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
        u63::BlockNumber,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
    falcon_sig::{agg::FalconAggCircuit, agg_list::AggListCircuit},
    partial_withdrawal_payout::{
        PartialWithdrawalPayoutStore, PartialWithdrawalProofArtifacts,
        PartialWithdrawalProofMetrics,
    },
    proof_da::{DecodedBlobTransaction, ValidatedBlobSidecars, validate_decoded_blob_transaction},
    regev::{RegevCiphertext, RegevPk, RegevSecurityLevel, encrypt_amount},
    utils::{
        conversion::ToU64 as _,
        mle_prover::{
            export_mle_v2_json, mle_v2_compact_submission_metadata, prove_with_mle_v2,
            setup_mle_vk_v2, validate_mle_v2_full_against_config_json, verify_mle_proof_v2,
        },
        wrapper::WrapperCircuit,
    },
    wallet_core::{
        ChannelBalanceAttestation, MemberInfo, MemberKeys, add_signature,
        assemble_genesis_state_backed, build_burn_send_token_at_base_nonce_decrypted, build_record,
        burn_withdrawal_leaf, inter_channel_base_transfer, sign_state, sign_state_if_backed,
        verify_all_signatures, verify_channel_backing,
    },
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_data::VerifierCircuitData, config::PoseidonGoldilocksConfig},
};
use std::{
    io::Write as _,
    path::{Path, PathBuf},
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
/// The account behind `ANVIL0`: deployer, block producer and depositor of this E2E.
const ANVIL0_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
/// Anvil account 1 (`PW_RECIPIENTS[0]`): the burn's proved L1 recipient and the `pw-finalize`
/// signer, so the CLI runs the recipient pull leg as well.
const RECIPIENT_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const PORT: u16 = 8553;
/// The node's block gas limit. Proof-DA attestation (KZG openings over two blobs), the
/// multi-block validity finalization and the proof payout are each large single transactions.
const ANVIL_BLOCK_GAS_LIMIT: u64 = 30_000_000;
/// Each post's `msg.value`: it tops the producer's posting bond up by more than a post needs
/// (`baseStake` + `postStake` per unfinalized post); the surplus stays in the bond.
const POST_BLOCK_STAKE_WEI: u64 = 1_000_000_000_000_000_000;
const POST_SIG: &str =
    "postBlockAndSubmit((uint32,uint64,bytes32,uint32[])[],bytes32,uint32,bytes32,bytes32)";
/// L1 payout recipients registered for the three members (anvil accounts 1..3).
const PW_RECIPIENTS: [&str; 3] = [
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
];

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

/// Post one block as an EIP-4844 blob transaction carrying the validity proof-DA payload: sign
/// with `cast mktx --blob`, decode the signed transaction, validate it against the exact payload
/// and intended calldata (`proof_da::validate_decoded_blob_transaction`, the same check the
/// production CLI applies before publishing), publish it and require a successful receipt.
#[allow(clippy::too_many_arguments)]
fn post_block_with_blob(
    rpc: &str,
    rollup: &str,
    sub_block: &str,
    proof_da_path: &Path,
    payload: &[u8],
    proof_hash: &str,
    proof_length: u32,
    state_root: &str,
) -> (u64, ValidatedBlobSidecars) {
    let submission_id: u64 = cast(
        rpc,
        &["call", rollup, "nextSubmissionId()(uint256)"],
        "next sub id",
    )
    .trim()
    .parse()
    .expect("nextSubmissionId");
    let pending_pin = cast(
        rpc,
        &["call", rollup, "pendingChainsPin()(bytes32)"],
        "pending pin",
    )
    .trim()
    .to_string();
    let proof_length_s = proof_length.to_string();
    let calldata = run_capture(
        Command::new("cast").args([
            "calldata",
            POST_SIG,
            sub_block,
            proof_hash,
            &proof_length_s,
            state_root,
            &pending_pin,
        ]),
        "cast calldata postBlockAndSubmit",
    )
    .trim()
    .to_string();
    let raw = run_capture(
        Command::new("cast").args([
            "mktx",
            rollup,
            POST_SIG,
            sub_block,
            proof_hash,
            &proof_length_s,
            state_root,
            &pending_pin,
            "--value",
            "1ether",
            "--blob",
            "--path",
            proof_da_path.to_str().expect("utf-8 proof-DA path"),
            "--private-key",
            ANVIL0,
            "--rpc-url",
            rpc,
        ]),
        "cast mktx --blob postBlockAndSubmit",
    )
    .trim()
    .to_string();
    assert!(
        raw.starts_with("0x03"),
        "cast mktx must return a signed EIP-4844 transaction, got {}",
        &raw[..raw.len().min(16)]
    );
    let mut decoder = Command::new("cast")
        .args(["decode-transaction", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cast decode-transaction");
    decoder
        .stdin
        .take()
        .expect("decoder stdin")
        .write_all(raw.as_bytes())
        .expect("write signed blob transaction");
    let decoded_out = decoder.wait_with_output().expect("cast decode-transaction");
    assert!(
        decoded_out.status.success(),
        "cast decode-transaction failed: {}",
        String::from_utf8_lossy(&decoded_out.stderr)
    );
    let decoded: DecodedBlobTransaction =
        serde_json::from_slice(&decoded_out.stdout).expect("decoded blob transaction JSON");
    let validated = validate_decoded_blob_transaction(
        &decoded,
        payload,
        31337,
        ANVIL0_ADDR,
        rollup,
        POST_BLOCK_STAKE_WEI,
        &calldata,
    )
    .unwrap_or_else(|e| panic!("signed blob post is not the intended post: {e}"));
    let published = cast(rpc, &["publish", &raw, "--async"], "cast publish blob post")
        .trim()
        .trim_matches('"')
        .to_string();
    assert!(
        published.eq_ignore_ascii_case(&validated.transaction_hash),
        "published hash {published} != signed hash {}",
        validated.transaction_hash
    );
    let receipt = cast(
        rpc,
        &["receipt", &validated.transaction_hash, "--json"],
        "blob post receipt",
    );
    let receipt: serde_json::Value = serde_json::from_str(&receipt).expect("receipt JSON");
    assert_eq!(
        json_hex_quantity(&receipt["status"], "blob post status"),
        1,
        "postBlockAndSubmit reverted for submission {submission_id}"
    );
    let next: u64 = cast(
        rpc,
        &["call", rollup, "nextSubmissionId()(uint256)"],
        "next sub id",
    )
    .trim()
    .parse()
    .expect("nextSubmissionId");
    assert_eq!(
        next,
        submission_id + 1,
        "exactly one submission must have been recorded"
    );
    (submission_id, validated)
}

/// One step of `script/PartialWithdrawalE2ELifecycle.s.sol` broadcast from `ANVIL0`.
fn lifecycle_script(contracts: &Path, rpc: &str, sig: &str, envs: &[(&str, &str)]) -> String {
    let mut cmd = Command::new("forge");
    cmd.current_dir(contracts).args([
        "script",
        "script/PartialWithdrawalE2ELifecycle.s.sol",
        "--sig",
        sig,
        "--rpc-url",
        rpc,
        "--private-key",
        ANVIL0,
        "--broadcast",
        "--slow",
        "--offline",
    ]);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    run_capture(
        &mut cmd,
        &format!("forge PartialWithdrawalE2ELifecycle {sig}"),
    )
}

/// The lifecycle-descriptor view of one posted block, formatted for `cast`:
/// `[(channel_id,timestamp,tx_tree_root,[key_ids...])]`.
fn sub_block_literal(block: &intmax3_zkp::common::block::Block) -> String {
    let key_ids = block
        .key_ids
        .iter()
        .map(|k| k.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "[({},{},{},[{}])]",
        block.channel_id,
        block.timestamp,
        block.tx_tree_root.to_hex(),
        key_ids
    )
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
    let block_gas_limit = ANVIL_BLOCK_GAS_LIMIT.to_string();
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
    // The same block profile the deployed validity adapter was pinned from
    // (`generate_e2e_fixture`: `supported_user_counts = [2]`), so the 4-block validity proof below
    // verifies against `mle_fixture_config.json`.
    let supported_user_counts = vec![2u32];
    let bwgen =
        BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));
    let initial_ext_state = bwgen.borrow().current_extended_public_state();
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

    // ── Phase B: deploy the ROLLUP ONLY and register the channel ────────────────────────────
    // A burn is paid by the rollup's withdrawal verifier alone; no settlement manager, settlement
    // verifier or close-funding materializer is deployed.
    let contracts = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts");
    let data_dir = contracts.join("test").join("data");
    let deploy = run_capture(
        Command::new("forge").current_dir(&contracts).args([
            "script",
            "script/Deploy.s.sol",
            "--tc",
            "Deploy",
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
        "forge deploy rollup",
    );
    let rollup = find_addr(&deploy, "IntmaxRollup  :");
    eprintln!("[PW E2E] rollup={rollup} (no settlement manager deployed)");
    {
        let list = |items: Vec<String>| format!("[{}]", items.join(","));
        let pk_gs = list(keys.iter().map(|k| k.pk_g().to_hex()).collect());
        let pk_bs = list(keys.iter().map(|k| k.pk_b().to_hex()).collect());
        let regev_digests = list(
            keys.iter()
                .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()).to_hex())
                .collect(),
        );
        let recipients = list(PW_RECIPIENTS.iter().map(|r| r.to_string()).collect());
        // Cosigners only: the registration record's delegate count is a constant zero (the
        // validity `channel_reg_step` circuit constrains it), exactly as the deploy scripts send.
        run_capture(
            Command::new("cast").args([
                "send",
                &rollup,
                "registerChannel(uint32,uint8,uint8,bytes32[],bytes32[],bytes32[],address[])",
                "42",
                "0",
                "0",
                &pk_gs,
                &pk_bs,
                &regev_digests,
                &recipients,
                "--private-key",
                ANVIL0,
                "--rpc-url",
                &rpc,
            ]),
            "cast registerChannel",
        );
    }

    // The deployed genesis root must be the Rust generator's initial extended state: every block
    // below is proved from it, and the payout proof is anchored at the root they finalize.
    let finalized_state_root = Bytes32::from_hex(
        cast(
            &rpc,
            &["call", &rollup, "latestFinalizedStateRoot()"],
            "read live finalized state root",
        )
        .trim(),
    )
    .expect("parse live latestFinalizedStateRoot");
    assert_eq!(
        initial_ext_state.commitment(),
        finalized_state_root,
        "the deployed genesis root must be the Rust generator's initial extended state"
    );

    // ── Phase B': mirror the live `registerChannel` (Phase B's cast send) in the Rust
    // block generator and fold it as block 1, exactly as the posted registration block will.
    {
        let member_keys = ChannelMemberKeys::from_member_keys(&keys);
        let mut reg_record =
            member_keys.to_reg_record_split(chan_id.channel_id(), keys.len() as u32, 0);
        for (slot, (entry, recipient)) in reg_record
            .members
            .iter_mut()
            .zip(PW_RECIPIENTS.iter())
            .enumerate()
        {
            assert_eq!(entry.pk_g, keys[slot].pk_g(), "registration pk_g[{slot}]");
            assert_eq!(entry.pk_b, keys[slot].pk_b(), "registration pk_b[{slot}]");
            entry.recipient = Address::from_hex(recipient).expect("recipient");
        }
        let mut generator = bwgen.borrow_mut();
        generator
            .add_channel_registration_with_record(reg_record, member_keys)
            .expect("mirror the live channel registration");
        generator
            .add_registration_block(0)
            .expect("registration block");
    }
    eprintln!("[PW E2E] registration block 1 mirrored");

    // ── Phase C: deposit-backed genesis. The real ETH deposit is sent AFTER the registration
    // block is posted (a pending deposit would otherwise be folded into block 1 on chain); the
    // Rust mirror already knows the depositor (ANVIL0) and the deposit index (0).
    let balances = [50u64, 10, 30];
    let fund: u64 = balances.iter().sum(); // 90

    let mut brng = rand::rngs::StdRng::seed_from_u64(0xDE_AD_BE_EF);
    let salt = Salt::rand(&mut brng);
    let recipient = calculate_recipient_from_user_id(chan_id, salt);
    let depositor = Address::from_hex(ANVIL0_ADDR).expect("depositor");

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
    // The registered channel's updating slot must open its TxV2 leaf inside the block hash chain
    // proof (the posted block is proven, not merely mirrored), exactly like the lifecycle fixtures.
    bwgen
        .borrow_mut()
        .add_block_with_tx_v2(
            chan_id.channel_id(),
            &[1],
            0,
            bootstrap_root,
            Some(BlockTxV2Witness {
                tx_v2_indices: vec![chan_id.as_u64(), 0],
                tx_v2s: vec![bootstrap_tx_v2, TxV2::default()],
                tx_v2_merkle_proofs: vec![
                    bootstrap_tx_v2_proof.clone(),
                    bootstrap_tx_v2_proof.clone(),
                ],
                new_member_leaves: None,
                channel_action_indices: None,
                channel_actions: None,
                channel_action_merkle_proofs: None,
            }),
        )
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
    let (ct0, _w0) = encrypt_amount(&mut crng, &all_pks[0], balances[0]).unwrap();
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

    // ── Phase D: burn builder (alice burns 5 ETH) ───────────────────────────────────────────
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
    let built = build_burn_send_token_at_base_nonce_decrypted(
        &keys[0],
        &snapshot,
        // bootstrap base send advanced the authenticated ChannelLeaf index to one
        0,
        // sender_slot
        withdrawal_addr,
        snapshot.state.balance_state.token_registry[0],
        1,
        burn_amount,
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
        Bytes32::from(desc.receiver_pk.poseidon_digest()),
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

    // Settle the exact burn transfer into the persisted base balance IVC head. The burn's
    // withdrawal proof (Phase F) opens its sent-tx slot from this head.
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
        .add_block_with_tx_v2(
            chan_id.channel_id(),
            &[1],
            0,
            burn_root,
            Some(BlockTxV2Witness {
                tx_v2_indices: vec![chan_id.as_u64(), 0],
                tx_v2s: vec![desc.tx_v2, TxV2::default()],
                tx_v2_merkle_proofs: vec![burn_tx_v2_proof.clone(), burn_tx_v2_proof.clone()],
                new_member_leaves: None,
                channel_action_indices: None,
                channel_actions: None,
                channel_action_merkle_proofs: None,
            }),
        )
        .unwrap();
    // The burn's withdrawal leg opens the SAME transfer in the SAME block the send settles: the
    // extraction recipe `LiveBalanceService::prove_burn_withdrawal` uses.
    let burn_withdrawal_data = SingleWithdrawalData {
        tx_tree_root: burn_root,
        tx: burn_tx,
        tx_merkle_proof: burn_tx_proof.clone(),
        tx_v2: Some(desc.tx_v2),
        tx_v2_merkle_proof: Some(burn_tx_v2_proof.clone()),
        transfer: base_transfer.clone(),
        transfer_index: 0,
        transfer_merkle_proof: burn_transfer_proof.clone(),
    };
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

    // ── Phase E: the 4-block validity proof of the mirrored chain (local) ──────────────────
    let final_ext_state = bwgen.borrow().current_extended_public_state();
    let pw_e2e_dir = contracts
        .parent()
        .expect("repo root")
        .join("proof-da-output")
        .join("pw-e2e");
    std::fs::create_dir_all(&pw_e2e_dir).unwrap();
    let (pw_lifecycle_json, validity_payload, validity_proof_hash, validity_proof_length) = {
        let timer = Instant::now();
        let processor = BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
        let block_chain_vd = processor.block_chain_vd();
        let (blocks, final_block_chain_proof) = {
            let guard = bwgen.borrow();
            let total_blocks = guard.block_number.as_u64();
            assert_eq!(
                total_blocks, 4,
                "registration, deposit, bootstrap and burn blocks"
            );
            let mut blocks = Vec::new();
            let mut prev_block_proof = None;
            for block_idx in 1..=total_blocks {
                let block_number = BlockNumber::new(block_idx).expect("block number");
                let witness = guard
                    .block_chain_witness
                    .get(&block_number)
                    .cloned()
                    .expect("block witness");
                let initial_state = prev_block_proof
                    .is_none()
                    .then(|| initial_ext_state.clone());
                let proof = processor
                    .prove_block(initial_state, prev_block_proof.clone(), &witness)
                    .expect("block hash chain proof");
                prev_block_proof = Some(proof);
                blocks.push(witness.block.clone());
            }
            (blocks, prev_block_proof.expect("final block proof"))
        };
        eprintln!("[PW BENCH] 4-block hash chain prove={:?}", timer.elapsed());
        let timer = Instant::now();
        let agg_circuit = FalconAggCircuit::<F, C, D>::new();
        let agg_list_circuit = AggListCircuit::<F, C, D>::new(&agg_circuit.verifier_data());
        let list_proof = bwgen
            .borrow()
            .build_agg_sig_list_proof(&agg_circuit, &agg_list_circuit)
            .expect("bp signature list proof");
        let validity_circuit =
            ValidityCircuit::<F, C, D>::new(&block_chain_vd, &agg_list_circuit.verifier_data());
        let validity_prover = Address::default();
        let validity_proof = validity_circuit
            .prove(
                &final_block_chain_proof,
                list_proof.as_ref(),
                validity_prover,
            )
            .expect("validity proof");
        validity_circuit
            .data
            .verify(validity_proof.clone())
            .expect("validity proof verifies");
        eprintln!("[PW BENCH] validity prove={:?}", timer.elapsed());
        let block_chain_inputs = BlockChainPublicInputs::<F, C, D>::from_u64_slice(
            &final_block_chain_proof.public_inputs.to_u64_vec(),
            &block_chain_vd.common.config,
        )
        .expect("block chain PIs");
        let vpis = ValidityPublicInputs::from_states(
            &block_chain_inputs.initial_ext_public_state,
            &block_chain_inputs.ext_public_state,
            validity_prover,
        );
        assert_eq!(
            vpis.final_ext_commitment,
            final_ext_state.commitment(),
            "validity proof must end at the generator's current extended state"
        );
        assert_eq!(vpis.initial_ext_commitment, finalized_state_root);

        let timer = Instant::now();
        let wrapper = WrapperCircuit::<F, C, C, D>::new(&validity_circuit.data.verifier_data());
        let wrapped = wrapper.prove(&validity_proof).expect("wrap validity proof");
        wrapper
            .data
            .verify(wrapped)
            .expect("wrapped validity proof verifies");
        let vk = setup_mle_vk_v2::<F, C, D>(&wrapper.data);
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&wrapper.wrap_proof, &validity_proof)
            .expect("wrap witness");
        let mle = prove_with_mle_v2::<F, C, D>(&wrapper.data, pw).expect("validity MLE proof");
        verify_mle_proof_v2(&wrapper.data, &vk, &mle.proof).expect("validity MLE verifies");
        let mle_json =
            export_mle_v2_json(&mle.proof, &vk, &wrapper.data).expect("export validity MLE");
        let deployed_config = std::fs::read_to_string(data_dir.join("mle_fixture_config.json"))
            .expect("read the deployed validity config");
        let payload = validate_mle_v2_full_against_config_json(&mle_json, &deployed_config)
            .expect("PW validity proof must match the deployed validity adapter config");
        let (proof_hash, proof_length) =
            mle_v2_compact_submission_metadata(&mle_json, &deployed_config).expect("metadata");
        eprintln!(
            "[PW BENCH] validity wrap+MLE={:?} compact={} bytes",
            timer.elapsed(),
            payload.len()
        );
        std::fs::write(pw_e2e_dir.join("pw_lifecycle_validity_mle.json"), &mle_json).unwrap();
        let lifecycle = serde_json::json!({
            "genesis_state_root": vpis.initial_ext_commitment.to_hex(),
            "final_state_root": vpis.final_ext_commitment.to_hex(),
            "blocks": blocks.iter().map(|b| serde_json::json!({
                "channel_id": b.channel_id,
                "timestamp": b.timestamp,
                "tx_tree_root": b.tx_tree_root.to_hex(),
                "key_ids": b.key_ids,
            })).collect::<Vec<_>>(),
            "vpis": {
                "initial_block_number": vpis.initial_block_number.as_u64(),
                "initial_block_chain": vpis.initial_block_chain.to_hex(),
                "initial_ext_commitment": vpis.initial_ext_commitment.to_hex(),
                "final_block_number": vpis.final_block_number.as_u64(),
                "final_block_chain": vpis.final_block_chain.to_hex(),
                "final_ext_commitment": vpis.final_ext_commitment.to_hex(),
                "prover": format!("0x{}", hex::encode(validity_prover.to_bytes_be())),
            },
            "proof_hash": proof_hash,
            "proof_length": proof_length,
        });
        std::fs::write(
            pw_e2e_dir.join("pw_lifecycle.json"),
            serde_json::to_string_pretty(&lifecycle).unwrap(),
        )
        .unwrap();
        (blocks, payload, proof_hash, proof_length)
    };
    let validity_payload_path = pw_e2e_dir.join("validity-proof.bin");
    std::fs::write(&validity_payload_path, &validity_payload).unwrap();
    let final_state_root_hex = final_ext_state.commitment().to_hex();

    // ── Phase F: the burn's withdrawal proof (local), anchored at the root Phase E ends at ──
    // Exactly the live prover's recipe (`LiveBalanceService::burn_payout_artifacts`): the leaf is
    // READ OUT OF the single-withdrawal proof's public inputs, never recomputed by the payer.
    let payout_signer = Address::from_hex(PW_RECIPIENTS[0]).expect("payout signer");
    let artifacts = {
        let timer = Instant::now();
        let witness = bwg
            .single_withdrawal_witness(&burn_withdrawal_data)
            .expect("burn single-withdrawal witness");
        let single_circuit = SingleWithdawalCircuit::<F, C, D>::new(&balance_vd);
        let single_proof = single_circuit
            .prove(&witness)
            .expect("single withdrawal proof");
        single_circuit
            .data
            .verify(single_proof.clone())
            .expect("single withdrawal proof verifies");
        let single_millis = timer.elapsed().as_millis() as u64;
        let single_proof_bytes = single_proof.to_bytes().len();
        let withdrawal = SingleWithdawalPublicInputs::from_u64_slice(
            &single_proof.public_inputs[..SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN].to_u64_vec(),
        )
        .expect("single withdrawal PIs")
        .withdrawal;
        // The PI-decoded leaf is the one `cosign-burn-send` records at burn time.
        let expected = burn_withdrawal_leaf(
            desc.source_channel_id,
            desc.receiver_pk_g,
            desc.inter_channel_tx.token_index,
            burn_amount,
            burn_aux_data,
            desc.tx_v2.nonce,
        )
        .expect("burn withdrawal leaf");
        assert_eq!(withdrawal.recipient, withdrawal_addr, "proved recipient");
        assert_eq!(withdrawal.recipient, expected.recipient);
        assert_eq!(withdrawal.token_index, expected.token_index);
        assert_eq!(withdrawal.amount, u256(burn_amount), "proved amount");
        assert_eq!(withdrawal.nullifier, expected.nullifier, "proved nullifier");
        assert_eq!(
            withdrawal.aux_data, burn_aux_data,
            "proved IMD2 burn descriptor"
        );

        let timer = Instant::now();
        let processor = WithdrawalProcessor::<F, C, D>::new(&single_circuit.data.verifier_data());
        let chain_proof = processor
            .prove_step(&WithdrawalStepWitness::<F, C, D> {
                prev_withdrawal_chain_proof: None,
                single_withdrawal_proof: single_proof,
                update_public_state: witness.update_public_state.clone(),
            })
            .expect("withdrawal chain proof");
        let chain_millis = timer.elapsed().as_millis() as u64;
        let chain_proof_bytes = chain_proof.to_bytes().len();
        let timer = Instant::now();
        let final_proof = processor
            .prove_final(&chain_proof, payout_signer, &final_ext_state)
            .expect("final withdrawal proof");
        processor
            .withdrawal_vd()
            .verify(final_proof.clone())
            .expect("final withdrawal proof verifies");
        let final_millis = timer.elapsed().as_millis() as u64;
        let final_proof_bytes = final_proof.to_bytes().len();

        let timer = Instant::now();
        let wrapper = WrapperCircuit::<F, C, C, D>::new(&processor.withdrawal_vd());
        let wrapped = wrapper.prove(&final_proof).expect("wrap withdrawal proof");
        wrapper
            .data
            .verify(wrapped)
            .expect("wrapped withdrawal proof verifies");
        let vk = setup_mle_vk_v2::<F, C, D>(&wrapper.data);
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&wrapper.wrap_proof, &final_proof)
            .expect("withdrawal wrap witness");
        let mle = prove_with_mle_v2::<F, C, D>(&wrapper.data, pw).expect("withdrawal MLE proof");
        verify_mle_proof_v2(&wrapper.data, &vk, &mle.proof).expect("withdrawal MLE verifies");
        let withdrawal_mle_json =
            export_mle_v2_json(&mle.proof, &vk, &wrapper.data).expect("export withdrawal MLE");
        let deployed = std::fs::read_to_string(data_dir.join("withdrawal_mle_config.json"))
            .expect("read the deployed withdrawal config");
        validate_mle_v2_full_against_config_json(&withdrawal_mle_json, &deployed).expect(
            "the burn's payout proof must match the deployed withdrawal adapter config \
             (Deploy.s.sol pins test/data/withdrawal_mle_config.json). The balance circuit, \
             hence the withdrawal VK, depends on the `authenticated-tail-receive` feature: the \
             config fixtures must come from a build with this test's feature set",
        );
        let wrap_millis = timer.elapsed().as_millis() as u64;
        eprintln!(
            "[PW BENCH] withdrawal single={single_millis}ms chain={chain_millis}ms \
             final={final_millis}ms wrap+MLE={wrap_millis}ms MLE JSON={} bytes",
            withdrawal_mle_json.len()
        );

        // This test has no producer journal; the anchor's journal-only fields are tags. The
        // payout-relevant fields (block number, extended state commitment) are the real ones the
        // proof is bound to and Phase I finalizes.
        let anchor = BlockProducerAnchor {
            generation: 4,
            entry_hash: Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0xE2E, 4]).unwrap(),
            block_number: final_ext_state.inner.block_number.as_u64(),
            timestamp: pw_lifecycle_json.last().expect("burn block").timestamp,
            extended_state_commitment: final_ext_state.commitment(),
            bp_sig_chain: final_ext_state.bp_sig_chain,
        };
        assert_eq!(anchor.block_number, 4);
        let payout_json = serde_json::to_string_pretty(&serde_json::json!({
            "withdrawals": [{
                "recipient": withdrawal.recipient.to_string(),
                "token_index": withdrawal.token_index,
                "amount": withdrawal.amount.to_string(),
                "nullifier": withdrawal.nullifier.to_string(),
                "aux_data": withdrawal.aux_data.to_string(),
            }],
            "withdrawal_prover": payout_signer.to_string(),
            "block_number": anchor.block_number,
            "ext_commitment": anchor.extended_state_commitment.to_string(),
        }))
        .unwrap();
        PartialWithdrawalProofArtifacts {
            withdrawal,
            withdrawal_prover: payout_signer,
            payout_json,
            metrics: PartialWithdrawalProofMetrics {
                single_withdrawal_millis: single_millis,
                withdrawal_chain_millis: chain_millis,
                withdrawal_final_millis: final_millis,
                wrap_mle_millis: wrap_millis,
                single_withdrawal_proof_bytes: single_proof_bytes,
                withdrawal_chain_proof_bytes: chain_proof_bytes,
                withdrawal_final_proof_bytes: final_proof_bytes,
                mle_json_bytes: withdrawal_mle_json.len(),
                peak_rss_bytes: None,
            },
            withdrawal_mle_json,
            producer_anchor: anchor,
        }
    };

    // Stage the channel working directory exactly as the relay does before `pw-finalize`.
    let workdir = pw_e2e_dir.join("ch42");
    let _ = std::fs::remove_dir_all(&workdir);
    std::fs::create_dir_all(&workdir).unwrap();
    let write = |name: &str, value: &serde_json::Value| {
        std::fs::write(
            workdir.join(name),
            serde_json::to_string_pretty(value).unwrap(),
        )
        .unwrap()
    };
    // The channel's backing record names the rollup that pays; no settlement manager exists.
    write(
        "channel_backing.json",
        &serde_json::json!({
            "settled_tx_chain": genesis_chain.to_hex(),
            "intmax_state_root": finalized_state_root.to_hex(),
            "fund": fund,
            "rollup": rollup,
        }),
    );
    write(
        "burn_cosigned.json",
        &serde_json::to_value(&next_state).expect("signed burn head JSON"),
    );
    let burn_receipt = BlockProducerReceipt {
        request_id: "pw-e2e-burn".into(),
        generation: artifacts.producer_anchor.generation,
        entry_hash: artifacts.producer_anchor.entry_hash,
        block_number: artifacts.producer_anchor.block_number,
        timestamp: artifacts.producer_anchor.timestamp,
        extended_state_commitment: artifacts.producer_anchor.extended_state_commitment,
        bp_sig_chain: artifacts.producer_anchor.bp_sig_chain,
    };
    write(
        "pw_producer.json",
        &serde_json::json!({
            "producerRequestId": burn_receipt.request_id,
            "blockReceipt": burn_receipt,
            // The live settle reports the post-burn cursor; the burn consumed the one before it.
            "liveReceipt": { "baseNonce": desc.tx_v2.nonce + 1 },
        }),
    );
    write(
        "pw_artifacts.json",
        &serde_json::to_value(&artifacts).expect("artifacts JSON"),
    );

    // ── Phase G: post the four blocks and attest their proof data ──────────────────────────
    // On chain: registration block, then the real deposit, then the remaining blocks; every
    // post is an EIP-4844 blob transaction carrying the validity proof-DA payload.
    let mut final_submission = None;
    for (i, block) in pw_lifecycle_json.iter().enumerate() {
        if i == 1 {
            let onchain_depositor =
                real_onchain_deposit(&rpc, &rollup, recipient, fund, Bytes32::default());
            assert_eq!(
                onchain_depositor, depositor,
                "the deposit mirror named the depositor"
            );
            eprintln!("[PW E2E] real deposit of {fund} wei landed after the registration block");
        }
        let (submission_id, sidecars) = post_block_with_blob(
            &rpc,
            &rollup,
            &sub_block_literal(block),
            &validity_payload_path,
            &validity_payload,
            &validity_proof_hash,
            validity_proof_length,
            &final_state_root_hex,
        );
        assert_eq!(
            submission_id as usize, i,
            "submissions are posted in block order"
        );
        eprintln!(
            "[PW E2E] posted block {} as submission {submission_id} ({} blob(s))",
            i + 1,
            sidecars.blob_versioned_hashes.len()
        );
        final_submission = Some((submission_id, sidecars));
    }
    let (final_submission_id, final_sidecars) = final_submission.expect("four posts");
    let pw_e2e_dir_s = pw_e2e_dir.to_str().expect("utf-8 pw-e2e dir").to_string();
    let final_submission_s = final_submission_id.to_string();
    lifecycle_script(
        &contracts,
        &rpc,
        "attestProofData()",
        &[
            ("ROLLUP", rollup.as_str()),
            ("SUB_ID", final_submission_s.as_str()),
            ("BLOB_SIDECARS", final_sidecars.compact_sidecars.as_str()),
            ("PW_E2E_DIR", pw_e2e_dir_s.as_str()),
        ],
    );

    // ── Phase H: before L1 finalizes the anchor root, pw-finalize refuses and journals nothing
    let (ok, stdout, stderr) = pw_finalize(&workdir, &contracts, &rpc);
    assert!(
        !ok && stderr.contains("payout anchor is not L1-finalized")
            && stderr.contains("retry after the finalized head advances"),
        "pw-finalize must refuse a proof anchored at an unfinalized root\nstdout: {stdout}\nstderr: {stderr}"
    );
    {
        let store = PartialWithdrawalPayoutStore::open(workdir.join("pw_payout_store.bin"))
            .expect("payout journal after refusal");
        let candidate = store
            .active()
            .unwrap()
            .expect("candidate prepared before the gate");
        assert!(
            candidate.payout_broadcast.is_none() && candidate.payout_tx_hashes.is_empty(),
            "the anchor gate must refuse before any payout intent is journaled"
        );
    }
    assert!(
        !bool_view(
            &rpc,
            &rollup,
            "withdrawalNullifierUsed(bytes32)",
            &artifacts.withdrawal.nullifier.to_hex()
        ),
        "nothing was paid before finalization"
    );
    eprintln!("[PW E2E] pw-finalize refused the unfinalized anchor without journaling a payout");

    // ── Phase I: finalize the 4-block chain on L1 ─────────────────────────────────────────
    let finalize_out = lifecycle_script(
        &contracts,
        &rpc,
        "finalize()",
        &[
            ("ROLLUP", rollup.as_str()),
            ("SUB_ID", final_submission_s.as_str()),
            ("PW_E2E_DIR", pw_e2e_dir_s.as_str()),
        ],
    );
    assert!(
        finalize_out.contains("PW_E2E_FINALIZED_BLOCK: 4"),
        "finalize must land the 4-block chain:\n{finalize_out}"
    );
    assert!(
        bool_view(
            &rpc,
            &rollup,
            "isFinalizedStateRoot(bytes32)",
            &final_state_root_hex
        ),
        "the burn block's root must now be a finalized state root"
    );
    eprintln!("[PW E2E] 4-block chain finalized on anvil at {final_state_root_hex}");

    // ── Phase J: pw-finalize pays the burn by its proof and the recipient pulls ─────────────
    let recipient_hex = format!("0x{}", hex::encode(withdrawal_addr.to_bytes_be()));
    let escrow_before = u256_view(&rpc, &rollup, "totalEscrowed()(uint256)", &[]);
    let (ok, stdout, stderr) = pw_finalize(&workdir, &contracts, &rpc);
    assert!(
        ok,
        "pw-finalize must pay the finalized burn\nstdout: {stdout}\nstderr: {stderr}"
    );
    let result: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("pw-finalize stdout must be one JSON line ({e}): {stdout}"));
    assert_eq!(result["complete"], true, "{result}");
    assert_eq!(result["recipientPullDelegated"], false, "{result}");
    assert!(
        result["payoutTxHash"].is_string() && result["pullTxHash"].is_string(),
        "{result}"
    );
    assert_eq!(result["amount"], burn_amount.to_string(), "{result}");
    assert_eq!(
        result["nullifier"].as_str().map(str::to_lowercase),
        Some(artifacts.withdrawal.nullifier.to_hex().to_lowercase()),
        "{result}"
    );
    assert!(
        bool_view(
            &rpc,
            &rollup,
            "withdrawalNullifierUsed(bytes32)",
            &artifacts.withdrawal.nullifier.to_hex()
        ),
        "the proof-committed nullifier is consumed"
    );
    let escrow_after = u256_view(&rpc, &rollup, "totalEscrowed()(uint256)", &[]);
    assert_eq!(
        escrow_before - escrow_after,
        u128::from(burn_amount),
        "the escrow pays exactly the burned amount"
    );
    assert_eq!(
        u256_view(
            &rpc,
            &rollup,
            "pendingWithdrawals(address)(uint256)",
            &[&recipient_hex]
        ),
        0,
        "the recipient pulled its whole credit"
    );
    eprintln!(
        "[PW E2E] burn of {burn_amount} wei paid to {recipient_hex} by its withdrawal proof and pulled"
    );

    // ── Phase K: idempotent re-run, and the nullifier makes the payout single-use ───────────
    let (ok, rerun_stdout, stderr) = pw_finalize(&workdir, &contracts, &rpc);
    assert!(
        ok,
        "a re-run after completion is a no-op success\nstderr: {stderr}"
    );
    let rerun: serde_json::Value = serde_json::from_str(rerun_stdout.trim()).expect("re-run JSON");
    assert_eq!(rerun["payoutTxHash"], result["payoutTxHash"]);
    assert_eq!(rerun["pullTxHash"], result["pullTxHash"]);
    // Replay the exact script inputs pw-finalize staged for this candidate.
    let staged = contracts
        .parent()
        .expect("repo root")
        .join("proof-da-output")
        .join(format!(
            "pw-payout-{}",
            result["candidateId"].as_str().expect("candidateId")
        ));
    let replay = Command::new("forge")
        .current_dir(&contracts)
        .env("ROLLUP", &rollup)
        .env("PW_PAYOUT_PATH", staged.join("payout.json"))
        .env("PW_MLE_PATH", staged.join("withdrawal_mle.json"))
        .args([
            "script",
            "script/RunPartialWithdrawalPayout.s.sol",
            "--sig",
            "withdrawNativeStep()",
            "--rpc-url",
            &rpc,
            "--private-key",
            ANVIL0,
            "--broadcast",
            "--code-size-limit",
            "50000",
        ])
        .output()
        .expect("spawn replayed payout");
    let replay_out = format!(
        "{}{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        !replay.status.success() && replay_out.contains("WithdrawalNullifierUsed"),
        "a replayed proof payout must revert on the used nullifier: {replay_out}"
    );
    assert_eq!(
        u256_view(&rpc, &rollup, "totalEscrowed()(uint256)", &[]),
        escrow_after,
        "the rejected replay moved no escrow"
    );

    eprintln!(
        "[PW E2E] ALL PASSED: deposit → burn → validity finalize → proof-only payout → pull, \
         unfinalized anchor refused, re-run idempotent, replay rejected by the nullifier."
    );
}

/// `channel_member pw-finalize` in a relay-shaped channel working directory, signed by the proved
/// recipient (anvil account 1) so the pull leg runs too. Anvil serves `finalized` 64 blocks behind
/// `latest`; `INTMAX_WALLET_ANVIL_MINE=1` mines real empty blocks so the finalized tag covers each
/// transaction, as the local wallet runner does. Like the relay, retry only the transient
/// historical-state error that can follow such mining; every re-run resumes the durable journal.
fn pw_finalize(workdir: &Path, contracts: &Path, rpc: &str) -> (bool, String, String) {
    for attempt in 0..3 {
        let out = Command::new(env!("CARGO_BIN_EXE_channel_member"))
            .args(["pw-finalize", rpc])
            .current_dir(workdir)
            .env("INTMAX_CHANNEL", "42")
            .env("CONTRACTS_DIR", contracts)
            .env("INTMAX_DEPOSIT_KEY", RECIPIENT_KEY)
            .env("INTMAX_WALLET_ANVIL_MINE", "1")
            .env_remove("INTMAX_L1_ACCOUNT")
            .env_remove("INTMAX_ALLOW_UNFINALIZED_DEVNET")
            .output()
            .expect("spawn channel_member pw-finalize");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if out.status.success() || attempt == 2 || !stderr.contains("BlockOutOfRangeError") {
            return (out.status.success(), stdout, stderr);
        }
        std::thread::sleep(std::time::Duration::from_secs(attempt + 1));
    }
    unreachable!()
}

fn bool_view(rpc: &str, contract: &str, sig: &str, arg: &str) -> bool {
    let out = cast(rpc, &["call", contract, sig, arg], sig);
    let out = out.trim();
    out == "true" || out.ends_with("01")
}

fn u256_view(rpc: &str, contract: &str, sig: &str, args: &[&str]) -> u128 {
    let mut argv = vec!["call", contract, sig];
    argv.extend_from_slice(args);
    let out = cast(rpc, &argv, sig);
    out.split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("{sig}: unparsable {out}"))
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
