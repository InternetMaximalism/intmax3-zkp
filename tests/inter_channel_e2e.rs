//! B-1: genuine channel→channel transfer, no fabrication of the security-bearing parts.
//!
//! detail2 §C-6/§E-2/§3.4, abstract2 §2.3/§3.4. Two channels are each backed by a REAL on-chain ETH
//! deposit (real `balanceProof`, §F-1 reconciled), built from REAL member keys (so the verifier's
//! `regev_pk_root` check is genuine), and a REAL E-2 `channelUpdateZKP` carries the inter-channel
//! transfer (equal-magnitude / opposite-sign deltas, sender balance ≥ amount — no negative/inflation,
//! correct ciphertexts to both `RegevPk`s). The InterChannel send / fund-import / receiver-bundle
//! transitions verify with the REAL Regev verifier.
//!
//! Documented base-layer artifact (NOT in B-1 scope, = B-2): the small-block signature and the
//! intmax transport proof remain structural — detail2 treats them as validity-proven in the base
//! layer (§F-2 `update_channel_tree`). Everything cryptographically bearing on channel soundness
//! here (deposit backing, E-2, regev_pk_root, §F-1) is real. Skips if foundry is absent.
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    circuits::{
        balance::{
            balance_processor::BalanceProcessor,
            common::recipient::calculate_recipient_from_user_id, spend_circuit::SpendCircuit,
        },
        channel::state_update_verifier::{
            ChannelProofEnvelope, ChannelProofVerifier, ChannelStateUpdateError,
            ChannelStateUpdatePublicInputs, InterChannelFundImportUpdateWitness,
            InterChannelSendUpdateWitness, ReceiverBundleApplyUpdateWitness,
        },
        test_utils::{
            balance_witness_generator::{BalanceWitnessGenerator, ReceiveDepositData},
            block_witness_generator::{BlockWitnessGenerator, BlockWitnessGeneratorHandle},
        },
    },
    common::{
        balance_state::{settled_tx_chain_push, tx_leaf_hash, BalanceState},
        channel::{
            ChannelFund, ChannelRecord, ChannelState, ChannelTransitionKind, InterChannelTx,
            MemberSignature, MerkleInclusionProof, ProofBackend, ReceiverBalanceDelta,
            SignedSmallBlock, SmallBlockRootMessage, TransitionProofRole,
        },
        channel_id::ChannelId,
        deposit::Deposit,
        salt::Salt,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
    regev::{
        RealRegevProofVerifier, RegevCiphertext, RegevPk, RegevSecurityLevel, RegevSk,
        add_ciphertexts, encrypt_amount, prove_channel_update, regev_pk_root,
    },
    wallet_core::{
        ChannelBalanceAttestation, MemberInfo, MemberKeys, add_signature,
        assemble_genesis_state_backed, build_record, sign_state, sign_state_if_backed,
        verify_all_signatures, verify_channel_backing,
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
const VERIFIER: RealRegevProofVerifier = RealRegevProofVerifier { level: LEVEL };
const ANVIL0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PORT: u16 = 8551;

// Documented base-layer artifact: the intmax transport / small-block validity is proven in the base
// layer (detail2 §F-2). B-1 checks its STRUCTURE only; the soundness-bearing E-2 + §F-1 are real.
struct StructuralTransport;
impl ChannelProofVerifier for StructuralTransport {
    fn verify(
        &self,
        proof: &ChannelProofEnvelope,
        _pis: &ChannelStateUpdatePublicInputs,
    ) -> Result<(), ChannelStateUpdateError> {
        if proof.proof.is_empty() {
            return Err(ChannelStateUpdateError::ProofVerification("empty transport".into()));
        }
        Ok(())
    }
}

/// All-zero update PIs — the structural transport gate ignores them, so this is only a placeholder
/// to satisfy the `verify` signature in the unit negative below.
fn zero_update_pis() -> ChannelStateUpdatePublicInputs {
    ChannelStateUpdatePublicInputs {
        kind: ChannelTransitionKind::InterChannelSend,
        channel_id: ChannelId::default(),
        prev_state_digest: Bytes32::default(),
        next_state_digest: Bytes32::default(),
        amount: 0,
        prev_state_version: 0,
        next_state_version: 0,
        h2_tag: Bytes32::default(),
        prev_settled_tx_chain: Bytes32::default(),
        next_settled_tx_chain: Bytes32::default(),
        receiver_entry_count: 0,
        sender_user_id_hash: Bytes32::default(),
        receiver_user_id_hash: Bytes32::default(),
        channel_fund_before: U256::default(),
        channel_fund_after: U256::default(),
        unallocated_before: U256::default(),
        unallocated_after: U256::default(),
        shared_nullifier_before: Bytes32::default(),
        shared_nullifier_after: Bytes32::default(),
        transition_digest: Bytes32::default(),
    }
}

/// B-5c: this file's main flow is a STRUCTURAL SMOKE E2E — the soundness-bearing parts (real deposit
/// backing, real E-2 `channelUpdateZKP`, `regev_pk_root`, §F-1) are genuine, but the transport /
/// small-block validity is a documented base-layer artifact (detail2 §F-2) checked only for
/// STRUCTURE via `StructuralTransport`, with constant stand-ins like `vec![7,7,7]`. The
/// soundness-bearing inter-channel negatives (forged N-of-N A-state with no committed debit, tampered
/// amount, replay, atomicity) live in `tests/inter_channel_live.rs` and `tests/inter_channel_cli.rs`.
/// This fast unit test at least pins the structural gate itself so it can never silently degrade to a
/// no-op: an EMPTY transport is rejected (with the expected reason); a non-empty one passes.
#[test]
fn structural_transport_rejects_empty_proof() {
    let pis = zero_update_pis();

    let empty = ChannelProofEnvelope {
        role: TransitionProofRole::IntmaxTransport,
        backend: ProofBackend::Plonky2,
        proof: vec![],
    };
    let err = StructuralTransport.verify(&empty, &pis);
    assert!(err.is_err(), "empty transport MUST be rejected by the structural gate");
    let msg = format!("{:?}", err.unwrap_err());
    assert!(msg.contains("empty transport"), "rejection must cite the empty transport, got: {msg}");

    let nonempty = ChannelProofEnvelope {
        role: TransitionProofRole::IntmaxTransport,
        backend: ProofBackend::Plonky2,
        proof: vec![1],
    };
    StructuralTransport
        .verify(&nonempty, &pis)
        .expect("a non-empty transport passes the structural gate");
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
    let out = cmd.output().unwrap_or_else(|e| panic!("{label}: {e}"));
    assert!(out.status.success(), "{label} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).to_string()
}
fn cast(rpc: &str, args: &[&str], label: &str) -> String {
    run_capture(Command::new("cast").args(args).arg("--rpc-url").arg(rpc), label)
}
fn abi_word(data: &str, i: usize) -> &str {
    &data[i * 64..(i + 1) * 64]
}
fn info(slot: u8, k: &MemberKeys) -> MemberInfo {
    MemberInfo { slot, pk_g: k.pk_g(), pk_b: k.pk_b(), regev_pk: k.regev_pk.clone() }
}
fn pks_array(keys: &[MemberKeys]) -> [RegevPk; intmax3_zkp::constants::MAX_CHANNEL_MEMBERS] {
    let mut arr: [RegevPk; intmax3_zkp::constants::MAX_CHANNEL_MEMBERS] =
        std::array::from_fn(|_| RegevPk::padding());
    for (i, k) in keys.iter().enumerate() {
        arr[i] = k.regev_pk.clone();
    }
    arr
}

/// Make a REAL ETH deposit to `recipient` on the live chain; assert the Rust deposit reproduces the
/// on-chain depositHashChain (keystone, `prev` = cumulative chain so far), and return the depositor.
fn real_onchain_deposit(
    rpc: &str,
    rollup: &str,
    recipient: Bytes32,
    amount: u64,
    prev_chain: Bytes32,
) -> Address {
    let send = run_capture(
        Command::new("cast").args([
            "send", rollup, "deposit(bytes32,uint32,uint256,bytes32)", &recipient.to_hex(), "0",
            &amount.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--value", &amount.to_string(), "--private-key", ANVIL0, "--rpc-url", rpc, "--json",
        ]),
        "cast deposit",
    );
    let txhash = send.split("\"transactionHash\":\"").nth(1).and_then(|s| s.split('"').next()).expect("tx");
    let receipt = cast(rpc, &["receipt", txhash, "--json"], "receipt");
    let data = receipt.split("\"data\":\"0x").nth(1).and_then(|s| s.split('"').next()).expect("log");
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
    assert_eq!(d.hash_with_prev_hash(prev_chain), onchain, "Rust deposit hash != on-chain chain");
    depositor
}

#[test]
fn inter_channel_transfer_real_deposit_backed() {
    if !(tool_present("anvil") && tool_present("forge") && tool_present("cast")) {
        eprintln!("[skip] foundry not found — inter-channel test needs real on-chain deposits");
        return;
    }
    use rand::SeedableRng as _;
    use rand010::SeedableRng as _;
    let rpc = format!("http://127.0.0.1:{PORT}");
    let anvil = Command::new("anvil")
        .args(["--hardfork", "prague", "--port", &PORT.to_string()])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("anvil");
    let _guard = AnvilGuard(anvil);
    let mut up = false;
    for _ in 0..40 {
        if Command::new("cast").args(["block-number", "--rpc-url", &rpc])
            .stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
        { up = true; break; }
        thread::sleep(Duration::from_millis(250));
    }
    assert!(up, "anvil down");
    let contracts = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts");
    let deploy = run_capture(
        Command::new("forge").current_dir(&contracts).args([
            "script", "script/Deploy.s.sol", "--rpc-url", &rpc, "--private-key", ANVIL0, "--broadcast",
        ]),
        "forge deploy",
    );
    let rollup = deploy.lines()
        .find_map(|l| l.split("IntmaxRollup").nth(1).and_then(|s| s.split("0x").nth(1)))
        .map(|s| format!("0x{}", &s.trim()[..40])).expect("rollup addr");

    // ---- Prover + two channels A(=5) and B(=7), each with REAL keys ----------------------------
    let spend = SpendCircuit::<F, C, D>::new();
    let bp = BalanceProcessor::<F, C, D>::new(&spend.data.verifier_data());
    let bwgen = BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&[1, 4, 512]));
    let balance_vd = bp.balance_vd();

    let mut crng = rand010::rngs::StdRng::seed_from_u64(0xB1);
    let a_id = ChannelId::new(5).unwrap();
    let b_id = ChannelId::new(7).unwrap();
    let a_keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut crng)).collect();
    let b_keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut crng)).collect();
    let a_members: Vec<MemberInfo> = a_keys.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect();
    let b_members: Vec<MemberInfo> = b_keys.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect();
    let a_record = build_record(5, &a_members, 0, 0).expect("A record");
    let b_record = build_record(7, &b_members, 0, 0).expect("B record");
    let a_pks = pks_array(&a_keys);
    let b_pks = pks_array(&b_keys);

    // Channel A fund = 90 (alice 50, bob 10, carol 30); B fund = 40 (dave 20, erin 10, frank 10).
    let a_bal = [50u64, 10, 30];
    let b_bal = [20u64, 10, 10];
    let a_fund: u64 = a_bal.iter().sum();
    let b_fund: u64 = b_bal.iter().sum();

    // ---- REAL on-chain deposit backing for each channel → balanceProof + settled_tx_chain ------
    let mut brng = rand::rngs::StdRng::seed_from_u64(0xDEadBeef);
    // Channel A.
    let a_salt = Salt::rand(&mut brng);
    let a_recipient = calculate_recipient_from_user_id(a_id, a_salt);
    let a_depositor = real_onchain_deposit(&rpc, &rollup, a_recipient, a_fund, Bytes32::default());
    bwgen.borrow_mut().add_deposit(a_depositor, a_recipient, 0, U256::from(a_fund as u32), Bytes32::default()).unwrap();
    bwgen.borrow_mut().add_block(0, &[], 0, Bytes32::default()).unwrap();
    let mut a_bwg = BalanceWitnessGenerator::new(a_id, Salt::rand(&mut brng), bwgen.clone(), &bp).unwrap();
    let a_dw = a_bwg.receive_deposit_witness(&ReceiveDepositData { receiver: a_recipient, deposit_salt: a_salt }).unwrap();
    let a_proof = bp.prove_receive_deposit(&a_dw).unwrap();
    a_bwg.commit_receive_deposit(&a_proof, &a_dw).unwrap();
    let a_chain = a_bwg.get_public_inputs().unwrap().settled_tx_chain;
    let a_att = ChannelBalanceAttestation { balance_proof: a_proof.to_bytes() };
    // Channel B (prev cumulative chain = A's on-chain deposit hash).
    let a_onchain = Deposit { deposit_index: Default::default(), block_number: Default::default(),
        depositor: a_depositor, recipient: a_recipient, token_index: 0, amount: U256::from(a_fund as u32),
        aux_data: Bytes32::default() }.hash_with_prev_hash(Bytes32::default());
    let b_salt = Salt::rand(&mut brng);
    let b_recipient = calculate_recipient_from_user_id(b_id, b_salt);
    let b_depositor = real_onchain_deposit(&rpc, &rollup, b_recipient, b_fund, a_onchain);
    bwgen.borrow_mut().add_deposit(b_depositor, b_recipient, 0, U256::from(b_fund as u32), Bytes32::default()).unwrap();
    bwgen.borrow_mut().add_block(0, &[], 0, Bytes32::default()).unwrap();
    let mut b_bwg = BalanceWitnessGenerator::new(b_id, Salt::rand(&mut brng), bwgen.clone(), &bp).unwrap();
    let b_dw = b_bwg.receive_deposit_witness(&ReceiveDepositData { receiver: b_recipient, deposit_salt: b_salt }).unwrap();
    let b_proof = bp.prove_receive_deposit(&b_dw).unwrap();
    b_bwg.commit_receive_deposit(&b_proof, &b_dw).unwrap();
    let b_chain = b_bwg.get_public_inputs().unwrap().settled_tx_chain;
    let b_att = ChannelBalanceAttestation { balance_proof: b_proof.to_bytes() };

    // ---- Genesis (deposit-backed) signed by REAL members; §F-1 reconciles on BOTH channels ------
    // Build A's genesis ciphertexts RETAINING alice's witness (slot 0) — the E-2 `before` MUST be the
    // exact genesis ciphertext the verifier reads from `prev_state.enc_balances[0]`.
    let (a_ct0, a_w0) = encrypt_amount(&mut crng, &a_pks[0], a_bal[0]).unwrap();
    let a_ct1 = encrypt_amount(&mut crng, &a_pks[1], a_bal[1]).unwrap().0;
    let a_ct2 = encrypt_amount(&mut crng, &a_pks[2], a_bal[2]).unwrap().0;
    let a_cts = [a_ct0.clone(), a_ct1, a_ct2];
    let b_cts: Vec<RegevCiphertext> =
        (0..3).map(|i| encrypt_amount(&mut crng, &b_pks[i], b_bal[i]).unwrap().0).collect();
    let a_genesis = build_signed_genesis(&a_record, &a_keys, &a_cts, a_fund, a_chain, &a_att, &balance_vd);
    let b_genesis = build_signed_genesis(&b_record, &b_keys, &b_cts, b_fund, b_chain, &b_att, &balance_vd);
    verify_channel_backing(&a_record, &a_genesis, Some(&a_att), &balance_vd).expect("A §F-1");
    verify_channel_backing(&b_record, &b_genesis, Some(&b_att), &balance_vd).expect("B §F-1");

    // ---- REAL inter-channel send: alice (A slot 0) → dave (B slot 0), amount 5 -------------------
    const AMT: u64 = 5;
    let (alice_after_ct, alice_after_w) = encrypt_amount(&mut crng, &a_pks[0], a_bal[0] - AMT).unwrap();
    let sender_delta = encrypt_amount(&mut crng, &a_pks[0], AMT).unwrap();
    let receiver_delta = encrypt_amount(&mut crng, &b_pks[0], AMT).unwrap();
    let e2 = prove_channel_update(
        LEVEL, &a_pks[0], &b_pks[0],
        (&a_ct0, &a_w0), // before = the genesis ciphertext at alice's slot
        (&alice_after_ct, &alice_after_w),
        (&sender_delta.0, &sender_delta.1),
        (&receiver_delta.0, &receiver_delta.1),
        AMT,
    ).unwrap();

    let tx_leaf = tx_leaf_hash(a_keys[0].pk_g(), sender_delta.0.digest(), b_keys[0].pk_g(), receiver_delta.0.digest());
    let tx_tree_root = Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0x301]).unwrap(); // base-layer artifact

    // Source channel A state after the send (alice debited; settled_tx_chain absorbs the leaf).
    let mut a_send = ChannelState {
        epoch: a_genesis.epoch + 1,
        small_block_number: 1,
        channel_fund: ChannelFund { amount: a_genesis.channel_fund.amount - u256(AMT), ..a_genesis.channel_fund.clone() },
        balance_state: BalanceState {
            enc_balances: BalanceState::pad_enc_balances(&[
                alice_after_ct.clone(),
                a_genesis.balance_state.enc_balances[1].clone(),
                a_genesis.balance_state.enc_balances[2].clone(),
            ]),
            settled_tx_chain: settled_tx_chain_push(a_genesis.balance_state.settled_tx_chain, tx_leaf),
            state_version: 1,
            ..a_genesis.balance_state.clone()
        },
        h2_tag: tx_tree_root,
        // detail2 §C-3: a send advances the shared native nullifier root (must differ from prev).
        shared_native_nullifier_root: Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0x412]).unwrap(),
        prev_digest: a_genesis.digest,
        member_signatures: Vec::new(),
        ..a_genesis.clone()
    }.with_computed_digest();

    let inter_tx = InterChannelTx {
        tx_inclusion_proof: MerkleInclusionProof::default(),
        signed_small_block: SignedSmallBlock {
            message: SmallBlockRootMessage {
                channel_id: a_id,
                bp_member_slot: 0,
                bp_pk_g: a_keys[0].pk_g(),
                small_block_number: 1,
                prev_small_block_root: Bytes32::default(),
                tx_tree_root,
                state_commitment_root: a_send.balance_state.h1(),
                medium_epoch_hint: 3,
                close_freeze_nonce: 0,
            },
            // base-layer artifact (B-2): structural signatures + aggregate proof.
            signatures: structural_smallblock_sigs(&a_record),
            aggregated_signature_proof: vec![9, 9],
            medium_block_number: 4,
            confirmation_proof: vec![8, 8],
        },
        sender_delta_ct: sender_delta.0.clone(),
        source_channel_id: a_id,
        destination_channel_id: b_id,
        source_pk_g: a_keys[0].pk_g(),
        seal: Bytes32::default(),
        tx_hash: Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0x502]).unwrap(),
        intmax_transfer_commitment: Bytes32::default(),
        recipient_memo: vec![1, 2, 3],
        receiver_deltas: vec![ReceiverBalanceDelta { receiver_pk_g: b_keys[0].pk_g(), amount: receiver_delta.0.clone() }],
        channel_update_zkp: ChannelProofEnvelope { role: TransitionProofRole::ChannelStateUpdate, backend: ProofBackend::Plonky3, proof: e2 },
        transport_proof: vec![7, 7, 7],
    };
    let transport = ChannelProofEnvelope { role: TransitionProofRole::IntmaxTransport, backend: ProofBackend::Plonky2, proof: vec![7, 7, 7] };

    // REAL member co-signing of the post-send state (the next_state IS member-signed; verified for real).
    sign_real(&mut a_send, &a_keys);
    verify_all_signatures(&a_record, &record_members(&a_record, &a_keys), &a_send).expect("a_send member-signed");

    let send = InterChannelSendUpdateWitness {
        channel_record: a_record.clone(),
        regev_pks: a_pks.clone(),
        destination_recipient_pk: b_pks[0].clone(),
        prev_state: a_genesis.clone(),
        next_state: a_send.clone(),
        inter_channel_tx: inter_tx.clone(),
        amount: AMT,
        transport_proof: transport.clone(),
    };
    let tverify = StructuralTransport;
    let pis = send.verify(&tverify, &VERIFIER).expect("REAL inter-channel send verifies");
    assert_eq!(pis.kind, ChannelTransitionKind::InterChannelSend);
    assert_eq!(pis.amount, AMT, "inter-channel amount is public");

    // ---- Fund import on B: confirmed incoming → ChannelFund grows; settled_tx_chain absorbs tx_hash
    let mut b_import = ChannelState {
        epoch: b_genesis.epoch + 1,
        small_block_number: 1,
        channel_fund: ChannelFund { amount: b_genesis.channel_fund.amount + u256(AMT), ..b_genesis.channel_fund.clone() },
        balance_state: BalanceState {
            settled_tx_chain: settled_tx_chain_push(b_genesis.balance_state.settled_tx_chain, inter_tx.tx_hash),
            state_version: 1,
            ..b_genesis.balance_state.clone()
        },
        unallocated_confirmed_incoming: u256(AMT),
        shared_native_nullifier_root: Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0x603]).unwrap(),
        prev_digest: b_genesis.digest,
        ..b_genesis.clone()
    }.with_computed_digest();
    sign_real(&mut b_import, &b_keys);
    verify_all_signatures(&b_record, &record_members(&b_record, &b_keys), &b_import).expect("b_import member-signed");
    let import = InterChannelFundImportUpdateWitness {
        source_channel_record: a_record.clone(),
        receiver_channel_record: b_record.clone(),
        prev_state: b_genesis.clone(),
        next_state: b_import.clone(),
        inter_channel_tx: inter_tx.clone(),
        amount: AMT,
        transport_proof: transport.clone(),
    };
    let ipis = import.verify(&tverify).expect("REAL fund import verifies");
    assert_eq!(ipis.kind, ChannelTransitionKind::InterChannelFundImport);

    // ---- Receiver bundle apply on B: dave's slot += receiver_delta; settled_tx_chain absorbs leaf
    let dave_after = add_ciphertexts(&b_import.balance_state.enc_balances[0], &receiver_delta.0).unwrap();
    let mut b_bundle = ChannelState {
        epoch: b_import.epoch + 1,
        balance_state: BalanceState {
            enc_balances: BalanceState::pad_enc_balances(&[
                dave_after,
                b_import.balance_state.enc_balances[1].clone(),
                b_import.balance_state.enc_balances[2].clone(),
            ]),
            settled_tx_chain: settled_tx_chain_push(b_import.balance_state.settled_tx_chain, tx_leaf),
            state_version: 2,
            pending_adds: BalanceState::pad_pending_adds(&[1, 0, 0]),
            ..b_import.balance_state.clone()
        },
        unallocated_confirmed_incoming: U256::zero(),
        prev_digest: b_import.digest,
        ..b_import.clone()
    }.with_computed_digest();
    sign_real(&mut b_bundle, &b_keys);
    verify_all_signatures(&b_record, &record_members(&b_record, &b_keys), &b_bundle).expect("b_bundle member-signed");
    let bundle = ReceiverBundleApplyUpdateWitness {
        receiver_channel_record: b_record.clone(),
        regev_pks: b_pks.clone(),
        source_sender_pk: a_pks[0].clone(),
        sender_before_ct: a_ct0.clone(),
        sender_after_ct: alice_after_ct.clone(),
        prev_state: b_import.clone(),
        next_state: b_bundle.clone(),
        inter_channel_tx: inter_tx.clone(),
        amount: AMT,
        recipient_index: 0,
        recipient_sk: Some(b_keys[0].regev_sk.clone()),
        expected_amount: Some(AMT),
    };
    let bpis = bundle.verify(&VERIFIER).expect("REAL receiver bundle verifies (dave decrypts 5)");
    assert_eq!(bpis.kind, ChannelTransitionKind::ReceiverBundleApply);

    eprintln!("[B-1] OK: 2 real-deposit-backed channels, §F-1 on both, REAL E-2 inter-channel send + import + bundle.");
}

fn u256(v: u64) -> U256 {
    U256::from_u32_slice(&[0, 0, 0, 0, 0, 0, (v >> 32) as u32, v as u32]).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn build_signed_genesis(
    record: &ChannelRecord,
    keys: &[MemberKeys],
    cts: &[RegevCiphertext],
    fund: u64,
    settled_tx_chain: Bytes32,
    att: &ChannelBalanceAttestation,
    balance_vd: &VerifierCircuitData<F, C, D>,
) -> ChannelState {
    // Decryption Stage 1: per-active-slot Regev pk digests, in the SAME slot order as `cts`
    // (mirrors channel_member.rs:601-605).
    let regev_pk_digests: Vec<Bytes32> =
        keys.iter().map(|k| Bytes32::from(k.regev_pk.poseidon_digest())).collect();
    let mut state = assemble_genesis_state_backed(record, cts, &regev_pk_digests, fund, settled_tx_chain, Bytes32::default()).unwrap();
    for (slot, k) in keys.iter().enumerate() {
        let sig = sign_state_if_backed(k, slot as u8, record, &state, att, balance_vd).expect("genesis check-and-sign");
        add_signature(&mut state, sig);
    }
    verify_all_signatures(record, &record_members(record, keys), &state).expect("genesis fully signed");
    state
}

fn record_members(record: &ChannelRecord, keys: &[MemberKeys]) -> Vec<MemberInfo> {
    let _ = record;
    keys.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect()
}

/// REAL member co-signing of a next state (real Goldilocks SingleSig proofs over the IMCH digest).
fn sign_real(state: &mut ChannelState, keys: &[MemberKeys]) {
    for (slot, k) in keys.iter().enumerate() {
        let sig = sign_state(k, slot as u8, state).expect("real member signature");
        add_signature(state, sig);
    }
}
/// Structural small-block signatures (base-layer artifact, B-2): slot/pk match the record.
fn structural_smallblock_sigs(record: &ChannelRecord) -> Vec<MemberSignature> {
    (0..record.member_count)
        .map(|i| MemberSignature {
            member_slot: i,
            pk_g: record.member_pk_gs[i as usize],
            signature: vec![1 + i],
        })
        .collect()
}
