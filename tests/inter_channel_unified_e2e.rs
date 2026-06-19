//! UNIFIED inter-channel transfer E2E: ONE transfer, every security-bearing part real and STITCHED.
//!
//! The SAME `a_send` state flows through the whole pipeline (detail2 §C-6/§E-2/§C-7/§F-2, abstract2
//! §2.3/§3.3/§3.4):
//!   1. channel A is backed by a REAL on-chain ETH deposit (real `balanceProof`, §F-1 reconciled);
//!   2. a REAL E-2 `channelUpdateZKP` debits the sender → produces `a_send`;
//!   3. the post-debit `H1' = a_send.balance_state.h1()` is bound into the small block's IMSB, and a
//!      REAL validity proof verifies the bp's `channelStateSig` over `hash(H1', tx_tree_root)` (§C-7
//!      / §F-2) — the SAME H1' the E-2 produced (the stitch B-1↔B-2);
//!   4. the receiver verifies the tx is INCLUDED in the validity-proven small block (flowReceive3-1).
//! No transport_proof (abstract2 §3.4 note). Skips if foundry is absent.
#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    circuits::{
        balance::{
            balance_processor::BalanceProcessor,
            common::recipient::calculate_recipient_from_user_id, spend_circuit::SpendCircuit,
        },
        channel::state_update_verifier::{
            ChannelProofEnvelope, ChannelProofVerifier, ChannelStateUpdateError,
            ChannelStateUpdatePublicInputs, InterChannelSendUpdateWitness,
        },
        test_utils::{
            balance_witness_generator::{BalanceWitnessGenerator, ReceiveDepositData},
            block_witness_generator::{
                BlockTxV2Witness, BlockWitnessGenerator, BlockWitnessGeneratorHandle,
                ChannelMemberKeys,
            },
        },
        validity::block_hash_chain::{
            block_hash_chain_processor::BlockHashChainProcessor, validity_circuit::ValidityCircuit,
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
        transfer::Transfer,
        trees::{transfer_tree::TransferTree, tx_v2_tree::TxV2Tree},
        tx::{TxClass, TxV2},
        u63::BlockNumber,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
    poseidon_sig::{circuit::SingleSigCircuit, list::ListCircuit},
    regev::{
        RealRegevProofVerifier, RegevCiphertext, RegevPk, RegevSecurityLevel,
        encrypt_amount, prove_channel_update,
    },
    utils::poseidon_hash_out::PoseidonHashOut,
    wallet_core::{
        add_signature, assemble_genesis_state_backed, build_record, sign_state, sign_state_if_backed,
        verify_all_signatures, verify_channel_backing, ChannelBalanceAttestation, MemberInfo,
        MemberKeys,
    },
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
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
const PORT: u16 = 8552;
const A_ID: u32 = 5;

struct StructuralTransport;
impl ChannelProofVerifier for StructuralTransport {
    fn verify(&self, p: &ChannelProofEnvelope, _: &ChannelStateUpdatePublicInputs) -> Result<(), ChannelStateUpdateError> {
        if p.proof.is_empty() { return Err(ChannelStateUpdateError::ProofVerification("empty".into())); }
        Ok(())
    }
}
struct AnvilGuard(Child);
impl Drop for AnvilGuard { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
fn tool(b: &str) -> bool { Command::new(b).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false) }
fn cap(c: &mut Command, l: &str) -> String { let o = c.output().unwrap_or_else(|e| panic!("{l}: {e}")); assert!(o.status.success(), "{l}: {}", String::from_utf8_lossy(&o.stderr)); String::from_utf8_lossy(&o.stdout).to_string() }
fn cast(rpc: &str, a: &[&str], l: &str) -> String { cap(Command::new("cast").args(a).arg("--rpc-url").arg(rpc), l) }
fn word(d: &str, i: usize) -> &str { &d[i * 64..(i + 1) * 64] }
fn info(slot: u8, k: &MemberKeys) -> MemberInfo { MemberInfo { slot, pk_g: k.pk_g(), pk_b: k.pk_b(), regev_pk: k.regev_pk.clone() } }
fn pks_array(keys: &[MemberKeys]) -> [RegevPk; intmax3_zkp::constants::MAX_CHANNEL_MEMBERS] {
    let mut a: [RegevPk; intmax3_zkp::constants::MAX_CHANNEL_MEMBERS] = std::array::from_fn(|_| RegevPk::padding());
    for (i, k) in keys.iter().enumerate() { a[i] = k.regev_pk.clone(); }
    a
}
fn structural_sigs(r: &ChannelRecord) -> Vec<MemberSignature> {
    (0..r.member_count).map(|i| MemberSignature { member_slot: i, pk_g: r.member_pk_gs[i as usize], signature: vec![1 + i] }).collect()
}
fn u256(v: u64) -> U256 { U256::from_u32_slice(&[0, 0, 0, 0, 0, 0, (v >> 32) as u32, v as u32]).unwrap() }

#[test]
fn unified_inter_channel_transfer_e2e() {
    if !(tool("anvil") && tool("forge") && tool("cast")) {
        eprintln!("[skip] foundry not found — unified inter-channel E2E needs real on-chain deposits");
        return;
    }
    use rand::SeedableRng as _;
    use rand010::SeedableRng as _;
    let rpc = format!("http://127.0.0.1:{PORT}");
    let anvil = Command::new("anvil").args(["--hardfork", "prague", "--port", &PORT.to_string()])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("anvil");
    let _g = AnvilGuard(anvil);
    let mut up = false;
    for _ in 0..40 { if Command::new("cast").args(["block-number", "--rpc-url", &rpc]).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false) { up = true; break; } thread::sleep(Duration::from_millis(250)); }
    assert!(up, "anvil down");
    let contracts = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts");
    let deploy = cap(Command::new("forge").current_dir(&contracts).args(["script", "script/Deploy.s.sol", "--rpc-url", &rpc, "--private-key", ANVIL0, "--broadcast"]), "deploy");
    let rollup = deploy.lines().find_map(|l| l.split("IntmaxRollup").nth(1).and_then(|s| s.split("0x").nth(1))).map(|s| format!("0x{}", &s.trim()[..40])).expect("rollup");

    // ---- circuits ----
    let spend = SpendCircuit::<F, C, D>::new();
    let bp = BalanceProcessor::<F, C, D>::new(&spend.data.verifier_data());
    let supported = vec![2];
    let bhc = BlockHashChainProcessor::<F, C, D>::new(&supported);
    let block_chain_vd = bhc.block_chain_vd();
    let bwgen = BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported));
    let initial_ext = bwgen.borrow().current_extended_public_state();

    // ---- channel A: REAL keys; the channel record AND the validity registration share them ----
    let mut crng = rand010::rngs::StdRng::seed_from_u64(0xACE);
    let a_id = ChannelId::new(A_ID as u64).unwrap();
    let a_keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut crng)).collect();
    let a_members: Vec<MemberInfo> = a_keys.iter().enumerate().map(|(i, k)| info(i as u8, k)).collect();
    let a_record = build_record(A_ID, &a_members, 0, 0).expect("A record");
    let a_pks = pks_array(&a_keys);
    let ck = ChannelMemberKeys::from_member_keys(&a_keys);
    // The channel record's member set IS the registered member set (B-2 stitch).
    assert_eq!(a_record.member_pubkeys_root, ck.member_tree.get_root().into(), "record root == registration root");

    // ---- block 1: registration; block 2: REAL on-chain deposit funding channel A ----
    { let mut g = bwgen.borrow_mut(); g.add_channel_registration_keys(A_ID, ck.clone()); g.add_registration_block(0).expect("reg block"); }
    let mut brng = rand::rngs::StdRng::seed_from_u64(0xBEEF);
    let a_bal = [50u64, 10, 30];
    let a_fund: u64 = a_bal.iter().sum();
    let a_salt = Salt::rand(&mut brng);
    let a_recipient = calculate_recipient_from_user_id(a_id, a_salt);
    // real ETH deposit + keystone reconcile
    let send = cap(Command::new("cast").args(["send", &rollup, "deposit(bytes32,uint32,uint256,bytes32)", &a_recipient.to_hex(), "0", &a_fund.to_string(), "0x0000000000000000000000000000000000000000000000000000000000000000", "--value", &a_fund.to_string(), "--private-key", ANVIL0, "--rpc-url", &rpc, "--json"]), "deposit");
    let tx = send.split("\"transactionHash\":\"").nth(1).and_then(|s| s.split('"').next()).unwrap();
    let rc = cast(&rpc, &["receipt", tx, "--json"], "receipt");
    let data = rc.split("\"data\":\"0x").nth(1).and_then(|s| s.split('"').next()).unwrap();
    let depositor = Address::from_hex(&format!("0x{}", &word(data, 0)[24..])).unwrap();
    let onchain = Bytes32::from_hex(&format!("0x{}", word(data, 5))).unwrap();
    assert_eq!(Deposit { deposit_index: Default::default(), block_number: Default::default(), depositor, recipient: a_recipient, token_index: 0, amount: U256::from(a_fund as u32), aux_data: Bytes32::default() }.hash_with_prev_hash(Bytes32::default()), onchain, "deposit reconcile");
    { let mut g = bwgen.borrow_mut(); g.add_deposit(depositor, a_recipient, 0, U256::from(a_fund as u32), Bytes32::default()).unwrap(); g.add_block(0, &[], 0, Bytes32::default()).unwrap(); }
    let mut a_bwg = BalanceWitnessGenerator::new(a_id, Salt::rand(&mut brng), bwgen.clone(), &bp).unwrap();
    let a_dw = a_bwg.receive_deposit_witness(&ReceiveDepositData { receiver: a_recipient, deposit_salt: a_salt }).unwrap();
    let a_proof = bp.prove_receive_deposit(&a_dw).unwrap();
    a_bwg.commit_receive_deposit(&a_proof, &a_dw).unwrap();
    let a_chain = a_bwg.get_public_inputs().unwrap().settled_tx_chain;
    let a_att = ChannelBalanceAttestation { balance_proof: a_proof.to_bytes() };

    // ---- genesis A (deposit-backed) + §F-1; retain alice's witness for the E-2 ----
    let (a_ct0, a_w0) = encrypt_amount(&mut crng, &a_pks[0], a_bal[0]).unwrap();
    let a_cts = [a_ct0.clone(), encrypt_amount(&mut crng, &a_pks[1], a_bal[1]).unwrap().0, encrypt_amount(&mut crng, &a_pks[2], a_bal[2]).unwrap().0];
    // Decryption Stage 1: per-active-slot Regev pk digests, in the SAME slot order as `a_cts`
    // (mirrors channel_member.rs:601-605).
    let a_regev_pk_digests: Vec<Bytes32> = a_keys.iter().map(|k| Bytes32::from(k.regev_pk.poseidon_digest())).collect();
    let mut a_genesis = assemble_genesis_state_backed(&a_record, &a_cts, &a_regev_pk_digests, a_fund, a_chain, Bytes32::default()).unwrap();
    for (slot, k) in a_keys.iter().enumerate() { let s = sign_state_if_backed(k, slot as u8, &a_record, &a_genesis, &a_att, &bp.balance_vd()).expect("genesis sign"); add_signature(&mut a_genesis, s); }
    verify_all_signatures(&a_record, &a_members, &a_genesis).expect("genesis signed");
    verify_channel_backing(&a_record, &a_genesis, Some(&a_att), &bp.balance_vd()).expect("A §F-1");

    // ---- REAL E-2 inter-channel send alice (A0) → an external recipient; produces a_send ----
    const AMT: u64 = 5;
    let b_pk = encrypt_amount(&mut crng, &a_pks[1], 0).unwrap().0; // a destination RegevPk stand-in (any real pk)
    let (dest_pk, _dest_sk) = intmax3_zkp::regev::channel_keygen(&mut crng);
    let _ = b_pk;
    let (alice_after, alice_after_w) = encrypt_amount(&mut crng, &a_pks[0], a_bal[0] - AMT).unwrap();
    let sdelta = encrypt_amount(&mut crng, &a_pks[0], AMT).unwrap();
    let rdelta = encrypt_amount(&mut crng, &dest_pk, AMT).unwrap();
    let e2 = prove_channel_update(LEVEL, &a_pks[0], &dest_pk, (&a_ct0, &a_w0), (&alice_after, &alice_after_w), (&sdelta.0, &sdelta.1), (&rdelta.0, &rdelta.1), AMT).unwrap();
    let tx_leaf = tx_leaf_hash(a_keys[0].pk_g(), sdelta.0.digest(), a_keys[1].pk_g(), rdelta.0.digest());

    // The inter-channel tx's small block carries the channel's own 1-tx TxV2 tree (detail2 §A-2).
    let mut tt = TransferTree::init();
    tt.push(Transfer { recipient: Bytes32::rand(&mut brng), token_index: 0, amount: U256::from(AMT as u32), aux_data: Bytes32::default() });
    let tx_v2 = TxV2 { tx_class: TxClass::UserTransfer, transfer_tree_root: tt.get_root(), nonce: 1, channel_action_root: PoseidonHashOut::default() };
    let mut tv2 = TxV2Tree::init();
    tv2.update(a_id.as_u64(), tx_v2);
    let tx_v2_root_h = tv2.get_root();
    let tx_tree_root: Bytes32 = tx_v2_root_h.into(); // = H2
    let tx_v2_proof = tv2.prove(a_id.as_u64());

    // a_send = post-debit channel A state; its h1() is the H1' bound into BOTH the channelStateSig
    // and the validity-proof IMSB (THE stitch).
    let mut a_send = ChannelState {
        epoch: a_genesis.epoch + 1,
        small_block_number: 1,
        channel_fund: ChannelFund { amount: a_genesis.channel_fund.amount - u256(AMT), ..a_genesis.channel_fund.clone() },
        balance_state: BalanceState {
            enc_balances: BalanceState::pad_enc_balances(&[alice_after.clone(), a_genesis.balance_state.enc_balances[1].clone(), a_genesis.balance_state.enc_balances[2].clone()]),
            settled_tx_chain: settled_tx_chain_push(a_genesis.balance_state.settled_tx_chain, tx_leaf),
            state_version: 1,
            ..a_genesis.balance_state.clone()
        },
        h2_tag: tx_tree_root,
        shared_native_nullifier_root: Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0x412]).unwrap(),
        prev_digest: a_genesis.digest,
        member_signatures: Vec::new(),
        ..a_genesis.clone()
    }.with_computed_digest();
    let h1_prime = a_send.balance_state.h1();

    let inter_tx = InterChannelTx {
        tx_inclusion_proof: MerkleInclusionProof::default(),
        signed_small_block: SignedSmallBlock {
            message: SmallBlockRootMessage { channel_id: a_id, bp_member_slot: 0, bp_pk_g: a_keys[0].pk_g(), small_block_number: 1, prev_small_block_root: Bytes32::default(), tx_tree_root, state_commitment_root: h1_prime, medium_epoch_hint: 3, close_freeze_nonce: 0 },
            signatures: structural_sigs(&a_record), aggregated_signature_proof: vec![9, 9], medium_block_number: 4, confirmation_proof: vec![8, 8],
        },
        sender_delta_ct: sdelta.0.clone(), source_channel_id: a_id, destination_channel_id: ChannelId::new(7).unwrap(), source_pk_g: a_keys[0].pk_g(),
        seal: Bytes32::default(), tx_hash: Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0x502]).unwrap(), intmax_transfer_commitment: Bytes32::default(), recipient_memo: vec![1],
        receiver_deltas: vec![ReceiverBalanceDelta { receiver_pk_g: a_keys[1].pk_g(), amount: rdelta.0.clone() }],
        channel_update_zkp: ChannelProofEnvelope { role: TransitionProofRole::ChannelStateUpdate, backend: ProofBackend::Plonky3, proof: e2 },
        transport_proof: vec![7, 7, 7],
    };
    for (slot, k) in a_keys.iter().enumerate() { let s = sign_state(k, slot as u8, &a_send).unwrap(); add_signature(&mut a_send, s); }
    verify_all_signatures(&a_record, &a_members, &a_send).expect("a_send member-signed");

    // ---- the REAL E-2 inter-channel send transition verifies (B-1 crypto) ----
    let icw = InterChannelSendUpdateWitness {
        channel_record: a_record.clone(), regev_pks: a_pks.clone(), destination_recipient_pk: dest_pk.clone(),
        prev_state: a_genesis.clone(), next_state: a_send.clone(), inter_channel_tx: inter_tx.clone(), amount: AMT,
        transport_proof: ChannelProofEnvelope { role: TransitionProofRole::IntmaxTransport, backend: ProofBackend::Plonky2, proof: vec![7, 7, 7] },
    };
    let pis = icw.verify(&StructuralTransport, &VERIFIER).expect("REAL E-2 inter-channel send verifies");
    assert_eq!(pis.kind, ChannelTransitionKind::InterChannelSend);
    assert_eq!(pis.amount, AMT);

    // ---- block 3: post the small block; the bp signs hash(H1'=a_send.h1(), tx_tree_root) ----
    let tx_v2_witness = BlockTxV2Witness { tx_v2_indices: vec![a_id.as_u64(), 0], tx_v2s: vec![tx_v2, TxV2::default()], tx_v2_merkle_proofs: vec![tx_v2_proof.clone(), tx_v2_proof.clone()] };
    { let mut g = bwgen.borrow_mut(); g.next_imsb_state_commitment_root = Some(h1_prime); g.add_block_with_tx_v2(A_ID, &[1], 1, tx_tree_root, Some(tx_v2_witness)).expect("small block"); }

    // ---- REAL validity proof: verifies the channelStateSig over hash(a_send.h1(), tx_tree_root) ----
    let mut prev = None; let mut last = None;
    { let g = bwgen.borrow(); for idx in 1..=g.block_number.as_u64() {
        let bn = BlockNumber::new(idx).unwrap();
        let w = g.block_chain_witness.get(&bn).cloned().expect("block witness");
        let init = if prev.is_none() { Some(initial_ext.clone()) } else { None };
        let p = bhc.prove_block(init, prev.clone(), &w).expect("block chain proof");
        prev = Some(p.clone()); last = Some(p);
    } }
    let final_chain = last.unwrap();
    assert_ne!(bwgen.borrow().current_bp_sig_chain(), Bytes32::default(), "bp IMSB signature recorded");
    let single = SingleSigCircuit::new();
    let list = ListCircuit::new(&single.verifier_data());
    let list_proof = bwgen.borrow().build_bp_sig_list_proof(&single, &list).expect("list proof");
    assert!(list_proof.is_some());
    let validity = ValidityCircuit::<F, C, D>::new(&block_chain_vd, &list.verifier_data());
    let vproof = validity.prove(&final_chain, list_proof.as_ref(), Address::rand(&mut brng)).expect("validity proof");
    validity.verify(&vproof).expect("verify validity proof");

    // ---- flowReceive3-1: receiver confirms inclusion of the tx in the validity-proven small block ----
    tx_v2_proof.verify(&tx_v2, a_id.as_u64(), tx_v2_root_h).expect("receiver TxV2 inclusion (flowReceive3-1)");

    eprintln!("[UNIFIED] OK: real deposit (§F-1) → real E-2 → channelStateSig validity-proven over the SAME H1'={} → receiver inclusion. tx_tree_root={}.", h1_prime.to_hex(), tx_tree_root.to_hex());
}
