//! Channel-layer end-to-end flow tests on the v2 (Regev) types.
//!
//! Flow mapping (detail2 §H-1, abstract2 §3): two channels — sender channel A (members
//! alice/bob/carol) and receiver channel B (members dave/erin/frank) — drive the full life cycle:
//!
//! 1. keygen + L1-anchored `regev_pk_root` (abstract2 §2.1)
//! 2. in-channel `ChannelTx` alice→bob with the mandatory E-1 channelTxZKP (§3.1/§3.2)
//! 3. inter-channel send alice→dave: E-2 channelUpdateZKP, signed small block with `H2 =
//!    tx_tree_root` and `state_commitment_root = H1'`, settled-tx-chain push (§3.3)
//! 4. fund import on channel B (confirmed incoming, balances untouched)
//! 5. receiver bundle apply on channel B: public homomorphic add + E-2 re-verification with the
//!    sender-side witness ciphertexts (§3.4 flowReceive3)
//! 6. balance refresh: dave re-encrypts his accumulated slot, `pending_adds → 0` (detail2 §B-3,
//!    deviation D3)
//! 7. close: `CloseWithdrawal` + `CloseIntent` carrying `final_state_version` +
//!    `final_settled_tx_chain` (§3.5). The FULL P7 `ChannelCloseCircuit` (H1 recompute + recursive
//!    balance-proof verification + 3 real SPHINCS+ member signatures) is proven for channel A's
//!    post-in-channel state, whose settled_tx_chain is still genesis and therefore matches a REAL
//!    initial balance proof (the nonzero-chain close needs a base-layer balance flow whose chain
//!    leaves equal the channel-side ones — deferred to the full-stack integration)
//! 8. `WithdrawalClaim` via the E-3 decryption AIR (§3.5.4), `CancelClose` (§3.5.3) and
//!    `PostCloseIncomingClaim` (§3.5.5)
//!
//! plus the adversarial suite (missing ZKP / tampered slot / tx_tree_root == 0 / h2 mismatch /
//! H1 mismatch / version skip / pending_adds overflow / wrong chain leaf / prev-state replay /
//! cross-purpose proof / forged E-2 witness ciphertexts). All proofs run at
//! `RegevSecurityLevel::Test` with seeded RNGs; the expensive artifacts are built ONCE in a
//! shared `OnceLock` fixture and the negative tests tamper with clones, so the suite stays
//! bounded at one E-1 + one E-2 + one refresh proof (fixture) and two E-3 proofs + one plonky2
//! close proof (happy path).

use std::sync::OnceLock;

use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use rand010::{SeedableRng, rngs::SmallRng};

use crate::{
    circuits::channel::{
        cancel_close_pis::CancelCloseWitness,
        close_circuit::{ChannelCloseFullWitness, test_fixture as close_fixture},
        close_pis::ChannelCloseWitness,
        post_close_claim_pis::PostCloseClaimWitness,
        state_update_verifier::{
            BalanceRefreshUpdateWitness, ChannelProofEnvelope, ChannelProofVerifier,
            ChannelStateUpdateError, ChannelStateUpdatePublicInputs,
            InChannelTransferUpdateWitness, InterChannelFundImportUpdateWitness,
            InterChannelSendUpdateWitness, ReceiverBundleApplyUpdateWitness,
        },
        withdrawal_claim_pis::WithdrawalClaimWitness,
    },
    common::{
        balance_state::{BalanceState, settled_tx_chain_push, tx_leaf_hash},
        channel::{
            CancelClose, ChannelFund, ChannelId, ChannelMember, ChannelRecord, ChannelState,
            ChannelStatus, ChannelTransitionKind, ChannelTx, CloseIntent, CloseWithdrawal,
            InterChannelTx, MemberSignature, MerkleInclusionProof, PostCloseIncomingClaim,
            ProofBackend, ReceiverBalanceDelta, SignedSmallBlock, SmallBlockRootMessage,
            TransitionProofRole, WithdrawalClaim,
        },
    },
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    regev::{
        MAX_HOMO_ADDS_BEFORE_REFRESH, RealRegevProofVerifier, RegevPk, RegevSecurityLevel, RegevSk,
        add_ciphertexts, channel_keygen, decrypt_amount, encrypt_amount, prove_balance_refresh,
        prove_channel_tx, prove_channel_update, prove_withdraw_claim, regev_pk_root,
    },
};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Test;
const VERIFIER: RealRegevProofVerifier = RealRegevProofVerifier { level: LEVEL };

/// alice → bob (hidden) in-channel amount.
const IN_CHANNEL_AMOUNT: u64 = 7;
/// alice → dave (public) inter-channel amount.
const INTER_CHANNEL_AMOUNT: u64 = 5;
/// Active member count for this e2e flow (pad-to-MAX D6: 3 active members per channel, the rest
/// padding slots).
const E2E_ACTIVE: usize = 3;
/// Genesis balances of channel A: alice / bob / carol (the 3 active members).
const A_GENESIS: [u64; E2E_ACTIVE] = [50, 10, 30];
/// Genesis balances of channel B: dave / erin / frank.
const B_GENESIS: [u64; E2E_ACTIVE] = [10, 20, 30];

/// Pad an active prefix of Regev pubkeys to the full MAX_CHANNEL_MEMBERS array (padding =
/// `RegevPk::padding()`, pad-to-MAX D6).
fn pad_pks(active: &[RegevPk]) -> [RegevPk; MAX_CHANNEL_MEMBERS] {
    std::array::from_fn(|i| active.get(i).cloned().unwrap_or_else(RegevPk::padding))
}

/// Pad an active prefix of member pubkey hashes to the full MAX_CHANNEL_MEMBERS array (padding =
/// `Bytes32::default()`).
fn pad_hashes(active: &[Bytes32]) -> [Bytes32; MAX_CHANNEL_MEMBERS] {
    std::array::from_fn(|i| active.get(i).copied().unwrap_or_default())
}

/// Transport-level (Plonky2 intmax) proof verifier for this flow.
///
/// INTENTIONALLY SIMPLE: the intmax transport proof is a BASE-layer artifact whose real
/// verification lives in the balance/validity circuit tests (plan §P5/§P6); at the channel
/// witness layer the binding under test is structural (role/backend tags are enforced by
/// `verify_proof` before this is called, and the envelope bytes must match the signed
/// `InterChannelTx.transport_proof`). This mirrors the fixed-behavior helper pattern that
/// CLAUDE.md explicitly allows in tests.
struct StructuralTransportVerifier;

impl ChannelProofVerifier for StructuralTransportVerifier {
    fn verify(
        &self,
        proof: &ChannelProofEnvelope,
        _public_inputs: &ChannelStateUpdatePublicInputs,
    ) -> Result<(), ChannelStateUpdateError> {
        if proof.proof.is_empty() {
            return Err(ChannelStateUpdateError::ProofVerification(
                "transport proof bytes must not be empty".to_string(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fixture helpers (patterns carried over from the SIS-era flow, on the new types)
// ---------------------------------------------------------------------------

/// A member's SPHINCS+ pubkey hash, deterministic in (channel_id, member value). One key per
/// member: this IS the member identity (no KeyId/UserId).
fn user(channel_id: ChannelId, value: u64) -> Bytes32 {
    let ch = channel_id.as_u64() as u32;
    Bytes32::from_u32_slice(&[
        0xdead_0000 ^ ch,
        value as u32,
        ch,
        value as u32 + 1,
        ch + 1,
        value as u32 + 2,
        ch + 2,
        value as u32 + 3,
    ])
    .unwrap()
}

fn bytes32_word(word: u32) -> Bytes32 {
    Bytes32::from_u32_slice(&[word, 0, 0, 0, 0, 0, 0, 0]).unwrap()
}

fn address_word(word: u32) -> Address {
    Address::from_u32_slice(&[0, 0, 0, 0, word]).unwrap()
}

/// Build an `E2E_ACTIVE`-member channel record (pad-to-MAX D6). `active_member_pubkey_hashes` are
/// the active prefix in slot order; padding slots are `Bytes32::default()`. `bp_member_slot`
/// selects the block proposer.
fn channel_record(
    channel_id: ChannelId,
    bp_member_slot: u8,
    active_member_pubkey_hashes: [Bytes32; E2E_ACTIVE],
    regev_pk_root: Bytes32,
) -> ChannelRecord {
    ChannelRecord {
        channel_id,
        member_count: E2E_ACTIVE as u8,
        delegate_count: 0,
        member_pk_gs: pad_hashes(&active_member_pubkey_hashes),
        member_pubkeys_root: bytes32_word(100 + channel_id.as_u64() as u32),
        bp_member_slot,
        special_close_penalty: U256::from(9u32),
        close_freeze_nonce: 0,
        status: ChannelStatus::Active,
        regev_pk_root,
    }
}

fn signatures_for(record: &ChannelRecord) -> Vec<MemberSignature> {
    // pad-to-MAX D6: only the ACTIVE members (0..member_count) sign.
    record
        .member_pk_gs
        .iter()
        .enumerate()
        .take(record.member_count as usize)
        .map(|(idx, hash)| MemberSignature {
            member_slot: idx as u8,
            pk_g: *hash,
            signature: vec![1 + idx as u8],
        })
        .collect()
}

fn state_update_envelope(proof: Vec<u8>) -> ChannelProofEnvelope {
    ChannelProofEnvelope {
        role: TransitionProofRole::ChannelStateUpdate,
        backend: ProofBackend::Plonky3,
        proof,
    }
}

fn transport_envelope() -> ChannelProofEnvelope {
    ChannelProofEnvelope {
        role: TransitionProofRole::IntmaxTransport,
        backend: ProofBackend::Plonky2,
        proof: vec![7, 7, 7],
    }
}

/// Genesis channel state: fresh encryptions of the initial balances, `settled_tx_chain = 0`,
/// `state_version = 0`, `pending_adds = [0; 3]` (abstract2 §2.1).
fn genesis_state(
    rng: &mut SmallRng,
    record: &ChannelRecord,
    pks: &[RegevPk; MAX_CHANNEL_MEMBERS],
    balances: [u64; E2E_ACTIVE],
    fund_amount: u32,
    nullifier_root: Bytes32,
) -> (ChannelState, [crate::regev::AmountWitness; E2E_ACTIVE]) {
    let enc: Vec<_> = (0..E2E_ACTIVE)
        .map(|i| encrypt_amount(rng, &pks[i], balances[i]).unwrap())
        .collect();
    let mut enc = enc.into_iter();
    let (ct0, w0) = enc.next().unwrap();
    let (ct1, w1) = enc.next().unwrap();
    let (ct2, w2) = enc.next().unwrap();
    let state = ChannelState {
        channel_id: record.channel_id,
        epoch: 1,
        small_block_number: 0,
        close_freeze_nonce: 0,
        channel_fund: ChannelFund {
            channel_id: record.channel_id,
            amount: U256::from(fund_amount),
            intmax_state_root: bytes32_word(200 + fund_amount),
        },
        balance_state: BalanceState {
            channel_id: record.channel_id,
            member_count: E2E_ACTIVE as u8,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances(&[ct0, ct1, ct2]),
            settled_tx_chain: Bytes32::default(),
            state_version: 0,
            pending_adds: BalanceState::pad_pending_adds(&[0; E2E_ACTIVE]),
        },
        h2_tag: Bytes32::default(),
        shared_native_nullifier_root: nullifier_root,
        unallocated_confirmed_incoming: U256::zero(),
        prev_digest: Bytes32::default(),
        digest: Bytes32::default(),
        member_signatures: signatures_for(record),
    }
    .with_computed_digest();
    (state, [w0, w1, w2])
}

fn u256_from_u64(value: u64) -> U256 {
    U256::from_u32_slice(&[0, 0, 0, 0, 0, 0, (value >> 32) as u32, value as u32]).unwrap()
}

// ---------------------------------------------------------------------------
// Shared flow fixture
// ---------------------------------------------------------------------------

/// All happy-path artifacts of the two-channel flow, built once. The witnesses already passed a
/// dry-run construction here; tests verify clones (happy path) or tampered clones (negatives),
/// so the proof generation count stays bounded.
struct FlowFixture {
    a_pks: [RegevPk; MAX_CHANNEL_MEMBERS],
    a_sks: Vec<RegevSk>,
    b_pks: [RegevPk; MAX_CHANNEL_MEMBERS],
    b_sks: Vec<RegevSk>,
    in_channel: InChannelTransferUpdateWitness,
    send: InterChannelSendUpdateWitness,
    import: InterChannelFundImportUpdateWitness,
    bundle: ReceiverBundleApplyUpdateWitness,
    refresh: BalanceRefreshUpdateWitness,
    tx_leaf: Bytes32,
    tx_tree_root: Bytes32,
}

fn flow() -> &'static FlowFixture {
    static FLOW: OnceLock<FlowFixture> = OnceLock::new();
    FLOW.get_or_init(build_flow)
}

fn build_flow() -> FlowFixture {
    let mut rng = SmallRng::seed_from_u64(0x9434);
    let a_id = ChannelId::new(5).unwrap();
    let b_id = ChannelId::new(7).unwrap();

    // Channel A: alice (key 10, slot 0), bob (key 11, slot 1), carol (key 12, slot 2).
    let (a_pk0, a_sk0) = channel_keygen(&mut rng);
    let (a_pk1, a_sk1) = channel_keygen(&mut rng);
    let (a_pk2, a_sk2) = channel_keygen(&mut rng);
    let a_pks = pad_pks(&[a_pk0, a_pk1, a_pk2]);
    let sender_record = channel_record(
        a_id,
        0,
        [user(a_id, 10), user(a_id, 11), user(a_id, 12)],
        regev_pk_root(&a_pks),
    );

    // Channel B: dave (key 21, slot 0), erin (key 22, slot 1), frank (key 23, slot 2).
    let (b_pk0, b_sk0) = channel_keygen(&mut rng);
    let (b_pk1, b_sk1) = channel_keygen(&mut rng);
    let (b_pk2, b_sk2) = channel_keygen(&mut rng);
    let b_pks = pad_pks(&[b_pk0, b_pk1, b_pk2]);
    let receiver_record = channel_record(
        b_id,
        0,
        [user(b_id, 21), user(b_id, 22), user(b_id, 23)],
        regev_pk_root(&b_pks),
    );

    let (a0, a_genesis_witnesses) = genesis_state(
        &mut rng,
        &sender_record,
        &a_pks,
        A_GENESIS,
        100,
        bytes32_word(402),
    );
    let (b0, _) = genesis_state(
        &mut rng,
        &receiver_record,
        &b_pks,
        B_GENESIS,
        200,
        bytes32_word(602),
    );

    // -- step (a): in-channel ChannelTx alice -> bob, amount 7 (abstract2 §3.1/§3.2) ----------
    // The sender re-encrypts their own slot (50 - 7 = 43) and proves E-1 over
    // (before, enc_amount, after); the recipient slot is the PUBLIC homomorphic sum.
    let enc_amount = encrypt_amount(&mut rng, &a_pks[1], IN_CHANNEL_AMOUNT).unwrap();
    let alice_after_tx =
        encrypt_amount(&mut rng, &a_pks[0], A_GENESIS[0] - IN_CHANNEL_AMOUNT).unwrap();
    let bob_after = add_ciphertexts(&a0.balance_state.enc_balances[1], &enc_amount.0).unwrap();
    let e1_proof = prove_channel_tx(
        LEVEL,
        &a_pks[0],
        &a_pks[1],
        (&a0.balance_state.enc_balances[0], &a_genesis_witnesses[0]),
        (&enc_amount.0, &enc_amount.1),
        (&alice_after_tx.0, &alice_after_tx.1),
    )
    .unwrap();

    let a1 = ChannelState {
        epoch: 2,
        balance_state: BalanceState {
            channel_id: a_id,
            member_count: E2E_ACTIVE as u8,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances(&[
                alice_after_tx.0.clone(),
                bob_after,
                a0.balance_state.enc_balances[2].clone(),
            ]),
            settled_tx_chain: a0.balance_state.settled_tx_chain,
            state_version: 1,
            pending_adds: BalanceState::pad_pending_adds(&[0, 1, 0]),
        },
        prev_digest: a0.digest,
        ..a0.clone()
    }
    .with_computed_digest();

    let channel_tx = ChannelTx {
        recipient_pk_g: user(a_id, 11),
        enc_amount: enc_amount.0.clone(),
        nonce: bytes32_word(777),
        channel_tx_zkp: state_update_envelope(e1_proof),
        sender_pk_g: user(a_id, 10),
        sender_hash_sig: vec![1, 2, 3],
        sender_pk_b: user(a_id, 40),
    };
    let in_channel = InChannelTransferUpdateWitness {
        channel_record: sender_record.clone(),
        regev_pks: a_pks.clone(),
        prev_state: a0,
        next_state: a1.clone(),
        channel_tx,
        sender_index: 0,
        recipient_index: 1,
        recipient_sk: None,
        expected_amount: None,
    };

    // -- step (b): inter-channel send alice -> dave, public amount 5 (abstract2 §3.3) ---------
    // Sender rebind (43 - 5 = 38) + own-key delta + receiver-key delta, all bound by ONE E-2.
    let alice_after_send = encrypt_amount(
        &mut rng,
        &a_pks[0],
        A_GENESIS[0] - IN_CHANNEL_AMOUNT - INTER_CHANNEL_AMOUNT,
    )
    .unwrap();
    let sender_delta = encrypt_amount(&mut rng, &a_pks[0], INTER_CHANNEL_AMOUNT).unwrap();
    let receiver_delta = encrypt_amount(&mut rng, &b_pks[0], INTER_CHANNEL_AMOUNT).unwrap();
    let e2_proof = prove_channel_update(
        LEVEL,
        &a_pks[0],
        &b_pks[0],
        (&alice_after_tx.0, &alice_after_tx.1),
        (&alice_after_send.0, &alice_after_send.1),
        (&sender_delta.0, &sender_delta.1),
        (&receiver_delta.0, &receiver_delta.1),
        INTER_CHANNEL_AMOUNT,
    )
    .unwrap();

    // The chain leaf binds sender id + receiver id + both hidden delta digests (detail2 §C-6).
    let tx_leaf = tx_leaf_hash(
        user(a_id, 10),
        sender_delta.0.digest(),
        user(b_id, 21),
        receiver_delta.0.digest(),
    );
    let tx_tree_root = bytes32_word(301);

    let a2 = ChannelState {
        epoch: 3,
        small_block_number: 1,
        channel_fund: ChannelFund {
            amount: a1.channel_fund.amount - u256_from_u64(INTER_CHANNEL_AMOUNT),
            ..a1.channel_fund.clone()
        },
        balance_state: BalanceState {
            channel_id: a_id,
            member_count: E2E_ACTIVE as u8,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances(&[
                alice_after_send.0.clone(),
                a1.balance_state.enc_balances[1].clone(),
                a1.balance_state.enc_balances[2].clone(),
            ]),
            settled_tx_chain: settled_tx_chain_push(a1.balance_state.settled_tx_chain, tx_leaf),
            state_version: 2,
            pending_adds: a1.balance_state.pending_adds,
        },
        // detail2 §C-2: the send version is finalized with H2 = own small block tx_tree_root.
        h2_tag: tx_tree_root,
        shared_native_nullifier_root: bytes32_word(412),
        prev_digest: a1.digest,
        ..a1.clone()
    }
    .with_computed_digest();

    let signed_small_block = SignedSmallBlock {
        message: SmallBlockRootMessage {
            channel_id: a_id,
            bp_member_slot: 0,
            bp_pk_g: user(a_id, 10),
            small_block_number: 1,
            prev_small_block_root: bytes32_word(300),
            tx_tree_root,
            // detail2 §C-7: state_commitment_root IS H1' of the post-debit balance state.
            state_commitment_root: a2.balance_state.h1(),
            medium_epoch_hint: 3,
            close_freeze_nonce: 0,
        },
        signatures: signatures_for(&sender_record),
        aggregated_signature_proof: vec![9, 9],
        medium_block_number: 4,
        confirmation_proof: vec![8, 8],
    };
    let transport = transport_envelope();
    let inter_channel_tx = InterChannelTx {
        tx_inclusion_proof: MerkleInclusionProof::default(),
        signed_small_block,
        sender_delta_ct: sender_delta.0.clone(),
        source_channel_id: a_id,
        destination_channel_id: b_id,
        source_pk_g: user(a_id, 10),
        seal: bytes32_word(501),
        tx_hash: bytes32_word(502),
        intmax_transfer_commitment: bytes32_word(503),
        recipient_memo: vec![1, 2, 3],
        receiver_deltas: vec![ReceiverBalanceDelta {
            receiver_pk_g: user(b_id, 21),
            amount: receiver_delta.0.clone(),
        }],
        channel_update_zkp: state_update_envelope(e2_proof),
        transport_proof: transport.proof.clone(),
    };
    let send = InterChannelSendUpdateWitness {
        channel_record: sender_record,
        regev_pks: a_pks.clone(),
        destination_recipient_pk: b_pks[0].clone(),
        prev_state: a1,
        next_state: a2,
        inter_channel_tx: inter_channel_tx.clone(),
        amount: INTER_CHANNEL_AMOUNT,
        transport_proof: transport.clone(),
    };

    // -- step (c): fund import on channel B (confirmed incoming; balances untouched) ----------
    let b1 = ChannelState {
        epoch: 2,
        small_block_number: 1,
        channel_fund: ChannelFund {
            amount: b0.channel_fund.amount + u256_from_u64(INTER_CHANNEL_AMOUNT),
            ..b0.channel_fund.clone()
        },
        balance_state: BalanceState {
            // detail2 §C-6: the import chains the base-layer settle identifier (tx_hash).
            settled_tx_chain: settled_tx_chain_push(
                b0.balance_state.settled_tx_chain,
                inter_channel_tx.tx_hash,
            ),
            state_version: 1,
            ..b0.balance_state.clone()
        },
        shared_native_nullifier_root: bytes32_word(603),
        unallocated_confirmed_incoming: u256_from_u64(INTER_CHANNEL_AMOUNT),
        prev_digest: b0.digest,
        ..b0.clone()
    }
    .with_computed_digest();
    let import = InterChannelFundImportUpdateWitness {
        source_channel_record: send.channel_record.clone(),
        receiver_channel_record: receiver_record.clone(),
        prev_state: b0,
        next_state: b1.clone(),
        inter_channel_tx: inter_channel_tx.clone(),
        amount: INTER_CHANNEL_AMOUNT,
        transport_proof: transport,
    };

    // -- step (d): receiver bundle apply on channel B (abstract2 §3.4 flowReceive3) -----------
    let dave_after = add_ciphertexts(&b1.balance_state.enc_balances[0], &receiver_delta.0).unwrap();
    let b2 = ChannelState {
        epoch: 3,
        balance_state: BalanceState {
            enc_balances: BalanceState::pad_enc_balances(&[
                dave_after.clone(),
                b1.balance_state.enc_balances[1].clone(),
                b1.balance_state.enc_balances[2].clone(),
            ]),
            // The receiver chains the SAME tx leaf the sender chained (F3-A multi-layer defense).
            settled_tx_chain: settled_tx_chain_push(b1.balance_state.settled_tx_chain, tx_leaf),
            state_version: 2,
            pending_adds: BalanceState::pad_pending_adds(&[1, 0, 0]),
            ..b1.balance_state.clone()
        },
        unallocated_confirmed_incoming: U256::zero(),
        prev_digest: b1.digest,
        ..b1.clone()
    }
    .with_computed_digest();
    let bundle = ReceiverBundleApplyUpdateWitness {
        receiver_channel_record: receiver_record.clone(),
        regev_pks: b_pks.clone(),
        source_sender_pk: a_pks[0].clone(),
        // Witness-only sender-side ciphertexts shared off-chain (bound by the E-2 transcript).
        sender_before_ct: alice_after_tx.0.clone(),
        sender_after_ct: alice_after_send.0.clone(),
        prev_state: b1,
        next_state: b2.clone(),
        inter_channel_tx,
        amount: INTER_CHANNEL_AMOUNT,
        recipient_index: 0,
        recipient_sk: None,
        expected_amount: None,
    };

    // -- step (e): balance refresh (detail2 §B-3 / D3): dave re-encrypts his accumulated slot --
    let (dave_refreshed, refresh_proof) =
        prove_balance_refresh(&mut rng, LEVEL, &b_pks[0], &b_sk0, &dave_after).unwrap();
    let b3 = ChannelState {
        epoch: 4,
        balance_state: BalanceState {
            enc_balances: BalanceState::pad_enc_balances(&[
                dave_refreshed,
                b2.balance_state.enc_balances[1].clone(),
                b2.balance_state.enc_balances[2].clone(),
            ]),
            state_version: 3,
            pending_adds: BalanceState::pad_pending_adds(&[0, 0, 0]),
            ..b2.balance_state.clone()
        },
        prev_digest: b2.digest,
        ..b2.clone()
    }
    .with_computed_digest();
    let refresh = BalanceRefreshUpdateWitness {
        channel_record: receiver_record,
        regev_pks: b_pks.clone(),
        prev_state: b2,
        next_state: b3,
        member_index: 0,
        refresh_proof: state_update_envelope(refresh_proof),
    };

    FlowFixture {
        a_pks,
        a_sks: vec![a_sk0, a_sk1, a_sk2],
        b_pks,
        b_sks: vec![b_sk0, b_sk1, b_sk2],
        in_channel,
        send,
        import,
        bundle,
        refresh,
        tx_leaf,
        tx_tree_root,
    }
}

fn close_withdrawal_for(state: &ChannelState, burn_word: u32) -> CloseWithdrawal {
    CloseWithdrawal {
        channel_id: state.channel_id,
        final_channel_state_digest: state.digest,
        final_balance_state_h1: state.balance_state.h1(),
        intmax_state_root: state.channel_fund.intmax_state_root,
        burn_tx_hash: bytes32_word(burn_word),
        burn_amount: state.channel_fund.amount,
        zkp: vec![1, 2, 3],
    }
}

// ---------------------------------------------------------------------------
// Happy-path E2E
// ---------------------------------------------------------------------------

/// Full v2 life cycle (abstract2 §3 flows a–h): every state transition is accepted by the
/// corresponding witness verifier with the REAL Regev STARKs, the chain/version/H2 bindings
/// advance exactly as specified, and the close/claim layer reproduces them on L1-facing digests.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn channel_native_regev_full_flow_e2e() {
    let f = flow();
    let transport_verifier = StructuralTransportVerifier;
    let b_id = ChannelId::new(7).unwrap();

    // (a) In-channel ChannelTx alice -> bob, verified first as a non-recipient co-signer
    // (no secret key: E-1 + public recomputation only)…
    let pis = f.in_channel.verify(&VERIFIER).unwrap();
    assert_eq!(pis.kind, ChannelTransitionKind::InChannelTransfer);
    assert_eq!(pis.amount, 0, "in-channel amounts stay hidden");
    assert_eq!((pis.prev_state_version, pis.next_state_version), (0, 1));
    assert_eq!(
        pis.h2_tag,
        Bytes32::default(),
        "H2 = 0 is the in-channel tag"
    );
    assert_eq!(
        pis.prev_settled_tx_chain, pis.next_settled_tx_chain,
        "in-channel transfers never advance the settled-tx chain"
    );
    assert_eq!(
        f.in_channel.next_state.balance_state.pending_adds[..E2E_ACTIVE],
        [0, 1, 0]
    );
    // …then as the recipient (decryption check, abstract2 §3.1).
    let mut as_recipient = f.in_channel.clone();
    as_recipient.recipient_sk = Some(f.a_sks[1].clone());
    as_recipient.expected_amount = Some(IN_CHANNEL_AMOUNT);
    as_recipient.verify(&VERIFIER).unwrap();
    assert_eq!(
        decrypt_amount(
            &f.a_sks[1],
            &f.in_channel.next_state.balance_state.enc_balances[1]
        )
        .unwrap(),
        A_GENESIS[1] + IN_CHANNEL_AMOUNT,
        "bob's homomorphically credited slot decrypts to 10 + 7"
    );

    // (b) Inter-channel send alice -> dave.
    let pis = f.send.verify(&transport_verifier, &VERIFIER).unwrap();
    assert_eq!(pis.kind, ChannelTransitionKind::InterChannelSend);
    assert_eq!(
        pis.amount, INTER_CHANNEL_AMOUNT,
        "inter-channel amount is public"
    );
    assert_eq!((pis.prev_state_version, pis.next_state_version), (1, 2));
    assert_eq!(
        pis.h2_tag, f.tx_tree_root,
        "H2 = own small block tx_tree_root"
    );
    assert_eq!(f.send.inter_channel_tx.tx_leaf_hash().unwrap(), f.tx_leaf);
    assert_eq!(
        pis.next_settled_tx_chain,
        settled_tx_chain_push(pis.prev_settled_tx_chain, f.tx_leaf),
        "the sender chain absorbs the tx leaf"
    );
    assert_eq!(
        decrypt_amount(
            &f.a_sks[0],
            &f.send.next_state.balance_state.enc_balances[0]
        )
        .unwrap(),
        A_GENESIS[0] - IN_CHANNEL_AMOUNT - INTER_CHANNEL_AMOUNT,
        "alice's rebound slot decrypts to 50 - 7 - 5"
    );

    // (c) Fund import on channel B.
    let pis = f.import.verify(&transport_verifier).unwrap();
    assert_eq!(pis.kind, ChannelTransitionKind::InterChannelFundImport);
    assert_eq!(pis.unallocated_after, u256_from_u64(INTER_CHANNEL_AMOUNT));
    assert_eq!(
        pis.next_settled_tx_chain,
        settled_tx_chain_push(pis.prev_settled_tx_chain, f.import.inter_channel_tx.tx_hash),
        "the import chains the base-layer settle identifier"
    );

    // (d) Receiver bundle apply on channel B, first as a co-signer, then as dave (recipient).
    let pis = f.bundle.verify(&VERIFIER).unwrap();
    assert_eq!(pis.kind, ChannelTransitionKind::ReceiverBundleApply);
    assert_eq!((pis.prev_state_version, pis.next_state_version), (1, 2));
    assert_eq!(pis.h2_tag, Bytes32::default());
    assert_eq!(pis.unallocated_after, U256::zero());
    assert_eq!(
        pis.next_settled_tx_chain,
        settled_tx_chain_push(pis.prev_settled_tx_chain, f.tx_leaf),
        "the receiver chains the SAME tx leaf the sender chained"
    );
    assert_eq!(
        f.bundle.next_state.balance_state.pending_adds[..E2E_ACTIVE],
        [1, 0, 0]
    );
    let mut as_dave = f.bundle.clone();
    as_dave.recipient_sk = Some(f.b_sks[0].clone());
    as_dave.expected_amount = Some(INTER_CHANNEL_AMOUNT);
    as_dave.verify(&VERIFIER).unwrap();
    assert_eq!(
        decrypt_amount(
            &f.b_sks[0],
            &f.bundle.next_state.balance_state.enc_balances[0]
        )
        .unwrap(),
        B_GENESIS[0] + INTER_CHANNEL_AMOUNT,
        "dave's accumulated slot decrypts to 10 + 5"
    );

    // (e) Balance refresh: dave's slot is replaced by a fresh re-encryption, counter reset (D3).
    let pis = f.refresh.verify(&VERIFIER).unwrap();
    assert_eq!(pis.kind, ChannelTransitionKind::BalanceRefresh);
    assert_eq!((pis.prev_state_version, pis.next_state_version), (2, 3));
    assert_eq!(
        pis.prev_settled_tx_chain, pis.next_settled_tx_chain,
        "a refresh never advances the settled-tx chain"
    );
    assert_eq!(
        f.refresh.next_state.balance_state.pending_adds[..E2E_ACTIVE],
        [0, 0, 0]
    );
    let final_state = f.refresh.next_state.clone();
    assert_eq!(
        decrypt_amount(&f.b_sks[0], &final_state.balance_state.enc_balances[0]).unwrap(),
        B_GENESIS[0] + INTER_CHANNEL_AMOUNT,
        "the refreshed slot still decrypts to the same hidden balance"
    );

    // (f) Close on channel B: CloseWithdrawal + CloseIntent carry the v2 chain/version bindings.
    let close_tx = close_withdrawal_for(&final_state, 701);
    let close_intent = CloseIntent::new(1, &final_state, &close_tx, 4).unwrap();
    assert_eq!(close_intent.final_state_version, 3);
    assert_eq!(
        close_intent.final_settled_tx_chain,
        settled_tx_chain_push(
            settled_tx_chain_push(Bytes32::default(), f.import.inter_channel_tx.tx_hash),
            f.tx_leaf,
        ),
        "the close intent pins the full settle history of channel B"
    );
    // IMCI digest stability: rebuilding the intent from the same data reproduces the digest.
    assert_eq!(
        close_intent.signing_digest(),
        CloseIntent::new(1, &final_state, &close_tx, 4)
            .unwrap()
            .signing_digest()
    );
    // The FULL P7 close circuit (detail2 §F-3, D4) is proven for channel A at a1 — the
    // post-in-channel state. Its settled_tx_chain is still genesis (= 0x00…00; in-channel
    // transfers never advance the chain), so the REAL initial balance proof for channel 5
    // carries the matching `settled_tx_chain` / `channel_id` public inputs that the circuit
    // constrains against the close PIs. On top of the IMCH/IMCL/IMCI digest chain the circuit
    // recomputes H1 from the witnessed ciphertext digests and verifies 3 REAL SPHINCS+ member
    // signatures over the recomputed IMCH digest.
    let a1 = f.in_channel.next_state.clone();
    let a1_close_tx = close_withdrawal_for(&a1, 721);
    let a1_close_intent = CloseIntent::new(1, &a1, &a1_close_tx, 4).unwrap();
    assert_eq!(a1_close_intent.final_settled_tx_chain, Bytes32::default());
    let close_fx = close_fixture::fixture();
    let t_balance = std::time::Instant::now();
    let initial_balance_proof = close_fx
        .balance_processor
        .prove_initial(
            a1.channel_id,
            crate::common::salt::Salt::rand(&mut rand::thread_rng()),
        )
        .unwrap();
    println!("[e2e] initial balance proof: {:?}", t_balance.elapsed());
    let (a1_member_auth, a1_list_proof) = close_fixture::member_auth_for_digest(a1.digest, 0xe2ec);
    let close_witness: ChannelCloseFullWitness<F, C, D> = ChannelCloseFullWitness {
        close: ChannelCloseWitness {
            final_channel_state: a1.clone(),
            close_tx: a1_close_tx,
            close_intent: a1_close_intent,
        },
        final_balance_proof: initial_balance_proof,
        member_auth: a1_member_auth,
        list_proof: a1_list_proof,
    };
    let t_close = std::time::Instant::now();
    let close_proof = close_fx.close_circuit.prove(&close_witness).unwrap();
    println!("[e2e] full close proof: {:?}", t_close.elapsed());
    close_fx.close_circuit.data.verify(close_proof).unwrap();

    // (g) WithdrawalClaim for dave: the E-3 decryption AIR opens his final slot publicly.
    let final_amount = B_GENESIS[0] + INTER_CHANNEL_AMOUNT;
    let dave_member = ChannelMember {
        pk_g: user(b_id, 21),
        member_slot: 0,
        l1_withdrawal_recipient: address_word(91),
    };
    let dave_slot = final_state.balance_state.enc_balances[0].clone();
    let claim_proof =
        prove_withdraw_claim(LEVEL, &f.b_pks[0], &f.b_sks[0], &dave_slot, final_amount).unwrap();
    let withdrawal_claim = WithdrawalClaim {
        close_intent_digest: close_intent.signing_digest(),
        member_pk_g: dave_member.pk_g,
        l1_recipient: dave_member.l1_withdrawal_recipient,
        user_amount_ct: dave_slot,
        withdrawal_nullifier: WithdrawalClaim::derive_nullifier(
            close_intent.signing_digest(),
            dave_member.pk_g,
        ),
        claim_proof,
    };
    let withdrawal_witness = WithdrawalClaimWitness {
        close_intent: close_intent.clone(),
        close_tx,
        member: dave_member,
        claim: withdrawal_claim,
        final_balance_state: final_state.balance_state.clone(),
        member_index: 0,
        user_pk: f.b_pks[0].clone(),
        amount: final_amount,
    };
    let pis = withdrawal_witness.to_public_inputs(LEVEL).unwrap();
    assert_eq!(pis.amount, final_amount);
    assert_eq!(pis.final_balance_state_h1, final_state.balance_state.h1());

    // (h) CancelClose on channel A: a member who tried to close mid-send is overridden by the
    // revived inter-channel tx (abstract2 §3.5.3)…
    let sender_final = f.send.next_state.clone();
    let sender_close_tx = close_withdrawal_for(&sender_final, 711);
    let sender_close_intent = CloseIntent::new(2, &sender_final, &sender_close_tx, 4).unwrap();
    let cancel_witness = CancelCloseWitness {
        close_intent: sender_close_intent.clone(),
        revived_tx: f.send.inter_channel_tx.clone(),
        cancel_close: CancelClose::new(&sender_close_intent, &f.send.inter_channel_tx, vec![7, 7]),
    };
    cancel_witness.to_public_inputs().unwrap();

    // …and PostCloseIncomingClaim on channel B: a late inbound delta is claimed directly on L1
    // with the E-3 proof over the signed receiver delta ciphertext (abstract2 §3.5.5).
    let late_delta_ct = f.send.inter_channel_tx.receiver_deltas[0].amount.clone();
    let late_claim_proof = prove_withdraw_claim(
        LEVEL,
        &f.b_pks[0],
        &f.b_sks[0],
        &late_delta_ct,
        INTER_CHANNEL_AMOUNT,
    )
    .unwrap();
    let post_close_claim = PostCloseIncomingClaim {
        close_intent_digest: close_intent.signing_digest(),
        incoming_tx_hash: f.send.inter_channel_tx.tx_hash,
        receiver_pk_g: user(b_id, 21),
        l1_recipient: address_word(91),
        receiver_amount: late_delta_ct,
        shared_native_nullifier: bytes32_word(801),
        recipient_memo: f.send.inter_channel_tx.recipient_memo.clone(),
        claim_proof: late_claim_proof,
    };
    let post_close_witness = PostCloseClaimWitness {
        close_intent_digest: close_intent.signing_digest(),
        closed_channel_id: b_id,
        source_tx: f.send.inter_channel_tx.clone(),
        claim: post_close_claim,
        receiver_pk: f.b_pks[0].clone(),
        amount: INTER_CHANNEL_AMOUNT,
    };
    let pis = post_close_witness.to_public_inputs(LEVEL).unwrap();
    assert_eq!(pis.amount, INTER_CHANNEL_AMOUNT);
}

// ---------------------------------------------------------------------------
// Negative suite — every test states the security property it demonstrates
// ---------------------------------------------------------------------------

/// E-1 is MANDATORY (abstract2 §3.1): a `ChannelTx` whose proof envelope carries no bytes must
/// be refused by every co-signer — there is no "trust the sender" path for hidden amounts.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn in_channel_tx_without_zkp_is_rejected() {
    let mut witness = flow().in_channel.clone();
    witness.channel_tx.channel_tx_zkp.proof = vec![];
    assert!(matches!(
        witness.verify(&VERIFIER),
        Err(ChannelStateUpdateError::ProofVerification(_))
    ));
}

/// The receiving slot is recomputed publicly: crediting the delta twice (or anything other than
/// the exact homomorphic sum) is caught by every co-signer without any key material.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn bundle_apply_rejects_tampered_recipient_slot() {
    let mut witness = flow().bundle.clone();
    let double_credit = add_ciphertexts(
        &witness.next_state.balance_state.enc_balances[0],
        &witness.inter_channel_tx.receiver_deltas[0].amount,
    )
    .unwrap();
    witness.next_state.balance_state.enc_balances[0] = double_credit;
    witness.next_state = witness.next_state.clone().with_computed_digest();
    assert!(matches!(
        witness.verify(&VERIFIER),
        Err(ChannelStateUpdateError::InvalidCiphertextTransition(_))
    ));
}

/// H2 = 0 is RESERVED for in-channel updates (detail2 §C-2): an inter-channel send whose small
/// block claims `tx_tree_root = 0` would alias the in-channel signing target and must be refused.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn inter_channel_send_rejects_zero_tx_tree_root() {
    let mut witness = flow().send.clone();
    witness
        .inter_channel_tx
        .signed_small_block
        .message
        .tx_tree_root = Bytes32::default();
    assert!(matches!(
        witness.verify(&StructuralTransportVerifier, &VERIFIER),
        Err(ChannelStateUpdateError::InvalidH2Tag(_))
    ));
}

/// The signed next state's `h2_tag` must equal the small block's `tx_tree_root` (detail2 §D):
/// decoupling them would detach the member signatures from the block that settles the debit.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn inter_channel_send_rejects_h2_tag_mismatch() {
    let mut witness = flow().send.clone();
    witness.next_state.h2_tag = bytes32_word(999);
    witness.next_state = witness.next_state.clone().with_computed_digest();
    assert!(matches!(
        witness.verify(&StructuralTransportVerifier, &VERIFIER),
        Err(ChannelStateUpdateError::InvalidH2Tag(_))
    ));
}

/// `state_commitment_root` of the signed small block IS H1' of the post-debit balance state
/// (detail2 §C-7, structural atomicity §D-3): a root that does not match the recomputed h1()
/// breaks the binding between the settled block and the signed hidden balances.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn inter_channel_send_rejects_state_commitment_root_mismatch() {
    let mut witness = flow().send.clone();
    witness
        .inter_channel_tx
        .signed_small_block
        .message
        .state_commitment_root = bytes32_word(998);
    assert!(matches!(
        witness.verify(&StructuralTransportVerifier, &VERIFIER),
        Err(ChannelStateUpdateError::InvalidSmallBlock(_))
    ));
}

/// `state_version` is strictly monotone +1 (OneStatePerVersion, ChannelSafety2.lean): a version
/// skip would open a gap for a parallel, equally "newest" state in the L1 close ordering.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn inter_channel_send_rejects_version_skip() {
    let mut witness = flow().send.clone();
    witness.next_state.balance_state.state_version += 1; // prev + 2 overall
    witness.next_state = witness.next_state.clone().with_computed_digest();
    assert!(matches!(
        witness.verify(&StructuralTransportVerifier, &VERIFIER),
        Err(ChannelStateUpdateError::InvalidStateVersion(_))
    ));
}

/// D3 exit-liveness defense: once a slot's `pending_adds` hits `MAX_HOMO_ADDS_BEFORE_REFRESH`
/// (64), one more homomorphic add must be refused until the member refreshes — co-signers
/// enforce the budget before the noise/digit headroom can be flooded.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn bundle_apply_rejects_pending_adds_over_budget() {
    let mut witness = flow().bundle.clone();
    witness.prev_state.balance_state.pending_adds[0] = MAX_HOMO_ADDS_BEFORE_REFRESH;
    witness.prev_state = witness.prev_state.clone().with_computed_digest();
    witness.next_state.prev_digest = witness.prev_state.digest;
    witness.next_state.balance_state.pending_adds[0] = MAX_HOMO_ADDS_BEFORE_REFRESH + 1;
    witness.next_state = witness.next_state.clone().with_computed_digest();
    // Either the budget gate or the balance-state validate() (counter above MAX) must fire.
    assert!(matches!(
        witness.verify(&VERIFIER),
        Err(ChannelStateUpdateError::InvalidPendingAdds(_)
            | ChannelStateUpdateError::InvalidCiphertextTransition(_))
    ));
}

/// The settled-tx chain must absorb EXACTLY the tx leaf recomputed from the signed transfer
/// (detail2 §C-6/F-1): pushing any other leaf detaches the signed state from the settle history
/// that the close game replays on L1.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn inter_channel_send_rejects_wrong_chain_leaf() {
    let mut witness = flow().send.clone();
    witness.next_state.balance_state.settled_tx_chain = settled_tx_chain_push(
        witness.prev_state.balance_state.settled_tx_chain,
        bytes32_word(666),
    );
    // Keep the (earlier-checked) H1 binding consistent so the chain check itself is exercised.
    witness
        .inter_channel_tx
        .signed_small_block
        .message
        .state_commitment_root = witness.next_state.balance_state.h1();
    witness.next_state = witness.next_state.clone().with_computed_digest();
    assert!(matches!(
        witness.verify(&StructuralTransportVerifier, &VERIFIER),
        Err(ChannelStateUpdateError::InvalidSettledTxChain(_))
    ));
}

/// A `ChannelTx` (and its E-1 proof) is bound to the prev state it was authored against: the
/// E-1 transcript absorbs the sender's prev-slot ciphertext, so replaying the same signed tx
/// against any other prev state (here: same balance, different encryption) fails verification.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn in_channel_tx_replay_against_other_prev_state_is_rejected() {
    let fixture = flow();
    let mut rng = SmallRng::seed_from_u64(0xdead);
    let mut witness = fixture.in_channel.clone();
    let (other_before, _) = encrypt_amount(&mut rng, &fixture.a_pks[0], A_GENESIS[0]).unwrap();
    witness.prev_state.balance_state.enc_balances[0] = other_before;
    witness.prev_state = witness.prev_state.clone().with_computed_digest();
    witness.next_state.prev_digest = witness.prev_state.digest;
    witness.next_state = witness.next_state.clone().with_computed_digest();
    assert!(matches!(
        witness.verify(&VERIFIER),
        Err(ChannelStateUpdateError::ProofVerification(_))
    ));
}

/// Cross-purpose replay (F2-B): a valid E-1 channelTxZKP smuggled into the `channel_update_zkp`
/// slot must fail — the verifier rebuilds the E-2 statement with ITS purpose domain word, so the
/// transcript diverges even though the bytes are a genuine proof.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn inter_channel_send_rejects_e1_proof_in_channel_update_slot() {
    let fixture = flow();
    let mut witness = fixture.send.clone();
    witness.inter_channel_tx.channel_update_zkp.proof =
        fixture.in_channel.channel_tx.channel_tx_zkp.proof.clone();
    assert!(matches!(
        witness.verify(&StructuralTransportVerifier, &VERIFIER),
        Err(ChannelStateUpdateError::ProofVerification(_))
    ));
}

/// The sender-side before/after ciphertexts of flowReceive3 are witness-only data, but they
/// CANNOT be forged: the E-2 transcript binds all four ciphertexts, so any pair other than the
/// genuine one (here: before/after swapped) fails the re-verification on the receiver side.
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn bundle_apply_rejects_forged_sender_cts() {
    let mut witness = flow().bundle.clone();
    std::mem::swap(&mut witness.sender_before_ct, &mut witness.sender_after_ct);
    assert!(matches!(
        witness.verify(&VERIFIER),
        Err(ChannelStateUpdateError::ProofVerification(_))
    ));
}
