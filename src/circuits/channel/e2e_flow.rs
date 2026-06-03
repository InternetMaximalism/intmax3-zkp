use crate::{
    circuits::channel::{
        cancel_close_pis::CancelCloseWitness,
        close_circuit::ChannelCloseCircuit,
        close_pis::ChannelCloseWitness,
        plonky3_state::{
            RealPlonky3ChannelProofVerifier, ReceiverBundleRowWitness, ReceiverBundleWitness,
            SingleTransitionWitness, receiver_bundle_envelope, single_transition_envelope,
        },
        post_close_claim_pis::PostCloseClaimWitness,
        state_update_verifier::{
            ChannelProofEnvelope, ChannelProofVerifier, ChannelStateUpdateError,
            ChannelStateUpdatePublicInputs, InterChannelFundImportUpdateWitness,
            InterChannelSendUpdateWitness, LatticeProofPurpose, ReceiverDeltaApplicationWitness,
            ReceiverBundleApplyUpdateWitness,
        },
        withdrawal_claim_pis::WithdrawalClaimWitness,
    },
    common::channel::{
        CancelClose, ChannelBalance, ChannelFund, ChannelId, ChannelMember, ChannelRecord,
        ChannelState, ChannelStatus, CloseIntent, CloseWithdrawal, InterChannelTx, KeyId,
        LatticeCommitment, LatticeOpening, MemberSignature, MerkleInclusionProof,
        PostCloseIncomingClaim, ProofBackend, ReceiverBalanceDelta, SignedSmallBlock,
        SmallBlockRootMessage, TransitionProofRole, UserId, WithdrawalClaim,
        channel_balance_leaf_digest,
    },
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    lattice::proof_adapter::{
        LatticeRandomnessArray, RealLatticeBindingVerifier, compute_commitment_from_opening,
        default_lattice_systems, prove_opening,
    },
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

struct MixedProofVerifier;

impl ChannelProofVerifier for MixedProofVerifier {
    fn verify(
        &self,
        proof: &ChannelProofEnvelope,
        public_inputs: &ChannelStateUpdatePublicInputs,
    ) -> Result<(), ChannelStateUpdateError> {
        match (proof.role, proof.backend) {
            (TransitionProofRole::ChannelStateUpdate, ProofBackend::Plonky3) => {
                RealPlonky3ChannelProofVerifier.verify(proof, public_inputs)
            }
            (TransitionProofRole::IntmaxTransport, ProofBackend::Plonky2) => Ok(()),
            _ => Ok(()),
        }
    }
}

fn key(value: u64) -> KeyId {
    KeyId::new(value).unwrap()
}

fn user(channel_id: ChannelId, value: u64) -> UserId {
    UserId::from_parts(channel_id, key(value))
}

fn bytes32_word(word: u32) -> Bytes32 {
    Bytes32::from_u32_slice(&[word, 0, 0, 0, 0, 0, 0, 0]).unwrap()
}

fn address_word(word: u32) -> Address {
    Address::from_u32_slice(&[0, 0, 0, 0, word]).unwrap()
}

fn channel_record(channel_id: ChannelId, bp_key_id: KeyId, member_key_ids: Vec<KeyId>) -> ChannelRecord {
    ChannelRecord {
        channel_id,
        bp_key_id,
        member_key_ids,
        member_key_ids_root: bytes32_word(100 + channel_id.as_u64() as u32),
        special_close_penalty: U256::from(9u32),
        close_freeze_nonce: 0,
        status: ChannelStatus::Active,
    }
}

fn signatures_for(record: &ChannelRecord) -> Vec<MemberSignature> {
    record
        .member_key_ids
        .iter()
        .enumerate()
        .map(|(idx, key_id)| MemberSignature {
            key_id: *key_id,
            user_id: UserId::from_parts(record.channel_id, *key_id),
            signature: vec![1 + idx as u8],
            key_condition_proof: vec![11 + idx as u8],
        })
        .collect()
}

fn sample_state(
    record: &ChannelRecord,
    epoch: u64,
    small_block_number: u64,
    close_freeze_nonce: u64,
    fund_amount: u32,
    balance_root: Bytes32,
    shared_native_nullifier_root: Bytes32,
    unallocated_confirmed_incoming: U256,
    prev_digest: Bytes32,
) -> ChannelState {
    ChannelState {
        channel_id: record.channel_id,
        epoch,
        small_block_number,
        close_freeze_nonce,
        channel_fund: ChannelFund {
            channel_id: record.channel_id,
            amount: U256::from(fund_amount),
            intmax_state_root: bytes32_word(200 + fund_amount),
        },
        channel_balance_root: balance_root,
        shared_native_nullifier_root,
        unallocated_confirmed_incoming,
        prev_digest,
        digest: Bytes32::default(),
        member_signatures: signatures_for(record),
    }
    .with_computed_digest()
}

fn signed_small_block(
    source_record: &ChannelRecord,
    small_block_number: u64,
    medium_block_number: u64,
    close_freeze_nonce: u64,
) -> SignedSmallBlock {
    SignedSmallBlock {
        message: SmallBlockRootMessage {
            channel_id: source_record.channel_id,
            bp_key_id: source_record.bp_key_id,
            small_block_number,
            prev_small_block_root: bytes32_word(300),
            tx_tree_root: bytes32_word(301),
            state_commitment_root: bytes32_word(302),
            medium_epoch_hint: medium_block_number,
            close_freeze_nonce,
        },
        signatures: signatures_for(source_record),
        aggregated_signature_proof: vec![9, 9],
        medium_block_number,
        confirmation_proof: vec![8, 8],
    }
}

fn transport_proof() -> ChannelProofEnvelope {
    ChannelProofEnvelope {
        role: TransitionProofRole::IntmaxTransport,
        backend: ProofBackend::Plonky2,
        proof: vec![7, 7, 7],
    }
}

fn randomness(seed: i64) -> LatticeRandomnessArray {
    let mut out = [0i64; crate::lattice::proof_adapter::N];
    for (idx, slot) in out.iter_mut().enumerate() {
        let tweak = (idx as i64 % 3) - 1;
        *slot = (seed + tweak).clamp(-1, 1);
    }
    out
}

fn proven_opening(
    purpose: LatticeProofPurpose,
    amount: u64,
    seed: i64,
) -> (LatticeCommitment, LatticeOpening) {
    let randomness = randomness(seed);
    let opening = prove_opening(default_lattice_systems(), purpose, amount, &randomness)
        .expect("opening proof must be generated");
    let commitment = compute_commitment_from_opening(amount, &randomness);
    (commitment, opening)
}

#[test]
fn channel_native_send_close_and_recovery_e2e() {
    let proof_verifier = MixedProofVerifier;
    let lattice_verifier = RealLatticeBindingVerifier::default();

    let sender_channel_id = ChannelId::new(5).unwrap();
    let receiver_channel_id = ChannelId::new(7).unwrap();
    let sender_record =
        channel_record(sender_channel_id, key(10), vec![key(10), key(11), key(12)]);
    let receiver_record =
        channel_record(receiver_channel_id, key(21), vec![key(21), key(22), key(23)]);

    let prev_send = sample_state(
        &sender_record,
        1,
        7,
        0,
        100,
        bytes32_word(401),
        bytes32_word(402),
        U256::zero(),
        Bytes32::default(),
    );
    let next_send = sample_state(
        &sender_record,
        2,
        8,
        0,
        93,
        bytes32_word(411),
        bytes32_word(412),
        U256::zero(),
        prev_send.digest,
    );

    let send_state_proof = single_transition_envelope(SingleTransitionWitness {
        is_in_channel: false,
        amount: 7,
        sender_before: 50,
        sender_after: 43,
        receiver_before: 0,
        receiver_after: 0,
        channel_fund_before: 100,
        channel_fund_after: 93,
    })
    .unwrap();

    let (sender_amount_commitment, sender_amount_opening) =
        proven_opening(LatticeProofPurpose::TransferAmount, 7, 1);
    let (real_delta_commitment, real_delta_opening) =
        proven_opening(LatticeProofPurpose::TransferAmount, 5, 21);
    let (dummy_delta_commitment_0, dummy_delta_opening_0) =
        proven_opening(LatticeProofPurpose::TransferAmount, 1, 22);
    let (dummy_delta_commitment_1, dummy_delta_opening_1) =
        proven_opening(LatticeProofPurpose::TransferAmount, 1, 23);
    let (sender_before_commitment, sender_before_opening) =
        proven_opening(LatticeProofPurpose::BalanceOpening, 50, 2);
    let (sender_after_commitment, sender_after_opening) =
        proven_opening(LatticeProofPurpose::BalanceOpening, 43, 3);

    let signed_root = signed_small_block(&sender_record, 8, 11, prev_send.close_freeze_nonce);
    let transport = transport_proof();
    let inter_channel_tx = InterChannelTx {
        tx_inclusion_proof: MerkleInclusionProof {
            siblings: vec![],
            leaf_index: U256::zero(),
        },
        signed_small_block: signed_root.clone(),
        sender_amount: sender_amount_commitment.clone(),
        source_channel_id: sender_channel_id,
        destination_channel_id: receiver_channel_id,
        source_key_id: key(10),
        source_user_id: user(sender_channel_id, 10),
        seal: bytes32_word(501),
        tx_hash: bytes32_word(502),
        intmax_transfer_commitment: bytes32_word(503),
        recipient_memo: vec![1, 2, 3],
        receiver_deltas: vec![
            ReceiverBalanceDelta {
                receiver_key_id: key(21),
                receiver_user_id: user(receiver_channel_id, 21),
                amount: real_delta_commitment.clone(),
            },
            ReceiverBalanceDelta {
                receiver_key_id: key(22),
                receiver_user_id: user(receiver_channel_id, 22),
                amount: dummy_delta_commitment_0.clone(),
            },
            ReceiverBalanceDelta {
                receiver_key_id: key(23),
                receiver_user_id: user(receiver_channel_id, 23),
                amount: dummy_delta_commitment_1.clone(),
            },
        ],
        receiver_update_proof: vec![3, 3, 3],
        sender_balance_update_proof: send_state_proof.proof.clone(),
        transport_proof: transport.proof.clone(),
    };

    let send_witness = InterChannelSendUpdateWitness {
        channel_record: sender_record.clone(),
        prev_state: prev_send.clone(),
        next_state: next_send.clone(),
        inter_channel_tx: inter_channel_tx.clone(),
        amount: 7,
        sender_amount_opening,
        sender_before_balance: ChannelBalance {
            channel_id: sender_channel_id,
            user_id: user(sender_channel_id, 10),
            balance_commitment: sender_before_commitment.clone(),
        },
        sender_before_opening,
        sender_after_balance: ChannelBalance {
            channel_id: sender_channel_id,
            user_id: user(sender_channel_id, 10),
            balance_commitment: sender_after_commitment.clone(),
        },
        sender_after_opening,
        receiver_delta_openings: vec![
            real_delta_opening.clone(),
            dummy_delta_opening_0.clone(),
            dummy_delta_opening_1.clone(),
        ],
        state_update_proof: send_state_proof,
        transport_proof: transport.clone(),
    };
    send_witness
        .verify(&proof_verifier, &lattice_verifier)
        .unwrap();

    let prev_import = sample_state(
        &receiver_record,
        10,
        30,
        0,
        200,
        bytes32_word(601),
        bytes32_word(602),
        U256::zero(),
        Bytes32::default(),
    );
    let next_import = sample_state(
        &receiver_record,
        11,
        31,
        0,
        207,
        prev_import.channel_balance_root,
        bytes32_word(603),
        U256::from(7u32),
        prev_import.digest,
    );

    let import_witness = InterChannelFundImportUpdateWitness {
        source_channel_record: sender_record.clone(),
        receiver_channel_record: receiver_record.clone(),
        prev_state: prev_import.clone(),
        next_state: next_import.clone(),
        inter_channel_tx: inter_channel_tx.clone(),
        amount: 7,
        transport_proof: transport.clone(),
    };
    import_witness.verify(&proof_verifier).unwrap();

    let (receiver_before_commitment_0, receiver_before_opening_0) =
        proven_opening(LatticeProofPurpose::BalanceOpening, 10, 30);
    let (receiver_after_commitment_0, receiver_after_opening_0) =
        proven_opening(LatticeProofPurpose::BalanceOpening, 15, 31);
    let (receiver_before_commitment_1, receiver_before_opening_1) =
        proven_opening(LatticeProofPurpose::BalanceOpening, 20, 32);
    let (receiver_after_commitment_1, receiver_after_opening_1) =
        proven_opening(LatticeProofPurpose::BalanceOpening, 21, 33);
    let (receiver_before_commitment_2, receiver_before_opening_2) =
        proven_opening(LatticeProofPurpose::BalanceOpening, 30, 34);
    let (receiver_after_commitment_2, receiver_after_opening_2) =
        proven_opening(LatticeProofPurpose::BalanceOpening, 31, 35);

    let final_balance_root = channel_balance_leaf_digest(
        receiver_channel_id,
        user(receiver_channel_id, 21),
        &receiver_after_commitment_0,
    );
    let next_bundle = sample_state(
        &receiver_record,
        12,
        32,
        0,
        207,
        final_balance_root,
        next_import.shared_native_nullifier_root,
        U256::zero(),
        next_import.digest,
    );

    let bundle_state_proof = receiver_bundle_envelope(ReceiverBundleWitness {
        amount: 7,
        unallocated_before: 7,
        unallocated_after: 0,
        rows: vec![
            ReceiverBundleRowWitness {
                receiver_before: 10,
                delta_amount: 5,
                receiver_after: 15,
                is_dummy: false,
            },
            ReceiverBundleRowWitness {
                receiver_before: 20,
                delta_amount: 1,
                receiver_after: 21,
                is_dummy: true,
            },
            ReceiverBundleRowWitness {
                receiver_before: 30,
                delta_amount: 1,
                receiver_after: 31,
                is_dummy: true,
            },
        ],
    })
    .unwrap();
    let receiver_bundle_tx = InterChannelTx {
        receiver_update_proof: bundle_state_proof.proof.clone(),
        ..inter_channel_tx.clone()
    };

    let bundle_witness = ReceiverBundleApplyUpdateWitness {
        receiver_channel_record: receiver_record.clone(),
        prev_state: next_import.clone(),
        next_state: next_bundle.clone(),
        inter_channel_tx: receiver_bundle_tx.clone(),
        amount: 7,
        receiver_applications: vec![
            ReceiverDeltaApplicationWitness {
                receiver_user_id: user(receiver_channel_id, 21),
                delta_commitment: real_delta_commitment.clone(),
                delta_opening: real_delta_opening.clone(),
                receiver_before_commitment: receiver_before_commitment_0.clone(),
                receiver_before_opening: receiver_before_opening_0,
                receiver_after_commitment: receiver_after_commitment_0.clone(),
                receiver_after_opening: receiver_after_opening_0.clone(),
            },
            ReceiverDeltaApplicationWitness {
                receiver_user_id: user(receiver_channel_id, 22),
                delta_commitment: dummy_delta_commitment_0.clone(),
                delta_opening: dummy_delta_opening_0.clone(),
                receiver_before_commitment: receiver_before_commitment_1,
                receiver_before_opening: receiver_before_opening_1,
                receiver_after_commitment: receiver_after_commitment_1,
                receiver_after_opening: receiver_after_opening_1,
            },
            ReceiverDeltaApplicationWitness {
                receiver_user_id: user(receiver_channel_id, 23),
                delta_commitment: dummy_delta_commitment_1.clone(),
                delta_opening: dummy_delta_opening_1.clone(),
                receiver_before_commitment: receiver_before_commitment_2,
                receiver_before_opening: receiver_before_opening_2,
                receiver_after_commitment: receiver_after_commitment_2,
                receiver_after_opening: receiver_after_opening_2,
            },
        ],
        state_update_proof: bundle_state_proof,
    };
    bundle_witness
        .verify(&proof_verifier, &lattice_verifier)
        .unwrap();

    let receiver_close_tx = CloseWithdrawal {
        channel_id: receiver_channel_id,
        final_channel_state_digest: next_bundle.digest,
        final_channel_balance_root: next_bundle.channel_balance_root,
        intmax_state_root: next_bundle.channel_fund.intmax_state_root,
        burn_tx_hash: bytes32_word(701),
        burn_amount: next_bundle.channel_fund.amount,
        zkp: vec![1, 2, 3],
    };
    let receiver_close_intent =
        CloseIntent::new(1, &next_bundle, &receiver_close_tx, signed_root.medium_block_number)
            .unwrap();
    let receiver_close_witness = ChannelCloseWitness {
        final_channel_state: next_bundle.clone(),
        close_tx: receiver_close_tx.clone(),
        close_intent: receiver_close_intent.clone(),
    };
    let close_circuit = ChannelCloseCircuit::<F, C, D>::new();
    let close_proof = close_circuit.prove(&receiver_close_witness).unwrap();
    close_circuit.data.verify(close_proof).unwrap();

    let withdrawal_member = ChannelMember {
        key_id: key(21),
        user_id: user(receiver_channel_id, 21),
        l1_withdrawal_recipient: address_word(91),
    };
    let withdrawal_claim = WithdrawalClaim {
        close_intent_digest: receiver_close_intent.signing_digest(),
        user_id: withdrawal_member.user_id,
        l1_recipient: withdrawal_member.l1_withdrawal_recipient,
        user_amount: receiver_after_commitment_0.clone(),
        withdrawal_nullifier: WithdrawalClaim::derive_nullifier(
            receiver_close_intent.signing_digest(),
            withdrawal_member.user_id,
        ),
        claim_proof: vec![4, 5, 6],
    };
    let withdrawal_witness = WithdrawalClaimWitness {
        close_intent: receiver_close_intent.clone(),
        close_tx: receiver_close_tx,
        member: withdrawal_member,
        claim: withdrawal_claim,
        opening: receiver_after_opening_0.clone(),
        membership_proof: MerkleInclusionProof {
            siblings: vec![],
            leaf_index: U256::zero(),
        },
    };
    withdrawal_witness.to_public_inputs().unwrap();

    let sender_close_tx = CloseWithdrawal {
        channel_id: sender_channel_id,
        final_channel_state_digest: next_send.digest,
        final_channel_balance_root: next_send.channel_balance_root,
        intmax_state_root: next_send.channel_fund.intmax_state_root,
        burn_tx_hash: bytes32_word(711),
        burn_amount: next_send.channel_fund.amount,
        zkp: vec![6, 6, 6],
    };
    let sender_close_intent =
        CloseIntent::new(2, &next_send, &sender_close_tx, signed_root.medium_block_number).unwrap();
    let cancel_witness = CancelCloseWitness {
        close_intent: sender_close_intent,
        revived_tx: inter_channel_tx.clone(),
        cancel_close: CancelClose::new(
            &CloseIntent::new(2, &next_send, &sender_close_tx, signed_root.medium_block_number)
                .unwrap(),
            &inter_channel_tx,
            vec![7, 7],
        ),
    };
    cancel_witness.to_public_inputs().unwrap();

    let post_close_claim = PostCloseIncomingClaim {
        close_intent_digest: receiver_close_intent.signing_digest(),
        incoming_tx_hash: inter_channel_tx.tx_hash,
        receiver_user_id: user(receiver_channel_id, 21),
        l1_recipient: address_word(91),
        receiver_amount: real_delta_commitment,
        shared_native_nullifier: bytes32_word(801),
        recipient_memo: inter_channel_tx.recipient_memo.clone(),
        claim_proof: vec![8, 8],
    };
    let post_close_witness = PostCloseClaimWitness {
        close_intent_digest: receiver_close_intent.signing_digest(),
        closed_channel_id: receiver_channel_id,
        source_tx: receiver_bundle_tx,
        claim: post_close_claim,
        receiver_amount_opening: real_delta_opening,
    };
    post_close_witness.to_public_inputs().unwrap();
}
