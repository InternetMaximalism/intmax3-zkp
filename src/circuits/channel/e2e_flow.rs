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
            ChannelStateUpdatePublicInputs, InterChannelImportUpdateWitness,
            InterChannelSendUpdateWitness, LatticeBindingVerifier,
            ReceiverDeltaApplicationWitness,
        },
    },
    common::{
        channel::{
            CancelClose, ChannelFund, ChannelMember, ChannelState, CloseIntent, CloseTransfer,
            CloseWithdrawal, InterChannelTx, LatticeCommitment, LatticeOpening, MemberSignature,
            MerkleInclusionProof, PostCloseIncomingClaim, ProofBackend, ReceiverBalanceDelta,
            TransitionProofRole,
        },
        user_id::AccountId,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::config::PoseidonGoldilocksConfig,
};

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
            _ => Ok(()),
        }
    }
}

struct MockLatticeVerifier;

impl LatticeBindingVerifier for MockLatticeVerifier {
    fn verify(
        &self,
        _commitment: &LatticeCommitment,
        _opening: &LatticeOpening,
    ) -> Result<(), ChannelStateUpdateError> {
        Ok(())
    }
}

fn commitment(seed: u8) -> LatticeCommitment {
    LatticeCommitment {
        commitment: vec![seed; 48],
    }
}

fn sample_state(amount: u32) -> ChannelState {
    ChannelState {
        channel_id: AccountId::new(5, 9).unwrap(),
        epoch: 1,
        channel_fund: ChannelFund {
            channel_id: AccountId::new(5, 9).unwrap(),
            amount: U256::from(amount),
            intmax_state_root: Bytes32::default(),
        },
        user_fund_root: Bytes32::default(),
        channel_nullifier_root: Bytes32::default(),
        personal_nullifier_root: Bytes32::default(),
        incoming_root: Bytes32::default(),
        prev_digest: Bytes32::default(),
        digest: Bytes32::default(),
        member_signatures: vec![MemberSignature {
            signer: AccountId::new(5, 10).unwrap(),
            signature: vec![1],
        }],
    }
    .with_computed_digest()
}

fn transport_proof() -> ChannelProofEnvelope {
    ChannelProofEnvelope {
        role: TransitionProofRole::IntmaxTransport,
        backend: ProofBackend::Plonky2,
        proof: vec![2],
    }
}

#[test]
fn channel_close_flow_e2e() {
    let prev_send = sample_state(100);
    let mut next_send = prev_send.clone();
    next_send.epoch += 1;
    next_send.channel_fund.amount = U256::from(93u32);
    next_send.user_fund_root = Bytes32::from_u32_slice(&[0, 0, 1, 0, 0, 0, 0, 0]).unwrap();
    next_send.channel_nullifier_root =
        Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    next_send.prev_digest = prev_send.digest;
    next_send = next_send.with_computed_digest();

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

    let send_tx = InterChannelTx {
        mkproof: MerkleInclusionProof {
            siblings: vec![],
            leaf_index: U256::default(),
        },
        sender_amount: commitment(1),
        sender_channel_id: prev_send.channel_id,
        receiver_channel_id: AccountId::new(7, 1).unwrap(),
        seal: Bytes32::from_u32_slice(&[8, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        intmax_transfer_commitment: Bytes32::default(),
        recipient_memo: vec![1, 2],
        receiver_deltas: vec![
            ReceiverBalanceDelta {
                receiver_id: AccountId::new(7, 11).unwrap(),
                amount: commitment(21),
            },
            ReceiverBalanceDelta {
                receiver_id: AccountId::new(7, 12).unwrap(),
                amount: commitment(22),
            },
            ReceiverBalanceDelta {
                receiver_id: AccountId::new(7, 13).unwrap(),
                amount: commitment(23),
            },
        ],
        receiver_update_proof: vec![1],
        sender_debit_proof: vec![2],
        sender_channel_signatures: vec![],
    };

    let send_witness = InterChannelSendUpdateWitness {
        prev_state: prev_send.clone(),
        next_state: next_send,
        inter_channel_tx: send_tx.clone(),
        sender_member_id: AccountId::new(5, 10).unwrap(),
        amount: 7,
        sender_amount_opening: LatticeOpening {
            amount: 7,
            randomness: vec![],
        },
        sender_before_commitment: commitment(2),
        sender_before_opening: LatticeOpening {
            amount: 50,
            randomness: vec![],
        },
        sender_after_commitment: commitment(3),
        sender_after_opening: LatticeOpening {
            amount: 43,
            randomness: vec![],
        },
        receiver_delta_openings: vec![
            LatticeOpening {
                amount: 5,
                randomness: vec![],
            },
            LatticeOpening {
                amount: 1,
                randomness: vec![],
            },
            LatticeOpening {
                amount: 1,
                randomness: vec![],
            },
        ],
        state_update_proof: send_state_proof,
        transport_proof: transport_proof(),
    };
    send_witness
        .verify(&MixedProofVerifier, &MockLatticeVerifier)
        .unwrap();

    let prev_import = sample_state(100);
    let mut next_import = prev_import.clone();
    next_import.epoch += 1;
    next_import.channel_fund.amount = U256::from(107u32);
    next_import.user_fund_root = Bytes32::from_u32_slice(&[0, 0, 2, 0, 0, 0, 0, 0]).unwrap();
    next_import.channel_nullifier_root =
        Bytes32::from_u32_slice(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    next_import.prev_digest = prev_import.digest;
    next_import = next_import.with_computed_digest();

    let import_state_proof = receiver_bundle_envelope(ReceiverBundleWitness {
        amount: 7,
        channel_fund_before: 100,
        channel_fund_after: 107,
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

    let import_tx = InterChannelTx {
        receiver_channel_id: prev_import.channel_id,
        sender_channel_id: AccountId::new(6, 1).unwrap(),
        receiver_update_proof: import_state_proof.proof.clone(),
        sender_amount: commitment(31),
        mkproof: MerkleInclusionProof {
            siblings: vec![],
            leaf_index: U256::default(),
        },
        seal: send_tx.seal,
        tx_hash: send_tx.tx_hash,
        intmax_transfer_commitment: Bytes32::default(),
        recipient_memo: vec![1, 2],
        receiver_deltas: vec![
            ReceiverBalanceDelta {
                receiver_id: AccountId::new(5, 12).unwrap(),
                amount: commitment(32),
            },
            ReceiverBalanceDelta {
                receiver_id: AccountId::new(5, 13).unwrap(),
                amount: commitment(33),
            },
            ReceiverBalanceDelta {
                receiver_id: AccountId::new(5, 14).unwrap(),
                amount: commitment(34),
            },
        ],
        sender_debit_proof: vec![2],
        sender_channel_signatures: vec![],
    };

    let import_witness = InterChannelImportUpdateWitness {
        prev_state: prev_import.clone(),
        next_state: next_import.clone(),
        inter_channel_tx: import_tx.clone(),
        amount: 7,
        receiver_applications: vec![
            ReceiverDeltaApplicationWitness {
                receiver_id: AccountId::new(5, 12).unwrap(),
                delta_commitment: commitment(32),
                delta_opening: LatticeOpening {
                    amount: 5,
                    randomness: vec![],
                },
                receiver_before_commitment: commitment(40),
                receiver_before_opening: LatticeOpening {
                    amount: 10,
                    randomness: vec![],
                },
                receiver_after_commitment: commitment(41),
                receiver_after_opening: LatticeOpening {
                    amount: 15,
                    randomness: vec![],
                },
            },
            ReceiverDeltaApplicationWitness {
                receiver_id: AccountId::new(5, 13).unwrap(),
                delta_commitment: commitment(33),
                delta_opening: LatticeOpening {
                    amount: 1,
                    randomness: vec![],
                },
                receiver_before_commitment: commitment(42),
                receiver_before_opening: LatticeOpening {
                    amount: 20,
                    randomness: vec![],
                },
                receiver_after_commitment: commitment(43),
                receiver_after_opening: LatticeOpening {
                    amount: 21,
                    randomness: vec![],
                },
            },
            ReceiverDeltaApplicationWitness {
                receiver_id: AccountId::new(5, 14).unwrap(),
                delta_commitment: commitment(34),
                delta_opening: LatticeOpening {
                    amount: 1,
                    randomness: vec![],
                },
                receiver_before_commitment: commitment(44),
                receiver_before_opening: LatticeOpening {
                    amount: 30,
                    randomness: vec![],
                },
                receiver_after_commitment: commitment(45),
                receiver_after_opening: LatticeOpening {
                    amount: 31,
                    randomness: vec![],
                },
            },
        ],
        state_update_proof: import_state_proof,
        transport_proof: transport_proof(),
    };
    import_witness
        .verify(&MixedProofVerifier, &MockLatticeVerifier)
        .unwrap();

    let close_tx = CloseWithdrawal {
        channel_id: next_import.channel_id,
        final_channel_state_digest: next_import.digest,
        intmax_state_root: next_import.channel_fund.intmax_state_root,
        transfers: vec![
            CloseTransfer {
                member_id: AccountId::new(5, 12).unwrap(),
                l1_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
                user_amount: commitment(46),
            },
            CloseTransfer {
                member_id: AccountId::new(5, 13).unwrap(),
                l1_recipient: Address::from_u32_slice(&[2, 2, 3, 4, 5]).unwrap(),
                user_amount: commitment(47),
            },
            CloseTransfer {
                member_id: AccountId::new(5, 14).unwrap(),
                l1_recipient: Address::from_u32_slice(&[3, 2, 3, 4, 5]).unwrap(),
                user_amount: commitment(48),
            },
        ],
        zkp: vec![9, 9, 9],
    };
    let close_intent = CloseIntent::new(
        5,
        &next_import,
        &close_tx,
        &[
            LatticeOpening {
                amount: 15,
                randomness: vec![],
            },
            LatticeOpening {
                amount: 21,
                randomness: vec![],
            },
            LatticeOpening {
                amount: 71,
                randomness: vec![],
            },
        ],
        123,
    )
    .unwrap();
    let close_witness = ChannelCloseWitness {
        final_channel_state: next_import.clone(),
        registered_members: vec![
            ChannelMember {
                member_id: AccountId::new(5, 12).unwrap(),
                signing_pubkey: vec![1],
                l1_withdrawal_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
            },
            ChannelMember {
                member_id: AccountId::new(5, 13).unwrap(),
                signing_pubkey: vec![2],
                l1_withdrawal_recipient: Address::from_u32_slice(&[2, 2, 3, 4, 5]).unwrap(),
            },
            ChannelMember {
                member_id: AccountId::new(5, 14).unwrap(),
                signing_pubkey: vec![3],
                l1_withdrawal_recipient: Address::from_u32_slice(&[3, 2, 3, 4, 5]).unwrap(),
            },
        ],
        close_tx: close_tx.clone(),
        close_intent: close_intent.clone(),
        transfer_openings: vec![
            LatticeOpening {
                amount: 15,
                randomness: vec![],
            },
            LatticeOpening {
                amount: 21,
                randomness: vec![],
            },
            LatticeOpening {
                amount: 71,
                randomness: vec![],
            },
        ],
    };
    let close_circuit = ChannelCloseCircuit::<F, C, D>::new();
    let close_proof = close_circuit.prove(&close_witness).unwrap();
    close_circuit.data.verify(close_proof).unwrap();

    let cancel_close = CancelClose::new(&close_intent, &send_tx, vec![7, 7]);
    let cancel_witness = CancelCloseWitness {
        close_intent: close_intent.clone(),
        revived_tx: send_tx,
        cancel_close,
    };
    cancel_witness.to_public_inputs().unwrap();

    let post_close_claim = PostCloseIncomingClaim {
        close_intent_digest: close_intent.signing_digest(),
        incoming_tx_hash: import_tx.tx_hash,
        receiver_id: AccountId::new(5, 12).unwrap(),
        l1_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
        receiver_amount: import_tx.receiver_deltas[0].amount.clone(),
        personal_nullifier: Bytes32::from_u32_slice(&[5, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        recipient_memo: vec![8, 8],
        claim_proof: vec![9],
    };
    let post_close_witness = PostCloseClaimWitness {
        close_intent_digest: close_intent.signing_digest(),
        closed_channel_id: next_import.channel_id,
        source_tx: import_tx,
        claim: post_close_claim,
        receiver_amount_opening: LatticeOpening {
            amount: 5,
            randomness: vec![],
        },
    };
    post_close_witness.to_public_inputs().unwrap();
}
