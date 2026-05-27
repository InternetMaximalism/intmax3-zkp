use plonky2_keccak::utils::solidity_keccak256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::{
        channel::{
            ChannelId, ChannelState, ChannelTransitionKind, InterChannelTx, LatticeCommitment,
            LatticeOpening, Pay, ProofBackend, ReceiverBalanceDelta,
            TransitionProofRole,
        },
        user_id::AccountId,
    },
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256},
};

const MIN_RECEIVER_DELTA_COUNT: usize = 3;
const MIN_DUMMY_DELTA_COUNT: usize = 2;
const MAX_DUMMY_DELTA_AMOUNT: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelProofEnvelope {
    pub role: TransitionProofRole,
    pub backend: ProofBackend,
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStateUpdatePublicInputs {
    pub kind: ChannelTransitionKind,
    pub channel_id: ChannelId,
    pub prev_state_digest: Bytes32,
    pub next_state_digest: Bytes32,
    pub amount: u64,
    pub sender_balance_before: u64,
    pub sender_balance_after: u64,
    pub receiver_balance_before: u64,
    pub receiver_balance_after: u64,
    pub receiver_entry_count: u64,
    pub receiver_dummy_count: u64,
    pub sender: AccountId,
    pub receiver: AccountId,
    pub channel_fund_before: U256,
    pub channel_fund_after: U256,
    pub channel_nullifier_before: Bytes32,
    pub channel_nullifier_after: Bytes32,
    pub personal_nullifier_before: Bytes32,
    pub personal_nullifier_after: Bytes32,
    pub incoming_before: Bytes32,
    pub incoming_after: Bytes32,
    pub transition_digest: Bytes32,
}

impl ChannelStateUpdatePublicInputs {
    pub fn digest(&self) -> Bytes32 {
        let words = [
            vec![self.kind as u32],
            self.channel_id.to_u32_vec(),
            self.prev_state_digest.to_u32_vec(),
            self.next_state_digest.to_u32_vec(),
            split_u64(self.amount),
            split_u64(self.sender_balance_before),
            split_u64(self.sender_balance_after),
            split_u64(self.receiver_balance_before),
            split_u64(self.receiver_balance_after),
            split_u64(self.receiver_entry_count),
            split_u64(self.receiver_dummy_count),
            self.sender.to_u32_vec(),
            self.receiver.to_u32_vec(),
            self.channel_fund_before.to_u32_vec(),
            self.channel_fund_after.to_u32_vec(),
            self.channel_nullifier_before.to_u32_vec(),
            self.channel_nullifier_after.to_u32_vec(),
            self.personal_nullifier_before.to_u32_vec(),
            self.personal_nullifier_after.to_u32_vec(),
            self.incoming_before.to_u32_vec(),
            self.incoming_after.to_u32_vec(),
            self.transition_digest.to_u32_vec(),
        ]
        .concat();
        Bytes32::from_u32_slice(&solidity_keccak256(&words)).expect("keccak output must be bytes32")
    }
}

pub trait ChannelProofVerifier {
    fn verify(
        &self,
        proof: &ChannelProofEnvelope,
        public_inputs: &ChannelStateUpdatePublicInputs,
    ) -> Result<(), ChannelStateUpdateError>;
}

pub trait LatticeBindingVerifier {
    fn verify(
        &self,
        commitment: &LatticeCommitment,
        opening: &LatticeOpening,
    ) -> Result<(), ChannelStateUpdateError>;
}

#[derive(Debug, Error)]
pub enum ChannelStateUpdateError {
    #[error("invalid proof role: expected {expected:?}, got {actual:?}")]
    InvalidProofRole {
        expected: TransitionProofRole,
        actual: TransitionProofRole,
    },

    #[error("invalid proof backend: expected {expected:?}, got {actual:?}")]
    InvalidProofBackend {
        expected: ProofBackend,
        actual: ProofBackend,
    },

    #[error("invalid state linkage: {0}")]
    InvalidStateLinkage(String),

    #[error("invalid amount relation: {0}")]
    InvalidAmountRelation(String),

    #[error("invalid root transition: {0}")]
    InvalidRootTransition(String),

    #[error("invalid transition digest: {0}")]
    InvalidTransitionDigest(String),

    #[error("invalid receiver delta bundle: {0}")]
    InvalidReceiverDeltaBundle(String),

    #[error("proof verification failed: {0}")]
    ProofVerification(String),

    #[error("public input mismatch: {0}")]
    PublicInputMismatch(String),
}

#[derive(Clone, Debug)]
pub struct ReceiverDeltaApplicationWitness {
    pub receiver_id: AccountId,
    pub delta_commitment: LatticeCommitment,
    pub delta_opening: LatticeOpening,
    pub receiver_before_commitment: LatticeCommitment,
    pub receiver_before_opening: LatticeOpening,
    pub receiver_after_commitment: LatticeCommitment,
    pub receiver_after_opening: LatticeOpening,
}

#[derive(Clone, Debug)]
pub struct InChannelTransferUpdateWitness {
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub pay: Pay,
    pub pay_amount_opening: LatticeOpening,
    pub sender_before_commitment: LatticeCommitment,
    pub sender_before_opening: LatticeOpening,
    pub sender_after_commitment: LatticeCommitment,
    pub sender_after_opening: LatticeOpening,
    pub receiver_before_commitment: LatticeCommitment,
    pub receiver_before_opening: LatticeOpening,
    pub receiver_after_commitment: LatticeCommitment,
    pub receiver_after_opening: LatticeOpening,
    pub state_update_proof: ChannelProofEnvelope,
}

#[derive(Clone, Debug)]
pub struct InterChannelSendUpdateWitness {
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub inter_channel_tx: InterChannelTx,
    pub sender_member_id: AccountId,
    pub amount: u64,
    pub sender_amount_opening: LatticeOpening,
    pub sender_before_commitment: LatticeCommitment,
    pub sender_before_opening: LatticeOpening,
    pub sender_after_commitment: LatticeCommitment,
    pub sender_after_opening: LatticeOpening,
    pub receiver_delta_openings: Vec<LatticeOpening>,
    pub state_update_proof: ChannelProofEnvelope,
    pub transport_proof: ChannelProofEnvelope,
}

#[derive(Clone, Debug)]
pub struct InterChannelImportUpdateWitness {
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub inter_channel_tx: InterChannelTx,
    pub amount: u64,
    pub receiver_applications: Vec<ReceiverDeltaApplicationWitness>,
    pub state_update_proof: ChannelProofEnvelope,
    pub transport_proof: ChannelProofEnvelope,
}

impl InChannelTransferUpdateWitness {
    pub fn verify<VP, VL>(
        &self,
        proof_verifier: &VP,
        lattice_verifier: &VL,
    ) -> Result<ChannelStateUpdatePublicInputs, ChannelStateUpdateError>
    where
        VP: ChannelProofVerifier,
        VL: LatticeBindingVerifier,
    {
        verify_state_linkage(&self.prev_state, &self.next_state)?;
        ensure_same_channel_fund(&self.prev_state, &self.next_state)?;
        ensure_different_root(
            "user_fund_root",
            self.prev_state.user_fund_root,
            self.next_state.user_fund_root,
        )?;
        ensure_same_root(
            "channel_nullifier_root",
            self.prev_state.channel_nullifier_root,
            self.next_state.channel_nullifier_root,
        )?;
        ensure_same_root(
            "personal_nullifier_root",
            self.prev_state.personal_nullifier_root,
            self.next_state.personal_nullifier_root,
        )?;
        ensure_same_root(
            "incoming_root",
            self.prev_state.incoming_root,
            self.next_state.incoming_root,
        )?;

        lattice_verifier.verify(&self.pay.amount, &self.pay_amount_opening)?;
        lattice_verifier.verify(&self.sender_before_commitment, &self.sender_before_opening)?;
        lattice_verifier.verify(&self.sender_after_commitment, &self.sender_after_opening)?;
        lattice_verifier.verify(
            &self.receiver_before_commitment,
            &self.receiver_before_opening,
        )?;
        lattice_verifier.verify(
            &self.receiver_after_commitment,
            &self.receiver_after_opening,
        )?;
        if self.pay.sender == self.pay.receiver {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "sender and receiver must be distinct members".to_string(),
            ));
        }

        let amount = self
            .receiver_after_opening
            .amount
            .checked_sub(self.receiver_before_opening.amount)
            .ok_or_else(|| {
                ChannelStateUpdateError::InvalidAmountRelation(
                    "receiver balance must increase".to_string(),
                )
            })?;
        if self.pay_amount_opening.amount != amount {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "pay amount opening mismatch".to_string(),
            ));
        }
        if self.sender_before_opening.amount != self.sender_after_opening.amount + amount {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "sender balance decrement mismatch".to_string(),
            ));
        }
        let expected_pay_digest = Pay::signing_digest(
            self.prev_state.channel_id,
            self.prev_state.digest,
            &self.pay.amount,
            self.pay.sender,
            self.pay.receiver,
        );
        if self.pay.digest != expected_pay_digest {
            return Err(ChannelStateUpdateError::InvalidTransitionDigest(
                "pay digest must match prev state, channel, amount, sender, and receiver"
                    .to_string(),
            ));
        }

        let public_inputs = ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::InChannelTransfer,
            channel_id: self.prev_state.channel_id,
            prev_state_digest: self.prev_state.digest,
            next_state_digest: self.next_state.digest,
            amount,
            sender_balance_before: self.sender_before_opening.amount,
            sender_balance_after: self.sender_after_opening.amount,
            receiver_balance_before: self.receiver_before_opening.amount,
            receiver_balance_after: self.receiver_after_opening.amount,
            receiver_entry_count: 1,
            receiver_dummy_count: 0,
            sender: self.pay.sender,
            receiver: self.pay.receiver,
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            channel_nullifier_before: self.prev_state.channel_nullifier_root,
            channel_nullifier_after: self.next_state.channel_nullifier_root,
            personal_nullifier_before: self.prev_state.personal_nullifier_root,
            personal_nullifier_after: self.next_state.personal_nullifier_root,
            incoming_before: self.prev_state.incoming_root,
            incoming_after: self.next_state.incoming_root,
            transition_digest: self.pay.digest,
        };

        verify_proof(
            proof_verifier,
            &self.state_update_proof,
            TransitionProofRole::ChannelStateUpdate,
            ProofBackend::Plonky3,
            &public_inputs,
        )?;
        Ok(public_inputs)
    }
}

impl InterChannelSendUpdateWitness {
    pub fn verify<VP, VL>(
        &self,
        proof_verifier: &VP,
        lattice_verifier: &VL,
    ) -> Result<ChannelStateUpdatePublicInputs, ChannelStateUpdateError>
    where
        VP: ChannelProofVerifier,
        VL: LatticeBindingVerifier,
    {
        verify_state_linkage(&self.prev_state, &self.next_state)?;
        if self.prev_state.channel_id != self.inter_channel_tx.sender_channel_id {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "sender channel id mismatch".to_string(),
            ));
        }
        ensure_different_root(
            "user_fund_root",
            self.prev_state.user_fund_root,
            self.next_state.user_fund_root,
        )?;
        if self.next_state.channel_fund.amount + u64_to_u256(self.amount)
            != self.prev_state.channel_fund.amount
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "channel fund must decrease by transfer amount".to_string(),
            ));
        }
        ensure_different_root(
            "channel_nullifier_root",
            self.prev_state.channel_nullifier_root,
            self.next_state.channel_nullifier_root,
        )?;
        ensure_same_root(
            "personal_nullifier_root",
            self.prev_state.personal_nullifier_root,
            self.next_state.personal_nullifier_root,
        )?;
        ensure_same_root(
            "incoming_root",
            self.prev_state.incoming_root,
            self.next_state.incoming_root,
        )?;

        lattice_verifier.verify(&self.sender_before_commitment, &self.sender_before_opening)?;
        lattice_verifier.verify(&self.sender_after_commitment, &self.sender_after_opening)?;
        lattice_verifier.verify(
            &self.inter_channel_tx.sender_amount,
            &self.sender_amount_opening,
        )?;
        if self.sender_amount_opening.amount != self.amount {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "inter-channel sender amount opening mismatch".to_string(),
            ));
        }

        if self.sender_before_opening.amount != self.sender_after_opening.amount + self.amount {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "sender balance decrement mismatch".to_string(),
            ));
        }
        verify_sender_supplied_receiver_bundle(
            lattice_verifier,
            &self.inter_channel_tx.receiver_deltas,
            &self.receiver_delta_openings,
            self.amount,
        )?;
        if self.transport_proof.proof != self.inter_channel_tx.sender_debit_proof {
            return Err(ChannelStateUpdateError::InvalidTransitionDigest(
                "transport proof bytes must match sender_debit_proof carried in inter-channel tx"
                    .to_string(),
            ));
        }

        let public_inputs = ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::InterChannelSend,
            channel_id: self.prev_state.channel_id,
            prev_state_digest: self.prev_state.digest,
            next_state_digest: self.next_state.digest,
            amount: self.amount,
            sender_balance_before: self.sender_before_opening.amount,
            sender_balance_after: self.sender_after_opening.amount,
            receiver_balance_before: 0,
            receiver_balance_after: 0,
            receiver_entry_count: self.inter_channel_tx.receiver_deltas.len() as u64,
            receiver_dummy_count: count_dummy_delta_openings(&self.receiver_delta_openings),
            sender: self.sender_member_id,
            receiver: self.inter_channel_tx.receiver_channel_id,
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            channel_nullifier_before: self.prev_state.channel_nullifier_root,
            channel_nullifier_after: self.next_state.channel_nullifier_root,
            personal_nullifier_before: self.prev_state.personal_nullifier_root,
            personal_nullifier_after: self.next_state.personal_nullifier_root,
            incoming_before: self.prev_state.incoming_root,
            incoming_after: self.next_state.incoming_root,
            transition_digest: self.inter_channel_tx.signing_digest(),
        };

        verify_proof(
            proof_verifier,
            &self.state_update_proof,
            TransitionProofRole::ChannelStateUpdate,
            ProofBackend::Plonky3,
            &public_inputs,
        )?;
        verify_proof(
            proof_verifier,
            &self.transport_proof,
            TransitionProofRole::IntmaxTransport,
            ProofBackend::Plonky2,
            &public_inputs,
        )?;
        Ok(public_inputs)
    }
}

impl InterChannelImportUpdateWitness {
    pub fn verify<VP, VL>(
        &self,
        proof_verifier: &VP,
        lattice_verifier: &VL,
    ) -> Result<ChannelStateUpdatePublicInputs, ChannelStateUpdateError>
    where
        VP: ChannelProofVerifier,
        VL: LatticeBindingVerifier,
    {
        verify_state_linkage(&self.prev_state, &self.next_state)?;
        if self.prev_state.channel_id != self.inter_channel_tx.receiver_channel_id {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "receiver channel id mismatch".to_string(),
            ));
        }
        if self.next_state.channel_fund.amount
            != self.prev_state.channel_fund.amount + u64_to_u256(self.amount)
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "channel fund must increase by imported amount".to_string(),
            ));
        }
        ensure_different_root(
            "channel_nullifier_root",
            self.prev_state.channel_nullifier_root,
            self.next_state.channel_nullifier_root,
        )?;
        ensure_same_root(
            "personal_nullifier_root",
            self.prev_state.personal_nullifier_root,
            self.next_state.personal_nullifier_root,
        )?;
        ensure_same_root(
            "incoming_root",
            self.prev_state.incoming_root,
            self.next_state.incoming_root,
        )?;
        ensure_different_root(
            "user_fund_root",
            self.prev_state.user_fund_root,
            self.next_state.user_fund_root,
        )?;
        verify_receiver_delta_applications(
            lattice_verifier,
            &self.inter_channel_tx.receiver_deltas,
            &self.receiver_applications,
            self.amount,
        )?;
        if self.state_update_proof.proof != self.inter_channel_tx.receiver_update_proof {
            return Err(ChannelStateUpdateError::InvalidTransitionDigest(
                "state update proof bytes must match receiver_update_proof carried in inter-channel tx"
                    .to_string(),
            ));
        }

        let public_inputs = ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::InterChannelImport,
            channel_id: self.prev_state.channel_id,
            prev_state_digest: self.prev_state.digest,
            next_state_digest: self.next_state.digest,
            amount: self.amount,
            sender_balance_before: 0,
            sender_balance_after: 0,
            receiver_balance_before: 0,
            receiver_balance_after: 0,
            receiver_entry_count: self.inter_channel_tx.receiver_deltas.len() as u64,
            receiver_dummy_count: count_dummy_delta_openings(
                &self
                    .receiver_applications
                    .iter()
                    .map(|application| application.delta_opening.clone())
                    .collect::<Vec<_>>(),
            ),
            sender: self.inter_channel_tx.sender_channel_id,
            receiver: self.inter_channel_tx.receiver_channel_id,
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            channel_nullifier_before: self.prev_state.channel_nullifier_root,
            channel_nullifier_after: self.next_state.channel_nullifier_root,
            personal_nullifier_before: self.prev_state.personal_nullifier_root,
            personal_nullifier_after: self.next_state.personal_nullifier_root,
            incoming_before: self.prev_state.incoming_root,
            incoming_after: self.next_state.incoming_root,
            transition_digest: self.inter_channel_tx.signing_digest(),
        };

        verify_proof(
            proof_verifier,
            &self.state_update_proof,
            TransitionProofRole::ChannelStateUpdate,
            ProofBackend::Plonky3,
            &public_inputs,
        )?;
        verify_proof(
            proof_verifier,
            &self.transport_proof,
            TransitionProofRole::IntmaxTransport,
            ProofBackend::Plonky2,
            &public_inputs,
        )?;
        Ok(public_inputs)
    }
}

fn verify_state_linkage(
    prev_state: &ChannelState,
    next_state: &ChannelState,
) -> Result<(), ChannelStateUpdateError> {
    if prev_state.channel_id != next_state.channel_id {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "channel id mismatch".to_string(),
        ));
    }
    if next_state.epoch != prev_state.epoch + 1 {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "next epoch must equal prev epoch + 1".to_string(),
        ));
    }
    if next_state.prev_digest != prev_state.digest {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "next prev_digest must equal prev digest".to_string(),
        ));
    }
    if next_state.digest != next_state.signing_digest() {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "next digest must match signing digest".to_string(),
        ));
    }
    Ok(())
}

fn ensure_same_channel_fund(
    prev_state: &ChannelState,
    next_state: &ChannelState,
) -> Result<(), ChannelStateUpdateError> {
    if prev_state.channel_fund != next_state.channel_fund {
        return Err(ChannelStateUpdateError::InvalidRootTransition(
            "channel fund must remain unchanged".to_string(),
        ));
    }
    Ok(())
}

fn ensure_same_root(
    name: &str,
    before: Bytes32,
    after: Bytes32,
) -> Result<(), ChannelStateUpdateError> {
    if before != after {
        return Err(ChannelStateUpdateError::InvalidRootTransition(format!(
            "{name} must remain unchanged",
        )));
    }
    Ok(())
}

fn ensure_different_root(
    name: &str,
    before: Bytes32,
    after: Bytes32,
) -> Result<(), ChannelStateUpdateError> {
    if before == after {
        return Err(ChannelStateUpdateError::InvalidRootTransition(format!(
            "{name} must change",
        )));
    }
    Ok(())
}

fn verify_proof<VP: ChannelProofVerifier>(
    verifier: &VP,
    proof: &ChannelProofEnvelope,
    expected_role: TransitionProofRole,
    expected_backend: ProofBackend,
    public_inputs: &ChannelStateUpdatePublicInputs,
) -> Result<(), ChannelStateUpdateError> {
    if proof.role != expected_role {
        return Err(ChannelStateUpdateError::InvalidProofRole {
            expected: expected_role,
            actual: proof.role,
        });
    }
    if proof.backend != expected_backend {
        return Err(ChannelStateUpdateError::InvalidProofBackend {
            expected: expected_backend,
            actual: proof.backend,
        });
    }
    verifier.verify(proof, public_inputs)
}

fn verify_sender_supplied_receiver_bundle<VL: LatticeBindingVerifier>(
    lattice_verifier: &VL,
    deltas: &[ReceiverBalanceDelta],
    openings: &[LatticeOpening],
    expected_total: u64,
) -> Result<(), ChannelStateUpdateError> {
    if deltas.len() < MIN_RECEIVER_DELTA_COUNT {
        return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
            format!(
                "expected at least {MIN_RECEIVER_DELTA_COUNT} receiver deltas, got {}",
                deltas.len()
            ),
        ));
    }
    if deltas.len() != openings.len() {
        return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
            "receiver delta commitments and openings length mismatch".to_string(),
        ));
    }

    let mut dummy_count = 0usize;
    let mut total = 0u64;
    for (delta, opening) in deltas.iter().zip(openings) {
        lattice_verifier.verify(&delta.amount, opening)?;
        total = total.checked_add(opening.amount).ok_or_else(|| {
            ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                "receiver delta amount overflow".to_string(),
            )
        })?;
        if opening.amount <= MAX_DUMMY_DELTA_AMOUNT {
            dummy_count += 1;
        }
    }
    if dummy_count < MIN_DUMMY_DELTA_COUNT {
        return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
            format!(
                "expected at least {MIN_DUMMY_DELTA_COUNT} dummy deltas with amount <= {MAX_DUMMY_DELTA_AMOUNT}, got {dummy_count}",
            ),
        ));
    }
    if total != expected_total {
        return Err(ChannelStateUpdateError::InvalidAmountRelation(
            "sender debit must equal the sum of all receiver delta amounts".to_string(),
        ));
    }
    Ok(())
}

fn verify_receiver_delta_applications<VL: LatticeBindingVerifier>(
    lattice_verifier: &VL,
    deltas: &[ReceiverBalanceDelta],
    applications: &[ReceiverDeltaApplicationWitness],
    expected_total: u64,
) -> Result<(), ChannelStateUpdateError> {
    verify_sender_supplied_receiver_bundle(
        lattice_verifier,
        deltas,
        &applications
            .iter()
            .map(|application| application.delta_opening.clone())
            .collect::<Vec<_>>(),
        expected_total,
    )?;
    if deltas.len() != applications.len() {
        return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
            "receiver delta bundle and receiver applications length mismatch".to_string(),
        ));
    }

    let mut seen_receivers = std::collections::BTreeSet::new();
    for (delta, application) in deltas.iter().zip(applications) {
        if delta.receiver_id != application.receiver_id {
            return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                "receiver application receiver_id must match tx receiver delta".to_string(),
            ));
        }
        if delta.amount != application.delta_commitment {
            return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                "receiver application delta commitment must match tx receiver delta commitment"
                    .to_string(),
            ));
        }
        if !seen_receivers.insert(application.receiver_id.as_u64()) {
            return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                "receiver delta bundle must not contain duplicate receiver ids".to_string(),
            ));
        }
        lattice_verifier.verify(
            &application.receiver_before_commitment,
            &application.receiver_before_opening,
        )?;
        lattice_verifier.verify(
            &application.receiver_after_commitment,
            &application.receiver_after_opening,
        )?;
        if application.receiver_after_opening.amount
            != application.receiver_before_opening.amount + application.delta_opening.amount
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "receiver after balance must equal receiver before balance plus delta amount"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn count_dummy_delta_openings(openings: &[LatticeOpening]) -> u64 {
    openings
        .iter()
        .filter(|opening| opening.amount <= MAX_DUMMY_DELTA_AMOUNT)
        .count() as u64
}

fn split_u64(value: u64) -> Vec<u32> {
    vec![(value >> 32) as u32, value as u32]
}

fn u64_to_u256(value: u64) -> U256 {
    U256::from_u64_slice(&[0, 0, 0, 0, 0, 0, (value >> 32) as u64, value as u32 as u64])
        .expect("u64 must fit into U256")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::channel::plonky3_state::{
            RealPlonky3ChannelProofVerifier, ReceiverBundleRowWitness, ReceiverBundleWitness,
            SingleTransitionWitness, receiver_bundle_envelope, single_transition_envelope,
        },
        common::channel::{ChannelFund, MemberSignature},
    };

    struct MockProofVerifier;

    impl ChannelProofVerifier for MockProofVerifier {
        fn verify(
            &self,
            _proof: &ChannelProofEnvelope,
            _public_inputs: &ChannelStateUpdatePublicInputs,
        ) -> Result<(), ChannelStateUpdateError> {
            Ok(())
        }
    }

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

    fn sample_state() -> ChannelState {
        ChannelState {
            channel_id: AccountId::new(5, 9).unwrap(),
            epoch: 1,
            channel_fund: ChannelFund {
                channel_id: AccountId::new(5, 9).unwrap(),
                amount: U256::from(100u32),
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
                signature: vec![],
            }],
        }
        .with_computed_digest()
    }

    fn state_update_proof() -> ChannelProofEnvelope {
        ChannelProofEnvelope {
            role: TransitionProofRole::ChannelStateUpdate,
            backend: ProofBackend::Plonky3,
            proof: vec![1],
        }
    }

    fn transport_proof() -> ChannelProofEnvelope {
        ChannelProofEnvelope {
            role: TransitionProofRole::IntmaxTransport,
            backend: ProofBackend::Plonky2,
            proof: vec![2],
        }
    }

    fn commitment(seed: u8) -> LatticeCommitment {
        LatticeCommitment {
            commitment: vec![seed; 48],
        }
    }

    #[test]
    fn inter_channel_send_requires_plonky3_state_and_plonky2_transport() {
        let prev = sample_state();
        let mut next = prev.clone();
        next.epoch += 1;
        next.channel_fund.amount = U256::from(93u32);
        next.user_fund_root = Bytes32::from_u32_slice(&[0, 0, 1, 0, 0, 0, 0, 0]).unwrap();
        next.channel_nullifier_root = Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        next.prev_digest = prev.digest;
        next = next.with_computed_digest();

        let witness = InterChannelSendUpdateWitness {
            prev_state: prev.clone(),
            next_state: next,
            inter_channel_tx: InterChannelTx {
                mkproof: crate::common::channel::MerkleInclusionProof {
                    siblings: vec![],
                    leaf_index: U256::default(),
                },
                sender_amount: commitment(1),
                sender_channel_id: prev.channel_id,
                receiver_channel_id: AccountId::new(7, 1).unwrap(),
                seal: Bytes32::default(),
                tx_hash: Bytes32::default(),
                intmax_transfer_commitment: Bytes32::default(),
                recipient_memo: vec![],
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
            },
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
            state_update_proof: state_update_proof(),
            transport_proof: transport_proof(),
        };

        witness
            .verify(&MockProofVerifier, &MockLatticeVerifier)
            .unwrap();
    }

    #[test]
    fn inter_channel_import_applies_sender_supplied_receiver_bundle() {
        let prev = sample_state();
        let mut next = prev.clone();
        next.epoch += 1;
        next.channel_fund.amount = U256::from(107u32);
        next.user_fund_root = Bytes32::from_u32_slice(&[0, 0, 2, 0, 0, 0, 0, 0]).unwrap();
        next.channel_nullifier_root = Bytes32::from_u32_slice(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        next.prev_digest = prev.digest;
        next = next.with_computed_digest();

        let witness = InterChannelImportUpdateWitness {
            prev_state: prev.clone(),
            next_state: next,
            inter_channel_tx: InterChannelTx {
                mkproof: crate::common::channel::MerkleInclusionProof {
                    siblings: vec![],
                    leaf_index: U256::default(),
                },
                sender_amount: commitment(31),
                sender_channel_id: AccountId::new(6, 1).unwrap(),
                receiver_channel_id: prev.channel_id,
                seal: Bytes32::default(),
                tx_hash: Bytes32::default(),
                intmax_transfer_commitment: Bytes32::default(),
                recipient_memo: vec![],
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
                receiver_update_proof: vec![1],
                sender_debit_proof: vec![2],
                sender_channel_signatures: vec![],
            },
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
            state_update_proof: state_update_proof(),
            transport_proof: transport_proof(),
        };

        witness
            .verify(&MockProofVerifier, &MockLatticeVerifier)
            .unwrap();
    }

    #[test]
    fn in_channel_transfer_rejects_mismatched_pay_digest() {
        let prev = sample_state();
        let mut next = prev.clone();
        next.epoch += 1;
        next.user_fund_root = Bytes32::from_u32_slice(&[0, 0, 0, 0, 1, 0, 0, 0]).unwrap();
        next.prev_digest = prev.digest;
        next = next.with_computed_digest();

        let witness = InChannelTransferUpdateWitness {
            prev_state: prev.clone(),
            next_state: next,
            pay: Pay {
                amount: commitment(7),
                digest: Bytes32::default(),
                sender_signature: vec![],
                sender: AccountId::new(5, 10).unwrap(),
                receiver: AccountId::new(5, 12).unwrap(),
            },
            pay_amount_opening: LatticeOpening {
                amount: 4,
                randomness: vec![],
            },
            sender_before_commitment: commitment(8),
            sender_before_opening: LatticeOpening {
                amount: 10,
                randomness: vec![],
            },
            sender_after_commitment: commitment(9),
            sender_after_opening: LatticeOpening {
                amount: 6,
                randomness: vec![],
            },
            receiver_before_commitment: commitment(10),
            receiver_before_opening: LatticeOpening {
                amount: 3,
                randomness: vec![],
            },
            receiver_after_commitment: commitment(11),
            receiver_after_opening: LatticeOpening {
                amount: 7,
                randomness: vec![],
            },
            state_update_proof: state_update_proof(),
        };

        let err = witness
            .verify(&MockProofVerifier, &MockLatticeVerifier)
            .unwrap_err();
        assert!(matches!(
            err,
            ChannelStateUpdateError::InvalidTransitionDigest(_)
        ));
    }

    #[test]
    fn inter_channel_send_verifies_real_plonky3_proof() {
        let prev = sample_state();
        let mut next = prev.clone();
        next.epoch += 1;
        next.channel_fund.amount = U256::from(93u32);
        next.user_fund_root = Bytes32::from_u32_slice(&[0, 0, 1, 0, 0, 0, 0, 0]).unwrap();
        next.channel_nullifier_root = Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        next.prev_digest = prev.digest;
        next = next.with_computed_digest();

        let state_update_proof = single_transition_envelope(SingleTransitionWitness {
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

        let witness = InterChannelSendUpdateWitness {
            prev_state: prev.clone(),
            next_state: next,
            inter_channel_tx: InterChannelTx {
                mkproof: crate::common::channel::MerkleInclusionProof {
                    siblings: vec![],
                    leaf_index: U256::default(),
                },
                sender_amount: commitment(1),
                sender_channel_id: prev.channel_id,
                receiver_channel_id: AccountId::new(7, 1).unwrap(),
                seal: Bytes32::default(),
                tx_hash: Bytes32::default(),
                intmax_transfer_commitment: Bytes32::default(),
                recipient_memo: vec![],
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
            },
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
            state_update_proof,
            transport_proof: transport_proof(),
        };

        witness
            .verify(&MixedProofVerifier, &MockLatticeVerifier)
            .unwrap();
    }

    #[test]
    fn inter_channel_import_verifies_real_plonky3_bundle_proof() {
        let prev = sample_state();
        let mut next = prev.clone();
        next.epoch += 1;
        next.channel_fund.amount = U256::from(107u32);
        next.user_fund_root = Bytes32::from_u32_slice(&[0, 0, 2, 0, 0, 0, 0, 0]).unwrap();
        next.channel_nullifier_root = Bytes32::from_u32_slice(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        next.prev_digest = prev.digest;
        next = next.with_computed_digest();

        let state_update_proof = receiver_bundle_envelope(ReceiverBundleWitness {
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

        let witness = InterChannelImportUpdateWitness {
            prev_state: prev.clone(),
            next_state: next,
            inter_channel_tx: InterChannelTx {
                mkproof: crate::common::channel::MerkleInclusionProof {
                    siblings: vec![],
                    leaf_index: U256::default(),
                },
                sender_amount: commitment(31),
                sender_channel_id: AccountId::new(6, 1).unwrap(),
                receiver_channel_id: prev.channel_id,
                seal: Bytes32::default(),
                tx_hash: Bytes32::default(),
                intmax_transfer_commitment: Bytes32::default(),
                recipient_memo: vec![],
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
                receiver_update_proof: state_update_proof.proof.clone(),
                sender_debit_proof: vec![2],
                sender_channel_signatures: vec![],
            },
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
            state_update_proof,
            transport_proof: transport_proof(),
        };

        witness
            .verify(&MixedProofVerifier, &MockLatticeVerifier)
            .unwrap();
    }
}
