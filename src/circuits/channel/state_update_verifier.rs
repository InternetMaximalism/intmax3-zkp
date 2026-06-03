use plonky2_keccak::utils::solidity_keccak256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::channel::{
        validate_all_member_signatures, ChannelBalance, ChannelError, ChannelId, ChannelRecord,
        ChannelState, ChannelTransitionKind, InterChannelTx, LatticeCommitment, LatticeOpening,
        Pay, ProofBackend, ReceiverBalanceDelta, TransitionProofRole, UserId,
        MAX_DUMMY_DELTA_AMOUNT,
    },
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256},
};

const MIN_RECEIVER_DELTA_COUNT: usize = 3;
const MIN_DUMMY_DELTA_COUNT: usize = 2;

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
    pub sender_user_id_hash: Bytes32,
    pub receiver_user_id_hash: Bytes32,
    pub channel_fund_before: U256,
    pub channel_fund_after: U256,
    pub unallocated_before: U256,
    pub unallocated_after: U256,
    pub shared_nullifier_before: Bytes32,
    pub shared_nullifier_after: Bytes32,
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
            self.sender_user_id_hash.to_u32_vec(),
            self.receiver_user_id_hash.to_u32_vec(),
            self.channel_fund_before.to_u32_vec(),
            self.channel_fund_after.to_u32_vec(),
            self.unallocated_before.to_u32_vec(),
            self.unallocated_after.to_u32_vec(),
            self.shared_nullifier_before.to_u32_vec(),
            self.shared_nullifier_after.to_u32_vec(),
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
        purpose: LatticeProofPurpose,
    ) -> Result<(), ChannelStateUpdateError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatticeProofPurpose {
    TransferAmount,
    BalanceOpening,
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

    #[error("invalid small block: {0}")]
    InvalidSmallBlock(String),

    #[error("invalid member signatures: {0}")]
    InvalidMemberSignatures(String),

    #[error("proof verification failed: {0}")]
    ProofVerification(String),

    #[error("public input mismatch: {0}")]
    PublicInputMismatch(String),
}

#[derive(Clone, Debug)]
pub struct ReceiverDeltaApplicationWitness {
    pub receiver_user_id: UserId,
    pub delta_commitment: LatticeCommitment,
    pub delta_opening: LatticeOpening,
    pub receiver_before_commitment: LatticeCommitment,
    pub receiver_before_opening: LatticeOpening,
    pub receiver_after_commitment: LatticeCommitment,
    pub receiver_after_opening: LatticeOpening,
}

#[derive(Clone, Debug)]
pub struct InChannelTransferUpdateWitness {
    pub channel_record: ChannelRecord,
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub pay: Pay,
    pub pay_amount_opening: LatticeOpening,
    pub sender_before_balance: ChannelBalance,
    pub sender_before_opening: LatticeOpening,
    pub sender_after_balance: ChannelBalance,
    pub sender_after_opening: LatticeOpening,
    pub receiver_before_balance: ChannelBalance,
    pub receiver_before_opening: LatticeOpening,
    pub receiver_after_balance: ChannelBalance,
    pub receiver_after_opening: LatticeOpening,
    pub state_update_proof: ChannelProofEnvelope,
}

#[derive(Clone, Debug)]
pub struct InterChannelSendUpdateWitness {
    pub channel_record: ChannelRecord,
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub inter_channel_tx: InterChannelTx,
    pub amount: u64,
    pub sender_amount_opening: LatticeOpening,
    pub sender_before_balance: ChannelBalance,
    pub sender_before_opening: LatticeOpening,
    pub sender_after_balance: ChannelBalance,
    pub sender_after_opening: LatticeOpening,
    pub receiver_delta_openings: Vec<LatticeOpening>,
    pub state_update_proof: ChannelProofEnvelope,
    pub transport_proof: ChannelProofEnvelope,
}

#[derive(Clone, Debug)]
pub struct InterChannelFundImportUpdateWitness {
    pub source_channel_record: ChannelRecord,
    pub receiver_channel_record: ChannelRecord,
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub inter_channel_tx: InterChannelTx,
    pub amount: u64,
    pub transport_proof: ChannelProofEnvelope,
}

#[derive(Clone, Debug)]
pub struct ReceiverBundleApplyUpdateWitness {
    pub receiver_channel_record: ChannelRecord,
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub inter_channel_tx: InterChannelTx,
    pub amount: u64,
    pub receiver_applications: Vec<ReceiverDeltaApplicationWitness>,
    pub state_update_proof: ChannelProofEnvelope,
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
        verify_next_state_signatures(&self.channel_record, &self.next_state)?;
        ensure_same_channel_fund(&self.prev_state, &self.next_state)?;
        ensure_same_u256(
            "unallocated_confirmed_incoming",
            self.prev_state.unallocated_confirmed_incoming,
            self.next_state.unallocated_confirmed_incoming,
        )?;
        ensure_different_root(
            "channel_balance_root",
            self.prev_state.channel_balance_root,
            self.next_state.channel_balance_root,
        )?;
        ensure_same_root(
            "shared_native_nullifier_root",
            self.prev_state.shared_native_nullifier_root,
            self.next_state.shared_native_nullifier_root,
        )?;
        verify_channel_balance_opening(
            lattice_verifier,
            &self.sender_before_balance,
            &self.sender_before_opening,
        )?;
        verify_channel_balance_opening(
            lattice_verifier,
            &self.sender_after_balance,
            &self.sender_after_opening,
        )?;
        verify_channel_balance_opening(
            lattice_verifier,
            &self.receiver_before_balance,
            &self.receiver_before_opening,
        )?;
        verify_channel_balance_opening(
            lattice_verifier,
            &self.receiver_after_balance,
            &self.receiver_after_opening,
        )?;
        lattice_verifier.verify(
            &self.pay.amount,
            &self.pay_amount_opening,
            LatticeProofPurpose::TransferAmount,
        )?;
        if self.pay.sender_user_id == self.pay.receiver_user_id {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "sender and receiver must be distinct users".to_string(),
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
            self.pay.sender_user_id,
            self.pay.receiver_user_id,
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
            sender_user_id_hash: hash_user_id(self.pay.sender_user_id),
            receiver_user_id_hash: hash_user_id(self.pay.receiver_user_id),
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            unallocated_before: self.prev_state.unallocated_confirmed_incoming,
            unallocated_after: self.next_state.unallocated_confirmed_incoming,
            shared_nullifier_before: self.prev_state.shared_native_nullifier_root,
            shared_nullifier_after: self.next_state.shared_native_nullifier_root,
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
        verify_next_state_signatures(&self.channel_record, &self.next_state)?;
        validate_signed_small_block(
            &self.channel_record,
            self.prev_state.channel_id,
            self.prev_state.close_freeze_nonce,
            &self.inter_channel_tx,
        )?;
        if self.prev_state.channel_id != self.inter_channel_tx.source_channel_id {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "source channel id mismatch".to_string(),
            ));
        }
        lattice_verifier.verify(
            &self.inter_channel_tx.sender_amount,
            &self.sender_amount_opening,
            LatticeProofPurpose::TransferAmount,
        )?;
        verify_channel_balance_opening(
            lattice_verifier,
            &self.sender_before_balance,
            &self.sender_before_opening,
        )?;
        verify_channel_balance_opening(
            lattice_verifier,
            &self.sender_after_balance,
            &self.sender_after_opening,
        )?;
        if self.sender_amount_opening.amount != self.amount {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "sender amount opening mismatch".to_string(),
            ));
        }
        if self.sender_before_opening.amount != self.sender_after_opening.amount + self.amount {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "sender balance decrement mismatch".to_string(),
            ));
        }
        if self.next_state.channel_fund.amount + u64_to_u256(self.amount)
            != self.prev_state.channel_fund.amount
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "channel fund must decrease by transfer amount".to_string(),
            ));
        }
        ensure_same_u256(
            "unallocated_confirmed_incoming",
            self.prev_state.unallocated_confirmed_incoming,
            self.next_state.unallocated_confirmed_incoming,
        )?;
        ensure_different_root(
            "channel_balance_root",
            self.prev_state.channel_balance_root,
            self.next_state.channel_balance_root,
        )?;
        ensure_different_root(
            "shared_native_nullifier_root",
            self.prev_state.shared_native_nullifier_root,
            self.next_state.shared_native_nullifier_root,
        )?;
        verify_sender_supplied_receiver_bundle(
            lattice_verifier,
            &self.inter_channel_tx.receiver_deltas,
            &self.receiver_delta_openings,
            self.amount,
        )?;
        if self.inter_channel_tx.sender_balance_update_proof != self.state_update_proof.proof {
            return Err(ChannelStateUpdateError::InvalidTransitionDigest(
                "state proof bytes must match sender_balance_update_proof".to_string(),
            ));
        }
        if self.inter_channel_tx.transport_proof != self.transport_proof.proof {
            return Err(ChannelStateUpdateError::InvalidTransitionDigest(
                "transport proof bytes must match transport_proof".to_string(),
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
            sender_user_id_hash: hash_user_id(self.inter_channel_tx.source_user_id),
            receiver_user_id_hash: hash_user_id(UserId::from_parts(
                self.inter_channel_tx.destination_channel_id,
                self.inter_channel_tx.receiver_deltas[0].receiver_key_id,
            )),
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            unallocated_before: self.prev_state.unallocated_confirmed_incoming,
            unallocated_after: self.next_state.unallocated_confirmed_incoming,
            shared_nullifier_before: self.prev_state.shared_native_nullifier_root,
            shared_nullifier_after: self.next_state.shared_native_nullifier_root,
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

impl InterChannelFundImportUpdateWitness {
    pub fn verify<VP>(
        &self,
        proof_verifier: &VP,
    ) -> Result<ChannelStateUpdatePublicInputs, ChannelStateUpdateError>
    where
        VP: ChannelProofVerifier,
    {
        verify_state_linkage(&self.prev_state, &self.next_state)?;
        verify_next_state_signatures(&self.receiver_channel_record, &self.next_state)?;
        validate_signed_small_block(
            &self.source_channel_record,
            self.inter_channel_tx.source_channel_id,
            self.inter_channel_tx.signed_small_block.message.close_freeze_nonce,
            &self.inter_channel_tx,
        )?;
        if self.prev_state.channel_id != self.inter_channel_tx.destination_channel_id {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "destination channel id mismatch".to_string(),
            ));
        }
        if self.next_state.channel_fund.amount
            != self.prev_state.channel_fund.amount + u64_to_u256(self.amount)
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "channel fund must increase by imported amount".to_string(),
            ));
        }
        if self.next_state.unallocated_confirmed_incoming
            != self.prev_state.unallocated_confirmed_incoming + u64_to_u256(self.amount)
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "unallocated_confirmed_incoming must increase by imported amount".to_string(),
            ));
        }
        ensure_same_root(
            "channel_balance_root",
            self.prev_state.channel_balance_root,
            self.next_state.channel_balance_root,
        )?;
        ensure_different_root(
            "shared_native_nullifier_root",
            self.prev_state.shared_native_nullifier_root,
            self.next_state.shared_native_nullifier_root,
        )?;
        if self.inter_channel_tx.transport_proof != self.transport_proof.proof {
            return Err(ChannelStateUpdateError::InvalidTransitionDigest(
                "transport proof bytes must match transport_proof".to_string(),
            ));
        }
        let public_inputs = ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::InterChannelFundImport,
            channel_id: self.prev_state.channel_id,
            prev_state_digest: self.prev_state.digest,
            next_state_digest: self.next_state.digest,
            amount: self.amount,
            sender_balance_before: 0,
            sender_balance_after: 0,
            receiver_balance_before: 0,
            receiver_balance_after: 0,
            receiver_entry_count: self.inter_channel_tx.receiver_deltas.len() as u64,
            receiver_dummy_count: 0,
            sender_user_id_hash: hash_user_id(self.inter_channel_tx.source_user_id),
            receiver_user_id_hash: hash_user_id(UserId::from_parts(
                self.inter_channel_tx.destination_channel_id,
                self.inter_channel_tx.receiver_deltas[0].receiver_key_id,
            )),
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            unallocated_before: self.prev_state.unallocated_confirmed_incoming,
            unallocated_after: self.next_state.unallocated_confirmed_incoming,
            shared_nullifier_before: self.prev_state.shared_native_nullifier_root,
            shared_nullifier_after: self.next_state.shared_native_nullifier_root,
            transition_digest: self.inter_channel_tx.signing_digest(),
        };
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

impl ReceiverBundleApplyUpdateWitness {
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
        verify_next_state_signatures(&self.receiver_channel_record, &self.next_state)?;
        if self.prev_state.channel_id != self.inter_channel_tx.destination_channel_id {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "destination channel id mismatch".to_string(),
            ));
        }
        ensure_same_channel_fund(&self.prev_state, &self.next_state)?;
        if self.prev_state.unallocated_confirmed_incoming
            != self.next_state.unallocated_confirmed_incoming + u64_to_u256(self.amount)
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "unallocated_confirmed_incoming must decrease by bundle amount".to_string(),
            ));
        }
        ensure_different_root(
            "channel_balance_root",
            self.prev_state.channel_balance_root,
            self.next_state.channel_balance_root,
        )?;
        ensure_same_root(
            "shared_native_nullifier_root",
            self.prev_state.shared_native_nullifier_root,
            self.next_state.shared_native_nullifier_root,
        )?;
        verify_receiver_delta_applications(
            lattice_verifier,
            &self.inter_channel_tx.receiver_deltas,
            &self.receiver_applications,
            self.amount,
        )?;
        if self.inter_channel_tx.receiver_update_proof != self.state_update_proof.proof {
            return Err(ChannelStateUpdateError::InvalidTransitionDigest(
                "state proof bytes must match receiver_update_proof".to_string(),
            ));
        }
        let first_receiver = self
            .receiver_applications
            .first()
            .map(|application| application.receiver_user_id)
            .unwrap_or_else(|| UserId::from_parts(self.prev_state.channel_id, self.receiver_channel_record.bp_key_id));
        let public_inputs = ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::ReceiverBundleApply,
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
            sender_user_id_hash: hash_user_id(self.inter_channel_tx.source_user_id),
            receiver_user_id_hash: hash_user_id(first_receiver),
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            unallocated_before: self.prev_state.unallocated_confirmed_incoming,
            unallocated_after: self.next_state.unallocated_confirmed_incoming,
            shared_nullifier_before: self.prev_state.shared_native_nullifier_root,
            shared_nullifier_after: self.next_state.shared_native_nullifier_root,
            transition_digest: self.inter_channel_tx.signing_digest(),
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

fn verify_next_state_signatures(
    record: &ChannelRecord,
    next_state: &ChannelState,
) -> Result<(), ChannelStateUpdateError> {
    validate_all_member_signatures(record, next_state.channel_id, &next_state.member_signatures)
        .map_err(|err| ChannelStateUpdateError::InvalidMemberSignatures(err.to_string()))
}

fn validate_signed_small_block(
    source_channel_record: &ChannelRecord,
    expected_source_channel_id: ChannelId,
    expected_close_freeze_nonce: u64,
    inter_channel_tx: &InterChannelTx,
) -> Result<(), ChannelStateUpdateError> {
    let signed = &inter_channel_tx.signed_small_block;
    if inter_channel_tx.source_channel_id != expected_source_channel_id {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "source channel mismatch".to_string(),
        ));
    }
    if signed.message.channel_id != expected_source_channel_id {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "small block message channel mismatch".to_string(),
        ));
    }
    if signed.message.bp_key_id != source_channel_record.bp_key_id {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "small block BP mismatch".to_string(),
        ));
    }
    if signed.message.close_freeze_nonce != expected_close_freeze_nonce {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "small block close_freeze_nonce mismatch".to_string(),
        ));
    }
    if signed.medium_block_number < signed.message.medium_epoch_hint {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "medium_block_number must be >= medium_epoch_hint".to_string(),
        ));
    }
    if signed.aggregated_signature_proof.is_empty() {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "aggregated signature proof must not be empty".to_string(),
        ));
    }
    if signed.confirmation_proof.is_empty() {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "confirmation proof must not be empty".to_string(),
        ));
    }
    validate_all_member_signatures(
        source_channel_record,
        expected_source_channel_id,
        &signed.signatures,
    )
    .map_err(|err| ChannelStateUpdateError::InvalidSmallBlock(err.to_string()))
}

fn verify_channel_balance_opening<VL>(
    lattice_verifier: &VL,
    balance: &ChannelBalance,
    opening: &LatticeOpening,
) -> Result<(), ChannelStateUpdateError>
where
    VL: LatticeBindingVerifier,
{
    lattice_verifier.verify(
        &balance.balance_commitment,
        opening,
        LatticeProofPurpose::BalanceOpening,
    )
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

fn ensure_same_u256(
    name: &str,
    before: U256,
    after: U256,
) -> Result<(), ChannelStateUpdateError> {
    if before != after {
        return Err(ChannelStateUpdateError::InvalidRootTransition(format!(
            "{name} must remain unchanged",
        )));
    }
    Ok(())
}

fn verify_sender_supplied_receiver_bundle<VL>(
    lattice_verifier: &VL,
    deltas: &[ReceiverBalanceDelta],
    openings: &[LatticeOpening],
    total_amount: u64,
) -> Result<(), ChannelStateUpdateError>
where
    VL: LatticeBindingVerifier,
{
    if deltas.len() != openings.len() {
        return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
            "receiver delta opening length mismatch".to_string(),
        ));
    }
    if deltas.len() < MIN_RECEIVER_DELTA_COUNT {
        return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(format!(
            "receiver delta bundle must contain at least {MIN_RECEIVER_DELTA_COUNT} entries",
        )));
    }
    let mut dummy_count = 0usize;
    let mut sum = 0u64;
    for (delta, opening) in deltas.iter().zip(openings) {
        lattice_verifier.verify(&delta.amount, opening, LatticeProofPurpose::TransferAmount)?;
        sum = sum
            .checked_add(opening.amount)
            .ok_or_else(|| {
                ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                    "receiver delta total overflow".to_string(),
                )
            })?;
        if opening.amount <= MAX_DUMMY_DELTA_AMOUNT {
            dummy_count += 1;
        }
        if delta.receiver_user_id.key_id() != delta.receiver_key_id {
            return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                "receiver_user_id must embed receiver_key_id".to_string(),
            ));
        }
    }
    if dummy_count < MIN_DUMMY_DELTA_COUNT {
        return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(format!(
            "receiver delta bundle must contain at least {MIN_DUMMY_DELTA_COUNT} dummy entries",
        )));
    }
    if sum != total_amount {
        return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
            "receiver delta total must equal sender amount".to_string(),
        ));
    }
    Ok(())
}

fn verify_receiver_delta_applications<VL>(
    lattice_verifier: &VL,
    deltas: &[ReceiverBalanceDelta],
    applications: &[ReceiverDeltaApplicationWitness],
    total_amount: u64,
) -> Result<(), ChannelStateUpdateError>
where
    VL: LatticeBindingVerifier,
{
    if deltas.len() != applications.len() {
        return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
            "receiver application length mismatch".to_string(),
        ));
    }
    let mut sum = 0u64;
    for (delta, application) in deltas.iter().zip(applications) {
        if delta.receiver_user_id != application.receiver_user_id {
            return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                "receiver application user mismatch".to_string(),
            ));
        }
        if delta.amount != application.delta_commitment {
            return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                "receiver application delta commitment mismatch".to_string(),
            ));
        }
        lattice_verifier.verify(
            &application.delta_commitment,
            &application.delta_opening,
            LatticeProofPurpose::TransferAmount,
        )?;
        lattice_verifier.verify(
            &application.receiver_before_commitment,
            &application.receiver_before_opening,
            LatticeProofPurpose::BalanceOpening,
        )?;
        lattice_verifier.verify(
            &application.receiver_after_commitment,
            &application.receiver_after_opening,
            LatticeProofPurpose::BalanceOpening,
        )?;
        if application.receiver_after_opening.amount
            != application.receiver_before_opening.amount + application.delta_opening.amount
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "receiver balance increment mismatch".to_string(),
            ));
        }
        sum = sum
            .checked_add(application.delta_opening.amount)
            .ok_or_else(|| {
                ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                    "receiver application total overflow".to_string(),
                )
            })?;
    }
    if sum != total_amount {
        return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
            "receiver application total must equal bundle amount".to_string(),
        ));
    }
    Ok(())
}

fn count_dummy_delta_openings(openings: &[LatticeOpening]) -> u64 {
    openings
        .iter()
        .filter(|opening| opening.amount <= MAX_DUMMY_DELTA_AMOUNT)
        .count() as u64
}

fn verify_proof<VP>(
    verifier: &VP,
    proof: &ChannelProofEnvelope,
    expected_role: TransitionProofRole,
    expected_backend: ProofBackend,
    public_inputs: &ChannelStateUpdatePublicInputs,
) -> Result<(), ChannelStateUpdateError>
where
    VP: ChannelProofVerifier,
{
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

fn hash_user_id(user_id: UserId) -> Bytes32 {
    Bytes32::from_u32_slice(&solidity_keccak256(&user_id.to_u32_vec()))
        .expect("keccak output must be bytes32")
}

fn split_u64(value: u64) -> Vec<u32> {
    vec![(value >> 32) as u32, value as u32]
}

fn u64_to_u256(value: u64) -> U256 {
    U256::from_u32_slice(&[0, 0, 0, 0, 0, 0, (value >> 32) as u32, value as u32])
        .expect("u64 must fit in U256")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::channel::{
            ChannelFund, ChannelMember, KeyId, MemberSignature, MerkleInclusionProof,
            SignedSmallBlock, SmallBlockRootMessage, bridge_account_to_channel_id,
            bridge_account_to_key_id,
        },
        common::user_id::AccountId,
        ethereum_types::{address::Address, u256::U256},
    };

    fn sample_channel_id() -> ChannelId {
        ChannelId::new(5).unwrap()
    }

    fn key(value: u64) -> KeyId {
        KeyId::new(value).unwrap()
    }

    fn user(value: u64) -> UserId {
        UserId::from_parts(sample_channel_id(), key(value))
    }

    fn sample_record() -> ChannelRecord {
        ChannelRecord {
            channel_id: sample_channel_id(),
            bp_key_id: key(10),
            member_key_ids: vec![key(10), key(11), key(12)],
            member_key_ids_root: Bytes32::default(),
            special_close_penalty: U256::from(7u32),
            close_freeze_nonce: 0,
            status: crate::common::channel::ChannelStatus::Active,
        }
    }

    fn sample_state(amount: u32) -> ChannelState {
        ChannelState {
            channel_id: sample_channel_id(),
            epoch: 1,
            small_block_number: 0,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id: sample_channel_id(),
                amount: U256::from(amount),
                intmax_state_root: Bytes32::default(),
            },
            channel_balance_root: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![
                MemberSignature {
                    key_id: key(10),
                    user_id: user(10),
                    signature: vec![1],
                    key_condition_proof: vec![2],
                },
                MemberSignature {
                    key_id: key(11),
                    user_id: user(11),
                    signature: vec![3],
                    key_condition_proof: vec![4],
                },
                MemberSignature {
                    key_id: key(12),
                    user_id: user(12),
                    signature: vec![5],
                    key_condition_proof: vec![6],
                },
            ],
        }
        .with_computed_digest()
    }

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

    struct MockLatticeVerifier;

    impl LatticeBindingVerifier for MockLatticeVerifier {
        fn verify(
            &self,
            _commitment: &LatticeCommitment,
            _opening: &LatticeOpening,
            _purpose: LatticeProofPurpose,
        ) -> Result<(), ChannelStateUpdateError> {
            Ok(())
        }
    }

    fn signed_small_block() -> SignedSmallBlock {
        SignedSmallBlock {
            message: SmallBlockRootMessage {
                channel_id: sample_channel_id(),
                bp_key_id: key(10),
                small_block_number: 1,
                prev_small_block_root: Bytes32::default(),
                tx_tree_root: Bytes32::default(),
                state_commitment_root: Bytes32::default(),
                medium_epoch_hint: 3,
                close_freeze_nonce: 0,
            },
            signatures: sample_state(100).member_signatures,
            aggregated_signature_proof: vec![9],
            medium_block_number: 3,
            confirmation_proof: vec![8],
        }
    }

    #[test]
    fn in_channel_transfer_rejects_mismatched_pay_digest() {
        let prev = sample_state(100);
        let mut next = prev.clone();
        next.epoch += 1;
        next.channel_balance_root = Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        next.prev_digest = prev.digest;
        next = next.with_computed_digest();
        let witness = InChannelTransferUpdateWitness {
            channel_record: sample_record(),
            prev_state: prev,
            next_state: next,
            pay: Pay {
                amount: LatticeCommitment {
                    commitment: vec![1; 48],
                },
                digest: Bytes32::default(),
                sender_signature: vec![1],
                sender_user_id: user(10),
                receiver_user_id: user(11),
            },
            pay_amount_opening: LatticeOpening {
                amount: 7,
                randomness: vec![],
                proof: vec![],
            },
            sender_before_balance: ChannelBalance {
                channel_id: sample_channel_id(),
                user_id: user(10),
                balance_commitment: LatticeCommitment {
                    commitment: vec![2; 48],
                },
            },
            sender_before_opening: LatticeOpening {
                amount: 50,
                randomness: vec![],
                proof: vec![],
            },
            sender_after_balance: ChannelBalance {
                channel_id: sample_channel_id(),
                user_id: user(10),
                balance_commitment: LatticeCommitment {
                    commitment: vec![3; 48],
                },
            },
            sender_after_opening: LatticeOpening {
                amount: 43,
                randomness: vec![],
                proof: vec![],
            },
            receiver_before_balance: ChannelBalance {
                channel_id: sample_channel_id(),
                user_id: user(11),
                balance_commitment: LatticeCommitment {
                    commitment: vec![4; 48],
                },
            },
            receiver_before_opening: LatticeOpening {
                amount: 10,
                randomness: vec![],
                proof: vec![],
            },
            receiver_after_balance: ChannelBalance {
                channel_id: sample_channel_id(),
                user_id: user(11),
                balance_commitment: LatticeCommitment {
                    commitment: vec![5; 48],
                },
            },
            receiver_after_opening: LatticeOpening {
                amount: 17,
                randomness: vec![],
                proof: vec![],
            },
            state_update_proof: ChannelProofEnvelope {
                role: TransitionProofRole::ChannelStateUpdate,
                backend: ProofBackend::Plonky3,
                proof: vec![1],
            },
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
    fn inter_channel_send_requires_plonky3_state_and_plonky2_transport() {
        let prev = sample_state(100);
        let mut next = prev.clone();
        next.epoch += 1;
        next.small_block_number = 1;
        next.channel_fund.amount = U256::from(93u32);
        next.channel_balance_root = Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        next.shared_native_nullifier_root =
            Bytes32::from_u32_slice(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        next.prev_digest = prev.digest;
        next = next.with_computed_digest();
        let tx = InterChannelTx {
            tx_inclusion_proof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::zero(),
            },
            signed_small_block: signed_small_block(),
            sender_amount: LatticeCommitment {
                commitment: vec![6; 48],
            },
            source_channel_id: sample_channel_id(),
            destination_channel_id: ChannelId::new(7).unwrap(),
            source_key_id: key(10),
            source_user_id: user(10),
            seal: Bytes32::default(),
            tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![1],
            receiver_deltas: vec![
                ReceiverBalanceDelta {
                    receiver_key_id: KeyId::new(21).unwrap(),
                    receiver_user_id: UserId::from_parts(ChannelId::new(7).unwrap(), KeyId::new(21).unwrap()),
                    amount: LatticeCommitment { commitment: vec![7; 48] },
                },
                ReceiverBalanceDelta {
                    receiver_key_id: KeyId::new(22).unwrap(),
                    receiver_user_id: UserId::from_parts(ChannelId::new(7).unwrap(), KeyId::new(22).unwrap()),
                    amount: LatticeCommitment { commitment: vec![8; 48] },
                },
                ReceiverBalanceDelta {
                    receiver_key_id: KeyId::new(23).unwrap(),
                    receiver_user_id: UserId::from_parts(ChannelId::new(7).unwrap(), KeyId::new(23).unwrap()),
                    amount: LatticeCommitment { commitment: vec![9; 48] },
                },
            ],
            receiver_update_proof: vec![3],
            sender_balance_update_proof: vec![4],
            transport_proof: vec![5],
        };
        let witness = InterChannelSendUpdateWitness {
            channel_record: sample_record(),
            prev_state: prev,
            next_state: next,
            inter_channel_tx: tx,
            amount: 7,
            sender_amount_opening: LatticeOpening {
                amount: 7,
                randomness: vec![],
                proof: vec![],
            },
            sender_before_balance: ChannelBalance {
                channel_id: sample_channel_id(),
                user_id: user(10),
                balance_commitment: LatticeCommitment { commitment: vec![1; 48] },
            },
            sender_before_opening: LatticeOpening {
                amount: 50,
                randomness: vec![],
                proof: vec![],
            },
            sender_after_balance: ChannelBalance {
                channel_id: sample_channel_id(),
                user_id: user(10),
                balance_commitment: LatticeCommitment { commitment: vec![2; 48] },
            },
            sender_after_opening: LatticeOpening {
                amount: 43,
                randomness: vec![],
                proof: vec![],
            },
            receiver_delta_openings: vec![
                LatticeOpening { amount: 5, randomness: vec![], proof: vec![] },
                LatticeOpening { amount: 1, randomness: vec![], proof: vec![] },
                LatticeOpening { amount: 1, randomness: vec![], proof: vec![] },
            ],
            state_update_proof: ChannelProofEnvelope {
                role: TransitionProofRole::ChannelStateUpdate,
                backend: ProofBackend::Plonky3,
                proof: vec![4],
            },
            transport_proof: ChannelProofEnvelope {
                role: TransitionProofRole::IntmaxTransport,
                backend: ProofBackend::Plonky2,
                proof: vec![5],
            },
        };
        witness
            .verify(&MockProofVerifier, &MockLatticeVerifier)
            .unwrap();
    }

    #[test]
    fn bridge_account_id_helpers_match_expected_parts() {
        let account = AccountId::new(9, 11).unwrap();
        assert_eq!(bridge_account_to_channel_id(account).unwrap().as_u64(), 9);
        assert_eq!(bridge_account_to_key_id(account).unwrap().as_u64(), 11);
    }
}
