use plonky2_keccak::utils::solidity_keccak256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::user_id::AccountId,
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
};

pub type ChannelId = AccountId;
pub type MemberId = AccountId;
pub type SignatureBytes = Vec<u8>;

const CHANNEL_STATE_DOMAIN: u32 = 0x494d4348; // "IMCH"
const PAY_DOMAIN: u32 = 0x494d5041; // "IMPA"
const INTER_CHANNEL_TX_DOMAIN: u32 = 0x494d4954; // "IMIT"
const CLOSE_TX_DOMAIN: u32 = 0x494d434c; // "IMCL"
const CLOSE_INTENT_DOMAIN: u32 = 0x494d4349; // "IMCI"
const CANCEL_CLOSE_DOMAIN: u32 = 0x494d434e; // "IMCN"
const POST_CLOSE_CLAIM_DOMAIN: u32 = 0x494d4350; // "IMCP"

#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("invalid lattice commitment length: {0}")]
    InvalidCommitmentLength(usize),

    #[error("invalid close binding: {0}")]
    InvalidCloseBinding(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBackend {
    Plonky2,
    Plonky3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionProofRole {
    ChannelStateUpdate,
    IntmaxTransport,
    ChannelCloseSettlement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelTransitionKind {
    InChannelTransfer,
    InterChannelSend,
    InterChannelImport,
    ChannelClose,
}

impl ChannelTransitionKind {
    pub const fn required_state_backend(self) -> Option<ProofBackend> {
        match self {
            Self::InChannelTransfer | Self::InterChannelSend | Self::InterChannelImport => {
                Some(ProofBackend::Plonky3)
            }
            Self::ChannelClose => None,
        }
    }

    pub const fn required_transport_backend(self) -> Option<ProofBackend> {
        match self {
            Self::InterChannelSend | Self::InterChannelImport | Self::ChannelClose => {
                Some(ProofBackend::Plonky2)
            }
            Self::InChannelTransfer => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatticeCommitment {
    pub commitment: Vec<u8>,
}

impl LatticeCommitment {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        bytes_to_u32_words(&self.commitment)
    }

    pub fn digest(&self) -> Bytes32 {
        hash_words(&[vec![self.commitment.len() as u32], self.to_u32_vec()].concat())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatticeOpening {
    pub amount: u64,
    pub randomness: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleInclusionProof {
    pub siblings: Vec<Bytes32>,
    pub leaf_index: U256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelFund {
    pub channel_id: ChannelId,
    pub amount: U256,
    pub intmax_state_root: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserFund {
    pub channel_id: ChannelId,
    pub member_id: MemberId,
    pub balance_commitment: LatticeCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelMember {
    pub member_id: MemberId,
    pub signing_pubkey: Vec<u8>,
    pub l1_withdrawal_recipient: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberSignature {
    pub signer: MemberId,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelState {
    pub channel_id: ChannelId,
    pub epoch: u64,
    pub channel_fund: ChannelFund,
    pub user_fund_root: Bytes32,
    pub channel_nullifier_root: Bytes32,
    pub personal_nullifier_root: Bytes32,
    pub incoming_root: Bytes32,
    pub prev_digest: Bytes32,
    pub digest: Bytes32,
    pub member_signatures: Vec<MemberSignature>,
}

impl ChannelState {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CHANNEL_STATE_DOMAIN],
                self.channel_id.to_u32_vec(),
                split_u64(self.epoch),
                self.channel_fund.channel_id.to_u32_vec(),
                self.channel_fund.amount.to_u32_vec(),
                self.channel_fund.intmax_state_root.to_u32_vec(),
                self.user_fund_root.to_u32_vec(),
                self.channel_nullifier_root.to_u32_vec(),
                self.personal_nullifier_root.to_u32_vec(),
                self.incoming_root.to_u32_vec(),
                self.prev_digest.to_u32_vec(),
            ]
            .concat(),
        )
    }

    pub fn with_computed_digest(mut self) -> Self {
        self.digest = self.signing_digest();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reject {
    pub proposal_digest: Bytes32,
    pub rejecting_member: MemberId,
    pub reason: RejectReason,
    pub detail: Vec<u8>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    InvalidZkp,
    InvalidSignature,
    InvalidPrevState,
    InvalidEpoch,
    InvalidStateTransition,
    InsufficientBalance,
    InvalidIntmaxProof,
    AlreadyUsedNullifier,
    InvalidReceiver,
    InvalidSender,
    InvalidDigest,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pay {
    pub amount: LatticeCommitment,
    pub digest: Bytes32,
    pub sender_signature: SignatureBytes,
    pub sender: MemberId,
    pub receiver: MemberId,
}

impl Pay {
    pub fn signing_digest(
        channel_id: ChannelId,
        prev_state_digest: Bytes32,
        amount: &LatticeCommitment,
        sender: MemberId,
        receiver: MemberId,
    ) -> Bytes32 {
        hash_words(
            &[
                vec![PAY_DOMAIN],
                channel_id.to_u32_vec(),
                prev_state_digest.to_u32_vec(),
                amount.digest().to_u32_vec(),
                sender.to_u32_vec(),
                receiver.to_u32_vec(),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiverBalanceDelta {
    pub receiver_id: MemberId,
    pub amount: LatticeCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterChannelTx {
    pub mkproof: MerkleInclusionProof,
    pub sender_amount: LatticeCommitment,
    pub sender_channel_id: ChannelId,
    pub receiver_channel_id: ChannelId,
    pub seal: Bytes32,
    pub tx_hash: Bytes32,
    pub intmax_transfer_commitment: Bytes32,
    pub recipient_memo: Vec<u8>,
    pub receiver_deltas: Vec<ReceiverBalanceDelta>,
    pub receiver_update_proof: Vec<u8>,
    pub sender_debit_proof: Vec<u8>,
    pub sender_channel_signatures: Vec<MemberSignature>,
}

impl InterChannelTx {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![INTER_CHANNEL_TX_DOMAIN],
                self.sender_amount.digest().to_u32_vec(),
                self.sender_channel_id.to_u32_vec(),
                self.receiver_channel_id.to_u32_vec(),
                self.seal.to_u32_vec(),
                self.tx_hash.to_u32_vec(),
                self.intmax_transfer_commitment.to_u32_vec(),
                vec![self.recipient_memo.len() as u32],
                bytes_to_u32_words(&self.recipient_memo),
                vec![self.receiver_deltas.len() as u32],
                self.receiver_deltas
                    .iter()
                    .flat_map(|delta| {
                        [
                            delta.receiver_id.to_u32_vec(),
                            delta.amount.digest().to_u32_vec(),
                        ]
                        .concat()
                    })
                    .collect(),
                vec![self.receiver_update_proof.len() as u32],
                bytes_to_u32_words(&self.receiver_update_proof),
                vec![self.sender_debit_proof.len() as u32],
                bytes_to_u32_words(&self.sender_debit_proof),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseTransfer {
    pub member_id: MemberId,
    pub l1_recipient: Address,
    pub user_amount: LatticeCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseWithdrawal {
    pub channel_id: ChannelId,
    pub final_channel_state_digest: Bytes32,
    pub intmax_state_root: Bytes32,
    pub transfers: Vec<CloseTransfer>,
    pub zkp: Vec<u8>,
}

impl CloseWithdrawal {
    pub fn signing_digest(&self) -> Bytes32 {
        let mut words = vec![CLOSE_TX_DOMAIN];
        words.extend(self.channel_id.to_u32_vec());
        words.extend(self.final_channel_state_digest.to_u32_vec());
        words.extend(self.intmax_state_root.to_u32_vec());
        words.push(self.transfers.len() as u32);
        for transfer in &self.transfers {
            words.extend(transfer.member_id.to_u32_vec());
            words.extend(transfer.l1_recipient.to_u32_vec());
            words.extend(transfer.user_amount.digest().to_u32_vec());
        }
        words.push(self.zkp.len() as u32);
        words.extend(bytes_to_u32_words(&self.zkp));
        hash_words(&words)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseIntent {
    pub channel_id: ChannelId,
    pub close_nonce: u64,
    pub final_channel_state_digest: Bytes32,
    pub channel_fund_snapshot: ChannelFund,
    pub settlement_digest: Bytes32,
    pub snapshot_block_number: u64,
}

impl CloseIntent {
    pub fn new(
        close_nonce: u64,
        final_channel_state: &ChannelState,
        close_withdrawal: &CloseWithdrawal,
        snapshot_block_number: u64,
    ) -> Result<Self, ChannelError> {
        if final_channel_state.channel_id != close_withdrawal.channel_id {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final channel state channel_id {:?} != close withdrawal channel_id {:?}",
                final_channel_state.channel_id, close_withdrawal.channel_id
            )));
        }
        if final_channel_state.digest != close_withdrawal.final_channel_state_digest {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final channel state digest {:?} != close withdrawal digest {:?}",
                final_channel_state.digest, close_withdrawal.final_channel_state_digest
            )));
        }
        if final_channel_state.channel_fund.intmax_state_root != close_withdrawal.intmax_state_root
        {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "channel fund snapshot intmax_state_root {:?} != close withdrawal intmax_state_root {:?}",
                final_channel_state.channel_fund.intmax_state_root,
                close_withdrawal.intmax_state_root
            )));
        }

        Ok(Self {
            channel_id: final_channel_state.channel_id,
            close_nonce,
            final_channel_state_digest: final_channel_state.digest,
            channel_fund_snapshot: final_channel_state.channel_fund.clone(),
            settlement_digest: close_withdrawal.signing_digest(),
            snapshot_block_number,
        })
    }

    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CLOSE_INTENT_DOMAIN],
                self.channel_id.to_u32_vec(),
                split_u64(self.close_nonce),
                self.final_channel_state_digest.to_u32_vec(),
                self.channel_fund_snapshot.channel_id.to_u32_vec(),
                self.channel_fund_snapshot.amount.to_u32_vec(),
                self.channel_fund_snapshot.intmax_state_root.to_u32_vec(),
                self.settlement_digest.to_u32_vec(),
                split_u64(self.snapshot_block_number),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelClose {
    pub close_intent_digest: Bytes32,
    pub revived_inter_channel_tx_digest: Bytes32,
    pub revived_tx_hash: Bytes32,
    pub revived_seal: Bytes32,
    pub cancel_proof: Vec<u8>,
}

impl CancelClose {
    pub fn new(
        close_intent: &CloseIntent,
        revived_tx: &InterChannelTx,
        cancel_proof: Vec<u8>,
    ) -> Self {
        Self {
            close_intent_digest: close_intent.signing_digest(),
            revived_inter_channel_tx_digest: revived_tx.signing_digest(),
            revived_tx_hash: revived_tx.tx_hash,
            revived_seal: revived_tx.seal,
            cancel_proof,
        }
    }

    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CANCEL_CLOSE_DOMAIN],
                self.close_intent_digest.to_u32_vec(),
                self.revived_inter_channel_tx_digest.to_u32_vec(),
                self.revived_tx_hash.to_u32_vec(),
                self.revived_seal.to_u32_vec(),
                vec![self.cancel_proof.len() as u32],
                bytes_to_u32_words(&self.cancel_proof),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostCloseIncomingClaim {
    pub close_intent_digest: Bytes32,
    pub incoming_tx_hash: Bytes32,
    pub receiver_id: MemberId,
    pub receiver_amount: LatticeCommitment,
    pub personal_nullifier: Bytes32,
    pub recipient_memo: Vec<u8>,
    pub claim_proof: Vec<u8>,
}

impl PostCloseIncomingClaim {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![POST_CLOSE_CLAIM_DOMAIN],
                self.close_intent_digest.to_u32_vec(),
                self.incoming_tx_hash.to_u32_vec(),
                self.receiver_id.to_u32_vec(),
                self.receiver_amount.digest().to_u32_vec(),
                self.personal_nullifier.to_u32_vec(),
                vec![self.recipient_memo.len() as u32],
                bytes_to_u32_words(&self.recipient_memo),
                vec![self.claim_proof.len() as u32],
                bytes_to_u32_words(&self.claim_proof),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChannelTransition {
    InChannelTransfer(Pay),
    InterChannelSend(InterChannelTx),
    InterChannelImport(InterChannelTx),
    ChannelClose(CloseWithdrawal),
}

impl ChannelTransition {
    pub const fn kind(&self) -> ChannelTransitionKind {
        match self {
            Self::InChannelTransfer(_) => ChannelTransitionKind::InChannelTransfer,
            Self::InterChannelSend(_) => ChannelTransitionKind::InterChannelSend,
            Self::InterChannelImport(_) => ChannelTransitionKind::InterChannelImport,
            Self::ChannelClose(_) => ChannelTransitionKind::ChannelClose,
        }
    }

    pub const fn required_state_backend(&self) -> Option<ProofBackend> {
        self.kind().required_state_backend()
    }

    pub const fn required_transport_backend(&self) -> Option<ProofBackend> {
        self.kind().required_transport_backend()
    }
}

fn split_u64(value: u64) -> Vec<u32> {
    vec![(value >> 32) as u32, value as u32]
}

fn bytes_to_u32_words(bytes: &[u8]) -> Vec<u32> {
    let mut words = Vec::with_capacity(bytes.len().div_ceil(4));
    for chunk in bytes.chunks(4) {
        let mut padded = [0u8; 4];
        padded[..chunk.len()].copy_from_slice(chunk);
        words.push(u32::from_be_bytes(padded));
    }
    words
}

fn hash_words(words: &[u32]) -> Bytes32 {
    Bytes32::from_u32_slice(&solidity_keccak256(words)).expect("keccak output must be bytes32")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_types::u32limb_trait::U32LimbTrait;

    fn commitment(seed: u8) -> LatticeCommitment {
        LatticeCommitment {
            commitment: vec![seed; 48],
        }
    }

    fn sample_state() -> ChannelState {
        ChannelState {
            channel_id: AccountId::new(7, 11).unwrap(),
            epoch: 3,
            channel_fund: ChannelFund {
                channel_id: AccountId::new(7, 11).unwrap(),
                amount: U256::from(100u32),
                intmax_state_root: Bytes32::default(),
            },
            user_fund_root: Bytes32::default(),
            channel_nullifier_root: Bytes32::default(),
            personal_nullifier_root: Bytes32::default(),
            incoming_root: Bytes32::default(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![],
        }
    }

    #[test]
    fn transition_backend_matches_spec() {
        assert_eq!(
            ChannelTransitionKind::InChannelTransfer.required_state_backend(),
            Some(ProofBackend::Plonky3)
        );
        assert_eq!(
            ChannelTransitionKind::InterChannelSend.required_state_backend(),
            Some(ProofBackend::Plonky3)
        );
        assert_eq!(
            ChannelTransitionKind::InterChannelImport.required_state_backend(),
            Some(ProofBackend::Plonky3)
        );
        assert_eq!(
            ChannelTransitionKind::InterChannelSend.required_transport_backend(),
            Some(ProofBackend::Plonky2)
        );
        assert_eq!(
            ChannelTransitionKind::InterChannelImport.required_transport_backend(),
            Some(ProofBackend::Plonky2)
        );
        assert_eq!(
            ChannelTransitionKind::ChannelClose.required_transport_backend(),
            Some(ProofBackend::Plonky2)
        );
    }

    #[test]
    fn channel_state_digest_is_stable() {
        let a = sample_state().with_computed_digest();
        let b = sample_state().with_computed_digest();
        assert_eq!(a.digest, b.digest);
    }

    #[test]
    fn pay_digest_binds_channel_state_and_participants() {
        let digest = Pay::signing_digest(
            AccountId::new(1, 9).unwrap(),
            Bytes32::default(),
            &commitment(3),
            AccountId::new(1, 10).unwrap(),
            AccountId::new(1, 11).unwrap(),
        );
        let different = Pay::signing_digest(
            AccountId::new(1, 9).unwrap(),
            Bytes32::default(),
            &commitment(4),
            AccountId::new(1, 10).unwrap(),
            AccountId::new(1, 11).unwrap(),
        );
        assert_ne!(digest, different);
    }

    #[test]
    fn close_intent_binds_state_snapshot_and_settlement() {
        let final_state = sample_state().with_computed_digest();
        let close_tx = CloseWithdrawal {
            channel_id: final_state.channel_id,
            final_channel_state_digest: final_state.digest,
            intmax_state_root: final_state.channel_fund.intmax_state_root,
            transfers: vec![CloseTransfer {
                member_id: AccountId::new(7, 12).unwrap(),
                l1_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
                user_amount: commitment(8),
            }],
            zkp: vec![1, 2, 3],
        };

        let intent_a = CloseIntent::new(9, &final_state, &close_tx, 123).unwrap();
        let intent_b = CloseIntent::new(9, &final_state, &close_tx, 123).unwrap();
        assert_eq!(intent_a.signing_digest(), intent_b.signing_digest());

        let different = CloseIntent::new(10, &final_state, &close_tx, 123).unwrap();
        assert_ne!(intent_a.signing_digest(), different.signing_digest());
    }

    #[test]
    fn cancel_close_binds_revived_tx_to_close_intent() {
        let final_state = sample_state().with_computed_digest();
        let close_tx = CloseWithdrawal {
            channel_id: final_state.channel_id,
            final_channel_state_digest: final_state.digest,
            intmax_state_root: final_state.channel_fund.intmax_state_root,
            transfers: vec![],
            zkp: vec![],
        };
        let close_intent = CloseIntent::new(1, &final_state, &close_tx, 55).unwrap();
        let inter_channel_tx = InterChannelTx {
            mkproof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::default(),
            },
            sender_amount: commitment(4),
            sender_channel_id: final_state.channel_id,
            receiver_channel_id: AccountId::new(8, 1).unwrap(),
            seal: Bytes32::default(),
            tx_hash: Bytes32::from_u32_slice(&[0, 1, 2, 3, 4, 5, 6, 7]).unwrap(),
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![1, 2],
            receiver_deltas: vec![],
            receiver_update_proof: vec![],
            sender_debit_proof: vec![3, 4],
            sender_channel_signatures: vec![],
        };

        let cancel_a = CancelClose::new(&close_intent, &inter_channel_tx, vec![9]);
        let mut inter_channel_tx_b = inter_channel_tx.clone();
        inter_channel_tx_b.tx_hash = Bytes32::from_u32_slice(&[7, 6, 5, 4, 3, 2, 1, 0]).unwrap();
        let cancel_b = CancelClose::new(&close_intent, &inter_channel_tx_b, vec![9]);
        assert_ne!(cancel_a.signing_digest(), cancel_b.signing_digest());
    }

    #[test]
    fn post_close_claim_binds_nullifier_and_amount() {
        let claim_a = PostCloseIncomingClaim {
            close_intent_digest: Bytes32::default(),
            incoming_tx_hash: Bytes32::default(),
            receiver_id: AccountId::new(1, 2).unwrap(),
            receiver_amount: commitment(3),
            personal_nullifier: Bytes32::default(),
            recipient_memo: vec![1, 2, 3],
            claim_proof: vec![4, 5, 6],
        };
        let mut claim_b = claim_a.clone();
        claim_b.personal_nullifier = Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(claim_a.signing_digest(), claim_b.signing_digest());
    }
}
