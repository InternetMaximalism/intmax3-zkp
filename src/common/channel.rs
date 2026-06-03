use plonky2_keccak::utils::solidity_keccak256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::user_id::AccountId,
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
};

pub type SignatureBytes = Vec<u8>;

const CHANNEL_STATE_DOMAIN: u32 = 0x494d4348; // "IMCH"
const PAY_DOMAIN: u32 = 0x494d5041; // "IMPA"
const SMALL_BLOCK_DOMAIN: u32 = 0x494d5342; // "IMSB"
const SIGNED_SMALL_BLOCK_DOMAIN: u32 = 0x494d5353; // "IMSS"
const INTER_CHANNEL_TX_DOMAIN: u32 = 0x494d4954; // "IMIT"
const CLOSE_TX_DOMAIN: u32 = 0x494d434c; // "IMCL"
const CLOSE_INTENT_DOMAIN: u32 = 0x494d4349; // "IMCI"
const SPECIAL_CLOSE_DOMAIN: u32 = 0x494d5343; // "IMSC"
const CANCEL_CLOSE_DOMAIN: u32 = 0x494d434e; // "IMCN"
const POST_CLOSE_CLAIM_DOMAIN: u32 = 0x494d4350; // "IMCP"
const WITHDRAWAL_CLAIM_DOMAIN: u32 = 0x494d4357; // "IMCW"
const CHANNEL_BALANCE_LEAF_DOMAIN: u32 = 0x494d5546; // "IMUF"
const CHANNEL_RECORD_DOMAIN: u32 = 0x494d4352; // "IMCR"
const KEY_RECORD_DOMAIN: u32 = 0x494d4b52; // "IMKR"
pub const MAX_CLOSE_TRANSFERS: usize = 16;
pub const SMALL_BLOCK_SIGNATURE_TIMEOUT_SECS: u64 = 60;
pub const SPECIAL_CLOSE_MEDIUM_BLOCK_WINDOW: u64 = 5;
pub const MAX_DUMMY_DELTA_AMOUNT: u64 = 1;

#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("invalid identifier length: expected {expected}, got {actual}")]
    InvalidIdLength { expected: usize, actual: usize },

    #[error("invalid identifier value: {0}")]
    InvalidIdValue(String),

    #[error("invalid close binding: {0}")]
    InvalidCloseBinding(String),

    #[error("invalid channel record: {0}")]
    InvalidChannelRecord(String),

    #[error("invalid signature set: {0}")]
    InvalidSignatureSet(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelStatus {
    Active,
    ClosePending,
    Closed,
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
    SpecialCloseSettlement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelTransitionKind {
    InChannelTransfer,
    InterChannelSend,
    InterChannelFundImport,
    ReceiverBundleApply,
    ChannelClose,
    SpecialClose,
}

impl ChannelTransitionKind {
    pub const fn required_state_backend(self) -> Option<ProofBackend> {
        match self {
            Self::InChannelTransfer | Self::InterChannelSend | Self::ReceiverBundleApply => {
                Some(ProofBackend::Plonky3)
            }
            Self::InterChannelFundImport | Self::ChannelClose | Self::SpecialClose => None,
        }
    }

    pub const fn required_transport_backend(self) -> Option<ProofBackend> {
        match self {
            Self::InterChannelSend
            | Self::InterChannelFundImport
            | Self::ChannelClose
            | Self::SpecialClose => Some(ProofBackend::Plonky2),
            Self::InChannelTransfer | Self::ReceiverBundleApply => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChannelId([u8; 5]);

impl ChannelId {
    pub fn new(value: u64) -> Result<Self, ChannelError> {
        if value >= (1u64 << 40) {
            return Err(ChannelError::InvalidIdValue(format!(
                "channel id {value} does not fit in 5 bytes"
            )));
        }
        Ok(Self(value.to_be_bytes()[3..8].try_into().expect("slice len 5")))
    }

    pub fn from_bytes(bytes: [u8; 5]) -> Result<Self, ChannelError> {
        let out = Self(bytes);
        if out.as_u64() == 0 {
            return Err(ChannelError::InvalidIdValue(
                "channel id 0 is reserved".to_string(),
            ));
        }
        Ok(out)
    }

    pub fn as_bytes(&self) -> [u8; 5] {
        self.0
    }

    pub fn as_u64(&self) -> u64 {
        let mut out = [0u8; 8];
        out[3..8].copy_from_slice(&self.0);
        u64::from_be_bytes(out)
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        bytes_to_u32_words(&self.0)
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        self.to_u32_vec().into_iter().map(|value| value as u64).collect()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, ChannelError> {
        let bytes = fixed_bytes_from_u32_word_slice(values, 5)?;
        Self::from_bytes(bytes.try_into().expect("slice len 5"))
    }
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId([u8; 5]);

impl KeyId {
    pub fn new(value: u64) -> Result<Self, ChannelError> {
        if value >= (1u64 << 40) {
            return Err(ChannelError::InvalidIdValue(format!(
                "key id {value} does not fit in 5 bytes"
            )));
        }
        Ok(Self(value.to_be_bytes()[3..8].try_into().expect("slice len 5")))
    }

    pub fn from_bytes(bytes: [u8; 5]) -> Result<Self, ChannelError> {
        let out = Self(bytes);
        if out.as_u64() == 0 {
            return Err(ChannelError::InvalidIdValue(
                "key id 0 is reserved".to_string(),
            ));
        }
        Ok(out)
    }

    pub fn as_bytes(&self) -> [u8; 5] {
        self.0
    }

    pub fn as_u64(&self) -> u64 {
        let mut out = [0u8; 8];
        out[3..8].copy_from_slice(&self.0);
        u64::from_be_bytes(out)
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        bytes_to_u32_words(&self.0)
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        self.to_u32_vec().into_iter().map(|value| value as u64).collect()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, ChannelError> {
        let bytes = fixed_bytes_from_u32_word_slice(values, 5)?;
        Self::from_bytes(bytes.try_into().expect("slice len 5"))
    }
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId([u8; 10]);

impl UserId {
    pub fn from_parts(channel_id: ChannelId, key_id: KeyId) -> Self {
        let mut out = [0u8; 10];
        out[..5].copy_from_slice(&channel_id.as_bytes());
        out[5..10].copy_from_slice(&key_id.as_bytes());
        Self(out)
    }

    pub fn as_bytes(&self) -> [u8; 10] {
        self.0
    }

    pub fn channel_id(&self) -> ChannelId {
        ChannelId(self.0[..5].try_into().expect("slice len 5"))
    }

    pub fn key_id(&self) -> KeyId {
        KeyId(self.0[5..10].try_into().expect("slice len 5"))
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        bytes_to_u32_words(&self.0)
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        self.to_u32_vec().into_iter().map(|value| value as u64).collect()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, ChannelError> {
        let bytes = fixed_bytes_from_u32_word_slice(values, 10)?;
        Ok(Self(bytes.try_into().expect("slice len 10")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRecord {
    pub key_id: KeyId,
    pub sphincs_pubkey_hashes_root: Bytes32,
    pub threshold: u32,
    pub num_keys: u32,
}

impl KeyRecord {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![KEY_RECORD_DOMAIN],
                self.key_id.to_u32_vec(),
                self.sphincs_pubkey_hashes_root.to_u32_vec(),
                vec![self.threshold, self.num_keys],
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelRecord {
    pub channel_id: ChannelId,
    pub bp_key_id: KeyId,
    pub member_key_ids: Vec<KeyId>,
    pub member_key_ids_root: Bytes32,
    pub special_close_penalty: U256,
    pub close_freeze_nonce: u64,
    pub status: ChannelStatus,
}

impl ChannelRecord {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.member_key_ids.is_empty() {
            return Err(ChannelError::InvalidChannelRecord(
                "member_key_ids must not be empty".to_string(),
            ));
        }
        let mut prev: Option<KeyId> = None;
        for key_id in &self.member_key_ids {
            if let Some(previous) = prev {
                if previous.as_u64() >= key_id.as_u64() {
                    return Err(ChannelError::InvalidChannelRecord(
                        "member_key_ids must be strictly ordered and unique".to_string(),
                    ));
                }
            }
            prev = Some(*key_id);
        }
        if !self.member_key_ids.contains(&self.bp_key_id) {
            return Err(ChannelError::InvalidChannelRecord(
                "bp_key_id must belong to member_key_ids".to_string(),
            ));
        }
        Ok(())
    }

    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CHANNEL_RECORD_DOMAIN],
                self.channel_id.to_u32_vec(),
                self.bp_key_id.to_u32_vec(),
                split_u64(self.close_freeze_nonce),
                vec![self.status as u32, self.member_key_ids.len() as u32],
                self.member_key_ids
                    .iter()
                    .flat_map(KeyId::to_u32_vec)
                    .collect::<Vec<_>>(),
                self.member_key_ids_root.to_u32_vec(),
                self.special_close_penalty.to_u32_vec(),
            ]
            .concat(),
        )
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
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleInclusionProof {
    pub siblings: Vec<Bytes32>,
    pub leaf_index: U256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmallBlockRootMessage {
    pub channel_id: ChannelId,
    pub bp_key_id: KeyId,
    pub small_block_number: u64,
    pub prev_small_block_root: Bytes32,
    pub tx_tree_root: Bytes32,
    pub state_commitment_root: Bytes32,
    pub medium_epoch_hint: u64,
    pub close_freeze_nonce: u64,
}

impl SmallBlockRootMessage {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![SMALL_BLOCK_DOMAIN],
                self.channel_id.to_u32_vec(),
                self.bp_key_id.to_u32_vec(),
                split_u64(self.small_block_number),
                self.prev_small_block_root.to_u32_vec(),
                self.tx_tree_root.to_u32_vec(),
                self.state_commitment_root.to_u32_vec(),
                split_u64(self.medium_epoch_hint),
                split_u64(self.close_freeze_nonce),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberSignature {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub signature: SignatureBytes,
    pub key_condition_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedSmallBlock {
    pub message: SmallBlockRootMessage,
    pub signatures: Vec<MemberSignature>,
    pub aggregated_signature_proof: Vec<u8>,
    pub medium_block_number: u64,
    pub confirmation_proof: Vec<u8>,
}

impl SignedSmallBlock {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![SIGNED_SMALL_BLOCK_DOMAIN],
                self.message.signing_digest().to_u32_vec(),
                split_u64(self.medium_block_number),
                vec![self.signatures.len() as u32],
                self.signatures
                    .iter()
                    .flat_map(|signature| {
                        [
                            signature.key_id.to_u32_vec(),
                            signature.user_id.to_u32_vec(),
                            vec![signature.signature.len() as u32],
                            bytes_to_u32_words(&signature.signature),
                            vec![signature.key_condition_proof.len() as u32],
                            bytes_to_u32_words(&signature.key_condition_proof),
                        ]
                        .concat()
                    })
                    .collect::<Vec<_>>(),
                vec![self.aggregated_signature_proof.len() as u32],
                bytes_to_u32_words(&self.aggregated_signature_proof),
                vec![self.confirmation_proof.len() as u32],
                bytes_to_u32_words(&self.confirmation_proof),
            ]
            .concat(),
        )
    }
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
pub struct ChannelBalance {
    pub channel_id: ChannelId,
    pub user_id: UserId,
    pub balance_commitment: LatticeCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelMember {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub l1_withdrawal_recipient: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelState {
    pub channel_id: ChannelId,
    pub epoch: u64,
    pub small_block_number: u64,
    pub close_freeze_nonce: u64,
    pub channel_fund: ChannelFund,
    pub channel_balance_root: Bytes32,
    pub shared_native_nullifier_root: Bytes32,
    pub unallocated_confirmed_incoming: U256,
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
                split_u64(self.small_block_number),
                split_u64(self.close_freeze_nonce),
                self.channel_fund.channel_id.to_u32_vec(),
                self.channel_fund.amount.to_u32_vec(),
                self.channel_fund.intmax_state_root.to_u32_vec(),
                self.channel_balance_root.to_u32_vec(),
                self.shared_native_nullifier_root.to_u32_vec(),
                self.unallocated_confirmed_incoming.to_u32_vec(),
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
    pub rejecting_user_id: UserId,
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
    pub sender_user_id: UserId,
    pub receiver_user_id: UserId,
}

impl Pay {
    pub fn signing_digest(
        channel_id: ChannelId,
        prev_state_digest: Bytes32,
        amount: &LatticeCommitment,
        sender_user_id: UserId,
        receiver_user_id: UserId,
    ) -> Bytes32 {
        hash_words(
            &[
                vec![PAY_DOMAIN],
                channel_id.to_u32_vec(),
                prev_state_digest.to_u32_vec(),
                amount.digest().to_u32_vec(),
                sender_user_id.to_u32_vec(),
                receiver_user_id.to_u32_vec(),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiverBalanceDelta {
    pub receiver_key_id: KeyId,
    pub receiver_user_id: UserId,
    pub amount: LatticeCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterChannelTx {
    pub tx_inclusion_proof: MerkleInclusionProof,
    pub signed_small_block: SignedSmallBlock,
    pub sender_amount: LatticeCommitment,
    pub source_channel_id: ChannelId,
    pub destination_channel_id: ChannelId,
    pub source_key_id: KeyId,
    pub source_user_id: UserId,
    pub seal: Bytes32,
    pub tx_hash: Bytes32,
    pub intmax_transfer_commitment: Bytes32,
    pub recipient_memo: Vec<u8>,
    pub receiver_deltas: Vec<ReceiverBalanceDelta>,
    pub receiver_update_proof: Vec<u8>,
    pub sender_balance_update_proof: Vec<u8>,
    pub transport_proof: Vec<u8>,
}

impl InterChannelTx {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![INTER_CHANNEL_TX_DOMAIN],
                self.signed_small_block.signing_digest().to_u32_vec(),
                self.sender_amount.digest().to_u32_vec(),
                self.source_channel_id.to_u32_vec(),
                self.destination_channel_id.to_u32_vec(),
                self.source_key_id.to_u32_vec(),
                self.source_user_id.to_u32_vec(),
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
                            delta.receiver_key_id.to_u32_vec(),
                            delta.receiver_user_id.to_u32_vec(),
                            delta.amount.digest().to_u32_vec(),
                        ]
                        .concat()
                    })
                    .collect::<Vec<_>>(),
                vec![self.receiver_update_proof.len() as u32],
                bytes_to_u32_words(&self.receiver_update_proof),
                vec![self.sender_balance_update_proof.len() as u32],
                bytes_to_u32_words(&self.sender_balance_update_proof),
                vec![self.transport_proof.len() as u32],
                bytes_to_u32_words(&self.transport_proof),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseWithdrawal {
    pub channel_id: ChannelId,
    pub final_channel_state_digest: Bytes32,
    pub final_channel_balance_root: Bytes32,
    pub intmax_state_root: Bytes32,
    pub burn_tx_hash: Bytes32,
    pub burn_amount: U256,
    pub zkp: Vec<u8>,
}

impl CloseWithdrawal {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CLOSE_TX_DOMAIN],
                self.channel_id.to_u32_vec(),
                self.final_channel_state_digest.to_u32_vec(),
                self.final_channel_balance_root.to_u32_vec(),
                self.intmax_state_root.to_u32_vec(),
                self.burn_tx_hash.to_u32_vec(),
                self.burn_amount.to_u32_vec(),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseIntent {
    pub channel_id: ChannelId,
    pub close_nonce: u64,
    pub final_epoch: u64,
    pub final_small_block_number: u64,
    pub close_freeze_nonce: u64,
    pub final_channel_state_digest: Bytes32,
    pub final_channel_balance_root: Bytes32,
    pub channel_fund_snapshot: ChannelFund,
    pub burn_tx_hash: Bytes32,
    pub close_withdrawal_digest: Bytes32,
    pub snapshot_medium_block_number: u64,
}

impl CloseIntent {
    pub fn new(
        close_nonce: u64,
        final_channel_state: &ChannelState,
        close_withdrawal: &CloseWithdrawal,
        snapshot_medium_block_number: u64,
    ) -> Result<Self, ChannelError> {
        if final_channel_state.channel_id != close_withdrawal.channel_id {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final state channel_id {:?} != close withdrawal channel_id {:?}",
                final_channel_state.channel_id, close_withdrawal.channel_id
            )));
        }
        if final_channel_state.digest != close_withdrawal.final_channel_state_digest {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final state digest {:?} != close withdrawal digest {:?}",
                final_channel_state.digest, close_withdrawal.final_channel_state_digest
            )));
        }
        if final_channel_state.channel_balance_root != close_withdrawal.final_channel_balance_root {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final balance root {:?} != close withdrawal balance root {:?}",
                final_channel_state.channel_balance_root,
                close_withdrawal.final_channel_balance_root
            )));
        }
        if final_channel_state.channel_fund.intmax_state_root != close_withdrawal.intmax_state_root
        {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final intmax state root {:?} != close withdrawal intmax_state_root {:?}",
                final_channel_state.channel_fund.intmax_state_root,
                close_withdrawal.intmax_state_root
            )));
        }
        if final_channel_state.channel_fund.amount != close_withdrawal.burn_amount {
            return Err(ChannelError::InvalidCloseBinding(format!(
                "final channel fund amount {:?} != close withdrawal burn_amount {:?}",
                final_channel_state.channel_fund.amount, close_withdrawal.burn_amount
            )));
        }
        if final_channel_state.unallocated_confirmed_incoming != U256::zero() {
            return Err(ChannelError::InvalidCloseBinding(
                "close requires unallocated_confirmed_incoming = 0".to_string(),
            ));
        }
        Ok(Self {
            channel_id: final_channel_state.channel_id,
            close_nonce,
            final_epoch: final_channel_state.epoch,
            final_small_block_number: final_channel_state.small_block_number,
            close_freeze_nonce: final_channel_state.close_freeze_nonce + 1,
            final_channel_state_digest: final_channel_state.digest,
            final_channel_balance_root: final_channel_state.channel_balance_root,
            channel_fund_snapshot: final_channel_state.channel_fund.clone(),
            burn_tx_hash: close_withdrawal.burn_tx_hash,
            close_withdrawal_digest: close_withdrawal.signing_digest(),
            snapshot_medium_block_number,
        })
    }

    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![CLOSE_INTENT_DOMAIN],
                self.channel_id.to_u32_vec(),
                split_u64(self.close_nonce),
                split_u64(self.final_epoch),
                split_u64(self.final_small_block_number),
                split_u64(self.close_freeze_nonce),
                self.final_channel_state_digest.to_u32_vec(),
                self.final_channel_balance_root.to_u32_vec(),
                self.channel_fund_snapshot.channel_id.to_u32_vec(),
                self.channel_fund_snapshot.amount.to_u32_vec(),
                self.channel_fund_snapshot.intmax_state_root.to_u32_vec(),
                self.burn_tx_hash.to_u32_vec(),
                self.close_withdrawal_digest.to_u32_vec(),
                split_u64(self.snapshot_medium_block_number),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalClaim {
    pub close_intent_digest: Bytes32,
    pub user_id: UserId,
    pub l1_recipient: Address,
    pub user_amount: LatticeCommitment,
    pub withdrawal_nullifier: Bytes32,
    pub claim_proof: Vec<u8>,
}

impl WithdrawalClaim {
    pub fn derive_nullifier(close_intent_digest: Bytes32, user_id: UserId) -> Bytes32 {
        hash_words(
            &[
                vec![WITHDRAWAL_CLAIM_DOMAIN],
                close_intent_digest.to_u32_vec(),
                user_id.to_u32_vec(),
            ]
            .concat(),
        )
    }

    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![WITHDRAWAL_CLAIM_DOMAIN],
                self.close_intent_digest.to_u32_vec(),
                self.user_id.to_u32_vec(),
                self.l1_recipient.to_u32_vec(),
                self.user_amount.digest().to_u32_vec(),
                self.withdrawal_nullifier.to_u32_vec(),
                vec![self.claim_proof.len() as u32],
                bytes_to_u32_words(&self.claim_proof),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecialClose {
    pub channel_id: ChannelId,
    pub offending_bp_key_id: KeyId,
    pub fully_signed_small_block_root: Bytes32,
    pub small_block_number: u64,
    pub signed_medium_block_number: u64,
    pub latest_finalized_medium_block_number: u64,
    pub non_inclusion_proof: Vec<u8>,
    pub aggregated_signature_proof: Vec<u8>,
}

impl SpecialClose {
    pub fn signing_digest(&self) -> Bytes32 {
        hash_words(
            &[
                vec![SPECIAL_CLOSE_DOMAIN],
                self.channel_id.to_u32_vec(),
                self.offending_bp_key_id.to_u32_vec(),
                self.fully_signed_small_block_root.to_u32_vec(),
                split_u64(self.small_block_number),
                split_u64(self.signed_medium_block_number),
                split_u64(self.latest_finalized_medium_block_number),
                vec![self.non_inclusion_proof.len() as u32],
                bytes_to_u32_words(&self.non_inclusion_proof),
                vec![self.aggregated_signature_proof.len() as u32],
                bytes_to_u32_words(&self.aggregated_signature_proof),
            ]
            .concat(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelClose {
    pub close_intent_digest: Bytes32,
    pub revived_small_block_root: Bytes32,
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
            revived_small_block_root: revived_tx.signed_small_block.message.signing_digest(),
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
                self.revived_small_block_root.to_u32_vec(),
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
    pub receiver_user_id: UserId,
    pub l1_recipient: Address,
    pub receiver_amount: LatticeCommitment,
    pub shared_native_nullifier: Bytes32,
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
                self.receiver_user_id.to_u32_vec(),
                self.l1_recipient.to_u32_vec(),
                self.receiver_amount.digest().to_u32_vec(),
                self.shared_native_nullifier.to_u32_vec(),
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
    InterChannelFundImport(InterChannelTx),
    ReceiverBundleApply(InterChannelTx),
    ChannelClose(CloseWithdrawal),
    SpecialClose(SpecialClose),
}

impl ChannelTransition {
    pub const fn kind(&self) -> ChannelTransitionKind {
        match self {
            Self::InChannelTransfer(_) => ChannelTransitionKind::InChannelTransfer,
            Self::InterChannelSend(_) => ChannelTransitionKind::InterChannelSend,
            Self::InterChannelFundImport(_) => ChannelTransitionKind::InterChannelFundImport,
            Self::ReceiverBundleApply(_) => ChannelTransitionKind::ReceiverBundleApply,
            Self::ChannelClose(_) => ChannelTransitionKind::ChannelClose,
            Self::SpecialClose(_) => ChannelTransitionKind::SpecialClose,
        }
    }

    pub const fn required_state_backend(&self) -> Option<ProofBackend> {
        self.kind().required_state_backend()
    }

    pub const fn required_transport_backend(&self) -> Option<ProofBackend> {
        self.kind().required_transport_backend()
    }
}

pub fn validate_all_member_signatures(
    record: &ChannelRecord,
    channel_id: ChannelId,
    signatures: &[MemberSignature],
) -> Result<(), ChannelError> {
    record.validate()?;
    if signatures.len() != record.member_key_ids.len() {
        return Err(ChannelError::InvalidSignatureSet(format!(
            "expected {} member signatures, got {}",
            record.member_key_ids.len(),
            signatures.len()
        )));
    }
    for (expected_key_id, actual) in record.member_key_ids.iter().zip(signatures) {
        if actual.key_id != *expected_key_id {
            return Err(ChannelError::InvalidSignatureSet(format!(
                "signature key {:?} does not match expected key {:?}",
                actual.key_id, expected_key_id
            )));
        }
        if actual.user_id != UserId::from_parts(channel_id, *expected_key_id) {
            return Err(ChannelError::InvalidSignatureSet(
                "user_id must equal channel_id || key_id".to_string(),
            ));
        }
        if actual.signature.is_empty() {
            return Err(ChannelError::InvalidSignatureSet(
                "signature bytes must not be empty".to_string(),
            ));
        }
        if actual.key_condition_proof.is_empty() {
            return Err(ChannelError::InvalidSignatureSet(
                "key condition proof must not be empty".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn channel_balance_leaf_digest(
    channel_id: ChannelId,
    user_id: UserId,
    balance_commitment: &LatticeCommitment,
) -> Bytes32 {
    hash_words(
        &[
            vec![CHANNEL_BALANCE_LEAF_DOMAIN],
            channel_id.to_u32_vec(),
            user_id.to_u32_vec(),
            balance_commitment.digest().to_u32_vec(),
        ]
        .concat(),
    )
}

pub fn user_fund_leaf_digest(
    channel_id: ChannelId,
    user_id: UserId,
    balance_commitment: &LatticeCommitment,
) -> Bytes32 {
    channel_balance_leaf_digest(channel_id, user_id, balance_commitment)
}

pub fn merkle_root_from_proof(leaf: Bytes32, proof: &MerkleInclusionProof) -> Bytes32 {
    let mut current = leaf;
    let bits = proof.leaf_index.to_u32_vec();
    for (depth, sibling) in proof.siblings.iter().enumerate() {
        let limb = bits[bits.len() - 1 - (depth / 32)];
        let bit = (limb >> (depth % 32)) & 1;
        let pair = if bit == 0 {
            [current.to_u32_vec(), sibling.to_u32_vec()].concat()
        } else {
            [sibling.to_u32_vec(), current.to_u32_vec()].concat()
        };
        current = hash_words(&pair);
    }
    current
}

pub fn bridge_account_to_channel_id(account_id: AccountId) -> Result<ChannelId, ChannelError> {
    ChannelId::new(account_id.hub_id() as u64)
}

pub fn bridge_account_to_key_id(account_id: AccountId) -> Result<KeyId, ChannelError> {
    KeyId::new(account_id.account_no() as u64)
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

fn fixed_bytes_from_u32_word_slice(values: &[u64], len: usize) -> Result<Vec<u8>, ChannelError> {
    let expected_words = len.div_ceil(4);
    if values.len() != expected_words {
        return Err(ChannelError::InvalidIdLength {
            expected: expected_words,
            actual: values.len(),
        });
    }
    let mut out = Vec::with_capacity(expected_words * 4);
    for word in values {
        if *word > u32::MAX as u64 {
            return Err(ChannelError::InvalidIdValue(format!(
                "u32 limb out of range: {word}"
            )));
        }
        out.extend_from_slice(&(u32::try_from(*word).unwrap()).to_be_bytes());
    }
    out.truncate(len);
    Ok(out)
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

    fn sample_channel_id() -> ChannelId {
        ChannelId::new(7).unwrap()
    }

    fn sample_key_id(value: u64) -> KeyId {
        KeyId::new(value).unwrap()
    }

    fn sample_user_id(value: u64) -> UserId {
        UserId::from_parts(sample_channel_id(), sample_key_id(value))
    }

    fn sample_state() -> ChannelState {
        ChannelState {
            channel_id: sample_channel_id(),
            epoch: 3,
            small_block_number: 11,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id: sample_channel_id(),
                amount: U256::from(15u32),
                intmax_state_root: Bytes32::default(),
            },
            channel_balance_root: Bytes32::from_u32_slice(&[1, 2, 3, 4, 0, 0, 0, 0]).unwrap(),
            shared_native_nullifier_root: Bytes32::from_u32_slice(&[5, 6, 7, 8, 0, 0, 0, 0])
                .unwrap(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![
                MemberSignature {
                    key_id: sample_key_id(10),
                    user_id: sample_user_id(10),
                    signature: vec![1],
                    key_condition_proof: vec![2],
                },
                MemberSignature {
                    key_id: sample_key_id(11),
                    user_id: sample_user_id(11),
                    signature: vec![3],
                    key_condition_proof: vec![4],
                },
            ],
        }
        .with_computed_digest()
    }

    #[test]
    fn user_id_roundtrip() {
        let channel_id = ChannelId::new(0x0102030405).unwrap();
        let key_id = KeyId::new(0x060708090a).unwrap();
        let user_id = UserId::from_parts(channel_id, key_id);
        assert_eq!(user_id.channel_id(), channel_id);
        assert_eq!(user_id.key_id(), key_id);
        assert_eq!(UserId::from_u64_slice(&user_id.to_u64_vec()).unwrap(), user_id);
    }

    #[test]
    fn close_intent_is_stable() {
        let state = sample_state();
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_channel_balance_root: state.channel_balance_root,
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[9, 1, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: state.channel_fund.amount,
            zkp: vec![1, 2, 3],
        };
        let intent_a = CloseIntent::new(9, &state, &close_tx, 123).unwrap();
        let intent_b = CloseIntent::new(9, &state, &close_tx, 123).unwrap();
        assert_eq!(intent_a, intent_b);
    }

    #[test]
    fn validate_channel_record_signatures_requires_exact_members() {
        let record = ChannelRecord {
            channel_id: sample_channel_id(),
            bp_key_id: sample_key_id(10),
            member_key_ids: vec![sample_key_id(10), sample_key_id(11)],
            member_key_ids_root: Bytes32::default(),
            special_close_penalty: U256::from(5u32),
            close_freeze_nonce: 0,
            status: ChannelStatus::Active,
        };
        validate_all_member_signatures(&record, sample_channel_id(), &sample_state().member_signatures)
            .unwrap();
    }

    #[test]
    fn cancel_close_binds_small_block_root() {
        let state = sample_state();
        let small_block = SignedSmallBlock {
            message: SmallBlockRootMessage {
                channel_id: sample_channel_id(),
                bp_key_id: sample_key_id(10),
                small_block_number: 12,
                prev_small_block_root: Bytes32::default(),
                tx_tree_root: Bytes32::default(),
                state_commitment_root: Bytes32::default(),
                medium_epoch_hint: 3,
                close_freeze_nonce: 0,
            },
            signatures: state.member_signatures.clone(),
            aggregated_signature_proof: vec![1],
            medium_block_number: 4,
            confirmation_proof: vec![2],
        };
        let tx = InterChannelTx {
            tx_inclusion_proof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::zero(),
            },
            signed_small_block: small_block,
            sender_amount: commitment(1),
            source_channel_id: sample_channel_id(),
            destination_channel_id: ChannelId::new(8).unwrap(),
            source_key_id: sample_key_id(10),
            source_user_id: sample_user_id(10),
            seal: Bytes32::default(),
            tx_hash: Bytes32::from_u32_slice(&[3, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![],
            receiver_deltas: vec![],
            receiver_update_proof: vec![1],
            sender_balance_update_proof: vec![2],
            transport_proof: vec![3],
        };
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_channel_balance_root: state.channel_balance_root,
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::default(),
            burn_amount: state.channel_fund.amount,
            zkp: vec![],
        };
        let close_intent = CloseIntent::new(1, &state, &close_tx, 5).unwrap();
        let cancel = CancelClose::new(&close_intent, &tx, vec![9]);
        assert_eq!(
            cancel.revived_small_block_root,
            tx.signed_small_block.message.signing_digest()
        );
    }

    #[test]
    fn withdrawal_nullifier_depends_on_user_id() {
        let close_digest = Bytes32::from_u32_slice(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let a = WithdrawalClaim::derive_nullifier(close_digest, sample_user_id(10));
        let b = WithdrawalClaim::derive_nullifier(close_digest, sample_user_id(11));
        assert_ne!(a, b);
    }
}
