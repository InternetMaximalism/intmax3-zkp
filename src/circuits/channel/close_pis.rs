use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::channel::{ChannelError, ChannelId, ChannelState, CloseIntent, CloseWithdrawal},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
};

pub const CHANNEL_CLOSE_PUBLIC_INPUTS_LEN: usize = 68;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelClosePublicInputs {
    pub channel_id: ChannelId,
    pub close_nonce: u64,
    pub final_epoch: u64,
    pub final_small_block_number: u64,
    pub close_freeze_nonce: u64,
    pub final_channel_state_digest: Bytes32,
    pub final_channel_balance_root: Bytes32,
    pub channel_fund_amount: U256,
    pub channel_fund_intmax_state_root: Bytes32,
    pub burn_tx_hash: Bytes32,
    pub close_withdrawal_digest: Bytes32,
    pub close_intent_digest: Bytes32,
    pub snapshot_medium_block_number: u64,
}

#[derive(Debug, Error)]
pub enum ChannelClosePublicInputsError {
    #[error("invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("invalid field: {0}")]
    InvalidField(String),
}

impl ChannelClosePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.channel_id.to_u64_vec(),
            split_u64(self.close_nonce),
            split_u64(self.final_epoch),
            split_u64(self.final_small_block_number),
            split_u64(self.close_freeze_nonce),
            self.final_channel_state_digest.to_u64_vec(),
            self.final_channel_balance_root.to_u64_vec(),
            self.channel_fund_amount.to_u64_vec(),
            self.channel_fund_intmax_state_root.to_u64_vec(),
            self.burn_tx_hash.to_u64_vec(),
            self.close_withdrawal_digest.to_u64_vec(),
            self.close_intent_digest.to_u64_vec(),
            split_u64(self.snapshot_medium_block_number),
        ]
        .concat()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, ChannelClosePublicInputsError> {
        if values.len() != CHANNEL_CLOSE_PUBLIC_INPUTS_LEN {
            return Err(ChannelClosePublicInputsError::InvalidLength {
                expected: CHANNEL_CLOSE_PUBLIC_INPUTS_LEN,
                actual: values.len(),
            });
        }

        Ok(Self {
            channel_id: ChannelId::from_u64_slice(&values[0..2])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            close_nonce: join_u64(&values[2..4]),
            final_epoch: join_u64(&values[4..6]),
            final_small_block_number: join_u64(&values[6..8]),
            close_freeze_nonce: join_u64(&values[8..10]),
            final_channel_state_digest: Bytes32::from_u64_slice(&values[10..18])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            final_channel_balance_root: Bytes32::from_u64_slice(&values[18..26])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            channel_fund_amount: U256::from_u64_slice(&values[26..34])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            channel_fund_intmax_state_root: Bytes32::from_u64_slice(&values[34..42])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            burn_tx_hash: Bytes32::from_u64_slice(&values[42..50])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            close_withdrawal_digest: Bytes32::from_u64_slice(&values[50..58])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            close_intent_digest: Bytes32::from_u64_slice(&values[58..66])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            snapshot_medium_block_number: join_u64(&values[66..68]),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelCloseWitness {
    pub final_channel_state: ChannelState,
    pub close_tx: CloseWithdrawal,
    pub close_intent: CloseIntent,
}

#[derive(Debug, Error)]
pub enum ChannelCloseWitnessError {
    #[error("invalid close binding: {0}")]
    InvalidCloseBinding(#[from] ChannelError),

    #[error("close intent mismatch")]
    CloseIntentMismatch,
}

impl ChannelCloseWitness {
    pub fn to_public_inputs(&self) -> Result<ChannelClosePublicInputs, ChannelCloseWitnessError> {
        let expected_intent = CloseIntent::new(
            self.close_intent.close_nonce,
            &self.final_channel_state,
            &self.close_tx,
            self.close_intent.snapshot_medium_block_number,
        )?;

        if expected_intent != self.close_intent {
            return Err(ChannelCloseWitnessError::CloseIntentMismatch);
        }

        Ok(ChannelClosePublicInputs {
            channel_id: self.close_intent.channel_id,
            close_nonce: self.close_intent.close_nonce,
            final_epoch: self.close_intent.final_epoch,
            final_small_block_number: self.close_intent.final_small_block_number,
            close_freeze_nonce: self.close_intent.close_freeze_nonce,
            final_channel_state_digest: self.close_intent.final_channel_state_digest,
            final_channel_balance_root: self.close_intent.final_channel_balance_root,
            channel_fund_amount: self.close_intent.channel_fund_snapshot.amount,
            channel_fund_intmax_state_root: self
                .close_intent
                .channel_fund_snapshot
                .intmax_state_root,
            burn_tx_hash: self.close_intent.burn_tx_hash,
            close_withdrawal_digest: self.close_intent.close_withdrawal_digest,
            close_intent_digest: self.close_intent.signing_digest(),
            snapshot_medium_block_number: self.close_intent.snapshot_medium_block_number,
        })
    }
}

fn split_u64(value: u64) -> Vec<u64> {
    vec![(value >> 32) as u64, value as u32 as u64]
}

fn join_u64(limbs: &[u64]) -> u64 {
    ((limbs[0] as u64) << 32) | limbs[1] as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::channel::{
            ChannelFund, ChannelId, ChannelState, KeyId, MemberSignature, UserId,
        },
        ethereum_types::bytes32::Bytes32,
    };

    fn sample_state() -> ChannelState {
        ChannelState {
            channel_id: ChannelId::new(3).unwrap(),
            epoch: 8,
            small_block_number: 22,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id: ChannelId::new(3).unwrap(),
                amount: U256::from(77u32),
                intmax_state_root: Bytes32::default(),
            },
            channel_balance_root: Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            shared_native_nullifier_root: Bytes32::from_u32_slice(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                key_id: KeyId::new(10).unwrap(),
                user_id: UserId::from_parts(ChannelId::new(3).unwrap(), KeyId::new(10).unwrap()),
                signature: vec![1, 2, 3],
                key_condition_proof: vec![4, 5],
            }],
        }
        .with_computed_digest()
    }

    #[test]
    fn close_public_inputs_roundtrip() {
        let state = sample_state();
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_channel_balance_root: state.channel_balance_root,
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: state.channel_fund.amount,
            zkp: vec![9, 9, 9],
        };
        let close_intent = CloseIntent::new(5, &state, &close_tx, 123).unwrap();
        let witness = ChannelCloseWitness {
            final_channel_state: state,
            close_tx,
            close_intent,
        };

        let public_inputs = witness.to_public_inputs().unwrap();
        let roundtrip =
            ChannelClosePublicInputs::from_u64_slice(&public_inputs.to_u64_vec()).unwrap();
        assert_eq!(public_inputs, roundtrip);
    }
}
