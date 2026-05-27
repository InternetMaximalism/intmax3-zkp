use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::{
        channel::{ChannelError, ChannelState, CloseIntent, CloseWithdrawal},
        user_id::AccountId,
    },
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
};

pub const CHANNEL_CLOSE_PUBLIC_INPUTS_LEN: usize = 45;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelClosePublicInputs {
    pub channel_id: AccountId,
    pub close_nonce: u64,
    pub final_channel_state_digest: Bytes32,
    pub channel_fund_amount: U256,
    pub channel_fund_intmax_state_root: Bytes32,
    pub settlement_digest: Bytes32,
    pub close_intent_digest: Bytes32,
    pub snapshot_block_number: u64,
}

#[derive(Debug, Error)]
pub enum ChannelClosePublicInputsError {
    #[error("invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("invalid channel id: {0}")]
    InvalidChannelId(String),

    #[error("invalid final channel state digest: {0}")]
    InvalidFinalChannelStateDigest(String),

    #[error("invalid channel fund amount: {0}")]
    InvalidChannelFundAmount(String),

    #[error("invalid channel fund intmax state root: {0}")]
    InvalidChannelFundIntmaxStateRoot(String),

    #[error("invalid settlement digest: {0}")]
    InvalidSettlementDigest(String),

    #[error("invalid close intent digest: {0}")]
    InvalidCloseIntentDigest(String),
}

impl ChannelClosePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.channel_id.to_u64_vec(),
            split_u64(self.close_nonce),
            self.final_channel_state_digest.to_u64_vec(),
            self.channel_fund_amount.to_u64_vec(),
            self.channel_fund_intmax_state_root.to_u64_vec(),
            self.settlement_digest.to_u64_vec(),
            self.close_intent_digest.to_u64_vec(),
            split_u64(self.snapshot_block_number),
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

        let channel_id = AccountId::from_u64(values[0])
            .map_err(|e| ChannelClosePublicInputsError::InvalidChannelId(e.to_string()))?;
        let close_nonce = join_u64(&values[1..3]);
        let final_channel_state_digest = Bytes32::from_u64_slice(&values[3..11]).map_err(|e| {
            ChannelClosePublicInputsError::InvalidFinalChannelStateDigest(e.to_string())
        })?;
        let channel_fund_amount = U256::from_u64_slice(&values[11..19])
            .map_err(|e| ChannelClosePublicInputsError::InvalidChannelFundAmount(e.to_string()))?;
        let channel_fund_intmax_state_root =
            Bytes32::from_u64_slice(&values[19..27]).map_err(|e| {
                ChannelClosePublicInputsError::InvalidChannelFundIntmaxStateRoot(e.to_string())
            })?;
        let settlement_digest = Bytes32::from_u64_slice(&values[27..35])
            .map_err(|e| ChannelClosePublicInputsError::InvalidSettlementDigest(e.to_string()))?;
        let close_intent_digest = Bytes32::from_u64_slice(&values[35..43])
            .map_err(|e| ChannelClosePublicInputsError::InvalidCloseIntentDigest(e.to_string()))?;
        let snapshot_block_number = join_u64(&values[43..45]);

        Ok(Self {
            channel_id,
            close_nonce,
            final_channel_state_digest,
            channel_fund_amount,
            channel_fund_intmax_state_root,
            settlement_digest,
            close_intent_digest,
            snapshot_block_number,
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

    #[error("close intent mismatch: expected {expected:?}, got {actual:?}")]
    CloseIntentMismatch {
        expected: CloseIntent,
        actual: CloseIntent,
    },

    #[error(
        "close tx channel id {close_tx:?} does not match close intent channel id {close_intent:?}"
    )]
    ChannelIdMismatch {
        close_tx: AccountId,
        close_intent: AccountId,
    },
}

impl ChannelCloseWitness {
    pub fn to_public_inputs(&self) -> Result<ChannelClosePublicInputs, ChannelCloseWitnessError> {
        let expected_intent = CloseIntent::new(
            self.close_intent.close_nonce,
            &self.final_channel_state,
            &self.close_tx,
            self.close_intent.snapshot_block_number,
        )?;

        if expected_intent != self.close_intent {
            return Err(ChannelCloseWitnessError::CloseIntentMismatch {
                expected: expected_intent,
                actual: self.close_intent.clone(),
            });
        }

        if self.close_tx.channel_id != self.close_intent.channel_id {
            return Err(ChannelCloseWitnessError::ChannelIdMismatch {
                close_tx: self.close_tx.channel_id,
                close_intent: self.close_intent.channel_id,
            });
        }

        Ok(ChannelClosePublicInputs {
            channel_id: self.close_intent.channel_id,
            close_nonce: self.close_intent.close_nonce,
            final_channel_state_digest: self.close_intent.final_channel_state_digest,
            channel_fund_amount: self.close_intent.channel_fund_snapshot.amount,
            channel_fund_intmax_state_root: self
                .close_intent
                .channel_fund_snapshot
                .intmax_state_root,
            settlement_digest: self.close_intent.settlement_digest,
            close_intent_digest: self.close_intent.signing_digest(),
            snapshot_block_number: self.close_intent.snapshot_block_number,
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
            ChannelFund, ChannelState, CloseTransfer, CloseWithdrawal, LatticeCommitment,
            MemberSignature,
        },
        ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    };

    fn sample_state() -> ChannelState {
        ChannelState {
            channel_id: AccountId::new(3, 9).unwrap(),
            epoch: 8,
            channel_fund: ChannelFund {
                channel_id: AccountId::new(3, 9).unwrap(),
                amount: U256::from(77u32),
                intmax_state_root: Bytes32::default(),
            },
            user_fund_root: Bytes32::default(),
            channel_nullifier_root: Bytes32::default(),
            personal_nullifier_root: Bytes32::default(),
            incoming_root: Bytes32::default(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                signer: AccountId::new(3, 10).unwrap(),
                signature: vec![1, 2, 3],
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
            intmax_state_root: state.channel_fund.intmax_state_root,
            transfers: vec![CloseTransfer {
                member_id: AccountId::new(3, 10).unwrap(),
                l1_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
                user_amount: LatticeCommitment {
                    commitment: vec![7; 48],
                },
            }],
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
