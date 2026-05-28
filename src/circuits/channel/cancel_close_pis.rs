use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::{
        channel::{CancelClose, CloseIntent, InterChannelTx},
        user_id::AccountId,
    },
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
};

pub const CANCEL_CLOSE_PUBLIC_INPUTS_LEN: usize = 33;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelClosePublicInputs {
    pub channel_id: AccountId,
    pub close_intent_digest: Bytes32,
    pub revived_inter_channel_tx_digest: Bytes32,
    pub revived_tx_hash: Bytes32,
    pub revived_seal: Bytes32,
}

#[derive(Debug, Error)]
pub enum CancelCloseWitnessError {
    #[error("cancel close object mismatch")]
    CancelCloseMismatch,

    #[error("revived tx sender channel {revived_tx:?} does not match close channel {close_intent:?}")]
    ChannelIdMismatch {
        revived_tx: AccountId,
        close_intent: AccountId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelCloseWitness {
    pub close_intent: CloseIntent,
    pub revived_tx: InterChannelTx,
    pub cancel_close: CancelClose,
}

impl CancelCloseWitness {
    pub fn to_public_inputs(&self) -> Result<CancelClosePublicInputs, CancelCloseWitnessError> {
        if self.revived_tx.sender_channel_id != self.close_intent.channel_id {
            return Err(CancelCloseWitnessError::ChannelIdMismatch {
                revived_tx: self.revived_tx.sender_channel_id,
                close_intent: self.close_intent.channel_id,
            });
        }

        let expected = CancelClose::new(
            &self.close_intent,
            &self.revived_tx,
            self.cancel_close.cancel_proof.clone(),
        );
        if expected != self.cancel_close {
            return Err(CancelCloseWitnessError::CancelCloseMismatch);
        }

        Ok(CancelClosePublicInputs {
            channel_id: self.close_intent.channel_id,
            close_intent_digest: self.close_intent.signing_digest(),
            revived_inter_channel_tx_digest: self.revived_tx.signing_digest(),
            revived_tx_hash: self.revived_tx.tx_hash,
            revived_seal: self.revived_tx.seal,
        })
    }
}

impl CancelClosePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.channel_id.to_u64_vec(),
            self.close_intent_digest.to_u64_vec(),
            self.revived_inter_channel_tx_digest.to_u64_vec(),
            self.revived_tx_hash.to_u64_vec(),
            self.revived_seal.to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, String> {
        if values.len() != CANCEL_CLOSE_PUBLIC_INPUTS_LEN {
            return Err(format!(
                "invalid cancel-close public input length: expected {CANCEL_CLOSE_PUBLIC_INPUTS_LEN}, got {}",
                values.len()
            ));
        }

        Ok(Self {
            channel_id: AccountId::from_u64(values[0]).map_err(|e| e.to_string())?,
            close_intent_digest: Bytes32::from_u64_slice(&values[1..9]).map_err(|e| e.to_string())?,
            revived_inter_channel_tx_digest: Bytes32::from_u64_slice(&values[9..17])
                .map_err(|e| e.to_string())?,
            revived_tx_hash: Bytes32::from_u64_slice(&values[17..25]).map_err(|e| e.to_string())?,
            revived_seal: Bytes32::from_u64_slice(&values[25..33]).map_err(|e| e.to_string())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::channel::{
            ChannelFund, ChannelState, LatticeCommitment, MemberSignature, MerkleInclusionProof,
            ReceiverBalanceDelta,
        },
        ethereum_types::{bytes32::Bytes32, u256::U256},
    };

    fn sample_close_intent() -> CloseIntent {
        let state = ChannelState {
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
                signature: vec![1],
            }],
        }
        .with_computed_digest();
        let close_withdrawal = crate::common::channel::CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            intmax_state_root: state.channel_fund.intmax_state_root,
            transfers: vec![],
            zkp: vec![7],
        };
        CloseIntent::new(5, &state, &close_withdrawal, &[], 123).unwrap()
    }

    #[test]
    fn cancel_close_public_inputs_roundtrip() {
        let close_intent = sample_close_intent();
        let revived_tx = InterChannelTx {
            mkproof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::default(),
            },
            sender_amount: LatticeCommitment {
                commitment: vec![1; 48],
            },
            sender_channel_id: close_intent.channel_id,
            receiver_channel_id: AccountId::new(4, 1).unwrap(),
            seal: Bytes32::from_u32_slice(&[8, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![1, 2],
            receiver_deltas: vec![ReceiverBalanceDelta {
                receiver_id: AccountId::new(4, 11).unwrap(),
                amount: LatticeCommitment {
                    commitment: vec![2; 48],
                },
            }],
            receiver_update_proof: vec![3],
            sender_debit_proof: vec![4],
            sender_channel_signatures: vec![],
        };
        let cancel_close = CancelClose::new(&close_intent, &revived_tx, vec![5, 6]);
        let witness = CancelCloseWitness {
            close_intent,
            revived_tx,
            cancel_close,
        };

        let public_inputs = witness.to_public_inputs().unwrap();
        let roundtrip =
            CancelClosePublicInputs::from_u64_slice(&public_inputs.to_u64_vec()).unwrap();
        assert_eq!(public_inputs, roundtrip);
    }
}
