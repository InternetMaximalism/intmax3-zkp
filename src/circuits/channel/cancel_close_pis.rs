use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::channel::{CancelClose, CloseIntent, InterChannelTx},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
};

pub const CANCEL_CLOSE_PUBLIC_INPUTS_LEN: usize = 42;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelClosePublicInputs {
    pub channel_id: crate::common::channel::ChannelId,
    pub close_intent_digest: Bytes32,
    pub revived_small_block_root: Bytes32,
    pub revived_inter_channel_tx_digest: Bytes32,
    pub revived_tx_hash: Bytes32,
    pub revived_seal: Bytes32,
}

#[derive(Debug, Error)]
pub enum CancelCloseWitnessError {
    #[error("cancel close object mismatch")]
    CancelCloseMismatch,
    #[error("revived tx source channel does not match close channel")]
    ChannelIdMismatch,
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
        if self.revived_tx.source_channel_id != self.close_intent.channel_id {
            return Err(CancelCloseWitnessError::ChannelIdMismatch);
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
            revived_small_block_root: self.cancel_close.revived_small_block_root,
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
            self.revived_small_block_root.to_u64_vec(),
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
            channel_id: crate::common::channel::ChannelId::from_u64_slice(&values[0..2])
                .map_err(|e| e.to_string())?,
            close_intent_digest: Bytes32::from_u64_slice(&values[2..10]).map_err(|e| e.to_string())?,
            revived_small_block_root: Bytes32::from_u64_slice(&values[10..18]).map_err(|e| e.to_string())?,
            revived_inter_channel_tx_digest: Bytes32::from_u64_slice(&values[18..26]).map_err(|e| e.to_string())?,
            revived_tx_hash: Bytes32::from_u64_slice(&values[26..34]).map_err(|e| e.to_string())?,
            revived_seal: Bytes32::from_u64_slice(&values[34..42]).map_err(|e| e.to_string())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::channel::{
            ChannelFund, ChannelId, ChannelState, CloseWithdrawal, KeyId, LatticeCommitment,
            MemberSignature, MerkleInclusionProof, ReceiverBalanceDelta, SignedSmallBlock,
            SmallBlockRootMessage, UserId,
        },
        ethereum_types::{bytes32::Bytes32, u256::U256},
    };

    fn sample_close_intent() -> CloseIntent {
        let state = ChannelState {
            channel_id: ChannelId::new(3).unwrap(),
            epoch: 8,
            small_block_number: 4,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id: ChannelId::new(3).unwrap(),
                amount: U256::from(77u32),
                intmax_state_root: Bytes32::default(),
            },
            channel_balance_root: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                key_id: KeyId::new(10).unwrap(),
                user_id: UserId::from_parts(ChannelId::new(3).unwrap(), KeyId::new(10).unwrap()),
                signature: vec![1],
                key_condition_proof: vec![2],
            }],
        }
        .with_computed_digest();
        let close_withdrawal = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_channel_balance_root: state.channel_balance_root,
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: state.channel_fund.amount,
            zkp: vec![7],
        };
        CloseIntent::new(5, &state, &close_withdrawal, 123).unwrap()
    }

    #[test]
    fn cancel_close_public_inputs_roundtrip() {
        let close_intent = sample_close_intent();
        let revived_tx = InterChannelTx {
            tx_inclusion_proof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::default(),
            },
            signed_small_block: SignedSmallBlock {
                message: SmallBlockRootMessage {
                    channel_id: close_intent.channel_id,
                    bp_key_id: KeyId::new(10).unwrap(),
                    small_block_number: 5,
                    prev_small_block_root: Bytes32::default(),
                    tx_tree_root: Bytes32::default(),
                    state_commitment_root: Bytes32::default(),
                    medium_epoch_hint: 3,
                    close_freeze_nonce: 0,
                },
                signatures: vec![MemberSignature {
                    key_id: KeyId::new(10).unwrap(),
                    user_id: UserId::from_parts(close_intent.channel_id, KeyId::new(10).unwrap()),
                    signature: vec![1],
                    key_condition_proof: vec![2],
                }],
                aggregated_signature_proof: vec![3],
                medium_block_number: 3,
                confirmation_proof: vec![4],
            },
            sender_amount: LatticeCommitment {
                commitment: vec![1; 48],
            },
            source_channel_id: close_intent.channel_id,
            destination_channel_id: ChannelId::new(4).unwrap(),
            source_key_id: KeyId::new(10).unwrap(),
            source_user_id: UserId::from_parts(close_intent.channel_id, KeyId::new(10).unwrap()),
            seal: Bytes32::from_u32_slice(&[8, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![1, 2],
            receiver_deltas: vec![ReceiverBalanceDelta {
                receiver_key_id: KeyId::new(11).unwrap(),
                receiver_user_id: UserId::from_parts(ChannelId::new(4).unwrap(), KeyId::new(11).unwrap()),
                amount: LatticeCommitment {
                    commitment: vec![2; 48],
                },
            }],
            receiver_update_proof: vec![3],
            sender_balance_update_proof: vec![4],
            transport_proof: vec![5],
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
