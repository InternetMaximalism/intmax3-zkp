use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::channel::{InterChannelTx, LatticeOpening, PostCloseIncomingClaim},
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
};

pub const POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN: usize = 36;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostCloseClaimPublicInputs {
    pub close_intent_digest: Bytes32,
    pub receiver_channel_id: crate::common::channel::ChannelId,
    pub incoming_tx_hash: Bytes32,
    pub receiver_user_id: crate::common::channel::UserId,
    pub recipient: Address,
    pub shared_native_nullifier: Bytes32,
    pub amount: u64,
}

#[derive(Debug, Error)]
pub enum PostCloseClaimWitnessError {
    #[error("post-close claim close_intent_digest mismatch")]
    CloseIntentDigestMismatch,
    #[error("post-close claim tx hash mismatch")]
    IncomingTxHashMismatch,
    #[error("post-close claim receiver channel mismatch")]
    ReceiverChannelMismatch,
    #[error("post-close claim receiver delta does not match imported tx bundle")]
    ReceiverDeltaMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostCloseClaimWitness {
    pub close_intent_digest: Bytes32,
    pub closed_channel_id: crate::common::channel::ChannelId,
    pub source_tx: InterChannelTx,
    pub claim: PostCloseIncomingClaim,
    pub receiver_amount_opening: LatticeOpening,
}

impl PostCloseClaimWitness {
    pub fn to_public_inputs(
        &self,
    ) -> Result<PostCloseClaimPublicInputs, PostCloseClaimWitnessError> {
        if self.claim.close_intent_digest != self.close_intent_digest {
            return Err(PostCloseClaimWitnessError::CloseIntentDigestMismatch);
        }
        if self.claim.incoming_tx_hash != self.source_tx.tx_hash {
            return Err(PostCloseClaimWitnessError::IncomingTxHashMismatch);
        }
        if self.source_tx.destination_channel_id != self.closed_channel_id {
            return Err(PostCloseClaimWitnessError::ReceiverChannelMismatch);
        }

        let matching_delta = self.source_tx.receiver_deltas.iter().any(|delta| {
            delta.receiver_user_id == self.claim.receiver_user_id
                && delta.amount == self.claim.receiver_amount
        });
        if !matching_delta {
            return Err(PostCloseClaimWitnessError::ReceiverDeltaMismatch);
        }

        Ok(PostCloseClaimPublicInputs {
            close_intent_digest: self.close_intent_digest,
            receiver_channel_id: self.closed_channel_id,
            incoming_tx_hash: self.source_tx.tx_hash,
            receiver_user_id: self.claim.receiver_user_id,
            recipient: self.claim.l1_recipient,
            shared_native_nullifier: self.claim.shared_native_nullifier,
            amount: self.receiver_amount_opening.amount,
        })
    }
}

impl PostCloseClaimPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.close_intent_digest.to_u64_vec(),
            self.receiver_channel_id.to_u64_vec(),
            self.incoming_tx_hash.to_u64_vec(),
            self.receiver_user_id.to_u64_vec(),
            self.recipient.to_u64_vec(),
            self.shared_native_nullifier.to_u64_vec(),
            split_u64(self.amount),
        ]
        .concat()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, String> {
        if values.len() != POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN {
            return Err(format!(
                "invalid post-close-claim public input length: expected {POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN}, got {}",
                values.len()
            ));
        }
        Ok(Self {
            close_intent_digest: Bytes32::from_u64_slice(&values[0..8]).map_err(|e| e.to_string())?,
            receiver_channel_id: crate::common::channel::ChannelId::from_u64_slice(&values[8..10]).map_err(|e| e.to_string())?,
            incoming_tx_hash: Bytes32::from_u64_slice(&values[10..18]).map_err(|e| e.to_string())?,
            receiver_user_id: crate::common::channel::UserId::from_u64_slice(&values[18..21]).map_err(|e| e.to_string())?,
            recipient: Address::from_u64_slice(&values[21..26]).map_err(|e| e.to_string())?,
            shared_native_nullifier: Bytes32::from_u64_slice(&values[26..34]).map_err(|e| e.to_string())?,
            amount: join_u64(&values[34..36]),
        })
    }
}

fn split_u64(value: u64) -> Vec<u64> {
    vec![(value >> 32), value as u32 as u64]
}

fn join_u64(limbs: &[u64]) -> u64 {
    (limbs[0] << 32) | limbs[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::channel::{
            ChannelId, InterChannelTx, KeyId, LatticeCommitment, MerkleInclusionProof,
            ReceiverBalanceDelta, SignedSmallBlock, SmallBlockRootMessage, UserId,
        },
        ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
    };

    #[test]
    fn post_close_claim_public_inputs_roundtrip() {
        let receiver_user_id =
            UserId::from_parts(ChannelId::new(7).unwrap(), KeyId::new(11).unwrap());
        let source_tx = InterChannelTx {
            tx_inclusion_proof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::default(),
            },
            signed_small_block: SignedSmallBlock {
                message: SmallBlockRootMessage {
                    channel_id: ChannelId::new(5).unwrap(),
                    bp_key_id: KeyId::new(10).unwrap(),
                    small_block_number: 1,
                    prev_small_block_root: Bytes32::default(),
                    tx_tree_root: Bytes32::default(),
                    state_commitment_root: Bytes32::default(),
                    medium_epoch_hint: 3,
                    close_freeze_nonce: 0,
                },
                signatures: vec![],
                aggregated_signature_proof: vec![1],
                medium_block_number: 3,
                confirmation_proof: vec![2],
            },
            sender_amount: LatticeCommitment {
                commitment: vec![1; 48],
            },
            source_channel_id: ChannelId::new(5).unwrap(),
            destination_channel_id: ChannelId::new(7).unwrap(),
            source_key_id: KeyId::new(10).unwrap(),
            source_user_id: UserId::from_parts(ChannelId::new(5).unwrap(), KeyId::new(10).unwrap()),
            seal: Bytes32::default(),
            tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![1, 2],
            receiver_deltas: vec![ReceiverBalanceDelta {
                receiver_key_id: KeyId::new(11).unwrap(),
                receiver_user_id,
                amount: LatticeCommitment {
                    commitment: vec![2; 48],
                },
            }],
            receiver_update_proof: vec![3],
            sender_balance_update_proof: vec![4],
            transport_proof: vec![5],
        };
        let claim = PostCloseIncomingClaim {
            close_intent_digest: Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            incoming_tx_hash: source_tx.tx_hash,
            receiver_user_id,
            l1_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
            receiver_amount: source_tx.receiver_deltas[0].amount.clone(),
            shared_native_nullifier: Bytes32::from_u32_slice(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            recipient_memo: vec![5, 6],
            claim_proof: vec![7],
        };
        let witness = PostCloseClaimWitness {
            close_intent_digest: claim.close_intent_digest,
            closed_channel_id: ChannelId::new(7).unwrap(),
            source_tx,
            claim,
            receiver_amount_opening: LatticeOpening {
                amount: 1,
                randomness: vec![],
                proof: vec![],
            },
        };

        let public_inputs = witness.to_public_inputs().unwrap();
        let roundtrip =
            PostCloseClaimPublicInputs::from_u64_slice(&public_inputs.to_u64_vec()).unwrap();
        assert_eq!(public_inputs, roundtrip);
    }
}
