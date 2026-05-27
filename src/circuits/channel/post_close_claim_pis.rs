use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::{
        channel::{InterChannelTx, LatticeOpening, PostCloseIncomingClaim},
        user_id::AccountId,
    },
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
};

pub const POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN: usize = 37;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostCloseClaimPublicInputs {
    pub close_intent_digest: Bytes32,
    pub receiver_channel_id: AccountId,
    pub sender_channel_id: AccountId,
    pub incoming_tx_hash: Bytes32,
    pub receiver_id: AccountId,
    pub receiver_amount_digest: Bytes32,
    pub personal_nullifier: Bytes32,
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
    pub closed_channel_id: AccountId,
    pub source_tx: InterChannelTx,
    pub claim: PostCloseIncomingClaim,
    pub receiver_amount_opening: LatticeOpening,
}

impl PostCloseClaimWitness {
    pub fn to_public_inputs(&self) -> Result<PostCloseClaimPublicInputs, PostCloseClaimWitnessError> {
        if self.claim.close_intent_digest != self.close_intent_digest {
            return Err(PostCloseClaimWitnessError::CloseIntentDigestMismatch);
        }
        if self.claim.incoming_tx_hash != self.source_tx.tx_hash {
            return Err(PostCloseClaimWitnessError::IncomingTxHashMismatch);
        }
        if self.source_tx.receiver_channel_id != self.closed_channel_id {
            return Err(PostCloseClaimWitnessError::ReceiverChannelMismatch);
        }

        let matching_delta = self.source_tx.receiver_deltas.iter().any(|delta| {
            delta.receiver_id == self.claim.receiver_id && delta.amount == self.claim.receiver_amount
        });
        if !matching_delta {
            return Err(PostCloseClaimWitnessError::ReceiverDeltaMismatch);
        }

        Ok(PostCloseClaimPublicInputs {
            close_intent_digest: self.close_intent_digest,
            receiver_channel_id: self.closed_channel_id,
            sender_channel_id: self.source_tx.sender_channel_id,
            incoming_tx_hash: self.source_tx.tx_hash,
            receiver_id: self.claim.receiver_id,
            receiver_amount_digest: self.claim.receiver_amount.digest(),
            personal_nullifier: self.claim.personal_nullifier,
            amount: self.receiver_amount_opening.amount,
        })
    }
}

impl PostCloseClaimPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.close_intent_digest.to_u64_vec(),
            self.receiver_channel_id.to_u64_vec(),
            self.sender_channel_id.to_u64_vec(),
            self.incoming_tx_hash.to_u64_vec(),
            self.receiver_id.to_u64_vec(),
            self.receiver_amount_digest.to_u64_vec(),
            self.personal_nullifier.to_u64_vec(),
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
            receiver_channel_id: AccountId::from_u64(values[8]).map_err(|e| e.to_string())?,
            sender_channel_id: AccountId::from_u64(values[9]).map_err(|e| e.to_string())?,
            incoming_tx_hash: Bytes32::from_u64_slice(&values[10..18]).map_err(|e| e.to_string())?,
            receiver_id: AccountId::from_u64(values[18]).map_err(|e| e.to_string())?,
            receiver_amount_digest: Bytes32::from_u64_slice(&values[19..27]).map_err(|e| e.to_string())?,
            personal_nullifier: Bytes32::from_u64_slice(&values[27..35]).map_err(|e| e.to_string())?,
            amount: join_u64(&values[35..37]),
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
    use crate::common::channel::{
        LatticeCommitment, MerkleInclusionProof, ReceiverBalanceDelta,
    };
    use crate::ethereum_types::{bytes32::Bytes32, u256::U256};

    #[test]
    fn post_close_claim_public_inputs_roundtrip() {
        let receiver_id = AccountId::new(7, 11).unwrap();
        let source_tx = InterChannelTx {
            mkproof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::default(),
            },
            sender_amount: LatticeCommitment {
                commitment: vec![1; 48],
            },
            sender_channel_id: AccountId::new(5, 1).unwrap(),
            receiver_channel_id: AccountId::new(7, 1).unwrap(),
            seal: Bytes32::default(),
            tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![1, 2],
            receiver_deltas: vec![ReceiverBalanceDelta {
                receiver_id,
                amount: LatticeCommitment {
                    commitment: vec![2; 48],
                },
            }],
            receiver_update_proof: vec![3],
            sender_debit_proof: vec![4],
            sender_channel_signatures: vec![],
        };
        let claim = PostCloseIncomingClaim {
            close_intent_digest: Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            incoming_tx_hash: source_tx.tx_hash,
            receiver_id,
            receiver_amount: source_tx.receiver_deltas[0].amount.clone(),
            personal_nullifier: Bytes32::from_u32_slice(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            recipient_memo: vec![5, 6],
            claim_proof: vec![7],
        };
        let witness = PostCloseClaimWitness {
            close_intent_digest: claim.close_intent_digest,
            closed_channel_id: AccountId::new(7, 1).unwrap(),
            source_tx,
            claim,
            receiver_amount_opening: LatticeOpening {
                amount: 1,
                randomness: vec![],
            },
        };

        let public_inputs = witness.to_public_inputs().unwrap();
        let roundtrip =
            PostCloseClaimPublicInputs::from_u64_slice(&public_inputs.to_u64_vec()).unwrap();
        assert_eq!(public_inputs, roundtrip);
    }
}
