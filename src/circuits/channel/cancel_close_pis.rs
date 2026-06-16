use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::channel::{CancelClose, CloseIntent, InterChannelTx},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
};

// 1 (channel id, single u32 limb) + 5 x 8 (digests/hashes).
pub const CANCEL_CLOSE_PUBLIC_INPUTS_LEN: usize = 41;

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
            channel_id: crate::common::channel::ChannelId::from_u64_slice(&values[0..1])
                .map_err(|e| e.to_string())?,
            close_intent_digest: Bytes32::from_u64_slice(&values[1..9])
                .map_err(|e| e.to_string())?,
            revived_small_block_root: Bytes32::from_u64_slice(&values[9..17])
                .map_err(|e| e.to_string())?,
            revived_inter_channel_tx_digest: Bytes32::from_u64_slice(&values[17..25])
                .map_err(|e| e.to_string())?,
            revived_tx_hash: Bytes32::from_u64_slice(&values[25..33]).map_err(|e| e.to_string())?,
            revived_seal: Bytes32::from_u64_slice(&values[33..41]).map_err(|e| e.to_string())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{
            balance_state::BalanceState,
            channel::{
                ChannelFund, ChannelId, ChannelProofEnvelope, ChannelState, CloseWithdrawal,
                MemberSignature, MerkleInclusionProof, ProofBackend, ReceiverBalanceDelta,
                SignedSmallBlock, SmallBlockRootMessage, TransitionProofRole,
            },
        },
        ethereum_types::{bytes32::Bytes32, u256::U256},
        regev::{REGEV_N, REGEV_Q, RegevCiphertext},
    };

    fn pubkey_hash(seed: u32) -> Bytes32 {
        Bytes32::from_u32_slice(&[
            seed,
            seed + 1,
            seed + 2,
            seed + 3,
            seed + 4,
            seed + 5,
            seed + 6,
            seed + 7,
        ])
        .unwrap()
    }

    fn ciphertext(seed: u32) -> RegevCiphertext {
        RegevCiphertext {
            c1: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(2_654_435_761).wrapping_add(i)) % REGEV_Q)
                .collect(),
            c2: (0..REGEV_N as u32)
                .map(|i| (seed.wrapping_mul(40_503).wrapping_add(1000 + i)) % REGEV_Q)
                .collect(),
        }
    }

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
            balance_state: BalanceState {
                channel_id: ChannelId::new(3).unwrap(),
                member_count: 3,
                delegate_count: 0,
                enc_balances: BalanceState::pad_enc_balances(&[
                    ciphertext(1),
                    ciphertext(2),
                    ciphertext(3),
                ]),
                settled_tx_chain: Bytes32::default(),
                state_version: 7,
                pending_adds: BalanceState::pad_pending_adds(&[0, 0, 0]),
            },
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                member_slot: 0,
                pk_g: pubkey_hash(10),
                signature: vec![1],
            }],
        }
        .with_computed_digest();
        let close_withdrawal = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_balance_state_h1: state.balance_state.h1(),
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
                    bp_member_slot: 0,
                    bp_pk_g: pubkey_hash(10),
                    small_block_number: 5,
                    prev_small_block_root: Bytes32::default(),
                    tx_tree_root: Bytes32::from_u32_slice(&[4, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
                    state_commitment_root: Bytes32::default(),
                    medium_epoch_hint: 3,
                    close_freeze_nonce: 0,
                },
                signatures: vec![MemberSignature {
                    member_slot: 0,
                    pk_g: pubkey_hash(10),
                    signature: vec![1],
                }],
                aggregated_signature_proof: vec![3],
                medium_block_number: 3,
                confirmation_proof: vec![4],
            },
            sender_delta_ct: ciphertext(10),
            source_channel_id: close_intent.channel_id,
            destination_channel_id: ChannelId::new(4).unwrap(),
            source_pk_g: pubkey_hash(10),
            seal: Bytes32::from_u32_slice(&[8, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![1, 2],
            receiver_deltas: vec![ReceiverBalanceDelta {
                receiver_pk_g: pubkey_hash(11),
                amount: ciphertext(11),
            }],
            channel_update_zkp: ChannelProofEnvelope {
                role: TransitionProofRole::ChannelStateUpdate,
                backend: ProofBackend::Plonky3,
                proof: vec![3],
            },
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
