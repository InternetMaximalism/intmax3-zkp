//! Post-close incoming claim (abstract2 §3.5.5 `claimLateTx`, detail2 §C-8).
//!
//! v2 model: the receiver's late inbound delta is a Regev ciphertext inside the signed
//! `InterChannelTx`; the claim proves it decrypts to the public amount via the E-3
//! withdrawClaimZKP (the SIS opening hand-off is retired).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::channel::{InterChannelTx, PostCloseIncomingClaim},
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    regev::{RegevPk, RegevSecurityLevel, verify_withdraw_claim},
};

// 8 (close intent digest) + 1 (channel id, single u32 limb) + 8 (tx hash) +
// 8 (receiver sphincs pubkey hash) + 5 (recipient) + 8 (nullifier) + 2 (amount).
pub const POST_CLOSE_CLAIM_PUBLIC_INPUTS_LEN: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostCloseClaimPublicInputs {
    pub close_intent_digest: Bytes32,
    pub receiver_channel_id: crate::common::channel::ChannelId,
    pub incoming_tx_hash: Bytes32,
    pub receiver_pk_g: Bytes32,
    pub recipient: Address,
    pub shared_native_nullifier: Bytes32,
    /// Public claim amount, proven equal to the plaintext of `receiver_amount` by the E-3 proof.
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
    #[error("invalid post-close claim proof: {0}")]
    InvalidClaimProof(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostCloseClaimWitness {
    pub close_intent_digest: Bytes32,
    pub closed_channel_id: crate::common::channel::ChannelId,
    pub source_tx: InterChannelTx,
    pub claim: PostCloseIncomingClaim,
    /// The receiver's Regev public key (E-3 statement input; anchored by the receiver channel's
    /// `regev_pk_root`).
    pub receiver_pk: RegevPk,
    /// Public claim amount.
    pub amount: u64,
}

impl PostCloseClaimWitness {
    pub fn to_public_inputs(
        &self,
        level: RegevSecurityLevel,
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

        // The claimed ciphertext must be the receiver's delta of the signed source tx.
        let matching_delta = self.source_tx.receiver_deltas.iter().any(|delta| {
            delta.receiver_pk_g == self.claim.receiver_pk_g
                && delta.amount == self.claim.receiver_amount
        });
        if !matching_delta {
            return Err(PostCloseClaimWitnessError::ReceiverDeltaMismatch);
        }

        // E-3 withdrawClaimZKP: receiver_amount decrypts to the public amount under receiver_pk.
        verify_withdraw_claim(
            level,
            &self.receiver_pk,
            &self.claim.receiver_amount,
            self.amount,
            &self.claim.claim_proof,
        )
        .map_err(|err| PostCloseClaimWitnessError::InvalidClaimProof(err.to_string()))?;

        Ok(PostCloseClaimPublicInputs {
            close_intent_digest: self.close_intent_digest,
            receiver_channel_id: self.closed_channel_id,
            incoming_tx_hash: self.source_tx.tx_hash,
            receiver_pk_g: self.claim.receiver_pk_g,
            recipient: self.claim.l1_recipient,
            shared_native_nullifier: self.claim.shared_native_nullifier,
            amount: self.amount,
        })
    }
}

impl PostCloseClaimPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.close_intent_digest.to_u64_vec(),
            self.receiver_channel_id.to_u64_vec(),
            self.incoming_tx_hash.to_u64_vec(),
            self.receiver_pk_g.to_u64_vec(),
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
            close_intent_digest: Bytes32::from_u64_slice(&values[0..8])
                .map_err(|e| e.to_string())?,
            receiver_channel_id: crate::common::channel::ChannelId::from_u64_slice(&values[8..9])
                .map_err(|e| e.to_string())?,
            incoming_tx_hash: Bytes32::from_u64_slice(&values[9..17]).map_err(|e| e.to_string())?,
            receiver_pk_g: Bytes32::from_u64_slice(&values[17..25])
                .map_err(|e| e.to_string())?,
            recipient: Address::from_u64_slice(&values[25..30]).map_err(|e| e.to_string())?,
            shared_native_nullifier: Bytes32::from_u64_slice(&values[30..38])
                .map_err(|e| e.to_string())?,
            amount: join_u64(&values[38..40]),
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
    use rand010::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::{
        common::channel::{
            ChannelId, ChannelProofEnvelope, InterChannelTx, MerkleInclusionProof, ProofBackend,
            ReceiverBalanceDelta, SignedSmallBlock, SmallBlockRootMessage, TransitionProofRole,
        },
        ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
        regev::{
            REGEV_N, REGEV_Q, RegevCiphertext, channel_keygen, encrypt_amount, prove_withdraw_claim,
        },
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

    #[test]
    fn post_close_claim_verifies_e3_proof_and_roundtrips() {
        let mut rng = SmallRng::seed_from_u64(88);
        let (receiver_pk, receiver_sk) = channel_keygen(&mut rng);
        let amount = 21u64;
        let (delta_ct, _) = encrypt_amount(&mut rng, &receiver_pk, amount).unwrap();

        let receiver_pk_g = pubkey_hash(11);
        let source_tx = InterChannelTx {
            tx_inclusion_proof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::default(),
            },
            signed_small_block: SignedSmallBlock {
                message: SmallBlockRootMessage {
                    channel_id: ChannelId::new(5).unwrap(),
                    bp_member_slot: 0,
                    bp_pk_g: pubkey_hash(10),
                    small_block_number: 1,
                    prev_small_block_root: Bytes32::default(),
                    tx_tree_root: Bytes32::from_u32_slice(&[4, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
                    state_commitment_root: Bytes32::default(),
                    medium_epoch_hint: 3,
                    close_freeze_nonce: 0,
                },
                signatures: vec![],
                aggregated_signature_proof: vec![1],
                medium_block_number: 3,
                confirmation_proof: vec![2],
            },
            sender_delta_ct: ciphertext(1),
            source_channel_id: ChannelId::new(5).unwrap(),
            destination_channel_id: ChannelId::new(7).unwrap(),
            source_pk_g: pubkey_hash(10),
            seal: Bytes32::default(),
            tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![1, 2],
            receiver_deltas: vec![ReceiverBalanceDelta {
                receiver_pk_g,
                amount: delta_ct.clone(),
            }],
            channel_update_zkp: ChannelProofEnvelope {
                role: TransitionProofRole::ChannelStateUpdate,
                backend: ProofBackend::Plonky3,
                proof: vec![3],
            },
            transport_proof: vec![5],
        };
        let claim_proof = prove_withdraw_claim(
            RegevSecurityLevel::Test,
            &receiver_pk,
            &receiver_sk,
            &delta_ct,
            amount,
        )
        .unwrap();
        let claim = PostCloseIncomingClaim {
            close_intent_digest: Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            incoming_tx_hash: source_tx.tx_hash,
            receiver_pk_g,
            l1_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
            receiver_amount: delta_ct,
            shared_native_nullifier: Bytes32::from_u32_slice(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            recipient_memo: vec![5, 6],
            claim_proof,
        };
        let witness = PostCloseClaimWitness {
            close_intent_digest: claim.close_intent_digest,
            closed_channel_id: ChannelId::new(7).unwrap(),
            source_tx,
            claim,
            receiver_pk,
            amount,
        };

        let public_inputs = witness.to_public_inputs(RegevSecurityLevel::Test).unwrap();
        let roundtrip =
            PostCloseClaimPublicInputs::from_u64_slice(&public_inputs.to_u64_vec()).unwrap();
        assert_eq!(public_inputs, roundtrip);

        // A wrong public amount must fail the E-3 verification.
        let mut wrong = witness;
        wrong.amount += 1;
        assert!(matches!(
            wrong.to_public_inputs(RegevSecurityLevel::Test),
            Err(PostCloseClaimWitnessError::InvalidClaimProof(_))
        ));
    }
}
