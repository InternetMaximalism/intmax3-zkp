use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    circuits::channel::state_update_verifier::{LatticeBindingVerifier, LatticeProofPurpose},
    common::channel::{
        merkle_root_from_proof, user_fund_leaf_digest, ChannelMember, CloseIntent, CloseWithdrawal,
        LatticeOpening, MerkleInclusionProof, WithdrawalClaim,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    lattice::proof_adapter::RealLatticeBindingVerifier,
};

pub const WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN: usize = 44;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalClaimPublicInputs {
    pub close_intent_digest: Bytes32,
    pub channel_id: crate::common::channel::ChannelId,
    pub final_channel_balance_root: Bytes32,
    pub user_id: crate::common::channel::UserId,
    pub recipient: Address,
    pub user_amount_digest: Bytes32,
    pub withdrawal_nullifier: Bytes32,
    pub amount: u64,
}

#[derive(Debug, Error)]
pub enum WithdrawalClaimWitnessError {
    #[error("withdrawal claim close intent mismatch")]
    CloseIntentMismatch,
    #[error("withdrawal claim close withdrawal mismatch")]
    CloseWithdrawalMismatch,
    #[error("withdrawal claim recipient mismatch")]
    RecipientMismatch,
    #[error("withdrawal claim nullifier mismatch")]
    NullifierMismatch,
    #[error("withdrawal claim merkle root mismatch")]
    MerkleRootMismatch,
    #[error("invalid lattice opening proof: {0}")]
    InvalidOpeningProof(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalClaimWitness {
    pub close_intent: CloseIntent,
    pub close_tx: CloseWithdrawal,
    pub member: ChannelMember,
    pub claim: WithdrawalClaim,
    pub opening: LatticeOpening,
    pub membership_proof: MerkleInclusionProof,
}

impl WithdrawalClaimWitness {
    pub fn to_public_inputs(
        &self,
    ) -> Result<WithdrawalClaimPublicInputs, WithdrawalClaimWitnessError> {
        if self.claim.close_intent_digest != self.close_intent.signing_digest() {
            return Err(WithdrawalClaimWitnessError::CloseIntentMismatch);
        }
        if self.close_tx.signing_digest() != self.close_intent.close_withdrawal_digest
            || self.close_tx.final_channel_balance_root != self.close_intent.final_channel_balance_root
            || self.close_tx.channel_id != self.close_intent.channel_id
        {
            return Err(WithdrawalClaimWitnessError::CloseWithdrawalMismatch);
        }
        if self.member.user_id != self.claim.user_id
            || self.member.l1_withdrawal_recipient != self.claim.l1_recipient
        {
            return Err(WithdrawalClaimWitnessError::RecipientMismatch);
        }
        let expected_nullifier =
            WithdrawalClaim::derive_nullifier(self.close_intent.signing_digest(), self.member.user_id);
        if expected_nullifier != self.claim.withdrawal_nullifier {
            return Err(WithdrawalClaimWitnessError::NullifierMismatch);
        }

        let lattice_verifier = RealLatticeBindingVerifier::default();
        lattice_verifier
            .verify(
                &self.claim.user_amount,
                &self.opening,
                LatticeProofPurpose::BalanceOpening,
            )
            .map_err(|err| WithdrawalClaimWitnessError::InvalidOpeningProof(err.to_string()))?;

        let leaf = user_fund_leaf_digest(
            self.close_intent.channel_id,
            self.member.user_id,
            &self.claim.user_amount,
        );
        let root = merkle_root_from_proof(leaf, &self.membership_proof);
        if root != self.close_intent.final_channel_balance_root {
            return Err(WithdrawalClaimWitnessError::MerkleRootMismatch);
        }

        Ok(WithdrawalClaimPublicInputs {
            close_intent_digest: self.close_intent.signing_digest(),
            channel_id: self.close_intent.channel_id,
            final_channel_balance_root: self.close_intent.final_channel_balance_root,
            user_id: self.member.user_id,
            recipient: self.member.l1_withdrawal_recipient,
            user_amount_digest: self.claim.user_amount.digest(),
            withdrawal_nullifier: self.claim.withdrawal_nullifier,
            amount: self.opening.amount,
        })
    }
}

impl WithdrawalClaimPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.close_intent_digest.to_u64_vec(),
            self.channel_id.to_u64_vec(),
            self.final_channel_balance_root.to_u64_vec(),
            self.user_id.to_u64_vec(),
            self.recipient.to_u64_vec(),
            self.user_amount_digest.to_u64_vec(),
            self.withdrawal_nullifier.to_u64_vec(),
            split_u64(self.amount),
        ]
        .concat()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, String> {
        if values.len() != WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN {
            return Err(format!(
                "invalid withdrawal-claim public input length: expected {WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN}, got {}",
                values.len()
            ));
        }

        Ok(Self {
            close_intent_digest: Bytes32::from_u64_slice(&values[0..8]).map_err(|e| e.to_string())?,
            channel_id: crate::common::channel::ChannelId::from_u64_slice(&values[8..10])
                .map_err(|e| e.to_string())?,
            final_channel_balance_root: Bytes32::from_u64_slice(&values[10..18]).map_err(|e| e.to_string())?,
            user_id: crate::common::channel::UserId::from_u64_slice(&values[18..21]).map_err(|e| e.to_string())?,
            recipient: Address::from_u64_slice(&values[21..26]).map_err(|e| e.to_string())?,
            user_amount_digest: Bytes32::from_u64_slice(&values[26..34]).map_err(|e| e.to_string())?,
            withdrawal_nullifier: Bytes32::from_u64_slice(&values[34..42]).map_err(|e| e.to_string())?,
            amount: join_u64(&values[42..44]),
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
        common::channel::{ChannelFund, ChannelId, ChannelState, CloseIntent, CloseWithdrawal, KeyId, MemberSignature, UserId},
        ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
        lattice::proof_adapter::{
            LatticeRandomnessArray, compute_commitment_from_opening, default_lattice_systems,
            prove_opening,
        },
    };

    fn randomness(seed: i64) -> LatticeRandomnessArray {
        let mut out = [0i64; crate::lattice::proof_adapter::N];
        for (idx, slot) in out.iter_mut().enumerate() {
            *slot = if idx % 2 == 0 { seed } else { -seed };
        }
        out
    }

    #[test]
    fn withdrawal_claim_public_inputs_roundtrip() {
        let state = ChannelState {
            channel_id: ChannelId::new(3).unwrap(),
            epoch: 8,
            small_block_number: 5,
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
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_channel_balance_root: Bytes32::default(),
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: state.channel_fund.amount,
            zkp: vec![9],
        };
        let amount = 77u64;
        let r = randomness(1);
        let opening = prove_opening(
            default_lattice_systems(),
            LatticeProofPurpose::BalanceOpening,
            amount,
            &r,
        )
        .unwrap();
        let commitment = compute_commitment_from_opening(amount, &r);
        let member = ChannelMember {
            key_id: KeyId::new(10).unwrap(),
            user_id: UserId::from_parts(ChannelId::new(3).unwrap(), KeyId::new(10).unwrap()),
            l1_withdrawal_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
        };
        let leaf = user_fund_leaf_digest(state.channel_id, member.user_id, &commitment);
        let close_tx = CloseWithdrawal {
            final_channel_balance_root: leaf,
            ..close_tx
        };
        let close_intent =
            CloseIntent::new(5, &ChannelState { channel_balance_root: leaf, ..state }, &close_tx, 123)
                .unwrap();
        let claim = WithdrawalClaim {
            close_intent_digest: close_intent.signing_digest(),
            user_id: member.user_id,
            l1_recipient: member.l1_withdrawal_recipient,
            user_amount: commitment,
            withdrawal_nullifier: WithdrawalClaim::derive_nullifier(
                close_intent.signing_digest(),
                member.user_id,
            ),
            claim_proof: vec![1, 2, 3],
        };
        let witness = WithdrawalClaimWitness {
            close_intent,
            close_tx,
            member,
            claim,
            opening,
            membership_proof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::default(),
            },
        };

        let pis = witness.to_public_inputs().unwrap();
        let roundtrip = WithdrawalClaimPublicInputs::from_u64_slice(&pis.to_u64_vec()).unwrap();
        assert_eq!(pis, roundtrip);
    }
}
