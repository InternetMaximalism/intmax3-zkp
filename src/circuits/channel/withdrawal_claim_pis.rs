//! Withdrawal-claim verification (detail2 §E-3 / abstract2 §3.5.4).
//!
//! v2 model: the member's withdrawable amount is their slot of the final `BalanceState`.
//! The claim binds to `CloseIntent.final_balance_state_h1` by recomputing `h1()` from the full
//! final balance state, picks the member's ciphertext slot, and verifies the E-3
//! withdrawClaimZKP ("`user_amount_ct` decrypts to the public `amount` under `user_pk`").
//! No co-member cooperation is needed (exit-liveness, abstract2 §4.4); the SIS opening +
//! balance-tree membership path is retired.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::{
        balance_state::BalanceState,
        channel::{ChannelMember, CloseIntent, CloseWithdrawal, WithdrawalClaim},
    },
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    regev::{RegevPk, RegevSecurityLevel, verify_withdraw_claim},
};

// 8 (close intent digest) + 1 (channel id, single u32 limb) + 8 (h1) +
// 8 (member sphincs pubkey hash) + 5 (recipient) + 8 (ct digest) + 8 (nullifier) + 2 (amount).
pub const WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN: usize = 48;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalClaimPublicInputs {
    pub close_intent_digest: Bytes32,
    pub channel_id: crate::common::channel::ChannelId,
    pub final_balance_state_h1: Bytes32,
    pub member_sphincs_pubkey_hash: Bytes32,
    pub recipient: Address,
    pub user_amount_digest: Bytes32,
    pub withdrawal_nullifier: Bytes32,
    /// Public withdrawal amount, proven equal to the plaintext of `user_amount_ct` by the E-3
    /// withdrawClaimZKP.
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
    #[error("withdrawal claim final balance state mismatch: {0}")]
    FinalBalanceStateMismatch(String),
    #[error("withdrawal claim member slot mismatch: {0}")]
    MemberSlotMismatch(String),
    #[error("invalid withdraw claim proof: {0}")]
    InvalidClaimProof(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalClaimWitness {
    pub close_intent: CloseIntent,
    pub close_tx: CloseWithdrawal,
    pub member: ChannelMember,
    pub claim: WithdrawalClaim,
    /// The full final balance state — bound to the close intent via `h1()` recomputation.
    pub final_balance_state: BalanceState,
    /// The claiming member's slot index in `enc_balances` (member slot order).
    pub member_index: usize,
    /// The claiming member's Regev public key (E-3 statement input). Its authenticity is
    /// anchored by `ChannelRecord.regev_pk_root`, which the L1 close game checks separately.
    pub user_pk: RegevPk,
    /// Public withdrawal amount claimed by the member.
    pub amount: u64,
}

impl WithdrawalClaimWitness {
    pub fn to_public_inputs(
        &self,
        level: RegevSecurityLevel,
    ) -> Result<WithdrawalClaimPublicInputs, WithdrawalClaimWitnessError> {
        if self.claim.close_intent_digest != self.close_intent.signing_digest() {
            return Err(WithdrawalClaimWitnessError::CloseIntentMismatch);
        }
        if self.close_tx.signing_digest() != self.close_intent.close_withdrawal_digest
            || self.close_tx.final_balance_state_h1 != self.close_intent.final_balance_state_h1
            || self.close_tx.channel_id != self.close_intent.channel_id
        {
            return Err(WithdrawalClaimWitnessError::CloseWithdrawalMismatch);
        }
        if self.member.sphincs_pubkey_hash != self.claim.member_sphincs_pubkey_hash
            || self.member.l1_withdrawal_recipient != self.claim.l1_recipient
        {
            return Err(WithdrawalClaimWitnessError::RecipientMismatch);
        }
        let expected_nullifier = WithdrawalClaim::derive_nullifier(
            self.close_intent.signing_digest(),
            self.member.sphincs_pubkey_hash,
        );
        if expected_nullifier != self.claim.withdrawal_nullifier {
            return Err(WithdrawalClaimWitnessError::NullifierMismatch);
        }

        // Bind the witness balance state to the close intent: recomputed H1 must match.
        self.final_balance_state.validate().map_err(|err| {
            WithdrawalClaimWitnessError::FinalBalanceStateMismatch(err.to_string())
        })?;
        if self.final_balance_state.h1() != self.close_intent.final_balance_state_h1 {
            return Err(WithdrawalClaimWitnessError::FinalBalanceStateMismatch(
                "final_balance_state.h1() != close_intent.final_balance_state_h1".to_string(),
            ));
        }
        if self.final_balance_state.channel_id != self.close_intent.channel_id {
            return Err(WithdrawalClaimWitnessError::FinalBalanceStateMismatch(
                "final balance state channel_id mismatch".to_string(),
            ));
        }
        // The claimed ciphertext IS the member's slot of the H1-bound balance state. Pad-to-MAX
        // D6: the claiming member must be an ACTIVE slot (`< member_count`); padding slots carry
        // the empty ciphertext and are not withdrawable.
        if self.member_index >= MAX_CHANNEL_MEMBERS {
            return Err(WithdrawalClaimWitnessError::MemberSlotMismatch(format!(
                "member_index {} out of range (>= MAX_CHANNEL_MEMBERS)",
                self.member_index
            )));
        }
        if self.member_index >= self.final_balance_state.member_count as usize {
            return Err(WithdrawalClaimWitnessError::MemberSlotMismatch(format!(
                "member_index {} is a padding slot (>= member_count {})",
                self.member_index, self.final_balance_state.member_count
            )));
        }
        if self.claim.user_amount_ct != self.final_balance_state.enc_balances[self.member_index] {
            return Err(WithdrawalClaimWitnessError::MemberSlotMismatch(
                "user_amount_ct must equal final_balance_state.enc_balances[member_index]"
                    .to_string(),
            ));
        }

        // E-3 withdrawClaimZKP: user_amount_ct decrypts to the public amount under user_pk.
        verify_withdraw_claim(
            level,
            &self.user_pk,
            &self.claim.user_amount_ct,
            self.amount,
            &self.claim.claim_proof,
        )
        .map_err(|err| WithdrawalClaimWitnessError::InvalidClaimProof(err.to_string()))?;

        Ok(WithdrawalClaimPublicInputs {
            close_intent_digest: self.close_intent.signing_digest(),
            channel_id: self.close_intent.channel_id,
            final_balance_state_h1: self.close_intent.final_balance_state_h1,
            member_sphincs_pubkey_hash: self.member.sphincs_pubkey_hash,
            recipient: self.member.l1_withdrawal_recipient,
            user_amount_digest: self.claim.user_amount_ct.digest(),
            withdrawal_nullifier: self.claim.withdrawal_nullifier,
            amount: self.amount,
        })
    }
}

impl WithdrawalClaimPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.close_intent_digest.to_u64_vec(),
            self.channel_id.to_u64_vec(),
            self.final_balance_state_h1.to_u64_vec(),
            self.member_sphincs_pubkey_hash.to_u64_vec(),
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
            close_intent_digest: Bytes32::from_u64_slice(&values[0..8])
                .map_err(|e| e.to_string())?,
            channel_id: crate::common::channel::ChannelId::from_u64_slice(&values[8..9])
                .map_err(|e| e.to_string())?,
            final_balance_state_h1: Bytes32::from_u64_slice(&values[9..17])
                .map_err(|e| e.to_string())?,
            member_sphincs_pubkey_hash: Bytes32::from_u64_slice(&values[17..25])
                .map_err(|e| e.to_string())?,
            recipient: Address::from_u64_slice(&values[25..30]).map_err(|e| e.to_string())?,
            user_amount_digest: Bytes32::from_u64_slice(&values[30..38])
                .map_err(|e| e.to_string())?,
            withdrawal_nullifier: Bytes32::from_u64_slice(&values[38..46])
                .map_err(|e| e.to_string())?,
            amount: join_u64(&values[46..48]),
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
        common::channel::{ChannelFund, ChannelId, ChannelState, MemberSignature},
        ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
        regev::{channel_keygen, encrypt_amount, prove_withdraw_claim},
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

    #[test]
    fn withdrawal_claim_verifies_e3_proof_and_roundtrips() {
        let mut rng = SmallRng::seed_from_u64(77);
        let channel_id = ChannelId::new(3).unwrap();
        let (pk0, sk0) = channel_keygen(&mut rng);
        let (pk1, _) = channel_keygen(&mut rng);
        let (pk2, _) = channel_keygen(&mut rng);

        let amount = 77u64;
        let (ct0, _) = encrypt_amount(&mut rng, &pk0, amount).unwrap();
        let (ct1, _) = encrypt_amount(&mut rng, &pk1, 5).unwrap();
        let (ct2, _) = encrypt_amount(&mut rng, &pk2, 11).unwrap();
        let final_balance_state = BalanceState {
            channel_id,
            member_count: 3,
            enc_balances: BalanceState::pad_enc_balances(&[ct0.clone(), ct1, ct2]),
            settled_tx_chain: Bytes32::default(),
            state_version: 6,
            pending_adds: BalanceState::pad_pending_adds(&[0, 0, 0]),
        };

        let state = ChannelState {
            channel_id,
            epoch: 8,
            small_block_number: 5,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id,
                amount: U256::from(93u32),
                intmax_state_root: Bytes32::default(),
            },
            balance_state: final_balance_state.clone(),
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                member_slot: 0,
                sphincs_pubkey_hash: pubkey_hash(10),
                signature: vec![1],
            }],
        }
        .with_computed_digest();
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_balance_state_h1: state.balance_state.h1(),
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: state.channel_fund.amount,
            zkp: vec![9],
        };
        let close_intent = CloseIntent::new(5, &state, &close_tx, 123).unwrap();

        let member = ChannelMember {
            sphincs_pubkey_hash: pubkey_hash(10),
            member_slot: 0,
            l1_withdrawal_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
        };
        let claim_proof =
            prove_withdraw_claim(RegevSecurityLevel::Test, &pk0, &sk0, &ct0, amount).unwrap();
        let claim = WithdrawalClaim {
            close_intent_digest: close_intent.signing_digest(),
            member_sphincs_pubkey_hash: member.sphincs_pubkey_hash,
            l1_recipient: member.l1_withdrawal_recipient,
            user_amount_ct: ct0,
            withdrawal_nullifier: WithdrawalClaim::derive_nullifier(
                close_intent.signing_digest(),
                member.sphincs_pubkey_hash,
            ),
            claim_proof,
        };
        let witness = WithdrawalClaimWitness {
            close_intent,
            close_tx,
            member,
            claim,
            final_balance_state,
            member_index: 0,
            user_pk: pk0,
            amount,
        };

        let pis = witness.to_public_inputs(RegevSecurityLevel::Test).unwrap();
        let roundtrip = WithdrawalClaimPublicInputs::from_u64_slice(&pis.to_u64_vec()).unwrap();
        assert_eq!(pis, roundtrip);

        // A wrong public amount must fail the E-3 verification.
        let mut wrong = witness.clone();
        wrong.amount += 1;
        assert!(matches!(
            wrong.to_public_inputs(RegevSecurityLevel::Test),
            Err(WithdrawalClaimWitnessError::InvalidClaimProof(_))
        ));

        // Claiming a slot that is not the member's own must fail the slot binding.
        let mut wrong_slot = witness.clone();
        wrong_slot.member_index = 1;
        assert!(matches!(
            wrong_slot.to_public_inputs(RegevSecurityLevel::Test),
            Err(WithdrawalClaimWitnessError::MemberSlotMismatch(_))
        ));

        // A tampered balance state no longer matches the close intent's H1.
        let mut wrong_state = witness;
        wrong_state.final_balance_state.state_version += 1;
        assert!(matches!(
            wrong_state.to_public_inputs(RegevSecurityLevel::Test),
            Err(WithdrawalClaimWitnessError::FinalBalanceStateMismatch(_))
        ));
    }
}
