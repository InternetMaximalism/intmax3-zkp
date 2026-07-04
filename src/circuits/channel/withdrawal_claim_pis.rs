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
    pub member_pk_g: Bytes32,
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
        if self.member.pk_g != self.claim.member_pk_g
            || self.member.l1_withdrawal_recipient != self.claim.l1_recipient
        {
            return Err(WithdrawalClaimWitnessError::RecipientMismatch);
        }
        // SECURITY (B-2 blocker fix): the nullifier keys on the slot's LEAF-BOUND Regev pk digest
        // (`Bytes32::from(user_pk.poseidon_digest())`), NOT the slot-free `member_pk_g`, so a slot
        // owner cannot grind `member_pk_g` for distinct nullifiers. See
        // `WithdrawalClaim::derive_nullifier`.
        let slot_regev_pk_digest = Bytes32::from(self.user_pk.poseidon_digest());
        let expected_nullifier = WithdrawalClaim::derive_nullifier(
            self.close_intent.signing_digest(),
            slot_regev_pk_digest,
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
        // The claimed ciphertext IS the claimant's slot of the H1-bound balance state. Pad-to-MAX
        // D6 + delegate account: the claimant must be an ACTIVE slot — a co-signing MEMBER
        // (`0..member_count`) OR a DELEGATE (`member_count..member_count+delegate_count`). Both own
        // a real, withdrawable balance ciphertext; only padding slots
        // (`>= member_count+delegate_count`) carry the empty ciphertext and are not withdrawable.
        // SECURITY: H1 (checked above) commits BOTH `member_count` and `delegate_count`, so the
        // active/padding boundary — and thus withdrawal eligibility — is fixed under the members'
        // signed final state. Delegates do NOT co-sign, but their final balance IS member-attested
        // (DLG-2), exactly the trust model the withdrawal inherits.
        if self.member_index >= MAX_CHANNEL_MEMBERS {
            return Err(WithdrawalClaimWitnessError::MemberSlotMismatch(format!(
                "member_index {} out of range (>= MAX_CHANNEL_MEMBERS)",
                self.member_index
            )));
        }
        let active = self.final_balance_state.member_count as usize
            + self.final_balance_state.delegate_count as usize;
        if self.member_index >= active {
            return Err(WithdrawalClaimWitnessError::MemberSlotMismatch(format!(
                "member_index {} is a padding slot (>= member_count+delegate_count {active})",
                self.member_index
            )));
        }
        if self.claim.user_amount_ct != self.final_balance_state.enc_balances[self.member_index] {
            return Err(WithdrawalClaimWitnessError::MemberSlotMismatch(
                "user_amount_ct must equal final_balance_state.enc_balances[member_index]"
                    .to_string(),
            ));
        }
        // SECURITY (B-1b): the exposed recipient MUST be the cosigner-signed per-slot L1 exit
        // address (the leaf field the circuit opens by inclusion). Native mirror of the circuit's
        // leaf-recipient connect — fail-closed BEFORE any proving. Without this, a delegate's
        // payout (no L1 registration under Option B) could be redirected.
        if self.member.l1_withdrawal_recipient
            != self.final_balance_state.recipients[self.member_index]
        {
            return Err(WithdrawalClaimWitnessError::RecipientMismatch);
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
            member_pk_g: self.member.pk_g,
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
            self.member_pk_g.to_u64_vec(),
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
            member_pk_g: Bytes32::from_u64_slice(&values[17..25]).map_err(|e| e.to_string())?,
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
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances(&[ct0.clone(), ct1, ct2]),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[
                Bytes32::from(pk0.poseidon_digest()),
                Bytes32::from(pk1.poseidon_digest()),
                Bytes32::from(pk2.poseidon_digest()),
            ]),
            // B-1b: slot 0 (the claimant) carries the SAME L1 exit address the claim exposes.
            recipients: BalanceState::pad_recipients(&[
                Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
                Address::from_u32_slice(&[21, 22, 23, 24, 25]).unwrap(),
                Address::from_u32_slice(&[31, 32, 33, 34, 35]).unwrap(),
            ]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
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
                pk_g: pubkey_hash(10),
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
            pk_g: pubkey_hash(10),
            member_slot: 0,
            l1_withdrawal_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
        };
        let claim_proof =
            prove_withdraw_claim(RegevSecurityLevel::Test, &pk0, &sk0, &ct0, amount).unwrap();
        let claim = WithdrawalClaim {
            close_intent_digest: close_intent.signing_digest(),
            member_pk_g: member.pk_g,
            l1_recipient: member.l1_withdrawal_recipient,
            user_amount_ct: ct0,
            withdrawal_nullifier: WithdrawalClaim::derive_nullifier(
                close_intent.signing_digest(),
                Bytes32::from(pk0.poseidon_digest()),
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

        // B-1b: a claim whose recipient differs from the cosigner-signed per-slot exit address
        // (recipients[member_index]) is rejected fail-closed (native mirror of the circuit's
        // leaf-recipient binding).
        let mut wrong_recipient = witness.clone();
        let redirected = Address::from_u32_slice(&[9, 9, 9, 9, 9]).unwrap();
        wrong_recipient.member.l1_withdrawal_recipient = redirected;
        wrong_recipient.claim.l1_recipient = redirected;
        assert!(matches!(
            wrong_recipient.to_public_inputs(RegevSecurityLevel::Test),
            Err(WithdrawalClaimWitnessError::RecipientMismatch)
        ));

        // A tampered balance state no longer matches the close intent's H1.
        let mut wrong_state = witness;
        wrong_state.final_balance_state.state_version += 1;
        assert!(matches!(
            wrong_state.to_public_inputs(RegevSecurityLevel::Test),
            Err(WithdrawalClaimWitnessError::FinalBalanceStateMismatch(_))
        ));
    }

    /// Delegate account (Phase 3 / DA4): a DELEGATE slot (`member_count..member_count+
    /// delegate_count`) is an ACTIVE, withdrawable slot. The delegate withdraws its member-attested
    /// final balance via the SAME E-3 WithdrawalClaim a member uses; a padding slot
    /// (`>= member_count+delegate_count`) is still rejected. member_count=2, delegate_count=1
    /// (delegate in slot 2).
    #[test]
    fn delegate_slot_withdrawal_claim_is_accepted_padding_rejected() {
        let mut rng = SmallRng::seed_from_u64(0xDE1E);
        let channel_id = ChannelId::new(4).unwrap();
        let (pk0, _) = channel_keygen(&mut rng); // member 0
        let (pk1, _) = channel_keygen(&mut rng); // member 1
        let (pk_d, sk_d) = channel_keygen(&mut rng); // delegate (slot 2)

        let d_amount = 42u64;
        let (ct0, _) = encrypt_amount(&mut rng, &pk0, 7).unwrap();
        let (ct1, _) = encrypt_amount(&mut rng, &pk1, 9).unwrap();
        let (ct_d, _) = encrypt_amount(&mut rng, &pk_d, d_amount).unwrap();
        let final_balance_state = BalanceState {
            channel_id,
            member_count: 2,
            delegate_count: 1,
            enc_balances: BalanceState::pad_enc_balances(&[ct0, ct1, ct_d.clone()]),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[
                Bytes32::from(pk0.poseidon_digest()),
                Bytes32::from(pk1.poseidon_digest()),
                Bytes32::from(pk_d.poseidon_digest()),
            ]),
            // B-1b: the DELEGATE's (slot 2) leaf-bound exit address is the one the claim exposes
            // — under Option B this is the delegate's ONLY recipient binding.
            recipients: BalanceState::pad_recipients(&[
                Address::from_u32_slice(&[11, 12, 13, 14, 15]).unwrap(),
                Address::from_u32_slice(&[21, 22, 23, 24, 25]).unwrap(),
                Address::from_u32_slice(&[2, 3, 4, 5, 6]).unwrap(),
            ]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
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
                pk_g: pubkey_hash(10),
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

        // The DELEGATE claims its own slot-2 ciphertext.
        let delegate = ChannelMember {
            pk_g: pubkey_hash(30),
            member_slot: 2,
            l1_withdrawal_recipient: Address::from_u32_slice(&[2, 3, 4, 5, 6]).unwrap(),
        };
        let claim_proof =
            prove_withdraw_claim(RegevSecurityLevel::Test, &pk_d, &sk_d, &ct_d, d_amount).unwrap();
        let claim = WithdrawalClaim {
            close_intent_digest: close_intent.signing_digest(),
            member_pk_g: delegate.pk_g,
            l1_recipient: delegate.l1_withdrawal_recipient,
            user_amount_ct: ct_d,
            withdrawal_nullifier: WithdrawalClaim::derive_nullifier(
                close_intent.signing_digest(),
                Bytes32::from(pk_d.poseidon_digest()),
            ),
            claim_proof,
        };
        let witness = WithdrawalClaimWitness {
            close_intent,
            close_tx,
            member: delegate,
            claim,
            final_balance_state,
            member_index: 2, // delegate region (active = member_count + delegate_count = 3)
            user_pk: pk_d,
            amount: d_amount,
        };

        // The delegate's slot-2 withdrawal claim is ACCEPTED (E-3 verifies + slot in active range).
        let pis = witness
            .to_public_inputs(RegevSecurityLevel::Test)
            .expect("delegate slot withdrawal must be accepted");
        let roundtrip = WithdrawalClaimPublicInputs::from_u64_slice(&pis.to_u64_vec()).unwrap();
        assert_eq!(pis, roundtrip);

        // A padding slot (>= member_count + delegate_count = 3) is still rejected as
        // non-withdrawable.
        let mut padding = witness;
        padding.member_index = 3;
        assert!(matches!(
            padding.to_public_inputs(RegevSecurityLevel::Test),
            Err(WithdrawalClaimWitnessError::MemberSlotMismatch(_))
        ));
    }
}
