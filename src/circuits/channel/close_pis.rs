use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::channel::{ChannelError, ChannelId, ChannelState, CloseIntent, CloseWithdrawal},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
};

// NOTE: the unified `ChannelId` is a single u32 limb (channel-id-only base identity). The P7
// (F-3) layout appends final_state_version (2 limbs, hi/lo) and final_settled_tx_chain (8 limbs)
// to the legacy 67-limb vector, for 77 limbs total. This order is pinned by the P8 Solidity
// `closePIHash` preimage (ChannelSettlementVerifier.sol) — one BE u32 word per limb:
//   channelId(1) | closeNonce(2) | finalEpoch(2) | finalSmallBlockNumber(2) |
//   closeFreezeNonce(2) | finalChannelStateDigest(8) | finalBalanceStateH1(8) |
//   channelFundAmount(8) | channelFundIntmaxStateRoot(8) | burnTxHash(8) |
//   closeWithdrawalDigest(8) | closeIntentDigest(8) | snapshotMediumBlockNumber(2) |
//   finalStateVersion(2) | finalSettledTxChain(8) | memberSetCommitment(8)
//
// F5 SECURITY: `member_set_commitment` (8 limbs, appended at the END so the legacy close-intent
// IMCI vector is byte-for-byte unchanged) = keccak([IMCM, sphincs_pk_hash_0..2]) over the 3
// member SPHINCS+ pubkey hashes the close circuit's signatures verify (slot order). L1
// (`ChannelSettlementManager`) matches it against the channel's registered member set, binding
// the verified signing keys to the registered members (no non-member-key substitution).
pub const CHANNEL_CLOSE_PUBLIC_INPUTS_LEN: usize = 85;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelClosePublicInputs {
    pub channel_id: ChannelId,
    pub close_nonce: u64,
    pub final_epoch: u64,
    pub final_small_block_number: u64,
    pub close_freeze_nonce: u64,
    pub final_channel_state_digest: Bytes32,
    pub final_balance_state_h1: Bytes32,
    pub channel_fund_amount: U256,
    pub channel_fund_intmax_state_root: Bytes32,
    pub burn_tx_hash: Bytes32,
    pub close_withdrawal_digest: Bytes32,
    pub close_intent_digest: Bytes32,
    pub snapshot_medium_block_number: u64,
    /// `state_version` of the final balance state (detail2 §H-4 L1 ordering key). Anchored
    /// in-circuit as the unique version inside the signed H1 preimage.
    pub final_state_version: u64,
    /// `settled_tx_chain` of the final balance state (detail2 §H-2). Matched in-circuit against
    /// the final balance proof's `settled_tx_chain` public input and anchored inside H1.
    pub final_settled_tx_chain: Bytes32,
    /// F5 binding: `keccak([IMCM, sphincs_pk_hash_0..2])` over the 3 members' SPHINCS+ pubkey
    /// hashes (slot order) whose signatures the close circuit verifies. Computed in-circuit from
    /// the verified signing keys and matched on L1 against the channel's registered member set.
    /// Derived by the circuit (`ChannelCloseCircuit::prove`) from the member auth, not by the
    /// close witness alone — `ChannelCloseWitness::to_public_inputs` leaves it zero as a
    /// placeholder.
    pub member_set_commitment: Bytes32,
}

#[derive(Debug, Error)]
pub enum ChannelClosePublicInputsError {
    #[error("invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("invalid field: {0}")]
    InvalidField(String),
}

impl ChannelClosePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.channel_id.to_u64_vec(),
            split_u64(self.close_nonce),
            split_u64(self.final_epoch),
            split_u64(self.final_small_block_number),
            split_u64(self.close_freeze_nonce),
            self.final_channel_state_digest.to_u64_vec(),
            self.final_balance_state_h1.to_u64_vec(),
            self.channel_fund_amount.to_u64_vec(),
            self.channel_fund_intmax_state_root.to_u64_vec(),
            self.burn_tx_hash.to_u64_vec(),
            self.close_withdrawal_digest.to_u64_vec(),
            self.close_intent_digest.to_u64_vec(),
            split_u64(self.snapshot_medium_block_number),
            split_u64(self.final_state_version),
            self.final_settled_tx_chain.to_u64_vec(),
            self.member_set_commitment.to_u64_vec(),
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

        Ok(Self {
            channel_id: ChannelId::from_u64_slice(&values[0..1])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            close_nonce: join_u64(&values[1..3]),
            final_epoch: join_u64(&values[3..5]),
            final_small_block_number: join_u64(&values[5..7]),
            close_freeze_nonce: join_u64(&values[7..9]),
            final_channel_state_digest: Bytes32::from_u64_slice(&values[9..17])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            final_balance_state_h1: Bytes32::from_u64_slice(&values[17..25])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            channel_fund_amount: U256::from_u64_slice(&values[25..33])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            channel_fund_intmax_state_root: Bytes32::from_u64_slice(&values[33..41])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            burn_tx_hash: Bytes32::from_u64_slice(&values[41..49])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            close_withdrawal_digest: Bytes32::from_u64_slice(&values[49..57])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            close_intent_digest: Bytes32::from_u64_slice(&values[57..65])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            snapshot_medium_block_number: join_u64(&values[65..67]),
            final_state_version: join_u64(&values[67..69]),
            final_settled_tx_chain: Bytes32::from_u64_slice(&values[69..77])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
            member_set_commitment: Bytes32::from_u64_slice(&values[77..85])
                .map_err(|e| ChannelClosePublicInputsError::InvalidField(e.to_string()))?,
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

    #[error("close intent mismatch")]
    CloseIntentMismatch,
}

impl ChannelCloseWitness {
    pub fn to_public_inputs(&self) -> Result<ChannelClosePublicInputs, ChannelCloseWitnessError> {
        let expected_intent = CloseIntent::new(
            self.close_intent.close_nonce,
            &self.final_channel_state,
            &self.close_tx,
            self.close_intent.snapshot_medium_block_number,
        )?;

        if expected_intent != self.close_intent {
            return Err(ChannelCloseWitnessError::CloseIntentMismatch);
        }

        Ok(ChannelClosePublicInputs {
            channel_id: self.close_intent.channel_id,
            close_nonce: self.close_intent.close_nonce,
            final_epoch: self.close_intent.final_epoch,
            final_small_block_number: self.close_intent.final_small_block_number,
            close_freeze_nonce: self.close_intent.close_freeze_nonce,
            final_channel_state_digest: self.close_intent.final_channel_state_digest,
            final_balance_state_h1: self.close_intent.final_balance_state_h1,
            channel_fund_amount: self.close_intent.channel_fund_snapshot.amount,
            channel_fund_intmax_state_root: self
                .close_intent
                .channel_fund_snapshot
                .intmax_state_root,
            burn_tx_hash: self.close_intent.burn_tx_hash,
            close_withdrawal_digest: self.close_intent.close_withdrawal_digest,
            close_intent_digest: self.close_intent.signing_digest(),
            snapshot_medium_block_number: self.close_intent.snapshot_medium_block_number,
            final_state_version: self.close_intent.final_state_version,
            final_settled_tx_chain: self.close_intent.final_settled_tx_chain,
            // F5: the member-set commitment is derived from the verified signing keys, which the
            // close witness alone does not carry. `ChannelCloseCircuit::prove`/`fill_witness`
            // computes it from `member_auth` and overrides this placeholder before proving.
            member_set_commitment: Bytes32::default(),
        })
    }
}

fn split_u64(value: u64) -> Vec<u64> {
    vec![value >> 32, value as u32 as u64]
}

fn join_u64(limbs: &[u64]) -> u64 {
    (limbs[0] << 32) | limbs[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{
            balance_state::BalanceState,
            channel::{ChannelFund, ChannelId, ChannelState, MemberSignature},
        },
        ethereum_types::bytes32::Bytes32,
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

    fn sample_state() -> ChannelState {
        ChannelState {
            channel_id: ChannelId::new(3).unwrap(),
            epoch: 8,
            small_block_number: 22,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id: ChannelId::new(3).unwrap(),
                amount: U256::from(77u32),
                intmax_state_root: Bytes32::default(),
            },
            balance_state: BalanceState {
                channel_id: ChannelId::new(3).unwrap(),
                enc_balances: [ciphertext(1), ciphertext(2), ciphertext(3)],
                settled_tx_chain: Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
                state_version: 12,
                pending_adds: [0, 0, 0],
            },
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::from_u32_slice(&[2, 0, 0, 0, 0, 0, 0, 0])
                .unwrap(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                member_slot: 0,
                sphincs_pubkey_hash: pubkey_hash(10),
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
            final_balance_state_h1: state.balance_state.h1(),
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: state.channel_fund.amount,
            zkp: vec![9, 9, 9],
        };
        let close_intent = CloseIntent::new(5, &state, &close_tx, 123).unwrap();
        let witness = ChannelCloseWitness {
            final_channel_state: state,
            close_tx,
            close_intent,
        };

        let mut public_inputs = witness.to_public_inputs().unwrap();
        // F5: the close witness leaves member_set_commitment zero; set a non-default value here so
        // the roundtrip exercises the appended 8 limbs (the circuit fills it from member_auth).
        public_inputs.member_set_commitment =
            Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let limbs = public_inputs.to_u64_vec();
        assert_eq!(
            limbs.len(),
            CHANNEL_CLOSE_PUBLIC_INPUTS_LEN,
            "P8 closePIHash preimage is exactly 85 BE u32 words (77 legacy + 8 memberSetCommitment)"
        );
        assert_eq!(
            &limbs[77..85],
            &public_inputs.member_set_commitment.to_u64_vec()[..],
            "member_set_commitment occupies the final 8 limbs"
        );
        // The P8-pinned tail: snapshotMediumBlockNumber(2) | finalStateVersion(2 hi,lo) |
        // finalSettledTxChain(8).
        assert_eq!(limbs[65], 0, "snapshot_medium_block_number hi limb");
        assert_eq!(limbs[66], 123, "snapshot_medium_block_number lo limb");
        assert_eq!(limbs[67], 0, "final_state_version hi limb");
        assert_eq!(
            limbs[68], 12,
            "final_state_version lo limb (sample state_version)"
        );
        assert_eq!(
            &limbs[69..77],
            &witness
                .final_channel_state
                .balance_state
                .settled_tx_chain
                .to_u64_vec()[..],
            "final_settled_tx_chain limbs"
        );
        let roundtrip = ChannelClosePublicInputs::from_u64_slice(&limbs).unwrap();
        assert_eq!(public_inputs, roundtrip);
    }
}
