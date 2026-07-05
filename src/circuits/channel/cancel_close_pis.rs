use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::channel::{ChannelId, ChannelState, CloseIntent},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
};

// CORRECTED cancelClose statement (Phase C1, threat model
// `tasks/phase-c-challenge-stubs-threat-model.md` "CORRECTED cancelClose statement"):
//
//   Prove the registered channel members N-of-N signed a channel state (IMCH) at a
//   `state_version` STRICTLY GREATER than the pending close's `final_state_version` ⇒ the members
//   agreed to keep operating ⇒ the pending close froze a stale state ⇒ cancel.
//
// This REPLACES the legacy 41-limb revived-tx layout (revived_small_block_root /
// revived_inter_channel_tx_digest / revived_tx_hash / revived_seal), which Finding D showed was
// forgeable (no member binding) and Finding B showed had an unsound staleness predicate
// (bare block-number succession ≠ stale close). The new layout binds:
//
//  - `member_set_commitment` (8) — keccak over the revived state's signing member pk_g set (EXACTLY
//    as `close_circuit.rs` computes/exposes it). L1 (`ChannelSettlementManager`) matches it against
//    `registeredMemberSetCommitment()` (the SAME mechanism the close path uses), so a third party
//    cannot forge a cancel with their own keys (Finding D fix).
//  - `revived_state_version` (2, hi/lo) — proven `> close_intent.final_state_version` in-circuit
//    (Finding B fix). The version operand is anchored inside the revived IMCH (via H1), and the
//    close-side operand is anchored inside the recomputed `close_intent_digest`, so neither side
//    can be tampered independently of the digests the manager binds.
//  - `revived_channel_state_digest` (8) — the IMCH digest the members signed (the revived state).
//  - `close_intent_digest` (8) — binds the pending close being cancelled (matched on L1 against
//    `pendingClose.closeIntentDigest`). The circuit recomputes the FULL IMCI preimage in-circuit,
//    so `close_intent.final_state_version` and `close_intent.close_freeze_nonce` used in the
//    comparison / era fence are the SAME wires hashed into this digest.
//
// Limb order (pinned by the Solidity `_expectedCancelCloseLimbs`, one BE u32 word per limb):
//   channelId(1) | closeIntentDigest(8) | memberSetCommitment(8) | revivedStateVersion(2 hi,lo) |
//   revivedChannelStateDigest(8)
pub const CANCEL_CLOSE_PUBLIC_INPUTS_LEN: usize = 27;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelClosePublicInputs {
    /// The channel whose pending close is being cancelled. Single u32 limb (channel-id-only base
    /// identity), equal to `close_intent.channel_id` and to the revived state's `channel_id`
    /// (both anchored in-circuit via the recomputed digests).
    pub channel_id: ChannelId,
    /// IMCI digest of the pending close being cancelled. Recomputed in-circuit from the full
    /// `CloseIntent` preimage; matched on L1 against `pendingClose.closeIntentDigest`.
    pub close_intent_digest: Bytes32,
    /// `keccak([IMCM, member_count, pk_g_0..pk_g_{MAX-1}])` over the revived state's signing
    /// members (slot order, padding zeroed) — byte-identical to the close circuit's
    /// `member_set_commitment`. L1 matches it against the channel's registered member set
    /// (Finding D fix). Derived by the circuit from `member_auth`, not by the witness alone —
    /// `CancelCloseWitness::to_public_inputs` leaves it zero as a placeholder.
    pub member_set_commitment: Bytes32,
    /// `state_version` of the revived channel state. Proven `> close_intent.final_state_version`
    /// in-circuit (Finding B fix). Anchored inside the revived IMCH (via the recomputed H1).
    pub revived_state_version: u64,
    /// IMCH digest of the revived channel state the members N-of-N signed. Recomputed in-circuit
    /// (`ChannelState::signing_digest`) and bound to the verified member signatures.
    pub revived_channel_state_digest: Bytes32,
}

#[derive(Debug, Error)]
pub enum CancelCloseWitnessError {
    #[error("revived state channel does not match close channel")]
    ChannelIdMismatch,
    #[error(
        "revived state version {revived} is not strictly greater than close final_state_version {close}"
    )]
    StaleRevivedState { revived: u64, close: u64 },
    #[error(
        "era fence violated: revived close_freeze_nonce {revived} + 1 != close close_freeze_nonce {close}"
    )]
    EraFenceMismatch { revived: u64, close: u64 },
    #[error("revived channel state digest mismatch (stored digest != recomputed signing digest)")]
    RevivedDigestMismatch,
}

/// Witness for the corrected cancelClose statement. The revived `ChannelState` (the state the
/// members kept operating at a higher version) plus the `CloseIntent` being cancelled. The member
/// authentication (per-slot `pk_g`) and the aggregated sign-zkp proof live in the circuit's
/// `CancelCloseFullWitness` (mirroring `ChannelCloseFullWitness`), not here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelCloseWitness {
    pub revived_state: ChannelState,
    pub close_intent: CloseIntent,
}

impl CancelCloseWitness {
    pub fn to_public_inputs(&self) -> Result<CancelClosePublicInputs, CancelCloseWitnessError> {
        // Same channel (anchored in-circuit via the recomputed digests; checked natively here for
        // an early, structured error).
        if self.revived_state.channel_id != self.close_intent.channel_id {
            return Err(CancelCloseWitnessError::ChannelIdMismatch);
        }
        // The revived state's stored digest must equal its signing digest (the in-circuit recompute
        // is authoritative; this native check surfaces a malformed witness early).
        if self.revived_state.digest != self.revived_state.signing_digest() {
            return Err(CancelCloseWitnessError::RevivedDigestMismatch);
        }
        let revived_version = self.revived_state.balance_state.state_version;
        // Finding B (staleness): the revived state must post-date the close snapshot STRICTLY.
        if !(revived_version > self.close_intent.final_state_version) {
            return Err(CancelCloseWitnessError::StaleRevivedState {
                revived: revived_version,
                close: self.close_intent.final_state_version,
            });
        }
        // Finding C (era fence): the revived state belongs to the SAME operating era as the state
        // that was closed. `CloseIntent::new` advances `close_freeze_nonce` by +1 off the closing
        // state, so a continued-operation state from the pre-close era satisfies
        // `revived.close_freeze_nonce + 1 == close.close_freeze_nonce`. Do NOT relax to `>=`.
        if self.revived_state.close_freeze_nonce + 1 != self.close_intent.close_freeze_nonce {
            return Err(CancelCloseWitnessError::EraFenceMismatch {
                revived: self.revived_state.close_freeze_nonce,
                close: self.close_intent.close_freeze_nonce,
            });
        }
        Ok(CancelClosePublicInputs {
            channel_id: self.close_intent.channel_id,
            close_intent_digest: self.close_intent.signing_digest(),
            // Filled by `CancelCloseCircuit::prove` from `member_auth`; placeholder here.
            member_set_commitment: Bytes32::default(),
            revived_state_version: revived_version,
            revived_channel_state_digest: self.revived_state.signing_digest(),
        })
    }
}

fn split_u64(value: u64) -> Vec<u64> {
    vec![value >> 32, value as u32 as u64]
}

fn join_u64(limbs: &[u64]) -> u64 {
    (limbs[0] << 32) | limbs[1]
}

impl CancelClosePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.channel_id.to_u64_vec(),
            self.close_intent_digest.to_u64_vec(),
            self.member_set_commitment.to_u64_vec(),
            split_u64(self.revived_state_version),
            self.revived_channel_state_digest.to_u64_vec(),
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
            channel_id: ChannelId::from_u64_slice(&values[0..1]).map_err(|e| e.to_string())?,
            close_intent_digest: Bytes32::from_u64_slice(&values[1..9])
                .map_err(|e| e.to_string())?,
            member_set_commitment: Bytes32::from_u64_slice(&values[9..17])
                .map_err(|e| e.to_string())?,
            revived_state_version: join_u64(&values[17..19]),
            revived_channel_state_digest: Bytes32::from_u64_slice(&values[19..27])
                .map_err(|e| e.to_string())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{
            balance_state::BalanceState,
            channel::{ChannelFund, ChannelId, ChannelState, CloseWithdrawal, MemberSignature},
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

    /// A channel state at `close_freeze_nonce`/`state_version`, with `member_count` active members.
    fn sample_state(close_freeze_nonce: u64, state_version: u64) -> ChannelState {
        ChannelState {
            channel_id: ChannelId::new(3).unwrap(),
            epoch: 8,
            small_block_number: 4,
            close_freeze_nonce,
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
                regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
                // B-1b: nonzero per-active-slot exit addresses (validate() rejects zero actives).
                recipients: BalanceState::pad_recipients(
                    &(0..3)
                        .map(|i| {
                            crate::ethereum_types::address::Address::from_u32_slice(
                                &[0x7E57_0000u32 + i; 5],
                            )
                            .unwrap()
                        })
                        .collect::<Vec<_>>(),
                ),
                settled_tx_chain: Bytes32::default(),
                settled_tx_accumulator_root: Bytes32::default(),
                state_version,
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
        .with_computed_digest()
    }

    /// A close intent built off `closing_state` (its nonce advances +1).
    fn close_intent_for(closing_state: &ChannelState) -> CloseIntent {
        let close_withdrawal = CloseWithdrawal {
            channel_id: closing_state.channel_id,
            final_channel_state_digest: closing_state.digest,
            final_balance_state_h1: closing_state.balance_state.h1(),
            intmax_state_root: closing_state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: closing_state.channel_fund.amount,
            zkp: vec![7],
        };
        CloseIntent::new(5, closing_state, &close_withdrawal, 123).unwrap()
    }

    #[test]
    fn cancel_close_public_inputs_roundtrip() {
        // Closing state at era nonce 0, version 7. Revived state at the SAME era (nonce 0) but a
        // higher version (9) — members kept operating.
        let closing_state = sample_state(0, 7);
        let close_intent = close_intent_for(&closing_state);
        let revived_state = sample_state(0, 9);
        let witness = CancelCloseWitness {
            revived_state,
            close_intent,
        };

        let mut public_inputs = witness.to_public_inputs().unwrap();
        // The witness leaves member_set_commitment zero; set a non-default value so the roundtrip
        // exercises the 8 limbs (the circuit fills it from member_auth).
        public_inputs.member_set_commitment =
            Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let limbs = public_inputs.to_u64_vec();
        assert_eq!(
            limbs.len(),
            CANCEL_CLOSE_PUBLIC_INPUTS_LEN,
            "cancel PI is exactly 27 BE u32 words (1 channelId + 8 closeIntentDigest + 8 \
             memberSetCommitment + 2 revivedStateVersion + 8 revivedChannelStateDigest)"
        );
        // Pinned limb offsets (mirrored by Solidity `_expectedCancelCloseLimbs`).
        assert_eq!(&limbs[0..1], &public_inputs.channel_id.to_u64_vec()[..]);
        assert_eq!(
            &limbs[1..9],
            &public_inputs.close_intent_digest.to_u64_vec()[..]
        );
        assert_eq!(
            &limbs[9..17],
            &public_inputs.member_set_commitment.to_u64_vec()[..],
            "member_set_commitment occupies limbs 9..17"
        );
        assert_eq!(limbs[17], 0, "revived_state_version hi limb");
        assert_eq!(limbs[18], 9, "revived_state_version lo limb");
        assert_eq!(
            &limbs[19..27],
            &public_inputs.revived_channel_state_digest.to_u64_vec()[..]
        );
        let roundtrip = CancelClosePublicInputs::from_u64_slice(&limbs).unwrap();
        assert_eq!(public_inputs, roundtrip);
    }

    #[test]
    fn cancel_close_rejects_stale_revived_state() {
        // Revived version (5) <= close.final_state_version (7) → staleness rejection.
        let closing_state = sample_state(0, 7);
        let close_intent = close_intent_for(&closing_state);
        let revived_state = sample_state(0, 5);
        let witness = CancelCloseWitness {
            revived_state,
            close_intent,
        };
        match witness.to_public_inputs() {
            Err(CancelCloseWitnessError::StaleRevivedState { revived, close }) => {
                assert_eq!(revived, 5);
                assert_eq!(close, 7);
            }
            other => panic!("expected StaleRevivedState, got {other:?}"),
        }
    }

    #[test]
    fn cancel_close_rejects_equal_revived_version() {
        // Equal version is NOT strictly greater → rejection (boundary case).
        let closing_state = sample_state(0, 7);
        let close_intent = close_intent_for(&closing_state);
        let revived_state = sample_state(0, 7);
        let witness = CancelCloseWitness {
            revived_state,
            close_intent,
        };
        assert!(matches!(
            witness.to_public_inputs(),
            Err(CancelCloseWitnessError::StaleRevivedState { .. })
        ));
    }

    #[test]
    fn cancel_close_rejects_wrong_era_fence() {
        // Revived state from a DIFFERENT era (nonce 1, so +1 = 2 != close nonce 1) → rejection.
        let closing_state = sample_state(0, 7);
        let close_intent = close_intent_for(&closing_state); // close_freeze_nonce == 1
        let revived_state = sample_state(1, 9); // 1 + 1 = 2 != 1
        let witness = CancelCloseWitness {
            revived_state,
            close_intent,
        };
        assert!(matches!(
            witness.to_public_inputs(),
            Err(CancelCloseWitnessError::EraFenceMismatch { .. })
        ));
    }

    /// GOLDEN VECTOR: the Rust `CancelClosePublicInputs::to_u64_vec()` must produce the SAME
    /// 27-limb vector as the Solidity `_expectedCancelCloseLimbs` (pinned by the Solidity
    /// `test_expectedCancelCloseLimbs_goldenVector`, same sentinels). One BE u32 word per limb.
    #[test]
    fn cancel_close_public_inputs_match_solidity_shared_vector() {
        // `b32(tag)` = the 8 BE u32 words [tag, tag+1, ..., tag+7] — mirror of Solidity `_b32`.
        fn b32(tag: u32) -> Bytes32 {
            Bytes32::from_u32_slice(&[
                tag,
                tag + 1,
                tag + 2,
                tag + 3,
                tag + 4,
                tag + 5,
                tag + 6,
                tag + 7,
            ])
            .unwrap()
        }
        let pis = CancelClosePublicInputs {
            channel_id: ChannelId::new(0x0a0b_0c0d).unwrap(),
            close_intent_digest: b32(0x1000),
            member_set_commitment: b32(0x2000),
            revived_state_version: 0x0000_0011_0000_0022,
            revived_channel_state_digest: b32(0x3000),
        };
        let v = pis.to_u64_vec();
        assert_eq!(v.len(), CANCEL_CLOSE_PUBLIC_INPUTS_LEN);
        assert_eq!(v[0], 0x0a0b_0c0d, "channel_id");
        for i in 0..8 {
            assert_eq!(v[1 + i], (0x1000 + i as u64), "close_intent_digest");
            assert_eq!(v[9 + i], (0x2000 + i as u64), "member_set_commitment");
            assert_eq!(
                v[19 + i],
                (0x3000 + i as u64),
                "revived_channel_state_digest"
            );
        }
        assert_eq!(v[17], 0x11, "revived_state_version hi");
        assert_eq!(v[18], 0x22, "revived_state_version lo");
    }

    #[test]
    fn cancel_close_rejects_wrong_channel() {
        let closing_state = sample_state(0, 7);
        let close_intent = close_intent_for(&closing_state);
        let mut revived_state = sample_state(0, 9);
        revived_state.channel_id = ChannelId::new(4).unwrap();
        revived_state = revived_state.with_computed_digest();
        let witness = CancelCloseWitness {
            revived_state,
            close_intent,
        };
        assert!(matches!(
            witness.to_public_inputs(),
            Err(CancelCloseWitnessError::ChannelIdMismatch)
        ));
    }
}
