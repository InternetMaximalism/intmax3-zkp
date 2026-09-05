//! Private, host-side range evidence for channel balance credits.
//!
//! Call this module **after** authenticating the complete transition against the trusted
//! predecessor, registered keys, and E1/E2/refresh proof. It does not verify a transition, a
//! ciphertext, a signature, an opening, or channel backing. In particular, the token-wise
//! conservation invariant (nonnegative balances whose sum is at most the token fund) must
//! already hold inductively. These checks add no proof, public input, or circuit constraint.
//!
//! `Some(b)` means the signer has established `plaintext <= b <= u64::MAX`; `None` means
//! unknown, NOT zero. This is private signer state, not a peer-supplied attestation: binding it
//! to a state digest prevents accidental reuse, not malicious editing of the bounds themselves.
//! Keep it in the same rollback-protected private store as the signing ledger, and persist the
//! returned successor bounds atomically with the successor. Never publish it in a snapshot:
//! bounds learned by own-key decryption can reveal that signer's exact balance.
//!
//! Owned plaintext maps must contain successful decryption results for the exact state's
//! ciphertext under its registered recipient key. A supplied number or a refresh proof is not
//! a substitute. The current hidden-message refresh AIR alone does not prove a u64 range.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::channel::{ChannelId, ChannelState},
    constants::{MAX_CHANNEL_MEMBERS, MAX_CHANNEL_TOKENS},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
};

pub const CREDIT_BOUNDS_SCHEMA_VERSION: u32 = 1;

/// `(participant slot, local token slot) -> successfully decrypted/verified opening`.
/// Neither slot numbers nor values in this map may be trusted from a request body.
pub type OwnedPlaintexts = BTreeMap<(usize, usize), u64>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelCreditBounds {
    pub schema_version: u32,
    pub channel_id: ChannelId,
    pub state_digest: Bytes32,
    pub upper_bounds: Vec<[Option<u64>; MAX_CHANNEL_TOKENS]>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CreditSafetyError {
    #[error("unsupported channel-credit bounds schema {0}")]
    UnsupportedSchema(u32),
    #[error("channel-credit bounds do not belong to the authenticated state")]
    StateMismatch,
    #[error("invalid channel-credit state/bounds layout: {0}")]
    InvalidLayout(&'static str),
    #[error("channel-credit successor is not a direct child of the authenticated predecessor")]
    SuccessorMismatch,
    #[error("channel-credit token registry was removed or remapped")]
    RegistryChanged,
    #[error("channel-credit cell ({slot}, {token_slot}) is not active")]
    InactiveCell { slot: usize, token_slot: usize },
    #[error(
        "new balance at ({slot}, {token_slot}) is not admissible to the existing withdrawal claim; rebuild/refresh before signing"
    )]
    UnclaimableCiphertext { slot: usize, token_slot: usize },
    #[error(
        "decrypted balance conflicts with authenticated range evidence at ({slot}, {token_slot})"
    )]
    InconsistentPlaintext { slot: usize, token_slot: usize },
    #[error(
        "recipient range evidence required before signing credit to ({slot}, {token_slot}); retain the current head and obtain recipient evidence or reduce/restructure the credit"
    )]
    RangeEvidenceRequired { slot: usize, token_slot: usize },
}

impl CreditSafetyError {
    /// The specific credit can be retried with better evidence; no state should be committed.
    pub fn is_recoverable_range_error(&self) -> bool {
        matches!(self, Self::RangeEvidenceRequired { .. })
    }
}

impl ChannelCreditBounds {
    /// Safely bootstrap an authenticated snapshot without assuming its hidden balances are
    /// known. A token fund fitting u64 bounds each individual balance by conservation; otherwise
    /// only owned, successfully decrypted cells become known. Inactive cells are canonical zero
    /// by the caller's preceding state validation. Unknown, unchanged active cells do not prevent
    /// a future unrelated transition.
    pub fn bootstrap(
        state: &ChannelState,
        owned: &OwnedPlaintexts,
    ) -> Result<Self, CreditSafetyError> {
        let (active, tokens) = checked_layout(state)?;
        validate_plaintext_cells(owned, active, tokens)?;
        let mut result = Self {
            schema_version: CREDIT_BOUNDS_SCHEMA_VERSION,
            channel_id: state.channel_id,
            state_digest: state.digest,
            upper_bounds: vec![[Some(0); MAX_CHANNEL_TOKENS]; MAX_CHANNEL_MEMBERS],
        };
        for slot in 0..active {
            for token_slot in 0..tokens {
                let fund_bound = as_u64(state.channel_fund.amounts[token_slot]);
                result.upper_bounds[slot][token_slot] = with_owned_plaintext(
                    fund_bound,
                    owned.get(&(slot, token_slot)).copied(),
                    slot,
                    token_slot,
                )?;
            }
        }
        Ok(result)
    }

    /// Genesis/join initializer for openings the caller has already independently verified.
    /// This is deliberately not an "accept claimed balances" constructor. Partial maps are
    /// allowed: other active cells remain unknown unless the token fund supplies a safe bound.
    pub fn from_known_openings(
        state: &ChannelState,
        verified_openings: &OwnedPlaintexts,
    ) -> Result<Self, CreditSafetyError> {
        Self::bootstrap(state, verified_openings)
    }

    /// Cheap store/context validation; the caller already verified the state's actual digest.
    pub fn validate_for(&self, state: &ChannelState) -> Result<(), CreditSafetyError> {
        let (active, tokens) = checked_layout(state)?;
        if self.schema_version != CREDIT_BOUNDS_SCHEMA_VERSION {
            return Err(CreditSafetyError::UnsupportedSchema(self.schema_version));
        }
        if self.channel_id != state.channel_id || self.state_digest != state.digest {
            return Err(CreditSafetyError::StateMismatch);
        }
        if self.upper_bounds.len() != MAX_CHANNEL_MEMBERS {
            return Err(CreditSafetyError::InvalidLayout("bounds row count"));
        }
        for (slot, row) in self.upper_bounds.iter().enumerate() {
            for (token_slot, &bound) in row.iter().enumerate() {
                if (slot >= active || token_slot >= tokens) && bound != Some(0) {
                    return Err(CreditSafetyError::InvalidLayout(
                        "nonzero/unknown padding bound",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Certify every changed active ciphertext cell before releasing any successor signature.
    ///
    /// For each token let C contain all changed cells. Authenticated conservation and unchanged
    /// keys/ciphertexts outside C imply
    ///
    /// `sum(next[C]) <= sum(prev[C]) + positive(fund delta) + positive(unallocated decrease)`.
    ///
    /// Nonnegativity therefore bounds EACH next cell by that same sum. The unallocated term is
    /// necessary for the second half of an import: the first half grew fund + unallocated while
    /// leaving balances unchanged, and the bundle now moves unallocated value into one cell.
    /// Unallocated is currently a cross-token scalar, so giving its complete decrease to every
    /// changed token is a conservative overestimate, never a cross-token fund transfer.
    ///
    /// We intersect that bound with the post-token fund bound and owned exact decryption. This
    /// avoids a global channel-fund cap. The pooled bound is intentionally conservative: where
    /// it is too loose, only an affected unknown cell is refused, without mutating this object.
    /// No bound is learned from the honesty of a remote proof-generation helper.
    pub fn advance_authenticated(
        &self,
        prev: &ChannelState,
        next: &ChannelState,
        owned_next: &OwnedPlaintexts,
    ) -> Result<Self, CreditSafetyError> {
        self.validate_for(prev)?;
        let (next_active, next_tokens) = checked_layout(next)?;
        validate_plaintext_cells(owned_next, next_active, next_tokens)?;
        if next.channel_id != prev.channel_id || next.prev_digest != prev.digest {
            return Err(CreditSafetyError::SuccessorMismatch);
        }
        let prev_tokens = prev.balance_state.token_count as usize;
        if next_tokens < prev_tokens
            || next.balance_state.token_registry[..prev_tokens]
                != prev.balance_state.token_registry[..prev_tokens]
        {
            return Err(CreditSafetyError::RegistryChanged);
        }

        // Compute differences without adding U256 values: even a full-width fund cannot make
        // this preflight overflow. None is an unknown/>u64 bound, not wrapping arithmetic.
        let allocation = positive_difference_bound(
            prev.unallocated_confirmed_incoming,
            next.unallocated_confirmed_incoming,
        );
        let mut pools = [Some(0); MAX_CHANNEL_TOKENS];
        let mut changed = vec![[false; MAX_CHANNEL_TOKENS]; MAX_CHANNEL_MEMBERS];
        for (token_slot, pool) in pools.iter_mut().enumerate().take(next_tokens) {
            *pool = add_bounds(
                positive_difference_bound(
                    next.channel_fund.amounts[token_slot],
                    prev.channel_fund.amounts[token_slot],
                ),
                allocation,
            );
            for (slot, row) in changed.iter_mut().enumerate() {
                // Including the key digest makes an unchanged ciphertext under a new key a
                // changed cell too. Legitimate zero-opening joins must have been authenticated
                // by their dedicated caller before reaching this module.
                row[token_slot] = prev.balance_state.enc_balances[slot][token_slot]
                    != next.balance_state.enc_balances[slot][token_slot]
                    || prev.balance_state.regev_pk_digests[slot]
                        != next.balance_state.regev_pk_digests[slot];
                if row[token_slot] {
                    *pool = add_bounds(*pool, self.upper_bounds[slot][token_slot]);
                }
            }
        }

        let mut result = Self {
            schema_version: CREDIT_BOUNDS_SCHEMA_VERSION,
            channel_id: next.channel_id,
            state_digest: next.digest,
            upper_bounds: vec![[Some(0); MAX_CHANNEL_TOKENS]; MAX_CHANNEL_MEMBERS],
        };
        for (slot, row) in changed.iter().enumerate().take(next_active) {
            for (token_slot, &is_changed) in row.iter().enumerate().take(next_tokens) {
                if is_changed {
                    next.balance_state.enc_balances[slot][token_slot]
                        .validate_balance_exit_shape()
                        .map_err(|_| CreditSafetyError::UnclaimableCiphertext {
                            slot,
                            token_slot,
                        })?;
                }
                let carried = if is_changed {
                    pools[token_slot]
                } else {
                    self.upper_bounds[slot][token_slot]
                };
                let known = tighter_bound(carried, as_u64(next.channel_fund.amounts[token_slot]));
                let bound = with_owned_plaintext(
                    known,
                    owned_next.get(&(slot, token_slot)).copied(),
                    slot,
                    token_slot,
                )?;
                if is_changed && bound.is_none() {
                    return Err(CreditSafetyError::RangeEvidenceRequired { slot, token_slot });
                }
                result.upper_bounds[slot][token_slot] = bound;
            }
        }
        Ok(result)
    }

    /// Pre-spend check for a PUBLIC external credit (L1 deposit / inbound inter-channel amount).
    /// The post-fund upper bound is `current token fund + amount`; this is not an authorization
    /// to import, and does not replace the post-transition check above. `owned_before`, if any,
    /// must be locally decrypted at this exact state, never taken from the deposit request.
    pub fn can_credit(
        &self,
        state: &ChannelState,
        slot: usize,
        token_slot: usize,
        amount: u64,
        owned_before: Option<u64>,
    ) -> Result<(), CreditSafetyError> {
        self.validate_for(state)?;
        let (active, tokens) = checked_layout(state)?;
        if slot >= active || token_slot >= tokens {
            return Err(CreditSafetyError::InactiveCell { slot, token_slot });
        }
        let fund_before = as_u64(state.channel_fund.amounts[token_slot]);
        let before = with_owned_plaintext(
            tighter_bound(self.upper_bounds[slot][token_slot], fund_before),
            owned_before,
            slot,
            token_slot,
        )?;
        let after = tighter_bound(
            add_bounds(before, Some(amount)),
            add_bounds(fund_before, Some(amount)),
        );
        if after.is_none() {
            return Err(CreditSafetyError::RangeEvidenceRequired { slot, token_slot });
        }
        Ok(())
    }
}

fn checked_layout(state: &ChannelState) -> Result<(usize, usize), CreditSafetyError> {
    let balance = &state.balance_state;
    let active = balance.member_count as usize + balance.delegate_count as usize;
    let tokens = balance.token_count as usize;
    if balance.channel_id != state.channel_id || state.channel_fund.channel_id != state.channel_id {
        return Err(CreditSafetyError::InvalidLayout("channel identifiers"));
    }
    if active > MAX_CHANNEL_MEMBERS || active == 0 || tokens == 0 || tokens > MAX_CHANNEL_TOKENS {
        return Err(CreditSafetyError::InvalidLayout(
            "active participant/token count",
        ));
    }
    if balance.enc_balances.len() != MAX_CHANNEL_MEMBERS {
        return Err(CreditSafetyError::InvalidLayout("ciphertext row count"));
    }
    Ok((active, tokens))
}

fn validate_plaintext_cells(
    values: &OwnedPlaintexts,
    active: usize,
    tokens: usize,
) -> Result<(), CreditSafetyError> {
    for &(slot, token_slot) in values.keys() {
        if slot >= active || token_slot >= tokens {
            return Err(CreditSafetyError::InactiveCell { slot, token_slot });
        }
    }
    Ok(())
}

fn as_u64(value: U256) -> Option<u64> {
    let limbs = value.to_u32_vec();
    if limbs[..6].iter().any(|&limb| limb != 0) {
        return None;
    }
    Some((u64::from(limbs[6]) << 32) | u64::from(limbs[7]))
}

/// `max(a-b, 0)`, represented only if <= u64::MAX.
fn positive_difference_bound(a: U256, b: U256) -> Option<u64> {
    if a > b { as_u64(a - b) } else { Some(0) }
}

fn add_bounds(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    a?.checked_add(b?)
}

fn tighter_bound(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(bound), None) | (None, Some(bound)) => Some(bound),
        (None, None) => None,
    }
}

fn with_owned_plaintext(
    bound: Option<u64>,
    owned: Option<u64>,
    slot: usize,
    token_slot: usize,
) -> Result<Option<u64>, CreditSafetyError> {
    if let Some(value) = owned {
        if bound.is_some_and(|upper| value > upper) {
            return Err(CreditSafetyError::InconsistentPlaintext { slot, token_slot });
        }
        return Ok(Some(value));
    }
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{balance_state::BalanceState, channel::ChannelFund},
        ethereum_types::address::Address,
    };

    // These are pure accounting tests. Ciphertexts are opaque equality labels, deliberately
    // not cryptographic fixtures; no proof, encryption, signature, or transaction is generated.
    fn state(fund: U256) -> ChannelState {
        let channel_id = ChannelId::new(7).unwrap();
        ChannelState {
            channel_id,
            epoch: 0,
            small_block_number: 0,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id,
                amounts: ChannelFund::single_token_amounts(fund),
                intmax_state_root: Bytes32::default(),
            },
            balance_state: BalanceState {
                channel_id,
                member_count: 2,
                delegate_count: 1,
                enc_balances: vec![
                    std::array::from_fn(|_| {
                        crate::common::balance_state::zero_ciphertext().clone()
                    });
                    MAX_CHANNEL_MEMBERS
                ],
                regev_pk_digests: [Bytes32::default(); MAX_CHANNEL_MEMBERS],
                recipients: [Address::default(); MAX_CHANNEL_MEMBERS],
                settled_tx_chain: Bytes32::default(),
                settled_tx_accumulator_root: Bytes32::default(),
                state_version: 0,
                pending_adds: vec![[0; MAX_CHANNEL_TOKENS]; MAX_CHANNEL_MEMBERS],
                token_registry: [0; MAX_CHANNEL_TOKENS],
                token_count: 1,
            },
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::from(0u64),
            prev_digest: Bytes32::default(),
            digest: U256::from(1u64).into(),
            member_signatures: vec![],
        }
    }

    fn child(prev: &ChannelState, cells: &[(usize, usize)]) -> ChannelState {
        let mut next = prev.clone();
        next.prev_digest = prev.digest;
        next.digest = (U256::from(prev.digest) + U256::from(1u64)).into();
        next.epoch += 1;
        next.balance_state.state_version += 1;
        for &(slot, token) in cells {
            next.balance_state.enc_balances[slot][token].c1[0] += 1;
        }
        next
    }

    fn wide_fund() -> U256 {
        U256::from(u64::MAX) + U256::from(100u64)
    }

    #[test]
    fn small_token_fund_is_a_fast_path_not_a_channel_wide_cap() {
        let mut prev = state(U256::from(100u64));
        prev.balance_state.token_count = 2;
        prev.balance_state.token_registry[1] = 9;
        prev.channel_fund.amounts[1] = wide_fund();
        let bounds = ChannelCreditBounds::bootstrap(&prev, &OwnedPlaintexts::new()).unwrap();
        let next = child(&prev, &[(0, 0), (2, 0)]);
        let updated = bounds
            .advance_authenticated(&prev, &next, &OwnedPlaintexts::new())
            .unwrap();
        assert_eq!(updated.upper_bounds[2][0], Some(100));
        assert_eq!(updated.upper_bounds[2][1], None);
    }

    #[test]
    fn wide_fund_accepts_bounded_hidden_redistribution_and_keeps_other_cells() {
        let prev = state(wide_fund());
        let known = BTreeMap::from([((0, 0), 10), ((1, 0), 20), ((2, 0), 0)]);
        let bounds = ChannelCreditBounds::from_known_openings(&prev, &known).unwrap();
        let next = child(&prev, &[(0, 0), (2, 0)]);
        let updated = bounds
            .advance_authenticated(&prev, &next, &OwnedPlaintexts::new())
            .unwrap();
        assert_eq!(updated.upper_bounds[0][0], Some(10));
        assert_eq!(updated.upper_bounds[2][0], Some(10));
        assert_eq!(updated.upper_bounds[1][0], Some(20));
        assert_eq!(updated.state_digest, next.digest);
    }

    #[test]
    fn inclusive_u64_boundary_is_allowed_without_wrapping() {
        assert_eq!(add_bounds(Some(u64::MAX - 1), Some(1)), Some(u64::MAX));
        assert_eq!(add_bounds(Some(u64::MAX), Some(1)), None);
        let prev = state(wide_fund());
        let bounds = ChannelCreditBounds::from_known_openings(
            &prev,
            &BTreeMap::from([((0, 0), u64::MAX), ((2, 0), 0)]),
        )
        .unwrap();
        let next = child(&prev, &[(0, 0), (2, 0)]);
        assert_eq!(
            bounds
                .advance_authenticated(&prev, &next, &OwnedPlaintexts::new())
                .unwrap()
                .upper_bounds[2][0],
            Some(u64::MAX)
        );
    }

    #[test]
    fn only_changed_unknown_cells_require_recoverable_evidence() {
        let prev = state(wide_fund());
        let bounds = ChannelCreditBounds::bootstrap(&prev, &OwnedPlaintexts::new()).unwrap();
        let untouched = child(&prev, &[]);
        assert!(
            bounds
                .advance_authenticated(&prev, &untouched, &OwnedPlaintexts::new())
                .is_ok()
        );
        let next = child(&prev, &[(2, 0)]);
        let err = bounds
            .advance_authenticated(&prev, &next, &OwnedPlaintexts::new())
            .unwrap_err();
        assert_eq!(
            err,
            CreditSafetyError::RangeEvidenceRequired {
                slot: 2,
                token_slot: 0
            }
        );
        assert!(err.is_recoverable_range_error());
        assert_eq!(bounds.state_digest, prev.digest);
        let owned = BTreeMap::from([((2, 0), 31)]);
        assert_eq!(
            bounds
                .advance_authenticated(&prev, &next, &owned)
                .unwrap()
                .upper_bounds[2][0],
            Some(31)
        );
    }

    #[test]
    fn public_fund_growth_is_included_in_recipient_bound() {
        let prev = state(wide_fund());
        let bounds =
            ChannelCreditBounds::bootstrap(&prev, &BTreeMap::from([((2, 0), 10)])).unwrap();
        let mut next = child(&prev, &[(2, 0)]);
        next.channel_fund.amounts[0] += U256::from(7u64);
        assert_eq!(
            bounds
                .advance_authenticated(&prev, &next, &OwnedPlaintexts::new())
                .unwrap()
                .upper_bounds[2][0],
            Some(17)
        );
    }

    #[test]
    fn two_step_import_counts_allocation_when_fund_is_unchanged() {
        let prev = state(wide_fund());
        let bounds =
            ChannelCreditBounds::bootstrap(&prev, &BTreeMap::from([((2, 0), 10)])).unwrap();
        let mut imported = child(&prev, &[]);
        imported.channel_fund.amounts[0] += U256::from(7u64);
        imported.unallocated_confirmed_incoming = U256::from(7u64);
        let imported_bounds = bounds
            .advance_authenticated(&prev, &imported, &OwnedPlaintexts::new())
            .unwrap();
        assert_eq!(imported_bounds.upper_bounds[2][0], Some(10));
        let mut bundled = child(&imported, &[(2, 0)]);
        bundled.unallocated_confirmed_incoming = U256::from(0u64);
        assert_eq!(
            imported_bounds
                .advance_authenticated(&imported, &bundled, &OwnedPlaintexts::new())
                .unwrap()
                .upper_bounds[2][0],
            Some(17)
        );
    }

    #[test]
    fn public_credit_preflight_is_cell_scoped_and_checked() {
        let prev = state(wide_fund());
        let bounds =
            ChannelCreditBounds::bootstrap(&prev, &BTreeMap::from([((2, 0), 10)])).unwrap();
        assert!(bounds.can_credit(&prev, 2, 0, 7, None).is_ok());
        assert!(bounds.can_credit(&prev, 1, 0, 7, Some(20)).is_ok());
        assert!(matches!(
            bounds.can_credit(&prev, 1, 0, 7, None),
            Err(CreditSafetyError::RangeEvidenceRequired { .. })
        ));
        assert!(matches!(
            bounds.can_credit(&prev, 2, 0, u64::MAX, None),
            Err(CreditSafetyError::RangeEvidenceRequired { .. })
        ));
        assert!(matches!(
            bounds.can_credit(&prev, 3, 0, 1, None),
            Err(CreditSafetyError::InactiveCell { .. })
        ));
    }

    #[test]
    fn stale_or_malformed_bounds_are_never_silently_reset() {
        let prev = state(U256::from(100u64));
        let mut bounds = ChannelCreditBounds::bootstrap(&prev, &OwnedPlaintexts::new()).unwrap();
        let next = child(&prev, &[]);
        assert_eq!(
            bounds.validate_for(&next),
            Err(CreditSafetyError::StateMismatch)
        );
        bounds.upper_bounds.pop();
        assert!(matches!(
            bounds.validate_for(&prev),
            Err(CreditSafetyError::InvalidLayout(_))
        ));
    }

    #[test]
    fn serde_roundtrip_preserves_unknown_and_digest_binding() {
        let prev = state(wide_fund());
        let bounds = ChannelCreditBounds::bootstrap(&prev, &BTreeMap::from([((0, 0), 5)])).unwrap();
        let encoded = serde_json::to_string(&bounds).unwrap();
        let decoded: ChannelCreditBounds = serde_json::from_str(&encoded).unwrap();
        decoded.validate_for(&prev).unwrap();
        assert_eq!(decoded, bounds);
        assert_eq!(decoded.upper_bounds[1][0], None);
    }

    #[test]
    fn contradictory_plaintext_or_registry_remap_is_rejected() {
        let prev = state(U256::from(10u64));
        assert!(matches!(
            ChannelCreditBounds::bootstrap(&prev, &BTreeMap::from([((0, 0), 11)])),
            Err(CreditSafetyError::InconsistentPlaintext { .. })
        ));
        let bounds = ChannelCreditBounds::bootstrap(&prev, &OwnedPlaintexts::new()).unwrap();
        let mut next = child(&prev, &[]);
        next.balance_state.token_registry[0] = 1;
        assert_eq!(
            bounds.advance_authenticated(&prev, &next, &OwnedPlaintexts::new()),
            Err(CreditSafetyError::RegistryChanged)
        );
    }

    #[test]
    fn maximum_width_funds_do_not_overflow_the_preflight() {
        let maximum = U256::from_u32_slice(&[u32::MAX; 8]).unwrap();
        let prev = state(maximum);
        let bounds = ChannelCreditBounds::bootstrap(&prev, &BTreeMap::from([((2, 0), 0)])).unwrap();
        assert!(bounds.can_credit(&prev, 2, 0, 5, None).is_ok());
        // Fund representability is the deposit/transition verifier's separate responsibility;
        // this range-only helper never adds full-width U256 values or promises deposit validity.
    }
}
