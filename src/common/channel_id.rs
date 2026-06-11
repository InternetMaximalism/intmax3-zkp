use std::convert::TryFrom;

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    common::u63::{U63, U63Target},
    constants::{ACCOUNT_NO_BITS, HUB_ID_BITS, MAX_NUM_HUBS},
};

#[derive(Debug, Error)]
pub enum AccountIdError {
    #[error("Invalid hub ID: {0}")]
    InvalidHubId(String),
    #[error("Invalid account number: {0}")]
    InvalidAccountNo(String),
    #[error("Invalid raw value: {0}")]
    InvalidValue(String),
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountId(U63);

impl AccountId {
    pub fn new(hub_id: u32, account_no: u32) -> Result<Self, AccountIdError> {
        if hub_id as usize >= MAX_NUM_HUBS {
            return Err(AccountIdError::InvalidHubId(format!(
                "{} >= {}",
                hub_id, MAX_NUM_HUBS
            )));
        }
        if hub_id == 0 && account_no == 0 {
            return Err(AccountIdError::InvalidAccountNo(
                "Both hub_id=0 and account_no=0 are reserved for dummy".to_string(),
            ));
        }
        let value = U63::from_parts(hub_id, account_no)
            .map_err(|err| AccountIdError::InvalidValue(err.to_string()))?;
        Ok(Self(value))
    }

    pub fn dummy() -> Self {
        Self(U63::default())
    }

    pub fn hub_id(&self) -> u32 {
        self.0.high()
    }

    pub fn account_no(&self) -> u32 {
        self.0.low()
    }

    pub fn as_u63(&self) -> U63 {
        self.0
    }

    pub fn as_u64(&self) -> u64 {
        self.0.as_u64()
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        self.0.to_u32_vec()
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        self.0.to_u64_vec()
    }

    pub fn from_u63(value: U63) -> Result<Self, AccountIdError> {
        Self::validate_components(value.high(), value.low())?;
        Ok(Self(value))
    }

    pub fn from_u64(value: u64) -> Result<Self, AccountIdError> {
        let value = U63::new(value).map_err(|err| AccountIdError::InvalidValue(err.to_string()))?;
        Self::from_u63(value)
    }

    pub fn aggregator_id(&self) -> u32 {
        self.hub_id()
    }

    pub fn local_id(&self) -> u32 {
        self.account_no()
    }

    fn validate_components(hub_id: u32, account_no: u32) -> Result<(), AccountIdError> {
        if hub_id as usize >= MAX_NUM_HUBS {
            return Err(AccountIdError::InvalidHubId(format!(
                "{} >= {}",
                hub_id, MAX_NUM_HUBS
            )));
        }
        if hub_id == 0 && account_no == 0 {
            return Err(AccountIdError::InvalidAccountNo(
                "Both hub_id=0 and account_no=0 are reserved for dummy".to_string(),
            ));
        }
        Ok(())
    }
}

impl From<AccountId> for U63 {
    fn from(value: AccountId) -> Self {
        value.0
    }
}

impl From<&AccountId> for U63 {
    fn from(value: &AccountId) -> Self {
        value.0
    }
}

impl From<AccountId> for u64 {
    fn from(value: AccountId) -> Self {
        value.as_u64()
    }
}

impl TryFrom<U63> for AccountId {
    type Error = AccountIdError;

    fn try_from(value: U63) -> Result<Self, Self::Error> {
        Self::from_u63(value)
    }
}

impl TryFrom<u64> for AccountId {
    type Error = AccountIdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_u64(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountIdTarget {
    pub value: Target,
}

impl AccountIdTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let base = U63Target::new(builder, is_checked);
        Self { value: base.value }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: AccountId,
    ) -> Self {
        let base = U63Target::constant(builder, value.into());
        Self { value: base.value }
    }

    pub fn from_parts<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        hub_id: Target,
        account_no: Target,
        is_checked: bool,
    ) -> Self {
        if is_checked {
            builder.range_check(hub_id, HUB_ID_BITS);
            builder.range_check(account_no, ACCOUNT_NO_BITS);
        }
        let base = U63Target::from_parts(builder, hub_id, account_no, is_checked);
        Self { value: base.value }
    }

    pub fn from_slice(values: &[Target]) -> Self {
        let base = U63Target::from_slice(values);
        Self { value: base.value }
    }

    pub fn from_u32_slice<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        limbs: &[Target],
        is_checked: bool,
    ) -> Self {
        let base = U63Target::from_u32_slice(builder, limbs, is_checked);
        Self { value: base.value }
    }

    pub fn from_u64_slice(limbs: &[Target]) -> Self {
        let base = U63Target::from_u64_slice(limbs);
        Self { value: base.value }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        vec![self.value]
    }

    pub fn to_u32_vec<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        U63Target { value: self.value }.to_u32_vec(builder)
    }

    pub fn to_u64_vec(&self) -> Vec<Target> {
        U63Target { value: self.value }.to_u64_vec()
    }

    pub fn hub_id<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let (high, _) = U63Target { value: self.value }.split_parts(builder);
        high
    }

    pub fn account_no<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let (_, low) = U63Target { value: self.value }.split_parts(builder);
        low
    }

    pub fn aggregator_id<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        self.hub_id(builder)
    }

    pub fn local_id<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        self.account_no(builder)
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        U63Target { value: self.value }.connect(builder, &U63Target { value: other.value });
    }

    pub fn is_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> BoolTarget {
        U63Target { value: self.value }.is_equal(builder, &U63Target { value: other.value })
    }

    pub fn is_zero<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        U63Target { value: self.value }.is_zero(builder)
    }

    pub fn enforce_ge<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        lower: &Self,
    ) {
        U63Target { value: self.value }.enforce_ge(builder, &U63Target { value: lower.value });
    }

    pub fn enforce_gt<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        lower: &Self,
    ) {
        U63Target { value: self.value }.enforce_gt(builder, &U63Target { value: lower.value });
    }

    pub fn conditional_ge<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        lower: &Self,
        condition: BoolTarget,
    ) {
        U63Target { value: self.value }.conditional_ge(
            builder,
            &U63Target { value: lower.value },
            condition,
        );
    }

    pub fn conditional_gt<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        lower: &Self,
        condition: BoolTarget,
    ) {
        U63Target { value: self.value }.conditional_gt(
            builder,
            &U63Target { value: lower.value },
            condition,
        );
    }

    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        when_true: &Self,
        when_false: &Self,
    ) -> Self {
        let target = U63Target::select(
            builder,
            condition,
            &U63Target {
                value: when_true.value,
            },
            &U63Target {
                value: when_false.value,
            },
        );
        Self {
            value: target.value,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: AccountId) {
        U63Target { value: self.value }.set_witness(witness, value.into());
    }
}

pub type UserId = AccountId;
pub type UserIdError = AccountIdError;
pub type UserIdTarget = AccountIdTarget;
