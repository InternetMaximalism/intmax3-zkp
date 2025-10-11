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
    constants::{AGGREGATOR_ID_BITS, LOCAL_ID_BITS, MAX_NUM_AGGREGATORS},
};

#[derive(Debug, Error)]
pub enum UserIdError {
    #[error("Invalid aggregator ID: {0}")]
    InvalidAggregatorId(String),
    #[error("Invalid local ID: {0}")]
    InvalidLocalId(String),
    #[error("Invalid raw value: {0}")]
    InvalidValue(String),
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserId(U63);

impl UserId {
    pub fn new(aggregator_id: u32, local_id: u32) -> Result<Self, UserIdError> {
        if aggregator_id as usize >= MAX_NUM_AGGREGATORS {
            return Err(UserIdError::InvalidAggregatorId(format!(
                "{} >= {}",
                aggregator_id, MAX_NUM_AGGREGATORS
            )));
        }
        if aggregator_id == 0 && local_id == 0 {
            return Err(UserIdError::InvalidLocalId(
                "Both aggregator_id=0 and local_id=0 are reserved for dummy".to_string(),
            ));
        }
        let value = U63::from_parts(aggregator_id, local_id)
            .map_err(|err| UserIdError::InvalidValue(err.to_string()))?;
        Ok(Self(value))
    }

    pub fn dummy() -> Self {
        Self(U63::default())
    }

    pub fn aggregator_id(&self) -> u32 {
        self.0.high()
    }

    pub fn local_id(&self) -> u32 {
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

    pub fn from_u63(value: U63) -> Result<Self, UserIdError> {
        Self::validate_components(value.high(), value.low())?;
        Ok(Self(value))
    }

    pub fn from_u64(value: u64) -> Result<Self, UserIdError> {
        let value = U63::new(value).map_err(|err| UserIdError::InvalidValue(err.to_string()))?;
        Self::from_u63(value)
    }

    fn validate_components(aggregator_id: u32, local_id: u32) -> Result<(), UserIdError> {
        if aggregator_id as usize >= MAX_NUM_AGGREGATORS {
            return Err(UserIdError::InvalidAggregatorId(format!(
                "{} >= {}",
                aggregator_id, MAX_NUM_AGGREGATORS
            )));
        }
        if aggregator_id == 0 && local_id == 0 {
            return Err(UserIdError::InvalidLocalId(
                "Both aggregator_id=0 and local_id=0 are reserved for dummy".to_string(),
            ));
        }
        Ok(())
    }
}

impl From<UserId> for U63 {
    fn from(value: UserId) -> Self {
        value.0
    }
}

impl From<&UserId> for U63 {
    fn from(value: &UserId) -> Self {
        value.0
    }
}

impl From<UserId> for u64 {
    fn from(value: UserId) -> Self {
        value.as_u64()
    }
}

impl TryFrom<U63> for UserId {
    type Error = UserIdError;

    fn try_from(value: U63) -> Result<Self, Self::Error> {
        Self::from_u63(value)
    }
}

impl TryFrom<u64> for UserId {
    type Error = UserIdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_u64(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserIdTarget {
    pub value: Target,
}

impl UserIdTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let base = U63Target::new(builder, is_checked);
        Self { value: base.value }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: UserId,
    ) -> Self {
        let base = U63Target::constant(builder, value.into());
        Self { value: base.value }
    }

    pub fn from_parts<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        aggregator_id: Target,
        local_id: Target,
        is_checked: bool,
    ) -> Self {
        if is_checked {
            builder.range_check(aggregator_id, AGGREGATOR_ID_BITS);
            builder.range_check(local_id, LOCAL_ID_BITS);
        }
        let base = U63Target::from_parts(builder, aggregator_id, local_id, is_checked);
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

    pub fn aggregator_id<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let (high, _) = U63Target { value: self.value }.split_parts(builder);
        high
    }

    pub fn local_id<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let (_, low) = U63Target { value: self.value }.split_parts(builder);
        low
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

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: UserId) {
        U63Target { value: self.value }.set_witness(witness, value.into());
    }
}
