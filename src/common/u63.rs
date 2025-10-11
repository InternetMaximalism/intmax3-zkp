use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const U63_BITS: usize = 63;
const U63_LOW_BITS: usize = 32;
const U63_HIGH_BITS: usize = U63_BITS - U63_LOW_BITS;
const U63_MAX_VALUE: u64 = (1u64 << U63_BITS) - 1;
const U63_HIGH_MAX: u64 = (1u64 << U63_HIGH_BITS) - 1;

#[derive(Debug, Error)]
pub enum U63Error {
    #[error("Value {0} exceeds 63-bit range")]
    ValueOverflow(u64),
    #[error("High part {0} exceeds {1}-bit range")]
    InvalidHigh(u32, usize),
    #[error("Expected {1} elements in u32 slice, got {0}")]
    InvalidU32SliceLength(usize, usize),
    #[error("Expected {1} elements in u64 slice, got {0}")]
    InvalidU64SliceLength(usize, usize),
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct U63(u64);

impl U63 {
    pub fn new(value: u64) -> Result<Self, U63Error> {
        if value > U63_MAX_VALUE {
            return Err(U63Error::ValueOverflow(value));
        }
        Ok(Self(value))
    }

    pub fn from_parts(high: u32, low: u32) -> Result<Self, U63Error> {
        if (high as u64) > U63_HIGH_MAX {
            return Err(U63Error::InvalidHigh(high, U63_HIGH_BITS));
        }
        let value = ((high as u64) << U63_LOW_BITS) | low as u64;
        Self::new(value)
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        let value = rng.gen_range(0..=U63_MAX_VALUE);
        Self(value)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn high(&self) -> u32 {
        ((self.0 >> U63_LOW_BITS) & U63_HIGH_MAX) as u32
    }

    pub fn low(&self) -> u32 {
        (self.0 & ((1u64 << U63_LOW_BITS) - 1)) as u32
    }

    pub fn to_u32_parts(&self) -> (u32, u32) {
        (self.high(), self.low())
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        let (high, low) = self.to_u32_parts();
        vec![high, low]
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        vec![self.0]
    }

    pub fn from_u32_slice(slice: &[u32]) -> Result<Self, U63Error> {
        if slice.len() != 2 {
            return Err(U63Error::InvalidU32SliceLength(slice.len(), 2));
        }
        Self::from_parts(slice[0], slice[1])
    }

    pub fn from_u64_slice(slice: &[u64]) -> Result<Self, U63Error> {
        if slice.len() != 1 {
            return Err(U63Error::InvalidU64SliceLength(slice.len(), 1));
        }
        Self::new(slice[0])
    }

    pub fn add(&self, x: u64) -> Result<Self, U63Error> {
        Self::new(
            self.0
                .checked_add(x)
                .ok_or(U63Error::ValueOverflow(self.0))?,
        )
    }
}

pub type BlockNumber = U63;
pub type BlockNumberTarget = U63Target;
pub type BlockNumberError = U63Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct U63Target {
    pub value: Target,
}

impl U63Target {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let value = builder.add_virtual_target();
        if is_checked {
            builder.range_check(value, U63_BITS);
        }
        Self { value }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: U63,
    ) -> Self {
        Self {
            value: builder.constant(F::from_canonical_u64(value.as_u64())),
        }
    }

    pub fn from_parts<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        high: Target,
        low: Target,
        is_checked: bool,
    ) -> Self {
        if is_checked {
            builder.range_check(high, U63_HIGH_BITS);
            builder.range_check(low, U63_LOW_BITS);
        }
        let shift = builder.constant(F::from_canonical_u64(1u64 << U63_LOW_BITS));
        let high_shifted = builder.mul(shift, high);
        let value = builder.add(high_shifted, low);
        if is_checked {
            builder.range_check(value, U63_BITS);
        }
        Self { value }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        vec![self.value]
    }

    pub fn from_slice(slice: &[Target]) -> Self {
        assert_eq!(slice.len(), 1, "U63Target expects a single target");
        Self { value: slice[0] }
    }

    pub fn split_parts<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> (Target, Target) {
        let (low, high) = builder.split_low_high(self.value, U63_LOW_BITS, U63_BITS);
        (high, low)
    }

    pub fn to_u32_vec<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let (high, low) = self.split_parts(builder);
        vec![high, low]
    }

    pub fn to_u64_vec(&self) -> Vec<Target> {
        vec![self.value]
    }

    pub fn from_u32_slice<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        slice: &[Target],
        is_checked: bool,
    ) -> Self {
        assert_eq!(
            slice.len(),
            2,
            "U63Target expects two targets for u32 limbs"
        );
        Self::from_parts(builder, slice[0], slice[1], is_checked)
    }

    pub fn from_u64_slice(slice: &[Target]) -> Self {
        Self::from_slice(slice)
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        builder.connect(self.value, other.value);
    }

    pub fn is_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> BoolTarget {
        builder.is_equal(self.value, other.value)
    }

    pub fn is_zero<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        let zero = builder.zero();
        builder.is_equal(self.value, zero)
    }

    pub fn enforce_ge<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        lower: &Self,
    ) {
        let diff = builder.sub(self.value, lower.value);
        builder.range_check(diff, U63_BITS);
    }

    pub fn enforce_gt<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        lower: &Self,
    ) {
        let lower_plus_one = builder.add_const(lower.value, F::ONE);
        self.enforce_ge(
            builder,
            &Self {
                value: lower_plus_one,
            },
        );
    }

    pub fn conditional_ge<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        lower: &Self,
        condition: BoolTarget,
    ) {
        let diff = builder.sub(self.value, lower.value);
        let zero = builder.zero();
        let diff_when_true = builder.select(condition, diff, zero);
        builder.range_check(diff_when_true, U63_BITS);
    }

    pub fn conditional_gt<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        lower: &Self,
        condition: BoolTarget,
    ) {
        let lower_plus_one = builder.add_const(lower.value, F::ONE);
        self.conditional_ge(
            builder,
            &Self {
                value: lower_plus_one,
            },
            condition,
        );
    }

    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        when_true: &Self,
        when_false: &Self,
    ) -> Self {
        let value = builder.select(condition, when_true.value, when_false.value);
        Self { value }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: U63) {
        witness.set_target(self.value, F::from_canonical_u64(value.as_u64()));
    }
}
