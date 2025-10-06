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

use crate::constants::BLOCK_NUMBER_BITS;

#[derive(Debug, thiserror::Error)]
pub enum BlockNumberError {
    #[error("Invalid block number: {0}")]
    InvalidBlockNumber(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockNumber(pub u64);

impl BlockNumber {
    pub fn new(block_number: u64) -> Result<Self, BlockNumberError> {
        if block_number >= 1 << BLOCK_NUMBER_BITS {
            return Err(BlockNumberError::InvalidBlockNumber(format!(
                "{} >= {}",
                block_number,
                1u64 << BLOCK_NUMBER_BITS
            )));
        }
        Ok(Self(block_number))
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self(rng.gen_range(0..(1 << BLOCK_NUMBER_BITS)))
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        vec![self.0]
    }
}

#[derive(Clone, Debug)]
pub struct BlockNumberTarget {
    pub value: Target,
}

impl BlockNumberTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let value = builder.add_virtual_target();
        if is_checked {
            builder.range_check(value, BLOCK_NUMBER_BITS);
        }
        Self { value }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: BlockNumber,
    ) -> Self {
        Self {
            value: builder.constant(F::from_canonical_u64(value.0)),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        vec![self.value]
    }

    pub fn is_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> BoolTarget {
        builder.is_equal(self.value, other.value)
    }

    pub fn enforce_ge<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        lower_bound: &Self,
    ) {
        let diff = builder.sub(self.value, lower_bound.value);
        builder.range_check(diff, BLOCK_NUMBER_BITS);
    }

    pub fn enforce_gt<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        lower_bound: &Self,
    ) {
        // self > lower_bound  <=>  self >= lower_bound + 1
        let lower_bound_plus_one = builder.add_const(lower_bound.value, F::ONE);
        self.enforce_ge(
            builder,
            &Self {
                value: lower_bound_plus_one,
            },
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

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: BlockNumber) {
        witness.set_target(self.value, F::from_canonical_u64(value.0));
    }
}
