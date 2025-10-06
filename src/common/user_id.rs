use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

use crate::constants::{LOCAL_ID_BITS, MAX_NUM_AGGREGATORS, USER_ID_BITS};

#[derive(Debug, thiserror::Error)]
pub enum UserIdError {
    #[error("Invalid aggregator ID: {0}")]
    InvalidAggregatorId(String),
    #[error("Invalid local ID: {0}")]
    InvalidLocalId(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserId(pub u64);

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
        let user_id = ((aggregator_id as u64) << 32) | (local_id as u64);
        Ok(Self(user_id))
    }

    pub fn dummy() -> Self {
        Self(0)
    }

    pub fn aggregator_id(&self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub fn local_id(&self) -> u32 {
        (self.0 & 0xFFFFFFFF) as u32
    }
}

#[derive(Clone, Debug)]
pub struct UserIdTarget {
    pub value: Target,
}

impl UserIdTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let value = builder.add_virtual_target();
        if is_checked {
            builder.range_check(value, USER_ID_BITS);
        }
        Self { value }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: UserId,
    ) -> Self {
        Self {
            value: builder.constant(F::from_canonical_u64(value.0)),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: UserId) {
        witness.set_target(self.value, F::from_canonical_u64(value.0));
    }

    pub fn aggregator_id<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let (_lo, hi) = builder.split_low_high(self.value, LOCAL_ID_BITS, USER_ID_BITS);
        hi
    }

    pub fn local_id<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let (lo, _hi) = builder.split_low_high(self.value, LOCAL_ID_BITS, USER_ID_BITS);
        lo
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        builder.connect(self.value, other.value);
    }
}
