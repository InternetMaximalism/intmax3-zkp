use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

use crate::ethereum_types::{
    u32limb_trait::U32LimbTargetTrait as _,
    u64::{U64, U64Target},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserId(pub u64);

impl UserId {
    pub fn new(aggregator_id: u32, local_id: u32) -> Self {
        let user_id = ((aggregator_id as u64) << 32) | (local_id as u64);
        Self(user_id)
    }

    pub fn aggregator_id(&self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub fn local_id(&self) -> u32 {
        (self.0 & 0xFFFFFFFF) as u32
    }

    pub fn to_u64(&self) -> U64 {
        U64::from(self.0)
    }
}

#[derive(Clone, Debug)]
pub struct UserIdTarget {
    pub value: U64Target,
}

impl UserIdTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let value = U64Target::new(builder, is_checked);
        Self { value }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: UserId,
    ) -> Self {
        Self {
            value: U64Target::constant(builder, value.to_u64()),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: UserId) {
        self.value.set_witness(witness, value.to_u64());
    }

    pub fn aggregator_id(&self) -> Target {
        self.value.to_vec()[0]
    }

    pub fn local_id(&self) -> Target {
        self.value.to_vec()[1]
    }
}
