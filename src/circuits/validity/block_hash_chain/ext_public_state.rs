use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use thiserror::Error;

use crate::{
    common::{
        public_state::{PUBLIC_STATE_U64_LEN, PublicState, PublicStateError, PublicStateTarget},
        u63::{U63, U63Target},
    },
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
};

pub const EXTENDED_PUBLIC_STATE_U64_LEN: usize = PUBLIC_STATE_U64_LEN + BYTES32_LEN + 1;

#[derive(Debug, Error)]
pub enum ExtendedPublicStateError {
    #[error("Invalid length: {0}")]
    InvalidLength(String),

    #[error("Public state error: {0}")]
    PublicState(#[from] PublicStateError),

    #[error("Bytes32 error: {0}")]
    Bytes32(String),
}

#[derive(Clone, Debug, Default)]
pub struct ExtendedPublicState {
    pub inner: PublicState,
    pub deposit_hash_chain: Bytes32,
    pub deposit_count: U63,
}

impl ExtendedPublicState {
    pub fn new(inner: PublicState, deposit_hash_chain: Bytes32, deposit_count: U63) -> Self {
        Self {
            inner,
            deposit_hash_chain,
            deposit_count,
        }
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.inner.to_u64_vec(),
            self.deposit_hash_chain.to_u64_vec(),
            self.deposit_count.to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, ExtendedPublicStateError> {
        if values.len() != EXTENDED_PUBLIC_STATE_U64_LEN {
            return Err(ExtendedPublicStateError::InvalidLength(format!(
                "expected {EXTENDED_PUBLIC_STATE_U64_LEN} elements, got {}",
                values.len()
            )));
        }

        let mut cursor = 0;

        let inner = PublicState::from_u64_slice(&values[cursor..cursor + PUBLIC_STATE_U64_LEN])?;
        cursor += PUBLIC_STATE_U64_LEN;

        let deposit_hash_chain = Bytes32::from_u64_slice(&values[cursor..cursor + BYTES32_LEN])
            .map_err(|e| ExtendedPublicStateError::Bytes32(e.to_string()))?;
        cursor += BYTES32_LEN;

        let deposit_count = U63::new(values[cursor]).map_err(|e| {
            ExtendedPublicStateError::InvalidLength(format!("invalid deposit count: {e}"))
        })?;

        Ok(Self {
            inner,
            deposit_hash_chain,
            deposit_count,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ExtendedPublicStateTarget {
    pub inner: PublicStateTarget,
    pub deposit_hash_chain: Bytes32Target,
    pub deposit_count: U63Target,
}

impl ExtendedPublicStateTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            inner: PublicStateTarget::new(builder, is_checked),
            deposit_hash_chain: Bytes32Target::new::<F, D>(builder, is_checked),
            deposit_count: U63Target::new(builder, is_checked),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &ExtendedPublicState,
    ) -> Self {
        Self {
            inner: PublicStateTarget::constant(builder, &value.inner),
            deposit_hash_chain: Bytes32Target::constant::<F, D, Bytes32>(
                builder,
                value.deposit_hash_chain,
            ),
            deposit_count: U63Target::constant(builder, value.deposit_count),
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, const D: usize, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &ExtendedPublicState,
    ) {
        self.inner.set_witness(witness, &value.inner);
        self.deposit_hash_chain
            .set_witness(witness, value.deposit_hash_chain);
        self.deposit_count.set_witness(witness, value.deposit_count);
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.inner.connect(builder, &other.inner);
        self.deposit_hash_chain
            .connect(builder, other.deposit_hash_chain);
        self.deposit_count.connect(builder, &other.deposit_count);
    }

    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        when_true: &Self,
        when_false: &Self,
    ) -> Self {
        Self {
            inner: PublicStateTarget::select(
                builder,
                condition,
                &when_true.inner,
                &when_false.inner,
            ),
            deposit_hash_chain: Bytes32Target::select(
                builder,
                condition,
                when_true.deposit_hash_chain.clone(),
                when_false.deposit_hash_chain.clone(),
            ),
            deposit_count: U63Target::select(
                builder,
                condition,
                &when_true.deposit_count,
                &when_false.deposit_count,
            ),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.inner.to_vec(),
            self.deposit_hash_chain.to_vec(),
            self.deposit_count.to_vec(),
        ]
        .concat()
    }

    pub fn from_slice(values: &[Target]) -> Self {
        assert_eq!(
            values.len(),
            EXTENDED_PUBLIC_STATE_U64_LEN,
            "ExtendedPublicStateTarget::from_slice length mismatch",
        );

        let mut cursor = 0;
        let inner = PublicStateTarget::from_slice(&values[cursor..cursor + PUBLIC_STATE_U64_LEN]);
        cursor += PUBLIC_STATE_U64_LEN;

        let deposit_hash_chain = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let deposit_count = U63Target::from_slice(&values[cursor..cursor + 1]);

        Self {
            inner,
            deposit_hash_chain,
            deposit_count,
        }
    }
}
