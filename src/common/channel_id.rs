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
use std::convert::TryFrom;
use thiserror::Error;

use crate::constants::CHANNEL_ID_BITS;

#[derive(Debug, Error)]
pub enum ChannelIdError {
    #[error("Invalid channel ID: {0}")]
    InvalidChannelId(String),
    #[error("Invalid raw value: {0}")]
    InvalidValue(String),
}

/// Canonical channel identifier, shared by the BASE intmax layer and the channel layer.
///
/// SECURITY / ARCHITECTURE: in the enshrined-payment-channel design the base intmax native
/// "user" IS the channel. The identifier therefore carries ONLY `channel_id` (a single u32
/// limb); per-member `key_id` exists exclusively in the channel layer (`crate::common::channel`,
/// the `UserId([u8;8])` member identity). The packed value is the channel id and doubles as the
/// channel-tree Merkle index (32-bit space).
///
/// SECURITY: the channel layer computes keccak `signing_digest`s from this type via
/// `to_u32_vec()` / `as_bytes()` / `as_u64()`. Those outputs MUST stay byte-identical to the
/// legacy `[u8;4]`-backed `ChannelId`: for value `v`, `to_u32_vec() == vec![v]`,
/// `to_u64_vec() == vec![v as u64]`, `as_u64() == v as u64`, `as_bytes() == v.to_be_bytes()`,
/// and `from_bytes(b) == u32::from_be_bytes(b)`. The u32 backing satisfies all of these.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelId(u32);

impl ChannelId {
    /// Construct a channel id from a raw value. `value = 0` is reserved for the dummy.
    ///
    /// SECURITY: accepts a `u64` so both layers share one constructor. The channel layer's legacy
    /// `ChannelId::new(u64)` enforced the 32-bit range; this constructor keeps that range check
    /// and additionally rejects the reserved `0` id (the base layer always rejected `0`).
    pub fn new(value: u64) -> Result<Self, ChannelIdError> {
        let channel_id = u32::try_from(value).map_err(|_| {
            ChannelIdError::InvalidValue(format!("channel id {value} does not fit in 4 bytes"))
        })?;
        Self::validate_components(channel_id)?;
        Ok(Self(channel_id))
    }

    pub fn dummy() -> Self {
        Self(0)
    }

    pub fn channel_id(&self) -> u32 {
        self.0
    }

    pub fn as_u63(&self) -> u64 {
        self.0 as u64
    }

    pub fn as_u64(&self) -> u64 {
        self.0 as u64
    }

    /// SECURITY: byte layout MUST equal the legacy `[u8;4]` big-endian encoding so keccak
    /// preimages are unchanged.
    pub fn as_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// SECURITY: inverse of `as_bytes`; rejects the reserved `0` id exactly like the legacy
    /// `[u8;4]`-backed `ChannelId::from_bytes`.
    pub fn from_bytes(bytes: [u8; 4]) -> Result<Self, ChannelIdError> {
        let channel_id = u32::from_be_bytes(bytes);
        Self::validate_components(channel_id)?;
        Ok(Self(channel_id))
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        vec![self.0]
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        vec![self.0 as u64]
    }

    pub fn from_u63(value: u64) -> Result<Self, ChannelIdError> {
        Self::from_u64(value)
    }

    pub fn from_u64(value: u64) -> Result<Self, ChannelIdError> {
        Self::new(value)
    }

    /// SECURITY: parses the single-word u32 limb encoding used by the channel-layer digests.
    pub fn from_u64_slice(values: &[u64]) -> Result<Self, ChannelIdError> {
        if values.len() != 1 {
            return Err(ChannelIdError::InvalidValue(format!(
                "channel id expects a single u32 limb, got {}",
                values.len()
            )));
        }
        Self::from_u64(values[0])
    }

    fn validate_components(channel_id: u32) -> Result<(), ChannelIdError> {
        if channel_id == 0 {
            return Err(ChannelIdError::InvalidChannelId(
                "channel_id=0 is reserved for dummy".to_string(),
            ));
        }
        Ok(())
    }
}

impl From<ChannelId> for u64 {
    fn from(value: ChannelId) -> Self {
        value.0 as u64
    }
}

impl From<&ChannelId> for u64 {
    fn from(value: &ChannelId) -> Self {
        value.0 as u64
    }
}

impl TryFrom<u64> for ChannelId {
    type Error = ChannelIdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_u64(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelIdTarget {
    pub value: Target,
}

impl ChannelIdTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let value = builder.add_virtual_target();
        if is_checked {
            builder.range_check(value, CHANNEL_ID_BITS);
        }
        Self { value }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: ChannelId,
    ) -> Self {
        Self {
            value: builder.constant(F::from_canonical_u64(value.as_u64())),
        }
    }

    /// Build a channel id target from its `channel_id` limb.
    pub fn from_parts<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        channel_id: Target,
        is_checked: bool,
    ) -> Self {
        if is_checked {
            builder.range_check(channel_id, CHANNEL_ID_BITS);
        }
        Self { value: channel_id }
    }

    pub fn from_slice(values: &[Target]) -> Self {
        assert_eq!(values.len(), 1, "ChannelIdTarget expects a single target");
        Self { value: values[0] }
    }

    pub fn from_u32_slice<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        limbs: &[Target],
        is_checked: bool,
    ) -> Self {
        assert_eq!(
            limbs.len(),
            1,
            "ChannelIdTarget expects a single u32 limb (channel_id)"
        );
        Self::from_parts(builder, limbs[0], is_checked)
    }

    pub fn from_u64_slice(limbs: &[Target]) -> Self {
        Self::from_slice(limbs)
    }

    pub fn to_vec(&self) -> Vec<Target> {
        vec![self.value]
    }

    pub fn to_u32_vec<F: RichField + Extendable<D>, const D: usize>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        vec![self.value]
    }

    pub fn to_u64_vec(&self) -> Vec<Target> {
        vec![self.value]
    }

    pub fn channel_id<F: RichField + Extendable<D>, const D: usize>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        self.value
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
        builder.range_check(diff, CHANNEL_ID_BITS);
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
        builder.range_check(diff_when_true, CHANNEL_ID_BITS);
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
        Self {
            value: builder.select(condition, when_true.value, when_false.value),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: ChannelId) {
        witness.set_target(self.value, F::from_canonical_u64(value.as_u64()));
    }
}
