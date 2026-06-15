use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    common::channel_id::{ChannelId, ChannelIdTarget},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
};

use crate::utils::{
    leafable::{Leafable, LeafableTarget},
    leafable_hasher::PoseidonLeafableHasher,
    poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
};

pub const TX_LEN: usize = POSEIDON_HASH_OUT_LEN + 1;
pub const CHANNEL_ACTION_LEN: usize = 1 + 1 + 1 + 8 + 8 + POSEIDON_HASH_OUT_LEN;
pub const TX_V2_LEN: usize = 1 + POSEIDON_HASH_OUT_LEN + 1 + POSEIDON_HASH_OUT_LEN;

/// A transaction, which contains multiple transfers of tokens.
#[derive(Clone, Default, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tx {
    /// The root of the transfer tree
    pub transfer_tree_root: PoseidonHashOut,

    /// The nonce of the sender's accounts
    pub nonce: u32,
}

impl Tx {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = self
            .transfer_tree_root
            .to_u64_vec()
            .into_iter()
            .chain(vec![self.nonce as u64])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), TX_LEN);
        vec
    }

    pub fn from_u64_slice(input: &[u64]) -> Result<Self, crate::common::error::CommonError> {
        if input.len() != TX_LEN {
            return Err(crate::common::error::CommonError::InvalidData(format!(
                "Invalid input length for Tx: expected {}, got {}",
                TX_LEN,
                input.len()
            )));
        }
        let transfer_tree_root = PoseidonHashOut::from_u64_slice(&input[0..4]).unwrap();
        let nonce = input[4] as u32;
        Ok(Self {
            transfer_tree_root,
            nonce,
        })
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            transfer_tree_root: PoseidonHashOut::rand(rng),
            nonce: rng.r#gen(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxTarget {
    pub transfer_tree_root: PoseidonHashOutTarget,
    pub nonce: Target,
}

impl TxTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            transfer_tree_root: PoseidonHashOutTarget::new(builder),
            nonce: builder.add_virtual_target(),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .transfer_tree_root
            .to_vec()
            .into_iter()
            .chain([self.nonce].iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), TX_LEN);
        vec
    }

    pub fn from_slice(input: &[Target]) -> Self {
        assert_eq!(input.len(), TX_LEN);
        let transfer_tree_root = PoseidonHashOutTarget::from_slice(&input[0..4]);
        let nonce = input[4];
        Self {
            transfer_tree_root,
            nonce,
        }
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.transfer_tree_root
            .connect(builder, other.transfer_tree_root);
        builder.connect(self.nonce, other.nonce);
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Tx,
    ) -> Self {
        Self {
            transfer_tree_root: PoseidonHashOutTarget::constant(builder, value.transfer_tree_root),
            nonce: builder.constant(F::from_canonical_u32(value.nonce)),
        }
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(&self, witness: &mut W, value: Tx) {
        self.transfer_tree_root
            .set_witness(witness, value.transfer_tree_root);
        witness.set_target(self.nonce, F::from_canonical_u32(value.nonce));
    }
}

impl Leafable for Tx {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

impl LeafableTarget for TxTarget {
    type Leaf = Tx;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        TxTarget::constant(builder, Tx::empty_leaf())
    }

    fn hash<F: RichField + Extendable<D>, C: 'static + GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum TxClass {
    #[default]
    UserTransfer = 0,
    ChannelAction = 1,
}

impl TxClass {
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    pub fn from_u32(value: u32) -> Result<Self, crate::common::error::CommonError> {
        match value {
            0 => Ok(Self::UserTransfer),
            1 => Ok(Self::ChannelAction),
            _ => Err(crate::common::error::CommonError::InvalidData(format!(
                "invalid tx class: {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum ChannelActionKind {
    #[default]
    InterChannelSend = 0,
    ChannelClose = 1,
}

impl ChannelActionKind {
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    pub fn from_u32(value: u32) -> Result<Self, crate::common::error::CommonError> {
        match value {
            0 => Ok(Self::InterChannelSend),
            1 => Ok(Self::ChannelClose),
            _ => Err(crate::common::error::CommonError::InvalidData(format!(
                "invalid channel action kind: {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelAction {
    pub kind: ChannelActionKind,
    pub source_channel_id: ChannelId,
    pub destination_channel_id: ChannelId,
    pub tx_hash: Bytes32,
    pub seal: Bytes32,
    pub payload_hash: PoseidonHashOut,
}

impl ChannelAction {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            vec![self.kind.as_u32() as u64],
            self.source_channel_id.to_u64_vec(),
            self.destination_channel_id.to_u64_vec(),
            self.tx_hash.to_u64_vec(),
            self.seal.to_u64_vec(),
            self.payload_hash.to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(input: &[u64]) -> Result<Self, crate::common::error::CommonError> {
        if input.len() != CHANNEL_ACTION_LEN {
            return Err(crate::common::error::CommonError::InvalidData(format!(
                "Invalid input length for ChannelAction: expected {}, got {}",
                CHANNEL_ACTION_LEN,
                input.len()
            )));
        }

        Ok(Self {
            kind: ChannelActionKind::from_u32(input[0] as u32)?,
            source_channel_id: ChannelId::from_u64(input[1]).map_err(|e| {
                crate::common::error::CommonError::InvalidData(format!(
                    "invalid source channel id: {e}"
                ))
            })?,
            destination_channel_id: ChannelId::from_u64(input[2]).map_err(|e| {
                crate::common::error::CommonError::InvalidData(format!(
                    "invalid destination channel id: {e}"
                ))
            })?,
            tx_hash: Bytes32::from_u64_slice(&input[3..11]).map_err(|e| {
                crate::common::error::CommonError::InvalidData(format!("invalid tx hash: {e}"))
            })?,
            seal: Bytes32::from_u64_slice(&input[11..19]).map_err(|e| {
                crate::common::error::CommonError::InvalidData(format!("invalid seal: {e}"))
            })?,
            payload_hash: PoseidonHashOut::from_u64_slice(&input[19..23]).map_err(|e| {
                crate::common::error::CommonError::InvalidData(format!("invalid payload hash: {e}"))
            })?,
        })
    }
}

impl Default for ChannelAction {
    fn default() -> Self {
        Self {
            kind: ChannelActionKind::InterChannelSend,
            source_channel_id: ChannelId::dummy(),
            destination_channel_id: ChannelId::dummy(),
            tx_hash: Bytes32::default(),
            seal: Bytes32::default(),
            payload_hash: PoseidonHashOut::default(),
        }
    }
}

impl Leafable for ChannelAction {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelActionTarget {
    pub kind: Target,
    pub source_channel_id: ChannelIdTarget,
    pub destination_channel_id: ChannelIdTarget,
    pub tx_hash: Bytes32Target,
    pub seal: Bytes32Target,
    pub payload_hash: PoseidonHashOutTarget,
}

impl ChannelActionTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            kind: builder.add_virtual_target(),
            source_channel_id: ChannelIdTarget::new(builder, is_checked),
            destination_channel_id: ChannelIdTarget::new(builder, is_checked),
            tx_hash: Bytes32Target::new(builder, is_checked),
            seal: Bytes32Target::new(builder, is_checked),
            payload_hash: PoseidonHashOutTarget::new(builder),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: ChannelAction,
    ) -> Self {
        Self {
            kind: builder.constant(F::from_canonical_u32(value.kind.as_u32())),
            source_channel_id: ChannelIdTarget::constant(builder, value.source_channel_id),
            destination_channel_id: ChannelIdTarget::constant(
                builder,
                value.destination_channel_id,
            ),
            tx_hash: Bytes32Target::constant(builder, value.tx_hash),
            seal: Bytes32Target::constant(builder, value.seal),
            payload_hash: PoseidonHashOutTarget::constant(builder, value.payload_hash),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            vec![self.kind],
            self.source_channel_id.to_vec(),
            self.destination_channel_id.to_vec(),
            self.tx_hash.to_vec(),
            self.seal.to_vec(),
            self.payload_hash.to_vec(),
        ]
        .concat()
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(&self, witness: &mut W, value: ChannelAction) {
        witness.set_target(self.kind, F::from_canonical_u32(value.kind.as_u32()));
        self.source_channel_id
            .set_witness(witness, value.source_channel_id);
        self.destination_channel_id
            .set_witness(witness, value.destination_channel_id);
        self.tx_hash.set_witness(witness, value.tx_hash);
        self.seal.set_witness(witness, value.seal);
        self.payload_hash.set_witness(witness, value.payload_hash);
    }
}

impl LeafableTarget for ChannelActionTarget {
    type Leaf = ChannelAction;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, ChannelAction::empty_leaf())
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxV2 {
    pub tx_class: TxClass,
    pub transfer_tree_root: PoseidonHashOut,
    pub nonce: u32,
    pub channel_action_root: PoseidonHashOut,
}

impl TxV2 {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            vec![self.tx_class.as_u32() as u64],
            self.transfer_tree_root.to_u64_vec(),
            vec![self.nonce as u64],
            self.channel_action_root.to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(input: &[u64]) -> Result<Self, crate::common::error::CommonError> {
        if input.len() != TX_V2_LEN {
            return Err(crate::common::error::CommonError::InvalidData(format!(
                "Invalid input length for TxV2: expected {}, got {}",
                TX_V2_LEN,
                input.len()
            )));
        }

        Ok(Self {
            tx_class: TxClass::from_u32(input[0] as u32)?,
            transfer_tree_root: PoseidonHashOut::from_u64_slice(&input[1..5]).map_err(|e| {
                crate::common::error::CommonError::InvalidData(format!(
                    "invalid transfer tree root: {e}"
                ))
            })?,
            nonce: input[5] as u32,
            channel_action_root: PoseidonHashOut::from_u64_slice(&input[6..10]).map_err(|e| {
                crate::common::error::CommonError::InvalidData(format!(
                    "invalid channel action root: {e}"
                ))
            })?,
        })
    }
}

impl Leafable for TxV2 {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxV2Target {
    pub tx_class: Target,
    pub transfer_tree_root: PoseidonHashOutTarget,
    pub nonce: Target,
    pub channel_action_root: PoseidonHashOutTarget,
}

impl TxV2Target {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            tx_class: builder.add_virtual_target(),
            transfer_tree_root: PoseidonHashOutTarget::new(builder),
            nonce: builder.add_virtual_target(),
            channel_action_root: PoseidonHashOutTarget::new(builder),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: TxV2,
    ) -> Self {
        Self {
            tx_class: builder.constant(F::from_canonical_u32(value.tx_class.as_u32())),
            transfer_tree_root: PoseidonHashOutTarget::constant(builder, value.transfer_tree_root),
            nonce: builder.constant(F::from_canonical_u32(value.nonce)),
            channel_action_root: PoseidonHashOutTarget::constant(
                builder,
                value.channel_action_root,
            ),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            vec![self.tx_class],
            self.transfer_tree_root.to_vec(),
            vec![self.nonce],
            self.channel_action_root.to_vec(),
        ]
        .concat()
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(&self, witness: &mut W, value: TxV2) {
        witness.set_target(
            self.tx_class,
            F::from_canonical_u32(value.tx_class.as_u32()),
        );
        self.transfer_tree_root
            .set_witness(witness, value.transfer_tree_root);
        witness.set_target(self.nonce, F::from_canonical_u32(value.nonce));
        self.channel_action_root
            .set_witness(witness, value.channel_action_root);
    }
}

impl LeafableTarget for TxV2Target {
    type Leaf = TxV2;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, TxV2::empty_leaf())
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }
}

#[cfg(test)]
mod tx_v2_tests {
    use super::*;

    #[test]
    fn tx_v2_roundtrip() {
        let tx = TxV2 {
            tx_class: TxClass::ChannelAction,
            transfer_tree_root: PoseidonHashOut::default(),
            nonce: 9,
            channel_action_root: PoseidonHashOut::default(),
        };
        let encoded = tx.to_u64_vec();
        let decoded = TxV2::from_u64_slice(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn channel_action_roundtrip() {
        let action = ChannelAction {
            kind: ChannelActionKind::InterChannelSend,
            source_channel_id: ChannelId::new(4).unwrap(),
            destination_channel_id: ChannelId::new(9).unwrap(),
            tx_hash: Bytes32::default(),
            seal: Bytes32::default(),
            payload_hash: PoseidonHashOut::default(),
        };
        let encoded = action.to_u64_vec();
        let decoded = ChannelAction::from_u64_slice(&encoded).unwrap();
        assert_eq!(action, decoded);
    }
}
