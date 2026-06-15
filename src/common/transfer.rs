use crate::{
    common::{
        channel_id::{ChannelId, ChannelIdTarget},
        u63::{BlockNumber, BlockNumberTarget},
    },
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
        u256::{U256, U256_LEN, U256Target},
    },
    utils::{
        leafable::{Leafable, LeafableTarget},
        leafable_hasher::PoseidonLeafableHasher,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};
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

pub const TRANSFER_LEN: usize = BYTES32_LEN + 1 + U256_LEN + BYTES32_LEN;

/// A transfer of tokens from one account to another
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transfer {
    pub recipient: Bytes32,
    pub token_index: u32,
    pub amount: U256,
    pub aux_data: Bytes32,
}

/// Transfer that is already settled in the chain, which is used to derive nullifier
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettledTransfer {
    pub inner: Transfer,
    pub from: ChannelId,
    pub transfer_index: u32,
    pub block_number: BlockNumber,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferTarget {
    pub recipient: Bytes32Target,
    pub token_index: Target,
    pub amount: U256Target,
    pub aux_data: Bytes32Target,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettledTransferTarget {
    pub inner: TransferTarget,
    pub from: ChannelIdTarget,
    pub transfer_index: Target,
    pub block_number: BlockNumberTarget,
}

impl Transfer {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = self
            .recipient
            .to_u64_vec()
            .into_iter()
            .chain([self.token_index as u64].iter().copied())
            .chain(self.amount.to_u64_vec())
            .chain(self.aux_data.to_u64_vec())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), TRANSFER_LEN);
        vec
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            recipient: U256::rand(rng).into(),
            token_index: rng.r#gen(),
            amount: U256::rand_small(rng),
            aux_data: Bytes32::rand(rng),
        }
    }

    pub fn poseidon_hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

impl SettledTransfer {
    pub fn new(
        inner: Transfer,
        from: ChannelId,
        transfer_index: u32,
        block_number: BlockNumber,
    ) -> Self {
        Self {
            inner,
            from,
            transfer_index,
            block_number,
        }
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.inner.to_u64_vec(),
            self.from.to_u64_vec(),
            vec![self.transfer_index as u64],
            self.block_number.to_u64_vec(),
        ]
        .concat()
    }

    pub fn poseidon_hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }

    pub fn nullifier(&self) -> Bytes32 {
        self.poseidon_hash().into()
    }
}

impl TransferTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .recipient
            .to_vec()
            .into_iter()
            .chain([self.token_index].iter().copied())
            .chain(self.amount.to_vec())
            .chain(self.aux_data.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), TRANSFER_LEN);
        vec
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            recipient: Bytes32Target::new(builder, is_checked),
            token_index: builder.add_virtual_target(),
            amount: U256Target::new(builder, is_checked),
            aux_data: Bytes32Target::new(builder, is_checked),
        }
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.recipient.connect(builder, other.recipient);
        builder.connect(self.token_index, other.token_index);
        self.amount.connect(builder, other.amount);
        self.aux_data.connect(builder, other.aux_data);
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Transfer,
    ) -> Self {
        Self {
            recipient: Bytes32Target::constant(builder, value.recipient),
            token_index: builder.constant(F::from_canonical_u32(value.token_index)),
            amount: U256Target::constant(builder, value.amount),
            aux_data: Bytes32Target::constant(builder, value.aux_data),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &Transfer) {
        self.recipient.set_witness(witness, value.recipient);
        witness.set_target(self.token_index, F::from_canonical_u32(value.token_index));
        self.amount.set_witness(witness, value.amount);
        self.aux_data.set_witness(witness, value.aux_data);
    }

    pub fn poseidon_hash<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }
}

impl SettledTransferTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            inner: TransferTarget::new(builder, is_checked),
            from: ChannelIdTarget::new(builder, is_checked),
            transfer_index: builder.add_virtual_target(),
            block_number: BlockNumberTarget::new(builder, is_checked),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &SettledTransfer,
    ) -> Self {
        Self {
            inner: TransferTarget::constant(builder, value.inner.clone()),
            from: ChannelIdTarget::constant(builder, value.from),
            transfer_index: builder.constant(F::from_canonical_u32(value.transfer_index)),
            block_number: BlockNumberTarget::constant(builder, value.block_number),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.inner.to_vec(),
            self.from.to_vec(),
            vec![self.transfer_index],
            self.block_number.to_vec(),
        ]
        .concat()
    }

    pub fn nullifier<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target {
        let hash = PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec());
        Bytes32Target::from_hash_out(builder, hash)
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &SettledTransfer,
    ) {
        self.inner.set_witness(witness, &value.inner);
        self.from.set_witness(witness, value.from);
        witness.set_target(
            self.transfer_index,
            F::from_canonical_u32(value.transfer_index),
        );
        self.block_number.set_witness(witness, value.block_number);
    }
}

impl Leafable for Transfer {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(self.to_u64_vec().as_slice())
    }
}

impl LeafableTarget for TransferTarget {
    type Leaf = Transfer;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = <Transfer as Leafable>::empty_leaf();
        TransferTarget::constant(builder, empty_leaf)
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
