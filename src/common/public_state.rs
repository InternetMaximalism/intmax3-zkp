use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    common::block_number::{BlockNumber, BlockNumberTarget},
    utils::{
        leafable::{Leafable, LeafableTarget},
        leafable_hasher::PoseidonLeafableHasher,
        poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
    },
};

pub const PUBLIC_STATE_U64_LEN: usize = 1 + 3 * POSEIDON_HASH_OUT_LEN;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicState {
    pub block_number: BlockNumber,
    pub account_tree_root: PoseidonHashOut,
    pub deposit_tree_root: PoseidonHashOut,
    pub prev_public_state_root: PoseidonHashOut,
}

#[derive(Clone, Debug)]
pub struct PublicStateTarget {
    pub block_number: BlockNumberTarget,
    pub account_tree_root: PoseidonHashOutTarget,
    pub deposit_tree_root: PoseidonHashOutTarget,
    pub prev_public_state_root: PoseidonHashOutTarget,
}

impl PublicState {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.block_number.to_u64_vec(),
            self.account_tree_root.to_u64_vec(),
            self.deposit_tree_root.to_u64_vec(),
            self.prev_public_state_root.to_u64_vec(),
        ]
        .concat()
    }

    pub fn poseidon_hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

impl Leafable for PublicState {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        self.poseidon_hash()
    }
}

impl PublicStateTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.block_number.to_vec(),
            self.account_tree_root.to_vec(),
            self.deposit_tree_root.to_vec(),
            self.prev_public_state_root.to_vec(),
        ]
        .concat()
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            block_number: BlockNumberTarget::new(builder, is_checked),
            account_tree_root: PoseidonHashOutTarget::new(builder),
            deposit_tree_root: PoseidonHashOutTarget::new(builder),
            prev_public_state_root: PoseidonHashOutTarget::new(builder),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &PublicState,
    ) -> Self {
        Self {
            block_number: BlockNumberTarget::constant(builder, value.block_number),
            account_tree_root: PoseidonHashOutTarget::constant(builder, value.account_tree_root),
            deposit_tree_root: PoseidonHashOutTarget::constant(builder, value.deposit_tree_root),
            prev_public_state_root: PoseidonHashOutTarget::constant(
                builder,
                value.prev_public_state_root,
            ),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &PublicState) {
        self.block_number.set_witness(witness, value.block_number);
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        self.deposit_tree_root
            .set_witness(witness, value.deposit_tree_root);
        self.prev_public_state_root
            .set_witness(witness, value.prev_public_state_root);
    }

    pub fn is_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> BoolTarget {
        let block_eq = self.block_number.is_equal(builder, &other.block_number);
        let account_eq = self
            .account_tree_root
            .is_equal(builder, &other.account_tree_root);
        let deposit_eq = self
            .deposit_tree_root
            .is_equal(builder, &other.deposit_tree_root);
        let prev_state_eq = self
            .prev_public_state_root
            .is_equal(builder, &other.prev_public_state_root);

        let tmp = builder.and(block_eq, account_eq);
        let tmp = builder.and(tmp, deposit_eq);
        builder.and(tmp, prev_state_eq)
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        builder.connect(self.block_number.value, other.block_number.value);
        self.account_tree_root
            .connect(builder, other.account_tree_root.clone());
        self.deposit_tree_root
            .connect(builder, other.deposit_tree_root.clone());
        self.prev_public_state_root
            .connect(builder, other.prev_public_state_root.clone());
    }
}

impl LeafableTarget for PublicStateTarget {
    type Leaf = PublicState;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, &PublicState::default())
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
