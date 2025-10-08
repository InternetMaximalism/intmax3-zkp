use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{
    common::u63::U63, ethereum_types::bytes32::Bytes32, utils::poseidon_hash_out::PoseidonHashOut,
};

pub struct DepositChainPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_deposit_hash_chain: Bytes32,
    pub initial_deposit_tree_root: PoseidonHashOut,
    pub initial_deposit_count: U63,
    pub deposit_hash_chain: Bytes32,
    pub deposit_tree_root: Bytes32,
    pub deposit_count: U63,
    pub vd: VerifierOnlyCircuitData<C, D>,
}
