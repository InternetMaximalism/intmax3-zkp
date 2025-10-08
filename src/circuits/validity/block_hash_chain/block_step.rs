use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

pub struct BlockStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // Previous block hash chain proof
    pub prev_block_chain_proof: ProofWithPublicInputs<F, C, D>,

    pub num_users: u32,
    pub update_account_proof: ProofWithPublicInputs<F, C, D>,
}
