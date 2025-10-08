use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{CommonCircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::block_hash_chain::block_chain_pis::BlockChainPublicInputs,
    common::trees::public_state_tree::PublicStateMerkleProof,
};

#[derive(Debug, thiserror::Error)]
pub enum BlockStepError {}

pub struct BlockStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // Previous block hash chain proof if not the first block
    pub prev_block_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,

    // Deposit hash chain proof if there is a deposit in this block
    pub deposit_hash_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,

    // paddind number of users in this block
    pub num_users: u32,

    // Update account proof if not num_users == 0
    pub update_account_proof: Option<ProofWithPublicInputs<F, C, D>>,

    // Merkle proof to update public state tree
    pub public_state_merkle_proof: PublicStateMerkleProof,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    BlockStepWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        block_chain_cd: &CommonCircuitData<F, D>,
        update_account_vds: &[(u32, VerifierCircuitData<F, C, D>)],
    ) -> Result<BlockChainPublicInputs<F, C, D>, BlockStepError> {
        todo!()
    }
}
