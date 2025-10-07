use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::balance::{
        balance_pis::{BalanceFullPublicInputs, BalancePublicInputsError},
        common::{
            account_state::AccountState, deposit_witness::DepositWitness,
            update_private_state::UpdatePrivateState, update_public_state::UpdatePublicState,
        },
    },
    common::block_number::BlockNumber,
};

#[derive(Debug, thiserror::Error)]
pub enum ReceiveDepositError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Balance public inputs error: {0}")]
    BalancePublicInputsError(#[from] BalancePublicInputsError),

    #[error("Invalid balance proof: {0}")]
    InvalidBalanceProof(String),

    #[error("Invalid balance verifier data: {0}")]
    InvalidBalanceVd(String),

    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("Block number error: {0}")]
    BlockNumberError(String),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),
}

#[derive(Clone, Debug)]
pub struct ReceiveDepositWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // Previous receiver balance proof
    pub prev_balance_proof: ProofWithPublicInputs<F, C, D>,

    // receiver's public state update
    pub update_public_state: UpdatePublicState,

    // receiver's new block_r
    pub new_block_r: BlockNumber,

    // account state that proves no outgoing tx (prev_balance_proof.block_r, new_block_r]
    pub account_state: AccountState,

    // deposit witness
    pub deposit_witness: DepositWitness,

    // private state update
    pub update_private_state: UpdatePrivateState,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveDepositWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<BalanceFullPublicInputs<F, C, D>, ReceiveDepositError> {
        todo!()
    }
}
