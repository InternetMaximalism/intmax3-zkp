use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};

use crate::{
    circuits::balance::balance_pis::BalancePublicInputs,
    common::{private_state::FullPrivateState, salt::Salt, user_id::UserId},
};

#[derive(Debug, Clone)]
pub enum BalanceWitnessGeneratorError {}

// generate witness for balance processor
#[derive(Clone, Debug)]
pub struct BalanceWitnessGenerator<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub user_id: UserId,
    pub salt: Salt,
    pub balance_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub full_private_state: FullPrivateState,
}

impl<F, C, const D: usize> BalanceWitnessGenerator<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn new(user_id: UserId, salt: Salt) -> Self {
        Self {
            user_id,
            salt,
            balance_proof: None,
            full_private_state: FullPrivateState::new(salt),
        }
    }

    // get balance public inputs from the witness generator
    pub fn get_public_inputs(&self) -> Result<BalancePublicInputs, BalanceWitnessGeneratorError> {
        todo!()
    }
}
