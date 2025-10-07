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
    circuits::balance::balance_pis::{BalanceFullPublicInputs, BalancePublicInputs},
    common::{salt::Salt, user_id::UserId},
};

#[derive(thiserror::Error, Debug)]
pub enum BalanceSwitchBoardError {
    #[error("Invalid balance proof: {0}")]
    InvalidBalanceProof(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub struct BalanceSwichBoard<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_value: Option<(UserId, Salt)>,
    pub receive_transfer_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub receive_deposit_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub send_tx_proof: Option<ProofWithPublicInputs<F, C, D>>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    BalanceSwichBoard<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<BalanceFullPublicInputs<F, C, D>, BalanceSwitchBoardError> {
        // number of initial value or proofs must be exactly one
        let total = self.initial_value.is_some() as u8
            + self.receive_transfer_proof.is_some() as u8
            + self.receive_deposit_proof.is_some() as u8
            + self.send_tx_proof.is_some() as u8;
        if total != 1 {
            return Err(BalanceSwitchBoardError::InvalidInput(
                "exactly one of initial value or proofs must be provided".to_string(),
            ));
        }

        if self.initial_value.is_some() {
            let (user_id, salt) = self.initial_value.unwrap();
            let pis = BalancePublicInputs::new(user_id, salt);
            return Ok(BalanceFullPublicInputs {
                pis,
                vd: balance_vd.verifier_only.clone(),
            });
        }

        todo!()
    }
}
