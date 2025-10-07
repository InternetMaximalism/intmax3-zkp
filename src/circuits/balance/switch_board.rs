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
    circuits::balance::balance_pis::{
        BalanceFullPublicInputs, BalancePublicInputs, BalancePublicInputsError,
    },
    common::{salt::Salt, user_id::UserId},
    utils::conversion::ToU64,
};

#[derive(thiserror::Error, Debug)]
pub enum BalanceSwitchBoardError {
    #[error("Invalid balance proof: {0}")]
    InvalidBalanceProof(String),

    #[error("Invalid balance verifier data: {0}")]
    InvalidBalanceVd(String),

    #[error("Balance public inputs error: {0}")]
    BalancePublicInputsError(#[from] BalancePublicInputsError),

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
        receive_transfer_vd: &VerifierCircuitData<F, C, D>,
        receive_deposit_vd: &VerifierCircuitData<F, C, D>,
        send_tx_vd: &VerifierCircuitData<F, C, D>,
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

        if self.receive_transfer_proof.is_some() {
            let proof = self.receive_transfer_proof.as_ref().unwrap();
            receive_transfer_vd.verify(proof.clone()).map_err(|e| {
                BalanceSwitchBoardError::InvalidBalanceProof(format!(
                    "receive transfer proof is invalid: {}",
                    e
                ))
            })?;
            let pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
                &proof.public_inputs.to_u64_vec(),
                &balance_vd.common.config,
            )?;
            return Ok(pis);
        }

        if self.receive_deposit_proof.is_some() {
            let proof = self.receive_deposit_proof.as_ref().unwrap();
            receive_deposit_vd.verify(proof.clone()).map_err(|e| {
                BalanceSwitchBoardError::InvalidBalanceProof(format!(
                    "receive deposit proof is invalid: {}",
                    e
                ))
            })?;
            let pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
                &proof.public_inputs.to_u64_vec(),
                &balance_vd.common.config,
            )?;
            return Ok(pis);
        }

        if self.send_tx_proof.is_some() {
            let proof = self.send_tx_proof.as_ref().unwrap();
            send_tx_vd.verify(proof.clone()).map_err(|e| {
                BalanceSwitchBoardError::InvalidBalanceProof(format!(
                    "send tx proof is invalid: {}",
                    e
                ))
            })?;
            let pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
                &proof.public_inputs.to_u64_vec(),
                &balance_vd.common.config,
            )?;
            return Ok(pis);
        }

        unreachable!()
    }
}
