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
    circuits::{
        validity::block_hash_chain::ext_public_state::ExtendedPublicState,
        withdraw::{
            withdrawal_chain_circuit::{WithdrawalChainCircuit, WithdrawalChainCircuitError},
            withdrawal_circuit::{WithdrawalCircuit, WithdrawalCircuitError},
            withdrawal_step::{WithdrawalStepCircuit, WithdrawalStepError, WithdrawalStepWitness},
        },
    },
    ethereum_types::address::Address,
};

#[derive(Debug, thiserror::Error)]
pub enum WithdrawalProcessorError {
    #[error("Withdrawal step circuit error: {0}")]
    WithdrawalStepCircuitError(#[from] WithdrawalStepError),

    #[error("Withdrawal chain circuit error: {0}")]
    WithdrawalChainCircuitError(#[from] WithdrawalChainCircuitError),

    #[error("Withdrawal circuit error: {0}")]
    WithdrawalCircuitError(#[from] WithdrawalCircuitError),
}

pub struct WithdrawalProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    withdrawal_step_circuit: WithdrawalStepCircuit<F, C, D>,
    withdrawal_chain_circuit: WithdrawalChainCircuit<F, C, D>,
    withdrawal_circuit: WithdrawalCircuit<F, C, D>,
}

impl<F, C, const D: usize> WithdrawalProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(single_withdrawal_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let withdrawal_chain_cd = WithdrawalChainCircuit::<F, C, D>::generate_cd();
        let withdrawal_step_circuit =
            WithdrawalStepCircuit::<F, C, D>::new(&withdrawal_chain_cd, single_withdrawal_vd);
        let withdrawal_chain_circuit = WithdrawalChainCircuit::<F, C, D>::new(
            &withdrawal_chain_cd,
            &withdrawal_step_circuit.data.verifier_data(),
        );
        let withdrawal_circuit =
            WithdrawalCircuit::<F, C, D>::new(&withdrawal_chain_circuit.data.verifier_data());

        Self {
            withdrawal_step_circuit,
            withdrawal_chain_circuit,
            withdrawal_circuit,
        }
    }

    pub fn withdrawal_step_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.withdrawal_step_circuit.data.verifier_data()
    }

    pub fn withdrawal_chain_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.withdrawal_chain_circuit.data.verifier_data()
    }

    pub fn withdrawal_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.withdrawal_circuit.data.verifier_data()
    }

    pub fn prove_step(
        &self,
        witness: &WithdrawalStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, WithdrawalProcessorError> {
        let withdrawal_chain_vd = self.withdrawal_chain_vd();
        let withdrawal_step_proof = self
            .withdrawal_step_circuit
            .prove(&withdrawal_chain_vd, witness)?;
        let withdrawal_chain_proof = self
            .withdrawal_chain_circuit
            .prove(&withdrawal_step_proof)?;
        Ok(withdrawal_chain_proof)
    }

    pub fn prove_final(
        &self,
        withdrawal_chain_proof: &ProofWithPublicInputs<F, C, D>,
        withdrawal_prover: Address,
        ext_public_state: &ExtendedPublicState,
    ) -> Result<ProofWithPublicInputs<F, C, D>, WithdrawalProcessorError> {
        let withdrawal_proof = self.withdrawal_circuit.prove(
            withdrawal_chain_proof,
            withdrawal_prover,
            ext_public_state,
        )?;
        Ok(withdrawal_proof)
    }
}
