use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuits::validity::forced_tx_hash_chain::{
    forced_tx_hash_chain_circuit::{ForcedTxHashChainCircuit, ForcedTxHashChainCircuitError},
    forced_tx_step::{ForcedTxStepCircuit, ForcedTxStepError, ForcedTxStepWitness},
};

#[derive(Debug, thiserror::Error)]
pub enum ForcedTxChainProcessorError {
    #[error("Forced tx step circuit error: {0}")]
    ForcedTxStepCircuitError(#[from] ForcedTxStepError),

    #[error("Forced tx hash chain circuit error: {0}")]
    ForcedTxHashChainCircuitError(#[from] ForcedTxHashChainCircuitError),
}

pub struct ForcedTxChainProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    forced_tx_step_circuit: ForcedTxStepCircuit<F, C, D>,
    forced_tx_hash_chain_circuit: ForcedTxHashChainCircuit<F, C, D>,
}

impl<F, C, const D: usize> ForcedTxChainProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let forced_tx_chain_cd = ForcedTxHashChainCircuit::<F, C, D>::generate_cd();
        let forced_tx_step_circuit = ForcedTxStepCircuit::<F, C, D>::new(&forced_tx_chain_cd);
        let forced_tx_hash_chain_circuit = ForcedTxHashChainCircuit::<F, C, D>::new(
            &forced_tx_chain_cd,
            &forced_tx_step_circuit.data.verifier_data(),
        );
        Self {
            forced_tx_step_circuit,
            forced_tx_hash_chain_circuit,
        }
    }

    pub fn forced_tx_chain_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.forced_tx_hash_chain_circuit.data.verifier_data()
    }

    pub fn prove_step(
        &self,
        witness: &ForcedTxStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ForcedTxChainProcessorError> {
        let forced_tx_step_proof = self
            .forced_tx_step_circuit
            .prove(&self.forced_tx_chain_vd(), witness)?;
        let forced_tx_chain_proof = self
            .forced_tx_hash_chain_circuit
            .prove(&forced_tx_step_proof)?;
        Ok(forced_tx_chain_proof)
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), ForcedTxHashChainCircuitError> {
        self.forced_tx_hash_chain_circuit.verify(proof)
    }
}
