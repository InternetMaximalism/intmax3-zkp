use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite as _},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
            VerifierCircuitTarget,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use thiserror::Error;

use crate::{
    circuits::balance::balance_pis::{BALANCE_PUBLIC_INPUTS_LEN, BalanceFullPublicInputsTarget},
    utils::{
        cyclic::{add_noop_gates, simple_recursion_circuit_data, vd_vec_len},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

#[derive(Debug, Error)]
pub enum BalanceCircuitError {
    #[error("Failed to prove: {0}")]
    FailedToProve(String),
}

pub struct BalanceCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub switch_proof: ProofWithPublicInputsTarget<D>,
}

impl<F, C, const D: usize> BalanceCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        balance_cd: &CommonCircuitData<F, D>,
        switch_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let switch_proof = add_proof_target_and_verify(switch_vd, &mut builder);
        let new_balance_pis = BalanceFullPublicInputsTarget::from_pis(
            &switch_proof.public_inputs,
            &balance_cd.config,
        );
        builder.register_public_inputs(&new_balance_pis.to_vec(&balance_cd.config));

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(
            data.common,
            balance_cd.clone(),
            "Common data mismatch in balance circuit"
        );
        assert!(success, "Failed to build balance circuit");

        Self { data, switch_proof }
    }

    pub fn generate_cd() -> CommonCircuitData<F, D> {
        let data = simple_recursion_circuit_data::<F, C, D>();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
        // pad degree should be ajusted to fullfill common data equality
        add_noop_gates(&mut builder, 1 << 12);
        let mut common = builder.build::<C>().common;
        common.num_public_inputs = BALANCE_PUBLIC_INPUTS_LEN + vd_vec_len(&common.config);
        common
    }

    pub fn prove(
        &self,
        switch_board_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceCircuitError> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.switch_proof, switch_board_proof);

        self.data
            .prove(pw)
            .map_err(|e| BalanceCircuitError::FailedToProve(e.to_string()))
    }
}
