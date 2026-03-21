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
    recursion::cyclic_recursion::check_cyclic_proof_verifier_data,
};
use thiserror::Error;

use crate::{
    circuits::validity::signature_aggregation::sig_agg_pis::{
        SIG_AGG_PUBLIC_INPUTS_LEN, SigAggPublicInputsTarget,
    },
    utils::{
        cyclic::{add_noop_gates, simple_recursion_circuit_data, vd_vec_len},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

#[derive(Debug, Error)]
pub enum SigAggCircuitError {
    #[error("Failed to prove: {0}")]
    FailedToProve(String),

    #[error("Failed to verify: {0}")]
    ProofVerificationError(String),
}

pub struct SigAggCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub sig_agg_step_proof: ProofWithPublicInputsTarget<D>,
}

impl<F, C, const D: usize> SigAggCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        sig_agg_cd: &CommonCircuitData<F, D>,
        sig_agg_step_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(sig_agg_cd.config.clone());
        let sig_agg_step_proof = add_proof_target_and_verify(sig_agg_step_vd, &mut builder);
        let new_pis = SigAggPublicInputsTarget::from_pis(
            &sig_agg_step_proof.public_inputs,
            &sig_agg_cd.config,
        );
        builder.register_public_inputs(&new_pis.to_vec(&sig_agg_cd.config));

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(
            data.common,
            sig_agg_cd.clone(),
            "Common data mismatch in signature aggregation circuit",
        );
        assert!(success, "Failed to build signature aggregation circuit");

        Self {
            data,
            sig_agg_step_proof,
        }
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
        add_noop_gates(&mut builder, 1 << 12);
        let mut common = builder.build::<C>().common;
        common.num_public_inputs = SIG_AGG_PUBLIC_INPUTS_LEN + vd_vec_len(&common.config);
        common
    }

    pub fn prove(
        &self,
        sig_agg_step_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, SigAggCircuitError> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.sig_agg_step_proof, sig_agg_step_proof);

        self.data
            .prove(pw)
            .map_err(|e| SigAggCircuitError::FailedToProve(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), SigAggCircuitError> {
        check_cyclic_proof_verifier_data(proof, &self.data.verifier_only, &self.data.common)
            .map_err(|e| {
                SigAggCircuitError::ProofVerificationError(format!(
                    "Cyclic proof verifier data check failed: {:?}",
                    e
                ))
            })?;
        self.data.verify(proof.clone()).map_err(|e| {
            SigAggCircuitError::ProofVerificationError(format!(
                "Failed to verify proof: {:?}",
                e
            ))
        })
    }
}
