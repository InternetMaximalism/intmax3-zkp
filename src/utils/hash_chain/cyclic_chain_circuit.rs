use super::error::Result;
use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
            VerifierCircuitTarget,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::dummy_circuit::cyclic_base_proof,
};

use crate::{
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
    },
    utils::{cyclic::vd_vec_len, recursively_verifiable::add_proof_target_and_verify},
};

#[derive(Debug)]
pub struct CyclicChainCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    is_first_step: BoolTarget,
    inner_proof: ProofWithPublicInputsTarget<D>,
    prev_proof: ProofWithPublicInputsTarget<D>,
    verifier_data_target: VerifierCircuitTarget,
}

impl<F, C, const D: usize> CyclicChainCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(inner_verifier_data: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);
        let inner_proof = add_proof_target_and_verify(inner_verifier_data, &mut builder);
        let prev_hash = Bytes32Target::from_slice(&inner_proof.public_inputs[0..BYTES32_LEN]);
        let hash = Bytes32Target::from_slice(&inner_proof.public_inputs[BYTES32_LEN..]);
        builder.register_public_inputs(&hash.to_vec());

        let common_data = common_data_for_hash_chain_circuit::<F, C, D>();
        let verifier_data_target = builder.add_verifier_data_public_inputs();

        let prev_proof = builder.add_virtual_proof_with_pis(&common_data);
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_proof,
                &common_data,
            )
            .unwrap();
        let prev_pis = Bytes32Target::from_slice(&prev_proof.public_inputs[0..BYTES32_LEN]);
        prev_pis.connect(&mut builder, prev_hash);
        // initial condition
        let zero = Bytes32Target::zero::<F, D, Bytes32>(&mut builder);
        prev_hash.conditional_assert_eq(&mut builder, zero, is_first_step);

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(data.common, common_data);
        assert!(success);
        Self {
            data,
            is_first_step,
            inner_proof,
            prev_proof,
            verifier_data_target,
        }
    }

    pub fn prove(
        &self,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.verifier_data_target, &self.data.verifier_only);
        pw.set_proof_with_pis_target(&self.inner_proof, inner_proof);
        if prev_proof.is_none() {
            let dummy_proof = cyclic_base_proof(
                &self.data.common,
                &self.data.verifier_only,
                [].into_iter().collect(),
            );
            pw.set_bool_target(self.is_first_step, true);
            pw.set_proof_with_pis_target(&self.prev_proof, &dummy_proof);
        } else {
            pw.set_bool_target(self.is_first_step, false);
            pw.set_proof_with_pis_target(&self.prev_proof, prev_proof.as_ref().unwrap());
        }
        self.data.prove(pw).map_err(|e| {
            crate::utils::error::UtilsError::from(super::error::HashChainError::CyclicProofError(
                e.to_string(),
            ))
        })
    }

    /// TEST-ONLY forgery helper. Proves one non-first step whose verifier-data PUBLIC INPUTS are
    /// `verifier_data_public_inputs` instead of this circuit's own verifier data. The in-circuit
    /// `conditionally_verify_cyclic_proof_or_dummy` checks `prev_proof` against exactly those
    /// public inputs, so a `prev_proof` produced by `dummy_circuit(common)` with its own verifier
    /// data in the slots verifies, and the chain is seeded at whatever `prev_proof` claims in
    /// `PI[0..8]`. The resulting proof is a GENUINE proof of this circuit (it verifies under
    /// `self.data.verifier_data()` as a plain proof) — only `check_cyclic_proof_verifier_data`,
    /// or an outer circuit that connects the proof's verifier-data public inputs to its constant,
    /// can tell it apart from an honest chain. Consumers of a cyclic proof MUST do one of those
    /// two; the negative tests built on this helper pin that they do.
    #[cfg(test)]
    pub fn prove_with_verifier_data_public_inputs(
        &self,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data_public_inputs: &plonky2::plonk::circuit_data::VerifierOnlyCircuitData<C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.verifier_data_target, verifier_data_public_inputs);
        pw.set_proof_with_pis_target(&self.inner_proof, inner_proof);
        pw.set_bool_target(self.is_first_step, false);
        pw.set_proof_with_pis_target(&self.prev_proof, prev_proof);
        self.data.prove(pw).map_err(|e| {
            crate::utils::error::UtilsError::from(super::error::HashChainError::CyclicProofError(
                e.to_string(),
            ))
        })
    }
}

// Generates `CommonCircuitData` for the cyclic circuit
fn common_data_for_hash_chain_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>() -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << 13 {
        builder.add_gate(NoopGate, vec![]);
    }
    let mut common = builder.build::<C>().common;
    common.num_public_inputs = BYTES32_LEN + vd_vec_len(&common.config);
    common
}
