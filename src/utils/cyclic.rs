use crate::utils::error::{CyclicError, Result, UtilsError};
use anyhow::Context;
use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::{
        hash_types::{HashOut, HashOutTarget, MerkleCapTarget, RichField},
        merkle_tree::MerkleCap,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig, GenericHashOut as _},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::dummy_circuit::cyclic_base_proof,
};

pub fn vd_vec_len(config: &CircuitConfig) -> usize {
    4 + 4 * config.fri_config.num_cap_elements()
}

pub fn vd_to_vec<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    config: &CircuitConfig,
    vd: &VerifierOnlyCircuitData<C, D>,
) -> Vec<F> {
    let mut vec = vec![];
    vec.extend_from_slice(&vd.circuit_digest.to_vec());
    for i in 0..config.fri_config.num_cap_elements() {
        vec.extend_from_slice(&vd.constants_sigmas_cap.0[i].to_vec());
    }
    vec
}

pub fn vd_to_vec_target(config: &CircuitConfig, vd: &VerifierCircuitTarget) -> Vec<Target> {
    let mut vec = vec![];
    vec.extend_from_slice(&vd.circuit_digest.elements);
    for i in 0..config.fri_config.num_cap_elements() {
        vec.extend_from_slice(&vd.constants_sigmas_cap.0[i].elements);
    }
    vec
}

pub fn vd_from_pis_slice<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    slice: &[F],
    config: &CircuitConfig,
) -> Result<VerifierOnlyCircuitData<C, D>>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let cap_len = config.fri_config.num_cap_elements();
    let len = slice.len();
    if len < 4 + 4 * cap_len {
        return Err(UtilsError::from(CyclicError::NotEnoughPublicInputs));
    }
    let constants_sigmas_cap = MerkleCap(
        (0..cap_len)
            .map(|i| HashOut {
                elements: core::array::from_fn(|j| slice[len - 4 * (cap_len - i) + j]),
            })
            .collect(),
    );
    let circuit_digest = HashOut {
        elements: core::array::from_fn(|i| slice[len - 4 - 4 * cap_len + i]),
    };
    Ok(VerifierOnlyCircuitData {
        circuit_digest,
        constants_sigmas_cap,
    })
}

pub fn vd_from_pis_slice_target(
    slice: &[Target],
    config: &CircuitConfig,
) -> Result<VerifierCircuitTarget> {
    let cap_len = config.fri_config.num_cap_elements();
    let len = slice.len();
    if len < 4 + 4 * cap_len {
        return Err(UtilsError::from(CyclicError::NotEnoughPublicInputs));
    }
    let constants_sigmas_cap = MerkleCapTarget(
        (0..cap_len)
            .map(|i| HashOutTarget {
                elements: core::array::from_fn(|j| slice[len - 4 * (cap_len - i) + j]),
            })
            .collect(),
    );
    let circuit_digest = HashOutTarget {
        elements: core::array::from_fn(|i| slice[len - 4 - 4 * cap_len + i]),
    };
    Ok(VerifierCircuitTarget {
        circuit_digest,
        constants_sigmas_cap,
    })
}

pub fn conditionally_connect_vd<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    condition: BoolTarget,
    vk0: &VerifierCircuitTarget,
    vk1: &VerifierCircuitTarget,
) {
    let selected_vd = builder.select_verifier_data(condition, vk0, vk1);
    builder.connect_verifier_data(&selected_vd, vk1);
}

pub fn add_noop_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    target_num_gates: u64,
) {
    while (builder.num_gates() as u64) < target_num_gates {
        builder.add_gate(NoopGate, vec![]);
    }
}

pub fn simple_recursion_circuit_data<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>() -> CircuitData<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
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
    builder.build::<C>()
}

pub struct TestCyclicCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub pis_len: usize,
    pub data: CircuitData<F, C, D>,
    pub is_first_step: BoolTarget,
    pub prev_proof: ProofWithPublicInputsTarget<D>,
    pub vd: VerifierCircuitTarget,
}

impl<F, C, const D: usize> TestCyclicCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(config: CircuitConfig, pis_len: usize, cd: &CommonCircuitData<F, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);
        let prev_proof = builder.add_virtual_proof_with_pis(cd);

        // parse public inputs
        let prev_pis = &prev_proof.public_inputs[..pis_len];
        let vd = vd_from_pis_slice_target(
            &prev_proof.public_inputs[pis_len..pis_len + vd_vec_len(&builder.config)],
            &builder.config,
        )
        .unwrap();

        // register public inputs
        builder.register_public_inputs(prev_pis);
        let vd_pis = builder.add_verifier_data_public_inputs();
        builder.connect_verifier_data(&vd, &vd_pis);

        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(is_not_first_step, &prev_proof, cd)
            .expect("Failed to conditionally verify cyclic proof or dummy");

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(
            data.common,
            cd.clone(),
            "Common data mismatch in balance circuit"
        );
        assert!(success, "Failed to build balance circuit");

        Self {
            pis_len,
            data,
            is_first_step,
            prev_proof,
            vd,
        }
    }

    pub fn prove(
        &self,
        initial_pis: Option<&[F]>,
        prev_proof: Option<&ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.vd, &self.data.verifier_only);
        if prev_proof.is_none() {
            let initial_pis = initial_pis.ok_or_else(|| {
                anyhow::anyhow!(
                    "Initial public inputs must be provided for the first step".to_string(),
                )
            })?;
            let dummy_proof = cyclic_base_proof(
                &self.data.common,
                &self.data.verifier_only,
                initial_pis.iter().cloned().enumerate().collect(),
            );
            pw.set_bool_target(self.is_first_step, true);
            pw.set_proof_with_pis_target(&self.prev_proof, &dummy_proof);
        } else {
            pw.set_bool_target(self.is_first_step, false);
            pw.set_proof_with_pis_target(&self.prev_proof, prev_proof.as_ref().unwrap());
        }
        self.data.prove(pw).context("Failed to create cyclic proof")
    }

    pub fn generate_cd(pis_len: usize) -> CommonCircuitData<F, D> {
        let data = simple_recursion_circuit_data::<F, C, D>();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
        // pad degree should be ajusted to fullfill common data equality
        while builder.num_gates() < 1 << 12 {
            builder.add_gate(NoopGate, vec![]);
        }
        let mut common = builder.build::<C>().common;
        common.num_public_inputs = pis_len + vd_vec_len(&common.config);
        common
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };

    const D: usize = 2;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_cyclic_circuit_proves_multiple_steps() {
        type F = GoldilocksField;
        type C = PoseidonGoldilocksConfig;

        let pis_len = 8;
        let common_data = TestCyclicCircuit::<F, C, D>::generate_cd(pis_len);
        let config = CircuitConfig::standard_recursion_config();
        let circuit = TestCyclicCircuit::<F, C, D>::new(config, pis_len, &common_data);

        let initial_pis: Vec<F> = (0..pis_len)
            .map(|i| F::from_canonical_usize(i + 1))
            .collect();

        let first_proof = circuit
            .prove(Some(&initial_pis), None)
            .expect("first step proof should succeed");
        circuit
            .data
            .verify(first_proof.clone())
            .expect("first proof must verify");

        let second_proof = circuit
            .prove(None, Some(&first_proof))
            .expect("second step proof should succeed");
        circuit
            .data
            .verify(second_proof.clone())
            .expect("second proof must verify");
    }
}
