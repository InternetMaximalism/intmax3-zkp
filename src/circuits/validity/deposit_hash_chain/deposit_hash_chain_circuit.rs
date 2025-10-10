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
    circuits::validity::deposit_hash_chain::deposit_chain_pis::{
        DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN, DepositChainPublicInputsTarget,
    },
    utils::{
        cyclic::{add_noop_gates, simple_recursion_circuit_data, vd_vec_len},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

#[derive(Debug, Error)]
pub enum DepositHashChainCircuitError {
    #[error("Failed to prove: {0}")]
    FailedToProve(String),

    #[error("Failed to verify: {0}")]
    ProofVerificationError(String),
}

pub struct DepositHashChainCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub deposit_step_proof: ProofWithPublicInputsTarget<D>,
}

impl<F, C, const D: usize> DepositHashChainCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        deposit_chain_cd: &CommonCircuitData<F, D>,
        deposit_step_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let deposit_step_proof = add_proof_target_and_verify(deposit_step_vd, &mut builder);
        let new_chain_pis = DepositChainPublicInputsTarget::from_pis(
            &deposit_step_proof.public_inputs,
            &deposit_chain_cd.config,
        );
        builder.register_public_inputs(&new_chain_pis.to_vec(&deposit_chain_cd.config));

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(
            data.common,
            deposit_chain_cd.clone(),
            "Common data mismatch in deposit hash chain circuit",
        );
        assert!(success, "Failed to build deposit hash chain circuit");

        Self {
            data,
            deposit_step_proof,
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
        common.num_public_inputs = DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN + vd_vec_len(&common.config);
        common
    }

    pub fn prove(
        &self,
        deposit_step_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, DepositHashChainCircuitError> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.deposit_step_proof, deposit_step_proof);

        self.data
            .prove(pw)
            .map_err(|e| DepositHashChainCircuitError::FailedToProve(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), DepositHashChainCircuitError> {
        check_cyclic_proof_verifier_data(proof, &self.data.verifier_only, &self.data.common)
            .map_err(|e| {
                DepositHashChainCircuitError::ProofVerificationError(format!(
                    "Cyclic proof verifier data check failed: {:?}",
                    e
                ))
            })?;
        self.data.verify(proof.clone()).map_err(|e| {
            DepositHashChainCircuitError::ProofVerificationError(format!(
                "Failed to verify proof: {:?}",
                e
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::validity::deposit_hash_chain::deposit_step::{
            DepositStepCircuit, DepositStepWitness,
        },
        common::{deposit::Deposit, trees::deposit_tree::DepositTree, u63::U63},
        ethereum_types::{bytes32::Bytes32, u256::U256},
        utils::conversion::ToField as _,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_deposit_hash_chain_circuit() {
        let deposit_chain_cd = DepositHashChainCircuit::<F, C, D>::generate_cd();
        let deposit_step_circuit = DepositStepCircuit::<F, C, D>::new(&deposit_chain_cd);
        let deposit_hash_chain_circuit = DepositHashChainCircuit::<F, C, D>::new(
            &deposit_chain_cd,
            &deposit_step_circuit.data.verifier_data(),
        );
        let deposit_chain_vd = deposit_hash_chain_circuit.data.verifier_data();

        let initial_deposit_hash_chain = Bytes32::default();
        let deposit_tree = DepositTree::init();
        let initial_deposit_tree_root = deposit_tree.get_root();
        let initial_deposit_count = U63::default();

        let deposit = Deposit {
            deposit_index: U63::default(),
            block_number: U63::default(),
            depositor: Default::default(),
            recipient: Bytes32::default(),
            token_index: 0,
            amount: U256::from(5u32),

            aux_data: Bytes32::default(),
        };
        let deposit_merkle_proof = deposit_tree.prove(deposit.deposit_index.as_u64());

        let mut deposit_tree_after = deposit_tree.clone();
        deposit_tree_after.push(deposit.clone());
        let expected_deposit_tree_root = deposit_tree_after.get_root();
        let expected_deposit_hash_chain = deposit.hash_with_prev_hash(initial_deposit_hash_chain);

        let witness = DepositStepWitness::<F, C, D> {
            initial_value: Some((
                initial_deposit_hash_chain,
                initial_deposit_tree_root,
                initial_deposit_count,
            )),
            prev_deposit_chain_proof: None,
            deposit: deposit.clone(),
            deposit_merkle_proof,
        };

        let expected_public_inputs = witness
            .to_public_inputs(&deposit_chain_vd)
            .expect("deposit chain public inputs");
        assert_eq!(expected_public_inputs.deposit_count.as_u64(), 1);
        assert_eq!(
            expected_public_inputs.deposit_tree_root,
            expected_deposit_tree_root
        );
        assert_eq!(
            expected_public_inputs.deposit_hash_chain,
            expected_deposit_hash_chain
        );

        let deposit_step_proof = deposit_step_circuit
            .prove(&deposit_chain_vd, &witness)
            .expect("deposit step proof");
        deposit_step_circuit
            .verify(deposit_step_proof.clone())
            .expect("deposit step proof verifies");

        let deposit_chain_proof = deposit_hash_chain_circuit
            .prove(&deposit_step_proof)
            .expect("deposit hash chain proof");
        deposit_hash_chain_circuit
            .verify(&deposit_chain_proof)
            .expect("deposit hash chain proof verifies");

        let expected_fields = expected_public_inputs
            .to_u64_vec(&deposit_chain_cd.config)
            .to_field_vec::<F>();
        assert_eq!(deposit_chain_proof.public_inputs, expected_fields);
    }
}
