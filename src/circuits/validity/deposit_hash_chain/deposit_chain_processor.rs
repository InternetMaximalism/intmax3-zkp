use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuits::validity::deposit_hash_chain::{
    deposit_hash_chain_circuit::{DepositHashChainCircuit, DepositHashChainCircuitError},
    deposit_step::{DepositStepCircuit, DepositStepWitness, UpdateDepositTreeError},
};

#[derive(Debug, thiserror::Error)]
pub enum DepositChainProcessorError {
    #[error("Deposit step circuit error: {0}")]
    DepositStepCircuitError(#[from] UpdateDepositTreeError),

    #[error("Deposit hash chain circuit error: {0}")]
    DepositHashChainCircuitError(#[from] DepositHashChainCircuitError),
}

pub struct DepositChainProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    deposit_step_circuit: DepositStepCircuit<F, C, D>,
    deposit_hash_chain_circuit: DepositHashChainCircuit<F, C, D>,
}

impl<F, C, const D: usize> DepositChainProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let deposit_chain_cd = DepositHashChainCircuit::<F, C, D>::generate_cd();
        let deposit_step_circuit = DepositStepCircuit::<F, C, D>::new(&deposit_chain_cd);
        let deposit_hash_chain_circuit = DepositHashChainCircuit::<F, C, D>::new(
            &deposit_chain_cd,
            &deposit_step_circuit.data.verifier_data(),
        );
        Self {
            deposit_step_circuit,
            deposit_hash_chain_circuit,
        }
    }

    pub fn deposit_chain_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.deposit_hash_chain_circuit.data.verifier_data()
    }

    pub fn prove_step(
        &self,
        witness: &DepositStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, DepositChainProcessorError> {
        let deposit_step_proof = self
            .deposit_step_circuit
            .prove(&self.deposit_chain_vd(), witness)?;
        let deposit_chain_proof = self.deposit_hash_chain_circuit.prove(&deposit_step_proof)?;
        Ok(deposit_chain_proof)
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), DepositHashChainCircuitError> {
        self.deposit_hash_chain_circuit.verify(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
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
    fn test_deposit_chain_processor() {
        let processor = DepositChainProcessor::<F, C, D>::new();
        let deposit_chain_vd = processor.deposit_chain_vd();

        // First deposit.
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

        let mut deposit_tree_after_first = deposit_tree.clone();
        deposit_tree_after_first.push(deposit.clone());
        let expected_deposit_tree_root_first = deposit_tree_after_first.get_root();
        let expected_deposit_hash_chain_first =
            deposit.hash_with_prev_hash(initial_deposit_hash_chain);

        let first_witness = DepositStepWitness::<F, C, D> {
            initial_value: Some((
                initial_deposit_hash_chain,
                initial_deposit_tree_root,
                initial_deposit_count,
            )),
            prev_deposit_chain_proof: None,
            deposit: deposit.clone(),
            deposit_merkle_proof: deposit_merkle_proof.clone(),
        };

        let first_public_inputs = first_witness
            .to_public_inputs(&deposit_chain_vd)
            .expect("first deposit public inputs");

        let first_proof = processor
            .prove_step(&first_witness)
            .expect("first deposit chain proof");
        processor
            .verify(&first_proof)
            .expect("first deposit chain proof verifies");

        let expected_first_fields = first_public_inputs
            .to_u64_vec(&processor.deposit_hash_chain_circuit.data.common.config)
            .to_field_vec::<F>();
        assert_eq!(first_proof.public_inputs, expected_first_fields);
        assert_eq!(
            first_public_inputs.deposit_tree_root,
            expected_deposit_tree_root_first
        );
        assert_eq!(
            first_public_inputs.deposit_hash_chain,
            expected_deposit_hash_chain_first
        );
        assert_eq!(first_public_inputs.block_number, deposit.block_number);

        // Second deposit step using the first proof.
        let second_deposit = Deposit {
            deposit_index: U63::new(1).unwrap(),
            block_number: U63::default(),
            depositor: Default::default(),
            recipient: Bytes32::default(),
            token_index: 1,
            amount: U256::from(7u32),
            aux_data: Bytes32::default(),
        };
        let second_deposit_merkle_proof =
            deposit_tree_after_first.prove(second_deposit.deposit_index.as_u64());

        let mut deposit_tree_after_second = deposit_tree_after_first.clone();
        deposit_tree_after_second.push(second_deposit.clone());
        let expected_deposit_tree_root_second = deposit_tree_after_second.get_root();
        let expected_deposit_hash_chain_second =
            second_deposit.hash_with_prev_hash(expected_deposit_hash_chain_first);

        let second_witness = DepositStepWitness::<F, C, D> {
            initial_value: None,
            prev_deposit_chain_proof: Some(first_proof.clone()),
            deposit: second_deposit.clone(),
            deposit_merkle_proof: second_deposit_merkle_proof,
        };

        let second_public_inputs = second_witness
            .to_public_inputs(&deposit_chain_vd)
            .expect("second deposit public inputs");

        let second_proof = processor
            .prove_step(&second_witness)
            .expect("second deposit chain proof");
        processor
            .verify(&second_proof)
            .expect("second deposit chain proof verifies");

        let expected_second_fields = second_public_inputs
            .to_u64_vec(&processor.deposit_hash_chain_circuit.data.common.config)
            .to_field_vec::<F>();
        assert_eq!(second_proof.public_inputs, expected_second_fields);
        assert_eq!(
            second_public_inputs.deposit_tree_root,
            expected_deposit_tree_root_second
        );
        assert_eq!(
            second_public_inputs.deposit_hash_chain,
            expected_deposit_hash_chain_second
        );
        assert_eq!(second_public_inputs.deposit_count.as_u64(), 2);
        assert_eq!(
            second_public_inputs.block_number,
            second_deposit.block_number
        );
    }
}
