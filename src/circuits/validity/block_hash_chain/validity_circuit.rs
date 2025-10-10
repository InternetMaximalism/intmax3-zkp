use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use thiserror::Error;

use crate::{
    circuits::validity::block_hash_chain::{
        block_chain_pis::BlockChainPublicInputsTarget, ext_public_state::ExtendedPublicState,
    },
    common::u63::{BlockNumber, BlockNumberTarget},
    ethereum_types::{
        address::{Address, AddressTarget},
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::recursively_verifiable::add_proof_target_and_verify_cyclic,
};

pub struct ValidityPublicInputs {
    pub initial_block_number: BlockNumber,
    pub initial_block_chain: Bytes32,
    pub initial_ext_commitment: Bytes32,
    pub final_block_number: BlockNumber,
    pub final_block_chain: Bytes32,
    pub final_ext_commitment: Bytes32,
    pub prover: Address,
}

impl ValidityPublicInputs {
    pub fn from_states(
        initial: &ExtendedPublicState,
        final_state: &ExtendedPublicState,
        prover: Address,
    ) -> Self {
        Self {
            initial_block_number: initial.inner.block_number,
            initial_block_chain: initial.block_hash_chain,
            initial_ext_commitment: initial.commitment(),
            final_block_number: final_state.inner.block_number,
            final_block_chain: final_state.block_hash_chain,
            final_ext_commitment: final_state.commitment(),
            prover,
        }
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        [
            self.initial_block_number.to_u32_vec(),
            self.initial_block_chain.to_u32_vec(),
            self.initial_ext_commitment.to_u32_vec(),
            self.final_block_number.to_u32_vec(),
            self.final_block_chain.to_u32_vec(),
            self.final_ext_commitment.to_u32_vec(),
            self.prover.to_u32_vec(),
        ]
        .concat()
    }

    pub fn hash(&self) -> Bytes32 {
        Bytes32::from_u32_slice(&solidity_keccak256(&self.to_u32_vec()))
            .expect("keccak256 output should fit in Bytes32")
    }
}

pub struct ValidityPublicInputsTarget {
    pub initial_block_number: BlockNumberTarget,
    pub initial_block_chain: Bytes32Target,
    pub initial_ext_commitment: Bytes32Target,
    pub final_block_number: BlockNumberTarget,
    pub final_block_chain: Bytes32Target,
    pub final_ext_commitment: Bytes32Target,
    pub prover: AddressTarget,
}

impl ValidityPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            initial_block_number: BlockNumberTarget::new(builder, is_checked),
            initial_block_chain: Bytes32Target::new::<F, D>(builder, is_checked),
            initial_ext_commitment: Bytes32Target::new::<F, D>(builder, is_checked),
            final_block_number: BlockNumberTarget::new(builder, is_checked),
            final_block_chain: Bytes32Target::new::<F, D>(builder, is_checked),
            final_ext_commitment: Bytes32Target::new::<F, D>(builder, is_checked),
            prover: AddressTarget::new(builder, is_checked),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &ValidityPublicInputs,
    ) {
        self.initial_block_number
            .set_witness(witness, value.initial_block_number);
        self.initial_block_chain
            .set_witness(witness, value.initial_block_chain);
        self.initial_ext_commitment
            .set_witness(witness, value.initial_ext_commitment);
        self.final_block_number
            .set_witness(witness, value.final_block_number);
        self.final_block_chain
            .set_witness(witness, value.final_block_chain);
        self.final_ext_commitment
            .set_witness(witness, value.final_ext_commitment);
        self.prover.set_witness(witness, value.prover);
    }

    pub fn to_vec<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let mut limbs = self.initial_block_number.to_u32_vec(builder);
        limbs.extend(self.initial_block_chain.to_vec());
        limbs.extend(self.initial_ext_commitment.to_vec());
        limbs.extend(self.final_block_number.to_u32_vec(builder));
        limbs.extend(self.final_block_chain.to_vec());
        limbs.extend(self.final_ext_commitment.to_vec());
        limbs.extend(self.prover.to_vec());
        limbs
    }

    pub fn hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let inputs = self.to_vec(builder);
        Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
    }
}

#[derive(Debug, Error)]
pub enum ValidityCircuitError {
    #[error("Failed to prove: {0}")]
    FailedToProve(String),

    #[error("Failed to verify: {0}")]
    ProofVerificationError(String),
}

pub struct ValidityCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub block_hash_chain_proof: ProofWithPublicInputsTarget<D>,
    pub prover: AddressTarget,
}

impl<F, C, const D: usize> ValidityCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(block_hash_chain_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let block_hash_chain_proof =
            add_proof_target_and_verify_cyclic(block_hash_chain_vd, &mut builder);

        let block_chain_pis = BlockChainPublicInputsTarget::from_pis(
            &block_hash_chain_proof.public_inputs,
            &block_hash_chain_vd.common.config,
        );

        let initial_commitment = block_chain_pis
            .initial_ext_public_state
            .commitment(&mut builder);
        let final_commitment = block_chain_pis.ext_public_state.commitment(&mut builder);
        let prover = AddressTarget::new(&mut builder, true);
        let validity_pis = ValidityPublicInputsTarget {
            initial_block_number: block_chain_pis
                .initial_ext_public_state
                .inner
                .block_number
                .clone(),
            initial_block_chain: block_chain_pis
                .initial_ext_public_state
                .block_hash_chain
                .clone(),
            initial_ext_commitment: initial_commitment,
            final_block_number: block_chain_pis.ext_public_state.inner.block_number.clone(),
            final_block_chain: block_chain_pis.ext_public_state.block_hash_chain.clone(),
            final_ext_commitment: final_commitment,
            prover,
        };

        let hash = validity_pis.hash::<F, C, D>(&mut builder);
        builder.register_public_inputs(&hash.to_vec());

        let data = builder.build::<C>();

        Self {
            data,
            block_hash_chain_proof,
            prover,
        }
    }

    pub fn prove(
        &self,
        block_hash_chain_proof: &ProofWithPublicInputs<F, C, D>,
        prover: Address,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ValidityCircuitError> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.block_hash_chain_proof, block_hash_chain_proof);
        self.prover.set_witness(&mut pw, prover);

        self.data
            .prove(pw)
            .map_err(|e| ValidityCircuitError::FailedToProve(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), ValidityCircuitError> {
        self.data.verify(proof.clone()).map_err(|e| {
            ValidityCircuitError::ProofVerificationError(format!("Failed to verify proof: {:?}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::{
            test_utils::block_witness_generator::BlockWitnessGenerator,
            validity::block_hash_chain::{
                block_chain_pis::BlockChainPublicInputs,
                block_hash_chain_processor::BlockHashChainProcessor,
            },
        },
        ethereum_types::{address::Address, bytes32::Bytes32},
        utils::conversion::ToU64,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_validity_circuit() {
        let supported_user_counts = vec![2];
        let mut generator = BlockWitnessGenerator::new(&supported_user_counts);
        let initial_state = generator.current_extended_public_state();

        let aggregator_id = 1;
        let local_ids = vec![1];
        let timestamp = 42u64;
        let tx_tree_root = Bytes32::default();
        generator
            .add_block(aggregator_id, &local_ids, timestamp, tx_tree_root)
            .expect("add block");

        let block_number = generator.block_number;
        let block_witness = generator
            .block_chain_witness
            .get(&block_number)
            .cloned()
            .expect("block witness");

        let processor = BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
        let block_hash_chain_proof = processor
            .prove_block(Some(initial_state.clone()), None, &block_witness)
            .expect("block hash chain proof");
        let block_chain_vd = processor.block_chain_vd();

        let validity_circuit = ValidityCircuit::<F, C, D>::new(&block_chain_vd);
        let prover = Address::default();
        let validity_proof = validity_circuit
            .prove(&block_hash_chain_proof, prover)
            .expect("validity proof");
        validity_circuit
            .verify(&validity_proof)
            .expect("validity proof verifies");

        let config = &block_chain_vd.common.config;
        let block_chain_inputs = BlockChainPublicInputs::<F, C, D>::from_u64_slice(
            &block_hash_chain_proof.public_inputs.to_u64_vec(),
            config,
        )
        .expect("parse block chain public inputs");
        let validity_inputs = ValidityPublicInputs::from_states(
            &block_chain_inputs.initial_ext_public_state,
            &block_chain_inputs.ext_public_state,
            prover,
        );
        let expected_hash = validity_inputs.hash();
        let expected_public_inputs: Vec<F> = expected_hash
            .to_u32_vec()
            .into_iter()
            .map(F::from_canonical_u32)
            .collect();

        assert_eq!(validity_proof.public_inputs, expected_public_inputs);
    }
}
