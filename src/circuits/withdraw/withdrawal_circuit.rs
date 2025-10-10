use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ethereum_types::{
        address::{ADDRESS_LEN, Address, AddressTarget},
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{conversion::ToU64 as _, recursively_verifiable::add_proof_target_and_verify_cyclic},
};

const WITHDRAWAL_PROOF_PUBLIC_INPUTS_LEN: usize = BYTES32_LEN + ADDRESS_LEN;

#[derive(Debug, Error)]
pub enum WithdrawalCircuitError {
    #[error("Invalid public inputs: {0}")]
    InvalidPublicInputs(String),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalProofPublicInputs {
    pub withdrawal_hash: Bytes32,
    pub withdrawal_aggregator: Address,
}

impl WithdrawalProofPublicInputs {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = [
            self.withdrawal_hash.to_u32_vec(),
            self.withdrawal_aggregator.to_u32_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), WITHDRAWAL_PROOF_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u32_slice(slice: &[u32]) -> Result<Self, WithdrawalCircuitError> {
        if slice.len() != WITHDRAWAL_PROOF_PUBLIC_INPUTS_LEN {
            return Err(WithdrawalCircuitError::InvalidPublicInputs(format!(
                "expected {}, got {}",
                WITHDRAWAL_PROOF_PUBLIC_INPUTS_LEN,
                slice.len()
            )));
        }
        let withdrawal_hash = Bytes32::from_u32_slice(&slice[0..BYTES32_LEN]).unwrap();
        let withdrawal_aggregator =
            Address::from_u32_slice(&slice[BYTES32_LEN..BYTES32_LEN + ADDRESS_LEN]).unwrap();
        Ok(Self {
            withdrawal_hash,
            withdrawal_aggregator,
        })
    }

    pub fn from_u64_slice(slice: &[u64]) -> Result<Self, WithdrawalCircuitError> {
        if slice.len() != WITHDRAWAL_PROOF_PUBLIC_INPUTS_LEN {
            return Err(WithdrawalCircuitError::InvalidPublicInputs(format!(
                "expected {}, got {}",
                WITHDRAWAL_PROOF_PUBLIC_INPUTS_LEN,
                slice.len()
            )));
        }
        let inputs = slice
            .iter()
            .map(|&x| {
                assert!(x <= u32::MAX as u64);
                x as u32
            })
            .collect::<Vec<u32>>();
        Self::from_u32_slice(&inputs)
    }

    pub fn from_pis<F: PrimeField64>(pis: &[F]) -> Result<Self, WithdrawalCircuitError> {
        Self::from_u64_slice(&pis.to_u64_vec())
    }

    pub fn hash(&self) -> Bytes32 {
        Bytes32::from_u32_slice(&solidity_keccak256(&self.to_u32_vec()))
            .unwrap()
            .remove_3bits()
    }
}

#[derive(Debug, Clone)]
struct WithdrawalProofPublicInputsTarget {
    withdrawal_hash: Bytes32Target,
    withdrawal_aggregator: AddressTarget,
}

impl WithdrawalProofPublicInputsTarget {
    fn to_vec(&self) -> Vec<Target> {
        [
            self.withdrawal_hash.to_vec(),
            self.withdrawal_aggregator.to_vec(),
        ]
        .concat()
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Bytes32Target::from_slice(&builder.keccak256::<C>(&self.to_vec()))
    }
}

#[derive(Debug)]
pub struct WithdrawalCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    proof: ProofWithPublicInputsTarget<D>,
    withdrawal_aggregator: AddressTarget,
}

impl<F, C, const D: usize> WithdrawalCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(verifier_data: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof = add_proof_target_and_verify_cyclic(verifier_data, &mut builder);
        let withdrawal_hash = Bytes32Target::from_slice(&proof.public_inputs[0..BYTES32_LEN]);
        let withdrawal_aggregator = AddressTarget::new(&mut builder, true);
        let pis = WithdrawalProofPublicInputsTarget {
            withdrawal_hash,
            withdrawal_aggregator,
        };
        let pis_hash = pis
            .hash::<F, C, D>(&mut builder)
            .remove_3bits::<F, D>(&mut builder);
        builder.register_public_inputs(&pis_hash.to_vec());
        let data = builder.build();
        Self {
            data,
            proof,
            withdrawal_aggregator,
        }
    }

    pub fn prove(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
        withdrawal_aggregator: Address,
    ) -> Result<ProofWithPublicInputs<F, C, D>, WithdrawalCircuitError> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.proof, proof);
        self.withdrawal_aggregator
            .set_witness(&mut pw, withdrawal_aggregator);
        self.data
            .prove(pw)
            .map_err(|e| WithdrawalCircuitError::FailedToProve(e.to_string()))
    }
}
