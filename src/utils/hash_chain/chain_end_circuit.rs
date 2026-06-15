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

use crate::{
    ethereum_types::{
        address::{ADDRESS_LEN, Address, AddressTarget},
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{conversion::ToU64 as _, recursively_verifiable::add_proof_target_and_verify_cyclic},
};

use super::error::HashChainError;

const CHAIN_END_PROOF_PUBLIC_INPUTS_LEN: usize = BYTES32_LEN + ADDRESS_LEN;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainEndProofPublicInputs {
    pub last_hash: Bytes32,
    pub proof_submitter: Address,
}

impl ChainEndProofPublicInputs {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = [
            self.last_hash.to_u32_vec(),
            self.proof_submitter.to_u32_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), CHAIN_END_PROOF_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u32_slice(slice: &[u32]) -> Result<Self, HashChainError> {
        if slice.len() != CHAIN_END_PROOF_PUBLIC_INPUTS_LEN {
            return Err(HashChainError::InvalidData(format!(
                "Invalid input length for ChainEndProofPublicInputs: expected {}, got {}",
                CHAIN_END_PROOF_PUBLIC_INPUTS_LEN,
                slice.len()
            )));
        }
        let last_hash = Bytes32::from_u32_slice(&slice[0..BYTES32_LEN]).unwrap();
        let proof_submitter = Address::from_u32_slice(&slice[BYTES32_LEN..]).unwrap();
        Ok(Self {
            last_hash,
            proof_submitter,
        })
    }

    pub fn from_u64_slice(slice: &[u64]) -> Result<Self, HashChainError> {
        if slice.len() != CHAIN_END_PROOF_PUBLIC_INPUTS_LEN {
            return Err(HashChainError::InvalidData(format!(
                "Invalid input length for ChainEndProofPublicInputs: expected {}, got {}",
                CHAIN_END_PROOF_PUBLIC_INPUTS_LEN,
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

    pub fn from_pis<F: PrimeField64>(pis: &[F]) -> Result<Self, HashChainError> {
        Self::from_u64_slice(&pis.to_u64_vec())
    }

    pub fn hash(&self) -> Bytes32 {
        Bytes32::from_u32_slice(&solidity_keccak256(&self.to_u32_vec())).unwrap()
    }
}

#[derive(Debug, Clone)]
struct ChainEndProofPublicInputsTarget {
    last_hash: Bytes32Target,
    proof_submitter: AddressTarget,
}

impl ChainEndProofPublicInputsTarget {
    fn to_vec(&self) -> Vec<Target> {
        [self.last_hash.to_vec(), self.proof_submitter.to_vec()].concat()
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
pub struct ChainEndCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    proof: ProofWithPublicInputsTarget<D>,
    proof_submitter: AddressTarget, // Who makes the aggregated proof and receive the reward
}

impl<F, C, const D: usize> ChainEndCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(verifier_data: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof = add_proof_target_and_verify_cyclic(verifier_data, &mut builder);
        let last_hash = Bytes32Target::from_slice(&proof.public_inputs[0..BYTES32_LEN]);
        let proof_submitter = AddressTarget::new(&mut builder, true);
        let pis = ChainEndProofPublicInputsTarget {
            last_hash,
            proof_submitter,
        };
        let pis_hash = pis.hash::<F, C, D>(&mut builder);
        builder.register_public_inputs(&pis_hash.to_vec());
        let data = builder.build();
        Self {
            data,
            proof,
            proof_submitter,
        }
    }

    pub fn prove(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
        proof_submitter: Address,
    ) -> super::error::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.proof, proof);
        self.proof_submitter.set_witness(&mut pw, proof_submitter);
        self.data.prove(pw).map_err(|e| {
            crate::utils::error::UtilsError::from(super::error::HashChainError::ChainEndProofError(
                e.to_string(),
            ))
        })
    }
}
