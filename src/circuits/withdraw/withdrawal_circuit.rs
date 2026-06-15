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
    circuits::validity::block_hash_chain::ext_public_state::{
        ExtendedPublicState, ExtendedPublicStateTarget,
    },
    common::{
        public_state::{PUBLIC_STATE_U64_LEN, PublicStateTarget},
        u63::{BlockNumber, BlockNumberTarget},
    },
    ethereum_types::{
        address::{ADDRESS_LEN, Address, AddressTarget},
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{conversion::ToU64 as _, recursively_verifiable::add_proof_target_and_verify_cyclic},
};

const BLOCK_NUMBER_U32_LEN: usize = 2;
const WITHDRAWAL_PROOF_PUBLIC_INPUTS_LEN: usize =
    BYTES32_LEN + ADDRESS_LEN + BYTES32_LEN + BLOCK_NUMBER_U32_LEN;

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
    pub withdrawal_prover: Address,
    pub ext_public_state_commitment: Bytes32,
    pub block_number: BlockNumber,
}

impl WithdrawalProofPublicInputs {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = [
            self.withdrawal_hash.to_u32_vec(),
            self.withdrawal_prover.to_u32_vec(),
            self.ext_public_state_commitment.to_u32_vec(),
            self.block_number.to_u32_vec(),
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
        let mut cursor = 0;
        let withdrawal_hash =
            Bytes32::from_u32_slice(&slice[cursor..cursor + BYTES32_LEN]).unwrap();
        cursor += BYTES32_LEN;
        let withdrawal_prover =
            Address::from_u32_slice(&slice[cursor..cursor + ADDRESS_LEN]).unwrap();
        cursor += ADDRESS_LEN;
        let ext_public_state_commitment =
            Bytes32::from_u32_slice(&slice[cursor..cursor + BYTES32_LEN]).unwrap();
        cursor += BYTES32_LEN;
        let block_number =
            BlockNumber::from_u32_slice(&slice[cursor..cursor + BLOCK_NUMBER_U32_LEN])
                .map_err(|e| WithdrawalCircuitError::InvalidPublicInputs(e.to_string()))?;
        Ok(Self {
            withdrawal_hash,
            withdrawal_prover,
            ext_public_state_commitment,
            block_number,
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
    withdrawal_prover: AddressTarget,
    ext_public_state_commitment: Bytes32Target,
    block_number: BlockNumberTarget,
}

impl WithdrawalProofPublicInputsTarget {
    fn to_vec<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let mut values =
            Vec::with_capacity(BYTES32_LEN + ADDRESS_LEN + BYTES32_LEN + BLOCK_NUMBER_U32_LEN);
        values.extend(self.withdrawal_hash.to_vec());
        values.extend(self.withdrawal_prover.to_vec());
        values.extend(self.ext_public_state_commitment.to_vec());
        values.extend(self.block_number.to_u32_vec(builder));
        values
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let inputs = self.to_vec(builder);
        let hash = builder.keccak256::<C>(&inputs);
        Bytes32Target::from_slice(&hash)
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
    ext_public_state: ExtendedPublicStateTarget,
    withdrawal_prover: AddressTarget,
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
        let public_state_start = BYTES32_LEN;
        let public_state_end = public_state_start + PUBLIC_STATE_U64_LEN;
        let chain_public_state = PublicStateTarget::from_slice(
            &proof.public_inputs[public_state_start..public_state_end],
        );
        let ext_public_state = ExtendedPublicStateTarget::new(&mut builder, true);
        ext_public_state
            .inner
            .connect(&mut builder, &chain_public_state);
        let ext_public_state_commitment = ext_public_state.commitment(&mut builder);
        let block_number = ext_public_state.inner.block_number.clone();
        let withdrawal_prover = AddressTarget::new(&mut builder, true);
        let pis = WithdrawalProofPublicInputsTarget {
            withdrawal_hash,
            withdrawal_prover,
            ext_public_state_commitment: ext_public_state_commitment.clone(),
            block_number: block_number.clone(),
        };
        let pis_hash = pis
            .hash::<F, C, D>(&mut builder)
            .remove_3bits::<F, D>(&mut builder);
        builder.register_public_inputs(&pis_hash.to_vec());
        builder.register_public_inputs(&ext_public_state_commitment.to_vec());
        builder.register_public_inputs(&block_number.to_vec());
        let data = builder.build();
        Self {
            data,
            proof,
            ext_public_state,
            withdrawal_prover,
        }
    }

    pub fn prove(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
        withdrawal_prover: Address,
        ext_public_state: &ExtendedPublicState,
    ) -> Result<ProofWithPublicInputs<F, C, D>, WithdrawalCircuitError> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.proof, proof);
        self.ext_public_state.set_witness(&mut pw, ext_public_state);
        self.withdrawal_prover
            .set_witness(&mut pw, withdrawal_prover);
        self.data
            .prove(pw)
            .map_err(|e| WithdrawalCircuitError::FailedToProve(e.to_string()))
    }
}
