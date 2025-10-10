use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};

use crate::{
    common::u63::{BlockNumber, BlockNumberTarget},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
};

pub struct ValidityPublicInputs {
    pub initial_block_number: BlockNumber,
    pub initial_block_chain: Bytes32,
    pub initial_ext_commitment: Bytes32,
    pub final_block_number: BlockNumber,
    pub final_block_chain: Bytes32,
    pub final_ext_commitment: Bytes32,
}

impl ValidityPublicInputs {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        [
            self.initial_block_number.to_u32_vec(),
            self.initial_block_chain.to_u32_vec(),
            self.initial_ext_commitment.to_u32_vec(),
            self.final_block_number.to_u32_vec(),
            self.final_block_chain.to_u32_vec(),
            self.final_ext_commitment.to_u32_vec(),
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
