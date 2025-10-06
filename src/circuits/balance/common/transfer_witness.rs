use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{
    common::{
        transfer::{Transfer, TransferTarget},
        trees::transfer_tree::{TransferMerkleProof, TransferMerkleProofTarget},
    },
    constants::TRANSFER_TREE_HEIGHT,
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

#[derive(Debug, thiserror::Error)]
pub enum TransferWitnessError {
    #[error("Invalid transfer merkle proof: {0}")]
    InvalidTransferMerkleProof(String),
}

#[derive(Clone, Debug)]
pub struct TransferWitness {
    pub transfer_tree_root: PoseidonHashOut,
    pub transfer: Transfer,
    pub transfer_index: u32,
    pub transfer_merkle_proof: TransferMerkleProof,
}

impl TransferWitness {
    pub fn new(
        transfer_tree_root: PoseidonHashOut,
        transfer: Transfer,
        transfer_index: u32,
        transfer_merkle_proof: TransferMerkleProof,
    ) -> Result<Self, TransferWitnessError> {
        let witness = Self {
            transfer_tree_root,
            transfer,
            transfer_index,
            transfer_merkle_proof,
        };
        witness.verify()?;
        Ok(witness)
    }

    pub fn verify(&self) -> Result<(), TransferWitnessError> {
        self.transfer_merkle_proof
            .verify(
                &self.transfer,
                self.transfer_index as u64,
                self.transfer_tree_root,
            )
            .map_err(|e| TransferWitnessError::InvalidTransferMerkleProof(e.to_string()))?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TransferWitnessTarget {
    pub transfer_tree_root: PoseidonHashOutTarget,
    pub transfer: TransferTarget,
    pub transfer_index: Target,
    pub transfer_merkle_proof: TransferMerkleProofTarget,
}

impl TransferWitnessTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let transfer_tree_root = PoseidonHashOutTarget::new(builder);
        let transfer = TransferTarget::new(builder, is_checked);
        let transfer_index = builder.add_virtual_target();
        if is_checked {
            builder.range_check(transfer_index, TRANSFER_TREE_HEIGHT);
        }
        let transfer_merkle_proof = TransferMerkleProofTarget::new(builder, TRANSFER_TREE_HEIGHT);

        transfer_merkle_proof.verify::<F, C, D>(
            builder,
            &transfer,
            transfer_index,
            transfer_tree_root,
        );

        Self {
            transfer_tree_root,
            transfer,
            transfer_index,
            transfer_merkle_proof,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &TransferWitness,
    ) {
        self.transfer_tree_root
            .set_witness(witness, value.transfer_tree_root);
        self.transfer.set_witness(witness, &value.transfer);
        witness.set_target(
            self.transfer_index,
            F::from_canonical_u32(value.transfer_index),
        );
        self.transfer_merkle_proof
            .set_witness(witness, &value.transfer_merkle_proof);
    }
}
