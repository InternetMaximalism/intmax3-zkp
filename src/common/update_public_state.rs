use crate::{
    common::trees::public_state_tree::{
        PublicState, PublicStateMerkleProof, PublicStateMerkleProofTarget, PublicStateTarget,
    },
    constants::PUBLIC_STATE_TREE_HEIGHT,
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::witness::WitnessWrite,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

#[derive(thiserror::Error, Debug)]
pub enum UpdatePublicStateError {
    #[error("Invalid Merkle proof {0}")]
    InvalidMerkleProof(String),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UpdatePublicState {
    pub new: PublicState,
    pub old: PublicState,
    pub merkle_proof: PublicStateMerkleProof,
}

#[derive(Clone, Debug)]
pub struct UpdatePublicStateTarget {
    pub new: PublicStateTarget,
    pub old: PublicStateTarget,
    pub merkle_proof: PublicStateMerkleProofTarget,
}

impl UpdatePublicState {
    pub fn new(
        new: PublicState,
        old: PublicState,
        merkle_proof: PublicStateMerkleProof,
    ) -> Result<Self, UpdatePublicStateError> {
        if new == old {
            return Ok(Self {
                new,
                old,
                merkle_proof,
            });
        }
        let calculated = merkle_proof.get_root(&old, old.block_number as u64);
        if calculated != new.prev_public_state_root {
            return Err(UpdatePublicStateError::InvalidMerkleProof(format!(
                "calculated: {}, expected: {}",
                calculated, new.prev_public_state_root
            )));
        }
        Ok(Self {
            new,
            old,
            merkle_proof,
        })
    }
}

impl UpdatePublicStateTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let new = PublicStateTarget::new(builder);
        let old = PublicStateTarget::new(builder);
        let merkle_proof = PublicStateMerkleProofTarget::new(builder, PUBLIC_STATE_TREE_HEIGHT);

        let states_equal = new.is_equal(builder, &old);
        let should_verify = builder.not(states_equal);

        merkle_proof.conditional_verify::<F, C, D>(
            builder,
            should_verify,
            &old,
            old.block_number,
            new.prev_public_state_root,
        );

        Self {
            new,
            old,
            merkle_proof,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &UpdatePublicState,
    ) {
        self.new.set_witness(witness, &value.new);
        self.old.set_witness(witness, &value.old);
        self.merkle_proof.set_witness(witness, &value.merkle_proof);
    }
}
