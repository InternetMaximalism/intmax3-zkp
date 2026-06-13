use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    common::{
        channel_id::{ChannelId, ChannelIdTarget},
        trees::channel_tree::{
            ChannelLeaf, ChannelLeafTarget, ChannelMerkleProof, ChannelMerkleProofTarget, SendLeaf,
            SendLeafTarget, SendMerkleProof, SendMerkleProofTarget,
        },
    },
    constants::{CHANNEL_TREE_HEIGHT, SEND_TREE_HEIGHT},
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

#[derive(Debug, thiserror::Error)]
pub enum AccountStateError {
    #[error("Invalid send merkle proof: {0}")]
    InvalidSendMerkleProof(String),

    #[error("Invalid account merkle proof: {0}")]
    InvalidUserMerkleProof(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountState {
    pub channel_id: ChannelId,
    pub account_tree_root: PoseidonHashOut,

    pub send_leaf: SendLeaf,
    pub send_leaf_index: u32,
    pub send_merkle_proof: SendMerkleProof,
    pub channel_leaf: ChannelLeaf,
    pub user_merkle_proof: ChannelMerkleProof,
}

impl AccountState {
    pub fn new(
        channel_id: ChannelId,
        account_tree_root: PoseidonHashOut,
        send_leaf: SendLeaf,
        send_leaf_index: u32,
        send_merkle_proof: SendMerkleProof,
        channel_leaf: ChannelLeaf,
        user_merkle_proof: ChannelMerkleProof,
    ) -> Result<Self, AccountStateError> {
        let state = Self {
            channel_id,
            account_tree_root,
            send_leaf,
            send_leaf_index,
            send_merkle_proof,
            channel_leaf,
            user_merkle_proof,
        };
        state.verify()?;
        Ok(state)
    }

    pub fn verify(&self) -> Result<(), AccountStateError> {
        // verify send leaf inclusion
        self.send_merkle_proof
            .verify(
                &self.send_leaf,
                self.send_leaf_index as u64,
                self.channel_leaf.send_tree_root,
            )
            .map_err(|e| AccountStateError::InvalidSendMerkleProof(e.to_string()))?;

        // verify account leaf inclusion
        self.user_merkle_proof
            .verify(
                &self.channel_leaf,
                self.channel_id.as_u64(),
                self.account_tree_root,
            )
            .map_err(|e| AccountStateError::InvalidUserMerkleProof(e.to_string()))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountStateTarget {
    pub channel_id: ChannelIdTarget,
    pub account_tree_root: PoseidonHashOutTarget,

    pub send_leaf: SendLeafTarget,
    pub send_leaf_index: Target,
    pub send_merkle_proof: SendMerkleProofTarget,
    pub channel_leaf: ChannelLeafTarget,
    pub user_merkle_proof: ChannelMerkleProofTarget,
}

impl AccountStateTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let channel_id = ChannelIdTarget::new(builder, is_checked);
        let account_tree_root = PoseidonHashOutTarget::new(builder);

        let send_leaf = SendLeafTarget::new(builder, is_checked);
        let send_leaf_index = builder.add_virtual_target();
        if is_checked {
            builder.range_check(send_leaf_index, SEND_TREE_HEIGHT);
        }
        let send_merkle_proof = SendMerkleProofTarget::new(builder, SEND_TREE_HEIGHT);

        let channel_leaf = ChannelLeafTarget::new(builder, is_checked);
        let user_merkle_proof = ChannelMerkleProofTarget::new(builder, CHANNEL_TREE_HEIGHT);

        send_merkle_proof.verify::<F, C, D>(
            builder,
            &send_leaf,
            send_leaf_index,
            channel_leaf.send_tree_root,
        );

        user_merkle_proof.verify::<F, C, D>(
            builder,
            &channel_leaf,
            channel_id.value,
            account_tree_root,
        );

        Self {
            channel_id,
            account_tree_root,
            send_leaf,
            send_leaf_index,
            send_merkle_proof,
            channel_leaf,
            user_merkle_proof,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &AccountState) {
        self.channel_id.set_witness(witness, value.channel_id);
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        self.send_leaf.set_witness(witness, &value.send_leaf);
        witness.set_target(
            self.send_leaf_index,
            F::from_canonical_u32(value.send_leaf_index),
        );
        self.send_merkle_proof
            .set_witness(witness, &value.send_merkle_proof);
        self.channel_leaf.set_witness(witness, &value.channel_leaf);
        self.user_merkle_proof
            .set_witness(witness, &value.user_merkle_proof);
    }
}
