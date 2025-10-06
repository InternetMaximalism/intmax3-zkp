use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    common::{
        trees::account_tree::{
            AccountLeaf, AccountLeafTarget, AccountMerkleProof, AccountMerkleProofTarget, SendLeaf,
            SendLeafTarget, SendMerkleProof, SendMerkleProofTarget,
        },
        user_id::{UserId, UserIdTarget},
    },
    constants::{ACCOUNT_TREE_HEIGHT, SEND_TREE_HEIGHT},
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

#[derive(Debug, thiserror::Error)]
pub enum AccountStateError {
    #[error("Invalid send merkle proof: {0}")]
    InvalidSendMerkleProof(String),

    #[error("Invalid account merkle proof: {0}")]
    InvalidAccountMerkleProof(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountState {
    pub user_id: UserId,
    pub account_tree_root: PoseidonHashOut,

    pub send_leaf: SendLeaf,
    pub send_leaf_index: u32,
    pub send_merkle_proof: SendMerkleProof,
    pub account_leaf: AccountLeaf,
    pub account_merkle_proof: AccountMerkleProof,
}

impl AccountState {
    pub fn new(
        user_id: UserId,
        account_tree_root: PoseidonHashOut,
        send_leaf: SendLeaf,
        send_leaf_index: u32,
        send_merkle_proof: SendMerkleProof,
        account_leaf: AccountLeaf,
        account_merkle_proof: AccountMerkleProof,
    ) -> Result<Self, AccountStateError> {
        // verify send leaf inclusion
        send_merkle_proof
            .verify(
                &send_leaf,
                send_leaf_index as u64,
                account_leaf.send_tree_root,
            )
            .map_err(|e| AccountStateError::InvalidSendMerkleProof(e.to_string()))?;

        // verify account leaf inclusion
        account_merkle_proof
            .verify(&account_leaf, user_id.0, account_tree_root)
            .map_err(|e| AccountStateError::InvalidAccountMerkleProof(e.to_string()))?;

        Ok(Self {
            user_id,
            account_tree_root,
            send_leaf,
            send_leaf_index,
            send_merkle_proof,
            account_leaf,
            account_merkle_proof,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AccountStateTarget {
    pub user_id: UserIdTarget,
    pub account_tree_root: PoseidonHashOutTarget,

    pub send_leaf: SendLeafTarget,
    pub send_leaf_index: Target,
    pub send_merkle_proof: SendMerkleProofTarget,
    pub account_leaf: AccountLeafTarget,
    pub account_merkle_proof: AccountMerkleProofTarget,
}

impl AccountStateTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let user_id = UserIdTarget::new(builder, is_checked);
        let account_tree_root = PoseidonHashOutTarget::new(builder);

        let send_leaf = SendLeafTarget::new(builder, is_checked);
        let send_leaf_index = builder.add_virtual_target();
        if is_checked {
            builder.range_check(send_leaf_index, SEND_TREE_HEIGHT);
        }
        let send_merkle_proof = SendMerkleProofTarget::new(builder, SEND_TREE_HEIGHT);

        let account_leaf = AccountLeafTarget::new(builder, is_checked);
        let account_merkle_proof = AccountMerkleProofTarget::new(builder, ACCOUNT_TREE_HEIGHT);

        send_merkle_proof.verify::<F, C, D>(
            builder,
            &send_leaf,
            send_leaf_index,
            account_leaf.send_tree_root,
        );

        account_merkle_proof.verify::<F, C, D>(
            builder,
            &account_leaf,
            user_id.value,
            account_tree_root,
        );

        Self {
            user_id,
            account_tree_root,
            send_leaf,
            send_leaf_index,
            send_merkle_proof,
            account_leaf,
            account_merkle_proof,
        }
    }
}
