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
use serde::{Deserialize, Serialize};

use crate::{
    constants::MAX_NUM_USERS_PER_BLOCK,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
};

#[derive(thiserror::Error, Debug, Clone)]
pub enum BlockError {
    #[error("The number of users in a block exceeds the maximum allowed: {0}")]
    ExceedMaxNumUsers(usize),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub aggregator_id: u32,
    pub user_ids: Vec<u32>,
    pub tx_tree_root: Bytes32,
    pub deposit_hash_chain: Bytes32,
}

#[derive(Debug, Clone)]
pub struct BlockTarget {
    pub aggregator_id: Target,
    pub user_ids: Vec<Target>,
    pub tx_tree_root: Bytes32Target,
    pub deposit_hash_chain: Bytes32Target,
}

impl Block {
    pub fn hash_with_prev_hash(&self, prev_hash: Bytes32) -> Result<Bytes32, BlockError> {
        if self.user_ids.len() > MAX_NUM_USERS_PER_BLOCK {
            return Err(BlockError::ExceedMaxNumUsers(self.user_ids.len()));
        }
        // pad user_ids with zeros
        let mut padded_user_ids = self.user_ids.clone();
        padded_user_ids.resize(MAX_NUM_USERS_PER_BLOCK, 0);
        let inputs = [
            prev_hash.to_u32_vec(),
            vec![self.aggregator_id],
            padded_user_ids,
            self.tx_tree_root.to_u32_vec(),
            self.deposit_hash_chain.to_u32_vec(),
        ]
        .concat();
        Ok(Bytes32::from_u32_slice(&solidity_keccak256(&inputs)).expect("hashing result invalid"))
    }
}

impl BlockTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let aggregator_id = builder.add_virtual_target();
        if is_checked {
            builder.range_check(aggregator_id, 32);
        }

        let user_ids = (0..MAX_NUM_USERS_PER_BLOCK)
            .map(|_| {
                let target = builder.add_virtual_target();
                if is_checked {
                    builder.range_check(target, 32);
                }
                target
            })
            .collect();

        let tx_tree_root = Bytes32Target::new(builder, is_checked);
        let deposit_hash_chain = Bytes32Target::new(builder, is_checked);

        Self {
            aggregator_id,
            user_ids,
            tx_tree_root,
            deposit_hash_chain,
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &Block,
    ) -> Self {
        assert!(
            value.user_ids.len() <= MAX_NUM_USERS_PER_BLOCK,
            "user_ids length exceeds MAX_NUM_USERS_PER_BLOCK"
        );
        let aggregator_id = builder.constant(F::from_canonical_u32(value.aggregator_id));
        let mut padded_user_ids = value.user_ids.clone();
        padded_user_ids.resize(MAX_NUM_USERS_PER_BLOCK, 0);
        let user_ids = padded_user_ids
            .into_iter()
            .map(|id| builder.constant(F::from_canonical_u32(id)))
            .collect();
        let tx_tree_root = Bytes32Target::constant(builder, value.tx_tree_root);
        let deposit_hash_chain = Bytes32Target::constant(builder, value.deposit_hash_chain);

        Self {
            aggregator_id,
            user_ids,
            tx_tree_root,
            deposit_hash_chain,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            vec![self.aggregator_id],
            self.user_ids.clone(),
            self.tx_tree_root.to_vec(),
            self.deposit_hash_chain.to_vec(),
        ]
        .concat()
    }

    pub fn hash_with_prev_hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        prev_hash: Bytes32Target,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut inputs = prev_hash.to_vec();
        inputs.push(self.aggregator_id);
        inputs.extend(self.user_ids.iter().copied());
        inputs.extend(self.tx_tree_root.to_vec());
        inputs.extend(self.deposit_hash_chain.to_vec());
        Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &Block) {
        assert!(
            value.user_ids.len() <= MAX_NUM_USERS_PER_BLOCK,
            "user_ids length exceeds MAX_NUM_USERS_PER_BLOCK"
        );

        witness.set_target(
            self.aggregator_id,
            F::from_canonical_u32(value.aggregator_id),
        );

        let mut padded_user_ids = value.user_ids.clone();
        padded_user_ids.resize(MAX_NUM_USERS_PER_BLOCK, 0);
        for (target, user_id) in self.user_ids.iter().zip(padded_user_ids.iter()) {
            witness.set_target(*target, F::from_canonical_u32(*user_id));
        }

        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        self.deposit_hash_chain
            .set_witness(witness, value.deposit_hash_chain);
    }
}
