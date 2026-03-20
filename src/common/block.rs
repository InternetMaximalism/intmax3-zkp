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
    constants::{AGGREGATOR_ID_BITS, LOCAL_ID_BITS},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
        u64::{U64, U64Target},
    },
};

#[derive(thiserror::Error, Debug, Clone)]
pub enum BlockError {
    #[error("Invalid number of local IDs: {0}")]
    InvalidNumUsers(String),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Block {
    // the number of users in this block
    pub num_users: u32,

    pub aggregator_id: u32,
    pub timestamp: u64,
    pub local_ids: Vec<u32>,
    pub tx_tree_root: Bytes32,
    pub deposit_hash_chain: Bytes32,
    pub forced_tx_hash_chain: Bytes32,
}

#[derive(Debug, Clone)]
pub struct BlockTarget {
    // user length is the constant of the circuit
    pub num_users: u32,

    pub aggregator_id: Target,
    pub timestamp: U64Target,
    pub local_ids: Vec<Target>,
    pub tx_tree_root: Bytes32Target,
    pub deposit_hash_chain: Bytes32Target,
    pub forced_tx_hash_chain: Bytes32Target,
}

impl Block {
    pub fn new(
        num_users: u32,
        aggregator_id: u32,
        local_ids: &[u32],
        timestamp: u64,
        tx_tree_root: Bytes32,
        deposit_hash_chain: Bytes32,
        forced_tx_hash_chain: Bytes32,
    ) -> Result<Self, BlockError> {
        if local_ids.len() as u32 > num_users {
            return Err(BlockError::InvalidNumUsers(format!(
                "local_ids length is {}, but num_users is {}",
                local_ids.len(),
                num_users
            )));
        }
        // pad user_ids with zeros
        let mut local_ids = local_ids.to_vec();
        local_ids.resize(num_users as usize, 0);

        Ok(Self {
            num_users,
            aggregator_id,
            timestamp,
            local_ids,
            tx_tree_root,
            deposit_hash_chain,
            forced_tx_hash_chain,
        })
    }

    pub fn hash_with_prev_hash(&self, prev_hash: Bytes32) -> Result<Bytes32, BlockError> {
        // local_ids should be alread padded with zeros
        if self.local_ids.len() as u32 != self.num_users {
            return Err(BlockError::InvalidNumUsers(format!(
                "local_ids length is {}, but num_users is {}",
                self.local_ids.len(),
                self.num_users
            )));
        }
        let inputs = [
            prev_hash.to_u32_vec(),
            vec![self.aggregator_id],
            U64::from(self.timestamp).to_u32_vec(),
            self.local_ids.to_vec(),
            self.tx_tree_root.to_u32_vec(),
            self.deposit_hash_chain.to_u32_vec(),
            self.forced_tx_hash_chain.to_u32_vec(),
        ]
        .concat();
        Ok(Bytes32::from_u32_slice(&solidity_keccak256(&inputs)).expect("hashing result invalid"))
    }
}

impl BlockTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        num_users: u32,
        is_checked: bool,
    ) -> Self {
        let aggregator_id = builder.add_virtual_target();
        if is_checked {
            builder.range_check(aggregator_id, AGGREGATOR_ID_BITS);
        }

        let timestamp = U64Target::new(builder, is_checked);

        let local_ids = (0..num_users)
            .map(|_| {
                let target = builder.add_virtual_target();
                if is_checked {
                    builder.range_check(target, LOCAL_ID_BITS);
                }
                target
            })
            .collect();

        let tx_tree_root = Bytes32Target::new(builder, is_checked);
        let deposit_hash_chain = Bytes32Target::new(builder, is_checked);
        let forced_tx_hash_chain = Bytes32Target::new(builder, is_checked);

        Self {
            num_users,
            aggregator_id,
            timestamp,
            local_ids,
            tx_tree_root,
            deposit_hash_chain,
            forced_tx_hash_chain,
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &Block,
    ) -> Self {
        if value.local_ids.len() as u32 != value.num_users {
            panic!("user_ids length does not match num_users");
        }
        let aggregator_id = builder.constant(F::from_canonical_u32(value.aggregator_id));
        let timestamp = U64Target::constant(builder, U64::from(value.timestamp));
        let local_ids = value
            .local_ids
            .iter()
            .cloned()
            .map(|id| builder.constant(F::from_canonical_u32(id)))
            .collect();
        let tx_tree_root = Bytes32Target::constant(builder, value.tx_tree_root);
        let deposit_hash_chain = Bytes32Target::constant(builder, value.deposit_hash_chain);
        let forced_tx_hash_chain = Bytes32Target::constant(builder, value.forced_tx_hash_chain);
        Self {
            num_users: value.num_users,
            aggregator_id,
            timestamp,
            local_ids,
            tx_tree_root,
            deposit_hash_chain,
            forced_tx_hash_chain,
        }
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
        inputs.extend(self.timestamp.to_vec());
        inputs.extend(self.local_ids.iter().copied());
        inputs.extend(self.tx_tree_root.to_vec());
        inputs.extend(self.deposit_hash_chain.to_vec());
        inputs.extend(self.forced_tx_hash_chain.to_vec());
        Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &Block) {
        assert_eq!(self.num_users, value.num_users, "num_users mismatch");
        witness.set_target(
            self.aggregator_id,
            F::from_canonical_u32(value.aggregator_id),
        );
        self.timestamp
            .set_witness(witness, U64::from(value.timestamp));
        for (target, local_id) in self.local_ids.iter().zip(value.local_ids.iter()) {
            witness.set_target(*target, F::from_canonical_u32(*local_id));
        }
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        self.deposit_hash_chain
            .set_witness(witness, value.deposit_hash_chain);
        self.forced_tx_hash_chain
            .set_witness(witness, value.forced_tx_hash_chain);
    }
}
