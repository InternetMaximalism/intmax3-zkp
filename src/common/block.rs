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
    common::{trees::tx_v2_tree::compute_tx_v2_root, tx::TxV2},
    constants::{ACCOUNT_NO_BITS, HUB_ID_BITS},
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
}

impl Block {
    pub fn new_with_tx_v2s(
        num_users: u32,
        hub_id: u32,
        account_nos: &[u32],
        timestamp: u64,
        txs: &[TxV2],
        deposit_hash_chain: Bytes32,
    ) -> Result<Self, BlockError> {
        Self::new_with_hub(
            num_users,
            hub_id,
            account_nos,
            timestamp,
            compute_tx_v2_root(txs).into(),
            deposit_hash_chain,
        )
    }

    pub fn new_with_hub(
        num_users: u32,
        hub_id: u32,
        account_nos: &[u32],
        timestamp: u64,
        tx_tree_root: Bytes32,
        deposit_hash_chain: Bytes32,
    ) -> Result<Self, BlockError> {
        Self::new(
            num_users,
            hub_id,
            account_nos,
            timestamp,
            tx_tree_root,
            deposit_hash_chain,
        )
    }

    pub fn new(
        num_users: u32,
        aggregator_id: u32,
        local_ids: &[u32],
        timestamp: u64,
        tx_tree_root: Bytes32,
        deposit_hash_chain: Bytes32,
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
        })
    }

    pub fn hub_id(&self) -> u32 {
        self.aggregator_id
    }

    pub fn account_nos(&self) -> &[u32] {
        &self.local_ids
    }

    pub fn hash_with_prev_hash(&self, prev_hash: Bytes32) -> Result<Bytes32, BlockError> {
        // account_nos should already be padded with zeros
        if self.local_ids.len() as u32 != self.num_users {
            return Err(BlockError::InvalidNumUsers(format!(
                "local_ids length is {}, but num_users is {}",
                self.local_ids.len(),
                self.num_users
            )));
        }
        let inputs = [
            prev_hash.to_u32_vec(),
            vec![self.hub_id()],
            U64::from(self.timestamp).to_u32_vec(),
            self.account_nos().to_vec(),
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
        num_users: u32,
        is_checked: bool,
    ) -> Self {
        let aggregator_id = builder.add_virtual_target();
        if is_checked {
            builder.range_check(aggregator_id, HUB_ID_BITS);
        }

        let timestamp = U64Target::new(builder, is_checked);

        let local_ids = (0..num_users)
            .map(|_| {
                let target = builder.add_virtual_target();
                if is_checked {
                    builder.range_check(target, ACCOUNT_NO_BITS);
                }
                target
            })
            .collect();

        let tx_tree_root = Bytes32Target::new(builder, is_checked);
        let deposit_hash_chain = Bytes32Target::new(builder, is_checked);

        Self {
            num_users,
            aggregator_id,
            timestamp,
            local_ids,
            tx_tree_root,
            deposit_hash_chain,
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
        Self {
            num_users: value.num_users,
            aggregator_id,
            timestamp,
            local_ids,
            tx_tree_root,
            deposit_hash_chain,
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
        Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
    }

    pub fn hub_id(&self) -> Target {
        self.aggregator_id
    }

    pub fn account_nos(&self) -> &[Target] {
        &self.local_ids
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait};
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_block_new_and_hash() {
        let mut rng = StdRng::seed_from_u64(42);
        let tx_tree_root = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);
        let prev_hash = Bytes32::rand(&mut rng);

        let block = Block::new(
            2,
            1,
            &[10, 20],
            1000,
            tx_tree_root,
            deposit_hash_chain,
        )
        .unwrap();

        let h1 = block.hash_with_prev_hash(prev_hash).unwrap();
        let h2 = block.hash_with_prev_hash(prev_hash).unwrap();
        assert_eq!(h1, h2, "block hash should be deterministic");
    }

    #[test]
    fn test_block_hash_is_stable_without_extra_queue_state() {
        let mut rng = StdRng::seed_from_u64(99);
        let tx_tree_root = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);
        let prev_hash = Bytes32::default();

        let block_a = Block::new(
            1,
            1,
            &[1],
            100,
            tx_tree_root,
            deposit_hash_chain,
        )
        .unwrap();

        let block_b = Block::new(
            1,
            1,
            &[1],
            100,
            tx_tree_root,
            deposit_hash_chain,
        )
        .unwrap();

        let h1 = block_a.hash_with_prev_hash(prev_hash).unwrap();
        let h2 = block_b.hash_with_prev_hash(prev_hash).unwrap();
        assert_eq!(h1, h2, "block hash should depend only on the block payload");
    }

    #[test]
    fn test_block_padding() {
        let block = Block::new(
            4,
            1,
            &[10, 20],
            100,
            Bytes32::default(),
            Bytes32::default(),
        )
        .unwrap();
        assert_eq!(block.local_ids.len(), 4);
        assert_eq!(block.local_ids[2], 0);
        assert_eq!(block.local_ids[3], 0);
    }

    #[test]
    fn test_block_new_with_tx_v2s_uses_poseidon_root() {
        use crate::common::{
            trees::tx_v2_tree::{compute_channel_action_root, compute_tx_v2_root},
            tx::{ChannelAction, ChannelActionKind, TxClass, TxV2},
            user_id::AccountId,
        };

        let tx = TxV2 {
            tx_class: TxClass::ChannelAction,
            transfer_tree_root: Default::default(),
            nonce: 11,
            channel_action_root: compute_channel_action_root(&[ChannelAction {
                kind: ChannelActionKind::InterChannelSend,
                source_channel_id: AccountId::new(1, 10).unwrap(),
                destination_channel_id: AccountId::new(2, 20).unwrap(),
                tx_hash: Bytes32::default(),
                seal: Bytes32::default(),
                payload_hash: Default::default(),
            }]),
        };

        let block = Block::new_with_tx_v2s(
            1,
            3,
            &[9],
            100,
            &[tx],
            Bytes32::default(),
        )
        .unwrap();

        assert_eq!(block.tx_tree_root, compute_tx_v2_root(&[tx]).into());
    }
}
