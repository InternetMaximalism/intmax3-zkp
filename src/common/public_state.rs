use std::collections::HashMap;

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    common::{
        block::{Block, BlockError},
        channel_id::{ChannelId, ChannelIdError as UserIdError},
        channel_message::ChannelMessage,
        deposit::Deposit,
        trees::{
            channel_tree::{ChannelLeaf, ChannelTree, SendLeaf, SendTree},
            deposit_tree::DepositTree,
            public_state_tree::PublicStateTree,
            tx_v2_tree::compute_tx_v2_root,
        },
        tx::TxV2,
        u63::{BlockNumber, BlockNumberError, BlockNumberTarget, U63, U63Target},
    },
    ethereum_types::{
        address::Address,
        bytes32::Bytes32,
        error::EthereumTypeError,
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
        u64::{U64, U64_LEN, U64Target},
        u256::U256,
    },
    utils::{
        error::PoseidonHashOutError,
        leafable::{Leafable, LeafableTarget},
        leafable_hasher::PoseidonLeafableHasher,
        poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
    },
};

pub const PUBLIC_STATE_U64_LEN: usize = 1 + U64_LEN + 3 * POSEIDON_HASH_OUT_LEN;

#[derive(thiserror::Error, Debug)]
pub enum PublicStateError {
    #[error("Invalid public state length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Block number error: {0}")]
    BlockNumber(#[from] BlockNumberError),

    #[error("Timestamp error: {0}")]
    Timestamp(#[from] EthereumTypeError),

    #[error("Failed to parse {field}: {source}")]
    PoseidonHash {
        field: &'static str,
        #[source]
        source: PoseidonHashOutError,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicState {
    pub block_number: BlockNumber,
    pub timestamp: u64,
    pub account_tree_root: PoseidonHashOut,
    pub deposit_tree_root: PoseidonHashOut,
    pub prev_public_state_root: PoseidonHashOut,
}

impl Default for PublicState {
    fn default() -> Self {
        Self {
            block_number: BlockNumber::default(),
            timestamp: 0,
            account_tree_root: ChannelTree::init().get_root(),
            deposit_tree_root: DepositTree::init().get_root(),
            prev_public_state_root: PublicStateTree::init().get_root(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicStateTarget {
    pub block_number: BlockNumberTarget,
    pub timestamp: U64Target,
    pub account_tree_root: PoseidonHashOutTarget,
    pub deposit_tree_root: PoseidonHashOutTarget,
    pub prev_public_state_root: PoseidonHashOutTarget,
}

impl PublicState {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.block_number.to_u64_vec(),
            U64::from(self.timestamp).to_u64_vec(),
            self.account_tree_root.to_u64_vec(),
            self.deposit_tree_root.to_u64_vec(),
            self.prev_public_state_root.to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, PublicStateError> {
        if values.len() != PUBLIC_STATE_U64_LEN {
            return Err(PublicStateError::InvalidLength {
                expected: PUBLIC_STATE_U64_LEN,
                actual: values.len(),
            });
        }

        let mut cursor = 0;

        let block_number = BlockNumber::new(values[cursor])?;
        cursor += 1;

        let timestamp = U64::from_u64_slice(&values[cursor..cursor + U64_LEN])?;
        cursor += U64_LEN;

        let account_tree_root =
            PoseidonHashOut::from_u64_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|source| PublicStateError::PoseidonHash {
                    field: "account_tree_root",
                    source,
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let deposit_tree_root =
            PoseidonHashOut::from_u64_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|source| PublicStateError::PoseidonHash {
                    field: "deposit_tree_root",
                    source,
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let prev_public_state_root =
            PoseidonHashOut::from_u64_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|source| PublicStateError::PoseidonHash {
                    field: "prev_public_state_root",
                    source,
                })?;

        Ok(Self {
            block_number,
            timestamp: u64::from(timestamp),
            account_tree_root,
            deposit_tree_root,
            prev_public_state_root,
        })
    }

    pub fn poseidon_hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

impl Leafable for PublicState {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self {
            block_number: Default::default(),
            timestamp: 0,
            account_tree_root: Default::default(),
            deposit_tree_root: Default::default(),
            prev_public_state_root: Default::default(),
        }
    }

    fn hash(&self) -> PoseidonHashOut {
        self.poseidon_hash()
    }
}

impl PublicStateTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.block_number.to_vec(),
            self.timestamp.to_vec(),
            self.account_tree_root.to_vec(),
            self.deposit_tree_root.to_vec(),
            self.prev_public_state_root.to_vec(),
        ]
        .concat()
    }

    pub fn from_slice(values: &[Target]) -> Self {
        assert_eq!(values.len(), PUBLIC_STATE_U64_LEN);

        let mut cursor = 0;

        let block_number = BlockNumberTarget::from_slice(&values[cursor..cursor + 1]);
        cursor += 1;

        let timestamp = U64Target::from_slice(&values[cursor..cursor + U64_LEN]);
        cursor += U64_LEN;

        let account_tree_root =
            PoseidonHashOutTarget::from_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let deposit_tree_root =
            PoseidonHashOutTarget::from_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let prev_public_state_root =
            PoseidonHashOutTarget::from_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN]);

        Self {
            block_number,
            timestamp,
            account_tree_root,
            deposit_tree_root,
            prev_public_state_root,
        }
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            block_number: BlockNumberTarget::new(builder, is_checked),
            timestamp: U64Target::new(builder, is_checked),
            account_tree_root: PoseidonHashOutTarget::new(builder),
            deposit_tree_root: PoseidonHashOutTarget::new(builder),
            prev_public_state_root: PoseidonHashOutTarget::new(builder),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &PublicState,
    ) -> Self {
        Self {
            block_number: BlockNumberTarget::constant(builder, value.block_number),
            timestamp: U64Target::constant(builder, U64::from(value.timestamp)),
            account_tree_root: PoseidonHashOutTarget::constant(builder, value.account_tree_root),
            deposit_tree_root: PoseidonHashOutTarget::constant(builder, value.deposit_tree_root),
            prev_public_state_root: PoseidonHashOutTarget::constant(
                builder,
                value.prev_public_state_root,
            ),
        }
    }

    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        when_true: &Self,
        when_false: &Self,
    ) -> Self {
        Self {
            block_number: U63Target::select(
                builder,
                condition,
                &when_true.block_number,
                &when_false.block_number,
            ),
            timestamp: U64Target::select(
                builder,
                condition,
                when_true.timestamp,
                when_false.timestamp,
            ),
            account_tree_root: PoseidonHashOutTarget::select(
                builder,
                condition,
                when_true.account_tree_root.clone(),
                when_false.account_tree_root.clone(),
            ),
            deposit_tree_root: PoseidonHashOutTarget::select(
                builder,
                condition,
                when_true.deposit_tree_root.clone(),
                when_false.deposit_tree_root.clone(),
            ),
            prev_public_state_root: PoseidonHashOutTarget::select(
                builder,
                condition,
                when_true.prev_public_state_root.clone(),
                when_false.prev_public_state_root.clone(),
            ),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &PublicState) {
        self.block_number.set_witness(witness, value.block_number);
        self.timestamp
            .set_witness(witness, U64::from(value.timestamp));
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        self.deposit_tree_root
            .set_witness(witness, value.deposit_tree_root);
        self.prev_public_state_root
            .set_witness(witness, value.prev_public_state_root);
    }

    pub fn is_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> BoolTarget {
        let block_eq = self.block_number.is_equal(builder, &other.block_number);
        let timestamp_eq = self.timestamp.is_equal(builder, &other.timestamp);
        let account_eq = self
            .account_tree_root
            .is_equal(builder, &other.account_tree_root);
        let deposit_eq = self
            .deposit_tree_root
            .is_equal(builder, &other.deposit_tree_root);
        let prev_state_eq = self
            .prev_public_state_root
            .is_equal(builder, &other.prev_public_state_root);

        let tmp = builder.and(block_eq, timestamp_eq);
        let tmp = builder.and(tmp, account_eq);
        let tmp = builder.and(tmp, deposit_eq);
        builder.and(tmp, prev_state_eq)
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        builder.connect(self.block_number.value, other.block_number.value);
        self.timestamp.connect(builder, other.timestamp);
        self.account_tree_root
            .connect(builder, other.account_tree_root.clone());
        self.deposit_tree_root
            .connect(builder, other.deposit_tree_root.clone());
        self.prev_public_state_root
            .connect(builder, other.prev_public_state_root.clone());
    }

    /// Conditionally asserts `self == other`. When `condition` is false, no
    /// equality constraint is imposed.
    pub fn conditional_assert_eq<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
        condition: BoolTarget,
    ) {
        builder.conditional_assert_eq(
            condition.target,
            self.block_number.value,
            other.block_number.value,
        );
        self.timestamp
            .conditional_assert_eq(builder, other.timestamp, condition);
        self.account_tree_root
            .conditional_assert_eq(builder, other.account_tree_root, condition);
        self.deposit_tree_root
            .conditional_assert_eq(builder, other.deposit_tree_root, condition);
        self.prev_public_state_root.conditional_assert_eq(
            builder,
            other.prev_public_state_root,
            condition,
        );
    }
}

impl LeafableTarget for PublicStateTarget {
    type Leaf = PublicState;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, &PublicState::default())
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum FullPublicStateError {
    #[error("Too many key IDs: {0}")]
    TooManyKeyIds(usize),

    #[error("ChannelId error: {0}")]
    UserIdError(#[from] UserIdError),

    #[error("Block error: {0}")]
    BlockError(#[from] BlockError),
}

pub struct FullPublicState {
    pub supported_user_counts: Vec<u32>,

    pub block_number: BlockNumber,
    pub channel_tree: ChannelTree,
    pub send_leaves: HashMap<ChannelId, Vec<SendLeaf>>,
    pub deposit_tree: DepositTree,
    pub public_state_tree: PublicStateTree,

    pub blocks: Vec<Block>,
    pub deposits: Vec<Deposit>,
    pub block_hash_chain: Bytes32,
    pub deposit_hash_chain: Bytes32,
    /// This simple helper never registers channels, so the reg chain stays the zero default; it is
    /// still folded into the block hash (G6) for layout consistency with the on-chain block hash.
    pub channel_reg_hash_chain: Bytes32,
}

impl FullPublicState {
    pub fn new(supported_user_counts: &[u32]) -> Self {
        Self {
            supported_user_counts: supported_user_counts.to_vec(),

            block_number: BlockNumber::default(),
            channel_tree: ChannelTree::init(),
            send_leaves: HashMap::new(),
            deposit_tree: DepositTree::init(),
            public_state_tree: PublicStateTree::init(),

            blocks: vec![Block::default()], // genesis block
            deposits: vec![],
            block_hash_chain: Bytes32::default(),
            deposit_hash_chain: Bytes32::default(),
            channel_reg_hash_chain: Bytes32::default(),
        }
    }

    pub fn to_public_state(&self) -> PublicState {
        let timestamp = self
            .blocks
            .last()
            .map(|block| block.timestamp)
            .unwrap_or_default();

        PublicState {
            block_number: self.block_number,
            timestamp,
            account_tree_root: self.channel_tree.get_root(),
            deposit_tree_root: self.deposit_tree.get_root(),
            prev_public_state_root: self.public_state_tree.get_root(),
        }
    }

    pub fn add_block(
        &mut self,
        channel_id: u32,
        key_ids: &[u32],
        timestamp: u64,
        tx_tree_root: Bytes32,
    ) -> Result<(), FullPublicStateError> {
        self.add_block_with_channel(channel_id, key_ids, timestamp, tx_tree_root)
    }

    pub fn add_block_with_channel(
        &mut self,
        channel_id: u32,
        key_ids: &[u32],
        timestamp: u64,
        tx_tree_root: Bytes32,
    ) -> Result<(), FullPublicStateError> {
        let num_users = get_num_users(key_ids.len(), &self.supported_user_counts)
            .ok_or(FullPublicStateError::TooManyKeyIds(key_ids.len()))?;

        // create block
        let block = Block::new_with_channel(
            num_users,
            channel_id,
            key_ids,
            timestamp,
            tx_tree_root,
            self.deposit_hash_chain,
            self.channel_reg_hash_chain,
        )?;

        // update public state tree
        let prev_public_state = self.to_public_state();
        self.public_state_tree.push(prev_public_state);

        // add block
        let block_number = self.block_number.as_u64() + 1;
        self.block_number =
            BlockNumber::new(block_number).expect("block number should fit within 63 bits");
        self.blocks.push(block.clone());
        self.block_hash_chain = block
            .hash_with_prev_hash(self.block_hash_chain)
            .expect("hashing should not fail");

        // update user tree
        for &key_id in key_ids {
            if key_id == 0 {
                // ignore zero account number (padding or dummy)
                continue;
            }
            // Two-layer identity: the channel-tree index is the channel id alone; member key_ids
            // identify signers within the channel and do not index base-layer state.
            let channel_id = ChannelId::new(channel_id as u64)?;
            let mut send_leaves = self
                .send_leaves
                .get(&channel_id)
                .cloned()
                .unwrap_or_default();
            let prev = if let Some(last) = send_leaves.last() {
                last.cur
            } else {
                BlockNumber::default()
            };
            let current_block =
                BlockNumber::new(block_number).expect("block number should fit within 63 bits");
            if prev == current_block {
                // skip if the user already has a tx in this block
                continue;
            }

            // reconstruct send tree from send leaves
            let mut send_tree = SendTree::init();
            for leaf in &send_leaves {
                send_tree.push(leaf.clone());
            }

            let current_user_leaf = self.channel_tree.get_leaf(channel_id.as_u64());

            // sanity check (member_pubkeys_root preserved from tree, not reconstructed from send
            // leaves)
            let channel_leaf = ChannelLeaf {
                index: send_tree.len() as u32,
                prev,
                send_tree_root: send_tree.get_root(),
                member_pubkeys_root: current_user_leaf.member_pubkeys_root,
            };
            assert_eq!(
                current_user_leaf, channel_leaf,
                "Account leaf mismatch for channel_id {:?}: calculated from send leaves {:?}, actual {:?}",
                channel_id, channel_leaf, current_user_leaf
            );

            // add new send leaf
            let new_send_leaf = SendLeaf {
                cur: current_block,
                prev,
                tx_tree_root,
            };
            send_tree.push(new_send_leaf.clone());

            // update send leaves
            send_leaves.push(new_send_leaf);
            self.send_leaves.insert(channel_id, send_leaves.clone());

            // update user tree (member_pubkeys_root preserved across state transitions)
            let new_user_leaf = ChannelLeaf {
                index: send_tree.len() as u32,
                prev: current_block,
                send_tree_root: send_tree.get_root(),
                member_pubkeys_root: current_user_leaf.member_pubkeys_root,
            };
            self.channel_tree.update(channel_id.as_u64(), new_user_leaf);
        }

        Ok(())
    }

    pub fn add_block_with_tx_tree_root_v2(
        &mut self,
        channel_id: u32,
        key_ids: &[u32],
        timestamp: u64,
        tx_tree_root: PoseidonHashOut,
    ) -> Result<(), FullPublicStateError> {
        self.add_block_with_channel(channel_id, key_ids, timestamp, tx_tree_root.into())
    }

    pub fn add_block_with_tx_v2s(
        &mut self,
        channel_id: u32,
        key_ids: &[u32],
        timestamp: u64,
        txs: &[TxV2],
    ) -> Result<(), FullPublicStateError> {
        self.add_block_with_tx_tree_root_v2(channel_id, key_ids, timestamp, compute_tx_v2_root(txs))
    }

    pub fn add_channel_close_block(
        &mut self,
        channel_id: u32,
        key_ids: &[u32],
        timestamp: u64,
        channel_message: &ChannelMessage,
        seal: Bytes32,
        nonce: u32,
    ) -> Result<(), FullPublicStateError> {
        let close_tx = channel_message.to_channel_close_tx_v2(seal, nonce);
        self.add_block_with_tx_v2s(channel_id, key_ids, timestamp, &[close_tx])
    }

    pub fn add_deposit(
        &mut self,
        depositor: Address,
        recipient: Bytes32,
        token_index: u32,
        amount: U256,
        aux_data: Bytes32,
    ) -> Result<(), FullPublicStateError> {
        // the block number of the deposit is the next block number
        let block_number = self.block_number.add(1).expect("should not overflow");
        let deposit_index =
            U63::new(self.deposits.len() as u64).expect("should fit within 63 bits");
        let deposit = Deposit {
            deposit_index,
            block_number,
            depositor,
            recipient,
            token_index,
            amount,
            aux_data,
        };
        // add deposit
        self.deposits.push(deposit.clone());
        self.deposit_tree.push(deposit.clone());
        self.deposit_hash_chain = deposit.hash_with_prev_hash(self.deposit_hash_chain);

        Ok(())
    }
}

// get next supported user number
pub fn get_num_users(length: usize, supported_user_counts: &[u32]) -> Option<u32> {
    supported_user_counts
        .into_iter()
        .cloned()
        .find(|&num_users| length as u32 <= num_users)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        channel_id::ChannelId,
        trees::tx_v2_tree::compute_tx_v2_root,
        tx::{ChannelAction, ChannelActionKind, TxClass, TxV2},
    };

    #[test]
    fn add_block_with_tx_v2s_uses_tx_v2_root() {
        let mut state = FullPublicState::new(&[1, 2]);
        let tx = TxV2 {
            tx_class: TxClass::ChannelAction,
            transfer_tree_root: PoseidonHashOut::default(),
            nonce: 5,
            channel_action_root: crate::common::trees::tx_v2_tree::compute_channel_action_root(&[
                ChannelAction {
                    kind: ChannelActionKind::InterChannelSend,
                    source_channel_id: ChannelId::new(1).unwrap(),
                    destination_channel_id: ChannelId::new(2).unwrap(),
                    tx_hash: Bytes32::default(),
                    seal: Bytes32::default(),
                    payload_hash: PoseidonHashOut::default(),
                },
            ]),
        };

        state.add_block_with_tx_v2s(1, &[10], 123, &[tx]).unwrap();

        let block = state.blocks.last().unwrap();
        assert_eq!(block.channel_id(), 1);
        assert_eq!(block.key_ids(), &[10]);
        assert_eq!(block.tx_tree_root, compute_tx_v2_root(&[tx]).into());
    }

    #[test]
    fn add_channel_close_block_connects_channel_message_to_block_inclusion() {
        let mut state = FullPublicState::new(&[2]);
        let message = ChannelMessage {
            channel_id: ChannelId::new(7).unwrap(),
            sequence: 3,
            allocations: vec![],
            tx_tree_root: Bytes32::default(),
        };
        let seal = Bytes32::from_u32_slice(&[9, 8, 7, 6, 5, 4, 3, 2]).unwrap();

        state
            .add_channel_close_block(7, &[77], 456, &message, seal, 12)
            .unwrap();

        let expected_tx = message.to_channel_close_tx_v2(seal, 12);
        let block = state.blocks.last().unwrap();
        assert_eq!(
            block.tx_tree_root,
            compute_tx_v2_root(&[expected_tx]).into()
        );
    }
}
