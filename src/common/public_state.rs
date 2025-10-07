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
        block_number::{BlockNumber, BlockNumberTarget},
        deposit::Deposit,
        trees::{
            account_tree::{AccountLeaf, AccountTree, SendLeaf, SendTree},
            deposit_tree::DepositTree,
            public_state_tree::PublicStateTree,
        },
        user_id::{UserId, UserIdError},
    },
    constants::get_num_users,
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
    utils::{
        leafable::{Leafable, LeafableTarget},
        leafable_hasher::PoseidonLeafableHasher,
        poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
    },
};

pub const PUBLIC_STATE_U64_LEN: usize = 1 + 3 * POSEIDON_HASH_OUT_LEN;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicState {
    pub block_number: BlockNumber,
    pub account_tree_root: PoseidonHashOut,
    pub deposit_tree_root: PoseidonHashOut,
    pub prev_public_state_root: PoseidonHashOut,
}

impl Default for PublicState {
    fn default() -> Self {
        Self {
            block_number: BlockNumber(0),
            account_tree_root: AccountTree::init().get_root(),
            deposit_tree_root: DepositTree::init().get_root(),
            prev_public_state_root: PublicStateTree::init().get_root(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublicStateTarget {
    pub block_number: BlockNumberTarget,
    pub account_tree_root: PoseidonHashOutTarget,
    pub deposit_tree_root: PoseidonHashOutTarget,
    pub prev_public_state_root: PoseidonHashOutTarget,
}

impl PublicState {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.block_number.to_u64_vec(),
            self.account_tree_root.to_u64_vec(),
            self.deposit_tree_root.to_u64_vec(),
            self.prev_public_state_root.to_u64_vec(),
        ]
        .concat()
    }

    pub fn poseidon_hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

impl Leafable for PublicState {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        self.poseidon_hash()
    }
}

impl PublicStateTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.block_number.to_vec(),
            self.account_tree_root.to_vec(),
            self.deposit_tree_root.to_vec(),
            self.prev_public_state_root.to_vec(),
        ]
        .concat()
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            block_number: BlockNumberTarget::new(builder, is_checked),
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
            account_tree_root: PoseidonHashOutTarget::constant(builder, value.account_tree_root),
            deposit_tree_root: PoseidonHashOutTarget::constant(builder, value.deposit_tree_root),
            prev_public_state_root: PoseidonHashOutTarget::constant(
                builder,
                value.prev_public_state_root,
            ),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &PublicState) {
        self.block_number.set_witness(witness, value.block_number);
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
        let account_eq = self
            .account_tree_root
            .is_equal(builder, &other.account_tree_root);
        let deposit_eq = self
            .deposit_tree_root
            .is_equal(builder, &other.deposit_tree_root);
        let prev_state_eq = self
            .prev_public_state_root
            .is_equal(builder, &other.prev_public_state_root);

        let tmp = builder.and(block_eq, account_eq);
        let tmp = builder.and(tmp, deposit_eq);
        builder.and(tmp, prev_state_eq)
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        builder.connect(self.block_number.value, other.block_number.value);
        self.account_tree_root
            .connect(builder, other.account_tree_root.clone());
        self.deposit_tree_root
            .connect(builder, other.deposit_tree_root.clone());
        self.prev_public_state_root
            .connect(builder, other.prev_public_state_root.clone());
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
    #[error("Too many local IDs: {0}")]
    TooManyLocalIds(usize),

    #[error("UserId error: {0}")]
    UserIdError(#[from] UserIdError),

    #[error("Block error: {0}")]
    BlockError(#[from] BlockError),
}

pub struct FullPublicState {
    pub block_number: BlockNumber,
    pub account_tree: AccountTree,
    pub send_leaves: HashMap<UserId, Vec<SendLeaf>>,
    pub deposit_tree: DepositTree,
    pub public_state_tree: PublicStateTree,

    pub blocks: Vec<Block>,
    pub deposits: Vec<Deposit>,
    pub block_hash_chain: Bytes32,
    pub deposit_hash_chain: Bytes32,
}

impl FullPublicState {
    pub fn new() -> Self {
        Self {
            block_number: BlockNumber(0),
            account_tree: AccountTree::init(),
            send_leaves: HashMap::new(),
            deposit_tree: DepositTree::init(),
            public_state_tree: PublicStateTree::init(),

            blocks: vec![Block::default()], // genesis block
            deposits: vec![],
            block_hash_chain: Bytes32::default(),
            deposit_hash_chain: Bytes32::default(),
        }
    }

    pub fn to_public_state(&self) -> PublicState {
        PublicState {
            block_number: self.block_number,
            account_tree_root: self.account_tree.get_root(),
            deposit_tree_root: self.deposit_tree.get_root(),
            prev_public_state_root: self.public_state_tree.get_root(),
        }
    }

    pub fn add_block(
        &mut self,
        aggregator_id: u32,
        local_ids: &[u32],
        tx_tree_root: Bytes32,
    ) -> Result<(), FullPublicStateError> {
        let num_users = get_num_users(local_ids.len())
            .ok_or(FullPublicStateError::TooManyLocalIds(local_ids.len()))?;
        let block_number = self.block_number.0 + 1;
        let block = Block::new(
            num_users,
            aggregator_id,
            local_ids,
            tx_tree_root,
            self.deposit_hash_chain,
        )?;
        // update public state tree
        let prev_public_state = self.to_public_state();
        self.public_state_tree.push(prev_public_state);

        // add block
        self.block_number = BlockNumber(block_number);
        self.blocks.push(block.clone());
        self.block_hash_chain = block
            .hash_with_prev_hash(self.block_hash_chain)
            .expect("hashing should not fail");

        // update account tree
        for &local_id in local_ids {
            if local_id == 0 {
                // skip dummy local_id
                continue;
            }
            let user_id = UserId::new(aggregator_id, local_id)?;
            let mut send_leaves = self.send_leaves.get(&user_id).cloned().unwrap_or_default();
            let prev = if let Some(last) = send_leaves.last() {
                last.cur
            } else {
                BlockNumber(0)
            };
            if prev == BlockNumber(block_number) {
                // skip if the user already has a tx in this block
                continue;
            }

            // reconstruct send tree from send leaves
            let mut send_tree = SendTree::init();
            for leaf in &send_leaves {
                send_tree.push(leaf.clone());
            }

            // sanity check
            let account_leaf = AccountLeaf {
                index: send_tree.len() as u64,
                prev,
                send_tree_root: send_tree.get_root(),
            };
            let current_account_leaf = self.account_tree.get_leaf(user_id.0);
            assert_eq!(
                current_account_leaf, account_leaf,
                "Account leaf mismatch for user_id {:?}: calculated from send leaves {:?}, actual {:?}",
                user_id, account_leaf, current_account_leaf
            );

            // add new send leaf
            let new_send_leaf = SendLeaf {
                cur: BlockNumber(block_number),
                prev,
                tx_tree_root,
            };
            send_tree.push(new_send_leaf.clone());

            // update send leaves
            send_leaves.push(new_send_leaf);
            self.send_leaves.insert(user_id, send_leaves.clone());

            // update account tree
            let new_account_leaf = AccountLeaf {
                index: send_tree.len() as u64,
                prev: BlockNumber(block_number),
                send_tree_root: send_tree.get_root(),
            };
            self.account_tree.update(user_id.0, new_account_leaf);
        }

        Ok(())
    }

    pub fn add_deposit(
        &mut self,
        depositor: Address,
        recipient: Bytes32,
        token_index: u32,
        amount: U256,
        aux_data: Bytes32,
    ) -> Result<(), FullPublicStateError> {
        let block_number = self.block_number.0 + 1;
        let deposit = Deposit {
            depositor,
            recipient,
            token_index,
            amount,
            aux_data,
            block_number: BlockNumber(block_number),
        };

        // add deposit
        self.deposits.push(deposit.clone());
        self.deposit_tree.push(deposit.clone());
        self.deposit_hash_chain = deposit.hash_with_prev_hash(self.deposit_hash_chain);

        Ok(())
    }
}
