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
        deposit::Deposit,
        trees::{
            account_tree::{AccountLeaf, AccountTree, SendLeaf, SendTree},
            deposit_tree::DepositTree,
            public_state_tree::PublicStateTree,
        },
        u63::{BlockNumber, BlockNumberError, BlockNumberTarget, U63Target},
        user_id::{UserId, UserIdError},
    },
    constants::get_num_users,
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
    utils::{
        error::PoseidonHashOutError,
        leafable::{Leafable, LeafableTarget},
        leafable_hasher::PoseidonLeafableHasher,
        poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
    },
};

pub const PUBLIC_STATE_U64_LEN: usize = 1 + 3 * POSEIDON_HASH_OUT_LEN;

#[derive(thiserror::Error, Debug)]
pub enum PublicStateError {
    #[error("Invalid public state length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Block number error: {0}")]
    BlockNumber(#[from] BlockNumberError),

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
    pub account_tree_root: PoseidonHashOut,
    pub deposit_tree_root: PoseidonHashOut,
    pub prev_public_state_root: PoseidonHashOut,
}

impl Default for PublicState {
    fn default() -> Self {
        Self {
            block_number: BlockNumber::default(),
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
            block_number: BlockNumber::default(),
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

        // create block
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
        let block_number = self.block_number.as_u64() + 1;
        self.block_number =
            BlockNumber::new(block_number).expect("block number should fit within 63 bits");
        self.blocks.push(block.clone());
        self.block_hash_chain = block
            .hash_with_prev_hash(self.block_hash_chain)
            .expect("hashing should not fail");

        // update account tree
        for &local_id in local_ids {
            if local_id == 0 {
                // ignore zero local_id (padding or dummy)
                continue;
            }
            let user_id = UserId::new(aggregator_id, local_id)?;
            let mut send_leaves = self.send_leaves.get(&user_id).cloned().unwrap_or_default();
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

            // sanity check
            let account_leaf = AccountLeaf {
                index: send_tree.len() as u32,
                prev,
                send_tree_root: send_tree.get_root(),
            };
            let current_account_leaf = self.account_tree.get_leaf(user_id.as_u64());
            assert_eq!(
                current_account_leaf, account_leaf,
                "Account leaf mismatch for user_id {:?}: calculated from send leaves {:?}, actual {:?}",
                user_id, account_leaf, current_account_leaf
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
            self.send_leaves.insert(user_id, send_leaves.clone());

            // update account tree
            let new_account_leaf = AccountLeaf {
                index: send_tree.len() as u32,
                prev: current_block,
                send_tree_root: send_tree.get_root(),
            };
            self.account_tree.update(user_id.as_u64(), new_account_leaf);
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
        let block_number = self.block_number.as_u64() + 1;
        let deposit = Deposit {
            depositor,
            recipient,
            token_index,
            amount,
            aux_data,
            block_number: BlockNumber::new(block_number)
                .expect("block number should fit within 63 bits"),
        };

        // add deposit
        self.deposits.push(deposit.clone());
        self.deposit_tree.push(deposit.clone());
        self.deposit_hash_chain = deposit.hash_with_prev_hash(self.deposit_hash_chain);

        Ok(())
    }
}
