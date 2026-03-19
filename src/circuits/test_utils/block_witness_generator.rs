use crate::{
    circuits::{
        balance::common::{
            account_state::AccountState,
            update_public_state::{UpdatePublicState, UpdatePublicStateError},
        },
        validity::block_hash_chain::{
            block_hash_chain_processor::BlockHashChainProcessorWitness,
            ext_public_state::ExtendedPublicState,
        },
    },
    common::{
        block::{Block, BlockError},
        deposit::Deposit,
        public_state::{PublicState, get_num_users},
        trees::{
            account_tree::{
                AccountLeaf, AccountMerkleProof, AccountTree, SendLeaf, SendMerkleProof, SendTree,
            },
            deposit_tree::{DepositMerkleProof, DepositTree},
            public_state_tree::{PublicStateMerkleProof, PublicStateTree},
        },
        u63::{BlockNumber, BlockNumberError, U63},
        user_id::{UserId, UserIdError},
    },
    constants::{ACCOUNT_TREE_HEIGHT, SEND_TREE_HEIGHT},
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
};
use std::collections::HashMap;

#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(target_arch = "wasm32")]
use std::{
    cell::{Ref, RefCell, RefMut},
    rc::Rc,
};

/// Shared handle to a [`BlockWitnessGenerator`] that works on native and wasm targets.
#[derive(Clone, Debug)]
pub struct BlockWitnessGeneratorHandle {
    #[cfg(target_arch = "wasm32")]
    inner: Rc<RefCell<BlockWitnessGenerator>>,
    #[cfg(not(target_arch = "wasm32"))]
    inner: Arc<RwLock<BlockWitnessGenerator>>,
}

#[cfg(target_arch = "wasm32")]
type BlockWitnessGeneratorReadGuard<'a> = Ref<'a, BlockWitnessGenerator>;
#[cfg(target_arch = "wasm32")]
type BlockWitnessGeneratorWriteGuard<'a> = RefMut<'a, BlockWitnessGenerator>;

#[cfg(not(target_arch = "wasm32"))]
type BlockWitnessGeneratorReadGuard<'a> = RwLockReadGuard<'a, BlockWitnessGenerator>;
#[cfg(not(target_arch = "wasm32"))]
type BlockWitnessGeneratorWriteGuard<'a> = RwLockWriteGuard<'a, BlockWitnessGenerator>;

impl BlockWitnessGeneratorHandle {
    pub fn new(generator: BlockWitnessGenerator) -> Self {
        #[cfg(target_arch = "wasm32")]
        {
            Self {
                inner: Rc::new(RefCell::new(generator)),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Self {
                inner: Arc::new(RwLock::new(generator)),
            }
        }
    }

    pub fn borrow(&self) -> BlockWitnessGeneratorReadGuard<'_> {
        #[cfg(target_arch = "wasm32")]
        {
            self.inner.borrow()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner
                .read()
                .expect("block witness generator read lock")
        }
    }

    pub fn borrow_mut(&self) -> BlockWitnessGeneratorWriteGuard<'_> {
        #[cfg(target_arch = "wasm32")]
        {
            self.inner.borrow_mut()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner
                .write()
                .expect("block witness generator write lock")
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BlockWitnessGeneratorError {
    #[error("Too many local IDs: {0}")]
    TooManyLocalIds(usize),

    #[error("UserId error: {0}")]
    UserIdError(#[from] UserIdError),

    #[error("Block error: {0}")]
    BlockError(#[from] BlockError),

    #[error("Block number error: {0}")]
    BlockNumber(#[from] BlockNumberError),

    #[error("Update public state error: {0}")]
    UpdatePublicState(#[from] UpdatePublicStateError),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

#[derive(Debug, Clone)]
pub struct BlockWitnessGenerator {
    pub supported_user_counts: Vec<u32>,

    pub block_number: BlockNumber,
    pub account_tree: AccountTree,
    pub send_leaves: HashMap<UserId, Vec<SendLeaf>>,
    pub deposit_tree: DepositTree,
    pub public_state_tree: PublicStateTree,

    pub block_hash_chain: Bytes32,
    pub deposit_hash_chain: Bytes32,

    pub blocks: Vec<Block>,
    pub deposits: HashMap<BlockNumber, Vec<Deposit>>,
    pub deposit_counts: u64,
    pub block_chain_witness: HashMap<BlockNumber, BlockHashChainProcessorWitness>,
}

impl BlockWitnessGenerator {
    pub fn new(supported_user_counts: &[u32]) -> Self {
        Self {
            supported_user_counts: supported_user_counts.to_vec(),
            block_number: BlockNumber::default(),
            account_tree: AccountTree::init(),
            send_leaves: HashMap::new(),
            deposit_tree: DepositTree::init(),
            public_state_tree: PublicStateTree::init(),
            block_hash_chain: Bytes32::default(),
            deposit_hash_chain: Bytes32::default(),
            blocks: vec![Block::default()], // genesis block placeholder
            deposits: HashMap::new(),
            deposit_counts: 0,
            block_chain_witness: HashMap::new(),
        }
    }

    fn current_public_state(&self) -> PublicState {
        let timestamp = self
            .blocks
            .last()
            .map(|block| block.timestamp)
            .unwrap_or_default();

        PublicState {
            block_number: self.block_number,
            timestamp,
            account_tree_root: self.account_tree.get_root(),
            deposit_tree_root: self.deposit_tree.get_root(),
            prev_public_state_root: self.public_state_tree.get_root(),
        }
    }

    pub fn current_extended_public_state(&self) -> ExtendedPublicState {
        ExtendedPublicState::new(
            self.current_public_state(),
            self.block_hash_chain,
            self.deposit_hash_chain,
            U63::new(self.deposit_tree.len() as u64).expect("deposit count fits in 63 bits"),
        )
    }

    pub fn add_deposit(
        &mut self,
        depositor: Address,
        recipient: Bytes32,
        token_index: u32,
        amount: U256,
        aux_data: Bytes32,
    ) -> Result<(), BlockWitnessGeneratorError> {
        let target_block_number = self
            .block_number
            .add(1)
            .map_err(BlockWitnessGeneratorError::BlockNumber)?;

        let deposit = Deposit {
            deposit_index: U63::new(self.deposit_counts).unwrap(),
            depositor,
            recipient,
            token_index,
            amount,
            block_number: target_block_number,
            aux_data,
        };

        self.deposits
            .entry(target_block_number)
            .or_default()
            .push(deposit);
        self.deposit_counts += 1;

        Ok(())
    }

    pub fn add_block(
        &mut self,
        aggregator_id: u32,
        local_ids: &[u32],
        timestamp: u64,
        tx_tree_root: Bytes32,
    ) -> Result<(), BlockWitnessGeneratorError> {
        let num_users = get_num_users(local_ids.len(), &self.supported_user_counts)
            .ok_or(BlockWitnessGeneratorError::TooManyLocalIds(local_ids.len()))?;

        let new_block_number = self
            .block_number
            .add(1)
            .map_err(BlockWitnessGeneratorError::BlockNumber)?;

        let mut pending_deposits = self.deposits.remove(&new_block_number).unwrap_or_default();
        let mut projected_deposit_hash_chain = self.deposit_hash_chain;
        for deposit in pending_deposits.iter() {
            projected_deposit_hash_chain =
                deposit.hash_with_prev_hash(projected_deposit_hash_chain);
        }

        let block = Block::new(
            num_users,
            aggregator_id,
            local_ids,
            timestamp,
            tx_tree_root,
            projected_deposit_hash_chain,
        )?;

        let prev_ext_state = self.current_extended_public_state();
        let public_state_index = self.block_number.as_u64();
        let public_state_merkle_proof: PublicStateMerkleProof =
            self.public_state_tree.prove(public_state_index);
        self.public_state_tree.push(prev_ext_state.inner.clone());

        let mut prev_account_leaves = Vec::with_capacity(num_users as usize);
        let mut account_merkle_proofs = Vec::with_capacity(num_users as usize);
        let mut send_merkle_proofs = Vec::with_capacity(num_users as usize);

        let dummy_account_proof = AccountMerkleProof::dummy(ACCOUNT_TREE_HEIGHT);
        let dummy_send_proof = SendMerkleProof::dummy(SEND_TREE_HEIGHT);

        let mut account_tree_for_proofs = self.account_tree.clone();

        for &local_id in block.local_ids.iter() {
            if local_id == 0 {
                prev_account_leaves.push(AccountLeaf::default());
                account_merkle_proofs.push(dummy_account_proof.clone());
                send_merkle_proofs.push(dummy_send_proof.clone());
                continue;
            }

            let user_id = UserId::new(aggregator_id, local_id)?;
            let send_entries = self.send_leaves.entry(user_id).or_insert_with(Vec::new);

            let mut send_tree = SendTree::init();
            for leaf in send_entries.iter() {
                send_tree.push(leaf.clone());
            }

            let prev_account_leaf = account_tree_for_proofs.get_leaf(user_id.as_u64());
            prev_account_leaves.push(prev_account_leaf.clone());

            let account_proof = account_tree_for_proofs.prove(user_id.as_u64());
            account_merkle_proofs.push(account_proof);

            let send_proof = send_tree.prove(prev_account_leaf.index.into());
            send_merkle_proofs.push(send_proof.clone());

            if prev_account_leaf.prev != new_block_number {
                let new_send_leaf = SendLeaf {
                    prev: prev_account_leaf.prev,
                    cur: new_block_number,
                    tx_tree_root,
                };
                let new_send_root =
                    send_proof.get_root(&new_send_leaf, prev_account_leaf.index.into());
                send_tree.push(new_send_leaf.clone());
                send_entries.push(new_send_leaf.clone());

                // pk_hash is preserved from the previous leaf
                let new_account_leaf = AccountLeaf {
                    index: prev_account_leaf.index + 1,
                    prev: new_block_number,
                    send_tree_root: new_send_root,
                    pk_hash: prev_account_leaf.pk_hash,
                };
                account_tree_for_proofs.update(user_id.as_u64(), new_account_leaf.clone());
                self.account_tree.update(user_id.as_u64(), new_account_leaf);
            }
        }

        let mut deposit_step_witness = Vec::with_capacity(pending_deposits.len());
        let mut deposit_hash_chain_acc = self.deposit_hash_chain;
        for deposit in pending_deposits.drain(..) {
            let deposit_index = self.deposit_tree.len() as u64;
            let deposit_merkle_proof = self.deposit_tree.prove(deposit_index);
            deposit_step_witness.push((deposit.clone(), deposit_merkle_proof));
            self.deposit_tree.push(deposit.clone());
            deposit_hash_chain_acc = deposit.hash_with_prev_hash(deposit_hash_chain_acc);
        }
        self.deposit_hash_chain = deposit_hash_chain_acc;

        let block_witness = BlockHashChainProcessorWitness {
            deposit_step_witness,
            block: block.clone(),
            prev_account_leaves,
            account_merkle_proofs,
            send_merkle_proofs,
            public_state_merkle_proof,
            sig_witnesses: None, // dummy witnesses used by default in tests
        };

        self.block_chain_witness
            .insert(new_block_number, block_witness);

        self.block_hash_chain = block.hash_with_prev_hash(self.block_hash_chain)?;
        self.blocks.push(block);
        self.block_number = new_block_number;

        Ok(())
    }

    pub fn get_send_status(
        &self,
        user_id: UserId,
        at_block: BlockNumber,
    ) -> Result<SendStatus, BlockWitnessGeneratorError> {
        let send_leaves = self.send_leaves.get(&user_id).cloned().unwrap_or_default();
        if send_leaves.is_empty() {
            return Ok(SendStatus {
                last_send_block: BlockNumber::default(),
                next_send_block: None,
            });
        }
        if let Some(send_leaf) = send_leaves
            .iter()
            .find(|leaf| leaf.prev <= at_block && at_block < leaf.cur)
        {
            // at_block is in the range of this send leaf
            Ok(SendStatus {
                last_send_block: send_leaf.prev,
                next_send_block: Some(send_leaf.cur),
            })
        } else {
            // at_block is greater than or equal to the last send leaf's cur
            Ok(SendStatus {
                last_send_block: send_leaves.last().unwrap().cur,
                next_send_block: None,
            })
        }
    }

    pub fn get_account_state(
        &self,
        user_id: UserId,
        block_number: BlockNumber,
    ) -> Result<(BlockNumber, AccountState), BlockWitnessGeneratorError> {
        let current_block_number = self.block_number;
        if block_number > current_block_number {
            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                "Requested block number {} is greater than current block number {}",
                block_number.as_u64(),
                current_block_number.as_u64()
            )));
        }

        // find send tree for the user
        let send_leaves = self.send_leaves.get(&user_id).cloned().unwrap_or_default();
        let mut send_tree = SendTree::init();
        for leaf in send_leaves.iter() {
            send_tree.push(leaf.clone());
        }

        // find send leaves that send_leaf.prev <= block_number < send_leaf.cur if any, 0 otherwise
        let send_leaf_index = match send_leaves
            .iter()
            .position(|leaf| leaf.prev <= block_number && block_number < leaf.cur)
        {
            Some(index) => index as u32,
            None => 0, // use default
        };
        let send_leaf = send_tree.get_leaf(send_leaf_index as u64);
        let send_merkle_proof = send_tree.prove(send_leaf_index as u64);

        let account_tree_root = self.account_tree.get_root();
        let account_leaf = self.account_tree.get_leaf(user_id.as_u64());
        let account_merkle_proof = self.account_tree.prove(user_id.as_u64());

        Ok((
            current_block_number,
            AccountState {
                user_id,
                account_tree_root,
                send_leaf,
                send_leaf_index,
                send_merkle_proof,
                account_leaf,
                account_merkle_proof,
            },
        ))
    }

    pub fn get_account_state_for_tx(
        &self,
        user_id: UserId,
        tx_tree_root: Bytes32,
    ) -> Result<(BlockNumber, AccountState), BlockWitnessGeneratorError> {
        let current_block_number = self.block_number;

        // find send tree for the user
        let send_leaves = self.send_leaves.get(&user_id).cloned().unwrap_or_default();
        let send_leaf_index = send_leaves
            .iter()
            .position(|leaf| leaf.tx_tree_root == tx_tree_root)
            .ok_or(BlockWitnessGeneratorError::InvalidRequest(format!(
                "No send leaf found for user {:?} with tx_tree_root {:?}",
                user_id, tx_tree_root
            )))? as u32;

        let mut send_tree = SendTree::init();
        for leaf in send_leaves.iter() {
            send_tree.push(leaf.clone());
        }
        let send_leaf = send_tree.get_leaf(send_leaf_index as u64);
        let send_merkle_proof = send_tree.prove(send_leaf_index as u64);

        let account_tree_root = self.account_tree.get_root();
        let account_leaf = self.account_tree.get_leaf(user_id.as_u64());
        let account_merkle_proof = self.account_tree.prove(user_id.as_u64());

        Ok((
            current_block_number,
            AccountState {
                user_id,
                account_tree_root,
                send_leaf,
                send_leaf_index,
                send_merkle_proof,
                account_leaf,
                account_merkle_proof,
            },
        ))
    }

    pub fn get_update_public_state_witness(
        &self,
        block_number: BlockNumber,
    ) -> Result<UpdatePublicState, BlockWitnessGeneratorError> {
        let current_block_number = self.block_number;
        if block_number > current_block_number {
            return Err(BlockWitnessGeneratorError::InvalidRequest(format!(
                "Requested block number {} is greater than current block number {}",
                block_number.as_u64(),
                current_block_number.as_u64()
            )));
        }

        let new = self.current_public_state();
        if block_number == current_block_number {
            return Ok(UpdatePublicState::new(new.clone(), new.clone(), None)?);
        }
        let merkle_proof = self.public_state_tree.prove(block_number.as_u64());
        let old = self.public_state_tree.get_leaf(block_number.as_u64());
        Ok(UpdatePublicState::new(new, old, Some(merkle_proof))?)
    }

    pub fn get_deposit_merkle_proof(
        &self,
        receiver: Bytes32,
    ) -> Result<(Deposit, DepositMerkleProof), BlockWitnessGeneratorError> {
        let deposits = self.deposit_tree.leaves();
        let deposit_index = deposits
            .iter()
            .position(|d| d.recipient == receiver)
            .ok_or(BlockWitnessGeneratorError::InvalidRequest(format!(
                "No deposit found for receiver {:?}",
                receiver
            )))? as u64;
        let deposit = deposits[deposit_index as usize].clone();
        let deposit_merkle_proof = self.deposit_tree.prove(deposit_index);
        Ok((deposit, deposit_merkle_proof))
    }
}

#[derive(Debug, Clone)]
pub struct SendStatus {
    // the block number of the last send tx. If there is no send tx, it is 0.
    pub last_send_block: BlockNumber,

    // the block number of the next send tx. If there is no next send tx, it is None.
    pub next_send_block: Option<BlockNumber>,
}
