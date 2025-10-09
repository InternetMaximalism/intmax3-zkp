use std::collections::HashMap;

use crate::{
    circuits::validity::block_hash_chain::{
        block_hash_chain_processor::BlockHashChainProcessorWitness,
        ext_public_state::ExtendedPublicState,
    },
    common::{
        block::{Block, BlockError},
        deposit::Deposit,
        public_state::PublicState,
        trees::{
            account_tree::{
                AccountLeaf, AccountMerkleProof, AccountTree, SendLeaf, SendMerkleProof, SendTree,
            },
            deposit_tree::DepositTree,
            public_state_tree::{PublicStateMerkleProof, PublicStateTree},
        },
        u63::{BlockNumber, BlockNumberError, U63},
        user_id::{UserId, UserIdError},
    },
    constants::{ACCOUNT_TREE_HEIGHT, SEND_TREE_HEIGHT, get_num_users},
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
};

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
}

pub struct BlockWitnessGenerator {
    pub block_number: BlockNumber,
    pub account_tree: AccountTree,
    pub send_leaves: HashMap<UserId, Vec<SendLeaf>>,
    pub deposit_tree: DepositTree,
    pub public_state_tree: PublicStateTree,

    pub block_hash_chain: Bytes32,
    pub deposit_hash_chain: Bytes32,

    pub blocks: Vec<Block>,
    pub deposits: HashMap<BlockNumber, Vec<Deposit>>,
    pub block_chain_witness: HashMap<BlockNumber, BlockHashChainProcessorWitness>,
}

impl BlockWitnessGenerator {
    pub fn new() -> Self {
        Self {
            block_number: BlockNumber::default(),
            account_tree: AccountTree::init(),
            send_leaves: HashMap::new(),
            deposit_tree: DepositTree::init(),
            public_state_tree: PublicStateTree::init(),
            block_hash_chain: Bytes32::default(),
            deposit_hash_chain: Bytes32::default(),
            blocks: vec![Block::default()], // genesis block placeholder
            deposits: HashMap::new(),
            block_chain_witness: HashMap::new(),
        }
    }

    fn current_public_state(&self) -> PublicState {
        PublicState {
            block_number: self.block_number,
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

        Ok(())
    }

    pub fn add_block(
        &mut self,
        aggregator_id: u32,
        local_ids: &[u32],
        tx_tree_root: Bytes32,
    ) -> Result<(), BlockWitnessGeneratorError> {
        let num_users = get_num_users(local_ids.len())
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

                let new_account_leaf = AccountLeaf {
                    index: prev_account_leaf.index + 1,
                    prev: new_block_number,
                    send_tree_root: new_send_root,
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
        };

        self.block_chain_witness
            .insert(new_block_number, block_witness);

        self.block_hash_chain = block.hash_with_prev_hash(self.block_hash_chain)?;
        self.blocks.push(block);
        self.block_number = new_block_number;

        Ok(())
    }
}
