use crate::{
    circuits::{
        balance::{
            balance_pis::{
                BALANCE_PUBLIC_INPUTS_LEN, BalancePublicInputs, BalancePublicInputsError,
            },
            balance_processor::{BalanceProcessor, BalanceProcessorError},
            common::{
                deposit_witness::{DepositWitness, DepositWitnessError},
                transfer_witness::{TransferWitness, TransferWitnessError},
                tx_settlement::{TxSettlement, TxSettlementError},
                update_private_state::{UpdatePrivateState, UpdatePrivateStateError},
                update_public_state::UpdatePublicStateError,
            },
            receive_deposit_circuit::ReceiveDepositWitness,
            receive_transfer_circuit::ReceiveTransferWitness,
            send_tx_circuit::SendTxWitness,
            spend_circuit::SpendWitness,
        },
        test_utils::block_witness_generator::{BlockWitnessGenerator, BlockWitnessGeneratorError},
    },
    common::{
        error::CommonError,
        private_state::FullPrivateState,
        salt::Salt,
        transfer::Transfer,
        trees::{transfer_tree::TransferMerkleProof, tx_tree::TxMerkleProof},
        tx::Tx,
        u63::BlockNumber,
        user_id::UserId,
    },
    constants::MAX_NUM_TRANSFERS_PER_TX,
    ethereum_types::bytes32::Bytes32,
    utils::conversion::ToU64,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BalanceWitnessGeneratorError {
    #[error("failed to parse balance public inputs: {0}")]
    BalancePublicInputs(#[from] BalancePublicInputsError),

    #[error("update public state error: {0}")]
    UpdatePublicState(#[from] UpdatePublicStateError),

    #[error("block witness error: {0}")]
    BlockWitness(#[from] BlockWitnessGeneratorError),

    #[error("transfer witness error: {0}")]
    TransferWitness(#[from] TransferWitnessError),

    #[error("nullifier tree error: {0}")]
    Nullifier(#[from] CommonError),

    #[error("private state update error: {0}")]
    UpdatePrivateState(#[from] UpdatePrivateStateError),

    #[error("tx settlement error: {0}")]
    TxSettlement(#[from] TxSettlementError),

    #[error("spend proof public inputs error: {0}")]
    SpendPis(String),

    #[error("initial balance proof error: {0}")]
    InitialProof(#[from] BalanceProcessorError),

    #[error("deposit witness error: {0}")]
    DepositWitness(#[from] DepositWitnessError),

    #[error("invalid block selection: {0}")]
    InvalidBlock(String),
}

// generate witness for balance processor
#[derive(Clone, Debug)]
pub struct BalanceWitnessGenerator<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub user_id: UserId,
    pub salt: Salt,
    pub balance_proof: ProofWithPublicInputs<F, C, D>,
    pub full_private_state: FullPrivateState,

    pub block_witness_generator: Arc<BlockWitnessGenerator>,
}

impl<F, C, const D: usize> BalanceWitnessGenerator<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        user_id: UserId,
        salt: Salt,
        block_witness_generator: Arc<BlockWitnessGenerator>,
        balance_processor: &BalanceProcessor<F, C, D>,
    ) -> Result<Self, BalanceWitnessGeneratorError> {
        let balance_proof = balance_processor.prove_initial(user_id, salt)?;

        Ok(Self {
            user_id,
            salt,
            balance_proof,
            full_private_state: FullPrivateState::new(salt),
            block_witness_generator,
        })
    }

    // get balance public inputs from the witness generator
    pub fn get_public_inputs(&self) -> Result<BalancePublicInputs, BalanceWitnessGeneratorError> {
        let pis_u64 = self.balance_proof.public_inputs.to_u64_vec();
        BalancePublicInputs::from_u64(&pis_u64[..BALANCE_PUBLIC_INPUTS_LEN])
            .map_err(BalanceWitnessGeneratorError::from)
    }

    pub fn spend_witness(
        &self,
        transfers: &[Transfer],
    ) -> Result<SpendWitness, BalanceWitnessGeneratorError> {
        let prev_private_state = self.full_private_state.to_private_state();

        let mut padded_transfers = transfers.to_vec();
        padded_transfers.resize(MAX_NUM_TRANSFERS_PER_TX, Transfer::default());

        let mut asset_tree = self.full_private_state.asset_tree.clone();
        let mut before_balances = Vec::with_capacity(MAX_NUM_TRANSFERS_PER_TX);
        let mut asset_merkle_proofs = Vec::with_capacity(MAX_NUM_TRANSFERS_PER_TX);

        for transfer in padded_transfers.iter() {
            let index = transfer.token_index as u64;
            let prev_balance = asset_tree.get_leaf(index);
            let proof = asset_tree.prove(index);
            before_balances.push(prev_balance);
            asset_merkle_proofs.push(proof);

            let new_balance = prev_balance - transfer.amount;
            asset_tree.update(index, new_balance);
        }

        let witness = SpendWitness {
            tx_nonce: prev_private_state.nonce,
            prev_private_state,
            transfers: padded_transfers,
            before_balances,
            asset_merkle_proofs,
        };

        Ok(witness)
    }

    pub fn receive_transfer_witness(
        &self,
        data: &ReceiveTransferData<F, C, D>,
    ) -> Result<ReceiveTransferWitness<F, C, D>, BalanceWitnessGeneratorError> {
        let prev_balance_proof = self.balance_proof.clone();
        let prev_balance_pis = self.get_public_inputs()?;

        let sender_balance_pis = BalancePublicInputs::from_u64(
            &data.sender_proof.public_inputs.to_u64_vec()[..BALANCE_PUBLIC_INPUTS_LEN],
        )
        .map_err(BalanceWitnessGeneratorError::from)?;

        assert_eq!(data.to, self.user_id);
        let sender_update_public_state = self
            .block_witness_generator
            .get_update_public_state_witness(sender_balance_pis.public_state.block_number)?;
        let receiver_update_public_state = self
            .block_witness_generator
            .get_update_public_state_witness(prev_balance_pis.public_state.block_number)?;

        assert_eq!(
            sender_update_public_state.old, sender_balance_pis.public_state,
            "sender old public state mismatch",
        );
        assert_eq!(
            receiver_update_public_state.old, prev_balance_pis.public_state,
            "receiver old public state mismatch",
        );
        let new_public_state = receiver_update_public_state.new.clone();
        assert_eq!(
            sender_update_public_state.new, new_public_state,
            "sender and receiver must agree on new public state",
        );

        let send_status = self
            .block_witness_generator
            .get_send_status(self.user_id, prev_balance_pis.block_r)?;
        let new_block_r = match send_status.next_send_block {
            Some(next_block) => BlockNumber::new(next_block.as_u64() - 1)
                .map_err(|e| BalanceWitnessGeneratorError::InvalidBlock(e.to_string()))?,
            None => self.block_witness_generator.block_number,
        };
        if new_block_r.as_u64() < prev_balance_pis.block_r.as_u64() {
            return Err(BalanceWitnessGeneratorError::InvalidBlock(format!(
                "new_block_r {} is smaller than previous block_r {}",
                new_block_r.as_u64(),
                prev_balance_pis.block_r.as_u64()
            )));
        }

        let account_state_sender = self
            .block_witness_generator
            .get_account_state_for_tx(sender_balance_pis.user_id, data.tx_tree_root)?
            .1;
        let tx_block_number = account_state_sender.send_leaf.cur;
        if tx_block_number.as_u64() > new_block_r.as_u64() {
            return Err(BalanceWitnessGeneratorError::InvalidBlock(format!(
                "tx block number {} exceeds receiver new_block_r {}",
                tx_block_number.as_u64(),
                new_block_r.as_u64()
            )));
        }
        assert_eq!(
            account_state_sender.account_tree_root,
            sender_update_public_state.new.account_tree_root,
            "sender account state root mismatch",
        );

        let (_, account_state_receiver) = self
            .block_witness_generator
            .get_account_state(self.user_id, prev_balance_pis.block_r)?;
        assert_eq!(
            account_state_receiver.account_tree_root, new_public_state.account_tree_root,
            "receiver account state root mismatch",
        );

        let tx_merkle_proof = data.tx_merkle_proof.clone();
        let tx_settlement = TxSettlement {
            user_id: sender_balance_pis.user_id,
            tx: data.tx,
            public_state: sender_update_public_state.new.clone(),
            account_state: account_state_sender,
            tx_merkle_proof,
            spend_proof: data.spend_proof.clone(),
        };

        let transfer_witness = TransferWitness::new(
            data.tx.transfer_tree_root,
            data.transfer.clone(),
            data.transfer_index,
            data.transfer_merkle_proof.clone(),
        )?;

        let nullifier = transfer_witness.transfer.nullifier();
        let mut nullifier_tree = self.full_private_state.nullifier_tree.clone();
        let nullifier_proof = nullifier_tree.prove_and_insert(nullifier)?;

        let asset_tree = self.full_private_state.asset_tree.clone();
        let token_index = transfer_witness.transfer.token_index as u64;
        let prev_balance = asset_tree.get_leaf(token_index);
        let asset_merkle_proof = asset_tree.prove(token_index);

        let prev_private_state = self.full_private_state.to_private_state();
        let update_private_state = UpdatePrivateState::new(
            transfer_witness.transfer.token_index,
            transfer_witness.transfer.amount,
            nullifier,
            &prev_private_state,
            &nullifier_proof,
            prev_balance,
            &asset_merkle_proof,
        )?;

        Ok(ReceiveTransferWitness {
            prev_balance_proof,
            sender_balance_proof: data.sender_proof.clone(),
            sender_update_public_state,
            receiver_update_public_state,
            new_block_r,
            account_state: account_state_receiver,
            tx_settlement,
            transfer_witness,
            transfer_salt: data.transfer_salt,
            update_private_state,
        })
    }

    pub fn commit_receive_transfer(
        &mut self,
        new_balance_proof: &ProofWithPublicInputs<F, C, D>,
        witness: &ReceiveTransferWitness<F, C, D>,
    ) -> Result<(), BalanceWitnessGeneratorError> {
        self.balance_proof = new_balance_proof.clone();

        let token_index = witness.update_private_state.token_index as u64;
        let prev_balance = self.full_private_state.asset_tree.get_leaf(token_index);
        assert_eq!(prev_balance, witness.update_private_state.prev_balance);
        let new_balance = prev_balance + witness.update_private_state.amount;
        self.full_private_state
            .asset_tree
            .update(token_index, new_balance);

        let _ = self
            .full_private_state
            .nullifier_tree
            .prove_and_insert(witness.update_private_state.nullifier)?;

        self.full_private_state.prev_private_commitment =
            witness.update_private_state.prev_private_state.commitment();
        self.full_private_state.nonce = witness.update_private_state.new_private_state.nonce;
        self.full_private_state.salt = witness.update_private_state.new_private_state.salt;

        let expected_commitment = witness.update_private_state.new_private_state.commitment();
        let actual_commitment = self.full_private_state.to_private_state().commitment();
        assert_eq!(expected_commitment, actual_commitment);

        Ok(())
    }

    pub fn receive_deposit_witness(
        &self,
        data: &ReceiveDepositData,
    ) -> Result<ReceiveDepositWitness<F, C, D>, BalanceWitnessGeneratorError> {
        let prev_balance_proof = self.balance_proof.clone();
        let prev_balance_pis = self.get_public_inputs()?;

        let update_public_state = self
            .block_witness_generator
            .get_update_public_state_witness(prev_balance_pis.public_state.block_number)?;
        assert_eq!(
            update_public_state.old, prev_balance_pis.public_state,
            "update_public_state old mismatch for deposit",
        );
        let new_public_state = update_public_state.new.clone();

        let send_status = self
            .block_witness_generator
            .get_send_status(self.user_id, prev_balance_pis.block_r)?;
        let new_block_r = match send_status.next_send_block {
            Some(next_block) => BlockNumber::new(next_block.as_u64() - 1)
                .map_err(|e| BalanceWitnessGeneratorError::InvalidBlock(e.to_string()))?,
            None => self.block_witness_generator.block_number,
        };
        if new_block_r.as_u64() < prev_balance_pis.block_r.as_u64() {
            return Err(BalanceWitnessGeneratorError::InvalidBlock(format!(
                "new_block_r {} is smaller than previous block_r {}",
                new_block_r.as_u64(),
                prev_balance_pis.block_r.as_u64()
            )));
        }

        let (_, account_state) = self
            .block_witness_generator
            .get_account_state(self.user_id, prev_balance_pis.block_r)?;
        assert_eq!(
            account_state.account_tree_root, new_public_state.account_tree_root,
            "account state root mismatch for deposit",
        );

        let (deposit, deposit_index, deposit_merkle_proof) = self
            .block_witness_generator
            .get_deposit_merkle_proof(data.receiver)?;
        if deposit.block_number.as_u64() > new_block_r.as_u64() {
            return Err(BalanceWitnessGeneratorError::InvalidBlock(format!(
                "deposit block number {} exceeds receiver new_block_r {}",
                deposit.block_number.as_u64(),
                new_block_r.as_u64()
            )));
        }

        let mut nullifier_tree = self.full_private_state.nullifier_tree.clone();
        let deposit_nullifier = deposit.nullifier();
        let nullifier_proof = nullifier_tree.prove_and_insert(deposit_nullifier)?;

        let asset_tree = self.full_private_state.asset_tree.clone();
        let token_index = deposit.token_index as u64;
        let prev_balance = asset_tree.get_leaf(token_index);
        let asset_merkle_proof = asset_tree.prove(token_index);

        let prev_private_state = self.full_private_state.to_private_state();
        let update_private_state = UpdatePrivateState::new(
            deposit.token_index,
            deposit.amount,
            deposit_nullifier,
            &prev_private_state,
            &nullifier_proof,
            prev_balance,
            &asset_merkle_proof,
        )?;

        let deposit_witness = DepositWitness::new(
            self.user_id,
            new_public_state.deposit_tree_root,
            data.deposit_salt,
            deposit.clone(),
            deposit_index,
            deposit_merkle_proof,
        )?;

        Ok(ReceiveDepositWitness {
            prev_balance_proof,
            update_public_state,
            new_block_r,
            account_state,
            deposit_witness,
            update_private_state,
        })
    }

    pub fn commit_receive_deposit(
        &mut self,
        new_balance_proof: &ProofWithPublicInputs<F, C, D>,
        witness: &ReceiveDepositWitness<F, C, D>,
    ) -> Result<(), BalanceWitnessGeneratorError> {
        self.balance_proof = new_balance_proof.clone();

        let token_index = witness.deposit_witness.deposit.token_index as u64;
        let prev_balance = self.full_private_state.asset_tree.get_leaf(token_index);
        assert_eq!(prev_balance, witness.update_private_state.prev_balance);
        let new_balance = prev_balance + witness.update_private_state.amount;
        self.full_private_state
            .asset_tree
            .update(token_index, new_balance);

        let _ = self
            .full_private_state
            .nullifier_tree
            .prove_and_insert(witness.update_private_state.nullifier)?;

        self.full_private_state.prev_private_commitment =
            witness.update_private_state.prev_private_state.commitment();
        self.full_private_state.nonce = witness.update_private_state.new_private_state.nonce;
        self.full_private_state.salt = witness.update_private_state.new_private_state.salt;

        let expected_commitment = witness.update_private_state.new_private_state.commitment();
        let actual_commitment = self.full_private_state.to_private_state().commitment();
        assert_eq!(expected_commitment, actual_commitment);

        Ok(())
    }

    pub fn send_tx_witness(
        &self,
        data: &SendTxData<F, C, D>,
    ) -> Result<SendTxWitness<F, C, D>, BalanceWitnessGeneratorError> {
        let prev_balance_proof = self.balance_proof.clone();
        let prev_balance_pis = self.get_public_inputs()?;

        let update_public_state = self
            .block_witness_generator
            .get_update_public_state_witness(prev_balance_pis.public_state.block_number)?;
        assert_eq!(
            update_public_state.old, prev_balance_pis.public_state,
            "update_public_state old mismatch for send_tx",
        );
        let new_public_state = update_public_state.new.clone();

        let account_state = self
            .block_witness_generator
            .get_account_state_for_tx(self.user_id, data.tx_tree_root)?
            .1;
        assert_eq!(
            account_state.account_tree_root, new_public_state.account_tree_root,
            "account state root mismatch for send_tx",
        );

        let tx_merkle_proof = data.tx_merkle_proof.clone();
        let tx_settlement = TxSettlement {
            user_id: self.user_id,
            tx: data.tx,
            public_state: new_public_state,
            account_state,
            tx_merkle_proof,
            spend_proof: data.spend_proof.clone(),
        };

        Ok(SendTxWitness {
            prev_balance_proof,
            update_public_state,
            tx_settlement,
        })
    }

    pub fn commit_send_tx(
        &mut self,
        new_balance_proof: &ProofWithPublicInputs<F, C, D>,
        witness: &SendTxWitness<F, C, D>,
        spend_witness: &SpendWitness,
    ) -> Result<(), BalanceWitnessGeneratorError> {
        self.balance_proof = new_balance_proof.clone();

        let spend_pis = witness
            .tx_settlement
            .spend_pis()
            .map_err(|e| BalanceWitnessGeneratorError::SpendPis(e.to_string()))?;

        if spend_pis.is_valid {
            assert_eq!(
                spend_witness.prev_private_state.commitment(),
                spend_pis.prev_private_commitment,
            );

            for (transfer, prev_balance) in spend_witness
                .transfers
                .iter()
                .zip(spend_witness.before_balances.iter())
            {
                let index = transfer.token_index as u64;
                let mut new_balance = prev_balance.clone();
                new_balance -= transfer.amount;
                self.full_private_state
                    .asset_tree
                    .update(index, new_balance);
            }

            self.full_private_state.prev_private_commitment =
                spend_witness.prev_private_state.commitment();
            self.full_private_state.nonce = spend_witness.prev_private_state.nonce + 1;

            let actual_commitment = self.full_private_state.to_private_state().commitment();
            assert_eq!(actual_commitment, spend_pis.new_private_commitment);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveTransferData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub to: UserId,
    pub transfer: Transfer,

    // witness data
    pub sender_proof: ProofWithPublicInputs<F, C, D>,
    pub spend_proof: ProofWithPublicInputs<F, C, D>,
    pub tx_tree_root: Bytes32,
    pub tx: Tx,
    pub tx_merkle_proof: TxMerkleProof,
    pub transfer_index: u32,
    pub transfer_merkle_proof: TransferMerkleProof,
    pub transfer_salt: Salt,
}

#[derive(Debug, Clone)]
pub struct ReceiveDepositData {
    pub receiver: Bytes32,
    pub deposit_salt: Salt,
}

#[derive(Debug, Clone)]
pub struct SendTxData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub spend_proof: ProofWithPublicInputs<F, C, D>,
    pub tx_tree_root: Bytes32,
    pub tx: Tx,
    pub tx_merkle_proof: TxMerkleProof,
}
