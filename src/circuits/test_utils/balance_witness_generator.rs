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
        test_utils::block_witness_generator::{
            BlockWitnessGeneratorError, BlockWitnessGeneratorHandle,
        },
        withdraw::single_withdrawal_circuit::SingleWithdawalWitness,
    },
    common::{
        channel_id::ChannelId,
        error::CommonError,
        private_state::FullPrivateState,
        salt::Salt,
        transfer::{SettledTransfer, Transfer},
        trees::{
            transfer_tree::TransferMerkleProof, tx_tree::TxMerkleProof, tx_v2_tree::TxV2MerkleProof,
        },
        tx::{Tx, TxV2},
        u63::BlockNumber,
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
    C: GenericConfig<D, F = F> + Default + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub channel_id: ChannelId,
    pub salt: Salt,
    pub balance_proof: ProofWithPublicInputs<F, C, D>,
    pub full_private_state: FullPrivateState,

    pub block_witness_generator: BlockWitnessGeneratorHandle,
}

impl<F, C, const D: usize> BalanceWitnessGenerator<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + Default + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        channel_id: ChannelId,
        salt: Salt,
        block_witness_generator: BlockWitnessGeneratorHandle,
        balance_processor: &BalanceProcessor<F, C, D>,
    ) -> Result<Self, BalanceWitnessGeneratorError> {
        let balance_proof = balance_processor.prove_initial(channel_id, salt)?;

        Ok(Self {
            channel_id,
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
        let sent_tx_merkle_proof = self
            .full_private_state
            .sent_tx_tree
            .prove(self.full_private_state.nonce as u64);

        let witness = SpendWitness {
            tx_nonce: prev_private_state.nonce,
            prev_private_state,
            transfers: padded_transfers,
            before_balances,
            asset_merkle_proofs,
            sent_tx_merkle_proof,
        };

        Ok(witness)
    }

    pub fn receive_transfer_witness(
        &self,
        data: &ReceiveTransferData<F, C, D>,
    ) -> Result<ReceiveTransferWitness<F, C, D>, BalanceWitnessGeneratorError> {
        let prev_balance_proof = self.balance_proof.clone();
        let prev_balance_pis = self.get_public_inputs()?;
        let current_block_number = self.block_witness_generator.borrow().block_number;

        let sender_balance_pis = BalancePublicInputs::from_u64(
            &data.sender_proof.public_inputs.to_u64_vec()[..BALANCE_PUBLIC_INPUTS_LEN],
        )
        .map_err(BalanceWitnessGeneratorError::from)?;

        assert_eq!(data.to, self.channel_id);
        let sender_update_public_state = self
            .block_witness_generator
            .borrow()
            .get_update_public_state_witness(sender_balance_pis.public_state.block_number)?;
        let receiver_update_public_state = self
            .block_witness_generator
            .borrow()
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
            .borrow()
            .get_send_status(self.channel_id, prev_balance_pis.block_r)?;
        let new_block_r = match send_status.next_send_block {
            Some(next_block) => BlockNumber::new(next_block.as_u64() - 1)
                .map_err(|e| BalanceWitnessGeneratorError::InvalidBlock(e.to_string()))?,
            None => current_block_number,
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
            .borrow()
            .get_account_state_for_tx(sender_balance_pis.channel_id, data.tx_tree_root)?
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
            .borrow()
            .get_account_state(self.channel_id, prev_balance_pis.block_r)?;
        assert_eq!(
            account_state_receiver.account_tree_root, new_public_state.account_tree_root,
            "receiver account state root mismatch",
        );

        let tx_merkle_proof = data.tx_merkle_proof.clone();
        let tx_settlement = TxSettlement {
            channel_id: sender_balance_pis.channel_id,
            tx: data.tx,
            public_state: sender_update_public_state.new.clone(),
            account_state: account_state_sender,
            tx_merkle_proof,
            tx_v2_merkle_proof: data.tx_v2_merkle_proof.clone(),
            tx_v2: data.tx_v2,
            spend_proof: data.spend_proof.clone(),
        };

        let transfer_witness = TransferWitness::new(
            data.tx.transfer_tree_root,
            data.transfer.clone(),
            data.transfer_index,
            data.transfer_merkle_proof.clone(),
        )?;

        // SECURITY (F-WD-2): settlement-independent nonce, matching the circuit.
        let nullifier = SettledTransfer::new(
            transfer_witness.transfer.clone(),
            sender_balance_pis.channel_id,
            transfer_witness.transfer_index,
            tx_settlement.tx.nonce,
        )
        .nullifier();
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

        let current_block_number = self.block_witness_generator.borrow().block_number;

        let update_public_state = self
            .block_witness_generator
            .borrow()
            .get_update_public_state_witness(prev_balance_pis.public_state.block_number)?;
        assert_eq!(
            update_public_state.old, prev_balance_pis.public_state,
            "update_public_state old mismatch for deposit",
        );
        let new_public_state = update_public_state.new.clone();

        let send_status = self
            .block_witness_generator
            .borrow()
            .get_send_status(self.channel_id, prev_balance_pis.block_r)?;
        let new_block_r = match send_status.next_send_block {
            Some(next_block) => BlockNumber::new(next_block.as_u64() - 1)
                .map_err(|e| BalanceWitnessGeneratorError::InvalidBlock(e.to_string()))?,
            None => current_block_number,
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
            .borrow()
            .get_account_state(self.channel_id, prev_balance_pis.block_r)?;
        assert_eq!(
            account_state.account_tree_root, new_public_state.account_tree_root,
            "account state root mismatch for deposit",
        );

        let (deposit, deposit_merkle_proof) = self
            .block_witness_generator
            .borrow()
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
            self.channel_id,
            new_public_state.deposit_tree_root,
            data.deposit_salt,
            deposit.clone(),
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
            .borrow()
            .get_update_public_state_witness(prev_balance_pis.public_state.block_number)?;
        assert_eq!(
            update_public_state.old, prev_balance_pis.public_state,
            "update_public_state old mismatch for send_tx",
        );
        let new_public_state = update_public_state.new.clone();

        let account_state = self
            .block_witness_generator
            .borrow()
            .get_account_state_for_tx(self.channel_id, data.tx_tree_root)?
            .1;
        assert_eq!(
            account_state.account_tree_root, new_public_state.account_tree_root,
            "account state root mismatch for send_tx",
        );

        let tx_merkle_proof = data.tx_merkle_proof.clone();
        let tx_settlement = TxSettlement {
            channel_id: self.channel_id,
            tx: data.tx,
            public_state: new_public_state,
            account_state,
            tx_merkle_proof,
            tx_v2_merkle_proof: data.tx_v2_merkle_proof.clone(),
            tx_v2: data.tx_v2,
            spend_proof: data.spend_proof.clone(),
        };

        let transfer_witness = TransferWitness::new(
            data.tx.transfer_tree_root,
            data.transfer.clone(),
            0,
            data.transfer_merkle_proof.clone(),
        )?;

        Ok(SendTxWitness {
            prev_balance_proof,
            update_public_state,
            tx_settlement,
            transfer_witness,
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

            self.full_private_state
                .sent_tx_tree
                .push(witness.tx_settlement.tx.clone());
            assert_eq!(
                self.full_private_state.sent_tx_tree.len() as u32,
                witness.tx_settlement.tx.nonce + 1,
            );

            self.full_private_state.prev_private_commitment =
                spend_witness.prev_private_state.commitment();
            self.full_private_state.nonce = spend_witness.prev_private_state.nonce + 1;

            let actual_commitment = self.full_private_state.to_private_state().commitment();
            assert_eq!(actual_commitment, spend_pis.new_private_commitment);
        }

        Ok(())
    }

    pub fn single_withdrawal_witness(
        &self,
        data: &SingleWithdrawalData,
    ) -> Result<SingleWithdawalWitness<F, C, D>, BalanceWitnessGeneratorError> {
        let balance_proof = self.balance_proof.clone();
        let balance_pis = self.get_public_inputs()?;

        let update_public_state = self
            .block_witness_generator
            .borrow()
            .get_update_public_state_witness(balance_pis.public_state.block_number)?;

        let account_state = self
            .block_witness_generator
            .borrow()
            .get_account_state_for_tx(self.channel_id, data.tx_tree_root)?
            .1;

        let tx = data.tx.clone();
        let tx_merkle_proof = data.tx_merkle_proof.clone();
        let sent_tx_merkle_proof = self.full_private_state.sent_tx_tree.prove(tx.nonce as u64);

        let transfer_witness = TransferWitness::new(
            tx.transfer_tree_root,
            data.transfer.clone(),
            data.transfer_index,
            data.transfer_merkle_proof.clone(),
        )?;

        Ok(SingleWithdawalWitness {
            balance_proof,
            private_state: self.full_private_state.to_private_state(),
            update_public_state,
            account_state,
            tx_merkle_proof,
            tx_v2_merkle_proof: data.tx_v2_merkle_proof.clone(),
            tx_v2: data.tx_v2,
            tx,
            sent_tx_merkle_proof,
            transfer_witness,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveTransferData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub to: ChannelId,
    pub transfer: Transfer,

    // witness data
    pub sender_proof: ProofWithPublicInputs<F, C, D>,
    pub spend_proof: ProofWithPublicInputs<F, C, D>,
    pub tx_tree_root: Bytes32,
    pub tx: Tx,
    pub tx_merkle_proof: TxMerkleProof,
    pub tx_v2: Option<TxV2>,
    pub tx_v2_merkle_proof: Option<TxV2MerkleProof>,
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
    pub tx_v2: Option<TxV2>,
    pub tx_v2_merkle_proof: Option<TxV2MerkleProof>,
    /// The outgoing transfer at index 0 of `tx.transfer_tree_root` (detail2 §A-2/§F-1). Its
    /// aux_data is folded into the settled_tx_chain PI when nonzero.
    pub transfer: Transfer,
    /// Merkle proof of `transfer` at index 0 against `tx.transfer_tree_root`.
    pub transfer_merkle_proof: TransferMerkleProof,
}

#[derive(Debug, Clone)]
pub struct SingleWithdrawalData {
    pub tx_tree_root: Bytes32,
    pub tx: Tx,
    pub tx_merkle_proof: TxMerkleProof,
    pub tx_v2: Option<TxV2>,
    pub tx_v2_merkle_proof: Option<TxV2MerkleProof>,
    pub transfer: Transfer,
    pub transfer_index: u32,
    pub transfer_merkle_proof: TransferMerkleProof,
}

#[cfg(test)]
mod tests {
    use super::BlockWitnessGeneratorHandle;
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{SeedableRng as _, rngs::StdRng};

    use crate::{
        circuits::{
            balance::{
                balance_processor::BalanceProcessor,
                common::recipient::calculate_recipient_from_user_id, spend_circuit::SpendCircuit,
            },
            test_utils::{
                balance_witness_generator::{
                    BalanceWitnessGenerator, ReceiveDepositData, ReceiveTransferData, SendTxData,
                },
                block_witness_generator::BlockWitnessGenerator,
            },
        },
        common::{
            balance_state::settled_tx_chain_push,
            channel_id::ChannelId,
            salt::Salt,
            transfer::Transfer,
            trees::{transfer_tree::TransferTree, tx_tree::TxTree, tx_v2_tree::TxV2Tree},
            tx::{Tx, TxClass, TxV2},
        },
        ethereum_types::{
            address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256,
        },
        utils::poseidon_hash_out::PoseidonHashOut,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_balance_witness_generator() {
        let supported_user_counts = vec![1, 4, 512];

        let spend_circuit = SpendCircuit::<F, C, D>::new();
        let balance_processor =
            BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
        let block_witness_generator =
            BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

        let mut rng = StdRng::seed_from_u64(42);
        let channel_id = ChannelId::new(1).unwrap();
        let salt = Salt::rand(&mut rng);
        let mut balance_witness_generator = BalanceWitnessGenerator::new(
            channel_id,
            salt,
            block_witness_generator.clone(),
            &balance_processor,
        )
        .unwrap();

        // deposit
        let deposit_salt = Salt::rand(&mut rng);
        let recipient = calculate_recipient_from_user_id(channel_id, deposit_salt);
        block_witness_generator
            .borrow_mut()
            .add_deposit(
                Address::rand(&mut rng),
                recipient,
                0,
                U256::from(10),
                Bytes32::rand(&mut rng),
            )
            .unwrap();
        let deposit_data = ReceiveDepositData {
            receiver: recipient,
            deposit_salt: deposit_salt,
        };

        // add block to make the deposit available
        block_witness_generator
            .borrow_mut()
            .add_block(0, &[], 0, Bytes32::default())
            .unwrap();

        let receive_deposit_witness = balance_witness_generator
            .receive_deposit_witness(&deposit_data)
            .unwrap();

        let new_balance_proof = balance_processor
            .prove_receive_deposit(&receive_deposit_witness)
            .unwrap();

        balance_witness_generator
            .commit_receive_deposit(&new_balance_proof, &receive_deposit_witness)
            .unwrap();

        // detail2 §C-6: the consumed deposit chains its nullifier from the genesis chain (= 0).
        let chain_after_deposit = settled_tx_chain_push(
            Bytes32::default(),
            receive_deposit_witness.deposit_witness.deposit.nullifier(),
        );
        assert_eq!(
            balance_witness_generator
                .get_public_inputs()
                .unwrap()
                .settled_tx_chain,
            chain_after_deposit,
        );

        // another user
        let user_id2 = ChannelId::new(2).unwrap();
        let salt2 = Salt::rand(&mut rng);
        let mut balance_witness_generator2 = BalanceWitnessGenerator::new(
            user_id2,
            salt2,
            block_witness_generator.clone(),
            &balance_processor,
        )
        .unwrap();

        // transfer from user 1 to user 2 — inter-channel, so aux_data carries a (test) tx leaf
        // hash that must be folded into both the sender's and the receiver's chain.
        let transfer_salt = Salt::rand(&mut rng);
        let inter_channel_tx_leaf = Bytes32::rand(&mut rng);
        let transfer = Transfer {
            token_index: 0,
            amount: U256::from(3),
            recipient: calculate_recipient_from_user_id(user_id2, transfer_salt),
            aux_data: inter_channel_tx_leaf,
        };
        let sender_proof = balance_witness_generator.balance_proof.clone();
        let spend_witness = balance_witness_generator
            .spend_witness(&[transfer.clone()])
            .unwrap();
        let spend_proof = spend_circuit.prove(&spend_witness).unwrap();

        // construct transfer tree
        let mut transfer_tree = TransferTree::init();
        transfer_tree.push(transfer.clone());
        let transfer_index = 0u32;
        let transfer_tree_root = transfer_tree.get_root();
        let transfer_merkle_proof = transfer_tree.prove(transfer_index as u64);
        let tx = Tx {
            transfer_tree_root,
            nonce: balance_witness_generator.full_private_state.nonce,
        };

        // generate tx tree
        let mut tx_tree = TxTree::init();
        tx_tree.update(channel_id.as_u64(), tx.clone());
        let tx_tree_root = tx_tree.get_root();
        let tx_merkle_proof = tx_tree.prove(channel_id.as_u64());

        // add block
        block_witness_generator
            .borrow_mut()
            .add_block(channel_id.channel_id(), &[1], 0, tx_tree_root.into())
            .unwrap();

        let send_tx_data = SendTxData {
            spend_proof: spend_proof.clone(),
            tx_tree_root: tx_tree_root.into(),
            tx,
            tx_merkle_proof: tx_merkle_proof.clone(),
            tx_v2: None,
            tx_v2_merkle_proof: None,
            transfer: transfer.clone(),
            transfer_merkle_proof: transfer_merkle_proof.clone(),
        };
        let receive_transfer_data = ReceiveTransferData {
            to: user_id2,
            transfer,
            sender_proof,
            spend_proof,
            tx_tree_root: tx_tree_root.into(),
            tx,
            tx_merkle_proof,
            tx_v2: None,
            tx_v2_merkle_proof: None,
            transfer_index,
            transfer_merkle_proof,
            transfer_salt,
        };

        // update the balance proof of user 1
        let send_tx_witness = balance_witness_generator
            .send_tx_witness(&send_tx_data)
            .unwrap();
        let new_balance_proof = balance_processor.prove_send_tx(&send_tx_witness).unwrap();
        balance_witness_generator
            .commit_send_tx(&new_balance_proof, &send_tx_witness, &spend_witness)
            .unwrap();

        // Sender chain: deposit fold, then the outgoing inter-channel tx leaf (detail2 §F-1).
        let sender_chain_after_send =
            settled_tx_chain_push(chain_after_deposit, inter_channel_tx_leaf);
        assert_eq!(
            balance_witness_generator
                .get_public_inputs()
                .unwrap()
                .settled_tx_chain,
            sender_chain_after_send,
        );

        // user 2 receives the transfer
        let receive_transfer_witness = balance_witness_generator2
            .receive_transfer_witness(&receive_transfer_data)
            .unwrap();
        let new_balance_proof = balance_processor
            .prove_receive_transfer(&receive_transfer_witness)
            .unwrap();
        balance_witness_generator2
            .commit_receive_transfer(&new_balance_proof, &receive_transfer_witness)
            .unwrap();

        // Receiver chain: genesis (= 0) folded with the same inter-channel tx leaf — both sides
        // of the transfer agree on the leaf they chain.
        assert_eq!(
            balance_witness_generator2
                .get_public_inputs()
                .unwrap()
                .settled_tx_chain,
            settled_tx_chain_push(Bytes32::default(), inter_channel_tx_leaf),
        );
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_balance_witness_generator_with_tx_v2_user_transfer() {
        let supported_user_counts = vec![1, 4, 512];

        let spend_circuit = SpendCircuit::<F, C, D>::new();
        let balance_processor =
            BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
        let block_witness_generator =
            BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

        let mut rng = StdRng::seed_from_u64(43);
        let channel_id = ChannelId::new(1).unwrap();
        let salt = Salt::rand(&mut rng);
        let mut balance_witness_generator = BalanceWitnessGenerator::new(
            channel_id,
            salt,
            block_witness_generator.clone(),
            &balance_processor,
        )
        .unwrap();

        let deposit_salt = Salt::rand(&mut rng);
        let recipient = calculate_recipient_from_user_id(channel_id, deposit_salt);
        block_witness_generator
            .borrow_mut()
            .add_deposit(
                Address::rand(&mut rng),
                recipient,
                0,
                U256::from(10),
                Bytes32::rand(&mut rng),
            )
            .unwrap();
        block_witness_generator
            .borrow_mut()
            .add_block(0, &[], 0, Bytes32::default())
            .unwrap();
        let receive_deposit_data = ReceiveDepositData {
            receiver: recipient,
            deposit_salt,
        };
        let receive_deposit_witness = balance_witness_generator
            .receive_deposit_witness(&receive_deposit_data)
            .unwrap();
        let new_balance_proof = balance_processor
            .prove_receive_deposit(&receive_deposit_witness)
            .unwrap();
        balance_witness_generator
            .commit_receive_deposit(&new_balance_proof, &receive_deposit_witness)
            .unwrap();

        let user_id2 = ChannelId::new(2).unwrap();
        let salt2 = Salt::rand(&mut rng);
        let mut balance_witness_generator2 = BalanceWitnessGenerator::new(
            user_id2,
            salt2,
            block_witness_generator.clone(),
            &balance_processor,
        )
        .unwrap();

        let transfer_salt = Salt::rand(&mut rng);
        let transfer = Transfer {
            token_index: 0,
            amount: U256::from(3),
            recipient: calculate_recipient_from_user_id(user_id2, transfer_salt),
            aux_data: Bytes32::default(),
        };
        let sender_proof = balance_witness_generator.balance_proof.clone();
        let spend_witness = balance_witness_generator
            .spend_witness(&[transfer.clone()])
            .unwrap();
        let spend_proof = spend_circuit.prove(&spend_witness).unwrap();

        let mut transfer_tree = TransferTree::init();
        transfer_tree.push(transfer.clone());
        let transfer_index = 0u32;
        let transfer_tree_root = transfer_tree.get_root();
        let transfer_merkle_proof = transfer_tree.prove(transfer_index as u64);
        let tx = Tx {
            transfer_tree_root,
            nonce: balance_witness_generator.full_private_state.nonce,
        };
        let tx_v2 = TxV2 {
            tx_class: TxClass::UserTransfer,
            transfer_tree_root,
            nonce: tx.nonce,
            channel_action_root: PoseidonHashOut::default(),
        };

        let mut tx_tree = TxTree::init();
        tx_tree.update(channel_id.as_u64(), tx.clone());
        let tx_merkle_proof = tx_tree.prove(channel_id.as_u64());

        let mut tx_v2_tree = TxV2Tree::init();
        tx_v2_tree.update(channel_id.as_u64(), tx_v2);
        let tx_tree_root = tx_v2_tree.get_root();
        let tx_tree_root_bytes: Bytes32 = tx_tree_root.into();
        let tx_v2_merkle_proof = tx_v2_tree.prove(channel_id.as_u64());

        block_witness_generator
            .borrow_mut()
            .add_block(channel_id.channel_id(), &[1], 0, tx_tree_root_bytes)
            .unwrap();

        let send_tx_data = SendTxData {
            spend_proof: spend_proof.clone(),
            tx_tree_root: tx_tree_root_bytes,
            tx,
            tx_merkle_proof: tx_merkle_proof.clone(),
            tx_v2: Some(tx_v2),
            tx_v2_merkle_proof: Some(tx_v2_merkle_proof.clone()),
            transfer: transfer.clone(),
            transfer_merkle_proof: transfer_merkle_proof.clone(),
        };
        let receive_transfer_data = ReceiveTransferData {
            to: user_id2,
            transfer,
            sender_proof,
            spend_proof,
            tx_tree_root: tx_tree_root_bytes,
            tx,
            tx_merkle_proof,
            tx_v2: Some(tx_v2),
            tx_v2_merkle_proof: Some(tx_v2_merkle_proof),
            transfer_index,
            transfer_merkle_proof,
            transfer_salt,
        };

        let send_tx_witness = balance_witness_generator
            .send_tx_witness(&send_tx_data)
            .unwrap();
        let new_balance_proof = balance_processor.prove_send_tx(&send_tx_witness).unwrap();
        balance_witness_generator
            .commit_send_tx(&new_balance_proof, &send_tx_witness, &spend_witness)
            .unwrap();

        let receive_transfer_witness = balance_witness_generator2
            .receive_transfer_witness(&receive_transfer_data)
            .unwrap();
        let new_balance_proof = balance_processor
            .prove_receive_transfer(&receive_transfer_witness)
            .unwrap();
        balance_witness_generator2
            .commit_receive_transfer(&new_balance_proof, &receive_transfer_witness)
            .unwrap();
    }
}
