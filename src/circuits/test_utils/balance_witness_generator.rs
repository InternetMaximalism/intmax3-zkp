use crate::{
    circuits::{
        balance::{
            balance_pis::{BALANCE_PUBLIC_INPUTS_LEN, BalancePublicInputs},
            common::{
                deposit_witness::DepositWitness, transfer_witness::TransferWitness,
                tx_settlement::TxSettlement, update_private_state::UpdatePrivateState,
                update_public_state::UpdatePublicState,
            },
            receive_deposit_circuit::ReceiveDepositWitness,
            receive_transfer_circuit::ReceiveTransferWitness,
            send_tx_circuit::SendTxWitness,
            spend_circuit::SpendWitness,
        },
        test_utils::block_witness_generator::BlockWitnessGenerator,
    },
    common::{
        private_state::FullPrivateState,
        public_state::PublicState,
        salt::Salt,
        transfer::Transfer,
        trees::{transfer_tree::TransferMerkleProof, tx_tree::TxMerkleProof},
        tx::Tx,
        u63::BlockNumber,
        user_id::UserId,
    },
    constants::MAX_NUM_TRANSFERS_PER_TX,
    ethereum_types::bytes32::Bytes32,
    utils::{conversion::ToU64, poseidon_hash_out::PoseidonHashOut},
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

#[derive(Debug, Clone)]
pub enum BalanceWitnessGeneratorError {}

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
    pub balance_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub full_private_state: FullPrivateState,
    pub current_block_r: BlockNumber,

    pub block_witness_generator: Arc<BlockWitnessGenerator>,
    pending_spend_witness: Option<SpendWitness>,
}

impl<F, C, const D: usize> BalanceWitnessGenerator<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn balance_pis_from_proof(proof: &ProofWithPublicInputs<F, C, D>) -> BalancePublicInputs {
        let pis_u64 = proof.public_inputs.to_u64_vec();
        BalancePublicInputs::from_u64(&pis_u64[..BALANCE_PUBLIC_INPUTS_LEN])
            .expect("balance proof public inputs must be well-formed")
    }

    fn identity_update_public_state(state: &PublicState) -> UpdatePublicState {
        UpdatePublicState::new(state.clone(), state.clone(), None)
            .expect("identical public states never require a proof")
    }

    pub fn new(
        user_id: UserId,
        salt: Salt,
        block_witness_generator: Arc<BlockWitnessGenerator>,
    ) -> Self {
        Self {
            user_id,
            salt,
            balance_proof: None,
            full_private_state: FullPrivateState::new(salt),
            current_block_r: BlockNumber::default(),
            block_witness_generator,
            pending_spend_witness: None,
        }
    }

    // get balance public inputs from the witness generator
    pub fn get_public_inputs(&self) -> Result<BalancePublicInputs, BalanceWitnessGeneratorError> {
        if let Some(proof) = &self.balance_proof {
            Ok(Self::balance_pis_from_proof(proof))
        } else {
            Ok(BalancePublicInputs::new(self.user_id, self.salt))
        }
    }

    pub fn spend_witness(
        &mut self,
        transfers: &[Transfer],
    ) -> Result<SpendWitness, BalanceWitnessGeneratorError> {
        let prev_private_state = self.full_private_state.to_private_state();

        let mut padded_transfers = vec![Transfer::default(); MAX_NUM_TRANSFERS_PER_TX];
        for (dst, src) in padded_transfers.iter_mut().zip(transfers.iter()) {
            *dst = src.clone();
        }

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

        self.pending_spend_witness = Some(witness.clone());
        Ok(witness)
    }

    pub fn receive_transfer_witness(
        &self,
        data: &ReceiveTransferData<F, C, D>,
    ) -> Result<ReceiveTransferWitness<F, C, D>, BalanceWitnessGeneratorError> {
        let prev_balance_proof = self
            .balance_proof
            .as_ref()
            .expect("receiver balance proof must be available")
            .clone();
        let prev_balance_pis = Self::balance_pis_from_proof(&prev_balance_proof);

        let sender_balance_pis = Self::balance_pis_from_proof(&data.sender_proof);

        debug_assert_eq!(data.to, self.user_id);
        debug_assert_eq!(
            sender_balance_pis.public_state, prev_balance_pis.public_state,
            "sender and receiver public states must match",
        );

        let public_state = prev_balance_pis.public_state.clone();
        let sender_update_public_state = Self::identity_update_public_state(&public_state);
        let receiver_update_public_state = Self::identity_update_public_state(&public_state);

        let new_block_r = self.block_witness_generator.block_number;
        let (_, account_state_receiver) = self
            .block_witness_generator
            .get_account_state(self.user_id, new_block_r)
            .expect("receiver account state should exist");

        let (tx_block_number, account_state_sender) = self
            .block_witness_generator
            .get_account_state_for_tx(sender_balance_pis.user_id, data.tx_tree_root)
            .expect("sender account state should exist for tx");

        let tx_merkle_proof = data.tx_merkle_proof.clone();
        let tx_settlement = TxSettlement {
            user_id: sender_balance_pis.user_id,
            tx: data.tx,
            public_state: public_state.clone(),
            account_state: account_state_sender,
            tx_merkle_proof,
            spend_proof: data.spend_proof.clone(),
        };

        debug_assert!(tx_block_number.as_u64() <= new_block_r.as_u64());

        let transfer_witness = TransferWitness::new(
            data.tx.transfer_tree_root,
            data.transfer.clone(),
            data.transfer_index,
            data.transfer_merkle_proof.clone(),
        )
        .expect("transfer witness must verify");

        let nullifier = transfer_witness.transfer.nullifier();
        let mut nullifier_tree = self.full_private_state.nullifier_tree.clone();
        let nullifier_proof = nullifier_tree
            .prove_and_insert(nullifier)
            .expect("nullifier insertion proof");

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
        )
        .expect("update private state must be consistent");

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
        self.balance_proof = Some(new_balance_proof.clone());
        self.current_block_r = witness.new_block_r;

        let token_index = witness.update_private_state.token_index as u64;
        let prev_balance = self.full_private_state.asset_tree.get_leaf(token_index);
        debug_assert_eq!(prev_balance, witness.update_private_state.prev_balance);
        let new_balance = prev_balance + witness.update_private_state.amount;
        self.full_private_state
            .asset_tree
            .update(token_index, new_balance);

        self.full_private_state
            .nullifier_tree
            .prove_and_insert(witness.update_private_state.nullifier)
            .expect("nullifier should insert once");

        self.full_private_state.prev_private_commitment =
            witness.update_private_state.prev_private_state.commitment();
        self.full_private_state.nonce = witness.update_private_state.new_private_state.nonce;
        self.full_private_state.salt = witness.update_private_state.new_private_state.salt;

        let expected_commitment = witness.update_private_state.new_private_state.commitment();
        let actual_commitment = self.full_private_state.to_private_state().commitment();
        debug_assert_eq!(expected_commitment, actual_commitment);

        Ok(())
    }

    pub fn receive_deposit_witness(
        &self,
        data: &ReceiveDepositData,
    ) -> Result<ReceiveDepositWitness<F, C, D>, BalanceWitnessGeneratorError> {
        let prev_balance_proof = self
            .balance_proof
            .as_ref()
            .expect("balance proof must exist")
            .clone();
        let prev_balance_pis = Self::balance_pis_from_proof(&prev_balance_proof);

        let public_state = prev_balance_pis.public_state.clone();
        let update_public_state = Self::identity_update_public_state(&public_state);
        let new_block_r = self.block_witness_generator.block_number;

        let (_, account_state) = self
            .block_witness_generator
            .get_account_state(self.user_id, new_block_r)
            .expect("account state must exist");

        let deposit = &data.deposit;

        let mut nullifier_tree = self.full_private_state.nullifier_tree.clone();
        let deposit_nullifier = deposit.nullifier();
        let nullifier_proof = nullifier_tree
            .prove_and_insert(deposit_nullifier)
            .expect("nullifier insertion proof");

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
        )
        .expect("update private state must be consistent");

        Ok(ReceiveDepositWitness {
            prev_balance_proof,
            update_public_state,
            new_block_r,
            account_state,
            deposit_witness: data.clone(),
            update_private_state,
        })
    }

    pub fn commit_receive_deposit(
        &mut self,
        new_balance_proof: &ProofWithPublicInputs<F, C, D>,
        witness: &ReceiveDepositWitness<F, C, D>,
    ) -> Result<(), BalanceWitnessGeneratorError> {
        self.balance_proof = Some(new_balance_proof.clone());
        self.current_block_r = witness.new_block_r;

        let token_index = witness.deposit_witness.deposit.token_index as u64;
        let prev_balance = self.full_private_state.asset_tree.get_leaf(token_index);
        debug_assert_eq!(prev_balance, witness.update_private_state.prev_balance);
        let new_balance = prev_balance + witness.update_private_state.amount;
        self.full_private_state
            .asset_tree
            .update(token_index, new_balance);

        self.full_private_state
            .nullifier_tree
            .prove_and_insert(witness.update_private_state.nullifier)
            .expect("nullifier should insert once");

        self.full_private_state.prev_private_commitment =
            witness.update_private_state.prev_private_state.commitment();
        self.full_private_state.nonce = witness.update_private_state.new_private_state.nonce;
        self.full_private_state.salt = witness.update_private_state.new_private_state.salt;

        let expected_commitment = witness.update_private_state.new_private_state.commitment();
        let actual_commitment = self.full_private_state.to_private_state().commitment();
        debug_assert_eq!(expected_commitment, actual_commitment);

        Ok(())
    }

    pub fn send_tx_witness(
        &self,
        data: &SendTxData<F, C, D>,
    ) -> Result<SendTxWitness<F, C, D>, BalanceWitnessGeneratorError> {
        let prev_balance_proof = self
            .balance_proof
            .as_ref()
            .expect("balance proof must exist")
            .clone();
        let prev_balance_pis = Self::balance_pis_from_proof(&prev_balance_proof);

        let public_state = prev_balance_pis.public_state.clone();
        let update_public_state = Self::identity_update_public_state(&public_state);

        let account_state = self
            .block_witness_generator
            .get_account_state_for_tx(self.user_id, data.tx_tree_root)
            .expect("account state for tx must exist")
            .1;

        let tx_merkle_proof = data.tx_merkle_proof.clone();
        let tx_settlement = TxSettlement {
            user_id: self.user_id,
            tx: data.tx,
            public_state: public_state.clone(),
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
    ) -> Result<(), BalanceWitnessGeneratorError> {
        self.balance_proof = Some(new_balance_proof.clone());

        let spend_pis = witness
            .tx_settlement
            .spend_pis()
            .expect("spend proof public inputs must decode");

        if spend_pis.is_valid {
            let spend_witness = self
                .pending_spend_witness
                .take()
                .expect("spend witness must be recorded before committing send");

            debug_assert_eq!(
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
            debug_assert_eq!(actual_commitment, spend_pis.new_private_commitment);

            self.current_block_r = witness.tx_settlement.tx_block_number();
        } else {
            self.pending_spend_witness = None;
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

pub type ReceiveDepositData = DepositWitness;

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
