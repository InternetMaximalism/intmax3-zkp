use std::sync::Arc;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::{
        balance::{
            balance_pis::BalancePublicInputs, common::deposit_witness::DepositWitness,
            receive_transfer_circuit::ReceiveTransferWitness, send_tx_circuit::SendTxWitness,
        },
        test_utils::block_witness_generator::BlockWitnessGenerator,
    },
    common::{
        private_state::FullPrivateState, salt::Salt, transfer::Transfer,
        trees::transfer_tree::TransferMerkleProof, tx::Tx, user_id::UserId,
    },
    ethereum_types::bytes32::Bytes32,
};

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
    ) -> Self {
        Self {
            user_id,
            salt,
            balance_proof: None,
            full_private_state: FullPrivateState::new(salt),
            block_witness_generator,
        }
    }

    // get balance public inputs from the witness generator
    pub fn get_public_inputs(&self) -> Result<BalancePublicInputs, BalanceWitnessGeneratorError> {
        todo!()
    }

    pub fn receive_transfer_witness(
        &self,
        data: &ReceiveTransferData<F, C, D>,
    ) -> Result<ReceiveTransferWitness<F, C, D>, BalanceWitnessGeneratorError> {
        todo!()
    }

    pub fn commit_receive_transfer(
        &mut self,
        new_balance_proof: &ProofWithPublicInputs<F, C, D>,
        witness: &ReceiveTransferWitness<F, C, D>,
    ) -> Result<(), BalanceWitnessGeneratorError> {
        todo!()
    }

    pub fn receive_deposit_witness(
        &self,
        data: &ReceiveDepositData,
    ) -> Result<ReceiveTransferWitness<F, C, D>, BalanceWitnessGeneratorError> {
        todo!()
    }

    pub fn commit_receive_deposit(
        &mut self,
        new_balance_proof: &ProofWithPublicInputs<F, C, D>,
        witness: &ReceiveTransferWitness<F, C, D>,
    ) -> Result<(), BalanceWitnessGeneratorError> {
        todo!()
    }

    pub fn send_tx_witness(
        &self,
        data: &SendTxData<F, C, D>,
    ) -> Result<SendTxWitness<F, C, D>, BalanceWitnessGeneratorError> {
        todo!()
    }

    pub fn commit_send_tx(
        &mut self,
        new_balance_proof: &ProofWithPublicInputs<F, C, D>,
        witness: &SendTxWitness<F, C, D>,
    ) -> Result<(), BalanceWitnessGeneratorError> {
        todo!()
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
    pub tx_merkle_proof: Vec<Bytes32>,
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
    pub tx_merkle_proof: Vec<Bytes32>,
}
