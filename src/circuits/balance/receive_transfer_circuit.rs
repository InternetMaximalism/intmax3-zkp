use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::balance::{
        balance_pis::{BalanceFullPublicInputs, BalancePublicInputsError},
        common::{
            account_state::AccountState, recipient::calculate_recipient_from_user_id,
            transfer_witness::TransferWitness, tx_settlement::TxSettlement,
            update_public_state::UpdatePublicState,
        },
    },
    common::{block_number::BlockNumber, salt::Salt},
    utils::conversion::ToU64,
};

#[derive(Debug, thiserror::Error)]
pub enum ReceiveTransferError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Balance public inputs error: {0}")]
    BalancePublicInputsError(#[from] BalancePublicInputsError),

    #[error("Invalid balance proof: {0}")]
    InvalidBalanceProof(String),

    #[error("Invalid balance verifier data: {0}")]
    InvalidBalanceVd(String),

    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("Block number error: {0}")]
    BlockNumberError(String),

    #[error("Spend public inputs error: {0}")]
    SpendPisError(String),
}

pub struct ReceiveTransferWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // Previous receiver balance proof
    pub prev_balance_proof: ProofWithPublicInputs<F, C, D>,

    // Previous sender balance proof right before this transfer
    pub sender_balance_proof: ProofWithPublicInputs<F, C, D>,

    /* sender_update_public_state.old ==
     * sender_balance_proof.public_state */
    pub sender_update_public_state: UpdatePublicState,

    /* receiver_update_public_state.old ==
     * prev_balance_proof.public_state */
    pub receiver_update_public_state: UpdatePublicState,

    // receiver's new block_r
    pub new_block_r: BlockNumber,

    // account state that proves no outgoing tx (prev_balance_proof.block_r, new_block_r]
    pub account_state: AccountState,

    // tx settlement that includes the transfer
    pub tx_settlement: TxSettlement<F, C, D>,

    // transfer witness that proves the transfer is included in tx_settlement.tx
    pub transfer_witness: TransferWitness,

    // salt for the transfer.recipient
    pub transfer_salt: Salt,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveTransferWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<BalanceFullPublicInputs<F, C, D>, ReceiveTransferError> {
        // verify balance proofs
        balance_vd
            .verify(self.prev_balance_proof.clone())
            .map_err(|e| {
                ReceiveTransferError::InvalidBalanceProof(format!(
                    "failed to verify prev_balance_proof: {e}"
                ))
            })?;
        balance_vd
            .verify(self.sender_balance_proof.clone())
            .map_err(|e| {
                ReceiveTransferError::InvalidBalanceProof(format!(
                    "failed to verify sender_balance_proof: {e}"
                ))
            })?;
        // obtain public inputs
        let prev_full_pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &self.prev_balance_proof.public_inputs.to_u64_vec(),
            &balance_vd.common.config,
        )?;
        let sender_full_pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &self.sender_balance_proof.public_inputs.to_u64_vec(),
            &balance_vd.common.config,
        )?;
        // balance vd check
        if prev_full_pis.vd != balance_vd.verifier_only {
            return Err(ReceiveTransferError::InvalidBalanceVd(
                "prev_balance_proof vd mismatch".to_string(),
            ));
        }
        if sender_full_pis.vd != balance_vd.verifier_only {
            return Err(ReceiveTransferError::InvalidBalanceVd(
                "sender_balance_proof vd mismatch".to_string(),
            ));
        }
        let prev_balance_pis = &prev_full_pis.pis;
        let sender_balance_pis = &sender_full_pis.pis;

        let sender_user_id = sender_balance_pis.user_id;
        let receiver_user_id = prev_balance_pis.user_id;

        // check update_public_state connections
        if self.receiver_update_public_state.old != prev_balance_pis.public_state {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "receiver_update_public_state.old {:?} != prev_balance_pis.public_state {:?}",
                self.receiver_update_public_state.old, prev_balance_pis.public_state,
            )));
        }
        if self.sender_update_public_state.old != sender_balance_pis.public_state {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "sender_update_public_state.old {:?} != sender_balance_pis.public_state {:?}",
                self.sender_update_public_state.old, sender_balance_pis.public_state,
            )));
        }
        if self.receiver_update_public_state.new != self.sender_update_public_state.new {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "receiver_update_public_state.new {:?} != sender_update_public_state.new {:?}",
                self.receiver_update_public_state.new, self.sender_update_public_state.new,
            )));
        }
        let public_state = self.receiver_update_public_state.new.clone();

        // check account_state connections
        if self.account_state.user_id != receiver_user_id {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "account_state.user_id {:?} != receiver_user_id {:?}",
                self.account_state.user_id, receiver_user_id,
            )));
        }
        if self.account_state.account_tree_root != public_state.account_tree_root {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "account_state.account_tree_root {:?} != public_state.account_tree_root {:?}",
                self.account_state.account_tree_root, public_state.account_tree_root,
            )));
        }

        // check tx settlement connections
        if self.tx_settlement.user_id != sender_user_id {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "tx_settlement.user_id {:?} != sender_user_id {:?}",
                self.tx_settlement.user_id, sender_user_id,
            )));
        }
        if self.tx_settlement.public_state != public_state {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "tx_settlement.public_state {:?} != public_state {:?}",
                self.tx_settlement.public_state, public_state,
            )));
        }
        let tx = &self.tx_settlement.tx;

        // check transfer_witness connections
        if self.transfer_witness.transfer_tree_root != tx.transfer_tree_root {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "transfer_witness.transfer_tree_root {:?} != tx.transfer_tree_root {:?}",
                self.transfer_witness.transfer_tree_root, tx.transfer_tree_root,
            )));
        }

        // recipient check (salt check)
        let expected_recipient =
            calculate_recipient_from_user_id(receiver_user_id, self.transfer_salt);
        if self.transfer_witness.transfer.recipient != expected_recipient {
            return Err(ReceiveTransferError::InvalidRecipient(format!(
                "transfer.recipient {:?} != expected_recipient {:?}",
                self.transfer_witness.transfer.recipient, expected_recipient,
            )));
        }

        // block number checks
        let prev_block_r = prev_balance_pis.block_r;

        // check prev_block_r <= new_block_r <= public_state.block_number
        if self.new_block_r < prev_block_r || self.new_block_r > public_state.block_number {
            return Err(ReceiveTransferError::BlockNumberError(format!(
                "Not prev_block_r <= new_block_r <= public_state.block_number: {:?} <= {:?} <= {:?}",
                prev_block_r, self.new_block_r, public_state.block_number,
            )));
        }

        // if there is a previous outgoing tx check additional conditions
        if self.account_state.account_leaf.prev != BlockNumber(0) {
            // account_witness.send_leaf.prev <= receiver_balance_proof.block_r
            if self.account_state.send_leaf.prev > prev_block_r {
                return Err(ReceiveTransferError::BlockNumberError(format!(
                    "Not account_state.send_leaf.prev <= prev_balance_pis.block_r: {:?} <= {:?}",
                    self.account_state.send_leaf.prev, prev_block_r,
                )));
            }

            // new_block_r < account_witness.send_leaf.cur
            if self.new_block_r >= self.account_state.send_leaf.cur {
                return Err(ReceiveTransferError::BlockNumberError(format!(
                    "Not new_block_r < account_state.send_leaf.cur: {:?} < {:?}",
                    self.new_block_r, self.account_state.send_leaf.cur,
                )));
            }
        }

        // Check receiving eligibilities:

        // tx_settlement_witness.tx_block_number() <= new_block_r
        if self.tx_settlement.tx_block_number() > self.new_block_r {
            return Err(ReceiveTransferError::BlockNumberError(format!(
                "Not tx_settlement.tx_block_number() <= new_block_r: {:?} <= {:?}",
                self.tx_settlement.tx_block_number(),
                self.new_block_r,
            )));
        }

        let spend_pis = self.tx_settlement.spend_pis().map_err(|e| {
            ReceiveTransferError::SpendPisError(format!("failed to get spend_pis: {e}"))
        })?;
        // sender_balance_pis.private_commitment ==
        // tx_settlement_witness.spent_proof.prev_private_commitment
        if sender_balance_pis.private_commitment != spend_pis.prev_private_commitment {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "sender_balance_pis.private_commitment {:?} != spend_pis.prev_private_commitment {:?}",
                sender_balance_pis.private_commitment, spend_pis.prev_private_commitment,
            )));
        }
        // tx_settlement_witness.spent_proof.is_valid == true
        if !spend_pis.is_valid {
            return Err(ReceiveTransferError::ConnectionError(
                "spend_pis.is_valid is false".to_string(),
            ));
        }

        // private state update

        todo!()
    }
}
