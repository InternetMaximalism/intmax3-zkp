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
        balance_pis::{BalanceFullPublicInputs, BalancePublicInputs, BalancePublicInputsError},
        common::{
            account_state::{AccountState, AccountStateError},
            deposit_witness::{DepositWitness, DepositWitnessError},
            update_private_state::UpdatePrivateState,
            update_public_state::UpdatePublicState,
        },
    },
    common::block_number::BlockNumber,
    utils::conversion::ToU64,
};

#[derive(Debug, thiserror::Error)]
pub enum ReceiveDepositError {
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

    #[error("Invalid deposit witness: {0}")]
    InvalidDepositWitness(String),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),
}

#[derive(Clone, Debug)]
pub struct ReceiveDepositWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // Previous receiver balance proof
    pub prev_balance_proof: ProofWithPublicInputs<F, C, D>,

    // receiver's public state update
    pub update_public_state: UpdatePublicState,

    // receiver's new block_r
    pub new_block_r: BlockNumber,

    // account state that proves no outgoing tx (prev_balance_proof.block_r, new_block_r]
    pub account_state: AccountState,

    // deposit witness
    pub deposit_witness: DepositWitness,

    // private state update
    pub update_private_state: UpdatePrivateState,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveDepositWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<BalanceFullPublicInputs<F, C, D>, ReceiveDepositError> {
        balance_vd
            .verify(self.prev_balance_proof.clone())
            .map_err(|e| {
                ReceiveDepositError::InvalidBalanceProof(format!(
                    "failed to verify prev_balance_proof: {e}"
                ))
            })?;

        let prev_full_pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &self.prev_balance_proof.public_inputs.to_u64_vec(),
            &balance_vd.common.config,
        )?;

        if prev_full_pis.vd != balance_vd.verifier_only {
            return Err(ReceiveDepositError::InvalidBalanceVd(
                "prev_balance_proof vd mismatch".to_string(),
            ));
        }

        let prev_balance_pis = prev_full_pis.pis;
        let receiver_user_id = prev_balance_pis.user_id;

        self.update_public_state.verify().map_err(|e| {
            ReceiveDepositError::ConnectionError(format!(
                "update_public_state verification failed: {e}"
            ))
        })?;

        if self.update_public_state.old != prev_balance_pis.public_state {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "update_public_state.old {:?} != prev_balance_pis.public_state {:?}",
                self.update_public_state.old, prev_balance_pis.public_state
            )));
        }
        let public_state = self.update_public_state.new.clone();

        self.account_state
            .verify()
            .map_err(|e: AccountStateError| {
                ReceiveDepositError::ConnectionError(format!(
                    "account_state verification failed: {e}"
                ))
            })?;

        if self.account_state.user_id != receiver_user_id {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "account_state.user_id {:?} != receiver_user_id {:?}",
                self.account_state.user_id, receiver_user_id,
            )));
        }
        if self.account_state.account_tree_root != public_state.account_tree_root {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "account_state.account_tree_root {:?} != public_state.account_tree_root {:?}",
                self.account_state.account_tree_root, public_state.account_tree_root,
            )));
        }

        if self.deposit_witness.user_id != receiver_user_id {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "deposit_witness.user_id {:?} != receiver_user_id {:?}",
                self.deposit_witness.user_id, receiver_user_id,
            )));
        }

        self.deposit_witness
            .verify()
            .map_err(|e: DepositWitnessError| {
                ReceiveDepositError::InvalidDepositWitness(format!(
                    "deposit_witness verification failed: {e}"
                ))
            })?;

        if self.deposit_witness.deposit_tree_root != public_state.deposit_tree_root {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "deposit_witness.deposit_tree_root {:?} != public_state.deposit_tree_root {:?}",
                self.deposit_witness.deposit_tree_root, public_state.deposit_tree_root,
            )));
        }

        let prev_block_r = prev_balance_pis.block_r;

        if self.new_block_r < prev_block_r || self.new_block_r > public_state.block_number {
            return Err(ReceiveDepositError::BlockNumberError(format!(
                "Not prev_block_r <= new_block_r <= public_state.block_number: {:?} <= {:?} <= {:?}",
                prev_block_r, self.new_block_r, public_state.block_number,
            )));
        }

        if self.account_state.account_leaf.prev != BlockNumber(0) {
            if self.account_state.send_leaf.prev > prev_block_r {
                return Err(ReceiveDepositError::BlockNumberError(format!(
                    "Not account_state.send_leaf.prev <= prev_balance_pis.block_r: {:?} <= {:?}",
                    self.account_state.send_leaf.prev, prev_block_r,
                )));
            }

            if self.new_block_r >= self.account_state.send_leaf.cur {
                return Err(ReceiveDepositError::BlockNumberError(format!(
                    "Not new_block_r < account_state.send_leaf.cur: {:?} < {:?}",
                    self.new_block_r, self.account_state.send_leaf.cur,
                )));
            }
        }

        if self.deposit_witness.deposit.block_number > self.new_block_r {
            return Err(ReceiveDepositError::BlockNumberError(format!(
                "deposit block number {:?} must be <= new_block_r {:?}",
                self.deposit_witness.deposit.block_number, self.new_block_r,
            )));
        }

        let deposit = &self.deposit_witness.deposit;
        if self.update_private_state.token_index != deposit.token_index {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "update_private_state.token_index {:?} != deposit.token_index {:?}",
                self.update_private_state.token_index, deposit.token_index,
            )));
        }
        if self.update_private_state.amount != deposit.amount {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "update_private_state.amount {:?} != deposit.amount {:?}",
                self.update_private_state.amount, deposit.amount,
            )));
        }
        let deposit_nullifier = deposit.nullifier();
        if self.update_private_state.nullifier != deposit_nullifier {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "update_private_state.nullifier {:?} != deposit.nullifier {:?}",
                self.update_private_state.nullifier, deposit_nullifier,
            )));
        }

        let prev_private_commitment = self.update_private_state.prev_private_state.commitment();
        if prev_private_commitment != prev_balance_pis.private_commitment {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "update_private_state.prev_private_state.commitment() {:?} != prev_balance_pis.private_commitment {:?}",
                prev_private_commitment, prev_balance_pis.private_commitment,
            )));
        }

        let new_private_commitment = self.update_private_state.new_private_state.commitment();

        let new_balance_pis = BalanceFullPublicInputs {
            pis: BalancePublicInputs {
                user_id: receiver_user_id,
                public_state,
                block_r: self.new_block_r,
                private_commitment: new_private_commitment,
            },
            vd: balance_vd.verifier_only.clone(),
        };

        Ok(new_balance_pis)
    }
}
