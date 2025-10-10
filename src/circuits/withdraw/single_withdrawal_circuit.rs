use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
    recursion::cyclic_recursion::check_cyclic_proof_verifier_data,
};
use thiserror::Error;

use crate::{
    circuits::balance::{
        balance_pis::BalanceFullPublicInputs,
        common::{
            account_state::{AccountState, AccountStateError},
            recipient::extract_address_from_recipient,
            transfer_witness::{TransferWitness, TransferWitnessError},
            update_public_state::UpdatePublicState,
        },
    },
    common::{
        private_state::PrivateState,
        public_state::{PUBLIC_STATE_U64_LEN, PublicState, PublicStateError, PublicStateTarget},
        transfer::SettledTransfer,
        trees::{sent_tx_tree::SentTxMerkleProof, tx_tree::TxMerkleProof},
        tx::Tx,
        withdrawal::{WITHDRAWAL_LEN, Withdrawal, WithdrawalTarget},
    },
    utils::{conversion::ToU64, poseidon_hash_out::PoseidonHashOut},
};

pub const SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN: usize = PUBLIC_STATE_U64_LEN + WITHDRAWAL_LEN;

pub struct SingleWithdawalPublicInputs {
    pub public_state: PublicState,
    pub withdrawal: Withdrawal,
}

#[derive(Debug, Error)]
pub enum SingleWithdawalPublicInputsError {
    #[error("Invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Failed to parse public state: {0}")]
    PublicState(#[from] PublicStateError),

    #[error("Failed to parse withdrawal: {0}")]
    Withdrawal(String),
}

impl SingleWithdawalPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let mut limbs = self.public_state.to_u64_vec();
        limbs.extend(self.withdrawal.to_u32_vec().into_iter().map(|x| x as u64));
        limbs
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, SingleWithdawalPublicInputsError> {
        if values.len() != SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN {
            return Err(SingleWithdawalPublicInputsError::InvalidLength {
                expected: SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN,
                actual: values.len(),
            });
        }

        let mut cursor = 0;

        let public_state =
            PublicState::from_u64_slice(&values[cursor..cursor + PUBLIC_STATE_U64_LEN])?;
        cursor += PUBLIC_STATE_U64_LEN;

        let withdraw_slice = &values[cursor..cursor + WITHDRAWAL_LEN];
        let withdrawal = Withdrawal::from_u64_slice(withdraw_slice)
            .map_err(|e| SingleWithdawalPublicInputsError::Withdrawal(e.to_string()))?;

        Ok(Self {
            public_state,
            withdrawal,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SingleWithdawalPublicInputsTarget {
    pub public_state: PublicStateTarget,
    pub withdrawal: WithdrawalTarget,
}

impl SingleWithdawalPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        [self.public_state.to_vec(), self.withdrawal.to_vec()].concat()
    }

    pub fn from_vec(values: &[Target]) -> Self {
        assert_eq!(
            values.len(),
            SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN,
            "SingleWithdawalPublicInputsTarget::from_vec length mismatch",
        );

        let mut cursor = 0;

        let public_state =
            PublicStateTarget::from_slice(&values[cursor..cursor + PUBLIC_STATE_U64_LEN]);
        cursor += PUBLIC_STATE_U64_LEN;

        let withdrawal = WithdrawalTarget::from_slice(&values[cursor..cursor + WITHDRAWAL_LEN]);

        Self {
            public_state,
            withdrawal,
        }
    }
}

#[derive(Debug, Error)]
pub enum SingleWithdawalWitnessError {
    #[error("Balance proof verification failed: {0}")]
    BalanceProofVerification(String),

    #[error("Failed to parse balance public inputs: {0}")]
    BalancePublicInputs(String),

    #[error("Private state commitment mismatch: expected {expected:?}, got {actual:?}")]
    PrivateStateCommitmentMismatch {
        expected: PoseidonHashOut,
        actual: PoseidonHashOut,
    },

    #[error("Sent tx merkle proof verification failed: {0}")]
    SentTxMerkleProof(String),

    #[error("Tx merkle proof verification failed: {0}")]
    TxMerkleProof(String),

    #[error("Transfer witness verification failed: {0}")]
    TransferWitness(String),

    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("Inconsistent witness data: {0}")]
    InconsistentWitness(String),

    #[error("Account state verification failed: {0}")]
    AccountState(String),

    #[error("Public state update verification failed: {0}")]
    UpdatePublicState(String),

    #[error("Balance public state mismatch after update")]
    BalancePublicStateMismatch,
}

pub struct SingleWithdawalWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // the balance proof of the user performing the withdrawal
    // it must contain the withdrawal in its sent tx tree
    pub balance_proof: ProofWithPublicInputs<F, C, D>,

    // the private state of the balance proof
    pub private_state: PrivateState,

    // the witness to update the public state of the balance proof to the latest
    pub update_public_state: UpdatePublicState,

    // the account state that proves the block number of the tx.
    pub account_state: AccountState,

    // the tx merkle proof of the tx that contains the withdrawal
    pub tx_merkle_proof: TxMerkleProof,

    // the tx that contains the withdrawal
    pub tx: Tx,

    // the sent tx merkle proof of the tx
    pub sent_tx_merkle_proof: SentTxMerkleProof,

    // the transfer witness of the withdrawal
    pub transfer_witness: TransferWitness,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SingleWithdawalWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<SingleWithdawalPublicInputs, SingleWithdawalWitnessError> {
        // verify the balance proof
        check_cyclic_proof_verifier_data(
            &self.balance_proof,
            &balance_vd.verifier_only,
            &balance_vd.common,
        )
        .map_err(|e| {
            SingleWithdawalWitnessError::BalanceProofVerification(format!(
                "cyclic verifier data check failed: {e:?}",
            ))
        })?;
        balance_vd.verify(self.balance_proof.clone()).map_err(|e| {
            SingleWithdawalWitnessError::BalanceProofVerification(format!(
                "verification failed: {e:?}",
            ))
        })?;

        let balance_full_pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &self.balance_proof.public_inputs.to_u64_vec(),
            &balance_vd.common.config,
        )
        .map_err(|e| SingleWithdawalWitnessError::BalancePublicInputs(e.to_string()))?;
        let balance_pis = balance_full_pis.pis;
        let user_id = balance_pis.user_id;

        // verify the private state by checking the commitment
        if balance_pis.private_commitment != self.private_state.commitment() {
            return Err(
                SingleWithdawalWitnessError::PrivateStateCommitmentMismatch {
                    expected: balance_pis.private_commitment,
                    actual: self.private_state.commitment(),
                },
            );
        }

        // verify the public state update
        self.update_public_state
            .verify()
            .map_err(|e| SingleWithdawalWitnessError::UpdatePublicState(e.to_string()))?;
        if self.update_public_state.old != balance_pis.public_state {
            return Err(SingleWithdawalWitnessError::BalancePublicStateMismatch);
        }
        let public_state = self.update_public_state.new.clone();

        // verify that the tx is included in the sent tx tree
        self.sent_tx_merkle_proof
            .verify(
                &self.tx,
                self.tx.nonce as u64,
                self.private_state.sent_tx_tree_root,
            )
            .map_err(|e| SingleWithdawalWitnessError::TxMerkleProof(e.to_string()))?;

        // verify the transfer witness
        if self.transfer_witness.transfer_tree_root != self.tx.transfer_tree_root {
            return Err(SingleWithdawalWitnessError::InconsistentWitness(format!(
                "transfer tree root mismatch: expected {:?}, got {:?}",
                self.tx.transfer_tree_root, self.transfer_witness.transfer_tree_root
            )));
        }
        self.transfer_witness
            .verify()
            .map_err(|e: TransferWitnessError| {
                SingleWithdawalWitnessError::TransferWitness(e.to_string())
            })?;

        // verify the account state
        if self.account_state.user_id != user_id {
            return Err(SingleWithdawalWitnessError::InconsistentWitness(format!(
                "account state user {:?} != balance proof user {:?}",
                self.account_state.user_id, user_id
            )));
        }
        if self.account_state.account_tree_root != public_state.account_tree_root {
            return Err(SingleWithdawalWitnessError::InconsistentWitness(format!(
                "account tree root mismatch: {:?} vs {:?}",
                self.account_state.account_tree_root, public_state.account_tree_root
            )));
        }
        self.account_state
            .verify()
            .map_err(|e: AccountStateError| {
                SingleWithdawalWitnessError::AccountState(e.to_string())
            })?;
        let tx_tree_root = self
            .account_state
            .send_leaf
            .tx_tree_root
            .reduce_to_hash_out();
        let tx_block_number = self.account_state.send_leaf.cur;

        // verify that the tx is included in the tx tree root
        self.tx_merkle_proof
            .verify(&self.tx, user_id.local_id() as u64, tx_tree_root)
            .map_err(|e| SingleWithdawalWitnessError::TxMerkleProof(e.to_string()))?;

        let transfer = self.transfer_witness.transfer.clone();
        let recipient = extract_address_from_recipient(transfer.recipient)
            .map_err(|e| SingleWithdawalWitnessError::InvalidRecipient(e.to_string()))?;

        let settled_transfer = SettledTransfer::new(
            transfer.clone(),
            user_id,
            self.transfer_witness.transfer_index,
            tx_block_number,
        );

        // construct the withdrawal
        let withdrawal = Withdrawal {
            recipient,
            token_index: transfer.token_index,
            amount: transfer.amount,
            nullifier: settled_transfer.nullifier(),
            aux_data: transfer.aux_data,
        };

        Ok(SingleWithdawalPublicInputs {
            public_state: self.update_public_state.new.clone(),
            withdrawal,
        })
    }
}
