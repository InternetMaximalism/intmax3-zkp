use crate::{
    circuits::balance::{
        account_state::{AccountState, AccountStateError},
        spend_circuit::SpendPublicInputs,
    },
    common::{
        block_number::BlockNumber,
        trees::{public_state_tree::PublicState, tx_tree::TxMerkleProof},
        tx::Tx,
        user_id::UserId,
    },
    utils::conversion::ToU64,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData, config::GenericConfig, proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum TxSettlementError {
    #[error("Invalid spend proof: {0}")]
    InvalidSpendProof(String),

    #[error("Invalid tx merkle proof: {0}")]
    InvalidTxMerkleProof(String),

    #[error("Invalid account state: {0}")]
    InvalidAccountState(#[from] AccountStateError),

    #[error("Invalid user ID: {0}")]
    InvalidUserId(String),

    #[error("Invalid public state: {0}")]
    InvalidPublicState(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TxSettlement<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub user_id: UserId,
    pub tx: Tx,
    pub public_state: PublicState,
    pub account_state: AccountState,
    pub tx_merkle_proof: TxMerkleProof,
    pub spend_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> TxSettlement<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn new(
        spend_vd: &VerifierCircuitData<F, C, D>,
        user_id: UserId,
        tx: Tx,
        public_state: PublicState,

        account_state: AccountState,
        tx_merkle_proof: TxMerkleProof,
        spend_proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self, TxSettlementError> {
        // verify the spend proof
        spend_vd.verify(spend_proof.clone()).map_err(|e| {
            TxSettlementError::InvalidSpendProof(format!("Spend proof verification failed: {}", e))
        })?;

        // verify account state
        account_state.verify()?;
        if account_state.user_id != user_id {
            return Err(TxSettlementError::InvalidUserId(
                "user_id does not match".to_string(),
            ));
        }
        if account_state.account_tree_root != public_state.account_tree_root {
            return Err(TxSettlementError::InvalidPublicState(
                "account_tree_root does not match".to_string(),
            ));
        }

        // verify tx inclusion
        let tx_tree_root = account_state.send_leaf.tx_tree_root.reduce_to_hash_out();
        tx_merkle_proof
            .verify(&tx, user_id.local_id() as u64, tx_tree_root)
            .map_err(|e| TxSettlementError::InvalidTxMerkleProof(e.to_string()))?;

        // verify public inputs
        let spend_pis = SpendPublicInputs::from_pis_u64(&spend_proof.public_inputs.to_u64_vec())
            .map_err(|e| {
                TxSettlementError::InvalidSpendProof(format!(
                    "failed to parse public inputs: {}",
                    e
                ))
            })?;
        if spend_pis.tx != tx {
            return Err(TxSettlementError::InvalidSpendProof(
                "tx in public inputs does not match".to_string(),
            ));
        }

        Ok(Self {
            user_id,
            tx,
            public_state,
            tx_merkle_proof,
            account_state,
            spend_proof,
        })
    }

    // return the block number that the tx was included in
    pub fn tx_block_number(&self) -> BlockNumber {
        self.account_state.send_leaf.cur
    }

    // return the block number before the tx was included
    pub fn send_block_number_before_tx(&self) -> BlockNumber {
        self.account_state.send_leaf.prev
    }

    // return true if the tx is valid (i.e., valid nonce)
    pub fn is_valid(&self) -> Result<bool, TxSettlementError> {
        let spend_pis = SpendPublicInputs::from_pis_u64(
            &self.spend_proof.public_inputs.to_u64_vec(),
        )
        .map_err(|e| {
            TxSettlementError::InvalidSpendProof(format!("failed to parse public inputs: {}", e))
        })?;
        Ok(spend_pis.is_valid)
    }
}
