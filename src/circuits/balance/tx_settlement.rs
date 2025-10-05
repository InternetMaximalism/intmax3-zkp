use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData, config::GenericConfig, proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    circuits::balance::spend_circuit::SpendPublicInputs,
    common::{
        trees::{
            account_tree::{AccountLeaf, AccountMerkleProof, SendLeaf, SendMerkleProof},
            public_state_tree::PublicState,
            tx_tree::TxMerkleProof,
        },
        tx::Tx,
        user_id::UserId,
    },
    utils::conversion::ToU64,
};

#[derive(Debug, thiserror::Error)]
pub enum TxSettlementError {
    #[error("Invalid spend proof: {0}")]
    InvalidSpendProof(String),

    #[error("Invalid tx merkle proof: {0}")]
    InvalidTxMerkleProof(String),

    #[error("Invalid send merkle proof: {0}")]
    InvalidSendMerkleProof(String),

    #[error("Invalid account merkle proof: {0}")]
    InvalidAccountMerkleProof(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TxSettlement<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub user_id: UserId,
    pub tx: Tx,
    pub public_state: PublicState,

    pub tx_merkle_proof: TxMerkleProof,
    pub send_leaf: SendLeaf,
    pub send_leaf_index: u32,
    pub send_merkle_proof: SendMerkleProof,
    pub account_leaf: AccountLeaf,
    pub account_merkle_proof: AccountMerkleProof,
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

        tx_merkle_proof: TxMerkleProof,
        send_leaf: SendLeaf,
        send_leaf_index: u32,
        send_merkle_proof: SendMerkleProof,
        account_leaf: AccountLeaf,
        account_merkle_proof: AccountMerkleProof,
        spend_proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self, TxSettlementError> {
        // verify the spend proof
        spend_vd.verify(spend_proof.clone()).map_err(|e| {
            TxSettlementError::InvalidSpendProof(format!("Spend proof verification failed: {}", e))
        })?;

        // verify tx inclusion
        let tx_tree_root = send_leaf.tx_tree_root.reduce_to_hash_out();
        tx_merkle_proof
            .verify(&tx, user_id.local_id() as u64, tx_tree_root)
            .map_err(|e| TxSettlementError::InvalidTxMerkleProof(e.to_string()))?;

        // verify send leaf inclusion
        send_merkle_proof
            .verify(
                &send_leaf,
                send_leaf_index as u64,
                account_leaf.send_tree_root,
            )
            .map_err(|e| TxSettlementError::InvalidTxMerkleProof(e.to_string()))?;

        // verify account leaf inclusion
        account_merkle_proof
            .verify(&account_leaf, user_id.0, public_state.account_tree_root)
            .map_err(|e| TxSettlementError::InvalidAccountMerkleProof(e.to_string()))?;

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
            send_leaf,
            send_leaf_index,
            send_merkle_proof,
            account_leaf,
            account_merkle_proof,
            spend_proof,
        })
    }

    pub fn included_block_number(&self) -> u64 {
        self.send_leaf.cur
    }
}
