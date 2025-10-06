use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig,
};

use crate::circuits::balance::{
    balance_pis::{BalancePisBeforeAfter, BalancePublicInputs},
    common::{tx_settlement::TxSettlement, update_public_state::UpdatePublicState},
};

#[derive(thiserror::Error, Debug)]
pub enum SpendTxError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Spend public inputs error: {0}")]
    SpendPisError(String),

    #[error("Block number error: {0}")]
    BlockNumberError(String),
}

pub struct SpendTxWitness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
    pub prev_balance_pis: BalancePublicInputs,

    /* update_public_state.old ==
     * prev_balance_pis.public_state */
    pub update_public_state: UpdatePublicState,

    /* update_public_state.new ==
     * tx_settlement.public_state */
    pub tx_settlement: TxSettlement<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SpendTxWitness<F, C, D>
{
    pub fn to_public_inputs(&self) -> Result<BalancePisBeforeAfter, SpendTxError> {
        if self.prev_balance_pis.public_state != self.update_public_state.old {
            return Err(SpendTxError::ConnectionError(format!(
                "prev_balance_pis.public_state: {:?}, update_public_state.old: {:?}",
                self.prev_balance_pis.public_state, self.update_public_state.old
            )));
        }
        if self.update_public_state.new != self.tx_settlement.public_state {
            return Err(SpendTxError::ConnectionError(format!(
                "update_public_state.new: {:?}, tx_settlement.public_state: {:?}",
                self.update_public_state.new, self.tx_settlement.public_state
            )));
        }
        if self.tx_settlement.user_id != self.prev_balance_pis.user_id {
            return Err(SpendTxError::ConnectionError(format!(
                "tx_settlement.user_id: {}, prev_balance_pis.user_id: {}",
                self.tx_settlement.user_id.0, self.prev_balance_pis.user_id.0
            )));
        }
        let spend_pis = self
            .tx_settlement
            .spend_pis()
            .map_err(|e| SpendTxError::SpendPisError(format!("failed to get spend pis: {}", e)))?;
        if spend_pis.prev_private_commitment != self.prev_balance_pis.private_commitment {
            return Err(SpendTxError::ConnectionError(format!(
                "spend_pis.prev_private_commitment: {}, prev_balance_pis.private_commitment: {}",
                spend_pis.prev_private_commitment, self.prev_balance_pis.private_commitment
            )));
        }
        if self.prev_balance_pis.block_r < self.tx_settlement.tx_block_number() {
            return Err(SpendTxError::BlockNumberError(format!(
                "prev_balance_pis.block_r: {} should be >= tx_settlement.tx_block_number(): {}",
                self.prev_balance_pis.block_r.0,
                self.tx_settlement.tx_block_number().0
            )));
        }
        let (new_block_r, new_private_commitment) = if spend_pis.is_valid {
            (
                self.tx_settlement.tx_block_number(),
                spend_pis.new_private_commitment,
            )
        } else {
            (
                self.prev_balance_pis.block_r,
                self.prev_balance_pis.private_commitment,
            )
        };
        let new_balance_pis = BalancePublicInputs {
            user_id: self.prev_balance_pis.user_id,
            public_state: self.update_public_state.new.clone(),
            block_r: new_block_r,
            private_commitment: new_private_commitment,
        };
        Ok(BalancePisBeforeAfter {
            before: self.prev_balance_pis.clone(),
            after: new_balance_pis,
        })
    }
}
