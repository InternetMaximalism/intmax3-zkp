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
        balance_circuit::{BalanceCircuit, BalanceCircuitError},
        receive_deposit_circuit::{
            ReceiveDepositCircuit, ReceiveDepositError, ReceiveDepositWitness,
        },
        receive_transfer_circuit::{
            ReceiveTransferCircuit, ReceiveTransferError, ReceiveTransferWitness,
        },
        send_tx_circuit::{SendTxCircuit, SendTxError, SendTxWitness},
        switch_board::{BalanceSwichBoard, BalanceSwichBoardCircuit, BalanceSwitchBoardError},
    },
    common::{salt::Salt, user_id::UserId},
};

#[derive(Debug, thiserror::Error)]
pub enum BalanceProcessorError {
    #[error("Receive transfer circuit error: {0}")]
    ReceiveTransferCircuitError(#[from] ReceiveTransferError),

    #[error("Receive deposit circuit error: {0}")]
    ReceiveDepositCircuitError(#[from] ReceiveDepositError),

    #[error("Send tx circuit error: {0}")]
    SendTxCircuitError(#[from] SendTxError),

    #[error("Switch board circuit error: {0}")]
    SwitchBoardCircuitError(#[from] BalanceSwitchBoardError),

    #[error("Balance circuit error: {0}")]
    BalanceCircuitError(#[from] BalanceCircuitError),
}

/// A processor that holds all the balance-related circuits and can be used to create proofs.
#[derive(Debug)]
pub struct BalanceProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    receive_transfer_circuit: ReceiveTransferCircuit<F, C, D>,
    receive_deposit_circuit: ReceiveDepositCircuit<F, C, D>,
    send_tx_circuit: SendTxCircuit<F, C, D>,
    switch_board_circuit: BalanceSwichBoardCircuit<F, C, D>,
    balance_circuit: BalanceCircuit<F, C, D>,
}

impl<F, C, const D: usize> BalanceProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(spend_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let balance_cd = BalanceCircuit::<F, C, D>::generate_cd();
        let receive_transfer_circuit =
            ReceiveTransferCircuit::<F, C, D>::new(&balance_cd, &spend_vd);
        let receive_deposit_circuit = ReceiveDepositCircuit::<F, C, D>::new(&balance_cd);
        let send_tx_circuit = SendTxCircuit::<F, C, D>::new(&balance_cd, &spend_vd);
        let switch_board_circuit = BalanceSwichBoardCircuit::new(
            &balance_cd.config,
            &receive_transfer_circuit.data.verifier_data(),
            &receive_deposit_circuit.data.verifier_data(),
            &send_tx_circuit.data.verifier_data(),
        );
        let balance_circuit =
            BalanceCircuit::<F, C, D>::new(&balance_cd, &switch_board_circuit.data.verifier_data());
        Self {
            receive_transfer_circuit,
            receive_deposit_circuit,
            send_tx_circuit,
            switch_board_circuit,
            balance_circuit,
        }
    }

    pub fn balance_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.balance_circuit.data.verifier_data()
    }

    pub fn prove_initial(
        &self,
        user_id: UserId,
        salt: Salt,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let switch_board_witness = BalanceSwichBoard::<F, C, D> {
            initial_value: Some((user_id, salt)),
            receive_transfer_proof: None,
            receive_deposit_proof: None,
            send_tx_proof: None,
        };
        let switch_board_proof = self
            .switch_board_circuit
            .prove(&self.balance_vd(), &switch_board_witness)
            .map_err(|e| BalanceProcessorError::SwitchBoardCircuitError(e))?;
        let balance_proof = self
            .balance_circuit
            .prove(&switch_board_proof)
            .map_err(|e| BalanceProcessorError::BalanceCircuitError(e))?;
        Ok(balance_proof)
    }

    pub fn prove_receive_transfer(
        &self,
        witness: &ReceiveTransferWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let receive_transfer_proof = self
            .receive_transfer_circuit
            .prove(witness)
            .map_err(|e| BalanceProcessorError::ReceiveTransferCircuitError(e))?;

        let switch_board_witness = BalanceSwichBoard::<F, C, D> {
            initial_value: None,
            receive_transfer_proof: Some(receive_transfer_proof),
            receive_deposit_proof: None,
            send_tx_proof: None,
        };

        let switch_board_proof = self
            .switch_board_circuit
            .prove(&self.balance_vd(), &switch_board_witness)
            .map_err(|e| BalanceProcessorError::SwitchBoardCircuitError(e))?;

        let balance_proof = self
            .balance_circuit
            .prove(&switch_board_proof)
            .map_err(|e| BalanceProcessorError::BalanceCircuitError(e))?;

        Ok(balance_proof)
    }

    pub fn prove_receive_deposit(
        &self,
        witness: &ReceiveDepositWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let receive_deposit_proof = self
            .receive_deposit_circuit
            .prove(witness)
            .map_err(|e| BalanceProcessorError::ReceiveDepositCircuitError(e))?;

        let switch_board_witness = BalanceSwichBoard::<F, C, D> {
            initial_value: None,
            receive_transfer_proof: None,
            receive_deposit_proof: Some(receive_deposit_proof),
            send_tx_proof: None,
        };

        let switch_board_proof = self
            .switch_board_circuit
            .prove(&self.balance_vd(), &switch_board_witness)
            .map_err(|e| BalanceProcessorError::SwitchBoardCircuitError(e))?;

        let balance_proof = self
            .balance_circuit
            .prove(&switch_board_proof)
            .map_err(|e| BalanceProcessorError::BalanceCircuitError(e))?;

        Ok(balance_proof)
    }

    pub fn prove_send_tx(
        &self,
        witness: &SendTxWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let send_tx_proof = self
            .send_tx_circuit
            .prove(witness)
            .map_err(|e| BalanceProcessorError::SendTxCircuitError(e))?;

        let switch_board_witness = BalanceSwichBoard::<F, C, D> {
            initial_value: None,
            receive_transfer_proof: None,
            receive_deposit_proof: None,
            send_tx_proof: Some(send_tx_proof),
        };

        let switch_board_proof = self
            .switch_board_circuit
            .prove(&self.balance_vd(), &switch_board_witness)
            .map_err(|e| BalanceProcessorError::SwitchBoardCircuitError(e))?;

        let balance_proof = self
            .balance_circuit
            .prove(&switch_board_proof)
            .map_err(|e| BalanceProcessorError::BalanceCircuitError(e))?;

        Ok(balance_proof)
    }
}
