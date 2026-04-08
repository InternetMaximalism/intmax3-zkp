use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};

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
    utils::serialize::CircuitSerializationError,
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
    C: GenericConfig<D, F = F> + 'static + Default,
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
    C: GenericConfig<D, F = F> + Default + 'static,
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

    fn prove_via_switch_board(
        &self,
        switch_board_witness: &BalanceSwichBoard<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let switch_board_proof = self
            .switch_board_circuit
            .prove(&self.balance_vd(), switch_board_witness)
            .map_err(|e| BalanceProcessorError::SwitchBoardCircuitError(e))?;
        self.balance_circuit
            .prove(&switch_board_proof)
            .map_err(|e| BalanceProcessorError::BalanceCircuitError(e))
    }

    async fn prove_via_switch_board_async(
        &self,
        switch_board_witness: &BalanceSwichBoard<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let switch_board_proof = self
            .switch_board_circuit
            .prove_async(&self.balance_vd(), switch_board_witness)
            .await
            .map_err(|e| BalanceProcessorError::SwitchBoardCircuitError(e))?;
        self.balance_circuit
            .prove_async(&switch_board_proof)
            .await
            .map_err(|e| BalanceProcessorError::BalanceCircuitError(e))
    }

    pub fn prove_initial(
        &self,
        user_id: UserId,
        salt: Salt,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let witness = BalanceSwichBoard::<F, C, D> {
            initial_value: Some((user_id, salt)),
            receive_transfer_proof: None,
            receive_deposit_proof: None,
            send_tx_proof: None,
        };
        self.prove_via_switch_board(&witness)
    }

    pub fn prove_receive_transfer(
        &self,
        witness: &ReceiveTransferWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let proof = self
            .receive_transfer_circuit
            .prove(witness)
            .map_err(|e| BalanceProcessorError::ReceiveTransferCircuitError(e))?;
        let sb_witness = BalanceSwichBoard::<F, C, D> {
            initial_value: None,
            receive_transfer_proof: Some(proof),
            receive_deposit_proof: None,
            send_tx_proof: None,
        };
        self.prove_via_switch_board(&sb_witness)
    }

    pub fn prove_receive_deposit(
        &self,
        witness: &ReceiveDepositWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let proof = self
            .receive_deposit_circuit
            .prove(witness)
            .map_err(|e| BalanceProcessorError::ReceiveDepositCircuitError(e))?;
        let sb_witness = BalanceSwichBoard::<F, C, D> {
            initial_value: None,
            receive_transfer_proof: None,
            receive_deposit_proof: Some(proof),
            send_tx_proof: None,
        };
        self.prove_via_switch_board(&sb_witness)
    }

    pub fn prove_send_tx(
        &self,
        witness: &SendTxWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let proof = self
            .send_tx_circuit
            .prove(witness)
            .map_err(|e| BalanceProcessorError::SendTxCircuitError(e))?;
        let sb_witness = BalanceSwichBoard::<F, C, D> {
            initial_value: None,
            receive_transfer_proof: None,
            receive_deposit_proof: None,
            send_tx_proof: Some(proof),
        };
        self.prove_via_switch_board(&sb_witness)
    }

    pub async fn prove_initial_async(
        &self,
        user_id: UserId,
        salt: Salt,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let witness = BalanceSwichBoard::<F, C, D> {
            initial_value: Some((user_id, salt)),
            receive_transfer_proof: None,
            receive_deposit_proof: None,
            send_tx_proof: None,
        };
        self.prove_via_switch_board_async(&witness).await
    }

    pub async fn prove_receive_transfer_async(
        &self,
        witness: &ReceiveTransferWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let proof = self
            .receive_transfer_circuit
            .prove_async(witness)
            .await
            .map_err(|e| BalanceProcessorError::ReceiveTransferCircuitError(e))?;
        let sb_witness = BalanceSwichBoard::<F, C, D> {
            initial_value: None,
            receive_transfer_proof: Some(proof),
            receive_deposit_proof: None,
            send_tx_proof: None,
        };
        self.prove_via_switch_board_async(&sb_witness).await
    }

    pub async fn prove_receive_deposit_async(
        &self,
        witness: &ReceiveDepositWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let proof = self
            .receive_deposit_circuit
            .prove_async(witness)
            .await
            .map_err(|e| BalanceProcessorError::ReceiveDepositCircuitError(e))?;
        let sb_witness = BalanceSwichBoard::<F, C, D> {
            initial_value: None,
            receive_transfer_proof: None,
            receive_deposit_proof: Some(proof),
            send_tx_proof: None,
        };
        self.prove_via_switch_board_async(&sb_witness).await
    }

    pub async fn prove_send_tx_async(
        &self,
        witness: &SendTxWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceProcessorError> {
        let proof = self
            .send_tx_circuit
            .prove_async(witness)
            .await
            .map_err(|e| BalanceProcessorError::SendTxCircuitError(e))?;
        let sb_witness = BalanceSwichBoard::<F, C, D> {
            initial_value: None,
            receive_transfer_proof: None,
            receive_deposit_proof: None,
            send_tx_proof: Some(proof),
        };
        self.prove_via_switch_board_async(&sb_witness).await
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CircuitSerializationError> {
        let payload = BalanceProcessorBytes {
            receive_transfer: self.receive_transfer_circuit.to_bytes()?,
            receive_deposit: self.receive_deposit_circuit.to_bytes()?,
            send_tx: self.send_tx_circuit.to_bytes()?,
            switch_board: self.switch_board_circuit.to_bytes()?,
            balance: self.balance_circuit.to_bytes()?,
        };
        bincode::serde::encode_to_vec(&payload, bincode::config::standard())
            .map_err(|e| CircuitSerializationError::serialization("balance processor", e))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CircuitSerializationError> {
        let (payload, _) = bincode::serde::decode_from_slice::<BalanceProcessorBytes, _>(
            bytes,
            bincode::config::standard(),
        )
        .map_err(|e| CircuitSerializationError::deserialization("balance processor", e))?;
        let receive_transfer_circuit =
            ReceiveTransferCircuit::<F, C, D>::from_bytes(&payload.receive_transfer)?;
        let receive_deposit_circuit =
            ReceiveDepositCircuit::<F, C, D>::from_bytes(&payload.receive_deposit)?;
        let send_tx_circuit = SendTxCircuit::<F, C, D>::from_bytes(&payload.send_tx)?;
        let switch_board_circuit =
            BalanceSwichBoardCircuit::<F, C, D>::from_bytes(&payload.switch_board)?;
        let balance_circuit = BalanceCircuit::<F, C, D>::from_bytes(&payload.balance)?;
        Ok(Self {
            receive_transfer_circuit,
            receive_deposit_circuit,
            send_tx_circuit,
            switch_board_circuit,
            balance_circuit,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct BalanceProcessorBytes {
    receive_transfer: Vec<u8>,
    receive_deposit: Vec<u8>,
    send_tx: Vec<u8>,
    switch_board: Vec<u8>,
    balance: Vec<u8>,
}
