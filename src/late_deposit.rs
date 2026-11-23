//! Native post-close late-deposit workflow. A deposit that reached the rollup but was never
//! imported into a signed channel state before the close is proved as one ReceiveDeposit step
//! over the confirmed late cursor; the materializer refunds the depositor on the rollup.
//!
//! The cursor is shared with the late-incoming lane (`LateIncomingCheckpoint`): both lanes advance
//! the materializer's `lateBalanceStateCommitment`. Build with `authenticated-tail-receive`; all
//! deployed Balance/backing/late verifier keys must come from the same build. A prepared receipt
//! never advances the confirmed checkpoint.
use crate::{
    circuits::{
        balance::{balance_pis::BalanceFullPublicInputs, balance_processor::BalanceProcessor},
        channel::late_deposit_circuit::{LateDepositCircuit, LateDepositPublicInputs},
        validity::block_hash_chain::ext_public_state::ExtendedPublicState,
        witness::{
            balance_witness_generator::{BalanceWitnessGenerator, ReceiveDepositData},
            block_witness_generator::BlockWitnessGeneratorHandle,
        },
    },
    ethereum_types::bytes32::Bytes32,
    late_incoming::LateIncomingCheckpoint,
    public_close_prover::wrap_and_export_circuit_mle,
    utils::{conversion::ToU64, mle_prover::export_mle_v2_config_json, wrapper::WrapperCircuit},
};
use anyhow::{Result, ensure};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use serde::{Deserialize, Serialize};
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedLateDeposit {
    pub statement: LateDepositPublicInputs,
    /// Exact calldata proof for materializer.claimLateDeposit(manager, compactProof).
    pub compact_proof: Vec<u8>,
    pub mle_json: String,
    pub mle_config_json: String,
    next_checkpoint: LateIncomingCheckpoint,
}

/// Reuse the ordinary receive-deposit witness and Balance prover from a confirmed late cursor.
/// `extended` must be the canonical producer journal preimage of the new public state
/// (LiveBlockProducer's matching lookup). The caller persists the returned artifact BEFORE
/// submission and retains `checkpoint` until finality. The confirmed checkpoint is not advanced.
pub fn prepare_deposit(
    checkpoint: &LateIncomingCheckpoint,
    balance: &BalanceProcessor<F, C, D>,
    circuit: &LateDepositCircuit<F, C, D>,
    blocks: BlockWitnessGeneratorHandle,
    data: &ReceiveDepositData,
    deposit_index: u64,
    extended: &ExtendedPublicState,
) -> Result<PreparedLateDeposit> {
    let balance_vd = balance.balance_vd();
    ensure!(
        *circuit.balance_vd() == balance_vd,
        "late deposit circuit was built for another Balance verifier key"
    );
    let proof = ProofWithPublicInputs::from_bytes(
        checkpoint.balance_proof_bytes().to_vec(),
        &balance_vd.common,
    )?;
    ensure!(
        circuit.balance_commitment(&proof)? == checkpoint.commitment(),
        "corrupt checkpoint"
    );
    let full = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
        &proof.public_inputs.to_u64_vec(),
        &balance_vd.common.config,
    )?;
    ensure!(
        full.pis.private_commitment == checkpoint.private_state().to_private_state().commitment(),
        "corrupt private checkpoint"
    );
    ensure!(
        full.pis.channel_id == checkpoint.channel_id(),
        "corrupt checkpoint channel"
    );
    let mut generator = BalanceWitnessGenerator {
        channel_id: checkpoint.channel_id(),
        salt: checkpoint.private_state().salt,
        balance_proof: proof,
        full_private_state: checkpoint.private_state().clone(),
        block_witness_generator: blocks,
    };
    let witness = generator.receive_deposit_witness_at_index(data, deposit_index)?;
    ensure!(
        witness.deposit_witness.deposit.deposit_index.as_u64() == deposit_index
            && witness.deposit_witness.deposit.recipient == data.receiver,
        "deposit witness leaf differs from the requested deposit"
    );
    let late_proof = circuit.prove(&witness, extended)?;
    circuit.data.verify(late_proof.clone())?;
    let statement =
        LateDepositPublicInputs::from_u64_slice(&late_proof.public_inputs.to_u64_vec())?;
    ensure!(
        statement.previous_balance_commitment == checkpoint.commitment()
            && u64::from(statement.channel_id) == checkpoint.channel_id().as_u64(),
        "receipt uses another checkpoint"
    );
    let next_proof = balance.prove_receive_deposit(&witness)?;
    ensure!(
        circuit.balance_commitment(&next_proof)? == statement.next_balance_commitment,
        "continuation proof mismatch"
    );
    generator.commit_receive_deposit(&next_proof, &witness)?;
    let next_checkpoint = LateIncomingCheckpoint::with_balance_vd(
        &balance_vd,
        &next_proof,
        generator.full_private_state,
        checkpoint.close_intent_digest(),
        checkpoint.final_balance_state_h1(),
        statement.next_balance_commitment,
    )?;
    let exported = wrap_and_export_circuit_mle(&circuit.data, &late_proof)?;
    Ok(PreparedLateDeposit {
        statement,
        compact_proof: exported.compact_proof,
        mle_json: exported.mle_json,
        mle_config_json: exported.mle_config_json,
        next_checkpoint,
    })
}

impl PreparedLateDeposit {
    /// Promote only after the submission is finalized and the materializer's confirmed checkpoint
    /// equals this receipt's next commitment. A stale competing branch must be rebuilt instead.
    pub fn confirmed_checkpoint(
        &self,
        confirmed_l1_commitment: Bytes32,
    ) -> Result<LateIncomingCheckpoint> {
        ensure!(
            confirmed_l1_commitment == self.statement.next_balance_commitment
                && self.next_checkpoint.commitment() == confirmed_l1_commitment,
            "receipt is not the confirmed L1 continuation"
        );
        ensure!(
            self.next_checkpoint.channel_id().as_u64() == u64::from(self.statement.channel_id),
            "receipt and checkpoint identify different channels"
        );
        Ok(self.next_checkpoint.clone())
    }
}

/// Available before the first receipt: deploy this config's pinned adapter before the materializer.
pub fn export_late_deposit_mle_config(circuit: &LateDepositCircuit<F, C, D>) -> Result<String> {
    let wrapper = WrapperCircuit::<F, C, C, D>::new(&circuit.data.verifier_data());
    Ok(export_mle_v2_config_json(&wrapper.data)?)
}
