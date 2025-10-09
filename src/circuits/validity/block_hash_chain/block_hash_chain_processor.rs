use std::collections::HashMap;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use thiserror::Error;

use crate::{
    circuits::validity::{
        block_hash_chain::{
            block_chain_pis::BlockChainPublicInputs,
            block_hash_chain_circuit::{BlockHashChainCircuit, BlockHashChainCircuitError},
            block_step::{BlockStepCircuit, BlockStepError, BlockStepWitness},
            ext_public_state::ExtendedPublicState,
            update_account_tree::{
                UpdateAccountCircuit, UpdateAccountCircuitError, UpdateAccountTree,
            },
        },
        deposit_hash_chain::{
            deposit_chain_processor::{DepositChainProcessor, DepositChainProcessorError},
            deposit_step::DepositStepWitness,
        },
    },
    common::{
        block::Block,
        deposit::Deposit,
        trees::{
            account_tree::{AccountLeaf, AccountMerkleProof, SendMerkleProof},
            deposit_tree::DepositMerkleProof,
            public_state_tree::PublicStateMerkleProof,
        },
    },
    utils::conversion::ToU64,
};

#[derive(Debug, Error)]
pub enum BlockHashChainProcessorError {
    #[error("unsupported number of users: {0}")]
    UnsupportedUserCount(u32),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("deposit chain processor error: {0}")]
    DepositChainProcessor(#[from] DepositChainProcessorError),
    #[error("update account circuit error: {0}")]
    UpdateAccountCircuit(#[from] UpdateAccountCircuitError),
    #[error("block step error: {0}")]
    BlockStep(#[from] BlockStepError),
    #[error("block hash chain circuit error: {0}")]
    BlockHashChain(#[from] BlockHashChainCircuitError),
}

pub struct BlockHashChainProcessorWitness {
    pub deposit_step_witness: Vec<(Deposit, DepositMerkleProof)>,
    pub block: Block,
    pub prev_account_leaves: Vec<AccountLeaf>,
    pub account_merkle_proofs: Vec<AccountMerkleProof>,
    pub send_merkle_proofs: Vec<SendMerkleProof>,
    pub public_state_merkle_proof: PublicStateMerkleProof,
}

pub struct BlockHashChainProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    block_hash_chain_circuit: BlockHashChainCircuit<F, C, D>,
    block_step_circuit: BlockStepCircuit<F, C, D>,
    deposit_chain_vd: VerifierCircuitData<F, C, D>,
    update_account_vds: Vec<(u32, VerifierCircuitData<F, C, D>)>,
    update_account_circuits: HashMap<u32, UpdateAccountCircuit<F, C, D>>,
    deposit_chain_processor: DepositChainProcessor<F, C, D>,
}

impl<F, C, const D: usize> BlockHashChainProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(supported_user_counts: &[u32]) -> Self {
        assert!(
            !supported_user_counts.is_empty(),
            "at least one supported user count is required"
        );

        let block_chain_cd = BlockHashChainCircuit::<F, C, D>::generate_cd();

        let deposit_chain_processor = DepositChainProcessor::<F, C, D>::new();
        let deposit_chain_vd = deposit_chain_processor.deposit_chain_vd();

        let mut update_account_circuits = HashMap::new();
        let mut update_account_vds = Vec::with_capacity(supported_user_counts.len());
        for &num_users in supported_user_counts {
            let circuit = UpdateAccountCircuit::<F, C, D>::new(num_users);
            let vd = circuit.data.verifier_data();
            update_account_vds.push((num_users, vd.clone()));
            update_account_circuits.insert(num_users, circuit);
        }

        let block_step_circuit = BlockStepCircuit::<F, C, D>::new(
            &block_chain_cd,
            &update_account_vds,
            &deposit_chain_vd,
        );

        let block_hash_chain_circuit = BlockHashChainCircuit::<F, C, D>::new(
            &block_chain_cd,
            &block_step_circuit.data.verifier_data(),
        );

        Self {
            block_hash_chain_circuit,
            block_step_circuit,
            deposit_chain_vd,
            update_account_vds,
            update_account_circuits,
            deposit_chain_processor,
        }
    }

    pub fn block_chain_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.block_hash_chain_circuit.data.verifier_data()
    }

    pub fn deposit_chain_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.deposit_chain_vd.clone()
    }

    pub fn prove_block(
        &self,
        initial_public_state: Option<ExtendedPublicState>,
        prev_block_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,
        witness: &BlockHashChainProcessorWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BlockHashChainProcessorError> {
        // get corresponding update account circuit
        let num_users = witness.block.num_users;
        let update_account_circuit = self.update_account_circuits.get(&num_users).ok_or(
            BlockHashChainProcessorError::UnsupportedUserCount(num_users),
        )?;

        // require initial state or previous proof
        if initial_public_state.is_some() as u8 + prev_block_chain_proof.is_some() as u8 != 1 {
            return Err(BlockHashChainProcessorError::InvalidInput(
                "either initial public state or previous block chain proof must be provided"
                    .to_string(),
            ));
        }
        let prev_ext_public_state = if let Some(ref proof) = prev_block_chain_proof {
            self.block_hash_chain_circuit
                .verify(proof)
                .map_err(BlockHashChainProcessorError::BlockHashChain)?;

            let prev_pis = BlockChainPublicInputs::<F, C, D>::from_u64_slice(
                &proof.public_inputs.to_u64_vec(),
                &self.block_hash_chain_circuit.data.common.config,
            )
            .map_err(|e| {
                BlockHashChainProcessorError::InvalidInput(format!(
                    "failed to parse previous block chain proof public inputs: {:?}",
                    e
                ))
            })?;
            prev_pis.ext_public_state.clone()
        } else {
            initial_public_state
                .clone()
                .ok_or(BlockHashChainProcessorError::InvalidInput(
                    "initial public state must be provided".to_string(),
                ))?
        };

        // generate deposit chain proof
        let mut deposit_chain_proof = None;
        for (deposit, deposit_merkle_proof) in &witness.deposit_step_witness {
            let initial_value = if deposit_chain_proof.is_none() {
                Some((
                    prev_ext_public_state.deposit_hash_chain,
                    prev_ext_public_state.inner.deposit_tree_root,
                    prev_ext_public_state.deposit_count,
                ))
            } else {
                None
            };
            let deposit_step_witness = DepositStepWitness::<F, C, D> {
                initial_value,
                prev_deposit_chain_proof: deposit_chain_proof.clone(),
                deposit: deposit.clone(),
                deposit_merkle_proof: deposit_merkle_proof.clone(),
            };
            let proof = self
                .deposit_chain_processor
                .prove_step(&deposit_step_witness)?;
            deposit_chain_proof = Some(proof);
        }

        let block_number = prev_ext_public_state
            .inner
            .block_number
            .add(1)
            .map_err(|_e| {
                BlockHashChainProcessorError::InvalidInput(
                    "previous block number is at max value".to_string(),
                )
            })?;
        let update_account_tree = UpdateAccountTree {
            prev_block_hash_chain: prev_ext_public_state.block_hash_chain,
            prev_account_tree_root: prev_ext_public_state.inner.account_tree_root,
            block_number,
            block: witness.block.clone(),
            prev_account_leaves: witness.prev_account_leaves.clone(),
            account_merkle_proofs: witness.account_merkle_proofs.clone(),
            send_merkle_proofs: witness.send_merkle_proofs.clone(),
        };
        let update_account_proof = update_account_circuit.prove(&update_account_tree)?;

        let block_step_witness = BlockStepWitness::<F, C, D> {
            num_users,
            initial_public_state: initial_public_state.clone(),
            prev_block_chain_proof: prev_block_chain_proof.clone(),
            deposit_hash_chain_proof: deposit_chain_proof.clone(),
            update_account_proof: update_account_proof.clone(),
            public_state_merkle_proof: witness.public_state_merkle_proof.clone(),
        };
        let block_step_proof = self.block_step_circuit.prove(
            &self.block_chain_vd(),
            &self.update_account_vds,
            &self.deposit_chain_vd,
            &block_step_witness,
        )?;

        let block_hash_chain_proof = self.block_hash_chain_circuit.prove(&block_step_proof)?;

        Ok(block_hash_chain_proof)
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), BlockHashChainCircuitError> {
        self.block_hash_chain_circuit.verify(proof)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use super::*;

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_block_hash_chain_processor() {
        let supported_user_counts = [2];
        let _processor = BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
    }
}
