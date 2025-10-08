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

use crate::{
    circuits::validity::{
        block_hash_chain::{
            block_chain_pis::{BlockChainPublicInputs, BlockChainPublicInputsError},
            ext_public_state::ExtendedPublicState,
            update_account_tree::UpdateAccountPublicInputs,
        },
        deposit_hash_chain::deposit_chain_pis::{
            DepositChainPublicInputs, DepositChainPublicInputsError,
        },
    },
    common::{
        public_state::PublicState, trees::public_state_tree::PublicStateMerkleProof, u63::U63,
    },
    ethereum_types::bytes32::Bytes32,
    utils::conversion::ToU64,
};

#[derive(Debug, thiserror::Error)]
pub enum BlockStepError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Missing update account verifier data for num_users {0}")]
    MissingUpdateAccountVerifierData(u32),

    #[error("Deposit chain public inputs error: {0}")]
    DepositChainPublicInputs(#[from] DepositChainPublicInputsError),

    #[error("Block chain public inputs error: {0}")]
    BlockChainPublicInputs(#[from] BlockChainPublicInputsError),

    #[error("Update account public inputs error: {0}")]
    UpdateAccountPublicInputs(String),

    #[error("Public state merkle proof error: {0}")]
    PublicStateMerkleProof(String),
}

pub struct BlockStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_public_state: Option<PublicState>,

    // Previous block hash chain proof if not the first block
    pub prev_block_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,

    // Deposit hash chain proof if there is a deposit in this block
    pub deposit_hash_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,

    // paddind number of users in this block (must be > 0)
    pub num_users: u32,

    // Update account proof corresponding to this block
    pub update_account_proof: ProofWithPublicInputs<F, C, D>,

    // Merkle proof to update public state tree
    pub public_state_merkle_proof: PublicStateMerkleProof,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    BlockStepWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        block_chain_vd: &VerifierCircuitData<F, C, D>,
        update_account_vds: &[(u32, VerifierCircuitData<F, C, D>)],
        deposit_chain_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<BlockChainPublicInputs<F, C, D>, BlockStepError> {
        let prev_inputs = if let Some(prev_proof) = &self.prev_block_chain_proof {
            block_chain_vd.verify(prev_proof.clone()).map_err(|e| {
                BlockStepError::InvalidProof(format!("previous block chain proof invalid: {e}"))
            })?;
            BlockChainPublicInputs::<F, C, D>::from_u64_slice(
                &prev_proof.public_inputs.to_u64_vec(),
                &block_chain_vd.common.config,
            )?
        } else {
            let default_state = ExtendedPublicState::new(
                PublicState::default(),
                Bytes32::default(),
                U63::default(),
            );
            BlockChainPublicInputs {
                initial_ext_public_state: default_state.clone(),
                ext_public_state: default_state,
                vd: block_chain_vd.verifier_only.clone(),
            }
        };

        let prev_public_state_ext = prev_inputs.ext_public_state.clone();
        let prev_public_state = prev_public_state_ext.inner.clone();

        // Validate deposit hash chain proof if provided.
        let deposit_chain_inputs: Option<DepositChainPublicInputs<F, C, D>> =
            if let Some(deposit_proof) = &self.deposit_hash_chain_proof {
                deposit_chain_vd
                    .verify(deposit_proof.clone())
                    .map_err(|e| {
                        BlockStepError::InvalidProof(format!(
                            "deposit hash chain proof invalid: {e}"
                        ))
                    })?;
                let deposit_inputs = DepositChainPublicInputs::from_u64_slice(
                    &deposit_proof.public_inputs.to_u64_vec(),
                    &deposit_chain_vd.common.config,
                )?;

                if deposit_inputs.initial_deposit_hash_chain
                    != prev_public_state_ext.deposit_hash_chain
                {
                    return Err(BlockStepError::InvalidInput(
                        "deposit proof initial deposit hash chain mismatch".to_string(),
                    ));
                }
                if deposit_inputs.initial_deposit_tree_root != prev_public_state.deposit_tree_root {
                    return Err(BlockStepError::InvalidInput(
                        "deposit proof initial deposit tree root mismatch".to_string(),
                    ));
                }
                if deposit_inputs.initial_deposit_count != prev_public_state_ext.deposit_count {
                    return Err(BlockStepError::InvalidInput(
                        "deposit proof initial deposit count mismatch".to_string(),
                    ));
                }
                Some(deposit_inputs)
            } else {
                None
            };

        if self.num_users == 0 {
            return Err(BlockStepError::InvalidInput(
                "num_users must be greater than zero".to_string(),
            ));
        }

        let update_vd_map: HashMap<u32, &VerifierCircuitData<F, C, D>> =
            update_account_vds.iter().map(|(n, vd)| (*n, vd)).collect();

        let update_vd = update_vd_map.get(&self.num_users).copied().ok_or(
            BlockStepError::MissingUpdateAccountVerifierData(self.num_users),
        )?;

        update_vd
            .verify(self.update_account_proof.clone())
            .map_err(|e| {
                BlockStepError::InvalidProof(format!("update account proof invalid: {e}"))
            })?;

        let update_inputs_u64 = self.update_account_proof.public_inputs.to_u64_vec();
        let update_account_inputs =
            UpdateAccountPublicInputs::from_u64_slice(&update_inputs_u64)
                .map_err(|e| BlockStepError::UpdateAccountPublicInputs(e.to_string()))?;

        if let Some(deposit_inputs) = deposit_chain_inputs.as_ref() {
            if update_account_inputs.deposit_hash_chain != deposit_inputs.deposit_hash_chain {
                return Err(BlockStepError::InvalidInput(
                    "deposit hash chain mismatch between update account and deposit proofs"
                        .to_string(),
                ));
            }
        }

        // Verify previous public state membership and derive the root prior to this update.
        let merkle_index = prev_public_state.block_number.as_u64();
        self.public_state_merkle_proof
            .verify(
                &prev_public_state,
                merkle_index,
                prev_public_state.prev_public_state_root,
            )
            .map_err(|e| {
                BlockStepError::PublicStateMerkleProof(format!(
                    "failed to verify previous public state: {e}"
                ))
            })?;
        let prev_public_state_root = self
            .public_state_merkle_proof
            .get_root(&prev_public_state, merkle_index);

        // Determine new state components.
        if update_account_inputs.prev_account_tree_root != prev_public_state.account_tree_root {
            return Err(BlockStepError::InvalidInput(
                "update account proof initial account tree root mismatch".to_string(),
            ));
        }
        let block_number = update_account_inputs.block_number;
        let account_tree_root = update_account_inputs.new_account_tree_root;

        let (deposit_tree_root, deposit_count) = if let Some(deposit_inputs) = &deposit_chain_inputs
        {
            (
                deposit_inputs.deposit_tree_root,
                deposit_inputs.deposit_count,
            )
        } else {
            (
                prev_public_state.deposit_tree_root,
                prev_public_state_ext.deposit_count,
            )
        };

        let deposit_hash_chain = if let Some(deposit_inputs) = &deposit_chain_inputs {
            deposit_inputs.deposit_hash_chain
        } else {
            prev_public_state_ext.deposit_hash_chain
        };

        let new_public_state = PublicState {
            block_number,
            account_tree_root,
            deposit_tree_root,
            deposit_count,
            prev_public_state_root,
        };

        let new_public_state_ext =
            ExtendedPublicState::new(new_public_state, deposit_hash_chain, deposit_count);

        Ok(BlockChainPublicInputs {
            initial_ext_public_state: prev_inputs.initial_ext_public_state,
            ext_public_state: new_public_state_ext,
            vd: prev_inputs.vd,
        })
    }
}
