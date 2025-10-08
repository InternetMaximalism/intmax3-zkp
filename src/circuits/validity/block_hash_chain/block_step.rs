use std::collections::HashMap;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::validity::{
        block_hash_chain::{
            block_chain_pis::{
                BlockChainPublicInputs, BlockChainPublicInputsError, BlockChainPublicInputsTarget,
            },
            ext_public_state::{ExtendedPublicState, ExtendedPublicStateTarget},
            update_account_tree::{UpdateAccountPublicInputs, UpdateAccountPublicInputsTarget},
        },
        deposit_hash_chain::deposit_chain_pis::{
            DepositChainPublicInputs, DepositChainPublicInputsError, DepositChainPublicInputsTarget,
        },
    },
    common::{
        public_state::{PublicState, PublicStateTarget},
        trees::public_state_tree::{PublicStateMerkleProof, PublicStateMerkleProofTarget},
        u63::U63Target,
    },
    constants::PUBLIC_STATE_TREE_HEIGHT,
    ethereum_types::{bytes32::Bytes32Target, u32limb_trait::U32LimbTargetTrait},
    utils::{
        conversion::ToU64,
        leafable::Leafable,
        poseidon_hash_out::PoseidonHashOutTarget,
        recursively_verifiable::{
            add_proof_target_and_conditionally_verify, add_proof_target_and_verify,
        },
    },
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
    pub initial_public_state: Option<ExtendedPublicState>,

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
            let initial_state = self.initial_public_state.clone().ok_or_else(|| {
                BlockStepError::InvalidInput(
                    "initial_public_state must be provided when previous block proof is absent"
                        .to_string(),
                )
            })?;
            BlockChainPublicInputs {
                initial_ext_public_state: initial_state.clone(),
                ext_public_state: initial_state,
                vd: block_chain_vd.verifier_only.clone(),
            }
        };

        let prev_public_state_ext = prev_inputs.ext_public_state.clone();
        let prev_public_state = prev_public_state_ext.inner.clone();

        // verify update account proof and extract public inputs
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
        let update_account_inputs = UpdateAccountPublicInputs::from_u64_slice(
            &self.update_account_proof.public_inputs.to_u64_vec(),
        )
        .map_err(|e| BlockStepError::UpdateAccountPublicInputs(e.to_string()))?;

        // validate consistency between update account proof and previous public state
        let block_number = prev_public_state.block_number.add(1).map_err(|_e| {
            BlockStepError::InvalidInput("previous block number is at max value".to_string())
        })?;
        if update_account_inputs.block_number != block_number {
            return Err(BlockStepError::InvalidInput(
                "update account proof block number must be previous block number + 1".to_string(),
            ));
        }
        if update_account_inputs.prev_account_tree_root != prev_public_state.account_tree_root {
            return Err(BlockStepError::InvalidInput(
                "update account proof initial account tree root mismatch".to_string(),
            ));
        }
        let account_tree_root = update_account_inputs.new_account_tree_root;

        let mut deposit_hash_chain = prev_public_state_ext.deposit_hash_chain;
        let mut deposit_tree_root = prev_public_state.deposit_tree_root;
        let mut deposit_count = prev_public_state_ext.deposit_count;
        // if there is update in deposit hash chain, the deposit proof must be provided
        if prev_inputs.ext_public_state.deposit_hash_chain
            != update_account_inputs.deposit_hash_chain
        {
            let deposit_proof = self.deposit_hash_chain_proof.as_ref().ok_or_else(|| {
                BlockStepError::InvalidInput(
                    "deposit_hash_chain_proof must be provided when deposit hash chain is updated"
                        .to_string(),
                )
            })?;

            // verify deposit hash chain proof and extract public inputs
            deposit_chain_vd
                .verify(deposit_proof.clone())
                .map_err(|e| {
                    BlockStepError::InvalidProof(format!("deposit hash chain proof invalid: {e}"))
                })?;
            let deposit_inputs = DepositChainPublicInputs::<F, C, D>::from_u64_slice(
                &deposit_proof.public_inputs.to_u64_vec(),
                &deposit_chain_vd.common.config,
            )?;

            // validate consistency between deposit proof and previous public state
            if deposit_inputs.initial_deposit_hash_chain != prev_public_state_ext.deposit_hash_chain
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
            if deposit_inputs.deposit_hash_chain != update_account_inputs.deposit_hash_chain {
                return Err(BlockStepError::InvalidInput(
                    "deposit proof resulting deposit hash chain must match update account input"
                        .to_string(),
                ));
            }

            // update deposit-related state components
            deposit_hash_chain = deposit_inputs.deposit_hash_chain;
            deposit_tree_root = deposit_inputs.deposit_tree_root;
            deposit_count = deposit_inputs.deposit_count;
        }

        // Verify previous public state membership and derive the root prior to this update.
        let empty_public_state = PublicState::empty_leaf();
        self.public_state_merkle_proof
            .verify(
                &empty_public_state,
                prev_public_state.block_number.as_u64(),
                prev_public_state.prev_public_state_root,
            )
            .map_err(|e| {
                BlockStepError::PublicStateMerkleProof(format!(
                    "failed to verify empty public state membership: {e}"
                ))
            })?;
        // update prev_public_state_root
        let prev_public_state_root = self
            .public_state_merkle_proof
            .get_root(&prev_public_state, prev_public_state.block_number.as_u64());

        let new_public_state = PublicState {
            block_number,
            account_tree_root,
            deposit_tree_root,
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

#[derive(Clone, Debug)]
pub struct BlockStepTarget<const D: usize> {
    // one hot encoding of which update account circuit to use
    // length is number of supported update account circuits
    pub one_hot: Vec<BoolTarget>,

    pub has_prev_block_proof: BoolTarget,
    pub has_deposit_proof: BoolTarget,
    pub initial_public_state: ExtendedPublicStateTarget,
    pub prev_block_chain_proof: ProofWithPublicInputsTarget<D>,
    pub deposit_hash_chain_proof: ProofWithPublicInputsTarget<D>,

    // Update account proof different for each number of users
    pub update_account_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    pub public_state_merkle_proof: PublicStateMerkleProofTarget,

    pub new_pis: BlockChainPublicInputsTarget,
}

impl<const D: usize> BlockStepTarget<D> {
    #[allow(clippy::too_many_arguments)]
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        block_chain_cd: &CommonCircuitData<F, D>,
        update_account_vds: &[(u32, VerifierCircuitData<F, C, D>)],
        deposit_chain_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        todo!()
    }
}

fn enforce_conditional_selection<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    condition: BoolTarget,
    not_condition: BoolTarget,
    target: &[Target],
    when_true: &[Target],
    when_false: &[Target],
) {
    debug_assert_eq!(target.len(), when_true.len());
    debug_assert_eq!(target.len(), when_false.len());
    for (selected, expected) in target.iter().zip(when_true.iter()) {
        builder.conditional_assert_eq(condition.target, *selected, *expected);
    }
    for (selected, expected) in target.iter().zip(when_false.iter()) {
        builder.conditional_assert_eq(not_condition.target, *selected, *expected);
    }
}
