use std::collections::HashMap;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
            VerifierCircuitTarget,
        },
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
            update_channel_tree::{UpdateUserPublicInputs, UpdateUserPublicInputsTarget},
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
        cyclic::conditionally_connect_vd,
        dummy::{DummyProof, conditionally_verify_proof},
        leafable::Leafable,
        logic::BuilderLogic,
        poseidon_hash_out::PoseidonHashOutTarget,
        recursively_verifiable::{
            add_proof_target_and_conditionally_verify,
            add_proof_target_and_conditionally_verify_cyclic,
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
    MissingUpdateUserVerifierData(u32),

    #[error("Deposit chain public inputs error: {0}")]
    DepositChainPublicInputs(#[from] DepositChainPublicInputsError),

    #[error("Block chain public inputs error: {0}")]
    BlockChainPublicInputs(#[from] BlockChainPublicInputsError),

    #[error("Update account public inputs error: {0}")]
    UpdateUserPublicInputs(String),

    #[error("Public state merkle proof error: {0}")]
    PublicStateMerkleProof(String),

    #[error("Failed to prove block step: {0}")]
    FailedToProve(String),
}

pub struct BlockStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // paddind number of users in this block (must be > 0)
    pub num_users: u32,

    pub initial_public_state: Option<ExtendedPublicState>,

    // Previous block hash chain proof if not the first block
    pub prev_block_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,

    // Deposit hash chain proof if there is a deposit in this block
    pub deposit_hash_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,

    // Update account proof corresponding to this block
    pub update_user_proof: ProofWithPublicInputs<F, C, D>,

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
            BlockStepError::MissingUpdateUserVerifierData(self.num_users),
        )?;
        update_vd
            .verify(self.update_user_proof.clone())
            .map_err(|e| {
                BlockStepError::InvalidProof(format!("update account proof invalid: {e}"))
            })?;
        let update_user_inputs = UpdateUserPublicInputs::from_u64_slice(
            &self.update_user_proof.public_inputs.to_u64_vec(),
        )
        .map_err(|e| BlockStepError::UpdateUserPublicInputs(e.to_string()))?;

        // validate consistency between update account proof and previous public state
        let block_number = prev_public_state.block_number.add(1).map_err(|_e| {
            BlockStepError::InvalidInput("previous block number is at max value".to_string())
        })?;
        if update_user_inputs.block_number != block_number {
            return Err(BlockStepError::InvalidInput(
                "update account proof block number must be previous block number + 1".to_string(),
            ));
        }
        if update_user_inputs.prev_account_tree_root != prev_public_state.account_tree_root {
            return Err(BlockStepError::InvalidInput(
                "update account proof initial user tree root mismatch".to_string(),
            ));
        }
        if update_user_inputs.prev_block_hash_chain != prev_public_state_ext.block_hash_chain {
            return Err(BlockStepError::InvalidInput(
                "update account proof initial block hash chain mismatch".to_string(),
            ));
        }
        let account_tree_root = update_user_inputs.new_account_tree_root;
        let block_hash_chain = update_user_inputs.new_block_hash_chain;

        let mut deposit_hash_chain = prev_public_state_ext.deposit_hash_chain;
        let mut deposit_tree_root = prev_public_state.deposit_tree_root;
        let mut deposit_count = prev_public_state_ext.deposit_count;
        // if there is update in deposit hash chain, the deposit proof must be provided
        if prev_inputs.ext_public_state.deposit_hash_chain != update_user_inputs.deposit_hash_chain
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
            if deposit_inputs.deposit_hash_chain != update_user_inputs.deposit_hash_chain {
                return Err(BlockStepError::InvalidInput(
                    "deposit proof resulting deposit hash chain must match update account input"
                        .to_string(),
                ));
            }
            if deposit_inputs.block_number != block_number {
                return Err(BlockStepError::InvalidInput(
                    "deposit proof block number mismatch".to_string(),
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
            timestamp: update_user_inputs.block_timestamp,
            account_tree_root,
            deposit_tree_root,
            prev_public_state_root,
        };

        let new_public_state_ext = ExtendedPublicState::new(
            new_public_state,
            block_hash_chain,
            deposit_hash_chain,
            deposit_count,
        );

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
    pub update_user_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    pub selected_update_inputs: UpdateUserPublicInputsTarget,

    pub public_state_merkle_proof: PublicStateMerkleProofTarget,
    pub block_chain_vd: VerifierCircuitTarget,

    pub new_pis: BlockChainPublicInputsTarget,
}

impl<const D: usize> BlockStepTarget<D> {
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
        assert!(
            !update_account_vds.is_empty(),
            "at least one update account verifier must be provided",
        );

        let has_prev_block_proof = builder.add_virtual_bool_target_safe();

        // add previous block chain proof and conditionally verify
        let block_chain_vd =
            builder.add_virtual_verifier_data(block_chain_cd.config.fri_config.cap_height);
        let prev_block_chain_proof = builder.add_virtual_proof_with_pis(block_chain_cd);
        let prev_inputs_from_proof = BlockChainPublicInputsTarget::from_pis(
            &prev_block_chain_proof.public_inputs,
            &block_chain_cd.config,
        );
        conditionally_verify_proof::<F, C, D>(
            builder,
            has_prev_block_proof,
            &prev_block_chain_proof,
            &block_chain_vd,
            &block_chain_cd,
        );
        conditionally_connect_vd(
            builder,
            has_prev_block_proof,
            &prev_inputs_from_proof.vd,
            &block_chain_vd,
        );

        let initial_public_state = ExtendedPublicStateTarget::new(builder, true);
        let selected_initial_state = ExtendedPublicStateTarget::select(
            builder,
            has_prev_block_proof,
            &prev_inputs_from_proof.initial_ext_public_state,
            &initial_public_state,
        );
        let selected_prev_state = ExtendedPublicStateTarget::select(
            builder,
            has_prev_block_proof,
            &prev_inputs_from_proof.ext_public_state,
            &initial_public_state,
        );

        let mut one_hot = Vec::with_capacity(update_account_vds.len());
        for _ in update_account_vds {
            one_hot.push(builder.add_virtual_bool_target_safe());
        }
        let hot_sum = one_hot
            .iter()
            .fold(builder.zero(), |acc, flag| builder.add(acc, flag.target));
        builder.assert_one(hot_sum);

        let mut update_user_proofs = Vec::with_capacity(update_account_vds.len());
        let mut update_user_inputs = Vec::with_capacity(update_account_vds.len());
        for (flag, (_num_users, vd)) in one_hot.iter().zip(update_account_vds.iter()) {
            let proof = add_proof_target_and_conditionally_verify(vd, builder, *flag);
            let inputs = UpdateUserPublicInputsTarget::from_slice(&proof.public_inputs);
            update_user_proofs.push(proof);
            update_user_inputs.push(inputs);
        }

        let update_user_inputs_commitments = update_user_inputs
            .iter()
            .map(|inputs| inputs.commitment(builder))
            .collect::<Vec<_>>();
        let update_commitment_vecs = update_user_inputs_commitments
            .iter()
            .map(|inputs| inputs.to_vec())
            .collect::<Vec<_>>();
        let selected_commitment_vec = builder.select_vec(&update_commitment_vecs, &one_hot);
        let selected_update_inputs = UpdateUserPublicInputsTarget::new(builder, false);
        selected_update_inputs.commitment(builder).connect(
            builder,
            PoseidonHashOutTarget::from_slice(&selected_commitment_vec),
        );

        let has_deposit_proof = builder.add_virtual_bool_target_safe();
        let deposit_hash_chain_proof = add_proof_target_and_conditionally_verify_cyclic(
            deposit_chain_vd,
            builder,
            has_deposit_proof,
        );
        let deposit_inputs = DepositChainPublicInputsTarget::from_pis(
            &deposit_hash_chain_proof.public_inputs,
            &deposit_chain_vd.common.config,
        );

        let prev_public_state_ext = selected_prev_state.clone();
        let prev_public_state = prev_public_state_ext.inner.clone();

        let next_block_number_value =
            builder.add_const(prev_public_state.block_number.value, F::ONE);
        builder.range_check(next_block_number_value, 63);
        builder.connect(
            selected_update_inputs.block_number.value,
            next_block_number_value,
        );
        let next_block_number = U63Target {
            value: next_block_number_value,
        };

        selected_update_inputs
            .prev_account_tree_root
            .connect(builder, prev_public_state.account_tree_root.clone());
        let account_tree_root = selected_update_inputs.new_account_tree_root.clone();

        selected_update_inputs
            .prev_block_hash_chain
            .connect(builder, prev_public_state_ext.block_hash_chain.clone());
        let block_hash_chain = selected_update_inputs.new_block_hash_chain.clone();

        let deposit_hash_eq = prev_public_state_ext
            .deposit_hash_chain
            .is_equal(builder, &selected_update_inputs.deposit_hash_chain);
        let deposit_hash_changed = builder.not(deposit_hash_eq);
        builder.connect(has_deposit_proof.target, deposit_hash_changed.target);

        deposit_inputs
            .initial_deposit_hash_chain
            .conditional_assert_eq(
                builder,
                prev_public_state_ext.deposit_hash_chain.clone(),
                has_deposit_proof,
            );
        deposit_inputs
            .initial_deposit_tree_root
            .conditional_assert_eq(
                builder,
                prev_public_state.deposit_tree_root.clone(),
                has_deposit_proof,
            );
        builder.conditional_assert_eq(
            has_deposit_proof.target,
            deposit_inputs.initial_deposit_count.value,
            prev_public_state_ext.deposit_count.value,
        );
        deposit_inputs.deposit_hash_chain.conditional_assert_eq(
            builder,
            selected_update_inputs.deposit_hash_chain.clone(),
            has_deposit_proof,
        );
        builder.conditional_assert_eq(
            has_deposit_proof.target,
            deposit_inputs.block_number.value,
            next_block_number.value,
        );

        let selected_deposit_hash_chain = Bytes32Target::select(
            builder,
            has_deposit_proof,
            deposit_inputs.deposit_hash_chain.clone(),
            prev_public_state_ext.deposit_hash_chain.clone(),
        );
        let selected_deposit_tree_root = PoseidonHashOutTarget::select(
            builder,
            has_deposit_proof,
            deposit_inputs.deposit_tree_root.clone(),
            prev_public_state.deposit_tree_root.clone(),
        );
        let selected_deposit_count = U63Target::select(
            builder,
            has_deposit_proof,
            &deposit_inputs.deposit_count,
            &prev_public_state_ext.deposit_count,
        );

        let selected_account_tree_root = account_tree_root;

        let public_state_merkle_proof =
            PublicStateMerkleProofTarget::new(builder, PUBLIC_STATE_TREE_HEIGHT);

        // update public state tree
        let empty_public_state_target =
            PublicStateTarget::constant(builder, &PublicState::empty_leaf());
        public_state_merkle_proof.verify::<F, C, D>(
            builder,
            &empty_public_state_target,
            prev_public_state.block_number.value,
            prev_public_state.prev_public_state_root.clone(),
        );
        let prev_public_state_root = public_state_merkle_proof.get_root::<F, C, D>(
            builder,
            &prev_public_state,
            prev_public_state.block_number.value,
        );

        let new_pis = BlockChainPublicInputsTarget {
            initial_ext_public_state: selected_initial_state,
            ext_public_state: ExtendedPublicStateTarget {
                inner: PublicStateTarget {
                    block_number: next_block_number,
                    timestamp: selected_update_inputs.block_timestamp.clone(),
                    account_tree_root: selected_account_tree_root,
                    deposit_tree_root: selected_deposit_tree_root,
                    prev_public_state_root,
                },
                block_hash_chain,
                deposit_hash_chain: selected_deposit_hash_chain,
                deposit_count: selected_deposit_count,
            },
            vd: block_chain_vd.clone(),
        };

        Self {
            one_hot,
            has_prev_block_proof,
            has_deposit_proof,
            initial_public_state,
            prev_block_chain_proof,
            deposit_hash_chain_proof,
            update_user_proofs,
            selected_update_inputs,
            public_state_merkle_proof,
            block_chain_vd,
            new_pis,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &BlockStepWitness<F, C, D>,
        block_chain_vd: &VerifierCircuitData<F, C, D>,
        update_account_vds: &[(u32, VerifierCircuitData<F, C, D>)],
        new_public_inputs: &BlockChainPublicInputs<F, C, D>,
        dummy_prev_block_proof: &ProofWithPublicInputs<F, C, D>,
        dummy_deposit_proof: &ProofWithPublicInputs<F, C, D>,
        dummy_update_proofs: &HashMap<u32, ProofWithPublicInputs<F, C, D>>,
    ) -> Result<(), BlockStepError>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        let has_prev_block = value.prev_block_chain_proof.is_some();
        witness.set_bool_target(self.has_prev_block_proof, has_prev_block);
        if let Some(proof) = &value.prev_block_chain_proof {
            witness.set_proof_with_pis_target(&self.prev_block_chain_proof, proof);
        } else {
            witness.set_proof_with_pis_target(&self.prev_block_chain_proof, dummy_prev_block_proof);
        }

        if !has_prev_block && value.initial_public_state.is_none() {
            return Err(BlockStepError::InvalidInput(
                "initial_public_state must be provided when previous block proof is absent"
                    .to_string(),
            ));
        }

        if let Some(initial_state) = &value.initial_public_state {
            self.initial_public_state
                .set_witness(witness, initial_state);
        } else {
            self.initial_public_state
                .set_witness(witness, &ExtendedPublicState::default());
        }

        let has_deposit_proof = value.deposit_hash_chain_proof.is_some();
        witness.set_bool_target(self.has_deposit_proof, has_deposit_proof);
        if let Some(proof) = &value.deposit_hash_chain_proof {
            witness.set_proof_with_pis_target(&self.deposit_hash_chain_proof, proof);
        } else {
            witness.set_proof_with_pis_target(&self.deposit_hash_chain_proof, dummy_deposit_proof);
        }

        let mut matched_update_proof = false;
        for ((flag_target, proof_target), (num_users, _vd)) in self
            .one_hot
            .iter()
            .zip(self.update_user_proofs.iter())
            .zip(update_account_vds.iter())
        {
            let is_selected = value.num_users == *num_users;
            witness.set_bool_target(*flag_target, is_selected);
            if is_selected {
                matched_update_proof = true;
                witness.set_proof_with_pis_target(proof_target, &value.update_user_proof);
                let selected_update_inputs = UpdateUserPublicInputs::from_u64_slice(
                    &value.update_user_proof.public_inputs.to_u64_vec(),
                )
                .map_err(|e| BlockStepError::UpdateUserPublicInputs(e.to_string()))?;
                self.selected_update_inputs
                    .set_witness(witness, &selected_update_inputs);
            } else {
                let dummy_proof = dummy_update_proofs.get(num_users).ok_or_else(|| {
                    BlockStepError::InvalidInput(format!(
                        "dummy update-account proof missing for num_users {}",
                        num_users
                    ))
                })?;
                witness.set_proof_with_pis_target(proof_target, dummy_proof);
            }
        }

        if !matched_update_proof {
            return Err(BlockStepError::MissingUpdateUserVerifierData(
                value.num_users,
            ));
        }

        self.public_state_merkle_proof
            .set_witness(witness, &value.public_state_merkle_proof);

        witness.set_verifier_data_target(&self.block_chain_vd, &block_chain_vd.verifier_only);
        self.new_pis
            .set_witness::<F, C, D, _>(witness, new_public_inputs);

        Ok(())
    }
}

pub struct BlockStepCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: BlockStepTarget<D>,
    pub public_inputs: BlockChainPublicInputsTarget,
    pub block_chain_cd: CommonCircuitData<F, D>,
    pub deposit_chain_common: CommonCircuitData<F, D>,
    pub supported_user_counts: Vec<u32>,
    pub dummy_prev_block_proof: ProofWithPublicInputs<F, C, D>,
    pub dummy_deposit_proof: ProofWithPublicInputs<F, C, D>,
    pub dummy_update_proofs: HashMap<u32, ProofWithPublicInputs<F, C, D>>,
}

impl<F, C, const D: usize> BlockStepCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        block_chain_cd: &CommonCircuitData<F, D>,
        update_account_vds: &[(u32, VerifierCircuitData<F, C, D>)],
        deposit_chain_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = BlockStepTarget::new::<F, C>(
            &mut builder,
            block_chain_cd,
            update_account_vds,
            deposit_chain_vd,
        );
        let public_inputs = target.new_pis.clone();
        builder.register_public_inputs(&public_inputs.to_vec(&block_chain_cd.config));

        let data = builder.build::<C>();

        let dummy_prev_block_proof = DummyProof::new(block_chain_cd).proof;
        let dummy_deposit_proof = DummyProof::new(&deposit_chain_vd.common).proof;
        let mut dummy_update_proofs = HashMap::new();
        for (num_users, vd) in update_account_vds.iter() {
            let dummy = DummyProof::new(&vd.common);
            dummy_update_proofs.insert(*num_users, dummy.proof);
        }
        let supported_user_counts = update_account_vds
            .iter()
            .map(|(num_users, _)| *num_users)
            .collect();

        Self {
            data,
            target,
            public_inputs,
            block_chain_cd: block_chain_cd.clone(),
            deposit_chain_common: deposit_chain_vd.common.clone(),
            supported_user_counts,
            dummy_prev_block_proof,
            dummy_deposit_proof,
            dummy_update_proofs,
        }
    }

    pub fn prove(
        &self,
        block_chain_vd: &VerifierCircuitData<F, C, D>,
        update_account_vds: &[(u32, VerifierCircuitData<F, C, D>)],
        deposit_chain_vd: &VerifierCircuitData<F, C, D>,
        witness: &BlockStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BlockStepError> {
        if block_chain_vd.common != self.block_chain_cd {
            return Err(BlockStepError::InvalidInput(
                "block chain verifier common data mismatch".to_string(),
            ));
        }
        if deposit_chain_vd.common != self.deposit_chain_common {
            return Err(BlockStepError::InvalidInput(
                "deposit chain verifier common data mismatch".to_string(),
            ));
        }
        if update_account_vds.len() != self.supported_user_counts.len() {
            return Err(BlockStepError::InvalidInput(format!(
                "expected {} update account verifiers, got {}",
                self.supported_user_counts.len(),
                update_account_vds.len()
            )));
        }
        for (expected, (num_users, _)) in self
            .supported_user_counts
            .iter()
            .zip(update_account_vds.iter())
        {
            if *expected != *num_users {
                return Err(BlockStepError::InvalidInput(format!(
                    "update account verifier mismatch: expected num_users {}, got {}",
                    *expected, *num_users
                )));
            }
        }

        let new_public_inputs =
            witness.to_public_inputs(block_chain_vd, update_account_vds, deposit_chain_vd)?;

        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(
            &mut pw,
            witness,
            block_chain_vd,
            update_account_vds,
            &new_public_inputs,
            &self.dummy_prev_block_proof,
            &self.dummy_deposit_proof,
            &self.dummy_update_proofs,
        )?;
        self.public_inputs
            .set_witness::<F, C, D, _>(&mut pw, &new_public_inputs);

        self.data
            .prove(pw)
            .map_err(|e| BlockStepError::FailedToProve(e.to_string()))
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> Result<(), BlockStepError> {
        self.data
            .verify(proof)
            .map_err(|e| BlockStepError::InvalidProof(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::{
            test_utils::block_witness_generator::BlockWitnessGenerator,
            validity::{
                block_hash_chain::{
                    block_chain_pis::BLOCK_CHAIN_PUBLIC_INPUTS_LEN,
                    sphincs_sig::SpxSigWitness,
                    update_channel_tree::{UpdateUserCircuit, UpdateUserTree},
                },
                deposit_hash_chain::deposit_chain_pis::DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN,
            },
        },
        common::u63::U63,
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
        utils::cyclic::TestCyclicCircuit,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_block_step_from_generator() {
        let supported_user_counts = vec![2];
        let mut rng = StdRng::seed_from_u64(42);

        let mut generator = BlockWitnessGenerator::new(&supported_user_counts);
        let initial_state = generator.current_extended_public_state();

        let tx_tree_root = Bytes32::rand(&mut rng);
        let timestamp = rng.next_u64();
        // Use empty key_ids (all-padding block) so that should_update=false for
        // every slot, bypassing SPHINCS+ signature verification.  Dedicated signing
        // tests live in update_channel_tree.rs.
        generator
            .add_block(1, &[], timestamp, tx_tree_root)
            .expect("add block");

        let block_number = generator.block_number;
        let block_witness = generator
            .block_chain_witness
            .get(&block_number)
            .expect("block witness");

        let update_circuit = UpdateUserCircuit::<F, C, D>::new(block_witness.block.num_users);
        let next_block_number = initial_state
            .inner
            .block_number
            .add(1)
            .expect("increment block number");

        let num_users = block_witness.block.num_users as usize;
        let update_tree = UpdateUserTree {
            prev_block_hash_chain: initial_state.block_hash_chain,
            prev_account_tree_root: initial_state.inner.account_tree_root,
            block_number: next_block_number,
            block: block_witness.block.clone(),
            prev_account_leaves: block_witness.prev_account_leaves.clone(),
            user_merkle_proofs: block_witness.user_merkle_proofs.clone(),
            send_merkle_proofs: block_witness.send_merkle_proofs.clone(),
            sig_witnesses: vec![SpxSigWitness::dummy(); num_users],
            // Dummy member proofs/keys: this test path keeps every slot non-updating, so the
            // member binding and signature constraints are skipped (should_update == false).
            member_merkle_proofs: vec![
                crate::common::trees::key_tree::MemberMerkleProof::dummy(
                    crate::constants::MEMBER_TREE_HEIGHT,
                );
                num_users
            ],
            member_regev_pks: vec![
                crate::regev::RegevPk {
                    a: vec![0u32; crate::regev::REGEV_N],
                    b: vec![0u32; crate::regev::REGEV_N],
                };
                num_users
            ],
            msg_fields:
                crate::circuits::validity::block_hash_chain::sphincs_sig::SmallBlockMessageFields::default(),
            tx_v2_indices: vec![0; num_users],
            tx_v2s: vec![crate::common::tx::TxV2::default(); num_users],
            tx_v2_merkle_proofs: vec![
                crate::common::trees::tx_v2_tree::TxV2MerkleProof::dummy(
                    crate::constants::TX_TREE_HEIGHT,
                );
                num_users
            ],
            channel_action_indices: vec![0; num_users],
            channel_actions: vec![crate::common::tx::ChannelAction::default(); num_users],
            channel_action_merkle_proofs: vec![
                crate::common::trees::tx_v2_tree::ChannelActionMerkleProof::dummy(
                    crate::constants::TX_TREE_HEIGHT,
                );
                num_users
            ],
        };
        let update_inputs = update_tree.to_public_inputs().expect("update inputs");
        let update_proof = update_circuit
            .prove(&update_tree)
            .expect("update account proof");

        let block_chain_cd =
            TestCyclicCircuit::<F, C, D>::generate_cd(BLOCK_CHAIN_PUBLIC_INPUTS_LEN);
        let block_chain_circuit = TestCyclicCircuit::<F, C, D>::new(
            CircuitConfig::standard_recursion_config(),
            BLOCK_CHAIN_PUBLIC_INPUTS_LEN,
            &block_chain_cd,
        );
        let block_chain_common = block_chain_circuit.data.common.clone();
        let block_chain_vd = block_chain_circuit.data.verifier_data();

        let deposit_chain_cd =
            TestCyclicCircuit::<F, C, D>::generate_cd(DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN);
        let deposit_chain_circuit = TestCyclicCircuit::<F, C, D>::new(
            CircuitConfig::standard_recursion_config(),
            DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN,
            &deposit_chain_cd,
        );
        let deposit_chain_vd = deposit_chain_circuit.data.verifier_data();

        let update_account_vds = vec![(
            block_witness.block.num_users,
            update_circuit.data.verifier_data(),
        )];

        let block_step_circuit = BlockStepCircuit::<F, C, D>::new(
            &block_chain_common,
            &update_account_vds,
            &deposit_chain_vd,
        );

        let witness = BlockStepWitness {
            initial_public_state: Some(initial_state.clone()),
            prev_block_chain_proof: None,
            deposit_hash_chain_proof: None,
            num_users: block_witness.block.num_users,
            update_user_proof: update_proof,
            public_state_merkle_proof: block_witness.public_state_merkle_proof.clone(),
        };

        let public_inputs = witness
            .to_public_inputs(&block_chain_vd, &update_account_vds, &deposit_chain_vd)
            .expect("block step public inputs");
        assert_eq!(
            public_inputs.ext_public_state.inner.block_number,
            next_block_number
        );
        assert_eq!(
            public_inputs.ext_public_state.block_hash_chain,
            update_inputs.new_block_hash_chain
        );

        let proof = block_step_circuit
            .prove(
                &block_chain_vd,
                &update_account_vds,
                &deposit_chain_vd,
                &witness,
            )
            .expect("block step proof");
        block_step_circuit.verify(proof).expect("block step verify");
    }
}
