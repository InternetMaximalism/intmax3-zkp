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
        cyclic::conditionally_connect_vd,
        dummy::{DummyProof, conditionally_verify_proof},
        leafable::Leafable,
        poseidon_hash_out::PoseidonHashOutTarget,
        recursively_verifiable::add_proof_target_and_conditionally_verify,
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
    pub block_chain_vd: VerifierCircuitTarget,

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
        println!("conditionally verify previous block proof");
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

        let mut update_account_proofs = Vec::with_capacity(update_account_vds.len());
        let mut update_account_inputs = Vec::with_capacity(update_account_vds.len());
        for (flag, (_num_users, vd)) in one_hot.iter().zip(update_account_vds.iter()) {
            println!("add update account proof for num_users {}", _num_users);
            let proof = add_proof_target_and_conditionally_verify(vd, builder, *flag);
            let inputs = UpdateAccountPublicInputsTarget::from_slice(&proof.public_inputs);
            update_account_proofs.push(proof);
            update_account_inputs.push(inputs);
        }

        let mut selected_update_inputs = update_account_inputs[0].clone();
        for (flag, inputs) in one_hot
            .iter()
            .copied()
            .zip(update_account_inputs.iter())
            .skip(1)
        {
            selected_update_inputs = UpdateAccountPublicInputsTarget::select(
                builder,
                flag,
                inputs,
                &selected_update_inputs,
            );
        }

        println!("add deposit hash chain proof");
        let has_deposit_proof = builder.add_virtual_bool_target_safe();
        let deposit_hash_chain_proof =
            add_proof_target_and_conditionally_verify(deposit_chain_vd, builder, has_deposit_proof);
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
                    account_tree_root,
                    deposit_tree_root: selected_deposit_tree_root,
                    prev_public_state_root,
                },
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
            update_account_proofs,
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
            .zip(self.update_account_proofs.iter())
            .zip(update_account_vds.iter())
        {
            let is_selected = value.num_users == *num_users;
            witness.set_bool_target(*flag_target, is_selected);
            if is_selected {
                matched_update_proof = true;
                witness.set_proof_with_pis_target(proof_target, &value.update_account_proof);
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
            return Err(BlockStepError::MissingUpdateAccountVerifierData(
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

    #[allow(clippy::too_many_arguments)]
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
        circuits::validity::{
            block_hash_chain::{
                block_chain_pis::BLOCK_CHAIN_PUBLIC_INPUTS_LEN,
                update_account_tree::{UpdateAccountCircuit, UpdateAccountTree},
            },
            deposit_hash_chain::{
                deposit_chain_pis::DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN,
                deposit_step::DepositStepWitness,
            },
        },
        common::{
            block::Block,
            deposit::Deposit,
            public_state::PublicState,
            trees::{
                account_tree::{AccountLeaf, AccountTree, SendLeaf, SendMerkleProof, SendTree},
                deposit_tree::DepositTree,
                public_state_tree::PublicStateTree,
            },
            u63::{BlockNumber, U63},
            user_id::UserId,
        },
        constants::ACCOUNT_TREE_HEIGHT,
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
        utils::{
            conversion::ToField as _,
            cyclic::{TestCyclicCircuit, vd_vec_len},
        },
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use rand::{SeedableRng, rngs::StdRng};

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    #[allow(clippy::too_many_locals)]
    fn test_block_step_circuit() {
        let block_chain_config = CircuitConfig::standard_recursion_config();
        let block_chain_vd_len = vd_vec_len(&block_chain_config);
        let block_chain_pis_len = BLOCK_CHAIN_PUBLIC_INPUTS_LEN;
        let block_chain_total_pis_len = block_chain_pis_len + block_chain_vd_len;
        let block_chain_cd = TestCyclicCircuit::<F, C, D>::generate_cd(block_chain_pis_len);
        let block_chain_circuit = TestCyclicCircuit::<F, C, D>::new(
            block_chain_config.clone(),
            block_chain_pis_len,
            &block_chain_cd,
        );
        let block_chain_common = block_chain_circuit.data.common.clone();
        let block_chain_vd = block_chain_circuit.data.verifier_data();

        let deposit_chain_pis_len = DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN;
        let deposit_chain_cd = TestCyclicCircuit::<F, C, D>::generate_cd(deposit_chain_pis_len);
        let deposit_chain_config = CircuitConfig::standard_recursion_config();
        let deposit_chain_circuit = TestCyclicCircuit::<F, C, D>::new(
            deposit_chain_config,
            deposit_chain_pis_len,
            &deposit_chain_cd,
        );
        let deposit_chain_vd = deposit_chain_circuit.data.verifier_data();

        let num_users = 2;
        let update_account_circuit = UpdateAccountCircuit::<F, C, D>::new(num_users);
        let update_account_vd = update_account_circuit.data.verifier_data();
        let update_account_vds = vec![(num_users, update_account_vd.clone())];

        let block_step_circuit = BlockStepCircuit::<F, C, D>::new(
            &block_chain_common,
            &update_account_vds,
            &deposit_chain_vd,
        );

        let mut rng = StdRng::seed_from_u64(42);
        let aggregator_id = 5u32;

        let mut public_state_tree = PublicStateTree::init();
        let set_public_state = |tree: &mut PublicStateTree, index: u64, state: PublicState| {
            while tree.len() < index as usize {
                tree.push(PublicState::empty_leaf());
            }
            if tree.len() == index as usize {
                tree.push(state);
            } else {
                tree.update(index, state);
            }
        };
        let initial_public_state_root = public_state_tree.get_root();

        let deposit_tree = DepositTree::init();
        let initial_deposit_tree_root = deposit_tree.get_root();
        let initial_deposit_hash_chain = Bytes32::default();
        let initial_deposit_count = U63::default();

        let deposit = Deposit {
            depositor: Default::default(),
            recipient: Bytes32::rand(&mut rng),
            token_index: 0,
            amount: U256::from(10u32),
            block_number: BlockNumber::default(),
            aux_data: Bytes32::rand(&mut rng),
        };
        let deposit_index = 0u64;
        let deposit_merkle_proof = deposit_tree.prove(deposit_index);
        let mut deposit_tree_after_first = deposit_tree.clone();
        deposit_tree_after_first.push(deposit.clone());
        let expected_deposit_tree_root = deposit_tree_after_first.get_root();
        let expected_deposit_hash_chain = deposit.hash_with_prev_hash(initial_deposit_hash_chain);

        let deposit_witness = DepositStepWitness::<F, C, D> {
            initial_value: Some((
                initial_deposit_hash_chain,
                initial_deposit_tree_root,
                initial_deposit_count,
            )),
            prev_deposit_chain_proof: None,
            deposit: deposit.clone(),
            deposit_merkle_proof: deposit_merkle_proof.clone(),
        };
        let deposit_chain_public_inputs_first = deposit_witness
            .to_public_inputs(&deposit_chain_vd)
            .expect("deposit chain public inputs");
        assert_eq!(
            deposit_chain_public_inputs_first.deposit_tree_root,
            expected_deposit_tree_root
        );
        assert_eq!(
            deposit_chain_public_inputs_first.deposit_hash_chain,
            expected_deposit_hash_chain
        );
        let deposit_chain_pis_first_fields = deposit_chain_public_inputs_first
            .to_u64_vec(&deposit_chain_cd.config)
            .to_field_vec::<F>();
        let deposit_chain_proof_first = deposit_chain_circuit
            .prove(Some(deposit_chain_pis_first_fields.as_slice()), None)
            .expect("deposit chain proof");

        let block_number_prev = BlockNumber::default();
        let block_number_first = BlockNumber::new(1).unwrap();
        let prev_block_hash_chain = Bytes32::rand(&mut rng);
        let tx_tree_root_first = Bytes32::rand(&mut rng);

        let user1 = UserId::new(aggregator_id, 1).unwrap();
        let user2 = UserId::new(aggregator_id, 2).unwrap();

        let mut send_tree_user1 = SendTree::init();
        let send_leaf_user1_prev = SendLeaf {
            prev: BlockNumber::default(),
            cur: BlockNumber::new(10).unwrap(),
            tx_tree_root: Bytes32::rand(&mut rng),
        };
        send_tree_user1.push(send_leaf_user1_prev.clone());
        let prev_account_leaf_user1 = AccountLeaf {
            index: send_tree_user1.len() as u32,
            prev: send_leaf_user1_prev.cur,
            send_tree_root: send_tree_user1.get_root(),
        };

        let mut send_tree_user2 = SendTree::init();
        let send_leaf_user2_prev = SendLeaf {
            prev: BlockNumber::new(7).unwrap(),
            cur: block_number_first,
            tx_tree_root: Bytes32::rand(&mut rng),
        };
        send_tree_user2.push(send_leaf_user2_prev.clone());
        let prev_account_leaf_user2 = AccountLeaf {
            index: send_tree_user2.len() as u32,
            prev: block_number_first,
            send_tree_root: send_tree_user2.get_root(),
        };

        let mut account_tree = AccountTree::new(ACCOUNT_TREE_HEIGHT);
        account_tree.update(user1.as_u64(), prev_account_leaf_user1.clone());
        account_tree.update(user2.as_u64(), prev_account_leaf_user2.clone());
        let prev_account_tree_root = account_tree.get_root();

        let block_first = Block::new(
            num_users,
            aggregator_id,
            &[1, 2],
            tx_tree_root_first,
            expected_deposit_hash_chain,
        )
        .unwrap();

        let send_proof_user1_first = send_tree_user1.prove(prev_account_leaf_user1.index.into());
        let send_proof_user2_first = send_tree_user2.prove(prev_account_leaf_user2.index.into());

        let prev_account_leaves_first = vec![
            prev_account_leaf_user1.clone(),
            prev_account_leaf_user2.clone(),
        ];
        let send_merkle_proofs_first: Vec<SendMerkleProof> = vec![
            send_proof_user1_first.clone(),
            send_proof_user2_first.clone(),
        ];
        let mut account_tree_for_proofs_first = account_tree.clone();
        let mut account_merkle_proofs_first = Vec::with_capacity(num_users as usize);
        for (i, &local_id) in block_first.local_ids.iter().enumerate() {
            let user_id = UserId::new(aggregator_id, local_id).unwrap();
            let proof = account_tree_for_proofs_first.prove(user_id.as_u64());
            account_merkle_proofs_first.push(proof);

            let prev_leaf = &prev_account_leaves_first[i];
            if prev_leaf.prev == block_number_first {
                continue;
            }

            let send_proof = &send_merkle_proofs_first[i];
            let new_send_leaf = SendLeaf {
                prev: prev_leaf.prev,
                cur: block_number_first,
                tx_tree_root: tx_tree_root_first,
            };
            let new_send_root = send_proof.get_root(&new_send_leaf, prev_leaf.index.into());
            let new_account_leaf = AccountLeaf {
                index: prev_leaf.index + 1,
                prev: block_number_first,
                send_tree_root: new_send_root,
            };
            account_tree_for_proofs_first.update(user_id.as_u64(), new_account_leaf);
        }

        let update_account_tree_first = UpdateAccountTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number: block_number_first,
            block: block_first.clone(),
            prev_account_leaves: prev_account_leaves_first.clone(),
            account_merkle_proofs: account_merkle_proofs_first.clone(),
            send_merkle_proofs: send_merkle_proofs_first.clone(),
        };
        let update_account_inputs_first = update_account_tree_first
            .to_public_inputs()
            .expect("update account inputs");
        let update_account_proof_first = update_account_circuit
            .prove(&update_account_tree_first)
            .expect("update account proof");

        let new_send_leaf_user1_first = SendLeaf {
            prev: prev_account_leaf_user1.prev,
            cur: block_number_first,
            tx_tree_root: tx_tree_root_first,
        };
        let new_send_root_user1_first = send_proof_user1_first.get_root(
            &new_send_leaf_user1_first,
            prev_account_leaf_user1.index.into(),
        );
        send_tree_user1.push(new_send_leaf_user1_first.clone());
        let new_account_leaf_user1_first = AccountLeaf {
            index: prev_account_leaf_user1.index + 1,
            prev: block_number_first,
            send_tree_root: new_send_root_user1_first,
        };
        account_tree.update(user1.as_u64(), new_account_leaf_user1_first.clone());

        let initial_public_state = PublicState {
            block_number: block_number_prev,
            account_tree_root: prev_account_tree_root,
            deposit_tree_root: initial_deposit_tree_root,
            prev_public_state_root: initial_public_state_root,
        };
        let initial_ext_public_state = ExtendedPublicState::new(
            initial_public_state.clone(),
            initial_deposit_hash_chain,
            initial_deposit_count,
        );
        let public_state_merkle_proof_first = public_state_tree.prove(block_number_prev.as_u64());

        let witness_first = BlockStepWitness {
            initial_public_state: Some(initial_ext_public_state.clone()),
            prev_block_chain_proof: None,
            deposit_hash_chain_proof: Some(deposit_chain_proof_first.clone()),
            num_users,
            update_account_proof: update_account_proof_first.clone(),
            public_state_merkle_proof: public_state_merkle_proof_first.clone(),
        };
        let expected_block_inputs_first = witness_first
            .to_public_inputs(&block_chain_vd, &update_account_vds, &deposit_chain_vd)
            .expect("block chain public inputs");
        assert_eq!(
            expected_block_inputs_first
                .ext_public_state
                .inner
                .block_number,
            block_number_first
        );
        assert_eq!(
            expected_block_inputs_first
                .ext_public_state
                .deposit_hash_chain,
            expected_deposit_hash_chain
        );
        assert_eq!(
            expected_block_inputs_first
                .ext_public_state
                .inner
                .deposit_tree_root,
            expected_deposit_tree_root
        );

        let mut block_chain_state_root_after_first = public_state_tree.clone();
        set_public_state(
            &mut block_chain_state_root_after_first,
            initial_public_state.block_number.as_u64(),
            initial_public_state.clone(),
        );
        assert_eq!(
            expected_block_inputs_first
                .ext_public_state
                .inner
                .prev_public_state_root,
            block_chain_state_root_after_first.get_root()
        );

        let block_step_proof_first = block_step_circuit
            .prove(
                &block_chain_vd,
                &update_account_vds,
                &deposit_chain_vd,
                &witness_first,
            )
            .expect("first block step proof");
        block_step_circuit
            .verify(block_step_proof_first.clone())
            .expect("first block step verification");
        let expected_block_inputs_first_fields = expected_block_inputs_first
            .to_u64_vec(&block_chain_common.config)
            .to_field_vec::<F>();
        assert_eq!(
            expected_block_inputs_first_fields.len(),
            block_chain_total_pis_len,
        );
        assert_eq!(
            block_step_proof_first.public_inputs,
            expected_block_inputs_first_fields
        );

        let first_block_chain_proof = block_chain_circuit
            .prove(Some(expected_block_inputs_first_fields.as_slice()), None)
            .expect("first block chain proof");

        set_public_state(
            &mut public_state_tree,
            block_number_prev.as_u64(),
            initial_public_state.clone(),
        );

        let mut current_account_leaf_user1 = new_account_leaf_user1_first.clone();
        let current_account_leaf_user2 = prev_account_leaf_user2.clone();

        let block_number_second = BlockNumber::new(block_number_first.as_u64() + 1).unwrap();
        let tx_tree_root_second = Bytes32::rand(&mut rng);
        let block_second = Block::new(
            num_users,
            aggregator_id,
            &[1, 2],
            tx_tree_root_second,
            expected_deposit_hash_chain,
        )
        .unwrap();

        let send_proof_user1_second =
            send_tree_user1.prove(current_account_leaf_user1.index.into());
        let send_proof_user2_second =
            send_tree_user2.prove(current_account_leaf_user2.index.into());

        let prev_account_leaves_second = vec![
            current_account_leaf_user1.clone(),
            current_account_leaf_user2.clone(),
        ];
        let send_merkle_proofs_second: Vec<SendMerkleProof> = vec![
            send_proof_user1_second.clone(),
            send_proof_user2_second.clone(),
        ];

        let mut account_tree_for_proofs_second = account_tree.clone();
        let mut account_merkle_proofs_second = Vec::with_capacity(num_users as usize);
        for (i, &local_id) in block_second.local_ids.iter().enumerate() {
            let user_id = UserId::new(aggregator_id, local_id).unwrap();
            let proof = account_tree_for_proofs_second.prove(user_id.as_u64());
            account_merkle_proofs_second.push(proof);

            let prev_leaf = &prev_account_leaves_second[i];
            if prev_leaf.prev == block_number_second {
                continue;
            }

            let send_proof = &send_merkle_proofs_second[i];
            let new_send_leaf = SendLeaf {
                prev: prev_leaf.prev,
                cur: block_number_second,
                tx_tree_root: tx_tree_root_second,
            };
            let new_send_root = send_proof.get_root(&new_send_leaf, prev_leaf.index.into());
            let new_account_leaf = AccountLeaf {
                index: prev_leaf.index + 1,
                prev: block_number_second,
                send_tree_root: new_send_root,
            };
            account_tree_for_proofs_second.update(user_id.as_u64(), new_account_leaf);
        }

        let update_account_tree_second = UpdateAccountTree {
            prev_block_hash_chain: update_account_inputs_first.new_block_hash_chain,
            prev_account_tree_root: account_tree.get_root(),
            block_number: block_number_second,
            block: block_second.clone(),
            prev_account_leaves: prev_account_leaves_second.clone(),
            account_merkle_proofs: account_merkle_proofs_second.clone(),
            send_merkle_proofs: send_merkle_proofs_second.clone(),
        };
        let update_account_inputs_second = update_account_tree_second
            .to_public_inputs()
            .expect("second update account inputs");
        let update_account_proof_second = update_account_circuit
            .prove(&update_account_tree_second)
            .expect("second update account proof");

        let new_send_leaf_user1_second = SendLeaf {
            prev: current_account_leaf_user1.prev,
            cur: block_number_second,
            tx_tree_root: tx_tree_root_second,
        };
        let new_send_root_user1_second = send_proof_user1_second.get_root(
            &new_send_leaf_user1_second,
            current_account_leaf_user1.index.into(),
        );
        send_tree_user1.push(new_send_leaf_user1_second.clone());
        current_account_leaf_user1 = AccountLeaf {
            index: current_account_leaf_user1.index + 1,
            prev: block_number_second,
            send_tree_root: new_send_root_user1_second,
        };
        account_tree.update(user1.as_u64(), current_account_leaf_user1.clone());

        let prev_ext_public_state_second = expected_block_inputs_first.ext_public_state.clone();
        let prev_public_state_second = prev_ext_public_state_second.inner.clone();
        let public_state_merkle_proof_second =
            public_state_tree.prove(prev_public_state_second.block_number.as_u64());

        let witness_second = BlockStepWitness {
            initial_public_state: None,
            prev_block_chain_proof: Some(first_block_chain_proof.clone()),
            deposit_hash_chain_proof: None,
            num_users,
            update_account_proof: update_account_proof_second.clone(),
            public_state_merkle_proof: public_state_merkle_proof_second.clone(),
        };
        let expected_block_inputs_second = witness_second
            .to_public_inputs(&block_chain_vd, &update_account_vds, &deposit_chain_vd)
            .expect("second block inputs");
        assert_eq!(
            expected_block_inputs_second
                .ext_public_state
                .inner
                .block_number,
            block_number_second
        );
        assert_eq!(
            expected_block_inputs_second
                .ext_public_state
                .deposit_hash_chain,
            expected_deposit_hash_chain
        );
        assert_eq!(
            expected_block_inputs_second
                .ext_public_state
                .inner
                .deposit_tree_root,
            expected_deposit_tree_root
        );
        assert_eq!(
            expected_block_inputs_second
                .ext_public_state
                .inner
                .account_tree_root,
            update_account_inputs_second.new_account_tree_root
        );

        let block_step_proof_second = block_step_circuit
            .prove(
                &block_chain_vd,
                &update_account_vds,
                &deposit_chain_vd,
                &witness_second,
            )
            .expect("second block step proof");
        block_step_circuit
            .verify(block_step_proof_second.clone())
            .expect("second block step verification");
        let expected_block_inputs_second_fields = expected_block_inputs_second
            .to_u64_vec(&block_chain_common.config)
            .to_field_vec::<F>();
        assert_eq!(
            expected_block_inputs_second_fields.len(),
            block_chain_total_pis_len,
        );
        assert_eq!(
            block_step_proof_second.public_inputs,
            expected_block_inputs_second_fields
        );
    }
}
