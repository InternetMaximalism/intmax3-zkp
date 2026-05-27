use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::validity::signature_aggregation::{
        account_apply_block_pis::{
            AccountApplyBlockPublicInputs, AccountApplyBlockPublicInputsTarget,
        },
        account_apply_pis::{
            AccountApplyPublicInputs, AccountApplyPublicInputsError, AccountApplyPublicInputsTarget,
        },
    },
    common::u63::{BlockNumber, BlockNumberTarget},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
    },
    utils::{
        conversion::ToU64,
        cyclic::conditionally_connect_vd,
        dummy::{DummyProof, conditionally_verify_proof},
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum AccountApplyStepError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Failed to prove: {0}")]
    FailedToProve(String),
    #[error("Public inputs error: {0}")]
    PublicInputsError(#[from] AccountApplyPublicInputsError),
}

/// Initial values for the first account apply step.
pub struct AccountApplyInitialValue {
    pub account_tree_root: PoseidonHashOut,
    pub block_number: BlockNumber,
    pub aggregator_id: u32,
    pub tx_tree_root: Bytes32,
}

/// Witness for a single account apply step.
///
/// Each step absorbs one AccountApplyBlock proof. The block proof represents
/// a flat (non-cyclic) circuit that processes a batch of users, updating the
/// account tree from `initial_account_tree_root` to `final_account_tree_root`.
///
/// The step:
/// 1. Verifies the block proof is valid
/// 2. Checks block has at least one user (user_count > 0)
/// 3. Chains account tree roots: prev.new_account_tree_root == block.initial_account_tree_root
/// 4. Checks ordering: prev.last_user_id < block.first_user_id
/// 5. Combines users_hash: Poseidon(prev_hash || block.users_hash)
/// 6. Accumulates verified_count
/// 7. Updates first_user_id / last_user_id range
pub struct AccountApplyStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_value: Option<AccountApplyInitialValue>,
    pub prev_apply_proof: Option<ProofWithPublicInputs<F, C, D>>,
    /// The AccountApplyBlock proof to absorb.
    pub block_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    AccountApplyStepWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        account_apply_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<AccountApplyPublicInputs<F, C, D>, AccountApplyStepError> {
        let total_inputs =
            self.initial_value.is_some() as usize + self.prev_apply_proof.is_some() as usize;
        if total_inputs != 1 {
            return Err(AccountApplyStepError::InvalidInput(
                "Exactly one of initial_value or prev_apply_proof must be provided".to_string(),
            ));
        }

        // Parse block proof public inputs (no config — flat circuit, no VD)
        let block_pis = AccountApplyBlockPublicInputs::from_u64_slice(
            &self.block_proof.public_inputs.to_u64_vec(),
        )
        .map_err(|e| AccountApplyStepError::InvalidInput(format!("Bad block PIS: {}", e)))?;

        // Block must have at least one user
        if block_pis.user_count == 0 {
            return Err(AccountApplyStepError::InvalidInput(
                "Block proof has no users: user_count == 0".to_string(),
            ));
        }

        let prev_apply = if let Some(initial) = &self.initial_value {
            AccountApplyPublicInputs {
                prev_account_tree_root: initial.account_tree_root,
                new_account_tree_root: initial.account_tree_root,
                block_number: initial.block_number,
                aggregator_id: initial.aggregator_id,
                tx_tree_root: initial.tx_tree_root,
                verified_users_hash: PoseidonHashOut::default(),
                verified_count: 0,
                first_user_id: 0,
                last_user_id: 0,
                vd: account_apply_vd.verifier_only.clone(),
            }
        } else {
            let prev_proof = self.prev_apply_proof.clone().expect("Checked above");
            AccountApplyPublicInputs::<F, C, D>::from_u64_slice(
                &prev_proof.public_inputs.to_u64_vec(),
                &account_apply_vd.common.config,
            )?
        };

        // Root chaining: prev.new_account_tree_root == block.initial_account_tree_root
        if prev_apply.new_account_tree_root != block_pis.initial_account_tree_root {
            return Err(AccountApplyStepError::InvalidInput(
                "account tree root chain mismatch: prev.new_account_tree_root != block.initial_account_tree_root".to_string(),
            ));
        }

        // Check block data consistency
        if block_pis.block_number != prev_apply.block_number {
            return Err(AccountApplyStepError::InvalidInput(
                "block_number mismatch".to_string(),
            ));
        }
        if block_pis.hub_id() != prev_apply.hub_id() {
            return Err(AccountApplyStepError::InvalidInput(
                "hub_id mismatch".to_string(),
            ));
        }
        if block_pis.tx_tree_root != prev_apply.tx_tree_root {
            return Err(AccountApplyStepError::InvalidInput(
                "tx_tree_root mismatch".to_string(),
            ));
        }

        // Ordering check: prev_apply.last_user_id < block.first_user_id
        if prev_apply.last_user_id != 0 && block_pis.first_user_id <= prev_apply.last_user_id {
            return Err(AccountApplyStepError::InvalidInput(format!(
                "Block user IDs must follow previous: block.first={} <= prev.last={}",
                block_pis.first_user_id, prev_apply.last_user_id
            )));
        }

        // Combine: new_hash = Poseidon(prev_hash || block.users_hash)
        let new_verified_users_hash = PoseidonHashOut::hash_inputs_u64(
            &[
                prev_apply.verified_users_hash.to_u64_vec(),
                block_pis.users_hash.to_u64_vec(),
            ]
            .concat(),
        );

        let new_count = prev_apply.verified_count + block_pis.user_count;
        let first_user_id = if prev_apply.first_user_id == 0 {
            block_pis.first_user_id
        } else {
            prev_apply.first_user_id
        };
        let last_user_id = block_pis.last_user_id;

        Ok(AccountApplyPublicInputs {
            prev_account_tree_root: prev_apply.prev_account_tree_root,
            new_account_tree_root: block_pis.final_account_tree_root,
            block_number: prev_apply.block_number,
            aggregator_id: prev_apply.hub_id(),
            tx_tree_root: prev_apply.tx_tree_root,
            verified_users_hash: new_verified_users_hash,
            verified_count: new_count,
            first_user_id,
            last_user_id,
            vd: prev_apply.vd,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AccountApplyStepTarget<const D: usize> {
    pub is_initial: BoolTarget,
    pub initial_account_tree_root: PoseidonHashOutTarget,
    pub initial_block_number: BlockNumberTarget,
    pub initial_aggregator_id: Target,
    pub initial_tx_tree_root: Bytes32Target,
    pub prev_apply_proof: ProofWithPublicInputsTarget<D>,
    pub block_proof: ProofWithPublicInputsTarget<D>,
    pub new_pis: AccountApplyPublicInputsTarget,
}

impl<const D: usize> AccountApplyStepTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        account_apply_cd: &CommonCircuitData<F, D>,
        account_apply_block_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let is_initial = builder.add_virtual_bool_target_safe();
        let not_initial = builder.not(is_initial);

        // Initial values
        let initial_account_tree_root = PoseidonHashOutTarget::new(builder);
        let initial_block_number = BlockNumberTarget::new(builder, true);
        let initial_aggregator_id = builder.add_virtual_target();
        let initial_tx_tree_root = Bytes32Target::new::<F, D>(builder, true);

        // ── Previous apply proof (conditional) ──
        let prev_apply_proof = builder.add_virtual_proof_with_pis(account_apply_cd);
        let prev_apply_pis = AccountApplyPublicInputsTarget::from_pis(
            &prev_apply_proof.public_inputs,
            &account_apply_cd.config,
        );
        conditionally_verify_proof::<F, C, D>(
            builder,
            not_initial,
            &prev_apply_proof,
            &prev_apply_pis.vd,
            account_apply_cd,
        );
        let account_apply_vd =
            builder.add_virtual_verifier_data(account_apply_cd.config.fri_config.cap_height);
        conditionally_connect_vd(builder, not_initial, &prev_apply_pis.vd, &account_apply_vd);

        // ── Block proof (always verified, flat circuit) ──
        let block_proof = add_proof_target_and_verify(account_apply_block_vd, builder);
        let block_pis = AccountApplyBlockPublicInputsTarget::from_pis(&block_proof.public_inputs);

        // ── Block user_count > 0 ──
        let zero = builder.zero();
        let block_has_users = builder.is_equal(block_pis.user_count, zero);
        let _false = builder._false();
        builder.connect(block_has_users.target, _false.target);

        // ── Select previous apply state ──
        let zero_hash = PoseidonHashOutTarget::constant(builder, PoseidonHashOut::default());

        // For the initial case, new_account_tree_root starts as the initial root
        let prev_new_account_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            initial_account_tree_root.clone(),
            prev_apply_pis.new_account_tree_root.clone(),
        );
        // prev_account_tree_root preserves the FIRST root
        let prev_prev_account_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            initial_account_tree_root.clone(),
            prev_apply_pis.prev_account_tree_root.clone(),
        );
        let prev_block_number = builder.select(
            is_initial,
            initial_block_number.value,
            prev_apply_pis.block_number.value,
        );
        let prev_hub_id =
            builder.select(is_initial, initial_aggregator_id, prev_apply_pis.hub_id());
        let prev_tx_tree_root = Bytes32Target::select(
            builder,
            is_initial,
            initial_tx_tree_root.clone(),
            prev_apply_pis.tx_tree_root.clone(),
        );
        let prev_verified_users_hash = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            zero_hash,
            prev_apply_pis.verified_users_hash.clone(),
        );
        let prev_verified_count = builder.select(is_initial, zero, prev_apply_pis.verified_count);
        let prev_first_user_id = builder.select(is_initial, zero, prev_apply_pis.first_user_id);
        let prev_last_user_id = builder.select(is_initial, zero, prev_apply_pis.last_user_id);

        // ── Root chaining: prev.new_account_tree_root == block.initial_account_tree_root ──
        let _true = builder._true();
        prev_new_account_tree_root.conditional_assert_eq(
            builder,
            block_pis.initial_account_tree_root.clone(),
            _true,
        );

        // ── Block data consistency ──
        builder.connect(prev_block_number, block_pis.block_number.value);
        builder.connect(prev_hub_id, block_pis.hub_id());
        for (a, b) in prev_tx_tree_root
            .to_vec()
            .iter()
            .zip(block_pis.tx_tree_root.to_vec().iter())
        {
            builder.connect(*a, *b);
        }

        // ── Ordering: prev_last_user_id < block.first_user_id ──
        let one = builder.one();
        let has_prev_users = builder.is_equal(prev_last_user_id, zero);
        let has_prev_users = builder.not(has_prev_users);
        let user_diff = builder.sub(block_pis.first_user_id, prev_last_user_id);
        let user_diff_minus_one = builder.sub(user_diff, one);
        let order_check = builder.select(has_prev_users, user_diff_minus_one, zero);
        builder.range_check(order_check, 63);

        // ── Combine hashes: Poseidon(prev_hash || block.users_hash) ──
        let hash_inputs: Vec<_> = prev_verified_users_hash
            .to_vec()
            .into_iter()
            .chain(block_pis.users_hash.to_vec())
            .collect();
        let new_verified_users_hash = PoseidonHashOutTarget::hash_inputs(builder, &hash_inputs);

        let new_verified_count = builder.add(prev_verified_count, block_pis.user_count);

        // first_user_id: set from block on first step
        let is_first_step = builder.is_equal(prev_first_user_id, zero);
        let out_first_user_id =
            builder.select(is_first_step, block_pis.first_user_id, prev_first_user_id);

        // last_user_id: always from block
        let out_last_user_id = block_pis.last_user_id;

        // ── Output PIS ──
        let new_pis = AccountApplyPublicInputsTarget {
            prev_account_tree_root: prev_prev_account_tree_root,
            new_account_tree_root: block_pis.final_account_tree_root,
            block_number: BlockNumberTarget::from_slice(&[prev_block_number]),
            aggregator_id: prev_hub_id,
            tx_tree_root: prev_tx_tree_root,
            verified_users_hash: new_verified_users_hash,
            verified_count: new_verified_count,
            first_user_id: out_first_user_id,
            last_user_id: out_last_user_id,
            vd: account_apply_vd,
        };

        Self {
            is_initial,
            initial_account_tree_root,
            initial_block_number,
            initial_aggregator_id,
            initial_tx_tree_root,
            prev_apply_proof,
            block_proof,
            new_pis,
        }
    }

    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &AccountApplyStepWitness<F, C, D>,
        new_pis: &AccountApplyPublicInputs<F, C, D>,
        dummy_apply_proof: &ProofWithPublicInputs<F, C, D>,
    ) where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        let is_initial = value.initial_value.is_some();
        witness.set_bool_target(self.is_initial, is_initial);

        if let Some(initial) = &value.initial_value {
            self.initial_account_tree_root
                .set_witness(witness, initial.account_tree_root);
            self.initial_block_number
                .set_witness(witness, initial.block_number);
            witness.set_target(
                self.initial_aggregator_id,
                F::from_canonical_u64(initial.aggregator_id as u64),
            );
            self.initial_tx_tree_root
                .set_witness(witness, initial.tx_tree_root);
        } else {
            self.initial_account_tree_root
                .set_witness(witness, PoseidonHashOut::default());
            self.initial_block_number
                .set_witness(witness, BlockNumber::default());
            witness.set_target(self.initial_aggregator_id, F::ZERO);
            self.initial_tx_tree_root
                .set_witness(witness, Bytes32::default());
        }

        if let Some(proof) = &value.prev_apply_proof {
            witness.set_proof_with_pis_target(&self.prev_apply_proof, proof);
        } else {
            witness.set_proof_with_pis_target(&self.prev_apply_proof, dummy_apply_proof);
        }

        witness.set_proof_with_pis_target(&self.block_proof, &value.block_proof);
        self.new_pis.set_witness::<F, C, D, _>(witness, new_pis);
    }
}

pub struct AccountApplyStepCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: AccountApplyStepTarget<D>,
    pub public_inputs: AccountApplyPublicInputsTarget,
    pub dummy_apply_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> AccountApplyStepCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        account_apply_cd: &CommonCircuitData<F, D>,
        account_apply_block_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = AccountApplyStepTarget::new::<F, C>(
            &mut builder,
            account_apply_cd,
            account_apply_block_vd,
        );
        let public_inputs = target.new_pis.clone();
        builder.register_public_inputs(&public_inputs.to_vec(&account_apply_cd.config));
        let data = builder.build::<C>();
        let dummy_apply_proof = DummyProof::new(account_apply_cd);
        Self {
            data,
            target,
            public_inputs,
            dummy_apply_proof: dummy_apply_proof.proof,
        }
    }

    pub fn prove(
        &self,
        account_apply_vd: &VerifierCircuitData<F, C, D>,
        witness: &AccountApplyStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, AccountApplyStepError> {
        let new_pis = witness.to_public_inputs(account_apply_vd)?;
        let mut pw = PartialWitness::<F>::new();
        self.target
            .set_witness(&mut pw, witness, &new_pis, &self.dummy_apply_proof);
        self.data
            .prove(pw)
            .map_err(|e| AccountApplyStepError::FailedToProve(e.to_string()))
    }
}
