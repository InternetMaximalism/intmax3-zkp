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
        sig_batch_pis::{SigBatchPublicInputs, SigBatchPublicInputsTarget},
        sig_merge_pis::{
            SigMergePublicInputs, SigMergePublicInputsError, SigMergePublicInputsTarget,
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
pub enum SigMergeStepError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Failed to prove: {0}")]
    FailedToProve(String),
    #[error("Public inputs error: {0}")]
    PublicInputsError(#[from] SigMergePublicInputsError),
}

/// Initial values for the first merge step.
pub struct SigMergeInitialValue {
    pub account_tree_root: PoseidonHashOut,
    pub block_number: BlockNumber,
    pub aggregator_id: u32,
    pub tx_tree_root: Bytes32,
}

/// Witness for a single merge step.
///
/// Each step absorbs one completed SigBatch proof. The batch must be "complete"
/// (current_user_local_id == 0, meaning no in-progress user).
///
/// The merge step:
/// 1. Verifies the batch proof is valid
/// 2. Checks batch is complete (current_user_local_id == 0)
/// 3. Checks ordering: prev_merge.last_user_id < batch.first_user_id
/// 4. Combines verified_users_hash: Poseidon(merge_hash || batch_hash)
/// 5. Accumulates verified_count
/// 6. Updates first_user_id / last_user_id range
pub struct SigMergeStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_value: Option<SigMergeInitialValue>,
    pub prev_merge_proof: Option<ProofWithPublicInputs<F, C, D>>,
    /// The completed batch proof to absorb.
    pub batch_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SigMergeStepWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        sig_merge_vd: &VerifierCircuitData<F, C, D>,
        sig_batch_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<SigMergePublicInputs<F, C, D>, SigMergeStepError> {
        let total_inputs =
            self.initial_value.is_some() as usize + self.prev_merge_proof.is_some() as usize;
        if total_inputs != 1 {
            return Err(SigMergeStepError::InvalidInput(
                "Exactly one of initial_value or prev_merge_proof must be provided".to_string(),
            ));
        }

        // Parse batch proof public inputs
        let batch_pis = SigBatchPublicInputs::<F, C, D>::from_u64_slice(
            &self.batch_proof.public_inputs.to_u64_vec(),
            &sig_batch_vd.common.config,
        )
        .map_err(|e| SigMergeStepError::InvalidInput(format!("Bad batch PIS: {}", e)))?;

        // Batch must be complete
        if batch_pis.current_user_local_id != 0 {
            return Err(SigMergeStepError::InvalidInput(
                "Batch proof is incomplete: current_user_local_id != 0".to_string(),
            ));
        }

        // Batch must have at least one verified user
        if batch_pis.verified_count == 0 {
            return Err(SigMergeStepError::InvalidInput(
                "Batch proof has no verified users".to_string(),
            ));
        }

        let prev_merge = if let Some(initial) = &self.initial_value {
            SigMergePublicInputs {
                account_tree_root: initial.account_tree_root,
                block_number: initial.block_number,
                aggregator_id: initial.aggregator_id,
                tx_tree_root: initial.tx_tree_root,
                verified_users_hash: PoseidonHashOut::default(),
                verified_count: 0,
                first_user_id: 0,
                last_user_id: 0,
                vd: sig_merge_vd.verifier_only.clone(),
            }
        } else {
            let prev_proof = self.prev_merge_proof.clone().expect("Checked above");
            SigMergePublicInputs::<F, C, D>::from_u64_slice(
                &prev_proof.public_inputs.to_u64_vec(),
                &sig_merge_vd.common.config,
            )?
        };

        // Check block data consistency
        if batch_pis.account_tree_root != prev_merge.account_tree_root {
            return Err(SigMergeStepError::InvalidInput(
                "account_tree_root mismatch between merge and batch".to_string(),
            ));
        }
        if batch_pis.block_number != prev_merge.block_number {
            return Err(SigMergeStepError::InvalidInput(
                "block_number mismatch".to_string(),
            ));
        }
        if batch_pis.hub_id() != prev_merge.hub_id() {
            return Err(SigMergeStepError::InvalidInput(
                "hub_id mismatch".to_string(),
            ));
        }
        if batch_pis.tx_tree_root != prev_merge.tx_tree_root {
            return Err(SigMergeStepError::InvalidInput(
                "tx_tree_root mismatch".to_string(),
            ));
        }

        // Ordering check: prev_merge.last_user_id < batch.first_user_id
        if prev_merge.last_user_id != 0 && batch_pis.first_user_id <= prev_merge.last_user_id {
            return Err(SigMergeStepError::InvalidInput(format!(
                "Batch user IDs must follow merge: batch.first={} <= merge.last={}",
                batch_pis.first_user_id, prev_merge.last_user_id
            )));
        }

        // Combine: new_hash = Poseidon(merge_hash || batch_hash)
        let new_verified_users_hash = PoseidonHashOut::hash_inputs_u64(
            &[
                prev_merge.verified_users_hash.to_u64_vec(),
                batch_pis.verified_users_hash.to_u64_vec(),
            ]
            .concat(),
        );

        let new_count = prev_merge.verified_count + batch_pis.verified_count;
        let first_user_id = if prev_merge.first_user_id == 0 {
            batch_pis.first_user_id
        } else {
            prev_merge.first_user_id
        };
        let last_user_id = batch_pis.last_user_id;

        Ok(SigMergePublicInputs {
            account_tree_root: prev_merge.account_tree_root,
            block_number: prev_merge.block_number,
            aggregator_id: prev_merge.hub_id(),
            tx_tree_root: prev_merge.tx_tree_root,
            verified_users_hash: new_verified_users_hash,
            verified_count: new_count,
            first_user_id,
            last_user_id,
            vd: prev_merge.vd,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SigMergeStepTarget<const D: usize> {
    pub is_initial: BoolTarget,
    pub initial_account_tree_root: PoseidonHashOutTarget,
    pub initial_block_number: BlockNumberTarget,
    pub initial_aggregator_id: Target,
    pub initial_tx_tree_root: Bytes32Target,
    pub prev_merge_proof: ProofWithPublicInputsTarget<D>,
    pub batch_proof: ProofWithPublicInputsTarget<D>,
    pub new_pis: SigMergePublicInputsTarget,
}

impl<const D: usize> SigMergeStepTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        sig_merge_cd: &CommonCircuitData<F, D>,
        sig_batch_vd: &VerifierCircuitData<F, C, D>,
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

        // ── Previous merge proof (conditional) ──
        let prev_merge_proof = builder.add_virtual_proof_with_pis(sig_merge_cd);
        let prev_merge_pis = SigMergePublicInputsTarget::from_pis(
            &prev_merge_proof.public_inputs,
            &sig_merge_cd.config,
        );
        conditionally_verify_proof::<F, C, D>(
            builder,
            not_initial,
            &prev_merge_proof,
            &prev_merge_pis.vd,
            sig_merge_cd,
        );
        let sig_merge_vd =
            builder.add_virtual_verifier_data(sig_merge_cd.config.fri_config.cap_height);
        conditionally_connect_vd(builder, not_initial, &prev_merge_pis.vd, &sig_merge_vd);

        // ── Batch proof (always verified) ──
        let batch_proof = add_proof_target_and_verify(sig_batch_vd, builder);
        let batch_pis = SigBatchPublicInputsTarget::from_pis(
            &batch_proof.public_inputs,
            &sig_batch_vd.common.config,
        );

        // ── Batch completeness: current_user_local_id == 0 ──
        let zero = builder.zero();
        let batch_complete = builder.is_equal(batch_pis.current_user_local_id, zero);
        let _true = builder._true();
        builder.connect(batch_complete.target, _true.target);

        // ── Batch verified_count > 0 ──
        let batch_has_users = builder.is_equal(batch_pis.verified_count, zero);
        let _false = builder._false();
        builder.connect(batch_has_users.target, _false.target);

        // ── Select previous merge state ──
        let zero_hash = PoseidonHashOutTarget::constant(builder, PoseidonHashOut::default());

        let prev_account_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            initial_account_tree_root.clone(),
            prev_merge_pis.account_tree_root.clone(),
        );
        let prev_block_number = builder.select(
            is_initial,
            initial_block_number.value,
            prev_merge_pis.block_number.value,
        );
        let prev_hub_id =
            builder.select(is_initial, initial_aggregator_id, prev_merge_pis.hub_id());
        let prev_tx_tree_root = Bytes32Target::select(
            builder,
            is_initial,
            initial_tx_tree_root.clone(),
            prev_merge_pis.tx_tree_root.clone(),
        );
        let prev_verified_users_hash = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            zero_hash,
            prev_merge_pis.verified_users_hash.clone(),
        );
        let prev_verified_count = builder.select(is_initial, zero, prev_merge_pis.verified_count);
        let prev_first_user_id = builder.select(is_initial, zero, prev_merge_pis.first_user_id);
        let prev_last_user_id = builder.select(is_initial, zero, prev_merge_pis.last_user_id);

        // ── Block data consistency: batch must match merge state ──
        prev_account_tree_root.conditional_assert_eq(
            builder,
            batch_pis.account_tree_root.clone(),
            _true,
        );
        builder.connect(prev_block_number, batch_pis.block_number.value);
        builder.connect(prev_hub_id, batch_pis.hub_id());
        for (a, b) in prev_tx_tree_root
            .to_vec()
            .iter()
            .zip(batch_pis.tx_tree_root.to_vec().iter())
        {
            builder.connect(*a, *b);
        }

        // ── Ordering: prev_last_user_id < batch.first_user_id ──
        let one = builder.one();
        let has_prev_users = builder.is_equal(prev_last_user_id, zero);
        let has_prev_users = builder.not(has_prev_users);
        let user_diff = builder.sub(batch_pis.first_user_id, prev_last_user_id);
        let user_diff_minus_one = builder.sub(user_diff, one);
        let order_check = builder.select(has_prev_users, user_diff_minus_one, zero);
        builder.range_check(order_check, 63);

        // ── Combine hashes: Poseidon(merge_hash || batch_hash) ──
        let hash_inputs: Vec<_> = prev_verified_users_hash
            .to_vec()
            .into_iter()
            .chain(batch_pis.verified_users_hash.to_vec())
            .collect();
        let new_verified_users_hash = PoseidonHashOutTarget::hash_inputs(builder, &hash_inputs);

        let new_verified_count = builder.add(prev_verified_count, batch_pis.verified_count);

        // first_user_id: set from batch on first merge
        let is_first_merge = builder.is_equal(prev_first_user_id, zero);
        let out_first_user_id =
            builder.select(is_first_merge, batch_pis.first_user_id, prev_first_user_id);

        // last_user_id: always from batch
        let out_last_user_id = batch_pis.last_user_id;

        // ── Output PIS ──
        let new_pis = SigMergePublicInputsTarget {
            account_tree_root: prev_account_tree_root,
            block_number: BlockNumberTarget::from_slice(&[prev_block_number]),
            aggregator_id: prev_hub_id,
            tx_tree_root: prev_tx_tree_root,
            verified_users_hash: new_verified_users_hash,
            verified_count: new_verified_count,
            first_user_id: out_first_user_id,
            last_user_id: out_last_user_id,
            vd: sig_merge_vd,
        };

        Self {
            is_initial,
            initial_account_tree_root,
            initial_block_number,
            initial_aggregator_id,
            initial_tx_tree_root,
            prev_merge_proof,
            batch_proof,
            new_pis,
        }
    }

    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &SigMergeStepWitness<F, C, D>,
        new_pis: &SigMergePublicInputs<F, C, D>,
        dummy_merge_proof: &ProofWithPublicInputs<F, C, D>,
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

        if let Some(proof) = &value.prev_merge_proof {
            witness.set_proof_with_pis_target(&self.prev_merge_proof, proof);
        } else {
            witness.set_proof_with_pis_target(&self.prev_merge_proof, dummy_merge_proof);
        }

        witness.set_proof_with_pis_target(&self.batch_proof, &value.batch_proof);
        self.new_pis.set_witness::<F, C, D, _>(witness, new_pis);
    }
}

pub struct SigMergeStepCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: SigMergeStepTarget<D>,
    pub public_inputs: SigMergePublicInputsTarget,
    pub dummy_merge_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> SigMergeStepCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        sig_merge_cd: &CommonCircuitData<F, D>,
        sig_batch_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = SigMergeStepTarget::new::<F, C>(&mut builder, sig_merge_cd, sig_batch_vd);
        let public_inputs = target.new_pis.clone();
        builder.register_public_inputs(&public_inputs.to_vec(&sig_merge_cd.config));
        let data = builder.build::<C>();
        let dummy_merge_proof = DummyProof::new(sig_merge_cd);
        Self {
            data,
            target,
            public_inputs,
            dummy_merge_proof: dummy_merge_proof.proof,
        }
    }

    pub fn prove(
        &self,
        sig_merge_vd: &VerifierCircuitData<F, C, D>,
        sig_batch_vd: &VerifierCircuitData<F, C, D>,
        witness: &SigMergeStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, SigMergeStepError> {
        let new_pis = witness.to_public_inputs(sig_merge_vd, sig_batch_vd)?;
        let mut pw = PartialWitness::<F>::new();
        self.target
            .set_witness(&mut pw, witness, &new_pis, &self.dummy_merge_proof);
        self.data
            .prove(pw)
            .map_err(|e| SigMergeStepError::FailedToProve(e.to_string()))
    }
}
