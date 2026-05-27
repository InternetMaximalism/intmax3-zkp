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
use sphincsplus_circuits::verification::{SpxVerifyWitness, verify_circuit};

use crate::{
    circuits::validity::{
        block_hash_chain::sphincs_sig::{
            SPX_AUTH_GL_LEN, SPX_D, SPX_FORS_SIG_GL_LEN, SPX_WOTS_SIG_GL_LEN, SpxSigTargets,
            SpxSigWitness,
        },
        signature_aggregation::sig_batch_pis::{
            SigBatchPublicInputs, SigBatchPublicInputsError, SigBatchPublicInputsTarget,
        },
    },
    common::{
        key_set::{KeySetMerkleProof, KeySetMerkleProofTarget, PkLeaf, PkLeafTarget},
        trees::account_tree::{
            AccountLeaf, AccountLeafTarget, AccountMerkleProof, AccountMerkleProofTarget,
        },
        u63::{BlockNumber, BlockNumberTarget},
        user_id::{UserId, UserIdTarget},
    },
    constants::{ACCOUNT_TREE_HEIGHT, KEY_SET_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
    },
    utils::{
        conversion::ToU64,
        cyclic::conditionally_connect_vd,
        dummy::{DummyProof, conditionally_verify_proof},
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum SigBatchStepError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    #[error("Failed to prove: {0}")]
    FailedToProve(String),
    #[error("Merkle proof error: {0}")]
    MerkleProofError(String),
    #[error("Public inputs error: {0}")]
    PublicInputsError(#[from] SigBatchPublicInputsError),
}

/// Initial values for the first step in a batch.
pub struct SigBatchInitialValue {
    pub account_tree_root: PoseidonHashOut,
    pub block_number: BlockNumber,
    pub aggregator_id: u32,
    pub tx_tree_root: Bytes32,
}

/// Witness for a single batch step.
///
/// Two modes:
/// - `is_finalize = false`: Verify one SPHINCS+ signature for the current user.
/// - `is_finalize = true`: Finalize user (check threshold, record in verified_users_hash). NO
///   account tree update — this is the key difference from SigAggStep.
pub struct SigBatchStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_value: Option<SigBatchInitialValue>,
    pub prev_batch_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub is_finalize: bool,
    pub block_number: BlockNumber,
    pub aggregator_id: u32,
    pub tx_tree_root: Bytes32,
    pub new_user_local_id: u32,
    /// Account leaf for new user setup (read-only membership verification).
    pub prev_account_leaf: AccountLeaf,
    pub account_merkle_proof: AccountMerkleProof,
    /// Key set membership proof (sig_verify mode only).
    pub pk_index: u32,
    pub key_set_merkle_proof: KeySetMerkleProof,
    /// SPHINCS+ signature (sig_verify mode only).
    pub sig_witness: SpxSigWitness,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SigBatchStepWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        sig_batch_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<SigBatchPublicInputs<F, C, D>, SigBatchStepError> {
        let total_inputs =
            self.initial_value.is_some() as usize + self.prev_batch_proof.is_some() as usize;
        if total_inputs != 1 {
            return Err(SigBatchStepError::InvalidInput(
                "Exactly one of initial_value or prev_batch_proof must be provided".to_string(),
            ));
        }

        let prev_pis = if let Some(initial) = &self.initial_value {
            SigBatchPublicInputs {
                account_tree_root: initial.account_tree_root,
                block_number: initial.block_number,
                aggregator_id: initial.aggregator_id,
                tx_tree_root: initial.tx_tree_root,
                current_user_local_id: 0,
                current_user_pk_set_root: PoseidonHashOut::default(),
                current_user_threshold: 0,
                current_user_sigs_verified: 0,
                current_user_last_pk_index: 0,
                verified_users_hash: PoseidonHashOut::default(),
                verified_count: 0,
                first_user_id: 0,
                last_user_id: 0,
                vd: sig_batch_vd.verifier_only.clone(),
            }
        } else {
            let prev_proof = self.prev_batch_proof.clone().expect("Checked above");
            SigBatchPublicInputs::<F, C, D>::from_u64_slice(
                &prev_proof.public_inputs.to_u64_vec(),
                &sig_batch_vd.common.config,
            )?
        };

        if self.is_finalize {
            // Finalize mode: check threshold met, record user in hash chain.
            // NO account tree update.
            if prev_pis.current_user_local_id == 0 {
                return Err(SigBatchStepError::InvalidInput(
                    "Cannot finalize: no current user".to_string(),
                ));
            }
            if prev_pis.current_user_sigs_verified < prev_pis.current_user_threshold {
                return Err(SigBatchStepError::InvalidInput(format!(
                    "Threshold not met: {} < {}",
                    prev_pis.current_user_sigs_verified, prev_pis.current_user_threshold
                )));
            }

            let user_id = UserId::new(prev_pis.hub_id(), prev_pis.current_user_local_id)
                .map_err(|e| SigBatchStepError::InvalidInput(e.to_string()))?;

            // Update verified_users_hash
            let new_verified_users_hash = PoseidonHashOut::hash_inputs_u64(
                &[
                    prev_pis.verified_users_hash.to_u64_vec(),
                    vec![user_id.as_u64()],
                ]
                .concat(),
            );

            let new_count = prev_pis.verified_count + 1;
            let first_user_id = if prev_pis.first_user_id == 0 {
                user_id.as_u64()
            } else {
                prev_pis.first_user_id
            };
            let last_user_id = user_id.as_u64();

            // Enforce strict ordering: last finalized user_id must increase
            if prev_pis.last_user_id != 0 && user_id.as_u64() <= prev_pis.last_user_id {
                return Err(SigBatchStepError::InvalidInput(format!(
                    "User IDs must be strictly increasing: {} <= {}",
                    user_id.as_u64(),
                    prev_pis.last_user_id
                )));
            }

            Ok(SigBatchPublicInputs {
                account_tree_root: prev_pis.account_tree_root,
                block_number: prev_pis.block_number,
                aggregator_id: prev_pis.hub_id(),
                tx_tree_root: prev_pis.tx_tree_root,
                current_user_local_id: 0,
                current_user_pk_set_root: PoseidonHashOut::default(),
                current_user_threshold: 0,
                current_user_sigs_verified: 0,
                current_user_last_pk_index: 0,
                verified_users_hash: new_verified_users_hash,
                verified_count: new_count,
                first_user_id,
                last_user_id,
                vd: prev_pis.vd,
            })
        } else {
            // Sig verify mode (same as SigAggStep but no tree update)
            let is_new_user = prev_pis.current_user_local_id == 0;
            let (local_id, pk_set_root, threshold, sigs_verified, last_pk_index) = if is_new_user {
                if self.new_user_local_id == 0 {
                    return Err(SigBatchStepError::InvalidInput(
                        "new_user_local_id must be non-zero when starting a new user".to_string(),
                    ));
                }
                let user_id = UserId::new(prev_pis.hub_id(), self.new_user_local_id)
                    .map_err(|e| SigBatchStepError::InvalidInput(e.to_string()))?;

                // Verify account leaf membership (read-only)
                self.account_merkle_proof
                    .verify(
                        &self.prev_account_leaf,
                        user_id.as_u64(),
                        prev_pis.account_tree_root,
                    )
                    .map_err(|e| SigBatchStepError::MerkleProofError(e.to_string()))?;

                (
                    self.new_user_local_id,
                    self.prev_account_leaf.pk_set_root,
                    self.prev_account_leaf.threshold,
                    0u32,
                    0u32,
                )
            } else {
                (
                    prev_pis.current_user_local_id,
                    prev_pis.current_user_pk_set_root,
                    prev_pis.current_user_threshold,
                    prev_pis.current_user_sigs_verified,
                    prev_pis.current_user_last_pk_index,
                )
            };

            // Verify pk membership in key set
            let pk_leaf = PkLeaf::new(PoseidonHashOut::hash_inputs_u64(&[
                self.sig_witness.pk_gl[0],
                self.sig_witness.pk_gl[1],
                self.sig_witness.pk_gl[2],
                self.sig_witness.pk_gl[3],
            ]));
            self.key_set_merkle_proof
                .verify(&pk_leaf, self.pk_index as u64, pk_set_root)
                .map_err(|e| {
                    SigBatchStepError::MerkleProofError(format!(
                        "Key set membership proof failed: {}",
                        e
                    ))
                })?;

            // Check pk_index ordering
            if sigs_verified > 0 && self.pk_index <= last_pk_index {
                return Err(SigBatchStepError::InvalidInput(format!(
                    "pk_index must be strictly increasing: {} <= {}",
                    self.pk_index, last_pk_index
                )));
            }

            Ok(SigBatchPublicInputs {
                account_tree_root: prev_pis.account_tree_root,
                block_number: prev_pis.block_number,
                aggregator_id: prev_pis.hub_id(),
                tx_tree_root: prev_pis.tx_tree_root,
                current_user_local_id: local_id,
                current_user_pk_set_root: pk_set_root,
                current_user_threshold: threshold,
                current_user_sigs_verified: sigs_verified + 1,
                current_user_last_pk_index: self.pk_index,
                verified_users_hash: prev_pis.verified_users_hash,
                verified_count: prev_pis.verified_count,
                first_user_id: prev_pis.first_user_id,
                last_user_id: prev_pis.last_user_id,
                vd: prev_pis.vd,
            })
        }
    }
}

#[derive(Clone, Debug)]
pub struct SigBatchStepTarget<const D: usize> {
    pub is_initial: BoolTarget,
    pub is_finalize: BoolTarget,
    pub initial_account_tree_root: PoseidonHashOutTarget,
    pub initial_block_number: BlockNumberTarget,
    pub initial_aggregator_id: Target,
    pub initial_tx_tree_root: Bytes32Target,
    pub prev_batch_proof: ProofWithPublicInputsTarget<D>,
    pub block_number: BlockNumberTarget,
    pub aggregator_id: Target,
    pub tx_tree_root: Bytes32Target,
    pub new_user_local_id: Target,
    pub prev_account_leaf: AccountLeafTarget,
    pub account_merkle_proof: AccountMerkleProofTarget,
    pub pk_index: Target,
    pub key_set_merkle_proof: KeySetMerkleProofTarget,
    pub spx_sig_targets: SpxSigTargets,
    pub new_pis: SigBatchPublicInputsTarget,
}

impl<const D: usize> SigBatchStepTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        sig_batch_cd: &CommonCircuitData<F, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let is_initial = builder.add_virtual_bool_target_safe();
        let not_initial = builder.not(is_initial);
        let is_finalize = builder.add_virtual_bool_target_safe();
        let not_finalize = builder.not(is_finalize);

        // Initial values
        let initial_account_tree_root = PoseidonHashOutTarget::new(builder);
        let initial_block_number = BlockNumberTarget::new(builder, true);
        let initial_aggregator_id = builder.add_virtual_target();
        let initial_tx_tree_root = Bytes32Target::new::<F, D>(builder, true);

        let block_number = BlockNumberTarget::new(builder, true);
        let aggregator_id = builder.add_virtual_target();
        let tx_tree_root = Bytes32Target::new::<F, D>(builder, true);

        let new_user_local_id = builder.add_virtual_target();
        let prev_account_leaf = AccountLeafTarget::new(builder, true);
        let account_merkle_proof = AccountMerkleProofTarget::new(builder, ACCOUNT_TREE_HEIGHT);
        let pk_index = builder.add_virtual_target();
        builder.range_check(pk_index, KEY_SET_TREE_HEIGHT);
        let key_set_merkle_proof = KeySetMerkleProofTarget::new(builder, KEY_SET_TREE_HEIGHT);

        // SPHINCS+ signature targets
        let pub_seed_gl: [_; 2] = std::array::from_fn(|_| builder.add_virtual_target());
        let pub_root_gl: [_; 2] = std::array::from_fn(|_| builder.add_virtual_target());
        let r_gl: [_; 2] = std::array::from_fn(|_| builder.add_virtual_target());
        let fors_sig_gl = builder.add_virtual_targets(SPX_FORS_SIG_GL_LEN);
        let ht_sig_gls: Vec<Vec<_>> = (0..SPX_D)
            .map(|_| builder.add_virtual_targets(SPX_WOTS_SIG_GL_LEN))
            .collect();
        let ht_auth_gls: Vec<Vec<_>> = (0..SPX_D)
            .map(|_| builder.add_virtual_targets(SPX_AUTH_GL_LEN))
            .collect();

        // ── Conditional prev proof verification ──
        let prev_batch_proof = builder.add_virtual_proof_with_pis(sig_batch_cd);
        let prev_pis = SigBatchPublicInputsTarget::from_pis(
            &prev_batch_proof.public_inputs,
            &sig_batch_cd.config,
        );
        conditionally_verify_proof::<F, C, D>(
            builder,
            not_initial,
            &prev_batch_proof,
            &prev_pis.vd,
            sig_batch_cd,
        );
        let sig_batch_vd =
            builder.add_virtual_verifier_data(sig_batch_cd.config.fri_config.cap_height);
        conditionally_connect_vd(builder, not_initial, &prev_pis.vd, &sig_batch_vd);

        // ── Select previous state ──
        let zero = builder.zero();
        let zero_hash = PoseidonHashOutTarget::constant(builder, PoseidonHashOut::default());

        let prev_account_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            initial_account_tree_root.clone(),
            prev_pis.account_tree_root.clone(),
        );

        // Block data consistency
        builder.conditional_assert_eq(
            not_initial.target,
            prev_pis.block_number.value,
            block_number.value,
        );
        builder.conditional_assert_eq(not_initial.target, prev_pis.hub_id(), aggregator_id);
        for (a, b) in prev_pis
            .tx_tree_root
            .to_vec()
            .iter()
            .zip(tx_tree_root.to_vec().iter())
        {
            builder.conditional_assert_eq(not_initial.target, *a, *b);
        }

        let sel_hub_id = builder.select(is_initial, initial_aggregator_id, aggregator_id);
        let sel_tx_tree_root = Bytes32Target::select(
            builder,
            is_initial,
            initial_tx_tree_root.clone(),
            tx_tree_root.clone(),
        );

        // Previous user state
        let prev_current_user_local_id =
            builder.select(is_initial, zero, prev_pis.current_user_local_id);
        let prev_current_user_pk_set_root = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            zero_hash.clone(),
            prev_pis.current_user_pk_set_root.clone(),
        );
        let prev_current_user_threshold =
            builder.select(is_initial, zero, prev_pis.current_user_threshold);
        let prev_current_user_sigs_verified =
            builder.select(is_initial, zero, prev_pis.current_user_sigs_verified);
        let prev_current_user_last_pk_index =
            builder.select(is_initial, zero, prev_pis.current_user_last_pk_index);
        let prev_verified_users_hash = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            zero_hash.clone(),
            prev_pis.verified_users_hash.clone(),
        );
        let prev_verified_count = builder.select(is_initial, zero, prev_pis.verified_count);
        let prev_first_user_id = builder.select(is_initial, zero, prev_pis.first_user_id);
        let prev_last_user_id = builder.select(is_initial, zero, prev_pis.last_user_id);

        // ── is_new_user: current_user_local_id == 0 AND not_finalize ──
        let is_no_current_user = builder.is_equal(prev_current_user_local_id, zero);
        let is_new_user = builder.and(is_no_current_user, not_finalize);

        // ── New user setup: verify account leaf (read-only) ──
        let user_id_for_new =
            UserIdTarget::from_parts(builder, sel_hub_id, new_user_local_id, true).value;
        let leaf_root_new =
            account_merkle_proof.get_root::<F, C, D>(builder, &prev_account_leaf, user_id_for_new);
        prev_account_tree_root.conditional_assert_eq(builder, leaf_root_new, is_new_user);

        // Select current user state
        let cur_local_id =
            builder.select(is_new_user, new_user_local_id, prev_current_user_local_id);
        let cur_pk_set_root = PoseidonHashOutTarget::select(
            builder,
            is_new_user,
            prev_account_leaf.pk_set_root.clone(),
            prev_current_user_pk_set_root,
        );
        let cur_threshold = builder.select(
            is_new_user,
            prev_account_leaf.threshold,
            prev_current_user_threshold,
        );
        let cur_sigs_verified = builder.select(is_new_user, zero, prev_current_user_sigs_verified);
        let cur_last_pk_index = builder.select(is_new_user, zero, prev_current_user_last_pk_index);

        // ── Signature verification (conditional on not_finalize) ──
        let pk_inputs: Vec<_> = [pub_seed_gl.as_slice(), pub_root_gl.as_slice()].concat();
        let computed_pk_hash = PoseidonHashOutTarget::hash_inputs(builder, &pk_inputs);

        let pk_leaf_target = PkLeafTarget {
            pk_hash: computed_pk_hash.clone(),
        };
        let key_set_root_from_proof =
            key_set_merkle_proof.get_root::<F, C, D>(builder, &pk_leaf_target, pk_index);
        cur_pk_set_root.conditional_assert_eq(builder, key_set_root_from_proof, not_finalize);

        // Message: [block_number, hub_id, account_no, tx_tree_root×8]
        let msg_gl: Vec<_> = std::iter::once(block_number.value)
            .chain(std::iter::once(sel_hub_id))
            .chain(std::iter::once(cur_local_id))
            .chain(sel_tx_tree_root.to_vec())
            .collect();

        let pk_gl: Vec<_> = [pub_seed_gl.as_slice(), pub_root_gl.as_slice()].concat();
        let spx_witness = SpxVerifyWitness {
            pub_seed_gl,
            pub_root_gl,
            r_gl,
            pk_gl,
            msg_gl,
            fors_sig_gl: fors_sig_gl.clone(),
            ht_sig_gl: ht_sig_gls.clone(),
            ht_auth_gl: ht_auth_gls.clone(),
        };
        let computed_root = verify_circuit(builder, &spx_witness);

        builder.conditional_assert_eq(not_finalize.target, computed_root[0], pub_root_gl[0]);
        builder.conditional_assert_eq(not_finalize.target, computed_root[1], pub_root_gl[1]);

        // pk_index ordering check
        let is_zero_sigs = builder.is_equal(cur_sigs_verified, zero);
        let has_prev_sig = builder.not(is_zero_sigs);
        let should_check_order = builder.and(has_prev_sig, not_finalize);
        let one = builder.one();
        let diff = builder.sub(pk_index, cur_last_pk_index);
        let diff_minus_one = builder.sub(diff, one);
        let check_val = builder.select(should_check_order, diff_minus_one, zero);
        builder.range_check(check_val, KEY_SET_TREE_HEIGHT);

        let new_sigs_verified_sig = builder.add_const(cur_sigs_verified, F::ONE);

        // ── Finalization: check threshold, record user, NO tree update ──
        let is_zero_user = builder.is_equal(prev_current_user_local_id, zero);
        let has_current_user = builder.not(is_zero_user);
        let finalize_check = builder.and(is_finalize, has_current_user);
        builder.conditional_assert_eq(
            is_finalize.target,
            finalize_check.target,
            is_finalize.target,
        );

        // sigs_verified >= threshold
        let sig_surplus = builder.sub(prev_current_user_sigs_verified, prev_current_user_threshold);
        let sig_check_val = builder.select(is_finalize, sig_surplus, zero);
        builder.range_check(sig_check_val, 32);

        // Compute user_id for finalization
        let user_id_for_finalize =
            UserIdTarget::from_parts(builder, sel_hub_id, prev_current_user_local_id, true).value;

        // Update verified_users_hash: Poseidon(prev || user_id)
        let hash_inputs: Vec<_> = prev_verified_users_hash
            .to_vec()
            .into_iter()
            .chain(std::iter::once(user_id_for_finalize))
            .collect();
        let new_verified_users_hash = PoseidonHashOutTarget::hash_inputs(builder, &hash_inputs);
        let out_verified_users_hash = PoseidonHashOutTarget::select(
            builder,
            is_finalize,
            new_verified_users_hash,
            prev_verified_users_hash,
        );

        let one_target = builder.one();
        let new_verified_count = builder.add(prev_verified_count, one_target);
        let out_verified_count =
            builder.select(is_finalize, new_verified_count, prev_verified_count);

        // first_user_id: set on first finalize only
        let is_first_finalize_zero = builder.is_equal(prev_first_user_id, zero);
        let is_first_finalize = builder.and(is_finalize, is_first_finalize_zero);
        let out_first_user_id =
            builder.select(is_first_finalize, user_id_for_finalize, prev_first_user_id);

        // last_user_id: updated on every finalize
        let out_last_user_id = builder.select(is_finalize, user_id_for_finalize, prev_last_user_id);

        // Ordering: user_id > prev_last_user_id (when prev_last_user_id != 0)
        let is_prev_last_zero = builder.is_equal(prev_last_user_id, zero);
        let has_prev_finalized = builder.not(is_prev_last_zero);
        let should_check_user_order = builder.and(is_finalize, has_prev_finalized);
        let user_diff = builder.sub(user_id_for_finalize, prev_last_user_id);
        let user_diff_minus_one = builder.sub(user_diff, one);
        let user_order_check = builder.select(should_check_user_order, user_diff_minus_one, zero);
        builder.range_check(user_order_check, 63);

        // ── Output ──
        let out_current_user_local_id = builder.select(is_finalize, zero, cur_local_id);
        let out_current_user_pk_set_root =
            PoseidonHashOutTarget::select(builder, is_finalize, zero_hash.clone(), cur_pk_set_root);
        let out_current_user_threshold = builder.select(is_finalize, zero, cur_threshold);
        let out_current_user_sigs_verified =
            builder.select(is_finalize, zero, new_sigs_verified_sig);
        let out_current_user_last_pk_index = builder.select(is_finalize, zero, pk_index);

        let new_pis = SigBatchPublicInputsTarget {
            account_tree_root: prev_account_tree_root,
            block_number: block_number.clone(),
            aggregator_id: sel_hub_id,
            tx_tree_root: sel_tx_tree_root,
            current_user_local_id: out_current_user_local_id,
            current_user_pk_set_root: out_current_user_pk_set_root,
            current_user_threshold: out_current_user_threshold,
            current_user_sigs_verified: out_current_user_sigs_verified,
            current_user_last_pk_index: out_current_user_last_pk_index,
            verified_users_hash: out_verified_users_hash,
            verified_count: out_verified_count,
            first_user_id: out_first_user_id,
            last_user_id: out_last_user_id,
            vd: sig_batch_vd,
        };

        let spx_sig_targets = SpxSigTargets {
            pub_seed_gl,
            pub_root_gl,
            r_gl,
            fors_sig_gl,
            ht_sig_gls,
            ht_auth_gls,
        };

        Self {
            is_initial,
            is_finalize,
            initial_account_tree_root,
            initial_block_number,
            initial_aggregator_id,
            initial_tx_tree_root,
            prev_batch_proof,
            block_number,
            aggregator_id,
            tx_tree_root,
            new_user_local_id,
            prev_account_leaf,
            account_merkle_proof,
            pk_index,
            key_set_merkle_proof,
            spx_sig_targets,
            new_pis,
        }
    }

    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &SigBatchStepWitness<F, C, D>,
        new_pis: &SigBatchPublicInputs<F, C, D>,
        dummy_proof: &ProofWithPublicInputs<F, C, D>,
    ) where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        let is_initial = value.initial_value.is_some();
        witness.set_bool_target(self.is_initial, is_initial);
        witness.set_bool_target(self.is_finalize, value.is_finalize);

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

        if let Some(proof) = &value.prev_batch_proof {
            witness.set_proof_with_pis_target(&self.prev_batch_proof, proof);
        } else {
            witness.set_proof_with_pis_target(&self.prev_batch_proof, dummy_proof);
        }

        self.block_number.set_witness(witness, value.block_number);
        witness.set_target(
            self.aggregator_id,
            F::from_canonical_u64(value.aggregator_id as u64),
        );
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        witness.set_target(
            self.new_user_local_id,
            F::from_canonical_u64(value.new_user_local_id as u64),
        );
        self.prev_account_leaf
            .set_witness(witness, &value.prev_account_leaf);
        self.account_merkle_proof
            .set_witness(witness, &value.account_merkle_proof);
        witness.set_target(self.pk_index, F::from_canonical_u64(value.pk_index as u64));
        self.key_set_merkle_proof
            .set_witness(witness, &value.key_set_merkle_proof);
        self.spx_sig_targets
            .set_witness(witness, &value.sig_witness);
        self.new_pis.set_witness::<F, C, D, _>(witness, new_pis);
    }
}

pub struct SigBatchStepCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: SigBatchStepTarget<D>,
    pub public_inputs: SigBatchPublicInputsTarget,
    pub dummy_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> SigBatchStepCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(sig_batch_cd: &CommonCircuitData<F, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = SigBatchStepTarget::new::<F, C>(&mut builder, sig_batch_cd);
        let public_inputs = target.new_pis.clone();
        builder.register_public_inputs(&public_inputs.to_vec(&sig_batch_cd.config));
        let data = builder.build::<C>();
        let dummy_proof = DummyProof::new(sig_batch_cd);
        Self {
            data,
            target,
            public_inputs,
            dummy_proof: dummy_proof.proof,
        }
    }

    pub fn prove(
        &self,
        sig_batch_vd: &VerifierCircuitData<F, C, D>,
        witness: &SigBatchStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, SigBatchStepError> {
        let new_pis = witness.to_public_inputs(sig_batch_vd)?;
        let mut pw = PartialWitness::<F>::new();
        self.target
            .set_witness(&mut pw, witness, &new_pis, &self.dummy_proof);
        self.data
            .prove(pw)
            .map_err(|e| SigBatchStepError::FailedToProve(e.to_string()))
    }
}
