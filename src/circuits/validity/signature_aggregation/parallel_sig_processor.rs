use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuits::validity::signature_aggregation::{
    account_apply_block::{
        AccountApplyBlockCircuit, AccountApplyBlockError, AccountApplyBlockWitness,
    },
    account_apply_circuit::{AccountApplyCircuit, AccountApplyCircuitError},
    account_apply_step::{AccountApplyStepCircuit, AccountApplyStepError, AccountApplyStepWitness},
    sig_batch_circuit::{SigBatchCircuit, SigBatchCircuitError},
    sig_batch_step::{SigBatchStepCircuit, SigBatchStepError, SigBatchStepWitness},
    sig_merge_circuit::{SigMergeCircuit, SigMergeCircuitError},
    sig_merge_step::{SigMergeStepCircuit, SigMergeStepError, SigMergeStepWitness},
};

#[derive(Debug, thiserror::Error)]
pub enum ParallelSigProcessorError {
    #[error("Batch step error: {0}")]
    BatchStepError(#[from] SigBatchStepError),

    #[error("Batch circuit error: {0}")]
    BatchCircuitError(#[from] SigBatchCircuitError),

    #[error("Merge step error: {0}")]
    MergeStepError(#[from] SigMergeStepError),

    #[error("Merge circuit error: {0}")]
    MergeCircuitError(#[from] SigMergeCircuitError),

    #[error("Account apply block error: {0}")]
    ApplyBlockError(#[from] AccountApplyBlockError),

    #[error("Account apply step error: {0}")]
    ApplyStepError(#[from] AccountApplyStepError),

    #[error("Account apply circuit error: {0}")]
    ApplyCircuitError(#[from] AccountApplyCircuitError),
}

/// Orchestrator for the parallel signature aggregation pipeline.
///
/// Architecture (optimized for 1000 signatures in < 3 minutes):
///
/// ```text
/// ╔═══════════════════════════════════════════════════════════╗
/// ║  Pipeline 1: Signature Verification (parallel + merge)    ║
/// ║  [Parallel - N workers]          [Linear Merge]           ║
/// ║  Batch_A: users 1-25  ─┐                                 ║
/// ║  Batch_B: users 26-50 ─┼─→ SigMerge(A,B,...) ─→ proof   ║
/// ║  Batch_C: users 51-75 ─┤                                 ║
/// ║  ...                   ┘                                  ║
/// ╠═══════════════════════════════════════════════════════════╣
/// ║  Pipeline 2: Account Tree Updates (parallel + merge)      ║
/// ║  [Parallel - N workers]          [Linear Merge]           ║
/// ║  Block_1: users 1-20  ─┐                                 ║
/// ║  Block_2: users 21-40 ─┼─→ ApplyMerge(1,2,...) ─→ proof  ║
/// ║  Block_3: users 41-60 ─┤                                 ║
/// ║  ...                   ┘                                  ║
/// ╚═══════════════════════════════════════════════════════════╝
/// Both pipelines run concurrently.
/// Total time ≈ max(pipeline1, pipeline2).
/// ```
pub struct ParallelSigProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // Signature verification pipeline
    sig_batch_step_circuit: SigBatchStepCircuit<F, C, D>,
    sig_batch_circuit: SigBatchCircuit<F, C, D>,
    sig_merge_step_circuit: SigMergeStepCircuit<F, C, D>,
    sig_merge_circuit: SigMergeCircuit<F, C, D>,

    // Account tree update pipeline
    account_apply_block_circuit: AccountApplyBlockCircuit<F, C, D>,
    account_apply_step_circuit: AccountApplyStepCircuit<F, C, D>,
    account_apply_circuit: AccountApplyCircuit<F, C, D>,
}

impl<F, C, const D: usize> ParallelSigProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        // Build batch pipeline
        let sig_batch_cd = SigBatchCircuit::<F, C, D>::generate_cd();
        let sig_batch_step_circuit = SigBatchStepCircuit::<F, C, D>::new(&sig_batch_cd);
        let sig_batch_circuit = SigBatchCircuit::<F, C, D>::new(
            &sig_batch_cd,
            &sig_batch_step_circuit.data.verifier_data(),
        );

        // Build merge pipeline
        let sig_merge_cd = SigMergeCircuit::<F, C, D>::generate_cd();
        let sig_merge_step_circuit = SigMergeStepCircuit::<F, C, D>::new(
            &sig_merge_cd,
            &sig_batch_circuit.data.verifier_data(),
        );
        let sig_merge_circuit = SigMergeCircuit::<F, C, D>::new(
            &sig_merge_cd,
            &sig_merge_step_circuit.data.verifier_data(),
        );

        // Build account apply pipeline
        let account_apply_block_circuit = AccountApplyBlockCircuit::<F, C, D>::new();
        let account_apply_cd = AccountApplyCircuit::<F, C, D>::generate_cd();
        let account_apply_step_circuit = AccountApplyStepCircuit::<F, C, D>::new(
            &account_apply_cd,
            &account_apply_block_circuit.data.verifier_data(),
        );
        let account_apply_circuit = AccountApplyCircuit::<F, C, D>::new(
            &account_apply_cd,
            &account_apply_step_circuit.data.verifier_data(),
        );

        Self {
            sig_batch_step_circuit,
            sig_batch_circuit,
            sig_merge_step_circuit,
            sig_merge_circuit,
            account_apply_block_circuit,
            account_apply_step_circuit,
            account_apply_circuit,
        }
    }

    // ── Signature verification pipeline ──

    pub fn sig_batch_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.sig_batch_circuit.data.verifier_data()
    }

    pub fn sig_merge_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.sig_merge_circuit.data.verifier_data()
    }

    /// Prove a single batch step (sig_verify or finalize) and wrap it.
    ///
    /// Multiple batch proofs can be created in parallel since account_tree_root
    /// is read-only within batches.
    pub fn prove_batch_step(
        &self,
        witness: &SigBatchStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ParallelSigProcessorError> {
        let sig_batch_vd = self.sig_batch_vd();
        let step_proof = self.sig_batch_step_circuit.prove(&sig_batch_vd, witness)?;
        let batch_proof = self.sig_batch_circuit.prove(&step_proof)?;
        Ok(batch_proof)
    }

    /// Prove a single merge step: absorb one completed batch proof.
    pub fn prove_merge_step(
        &self,
        witness: &SigMergeStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ParallelSigProcessorError> {
        let sig_merge_vd = self.sig_merge_vd();
        let sig_batch_vd = self.sig_batch_vd();
        let step_proof =
            self.sig_merge_step_circuit
                .prove(&sig_merge_vd, &sig_batch_vd, witness)?;
        let merge_proof = self.sig_merge_circuit.prove(&step_proof)?;
        Ok(merge_proof)
    }

    /// Verify a batch proof.
    pub fn verify_batch(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), SigBatchCircuitError> {
        self.sig_batch_circuit.verify(proof)
    }

    /// Verify a merge proof.
    pub fn verify_merge(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), SigMergeCircuitError> {
        self.sig_merge_circuit.verify(proof)
    }

    // ── Account tree update pipeline ──

    pub fn account_apply_block_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.account_apply_block_circuit.data.verifier_data()
    }

    pub fn account_apply_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.account_apply_circuit.data.verifier_data()
    }

    /// Prove a flat block of account tree updates (parallelizable).
    ///
    /// Each block processes up to ACCOUNT_APPLY_BLOCK_SIZE users.
    /// Multiple blocks can be proven in parallel since each block
    /// operates on pre-computed intermediate tree states.
    pub fn prove_apply_block(
        &self,
        witness: &AccountApplyBlockWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ParallelSigProcessorError> {
        let proof = self.account_apply_block_circuit.prove(witness)?;
        Ok(proof)
    }

    /// Prove a single apply merge step: absorb one AccountApplyBlock proof.
    pub fn prove_apply_step(
        &self,
        witness: &AccountApplyStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ParallelSigProcessorError> {
        let account_apply_vd = self.account_apply_vd();
        let step_proof = self
            .account_apply_step_circuit
            .prove(&account_apply_vd, witness)?;
        let apply_proof = self.account_apply_circuit.prove(&step_proof)?;
        Ok(apply_proof)
    }

    /// Verify a block proof.
    pub fn verify_apply_block(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), AccountApplyBlockError> {
        self.account_apply_block_circuit.verify(proof)
    }

    /// Verify a merged apply proof.
    pub fn verify_apply(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), AccountApplyCircuitError> {
        self.account_apply_circuit.verify(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::{
            test_utils::sphincs_sign::{pk_hash_from_pk_bytes, sphincs_keygen, sphincs_sign},
            validity::{
                block_hash_chain::sphincs_sig::SpxSigWitness,
                signature_aggregation::{
                    account_apply_block::{AccountApplyBlockWitness, AccountApplyUserWitness},
                    account_apply_step::AccountApplyInitialValue,
                    sig_batch_pis::SigBatchPublicInputs,
                    sig_batch_step::{SigBatchInitialValue, SigBatchStepWitness},
                    sig_merge_pis::SigMergePublicInputs,
                    sig_merge_step::{SigMergeInitialValue, SigMergeStepWitness},
                },
            },
        },
        common::{
            key_set::{KeySetMerkleProof, KeySetTree, PkLeaf},
            trees::account_tree::{AccountLeaf, AccountTree, SendLeaf, SendTree},
            u63::BlockNumber,
            user_id::UserId,
        },
        constants::{ACCOUNT_TREE_HEIGHT, KEY_SET_TREE_HEIGHT, SEND_TREE_HEIGHT},
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
        utils::conversion::ToU64,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{SeedableRng, rngs::StdRng};

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    use crate::circuits::test_utils::sphincs_sign::SpxKeyPair;

    /// Helper: create a user with a key set and register in account tree.
    fn setup_user(
        rng: &mut StdRng,
        account_tree: &mut AccountTree,
        aggregator_id: u32,
        local_id: u32,
    ) -> (SpxKeyPair, KeySetTree, AccountLeaf, SendTree) {
        let sk_seed: [u8; 16] = rand::random();
        let sk_prf: [u8; 16] = rand::random();
        let pub_seed: [u8; 16] = rand::random();
        let kp = sphincs_keygen(sk_seed, sk_prf, pub_seed);
        let pk_hash = pk_hash_from_pk_bytes(&kp.pk_bytes);

        let mut key_set_tree = KeySetTree::init();
        key_set_tree.update(0, PkLeaf::new(pk_hash));

        let mut send_tree = SendTree::init();
        let prev_send_leaf = SendLeaf {
            prev: BlockNumber::new(1).unwrap(),
            cur: BlockNumber::new(3).unwrap(),
            tx_tree_root: Bytes32::rand(rng),
        };
        send_tree.push(prev_send_leaf);

        let prev_account_leaf = AccountLeaf {
            index: send_tree.len() as u32,
            prev: BlockNumber::new(3).unwrap(),
            send_tree_root: send_tree.get_root(),
            pk_set_root: key_set_tree.get_root(),
            threshold: 1,
        };

        let user_id = UserId::new(aggregator_id, local_id).unwrap();
        account_tree.update(user_id.as_u64(), prev_account_leaf.clone());

        (kp, key_set_tree, prev_account_leaf, send_tree)
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_parallel_sig_two_batches_merged() {
        use std::time::Instant;
        let mut rng = StdRng::seed_from_u64(42);

        let t0 = Instant::now();
        let processor = ParallelSigProcessor::<F, C, D>::new();
        println!("ParallelSigProcessor::new(): {:?}", t0.elapsed());

        let sig_batch_vd = processor.sig_batch_vd();
        let block_number = BlockNumber::new(5).unwrap();
        let aggregator_id = 1u32;
        let tx_tree_root = Bytes32::rand(&mut rng);

        // Set up two users
        let mut account_tree = AccountTree::new(ACCOUNT_TREE_HEIGHT);

        let local_id_a = 10u32;
        let local_id_b = 20u32;

        let (kp_a, kst_a, leaf_a, st_a) =
            setup_user(&mut rng, &mut account_tree, aggregator_id, local_id_a);
        let (kp_b, kst_b, leaf_b, st_b) =
            setup_user(&mut rng, &mut account_tree, aggregator_id, local_id_b);

        let account_tree_root = account_tree.get_root();

        // Helper to sign
        let sign_msg = |kp: &SpxKeyPair, local_id: u32| {
            let msg_u64: Vec<u64> = std::iter::once(block_number.as_u64())
                .chain(std::iter::once(aggregator_id as u64))
                .chain(std::iter::once(local_id as u64))
                .chain(tx_tree_root.to_u64_vec())
                .collect();
            let msg_bytes: Vec<u8> = msg_u64.iter().flat_map(|w| w.to_le_bytes()).collect();
            sphincs_sign(&msg_bytes, kp)
        };

        // ── Batch A: user_a (local_id=10) ──
        let sig_a = sign_msg(&kp_a, local_id_a);
        let sig_witness_a = SpxSigWitness::from_bytes(&kp_a.pk_bytes, &sig_a);
        let account_proof_a =
            account_tree.prove(UserId::new(aggregator_id, local_id_a).unwrap().as_u64());
        let _send_proof_a = st_a.prove(leaf_a.index.into());
        let kst_proof_a = kst_a.prove(0);

        let t1 = Instant::now();
        // Step 1: sig_verify for user A
        let batch_a_step1 = processor
            .prove_batch_step(&SigBatchStepWitness::<F, C, D> {
                initial_value: Some(SigBatchInitialValue {
                    account_tree_root,
                    block_number,
                    aggregator_id,
                    tx_tree_root,
                }),
                prev_batch_proof: None,
                is_finalize: false,
                block_number,
                aggregator_id,
                tx_tree_root,
                new_user_local_id: local_id_a,
                prev_account_leaf: leaf_a.clone(),
                account_merkle_proof: account_proof_a.clone(),
                pk_index: 0,
                key_set_merkle_proof: kst_proof_a,
                sig_witness: sig_witness_a,
            })
            .expect("batch A step 1");
        println!("Batch A step 1 (sig_verify): {:?}", t1.elapsed());

        // Step 2: finalize user A
        let t2 = Instant::now();
        let batch_a_final = processor
            .prove_batch_step(&SigBatchStepWitness::<F, C, D> {
                initial_value: None,
                prev_batch_proof: Some(batch_a_step1),
                is_finalize: true,
                block_number,
                aggregator_id,
                tx_tree_root,
                new_user_local_id: 0,
                prev_account_leaf: leaf_a.clone(),
                account_merkle_proof: account_proof_a,
                pk_index: 0,
                key_set_merkle_proof: KeySetMerkleProof::dummy(KEY_SET_TREE_HEIGHT),
                sig_witness: SpxSigWitness::dummy(),
            })
            .expect("batch A finalize");
        println!("Batch A step 2 (finalize): {:?}", t2.elapsed());
        processor
            .verify_batch(&batch_a_final)
            .expect("batch A verify");

        // Check batch A PIS
        let batch_a_pis = SigBatchPublicInputs::<F, C, D>::from_u64_slice(
            &batch_a_final.public_inputs.to_u64_vec(),
            &sig_batch_vd.common.config,
        )
        .unwrap();
        assert_eq!(batch_a_pis.verified_count, 1);
        assert_eq!(batch_a_pis.current_user_local_id, 0);
        let user_id_a = UserId::new(aggregator_id, local_id_a).unwrap().as_u64();
        assert_eq!(batch_a_pis.first_user_id, user_id_a);
        assert_eq!(batch_a_pis.last_user_id, user_id_a);

        // ── Batch B: user_b (local_id=20) ──
        let sig_b = sign_msg(&kp_b, local_id_b);
        let sig_witness_b = SpxSigWitness::from_bytes(&kp_b.pk_bytes, &sig_b);
        let account_proof_b =
            account_tree.prove(UserId::new(aggregator_id, local_id_b).unwrap().as_u64());
        let _send_proof_b = st_b.prove(leaf_b.index.into());
        let kst_proof_b = kst_b.prove(0);

        let t3 = Instant::now();
        let batch_b_step1 = processor
            .prove_batch_step(&SigBatchStepWitness::<F, C, D> {
                initial_value: Some(SigBatchInitialValue {
                    account_tree_root,
                    block_number,
                    aggregator_id,
                    tx_tree_root,
                }),
                prev_batch_proof: None,
                is_finalize: false,
                block_number,
                aggregator_id,
                tx_tree_root,
                new_user_local_id: local_id_b,
                prev_account_leaf: leaf_b.clone(),
                account_merkle_proof: account_proof_b.clone(),
                pk_index: 0,
                key_set_merkle_proof: kst_proof_b,
                sig_witness: sig_witness_b,
            })
            .expect("batch B step 1");
        println!("Batch B step 1 (sig_verify): {:?}", t3.elapsed());

        let t4 = Instant::now();
        let batch_b_final = processor
            .prove_batch_step(&SigBatchStepWitness::<F, C, D> {
                initial_value: None,
                prev_batch_proof: Some(batch_b_step1),
                is_finalize: true,
                block_number,
                aggregator_id,
                tx_tree_root,
                new_user_local_id: 0,
                prev_account_leaf: leaf_b.clone(),
                account_merkle_proof: account_proof_b,
                pk_index: 0,
                key_set_merkle_proof: KeySetMerkleProof::dummy(KEY_SET_TREE_HEIGHT),
                sig_witness: SpxSigWitness::dummy(),
            })
            .expect("batch B finalize");
        println!("Batch B step 2 (finalize): {:?}", t4.elapsed());
        processor
            .verify_batch(&batch_b_final)
            .expect("batch B verify");

        // ── Merge: A then B ──
        let t5 = Instant::now();
        let merge_step1 = processor
            .prove_merge_step(&SigMergeStepWitness::<F, C, D> {
                initial_value: Some(SigMergeInitialValue {
                    account_tree_root,
                    block_number,
                    aggregator_id,
                    tx_tree_root,
                }),
                prev_merge_proof: None,
                batch_proof: batch_a_final,
            })
            .expect("merge step 1");
        println!("Merge step 1 (absorb batch A): {:?}", t5.elapsed());

        let t6 = Instant::now();
        let merge_final = processor
            .prove_merge_step(&SigMergeStepWitness::<F, C, D> {
                initial_value: None,
                prev_merge_proof: Some(merge_step1),
                batch_proof: batch_b_final,
            })
            .expect("merge step 2");
        println!("Merge step 2 (absorb batch B): {:?}", t6.elapsed());
        processor.verify_merge(&merge_final).expect("merge verify");

        // Check final merge PIS
        let sig_merge_vd = processor.sig_merge_vd();
        let merge_pis = SigMergePublicInputs::<F, C, D>::from_u64_slice(
            &merge_final.public_inputs.to_u64_vec(),
            &sig_merge_vd.common.config,
        )
        .unwrap();
        assert_eq!(merge_pis.verified_count, 2);
        assert_eq!(merge_pis.first_user_id, user_id_a);
        let user_id_b = UserId::new(aggregator_id, local_id_b).unwrap().as_u64();
        assert_eq!(merge_pis.last_user_id, user_id_b);
        assert_eq!(merge_pis.account_tree_root, account_tree_root);

        println!("\n=== All assertions passed ===");
        println!("  Batch A: 1 user verified");
        println!("  Batch B: 1 user verified");
        println!("  Merge: 2 users total, IDs [{}, {}]", user_id_a, user_id_b);
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_account_apply_block_and_merge() {
        use crate::circuits::validity::signature_aggregation::{
            account_apply_block::ACCOUNT_APPLY_BLOCK_SIZE,
            account_apply_pis::AccountApplyPublicInputs,
        };
        use std::time::Instant;
        let mut rng = StdRng::seed_from_u64(42);

        let t0 = Instant::now();
        let processor = ParallelSigProcessor::<F, C, D>::new();
        println!("ParallelSigProcessor::new(): {:?}", t0.elapsed());

        let block_number = BlockNumber::new(5).unwrap();
        let aggregator_id = 1u32;
        let tx_tree_root = Bytes32::rand(&mut rng);

        // Set up 2 users for account tree updates
        let mut account_tree = AccountTree::new(ACCOUNT_TREE_HEIGHT);
        let local_id_a = 10u32;
        let local_id_b = 20u32;

        let (_kp_a, _kst_a, leaf_a, st_a) =
            setup_user(&mut rng, &mut account_tree, aggregator_id, local_id_a);
        let (_kp_b, _kst_b, leaf_b, st_b) =
            setup_user(&mut rng, &mut account_tree, aggregator_id, local_id_b);

        let initial_root = account_tree.get_root();

        // ── Build AccountApplyBlock with 2 active users ──
        let user_id_a = UserId::new(aggregator_id, local_id_a).unwrap();
        let user_id_b = UserId::new(aggregator_id, local_id_b).unwrap();

        let account_proof_a = account_tree.prove(user_id_a.as_u64());
        let send_proof_a = st_a.prove(leaf_a.index.into());

        let mut users = vec![AccountApplyUserWitness {
            is_active: true,
            user_local_id: local_id_a,
            prev_account_leaf: leaf_a.clone(),
            account_merkle_proof: account_proof_a,
            send_merkle_proof: send_proof_a,
        }];

        // Apply user A's update to account tree (off-circuit) to get updated proofs for user B
        let new_send_leaf_a = SendLeaf {
            prev: leaf_a.prev,
            cur: block_number,
            tx_tree_root,
        };
        let mut updated_st_a = st_a.clone();
        updated_st_a.push(new_send_leaf_a);
        let new_account_leaf_a = AccountLeaf {
            index: leaf_a.index + 1,
            prev: block_number,
            send_tree_root: updated_st_a.get_root(),
            pk_set_root: leaf_a.pk_set_root,
            threshold: leaf_a.threshold,
        };
        account_tree.update(user_id_a.as_u64(), new_account_leaf_a);

        let account_proof_b = account_tree.prove(user_id_b.as_u64());
        let send_proof_b = st_b.prove(leaf_b.index.into());

        users.push(AccountApplyUserWitness {
            is_active: true,
            user_local_id: local_id_b,
            prev_account_leaf: leaf_b.clone(),
            account_merkle_proof: account_proof_b,
            send_merkle_proof: send_proof_b,
        });

        // Pad remaining slots with inactive dummies
        use crate::common::trees::account_tree::{AccountMerkleProof, SendMerkleProof};
        while users.len() < ACCOUNT_APPLY_BLOCK_SIZE {
            users.push(AccountApplyUserWitness {
                is_active: false,
                user_local_id: 0,
                prev_account_leaf: AccountLeaf::default(),
                account_merkle_proof: AccountMerkleProof::dummy(ACCOUNT_TREE_HEIGHT),
                send_merkle_proof: SendMerkleProof::dummy(SEND_TREE_HEIGHT),
            });
        }

        let block_witness = AccountApplyBlockWitness {
            initial_account_tree_root: initial_root,
            block_number,
            aggregator_id,
            tx_tree_root,
            users,
        };

        // ── Prove the block ──
        let t1 = Instant::now();
        let block_proof = processor
            .prove_apply_block(&block_witness)
            .expect("apply block");
        println!("AccountApplyBlock prove (2 users): {:?}", t1.elapsed());
        processor
            .verify_apply_block(&block_proof)
            .expect("apply block verify");

        // ── Merge the block ──
        let t2 = Instant::now();
        let apply_proof = processor
            .prove_apply_step(&AccountApplyStepWitness::<F, C, D> {
                initial_value: Some(AccountApplyInitialValue {
                    account_tree_root: initial_root,
                    block_number,
                    aggregator_id,
                    tx_tree_root,
                }),
                prev_apply_proof: None,
                block_proof,
            })
            .expect("apply merge step");
        println!("AccountApplyMerge step (absorb block): {:?}", t2.elapsed());
        processor
            .verify_apply(&apply_proof)
            .expect("apply merge verify");

        // Check final apply PIS
        let apply_vd = processor.account_apply_vd();
        let apply_pis = AccountApplyPublicInputs::<F, C, D>::from_u64_slice(
            &apply_proof.public_inputs.to_u64_vec(),
            &apply_vd.common.config,
        )
        .unwrap();
        assert_eq!(apply_pis.verified_count, 2);
        assert_eq!(apply_pis.prev_account_tree_root, initial_root);
        // new_account_tree_root should be different from initial (users were applied)
        assert_ne!(apply_pis.new_account_tree_root, initial_root);
        assert_eq!(apply_pis.first_user_id, user_id_a.as_u64());
        assert_eq!(apply_pis.last_user_id, user_id_b.as_u64());

        println!("\n=== AccountApply test passed ===");
        println!("  Block: 2 users applied");
        println!("  Initial root: {:?}", initial_root);
        println!("  Final root: {:?}", apply_pis.new_account_tree_root);
    }
}
