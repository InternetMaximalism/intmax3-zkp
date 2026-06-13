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
    channel_apply_block::{
        ChannelApplyBlockCircuit, ChannelApplyBlockError, ChannelApplyBlockWitness,
    },
    channel_apply_circuit::{ChannelApplyCircuit, ChannelApplyCircuitError},
    channel_apply_step::{ChannelApplyStepCircuit, ChannelApplyStepError, ChannelApplyStepWitness},
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
    ApplyBlockError(#[from] ChannelApplyBlockError),

    #[error("Account apply step error: {0}")]
    ApplyStepError(#[from] ChannelApplyStepError),

    #[error("Account apply circuit error: {0}")]
    ApplyCircuitError(#[from] ChannelApplyCircuitError),
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
/// ║  Pipeline 2: User Tree Updates (parallel + merge)      ║
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
    user_apply_block_circuit: ChannelApplyBlockCircuit<F, C, D>,
    user_apply_step_circuit: ChannelApplyStepCircuit<F, C, D>,
    channel_apply_circuit: ChannelApplyCircuit<F, C, D>,
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
        let user_apply_block_circuit = ChannelApplyBlockCircuit::<F, C, D>::new();
        let user_apply_cd = ChannelApplyCircuit::<F, C, D>::generate_cd();
        let user_apply_step_circuit = ChannelApplyStepCircuit::<F, C, D>::new(
            &user_apply_cd,
            &user_apply_block_circuit.data.verifier_data(),
        );
        let channel_apply_circuit = ChannelApplyCircuit::<F, C, D>::new(
            &user_apply_cd,
            &user_apply_step_circuit.data.verifier_data(),
        );

        Self {
            sig_batch_step_circuit,
            sig_batch_circuit,
            sig_merge_step_circuit,
            sig_merge_circuit,
            user_apply_block_circuit,
            user_apply_step_circuit,
            channel_apply_circuit,
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

    pub fn user_apply_block_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.user_apply_block_circuit.data.verifier_data()
    }

    pub fn user_apply_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.channel_apply_circuit.data.verifier_data()
    }

    /// Prove a flat block of user tree updates (parallelizable).
    ///
    /// Each block processes up to USER_APPLY_BLOCK_SIZE users.
    /// Multiple blocks can be proven in parallel since each block
    /// operates on pre-computed intermediate tree states.
    pub fn prove_apply_block(
        &self,
        witness: &ChannelApplyBlockWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ParallelSigProcessorError> {
        let proof = self.user_apply_block_circuit.prove(witness)?;
        Ok(proof)
    }

    /// Prove a single apply merge step: absorb one ChannelApplyBlock proof.
    pub fn prove_apply_step(
        &self,
        witness: &ChannelApplyStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ParallelSigProcessorError> {
        let user_apply_vd = self.user_apply_vd();
        let step_proof = self
            .user_apply_step_circuit
            .prove(&user_apply_vd, witness)?;
        let apply_proof = self.channel_apply_circuit.prove(&step_proof)?;
        Ok(apply_proof)
    }

    /// Verify a block proof.
    pub fn verify_apply_block(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), ChannelApplyBlockError> {
        self.user_apply_block_circuit.verify(proof)
    }

    /// Verify a merged apply proof.
    pub fn verify_apply(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), ChannelApplyCircuitError> {
        self.channel_apply_circuit.verify(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::{
            test_utils::sphincs_sign::{pk_hash_from_pk_bytes, sphincs_keygen, sphincs_sign},
            validity::{
                block_hash_chain::sphincs_sig::{SmallBlockMessageFields, SpxSigWitness},
                signature_aggregation::{
                    channel_apply_block::{ChannelApplyBlockWitness, ChannelApplyUserWitness},
                    channel_apply_step::ChannelApplyInitialValue,
                    sig_batch_pis::SigBatchPublicInputs,
                    sig_batch_step::{SigBatchInitialValue, SigBatchStepWitness},
                    sig_merge_pis::SigMergePublicInputs,
                    sig_merge_step::{SigMergeInitialValue, SigMergeStepWitness},
                },
            },
        },
        common::{
            channel_id::ChannelId,
            key_set::{KeySetMerkleProof, KeySetTree, PkLeaf},
            trees::{
                channel_tree::{ChannelLeaf, ChannelTree, SendLeaf, SendTree},
                key_tree::KeyLeaf,
            },
            u63::BlockNumber,
        },
        constants::{CHANNEL_TREE_HEIGHT, KEY_SET_TREE_HEIGHT, SEND_TREE_HEIGHT},
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

    /// Helper: create a member keyID with a 1-of-1 SPHINCS+ key set.
    /// Two-layer identity: the per-keyID (pk_set_root, threshold) live in the KeyLeaf
    /// (KeyTree), not in the channel leaf.
    fn setup_member(_rng: &mut StdRng) -> (SpxKeyPair, KeySetTree, KeyLeaf) {
        let sk_seed: [u8; 16] = rand::random();
        let sk_prf: [u8; 16] = rand::random();
        let pub_seed: [u8; 16] = rand::random();
        let kp = sphincs_keygen(sk_seed, sk_prf, pub_seed);
        let pk_hash = pk_hash_from_pk_bytes(&kp.pk_bytes);

        let mut key_set_tree = KeySetTree::init();
        key_set_tree.update(0, PkLeaf::new(pk_hash));

        let key_leaf = KeyLeaf {
            pk_set_root: key_set_tree.get_root(),
            threshold: 1,
            num_keys: 1,
        };

        (kp, key_set_tree, key_leaf)
    }

    /// Helper: create the channel's single leaf (indexed by channel_id) and register it in the
    /// channel tree.
    fn setup_channel(
        rng: &mut StdRng,
        channel_tree: &mut ChannelTree,
        channel_id: u32,
    ) -> (ChannelLeaf, SendTree) {
        let mut send_tree = SendTree::init();
        let prev_send_leaf = SendLeaf {
            prev: BlockNumber::new(1).unwrap(),
            cur: BlockNumber::new(3).unwrap(),
            tx_tree_root: Bytes32::rand(rng),
        };
        send_tree.push(prev_send_leaf);

        let channel_leaf = ChannelLeaf {
            index: send_tree.len() as u32,
            prev: BlockNumber::new(3).unwrap(),
            send_tree_root: send_tree.get_root(),
            member_key_ids_root: ChannelLeaf::default().member_key_ids_root,
        };

        let channel = ChannelId::new(channel_id as u64).unwrap();
        channel_tree.update(channel.as_u64(), channel_leaf.clone());

        (channel_leaf, send_tree)
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
        let channel_id = 1u32;
        let tx_tree_root = Bytes32::rand(&mut rng);

        // Set up one channel (single leaf) with two member keyIDs
        let mut channel_tree = ChannelTree::new(CHANNEL_TREE_HEIGHT);

        let key_id_a = 10u32;
        let key_id_b = 20u32;

        let (kp_a, kst_a, key_leaf_a) = setup_member(&mut rng);
        let (kp_b, kst_b, key_leaf_b) = setup_member(&mut rng);
        let (channel_leaf, _send_tree) = setup_channel(&mut rng, &mut channel_tree, channel_id);
        let leaf_a = channel_leaf.clone();
        let leaf_b = channel_leaf.clone();

        let account_tree_root = channel_tree.get_root();

        // All members sign the SAME IMSB digest (detail2 §F-2): the 8 u32 digest limbs,
        // each serialised as an 8-byte little-endian word — matching the in-circuit msg_gl.
        let msg_fields = SmallBlockMessageFields {
            bp_key_id: key_id_a,
            small_block_number: 5,
            prev_small_block_root: Bytes32::rand(&mut rng),
            state_commitment_root: Bytes32::rand(&mut rng), // H1' (any nonzero test value)
            medium_epoch_hint: 1,
            close_freeze_nonce: 0,
        };
        let signed_digest = msg_fields.signing_digest(channel_id, tx_tree_root);
        let sign_msg = |kp: &SpxKeyPair| {
            let msg_bytes: Vec<u8> = signed_digest
                .to_u64_vec()
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect();
            sphincs_sign(&msg_bytes, kp)
        };

        // ── Batch A: user_a (key_id=10) ──
        let sig_a = sign_msg(&kp_a);
        let sig_witness_a = SpxSigWitness::from_bytes(&kp_a.pk_bytes, &sig_a);
        let account_proof_a =
            channel_tree.prove(ChannelId::new(channel_id as u64).unwrap().as_u64());
        let kst_proof_a = kst_a.prove(0);

        let t1 = Instant::now();
        // Step 1: sig_verify for user A
        let batch_a_step1 = processor
            .prove_batch_step(&SigBatchStepWitness::<F, C, D> {
                initial_value: Some(SigBatchInitialValue {
                    account_tree_root,
                    block_number,
                    channel_id,
                    tx_tree_root,
                    signed_digest,
                }),
                prev_batch_proof: None,
                is_finalize: false,
                block_number,
                channel_id,
                tx_tree_root,
                signed_digest,
                new_user_key_id: key_id_a,
                prev_user_leaf: leaf_a.clone(),
                user_merkle_proof: account_proof_a.clone(),
                key_leaf: key_leaf_a.clone(),
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
                channel_id,
                tx_tree_root,
                signed_digest,
                new_user_key_id: 0,
                prev_user_leaf: leaf_a.clone(),
                user_merkle_proof: account_proof_a,
                key_leaf: KeyLeaf::default(),
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
        assert_eq!(batch_a_pis.current_user_key_id, 0);
        // Two-layer identity: the per-user ordering/chain ids are member key_ids.
        let user_id_a = key_id_a as u64;
        assert_eq!(batch_a_pis.first_user_id, user_id_a);
        assert_eq!(batch_a_pis.last_user_id, user_id_a);

        // ── Batch B: user_b (key_id=20) ──
        let sig_b = sign_msg(&kp_b);
        let sig_witness_b = SpxSigWitness::from_bytes(&kp_b.pk_bytes, &sig_b);
        let account_proof_b =
            channel_tree.prove(ChannelId::new(channel_id as u64).unwrap().as_u64());
        let kst_proof_b = kst_b.prove(0);

        let t3 = Instant::now();
        let batch_b_step1 = processor
            .prove_batch_step(&SigBatchStepWitness::<F, C, D> {
                initial_value: Some(SigBatchInitialValue {
                    account_tree_root,
                    block_number,
                    channel_id,
                    tx_tree_root,
                    signed_digest,
                }),
                prev_batch_proof: None,
                is_finalize: false,
                block_number,
                channel_id,
                tx_tree_root,
                signed_digest,
                new_user_key_id: key_id_b,
                prev_user_leaf: leaf_b.clone(),
                user_merkle_proof: account_proof_b.clone(),
                key_leaf: key_leaf_b.clone(),
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
                channel_id,
                tx_tree_root,
                signed_digest,
                new_user_key_id: 0,
                prev_user_leaf: leaf_b.clone(),
                user_merkle_proof: account_proof_b,
                key_leaf: KeyLeaf::default(),
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
                    channel_id,
                    tx_tree_root,
                    signed_digest,
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
        let user_id_b = key_id_b as u64;
        assert_eq!(merge_pis.last_user_id, user_id_b);
        assert_eq!(merge_pis.account_tree_root, account_tree_root);

        println!("\n=== All assertions passed ===");
        println!("  Batch A: 1 user verified");
        println!("  Batch B: 1 user verified");
        println!("  Merge: 2 users total, IDs [{}, {}]", user_id_a, user_id_b);
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_user_apply_block_and_merge() {
        use crate::circuits::validity::signature_aggregation::{
            channel_apply_block::USER_APPLY_BLOCK_SIZE, channel_apply_pis::ChannelApplyPublicInputs,
        };
        use std::time::Instant;
        let mut rng = StdRng::seed_from_u64(42);

        let t0 = Instant::now();
        let processor = ParallelSigProcessor::<F, C, D>::new();
        println!("ParallelSigProcessor::new(): {:?}", t0.elapsed());

        let block_number = BlockNumber::new(5).unwrap();
        let channel_id = 1u32;
        let tx_tree_root = Bytes32::rand(&mut rng);

        // Set up one channel (single leaf) with two member keyIDs updating it in turn
        let mut channel_tree = ChannelTree::new(CHANNEL_TREE_HEIGHT);
        let key_id_a = 10u32;
        let key_id_b = 20u32;

        let (channel_leaf, send_tree) = setup_channel(&mut rng, &mut channel_tree, channel_id);

        let initial_root = channel_tree.get_root();

        // ── Build ChannelApplyBlock with 2 active member keyIDs on the same channel leaf ──
        let channel = ChannelId::new(channel_id as u64).unwrap();

        let account_proof_a = channel_tree.prove(channel.as_u64());
        let send_proof_a = send_tree.prove(channel_leaf.index.into());

        let mut users = vec![ChannelApplyUserWitness {
            is_active: true,
            user_key_id: key_id_a,
            prev_user_leaf: channel_leaf.clone(),
            user_merkle_proof: account_proof_a,
            send_merkle_proof: send_proof_a,
        }];

        // Apply member A's update to the channel leaf (off-circuit) to get updated proofs for
        // member B — both members update the SAME channel leaf in sequence.
        let new_send_leaf_a = SendLeaf {
            prev: channel_leaf.prev,
            cur: block_number,
            tx_tree_root,
        };
        let mut updated_send_tree = send_tree.clone();
        updated_send_tree.push(new_send_leaf_a);
        let new_channel_leaf_a = ChannelLeaf {
            index: channel_leaf.index + 1,
            prev: block_number,
            send_tree_root: updated_send_tree.get_root(),
            member_key_ids_root: channel_leaf.member_key_ids_root,
        };
        channel_tree.update(channel.as_u64(), new_channel_leaf_a.clone());

        let account_proof_b = channel_tree.prove(channel.as_u64());
        let send_proof_b = updated_send_tree.prove(new_channel_leaf_a.index.into());

        users.push(ChannelApplyUserWitness {
            is_active: true,
            user_key_id: key_id_b,
            prev_user_leaf: new_channel_leaf_a.clone(),
            user_merkle_proof: account_proof_b,
            send_merkle_proof: send_proof_b,
        });

        // Pad remaining slots with inactive dummies
        use crate::common::trees::channel_tree::{ChannelMerkleProof, SendMerkleProof};
        while users.len() < USER_APPLY_BLOCK_SIZE {
            users.push(ChannelApplyUserWitness {
                is_active: false,
                user_key_id: 0,
                prev_user_leaf: ChannelLeaf::default(),
                user_merkle_proof: ChannelMerkleProof::dummy(CHANNEL_TREE_HEIGHT),
                send_merkle_proof: SendMerkleProof::dummy(SEND_TREE_HEIGHT),
            });
        }

        // IMSB message fields for this block — the apply-block circuit recomputes the digest
        // in-circuit, binding it to the block's channel_id/tx_tree_root targets.
        let msg_fields = SmallBlockMessageFields {
            bp_key_id: key_id_a,
            small_block_number: 5,
            prev_small_block_root: Bytes32::rand(&mut rng),
            state_commitment_root: Bytes32::rand(&mut rng), // H1' (any nonzero test value)
            medium_epoch_hint: 1,
            close_freeze_nonce: 0,
        };
        let signed_digest = msg_fields.signing_digest(channel_id, tx_tree_root);
        let block_witness = ChannelApplyBlockWitness {
            initial_account_tree_root: initial_root,
            block_number,
            channel_id,
            tx_tree_root,
            msg_fields,
            users,
        };

        // ── Prove the block ──
        let t1 = Instant::now();
        let block_proof = processor
            .prove_apply_block(&block_witness)
            .expect("apply block");
        println!("ChannelApplyBlock prove (2 users): {:?}", t1.elapsed());
        processor
            .verify_apply_block(&block_proof)
            .expect("apply block verify");

        // ── Merge the block ──
        let t2 = Instant::now();
        let apply_proof = processor
            .prove_apply_step(&ChannelApplyStepWitness::<F, C, D> {
                initial_value: Some(ChannelApplyInitialValue {
                    account_tree_root: initial_root,
                    block_number,
                    channel_id,
                    tx_tree_root,
                    signed_digest,
                }),
                prev_apply_proof: None,
                block_proof,
            })
            .expect("apply merge step");
        println!("ChannelApplyMerge step (absorb block): {:?}", t2.elapsed());
        processor
            .verify_apply(&apply_proof)
            .expect("apply merge verify");

        // Check final apply PIS
        let apply_vd = processor.user_apply_vd();
        let apply_pis = ChannelApplyPublicInputs::<F, C, D>::from_u64_slice(
            &apply_proof.public_inputs.to_u64_vec(),
            &apply_vd.common.config,
        )
        .unwrap();
        assert_eq!(apply_pis.verified_count, 2);
        assert_eq!(apply_pis.prev_account_tree_root, initial_root);
        // new_account_tree_root should be different from initial (users were applied)
        assert_ne!(apply_pis.new_account_tree_root, initial_root);
        // Two-layer identity: the per-user ordering/chain ids are member key_ids.
        assert_eq!(apply_pis.first_user_id, key_id_a as u64);
        assert_eq!(apply_pis.last_user_id, key_id_b as u64);

        println!("\n=== ChannelApply test passed ===");
        println!("  Block: 2 users applied");
        println!("  Initial root: {:?}", initial_root);
        println!("  Final root: {:?}", apply_pis.new_account_tree_root);
    }
}
