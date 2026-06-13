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
    sig_agg_circuit::{SigAggCircuit, SigAggCircuitError},
    sig_agg_step::{SigAggStepCircuit, SigAggStepError, SigAggStepWitness},
};

#[derive(Debug, thiserror::Error)]
pub enum SigAggProcessorError {
    #[error("Sig agg step circuit error: {0}")]
    StepCircuitError(#[from] SigAggStepError),

    #[error("Sig agg circuit error: {0}")]
    CircuitError(#[from] SigAggCircuitError),
}

pub struct SigAggProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    sig_agg_step_circuit: SigAggStepCircuit<F, C, D>,
    sig_agg_circuit: SigAggCircuit<F, C, D>,
}

impl<F, C, const D: usize> SigAggProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let sig_agg_cd = SigAggCircuit::<F, C, D>::generate_cd();
        let sig_agg_step_circuit = SigAggStepCircuit::<F, C, D>::new(&sig_agg_cd);
        let sig_agg_circuit =
            SigAggCircuit::<F, C, D>::new(&sig_agg_cd, &sig_agg_step_circuit.data.verifier_data());
        Self {
            sig_agg_step_circuit,
            sig_agg_circuit,
        }
    }

    pub fn sig_agg_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.sig_agg_circuit.data.verifier_data()
    }

    /// Prove a single step (sig_verify or finalize) and wrap it.
    pub fn prove_step(
        &self,
        witness: &SigAggStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, SigAggProcessorError> {
        let sig_agg_step_proof = self
            .sig_agg_step_circuit
            .prove(&self.sig_agg_vd(), witness)?;
        let sig_agg_proof = self.sig_agg_circuit.prove(&sig_agg_step_proof)?;
        Ok(sig_agg_proof)
    }

    pub fn verify(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<(), SigAggCircuitError> {
        self.sig_agg_circuit.verify(proof)
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
                signature_aggregation::sig_agg_pis::SigAggPublicInputs,
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
        constants::{CHANNEL_TREE_HEIGHT, KEY_SET_TREE_HEIGHT},
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
        utils::conversion::ToU64,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{SeedableRng, rngs::StdRng};

    use crate::circuits::validity::signature_aggregation::sig_agg_step::{
        SigAggInitialValue, SigAggStepWitness,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_sig_agg_processor_single_user_single_sig() {
        use std::time::Instant;
        let mut rng = StdRng::seed_from_u64(42);

        let t0 = Instant::now();
        let processor = SigAggProcessor::<F, C, D>::new();
        println!(
            "SigAggProcessor::new() (circuit construction): {:?}",
            t0.elapsed()
        );
        let sig_agg_vd = processor.sig_agg_vd();

        let block_number = BlockNumber::new(5).unwrap();
        let channel_id = 1u32;
        let key_id = 10u32;
        let tx_tree_root = Bytes32::rand(&mut rng);
        // Two-layer identity: the channel-tree index is the channel id alone.
        let channel = ChannelId::new(channel_id as u64).unwrap();

        // Generate SPHINCS+ key pair
        let sk_seed: [u8; 16] = rand::random();
        let sk_prf: [u8; 16] = rand::random();
        let pub_seed: [u8; 16] = rand::random();
        let kp = sphincs_keygen(sk_seed, sk_prf, pub_seed);
        let pk_hash = pk_hash_from_pk_bytes(&kp.pk_bytes);

        // Build key set tree with one key
        let mut key_set_tree = KeySetTree::init();
        key_set_tree.update(0, PkLeaf::new(pk_hash));
        let pk_set_root = key_set_tree.get_root();

        // Build user tree
        let mut send_tree = SendTree::init();
        let prev_send_leaf = SendLeaf {
            prev: BlockNumber::new(1).unwrap(),
            cur: BlockNumber::new(3).unwrap(),
            tx_tree_root: Bytes32::rand(&mut rng),
        };
        send_tree.push(prev_send_leaf);
        let prev_user_leaf = ChannelLeaf {
            index: send_tree.len() as u32,
            prev: BlockNumber::new(3).unwrap(),
            send_tree_root: send_tree.get_root(),
            member_key_ids_root: ChannelLeaf::default().member_key_ids_root,
        };
        // Two-layer identity: (pk_set_root, threshold) live in the per-keyID KeyLeaf.
        let key_leaf = KeyLeaf {
            pk_set_root,
            threshold: 1,
            num_keys: 1,
        };

        let mut channel_tree = ChannelTree::new(CHANNEL_TREE_HEIGHT);
        channel_tree.update(channel.as_u64(), prev_user_leaf.clone());
        let initial_account_tree_root = channel_tree.get_root();

        // Sign the IMSB digest (detail2 §F-2): the 8 u32 digest limbs, each serialised as
        // an 8-byte little-endian word — matching the in-circuit msg_gl consumption.
        let msg_fields = SmallBlockMessageFields {
            bp_key_id: key_id,
            small_block_number: 5,
            prev_small_block_root: Bytes32::rand(&mut rng),
            state_commitment_root: Bytes32::rand(&mut rng), // H1' (any nonzero test value)
            medium_epoch_hint: 1,
            close_freeze_nonce: 0,
        };
        let signed_digest = msg_fields.signing_digest(channel_id, tx_tree_root);
        let msg_bytes: Vec<u8> = signed_digest
            .to_u64_vec()
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let sig = sphincs_sign(&msg_bytes, &kp);
        let sig_witness = SpxSigWitness::from_bytes(&kp.pk_bytes, &sig);

        let key_set_proof = key_set_tree.prove(0);
        let account_proof = channel_tree.prove(channel.as_u64());
        let send_proof = send_tree.prove(prev_user_leaf.index.into());

        // Step 1: Signature verification (new user)
        let step1_witness = SigAggStepWitness::<F, C, D> {
            initial_value: Some(SigAggInitialValue {
                account_tree_root: initial_account_tree_root,
                block_number,
                channel_id,
                tx_tree_root,
                signed_digest,
            }),
            prev_sig_agg_proof: None,
            is_finalize: false,
            block_number,
            channel_id,
            tx_tree_root,
            signed_digest,
            new_user_key_id: key_id,
            prev_user_leaf: prev_user_leaf.clone(),
            user_merkle_proof: account_proof.clone(),
            send_merkle_proof: send_proof.clone(),
            key_leaf: key_leaf.clone(),
            pk_index: 0,
            key_set_merkle_proof: key_set_proof,
            sig_witness,
        };

        let t1 = Instant::now();
        let step1_proof = processor.prove_step(&step1_witness).expect("step 1 proof");
        println!("Step 1 (sig_verify, initial): {:?}", t1.elapsed());
        processor.verify(&step1_proof).expect("step 1 verify");

        // Step 2: Finalize user
        let step2_witness = SigAggStepWitness::<F, C, D> {
            initial_value: None,
            prev_sig_agg_proof: Some(step1_proof),
            is_finalize: true,
            block_number,
            channel_id,
            tx_tree_root,
            signed_digest,
            new_user_key_id: 0,
            prev_user_leaf: prev_user_leaf.clone(),
            user_merkle_proof: account_proof,
            send_merkle_proof: send_proof,
            key_leaf: KeyLeaf::default(),
            pk_index: 0,
            key_set_merkle_proof: KeySetMerkleProof::dummy(KEY_SET_TREE_HEIGHT),
            sig_witness: SpxSigWitness::dummy(),
        };

        let t2 = Instant::now();
        let step2_proof = processor
            .prove_step(&step2_witness)
            .expect("step 2 (finalize) proof");
        println!("Step 2 (finalize): {:?}", t2.elapsed());
        processor.verify(&step2_proof).expect("step 2 verify");

        // Verify final state: current_user_key_id == 0, processed_count == 1
        let final_pis = SigAggPublicInputs::<F, C, D>::from_u64_slice(
            &step2_proof.public_inputs.to_u64_vec(),
            &sig_agg_vd.common.config,
        )
        .unwrap();
        assert_eq!(final_pis.current_user_key_id, 0);
        assert_eq!(final_pis.processed_count, 1);
        assert_ne!(
            final_pis.account_tree_root, initial_account_tree_root,
            "user tree root should change after finalization"
        );
    }
}
