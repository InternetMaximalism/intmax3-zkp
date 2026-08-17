use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use thiserror::Error;

use crate::{
    circuits::validity::block_hash_chain::{
        block_chain_pis::BlockChainPublicInputsTarget, ext_public_state::ExtendedPublicState,
    },
    common::u63::{BlockNumber, BlockNumberTarget},
    ethereum_types::{
        address::{Address, AddressTarget},
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{
        dummy::DummyProof,
        recursively_verifiable::{
            add_proof_target_and_conditionally_verify, add_proof_target_and_verify_cyclic,
        },
    },
};

pub struct ValidityPublicInputs {
    pub initial_block_number: BlockNumber,
    pub initial_block_chain: Bytes32,
    pub initial_ext_commitment: Bytes32,
    pub final_block_number: BlockNumber,
    pub final_block_chain: Bytes32,
    pub final_ext_commitment: Bytes32,
    pub prover: Address,
}

impl ValidityPublicInputs {
    pub fn from_states(
        initial: &ExtendedPublicState,
        final_state: &ExtendedPublicState,
        prover: Address,
    ) -> Self {
        Self {
            initial_block_number: initial.inner.block_number,
            initial_block_chain: initial.block_hash_chain,
            initial_ext_commitment: initial.commitment(),
            final_block_number: final_state.inner.block_number,
            final_block_chain: final_state.block_hash_chain,
            final_ext_commitment: final_state.commitment(),
            prover,
        }
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        [
            self.initial_block_number.to_u32_vec(),
            self.initial_block_chain.to_u32_vec(),
            self.initial_ext_commitment.to_u32_vec(),
            self.final_block_number.to_u32_vec(),
            self.final_block_chain.to_u32_vec(),
            self.final_ext_commitment.to_u32_vec(),
            self.prover.to_u32_vec(),
        ]
        .concat()
    }

    pub fn hash(&self) -> Bytes32 {
        Bytes32::from_u32_slice(&solidity_keccak256(&self.to_u32_vec()))
            .expect("keccak256 output should fit in Bytes32")
    }
}

pub struct ValidityPublicInputsTarget {
    pub initial_block_number: BlockNumberTarget,
    pub initial_block_chain: Bytes32Target,
    pub initial_ext_commitment: Bytes32Target,
    pub final_block_number: BlockNumberTarget,
    pub final_block_chain: Bytes32Target,
    pub final_ext_commitment: Bytes32Target,
    pub prover: AddressTarget,
}

impl ValidityPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            initial_block_number: BlockNumberTarget::new(builder, is_checked),
            initial_block_chain: Bytes32Target::new::<F, D>(builder, is_checked),
            initial_ext_commitment: Bytes32Target::new::<F, D>(builder, is_checked),
            final_block_number: BlockNumberTarget::new(builder, is_checked),
            final_block_chain: Bytes32Target::new::<F, D>(builder, is_checked),
            final_ext_commitment: Bytes32Target::new::<F, D>(builder, is_checked),
            prover: AddressTarget::new(builder, is_checked),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &ValidityPublicInputs,
    ) {
        self.initial_block_number
            .set_witness(witness, value.initial_block_number);
        self.initial_block_chain
            .set_witness(witness, value.initial_block_chain);
        self.initial_ext_commitment
            .set_witness(witness, value.initial_ext_commitment);
        self.final_block_number
            .set_witness(witness, value.final_block_number);
        self.final_block_chain
            .set_witness(witness, value.final_block_chain);
        self.final_ext_commitment
            .set_witness(witness, value.final_ext_commitment);
        self.prover.set_witness(witness, value.prover);
    }

    pub fn to_vec<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let mut limbs = self.initial_block_number.to_u32_vec(builder);
        limbs.extend(self.initial_block_chain.to_vec());
        limbs.extend(self.initial_ext_commitment.to_vec());
        limbs.extend(self.final_block_number.to_u32_vec(builder));
        limbs.extend(self.final_block_chain.to_vec());
        limbs.extend(self.final_ext_commitment.to_vec());
        limbs.extend(self.prover.to_vec());
        limbs
    }

    pub fn hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let inputs = self.to_vec(builder);
        Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
    }
}

#[derive(Debug, Error)]
pub enum ValidityCircuitError {
    #[error("Failed to prove: {0}")]
    FailedToProve(String),

    #[error("Failed to verify: {0}")]
    ProofVerificationError(String),
}

pub struct ValidityCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub block_hash_chain_proof: ProofWithPublicInputsTarget<D>,
    /// P2b: the recursive `falcon_sig::agg_list::AggListCircuit` proof carrying the
    /// per-signing-block N-of-N signature list commitment `C` (small-block N-of-N design §9
    /// Phase 4: each list step recursively verifies ONE `FalconAggCircuit` TOP proof and folds
    /// `(IMCH digest, signer_count, pk_list_digest)` — the SAME statement `update_channel_tree`
    /// folds into `bp_sig_chain`). Verified CONDITIONALLY (gated on the computed
    /// `final.bp_sig_chain != 0`, decision D3).
    ///
    /// The cyclic wrapper's `CommonCircuitData` is byte-identical to the retired single-signature
    /// `falcon_sig::list::ListCircuit` wrapper's (pinned by
    /// `agg_list::tests::wrapper_common_data_is_identical_to_the_falcon_list_wrapper`), so the
    /// swap was a VERIFIER-KEY change only: this conditional-verify gate, the proof-target
    /// shape and the dummy proof below are structurally unchanged.
    pub agg_list_proof: ProofWithPublicInputsTarget<D>,
    /// Dummy `AggListCircuit` proof for the no-signing-block span (chain == 0 ⇒ verification
    /// skipped).
    pub agg_list_dummy: ProofWithPublicInputs<F, C, D>,
    pub prover: AddressTarget,
}

impl<F, C, const D: usize> ValidityCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// `agg_list_vd` is the `falcon_sig::agg_list::AggListCircuit` verifier data; it is baked in as
    /// a build-time constant (A7) inside `add_proof_target_and_conditionally_verify`.
    ///
    /// SECURITY (why this MUST be the aggregate list and not the single-signature
    /// `falcon_sig::list::ListCircuit`): the two wrappers present identical `CommonCircuitData`, so
    /// passing the wrong one still BUILDS — the mismatch only surfaces as a failed proof. What
    /// separates them is the statement each step folds. A `ListCircuit` step folds "ONE key signed
    /// this digest"; the N-of-N rule this circuit is the last hop of requires "ALL `signer_count`
    /// registered members signed this digest", which is what an `AggListCircuit` step folds and
    /// what `update_channel_tree` accumulates into `bp_sig_chain`. Since the wrappers' VKs differ,
    /// the constant baked in here is what actually pins the choice.
    pub fn new(
        block_hash_chain_vd: &VerifierCircuitData<F, C, D>,
        agg_list_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let block_hash_chain_proof =
            add_proof_target_and_verify_cyclic(block_hash_chain_vd, &mut builder);

        let block_chain_pis = BlockChainPublicInputsTarget::from_pis(
            &block_hash_chain_proof.public_inputs,
            &block_hash_chain_vd.common.config,
        );

        // ── P2b: conditional verification of the N-of-N signature list proof (decision D3) ──
        //
        // The `AggListCircuit` cannot represent the empty (0-entry) list (C == 0 has no proof). The
        // validity span's `final.bp_sig_chain` is an ACCUMULATED commitment over every signing
        // block. When it is non-zero we MUST verify the list proof and assert its commitment equals
        // the accumulator (so every folded statement was a verified N-of-N Falcon aggregate — A8
        // truncation guard). When it is zero (no signing block in the span) we skip with a dummy
        // proof.
        //
        // SECURITY: the gate is the COMPUTED final.bp_sig_chain (an accumulated value bound to the
        // per-block IMCH digest / signer_count / pk_list_digest wires by `update_channel_tree`),
        // NOT a prover flag — so a prover cannot turn the list verification off while still having
        // applied a signed update. Re-tested, not assumed, by
        // `tests/small_block_sig_validity.rs::a_signed_span_cannot_be_proven_with_the_dummy_list`.
        let final_bp_sig_chain = block_chain_pis.ext_public_state.bp_sig_chain.clone();
        let initial_bp_sig_chain = block_chain_pis
            .initial_ext_public_state
            .bp_sig_chain
            .clone();
        // initial.bp_sig_chain == 0 (the span starts with an empty signature list).
        let zero = builder.zero();
        for limb in initial_bp_sig_chain.to_vec() {
            builder.connect(limb, zero);
        }
        let chain_is_zero = final_bp_sig_chain.is_zero::<F, D, Bytes32>(&mut builder);
        let should_verify_list = builder.not(chain_is_zero);
        let agg_list_proof = add_proof_target_and_conditionally_verify(
            agg_list_vd,
            &mut builder,
            should_verify_list,
        );
        // The list circuit's public output [0..8] is its commitment C. When verifying, assert
        // C == final.bp_sig_chain.
        let list_commitment =
            Bytes32Target::from_slice(&agg_list_proof.public_inputs[0..BYTES32_LEN]);
        list_commitment.conditional_assert_eq(
            &mut builder,
            final_bp_sig_chain.clone(),
            should_verify_list,
        );

        let initial_commitment = block_chain_pis
            .initial_ext_public_state
            .commitment(&mut builder);
        let final_commitment = block_chain_pis.ext_public_state.commitment(&mut builder);
        let prover = AddressTarget::new(&mut builder, true);
        let validity_pis = ValidityPublicInputsTarget {
            initial_block_number: block_chain_pis
                .initial_ext_public_state
                .inner
                .block_number
                .clone(),
            initial_block_chain: block_chain_pis
                .initial_ext_public_state
                .block_hash_chain
                .clone(),
            initial_ext_commitment: initial_commitment,
            final_block_number: block_chain_pis.ext_public_state.inner.block_number.clone(),
            final_block_chain: block_chain_pis.ext_public_state.block_hash_chain.clone(),
            final_ext_commitment: final_commitment,
            prover,
        };

        let hash = validity_pis.hash::<F, C, D>(&mut builder);
        builder.register_public_inputs(&hash.to_vec());

        let data = builder.build::<C>();

        // Dummy AggListCircuit proof for the no-signing-block span (verification is gated off).
        let agg_list_dummy = DummyProof::new(&agg_list_vd.common).proof;

        Self {
            data,
            block_hash_chain_proof,
            agg_list_proof,
            agg_list_dummy,
            prover,
        }
    }

    /// Prove the validity statement. `agg_list_proof` is the recursive N-of-N signature-list proof
    /// (`falcon_sig::agg_list::AggListCircuit`) over the span's signing blocks; it MUST be `Some`
    /// exactly when `final.bp_sig_chain != 0` (the span has at least one signing block). When
    /// `None`, the dummy proof is supplied and the conditional list verification is gated off.
    ///
    /// SECURITY: passing `None` for a span that DOES contain a signing block is not a way to skip
    /// the signature check — it makes the proof unprovable. `should_verify_list` is computed from
    /// the block chain's own `final.bp_sig_chain`, so a nonzero chain forces both the recursive
    /// verification of the supplied proof (which the dummy fails) and `C == final.bp_sig_chain`
    /// (which the dummy's all-zero commitment fails). This is an error path, deliberately, rather
    /// than a caller-facing argument check.
    pub fn prove(
        &self,
        block_hash_chain_proof: &ProofWithPublicInputs<F, C, D>,
        agg_list_proof: Option<&ProofWithPublicInputs<F, C, D>>,
        prover: Address,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ValidityCircuitError> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.block_hash_chain_proof, block_hash_chain_proof);
        let list = agg_list_proof.unwrap_or(&self.agg_list_dummy);
        pw.set_proof_with_pis_target(&self.agg_list_proof, list);
        self.prover.set_witness(&mut pw, prover);

        self.data
            .prove(pw)
            .map_err(|e| ValidityCircuitError::FailedToProve(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), ValidityCircuitError> {
        self.data.verify(proof.clone()).map_err(|e| {
            ValidityCircuitError::ProofVerificationError(format!("Failed to verify proof: {:?}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::{
            test_utils::block_witness_generator::BlockWitnessGenerator,
            validity::block_hash_chain::{
                block_chain_pis::BlockChainPublicInputs,
                block_hash_chain_processor::BlockHashChainProcessor,
            },
        },
        ethereum_types::{address::Address, bytes32::Bytes32},
        utils::conversion::ToU64,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_validity_circuit() {
        let supported_user_counts = vec![2];
        let mut generator = BlockWitnessGenerator::new(&supported_user_counts);
        let initial_state = generator.current_extended_public_state();

        let channel_id = 1;
        // Use empty key_ids (all-padding) to bypass SPHINCS+ signature constraints.
        let key_ids: Vec<u32> = vec![];
        let timestamp = 42u64;
        let tx_tree_root = Bytes32::default();
        generator
            .add_block(channel_id, &key_ids, timestamp, tx_tree_root)
            .expect("add block");

        let block_number = generator.block_number;
        let block_witness = generator
            .block_chain_witness
            .get(&block_number)
            .cloned()
            .expect("block witness");

        let processor = BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
        let block_hash_chain_proof = processor
            .prove_block(Some(initial_state.clone()), None, &block_witness)
            .expect("block hash chain proof");
        let block_chain_vd = processor.block_chain_vd();

        // Phase 4 acceptance: a span with ZERO signing blocks still takes the DUMMY-PROOF path.
        // All-padding key_ids ⇒ no signing event ⇒ final.bp_sig_chain == 0 ⇒ the list proof is
        // `None` and its conditional verification is gated off. The verifier data is now the
        // AGGREGATE list's; the dummy proof is reconstructed from its `common`.
        use crate::falcon_sig::{agg::FalconAggCircuit, agg_list::AggListCircuit};
        let agg = FalconAggCircuit::<F, C, D>::new();
        let agg_list = AggListCircuit::<F, C, D>::new(&agg.verifier_data());

        let validity_circuit =
            ValidityCircuit::<F, C, D>::new(&block_chain_vd, &agg_list.verifier_data());
        println!(
            "MEASURE validity degree=2^{} (agg_list wrapper 2^{})",
            validity_circuit.data.common.degree_bits(),
            agg_list.cyclic.data.common.degree_bits(),
        );
        // SECURITY / Phase 0 gate (small-block N-of-N design §9 Phase 0, §12 flag 3): the MLE
        // wrapper and every committed on-chain VK are shaped by this degree. There is no
        // `CommonCircuitData` assert protecting `ValidityCircuit` — this pin is the only thing that
        // makes a shape change loud rather than silently invalidating the wrapper. 2^14 is the
        // aggregate-list wrapper's degree, byte-identical to the retired single-signature list
        // wrapper's, which is what makes the Phase 4 swap a verifier-key change only.
        assert_eq!(
            validity_circuit.data.common.degree_bits(),
            16,
            "ValidityCircuit must stay at 2^16 (Phase 0 decision gate)"
        );
        assert_eq!(
            agg_list.cyclic.data.common.degree_bits(),
            14,
            "the agg-list cyclic wrapper must stay at the hash-chain template's 2^14"
        );
        let prover = Address::default();
        let validity_proof = validity_circuit
            .prove(&block_hash_chain_proof, None, prover)
            .expect("validity proof");
        validity_circuit
            .verify(&validity_proof)
            .expect("validity proof verifies");

        let config = &block_chain_vd.common.config;
        let block_chain_inputs = BlockChainPublicInputs::<F, C, D>::from_u64_slice(
            &block_hash_chain_proof.public_inputs.to_u64_vec(),
            config,
        )
        .expect("parse block chain public inputs");
        let validity_inputs = ValidityPublicInputs::from_states(
            &block_chain_inputs.initial_ext_public_state,
            &block_chain_inputs.ext_public_state,
            prover,
        );
        let expected_hash = validity_inputs.hash();
        let expected_public_inputs: Vec<F> = expected_hash
            .to_u32_vec()
            .into_iter()
            .map(F::from_canonical_u32)
            .collect();

        assert_eq!(validity_proof.public_inputs, expected_public_inputs);
    }
}
