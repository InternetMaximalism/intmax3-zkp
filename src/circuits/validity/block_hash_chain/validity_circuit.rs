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
            add_proof_target_and_conditionally_verify_cyclic, add_proof_target_and_verify_cyclic,
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
    /// folds into `bp_sig_chain`). This is a lifetime proof from genesis, not a proof local to the
    /// current validity span. It is verified CONDITIONALLY (gated on the computed
    /// `final.bp_sig_chain != 0`, decision D3), including when the span starts from a non-zero
    /// signature-chain head.
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
        // validity span's `final.bp_sig_chain` is a LIFETIME commitment accumulated from genesis,
        // not a span-local commitment. When it is non-zero we MUST verify the cumulative list proof
        // and assert its commitment equals the accumulator (so every folded statement was a
        // verified N-of-N Falcon aggregate — A8 truncation guard). This remains mandatory when
        // `initial.bp_sig_chain` is already non-zero, and even for a later span that adds no new
        // signing event. Only a lifetime-empty chain may use the dummy proof.
        //
        // SECURITY: the gate is the COMPUTED final.bp_sig_chain (an accumulated value bound to the
        // per-block IMCH digest / signer_count / pk_list_digest wires by `update_channel_tree`),
        // NOT a prover flag — so a prover cannot turn the list verification off while still having
        // applied a signed update. Re-tested, not assumed, by
        // `tests/small_block_sig_validity.rs::inter_channel_small_block_sig_is_validity_proven`
        // and the cross-span truncation cases in `tests/validity_multispan.rs`.
        let final_bp_sig_chain = block_chain_pis.ext_public_state.bp_sig_chain.clone();
        // Do NOT constrain `initial.bp_sig_chain` to zero. A validity proof is allowed to begin at
        // any finalized extended state. The cumulative AggList proof still starts at genesis and
        // its final commitment is bound below to this span's computed final chain. Requiring zero
        // here made the second finalized span unprovable after the first signing block.
        let chain_is_zero = final_bp_sig_chain.is_zero::<F, D, Bytes32>(&mut builder);
        let should_verify_list = builder.not(chain_is_zero);
        // SECURITY (code review 2026-10-15, finding C1): the agg-list proof is a CYCLIC proof. Its
        // predecessor was verified inside the list circuit against the verifier data carried in
        // the proof's own public inputs, so those public inputs MUST be connected to the constant
        // `agg_list_vd` here — exactly as the block-chain proof above and the deposit/registration
        // chains in `block_step` do. The plain conditional helper verified the proof under the
        // constant key but left its verifier-data public inputs free: a prover could then seed
        // the chain from a `dummy_circuit` predecessor claiming any `C_{k-1}` and fold only the
        // last signing block's real aggregate, skipping every earlier block's N-of-N check while
        // still matching `final.bp_sig_chain`. Pinned by
        // `a_signature_list_seeded_from_a_dummy_predecessor_is_refused`. The dummy path (no
        // signing block, `should_verify_list == false`) is unaffected: the connection is gated.
        let agg_list_proof = add_proof_target_and_conditionally_verify_cyclic(
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
    /// (`falcon_sig::agg_list::AggListCircuit`) over every signing block since genesis; it MUST be
    /// `Some` exactly when `final.bp_sig_chain != 0`. For a span whose initial chain is already
    /// non-zero this means passing the previously accumulated proof, extended with any new signing
    /// events. When `None`, the dummy proof is supplied and the conditional list verification is
    /// gated off only for a lifetime-empty chain.
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

    /// SECURITY regression (code review 2026-10-15, finding C1 — agg-list verifier data).
    ///
    /// The N-of-N signature evidence of a span is the cyclic `AggListCircuit` proof. A cyclic
    /// circuit verifies its PREDECESSOR against the verifier data carried in its OWN public
    /// inputs, so a prover who is free to choose those public inputs can seed the chain from a
    /// `dummy_circuit` proof claiming any `C_{k-1}` and fold only the LAST signing block's real
    /// aggregate. The resulting list proof is a genuine proof of the cyclic circuit — plain
    /// verification under the agg-list key accepts it — and its commitment equals the span's
    /// `final.bp_sig_chain`. Only connecting the proof's verifier-data public inputs to the
    /// constant agg-list key (`add_proof_target_and_conditionally_verify_cyclic`) refuses it.
    ///
    /// Span: registration block, then TWO real N-of-N signing blocks. The forged list skips the
    /// first block's aggregate entirely. The validity circuit must not accept it.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a_signature_list_seeded_from_a_dummy_predecessor_is_refused() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        use plonky2::recursion::{
            cyclic_recursion::check_cyclic_proof_verifier_data,
            dummy_circuit::{cyclic_base_proof, dummy_circuit},
        };
        use rand::SeedableRng as _;
        use rand010::SeedableRng as _;

        use crate::{
            circuits::test_utils::block_witness_generator::{BlockTxV2Witness, ChannelMemberKeys},
            common::{
                balance_state::BalanceState,
                channel_id::ChannelId,
                transfer::Transfer,
                trees::{transfer_tree::TransferTree, tx_v2_tree::TxV2Tree},
                tx::{TxClass, TxV2},
                u63::BlockNumber,
            },
            ethereum_types::u256::U256,
            falcon_sig::{
                agg::{FalconAggCircuit, FalconAggWitness},
                agg_list::{AggListCircuit, AggListEntry, agg_list_commitment},
            },
            regev::encrypt_amount,
            utils::poseidon_hash_out::PoseidonHashOut,
            wallet_core::MemberKeys,
        };

        const CHANNEL: u32 = 1;
        let supported = vec![2];
        let processor = BlockHashChainProcessor::<F, C, D>::new(&supported);
        let block_chain_vd = processor.block_chain_vd();
        let mut g = BlockWitnessGenerator::new(&supported);
        let initial_ext_state = g.current_extended_public_state();
        let channel_id = ChannelId::new(CHANNEL as u64).unwrap();

        // Three real members; the channel is registered with exactly their Falcon keys.
        let mut crng = rand010::rngs::StdRng::seed_from_u64(0xC1);
        let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut crng)).collect();
        let ck = ChannelMemberKeys::from_member_keys(&keys);
        g.add_channel_registration_keys(CHANNEL, ck);
        g.add_registration_block(0).expect("registration block");

        // One synthetic post-debit H1' reused by both signing blocks (its content is not what this
        // test is about; the generator only needs a nonzero IMSB state commitment to sign).
        let pks: Vec<_> = keys.iter().map(|k| k.regev_pk.clone()).collect();
        let enc: Vec<_> = (0..3)
            .map(|i| encrypt_amount(&mut crng, &pks[i], [45u64, 10, 30][i]).unwrap().0)
            .collect();
        let regev_pk_digests: Vec<Bytes32> = keys
            .iter()
            .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
            .collect();
        let post_balance_state = BalanceState {
            channel_id,
            member_count: 3,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances_token0(&enc),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&regev_pk_digests),
            recipients: BalanceState::pad_recipients(
                &(0..3u32)
                    .map(|i| Address::from_u32_slice(&[0x7E57_0000u32 + i; 5]).unwrap())
                    .collect::<Vec<_>>(),
            ),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: crate::wallet_core::empty_settled_tx_accumulator_root(),
            state_version: 1,
            pending_adds: BalanceState::pad_pending_adds_token0(&[0, 0, 0]),
            token_registry: BalanceState::single_token_registry(0),
            token_count: 1,
        };
        let h1: Bytes32 = post_balance_state.h1();

        // Two real signing blocks for the channel: distinct transfers, consecutive nonces, the
        // TxV2 at the channel's own tx-tree index.
        let mut brng = rand::rngs::StdRng::seed_from_u64(7);
        // The registered channel leaf starts at send index 0, so the nonces are 0 then 1.
        for (round, nonce) in [(1u64, 0u32), (2u64, 1u32)] {
            let mut transfer_tree = TransferTree::init();
            transfer_tree.push(Transfer {
                recipient: Bytes32::rand(&mut brng),
                token_index: 0,
                amount: U256::from(5u32 * round as u32),
                aux_data: Bytes32::default(),
            });
            let tx_v2 = TxV2 {
                tx_class: TxClass::UserTransfer,
                transfer_tree_root: transfer_tree.get_root(),
                nonce,
                channel_action_root: PoseidonHashOut::default(),
            };
            let mut tx_v2_tree = TxV2Tree::init();
            tx_v2_tree.update(channel_id.as_u64(), tx_v2);
            let tx_tree_root: Bytes32 = tx_v2_tree.get_root().into();
            let tx_v2_proof = tx_v2_tree.prove(channel_id.as_u64());
            let witness = BlockTxV2Witness {
                tx_v2_indices: vec![channel_id.as_u64(), 0],
                tx_v2s: vec![tx_v2, TxV2::default()],
                tx_v2_merkle_proofs: vec![tx_v2_proof.clone(), tx_v2_proof],
                new_member_leaves: None,
                channel_action_indices: None,
                channel_actions: None,
                channel_action_merkle_proofs: None,
            };
            g.next_imsb_state_commitment_root = Some(h1);
            g.add_block_with_tx_v2(CHANNEL, &[1], round, tx_tree_root, Some(witness))
                .expect("real signing block");
        }
        assert_eq!(g.bp_sig_events.len(), 2, "two signing events were folded");

        // The real block-hash-chain proof over [registration, signing 1, signing 2].
        let mut prev_block_proof = None;
        for idx in 1..=g.block_number.as_u64() {
            let bn = BlockNumber::new(idx).unwrap();
            let witness = g.block_chain_witness.get(&bn).cloned().expect("block witness");
            let init = if prev_block_proof.is_none() {
                Some(initial_ext_state.clone())
            } else {
                None
            };
            let proof = processor
                .prove_block(init, prev_block_proof.clone(), &witness)
                .expect("block hash chain proof");
            prev_block_proof = Some(proof);
        }
        let final_block_chain_proof = prev_block_proof.expect("final block chain proof");
        let final_bp_sig_chain = g.current_bp_sig_chain();
        assert_ne!(final_bp_sig_chain, Bytes32::default());

        let agg = FalconAggCircuit::<F, C, D>::new();
        let agg_list = AggListCircuit::<F, C, D>::new(&agg.verifier_data());
        let validity_circuit =
            ValidityCircuit::<F, C, D>::new(&block_chain_vd, &agg_list.verifier_data());
        let prover = Address::rand(&mut brng);

        // Sanity: the HONEST two-step list proves the span.
        let honest_list = g
            .build_agg_sig_list_proof(&agg, &agg_list)
            .expect("honest list")
            .expect("a signing span has a list");
        let honest = validity_circuit
            .prove(&final_block_chain_proof, Some(&honest_list), prover)
            .expect("the honest list proves the span");
        validity_circuit.verify(&honest).expect("honest validity proof verifies");

        // The forgery: seed the chain at C_1 (the chain AFTER the first block's statement, which
        // anyone can compute from the public statements) with a dummy-circuit predecessor, and
        // fold only the second block's real aggregate on top.
        let entries: Vec<AggListEntry> = g.bp_sig_events.iter().map(|e| e.entry()).collect();
        let c1 = agg_list_commitment(&entries[0..1]);
        let last = &g.bp_sig_events[1];
        let agg_proof_2 = agg
            .prove(&FalconAggWitness {
                message: last.digest,
                active: last.witnesses.clone(),
            })
            .expect("real aggregate for the last signing block");
        let step_2 = agg_list
            .step
            .prove(&agg_proof_2, c1)
            .expect("the step folds any claimed prev_chain");
        let common = &agg_list.cyclic.data.common;
        let dummy = dummy_circuit::<F, C, D>(common);
        // plonky2's map type (hashbrown); build it by collecting into the parameter's type.
        let seed = c1
            .to_u32_vec()
            .into_iter()
            .enumerate()
            .map(|(i, limb)| (i, F::from_canonical_u32(limb)))
            .collect();
        let dummy_prev = cyclic_base_proof::<F, C, D>(common, &dummy.verifier_only, seed);
        let forged = agg_list
            .cyclic
            .prove_with_verifier_data_public_inputs(&step_2, &dummy_prev, &dummy.verifier_only)
            .expect("the cyclic step accepts a self-consistent dummy predecessor");

        // It IS a valid proof of the agg-list circuit, its commitment IS the span's chain, and only
        // the verifier-data public inputs betray it.
        agg_list
            .verifier_data()
            .verify(forged.clone())
            .expect("plain verification cannot see the forgery");
        let forged_commitment = Bytes32::from_u32_slice(
            &forged.public_inputs[0..BYTES32_LEN]
                .iter()
                .map(|f| f.0 as u32)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(forged_commitment, final_bp_sig_chain);
        assert!(
            check_cyclic_proof_verifier_data(&forged, &agg_list.cyclic.data.verifier_only, common)
                .is_err(),
            "the forged list carries foreign verifier data in its public inputs"
        );

        // The validity circuit must refuse it: either proving fails (the connected verifier data
        // mismatch is an unsatisfiable constraint) or the produced proof does not verify.
        let attempt = catch_unwind(AssertUnwindSafe(|| {
            validity_circuit.prove(&final_block_chain_proof, Some(&forged), prover)
        }));
        let rejected = match attempt {
            Err(_) => true,
            Ok(Err(_)) => true,
            Ok(Ok(proof)) => validity_circuit.verify(&proof).is_err(),
        };
        assert!(
            rejected,
            "a signature list seeded from a dummy predecessor was accepted: the first signing \
             block's N-of-N signatures were never verified"
        );
    }
}
