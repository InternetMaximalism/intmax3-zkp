//! Falcon-512/Poseidon signature **list proof** (validity path, falcon-sig Phase 3).
//!
//! Accumulates DIRECTLY-VERIFIED Falcon signatures into the SAME order-sensitive Poseidon hash
//! chain the retired `SingleSigCircuit`-based list produced (format-stable, see
//! [`crate::poseidon_sig::list`]):
//!   - `leaf_i  = Poseidon([LIST_LEAF_DOMAIN] ‖ m_i ‖ pk_i)`
//!   - `C_0     = 0` (the empty chain)
//!   - `C_i     = Poseidon(C_{i-1} ‖ leaf_i)`   (two-to-one)
//!
//! The final `C_N` (a `Bytes32`) commits to the exact ordered multiset of `(m, pk)` pairs that were
//! each backed by an in-circuit-verified Falcon-512/Poseidon signature. The consumer (the validity
//! circuit) recursively verifies the list proof, rebuilds the same chain from the `(m, pk)` pairs
//! it requires (`update_channel_tree`'s `bp_sig_chain` fold), and asserts equality — so it learns
//! "these messages were signed by these keys" without re-running any signature check.
//!
//! # What changed in Phase 3 (and what did NOT)
//!
//! BEFORE: [`ListStepCircuit`] recursively verified one `poseidon_sig::circuit::SingleSigCircuit`
//! proof at a constant VK and read `(pk, m)` from that proof's public inputs.
//!
//! AFTER: the step verifies ONE Falcon-512/Poseidon signature DIRECTLY with the Phase-1
//! [`FalconSigVerifyTarget`] gadget, and takes:
//!   - `pk` = the gadget's `pk_g` wire, which the gadget itself constrains to `Poseidon(IMFK ‖
//!     encode(h))` — so `pk` is a function of the witnessed public polynomial `h`, not a free
//!     witness;
//!   - `m`  = the gadget's `message_digest` input wire — the very wire `c = H2P(salt, m)` is
//!     derived from, i.e. the digest the norm bound was checked against.
//!
//! UNCHANGED, deliberately and bit-for-bit: the `leaf_target` / `chain_step_target` gadgets, the
//! `IMLL` leaf domain, the step's public-input layout `[prev_chain(8), new_chain(8)]`, the cyclic
//! wrapper, and therefore the `bp_sig_chain` accumulator semantics that
//! `update_channel_tree.rs` folds in-circuit.
//!
//! # Message binding (TM-C5 item 4)
//!
//! The step's `message_digest` is a free witness INSIDE this circuit — exactly as the SingleSig
//! proof's `m` public input was before. It is bound EXTERNALLY, by the consumer, and the binding is
//! unchanged: `update_channel_tree` recomputes the IMSB digest in-circuit
//! (`SmallBlockMessageFieldsTarget::compute_signing_digest`) and folds `(that digest, bp_pk_g)`
//! into `bp_sig_chain` with the SAME `leaf_target`/`chain_step_target` gadgets; the validity
//! circuit then asserts `C == final.bp_sig_chain`. Because the leaf hash commits to BOTH `m` and
//! `pk`, that equality forces every step's `(m, pk)` to equal the consumer's
//! `(recomputed IMSB digest, registered bp_pk_g)` pair, up to a Poseidon collision. A prover who
//! picks a different `message_digest` produces a different chain and fails the equality.
//!
//! # Cross-context isolation (TM-C6 / O-6)
//!
//! One Falcon key signs both the channel-state co-sign (IMCH digest) and the small-block root
//! (IMSB digest). The gadget verifies against whatever 32-byte digest is on its `message_digest`
//! wire, so isolation rests ENTIRELY on the two contexts recomputing distinct digests: IMCH and
//! IMSB are keccak digests over preimages that begin with distinct domain constants
//! (`CHANNEL_STATE_DOMAIN` = "IMCH" vs `SMALL_BLOCK_DOMAIN` = "IMSB") and have different field
//! layouts. Neither consumer ever accepts a caller-supplied message: close/cancel-close connect the
//! aggregation's `message` PI to their in-circuit-recomputed IMCH digest, and the validity path
//! binds this chain to its in-circuit-recomputed IMSB digest. Test:
//! `tests::imch_and_imsb_signatures_reject_in_both_directions`.
//!
//! # No lookups
//!
//! The Falcon gadget uses BINARY range checks only. Phase 2.5's lookup approach was REJECTED as
//! unsound (`doc/tasks/falcon-sig-phase2_5-notes.md`); reintroducing lookups here would also break
//! the validity circuit's `DummyProof::new(&list_vd.common)` reconstruction.

use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::gadget::{FalconSigGadgetWitness, FalconSigVerifyTarget};
use crate::{
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
    },
    poseidon_sig::list::{chain_step_target, leaf_target},
    utils::hash_chain::cyclic_chain_circuit::CyclicChainCircuit,
};

// ----------------------------------------------------------------------------------------------
// In-circuit per-step chain folder: verify ONE Falcon signature, fold its (m, pk) into the chain.
// ----------------------------------------------------------------------------------------------

/// One list step: verify one Falcon-512/Poseidon signature in-circuit and fold its `(m, pk)` into
/// the running chain. Public inputs: `[prev_chain(8), new_chain(8)]` — the exact `(prev_hash,
/// hash)` shape [`CyclicChainCircuit`] chains, unchanged from the retired recursive step.
pub struct ListStepCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    sig: FalconSigVerifyTarget,
    prev_chain: Bytes32Target,
    /// Builder gate count before padding (reported alongside `data.common.degree_bits()`).
    pub num_gates_before_padding: usize,
}

impl<F, C, const D: usize> Default for ListStepCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> ListStepCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // SECURITY: the UNCONDITIONAL gadget — there is no `verify` gate wire in this circuit at
        // all, so the norm bound (the sole accept/reject decision of Falcon) is always live. A
        // step proof therefore exists only if a genuine Falcon signature over `message_digest`
        // under `pk_g` exists. (The retired step got the same guarantee from a recursive
        // `SingleSigCircuit` proof at a constant VK.)
        let sig = FalconSigVerifyTarget::new(&mut builder);

        // `pk` is the gadget's own `pk_g` wire — constrained INSIDE the gadget to
        // `Poseidon(IMFK ‖ encode(h))`, so it is a function of the witnessed `h`, never free.
        // `m` is the gadget's `message_digest` input wire — the wire `c = H2P(salt, m)` (and hence
        // the norm bound) is computed from. There is no free witness between "what was signed" and
        // "what is folded into the chain".
        //
        // leaf = Poseidon([LIST_LEAF_DOMAIN] ‖ m ‖ pk) — the SHARED gadget, identical to the
        // consumer's fold in `update_channel_tree.rs`.
        let leaf = leaf_target(&mut builder, &sig.message_digest, &sig.pk_g);

        // new_chain = Poseidon(prev_chain ‖ leaf). `to_hash_out` enforces that prev_chain is a
        // valid hash-out-derived Bytes32 (it always is: 0 on the first step, or a previous
        // new_chain).
        let prev_chain = Bytes32Target::new(&mut builder, true);
        let prev_hashout = prev_chain.to_hash_out(&mut builder);
        let new_hashout = chain_step_target(&mut builder, prev_hashout, leaf);
        let new_chain = Bytes32Target::from_hash_out(&mut builder, new_hashout);

        builder.register_public_inputs(&prev_chain.to_vec());
        builder.register_public_inputs(&new_chain.to_vec());

        let num_gates_before_padding = builder.num_gates();
        let data = builder.build::<C>();
        // RELEASE-mode self-check: the cyclic wrapper slices these 16 PIs positionally
        // (`[0..8]` = prev, `[8..16]` = new); a layout drift must fail loudly at build time.
        assert_eq!(
            data.common.num_public_inputs,
            2 * crate::ethereum_types::bytes32::BYTES32_LEN,
            "list step public-input arity must stay [prev_chain(8), new_chain(8)]"
        );

        Self {
            data,
            sig,
            prev_chain,
            num_gates_before_padding,
        }
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.data.verifier_data()
    }

    /// Prove one chain step over `witness`'s signature. `pk_g` is NOT set from the witness: it is a
    /// DERIVED wire (connected to `Poseidon(IMFK ‖ encode(h))` inside the gadget), so witness
    /// generation produces it — a tampered `pk_g` is rejected by the in-circuit binding rather
    /// than by an early witness conflict.
    pub fn prove(
        &self,
        witness: &FalconSigGadgetWitness,
        prev_chain: Bytes32,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.sig
            .message_digest
            .set_witness::<F, Bytes32>(&mut pw, witness.message_digest);
        self.sig.set_signature_witness(&mut pw, witness)?;
        self.prev_chain
            .set_witness::<F, Bytes32>(&mut pw, prev_chain);
        self.data.prove(pw)
    }
}

// ----------------------------------------------------------------------------------------------
// The recursive list proof = the per-step folder wrapped in the cyclic chain accumulator.
// ----------------------------------------------------------------------------------------------

/// The recursive Falcon signature list proof. Its public output `[0..8]` is the running chain
/// commitment `C` (a `Bytes32`); compare it against
/// [`crate::poseidon_sig::list::list_commitment`].
///
/// SECURITY (A7): the cyclic wrapper enforces `prev_chain_i == C_{i-1}` and `C_0 == 0`, and
/// self-references its own verifier data (constant-VD), so only proofs from this circuit can
/// extend the list.
pub struct ListCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub step: ListStepCircuit<F, C, D>,
    pub cyclic: CyclicChainCircuit<F, C, D>,
}

impl<F, C, const D: usize> Default for ListCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> ListCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let step = ListStepCircuit::new();
        let cyclic = CyclicChainCircuit::new(&step.verifier_data());
        Self { step, cyclic }
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.cyclic.data.verifier_data()
    }

    /// Append one Falcon signature to the list. `prev_chain` is the running native commitment over
    /// all previously-appended pairs (`Bytes32::zero()` for the first). `prev_cyclic` is the
    /// previous list proof (`None` for the first).
    pub fn prove_append(
        &self,
        witness: &FalconSigGadgetWitness,
        prev_chain: Bytes32,
        prev_cyclic: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let step_proof = self.step.prove(witness, prev_chain)?;
        self.cyclic
            .prove(&step_proof, prev_cyclic)
            .map_err(|e| anyhow::anyhow!("cyclic list proof failed: {e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::validity::block_hash_chain::small_block_message::SmallBlockMessageFields,
        ethereum_types::{bytes32::BYTES32_LEN, u32limb_trait::U32LimbTrait as _},
        falcon_sig::FalconKeys,
        poseidon_sig::list::{LIST_LEAF_DOMAIN, list_commitment},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    type Step = ListStepCircuit<F, C, D>;
    type List = ListCircuit<F, C, D>;

    fn digest(byte: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_0000 | byte as u32, 9, 8, 7, 6, 5, 4, 3]).unwrap()
    }

    /// An honest gadget witness: `key` signs `message`.
    fn witness_for(key: &FalconKeys, message: Bytes32) -> FalconSigGadgetWitness {
        let sig = key.sign(message);
        FalconSigGadgetWitness::for_signature(&key.pk_coefficients(), message, &sig)
    }

    fn chain_output(proof: &ProofWithPublicInputs<F, C, D>) -> Bytes32 {
        Bytes32::from_u32_slice(
            &proof.public_inputs[0..BYTES32_LEN]
                .iter()
                .map(|f| f.0 as u32)
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    /// MEASUREMENT + structural pin: the step's gate count / degree, and — the Phase-3 risk point —
    /// that the cyclic wrapper still builds at the (much larger) step degree. `CyclicChainCircuit`
    /// asserts its own `common` equals a FIXED template (`common_data_for_hash_chain_circuit`), so
    /// a step whose recursive verification no longer fits the template panics here.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn list_step_and_cyclic_degrees() {
        let t0 = std::time::Instant::now();
        let step = Step::new();
        let step_build = t0.elapsed();
        println!(
            "MEASURE list_step gates={} degree=2^{} pis={} build={:?}",
            step.num_gates_before_padding,
            step.data.common.degree_bits(),
            step.data.common.num_public_inputs,
            step_build
        );
        let t1 = std::time::Instant::now();
        let cyclic = CyclicChainCircuit::<F, C, D>::new(&step.verifier_data());
        println!(
            "MEASURE list_cyclic degree=2^{} pis={} build={:?}",
            cyclic.data.common.degree_bits(),
            cyclic.data.common.num_public_inputs,
            t1.elapsed()
        );

        // One step proof, timed.
        let key = FalconKeys::from_seed([0x31u8; 32]);
        let w = witness_for(&key, digest(0x01));
        let t2 = std::time::Instant::now();
        let proof = step.prove(&w, Bytes32::zero()).expect("step proves");
        println!("MEASURE list_step prove={:?}", t2.elapsed());
        step.data.verify(proof).expect("step proof verifies");
    }

    /// The recursive list commits to exactly the native `(m, pk)` fold — the equality the validity
    /// circuit's `C == final.bp_sig_chain` assertion relies on. This is the native <-> in-circuit
    /// equivalence guard for the UNCHANGED chain format.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn recursive_list_matches_native_commitment() {
        let list = List::new();

        let entries: Vec<(FalconKeys, Bytes32)> = vec![
            (FalconKeys::from_seed([1u8; 32]), digest(0xa1)),
            (FalconKeys::from_seed([2u8; 32]), digest(0xa2)),
            (FalconKeys::from_seed([3u8; 32]), digest(0xa3)),
        ];
        let pairs: Vec<(Bytes32, Bytes32)> = entries.iter().map(|(k, m)| (*m, k.pk_g())).collect();

        let mut prev_cyclic: Option<ProofWithPublicInputs<F, C, D>> = None;
        for (i, (key, m)) in entries.iter().enumerate() {
            let w = witness_for(key, *m);
            let prev_chain = list_commitment(&pairs[0..i]);
            let cyclic = list
                .prove_append(&w, prev_chain, &prev_cyclic)
                .expect("append");
            assert_eq!(
                chain_output(&cyclic),
                list_commitment(&pairs[0..=i]),
                "step {i} commitment mismatch"
            );
            prev_cyclic = Some(cyclic);
        }

        let final_proof = prev_cyclic.unwrap();
        list.verifier_data()
            .verify(final_proof.clone())
            .expect("final list proof must verify");
        assert_eq!(chain_output(&final_proof), list_commitment(&pairs));
    }

    /// The cyclic wrapper forces `C_0 == 0`, so the list cannot be seeded mid-chain to hide earlier
    /// entries (A8 truncation guard). Unchanged from the retired step; re-pinned because the step
    /// circuit was rewritten.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn first_step_must_start_from_zero_chain() {
        let list = List::new();
        let key = FalconKeys::from_seed([0x21; 32]);
        let m = digest(0xc0);
        // A real, reducible, non-zero commitment: the step itself proves fine; the cyclic
        // first-step zero-check is what must reject it.
        let bogus_prev = list_commitment(&[(digest(0xee), key.pk_g())]);
        let w = witness_for(&key, m);
        assert!(
            list.prove_append(&w, bogus_prev, &None).is_err(),
            "first step must start from a zero chain"
        );
    }

    /// A mismatched `prev_chain` must break the recursion (the cyclic circuit connects the step's
    /// `prev_chain` PI to the previous proof's output).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn list_step_rejects_wrong_prev_chain() {
        let list = List::new();
        let k0 = FalconKeys::from_seed([7u8; 32]);
        let m0 = digest(0xb0);
        let cyclic0 = list
            .prove_append(&witness_for(&k0, m0), Bytes32::zero(), &None)
            .expect("first append");

        let k1 = FalconKeys::from_seed([8u8; 32]);
        let bad = list.prove_append(
            &witness_for(&k1, digest(0xb1)),
            Bytes32::zero(), // lie: should be C_1
            &Some(cyclic0),
        );
        assert!(
            bad.is_err(),
            "mismatched prev_chain must break the cyclic chain"
        );
    }

    /// TM-C5 item 4 at the step level: the folded `message_digest` is the digest the norm bound was
    /// checked against. Presenting a signature over `m1` while claiming `m2` is unprovable — this
    /// is the property that makes the consumer's `C == final.bp_sig_chain` equality a genuine
    /// message binding rather than a bookkeeping check.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn step_rejects_signature_over_a_different_message() {
        let step = Step::new();
        let key = FalconKeys::from_seed([0x41u8; 32]);
        let mut w = witness_for(&key, digest(0x10));
        w.message_digest = digest(0x11); // claim a different message with the same signature
        assert!(
            step.prove(&w, Bytes32::zero()).is_err(),
            "a signature over another message must not fold into the chain"
        );
    }

    /// TM-C6 / O-6 — CROSS-CONTEXT ISOLATION UNDER ONE KEY, in BOTH directions, at the level the
    /// circuits actually consume.
    ///
    /// ONE Falcon key signs both the channel-state co-sign (IMCH digest, consumed by the close /
    /// cancel-close `FalconAggCircuit` leaf) and the small-block root (IMSB digest, consumed by
    /// this list step). Isolation rests entirely on the two digests being distinct keccak outputs
    /// under distinct domain constants, and on every verifier recomputing the digest for ITS OWN
    /// context instead of accepting a caller-supplied message.
    ///
    /// Direction 1: the IMCH signature presented to the IMSB list step (claiming the IMSB digest)
    /// must be unprovable.
    /// Direction 2: the IMSB signature presented to the close-context aggregation leaf (claiming
    /// the IMCH digest) must be unprovable.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn imch_and_imsb_signatures_reject_in_both_directions() {
        use crate::{
            circuits::channel::close_circuit::test_fixture::final_state_n,
            falcon_sig::agg::FalconLeafCircuit,
        };

        let key = FalconKeys::from_seed([0x77u8; 32]);

        // A REAL IMCH digest (`ChannelState::signing_digest`, domain "IMCH").
        let imch = final_state_n(3, Bytes32::default()).signing_digest();
        // A REAL IMSB digest (`SmallBlockMessageFields::signing_digest`, domain "IMSB"), whose
        // preimage even carries this key's own pk_g.
        let imsb = SmallBlockMessageFields {
            bp_member_slot: 0,
            bp_pk_g: key.pk_g(),
            small_block_number: 0,
            prev_small_block_root: Bytes32::default(),
            state_commitment_root: digest(0x55),
            medium_epoch_hint: 0,
            close_freeze_nonce: 0,
        }
        .signing_digest(1, digest(0x56));
        assert_ne!(imch, imsb, "the two context digests must differ");

        let sig_imch = key.sign(imch);
        let sig_imsb = key.sign(imsb);
        let h = key.pk_coefficients();

        // Sanity: each signature is valid in its OWN context (native predicate).
        assert!(crate::falcon_sig::verify(&h, imch, &sig_imch));
        assert!(crate::falcon_sig::verify(&h, imsb, &sig_imsb));
        // ... and invalid in the other, natively.
        assert!(!crate::falcon_sig::verify(&h, imsb, &sig_imch));
        assert!(!crate::falcon_sig::verify(&h, imch, &sig_imsb));

        // Direction 1 — IMCH signature replayed into the IMSB (validity) list step.
        let step = Step::new();
        let mut cross = FalconSigGadgetWitness::for_signature(&h, imch, &sig_imch);
        cross.message_digest = imsb;
        assert!(
            step.prove(&cross, Bytes32::zero()).is_err(),
            "an IMCH co-sign signature must not fold into the IMSB bp_sig_chain"
        );
        // Control: the genuine IMSB signature DOES fold at the same step.
        let honest = FalconSigGadgetWitness::for_signature(&h, imsb, &sig_imsb);
        let ok = step
            .prove(&honest, Bytes32::zero())
            .expect("honest IMSB step");
        step.data.verify(ok).expect("honest step verifies");
        drop(step);

        // Direction 2 — IMSB signature replayed into the close-context aggregation leaf.
        let leaf = FalconLeafCircuit::<F, C, D>::new();
        let mut cross_back = FalconSigGadgetWitness::for_signature(&h, imsb, &sig_imsb);
        cross_back.message_digest = imch;
        assert!(
            leaf.prove(&cross_back).is_err(),
            "an IMSB small-block signature must not aggregate as an IMCH co-signature"
        );
        // Control: the genuine IMCH signature DOES aggregate.
        let honest_imch = FalconSigGadgetWitness::for_signature(&h, imch, &sig_imch);
        let ok = leaf.prove(&honest_imch).expect("honest IMCH leaf");
        leaf.data.verify(ok).expect("honest leaf verifies");
    }

    /// Cheap native pin of the chain format the step must keep producing (no proving).
    #[test]
    fn chain_format_is_unchanged_and_order_sensitive() {
        let a = (digest(1), digest(0x10));
        let b = (digest(2), digest(0x20));
        assert_eq!(list_commitment(&[a, b]), list_commitment(&[a, b]));
        assert_ne!(list_commitment(&[a, b]), list_commitment(&[b, a]));
        assert_ne!(list_commitment(&[a]), list_commitment(&[a, b]));
        assert_eq!(LIST_LEAF_DOMAIN, u32::from_be_bytes(*b"IMLL"));
    }
}
