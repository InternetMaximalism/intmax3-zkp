//! Phase-2.6 Falcon-512/Poseidon signature AGGREGATION — BINARY-TREE recursion.
//!
//! NOTE (2026-08-15): the close / cancel-close provers now use
//! [`super::batch::FalconBatchAggCircuit`] — ONE flat circuit with a batched (random-evaluation)
//! product check instead of per-leaf NTTs — which proves all 16 signatures ~10x faster at the
//! SAME 137-element public-input contract defined here. This tree is retained as the audited
//! fallback and as the owner of the shared layout constants / `FalconAggWitness` type.
//!
//! This module restores the RETIRED `poseidon_sig::aggregate` binary-tree aggregator
//! (`git show e0dec8b:src/poseidon_sig/aggregate.rs`), instantiated for Falcon-512/Poseidon. It
//! replaces the Phase-2 FLAT `FalconAggCircuit`, which verified all `MAX_COSIGNERS` signatures in
//! ONE degree-2^20 circuit and therefore needed ~22 GB peak RSS just to build and prove.
//!
//! Memory is (roughly) linear in circuit DEGREE — every polynomial is stored at 8x its degree
//! (LDE blowup) across ~220 polynomials — so the fix is structural: split the 16 signatures across
//! 16 SMALL leaf circuits and recombine them with 4 SMALL recursion levels. No leaf or level
//! exceeds 2^17, and only one circuit proves at a time.
//!
//! ```text
//!   leaf (1 Falcon signature)        -> 1 slot   ("level 0" layout)
//!   level 1: 2 leaves                -> 2 slots
//!   level 2: 2 level-1 nodes         -> 4 slots
//!   level 3: 2 level-2 nodes         -> 8 slots
//!   level 4: 2 level-3 nodes         -> 16 slots   == MAX_COSIGNERS
//! ```
//!
//! # Public-input layout (canonical, level `k`, `0 <= k <= AGG_LEVELS`)
//!
//! ```text
//!   [ message (8 u32 limbs) | signer_count (1) | pk_g_0 (8) | ... | pk_g_{2^k - 1} (8) ]
//! ```
//!
//! total `falcon_agg_public_inputs_len(k)` field elements. The LEAF uses the SAME layout at
//! `k = 0` (`[message(8), signer_count = 1, pk_g(8)]`, 17 elements) — a deliberate simplification
//! over the retired aggregator, whose leaf (`SingleSigCircuit`) had a bespoke `[pk(8), m(8)]`
//! layout that forced a level-1 special case in `child_pis`. Here every level parses its children
//! identically.
//!
//! The TOP level (`k = AGG_LEVELS = 4`) exposes EXACTLY the Phase-2 contract the close /
//! cancel-close circuits already consume: `FALCON_AGG_MSG_OFFSET = 0`,
//! `FALCON_AGG_COUNT_OFFSET = 8`, `FALCON_AGG_PK_LIST_OFFSET = 9`,
//! `FALCON_AGG_PUBLIC_INPUTS_LEN = 137`. Those consumers change by a VERIFIER-KEY swap ONLY; their
//! member-set commitment, A5 distinctness chain and MLE wrapper are untouched.
//!
//! # Padding design (non-power-of-2 signer counts) — mirrored from the retired design
//!
//! Each aggregation node takes a boolean witness `is_right_present`:
//!   - The LEFT child proof is ALWAYS verified unconditionally (`add_proof_target_and_verify`).
//!   - The RIGHT child proof is verified via `add_proof_target_and_conditionally_verify`: when
//!     `is_right_present = 1` it is verified against the REAL child verifier data; when
//!     `is_right_present = 0` the prover supplies a canonical dummy proof, verified against the
//!     dummy circuit's verifier data (so the proof slot is well-formed but carries no cryptographic
//!     claim, and its public inputs are UNTRUSTED).
//!
//! Every value read from the right child is gated by `is_right_present` before it can influence a
//! public input or a constraint:
//!   - exposed right pk_g slots   = `is_right_present * right.pk_limb`  (zeros when absent),
//!   - exposed `signer_count`     = `left.count + is_right_present * right.count`,
//!   - message equality           = `is_right_present * (left.m_limb - right.m_limb) == 0`
//!     (enforced when present, vacuous when absent).
//!
//! SECURITY (padding soundness):
//!   - A prover cannot smuggle a padding slot in as a real signer: incrementing `signer_count`
//!     requires `is_right_present = 1`, which forces the right proof to verify against the REAL
//!     child verifier data (a dummy proof fails that check — `select_verifier_data` picks the real
//!     VK when the flag is 1). By induction (a leaf proof exposes the CONSTANT count 1 and carries
//!     an UNCONDITIONALLY verified Falcon signature), `signer_count` equals the number of genuinely
//!     verified Falcon signatures in the tree.
//!   - `signer_count >= 1` is STRUCTURAL, not asserted: the left child is verified unconditionally
//!     at every level and a leaf's count is the constant 1, so by induction every node's count is
//!     `>= 1`. This is the invariant the flat Phase-2 circuit lost (and had to restore with an
//!     explicit `assert_one`); the tree gets it back for free. The consumers' own `assert_one`
//!     checks on `signer_count` are KEPT as defence in depth (they cost one gate).
//!   - A prover cannot smuggle a real signer in as padding at a NONZERO slot: with
//!     `is_right_present = 0` the exposed right slots are identically zero, byte-identical to the
//!     native `close_member_set_commitment` zero padding. A real leaf pk_g is `Poseidon(IMFK ||
//!     encode(h))`, so a zero pk_g would require a Poseidon preimage of the all-zero digest.
//!   - LEFT-PACKING: `is_right_present ⟹ count_l == 2^{level-1}` (the left child is FULL). Without
//!     it two half-full nodes could produce `[pk0, 0, pk2, 0]` with count 2 — a ZERO pk in a
//!     NON-suffix slot, breaking every consumer that reads "the first `signer_count` slots" as the
//!     signer set. With it, by induction the nonzero pk_g list is exactly the first `signer_count`
//!     slots and the zero padding is strictly a suffix.
//!   - There is NO witnessed freedom in the exposed list: `message`, `signer_count` and every pk_g
//!     slot are wired functions of the two (verified) children's public inputs and the boolean
//!     flag. The only witnesses of an aggregation node are the two child proofs and
//!     `is_right_present` (constrained boolean via `add_virtual_bool_target_safe`).
//!   - Signer DISTINCTNESS is intentionally NOT enforced here: the same leaf proof may be placed in
//!     two slots, each backed by its own verification. Deduplication / pk-in-member-set checks are
//!     CONSUMER obligations (threat model A5/A8) and are unchanged by this phase.
//!
//! # Message binding (TM-C5 item 4 / TM-C6)
//!
//! A leaf's exposed `message` IS the gadget's `message_digest` input wire (registered directly as
//! PI 0..8), so the signature is verified over exactly the exposed digest — no free witness on that
//! path. Each level copies `message` from its LEFT child and forces the (present) right child to
//! agree limb-by-limb, so a top-level proof's `message` is the single digest EVERY leaf signature
//! was verified against. The CONSUMER (close / cancel-close) connects that PI to its
//! in-circuit-recomputed IMCH/IMSB digest, exactly as before.
//!
//! # Verifier-data binding (A7)
//!
//! Each level bakes the PREVIOUS level's verifier data in as a CONSTANT
//! (`add_proof_target_and_verify` / `add_proof_target_and_conditionally_verify` both call
//! `builder.constant_verifier_data`), so a level-`k` proof can only be built from genuine
//! level-`(k-1)` proofs (level 1 only from genuine leaf proofs) — a proof from any other circuit
//! with the same PI shape fails against the build-fixed VK.
//!
//! # No lookups
//!
//! The dummy-proof path (`DummyProof::new(&child_vd.common)` + `conditionally_verify_proof`)
//! reconstructs the child circuit from its `CommonCircuitData`; this works because the Falcon
//! gadget uses BINARY range checks only. Phase 2.5's lookup-table approach was REJECTED as unsound
//! (`doc/tasks/falcon-sig-phase2_5-notes.md`) and must not be reintroduced.

use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use super::{
    FALCON_N, FalconSignature,
    gadget::{FalconSigGadgetWitness, FalconSigVerifyTarget},
};
use crate::{
    constants::MAX_COSIGNERS,
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32},
        u32limb_trait::U32LimbTargetTrait as _,
    },
    utils::{
        cyclic::add_const_gate,
        dummy::DummyProof,
        recursively_verifiable::{
            add_proof_target_and_conditionally_verify, add_proof_target_and_verify,
        },
    },
};

// PUBLIC-INPUT LAYOUT (identical offsets/width to the flat Phase-2 circuit and to the retired
// `poseidon_sig::aggregate` at level 4)
// ================================================================================================

/// Number of aggregation levels above the leaf (level 4 => 16 slots == `MAX_COSIGNERS`).
pub const AGG_LEVELS: usize = 4;
const _: () = assert!(
    MAX_COSIGNERS == 1 << AGG_LEVELS,
    "AGG_LEVELS must be log2(MAX_COSIGNERS)"
);

/// Offset of the 8 message limbs (the shared IMCH/IMSB digest all signers sign).
pub const FALCON_AGG_MSG_OFFSET: usize = 0;
/// Offset of the single `signer_count` field element.
pub const FALCON_AGG_COUNT_OFFSET: usize = BYTES32_LEN;
/// Offset of the first pk_g slot; slot `i` begins at `FALCON_AGG_PK_LIST_OFFSET + i * BYTES32_LEN`.
pub const FALCON_AGG_PK_LIST_OFFSET: usize = BYTES32_LEN + 1;
/// Total public-input length of the TOP-level proof: `message(8) + count(1) + 16 * pk_g(8)` = 137.
pub const FALCON_AGG_PUBLIC_INPUTS_LEN: usize = BYTES32_LEN + 1 + MAX_COSIGNERS * BYTES32_LEN;

/// Public-input length of a level-`k` proof (`k = 0` is the LEAF layout, 17 elements).
pub const fn falcon_agg_public_inputs_len(level: usize) -> usize {
    BYTES32_LEN + 1 + (1 << level) * BYTES32_LEN
}

/// The expected public inputs of a left-packed aggregation at `level`: `signer_pks` in slot order,
/// padding slots zero-suffixed. Native reference for consumers and tests.
pub fn falcon_agg_expected_public_inputs<F: RichField>(
    level: usize,
    message: Bytes32,
    signer_pks: &[Bytes32],
) -> Vec<F> {
    use crate::ethereum_types::u32limb_trait::U32LimbTrait as _;
    assert!(level <= AGG_LEVELS, "level out of range");
    assert!(
        signer_pks.len() <= (1 << level),
        "more signers than slots at this level"
    );
    let mut pis = Vec::with_capacity(falcon_agg_public_inputs_len(level));
    pis.extend(message.to_u32_vec().into_iter().map(F::from_canonical_u32));
    pis.push(F::from_canonical_usize(signer_pks.len()));
    for pk in signer_pks {
        pis.extend(pk.to_u32_vec().into_iter().map(F::from_canonical_u32));
    }
    pis.resize(falcon_agg_public_inputs_len(level), F::ZERO);
    pis
}

// WITNESS (unchanged from the flat Phase-2 circuit — the consumer-facing contract)
// ================================================================================================

/// Prover witness for [`FalconAggCircuit`]: the shared message digest and the ACTIVE signers'
/// per-slot gadget witnesses (salt / h / s2), in slot order. `active.len()` = `signer_count`, which
/// must be in `1..=MAX_COSIGNERS`; the remaining slots become ABSENT subtrees (their exposed pk_g
/// is provably zero and they contribute 0 to `signer_count`).
#[derive(Debug, Clone)]
pub struct FalconAggWitness {
    pub message: Bytes32,
    pub active: Vec<FalconSigGadgetWitness>,
}

impl FalconAggWitness {
    /// Builds the witness from the active signers' public polynomials + native signatures over
    /// `message` (slot order). Each `(h, sig)` becomes a [`FalconSigGadgetWitness::for_signature`].
    ///
    /// SECURITY (message binding): `message` MUST be the caller's domain-separated IMCH/IMSB
    /// digest; each signature must have been produced over exactly this digest, or the leaf's
    /// (unconditional) norm bound rejects it.
    pub fn for_signatures(
        message: Bytes32,
        signers: &[(&[u16; FALCON_N], &FalconSignature)],
    ) -> Self {
        let active = signers
            .iter()
            .map(|(h, sig)| FalconSigGadgetWitness::for_signature(h, message, sig))
            .collect();
        Self { message, active }
    }
}

// LEAF CIRCUIT
// ================================================================================================

/// Verifies ONE Falcon-512/Poseidon signature with the Phase-1 gadget and exposes the canonical
/// "level 0" statement `[message(8), signer_count = 1, pk_g(8)]`.
///
/// SECURITY: the gadget is the UNCONDITIONAL [`FalconSigVerifyTarget::new`] — there is no
/// `verify` gate wire here at all, so a leaf proof ALWAYS carries a genuine signature. This is what
/// makes `signer_count >= 1` structural in the whole tree (the constant `1` below is the base case
/// of the induction). `message` is the gadget's own `message_digest` input wire, so the exposed
/// digest is exactly the digest the signature was verified against.
pub struct FalconLeafCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    sig: FalconSigVerifyTarget,
    /// Builder gate count before padding (reported alongside `data.common.degree_bits()`).
    pub num_gates_before_padding: usize,
}

impl<F, C, const D: usize> Default for FalconLeafCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> FalconLeafCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let sig = FalconSigVerifyTarget::new(&mut builder);

        // PI 0..8: the signed digest (the gadget's own input wire — no free witness).
        builder.register_public_inputs(&sig.message_digest.to_vec());
        // PI 8: signer_count, the CONSTANT 1 (a leaf is exactly one verified signature).
        let one = builder.one();
        builder.register_public_input(one);
        // PI 9..17: the gadget-derived pk_g = Poseidon(IMFK || encode(h)).
        builder.register_public_inputs(&sig.pk_g.to_vec());

        // Ensure a `ConstantGate` is in this circuit's gate set so level 1 can embed it via
        // `conditionally_verify_proof` (the dummy-circuit reconstruction in utils/dummy.rs always
        // emits one, and its rebuilt common data must match ours exactly). INTENTIONALLY SIMPLE:
        // one extra constant row; adds no constraints on witness values.
        add_const_gate(&mut builder);

        let num_gates_before_padding = builder.num_gates();
        let data = builder.build::<C>();
        // SECURITY (review INFO-1): a RELEASE-mode self-check. `debug_assert` here compiled out of
        // every test and production build, leaving the 137-element top-level contract guarded
        // solely by the consumers' asserts. This module now guards its own layout too.
        assert_eq!(
            data.common.num_public_inputs,
            falcon_agg_public_inputs_len(0),
            "leaf public-input arity does not match the level-0 layout"
        );

        Self {
            data,
            sig,
            num_gates_before_padding,
        }
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.data.verifier_data()
    }

    /// Proves one signature. `pk_g` is NOT set: it is a DERIVED wire (connected to
    /// `Poseidon(IMFK || encode(h))` inside the gadget), so witness generation produces it — a
    /// tampered `pk_g` is therefore rejected by the in-circuit binding rather than by an early
    /// witness conflict.
    pub fn prove(
        &self,
        witness: &FalconSigGadgetWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.sig
            .message_digest
            .set_witness::<F, Bytes32>(&mut pw, witness.message_digest);
        self.sig.set_signature_witness(&mut pw, witness)?;
        self.data.prove(pw)
    }
}

// LEVEL CIRCUIT (faithful mirror of the retired `AggLevelCircuit`)
// ================================================================================================

/// Parse a child proof's public inputs into `(message limbs, signer_count, pk slot limbs)`.
/// Uniform across levels: a level-`k` circuit's children are level-`(k-1)` proofs, and the LEAF is
/// level 0 in the same layout.
fn child_pis(level: usize, pis: &[Target]) -> (Vec<Target>, Target, Vec<Target>) {
    let slots = 1 << (level - 1);
    (
        pis[FALCON_AGG_MSG_OFFSET..FALCON_AGG_MSG_OFFSET + BYTES32_LEN].to_vec(),
        pis[FALCON_AGG_COUNT_OFFSET],
        pis[FALCON_AGG_PK_LIST_OFFSET..FALCON_AGG_PK_LIST_OFFSET + slots * BYTES32_LEN].to_vec(),
    )
}

/// One aggregation level: verifies a left child proof (always) and a right child proof
/// (conditionally), asserts message agreement, and exposes the concatenated signer list.
pub struct FalconAggLevelCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// This node's level (`1..=AGG_LEVELS`); the exposed list has `2^level` pk_g slots.
    pub level: usize,
    pub data: CircuitData<F, C, D>,
    left_proof: ProofWithPublicInputsTarget<D>,
    right_proof: ProofWithPublicInputsTarget<D>,
    is_right_present: BoolTarget,
    /// Canonical dummy proof for the child common data — set into `right_proof` when the right
    /// child is absent (`is_right_present = 0`). Its public inputs are untrusted by design; every
    /// read of the right child is gated by `is_right_present`.
    right_dummy: DummyProof<F, C, D>,
    /// Builder gate count before padding.
    pub num_gates_before_padding: usize,
}

impl<F, C, const D: usize> FalconAggLevelCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// Build the level-`level` circuit over `child_vd` (the [`FalconLeafCircuit`] verifier data for
    /// `level == 1`, the level-`(level-1)` circuit's verifier data otherwise).
    pub fn new(level: usize, child_vd: &VerifierCircuitData<F, C, D>) -> Self {
        assert!((1..=AGG_LEVELS).contains(&level), "level out of range");
        // Guard against wiring the wrong child circuit in: the child's PI length must match the
        // layout this level parses. (The real binding is the constant VK below — this is a
        // build-time sanity check, not the security mechanism.)
        assert_eq!(
            child_vd.common.num_public_inputs,
            falcon_agg_public_inputs_len(level - 1),
            "child verifier data has the wrong public-input arity for level {level}"
        );
        // SECURITY (review MINOR-1): pin the INDUCTION BASE. `child_pis` reads a child's
        // signer_count from PI `FALCON_AGG_COUNT_OFFSET`, where the retired design instead
        // injected `builder.one()` inside the level-1 circuit. The two are equivalent only while
        // the LEAF's PI 8 really is the verifier-enforced constant 1 — and the arity check above
        // would not notice a future leaf edit that kept 17 PIs but moved or freed that slot,
        // silently breaking "signer_count == number of verified signatures" with no build-time
        // signal. Re-derive the leaf's own layout constants here so such an edit fails loudly.
        const {
            assert!(FALCON_AGG_COUNT_OFFSET == BYTES32_LEN);
            assert!(falcon_agg_public_inputs_len(0) == BYTES32_LEN + 1 + BYTES32_LEN);
        }

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // SECURITY (A7): both helpers bake `child_vd` in as CONSTANT verifier data, so only proofs
        // from the genuine child circuit can be aggregated. The left child is verified
        // unconditionally; the right child only when `is_right_present = 1` (when 0, the in-circuit
        // `select_verifier_data` picks the dummy VK, and everything read from the right proof is
        // gated below).
        let left_proof = add_proof_target_and_verify(child_vd, &mut builder);
        // `_safe` constrains the flag to {0, 1} — without it, a fractional "presence" could scale
        // counts / pk_g limbs arbitrarily.
        let is_right_present = builder.add_virtual_bool_target_safe();
        let right_proof =
            add_proof_target_and_conditionally_verify(child_vd, &mut builder, is_right_present);

        let (msg_l, count_l, pks_l) = child_pis(level, &left_proof.public_inputs);
        let (msg_r, count_r, pks_r) = child_pis(level, &right_proof.public_inputs);

        // All aggregated signatures are over the SAME message: when the right child is present, its
        // message must equal the left child's, limb by limb. Gated so an absent (dummy) right child
        // imposes nothing.
        for (&l, &r) in msg_l.iter().zip(msg_r.iter()) {
            let diff = builder.sub(l, r);
            let gated = builder.mul(is_right_present.target, diff);
            builder.assert_zero(gated);
        }

        // signer_count = left.count + is_right_present * right.count. No other witness feeds this
        // value, so it counts exactly the verified leaf signatures in the tree (module doc, padding
        // soundness). `count_l >= 1` by induction (leaf count is the constant 1 and the left child
        // is verified unconditionally), so `signer_count >= 1` STRUCTURALLY.
        let gated_count_r = builder.mul(is_right_present.target, count_r);
        let signer_count = builder.add(count_l, gated_count_r);

        // SECURITY (left-packing): if the right child is PRESENT, the left child must be FULL
        // (`count_l == 2^{level-1}`). Without this, two half-full nodes could be aggregated into a
        // list with a ZERO pk_g in a NON-suffix slot (e.g. `[pk0, 0, pk2, 0]` with count 2),
        // breaking any consumer that reads "the first `signer_count` slots" as the signer set. With
        // it, by induction every exposed list is left-packed: the nonzero pk_g slots are exactly
        // the first `signer_count` and the zero padding is strictly a suffix —
        // byte-identical to the native `close_member_set_commitment` padding. Gated so an
        // absent right child imposes nothing (a lone non-full left child is fine — its own
        // padding is already a suffix by the same induction).
        let half_full = builder.constant(F::from_canonical_usize(1 << (level - 1)));
        let left_fullness_gap = builder.sub(count_l, half_full);
        let gated_gap = builder.mul(is_right_present.target, left_fullness_gap);
        builder.assert_zero(gated_gap);

        // Public inputs — fully wired from child PIs + the boolean flag; no witnessed slots. Left
        // half of the list is the left child's list verbatim; right half is the right child's list
        // gated by presence (identically zero when absent).
        builder.register_public_inputs(&msg_l);
        builder.register_public_input(signer_count);
        builder.register_public_inputs(&pks_l);
        for &t in &pks_r {
            let gated = builder.mul(is_right_present.target, t);
            builder.register_public_input(gated);
        }

        // Keep a `ConstantGate` in the gate set so the NEXT level can rebuild this circuit's dummy
        // (see the leaf's identical note).
        add_const_gate(&mut builder);

        let num_gates_before_padding = builder.num_gates();
        let data = builder.build::<C>();
        // SECURITY (review INFO-1): release-mode self-check — at level AGG_LEVELS this IS the
        // 137-element contract the close / cancel-close circuits slice blindly.
        assert_eq!(
            data.common.num_public_inputs,
            falcon_agg_public_inputs_len(level),
            "level-{level} public-input arity does not match the layout"
        );

        // Same dummy construction the switch-board / block-step circuits pair with
        // `add_proof_target_and_conditionally_verify` (utils/dummy.rs).
        let right_dummy = DummyProof::new(&child_vd.common);

        Self {
            level,
            data,
            left_proof,
            right_proof,
            is_right_present,
            right_dummy,
            num_gates_before_padding,
        }
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.data.verifier_data()
    }

    /// Aggregate `left` with an optional `right` child proof (both at this circuit's child level).
    /// `right = None` marks the right subtree absent: its slots are exposed as zeros and it
    /// contributes 0 to `signer_count`.
    pub fn prove(
        &self,
        left: &ProofWithPublicInputs<F, C, D>,
        right: Option<&ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.left_proof, left)?;
        match right {
            Some(right) => {
                pw.set_bool_target(self.is_right_present, true)?;
                pw.set_proof_with_pis_target(&self.right_proof, right)?;
            }
            None => {
                pw.set_bool_target(self.is_right_present, false)?;
                pw.set_proof_with_pis_target(&self.right_proof, &self.right_dummy.proof)?;
            }
        }
        self.data.prove(pw)
    }
}

// FACADE: the consumer-facing aggregation circuit
// ================================================================================================

/// Binary-tree aggregation of up to [`MAX_COSIGNERS`] Falcon-512/Poseidon signatures over one
/// shared message digest.
///
/// The consumer-facing API is unchanged from the flat Phase-2 circuit — `new()`,
/// `verifier_data()` (the TOP level's), `prove(&FalconAggWitness)` (returns a TOP-level proof with
/// the 137-element contract) — so close / cancel-close change by a VK swap only.
pub struct FalconAggCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub leaf: FalconLeafCircuit<F, C, D>,
    /// `levels[k-1]` is the level-`k` circuit; `levels[AGG_LEVELS-1]` is the TOP level.
    pub levels: Vec<FalconAggLevelCircuit<F, C, D>>,
}

impl<F, C, const D: usize> Default for FalconAggCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> FalconAggCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let leaf = FalconLeafCircuit::<F, C, D>::new();
        let mut levels: Vec<FalconAggLevelCircuit<F, C, D>> = Vec::with_capacity(AGG_LEVELS);
        let mut child_vd = leaf.verifier_data();
        for level in 1..=AGG_LEVELS {
            let circuit = FalconAggLevelCircuit::<F, C, D>::new(level, &child_vd);
            child_vd = circuit.verifier_data();
            levels.push(circuit);
        }
        Self { leaf, levels }
    }

    /// The TOP-level (`AGG_LEVELS`) circuit — the one whose proofs the close / cancel-close
    /// circuits recursively verify.
    pub fn top(&self) -> &FalconAggLevelCircuit<F, C, D> {
        &self.levels[AGG_LEVELS - 1]
    }

    /// The TOP-level circuit data (137 public inputs).
    pub fn data(&self) -> &CircuitData<F, C, D> {
        &self.top().data
    }

    /// The TOP-level verifier data — what consumers bake in as a constant VK.
    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.top().verifier_data()
    }

    /// The minimal aggregation level whose list can hold `n` signers (`2^k >= n`, `k >= 1`).
    /// `n = 1` still uses level 1 (right absent) because the leaf layout, while identical in shape,
    /// belongs to a DIFFERENT circuit than the one consumers verify.
    pub fn top_level_for(n: usize) -> usize {
        assert!(
            (1..=MAX_COSIGNERS).contains(&n),
            "signer count out of range"
        );
        let mut k = 1;
        while (1 << k) < n {
            k += 1;
        }
        k
    }

    /// Build the aggregation tree bottom-up over `leaf_proofs` (each a [`FalconLeafCircuit`] proof,
    /// all over the same message) and return `(top proof, top level)`. Signers are packed to the
    /// left, so the result's public inputs equal
    /// `falcon_agg_expected_public_inputs(level, message, leaf pk_gs in order)`.
    ///
    /// The same-message precheck here is prover-side convenience ONLY (fail early with a clear
    /// error instead of an unsatisfiable-witness error); the binding check is the in-circuit gated
    /// message-equality constraint in every level.
    pub fn aggregate(
        &self,
        leaf_proofs: &[ProofWithPublicInputs<F, C, D>],
    ) -> Result<(ProofWithPublicInputs<F, C, D>, usize)> {
        let n = leaf_proofs.len();
        anyhow::ensure!(
            (1..=MAX_COSIGNERS).contains(&n),
            "signer count must be in 1..={MAX_COSIGNERS}, got {n}"
        );
        let msg0 = &leaf_proofs[0].public_inputs
            [FALCON_AGG_MSG_OFFSET..FALCON_AGG_MSG_OFFSET + BYTES32_LEN];
        for (i, proof) in leaf_proofs.iter().enumerate() {
            anyhow::ensure!(
                &proof.public_inputs[FALCON_AGG_MSG_OFFSET..FALCON_AGG_MSG_OFFSET + BYTES32_LEN]
                    == msg0,
                "leaf proof {i} signs a different message"
            );
        }

        let top_level = Self::top_level_for(n);
        let mut nodes: Vec<ProofWithPublicInputs<F, C, D>> = leaf_proofs.to_vec();
        for level in 1..=top_level {
            let circuit = &self.levels[level - 1];
            let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
            for pair in nodes.chunks(2) {
                next.push(circuit.prove(&pair[0], pair.get(1))?);
            }
            nodes = next;
        }
        debug_assert_eq!(nodes.len(), 1);
        Ok((nodes.pop().unwrap(), top_level))
    }

    /// Aggregate `leaf_proofs` and then LIFT the result to the FIXED `level` (consumers verify at a
    /// build-time CONSTANT verifier key — the close / cancel-close circuits need the
    /// level-`AGG_LEVELS` (16-slot) layout regardless of `n` — and so cannot accept the minimal
    /// level, which varies with `n`).
    ///
    /// Each lift step is `level_k.prove(node, None)`: the lifted node becomes a lone LEFT child
    /// with the right subtree ABSENT. This is explicitly allowed by the left-packing rule
    /// ("right present ⟹ left child full" is vacuous when the right is absent), and it
    /// preserves the exposed statement exactly: `message` and `signer_count` are copied from
    /// the left child, the pk_g list keeps its left-packed prefix, and the new right-half slots
    /// are PROVABLY zero padding (gated by `is_right_present = 0`).
    pub fn aggregate_to_level(
        &self,
        leaf_proofs: &[ProofWithPublicInputs<F, C, D>],
        level: usize,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        assert!((1..=AGG_LEVELS).contains(&level), "level out of range");
        anyhow::ensure!(
            leaf_proofs.len() <= (1 << level),
            "more signers ({}) than slots at level {level}",
            leaf_proofs.len()
        );
        let (mut node, mut node_level) = self.aggregate(leaf_proofs)?;
        while node_level < level {
            node_level += 1;
            node = self.levels[node_level - 1].prove(&node, None)?;
        }
        Ok(node)
    }

    /// Proves the aggregation of `witness.active` signatures (slot order) over `witness.message`,
    /// returning a TOP-LEVEL (`AGG_LEVELS`) proof in the 137-element consumer contract.
    ///
    /// Leaves are proved one at a time and the tree is folded bottom-up, so peak memory is that of
    /// ONE small circuit rather than one 2^20 monolith.
    pub fn prove(&self, witness: &FalconAggWitness) -> Result<ProofWithPublicInputs<F, C, D>> {
        anyhow::ensure!(
            (1..=MAX_COSIGNERS).contains(&witness.active.len()),
            "FalconAggCircuit: active signer count {} out of range 1..={MAX_COSIGNERS}",
            witness.active.len()
        );
        // Prover-side convenience only (see `aggregate`): the binding checks are in-circuit.
        for (i, gw) in witness.active.iter().enumerate() {
            anyhow::ensure!(
                gw.message_digest == witness.message,
                "FalconAggCircuit: signer {i} witness signs a different message than the aggregate"
            );
        }
        let mut leaf_proofs = Vec::with_capacity(witness.active.len());
        for gw in witness.active.iter() {
            leaf_proofs.push(self.leaf.prove(gw)?);
        }
        self.aggregate_to_level(&leaf_proofs, AGG_LEVELS)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use once_cell::sync::Lazy;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::PrimeField64 as _},
        plonk::config::PoseidonGoldilocksConfig,
    };

    use super::*;
    use crate::{
        ethereum_types::u32limb_trait::U32LimbTrait as _,
        falcon_sig::{FalconKeys, falcon_padding_pk_g, falcon_pk_digest},
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    /// ONE shared aggregation tree for the whole suite (every case proves / fails against the same
    /// constraint systems, so sharing weakens nothing).
    static AGG: Lazy<FalconAggCircuit<F, C, D>> = Lazy::new(FalconAggCircuit::new);

    fn digest(tag: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_4348, tag as u32, 2, 3, 4, 5, 6, 7]).unwrap()
    }

    /// `n` distinct deterministic keys signing `msg`, as `(h, sig)` gadget-witness inputs.
    fn signers(n: usize, msg: Bytes32, seed0: u8) -> (Vec<[u16; FALCON_N]>, Vec<FalconSignature>) {
        let mut hs = Vec::new();
        let mut sigs = Vec::new();
        for i in 0..n {
            let keys = FalconKeys::from_seed([seed0 + i as u8; 32]);
            hs.push(keys.pk_coefficients());
            sigs.push(keys.sign(msg));
        }
        (hs, sigs)
    }

    fn witness_for(
        hs: &[[u16; FALCON_N]],
        sigs: &[FalconSignature],
        msg: Bytes32,
    ) -> FalconAggWitness {
        let refs: Vec<(&[u16; FALCON_N], &FalconSignature)> = hs.iter().zip(sigs.iter()).collect();
        FalconAggWitness::for_signatures(msg, &refs)
    }

    /// Asserts the exposed TOP-level PI layout: message@0, signer_count@8, pk_g_i@(9 + 8i), padding
    /// slots EXACTLY zero.
    fn check_pis(proof: &ProofWithPublicInputs<F, C, D>, msg: Bytes32, active_pks: &[Bytes32]) {
        let pis = &proof.public_inputs;
        assert_eq!(pis.len(), FALCON_AGG_PUBLIC_INPUTS_LEN);
        for (limb, want) in pis[FALCON_AGG_MSG_OFFSET..FALCON_AGG_MSG_OFFSET + BYTES32_LEN]
            .iter()
            .zip(msg.to_u32_vec())
        {
            assert_eq!(limb.to_canonical_u64(), want as u64, "message limb");
        }
        assert_eq!(
            pis[FALCON_AGG_COUNT_OFFSET].to_canonical_u64(),
            active_pks.len() as u64,
            "signer_count"
        );
        for i in 0..MAX_COSIGNERS {
            let start = FALCON_AGG_PK_LIST_OFFSET + i * BYTES32_LEN;
            let got: Vec<u64> = pis[start..start + BYTES32_LEN]
                .iter()
                .map(|f| f.to_canonical_u64())
                .collect();
            let want: Vec<u64> = if i < active_pks.len() {
                active_pks[i]
                    .to_u32_vec()
                    .iter()
                    .map(|&l| l as u64)
                    .collect()
            } else {
                vec![0u64; BYTES32_LEN]
            };
            assert_eq!(got, want, "pk slot {i} (padding must be EXACTLY zero)");
        }
        // Byte-identical to the native left-packed reference.
        assert_eq!(
            *pis,
            falcon_agg_expected_public_inputs::<F>(AGG_LEVELS, msg, active_pks)
        );
    }

    /// An unsatisfiable witness must never yield a verifying proof.
    fn assert_rejected(build: impl FnOnce() -> Result<ProofWithPublicInputs<F, C, D>>, msg: &str) {
        let result = catch_unwind(AssertUnwindSafe(build));
        let rejected = match result {
            Err(_) => true,
            Ok(Err(_)) => true,
            Ok(Ok(proof)) => AGG.data().verify(proof).is_err(),
        };
        assert!(rejected, "{msg}");
    }

    /// Happy path, N = 2 (minimum close cosigner count): both signatures verify, the exposed
    /// statement is left-packed with a zero padding suffix, and it verifies at the TOP-level VK.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn agg_happy_n2() {
        let msg = digest(1);
        let (hs, sigs) = signers(2, msg, 10);
        let pks: Vec<Bytes32> = hs.iter().map(falcon_pk_digest).collect();
        let w = witness_for(&hs, &sigs, msg);
        let proof = AGG.prove(&w).expect("prove n2");
        AGG.data().verify(proof.clone()).expect("verify n2");
        check_pis(&proof, msg, &pks);
    }

    /// Happy path, N = 3: an ODD count exercises an ABSENT right subtree at level 1 AND the
    /// left-packing rule at level 2 (left node full, right node half-full).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn agg_happy_n3_padding() {
        let msg = digest(3);
        let (hs, sigs) = signers(3, msg, 50);
        let pks: Vec<Bytes32> = hs.iter().map(falcon_pk_digest).collect();
        let proof = AGG.prove(&witness_for(&hs, &sigs, msg)).expect("prove n3");
        AGG.data().verify(proof.clone()).expect("verify n3");
        check_pis(&proof, msg, &pks);
        // The padding pk_g the gadget would produce for h = 0 is NONZERO, so exposing zero for an
        // absent subtree is a real gating result, not a tautology.
        assert_ne!(falcon_padding_pk_g(), Bytes32::default());
    }

    /// Happy path, N = MAX_COSIGNERS = 16 (a full tree, no absent subtree anywhere).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn agg_happy_n16() {
        let msg = digest(2);
        let (hs, sigs) = signers(MAX_COSIGNERS, msg, 30);
        let pks: Vec<Bytes32> = hs.iter().map(falcon_pk_digest).collect();
        let w = witness_for(&hs, &sigs, msg);
        let proof = AGG.prove(&w).expect("prove n16");
        AGG.data().verify(proof.clone()).expect("verify n16");
        check_pis(&proof, msg, &pks);
    }

    // ---- adversarial suite -------------------------------------------------------------------

    /// O-6 (message binding / cross-context): a signature produced over message A is rejected when
    /// aggregated under a DIFFERENT message B — the LEAF's unconditional norm bound fails for the
    /// wrong `c`. This is the circuit-level guarantee that an IMCH cosignature cannot be replayed
    /// as an IMSB signature (and vice versa).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn wrong_message_rejected() {
        let msg_a = digest(4);
        let msg_b = digest(5);
        let (hs, sigs) = signers(2, msg_a, 60);
        let mut w = witness_for(&hs, &sigs, msg_a);
        w.message = msg_b;
        for gw in w.active.iter_mut() {
            gw.message_digest = msg_b;
        }
        assert_rejected(
            || AGG.prove(&w),
            "signatures over A must not aggregate under message B",
        );
    }

    /// A leaf backed by the all-zero PADDING witness must be UNPROVABLE: unlike the retired flat
    /// design there is no `verify` gate at the leaf at all, so the norm bound is always live and
    /// `||c||^2 >> beta^2` rejects. A prover therefore cannot manufacture a "signature-free" leaf
    /// to inflate `signer_count`.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn padding_witness_leaf_is_unprovable() {
        let msg = digest(6);
        assert_rejected(
            || AGG.leaf.prove(&FalconSigGadgetWitness::padding(msg)),
            "the all-zero padding witness must not produce a leaf proof",
        );
    }

    /// Same, via the consumer entry point: appending a padding witness as an extra "active" signer
    /// must be rejected.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn active_slot_without_signature_rejected() {
        let msg = digest(7);
        let (hs, sigs) = signers(2, msg, 70);
        let mut w = witness_for(&hs, &sigs, msg);
        w.active.push(FalconSigGadgetWitness::padding(msg));
        assert_rejected(
            || AGG.prove(&w),
            "an active slot backed by the all-zero padding witness must be rejected",
        );
    }

    /// SECURITY: `signer_count = 0` must be UNREACHABLE, and in the TREE it is STRUCTURAL rather
    /// than asserted: every level verifies its LEFT child unconditionally and a leaf's count is the
    /// CONSTANT 1, so the minimum reachable count is 1. This test pins both halves:
    ///   (a) the consumer entry point rejects an empty active list, and
    ///   (b) the smallest provable top-level statement has `signer_count == 1` (not 0) — there is
    ///       no witness that turns the left child off.
    /// The regression this replaces (`zero_signers_rejected` against the flat circuit) is therefore
    /// preserved in spirit: the flat circuit needed `assert_one(is_active[0])` to get here.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn zero_signers_rejected() {
        let msg = digest(11);
        let w = FalconAggWitness {
            message: msg,
            active: Vec::new(),
        };
        assert_rejected(
            || AGG.prove(&w),
            "an empty aggregate (signer_count = 0) must be rejected",
        );

        // (b) The structural floor: n = 1 is the minimum, and it exposes count 1.
        let (hs, sigs) = signers(1, msg, 90);
        let proof = AGG.prove(&witness_for(&hs, &sigs, msg)).expect("prove n1");
        AGG.data().verify(proof.clone()).expect("verify n1");
        assert_eq!(
            proof.public_inputs[FALCON_AGG_COUNT_OFFSET].to_canonical_u64(),
            1,
            "the minimum reachable signer_count is 1, structurally"
        );
    }

    /// The exposed list carries no witnessed freedom (it is wired from the verified children's
    /// public inputs), so the only way to present a different list is to tamper with the proof's
    /// public inputs — which must break verification. Flip every PI limb of a level-1 proof.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn forged_public_input_list_fails_verification() {
        use plonky2::field::types::Field as _;
        let msg = digest(0x33);
        let (hs, sigs) = signers(2, msg, 110);
        let l0 = AGG
            .leaf
            .prove(&witness_for(&hs, &sigs, msg).active[0])
            .unwrap();
        let l1 = AGG
            .leaf
            .prove(&witness_for(&hs, &sigs, msg).active[1])
            .unwrap();
        let level1 = &AGG.levels[0];
        let top = level1.prove(&l0, Some(&l1)).unwrap();
        level1.verifier_data().verify(top.clone()).unwrap();
        assert_eq!(top.public_inputs.len(), falcon_agg_public_inputs_len(1));

        for i in 0..top.public_inputs.len() {
            let mut forged = top.clone();
            forged.public_inputs[i] += F::ONE;
            assert!(
                level1.verifier_data().verify(forged).is_err(),
                "tampered public input {i} must fail verification"
            );
        }
    }

    /// SECURITY (review MINOR-1): pins the INDUCTION BASE that every count argument rests on.
    ///
    /// The whole "signer_count == number of genuinely verified Falcon signatures" induction has
    /// its base at the LEAF: a leaf proof must expose `signer_count = 1`, and that 1 must be
    /// VERIFIER-ENFORCED, not a value the prover routes. (It is `builder.one()`, which plonky2
    /// materialises into a `ConstantGate` row whose value lives in the constants polynomial
    /// committed in the VK — but that is an argument about library internals, so pin it
    /// empirically here.) A leaf whose count slot became free would let a prover inflate the top
    /// count without extra signatures, i.e. commit member-set slots nobody signed for.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn leaf_signer_count_is_a_verifier_enforced_constant_one() {
        use plonky2::field::types::Field as _;
        let msg = digest(0x5c);
        let (hs, sigs) = signers(1, msg, 130);
        let leaf = AGG
            .leaf
            .prove(&witness_for(&hs, &sigs, msg).active[0])
            .unwrap();
        assert_eq!(leaf.public_inputs.len(), falcon_agg_public_inputs_len(0));
        assert_eq!(
            leaf.public_inputs[FALCON_AGG_COUNT_OFFSET],
            F::ONE,
            "a leaf must expose signer_count = 1"
        );
        AGG.leaf.verifier_data().verify(leaf.clone()).unwrap();

        // The value is CONSTRAINED, not merely conventional: claiming any other count on the same
        // proof must fail verification.
        for delta in [F::ONE, F::TWO, F::NEG_ONE] {
            let mut forged = leaf.clone();
            forged.public_inputs[FALCON_AGG_COUNT_OFFSET] += delta;
            assert!(
                AGG.leaf.verifier_data().verify(forged).is_err(),
                "a leaf signer_count other than 1 must fail verification"
            );
        }
    }

    /// Two children signing DIFFERENT messages cannot be aggregated: the gated message-equality
    /// constraint is unsatisfiable when the right child is present. (Calls the level circuit
    /// directly, bypassing the prover-side precheck, so the IN-CIRCUIT constraint is what rejects.)
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn mixed_message_children_cannot_be_aggregated() {
        let m_a = digest(0x21);
        let m_b = digest(0x22);
        let (hs_a, sigs_a) = signers(1, m_a, 120);
        let (hs_b, sigs_b) = signers(1, m_b, 121);
        let p_a = AGG
            .leaf
            .prove(&witness_for(&hs_a, &sigs_a, m_a).active[0])
            .unwrap();
        let p_b = AGG
            .leaf
            .prove(&witness_for(&hs_b, &sigs_b, m_b).active[0])
            .unwrap();
        let level1 = &AGG.levels[0];
        for (l, r, what) in [
            (&p_a, &p_b, "mixed-message aggregation"),
            (&p_b, &p_a, "mixed-message aggregation (swapped)"),
        ] {
            let result = level1.prove(l, Some(r));
            let rejected = match result {
                Err(_) => true,
                Ok(p) => level1.verifier_data().verify(p).is_err(),
            };
            assert!(rejected, "{what}");
        }
    }

    /// LEFT-PACKING enforcement: aggregating two HALF-FULL level-1 nodes (each carrying one pk_g
    /// and one zero slot, count 1) at level 2 would expose `pk0, 0, pk2, 0` with count 2 — a ZERO
    /// pk_g in a NON-suffix slot, breaking any consumer that reads "the first `signer_count` slots"
    /// as the signer set. The rule "right present ⟹ left child FULL" makes that UNPROVABLE.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn non_left_packed_aggregation_is_unprovable() {
        let msg = digest(0x78);
        let (hs, sigs) = signers(2, msg, 130);
        let w = witness_for(&hs, &sigs, msg);
        let leaf0 = AGG.leaf.prove(&w.active[0]).unwrap();
        let leaf1 = AGG.leaf.prove(&w.active[1]).unwrap();
        let level1 = &AGG.levels[0];
        let level2 = &AGG.levels[1];
        let node_a = level1.prove(&leaf0, None).unwrap();
        let node_b = level1.prove(&leaf1, None).unwrap();
        let result = level2.prove(&node_a, Some(&node_b));
        let rejected = match result {
            Err(_) => true,
            Ok(p) => level2.verifier_data().verify(p).is_err(),
        };
        assert!(
            rejected,
            "non-left-packed aggregation (half-full left child with right present) must fail"
        );
    }

    /// Smuggling: flag the right child PRESENT but supply the canonical DUMMY proof. The
    /// conditional verifier then selects the REAL child VK, against which the dummy proof is
    /// invalid — so `signer_count` cannot be inflated without a genuine child proof.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn dummy_right_child_flagged_present_is_rejected() {
        let msg = digest(0x55);
        let (hs, sigs) = signers(1, msg, 140);
        let leaf = AGG
            .leaf
            .prove(&witness_for(&hs, &sigs, msg).active[0])
            .unwrap();
        let level1 = &AGG.levels[0];
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&level1.left_proof, &leaf)
            .unwrap();
        pw.set_bool_target(level1.is_right_present, true).unwrap();
        pw.set_proof_with_pis_target(&level1.right_proof, &level1.right_dummy.proof)
            .unwrap();
        let result = level1.data.prove(pw);
        let rejected = match result {
            Err(_) => true,
            Ok(p) => level1.verifier_data().verify(p).is_err(),
        };
        assert!(rejected, "a dummy right proof flagged as present must fail");
    }

    /// Pins the padding-digest identity: `Poseidon(IMFK || encode(0))` = `falcon_padding_pk_g`.
    /// In the tree this constant is never exposed at all (absent subtrees expose gated zeros and
    /// there is no padding-slot gadget), but the identity is still the reference the native padding
    /// argument quotes.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn padding_digest_identity() {
        assert_eq!(falcon_pk_digest(&[0u16; FALCON_N]), falcon_padding_pk_g());
    }

    /// Measurement: the LEAF circuit ALONE (build + prove + verify), so its peak RSS can be
    /// attributed separately under `/usr/bin/time -l`.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn leaf_measure_1sig() {
        let t0 = std::time::Instant::now();
        let leaf = FalconLeafCircuit::<F, C, D>::new();
        let build = t0.elapsed();
        let msg = digest(0x61);
        let (hs, sigs) = signers(1, msg, 160);
        let w = witness_for(&hs, &sigs, msg);
        let t1 = std::time::Instant::now();
        let proof = leaf.prove(&w.active[0]).expect("prove");
        let prove = t1.elapsed();
        leaf.data.verify(proof).expect("verify");
        println!(
            "[leaf 1sig] gates={} degree_bits={} num_pis={} build={build:?} prove={prove:?}",
            leaf.num_gates_before_padding,
            leaf.data.common.degree_bits(),
            leaf.data.common.num_public_inputs,
        );
    }

    /// Measurement of the ALTERNATIVE leaf shape the owner asked about: TWO signatures per leaf
    /// (slot 0 unconditional — the `signer_count >= 1` base case; slot 1 conditional, its pk_g
    /// gated to zero when absent, `count = 1 + is_second`). Built here as a measurement-only
    /// circuit: adopting it would drop one tree level (leaf layout becomes "level 1"), so the
    /// production tree would be leaf2 -> level2 -> level3 -> level4.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn leaf_measure_2sig() {
        let t0 = std::time::Instant::now();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let sig0 = FalconSigVerifyTarget::new(&mut builder);
        let is_second = builder.add_virtual_bool_target_safe();
        let sig1 = FalconSigVerifyTarget::new_conditional(&mut builder, is_second);
        sig1.message_digest
            .connect(&mut builder, sig0.message_digest);
        builder.register_public_inputs(&sig0.message_digest.to_vec());
        let one = builder.one();
        let count = builder.add(one, is_second.target);
        builder.register_public_input(count);
        builder.register_public_inputs(&sig0.pk_g.to_vec());
        let zero = builder.zero();
        for &limb in sig1.pk_g.to_vec().iter() {
            let exposed = builder.select(is_second, limb, zero);
            builder.register_public_input(exposed);
        }
        add_const_gate(&mut builder);
        let gates = builder.num_gates();
        let data = builder.build::<C>();
        let build = t0.elapsed();

        let msg = digest(0x62);
        let (hs, sigs) = signers(2, msg, 170);
        let w = witness_for(&hs, &sigs, msg);
        let mut pw = PartialWitness::<F>::new();
        sig0.message_digest.set_witness::<F, Bytes32>(&mut pw, msg);
        sig0.set_signature_witness(&mut pw, &w.active[0]).unwrap();
        pw.set_bool_target(is_second, true).unwrap();
        sig1.set_signature_witness(&mut pw, &w.active[1]).unwrap();
        let t1 = std::time::Instant::now();
        let proof = data.prove(pw).expect("prove");
        let prove = t1.elapsed();
        data.verify(proof).expect("verify");
        println!(
            "[leaf 2sig] gates={gates} degree_bits={} num_pis={} build={build:?} prove={prove:?}",
            data.common.degree_bits(),
            data.common.num_public_inputs,
        );
    }

    /// Measurement (the Phase-2.6 deliverable): per-circuit gates / degree / build time, plus the
    /// end-to-end 16-signature aggregation prove time. Run in isolation with --nocapture under
    /// `/usr/bin/time -l` to capture peak RSS.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn agg_tree_measure() {
        let t0 = std::time::Instant::now();
        let leaf = FalconLeafCircuit::<F, C, D>::new();
        println!(
            "[leaf] gates={} degree_bits={} num_pis={} build={:?}",
            leaf.num_gates_before_padding,
            leaf.data.common.degree_bits(),
            leaf.data.common.num_public_inputs,
            t0.elapsed()
        );

        let msg = digest(9);
        let (hs, sigs) = signers(MAX_COSIGNERS, msg, 150);
        let w = witness_for(&hs, &sigs, msg);

        let t_leaf = std::time::Instant::now();
        let first = leaf.prove(&w.active[0]).expect("leaf prove");
        println!("[leaf] prove={:?}", t_leaf.elapsed());
        leaf.data.verify(first).expect("leaf verify");

        let mut levels: Vec<FalconAggLevelCircuit<F, C, D>> = Vec::new();
        let mut child_vd = leaf.verifier_data();
        for level in 1..=AGG_LEVELS {
            let t = std::time::Instant::now();
            let circuit = FalconAggLevelCircuit::<F, C, D>::new(level, &child_vd);
            println!(
                "[level {level}] gates={} degree_bits={} num_pis={} build={:?}",
                circuit.num_gates_before_padding,
                circuit.data.common.degree_bits(),
                circuit.data.common.num_public_inputs,
                t.elapsed()
            );
            child_vd = circuit.verifier_data();
            levels.push(circuit);
        }
        let agg = FalconAggCircuit::<F, C, D> { leaf, levels };

        let t_all = std::time::Instant::now();
        let proof = agg.prove(&w).expect("full 16-signature aggregation");
        println!("[tree N=16] end-to-end prove={:?}", t_all.elapsed());
        let t_v = std::time::Instant::now();
        agg.data().verify(proof).expect("top verify");
        println!("[tree N=16] top verify={:?}", t_v.elapsed());
    }
}
