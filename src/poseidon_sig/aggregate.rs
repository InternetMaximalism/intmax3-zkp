//! Binary-tree aggregation of single-signature proofs ("sign-zkp") for channel cosigners.
//!
//! Aggregates up to [`MAX_AGG_SIGNERS`] (= 16)
//! [`SingleSigCircuit`](super::circuit::SingleSigCircuit) proofs over the SAME message into one
//! proof whose public inputs expose the full signer list. Combining two aggregated proofs yields
//! one proof whose signer list is the CONCATENATION `left.list || right.list`, so the list length
//! doubles per level:
//!
//!   level 1: 2 leaves  -> 2 slots
//!   level 2: 2 level-1 -> 4 slots
//!   level 3: 2 level-2 -> 8 slots
//!   level 4: 2 level-3 -> 16 slots
//!
//! Plonky2 public inputs are fixed-length per circuit, so there is ONE CIRCUIT PER LEVEL
//! (4 aggregation circuits + the leaf `SingleSigCircuit` = 5 circuits total).
//!
//! # Public-input layout (canonical, level `k`, `1 <= k <= 4`)
//!
//! ```text
//!   [ message (8 u32 limbs) | signer_count (1) | pk_0 (8) | pk_1 (8) | ... | pk_{2^k - 1} (8) ]
//! ```
//!
//! total `8 + 1 + 8 * 2^k` field elements (see [`agg_public_inputs_len`]). The leaf
//! (`SingleSigCircuit`) keeps its own layout `[pk(8), m(8)]`; the level-1 circuit adapts it.
//! `pk` slot `i` is the pk of leaf `i` in left-to-right tree order; unused (padding) slots are
//! all-zero and appear only where a subtree is absent (the native helper packs signers to the
//! left, so padding is a zero suffix).
//!
//! # Padding design (non-power-of-2 signer counts)
//!
//! Each aggregation node takes a boolean witness `is_right_present`:
//!   - The LEFT child proof is ALWAYS verified unconditionally (a node with zero children is
//!     meaningless — use a smaller level instead).
//!   - The RIGHT child proof is verified via `add_proof_target_and_conditionally_verify`: when
//!     `is_right_present = 1` it is verified against the REAL child verifier data; when
//!     `is_right_present = 0` the prover supplies a canonical dummy proof which is verified against
//!     the dummy circuit's verifier data (so the proof slot is well-formed but carries no
//!     cryptographic claim, and its public inputs are UNTRUSTED).
//!
//! Every value read from the right child is gated by `is_right_present` before it can influence
//! a public input or a constraint:
//!   - exposed right pk slots     = `is_right_present * right.pk_limb`  (zeros when absent),
//!   - exposed `signer_count`     = `left.count + is_right_present * right.count`,
//!   - message-equality check     = `is_right_present * (left.m_limb - right.m_limb) == 0`
//!     (enforced when present, vacuous when absent).
//!
//! SECURITY (padding soundness):
//!   - A prover cannot smuggle a padding slot as a real signer: incrementing `signer_count`
//!     requires `is_right_present = 1`, which forces the right proof to verify against the REAL
//!     child verifier data (a dummy proof fails that check — `select_verifier_data` picks the real
//!     VK when the flag is 1). By induction (level-1 children are leaf proofs counting exactly 1),
//!     `signer_count` equals the number of genuinely verified leaf signature proofs in the tree.
//!   - A prover cannot smuggle a real signer as padding into a NONZERO slot: with `is_right_present
//!     = 0` the exposed right slots are identically zero, and a real leaf pk is
//!     `Poseidon([DOMAIN_PK_G] ‖ sk)`, so a zero pk would require a Poseidon preimage of the
//!     all-zero digest (and the all-zero `sk` is rejected in the leaf circuit). Hence every NONZERO
//!     pk in the list corresponds to exactly one verified leaf proof, in leaf order.
//!   - There is NO witnessed freedom in the exposed list: `message`, `signer_count`, and every pk
//!     slot are wired functions of the two (verified) children's public inputs and the boolean
//!     flag. The only witness values of an aggregation node are the two child proofs and
//!     `is_right_present` (constrained boolean via `add_virtual_bool_target_safe`).
//!   - Signer DISTINCTNESS is intentionally NOT enforced here (same boundary as
//!     `list.rs::duplicate_entries_are_accepted_at_list_level`): the same leaf proof may be placed
//!     in two slots, each backed by its own verification. Deduplication / pk-in-member-set checks
//!     are CONSUMER obligations (threat model A5/A8).
//!
//! # Verifier-data binding (A7)
//!
//! Each level bakes the PREVIOUS level's verifier data in as a CONSTANT
//! (`add_proof_target_and_verify` / `add_proof_target_and_conditionally_verify` both call
//! `builder.constant_verifier_data`), so a level-`k` proof can only be built from genuine
//! level-`(k-1)` proofs (level-1 only from genuine `SingleSigCircuit` proofs) — a proof from
//! any other circuit with the same PI shape fails against the build-fixed VK.

use plonky2::{
    field::types::Field as _,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32},
        u32limb_trait::U32LimbTrait as _,
    },
    utils::{
        cyclic::add_const_gate,
        dummy::DummyProof,
        recursively_verifiable::{
            add_proof_target_and_conditionally_verify, add_proof_target_and_verify,
        },
    },
};

use super::circuit::{C, D, F, SINGLE_SIG_PUBLIC_INPUTS_LEN};

/// Number of aggregation levels above the leaf (level 4 => 16 slots).
pub const AGG_LEVELS: usize = 4;

/// Maximum number of cosigner signatures one top proof can carry (`2^AGG_LEVELS`).
pub const MAX_AGG_SIGNERS: usize = 1 << AGG_LEVELS;

/// Offset of the 8 message limbs in a level-`k` aggregated proof's public inputs.
pub const AGG_MSG_OFFSET: usize = 0;
/// Offset of the single `signer_count` field element.
pub const AGG_COUNT_OFFSET: usize = BYTES32_LEN;
/// Offset of the first pk slot (each slot is 8 limbs; slot `i` starts at
/// `AGG_PK_LIST_OFFSET + i * BYTES32_LEN`).
pub const AGG_PK_LIST_OFFSET: usize = BYTES32_LEN + 1;

/// Total public-input length of a level-`k` aggregated proof:
/// `message(8) + signer_count(1) + 2^k pk slots (8 each)`.
pub const fn agg_public_inputs_len(level: usize) -> usize {
    BYTES32_LEN + 1 + (1 << level) * BYTES32_LEN
}

/// The expected public inputs of a left-packed aggregation (the shape produced by
/// [`SigAggregator::aggregate`]): `signer_pks` in leaf order, padding slots zero-suffixed.
/// Native reference for consumers and tests.
pub fn agg_expected_public_inputs(
    level: usize,
    message: Bytes32,
    signer_pks: &[Bytes32],
) -> Vec<F> {
    assert!((1..=AGG_LEVELS).contains(&level), "level out of range");
    assert!(
        signer_pks.len() <= (1 << level),
        "more signers than slots at this level"
    );
    let mut pis = Vec::with_capacity(agg_public_inputs_len(level));
    pis.extend(message.to_u32_vec().into_iter().map(F::from_canonical_u32));
    pis.push(F::from_canonical_usize(signer_pks.len()));
    for pk in signer_pks {
        pis.extend(pk.to_u32_vec().into_iter().map(F::from_canonical_u32));
    }
    pis.resize(agg_public_inputs_len(level), F::ZERO);
    pis
}

/// Parse a child proof's public inputs into `(message limbs, signer_count, pk slot limbs)`.
///
/// At level 1 the children are `SingleSigCircuit` leaves (`[pk(8), m(8)]`, implicit count 1);
/// at level `k >= 2` they are level-`(k-1)` aggregated proofs in the canonical layout above.
fn child_pis(
    builder: &mut CircuitBuilder<F, D>,
    level: usize,
    pis: &[Target],
) -> (Vec<Target>, Target, Vec<Target>) {
    if level == 1 {
        let one = builder.one();
        (
            pis[BYTES32_LEN..2 * BYTES32_LEN].to_vec(),
            one,
            pis[0..BYTES32_LEN].to_vec(),
        )
    } else {
        let slots = 1 << (level - 1);
        (
            pis[AGG_MSG_OFFSET..AGG_MSG_OFFSET + BYTES32_LEN].to_vec(),
            pis[AGG_COUNT_OFFSET],
            pis[AGG_PK_LIST_OFFSET..AGG_PK_LIST_OFFSET + slots * BYTES32_LEN].to_vec(),
        )
    }
}

/// One aggregation level: verifies a left child proof (always) and a right child proof
/// (conditionally), asserts message agreement, and exposes the concatenated signer list.
pub struct AggLevelCircuit {
    /// This node's level (`1..=AGG_LEVELS`); output list has `2^level` pk slots.
    pub level: usize,
    pub data: CircuitData<F, C, D>,
    left_proof: ProofWithPublicInputsTarget<D>,
    right_proof: ProofWithPublicInputsTarget<D>,
    is_right_present: BoolTarget,
    /// Canonical dummy proof for the child common data — set into `right_proof` when the right
    /// child is absent (`is_right_present = 0`). Its public inputs are untrusted by design; every
    /// read of the right child is gated by `is_right_present`.
    right_dummy: DummyProof<F, C, D>,
}

impl AggLevelCircuit {
    /// Build the level-`level` circuit over `child_vd` (the `SingleSigCircuit` verifier data for
    /// `level == 1`, the level-`(level-1)` `AggLevelCircuit` verifier data otherwise).
    pub fn new(level: usize, child_vd: &VerifierCircuitData<F, C, D>) -> Self {
        assert!((1..=AGG_LEVELS).contains(&level), "level out of range");
        // Guard against wiring the wrong child circuit in: the child's PI length must match the
        // layout this level parses. (The real binding is the constant VK below — this is a
        // build-time sanity check, not the security mechanism.)
        let expected_child_pis = if level == 1 {
            SINGLE_SIG_PUBLIC_INPUTS_LEN
        } else {
            agg_public_inputs_len(level - 1)
        };
        assert_eq!(
            child_vd.common.num_public_inputs, expected_child_pis,
            "child verifier data has the wrong public-input arity for level {level}"
        );

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // SECURITY (A7): both helpers bake `child_vd` in as a CONSTANT verifier data, so only
        // proofs from the genuine child circuit can be aggregated. The left child is verified
        // unconditionally; the right child only when `is_right_present = 1` (when 0, the
        // in-circuit `select_verifier_data` picks the dummy VK, and everything read from the
        // right proof is gated below).
        let left_proof = add_proof_target_and_verify(child_vd, &mut builder);
        // `_safe` constrains the flag to {0, 1} — without it, a fractional "presence" could
        // scale counts/pks arbitrarily.
        let is_right_present = builder.add_virtual_bool_target_safe();
        let right_proof =
            add_proof_target_and_conditionally_verify(child_vd, &mut builder, is_right_present);

        let (msg_l, count_l, pks_l) = child_pis(&mut builder, level, &left_proof.public_inputs);
        let (msg_r, count_r, pks_r) = child_pis(&mut builder, level, &right_proof.public_inputs);

        // All aggregated signatures are over the SAME message: when the right child is present,
        // its message must equal the left child's, limb by limb. Gated so an absent (dummy)
        // right child imposes nothing.
        for (&l, &r) in msg_l.iter().zip(msg_r.iter()) {
            let diff = builder.sub(l, r);
            let gated = builder.mul(is_right_present.target, diff);
            builder.assert_zero(gated);
        }

        // signer_count = left.count + is_right_present * right.count. No other witness feeds
        // this value, so it counts exactly the verified leaf proofs in the tree (see module
        // doc, padding soundness).
        let gated_count_r = builder.mul(is_right_present.target, count_r);
        let signer_count = builder.add(count_l, gated_count_r);

        // SECURITY (left-packing, adversarial-review fix): if the right child is PRESENT, the left
        // child must be FULL (count_l == 2^{level-1}). Without this, two half-full nodes could be
        // aggregated into a list with a ZERO pk in a NON-suffix slot (e.g. [pk0, 0, pk2, 0] with
        // count 2), breaking any consumer that reads "the first `signer_count` slots" as the
        // signer set. With it, by induction every exposed list is left-packed: the nonzero pks are
        // exactly the first `signer_count` slots and the zero padding is strictly a suffix. Gated
        // so an absent right child imposes nothing (a lone non-full left child is fine — its own
        // padding is already a suffix by the same induction).
        let half_full = builder.constant(F::from_canonical_usize(1 << (level - 1)));
        let left_fullness_gap = builder.sub(count_l, half_full);
        let gated_gap = builder.mul(is_right_present.target, left_fullness_gap);
        builder.assert_zero(gated_gap);

        // Public inputs — fully wired from child PIs + the boolean flag; no witnessed slots.
        // Left half of the list is the left child's list verbatim; right half is the right
        // child's list gated by presence (identically zero when absent).
        builder.register_public_inputs(&msg_l);
        builder.register_public_input(signer_count);
        builder.register_public_inputs(&pks_l);
        for &t in &pks_r {
            let gated = builder.mul(is_right_present.target, t);
            builder.register_public_input(gated);
        }

        // Ensure a `ConstantGate` is in this circuit's gate set so the NEXT level can embed it
        // via `conditionally_verify_proof` (the dummy-circuit reconstruction in utils/dummy.rs
        // always emits one, and its rebuilt common data must match ours exactly). Same pattern
        // as send_tx / receive_transfer / receive_deposit. INTENTIONALLY SIMPLE: one extra
        // constant row; adds no constraints on witness values.
        add_const_gate(&mut builder);

        let data = builder.build::<C>();
        debug_assert_eq!(data.common.num_public_inputs, agg_public_inputs_len(level));

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
        }
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.data.verifier_data()
    }

    /// Aggregate `left` with an optional `right` child proof (both at this circuit's child
    /// level). `right = None` marks the right subtree absent: its slots are exposed as zeros and
    /// it contributes 0 to `signer_count`.
    pub fn prove(
        &self,
        left: &ProofWithPublicInputs<F, C, D>,
        right: Option<&ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
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

/// All aggregation levels, built once over a `SingleSigCircuit`'s verifier data.
/// `levels[k-1]` is the level-`k` circuit.
pub struct SigAggregator {
    pub levels: [AggLevelCircuit; AGG_LEVELS],
}

impl SigAggregator {
    pub fn new(single_sig_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let l1 = AggLevelCircuit::new(1, single_sig_vd);
        let l2 = AggLevelCircuit::new(2, &l1.verifier_data());
        let l3 = AggLevelCircuit::new(3, &l2.verifier_data());
        let l4 = AggLevelCircuit::new(4, &l3.verifier_data());
        Self {
            levels: [l1, l2, l3, l4],
        }
    }

    /// The minimal aggregation level whose list can hold `n` signers (`2^k >= n`, `k >= 1`).
    /// `n = 1` still uses level 1 (right absent) because the leaf circuit has a different PI
    /// layout than the aggregated one.
    pub fn top_level_for(n: usize) -> usize {
        assert!(
            (1..=MAX_AGG_SIGNERS).contains(&n),
            "signer count out of range"
        );
        let mut k = 1;
        while (1 << k) < n {
            k += 1;
        }
        k
    }

    /// Build the aggregation tree bottom-up over `leaf_proofs` (each a `SingleSigCircuit` proof;
    /// all over the same message) and return `(top proof, top level)`. Signers are packed to the
    /// left, so the top proof's public inputs equal
    /// `agg_expected_public_inputs(level, message, leaf pks in order)`.
    ///
    /// The same-message precheck here is prover-side convenience ONLY (fail early with a clear
    /// error instead of an unsatisfiable-witness error); the binding check is the in-circuit
    /// gated message-equality constraint in every [`AggLevelCircuit`].
    pub fn aggregate(
        &self,
        leaf_proofs: &[ProofWithPublicInputs<F, C, D>],
    ) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, usize)> {
        let n = leaf_proofs.len();
        anyhow::ensure!(
            (1..=MAX_AGG_SIGNERS).contains(&n),
            "signer count must be in 1..={MAX_AGG_SIGNERS}, got {n}"
        );
        let msg0 = &leaf_proofs[0].public_inputs[BYTES32_LEN..2 * BYTES32_LEN];
        for (i, proof) in leaf_proofs.iter().enumerate() {
            anyhow::ensure!(
                &proof.public_inputs[BYTES32_LEN..2 * BYTES32_LEN] == msg0,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon_sig::{GoldilocksSecretKey, circuit::SingleSigCircuit};

    fn message(byte: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_0000 | byte as u32, 11, 22, 33, 44, 55, 66, 77]).unwrap()
    }

    fn secret_key(i: usize) -> GoldilocksSecretKey {
        GoldilocksSecretKey::from_seed([i as u8 + 1; 32])
    }

    /// An unsatisfiable witness must never yield a verifying proof. This fork's prover errors on
    /// conflicting copy-constraint assignments; if a prover build ever returned Ok anyway, the
    /// proof failing verification is the last line of defense — never accept both succeeding.
    fn assert_rejected(
        result: anyhow::Result<ProofWithPublicInputs<F, C, D>>,
        vd: &VerifierCircuitData<F, C, D>,
        what: &str,
    ) {
        match result {
            Err(_) => {}
            Ok(proof) => assert!(
                vd.verify(proof).is_err(),
                "{what}: proving succeeded AND the proof verifies — soundness bug"
            ),
        }
    }

    /// Happy path across 2, 3, 4, and 16 signers over one message: the top proof verifies at the
    /// minimal level, `signer_count == n`, the exposed message is `m`, and the pk list is exactly
    /// the leaf pks in order followed by zero padding.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn aggregates_2_3_4_16_signers_happy_path() {
        let single = SingleSigCircuit::new();
        let agg = SigAggregator::new(&single.verifier_data());
        for (i, level) in agg.levels.iter().enumerate() {
            eprintln!(
                "agg level {} degree_bits = {}",
                i + 1,
                level.data.common.degree_bits()
            );
        }

        let m = message(0xaa);
        let sks: Vec<GoldilocksSecretKey> = (0..MAX_AGG_SIGNERS).map(secret_key).collect();
        let leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>> = sks
            .iter()
            .map(|sk| single.prove(sk, m).expect("leaf proving"))
            .collect();

        for &n in &[2usize, 3, 4, 16] {
            let (top, level) = agg.aggregate(&leaf_proofs[..n]).expect("aggregation");
            assert_eq!(level, SigAggregator::top_level_for(n));
            agg.levels[level - 1]
                .verifier_data()
                .verify(top.clone())
                .unwrap_or_else(|e| panic!("top proof for n={n} must verify: {e:?}"));

            let pks: Vec<Bytes32> = sks[..n].iter().map(|sk| sk.public_key()).collect();
            let expected = agg_expected_public_inputs(level, m, &pks);
            assert_eq!(
                top.public_inputs, expected,
                "n={n}: top public inputs must be [m, n, pk_0..pk_{{n-1}}, 0...]"
            );
        }
    }

    /// Two children signing DIFFERENT messages cannot be aggregated: the gated message-equality
    /// constraint is unsatisfiable when the right child is present.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn mixed_message_children_cannot_be_aggregated() {
        let single = SingleSigCircuit::new();
        let level1 = AggLevelCircuit::new(1, &single.verifier_data());

        let p_a = single.prove(&secret_key(0), message(0x01)).unwrap();
        let p_b = single.prove(&secret_key(1), message(0x02)).unwrap();
        // Call the level circuit directly (bypassing SigAggregator's native precheck) so the
        // IN-CIRCUIT constraint is what rejects.
        assert_rejected(
            level1.prove(&p_a, Some(&p_b)),
            &level1.verifier_data(),
            "mixed-message aggregation",
        );
        // Same-order sanity: swapping the operands must also fail.
        assert_rejected(
            level1.prove(&p_b, Some(&p_a)),
            &level1.verifier_data(),
            "mixed-message aggregation (swapped)",
        );
    }

    /// The exposed list carries no witnessed freedom (it is fully wired from the verified
    /// children's public inputs — see the module doc), so the only way to present a different
    /// list is to tamper with the proof's public inputs, which must break verification. Flip
    /// every single PI limb (message, count, both pk slots) and check each forgery is rejected.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn forged_public_input_list_fails_verification() {
        let single = SingleSigCircuit::new();
        let level1 = AggLevelCircuit::new(1, &single.verifier_data());
        let m = message(0x33);
        let p0 = single.prove(&secret_key(0), m).unwrap();
        let p1 = single.prove(&secret_key(1), m).unwrap();
        let top = level1.prove(&p0, Some(&p1)).unwrap();
        level1.verifier_data().verify(top.clone()).unwrap();
        assert_eq!(top.public_inputs.len(), agg_public_inputs_len(1));

        for i in 0..top.public_inputs.len() {
            let mut forged = top.clone();
            forged.public_inputs[i] += F::ONE;
            assert!(
                level1.verifier_data().verify(forged).is_err(),
                "tampered public input {i} must fail verification"
            );
        }
    }

    /// Padding soundness with n = 3 (level 2; right child of the second level-1 node absent):
    /// the absent slot's pk is zero, `signer_count == 3`, a forged count of 4 is rejected, and a
    /// prover cannot pass the dummy proof off as a present (real) child.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn padding_n3_soundness() {
        let single = SingleSigCircuit::new();
        let level1 = AggLevelCircuit::new(1, &single.verifier_data());
        let level2 = AggLevelCircuit::new(2, &level1.verifier_data());

        let m = message(0x77);
        let sks: Vec<GoldilocksSecretKey> = (0..3).map(secret_key).collect();
        let leaves: Vec<ProofWithPublicInputs<F, C, D>> =
            sks.iter().map(|sk| single.prove(sk, m).unwrap()).collect();

        let node_a = level1.prove(&leaves[0], Some(&leaves[1])).unwrap();
        let node_b = level1.prove(&leaves[2], None).unwrap();
        let top = level2.prove(&node_a, Some(&node_b)).unwrap();
        level2.verifier_data().verify(top.clone()).unwrap();

        // Full canonical layout: [m(8), 3, pk0(8), pk1(8), pk2(8), 0(8)].
        let pks: Vec<Bytes32> = sks.iter().map(|sk| sk.public_key()).collect();
        let expected = agg_expected_public_inputs(2, m, &pks);
        assert_eq!(top.public_inputs, expected);
        assert_eq!(
            top.public_inputs[AGG_COUNT_OFFSET],
            F::from_canonical_u64(3)
        );
        // The absent slot (slot 3) is identically zero.
        assert!(
            top.public_inputs[AGG_PK_LIST_OFFSET + 3 * BYTES32_LEN..]
                .iter()
                .all(|&limb| limb == F::ZERO),
            "padding slot must be all-zero"
        );
        // Real pks are nonzero (a zero pk would need a Poseidon preimage of the zero digest).
        for i in 0..3 {
            let slot = &top.public_inputs
                [AGG_PK_LIST_OFFSET + i * BYTES32_LEN..AGG_PK_LIST_OFFSET + (i + 1) * BYTES32_LEN];
            assert!(slot.iter().any(|&limb| limb != F::ZERO));
        }

        // Forgery: claiming signer_count = 4 on the n = 3 proof must fail verification.
        let mut forged = top.clone();
        forged.public_inputs[AGG_COUNT_OFFSET] = F::from_canonical_u64(4);
        assert!(
            level2.verifier_data().verify(forged).is_err(),
            "signer_count 4 with 3 verified signatures must be rejected"
        );

        // Smuggling: flag the right child PRESENT but supply the dummy proof. The conditional
        // verifier then selects the REAL level-1 VK, against which the dummy proof is invalid —
        // so `signer_count` cannot be inflated without a genuine child proof.
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&level2.left_proof, &node_a)
            .unwrap();
        pw.set_bool_target(level2.is_right_present, true).unwrap();
        pw.set_proof_with_pis_target(&level2.right_proof, &level2.right_dummy.proof)
            .unwrap();
        assert_rejected(
            level2.data.prove(pw),
            &level2.verifier_data(),
            "dummy right proof flagged as present",
        );
    }

    /// LEFT-PACKING enforcement (adversarial-review fix): aggregating two HALF-FULL level-1 nodes
    /// (each `[pk, 0]` with count 1) at level 2 would expose `[pk0, 0, pk2, 0]` with count 2 — a
    /// ZERO pk in a NON-suffix slot, breaking any consumer that reads "the first `signer_count`
    /// slots" as the signer set. The in-circuit rule "right present ⇒ left child FULL
    /// (count_l == 2^{level-1})" makes this construction UNPROVABLE; padding is provably always a
    /// suffix.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn non_left_packed_aggregation_is_unprovable() {
        let single = SingleSigCircuit::new();
        let level1 = AggLevelCircuit::new(1, &single.verifier_data());
        let level2 = AggLevelCircuit::new(2, &level1.verifier_data());

        let m = message(0x78);
        let leaf0 = single.prove(&secret_key(0), m).unwrap();
        let leaf2 = single.prove(&secret_key(2), m).unwrap();

        // Two half-full level-1 nodes: [pk0, 0] and [pk2, 0], each count 1.
        let node_a = level1.prove(&leaf0, None).unwrap();
        let node_b = level1.prove(&leaf2, None).unwrap();

        // Aggregating them (right PRESENT, left NOT full: count_l = 1 != 2) must be unprovable.
        assert_rejected(
            level2.prove(&node_a, Some(&node_b)),
            &level2.verifier_data(),
            "non-left-packed aggregation (half-full left child with right present)",
        );
    }
}
