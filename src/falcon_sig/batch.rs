//! Falcon-512/Poseidon signature AGGREGATE VERIFICATION — one flat circuit, batched algebra.
//!
//! Replaces the binary-tree recursion of [`super::agg`] (16 leaf proofs + 4 recursion levels =
//! up to 31 proofs for a full close) with ONE proof that verifies all `MAX_COSIGNERS` signatures
//! directly. The tree existed because the old FLAT circuit verified each signature with an
//! in-circuit NTT (~14.8k range-checked mod-q reductions per signature) and therefore needed a
//! degree-2^20 circuit (~22 GB peak RSS). This module removes the NTT itself, so the flat form
//! fits in a SMALL circuit again — the memory argument that motivated the tree disappears
//! together with the cost the tree was amortizing.
//!
//! # The aggregation idea (why this is the SNARK-native "aggregate signature")
//!
//! A lattice aggregate signature in the wire-format sense (N Falcon signatures compressed into
//! one short object, LaBRADOR-style) would not help here: the aggregate VERIFIER would still
//! have to be expressed in-circuit, and those verifiers are heavier than Falcon's own. In a
//! SNARK context the proof itself already IS the aggregate object; what matters is making the
//! aggregate STATEMENT ("these N signatures all verify") cheap to constrain. This module does
//! that with the standard batched-algebra technique (the same one Miden VM uses for its Falcon
//! verifier): replace the ring multiplication `s2 * h` — the only super-linear part of Falcon
//! verification — by a witnessed product checked at ONE random point, shared across all N
//! signatures:
//!
//! 1. For each slot `i`, the prover witnesses the INTEGER polynomial product `pi_i = h_i * s2_i`
//!    over `Z[x]` (degree <= 2n-2 = 1022, coefficients in `[0, n*(q-1)^2] ⊂ [0, 2^37)`, each
//!    range-checked).
//! 2. A single in-circuit Poseidon transcript absorbs ALL slots' `(h_i, s2_i, pi_i)` (h/s2 packed
//!    4-per-element in their canonicity-checked 14-bit lanes; pi raw, one element per coefficient)
//!    and squeezes the Fiat-Shamir challenge `tau ∈ F_{p^D}` (D = 2: ~2^128).
//! 3. Each slot checks `pi_i(tau) == h_i(tau) * s2_i(tau)` by Horner evaluation in the extension
//!    field — ~2k cheap extension mul-adds per signature instead of ~15k range-checked reductions.
//! 4. `s1_i` is then obtained coefficient-wise from the negacyclic fold of `pi_i`: `s1_i[j] =
//!    c_i[j] - pi_i[j] + pi_i[512 + j] (mod q)` in ONE range-checked reduction per coefficient, and
//!    the usual centered norm bound `||(s1, s2)||^2 <= beta^2` is enforced.
//!
//! # Soundness of the product check
//!
//! Fix any witness. The transcript commits every coefficient of `h_i`, `s2_i`, `pi_i` BEFORE
//! `tau` exists (`tau` is a deterministic in-circuit function of them), so the difference
//! polynomial `delta_i(x) = pi_i(x) - h_i(x) * s2_i(x)` is fixed before `tau` is known —
//! choosing the witness after seeing `tau` is impossible because changing the witness changes
//! `tau`. All coefficients involved are `< 2^38 << p`, so `delta_i ≡ 0 mod p` iff
//! `delta_i = 0` over `Z`; if `delta_i != 0`, it is a nonzero polynomial of degree <= 1022
//! over `F_p`, and `tau` (modeled as a random oracle output in `F_{p^2}`) is a root with
//! probability <= 1022/p^2 < 2^-117 per witness attempt (grinding a new witness re-randomizes
//! `tau`, so each attempt pays the full 2^-117). Given `pi_i = h_i * s2_i` over `Z`, the
//! per-coefficient reduction in step 4 makes `s1_i` EXACTLY the native
//! `c - s2*h mod (q, x^n + 1)` — the accepted set is precisely the native
//! `verify_with_pk_g` predicate, per slot.
//!
//! The packing absorbed by the transcript is injective on the constrained domain: h/s2 lanes
//! are canonicity-checked `< q < 2^14` (so the 4x14-bit packing is a bijection), and pi
//! coefficients are absorbed one per field element. Two distinct witnesses therefore produce
//! distinct transcripts.
//!
//! # Slot gating / padding (pad-to-MAX, left-packed — same statement as the tree)
//!
//! Slot `i` carries a boolean `is_active[i]`:
//! - `is_active[0]` is asserted 1 (`signer_count >= 1`, the invariant the retired flat circuit lost
//!   and the tree restored structurally);
//! - monotonicity `is_active[i+1] <= is_active[i]` makes active slots a strict PREFIX, so the
//!   exposed pk_g list is left-packed with an exactly-zero suffix — byte-identical to
//!   [`super::agg::falcon_agg_expected_public_inputs`];
//! - `signer_count = sum(is_active)`;
//! - ONLY the norm-bound comparison is gated (`select(is_active, beta^2 - norm, 0)`), exactly like
//!   [`super::gadget::FalconSigVerifyTarget::new_conditional`]: an ACTIVE slot enforces the full
//!   native predicate; a PADDING slot (all-zero salt/h/s2/pi) satisfies every ungated constraint
//!   (`pi = 0 = h * s2` at `tau`; `s1 = c` with the norm check off) and exposes a pk_g gated to
//!   EXACTLY zero. A prover cannot inflate `signer_count`: raising a flag turns the norm bound ON,
//!   which the all-zero witness fails for any real digest (`||c||^2 >> beta^2`).
//!
//! # Message binding (TM-C5 item 4 / TM-C6)
//!
//! ONE shared `message` input (PI 0..8) feeds EVERY slot's in-circuit H2P, so all N signatures
//! are verified over exactly the exposed digest — there is no per-slot message witness at all
//! (strictly less witnessed freedom than the tree, which proved per-leaf messages equal). The
//! consumer connects that PI to its in-circuit-recomputed IMCH/IMSB digest, unchanged.
//!
//! # Consumer contract
//!
//! Public inputs are EXACTLY the tree's top-level 137-element layout
//! (`FALCON_AGG_MSG_OFFSET` / `FALCON_AGG_COUNT_OFFSET` / `FALCON_AGG_PK_LIST_OFFSET`), so the
//! close / cancel-close circuits consume a batch proof by a VERIFIER-KEY swap ONLY.
//!
//! # No lookups
//!
//! Binary range checks only, same as the Phase-1 gadget (`doc/tasks/falcon-sig-phase2_5-notes.md`
//! rejected lookups; consumers' `DummyProof` reconstruction requires their absence).

use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::RichField,
        hashing::PlonkyPermutation as _,
        poseidon::{PoseidonHash, SPONGE_RATE, SPONGE_WIDTH},
    },
    iop::{
        ext_target::ExtensionTarget,
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::{
    DOMAIN_FALCON_BATCH, FALCON_N, FALCON_Q, FALCON_SIG_L2_BOUND,
    agg::{FALCON_AGG_PUBLIC_INPUTS_LEN, FalconAggWitness, falcon_agg_public_inputs_len},
    gadget::{
        FalconSigGadgetWitness, ModQGenerator, centered_square, h2p_circuit, pk_digest_circuit,
    },
};
use crate::{
    constants::MAX_COSIGNERS,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
    },
};

// PARAMETERS / BOUNDS LEDGER
// ================================================================================================

const Q: u64 = FALCON_Q as u64; // 12289
const N: usize = FALCON_N; // 512

/// Degree bound of the witnessed integer product `pi = h * s2`: `deg <= 2N - 2`.
pub const PI_COEFFS: usize = 2 * N - 1; // 1023

/// Range-check width of each `pi` coefficient. The honest maximum is
/// `N * (q-1)^2 = 512 * 12288^2 = 77_309_411_328 < 2^37` (asserted at build time).
const PI_BITS: usize = 37;

/// The positive offset added before the `s1` fold reduction so the reduced value is
/// non-negative: `t = c[j] + pi[512+j] + S1_FOLD_OFFSET - pi[j]` with `pi[j] < 2^PI_BITS`.
/// A multiple of q (congruence preserved), `>= 2^PI_BITS` (non-negativity).
const S1_FOLD_OFFSET: u64 = ((1u64 << PI_BITS) / Q + 1) * Q;

/// Quotient bits of the `s1` fold reduction:
/// `t_max = (q-1) + (2^37 - 1) + S1_FOLD_OFFSET < 2^25 * q` (asserted at build time).
const S1_FOLD_K_BITS: usize = 25;

const _: () = {
    // pi coefficient bound: N * (q-1)^2 < 2^PI_BITS.
    assert!((N as u64) * (Q - 1) * (Q - 1) < 1 << PI_BITS);
    // The offset really is a multiple of q and covers the largest subtrahend.
    assert!(S1_FOLD_OFFSET % Q == 0);
    assert!(S1_FOLD_OFFSET >= (1 << PI_BITS) - 1);
    // Fold-reduction quotient fits S1_FOLD_K_BITS, and the reduction cannot wrap mod p
    // (k_bits <= 49 is separately asserted inside `reduce_mod_q`).
    assert!((Q - 1) + ((1u64 << PI_BITS) - 1) + S1_FOLD_OFFSET < (1u64 << S1_FOLD_K_BITS) * Q);
    // Schwartz-Zippel integer-lift premise: |delta coefficients| < 2^38 << p/2, so
    // delta ≡ 0 mod p iff delta = 0 over Z. (p = Goldilocks, ~2^64.)
    assert!((1u128 << PI_BITS) + ((N as u128) * ((Q - 1) as u128) * ((Q - 1) as u128)) < 1 << 62);
};

/// Transcript length: per slot `h` packed (N/4) + `s2` packed (N/4) + `pi` raw (PI_COEFFS).
const TRANSCRIPT_ELEMS_PER_SLOT: usize = N / 4 + N / 4 + PI_COEFFS; // 1279
const TRANSCRIPT_ELEMS: usize = MAX_COSIGNERS * TRANSCRIPT_ELEMS_PER_SLOT; // 20464 = 2558 * 8

// IN-CIRCUIT HELPERS
// ================================================================================================

/// Range-checks `v < q` with ONE binary decomposition row instead of the Phase-1 gadget's two
/// (`v < 2^14` and `(q-1) - v < 2^14`). This circuit performs ~1.5k `< q` checks PER SLOT; the
/// one-row form is what keeps the whole 16-slot batch inside degree 2^17.
///
/// SECURITY (equivalence with the two-check form): `split_le` constrains `v = sum b_i 2^i` over
/// exactly 14 boolean limbs (booleanity enforced by the `BaseSumGate` itself), so `v < 2^14`.
/// With `q - 1 = 12288 = 2^13 + 2^12`, the additional constraint `b13 * b12 * (v - 12288) = 0`
/// gives exactly `v <= 12288`:
///   - if `b13 * b12 = 1` then `v = 12288 + (low 12 bits)` and the constraint forces the low bits
///     to zero, i.e. `v = 12288`;
///   - if `b13 * b12 = 0` the maximum is `2^13 + 2^12 - 1 = 12287 < q` already.
/// Completeness: every canonical `v < q` satisfies it (honest low bits are zero when both top
/// bits are set only for `v = 12288`). Binary gates only — the no-lookups rule holds.
fn assert_canonical_coeff_fast<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    v: Target,
) {
    let bits = builder.split_le(v, 14);
    let hi_and = builder.mul(bits[13].target, bits[12].target);
    let shifted = builder.add_const(v, -F::from_canonical_u64(Q - 1));
    let smuggled = builder.mul(hi_and, shifted);
    builder.assert_zero(smuggled);
}

/// Batch-local mirror of the Phase-1 `reduce_mod_q` (same [`ModQGenerator`], same `t = k*q + r`
/// recomposition and `k < 2^k_bits` quotient check, same no-wrap obligation `k_bits <= 49`),
/// with the `r < q` half done by [`assert_canonical_coeff_fast`]. The uniqueness argument is
/// unchanged: the representable set `{k*q + r : k < 2^k_bits, r < q}` has one `(k, r)` per
/// value and cannot wrap mod p.
fn reduce_mod_q_fast<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    t: Target,
    k_bits: usize,
) -> Target {
    assert!(
        (1..=49).contains(&k_bits),
        "k_bits out of the no-wrap range"
    );
    let k = builder.add_virtual_target();
    let r = builder.add_virtual_target();
    builder.add_simple_generator(ModQGenerator { t, k, r });
    let recomposed = builder.mul_const_add(F::from_canonical_u64(Q), k, r);
    builder.connect(t, recomposed);
    builder.range_check(k, k_bits);
    assert_canonical_coeff_fast(builder, r);
    r
}

/// Packs canonicity-checked (`< q < 2^14`) coefficients 4-per-element in 14-bit lanes,
/// little-lane-first — the same injective packing `falcon_pk_digest` uses. PRECONDITION
/// (caller-enforced): every coefficient has been range-checked `< q`.
fn pack_coeffs_4x14<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    coeffs: &[Target],
) -> Vec<Target> {
    assert_eq!(coeffs.len() % 4, 0);
    coeffs
        .chunks_exact(4)
        .map(|chunk| {
            let mut e = chunk[3];
            for &lane in [chunk[2], chunk[1], chunk[0]].iter() {
                e = builder.mul_const_add(F::from_canonical_u64(1 << 14), e, lane);
            }
            e
        })
        .collect()
}

/// Fixed-length overwrite-mode Poseidon sponge over `absorbed` (whose length must be a multiple
/// of the rate), capacity domain-separated with [`DOMAIN_FALCON_BATCH`]; returns the first `D`
/// squeezed elements as the extension-field challenge `tau`.
///
/// SECURITY: same sponge conventions as the audited H2P mirror (`gadget::h2p_circuit`): the
/// domain constant sits in the CAPACITY, rate blocks OVERWRITE, the length is a build-time
/// constant (so no variable-length padding ambiguity exists), and every absorbed element is a
/// constrained wire of this circuit.
fn transcript_challenge<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    absorbed: &[Target],
) -> ExtensionTarget<D> {
    assert!(D <= 4, "tau must fit in one squeezed rate block half");
    assert_eq!(absorbed.len() % SPONGE_RATE, 0);
    assert!(!absorbed.is_empty());

    let zero = builder.zero();
    let domain = builder.constant(F::from_canonical_u32(DOMAIN_FALCON_BATCH));

    // State: [block_0 (rate 8) | IMFB, 0, 0, 0 (capacity)].
    let mut state: Vec<Target> = absorbed[..SPONGE_RATE].to_vec();
    state.push(domain);
    state.extend([zero; 3]);
    debug_assert_eq!(state.len(), SPONGE_WIDTH);

    let mut perm = <PoseidonHash as AlgebraicHasher<F>>::AlgebraicPermutation::default();
    perm.set_from_slice(&state, 0);
    perm = builder.permute::<PoseidonHash>(perm);

    for block in absorbed[SPONGE_RATE..].chunks(SPONGE_RATE) {
        let mut state: Vec<Target> = perm.as_ref().to_vec();
        state[..SPONGE_RATE].copy_from_slice(block);
        let mut next = <PoseidonHash as AlgebraicHasher<F>>::AlgebraicPermutation::default();
        next.set_from_slice(&state, 0);
        perm = builder.permute::<PoseidonHash>(next);
    }

    let out = perm.squeeze();
    ExtensionTarget(core::array::from_fn(|i| out[i]))
}

/// Horner evaluation of a base-field-coefficient polynomial at the extension point `tau`.
/// One `mul_add_extension` per coefficient (~`num_ops` packed per `ArithmeticExtensionGate`
/// row), which is the whole point: evaluation is LINEAR in n with a tiny constant, unlike the
/// NTT it replaces.
fn eval_at_tau<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    coeffs: &[Target],
    tau: ExtensionTarget<D>,
) -> ExtensionTarget<D> {
    let mut acc = builder.zero_extension();
    for &c in coeffs.iter().rev() {
        let c_ext = builder.convert_to_ext(c);
        acc = builder.mul_add_extension(acc, tau, c_ext);
    }
    acc
}

// THE CIRCUIT
// ================================================================================================

/// Per-slot targets: the presence flag and the signature witnesses (`pi` is the witnessed
/// integer product `h * s2` — see the module doc).
struct BatchSlotTarget {
    is_active: BoolTarget,
    salt: [Target; 8],
    h: Vec<Target>,
    s2: Vec<Target>,
    pi: Vec<Target>,
}

/// Flat aggregate-verification circuit for up to [`MAX_COSIGNERS`] Falcon-512/Poseidon
/// signatures over one shared message digest, exposing the tree's exact 137-element top-level
/// contract. Consumer-facing API mirrors [`super::agg::FalconAggCircuit`]: `new()`,
/// `verifier_data()`, `data()`, `prove(&FalconAggWitness)`.
pub struct FalconBatchAggCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    message: Bytes32Target,
    slots: Vec<BatchSlotTarget>,
    /// Builder gate count before padding (reported alongside `data.common.degree_bits()`).
    pub num_gates_before_padding: usize,
}

impl<F, C, const D: usize> Default for FalconBatchAggCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> FalconBatchAggCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        // D >= 2 keeps the Schwartz-Zippel error at n/p^D <= 2^-117; a base-field tau (D = 1)
        // would leave a ~2^-54 forgery margin, far below the scheme's security level.
        assert!(
            D >= 2,
            "batch product check requires an extension-field tau"
        );

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // The ONE shared message input (PI 0..8) — every slot's H2P consumes these very wires.
        let message = Bytes32Target::new(&mut builder, true);

        // Presence flags: booleans, slot 0 forced active, monotone non-increasing (left-packed
        // prefix). `signer_count = sum(flags)` — no other witness feeds the count.
        let flags: Vec<BoolTarget> = (0..MAX_COSIGNERS)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect();
        builder.assert_one(flags[0].target);
        let one = builder.one();
        for w in flags.windows(2) {
            // next * (1 - prev) == 0  ⟺  next <= prev.
            let not_prev = builder.sub(one, w[0].target);
            let smuggled = builder.mul(w[1].target, not_prev);
            builder.assert_zero(smuggled);
        }
        let signer_count = builder.add_many(flags.iter().map(|b| b.target));

        // Per-slot witnesses + everything EXCEPT the product check (deferred to tau).
        let mut slots: Vec<BatchSlotTarget> = Vec::with_capacity(MAX_COSIGNERS);
        let mut transcript: Vec<Target> = Vec::with_capacity(TRANSCRIPT_ELEMS);
        let mut gated_pk_limbs: Vec<Target> = Vec::with_capacity(MAX_COSIGNERS * 8);
        let beta_sq = builder.constant(F::from_canonical_u64(FALCON_SIG_L2_BOUND));
        let zero = builder.zero();

        for &flag in flags.iter() {
            let salt: [Target; 8] = core::array::from_fn(|_| builder.add_virtual_target());
            let h: Vec<Target> = (0..N).map(|_| builder.add_virtual_target()).collect();
            let s2: Vec<Target> = (0..N).map(|_| builder.add_virtual_target()).collect();
            let pi: Vec<Target> = (0..PI_COEFFS)
                .map(|_| builder.add_virtual_target())
                .collect();

            // Canonicity (TM-C5 items 1/5): h and s2 in [0, q) — makes the 4x14 packing (pk
            // digest AND transcript) injective and feeds the centered norm.
            for &c in h.iter().chain(s2.iter()) {
                assert_canonical_coeff_fast(&mut builder, c);
            }
            // pi coefficients: the honest integer-product range (bounds ledger above). This is
            // also what makes the Schwartz-Zippel integer lift valid.
            for &c in pi.iter() {
                builder.range_check(c, PI_BITS);
            }

            // pk_g = Poseidon(IMFK || encode(h)), gated by presence into the exposed list
            // (identically zero for padding slots — the native left-packed reference).
            let pk = pk_digest_circuit(&mut builder, &h);
            for &limb in pk.to_vec().iter() {
                gated_pk_limbs.push(builder.mul(flag.target, limb));
            }

            // c = H2P(salt, message) over the SHARED message wires (salt range checks inside).
            let c = h2p_circuit(&mut builder, &salt, &message);

            // s1[j] = c[j] - pi[j] + pi[512 + j] (mod q), one reduction per coefficient
            // (negacyclic fold: x^512 ≡ -1). t is kept positive by S1_FOLD_OFFSET (a multiple
            // of q); quotient bound per the ledger.
            let offset = F::from_canonical_u64(S1_FOLD_OFFSET);
            let s1: Vec<Target> = (0..N)
                .map(|j| {
                    let hi = if j < PI_COEFFS - N { pi[N + j] } else { zero };
                    let c_plus_hi = builder.add(c[j], hi);
                    let shifted = builder.add_const(c_plus_hi, offset);
                    let t = builder.sub(shifted, pi[j]);
                    reduce_mod_q_fast(&mut builder, t, S1_FOLD_K_BITS)
                })
                .collect();

            // Centered norm over (s1, s2); ONLY this comparison is gated by the presence flag
            // (module doc: identical gating to the audited conditional gadget).
            let squares: Vec<Target> = s1
                .iter()
                .chain(s2.iter())
                .map(|&v| centered_square(&mut builder, v))
                .collect();
            let norm = builder.add_many(&squares);
            let slack = builder.sub(beta_sq, norm);
            let checked_slack = builder.select(flag, slack, zero);
            builder.range_check(checked_slack, 26);

            // Transcript contribution (order fixed: packed h, packed s2, raw pi).
            transcript.extend(pack_coeffs_4x14(&mut builder, &h));
            transcript.extend(pack_coeffs_4x14(&mut builder, &s2));
            transcript.extend_from_slice(&pi);

            slots.push(BatchSlotTarget {
                is_active: flag,
                salt,
                h,
                s2,
                pi,
            });
        }

        // Fiat-Shamir challenge over ALL slots' committed polynomials, then the per-slot
        // product checks pi_i(tau) == h_i(tau) * s2_i(tau).
        assert_eq!(transcript.len(), TRANSCRIPT_ELEMS);
        let tau = transcript_challenge(&mut builder, &transcript);
        for slot in slots.iter() {
            let h_eval = eval_at_tau(&mut builder, &slot.h, tau);
            let s2_eval = eval_at_tau(&mut builder, &slot.s2, tau);
            let pi_eval = eval_at_tau(&mut builder, &slot.pi, tau);
            let prod = builder.mul_extension(h_eval, s2_eval);
            builder.connect_extension(pi_eval, prod);
        }

        // Public inputs — the tree's exact top-level layout: message(8) | count(1) | 16 pk_g(8).
        builder.register_public_inputs(&message.to_vec());
        builder.register_public_input(signer_count);
        builder.register_public_inputs(&gated_pk_limbs);

        let num_gates_before_padding = builder.num_gates();
        let data = builder.build::<C>();
        // Release-mode self-check of the consumer contract (same guard as agg.rs).
        assert_eq!(
            data.common.num_public_inputs, FALCON_AGG_PUBLIC_INPUTS_LEN,
            "batch public-input arity does not match the 137-element contract"
        );
        debug_assert_eq!(
            FALCON_AGG_PUBLIC_INPUTS_LEN,
            falcon_agg_public_inputs_len(super::agg::AGG_LEVELS)
        );

        Self {
            data,
            message,
            slots,
            num_gates_before_padding,
        }
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.data.verifier_data()
    }

    /// API parity with `FalconAggCircuit::data()` (consumers report degree bits etc.).
    pub fn data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }

    /// Proves the aggregate over `witness.active` signatures (slot order) — same entry point
    /// and same [`FalconAggWitness`] as the tree, ONE proof instead of up to 31.
    pub fn prove(&self, witness: &FalconAggWitness) -> Result<ProofWithPublicInputs<F, C, D>> {
        anyhow::ensure!(
            (1..=MAX_COSIGNERS).contains(&witness.active.len()),
            "FalconBatchAggCircuit: active signer count {} out of range 1..={MAX_COSIGNERS}",
            witness.active.len()
        );
        // Prover-side convenience only (fail early with a clear error); the binding check is
        // the shared in-circuit message wire.
        for (i, gw) in witness.active.iter().enumerate() {
            anyhow::ensure!(
                gw.message_digest == witness.message,
                "FalconBatchAggCircuit: signer {i} witness signs a different message"
            );
        }

        let mut pw = PartialWitness::<F>::new();
        self.message
            .set_witness::<F, Bytes32>(&mut pw, witness.message);
        let padding = FalconSigGadgetWitness::padding(witness.message);
        for (i, slot) in self.slots.iter().enumerate() {
            match witness.active.get(i) {
                Some(gw) => {
                    let pi = integer_product(&gw.h, &gw.s2);
                    set_slot_witness(&mut pw, slot, true, gw, &pi)?;
                }
                None => {
                    set_slot_witness(&mut pw, slot, false, &padding, &[0u64; PI_COEFFS])?;
                }
            }
        }
        self.data.prove(pw)
    }
}

/// Sets one slot's raw witness values. Split out (rather than inlined in `prove`) so the
/// adversarial tests can drive DOCTORED `pi` values through the exact production path.
fn set_slot_witness<F: RichField>(
    pw: &mut PartialWitness<F>,
    slot: &BatchSlotTarget,
    is_active: bool,
    gw: &FalconSigGadgetWitness,
    pi: &[u64],
) -> Result<()> {
    pw.set_bool_target(slot.is_active, is_active)?;
    for (t, v) in slot.salt.iter().zip(gw.salt_elements.iter()) {
        pw.set_target(*t, F::from_canonical_u64(*v))?;
    }
    for (t, v) in slot.h.iter().zip(gw.h.iter()) {
        pw.set_target(*t, F::from_canonical_u64(*v))?;
    }
    for (t, v) in slot.s2.iter().zip(gw.s2.iter()) {
        pw.set_target(*t, F::from_canonical_u64(*v))?;
    }
    anyhow::ensure!(pi.len() == PI_COEFFS, "pi witness has the wrong length");
    for (t, v) in slot.pi.iter().zip(pi.iter()) {
        pw.set_target(*t, F::from_canonical_u64(*v))?;
    }
    Ok(())
}

/// The honest `pi` witness: the INTEGER product `h * s2` over `Z[x]` (no reduction), canonical
/// inputs in `[0, q)`. Max coefficient `N * (q-1)^2 < 2^37` — no u64 overflow (bounds ledger).
fn integer_product(h: &[u64], s2: &[u64]) -> Vec<u64> {
    assert_eq!(h.len(), N);
    assert_eq!(s2.len(), N);
    let mut pi = vec![0u64; PI_COEFFS];
    for (i, &hi) in h.iter().enumerate() {
        if hi == 0 {
            continue;
        }
        for (j, &sj) in s2.iter().enumerate() {
            pi[i + j] += hi * sj;
        }
    }
    pi
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use once_cell::sync::Lazy;
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field as _, PrimeField64 as _},
        },
        plonk::config::PoseidonGoldilocksConfig,
    };

    use super::*;
    use crate::{
        ethereum_types::u32limb_trait::U32LimbTrait as _,
        falcon_sig::{
            FalconKeys, FalconSignature,
            agg::{FALCON_AGG_COUNT_OFFSET, falcon_agg_expected_public_inputs},
            falcon_pk_digest,
        },
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    /// ONE shared batch circuit for the whole suite (every case proves / fails against the same
    /// constraint system, so sharing weakens nothing).
    static BATCH: Lazy<FalconBatchAggCircuit<F, C, D>> = Lazy::new(FalconBatchAggCircuit::new);

    fn digest(tag: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_4348, tag as u32, 2, 3, 4, 5, 6, 7]).unwrap()
    }

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

    fn assert_rejected(build: impl FnOnce() -> Result<ProofWithPublicInputs<F, C, D>>, msg: &str) {
        let result = catch_unwind(AssertUnwindSafe(build));
        let rejected = match result {
            Err(_) => true,
            Ok(Err(_)) => true,
            Ok(Ok(proof)) => BATCH.data.verify(proof).is_err(),
        };
        assert!(rejected, "{msg}");
    }

    /// Prove with raw per-slot control (flags / doctored pi) through the production
    /// `set_slot_witness` path.
    fn raw_prove(
        message: Bytes32,
        slots: &[(bool, FalconSigGadgetWitness, Vec<u64>)],
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        assert_eq!(slots.len(), MAX_COSIGNERS);
        let mut pw = PartialWitness::<F>::new();
        BATCH.message.set_witness::<F, Bytes32>(&mut pw, message);
        for (slot, (flag, gw, pi)) in BATCH.slots.iter().zip(slots.iter()) {
            set_slot_witness(&mut pw, slot, *flag, gw, pi)?;
        }
        BATCH.data.prove(pw)
    }

    fn padding_slot(msg: Bytes32) -> (bool, FalconSigGadgetWitness, Vec<u64>) {
        (
            false,
            FalconSigGadgetWitness::padding(msg),
            vec![0u64; PI_COEFFS],
        )
    }

    fn active_slot(gw: &FalconSigGadgetWitness) -> (bool, FalconSigGadgetWitness, Vec<u64>) {
        (true, gw.clone(), integer_product(&gw.h, &gw.s2))
    }

    /// The native schoolbook integer product really is what `integer_product` computes and its
    /// coefficients respect the range-check bound (bounds-ledger completeness half).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn integer_product_bound() {
        let msg = digest(0x70);
        let (hs, sigs) = signers(1, msg, 200);
        let gw = witness_for(&hs, &sigs, msg);
        let pi = integer_product(&gw.active[0].h, &gw.active[0].s2);
        assert!(pi.iter().all(|&c| c < 1 << PI_BITS));
        // Spot-check one middle coefficient against a direct convolution.
        let j = 700;
        let mut want = 0u64;
        for i in 0..N {
            if j >= i && j - i < N {
                want += gw.active[0].h[i] * gw.active[0].s2[j - i];
            }
        }
        assert_eq!(pi[j], want);
    }

    /// Happy path, N = 2 (minimum close cosigner count), PIs byte-identical to the tree's
    /// left-packed reference — the consumer-contract equivalence this module claims.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn batch_happy_n2() {
        let msg = digest(1);
        let (hs, sigs) = signers(2, msg, 10);
        let pks: Vec<Bytes32> = hs.iter().map(falcon_pk_digest).collect();
        let proof = BATCH
            .prove(&witness_for(&hs, &sigs, msg))
            .expect("prove n2");
        BATCH.data.verify(proof.clone()).expect("verify n2");
        assert_eq!(
            proof.public_inputs,
            falcon_agg_expected_public_inputs::<F>(crate::falcon_sig::agg::AGG_LEVELS, msg, &pks)
        );
    }

    /// Happy path, N = 3 (odd count exercises padding slots) and N = 1 (structural minimum).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn batch_happy_n3_and_n1() {
        let msg = digest(3);
        let (hs, sigs) = signers(3, msg, 50);
        let pks: Vec<Bytes32> = hs.iter().map(falcon_pk_digest).collect();
        let proof = BATCH
            .prove(&witness_for(&hs, &sigs, msg))
            .expect("prove n3");
        BATCH.data.verify(proof.clone()).expect("verify n3");
        assert_eq!(
            proof.public_inputs,
            falcon_agg_expected_public_inputs::<F>(crate::falcon_sig::agg::AGG_LEVELS, msg, &pks)
        );

        let (hs1, sigs1) = signers(1, msg, 90);
        let p1 = BATCH.prove(&witness_for(&hs1, &sigs1, msg)).expect("n1");
        BATCH.data.verify(p1.clone()).expect("verify n1");
        assert_eq!(p1.public_inputs[FALCON_AGG_COUNT_OFFSET], F::ONE);
    }

    /// Happy path, N = MAX_COSIGNERS = 16 (no padding slot anywhere).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn batch_happy_n16() {
        let msg = digest(2);
        let (hs, sigs) = signers(MAX_COSIGNERS, msg, 30);
        let pks: Vec<Bytes32> = hs.iter().map(falcon_pk_digest).collect();
        let proof = BATCH
            .prove(&witness_for(&hs, &sigs, msg))
            .expect("prove n16");
        BATCH.data.verify(proof.clone()).expect("verify n16");
        assert_eq!(
            proof.public_inputs,
            falcon_agg_expected_public_inputs::<F>(crate::falcon_sig::agg::AGG_LEVELS, msg, &pks)
        );
    }

    // ---- adversarial suite -------------------------------------------------------------------

    /// O-6 (message binding): signatures over message A cannot be aggregated under message B —
    /// the shared message wire feeds every slot's H2P, so the norm bound fails.
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
            || BATCH.prove(&w),
            "signatures over A must not aggregate under message B",
        );
    }

    /// signer_count inflation: flagging a PADDING slot active turns its norm bound ON, which
    /// the all-zero witness fails (`s1 = c`, `||c||^2 >> beta^2`). This is the batch analogue
    /// of the tree's "dummy right child flagged present" attack.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn padding_slot_flagged_active_rejected() {
        let msg = digest(7);
        let (hs, sigs) = signers(1, msg, 70);
        let w = witness_for(&hs, &sigs, msg);
        let mut slots = vec![padding_slot(msg); MAX_COSIGNERS];
        slots[0] = active_slot(&w.active[0]);
        // Slot 1: padding witness, flag forced ACTIVE.
        slots[1] = (
            true,
            FalconSigGadgetWitness::padding(msg),
            vec![0u64; PI_COEFFS],
        );
        assert_rejected(
            || raw_prove(msg, &slots),
            "an active flag on a padding witness must be rejected by the live norm bound",
        );
    }

    /// signer_count floor: all-flags-zero (count 0) must be unprovable — slot 0's flag is the
    /// asserted constant 1. (The consumer entry point separately rejects an empty active list.)
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn zero_signers_rejected() {
        let msg = digest(11);
        let slots = vec![padding_slot(msg); MAX_COSIGNERS];
        assert_rejected(
            || raw_prove(msg, &slots),
            "an aggregate with signer_count = 0 must be rejected",
        );
        assert!(
            BATCH
                .prove(&FalconAggWitness {
                    message: msg,
                    active: Vec::new(),
                })
                .is_err(),
            "the consumer entry point must reject an empty active list"
        );
    }

    /// LEFT-PACKING: a real signature in a NON-prefix slot (gap before it) violates flag
    /// monotonicity and must be unprovable — otherwise a zero pk_g could appear in a non-suffix
    /// slot, breaking every consumer that reads "the first signer_count slots".
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn non_left_packed_flags_rejected() {
        let msg = digest(0x78);
        let (hs, sigs) = signers(2, msg, 130);
        let w = witness_for(&hs, &sigs, msg);
        let mut slots = vec![padding_slot(msg); MAX_COSIGNERS];
        slots[0] = active_slot(&w.active[0]);
        // GAP at slot 1; real signature flagged active at slot 2.
        slots[2] = active_slot(&w.active[1]);
        assert_rejected(
            || raw_prove(msg, &slots),
            "a non-prefix active slot must violate the monotone-flag constraint",
        );
    }

    /// PRODUCT-CHECK soundness, both directions the eval identity must catch:
    ///   (a) an additive tamper (`pi[0] += 1`) and
    ///   (b) a MOD-Q-EQUIVALENT tamper (`pi[0] += q`) — the s1 fold would NOT notice (b)
    ///       (same residue), so rejecting it demonstrates the integer-level binding of the
    ///       Schwartz-Zippel check, not just the mod-q arithmetic.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn tampered_product_witness_rejected() {
        let msg = digest(0x41);
        let (hs, sigs) = signers(1, msg, 140);
        let w = witness_for(&hs, &sigs, msg);
        for delta in [1u64, Q] {
            let mut slots = vec![padding_slot(msg); MAX_COSIGNERS];
            let (flag, gw, mut pi) = active_slot(&w.active[0]);
            pi[0] += delta;
            slots[0] = (flag, gw, pi);
            assert_rejected(
                || raw_prove(msg, &slots),
                "a tampered product polynomial must fail the tau evaluation check",
            );
        }
    }

    /// Boundary semantics of the ONE-ROW canonicity check (`assert_canonical_coeff_fast`):
    /// exactly `[0, q)` is accepted — `q - 1 = 12288` (both top bits set, low bits zero) is the
    /// largest accepted value; `q` and any 14-bit value above it reject; values needing a 15th
    /// bit reject on the decomposition itself.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn fast_canonical_check_boundary() {
        for (v, ok) in [
            (0u64, true),
            (12287, true),
            (12288, true), // q - 1: the exact boundary the b13*b12 constraint must ACCEPT
            (12289, false), // q: must REJECT (the classic (k-1, r+q) smuggling residue)
            (16383, false), // 2^14 - 1: fits the decomposition, must reject on the top-bit rule
            (16384, false), // 2^14: must reject on the 14-limb decomposition
        ] {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            let t = builder.add_virtual_target();
            assert_canonical_coeff_fast(&mut builder, t);
            let data = builder.build::<C>();
            let mut pw = PartialWitness::<F>::new();
            pw.set_target(t, F::from_canonical_u64(v)).unwrap();
            let result = catch_unwind(AssertUnwindSafe(|| data.prove(pw)));
            let accepted = matches!(&result, Ok(Ok(p)) if data.verify(p.clone()).is_ok());
            assert_eq!(accepted, ok, "canonicity boundary at v = {v}");
        }
    }

    /// A NON-CANONICAL `s2` residue (`s2[0] = q`) must be rejected by the canonicity gate even
    /// when the product witness `pi` is consistently computed over it (so the tau check alone
    /// would pass) — one residue class must have exactly one in-circuit encoding.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn noncanonical_s2_rejected() {
        let msg = digest(0x52);
        let (hs, sigs) = signers(1, msg, 180);
        let w = witness_for(&hs, &sigs, msg);
        let mut gw = w.active[0].clone();
        gw.s2[0] = Q; // same residue class as 0, non-canonical encoding
        let mut slots = vec![padding_slot(msg); MAX_COSIGNERS];
        slots[0] = (true, gw.clone(), integer_product(&gw.h, &gw.s2));
        assert_rejected(
            || raw_prove(msg, &slots),
            "a non-canonical s2 coefficient must be rejected by the canonicity gate",
        );
    }

    /// The exposed statement carries no witnessed freedom: tampering ANY public input of a
    /// verified proof must break verification.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn forged_public_input_fails_verification() {
        let msg = digest(0x33);
        let (hs, sigs) = signers(2, msg, 110);
        let proof = BATCH.prove(&witness_for(&hs, &sigs, msg)).unwrap();
        BATCH.data.verify(proof.clone()).unwrap();
        assert_eq!(proof.public_inputs.len(), FALCON_AGG_PUBLIC_INPUTS_LEN);
        for i in 0..proof.public_inputs.len() {
            let mut forged = proof.clone();
            forged.public_inputs[i] += F::ONE;
            assert!(
                BATCH.data.verify(forged).is_err(),
                "tampered public input {i} must fail verification"
            );
        }
    }

    /// Measurement (the deliverable): build + prove times for N = 2 and N = 16 in the ONE flat
    /// circuit, to compare against the tree's leaf/level chain. Run with --nocapture.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn batch_measure() {
        let t0 = std::time::Instant::now();
        let circuit = FalconBatchAggCircuit::<F, C, D>::new();
        println!(
            "[batch] gates={} degree_bits={} num_pis={} build={:?}",
            circuit.num_gates_before_padding,
            circuit.data.common.degree_bits(),
            circuit.data.common.num_public_inputs,
            t0.elapsed()
        );

        let msg = digest(9);
        for n in [2usize, 16] {
            let (hs, sigs) = signers(n, msg, 150);
            let w = witness_for(&hs, &sigs, msg);
            let t = std::time::Instant::now();
            let proof = circuit.prove(&w).expect("prove");
            println!("[batch N={n}] prove={:?}", t.elapsed());
            circuit.data.verify(proof).expect("verify");
        }
    }
}
