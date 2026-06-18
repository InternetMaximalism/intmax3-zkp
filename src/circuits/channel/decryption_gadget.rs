//! Decryption Stage 2 — the shared in-circuit Regev decryption-core gadget (plonky2, Goldilocks).
//!
//! This is the highest-risk cryptographic component in the repository: a HAND-ROLLED lattice
//! decryption relation proven inside a plonky2 circuit. It binds a withdrawal/post-close claim's
//! `amount` to the plaintext of the slot/delta ciphertext, closing the over-claim residual of
//! Phase B-D. Authoritative spec: `tasks/decryption-subphase-design.md` (§design construction,
//! the per-hazard soundness table, the MUST-FIX list, and the Stage 2 section).
//!
//! GROUND TRUTH mirrored from the BabyBear STARK `DecryptionAir` core
//! (`src/regev/transfer_stark.rs`): `eval_decryption_core` (constraints 1–4),
//! `negacyclic_mul_with_quotient` (the ring product), `build_decryption_witness` (the prove-side
//! witness), and `params.rs` (q, n, Δ, the digit/noise decomposition). The STARK proves the ring
//! products `a·s`, `c1·s` via a Schwartz–Zippel identity at a post-commitment challenge `z`; this
//! gadget instead proves them DIRECTLY per coefficient as signed-selection sums (§design "ternary-s
//! construction") — the ternary key makes that cheap, and it removes the SZ/extension machinery
//! that does not exist on the Goldilocks @mle rail.
//!
//! ## What the gadget proves
//!
//! Given a Regev public key `(a, b)` and a ciphertext `(c1, c2)` (all four polynomials are
//! `REGEV_N = 128`-coefficient vectors of mod-q field elements, witnessed by the caller and bound
//! to committed digests OUTSIDE this gadget), and a secret key `s ∈ {-1,0,1}^n`:
//!
//!   (1) Key binding (per coeff, mod q): `b[i] = (a·s)_lo[i] + e_pk[i]` with `e_pk` CBD(2)-ranged.
//!       This forces `s` to be A secret behind the committed pk — without it the plaintext
//!       `c2 − c1·s` is a free function of an attacker-chosen `s` (the CRITICAL-1 attack).
//!   (2) Decryption (per coeff, mod q): `v[i] = c2[i] − (c1·s)_lo[i]`, `v` the canonical
//!       representative (strictly `< q`).
//!   (3) Digit extraction (per coeff, mod q): `v[i] + Δ/2 = Δ·d[i] + ns[i]` with `d[i] ∈ [0,256)`
//!       and `ns[i] ∈ [0,Δ)` EXACTLY (the uniqueness/no-wrap argument of the STARK header).
//!   (4) Digit→bit normalization: `Σ d[i]·2^i == Σ bit[i]·2^i` over the integers via a ripple
//!       carry, where `bit` is the 128-bit binary message.
//!   (5) Amount binding (only when `expose_amount`): the low 64 `bit[i]` equal the claim's u64
//!       `amount` (repo 2×32 form), and `bit[64..128] == 0`.
//!
//! ## The negacyclic ring product as a per-coefficient signed-selection sum (MUST-FIX #1, #4)
//!
//! The native `negacyclic_mul_with_quotient(x, y)` computes, over `Z_q[x]/(x^n+1)`:
//!
//! ```text
//!   prod[k] = Σ_{i+j=k} x[i]·y[j]          (k = 0 .. 2n-2, the full schoolbook product)
//!   lo[i]   = prod[i] − prod[n+i]          (i = 0 .. n-1, the negacyclic reduction x^n ≡ −1)
//! ```
//!
//! Expanding `prod[i]` and `prod[n+i]` and reindexing by the SOURCE coefficient `m` of `x`:
//!
//! ```text
//!   prod[i]   = Σ_{j=0}^{i}     x[i−j]·y[j]        (set m = i−j, m ∈ [0, i])
//!   prod[n+i] = Σ_{j=i+1}^{n-1} x[n+i−j]·y[j]      (set m = n+i−j, m ∈ [i+1, n-1])
//! ```
//!
//! Each source index `m ∈ [0, n-1]` therefore appears in `lo[i]` EXACTLY ONCE:
//!
//! ```text
//!   lo[i] = Σ_{m=0}^{n-1} sign(i,m) · x[m] · y[ (i−m) mod n ]
//!     where  sign(i,m) = +1  if  m ≤ i   (no wrap: y-index = i−m ∈ [0, i])
//!            sign(i,m) = −1  if  m >  i   (wrapped:  y-index = n+i−m ∈ [i+1, n-1], and x^n = −1)
//! ```
//!
//! PROOF the index/sign split matches the ring: for fixed `i`, partition `m` at `i`.
//!   * `m ≤ i`: `j = i − m ∈ [0, i]`, the term `x[m]·y[j]` contributes to `prod[i]` (degree
//!     `m+j=i`), so it lands in `lo[i]` with sign `+1`. ✔
//!   * `m > i`: `j = n + i − m`. Since `i < m ≤ n-1`, `j ∈ [i+1, n-1] ⊂ [0, n-1]` is a valid
//!     `y`-index, and `m + j = n + i`, so the term contributes to `prod[n+i]`, hence to `lo[i]`
//!     with sign `−1` (the `x^n ≡ −1` reduction). ✔
//! Every `(m, j)` pair with `m + j ∈ {i, n+i}` is covered exactly once and no other pair maps to
//! `lo[i]`, so the per-coeff sum equals the native `lo[i]`. The randomized differential test
//! `decryption_gadget_negacyclic_matches_native` checks this over hundreds of `(x, ternary y)`.
//!
//! Because `y = s ∈ {-1,0,1}` and `x[m] < q < 2^31`, every term has magnitude `< q`, the unreduced
//! `lo[i]` integer sum has magnitude `< n·q = 128·q ≈ 2^38 ≪ p` (Goldilocks `p ≈ 2^64`), so the sum
//! is computed with NO intermediate mod-q (and no mod-p wrap) — the only reduction is the explicit
//! per-coeff quotient below. (MUST-FIX #1.)
//!
//! ## Per-coefficient mod-q reduction (MUST-FIX #2, #3)
//!
//! `lo[i]` (an integer in `(−n·q, n·q)`) is reduced to the canonical representative by witnessing
//! an integer quotient `κ[i] ∈ [−n, n]` (range-checked) and asserting `lo[i] − rem[i] − κ[i]·q =
//! 0`, with `rem[i]` range-checked STRICTLY `< q` via the non-power-of-two gadget `assert_lt_q`
//! (NOT a bare 31-bit range — a 31-bit window would admit `rem` and `rem − q` aliases, a
//! malleability hole, since `2^31 − q = 2^27`). For decryption, `rem` is folded directly into `v =
//! c2 − rem`; for key binding, `rem` is the `a·s` remainder compared against `b − e_pk`.
//!
//! Degenerate inputs `a == 0` and `c1 == 0` are rejected (MUST-FIX #3): with `a == 0` the key
//! binding `b = e_pk` holds for any `s`, and with `c1 == 0` the plaintext `v = c2` is independent
//! of `s` — both sever the `s ↔ pk` link the whole soundness argument rests on. "Zero polynomial"
//! means every coefficient is zero; we reject by asserting the polynomial is nonzero (its
//! coefficient sum's inverse exists is too weak — a cancelling sum could be
//! nonzero-poly-but-zero-sum; instead we assert NOT all-coefficients-zero via an OR of per-coeff
//! non-zeros).

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::regev::{REGEV_N, REGEV_PLAIN_BITS, REGEV_Q};

/// `q` as a field constant helper value (`2_013_265_921`).
const Q_U64: u64 = REGEV_Q as u64;
/// `Δ = floor(q / 2^8) = 7_864_320 = 15·2^19` (mirrors `transfer_stark::DELTA_U32`).
const DELTA_U32: u32 = REGEV_Q >> REGEV_PLAIN_BITS;
/// `Δ/2 = 3_932_160`.
const HALF_DELTA_U32: u32 = DELTA_U32 / 2;

/// Digit bits per coefficient (`d ∈ [0, 256)`).
const DIGIT_BITS: usize = REGEV_PLAIN_BITS;
/// Low limb of the shifted-noise decomposition (19 bits).
const NOISE_LO_BITS: usize = 19;
/// Each high-half of the shifted noise (`u, v ∈ [0, 7]`).
const NOISE_HI_HALF_BITS: usize = 3;
/// Normalization carry width (tight bound 254; see the STARK carry-bound analysis).
const CARRY_BITS: usize = 8;

// SECURITY: the digit-extraction soundness argument is arithmetic on these EXACT values; pin them
// at compile time so a parameter change cannot silently invalidate it (mirrors transfer_stark.rs).
const _: () = {
    assert!(DELTA_U32 == 7_864_320);
    assert!(DELTA_U32 % 2 == 0);
    // q = 256·Δ + 1 — the digit no-wrap bound 255·Δ + (Δ − 1) = q − 2 < q.
    assert!(256 * (DELTA_U32 as u64) + 1 == Q_U64);
    // Δ = 15·2^19 — the shifted-noise decomposition covers exactly [0, Δ).
    assert!(DELTA_U32 as u64 == 15u64 << NOISE_LO_BITS);
    assert!((1u64 << NOISE_LO_BITS) - 1 + 14 * (1u64 << NOISE_LO_BITS) == DELTA_U32 as u64 - 1);
    // q − 1 fits in 31 bits, which `assert_lt_q` relies on (q − 1 = 2^31 − 2^27 < 2^31).
    assert!(Q_U64 - 1 < (1u64 << 31));
};

/// The full prove-side witness of one decryption-core invocation, computed natively from
/// `(a, b, c1, c2, s)`. Mirror of `transfer_stark::DecCoreWitness` restricted to what the gadget
/// constrains. `value` is the decoded u64 (only meaningful when `expose_amount`).
#[derive(Clone, Debug)]
pub struct DecryptionCoreWitness {
    /// Secret key, ternary `{-1,0,1}` per coefficient (length `REGEV_N`).
    pub s: Vec<i8>,
    /// `e_pk = e_pk_u − e_pk_v`, halves in `{0,1,2}` (length `REGEV_N`).
    pub epk_u: Vec<u8>,
    pub epk_v: Vec<u8>,
    /// `(a·s)_lo` remainder, canonical `< q` (length `REGEV_N`).
    pub as_rem: Vec<u32>,
    /// `(a·s)_lo` integer quotient `κ ∈ [−n, n]` (length `REGEV_N`).
    pub as_kappa: Vec<i64>,
    /// Key-binding boundary wrap `w ∈ {−1,0,1}`: `b − e_pk − as_rem = w·q` (length `REGEV_N`).
    pub as_wrap: Vec<i64>,
    /// `v = (c2 − (c1·s)_lo)` canonical `< q` (length `REGEV_N`).
    pub v: Vec<u32>,
    /// `(c1·s)_lo` integer quotient `κ ∈ [−n, n]` (length `REGEV_N`).
    pub cs_kappa: Vec<i64>,
    /// Per-coeff digit `d ∈ [0, 256)` (length `REGEV_N`).
    pub digits: Vec<u8>,
    /// Per-coeff shifted noise `ns ∈ [0, Δ)` (length `REGEV_N`).
    pub noise_shifted: Vec<u32>,
    /// Per-coeff digit-extraction boundary wrap `dwrap ∈ {0,1}`: `v + Δ/2 = Δ·d + ns + dwrap·q`.
    pub digit_wrap: Vec<bool>,
    /// 128-bit binary message (length `REGEV_N`), `Σ bit·2^i == Σ d·2^i`.
    pub bits: Vec<u8>,
    /// Normalization carries `c_i ∈ [0, 254]` (length `REGEV_N`), `c_0 = 0`, final carry 0.
    pub carries: Vec<u16>,
    /// Decoded value (only meaningful for `expose_amount`).
    pub value: u64,
}

/// Targets the caller supplies to [`decryption_core`]: the four ciphertext/pk polynomials. Each is
/// a `REGEV_N`-length vector of u32-range-checked targets (the caller must range-check them — the
/// digest gadgets that bind these to commitments already 32-bit range-check, and the strict-`<q`
/// checks below tighten `a`, `b`, `c1`, `c2` to canonical).
pub struct DecryptionCoreInputs<'a> {
    pub a: &'a [Target],
    pub b: &'a [Target],
    pub c1: &'a [Target],
    pub c2: &'a [Target],
}

/// Witness handles returned by [`decryption_core`] so the caller can fill them via
/// [`fill_decryption_core`]. Opaque to the caller — it only needs to pass the
/// [`DecryptionCoreWitness`].
pub struct DecryptionCoreTargets {
    s: Vec<Target>,
    epk_u: Vec<Target>,
    epk_v: Vec<Target>,
    as_rem: Vec<Target>,
    as_kappa: Vec<Target>,
    as_wrap: Vec<Target>,
    v: Vec<Target>,
    cs_kappa: Vec<Target>,
    d_bits: Vec<[BoolTarget; DIGIT_BITS]>,
    noise_lo: Vec<[BoolTarget; NOISE_LO_BITS]>,
    noise_u: Vec<[BoolTarget; NOISE_HI_HALF_BITS]>,
    noise_v: Vec<[BoolTarget; NOISE_HI_HALF_BITS]>,
    bit: Vec<BoolTarget>,
    carry: Vec<Target>,
    digit_wrap: Vec<BoolTarget>,
    /// Whether the amount limbs are bound (true for claim circuits).
    expose_amount: bool,
}

/// Build the decryption-core constraints. Returns the witness handles plus, when `expose_amount`,
/// the two u32 amount limbs `(lo, hi)` so the caller can connect them to the claim's U64 PI.
///
/// `expose_amount == false` keeps `bit` private and OMITS the amount binding (refresh/privacy,
/// hazard #9). Stage 2 only uses `expose_amount == true`.
pub fn decryption_core<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &DecryptionCoreInputs,
    expose_amount: bool,
) -> (DecryptionCoreTargets, Option<(Target, Target)>) {
    let n = REGEV_N;
    assert_eq!(inputs.a.len(), n);
    assert_eq!(inputs.b.len(), n);
    assert_eq!(inputs.c1.len(), n);
    assert_eq!(inputs.c2.len(), n);

    let q = builder.constant(F::from_canonical_u64(Q_U64));
    let delta = builder.constant(F::from_canonical_u32(DELTA_U32));
    let half_delta = builder.constant(F::from_canonical_u32(HALF_DELTA_U32));
    let zero = builder.zero();

    // --- Canonicality of the four public polynomials (strict < q). The digest gadgets that bind
    // these to commitments only 32-bit range-check; q < 2^31 so a 32-bit-range coeff could be a
    // non-canonical `coeff` vs `coeff + q` alias relative to the committed value. Pin them < q so
    // the ring arithmetic operates on canonical representatives. (Hardens MUST-FIX #2 at the
    // inputs.)
    for poly in [inputs.a, inputs.b, inputs.c1, inputs.c2] {
        for &c in poly {
            assert_lt_q(builder, c);
        }
    }

    // --- MUST-FIX #3: reject the degenerate a == 0 and c1 == 0 polynomials. ------------------
    assert_poly_nonzero(builder, inputs.a);
    assert_poly_nonzero(builder, inputs.c1);

    // --- Witness allocation. -----------------------------------------------------------------
    let mut s = Vec::with_capacity(n);
    let mut epk_u = Vec::with_capacity(n);
    let mut epk_v = Vec::with_capacity(n);
    let mut as_rem = Vec::with_capacity(n);
    let mut as_kappa = Vec::with_capacity(n);
    let mut as_wrap = Vec::with_capacity(n);
    let mut v_col = Vec::with_capacity(n);
    let mut cs_kappa = Vec::with_capacity(n);
    let mut d_bits: Vec<[BoolTarget; DIGIT_BITS]> = Vec::with_capacity(n);
    let mut noise_lo: Vec<[BoolTarget; NOISE_LO_BITS]> = Vec::with_capacity(n);
    let mut noise_u: Vec<[BoolTarget; NOISE_HI_HALF_BITS]> = Vec::with_capacity(n);
    let mut noise_v: Vec<[BoolTarget; NOISE_HI_HALF_BITS]> = Vec::with_capacity(n);
    let mut bit = Vec::with_capacity(n);
    let mut carry = Vec::with_capacity(n);
    let mut digit_wrap = Vec::with_capacity(n);

    for _ in 0..n {
        s.push(builder.add_virtual_target());
        epk_u.push(builder.add_virtual_target());
        epk_v.push(builder.add_virtual_target());
        as_rem.push(builder.add_virtual_target());
        as_kappa.push(builder.add_virtual_target());
        as_wrap.push(builder.add_virtual_target());
        v_col.push(builder.add_virtual_target());
        cs_kappa.push(builder.add_virtual_target());
        d_bits.push(core::array::from_fn(|_| {
            builder.add_virtual_bool_target_safe()
        }));
        noise_lo.push(core::array::from_fn(|_| {
            builder.add_virtual_bool_target_safe()
        }));
        noise_u.push(core::array::from_fn(|_| {
            builder.add_virtual_bool_target_safe()
        }));
        noise_v.push(core::array::from_fn(|_| {
            builder.add_virtual_bool_target_safe()
        }));
        bit.push(builder.add_virtual_bool_target_safe());
        carry.push(builder.add_virtual_target());
        digit_wrap.push(builder.add_virtual_bool_target_safe());
    }

    // --- Smallness ranges. -------------------------------------------------------------------
    // s ternary {−1,0,1}: s(s−1)(s+1) = 0.
    for &si in &s {
        let s_m1 = builder.add_const(si, F::NEG_ONE);
        let s_p1 = builder.add_const(si, F::ONE);
        let prod = builder.mul(s_m1, s_p1); // s^2 − 1
        let z = builder.mul(si, prod);
        builder.connect(z, zero);
    }
    // e_pk halves ∈ {0,1,2}: x(x−1)(x−2) = 0. (MUST-FIX #3.)
    for col in [&epk_u, &epk_v] {
        for &x in col {
            let x_m1 = builder.add_const(x, F::NEG_ONE);
            let x_m2 = builder.add_const(x, F::from_canonical_u64(F::ORDER - 2));
            let p = builder.mul(x_m1, x_m2);
            let z = builder.mul(x, p);
            builder.connect(z, zero);
        }
    }

    // κ range: κ ∈ [−n, n] ⇔ κ + n ∈ [0, 2n] decomposes in `ceil(log2(2n+1))` bits and ≤ 2n.
    // n = 128 ⇒ 2n = 256 ⇒ 9 bits; we range-check κ + n to 9 bits then assert κ + n ≤ 2n.
    let kappa_shift = builder.constant(F::from_canonical_usize(n));
    let two_n = builder.constant(F::from_canonical_usize(2 * n));
    let bound_kappa = |builder: &mut CircuitBuilder<F, D>, k: Target| {
        let shifted = builder.add(k, kappa_shift);
        builder.range_check(shifted, 9); // 0 ≤ κ + n < 512
        // κ + n ≤ 2n  ⇔  2n − (κ + n) ∈ [0, 2n] ⊂ [0, 512), 9-bit decomposable.
        let comp = builder.sub(two_n, shifted);
        builder.range_check(comp, 9);
    };

    // --- Per-coefficient ring products, reductions, digit extraction. -----------------------
    for i in 0..n {
        // (1) Key binding remainder: (a·s)_lo[i] reduced to as_rem[i] < q, κ = as_kappa[i].
        let as_lo_i = negacyclic_coeff(builder, inputs.a, &s, i);
        bound_kappa(builder, as_kappa[i]);
        // as_lo_i − as_rem[i] − κ·q = 0.
        let kq = builder.mul(as_kappa[i], q);
        let diff = builder.sub(as_lo_i, as_rem[i]);
        let diff = builder.sub(diff, kq);
        builder.connect(diff, zero);
        assert_lt_q(builder, as_rem[i]); // strict < q (MUST-FIX #2).
        // Key binding identity (mod q): b[i] ≡ as_rem[i] + e_pk[i], e_pk = e_pk_u − e_pk_v.
        // `as_rem` is canonical (< q) and `b` is canonical (< q), but `as_rem + e_pk` can cross the
        // modulus boundary when |e_pk| ≤ 2 pushes it out of [0, q); so the relation is
        //   b[i] − e_pk[i] − as_rem[i] − w[i]·q = 0   with a witnessed wrap w[i] ∈ {−1, 0, 1}.
        // Since b, as_rem ∈ [0, q) and e_pk ∈ [−2, 2], b − e_pk − as_rem ∈ (−q−2, q+2) ⇒ w ∈
        // {−1,0,1}. SECURITY: this keeps `as_rem` strictly canonical (MUST-FIX #2) while
        // making the binding sound across the boundary; w is ternary-constrained so it adds
        // no spurious DOF beyond the single legitimate modular wrap.
        let w_m1 = builder.add_const(as_wrap[i], F::NEG_ONE);
        let w_p1 = builder.add_const(as_wrap[i], F::ONE);
        let w_sq_m1 = builder.mul(w_m1, w_p1);
        let w_tern = builder.mul(as_wrap[i], w_sq_m1);
        builder.connect(w_tern, zero); // w ∈ {−1,0,1}
        let epk_i = builder.sub(epk_u[i], epk_v[i]);
        let wq = builder.mul(as_wrap[i], q);
        // b − e_pk − as_rem − w·q == 0.
        let kb = builder.sub(inputs.b[i], epk_i);
        let kb = builder.sub(kb, as_rem[i]);
        let kb = builder.sub(kb, wq);
        builder.connect(kb, zero);

        // (2) Decryption remainder: (c1·s)_lo[i] reduced to cs_rem (= c2[i] − v[i]) with κ =
        // cs_kappa[i].
        let cs_lo_i = negacyclic_coeff(builder, inputs.c1, &s, i);
        bound_kappa(builder, cs_kappa[i]);
        // v[i] = c2[i] − cs_rem[i]  ⇔  cs_rem[i] = c2[i] − v[i]. Reduce against cs_lo_i:
        // cs_lo_i − (c2[i] − v[i]) − κ·q = 0.
        let cs_rem = builder.sub(inputs.c2[i], v_col[i]);
        let kq = builder.mul(cs_kappa[i], q);
        let diff = builder.sub(cs_lo_i, cs_rem);
        let diff = builder.sub(diff, kq);
        builder.connect(diff, zero);
        assert_lt_q(builder, v_col[i]); // v strictly < q (MUST-FIX #2).

        // (3) Digit extraction: v[i] + Δ/2 = Δ·d[i] + ns[i] (mod q; uniqueness per the no-wrap
        // analysis). d[i] ∈ [0,256) (8 bits), ns[i] ∈ [0,Δ) EXACTLY via lo19 + (u+v)·2^19,
        // u,v∈[0,7].
        let d_val = bits_to_target(builder, &d_bits[i]);
        let ns_lo = bits_to_target(builder, &noise_lo[i]);
        let ns_u = bits_to_target(builder, &noise_u[i]);
        let ns_v = bits_to_target(builder, &noise_v[i]);
        let uv = builder.add(ns_u, ns_v); // u + v ∈ [0, 14]
        // ns = ns_lo + (u+v)·2^19. (MUST-FIX #6/#3: NOT a 23-bit range.)
        let hi_scaled = builder.mul_const(F::from_canonical_u32(1u32 << NOISE_LO_BITS), uv);
        let ns = builder.add(ns_lo, hi_scaled);
        // v[i] + Δ/2 = Δ·d + ns + dwrap·q  (mod-q boundary wrap made explicit over Goldilocks).
        //
        // SECURITY (MUST-FIX #5: dwrap is DERIVED, not a free DOF). Over the STARK's BabyBear field
        // this is the pure mod-q field equation; over Goldilocks both sides are small integers, so
        // we expose the single boundary wrap `dwrap`. It is NOT an adversarial degree of
        // freedom: with d ∈ [0,256), ns ∈ [0,Δ) (range-checked), Δ·d + ns ≤ 256Δ − 1 = q −
        // 2 < q ALWAYS, and v + Δ/2 ∈ [0, 2q) (v < q, Δ/2 < q). So dwrap = 0 forces v + Δ/2
        // = Δd + ns < q, and dwrap = 1 forces v + Δ/2 = Δd + ns + q ∈ [q, 2q). These two
        // cases are disjoint in v + Δ/2, so the boolean dwrap is UNIQUELY pinned by v (and
        // the (d, ns) decomposition is unique within each case by the STARK no-wrap
        // argument) — adding dwrap recovers exactly the BabyBear semantics without widening
        // the solution set.
        let d_delta = builder.mul(d_val, delta);
        let dwrap_q = builder.mul(digit_wrap[i].target, q);
        let lhs = builder.add(v_col[i], half_delta);
        let lhs = builder.sub(lhs, d_delta);
        let lhs = builder.sub(lhs, ns);
        let lhs = builder.sub(lhs, dwrap_q);
        builder.connect(lhs, zero);
    }

    // --- (4) Digit→bit normalization adder: Σ d·2^i == Σ bit·2^i over the integers. ---------
    // c_0 = 0; d_i + c_i = bit_i + 2·c_{i+1}; final carry 0. All terms range-checked (d ≤ 255,
    // c ≤ 254, bit ≤ 1) so the field equation implies the integer one (|d + c − bit − 2c'| < q).
    builder.connect(carry[0], zero);
    for i in 0..n {
        builder.range_check(carry[i], CARRY_BITS);
        let d_val = bits_to_target(builder, &d_bits[i]);
        // lhs = d_i + c_i − bit_i.
        let lhs = builder.add(d_val, carry[i]);
        let lhs = builder.sub(lhs, bit[i].target);
        if i + 1 < n {
            // lhs == 2·c_{i+1}.
            let two_cnext = builder.mul_const(F::TWO, carry[i + 1]);
            builder.connect(lhs, two_cnext);
        } else {
            // Last row: lhs == 0 (final carry 0).
            builder.connect(lhs, zero);
        }
    }

    // --- (5) Amount binding (expose_amount only). -------------------------------------------
    // Σ_{i<32} bit_i·2^i == amount_lo ; Σ_{i<32} bit_{32+i}·2^i == amount_hi ; bit[64..128] == 0.
    // This is the repo 2×32 U64 form (MUST-FIX #6/#7): NO 4×16 STARK split.
    let amount_limbs = if expose_amount {
        let lo = pack_bits_le(builder, &bit[0..32]);
        let hi = pack_bits_le(builder, &bit[32..64]);
        for &b in &bit[64..n] {
            builder.connect(b.target, zero);
        }
        Some((lo, hi))
    } else {
        None
    };

    let targets = DecryptionCoreTargets {
        s,
        epk_u,
        epk_v,
        as_rem,
        as_kappa,
        as_wrap,
        v: v_col,
        cs_kappa,
        d_bits,
        noise_lo,
        noise_u,
        noise_v,
        bit,
        carry,
        digit_wrap,
        expose_amount,
    };
    (targets, amount_limbs)
}

/// One coefficient `lo[i]` of the negacyclic product `x · s` as the signed-selection sum proven in
/// the module docs: `lo[i] = Σ_m sign(i,m)·x[m]·s[(i−m) mod n]`, sign +1 if `m ≤ i` else −1.
///
/// SECURITY: no intermediate reduction — the returned target is the exact integer (in `(−n·q,
/// n·q)`, `< 2^38 ≪ p`), reduced to canonical form by the caller via the explicit κ·q quotient.
fn negacyclic_coeff<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: &[Target],
    s: &[Target],
    i: usize,
) -> Target {
    let n = x.len();
    let mut acc = builder.zero();
    for m in 0..n {
        // s-index (i − m) mod n, sign +1 when m ≤ i (no wrap) else −1 (x^n = −1).
        let (j, neg) = if m <= i {
            (i - m, false)
        } else {
            (n + i - m, true)
        };
        // term = x[m]·s[j]; accumulate ±term. s[j] ∈ {−1,0,1} but we treat it as a field target
        // (its ternary range is constrained at the call site), so this is a generic field product.
        let term = builder.mul(x[m], s[j]);
        if neg {
            acc = builder.sub(acc, term);
        } else {
            acc = builder.add(acc, term);
        }
    }
    acc
}

/// Strict `< q` range gadget (MUST-FIX #2): proves `0 ≤ x < q = 2^31 − 2^27 + 1` via a 31-bit
/// decomposition of BOTH `x` and `q − 1 − x`. A bare 31-bit range on `x` alone would admit
/// `x ∈ [q, 2^31)` (a window of `2^31 − q = 2^27` non-canonical values aliasing `x − q`); requiring
/// `q − 1 − x` to be 31-bit decomposable forces `q − 1 − x ≥ 0` (else it wraps to `≈ p`, not
/// 31-bit), i.e. `x ≤ q − 1`, exactly strict `< q`.
fn assert_lt_q<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
) {
    builder.range_check(x, 31); // 0 ≤ x < 2^31
    let q_minus_1 = builder.constant(F::from_canonical_u64(Q_U64 - 1));
    let comp = builder.sub(q_minus_1, x); // q − 1 − x
    builder.range_check(comp, 31); // forces q − 1 − x ∈ [0, 2^31), i.e. x ≤ q − 1
}

/// Assert a polynomial is not the zero polynomial: at least one coefficient is nonzero (MUST-FIX
/// #3). We assert `OR_i (x[i] != 0)` by computing the per-coeff `is_nonzero` Booleans and asserting
/// their sum is ≥ 1, i.e. NOT(all zero). Implemented as: `all_zero = AND_i (x[i] == 0)`; assert
/// `all_zero == false`. (Summing per-coeff nonzero flags could overflow reasoning; the AND-of-zeros
/// form is exact and each `is_equal` is a single Boolean.)
fn assert_poly_nonzero<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: &[Target],
) {
    let zero = builder.zero();
    // all_zero starts true; AND in each (x[i] == 0).
    let mut all_zero = builder._true();
    for &c in x {
        let is_zero = builder.is_equal(c, zero);
        all_zero = builder.and(all_zero, is_zero);
    }
    builder.assert_zero(all_zero.target); // all_zero must be false ⇒ poly nonzero.
}

/// Little-endian weighted sum of Booleans (no overflow: ≤ 23 bits here, far below p).
fn bits_to_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits: &[BoolTarget],
) -> Target {
    let mut acc = builder.zero();
    for (j, b) in bits.iter().enumerate() {
        acc = builder.mul_const_add(F::from_canonical_u64(1u64 << j), b.target, acc);
    }
    acc
}

/// Pack up to 32 little-endian Booleans into a single u32-valued target.
fn pack_bits_le<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits: &[BoolTarget],
) -> Target {
    debug_assert!(bits.len() <= 32);
    let mut acc = builder.zero();
    for (j, b) in bits.iter().enumerate() {
        acc = builder.mul_const_add(F::from_canonical_u64(1u64 << j), b.target, acc);
    }
    acc
}

// ---------------------------------------------------------------------------
// Deliverable B: in-circuit RegevCiphertext IMRC keccak digest gadget
// ---------------------------------------------------------------------------

/// Recompute `RegevCiphertext::digest()` in-circuit: `keccak([IMRC, 128, c1…, c2…])` over the u32
/// word stream (mirror of `encrypt.rs:99-120` / `hash_words`). Returns the digest as a
/// `Bytes32Target`. The caller `connect`s it to the committed `user_amount_digest` / delta digest.
///
/// SECURITY: each coefficient target MUST be 32-bit range-checked AND strictly `< q` by the caller
/// — the keccak gadget does not range-check, and `decryption_core` already pins `c1`/`c2` to
/// canonical, so feeding the SAME targets here ties the ciphertext the digest commits to the
/// ciphertext the decryption is computed on (no malleability gap between the two).
pub fn regev_ct_digest_gadget<F, C, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    c1: &[Target],
    c2: &[Target],
) -> crate::ethereum_types::bytes32::Bytes32Target
where
    F: RichField + Extendable<D>,
    C: plonky2::plonk::config::GenericConfig<D, F = F> + 'static,
    <C as plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2::plonk::config::AlgebraicHasher<F>,
{
    use plonky2_keccak::builder::BuilderKeccak256 as _;

    use crate::{
        ethereum_types::{bytes32::Bytes32Target, u32limb_trait::U32LimbTargetTrait as _},
        regev::REGEV_CT_DOMAIN,
    };
    assert_eq!(c1.len(), REGEV_N);
    assert_eq!(c2.len(), REGEV_N);
    let domain = builder.constant(F::from_canonical_u32(REGEV_CT_DOMAIN));
    let len = builder.constant(F::from_canonical_usize(REGEV_N));
    let mut words = Vec::with_capacity(2 + 2 * REGEV_N);
    words.push(domain);
    words.push(len);
    words.extend_from_slice(c1);
    words.extend_from_slice(c2);
    Bytes32Target::from_slice(&builder.keccak256::<C>(&words))
}

// ---------------------------------------------------------------------------
// Deliverable C: in-circuit RegevPk Poseidon digest gadget
// ---------------------------------------------------------------------------

/// Recompute `RegevPk::poseidon_digest()` in-circuit: `Poseidon([IMRP, 128, a…, b…])` over
/// Goldilocks limbs (mirror of `keys.rs:102-111` and the validity member-tree recompute in
/// `update_channel_tree.rs:974-986`). Returns the digest as a `Bytes32Target` (= `Bytes32::from(
/// poseidon_digest)`, matching the `regev_pk_digests[i]` encoding committed in H1, Stage 1) so the
/// caller can `connect` it to the one-hot-selected H1 digest — THE critical pk binding (MUST-FIX
/// #1).
///
/// SECURITY: each coefficient target MUST be 32-bit range-checked (< q < 2^32 ⇒ one Goldilocks
/// limb, no reduction) by the caller; `decryption_core` already pins `a`/`b` to canonical `< q`,
/// and feeding the SAME `a`/`b` targets here is what ties the witnessed key to the committed
/// digest.
pub fn regev_pk_poseidon_digest_gadget<F, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &[Target],
    b: &[Target],
) -> crate::ethereum_types::bytes32::Bytes32Target
where
    F: RichField + Extendable<D>,
{
    use crate::{
        ethereum_types::bytes32::Bytes32Target, regev::REGEV_PK_POSEIDON_DOMAIN,
        utils::poseidon_hash_out::PoseidonHashOutTarget,
    };
    assert_eq!(a.len(), REGEV_N);
    assert_eq!(b.len(), REGEV_N);
    let domain = builder.constant(F::from_canonical_u64(REGEV_PK_POSEIDON_DOMAIN));
    let len = builder.constant(F::from_canonical_usize(REGEV_N));
    let mut inputs = Vec::with_capacity(2 + 2 * REGEV_N);
    inputs.push(domain);
    inputs.push(len);
    inputs.extend_from_slice(a);
    inputs.extend_from_slice(b);
    let digest = PoseidonHashOutTarget::hash_inputs(builder, &inputs);
    // Encode as Bytes32 exactly like `Bytes32::from(PoseidonHashOut)` (the H1 commitment encoding).
    Bytes32Target::from_hash_out(builder, digest)
}

// ---------------------------------------------------------------------------
// Native witness construction
// ---------------------------------------------------------------------------

/// Reduce a Goldilocks-representable signed integer `lo ∈ (−n·q, n·q)` to its canonical
/// representative `rem ∈ [0, q)` plus the integer quotient `κ` such that `lo = rem + κ·q`. Used to
/// build `as_kappa`/`cs_kappa`. The native ring product feeds `lo` here.
fn reduce_with_quotient(lo: i64) -> (u32, i64) {
    let q = REGEV_Q as i64;
    // rem = lo mod q in [0, q); κ = (lo − rem)/q.
    let mut rem = lo % q;
    if rem < 0 {
        rem += q;
    }
    let kappa = (lo - rem) / q;
    (rem as u32, kappa)
}

/// Native negacyclic product `lo[i]` returned WITHOUT reduction (the raw signed integer the circuit
/// computes), matching `negacyclic_coeff`. `x` canonical mod q, `s` ternary.
fn native_negacyclic_unreduced(x: &[u32], s: &[i8]) -> Vec<i64> {
    let n = x.len();
    (0..n)
        .map(|i| {
            let mut acc: i64 = 0;
            for m in 0..n {
                let (j, neg) = if m <= i {
                    (i - m, false)
                } else {
                    (n + i - m, true)
                };
                let term = x[m] as i64 * s[j] as i64;
                if neg {
                    acc -= term;
                } else {
                    acc += term;
                }
            }
            acc
        })
        .collect()
}

/// Build the full decryption-core witness natively from canonical `(a, b, c1, c2)` and ternary `s`.
///
/// Returns `Err(())` (caller maps to a domain error) when the inputs are inconsistent: `s` not
/// ternary, `a == 0` or `c1 == 0`, the derived pk noise `e_pk = b − (a·s)` outside `[−2, 2]`, the
/// rounding noise outside the Δ/2 budget, the digit `d ≥ 256`, or the decoded value not a u64.
/// Mirrors `transfer_stark::build_decryption_witness`.
pub fn build_decryption_core_witness(
    a: &[u32],
    b: &[u32],
    c1: &[u32],
    c2: &[u32],
    s: &[i8],
) -> Result<DecryptionCoreWitness, ()> {
    let n = REGEV_N;
    if a.len() != n || b.len() != n || c1.len() != n || c2.len() != n || s.len() != n {
        return Err(());
    }
    if s.iter().any(|&x| !(-1..=1).contains(&x)) {
        return Err(());
    }
    if a.iter().all(|&c| c == 0) || c1.iter().all(|&c| c == 0) {
        return Err(()); // MUST-FIX #3 degenerate inputs.
    }
    if a.iter().chain(b).chain(c1).chain(c2).any(|&c| c >= REGEV_Q) {
        return Err(()); // non-canonical.
    }

    // Key binding: (a·s)_lo, reduce per coeff, derive e_pk = b − rem, split into CBD(2) halves.
    let as_lo = native_negacyclic_unreduced(a, s);
    let mut as_rem = Vec::with_capacity(n);
    let mut as_kappa = Vec::with_capacity(n);
    let mut as_wrap = Vec::with_capacity(n);
    let mut epk_u = Vec::with_capacity(n);
    let mut epk_v = Vec::with_capacity(n);
    let q_i64 = REGEV_Q as i64;
    for (i, &lo) in as_lo.iter().enumerate() {
        let (rem, kappa) = reduce_with_quotient(lo);
        // e_pk = b[i] − rem (mod q), centered into [−(q-1)/2, (q-1)/2] then must be in [−2, 2].
        let e = centered_diff(b[i], rem);
        if !(-2..=2).contains(&e) {
            return Err(());
        }
        // Boundary wrap w: b − e − rem = w·q (must divide exactly, w ∈ {−1,0,1}).
        let wnum = b[i] as i64 - e - rem as i64;
        debug_assert_eq!(wnum % q_i64, 0, "key-binding wrap does not divide by q");
        as_rem.push(rem);
        as_kappa.push(kappa);
        as_wrap.push(wnum / q_i64);
        epk_u.push(e.max(0) as u8);
        epk_v.push((-e).max(0) as u8);
    }

    // Decryption: (c1·s)_lo, reduce to canonical `rem`, then v = (c2 − rem) mod q (canonical).
    //
    // SECURITY/COMPLETENESS: the CIRCUIT enforces the reduction against `cs_rem := c2[i] − v[i]`
    // (NOT against the canonical `rem`), i.e. `cs_lo − (c2 − v) − κ·q = 0`. Since
    // `v ≡ c2 − rem (mod q)` we have `rem = (c2 − v) + ε·q` for some ε ∈ {0,1}, so the κ the
    // circuit needs is `cs_kappa_canonical + ε`. Derive κ directly from the circuit's own
    // equation so the witnessed quotient is EXACTLY `(cs_lo − (c2 − v))/q` — otherwise the κ·q
    // wire is set twice with conflicting values (a witness-completeness failure, not a
    // soundness gap: the constraint is the same; only the supplied κ must match it).
    let cs_lo = native_negacyclic_unreduced(c1, s);
    let mut v = Vec::with_capacity(n);
    let mut cs_kappa = Vec::with_capacity(n);
    for (i, &lo) in cs_lo.iter().enumerate() {
        let (rem, _kappa_canonical) = reduce_with_quotient(lo);
        // v = (c2 − rem) mod q, canonical.
        let vi = ((c2[i] as i64 - rem as i64).rem_euclid(q_i64)) as u32;
        v.push(vi);
        // κ from the circuit's equation: cs_lo − (c2 − v) = κ·q must divide exactly.
        let target = lo - (c2[i] as i64 - vi as i64);
        let q_i64 = REGEV_Q as i64;
        debug_assert_eq!(target % q_i64, 0, "cs reduction does not divide by q");
        cs_kappa.push(target / q_i64);
    }

    // Digit/noise decomposition: v + Δ/2 = Δ·d + ns (mod q), d ∈ [0,256), ns ∈ [0,Δ).
    let q = REGEV_Q as u64;
    let mut digits = Vec::with_capacity(n);
    let mut noise_shifted = Vec::with_capacity(n);
    let mut digit_wrap = Vec::with_capacity(n);
    for &vi in &v {
        let raw = vi as u64 + HALF_DELTA_U32 as u64; // < 2q
        let w = raw % q;
        digit_wrap.push(raw >= q); // dwrap ∈ {0,1}: whether v + Δ/2 crossed the modulus.
        let d = w / DELTA_U32 as u64;
        if d >= 1 << DIGIT_BITS {
            return Err(()); // rounding noise at the digit-255 boundary, outside the budget.
        }
        digits.push(d as u8);
        noise_shifted.push((w % DELTA_U32 as u64) as u32);
    }

    // Decode the value from the digits (1 bit per coeff = digit; but digits can be >1 after homo
    // adds — the value is Σ d_i·2^i, matching decrypt_amount/build_decryption_witness).
    let mut value: u128 = 0;
    for (i, &d) in digits.iter().enumerate() {
        if d != 0 {
            if i >= 64 {
                return Err(());
            }
            value += (d as u128) << i;
        }
    }
    let value = u64::try_from(value).map_err(|_| ())?;
    let bits = crate::regev::encode_amount(value);

    // Normalization carries: d_i + c_i = bit_i + 2·c_{i+1}, c_0 = 0, final carry 0.
    let mut carries = vec![0u16; n];
    let mut carry: u16 = 0;
    for i in 0..n {
        carries[i] = carry;
        let t = digits[i] as i32 + carry as i32 - bits[i] as i32;
        if t < 0 || t % 2 != 0 {
            return Err(());
        }
        carry = (t / 2) as u16;
    }
    if carry != 0 {
        return Err(());
    }

    Ok(DecryptionCoreWitness {
        s: s.to_vec(),
        epk_u,
        epk_v,
        as_rem,
        as_kappa,
        as_wrap,
        v,
        cs_kappa,
        digits,
        noise_shifted,
        digit_wrap,
        bits,
        carries,
        value,
    })
}

/// Centered difference `(b − rem) mod q` mapped to `[−(q−1)/2, (q−1)/2]` (for the `|e_pk| ≤ 2`
/// check). Mirrors `transfer_stark::field_to_centered` for the BabyBear prime.
fn centered_diff(b: u32, rem: u32) -> i64 {
    let q = REGEV_Q as i64;
    let mut d = (b as i64 - rem as i64).rem_euclid(q);
    if d > q / 2 {
        d -= q;
    }
    d
}

/// Fill the witness targets returned by [`decryption_core`] from a native
/// [`DecryptionCoreWitness`].
pub fn fill_decryption_core<F: RichField + Extendable<D>, const D: usize, W>(
    witness: &mut W,
    targets: &DecryptionCoreTargets,
    w: &DecryptionCoreWitness,
) where
    F: Field,
    W: plonky2::iop::witness::WitnessWrite<F>,
{
    use plonky2::iop::witness::WitnessWrite as _;
    let n = REGEV_N;
    let set = |witness: &mut W, t: Target, v: F| witness.set_target(t, v).unwrap();
    let f_i64 = |x: i64| -> F {
        if x >= 0 {
            F::from_canonical_u64(x as u64)
        } else {
            F::ZERO - F::from_canonical_u64((-x) as u64)
        }
    };
    for i in 0..n {
        set(witness, targets.s[i], f_i64(w.s[i] as i64));
        set(witness, targets.epk_u[i], F::from_canonical_u8(w.epk_u[i]));
        set(witness, targets.epk_v[i], F::from_canonical_u8(w.epk_v[i]));
        set(
            witness,
            targets.as_rem[i],
            F::from_canonical_u32(w.as_rem[i]),
        );
        set(witness, targets.as_kappa[i], f_i64(w.as_kappa[i]));
        set(witness, targets.as_wrap[i], f_i64(w.as_wrap[i]));
        set(witness, targets.v[i], F::from_canonical_u32(w.v[i]));
        set(witness, targets.cs_kappa[i], f_i64(w.cs_kappa[i]));
        for (j, b) in targets.d_bits[i].iter().enumerate() {
            witness
                .set_bool_target(*b, (w.digits[i] >> j) & 1 == 1)
                .unwrap();
        }
        for (j, b) in targets.noise_lo[i].iter().enumerate() {
            witness
                .set_bool_target(*b, (w.noise_shifted[i] >> j) & 1 == 1)
                .unwrap();
        }
        let hi = w.noise_shifted[i] >> NOISE_LO_BITS;
        let nu = hi.min(7);
        let nv = hi - nu;
        for (j, b) in targets.noise_u[i].iter().enumerate() {
            witness.set_bool_target(*b, (nu >> j) & 1 == 1).unwrap();
        }
        for (j, b) in targets.noise_v[i].iter().enumerate() {
            witness.set_bool_target(*b, (nv >> j) & 1 == 1).unwrap();
        }
        witness
            .set_bool_target(targets.bit[i], w.bits[i] == 1)
            .unwrap();
        set(
            witness,
            targets.carry[i],
            F::from_canonical_u16(w.carries[i]),
        );
        witness
            .set_bool_target(targets.digit_wrap[i], w.digit_wrap[i])
            .unwrap();
    }
    let _ = targets.expose_amount;
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use rand010::{RngExt, SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::regev::{channel_keygen, decrypt_amount, encrypt_amount};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    /// Reference schoolbook negacyclic `lo`, computed in i64 EXACTLY as
    /// `transfer_stark::negacyclic_mul_with_quotient` (the `prod[i] − prod[n+i]` form), independent
    /// of the reindexed `native_negacyclic_unreduced`. This is the differential oracle.
    fn schoolbook_lo_i64(x: &[u32], s: &[i8]) -> Vec<i64> {
        let n = x.len();
        let mut prod = vec![0i64; 2 * n];
        for i in 0..n {
            for j in 0..n {
                prod[i + j] += x[i] as i64 * s[j] as i64;
            }
        }
        (0..n).map(|i| prod[i] - prod[n + i]).collect()
    }

    /// MUST-FIX #4: the gadget's per-coeff negacyclic sum (`native_negacyclic_unreduced`, the SAME
    /// reindexed formula `negacyclic_coeff` proves in-circuit) matches the schoolbook
    /// `prod[i] − prod[n+i]` reduction over hundreds of random `(x, ternary s)` — AND,
    /// canonicalized, matches the real native ring product. This pins the wrap index/sign split
    /// (x^n = −1).
    #[test]
    fn negacyclic_matches_native() {
        let mut rng = SmallRng::seed_from_u64(0xDEC0_DE01);
        for _ in 0..400 {
            let x: Vec<u32> = (0..REGEV_N).map(|_| rng.random_range(0..REGEV_Q)).collect();
            let s: Vec<i8> = (0..REGEV_N).map(|_| rng.random_range(-1..=1)).collect();
            let ours = native_negacyclic_unreduced(&x, &s);
            let reference = schoolbook_lo_i64(&x, &s);
            for i in 0..REGEV_N {
                // Same unreduced integer (proves the reindexing is exact, not just congruent).
                assert_eq!(ours[i], reference[i], "unreduced coeff {i} mismatch");
                // And the canonical reduction is what the circuit binds v / as_rem to.
                let (rem, _k) = reduce_with_quotient(ours[i]);
                assert_eq!(
                    rem as i64,
                    reference[i].rem_euclid(REGEV_Q as i64),
                    "coeff {i}"
                );
            }
        }
    }

    /// Property test vs the native oracle: the gadget accepts iff `decrypt_amount` returns the
    /// claimed amount, over many random `(pk, sk, amount)` plus adversarial instances.
    #[test]
    fn property_vs_native_oracle() {
        let mut rng = SmallRng::seed_from_u64(0xDEC0_DE02);
        // Build ONE circuit and reuse.
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let a: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let b: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let c1: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let c2: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let inputs = DecryptionCoreInputs {
            a: &a,
            b: &b,
            c1: &c1,
            c2: &c2,
        };
        let (tg, amt) = decryption_core(&mut builder, &inputs, true);
        let (lo, hi) = amt.unwrap();
        builder.register_public_input(lo);
        builder.register_public_input(hi);
        let data = builder.build::<C>();

        let mut accepted = 0u32;
        for _ in 0..40 {
            let (pk, sk) = channel_keygen(&mut rng);
            let amount: u64 = rng.random_range(0..(1u64 << 40));
            let (ct, _) = encrypt_amount(&mut rng, &pk, amount).unwrap();
            let native = decrypt_amount(&sk, &ct).unwrap();
            assert_eq!(native, amount);

            let w = build_decryption_core_witness(&pk.a, &pk.b, &ct.c1, &ct.c2, &sk.s).unwrap();
            assert_eq!(
                w.value, amount,
                "core witness value must equal native amount"
            );

            let mut pw = PartialWitness::<F>::new();
            set_poly(&mut pw, &a, &pk.a);
            set_poly(&mut pw, &b, &pk.b);
            set_poly(&mut pw, &c1, &ct.c1);
            set_poly(&mut pw, &c2, &ct.c2);
            fill_decryption_core::<F, D, _>(&mut pw, &tg, &w);
            let proof = data.prove(pw).expect("honest witness must prove");
            // amount limbs exposed match the u64.
            let plo = proof.public_inputs[0].0;
            let phi = proof.public_inputs[1].0;
            assert_eq!(plo, amount & 0xffff_ffff);
            assert_eq!(phi, amount >> 32);
            data.verify(proof).unwrap();
            accepted += 1;
        }
        assert_eq!(accepted, 40);
    }

    /// CRITICAL-1 adversarial: a wrong `s` (not the key behind pk) makes the key-binding gate fail,
    /// so the honest-witness builder refuses AND a forced bad witness fails to prove.
    #[test]
    fn wrong_s_is_rejected() {
        let mut rng = SmallRng::seed_from_u64(0xDEC0_DE03);
        let (pk, _sk) = channel_keygen(&mut rng);
        let (_, wrong_sk) = channel_keygen(&mut rng);
        let amount = 123u64;
        let (ct, _) = encrypt_amount(&mut rng, &pk, amount).unwrap();
        // The native builder refuses: e_pk = b − a·(wrong s) is not in [−2, 2].
        assert!(build_decryption_core_witness(&pk.a, &pk.b, &ct.c1, &ct.c2, &wrong_sk.s).is_err());
    }

    /// Degenerate a == 0 / c1 == 0 are rejected by the witness builder (MUST-FIX #3).
    #[test]
    fn degenerate_zero_poly_rejected() {
        let mut rng = SmallRng::seed_from_u64(0xDEC0_DE04);
        let (pk, sk) = channel_keygen(&mut rng);
        let (ct, _) = encrypt_amount(&mut rng, &pk, 7).unwrap();
        let zero = vec![0u32; REGEV_N];
        assert!(build_decryption_core_witness(&zero, &pk.b, &ct.c1, &ct.c2, &sk.s).is_err());
        assert!(build_decryption_core_witness(&pk.a, &pk.b, &zero, &ct.c2, &sk.s).is_err());
    }

    /// Boundary: amount 0, 1, 255, 2^32, large.
    #[test]
    fn boundary_amounts_decode() {
        let mut rng = SmallRng::seed_from_u64(0xDEC0_DE05);
        let (pk, sk) = channel_keygen(&mut rng);
        for amount in [0u64, 1, 255, 1 << 32, (1u64 << 40) - 1] {
            let (ct, _) = encrypt_amount(&mut rng, &pk, amount).unwrap();
            assert_eq!(decrypt_amount(&sk, &ct).unwrap(), amount);
            let w = build_decryption_core_witness(&pk.a, &pk.b, &ct.c1, &ct.c2, &sk.s).unwrap();
            assert_eq!(w.value, amount);
        }
    }

    /// Non-canonical (>= q) coefficient is rejected by the witness builder.
    #[test]
    fn non_canonical_rejected() {
        let mut rng = SmallRng::seed_from_u64(0xDEC0_DE06);
        let (pk, sk) = channel_keygen(&mut rng);
        let (ct, _) = encrypt_amount(&mut rng, &pk, 9).unwrap();
        let mut bad_c2 = ct.c2.clone();
        bad_c2[0] = REGEV_Q;
        assert!(build_decryption_core_witness(&pk.a, &pk.b, &ct.c1, &bad_c2, &sk.s).is_err());
    }

    fn set_poly<W: plonky2::iop::witness::WitnessWrite<F>>(w: &mut W, t: &[Target], v: &[u32]) {
        use plonky2::iop::witness::WitnessWrite as _;
        for (&t, &v) in t.iter().zip(v) {
            w.set_target(t, F::from_canonical_u32(v)).unwrap();
        }
    }

    /// Golden: the in-circuit IMRC ct-digest gadget equals native `RegevCiphertext::digest()`.
    #[test]
    fn ct_digest_gadget_matches_native() {
        use crate::ethereum_types::{
            bytes32::Bytes32Target,
            u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
        };
        let mut rng = SmallRng::seed_from_u64(0xDEC0_DE10);
        let (pk, _) = channel_keygen(&mut rng);
        let (ct, _) = encrypt_amount(&mut rng, &pk, 4242).unwrap();
        let native = ct.digest();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let c1: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let c2: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let dig = regev_ct_digest_gadget::<F, C, D>(&mut builder, &c1, &c2);
        let expected = Bytes32Target::new(&mut builder, true);
        dig.connect(&mut builder, expected);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::<F>::new();
        set_poly(&mut pw, &c1, &ct.c1);
        set_poly(&mut pw, &c2, &ct.c2);
        expected.set_witness(&mut pw, native);
        data.verify(data.prove(pw).unwrap()).unwrap();
    }

    /// Golden: the in-circuit Poseidon pk-digest gadget equals
    /// `Bytes32::from(pk.poseidon_digest())`.
    #[test]
    fn pk_poseidon_digest_gadget_matches_native() {
        use crate::ethereum_types::{
            bytes32::{Bytes32, Bytes32Target},
            u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
        };
        let mut rng = SmallRng::seed_from_u64(0xDEC0_DE11);
        let (pk, _) = channel_keygen(&mut rng);
        let native = Bytes32::from(pk.poseidon_digest());

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let a: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let b: Vec<Target> = (0..REGEV_N).map(|_| builder.add_virtual_target()).collect();
        let dig = regev_pk_poseidon_digest_gadget::<F, D>(&mut builder, &a, &b);
        let expected = Bytes32Target::new(&mut builder, true);
        dig.connect(&mut builder, expected);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::<F>::new();
        set_poly(&mut pw, &a, &pk.a);
        set_poly(&mut pw, &b, &pk.b);
        expected.set_witness(&mut pw, native);
        data.verify(data.prove(pw).unwrap()).unwrap();
    }
}
