//! Phase-1 in-circuit Falcon-512/Poseidon signature verifier gadget (plonky2).
//!
//! Mirrors EXACTLY the native `falcon_sig::verify_with_pk_g` semantics (threat model
//! `doc/tasks/falcon-sig-threat-model.md` TM-C5, obligations O-2 / O-5), over the repo's
//! standard config (`F = GoldilocksField, D = 2, C = PoseidonGoldilocksConfig`,
//! `standard_recursion_config`). Nothing here is wired into any existing circuit; Phase 2
//! (close / cancel-close) and Phase 3 (validity list step) consume [`FalconSigVerifyTarget`].
//!
//! # Gadget contract (inputs vs witnesses)
//!
//! - `pk_g` (INPUT, [`Bytes32Target`]): the member identity digest. Representation choice:
//!   `Bytes32Target` (8 canonical u32-limb targets), because that is exactly how member `pk_g`
//!   values already flow through the close circuit (`MemberAuth.pk_g: Bytes32`, in-circuit
//!   `Bytes32Target` slices feeding the keccak member-set commitment) — Phase 2 connects its member
//!   `Bytes32Target` directly with zero conversion. The gadget connects this input to the
//!   internally recomputed `Poseidon(IMFK || encode(h))` digest (review F-2: the binding is INSIDE
//!   the gadget; callers cannot forget it).
//! - `message_digest` (INPUT, [`Bytes32Target`]): the 8 u32 limbs of the IMCH/IMSB keccak digest.
//!   SECURITY (TM-C5 item 4 / TM-C6): in this standalone gadget the digest is an input target;
//!   every CONSUMER MUST `connect` it to a digest recomputed in-circuit for its own context — it
//!   must never be a free witness at the consumer level, or a prover could verify a signature over
//!   an arbitrary message.
//! - `salt` (witness, 8 targets): the 40-byte signature salt in the native packed form — 8 elements
//!   of 5 little-endian bytes each (`Nonce::to_elements`). Each element is range-checked `< 2^40`,
//!   which IS the injectivity condition: the map `40 bytes <-> 8 x [0, 2^40)` elements is a
//!   bijection, so one salt has exactly one in-circuit encoding.
//! - `h` (witness, 512 targets): the public polynomial, canonical coefficients range-checked `< q`
//!   (TM-C5 item 5; mirrors the native canonicity gate that makes `encode(h)` injective).
//! - `s2` (witness, 512 targets): the signature polynomial in CANONICAL RESIDUE form, each target
//!   range-checked `< q = 12289`.
//!
//! # s2 representation decision (TM-C5 item 1)
//!
//! The native verifier operates on `s2` as elements of `Z_q` (the wire decoder produces
//! balanced values in `[-2047, 2047]`, immediately mapped into `FalconFelt`, i.e. the residue
//! class; the norm uses the canonical CENTERED representative `balanced_value()`). The circuit
//! witnesses the canonical residue `s2 mod q in [0, q)` — one and only one in-circuit encoding
//! per residue class (a centered offset encoding would be a second, redundant convention; the
//! canonical residue is also what the NTT consumes directly). Centering for the norm is done
//! per coefficient with a prover-supplied boolean `b` and the value `v - b*q`:
//!
//! SECURITY (free centering bit soundness): the circuit does NOT constrain `b` to equal
//! `v > q/2`. It does not need to: the squared term is `(v - b*q)^2` and for canonical
//! `v in [0, q)` the two choices are `v^2` and `(q - v)^2`, whose MINIMUM is the true centered
//! square. A lying prover can only INCREASE the computed norm (never decrease it), so
//! `computed_norm <= beta^2` still implies `true_norm <= beta^2` (soundness), and the honest
//! generator picks the minimizing bit (completeness, exact equality with the native norm).
//!
//! # Accepted-set equivalence with the native verifier
//!
//! The circuit accepts `(pk_g, digest, salt, h, s2)` iff:
//! `pk_g = Poseidon(IMFK || encode(h))` with `h` canonical, and
//! `||(c - s2*h mod q, s2)||^2 <= beta^2` over centered values with `c = H2P(salt, digest)` —
//! exactly the predicate of native `verify_with_pk_g` on the mod-q classes of `(h, s2)`. The
//! native wire layer additionally restricts `s2` coefficients to the Golomb-Rice-encodable
//! band `[-2047, 2047]`; that is a TRANSPORT restriction enforced by
//! `FalconSignature::from_bytes` before native verification, not part of the verification
//! predicate (the GPV unforgeability argument is the norm bound; any circuit-accepted `s2`
//! outside the encodable band still satisfies the full Falcon verification equation). Phase-2
//! consumers witness the s2 that the native decoder produced, so completeness is unaffected.
//!
//! # Modular-reduction discipline (TM-C5 item 2)
//!
//! Every modular reduction in the gadget is the single primitive
//! [`constrain_mod_q_decomposition`]: `t = k*q + r` with `k` range-checked to `k_bits` and
//! `r` range-checked `< q`. Soundness argument, with `t_max` the caller-guaranteed bound on
//! the canonical value of `t`:
//! - representable set: `{k*q + r : k < 2^k_bits, r < q} = [0, 2^k_bits * q)`, each value having a
//!   UNIQUE `(k, r)` pair;
//! - no field wrap: `k_bits <= 49` is asserted at build time, so `k*q + r <= 2^49 * q - 1 < p` —
//!   the field equation IS the integer equation;
//! - therefore if `t_max < 2^k_bits * q`, the only satisfiable witness is the honest `(t div q, t
//!   mod q)`.
//!
//! The per-call-site `t_max` bounds are documented at each call below. The classic
//! quotient-cheating attack (`k-1, r+q`) is caught by the `r < q` check and covered by a
//! dedicated adversarial test.
//!
//! Goldilocks-to-`Z_q` reduction of the 64-bit H2P sponge outputs (quotient bound ~2^50)
//! deliberately does NOT use a single 50-bit-quotient decomposition: with `r < q` and
//! `k < 2^51` needed to cover all of `[0, p)`, `k*q + r` can exceed `p` and wrap, giving a
//! second representation. SECURITY: the affected range is NOT small — a second witness
//! `(k', r') = ((x + p - r') / q, (x + p) mod q)` exists for every canonical `x` with
//! `x + p < 2^51 * q ~= 2.77e19`, i.e. for `x < ~9.23e18`, roughly HALF the field. (An earlier
//! draft of this note claimed only `x < 5287`; that is merely the sub-case where `x + (p mod q)`
//! does not itself wrap mod q. The correct bound makes rejecting the naive form more clearly
//! right, and does not affect the shipped design.) Instead the element is first split
//! into its unique canonical `(hi, lo)` 32/32 decomposition (reusing the audited
//! `Bytes32Target::from_hash_out` safe split), then `t = hi * (2^32 mod q) + lo < 2^46` is
//! reduced with a 32-bit quotient — unique end to end.

use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::RichField,
        hashing::PlonkyPermutation as _,
        poseidon::{PoseidonHash, SPONGE_RATE, SPONGE_WIDTH},
    },
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::{BoolTarget, Target},
        witness::{PartialWitness, PartitionWitness, Witness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
    util::serialization::{Buffer, IoResult, Read, Write},
};

use super::{
    DOMAIN_FALCON_H2P, DOMAIN_FALCON_PK, FALCON_N, FALCON_Q, FALCON_SIG_L2_BOUND, FalconSignature,
    falcon_pk_digest,
};
use crate::{
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::poseidon_hash_out::PoseidonHashOutTarget,
};

// PARAMETERS
// ================================================================================================

const Q: u64 = FALCON_Q as u64; // 12289
const N: usize = FALCON_N; // 512
const LOG_N: usize = 9;
/// `2^32 mod q` — the reduction constant of the two-stage Goldilocks -> Z_q reduction.
const POW32_MOD_Q: u64 = 10952;
/// Primitive 1024th root of unity mod q (`49 = 7^2`; 7 is the standard primitive 2048th root
/// for q = 12289). `49^512 = -1 mod q` is asserted at twiddle-table build time.
const PSI: u64 = 49;
/// `512^{-1} mod q`, asserted at twiddle-table build time.
const N_INV: u64 = 12265;
/// Number of squeeze permutations in H2P: 512 coefficients / rate 8.
const H2P_SQUEEZES: usize = N / SPONGE_RATE;

// TWIDDLE TABLES
// ================================================================================================

fn pow_mod_q(mut base: u64, mut exp: u64) -> u64 {
    let mut acc = 1u64;
    base %= Q;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base % Q;
        }
        base = base * base % Q;
        exp >>= 1;
    }
    acc
}

fn bit_reverse_9(mut x: usize) -> usize {
    let mut r = 0;
    for _ in 0..LOG_N {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

/// Bit-reversed psi power tables for the negacyclic NTT (Longa–Naehrig convention:
/// `PSI_REV[j] = psi^{brv9(j)}`, `PSI_INV_REV[j] = psi^{-brv9(j)}`). The primitivity and
/// inverse identities the NTT correctness rests on are asserted here at circuit-build time.
fn twiddle_tables() -> (Vec<u64>, Vec<u64>, u64) {
    // SECURITY: these assertions pin the root-of-unity facts the whole NTT argument depends
    // on; they run on every circuit build (release asserts included).
    assert_eq!(pow_mod_q(PSI, N as u64), Q - 1, "psi^512 must be -1 mod q");
    assert_eq!(pow_mod_q(PSI, 2 * N as u64), 1, "psi^1024 must be 1 mod q");
    let psi_inv = pow_mod_q(PSI, Q - 2);
    assert_eq!(PSI * psi_inv % Q, 1, "psi * psi^-1 must be 1 mod q");
    assert_eq!(N as u64 * N_INV % Q, 1, "n * n^-1 must be 1 mod q");
    let psi_rev: Vec<u64> = (0..N)
        .map(|j| pow_mod_q(PSI, bit_reverse_9(j) as u64))
        .collect();
    let psi_inv_rev: Vec<u64> = (0..N)
        .map(|j| pow_mod_q(psi_inv, bit_reverse_9(j) as u64))
        .collect();
    (psi_rev, psi_inv_rev, N_INV)
}

// MOD-Q REDUCTION PRIMITIVE
// ================================================================================================

/// Witness generator for the mod-q decomposition: writes `k = t div q`, `r = t mod q` of the
/// canonical value of `t`. Completeness only — soundness comes from
/// [`constrain_mod_q_decomposition`].
#[derive(Debug, Default)]
pub(super) struct ModQGenerator {
    pub(super) t: Target,
    pub(super) k: Target,
    pub(super) r: Target,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for ModQGenerator {
    fn id(&self) -> String {
        "FalconModQGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        vec![self.t]
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let t = witness.get_target(self.t).to_canonical_u64();
        out_buffer.set_target(self.k, F::from_canonical_u64(t / Q))?;
        out_buffer.set_target(self.r, F::from_canonical_u64(t % Q))
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target(self.t)?;
        dst.write_target(self.k)?;
        dst.write_target(self.r)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let t = src.read_target()?;
        let k = src.read_target()?;
        let r = src.read_target()?;
        Ok(Self { t, k, r })
    }
}

/// Constrains `t == k*q + r` with `k < 2^k_bits` and `r < q` (both range-checked).
///
/// SECURITY: this is the single reduction primitive of the gadget — see the module-level
/// "Modular-reduction discipline" for the uniqueness/no-wrap argument. The CALLER must
/// guarantee that the canonical value of `t` is `< 2^k_bits * q` (documented at each call
/// site); `k_bits <= 49` is asserted so `k*q + r` can never wrap mod p.
///
/// Exposed with witnessable `k`/`r` so the adversarial suite can drive quotient-cheating
/// attempts directly (O-5, "wrong quotient witness" test); production callers use
/// [`reduce_mod_q`], which allocates `k`/`r` and installs the honest generator.
fn constrain_mod_q_decomposition<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    t: Target,
    k: Target,
    r: Target,
    k_bits: usize,
) {
    assert!(
        (1..=49).contains(&k_bits),
        "k_bits out of the no-wrap range"
    );
    // t == k*q + r over the field (== over the integers, by the range checks + no-wrap bound).
    let recomposed = builder.mul_const_add(F::from_canonical_u64(Q), k, r);
    builder.connect(t, recomposed);
    // k < 2^k_bits. For the 1-bit case a booleanity constraint is cheaper than a range-check
    // row and equivalent (k in {0, 1}).
    if k_bits == 1 {
        builder.assert_bool(BoolTarget::new_unsafe(k));
    } else {
        builder.range_check(k, k_bits);
    }
    // r < q, as two 14-bit range checks: r < 2^14 AND (q-1) - r < 2^14. If r were in
    // [q, 2^14), the value (q-1) - r would wrap to ~p and fail the second check; if r >= 2^14
    // the first check fails. Together: r in [0, q). This closes the classic `(k-1, r+q)`
    // quotient-cheating hole (adversarial test below).
    builder.range_check(r, 14);
    let q_minus_1 = builder.constant(F::from_canonical_u64(Q - 1));
    let complement = builder.sub(q_minus_1, r);
    builder.range_check(complement, 14);
}

/// Reduces `t` mod q: allocates `(k, r)`, installs the honest [`ModQGenerator`], and applies
/// [`constrain_mod_q_decomposition`]. Returns `r`. Caller obligation on `t`'s bound as above.
pub(super) fn reduce_mod_q<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    t: Target,
    k_bits: usize,
) -> Target {
    let k = builder.add_virtual_target();
    let r = builder.add_virtual_target();
    builder.add_simple_generator(ModQGenerator { t, k, r });
    constrain_mod_q_decomposition(builder, t, k, r, k_bits);
    r
}

/// Range-checks a witnessed coefficient to the canonical domain `[0, q)` (same two-check
/// construction as the `r < q` part of the reduction primitive).
pub(super) fn assert_canonical_coeff<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    v: Target,
) {
    builder.range_check(v, 14);
    let q_minus_1 = builder.constant(F::from_canonical_u64(Q - 1));
    let complement = builder.sub(q_minus_1, v);
    builder.range_check(complement, 14);
}

// GOLDILOCKS -> Z_q REDUCTION OF SPONGE OUTPUTS
// ================================================================================================

/// Reduces a full rate block (8 sponge output elements) to 8 canonical Falcon coefficients,
/// mirroring the native `felt_to_falcon_felt` (`to_canonical_u64() % q`) exactly.
///
/// Stage 1: the unique canonical 32/32 split of each element, via the audited
/// `Bytes32Target::from_hash_out` (plonky2 `split_low_high` + the hi-max fix that removes the
/// second decomposition of values < 2^32). Stage 2: `t = hi * (2^32 mod q) + lo`, with
/// `t_max = (2^32 - 1) * 10952 + (2^32 - 1) < 2^46 < 2^32 * q`, reduced with a 32-bit
/// quotient (`k_max = t_max / q < 2^32`; `2^32 * q - 1 < p`, no wrap — see module doc).
fn goldilocks_mod_q_block<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    block: &[Target],
) -> Vec<Target> {
    assert_eq!(block.len(), SPONGE_RATE);
    let mut out = Vec::with_capacity(SPONGE_RATE);
    for half in block.chunks(4) {
        let hash_out = PoseidonHashOutTarget {
            elements: half.try_into().unwrap(),
        };
        // limbs = [hi_0, lo_0, hi_1, lo_1, ...] — canonical split with the two-decomposition
        // fix (see `safe_split_lo_and_hi` in utils/poseidon_hash_out.rs).
        let limbs = Bytes32Target::from_hash_out(builder, hash_out).to_vec();
        for i in 0..4 {
            let hi = limbs[2 * i];
            let lo = limbs[2 * i + 1];
            // t = hi * 10952 + lo, congruent to the element mod q; t < 2^46 (bound above).
            let t = builder.mul_const_add(F::from_canonical_u64(POW32_MOD_Q), hi, lo);
            out.push(reduce_mod_q(builder, t, 32));
        }
    }
    out
}

// HASH-TO-POINT (IN-CIRCUIT MIRROR OF `hash_to_point_poseidon`, O-2)
// ================================================================================================

/// Computes the 512 H2P coefficients from the salt elements and the message digest limbs.
///
/// Sponge layout mirrored element-for-element from `vendor/hash_to_point.rs`:
/// - capacity initialized `[IMFH, 0, 0, 0]` (the domain constant sits in the CAPACITY, unlike every
///   other IMxx use in this codebase, which prefixes the rate input — Phase-0 review flagged this
///   convention; the KAT mirror test pins it);
/// - rate overwritten with the 8 packed salt elements, one permutation;
/// - rate overwritten with the 8 digest u32 limbs (capacity carries state), then a fixed
///   64-permutation squeeze reading the full rate after each permutation;
/// - each output element reduced mod q from the FULL canonical 64-bit value (O-1: one full element
///   per coefficient, never split or reused).
///
/// Salt elements are range-checked `< 2^40` here (injectivity of the 40-byte packing).
/// Digest limbs must be canonical u32s — guaranteed by the gadget's `Bytes32Target::new(_,
/// true)` input construction (and by any consumer connecting a keccak output).
pub(super) fn h2p_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    salt: &[Target; 8],
    message_digest: &Bytes32Target,
) -> Vec<Target> {
    // SECURITY: 40-bit range checks make the salt-element encoding injective (exactly one
    // 8-element encoding per 40-byte salt), mirroring `Nonce::to_elements` canonicity.
    for s in salt.iter() {
        builder.range_check(*s, 40);
    }

    let zero = builder.zero();
    let imfh = builder.constant(F::from_canonical_u32(DOMAIN_FALCON_H2P));

    // State: [salt(8) | IMFH, 0, 0, 0].
    let mut state: Vec<Target> = Vec::with_capacity(SPONGE_WIDTH);
    state.extend_from_slice(salt);
    state.push(imfh);
    state.extend([zero; 3]);

    let mut perm = <PoseidonHash as AlgebraicHasher<F>>::AlgebraicPermutation::default();
    perm.set_from_slice(&state, 0);
    perm = builder.permute::<PoseidonHash>(perm);

    // Overwrite the rate with the digest limbs (canonical u32 lift, same limb order as the
    // native `Bytes32::to_u32_vec`); the 4-element capacity carries the salt binding.
    let mut state: Vec<Target> = perm.as_ref().to_vec();
    state[..SPONGE_RATE].copy_from_slice(&message_digest.to_vec());
    let mut perm = <PoseidonHash as AlgebraicHasher<F>>::AlgebraicPermutation::default();
    perm.set_from_slice(&state, 0);

    let mut coefficients = Vec::with_capacity(N);
    for _ in 0..H2P_SQUEEZES {
        perm = builder.permute::<PoseidonHash>(perm);
        let rate: Vec<Target> = perm.squeeze()[..SPONGE_RATE].to_vec();
        coefficients.extend(goldilocks_mod_q_block(builder, &rate));
    }
    coefficients
}

// PK DIGEST (IN-CIRCUIT MIRROR OF `falcon_pk_digest`, TM-C5 ITEM 5)
// ================================================================================================

/// Computes `Poseidon(IMFK || encode(h))` as a `Bytes32Target`.
///
/// PRECONDITION (caller-enforced, single site in [`FalconSigVerifyTarget::new`]): every `h`
/// coefficient is range-checked `< q < 2^14`, which makes the 4x14-bit-lane packing injective
/// (each packed element `< 2^56 < p`) — exactly the native `encode(h)` canonicity argument.
pub(super) fn pk_digest_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    h: &[Target],
) -> Bytes32Target {
    assert_eq!(h.len(), N);
    let imfk = builder.constant(F::from_canonical_u32(DOMAIN_FALCON_PK));
    let mut inputs = Vec::with_capacity(1 + N / 4);
    inputs.push(imfk);
    for chunk in h.chunks_exact(4) {
        // Horner: e = ((h3 * 2^14 + h2) * 2^14 + h1) * 2^14 + h0 — little-lane-first packing,
        // identical to the native `packed |= coeff << (14 * lane)`.
        let mut e = chunk[3];
        for &lane in [chunk[2], chunk[1], chunk[0]].iter() {
            e = builder.mul_const_add(F::from_canonical_u64(1 << 14), e, lane);
        }
        inputs.push(e);
    }
    let hash = PoseidonHashOutTarget::hash_inputs(builder, &inputs);
    // Same canonical HashOut -> Bytes32 conversion ([hi, lo] u32 limbs per element) as the
    // native `Bytes32::from(PoseidonHashOut)`.
    Bytes32Target::from_hash_out(builder, hash)
}

// NTT (IN-CIRCUIT, MOD 12289, EVERY REDUCTION RANGE-CHECKED — TM-C5 ITEM 2)
// ================================================================================================

/// Forward negacyclic NTT (Cooley–Tukey DIT; natural-order input, bit-reversed output). All
/// inputs and outputs canonical `< q`; every butterfly output is reduced immediately.
///
/// Per-butterfly reductions (bounds with `u, b < q`, twiddle constant `s < q`):
/// - `t_add = u + s*b < q + (q-1)^2 < q^2 + q < 2^14 * q` — quotient 14 bits;
/// - `t_sub = u + q^2 - s*b <= q^2 + q - 1 < 2^14 * q` — quotient 14 bits (the `q^2` offset keeps
///   the value positive; `q^2 ≡ 0 mod q` so congruence is preserved).
fn ntt_forward<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    psi_rev: &[u64],
    input: &[Target],
) -> Vec<Target> {
    assert_eq!(input.len(), N);
    let mut a = input.to_vec();
    let q_sq = F::from_canonical_u64(Q * Q);
    let mut t = N;
    let mut m = 1;
    while m < N {
        t /= 2;
        for i in 0..m {
            let j1 = 2 * i * t;
            let s = F::from_canonical_u64(psi_rev[m + i]);
            for j in j1..j1 + t {
                let u = a[j];
                let v_raw = builder.mul_const(s, a[j + t]); // < (q-1)^2, unreduced
                let t_add = builder.add(u, v_raw);
                a[j] = reduce_mod_q(builder, t_add, 14);
                // u - v mod q, computed as u + q^2 - v_raw (positive, congruent).
                let u_shift = builder.add_const(u, q_sq);
                let t_sub = builder.sub(u_shift, v_raw);
                a[j + t] = reduce_mod_q(builder, t_sub, 14);
            }
        }
        m *= 2;
    }
    a
}

/// Inverse negacyclic NTT (Gentleman–Sande; bit-reversed input, natural-order output),
/// including the final `n^{-1}` scaling. All values canonical `< q` throughout.
///
/// Per-butterfly reductions (with `u, v < q`, twiddle `s < q`):
/// - `t_add = u + v < 2q` — 1-bit quotient;
/// - `t_sub_prod = (u + q - v) * s <= (2q - 1)(q - 1) < 2^15 * q` — quotient 15 bits (the
///   sub-then-multiply is folded into a single reduction);
/// - final scaling `a * n_inv < q^2 < 2^14 * q` — quotient 14 bits.
fn ntt_inverse<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    psi_inv_rev: &[u64],
    n_inv: u64,
    input: &[Target],
) -> Vec<Target> {
    assert_eq!(input.len(), N);
    let mut a = input.to_vec();
    let q_const = F::from_canonical_u64(Q);
    let mut t = 1;
    let mut m = N;
    while m > 1 {
        let mut j1 = 0;
        let h = m / 2;
        for i in 0..h {
            let s = F::from_canonical_u64(psi_inv_rev[h + i]);
            for j in j1..j1 + t {
                let u = a[j];
                let v = a[j + t];
                let t_add = builder.add(u, v);
                a[j] = reduce_mod_q(builder, t_add, 1);
                // (u - v) * s mod q as (u + q - v) * s: u + q - v in [1, 2q-1].
                let u_shift = builder.add_const(u, q_const);
                let diff = builder.sub(u_shift, v);
                let prod = builder.mul_const(s, diff);
                a[j + t] = reduce_mod_q(builder, prod, 15);
            }
            j1 += 2 * t;
        }
        t *= 2;
        m = h;
    }
    let n_inv_const = F::from_canonical_u64(n_inv);
    a.into_iter()
        .map(|x| {
            let scaled = builder.mul_const(n_inv_const, x);
            reduce_mod_q(builder, scaled, 14)
        })
        .collect()
}

/// Pointwise product of two NTT-domain vectors: `x*y < (q-1)^2 < 2^14 * q` — 14-bit quotient.
fn pointwise_mul<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: &[Target],
    y: &[Target],
) -> Vec<Target> {
    x.iter()
        .zip(y.iter())
        .map(|(&a, &b)| {
            let prod = builder.mul(a, b);
            reduce_mod_q(builder, prod, 14)
        })
        .collect()
}

// CENTERED SQUARE (NORM, TM-C5 ITEM 3)
// ================================================================================================

/// Witness generator for the honest centering bit `b = (v > q/2)` of a canonical `v < q`.
#[derive(Debug, Default)]
struct CenterBitGenerator {
    v: Target,
    b: Target,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for CenterBitGenerator {
    fn id(&self) -> String {
        "FalconCenterBitGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        vec![self.v]
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let v = witness.get_target(self.v).to_canonical_u64();
        out_buffer.set_target(self.b, F::from_bool(v > Q / 2))
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target(self.v)?;
        dst.write_target(self.b)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let v = src.read_target()?;
        let b = src.read_target()?;
        Ok(Self { v, b })
    }
}

/// The squared centered value `(v - b*q)^2` of a canonical coefficient `v < q`, with a
/// prover-free boolean `b` — see the module-level soundness note (a lying `b` can only
/// increase the square, so the norm bound stays sound; the honest generator minimizes).
/// Field arithmetic note: for `b = 1` the field value `v - q mod p = p - (q - v)` squares to
/// `(q - v)^2 mod p`, and `(q - v)^2 < 2^28 << p`, so the field square IS the integer square.
pub(super) fn centered_square<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    v: Target,
) -> Target {
    let b = builder.add_virtual_target();
    builder.add_simple_generator(CenterBitGenerator { v, b });
    builder.assert_bool(BoolTarget::new_unsafe(b));
    let bq = builder.mul_const(F::from_canonical_u64(Q), b);
    let centered = builder.sub(v, bq);
    builder.mul(centered, centered)
}

// THE GADGET
// ================================================================================================

/// In-circuit Falcon-512/Poseidon signature verification for ONE signature.
///
/// See the module doc for the input/witness contract. Constraint satisfaction implies exactly
/// the native `verify_with_pk_g(pk_g, h, message_digest, (salt, s2))` predicate.
#[derive(Debug, Clone)]
pub struct FalconSigVerifyTarget {
    /// INPUT: member identity digest; internally connected to `Poseidon(IMFK || encode(h))`.
    pub pk_g: Bytes32Target,
    /// INPUT: the signed 32-byte digest as 8 u32 limbs. CONSUMERS MUST connect this to a
    /// digest recomputed in-circuit for their context (TM-C5 item 4) — never leave it free.
    pub message_digest: Bytes32Target,
    /// Witness: packed salt elements (8 x 5 LE bytes, each < 2^40).
    pub salt: [Target; 8],
    /// Witness: public polynomial coefficients, canonical `< q`.
    pub h: Vec<Target>,
    /// Witness: signature polynomial coefficients, canonical residues `< q`.
    pub s2: Vec<Target>,
}

impl FalconSigVerifyTarget {
    /// Builds the full verification constraint set:
    /// 1. range checks: salt < 2^40 per element (inside H2P), `h` and `s2` canonical `< q`;
    /// 2. `pk_g == Poseidon(IMFK || encode(h))` (binding INSIDE the gadget, review F-2);
    /// 3. `c = H2P(salt, message_digest)` — 65 Poseidon permutations, full-element mod-q;
    /// 4. `s1 = c - s2*h` in `Z_q[X]/(X^512 + 1)` via range-checked NTT;
    /// 5. `||(s1, s2)||^2 <= beta^2` over centered values.
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::build(builder, None)
    }

    /// Conditional variant for pad-to-MAX consumers (Phase 2, close / cancel-close): the
    /// signature is verified iff `verify` is 1; with `verify = 0` the slot is a PADDING slot and
    /// the all-zero witness ([`FalconSigGadgetWitness::padding`]) satisfies the constraints.
    ///
    /// SECURITY (padding-slot gating): ONLY the final norm-bound comparison is gated
    /// (`slack' = select(verify, beta^2 - norm, 0)` before the 26-bit range check). Everything
    /// else — coefficient canonicity, the `pk_g == Poseidon(IMFK || encode(h))` binding, H2P,
    /// and the NTT equation `s1 = c - s2*h` — remains UNCONDITIONALLY enforced:
    /// - with `verify = 1` the constraint set is EXACTLY the unconditional gadget (the select
    ///   passes the real slack through), so an active slot verifies the full native predicate — a
    ///   prover cannot "pad out" an active slot: its norm bound is live;
    /// - with `verify = 0` the norm bound (the sole accept/reject decision of the scheme) is
    ///   replaced by the trivially-true check of the constant 0, so the all-zero witness (`h = s2 =
    ///   salt = 0`, `pk_g = Poseidon(IMFK || encode(0))`) satisfies the slot: the ungated equations
    ///   then just compute `s1 = c` with an unchecked norm. The gate wire is NOT constrained here —
    ///   the CONSUMER MUST bind it (close/cancel bind it to the unary `member_count` decomposition,
    ///   which is itself bound into the signed H1/IMCH), exactly like the `message_digest` input
    ///   obligation.
    ///
    /// A padding slot's `pk_g` is therefore forced (by the ungated pk binding) to the fixed
    /// public constant [`super::falcon_padding_pk_g`] — consumers MUST NOT admit that digest
    /// into any identity-bearing structure for inactive slots (close/cancel zero padding slots
    /// out of the member-set commitment and skip them in the distinctness chain).
    pub fn new_conditional<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        verify: BoolTarget,
    ) -> Self {
        Self::build(builder, Some(verify))
    }

    fn build<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        verify: Option<BoolTarget>,
    ) -> Self {
        let (psi_rev, psi_inv_rev, n_inv) = twiddle_tables();

        // Inputs. `true` range-checks each limb < 2^32 (canonical limbs, matching the native
        // `from_canonical_u32` lift of digest limbs into the sponge).
        let pk_g = Bytes32Target::new(builder, true);
        let message_digest = Bytes32Target::new(builder, true);

        // Witnesses.
        let salt: [Target; 8] = core::array::from_fn(|_| builder.add_virtual_target());
        let h: Vec<Target> = (0..N).map(|_| builder.add_virtual_target()).collect();
        let s2: Vec<Target> = (0..N).map(|_| builder.add_virtual_target()).collect();

        // Canonicity gates (TM-C5 items 1 and 5): exactly one in-circuit encoding per
        // coefficient residue class, for both h (feeds the injective encode(h) packing) and
        // s2 (feeds the NTT and the centered norm).
        for &c in h.iter().chain(s2.iter()) {
            assert_canonical_coeff(builder, c);
        }

        // pk binding (TM-C5 item 5): computed INSIDE the gadget and connected to the input.
        let pk_computed = pk_digest_circuit(builder, &h);
        pk_g.connect(builder, pk_computed);

        // c = H2P(salt, digest) (TM-C1/O-1 mirror; salt range checks inside).
        let c = h2p_circuit(builder, &salt, &message_digest);

        // s1 = c - s2*h mod q mod (X^512 + 1) (TM-C5 item 2). `h` is a witness; its NTT is
        // computed IN-CIRCUIT (same constraint cost as witnessing NTT(h) and verifying by
        // inverse transform, but with no extra witness surface — strictly simpler).
        let h_ntt = ntt_forward(builder, &psi_rev, &h);
        let s2_ntt = ntt_forward(builder, &psi_rev, &s2);
        let prod_ntt = pointwise_mul(builder, &s2_ntt, &h_ntt);
        let prod = ntt_inverse(builder, &psi_inv_rev, n_inv, &prod_ntt);
        let q_const = plonky2::field::types::Field::from_canonical_u64(Q);
        let s1: Vec<Target> = c
            .iter()
            .zip(prod.iter())
            .map(|(&ci, &pi)| {
                // c + q - prod in [1, 2q-1] — 1-bit quotient.
                let shifted = builder.add_const(ci, q_const);
                let diff = builder.sub(shifted, pi);
                reduce_mod_q(builder, diff, 1)
            })
            .collect();

        // Norm (TM-C5 item 3): sum of 1024 centered squares. Max possible sum
        // 1024 * 6144^2 = 38_654_705_664 < 2^36 << p — no field wrap (pinned by test).
        let squares: Vec<Target> = s1
            .iter()
            .chain(s2.iter())
            .map(|&v| centered_square(builder, v))
            .collect();
        let norm = builder.add_many(&squares);

        // norm <= beta^2, via a 26-bit range check of beta^2 - norm (beta^2 < 2^26):
        // if norm <= beta^2 the difference is in [0, beta^2] subset [0, 2^26); if
        // norm > beta^2 (norm < 2^36), the field value wraps to >= p - 2^36 and fails.
        //
        // Conditional variant (see `new_conditional`): the gate wraps EXACTLY this comparison —
        // `select(verify, slack, 0)` — so verify = 1 reproduces the unconditional check
        // verbatim and verify = 0 range-checks the constant 0 (trivially true).
        let beta_sq = builder.constant(plonky2::field::types::Field::from_canonical_u64(
            FALCON_SIG_L2_BOUND,
        ));
        let slack = builder.sub(beta_sq, norm);
        let checked_slack = match verify {
            None => slack,
            Some(bit) => {
                let zero = builder.zero();
                builder.select(bit, slack, zero)
            }
        };
        builder.range_check(checked_slack, 26);

        Self {
            pk_g,
            message_digest,
            salt,
            h,
            s2,
        }
    }

    /// Sets all witness values from a [`FalconSigGadgetWitness`].
    pub fn set_witness<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        witness: &FalconSigGadgetWitness,
    ) -> Result<()> {
        for (t, limb) in self
            .pk_g
            .to_vec()
            .iter()
            .zip(witness.pk_g.to_u32_vec().iter())
        {
            pw.set_target(*t, F::from_canonical_u32(*limb))?;
        }
        for (t, limb) in self
            .message_digest
            .to_vec()
            .iter()
            .zip(witness.message_digest.to_u32_vec().iter())
        {
            pw.set_target(*t, F::from_canonical_u32(*limb))?;
        }
        for (t, v) in self.salt.iter().zip(witness.salt_elements.iter()) {
            pw.set_target(*t, F::from_canonical_u64(*v))?;
        }
        for (t, v) in self.h.iter().zip(witness.h.iter()) {
            pw.set_target(*t, F::from_canonical_u64(*v))?;
        }
        for (t, v) in self.s2.iter().zip(witness.s2.iter()) {
            pw.set_target(*t, F::from_canonical_u64(*v))?;
        }
        Ok(())
    }

    /// Sets ONLY the signature-side witnesses (salt, h, s2) — for consumers whose `pk_g` and
    /// `message_digest` inputs are CONNECTED to in-circuit-derived wires (the Phase-2 close /
    /// cancel-close pattern: `message_digest` is the recomputed IMCH keccak output and `pk_g`
    /// is derived by the gadget's own Poseidon binding from `h`), so their values are produced
    /// by witness generation through the copy constraints and setting them here would be
    /// redundant (and, for a tampered-PI test, a spurious early conflict instead of the
    /// in-circuit constraint rejection).
    pub fn set_signature_witness<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        witness: &FalconSigGadgetWitness,
    ) -> Result<()> {
        for (t, v) in self.salt.iter().zip(witness.salt_elements.iter()) {
            pw.set_target(*t, F::from_canonical_u64(*v))?;
        }
        for (t, v) in self.h.iter().zip(witness.h.iter()) {
            pw.set_target(*t, F::from_canonical_u64(*v))?;
        }
        for (t, v) in self.s2.iter().zip(witness.s2.iter()) {
            pw.set_target(*t, F::from_canonical_u64(*v))?;
        }
        Ok(())
    }
}

/// Witness values for one signature, in the exact raw form the circuit consumes (u64 field
/// values). Constructed honestly via [`FalconSigGadgetWitness::for_signature`]; the
/// adversarial tests doctor the public fields directly.
#[derive(Debug, Clone)]
pub struct FalconSigGadgetWitness {
    pub pk_g: Bytes32,
    pub message_digest: Bytes32,
    /// Salt packed as 8 elements of 5 LE bytes (mirror of `Nonce::to_elements`).
    pub salt_elements: [u64; 8],
    /// Canonical h coefficients (`< q`).
    pub h: Vec<u64>,
    /// Canonical s2 residues (`< q`; centered value `v` maps to `v >= 0 ? v : v + q`).
    pub s2: Vec<u64>,
}

impl FalconSigGadgetWitness {
    /// Honest witness for a native signature under public polynomial `h` (pk_g derived).
    pub fn for_signature(
        h: &[u16; FALCON_N],
        message_digest: Bytes32,
        sig: &FalconSignature,
    ) -> Self {
        let s2_centered = sig.s2_coefficients();
        Self {
            pk_g: falcon_pk_digest(h),
            message_digest,
            salt_elements: salt_to_elements(&sig.salt()),
            h: h.iter().map(|&c| c as u64).collect(),
            s2: s2_centered
                .iter()
                .map(|&c| {
                    if c < 0 {
                        (c as i64 + Q as i64) as u64
                    } else {
                        c as u64
                    }
                })
                .collect(),
        }
    }

    /// The canonical PADDING-slot witness for a [`FalconSigVerifyTarget::new_conditional`] slot
    /// with `verify = 0`: all-zero salt / h / s2, `pk_g = Poseidon(IMFK || encode(0)) =`
    /// [`super::falcon_padding_pk_g`], and the consumer's `message_digest` (whose input targets
    /// are connected to the consumer's recomputed digest, so the witness value must match it).
    ///
    /// SECURITY: this satisfies every UNGATED constraint (canonicity of zeros, the pk binding on
    /// the zero polynomial, H2P/NTT which simply compute `s1 = c`) while the gated norm bound is
    /// off. It is NOT a signature: with `verify = 1` this witness is rejected by the norm bound
    /// (`||c||^2 >> beta^2` for any real digest — pinned by the conditional-gadget tests).
    pub fn padding(message_digest: Bytes32) -> Self {
        Self {
            pk_g: super::falcon_padding_pk_g(),
            message_digest,
            salt_elements: [0u64; 8],
            h: vec![0u64; FALCON_N],
            s2: vec![0u64; FALCON_N],
        }
    }
}

/// The native 40-byte-salt -> 8-element packing (`Nonce::to_elements` mirror: 5 LE bytes per
/// element).
pub fn salt_to_elements(salt: &[u8; 40]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for (i, chunk) in salt.chunks(5).enumerate() {
        let mut buf = [0u8; 8];
        buf[..5].copy_from_slice(chunk);
        out[i] = u64::from_le_bytes(buf);
    }
    out
}

// STANDALONE HARNESS CIRCUIT (PHASE-1 MEASUREMENT DELIVERABLE)
// ================================================================================================

/// Standalone circuit verifying `n_sigs` independent Falcon signatures with
/// `standard_recursion_config`. Public inputs, per signature in order:
/// `pk_g` (8 limbs) then `message_digest` (8 limbs).
pub struct FalconSigCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub targets: Vec<FalconSigVerifyTarget>,
    /// Builder gate count before padding (reported alongside `data.common.degree_bits()`).
    pub num_gates_before_padding: usize,
}

impl<F, C, const D: usize> FalconSigCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn new(n_sigs: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let targets: Vec<FalconSigVerifyTarget> = (0..n_sigs)
            .map(|_| {
                let t = FalconSigVerifyTarget::new(&mut builder);
                builder.register_public_inputs(&t.pk_g.to_vec());
                builder.register_public_inputs(&t.message_digest.to_vec());
                t
            })
            .collect();
        let num_gates_before_padding = builder.num_gates();
        let data = builder.build::<C>();
        Self {
            data,
            targets,
            num_gates_before_padding,
        }
    }

    pub fn prove(
        &self,
        witnesses: &[FalconSigGadgetWitness],
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        anyhow::ensure!(
            witnesses.len() == self.targets.len(),
            "witness count {} != signature slot count {}",
            witnesses.len(),
            self.targets.len()
        );
        let mut pw = PartialWitness::new();
        for (t, w) in self.targets.iter().zip(witnesses.iter()) {
            t.set_witness(&mut pw, w)?;
        }
        self.data.prove(pw)
    }
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
    use crate::falcon_sig::{
        FalconKeys, Nonce, hash_to_point_poseidon,
        vendor::{FalconFelt, FastFft as _, Polynomial},
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    /// One shared deterministic keypair (same seed as the native suite) and one shared N=1
    /// harness circuit — building the circuit once keeps the adversarial suite fast without
    /// weakening any test (every case proves/fails against the same constraint system).
    static KEYS: Lazy<FalconKeys> = Lazy::new(|| FalconKeys::from_seed([7u8; 32]));
    static KEYS_H: Lazy<[u16; FALCON_N]> = Lazy::new(|| KEYS.pk_coefficients());
    static N1_CIRCUIT: Lazy<FalconSigCircuit<F, C, D>> = Lazy::new(|| FalconSigCircuit::new(1));

    fn sample_digest(tag: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_0000 | tag as u32, 1, 2, 3, 4, 5, 6, 7]).unwrap()
    }

    fn honest_witness(tag: u8) -> FalconSigGadgetWitness {
        let digest = sample_digest(tag);
        let sig = KEYS.sign(digest);
        FalconSigGadgetWitness::for_signature(&KEYS_H, digest, &sig)
    }

    /// Repo negative-proof idiom (close_circuit tests): the doctored witness must be rejected
    /// at witness generation, at proving, or — belt and braces — at verification. Never
    /// accepted end to end.
    fn assert_rejected(circuit: &FalconSigCircuit<F, C, D>, w: FalconSigGadgetWitness, msg: &str) {
        let result = catch_unwind(AssertUnwindSafe(|| circuit.prove(std::slice::from_ref(&w))));
        let rejected = match result {
            Err(_) => true,
            Ok(Err(_)) => true,
            Ok(Ok(proof)) => circuit.data.verify(proof).is_err(),
        };
        assert!(rejected, "{msg}");
    }

    fn assert_accepted(circuit: &FalconSigCircuit<F, C, D>, w: FalconSigGadgetWitness, msg: &str) {
        let proof = circuit
            .prove(std::slice::from_ref(&w))
            .unwrap_or_else(|e| panic!("{msg}: prove failed: {e}"));
        circuit
            .data
            .verify(proof)
            .unwrap_or_else(|e| panic!("{msg}: verify failed: {e}"));
    }

    // ---- native references used as oracles --------------------------------------------------

    /// Obviously-correct O(n^2) negacyclic schoolbook product mod q (test oracle for the NTT).
    fn schoolbook_negacyclic(a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut c = vec![0i128; N];
        for (i, &ai) in a.iter().enumerate() {
            if ai == 0 {
                continue;
            }
            for (j, &bj) in b.iter().enumerate() {
                let prod = (ai * bj) as i128;
                let k = i + j;
                if k < N {
                    c[k] += prod;
                } else {
                    c[k - N] -= prod;
                }
            }
        }
        c.into_iter()
            .map(|v| (v.rem_euclid(Q as i128)) as u64)
            .collect()
    }

    /// Native u64 mirror of the circuit NTT algorithms (same tables, same loop structure) —
    /// validates the algorithm itself against the schoolbook oracle before it is trusted in
    /// circuit form.
    fn ntt_product_native(a: &[u64], b: &[u64]) -> Vec<u64> {
        let (psi_rev, psi_inv_rev, n_inv) = twiddle_tables();
        let fwd = |input: &[u64]| -> Vec<u64> {
            let mut a = input.to_vec();
            let mut t = N;
            let mut m = 1;
            while m < N {
                t /= 2;
                for i in 0..m {
                    let j1 = 2 * i * t;
                    let s = psi_rev[m + i];
                    for j in j1..j1 + t {
                        let u = a[j];
                        let v = a[j + t] * s % Q;
                        a[j] = (u + v) % Q;
                        a[j + t] = (u + Q - v) % Q;
                    }
                }
                m *= 2;
            }
            a
        };
        let fa = fwd(a);
        let fb = fwd(b);
        let mut prod: Vec<u64> = fa.iter().zip(fb.iter()).map(|(x, y)| x * y % Q).collect();
        let mut t = 1;
        let mut m = N;
        while m > 1 {
            let mut j1 = 0;
            let h = m / 2;
            for i in 0..h {
                let s = psi_inv_rev[h + i];
                for j in j1..j1 + t {
                    let u = prod[j];
                    let v = prod[j + t];
                    prod[j] = (u + v) % Q;
                    prod[j + t] = (u + Q - v) * s % Q;
                }
                j1 += 2 * t;
            }
            t *= 2;
            m = h;
        }
        prod.into_iter().map(|x| x * n_inv % Q).collect()
    }

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn random_poly(state: &mut u64) -> Vec<u64> {
        (0..N).map(|_| xorshift(state) % Q).collect()
    }

    // ---- bound ledger -----------------------------------------------------------------------

    /// SECURITY: pins every arithmetic bound the reduction discipline quotes (module doc +
    /// per-call-site comments). If a parameter ever changes, this fails before a too-narrow
    /// range check silently becomes an unsoundness.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    // The whole point of this test is asserting (documented) constant facts.
    #[allow(clippy::assertions_on_constants)]
    fn reduction_bound_ledger() {
        const P: u128 = 0xffff_ffff_0000_0001; // Goldilocks
        let q = Q as u128;
        // constrain_mod_q_decomposition no-wrap: at the 49-bit cap, k*q + r <= 2^49*q - 1 < p
        // (50 bits would also be wrap-free, but 49 keeps a full bit of headroom); at 51 bits
        // the maximum exceeds p — i.e. an uncapped quotient WOULD admit wrapped second
        // representations, which is why the cap assertion in the primitive exists.
        assert!((1u128 << 49) * q - 1 < P);
        assert!((1u128 << 50) * q - 1 < P);
        assert!((1u128 << 51) * q > P, "wrap becomes possible at 51 bits");
        // H2P stage 2: t = hi*10952 + lo < 2^32 * q, 32-bit quotient, no wrap.
        let t_max = ((1u128 << 32) - 1) * (POW32_MOD_Q as u128) + ((1u128 << 32) - 1);
        assert!(t_max < (1u128 << 32) * q);
        assert!((1u128 << 32) * q - 1 < P);
        assert_eq!((1u128 << 32) % q, POW32_MOD_Q as u128);
        // CT butterfly: u + (q-1)^2 and u + q^2 - v_raw both < 2^14 * q.
        assert!((q - 1) + (q - 1) * (q - 1) < (1u128 << 14) * q);
        assert!(q * q + q - 1 < (1u128 << 14) * q);
        // GS butterfly: (2q-1)(q-1) < 2^15 * q; pointwise/scaling: (q-1)^2 < 2^14 * q.
        assert!((2 * q - 1) * (q - 1) < (1u128 << 15) * q);
        assert!((q - 1) * (q - 1) < (1u128 << 14) * q);
        // s1 subtraction: c + q - prod < 2q — 1-bit quotient.
        assert!(2 * q - 1 < 2 * q);
        // Norm, no field wrap in the 1024-term sum. SECURITY: the bound that matters is the
        // ADVERSARIAL maximum, not the honest one. Honestly centered coefficients give
        // |centered| <= q/2 = 6144 and 1024 * 6144^2 < 2^36 — but a prover may set the free
        // centering bit to 1 on v = 0, giving centered = -q and square q^2. The reachable
        // maximum is therefore 1024 * q^2 < 2^38, ~4x the honest figure. Both are ~8 orders of
        // magnitude below p, so the sum cannot wrap either way; pinning the adversarial bound
        // here means a future parameter change is judged against the right worst case.
        assert_eq!(1024u128 * 6144 * 6144, 38_654_705_664);
        assert!(1024u128 * 6144 * 6144 < 1 << 36);
        assert!(1024u128 * q * q < 1 << 38);
        assert!(1024u128 * q * q < P);
        assert!((FALCON_SIG_L2_BOUND as u128) < 1 << 26);
        // Twiddle sanity is asserted inside twiddle_tables(); force it here too.
        let _ = twiddle_tables();
    }

    // ---- native algorithm validation --------------------------------------------------------

    /// The circuit's NTT ALGORITHM (native u64 mirror, same tables/loops) matches both the
    /// schoolbook negacyclic product and the vendored exact FFT the native verifier uses —
    /// double oracle. This is the pre-trust step for the in-circuit NTT.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn ntt_algorithm_matches_schoolbook_and_vendor() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..3 {
            let a = random_poly(&mut state);
            let b = random_poly(&mut state);
            let via_ntt = ntt_product_native(&a, &b);
            let via_schoolbook = schoolbook_negacyclic(&a, &b);
            assert_eq!(via_ntt, via_schoolbook, "NTT mirror vs schoolbook");

            let pa = Polynomial::new(a.iter().map(|&v| FalconFelt::new(v as i16)).collect());
            let pb = Polynomial::new(b.iter().map(|&v| FalconFelt::new(v as i16)).collect());
            let via_vendor: Vec<u64> = (pa.fft().hadamard_mul(&pb.fft()))
                .ifft()
                .coefficients
                .iter()
                .map(|f| f.value() as u64)
                .collect();
            assert_eq!(via_ntt, via_vendor, "NTT mirror vs vendored FFT");
        }
    }

    // ---- circuit <-> native mirror tests (O-2) ----------------------------------------------

    /// SECURITY (O-2): the in-circuit polynomial product s2*h (forward NTTs, pointwise,
    /// inverse) equals the native product on random inputs — exposed coefficient-for-
    /// coefficient as public inputs and compared against the schoolbook oracle.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn circuit_ntt_product_matches_native() {
        let (psi_rev, psi_inv_rev, n_inv) = twiddle_tables();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let a: Vec<Target> = (0..N).map(|_| builder.add_virtual_target()).collect();
        let b: Vec<Target> = (0..N).map(|_| builder.add_virtual_target()).collect();
        for &t in a.iter().chain(b.iter()) {
            assert_canonical_coeff(&mut builder, t);
        }
        let fa = ntt_forward(&mut builder, &psi_rev, &a);
        let fb = ntt_forward(&mut builder, &psi_rev, &b);
        let pw_prod = pointwise_mul(&mut builder, &fa, &fb);
        let prod = ntt_inverse(&mut builder, &psi_inv_rev, n_inv, &pw_prod);
        builder.register_public_inputs(&prod);
        let data = builder.build::<C>();

        let mut state = 0xdead_beef_cafe_f00du64;
        let av = random_poly(&mut state);
        let bv = random_poly(&mut state);
        let mut pw = PartialWitness::new();
        for (&t, &v) in a.iter().zip(av.iter()).chain(b.iter().zip(bv.iter())) {
            pw.set_target(t, F::from_canonical_u64(v)).unwrap();
        }
        let proof = data.prove(pw).unwrap();
        data.verify(proof.clone()).unwrap();
        let circuit_prod: Vec<u64> = proof
            .public_inputs
            .iter()
            .map(|f| f.to_canonical_u64())
            .collect();
        assert_eq!(
            circuit_prod,
            schoolbook_negacyclic(&av, &bv),
            "in-circuit NTT product must equal the native negacyclic product"
        );
    }

    /// SECURITY (O-2 / TM-C1): the in-circuit H2P on the PINNED Phase-0 KAT inputs produces
    /// the same 512 coefficients as the native `hash_to_point_poseidon` — all 512 compared,
    /// plus the pinned prefix/suffix/fold anchors from
    /// `review_hardening_tests::h2p_and_pk_digest_pinned_vectors`, so a drift in the sponge
    /// layout / capacity domain / salt packing / limb order / reduction on EITHER side breaks
    /// this test rather than silently forking native from circuit.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn circuit_h2p_matches_native_pinned_vectors() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let salt_t: [Target; 8] = core::array::from_fn(|_| builder.add_virtual_target());
        let digest_t = Bytes32Target::new(&mut builder, true);
        let c = h2p_circuit(&mut builder, &salt_t, &digest_t);
        builder.register_public_inputs(&c);
        let data = builder.build::<C>();

        // The pinned KAT inputs (Phase-0 anchor).
        let salt: [u8; 40] = core::array::from_fn(|i| i as u8);
        let msg = Bytes32::from_u32_slice(&[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();

        let mut pw = PartialWitness::new();
        for (&t, &v) in salt_t.iter().zip(salt_to_elements(&salt).iter()) {
            pw.set_target(t, F::from_canonical_u64(v)).unwrap();
        }
        for (t, limb) in digest_t.to_vec().iter().zip(msg.to_u32_vec().iter()) {
            pw.set_target(*t, F::from_canonical_u32(*limb)).unwrap();
        }
        let proof = data.prove(pw).unwrap();
        data.verify(proof.clone()).unwrap();

        let circuit_c: Vec<u64> = proof
            .public_inputs
            .iter()
            .map(|f| f.to_canonical_u64())
            .collect();
        let native_c: Vec<u64> = hash_to_point_poseidon(msg, &Nonce::from_bytes(salt))
            .coefficients
            .iter()
            .map(|f| f.value() as u64)
            .collect();
        assert_eq!(circuit_c, native_c, "in-circuit H2P must equal native H2P");
        // Pinned anchors (must match the Phase-0 review KAT exactly).
        assert_eq!(
            &circuit_c[..8],
            &[12069, 12087, 3183, 532, 2490, 10450, 11601, 9973]
        );
        assert_eq!(&circuit_c[508..], &[2920, 9587, 9507, 7323]);
        let fold = circuit_c
            .iter()
            .fold(0u64, |a, &v| a.wrapping_mul(31).wrapping_add(v));
        assert_eq!(fold, 0x696f_2d35_6e5f_bbeb);
    }

    /// SECURITY (O-2 / TM-C5 item 5): the in-circuit `Poseidon(IMFK || encode(h))` digest
    /// equals the native `falcon_pk_digest` — checked against the pinned Phase-0 pk_g of
    /// `from_seed([42; 32])` AND against a second key, via public inputs.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn circuit_pk_digest_matches_native_pinned_vector() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let h_t: Vec<Target> = (0..N).map(|_| builder.add_virtual_target()).collect();
        for &t in h_t.iter() {
            assert_canonical_coeff(&mut builder, t);
        }
        let pk = pk_digest_circuit(&mut builder, &h_t);
        builder.register_public_inputs(&pk.to_vec());
        let data = builder.build::<C>();

        for (keys, pinned_hex) in [
            (
                FalconKeys::from_seed([42u8; 32]),
                Some("0x90eed9636e2a86f4043c297a284a6cc24666678312c6bd8a62fc56dc241decf0"),
            ),
            (FalconKeys::from_seed([43u8; 32]), None),
        ] {
            let h = keys.pk_coefficients();
            let mut pw = PartialWitness::new();
            for (&t, &v) in h_t.iter().zip(h.iter()) {
                pw.set_target(t, F::from_canonical_u64(v as u64)).unwrap();
            }
            let proof = data.prove(pw).unwrap();
            data.verify(proof.clone()).unwrap();
            let limbs: Vec<u32> = proof
                .public_inputs
                .iter()
                .map(|f| f.to_canonical_u64() as u32)
                .collect();
            let circuit_pk = Bytes32::from_u32_slice(&limbs).unwrap();
            assert_eq!(
                circuit_pk,
                keys.pk_g(),
                "circuit pk digest must equal native"
            );
            if let Some(hex) = pinned_hex {
                assert_eq!(format!("{circuit_pk}"), hex, "pinned Phase-0 pk_g anchor");
            }
        }
    }

    /// SECURITY (O-2 randomized equivalence, completeness direction): honestly generated
    /// native signatures — several keys and messages — satisfy the full gadget. Combined with
    /// the KAT mirrors above, this pins the circuit's accept-set to the native verifier's on
    /// real signature distributions (an NTT/H2P/norm mismatch would fail here).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn honest_signatures_prove_across_seeds_and_messages() {
        // Two messages under the shared key.
        for tag in [0x11u8, 0x22] {
            assert_accepted(
                &N1_CIRCUIT,
                honest_witness(tag),
                &format!("honest signature (shared key, tag {tag:#x}) must prove"),
            );
        }
        // A different key.
        let other = FalconKeys::from_seed([0xa5u8; 32]);
        let other_h = other.pk_coefficients();
        let digest = sample_digest(0x33);
        let sig = other.sign(digest);
        assert!(super::super::verify_with_pk_g(
            other.pk_g(),
            &other_h,
            digest,
            &sig
        ));
        assert_accepted(
            &N1_CIRCUIT,
            FalconSigGadgetWitness::for_signature(&other_h, digest, &sig),
            "honest signature (second key) must prove",
        );
    }

    // ---- adversarial suite (O-5) ------------------------------------------------------------

    /// SECURITY (TM-C5 item 3, in-circuit boundary): the FULL gadget accepts a crafted
    /// instance with `||(s1, s2)||^2 = beta^2` exactly and rejects `beta^2 + 1`.
    ///
    /// Construction (witness-level, as sanctioned for this layer): with `s2 = 1` (the constant
    /// polynomial, norm 1) the verification equation gives `s1 = c - h`, so choosing
    /// `h = c - s1_target mod q` for any desired `s1_target` (and setting `pk_g` to the digest
    /// of that h — the key is attacker-chosen, which is exactly the point: even an
    /// attacker-chosen key cannot stretch the norm bound) makes the circuit compute
    /// `s1 = s1_target`. `s1_target = [5833, 104, 4, 2, 0, ...]` has norm beta^2 - 1
    /// (5833^2 + 104^2 + 4^2 + 2^2 = 34_034_725), total beta^2 with s2; appending one more
    /// `1` coefficient gives beta^2 + 1.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn norm_boundary_beta_sq_accepts_and_plus_one_rejects_in_circuit() {
        let digest = sample_digest(0x44);
        let salt = [3u8; 40];
        let c: Vec<u64> = hash_to_point_poseidon(digest, &Nonce::from_bytes(salt))
            .coefficients
            .iter()
            .map(|f| f.value() as u64)
            .collect();

        let build = |extra_one: bool| -> FalconSigGadgetWitness {
            let mut s1_target = vec![0u64; N];
            s1_target[0] = 5833;
            s1_target[1] = 104;
            s1_target[2] = 4;
            s1_target[3] = 2;
            if extra_one {
                s1_target[4] = 1;
            }
            let h: Vec<u64> = c
                .iter()
                .zip(s1_target.iter())
                .map(|(&ci, &si)| (ci + Q - si) % Q)
                .collect();
            let h_u16: [u16; FALCON_N] = core::array::from_fn(|i| h[i] as u16);
            let mut s2 = vec![0u64; N];
            s2[0] = 1;
            FalconSigGadgetWitness {
                pk_g: falcon_pk_digest(&h_u16),
                message_digest: digest,
                salt_elements: salt_to_elements(&salt),
                h,
                s2,
            }
        };

        // Sanity: the native predicate agrees at both sides of the boundary.
        {
            let s2_poly = Polynomial::new(
                (0..N)
                    .map(|i| FalconFelt::new(if i == 0 { 1 } else { 0 }))
                    .collect(),
            );
            for (extra, expect) in [(false, true), (true, false)] {
                let w = build(extra);
                let h_poly =
                    Polynomial::new(w.h.iter().map(|&v| FalconFelt::new(v as i16)).collect());
                let c_poly = hash_to_point_poseidon(digest, &Nonce::from_bytes(salt));
                let norm = super::super::recomputed_norm_squared(&c_poly, &s2_poly, &h_poly);
                assert_eq!(super::super::norm_within_bound(norm), expect);
                assert_eq!(norm, FALCON_SIG_L2_BOUND + u64::from(extra));
            }
        }

        assert_accepted(
            &N1_CIRCUIT,
            build(false),
            "norm exactly beta^2 must be ACCEPTED by the circuit (threat model boundary)",
        );
        assert_rejected(
            &N1_CIRCUIT,
            build(true),
            "norm beta^2 + 1 must be REJECTED by the circuit",
        );
    }

    /// SECURITY (TM-C5 item 1): non-canonical s2 encodings must be rejected — a coefficient
    /// equal to q, a mod-q-EQUIVALENT non-canonical residue (q + 1 == 1 mod q, the
    /// two-encodings attack on the norm/product binding), and the centered-representation
    /// confusion of encoding -1 as the FIELD negative (p - 1) instead of the canonical
    /// residue q - 1.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn non_canonical_s2_rejected() {
        for (value, label) in [
            (Q, "s2[0] = q"),
            (
                Q + 1,
                "s2[0] = q + 1 (mod-q equivalent of 1, second encoding)",
            ),
            (
                0xffff_ffff_0000_0000u64,
                "s2[0] = p - 1 (field -1, centered confusion)",
            ),
        ] {
            let mut w = honest_witness(0x50);
            w.s2[0] = value;
            assert_rejected(&N1_CIRCUIT, w, &format!("{label} must be rejected"));
        }
        // Control: the canonical encoding of -1 (q - 1) in an otherwise-honest signature is a
        // VALUE change, so it must also reject (verification equation), but distinguish: it
        // passes the range gate and fails on the algebra — still rejected end to end.
        let mut w = honest_witness(0x50);
        w.s2[0] = Q - 1;
        // (If the honest s2[0] happened to be q-1 already, shift by one instead.)
        if w.s2[0] == honest_witness(0x50).s2[0] {
            w.s2[0] = 1;
        }
        assert_rejected(
            &N1_CIRCUIT,
            w,
            "tampered (canonical) s2 coefficient must be rejected",
        );
    }

    /// SECURITY (TM-C5 item 5): non-canonical h must be rejected even when pk_g is set to the
    /// matching forged digest — the sharp case is `h[0] + q` (mod-q equivalent key, would pass
    /// the algebra and norm identically; only the canonicity gate stops a second pk_g digest
    /// opening for the same key).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn non_canonical_h_rejected() {
        let mut w = honest_witness(0x51);
        w.h[0] += Q;
        // Forge the matching digest over the non-canonical packing (native mirror of the
        // packed Horner sum, computed here directly since falcon_pk_digest asserts canonicity).
        let mut inputs = vec![DOMAIN_FALCON_PK as u64];
        for chunk in w.h.chunks_exact(4) {
            inputs.push(chunk[0] + (chunk[1] << 14) + (chunk[2] << 28) + (chunk[3] << 42));
        }
        w.pk_g = crate::utils::poseidon_hash_out::PoseidonHashOut::hash_inputs_u64(&inputs).into();
        assert_rejected(
            &N1_CIRCUIT,
            w,
            "h[0] + q with a matching forged pk digest must be rejected by the canonicity gate",
        );

        // Plain out-of-range coefficient with the HONEST pk digest.
        let mut w = honest_witness(0x51);
        w.h[100] = Q;
        assert_rejected(&N1_CIRCUIT, w, "h coefficient == q must be rejected");
    }

    /// SECURITY (O-5): a valid signature with one salt element changed must be rejected — the
    /// tampered salt passes the 40-bit range gate, so rejection comes from the H2P/norm
    /// algebra (the salt is bound into c).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn tampered_salt_rejected() {
        let mut w = honest_witness(0x52);
        w.salt_elements[3] ^= 1; // still < 2^40
        assert_rejected(&N1_CIRCUIT, w, "tampered salt element must be rejected");
    }

    /// SECURITY (O-5, review §4 in-circuit analog): s2 = 0 with otherwise-honest witness data
    /// must be rejected (s1 = c alone violates the norm bound for any real c).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn zero_s2_rejected() {
        let mut w = honest_witness(0x53);
        w.s2 = vec![0u64; N];
        assert_rejected(&N1_CIRCUIT, w, "s2 = 0 must be rejected");
    }

    /// SECURITY (TM-C7 binding): a valid signature presented under ANOTHER member's pk_g must
    /// be rejected (the in-gadget pk connection fires), and an attacker's own (h, sig) pair
    /// presented under the victim's pk_g must be rejected too.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn wrong_pk_g_rejected() {
        let other = FalconKeys::from_seed([0x99u8; 32]);
        let mut w = honest_witness(0x54);
        w.pk_g = other.pk_g();
        assert_rejected(
            &N1_CIRCUIT,
            w,
            "valid signature under the wrong claimed pk_g must be rejected",
        );

        // Attacker signs with their own key but claims the victim's identity.
        let digest = sample_digest(0x54);
        let sig = other.sign(digest);
        let mut w = FalconSigGadgetWitness::for_signature(&other.pk_coefficients(), digest, &sig);
        w.pk_g = KEYS.pk_g();
        assert_rejected(
            &N1_CIRCUIT,
            w,
            "attacker key + victim pk_g must be rejected",
        );
    }

    /// SECURITY (TM-C5 item 4 / TM-C6): a valid signature witnessed against a DIFFERENT
    /// message digest must be rejected (in consumers the digest is recomputed and connected;
    /// this proves the gadget itself binds the digest through H2P).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn wrong_message_digest_rejected() {
        let digest = sample_digest(0x55);
        let sig = KEYS.sign(digest);
        let mut w = FalconSigGadgetWitness::for_signature(&KEYS_H, digest, &sig);
        w.message_digest = sample_digest(0x56);
        assert_rejected(&N1_CIRCUIT, w, "wrong message digest must be rejected");
    }

    /// SECURITY (O-5, the classic hand-rolled-reduction soundness hole): quotient-witness
    /// cheating in the mod-q decomposition must be caught by the range checks. Drives
    /// `constrain_mod_q_decomposition` directly with witnessed (t, k, r):
    /// - honest (k, r) proves;
    /// - `(k - 1, r + q)` — the congruence still holds over the integers; ONLY the `r < q` double
    ///   range check rejects it;
    /// - `(k + 1, r - q)` — r wraps to ~p, caught by the 14-bit check;
    /// - oversized k (wrap-around attempt) — caught by the k range check / booleanity.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn mod_q_quotient_cheating_rejected() {
        // SECURITY (review INFO-3): cover EVERY quotient width the gadget instantiates —
        // 1 (GS add, s1 subtraction), 14 (CT butterflies, pointwise, scaling), 15 (GS
        // sub-times-twiddle) and 32 (the H2P sponge-output reduction, the widest in the
        // gadget). The primitive is generic in k_bits and the uniqueness argument is uniform,
        // but "uniform argument" is not "tested argument".
        for k_bits in [1usize, 14, 15, 32] {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let t = builder.add_virtual_target();
            let k = builder.add_virtual_target();
            let r = builder.add_virtual_target();
            constrain_mod_q_decomposition(&mut builder, t, k, r, k_bits);
            let data = builder.build::<C>();

            let (tv, kv, rv) = if k_bits == 1 {
                (Q + 5, 1u64, 5u64) // t = q + 5
            } else {
                (3 * Q + 5, 3u64, 5u64) // t = 3q + 5
            };

            let run = |k_val: F, r_val: F| {
                let mut pw = PartialWitness::new();
                pw.set_target(t, F::from_canonical_u64(tv)).unwrap();
                pw.set_target(k, k_val).unwrap();
                pw.set_target(r, r_val).unwrap();
                let result = catch_unwind(AssertUnwindSafe(|| data.prove(pw)));
                match result {
                    Err(_) => Err(anyhow::anyhow!("prove panicked")),
                    Ok(Err(e)) => Err(e),
                    Ok(Ok(proof)) => data.verify(proof),
                }
            };

            // Honest decomposition proves.
            run(F::from_canonical_u64(kv), F::from_canonical_u64(rv))
                .unwrap_or_else(|e| panic!("honest (k, r) must prove (k_bits {k_bits}): {e}"));
            // (k - 1, r + q): integer identity intact — the r < q checks must reject.
            assert!(
                run(F::from_canonical_u64(kv - 1), F::from_canonical_u64(rv + Q)).is_err(),
                "(k-1, r+q) must be rejected (k_bits {k_bits})"
            );
            // (k + 1, r - q): r becomes a huge field value.
            assert!(
                run(
                    F::from_canonical_u64(kv + 1),
                    F::from_canonical_u64(rv) - F::from_canonical_u64(Q)
                )
                .is_err(),
                "(k+1, r-q) must be rejected (k_bits {k_bits})"
            );
            // Oversized k trying to wrap mod p: k' = 2^k_bits with r' = t - k'*q (mod p).
            let k_over = F::from_canonical_u64(1 << k_bits);
            let r_over = F::from_canonical_u64(tv) - k_over * F::from_canonical_u64(Q);
            assert!(
                run(k_over, r_over).is_err(),
                "oversized quotient must be rejected (k_bits {k_bits})"
            );
        }
    }

    /// SECURITY (review INFO-2): the centering bit in [`centered_square`] is the ONE
    /// soundness-critical value in this gadget that a prover supplies with no constraint
    /// pinning it to a particular choice — `assert_bool` fixes only that it is 0 or 1. The
    /// whole norm bound therefore rests on a MONOTONICITY argument: a lying bit can only make
    /// the computed square LARGER, never smaller, so `computed <= beta^2` implies
    /// `true <= beta^2`. That argument had no empirical probe; this test is it.
    ///
    /// Because the shipped bit is generator-driven (overriding it is a witness-set conflict),
    /// the constraint layer is exposed directly here — the same idiom the quotient-cheat test
    /// uses. What is proven:
    ///   1. the achievable set for a canonical `v` is EXACTLY `{v^2, (q-v)^2}` (no third choice),
    ///      and its minimum equals the vendored `balanced_value(v)^2` that the native verifier
    ///      squares — so the honest value is the smallest a prover can reach;
    ///   2. a non-boolean bit is rejected outright;
    ///   3. flipping the bit on a real coefficient PROVES but strictly INCREASES the exposed square
    ///      — the lie inflates, exactly as the argument claims.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn centering_bit_lie_can_only_inflate_the_norm() {
        use crate::falcon_sig::vendor::FalconFelt;

        // (1) The achievable set's minimum IS the native centered square, for every residue.
        for v in 0..Q {
            let honest = FalconFelt::new(v as i16).balanced_value() as i64;
            let honest_sq = (honest * honest) as u64;
            let b0 = v * v;
            let b1 = (Q - v) * (Q - v);
            assert_eq!(
                honest_sq,
                b0.min(b1),
                "native centered square must be the MINIMUM of the two reachable values (v={v})"
            );
        }

        // Constraint layer of `centered_square`, with `b` settable instead of generated.
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let v = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        builder.assert_bool(BoolTarget::new_unsafe(b));
        let bq = builder.mul_const(F::from_canonical_u64(Q), b);
        let centered = builder.sub(v, bq);
        let sq = builder.mul(centered, centered);
        builder.register_public_input(sq);
        let data = builder.build::<C>();

        let run = |v_val: u64, b_val: F| {
            let mut pw = PartialWitness::new();
            pw.set_target(v, F::from_canonical_u64(v_val)).unwrap();
            pw.set_target(b, b_val).unwrap();
            let result = catch_unwind(AssertUnwindSafe(|| data.prove(pw)));
            match result {
                Err(_) => Err(anyhow::anyhow!("prove panicked")),
                Ok(Err(e)) => Err(e),
                Ok(Ok(proof)) => {
                    let exposed = proof.public_inputs[0].to_canonical_u64();
                    data.verify(proof).map(|()| exposed)
                }
            }
        };

        // (2) A non-boolean bit is rejected — the prover cannot invent a third scaling.
        assert!(
            run(1234, F::from_canonical_u64(2)).is_err(),
            "non-boolean centering bit must be rejected"
        );
        assert!(
            run(1234, F::from_canonical_u64(Q)).is_err(),
            "non-boolean centering bit must be rejected"
        );

        // (3) On real coefficients, both bits PROVE (the bit is unconstrained by design) but the
        //     dishonest one is strictly larger — so a prover can never use it to sneak a
        //     too-large norm under the bound, only to inflate its own.
        for v_val in [1u64, 5_000, 6_143, 6_144, 6_145, 9_000, Q - 1] {
            let honest_bit = u64::from(v_val > Q / 2);
            let honest = run(v_val, F::from_canonical_u64(honest_bit))
                .unwrap_or_else(|e| panic!("honest centering must prove (v={v_val}): {e}"));
            let lying = run(v_val, F::from_canonical_u64(1 - honest_bit))
                .unwrap_or_else(|e| panic!("the lie is unconstrained and must also prove: {e}"));
            let native = FalconFelt::new(v_val as i16).balanced_value() as i64;
            assert_eq!(honest, (native * native) as u64, "honest == native square");
            assert!(
                lying > honest,
                "a lying centering bit must INFLATE the square, never shrink it \
                 (v={v_val}, honest={honest}, lying={lying})"
            );
        }
        // v = 0 is the adversarial extreme the bound ledger pins: the lie yields q^2, the
        // largest square any single coefficient can contribute.
        let zero_honest = run(0, F::ZERO).unwrap();
        let zero_lying = run(0, F::ONE).unwrap();
        assert_eq!(zero_honest, 0);
        assert_eq!(
            zero_lying,
            Q * Q,
            "v=0 with a lying bit reaches exactly q^2"
        );
    }

    // ---- measurement harness (Phase-1 deliverable) ------------------------------------------

    /// Phase-1 measurement (plan item: "measure gates + proving time — the number the owner
    /// asked for"): builds the standalone harness for N in {1, 3, 16}, proves with honest
    /// signatures, verifies, and prints a reproducible table (run with --nocapture).
    /// Signatures for N=16 come from 4 keys x 4 messages (mixed keys, the close-circuit
    /// shape).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn falcon_sig_circuit_measure_1_3_16() {
        use std::time::Instant;

        let keys: Vec<FalconKeys> = [[7u8; 32], [8u8; 32], [9u8; 32], [10u8; 32]]
            .into_iter()
            .map(FalconKeys::from_seed)
            .collect();
        let hs: Vec<[u16; FALCON_N]> = keys.iter().map(|k| k.pk_coefficients()).collect();

        let mut rows = Vec::new();
        for n_sigs in [1usize, 3, 16] {
            let t0 = Instant::now();
            let circuit = FalconSigCircuit::<F, C, D>::new(n_sigs);
            let build_s = t0.elapsed().as_secs_f64();

            let witnesses: Vec<FalconSigGadgetWitness> = (0..n_sigs)
                .map(|i| {
                    let key = &keys[i % keys.len()];
                    let digest = sample_digest(0x70 + i as u8);
                    let sig = key.sign(digest);
                    FalconSigGadgetWitness::for_signature(&hs[i % keys.len()], digest, &sig)
                })
                .collect();

            let t1 = Instant::now();
            let proof = circuit.prove(&witnesses).expect("honest batch must prove");
            let prove_s = t1.elapsed().as_secs_f64();

            let t2 = Instant::now();
            circuit.data.verify(proof).expect("proof must verify");
            let verify_ms = t2.elapsed().as_secs_f64() * 1e3;

            rows.push(format!(
                "| {n_sigs:>2} | {gates:>7} | {degree:>11} | {build_s:>7.2} | {prove_s:>7.2} | {verify_ms:>9.2} |",
                gates = circuit.num_gates_before_padding,
                degree = circuit.data.common.degree_bits(),
            ));
        }
        println!("falcon_sig gadget measurement (standard_recursion_config, release):");
        println!("|  N |   gates | degree_bits | build_s | prove_s | verify_ms |");
        for row in rows {
            println!("{row}");
        }
    }
}
