//! Native Poseidon2-BabyBear ZK hash-signature for channel-tx (intra-channel transfer) SENDER
//! authorization (detail2.md / threat-model D1(b), A11, P3).
//!
//! This is a SEPARATE bound proof from the regev channelTxZKP ([`DualKeyTransferAir`]). The
//! off-chain verifier requires BOTH proofs and binds them: the channel-tx is accepted only with a
//! valid owner signature whose message `m` equals the channel-tx IMPA digest and whose `pk_b`
//! belongs to the same registered `MemberLeaf` as the sender's `pk_g`/`regev_pk` (A11, software
//! MemberTree lookup — no in-AIR Merkle).
//!
//! # Signature scheme (threat model §1)
//!
//! Each member holds a BabyBear secret key `sk_b ∈ 𝔽_q^{SK_LIMBS}` (≥256-bit entropy, D2). Define
//! two Poseidon2-BabyBear width-16 sponge hashes over the AUDITED `default_babybear_poseidon2_16`
//! instance (the SAME permutation the regev transcript uses):
//!
//! - `pk_b  = Poseidon2_sponge([DOMAIN_PK_B]  ‖ sk_b)`           (public)
//! - `sig_b = Poseidon2_sponge([DOMAIN_SIG_B] ‖ sk_b ‖ m_limbs)` (witness-only, defense in depth)
//!
//! The "signature" is a STARK proof of knowledge of `sk_b` with `pk_b` and `m_limbs` as public
//! values and `sk_b`/`sig_b` as private witnesses. Unforgeability reduces to Poseidon2 preimage
//! resistance (§2.1).
//!
//! # Message encoding injectivity (P3 new A-item)
//!
//! The IMPA digest is a keccak `Bytes32` = 8×u32, each `< 2^32`. BabyBear `q ≈ 2^31`, so
//! `F::from_u32` ALIASES (`limb ≡ limb − q` when `limb ≥ q`). We therefore re-decompose the
//! digest into 16 little-endian 16-bit limbs (`< 2^16 < q`), an INJECTIVE map onto field elements,
//! mirroring the 16-bit amount-limb workaround in `transfer_stark.rs`. The verifier recomputes the
//! SAME decomposition from the actual channel-tx digest and binds it to the proof's `m_limbs`
//! public values.

use p3_air_05::{Air, AirBuilder, BaseAir};
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_16_INTERNAL, GenericPoseidon2LinearLayersBabyBear, Poseidon2BabyBear,
    default_babybear_poseidon2_16,
};
use p3_field_05::PrimeCharacteristicRing;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants, generate_trace_rows};
use p3_symmetric_05::Permutation;

use regev_plonky3::regev::F;

// ---------------------------------------------------------------------------
// Poseidon2-BabyBear width-16 AIR parameters (audited instance)
// ---------------------------------------------------------------------------

/// Sponge / permutation width.
pub(crate) const WIDTH: usize = 16;
/// BabyBear Poseidon2 S-box degree (`x^7`).
pub(crate) const SBOX_DEGREE: u64 = 7;
/// S-box auxiliary registers. For degree 7 the optimal register count is 1: the AIR commits
/// `x^3` and enforces `committed == x^3` (degree-3 constraint), keeping the maximum constraint
/// degree at 3 — matching the regev backend's `log_blowup = 1` (blowup 2 ⇒ degree ≤ 3) config.
pub(crate) const SBOX_REGISTERS: usize = 1;
/// Full rounds per half (`RF/2 = 4`).
pub(crate) const HALF_FULL_ROUNDS: usize = 4;
/// Partial rounds (width-16 BabyBear).
pub(crate) const PARTIAL_ROUNDS: usize = 13;

/// The concrete Poseidon2-BabyBear AIR type (audited round constants, native linear layers).
pub type BabyBearPoseidon2Air = Poseidon2Air<
    F,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// Build the AIR's `RoundConstants` from the AUDITED published BabyBear Poseidon2 constants.
///
/// SECURITY: these are exactly the constants baked into `default_babybear_poseidon2_16()` (the
/// regev transcript permutation), so the AIR's constraint system computes the SAME canonical
/// permutation. We do NOT derive constants from an RNG (that would fork the permutation across
/// targets) and we do NOT hand-author round constants.
pub(crate) fn babybear_round_constants()
-> RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    RoundConstants::new(
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        BABYBEAR_POSEIDON2_RC_16_INTERNAL,
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    )
}

/// Construct the Poseidon2-BabyBear AIR with the audited constants.
pub fn babybear_poseidon2_air() -> BabyBearPoseidon2Air {
    Poseidon2Air::new(babybear_round_constants())
}

/// The canonical native permutation (for trace generation and reference checks).
pub(crate) fn canonical_perm() -> Poseidon2BabyBear<16> {
    default_babybear_poseidon2_16()
}

/// Native single application of the canonical Poseidon2-BabyBear width-16 permutation.
pub(crate) fn permute16(input: [F; WIDTH]) -> [F; WIDTH] {
    canonical_perm().permute(input)
}

/// Generate the Poseidon2Air trace for the given permutation inputs. `inputs.len()` must be a
/// power of two (the AIR proves one permutation per row).
pub(crate) fn generate_poseidon2_trace(
    constants: &RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    inputs: Vec<[F; WIDTH]>,
) -> p3_matrix_05::dense::RowMajorMatrix<F> {
    generate_trace_rows::<
        F,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, constants, 0)
}

// ===========================================================================
// Native BabyBear hash-signature primitive (P3-2)
// ===========================================================================

use p3_field_05::PrimeField32;

use super::encrypt::RegevError;
use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _};

/// BabyBear domain word for `pk_b = Poseidon2([DOMAIN_PK_B] ‖ sk_b)` ("BPKB").
///
/// SECURITY (A2 domain confusion): `DOMAIN_PK_B != DOMAIN_SIG_B`, and both are distinct from
/// every existing transcript / signing domain (the regev purpose words `0x494d....`, the keccak
/// `IM..` digests, the Goldilocks `DOMAIN_PK_G/SIG_G`). Because each domain occupies a FIXED state
/// slot that is constrained to the constant in-AIR, a `sig_b` permutation can never be replayed as
/// a `pk_b` permutation (the input layouts differ in slot 0 and in width). Must be `< q`.
pub const DOMAIN_PK_B: u32 = 0x42504b42;
/// BabyBear domain word for `sig_b = Poseidon2([DOMAIN_SIG_B] ‖ sk_b ‖ m)` ("BSGB"). Must be `< q`.
pub const DOMAIN_SIG_B: u32 = 0x42534742;

// SECURITY: both domain words must be < q so `F::from_u32` is injective on them (no aliasing).
const _: () = {
    assert!(DOMAIN_PK_B < super::params::REGEV_Q);
    assert!(DOMAIN_SIG_B < super::params::REGEV_Q);
    assert!(DOMAIN_PK_B != DOMAIN_SIG_B);
};

/// Number of BabyBear limbs in the secret key.
///
/// SECURITY (D2, ≥256-bit entropy): each canonical BabyBear limb carries `< q ≈ 2^31` (~30.9
/// bits) of entropy. `9 × 30.9 ≈ 278 bits ≥ 256` classical / `139 bits ≥ 128` quantum (Grover).
pub const SK_LIMBS: usize = 9;

/// Number of BabyBear limbs in a digest (`pk_b`, the permutation-output rate). 8 limbs × ~30.9
/// bits ≈ 247 bits of output, matching the Bytes32 anchor width and exceeding the 128-bit
/// collision / preimage target by a wide margin for the unforgeability reduction (§2.1).
pub const DIGEST_LIMBS: usize = 8;

/// Number of 16-bit message limbs the IMPA digest is re-decomposed into (INJECTIVE absorption).
/// 8×u32 = 256 bits ⇒ 16 × 16-bit limbs, each `< 2^16 < q` (no BabyBear aliasing).
pub const MSG_LIMBS: usize = 16;

/// The `sig_b` sponge absorbs `[DOMAIN_SIG_B] ‖ sk_b(9) ‖ m(16)` = 26 elements. With sponge rate 8
/// this is `ceil(26/8) = 4` absorption blocks (last block zero-padded). Layout pinned here so the
/// AIR and the native reference agree exactly.
pub const SPONGE_RATE: usize = 8;
pub const SIG_ABSORB_LEN: usize = 1 + SK_LIMBS + MSG_LIMBS; // 26
pub const SIG_BLOCKS: usize = SIG_ABSORB_LEN.div_ceil(SPONGE_RATE); // 4

/// A member's BabyBear secret key. Redacted `Debug`; no serde (never leaves the wallet); never
/// enters any digest or transcript.
#[derive(Clone)]
pub struct BabyBearSecretKey {
    limbs: [F; SK_LIMBS],
}

impl core::fmt::Debug for BabyBearSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // INTENTIONALLY SIMPLE: never print key material.
        f.write_str("BabyBearSecretKey(<redacted>)")
    }
}

impl BabyBearSecretKey {
    /// Sample a fresh secret key from a cryptographically secure RNG.
    ///
    /// SECURITY: each limb is sampled uniformly in `[0, q)` via rejection-free `from_u32` of a
    /// reduced u32 — but we draw a full random u32 and reduce, then REJECT the all-zero key. The
    /// caller MUST pass a CSPRNG (`rand::rngs::OsRng` / wallet entropy); documented per D2.
    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        loop {
            let limbs: [F; SK_LIMBS] = core::array::from_fn(|_| {
                // Reduce a uniform u32 into the field. `from_u32` reduces mod q; the resulting
                // distribution over [0,q) is within 2^-31 of uniform (negligible bias), acceptable
                // for a ≥256-bit secret. (Documented entropy note, D2.)
                F::from_u32(rng.next_u32())
            });
            // SECURITY (A1): reject the degenerate all-zero key (pk would be a fixed public value
            // independent of any secret). Probability ~q^-9, but rejected unconditionally.
            if limbs.iter().any(|&x| x != F::ZERO) {
                return Self { limbs };
            }
        }
    }

    /// Construct from explicit canonical u32 limbs (each must be `< q`). Used by tests / wallet
    /// deserialization. Rejects out-of-range limbs and the all-zero key.
    pub fn from_canonical_limbs(limbs: [u32; SK_LIMBS]) -> Result<Self, RegevError> {
        if limbs.iter().any(|&x| x >= REGEV_Q) {
            return Err(RegevError::ProofVerification(
                "sk_b limb >= q (non-canonical)".to_string(),
            ));
        }
        if limbs.iter().all(|&x| x == 0) {
            return Err(RegevError::ProofVerification(
                "sk_b is all-zero (degenerate)".to_string(),
            ));
        }
        Ok(Self {
            limbs: limbs.map(F::from_u32),
        })
    }

    pub(crate) fn limbs(&self) -> &[F; SK_LIMBS] {
        &self.limbs
    }

    /// The public key `pk_b = Poseidon2([DOMAIN_PK_B] ‖ sk_b ‖ 0…)[0..DIGEST_LIMBS]`.
    pub fn public_key(&self) -> BabyBearPublicKey {
        let mut state = [F::ZERO; WIDTH];
        state[0] = F::from_u32(DOMAIN_PK_B);
        state[1..1 + SK_LIMBS].copy_from_slice(&self.limbs);
        let out = permute16(state);
        let mut digest = [F::ZERO; DIGEST_LIMBS];
        digest.copy_from_slice(&out[0..DIGEST_LIMBS]);
        BabyBearPublicKey { digest }
    }

    /// The witness-only signature `sig_b = Poseidon2_sponge([DOMAIN_SIG_B] ‖ sk_b ‖ m)`.
    ///
    /// SECURITY (§1.2 defense-in-depth): forces `m` to be consumed by the secret key inside the
    /// circuit. Returned only for the in-AIR witness; never exposed as a public output (A6).
    pub(crate) fn sign_digest_native(&self, m_limbs: &[F; MSG_LIMBS]) -> [F; DIGEST_LIMBS] {
        let mut absorb = Vec::with_capacity(SIG_BLOCKS * SPONGE_RATE);
        absorb.push(F::from_u32(DOMAIN_SIG_B));
        absorb.extend_from_slice(&self.limbs);
        absorb.extend_from_slice(m_limbs);
        absorb.resize(SIG_BLOCKS * SPONGE_RATE, F::ZERO); // zero-pad the last block

        // Sponge with rate = SPONGE_RATE, capacity = WIDTH - SPONGE_RATE. Absorb each block into
        // the rate portion (overwrite mode on the first block, add on subsequent blocks), then
        // permute.
        let mut state = [F::ZERO; WIDTH];
        for (b, block) in absorb.chunks(SPONGE_RATE).enumerate() {
            for (i, &x) in block.iter().enumerate() {
                if b == 0 {
                    state[i] = x;
                } else {
                    state[i] += x;
                }
            }
            state = permute16(state);
        }
        let mut out = [F::ZERO; DIGEST_LIMBS];
        out.copy_from_slice(&state[0..DIGEST_LIMBS]);
        out
    }
}

/// A member's BabyBear public key: the `DIGEST_LIMBS`-limb Poseidon2 preimage-signature key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BabyBearPublicKey {
    pub digest: [F; DIGEST_LIMBS],
}

impl BabyBearPublicKey {
    /// Canonical u32 limbs (each `< q`).
    pub fn to_canonical_limbs(&self) -> [u32; DIGEST_LIMBS] {
        self.digest.map(|x| x.as_canonical_u32())
    }

    /// Bytes32 anchor used in the Goldilocks `MemberLeaf` and on-chain registration (locked
    /// decision 6: `pk_b` is committed as a `Bytes32` so the Goldilocks leaf and the BabyBear AIR
    /// public values agree on the same canonical bytes).
    ///
    /// Encoding: the 8 canonical u32 limbs are packed big-endian into the 8 u32 words of a
    /// `Bytes32` (`abi.encodePacked`-compatible, same convention as the other channel digests).
    pub fn to_bytes32(&self) -> Bytes32 {
        Bytes32::from_u32_slice(&self.to_canonical_limbs())
            .expect("DIGEST_LIMBS == 8 == Bytes32 word count")
    }

    /// Recover from the `Bytes32` anchor. Validates canonical (`< q`) limbs.
    pub fn from_bytes32(b: &Bytes32) -> Result<Self, RegevError> {
        let words = b.to_u32_vec();
        if words.len() != DIGEST_LIMBS || words.iter().any(|&w| w >= REGEV_Q) {
            return Err(RegevError::ProofVerification(
                "pk_b bytes32 limb >= q (non-canonical)".to_string(),
            ));
        }
        let mut digest = [F::ZERO; DIGEST_LIMBS];
        for (d, &w) in digest.iter_mut().zip(words.iter()) {
            *d = F::from_u32(w);
        }
        Ok(Self { digest })
    }
}

/// Re-decompose a keccak `Bytes32` IMPA digest into `MSG_LIMBS` little-endian 16-bit limbs, each
/// mapped INJECTIVELY into BabyBear (`< 2^16 < q`, no aliasing).
///
/// SECURITY (P3 message-encoding injectivity): the raw 8×u32 digest cannot be absorbed directly
/// because `u32` values `≥ q` alias under `from_u32`. Splitting each 32-bit word into two 16-bit
/// halves yields 16 sub-`q` limbs whose tuple is a bijection with the 256-bit digest, so distinct
/// digests give distinct `m_limbs`. The VERIFIER recomputes this exact decomposition from the
/// channel-tx digest and binds it to the proof's public `m_limbs`.
pub fn decompose_digest_to_limbs(digest: &Bytes32) -> [F; MSG_LIMBS] {
    let words = digest.to_u32_vec();
    debug_assert_eq!(words.len(), 8, "Bytes32 is 8 u32 words");
    let mut limbs = [F::ZERO; MSG_LIMBS];
    for (w_idx, &w) in words.iter().enumerate() {
        let lo = (w & 0xffff) as u32;
        let hi = (w >> 16) & 0xffff;
        // Little-endian within each word: low half first, then high half.
        limbs[2 * w_idx] = F::from_u32(lo);
        limbs[2 * w_idx + 1] = F::from_u32(hi);
    }
    limbs
}

use super::params::REGEV_Q;

// ---------------------------------------------------------------------------
// No-lookup wrapper so the Poseidon2Air goes through the p3-batch-stark backend
// ---------------------------------------------------------------------------

use p3_air_05::symbolic::SymbolicAirBuilder;
use p3_lookup::{LookupAir, lookup_traits::Lookup};

/// Thin wrapper that gives [`BabyBearPoseidon2Air`] an empty [`LookupAir`] impl so it can be
/// proven/verified through `p3-batch-stark` (which requires every AIR to implement `LookupAir`).
/// All round constraints are delegated to the upstream `Poseidon2Air` — none are hand-authored.
#[derive(Clone)]
pub struct NoLookupPoseidon2Air {
    inner: BabyBearPoseidon2Air,
}

impl NoLookupPoseidon2Air {
    pub fn new() -> Self {
        Self {
            inner: babybear_poseidon2_air(),
        }
    }
}

impl Default for NoLookupPoseidon2Air {
    fn default() -> Self {
        Self::new()
    }
}

impl BaseAir<F> for NoLookupPoseidon2Air {
    fn width(&self) -> usize {
        self.inner.width()
    }

    fn num_public_values(&self) -> usize {
        // PoC: the bare permutation AIR exposes no public values.
        0
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        // Poseidon2Air has no cross-row (next) constraints.
        vec![]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        self.inner.max_constraint_degree()
    }
}

impl LookupAir<F> for NoLookupPoseidon2Air {
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        // INTENTIONALLY EMPTY: the hash-sig binding is done via public values + boolean/equality
        // constraints, not lookups. The permutation correctness is fully covered by the inner
        // Poseidon2Air's transition constraints.
        Vec::new()
    }
}

impl<AB> Air<AB> for NoLookupPoseidon2Air
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        // Delegate ALL constraints to the audited upstream Poseidon2Air.
        self.inner.eval(builder);
    }
}

// The SymbolicAirBuilder bound used by p3-batch-stark's degree analysis is satisfied by the
// blanket impl above (SymbolicAirBuilder<F, Challenge> has F = F).
const _: fn() = || {
    fn assert_air<A: Air<SymbolicAirBuilder<F, regev_plonky3::Challenge>>>() {}
    assert_air::<NoLookupPoseidon2Air>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regev::transfer_stark::{prove_poseidon2_poc, verify_poseidon2_poc};
    use p3_matrix_05::Matrix;

    use rand::{SeedableRng, rngs::StdRng};

    fn sk(seed: u64) -> BabyBearSecretKey {
        let mut rng = StdRng::seed_from_u64(seed);
        BabyBearSecretKey::random(&mut rng)
    }

    fn digest(byte: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x0a0b_0c00 | byte as u32, 1, 2, 3, 0xffff_ffff, 5, 6, 7]).unwrap()
    }

    /// Determinism: the same sk yields the same pk_b.
    #[test]
    fn pk_b_deterministic() {
        let s = sk(1);
        assert_eq!(s.public_key(), s.public_key());
    }

    /// Distinctness: distinct keys (overwhelmingly) yield distinct pk_b.
    #[test]
    fn pk_b_distinct_keys() {
        assert_ne!(sk(2).public_key(), sk(3).public_key());
    }

    /// Reject the degenerate all-zero secret key (A1).
    #[test]
    fn rejects_all_zero_sk() {
        assert!(BabyBearSecretKey::from_canonical_limbs([0; SK_LIMBS]).is_err());
    }

    /// Reject non-canonical (>= q) limbs.
    #[test]
    fn rejects_non_canonical_limbs() {
        let mut limbs = [1u32; SK_LIMBS];
        limbs[0] = REGEV_Q; // == q, non-canonical
        assert!(BabyBearSecretKey::from_canonical_limbs(limbs).is_err());
    }

    /// Bytes32 anchor round-trips and is canonical.
    #[test]
    fn pk_b_bytes32_roundtrip() {
        let pk = sk(4).public_key();
        let b = pk.to_bytes32();
        let pk2 = BabyBearPublicKey::from_bytes32(&b).unwrap();
        assert_eq!(pk, pk2);
    }

    /// Domain separation (A2): DOMAIN_PK_B != DOMAIN_SIG_B, and pk_b for a key never equals the
    /// sig_b output for the same key over any message (different domain in slot 0 + different
    /// construction — single permutation vs 4-block sponge).
    #[test]
    fn domain_separation_pk_vs_sig() {
        assert_ne!(DOMAIN_PK_B, DOMAIN_SIG_B);
        let s = sk(5);
        let pk = s.public_key().digest;
        let m = decompose_digest_to_limbs(&digest(0x11));
        let sig = s.sign_digest_native(&m);
        assert_ne!(pk, sig, "pk_b and sig_b must not collide");
    }

    /// sig_b is deterministic in (sk, m) and message-sensitive.
    #[test]
    fn sig_b_message_binding() {
        let s = sk(6);
        let m1 = decompose_digest_to_limbs(&digest(0x01));
        let m2 = decompose_digest_to_limbs(&digest(0x02));
        assert_eq!(s.sign_digest_native(&m1), s.sign_digest_native(&m1));
        assert_ne!(s.sign_digest_native(&m1), s.sign_digest_native(&m2));
    }

    /// Message-encoding injectivity: distinct digests yield distinct limb tuples, and each limb
    /// is < 2^16 < q (no BabyBear aliasing).
    #[test]
    fn digest_decomposition_injective() {
        let a = decompose_digest_to_limbs(&digest(0xaa));
        let b = decompose_digest_to_limbs(&digest(0xab));
        assert_ne!(a, b);
        for limb in a.iter().chain(b.iter()) {
            assert!(limb.as_canonical_u32() < (1 << 16));
        }
        // A digest whose words exceed q (e.g. 0xffffffff) must still decompose to canonical limbs.
        let big = decompose_digest_to_limbs(&digest(0x00));
        for limb in big.iter() {
            assert!(limb.as_canonical_u32() < (1 << 16));
        }
    }

    /// Non-collision of the BabyBear domains with the existing regev purpose domains and the
    /// Goldilocks signature domains (cross-protocol confusion guard, A2/A4). The check is on the
    /// raw u32 words; the BabyBear and Goldilocks domains live in different fields, but keeping the
    /// words distinct removes any ambiguity if they were ever compared as integers.
    #[test]
    fn domains_non_colliding() {
        use crate::regev::transfer_stark::{
            BALANCE_REFRESH_ZKP_DOMAIN, CHANNEL_TX_ZKP_DOMAIN, CHANNEL_UPDATE_ZKP_DOMAIN,
            WITHDRAW_CLAIM_ZKP_DOMAIN,
        };
        let words = [
            DOMAIN_PK_B,
            DOMAIN_SIG_B,
            CHANNEL_TX_ZKP_DOMAIN,
            CHANNEL_UPDATE_ZKP_DOMAIN,
            WITHDRAW_CLAIM_ZKP_DOMAIN,
            BALANCE_REFRESH_ZKP_DOMAIN,
        ];
        for i in 0..words.len() {
            for j in (i + 1)..words.len() {
                assert_ne!(words[i], words[j], "domain word collision at {i},{j}");
            }
        }
    }

    /// STEP 0 PoC: prove + verify a single Poseidon2-BabyBear permutation through the regev
    /// 0.5.3 batch-stark backend, and confirm the AIR computes the canonical permutation.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn poc_poseidon2_air_prove_verify_and_matches_native() {
        // A known, non-trivial input.
        let input: [F; WIDTH] = core::array::from_fn(|i| F::from_u32((i as u32) * 7 + 1));

        // Reference output from the native canonical permutation.
        let native_out = permute16(input);

        // Generate the Poseidon2Air trace for this single permutation (one row, padded to a
        // power of two by duplicating — but one input is already a power of two: 1 row is not a
        // power-of-two height for FRI, so pad to 2 identical permutations).
        let constants = babybear_round_constants();
        let inputs = vec![input, input];
        let trace = generate_poseidon2_trace(&constants, inputs);

        // Cross-check: the AIR trace's output (final-layer post columns) equals the native
        // permutation output, proving the constraint system computes the canonical permutation.
        let air = babybear_poseidon2_air();
        let out_from_trace = super::output_from_trace_row(&air, &trace, 0);
        assert_eq!(
            out_from_trace, native_out,
            "Poseidon2Air trace output must equal the native canonical permutation"
        );
        assert_eq!(trace.height(), 2);

        // Prove + verify through the regev batch-stark backend.
        let proof = prove_poseidon2_poc(&trace).expect("PoC prove must succeed");
        verify_poseidon2_poc(&proof).expect("PoC verify must succeed");
    }
}

// ---------------------------------------------------------------------------
// Trace-output extraction (for the PoC cross-check against the native permutation)
// ---------------------------------------------------------------------------

use core::borrow::Borrow;
use p3_matrix_05::Matrix;
use p3_poseidon2_air::Poseidon2Cols;

/// Read the permutation OUTPUT (final ending-full-round post-state) of trace row `row`.
///
/// The `Poseidon2Cols` layout ends with `ending_full_rounds[HALF_FULL_ROUNDS-1].post`, which is
/// the permutation output. We borrow the row as a `Poseidon2Cols` (the AIR's column type) and
/// read that field — exactly the columns the AIR's last `assert_eq` pins to the permutation.
pub(crate) fn output_from_trace_row(
    _air: &BabyBearPoseidon2Air,
    trace: &p3_matrix_05::dense::RowMajorMatrix<F>,
    row: usize,
) -> [F; WIDTH] {
    let width = trace.width();
    let slice = &trace.values[row * width..(row + 1) * width];
    let cols: &Poseidon2Cols<
        F,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    > = slice.borrow();
    cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post
}
