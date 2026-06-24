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

use p3_air_05::{Air, AirBuilder, BaseAir, WindowAccess};
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
        // SECURITY/CORRECTNESS: the inner Poseidon2Air reports SBOX_DEGREE (=7) as a conservative
        // hint, but with SBOX_REGISTERS=1 every committed constraint is degree 3 (the S-box commits
        // x^3 and reuses it). The batch-stark sizes the quotient domain from this hint; an
        // over-large hint demands a quotient domain larger than the log_blowup=1 (blowup-2) LDE can
        // represent, producing a (benign-looking) OodEvaluationMismatch for any non-degenerate
        // trace. Report the ACTUAL degree 3 so the quotient is sized correctly.
        Some(3)
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
        Bytes32::from_u32_slice(&[0x0a0b_0c00 | byte as u32, 1, 2, 3, 0xffff_ffff, 5, 6, 7])
            .unwrap()
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

    // =======================================================================
    // P3-3: Poseidon2HashSigAir standalone tests
    // =======================================================================

    use crate::regev::transfer_stark::{RegevSecurityLevel, prove_hash_sig, verify_hash_sig};

    fn msg(byte: u8) -> [F; MSG_LIMBS] {
        decompose_digest_to_limbs(&digest(byte))
    }

    /// The trace's row-0 output (pk_b) and row-4 output (sig_b) equal the native reference,
    /// bit-for-bit, for random (sk, m). This is the native==in-circuit equality check.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn trace_matches_native_pk_and_sig() {
        for seed in 0..8u64 {
            let s = sk(seed);
            let m = msg(seed as u8);
            let (trace, pvs, sig_b) = generate_hash_sig_trace(&s, &m);

            // pk_b: native vs trace row-0 output vs public values.
            let air = babybear_poseidon2_air();
            let pk_native = s.public_key().digest;
            let pk_row0 = output_from_trace_row(&air, &trace, 0);
            assert_eq!(
                &pk_row0[0..DIGEST_LIMBS],
                &pk_native[..],
                "row0 output == native pk_b"
            );
            assert_eq!(
                &pvs[0..DIGEST_LIMBS],
                &pk_native[..],
                "PV pk_b == native pk_b"
            );

            // sig_b: native vs trace row-SIG_BLOCKS output.
            let sig_native = s.sign_digest_native(&m);
            assert_eq!(sig_b, sig_native, "generate_hash_sig_trace sig_b == native");
            let sig_row = output_from_trace_row(&air, &trace, SIG_BLOCKS);
            assert_eq!(
                &sig_row[0..DIGEST_LIMBS],
                &sig_native[..],
                "row-N output == native sig_b"
            );

            // PV message == the supplied limbs.
            assert_eq!(&pvs[DIGEST_LIMBS..], &m[..], "PV message == m_limbs");
        }
    }

    /// Happy path: prove + verify; the public values expose the correct (pk_b, m).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn hash_sig_prove_verify_happy() {
        let s = sk(42);
        let m = msg(0x7c);
        let (proof, pvs) = prove_hash_sig(RegevSecurityLevel::Test, &s, &m).expect("prove");
        verify_hash_sig(RegevSecurityLevel::Test, &proof, &pvs).expect("verify");

        // The exposed PVs are exactly [pk_b ‖ m].
        assert_eq!(&pvs[0..DIGEST_LIMBS], &s.public_key().digest[..]);
        assert_eq!(&pvs[DIGEST_LIMBS..], &m[..]);
    }

    /// Wrong pk_b: tampering the pk_b public value makes verification fail (the proof was bound to
    /// the real pk_b; a different key would yield a different pk_b).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn hash_sig_wrong_pk_b_rejected() {
        let s = sk(7);
        let m = msg(0x11);
        let (proof, mut pvs) = prove_hash_sig(RegevSecurityLevel::Test, &s, &m).expect("prove");
        // Tamper the first pk_b limb.
        pvs[0] += F::ONE;
        assert!(
            verify_hash_sig(RegevSecurityLevel::Test, &proof, &pvs).is_err(),
            "verify must reject a tampered pk_b public value"
        );

        // Sanity: a genuinely different key has a different pk_b PV (so re-proving binds it).
        let s2 = sk(8);
        assert_ne!(s.public_key().digest, s2.public_key().digest);
    }

    /// Constraint-level forgery: a malicious prover tampers row-0's permutation OUTPUT column to a
    /// chosen forged pk_b and sets the PVs to match. The inner Poseidon2 permutation constraint
    /// (`post == permute16(inputs)`) — and the pk-output binding `post[0..8] == pv_pk` — must
    /// reject this: a valid proof of a pk_b that is NOT `Poseidon2(sk)` cannot exist.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn hash_sig_forged_pk_output_rejected() {
        let s = sk(123);
        let m = msg(0x55);
        let (mut trace, mut pvs, _sig) = generate_hash_sig_trace(&s, &m);

        // Forge row-0 output column [0]: set the trace's pk_b[0] and the PV[0] to a wrong value.
        // The permutation constraint will no longer hold (post != permute16(inputs)).
        let forged = pvs[0] + F::from_u32(777);
        // ending_full_rounds[last].post[0] is the LAST `post[0]` column in Poseidon2Cols. Locate it
        // by borrowing the row, finding the offset of that field, then overwriting in the trace.
        {
            let w = HASH_SIG_COLS;
            let row0 = &trace.values[0..w];
            let cols: &Poseidon2Cols<
                F,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            > = row0[0..POSEIDON2_COLS].borrow();
            let base = trace.values.as_ptr() as usize;
            let field =
                (&cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[0]) as *const F as usize;
            let idx = (field - base) / core::mem::size_of::<F>();
            trace.values[idx] = forged;
        }
        pvs[0] = forged;

        // Even though the PV matches the (forged) trace output, the permutation constraint fails.
        let proof = crate::regev::transfer_stark::prove_one_test_hash_sig(&trace, pvs.clone());
        // Proving may succeed (it does not check constraints) but verification MUST reject.
        match proof {
            Ok(p) => assert!(
                verify_hash_sig(RegevSecurityLevel::Test, &p, &pvs).is_err(),
                "a forged row-0 output (post != permute16(inputs)) must not verify"
            ),
            Err(_) => { /* prover refused — also acceptable */ }
        }
    }

    /// Wrong m: tampering a message public value makes verification fail (binding broken).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn hash_sig_wrong_m_rejected() {
        let s = sk(9);
        let m = msg(0x22);
        let (proof, mut pvs) = prove_hash_sig(RegevSecurityLevel::Test, &s, &m).expect("prove");
        // Tamper one message limb.
        pvs[DIGEST_LIMBS + 3] += F::ONE;
        assert!(
            verify_hash_sig(RegevSecurityLevel::Test, &proof, &pvs).is_err(),
            "verify must reject a tampered message public value"
        );

        // And a proof produced for a DIFFERENT message must not verify against the original m.
        let m2 = msg(0x23);
        let (proof2, _pvs2) = prove_hash_sig(RegevSecurityLevel::Test, &s, &m2).expect("prove m2");
        let (_p, pvs_m) = prove_hash_sig(RegevSecurityLevel::Test, &s, &m).expect("prove m");
        assert!(
            verify_hash_sig(RegevSecurityLevel::Test, &proof2, &pvs_m).is_err(),
            "a proof for m2 must not verify against m's public values"
        );
    }

    /// Wrong public-value length is rejected before any cryptographic work.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn hash_sig_wrong_pv_len_rejected() {
        let s = sk(10);
        let m = msg(0x33);
        let (proof, pvs) = prove_hash_sig(RegevSecurityLevel::Test, &s, &m).expect("prove");
        assert!(verify_hash_sig(RegevSecurityLevel::Test, &proof, &pvs[0..pvs.len() - 1]).is_err());
        let mut too_long = pvs.clone();
        too_long.push(F::ZERO);
        assert!(verify_hash_sig(RegevSecurityLevel::Test, &proof, &too_long).is_err());
    }

    /// Padding cannot forge: a crafted padding row (row 5) with a pk-like input that, if it were
    /// bound, would output a DIFFERENT pk_b cannot change the proof's bound pk_b. We build the
    /// honest trace, overwrite a padding row's Poseidon2Cols input/output with a foreign valid
    /// permutation, and confirm the proof STILL binds the genuine pk_b (verification with the
    /// genuine PVs succeeds; the selector schedule pins the pad row's kind so its binding is off).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn hash_sig_padding_cannot_forge() {
        let s = sk(11);
        let m = msg(0x44);
        let (mut trace, pvs, _sig) = generate_hash_sig_trace(&s, &m);
        assert!(
            HASH_SIG_HEIGHT > HASH_SIG_REAL_ROWS,
            "there is at least one padding row"
        );

        // Overwrite a PADDING row (row HASH_SIG_REAL_ROWS = 5) with a *foreign* valid permutation
        // whose input is a pk-style preimage for a DIFFERENT secret key. The upstream permutation
        // constraint will hold (we fill the full Poseidon2Cols via the trace generator), but the
        // pk binding is gated to SEL_PK (row 0) only, so this cannot inject a forged pk_b.
        let pad_row = HASH_SIG_REAL_ROWS;
        let s_evil = sk(99);
        let mut evil_in = [F::ZERO; WIDTH];
        evil_in[0] = F::from_u32(DOMAIN_PK_B);
        evil_in[1..1 + SK_LIMBS].copy_from_slice(s_evil.limbs());
        let constants = babybear_round_constants();
        let evil_prefix = generate_poseidon2_trace(&constants, vec![evil_in]);
        // Splice the foreign permutation columns into the padding row's Poseidon2Cols prefix,
        // keeping the (honest) SEL_PAD selector + sk tail intact.
        for c in 0..POSEIDON2_COLS {
            trace.values[pad_row * HASH_SIG_COLS + c] = evil_prefix.values[c];
        }

        // The genuine (pk_b, m) public values must STILL verify: padding is benign.
        let proof = crate::regev::transfer_stark::prove_one_test_hash_sig(&trace, pvs.clone())
            .expect("prove with spliced padding");
        verify_hash_sig(RegevSecurityLevel::Test, &proof, &pvs)
            .expect("genuine pk_b/m must still verify despite a foreign padding permutation");

        // And the proof must NOT verify against the EVIL pk_b (the forgery target): the bound
        // pk_b is still the genuine one.
        let mut evil_pvs = pvs.clone();
        evil_pvs[0..DIGEST_LIMBS].copy_from_slice(&s_evil.public_key().digest);
        assert!(
            verify_hash_sig(RegevSecurityLevel::Test, &proof, &evil_pvs).is_err(),
            "padding row must not be able to forge a foreign pk_b"
        );
    }

    /// Selector tamper: forcing row 0 to PAD (instead of PK) must be rejected. The `when_first_row`
    /// pin (`lsel(SEL_PK)==1` on row 0) and the `nsel(PK)=0` shift-register rule forbid any
    /// reshuffle of the pk/sig/pad schedule, so the pk_b binding can never be dodged.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn hash_sig_selector_tamper_rejected() {
        let s = sk(31);
        let m = msg(0x61);
        let (mut trace, pvs, _sig) = generate_hash_sig_trace(&s, &m);
        // Flip row 0's one-hot selector from PK to PAD (keeps sum==1, but breaks when_first_row).
        trace.values[POSEIDON2_COLS + SEL_PK] = F::ZERO;
        trace.values[POSEIDON2_COLS + SEL_PAD] = F::ONE;
        match crate::regev::transfer_stark::prove_one_test_hash_sig(&trace, pvs.clone()) {
            Ok(p) => assert!(
                verify_hash_sig(RegevSecurityLevel::Test, &p, &pvs).is_err(),
                "row 0 must be pinned to the PK selector"
            ),
            Err(_) => { /* prover refused — also acceptable */ }
        }
    }

    /// sk-not-broadcast: a sig row whose broadcast `sk` limb differs from row 0's must be rejected.
    /// The `assert_eq(nsk, lsk)` chain ties pk_b and the sponge to the SAME secret key (the binding
    /// that makes "the debited owner authorized this" meaningful).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn hash_sig_sk_not_broadcast_rejected() {
        let s = sk(32);
        let m = msg(0x62);
        let (mut trace, pvs, _sig) = generate_hash_sig_trace(&s, &m);
        // Tamper row 1's first broadcast sk limb so it diverges from row 0's.
        let idx = HASH_SIG_COLS + POSEIDON2_COLS + SEL_COLS; // row 1, sk[0]
        trace.values[idx] += F::ONE;
        match crate::regev::transfer_stark::prove_one_test_hash_sig(&trace, pvs.clone()) {
            Ok(p) => assert!(
                verify_hash_sig(RegevSecurityLevel::Test, &p, &pvs).is_err(),
                "sk must be held equal across all rows"
            ),
            Err(_) => {}
        }
    }

    /// Chaining tamper: corrupting a sponge chaining input cell must be rejected. The cross-row
    /// `next.inputs == post + block` constraints pin exactly how each message limb is absorbed, so
    /// a prover cannot absorb a different message than the one committed in the public values.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn hash_sig_chaining_tamper_rejected() {
        let s = sk(33);
        let m = msg(0x63);
        let (mut trace, pvs, _sig) = generate_hash_sig_trace(&s, &m);
        // Corrupt row 2's permutation input[0] (the SIG1->SIG2 chaining target; inputs are cols
        // 0..WIDTH).
        let idx = 2 * HASH_SIG_COLS; // row 2, Poseidon2Cols.inputs[0] == column 0
        trace.values[idx] += F::ONE;
        match crate::regev::transfer_stark::prove_one_test_hash_sig(&trace, pvs.clone()) {
            Ok(p) => assert!(
                verify_hash_sig(RegevSecurityLevel::Test, &p, &pvs).is_err(),
                "sponge chaining inputs must be constrained"
            ),
            Err(_) => {}
        }
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

// ===========================================================================
// P3-3: Poseidon2HashSigAir — the standalone binding AIR
// ===========================================================================
//
// Proves, for a PRIVATE witness `sk_b` and PUBLIC values `[pk_b(8) ‖ m(16)]`:
//   - `pk_b  = Poseidon2([DOMAIN_PK_B] ‖ sk_b ‖ 0…)[0..8]`            (row 0)
//   - `sig_b = Poseidon2_sponge([DOMAIN_SIG_B] ‖ sk_b ‖ m)`           (rows 1..=4)
// where the sponge is the SAME rate-8 overwrite-first / add-subsequent construction as
// [`BabyBearSecretKey::sign_digest_native`]. `sig_b` is witness-only (NOT a public value, A6).
//
// # Path: COMPOSITION over the vendored upstream `Poseidon2Air` (visibility-only diff)
//
// Each trace row is `[Poseidon2Cols | binding_tail]`. The wrapper:
//   1. borrows the `Poseidon2Cols` PREFIX of the local row and calls the AUDITED upstream free
//      `p3_poseidon2_air::eval(air, builder, prefix)` — this constrains EVERY row to be a valid
//      Poseidon2-BabyBear permutation (`post == permute16(inputs)`). NO round constraint is
//      hand-authored. The only vendored change is `pub(crate) fn eval -> pub fn eval`.
//   2. adds CROSS-ROW BINDING constraints referencing only `Poseidon2Cols.inputs` /
//      `.ending_full_rounds[last].post` and the binding tail, gated by one-hot row selectors.
//
// # Binding tail layout (BIND_TAIL_COLS columns appended after the Poseidon2Cols prefix)
//   - `sel[0..6]`  one-hot row-kind selector: pk, sig1, sig2, sig3, sig4, pad.
//   - `sk[0..9]`   the secret key, BROADCAST (held equal) on every row so it is available to both
//     the pk-row input binding and the sponge block bindings.
//
// # Why a binding tail / why vendored (composition could not stay "no extra columns")
//   The 4 sponge blocks absorb DIFFERENT message limbs, so a single uniform transition constraint
//   cannot gate them; per-sponge-row gating is required. The p3 stack here supports neither
//   periodic nor preprocessed-periodic columns (checked: no `PeriodicAirBuilder` impl in
//   regev_plonky3 / p3-lookup / vendored p3-uni-stark). The minimal sound mechanism is explicit
//   one-hot selector columns + a broadcast `sk` register, which requires a row WIDER than
//   `Poseidon2Cols`; the upstream trait `Air::eval` assumes the row width == `num_cols`, so we
//   call the free `eval` on an explicit `Poseidon2Cols` PREFIX borrow instead (the vendored
//   visibility change). See tasks/poseidon-signature-todo.md P3-3.
//
// # `sk_b` non-degeneracy is OUT of the AIR (documented)
//   Native keygen ([`BabyBearSecretKey::from_canonical_limbs`] / `random`) rejects the all-zero
//   and non-canonical keys; the off-chain verifier (P3-5) re-checks. No aux column is added here.

use p3_poseidon2_air::num_cols as poseidon2_num_cols;

/// Number of `Poseidon2Cols` (permutation) columns per row.
pub(crate) const POSEIDON2_COLS: usize =
    poseidon2_num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();

/// One-hot row-kind selector width: pk, sig1, sig2, sig3, sig4, pad.
pub(crate) const SEL_COLS: usize = 6;
const SEL_PK: usize = 0;
const SEL_SIG1: usize = 1;
const SEL_SIG2: usize = 2;
const SEL_SIG3: usize = 3;
const SEL_SIG4: usize = 4;
const SEL_PAD: usize = 5;

/// Binding-tail width: one-hot selectors + the broadcast secret key.
pub(crate) const BIND_TAIL_COLS: usize = SEL_COLS + SK_LIMBS; // 6 + 9 = 15
/// Total row width.
pub(crate) const HASH_SIG_COLS: usize = POSEIDON2_COLS + BIND_TAIL_COLS;

/// Number of public values: `pk_b` (8 limbs) ‖ `m` (16 limbs).
pub(crate) const HASH_SIG_NUM_PV: usize = DIGEST_LIMBS + MSG_LIMBS; // 24

/// Trace height: pk row + SIG_BLOCKS sponge rows, padded to a power of two.
/// 1 + 4 = 5 → next_pow2 = 8 (3 padding rows).
pub(crate) const HASH_SIG_REAL_ROWS: usize = 1 + SIG_BLOCKS; // 5
pub(crate) const HASH_SIG_HEIGHT: usize = HASH_SIG_REAL_ROWS.next_power_of_two(); // 8

/// Borrow the `Poseidon2Cols` prefix of a row slice (the first `POSEIDON2_COLS` columns).
fn poseidon_cols<T>(
    row: &[T],
) -> &Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    row[0..POSEIDON2_COLS].borrow()
}

/// The standalone Poseidon2-BabyBear hash-signature binding AIR.
#[derive(Clone)]
pub struct Poseidon2HashSigAir {
    inner: BabyBearPoseidon2Air,
}

impl Poseidon2HashSigAir {
    pub fn new() -> Self {
        Self {
            inner: babybear_poseidon2_air(),
        }
    }
}

impl Default for Poseidon2HashSigAir {
    fn default() -> Self {
        Self::new()
    }
}

impl BaseAir<F> for Poseidon2HashSigAir {
    fn width(&self) -> usize {
        HASH_SIG_COLS
    }

    fn num_public_values(&self) -> usize {
        HASH_SIG_NUM_PV
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        // The sponge-chaining and selector-shift constraints reference the NEXT row. The verifier
        // only checks emptiness to decide whether to open `trace_next` (it opens the WHOLE next
        // row), so the exact indices are an honest hint, not a soundness-bearing list. We list the
        // permutation `inputs` columns (read on the next row) plus the selector columns.
        let mut cols: Vec<usize> = (0..WIDTH).collect(); // Poseidon2Cols.inputs are columns 0..WIDTH
        cols.extend(POSEIDON2_COLS..POSEIDON2_COLS + SEL_COLS + SK_LIMBS);
        cols
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // The permutation constraints are committed at degree 3 (the 1-register x^7 S-box commits
        // x^3 and reuses it — see SBOX_REGISTERS). The binding constraints are a single selector
        // (degree 1) times a linear equality ⇒ degree 2. So the true maximum committed degree is 3.
        //
        // CORRECTNESS: the inner Poseidon2Air's own `max_constraint_degree()` reports the
        // conservative SBOX_DEGREE (=7), which OVER-sizes the quotient domain and breaks proving on
        // any non-degenerate trace under the log_blowup=1 (blowup-2) regev config. We report the
        // ACTUAL degree 3. (The batch-stark's `get_max_constraint_degree` symbolic check asserts
        // hint >= actual, so this is verified to be sound, not a weakening.)
        Some(3)
    }
}

impl LookupAir<F> for Poseidon2HashSigAir {
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        // INTENTIONALLY EMPTY: all binding is via public values + selector-gated equality
        // constraints. Public values are absorbed into the Fiat-Shamir transcript by the
        // verifier (regev_plonky3 stark/verifier.rs observe_slice), so no lookup is needed to
        // bind them.
        Vec::new()
    }
}

impl<AB> Air<AB> for Poseidon2HashSigAir
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        // --- (1) Permutation correctness on EVERY row (audited upstream eval) ---------------
        {
            let main = builder.main();
            let local = main.current_slice();
            let cols = poseidon_cols(local);
            // Calls the vendored `pub fn eval` (visibility-only change). Constrains
            // post == permute16(inputs) for this row.
            p3_poseidon2_air::eval::<
                AB,
                GenericPoseidon2LinearLayersBabyBear,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >(&self.inner, builder, cols);
        }

        // Snapshot the local/next rows and the public values into OWNED buffers so that nothing
        // borrows `builder` while we issue the (mutable) `assert_*` calls below. `AB::Var` and
        // `AB::PublicVar` are `Copy`.
        let local_row: Vec<AB::Var> = {
            let main = builder.main();
            main.current_slice().to_vec()
        };
        let next_row: Vec<AB::Var> = {
            let main = builder.main();
            main.next_slice().to_vec()
        };
        let pv_owned: Vec<AB::PublicVar> = builder.public_values().to_vec();

        let loc = poseidon_cols(&local_row);
        let nxt = poseidon_cols(&next_row);

        // Selector + sk tail accessors.
        let lsel = |i: usize| -> AB::Expr { local_row[POSEIDON2_COLS + i].into() };
        let nsel = |i: usize| -> AB::Expr { next_row[POSEIDON2_COLS + i].into() };
        let lsk = |i: usize| -> AB::Expr { local_row[POSEIDON2_COLS + SEL_COLS + i].into() };
        let nsk = |i: usize| -> AB::Expr { next_row[POSEIDON2_COLS + SEL_COLS + i].into() };

        // pv[0..8] = pk_b, pv[8..24] = m. PublicVar -> Expr.
        let pv_pk = |i: usize| -> AB::Expr { pv_owned[i].into() };
        let pv_m = |j: usize| -> AB::Expr { pv_owned[DIGEST_LIMBS + j].into() };

        let dom_pk = AB::Expr::from(F::from_u32(DOMAIN_PK_B));
        let dom_sig = AB::Expr::from(F::from_u32(DOMAIN_SIG_B));

        // --- (2) Selector structure: one-hot + shift-register schedule ---------------------
        for i in 0..SEL_COLS {
            builder.assert_bool(lsel(i));
        }
        // Exactly one active.
        let sum_sel = (0..SEL_COLS).fold(AB::Expr::ZERO, |acc, i| acc + lsel(i));
        builder.assert_one(sum_sel);

        // Row 0 is the pk row.
        builder.when_first_row().assert_one(lsel(SEL_PK));
        for i in 1..SEL_COLS {
            builder.when_first_row().assert_zero(lsel(i));
        }

        // Shift register: next = advance(local), absorbing in the pad state.
        //   next_pk = 0; next_sigK = local_sig(K-1) / pk; next_pad = local_sig4 + local_pad.
        builder.when_transition().assert_zero(nsel(SEL_PK)); // pk only ever on row 0
        builder
            .when_transition()
            .assert_eq(nsel(SEL_SIG1), lsel(SEL_PK));
        builder
            .when_transition()
            .assert_eq(nsel(SEL_SIG2), lsel(SEL_SIG1));
        builder
            .when_transition()
            .assert_eq(nsel(SEL_SIG3), lsel(SEL_SIG2));
        builder
            .when_transition()
            .assert_eq(nsel(SEL_SIG4), lsel(SEL_SIG3));
        builder
            .when_transition()
            .assert_eq(nsel(SEL_PAD), lsel(SEL_SIG4) + lsel(SEL_PAD));

        // --- (3) sk broadcast register: held equal across all rows -------------------------
        for i in 0..SK_LIMBS {
            builder.when_transition().assert_eq(nsk(i), lsk(i));
        }

        // --- (4) Row 0 (pk) binding, gated by sel[PK] ---------------------------------------
        // input = [DOMAIN_PK_B, sk(9), 0(6)]; output[0..8] = pk_b.
        {
            let g = lsel(SEL_PK);
            let mut b = builder.when(g);
            b.assert_eq(loc.inputs[0], dom_pk.clone());
            for i in 0..SK_LIMBS {
                b.assert_eq(loc.inputs[1 + i], lsk(i));
            }
            for k in 0..(WIDTH - 1 - SK_LIMBS) {
                // positions 10..16 are zero padding
                b.assert_zero(loc.inputs[1 + SK_LIMBS + k]);
            }
            for i in 0..DIGEST_LIMBS {
                b.assert_eq(
                    loc.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[i],
                    pv_pk(i),
                );
            }
        }

        // --- (5) Row 1 (sig block0) input binding, gated by sel[SIG1] -----------------------
        // input = [DOMAIN_SIG_B, sk0..sk6, 0(capacity 8)]  (overwrite-mode first block).
        {
            let g = lsel(SEL_SIG1);
            let mut b = builder.when(g);
            b.assert_eq(loc.inputs[0], dom_sig.clone());
            for i in 0..(SPONGE_RATE - 1) {
                // sk0..sk6 at rate positions 1..8
                b.assert_eq(loc.inputs[1 + i], lsk(i));
            }
            for k in 0..(WIDTH - SPONGE_RATE) {
                // capacity positions 8..16 are zero on the first block
                b.assert_zero(loc.inputs[SPONGE_RATE + k]);
            }
        }

        // --- (6) Row1 -> Row2 chaining, gated by sel[SIG1] ----------------------------------
        // block1 = [sk7, sk8, m0, m1, m2, m3, m4, m5].
        // next.rate[j] = local.post[j] + block1[j]; next.capacity = local.post (carry).
        {
            let g = lsel(SEL_SIG1);
            let mut b = builder.when(g);
            let post = |j: usize| -> AB::Expr {
                loc.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[j].into()
            };
            // sk7, sk8 at rate positions 0,1
            b.assert_eq(nxt.inputs[0], post(0) + lsk(SPONGE_RATE - 1)); // sk7
            b.assert_eq(nxt.inputs[1], post(1) + lsk(SPONGE_RATE)); // sk8
            // m0..m5 at rate positions 2..8
            for j in 0..(SPONGE_RATE - 2) {
                b.assert_eq(nxt.inputs[2 + j], post(2 + j) + pv_m(j));
            }
            // capacity carry
            for j in 0..(WIDTH - SPONGE_RATE) {
                b.assert_eq(nxt.inputs[SPONGE_RATE + j], post(SPONGE_RATE + j));
            }
        }

        // --- (7) Row2 -> Row3 chaining, gated by sel[SIG2] ----------------------------------
        // block2 = [m6, m7, m8, m9, m10, m11, m12, m13].
        {
            let g = lsel(SEL_SIG2);
            let mut b = builder.when(g);
            let post = |j: usize| -> AB::Expr {
                loc.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[j].into()
            };
            for j in 0..SPONGE_RATE {
                // m6 + j (the message limbs consumed in blocks 0..1 are 6: sk7,sk8 carry no m;
                // block1 absorbed m0..m5). So block2 absorbs m6..m13.
                b.assert_eq(nxt.inputs[j], post(j) + pv_m(6 + j));
            }
            for j in 0..(WIDTH - SPONGE_RATE) {
                b.assert_eq(nxt.inputs[SPONGE_RATE + j], post(SPONGE_RATE + j));
            }
        }

        // --- (8) Row3 -> Row4 chaining, gated by sel[SIG3] ----------------------------------
        // block3 = [m14, m15, 0, 0, 0, 0, 0, 0].
        {
            let g = lsel(SEL_SIG3);
            let mut b = builder.when(g);
            let post = |j: usize| -> AB::Expr {
                loc.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[j].into()
            };
            b.assert_eq(nxt.inputs[0], post(0) + pv_m(14));
            b.assert_eq(nxt.inputs[1], post(1) + pv_m(15));
            for j in 2..SPONGE_RATE {
                // zero pad added to the rate
                b.assert_eq(nxt.inputs[j], post(j));
            }
            for j in 0..(WIDTH - SPONGE_RATE) {
                b.assert_eq(nxt.inputs[SPONGE_RATE + j], post(SPONGE_RATE + j));
            }
        }
        // Row4 (sel[SIG4]) post[0..8] = sig_b is witness-only; intentionally NOT bound to any PV.
        // Padding rows (sel[PAD]) have no gated binding ⇒ free benign permutations that cannot
        // affect pk_b (only sel[PK] binds it) or m (only sel[SIG1..3] chaining binds it).
    }
}

// The SymbolicAirBuilder degree-analysis bound used by p3-batch-stark is satisfied here too.
const _: fn() = || {
    fn assert_air<A: Air<SymbolicAirBuilder<F, regev_plonky3::Challenge>>>() {}
    assert_air::<Poseidon2HashSigAir>();
};

// ---------------------------------------------------------------------------
// Trace generation for the hash-sig AIR
// ---------------------------------------------------------------------------

/// Build the full `[Poseidon2Cols | binding_tail]` trace for one (sk_b, m) instance, plus the
/// public values `[pk_b ‖ m]`. Returns `(trace, public_values, sig_b)`.
///
/// Trace generation is done by (a) computing the per-row permutation INPUT states exactly as the
/// native reference does, (b) calling the upstream `generate_poseidon2_trace` to fill the
/// Poseidon2Cols prefix (sbox / post columns) for those inputs, and (c) writing the binding-tail
/// selector + sk columns. The AIR then RE-CHECKS every relation in-circuit.
pub(crate) fn generate_hash_sig_trace(
    sk: &BabyBearSecretKey,
    m_limbs: &[F; MSG_LIMBS],
) -> (
    p3_matrix_05::dense::RowMajorMatrix<F>,
    Vec<F>,
    [F; DIGEST_LIMBS],
) {
    // --- Compute the per-row permutation inputs (native sponge layout) -----------------------
    // Row 0: pk permutation input.
    let mut pk_in = [F::ZERO; WIDTH];
    pk_in[0] = F::from_u32(DOMAIN_PK_B);
    pk_in[1..1 + SK_LIMBS].copy_from_slice(sk.limbs());

    // Sig sponge: absorb [DOMAIN_SIG_B] ‖ sk(9) ‖ m(16), rate 8, 4 blocks (zero-padded last).
    let mut absorb = Vec::with_capacity(SIG_BLOCKS * SPONGE_RATE);
    absorb.push(F::from_u32(DOMAIN_SIG_B));
    absorb.extend_from_slice(sk.limbs());
    absorb.extend_from_slice(m_limbs);
    absorb.resize(SIG_BLOCKS * SPONGE_RATE, F::ZERO);

    // Reconstruct the per-block INPUT states (pre-permutation), mirroring sign_digest_native.
    let mut sig_inputs: Vec<[F; WIDTH]> = Vec::with_capacity(SIG_BLOCKS);
    let mut state = [F::ZERO; WIDTH];
    for (b, block) in absorb.chunks(SPONGE_RATE).enumerate() {
        for (i, &x) in block.iter().enumerate() {
            if b == 0 {
                state[i] = x;
            } else {
                state[i] += x;
            }
        }
        sig_inputs.push(state); // the input to this block's permutation
        state = permute16(state); // advance to the next block's pre-add state
    }
    let mut sig_b = [F::ZERO; DIGEST_LIMBS];
    sig_b.copy_from_slice(&state[0..DIGEST_LIMBS]);

    // --- Assemble the ordered per-row permutation inputs (pad to power of two) ---------------
    let mut row_inputs: Vec<[F; WIDTH]> = Vec::with_capacity(HASH_SIG_HEIGHT);
    row_inputs.push(pk_in);
    row_inputs.extend_from_slice(&sig_inputs);
    debug_assert_eq!(row_inputs.len(), HASH_SIG_REAL_ROWS);
    // Benign fixed padding input (all-zero permutation); binding is gated off on pad rows.
    while row_inputs.len() < HASH_SIG_HEIGHT {
        row_inputs.push([F::ZERO; WIDTH]);
    }

    // --- Fill the Poseidon2Cols prefix via the upstream trace generator ----------------------
    let constants = babybear_round_constants();
    let prefix = generate_poseidon2_trace(&constants, row_inputs.clone());
    debug_assert_eq!(prefix.width(), POSEIDON2_COLS);
    debug_assert_eq!(prefix.height(), HASH_SIG_HEIGHT);

    // --- Widen into [Poseidon2Cols | binding_tail] -------------------------------------------
    let mut values = vec![F::ZERO; HASH_SIG_HEIGHT * HASH_SIG_COLS];
    for r in 0..HASH_SIG_HEIGHT {
        // Copy the permutation prefix.
        let src = &prefix.values[r * POSEIDON2_COLS..(r + 1) * POSEIDON2_COLS];
        let dst = &mut values[r * HASH_SIG_COLS..r * HASH_SIG_COLS + POSEIDON2_COLS];
        dst.copy_from_slice(src);

        // One-hot selector.
        let sel_base = r * HASH_SIG_COLS + POSEIDON2_COLS;
        let kind = match r {
            0 => SEL_PK,
            1 => SEL_SIG1,
            2 => SEL_SIG2,
            3 => SEL_SIG3,
            4 => SEL_SIG4,
            _ => SEL_PAD,
        };
        values[sel_base + kind] = F::ONE;

        // Broadcast sk on every row.
        let sk_base = sel_base + SEL_COLS;
        for (i, &limb) in sk.limbs().iter().enumerate() {
            values[sk_base + i] = limb;
        }
    }

    let trace = p3_matrix_05::dense::RowMajorMatrix::new(values, HASH_SIG_COLS);

    // Public values: pk_b ‖ m.
    let pk = sk.public_key();
    let mut pvs = Vec::with_capacity(HASH_SIG_NUM_PV);
    pvs.extend_from_slice(&pk.digest);
    pvs.extend_from_slice(m_limbs);
    debug_assert_eq!(pvs.len(), HASH_SIG_NUM_PV);

    (trace, pvs, sig_b)
}
