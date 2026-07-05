//! Poseidon-preimage ZK signature primitive — **Goldilocks key** (Plonky2 side).
//!
//! This module provides the native (out-of-circuit) reference for the Goldilocks member key that
//! replaces the SPHINCS+ member signature on the Plonky2 paths (channel-state agreement, channel
//! close, intmax-tx / small-block signing). The matching BabyBear key (Plonky3 in-channel sender
//! authorization) is a separate primitive shipped in Phase 3.
//!
//! Scheme (see `tasks/poseidon-signature-threat-model.md`):
//!   - secret key  `sk ∈ Goldilocks^4`            (≈256-bit entropy, D2)
//!   - public key  `pk  = Poseidon([DOMAIN_PK_G]  ‖ sk)`            → Bytes32 (256-bit digest)
//!   - signature   `sig = Poseidon([DOMAIN_SIG_G] ‖ sk ‖ m)`       → Bytes32
//!
//! The "signature" is **not** a self-checking value: there is no standalone native verifier,
//! because verifying `sig`/`pk` without `sk` is exactly what the ZK proof (Phase 2 single-sig
//! circuit) does. This module only computes the deterministic prover-side values that the circuit
//! will reproduce.
//!
//! SECURITY:
//! - Unforgeability reduces to Poseidon-Goldilocks **preimage** resistance on `sk` (256-bit
//!   classical / 128-bit quantum under Grover). Do not shrink `SECRET_KEY_LEN` (CLAUDE.md: never
//!   weaken an approved security parameter silently).
//! - `sig` is witness-only by design — it MUST NOT be published (avoids a deterministic per-(key,
//!   message) tag / PRF-leakage surface). Callers store it only as a private witness.
//! - `DOMAIN_PK_G != DOMAIN_SIG_G` keeps the pk-oracle and sig-oracle independent (no domain
//!   confusion).
//! - The audited Goldilocks Poseidon (`PoseidonHashOut`, already the member-identity hash) is
//!   reused; no primitive is implemented from scratch.

pub mod aggregate;
pub mod circuit;
pub mod consumer;
pub mod list;

use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64},
};
use rand::{CryptoRng, Rng};

use crate::{
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
    utils::poseidon_hash_out::PoseidonHashOut,
};

/// Domain separator for the Goldilocks public-key hash: `pk = H(DOMAIN_PK_G ‖ sk)`. ASCII "IMPG".
/// Non-colliding with every existing IMxx domain (verified by `domain_constants_no_collision`).
pub const DOMAIN_PK_G: u32 = 0x494d_5047;

/// Domain separator for the Goldilocks message signature: `sig = H(DOMAIN_SIG_G ‖ sk ‖ m)`. ASCII
/// "IMSG".
pub const DOMAIN_SIG_G: u32 = 0x494d_5347;

/// Number of Goldilocks limbs in a secret key.
///
/// Each Goldilocks element carries ≈63.99 bits, so 4 limbs ≈ 255.97 bits of entropy — meeting the
/// D2 target of ≥256-bit classical / ≥128-bit quantum preimage security. The public key is a
/// `Bytes32` (4 Goldilocks limbs ≈ 256-bit), matching the preimage-security target on the output
/// side.
pub const SECRET_KEY_LEN: usize = 4;

/// A Goldilocks signing secret key (`sk ∈ Goldilocks^4`, canonical limbs).
///
/// `Debug` is intentionally redacted so the secret never lands in a log or an error string.
///
/// SECURITY: this type intentionally does **not** derive `Serialize`/`Deserialize` (nor `Display`):
/// a default secret-bearing serialization is a leak-by-default footgun. When wallet persistence is
/// needed (P2/P3), add an explicit, clearly-named secret-export API guarded by a `// SECURITY:`
/// note and store it only on gitignored/encrypted storage.
///
/// INVARIANT: every `limbs[i]` is a canonical Goldilocks element (`< p`). All constructors enforce
/// this. Hashing relies on it — `from_canonical_u64`'s non-canonical guard is compiled out in
/// release, so a non-canonical limb would silently reduce mod `p` and diverge from the in-circuit
/// value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GoldilocksSecretKey {
    /// Canonical Goldilocks elements (`0 <= limb < p`).
    limbs: [u64; SECRET_KEY_LEN],
}

impl core::fmt::Debug for GoldilocksSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // INTENTIONALLY SIMPLE: never expose secret-key material.
        f.write_str("GoldilocksSecretKey(<redacted>)")
    }
}

impl GoldilocksSecretKey {
    /// Construct a key from already-canonical Goldilocks limbs.
    ///
    /// Each limb is reduced into the canonical range, so any caller-provided value is accepted.
    pub fn from_limbs(limbs: [u64; SECRET_KEY_LEN]) -> Self {
        let limbs = limbs.map(|x| GoldilocksField::from_noncanonical_u64(x).to_canonical_u64());
        Self { limbs }
    }

    /// Deterministically derive a key from a 32-byte seed (e.g. a CSPRNG output or a KDF).
    ///
    /// The seed is split into four little-endian u64 words, each reduced into Goldilocks. The full
    /// 256-bit seed feeds the 4-limb key, so seed entropy maps to key entropy up to the field
    /// reduction.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut limbs = [0u64; SECRET_KEY_LEN];
        for (limb, chunk) in limbs.iter_mut().zip(seed.chunks_exact(8)) {
            let raw = u64::from_le_bytes(chunk.try_into().unwrap());
            *limb = GoldilocksField::from_noncanonical_u64(raw).to_canonical_u64();
        }
        Self { limbs }
    }

    /// Sample a fresh key from a cryptographically secure RNG.
    ///
    /// SECURITY: the `CryptoRng` bound enforces a CSPRNG at compile time (e.g. `OsRng`, `StdRng`);
    /// key unforgeability depends on `sk` being unpredictable.
    pub fn rand<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut limbs = [0u64; SECRET_KEY_LEN];
        for limb in limbs.iter_mut() {
            // Mirror `PoseidonHashOut::rand`: uniform over [0, p-1).
            *limb = rng.gen_range(0..GoldilocksField::NEG_ONE.0);
        }
        Self { limbs }
    }

    /// The public key `pk = Poseidon([DOMAIN_PK_G] ‖ sk)` as a `PoseidonHashOut`.
    ///
    /// SECURITY (encoding injectivity): the input vector is `[domain(1), sk(SECRET_KEY_LEN)]` — a
    /// **fixed arity**. The Poseidon sponge here is `hash_no_pad` (no length framing), so
    /// injectivity of the `(domain, sk)` → input encoding holds ONLY because the arity is
    /// compile-time-fixed and distinct from `sign`'s arity. Do not feed variable-length inputs
    /// without explicit length framing.
    pub fn public_key_hash_out(&self) -> PoseidonHashOut {
        let mut inputs = Vec::with_capacity(1 + SECRET_KEY_LEN);
        inputs.push(DOMAIN_PK_G as u64);
        inputs.extend_from_slice(&self.limbs);
        PoseidonHashOut::hash_inputs_u64(&inputs)
    }

    /// The public key `pk = Poseidon([DOMAIN_PK_G] ‖ sk)` as the canonical `Bytes32` member
    /// identity.
    pub fn public_key(&self) -> Bytes32 {
        self.public_key_hash_out().into()
    }

    /// The signature over `message`: `sig = Poseidon([DOMAIN_SIG_G] ‖ sk ‖ m)`.
    ///
    /// SECURITY: the returned value is a **private witness** for the Phase-2 single-sig circuit. It
    /// MUST NOT be published, logged, or placed in any proof public input (it is a deterministic
    /// per-`(sk, m)` tag).
    ///
    /// SECURITY (encoding injectivity): the input vector is `[domain(1), sk(SECRET_KEY_LEN),
    /// m(BYTES32 u32 limbs = 8)]` — a fixed arity, distinct from `public_key_hash_out`'s arity.
    /// With the no-pad sponge, soundness of this encoding depends on the message being exactly
    /// a `Bytes32` (8 limbs). A variable-length message MUST introduce explicit length framing.
    pub fn sign(&self, message: Bytes32) -> Bytes32 {
        let msg_limbs = message.to_u32_vec();
        let mut inputs = Vec::with_capacity(1 + SECRET_KEY_LEN + msg_limbs.len());
        inputs.push(DOMAIN_SIG_G as u64);
        inputs.extend_from_slice(&self.limbs);
        inputs.extend(msg_limbs.into_iter().map(u64::from));
        let hash: PoseidonHashOut = PoseidonHashOut::hash_inputs_u64(&inputs);
        hash.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng as _, rngs::StdRng};

    fn sample_message(byte: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_0000 | byte as u32, 1, 2, 3, 4, 5, 6, 7]).unwrap()
    }

    #[test]
    fn determinism_same_inputs_same_outputs() {
        let sk = GoldilocksSecretKey::from_seed([7u8; 32]);
        let m = sample_message(0xaa);
        assert_eq!(sk.public_key(), sk.public_key());
        assert_eq!(sk.sign(m), sk.sign(m));
        // from_limbs of the same canonical limbs reproduces the same key.
        let sk2 = GoldilocksSecretKey::from_seed([7u8; 32]);
        assert_eq!(sk.public_key(), sk2.public_key());
        assert_eq!(sk.sign(m), sk2.sign(m));
    }

    #[test]
    fn distinct_keys_distinct_public_keys() {
        let sk_a = GoldilocksSecretKey::from_seed([1u8; 32]);
        let sk_b = GoldilocksSecretKey::from_seed([2u8; 32]);
        assert_ne!(sk_a.public_key(), sk_b.public_key());
        let m = sample_message(0x01);
        assert_ne!(sk_a.sign(m), sk_b.sign(m));
    }

    #[test]
    fn distinct_messages_distinct_signatures() {
        let sk = GoldilocksSecretKey::from_seed([9u8; 32]);
        let m1 = sample_message(0x10);
        let m2 = sample_message(0x11);
        assert_ne!(m1, m2);
        assert_ne!(sk.sign(m1), sk.sign(m2));
    }

    #[test]
    fn domain_separation_pk_vs_sig() {
        // With DOMAIN_PK_G != DOMAIN_SIG_G, the pk-oracle and sig-oracle are independent: even
        // though `sign` absorbs the same `sk`, no message digest yields `sig == pk`. We
        // additionally check the raw construction: hashing [DOMAIN_PK_G, sk..] vs
        // [DOMAIN_SIG_G, sk..] differ.
        let sk = GoldilocksSecretKey::from_seed([3u8; 32]);
        let mut pk_inputs = vec![DOMAIN_PK_G as u64];
        pk_inputs.extend_from_slice(&sk.limbs);
        let mut sig_inputs = vec![DOMAIN_SIG_G as u64];
        sig_inputs.extend_from_slice(&sk.limbs);
        assert_ne!(
            PoseidonHashOut::hash_inputs_u64(&pk_inputs),
            PoseidonHashOut::hash_inputs_u64(&sig_inputs),
        );
        // And the empty-message signature differs from the public key.
        let zero_msg = Bytes32::from_u32_slice(&[0u32; 8]).unwrap();
        assert_ne!(sk.public_key(), sk.sign(zero_msg));
    }

    #[test]
    fn public_key_is_bytes32_roundtrippable() {
        let sk = GoldilocksSecretKey::from_seed([5u8; 32]);
        let pk = sk.public_key();
        // The pk came from a PoseidonHashOut, so it must round-trip back into one.
        let recovered: PoseidonHashOut = pk.try_into().expect("pk must reduce to a hash out");
        let pk2: Bytes32 = recovered.into();
        assert_eq!(pk, pk2);
        assert_eq!(recovered, sk.public_key_hash_out());
    }

    #[test]
    fn rand_uses_a_csprng() {
        // `StdRng` is a CSPRNG (implements CryptoRng), so this compiles; the bound rejects
        // non-crypto RNGs at compile time. Two draws differ with overwhelming probability.
        let mut rng = StdRng::seed_from_u64(42);
        let a = GoldilocksSecretKey::rand(&mut rng);
        let b = GoldilocksSecretKey::rand(&mut rng);
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn boundary_all_zero_and_max_field_limbs() {
        // Degenerate all-zero sk must not panic and must produce a well-formed pk distinct from a
        // normal key. (Rejecting low-entropy sk is a P2 in-circuit/keygen obligation — see threat
        // model A1 — not enforced here; this only checks robustness.)
        let zero = GoldilocksSecretKey::from_limbs([0; SECRET_KEY_LEN]);
        let normal = GoldilocksSecretKey::from_seed([1u8; 32]);
        assert_ne!(zero.public_key(), normal.public_key());
        let _ = zero.sign(Bytes32::from_u32_slice(&[0u32; 8]).unwrap());

        // Non-canonical u64 limbs reduce mod p, so from_limbs([u64::MAX;4]) must equal the
        // canonical reduction. p = 2^64 - 2^32 + 1, so u64::MAX mod p = u64::MAX - p = 2^32
        // - 2 = 4294967294.
        let from_max = GoldilocksSecretKey::from_limbs([u64::MAX; SECRET_KEY_LEN]);
        let from_reduced = GoldilocksSecretKey::from_limbs([4_294_967_294u64; SECRET_KEY_LEN]);
        assert_eq!(from_max, from_reduced);
        assert_eq!(from_max.public_key(), from_reduced.public_key());
    }

    #[test]
    fn message_first_limb_aliasing_domain_is_not_confused() {
        // A message whose first limb equals a domain word must not collapse pk/sig (cross-protocol
        // confusion pattern, CLAUDE.md §4.4). The fixed arity + distinct domain lane prevent it.
        let sk = GoldilocksSecretKey::from_seed([4u8; 32]);
        let aliasing =
            Bytes32::from_u32_slice(&[DOMAIN_PK_G, DOMAIN_SIG_G, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(sk.public_key(), sk.sign(aliasing));
        // And a different message still yields a different signature.
        let other =
            Bytes32::from_u32_slice(&[DOMAIN_SIG_G, DOMAIN_PK_G, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(sk.sign(aliasing), sk.sign(other));
    }

    #[test]
    fn pk_and_sig_never_coincide_across_arities() {
        // pk has arity 1+4=5 inputs; sig has arity 1+4+8=13. They share the same sk but never
        // collide for any message — this is the invariant the no-pad-sponge fixed-arity
        // encoding must preserve.
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..256 {
            let sk = GoldilocksSecretKey::rand(&mut rng);
            let pk = sk.public_key();
            for byte in 0u8..8 {
                assert_ne!(pk, sk.sign(sample_message(byte)));
            }
        }
    }

    #[test]
    fn debug_is_redacted() {
        let sk = GoldilocksSecretKey::from_seed([0xff; 32]);
        let dbg = format!("{sk:?}");
        assert_eq!(dbg, "GoldilocksSecretKey(<redacted>)");
        // Ensure no raw limb leaked into the debug string.
        for limb in sk.limbs {
            assert!(!dbg.contains(&limb.to_string()));
        }
    }

    #[test]
    fn domain_constants_no_collision() {
        // ASCII sanity.
        assert_eq!(DOMAIN_PK_G, u32::from_be_bytes(*b"IMPG"));
        assert_eq!(DOMAIN_SIG_G, u32::from_be_bytes(*b"IMSG"));
        assert_ne!(DOMAIN_PK_G, DOMAIN_SIG_G);
        // Non-collision against the domain constants defined across the codebase as of P1 —
        // channel.rs, balance_state.rs, close member-set, the Poseidon trees, the regev
        // key/ct domains, the Plonky3 STARK domains, and recipient/user-id. Many of these
        // live in different hash contexts (keccak trees / BabyBear STARK), so a collision
        // there is lower-impact, but the list is kept explicit so a future domain addition
        // that collides with IMPG/IMSG trips this test. Values cross-checked by
        // grep against the source tree.
        const EXISTING: &[u32] = &[
            0x494d_4348, // IMCH CHANNEL_STATE_DOMAIN
            0x494d_5041, // IMPA PAY_DOMAIN
            0x494d_5342, // IMSB SMALL_BLOCK_DOMAIN
            0x494d_5353, // IMSS SIGNED_SMALL_BLOCK_DOMAIN
            0x494d_4954, // IMIT INTER_CHANNEL_TX_DOMAIN
            0x494d_434c, // IMCL CLOSE_TX_DOMAIN
            0x494d_4349, // IMCI CLOSE_INTENT_DOMAIN
            0x494d_5343, // IMSC SPECIAL_CLOSE_DOMAIN
            0x494d_434e, // IMCN CANCEL_CLOSE_DOMAIN
            0x494d_4350, // IMCP POST_CLOSE_CLAIM_DOMAIN
            0x494d_4357, // IMCW WITHDRAWAL_CLAIM_DOMAIN
            0x494d_5546, // IMUF CHANNEL_BALANCE_LEAF_DOMAIN
            0x494d_4352, // IMCR CHANNEL_RECORD_DOMAIN
            0x494d_434d, // IMCM CLOSE_MEMBER_SET_DOMAIN
            0x494d_4253, // IMBS BALANCE_STATE_DOMAIN
            0x494d_534c, // IMSL BALANCE_SLOT_LEAF_DOMAIN
            0x494d_4248, // IMBH BALANCE_STATE_HASH_DOMAIN
            0x494d_544c, // IMTL TX_LEAF_DOMAIN
            0x494d_5443, // IMTC SETTLED_TX_CHAIN_DOMAIN
            0x494d_5243, // IMRC REGEV_CT_DOMAIN
            0x494d_5250, // IMRP REGEV_PK_POSEIDON_DOMAIN
            0x494d_5252, // IMRR REGEV_PK_ROOT_DOMAIN
            0x494d_524b, // IMRK REGEV_PK_DOMAIN
            0x494d_435a, // IMCZ CHANNEL_TX_ZKP_DOMAIN
            0x494d_555a, // IMUZ CHANNEL_UPDATE_ZKP_DOMAIN
            0x494d_575a, // IMWZ WITHDRAW_CLAIM_ZKP_DOMAIN
            0x494d_5246, // IMRF BALANCE_REFRESH_ZKP_DOMAIN
            0x4d42_4c46, // MBLF MEMBER_LEAF_DOMAIN
            0x4348_4c46, // CHLF CHANNEL_LEAF_DOMAIN
            0x5549_4400, // "UID\0" USER_ID_DOMAIN
        ];
        for &d in EXISTING {
            assert_ne!(
                DOMAIN_PK_G, d,
                "DOMAIN_PK_G collides with existing domain {d:#010x}"
            );
            assert_ne!(
                DOMAIN_SIG_G, d,
                "DOMAIN_SIG_G collides with existing domain {d:#010x}"
            );
        }
    }
}
