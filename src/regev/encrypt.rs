//! Regev ciphertexts and amount encryption (detail2.md §B-2/§B-3, approved deviation D1:
//! amounts are encoded little-endian, 1 bit per coefficient).

use p3_field_05::{PrimeCharacteristicRing, PrimeField32};
use regev_plonky3::{
    Ciphertext as UpstreamCiphertext, EncryptionWitness, PublicKey as UpstreamPublicKey,
    SecretKey as UpstreamSecretKey, regev::F,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    hash_words,
    keys::{RegevPk, RegevSk},
    params::{REGEV_N, REGEV_Q, channel_regev_params},
};
use crate::ethereum_types::bytes32::Bytes32;

/// Domain separator for [`RegevCiphertext::digest`] ("IMRC").
pub const REGEV_CT_DOMAIN: u32 = 0x494d5243;

#[derive(Debug, Error)]
pub enum RegevError {
    #[error("invalid Regev public key: {0}")]
    InvalidPk(String),

    #[error("invalid Regev secret key: {0}")]
    InvalidSk(String),

    #[error("invalid Regev ciphertext: {0}")]
    InvalidCiphertext(String),

    #[error("decrypted value does not fit in u64 (digit/noise budget exceeded?)")]
    DecryptOverflow,

    #[error("invalid Regev STARK witness: {0}")]
    InvalidWitness(String),

    #[error("Regev proof encoding/decoding failed: {0}")]
    ProofCodec(String),

    #[error("Regev proof verification failed: {0}")]
    ProofVerification(String),

    #[error("Regev proof purpose/statement mismatch: {0}")]
    PurposeMismatch(String),
}

/// A Regev ciphertext `(c1, c2)`, both `REGEV_N` coefficients in canonical form (`< REGEV_Q`).
///
/// State and public inputs never carry this struct directly — only its [`Self::digest`]
/// (detail2 §B-2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RegevCiphertext {
    pub c1: Vec<u32>,
    pub c2: Vec<u32>,
}

impl RegevCiphertext {
    /// Canonical all-zero ciphertext used as the PADDING slot value in the pad-to-MAX channel
    /// model (slots `member_count..MAX_CHANNEL_MEMBERS`). Unlike `Default::default()` (empty
    /// vecs), this has the correct `REGEV_N` shape and all-zero (canonical) coefficients, so it
    /// passes [`Self::validate`] and has a well-defined [`Self::digest`].
    ///
    /// SECURITY: a padding slot carries no member, so its ciphertext is a fixed public constant —
    /// `digest()` of it is deterministic and identical for every channel's padding slots, which is
    /// exactly what the H1 preimage needs (padding contributes a constant, member_count selects
    /// the active prefix).
    pub fn padding() -> Self {
        Self {
            c1: vec![0u32; REGEV_N],
            c2: vec![0u32; REGEV_N],
        }
    }

    /// Canonicality / shape check. MUST be called on every ciphertext that crosses a trust
    /// boundary (deserialization, digest computation, homomorphic addition, decryption).
    ///
    /// SECURITY: coefficients are the canonical mod-q representatives. Two encodings of the same
    /// ciphertext (`c` vs `c + q`) must not produce two different digests, otherwise the digest
    /// stops being a binding commitment to the ring element (malleability finding F1-A/B).
    pub fn validate(&self) -> Result<(), RegevError> {
        if self.c1.len() != REGEV_N || self.c2.len() != REGEV_N {
            return Err(RegevError::InvalidCiphertext(format!(
                "expected {} coefficients per polynomial, got c1: {}, c2: {}",
                REGEV_N,
                self.c1.len(),
                self.c2.len()
            )));
        }
        if let Some(c) = self.c1.iter().chain(&self.c2).find(|&&c| c >= REGEV_Q) {
            return Err(RegevError::InvalidCiphertext(format!(
                "non-canonical coefficient {c} (>= q = {REGEV_Q})"
            )));
        }
        Ok(())
    }

    /// Keccak digest per detail2 §B-2: `hash_words([IMRC, c1.len(), c1…, c2…])`.
    ///
    /// SECURITY: canonicality is enforced in ALL build profiles — a non-canonical coefficient
    /// (`c + q` aliasing `c`) would otherwise produce a second digest for the same ciphertext
    /// (F1-A malleability), splitting the signed state from the proven state. Callers MUST
    /// [`Self::validate`] externally supplied ciphertexts at ingestion and reject them there;
    /// reaching this panic means an ingestion boundary failed to do so. Ciphertexts produced by
    /// [`encrypt_amount`] / [`add_ciphertexts`] are canonical by construction.
    pub fn digest(&self) -> Bytes32 {
        assert!(
            self.validate().is_ok(),
            "digest() on an invalid RegevCiphertext"
        );
        hash_words(
            &[
                vec![REGEV_CT_DOMAIN, self.c1.len() as u32],
                self.c1.clone(),
                self.c2.clone(),
            ]
            .concat(),
        )
    }
}

/// Sender-private witness of a fresh amount encryption: the plaintext amount plus everything the
/// encryption STARK needs (randomness, noise halves, message bits, negacyclic quotients).
///
/// SECURITY: intentionally NOT `Serialize` — this is STARK witness material that stays with the
/// sender. The `ReceiverWitnessShare` structure of the old SIS layer is deliberately not ported
/// (detail2 §A-1): the receiver learns the amount by decrypting with their own key, not by
/// receiving randomness shares.
#[derive(Clone, Debug)]
pub struct AmountWitness {
    pub amount: u64,
    pub witness: EncryptionWitness,
}

/// Encode a u64 amount as the canonical little-endian binary message polynomial (D1: 1 bit per
/// coefficient over the 64 low coefficients, zero above).
pub fn encode_amount(amount: u64) -> Vec<u8> {
    regev_plonky3::encode_value_message(amount, REGEV_N)
}

/// Encrypt `amount` under a member's public key. The ciphertext goes into state (as a digest);
/// the returned [`AmountWitness`] stays with the sender for the encryption STARK.
pub fn encrypt_amount(
    rng: &mut impl rand010::Rng,
    pk: &RegevPk,
    amount: u64,
) -> Result<(RegevCiphertext, AmountWitness), RegevError> {
    let upstream_pk = to_upstream_pk(pk)?;
    let params = channel_regev_params();
    let message = encode_amount(amount);
    let (ct, witness) = regev_plonky3::encrypt(rng, &params, &upstream_pk, &message);
    Ok((from_upstream_ct(&ct), AmountWitness { amount, witness }))
}

/// Decrypt a balance/amount ciphertext and decode the value `Σ dᵢ·2^i` from the per-coefficient
/// digits. Works for fresh encryptions and for homomorphic sums within the digit/noise budget
/// (see `MAX_HOMO_ADDS_BEFORE_REFRESH`).
pub fn decrypt_amount(sk: &RegevSk, ct: &RegevCiphertext) -> Result<u64, RegevError> {
    if sk.s.len() != REGEV_N {
        return Err(RegevError::InvalidSk(format!(
            "expected {} coefficients, got {}",
            REGEV_N,
            sk.s.len()
        )));
    }
    let upstream_ct = to_upstream_ct(ct)?;
    let params = channel_regev_params();
    let upstream_sk = UpstreamSecretKey { s: sk.s.clone() };
    // Decode the digits ourselves instead of calling `regev_plonky3::decrypt_value`: the
    // upstream decoder panics on high nonzero digits, and a panic reachable from an
    // adversarially crafted ciphertext is a DoS vector — we return `DecryptOverflow` instead.
    let digits = regev_plonky3::decrypt(&params, &upstream_sk, &upstream_ct);
    let mut value: u128 = 0;
    for (i, &d) in digits.iter().enumerate() {
        if d == 0 {
            continue;
        }
        if i >= 64 {
            // Any nonzero digit at weight 2^64 or above cannot come from valid u64 amounts.
            return Err(RegevError::DecryptOverflow);
        }
        // Safe in u128: i < 64 and d < 256, so the total stays below 2^72.
        value += (d as u128) << i;
    }
    u64::try_from(value).map_err(|_| RegevError::DecryptOverflow)
}

/// Coefficient-wise homomorphic addition: `decrypt_amount(add_ciphertexts(Enc(A), Enc(B))) =
/// A + B` within the digit/noise budget (detail2 §B-3, D1).
pub fn add_ciphertexts(
    a: &RegevCiphertext,
    b: &RegevCiphertext,
) -> Result<RegevCiphertext, RegevError> {
    a.validate()?;
    b.validate()?;
    // SECURITY: addition is done in u64 with an explicit `% REGEV_Q` so the result is always the
    // canonical representative — the sum of two canonical coefficients is < 2q, never wraps u64,
    // and reduces to exactly one canonical value.
    let add = |x: &[u32], y: &[u32]| -> Vec<u32> {
        x.iter()
            .zip(y)
            .map(|(&x, &y)| ((x as u64 + y as u64) % REGEV_Q as u64) as u32)
            .collect()
    };
    Ok(RegevCiphertext {
        c1: add(&a.c1, &b.c1),
        c2: add(&a.c2, &b.c2),
    })
}

/// Convert a validated public key into the upstream field representation.
/// Rejects non-canonical input via [`RegevPk::validate`] on the way in.
pub(crate) fn to_upstream_pk(pk: &RegevPk) -> Result<UpstreamPublicKey, RegevError> {
    pk.validate()?;
    Ok(UpstreamPublicKey {
        a: pk.a.iter().map(|&x| F::from_u32(x)).collect(),
        b: pk.b.iter().map(|&x| F::from_u32(x)).collect(),
    })
}

/// Convert a validated ciphertext into the upstream field representation.
/// Rejects non-canonical input via [`RegevCiphertext::validate`] on the way in.
pub(crate) fn to_upstream_ct(ct: &RegevCiphertext) -> Result<UpstreamCiphertext, RegevError> {
    ct.validate()?;
    Ok(UpstreamCiphertext {
        c1: ct.c1.iter().map(|&x| F::from_u32(x)).collect(),
        c2: ct.c2.iter().map(|&x| F::from_u32(x)).collect(),
    })
}

/// Convert an upstream ciphertext back to the canonical u32 representation.
/// `as_canonical_u32` guarantees `coeff < REGEV_Q`.
fn from_upstream_ct(ct: &UpstreamCiphertext) -> RegevCiphertext {
    RegevCiphertext {
        c1: ct.c1.iter().map(|x| x.as_canonical_u32()).collect(),
        c2: ct.c2.iter().map(|x| x.as_canonical_u32()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use rand010::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::regev::{MAX_HOMO_ADDS_BEFORE_REFRESH, channel_keygen};

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(10);
        let (pk, sk) = channel_keygen(&mut rng);
        for amount in [0u64, 1, 2, 255, 1 << 32, u64::MAX - 1, u64::MAX] {
            let (ct, witness) = encrypt_amount(&mut rng, &pk, amount).unwrap();
            ct.validate().unwrap();
            assert_eq!(witness.amount, amount);
            assert_eq!(witness.witness.m, encode_amount(amount));
            assert_eq!(decrypt_amount(&sk, &ct).unwrap(), amount);
        }
    }

    #[test]
    fn decrypt_with_wrong_key_does_not_return_the_amount() {
        let mut rng = SmallRng::seed_from_u64(11);
        let (pk, _) = channel_keygen(&mut rng);
        let (_, wrong_sk) = channel_keygen(&mut rng);
        let amount = 123_456_789u64;
        let (ct, _) = encrypt_amount(&mut rng, &pk, amount).unwrap();
        // Wrong-key decryption yields garbage digits: either a decode error or a wrong value.
        match decrypt_amount(&wrong_sk, &ct) {
            Ok(v) => assert_ne!(v, amount),
            Err(RegevError::DecryptOverflow) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn homomorphic_addition_decrypts_to_sum() {
        let mut rng = SmallRng::seed_from_u64(12);
        let (pk, sk) = channel_keygen(&mut rng);
        let (a, b) = (3_000_000_007u64, 99_999_999_999u64);
        let (ct_a, _) = encrypt_amount(&mut rng, &pk, a).unwrap();
        let (ct_b, _) = encrypt_amount(&mut rng, &pk, b).unwrap();
        let sum = add_ciphertexts(&ct_a, &ct_b).unwrap();
        sum.validate().unwrap();
        assert_eq!(decrypt_amount(&sk, &sum).unwrap(), a + b);
    }

    /// D1 validation: `MAX_HOMO_ADDS_BEFORE_REFRESH` stacked additions of all-ones bit patterns
    /// (every encoded bit = 1, so per-coefficient digits reach 64) still decrypt correctly —
    /// digits stay below t = 256 and accumulated noise stays below Δ/2.
    #[test]
    fn sixty_four_stacked_additions_of_max_digit_amounts_decrypt() {
        let mut rng = SmallRng::seed_from_u64(13);
        let (pk, sk) = channel_keygen(&mut rng);

        // All 32 low bits set: after 64 additions every low coefficient digit is exactly 64.
        let amount = (u32::MAX) as u64;
        let (mut acc, _) = encrypt_amount(&mut rng, &pk, amount).unwrap();
        for _ in 1..MAX_HOMO_ADDS_BEFORE_REFRESH {
            let (ct, _) = encrypt_amount(&mut rng, &pk, amount).unwrap();
            acc = add_ciphertexts(&acc, &ct).unwrap();
        }
        assert_eq!(
            decrypt_amount(&sk, &acc).unwrap(),
            amount * MAX_HOMO_ADDS_BEFORE_REFRESH as u64
        );
    }

    /// D1 validation with full-width values: 64 additions of distinct ~2^57 amounts whose sum
    /// stays within u64.
    #[test]
    fn sixty_four_stacked_additions_of_wide_amounts_decrypt() {
        let mut rng = SmallRng::seed_from_u64(14);
        let (pk, sk) = channel_keygen(&mut rng);

        let amounts: Vec<u64> = (0..MAX_HOMO_ADDS_BEFORE_REFRESH as u64)
            .map(|i| ((1u64 << 57) + 0x0123_4567_89ab_cdef) ^ (i * 0x1111_1111))
            .collect();
        let expected: u64 = amounts.iter().sum(); // ~2^63, fits u64.

        let (mut acc, _) = encrypt_amount(&mut rng, &pk, amounts[0]).unwrap();
        for &amount in &amounts[1..] {
            let (ct, _) = encrypt_amount(&mut rng, &pk, amount).unwrap();
            acc = add_ciphertexts(&acc, &ct).unwrap();
        }
        assert_eq!(decrypt_amount(&sk, &acc).unwrap(), expected);
    }

    /// Golden-value test pinning the digest preimage layout ([IMRC, len, c1…, c2…] over
    /// solidity-packed keccak). If this changes, every on-chain and in-circuit digest changes.
    #[test]
    fn digest_is_stable() {
        let ct = RegevCiphertext {
            c1: (0..REGEV_N as u32).collect(),
            c2: (0..REGEV_N as u32).map(|i| 1000 + i).collect(),
        };
        assert_eq!(
            ct.digest().to_string(),
            "0xf78243d1742012fe293047b153e0b7b9abac51f1b37b2993674c037f88048fa9"
        );
    }

    #[test]
    fn non_canonical_ciphertexts_are_rejected_everywhere() {
        let mut rng = SmallRng::seed_from_u64(15);
        let (pk, sk) = channel_keygen(&mut rng);
        let (good, _) = encrypt_amount(&mut rng, &pk, 42).unwrap();

        // Coefficient exactly q.
        let mut bad = good.clone();
        bad.c1[0] = REGEV_Q;
        assert!(bad.validate().is_err());
        assert!(matches!(
            decrypt_amount(&sk, &bad),
            Err(RegevError::InvalidCiphertext(_))
        ));
        assert!(add_ciphertexts(&bad, &good).is_err());
        assert!(add_ciphertexts(&good, &bad).is_err());

        // Coefficient q + small.
        let mut bad = good.clone();
        bad.c2[REGEV_N - 1] = REGEV_Q + 3;
        assert!(bad.validate().is_err());
        assert!(decrypt_amount(&sk, &bad).is_err());

        // Wrong dimension.
        let mut bad = good.clone();
        bad.c1.push(0);
        assert!(bad.validate().is_err());
        assert!(add_ciphertexts(&bad, &good).is_err());

        // Non-canonical pk is rejected by encrypt_amount.
        let mut bad_pk = pk;
        bad_pk.b[7] = REGEV_Q;
        assert!(matches!(
            encrypt_amount(&mut rng, &bad_pk, 1),
            Err(RegevError::InvalidPk(_))
        ));
    }
}
