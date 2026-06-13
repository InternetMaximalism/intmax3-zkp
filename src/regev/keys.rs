//! Regev key material for channel members (detail2.md §B-2).
//!
//! Public keys are plain `Vec<u32>` coefficient vectors so they serialize and hash without
//! dragging plonky3 field types across the module boundary. The secret key intentionally has no
//! serde support and never enters any digest.

use serde::{Deserialize, Serialize};

use super::{
    encrypt::RegevError,
    hash_words,
    params::{REGEV_N, REGEV_Q, channel_regev_params},
};
use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _};

/// Domain separator for [`RegevPk::digest`] ("IMRK").
pub const REGEV_PK_DOMAIN: u32 = 0x494d524b;
/// Domain separator for [`regev_pk_root`] ("IMRR").
pub const REGEV_PK_ROOT_DOMAIN: u32 = 0x494d5252;

/// A member's Regev public key: uniform `a` and `b = a·s + e`, both `REGEV_N` coefficients in
/// canonical form (`< REGEV_Q`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RegevPk {
    pub a: Vec<u32>,
    pub b: Vec<u32>,
}

impl RegevPk {
    /// Canonicality / shape check. MUST be called on every key that crosses a trust boundary
    /// (deserialization, digest computation, encryption) before use.
    ///
    /// SECURITY: coefficients are the canonical mod-q representatives. Without this check, two
    /// encodings of the same key (`c` vs `c + q`) would produce two different digests
    /// (malleability finding F1-A/B).
    pub fn validate(&self) -> Result<(), RegevError> {
        if self.a.len() != REGEV_N || self.b.len() != REGEV_N {
            return Err(RegevError::InvalidPk(format!(
                "expected {} coefficients per polynomial, got a: {}, b: {}",
                REGEV_N,
                self.a.len(),
                self.b.len()
            )));
        }
        if let Some(c) = self.a.iter().chain(&self.b).find(|&&c| c >= REGEV_Q) {
            return Err(RegevError::InvalidPk(format!(
                "non-canonical coefficient {c} (>= q = {REGEV_Q})"
            )));
        }
        Ok(())
    }

    /// Keccak digest binding the full key: `hash_words([IMRK, n, a…, b…])`.
    ///
    /// SECURITY: canonicality is enforced in ALL build profiles — a non-canonical coefficient
    /// (`c + q` aliasing `c`) would otherwise produce a second digest for the same key (F1-A
    /// malleability). Callers MUST [`Self::validate`] externally supplied keys at ingestion and
    /// reject them there; reaching this panic means an ingestion boundary failed to do so. Keys
    /// produced by [`channel_keygen`] are canonical by construction.
    pub fn digest(&self) -> Bytes32 {
        assert!(self.validate().is_ok(), "digest() on an invalid RegevPk");
        hash_words(
            &[
                vec![REGEV_PK_DOMAIN, REGEV_N as u32],
                self.a.clone(),
                self.b.clone(),
            ]
            .concat(),
        )
    }
}

/// A member's Regev secret key: ternary `s` with entries in `{-1, 0, 1}`.
///
/// SECURITY: intentionally NOT `Serialize`/`Deserialize` and never part of any digest — the
/// secret key must never leave the member's process through the state, witness, or wire formats
/// of this crate.
#[derive(Clone, Debug)]
pub struct RegevSk {
    pub s: Vec<i8>,
}

/// Generate a fresh channel key pair with the channel parameter set.
///
/// SECURITY: the caller must supply a cryptographically secure RNG (e.g. `rand010::rng()`);
/// deterministic RNGs are acceptable only in tests.
pub fn channel_keygen(rng: &mut impl rand010::Rng) -> (RegevPk, RegevSk) {
    use p3_field_05::PrimeField32;

    let params = channel_regev_params();
    let (pk, sk) = regev_plonky3::keygen(rng, &params);
    let pk = RegevPk {
        a: pk.a.iter().map(|x| x.as_canonical_u32()).collect(),
        b: pk.b.iter().map(|x| x.as_canonical_u32()).collect(),
    };
    (pk, RegevSk { s: sk.s })
}

/// Root digest over all member public keys, in member order:
/// `hash_words([IMRR, len, digest(pk_0)…, digest(pk_{len-1})…])`.
///
/// SECURITY: member order is part of the preimage — swapping two members' keys changes the root,
/// so the L1-anchored root binds each key to its member slot (detail2 §H-1).
pub fn regev_pk_root(pks: &[RegevPk]) -> Bytes32 {
    let mut words = vec![REGEV_PK_ROOT_DOMAIN, pks.len() as u32];
    for pk in pks {
        words.extend(pk.digest().to_u32_vec());
    }
    hash_words(&words)
}

#[cfg(test)]
mod tests {
    use rand010::{SeedableRng, rngs::SmallRng};

    use super::*;

    #[test]
    fn keygen_produces_valid_canonical_keys() {
        let mut rng = SmallRng::seed_from_u64(1);
        let (pk, sk) = channel_keygen(&mut rng);
        pk.validate().unwrap();
        assert_eq!(sk.s.len(), REGEV_N);
        assert!(sk.s.iter().all(|&x| (-1..=1).contains(&x)));
    }

    #[test]
    fn pk_validate_rejects_non_canonical_and_wrong_length() {
        let mut rng = SmallRng::seed_from_u64(2);
        let (pk, _) = channel_keygen(&mut rng);

        let mut bad = pk.clone();
        bad.a[0] = REGEV_Q;
        assert!(bad.validate().is_err());

        let mut bad = pk.clone();
        bad.b[REGEV_N - 1] = REGEV_Q + 5;
        assert!(bad.validate().is_err());

        let mut bad = pk;
        bad.a.pop();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn pk_root_is_deterministic_and_order_sensitive() {
        let mut rng = SmallRng::seed_from_u64(3);
        let (pk0, _) = channel_keygen(&mut rng);
        let (pk1, _) = channel_keygen(&mut rng);
        let (pk2, _) = channel_keygen(&mut rng);

        let members = [pk0.clone(), pk1.clone(), pk2.clone()];
        let root = regev_pk_root(&members);
        assert_eq!(root, regev_pk_root(&members), "root must be deterministic");

        let swapped = [pk1, pk0, pk2];
        assert_ne!(
            root,
            regev_pk_root(&swapped),
            "member order must be part of the root preimage"
        );
        assert_ne!(root, regev_pk_root(&members[..2]));
    }
}
