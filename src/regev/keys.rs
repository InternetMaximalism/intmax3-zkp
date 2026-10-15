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
use crate::{
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
    utils::poseidon_hash_out::PoseidonHashOut,
};

/// Domain separator for [`RegevPk::digest`] ("IMRK").
pub const REGEV_PK_DOMAIN: u32 = 0x494d524b;
/// Domain separator for [`regev_pk_root`] ("IMRR").
pub const REGEV_PK_ROOT_DOMAIN: u32 = 0x494d5252;
/// Domain separator (Goldilocks limb) for [`RegevPk::poseidon_digest`] ("IMRP").
///
/// SECURITY: this is a SEPARATE, Poseidon-native digest used ONLY inside the validity circuit's
/// member tree (`MemberLeaf.regev_pk_digest`). Recomputing the keccak [`RegevPk::digest`] in a
/// recursive STARK is prohibitively expensive, so the in-circuit member binding hashes the raw
/// coefficient vector with Poseidon instead. The off-chain L1 anchor still uses the keccak
/// [`regev_pk_root`]; both are built from the same canonical coefficients at registration (DB).
pub const REGEV_PK_POSEIDON_DOMAIN: u64 = 0x494d5250;

/// Centered-magnitude bound below which a whole key polynomial counts as "small" for
/// [`RegevPk::reject_degenerate`]: `2^20`, far above every term a degenerate opening needs
/// (`Δ`-free terms are ternary/CBD-sized) and far below where a uniform coefficient lands
/// (`q ≈ 2^31`; the chance that all `REGEV_N` coefficients of a uniform polynomial fall within
/// `±2^20` is `2^-10` per coefficient, `2^-20480` overall).
pub const DEGENERATE_SMALL_BOUND: u32 = 1 << 20;

/// A member's Regev public key: uniform `a` and `b = a·s + e`, both `REGEV_N` coefficients in
/// canonical form (`< REGEV_Q`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RegevPk {
    pub a: Vec<u32>,
    pub b: Vec<u32>,
}

impl RegevPk {
    /// Canonical all-zero public key used as the PADDING slot value in the pad-to-MAX channel
    /// model (slots `member_count..MAX_CHANNEL_MEMBERS`). Unlike `Default::default()` (empty
    /// vecs), this has the correct `REGEV_N` shape and all-zero (canonical) coefficients, so it
    /// passes [`Self::validate`] and `regev_pk_root` can hash it. A padding slot carries no
    /// member, so this fixed public constant is appropriate.
    pub fn padding() -> Self {
        Self {
            a: vec![0u32; REGEV_N],
            b: vec![0u32; REGEV_N],
        }
    }

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

    /// Registration-time screen against the trivially recognizable DEGENERATE key family
    /// (2026-10-15 adversarial review): refuses a key whose `a` or `b` is the zero polynomial or
    /// a monomial (at most one nonzero coefficient — e.g. `Δ·1`), a constant multiple of
    /// `1 + x + … + x^{n-1}` (all coefficients equal), or "small" (every centered coefficient
    /// within `±`[`DEGENERATE_SMALL_BOUND`]). A key from [`channel_keygen`] trips none of these
    /// except with negligible probability (`a` is uniform over `Z_q^n`, `b = a·s + e` is
    /// Ring-LWE pseudorandom), so an honest wallet is never refused. [`Self::padding`] IS
    /// refused: it is the padding-slot constant and must never be registered for a member.
    ///
    /// SECURITY (what this is NOT — and why it is not load-bearing): this is NOT a
    /// well-formedness proof, and no native test on `(a, b)` can be one. An encryption-witnessed
    /// opening `c1 = a·r + e1, c2 = b·r + e2 + Δ·m` of the all-zero ciphertext to a nonzero `m`
    /// only needs `a·r ≡ -e1` and `b·r ≡ -(e2 + Δ·m)` for a ternary `r` and CBD-small `e1, e2`.
    /// For `(a, b) = (0, Δ·1)` that is `r = -m`, which this screen catches; but for ANY ternary
    /// `r` that is a unit of `Z_q[x]/(x^n + 1)` the pair `a = -e1·r^{-1}`, `b = -(e2 + Δ·m)·r^{-1}`
    /// satisfies the same identities and is indistinguishable from a uniform key by any
    /// coefficient statistic. The load-bearing fix is therefore at the relying parties: they
    /// accept ONLY the decrypted proof purposes, whose AIR binds `b = a·s + e_pk` in-proof
    /// (`state_update_verifier::verify_decrypted_transfer_proof`); under a key with that
    /// binding the zero ciphertext decrypts to 0 for every `s`, so no opening to a nonzero
    /// amount exists. This screen only refuses the keys that would also make the holder's own
    /// decrypted proving impossible, and records the limitation where the key enters.
    pub fn reject_degenerate(&self) -> Result<(), RegevError> {
        self.validate()?;
        for (name, poly) in [("a", &self.a), ("b", &self.b)] {
            let nonzero = poly.iter().filter(|&&c| c != 0).count();
            if nonzero <= 1 {
                return Err(RegevError::InvalidPk(format!(
                    "degenerate key: `{name}` has {nonzero} nonzero coefficient(s) (zero \
                     polynomial or monomial)"
                )));
            }
            if poly.iter().all(|&c| c == poly[0]) {
                return Err(RegevError::InvalidPk(format!(
                    "degenerate key: every coefficient of `{name}` equals {}",
                    poly[0]
                )));
            }
            let small =
                |c: u32| c <= DEGENERATE_SMALL_BOUND || REGEV_Q - c <= DEGENERATE_SMALL_BOUND;
            if poly.iter().all(|&c| small(c)) {
                return Err(RegevError::InvalidPk(format!(
                    "degenerate key: every centered coefficient of `{name}` lies within \
                     ±{DEGENERATE_SMALL_BOUND}"
                )));
            }
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

    /// Poseidon digest over the canonical coefficients, used as the in-circuit member-tree leaf
    /// component: `Poseidon([REGEV_PK_POSEIDON_DOMAIN, n, a…, b…])` (Goldilocks limbs).
    ///
    /// SECURITY: MUST stay byte-identical to the in-circuit recompute in
    /// `circuits::validity::block_hash_chain::update_channel_tree` (same domain, same
    /// length-prefix, same a-then-b coefficient order). Canonicality is enforced (each
    /// coefficient < q < 2^32, so each fits one Goldilocks limb without reduction).
    pub fn poseidon_digest(&self) -> PoseidonHashOut {
        assert!(
            self.validate().is_ok(),
            "poseidon_digest() on an invalid RegevPk"
        );
        let mut inputs = vec![REGEV_PK_POSEIDON_DOMAIN, REGEV_N as u64];
        inputs.extend(self.a.iter().map(|&c| c as u64));
        inputs.extend(self.b.iter().map(|&c| c as u64));
        PoseidonHashOut::hash_inputs_u64(&inputs)
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

    /// `reject_degenerate` admits every honest key and refuses each member of the screened
    /// degenerate family — including the review's `(0, Δ·1)` and its nonzero-`a` relatives that
    /// the earlier "nonzero `a`" registration screen admitted.
    #[test]
    fn reject_degenerate_admits_honest_keys_and_refuses_the_screened_family() {
        let mut rng = SmallRng::seed_from_u64(0xde6e);
        for _ in 0..8 {
            let (pk, _) = channel_keygen(&mut rng);
            pk.reject_degenerate()
                .expect("an honest key is never refused");
        }
        let delta = channel_regev_params().delta();
        let constant = |value: u32| {
            let mut poly = vec![0u32; REGEV_N];
            poly[0] = value;
            poly
        };
        let (honest, _) = channel_keygen(&mut rng);
        let cases: Vec<(&str, RegevPk)> = vec![
            ("padding (a = b = 0)", RegevPk::padding()),
            (
                "(0, Δ·1)",
                RegevPk {
                    a: constant(0),
                    b: constant(delta),
                },
            ),
            (
                "(1, Δ·1)",
                RegevPk {
                    a: constant(1),
                    b: constant(delta),
                },
            ),
            (
                "(2·x^7, Δ·1)",
                RegevPk {
                    a: {
                        let mut a = vec![0u32; REGEV_N];
                        a[7] = 2;
                        a
                    },
                    b: constant(delta),
                },
            ),
            (
                "honest a, monomial b",
                RegevPk {
                    a: honest.a.clone(),
                    b: constant(delta),
                },
            ),
            (
                "all coefficients equal",
                RegevPk {
                    a: honest.a.clone(),
                    b: vec![delta; REGEV_N],
                },
            ),
            (
                "small a (ternary-looking)",
                RegevPk {
                    a: (0..REGEV_N)
                        .map(|i| [1u32, REGEV_Q - 1, 0][i % 3])
                        .collect(),
                    b: honest.b.clone(),
                },
            ),
            (
                "small b (every centered coefficient within the bound)",
                RegevPk {
                    a: honest.a.clone(),
                    b: (0..REGEV_N)
                        .map(|i| {
                            if i % 2 == 0 {
                                i as u32
                            } else {
                                REGEV_Q - i as u32
                            }
                        })
                        .collect(),
                },
            ),
        ];
        for (label, pk) in cases {
            let err = pk
                .reject_degenerate()
                .expect_err(&format!("{label} must be refused"));
            assert!(
                err.to_string().contains("degenerate key"),
                "{label}: unexpected error {err}"
            );
        }
        // Still a canonicality check first: a non-canonical key is refused as such.
        let mut bad = honest;
        bad.a[0] = REGEV_Q;
        assert!(
            !bad.reject_degenerate()
                .unwrap_err()
                .to_string()
                .contains("degenerate key")
        );
    }
}
