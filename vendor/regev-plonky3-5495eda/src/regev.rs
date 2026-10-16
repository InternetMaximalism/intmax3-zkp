//! Regev-style Ring-LWE public-key encryption over `R_q = Z_q[x]/(x^n + 1)`
//! with `q` = the BabyBear prime.
//!
//! KeyGen:  `s ← ternary`, `e ← CBD(η)`, `b = a·s + e` for uniform `a`.
//! Encrypt: `r ← ternary`, `e1, e2 ← CBD(η)`,
//!          `c1 = a·r + e1`, `c2 = b·r + e2 + Δ·m` with `m ∈ {0,1}[x]`,
//!          where `Δ = floor(q / t)`, `t = 2^plain_bits`.
//! Decrypt: `v = c2 − c1·s = Δ·m + (e·r − e1·s + e2)`; round each
//!          coefficient to the nearest multiple of `Δ`, giving a **digit**
//!          in `[0, t)` per coefficient.
//!
//! # Additive homomorphism (value level)
//!
//! Ciphertext addition is coefficient-wise; since each plaintext slot has
//! digit headroom `t` (not just `{0,1}`), sums do **not** wrap mod 2:
//!
//! ```text
//! decrypt_value(add_ciphertexts(Enc(A), Enc(B))) = A + B
//! ```
//!
//! where values are encoded as little-endian bits over the coefficients
//! ([`encode_value_message`]) and decoded as `Σ dᵢ·2^i` over the digits
//! ([`decrypt_value`]). The bit-weights make this exact without any carry
//! logic: `Σ(aᵢ+bᵢ)2^i = Σaᵢ2^i + Σbᵢ2^i`. Valid for up to `t − 1` stacked
//! additions (per-coefficient digits must stay below `t`).
//!
//! [`encrypt`] also returns an [`EncryptionWitness`] containing everything
//! the STARK prover needs, including the quotient polynomials `k1, k2` of
//! the reduction mod `x^n + 1`:
//!
//! ```text
//! a·r + e1          = c1 + (x^n + 1)·k1      (over Z_q[x], degrees < 2n-1)
//! b·r + e2 + Δ·m    = c2 + (x^n + 1)·k2
//! ```

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField32;
use rand::{Rng, RngExt};

use crate::ntt::full_poly_mul;
use crate::params::RegevParams;

pub type F = BabyBear;

/// Public key: uniform `a` and `b = a·s + e`.
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub a: Vec<F>,
    pub b: Vec<F>,
}

/// Secret key: ternary `s`.
#[derive(Clone, Debug)]
pub struct SecretKey {
    pub s: Vec<i8>,
}

/// A Regev ciphertext `(c1, c2)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub c1: Vec<F>,
    pub c2: Vec<F>,
}

/// Everything the prover needs to show `(c1, c2)` is a well-formed
/// encryption of *some* binary message under `(a, b)`.
#[derive(Clone, Debug)]
pub struct EncryptionWitness {
    /// Ternary encryption randomness, entries in `{-1, 0, 1}`.
    pub r: Vec<i8>,
    /// CBD(2) noise for `c1`, decomposed as `e1 = e1u - e1v`,
    /// `e1u, e1v ∈ {0, 1, 2}`.
    pub e1u: Vec<u8>,
    pub e1v: Vec<u8>,
    /// CBD(2) noise for `c2`, same decomposition.
    pub e2u: Vec<u8>,
    pub e2v: Vec<u8>,
    /// The binary message polynomial.
    pub m: Vec<u8>,
    /// Quotient of `(a·r + e1)` by `x^n + 1` (degree `<= n-2`, padded to n).
    pub k1: Vec<F>,
    /// Quotient of `(b·r + e2 + Δ·m)` by `x^n + 1`.
    pub k2: Vec<F>,
}

/// Map a centered value in `{-2,...,2}` (or ternary) to the field.
#[inline]
pub fn centered_to_field(x: i64) -> F {
    if x >= 0 {
        F::from_u32(x as u32)
    } else {
        -F::from_u32((-x) as u32)
    }
}

/// Lift a field element to its centered representative in `(-q/2, q/2]`.
#[inline]
pub fn field_to_centered(x: F) -> i64 {
    let v = x.as_canonical_u32() as i64;
    let q = BabyBear::ORDER_U32 as i64;
    if v > q / 2 { v - q } else { v }
}

fn sample_ternary<R: Rng>(rng: &mut R, n: usize) -> Vec<i8> {
    (0..n).map(|_| rng.random_range(-1i8..=1)).collect()
}

/// CBD(2) sample, kept as the two non-negative halves `(u, v)` with
/// `u, v ∈ {0, 1, 2}` so the noise `u - v` has a degree-3 smallness proof.
fn sample_cbd2_halves<R: Rng>(rng: &mut R, n: usize) -> (Vec<u8>, Vec<u8>) {
    let mut u = Vec::with_capacity(n);
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let bits: u8 = rng.random();
        u.push((bits & 1) + ((bits >> 1) & 1));
        v.push(((bits >> 2) & 1) + ((bits >> 3) & 1));
    }
    (u, v)
}

fn small_to_field(small: &[i8]) -> Vec<F> {
    small.iter().map(|&x| centered_to_field(x as i64)).collect()
}

fn cbd_to_field(u: &[u8], v: &[u8]) -> Vec<F> {
    u.iter()
        .zip(v)
        .map(|(&u, &v)| centered_to_field(u as i64 - v as i64))
        .collect()
}

/// Result of a full (unreduced) product split into remainder and quotient
/// mod `x^n + 1`: `prod = lo + (x^n + 1)·hi` with `deg(lo) < n`.
fn split_negacyclic(prod: &[F], n: usize) -> (Vec<F>, Vec<F>) {
    debug_assert_eq!(prod.len(), 2 * n);
    let lo: Vec<F> = (0..n).map(|i| prod[i] - prod[n + i]).collect();
    let hi: Vec<F> = (0..n).map(|i| prod[n + i]).collect();
    (lo, hi)
}

pub fn keygen<R: Rng>(rng: &mut R, params: &RegevParams) -> (PublicKey, SecretKey) {
    let n = params.n;
    let a: Vec<F> = (0..n).map(|_| rng.random()).collect();
    let s = sample_ternary(rng, n);
    let (eu, ev) = sample_cbd2_halves(rng, n);
    let e = cbd_to_field(&eu, &ev);

    let s_f = small_to_field(&s);
    let (mut b, _) = split_negacyclic(&full_poly_mul(&a, &s_f), n);
    for (bi, ei) in b.iter_mut().zip(e) {
        *bi += ei;
    }
    (PublicKey { a, b }, SecretKey { s })
}

/// Encrypt a binary message polynomial (length `n`, entries in `{0, 1}`).
pub fn encrypt<R: Rng>(
    rng: &mut R,
    params: &RegevParams,
    pk: &PublicKey,
    m: &[u8],
) -> (Ciphertext, EncryptionWitness) {
    let n = params.n;
    assert_eq!(m.len(), n, "message must have n bits");
    assert!(m.iter().all(|&b| b <= 1), "message must be binary");

    let r = sample_ternary(rng, n);
    let (e1u, e1v) = sample_cbd2_halves(rng, n);
    let (e2u, e2v) = sample_cbd2_halves(rng, n);

    let r_f = small_to_field(&r);
    let e1 = cbd_to_field(&e1u, &e1v);
    let e2 = cbd_to_field(&e2u, &e2v);
    let delta = F::from_u32(params.delta());

    // c1 = a·r + e1 mod (x^n + 1); k1 is the quotient of a·r.
    let (ar_lo, k1) = split_negacyclic(&full_poly_mul(&pk.a, &r_f), n);
    let c1: Vec<F> = ar_lo.iter().zip(&e1).map(|(&x, &e)| x + e).collect();

    // c2 = b·r + e2 + Δ·m mod (x^n + 1); k2 is the quotient of b·r.
    let (br_lo, k2) = split_negacyclic(&full_poly_mul(&pk.b, &r_f), n);
    let c2: Vec<F> = br_lo
        .iter()
        .zip(&e2)
        .zip(m)
        .map(|((&x, &e), &mi)| x + e + delta * F::from_u8(mi))
        .collect();

    (
        Ciphertext { c1, c2 },
        EncryptionWitness {
            r,
            e1u,
            e1v,
            e2u,
            e2v,
            m: m.to_vec(),
            k1,
            k2,
        },
    )
}

/// Decrypt; returns one **digit** in `[0, t)` per coefficient.
///
/// For a fresh ciphertext the digits are the message bits. For a
/// homomorphic sum of `k` ciphertexts the digits are the per-coefficient
/// sums (correct as long as `k < t` and the accumulated noise stays below
/// `Δ/2`).
pub fn decrypt(params: &RegevParams, sk: &SecretKey, ct: &Ciphertext) -> Vec<u8> {
    params.validate();
    let n = params.n;
    let s_f = small_to_field(&sk.s);
    let (c1s, _) = split_negacyclic(&full_poly_mul(&ct.c1, &s_f), n);
    let q = BabyBear::ORDER_U32 as u64;
    let t = params.t() as u64;
    ct.c2
        .iter()
        .zip(c1s)
        .map(|(&c2i, c1si)| {
            let v = (c2i - c1si).as_canonical_u32() as u64;
            // digit = round(v·t/q) mod t  (the mod folds negative noise,
            // which lifts v near q, back to digit 0).
            (((v * t + q / 2) / q) % t) as u8
        })
        .collect()
}

/// Decrypt and decode the value `Σ dᵢ·2^i` from the coefficient digits.
///
/// This is the value-level inverse of [`encode_value_message`] and is
/// additive under [`add_ciphertexts`]. Panics if a nonzero digit sits at a
/// coefficient index too high to fit the result in `u128`.
pub fn decrypt_value(params: &RegevParams, sk: &SecretKey, ct: &Ciphertext) -> u128 {
    let digits = decrypt(params, sk, ct);
    let mut value: u128 = 0;
    for (i, &d) in digits.iter().enumerate() {
        if d != 0 {
            assert!(i < 120, "nonzero digit at coefficient {i}: value overflows u128");
            value += (d as u128) << i;
        }
    }
    value
}

/// Coefficient-wise ciphertext addition: `Enc(A) ⊞ Enc(B)` decrypts to the
/// digit-wise sum, i.e. [`decrypt_value`] yields `A + B` (within the digit
/// and noise budgets — see module docs).
pub fn add_ciphertexts(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    assert_eq!(a.c1.len(), b.c1.len());
    Ciphertext {
        c1: a.c1.iter().zip(&b.c1).map(|(&x, &y)| x + y).collect(),
        c2: a.c2.iter().zip(&b.c2).map(|(&x, &y)| x + y).collect(),
    }
}

/// Encode an integer as a little-endian binary message polynomial of length
/// `n` (the canonical value encoding used by [`decrypt_value`] and the
/// plaintext range proof).
pub fn encode_value_message(value: u64, n: usize) -> Vec<u8> {
    assert!(n >= 64 || value < (1u64 << n), "value does not fit in n bits");
    (0..n)
        .map(|i| if i < 64 { ((value >> i) & 1) as u8 } else { 0 })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let params = RegevParams { n: 256, eta: 2, plain_bits: 8 };
        let mut rng = SmallRng::seed_from_u64(7);
        let (pk, sk) = keygen(&mut rng, &params);
        for _ in 0..10 {
            let m: Vec<u8> = (0..params.n).map(|_| rng.random_range(0..=1)).collect();
            let (ct, _) = encrypt(&mut rng, &params, &pk, &m);
            assert_eq!(decrypt(&params, &sk, &ct), m);
        }
    }

    #[test]
    fn witness_satisfies_ring_identities() {
        let params = RegevParams { n: 128, eta: 2, plain_bits: 8 };
        let mut rng = SmallRng::seed_from_u64(8);
        let (pk, _) = keygen(&mut rng, &params);
        let m: Vec<u8> = (0..params.n).map(|_| rng.random_range(0..=1)).collect();
        let (ct, w) = encrypt(&mut rng, &params, &pk, &m);

        // Check a·r + e1 = c1 + (x^n+1)·k1 as polynomials of degree < 2n.
        let n = params.n;
        let r_f = small_to_field(&w.r);
        let prod = full_poly_mul(&pk.a, &r_f);
        let mut lhs = prod.clone();
        for (l, (u, v)) in lhs.iter_mut().zip(w.e1u.iter().zip(&w.e1v)) {
            *l += centered_to_field(*u as i64 - *v as i64);
        }
        let mut rhs = vec![F::ZERO; 2 * n];
        for (i, (c, k)) in ct.c1.iter().zip(&w.k1).enumerate() {
            rhs[i] += *c + *k;
            rhs[n + i] += *k;
        }
        assert_eq!(lhs, rhs);
    }
}
