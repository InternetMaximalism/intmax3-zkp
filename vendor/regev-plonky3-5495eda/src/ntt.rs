//! Radix-2 NTT over BabyBear, used for fast polynomial multiplication in
//! `Z_q[x]/(x^n + 1)` where `q` is the proof-system field prime.
//!
//! Because the ciphertext modulus equals the STARK field modulus, all ring
//! arithmetic here is *native* field arithmetic — no limb decomposition or
//! modular-reduction gadgets are ever needed, in or out of the circuit.
//!
//! # Precomputed twiddle factors
//!
//! A naive radix-2 NTT recomputes the twiddle factors `w = g^k` on every
//! call (one extra multiply per butterfly, plus a `g^(N/len)` exponentiation
//! per stage). Since keygen/encrypt/decrypt run many transforms of the same
//! size, we instead **precompute the `N/2` roots of unity once per size**
//! (`roots[i] = g^i`) into a thread-local cache and index into them with a
//! per-stage stride. This removes the running `w *= w_len` multiply from the
//! inner loop entirely — about a third of the butterfly's field multiplies.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use p3_baby_bear::BabyBear;
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};

type F = BabyBear;

/// Cached twiddle tables for one transform size: forward roots `g^i`,
/// inverse roots `g^{-i}` (both length `size/2`), and the `1/size` scale.
struct Twiddles {
    fwd: Rc<Vec<F>>,
    inv: Rc<Vec<F>>,
    n_inv: F,
}

thread_local! {
    static TWIDDLE_CACHE: RefCell<HashMap<usize, Twiddles>> = RefCell::new(HashMap::new());
}

fn build_twiddles(size: usize) -> Twiddles {
    let log_size = size.trailing_zeros() as usize;
    assert!(
        log_size <= F::TWO_ADICITY,
        "NTT size exceeds field two-adicity"
    );
    let g = F::two_adic_generator(log_size);
    let g_inv = g.inverse();
    let half = size / 2;

    let mut fwd = Vec::with_capacity(half);
    let mut inv = Vec::with_capacity(half);
    let (mut wf, mut wi) = (F::ONE, F::ONE);
    for _ in 0..half {
        fwd.push(wf);
        inv.push(wi);
        wf *= g;
        wi *= g_inv;
    }
    Twiddles {
        fwd: Rc::new(fwd),
        inv: Rc::new(inv),
        n_inv: F::from_usize(size).inverse(),
    }
}

/// Core transform: bit-reverse then radix-2 butterflies indexing into a
/// precomputed `roots` table (`roots[i] = g^i`, stride `size/len` per stage).
fn transform(values: &mut [F], roots: &[F]) {
    let n = values.len();
    let log_n = n.trailing_zeros() as usize;

    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS as usize - log_n);
        if i < j {
            values.swap(i, j);
        }
    }

    let mut len = 2;
    while len <= n {
        let stride = n / len;
        let half = len / 2;
        for start in (0..n).step_by(len) {
            for k in 0..half {
                let w = roots[k * stride];
                let u = values[start + k];
                let v = values[start + k + half] * w;
                values[start + k] = u + v;
                values[start + k + half] = u - v;
            }
        }
        len <<= 1;
    }
}

/// In-place iterative Cooley-Tukey NTT (decimation in time) with cached
/// twiddles. `values.len()` must be a power of two `≤ 2^F::TWO_ADICITY`.
/// If `inverse`, applies the inverse transform including the `1/N` scaling.
pub fn ntt(values: &mut [F], inverse: bool) {
    let n = values.len();
    assert!(n.is_power_of_two(), "NTT size must be a power of two");

    let (roots, n_inv) = TWIDDLE_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let tw = cache.entry(n).or_insert_with(|| build_twiddles(n));
        let roots = if inverse { tw.inv.clone() } else { tw.fwd.clone() };
        (roots, tw.n_inv)
    });

    transform(values, &roots);

    if inverse {
        for v in values.iter_mut() {
            *v *= n_inv;
        }
    }
}

/// Full product of two polynomials with coefficients `a` and `b` (degree
/// `< n` each), returned as `2n` coefficients (the top coefficient is zero).
///
/// Uses a size-`2n` cyclic NTT on zero-padded inputs, which is exact because
/// `deg(a*b) <= 2n - 2 < 2n`.
pub fn full_poly_mul(a: &[F], b: &[F]) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    let size = 2 * n;

    let mut fa = vec![F::ZERO; size];
    let mut fb = vec![F::ZERO; size];
    fa[..n].copy_from_slice(a);
    fb[..n].copy_from_slice(b);

    ntt(&mut fa, false);
    ntt(&mut fb, false);
    for (x, y) in fa.iter_mut().zip(fb.iter()) {
        *x *= *y;
    }
    ntt(&mut fa, true);
    fa
}

/// Schoolbook negacyclic product, for testing the NTT path.
#[cfg(test)]
pub fn negacyclic_mul_naive(a: &[F], b: &[F]) -> Vec<F> {
    let n = a.len();
    let mut out = vec![F::ZERO; n];
    for i in 0..n {
        for j in 0..n {
            let prod = a[i] * b[j];
            if i + j < n {
                out[i + j] += prod;
            } else {
                out[i + j - n] -= prod;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    #[test]
    fn ntt_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(0);
        let original: Vec<F> = (0..256).map(|_| rng.random()).collect();
        let mut values = original.clone();
        ntt(&mut values, false);
        ntt(&mut values, true);
        assert_eq!(values, original);
    }

    #[test]
    fn full_mul_matches_naive_negacyclic() {
        let mut rng = SmallRng::seed_from_u64(1);
        let n = 64;
        let a: Vec<F> = (0..n).map(|_| rng.random()).collect();
        let b: Vec<F> = (0..n).map(|_| rng.random()).collect();
        let full = full_poly_mul(&a, &b);
        let expected = negacyclic_mul_naive(&a, &b);
        let reduced: Vec<F> = (0..n).map(|i| full[i] - full[n + i]).collect();
        assert_eq!(reduced, expected);
        assert_eq!(full[2 * n - 1], F::ZERO);
    }
}
