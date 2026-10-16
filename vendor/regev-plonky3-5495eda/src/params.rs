//! Parameter sets for the Regev (Ring-LWE) scheme.
//!
//! The ciphertext modulus `q` is **fixed to the proof-system field prime**
//! (BabyBear: `q = 2^31 - 2^27 + 1 = 2013265921`). This is the key design
//! decision that makes the encryption proof cheap: every `mod q` operation in
//! the scheme is a native field operation in the STARK.
//!
//! # Plaintext modulus and additive homomorphism
//!
//! Messages are scaled by `Δ = floor(q / t)` where `t = 2^plain_bits` is the
//! plaintext modulus. Fresh encryptions carry *binary* coefficients, but
//! decryption decodes each coefficient to a **digit** in `[0, t)`, so
//! ciphertext addition is value-level additive:
//!
//! ```text
//! decrypt_value(Enc(A) + Enc(B)) = A + B
//! ```
//!
//! as long as (a) no coefficient digit reaches `t` (at most `t − 1` stacked
//! additions of binary messages) and (b) the accumulated noise stays below
//! `Δ/2 ≈ q / 2^(plain_bits+1)`. With the default `plain_bits = 8`, that is
//! up to 255 additions digit-wise and a noise budget of ~`2^22`, several
//! thousand additions noise-wise — digits are the binding constraint.
//!
//! # Security
//!
//! Ring-LWE hardness is governed by the ring dimension `n`, the modulus `q`,
//! and the noise width (`Δ`/`plain_bits` only affect correctness, not
//! security). With `q ≈ 2^31` and centered-binomial noise `CBD(η=2)`
//! (σ = 1), `n = 1024` lands at roughly 2^100 classical core-SVP security —
//! usable, but below the 128-bit target. `n = 2048` gives a comfortable
//! margin. **Run the lattice-estimator on your final parameter choice** (see
//! README) before deploying.

use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;

/// Parameters for the Regev encryption scheme over `Z_q[x]/(x^n + 1)`,
/// with `q` equal to the BabyBear prime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegevParams {
    /// Ring dimension; must be a power of two (it is also the STARK trace
    /// height, so it must satisfy any minimum imposed by the FRI config).
    pub n: usize,
    /// Centered binomial noise parameter; the implementation is specialised
    /// to η = 2 (noise in `[-2, 2]`, decomposed as `u - v` with
    /// `u, v ∈ {0, 1, 2}` so smallness is a degree-3 constraint).
    pub eta: usize,
    /// log2 of the plaintext modulus `t = 2^plain_bits`; `Δ = floor(q / t)`.
    ///
    /// Each ciphertext coefficient holds a digit in `[0, t)`, giving
    /// `t − 1` headroom for homomorphic additions of binary messages.
    /// Must be in `1..=8` (digits are decoded into `u8`).
    pub plain_bits: usize,
}

impl RegevParams {
    /// `n = 1024` as in the design sketch. Re-estimate security before use;
    /// roughly 2^100 classical with ternary secrets and CBD(2) noise.
    pub const N1024: Self = Self {
        n: 1024,
        eta: 2,
        plain_bits: 8,
    };

    /// `n = 2048`, comfortable 128-bit-plus margin at `q ≈ 2^31`.
    pub const N2048: Self = Self {
        n: 2048,
        eta: 2,
        plain_bits: 8,
    };

    /// The ciphertext modulus `q` (the BabyBear prime).
    pub const fn q() -> u32 {
        BabyBear::ORDER_U32
    }

    /// The plaintext modulus `t = 2^plain_bits` (digit headroom per slot).
    pub const fn t(&self) -> u32 {
        1 << self.plain_bits
    }

    /// Message scaling factor `Δ = floor(q / t)`.
    pub const fn delta(&self) -> u32 {
        BabyBear::ORDER_U32 >> self.plain_bits
    }

    /// log2 of the ring dimension.
    pub fn log_n(&self) -> usize {
        debug_assert!(self.n.is_power_of_two());
        self.n.trailing_zeros() as usize
    }

    pub fn validate(&self) {
        assert!(self.n.is_power_of_two(), "n must be a power of two");
        // Key generation, encryption and the AIR are specialised to CBD(2); any other value
        // would be silently ignored while security estimates assumed it (review 2026-10-16).
        assert!(self.eta == 2, "eta must be 2: the implementation is specialised to CBD(2)");
        assert!(
            self.plain_bits >= 1 && self.plain_bits <= 8,
            "plain_bits must be in 1..=8"
        );
    }
}
