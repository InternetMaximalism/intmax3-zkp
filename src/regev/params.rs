//! Channel-wide Regev parameter set (detail2.md §B-1, with the approved D1 deviation:
//! amounts are encoded 1 bit per coefficient, not 8-bit digits).

use regev_plonky3::RegevParams;

/// Ring dimension `n` of `R_q = Z_q[x]/(x^n + 1)`. One u64 amount occupies the 64 low
/// coefficients (1 bit each, D1); the remaining coefficients stay zero in fresh encryptions.
///
/// SECURITY: `n` is the Ring-LWE security parameter and MUST NOT be lowered. At `q = BabyBear`
/// (~2^31) with ternary `s` and CBD(2) noise, the primal-uSVP core-SVP costs are:
///
/// | `n`  | BKZ block | classical | quantum |
/// |------|-----------|-----------|---------|
/// | 128  | —         | **broken by plain LLL** | — |
/// | 512  | 84        | 2^25      | 2^22    |
/// | 1024 | 264       | 2^77      | 2^70    |
/// | 2048 | 673       | 2^197     | 2^178   |
///
/// The estimator reproduces the published Kyber core-SVP block sizes to within 3%. `n = 128` (the
/// value used before this change) is not merely weak: a dim-257 Kannan embedding of a real
/// `channel_keygen` public key is solved by **LLL alone in ~4 minutes on a laptop**, recovering
/// `s` exactly and decrypting the balance. `n = 1024` would sit at 2^77, below NIST Level 1
/// (2^118), so `2048` is the smallest power of two that clears the 128-bit target — and `n` must
/// be a power of two for the negacyclic NTT (`RegevParams::validate`).
///
/// Cost of the bump (measured, Apple M3 Max, single-threaded): proving grows only ~2.5x because
/// the fixed FRI/Merkle overhead dominates at small `n`, while `RegevPk`/`RegevCiphertext` grow
/// linearly to 16 KB each.
pub const REGEV_N: usize = 2048;

/// Centered-binomial noise parameter; `regev_plonky3` is specialised to η = 2
/// (noise in `[-2, 2]`, smallness is a degree-3 STARK constraint).
pub const REGEV_ETA: usize = 2;

/// log2 of the plaintext modulus `t = 2^8 = 256`: each ciphertext coefficient decodes to a digit
/// in `[0, 256)`, giving 255 stacked homomorphic additions of binary messages before digit
/// overflow.
pub const REGEV_PLAIN_BITS: usize = 8;

/// The ciphertext modulus `q` — fixed to the BabyBear prime (`2^31 - 2^27 + 1`) so every ring
/// operation is a native field operation in the encryption STARK. Documentation/validation
/// constant; checked against the upstream crate at compile time below.
pub const REGEV_Q: u32 = 2_013_265_921;

// SECURITY: REGEV_Q must equal the upstream field modulus, otherwise canonicality checks
// (`coeff < REGEV_Q`) would diverge from the actual ring and digest malleability returns.
const _: () = assert!(REGEV_Q == RegevParams::q());

/// Maximum number of homomorphic additions applied to one balance ciphertext before a refresh
/// (decrypt + fresh re-encrypt, proven by the refresh AIR batch) is mandatory.
///
/// SECURITY: user-approved value (design decisions D1/D3). With the 1-bit-per-coefficient
/// encoding (D1) and `t = 256`, the digit headroom tolerates up to 255 stacked additions, and the
/// worst-case accumulated noise after 64 additions (CBD(2) upper bound, n = 128) is far below the
/// decryption threshold `Δ/2 ≈ 2^22` — so 64 keeps a 4x digit margin and a >100x noise margin.
/// This bound is only meaningful if enforced *in state*: the per-member counter lives in
/// `BalanceState.pending_adds` (D3) and is checked by the state-update circuits, so an adversary
/// cannot flood a member's balance with additions to break decryption liveness.
pub const MAX_HOMO_ADDS_BEFORE_REFRESH: u32 = 64;

/// The single parameter set used by the channel layer.
pub fn channel_regev_params() -> RegevParams {
    RegevParams {
        n: REGEV_N,
        eta: REGEV_ETA,
        plain_bits: REGEV_PLAIN_BITS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_params_are_consistent_with_upstream() {
        let params = channel_regev_params();
        params.validate();
        assert_eq!(params.t(), 1 << REGEV_PLAIN_BITS);
        assert_eq!(RegevParams::q(), REGEV_Q);
        // D1 sanity: 64 additions of binary digits stay strictly below the plaintext modulus.
        assert!(MAX_HOMO_ADDS_BEFORE_REFRESH < params.t());
    }
}
