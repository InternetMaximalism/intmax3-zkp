//! Cross-target determinism guard for the Fiat-Shamir transcript.
//!
//! A STARK proof verifies on a different machine only if the verifier
//! recomputes a **byte-identical** Fiat-Shamir transcript. That holds as long
//! as the field arithmetic and the Poseidon2 permutation are bit-identical
//! across targets — which they are, *provided the permutation's round
//! constants are themselves target-independent*.
//!
//! # The bug this guards against
//!
//! Building the Poseidon2 permutation from `rand::rngs::SmallRng` is **not**
//! target-independent: `SmallRng` is `Xoshiro256++` on 64-bit platforms and
//! `Xoshiro128++` on 32-bit ones (e.g. `wasm32`). A fixed seed therefore
//! yields *different* round constants on wasm vs native, silently forking the
//! transcript. The first place that surfaces is FRI's proof-of-work check,
//! as `InvalidPowWitness` — a wasm-generated proof fails native verification
//! and vice-versa, even though each self-verifies.
//!
//! The fix ([`crate::config::canonical_perm`]) uses Plonky3's canonical
//! compile-time Poseidon2 constants, so there is no RNG and no width
//! dependence.
//!
//! # Using this as a regression guard
//!
//! [`transcript_digest`] runs a fixed observe/sample script through the exact
//! [`crate::config::Challenger`] the default proof config uses, and returns
//! the sampled bytes. [`TRANSCRIPT_DIGEST_HEX`] is the golden value. The test
//! in `tests/portability.rs` asserts equality on the host target; compiling
//! the same assertion to `wasm32` (e.g. `wasm-pack test --node`) and getting
//! the *same* golden proves the transcript is target-independent. If the
//! permutation ever regresses to an RNG-derived construction, the wasm digest
//! diverges from this golden and the cross-target test fails.

use p3_challenger::{CanObserve, CanSample, CanSampleBits, DuplexChallenger, FieldChallenger};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};

use crate::config::{canonical_perm, Challenge, Val};

/// Golden value of [`transcript_digest`], computed on native aarch64 and
/// reproduced bit-for-bit on `wasm32` once [`crate::config::canonical_perm`]
/// is in use. Any change here means the transcript primitives changed.
pub const TRANSCRIPT_DIGEST_HEX: &str =
    "38f2f01a9f5d7c26f173fa596c67327652d19e24f84267778e06943567df9c3a6c1164107b92e6021881722be5e0bc25b5a2356894e427060e46a96f8a07d20fddcda46df7115d72158eda651de168151900c85e0837e30a597a02066d59ee41f2c80000";

/// Run a fixed Fiat-Shamir script — observe a deterministic sequence of base
/// field elements, then sample base- and extension-field challenges plus a
/// bit challenge (the FRI grinding primitive) — and return the sampled bytes.
///
/// This exercises the Poseidon2 permutation exactly as the prover/verifier
/// transcript does, so its output is a fingerprint of the transcript
/// primitives. It depends on nothing platform-specific *if* the primitives
/// are target-independent.
pub fn transcript_digest() -> Vec<u8> {
    let mut ch = DuplexChallenger::<Val, _, 16, 8>::new(canonical_perm());

    // Observe a deterministic sequence (values are field elements, so their
    // contribution is width-independent by construction).
    for i in 0..50u32 {
        ch.observe(Val::from_u32(i.wrapping_mul(0x0100_0193).wrapping_add(7)));
    }

    let mut out = Vec::new();
    // Base-field samples.
    for _ in 0..8 {
        let s: Val = ch.sample();
        out.extend_from_slice(&s.as_canonical_u32().to_le_bytes());
    }
    // Extension-field samples (challenges are drawn from the quartic extension).
    for _ in 0..4 {
        let e: Challenge = ch.sample_algebra_element();
        let coeffs: &[Val] = e.as_basis_coefficients_slice();
        for c in coeffs {
            out.extend_from_slice(&c.as_canonical_u32().to_le_bytes());
        }
    }
    // FRI grinding primitive: sampling bits must also be target-independent.
    let bits: usize = ch.sample_bits(16);
    out.extend_from_slice(&(bits as u32).to_le_bytes());
    out
}

/// Lowercase hex of [`transcript_digest`].
pub fn transcript_digest_hex() -> String {
    transcript_digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
