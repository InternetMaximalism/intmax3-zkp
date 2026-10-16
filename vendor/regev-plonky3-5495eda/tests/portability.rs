//! Cross-target Fiat-Shamir determinism guard.
//!
//! The native run pins the golden transcript digest. Compiling this same
//! assertion to `wasm32` and getting the *same* golden is what proves a
//! wasm-generated proof and a native verifier agree on the transcript:
//!
//! ```sh
//! cargo test --test portability                 # native
//! wasm-pack test --node -- --test portability   # wasm32 (needs wasm-pack)
//! ```
//!
//! Regression history: building the Poseidon2 permutation from
//! `rand::rngs::SmallRng` made this digest differ on wasm32 (Xoshiro128++)
//! vs native (Xoshiro256++), which surfaced downstream as FRI
//! `InvalidPowWitness` when verifying a wasm proof natively. The canonical
//! compile-time constants fix it; this test fails if that regresses.

use regev_plonky3::portability::{transcript_digest_hex, TRANSCRIPT_DIGEST_HEX};

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn transcript_digest_matches_golden_native() {
    assert_eq!(transcript_digest_hex(), TRANSCRIPT_DIGEST_HEX);
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn transcript_digest_matches_golden_wasm() {
        // Must equal the value the native build produced — otherwise a
        // wasm-built prover/verifier forks the transcript.
        assert_eq!(transcript_digest_hex(), TRANSCRIPT_DIGEST_HEX);
    }
}
