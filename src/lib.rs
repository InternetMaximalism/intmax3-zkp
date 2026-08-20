// The vendored Falcon code (src/falcon_sig/vendor, no_std-style upstream) imports via `alloc::`
// paths; this makes the `alloc` crate name resolvable in this (std) crate.
extern crate alloc;

pub mod block_producer;
#[cfg(not(target_arch = "wasm32"))]
pub mod block_producer_service;
pub mod circuits;
pub mod common;
pub mod constants;
pub mod ethereum_types;
pub mod falcon_sig;
#[cfg(not(target_arch = "wasm32"))]
pub mod live_balance_service;
#[cfg(not(target_arch = "wasm32"))]
pub mod partial_withdrawal_payout;
pub mod poseidon_sig;
pub mod regev;
pub mod utils;
#[cfg(not(target_arch = "wasm32"))]
pub mod validity_prover_service;
pub mod wallet_core;
pub mod wrapper_config;

// NOTE: `wasm_demo` is the legacy plonky2 balance-processor browser demo. It is stale on this
// branch — it calls `*_async` proving methods that were removed in the SIS→Regev migration
// (commit 3b60c23) and `include_bytes!`s `tests/fixtures/*.bin` that are not generated — so it
// does not compile for wasm. It is gated behind an off-by-default feature so the (working) wasm
// wallet below can build without modifying the demo file itself. Re-enable with
// `--features legacy_wasm_demo` once the demo is restored.
#[cfg(all(target_arch = "wasm32", feature = "legacy_wasm_demo"))]
mod wasm_demo;

#[cfg(target_arch = "wasm32")]
pub mod wasm_wallet;

pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(all(feature = "gpu_merkle", target_arch = "wasm32"))]
use plonky2::hash::merkle_tree_gpu;

use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

/// SECURITY GATE (falcon-sig Phase-4 review, check 9): the Falcon member identity
/// `pk_g = Poseidon(IMFK || encode(h))` derived from a seed MUST be identical on wasm32 and
/// native, and this export exists so that can be MEASURED rather than argued.
///
/// WHY IT IS MEASURED. NTRU keygen runs f64 arithmetic (FFT, Babai reduction, rejection
/// bounds). The structural argument for determinism is strong — the keygen path uses only
/// IEEE-754 `+ - * / floor round sqrt` over a hardcoded twiddle table, `approx_exp` is integer
/// FACCT rather than `libm::exp`, and Rust neither contracts to FMA nor reassociates without
/// fast-math. But THIS REPOSITORY HAS ALREADY OBSERVED a wasm-vs-native numeric divergence in a
/// proof path: see the note in `.cargo/config.toml` recording that the Regev STARK verifier
/// returns different results on wasm32 and native for identical bytes, and that disabling
/// simd128 did not fix it. A negative claim over a large vendored numeric surface is exactly the
/// kind of argument that failed there, so it is pinned empirically here.
///
/// FAILURE MODE IF IT DIVERGES: a wallet restored (or created) in the browser derives a
/// DIFFERENT `pk_g` from the same seed than the CLI does. The L1 registration then names an
/// identity that wallet cannot reproduce, its co-signatures stop verifying, and the channel
/// becomes permanently unclosable — funds stuck, with no error at the moment of divergence.
#[wasm_bindgen]
pub fn falcon_pk_g_for_seed_byte(seed_byte: u8) -> String {
    let keys = crate::falcon_sig::FalconKeys::from_seed([seed_byte; 32]);
    format!("{}", keys.pk_g())
}

#[wasm_bindgen]
pub async fn init_gpu_merkle() -> Result<bool, JsValue> {
    #[cfg(all(feature = "gpu_merkle", target_arch = "wasm32"))]
    {
        merkle_tree_gpu::initialize()
            .await
            .map_err(|err| JsValue::from_str(&format!("GPU init failed: {err}")))?;
        return Ok(true);
    }
    #[cfg(not(all(feature = "gpu_merkle", target_arch = "wasm32")))]
    Ok(false)
}
