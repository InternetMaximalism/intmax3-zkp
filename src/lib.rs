pub mod circuits;
pub mod common;
pub mod constants;
pub mod ethereum_types;
pub mod poseidon_sig;
pub mod regev;
pub mod utils;
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
