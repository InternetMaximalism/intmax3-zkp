pub mod circuits;
pub mod common;
pub mod constants;
pub mod ethereum_types;
pub mod utils;
pub mod wrapper_config;

#[cfg(target_arch = "wasm32")]
mod wasm_demo;

pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(all(feature = "gpu_merkle", target_arch = "wasm32"))]
use plonky2::hash::merkle_tree_gpu;

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[wasm_bindgen]
pub async fn init_gpu_merkle() -> Result<(), JsValue> {
    #[cfg(all(feature = "gpu_merkle", target_arch = "wasm32"))]
    {
        merkle_tree_gpu::initialize()
            .await
            .map_err(|err| JsValue::from_str(&format!("GPU init failed: {err}")))?;
    }
    Ok(())
}
