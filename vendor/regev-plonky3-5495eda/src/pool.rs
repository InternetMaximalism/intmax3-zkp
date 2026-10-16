//! Rayon thread-pool sizing.
//!
//! The proof traces here are short (height = ring dimension `n`, e.g. 1024),
//! so the per-matrix work that Plonky3 parallelises internally is small.
//! With the default Rayon pool (= number of logical CPUs) the work-stealing
//! and allocation overhead *dominates* on tiny tasks — empirically, proving
//! is ~2× slower at 14 threads than at ~6 (and `sys` time balloons).
//!
//! [`init_thread_pool`] therefore caps the global Rayon pool at a size tuned
//! for these workloads, **unless** the caller has already expressed a
//! preference via `RAYON_NUM_THREADS` (honoured as-is) or built their own
//! global pool (left untouched). Override the cap with `REGEV_PROVE_THREADS`.
//!
//! It is called automatically at the start of every prove/verify entry
//! point, runs at most once, and never panics.
//!
//! # wasm / browser
//!
//! On `wasm32` this is a **no-op**: there is no native thread support, so
//! `rayon::ThreadPoolBuilder::build_global()` cannot spawn workers there, and
//! calling it would race with — and can break — the Web Worker pool that
//! [`wasm-bindgen-rayon`](https://docs.rs/wasm-bindgen-rayon) installs as the
//! global Rayon pool. Browser multithreading is therefore owned entirely by
//! the application: build with the `parallel` feature, call
//! `wasm_bindgen_rayon::init_thread_pool(n)` from a worker *before* proving,
//! and serve with COOP/COEP headers so `SharedArrayBuffer` is available.
//! Plonky3's `par_iter`s then run on that pool with no involvement from here.

#[cfg(not(target_arch = "wasm32"))]
use std::sync::Once;

#[cfg(not(target_arch = "wasm32"))]
static POOL_INIT: Once = Once::new();

/// Default worker-thread count for proving/verification: capped at 6, which
/// is where the internal data-parallelism saturates for `n ≈ 1024..2048`
/// traces on current hardware.
#[cfg(not(target_arch = "wasm32"))]
fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, 6))
        .unwrap_or(4)
}

/// Size the global Rayon pool for STARK proving, once.
///
/// - If `RAYON_NUM_THREADS` is set, do nothing (Rayon already honours it).
/// - Else use `REGEV_PROVE_THREADS` if set, otherwise [`default_threads`].
/// - If a global pool already exists, the build fails harmlessly and the
///   existing pool is used.
pub fn init_thread_pool() {
    // On wasm the global Rayon pool is owned by wasm-bindgen-rayon (Web
    // Workers); native `build_global()` can't spawn there and would conflict.
    #[cfg(target_arch = "wasm32")]
    {
        return;
    }
    #[cfg(not(target_arch = "wasm32"))]
    POOL_INIT.call_once(|| {
        if std::env::var_os("RAYON_NUM_THREADS").is_some() {
            return; // respect the user's explicit choice
        }
        let n = std::env::var("REGEV_PROVE_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or_else(default_threads);
        #[cfg(feature = "parallel")]
        let _ = rayon::ThreadPoolBuilder::new().num_threads(n).build_global();
        #[cfg(not(feature = "parallel"))]
        let _ = n; // no Rayon without the `parallel` feature
    });
}
