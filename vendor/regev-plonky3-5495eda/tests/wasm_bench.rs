//! Real wasm32 timing guard for a single Production channel-tx (E-1) proof at
//! the consumer's params (n = 128), single-threaded and scalar (no rayon, no
//! NEON) — the browser worst case. Run under node:
//!
//! ```sh
//! wasm-pack test --release --node --no-default-features --test wasm_bench
//! ```
//!
//! Measured numbers (Apple Silicon, node):
//!   - release wasm, single-thread: ~25 ms/proof
//!   - debug   wasm, single-thread: ~900 ms/proof  (≈36× — never ship debug)
//!
//! So one channel-tx proof is tens of ms in a release browser build. Any
//! multi-second send latency is therefore NOT this computation — it is the
//! environment (a debug build, or a misconfigured wasm-bindgen-rayon worker
//! pool: missing COOP/COEP headers / SharedArrayBuffer, or `initThreadPool`
//! not awaited, which can make Rayon `par_iter` stall in the browser). At
//! 25 ms single-thread, wasm threading is unnecessary for this proof.
#![cfg(target_arch = "wasm32")]
use rand::rngs::SmallRng;
use rand::SeedableRng;
use regev_plonky3::*;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn production_transfer_n128_is_fast() {
    let params = RegevParams {
        n: 128,
        eta: 2,
        plain_bits: 8,
    };
    let mut rng = SmallRng::seed_from_u64(1);
    let (pk, _) = keygen(&mut rng, &params);
    let n = params.n;
    let (cb, wb) = encrypt(&mut rng, &params, &pk, &encode_value_message(100, n));
    let (cd, wd) = encrypt(&mut rng, &params, &pk, &encode_value_message(30, n));
    let (ca, wa) = encrypt(&mut rng, &params, &pk, &encode_value_message(70, n));
    let t = vec![Transfer { before: cb, delta: cd, after: ca }];
    let w = vec![TransferWitness { before: wb, delta: wd, after: wa }];
    let config = default_config(); // Production (16-bit FRI grinding)

    let _ = prove_transfers(&config, &params, &pk, &t, &w); // warm
    let start = js_sys::Date::now();
    let proof = prove_transfers(&config, &params, &pk, &t, &w);
    let ms = js_sys::Date::now() - start;

    verify_transfers(&config, &params, &pk, &t, &proof).expect("self-verify");

    // Generous bound: passes for release (~25 ms) and even debug (~900 ms),
    // but catches any catastrophic (multi-second) regression — e.g. a
    // platform-dependent transcript or a stalling thread pool.
    assert!(
        ms < 5_000.0,
        "channel-tx (n=128) wasm prove took {ms:.0} ms — expected tens of ms; \
         a multi-second time means a debug build or a broken Rayon/worker setup"
    );
}
