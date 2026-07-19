// Phase-0 feasibility worker: confirm regev plonky3 STARK prove+verify runs in wasm under the
// wasm-bindgen-rayon thread pool (init_thread_pool must not panic). Throwaway harness.
let wasm;
self.onmessage = async (e) => {
  if (e.data.action !== 'run') return;
  try {
    wasm = await import('/pkg/intmax3_zkp.js');
    await wasm.default();
    const n = e.data.threads || (navigator.hardwareConcurrency || 4);
    await wasm.initThreadPool(n);
    // `wallet_feasibility_check` is gated behind the `diagnostics` cargo feature
    // (Test-level prover, excluded from the production wallet build). Fail clearly
    // if this wasm was built without it, instead of a cryptic "not a function".
    if (typeof wasm.wallet_feasibility_check !== 'function') {
      self.postMessage({ type: 'error', msg: 'wallet_feasibility_check is not in this build — rebuild the wasm with `--features diagnostics` to run the probe.' });
      return;
    }
    self.postMessage({ type: 'log', msg: `thread pool initialized with ${n} threads; proving…` });
    const t0 = performance.now();
    const result = await wasm.wallet_feasibility_check();
    const ms = (performance.now() - t0).toFixed(0);
    self.postMessage({ type: 'done', msg: `${result} (in ${ms} ms)` });
  } catch (err) {
    self.postMessage({ type: 'error', msg: String(err && err.stack || err) });
  }
};
