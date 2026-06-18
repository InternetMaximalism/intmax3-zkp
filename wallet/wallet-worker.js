// Web Worker for the browser wallet: initializes the wasm module + the wasm-bindgen-rayon thread
// pool (multithreaded proving), then dispatches wallet_* calls. Mirrors test-worker.js's init.
let wasm = null;

function post(type, payload) {
  self.postMessage({ type, ...payload });
}

// Forward console output to the page log.
for (const level of ['log', 'warn', 'error']) {
  const orig = console[level].bind(console);
  console[level] = (...a) => {
    orig(...a);
    post('log', { level, message: a.map(String).join(' ') });
  };
}

async function init(threads) {
  post('progress', { msg: 'downloading prover (wasm)…' });
  wasm = await import('/pkg/intmax3_zkp.js');
  await wasm.default();
  const n = threads || navigator.hardwareConcurrency || 4;
  post('progress', { msg: `starting ${n} prover threads…` });
  await wasm.initThreadPool(n);
  post('ready', { threads: n });
}

// Map worker actions to wasm entry points. Each returns a JSON string (or void).
const CALLS = {
  keygen: () => wasm.wallet_keygen(),
  keygenSeeded: (a) => wasm.wallet_keygen_seeded(a.seed),
  genesisContribution: (a) => wasm.wallet_genesis_contribution(BigInt(a.balance)),
  signState: (a) => wasm.wallet_sign_state(a.slot, a.stateJson),
  importChannel: (a) => wasm.wallet_import_channel(a.snapshotJson),
  balance: () => wasm.wallet_balance(),
  send: (a) => wasm.wallet_send(a.recipientSlot, BigInt(a.amount)),
  sendInterChannel: (a) => wasm.wallet_send_inter_channel(a.toChannel, a.toSlot, BigInt(a.amount), a.destRecipientJson),
  refresh: () => wasm.wallet_refresh(),
  cosign: (a) => wasm.wallet_cosign(a.payloadJson),
  finalize: (a) => wasm.wallet_finalize(a.stateJson),
};

self.onmessage = async (e) => {
  const { action } = e.data;
  try {
    if (action === 'init') {
      await init(e.data.threads);
      return;
    }
    if (!wasm) throw new Error('wasm not initialized');
    const fn = CALLS[action];
    if (!fn) throw new Error('unknown action: ' + action);
    const t0 = performance.now();
    const result = await fn(e.data);
    const ms = (performance.now() - t0).toFixed(0);
    post('result', { action, result: result ?? '', ms });
  } catch (err) {
    post('error', { action, message: String((err && err.message) || err) });
  }
};
