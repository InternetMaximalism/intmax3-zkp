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

// LOCAL token slot (multitoken §N): the wasm arg is `Option<u8>`, so `undefined`/omitted means the
// GENESIS position 0 — that is the back-compat default every pre-multitoken caller relies on.
// SECURITY: validate here rather than letting a non-integer reach wasm-bindgen. The generated glue
// writes the value as a u8, which would TRUNCATE 1.9 to 1 — i.e. silently debit a different token
// position than the caller named. Fail closed instead.
function tokenSlotArg(v) {
  if (v === undefined || v === null) return undefined;
  if (!Number.isInteger(v) || v < 0 || v > 255) throw new Error('invalid token slot: ' + String(v));
  return v;
}

function claimTokenSlot(v) {
  if (!Number.isInteger(v) || v < 0 || v > 9) throw new Error('claim token slot must be an integer in 0..9');
  return v;
}

// Map worker actions to wasm entry points. Each returns a JSON string (or void).
const CALLS = {
  keygen: () => wasm.wallet_keygen(),
  keygenSeeded: (a) => wasm.wallet_keygen_seeded(a.seed),
  // B-1b: `recipient` (the user's L1/MetaMask address) is REQUIRED - it becomes the slot's
  // cosigner-signed leaf-bound exit address (the delegate's only payout binding).
  genesisContribution: (a) => wasm.wallet_genesis_contribution(BigInt(a.balance), a.recipient),
  signState: (a) => wasm.wallet_sign_state(a.slot, a.stateJson),
  importChannel: (a) => wasm.wallet_import_channel(a.snapshotJson),
  balance: () => wasm.wallet_balance(),
  send: (a) => wasm.wallet_send(a.recipientSlot, BigInt(a.amount), tokenSlotArg(a.tokenSlot)),
  slimWire: (a) => wasm.wallet_slim_send_wire(a.payloadJson),
  sendInterChannel: (a) => wasm.wallet_send_inter_channel(
    a.toChannel, a.toSlot, BigInt(a.amount), a.destRecipientJson, a.tokenIndex, a.baseNonce
  ),
  burnSend: (a) => wasm.wallet_burn_send(
    BigInt(a.amount), a.withdrawalAddress, a.tokenIndex, a.baseNonce
  ),
  refresh: (a) => wasm.wallet_refresh(tokenSlotArg(a.tokenSlot)),
  cosign: (a) => wasm.wallet_cosign(a.payloadJson),
  finalize: (a) => wasm.wallet_finalize(a.stateJson),
  // The Regev secret never crosses this worker boundary. Only the public claim tuple and its
  // self-verified MLE/WHIR proof are returned to the page for the keyless calldata handoff.
  withdrawalClaim: (a) => wasm.wallet_withdrawal_claim(
    a.finalizedContextJson, claimTokenSlot(a.tokenSlot)
  ),
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
    post('result', { action, _callId: e.data._callId, result: result ?? '', ms });
  } catch (err) {
    post('error', { action, _callId: e.data._callId, message: String((err && err.message) || err) });
  }
};
