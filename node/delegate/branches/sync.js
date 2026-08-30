'use strict';
// NORMAL branches for the delegate (DESIGN.md §4.3): import + verify the head, decrypt balance,
// and react to deposits. Head monotonicity is enforced — a regression/equivocation routes to exit.

const { checkHeadMonotonic } = require('../verify');
const dsm = require('../state-machine');
const wire = require('../../common/wire');

function headOf(snapshot) {
  const st = (snapshot && snapshot.state) || {};
  const version = wire.stateVersion(st);
  return { digest: st.digest, epoch: st.epoch || 0, stateVersion: version == null ? 0 : version };
}

// Record a decrypted BalanceReport into the store.
//
// SECURITY: sendability comes from the report's OWN `canSend`. The previous code derived it from
// `bal.pending_adds`, a field `BalanceReport` has never had (it serializes slot / balance /
// canSend / stateVersion / balances[] / witnessTokenSlot) — so the flag was `!(undefined > 0)`,
// i.e. unconditionally true. The mandatory pre-send refresh (owntx.js `ensureSendable`) therefore
// never ran, and a stale witness surfaced as a hard WASM error instead of an automatic refresh.
// The wasm's own `can_send` already encodes the D3 rule that was being reached for: it requires
// `pending_adds[slot][token] == 0` for the witness position (src/wasm_wallet.rs `balance_report`).
//
// Multi-token (§N): the wallet holds at most ONE send witness, for the position named by
// `witnessTokenSlot`, and `canSend` refers to THAT position only — a genesis-token witness does
// not authorize sending token 1. Both fields are stored so sendability can be checked per token.
function recordBalance(store, bal) {
  store.set('balance', bal);
  store.set('canSend', !!(bal && bal.canSend === true));
  const w = bal && bal.witnessTokenSlot;
  store.set('witnessTokenSlot', w === undefined || w === null ? null : Number(w));
}

async function importAndVerify(event, ctx) {
  const { api, wallet, ch, store, log, raiseSignal } = ctx;
  let snapshot = event.snapshot;
  if (!snapshot) snapshot = await api.getSnapshot(ch.id);
  const incoming = headOf(snapshot);

  const prevAccepted = store.get('acceptedHead');
  const mono = checkHeadMonotonic(prevAccepted, incoming);
  if (!mono.ok) {
    // Two conflicting signed heads / regression = member equivocation. Capture evidence + exit.
    store.set('equivocationEvidence', { prevAccepted, incoming, conflicting: snapshot });
    log.error({ event: 'EQUIVOCATION_DETECTED', channel: ch.id, reason: mono.reason });
    return raiseSignal({ source: 'signal', kind: 'equivocation', reason: mono.reason });
  }

  // Import into the WASM session (fails closed on a bad N-of-N signature).
  if (wallet.available()) {
    wallet.importChannel(snapshot, ctx.slot);
    const bal = wallet.balance(ctx.slot);
    recordBalance(store, bal);
    log.info({ event: 'SNAPSHOT_IMPORTED', channel: ch.id, head: incoming, balance: bal && bal.balance });
  } else {
    log.warn({ event: 'WASM_UNAVAILABLE', channel: ch.id, note: 'snapshot accepted structurally; build pkg-node to decrypt' });
  }
  store.set('acceptedHead', incoming);
}

async function decryptAndReport(event, ctx) {
  const { wallet, store, log, ch } = ctx;
  if (!wallet.available()) return log.warn({ event: 'WASM_UNAVAILABLE', channel: ch.id });
  const bal = wallet.balance(ctx.slot);
  recordBalance(store, bal);
  log.info({ event: 'BALANCE', channel: ch.id, slot: ctx.slot, balance: bal && bal.balance, canSend: store.get('canSend') });
  return bal;
}

async function awaitImportThenSync(event, ctx) {
  // A deposit landed; the co-signer imports it. Re-sync the snapshot so we pick up the credit.
  ctx.log.info({ event: 'DEPOSIT_SEEN', channel: ctx.ch.id, txHash: event.txHash });
  return importAndVerify({ source: 'api', kind: 'snapshot' }, ctx);
}

module.exports = { importAndVerify, decryptAndReport, awaitImportThenSync, headOf, recordBalance };
