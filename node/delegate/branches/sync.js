'use strict';
// NORMAL branches for the delegate (DESIGN.md §4.3): import + verify the head, decrypt balance,
// and react to deposits. Head monotonicity is enforced — a regression/equivocation routes to exit.

const { checkHeadMonotonic } = require('../verify');
const dsm = require('../state-machine');

function headOf(snapshot) {
  const st = (snapshot && snapshot.state) || {};
  const bs = st.balance_state || {};
  return { digest: st.digest, epoch: st.epoch || 0, stateVersion: bs.state_version || 0 };
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
    store.set('balance', bal);
    store.set('canSend', !(bal && bal.pending_adds > 0));
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
  store.set('balance', bal);
  store.set('canSend', !(bal && bal.pending_adds > 0));
  log.info({ event: 'BALANCE', channel: ch.id, slot: ctx.slot, balance: bal && bal.balance, canSend: store.get('canSend') });
  return bal;
}

async function awaitImportThenSync(event, ctx) {
  // A deposit landed; the co-signer imports it. Re-sync the snapshot so we pick up the credit.
  ctx.log.info({ event: 'DEPOSIT_SEEN', channel: ctx.ch.id, txHash: event.txHash });
  return importAndVerify({ source: 'api', kind: 'snapshot' }, ctx);
}

module.exports = { importAndVerify, decryptAndReport, awaitImportThenSync, headOf };
