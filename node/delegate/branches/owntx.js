'use strict';
// OWN-TX branches (DESIGN.md §4.4/§4.5): generate ZKP locally (WASM), submit for co-signing, then
// VERIFY the co-signed result BEFORE finalizing. A failed verify or withholding routes to exit mode
// (the co-signer is faulty; the delegate must recover on-chain). Refresh is mandatory when
// canSend == false.

const { verifyCosignedStructural } = require('../verify');
const { importPublishedState } = require('./sync');
const dsm = require('../state-machine');
const crypto = require('crypto');

// `undefined`/`null` means the GENESIS position (§N-3) — the same default the WASM `Option<u8>`
// token arguments take.
const GENESIS_TOKEN_SLOT = 0;
function normTokenSlot(t) { return (t === undefined || t === null) ? GENESIS_TOKEN_SLOT : Number(t); }

// SECURITY (§N, TM-13): sendability is per (member, TOKEN). The wallet holds at most one send
// witness, for the position named by `witnessTokenSlot`, and the report's `canSend` refers to THAT
// position only — a genesis-token witness must never be read as authorization to send token 1, or
// the pre-send refresh is skipped and the WASM refuses the send outright. Missing/legacy store
// state counts as NOT sendable: the cost is one extra refresh, and it can never authorize a send
// the wallet would reject.
function witnessBacks(store, tokenSlot) {
  if (store.get('canSend') !== true) return false;
  const w = store.get('witnessTokenSlot');
  if (w === undefined || w === null) return false;
  return Number(w) === normTokenSlot(tokenSlot);
}

// Resolve a BASE token index to this channel's LOCAL position from the last balance report's
// registry view (`balances[] = {tokenSlot, tokenIndex}`). Unknown ⇒ genesis: the WASM resolves the
// base index against the signed registry itself and fails closed on an unregistered token, so this
// only picks which witness to pre-refresh.
function localSlotForTokenIndex(store, tokenIndex) {
  if (tokenIndex === undefined || tokenIndex === null) return GENESIS_TOKEN_SLOT;
  const bal = store.get('balance');
  const rows = (bal && Array.isArray(bal.balances)) ? bal.balances : [];
  const hit = rows.find((e) => e && Number(e.tokenIndex) === Number(tokenIndex));
  return hit ? Number(hit.tokenSlot) : GENESIS_TOKEN_SLOT;
}

async function ensureSendable(ctx, tokenSlot) {
  if (witnessBacks(ctx.store, tokenSlot)) return true;
  await doRefresh({ source: 'api', kind: 'refresh', tokenSlot }, ctx);
  return witnessBacks(ctx.store, tokenSlot);
}

async function doRefresh(event, ctx) {
  const { api, wallet, ch, store, log, sm, raiseSignal } = ctx;
  if (!wallet.available()) { log.warn({ event: 'WASM_UNAVAILABLE_REFRESH', channel: ch.id }); return; }
  sm.signal(dsm.SIGNALS.START_PROVE);
  const prev = store.get('acceptedHead');
  // Multi-token (§N, TM-13): refreshes are per (member, token) — an intent may name the
  // token position (undefined = genesis token 0).
  const rp = wallet.refresh(ctx.slot, event && event.tokenSlot);
  sm.signal(dsm.SIGNALS.SENT);
  let resp;
  try {
    resp = await api.cosignRefresh(ch.id, rp);
  } catch (e) {
    return onWithholdingLike(e, ctx, 'refresh');
  }
  const v = verifyCosignedStructural(rp, resp, prev);
  if (!v.ok) {
    store.set('cosignFault', { op: 'refresh', reason: v.reason, resp });
    log.error({ event: 'COSIGN_INVALID', channel: ch.id, op: 'refresh', reason: v.reason });
    return raiseSignal({ source: 'signal', kind: 'cosign_invalid', reason: v.reason });
  }
  // Recover the complete published snapshot, verify it in WASM, and durably archive its exact
  // `/backing` v2 before acceptedHead advances. A bare co-sign response alone is not sufficient
  // recovery material if the coordinator later withholds the public close proof.
  await importPublishedState(resp.state || resp, ctx);
  sm.signal(dsm.SIGNALS.COSIGN_OK);
  store.set('canSend', true);
  // The refreshed witness backs exactly the position we refreshed (§N/TM-13).
  store.set('witnessTokenSlot', normTokenSlot(event && event.tokenSlot));
  sm.signal(dsm.SIGNALS.SYNCED);
  log.info({ event: 'REFRESH_FINALIZED', channel: ch.id });
}

async function doSend(event, ctx) {
  const { api, wallet, ch, store, log, sm, raiseSignal } = ctx;
  const { toSlot, amount, tokenSlot } = event;
  if (!wallet.available()) { log.warn({ event: 'WASM_UNAVAILABLE_SEND', channel: ch.id }); return; }
  if (!(await ensureSendable(ctx, tokenSlot))) return;
  sm.signal(dsm.SIGNALS.START_PROVE);
  const prev = store.get('acceptedHead');
  const nonce = '0x' + crypto.randomBytes(32).toString('hex');
  // Multi-token (§N-3): tokenSlot (undefined = genesis) selects the moved token position; the
  // WASM wallet signs it into the IMPA-v2 digest and refuses a witness/token mismatch.
  const payload = wallet.send(ctx.slot, toSlot, amount, nonce, tokenSlot);
  sm.signal(dsm.SIGNALS.SENT);
  let resp;
  try { resp = await api.cosign(ch.id, payload); }
  catch (e) { return onWithholdingLike(e, ctx, 'send'); }
  const v = verifyCosignedStructural(payload, resp, prev);
  if (!v.ok) {
    store.set('cosignFault', { op: 'send', reason: v.reason, resp });
    log.error({ event: 'COSIGN_INVALID', channel: ch.id, op: 'send', reason: v.reason });
    return raiseSignal({ source: 'signal', kind: 'cosign_invalid', reason: v.reason });
  }
  await importPublishedState(resp.state || resp, ctx);
  sm.signal(dsm.SIGNALS.COSIGN_OK);
  sm.signal(dsm.SIGNALS.SYNCED);
  log.info({ event: 'SEND_FINALIZED', channel: ch.id, toSlot, amount: String(amount), tokenSlot: tokenSlot === undefined ? 0 : tokenSlot });
}

async function doInterChannelSend(event, ctx) {
  const { api, wallet, ch, store, log, sm, raiseSignal } = ctx;
  const { toChannel, toSlot, amount, destRecipient, tokenIndex, tokenSlot } = event;
  if (!wallet.available()) { log.warn({ event: 'WASM_UNAVAILABLE_INTER', channel: ch.id }); return; }
  // Inter-channel ALWAYS requires a refresh first (W4) — of the position being sent (§N/TM-13).
  await doRefresh({ source: 'api', kind: 'refresh', tokenSlot }, ctx);
  sm.signal(dsm.SIGNALS.START_PROVE);
  // Multi-token (§N-4): tokenIndex is the BASE token index (undefined = the source channel's
  // genesis registry[0]); the WASM wallet resolves it against the source registry fail-closed.
  // The channel counter is not the base account's send cursor. Read the persisted IVC head at
  // prove time; a concurrent winner advances it and makes the co-signer reject this stale proof.
  const baseHead = await api.getBaseHead(ch.id);
  const built = wallet.sendInterChannel(
    toChannel, toSlot, amount, destRecipient, tokenIndex, Number(baseHead.nonce)
  );
  sm.signal(dsm.SIGNALS.SENT);
  let resp;
  try { resp = await api.interChannelSend(ch.id, { debitPayload: built.debit_payload || built.debitPayload, transferDescriptor: built.transfer_descriptor || built.transferDescriptor, tokenIndex }); }
  catch (e) { return onWithholdingLike(e, ctx, 'inter'); }
  // Verify the source head returned extends ours; the destination snapshot is informational.
  const v = verifyCosignedStructural(null, { state: resp.sourceHead }, store.get('acceptedHead'));
  if (!v.ok) {
    store.set('cosignFault', { op: 'inter', reason: v.reason, resp });
    return raiseSignal({ source: 'signal', kind: 'cosign_invalid', reason: v.reason });
  }
  if (resp.sourceHead) {
    await importPublishedState(resp.sourceHead, ctx);
  }
  sm.signal(dsm.SIGNALS.COSIGN_OK);
  sm.signal(dsm.SIGNALS.SYNCED);
  log.info({ event: 'INTER_SEND_FINALIZED', channel: ch.id, toChannel, toSlot, amount: String(amount) });
}

async function doBurn(event, ctx) {
  const { api, wallet, ch, store, log, sm, raiseSignal } = ctx;
  const { amount, l1Address, tokenIndex } = event;
  if (!wallet.available()) { log.warn({ event: 'WASM_UNAVAILABLE_BURN', channel: ch.id }); return; }
  // The burn debits the LOCAL position registered for this BASE token index (§N).
  await ensureSendable(ctx, localSlotForTokenIndex(store, tokenIndex));
  sm.signal(dsm.SIGNALS.START_PROVE);
  // Multi-token (§N): tokenIndex is the burned BASE token (undefined = genesis registry[0]);
  // the resulting L1 partial withdrawal pays out in that asset (IMPW binds tokenIndex).
  const baseHead = await api.getBaseHead(ch.id);
  const built = wallet.burnSend(amount, l1Address, tokenIndex, Number(baseHead.nonce));
  sm.signal(dsm.SIGNALS.SENT);
  let resp;
  try { resp = await api.pwBurn(ch.id, { debitPayload: built.debit_payload || built.debitPayload, transferDescriptor: built.transfer_descriptor || built.transferDescriptor, amount: String(amount), recipient: l1Address, tokenIndex }); }
  catch (e) { return onWithholdingLike(e, ctx, 'burn'); }
  // SIGNER-INDEPENDENT EXIT: the burn is authorized on-chain at the post-burn head (epoch,
  // stateVersion). If that head is not imported (and its exact backing archived) before this
  // delegate ever requests a close, the Manager refuses the close forever with
  // `CloseOlderThanAuthorizedBurn`. So the response MUST carry the cosigned state nested under
  // `state` (never the permissive top-level fallback) and the import is unconditional; any
  // failure is a cosign fault, never a silent "burn done" with a stale acceptedHead.
  if (!resp.state || typeof resp.state !== 'object') {
    const reason = 'burn response carries no nested cosigned state';
    store.set('cosignFault', { op: 'burn', reason, resp });
    return raiseSignal({ source: 'signal', kind: 'cosign_invalid', reason });
  }
  const prevHead = store.get('acceptedHead');
  const v = verifyCosignedStructural(null, { state: resp.state }, prevHead);
  if (!v.ok) {
    store.set('cosignFault', { op: 'burn', reason: v.reason, resp });
    return raiseSignal({ source: 'signal', kind: 'cosign_invalid', reason: v.reason });
  }
  await importPublishedState(resp.state, ctx);
  const burnHead = store.get('acceptedHead');
  if (!burnHead || (prevHead && burnHead.digest === prevHead.digest)) {
    const reason = 'burn head was not adopted as the accepted head after import';
    store.set('cosignFault', { op: 'burn', reason, resp });
    return raiseSignal({ source: 'signal', kind: 'cosign_invalid', reason });
  }
  sm.signal(dsm.SIGNALS.COSIGN_OK);
  // Record the exact head the burn was authorized against so a later close can be checked
  // against this local high-water mark.
  store.upsertTicket({
    id: 'pw_' + Date.now(),
    type: 'partial_withdrawal',
    status: 'burn_done',
    params: {
      amount: String(amount),
      recipient: l1Address,
      tokenIndex: tokenIndex === undefined ? '0' : String(tokenIndex),
      burnHead: {
        digest: burnHead.digest,
        epoch: burnHead.epoch === undefined ? null : Number(burnHead.epoch),
        stateVersion: burnHead.stateVersion === undefined ? null : Number(burnHead.stateVersion),
      },
    },
  });
  sm.signal(dsm.SIGNALS.SYNCED);
  log.info({ event: 'BURN_FINALIZED', channel: ch.id, amount: String(amount) });
}

// A request error: distinguish a 4xx "does not extend head" (retryable race) from withholding.
async function onWithholdingLike(err, ctx, op) {
  const { ch, store, log, raiseSignal } = ctx;
  const msg = String(err && err.message || err);
  const retries = (store.get('cosignRetries') || 0) + 1;
  store.set('cosignRetries', retries);
  const max = (ctx.policy && ctx.policy.maxCosignRetries) || 3;
  if (/extend|head|stale/i.test(msg) && retries <= 1) {
    // Likely a racing head — re-sync and let the caller retry once.
    log.warn({ event: 'COSIGN_RETRY', channel: ch.id, op, reason: msg });
    return { retry: true };
  }
  if (retries > max) {
    log.error({ event: 'COSIGNER_WITHHOLDING', channel: ch.id, op, retries });
    return raiseSignal({ source: 'signal', kind: 'withholding', reason: msg });
  }
  log.warn({ event: 'COSIGN_TRANSIENT', channel: ch.id, op, retries, reason: msg });
}

module.exports = { doSend, doRefresh, doInterChannelSend, doBurn, ensureSendable, witnessBacks, localSlotForTokenIndex };
