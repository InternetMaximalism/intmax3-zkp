'use strict';
// OWN-TX branches (DESIGN.md §4.4/§4.5): generate ZKP locally (WASM), submit for co-signing, then
// VERIFY the co-signed result BEFORE finalizing. A failed verify or withholding routes to exit mode
// (the co-signer is faulty; the delegate must recover on-chain). Refresh is mandatory when
// canSend == false.

const { verifyCosignedStructural } = require('../verify');
const { headOf } = require('./sync');
const dsm = require('../state-machine');
const crypto = require('crypto');

async function ensureSendable(ctx) {
  if (ctx.store.get('canSend')) return true;
  await doRefresh({ source: 'api', kind: 'refresh' }, ctx);
  return ctx.store.get('canSend');
}

async function doRefresh(event, ctx) {
  const { api, wallet, ch, store, log, sm, raiseSignal } = ctx;
  if (!wallet.available()) { log.warn({ event: 'WASM_UNAVAILABLE_REFRESH', channel: ch.id }); return; }
  sm.signal(dsm.SIGNALS.START_PROVE);
  const prev = store.get('acceptedHead');
  const rp = wallet.refresh(ctx.slot);
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
  if (wallet.available()) { wallet.cosignVerify(ctx.slot, resp.state || resp); wallet.finalize(resp); }
  sm.signal(dsm.SIGNALS.COSIGN_OK);
  store.set('canSend', true);
  store.set('acceptedHead', headOf({ state: resp.state || resp }));
  sm.signal(dsm.SIGNALS.SYNCED);
  log.info({ event: 'REFRESH_FINALIZED', channel: ch.id });
}

async function doSend(event, ctx) {
  const { api, wallet, ch, store, log, sm, raiseSignal } = ctx;
  const { toSlot, amount } = event;
  if (!wallet.available()) { log.warn({ event: 'WASM_UNAVAILABLE_SEND', channel: ch.id }); return; }
  if (!(await ensureSendable(ctx))) return;
  sm.signal(dsm.SIGNALS.START_PROVE);
  const prev = store.get('acceptedHead');
  const nonce = '0x' + crypto.randomBytes(32).toString('hex');
  const payload = wallet.send(ctx.slot, toSlot, amount, nonce);
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
  wallet.cosignVerify(ctx.slot, resp.state || resp);
  wallet.finalize(resp);
  sm.signal(dsm.SIGNALS.COSIGN_OK);
  store.set('acceptedHead', headOf({ state: resp.state || resp }));
  sm.signal(dsm.SIGNALS.SYNCED);
  log.info({ event: 'SEND_FINALIZED', channel: ch.id, toSlot, amount: String(amount) });
}

async function doInterChannelSend(event, ctx) {
  const { api, wallet, ch, store, log, sm, raiseSignal } = ctx;
  const { toChannel, toSlot, amount, destRecipient } = event;
  if (!wallet.available()) { log.warn({ event: 'WASM_UNAVAILABLE_INTER', channel: ch.id }); return; }
  // Inter-channel ALWAYS requires a refresh first (W4).
  await doRefresh({ source: 'api', kind: 'refresh' }, ctx);
  sm.signal(dsm.SIGNALS.START_PROVE);
  const built = wallet.sendInterChannel(toChannel, toSlot, amount, destRecipient);
  sm.signal(dsm.SIGNALS.SENT);
  let resp;
  try { resp = await api.interChannelSend(ch.id, { debitPayload: built.debit_payload || built.debitPayload, transferDescriptor: built.transfer_descriptor || built.transferDescriptor }); }
  catch (e) { return onWithholdingLike(e, ctx, 'inter'); }
  // Verify the source head returned extends ours; the destination snapshot is informational.
  const v = verifyCosignedStructural(null, { state: resp.sourceHead }, store.get('acceptedHead'));
  if (!v.ok) {
    store.set('cosignFault', { op: 'inter', reason: v.reason, resp });
    return raiseSignal({ source: 'signal', kind: 'cosign_invalid', reason: v.reason });
  }
  if (resp.sourceHead) {
    // Re-verify the source-head transition cryptographically before committing (review H5).
    wallet.cosignVerify(ctx.slot, resp.sourceHead);
    wallet.finalize({ state: resp.sourceHead });
  }
  sm.signal(dsm.SIGNALS.COSIGN_OK);
  store.set('acceptedHead', headOf({ state: resp.sourceHead }));
  sm.signal(dsm.SIGNALS.SYNCED);
  log.info({ event: 'INTER_SEND_FINALIZED', channel: ch.id, toChannel, toSlot, amount: String(amount) });
}

async function doBurn(event, ctx) {
  const { api, wallet, ch, store, log, sm, raiseSignal } = ctx;
  const { amount, l1Address } = event;
  if (!wallet.available()) { log.warn({ event: 'WASM_UNAVAILABLE_BURN', channel: ch.id }); return; }
  await ensureSendable(ctx);
  sm.signal(dsm.SIGNALS.START_PROVE);
  const built = wallet.burnSend(amount, l1Address);
  sm.signal(dsm.SIGNALS.SENT);
  let resp;
  try { resp = await api.pwBurn(ch.id, { debitPayload: built.debit_payload || built.debitPayload, transferDescriptor: built.transfer_descriptor || built.transferDescriptor, amount: String(amount), recipient: l1Address }); }
  catch (e) { return onWithholdingLike(e, ctx, 'burn'); }
  const v = verifyCosignedStructural(null, resp, store.get('acceptedHead'));
  if (!v.ok) {
    store.set('cosignFault', { op: 'burn', reason: v.reason, resp });
    return raiseSignal({ source: 'signal', kind: 'cosign_invalid', reason: v.reason });
  }
  if (wallet.available() && resp.state) {
    // Re-verify the burn-debit transition cryptographically before committing (review H5).
    wallet.cosignVerify(ctx.slot, resp.state);
    wallet.finalize({ state: resp.state });
  }
  sm.signal(dsm.SIGNALS.COSIGN_OK);
  store.set('acceptedHead', headOf({ state: resp.state }));
  store.upsertTicket({ id: 'pw_' + Date.now(), type: 'partial_withdrawal', status: 'burn_done', params: { amount: String(amount), recipient: l1Address } });
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

module.exports = { doSend, doRefresh, doInterChannelSend, doBurn, ensureSendable };
