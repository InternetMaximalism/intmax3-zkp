'use strict';
// OWN-ACTION + ABNORMAL branches for the close game (DESIGN.md §3.5, §3.7). The co-signer drives
// cooperative close steps it initiated, and reacts defensively to closes observed on-chain that
// froze a STALE state (it holds a strictly-newer N-of-N head ⇒ challenge A29 or cancel A30). The
// on-chain manager + verifier are the ultimate gate (monotonic _isNewer, member-set commitment).

const { SIGNALS } = require('../state-machine');
const policy = require('../../common/policy');
const wire = require('../../common/wire');

// --- OWN: drive cooperative close steps (timer-driven) ---
async function driveCloseStep(event, ctx) {
  const { cli, ch, rpc, store, log } = ctx;
  const step = event.step; // 'finalize'
  if (step === 'finalize') {
    const actionId = `finalize:${ch.id}:${event.closeIntentDigest || ''}`;
    if (!store.claimAction(actionId, { retryPending: true })) return;
    try {
      await cli.run(ch.id, ch.workDir, ['settle', ch.manager, rpc]);
      store.completeAction(actionId, 'ok');
      log.info({ event: 'CLOSE_FINALIZED_DRIVEN', channel: ch.id });
    } catch (e) {
      store.releaseAction(actionId);
      log.error({ event: 'CLOSE_FINALIZE_FAILED', channel: ch.id, error: String(e.stderr || e.message || e) });
      throw e;
    }
  }
}

async function drivePwFinalize(event, ctx) {
  const { cli, ch, rpc, store, log } = ctx;
  const actionId = `pw-finalize:${ch.id}:${event.authDigest || ''}`;
  if (!store.claimAction(actionId, { retryPending: true })) return;
  try {
    await cli.run(ch.id, ch.workDir, ['pw-finalize', rpc]);
    store.completeAction(actionId, 'ok');
    log.info({ event: 'PW_FINALIZED_DRIVEN', channel: ch.id });
  } catch (e) {
    store.releaseAction(actionId);
    log.error({ event: 'PW_FINALIZE_FAILED', channel: ch.id, error: String(e.stderr || e.message || e) });
    throw e;
  }
}

// Compatibility bridge for the delegate's typed ApiClient. Peer co-sign traffic terminates on the
// hardened co-signer HTTP service (default :8200), while the legacy native withdrawal-claim
// prover lives in the coordinator API (default :8100). Proxy only the configured manager and
// bounded scalar fields; the downstream CLI/circuit/on-chain verifier remain authoritative.
//
// This is a COOPERATIVE compatibility service. A real delegate instead uses its local
// `wallet_withdrawal_claim` export and submits directly; its Regev secret is not present here and
// this route must never be treated as that delegate's censorship-resistant recovery path.
async function proxyCloseClaim(event, ctx) {
  const { api, ch, log } = ctx;
  const body = (event && event.body) || {};
  const manager = String(body.manager || '');
  const configuredManager = String(ch.manager || '');
  if (!/^0x[0-9a-fA-F]{40}$/.test(manager)
      || manager.toLowerCase() !== configuredManager.toLowerCase()) {
    return { ok: false, status: 400, body: { error: 'manager must equal the configured channel manager' } };
  }
  const slot = Number(body.slot);
  if (!Number.isSafeInteger(slot) || slot < 0 || slot >= 1024) {
    return { ok: false, status: 400, body: { error: 'slot must be an integer in 0..1023' } };
  }
  const recipient = String(body.recipient || '');
  if (!/^0x[0-9a-fA-F]{40}$/.test(recipient)) {
    return { ok: false, status: 400, body: { error: 'recipient must be a 20-byte address' } };
  }
  const tokenSlot = body.tokenSlot === undefined || body.tokenSlot === null
    ? 0
    : Number(body.tokenSlot);
  if (!Number.isSafeInteger(tokenSlot) || tokenSlot < 0 || tokenSlot > 9) {
    return { ok: false, status: 400, body: { error: 'tokenSlot must be an integer in 0..9' } };
  }
  const result = await api.closeClaim(ch.id, { manager, slot, recipient, tokenSlot });
  log.info({ event: 'CLOSE_CLAIM_PROXIED', channel: ch.id, slot, recipient, tokenSlot });
  return { ok: true, status: 200, body: result };
}

// --- ABNORMAL: a close was observed on-chain ---
// CloseRequested can only be emitted by a registered member (the on-chain requestClose gates on
// isMemberRecipient), so advancing to CLOSE_PENDING (which pauses new co-signing) is the safe
// response. We additionally alert when the request was not one we initiated so an operator is aware.
async function onCloseObserved(event, ctx) {
  const { ch, store, log, alert } = ctx;
  ctx.sm.signal(SIGNALS.CLOSE_REQUESTED);
  const ours = Boolean(store.findTicket((t) => t.type === 'full_withdrawal' && t.status && t.status.startsWith('close')));
  log.info({ event: 'CLOSE_REQUESTED_OBSERVED', channel: ch.id, txHash: event.txHash, ours });
  if (!ours) {
    await alert.raise('warn', ch.id, 'CLOSE_REQUESTED_BY_OTHER',
      'a close was requested that this operator did not initiate; new co-signing paused pending intent reconciliation',
      { txHash: event.txHash, requester: event.args && event.args.requester });
  }
}

// Finalized lifecycle observations must reconcile the local signing state machine too. Merely
// logging them leaves a process permanently in CLOSE_SUBMITTED after another member cancels, or
// incorrectly able to resume from ACTIVE after a close has finalized. These events are dispatched
// only from the finalized/hash-authenticated watcher range.
async function onCloseCancelled(event, ctx) {
  const { ch, log, store } = ctx;
  if (store && typeof store.set === 'function') store.set('closeFinalizedObserved', false);
  ctx.sm.signal(SIGNALS.CANCELLED);
  log.info({
    event: 'CLOSE_CANCELLED_RECONCILED',
    channel: ch.id,
    closeIntentDigest: event.args && event.args.closeIntentDigest,
    txHash: event.txHash,
  });
}

async function onCloseFinalized(event, ctx) {
  const { ch, log, store } = ctx;
  // Keep this fact orthogonal to the defensive-mode state-machine sink. A process that entered
  // DEFENSIVE before finalization still needs to expose the fail-closed claim prover afterwards.
  if (store && typeof store.set === 'function') store.set('closeFinalizedObserved', true);
  ctx.sm.signal(SIGNALS.FINALIZED);
  log.info({
    event: 'CLOSE_FINALIZED_RECONCILED',
    channel: ch.id,
    closeIntentDigest: event.args && event.args.closeIntentDigest,
    txHash: event.txHash,
  });
}

// CloseSubmitted / SpecialCloseSubmitted: decide cooperate vs challenge/cancel. The pending close's
// (epoch, version) is read from the AUTHORITATIVE on-chain getPendingClose() getter (NOT our own
// persisted intent and not the event payload). This distinction is load-bearing when two close
// transitions land in one finalized block: the first log is canonical, but it is no longer the
// pending state at that block's end. A digest match only tells us who originally authored the
// intent; it must never override version ordering. In particular, a previously-authored intent can
// be replayed after cancellation, after this signer has advanced to a newer N-of-N head.
async function onCloseIntentObserved(event, ctx) {
  const { ch, store, log, alert, cli, rpc } = ctx;
  ctx.sm.signal(SIGNALS.CLOSE_SUBMITTED);

  const ourHead = readHeadVersion(cli, ch);
  const pending = await readOnChainPending(ctx, event);
  if (!ourHead || !pending) {
    await alert.raise('warn', ch.id, 'CLOSE_RECONCILE_FAILED', 'could not read pending close from chain to compare with local head', { txHash: event.txHash });
    return;
  }

  const ourDigest = ourCloseIntentDigest(cli, ch);
  const isOurs = ourDigest && pending.closeIntentDigest && ourDigest.toLowerCase() === String(pending.closeIntentDigest).toLowerCase();
  const cmp = policy.compareVersion(ourHead, pending); // 1 => our head strictly newer than the close

  if (cmp <= 0) {
    // It froze a state at/after our head ⇒ legitimate exit. `isOurs` is diagnostic only: an old
    // locally-authored intent is still stale once our signed head has advanced past it.
    log.info({ event: 'CLOSE_LEGITIMATE', channel: ch.id, ourHead, pending, isOurs });
    return;
  }

  // STALE close freezing an OLDER state ⇒ defend with a newer head, including when the digest
  // matches an intent we authored before advancing our local signed head.
  const response = policy.staleCloseResponse(ctx.policy);
  // Cancellation restores the freeze nonce, so an identical close-intent digest can lawfully
  // appear again in a distinct transaction. Bind deduplication to the observation as well as the
  // digest: retries of this event remain idempotent, while a later replay is defended again.
  const actionId = `stale-close:${response}:${pending.closeIntentDigest || ''}:${event.txHash || ''}`;
  if (!store.claimAction(actionId, { retryPending: true })) return;
  await alert.raise('attack', ch.id, 'STALE_CLOSE_DETECTED',
    `pending close froze v${pending.stateVersion}@e${pending.epoch} but our head is v${ourHead.stateVersion}@e${ourHead.epoch}`,
    { response, txHash: event.txHash, pendingDigest: pending.closeIntentDigest });
  try {
    if (response === 'challenge') {
      await cli.run(ch.id, ch.workDir, ['close', ch.manager, rpc], { CLOSE_SV: ch.verifier || '', CLOSE_SKIP_REQUEST: '1' });
    } else {
      await cli.run(ch.id, ch.workDir, ['cancel-close', ch.manager, rpc], { CANCEL_SV: ch.verifier || '' });
      ctx.sm.signal(SIGNALS.CANCELLED);
    }
    store.completeAction(actionId, 'ok');
  } catch (e) {
    store.releaseAction(actionId);
    await alert.raise('attack', ch.id, 'STALE_CLOSE_RESPONSE_FAILED', String(e.stderr || e.message || e), { response });
    // Chain watcher advances only after every handler succeeds. Throwing keeps this block/event
    // live for retry throughout the challenge window instead of permanently deduping a transient
    // RPC/fee/nonce failure.
    throw e;
  }
}

// PartialWithdrawalSubmitted not initiated by us: v1 cannot cancel a PW (A45 era-fence). Alert+record.
async function onPartialWithdrawalObserved(event, ctx) {
  const { ch, store, alert } = ctx;
  const initiated = store.findTicket((t) => t.type === 'partial_withdrawal' && t.status !== 'settle_done');
  if (initiated) return; // ours — normal
  await alert.raise('warn', ch.id, 'UNEXPECTED_PW_OBSERVED',
    'a partial withdrawal we did not initiate was submitted; A45 cancel unavailable (era-fence) — recording only',
    { txHash: event.txHash });
}

function readHeadVersion(cli, ch) {
  try {
    const snap = cli.readJson(ch.workDir, 'channel_snapshot.json');
    const st = snap.state || {};
    const version = wire.stateVersion(st);
    return { epoch: st.epoch || 0, stateVersion: version == null ? 0 : version };
  } catch (e) { return null; }
}

// The AUTHORITATIVE pending close as it actually is on-chain (NOT our own persisted intent).
// Production supplies getPendingClose and pins it to the finalized event block. A getter failure
// MUST escape so the chain watcher retries this block instead of advancing its durable cursor: an
// event payload describes the state immediately after that transaction, not necessarily the final
// state after a later replacement/cancel in the same block. Falling back to it can challenge the
// wrong close or permanently miss the actually pending one.
async function readOnChainPending(ctx, event) {
  if (typeof ctx.getPendingClose === 'function' && ctx.ch.manager) {
    const p = await ctx.getPendingClose(ctx.ch.manager, event && event.blockNumber);
    return p && p.active ? p : null;
  }
  throw new Error('authoritative getPendingClose reader is unavailable');
}

// The close_intent_digest of the close WE last authored (to tell "ours" from a foreign close).
function ourCloseIntentDigest(cli, ch) {
  try {
    const d = cli.readJson(ch.workDir, 'cancel_close.json');
    if (d && d.close_intent_digest) return d.close_intent_digest;
  } catch (e) { /* ignore */ }
  try {
    const d = cli.readJson(ch.workDir, 'close_intent.json');
    return d && d.close_intent_digest;
  } catch (e) { return null; }
}

module.exports = {
  driveCloseStep, drivePwFinalize, onCloseObserved, onCloseIntentObserved, onCloseCancelled,
  onCloseFinalized, onPartialWithdrawalObserved,
  proxyCloseClaim,
  readOnChainPending,
};
