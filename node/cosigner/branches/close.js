'use strict';
// OWN-ACTION + ABNORMAL branches for the close game (DESIGN.md §3.5, §3.7). The co-signer drives
// cooperative close steps it initiated, and reacts defensively to closes observed on-chain that
// froze a STALE state (it holds a strictly-newer N-of-N head ⇒ challenge A29 or cancel A30). The
// on-chain manager + verifier are the ultimate gate (monotonic _isNewer, member-set commitment).

const { SIGNALS } = require('../state-machine');
const policy = require('../../common/policy');

// --- OWN: drive cooperative close steps (timer-driven) ---
async function driveCloseStep(event, ctx) {
  const { cli, ch, rpc, store, log } = ctx;
  const step = event.step; // 'finalize'
  if (step === 'finalize') {
    const actionId = `finalize:${ch.id}:${event.closeIntentDigest || ''}`;
    if (!store.claimAction(actionId)) return;
    try {
      await cli.run(ch.id, ch.workDir, ['settle', ch.manager, rpc]);
      store.completeAction(actionId, 'ok');
      log.info({ event: 'CLOSE_FINALIZED_DRIVEN', channel: ch.id });
    } catch (e) {
      store.completeAction(actionId, 'error');
      log.error({ event: 'CLOSE_FINALIZE_FAILED', channel: ch.id, error: String(e.stderr || e.message || e) });
    }
  }
}

async function drivePwFinalize(event, ctx) {
  const { cli, ch, rpc, store, log } = ctx;
  const actionId = `pw-finalize:${ch.id}:${event.authDigest || ''}`;
  if (!store.claimAction(actionId)) return;
  try {
    await cli.run(ch.id, ch.workDir, ['pw-finalize', rpc]);
    store.completeAction(actionId, 'ok');
    log.info({ event: 'PW_FINALIZED_DRIVEN', channel: ch.id });
  } catch (e) {
    store.completeAction(actionId, 'error');
    log.error({ event: 'PW_FINALIZE_FAILED', channel: ch.id, error: String(e.stderr || e.message || e) });
  }
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

// CloseSubmitted / SpecialCloseSubmitted: decide cooperate vs challenge/cancel. The pending close's
// (epoch, version) is read from the AUTHORITATIVE on-chain getPendingClose() getter (NOT our own
// persisted intent), with the decoded event args as a fallback — so a STALE close submitted by
// anyone is detected. Whether it is "ours" is decided by digest match, not by version comparison.
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

  if (isOurs || cmp <= 0) {
    // Either we authored this close, or it froze a state at/after our head ⇒ legitimate exit.
    log.info({ event: 'CLOSE_LEGITIMATE', channel: ch.id, ourHead, pending, isOurs });
    return;
  }

  // STALE close authored by someone else freezing an OLDER state ⇒ defend with a newer head.
  const response = policy.staleCloseResponse(ctx.policy);
  const actionId = `stale-close:${response}:${pending.closeIntentDigest || event.txHash || ''}`;
  if (!store.claimAction(actionId)) return;
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
    store.completeAction(actionId, 'error');
    await alert.raise('attack', ch.id, 'STALE_CLOSE_RESPONSE_FAILED', String(e.stderr || e.message || e), { response });
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
    const bs = st.balance_state || {};
    return { epoch: st.epoch || 0, stateVersion: bs.state_version || 0 };
  } catch (e) { return null; }
}

// The AUTHORITATIVE pending close as it actually is on-chain (NOT our own persisted intent). Prefer
// the getPendingClose() getter; fall back to the decoded event args if the getter is unavailable.
async function readOnChainPending(ctx, event) {
  if (typeof ctx.getPendingClose === 'function' && ctx.ch.manager) {
    try {
      const p = await ctx.getPendingClose(ctx.ch.manager);
      if (p && p.active) return p;
    } catch (e) { /* fall through to event args */ }
  }
  const a = event && event.args;
  if (a && (a.finalEpoch != null || a.finalStateVersion != null)) {
    const epoch = Number(a.finalEpoch || 0);
    const stateVersion = Number(a.finalStateVersion || 0);
    if (!Number.isFinite(epoch) || !Number.isFinite(stateVersion)) return null; // review MED-2
    return { epoch, stateVersion, closeIntentDigest: a.closeIntentDigest };
  }
  return null;
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
  driveCloseStep, drivePwFinalize, onCloseObserved, onCloseIntentObserved, onPartialWithdrawalObserved,
};
