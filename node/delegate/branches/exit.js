'use strict';
// ABNORMAL branches (DESIGN.md §4.6-4.8): co-signer fault handling + exit-liveness. Once a fault is
// confirmed (invalid cosign, withholding, equivocation, or a close against a stale state), the
// delegate enters STICKY exit mode and pursues on-chain recovery only.
//
// NOTE (documented limitation / seam): full adversarial-co-signer exit for a DELEGATE requires a
// client-side withdrawal-claim prover (the delegate's own Regev decryption ZKP) exposed in WASM.
// v1 attempts the cooperative claim via the API (correct when the channel finalizes legitimately);
// the standalone client-claim path is a tracked follow-up (DESIGN.md §4.7 / §6.3 open question).

const dsm = require('../state-machine');

async function enterExitMode(event, ctx, code = 'EQUIVOCATION') {
  const { ch, store, alert, sm, log } = ctx;
  if (store.get('mode') !== 'exiting') {
    store.set('mode', 'exiting');
    sm.signal(dsm.SIGNALS.EXIT);
    const evidence = store.get('equivocationEvidence') || store.get('cosignFault') || { kind: event.kind, reason: event.reason };
    const rec = await alert.raise('attack', ch.id, code, event.reason || 'delegate entering exit mode', evidence);
    store.pushAlert(rec);
    log.error({ event: 'EXIT_MODE_ENTERED', channel: ch.id, code, reason: event.reason });
  }
  // Kick off recovery immediately.
  await attemptRecovery(ctx);
}

async function onCosignInvalid(event, ctx) {
  return enterExitMode(event, ctx, 'COSIGN_INVALID');
}

async function onWithholding(event, ctx) {
  return enterExitMode(event, ctx, 'COSIGNER_WITHHOLDING');
}

// A close was observed. Compare its (epoch, version) — DECODED from the chain event args (review M3:
// the watcher now decodes args; CloseSubmitted carries finalEpoch/finalStateVersion) — to our last
// accepted head. A close that froze an OLDER state is a roll-back attempt → alert + exit.
async function onCloseSeen(event, ctx) {
  const { ch, store, log, alert } = ctx;
  const head = store.get('acceptedHead');
  const a = event.args || {};
  const pendingV = (a.finalEpoch != null || a.finalStateVersion != null)
    ? { epoch: Number(a.finalEpoch || 0), stateVersion: Number(a.finalStateVersion || 0) }
    : null;
  log.info({ event: 'CLOSE_SEEN', channel: ch.id, txHash: event.txHash, head, pendingV });
  if (head && pendingV && (BigInt(pendingV.epoch) < BigInt(head.epoch) ||
      (BigInt(pendingV.epoch) === BigInt(head.epoch) && BigInt(pendingV.stateVersion) < BigInt(head.stateVersion)))) {
    await alert.raise('attack', ch.id, 'STALE_CLOSE_AGAINST_US', 'a close froze a state older than our accepted head', { head, pendingV });
    return enterExitMode({ kind: 'stale_close', reason: 'close against stale state' }, ctx, 'STALE_CLOSE_AGAINST_US');
  }
  store.set('awaitingClaim', true);
}

// Channel finalized → claim our slot, and file a post-close claim if a late transfer is recorded.
async function onChannelFinalized(event, ctx) {
  return attemptRecovery(ctx);
}

async function attemptRecovery(ctx) {
  const { api, ch, store, log, alert } = ctx;
  const recipient = ctx.recipient;
  const manager = ch.manager;
  if (!recipient || !manager || manager === '0x0000000000000000000000000000000000000000') {
    log.warn({ event: 'RECOVERY_NOT_CONFIGURED', channel: ch.id, note: 'need manager + recipient to claim' });
    return;
  }
  const actionId = `claim:${ch.id}:${ctx.slot}`;
  if (!store.claimAction(actionId)) return; // a claim is already in flight / submitted
  try {
    await api.closeClaim(ch.id, { manager, slot: ctx.slot, recipient });
    store.completeAction(actionId, 'submitted');
    store.set('awaitingCredit', true); // NOT exited yet — wait for the on-chain credit (review M5)
    log.info({ event: 'CLAIM_SUBMITTED', channel: ch.id, slot: ctx.slot, recipient, note: 'awaiting on-chain WithdrawalClaimed/NativeWithdrawn before EXITED' });

    // Late inter-channel transfer received after finalization → post-close claim (A34).
    const late = store.findTicket((t) => t.type === 'late_transfer' && t.status !== 'claimed');
    if (late) {
      try {
        await api.postCloseClaim(ch.id, { manager, slot: ctx.slot, recipient, incomingTxIndex: late.params.incomingTxIndex, sourceTx: late.params.sourceTx });
        store.upsertTicket({ ...late, status: 'claimed' });
        log.info({ event: 'POST_CLOSE_CLAIM_SUBMITTED', channel: ch.id });
      } catch (e) {
        await alert.raise('fault', ch.id, 'POST_CLOSE_CLAIM_FAILED', String(e && e.message || e), {});
      }
    }
  } catch (e) {
    // Transient/failed — RELEASE so a later finalize/retry can re-attempt (review M6).
    store.releaseAction(actionId);
    await alert.raise('fault', ch.id, 'CLAIM_FAILED', String(e && e.message || e),
      { note: 'will retry; standalone client-side withdrawal-claim prover is the follow-up for an adversarial co-signer' });
  }
}

// On-chain credit observed (WithdrawalClaimed / NativeWithdrawn). ONLY now is the exit truly done
// (review M5: never mark EXITED on a co-signer API 200 — the co-signer may be the adversary we flee).
async function onCreditConfirmed(event, ctx) {
  const { ch, store, log, sm } = ctx;
  if (store.get('mode') !== 'exiting' && !store.get('awaitingCredit')) return;
  const a = event.args || {};
  // The credit MUST name a recipient and it MUST be ours (review MED-4: an absent recipient must
  // NOT clear the sticky exit — never EXIT_DONE on an unbound/foreign credit). We require our own
  // configured recipient and an exact match.
  const credited = (a.recipient || '').toLowerCase();
  if (!ctx.recipient || !credited || credited !== ctx.recipient.toLowerCase()) {
    log.info({ event: 'CREDIT_IGNORED', channel: ch.id, reason: 'recipient absent or not ours', credited, txHash: event.txHash });
    return;
  }
  store.set('awaitingCredit', false);
  sm.signal(dsm.SIGNALS.EXIT_DONE);
  log.info({ event: 'EXIT_CONFIRMED', channel: ch.id, recipient: a.recipient, amount: a.amount, txHash: event.txHash });
}

module.exports = { enterExitMode, onCosignInvalid, onWithholding, onCloseSeen, onChannelFinalized, onCreditConfirmed };
