'use strict';
// ABNORMAL branches (DESIGN.md §4.6-4.8): co-signer fault handling + exit-liveness. Once a fault is
// confirmed (invalid cosign, withholding, equivocation, or a close against a stale state), the
// delegate enters STICKY exit mode and pursues on-chain recovery only.
//
// Close FREEZE initiation and post-finalization CLAIM are delegate-owned:
// requestCloseAsParticipant uses the signed-snapshot participant path; wallet_withdrawal_claim
// keeps the Regev secret inside WASM; and the delegate submits claims. Once a production live
// withdrawal has credited rollup backing for this manager, the permissionless pull functions let
// the delegate bring that existing backing into the manager and pull its own credit. They do not
// create the rollup backing. Both that producer and the ClosePending -> proved CloseSubmitted
// transition are distinct availability requirements; see DESIGN.md §6.3.

const dsm = require('../state-machine');

function isConfiguredManagerEvent(event, ctx, expectedKinds) {
  const manager = ctx && ctx.ch && ctx.ch.manager;
  return Boolean(
    event
    && event.contract === 'manager'
    && typeof event.address === 'string'
    && typeof manager === 'string'
    && event.address.toLowerCase() === manager.toLowerCase()
    && expectedKinds.includes(event.kind),
  );
}

function sameHex(a, b) {
  return typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
}

async function enterExitMode(event, ctx, code = 'EQUIVOCATION') {
  const { ch, store, alert, sm, log } = ctx;
  if (store.get('mode') !== 'exiting') {
    store.set('mode', 'exiting');
    sm.signal(dsm.SIGNALS.EXIT);
    const evidence = store.get('equivocationEvidence') || store.get('cosignFault')
      || event.evidence || { kind: event.kind, reason: event.reason };
    const rec = await alert.raise('attack', ch.id, code, event.reason || 'delegate entering exit mode', evidence);
    store.pushAlert(rec);
    log.error({ event: 'EXIT_MODE_ENTERED', channel: ch.id, code, reason: event.reason });
  }
  // Freeze an otherwise-Active channel immediately with the delegate's own participant proof.
  // Claim proving is intentionally NOT attempted here: submitWithdrawalClaim is valid only after
  // CloseFinalized, and the old eager call merely produced a deterministic pre-finalization error.
  await attemptCloseRequest(ctx);
}

function ensureExitMode(ctx) {
  if (ctx.store.get('mode') !== 'exiting') {
    ctx.store.set('mode', 'exiting');
    ctx.sm.signal(dsm.SIGNALS.EXIT);
  }
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
  const { ch, store, log } = ctx;
  if (!isConfiguredManagerEvent(
    event,
    ctx,
    ['CloseRequested', 'CloseSubmitted', 'SpecialCloseSubmitted'],
  )) return;
  const head = store.get('acceptedHead');
  const a = event.args || {};
  let pendingV = null;
  try {
    if (a.finalEpoch != null || a.finalStateVersion != null) {
      pendingV = {
        epoch: canonicalU64(a.finalEpoch == null ? 0 : a.finalEpoch, 'close finalEpoch'),
        stateVersion: canonicalU64(
          a.finalStateVersion == null ? 0 : a.finalStateVersion,
          'close finalStateVersion',
        ),
      };
    }
    if (head) {
      canonicalU64(head.epoch == null ? 0 : head.epoch, 'accepted head epoch');
      canonicalU64(head.stateVersion == null ? 0 : head.stateVersion, 'accepted head stateVersion');
    }
  } catch (error) {
    store.set('awaitingClaim', true);
    return enterExitMode({
      kind: 'malformed_close_version',
      reason: String(error && error.message || error),
      evidence: { head, args: a, txHash: event.txHash },
    }, ctx, 'MALFORMED_CLOSE_VERSION');
  }
  log.info({ event: 'CLOSE_SEEN', channel: ch.id, txHash: event.txHash, head, pendingV });
  if (head && pendingV && (BigInt(pendingV.epoch) < BigInt(head.epoch) ||
      (BigInt(pendingV.epoch) === BigInt(head.epoch) && BigInt(pendingV.stateVersion) < BigInt(head.stateVersion)))) {
    store.set('awaitingClaim', true);
    return enterExitMode({
      kind: 'stale_close',
      reason: 'close against stale state',
      evidence: { head, pendingV, txHash: event.txHash },
    }, ctx, 'STALE_CLOSE_AGAINST_US');
  }
  // Even an honest close makes further off-chain sends unsafe/useless. Enter the same sticky
  // recovery state without labelling it an attack, so EXIT_DONE is reachable after payout.
  ensureExitMode(ctx);
  store.set('awaitingClaim', true);
}

// Channel finalized → claim every positive token balance in our slot.
async function onChannelFinalized(event, ctx) {
  if (!isConfiguredManagerEvent(event, ctx, ['CloseFinalized'])) return;
  ensureExitMode(ctx);
  ctx.store.set('channelFinalized', true);
  if (event && event.blockNumber != null) ctx.store.set('closeFinalizedBlock', event.blockNumber);
  ctx.store.set('awaitingClaim', true);
  // A finalized CloseFinalized observation proves any earlier participant-close submission took
  // effect (possibly via another participant). Keep the local request id terminal across restart.
  const closeActionId = `participant-close:${ctx.ch.id}:${ctx.slot}`;
  if (ctx.store.hasAction && ctx.store.hasAction(closeActionId)) {
    ctx.store.completeAction(closeActionId, 'finalized');
  }
  return attemptRecovery(ctx);
}

function claimActionId(ch, slot, tokenSlot) {
  return `claim:${ch.id}:${slot}:${tokenSlot}`;
}

function creditActionId(ch, tokenIndex) {
  return `credit-pull:${ch.id}:${tokenIndex}`;
}

function canonicalU64(value, label) {
  if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) {
    throw new Error(`${label} must be an exact unsigned integer`);
  }
  const raw = String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error(`${label} must be a canonical unsigned integer`);
  const parsed = BigInt(raw);
  if (parsed > ((1n << 64n) - 1n)) throw new Error(`${label} is outside uint64`);
  return parsed.toString();
}

function positiveBalances(report, finalized) {
  if (!report || !Array.isArray(report.balances)
      || report.balances.length !== Number(finalized.tokenCount)) {
    throw new Error('wallet balance report must contain every finalized token slot exactly once');
  }
  const seen = new Set();
  return report.balances.map((entry) => {
    const tokenSlot = Number(entry.tokenSlot);
    const tokenIndex = Number(entry.tokenIndex);
    if (!Number.isSafeInteger(tokenSlot) || tokenSlot < 0 || tokenSlot >= finalized.tokenCount) {
      throw new Error(`wallet returned invalid finalized token slot ${entry.tokenSlot}`);
    }
    if (seen.has(tokenSlot)) throw new Error(`wallet returned duplicate token slot ${tokenSlot}`);
    seen.add(tokenSlot);
    if (!Number.isSafeInteger(tokenIndex) || tokenIndex !== Number(finalized.tokenRegistry[tokenSlot])) {
      throw new Error(`wallet token ${tokenSlot} disagrees with finalized registry`);
    }
    const raw = String(entry.balance);
    if (!/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error('wallet returned a non-canonical balance');
    const amount = BigInt(raw);
    if (amount > ((1n << 64n) - 1n)) throw new Error('wallet returned a balance outside uint64');
    return { tokenSlot, tokenIndex, amount: amount.toString() };
  }).filter((entry) => BigInt(entry.amount) > 0n);
}

function mergeClaimPlan(existing, finalized, balances) {
  const sameClose = existing && existing.closeIntentDigest === finalized.closeIntentDigest;
  const priorClaims = sameClose && Array.isArray(existing.claims) ? existing.claims : [];
  const oldBySlot = new Map(priorClaims.map((c) => [c.tokenSlot, c]));
  if (oldBySlot.size !== priorClaims.length) throw new Error('persisted exit plan has duplicate token slots');
  return {
    closeIntentDigest: finalized.closeIntentDigest,
    claims: balances.map((balance) => {
      const old = oldBySlot.get(balance.tokenSlot);
      if (old && (Number(old.tokenIndex) !== balance.tokenIndex || String(old.amount) !== balance.amount)) {
        throw new Error(`persisted exit plan disagrees with authenticated balance for token slot ${balance.tokenSlot}`);
      }
      // Transaction progress survives restart, but the freshly decrypted/authenticated economics
      // always overwrite persisted display fields.
      return { ...(old || {}), ...balance };
    }),
  };
}

function replacePlanItem(store, tokenSlot, patch) {
  const plan = store.get('exitClaimPlan');
  if (!plan) return null;
  const claims = plan.claims.map((item) => item.tokenSlot === tokenSlot ? { ...item, ...patch } : item);
  const next = { ...plan, claims };
  store.set('exitClaimPlan', next);
  return claims.find((item) => item.tokenSlot === tokenSlot);
}

async function attemptDirectCreditPull(ctx) {
  const { claimSettlement, ch, store, alert, log } = ctx;
  const plan = store.get('exitClaimPlan');
  if (!claimSettlement || !plan) return;
  for (const item of plan.claims) {
    if (item.paidFinalized || !item.nullifier) continue;
    const actionId = creditActionId(ch, item.tokenIndex);
    if (item.fundsPullTxHash) {
      // eslint-disable-next-line no-await-in-loop
      const fundStatus = await claimSettlement.transactionStatus(item.fundsPullTxHash);
      if (fundStatus === 'pending') continue;
      replacePlanItem(store, item.tokenSlot, { fundsPullTxHash: null });
      if (fundStatus === 'failed' || fundStatus === 'missing') store.releaseAction(actionId);
    }
    if (item.pullTxHash) {
      // Do not emit a second payout transaction while the first is pending/mined but not yet in
      // the finalized watcher range. A dropped/reverted tx clears the marker and becomes retryable.
      // eslint-disable-next-line no-await-in-loop
      const txStatus = await claimSettlement.transactionStatus(item.pullTxHash);
      if (txStatus === 'pending' || txStatus === 'mined') continue;
      replacePlanItem(store, item.tokenSlot, { pullTxHash: null });
      store.releaseAction(actionId);
    }
    if (!store.claimAction(actionId, { retryPending: true })) continue;
    try {
      // eslint-disable-next-line no-await-in-loop
      const pulled = await claimSettlement.pullCredit(ch.manager, item.tokenIndex, (broadcast) => {
        if (broadcast.phase === 'channel-funds') {
          replacePlanItem(store, item.tokenSlot, { fundsPullTxHash: broadcast.txHash });
        } else if (broadcast.phase === 'credit') {
          replacePlanItem(store, item.tokenSlot, {
            fundsPullTxHash: null,
            pullTxHash: broadcast.txHash,
            payoutAmount: broadcast.amount,
          });
        }
      });
      if (pulled.noCredit) {
        store.releaseAction(actionId);
        continue;
      }
      replacePlanItem(store, item.tokenSlot, {
        pullTxHash: pulled.txHash,
        payoutAmount: pulled.amount,
      });
      log.info({ event: 'WITHDRAWAL_CREDIT_TX_SUBMITTED', channel: ch.id, tokenIndex: item.tokenIndex, txHash: pulled.txHash });
    } catch (e) {
      const current = store.get('exitClaimPlan').claims.find((c) => c.tokenSlot === item.tokenSlot);
      if (!current || (!current.fundsPullTxHash && !current.pullTxHash)) store.releaseAction(actionId);
      // Funds may not have been pulled from the rollup yet. This is retryable and the recovery
      // timer / ChannelFundsPulled event will return here.
      // eslint-disable-next-line no-await-in-loop
      await alert.raise('fault', ch.id, 'WITHDRAWAL_CREDIT_PULL_DEFERRED', String(e && e.message || e), { tokenIndex: item.tokenIndex });
    }
  }
}

async function attemptDirectRecovery(ctx) {
  const { claimSettlement, wallet, snapshotVault, ch, store, log, alert } = ctx;
  const finalized = await claimSettlement.readFinalizedContext(
    ch.manager,
    store.get('closeFinalizedBlock') == null ? 'finalized' : store.get('closeFinalizedBlock'),
  );
  if (Number(finalized.channelId) !== Number(ch.id)) {
    throw new Error(`settlement manager channel ${finalized.channelId} differs from configured ${ch.id}`);
  }
  const archived = snapshotVault && snapshotVault.load(finalized.finalChannelStateDigest);
  if (snapshotVault && !archived) {
    throw new Error(`no authenticated archived snapshot for finalized state ${finalized.finalChannelStateDigest}`);
  }
  if (archived) wallet.importChannel(archived, ctx.slot);
  const balance = wallet.balance(ctx.slot);
  const plan = mergeClaimPlan(store.get('exitClaimPlan'), finalized, positiveBalances(balance, finalized));
  store.set('finalizedClaimContext', finalized);
  store.set('exitClaimPlan', plan);

  if (plan.claims.length === 0) {
    store.set('awaitingClaim', false);
    store.set('awaitingCredit', false);
    ctx.sm.signal(dsm.SIGNALS.EXIT_DONE);
    log.info({ event: 'EXIT_CONFIRMED_ZERO_BALANCE', channel: ch.id });
    return;
  }

  for (const original of plan.claims) {
    let item = store.get('exitClaimPlan').claims.find((c) => c.tokenSlot === original.tokenSlot);
    const actionId = claimActionId(ch, ctx.slot, item.tokenSlot);
    if (item.nullifier) {
      // eslint-disable-next-line no-await-in-loop
      const status = await claimSettlement.claimStatus(ch.manager, item.nullifier, item.claimTxHash);
      if (status === 'accepted' || status === 'mined' || status === 'pending') continue;
      replacePlanItem(store, item.tokenSlot, { nullifier: null, claimTxHash: null });
      store.releaseAction(actionId);
      item = store.get('exitClaimPlan').claims.find((c) => c.tokenSlot === original.tokenSlot);
    }
    if (!store.claimAction(actionId, { retryPending: true })) continue;
    try {
      const wasmContext = {
        closeIntentDigest: finalized.closeIntentDigest,
        finalChannelStateDigest: finalized.finalChannelStateDigest,
        finalBalanceStateH1: finalized.finalBalanceStateH1,
      };
      // Heavy proving happens here, inside WASM. Only the public artifact crosses back to JS.
      const artifact = wallet.withdrawalClaim(wasmContext, item.tokenSlot);
      // eslint-disable-next-line no-await-in-loop
      const submitted = await claimSettlement.submitClaim(
        ch.manager,
        artifact,
        finalized,
        item.tokenSlot,
        (txHash) => replacePlanItem(store, item.tokenSlot, {
          nullifier: artifact.claim.withdrawalNullifier,
          claimTxHash: txHash,
        }),
      );
      replacePlanItem(store, item.tokenSlot, {
        nullifier: submitted.nullifier,
        claimTxHash: submitted.txHash || null,
        memberPkG: artifact.claim.memberPkG,
        acceptedObserved: submitted.alreadySubmitted === true,
      });
      store.set('awaitingCredit', true);
      log.info({
        event: submitted.alreadySubmitted ? 'CLAIM_RECONCILED' : 'CLAIM_SUBMITTED',
        channel: ch.id,
        slot: ctx.slot,
        tokenSlot: item.tokenSlot,
        tokenIndex: submitted.tokenIndex,
        txHash: submitted.txHash,
      });
    } catch (e) {
      const current = store.get('exitClaimPlan').claims.find((c) => c.tokenSlot === item.tokenSlot);
      const uncertainHash = e && (e.transactionHash || e.hash) || (current && current.claimTxHash);
      if (uncertainHash) replacePlanItem(store, item.tokenSlot, { claimTxHash: uncertainHash });
      else store.releaseAction(actionId);
      // eslint-disable-next-line no-await-in-loop
      await alert.raise('fault', ch.id, 'CLAIM_FAILED', String(e && e.message || e), { tokenSlot: item.tokenSlot, uncertainTxHash: uncertainHash || null });
    }
  }
  await attemptDirectCreditPull(ctx);
}

async function attemptCloseRequest(ctx) {
  const { ch, store, log, alert, participantCloser } = ctx;
  // A close is already visible/finalized. Calling requestCloseAsParticipant now can only revert
  // ChannelAlreadyFrozen and must not consume another recipient-account nonce.
  if (store.get('awaitingClaim') || store.get('channelFinalized')) return;
  const proof = store.get('participantCloseProof');
  if (!participantCloser || !proof) {
    if (!store.get('unilateralCloseUnavailableAlerted')) {
      store.set('unilateralCloseUnavailableAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'UNILATERAL_CLOSE_UNAVAILABLE',
        'cannot submit requestCloseAsParticipant: recipient signer or authenticated participant proof is unavailable',
        { hasSigner: Boolean(participantCloser), hasProof: Boolean(proof) },
      );
    }
    return;
  }
  const actionId = `participant-close:${ch.id}:${ctx.slot}`;
  const prior = store.get('participantCloseSubmission');
  if (prior && prior.txHash && typeof participantCloser.transactionStatus === 'function') {
    const status = await participantCloser.transactionStatus(prior.txHash);
    if (status === 'pending' || status === 'mined') return;
    store.set('participantCloseSubmission', null);
    store.releaseAction(actionId);
  }
  if (!store.claimAction(actionId, { retryPending: true })) return;
  try {
    const submitted = await participantCloser.requestClose(ch.manager, proof);
    // Persist the hash before terminalizing the action. If the process dies after the send but
    // before this write, the still-pending action deliberately blocks blind resubmission; an
    // operator can reconcile the recipient nonce instead of risking two external effects.
    store.set('participantCloseSubmission', {
      txHash: submitted.txHash,
      participantRoot: proof.participantRoot,
      slot: proof.slot,
    });
    // Leave the action pending until a finalized close observation. A pre-finality reorg/drop is
    // reconciled by transactionStatus above and becomes retryable without blind nonce reuse.
    log.info({
      event: 'PARTICIPANT_CLOSE_SUBMITTED',
      channel: ch.id,
      slot: proof.slot,
      txHash: submitted.txHash,
      note: 'awaiting finalized CloseRequested/CloseSubmitted before claim',
    });
  } catch (e) {
    const uncertainHash = e && (e.transactionHash || e.hash);
    if (uncertainHash) {
      store.set('participantCloseSubmission', { txHash: uncertainHash, slot: proof.slot, uncertain: true });
    } else {
      store.releaseAction(actionId);
    }
    await alert.raise('fault', ch.id, 'PARTICIPANT_CLOSE_FAILED', String(e && e.message || e), {
      uncertainTxHash: uncertainHash || null,
    });
  }
}

async function attemptRecovery(ctx) {
  const { api, ch, store, log, alert } = ctx;
  if (!store.get('channelFinalized')) {
    log.info({ event: 'CLAIM_DEFERRED', channel: ch.id, note: 'waiting for finalized CloseFinalized event' });
    return;
  }
  const recipient = ctx.recipient;
  const manager = ch.manager;
  if (!recipient || !manager || manager === '0x0000000000000000000000000000000000000000') {
    log.warn({ event: 'RECOVERY_NOT_CONFIGURED', channel: ch.id, note: 'need manager + recipient to claim' });
    return;
  }
  if (ctx.claimSettlement && ctx.wallet && typeof ctx.wallet.withdrawalClaim === 'function') {
    try {
      return await attemptDirectRecovery(ctx);
    } catch (e) {
      await alert.raise('fault', ch.id, 'DIRECT_CLAIM_FAILED', String(e && e.message || e), {
        note: 'will retry from the authenticated snapshot archive; the cooperative cosigner is not trusted for this path',
      });
      return;
    }
  }
  // Compatibility only for deployments that have not configured the recipient key/WASM claim
  // build. This remains cooperative and is intentionally never selected by the production direct
  // path above.
  const actionId = `claim:${ch.id}:${ctx.slot}`;
  if (!store.claimAction(actionId)) return; // a claim is already in flight / submitted
  try {
    await api.closeClaim(ch.id, { manager, slot: ctx.slot, recipient });
    store.completeAction(actionId, 'submitted');
    store.set('awaitingCredit', true); // NOT exited yet — wait for the on-chain credit (review M5)
    log.info({ event: 'CLAIM_SUBMITTED', channel: ch.id, slot: ctx.slot, recipient, note: 'awaiting this manager\'s finalized WithdrawalClaimed before EXITED' });

    // No post-close top-up is attempted. The contract deliberately disables that lane because a
    // closeable state has already applied every incoming transfer to this ordinary slot balance;
    // submitting a second claim would double-credit it.
  } catch (e) {
    // Transient/failed — RELEASE so a later finalize/retry can re-attempt (review M6).
    store.releaseAction(actionId);
    await alert.raise('fault', ch.id, 'CLAIM_FAILED', String(e && e.message || e),
      { note: 'legacy cooperative proxy failed; configure the local WASM wallet and recipient key for the direct path' });
  }
}

async function onClaimAccepted(event, ctx) {
  if (!isConfiguredManagerEvent(event, ctx, ['WithdrawalClaimAccepted'])) return;
  const a = event.args || {};
  if (!ctx.recipient || String(a.recipient || '').toLowerCase() !== ctx.recipient.toLowerCase()) return;
  const tokenIndex = Number(a.tokenIndex);
  const plan = ctx.store.get('exitClaimPlan');
  if (!plan) return;
  if (!sameHex(a.closeIntentDigest, plan.closeIntentDigest)) return;
  const item = plan.claims.find((c) => (
    c.tokenIndex === tokenIndex
    && sameHex(c.nullifier, a.withdrawalNullifier)
  ));
  if (!item) return;
  if (String(a.amount) !== String(item.amount)) return;
  if (item.memberPkG && !sameHex(item.memberPkG, a.memberPkG)) return;
  if (item.claimTxHash && !sameHex(item.claimTxHash, event.txHash)) return;
  replacePlanItem(ctx.store, item.tokenSlot, { acceptedFinalized: true });
  ctx.store.completeAction(claimActionId(ctx.ch, ctx.slot, item.tokenSlot), 'finalized');
  await attemptDirectCreditPull(ctx);
}

async function onFundsPulled(event, ctx) {
  if (!isConfiguredManagerEvent(event, ctx, ['ChannelFundsPulled'])) return;
  const tokenIndex = String(event.args && event.args.tokenIndex);
  const plan = ctx.store.get('exitClaimPlan');
  if (!plan || !plan.claims.some((item) => String(item.tokenIndex) === tokenIndex)) return;
  if (ctx.store.get('mode') === 'exiting' && ctx.store.get('channelFinalized')) {
    await attemptDirectCreditPull(ctx);
  }
}

async function onRecoveryTick(_event, ctx) {
  if (ctx.store.get('mode') === 'exiting') {
    if (ctx.store.get('channelFinalized')) await attemptRecovery(ctx);
    else await attemptCloseRequest(ctx);
  }
}

// Only this channel manager's finalized WithdrawalClaimed event can complete an exit. Rollup
// WithdrawalCredited / NativeWithdrawn / ERC-20 events have no channel discriminator and may be
// unrelated refunds or withdrawals to the same recipient; accepting them here would permit false
// completion. The exact locally-broadcast payout transaction, accepted claim, token and amount are
// all bound before EXIT_DONE.
async function onCreditConfirmed(event, ctx) {
  const { ch, store, log, sm } = ctx;
  if (store.get('mode') !== 'exiting' && !store.get('awaitingCredit')) return;
  if (!isConfiguredManagerEvent(event, ctx, ['WithdrawalClaimed'])) return;
  const a = event.args || {};
  const credited = (a.recipient || '').toLowerCase();
  if (!ctx.recipient || !credited || credited !== ctx.recipient.toLowerCase()) {
    log.info({ event: 'CREDIT_IGNORED', channel: ch.id, reason: 'recipient absent or not ours', credited, txHash: event.txHash });
    return;
  }
  const tokenIndex = String(a.tokenIndex);
  const plan = store.get('exitClaimPlan');
  if (!plan || !Array.isArray(plan.claims)) return;
  const item = plan.claims.find((c) => String(c.tokenIndex) === tokenIndex);
  if (!item
      || (item.acceptedFinalized !== true && item.acceptedObserved !== true)
      || String(a.amount) !== String(item.payoutAmount)
      || !sameHex(item.pullTxHash, event.txHash)) return;
  replacePlanItem(store, item.tokenSlot, { paidFinalized: true });
  store.completeAction(creditActionId(ch, item.tokenIndex), 'finalized');
  const updated = store.get('exitClaimPlan');
  if (!updated.claims.every((c) => c.paidFinalized === true)) return;
  store.set('awaitingCredit', false);
  sm.signal(dsm.SIGNALS.EXIT_DONE);
  log.info({ event: 'EXIT_CONFIRMED', channel: ch.id, recipient: a.recipient, amount: a.amount, tokenIndex, kind: event.kind, txHash: event.txHash });
}

module.exports = {
  enterExitMode,
  onCosignInvalid,
  onWithholding,
  onCloseSeen,
  onChannelFinalized,
  onClaimAccepted,
  onFundsPulled,
  onRecoveryTick,
  onCreditConfirmed,
  attemptCloseRequest,
  attemptRecovery,
  attemptDirectRecovery,
  attemptDirectCreditPull,
  positiveBalances,
  canonicalU64,
  isConfiguredManagerEvent,
};
