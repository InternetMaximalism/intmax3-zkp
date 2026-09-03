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
const { participantCloseActionId } = require('../participant-close');

const CLOSE_PHASES = Object.freeze({
  OPEN: 'open',
  REQUEST_BROADCAST: 'request_broadcast',
  REQUESTED: 'requested',
  SUBMITTED: 'submitted',
  FINALIZE_BROADCAST: 'finalize_broadcast',
  CANCELLED: 'cancelled',
  FINALIZED: 'finalized',
  LEGACY_FROZEN: 'legacy_frozen',
});

function currentCloseLifecycle(store) {
  const saved = store.get('closeLifecycle');
  if (saved && typeof saved === 'object' && Object.values(CLOSE_PHASES).includes(saved.phase)) {
    return saved;
  }
  if (store.get('channelFinalized')) return { schemaVersion: 1, phase: CLOSE_PHASES.FINALIZED };
  // Old journals used one ambiguous boolean for both CloseRequested and CloseSubmitted.  Never
  // guess that such a channel is Active and emit a duplicate request; the finalized manager-state
  // reconciler upgrades it on the next recovery tick.
  if (store.get('awaitingClaim')) return { schemaVersion: 1, phase: CLOSE_PHASES.LEGACY_FROZEN };
  return { schemaVersion: 1, phase: CLOSE_PHASES.OPEN };
}

function sameStoredValue(a, b) {
  if (a === b) return true;
  if (a == null || b == null || typeof a !== 'object' || typeof b !== 'object') return false;
  return JSON.stringify(a) === JSON.stringify(b);
}

function setIfChanged(store, key, value) {
  if (!sameStoredValue(store.get(key), value)) store.set(key, value);
  return value;
}

function closeObservationKey(event, digest) {
  const txHash = event && event.txHash;
  if (typeof txHash === 'string' && txHash.length) return `${String(digest || 'none').toLowerCase()}:${txHash.toLowerCase()}`;
  const blockNumber = event && event.blockNumber;
  const logIndex = event && event.logIndex;
  return `${String(digest || 'none').toLowerCase()}:${blockNumber == null ? 'unknown' : blockNumber}:${logIndex == null ? 'unknown' : logIndex}`;
}

function persistCloseLifecycle(store, phase, event = null, details = {}) {
  const previous = currentCloseLifecycle(store);
  const hasDetail = (key) => Object.prototype.hasOwnProperty.call(details, key);
  const next = {
    schemaVersion: 1,
    ...previous,
    ...details,
    phase,
    observedBlockNumber: event && event.blockNumber != null
      ? event.blockNumber
      : (hasDetail('observedBlockNumber') ? details.observedBlockNumber : previous.observedBlockNumber),
    observedBlockHash: event && event.blockHash
      ? event.blockHash
      : (hasDetail('observedBlockHash') ? details.observedBlockHash : previous.observedBlockHash),
    observedTxHash: event && event.txHash
      ? event.txHash
      : (hasDetail('observedTxHash') ? details.observedTxHash : previous.observedTxHash),
    observedLogIndex: event && event.logIndex != null
      ? event.logIndex
      : (hasDetail('observedLogIndex') ? details.observedLogIndex : previous.observedLogIndex),
  };
  setIfChanged(store, 'closeLifecycle', next);
  return next;
}

function closeFinalizeActionId(ch, closeKey, closeRequestGeneration = null) {
  const base = `close-finalize:${ch.id}:${closeKey}`;
  return closeRequestGeneration == null
    ? base
    : `${base}:generation:${canonicalU64(closeRequestGeneration, 'close request generation')}`;
}

async function participantRequestIdentity(ctx, lifecycle) {
  const { participantCloser, ch, store } = ctx;
  if (!participantCloser || participantCloser.durableOutbox !== true) {
    return {
      actionId: `participant-close:${ch.id}:${ctx.slot}`,
      era: null,
    };
  }
  if (typeof participantCloser.readRequestEra !== 'function') {
    throw new Error('durable participant closer has no hash-authenticated request-era reader');
  }
  const freshEra = await participantCloser.readRequestEra(ch.manager, store.get('chainCheckpoint'));
  const saved = store.get('participantCloseSubmission');
  let cancelObservation = null;
  let restorationCheckpoint = null;
  if (lifecycle.phase === CLOSE_PHASES.CANCELLED) {
    if (lifecycle.observedTxHash && lifecycle.observedBlockNumber != null
        && lifecycle.observedBlockHash && lifecycle.observedLogIndex != null) {
      cancelObservation = {
        txHash: lifecycle.observedTxHash,
        blockNumber: lifecycle.observedBlockNumber,
        blockHash: lifecycle.observedBlockHash,
        logIndex: lifecycle.observedLogIndex,
      };
    } else if (lifecycle.observedBlockNumber != null && lifecycle.observedBlockHash) {
      // A crash can lose the individual CloseCancelled callback while the authoritative
      // finalized manager-state reconciliation still proves that a formerly frozen channel is
      // Active. Bind that recovery era to the exact canonical checkpoint rather than inheriting
      // stale transaction/log metadata from the prior freeze.
      restorationCheckpoint = {
        blockNumber: lifecycle.observedBlockNumber,
        blockHash: lifecycle.observedBlockHash,
      };
    } else {
      throw new Error('cancelled close era lacks a canonical event or restoration checkpoint');
    }
  } else if (lifecycle.phase === CLOSE_PHASES.REQUEST_BROADCAST
      && saved && saved.era) {
    // A cancellation-era request remains bound to the cancellation that created it while its raw
    // transaction is merely pending. A genuinely newer CloseCancelled observation moves the
    // lifecycle back to CANCELLED above and is compared as a distinct era.
    cancelObservation = saved.era.cancelObservation || null;
    restorationCheckpoint = saved.era.restorationCheckpoint || null;
  }
  if (saved && saved.actionId && saved.era) {
    if (String(saved.era.expectedCurrentCloseFreezeNonce)
          !== String(freshEra.expectedCurrentCloseFreezeNonce)
        || String(saved.era.expectedHighestCancelledRevivedStateVersion)
          !== String(freshEra.expectedHighestCancelledRevivedStateVersion)
        || JSON.stringify(saved.era.cancelObservation || null) !== JSON.stringify(cancelObservation)
        || JSON.stringify(saved.era.restorationCheckpoint || null)
          !== JSON.stringify(restorationCheckpoint)) {
      throw new Error('persisted participant close action belongs to a different live freeze/cancellation era');
    }
    const expectedSavedId = participantCloseActionId({
      chainId: participantCloser.chainId,
      manager: ch.manager,
      channelId: ch.id,
      slot: ctx.slot,
      era: saved.era,
    });
    if (saved.actionId !== expectedSavedId) throw new Error('persisted participant close era action id is invalid');
    return { era: saved.era, actionId: saved.actionId };
  }
  const era = { ...freshEra, cancelObservation, restorationCheckpoint };
  return {
    era,
    actionId: participantCloseActionId({
      chainId: participantCloser.chainId,
      manager: ch.manager,
      channelId: ch.id,
      slot: ctx.slot,
      era,
    }),
  };
}

function finalizeJournalEntry(store, closeKey) {
  const journal = store.get('closeFinalizeJournal');
  return journal && typeof journal === 'object' ? journal[closeKey] : null;
}

function setFinalizeJournalEntry(store, closeKey, entry) {
  const old = store.get('closeFinalizeJournal');
  const journal = old && typeof old === 'object' ? old : {};
  setIfChanged(store, 'closeFinalizeJournal', { ...journal, [closeKey]: entry });
}

function pendingAction(store, actionId) {
  const actions = store.get('actions');
  return Boolean(actions && actions[actionId] && actions[actionId].result === 'pending');
}

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

function finalizedTransactionObservation(event) {
  return {
    transactionHash: event && event.txHash,
    blockNumber: event && event.blockNumber,
    blockHash: event && event.blockHash,
  };
}

function journaledSemanticObservation(event, fields) {
  return {
    kind: event && event.kind,
    address: event && event.address,
    transactionHash: event && event.txHash,
    blockNumber: event && event.blockNumber,
    blockHash: event && event.blockHash,
    logIndex: event && event.logIndex,
    ...fields,
  };
}

function rememberDeferredExitSemantic(store, lane, key, observation) {
  const block = Number(observation && observation.blockNumber);
  const logIndex = Number(observation && observation.logIndex);
  if (!/^0x[0-9a-f]{64}$/i.test(String(observation && observation.transactionHash || ''))
      || !/^0x[0-9a-f]{64}$/i.test(String(observation && observation.blockHash || ''))
      || !Number.isSafeInteger(block) || block < 0
      || !Number.isSafeInteger(logIndex) || logIndex < 0) {
    throw new Error('deferred exit semantic observation lacks an exact transaction/log identity');
  }
  const saved = store.get('deferredExitSemantics');
  const journal = saved && typeof saved === 'object' ? saved : { schemaVersion: 1 };
  const entries = journal[lane] && typeof journal[lane] === 'object' ? journal[lane] : {};
  const canonicalKey = String(key).toLowerCase();
  if (!canonicalKey || canonicalKey.length > 80) throw new Error('invalid deferred exit semantic key');
  const existing = entries[canonicalKey];
  if (!existing && Object.keys(entries).length >= 16) {
    throw new Error(`deferred finalized ${lane} semantic journal exceeds the channel token bound`);
  }
  if (existing && !sameStoredValue(existing, observation)) {
    throw new Error(`conflicting finalized ${lane} semantic observations for ${canonicalKey}`);
  }
  setIfChanged(store, 'deferredExitSemantics', {
    ...journal,
    schemaVersion: 1,
    [lane]: { ...entries, [canonicalKey]: observation },
  });
}

function attachDeferredExitSemantics(ctx) {
  const plan = ctx.store.get('exitClaimPlan');
  const deferred = ctx.store.get('deferredExitSemantics');
  if (!plan || !Array.isArray(plan.claims) || !deferred || typeof deferred !== 'object') return;
  for (const original of plan.claims) {
    const item = ctx.store.get('exitClaimPlan').claims.find(
      (claim) => claim.tokenSlot === original.tokenSlot,
    );
    const patch = {};
    if (item.nullifier) {
      const nullifier = String(item.nullifier).toLowerCase();
      const claim = deferred.claims && deferred.claims[nullifier];
      if (claim
          && sameHex(claim.closeIntentDigest, plan.closeIntentDigest)
          && sameHex(claim.withdrawalNullifier, item.nullifier)
          && sameHex(claim.memberPkG, item.memberPkG)
          && ctx.recipient
          && String(claim.recipient).toLowerCase() === ctx.recipient.toLowerCase()
          && String(claim.tokenIndex) === String(item.tokenIndex)
          && String(claim.amount) === String(item.amount)) {
        patch.acceptedObserved = true;
        patch.claimSemanticObservation = claim;
      }
      const credit = deferred.credits && deferred.credits[nullifier];
      if (credit
          && sameHex(credit.withdrawalNullifier, item.nullifier)
          && ctx.recipient
          && String(credit.recipient).toLowerCase() === ctx.recipient.toLowerCase()
          && String(credit.tokenIndex) === String(item.tokenIndex)
          && String(credit.amount) === String(item.payoutAmount || item.amount)) {
        patch.creditSemanticObservation = credit;
      }
    }
    const funds = deferred.funds && deferred.funds[String(item.tokenIndex)];
    if (funds
        && String(funds.tokenIndex) === String(item.tokenIndex)
        && BigInt(funds.amount) > 0n
        && BigInt(funds.totalReceived) >= BigInt(item.amount)) {
      patch.fundsSemanticObservation = funds;
    }
    if (Object.keys(patch).length > 0) replacePlanItem(ctx.store, item.tokenSlot, patch);
  }
}

async function actionOwnsTransaction(publisher, actionId, transactionHash) {
  if (!publisher || typeof publisher.ownsTransaction !== 'function') return false;
  return await publisher.ownsTransaction(actionId, transactionHash) === true;
}

async function reconcileParticipantCloseSubmission(ctx, reconciled) {
  const { ch, store, participantCloser, alert, log } = ctx;
  const submission = store.get('participantCloseSubmission');
  if (!submission || !submission.actionId || !participantCloser
      || participantCloser.durableOutbox !== true) {
    return { unresolved: false, result: null };
  }
  if (typeof participantCloser.reconcileRequest !== 'function') {
    if (!store.get('participantCloseSettlementAlerted')) {
      store.set('participantCloseSettlementAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'PARTICIPANT_CLOSE_SETTLEMENT_UNAVAILABLE',
        'durable participant-close submission cannot be reconciled against its exact signer nonce',
        { actionId: submission.actionId },
      );
    }
    return { unresolved: true, result: null };
  }
  const durable = reconciled && reconciled.chain && reconciled.chain.durable;
  if (!durable || durable.number == null || !durable.hash) {
    return { unresolved: true, result: null };
  }
  const proof = store.get('participantCloseProof');
  if (!proof) return { unresolved: true, result: null };

  let result;
  try {
    result = await participantCloser.reconcileRequest(
      ch.manager,
      proof,
      submission.outboxActionId || submission.actionId,
      submission.era,
      {
        ...(submission.semanticObservation || {}),
        blockNumber: submission.semanticObservation
          ? submission.semanticObservation.blockNumber : durable.number,
        blockHash: submission.semanticObservation
          ? submission.semanticObservation.blockHash : durable.hash,
        channelStatus: reconciled.chain.status,
      },
    );
  } catch (error) {
    if (!store.get('participantCloseSettlementAlerted')) {
      store.set('participantCloseSettlementAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'PARTICIPANT_CLOSE_SETTLEMENT_FAILED',
        String(error && error.message || error),
        { actionId: submission.actionId, txHash: submission.txHash || null },
      );
    }
    return { unresolved: true, result: null };
  }
  setIfChanged(store, 'participantCloseSettlementAlerted', false);
  if (result && result.phase === 'absent') {
    if (submission.txHash || submission.prepared !== true) {
      await alert.raise(
        'fault',
        ch.id,
        'PARTICIPANT_CLOSE_OUTBOX_MISSING',
        'persisted participant-close hash has no durable outbox record or intent reservation',
        { actionId: submission.actionId, txHash: submission.txHash || null },
      );
      return { unresolved: true, result };
    }
    store.set('participantCloseSubmission', null);
    store.releaseAction(submission.actionId);
    return { unresolved: false, result };
  }

  if (result && result.transactionHash && !submission.txHash) {
    setIfChanged(store, 'participantCloseSubmission', {
      ...submission,
      txHash: result.transactionHash,
      prepared: false,
    });
  }
  if (result && result.phase === 'terminal') {
    const settled = {
      ...submission,
      txHash: result.transactionHash || submission.txHash || null,
      terminal: result.terminal,
      settledAt: new Date().toISOString(),
    };
    setIfChanged(store, 'participantCloseSettlement', settled);
    store.set('participantCloseSubmission', null);
    store.completeAction(submission.actionId, result.terminal && result.terminal.outcome
      ? result.terminal.outcome : 'finalized');
    log.info({
      event: 'PARTICIPANT_CLOSE_SIGNER_NONCE_SETTLED',
      channel: ch.id,
      actionId: submission.actionId,
      txHash: settled.txHash,
      outcome: result.terminal && result.terminal.outcome || 'success',
    });
    return { unresolved: false, result };
  }
  return { unresolved: true, result };
}

async function reconcileCloseFinalizeSubmissions(ctx, reconciled) {
  const { ch, store, participantCloser, alert, log } = ctx;
  const journal = store.get('closeFinalizeJournal');
  if (!journal || typeof journal !== 'object') return { unresolved: false };
  const pending = Object.entries(journal).filter(([, entry]) => entry && entry.actionId
    && entry.closeIntentDigest
    && !['finalized', 'superseded-revert', 'absent'].includes(entry.status));
  if (pending.length === 0) return { unresolved: false };
  if (!participantCloser || participantCloser.durableOutbox !== true
      || typeof participantCloser.reconcileFinalize !== 'function') {
    return { unresolved: true };
  }
  const durable = reconciled && reconciled.chain && reconciled.chain.durable;
  if (!durable || durable.number == null || !durable.hash) return { unresolved: true };

  let settled = false;
  for (const [closeKey, entry] of pending) {
    let result;
    try {
      // eslint-disable-next-line no-await-in-loop
      result = await participantCloser.reconcileFinalize(
        ch.manager,
        entry.outboxActionId || entry.actionId,
        entry.closeIntentDigest,
        entry.closeRequestGeneration,
        {
          ...(entry.semanticObservation || {}),
          blockNumber: entry.semanticObservation ? entry.semanticObservation.blockNumber : durable.number,
          blockHash: entry.semanticObservation ? entry.semanticObservation.blockHash : durable.hash,
          channelStatus: reconciled.chain.status,
        },
      );
    } catch (error) {
      if (!store.get('closeFinalizeSettlementAlerted')) {
        store.set('closeFinalizeSettlementAlerted', true);
        // eslint-disable-next-line no-await-in-loop
        await alert.raise(
          'fault',
          ch.id,
          'CLOSE_FINALIZE_SETTLEMENT_FAILED',
          String(error && error.message || error),
          { actionId: entry.actionId, txHash: entry.txHash || null },
        );
      }
      return { unresolved: true };
    }
    setIfChanged(store, 'closeFinalizeSettlementAlerted', false);
    if (result && result.phase === 'absent') {
      if (entry.txHash) {
        // A durable callback hash with no outbox record violates the raw-WAL invariant. Keep the
        // Store action fenced for operator investigation.
        return { unresolved: true };
      }
      setFinalizeJournalEntry(store, closeKey, { ...entry, status: 'absent' });
      store.releaseAction(entry.actionId);
      settled = true;
      continue;
    }
    if (result && result.phase === 'terminal') {
      const outcome = result.terminal && result.terminal.outcome || 'finalized';
      setFinalizeJournalEntry(store, closeKey, {
        ...entry,
        txHash: result.transactionHash || entry.txHash || null,
        status: outcome,
        terminal: result.terminal,
      });
      store.completeAction(entry.actionId, outcome);
      log.info({
        event: 'CLOSE_FINALIZE_SIGNER_NONCE_SETTLED',
        channel: ch.id,
        closeIntentDigest: entry.closeIntentDigest,
        txHash: result.transactionHash || entry.txHash || null,
        outcome,
      });
      settled = true;
      continue;
    }
    if (result && result.transactionHash && !entry.txHash) {
      setFinalizeJournalEntry(store, closeKey, {
        ...entry,
        txHash: result.transactionHash,
        status: result.phase,
      });
    }
    return { unresolved: true };
  }
  return { unresolved: false, settled };
}

async function reconcileClaimOutboxActions(ctx, reconciled) {
  const { claimSettlement, ch, store, alert, log } = ctx;
  const plan = store.get('exitClaimPlan');
  if (!plan || !Array.isArray(plan.claims) || !claimSettlement
      || claimSettlement.durableOutbox !== true) return { unresolved: false, settled: false };
  const durable = reconciled && reconciled.chain && reconciled.chain.durable;
  if (!durable || durable.number == null || !durable.hash) {
    return { unresolved: plan.claims.some((item) => (
      ((item.claimOutboxPrepared || item.claimTxHash) && !item.claimNonceSettled)
      || (item.claimSemanticObservation && item.acceptedFinalized !== true)
      || ((item.fundsOutboxPrepared || item.fundsPullTxHash) && !item.fundsNonceSettled)
      || (item.fundsSemanticObservation && item.fundsPulledFinalized !== true)
      || ((item.creditOutboxPrepared || item.pullTxHash) && !item.creditNonceSettled)
      || (item.creditSemanticObservation && item.paidFinalized !== true)
    )), settled: false };
  }
  const durableObservation = { blockNumber: durable.number, blockHash: durable.hash };
  const fail = async (code, error, item, actionId) => {
    const alertKey = `${code}:${actionId}`;
    if (!store.get(alertKey)) {
      store.set(alertKey, true);
      await alert.raise('fault', ch.id, code, String(error && error.message || error), {
        actionId,
        tokenSlot: item.tokenSlot,
      });
    }
    return { unresolved: true, settled: false };
  };

  for (const original of plan.claims) {
    let item = store.get('exitClaimPlan').claims.find((entry) => entry.tokenSlot === original.tokenSlot);
    const claimAction = item.claimOutboxActionId || claimActionId(ch, ctx.slot, item.tokenSlot);
    if (((item.claimOutboxPrepared || item.claimTxHash) && !item.claimNonceSettled)
        || (item.claimSemanticObservation && item.acceptedFinalized !== true)) {
      if (typeof claimSettlement.reconcileClaim !== 'function') return { unresolved: true, settled: false };
      let result;
      try {
        // eslint-disable-next-line no-await-in-loop
        result = await claimSettlement.reconcileClaim(
          ch.manager,
          item.tokenSlot,
          {
            actionId: claimAction,
            closeIntentDigest: plan.closeIntentDigest,
            nullifier: item.nullifier,
            tokenIndex: item.tokenIndex,
            amount: item.amount,
            memberPkG: item.memberPkG,
          },
          item.claimSemanticObservation || durableObservation,
        );
      } catch (error) {
        // eslint-disable-next-line no-await-in-loop
        return fail('WITHDRAWAL_CLAIM_SETTLEMENT_FAILED', error, item, claimAction);
      }
      if (result.phase === 'absent') {
        if (!item.claimTxHash) {
          if (result.semanticVerified === true) {
            replacePlanItem(store, item.tokenSlot, {
              claimOutboxPrepared: false,
              claimNonceSettled: true,
              acceptedFinalized: true,
              claimTerminal: { outcome: 'semantic-only', ...result.semanticEvidence },
              claimSemanticCheckpoint: item.claimSemanticObservation,
            });
            store.completeAction(claimAction, 'semantic-only');
          } else {
            replacePlanItem(store, item.tokenSlot, { claimOutboxPrepared: false });
            store.releaseAction(claimAction);
          }
          return { unresolved: false, settled: true };
        }
        return fail(
          'WITHDRAWAL_CLAIM_OUTBOX_MISSING',
          new Error('persisted claim hash has no durable outbox action'),
          item,
          claimAction,
        );
      }
      if (result.transactionHash && !item.claimTxHash) {
        replacePlanItem(store, item.tokenSlot, {
          claimTxHash: result.transactionHash,
          claimOutboxPrepared: true,
        });
      }
      if (result.phase !== 'terminal') return { unresolved: true, settled: false };
      replacePlanItem(store, item.tokenSlot, {
        claimOutboxPrepared: false,
        claimNonceSettled: true,
        acceptedFinalized: true,
        claimTerminal: result.terminal,
        claimSemanticCheckpoint: item.claimSemanticObservation || durableObservation,
      });
      store.completeAction(claimAction, result.terminal && result.terminal.outcome || 'finalized');
      log.info({ event: 'WITHDRAWAL_CLAIM_SIGNER_NONCE_SETTLED', channel: ch.id, txHash: result.transactionHash });
      return { unresolved: false, settled: true };
    }

    item = store.get('exitClaimPlan').claims.find((entry) => entry.tokenSlot === original.tokenSlot);
    const fundsAction = item.fundsOutboxActionId || `${creditActionId(ch, item.nullifier)}:channel-funds`;
    if (((item.fundsOutboxPrepared || item.fundsPullTxHash) && !item.fundsNonceSettled)
        || (item.fundsSemanticObservation && item.fundsPulledFinalized !== true)) {
      if (typeof claimSettlement.reconcileFunds !== 'function') return { unresolved: true, settled: false };
      let result;
      try {
        // eslint-disable-next-line no-await-in-loop
        result = await claimSettlement.reconcileFunds(
          ch.manager,
          item.nullifier,
          item.tokenIndex,
          item.amount,
          item.fundsSemanticObservation || durableObservation,
          fundsAction,
        );
      } catch (error) {
        // eslint-disable-next-line no-await-in-loop
        return fail('CHANNEL_FUNDS_SETTLEMENT_FAILED', error, item, fundsAction);
      }
      if (result.phase === 'absent') {
        if (!item.fundsPullTxHash) {
          if (result.semanticVerified === true) {
            replacePlanItem(store, item.tokenSlot, {
              fundsOutboxPrepared: false,
              fundsPullTxHash: null,
              fundsNonceSettled: true,
              fundsPulledFinalized: true,
              fundsTerminal: { outcome: 'semantic-only', ...result.semanticEvidence },
              fundsSemanticCheckpoint: item.fundsSemanticObservation,
            });
            store.completeAction(fundsAction, 'semantic-only');
          } else {
            replacePlanItem(store, item.tokenSlot, { fundsOutboxPrepared: false });
            store.releaseAction(fundsAction);
          }
          return { unresolved: false, settled: true };
        }
        return fail(
          'CHANNEL_FUNDS_OUTBOX_MISSING',
          new Error('persisted channel-funds hash has no durable outbox action'),
          item,
          fundsAction,
        );
      }
      if (result.transactionHash && !item.fundsPullTxHash) {
        replacePlanItem(store, item.tokenSlot, {
          fundsPullTxHash: result.transactionHash,
          fundsOutboxPrepared: true,
        });
      }
      if (result.phase !== 'terminal') return { unresolved: true, settled: false };
      replacePlanItem(store, item.tokenSlot, {
        fundsOutboxPrepared: false,
        fundsPullTxHash: null,
        fundsNonceSettled: true,
        fundsPulledFinalized: true,
        fundsTerminal: result.terminal,
        fundsSemanticCheckpoint: item.fundsSemanticObservation || durableObservation,
      });
      store.completeAction(fundsAction, result.terminal && result.terminal.outcome || 'finalized');
      log.info({ event: 'CHANNEL_FUNDS_SIGNER_NONCE_SETTLED', channel: ch.id, txHash: result.transactionHash });
      return { unresolved: false, settled: true };
    }

    item = store.get('exitClaimPlan').claims.find((entry) => entry.tokenSlot === original.tokenSlot);
    const creditAction = item.creditOutboxActionId || creditActionId(ch, item.nullifier);
    if (((item.creditOutboxPrepared || item.pullTxHash) && !item.creditNonceSettled)
        || (item.creditSemanticObservation && item.paidFinalized !== true)) {
      if (typeof claimSettlement.reconcileCredit !== 'function') return { unresolved: true, settled: false };
      let result;
      try {
        // eslint-disable-next-line no-await-in-loop
        result = await claimSettlement.reconcileCredit(
          ch.manager,
          item.nullifier,
          item.tokenIndex,
          item.payoutAmount || item.amount,
          item.creditSemanticObservation || durableObservation,
          creditAction,
        );
      } catch (error) {
        // eslint-disable-next-line no-await-in-loop
        return fail('WITHDRAWAL_CREDIT_SETTLEMENT_FAILED', error, item, creditAction);
      }
      if (result.phase === 'absent') {
        if (!item.pullTxHash) {
          if (result.semanticVerified === true) {
            replacePlanItem(store, item.tokenSlot, {
              creditOutboxPrepared: false,
              creditNonceSettled: true,
              paidFinalized: true,
              creditTerminal: { outcome: 'semantic-only', ...result.semanticEvidence },
              creditSemanticCheckpoint: item.creditSemanticObservation,
            });
            store.completeAction(creditAction, 'semantic-only');
            completeExitIfPaid(ctx, {
              kind: 'durable-semantic-settlement',
              txHash: item.creditSemanticObservation
                && item.creditSemanticObservation.transactionHash,
              args: { tokenIndex: item.tokenIndex, amount: item.payoutAmount || item.amount },
            });
          } else {
            replacePlanItem(store, item.tokenSlot, { creditOutboxPrepared: false });
            store.releaseAction(creditAction);
          }
          return { unresolved: false, settled: true };
        }
        return fail(
          'WITHDRAWAL_CREDIT_OUTBOX_MISSING',
          new Error('persisted credit hash has no durable outbox action'),
          item,
          creditAction,
        );
      }
      if (result.transactionHash && !item.pullTxHash) {
        replacePlanItem(store, item.tokenSlot, {
          pullTxHash: result.transactionHash,
          creditOutboxPrepared: true,
        });
      }
      if (result.phase !== 'terminal') return { unresolved: true, settled: false };
      replacePlanItem(store, item.tokenSlot, {
        creditOutboxPrepared: false,
        creditNonceSettled: true,
        paidFinalized: true,
        creditTerminal: result.terminal,
        creditSemanticCheckpoint: item.creditSemanticObservation || durableObservation,
      });
      store.completeAction(creditAction, result.terminal && result.terminal.outcome || 'finalized');
      log.info({ event: 'WITHDRAWAL_CREDIT_SIGNER_NONCE_SETTLED', channel: ch.id, txHash: result.transactionHash });
      completeExitIfPaid(ctx, {
        kind: 'durable-outbox-settlement',
        txHash: result.transactionHash,
        args: { tokenIndex: item.tokenIndex, amount: item.payoutAmount || item.amount },
      });
      return { unresolved: false, settled: true };
    }
  }
  return { unresolved: false, settled: false };
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
  const previousLifecycle = currentCloseLifecycle(store);
  const head = store.get('acceptedHead');
  const a = event.args || {};
  const requestedOnly = event.kind === 'CloseRequested';
  const digest = a.closeIntentDigest || a.specialCloseDigest || null;
  let pendingV = null;
  let challengeDeadline = null;
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
    if (a.challengeDeadline != null) {
      challengeDeadline = canonicalU64(a.challengeDeadline, 'close challengeDeadline');
    }
    if (head) {
      canonicalU64(head.epoch == null ? 0 : head.epoch, 'accepted head epoch');
      canonicalU64(head.stateVersion == null ? 0 : head.stateVersion, 'accepted head stateVersion');
    }
  } catch (error) {
    persistCloseLifecycle(
      store,
      requestedOnly ? CLOSE_PHASES.REQUESTED : CLOSE_PHASES.SUBMITTED,
      event,
      {
        closeIntentDigest: digest,
        closeKey: closeObservationKey(event, digest),
        malformed: true,
      },
    );
    // A request is only a freeze.  No claim exists and no finalization is legal until a proved
    // CloseSubmitted transition has supplied a deadline.
    store.set('awaitingClaim', !requestedOnly);
    return enterExitMode({
      kind: 'malformed_close_version',
      reason: String(error && error.message || error),
      evidence: { head, args: a, txHash: event.txHash },
    }, ctx, 'MALFORMED_CLOSE_VERSION');
  }

  if (requestedOnly) {
    persistCloseLifecycle(store, CLOSE_PHASES.REQUESTED, event, {
      closeFreezeNonce: a.closeFreezeNonce == null
        ? null
        : canonicalU64(a.closeFreezeNonce, 'close freeze nonce'),
      closeRequestedAt: a.closeRequestedAt == null
        ? null
        : canonicalU64(a.closeRequestedAt, 'close requested at'),
      closeIntentDigest: null,
      closeKey: closeObservationKey(event, null),
      challengeDeadline: null,
      journalGap: false,
    });
    setIfChanged(store, 'participantCloseJournalGapAlerted', false);
    store.set('channelFinalized', false);
    store.set('awaitingClaim', false);
    const submission = store.get('participantCloseSubmission');
    const submittedByUs = submission && submission.actionId && (
      sameHex(submission.txHash, event.txHash)
      || await actionOwnsTransaction(
        ctx.participantCloser,
        submission.outboxActionId || submission.actionId,
        event.txHash,
      )
    );
    if (submission && submission.actionId) {
      setIfChanged(store, 'participantCloseSubmission', {
        ...submission,
        semanticObservation: journaledSemanticObservation(event, {
          requester: a.requester,
          closeFreezeNonce: String(a.closeFreezeNonce),
        }),
      });
    }
    if (submittedByUs
        && ctx.participantCloser
        && typeof ctx.participantCloser.markRequestFinalized === 'function') {
      await ctx.participantCloser.markRequestFinalized(
        ch.manager,
        submission.actionId,
        finalizedTransactionObservation(event),
        submission.era,
      );
      store.completeAction(submission.actionId, 'finalized');
    }
    ensureExitMode(ctx);
    log.info({
      event: 'CLOSE_REQUESTED_OBSERVED',
      channel: ch.id,
      txHash: event.txHash,
      phase: CLOSE_PHASES.REQUESTED,
      note: 'channel is frozen; waiting for an authenticated CloseSubmitted proof, not a claim',
    });
    return;
  }

  const closeKey = closeObservationKey(event, digest);
  if (previousLifecycle.closeKey && previousLifecycle.closeIntentDigest
      && !sameHex(previousLifecycle.closeIntentDigest, digest)) {
    const priorFinalize = finalizeJournalEntry(store, previousLifecycle.closeKey);
    if (priorFinalize && !['finalized', 'superseded-revert'].includes(priorFinalize.status)) {
      setFinalizeJournalEntry(store, previousLifecycle.closeKey, {
        ...priorFinalize,
        semanticObservation: journaledSemanticObservation(event, {
          closeIntentDigest: digest,
        }),
      });
    }
  }
  persistCloseLifecycle(store, CLOSE_PHASES.SUBMITTED, event, {
    closeIntentDigest: digest,
    closeKey,
    closeFreezeNonce: a.closeFreezeNonce == null
      ? null
      : canonicalU64(a.closeFreezeNonce, 'close freeze nonce'),
    challengeDeadline,
    finalEpoch: pendingV && pendingV.epoch,
    finalStateVersion: pendingV && pendingV.stateVersion,
    journalGap: false,
  });
  setIfChanged(store, 'closeFinalizeJournalGapAlerted', false);
  store.set('awaitingClaim', true);
  log.info({ event: 'CLOSE_SEEN', channel: ch.id, txHash: event.txHash, head, pendingV, challengeDeadline });
  if (head && pendingV && (BigInt(pendingV.epoch) < BigInt(head.epoch) ||
      (BigInt(pendingV.epoch) === BigInt(head.epoch) && BigInt(pendingV.stateVersion) < BigInt(head.stateVersion)))) {
    await enterExitMode({
      kind: 'stale_close',
      reason: 'close against stale state',
      evidence: { head, pendingV, txHash: event.txHash },
    }, ctx, 'STALE_CLOSE_AGAINST_US');
    return;
  }
  // Even an honest close makes further off-chain sends unsafe/useless. Enter the same sticky
  // recovery state without labelling it an attack, so EXIT_DONE is reachable after payout.
  ensureExitMode(ctx);
  // Do not emit a transaction while the watcher may still be processing later logs from the same
  // finalized batch.  index.js runs one recovery tick immediately after the complete poll, where
  // the authoritative end-of-batch manager state and deadline are reconciled first.
}

// Cancellation restores Active.  An exiting delegate must not stay wedged behind the old
// `awaitingClaim` latch: clear the cancelled era and use its durable participant witness to freeze
// the channel again.  Normal-mode delegates merely reconcile the observation.
async function onCloseCancelled(event, ctx) {
  const { ch, store, log } = ctx;
  if (!isConfiguredManagerEvent(event, ctx, ['CloseCancelled'])) return;
  const previous = currentCloseLifecycle(store);
  const a = event.args || {};
  persistCloseLifecycle(store, CLOSE_PHASES.CANCELLED, event, {
    closeIntentDigest: a.closeIntentDigest || previous.closeIntentDigest || null,
    closeKey: closeObservationKey(event, a.closeIntentDigest || previous.closeIntentDigest),
    challengeDeadline: null,
    revivedChannelStateDigest: a.revivedChannelStateDigest || null,
    revivedStateVersion: a.revivedStateVersion == null
      ? null
      : canonicalU64(a.revivedStateVersion, 'revived state version'),
    journalGap: false,
  });
  // A cancelled era releases the publisher head pin: the next request targets the head current
  // at that time, and the native journal (keyed by digest) decides what may be replayed.
  setIfChanged(store, 'publicClosePublication', null);
  setIfChanged(store, 'publicClosePublisherHeadPinnedLogged', false);
  setIfChanged(store, 'participantCloseJournalGapAlerted', false);
  setIfChanged(store, 'closeFinalizeJournalGapAlerted', false);
  store.set('awaitingClaim', false);
  store.set('channelFinalized', false);
  store.set('closeFinalizedBlock', null);

  const priorSubmission = store.get('participantCloseSubmission');
  if (priorSubmission && ctx.participantCloser
      && ctx.participantCloser.durableOutbox === true
      && !priorSubmission.semanticObservation) {
    setIfChanged(store, 'participantCloseSubmission', {
      ...priorSubmission,
      semanticObservation: journaledSemanticObservation(event, {
        closeIntentDigest: a.closeIntentDigest || previous.closeIntentDigest,
        revivedChannelStateDigest: a.revivedChannelStateDigest,
        revivedStateVersion: a.revivedStateVersion == null ? null : String(a.revivedStateVersion),
      }),
    });
  }
  if (!(priorSubmission && ctx.participantCloser
      && ctx.participantCloser.durableOutbox === true)) {
    store.set('participantCloseSubmission', null);
    store.releaseAction(
      priorSubmission && priorSubmission.actionId
        ? priorSubmission.actionId
        : `participant-close:${ch.id}:${ctx.slot}`,
    );
  }
  if (previous.closeKey && !(ctx.participantCloser
      && ctx.participantCloser.durableOutbox === true)) {
    store.releaseAction(closeFinalizeActionId(
      ch,
      previous.closeKey,
      previous.closeRequestGeneration,
    ));
  }
  if (previous.closeKey && ctx.participantCloser
      && ctx.participantCloser.durableOutbox === true) {
    const priorFinalize = finalizeJournalEntry(store, previous.closeKey);
    if (priorFinalize && !['finalized', 'superseded-revert'].includes(priorFinalize.status)) {
      setFinalizeJournalEntry(store, previous.closeKey, {
        ...priorFinalize,
        semanticObservation: journaledSemanticObservation(event, {
          closeIntentDigest: a.closeIntentDigest || previous.closeIntentDigest,
          revivedChannelStateDigest: a.revivedChannelStateDigest,
          revivedStateVersion: a.revivedStateVersion == null ? null : String(a.revivedStateVersion),
        }),
      });
    }
  }
  log.info({
    event: 'CLOSE_CANCELLED_RECONCILED',
    channel: ch.id,
    closeIntentDigest: a.closeIntentDigest,
    txHash: event.txHash,
    retryingParticipantClose: store.get('mode') === 'exiting',
  });
  // Re-requesting inside a chain callback could race a later request/submission log in the same
  // finalized batch.  The post-poll recovery tick performs the retry against the batch's final
  // authenticated manager state.
}

// Channel finalized → claim every positive token balance in our slot.
async function onChannelFinalized(event, ctx) {
  if (!isConfiguredManagerEvent(event, ctx, ['CloseFinalized'])) return;
  ensureExitMode(ctx);
  const a = event.args || {};
  const previous = currentCloseLifecycle(ctx.store);
  persistCloseLifecycle(ctx.store, CLOSE_PHASES.FINALIZED, event, {
    closeIntentDigest: a.closeIntentDigest || previous.closeIntentDigest || null,
    closeKey: previous.closeKey || closeObservationKey(event, a.closeIntentDigest),
    challengeDeadline: previous.challengeDeadline || null,
    journalGap: false,
  });
  setIfChanged(ctx.store, 'closeFinalizeJournalGapAlerted', false);
  ctx.store.set('channelFinalized', true);
  if (event && event.blockNumber != null) ctx.store.set('closeFinalizedBlock', event.blockNumber);
  ctx.store.set('awaitingClaim', true);
  // A foreign semantic finalization does not consume this recipient signer's nonce.  The durable
  // submission remains pending until the recovery tick proves our exact raw succeeded or its
  // active nonce has a canonical-finalized revert.
  if (previous.closeKey) {
    const finalizeEntry = finalizeJournalEntry(ctx.store, previous.closeKey);
    const finalizeActionId = finalizeEntry && (finalizeEntry.outboxActionId || finalizeEntry.actionId)
      || closeFinalizeActionId(ctx.ch, previous.closeKey, previous.closeRequestGeneration);
    if (finalizeEntry && !['finalized', 'superseded-revert'].includes(finalizeEntry.status)) {
      setFinalizeJournalEntry(ctx.store, previous.closeKey, {
        ...finalizeEntry,
        semanticObservation: journaledSemanticObservation(event, {
          closeIntentDigest: a.closeIntentDigest || previous.closeIntentDigest,
        }),
      });
    }
    const finalizedByUs = finalizeEntry && (
      sameHex(finalizeEntry.txHash, event.txHash)
      || await actionOwnsTransaction(
        ctx.participantCloser,
        finalizeEntry.outboxActionId || finalizeActionId,
        event.txHash,
      )
    );
    if (finalizedByUs
        && finalizeEntry.closeRequestGeneration != null
        && ctx.participantCloser
        && typeof ctx.participantCloser.markFinalizeFinalized === 'function') {
      await ctx.participantCloser.markFinalizeFinalized(
        ctx.ch.manager,
        finalizeActionId,
        previous.closeIntentDigest || a.closeIntentDigest,
        finalizeEntry.closeRequestGeneration || previous.closeRequestGeneration,
        finalizedTransactionObservation(event),
      );
      ctx.store.completeAction(finalizeActionId, 'finalized');
    }
  }
  if (ctx.participantCloser && ctx.participantCloser.durableOutbox === true) {
    // Finish the watcher batch first. The recovery tick settles any older request/finalize nonce
    // under the stable durable manager checkpoint before a claim sharing this signer is attempted.
    return;
  }
  return attemptRecovery(ctx);
}

function claimActionId(ch, slot, tokenSlot) {
  return `claim:${ch.id}:${slot}:${tokenSlot}`;
}

function creditActionId(ch, withdrawalNullifier) {
  return `credit-pull:${ch.id}:${String(withdrawalNullifier).toLowerCase()}`;
}

function completeExitIfPaid(ctx, event = null) {
  const plan = ctx.store.get('exitClaimPlan');
  if (!plan || !Array.isArray(plan.claims)
      || plan.claims.length === 0
      || !plan.claims.every((item) => item.paidFinalized === true)) return false;
  if (ctx.claimSettlement && ctx.claimSettlement.durableOutbox === true
      && plan.claims.some((item) => (
        ((item.claimOutboxPrepared || item.claimTxHash) && item.claimNonceSettled !== true)
        || ((item.fundsOutboxPrepared || item.fundsPullTxHash) && item.fundsNonceSettled !== true)
        || ((item.creditOutboxPrepared || item.pullTxHash) && item.creditNonceSettled !== true)
      ))) return false;
  // The state-machine transition is itself durable. Perform it before clearing the presentation
  // latch so a crash between the two writes cannot leave an all-paid exit permanently in EXITING.
  ctx.sm.signal(dsm.SIGNALS.EXIT_DONE);
  ctx.store.set('awaitingCredit', false);
  const args = event && event.args || {};
  ctx.log.info({
    event: 'EXIT_CONFIRMED',
    channel: ctx.ch.id,
    recipient: args.recipient || ctx.recipient || null,
    amount: args.amount == null ? null : args.amount,
    tokenIndex: args.tokenIndex == null ? null : String(args.tokenIndex),
    kind: event && event.kind || 'durable-reconciliation',
    txHash: event && event.txHash || null,
  });
  return true;
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
    if (item.paidFinalized || item.acceptedFinalized !== true || !item.nullifier) continue;
    const actionId = creditActionId(ch, item.nullifier);
    if ((item.fundsOutboxPrepared || item.fundsPullTxHash) && !item.fundsNonceSettled) {
      // eslint-disable-next-line no-await-in-loop
      const fundStatus = item.fundsPullTxHash
        ? await claimSettlement.transactionStatus(item.fundsPullTxHash)
        : 'prepared';
      // A mined receipt is not terminal: the signer-wide lease remains until the finalized
      // ChannelFundsPulled observation authenticates the exact effect. Missing is retried through
      // the same outbox raw bytes; failed requires an explicit operator replacement.
      if (fundStatus === 'pending' || fundStatus === 'mined' || fundStatus === 'failed') continue;
      if (claimSettlement.durableOutbox === true) continue;
    }
    if ((item.creditOutboxPrepared || item.pullTxHash) && !item.creditNonceSettled) {
      // Do not emit a second payout transaction while the first is pending/mined but not yet in
      // the finalized watcher range. A dropped/reverted tx clears the marker and becomes retryable.
      // eslint-disable-next-line no-await-in-loop
      const txStatus = item.pullTxHash
        ? await claimSettlement.transactionStatus(item.pullTxHash)
        : 'prepared';
      if (txStatus === 'pending' || txStatus === 'mined') continue;
      if (claimSettlement.durableOutbox === true) continue;
      if (claimSettlement.durableOutbox !== true) {
        replacePlanItem(store, item.tokenSlot, { pullTxHash: null });
        store.releaseAction(actionId);
      }
    }
    if (!store.claimAction(actionId, { retryPending: true })) continue;
    try {
      // eslint-disable-next-line no-await-in-loop
      const pulled = await claimSettlement.pullCredit(ch.manager, item.nullifier, item.tokenIndex, item.amount, (broadcast) => {
        if (broadcast.phase === 'channel-funds') {
          replacePlanItem(store, item.tokenSlot, {
            fundsOutboxPrepared: true,
            fundsPullTxHash: broadcast.txHash,
            fundsOutboxActionId: broadcast.outboxActionId || null,
          });
        } else if (broadcast.phase === 'credit') {
          replacePlanItem(store, item.tokenSlot, {
            fundsPullTxHash: null,
            creditOutboxPrepared: true,
            pullTxHash: broadcast.txHash,
            creditOutboxActionId: broadcast.outboxActionId || null,
            payoutAmount: broadcast.amount,
          });
        }
      }, {
        actionId,
        fundsActionId: `${actionId}:channel-funds`,
        onPrepared: async (prepared) => {
          if (prepared.phase === 'channel-funds') {
            replacePlanItem(store, item.tokenSlot, {
              fundsOutboxPrepared: true,
              fundsOutboxActionId: prepared.actionId,
            });
          } else if (prepared.phase === 'credit') {
            replacePlanItem(store, item.tokenSlot, {
              creditOutboxPrepared: true,
              creditOutboxActionId: prepared.actionId,
              payoutAmount: prepared.amount,
            });
          }
          store.claimAction(prepared.actionId, { retryPending: true });
        },
      });
      if (pulled.noCredit) {
        store.releaseAction(actionId);
        continue;
      }
      replacePlanItem(store, item.tokenSlot, {
        creditOutboxPrepared: true,
        pullTxHash: pulled.txHash,
        creditOutboxActionId: pulled.outboxActionId || null,
        payoutAmount: pulled.amount,
      });
      log.info({ event: 'WITHDRAWAL_CREDIT_TX_SUBMITTED', channel: ch.id, tokenIndex: item.tokenIndex, txHash: pulled.txHash });
    } catch (e) {
      const current = store.get('exitClaimPlan').claims.find((c) => c.tokenSlot === item.tokenSlot);
      if (!current || (!current.fundsOutboxPrepared && !current.fundsPullTxHash
          && !current.creditOutboxPrepared && !current.pullTxHash)) store.releaseAction(actionId);
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
  attachDeferredExitSemantics(ctx);

  if (plan.claims.length === 0) {
    store.set('awaitingClaim', false);
    store.set('awaitingCredit', false);
    ctx.sm.signal(dsm.SIGNALS.EXIT_DONE);
    log.info({ event: 'EXIT_CONFIRMED_ZERO_BALANCE', channel: ch.id });
    return;
  }
  if (completeExitIfPaid(ctx)) return;

  for (const original of plan.claims) {
    let item = store.get('exitClaimPlan').claims.find((c) => c.tokenSlot === original.tokenSlot);
    const actionId = claimActionId(ch, ctx.slot, item.tokenSlot);
    if (item.nullifier) {
      // eslint-disable-next-line no-await-in-loop
      const status = await claimSettlement.claimStatus(ch.manager, item.nullifier, item.claimTxHash);
      if (status === 'accepted' || status === 'mined' || status === 'pending') continue;
      if (claimSettlement.durableOutbox === true
          && (item.claimOutboxPrepared || item.claimTxHash)) continue;
      if (claimSettlement.durableOutbox !== true) {
        replacePlanItem(store, item.tokenSlot, {
          nullifier: null,
          claimTxHash: null,
          claimArtifact: null,
        });
        store.releaseAction(actionId);
        item = store.get('exitClaimPlan').claims.find((c) => c.tokenSlot === original.tokenSlot);
      }
    }
    try {
      const wasmContext = {
        closeIntentDigest: finalized.closeIntentDigest,
        finalChannelStateDigest: finalized.finalChannelStateDigest,
        finalBalanceStateH1: finalized.finalBalanceStateH1,
      };
      // Heavy proving happens here, inside WASM. Its public proof may be randomized, so persist the
      // exact artifact before any code can enter the signed-transaction outbox and reuse it after
      // restart instead of regenerating different calldata for the same action id.
      const artifact = item.claimArtifact || wallet.withdrawalClaim(wasmContext, item.tokenSlot);
      if (!artifact || !artifact.claim
          || Number(artifact.claim.tokenSlot) !== Number(item.tokenSlot)
          || Number(artifact.claim.tokenIndex) !== Number(item.tokenIndex)
          || String(artifact.claim.amount) !== String(item.amount)
          || !sameHex(artifact.claim.closeIntentDigest, finalized.closeIntentDigest)) {
        throw new Error('wallet claim artifact disagrees with the finalized exit-plan economics');
      }
      replacePlanItem(store, item.tokenSlot, {
        claimArtifact: artifact,
        nullifier: artifact.claim.withdrawalNullifier,
        memberPkG: artifact.claim.memberPkG,
        claimOutboxActionId: actionId,
      });
      attachDeferredExitSemantics(ctx);
      if (!store.claimAction(actionId, { retryPending: true })) continue;
      replacePlanItem(store, item.tokenSlot, { claimOutboxPrepared: true });
      // eslint-disable-next-line no-await-in-loop
      const submitted = await claimSettlement.submitClaim(
        ch.manager,
        artifact,
        finalized,
        item.tokenSlot,
        (txHash) => replacePlanItem(store, item.tokenSlot, {
          nullifier: artifact.claim.withdrawalNullifier,
          claimTxHash: txHash,
          claimOutboxActionId: actionId,
        }),
        {
          actionId,
          onPrepared: async () => replacePlanItem(store, item.tokenSlot, {
            claimOutboxPrepared: true,
            claimOutboxActionId: actionId,
          }),
        },
      );
      replacePlanItem(store, item.tokenSlot, {
        nullifier: submitted.nullifier,
        claimTxHash: submitted.txHash || null,
        claimOutboxActionId: submitted.outboxActionId || null,
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
      if (uncertainHash) replacePlanItem(store, item.tokenSlot, {
        claimTxHash: uncertainHash,
        claimOutboxActionId: actionId,
      });
      else if (claimSettlement.durableOutbox !== true) store.releaseAction(actionId);
      // eslint-disable-next-line no-await-in-loop
      await alert.raise('fault', ch.id, 'CLAIM_FAILED', String(e && e.message || e), { tokenSlot: item.tokenSlot, uncertainTxHash: uncertainHash || null });
    }
  }
  await attemptDirectCreditPull(ctx);
}

async function reconcileCloseLifecycle(ctx) {
  const { ch, store, readDurableCloseState } = ctx;
  if (typeof readDurableCloseState !== 'function') {
    return { lifecycle: currentCloseLifecycle(store), chain: null };
  }
  const chain = await readDurableCloseState(ch.manager);
  if (!chain) return { lifecycle: currentCloseLifecycle(store), chain: null };
  const current = currentCloseLifecycle(store);
  const pending = chain.pending || {};
  const closeRequestGeneration = canonicalU64(
    chain.closeRequestGenerationExact,
    'reconciled close request generation',
  );

  if (chain.status === 2) {
    if (current.phase !== CLOSE_PHASES.FINALIZED
        || current.closeRequestGeneration !== closeRequestGeneration) {
      persistCloseLifecycle(store, CLOSE_PHASES.FINALIZED, null, {
        closeIntentDigest: current.closeIntentDigest || pending.closeIntentDigest || null,
        closeKey: current.closeKey || closeObservationKey(
          { blockNumber: chain.durable.number },
          current.closeIntentDigest || pending.closeIntentDigest,
        ),
        observedBlockNumber: chain.durable.number,
        observedBlockHash: chain.durable.hash,
        closeRequestGeneration,
        journalGap: false,
      });
    }
    setIfChanged(store, 'channelFinalized', true);
    setIfChanged(store, 'closeFinalizedBlock', chain.durable.number);
    setIfChanged(store, 'awaitingClaim', true);
    return { lifecycle: currentCloseLifecycle(store), chain };
  }

  if (chain.status === 1 && pending.active) {
    const digest = pending.closeIntentDigest || current.closeIntentDigest || null;
    const deadline = canonicalU64(
      pending.challengeDeadlineExact == null ? pending.challengeDeadline : pending.challengeDeadlineExact,
      'reconciled challenge deadline',
    );
    const samePending = current.closeIntentDigest
      && sameHex(current.closeIntentDigest, digest)
      && current.challengeDeadline === deadline;
    const phase = samePending && current.phase === CLOSE_PHASES.FINALIZE_BROADCAST
      ? CLOSE_PHASES.FINALIZE_BROADCAST
      : CLOSE_PHASES.SUBMITTED;
    if (!samePending || current.phase !== phase
        || current.closeRequestGeneration !== closeRequestGeneration) {
      persistCloseLifecycle(store, phase, null, {
        closeIntentDigest: digest,
        closeKey: samePending && current.closeKey
          ? current.closeKey
          : closeObservationKey({ blockNumber: chain.durable.number }, digest),
        closeFreezeNonce: canonicalU64(
          pending.closeFreezeNonceExact == null ? pending.closeFreezeNonce : pending.closeFreezeNonceExact,
          'reconciled close freeze nonce',
        ),
        closeRequestGeneration,
        challengeDeadline: deadline,
        finalEpoch: canonicalU64(
          pending.epochExact == null ? pending.epoch : pending.epochExact,
          'reconciled final epoch',
        ),
        finalStateVersion: canonicalU64(
          pending.stateVersionExact == null ? pending.stateVersion : pending.stateVersionExact,
          'reconciled final state version',
        ),
        observedBlockNumber: chain.durable.number,
        observedBlockHash: chain.durable.hash,
        journalGap: false,
      });
    }
    setIfChanged(store, 'channelFinalized', false);
    setIfChanged(store, 'awaitingClaim', true);
    return { lifecycle: currentCloseLifecycle(store), chain };
  }

  if (chain.status === 1) {
    if (current.phase !== CLOSE_PHASES.REQUESTED
        || current.closeRequestGeneration !== closeRequestGeneration) {
      persistCloseLifecycle(store, CLOSE_PHASES.REQUESTED, null, {
        closeIntentDigest: null,
        closeKey: closeObservationKey({ blockNumber: chain.durable.number }, null),
        closeFreezeNonce: pending.closeFreezeNonceExact == null
          ? null
          : canonicalU64(pending.closeFreezeNonceExact, 'reconciled close freeze nonce'),
        challengeDeadline: null,
        closeRequestGeneration,
        observedBlockNumber: chain.durable.number,
        observedBlockHash: chain.durable.hash,
        journalGap: false,
      });
    }
    setIfChanged(store, 'channelFinalized', false);
    setIfChanged(store, 'awaitingClaim', false);
    return { lifecycle: currentCloseLifecycle(store), chain };
  }

  // Active is expected for a fresh/cancelled channel and may also coexist with a locally
  // broadcast request that is not durable yet.  Only a previously durable frozen phase proves a
  // cancellation/reorg-safe restoration and is converted to CANCELLED here.
  if ([
    CLOSE_PHASES.REQUESTED,
    CLOSE_PHASES.SUBMITTED,
    CLOSE_PHASES.FINALIZE_BROADCAST,
    CLOSE_PHASES.LEGACY_FROZEN,
  ].includes(current.phase)) {
    persistCloseLifecycle(store, CLOSE_PHASES.CANCELLED, null, {
      closeIntentDigest: current.closeIntentDigest || null,
      closeKey: closeObservationKey({ blockNumber: chain.durable.number }, current.closeIntentDigest),
      challengeDeadline: null,
      closeRequestGeneration,
      observedBlockNumber: chain.durable.number,
      observedBlockHash: chain.durable.hash,
      observedTxHash: null,
      observedLogIndex: null,
      journalGap: false,
    });
    setIfChanged(store, 'publicClosePublication', null);
    setIfChanged(store, 'publicClosePublisherHeadPinnedLogged', false);
    const submission = store.get('participantCloseSubmission');
    if (!(submission && ctx.participantCloser
        && ctx.participantCloser.durableOutbox === true)) {
      setIfChanged(store, 'participantCloseSubmission', null);
      store.releaseAction(
        submission && submission.actionId
          ? submission.actionId
          : `participant-close:${ch.id}:${ctx.slot}`,
      );
    }
    if (current.closeKey && !(ctx.participantCloser
        && ctx.participantCloser.durableOutbox === true)) {
      store.releaseAction(closeFinalizeActionId(
        ch,
        current.closeKey,
        current.closeRequestGeneration,
      ));
    }
  }
  setIfChanged(store, 'channelFinalized', false);
  setIfChanged(store, 'awaitingClaim', false);
  return { lifecycle: currentCloseLifecycle(store), chain };
}

async function attemptCloseFinalize(ctx, alreadyReconciled = null) {
  const { ch, store, log, alert, participantCloser } = ctx;
  let reconciled = alreadyReconciled;
  try {
    if (!reconciled) reconciled = await reconcileCloseLifecycle(ctx);
    if (store.get('closeFinalizeReconcileAlerted')) store.set('closeFinalizeReconcileAlerted', false);
  } catch (e) {
    if (!store.get('closeFinalizeReconcileAlerted')) {
      store.set('closeFinalizeReconcileAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'CLOSE_FINALIZE_RECONCILE_FAILED',
        String(e && e.message || e),
        { note: 'finalization remains fail-closed until a durable manager state can be read' },
      );
    }
    return;
  }
  const lifecycle = reconciled.lifecycle;
  if (![CLOSE_PHASES.SUBMITTED, CLOSE_PHASES.FINALIZE_BROADCAST].includes(lifecycle.phase)) return;
  if (!participantCloser || typeof participantCloser.finalizeCloseGuarded !== 'function') {
    if (!store.get('permissionlessFinalizeUnavailableAlerted')) {
      store.set('permissionlessFinalizeUnavailableAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'PERMISSIONLESS_FINALIZE_UNAVAILABLE',
        'cannot schedule finalizeCloseGuarded: delegate recipient signer is unavailable',
        { hasParticipantCloser: Boolean(participantCloser) },
      );
    }
    return;
  }
  if (lifecycle.challengeDeadline == null || !lifecycle.closeKey) {
    if (!store.get('closeFinalizeDeadlineUnavailableAlerted')) {
      store.set('closeFinalizeDeadlineUnavailableAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'CLOSE_FINALIZE_DEADLINE_UNAVAILABLE',
        'proved close is visible but its authenticated challenge deadline is unavailable',
        { lifecycle },
      );
    }
    return;
  }
  if (lifecycle.closeRequestGeneration == null) {
    if (!store.get('closeFinalizeGenerationUnavailableAlerted')) {
      store.set('closeFinalizeGenerationUnavailableAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'CLOSE_FINALIZE_GENERATION_UNAVAILABLE',
        'proved close is visible but its durable manager request generation is unavailable',
        { lifecycle },
      );
    }
    return;
  }
  setIfChanged(store, 'closeFinalizeGenerationUnavailableAlerted', false);
  const durableTimestamp = reconciled.chain && reconciled.chain.durable
    ? canonicalU64(reconciled.chain.durable.timestamp, 'durable chain timestamp')
    : null;
  if (durableTimestamp == null) {
    // Event-only test/compatibility runtimes do not have an authenticated time source.  Refuse to
    // substitute the host clock; their periodic recovery path becomes active once the production
    // watcher dependency is supplied.
    return;
  }
  if (BigInt(durableTimestamp) <= BigInt(lifecycle.challengeDeadline)) {
    log.info({
      event: 'CLOSE_FINALIZE_DEFERRED',
      channel: ch.id,
      closeIntentDigest: lifecycle.closeIntentDigest,
      durableTimestamp,
      challengeDeadline: lifecycle.challengeDeadline,
    });
    return;
  }

  const actionId = closeFinalizeActionId(
    ch,
    lifecycle.closeKey,
    lifecycle.closeRequestGeneration,
  );
  const prior = finalizeJournalEntry(store, lifecycle.closeKey);
  if (prior && prior.txHash && typeof participantCloser.transactionStatus === 'function') {
    const status = await participantCloser.transactionStatus(prior.txHash);
    if (status === 'pending' || status === 'mined') return;
    if (participantCloser.durableOutbox === true) return;
    setFinalizeJournalEntry(store, lifecycle.closeKey, { ...prior, status, reconciledAt: Date.now() });
    store.releaseAction(actionId);
  }
  if (pendingAction(store, actionId) && (!prior || !prior.txHash)) {
    if (!store.get('closeFinalizeJournalGapAlerted')) {
      store.set('closeFinalizeJournalGapAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'CLOSE_FINALIZE_JOURNAL_GAP',
        'a prior finalize attempt may have escaped without a durable transaction hash; refusing blind resubmission',
        { closeIntentDigest: lifecycle.closeIntentDigest, closeKey: lifecycle.closeKey },
      );
    }
    return;
  }
  if (participantCloser.durableOutbox === true) {
    if (prior && ['finalized', 'superseded-revert'].includes(prior.status)) return;
    // Persist every semantic field needed to locate/resume the deterministic outbox action before
    // entering code that can sign. A crash after the outbox WAL but before onBroadcast therefore
    // remains recoverable without reconstructing calldata from mutable lifecycle state.
    setFinalizeJournalEntry(store, lifecycle.closeKey, {
      ...(prior || {}),
      txHash: prior && prior.txHash || null,
      actionId,
      outboxActionId: actionId,
      closeKey: lifecycle.closeKey,
      closeIntentDigest: lifecycle.closeIntentDigest,
      challengeDeadline: lifecycle.challengeDeadline,
      closeRequestGeneration: lifecycle.closeRequestGeneration,
      status: 'prepared',
    });
  }
  if (!store.claimAction(actionId, { retryPending: true })) return;
  try {
    const rememberBroadcast = async (txHash) => {
      setFinalizeJournalEntry(store, lifecycle.closeKey, {
        txHash,
        actionId,
        outboxActionId: actionId,
        closeKey: lifecycle.closeKey,
        closeIntentDigest: lifecycle.closeIntentDigest,
        challengeDeadline: lifecycle.challengeDeadline,
        closeRequestGeneration: lifecycle.closeRequestGeneration,
        status: 'broadcast',
      });
      persistCloseLifecycle(store, CLOSE_PHASES.FINALIZE_BROADCAST, null, lifecycle);
      setIfChanged(store, 'closeFinalizeJournalGapAlerted', false);
    };
    const submitted = await participantCloser.finalizeCloseGuarded(
      ch.manager,
      lifecycle.closeIntentDigest,
      rememberBroadcast,
      { actionId, expectedCloseRequestGeneration: lifecycle.closeRequestGeneration },
    );
    if (!finalizeJournalEntry(store, lifecycle.closeKey)) await rememberBroadcast(submitted.txHash);
    log.info({
      event: 'CLOSE_FINALIZE_SUBMITTED',
      channel: ch.id,
      closeIntentDigest: lifecycle.closeIntentDigest,
      txHash: submitted.txHash,
      note: 'awaiting finalized CloseFinalized observation',
    });
  } catch (e) {
    const uncertainHash = e && (e.transactionHash || e.hash);
    if (uncertainHash) {
      setFinalizeJournalEntry(store, lifecycle.closeKey, {
        ...(finalizeJournalEntry(store, lifecycle.closeKey) || {}),
        txHash: uncertainHash,
        actionId,
        outboxActionId: actionId,
        closeKey: lifecycle.closeKey,
        closeIntentDigest: lifecycle.closeIntentDigest,
        challengeDeadline: lifecycle.challengeDeadline,
        closeRequestGeneration: lifecycle.closeRequestGeneration,
        status: 'uncertain',
      });
      persistCloseLifecycle(store, CLOSE_PHASES.FINALIZE_BROADCAST, null, lifecycle);
    } else if (e && e.definitelyNotBroadcast === true) {
      store.releaseAction(actionId);
      if (participantCloser.durableOutbox === true) {
        setFinalizeJournalEntry(store, lifecycle.closeKey, {
          ...(finalizeJournalEntry(store, lifecycle.closeKey) || {}),
          status: 'absent',
        });
      }
    } else {
      setFinalizeJournalEntry(store, lifecycle.closeKey, {
        ...(finalizeJournalEntry(store, lifecycle.closeKey) || {}),
        txHash: null,
        actionId,
        outboxActionId: actionId,
        closeKey: lifecycle.closeKey,
        closeIntentDigest: lifecycle.closeIntentDigest,
        challengeDeadline: lifecycle.challengeDeadline,
        closeRequestGeneration: lifecycle.closeRequestGeneration,
        status: 'broadcast_unknown',
      });
      persistCloseLifecycle(store, CLOSE_PHASES.FINALIZE_BROADCAST, null, {
        ...lifecycle,
        journalGap: true,
      });
    }
    await alert.raise('fault', ch.id, 'CLOSE_FINALIZE_FAILED', String(e && e.message || e), {
      closeIntentDigest: lifecycle.closeIntentDigest,
      uncertainTxHash: uncertainHash || null,
    });
  }
}

async function attemptCloseRequest(ctx) {
  const { ch, store, log, alert, participantCloser } = ctx;
  // A close is already visible/finalized. Calling requestCloseAsParticipant now can only revert
  // ChannelAlreadyFrozen and must not consume another recipient-account nonce.
  const startingLifecycle = currentCloseLifecycle(store);
  if ([
    CLOSE_PHASES.REQUESTED,
    CLOSE_PHASES.SUBMITTED,
    CLOSE_PHASES.FINALIZE_BROADCAST,
    CLOSE_PHASES.FINALIZED,
    CLOSE_PHASES.LEGACY_FROZEN,
  ].includes(startingLifecycle.phase) || store.get('channelFinalized')) return;
  if (await refuseCloseBelowAuthorizedBurn(ctx, store.get('acceptedHead'), 'close request')) return;
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
  let requestIdentity;
  try {
    requestIdentity = await participantRequestIdentity(ctx, startingLifecycle);
  } catch (error) {
    await alert.raise(
      'fault',
      ch.id,
      'PARTICIPANT_CLOSE_ERA_UNAVAILABLE',
      String(error && error.message || error),
      { note: 'no close transaction is signed without a hash-authenticated freeze-nonce era' },
    );
    return;
  }
  const { actionId, era } = requestIdentity;
  const savedPrior = store.get('participantCloseSubmission');
  if (savedPrior && participantCloser.durableOutbox === true && savedPrior.actionId !== actionId) {
    await alert.raise(
      'fault',
      ch.id,
      'PARTICIPANT_CLOSE_ERA_MISMATCH',
      'persisted participant close belongs to a different canonical freeze/cancellation era',
      { persistedActionId: savedPrior.actionId || null, expectedActionId: actionId },
    );
    return;
  }
  const prior = savedPrior;
  if (prior && prior.txHash && typeof participantCloser.transactionStatus === 'function') {
    const status = await participantCloser.transactionStatus(prior.txHash);
    if (status === 'pending' || status === 'mined') return;
    if (participantCloser.durableOutbox !== true) {
      store.set('participantCloseSubmission', null);
      store.releaseAction(actionId);
      persistCloseLifecycle(
        store,
        startingLifecycle.phase === CLOSE_PHASES.CANCELLED ? CLOSE_PHASES.CANCELLED : CLOSE_PHASES.OPEN,
        null,
        { closeIntentDigest: null, challengeDeadline: null },
      );
    }
  }
  if (pendingAction(store, actionId) && (!prior || !prior.txHash)
      && participantCloser.durableOutbox !== true) {
    if (!store.get('participantCloseJournalGapAlerted')) {
      store.set('participantCloseJournalGapAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'PARTICIPANT_CLOSE_JOURNAL_GAP',
        'a prior close request may have escaped without a durable transaction hash; refusing blind resubmission',
        { slot: ctx.slot },
      );
    }
    return;
  }
  if (!store.claimAction(actionId, { retryPending: true })) return;
  if (participantCloser.durableOutbox === true && !store.get('participantCloseSubmission')) {
    // Persist the canonical era before entering the outbox. This is non-secret metadata and lets
    // a restart recover the same action id even if the finalized checkpoint advances before the
    // raw-transaction fsync/broadcast callback.
    store.set('participantCloseSubmission', {
      txHash: null,
      actionId,
      outboxActionId: actionId,
      era,
      participantRoot: proof.participantRoot,
      slot: proof.slot,
      prepared: true,
    });
  }
  try {
    const rememberBroadcast = async (txHash, metadata = {}) => {
      store.set('participantCloseSubmission', {
        txHash,
        actionId,
        outboxActionId: metadata.actionId || actionId,
        era,
        participantRoot: proof.participantRoot,
        slot: proof.slot,
      });
      persistCloseLifecycle(store, CLOSE_PHASES.REQUEST_BROADCAST, null, {
        closeIntentDigest: null,
        closeKey: closeObservationKey({ txHash }, null),
        challengeDeadline: null,
        journalGap: false,
      });
      setIfChanged(store, 'participantCloseJournalGapAlerted', false);
    };
    const submitted = await participantCloser.requestClose(
      ch.manager,
      proof,
      rememberBroadcast,
      era ? { actionId, era } : undefined,
    );
    // Persist the hash before terminalizing the action. If the process dies after the send but
    // before this write, the still-pending action deliberately blocks blind resubmission; an
    // operator can reconcile the recipient nonce instead of risking two external effects.
    if (!store.get('participantCloseSubmission')) await rememberBroadcast(submitted.txHash);
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
      store.set('participantCloseSubmission', {
        txHash: uncertainHash,
        actionId,
        outboxActionId: actionId,
        era,
        slot: proof.slot,
        uncertain: true,
      });
      persistCloseLifecycle(store, CLOSE_PHASES.REQUEST_BROADCAST, null, {
        closeIntentDigest: null,
        closeKey: closeObservationKey({ txHash: uncertainHash }, null),
        challengeDeadline: null,
      });
    } else if (e && e.definitelyNotBroadcast === true) {
      store.releaseAction(actionId);
      const currentSubmission = store.get('participantCloseSubmission');
      if (currentSubmission && currentSubmission.actionId === actionId && !currentSubmission.txHash) {
        store.set('participantCloseSubmission', null);
      }
      persistCloseLifecycle(
        store,
        startingLifecycle.phase === CLOSE_PHASES.CANCELLED ? CLOSE_PHASES.CANCELLED : CLOSE_PHASES.OPEN,
        null,
        { closeIntentDigest: null, challengeDeadline: null },
      );
    } else {
      persistCloseLifecycle(store, CLOSE_PHASES.REQUEST_BROADCAST, null, {
        closeIntentDigest: null,
        closeKey: closeObservationKey(null, null),
        challengeDeadline: null,
        journalGap: true,
      });
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
  const lifecycle = currentCloseLifecycle(ctx.store);
  const expectedCloseDigest = plan && plan.closeIntentDigest
    || lifecycle.phase === CLOSE_PHASES.FINALIZED && lifecycle.closeIntentDigest;
  if (!expectedCloseDigest || !sameHex(a.closeIntentDigest, expectedCloseDigest)) return;
  if (!/^0x[0-9a-f]{64}$/i.test(String(a.withdrawalNullifier || ''))
      || !/^0x[0-9a-f]{64}$/i.test(String(a.memberPkG || ''))) return;
  const participantProof = ctx.store.get('participantCloseProof');
  if (participantProof && participantProof.pkG && !sameHex(participantProof.pkG, a.memberPkG)) return;
  const semanticObservation = journaledSemanticObservation(event, {
    closeIntentDigest: a.closeIntentDigest,
    withdrawalNullifier: a.withdrawalNullifier,
    memberPkG: a.memberPkG,
    recipient: a.recipient,
    tokenIndex: String(a.tokenIndex),
    amount: String(a.amount),
  });
  if (!plan) {
    if (ctx.claimSettlement && ctx.claimSettlement.durableOutbox === true) {
      rememberDeferredExitSemantic(
        ctx.store,
        'claims',
        String(a.withdrawalNullifier || ''),
        semanticObservation,
      );
    }
    return;
  }
  const item = plan.claims.find((c) => (
    c.tokenIndex === tokenIndex
    && sameHex(c.nullifier, a.withdrawalNullifier)
  ));
  if (!item) return;
  if (String(a.amount) !== String(item.amount)) return;
  if (item.memberPkG && !sameHex(item.memberPkG, a.memberPkG)) return;
  if (ctx.claimSettlement && ctx.claimSettlement.durableOutbox === true) {
    rememberDeferredExitSemantic(
      ctx.store,
      'claims',
      String(a.withdrawalNullifier || ''),
      semanticObservation,
    );
  }
  const claimAction = item.claimOutboxActionId || claimActionId(ctx.ch, ctx.slot, item.tokenSlot);
  const hasLocalSubmission = Boolean(item.claimOutboxPrepared || item.claimTxHash);
  const submittedByUs = hasLocalSubmission && (
    sameHex(item.claimTxHash, event.txHash)
    || await actionOwnsTransaction(ctx.claimSettlement, claimAction, event.txHash)
  );
  replacePlanItem(ctx.store, item.tokenSlot, {
    acceptedObserved: true,
    claimSemanticObservation: semanticObservation,
  });
  if (submittedByUs && ctx.claimSettlement
      && typeof ctx.claimSettlement.markClaimFinalized === 'function') {
    const terminal = await ctx.claimSettlement.markClaimFinalized(
      ctx.ch.manager,
      item.tokenSlot,
      {
        actionId: claimAction,
        closeIntentDigest: plan.closeIntentDigest,
        nullifier: item.nullifier,
        tokenIndex: item.tokenIndex,
        amount: item.amount,
        memberPkG: item.memberPkG,
      },
      event,
    );
    replacePlanItem(ctx.store, item.tokenSlot, {
      claimOutboxPrepared: false,
      claimNonceSettled: true,
      acceptedFinalized: true,
      claimTerminal: terminal && terminal.terminal || null,
      claimSemanticCheckpoint: semanticObservation,
    });
    ctx.store.completeAction(claimAction, 'finalized');
    return;
  }
  if (ctx.claimSettlement && ctx.claimSettlement.durableOutbox === true) return;
  replacePlanItem(ctx.store, item.tokenSlot, { acceptedFinalized: true });
  ctx.store.completeAction(claimAction, 'finalized');
  // Never issue the dependent funds/payout transaction from inside a log callback. A later
  // post-poll recovery tick first settles any local signer nonce against the complete block.
}

async function onFundsPulled(event, ctx) {
  if (!isConfiguredManagerEvent(event, ctx, ['ChannelFundsPulled'])) return;
  let tokenIndex;
  let amount;
  let totalReceived;
  try {
    tokenIndex = canonicalU64(event.args && event.args.tokenIndex, 'funds token index');
    if (BigInt(tokenIndex) > 0xffffffffn) return;
    amount = BigInt(event.args && event.args.amount);
    totalReceived = BigInt(event.args && event.args.totalReceived);
  } catch (_) { return; }
  if (amount <= 0n || totalReceived < amount) return;
  const semanticObservation = journaledSemanticObservation(event, {
    tokenIndex,
    amount: amount.toString(),
    totalReceived: totalReceived.toString(),
  });
  const plan = ctx.store.get('exitClaimPlan');
  if (!plan || !Array.isArray(plan.claims)) {
    if (ctx.claimSettlement && ctx.claimSettlement.durableOutbox === true) {
      rememberDeferredExitSemantic(ctx.store, 'funds', tokenIndex, semanticObservation);
    }
    return;
  }
  const matching = plan.claims.filter((item) => String(item.tokenIndex) === tokenIndex);
  if (matching.length === 0 || !matching.some((item) => totalReceived >= BigInt(item.amount))) return;
  if (ctx.claimSettlement && ctx.claimSettlement.durableOutbox === true) {
    rememberDeferredExitSemantic(ctx.store, 'funds', tokenIndex, semanticObservation);
  }
  for (const observed of matching) {
    // One ChannelFundsPulled transition settles the Manager's entire proof-bound token cap. Bind it
    // to every same-token claim, not merely the first array entry: a later claim may own the local
    // outbox raw while an earlier claim is already complete.
    if (totalReceived < BigInt(observed.amount)) continue;
    const item = ctx.store.get('exitClaimPlan').claims.find(
      (claim) => claim.tokenSlot === observed.tokenSlot,
    );
    const actionId = item.fundsOutboxActionId
      || `${creditActionId(ctx.ch, item.nullifier)}:channel-funds`;
    const hasLocalSubmission = Boolean(item.fundsOutboxPrepared || item.fundsPullTxHash);
    // eslint-disable-next-line no-await-in-loop
    const submittedByUs = hasLocalSubmission && (
      sameHex(item.fundsPullTxHash, event.txHash)
      // eslint-disable-next-line no-await-in-loop
      || await actionOwnsTransaction(ctx.claimSettlement, actionId, event.txHash)
    );
    replacePlanItem(ctx.store, item.tokenSlot, { fundsSemanticObservation: semanticObservation });
    if (submittedByUs && ctx.claimSettlement
        && typeof ctx.claimSettlement.markFundsFinalized === 'function') {
      // eslint-disable-next-line no-await-in-loop
      const terminal = await ctx.claimSettlement.markFundsFinalized(
        ctx.ch.manager,
        item.nullifier,
        item.tokenIndex,
        item.amount,
        event,
        actionId,
      );
      replacePlanItem(ctx.store, item.tokenSlot, {
        fundsOutboxPrepared: false,
        fundsPullTxHash: null,
        fundsNonceSettled: true,
        fundsPulledFinalized: true,
        fundsTerminal: terminal && terminal.terminal || null,
        fundsSemanticCheckpoint: semanticObservation,
      });
      ctx.store.completeAction(actionId, 'finalized');
      continue;
    }
    if (ctx.claimSettlement && ctx.claimSettlement.durableOutbox === true) continue;
    replacePlanItem(ctx.store, item.tokenSlot, { fundsPulledFinalized: true });
  }
  // As above, dependent payout submission is post-poll only.
}

// Local burn high-water mark (Round 2 §2): every partial-withdrawal burn records the exact head
// it was authorized against. The Manager refuses any close older than an authorized burn
// (`CloseOlderThanAuthorizedBurn`), so a close head below that mark can never settle; refusing it
// here keeps the failure visible instead of stranding the channel behind a frozen stale request.
function headPosition(head) {
  if (!head || head.epoch == null || head.stateVersion == null) return null;
  const epoch = Number(head.epoch);
  const version = Number(head.stateVersion);
  if (!Number.isFinite(epoch) || !Number.isFinite(version)) return null;
  return { epoch, version };
}

function burnAboveHead(store, head) {
  if (typeof store.listTickets !== 'function') return null;
  const position = headPosition(head);
  const burns = store.listTickets((ticket) => ticket && ticket.type === 'partial_withdrawal'
    && ticket.params && ticket.params.burnHead);
  for (const ticket of burns) {
    const burn = headPosition(ticket.params.burnHead);
    if (!burn) continue;
    if (!position
      || burn.epoch > position.epoch
      || (burn.epoch === position.epoch && burn.version > position.version)) {
      return { ticketId: ticket.id, burnHead: ticket.params.burnHead };
    }
  }
  return null;
}

async function refuseCloseBelowAuthorizedBurn(ctx, head, stage) {
  const { store, ch, alert } = ctx;
  const above = burnAboveHead(store, head);
  if (!above) return false;
  if (!store.get('closeBelowAuthorizedBurnAlerted')) {
    store.set('closeBelowAuthorizedBurnAlerted', true);
    await alert.raise(
      'fault',
      ch.id,
      'CLOSE_BELOW_AUTHORIZED_BURN',
      `${stage}: the close head is older than a locally authorized partial-withdrawal burn`,
      {
        headDigest: head && head.digest ? String(head.digest).toLowerCase() : null,
        headEpoch: head && head.epoch != null ? String(head.epoch) : null,
        headStateVersion: head && head.stateVersion != null ? String(head.stateVersion) : null,
        burnTicketId: above.ticketId,
        burnHead: above.burnHead,
        note: 'the Manager would refuse this close with CloseOlderThanAuthorizedBurn; import the post-burn head before closing',
      },
    );
  }
  return true;
}

async function attemptPublicClosePublication(ctx) {
  const { store, ch, publicClosePublisher, snapshotVault, backingVault, log, alert } = ctx;
  const acceptedHead = store.get('acceptedHead');
  if (!publicClosePublisher || typeof publicClosePublisher.advance !== 'function') {
    if (!store.get('publicClosePublisherUnavailableAlerted')) {
      store.set('publicClosePublisherUnavailableAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'PUBLIC_CLOSE_PUBLISHER_UNAVAILABLE',
        'durable public close-proof publication is not configured',
        { note: 'the channel remains frozen; no unguarded finalize transaction is emitted' },
      );
    }
    return null;
  }
  if (!acceptedHead || typeof acceptedHead.digest !== 'string' || !snapshotVault || !backingVault) {
    if (!store.get('publicClosePublisherUnavailableAlerted')) {
      store.set('publicClosePublisherUnavailableAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'PUBLIC_CLOSE_RECOVERY_MATERIAL_UNAVAILABLE',
        'authenticated accepted head or immutable close recovery vault is unavailable',
        { note: 'proof publication remains fail-closed and will retry after recovery material is restored' },
      );
    }
    return null;
  }
  // SIGNER-INDEPENDENT EXIT (Round 2 §1a): a close in flight was requested for ONE exact signed
  // head, and its native WAL/journal and signer-lane reservation are keyed by that head's digest.
  // acceptedHead can still advance while exiting (a chain-sourced deposit import is routed before
  // the exit-mode intent drop), so retargeting the publisher to the newer head would open a
  // second journal that can never claim the lane while the first is unfinished: the first close
  // would never be advanced again. Pin the publisher to the head the in-flight close started
  // with; the pin is cleared only when the close era is cancelled.
  if (await refuseCloseBelowAuthorizedBurn(ctx, acceptedHead, 'public close publication')) return null;
  const pinned = store.get('publicClosePublication');
  let publisherHead = acceptedHead;
  if (pinned && typeof pinned.acceptedHeadDigest === 'string'
    && pinned.acceptedHeadDigest !== acceptedHead.digest.toLowerCase()) {
    publisherHead = { ...acceptedHead, digest: pinned.acceptedHeadDigest };
    if (!store.get('publicClosePublisherHeadPinnedLogged')) {
      store.set('publicClosePublisherHeadPinnedLogged', true);
      log.warn({
        event: 'CLOSE_PROOF_PUBLISHER_HEAD_PINNED',
        channel: ch.id,
        pinnedHeadDigest: pinned.acceptedHeadDigest,
        acceptedHeadDigest: acceptedHead.digest.toLowerCase(),
        note: 'the in-flight close keeps its original exact head; the newer accepted head is not retargeted',
      });
    }
  }
  try {
    // Only the WASM-authenticated head and the two immutable vault objects enter the handoff.
    // RPC, deployment, manager, signer selector, chain and lock root were fixed at daemon start.
    const progress = await publicClosePublisher.advance({
      acceptedHead: publisherHead,
      snapshotVault,
      backingVault,
    });
    const publication = {
      schemaVersion: 1,
      acceptedHeadDigest: publisherHead.digest.toLowerCase(),
      progress,
    };
    setIfChanged(store, 'publicClosePublication', publication);
    setIfChanged(store, 'publicClosePublisherUnavailableAlerted', false);
    setIfChanged(store, 'publicClosePublisherFailureAlerted', false);
    log.info({
      event: 'CLOSE_PROOF_PUBLISHER_PROGRESS',
      channel: ch.id,
      acceptedHeadDigest: publication.acceptedHeadDigest,
      phase: progress.phase,
      transactionHash: progress.transactionHash
        || (progress.publication && progress.publication.finalizeTransactionHash)
        || null,
    });
    return progress;
  } catch (e) {
    if (!store.get('publicClosePublisherFailureAlerted')) {
      store.set('publicClosePublisherFailureAlerted', true);
      await alert.raise(
        'fault',
        ch.id,
        'PUBLIC_CLOSE_PUBLISH_FAILED',
        String(e && e.message || e),
        { note: 'native WAL remains authoritative; the next recovery tick retries idempotently' },
      );
    }
    return null;
  }
}

async function onRecoveryTick(_event, ctx) {
  if (ctx.store.get('mode') !== 'exiting') return;
  let reconciled;
  try {
    reconciled = await reconcileCloseLifecycle(ctx);
    if (ctx.store.get('closeFinalizeReconcileAlerted')) {
      ctx.store.set('closeFinalizeReconcileAlerted', false);
    }
  } catch (e) {
    if (!ctx.store.get('closeFinalizeReconcileAlerted')) {
      ctx.store.set('closeFinalizeReconcileAlerted', true);
      await ctx.alert.raise(
        'fault',
        ctx.ch.id,
        'CLOSE_FINALIZE_RECONCILE_FAILED',
        String(e && e.message || e),
        { note: 'no close transaction is emitted until durable manager state is readable' },
      );
    }
    return;
  }
  const phase = reconciled.lifecycle.phase;
  const participantSettlement = await reconcileParticipantCloseSubmission(ctx, reconciled);
  const finalizeSettlement = participantSettlement.unresolved
    ? { unresolved: false, settled: false }
    : await reconcileCloseFinalizeSubmissions(ctx, reconciled);
  const claimSettlement = participantSettlement.unresolved || finalizeSettlement.unresolved
    ? { unresolved: false, settled: false }
    : await reconcileClaimOutboxActions(ctx, reconciled);
  if ((participantSettlement.result && ['terminal', 'absent'].includes(participantSettlement.result.phase))
      || finalizeSettlement.settled
      || claimSettlement.settled) {
    // Settlement can have become durable after the manager snapshot used above. Re-read the next
    // processed checkpoint before selecting a new semantic action.
    return;
  }
  if (claimSettlement.unresolved) return;
  if (participantSettlement.unresolved || finalizeSettlement.unresolved) {
    // A semantic transition never consumes this account's signer nonce. Until the exact raw is
    // durably successful or canonically reverted, every later outbox-backed action stays fenced.
    return;
  }
  if (phase === CLOSE_PHASES.FINALIZED || ctx.store.get('channelFinalized')) {
    await attemptRecovery(ctx);
  } else if (phase === CLOSE_PHASES.SUBMITTED || phase === CLOSE_PHASES.FINALIZE_BROADCAST) {
    await attemptPublicClosePublication(ctx);
  } else if (phase === CLOSE_PHASES.REQUESTED) {
    await attemptPublicClosePublication(ctx);
  } else if (phase === CLOSE_PHASES.LEGACY_FROZEN) {
    if (!ctx.store.get('legacyClosePhaseAlerted')) {
      ctx.store.set('legacyClosePhaseAlerted', true);
      await ctx.alert.raise(
        'fault',
        ctx.ch.id,
        'LEGACY_CLOSE_PHASE_UNRECONCILED',
        'legacy close journal is ambiguous and no durable manager-state reader is configured',
        {},
      );
    }
  } else {
    await attemptCloseRequest(ctx);
  }
}

// Only this channel manager's finalized WithdrawalClaimed event can complete an exit. Rollup
// WithdrawalCredited / NativeWithdrawn / ERC-20 events have no channel discriminator and may be
// unrelated refunds or withdrawals to the same recipient; accepting them here would permit false
// completion. The exact locally-broadcast payout transaction, accepted claim, withdrawal
// nullifier, token and amount are all bound before EXIT_DONE.
async function onCreditConfirmed(event, ctx) {
  const { ch, store } = ctx;
  if (store.get('mode') !== 'exiting' && !store.get('awaitingCredit')) return;
  if (!isConfiguredManagerEvent(event, ctx, ['WithdrawalClaimed'])) return;
  const a = event.args || {};
  const credited = (a.recipient || '').toLowerCase();
  if (!ctx.recipient || !credited || credited !== ctx.recipient.toLowerCase()) {
    ctx.log.info({ event: 'CREDIT_IGNORED', channel: ch.id, reason: 'recipient absent or not ours', credited, txHash: event.txHash });
    return;
  }
  if (!/^0x[0-9a-f]{64}$/i.test(String(a.withdrawalNullifier || ''))) return;
  const tokenIndex = String(a.tokenIndex);
  const semanticObservation = journaledSemanticObservation(event, {
    withdrawalNullifier: a.withdrawalNullifier,
    recipient: a.recipient,
    tokenIndex,
    amount: String(a.amount),
  });
  const plan = store.get('exitClaimPlan');
  if (!plan || !Array.isArray(plan.claims)) {
    if (ctx.claimSettlement && ctx.claimSettlement.durableOutbox === true) {
      const deferred = store.get('deferredExitSemantics');
      const matchingClaim = deferred && deferred.claims
        && deferred.claims[String(a.withdrawalNullifier).toLowerCase()];
      if (!matchingClaim) return;
      rememberDeferredExitSemantic(
        store,
        'credits',
        String(a.withdrawalNullifier || ''),
        semanticObservation,
      );
    }
    return;
  }
  const item = plan.claims.find((c) => sameHex(c.nullifier, a.withdrawalNullifier));
  const creditAction = item
    ? (item.creditOutboxActionId || creditActionId(ch, item.nullifier))
    : null;
  if (!item
      || (item.acceptedFinalized !== true && item.acceptedObserved !== true)
      || String(item.tokenIndex) !== tokenIndex
      || String(a.amount) !== String(item.payoutAmount || item.amount)) return;
  if (ctx.claimSettlement && ctx.claimSettlement.durableOutbox === true) {
    rememberDeferredExitSemantic(
      store,
      'credits',
      String(a.withdrawalNullifier || ''),
      semanticObservation,
    );
  }
  const hasLocalSubmission = Boolean(item.creditOutboxPrepared || item.pullTxHash);
  const submittedByUs = hasLocalSubmission && (
    sameHex(item.pullTxHash, event.txHash)
    || await actionOwnsTransaction(ctx.claimSettlement, creditAction, event.txHash)
  );
  replacePlanItem(store, item.tokenSlot, { creditSemanticObservation: semanticObservation });
  if (submittedByUs && ctx.claimSettlement
      && typeof ctx.claimSettlement.markCreditFinalized === 'function') {
    const terminal = await ctx.claimSettlement.markCreditFinalized(
      ch.manager,
      item.nullifier,
      item.tokenIndex,
      item.payoutAmount || item.amount,
      event,
      creditAction,
    );
    replacePlanItem(store, item.tokenSlot, {
      creditOutboxPrepared: false,
      creditNonceSettled: true,
      paidFinalized: true,
      creditTerminal: terminal && terminal.terminal || null,
      creditSemanticCheckpoint: semanticObservation,
    });
    store.completeAction(creditAction, 'finalized');
    completeExitIfPaid(ctx, event);
    return;
  }
  if (ctx.claimSettlement && ctx.claimSettlement.durableOutbox === true) return;
  replacePlanItem(store, item.tokenSlot, { paidFinalized: true });
  store.completeAction(creditAction, 'finalized');
  completeExitIfPaid(ctx, event);
}

module.exports = {
  enterExitMode,
  onCosignInvalid,
  onWithholding,
  onCloseSeen,
  onCloseCancelled,
  onChannelFinalized,
  onClaimAccepted,
  onFundsPulled,
  onRecoveryTick,
  onCreditConfirmed,
  attemptCloseRequest,
  attemptCloseFinalize,
  attemptPublicClosePublication,
  reconcileParticipantCloseSubmission,
  reconcileCloseFinalizeSubmissions,
  reconcileClaimOutboxActions,
  reconcileCloseLifecycle,
  attemptRecovery,
  attemptDirectRecovery,
  attemptDirectCreditPull,
  positiveBalances,
  canonicalU64,
  isConfiguredManagerEvent,
  currentCloseLifecycle,
  CLOSE_PHASES,
};
