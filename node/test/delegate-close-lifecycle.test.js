'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const exit = require('../delegate/branches/exit');

const MANAGER = '0x4444444444444444444444444444444444444444';
const DIGEST = `0x${'11'.repeat(32)}`;

function fakeStore(initial = {}) {
  const state = { actions: {}, mode: 'normal', ...initial };
  return {
    state,
    get(key) { return state[key]; },
    set(key, value) { state[key] = value; return value; },
    claimAction(id, options = {}) {
      if (state.actions[id]) {
        return options.retryPending === true && state.actions[id].result === 'pending';
      }
      state.actions[id] = { result: 'pending' };
      return true;
    },
    hasAction(id) { return Boolean(state.actions[id]); },
    completeAction(id, result) { state.actions[id] = { result }; },
    releaseAction(id) {
      if (state.actions[id] && state.actions[id].result === 'pending') delete state.actions[id];
    },
    pushAlert(record) { (state.alerts ||= []).push(record); },
    findTicket() { return null; },
    upsertTicket() {},
  };
}

function context(store, overrides = {}) {
  const alerts = [];
  const logs = [];
  return {
    ch: { id: 7, manager: MANAGER },
    slot: 3,
    recipient: null,
    store,
    sm: { signal() {} },
    log: {
      debug(value) { logs.push(value); },
      info(value) { logs.push(value); },
      warn(value) { logs.push(value); },
      error(value) { logs.push(value); },
    },
    alert: {
      async raise(...args) { alerts.push(args); return { code: args[2] }; },
    },
    alerts,
    logs,
    ...overrides,
  };
}

function managerEvent(kind, args = {}, extra = {}) {
  return {
    source: 'chain',
    kind,
    contract: 'manager',
    address: MANAGER,
    blockNumber: 50,
    blockHash: `0x${'50'.repeat(32)}`,
    txHash: `0x${'aa'.repeat(32)}`,
    logIndex: 1,
    args,
    ...extra,
  };
}

function durableSubmitted(timestampRef) {
  return async () => ({
    status: 1,
    closeRequestGenerationExact: '7',
    pending: {
      active: true,
      closeIntentDigest: DIGEST,
      epochExact: '4',
      stateVersionExact: '9',
      challengeDeadlineExact: '100',
      closeFreezeNonceExact: '2',
    },
    durable: {
      number: 50,
      hash: `0x${'50'.repeat(32)}`,
      parentHash: `0x${'49'.repeat(32)}`,
      timestamp: timestampRef.value,
    },
  });
}

test('finalized CloseRequested is a frozen/requested phase, never awaitingClaim', async () => {
  const store = fakeStore();
  let requestCalls = 0;
  let finalizeCalls = 0;
  const ctx = context(store, {
    participantCloser: {
      async requestClose() { requestCalls += 1; },
      async finalizeCloseGuarded() { finalizeCalls += 1; },
    },
  });

  await exit.onCloseSeen(managerEvent('CloseRequested', {
    requester: '0x1111111111111111111111111111111111111111',
    closeRequestedAt: '90',
    closeFreezeNonce: '2',
  }), ctx);

  assert.equal(store.get('mode'), 'exiting');
  assert.equal(store.get('closeLifecycle').phase, exit.CLOSE_PHASES.REQUESTED);
  assert.equal(store.get('awaitingClaim'), false);
  assert.equal(store.get('channelFinalized'), false);
  assert.equal(requestCalls, 0, 'an already-frozen channel must not consume another signer nonce');
  assert.equal(finalizeCalls, 0, 'a request has no proved close to finalize');
});

test('requested close hands authenticated head and immutable vaults to durable publisher', async () => {
  const snapshotVault = { name: 'snapshot-vault' };
  const backingVault = { name: 'backing-vault' };
  const acceptedHead = { digest: `0x${'77'.repeat(32)}`, epoch: 4, stateVersion: 9 };
  const store = fakeStore({
    mode: 'exiting',
    acceptedHead,
    closeLifecycle: { schemaVersion: 1, phase: exit.CLOSE_PHASES.REQUESTED },
  });
  const calls = [];
  const ctx = context(store, {
    snapshotVault,
    backingVault,
    publicClosePublisher: {
      async advance(input) {
        calls.push(input);
        return { phase: 'submitBroadcast', transactionHash: `0x${'78'.repeat(32)}` };
      },
    },
  });

  await exit.onRecoveryTick({ source: 'timer', kind: 'recovery' }, ctx);
  assert.deepEqual(calls, [{ acceptedHead, snapshotVault, backingVault }]);
  assert.equal(store.get('publicClosePublication').acceptedHeadDigest, acceptedHead.digest);
  assert.equal(store.get('publicClosePublication').progress.phase, 'submitBroadcast');
  assert.ok(ctx.logs.some((entry) => entry.event === 'CLOSE_PROOF_PUBLISHER_PROGRESS'));
  assert.ok(!ctx.logs.some((entry) => entry.event === 'CLOSE_PROOF_DEFERRED'));
});

test('an in-flight close stays pinned to the head it was requested for', async () => {
  // Round 2 §1a: a chain-sourced deposit import can advance acceptedHead while exiting. The
  // native journal and signer lane are keyed by the head the close started with, so retargeting
  // the publisher would strand the first journal forever.
  const h1 = { digest: `0x${'81'.repeat(32)}`, epoch: 4, stateVersion: 9 };
  const h2 = { digest: `0x${'82'.repeat(32)}`, epoch: 4, stateVersion: 10 };
  const store = fakeStore({
    mode: 'exiting',
    acceptedHead: h1,
    closeLifecycle: { schemaVersion: 1, phase: exit.CLOSE_PHASES.REQUESTED },
  });
  const calls = [];
  const ctx = context(store, {
    snapshotVault: {},
    backingVault: {},
    publicClosePublisher: {
      async advance(input) {
        calls.push(input.acceptedHead.digest);
        return { phase: 'awaitingChallengeDeadline' };
      },
    },
  });
  const tick = { source: 'timer', kind: 'recovery' };
  await exit.onRecoveryTick(tick, ctx);
  store.set('acceptedHead', h2);
  await exit.onRecoveryTick(tick, ctx);
  await exit.onRecoveryTick(tick, ctx);
  assert.deepEqual(calls, [h1.digest, h1.digest, h1.digest]);
  assert.equal(store.get('publicClosePublication').acceptedHeadDigest, h1.digest);
  assert.equal(
    ctx.logs.filter((entry) => entry.event === 'CLOSE_PROOF_PUBLISHER_HEAD_PINNED').length,
    1,
    'the pin is logged once, not on every tick',
  );

  // A cancelled era releases the pin; the next request targets the head current at that time.
  await exit.onCloseCancelled(managerEvent('CloseCancelled', {
    closeIntentDigest: `0x${'83'.repeat(32)}`,
    revivedChannelStateDigest: h2.digest,
    revivedStateVersion: '10',
  }), ctx);
  assert.equal(store.get('publicClosePublication'), null);
  store.set('closeLifecycle', { schemaVersion: 1, phase: exit.CLOSE_PHASES.REQUESTED });
  await exit.onRecoveryTick(tick, ctx);
  assert.equal(calls[calls.length - 1], h2.digest);
  assert.equal(store.get('publicClosePublication').acceptedHeadDigest, h2.digest);
});

test('a close head below a locally authorized burn is refused before the publisher runs', async () => {
  const head = { digest: `0x${'84'.repeat(32)}`, epoch: 4, stateVersion: 9 };
  const tickets = [
    { id: 'pw_1', type: 'partial_withdrawal', status: 'burn_done',
      params: { burnHead: { digest: `0x${'85'.repeat(32)}`, epoch: 4, stateVersion: 10 } } },
  ];
  const store = fakeStore({
    mode: 'exiting',
    acceptedHead: head,
    closeLifecycle: { schemaVersion: 1, phase: exit.CLOSE_PHASES.REQUESTED },
  });
  store.listTickets = (predicate) => tickets.filter(predicate);
  let calls = 0;
  const ctx = context(store, {
    snapshotVault: {},
    backingVault: {},
    publicClosePublisher: { async advance() { calls += 1; return { phase: 'submitBroadcast' }; } },
  });
  const tick = { source: 'timer', kind: 'recovery' };
  await exit.onRecoveryTick(tick, ctx);
  await exit.onRecoveryTick(tick, ctx);
  assert.equal(calls, 0, 'a stale head never reaches the native publisher');
  const alerts = ctx.alerts.filter((args) => args[2] === 'CLOSE_BELOW_AUTHORIZED_BURN');
  assert.equal(alerts.length, 1, 'alerted once');
  assert.equal(alerts[0][4].burnTicketId, 'pw_1');
  assert.equal(store.get('publicClosePublication'), undefined);

  // Once the post-burn head is adopted the same tick publishes it.
  store.set('acceptedHead', { digest: `0x${'85'.repeat(32)}`, epoch: 4, stateVersion: 10 });
  await exit.onRecoveryTick(tick, ctx);
  assert.equal(calls, 1);
  assert.equal(store.get('publicClosePublication').acceptedHeadDigest, `0x${'85'.repeat(32)}`);
});

test('publisher failure leaves requested phase unchanged and retries native WAL next tick', async () => {
  const store = fakeStore({
    mode: 'exiting',
    acceptedHead: { digest: `0x${'79'.repeat(32)}` },
    closeLifecycle: { schemaVersion: 1, phase: exit.CLOSE_PHASES.REQUESTED },
  });
  let calls = 0;
  const ctx = context(store, {
    snapshotVault: {},
    backingVault: {},
    publicClosePublisher: {
      async advance() { calls += 1; throw new Error('injected publisher failure'); },
    },
  });

  await exit.onRecoveryTick({ source: 'timer', kind: 'recovery' }, ctx);
  await exit.onRecoveryTick({ source: 'timer', kind: 'recovery' }, ctx);
  assert.equal(calls, 2, 'the native journal, not a JS action latch, controls replay');
  assert.equal(store.get('closeLifecycle').phase, exit.CLOSE_PHASES.REQUESTED);
  assert.equal(ctx.alerts.filter((args) => args[2] === 'PUBLIC_CLOSE_PUBLISH_FAILED').length, 1);
});

test('proved close uses native guarded publisher and never legacy unguarded finalizer', async () => {
  const store = fakeStore({
    mode: 'exiting',
    acceptedHead: { digest: `0x${'7a'.repeat(32)}` },
    closeLifecycle: {
      schemaVersion: 1,
      phase: exit.CLOSE_PHASES.SUBMITTED,
      closeIntentDigest: DIGEST,
      closeKey: `${DIGEST}:current`,
      challengeDeadline: '100',
    },
  });
  let publishCalls = 0;
  let legacyFinalizeCalls = 0;
  const ctx = context(store, {
    snapshotVault: {},
    backingVault: {},
    publicClosePublisher: {
      async advance() {
        publishCalls += 1;
        return { phase: 'awaitingChallengeDeadline', challengeDeadline: 100, durableTime: 99 };
      },
    },
    participantCloser: {
      async finalizeCloseGuarded() { legacyFinalizeCalls += 1; throw new Error('must not be called'); },
    },
  });

  await exit.onRecoveryTick({ source: 'timer', kind: 'recovery' }, ctx);
  assert.equal(publishCalls, 1);
  assert.equal(legacyFinalizeCalls, 0);
});

test('CloseCancelled clears the old era and re-requests after the finalized batch completes', async () => {
  const requestAction = 'participant-close:7:3';
  const store = fakeStore({
    mode: 'exiting',
    awaitingClaim: true,
    closeLifecycle: {
      schemaVersion: 1,
      phase: exit.CLOSE_PHASES.SUBMITTED,
      closeIntentDigest: DIGEST,
      closeKey: `${DIGEST}:old`,
      challengeDeadline: '100',
    },
    participantCloseProof: { slot: 3, participantRoot: DIGEST, siblings: [] },
    participantCloseSubmission: { txHash: `0x${'01'.repeat(32)}` },
    actions: { [requestAction]: { result: 'pending' } },
  });
  const broadcasts = [];
  const ctx = context(store, {
    readDurableCloseState: async () => ({
      status: 0,
      closeRequestGenerationExact: '7',
      pending: { active: false },
      durable: {
        number: 50,
        hash: `0x${'50'.repeat(32)}`,
        parentHash: `0x${'49'.repeat(32)}`,
        timestamp: 90,
      },
    }),
    participantCloser: {
      async requestClose(_manager, _proof, onBroadcast) {
        const txHash = `0x${'02'.repeat(32)}`;
        broadcasts.push(txHash);
        await onBroadcast(txHash);
        return { txHash };
      },
    },
  });

  await exit.onCloseCancelled(managerEvent('CloseCancelled', {
    closeIntentDigest: DIGEST,
    revivedChannelStateDigest: `0x${'22'.repeat(32)}`,
    revivedStateVersion: '10',
  }), ctx);

  assert.equal(broadcasts.length, 0, 'no tx is emitted midway through a finalized log batch');
  assert.equal(store.get('closeLifecycle').phase, exit.CLOSE_PHASES.CANCELLED);
  await exit.onRecoveryTick({ source: 'timer', kind: 'recovery' }, ctx);
  assert.deepEqual(broadcasts, [`0x${'02'.repeat(32)}`]);
  assert.equal(store.get('closeLifecycle').phase, exit.CLOSE_PHASES.REQUEST_BROADCAST);
  assert.equal(store.get('awaitingClaim'), false);
  assert.equal(store.get('participantCloseSubmission').txHash, broadcasts[0]);
  assert.equal(store.get('actions')[requestAction].result, 'pending');
});

test('durable participant request Store/outbox ids change across a canonical cancellation era', async () => {
  const checkpoint = {
    number: 49,
    hash: `0x${'49'.repeat(32)}`,
    parentHash: `0x${'48'.repeat(32)}`,
  };
  const store = fakeStore({
    mode: 'exiting',
    chainCheckpoint: checkpoint,
    participantCloseProof: { slot: 3, participantRoot: DIGEST, siblings: [] },
  });
  const calls = [];
  let hashByte = 1;
  let cancellationFloor = '0';
  const participantCloser = {
    durableOutbox: true,
    chainId: '31337',
    async readRequestEra(_manager, suppliedCheckpoint) {
      assert.deepEqual(suppliedCheckpoint, checkpoint);
      return {
        expectedCurrentCloseFreezeNonce: '1',
        expectedHighestCancelledRevivedStateVersion: cancellationFloor,
        checkpoint: { number: checkpoint.number, hash: checkpoint.hash },
      };
    },
    async requestClose(_manager, _proof, onBroadcast, options) {
      calls.push(options);
      const txHash = `0x${String(hashByte++).padStart(2, '0').repeat(32)}`;
      await onBroadcast(txHash, { actionId: options.actionId });
      return { txHash, outboxActionId: options.actionId };
    },
    async transactionStatus() { return 'missing'; },
    async reconcileRequest(_manager, _proof, actionId) {
      return {
        actionId,
        transactionHash: store.get('participantCloseSubmission').txHash,
        phase: 'terminal',
        terminal: { outcome: 'superseded-revert' },
      };
    },
  };
  const ctx = context(store, {
    participantCloser,
    readDurableCloseState: async () => ({
      status: 0,
      closeRequestGenerationExact: '7',
      pending: { active: false },
      durable: {
        number: 50,
        hash: `0x${'50'.repeat(32)}`,
        parentHash: `0x${'49'.repeat(32)}`,
        timestamp: 100,
      },
    }),
  });

  await exit.attemptCloseRequest(ctx);
  const first = calls[0].actionId;
  assert.ok(store.get('actions')[first]);
  assert.equal(store.get('participantCloseSubmission').actionId, first);

  await exit.onCloseCancelled(managerEvent('CloseCancelled', {
    closeIntentDigest: DIGEST,
    revivedChannelStateDigest: `0x${'22'.repeat(32)}`,
    revivedStateVersion: '10',
  }), ctx);
  cancellationFloor = '10';
  await exit.onRecoveryTick({ source: 'timer', kind: 'recovery' }, ctx);
  assert.equal(calls.length, 1, 'the new era waits for exact old-nonce settlement');
  await exit.onRecoveryTick({ source: 'timer', kind: 'recovery' }, ctx);
  const second = calls[1].actionId;
  assert.notEqual(second, first, 'cancel observation must create a fresh semantic request era');
  assert.equal(calls[1].era.expectedCurrentCloseFreezeNonce, '1');
  assert.equal(calls[1].era.expectedHighestCancelledRevivedStateVersion, '10');
  assert.deepEqual(calls[1].era.cancelObservation, {
    txHash: `0x${'aa'.repeat(32)}`,
    blockNumber: 50,
    blockHash: `0x${'50'.repeat(32)}`,
    logIndex: 1,
  });
  assert.ok(store.get('actions')[second]);
  assert.equal(store.get('participantCloseSubmission').actionId, second);
});

test('finalized watcher accepts an older journaled same-nonce participant replacement', async () => {
  const actionId = 'participant-close:7:3:era-a';
  const oldHash = `0x${'01'.repeat(32)}`;
  const replacementHash = `0x${'02'.repeat(32)}`;
  const store = fakeStore({
    mode: 'exiting',
    participantCloseSubmission: {
      txHash: replacementHash,
      actionId,
      outboxActionId: actionId,
    },
  });
  store.claimAction(actionId);
  const finalized = [];
  const ctx = context(store, {
    participantCloser: {
      durableOutbox: true,
      async ownsTransaction(id, txHash) {
        return id === actionId && txHash === oldHash;
      },
      async markRequestFinalized(_manager, id, observation) {
        finalized.push({ id, observation });
      },
    },
  });

  await exit.onCloseSeen(managerEvent('CloseRequested', {
    requester: '0x1111111111111111111111111111111111111111',
    closeRequestedAt: '90',
    closeFreezeNonce: '2',
  }, { txHash: oldHash }), ctx);

  assert.equal(finalized.length, 1);
  assert.equal(finalized[0].id, actionId);
  assert.equal(finalized[0].observation.transactionHash, oldHash);
  assert.equal(store.get('actions')[actionId].result, 'finalized');
});

test('guarded compatibility finalizer acts only after durable time is past the deadline', async () => {
  const store = fakeStore({ mode: 'exiting' });
  const time = { value: 100 };
  const finalizeCalls = [];
  let txStatus = 'pending';
  const txHash = `0x${'03'.repeat(32)}`;
  const ctx = context(store, {
    readDurableCloseState: durableSubmitted(time),
    participantCloser: {
      durableOutbox: true,
    async finalizeCloseGuarded(manager, digest, onBroadcast, options) {
      finalizeCalls.push({
        manager,
        digest,
        actionId: options.actionId,
        expectedCloseRequestGeneration: options.expectedCloseRequestGeneration,
      });
      const prepared = Object.values(store.get('closeFinalizeJournal'))[0];
      assert.equal(prepared.status, 'prepared');
      assert.equal(prepared.txHash, null);
      await onBroadcast(txHash);
        return { txHash };
      },
      async transactionStatus(hash) {
        assert.equal(hash, txHash);
        return txStatus;
      },
    },
  });

  await exit.onCloseSeen(managerEvent('CloseSubmitted', {
    closeIntentDigest: DIGEST,
    finalEpoch: '4',
    finalStateVersion: '9',
    closeFreezeNonce: '2',
    challengeDeadline: '100',
  }), ctx);
  await exit.attemptCloseFinalize(ctx);
  assert.equal(finalizeCalls.length, 0, 'equality remains inside the challenge window');
  assert.equal(store.get('closeLifecycle').phase, exit.CLOSE_PHASES.SUBMITTED);

  time.value = 101;
  await exit.attemptCloseFinalize(ctx);
  const expectedActionId = `close-finalize:7:${store.get('closeLifecycle').closeKey}:generation:7`;
  assert.deepEqual(finalizeCalls, [{
    manager: MANAGER,
    digest: DIGEST,
    actionId: expectedActionId,
    expectedCloseRequestGeneration: '7',
  }]);
  assert.equal(store.get('closeLifecycle').phase, exit.CLOSE_PHASES.FINALIZE_BROADCAST);
  const journal = store.get('closeFinalizeJournal');
  const entry = Object.values(journal)[0];
  assert.equal(entry.txHash, txHash);

  await exit.attemptCloseFinalize(ctx);
  assert.equal(finalizeCalls.length, 1, 'a pending journaled tx is never blindly duplicated');

  txStatus = 'missing';
  await exit.attemptCloseFinalize(ctx);
  assert.equal(finalizeCalls.length, 1, 'a durable dropped tx is resumed only by exact-raw reconciliation');
});

test('guarded finalize survives raw-WAL persistence before the Store broadcast callback', async () => {
  const closeKey = `${DIGEST}:callback-loss`;
  const localHash = `0x${'0f'.repeat(32)}`;
  const store = fakeStore({
    mode: 'exiting',
    closeLifecycle: {
      schemaVersion: 1,
      phase: exit.CLOSE_PHASES.SUBMITTED,
      closeIntentDigest: DIGEST,
      closeKey,
      challengeDeadline: '100',
    },
  });
  let reconcileCalls = 0;
  const participantCloser = {
    durableOutbox: true,
    async finalizeCloseGuarded(_manager, digest, _onBroadcast, options) {
      const prepared = store.get('closeFinalizeJournal')[closeKey];
      assert.equal(prepared.status, 'prepared');
      assert.equal(prepared.closeKey, closeKey);
      assert.equal(prepared.closeIntentDigest, digest);
      assert.equal(prepared.closeRequestGeneration, '7');
      assert.equal(prepared.actionId, options.actionId);
      assert.equal(options.expectedCloseRequestGeneration, '7');
      // The private outbox raw WAL is assumed fsynced, while its normal Store callback is lost.
      throw new Error('simulated crash before Store broadcast callback');
    },
    async reconcileFinalize(_manager, actionId, digest, generation) {
      reconcileCalls += 1;
      assert.equal(actionId, `close-finalize:7:${closeKey}:generation:7`);
      assert.equal(digest, DIGEST);
      assert.equal(generation, '7');
      return { phase: 'broadcast', transactionHash: localHash };
    },
  };
  const ctx = context(store, {
    participantCloser,
    readDurableCloseState: async () => ({
      status: 1,
      closeRequestGenerationExact: '7',
      pending: {
        active: true,
        closeIntentDigest: DIGEST,
        epochExact: '4',
        stateVersionExact: '9',
        challengeDeadlineExact: '100',
        closeFreezeNonceExact: '2',
      },
      durable: {
        number: 51,
        hash: `0x${'51'.repeat(32)}`,
        parentHash: `0x${'50'.repeat(32)}`,
        timestamp: 101,
      },
    }),
  });

  await exit.attemptCloseFinalize(ctx);
  let entry = store.get('closeFinalizeJournal')[closeKey];
  assert.equal(entry.status, 'broadcast_unknown');
  assert.equal(entry.txHash, null);
  assert.equal(entry.closeKey, closeKey, 'prepared locator survives callback loss');
  assert.equal(entry.outboxActionId, `close-finalize:7:${closeKey}:generation:7`);

  const reconciled = await exit.reconcileCloseLifecycle(ctx);
  const result = await exit.reconcileCloseFinalizeSubmissions(ctx, reconciled);
  assert.equal(result.unresolved, true);
  assert.equal(reconcileCalls, 1);
  entry = store.get('closeFinalizeJournal')[closeKey];
  assert.equal(entry.txHash, localHash, 'restart rediscovers the exact outbox raw by action id');
  assert.equal(entry.status, 'broadcast');
});

test('legacy awaitingClaim journal is upgraded from finalized manager state without guessing', async () => {
  const store = fakeStore({
    mode: 'exiting',
    awaitingClaim: true,
    participantCloseProof: { slot: 3, participantRoot: DIGEST, siblings: [] },
  });
  let chainState = {
    status: 1,
    closeRequestGenerationExact: '7',
    pending: { active: false, closeFreezeNonceExact: '2' },
    durable: {
      number: 60,
      hash: `0x${'60'.repeat(32)}`,
      parentHash: `0x${'59'.repeat(32)}`,
      timestamp: 90,
    },
  };
  let requests = 0;
  const ctx = context(store, {
    readDurableCloseState: async () => chainState,
    participantCloser: {
      async requestClose(_manager, _proof, onBroadcast) {
        requests += 1;
        const txHash = `0x${'04'.repeat(32)}`;
        await onBroadcast(txHash);
        return { txHash };
      },
    },
  });

  await exit.onRecoveryTick({ source: 'timer', kind: 'recovery' }, ctx);
  assert.equal(store.get('closeLifecycle').phase, exit.CLOSE_PHASES.REQUESTED);
  assert.equal(store.get('awaitingClaim'), false);
  assert.equal(requests, 0);

  chainState = {
    status: 0,
    closeRequestGenerationExact: '7',
    pending: { active: false },
    durable: {
      number: 61,
      hash: `0x${'61'.repeat(32)}`,
      parentHash: `0x${'60'.repeat(32)}`,
      timestamp: 91,
    },
  };
  await exit.onRecoveryTick({ source: 'timer', kind: 'recovery' }, ctx);
  assert.equal(requests, 1, 'an authenticated Active state after cancellation re-opens request liveness');
  assert.equal(store.get('closeLifecycle').phase, exit.CLOSE_PHASES.REQUEST_BROADCAST);
});

test('foreign-manager cancellation cannot clear or restart this delegate lifecycle', async () => {
  const store = fakeStore({
    mode: 'exiting',
    awaitingClaim: true,
    closeLifecycle: { schemaVersion: 1, phase: exit.CLOSE_PHASES.SUBMITTED },
  });
  let requests = 0;
  const ctx = context(store, {
    participantCloser: { async requestClose() { requests += 1; } },
  });
  await exit.onCloseCancelled(managerEvent('CloseCancelled', { closeIntentDigest: DIGEST }, {
    address: '0x5555555555555555555555555555555555555555',
  }), ctx);
  assert.equal(store.get('closeLifecycle').phase, exit.CLOSE_PHASES.SUBMITTED);
  assert.equal(store.get('awaitingClaim'), true);
  assert.equal(requests, 0);
});

test('crash gap without a durable tx hash fails closed instead of blindly reusing a nonce', async () => {
  const requestAction = 'participant-close:7:3';
  const store = fakeStore({
    mode: 'exiting',
    participantCloseProof: { slot: 3, participantRoot: DIGEST, siblings: [] },
    actions: { [requestAction]: { result: 'pending' } },
  });
  let requests = 0;
  const ctx = context(store, {
    participantCloser: {
      async requestClose() { requests += 1; return { txHash: `0x${'05'.repeat(32)}` }; },
    },
  });

  await exit.attemptCloseRequest(ctx);
  assert.equal(requests, 0);
  assert.equal(store.get('actions')[requestAction].result, 'pending');
  assert.ok(ctx.alerts.some((args) => args[2] === 'PARTICIPANT_CLOSE_JOURNAL_GAP'));
});
