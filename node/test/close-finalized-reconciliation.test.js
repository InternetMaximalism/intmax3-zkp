'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  readOnChainPending,
  onCloseIntentObserved,
  onCloseCancelled,
  onCloseFinalized,
} = require('../cosigner/branches/close');

const EVENT = {
  blockNumber: 91,
  args: {
    closeIntentDigest: `0x${'11'.repeat(32)}`,
    finalEpoch: '7',
    finalStateVersion: '12',
  },
};

test('close reconciliation uses the block-pinned getter, not an earlier log payload', async () => {
  const replacement = {
    active: true,
    closeIntentDigest: `0x${'22'.repeat(32)}`,
    epoch: 8,
    stateVersion: 13,
  };
  const calls = [];
  const got = await readOnChainPending({
    ch: { manager: '0xmanager' },
    getPendingClose: async (manager, blockTag) => {
      calls.push([manager, blockTag]);
      return replacement;
    },
  }, EVENT);

  assert.deepEqual(calls, [['0xmanager', 91]]);
  assert.equal(got, replacement);
  assert.notEqual(got.closeIntentDigest, EVENT.args.closeIntentDigest);
});

test('close reconciliation retries the block when the authoritative getter fails', async () => {
  await assert.rejects(
    readOnChainPending({
      ch: { manager: '0xmanager' },
      getPendingClose: async () => { throw new Error('RPC read failed'); },
    }, EVENT),
    /RPC read failed/,
  );
});

test('close reconciliation refuses an event-only authority', async () => {
  await assert.rejects(
    readOnChainPending({ ch: { manager: '0xmanager' } }, EVENT),
    /authoritative getPendingClose reader is unavailable/,
  );
});

test('close reconciliation treats an inactive block-end getter state as no pending close', async () => {
  const got = await readOnChainPending({
    ch: { manager: '0xmanager' },
    getPendingClose: async () => ({ active: false }),
  }, EVENT);
  assert.equal(got, null);
});

test('finalized cancel/finalize events reconcile the local signing state machine', async () => {
  const signals = [];
  const logs = [];
  const ctx = {
    ch: { id: 7 },
    sm: { signal: (signal) => signals.push(signal) },
    log: { info: (entry) => logs.push(entry) },
  };
  await onCloseCancelled({ args: {}, txHash: '0xcancel' }, ctx);
  await onCloseFinalized({ args: {}, txHash: '0xfinal' }, ctx);

  assert.deepEqual(signals, ['cancelled', 'finalized']);
  assert.deepEqual(logs.map((entry) => entry.event), [
    'CLOSE_CANCELLED_RECONCILED',
    'CLOSE_FINALIZED_RECONCILED',
  ]);
});

function closeIntentContext({
  headVersion = 13,
  pendingVersion = 12,
  localDigest = `0x${'22'.repeat(32)}`,
  pendingDigest = localDigest,
  response = 'cancel',
} = {}) {
  const signals = [];
  const runs = [];
  const alerts = [];
  const logs = [];
  const claimed = [];
  const completed = [];
  const ctx = {
    ch: { id: 7, workDir: '/tmp/channel-7', manager: '0xmanager', verifier: '0xverifier' },
    rpc: 'http://rpc.invalid',
    policy: { staleCloseResponse: response },
    sm: { signal: (signal) => signals.push(signal) },
    cli: {
      readJson(_workDir, file) {
        if (file === 'channel_snapshot.json') {
          return { state: { epoch: 7, balanceState: { stateVersion: headVersion } } };
        }
        if (file === 'cancel_close.json') throw new Error('absent');
        if (file === 'close_intent.json') return { close_intent_digest: localDigest };
        throw new Error(`unexpected read: ${file}`);
      },
      async run(...args) { runs.push(args); },
    },
    getPendingClose: async () => ({
      active: true,
      epoch: 7,
      stateVersion: pendingVersion,
      closeIntentDigest: pendingDigest,
    }),
    store: {
      claimAction(actionId) { claimed.push(actionId); return true; },
      completeAction(actionId, result) { completed.push([actionId, result]); },
      releaseAction() { throw new Error('successful response must not release action'); },
    },
    alert: { async raise(...args) { alerts.push(args); } },
    log: { info(entry) { logs.push(entry); } },
  };
  return { ctx, signals, runs, alerts, logs, claimed, completed };
}

test('an old locally-authored close intent cannot suppress cancellation when our signed head is newer', async () => {
  const h = closeIntentContext();
  await onCloseIntentObserved({ blockNumber: 91, txHash: '0xreplay-1' }, h.ctx);

  assert.deepEqual(h.signals, ['close_submitted', 'cancelled']);
  assert.equal(h.runs.length, 1);
  assert.deepEqual(h.runs[0].slice(0, 3), [7, '/tmp/channel-7', ['cancel-close', '0xmanager', 'http://rpc.invalid']]);
  assert.equal(h.alerts.length, 1);
  assert.equal(h.alerts[0][2], 'STALE_CLOSE_DETECTED');
  assert.equal(h.logs.some((entry) => entry.event === 'CLOSE_LEGITIMATE'), false);
  assert.match(h.claimed[0], /:0xreplay-1$/);
  assert.deepEqual(h.completed, [[h.claimed[0], 'ok']]);
});

test('distinct transactions replaying one stale local digest each trigger a defensive response', async () => {
  const h = closeIntentContext({ response: 'challenge' });
  await onCloseIntentObserved({ blockNumber: 91, txHash: '0xreplay-1' }, h.ctx);
  await onCloseIntentObserved({ blockNumber: 92, txHash: '0xreplay-2' }, h.ctx);

  assert.equal(h.runs.length, 2);
  assert.deepEqual(h.runs.map((run) => run[2]), [
    ['close', '0xmanager', 'http://rpc.invalid'],
    ['close', '0xmanager', 'http://rpc.invalid'],
  ]);
  assert.deepEqual(h.runs.map((run) => run[3]), [
    { CLOSE_SV: '0xverifier', CLOSE_SKIP_REQUEST: '1' },
    { CLOSE_SV: '0xverifier', CLOSE_SKIP_REQUEST: '1' },
  ]);
  assert.notEqual(h.claimed[0], h.claimed[1]);
  assert.deepEqual(h.alerts.map((args) => args[2]), [
    'STALE_CLOSE_DETECTED',
    'STALE_CLOSE_DETECTED',
  ]);
});

test('a close at the current local version remains legitimate when its digest is ours', async () => {
  const h = closeIntentContext({ headVersion: 12, pendingVersion: 12 });
  await onCloseIntentObserved({ blockNumber: 91, txHash: '0xcurrent' }, h.ctx);

  assert.deepEqual(h.signals, ['close_submitted']);
  assert.equal(h.runs.length, 0);
  assert.equal(h.alerts.length, 0);
  assert.equal(h.claimed.length, 0);
  assert.equal(h.logs.at(-1).event, 'CLOSE_LEGITIMATE');
  assert.equal(h.logs.at(-1).isOurs, true);
});
