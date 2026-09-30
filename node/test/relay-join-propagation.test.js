'use strict';
// A delegate join must reach the live balance, the producer's public head and the exit-kit receipt
// whenever the live balance already holds a bound head, including an empty genesis bound before
// any transition (every public-chain channel): gating on applied transitions left those joins
// unpropagated and the next deposit import failed "proposed record differs from the pinned record".
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-relay.js'), 'utf8');
// followJoinedHead and the two record helpers it calls, which follow it in the source.
const start = source.indexOf('async function followJoinedHead(');
const helpersEnd = source.indexOf('async function adoptJoinedRecord(');
const fn = source.slice(start, source.indexOf('\n}\n', helpersEnd) + 3);

function run(status, { receipt = { head: 'x' }, registeredDelegates = 2 } = {}) {
  const calls = [];
  const ctx = {
    producer: {
      liveStatus: async () => status,
      liveBindSnapshot: async () => { calls.push('bind'); },
      status: async () => ({ registeredRecords: [{ channelId: 8, memberCount: 3, delegateCount: registeredDelegates }] }),
      adoptDelegateJoin: async () => { calls.push('adopt'); },
    },
    flushPublishedHead: async () => { calls.push('flush'); },
    installHeadExitKit: async () => { calls.push('install'); },
    fs: { readFileSync: () => JSON.stringify({ signer_exit_kit_receipt: receipt }) },
    wc: (_ch, name) => name,
    JSON, String,
  };
  vm.createContext(ctx);
  vm.runInContext(fn, ctx);
  return ctx.followJoinedHead(8, { record: { delegateCount: 2 }, state: { digest: '0xJOIN' } }).then(result => ({ result, calls }));
}

test('an empty genesis bound before any transition follows the join', async () => {
  const { result, calls } = await run({ signedHeadDigest: '0xgenesis', awaitingChannelBinding: false, appliedTransitionCount: 0 }, { registeredDelegates: 1 });
  assert.equal(result, true);
  assert.deepEqual(calls, ['bind', 'flush', 'adopt', 'install']);
});

test('the producer adopts the joined record only when its registered record is behind', async () => {
  const { calls } = await run({ signedHeadDigest: '0xgenesis', awaitingChannelBinding: false, appliedTransitionCount: 0 }, { registeredDelegates: 2 });
  assert.deepEqual(calls, ['bind', 'flush', 'install']);
});

test('a bound head whose registered record is behind still catches the record up', async () => {
  const { calls } = await run({ signedHeadDigest: '0xjoin', awaitingChannelBinding: false, appliedTransitionCount: 0 }, { registeredDelegates: 1 });
  assert.deepEqual(calls, ['flush', 'adopt', 'install']);
});

test('an adopted funded channel follows the join', async () => {
  const { calls } = await run({ signedHeadDigest: '0xhead', awaitingChannelBinding: false, appliedTransitionCount: 3 });
  assert.deepEqual(calls, ['bind', 'flush', 'install']);
});

test('a funded genesis awaiting adoption, or no bound head, is left to the first import', async () => {
  for (const status of [
    { signedHeadDigest: '0xgenesis', awaitingChannelBinding: true, appliedTransitionCount: 1 },
    { signedHeadDigest: null, awaitingChannelBinding: false, appliedTransitionCount: 0 },
  ]) {
    const { result, calls } = await run(status);
    assert.equal(result, false);
    assert.deepEqual(calls, []);
  }
});

test('an idempotent re-join of the bound head does nothing, or completes an interrupted propagation', async () => {
  const bound = { signedHeadDigest: '0xjoin', awaitingChannelBinding: false, appliedTransitionCount: 0 };
  assert.deepEqual((await run(bound)).calls, []);
  assert.deepEqual((await run(bound, { receipt: null })).calls, ['flush', 'install']);
});
