'use strict';
// detail2 §M-7 relay batch window: window mechanics, fat→slim projection, anchor partition.
const test = require('node:test');
const assert = require('node:assert');
const { createBatchWindow, projectToSlim, partitionByAnchor } =
  require('../../hosting/wallet/batch-window');

const tick = () => new Promise((r) => setImmediate(r));

test('window closes on the cap: maxK payloads drain as ONE window', async () => {
  const drained = [];
  const bw = createBatchWindow({
    windowMs: 60_000, // timer must not be the closer here
    maxK: 3,
    drain: (ch, entries) => { drained.push(entries.length); entries.forEach((e) => e.resolve('ok')); },
  });
  const rs = [bw.enqueue(7, { a: 1 }), bw.enqueue(7, { a: 2 }), bw.enqueue(7, { a: 3 })];
  assert.deepStrictEqual(await Promise.all(rs), ['ok', 'ok', 'ok']);
  assert.deepStrictEqual(drained, [3], 'cap-full window drains once with all 3');
});

test('window closes on the timer with fewer than maxK', async () => {
  const drained = [];
  const bw = createBatchWindow({
    windowMs: 30,
    maxK: 200,
    drain: (ch, entries) => { drained.push(entries.length); entries.forEach((e) => e.resolve(1)); },
  });
  const r = bw.enqueue(7, {});
  await r;
  assert.deepStrictEqual(drained, [1]);
});

test('the 201st tx opens the NEXT window (cap overflow does not join a closed window)', async () => {
  const windows = [];
  const bw = createBatchWindow({
    windowMs: 30,
    maxK: 2,
    drain: (ch, entries) => { windows.push(entries.map((e) => e.payload)); entries.forEach((e) => e.resolve()); },
  });
  const all = [bw.enqueue(7, 'a'), bw.enqueue(7, 'b'), bw.enqueue(7, 'c')];
  await Promise.all(all);
  assert.deepStrictEqual(windows, [['a', 'b'], ['c']]);
});

test('channels have independent windows', async () => {
  const byCh = {};
  const bw = createBatchWindow({
    windowMs: 30,
    maxK: 10,
    drain: (ch, entries) => { byCh[ch] = entries.length; entries.forEach((e) => e.resolve()); },
  });
  await Promise.all([bw.enqueue(7, {}), bw.enqueue(8, {}), bw.enqueue(8, {})]);
  assert.deepStrictEqual(byCh, { 7: 1, 8: 2 });
});

test('a drain that throws rejects every still-unsettled entry (none hangs)', async () => {
  const bw = createBatchWindow({
    windowMs: 30,
    maxK: 2,
    drain: () => { throw new Error('boom'); },
  });
  const rs = await Promise.allSettled([bw.enqueue(7, {}), bw.enqueue(7, {})]);
  assert.ok(rs.every((r) => r.status === 'rejected' && /boom/.test(r.reason.message)));
});

test('per-entry settle wins over the blanket rejection (partial drain then throw)', async () => {
  const bw = createBatchWindow({
    windowMs: 30,
    maxK: 2,
    drain: (ch, entries) => { entries[0].resolve('landed'); throw new Error('rest failed'); },
  });
  const [a, b] = await Promise.allSettled([bw.enqueue(7, {}), bw.enqueue(7, {})]);
  assert.strictEqual(a.status, 'fulfilled');
  assert.strictEqual(a.value, 'landed');
  assert.strictEqual(b.status, 'rejected');
});

test('projectToSlim mirrors SendPayload::to_slim field-for-field, anchorDigest first', () => {
  const fat = {
    senderIndex: 2,
    recipientIndex: 5,
    channelTx: { tokenSlot: 1, nonce: 9 },
    proposedNextState: {
      prevDigest: '0xabc',
      balanceState: { encBalances: [[], [], [['ct-t0'], ['ct-t1']], []] },
    },
  };
  // encBalances[2] = [['ct-t0'], ['ct-t1']] — row per slot, entry per tokenSlot.
  fat.proposedNextState.balanceState.encBalances[2] = ['ct-t0', 'ct-t1'];
  const slim = projectToSlim(fat);
  assert.deepStrictEqual(slim, {
    anchorDigest: '0xabc',
    senderIndex: 2,
    recipientIndex: 5,
    channelTx: { tokenSlot: 1, nonce: 9 },
    afterCt: 'ct-t1',
  });
  assert.strictEqual(Object.keys(slim)[0], 'anchorDigest', '§M-1: anchorDigest leads the stream');
});

test('projectToSlim rejects out-of-range senderIndex / tokenSlot instead of emitting undefined', () => {
  const base = {
    senderIndex: 9,
    recipientIndex: 1,
    channelTx: { tokenSlot: 0 },
    proposedNextState: { prevDigest: '0x1', balanceState: { encBalances: [['ct']] } },
  };
  assert.throws(() => projectToSlim(base), /senderIndex 9/);
  base.senderIndex = 0;
  base.channelTx.tokenSlot = 7;
  assert.throws(() => projectToSlim(base), /tokenSlot 7/);
});

test('partitionByAnchor: stale entries split off per-tx, missing anchor counts as stale', () => {
  const mk = (d) => ({ payload: d === undefined ? {} : { proposedNextState: { prevDigest: d } } });
  const entries = [mk('0xhead'), mk('0xold'), mk(undefined), mk('0xhead')];
  const { fresh, stale } = partitionByAnchor(entries, '0xhead');
  assert.strictEqual(fresh.length, 2);
  assert.strictEqual(stale.length, 2);
});
