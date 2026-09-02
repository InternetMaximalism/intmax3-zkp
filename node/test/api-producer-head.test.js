const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-producer-head-'));
process.env.INTMAX_WORK_DIR = work;

const producer = require('../../api/lib/block-producer');
const cliModule = require('../../api/lib/cli');
const authoritativeSnapshots = new Map();
cliModule.cli = (ch, args) => {
  if (args[0] === 'publish-snapshot' && authoritativeSnapshots.has(ch)) {
    write(ch, args[1] || 'channel_snapshot.json', authoritativeSnapshots.get(ch));
  }
};
const { flushPublishedHead, publishOffchainSnapshot } = require('../../api/lib/producer-head');

const heads = new Map();
const calls = [];

producer.status = async () => ({
  channelHeads: [...heads].map(([channelId, stateDigest]) => ({ channelId, stateDigest })),
});
producer.syncOffchainHeads = async states => {
  calls.push({ kind: 'sync', states });
  for (const state of states) heads.set(state.channelId, state.digest);
  return { generation: calls.length };
};
producer.postInterChannel = async (state, debitPayload, descriptor) => {
  calls.push({ kind: 'post', state, debitPayload, descriptor });
  heads.set(state.channelId, state.digest);
  return { generation: calls.length };
};
producer.liveSettleInterChannel = async (channelId, receipt, state, debitPayload, descriptor) => {
  calls.push({ kind: 'settle', channelId, receipt, state, debitPayload, descriptor });
  return { baseNonce: calls.length };
};
producer.liveBindSnapshot = async (channelId, snapshot) => {
  calls.push({ kind: 'bind', channelId, snapshot });
  return { channelId, signedHeadDigest: snapshot.state.digest };
};

function write(ch, name, value) {
  const directory = path.join(work, `ch${ch}`);
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, name), JSON.stringify(value));
}

test.after(() => fs.rmSync(work, { recursive: true, force: true }));

test('recovers a source H2 transition before trying an off-chain sync', async () => {
  calls.length = 0;
  heads.set(7, 'before-a');
  heads.set(8, 'before-b');
  const source = { channelId: 7, digest: 'after-a' };
  const fund = { channelId: 8, digest: 'fund-b' };
  const bundle = { channelId: 8, digest: 'after-b' };
  write(7, 'channel_snapshot.json', { state: source });
  write(7, 'inter_debit_payload.json', { payload: 1 });
  write(7, 'inter_descriptor.json', { descriptor: 1 });
  write(7, 'inter_transfer.json', {
    aHead: source,
    bFundImportState: fund,
    bBundleApplyState: bundle,
  });

  await flushPublishedHead(7);
  assert.deepEqual(calls.map(call => call.kind), ['post', 'sync', 'settle']);
  assert.equal(heads.get(7), 'after-a');
  assert.equal(heads.get(8), 'after-b');
  assert.equal(calls[2].channelId, 7);
});

test('destination recovery copy replays both contiguous receive states', async () => {
  calls.length = 0;
  heads.set(9, 'before');
  const fund = { channelId: 9, digest: 'fund' };
  const bundle = { channelId: 9, digest: 'bundle' };
  write(9, 'channel_snapshot.json', { state: bundle });
  write(9, 'incoming_inter_transfer.json', {
    bFundImportState: fund,
    bBundleApplyState: bundle,
  });

  await flushPublishedHead(9);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], { kind: 'sync', states: [fund, bundle] });
  assert.equal(heads.get(9), 'bundle');
});

test('deposit recovery never skips its intermediate fund-import state', async () => {
  calls.length = 0;
  heads.set(10, 'before');
  const fund = { channelId: 10, digest: 'fund' };
  const bundle = { channelId: 10, digest: 'bundle' };
  write(10, 'channel_snapshot.json', { state: bundle });
  write(10, 'l1_import_cosigned.json', {
    fundImportState: fund,
    bundleApplyState: bundle,
  });

  await flushPublishedHead(10);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], { kind: 'sync', states: [fund, bundle] });
});

test('ordinary signed head is bound to backing before its public producer head advances', async () => {
  calls.length = 0;
  heads.set(11, 'before');
  const state = {
    channelId: 11,
    digest: 'after',
    h2Tag: `0x${'00'.repeat(32)}`,
  };
  const snapshot = { record: { channelId: 11 }, members: [], state };
  write(11, 'channel_snapshot.json', snapshot);

  const result = await publishOffchainSnapshot(11, state);
  assert.deepEqual(calls.map(call => call.kind), ['bind', 'sync']);
  assert.deepEqual(calls[0], { kind: 'bind', channelId: 11, snapshot });
  assert.equal(result.headSyncReceipt.generation, 2);
  assert.equal(heads.get(11), 'after');
});

test('failed backing bind leaves the public producer head unchanged', async () => {
  calls.length = 0;
  heads.set(12, 'before');
  const state = {
    channelId: 12,
    digest: 'after',
    h2Tag: `0x${'00'.repeat(32)}`,
  };
  write(12, 'channel_snapshot.json', { record: {}, members: [], state });
  const original = producer.liveBindSnapshot;
  producer.liveBindSnapshot = async () => {
    calls.push({ kind: 'bind-failed' });
    throw new Error('backing rejected');
  };
  try {
    await assert.rejects(publishOffchainSnapshot(12, state), /backing rejected/);
  } finally {
    producer.liveBindSnapshot = original;
  }
  assert.deepEqual(calls.map(call => call.kind), ['bind-failed']);
  assert.equal(heads.get(12), 'before');
});

test('flush republishes the authoritative private head before binding or exposing it', async () => {
  calls.length = 0;
  heads.set(13, 'parent');
  const parent = {
    record: { channelId: 13 }, members: [],
    state: { channelId: 13, digest: 'parent', h2Tag: `0x${'00'.repeat(32)}` },
  };
  const child = {
    record: { channelId: 13 }, members: [],
    state: { channelId: 13, digest: 'child', h2Tag: `0x${'00'.repeat(32)}` },
  };
  write(13, 'channel_snapshot.json', parent);
  authoritativeSnapshots.set(13, child);
  try {
    await flushPublishedHead(13);
  } finally {
    authoritativeSnapshots.delete(13);
  }
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(work, 'ch13', 'channel_snapshot.json'))), child);
  assert.deepEqual(calls.map(call => call.kind), ['bind', 'sync']);
  assert.equal(calls[0].snapshot.state.digest, 'child');
  assert.equal(heads.get(13), 'child');
});
