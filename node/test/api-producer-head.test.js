const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-producer-head-'));
process.env.INTMAX_WORK_DIR = work;

const producer = require('../../api/lib/block-producer');
const cliModule = require('../../api/lib/cli');
cliModule.cli = () => {};
const { flushPublishedHead } = require('../../api/lib/producer-head');

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
