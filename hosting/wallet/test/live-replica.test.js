'use strict';
// Unit test of the standby-replica exchange (api/lib/live-replica.js): a signed bundle is stored,
// a tampered or unsigned one is refused, a journal-generation rollback is refused, and
// ensureReplicated reports whether a peer holds the current state. No daemon, no relay.
//   node --test hosting/wallet/test/live-replica.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'live-replica-'));
process.env.INTMAX_WORK_DIR = WORK;
process.env.INTMAX_CLUSTER_SECRET = 'test-secret';
process.env.INTMAX_REPLICA_ROOT = path.join(WORK, 'replica');
process.env.INTMAX_CHANNELS = '7';

const producer = require('../../../api/lib/block-producer');
const replica = require('../../../api/lib/live-replica');

const SELF = 'http://self:8001';
const PEER = 'http://peer:8001';

function seed(generation) {
  fs.mkdirSync(path.dirname(producer.JOURNAL), { recursive: true });
  fs.writeFileSync(producer.JOURNAL, JSON.stringify({ magic: 'x', generation, entries: [] }));
  const snap = producer.liveSnapshotPath(7);
  fs.mkdirSync(path.dirname(snap), { recursive: true });
  fs.writeFileSync(snap, Buffer.concat([Buffer.from('IMLIVEBALANCE001'), Buffer.alloc(40, generation)]));
  fs.mkdirSync(path.join(WORK, 'ch7'), { recursive: true });
  fs.writeFileSync(path.join(WORK, 'ch7', 'channel_backing.json'), JSON.stringify({ deposit_salt: 's', generation }));
}

// Capture what the sender posts and feed it to a receiver configured as the peer.
const posted = [];
global.fetch = async (url, init) => {
  posted.push({ url, init });
  replica.configure({ selfUrl: PEER, peers: [{ url: SELF }], log: { error() {} } });
  try {
    const out = replica.receive(JSON.parse(init.body), init.headers['x-intmax-replica-signature']);
    return { ok: true, status: 200, text: async () => JSON.stringify(out) };
  } catch (e) {
    return { ok: false, status: e.status || 500, text: async () => e.message };
  } finally {
    replica.configure({ selfUrl: SELF, peers: [{ url: PEER }], log: { error() {} } });
  }
};

test('a signed bundle is stored on the peer and acknowledged', async () => {
  seed(3);
  replica.configure({ selfUrl: SELF, peers: [{ url: PEER }], log: { error() {} } });
  assert.equal(replica.enabled(), true);
  const r = await replica.replicate(7, 'test', { sync: true });
  assert.deepEqual(r.acked, [PEER]);
  assert.deepEqual(r.failed, []);
  const held = replica.held();
  assert.equal(held.length, 1);
  assert.equal(held[0].channel, 7);
  assert.equal(held[0].journalGeneration, 3);
  const dir = path.join(process.env.INTMAX_REPLICA_ROOT, replica.hostKey(SELF));
  assert.ok(fs.existsSync(path.join(dir, 'producer', 'journal.json')));
  assert.ok(fs.existsSync(path.join(dir, 'producer', 'live', 'channel-7', 'balance.snapshot')));
  assert.ok(fs.existsSync(path.join(dir, 'ch7', 'channel_backing.json')));
  assert.equal(fs.statSync(path.join(dir, 'producer', 'live', 'channel-7', 'balance.snapshot')).mode & 0o777, 0o600);
  // Unchanged state is not shipped again.
  const again = await replica.replicate(7, 'test', { sync: true });
  assert.equal(again.skipped, 'already replicated');
  assert.equal(await replica.ensureReplicated(7, 'test'), true);
});

test('a bundle with a wrong signature, a tampered file or a stale generation is refused', async () => {
  replica.configure({ selfUrl: PEER, peers: [{ url: SELF }], log: { error() {} } });
  const body = JSON.parse(posted[0].init.body);
  const sig = posted[0].init.headers['x-intmax-replica-signature'];
  assert.throws(() => replica.receive(body, 'deadbeef'), /signature mismatch/);
  const tampered = JSON.parse(JSON.stringify(body));
  tampered.files['ch7/channel_backing.json'].base64 = Buffer.from('{}').toString('base64');
  assert.throws(() => replica.receive(tampered, sig), /does not match its digest/);
  const stranger = { ...body, from: 'http://stranger:1' };
  assert.throws(() => replica.receive(stranger, sig), /not a configured peer/);
  // Rollback: a generation-2 bundle after the held generation 3.
  replica.configure({ selfUrl: SELF, peers: [{ url: PEER }], log: { error() {} } });
  seed(2);
  const r = await replica.replicate(7, 'rollback', { sync: true });
  assert.deepEqual(r.acked, []);
  assert.match(r.failed[0].error, /behind the held 3/);
});

test('without INTMAX_CLUSTER_SECRET nothing is shipped and ensureReplicated says so', async () => {
  delete require.cache[require.resolve('../../../api/lib/live-replica')];
  process.env.INTMAX_CLUSTER_SECRET = '';
  const fresh = require('../../../api/lib/live-replica');
  fresh.configure({ selfUrl: SELF, peers: [{ url: PEER }], log: { error() {} } });
  assert.equal(fresh.enabled(), false);
  assert.deepEqual(await fresh.replicate(7, 'x', { sync: true }), { skipped: 'no secret' });
  assert.equal(await fresh.ensureReplicated(7, 'x'), false);
});
