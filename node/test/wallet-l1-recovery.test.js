'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../api/lib/wallet-l1.js'), 'utf8');
function runner(mismatch = false, { candidate = {}, finalizedBlockNumber = 4, proved = [] } = {}) {
  const id = '0x' + '12'.repeat(32), rollup = '0x' + '34'.repeat(20);
  const posting = { receipt: { candidateId: id }, subBlocks: [{ channelId: 7 }] };
  const pinned = { rollup, posting: mismatch ? { ...posting, subBlocks: [] } : posting,
    finalize: { validityMleJson: 'the exact randomized proof already used by a signed blob' } };
  const written = new Map(); let published = false, acknowledged = false;
  const cli = { REPO: '/repo', WORK: '/work', RPC: 'http://localhost:8558', chainId: () => 31337,
    rollupOf: () => rollup, wc: (_, name) => '/work/ch7/' + name,
    readJson(file) {
      if (file.endsWith('candidate.json')) return pinned;
      if (file.endsWith('wallet-l1.json')) return { validityConfig: '/pinned-config.json' };
      if (file.endsWith('wallet_validity_receipt.json')) return { candidateId: id, transactionHash: 'tx' };
      if (file.endsWith('posts.json')) return { rollup, submitter: '0xoperator', rounds: [] };
      throw new Error('unexpected read ' + file);
    },
    writeJson: (file, value) => written.set(file, value), sh: () => '',
    cli() { published = true; assert.deepEqual(written.get('/work/ch7/wallet_validity_finalize.json'), pinned.finalize); },
    async cliAsync(...args) { return this.cli(...args); }, DEVNET_CHAIN_ID: 31337,
  };
  const producer = { enableLocalValidity: async () => {}, validityStatus: async () => ({ candidate, finalizedBlockNumber }),
    status: async () => ({ blockNumber: 4, generation: 5, extendedStateCommitment: '0xhead' }), validityPostingArtifact: async () => posting,
    stableRequestId: (kind, body) => kind + ':' + JSON.stringify(body), proveValidity: async id => { proved.push(id); },
    validityFinalizeArtifact: async () => { throw new Error('must not regenerate a published proof'); },
    acknowledgeValidity: async (_, candidateId, hash) => { assert.equal(candidateId, id); assert.equal(hash, 'tx'); acknowledged = true; },
  };
  const module = { exports: {} };
  vm.runInNewContext(source, { module, process, setTimeout, require(name) {
    if (name === 'fs') return { existsSync: file => file.endsWith('/candidate.json') };
    if (name === './cli') return cli;
    if (name === './block-producer') return producer;
    if (name === './exit-kit') return {};
    if (name === './validity-deployment') return { exportedConfig: () => '/pinned-config.json' };
    return require(name);
  } });
  return { run: (...opts) => module.exports.publish(7, ...opts), state: () => ({ published, acknowledged }) };
}
test('publication recovery reuses exact pinned randomized MLE bytes and acknowledges the receipt', async () => {
  const r = runner(); await r.run(); assert.deepEqual(r.state(), { published: true, acknowledged: true });
});
test('recovery refuses a different posting history before any publication', async () => {
  const r = runner(true); await assert.rejects(r.run(), /differs from the producer candidate/);
  assert.deepEqual(r.state(), { published: false, acknowledged: false });
});

// A burn payout proves its own validity candidate, anchored at the head it ends at: settlement
// publishes only that candidate and never proves a new one past it.
test('publishing without proving posts a pending candidate and never proves a new one', async () => {
  const proved = [];
  const idle = runner(false, { candidate: null, finalizedBlockNumber: 2, proved });
  await idle.run({ prove: false });
  assert.deepEqual(idle.state(), { published: false, acknowledged: false }, 'no candidate: nothing to publish');
  assert.deepEqual(proved, []);
  const pending = runner(false, { proved });
  await pending.run({ prove: false });
  assert.deepEqual(pending.state(), { published: true, acknowledged: true });
  assert.deepEqual(proved, []);
});
test('a default publish proves the history up to the producer head first', async () => {
  const proved = [];
  const r = runner(false, { candidate: null, finalizedBlockNumber: 2, proved });
  await r.run();
  assert.equal(proved.length, 1);
  assert.match(proved[0], /^wallet-validity:/);
  assert.deepEqual(r.state(), { published: true, acknowledged: true });
  const synced = [];
  await runner(false, { candidate: null, finalizedBlockNumber: 4, proved: synced }).run();
  assert.deepEqual(synced, [], 'nothing to prove once the producer head is finalized');
});
