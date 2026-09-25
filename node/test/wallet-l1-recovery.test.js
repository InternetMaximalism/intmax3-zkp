'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../api/lib/wallet-l1.js'), 'utf8');
function runner(mismatch = false) {
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
      throw new Error('unexpected read ' + file);
    },
    writeJson: (file, value) => written.set(file, value), sh: () => '',
    cli() { published = true; assert.deepEqual(written.get('/work/ch7/wallet_validity_finalize.json'), pinned.finalize); },
  };
  const producer = { enableLocalValidity: async () => {}, validityStatus: async () => ({ candidate: {} }),
    status: async () => ({ blockNumber: 4 }), validityPostingArtifact: async () => posting,
    validityFinalizeArtifact: async () => { throw new Error('must not regenerate a published proof'); },
    acknowledgeValidity: async (_, candidateId, hash) => { assert.equal(candidateId, id); assert.equal(hash, 'tx'); acknowledged = true; },
  };
  const module = { exports: {} };
  vm.runInNewContext(source, { module, require(name) {
    if (name === 'fs') return { existsSync: file => file.endsWith('/candidate.json') };
    if (name === './cli') return cli;
    if (name === './block-producer') return producer;
    if (name === './exit-kit') return {};
    return require(name);
  } });
  return { run: () => module.exports.publish(7), state: () => ({ published, acknowledged }) };
}
test('publication recovery reuses exact pinned randomized MLE bytes and acknowledges the receipt', async () => {
  const r = runner(); await r.run(); assert.deepEqual(r.state(), { published: true, acknowledged: true });
});
test('recovery refuses a different posting history before any publication', async () => {
  const r = runner(true); await assert.rejects(r.run(), /differs from the producer candidate/);
  assert.deepEqual(r.state(), { published: false, acknowledged: false });
});
