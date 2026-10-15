'use strict';
// M7 liveness gap (2): a validity candidate that still carries a sub-block of a channel the
// Manager has frozen or materialized can never post (contracts/test/FrozenChannelBatchPost.t.sol),
// and the producer journal cannot drop that block (tests/block_producer_service.rs). The L1
// publish step must refuse with an operator-readable error BEFORE any transaction, not revert on
// L1 and retry forever.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../api/lib/wallet-l1.js'), 'utf8');

const ROLLUP = '0x' + '34'.repeat(20), MATERIALIZER = '0x' + '56'.repeat(20), MANAGER_A = '0x' + '78'.repeat(20);
const ZERO_ADDRESS = '0x' + '0'.repeat(40), ZERO_WORD = '0x' + '0'.repeat(64);
// Values cross the vm realm boundary; compare their JSON shape, not their prototypes.
const plain = value => JSON.parse(JSON.stringify(value));

function runner({ l1 = {}, settlement = true, subBlocks = [{ channelId: 7 }, { channelId: 9 }] } = {}) {
  const id = '0x' + '12'.repeat(32);
  const posting = { receipt: { candidateId: id, initialBlockNumber: 4, finalBlockNumber: 4 + subBlocks.length }, subBlocks };
  const casts = []; let published = false;
  const cli = { REPO: '/repo', WORK: '/work', RPC: 'http://localhost:8558', chainId: () => 31337, CHANNELS: [7, 9],
    rollupOf: () => ROLLUP, wc: (ch, name) => `/work/ch${ch}/` + name, DEVNET_CHAIN_ID: 31337,
    readJson(file) {
      if (file.endsWith('settlement.json')) return { rollup: ROLLUP, manager: MANAGER_A, close_funding_materializer: MATERIALIZER };
      if (file.endsWith('wallet-l1.json')) return { validityConfig: '/pinned-config.json' };
      if (file.endsWith('wallet_validity_receipt.json')) return { candidateId: id, transactionHash: 'tx' };
      throw new Error('unexpected read ' + file);
    },
    writeJson() {},
    sh(bin, args) {
      if (bin === 'cast' && args[0] === 'call') {
        casts.push(args.slice(1, 4));
        const [address, sig, arg] = args.slice(1, 4);
        assert.equal(address, MATERIALIZER, 'only the materializer is read');
        const answers = l1[Number(arg)] || {};
        if (sig.startsWith('managerOfChannel')) return (answers.manager || ZERO_ADDRESS) + '\n';
        if (sig.startsWith('materializedChannelExit')) return (answers.exited || ZERO_WORD) + '\n';
        if (sig.startsWith('frozenGeneration')) return String(answers.frozen || 0) + '\n';
      }
      return '';
    },
    async cliAsync() { published = true; },
  };
  const producer = { enableLocalValidity: async () => {}, validityStatus: async () => ({ candidate: { id }, finalizedBlockNumber: 4 }),
    status: async () => ({ blockNumber: 6, generation: 5, extendedStateCommitment: '0xhead' }), validityPostingArtifact: async () => posting,
    stableRequestId: () => 'x', proveValidity: async () => {}, validityFinalizeArtifact: async () => ({ validityMleJson: 'proof' }),
    acknowledgeValidity: async () => {},
  };
  const module = { exports: {} };
  vm.runInNewContext(source, { module, process, setTimeout, require(name) {
    if (name === 'fs') return { existsSync: file => settlement && file.endsWith('settlement.json') };
    if (name === './cli') return cli;
    if (name === './block-producer') return producer;
    if (name === './validity-deployment') return { exportedConfig: () => '/pinned-config.json' };
    return require(name);
  } });
  return { run: () => module.exports.publish(7), scan: () => module.exports.frozenChannelsInCandidate(7, posting), casts, state: () => ({ published }) };
}

test('a candidate carrying a frozen channel sub-block is refused before any L1 transaction', async () => {
  const r = runner({ l1: { 7: { manager: MANAGER_A, frozen: 1 } } });
  await assert.rejects(r.run(), (error) => {
    assert.equal(error.code, 'VALIDITY_CANDIDATE_CONTAINS_FROZEN_CHANNEL_BLOCK');
    assert.match(error.message, /can never post: channel 7 is frozen on L1 \(ChannelExitAlreadyFrozen; blocks 5\)/);
    assert.match(error.message, /cancel the pending close/);
    assert.deepEqual(plain(error.frozenChannels), [{ channelId: 7, blocks: [5], state: 'frozen', revert: 'ChannelExitAlreadyFrozen', frozenGeneration: '1' }]);
    return true;
  });
  assert.deepEqual(r.state(), { published: false });
  // Channel 9 is unbound: only its manager binding is read, never its freeze state.
  assert.deepEqual(r.casts.filter(c => c[2] === '9').map(c => c[1]), ['managerOfChannel(uint32)(address)']);
});

test('an exited channel is reported as permanently unpostable', async () => {
  const exit = '0x' + 'ab'.repeat(32);
  const r = runner({ l1: { 7: { manager: MANAGER_A, exited: exit, frozen: 3 } }, subBlocks: [{ channelId: 9 }, { channelId: 7 }, { channelId: 7 }] });
  const stuck = r.scan();
  assert.deepEqual(plain(stuck), [{ channelId: 7, blocks: [6, 7], state: 'exited', revert: 'ChannelAlreadyExited', materializedChannelExit: exit }]);
  await assert.rejects(r.run(), /permanently unpostable/);
  assert.deepEqual(r.state(), { published: false });
});

test('a bound but active channel, or an unbound channel, publishes as before', async () => {
  const active = runner({ l1: { 7: { manager: MANAGER_A } } });
  assert.deepEqual(plain(active.scan()), []);
  await active.run();
  assert.deepEqual(active.state(), { published: true });
  const unbound = runner();
  await unbound.run();
  assert.deepEqual(unbound.state(), { published: true });
});

test('without any settlement stack on this rollup nothing is read and publication proceeds', async () => {
  const r = runner({ settlement: false, l1: { 7: { manager: MANAGER_A, frozen: 1 } } });
  await r.run();
  assert.deepEqual(r.casts, []);
  assert.deepEqual(r.state(), { published: true });
});
