'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-public-live-backing-'));
process.env.INTMAX_WORK_DIR = work;
process.env.CHAIN_ID = '31337';
fs.mkdirSync(path.join(work, 'ch7'), { recursive: true });
fs.writeFileSync(path.join(work, 'ch7', 'channel_backing.json'), JSON.stringify({
  rollup: '0x1111111111111111111111111111111111111111',
  deposit_recipient: '0x' + 'aa'.repeat(32),
  fund: 999,
  base_private_state: { secret: 'must-not-leak' },
}));

const producer = require('../../api/lib/block-producer');
producer.liveBackingArtifact = async () => ({
  baseHead: {
    snapshotVersion: 4,
    channelId: 7,
    settledTxChain: '0x' + '12'.repeat(32),
    awaitingChannelBinding: false,
  },
  balanceAttestation: { balanceProof: [1, 2, 3] },
  balanceVerifierData: [4, 5, 6],
  channelRecord: { channelId: 7 },
  signedHead: {
    channelId: 7,
    digest: '0x' + '34'.repeat(32),
    balanceState: { settledTxChain: '0x' + '12'.repeat(32) },
  },
  signedHeadExitKit: {
    schemaVersion: 1,
    backingProof: [7, 8, 9],
    backingPublicInputs: {
      channelId: 7,
      settledTxChain: '0x' + '12'.repeat(32),
      tokenFundsDigest: '0x' + '45'.repeat(32),
      finalizedExtendedStateCommitment: '0x' + '67'.repeat(32),
      anchorBlockNumber: 11,
    },
  },
});
producer.livePrepareDepositRecipient = async () => '0x' + '56'.repeat(32);

// The route must source its transport chain binding from the configured RPC authority. Keep this
// unit test network-free while still proving an unrelated CHAIN_ID label cannot override it.
const cliLib = require('../../api/lib/cli');
cliLib.chainId = () => 31337;
process.env.CHAIN_ID = '1';

// This route unit isolates the public transport projection. Crash-gap publication recovery has
// its own producer-head tests and requires a complete private CLI state, which this fixture
// deliberately does not fabricate.
const producerHead = require('../../api/lib/producer-head');
producerHead.flushPublishedHead = async () => null;

const express = require('../../api/node_modules/express');
const channelState = require('../../api/routes/channel-state');

test.after(() => fs.rmSync(work, { recursive: true, force: true }));

async function withServer(fn) {
  const app = express();
  app.use('/channel/:ch', channelState);
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  try { await fn(server.address().port); }
  finally { await new Promise(resolve => server.close(resolve)); }
}

test('backing endpoint serves only the durable live proof bundle, never setup-time state', async () => {
  await withServer(async port => {
    const response = await fetch(`http://127.0.0.1:${port}/channel/7/backing`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.schemaVersion, 3);
    assert.equal(body.source, 'liveBalanceService');
    assert.equal(body.chainId, 31337);
    assert.equal(body.rollup, '0x1111111111111111111111111111111111111111');
    assert.equal(body.baseHead.settledTxChain, '0x' + '12'.repeat(32));
    assert.deepEqual(body.signedHeadExitKit.backingProof, [7, 8, 9]);
    assert.equal(body.signedHeadExitKit.backingPublicInputs.anchorBlockNumber, 11);
    assert.equal(body.signedHeadExitKit.backingMleJson, undefined,
      'live source must archive the inner proof, never an MLE wrapper');
    assert.equal(body.fund, undefined);
    assert.equal(body.deposit_recipient, undefined);
    assert.doesNotMatch(JSON.stringify(body), /must-not-leak/);
  });
});

test('backing endpoint rejects a v4 signed head without a complete inner-proof exit kit', async () => {
  const previous = producer.liveBackingArtifact;
  try {
    for (const [name, mutate, pattern] of [
      ['old live snapshot', (x) => { x.baseHead.snapshotVersion = 3; }, /live snapshot version 4/],
      ['missing', (x) => { delete x.signedHeadExitKit; }, /signedHeadExitKit must be an object/],
      ['empty proof', (x) => { x.signedHeadExitKit.backingProof = []; }, /nonempty byte array/],
      ['MLE substitution', (x) => { x.signedHeadExitKit.backingMleJson = '{}'; }, /unexpected schema/],
      ['wrong chain', (x) => {
        x.signedHeadExitKit.backingPublicInputs.settledTxChain = '0x' + '99'.repeat(32);
      }, /settled chain differs/],
    ]) {
      producer.liveBackingArtifact = async () => {
        const artifact = await previous();
        mutate(artifact);
        return artifact;
      };
      await withServer(async port => {
        const response = await fetch(`http://127.0.0.1:${port}/channel/7/backing`);
        assert.equal(response.status, 409, name);
        assert.match((await response.json()).error, pattern, name);
      });
    }
  } finally {
    producer.liveBackingArtifact = previous;
  }
});

test('unavailable/unbound live backing is 409 and has no static fallback', async () => {
  const previous = producer.liveBackingArtifact;
  producer.liveBackingArtifact = async () => { throw new Error('awaiting N-of-N bind'); };
  try {
    await withServer(async port => {
      const response = await fetch(`http://127.0.0.1:${port}/channel/7/backing`);
      assert.equal(response.status, 409);
      const body = await response.json();
      assert.match(body.error, /awaiting N-of-N bind/);
      assert.equal(body.fund, undefined);
    });
  } finally {
    producer.liveBackingArtifact = previous;
  }
});

test('deposit info allocates from the live authority instead of reusing the legacy recipient', async () => {
  await withServer(async port => {
    const response = await fetch(`http://127.0.0.1:${port}/channel/7/deposit/info`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.depositRecipient, '0x' + '56'.repeat(32));
    assert.notEqual(body.depositRecipient, '0x' + 'aa'.repeat(32));
    assert.equal(body.chainId, 31337, 'RPC-derived chain id must override the unrelated env label');
  });
});
