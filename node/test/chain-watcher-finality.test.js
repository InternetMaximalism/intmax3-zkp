'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { ChainWatcher, ChainSafetyError } = require('../common/chain-watcher');
const { Store } = require('../common/store');
const { makeRuntime: makeCosignerRuntime } = require('../cosigner/loop');
const {
  createChainReadiness,
  handleCosignerPollFailure,
  markCosignerPollSuccess,
  propagateExistingChainSafetyHalt,
  startAfterInitialChainPoll,
} = require('../cosigner');
const { makeRuntime: makeDelegateRuntime } = require('../delegate/loop');
const cosignBranch = require('../cosigner/branches/cosign');

const ROLLUP = `0x${'11'.repeat(20)}`;

function hash(tag) {
  return `0x${BigInt(tag).toString(16).padStart(64, '0')}`;
}

function linearBlocks(last, forkTag = 0) {
  const blocks = new Map();
  for (let number = 0; number <= last; number += 1) {
    blocks.set(number, {
      number,
      hash: hash(BigInt(forkTag) * 1000n + BigInt(number + 1)),
      parentHash: number === 0
        ? hash(0)
        : hash(BigInt(forkTag) * 1000n + BigInt(number)),
    });
  }
  return blocks;
}

class FakeProvider {
  constructor({ blocks, finalized, latest, logs = [], chainId = 1n }) {
    this.blocks = blocks;
    this.finalized = finalized;
    this.latest = latest;
    this.logs = logs;
    this.chainId = chainId;
    this.logQueries = [];
  }

  async getNetwork() { return { chainId: this.chainId }; }

  async getBlock(tag) {
    if (tag === 'finalized') return this.finalized == null ? null : this.blocks.get(this.finalized);
    return this.blocks.get(Number(tag)) || null;
  }

  async getBlockNumber() { return this.latest; }

  async getLogs(query) {
    this.logQueries.push(query);
    return this.logs.filter(logEntry => (
      logEntry.blockNumber >= query.fromBlock && logEntry.blockNumber <= query.toBlock
    ));
  }
}

function watcher(provider, overrides = {}) {
  const result = new ChainWatcher({
    rpcUrl: 'http://unused.invalid',
    channels: [{ id: 7, rollup: ROLLUP }],
    chainId: Number(provider.chainId),
    provider,
    ...overrides,
  });
  // The finality tests exercise chain selection/checkpointing, not ABI decoding. Preserve exactly
  // the log identity the fake provider supplied.
  result._normalize = logEntry => ({
    kind: logEntry.kind || 'TestEvent',
    channelId: 7,
    channelIds: [7],
    blockNumber: logEntry.blockNumber,
    blockHash: logEntry.blockHash,
    txHash: logEntry.transactionHash || hash(900),
    logIndex: logEntry.index || 0,
  });
  return result;
}

function tempStore(name) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `intmax-${name}-`));
  return {
    directory,
    path: path.join(directory, 'state.json'),
    cleanup() { fs.rmSync(directory, { recursive: true, force: true }); },
  };
}

test('public watcher dispatches finalized blocks only and remains exact-once at the cursor', async () => {
  const blocks = linearBlocks(12);
  const provider = new FakeProvider({
    blocks,
    finalized: 10,
    latest: 12,
    logs: [
      { blockNumber: 10, blockHash: blocks.get(10).hash, index: 0 },
      { blockNumber: 11, blockHash: blocks.get(11).hash, index: 0 },
    ],
  });
  const chain = watcher(provider);
  const seen = [];
  let progress = null;
  const next = await chain.pollOnce(
    10,
    event => seen.push(event.blockNumber),
    (cursor, checkpoint) => { progress = { cursor, checkpoint }; },
  );

  assert.equal(next, 11);
  assert.deepEqual(seen, [10]);
  assert.equal(provider.logQueries[0].toBlock, 10);
  assert.deepEqual(progress, { cursor: 11, checkpoint: blocks.get(10) });

  await chain.pollOnce(11, event => seen.push(event.blockNumber));
  assert.deepEqual(seen, [10]);
});

test('unchanged finalized checkpoint resumes exactly once after store restart', async () => {
  const blocks = linearBlocks(10);
  const provider = new FakeProvider({
    blocks,
    finalized: 10,
    latest: 10,
    logs: [{ blockNumber: 10, blockHash: blocks.get(10).hash, index: 0 }],
  });
  const chain = watcher(provider);
  const temp = tempStore('finalized-exact-once-restart');
  const seen = [];
  try {
    let store = new Store(temp.path);
    await chain.pollOnce(
      store.get('cursor'),
      event => seen.push(event.blockNumber),
      (cursor, checkpoint) => store.setChainProgress(cursor, checkpoint),
    );
    assert.deepEqual(seen, [10]);
    dropStore(store);

    store = new Store(temp.path);
    const checked = await chain.validateCheckpoint(
      store.get('cursor'),
      store.get('chainCheckpoint'),
    );
    assert.equal(checked.bootstrapped, false);
    await chain.pollOnce(
      checked.cursor,
      event => seen.push(event.blockNumber),
      (cursor, checkpoint) => store.setChainProgress(cursor, checkpoint),
    );
    assert.deepEqual(seen, [10]);
  } finally {
    temp.cleanup();
  }
});

test('same-height finalized replacement is detected after store restart and halt is durable', async () => {
  const savedBlocks = linearBlocks(10);
  const temp = tempStore('finalized-restart');
  try {
    let store = new Store(temp.path);
    store.setChainProgress(11, savedBlocks.get(10));
    dropStore(store);

    const replacementBlocks = linearBlocks(10);
    replacementBlocks.set(10, {
      number: 10,
      hash: hash(7777),
      parentHash: replacementBlocks.get(9).hash,
    });
    const provider = new FakeProvider({ blocks: replacementBlocks, finalized: 10, latest: 10 });
    const chain = watcher(provider);
    store = new Store(temp.path);
    let error;
    try {
      await chain.validateCheckpoint(store.get('cursor'), store.get('chainCheckpoint'));
      assert.fail('replacement checkpoint must fail');
    } catch (caught) {
      error = caught;
    }
    assert.equal(error instanceof ChainSafetyError, true);
    assert.equal(error.code, 'FINALIZED_CHECKPOINT_MISMATCH');
    store.haltChainSafety(error);
    dropStore(store);

    const reopened = new Store(temp.path);
    assert.equal(reopened.get('chainSafetyHalt').code, 'FINALIZED_CHECKPOINT_MISMATCH');
  } finally {
    temp.cleanup();
  }
});

test('a log whose blockHash differs from the canonical block is rejected before dispatch', async () => {
  const blocks = linearBlocks(10);
  const provider = new FakeProvider({
    blocks,
    finalized: 10,
    latest: 10,
    logs: [{ blockNumber: 10, blockHash: hash(9999), index: 0 }],
  });
  const chain = watcher(provider);
  let dispatched = false;
  let persisted = false;
  await assert.rejects(
    chain.pollOnce(
      10,
      () => { dispatched = true; },
      () => { persisted = true; },
    ),
    err => err instanceof ChainSafetyError && err.code === 'LOG_BLOCK_HASH_MISMATCH',
  );
  assert.equal(dispatched, false);
  assert.equal(persisted, false);
});

test('a removed log in the finalized range is rejected before dispatch', async () => {
  const blocks = linearBlocks(10);
  const provider = new FakeProvider({
    blocks,
    finalized: 10,
    latest: 10,
    logs: [{ blockNumber: 10, blockHash: blocks.get(10).hash, index: 0, removed: true }],
  });
  const chain = watcher(provider);
  let dispatched = false;
  await assert.rejects(
    chain.pollOnce(10, () => { dispatched = true; }),
    err => err instanceof ChainSafetyError && err.code === 'REMOVED_LOG_IN_DURABLE_RANGE',
  );
  assert.equal(dispatched, false);
});

test('fork-A close state is not blessed by a checkpointless legacy cursor on fork B', async () => {
  const forkABlocks = linearBlocks(12, 1);
  const forkBBlocks = linearBlocks(12, 2);
  const provider = new FakeProvider({ blocks: forkBBlocks, finalized: 10, latest: 12 });
  const chain = watcher(provider);
  const temp = tempStore('legacy-cursor');
  try {
    fs.writeFileSync(temp.path, JSON.stringify({
      cursor: 10,
      // This is representative of a close action derived while fork A was canonical. The legacy
      // schema retained the cursor but not fork A's block-9 hash.
      actions: {
        'close:fork-a': {
          at: 1,
          result: 'submitted',
          observedBlockHash: forkABlocks.get(9).hash,
        },
      },
    }), { mode: 0o600 });
    const store = new Store(temp.path);
    await assert.rejects(
      chain.validateCheckpoint(store.get('cursor'), store.get('chainCheckpoint')),
      err => err instanceof ChainSafetyError && err.code === 'LEGACY_CURSOR_UNAUTHENTICATED',
    );
    assert.equal(store.hasAction('close:fork-a'), true);
    assert.equal(store.get('cursor'), 10);
    assert.equal(store.get('chainCheckpoint'), null);
    assert.notEqual(forkABlocks.get(9).hash, forkBBlocks.get(9).hash);
    assert.throws(
      () => store.bootstrapChainProgress(10, forkBBlocks.get(9)),
      /operator reconciliation/,
    );
  } finally {
    temp.cleanup();
  }
});

test('legacy number-only cursor ahead of finality fails before consulting the current fork', async () => {
  const blocks = linearBlocks(12);
  const provider = new FakeProvider({ blocks, finalized: 10, latest: 12 });
  const chain = watcher(provider);
  await assert.rejects(
    chain.validateCheckpoint(13, null),
    err => err instanceof ChainSafetyError && err.code === 'LEGACY_CURSOR_UNAUTHENTICATED',
  );
});

test('missing finalized RPC head fails closed on a public chain', async () => {
  const provider = new FakeProvider({ blocks: linearBlocks(5), finalized: null, latest: 5 });
  const chain = watcher(provider);
  await assert.rejects(
    chain.pollOnce(0, () => {}),
    err => err instanceof ChainSafetyError && err.code === 'FINALIZED_HEAD_UNAVAILABLE',
  );
});

test('unfinalized confirmation mode requires explicit chain 31337', async () => {
  const mainnet = new FakeProvider({ blocks: linearBlocks(5), finalized: null, latest: 5 });
  assert.throws(
    () => new ChainWatcher({ rpcUrl: 'http://unused.invalid', channels: [] }),
    /chainId is required/,
  );
  assert.throws(
    () => watcher(mainnet, { allowUnfinalizedDevnet: true }),
    /only for explicit chainId 31337/,
  );

  const blocks = linearBlocks(5);
  const devnet = new FakeProvider({
    blocks,
    finalized: null,
    latest: 5,
    chainId: 31337n,
    logs: [{ blockNumber: 3, blockHash: blocks.get(3).hash, index: 0 }],
  });
  const chain = watcher(devnet, { allowUnfinalizedDevnet: true, confirmations: 2 });
  const seen = [];
  const next = await chain.pollOnce(3, event => seen.push(event.blockNumber));
  assert.equal(next, 4);
  assert.deepEqual(seen, [3]);
});

test('pending-close reconciliation getter is pinned to the finalized event block', async () => {
  const provider = new FakeProvider({ blocks: linearBlocks(10), finalized: 10, latest: 12 });
  const chain = watcher(provider);
  let observedBlockTag;
  chain._ethers = {
    Contract: class {
      async getPendingClose(overrides) {
        observedBlockTag = overrides.blockTag;
        return {
          active: true,
          closeIntentDigest: hash(123),
          finalEpoch: 4n,
          finalStateVersion: 9n,
          challengeDeadline: 100n,
          closeFreezeNonce: 3n,
        };
      }
    },
  };
  const pending = await chain.getPendingClose(ROLLUP, 10);
  assert.equal(observedBlockTag, 10);
  assert.equal(pending.epoch, 4);
  assert.equal(pending.stateVersion, 9);
});

test('delegate close reconciliation reads status, pending intent, and time from one durable block', async () => {
  const blocks = linearBlocks(12);
  for (const [number, block] of blocks) block.timestamp = 1_000 + number;
  // The RPC finalized head has already advanced to 12, while the delegate's fully-dispatched
  // durable cursor is still pinned to block 10.  Reconciliation must not skip ahead.
  const provider = new FakeProvider({ blocks, finalized: 12, latest: 12 });
  const chain = watcher(provider);
  const observedBlockTags = [];
  chain._ethers = {
    Contract: class {
      async channelStatus(overrides) {
        observedBlockTags.push(overrides.blockTag);
        return 1n;
      }

      async closeRequestGeneration(overrides) {
        observedBlockTags.push(overrides.blockTag);
        return 7n;
      }

      async getPendingClose(overrides) {
        observedBlockTags.push(overrides.blockTag);
        return {
          active: true,
          closeIntentDigest: hash(123),
          finalEpoch: 4n,
          finalStateVersion: 9n,
          challengeDeadline: 1_100n,
          closeFreezeNonce: 3n,
        };
      }
    },
  };

  const close = await chain.getDurableCloseState(ROLLUP, blocks.get(10));
  assert.equal(close.status, 1);
  assert.equal(close.durable.number, 10);
  assert.equal(close.durable.timestamp, 1_010);
  assert.equal(close.closeRequestGenerationExact, '7');
  assert.equal(close.pending.challengeDeadlineExact, '1100');
  assert.deepEqual(observedBlockTags, [10, 10, 10]);
});

test('delegate close reconciliation rejects a fork switch during Manager reads', async () => {
  const blocks = linearBlocks(10);
  for (const [number, block] of blocks) block.timestamp = 1_000 + number;
  const original = { ...blocks.get(10) };
  const provider = new FakeProvider({ blocks, finalized: 10, latest: 10 });
  const chain = watcher(provider);
  chain._ethers = {
    Contract: class {
      async channelStatus() { return 1n; }
      async closeRequestGeneration() { return 7n; }

      async getPendingClose() {
        provider.blocks.set(10, {
          number: 10,
          hash: hash(8_888),
          parentHash: hash(8_887),
          timestamp: 1_010,
        });
        return {
          active: true,
          closeIntentDigest: hash(123),
          finalEpoch: 4n,
          finalStateVersion: 9n,
          challengeDeadline: 1_100n,
          closeFreezeNonce: 3n,
        };
      }
    },
  };

  await assert.rejects(
    () => chain.getDurableCloseState(ROLLUP, original),
    error => error instanceof ChainSafetyError
      && error.code === 'PROCESSED_CHECKPOINT_CHANGED_DURING_MANAGER_READ',
  );
});

test('sticky chain-safety halt refuses co-signer and delegate actions', async () => {
  const temp = tempStore('signing-halt');
  try {
    const store = new Store(temp.path);
    store.haltChainSafety(new ChainSafetyError(
      'FINALIZED_CHECKPOINT_MISMATCH',
      'saved finalized block changed',
    ));
    let invoked = 0;
    const quietLog = { debug() {}, info() {}, warn() {}, error() {} };
    const cosigner = makeCosignerRuntime(
      { id: 7 },
      {
        cli: { async run() { invoked += 1; } },
        api: {},
        store,
        log: quietLog,
        alert: {},
        rpc: '',
        policyCfg: {},
      },
    );
    const refused = await cosigner.dispatch({ source: 'api', kind: 'cosign', body: {} });
    assert.equal(refused.status, 503);

    const delegate = makeDelegateRuntime(
      { id: 7, slot: 0 },
      { api: {}, wallet: {}, store, log: quietLog, alert: {}, policyCfg: {} },
    );
    await assert.rejects(
      delegate.dispatch({ source: 'api', kind: 'send' }),
      /chain safety halt/,
    );
    assert.equal(invoked, 0);
  } finally {
    temp.cleanup();
  }
});

test('co-signer never exposes HTTP before a complete initial finalized scan', async () => {
  let starts = 0;
  await assert.rejects(
    startAfterInitialChainPoll(async () => false, () => { starts += 1; }),
    error => error.code === 'CHAIN_STARTUP_UNAVAILABLE',
  );
  assert.equal(starts, 0);

  await startAfterInitialChainPoll(async () => true, () => { starts += 1; });
  assert.equal(starts, 1);
});

test('transient poll unavailability inhibits co-signer API signing and timer actions', async () => {
  const temp = tempStore('transient-readiness');
  try {
    const readiness = createChainReadiness();
    const store = new Store(temp.path);
    const quietLog = { debug() {}, info() {}, warn() {}, error() {} };
    let invoked = 0;
    const cosigner = makeCosignerRuntime(
      { id: 7 },
      {
        cli: { async run() { invoked += 1; } },
        api: {},
        store,
        log: quietLog,
        alert: {},
        rpc: '',
        policyCfg: {},
        isChainReady: () => readiness.isReady(),
      },
    );

    // Even after one success, beginning a later poll closes the action gate until that complete
    // scan succeeds. A generic RPC failure leaves it closed without creating a sticky halt.
    readiness.markReady();
    readiness.beginPoll();
    const duringPoll = await cosigner.dispatch({ source: 'api', kind: 'cosign', body: {} });
    assert.equal(duringPoll.status, 503);
    assert.equal(duringPoll.body.code, 'CHAIN_UNAVAILABLE');

    readiness.markUnavailable();
    const afterFailure = await cosigner.dispatch({ source: 'api', kind: 'cosign', body: {} });
    assert.equal(afterFailure.status, 503);
    await assert.rejects(
      cosigner.dispatch({ source: 'timer', kind: 'settle_due' }),
      error => error.code === 'CHAIN_UNAVAILABLE',
    );
    assert.equal(store.get('chainSafetyHalt'), null);
    assert.equal(invoked, 0);

    readiness.markReady();
    assert.equal(readiness.isReady(), true);
  } finally {
    temp.cleanup();
  }
});

test('three transient co-signer RPC failures alert without sticky halt, then recover signing', async () => {
  const temp = tempStore('transient-three-then-recover');
  const originalHandleCosign = cosignBranch.handleCosign;
  try {
    const readiness = createChainReadiness();
    const store = new Store(temp.path);
    const quietLog = { debug() {}, info() {}, warn() {}, error() {} };
    const entries = [{ ch: { id: 7 }, store }];
    const pollFailures = new Map();
    const alerts = [];
    const alerter = {
      async raise(level, channel, code) { alerts.push({ level, channel, code }); },
    };
    for (let attempt = 0; attempt < 3; attempt += 1) {
      readiness.beginPoll();
      await handleCosignerPollFailure(
        new ChainSafetyError('RPC_NETWORK_UNAVAILABLE', 'transport offline'),
        { entries, pollFailures, chainReadiness: readiness, logger: quietLog, alerter },
      );
    }
    assert.equal(readiness.isReady(), false);
    assert.equal(pollFailures.get(7), 3);
    assert.equal(store.get('chainSafetyHalt'), null);
    assert.deepEqual(alerts, [{ level: 'fault', channel: 7, code: 'CHAIN_WATCHER_WEDGED' }]);

    let signed = 0;
    cosignBranch.handleCosign = async () => {
      signed += 1;
      return { ok: true, status: 200, body: { signed: true } };
    };
    const cosigner = makeCosignerRuntime(
      { id: 7 },
      {
        cli: {}, api: {}, store, log: quietLog, alert: {}, rpc: '', policyCfg: {},
        isChainReady: () => readiness.isReady(),
      },
    );
    const gated = await cosigner.dispatch({ source: 'api', kind: 'cosign', body: {} });
    assert.equal(gated.status, 503);
    assert.equal(signed, 0);

    markCosignerPollSuccess(entries, pollFailures, readiness);
    assert.equal(readiness.isReady(), true);
    assert.equal(pollFailures.get(7), 0);
    const resumed = await cosigner.dispatch({ source: 'api', kind: 'cosign', body: {} });
    assert.equal(resumed.status, 200);
    assert.equal(signed, 1);
  } finally {
    cosignBranch.handleCosign = originalHandleCosign;
    temp.cleanup();
  }
});

test('a surviving co-signer halt is propagated to every channel store after restart', () => {
  const firstTemp = tempStore('halt-propagation-first');
  const secondTemp = tempStore('halt-propagation-second');
  try {
    const first = new Store(firstTemp.path);
    const second = new Store(secondTemp.path);
    first.haltChainSafety(new ChainSafetyError(
      'FINALIZED_CHECKPOINT_MISMATCH',
      'saved finalized block changed',
      { number: 10 },
    ));
    const halt = propagateExistingChainSafetyHalt([{ store: first }, { store: second }]);
    assert.equal(halt.code, 'FINALIZED_CHECKPOINT_MISMATCH');
    assert.equal(second.get('chainSafetyHalt').code, 'FINALIZED_CHECKPOINT_MISMATCH');

    const reopened = new Store(secondTemp.path);
    assert.equal(reopened.get('chainSafetyHalt').evidence.number, 10);
  } finally {
    firstTemp.cleanup();
    secondTemp.cleanup();
  }
});

// Store owns no open descriptor after synchronous writes; this helper documents intentional
// lifetime boundaries in restart tests and avoids relying on implementation-specific GC timing.
function dropStore(_store) {}
