'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Store } = require('../common/store');
const { handleInterChannel } = require('../cosigner/branches/cosign');

test('one live base nonce can be durably reserved by exactly one outgoing request', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-nonce-reservation-'));
  const file = path.join(dir, 'state.json');
  try {
    const first = new Store(file);
    assert.equal(first.reserveOutgoingBaseNonce(7, 'request-a'), true);
    assert.equal(first.reserveOutgoingBaseNonce(7, 'request-b'), false);

    // Restarting the process does not reopen the nonce.
    const restarted = new Store(file);
    assert.equal(restarted.reserveOutgoingBaseNonce(7, 'request-b'), false);
    assert.equal(restarted.reserveOutgoingBaseNonce(6, 'request-b'), false);

    // The authoritative head advancing is the only normal release/fencing event.
    assert.equal(restarted.reserveOutgoingBaseNonce(8, 'request-b'), true);
    assert.deepEqual(restarted.get('outgoingBaseNonceReservation').nonce, 8);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('two Store instances loaded before either write cannot reserve the same nonce', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-nonce-multiprocess-'));
  const file = path.join(dir, 'state.json');
  try {
    // This is the stale-memory interleaving produced by two independently started node processes:
    // both load an empty JSON document before either reaches the reservation critical section.
    const first = new Store(file);
    const second = new Store(file);
    assert.equal(first.reserveOutgoingBaseNonce(9, 'request-a'), true);
    assert.equal(second.reserveOutgoingBaseNonce(9, 'request-b'), false);
    assert.equal(second.get('outgoingBaseNonceReservation').actionId, 'request-a');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('two stale Store instances cannot overwrite each other\'s general journal mutations', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-store-multiprocess-'));
  const file = path.join(dir, 'state.json');
  try {
    const first = new Store(file);
    const stale = new Store(file);
    assert.equal(first.claimAction('chain-event-a'), true);
    assert.throws(
      () => stale.claimAction('chain-event-b'),
      error => error && error.code === 'STORE_CONCURRENT_MODIFICATION',
    );

    const durable = new Store(file);
    assert.equal(durable.hasAction('chain-event-a'), true, 'winning action survives');
    assert.equal(durable.hasAction('chain-event-b'), false, 'stale full-snapshot rename never lands');
    assert.equal(stale.hasAction('chain-event-a'), true, 'loser reloads the durable winner before failing');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a pre-sign failure releases only its exact reservation', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-nonce-release-'));
  const file = path.join(dir, 'state.json');
  try {
    const store = new Store(file);
    assert.equal(store.reserveOutgoingBaseNonce(3, 'request-a'), true);
    assert.equal(store.releaseOutgoingBaseNonce(3, 'request-b'), false);
    assert.equal(store.releaseOutgoingBaseNonce(4, 'request-a'), false);
    assert.equal(store.releaseOutgoingBaseNonce(3, 'request-a'), true);
    assert.equal(store.reserveOutgoingBaseNonce(3, 'request-b'), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('two different requests at one live nonce produce exactly one co-sign', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-nonce-concurrency-'));
  try {
    const store = new Store(path.join(dir, 'state.json'));
    let runs = 0;
    const ctx = {
      store,
      ch: { id: 7, workDir: dir },
      api: { getBaseHead: async () => ({ nonce: 11 }) },
      log: { warn() {}, info() {}, debug() {} },
      cli: {
        writeJson() {},
        async run() { runs += 1; },
        readJson() { return { aHead: { digest: 'signed' } }; },
      },
    };
    const event = (txHash) => ({
      body: {
        debitPayload: { txHash },
        transferDescriptor: { txHash },
      },
    });
    const results = await Promise.all([
      handleInterChannel(event('0x' + 'aa'.repeat(32)), ctx),
      handleInterChannel(event('0x' + 'bb'.repeat(32)), ctx),
    ]);
    assert.equal(results.filter(r => r.status === 200).length, 1);
    assert.equal(results.filter(r => r.status === 409).length, 1);
    assert.equal(runs, 1, 'the fenced request must not reach the signing CLI');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('live-head failure never reaches the co-sign CLI', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-nonce-hard-fail-'));
  try {
    const store = new Store(path.join(dir, 'state.json'));
    let runs = 0;
    const result = await handleInterChannel({
      body: { debitPayload: {}, transferDescriptor: { txHash: '0x' + 'aa'.repeat(32) } },
    }, {
      store,
      ch: { id: 7, workDir: dir },
      api: { getBaseHead: async () => { throw new Error('offline'); } },
      log: { warn() {}, info() {}, debug() {} },
      cli: { writeJson() {}, async run() { runs += 1; }, readJson() { return {}; } },
    });
    assert.equal(result.status, 500);
    assert.match(result.body.error, /refusing to co-sign/);
    assert.equal(runs, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('an ambiguous child failure keeps the nonce fenced after invocation starts', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-nonce-child-failure-'));
  try {
    const store = new Store(path.join(dir, 'state.json'));
    let runs = 0;
    const ctx = {
      store,
      ch: { id: 7, workDir: dir },
      api: { getBaseHead: async () => ({ nonce: 12 }) },
      log: { warn() {}, info() {}, debug() {} },
      cli: {
        writeJson() {},
        async run() { runs += 1; throw new Error('child killed after an unknown commit point'); },
        readJson() { return {}; },
      },
    };
    const event = hash => ({
      body: { debitPayload: { hash }, transferDescriptor: { txHash: hash } },
    });
    const failed = await handleInterChannel(event('0x' + 'aa'.repeat(32)), ctx);
    assert.equal(failed.status, 500);
    assert.equal(store.get('outgoingBaseNonceReservation').nonce, 12);

    const fenced = await handleInterChannel(event('0x' + 'bb'.repeat(32)), ctx);
    assert.equal(fenced.status, 409);
    assert.equal(runs, 1, 'the ambiguous first invocation must fence every peer at that nonce');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
