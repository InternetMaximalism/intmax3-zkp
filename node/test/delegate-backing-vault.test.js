'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { BackingVault, validateBackingEnvelope } = require('../delegate/backing-vault');
const { makePublicBackingVerifier } = require('../delegate/public-backing-verifier');
const { responseText } = require('../common/api-client');
const { importAndVerify, importPublishedState } = require('../delegate/branches/sync');
const { SnapshotVault } = require('../delegate/snapshot-vault');

const DIGEST = `0x${'11'.repeat(32)}`;
const CHAIN = `0x${'22'.repeat(32)}`;
const PK0 = `0x${'33'.repeat(32)}`;
const PK1 = `0x${'44'.repeat(32)}`;
const RECIPIENT0 = `0x${'55'.repeat(20)}`;
const RECIPIENT1 = `0x${'66'.repeat(20)}`;
const ROLLUP = `0x${'77'.repeat(20)}`;

function fixture(digest = DIGEST) {
  const record = {
    channelId: 7,
    memberCount: 1,
    delegateCount: 1,
    memberPkGs: [PK0, PK1],
  };
  const state = {
    channelId: 7,
    epoch: 4,
    digest,
    memberSignatures: [{ memberSlot: 0, signature: [1] }],
    channelFund: { channelId: 7, amounts: ['9', '0'] },
    balanceState: {
      channelId: 7,
      memberCount: 1,
      delegateCount: 1,
      recipients: [RECIPIENT0, RECIPIENT1],
      stateVersion: 8,
      settledTxChain: CHAIN,
    },
  };
  const snapshot = { record, state, members: [] };
  const backing = {
    schemaVersion: 2,
    source: 'liveBalanceService',
    chainId: 31337,
    rollup: ROLLUP,
    baseHead: {
      snapshotVersion: 3,
      channelId: 7,
      settledTxChain: CHAIN,
      signedHeadDigest: digest,
      awaitingChannelBinding: false,
      proofSize: 3,
    },
    balanceAttestation: { balanceProof: [1, 2, 3] },
    balanceVerifierData: [4, 5, 6, 7],
    channelRecord: structuredClone(record),
    signedHead: structuredClone(state),
  };
  return { snapshot, backing };
}

function receiptFor(backing) {
  return {
    schemaVersion: 1,
    chainId: backing.chainId,
    rollup: backing.rollup,
    channelId: backing.signedHead.channelId,
    signedHeadDigest: backing.signedHead.digest,
    balanceVerifierDataSha256: `0x${crypto.createHash('sha256')
      .update(Buffer.from(backing.balanceVerifierData)).digest('hex')}`,
    balanceProofBytes: backing.balanceAttestation.balanceProof.length,
    selfVerified: true,
  };
}

function quietLog() {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

function memoryStore(order = []) {
  const state = {};
  return {
    state,
    get(key) { return state[key]; },
    set(key, value) { order.push(`store:${key}`); state[key] = value; return value; },
  };
}

test('backing HTTP body is rejected while streaming before an unbounded allocation', async () => {
  assert.equal(await responseText(new Response('1234'), 4), '1234');
  await assert.rejects(responseText(new Response('12345'), 4), /4-byte safety limit/);
});

test('BackingVault validates, size-bounds and immutably archives each exact signed head', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-backing-vault-'));
  try {
    const { snapshot, backing } = fixture();
    const vault = new BackingVault(directory, 7, { chainId: 31337, rollup: ROLLUP });
    const file = vault.save(backing, snapshot, receiptFor(backing));
    assert.equal(path.basename(file), `${DIGEST.slice(2)}.json`);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.deepEqual(vault.load(DIGEST, snapshot), backing);

    // Idempotent exact replay is accepted, while a second blob under the same signed-head key can
    // never replace the first immutable recovery artifact.
    assert.equal(vault.save(
      structuredClone(backing),
      structuredClone(snapshot),
      receiptFor(backing),
    ), file);
    const different = structuredClone(backing);
    different.balanceAttestation.balanceProof = [8, 9, 10];
    assert.throws(
      () => vault.save(different, snapshot, receiptFor(different)),
      /refusing to overwrite different backing/,
    );
    assert.deepEqual(vault.load(DIGEST, snapshot), backing);

    const second = fixture(`0x${'88'.repeat(32)}`);
    const secondFile = vault.save(second.backing, second.snapshot, receiptFor(second.backing));
    assert.notEqual(secondFile, file);
    assert.equal(fs.existsSync(file), true, 'new head must not remove/replace an older head');

    const tiny = new BackingVault(directory, 7, { chainId: 31337, rollup: ROLLUP }, { maximumBytes: 64 });
    assert.throws(() => tiny.save(backing, snapshot, receiptFor(backing)), /above the 64-byte limit/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('backing validation binds chain, rollup, exact signed state/record and settled chain', () => {
  const { snapshot, backing } = fixture();
  const authority = { channelId: 7, chainId: 31337, rollup: ROLLUP };
  assert.equal(validateBackingEnvelope(backing, snapshot, authority).digest, DIGEST);
  for (const [name, mutate, pattern] of [
    ['chain', (x) => { x.chainId = 1; }, /chainId differs/],
    ['rollup', (x) => { x.rollup = `0x${'99'.repeat(20)}`; }, /rollup differs/],
    ['head', (x) => { x.signedHead.digest = `0x${'aa'.repeat(32)}`; }, /exact accepted signed-head/],
    ['base digest', (x) => { x.baseHead.signedHeadDigest = `0x${'bb'.repeat(32)}`; }, /exact accepted signed-head/],
    ['settled chain', (x) => { x.baseHead.settledTxChain = `0x${'cc'.repeat(32)}`; }, /settled chain differs/],
    ['record', (x) => { x.channelRecord.memberCount = 2; }, /signed head\/record differs/],
    ['unbound', (x) => { x.baseHead.awaitingChannelBinding = true; }, /awaiting N-of-N/],
  ]) {
    const bad = structuredClone(backing);
    mutate(bad);
    assert.throws(() => validateBackingEnvelope(bad, snapshot, authority), pattern, name);
  }
});

test('production archive requires and enforces an independent balance verifier-data pin', () => {
  const { snapshot, backing } = fixture();
  assert.throws(
    () => validateBackingEnvelope(backing, snapshot, { channelId: 7, chainId: 1, rollup: ROLLUP }),
    /requires balanceVerifierDataSha256/,
  );
  const pin = `0x${crypto.createHash('sha256').update(Buffer.from(backing.balanceVerifierData)).digest('hex')}`;
  const production = structuredClone(backing);
  production.chainId = 1;
  assert.equal(validateBackingEnvelope(
    production,
    snapshot,
    { channelId: 7, chainId: 1, rollup: ROLLUP, balanceVerifierDataSha256: pin },
  ).verifierDataSha256, pin);
  assert.throws(
    () => validateBackingEnvelope(production, snapshot, {
      channelId: 7, chainId: 1, rollup: ROLLUP, balanceVerifierDataSha256: `0x${'00'.repeat(32)}`,
    }),
    /differs from the configured SHA-256 pin/,
  );
});

test('delegate archives exact backing and snapshot before advancing acceptedHead', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-backing-sync-'));
  try {
    const { snapshot, backing } = fixture();
    const order = [];
    const backingVault = new BackingVault(directory, 7, { chainId: 31337, rollup: ROLLUP });
    const backingCommit = backingVault.commit.bind(backingVault);
    backingVault.commit = staged => { order.push('backing'); return backingCommit(staged); };
    const snapshotVault = new SnapshotVault(directory, 7);
    const snapshotSave = snapshotVault.save.bind(snapshotVault);
    snapshotVault.save = value => { order.push('snapshot'); return snapshotSave(value); };
    const store = memoryStore(order);
    let verifiedInode = null;
    const wallet = {
      available: () => true,
      importChannel(value) { order.push('wasm'); assert.deepEqual(value, snapshot); },
      balance: () => ({ slot: 1, balance: '9', balances: [], canSend: true, witnessTokenSlot: 0 }),
    };
    const ctx = {
      api: { async getBacking() { order.push('fetch-backing'); return backing; } },
      wallet,
      ch: { id: 7 },
      slot: 1,
      recipient: RECIPIENT1,
      store,
      log: quietLog(),
      raiseSignal(value) { return value; },
      backingVault,
      backingVerifier: {
        async verify(file) {
          order.push('native-verify');
          verifiedInode = fs.statSync(file).ino;
          assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), backing);
          return receiptFor(backing);
        },
      },
      snapshotVault,
    };
    await importAndVerify({ snapshot }, ctx);
    assert.equal(store.state.acceptedHead.digest, DIGEST);
    assert.ok(order.indexOf('fetch-backing') < order.indexOf('wasm'));
    assert.ok(order.indexOf('fetch-backing') < order.indexOf('native-verify'));
    assert.ok(order.indexOf('native-verify') < order.indexOf('wasm'));
    assert.ok(order.indexOf('wasm') < order.indexOf('backing'));
    assert.ok(order.indexOf('backing') < order.indexOf('snapshot'));
    assert.ok(order.indexOf('snapshot') < order.indexOf('store:acceptedHead'));
    assert.deepEqual(backingVault.loadVerified(DIGEST, snapshot).backing, backing);
    assert.equal(fs.statSync(backingVault.fileFor(DIGEST)).ino, verifiedInode,
      'archive must hard-link the exact fsynced inode passed to the native verifier');
    assert.deepEqual(snapshotVault.load(DIGEST), snapshot);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('mismatched/withheld backing never advances or enters the WASM accepted session', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-backing-reject-'));
  try {
    const { snapshot, backing } = fixture();
    backing.baseHead.signedHeadDigest = `0x${'99'.repeat(32)}`;
    const store = memoryStore();
    let imported = false;
    await assert.rejects(importAndVerify({ snapshot }, {
      api: { async getBacking() { return backing; } },
      wallet: {
        available: () => true,
        importChannel() { imported = true; },
        balance: () => ({ slot: 1 }),
      },
      ch: { id: 7 }, slot: 1, recipient: RECIPIENT1, store, log: quietLog(),
      raiseSignal(value) { return value; },
      backingVault: new BackingVault(directory, 7, { chainId: 31337, rollup: ROLLUP }),
      backingVerifier: { async verify() { throw new Error('must not reach native verifier'); } },
      snapshotVault: new SnapshotVault(directory, 7),
    }), /exact accepted signed-head/);
    assert.equal(imported, false);
    assert.equal(store.state.acceptedHead, undefined);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('bare own-tx state is accepted only through its exact published snapshot', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-backing-own-tx-'));
  try {
    const { snapshot, backing } = fixture();
    const store = memoryStore();
    const ctx = {
      api: {
        async getSnapshot() { return snapshot; },
        async getBacking() { return backing; },
      },
      wallet: {
        available: () => true,
        importChannel() {},
        balance: () => ({ slot: 1, balance: '9', balances: [], canSend: true, witnessTokenSlot: 0 }),
      },
      ch: { id: 7 }, slot: 1, recipient: RECIPIENT1, store, log: quietLog(),
      raiseSignal(value) { return value; },
      backingVault: new BackingVault(directory, 7, { chainId: 31337, rollup: ROLLUP }),
      backingVerifier: { async verify() { return receiptFor(backing); } },
      snapshotVault: new SnapshotVault(directory, 7),
    };
    const changed = structuredClone(snapshot.state);
    changed.epoch += 1;
    await assert.rejects(importPublishedState(changed, ctx), /differs from the exact co-signed response/);
    assert.equal(store.state.acceptedHead, undefined);
    await importPublishedState(snapshot.state, ctx);
    assert.equal(store.state.acceptedHead.digest, DIGEST);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('native verifier failure leaves no published backing, metadata, WASM head, or acceptedHead', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-backing-native-reject-'));
  try {
    const { snapshot, backing } = fixture();
    const vault = new BackingVault(directory, 7, { chainId: 31337, rollup: ROLLUP });
    const store = memoryStore();
    let imported = false;
    await assert.rejects(importAndVerify({ snapshot }, {
      api: { async getBacking() { return backing; } },
      wallet: {
        available: () => true,
        importChannel() { imported = true; },
        balance: () => ({ slot: 1 }),
      },
      ch: { id: 7 }, slot: 1, recipient: RECIPIENT1, store, log: quietLog(),
      raiseSignal(value) { return value; },
      backingVault: vault,
      backingVerifier: { async verify() { throw new Error('invalid recursive proof'); } },
      snapshotVault: new SnapshotVault(directory, 7),
    }), /invalid recursive proof/);
    assert.equal(imported, false);
    assert.equal(store.state.acceptedHead, undefined);
    assert.equal(fs.existsSync(vault.fileFor(DIGEST)), false);
    assert.equal(fs.existsSync(vault.metadataFor(DIGEST)), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('archive refuses missing/substituted native receipts and persists an exact immutable marker', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-backing-receipt-'));
  try {
    const { snapshot, backing } = fixture();
    const vault = new BackingVault(directory, 7, { chainId: 31337, rollup: ROLLUP });
    let staged = vault.prepare(backing, snapshot);
    assert.throws(() => vault.commit(staged), /without native cryptographic verification/);
    vault.abort(staged);
    assert.equal(fs.existsSync(vault.fileFor(DIGEST)), false);

    staged = vault.prepare(backing, snapshot);
    const wrong = receiptFor(backing);
    wrong.signedHeadDigest = `0x${'99'.repeat(32)}`;
    assert.throws(
      () => vault.acceptVerification(staged, wrong),
      /differs from the canonical backing file/,
    );
    vault.abort(staged);
    assert.equal(fs.existsSync(vault.metadataFor(DIGEST)), false);

    const file = vault.save(backing, snapshot, receiptFor(backing));
    const archived = vault.loadVerified(DIGEST, snapshot);
    assert.deepEqual(archived.backing, backing);
    assert.equal(archived.verification.source, 'public_close_prover --verify-only');
    assert.equal(archived.verification.signedHeadDigest, DIGEST);
    assert.equal(archived.verification.settledTxChain, CHAIN);
    assert.equal(archived.verification.backingBytes, Buffer.byteLength(JSON.stringify(backing)));
    assert.equal(fs.statSync(vault.metadataFor(DIGEST)).mode & 0o777, 0o600);

    // Exact replay reuses the durable native receipt rather than re-verifying every poll.
    const replay = vault.prepare(structuredClone(backing), structuredClone(snapshot));
    assert.equal(vault.requiresVerification(replay), false);
    assert.equal(vault.commit(replay), file);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('public backing verifier passes only the staged file and independent authority to verify-only', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-backing-cli-'));
  try {
    const { snapshot, backing } = fixture();
    const vault = new BackingVault(directory, 7, { chainId: 31337, rollup: ROLLUP });
    const staged = vault.prepare(backing, snapshot);
    const input = vault.verificationInput(staged);
    let invocation;
    const verifier = makePublicBackingVerifier({
      binPath: process.execPath,
      repoRoot: directory,
      execFileImpl(binary, args, options, callback) {
        invocation = { binary, args, options };
        assert.deepEqual(JSON.parse(fs.readFileSync(args[1], 'utf8')), backing);
        callback(null, JSON.stringify(receiptFor(backing)), '');
      },
    });
    const receipt = await verifier.verify(input, vault.authority);
    assert.deepEqual(receipt, receiptFor(backing));
    assert.equal(invocation.binary, process.execPath);
    assert.deepEqual(invocation.args, [
      '--input', input,
      '--verify-only',
      '--expected-channel-id', '7',
      '--expected-chain-id', '31337',
      '--expected-rollup', ROLLUP,
    ]);
    assert.equal(invocation.options.maxBuffer, 64 * 1024);
    vault.abort(staged);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
