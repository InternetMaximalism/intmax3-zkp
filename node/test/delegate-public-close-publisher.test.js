'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  makePublicClosePublisher,
  parseProgress,
} = require('../delegate/public-close-publisher');

const ROLLUP = '0x1111111111111111111111111111111111111111';
const MANAGER = '0x2222222222222222222222222222222222222222';
const VD_PIN = `0x${'33'.repeat(32)}`;
const HEAD = `0x${'44'.repeat(32)}`;
const TX = `0x${'55'.repeat(32)}`;

function sha256(bytes) {
  return `0x${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function fixture(t, progress = { phase: 'submitBroadcast', transactionHash: TX }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-public-close-supervisor-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const prover = path.join(root, 'public_close_prover');
  const publisher = path.join(root, 'public_close_publisher');
  fs.writeFileSync(prover, '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  fs.writeFileSync(publisher, '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  const backing = path.join(root, 'backing.json');
  fs.writeFileSync(backing, '{}', { mode: 0o600 });
  const deployment = path.join(root, 'deployment.json');
  const deploymentBytes = Buffer.from(JSON.stringify({
    chainId: 31337,
    rollup: ROLLUP,
    manager: MANAGER,
    balanceVerifierDataSha256: VD_PIN,
  }));
  fs.writeFileSync(deployment, deploymentBytes, { mode: 0o600 });
  const calls = [];
  const execFileImpl = (binary, args, options, callback) => {
    calls.push({ binary, args: [...args], options: { ...options } });
    if (binary === prover) {
      const output = args[args.indexOf('--output-dir') + 1];
      fs.mkdirSync(output, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(output, 'public_close_manifest.json'), '{}', { mode: 0o600 });
      queueMicrotask(() => callback(null, '', ''));
    } else {
      queueMicrotask(() => callback(null, JSON.stringify(progress), ''));
    }
  };
  const options = {
    proverBinPath: prover,
    publisherBinPath: publisher,
    deploymentManifestPath: deployment,
    deploymentManifestSha256: sha256(deploymentBytes),
    signerLockRoot: path.join(root, 'shared-locks'),
    account: 'release-close-account',
    rpc: 'https://trusted-rpc.invalid',
    chainId: 31337,
    rollup: ROLLUP,
    manager: MANAGER,
    channelId: 7,
    balanceVerifierDataSha256: VD_PIN,
    workDir: path.join(root, 'work'),
    allowUnfinalizedDevnet: true,
    repoRoot: root,
    execFileImpl,
  };
  const snapshot = { state: { digest: HEAD } };
  const snapshotVault = { load: (digest) => digest === HEAD ? snapshot : null };
  const backingVault = {
    loadVerified: (digest, supplied) => digest === HEAD && supplied === snapshot
      ? { backing: {}, verification: {} }
      : null,
    fileFor: (digest) => {
      assert.equal(digest, HEAD);
      return backing;
    },
  };
  return {
    root,
    prover,
    publisher,
    deployment,
    calls,
    options,
    snapshotVault,
    backingVault,
  };
}

test('fixed startup authority drives proving/publication and restart reuses bundle and WAL path', async (t) => {
  const f = fixture(t);
  const first = makePublicClosePublisher(f.options);
  const result = await first.advance({
    acceptedHead: { digest: HEAD, rpc: 'https://attacker.invalid', manager: ROLLUP },
    snapshotVault: f.snapshotVault,
    backingVault: f.backingVault,
    rpc: 'https://attacker.invalid',
    manager: ROLLUP,
  });
  assert.deepEqual(result, { phase: 'submitBroadcast', transactionHash: TX });
  assert.equal(f.calls.length, 2);
  const prove = f.calls[0];
  assert.equal(prove.binary, f.prover);
  assert.equal(prove.args[prove.args.indexOf('--expected-chain-id') + 1], '31337');
  assert.equal(prove.args[prove.args.indexOf('--expected-channel-id') + 1], '7');
  assert.equal(prove.args[prove.args.indexOf('--expected-rollup') + 1], ROLLUP);
  assert.equal(prove.args[prove.args.indexOf('--expected-balance-vd-sha256') + 1], VD_PIN);
  const publish = f.calls[1];
  assert.equal(publish.binary, f.publisher);
  assert.equal(publish.args[publish.args.indexOf('--rpc-url') + 1], 'https://trusted-rpc.invalid');
  assert.equal(publish.args[publish.args.indexOf('--account') + 1], 'release-close-account');
  assert.equal(
    publish.args[publish.args.indexOf('--expected-final-channel-state-digest') + 1],
    HEAD,
    'the authenticated accepted head is passed as independent native bundle authority',
  );
  assert.equal(
    publish.args[publish.args.indexOf('--deployment-manifest-sha256') + 1],
    f.options.deploymentManifestSha256,
  );
  const journal = publish.args[publish.args.indexOf('--journal') + 1];

  const restarted = makePublicClosePublisher(f.options);
  await restarted.advance({
    acceptedHead: { digest: HEAD },
    snapshotVault: f.snapshotVault,
    backingVault: f.backingVault,
  });
  assert.equal(f.calls.length, 3, 'an existing committed bundle is never reproved on restart');
  const replay = f.calls[2];
  assert.equal(replay.binary, f.publisher);
  assert.equal(
    replay.args[replay.args.indexOf('--expected-final-channel-state-digest') + 1],
    HEAD,
  );
  assert.equal(replay.args[replay.args.indexOf('--journal') + 1], journal);
  assert.equal(replay.args[replay.args.indexOf('--bundle-dir') + 1],
    publish.args[publish.args.indexOf('--bundle-dir') + 1]);
});

test('manifest mutation after startup fails before either executable can run', async (t) => {
  const f = fixture(t);
  const publisher = makePublicClosePublisher(f.options);
  fs.writeFileSync(f.deployment, '{"chainId":1}', { mode: 0o600 });
  await assert.rejects(
    publisher.advance({
      acceptedHead: { digest: HEAD },
      snapshotVault: f.snapshotVault,
      backingVault: f.backingVault,
    }),
    /deployment manifest changed after startup/,
  );
  assert.equal(f.calls.length, 0);
});

test('verified backing and authenticated snapshot are mandatory', async (t) => {
  const f = fixture(t);
  const publisher = makePublicClosePublisher(f.options);
  await assert.rejects(
    publisher.advance({
      acceptedHead: { digest: HEAD },
      snapshotVault: { load: () => null },
      backingVault: f.backingVault,
    }),
    /authenticated snapshot .* unavailable/,
  );
  await assert.rejects(
    publisher.advance({
      acceptedHead: { digest: HEAD },
      snapshotVault: f.snapshotVault,
      backingVault: { ...f.backingVault, loadVerified: () => null },
    }),
    /verified public backing .* unavailable/,
  );
  assert.equal(f.calls.length, 0);
});

test('publisher progress parser is exact, lower-camel, bounded, and secret-free', () => {
  assert.deepEqual(parseProgress(JSON.stringify({ phase: 'awaitingCloseRequest' })), {
    phase: 'awaitingCloseRequest',
  });
  assert.throws(
    () => parseProgress(JSON.stringify({ phase: 'AwaitingCloseRequest' })),
    /unknown progress phase/,
  );
  assert.throws(
    () => parseProgress(JSON.stringify({
      phase: 'submitBroadcast', transactionHash: TX, rawSignedTransaction: 'secret',
    })),
    /unexpected schema/,
  );
  assert.throws(() => parseProgress('{'), /malformed JSON/);
});
