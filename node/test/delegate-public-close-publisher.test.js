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
  parseReadiness,
} = require('../delegate/public-close-publisher');

const ROLLUP = '0x1111111111111111111111111111111111111111';
const MANAGER = '0x2222222222222222222222222222222222222222';
const MATERIALIZER = '0x6666666666666666666666666666666666666666';
const VD_PIN = `0x${'33'.repeat(32)}`;
const HEAD = `0x${'44'.repeat(32)}`;
const TX = `0x${'55'.repeat(32)}`;

function sha256(bytes) {
  return `0x${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function fixture(t, progress = { phase: 'submitBroadcast', transaction_hash: TX }, readinessReceipt = readiness()) {
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
    closeFundingMaterializer: MATERIALIZER,
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
      const output = args.includes('--check-readiness') ? readinessReceipt : progress;
      queueMicrotask(() => callback(null, JSON.stringify(output), ''));
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
    readinessReceipt,
  };
}

test('fixed startup authority drives proving/publication and restart reuses bundle and WAL path', async (t) => {
  const f = fixture(t);
  const first = makePublicClosePublisher(f.options);
  assert.equal(first.authority.materializer, MATERIALIZER);
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

test('publisher progress parser is exact, bounded, and secret-free', () => {
  assert.deepEqual(parseProgress(JSON.stringify({ phase: 'awaitingCloseRequest' })), {
    phase: 'awaitingCloseRequest',
  });
  assert.throws(
    () => parseProgress(JSON.stringify({ phase: 'AwaitingCloseRequest' })),
    /unknown progress phase/,
  );
  assert.throws(
    () => parseProgress(JSON.stringify({
      phase: 'submitBroadcast', transaction_hash: TX, rawSignedTransaction: 'secret',
    })),
    /unexpected schema/,
  );
  assert.throws(() => parseProgress('{'), /malformed JSON/);
  assert.throws(() => parseProgress(' '.repeat(1024 * 1024 + 1)), /oversized/);
});

function publication(overrides = {}) {
  return {
    schemaVersion: 3,
    chainId: 31337,
    channelId: 7,
    rollup: ROLLUP,
    manager: MANAGER,
    materializer: MATERIALIZER,
    closeIntentDigest: HEAD,
    artifactHash: VD_PIN,
    attestTransactionHash: TX,
    submitTransactionHash: TX,
    finalizeTransactionHash: TX,
    materializeTransactionHash: TX,
    finalizedCheckpoint: {
      chainId: 31337, blockNumber: 12, blockHash: HEAD, parentHash: TX, source: 'devnetLatest',
    },
    ...overrides,
  };
}

function readiness(overrides = {}) {
  return {
    schemaVersion: 1,
    ready: true,
    chainId: 31337,
    rollup: ROLLUP,
    manager: MANAGER,
    materializer: MATERIALIZER,
    channelId: 7,
    signedHeadDigest: HEAD,
    backingFinalizedExtendedStateCommitment: VD_PIN,
    backingAnchorBlockNumber: 0,
    currentCloseFreezeNonce: 0,
    closeRequestGeneration: 0,
    finalizedCheckpoint: publication().finalizedCheckpoint,
    ...overrides,
  };
}

test('every native transaction and finality phase normalizes snake_case fields', () => {
  const transactionPhases = [
    'attestBroadcast', 'attestAdopted', 'awaitingAttestReceipt',
    'submitBroadcast', 'submitAdopted', 'awaitingSubmitReceipt',
    'finalizeBroadcast', 'awaitingFinalizeReceipt',
    'materializeBroadcast', 'materializeAdopted', 'awaitingMaterializeReceipt',
  ];
  for (const phase of transactionPhases) {
    assert.deepEqual(parseProgress(JSON.stringify({ phase, transaction_hash: TX })), {
      phase, transactionHash: TX,
    });
    assert.throws(() => parseProgress(JSON.stringify({ phase, transactionHash: TX })), /unexpected schema/);
    assert.throws(() => parseProgress(JSON.stringify({ phase, transaction_hash: TX, transactionHash: TX })), /unexpected schema/);
  }
  for (const phase of [
    'awaitingAttestFinality', 'awaitingSubmitFinality',
    'awaitingFinalizeFinality', 'awaitingMaterializeFinality',
  ]) {
    assert.deepEqual(parseProgress(JSON.stringify({ phase, transaction_hash: TX, receipt_block: 12 })), {
      phase, transactionHash: TX, receiptBlock: 12,
    });
    assert.throws(() => parseProgress(JSON.stringify({ phase, transaction_hash: TX, receiptBlock: 12 })), /unexpected schema/);
    assert.throws(() => parseProgress(JSON.stringify({ phase, transaction_hash: TX })), /unexpected schema/);
  }
});

test('native deadline phases use exact snake_case numeric fields', () => {
  assert.deepEqual(parseProgress(JSON.stringify({ phase: 'awaitingGrace', eligible_at: 20, durable_time: 0 })), {
    phase: 'awaitingGrace', eligibleAt: 20, durableTime: 0,
  });
  assert.deepEqual(parseProgress(JSON.stringify({ phase: 'awaitingChallengeDeadline', challenge_deadline: 20, durable_time: 12 })), {
    phase: 'awaitingChallengeDeadline', challengeDeadline: 20, durableTime: 12,
  });
  for (const invalid of ['12', null, true, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => parseProgress(JSON.stringify({
      phase: 'awaitingGrace', eligible_at: 20, durable_time: invalid,
    })), /exact safe integer/);
    assert.throws(() => parseProgress(JSON.stringify({
      phase: 'awaitingMaterializeFinality', transaction_hash: TX, receipt_block: invalid,
    })), /exact safe integer/);
  }
  assert.throws(() => parseProgress(JSON.stringify({ phase: 'awaitingGrace', eligibleAt: 20, durableTime: 12 })), /unexpected schema/);
  assert.throws(() => parseProgress(JSON.stringify({ phase: 'awaitingChallengeDeadline', challengeDeadline: 20, durableTime: 12 })), /unexpected schema/);
});

test('superseded phases accept only the four native local steps and exact fields', () => {
  for (const phase of ['awaitingSupersededReceipt', 'awaitingSupersededFinality']) {
    for (const localStep of ['attest', 'submit', 'finalize', 'materialize']) {
      const finality = phase === 'awaitingSupersededFinality';
      const native = { phase, local_step: localStep, transaction_hash: TX,
        ...(finality ? { receipt_block: 12 } : {}) };
      assert.deepEqual(parseProgress(JSON.stringify(native)), {
        phase, localStep, transactionHash: TX, ...(finality ? { receiptBlock: 12 } : {}),
      });
      assert.throws(() => parseProgress(JSON.stringify({ ...native, localStep })), /unexpected schema/);
      for (const invalid of ['close', 'Attest', '', null, 0]) {
        assert.throws(() => parseProgress(JSON.stringify({ ...native, local_step: invalid })), /unknown superseded local step/);
      }
    }
  }
});

test('schema-3 completion preserves required and nullable transaction hashes', () => {
  for (const submitTransactionHash of [TX, null]) {
    for (const finalizeTransactionHash of [TX, null]) {
      const complete = { phase: 'complete', publication: publication({ submitTransactionHash, finalizeTransactionHash }) };
      assert.deepEqual(parseProgress(JSON.stringify(complete)), complete);
    }
  }
  for (const schemaVersion of [1, 2, 4, '3']) {
    assert.throws(() => parseProgress(JSON.stringify({ phase: 'complete', publication: publication({ schemaVersion }) })), /schema version is unsupported/);
  }
  for (const name of ['attestTransactionHash', 'submitTransactionHash', 'finalizeTransactionHash', 'materializeTransactionHash']) {
    const missing = publication();
    delete missing[name];
    assert.throws(() => parseProgress(JSON.stringify({ phase: 'complete', publication: missing })), /unexpected schema/);
    for (const invalid of ['', `0x${'00'.repeat(32)}`, [TX]]) {
      assert.throws(() => parseProgress(JSON.stringify({ phase: 'complete', publication: publication({ [name]: invalid }) })), /bytes32|nonzero/);
    }
  }
  for (const name of ['attestTransactionHash', 'materializeTransactionHash']) {
    assert.throws(() => parseProgress(JSON.stringify({ phase: 'complete', publication: publication({ [name]: null }) })), /bytes32/);
  }
  assert.throws(() => parseProgress(JSON.stringify({ phase: 'complete', publication: {
    ...publication(), materialize_transaction_hash: TX,
  } })), /unexpected schema/);
});

test('completed publication is bound to every startup authority including the pinned materializer', async (t) => {
  const complete = { phase: 'complete', publication: publication({ submitTransactionHash: null, finalizeTransactionHash: null }) };
  const f = fixture(t, complete);
  const publisher = makePublicClosePublisher(f.options);
  const request = { acceptedHead: { digest: HEAD }, snapshotVault: f.snapshotVault, backingVault: f.backingVault };
  assert.deepEqual(await publisher.advance(request), complete);
  for (const [key, value] of Object.entries({ chainId: 1, channelId: 8, rollup: MANAGER, manager: ROLLUP, materializer: MANAGER })) {
    complete.publication = publication({ [key]: value,
      finalizedCheckpoint: { ...publication().finalizedCheckpoint, source: 'rpcFinalized', chainId: key === 'chainId' ? value : 31337 } });
    await assert.rejects(publisher.advance(request), /differs from startup channel authority/);
  }
});

test('startup requires a valid materializer in the SHA-pinned manifest', (t) => {
  const f = fixture(t);
  const deployment = JSON.parse(fs.readFileSync(f.deployment, 'utf8'));
  for (const materializer of [undefined, null, '0x0000000000000000000000000000000000000000', [MATERIALIZER]]) {
    const bytes = Buffer.from(JSON.stringify({ ...deployment, closeFundingMaterializer: materializer }));
    fs.writeFileSync(f.deployment, bytes);
    assert.throws(() => makePublicClosePublisher({ ...f.options, deploymentManifestSha256: sha256(bytes) }), /deployment close-funding materializer/);
  }
  assert.equal(f.calls.length, 0);
});

test('readiness is read-only and repeated checks plus publication reuse the authenticated bundle', async (t) => {
  const f = fixture(t);
  const publisher = makePublicClosePublisher(f.options);
  const request = { acceptedHead: { digest: HEAD }, snapshotVault: f.snapshotVault, backingVault: f.backingVault };
  assert.deepEqual(await publisher.checkReadiness(request), f.readinessReceipt);
  const firstCheck = f.calls[1];
  assert.equal(firstCheck.binary, f.publisher);
  assert.ok(firstCheck.args.includes('--check-readiness'));
  for (const option of ['--account', '--journal', '--signer-lock-root']) {
    assert.equal(firstCheck.args.includes(option), false, `${option} must never enter readiness mode`);
  }
  for (const [option, expected] of [
    ['--expected-final-channel-state-digest', HEAD],
    ['--deployment-manifest', f.deployment],
    ['--deployment-manifest-sha256', f.options.deploymentManifestSha256],
    ['--rpc-url', f.options.rpc],
  ]) assert.equal(firstCheck.args[firstCheck.args.indexOf(option) + 1], expected);
  assert.equal(fs.existsSync(path.join(f.options.workDir, 'public-close-publication', '7', 'journals')), false);
  await publisher.checkReadiness(request);
  await publisher.advance(request);
  assert.equal(f.calls.filter(call => call.binary === f.prover).length, 1);
  assert.equal(f.calls.length, 4);
  const bundle = firstCheck.args[firstCheck.args.indexOf('--bundle-dir') + 1];
  for (const call of f.calls.slice(1)) assert.equal(call.args[call.args.indexOf('--bundle-dir') + 1], bundle);
  assert.equal(f.calls[3].args.includes('--check-readiness'), false);
  assert.ok(f.calls[3].args.includes('--journal'));
});

test('readiness errors cannot fall through to publication', async (t) => {
  const f = fixture(t);
  const invoke = f.options.execFileImpl;
  let attempted = null;
  f.options.execFileImpl = (binary, args, options, callback) => {
    if (args.includes('--check-readiness')) {
      attempted = [...args];
      queueMicrotask(() => callback(new Error('backing anchor is not ready'), '', 'backing anchor is not ready'));
      return;
    }
    invoke(binary, args, options, callback);
  };
  const publisher = makePublicClosePublisher(f.options);
  await assert.rejects(publisher.checkReadiness({
    acceptedHead: { digest: HEAD }, snapshotVault: f.snapshotVault, backingVault: f.backingVault,
  }), /readiness check failed.*backing anchor is not ready/);
  assert.ok(attempted.includes('--check-readiness'));
  assert.equal(attempted.includes('--account'), false);
  assert.equal(f.calls.length, 1, 'only proof generation ran before the refused read-only check');
});

test('readiness receipt binds the exact head and every startup authority', async (t) => {
  const f = fixture(t);
  const publisher = makePublicClosePublisher(f.options);
  const request = { acceptedHead: { digest: HEAD }, snapshotVault: f.snapshotVault, backingVault: f.backingVault };
  for (const [key, value] of Object.entries({ chainId: 1, channelId: 8, rollup: MANAGER, manager: ROLLUP, materializer: MANAGER })) {
    Object.assign(f.readinessReceipt, readiness({ [key]: value,
      finalizedCheckpoint: { ...readiness().finalizedCheckpoint, source: 'rpcFinalized', chainId: key === 'chainId' ? value : 31337 } }));
    await assert.rejects(publisher.checkReadiness(request), /differs from startup channel authority/);
  }
  Object.assign(f.readinessReceipt, readiness({ signedHeadDigest: TX }));
  await assert.rejects(publisher.checkReadiness(request), /differs from the authenticated accepted head/);
  Object.assign(f.readinessReceipt, readiness());
  const finalizedOnly = makePublicClosePublisher({ ...f.options, allowUnfinalizedDevnet: false });
  await assert.rejects(finalizedOnly.checkReadiness(request), /unconfigured devnet finality/);
  f.readinessReceipt.finalizedCheckpoint.source = 'rpcFinalized';
  assert.deepEqual(await finalizedOnly.checkReadiness(request), f.readinessReceipt);
});

test('readiness retains deployment-pin and immutable-vault requirements', async (t) => {
  const f = fixture(t);
  const publisher = makePublicClosePublisher(f.options);
  const request = { acceptedHead: { digest: HEAD }, snapshotVault: f.snapshotVault, backingVault: f.backingVault };
  await assert.rejects(publisher.checkReadiness({ ...request, snapshotVault: { load: () => null } }), /authenticated snapshot .* unavailable/);
  await assert.rejects(publisher.checkReadiness({ ...request, backingVault: { loadVerified: () => null } }), /verified public backing .* unavailable/);
  assert.equal(f.calls.length, 0);
  await publisher.checkReadiness(request);
  fs.writeFileSync(f.deployment, '{"chainId":1}');
  await assert.rejects(publisher.checkReadiness(request), /deployment manifest changed after startup/);
  await assert.rejects(publisher.advance(request), /deployment manifest changed after startup/);
  assert.equal(f.calls.length, 2);
});

test('readiness requires the exact native schema and safe numeric receipt values', () => {
  assert.deepEqual(parseReadiness(JSON.stringify(readiness())), readiness());
  const genesis = readiness({ finalizedCheckpoint: {
    ...readiness().finalizedCheckpoint, blockNumber: 0, parentHash: `0x${'00'.repeat(32)}`,
  } });
  assert.deepEqual(parseReadiness(JSON.stringify(genesis)), genesis);
  assert.throws(() => parseReadiness(JSON.stringify(readiness({ chainId: 1,
    finalizedCheckpoint: { ...readiness().finalizedCheckpoint, chainId: 1 },
  }))), /devnet checkpoint requires chain 31337/);
  for (const key of Object.keys(readiness())) {
    const missing = readiness();
    delete missing[key];
    assert.throws(() => parseReadiness(JSON.stringify(missing)), /unexpected schema/);
  }
  for (const invalid of [{ schemaVersion: 2 }, { schemaVersion: '1' }, { ready: false }, { ready: 'true' }]) {
    assert.throws(() => parseReadiness(JSON.stringify(readiness(invalid))), /schema or ready status is unsupported/);
  }
  for (const key of ['backingAnchorBlockNumber', 'currentCloseFreezeNonce', 'closeRequestGeneration']) {
    for (const invalid of ['0', null, true, -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => parseReadiness(JSON.stringify(readiness({ [key]: invalid }))), /exact safe integer/);
    }
  }
  assert.throws(() => parseReadiness(JSON.stringify({ ...readiness(), signed_head_digest: HEAD })), /unexpected schema/);
  assert.throws(() => parseReadiness(JSON.stringify(readiness({
    finalizedCheckpoint: { ...readiness().finalizedCheckpoint, chainId: 1 },
  }))), /different chain/);
  assert.throws(() => parseReadiness(JSON.stringify(readiness({
    finalizedCheckpoint: { ...readiness().finalizedCheckpoint, source: 'latest' },
  }))), /unknown finality source/);
  assert.throws(() => parseReadiness(JSON.stringify(readiness({ materializer: [MATERIALIZER] }))), /nonzero canonical address/);
  assert.throws(() => parseReadiness('{'), /malformed readiness JSON/);
  assert.throws(() => parseReadiness(' '.repeat(1024 * 1024 + 1)), /oversized/);
});
