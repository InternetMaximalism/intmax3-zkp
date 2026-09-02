'use strict';

// Durable delegate handoff into the native public-close prover/publisher. Every authority value is
// fixed when the daemon starts; recovery events supply only the already-accepted head digest.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_PUBLISHER_OUTPUT_BYTES = 1024 * 1024;
const DEFAULT_PROVE_TIMEOUT_MS = 60 * 60 * 1000;
const DEFAULT_PUBLISH_TIMEOUT_MS = 5 * 60 * 1000;
const PROGRESS_PHASES = new Set([
  'awaitingCloseRequest',
  'awaitingGrace',
  'submitBroadcast',
  'submitAdopted',
  'awaitingSubmitReceipt',
  'awaitingSubmitFinality',
  'awaitingChallengeDeadline',
  'finalizeBroadcast',
  'awaitingFinalizeReceipt',
  'awaitingFinalizeFinality',
  'complete',
]);

function canonicalAddress(value, label) {
  const normalized = String(value || '').toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized) || /^0x0{40}$/.test(normalized)) {
    throw new Error(`${label} must be a nonzero canonical address`);
  }
  return normalized;
}

function canonicalDigest(value, label) {
  const normalized = String(value || '').toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(normalized)) throw new Error(`${label} must be bytes32`);
  return normalized;
}

function canonicalNonzeroDigest(value, label) {
  const digest = canonicalDigest(value, label);
  if (/^0x0{64}$/.test(digest)) throw new Error(`${label} must be nonzero`);
  return digest;
}

function exactObject(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} has an unexpected schema`);
  }
  return value;
}

function positiveSafeInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > maximum) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return parsed;
}

function boundedTimeout(value, fallback, label, maximum) {
  const parsed = value == null ? fallback : positiveSafeInteger(value, label);
  if (parsed > maximum) throw new Error(`${label} exceeds ${maximum}ms`);
  return parsed;
}

function executable(value, fallback, repoRoot, label) {
  const configured = String(value || '').trim();
  const resolved = configured
    ? (path.isAbsolute(configured) ? configured : path.resolve(repoRoot, configured))
    : path.resolve(repoRoot, fallback);
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`${label} must be a regular non-symlink file: ${resolved}`);
  }
  fs.accessSync(resolved, fs.constants.X_OK);
  return resolved;
}

function regularFile(value, repoRoot, label, maximum) {
  const configured = String(value || '').trim();
  if (!configured) throw new Error(`${label} is required`);
  const resolved = path.isAbsolute(configured) ? configured : path.resolve(repoRoot, configured);
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0 || stat.size > maximum) {
    throw new Error(`${label} must be a nonempty regular file no larger than ${maximum} bytes`);
  }
  return { resolved, bytes: fs.readFileSync(resolved) };
}

function sha256(bytes) {
  return `0x${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function accountSelector(value) {
  const account = String(value || '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(account)) {
    throw new Error('public-close publisher account must be a Foundry keystore selector');
  }
  return account;
}

function rpcUrl(value) {
  const rpc = String(value || '').trim();
  if (!rpc || /[\u0000-\u001f]/.test(rpc)) throw new Error('public-close RPC URL is invalid');
  return rpc;
}

function run(execFileImpl, binary, args, options, label) {
  return new Promise((resolve, reject) => {
    execFileImpl(binary, args, options, (error, stdout, stderr) => {
      if (error) {
        const failure = new Error(`${label} failed: ${String(stderr || error.message || error).trim()}`);
        failure.code = 'PUBLIC_CLOSE_PUBLISH_FAILED';
        failure.cause = error;
        reject(failure);
        return;
      }
      resolve(String(stdout || ''));
    });
  });
}

function parseProgress(stdout) {
  const bytes = Buffer.from(String(stdout || ''), 'utf8');
  if (bytes.length === 0 || bytes.length > MAX_PUBLISHER_OUTPUT_BYTES) {
    throw new Error('public-close publisher returned empty or oversized progress output');
  }
  let progress;
  try { progress = JSON.parse(bytes.toString('utf8').trim()); }
  catch (error) { throw new Error(`public-close publisher returned malformed JSON: ${error.message}`); }
  if (!progress || typeof progress !== 'object' || Array.isArray(progress)
      || typeof progress.phase !== 'string' || !PROGRESS_PHASES.has(progress.phase)) {
    throw new Error('public-close publisher returned an unknown progress phase');
  }
  const transactionPhases = new Set([
    'submitBroadcast',
    'submitAdopted',
    'awaitingSubmitReceipt',
    'finalizeBroadcast',
    'awaitingFinalizeReceipt',
  ]);
  if (transactionPhases.has(progress.phase)) {
    exactObject(progress, ['phase', 'transactionHash'], 'public-close progress');
    return {
      phase: progress.phase,
      transactionHash: canonicalNonzeroDigest(progress.transactionHash, 'progress transaction hash'),
    };
  }
  if (progress.phase === 'awaitingSubmitFinality' || progress.phase === 'awaitingFinalizeFinality') {
    exactObject(progress, ['phase', 'receiptBlock', 'transactionHash'], 'public-close progress');
    return {
      phase: progress.phase,
      transactionHash: canonicalNonzeroDigest(progress.transactionHash, 'progress transaction hash'),
      receiptBlock: positiveSafeInteger(progress.receiptBlock, 'progress receipt block'),
    };
  }
  if (progress.phase === 'awaitingGrace') {
    exactObject(progress, ['durableTime', 'eligibleAt', 'phase'], 'public-close progress');
    return {
      phase: progress.phase,
      eligibleAt: positiveSafeInteger(progress.eligibleAt, 'progress close eligibility time'),
      durableTime: positiveSafeInteger(progress.durableTime, 'progress durable time'),
    };
  }
  if (progress.phase === 'awaitingChallengeDeadline') {
    exactObject(progress, ['challengeDeadline', 'durableTime', 'phase'], 'public-close progress');
    return {
      phase: progress.phase,
      challengeDeadline: positiveSafeInteger(
        progress.challengeDeadline,
        'progress challenge deadline',
      ),
      durableTime: positiveSafeInteger(progress.durableTime, 'progress durable time'),
    };
  }
  if (progress.phase === 'awaitingCloseRequest') {
    exactObject(progress, ['phase'], 'public-close progress');
    return { phase: progress.phase };
  }

  exactObject(progress, ['phase', 'publication'], 'public-close progress');
  const publication = exactObject(progress.publication, [
    'artifactHash',
    'chainId',
    'channelId',
    'closeIntentDigest',
    'finalizeTransactionHash',
    'finalizedCheckpoint',
    'manager',
    'rollup',
    'schemaVersion',
    'submitTransactionHash',
  ], 'public-close publication');
  if (publication.schemaVersion !== 1) {
    throw new Error('public-close publication schema version is unsupported');
  }
  const checkpoint = exactObject(publication.finalizedCheckpoint, [
    'blockHash',
    'blockNumber',
    'chainId',
    'parentHash',
    'source',
  ], 'public-close finalized checkpoint');
  const chain = positiveSafeInteger(publication.chainId, 'publication chain id');
  if (positiveSafeInteger(checkpoint.chainId, 'checkpoint chain id') !== chain) {
    throw new Error('public-close checkpoint belongs to a different chain');
  }
  if (!['rpcFinalized', 'devnetLatest'].includes(checkpoint.source)) {
    throw new Error('public-close checkpoint has an unknown finality source');
  }
  return {
    phase: progress.phase,
    publication: {
      schemaVersion: 1,
      chainId: chain,
      rollup: canonicalAddress(publication.rollup, 'publication rollup'),
      manager: canonicalAddress(publication.manager, 'publication manager'),
      channelId: positiveSafeInteger(publication.channelId, 'publication channel id', 0xffffffff),
      closeIntentDigest: canonicalNonzeroDigest(
        publication.closeIntentDigest,
        'publication close-intent digest',
      ),
      artifactHash: canonicalNonzeroDigest(publication.artifactHash, 'publication artifact hash'),
      submitTransactionHash: canonicalNonzeroDigest(
        publication.submitTransactionHash,
        'publication submit transaction hash',
      ),
      finalizeTransactionHash: canonicalNonzeroDigest(
        publication.finalizeTransactionHash,
        'publication finalize transaction hash',
      ),
      finalizedCheckpoint: {
        chainId: chain,
        blockNumber: positiveSafeInteger(checkpoint.blockNumber, 'checkpoint block number'),
        blockHash: canonicalNonzeroDigest(checkpoint.blockHash, 'checkpoint block hash'),
        parentHash: canonicalNonzeroDigest(checkpoint.parentHash, 'checkpoint parent hash'),
        source: checkpoint.source,
      },
    },
  };
}

function inspectBundleDirectory(bundleDirectory) {
  const stat = fs.lstatSync(bundleDirectory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error('public-close proof bundle must be a real directory');
  }
  const manifest = path.join(bundleDirectory, 'public_close_manifest.json');
  const manifestStat = fs.lstatSync(manifest);
  if (!manifestStat.isFile() || manifestStat.isSymbolicLink()
      || manifestStat.size === 0 || manifestStat.size > MAX_MANIFEST_BYTES) {
    throw new Error('public-close bundle manifest is missing or unsafe');
  }
}

function makePublicClosePublisher({
  proverBinPath,
  publisherBinPath,
  deploymentManifestPath,
  deploymentManifestSha256,
  signerLockRoot,
  account,
  rpc,
  chainId,
  rollup,
  manager,
  channelId,
  balanceVerifierDataSha256,
  workDir,
  allowUnfinalizedDevnet = false,
  proveTimeoutMs,
  publishTimeoutMs,
  repoRoot = path.resolve(__dirname, '..', '..'),
  execFileImpl = execFile,
} = {}) {
  const repository = path.resolve(repoRoot);
  const authority = {
    chainId: positiveSafeInteger(chainId, 'public-close chain id'),
    channelId: positiveSafeInteger(channelId, 'public-close channel id', 0xffffffff),
    rollup: canonicalAddress(rollup, 'public-close rollup'),
    manager: canonicalAddress(manager, 'public-close manager'),
    balanceVerifierDataSha256: canonicalDigest(
      balanceVerifierDataSha256,
      'public-close balance verifier-data pin',
    ),
  };
  const binary = {
    prover: executable(proverBinPath, 'target/release/public_close_prover', repository, 'public-close prover'),
    publisher: executable(
      publisherBinPath,
      'target/release/public_close_publisher',
      repository,
      'public-close publisher',
    ),
  };
  const deploymentFile = regularFile(
    deploymentManifestPath,
    repository,
    'public-close deployment manifest',
    MAX_MANIFEST_BYTES,
  );
  const deploymentPin = canonicalDigest(
    deploymentManifestSha256,
    'public-close deployment manifest SHA-256',
  );
  if (sha256(deploymentFile.bytes) !== deploymentPin) {
    throw new Error('public-close deployment manifest differs from its configured SHA-256');
  }
  let deployment;
  try { deployment = JSON.parse(deploymentFile.bytes.toString('utf8')); }
  catch (error) { throw new Error(`public-close deployment manifest is malformed: ${error.message}`); }
  if (Number(deployment.chainId) !== authority.chainId
      || canonicalAddress(deployment.rollup, 'deployment rollup') !== authority.rollup
      || canonicalAddress(deployment.manager, 'deployment manager') !== authority.manager
      || canonicalDigest(
        deployment.balanceVerifierDataSha256,
        'deployment balance verifier-data pin',
      ) !== authority.balanceVerifierDataSha256) {
    throw new Error('public-close deployment manifest differs from configured channel authority');
  }
  const configuredAccount = accountSelector(account);
  const configuredRpc = rpcUrl(rpc);
  const lockRoot = path.isAbsolute(String(signerLockRoot || ''))
    ? path.resolve(String(signerLockRoot))
    : path.resolve(repository, String(signerLockRoot || ''));
  if (!String(signerLockRoot || '').trim()) throw new Error('shared public-close signer lock root is required');
  const baseDirectory = path.join(path.resolve(workDir || '.'), 'public-close-publication', String(authority.channelId));
  const proveTimeout = boundedTimeout(
    proveTimeoutMs,
    DEFAULT_PROVE_TIMEOUT_MS,
    'public-close proving timeout',
    6 * 60 * 60 * 1000,
  );
  const publishTimeout = boundedTimeout(
    publishTimeoutMs,
    DEFAULT_PUBLISH_TIMEOUT_MS,
    'public-close publishing timeout',
    30 * 60 * 1000,
  );
  if (allowUnfinalizedDevnet && authority.chainId !== 31_337) {
    throw new Error('unfinalized public-close mode is restricted to chain 31337');
  }

  function verifyDeploymentPin() {
    const current = regularFile(
      deploymentFile.resolved,
      repository,
      'public-close deployment manifest',
      MAX_MANIFEST_BYTES,
    );
    if (sha256(current.bytes) !== deploymentPin) {
      throw new Error('public-close deployment manifest changed after startup');
    }
  }

  async function advance({ acceptedHead, snapshotVault, backingVault } = {}) {
    verifyDeploymentPin();
    const digest = canonicalDigest(acceptedHead && acceptedHead.digest, 'accepted head digest');
    if (!snapshotVault || !backingVault) {
      throw new Error('public-close publication requires both immutable recovery vaults');
    }
    const snapshot = snapshotVault.load(digest);
    if (!snapshot) throw new Error(`authenticated snapshot ${digest} is unavailable`);
    const verified = backingVault.loadVerified(digest, snapshot);
    if (!verified) throw new Error(`verified public backing ${digest} is unavailable`);
    const backingFile = backingVault.fileFor(digest);
    const digestName = digest.slice(2);
    const bundleDirectory = path.join(baseDirectory, 'bundles', digestName);
    const journal = path.join(baseDirectory, 'journals', `${digestName}.json`);
    fs.mkdirSync(path.dirname(bundleDirectory), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.dirname(journal), { recursive: true, mode: 0o700 });

    if (!fs.existsSync(bundleDirectory)) {
      const args = [
        '--input', backingFile,
        '--output-dir', bundleDirectory,
        '--expected-channel-id', String(authority.channelId),
        '--expected-chain-id', String(authority.chainId),
        '--expected-rollup', authority.rollup,
        '--expected-balance-vd-sha256', authority.balanceVerifierDataSha256,
      ];
      await run(execFileImpl, binary.prover, args, {
        cwd: repository,
        encoding: 'utf8',
        timeout: proveTimeout,
        maxBuffer: MAX_PUBLISHER_OUTPUT_BYTES,
        windowsHide: true,
      }, 'public-close proof generation');
    }
    inspectBundleDirectory(bundleDirectory);

    const args = [
      '--bundle-dir', bundleDirectory,
      // This comes from the WASM-authenticated snapshot key, not from the reusable bundle. The
      // native publisher binds it to the descriptor, full intent, MLE public inputs and WAL.
      '--expected-final-channel-state-digest', digest,
      '--deployment-manifest', deploymentFile.resolved,
      '--deployment-manifest-sha256', deploymentPin,
      '--journal', journal,
      '--signer-lock-root', lockRoot,
      '--rpc-url', configuredRpc,
      '--account', configuredAccount,
    ];
    if (allowUnfinalizedDevnet) args.push('--allow-unfinalized-devnet');
    const output = await run(execFileImpl, binary.publisher, args, {
      cwd: repository,
      encoding: 'utf8',
      timeout: publishTimeout,
      maxBuffer: MAX_PUBLISHER_OUTPUT_BYTES,
      windowsHide: true,
    }, 'public-close publication');
    const progress = parseProgress(output);
    if (progress.phase === 'complete'
        && (progress.publication.chainId !== authority.chainId
          || progress.publication.channelId !== authority.channelId
          || progress.publication.rollup !== authority.rollup
          || progress.publication.manager !== authority.manager)) {
      throw new Error('completed public-close publication differs from startup channel authority');
    }
    return progress;
  }

  return {
    authority: Object.freeze({ ...authority }),
    deploymentManifestPath: deploymentFile.resolved,
    deploymentManifestSha256: deploymentPin,
    advance,
  };
}

module.exports = {
  DEFAULT_PROVE_TIMEOUT_MS,
  DEFAULT_PUBLISH_TIMEOUT_MS,
  MAX_PUBLISHER_OUTPUT_BYTES,
  makePublicClosePublisher,
  parseProgress,
};
