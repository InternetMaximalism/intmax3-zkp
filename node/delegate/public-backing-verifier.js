'use strict';

// Native receive-time verification for a public live-balance backing artifact.  The Rust binary
// verifies the N-of-N signed head, the independently pinned verifier data, and the recursive
// BalanceProcessor proof without constructing either close proof.  It receives a filesystem path
// (never request JSON over argv/stdin), and execFile is deliberately used without a shell.

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_RECEIPT_BYTES = 64 * 1024;

function positiveSafeInteger(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return parsed;
}

function resolveBinaryPath(value, repoRoot) {
  const configured = String(value || '').trim();
  const binary = configured
    ? (path.isAbsolute(configured) ? configured : path.resolve(repoRoot, configured))
    : path.join(repoRoot, 'target', 'release', 'public_close_prover');
  let stat;
  try { stat = fs.statSync(binary); }
  catch (error) {
    throw new Error(`public_close_prover is unavailable at ${binary}: ${error.message}`);
  }
  if (!stat.isFile()) throw new Error(`public_close_prover path is not a regular file: ${binary}`);
  try { fs.accessSync(binary, fs.constants.X_OK); }
  catch (error) { throw new Error(`public_close_prover is not executable at ${binary}: ${error.message}`); }
  return binary;
}

function parseReceipt(stdout) {
  const encoded = Buffer.from(String(stdout || ''), 'utf8');
  if (encoded.length === 0 || encoded.length > MAX_RECEIPT_BYTES) {
    throw new Error(`public_close_prover returned an invalid receipt size (${encoded.length} bytes)`);
  }
  let receipt;
  try { receipt = JSON.parse(encoded.toString('utf8'));
  } catch (error) {
    throw new Error(`public_close_prover returned malformed JSON: ${error.message}`);
  }
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new Error('public_close_prover receipt must be a JSON object');
  }
  return receipt;
}

function makePublicBackingVerifier({
  binPath,
  repoRoot = path.resolve(__dirname, '..', '..'),
  timeoutMs = DEFAULT_TIMEOUT_MS,
  execFileImpl = execFile,
} = {}) {
  const root = path.resolve(repoRoot);
  const binary = resolveBinaryPath(binPath, root);
  const timeout = positiveSafeInteger(timeoutMs, 'public backing verification timeout');
  if (timeout > 60 * 60 * 1000) {
    throw new Error('public backing verification timeout must not exceed one hour');
  }

  async function verify(inputFile, authority) {
    const file = path.resolve(String(inputFile || ''));
    let stat;
    try { stat = fs.lstatSync(file); }
    catch (error) { throw new Error(`canonical backing file is unavailable: ${error.message}`); }
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error('canonical backing input must be a regular non-symlink file');
    }

    const args = [
      '--input', file,
      '--verify-only',
      '--expected-channel-id', String(positiveSafeInteger(authority && authority.channelId, 'expected channel id')),
      '--expected-chain-id', String(positiveSafeInteger(authority && authority.chainId, 'expected chain id')),
      '--expected-rollup', String(authority && authority.rollup || ''),
    ];
    if (authority && authority.balanceVerifierDataSha256) {
      args.push('--expected-balance-vd-sha256', String(authority.balanceVerifierDataSha256));
    }

    const stdout = await new Promise((resolve, reject) => {
      execFileImpl(binary, args, {
        cwd: root,
        encoding: 'utf8',
        timeout,
        maxBuffer: MAX_RECEIPT_BYTES,
        windowsHide: true,
      }, (error, output, stderr) => {
        if (error) {
          const detail = String(stderr || error.message || error).trim();
          const failure = new Error(`public backing cryptographic verification failed: ${detail}`);
          failure.code = 'PUBLIC_BACKING_VERIFICATION_FAILED';
          failure.cause = error;
          reject(failure);
          return;
        }
        resolve(output);
      });
    });
    return parseReceipt(stdout);
  }

  return { binary, verify };
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  MAX_RECEIPT_BYTES,
  makePublicBackingVerifier,
  parseReceipt,
};
