'use strict';
// The wallet relay's explicit Anvil workflow. Public chains must use the pinned operator publisher.
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const { isDeepStrictEqual } = require('util');
const cli = require('./cli'), producer = require('./block-producer');
const { envelopeFor } = require('./exit-kit');
let queue = Promise.resolve();
function deploymentConfig() {
  const arities = process.env.BLOCK_PRODUCER_ARITIES || '2,4,8,16';
  if (!/^[0-9]+(,[0-9]+)*$/.test(arities)) throw new Error('invalid producer arities');
  const dir = path.join(cli.REPO, 'proof-da-output');
  fs.mkdirSync(dir, { recursive: true });
  const build = crypto.createHash('sha256').update(fs.readFileSync(cli.CLI)).digest('hex').slice(0, 16);
  const file = path.join(dir, 'wallet-validity-config-' + arities.replaceAll(',', '_') + '-' + build + '.json');
  if (!fs.existsSync(file)) cli.sh(cli.CLI, ['export-wallet-validity-config', file, arities],
    { timeout: Math.max(3_600_000, Number(process.env.INTMAX_CLI_TIMEOUT_MS || 0)) });
  return file;
}
function configure(rollup) {
  if (cli.chainId() !== 31337) throw new Error('wallet L1 orchestration requires Anvil');
  const code = cli.sh('cast', ['code', rollup, '--rpc-url', cli.RPC]).trim();
  if (!/^0x[0-9a-f]+$/i.test(code) || code.length <= 2) throw new Error('wallet rollup has no runtime code');
  const config = { snapshot: path.join(cli.WORK, 'producer', 'validity.snapshot'), prover: cli.l1SignerAddress(),
    rpc: cli.RPC, rollup, validityConfig: deploymentConfig(), codeHash: cli.sh('cast', ['keccak', code]).trim() };
  const pins = cli.readJson(config.validityConfig).pinnedVerifier;
  const view = (address, sig) => cli.sh('cast', ['call', address, sig, '--rpc-url', cli.RPC]).trim();
  const adapter = view(rollup, 'validityMleVerifier()(address)');
  const core = view(adapter, 'core()(address)');
  for (const name of ['verificationConfigDigest', 'circuitConfigDigest', 'whirParametersDigest']) {
    if (view(core, name + '()(bytes32)').toLowerCase() !== String(pins[name]).toLowerCase()) {
      throw new Error('deployed validity verifier does not match the resident producer: ' + name);
    }
  }
  config.validityConfigDigest = pins.verificationConfigDigest;
  const file = path.join(cli.WORK, 'producer', 'wallet-l1.json');
  if (fs.existsSync(file)) {
    const saved = cli.readJson(file);
    for (const key of Object.keys(config).filter(k => k !== 'validityConfig')) {
      if (saved[key] !== config[key]) throw new Error('wallet L1 deployment changed: ' + key);
    }
  }
  cli.writeJson(file, config);
  producer.configureLocalValidity(config);
  // Anvil's `finalized` tag lags; keep the daemon's actual finalized read-back, advance empty blocks.
  cli.sh('cast', ['rpc', 'anvil_mine', '0x40', '--rpc-url', cli.RPC]);
}
function publish(ch) {
  const run = queue.then(async () => {
    if (cli.chainId() !== 31337) throw new Error('wallet L1 orchestration requires Anvil');
    await producer.enableLocalValidity();
    const state = await producer.validityStatus();
    const head = await producer.status();
    if (!state.candidate && Number(state.finalizedBlockNumber) === Number(head.blockNumber)) return;
    if (!state.candidate) await producer.proveValidity(producer.stableRequestId('wallet-validity', {generation: head.generation, root: head.extendedStateCommitment}));
    const posting = await producer.validityPostingArtifact();
    if (!posting || !/^0x[0-9a-f]{64}$/i.test(posting.receipt.candidateId)) throw new Error('validity candidate missing');
    // MLE conversion is randomized. Once a blob transaction has been signed, reuse the exact
    // immutable proof bytes pinned by the publisher, including after a daemon restart.
    const manifestPath = path.join(cli.REPO, 'proof-da-output', 'wallet-validity-' + posting.receipt.candidateId, 'candidate.json');
    let finalize;
    if (fs.existsSync(manifestPath)) {
      const pinned = cli.readJson(manifestPath);
      if (!isDeepStrictEqual(pinned.posting, posting) || pinned.rollup.toLowerCase() !== cli.rollupOf(ch).toLowerCase()) {
        throw new Error('saved validity publication differs from the producer candidate');
      }
      finalize = pinned.finalize;
    } else {
      finalize = await producer.validityFinalizeArtifact();
    }
    if (!finalize) throw new Error('validity finalization artifact missing');
    cli.writeJson(cli.wc(ch, 'wallet_validity_posting.json'), posting);
    cli.writeJson(cli.wc(ch, 'wallet_validity_finalize.json'), finalize);
    cli.cli(ch, ['publish-wallet-validity', cli.RPC, 'wallet_validity_posting.json', 'wallet_validity_finalize.json'], { INTMAX_WALLET_ANVIL_MINE: '1', WALLET_VALIDITY_CONFIG: cli.readJson(path.join(cli.WORK, 'producer', 'wallet-l1.json')).validityConfig });
    const receipt = cli.readJson(cli.wc(ch, 'wallet_validity_receipt.json'));
    if (receipt.candidateId !== posting.receipt.candidateId) throw new Error('published validity candidate mismatch');
    cli.sh('cast', ['rpc', 'anvil_mine', '0x40', '--rpc-url', cli.RPC]);
    await producer.acknowledgeValidity('wallet-ack:' + receipt.candidateId, receipt.candidateId, receipt.transactionHash);
  });
  queue = run.catch(() => {});
  return run;
}
async function attest(ch, backing) {
  if (cli.chainId() !== 31337) throw new Error('wallet backing attestation requires Anvil');
  const dir = path.join(cli.REPO, 'proof-da-output', 'wallet-backing-' + ch + '-' + backing.signedHead.digest.slice(2));
  const input = cli.wc(ch, 'wallet_backing.json');
  cli.writeJson(input, envelopeFor(ch, backing));
  const manifest = path.join(dir, 'public_close_manifest.json');
  if (!fs.existsSync(manifest)) cli.sh(process.env.PUBLIC_CLOSE_PROVER_BIN || path.join(cli.REPO, 'target/release/public_close_prover'), [
    '--input', input, '--output-dir', dir, '--expected-channel-id', String(ch), '--expected-chain-id', '31337',
    '--expected-rollup', cli.rollupOf(ch),
  ], { timeout: Math.max(1_200_000, Number(process.env.INTMAX_CLI_TIMEOUT_MS || 0)) });
  const settlement = cli.readJson(cli.wc(ch, 'settlement.json'));
  cli.sh('forge', ['script', 'script/WalletL1Lifecycle.s.sol', '--sig', 'attestBacking()', '--rpc-url', cli.RPC,
    '--broadcast', '--slow', ...cli.l1SignerArgs()], { cwd: process.env.CONTRACTS_DIR || path.join(cli.REPO, 'contracts'), timeout: Math.max(1_200_000, Number(process.env.INTMAX_CLI_TIMEOUT_MS || 0)),
      env: { ...process.env, MANAGER: settlement.manager, WALLET_BACKING_PATH: path.join(dir, 'backing_mle.json') } });
}
module.exports = { deploymentConfig, configure, publish, attest };
