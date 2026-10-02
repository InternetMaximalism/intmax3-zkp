'use strict';
// The wallet relay's L1 settlement steps: publishing the producer's validity history to the rollup
// and attesting a signed head's backing. On the devnet the CLI mines Anvil blocks to reach
// finality; on a public chain every L1 step waits for the RPC's finalized head (minutes per
// transaction), so commands run asynchronously and never stall the relay.
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const { isDeepStrictEqual } = require('util');
const cli = require('./cli'), producer = require('./block-producer');
const { envelopeFor } = require('./exit-kit');
const { exportedConfig: deploymentConfig } = require('./validity-deployment');
let queue = Promise.resolve();
const devnet = () => cli.chainId() === cli.DEVNET_CHAIN_ID;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
// The daemon accepts an L1 finalization receipt only once the RPC's finalized head covers it.
const NOT_YET_FINAL = /not covered by the (initial|final) durable head|retry against one stable finalized block/;
const FINALITY_POLL_MS = Number(process.env.WALLET_L1_FINALITY_POLL_MS || 30_000);
const FINALITY_WAIT_MS = Number(process.env.WALLET_L1_FINALITY_WAIT_MS || 3 * 3600_000);
const contractsDir = () => process.env.CONTRACTS_DIR || path.join(cli.REPO, 'contracts');
// Where the CLI keeps its L1 publication journals: proof-da-output/ beside the contracts directory.
const proofDaDir = () => path.join(path.dirname(path.resolve(contractsDir())), 'proof-da-output');

function configure(rollup) {
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
  producer.configureLocalValidity({ ...config, chainId: cli.chainId() });
  // Anvil's `finalized` tag lags; keep the daemon's actual finalized read-back, advance empty blocks.
  if (devnet()) cli.sh('cast', ['rpc', 'anvil_mine', '0x40', '--rpc-url', cli.RPC]);
}

// Acknowledge only a finalized L1 finalization; off the devnet the finalized head trails the
// transaction by minutes, so wait for it rather than fail.
async function acknowledge(candidateId, transactionHash) {
  const deadline = Date.now() + FINALITY_WAIT_MS;
  for (;;) {
    try {
      return await producer.acknowledgeValidity('wallet-ack:' + candidateId, candidateId, transactionHash);
    } catch (e) {
      if (devnet() || !NOT_YET_FINAL.test(String((e && e.message) || e)) || Date.now() > deadline) throw e;
      await sleep(FINALITY_POLL_MS);
    }
  }
}

function publish(ch) {
  const run = queue.then(async () => {
    await publishCandidate(ch);
    await reclaimStakes(cli.rollupOf(ch));
  });
  queue = run.catch(() => {});
  return run;
}

async function publishCandidate(ch) {
    await producer.enableLocalValidity();
    const state = await producer.validityStatus();
    const head = await producer.status();
    if (!state.candidate && Number(state.finalizedBlockNumber) === Number(head.blockNumber)) return;
    if (!state.candidate) await producer.proveValidity(producer.stableRequestId('wallet-validity', {generation: head.generation, root: head.extendedStateCommitment}));
    const posting = await producer.validityPostingArtifact();
    if (!posting || !/^0x[0-9a-f]{64}$/i.test(posting.receipt.candidateId)) throw new Error('validity candidate missing');
    // MLE conversion is randomized. Once a blob transaction has been signed, reuse the exact
    // immutable proof bytes pinned by the publisher, including after a daemon restart.
    const manifestPath = path.join(proofDaDir(), 'wallet-validity-' + posting.receipt.candidateId, 'candidate.json');
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
    await cli.cliAsync(ch, ['publish-wallet-validity', cli.RPC, 'wallet_validity_posting.json', 'wallet_validity_finalize.json'], {
      ...(devnet() ? { INTMAX_WALLET_ANVIL_MINE: '1' } : {}),
      WALLET_VALIDITY_CONFIG: cli.readJson(path.join(cli.WORK, 'producer', 'wallet-l1.json')).validityConfig,
    });
    const receipt = cli.readJson(cli.wc(ch, 'wallet_validity_receipt.json'));
    if (receipt.candidateId !== posting.receipt.candidateId) throw new Error('published validity candidate mismatch');
    if (devnet()) cli.sh('cast', ['rpc', 'anvil_mine', '0x40', '--rpc-url', cli.RPC]);
    await acknowledge(receipt.candidateId, receipt.transactionHash);
}

// Every blob post locked the rollup's 1 ETH POST_BLOCK_STAKE. Finalization refunds the finalized
// round's; the earlier rounds are reclaimable once their blocks are finalized, and nothing else
// returns them. Reclaim every finalized one this operator posted on the rollup and pull its credit
// back to its account. Idempotent: an unfinalized, spent or foreign stake is skipped, an empty
// credit is not pulled.
async function reclaimStakes(rollup) {
  const dir = proofDaDir();
  const journals = (fs.existsSync(dir) ? fs.readdirSync(dir) : []).filter(d => d.startsWith('wallet-validity-0x'))
    .map(d => path.join(dir, d, 'posts.json')).filter(f => fs.existsSync(f)).map(f => cli.readJson(f))
    .filter(j => String(j.rollup).toLowerCase() === String(rollup).toLowerCase());
  const view = (sig, ...args) => cli.sh('cast', ['call', rollup, sig, ...args, '--rpc-url', cli.RPC]).trim();
  const send = (sig, ...args) => cli.shAsync('cast', ['send', rollup, sig, ...args, '--rpc-url', cli.RPC,
    ...cli.l1SignerArgs()], { timeout: 1_200_000 });
  // `reclaimStake` reverts until the round's blocks are finalized: simulate it first.
  const reclaimable = (id, submitter) => {
    try { cli.sh('cast', ['call', rollup, 'reclaimStake(uint256)', id, '--from', submitter, '--rpc-url', cli.RPC], { stdio: 'pipe' }); return true; }
    catch (e) { return false; }
  };
  const submitters = new Set();
  for (const journal of journals) {
    submitters.add(journal.submitter.toLowerCase());
    for (const round of journal.rounds) {
      if (!round.submissionId) continue;
      const id = String(BigInt(round.submissionId));
      const [submitter, spent] = view('stakeInfo(uint256)(address,bool)', id).split(/\s+/);
      if (submitter.toLowerCase() !== journal.submitter.toLowerCase() || spent === 'true') continue;
      if (!reclaimable(id, submitter)) continue;
      await send('reclaimStake(uint256)', id);
    }
  }
  for (const submitter of submitters) {
    const credit = BigInt(view('pendingWithdrawals(address)(uint256)', submitter).split(/\s+/)[0]);
    if (credit > 0n) await send('withdraw(uint256)', credit.toString());
  }
}

async function attest(ch, backing) {
  const dir = path.join(proofDaDir(), 'wallet-backing-' + ch + '-' + backing.signedHead.digest.slice(2));
  const input = cli.wc(ch, 'wallet_backing.json');
  cli.writeJson(input, envelopeFor(ch, backing));
  const manifest = path.join(dir, 'public_close_manifest.json');
  const timeout = Math.max(1_200_000, Number(process.env.INTMAX_CLI_TIMEOUT_MS || 0));
  // The balance verifier is pinned by the channel's own verifier data, as at bootstrap.
  const balanceVdSha256 = crypto.createHash('sha256').update(fs.readFileSync(cli.wc(ch, 'balance_vd.bin'))).digest('hex');
  if (!fs.existsSync(manifest)) await cli.shAsync(process.env.PUBLIC_CLOSE_PROVER_BIN || path.join(cli.REPO, 'target/release/public_close_prover'), [
    '--input', input, '--output-dir', dir, '--expected-channel-id', String(ch), '--expected-chain-id', String(cli.chainId()),
    '--expected-rollup', cli.rollupOf(ch), '--expected-balance-vd-sha256', balanceVdSha256,
  ], { timeout });
  const settlement = cli.readJson(cli.wc(ch, 'settlement.json'));
  // Idempotent on L1: an already attested proof is accepted again without effect.
  await cli.shAsync('forge', ['script', 'script/WalletL1Lifecycle.s.sol', '--sig', 'attestBacking()', '--rpc-url', cli.RPC,
    '--broadcast', '--slow', ...cli.l1SignerArgs()], { cwd: contractsDir(), timeout,
    env: { ...process.env, MANAGER: settlement.manager, WALLET_BACKING_PATH: path.join(dir, 'backing_mle.json') } });
}
module.exports = { deploymentConfig, configure, publish, attest };
