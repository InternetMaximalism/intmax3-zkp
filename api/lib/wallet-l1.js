'use strict';
// The wallet relay's L1 settlement step: publishing the producer's validity history to the rollup.
// On the devnet the CLI mines Anvil blocks to reach
// finality; on a public chain every L1 step waits for the RPC's finalized head (minutes per
// transaction), so commands run asynchronously and never stall the relay.
const fs = require('fs'), path = require('path');
const { isDeepStrictEqual } = require('util');
const cli = require('./cli'), producer = require('./block-producer');
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

// Each post tops the operator's prepaid posting bond up as it needs; the finalization releases
// every post up to the finalized one, and the bond stays in the rollup for the next posts.
// `prove: false` only publishes a candidate already proven (a burn payout proves its own, anchored
// at the head the candidate ends at), and never proves a new one past it.
function publish(ch, { prove = true } = {}) {
  const run = queue.then(() => publishCandidate(ch, prove));
  queue = run.catch(() => {});
  return run;
}

// The rollup's one close materializer, read from any sibling channel's settlement record on the
// same rollup (the materializer is shared by every manager of a rollup). Null when no channel of
// this relay has a settlement stack yet: then no channel can be frozen, and there is nothing to check.
function materializerOf(ch) {
  const rollup = cli.rollupOf(ch).toLowerCase();
  for (const other of cli.CHANNELS || []) {
    const file = cli.wc(other, 'settlement.json');
    if (!fs.existsSync(file)) continue;
    const settlement = cli.readJson(file);
    if (String(settlement.rollup || '').toLowerCase() !== rollup) continue;
    const materializer = settlement.close_funding_materializer || settlement.closeFundingMaterializer;
    if (/^0x[0-9a-f]{40}$/i.test(String(materializer))) return String(materializer);
  }
  return null;
}

const ZERO_ADDRESS = /^0x0{40}$/i, ZERO_WORD = /^0x0{64}$/i;
const view = (address, sig, arg) => cli.sh('cast', ['call', address, sig, String(arg), '--rpc-url', cli.RPC]).trim().split(/\s+/)[0];

// M7 liveness gap (2): `IntmaxRollup._postBlock` calls the materializer's `recordPost` for every
// sub-block and bubbles its revert, so a candidate whose span still carries a sub-block of a
// channel the Manager has frozen (`ChannelExitAlreadyFrozen`) or materialized
// (`ChannelAlreadyExited`) can never post — and the append-only producer journal cannot drop that
// block (tests/block_producer_service.rs). Returns every such channel with the span blocks it
// owns, so the publish step refuses with an operator-readable error instead of reverting on L1
// and retrying forever.
function frozenChannelsInCandidate(ch, posting) {
  const materializer = materializerOf(ch);
  if (!materializer) return [];
  const blocksByChannel = new Map();
  const first = Number(posting.receipt.initialBlockNumber || 0) + 1;
  posting.subBlocks.forEach((sub, index) => {
    const id = Number(sub.channelId);
    if (!blocksByChannel.has(id)) blocksByChannel.set(id, []);
    blocksByChannel.get(id).push(first + index);
  });
  const stuck = [];
  for (const [channelId, blocks] of blocksByChannel) {
    if (ZERO_ADDRESS.test(view(materializer, 'managerOfChannel(uint32)(address)', channelId))) continue;
    const exited = view(materializer, 'materializedChannelExit(uint32)(bytes32)', channelId);
    const frozen = view(materializer, 'frozenGeneration(uint32)(uint64)', channelId);
    if (!ZERO_WORD.test(exited)) stuck.push({ channelId, blocks, state: 'exited', revert: 'ChannelAlreadyExited', materializedChannelExit: exited });
    else if (frozen !== '0') stuck.push({ channelId, blocks, state: 'frozen', revert: 'ChannelExitAlreadyFrozen', frozenGeneration: frozen });
  }
  return stuck;
}

function refuseFrozenChannels(ch, posting) {
  const stuck = frozenChannelsInCandidate(ch, posting);
  if (stuck.length === 0) return;
  const detail = stuck.map(s => `channel ${s.channelId} is ${s.state} on L1 (${s.revert}; blocks ${s.blocks.join(',')})`).join('; ');
  const recoverable = stuck.every(s => s.state === 'frozen');
  const error = new Error(
    `validity candidate ${posting.receipt.candidateId} can never post: ${detail}. IntmaxRollup reverts ` +
    'the whole batch on the first such sub-block, and the producer journal cannot drop a committed block. ' +
    (recoverable
      ? 'Operator action: cancel the pending close (cancelClose unfreezes the channel) and this exact candidate posts as is.'
      : 'The channel has exited: this span is permanently unpostable. The producer is halted at this candidate; see doc/architecture-audit/detail2.md §K.1 (M7, 2026-10-15) for the owner decision.'));
  error.code = 'VALIDITY_CANDIDATE_CONTAINS_FROZEN_CHANNEL_BLOCK';
  error.frozenChannels = stuck;
  throw error;
}

async function publishCandidate(ch, prove) {
    await producer.enableLocalValidity();
    const state = await producer.validityStatus();
    const head = await producer.status();
    if (!state.candidate && (!prove || Number(state.finalizedBlockNumber) === Number(head.blockNumber))) return;
    if (!state.candidate) await producer.proveValidity(producer.stableRequestId('wallet-validity', {generation: head.generation, root: head.extendedStateCommitment}));
    const posting = await producer.validityPostingArtifact();
    if (!posting || !/^0x[0-9a-f]{64}$/i.test(posting.receipt.candidateId)) throw new Error('validity candidate missing');
    refuseFrozenChannels(ch, posting);
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

module.exports = { deploymentConfig, configure, publish, frozenChannelsInCandidate };
