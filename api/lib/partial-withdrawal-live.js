'use strict';
const fs = require('fs');
const cli = require('./cli');
const producer = require('./block-producer');

// A burn is an inter-channel send to the reserved burn channel. It is paid on L1 by the base
// withdrawal proof alone, as an inter-channel transfer is consumed by a receive proof: the
// validity circuit already binds every member's signature to the block that carries it. The
// channel keeps advancing after the burn, so nothing here may assume the burn is still the head.

// Caller holds the channel lock. The burn's own block and live settlement, recorded by the burn
// operation; a burn recorded before pw_producer.json carried both is replayed (idempotent by its
// producer request id), never signed again.
async function prepareLiveBurn(ch) {
  const head = cli.readJson(cli.wc(ch, 'burn_cosigned.json'));
  const payload = cli.readJson(cli.wc(ch, 'burn_payload.json'));
  const descriptor = cli.readJson(cli.wc(ch, 'burn_descriptor.json'));
  if (head.channelId !== ch || head.digest !== payload.proposedNextState.digest) {
    throw new Error('partial withdrawal must resume its exact signed burn');
  }
  const producerRequestId = producer.stableRequestId('burn', { ch, debitPayload: payload, transferDescriptor: descriptor });
  const saved = fs.existsSync(cli.wc(ch, 'pw_producer.json')) ? cli.readJson(cli.wc(ch, 'pw_producer.json')) : null;
  if (saved && saved.producerRequestId === producerRequestId && saved.blockReceipt && saved.liveReceipt) {
    return { head, descriptor, producerRequestId, blockReceipt: saved.blockReceipt };
  }
  const blockReceipt = await producer.postInterChannel(head, payload, descriptor, producerRequestId);
  cli.writeJson(cli.wc(ch, 'pw_producer.json'), { producerRequestId, blockReceipt, liveReceipt: null });
  const liveReceipt = await producer.liveSettleInterChannel(ch, blockReceipt, head, payload, descriptor);
  cli.writeJson(cli.wc(ch, 'pw_producer.json'), { producerRequestId, blockReceipt, liveReceipt });
  return { head, descriptor, producerRequestId, blockReceipt };
}

// Caller holds the channel lock. The payout proof of the burn: its withdrawal leaf must be the
// burn's (identified by its nullifier and IMD2 aux commitment, which fixes the amount, recipient
// and token), and its anchor a producer head at or after the burn block. On a public chain the
// daemon anchors it at the head a validity candidate ends at (proving that candidate in the same
// command if needed), so the anchor's root becomes L1-finalized when that candidate is; it
// answers `validity candidate pending L1 acknowledgement` while an older candidate is still being
// published, and the caller publishes that one first.
// Whether `artifacts` pay the channel's current burn (last_burn.json) from an anchor at or after
// its block.
function payoutOfBurn(ch, artifacts, blockReceipt) {
  const burn = cli.readJson(cli.wc(ch, 'last_burn.json'));
  const lower = value => String(value).toLowerCase();
  const w = artifacts && artifacts.withdrawal, a = artifacts && artifacts.producerAnchor;
  return !!(w && a && artifacts.withdrawalProver === lower(cli.l1SignerAddress())
    && lower(w.nullifier) === lower(burn.withdrawal_nullifier) && lower(w.auxData) === lower(burn.aux_data)
    && lower(w.recipient) === lower(burn.withdrawal_recipient) && w.tokenIndex === burn.token_index
    && /^[1-9][0-9]*$/.test(String(w.amount))
    && Number(a.blockNumber) >= Number(blockReceipt.blockNumber) && Number(a.generation) >= Number(blockReceipt.generation));
}

// The saved payout proof of the channel's current burn, or null (none, or one left by an earlier
// burn). Never replays or proves anything.
function savedPayoutArtifacts(ch) {
  const file = cli.wc(ch, 'pw_artifacts.json'), meta = cli.wc(ch, 'pw_producer.json');
  if (!fs.existsSync(file) || !fs.existsSync(meta)) return null;
  const { blockReceipt } = cli.readJson(meta);
  const saved = cli.readJson(file);
  return blockReceipt && payoutOfBurn(ch, saved, blockReceipt) ? saved : null;
}

async function stagePayoutArtifacts(ch) {
  const { producerRequestId, descriptor, blockReceipt } = await prepareLiveBurn(ch);
  const file = cli.wc(ch, 'pw_artifacts.json');
  // The native payout journal pins the randomized MLE bytes in its candidate identity.
  // Retain them on retries, while refusing to reuse a different burn.
  if (fs.existsSync(file)) {
    const saved = cli.readJson(file);
    if (payoutOfBurn(ch, saved, blockReceipt)) return saved;
  }
  const artifacts = await producer.liveBurnPayoutArtifacts(ch, producerRequestId, descriptor, cli.l1SignerAddress());
  if (!payoutOfBurn(ch, artifacts, blockReceipt)) throw new Error('payout proof does not match the burn');
  cli.writeJson(file, artifacts);
  return artifacts;
}
// Anvil may briefly reject a historical state immediately after mining finality blocks.
// Re-enter ONLY the journaled payout driver, with unchanged proof files and authorization.
// Never retry arbitrary CLI errors or downgrade the native finalized-checkpoint requirement.
async function finalizeSavedPayout(ch, {rpc=cli.RPC, run=cli.cli, env={}, wait=ms=>new Promise(r=>setTimeout(r,ms))}={}) {
  for (let attempt=0; ; attempt++) {
    try { return await run(ch, ['pw-finalize', rpc], env); }
    catch (error) {
      const detail=String(error.stderr || error.message || error);
      if (attempt>=2 || env.INTMAX_WALLET_ANVIL_MINE!=='1'
          || !detail.includes('BlockOutOfRangeError')
          || !/cast \["call",[^\n]*"--block"/.test(detail)) throw error;
      await wait(1000*(attempt+1));
    }
  }
}
module.exports = { prepareLiveBurn, stagePayoutArtifacts, savedPayoutArtifacts, finalizeSavedPayout };
