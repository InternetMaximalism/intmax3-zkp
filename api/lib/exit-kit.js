'use strict';
// Pre-sign exit kits (signer-independent exit).
//
// Every asset/composition-moving channel transition (L1 deposit import, token registration,
// burn / inter-channel debit) is refused by `channel_member` at its signing primitive until the
// co-signer durably holds a verified exit kit for the EXACT successor it is about to sign. The
// kit can only be proved by the resident live balance service (it owns the private asset opening),
// so the coordinator drives a two-phase command:
//   1. `<cmd> --propose-exit-kit`  → the CLI writes the exact proposal and signs nothing;
//   2. `livePrepareExitKit`         → the daemon proves the kit (a debit first stages the producer
//                                     block the real N-of-N must later reproduce);
//   3. `<cmd>` with INTMAX_PREPARED_EXIT_KIT → the CLI verifies, archives, records the receipt,
//                                     and only then releases its signatures.
// A destination-side inter-channel credit is signed against the durable head's receipt instead
// (the pre-credit head stays exitable); its own kit is installed right after the live balance
// service receives the transfer (`installHeadExitKit`).
const fs = require('fs');
// Resolved through the module objects at call time so the test harnesses that replace `cli.cli`
// and the producer client functions observe these calls too.
const cliModule = require('./cli');
const { wc, readJson, writeJson } = cliModule;
const producer = require('./block-producer');
const { publicBacking } = require('../../node/common/public-backing');
const { PUBLIC_BACKING_SCHEMA_VERSION } = require('../../node/delegate/backing-vault');

const PROPOSAL_FILE = 'exit_kit_proposal.json';
const ENVELOPE_FILE = 'prepared_exit_kit.json';
const INSTALL_FILE = 'installed_exit_kit.json';
const PROPOSE_FLAG = '--propose-exit-kit';
const ENVELOPE_ENV = 'INTMAX_PREPARED_EXIT_KIT';

// The transport context is a security binding consumed by the CLI's verifier: the configured RPC
// chain and the setup-time rollup, never a caller-supplied value.
function envelopeFor(ch, artifact) {
  const deployment = publicBacking(readJson(wc(ch, 'channel_backing.json')));
  return {
    schemaVersion: PUBLIC_BACKING_SCHEMA_VERSION,
    source: 'liveBalanceService',
    chainId: cliModule.chainId(),
    rollup: deployment.rollup,
    ...artifact,
  };
}

function debitRequestId(producerRequestId) {
  return `${producerRequestId}:exit-kit`;
}

// Run `args` once with --propose-exit-kit, prove the kit for that exact proposal, then run `args`
// for real with the envelope bound. `requestId` names the producer block a debit proposal stages.
async function cliWithPreparedExitKit(ch, args, extraEnv, options = {}) {
  fs.rmSync(wc(ch, PROPOSAL_FILE), { force: true });
  cliModule.cli(ch, [...args, PROPOSE_FLAG], extraEnv);
  const proposal = readJson(wc(ch, PROPOSAL_FILE));
  let stagedRequestId = null;
  if (proposal.kind === 'interChannelDebit') {
    if (!options.requestId) {
      throw new Error('a debit exit kit needs the producer request id of the block it stages');
    }
    stagedRequestId = debitRequestId(options.requestId);
    proposal.requestId = stagedRequestId;
  }
  const artifact = await producer.livePrepareExitKit(ch, proposal);
  writeJson(wc(ch, ENVELOPE_FILE), envelopeFor(ch, artifact));
  try {
    return cliModule.cli(ch, args, { ...(extraEnv || {}), [ENVELOPE_ENV]: ENVELOPE_FILE });
  } catch (error) {
    // The signer refused: the staged block would otherwise freeze every other producer mutation.
    // A signed-but-not-yet-posted debit is NOT abandoned here — the crash-recovery flush posts it
    // and promotes the staged block.
    if (stagedRequestId) {
      await producer.liveAbandonPreparedExitKit(ch, stagedRequestId).catch(() => {});
    }
    throw error;
  }
}

// Archive the live balance service's kit for the channel's CURRENT head into the CLI state. Used
// for kit-pending heads (a destination credit) and any head whose receipt was lost.
async function installHeadExitKit(ch) {
  const artifact = await producer.liveBackingArtifact(ch);
  writeJson(wc(ch, INSTALL_FILE), envelopeFor(ch, artifact));
  return cliModule.cli(ch, ['install-exit-kit', INSTALL_FILE]);
}

module.exports = {
  cliWithPreparedExitKit,
  installHeadExitKit,
  debitRequestId,
  envelopeFor,
  PROPOSAL_FILE,
  ENVELOPE_FILE,
  INSTALL_FILE,
  PROPOSE_FLAG,
  ENVELOPE_ENV,
};
