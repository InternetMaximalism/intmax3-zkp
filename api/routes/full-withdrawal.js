const { Router } = require('express');
const fs = require('fs');
const {
  cli,
  wc,
  RPC,
  DEVNET_CHAIN_ID,
  chainId,
  rollupOf,
  readJson,
  writeJson,
  l1SignerAddress,
  ensureSettlement,
  verifyActiveSettlementBinding,
  failRoute,
} = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');
const producer = require('../lib/block-producer');

const router = Router({ mergeParams: true });
// v2 is intentionally incompatible with the pre-proof authoritative-commit workflow. A durable
// v1 ticket/artifact must be restarted instead of being silently interpreted as a staged entry.
const CLOSE_FUNDING_SCHEMA_VERSION = 2;
const CLOSE_FUNDING_PAYOUT_FILE = 'full_close_funding_payout.json';
const CLOSE_FUNDING_VALIDITY_FILE = 'full_close_funding_validity.json';
const CLOSE_FUNDING_VALIDITY_ACK_FILE = 'full_close_funding_validity_ack.json';

function workflowError(httpStatus, error, detail) {
  const e = new Error(error);
  e.httpStatus = httpStatus;
  e.payload = { error, ...(detail ? { detail } : {}) };
  return e;
}

function canonicalAddress(value, label) {
  const address = String(value || '').trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address) || /^0x0{40}$/.test(address)) {
    throw workflowError(409, `${label} is not a nonzero 20-byte address`);
  }
  return address;
}

function sameHex(left, right) {
  return String(left || '').toLowerCase() === String(right || '').toLowerCase();
}

function canonicalUint(value, label) {
  let parsed;
  try { parsed = BigInt(value); } catch (_) { throw workflowError(502, `${label} is not an unsigned integer`); }
  if (parsed < 0n) throw workflowError(502, `${label} is negative`);
  return parsed.toString();
}

function anchorFromProducerStatus(status) {
  if (!status || typeof status !== 'object') {
    throw workflowError(503, 'block producer status is unavailable');
  }
  return {
    generation: Number(status.generation),
    entryHash: String(status.journalHead || '').toLowerCase(),
    blockNumber: Number(status.blockNumber),
    timestamp: Number(status.timestamp),
    extendedStateCommitment: String(status.extendedStateCommitment || '').toLowerCase(),
    bpSigChain: String(status.bpSigChain || '').toLowerCase(),
  };
}

function validAnchor(anchor) {
  return anchor
    && Number.isSafeInteger(anchor.generation) && anchor.generation >= 0
    && Number.isSafeInteger(anchor.blockNumber) && anchor.blockNumber >= 0
    && Number.isSafeInteger(anchor.timestamp) && anchor.timestamp >= 0
    && /^0x[0-9a-f]{64}$/.test(String(anchor.entryHash || ''))
    && /^0x[0-9a-f]{64}$/.test(String(anchor.extendedStateCommitment || ''))
    && /^0x[0-9a-f]{64}$/.test(String(anchor.bpSigChain || ''));
}

function sameAnchor(left, right) {
  return validAnchor(left) && validAnchor(right)
    && left.generation === Number(right.generation)
    && sameHex(left.entryHash, right.entryHash)
    && left.blockNumber === Number(right.blockNumber)
    && left.timestamp === Number(right.timestamp)
    && sameHex(left.extendedStateCommitment, right.extendedStateCommitment)
    && sameHex(left.bpSigChain, right.bpSigChain);
}

async function terminalReadiness() {
  // `validityStatus` performs the daemon's configured-RPC canonical/finalized read-back before it
  // returns. The two snapshots must name one identical journal head and there must be no pending
  // candidate. The daemon repeats this test atomically with NEW terminal staging; this API check
  // prevents asking members to sign a transition that is already doomed.
  const producerStatus = await producer.status();
  const validityStatus = await producer.validityStatus();
  const current = anchorFromProducerStatus(producerStatus);
  const finalized = validityStatus && validityStatus.finalizedAnchor;
  if (producerStatus.holdsLocalSigningKeys) {
    throw workflowError(503, 'production block producer unexpectedly owns channel signing keys');
  }
  if (validityStatus && validityStatus.candidate) {
    throw workflowError(409, 'finalize or discard the existing validity candidate before terminal funding');
  }
  if (!sameAnchor(current, finalized)
      || Number(validityStatus && validityStatus.finalizedBlockNumber) !== current.blockNumber
      || !sameHex(validityStatus && validityStatus.finalizedExtendedStateCommitment,
        current.extendedStateCommitment)) {
    throw workflowError(
      409,
      'terminal close funding requires the producer head to be fully finalized on L1',
      'Finalize and acknowledge every earlier producer block first. The terminal transition must be the sole next block.',
    );
  }
  return current;
}

function forbidCallerAuthority(body, allowed) {
  const input = body && typeof body === 'object' ? body : {};
  const forbidden = Object.keys(input).filter(field => !allowed.includes(field));
  if (forbidden.length) {
    throw workflowError(
      400,
      `caller-supplied close-funding authority is forbidden: ${forbidden.join(', ')}`,
      'The API derives every field except the explicitly requested signed handoff or transaction locator from durable local/RPC authorities.',
    );
  }
}

// Re-read all economic bindings at every phase. settlement.json is the ACTIVE deployment record,
// channel_backing.json pins the rollup that actually escrows this channel, and chainId() is read
// from the configured RPC. A ticket merely remembers this tuple; it never overrides it.
function trustedSettlementBinding(ch) {
  let settlement;
  try {
    settlement = readJson(wc(ch, 'settlement.json'));
  } catch (error) {
    throw workflowError(409, 'terminal close funding requires a durable settlement.json');
  }
  const rpcChainId = chainId();
  if (!Number.isSafeInteger(rpcChainId) || rpcChainId <= 0) {
    throw workflowError(503, 'configured RPC returned an unsafe chain id');
  }
  let backingRollup;
  try {
    backingRollup = canonicalAddress(rollupOf(ch), 'channel backing rollup');
  } catch (error) {
    if (error && error.payload) throw error;
    throw workflowError(409, 'channel backing does not pin a rollup');
  }
  const settlementRollup = canonicalAddress(settlement && settlement.rollup, 'settlement rollup');
  if (settlementRollup !== backingRollup) {
    throw workflowError(
      409,
      'settlement rollup differs from the channel backing rollup',
      `settlement=${settlementRollup}, backing=${backingRollup}`,
    );
  }
  const manager = canonicalAddress(settlement && settlement.manager, 'settlement manager');
  const verifier = canonicalAddress(settlement && settlement.verifier, 'settlement verifier');
  const materializer = canonicalAddress(
    settlement && (settlement.close_funding_materializer || settlement.closeFundingMaterializer),
    'close-funding materializer',
  );

  // Production settlement activation is finalized-head bound. Reject an old/copied convenience
  // file even when its addresses happen to look valid.
  if (rpcChainId !== DEVNET_CHAIN_ID) {
    const checkpoint = settlement.activation_checkpoint || settlement.activationCheckpoint;
    if (!checkpoint || Number(checkpoint.chainId) !== rpcChainId || checkpoint.source !== 'rpcFinalized') {
      throw workflowError(
        409,
        'production settlement.json lacks an RPC-finalized activation binding for this chain',
      );
    }
  }
  let durable;
  try {
    durable = verifyActiveSettlementBinding(ch, settlement);
  } catch (error) {
    throw workflowError(
      409,
      'durable ACTIVE settlement binding could not be revalidated',
      String(error && (error.stderr || error.message) || error),
    );
  }
  if (!durable
      || Number(durable.chainId) !== rpcChainId
      || Number(durable.channelId) !== ch
      || canonicalAddress(durable.rollup, 'durable rollup') !== backingRollup
      || canonicalAddress(durable.manager, 'durable manager') !== manager
      || canonicalAddress(durable.verifier, 'durable verifier') !== verifier
      || canonicalAddress(
        durable.closeFundingMaterializer,
        'durable close-funding materializer',
      ) !== materializer) {
    throw workflowError(
      409,
      'durable ACTIVE settlement authority differs from settlement.json/RPC/channel binding',
    );
  }
  if (rpcChainId !== DEVNET_CHAIN_ID) {
    const checkpoint = settlement.activation_checkpoint || settlement.activationCheckpoint;
    if (!sameJson(durable.activationCheckpoint, checkpoint)) {
      throw workflowError(409, 'settlement activation checkpoint differs from durable ACTIVE authority');
    }
  }
  return {
    chainId: rpcChainId, rollup: backingRollup, manager, verifier, materializer,
  };
}

function proposalHash(proposal) {
  return producer.stableRequestId('close-funding-proposal', proposal);
}

function validateProposal(proposal, binding, ch) {
  if (!proposal || typeof proposal !== 'object' || !proposal.plan || !proposal.proposedState) {
    throw workflowError(502, 'live close-funding authority returned a malformed proposal');
  }
  const { plan, proposedState } = proposal;
  if (Number(plan.chainId) !== binding.chainId
      || canonicalAddress(plan.rollup, 'proposal rollup') !== binding.rollup
      || canonicalAddress(plan.manager, 'proposal manager') !== binding.manager
      || Number(plan.sourceChannelId) !== ch
      || Number(proposedState.channelId) !== ch) {
    throw workflowError(502, 'live close-funding proposal diverges from the trusted settlement binding');
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(plan.planDigest || ''))) {
    throw workflowError(502, 'live close-funding proposal has no canonical plan digest');
  }
  if (!Array.isArray(proposedState.memberSignatures) || proposedState.memberSignatures.length !== 0) {
    throw workflowError(502, 'close-funding preparation must return an unsigned proposed state');
  }
  return proposal;
}

function sameJson(left, right) {
  return producer.canonicalJson(left) === producer.canonicalJson(right);
}

function assertPinnedBinding(closeFunding, binding, ch) {
  if (!closeFunding || closeFunding.schemaVersion !== CLOSE_FUNDING_SCHEMA_VERSION) {
    throw workflowError(409, 'prepare terminal close funding before submitting signatures');
  }
  if (closeFunding.channelId !== ch
      || closeFunding.chainId !== binding.chainId
      || closeFunding.rollup !== binding.rollup
      || closeFunding.manager !== binding.manager
      || closeFunding.verifier !== binding.verifier
      || closeFunding.materializer !== binding.materializer) {
    throw workflowError(409, 'trusted settlement/RPC binding changed after close-funding preparation');
  }
  if (!validAnchor(closeFunding.readinessAnchor)) {
    throw workflowError(409, 'close-funding ticket has no valid fully-finalized readiness anchor');
  }
  validateProposal(closeFunding.proposal, binding, ch);
  if (closeFunding.proposalHash !== proposalHash(closeFunding.proposal)) {
    throw workflowError(409, 'durable close-funding proposal no longer matches its ticket fingerprint');
  }
}

function requirePinnedCloseFunding(ch) {
  const ticket = findActiveTicket(ch, 'full_withdrawal');
  if (!ticket) throw workflowError(409, 'start a full-withdrawal ticket first');
  const binding = trustedSettlementBinding(ch);
  const closeFunding = ticket.params && ticket.params.closeFunding;
  assertPinnedBinding(closeFunding, binding, ch);
  return { ticket, binding, closeFunding };
}

function validateSignedHandoff(signedState, proposedState) {
  if (!signedState || typeof signedState !== 'object') {
    throw workflowError(400, 'needs { signedState } from the detached N-of-N signing handoff');
  }
  if (!Array.isArray(signedState.memberSignatures) || signedState.memberSignatures.length === 0) {
    throw workflowError(400, 'signedState must carry the detached member signatures');
  }
  const unsigned = { ...signedState, memberSignatures: [] };
  if (!sameJson(unsigned, proposedState)) {
    throw workflowError(409, 'signedState is not the exact prepared terminal child');
  }
}

function verifyStagedProducerReceipt(receipt, requestId, readinessAnchor) {
  if (!receipt || receipt.requestId !== requestId || !validAnchor(receipt)
      || Number(receipt.generation) !== Number(readinessAnchor.generation) + 1
      || Number(receipt.blockNumber) !== Number(readinessAnchor.blockNumber) + 1
      || Number(receipt.timestamp) <= Number(readinessAnchor.timestamp)
      || sameHex(receipt.entryHash, readinessAnchor.entryHash)
      || sameHex(receipt.extendedStateCommitment,
        readinessAnchor.extendedStateCommitment)) {
    throw workflowError(502, 'block producer staged a different terminal entry/anchor');
  }
  return receipt;
}

function verifyLiveReceipt(receipt, producerReceipt) {
  if (!receipt || !producerReceipt
      || receipt.producerRequestId !== producerReceipt.requestId
      || Number(receipt.producerGeneration) !== Number(producerReceipt.generation)
      || !sameHex(receipt.producerEntryHash, producerReceipt.entryHash)
      || !sameHex(receipt.producerExtendedStateCommitment,
        producerReceipt.extendedStateCommitment)) {
    throw workflowError(502, 'live balance service settled a different committed producer anchor');
  }
}

function validateFinalizationReceipt(
  receipt, acknowledgementRequestId, txHash, validityEnvelope, closeFunding,
) {
  const committed = receipt && receipt.committedProducerReceipt;
  const l1 = receipt && receipt.l1Acknowledgement;
  if (!receipt || receipt.requestId !== acknowledgementRequestId
      || receipt.candidateId !== validityEnvelope.candidateReceipt.candidateId
      || Number(receipt.finalizedBlockNumber)
        !== Number(validityEnvelope.candidateReceipt.finalBlockNumber)
      || !sameHex(receipt.finalExtendedStateCommitment,
        validityEnvelope.candidateReceipt.finalExtendedStateCommitment)
      || !sameAnchor(receipt.producerAnchor, closeFunding.stagedProducerReceipt)
      || !l1 || Number(l1.chainId) !== Number(closeFunding.chainId)
      || !sameHex(l1.transactionHash, txHash)
      || !/^0x[0-9a-fA-F]{64}$/.test(String(l1.blockHash || ''))
      || !Number.isSafeInteger(Number(l1.blockNumber)) || Number(l1.blockNumber) < 0
      || !sameHex(l1.finalExtendedStateCommitment,
        validityEnvelope.candidateReceipt.finalExtendedStateCommitment)
      || !committed
      || !sameJson(committed, closeFunding.stagedProducerReceipt)) {
    throw workflowError(
      502,
      'validity finalization did not commit the exact staged terminal producer entry',
    );
  }
  return receipt;
}

function acknowledgementHash(envelope) {
  return producer.stableRequestId('close-funding-validity-acknowledgement-v2', {
    channelId: envelope.channelId,
    chainId: envelope.chainId,
    rollup: envelope.rollup,
    manager: envelope.manager,
    verifier: envelope.verifier,
    materializer: envelope.materializer,
    proposalHash: envelope.proposalHash,
    producerRequestId: envelope.producerRequestId,
    acknowledgementRequestId: envelope.acknowledgementRequestId,
    candidateId: envelope.candidateId,
    transactionHash: envelope.transactionHash,
    receipt: envelope.receipt,
  });
}

function validateAcknowledgementEnvelope(
  envelope, closeFunding, binding, validityEnvelope, expectedTxHash,
) {
  if (!envelope || envelope.schemaVersion !== CLOSE_FUNDING_SCHEMA_VERSION
      || envelope.channelId !== closeFunding.channelId
      || envelope.chainId !== binding.chainId
      || envelope.rollup !== binding.rollup
      || envelope.manager !== binding.manager
      || envelope.verifier !== binding.verifier
      || envelope.materializer !== binding.materializer
      || envelope.proposalHash !== closeFunding.proposalHash
      || envelope.producerRequestId !== closeFunding.producerRequestId
      || envelope.candidateId !== validityEnvelope.candidateReceipt.candidateId
      || (expectedTxHash && !sameHex(envelope.transactionHash, expectedTxHash))
      || typeof envelope.acknowledgementRequestId !== 'string') {
    throw workflowError(409, 'durable validity finalization differs from the pinned terminal transition');
  }
  validateFinalizationReceipt(
    envelope.receipt,
    envelope.acknowledgementRequestId,
    envelope.transactionHash,
    validityEnvelope,
    closeFunding,
  );
  if (envelope.artifactHash !== acknowledgementHash(envelope)) {
    throw workflowError(409, 'durable validity finalization fingerprint mismatch');
  }
  return envelope;
}

function requireLegacyDevnet() {
  const id = chainId();
  if (id !== DEVNET_CHAIN_ID) {
    throw workflowError(
      409,
      'legacy full-withdrawal CLI flow is disabled on public chains',
      'Use /close-funding/prepare, stage signatures with /close-funding/commit, prove/acknowledge validity, then request payout artifacts.',
    );
  }
}

function validatePayoutEnvelope(envelope, closeFunding, binding) {
  if (!envelope || envelope.schemaVersion !== CLOSE_FUNDING_SCHEMA_VERSION
      || envelope.channelId !== closeFunding.channelId
      || envelope.chainId !== binding.chainId
      || envelope.rollup !== binding.rollup
      || envelope.manager !== binding.manager
      || envelope.verifier !== binding.verifier
      || envelope.materializer !== binding.materializer
      || envelope.proposalHash !== closeFunding.proposalHash
      || envelope.producerRequestId !== closeFunding.producerRequestId
      || envelope.validityAcknowledgementHash !== closeFunding.validityAcknowledgementHash
      || !closeFunding.committedProducerReceipt
      || !sameJson(closeFunding.committedProducerReceipt, closeFunding.stagedProducerReceipt)
      || !envelope.artifacts
      || !sameHex(envelope.artifacts.planDigest, closeFunding.proposal.plan.planDigest)) {
    throw workflowError(409, 'durable close-funding payout artifact does not match the pinned terminal transition');
  }
  const expectedHash = producer.stableRequestId('close-funding-payout', envelope.artifacts);
  if (envelope.artifactHash !== expectedHash) {
    throw workflowError(409, 'durable close-funding payout artifact fingerprint mismatch');
  }
  validatePayoutArtifacts(envelope.artifacts, closeFunding, envelope.withdrawalProver);
  return envelope;
}

function validatePayoutArtifacts(artifacts, closeFunding, withdrawalProver) {
  const plan = closeFunding.proposal.plan;
  if (!artifacts || !Array.isArray(artifacts.lanes)
      || artifacts.lanes.length < 1 || artifacts.lanes.length > 2
      || !sameHex(artifacts.planDigest, plan.planDigest)
      || !sameHex(artifacts.fundingAuxData, plan.fundingAuxData)) {
    throw workflowError(502, 'close-funding payout lanes do not bind the exact terminal plan');
  }
  const expected = new Map();
  for (const transfer of plan.transfers || []) {
    const token = Number(transfer.tokenIndex);
    if (!Number.isSafeInteger(token) || token < 0 || token > 0xffffffff || expected.has(token)) {
      throw workflowError(502, 'terminal plan has an invalid or duplicate base-token index');
    }
    expected.set(token, canonicalUint(transfer.amount, 'terminal transfer amount'));
  }
  if (expected.size === 0) throw workflowError(502, 'terminal plan has no nonzero transfer');

  const observed = new Map();
  for (const lane of artifacts.lanes) {
    if (!lane || !['native', 'erc20'].includes(lane.lane)
        || !Array.isArray(lane.withdrawals) || lane.withdrawals.length === 0
        || canonicalAddress(lane.withdrawalProver, 'payout withdrawal prover')
          !== canonicalAddress(withdrawalProver, 'configured withdrawal prover')) {
      throw workflowError(502, 'close-funding payout lane is malformed');
    }
    if (!sameAnchor(lane.producerAnchor, closeFunding.committedProducerReceipt)) {
      throw workflowError(502, 'close-funding payout lane is for a different producer anchor');
    }
    let payout;
    try { payout = JSON.parse(lane.payoutJson); } catch (_) {
      throw workflowError(502, 'close-funding payout lane contains malformed payout JSON');
    }
    if (!Array.isArray(payout.withdrawals)
        || payout.withdrawals.length !== lane.withdrawals.length
        || canonicalAddress(payout.withdrawal_prover, 'payout JSON prover')
          !== canonicalAddress(withdrawalProver, 'configured withdrawal prover')
        || Number(payout.block_number) !== closeFunding.committedProducerReceipt.blockNumber
        || !sameHex(payout.ext_commitment,
          closeFunding.committedProducerReceipt.extendedStateCommitment)) {
      throw workflowError(502, 'payout JSON diverges from its lane or terminal producer anchor');
    }
    for (let i = 0; i < lane.withdrawals.length; i += 1) {
      const withdrawal = lane.withdrawals[i];
      const encoded = payout.withdrawals[i];
      const token = Number(withdrawal.tokenIndex);
      const amount = canonicalUint(withdrawal.amount, 'proved withdrawal amount');
      const encodedToken = Number(encoded && encoded.token_index);
      if (!Number.isSafeInteger(token) || token < 0 || token > 0xffffffff
          || observed.has(token)
          || (lane.lane === 'native' ? token !== 0 : token === 0)
          || encodedToken !== token
          || canonicalUint(encoded && encoded.amount, 'payout JSON amount') !== amount
          || canonicalAddress(withdrawal.recipient, 'proved withdrawal recipient') !== closeFunding.manager
          || canonicalAddress(encoded && encoded.recipient, 'payout JSON recipient') !== closeFunding.manager
          || !sameHex(withdrawal.nullifier, encoded && encoded.nullifier)
          || !sameHex(withdrawal.auxData, plan.fundingAuxData)
          || !sameHex(encoded && encoded.aux_data, plan.fundingAuxData)) {
        throw workflowError(502, 'proved payout leaf diverges from its exact terminal plan/JSON lane');
      }
      observed.set(token, amount);
    }
  }
  if (observed.size !== expected.size) {
    throw workflowError(502, 'proved payout lanes do not cover the complete terminal fund vector');
  }
  for (const [token, amount] of expected) {
    if (observed.get(token) !== amount) {
      throw workflowError(502, `proved payout amount for token ${token} differs from the terminal plan`);
    }
  }
}

function assertCandidateReceipt(receipt, closeFunding, requestId) {
  if (!receipt || receipt.requestId !== requestId
      || !/^0x[0-9a-fA-F]{64}$/.test(String(receipt.candidateId || ''))
      || Number(receipt.initialBlockNumber) + 1 !== Number(receipt.finalBlockNumber)
      || Number(receipt.initialBlockNumber) !== Number(closeFunding.readinessAnchor.blockNumber)
      || Number(receipt.finalBlockNumber) !== Number(closeFunding.stagedProducerReceipt.blockNumber)
      || Number(receipt.metrics && receipt.metrics.blockCount) !== 1
      || !sameAnchor(receipt.producerAnchor, closeFunding.stagedProducerReceipt)
      || !sameHex(receipt.initialExtendedStateCommitment,
        closeFunding.readinessAnchor.extendedStateCommitment)
      || !sameHex(receipt.finalExtendedStateCommitment,
        closeFunding.stagedProducerReceipt.extendedStateCommitment)) {
    throw workflowError(
      502,
      'validity prover did not bind the sole terminal block/producer anchor',
    );
  }
  return receipt;
}

function validateValidityEnvelope(envelope, closeFunding, binding) {
  if (!envelope || envelope.schemaVersion !== CLOSE_FUNDING_SCHEMA_VERSION
      || envelope.channelId !== closeFunding.channelId
      || envelope.chainId !== binding.chainId
      || envelope.rollup !== binding.rollup
      || envelope.manager !== binding.manager
      || envelope.verifier !== binding.verifier
      || envelope.materializer !== binding.materializer
      || envelope.proposalHash !== closeFunding.proposalHash
      || envelope.producerRequestId !== closeFunding.producerRequestId
      || typeof envelope.candidateRequestId !== 'string') {
    throw workflowError(409, 'durable validity artifact does not match terminal close funding');
  }
  const receipt = assertCandidateReceipt(
    envelope.candidateReceipt, closeFunding, envelope.candidateRequestId,
  );
  const posting = envelope.postingArtifact;
  if (!posting || !sameJson(posting.receipt, receipt)
      || !Array.isArray(posting.subBlocks) || posting.subBlocks.length !== 1
      || !/^0x[0-9a-fA-F]{64}$/.test(String(posting.expectedPendingChains || ''))) {
    throw workflowError(409, 'validity posting artifact is not the exact one-block candidate');
  }
  const block = posting.subBlocks[0];
  if (Number(block.channelId) !== closeFunding.channelId
      || Number(block.timestamp) !== Number(closeFunding.stagedProducerReceipt.timestamp)
      || !sameHex(block.txTreeRoot, closeFunding.proposal.plan.txTreeRoot)
      || !sameHex(block.txTreeRoot, closeFunding.signedState && closeFunding.signedState.h2Tag)
      || !Number.isSafeInteger(Number(block.numUsers)) || Number(block.numUsers) <= 0
      || !Array.isArray(block.keyIds) || block.keyIds.length === 0
      || block.keyIds.length !== Number(block.numUsers)
      || block.keyIds.some(value => !Number.isSafeInteger(Number(value))
        || Number(value) < 0 || Number(value) > 0xffffffff)
      || !/^0x[0-9a-fA-F]{64}$/.test(String(block.depositHashChain || ''))
      || !/^0x[0-9a-fA-F]{64}$/.test(String(block.channelRegHashChain || ''))) {
    throw workflowError(409, 'posted SubBlock diverges from the signed terminal child');
  }
  const finalize = envelope.finalizeArtifact;
  let vpis;
  try { vpis = JSON.parse(finalize && finalize.vpisJson); } catch (_) {
    throw workflowError(409, 'validity finalize artifact contains malformed public inputs');
  }
  if (!finalize || typeof finalize.validityMleJson !== 'string'
      || finalize.validityMleJson.length === 0
      || !sameHex(finalize.finalStateRoot, receipt.finalExtendedStateCommitment)
      || Number(vpis.initial_block_number) !== Number(receipt.initialBlockNumber)
      || Number(vpis.final_block_number) !== Number(receipt.finalBlockNumber)
      || !sameHex(vpis.initial_ext_commitment, receipt.initialExtendedStateCommitment)
      || !sameHex(vpis.final_ext_commitment, receipt.finalExtendedStateCommitment)) {
    throw workflowError(409, 'validity finalize proof/public inputs diverge from the candidate');
  }
  const expectedHash = producer.stableRequestId('close-funding-validity-artifact', {
    candidateReceipt: envelope.candidateReceipt,
    postingArtifact: envelope.postingArtifact,
    finalizeArtifact: envelope.finalizeArtifact,
  });
  if (envelope.artifactHash !== expectedHash) {
    throw workflowError(409, 'durable validity artifact fingerprint mismatch');
  }
  return envelope;
}

// POST /api/v1/channel/:ch/full-withdrawal/start (W10 — returns ticket for tracking)
router.post('/start', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    let ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) {
      return res.json({ ticketId: ticket.id, ticket });
    }
    ticket = upsertTicket(ch, {
      id: 'fw_' + Date.now(),
      type: 'full_withdrawal',
      status: 'started',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      params: {},
      steps: {
        deploy: null,
        terminalCloseProposal: null,
        terminalProducerStaging: null,
        terminalValidity: null,
        terminalProducerFinalization: null,
        terminalLiveSettlement: null,
        payoutArtifacts: null,
        close: null,
        settle: null,
        withdraw: null,
        claim: null,
      },
    });
    res.json({ ticketId: ticket.id, ticket });
  }).catch(e => {
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// GET /api/v1/channel/:ch/full-withdrawal/status (W10)
router.get('/status', (req, res) => {
  const ch = Number(req.params.ch);
  const ticket = findActiveTicket(ch, 'full_withdrawal');
  if (!ticket) {
    return res.status(404).json({ error: 'no active full withdrawal' });
  }
  res.json({ step: ticket.status, canProceed: true, ticket });
});

// POST /api/v1/channel/:ch/full-withdrawal/deploy (W10 step 1)
router.post('/deploy', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    if (fs.existsSync(wc(ch, 'settlement.json'))) {
      const s = readJson(wc(ch, 'settlement.json'));
      let ticket = findActiveTicket(ch, 'full_withdrawal');
      if (ticket) {
        ticket.status = 'deploy_done';
        ticket.params.manager = s.manager;
        ticket.params.verifier = s.verifier;
        ticket.steps.deploy = { completedAt: Date.now(), manager: s.manager, verifier: s.verifier };
        upsertTicket(ch, ticket);
      }
      return res.json({ manager: s.manager, verifier: s.verifier });
    }
    // anvil: deploys as before. Real chain: throws a structured 409 naming the operator task —
    // the settlement stack must exist before the channel is funded (see lib/cli.ensureSettlement).
    const s = ensureSettlement(ch);
    let ticket = findActiveTicket(ch, 'full_withdrawal');
    if (!ticket) {
      ticket = {
        id: 'fw_' + Date.now(),
        type: 'full_withdrawal',
        status: 'deploy_done',
        createdAt: Date.now(),
        updatedAt: Date.now(),
        params: { manager: s.manager, verifier: s.verifier },
        steps: {
          deploy: { completedAt: Date.now(), manager: s.manager, verifier: s.verifier },
          terminalCloseProposal: null,
          terminalProducerStaging: null,
          terminalValidity: null,
          terminalProducerFinalization: null,
          terminalLiveSettlement: null,
          payoutArtifacts: null,
          close: null,
          settle: null,
          withdraw: null,
          claim: null,
        },
      };
    } else {
      ticket.status = 'deploy_done';
      ticket.params.manager = s.manager;
      ticket.params.verifier = s.verifier;
      ticket.steps.deploy = { completedAt: Date.now(), manager: s.manager, verifier: s.verifier };
    }
    upsertTicket(ch, ticket);
    res.json({ manager: s.manager, verifier: s.verifier });
  }).catch(e => failRoute(res, e));
});

// Production terminal-funding phase 1. The caller receives exactly one unsigned child to pass to
// detached N-of-N signers. No request body field is allowed to choose an economic binding.
router.post('/close-funding/prepare', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    forbidCallerAuthority(req.body, []);
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (!ticket) throw workflowError(409, 'start a full-withdrawal ticket first');
    const binding = trustedSettlementBinding(ch);
    const persisted = ticket.params && ticket.params.closeFunding;
    if (persisted) {
      assertPinnedBinding(persisted, binding, ch);
      if (!persisted.signedState) {
        const readinessAnchor = await terminalReadiness();
        if (!sameAnchor(readinessAnchor, persisted.readinessAnchor)) {
          throw workflowError(
            409,
            'producer/L1 head changed after terminal close-funding preparation',
            'Discard the unsigned handoff and prepare again from the new fully finalized channel head.',
          );
        }
      }
      return res.json({
        ticketId: ticket.id,
        status: ticket.status,
        proposalHash: persisted.proposalHash,
        proposal: persisted.proposal,
      });
    }
    if (!['started', 'deploy_done'].includes(ticket.status)) {
      throw workflowError(
        409,
        `cannot prepare terminal funding from full-withdrawal state ${ticket.status}`,
        'Resolve the already-started legacy/close operation before creating a terminal child.',
      );
    }

    const readinessAnchor = await terminalReadiness();
    const proposal = validateProposal(
      await producer.livePrepareCloseFunding(ch, binding.chainId, binding.rollup, binding.manager),
      binding,
      ch,
    );
    const preparedAt = Date.now();
    const closeFunding = {
      schemaVersion: CLOSE_FUNDING_SCHEMA_VERSION,
      channelId: ch,
      ...binding,
      proposalHash: proposalHash(proposal),
      proposal,
      readinessAnchor,
      signedState: null,
      producerRequestId: null,
      stagedProducerReceipt: null,
      committedProducerReceipt: null,
      validityArtifactHash: null,
      validityCandidateId: null,
      validityFinalizationReceipt: null,
      validityAcknowledgementHash: null,
      liveReceipt: null,
      payoutArtifactHash: null,
      preparedAt,
    };
    ticket.params = {
      ...(ticket.params || {}),
      // Retain these convenience fields for the devnet UI, but source them only from the trusted
      // settlement record. Later phases exclusively use closeFunding's pinned tuple.
      manager: binding.manager,
      closeFunding,
    };
    ticket.steps = {
      ...(ticket.steps || {}),
      terminalCloseProposal: { preparedAt },
      terminalProducerStaging: null,
      terminalValidity: null,
      terminalProducerFinalization: null,
      terminalLiveSettlement: null,
      payoutArtifacts: null,
    };
    ticket.status = 'close_funding_signatures_pending';
    upsertTicket(ch, ticket);
    res.json({
      ticketId: ticket.id,
      status: ticket.status,
      proposalHash: closeFunding.proposalHash,
      proposal,
    });
  }).catch(e => failRoute(res, e));
});

// Production terminal-funding phase 2. Despite the compatibility URL, this endpoint only stages
// the exact N-of-N signed terminal child. It does not advance the authoritative producer and does
// not settle the live balance. The staged daemon receipt is the sole input to validity proving.
router.post('/close-funding/commit', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    forbidCallerAuthority(req.body, ['signedState']);
    const submittedState = req.body && req.body.signedState;
    const { ticket, closeFunding } = requirePinnedCloseFunding(ch);
    validateSignedHandoff(submittedState, closeFunding.proposal.proposedState);

    if (closeFunding.signedState && !sameJson(closeFunding.signedState, submittedState)) {
      throw workflowError(409, 'close-funding ticket is already pinned to a different signed handoff');
    }
    const signedState = closeFunding.signedState || submittedState;
    const producerRequestId = closeFunding.producerRequestId
      || producer.stableRequestId('close-funding-stage-v2', {
        signedState,
        plan: closeFunding.proposal.plan,
      });
    // Do not pin signature bytes until the daemon has checked the exact transition and N-of-N
    // signatures. A crash after daemon staging but before this ticket write is recovered by the
    // content-addressed prepare replay; neither path can perform an authoritative commit.
    let stagedProducerReceipt = closeFunding.stagedProducerReceipt;
    if (!stagedProducerReceipt) {
      stagedProducerReceipt = await producer.prepareCloseFunding(
        signedState,
        closeFunding.proposal.plan,
        producerRequestId,
      );
    }
    verifyStagedProducerReceipt(
      stagedProducerReceipt,
      producerRequestId,
      closeFunding.readinessAnchor,
    );
    if (closeFunding.stagedProducerReceipt
        && !sameJson(closeFunding.stagedProducerReceipt, stagedProducerReceipt)) {
      throw workflowError(502, 'idempotent producer staging returned a different receipt');
    }
    if (closeFunding.committedProducerReceipt
        && !sameJson(closeFunding.committedProducerReceipt, stagedProducerReceipt)) {
      throw workflowError(409, 'finalized producer receipt differs from the staged terminal entry');
    }
    closeFunding.signedState = signedState;
    closeFunding.producerRequestId = producerRequestId;
    closeFunding.stagedProducerReceipt = stagedProducerReceipt;
    if (ticket.status === 'close_funding_signatures_pending') {
      ticket.status = 'close_funding_producer_staged';
    }
    ticket.steps = {
      ...(ticket.steps || {}),
      terminalProducerStaging: {
        stagedAt: ticket.steps && ticket.steps.terminalProducerStaging
          && ticket.steps.terminalProducerStaging.stagedAt || Date.now(),
        producerRequestId,
        entryHash: stagedProducerReceipt.entryHash,
      },
    };
    upsertTicket(ch, ticket);
    res.json({ ticketId: ticket.id, status: ticket.status, stagedProducerReceipt });
  }).catch(e => failRoute(res, e));
});

// Production terminal-funding phase 5. The daemon generates the existing withdrawal/MLE proof
// shapes only after finalized validity, authoritative producer commit, and live settlement. The
// payout prover is the configured operator signer, never
// a caller-selected address. The complete artifact is atomically staged before the ticket points
// to it, so a crash at either side of that rename is safely recoverable.
router.post('/close-funding/payout-artifacts', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    forbidCallerAuthority(req.body, []);
    const { ticket, binding, closeFunding } = requirePinnedCloseFunding(ch);
    if (!closeFunding.validityFinalizationReceipt
        || !closeFunding.committedProducerReceipt
        || !closeFunding.liveReceipt
        || !closeFunding.producerRequestId) {
      throw workflowError(
        409,
        'finalize validity, commit the staged producer entry, and settle live funding before payout artifacts',
      );
    }
    if (!sameJson(closeFunding.committedProducerReceipt, closeFunding.stagedProducerReceipt)) {
      throw workflowError(409, 'committed producer receipt differs from the staged terminal entry');
    }
    const validityPath = wc(ch, CLOSE_FUNDING_VALIDITY_FILE);
    const ackPath = wc(ch, CLOSE_FUNDING_VALIDITY_ACK_FILE);
    if (!fs.existsSync(validityPath) || !fs.existsSync(ackPath)) {
      throw workflowError(409, 'durable terminal validity/finalization artifacts are unavailable');
    }
    const validityEnvelope = validateValidityEnvelope(
      readJson(validityPath), closeFunding, binding,
    );
    const acknowledgement = validateAcknowledgementEnvelope(
      readJson(ackPath), closeFunding, binding, validityEnvelope,
      closeFunding.validityFinalizationReceipt.l1Acknowledgement
        && closeFunding.validityFinalizationReceipt.l1Acknowledgement.transactionHash,
    );
    if (!sameJson(acknowledgement.receipt, closeFunding.validityFinalizationReceipt)
        || closeFunding.validityAcknowledgementHash !== acknowledgement.artifactHash) {
      throw workflowError(409, 'ticket validity finalization differs from its durable artifact');
    }
    const withdrawalProver = canonicalAddress(l1SignerAddress(), 'configured withdrawal prover');
    const artifactPath = wc(ch, CLOSE_FUNDING_PAYOUT_FILE);

    if (fs.existsSync(artifactPath)) {
      const envelope = validatePayoutEnvelope(readJson(artifactPath), closeFunding, binding);
      if (canonicalAddress(envelope.withdrawalProver, 'durable withdrawal prover')
          !== withdrawalProver) {
        throw workflowError(409, 'configured withdrawal prover changed after payout generation');
      }
      if (closeFunding.payoutArtifactHash
          && closeFunding.payoutArtifactHash !== envelope.artifactHash) {
        throw workflowError(409, 'ticket payout fingerprint differs from the durable artifact');
      }
      closeFunding.payoutArtifactHash = envelope.artifactHash;
      closeFunding.withdrawalProver = withdrawalProver;
      ticket.status = 'close_funding_payout_ready';
      ticket.steps = {
        ...(ticket.steps || {}),
        payoutArtifacts: {
          completedAt: ticket.steps && ticket.steps.payoutArtifacts
            && ticket.steps.payoutArtifacts.completedAt || Date.now(),
          artifactHash: envelope.artifactHash,
        },
      };
      upsertTicket(ch, ticket);
      return res.json({ ticketId: ticket.id, status: ticket.status, artifacts: envelope.artifacts });
    }

    ticket.status = 'close_funding_payout_proving';
    upsertTicket(ch, ticket);
    const artifacts = await producer.liveCloseFundingPayoutArtifacts(
      ch,
      closeFunding.producerRequestId,
      withdrawalProver,
    );
    if (!artifacts || !sameHex(artifacts.planDigest, closeFunding.proposal.plan.planDigest)) {
      throw workflowError(502, 'live payout artifacts do not match the pinned close-funding plan');
    }
    const envelope = {
      schemaVersion: CLOSE_FUNDING_SCHEMA_VERSION,
      channelId: ch,
      ...binding,
      proposalHash: closeFunding.proposalHash,
      producerRequestId: closeFunding.producerRequestId,
      validityAcknowledgementHash: closeFunding.validityAcknowledgementHash,
      withdrawalProver,
      artifactHash: producer.stableRequestId('close-funding-payout', artifacts),
      artifacts,
    };
    writeJson(artifactPath, envelope);
    closeFunding.payoutArtifactHash = envelope.artifactHash;
    closeFunding.withdrawalProver = withdrawalProver;
    ticket.status = 'close_funding_payout_ready';
    ticket.steps = {
      ...(ticket.steps || {}),
      payoutArtifacts: { completedAt: Date.now(), artifactHash: envelope.artifactHash },
    };
    upsertTicket(ch, ticket);
    res.json({ ticketId: ticket.id, status: ticket.status, artifacts });
  }).catch(e => failRoute(res, e));
});

// Production terminal-funding phase 3. Prove exactly the staged terminal block after the previously
// L1-finalized producer anchor, before that block becomes authoritative or changes live balances.
// Persist everything an external blob transaction signer needs.
// This route does not broadcast: the signing account remains outside the keyless producer, while
// `/validity-acknowledge` later accepts only a transaction hash and lets the daemon re-read the
// exact canonical/finalized Rollup receipt.
router.post('/close-funding/validity-artifacts', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    forbidCallerAuthority(req.body, []);
    const { ticket, binding, closeFunding } = requirePinnedCloseFunding(ch);
    if (!closeFunding.stagedProducerReceipt || !closeFunding.signedState
        || !closeFunding.producerRequestId) {
      throw workflowError(409, 'stage the signed terminal producer entry before proving validity');
    }
    verifyStagedProducerReceipt(
      closeFunding.stagedProducerReceipt,
      closeFunding.producerRequestId,
      closeFunding.readinessAnchor,
    );

    const artifactPath = wc(ch, CLOSE_FUNDING_VALIDITY_FILE);
    if (fs.existsSync(artifactPath)) {
      const envelope = validateValidityEnvelope(readJson(artifactPath), closeFunding, binding);
      if ((closeFunding.validityArtifactHash
            && closeFunding.validityArtifactHash !== envelope.artifactHash)
          || (closeFunding.validityCandidateId
            && closeFunding.validityCandidateId !== envelope.candidateReceipt.candidateId)) {
        throw workflowError(409, 'ticket validity pin differs from the durable artifact');
      }
      closeFunding.validityArtifactHash = envelope.artifactHash;
      closeFunding.validityCandidateId = envelope.candidateReceipt.candidateId;
      if (!closeFunding.validityFinalizationReceipt && !closeFunding.liveReceipt
          && !closeFunding.payoutArtifactHash) {
        ticket.status = 'close_funding_validity_ready';
      }
      ticket.steps = {
        ...(ticket.steps || {}),
        terminalValidity: {
          ...((ticket.steps && ticket.steps.terminalValidity) || {}),
          provedAt: ticket.steps && ticket.steps.terminalValidity
            && ticket.steps.terminalValidity.provedAt || Date.now(),
          candidateId: envelope.candidateReceipt.candidateId,
          l1FinalizedAt: ticket.steps && ticket.steps.terminalValidity
            && ticket.steps.terminalValidity.l1FinalizedAt || null,
        },
      };
      upsertTicket(ch, ticket);
      return res.json({
        ticketId: ticket.id,
        status: ticket.status,
        candidateId: envelope.candidateReceipt.candidateId,
        postingArtifact: envelope.postingArtifact,
        finalizeArtifact: envelope.finalizeArtifact,
      });
    }

    const candidateRequestId = producer.stableRequestId('close-funding-validity', {
      proposalHash: closeFunding.proposalHash,
      producerRequestId: closeFunding.producerRequestId,
      entryHash: closeFunding.stagedProducerReceipt.entryHash,
    });
    ticket.status = 'close_funding_validity_proving';
    upsertTicket(ch, ticket);
    const candidateReceipt = assertCandidateReceipt(
      await producer.proveValidity(candidateRequestId), closeFunding, candidateRequestId,
    );
    const [postingArtifact, finalizeArtifact] = await Promise.all([
      producer.validityPostingArtifact(),
      producer.validityFinalizeArtifact(),
    ]);
    const envelope = {
      schemaVersion: CLOSE_FUNDING_SCHEMA_VERSION,
      channelId: ch,
      ...binding,
      proposalHash: closeFunding.proposalHash,
      producerRequestId: closeFunding.producerRequestId,
      candidateRequestId,
      candidateReceipt,
      postingArtifact,
      finalizeArtifact,
    };
    envelope.artifactHash = producer.stableRequestId('close-funding-validity-artifact', {
      candidateReceipt,
      postingArtifact,
      finalizeArtifact,
    });
    validateValidityEnvelope(envelope, closeFunding, binding);
    writeJson(artifactPath, envelope);
    closeFunding.validityArtifactHash = envelope.artifactHash;
    closeFunding.validityCandidateId = candidateReceipt.candidateId;
    ticket.status = 'close_funding_validity_ready';
    ticket.steps = {
      ...(ticket.steps || {}),
      terminalValidity: {
        provedAt: Date.now(),
        candidateId: candidateReceipt.candidateId,
        l1FinalizedAt: null,
      },
    };
    upsertTicket(ch, ticket);
    res.json({
      ticketId: ticket.id,
      status: ticket.status,
      candidateId: candidateReceipt.candidateId,
      postingArtifact,
      finalizeArtifact,
    });
  }).catch(e => failRoute(res, e));
});

// Production terminal-funding phase 4. The HTTP boundary accepts only a transaction locator. The
// daemon verifies the canonical finalized Rollup receipt and atomically promotes the exact staged
// producer entry. Only that committed receipt is then allowed to settle live balances. The durable
// acknowledgement file is written before live settlement, so every crash boundary is retryable.
router.post('/close-funding/validity-acknowledge', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body)
      ? req.body : {};
    const unknown = Object.keys(body).filter(key => key !== 'transactionHash');
    if (unknown.length || !/^0x[0-9a-fA-F]{64}$/.test(String(body.transactionHash || ''))) {
      throw workflowError(400, 'needs only { transactionHash } for the finalized Rollup validity transaction');
    }
    const txHash = String(body.transactionHash).toLowerCase();
    const { ticket, binding, closeFunding } = requirePinnedCloseFunding(ch);
    const validityPath = wc(ch, CLOSE_FUNDING_VALIDITY_FILE);
    if (!fs.existsSync(validityPath)) {
      throw workflowError(409, 'generate terminal validity artifacts before acknowledgement');
    }
    const envelope = validateValidityEnvelope(readJson(validityPath), closeFunding, binding);
    if (closeFunding.validityArtifactHash
        && closeFunding.validityArtifactHash !== envelope.artifactHash) {
      throw workflowError(409, 'ticket validity fingerprint differs from the durable artifact');
    }
    if (closeFunding.validityCandidateId
        && closeFunding.validityCandidateId !== envelope.candidateReceipt.candidateId) {
      throw workflowError(409, 'ticket validity candidate differs from the durable artifact');
    }
    closeFunding.validityArtifactHash = envelope.artifactHash;
    closeFunding.validityCandidateId = envelope.candidateReceipt.candidateId;
    const ackPath = wc(ch, CLOSE_FUNDING_VALIDITY_ACK_FILE);
    const acknowledgementRequestId = producer.stableRequestId('close-funding-validity-ack-v2', {
      channelId: ch,
      proposalHash: closeFunding.proposalHash,
      producerRequestId: closeFunding.producerRequestId,
      candidateId: envelope.candidateReceipt.candidateId,
      transactionHash: txHash,
    });
    let stored;
    if (fs.existsSync(ackPath)) {
      stored = validateAcknowledgementEnvelope(
        readJson(ackPath), closeFunding, binding, envelope, txHash,
      );
      if (stored.acknowledgementRequestId !== acknowledgementRequestId) {
        throw workflowError(409, 'validity finalization request fingerprint differs from durable content');
      }
    } else {
      if (closeFunding.validityFinalizationReceipt || closeFunding.validityAcknowledgementHash) {
        throw workflowError(409, 'ticket names a validity finalization whose durable artifact is missing');
      }
      const receipt = validateFinalizationReceipt(
        await producer.acknowledgeValidity(
          acknowledgementRequestId,
          envelope.candidateReceipt.candidateId,
          txHash,
        ),
        acknowledgementRequestId,
        txHash,
        envelope,
        closeFunding,
      );
      stored = {
        schemaVersion: CLOSE_FUNDING_SCHEMA_VERSION,
        channelId: ch,
        ...binding,
        proposalHash: closeFunding.proposalHash,
        producerRequestId: closeFunding.producerRequestId,
        acknowledgementRequestId,
        candidateId: envelope.candidateReceipt.candidateId,
        transactionHash: txHash,
        receipt,
      };
      stored.artifactHash = acknowledgementHash(stored);
      writeJson(ackPath, stored);
    }

    if ((closeFunding.validityFinalizationReceipt
          && !sameJson(closeFunding.validityFinalizationReceipt, stored.receipt))
        || (closeFunding.validityAcknowledgementHash
          && closeFunding.validityAcknowledgementHash !== stored.artifactHash)
        || (closeFunding.committedProducerReceipt
          && !sameJson(closeFunding.committedProducerReceipt,
            stored.receipt.committedProducerReceipt))) {
      throw workflowError(409, 'ticket finalization differs from the durable acknowledgement');
    }
    closeFunding.validityFinalizationReceipt = stored.receipt;
    closeFunding.validityAcknowledgementHash = stored.artifactHash;
    closeFunding.committedProducerReceipt = stored.receipt.committedProducerReceipt;
    if (!closeFunding.liveReceipt) {
      ticket.status = 'close_funding_producer_committed_live_settle_pending';
    }
    ticket.steps = {
      ...(ticket.steps || {}),
      terminalValidity: {
        ...((ticket.steps && ticket.steps.terminalValidity) || {}),
        l1FinalizedAt: ticket.steps && ticket.steps.terminalValidity
          && ticket.steps.terminalValidity.l1FinalizedAt || Date.now(),
        transactionHash: txHash,
      },
      terminalProducerFinalization: {
        committedAt: ticket.steps && ticket.steps.terminalProducerFinalization
          && ticket.steps.terminalProducerFinalization.committedAt || Date.now(),
        producerRequestId: closeFunding.producerRequestId,
        entryHash: closeFunding.committedProducerReceipt.entryHash,
      },
    };
    upsertTicket(ch, ticket);

    if (!closeFunding.liveReceipt) {
      const liveReceipt = await producer.liveSettleCloseFunding(
        ch,
        closeFunding.committedProducerReceipt,
        closeFunding.signedState,
        closeFunding.proposal.plan,
      );
      verifyLiveReceipt(liveReceipt, closeFunding.committedProducerReceipt);
      closeFunding.liveReceipt = liveReceipt;
    } else {
      verifyLiveReceipt(closeFunding.liveReceipt, closeFunding.committedProducerReceipt);
    }
    if (!closeFunding.payoutArtifactHash
        && ticket.status !== 'close_funding_payout_proving') {
      ticket.status = 'close_funding_live_settled';
    }
    ticket.steps = {
      ...(ticket.steps || {}),
      terminalLiveSettlement: {
        settledAt: ticket.steps && ticket.steps.terminalLiveSettlement
          && ticket.steps.terminalLiveSettlement.settledAt || Date.now(),
        producerRequestId: closeFunding.producerRequestId,
      },
    };
    upsertTicket(ch, ticket);
    res.json({
      ticketId: ticket.id,
      status: ticket.status,
      acknowledgement: stored.receipt,
      committedProducerReceipt: closeFunding.committedProducerReceipt,
      liveReceipt: closeFunding.liveReceipt,
    });
  }).catch(e => failRoute(res, e));
});

// POST /api/v1/channel/:ch/full-withdrawal/request (W10 step 2 — close request + submit intent)
// SECURITY (detached close signing): this is the combined requestClose + submitCloseIntent entry
// point and therefore the fourth key-bearing close route. It is key-bearing no longer — see the
// note at the top of routes/close.js. Argv and env are unchanged.
router.post('/request', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    requireLegacyDevnet();
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    const manager = (req.body && req.body.manager) || (ticket && ticket.params.manager);
    const sv = (req.body && req.body.verifier) || (ticket && ticket.params.verifier) || '';
    if (!manager) {
      res.status(400).json({ error: 'needs { manager } or active ticket with manager' });
      return;
    }
    if (ticket) {
      ticket.status = 'close_pending';
      upsertTicket(ch, ticket);
    }
    const out = cli(ch, ['close', manager, RPC], { CLOSE_SV: sv });
    if (ticket) {
      ticket.status = 'close_done';
      ticket.steps.close = { completedAt: Date.now() };
      upsertTicket(ch, ticket);
    }
    res.json({ ok: true, log: out });
  }).catch(e => failRoute(res, e));
});

// POST /api/v1/channel/:ch/full-withdrawal/submit (W10 step 3 — withdraw pipeline)
router.post('/submit', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    requireLegacyDevnet();
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    const manager = (req.body && req.body.manager) || (ticket && ticket.params.manager);
    if (!manager) {
      res.status(400).json({ error: 'needs { manager }' });
      return;
    }
    if (ticket) {
      ticket.status = 'withdraw_pending';
      upsertTicket(ch, ticket);
    }
    const out = cli(ch, ['withdraw', manager, RPC], { ROLLUP: rollupOf(ch) });
    if (ticket) {
      ticket.status = 'withdraw_done';
      ticket.steps.withdraw = { completedAt: Date.now() };
      upsertTicket(ch, ticket);
    }
    res.json({ ok: true, log: out });
  }).catch(e => failRoute(res, e));
});

// POST /api/v1/channel/:ch/full-withdrawal/finalize (W10 step 4 — settle)
router.post('/finalize', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    requireLegacyDevnet();
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    const manager = (req.body && req.body.manager) || (ticket && ticket.params.manager);
    if (!manager) {
      res.status(400).json({ error: 'needs { manager }' });
      return;
    }
    if (ticket) {
      ticket.status = 'settle_pending';
      upsertTicket(ch, ticket);
    }
    const out = cli(ch, ['settle', manager, RPC]);
    if (ticket) {
      ticket.status = 'settle_done';
      ticket.steps.settle = { completedAt: Date.now() };
      upsertTicket(ch, ticket);
    }
    res.json({ ok: true, log: out });
  }).catch(e => failRoute(res, e));
});

// POST /api/v1/channel/:ch/full-withdrawal/claim (W10 step 5)
// body: { manager?, slot, recipient, tokenSlot? } — tokenSlot optional, default 0 (multi-token
// §N-6: withdrawal claims are per (member slot, token slot); run once per held token).
router.post('/claim', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    requireLegacyDevnet();
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    const { manager, slot, recipient, tokenSlot } = req.body || {};
    const mgr = manager || (ticket && ticket.params.manager);
    if (!mgr || slot === undefined || !recipient) {
      res.status(400).json({ error: 'needs { manager, slot, recipient, tokenSlot? }' });
      return;
    }
    const ts = tokenSlot === undefined || tokenSlot === null ? '0' : String(tokenSlot);
    if (!/^[0-9]$/.test(ts)) {
      res.status(400).json({ error: 'tokenSlot must be 0..9' });
      return;
    }
    if (ticket) {
      ticket.status = 'claim_pending';
      upsertTicket(ch, ticket);
    }
    const out = cli(ch, ['claim', mgr, String(slot), RPC, ts], { CLAIM_RECIPIENT: recipient });
    if (ticket) {
      ticket.status = 'claim_done';
      ticket.steps.claim = { completedAt: Date.now() };
      upsertTicket(ch, ticket);
    }
    res.json({ ok: true, log: out });
  }).catch(e => failRoute(res, e));
});

module.exports = router;
