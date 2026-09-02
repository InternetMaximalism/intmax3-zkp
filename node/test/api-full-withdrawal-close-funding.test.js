'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const path = require('path');
const Module = require('module');

const ROUTE = path.resolve(__dirname, '../../api/routes/full-withdrawal.js');
const CHANNEL = 7;
const ROLLUP = '0x1111111111111111111111111111111111111111';
const MANAGER = '0x2222222222222222222222222222222222222222';
const MATERIALIZER = '0x6666666666666666666666666666666666666666';
const ATTACKER = '0x3333333333333333333333333333333333333333';
const WITHDRAWAL_PROVER = '0x4444444444444444444444444444444444444444';
const PLAN_DIGEST = `0x${'ab'.repeat(32)}`;
const FUNDING_AUX = `0x${'12'.repeat(32)}`;
const INITIAL_ENTRY = `0x${'09'.repeat(32)}`;
const TERMINAL_ENTRY = `0x${'10'.repeat(32)}`;
const INITIAL_EXT = `0x${'19'.repeat(32)}`;
const TERMINAL_EXT = `0x${'20'.repeat(32)}`;
const BP_SIG_CHAIN = `0x${'30'.repeat(32)}`;
const NULLIFIER = `0x${'40'.repeat(32)}`;
const CANDIDATE_ID = `0x${'50'.repeat(32)}`;
const FINALIZE_TX = `0x${'60'.repeat(32)}`;

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function stableRequestId(kind, body) {
  const digest = crypto.createHash('sha256').update(canonicalJson(body)).digest('hex');
  return `${kind}:${digest}`;
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function proposal() {
  return {
    plan: {
      chainId: 1,
      rollup: ROLLUP,
      manager: MANAGER,
      sourceChannelId: CHANNEL,
      planDigest: PLAN_DIGEST,
      fundingAuxData: FUNDING_AUX,
      baseNonce: 9,
      txTreeRoot: `0x${'ef'.repeat(32)}`,
      transfers: [{ tokenIndex: 0, amount: '12' }],
    },
    proposedState: {
      channelId: CHANNEL,
      epoch: 3,
      digest: `0x${'cd'.repeat(32)}`,
      h2Tag: `0x${'ef'.repeat(32)}`,
      memberSignatures: [],
    },
  };
}

function signedState(prepared) {
  return {
    ...clone(prepared.proposedState),
    memberSignatures: [{ signer: 0, signature: 'detached-signature' }],
  };
}

function loadHarness(options = {}) {
  const handlers = { post: new Map(), get: new Map() };
  const router = {
    post(route, handler) { handlers.post.set(route, handler); },
    get(route, handler) { handlers.get.set(route, handler); },
  };
  let rpcChainId = options.chainId || 1;
  let backingRollup = ROLLUP;
  let settlement = {
    rollup: ROLLUP,
    manager: MANAGER,
    verifier: '0x5555555555555555555555555555555555555555',
    close_funding_materializer: MATERIALIZER,
    activation_checkpoint: {
      chainId: rpcChainId,
      source: rpcChainId === 31337 ? 'devnetLatest' : 'rpcFinalized',
    },
  };
  let preparedProposal = proposal();
  if (rpcChainId !== 1) preparedProposal.plan.chainId = rpcChainId;
  let activeTicket = {
    id: 'fw_test',
    type: 'full_withdrawal',
    status: 'started',
    createdAt: 1,
    updatedAt: 1,
    params: {},
    steps: {},
  };
  const files = new Map();
  const calls = [];
  let cliCalls = 0;
  let failLiveOnce = Boolean(options.failLiveOnce);
  let rejectFirstStage = Boolean(options.rejectFirstStage);
  let lastLock = Promise.resolve();

  const initialAnchor = {
    generation: 9,
    entryHash: INITIAL_ENTRY,
    blockNumber: 9,
    timestamp: 900,
    extendedStateCommitment: INITIAL_EXT,
    bpSigChain: BP_SIG_CHAIN,
  };
  const stagedProducerReceipt = {
    requestId: null,
    generation: 10,
    entryHash: TERMINAL_ENTRY,
    blockNumber: 10,
    timestamp: 1000,
    extendedStateCommitment: TERMINAL_EXT,
    bpSigChain: BP_SIG_CHAIN,
  };
  const terminalAnchor = {
    generation: stagedProducerReceipt.generation,
    entryHash: stagedProducerReceipt.entryHash,
    blockNumber: stagedProducerReceipt.blockNumber,
    timestamp: stagedProducerReceipt.timestamp,
    extendedStateCommitment: stagedProducerReceipt.extendedStateCommitment,
    bpSigChain: stagedProducerReceipt.bpSigChain,
  };

  function candidateReceipt(requestId) {
    const receipt = {
      requestId,
      candidateId: CANDIDATE_ID,
      producerAnchor: clone(terminalAnchor),
      initialBlockNumber: 9,
      finalBlockNumber: 10,
      initialExtendedStateCommitment: INITIAL_EXT,
      finalExtendedStateCommitment: TERMINAL_EXT,
      signatureEventCount: 1,
      metrics: { blockCount: 1 },
    };
    if (options.wrongCandidateAnchor) {
      receipt.initialExtendedStateCommitment = `0x${'88'.repeat(32)}`;
    }
    return receipt;
  }

  const producerMock = {
    canonicalJson,
    stableRequestId,
    async status() {
      return {
        generation: initialAnchor.generation,
        journalHead: initialAnchor.entryHash,
        blockNumber: initialAnchor.blockNumber,
        timestamp: initialAnchor.timestamp,
        extendedStateCommitment: initialAnchor.extendedStateCommitment,
        bpSigChain: initialAnchor.bpSigChain,
        holdsLocalSigningKeys: false,
      };
    },
    async validityStatus() {
      const finalizedAnchor = options.staleValidity
        ? { ...initialAnchor, generation: 8, entryHash: `0x${'08'.repeat(32)}`, blockNumber: 8 }
        : initialAnchor;
      return {
        finalizedAnchor: clone(finalizedAnchor),
        finalizedBlockNumber: finalizedAnchor.blockNumber,
        finalizedExtendedStateCommitment: finalizedAnchor.extendedStateCommitment,
        candidate: options.pendingCandidate ? { candidateId: CANDIDATE_ID } : null,
      };
    },
    async livePrepareCloseFunding(channelId, chainId, rollup, manager) {
      calls.push({ kind: 'prepare', channelId, chainId, rollup, manager });
      return clone(preparedProposal);
    },
    async prepareCloseFunding(state, plan, requestId) {
      calls.push({ kind: 'stage', state: clone(state), plan: clone(plan), requestId });
      if (rejectFirstStage) {
        rejectFirstStage = false;
        throw new Error('terminal close-funding head is not N-of-N signed');
      }
      return { ...clone(stagedProducerReceipt), requestId };
    },
    async liveSettleCloseFunding(channelId, receipt, state, plan) {
      calls.push({
        kind: 'live', channelId, receipt: clone(receipt), state: clone(state), plan: clone(plan),
      });
      if (failLiveOnce) {
        failLiveOnce = false;
        throw new Error('simulated crash boundary after producer admission');
      }
      return {
        producerRequestId: receipt.requestId,
        producerGeneration: receipt.generation,
        producerEntryHash: receipt.entryHash,
        producerExtendedStateCommitment: receipt.extendedStateCommitment,
        balanceGeneration: 11,
        baseNonce: 10,
      };
    },
    async liveCloseFundingPayoutArtifacts(channelId, producerRequestId, withdrawalProver) {
      calls.push({ kind: 'payout', channelId, producerRequestId, withdrawalProver });
      const withdrawal = {
        recipient: MANAGER,
        tokenIndex: 0,
        amount: '12',
        nullifier: NULLIFIER,
        auxData: FUNDING_AUX,
      };
      return {
        planDigest: PLAN_DIGEST,
        fundingAuxData: FUNDING_AUX,
        lanes: [{
          lane: 'native',
          withdrawals: [withdrawal],
          withdrawalProver,
          payoutJson: JSON.stringify({
            withdrawals: [{
              recipient: MANAGER,
              token_index: 0,
              amount: '12',
              nullifier: NULLIFIER,
              aux_data: FUNDING_AUX,
            }],
            withdrawal_prover: withdrawalProver,
            block_number: 10,
            ext_commitment: TERMINAL_EXT,
          }),
          withdrawalMleJson: '{"proof":"withdrawal"}',
          producerAnchor: clone(terminalAnchor),
          metrics: {},
        }],
      };
    },
    async proveValidity(requestId) {
      calls.push({ kind: 'prove-validity', requestId });
      return candidateReceipt(requestId);
    },
    async validityPostingArtifact() {
      const requestId = calls.find(call => call.kind === 'prove-validity').requestId;
      return {
        receipt: candidateReceipt(requestId),
        expectedPendingChains: `0x${'77'.repeat(32)}`,
        subBlocks: [{
          channelId: CHANNEL,
          timestamp: 1000,
          txTreeRoot: `0x${'ef'.repeat(32)}`,
          numUsers: 2,
          keyIds: [1, 0],
          depositHashChain: `0x${'55'.repeat(32)}`,
          channelRegHashChain: `0x${'66'.repeat(32)}`,
        }],
      };
    },
    async validityFinalizeArtifact() {
      return {
        finalStateRoot: TERMINAL_EXT,
        vpisJson: JSON.stringify({
          initial_block_number: 9,
          final_block_number: 10,
          initial_ext_commitment: INITIAL_EXT,
          final_ext_commitment: TERMINAL_EXT,
          prover: WITHDRAWAL_PROVER,
        }),
        validityMleJson: '{"proof":"validity"}',
      };
    },
    async acknowledgeValidity(requestId, candidateId, transactionHash) {
      calls.push({ kind: 'ack-validity', requestId, candidateId, transactionHash });
      const committedProducerReceipt = {
        ...clone(stagedProducerReceipt),
        requestId: calls.find(call => call.kind === 'stage').requestId,
      };
      if (options.wrongCommittedReceipt) {
        committedProducerReceipt.entryHash = `0x${'99'.repeat(32)}`;
      }
      return {
        requestId,
        candidateId,
        producerAnchor: clone(terminalAnchor),
        finalizedBlockNumber: 10,
        finalExtendedStateCommitment: TERMINAL_EXT,
        l1Acknowledgement: {
          chainId: rpcChainId,
          transactionHash,
          blockHash: `0x${'70'.repeat(32)}`,
          blockNumber: 100,
          finalExtendedStateCommitment: TERMINAL_EXT,
        },
        committedProducerReceipt,
      };
    },
  };

  const cliMock = {
    RPC: 'https://rpc.invalid',
    DEVNET_CHAIN_ID: 31337,
    chainId: () => rpcChainId,
    rollupOf: () => backingRollup,
    wc: (_channel, filename) => `/virtual/ch${CHANNEL}/${filename}`,
    readJson(filepath) {
      if (filepath.endsWith('/settlement.json')) return clone(settlement);
      if (files.has(filepath)) return clone(files.get(filepath));
      const error = new Error(`ENOENT: ${filepath}`);
      error.code = 'ENOENT';
      throw error;
    },
    writeJson(filepath, value) { files.set(filepath, clone(value)); },
    l1SignerAddress: () => WITHDRAWAL_PROVER,
    verifyActiveSettlementBinding() {
      return {
        schemaVersion: 1,
        status: 'active',
        chainId: rpcChainId,
        channelId: CHANNEL,
        rollup: settlement.rollup,
        manager: settlement.manager,
        verifier: settlement.verifier,
        closeFundingMaterializer: settlement.close_funding_materializer,
        activationCheckpoint: settlement.activation_checkpoint,
      };
    },
    ensureSettlement: () => clone(settlement),
    cli() { cliCalls += 1; return 'ok'; },
    failRoute(res, error) {
      return res.status(error.httpStatus || 500).json(
        error.payload || { error: String(error.message || error) },
      );
    },
  };

  const fsMock = {
    existsSync(filepath) {
      if (filepath.endsWith('/settlement.json')) return true;
      return files.has(filepath);
    },
  };

  const originalLoad = Module._load;
  Module._load = function mockedLoad(request, parent, isMain) {
    if (request === 'express') return { Router: () => router };
    if (request === 'fs' && parent && parent.filename === ROUTE) return fsMock;
    if (request === '../lib/lock') {
      return {
        withLock(_channel, fn) {
          lastLock = Promise.resolve().then(fn);
          return lastLock;
        },
      };
    }
    if (request === '../lib/tickets') {
      return {
        findActiveTicket(_channel, type) {
          assert.equal(type, 'full_withdrawal');
          return activeTicket;
        },
        upsertTicket(_channel, ticket) {
          activeTicket = ticket;
          return ticket;
        },
      };
    }
    if (request === '../lib/block-producer') return producerMock;
    if (request === '../lib/cli') return cliMock;
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    delete require.cache[ROUTE];
    require(ROUTE);
  } finally {
    Module._load = originalLoad;
  }

  async function invoke(route, body = {}, method = 'post') {
    const handler = handlers[method].get(route);
    assert.equal(typeof handler, 'function', `${method.toUpperCase()} ${route} must exist`);
    const response = {
      statusCode: 200,
      body: undefined,
      status(code) { this.statusCode = code; return this; },
      json(value) { this.body = value; return this; },
    };
    handler({ params: { ch: String(CHANNEL) }, body }, response);
    await lastLock.catch(() => {});
    await new Promise(resolve => setImmediate(resolve));
    return response;
  }

  return {
    invoke,
    calls,
    files,
    cliCalls: () => cliCalls,
    ticket: () => activeTicket,
    proposal: () => clone(preparedProposal),
    setProposal(value) { preparedProposal = clone(value); },
    setSettlement(value) { settlement = clone(value); },
    settlement: () => clone(settlement),
    setBackingRollup(value) { backingRollup = value; },
  };
}

test('trusted settlement/RPC binding owns manager and plan; caller overrides fail closed', async () => {
  const harness = loadHarness();

  let response = await harness.invoke('/close-funding/prepare', { manager: ATTACKER });
  assert.equal(response.statusCode, 400);
  assert.match(response.body.error, /caller-supplied/);
  assert.equal(harness.calls.length, 0);

  response = await harness.invoke('/close-funding/prepare');
  assert.equal(response.statusCode, 200);
  assert.equal(harness.calls[0].kind, 'prepare');
  assert.equal(harness.calls[0].manager, MANAGER);
  assert.equal(harness.calls[0].rollup, ROLLUP);

  const signed = signedState(response.body.proposal);
  response = await harness.invoke('/close-funding/commit', {
    signedState: signed,
    plan: { ...response.body.proposal.plan, manager: ATTACKER },
  });
  assert.equal(response.statusCode, 400);
  assert.equal(harness.calls.filter(call => call.kind === 'stage').length, 0);

  response = await harness.invoke('/close-funding/commit', {
    signedState: signed,
    committedProducerReceipt: { requestId: 'caller-controlled' },
  });
  assert.equal(response.statusCode, 400);
  assert.match(response.body.error, /caller-supplied/);
  assert.equal(harness.calls.filter(call => call.kind === 'stage').length, 0);

  const changed = harness.settlement();
  changed.manager = ATTACKER;
  harness.setSettlement(changed);
  response = await harness.invoke('/close-funding/commit', { signedState: signed });
  assert.equal(response.statusCode, 409);
  assert.match(response.body.error, /binding changed/);
  assert.equal(harness.calls.filter(call => call.kind === 'stage').length, 0);

  const changedMaterializerHarness = loadHarness();
  const materializerPrepared = await changedMaterializerHarness.invoke('/close-funding/prepare');
  const changedMaterializer = changedMaterializerHarness.settlement();
  changedMaterializer.close_funding_materializer = ATTACKER;
  changedMaterializerHarness.setSettlement(changedMaterializer);
  response = await changedMaterializerHarness.invoke('/close-funding/commit', {
    signedState: signedState(materializerPrepared.body.proposal),
  });
  assert.equal(response.statusCode, 409);
  assert.match(response.body.error, /binding changed/);
  assert.equal(
    changedMaterializerHarness.calls.filter(call => call.kind === 'stage').length,
    0,
  );
});

test('malformed daemon proposal and settlement/backing mismatch are rejected before signing', async () => {
  const harness = loadHarness();
  const maliciousProposal = harness.proposal();
  maliciousProposal.plan.manager = ATTACKER;
  harness.setProposal(maliciousProposal);
  let response = await harness.invoke('/close-funding/prepare');
  assert.equal(response.statusCode, 502);
  assert.match(response.body.error, /diverges/);

  const second = loadHarness();
  second.setBackingRollup(ATTACKER);
  response = await second.invoke('/close-funding/prepare');
  assert.equal(response.statusCode, 409);
  assert.match(response.body.error, /rollup differs/);
  assert.equal(second.calls.length, 0);

  const third = loadHarness();
  const wrongChain = third.settlement();
  wrongChain.activation_checkpoint.chainId = 10;
  third.setSettlement(wrongChain);
  response = await third.invoke('/close-funding/prepare');
  assert.equal(response.statusCode, 409);
  assert.match(response.body.error, /activation binding/);
  assert.equal(third.calls.length, 0);
});

test('terminal signing is refused unless validity is L1-finalized at the exact producer head', async () => {
  for (const harness of [
    loadHarness({ staleValidity: true }),
    loadHarness({ pendingCandidate: true }),
  ]) {
    const response = await harness.invoke('/close-funding/prepare');
    assert.equal(response.statusCode, 409);
    assert.equal(harness.calls.length, 0, 'no unsigned terminal child is exposed before readiness');
  }
});

test('compatibility commit URL stages only; validity proof precedes authoritative commit and live settle', async () => {
  const harness = loadHarness();
  let response = await harness.invoke('/close-funding/commit', { signedState: {} });
  assert.equal(response.statusCode, 409, 'commit cannot run before preparation');

  response = await harness.invoke('/close-funding/validity-artifacts');
  assert.equal(response.statusCode, 409, 'validity cannot run before producer staging');
  response = await harness.invoke('/close-funding/payout-artifacts');
  assert.equal(response.statusCode, 409, 'payout cannot run before validity/finalization/settlement');

  const prepared = await harness.invoke('/close-funding/prepare');
  const signed = signedState(prepared.body.proposal);
  response = await harness.invoke('/close-funding/commit', { signedState: signed });
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.status, 'close_funding_producer_staged');
  assert.deepEqual(harness.calls.map(call => call.kind), ['prepare', 'stage']);
  const requestId = harness.ticket().params.closeFunding.producerRequestId;
  assert.ok(requestId.startsWith('close-funding-stage-v2:'));
  assert.equal(harness.ticket().params.closeFunding.stagedProducerReceipt.requestId, requestId);
  assert.equal(harness.ticket().params.closeFunding.committedProducerReceipt, null);
  assert.equal(harness.ticket().params.closeFunding.liveReceipt, null);
  assert.ok(harness.ticket().steps.terminalProducerStaging.stagedAt);
  assert.equal(harness.ticket().steps.terminalProducerFinalization, null);
  assert.equal(harness.ticket().steps.terminalLiveSettlement, null);
  assert.equal(harness.calls.filter(call => call.kind === 'live').length, 0);

  response = await harness.invoke('/close-funding/payout-artifacts');
  assert.equal(response.statusCode, 409, 'staging alone cannot expose payout artifacts');
  assert.equal(harness.calls.filter(call => call.kind === 'payout').length, 0);

  response = await harness.invoke('/close-funding/validity-artifacts');
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.status, 'close_funding_validity_ready');
  assert.deepEqual(harness.calls.map(call => call.kind), ['prepare', 'stage', 'prove-validity']);

  response = await harness.invoke('/close-funding/payout-artifacts');
  assert.equal(response.statusCode, 409, 'a proof without finalized acknowledgement cannot pay out');
  response = await harness.invoke('/close-funding/commit', { signedState: signed });
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.status, 'close_funding_validity_ready',
    'stage replay cannot roll a proved ticket backward');
  assert.equal(harness.calls.filter(call => call.kind === 'stage').length, 1);
});

test('a rejected partial signature handoff cannot poison the durable withdrawal ticket', async () => {
  const harness = loadHarness({ rejectFirstStage: true });
  const prepared = await harness.invoke('/close-funding/prepare');
  const partial = signedState(prepared.body.proposal);
  let response = await harness.invoke('/close-funding/commit', { signedState: partial });
  assert.equal(response.statusCode, 500);
  assert.match(response.body.error, /not N-of-N signed/);
  assert.equal(harness.ticket().status, 'close_funding_signatures_pending');
  assert.equal(harness.ticket().params.closeFunding.signedState, null);
  assert.equal(harness.ticket().params.closeFunding.producerRequestId, null);
  assert.equal(harness.ticket().params.closeFunding.stagedProducerReceipt, null);

  const complete = {
    ...partial,
    memberSignatures: [
      { signer: 0, signature: 'detached-signature' },
      { signer: 1, signature: 'second-detached-signature' },
    ],
  };
  response = await harness.invoke('/close-funding/commit', { signedState: complete });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(harness.ticket().params.closeFunding.signedState, complete);
  assert.equal(harness.calls.filter(call => call.kind === 'stage').length, 2);
});

test('finalized acknowledgement commits the exact stage, then crash-retries live settlement', async () => {
  const harness = loadHarness({ failLiveOnce: true });
  const prepared = await harness.invoke('/close-funding/prepare');
  const signed = signedState(prepared.body.proposal);
  let response = await harness.invoke('/close-funding/commit', { signedState: signed });
  assert.equal(response.statusCode, 200);
  const staged = clone(harness.ticket().params.closeFunding.stagedProducerReceipt);
  response = await harness.invoke('/close-funding/validity-artifacts');
  assert.equal(response.statusCode, 200);

  response = await harness.invoke('/close-funding/validity-acknowledge', {
    transactionHash: FINALIZE_TX,
    finalStateRoot: ATTACKER,
  });
  assert.equal(response.statusCode, 400);
  assert.equal(harness.calls.filter(call => call.kind === 'ack-validity').length, 0);

  response = await harness.invoke('/close-funding/validity-acknowledge', {
    transactionHash: FINALIZE_TX,
  });
  assert.equal(response.statusCode, 500);
  assert.match(response.body.error, /simulated crash boundary/);
  assert.equal(harness.ticket().status, 'close_funding_producer_committed_live_settle_pending');
  assert.deepEqual(harness.ticket().params.closeFunding.committedProducerReceipt, staged);
  assert.ok(harness.ticket().steps.terminalProducerFinalization.committedAt);
  assert.equal(harness.ticket().steps.terminalLiveSettlement, null);
  assert.equal(harness.files.size, 2,
    'validity bundle and finalization receipt are durable before live settlement');
  assert.equal(harness.calls.filter(call => call.kind === 'ack-validity').length, 1);
  assert.equal(harness.calls.filter(call => call.kind === 'live').length, 1);

  response = await harness.invoke('/close-funding/validity-acknowledge', {
    transactionHash: FINALIZE_TX,
  });
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.status, 'close_funding_live_settled');
  assert.deepEqual(response.body.committedProducerReceipt, staged);
  assert.ok(harness.ticket().steps.terminalLiveSettlement.settledAt);
  assert.equal(harness.calls.filter(call => call.kind === 'ack-validity').length, 1,
    'durable finalization receipt avoids a second authoritative mutation');
  assert.equal(harness.calls.filter(call => call.kind === 'live').length, 2,
    'live settlement replays after the recorded crash boundary');

  response = await harness.invoke('/close-funding/validity-acknowledge', {
    transactionHash: `0x${'61'.repeat(32)}`,
  });
  assert.equal(response.statusCode, 409, 'finalization transaction is content-pinned');
});

test('wrong committed producer anchor fails closed before live mutation', async () => {
  const harness = loadHarness({ wrongCommittedReceipt: true });
  const prepared = await harness.invoke('/close-funding/prepare');
  const signed = signedState(prepared.body.proposal);
  let response = await harness.invoke('/close-funding/commit', { signedState: signed });
  assert.equal(response.statusCode, 200);
  response = await harness.invoke('/close-funding/validity-artifacts');
  assert.equal(response.statusCode, 200);
  response = await harness.invoke('/close-funding/validity-acknowledge', {
    transactionHash: FINALIZE_TX,
  });
  assert.equal(response.statusCode, 502);
  assert.match(response.body.error, /exact staged terminal producer entry/);
  assert.equal(harness.calls.filter(call => call.kind === 'live').length, 0);
  assert.equal(harness.files.size, 1, 'invalid finalization is not persisted');
  assert.equal(harness.ticket().params.closeFunding.committedProducerReceipt, null);
});

test('validity candidate must start at the exact pre-terminal finalized anchor', async () => {
  const harness = loadHarness({ wrongCandidateAnchor: true });
  const prepared = await harness.invoke('/close-funding/prepare');
  const signed = signedState(prepared.body.proposal);
  let response = await harness.invoke('/close-funding/commit', { signedState: signed });
  assert.equal(response.statusCode, 200);
  response = await harness.invoke('/close-funding/validity-artifacts');
  assert.equal(response.statusCode, 502);
  assert.match(response.body.error, /sole terminal block\/producer anchor/);
  assert.equal(harness.calls.filter(call => call.kind === 'ack-validity').length, 0);
  assert.equal(harness.calls.filter(call => call.kind === 'live').length, 0);
});

test('validity and payout artifacts are content-pinned and replay without reproving', async () => {
  const harness = loadHarness();
  const prepared = await harness.invoke('/close-funding/prepare');
  const signed = signedState(prepared.body.proposal);
  let response = await harness.invoke('/close-funding/commit', { signedState: signed });
  assert.equal(response.statusCode, 200);

  response = await harness.invoke('/close-funding/validity-artifacts');
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.status, 'close_funding_validity_ready');
  assert.equal(response.body.candidateId, CANDIDATE_ID);
  assert.equal(response.body.postingArtifact.subBlocks.length, 1);
  assert.equal(response.body.finalizeArtifact.finalStateRoot, TERMINAL_EXT);
  assert.equal(harness.calls.filter(call => call.kind === 'prove-validity').length, 1);
  assert.equal(harness.files.size, 1);

  response = await harness.invoke('/close-funding/validity-artifacts');
  assert.equal(response.statusCode, 200);
  assert.equal(harness.calls.filter(call => call.kind === 'prove-validity').length, 1,
    'durable validity bundle is reused instead of reproving');

  response = await harness.invoke('/close-funding/validity-acknowledge', {
    transactionHash: FINALIZE_TX,
  });
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.status, 'close_funding_live_settled');
  assert.equal(harness.calls.filter(call => call.kind === 'ack-validity').length, 1);
  assert.equal(harness.files.size, 2);

  response = await harness.invoke('/close-funding/payout-artifacts', {
    withdrawalProver: ATTACKER,
  });
  assert.equal(response.statusCode, 400);
  assert.equal(harness.calls.filter(call => call.kind === 'payout').length, 0);

  response = await harness.invoke('/close-funding/payout-artifacts');
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.status, 'close_funding_payout_ready');
  assert.equal(harness.calls.filter(call => call.kind === 'payout').length, 1);
  assert.equal(harness.calls.find(call => call.kind === 'payout').withdrawalProver,
    WITHDRAWAL_PROVER);
  assert.equal(harness.files.size, 3);

  response = await harness.invoke('/close-funding/payout-artifacts');
  assert.equal(response.statusCode, 200);
  assert.equal(harness.calls.filter(call => call.kind === 'payout').length, 1,
    'durable payout artifact is reused instead of reproving');

  response = await harness.invoke('/close-funding/commit', { signedState: signed });
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.status, 'close_funding_payout_ready',
    'stage replay cannot roll a completed payout ticket backward');

  const ackPath = [...harness.files.keys()].find(file => file.endsWith('/full_close_funding_validity_ack.json'));
  const originalAck = clone(harness.files.get(ackPath));
  harness.files.get(ackPath).receipt.committedProducerReceipt.entryHash = `0x${'98'.repeat(32)}`;
  response = await harness.invoke('/close-funding/payout-artifacts');
  assert.notEqual(response.statusCode, 200, 'tampered durable finalization cannot authorize payout');
  harness.files.set(ackPath, originalAck);

  const payoutPath = [...harness.files.keys()].find(file => file.endsWith('/full_close_funding_payout.json'));
  harness.files.get(payoutPath).artifacts.planDigest = `0x${'97'.repeat(32)}`;
  response = await harness.invoke('/close-funding/payout-artifacts');
  assert.equal(response.statusCode, 409, 'tampered durable payout artifact is never served');
  assert.equal(harness.calls.filter(call => call.kind === 'payout').length, 1);
});

test('legacy JS immediate-commit wrapper is a local tombstone', async () => {
  const blockProducer = require('../../api/lib/block-producer');
  assert.equal(typeof blockProducer.prepareCloseFunding, 'function');
  await assert.rejects(
    blockProducer.postCloseFunding({}, {}, 'must-not-reach-daemon'),
    error => error && error.code === 'immediate_close_funding_retired'
      && /commit only through acknowledgeValidity/.test(error.message),
  );
});

test('legacy full-withdrawal mutation is devnet-only', async () => {
  const production = loadHarness();
  for (const [route, body] of [
    ['/request', { manager: MANAGER }],
    ['/submit', { manager: MANAGER }],
    ['/finalize', { manager: MANAGER }],
    ['/claim', { manager: MANAGER, slot: 0, recipient: ATTACKER }],
  ]) {
    const response = await production.invoke(route, body);
    assert.equal(response.statusCode, 409, route);
    assert.match(response.body.error, /disabled on public chains/, route);
  }
  assert.equal(production.cliCalls(), 0);

  const devnet = loadHarness({ chainId: 31337 });
  const response = await devnet.invoke('/request', { manager: MANAGER });
  assert.equal(response.statusCode, 200);
  assert.equal(devnet.cliCalls(), 1);
});
