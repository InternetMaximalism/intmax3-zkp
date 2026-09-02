'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Interface, ZeroHash } = require('ethers');

const {
  buildParticipantCloseProof,
  makeParticipantCloser,
  participantLeaf,
  participantNode,
} = require('../delegate/participant-close');
const exit = require('../delegate/branches/exit');
const close = require('../cosigner/branches/close');
const { classify, BRANCHES } = require('../cosigner/classify');
const { matchCosignerRoute } = require('../cosigner');

const RECIPIENTS = [
  '0x1111111111111111111111111111111111111111',
  '0x2222222222222222222222222222222222222222',
  '0x3333333333333333333333333333333333333333',
];
const PK_GS = [
  `0x${'11'.repeat(32)}`,
  `0x${'22'.repeat(32)}`,
  `0x${'33'.repeat(32)}`,
];

function snapshot() {
  return {
    record: { memberCount: 2, delegateCount: 1, memberPkGs: PK_GS },
    state: {
      digest: `0x${'aa'.repeat(32)}`,
      balanceState: { memberCount: 2, delegateCount: 1, recipients: RECIPIENTS },
    },
  };
}

function recomputeRoot(proof) {
  let node = participantLeaf(proof.slot, proof.pkG, proof.recipient);
  let index = proof.slot;
  for (const sibling of proof.siblings) {
    node = (index & 1) === 0
      ? participantNode(node, sibling)
      : participantNode(sibling, node);
    index >>= 1;
  }
  return node;
}

function fakeStore(initial = {}) {
  const state = { mode: 'normal', actions: {}, ...initial };
  return {
    state,
    get(key) { return state[key]; },
    set(key, value) { state[key] = value; return value; },
    setSmNode(value) { state.smNode = value; },
    claimAction(id) {
      if (state.actions[id]) return false;
      state.actions[id] = { result: 'pending' };
      return true;
    },
    hasAction(id) { return Boolean(state.actions[id]); },
    completeAction(id, result) { state.actions[id] = { result }; },
    releaseAction(id) { if (state.actions[id] && state.actions[id].result === 'pending') delete state.actions[id]; },
    pushAlert(record) { (state.alerts ||= []).push(record); },
    findTicket() { return null; },
    upsertTicket() {},
  };
}

test('delegate derives the exact depth-10 participant path from an authenticated signed snapshot', () => {
  const proof = buildParticipantCloseProof(snapshot(), 2, RECIPIENTS[2]);
  assert.equal(proof.slot, 2);
  assert.equal(proof.pkG, PK_GS[2]);
  assert.equal(proof.activeParticipantCount, 3);
  assert.equal(proof.siblings.length, 10);
  assert.notEqual(proof.participantRoot, ZeroHash);
  assert.equal(recomputeRoot(proof), proof.participantRoot);

  assert.throws(
    () => buildParticipantCloseProof(snapshot(), 2, RECIPIENTS[1]),
    /differs from signed slot 2 recipient/,
  );
  const conflicting = snapshot();
  conflicting.record.delegate_count = 2;
  assert.throws(() => buildParticipantCloseProof(conflicting, 2, RECIPIENTS[2]), /conflicting/);
  assert.throws(() => buildParticipantCloseProof(snapshot(), 3, RECIPIENTS[2]), /outside active/);
});

test('delegate L1 signer must control the exact signed recipient', () => {
  const anvilKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
  assert.throws(
    () => makeParticipantCloser({
      rpcUrl: 'http://127.0.0.1:8545', chainId: 31337, recipient: RECIPIENTS[2], privateKey: anvilKey,
    }),
    /not configured recipient/,
  );
});

test('own CloseRequested terminalizes from its exact receipt even when submit and cancel restore Active in the same block', async () => {
  const manager = '0x4444444444444444444444444444444444444444';
  const signerAddress = RECIPIENTS[2];
  const transactionHash = `0x${'77'.repeat(32)}`;
  const managerInterface = new Interface([
    'event CloseRequested(address indexed requester, uint64 closeRequestedAt, uint64 closeFreezeNonce)',
    'function highestCancelledRevivedStateVersion() view returns (uint64)',
  ]);
  const encodedEvent = managerInterface.encodeEventLog(
    managerInterface.getEvent('CloseRequested'),
    [signerAddress, 100n, 1n],
  );
  const provider = {
    async getNetwork() { return { chainId: 31337n }; },
    async call(transaction) {
      assert.equal(
        transaction.data.slice(0, 10),
        managerInterface.getFunction('highestCancelledRevivedStateVersion').selector,
      );
      assert.equal(transaction.blockTag, 50);
      // End-of-block state is already Active after a later submit+cancel. The monotone cancel
      // floor, not channelStatus/currentCloseFreezeNonce, remains available to authenticate era.
      return managerInterface.encodeFunctionResult('highestCancelledRevivedStateVersion', [13n]);
    },
  };
  const outbox = {
    signerAddress,
    provider,
    async markFinalized(actionId, observation, predicate) {
      assert.equal(actionId, 'participant-close:test-action');
      assert.equal(observation.transactionHash, transactionHash);
      return predicate({
        blockTag: 50,
        transactionHash,
        receipt: {
          logs: [{
            address: manager,
            transactionHash,
            index: 0,
            topics: encodedEvent.topics,
            data: encodedEvent.data,
          }],
        },
      });
    },
  };
  const closer = makeParticipantCloser({
    chainId: 31337,
    recipient: signerAddress,
    provider,
    outbox,
  });
  const accepted = await closer.markRequestFinalized(
    manager,
    'participant-close:test-action',
    { transactionHash },
    {
      expectedCurrentCloseFreezeNonce: '0',
      expectedHighestCancelledRevivedStateVersion: '0',
    },
  );
  assert.equal(accepted, true);
});

test('exit mode initiates participant close itself and never submits a claim before finalization', async () => {
  const store = fakeStore({ participantCloseProof: buildParticipantCloseProof(snapshot(), 2, RECIPIENTS[2]) });
  const closeCalls = [];
  const claimCalls = [];
  const alerts = [];
  const ctx = {
    ch: { id: 7, manager: '0x4444444444444444444444444444444444444444' },
    slot: 2,
    recipient: RECIPIENTS[2],
    store,
    sm: { signal() {} },
    participantCloser: {
      async requestClose(manager, proof) { closeCalls.push({ manager, proof }); return { txHash: `0x${'99'.repeat(32)}` }; },
    },
    api: { async closeClaim(...args) { claimCalls.push(args); return { ok: true }; } },
    alert: { async raise(...args) { alerts.push(args); return { code: args[2] }; } },
    log: { info() {}, warn() {}, error() {} },
  };

  await exit.enterExitMode({ kind: 'withholding', reason: 'timeout' }, ctx, 'COSIGNER_WITHHOLDING');
  assert.equal(store.get('mode'), 'exiting');
  assert.equal(closeCalls.length, 1);
  assert.equal(claimCalls.length, 0, 'claim must wait for finalized CloseFinalized');
  assert.equal(store.get('participantCloseSubmission').txHash, `0x${'99'.repeat(32)}`);

  await exit.onChannelFinalized({
    kind: 'CloseFinalized', contract: 'manager', address: ctx.ch.manager,
  }, ctx);
  assert.equal(claimCalls.length, 1);
  assert.deepEqual(claimCalls[0], [7, {
    manager: ctx.ch.manager,
    slot: 2,
    recipient: RECIPIENTS[2],
  }]);
  assert.equal(store.get('awaitingCredit'), true);
  assert.equal(alerts.filter(a => a[2] === 'CLAIM_FAILED').length, 0);
});

test('an observed close suppresses a redundant participant-close transaction', async () => {
  const store = fakeStore({
    acceptedHead: { epoch: 1, stateVersion: 9 },
    participantCloseProof: buildParticipantCloseProof(snapshot(), 2, RECIPIENTS[2]),
  });
  let closeCalls = 0;
  const ctx = {
    ch: { id: 7, manager: '0x4444444444444444444444444444444444444444' },
    slot: 2, recipient: RECIPIENTS[2], store,
    participantCloser: { async requestClose() { closeCalls += 1; } },
    alert: { async raise() { return {}; } },
    sm: { signal() {} }, log: { info() {}, warn() {}, error() {} },
  };
  await exit.onCloseSeen({
    kind: 'CloseSubmitted',
    contract: 'manager',
    address: ctx.ch.manager,
    args: { finalEpoch: 1, finalStateVersion: 8 },
  }, ctx);
  assert.equal(store.get('awaitingClaim'), true);
  assert.equal(store.get('mode'), 'exiting', 'an honest close must stop new off-chain sends too');
  assert.equal(closeCalls, 0);
});

test('foreign manager close/finalize observations cannot move delegate recovery state', async () => {
  const manager = '0x4444444444444444444444444444444444444444';
  const store = fakeStore({ acceptedHead: { epoch: 1, stateVersion: 9 } });
  let recoveryCalls = 0;
  const ctx = {
    ch: { id: 7, manager }, slot: 2, recipient: RECIPIENTS[2], store,
    api: { async closeClaim() { recoveryCalls += 1; } },
    alert: { async raise() { return {}; } },
    sm: { signal() {} }, log: { info() {}, warn() {}, error() {} },
  };
  const foreign = '0x5555555555555555555555555555555555555555';
  await exit.onCloseSeen({
    kind: 'CloseSubmitted', contract: 'manager', address: foreign,
    args: { finalEpoch: 0, finalStateVersion: 0 },
  }, ctx);
  await exit.onChannelFinalized({
    kind: 'CloseFinalized', contract: 'manager', address: foreign,
  }, ctx);
  assert.equal(store.get('mode'), 'normal');
  assert.equal(store.get('channelFinalized'), undefined);
  assert.equal(recoveryCalls, 0);
});

test('cosigner exposes close/claim and proxies only a closed configured manager request', async () => {
  const route = matchCosignerRoute('/api/v1/channel/7/close/claim?ignored=1');
  assert.ok(route);
  assert.equal(route[1], '7');
  assert.equal(route[2], 'close/claim');
  assert.equal(
    classify({ source: 'api', kind: 'close-claim' }, { status: 'active', mode: 'normal' }),
    BRANCHES.INVALID_REQUEST,
  );
  assert.equal(
    classify({ source: 'api', kind: 'close-claim' }, { status: 'closed', mode: 'defensive' }),
    BRANCHES.PEER_CLOSE_CLAIM,
  );
  assert.equal(
    classify(
      { source: 'api', kind: 'close-claim' },
      { status: 'active', mode: 'defensive', closeFinalized: true },
    ),
    BRANCHES.PEER_CLOSE_CLAIM,
    'defensive state-machine sink must not hide a later finalized close from the claim route',
  );

  const calls = [];
  const manager = '0x4444444444444444444444444444444444444444';
  const result = await close.proxyCloseClaim({
    body: { manager, slot: 2, recipient: RECIPIENTS[2], tokenSlot: 4 },
  }, {
    ch: { id: 7, manager },
    api: { async closeClaim(...args) { calls.push(args); return { ok: true, log: 'submitted' }; } },
    log: { info() {} },
  });
  assert.equal(result.status, 200);
  assert.deepEqual(calls[0], [7, { manager, slot: 2, recipient: RECIPIENTS[2], tokenSlot: 4 }]);

  const wrongManager = await close.proxyCloseClaim({
    body: { manager: RECIPIENTS[0], slot: 2, recipient: RECIPIENTS[2] },
  }, {
    ch: { id: 7, manager }, api: { closeClaim() { throw new Error('must not proxy'); } }, log: { info() {} },
  });
  assert.equal(wrongManager.status, 400);
});
