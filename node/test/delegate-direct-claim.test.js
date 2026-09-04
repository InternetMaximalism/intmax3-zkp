'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Interface } = require('ethers');

const { Wallet } = require('../common/wallet');
const {
  MANAGER_CLAIM_ABI,
  SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR,
  SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR,
  normalizeMleProof,
  validateClaimArtifact,
  validateWithdrawalClaimReceipt,
} = require('../delegate/claim-settlement');
const { SnapshotVault } = require('../delegate/snapshot-vault');
const exit = require('../delegate/branches/exit');
const { resolveDelegateSeed } = require('../delegate');

const RECIPIENT = '0x0000000100000002000000030000000400000005';
const WITHDRAWAL_NULLIFIER = `0x${'42'.repeat(32)}`;

function fixtureArtifact() {
  const descriptor = JSON.parse(fs.readFileSync(path.join(__dirname, '../../contracts/test/data/withdrawal_claim.json')));
  const mleProof = JSON.parse(fs.readFileSync(path.join(__dirname, '../../contracts/test/data/withdrawal_claim_mle.json')));
  return {
    descriptor,
    artifact: {
      claim: {
        closeIntentDigest: descriptor.close_intent_digest,
        memberPkG: descriptor.member_pk_g,
        recipient: descriptor.recipient,
        userAmountDigest: descriptor.user_amount_digest,
        amount: String(descriptor.amount),
        tokenSlot: descriptor.token_slot,
        tokenIndex: descriptor.token_index,
        withdrawalNullifier: descriptor.withdrawal_nullifier,
      },
      mleProof,
    },
  };
}

function fakeStore(initial = {}) {
  const state = { actions: {}, mode: 'exiting', channelFinalized: true, ...initial };
  return {
    get(key) { return state[key]; },
    set(key, value) { state[key] = value; return value; },
    claimAction(id, options = {}) {
      if (state.actions[id]) return options.retryPending === true && state.actions[id].result === 'pending';
      state.actions[id] = { result: 'pending' };
      return true;
    },
    completeAction(id, result) { state.actions[id] = { result }; },
    releaseAction(id) { if (state.actions[id] && state.actions[id].result === 'pending') delete state.actions[id]; },
    hasAction(id) { return Boolean(state.actions[id]); },
    findTicket() { return null; },
    upsertTicket() {},
  };
}

test('bundled direct-claim ABI is exact and fixture public inputs bind every claim field', () => {
  const iface = new Interface(MANAGER_CLAIM_ABI);
  assert.equal(iface.getFunction(SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR).selector, '0x70f89118');
  assert.equal(iface.getFunction(SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR).selector, '0x6d3e503a');
  assert.equal(iface.getFunction('pullChannelFunds').selector, '0x0829ffe3');
  assert.equal(iface.getFunction('pullChannelTokenFunds').selector, '0xcf450977');
  assert.equal(iface.getFunction('withdrawalPayouts(bytes32)').selector, '0xf7b3da94');
  assert.equal(iface.getFunction('claimWithdrawalCredit(bytes32)').selector, '0xc7cf9d48');
  assert.equal(iface.getEvent('WithdrawalClaimed').topicHash, '0x15c5fb707fcb503106cf7719d546816fd24935af974a053641d55f7ffb22d410');
  const { descriptor, artifact } = fixtureArtifact();
  const finalized = {
    channelId: descriptor.channel_id,
    closeIntentDigest: descriptor.close_intent_digest,
    finalChannelStateDigest: `0x${'77'.repeat(32)}`,
    finalBalanceStateH1: descriptor.final_balance_state_h1,
    tokenCount: 1,
    tokenRegistry: [descriptor.token_index],
  };
  const normalized = normalizeMleProof(artifact.mleProof);
  assert.equal(normalized.publicInputs.length, 50);
  assert.equal(normalized.gates.length, artifact.mleProof.gates.length);
  const validated = validateClaimArtifact(
    artifact,
    finalized,
    RECIPIENT,
    descriptor.token_slot,
    { allowLegacyMle: true },
  );
  assert.equal(validated.claim.amount, String(descriptor.amount));
  assert.equal(validated.submitWithdrawalClaimSelector, SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR);
  const calldata = iface.encodeFunctionData(validated.submitWithdrawalClaimSelector, [validated.claim, validated.proof]);
  assert.ok(calldata.startsWith('0x70f89118'));
  const decoded = iface.decodeFunctionData(validated.submitWithdrawalClaimSelector, calldata);
  assert.equal(decoded.claim.withdrawalNullifier, descriptor.withdrawal_nullifier);
  assert.equal(decoded.claim.amount.toString(), String(descriptor.amount));

  const redirected = structuredClone(artifact);
  redirected.claim.recipient = '0x1111111111111111111111111111111111111111';
  assert.throws(
    () => validateClaimArtifact(
      redirected,
      finalized,
      RECIPIENT,
      descriptor.token_slot,
      { allowLegacyMle: true },
    ),
    /recipient mismatch/,
  );

  assert.throws(
    () => validateClaimArtifact(artifact, finalized, RECIPIENT, descriptor.token_slot),
    /legacy MLE proof ABI is disabled/,
  );

  const v2Artifact = structuredClone(artifact);
  v2Artifact.mleProof.protocolVersion = 1;
  v2Artifact.mleProof.constituentWidth = Math.max(
    v2Artifact.mleProof.preprocessedIndividualEvals.length,
    v2Artifact.mleProof.witnessIndividualEvals.length,
    v2Artifact.mleProof.inverseHelpersEvalsAtRInv.length,
    v2Artifact.mleProof.inverseHelpersEvalsAtRH.length,
    v2Artifact.mleProof.preprocessedIndividualEvalsAtRGateV2.length,
    v2Artifact.mleProof.witnessIndividualEvalsAtRGateV2.length,
    2,
  );
  const v2 = validateClaimArtifact(v2Artifact, finalized, RECIPIENT, descriptor.token_slot);
  assert.equal(v2.mleAbiVersion, 2);
  assert.equal(v2.submitWithdrawalClaimSelector, SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR);
  assert.ok(iface.encodeFunctionData(v2.submitWithdrawalClaimSelector, [v2.claim, v2.proof])
    .startsWith('0x6d3e503a'));
  const partialVersion = structuredClone(artifact);
  partialVersion.mleProof.protocolVersion = 1;
  assert.throws(
    () => validateClaimArtifact(partialVersion, finalized, RECIPIENT, descriptor.token_slot),
    /both protocolVersion and constituentWidth/,
  );
});

test('credit receipt must bind exact manager, transaction, nullifier, recipient, token, and amount', () => {
  const iface = new Interface(MANAGER_CLAIM_ABI);
  const manager = '0x4444444444444444444444444444444444444444';
  const txHash = `0x${'ab'.repeat(32)}`;
  const event = iface.encodeEventLog(
    iface.getEvent('WithdrawalClaimed'),
    [WITHDRAWAL_NULLIFIER, RECIPIENT, 7, 9],
  );
  const receipt = {
    hash: txHash,
    status: 1,
    logs: [{ address: manager, transactionHash: txHash, topics: event.topics, data: event.data }],
  };
  assert.doesNotThrow(() => (
    validateWithdrawalClaimReceipt(
      manager, iface, receipt, txHash, WITHDRAWAL_NULLIFIER, RECIPIENT, 7, '9',
    )
  ));
  assert.throws(
    () => validateWithdrawalClaimReceipt(
      manager, iface, receipt, txHash, WITHDRAWAL_NULLIFIER, RECIPIENT, 7, '10',
    ),
    /does not match the journaled payout/,
  );
  assert.throws(
    () => validateWithdrawalClaimReceipt(
      manager, iface, receipt, txHash, `0x${'43'.repeat(32)}`, RECIPIENT, 7, '9',
    ),
    /does not match the journaled payout/,
  );
  assert.throws(
    () => validateWithdrawalClaimReceipt(
      manager, iface, { ...receipt, hash: `0x${'cd'.repeat(32)}` }, txHash,
      WITHDRAWAL_NULLIFIER, RECIPIENT, 7, '9',
    ),
    /transaction hash mismatch/,
  );
  assert.throws(
    () => validateWithdrawalClaimReceipt(
      manager, iface, { ...receipt, logs: [] }, txHash,
      WITHDRAWAL_NULLIFIER, RECIPIENT, 7, '9',
    ),
    /exactly one manager WithdrawalClaimed/,
  );
});

test('Wallet wrapper calls only the secret-preserving WASM claim export', () => {
  const wallet = new Wallet({ pkgDir: '/unused' });
  const calls = [];
  wallet._load = () => ({
    wallet_withdrawal_claim(context, tokenSlot) {
      calls.push({ context: JSON.parse(context), tokenSlot });
      return JSON.stringify({ claim: { amount: '9007199254740993' }, mleProof: {} });
    },
  });
  const context = {
    closeIntentDigest: `0x${'11'.repeat(32)}`,
    finalChannelStateDigest: `0x${'22'.repeat(32)}`,
    finalBalanceStateH1: `0x${'33'.repeat(32)}`,
  };
  const artifact = wallet.withdrawalClaim(context, 2);
  assert.deepEqual(calls, [{ context, tokenSlot: 2 }]);
  assert.equal(artifact.claim.amount, '9007199254740993');
  assert.equal('regevSk' in artifact, false);
});

test('delegate daemon requires an exact persistent non-placeholder recovery seed', () => {
  const seed = 'ab'.repeat(32);
  assert.equal(resolveDelegateSeed({ DELEGATE_SEED_HEX: `0x${seed.toUpperCase()}` }), seed);
  assert.throws(() => resolveDelegateSeed({}), /must be a persistent 32-byte hex secret/);
  assert.throws(() => resolveDelegateSeed({ DELEGATE_SEED_HEX: '00'.repeat(32) }), /all-zero/);
  assert.throws(() => resolveDelegateSeed({ DELEGATE_SEED_HEX: 'ab' }), /32-byte/);
});

test('snapshot vault keeps an authenticated stale-state witness across restart', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-snapshot-vault-'));
  try {
    const digest = `0x${'ab'.repeat(32)}`;
    const snapshot = { state: { digest }, record: { memberCount: 3 } };
    const first = new SnapshotVault(directory, 7);
    first.save(snapshot);
    const restarted = new SnapshotVault(directory, 7);
    assert.deepEqual(restarted.load(digest), snapshot);
    assert.equal(restarted.load(`0x${'cd'.repeat(32)}`), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('direct recovery proves/submits every positive token and exits only after every finalized payout', async () => {
  const closeIntentDigest = `0x${'11'.repeat(32)}`;
  const stateDigest = `0x${'22'.repeat(32)}`;
  const finalized = {
    channelId: 7,
    closeIntentDigest,
    finalChannelStateDigest: stateDigest,
    finalBalanceStateH1: `0x${'33'.repeat(32)}`,
    tokenCount: 2,
    tokenRegistry: [0, 7],
  };
  const store = fakeStore();
  const proofs = [];
  const submissions = [];
  const pulls = [];
  const signals = [];
  const wallet = {
    importChannel(snapshot) { assert.equal(snapshot.state.digest, stateDigest); },
    balance() {
      return { balances: [
        { tokenSlot: 0, tokenIndex: 0, balance: '5' },
        { tokenSlot: 1, tokenIndex: 7, balance: '9' },
      ] };
    },
    withdrawalClaim(context, tokenSlot) {
      proofs.push({ context, tokenSlot });
      return {
        claim: {
          closeIntentDigest,
          memberPkG: `0x${String(tokenSlot + 70).padStart(64, '0')}`,
          tokenSlot,
          tokenIndex: finalized.tokenRegistry[tokenSlot],
          amount: tokenSlot === 0 ? '5' : '9',
          withdrawalNullifier: `0x${String(tokenSlot + 9).padStart(64, '0')}`,
        },
        mleProof: {},
      };
    },
  };
  const claimSettlement = {
    async readFinalizedContext() { return finalized; },
    async claimStatus() { return 'accepted'; },
    async submitClaim(_manager, artifact, _finalized, tokenSlot, onBroadcast) {
      submissions.push({ artifact, tokenSlot });
      const txHash = `0x${String(tokenSlot + 1).padStart(64, '0')}`;
      onBroadcast(txHash);
      return { txHash, tokenIndex: finalized.tokenRegistry[tokenSlot], nullifier: artifact.claim.withdrawalNullifier };
    },
    async pullCredit(_manager, withdrawalNullifier, tokenIndex, exactAmount, onBroadcast) {
      pulls.push(tokenIndex);
      const fundHash = `0x${String(tokenIndex + 30).padStart(64, '0')}`;
      const txHash = `0x${String(tokenIndex + 20).padStart(64, '0')}`;
      const amount = tokenIndex === 0 ? '5' : '9';
      assert.equal(
        withdrawalNullifier,
        `0x${String((tokenIndex === 0 ? 0 : 1) + 9).padStart(64, '0')}`,
        'accepted claim nullifier must scope the payout',
      );
      assert.equal(String(exactAmount), amount, 'accepted claim amount must drive the exact payout');
      onBroadcast({ phase: 'channel-funds', txHash: fundHash });
      onBroadcast({ phase: 'credit', txHash, amount });
      return { txHash, tokenIndex, amount };
    },
    async transactionStatus() { return 'mined'; },
  };
  const ctx = {
    ch: { id: 7, manager: '0x4444444444444444444444444444444444444444' },
    slot: 3,
    recipient: RECIPIENT,
    store,
    wallet,
    claimSettlement,
    snapshotVault: { load() { return { state: { digest: stateDigest } }; } },
    sm: { signal(value) { signals.push(value); } },
    alert: { async raise() {} },
    log: { info() {}, warn() {}, error() {} },
  };

  await exit.attemptDirectRecovery(ctx);
  assert.deepEqual(proofs.map((p) => p.tokenSlot), [0, 1]);
  assert.deepEqual(submissions.map((s) => s.tokenSlot), [0, 1]);
  assert.deepEqual(pulls, [], 'dependent pulls are deferred until finalized claim events');
  assert.equal(store.get('exitClaimPlan').claims.length, 2);
  assert.ok(store.get('exitClaimPlan').claims.every((item) => item.claimTxHash && item.claimArtifact));

  const manager = ctx.ch.manager;
  const item0 = () => store.get('exitClaimPlan').claims.find((item) => item.tokenIndex === 0);
  const item7 = () => store.get('exitClaimPlan').claims.find((item) => item.tokenIndex === 7);
  await exit.onClaimAccepted({
    kind: 'WithdrawalClaimAccepted', contract: 'manager', address: manager,
    txHash: item0().claimTxHash,
    args: {
      closeIntentDigest, withdrawalNullifier: item0().nullifier,
      memberPkG: item0().memberPkG, recipient: RECIPIENT, tokenIndex: 0, amount: '5',
    },
  }, ctx);
  await exit.onClaimAccepted({
    kind: 'WithdrawalClaimAccepted', contract: 'manager', address: manager,
    txHash: item7().claimTxHash,
    args: {
      closeIntentDigest, withdrawalNullifier: item7().nullifier,
      memberPkG: item7().memberPkG, recipient: RECIPIENT, tokenIndex: 7, amount: '9',
    },
  }, ctx);
  await exit.attemptDirectCreditPull(ctx);
  assert.deepEqual(pulls, [0, 7]);
  assert.ok(store.get('exitClaimPlan').claims.every((item) => item.pullTxHash));
  assert.ok(store.get('exitClaimPlan').claims.every((item) => item.fundsPullTxHash == null));

  // Same-recipient rollup activity is global to the rollup and must never complete this channel's
  // exit. Nor may a different manager, amount, or nullifier satisfy the persisted plan. The exact
  // manager event may be emitted by a foreign process racing the same permissionless workflow.
  await exit.onCreditConfirmed({
    kind: 'NativeWithdrawn', contract: 'rollup', address: '0x5555555555555555555555555555555555555555',
    txHash: item0().pullTxHash, args: { recipient: RECIPIENT, tokenIndex: 0, amount: '5' },
  }, ctx);
  await exit.onCreditConfirmed({
    kind: 'WithdrawalClaimed', contract: 'manager', address: '0x6666666666666666666666666666666666666666',
    txHash: item0().pullTxHash,
    args: { withdrawalNullifier: item0().nullifier, recipient: RECIPIENT, tokenIndex: 0, amount: '5' },
  }, ctx);
  await exit.onCreditConfirmed({
    kind: 'WithdrawalClaimed', contract: 'manager', address: manager,
    txHash: item0().pullTxHash,
    args: { withdrawalNullifier: item0().nullifier, recipient: RECIPIENT, tokenIndex: 0, amount: '6' },
  }, ctx);
  await exit.onCreditConfirmed({
    kind: 'WithdrawalClaimed', contract: 'manager', address: manager,
    txHash: item0().pullTxHash,
    args: { withdrawalNullifier: item7().nullifier, recipient: RECIPIENT, tokenIndex: 0, amount: '5' },
  }, ctx);
  assert.deepEqual(signals, []);

  await exit.onCreditConfirmed({
    kind: 'WithdrawalClaimed', contract: 'manager', address: manager,
    txHash: `0x${'ee'.repeat(32)}`,
    args: { withdrawalNullifier: item0().nullifier, recipient: RECIPIENT, tokenIndex: 0, amount: '5' },
  }, ctx);
  assert.deepEqual(signals, []);
  await exit.onCreditConfirmed({
    kind: 'WithdrawalClaimed', contract: 'manager', address: manager,
    txHash: item7().pullTxHash,
    args: { withdrawalNullifier: item7().nullifier, recipient: RECIPIENT, tokenIndex: 7, amount: '9' },
  }, ctx);
  assert.equal(signals.length, 1);
  assert.equal(store.get('awaitingCredit'), false);
});

test('randomized public claim artifact is journaled before outbox entry and reused after restart', async () => {
  const closeIntentDigest = `0x${'31'.repeat(32)}`;
  const stateDigest = `0x${'32'.repeat(32)}`;
  const nullifier = `0x${'33'.repeat(32)}`;
  const memberPkG = `0x${'34'.repeat(32)}`;
  const finalized = {
    channelId: 7,
    closeIntentDigest,
    finalChannelStateDigest: stateDigest,
    finalBalanceStateH1: `0x${'35'.repeat(32)}`,
    tokenCount: 1,
    tokenRegistry: [0],
  };
  const artifact = {
    claim: {
      closeIntentDigest,
      memberPkG,
      tokenSlot: 0,
      tokenIndex: 0,
      amount: '5',
      withdrawalNullifier: nullifier,
    },
    mleProof: { randomizedCommitment: `0x${'36'.repeat(32)}` },
  };
  const store = fakeStore();
  let proofBuilds = 0;
  let submits = 0;
  const claimSettlement = {
    durableOutbox: true,
    async readFinalizedContext() { return finalized; },
    async claimStatus() { return 'missing'; },
    async submitClaim(_manager, supplied, _finalized, _slot, onBroadcast) {
      submits += 1;
      assert.deepEqual(supplied, artifact);
      const item = store.get('exitClaimPlan').claims[0];
      assert.equal(item.claimOutboxPrepared, true, 'prepared metadata precedes outbox entry');
      assert.deepEqual(item.claimArtifact, artifact, 'exact randomized artifact is already durable');
      if (submits === 1) throw new Error('simulated process death before broadcast callback');
      const txHash = `0x${'37'.repeat(32)}`;
      await onBroadcast(txHash);
      return { txHash, outboxActionId: 'claim:7:3:0', tokenIndex: 0, nullifier };
    },
    async reconcileClaim() { return { phase: 'absent' }; },
  };
  const ctx = {
    ch: { id: 7, manager: '0x4444444444444444444444444444444444444444' },
    slot: 3,
    recipient: RECIPIENT,
    store,
    wallet: {
      importChannel() {},
      balance() { return { balances: [{ tokenSlot: 0, tokenIndex: 0, balance: '5' }] }; },
      withdrawalClaim() { proofBuilds += 1; return structuredClone(artifact); },
    },
    snapshotVault: { load() { return { state: { digest: stateDigest } }; } },
    claimSettlement,
    sm: { signal() {} },
    alert: { async raise() {} },
    log: { info() {}, warn() {}, error() {} },
  };

  await exit.attemptDirectRecovery(ctx);
  assert.equal(proofBuilds, 1);
  assert.equal(store.get('exitClaimPlan').claims[0].claimOutboxPrepared, true);
  await exit.reconcileClaimOutboxActions(ctx, {
    chain: { durable: { number: 12, hash: `0x${'12'.repeat(32)}` } },
  });
  assert.equal(store.get('exitClaimPlan').claims[0].claimOutboxPrepared, false);
  await exit.attemptDirectRecovery(ctx);
  assert.equal(proofBuilds, 1, 'restart must never regenerate different claim calldata');
  assert.equal(submits, 2);
  assert.equal(store.get('exitClaimPlan').claims[0].claimTxHash, `0x${'37'.repeat(32)}`);
});

test('foreign claim/funds/credit winners are journaled and cannot unblock dependent actions before nonce settlement', async () => {
  const closeIntentDigest = `0x${'41'.repeat(32)}`;
  const nullifier = `0x${'42'.repeat(32)}`;
  const memberPkG = `0x${'43'.repeat(32)}`;
  const manager = '0x4444444444444444444444444444444444444444';
  const localClaim = `0x${'51'.repeat(32)}`;
  const localFunds = `0x${'52'.repeat(32)}`;
  const localCredit = `0x${'53'.repeat(32)}`;
  const foreignClaim = `0x${'61'.repeat(32)}`;
  const foreignFunds = `0x${'62'.repeat(32)}`;
  const foreignCredit = `0x${'63'.repeat(32)}`;
  const store = fakeStore({
    awaitingCredit: true,
    exitClaimPlan: {
      closeIntentDigest,
      claims: [{
        tokenSlot: 0,
        tokenIndex: 0,
        amount: '5',
        payoutAmount: '5',
        nullifier,
        memberPkG,
        claimOutboxPrepared: true,
        claimOutboxActionId: 'claim:7:3:0',
        claimTxHash: localClaim,
      }],
    },
  });
  const calls = [];
  const signals = [];
  const terminal = (hash) => ({
    phase: 'terminal',
    transactionHash: hash,
    terminal: { outcome: 'superseded-revert', transactionHash: hash },
  });
  const claimSettlement = {
    durableOutbox: true,
    async ownsTransaction() { return false; },
    async markClaimFinalized() { throw new Error('foreign claim must not use own-success path'); },
    async markFundsFinalized() { throw new Error('foreign funds must not use own-success path'); },
    async markCreditFinalized() { throw new Error('foreign credit must not use own-success path'); },
    async reconcileClaim(_manager, _slot, expected, observation) {
      calls.push({ kind: 'claim', expected, observation });
      return terminal(localClaim);
    },
    async reconcileFunds(_manager, _nullifier, _token, _amount, observation) {
      calls.push({ kind: 'funds', observation });
      return terminal(localFunds);
    },
    async reconcileCredit(_manager, _nullifier, _token, _amount, observation) {
      calls.push({ kind: 'credit', observation });
      return terminal(localCredit);
    },
  };
  const ctx = {
    ch: { id: 7, manager },
    slot: 3,
    recipient: RECIPIENT,
    store,
    claimSettlement,
    sm: { signal(value) { signals.push(value); } },
    alert: { async raise() {} },
    log: { info() {}, warn() {}, error() {} },
  };
  const event = (kind, txHash, logIndex, args) => ({
    kind,
    contract: 'manager',
    address: manager,
    txHash,
    blockNumber: 10,
    blockHash: `0x${'10'.repeat(32)}`,
    logIndex,
    args,
  });
  const reconciled = { chain: { durable: { number: 12, hash: `0x${'12'.repeat(32)}` } } };

  await exit.onClaimAccepted(event('WithdrawalClaimAccepted', foreignClaim, 2, {
    closeIntentDigest,
    withdrawalNullifier: nullifier,
    memberPkG,
    recipient: RECIPIENT,
    tokenIndex: 0,
    amount: '5',
  }), ctx);
  assert.equal(store.get('exitClaimPlan').claims[0].acceptedFinalized, undefined);
  assert.equal(store.get('exitClaimPlan').claims[0].claimSemanticObservation.transactionHash, foreignClaim);
  await exit.reconcileClaimOutboxActions(ctx, reconciled);
  assert.equal(store.get('exitClaimPlan').claims[0].acceptedFinalized, true);
  assert.equal(calls[0].expected.memberPkG, memberPkG);
  assert.equal(calls[0].observation.logIndex, 2);

  let item = store.get('exitClaimPlan').claims[0];
  store.set('exitClaimPlan', {
    ...store.get('exitClaimPlan'),
    claims: [{ ...item, fundsOutboxPrepared: true, fundsPullTxHash: localFunds }],
  });
  await exit.onFundsPulled(event('ChannelFundsPulled', foreignFunds, 3, {
    tokenIndex: 0,
    amount: '9',
    totalReceived: '9',
  }), ctx);
  assert.equal(store.get('exitClaimPlan').claims[0].fundsPulledFinalized, undefined);
  await exit.reconcileClaimOutboxActions(ctx, reconciled);
  item = store.get('exitClaimPlan').claims[0];
  assert.equal(item.fundsPulledFinalized, true);
  assert.equal(item.fundsPullTxHash, null, 'failed local hash moves into terminal evidence');
  assert.equal(calls[1].observation.transactionHash, foreignFunds);

  store.set('exitClaimPlan', {
    ...store.get('exitClaimPlan'),
    claims: [{ ...item, creditOutboxPrepared: true, pullTxHash: localCredit }],
  });
  await exit.onCreditConfirmed(event('WithdrawalClaimed', foreignCredit, 4, {
    withdrawalNullifier: nullifier,
    recipient: RECIPIENT,
    tokenIndex: 0,
    amount: '5',
  }), ctx);
  assert.deepEqual(signals, [], 'foreign semantics alone cannot release the local signer lane');
  await exit.reconcileClaimOutboxActions(ctx, reconciled);
  assert.equal(calls[2].observation.transactionHash, foreignCredit);
  assert.equal(store.get('exitClaimPlan').claims[0].paidFinalized, true);
  assert.equal(signals.length, 1, 'all-paid completion is driven after durable nonce settlement');
});

test('intent-only outbox crashes advance only after exact foreign semantics are verified', async () => {
  const closeIntentDigest = `0x${'71'.repeat(32)}`;
  const nullifier = `0x${'72'.repeat(32)}`;
  const memberPkG = `0x${'73'.repeat(32)}`;
  const manager = '0x4444444444444444444444444444444444444444';
  const store = fakeStore({
    awaitingCredit: true,
    exitClaimPlan: {
      closeIntentDigest,
      claims: [{
        tokenSlot: 0,
        tokenIndex: 0,
        amount: '5',
        payoutAmount: '5',
        nullifier,
        memberPkG,
        claimOutboxPrepared: true,
        claimOutboxActionId: 'claim:7:3:0',
      }],
    },
  });
  const signals = [];
  const semanticOnly = (observation) => ({
    phase: 'absent',
    semanticVerified: true,
    semanticEvidence: {
      semanticTransactionHash: observation.transactionHash,
      semanticBlockNumber: observation.blockNumber,
      semanticBlockHash: observation.blockHash,
      semanticLogIndex: observation.logIndex,
    },
  });
  const claimSettlement = {
    durableOutbox: true,
    async ownsTransaction() { return false; },
    async reconcileClaim(_manager, _slot, _expected, observation) {
      return semanticOnly(observation);
    },
    async reconcileFunds(_manager, _nullifier, _token, _amount, observation) {
      return semanticOnly(observation);
    },
    async reconcileCredit(_manager, _nullifier, _token, _amount, observation) {
      return semanticOnly(observation);
    },
  };
  const ctx = {
    ch: { id: 7, manager },
    slot: 3,
    recipient: RECIPIENT,
    store,
    claimSettlement,
    sm: { signal(value) { signals.push(value); } },
    alert: { async raise() {} },
    log: { info() {}, warn() {}, error() {} },
  };
  const event = (kind, txByte, logIndex, args) => ({
    kind,
    contract: 'manager',
    address: manager,
    txHash: `0x${txByte.repeat(32)}`,
    blockNumber: 10,
    blockHash: `0x${'10'.repeat(32)}`,
    logIndex,
    args,
  });
  const reconciled = { chain: { durable: { number: 12, hash: `0x${'12'.repeat(32)}` } } };

  await exit.onClaimAccepted(event('WithdrawalClaimAccepted', '81', 2, {
    closeIntentDigest,
    withdrawalNullifier: nullifier,
    memberPkG,
    recipient: RECIPIENT,
    tokenIndex: 0,
    amount: '5',
  }), ctx);
  await exit.reconcileClaimOutboxActions(ctx, reconciled);
  let item = store.get('exitClaimPlan').claims[0];
  assert.equal(item.claimNonceSettled, true);
  assert.equal(item.acceptedFinalized, true);
  assert.equal(item.claimTerminal.outcome, 'semantic-only');

  store.set('exitClaimPlan', {
    ...store.get('exitClaimPlan'),
    claims: [{ ...item, fundsOutboxPrepared: true }],
  });
  await exit.onFundsPulled(event('ChannelFundsPulled', '82', 3, {
    tokenIndex: 0,
    amount: '9',
    totalReceived: '9',
  }), ctx);
  await exit.reconcileClaimOutboxActions(ctx, reconciled);
  item = store.get('exitClaimPlan').claims[0];
  assert.equal(item.fundsNonceSettled, true);
  assert.equal(item.fundsPulledFinalized, true);
  assert.equal(item.fundsTerminal.outcome, 'semantic-only');

  store.set('exitClaimPlan', {
    ...store.get('exitClaimPlan'),
    claims: [{ ...item, creditOutboxPrepared: true }],
  });
  await exit.onCreditConfirmed(event('WithdrawalClaimed', '83', 4, {
    withdrawalNullifier: nullifier,
    recipient: RECIPIENT,
    tokenIndex: 0,
    amount: '5',
  }), ctx);
  assert.deepEqual(signals, [], 'intent metadata alone still defers protocol completion to recovery');
  await exit.reconcileClaimOutboxActions(ctx, reconciled);
  item = store.get('exitClaimPlan').claims[0];
  assert.equal(item.creditNonceSettled, true);
  assert.equal(item.paidFinalized, true);
  assert.equal(item.creditTerminal.outcome, 'semantic-only');
  assert.equal(signals.length, 1);
});

test('same-block close, claim, funds, and payout events survive claim-plan creation after the batch', async () => {
  const closeIntentDigest = `0x${'91'.repeat(32)}`;
  const stateDigest = `0x${'92'.repeat(32)}`;
  const nullifier = `0x${'93'.repeat(32)}`;
  const memberPkG = `0x${'94'.repeat(32)}`;
  const manager = '0x4444444444444444444444444444444444444444';
  const finalized = {
    channelId: 7,
    closeIntentDigest,
    finalChannelStateDigest: stateDigest,
    finalBalanceStateH1: `0x${'95'.repeat(32)}`,
    tokenCount: 1,
    tokenRegistry: [0],
  };
  const store = fakeStore({
    mode: 'exiting',
    awaitingCredit: true,
    closeLifecycle: {
      schemaVersion: 1,
      phase: exit.CLOSE_PHASES.FINALIZED,
      closeIntentDigest,
    },
    channelFinalized: true,
    closeFinalizedBlock: 10,
  });
  const signals = [];
  const semanticOnly = (observation) => ({
    phase: 'absent',
    semanticVerified: true,
    semanticEvidence: {
      semanticTransactionHash: observation.transactionHash,
      semanticBlockNumber: observation.blockNumber,
      semanticBlockHash: observation.blockHash,
      semanticLogIndex: observation.logIndex,
    },
  });
  const claimSettlement = {
    durableOutbox: true,
    async readFinalizedContext() { return finalized; },
    async submitClaim(_manager, artifact) {
      return {
        alreadySubmitted: true,
        txHash: null,
        outboxActionId: 'claim:7:3:0',
        tokenIndex: 0,
        nullifier: artifact.claim.withdrawalNullifier,
      };
    },
    async reconcileClaim(_manager, _slot, _expected, observation) {
      return semanticOnly(observation);
    },
    async reconcileFunds(_manager, _nullifier, _token, _amount, observation) {
      return semanticOnly(observation);
    },
    async reconcileCredit(_manager, _nullifier, _token, _amount, observation) {
      return semanticOnly(observation);
    },
    async ownsTransaction() { return false; },
  };
  const artifact = {
    claim: {
      closeIntentDigest,
      memberPkG,
      recipient: RECIPIENT,
      tokenSlot: 0,
      tokenIndex: 0,
      amount: '5',
      withdrawalNullifier: nullifier,
    },
    mleProof: { randomizedCommitment: `0x${'96'.repeat(32)}` },
  };
  const ctx = {
    ch: { id: 7, manager },
    slot: 3,
    recipient: RECIPIENT,
    store,
    claimSettlement,
    wallet: {
      importChannel() {},
      balance() { return { balances: [{ tokenSlot: 0, tokenIndex: 0, balance: '5' }] }; },
      withdrawalClaim() { return structuredClone(artifact); },
    },
    snapshotVault: { load() { return { state: { digest: stateDigest } }; } },
    sm: { signal(value) { signals.push(value); } },
    alert: { async raise() {} },
    log: { info() {}, warn() {}, error() {} },
  };
  const event = (kind, txByte, logIndex, args) => ({
    kind,
    contract: 'manager',
    address: manager,
    txHash: `0x${txByte.repeat(32)}`,
    blockNumber: 10,
    blockHash: `0x${'10'.repeat(32)}`,
    logIndex,
    args,
  });

  // These callbacks run after CloseFinalized in the same watcher batch, before recovery has built
  // the randomized claim artifact or learned its nullifier.
  await exit.onClaimAccepted(event('WithdrawalClaimAccepted', 'a1', 2, {
    closeIntentDigest,
    withdrawalNullifier: nullifier,
    memberPkG,
    recipient: RECIPIENT,
    tokenIndex: 0,
    amount: '5',
  }), ctx);
  await exit.onFundsPulled(event('ChannelFundsPulled', 'a2', 3, {
    tokenIndex: 0,
    amount: '9',
    totalReceived: '9',
  }), ctx);
  await exit.onCreditConfirmed(event('WithdrawalClaimed', 'a3', 4, {
    withdrawalNullifier: nullifier,
    recipient: RECIPIENT,
    tokenIndex: 0,
    amount: '5',
  }), ctx);
  assert.equal(store.get('exitClaimPlan'), undefined);
  assert.equal(Object.keys(store.get('deferredExitSemantics').claims).length, 1);

  await exit.attemptDirectRecovery(ctx);
  let item = store.get('exitClaimPlan').claims[0];
  assert.equal(item.claimSemanticObservation.transactionHash, `0x${'a1'.repeat(32)}`);
  assert.equal(item.fundsSemanticObservation.transactionHash, `0x${'a2'.repeat(32)}`);
  assert.equal(item.creditSemanticObservation.transactionHash, `0x${'a3'.repeat(32)}`);
  assert.deepEqual(signals, []);

  const reconciled = { chain: { durable: { number: 12, hash: `0x${'12'.repeat(32)}` } } };
  await exit.reconcileClaimOutboxActions(ctx, reconciled);
  assert.equal(store.get('exitClaimPlan').claims[0].acceptedFinalized, true);
  await exit.reconcileClaimOutboxActions(ctx, reconciled);
  assert.equal(store.get('exitClaimPlan').claims[0].fundsPulledFinalized, true);
  await exit.reconcileClaimOutboxActions(ctx, reconciled);
  item = store.get('exitClaimPlan').claims[0];
  assert.equal(item.paidFinalized, true);
  assert.equal(signals.length, 1, 'deferred exact payout reaches EXIT_DONE after ordered verification');
});

test('direct recovery rejects incomplete, duplicate, or non-canonical token balance reports', () => {
  const finalized = { tokenCount: 2, tokenRegistry: [0, 7] };
  assert.throws(
    () => exit.positiveBalances({ balances: [{ tokenSlot: 0, tokenIndex: 0, balance: '1' }] }, finalized),
    /every finalized token slot/,
  );
  assert.throws(
    () => exit.positiveBalances({ balances: [
      { tokenSlot: 0, tokenIndex: 0, balance: '1' },
      { tokenSlot: 0, tokenIndex: 0, balance: '0' },
    ] }, finalized),
    /duplicate token slot/,
  );
  assert.throws(
    () => exit.positiveBalances({ balances: [
      { tokenSlot: 0, tokenIndex: 0, balance: '01' },
      { tokenSlot: 1, tokenIndex: 7, balance: '0' },
    ] }, finalized),
    /non-canonical balance/,
  );
  assert.deepEqual(exit.positiveBalances({ balances: [
    { tokenSlot: 0, tokenIndex: 0, balance: '0' },
    { tokenSlot: 1, tokenIndex: 7, balance: '18446744073709551615' },
  ] }, finalized), [{ tokenSlot: 1, tokenIndex: 7, amount: '18446744073709551615' }]);
});

test('close-version comparison preserves the full uint64 range', () => {
  assert.equal(exit.canonicalU64('18446744073709551615', 'version'), '18446744073709551615');
  assert.throws(() => exit.canonicalU64(9007199254740992, 'version'), /exact unsigned integer/);
  assert.throws(() => exit.canonicalU64('18446744073709551616', 'version'), /outside uint64/);
});
