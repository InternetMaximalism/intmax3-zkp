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
  normalizeMleProof,
  validateClaimArtifact,
} = require('../delegate/claim-settlement');
const { SnapshotVault } = require('../delegate/snapshot-vault');
const exit = require('../delegate/branches/exit');
const { resolveDelegateSeed } = require('../delegate');

const RECIPIENT = '0x0000000100000002000000030000000400000005';

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
  assert.equal(iface.getFunction('submitWithdrawalClaim').selector, '0x70f89118');
  assert.equal(iface.getFunction('pullChannelFunds').selector, '0x0829ffe3');
  assert.equal(iface.getFunction('pullChannelTokenFunds').selector, '0xcf450977');
  assert.equal(iface.getFunction('claimWithdrawalCredit').selector, '0xa1790781');
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
  const validated = validateClaimArtifact(artifact, finalized, RECIPIENT, descriptor.token_slot);
  assert.equal(validated.claim.amount, String(descriptor.amount));
  const calldata = iface.encodeFunctionData('submitWithdrawalClaim', [validated.claim, validated.proof]);
  assert.ok(calldata.startsWith('0x70f89118'));
  const decoded = iface.decodeFunctionData('submitWithdrawalClaim', calldata);
  assert.equal(decoded.claim.withdrawalNullifier, descriptor.withdrawal_nullifier);
  assert.equal(decoded.claim.amount.toString(), String(descriptor.amount));

  const redirected = structuredClone(artifact);
  redirected.claim.recipient = '0x1111111111111111111111111111111111111111';
  assert.throws(
    () => validateClaimArtifact(redirected, finalized, RECIPIENT, descriptor.token_slot),
    /recipient mismatch/,
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
      return { claim: { tokenSlot }, mleProof: {} };
    },
  };
  const claimSettlement = {
    async readFinalizedContext() { return finalized; },
    async claimStatus() { return 'accepted'; },
    async submitClaim(_manager, artifact, _finalized, tokenSlot, onBroadcast) {
      submissions.push({ artifact, tokenSlot });
      const txHash = `0x${String(tokenSlot + 1).padStart(64, '0')}`;
      artifact.claim.withdrawalNullifier = `0x${String(tokenSlot + 9).padStart(64, '0')}`;
      onBroadcast(txHash);
      return { txHash, tokenIndex: finalized.tokenRegistry[tokenSlot], nullifier: artifact.claim.withdrawalNullifier };
    },
    async pullCredit(_manager, tokenIndex, onBroadcast) {
      pulls.push(tokenIndex);
      const fundHash = `0x${String(tokenIndex + 30).padStart(64, '0')}`;
      const txHash = `0x${String(tokenIndex + 20).padStart(64, '0')}`;
      const amount = tokenIndex === 0 ? '5' : '9';
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
  assert.deepEqual(pulls, [0, 7]);
  assert.equal(store.get('exitClaimPlan').claims.length, 2);
  assert.ok(store.get('exitClaimPlan').claims.every((item) => item.claimTxHash && item.pullTxHash));
  assert.ok(store.get('exitClaimPlan').claims.every((item) => item.fundsPullTxHash == null));

  const manager = ctx.ch.manager;
  const item0 = () => store.get('exitClaimPlan').claims.find((item) => item.tokenIndex === 0);
  const item7 = () => store.get('exitClaimPlan').claims.find((item) => item.tokenIndex === 7);
  await exit.onClaimAccepted({
    kind: 'WithdrawalClaimAccepted', contract: 'manager', address: manager,
    txHash: item0().claimTxHash,
    args: {
      closeIntentDigest, withdrawalNullifier: item0().nullifier,
      recipient: RECIPIENT, tokenIndex: 0, amount: '5',
    },
  }, ctx);
  await exit.onClaimAccepted({
    kind: 'WithdrawalClaimAccepted', contract: 'manager', address: manager,
    txHash: item7().claimTxHash,
    args: {
      closeIntentDigest, withdrawalNullifier: item7().nullifier,
      recipient: RECIPIENT, tokenIndex: 7, amount: '9',
    },
  }, ctx);

  // Same-recipient rollup activity is global to the rollup and must never complete this channel's
  // exit. Nor may a different manager, payout tx, or amount satisfy the locally persisted plan.
  await exit.onCreditConfirmed({
    kind: 'NativeWithdrawn', contract: 'rollup', address: '0x5555555555555555555555555555555555555555',
    txHash: item0().pullTxHash, args: { recipient: RECIPIENT, tokenIndex: 0, amount: '5' },
  }, ctx);
  await exit.onCreditConfirmed({
    kind: 'WithdrawalClaimed', contract: 'manager', address: '0x6666666666666666666666666666666666666666',
    txHash: item0().pullTxHash, args: { recipient: RECIPIENT, tokenIndex: 0, amount: '5' },
  }, ctx);
  await exit.onCreditConfirmed({
    kind: 'WithdrawalClaimed', contract: 'manager', address: manager,
    txHash: `0x${'ee'.repeat(32)}`, args: { recipient: RECIPIENT, tokenIndex: 0, amount: '5' },
  }, ctx);
  await exit.onCreditConfirmed({
    kind: 'WithdrawalClaimed', contract: 'manager', address: manager,
    txHash: item0().pullTxHash, args: { recipient: RECIPIENT, tokenIndex: 0, amount: '6' },
  }, ctx);
  assert.deepEqual(signals, []);

  await exit.onCreditConfirmed({
    kind: 'WithdrawalClaimed', contract: 'manager', address: manager,
    txHash: item0().pullTxHash, args: { recipient: RECIPIENT, tokenIndex: 0, amount: '5' },
  }, ctx);
  assert.deepEqual(signals, []);
  await exit.onCreditConfirmed({
    kind: 'WithdrawalClaimed', contract: 'manager', address: manager,
    txHash: item7().pullTxHash, args: { recipient: RECIPIENT, tokenIndex: 7, amount: '9' },
  }, ctx);
  assert.equal(signals.length, 1);
  assert.equal(store.get('awaitingCredit'), false);
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
