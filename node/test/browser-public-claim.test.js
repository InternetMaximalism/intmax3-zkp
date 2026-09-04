'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const vm = require('vm');

const {
  MANAGER_INTERFACE,
  NULLIFIER_PAYOUT_FUNCTION,
  SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR,
  SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR,
  BrowserClaimCoordinator,
  browserClaimOperationId,
  validateExactTransaction,
} = require('../browser-claim');
const {
  acquireClaimJournalLock,
  installBrowserClaimRoutes,
} = require('../../hosting/wallet/browser-claim-routes');

const MANAGER = '0x4444444444444444444444444444444444444444';
const ROLLUP = '0x5555555555555555555555555555555555555555';
const VERIFIER = '0x6666666666666666666666666666666666666666';
const MATERIALIZER = '0x7777777777777777777777777777777777777777';
const OTHER_MATERIALIZER = '0x8888888888888888888888888888888888888888';
const RECIPIENT = '0x0000000100000002000000030000000400000005';
const HASH100 = `0x${'10'.repeat(32)}`;
const HASH90 = `0x${'09'.repeat(32)}`;

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

function staticMethod(implementation = async () => true) {
  const fn = async (...args) => implementation(...args);
  fn.staticCall = async (...args) => implementation(...args);
  return fn;
}

function acceptedLog(claim, transactionHash = `0x${'aa'.repeat(32)}`) {
  const encoded = MANAGER_INTERFACE.encodeEventLog(
    MANAGER_INTERFACE.getEvent('WithdrawalClaimAccepted'),
    [
      claim.closeIntentDigest, claim.withdrawalNullifier, claim.memberPkG,
      claim.recipient, claim.amount, claim.tokenIndex,
    ],
  );
  return {
    address: MANAGER, topics: encoded.topics, data: encoded.data,
    transactionHash, blockNumber: 90, blockHash: HASH90,
  };
}

function payoutLog(claim, amount, transactionHash = `0x${'bb'.repeat(32)}`) {
  const encoded = MANAGER_INTERFACE.encodeEventLog(
    MANAGER_INTERFACE.getEvent('WithdrawalClaimed(bytes32,address,uint32,uint256)'),
    [claim.withdrawalNullifier, claim.recipient, claim.tokenIndex, amount],
  );
  return {
    address: MANAGER, topics: encoded.topics, data: encoded.data,
    transactionHash, blockNumber: 90, blockHash: HASH90,
  };
}

function fakeEnvironment() {
  const { descriptor, artifact } = fixtureArtifact();
  const state = {
    used: false,
    logs: [],
    credit: BigInt(descriptor.amount),
    received: BigInt(descriptor.amount) * 10n,
    paid: 0n,
    payout: {
      recipient: descriptor.recipient,
      tokenIndex: descriptor.token_index,
      amount: BigInt(descriptor.amount),
    },
    transactions: new Map(),
    receipts: new Map(),
    nullifierStaticCalls: [],
    usedReads: [],
    payoutReads: [],
  };
  const submitWithdrawalClaim = staticMethod();
  const manager = {
    async channelId() { return descriptor.channel_id; },
    async channelStatus() { return 2; },
    async registry() { return ROLLUP; },
    async verifier() { return VERIFIER; },
    async finalizedCloseIntentDigest() { return descriptor.close_intent_digest; },
    async finalizedChannelStateDigest() { return `0x${'77'.repeat(32)}`; },
    async finalizedBalanceStateH1() { return descriptor.final_balance_state_h1; },
    async finalizedTokenCount() { return 1; },
    async finalizedTokenRegistry() { return descriptor.token_index; },
    async usedWithdrawalNullifiers(_nullifier, options = {}) {
      state.usedReads.push(options.blockTag ?? null);
      return state.used;
    },
    async withdrawalCredits() { return state.credit; },
    async withdrawalPayouts(_nullifier, options = {}) {
      state.payoutReads.push(options.blockTag ?? null);
      return { ...state.payout, 0: state.payout.recipient, 1: state.payout.tokenIndex, 2: state.payout.amount };
    },
    async receivedChannelFunds() { return state.received; },
    async totalCreditedOut() { return state.paid; },
    getFunction(selector) {
      if ([SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR, SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR].includes(selector)) {
        return submitWithdrawalClaim;
      }
      throw new Error(`unexpected manager function ${selector}`);
    },
    [NULLIFIER_PAYOUT_FUNCTION]: staticMethod(async (...args) => {
      state.nullifierStaticCalls.push(String(args[0]).toLowerCase());
      return state.payout.amount;
    }),
  };
  const provider = {
    async getNetwork() { return { chainId: 31337n }; },
    async getBlock(tag) {
      if (tag === 'latest' || tag === 'finalized' || Number(tag) === 100) return { number: 100, hash: HASH100 };
      if (Number(tag) === 90) return { number: 90, hash: HASH90 };
      return null;
    },
    async getLogs() { return state.logs; },
    async getTransaction(hash) { return state.transactions.get(String(hash).toLowerCase()) || null; },
    async getTransactionReceipt(hash) { return state.receipts.get(String(hash).toLowerCase()) || null; },
  };
  const authority = {
    chainId: 31337,
    channelId: descriptor.channel_id,
    manager: MANAGER,
    rollup: ROLLUP,
    verifier: VERIFIER,
    closeFundingMaterializer: MATERIALIZER,
    startBlock: 0,
  };
  const coordinator = new BrowserClaimCoordinator({ authority, provider, contractFactory: () => manager });
  return { artifact, descriptor, authority, coordinator, manager, provider, state };
}

function installAccepted(env, claim, {
  transactionHash = `0x${'aa'.repeat(32)}`,
  target = MANAGER,
  extraLogs = [],
} = {}) {
  const exact = acceptedLog(claim, transactionHash);
  env.state.transactions.set(transactionHash, {
    hash: transactionHash,
    to: target,
    from: RECIPIENT,
    data: '0x1234',
    value: 0n,
  });
  env.state.receipts.set(transactionHash, {
    hash: transactionHash,
    status: 1,
    blockNumber: 90,
    blockHash: HASH90,
    logs: [...extraLogs, exact],
  });
  return exact;
}

test('browser claim preparation binds fixture PIs to one durable deployment and exact calldata', async () => {
  const env = fakeEnvironment();
  const prepared = await env.coordinator.prepare(env.artifact, env.descriptor.token_slot);
  assert.equal(prepared.status, 'prepared');
  assert.equal(prepared.claim.recipient, RECIPIENT.toLowerCase());
  assert.equal(prepared.claim.tokenIndex, env.descriptor.token_index);
  assert.equal(prepared.operationId, browserClaimOperationId(env.authority, env.descriptor.withdrawal_nullifier));
  assert.notEqual(prepared.operationId, browserClaimOperationId(
    { ...env.authority, closeFundingMaterializer: OTHER_MATERIALIZER },
    env.descriptor.withdrawal_nullifier,
  ));
  assert.equal(prepared.transaction.to, MANAGER.toLowerCase());
  assert.equal(prepared.mleAbiVersion, 1);
  assert.equal(prepared.submitWithdrawalClaimSelector, SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR);
  assert.equal(prepared.transaction.data.slice(0, 10), SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR);

  const redirected = structuredClone(env.artifact);
  redirected.claim.recipient = '0x1111111111111111111111111111111111111111';
  await assert.rejects(
    () => env.coordinator.prepare(redirected, env.descriptor.token_slot),
    /recipient mismatch/,
  );
});

test('manager reads reject a same-height durable fork switch', async () => {
  const env = fakeEnvironment();
  const replacement = `0x${'ef'.repeat(32)}`;
  let durableReads = 0;
  const originalGetBlock = env.provider.getBlock.bind(env.provider);
  env.provider.getBlock = async (tag) => {
    if (tag === 'latest' || tag === 'finalized') {
      durableReads += 1;
      return { number: 100, hash: durableReads === 1 ? HASH100 : replacement };
    }
    return originalGetBlock(tag);
  };
  await assert.rejects(
    () => env.coordinator.readContext(),
    /changed durable chain head/,
  );
});

test('browser payout is nullifier-scoped even when another aggregate claim credit coexists', async () => {
  const env = fakeEnvironment();
  const prepared = await env.coordinator.prepare(env.artifact, env.descriptor.token_slot);
  env.state.used = true;
  env.state.logs = [installAccepted(env, prepared.claim)];
  env.state.credit = BigInt(prepared.claim.amount) + 17n; // another accepted slot, same recipient/token

  const next = await env.coordinator.nextPayout(prepared);
  assert.equal(next.kind, 'payout');
  assert.equal(next.amount, prepared.claim.amount);
  const decoded = MANAGER_INTERFACE.decodeFunctionData(NULLIFIER_PAYOUT_FUNCTION, next.transaction.data);
  assert.equal(String(decoded.withdrawalNullifier).toLowerCase(), prepared.claim.withdrawalNullifier);
  assert.deepEqual(env.state.nullifierStaticCalls, [prepared.claim.withdrawalNullifier]);
  assert.equal(MANAGER_INTERFACE.getFunction(NULLIFIER_PAYOUT_FUNCTION).selector, '0xc7cf9d48');
  assert.equal(MANAGER_INTERFACE.getFunction('claimWithdrawalCredit(uint32,uint256)'), null);
});

test('finalized payout reconciliation requires recipient signer, exact calldata, manager event and amount', async () => {
  const env = fakeEnvironment();
  const prepared = await env.coordinator.prepare(env.artifact, env.descriptor.token_slot);
  env.state.used = true;
  env.state.logs = [installAccepted(env, prepared.claim)];
  const next = await env.coordinator.nextPayout(prepared);
  const action = { ...next, data: next.transaction.data };
  const txHash = `0x${'bb'.repeat(32)}`;
  env.state.transactions.set(txHash, {
    hash: txHash, to: MANAGER, from: RECIPIENT, data: action.transaction.data, value: 0n,
  });
  env.state.receipts.set(txHash, {
    hash: txHash, status: 1, blockNumber: 90, blockHash: HASH90,
    logs: [payoutLog(prepared.claim, prepared.claim.amount)],
  });
  env.state.payout.amount = 0n; // the nullifier-scoped record was consumed by this transaction
  const paid = await env.coordinator.reconcileAction(prepared, action, txHash);
  assert.equal(paid.status, 'paid');
  assert.equal(paid.amount, prepared.claim.amount);

  env.state.transactions.get(txHash).from = '0x1111111111111111111111111111111111111111';
  await assert.rejects(
    () => env.coordinator.reconcileAction(prepared, action, txHash),
    /leaf-bound recipient/,
  );
  env.state.transactions.get(txHash).from = RECIPIENT;
  env.state.receipts.get(txHash).hash = `0x${'cc'.repeat(32)}`;
  await assert.rejects(
    () => env.coordinator.reconcileAction(prepared, action, txHash),
    /receipt for a different transaction hash/,
  );
  env.state.receipts.get(txHash).hash = txHash;
  env.state.receipts.get(txHash).logs[0].transactionHash = `0x${'cc'.repeat(32)}`;
  await assert.rejects(
    () => env.coordinator.reconcileAction(prepared, action, txHash),
    /not bound to the reconciled receipt/,
  );
  env.state.receipts.get(txHash).logs[0].transactionHash = txHash;
  env.state.receipts.get(txHash).logs[0].address = ROLLUP;
  await assert.rejects(
    () => env.coordinator.reconcileAction(prepared, action, txHash),
    /exactly one matching WithdrawalClaimed/,
  );
});

test('fresh relay recognizes an already-paid claim only from its exact nullifier getter/event', async () => {
  const env = fakeEnvironment();
  const prepared = await env.coordinator.prepare(env.artifact, env.descriptor.token_slot);
  env.state.used = true;
  env.state.payout.amount = 0n;
  const accepted = installAccepted(env, prepared.claim);
  const payoutHash = `0x${'bb'.repeat(32)}`;
  const payout = payoutLog(prepared.claim, prepared.claim.amount, payoutHash);
  const payoutData = MANAGER_INTERFACE.encodeFunctionData(
    NULLIFIER_PAYOUT_FUNCTION,
    [prepared.claim.withdrawalNullifier],
  );
  env.state.transactions.set(payoutHash, {
    hash: payoutHash, to: MANAGER, from: RECIPIENT, data: payoutData, value: 0n,
  });
  env.state.receipts.set(payoutHash, {
    hash: payoutHash, status: 1, blockNumber: 90, blockHash: HASH90, logs: [payout],
  });
  env.state.logs = [accepted, payout];
  const next = await env.coordinator.nextPayout(prepared);
  assert.equal(next.status, 'paid');
  assert.equal(next.payout.withdrawalNullifier, prepared.claim.withdrawalNullifier);
  assert.equal(next.payout.amount, prepared.claim.amount);

  env.state.logs = [accepted];
  await assert.rejects(
    () => env.coordinator.nextPayout(prepared),
    /no live nullifier-scoped payout and no finalized payout event/,
  );
});

test('journaled paid state is revalidated against the current exact receipt and event', async () => {
  const env = fakeEnvironment();
  const prepared = await env.coordinator.prepare(env.artifact, env.descriptor.token_slot);
  env.state.used = true;
  env.state.payout.amount = 0n;
  const accepted = installAccepted(env, prepared.claim);
  const payoutHash = `0x${'bb'.repeat(32)}`;
  const payout = payoutLog(prepared.claim, prepared.claim.amount, payoutHash);
  const payoutData = MANAGER_INTERFACE.encodeFunctionData(
    NULLIFIER_PAYOUT_FUNCTION,
    [prepared.claim.withdrawalNullifier],
  );
  env.state.transactions.set(payoutHash, {
    hash: payoutHash, to: MANAGER, from: RECIPIENT, data: payoutData, value: 0n,
  });
  env.state.receipts.set(payoutHash, {
    hash: payoutHash, status: 1, blockNumber: 90, blockHash: HASH90, logs: [payout],
  });
  env.state.logs = [accepted, payout];
  const current = await env.coordinator.findPayout(prepared.claim, await env.coordinator.durableBlock());
  const paid = { ...prepared, status: 'paid', payout: current };
  assert.deepEqual(await env.coordinator.revalidatePaid(paid), current);

  env.state.logs = [accepted];
  await assert.rejects(
    () => env.coordinator.revalidatePaid(paid),
    /absent from the durable chain/,
  );
});

test('reverted exact submit adopts one finalized wrapper execution and still validates the local body', async () => {
  const env = fakeEnvironment();
  const prepared = await env.coordinator.prepare(env.artifact, env.descriptor.token_slot);
  const localHash = `0x${'c1'.repeat(32)}`;
  env.state.transactions.set(localHash, {
    hash: localHash,
    to: MANAGER,
    from: RECIPIENT,
    data: prepared.transaction.data,
    value: 0n,
  });
  env.state.receipts.set(localHash, {
    hash: localHash, status: 0, blockNumber: 90, blockHash: HASH90, logs: [],
  });

  env.state.used = true;
  const externalHash = `0x${'c2'.repeat(32)}`;
  const unrelatedClaim = {
    ...prepared.claim,
    amount: (BigInt(prepared.claim.amount) + 1n).toString(),
  };
  const unrelated = acceptedLog(unrelatedClaim, externalHash);
  const exact = installAccepted(env, prepared.claim, {
    transactionHash: externalHash,
    target: ROLLUP,
    extraLogs: [unrelated],
  });
  env.state.logs = [unrelated, exact];

  env.state.transactions.get(localHash).data = '0xdead';
  await assert.rejects(
    () => env.coordinator.reconcileSubmission(prepared, localHash),
    /calldata hash differs/,
  );
  env.state.transactions.get(localHash).data = prepared.transaction.data;

  const adopted = await env.coordinator.reconcileSubmission(prepared, localHash);
  assert.equal(adopted.status, 'accepted');
  assert.equal(adopted.txHash, externalHash);
  assert.equal(adopted.blockHash, HASH90);
  assert.ok(env.state.usedReads.includes(90), 'nullifier must be read at the event receipt block');
  assert.ok(env.state.payoutReads.includes(90), 'claim economics must be read at the event receipt block');
});

test('reverted exact payout adopts one finalized wrapper execution with exact economics', async () => {
  const env = fakeEnvironment();
  const prepared = await env.coordinator.prepare(env.artifact, env.descriptor.token_slot);
  env.state.used = true;
  const accepted = installAccepted(env, prepared.claim);
  env.state.logs = [accepted];
  const next = await env.coordinator.nextPayout(prepared);
  const action = { ...next, data: next.transaction.data };
  const localHash = `0x${'c3'.repeat(32)}`;
  env.state.transactions.set(localHash, {
    hash: localHash,
    to: MANAGER,
    from: RECIPIENT,
    data: action.data,
    value: 0n,
  });
  env.state.receipts.set(localHash, {
    hash: localHash, status: 0, blockNumber: 90, blockHash: HASH90, logs: [],
  });

  const wrongAction = { ...action, amount: (BigInt(action.amount) + 1n).toString() };
  await assert.rejects(
    () => env.coordinator.reconcileAction(prepared, wrongAction, localHash),
    /action amount differs/,
  );

  env.state.payout.amount = 0n;
  const externalHash = `0x${'c4'.repeat(32)}`;
  const unrelatedClaim = {
    ...prepared.claim,
    amount: (BigInt(prepared.claim.amount) + 1n).toString(),
  };
  const unrelated = payoutLog(unrelatedClaim, unrelatedClaim.amount, externalHash);
  const exact = payoutLog(prepared.claim, prepared.claim.amount, externalHash);
  env.state.transactions.set(externalHash, {
    hash: externalHash,
    to: ROLLUP,
    from: RECIPIENT,
    data: '0xdeadbeef',
    value: 0n,
  });
  env.state.receipts.set(externalHash, {
    hash: externalHash,
    status: 1,
    blockNumber: 90,
    blockHash: HASH90,
    logs: [unrelated, exact],
  });
  env.state.logs = [accepted, unrelated, exact];

  const adopted = await env.coordinator.reconcileAction(prepared, action, localHash);
  assert.equal(adopted.status, 'paid');
  assert.equal(adopted.txHash, externalHash);
  assert.equal(adopted.amount, prepared.claim.amount);
  assert.ok(env.state.usedReads.includes(90));
  assert.ok(env.state.payoutReads.includes(90));
});

test('semantic adoption rejects duplicate exact events, receipt stitching, and receipt-block getter stitching', async () => {
  const duplicate = fakeEnvironment();
  const duplicatePrepared = await duplicate.coordinator.prepare(
    duplicate.artifact, duplicate.descriptor.token_slot,
  );
  duplicate.state.used = true;
  const duplicateHash = `0x${'c5'.repeat(32)}`;
  const duplicateLog = acceptedLog(duplicatePrepared.claim, duplicateHash);
  const exact = installAccepted(duplicate, duplicatePrepared.claim, {
    transactionHash: duplicateHash,
    target: ROLLUP,
    extraLogs: [duplicateLog],
  });
  duplicate.state.logs = [exact];
  await assert.rejects(
    async () => duplicate.coordinator.findAccepted(
      duplicatePrepared.claim, await duplicate.coordinator.durableBlock(),
    ),
    /exactly one matching WithdrawalClaimAccepted/,
  );

  const duplicatePayout = fakeEnvironment();
  const duplicatePayoutPrepared = await duplicatePayout.coordinator.prepare(
    duplicatePayout.artifact, duplicatePayout.descriptor.token_slot,
  );
  duplicatePayout.state.used = true;
  duplicatePayout.state.payout.amount = 0n;
  const payoutHash = `0x${'c7'.repeat(32)}`;
  const payout = payoutLog(
    duplicatePayoutPrepared.claim, duplicatePayoutPrepared.claim.amount, payoutHash,
  );
  duplicatePayout.state.transactions.set(payoutHash, {
    hash: payoutHash, to: ROLLUP, from: RECIPIENT, data: '0xbeef', value: 0n,
  });
  duplicatePayout.state.receipts.set(payoutHash, {
    hash: payoutHash, status: 1, blockNumber: 90, blockHash: HASH90,
    logs: [payout, structuredClone(payout)],
  });
  duplicatePayout.state.logs = [payout];
  await assert.rejects(
    async () => duplicatePayout.coordinator.findPayout(
      duplicatePayoutPrepared.claim, await duplicatePayout.coordinator.durableBlock(),
    ),
    /exactly one matching WithdrawalClaimed/,
  );

  const stitched = fakeEnvironment();
  const stitchedPrepared = await stitched.coordinator.prepare(
    stitched.artifact, stitched.descriptor.token_slot,
  );
  stitched.state.used = true;
  const stitchedHash = `0x${'c6'.repeat(32)}`;
  const stitchedExact = installAccepted(stitched, stitchedPrepared.claim, {
    transactionHash: stitchedHash,
    target: ROLLUP,
  });
  stitched.state.logs = [stitchedExact];
  const stableReceipt = structuredClone(stitched.state.receipts.get(stitchedHash));
  let receiptReads = 0;
  stitched.provider.getTransactionReceipt = async (hash) => {
    if (String(hash).toLowerCase() !== stitchedHash) return null;
    receiptReads += 1;
    if (receiptReads === 1) return structuredClone(stableReceipt);
    return { ...structuredClone(stableReceipt), logs: [] };
  };
  await assert.rejects(
    async () => stitched.coordinator.findAccepted(
      stitchedPrepared.claim, await stitched.coordinator.durableBlock(),
    ),
    /evidence changed during finalized reconciliation/,
  );

  const getterStitched = fakeEnvironment();
  const getterPrepared = await getterStitched.coordinator.prepare(
    getterStitched.artifact, getterStitched.descriptor.token_slot,
  );
  getterStitched.state.used = true;
  const getterExact = installAccepted(getterStitched, getterPrepared.claim, { target: ROLLUP });
  getterStitched.state.logs = [getterExact];
  getterStitched.manager.usedWithdrawalNullifiers = async (_nullifier, { blockTag }) => (
    Number(blockTag) === 100
  );
  await assert.rejects(
    async () => getterStitched.coordinator.findAccepted(
      getterPrepared.claim, await getterStitched.coordinator.durableBlock(),
    ),
    /receipt block did not consume the exact withdrawal nullifier/,
  );
});

test('semantic adoption rejects a same-height finalized-head replacement', async () => {
  const env = fakeEnvironment();
  const prepared = await env.coordinator.prepare(env.artifact, env.descriptor.token_slot);
  env.state.used = true;
  env.state.logs = [installAccepted(env, prepared.claim, { target: ROLLUP })];
  const durable = await env.coordinator.durableBlock();
  const replacement = `0x${'ef'.repeat(32)}`;
  const originalGetBlock = env.provider.getBlock.bind(env.provider);
  env.provider.getBlock = async (tag) => {
    if (tag === 'latest' || tag === 'finalized') return { number: 100, hash: replacement };
    return originalGetBlock(tag);
  };
  await assert.rejects(
    () => env.coordinator.findAccepted(prepared.claim, durable),
    /crossed a changed durable chain head/,
  );
});

test('semantic adoption never accepts mismatched amount, nullifier, or recipient', async () => {
  for (const [label, mutate] of [
    ['amount', (claim) => ({ ...claim, amount: (BigInt(claim.amount) + 1n).toString() })],
    ['nullifier', (claim) => ({ ...claim, withdrawalNullifier: `0x${'fe'.repeat(32)}` })],
    ['recipient', (claim) => ({ ...claim, recipient: ROLLUP })],
  ]) {
    const submitEnv = fakeEnvironment();
    const submitPrepared = await submitEnv.coordinator.prepare(
      submitEnv.artifact, submitEnv.descriptor.token_slot,
    );
    submitEnv.state.used = true;
    const wrongSubmit = mutate(submitPrepared.claim);
    submitEnv.state.logs = [acceptedLog(wrongSubmit)];
    await assert.rejects(
      async () => submitEnv.coordinator.findAccepted(
        submitPrepared.claim, await submitEnv.coordinator.durableBlock(),
      ),
      /no unique exact finalized acceptance event/,
      `submit ${label} substitution`,
    );

    const payoutEnv = fakeEnvironment();
    const payoutPrepared = await payoutEnv.coordinator.prepare(
      payoutEnv.artifact, payoutEnv.descriptor.token_slot,
    );
    payoutEnv.state.used = true;
    payoutEnv.state.payout.amount = 0n;
    const wrongPayout = mutate(payoutPrepared.claim);
    payoutEnv.state.logs = [payoutLog(wrongPayout, wrongPayout.amount)];
    assert.equal(
      await payoutEnv.coordinator.findPayout(
        payoutPrepared.claim, await payoutEnv.coordinator.durableBlock(),
      ),
      null,
      `payout ${label} substitution`,
    );
  }
});

test('exact transaction validator rejects target, data, value and signer substitutions', () => {
  const expected = { to: MANAGER, data: '0x1234', value: '0x0' };
  assert.equal(validateExactTransaction({ ...expected, from: RECIPIENT }, expected, RECIPIENT), true);
  assert.throws(() => validateExactTransaction({ ...expected, to: ROLLUP, from: RECIPIENT }, expected, RECIPIENT), /different manager/);
  assert.throws(() => validateExactTransaction({ ...expected, data: '0x5678', from: RECIPIENT }, expected, RECIPIENT), /calldata differs/);
  assert.throws(() => validateExactTransaction({ ...expected, value: 1n, from: RECIPIENT }, expected, RECIPIENT), /unexpected value/);
  assert.throws(() => validateExactTransaction({ ...expected, from: ROLLUP }, expected, RECIPIENT), /leaf-bound recipient/);
});

test('a reverted receipt does not release the retry fence before it is durable', async () => {
  const env = fakeEnvironment();
  const txHash = `0x${'dd'.repeat(32)}`;
  env.state.transactions.set(txHash, {
    hash: txHash, to: MANAGER, from: RECIPIENT, data: '0x1234', value: 0n,
  });
  env.state.receipts.set(txHash, {
    hash: txHash, status: 0, blockNumber: 101, blockHash: `0x${'11'.repeat(32)}`, logs: [],
  });
  assert.equal((await env.coordinator.finalizedReceipt(txHash)).status, 'mined');

  env.state.receipts.set(txHash, {
    hash: txHash, status: 0, blockNumber: 90, blockHash: HASH90, logs: [],
  });
  assert.equal((await env.coordinator.finalizedReceipt(txHash)).status, 'failed');
});

function fakeApp() {
  const routes = new Map();
  return {
    routes,
    get(pathname, handler) { routes.set(`GET ${pathname}`, handler); },
    post(pathname, handler) { routes.set(`POST ${pathname}`, handler); },
  };
}

function fakeResponse() {
  return {
    statusCode: 200,
    body: null,
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; },
  };
}

test('relay rejects caller authority and journals an idempotent proof handoff atomically', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-browser-claim-'));
  try {
    fs.writeFileSync(path.join(directory, 'settlement.json'), JSON.stringify({
      manager: MANAGER,
      rollup: ROLLUP,
      verifier: VERIFIER,
      close_funding_materializer: MATERIALIZER,
    }));
    const app = fakeApp();
    const operationId = `0x${'ab'.repeat(32)}`;
    const prepared = {
      schemaVersion: 1, operationId,
      authority: {
        chainId: 31337,
        channelId: 7,
        manager: MANAGER.toLowerCase(),
        rollup: ROLLUP.toLowerCase(),
        verifier: VERIFIER.toLowerCase(),
        closeFundingMaterializer: MATERIALIZER.toLowerCase(),
        startBlock: 0,
      },
      mleAbiVersion: 1,
      submitWithdrawalClaimSelector: SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR,
      claim: {
        closeIntentDigest: `0x${'01'.repeat(32)}`, memberPkG: `0x${'02'.repeat(32)}`,
        recipient: RECIPIENT.toLowerCase(), userAmountDigest: `0x${'08'.repeat(32)}`,
        amount: '9', tokenSlot: 0, tokenIndex: 0,
        withdrawalNullifier: `0x${'03'.repeat(32)}`,
      },
      finalized: {}, durable: { number: 1, hash: HASH100, source: 'latest' },
      submitDataHash: `0x${'04'.repeat(32)}`, status: 'prepared',
      transaction: { to: MANAGER.toLowerCase(), data: '0x1234', value: '0x0' },
    };
    let prepareCalls = 0;
    let submissionResult = null;
    let actionResult = null;
    installBrowserClaimRoutes(app, {
      reqChannel: () => 7,
      wc: (_ch, name) => path.join(directory, name),
      rollupOf: () => ROLLUP,
      cli: async () => JSON.stringify({
        schemaVersion: 1, status: 'active', chainId: 31337, channelId: 7,
        manager: MANAGER, rollup: ROLLUP, verifier: VERIFIER,
        closeFundingMaterializer: MATERIALIZER, activationCheckpoint: null,
      }),
      rpc: 'http://unused',
      coordinatorFactory: () => ({
        async prepare() { prepareCalls += 1; return structuredClone(prepared); },
        async readContext() { return { authority: prepared.authority, finalized: {}, durable: prepared.durable }; },
        async reconcileSubmission() { return structuredClone(submissionResult); },
        async reconcileAction() { return structuredClone(actionResult); },
      }),
    });

    const forbiddenRes = fakeResponse();
    await app.routes.get('POST /api/browser-claim/prepare')(
      { body: { artifact: {}, tokenSlot: 0, manager: ROLLUP } }, forbiddenRes,
    );
    assert.equal(forbiddenRes.statusCode, 400);
    assert.match(forbiddenRes.body.error, /forbidden: manager/);
    assert.equal(prepareCalls, 0);

    const first = fakeResponse();
    await app.routes.get('POST /api/browser-claim/prepare')({ body: { artifact: {}, tokenSlot: 0 } }, first);
    assert.equal(first.statusCode, 200);
    assert.equal(first.body.operationId, operationId);
    const journalFile = path.join(directory, 'browser_claim_journal.json');
    assert.equal(fs.statSync(journalFile).mode & 0o777, 0o600);

    // A regenerated zero-knowledge proof may have different public proof bytes while proving the
    // same nullifier/claim. Retry must return the first exact calldata, not strand the operation or
    // silently replace the transaction the durable journal pinned.
    prepared.transaction.data = '0x5678';
    prepared.submitDataHash = `0x${'09'.repeat(32)}`;
    const second = fakeResponse();
    await app.routes.get('POST /api/browser-claim/prepare')({ body: { artifact: {}, tokenSlot: 0 } }, second);
    assert.equal(second.statusCode, 200);
    assert.equal(second.body.transaction.data, '0x1234');
    let journal = JSON.parse(fs.readFileSync(journalFile, 'utf8'));
    assert.deepEqual(Object.keys(journal.operations), [operationId]);
    assert.equal(
      journal.operations[operationId].authority.closeFundingMaterializer,
      MATERIALIZER.toLowerCase(),
    );

    const losingSubmitHash = `0x${'31'.repeat(32)}`;
    const adoptedSubmitHash = `0x${'32'.repeat(32)}`;
    journal.operations[operationId].status = 'submit-pending';
    journal.operations[operationId].submitTxHash = losingSubmitHash;
    fs.writeFileSync(journalFile, JSON.stringify(journal), { mode: 0o600 });
    prepared.status = 'accepted';
    prepared.accepted = {
      txHash: adoptedSubmitHash, blockNumber: 90, blockHash: HASH90,
    };
    const adoptedDuringPrepare = fakeResponse();
    await app.routes.get('POST /api/browser-claim/prepare')(
      { body: { artifact: {}, tokenSlot: 0 } }, adoptedDuringPrepare,
    );
    assert.equal(adoptedDuringPrepare.statusCode, 200);
    assert.equal(adoptedDuringPrepare.body.submitTxHash, adoptedSubmitHash);

    journal = JSON.parse(fs.readFileSync(journalFile, 'utf8'));
    journal.operations[operationId].status = 'submit-pending';
    journal.operations[operationId].accepted = null;
    journal.operations[operationId].submitTxHash = losingSubmitHash;
    fs.writeFileSync(journalFile, JSON.stringify(journal), { mode: 0o600 });
    submissionResult = {
      status: 'accepted', txHash: adoptedSubmitHash, blockNumber: 90, blockHash: HASH90,
    };
    const submitStatus = fakeResponse();
    await app.routes.get('POST /api/browser-claim/status')(
      { body: { operationId } }, submitStatus,
    );
    assert.equal(submitStatus.statusCode, 200);
    assert.equal(submitStatus.body.status, 'accepted');
    assert.equal(submitStatus.body.submitTxHash, adoptedSubmitHash);
    journal = JSON.parse(fs.readFileSync(journalFile, 'utf8'));
    assert.equal(journal.operations[operationId].submitTxHash, adoptedSubmitHash);

    const losingPayoutHash = `0x${'33'.repeat(32)}`;
    const adoptedPayoutHash = `0x${'34'.repeat(32)}`;
    journal.operations[operationId].status = 'action-pending';
    journal.operations[operationId].action = {
      kind: 'payout', amount: '9', data: '0xcafe', dataHash: `0x${'35'.repeat(32)}`,
      status: 'pending', txHash: losingPayoutHash,
    };
    fs.writeFileSync(journalFile, JSON.stringify(journal), { mode: 0o600 });
    actionResult = {
      status: 'paid', txHash: adoptedPayoutHash, amount: '9', tokenIndex: 0,
      recipient: RECIPIENT.toLowerCase(),
      withdrawalNullifier: journal.operations[operationId].claim.withdrawalNullifier,
      blockNumber: 90, blockHash: HASH90,
    };
    const payoutStatus = fakeResponse();
    await app.routes.get('POST /api/browser-claim/status')(
      { body: { operationId } }, payoutStatus,
    );
    assert.equal(payoutStatus.statusCode, 200);
    assert.equal(payoutStatus.body.status, 'paid');
    assert.equal(payoutStatus.body.action.txHash, adoptedPayoutHash);
    journal = JSON.parse(fs.readFileSync(journalFile, 'utf8'));
    assert.equal(journal.operations[operationId].action.txHash, adoptedPayoutHash);
    assert.equal(journal.operations[operationId].payout.txHash, adoptedPayoutHash);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('browser claim journal mutex excludes a live relay and recovers only a provably dead owner', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-browser-claim-lock-'));
  const journalFile = path.join(directory, 'browser_claim_journal.json');
  const lockDirectory = `${journalFile}.lock`;
  try {
    const release = acquireClaimJournalLock(journalFile);
    assert.throws(
      () => acquireClaimJournalLock(journalFile),
      /locked by another relay process/,
    );
    release();
    assert.equal(fs.existsSync(lockDirectory), false);

    const exited = spawnSync(process.execPath, ['-e', 'process.exit(0)']);
    assert.equal(exited.status, 0);
    assert.ok(Number.isSafeInteger(exited.pid) && exited.pid > 0);
    fs.mkdirSync(lockDirectory, { mode: 0o700 });
    fs.writeFileSync(path.join(lockDirectory, 'owner.json'), JSON.stringify({
      schemaVersion: 1,
      hostname: os.hostname(),
      pid: exited.pid,
      token: `0x${'ab'.repeat(32)}`,
    }), { mode: 0o600 });

    const releaseAfterCrash = acquireClaimJournalLock(journalFile);
    releaseAfterCrash();
    assert.equal(fs.existsSync(lockDirectory), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('public browser authority requires matching durable runtime code hashes', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-browser-claim-authority-'));
  const checkpoint = {
    chainId: 1,
    blockNumber: 100,
    blockHash: HASH100,
    parentHash: HASH90,
    source: 'rpcFinalized',
  };
  const runtimeCodeHashes = {
    rollup: `0x${'41'.repeat(32)}`,
    verifier: `0x${'42'.repeat(32)}`,
    manager: `0x${'43'.repeat(32)}`,
    materializer: `0x${'44'.repeat(32)}`,
  };
  const settlementFile = path.join(directory, 'settlement.json');
  try {
    fs.writeFileSync(settlementFile, JSON.stringify({
      manager: MANAGER,
      rollup: ROLLUP,
      verifier: VERIFIER,
      close_funding_materializer: MATERIALIZER,
      activation_checkpoint: checkpoint,
      runtime_code_hashes: runtimeCodeHashes,
    }));
    const installed = installBrowserClaimRoutes(fakeApp(), {
      reqChannel: () => 7,
      wc: (_ch, name) => path.join(directory, name),
      rollupOf: () => ROLLUP,
      cli: async () => JSON.stringify({
        schemaVersion: 1,
        status: 'active',
        chainId: 1,
        channelId: 7,
        manager: MANAGER,
        rollup: ROLLUP,
        verifier: VERIFIER,
        closeFundingMaterializer: MATERIALIZER,
        activationCheckpoint: checkpoint,
        runtimeCodeHashes,
      }),
      rpc: 'http://unused',
      coordinatorFactory: () => ({}),
    });
    const authority = await installed.trustedAuthority(7);
    assert.equal(authority.chainId, 1);
    assert.equal(authority.closeFundingMaterializer, MATERIALIZER);

    fs.writeFileSync(settlementFile, JSON.stringify({
      manager: MANAGER,
      rollup: ROLLUP,
      verifier: VERIFIER,
      close_funding_materializer: OTHER_MATERIALIZER,
      activation_checkpoint: checkpoint,
      runtime_code_hashes: runtimeCodeHashes,
    }));
    await assert.rejects(
      () => installed.trustedAuthority(7),
      /durable ACTIVE settlement authority differs/,
    );

    fs.writeFileSync(settlementFile, JSON.stringify({
      manager: MANAGER,
      rollup: ROLLUP,
      verifier: VERIFIER,
      close_funding_materializer: MATERIALIZER,
      activation_checkpoint: checkpoint,
      runtime_code_hashes: { ...runtimeCodeHashes, materializer: `0x${'99'.repeat(32)}` },
    }));
    await assert.rejects(
      () => installed.trustedAuthority(7),
      /runtime code hashes differ/,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('shipped browser gates reject relay recipient/token/manager substitution and UI uses browser-owned claim route', () => {
  const htmlPath = path.join(__dirname, '../../hosting/wallet/wallet-live.html');
  const html = fs.readFileSync(htmlPath, 'utf8');
  const begin = html.indexOf('// TESTABLE-BEGIN: deposit-ui');
  const end = html.indexOf('// TESTABLE-END: deposit-ui');
  const source = html.slice(begin, end);
  const gates = vm.runInThisContext(
    `(function(){${source}; return {normalizeBrowserClaimContext,validateBrowserClaimPrepared,validateBrowserClaimAction,validateBrowserClaimPinnedRecord};})()`,
    { filename: 'wallet-live.html#browser-claim-gates' },
  );
  const context = gates.normalizeBrowserClaimContext({
    schemaVersion: 1,
    authority: {
      chainId: 1,
      channelId: 7,
      manager: MANAGER,
      rollup: ROLLUP,
      verifier: VERIFIER,
      closeFundingMaterializer: MATERIALIZER,
      startBlock: 50,
    },
    finalized: {
      channelId: 7, closeIntentDigest: `0x${'01'.repeat(32)}`,
      finalChannelStateDigest: `0x${'02'.repeat(32)}`, finalBalanceStateH1: `0x${'03'.repeat(32)}`,
      tokenCount: 1, tokenRegistry: [0],
    },
    durable: { number: 100, hash: HASH100, source: 'finalized' },
  }, 7);
  const artifact = {
    claim: {
      closeIntentDigest: context.finalized.closeIntentDigest, memberPkG: `0x${'04'.repeat(32)}`,
      recipient: RECIPIENT, userAmountDigest: `0x${'07'.repeat(32)}`,
      amount: '9', tokenSlot: 0, tokenIndex: 0,
      withdrawalNullifier: `0x${'05'.repeat(32)}`,
    },
    mleProof: { protocolVersion: 1, constituentWidth: 160 },
  };
  const word = (value) => BigInt(value).toString(16).padStart(64, '0');
  const submitData = SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR
    + artifact.claim.closeIntentDigest.slice(2)
    + artifact.claim.memberPkG.slice(2)
    + '0'.repeat(24) + artifact.claim.recipient.slice(2).toLowerCase()
    + artifact.claim.userAmountDigest.slice(2)
    + word(artifact.claim.amount)
    + word(artifact.claim.tokenSlot)
    + word(artifact.claim.tokenIndex)
    + artifact.claim.withdrawalNullifier.slice(2)
    + word(0x120);
  const prepared = {
    schemaVersion: 1, operationId: `0x${'06'.repeat(32)}`, authority: context.authority,
    mleAbiVersion: 2, submitWithdrawalClaimSelector: SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR,
    claim: structuredClone(artifact.claim), status: 'prepared',
    transaction: { to: MANAGER, data: submitData, value: '0x0' },
  };
  assert.equal(gates.validateBrowserClaimPrepared(prepared, context, artifact, 0, RECIPIENT), prepared);
  assert.throws(
    () => gates.validateBrowserClaimPrepared({ ...prepared, authority: { ...prepared.authority, manager: ROLLUP } }, context, artifact, 0, RECIPIENT),
    /changed manager/,
  );
  assert.throws(
    () => gates.validateBrowserClaimPrepared({ ...prepared, claim: { ...prepared.claim, tokenIndex: 1 } }, context, artifact, 0, RECIPIENT),
    /wallet WASM field tokenIndex/,
  );
  assert.throws(
    () => gates.validateBrowserClaimPrepared(prepared, context, artifact, 0, ROLLUP),
    /not the proof-bound claim recipient/,
  );
  const payout = {
    ...prepared,
    status: 'action-ready',
    action: { kind: 'payout', amount: '9' },
    transaction: {
      to: MANAGER,
      value: '0x0',
      data: '0xc7cf9d48' + artifact.claim.withdrawalNullifier.slice(2),
    },
  };
  const pin = {
    operationId: prepared.operationId,
    authority: structuredClone(prepared.authority),
    claim: structuredClone(prepared.claim),
    mleAbiVersion: prepared.mleAbiVersion,
    submitWithdrawalClaimSelector: prepared.submitWithdrawalClaimSelector,
  };
  assert.equal(gates.validateBrowserClaimAction(payout, context, pin), payout);
  assert.throws(
    () => gates.validateBrowserClaimAction({
      ...payout,
      authority: { ...payout.authority, manager: ROLLUP },
      transaction: { ...payout.transaction, to: ROLLUP },
    }, context, pin),
    /changed pinned authority manager/,
  );
  assert.throws(
    () => gates.validateBrowserClaimPinnedRecord({
      ...payout,
      claim: { ...payout.claim, recipient: ROLLUP },
    }, context, pin),
    /changed pinned claim recipient/,
  );
  assert.throws(
    () => gates.validateBrowserClaimAction({ ...payout, transaction: { ...payout.transaction, data: '0x8cc7e172' + word(0) + word(9) } }),
    /exact local encoding/,
  );
  assert.match(html, /call\('withdrawalClaim'/);
  assert.match(html, /\/api\/browser-claim\/prepare/);
  assert.doesNotMatch(html, /api\('\/api\/claim'/);
  const worker = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-worker.js'), 'utf8');
  assert.match(worker, /wasm\.wallet_withdrawal_claim/);
  assert.match(html, /refusing to replace a different verified snapshot under the same digest/);
});
