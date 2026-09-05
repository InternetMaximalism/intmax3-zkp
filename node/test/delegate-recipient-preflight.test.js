'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Interface } = require('ethers');
const { makeParticipantCloser, buildParticipantCloseProof, participantCloseActionId } = require('../delegate/participant-close');
const { makeClaimSettlement, MANAGER_CLAIM_ABI } = require('../delegate/claim-settlement');
const hash = n => `0x${n.repeat(32)}`;
const recipient = `0x${'11'.repeat(20)}`;
const manager = `0x${'44'.repeat(20)}`;

test('provider-only participant-close preflight carries the actual recipient sender', async () => {
  const iface = new Interface([
    'function participantRoot() view returns (bytes32)',
    'function activeParticipantCount() view returns (uint16)',
    'function currentCloseFreezeNonce() view returns (uint64)',
    'function highestCancelledRevivedStateVersion() view returns (uint64)',
    'function requestCloseAsParticipant(uint16 slot,bytes32 pkG,bytes32[10] siblings,uint64 expectedCurrentCloseFreezeNonce,uint64 expectedHighestCancelledRevivedStateVersion)',
  ]);
  const snapshot = { record: { memberCount: 1, delegateCount: 1, memberPkGs: [hash('11'), hash('22')] },
    state: { digest: hash('cc'), balanceState: { memberCount: 1, delegateCount: 1,
      recipients: [`0x${'22'.repeat(20)}`, recipient] } } };
  const proof = buildParticipantCloseProof(snapshot, 1, recipient);
  let checked = false;
  let saved = null;
  let sendCount = 0;
  let readinessCount = 0;
  const provider = { async getNetwork() { return { chainId: 31337n }; }, async call(tx) {
    const call = iface.parseTransaction(tx);
    if (call.name === 'requestCloseAsParticipant') {
      assert.equal(tx.from.toLowerCase(), recipient);
      assert.equal(call.args.slot, 1n);
      checked = true;
      return '0x';
    }
    const values = { participantRoot: proof.participantRoot, activeParticipantCount: 2n,
      currentCloseFreezeNonce: 0n, highestCancelledRevivedStateVersion: 0n };
    assert.ok(call.name in values);
    return iface.encodeFunctionResult(call.name, [values[call.name]]);
  } };
  const outbox = { signerAddress: recipient, provider, status() { return saved; }, async send(tx) {
    if (!saved) assert.equal(checked, true, 'recipient-bound simulation precedes the offline signer');
    sendCount += 1;
    assert.equal(iface.parseTransaction(tx).name, 'requestCloseAsParticipant');
    return { transactionHash: hash('77'), phase: 'broadcast' };
  } };
  const closer = makeParticipantCloser({ chainId: 31337, recipient, provider, outbox,
    channelId: 7, participantSlot: 1 });
  const era = { expectedCurrentCloseFreezeNonce: '0', expectedHighestCancelledRevivedStateVersion: '0',
    checkpoint: { number: 10, hash: hash('aa') } };
  const actionId = participantCloseActionId({ chainId: 31337, manager, channelId: 7, slot: 1, era });
  const checkReadiness = async () => {
    readinessCount += 1;
    return { ready: true, chainId: 31337, channelId: 7, manager,
      signedHeadDigest: proof.stateDigest, currentCloseFreezeNonce: 0 };
  };
  await assert.rejects(closer.requestClose(manager, proof, null, { actionId, era }), /requires exact-head public-close readiness/);
  await assert.rejects(closer.requestClose(manager, proof, null, { actionId, era,
    checkReadiness: async () => { throw new Error('backing not finalized'); } }), /backing not finalized/);
  assert.equal(sendCount, 0, 'readiness errors never reach the offline signer');
  assert.equal((await closer.requestClose(manager, proof, null, { actionId, era, checkReadiness })).txHash, hash('77'));
  assert.equal(readinessCount, 1);
  saved = { transactionHash: hash('77') };
  checked = false;
  assert.equal((await closer.requestClose(manager, proof, null, { actionId, era,
    checkReadiness: async () => { throw new Error('must not block exact raw replay'); } })).txHash, hash('77'));
  assert.equal(checked, false, 'exact raw replay does not repeat pre-freeze simulation');
  assert.equal(sendCount, 2);
});

test('provider-only exact nullifier payout preflight carries the actual recipient sender', async () => {
  const iface = new Interface(MANAGER_CLAIM_ABI);
  const nullifier = hash('bb');
  const txHash = hash('88');
  let checked = false;
  const provider = { async getNetwork() { return { chainId: 31337n }; }, async call(tx) {
    const call = iface.parseTransaction(tx);
    if (call.name === 'claimWithdrawalCredit') {
      assert.equal(tx.from.toLowerCase(), recipient);
      assert.equal(call.args[0], nullifier);
      checked = true;
      return iface.encodeFunctionResult(call.fragment, [9n]);
    }
    const values = { withdrawalPayouts: [recipient, 0n, 9n], withdrawalCredits: [9n],
      receivedChannelFunds: [9n], totalCreditedOut: [0n] };
    assert.ok(call.name in values);
    return iface.encodeFunctionResult(call.name, values[call.name]);
  } };
  const event = iface.encodeEventLog(iface.getEvent('WithdrawalClaimed'), [nullifier, recipient, 0, 9]);
  const outbox = { signerAddress: recipient, provider, status() { return null; },
    async resumeExact() { return { phase: 'absent' }; },
    async send(tx) {
      assert.equal(checked, true, 'recipient-bound simulation precedes the offline signer');
      assert.equal(iface.parseTransaction(tx).name, 'claimWithdrawalCredit');
      return { transactionHash: txHash, phase: 'broadcast' };
    },
    async waitForReceipt() { return { hash: txHash, status: 1, blockNumber: 12,
      logs: [{ address: manager, transactionHash: txHash, index: 0, ...event }] }; },
  };
  const settlement = makeClaimSettlement({ chainId: 31337, recipient, provider, outbox });
  const result = await settlement.pullCredit(manager, nullifier, 0, '9');
  assert.equal(result.txHash, txHash);
  assert.equal(result.amount, '9');
});
