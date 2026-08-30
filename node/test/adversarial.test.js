'use strict';
// Adversarial regression tests for the fixes from the M4 review. Each test names the finding it
// guards (DESIGN.md §5.4: "document what security property the test proves").
const test = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { verifyCosignedStructural } = require('../delegate/verify');
const { classify: cosClassify, BRANCHES: COS } = require('../cosigner/classify');
const { Store } = require('../common/store');
const wire = require('../common/wire');
const { actionIdFrom, handleCosign } = require('../cosigner/branches/cosign');

const HEAD = '0x' + '11'.repeat(32);
const NEXT = '0x' + '22'.repeat(32);
const PREV = { digest: HEAD, epoch: 1, stateVersion: 4 };
function signedState(extra = {}) {
  return { state: { memberSignatures: ['s0', 's1', 's2'], prevDigest: HEAD, digest: NEXT, balanceState: { stateVersion: 5 }, ...extra } };
}

// --- H4: the canonical Rust response is a bare ChannelState; bind it by the signed digest ---
test('H4: canonical camelCase response needs no invented channelTx echo when digest matches', () => {
  const sent = { channelTx: { recipientPkG: '0xRECIP' }, proposedNextState: { digest: NEXT } };
  const resp = signedState();
  const v = verifyCosignedStructural(sent, resp, PREV);
  assert.equal(v.ok, true);
});

test('H4: verify REJECTS a different signed state digest', () => {
  const sent = { channelTx: { recipientPkG: '0xRECIP' }, proposedNextState: { digest: '0x' + '33'.repeat(32) } };
  const resp = signedState();
  const v = verifyCosignedStructural(sent, resp, PREV);
  assert.equal(v.ok, false);
  assert.match(v.reason, /digest/);
});

test('H4: verify REJECTS a mismatched optional channelTx echo', () => {
  const tx = { recipientPkG: '0xRECIP', encAmount: { c1: [1] }, nonce: '0xN' };
  const resp = signedState();
  resp.channelTx = { ...tx, nonce: '0xDIFFERENT' };
  assert.equal(verifyCosignedStructural({ channelTx: tx, proposedNextState: { digest: NEXT } }, resp, PREV).ok, false);
});

test('H4: verify ACCEPTS a faithful optional camelCase echo', () => {
  const tx = { recipientPkG: '0xRECIP', encAmount: { c1: [1], c2: [2] }, nonce: '0xN' };
  const resp = signedState(); resp.channelTx = { ...tx };
  assert.equal(verifyCosignedStructural({ channelTx: tx, proposedNextState: { digest: NEXT } }, resp, PREV).ok, true);
});

// --- H2: action ids are content-addressed, not lengths (collisions / splits) ---
test('H2: distinct real txHash bindings get DISTINCT action ids', () => {
  assert.notEqual(actionIdFrom('inter', '0x' + 'aa'.repeat(32)), actionIdFrom('inter', '0x' + 'bb'.repeat(32)));
});

test('H2: recursive canonical JSON distinguishes nested payloads and ignores key order', () => {
  const a = { outer: { z: 1, a: [2, { x: 3 }] } };
  const reordered = { outer: { a: [2, { x: 3 }], z: 1 } };
  const different = { outer: { a: [2, { x: 4 }], z: 1 } };
  assert.equal(wire.canonical(a), wire.canonical(reordered));
  assert.notEqual(wire.canonical(a), wire.canonical(different));
});

test('wire aliases fail closed when camelCase and snake_case conflict', () => {
  assert.throws(
    () => wire.descriptorTxHash({ txHash: '0x' + 'aa'.repeat(32), tx_hash: '0x' + 'bb'.repeat(32) }),
    /conflicting wire aliases/,
  );
});

test('Rust camelCase SendPayload is accepted and bare ChannelState signatures are recognized', async () => {
  const f = path.join(os.tmpdir(), `intmax-wire-${Date.now()}-${Math.random()}.json`);
  let runs = 0;
  try {
    const result = await handleCosign({
      body: { proposedNextState: { digest: NEXT }, channelTx: { nonce: '0x01' } },
    }, {
      ch: { id: 7, workDir: os.tmpdir() },
      store: new Store(f),
      log: { info() {} },
      cli: {
        writeJson() {},
        async run() { runs += 1; },
        readJson() { return { digest: NEXT, memberSignatures: ['s0'] }; },
      },
    });
    assert.equal(result.status, 200);
    assert.equal(runs, 1);
  } finally {
    fs.rmSync(f, { force: true });
  }
});

test('cosign refuses a missing or malformed proposed-state digest before CLI execution', async () => {
  let runs = 0;
  const ctx = {
    ch: { id: 7, workDir: os.tmpdir() },
    store: { claimAction() { throw new Error('must not claim'); } },
    log: { info() {} },
    cli: { writeJson() {}, async run() { runs += 1; }, readJson() { return {}; } },
  };
  const missing = await handleCosign({ body: { proposedNextState: {} } }, ctx);
  const malformed = await handleCosign({ body: { proposedNextState: { digest: '0x1234' } } }, ctx);
  assert.equal(missing.status, 400);
  assert.equal(malformed.status, 400);
  assert.equal(runs, 0);
});

// --- MED-1: the getPendingClose ABI must match the real PendingClose field order (decode test) ---
test('MED-1: getPendingClose ABI decodes finalEpoch/finalStateVersion at the CORRECT positions', () => {
  const ethers = require('ethers');
  const { MANAGER_GETTER_ABI } = require('../common/chain-watcher');
  const iface = new ethers.Interface(MANAGER_GETTER_ABI);
  const output = iface.getFunction('getPendingClose').outputs[0];
  // Encode the exact Solidity PendingClose layout independently. In particular, put a large value
  // in channelFundAmounts[5]: the stale watcher ABI decoded that word as finalStateVersion and could
  // suppress the stale-close response for a six-token channel.
  const TUPLE = '(bool active,uint64 closeNonce,uint64 finalEpoch,uint64 finalSmallBlockNumber,uint64 closeFreezeNonce,uint64 challengeDeadline,bytes32 closeIntentDigest,bytes32 finalChannelStateDigest,bytes32 finalBalanceStateH1,uint256[10] channelFundAmounts,uint32[10] tokenRegistry,uint8 tokenCount,bytes32 channelFundIntmaxStateRoot,bytes32 burnTxHash,bytes32 closeWithdrawalDigest,uint64 snapshotMediumBlockNumber,uint64 finalStateVersion,bytes32 finalSettledTxChain,bytes32 finalSettledTxAccumulatorRoot)';
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const Z = ethers.ZeroHash;
  // active, closeNonce=1, finalEpoch=3, fsbn=0, freeze=1, deadline=99, digest, ..., finalStateVersion=42, ...
  const funds = [1000n, 0, 0, 0, 0, (1n << 200n), 0, 0, 0, 0];
  const registry = [0, 1, 2, 3, 4, 5, 0, 0, 0, 0];
  const encoded = coder.encode([TUPLE], [[
    true, 1, 3, 0, 1, 99, ethers.id('d'), Z, Z, funds, registry, 6, Z, Z, Z, 0,
    42, Z, Z,
  ]]);
  const [r] = coder.decode([output], encoded);
  assert.equal(Number(r.finalEpoch), 3);
  assert.equal(Number(r.finalStateVersion), 42);
  assert.equal(Number(r.challengeDeadline), 99);
  assert.equal(r.channelFundAmounts[5], 1n << 200n);
  assert.equal(Number(r.tokenCount), 6);
  assert.equal(r.active, true);
});

// --- M2: an unknown/new chain event does NOT freeze the channel (routes to CHAIN_OBSERVE) ---
test('M2: unmapped chain event → CHAIN_OBSERVE, not ATTACK_SUSPECTED', () => {
  assert.equal(cosClassify({ source: 'chain', kind: 'SomeFutureBenignEvent' }, {}), COS.CHAIN_OBSERVE);
  // but malformed non-chain input is still fail-closed
  assert.equal(cosClassify({ source: 'ufo', kind: 'x' }, {}), COS.ATTACK_SUSPECTED);
});

// --- M6: a failed/released action is retryable; a completed one is not ---
test('M6: releaseAction makes a failed claim retryable; completeAction is permanent', () => {
  const f = path.join(os.tmpdir(), `intmax-retry-${Date.now()}.json`);
  try {
    const s = new Store(f);
    assert.equal(s.claimAction('claim:7:3'), true);
    s.releaseAction('claim:7:3');                 // simulate transient failure
    assert.equal(s.claimAction('claim:7:3'), true); // retry allowed
    s.completeAction('claim:7:3', 'submitted');     // success
    s.releaseAction('claim:7:3');                  // must NOT release a completed action
    assert.equal(s.claimAction('claim:7:3'), false); // still blocked (no double-submit)
  } finally { fs.rmSync(f, { force: true }); }
});
