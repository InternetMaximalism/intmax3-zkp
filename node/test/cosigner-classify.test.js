'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { classify, BRANCHES } = require('../cosigner/classify');

test('cosigner: peer cosign on active channel → PEER_TX_REQUEST', () => {
  assert.equal(classify({ source: 'api', kind: 'cosign' }, { status: 'active', mode: 'normal' }), BRANCHES.PEER_TX_REQUEST);
});

test('cosigner: peer cosign while NOT active → INVALID_REQUEST (cannot cosign a closing channel)', () => {
  for (const status of ['close_pending', 'close_submitted', 'closed', 'settled']) {
    assert.equal(classify({ source: 'api', kind: 'cosign' }, { status, mode: 'normal' }), BRANCHES.INVALID_REQUEST, status);
  }
});

test('cosigner: any peer request in defensive mode → INVALID_REQUEST', () => {
  for (const kind of ['cosign', 'cosign-refresh', 'inter', 'burn']) {
    assert.equal(classify({ source: 'api', kind }, { status: 'active', mode: 'defensive' }), BRANCHES.INVALID_REQUEST, kind);
  }
});

test('cosigner: explicit invalid flag → INVALID_REQUEST', () => {
  assert.equal(classify({ source: 'api', kind: 'cosign', invalid: true }, { status: 'active' }), BRANCHES.INVALID_REQUEST);
});

test('cosigner: snapshot read is always allowed (even defensive/closed)', () => {
  assert.equal(classify({ source: 'api', kind: 'snapshot' }, { status: 'closed', mode: 'defensive' }), BRANCHES.SNAPSHOT_POLL);
});

test('cosigner: unknown api kind → ATTACK_SUSPECTED (fail-closed)', () => {
  assert.equal(classify({ source: 'api', kind: 'wat' }, { status: 'active' }), BRANCHES.ATTACK_SUSPECTED);
});

test('cosigner: chain close events route to abnormal branches', () => {
  assert.equal(classify({ source: 'chain', kind: 'CloseRequested' }, {}), BRANCHES.CHAIN_CLOSE_REQUESTED);
  assert.equal(classify({ source: 'chain', kind: 'CloseSubmitted' }, {}), BRANCHES.CHAIN_CLOSE_SUBMITTED);
  assert.equal(classify({ source: 'chain', kind: 'SpecialCloseSubmitted' }, {}), BRANCHES.CHAIN_CLOSE_SUBMITTED);
  assert.equal(classify({ source: 'chain', kind: 'PartialWithdrawalSubmitted' }, {}), BRANCHES.CHAIN_PW_SUBMITTED);
  assert.equal(classify({ source: 'chain', kind: 'FraudConfirmed' }, {}), BRANCHES.ATTACK_SUSPECTED);
});

test('cosigner: benign chain events → CHAIN_OBSERVE, deposit/finalized routed', () => {
  assert.equal(classify({ source: 'chain', kind: 'Deposited' }, {}), BRANCHES.CHAIN_DEPOSITED);
  assert.equal(classify({ source: 'chain', kind: 'Finalized' }, {}), BRANCHES.CHAIN_BLOCK_FINALIZED);
  assert.equal(classify({ source: 'chain', kind: 'BlockPosted' }, {}), BRANCHES.CHAIN_OBSERVE);
  assert.equal(classify({ source: 'chain', kind: 'CloseCancelled' }, {}), BRANCHES.CHAIN_OBSERVE);
});

test('cosigner: unknown chain kind → CHAIN_OBSERVE (review M2: watcher only emits our ABI events; an unmapped one is benign/new, not an attack — do not freeze the channel)', () => {
  assert.equal(classify({ source: 'chain', kind: 'Nope' }, {}), BRANCHES.CHAIN_OBSERVE);
});

test('cosigner: timers route to own-action branches', () => {
  assert.equal(classify({ source: 'timer', kind: 'settle_due' }, {}), BRANCHES.TIMER_SETTLE_DUE);
  assert.equal(classify({ source: 'timer', kind: 'pw_finalize_due' }, {}), BRANCHES.TIMER_PW_FINALIZE_DUE);
  assert.equal(classify({ source: 'timer', kind: 'wat' }, {}), BRANCHES.ATTACK_SUSPECTED);
});

test('cosigner: malformed event → ATTACK_SUSPECTED', () => {
  assert.equal(classify(null, {}), BRANCHES.ATTACK_SUSPECTED);
  assert.equal(classify({}, {}), BRANCHES.ATTACK_SUSPECTED);
  assert.equal(classify({ source: 'ufo', kind: 'x' }, {}), BRANCHES.ATTACK_SUSPECTED);
});
