'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { classify, BRANCHES } = require('../delegate/classify');

test('delegate: intents route in normal mode', () => {
  assert.equal(classify({ source: 'api', kind: 'send' }, { mode: 'normal' }), BRANCHES.INTENT_SEND);
  assert.equal(classify({ source: 'api', kind: 'inter' }, { mode: 'normal' }), BRANCHES.INTENT_INTER_SEND);
  assert.equal(classify({ source: 'api', kind: 'burn' }, { mode: 'normal' }), BRANCHES.INTENT_BURN);
  assert.equal(classify({ source: 'api', kind: 'refresh' }, { mode: 'normal' }), BRANCHES.NEED_REFRESH);
});

test('delegate: in EXIT mode, outbound intents are dropped but sync/balance still work', () => {
  assert.equal(classify({ source: 'api', kind: 'send' }, { mode: 'exiting' }), BRANCHES.IGNORE);
  assert.equal(classify({ source: 'api', kind: 'inter' }, { mode: 'exiting' }), BRANCHES.IGNORE);
  assert.equal(classify({ source: 'api', kind: 'burn' }, { mode: 'exiting' }), BRANCHES.IGNORE);
  assert.equal(classify({ source: 'api', kind: 'snapshot' }, { mode: 'exiting' }), BRANCHES.SNAPSHOT_UPDATED);
  assert.equal(classify({ source: 'api', kind: 'balance' }, { mode: 'exiting' }), BRANCHES.BALANCE_POLL);
});

test('delegate: hard signals route to abnormal branches in any mode', () => {
  assert.equal(classify({ source: 'signal', kind: 'cosign_invalid' }, { mode: 'normal' }), BRANCHES.COSIGN_INVALID);
  assert.equal(classify({ source: 'signal', kind: 'withholding' }, { mode: 'normal' }), BRANCHES.COSIGNER_WITHHOLDING);
  assert.equal(classify({ source: 'signal', kind: 'equivocation' }, { mode: 'exiting' }), BRANCHES.EQUIVOCATION);
  assert.equal(classify({ source: 'signal', kind: 'unknown' }, {}), BRANCHES.EQUIVOCATION); // fail-closed
});

test('delegate: chain close/finalize route to exit-related branches', () => {
  assert.equal(classify({ source: 'chain', kind: 'CloseSubmitted' }, {}), BRANCHES.CHAIN_CLOSE_SEEN);
  assert.equal(classify({ source: 'chain', kind: 'CloseFinalized' }, {}), BRANCHES.CHAIN_FINALIZED);
  assert.equal(classify({ source: 'chain', kind: 'FraudConfirmed' }, {}), BRANCHES.EQUIVOCATION);
  assert.equal(classify({ source: 'chain', kind: 'BlockPosted' }, {}), BRANCHES.IGNORE);
});

test('delegate: malformed event → EQUIVOCATION (fail-closed)', () => {
  assert.equal(classify(null, {}), BRANCHES.EQUIVOCATION);
  assert.equal(classify({ source: 'ufo' }, {}), BRANCHES.EQUIVOCATION);
});
