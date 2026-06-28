'use strict';
const test = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');
const policy = require('../common/policy');
const { Store } = require('../common/store');
const { verifyCosignedStructural, checkHeadMonotonic } = require('../delegate/verify');

// ---- policy ----
test('policy: amount cap rejects zero, negative, overflow; accepts in-range', () => {
  const p = { amountCapWei: '1000' };
  assert.equal(policy.amountWithinCap('0', p), false);
  assert.equal(policy.amountWithinCap('1001', p), false);
  assert.equal(policy.amountWithinCap('1000', p), true);
  assert.equal(policy.amountWithinCap('not-a-number', p), false);
});

test('policy: invalid scoring back-pressures after threshold, resets after window', () => {
  const p = { invalidScoreThreshold: 3, invalidScoreWindowMs: 1000 };
  let rec = null; let now = 0; let r;
  r = policy.scoreInvalid(rec, now, p); rec = r.rec; assert.equal(r.backPressured, false);
  r = policy.scoreInvalid(rec, now + 10, p); rec = r.rec; assert.equal(r.backPressured, false);
  r = policy.scoreInvalid(rec, now + 20, p); rec = r.rec; assert.equal(r.backPressured, true);
  // window expiry resets
  r = policy.scoreInvalid(rec, now + 5000, p); assert.equal(r.rec.count, 1); assert.equal(r.backPressured, false);
});

test('policy: compareVersion is lexicographic (epoch, stateVersion)', () => {
  assert.equal(policy.compareVersion({ epoch: 2, stateVersion: 0 }, { epoch: 1, stateVersion: 9 }), 1);
  assert.equal(policy.compareVersion({ epoch: 1, stateVersion: 5 }, { epoch: 1, stateVersion: 6 }), -1);
  assert.equal(policy.compareVersion({ epoch: 1, stateVersion: 5 }, { epoch: 1, stateVersion: 5 }), 0);
});

test('policy: staleCloseResponse honors config, defaults to cancel', () => {
  assert.equal(policy.staleCloseResponse({ staleCloseResponse: 'challenge' }), 'challenge');
  assert.equal(policy.staleCloseResponse({}), 'cancel');
  assert.equal(policy.staleCloseResponse({ staleCloseResponse: 'bogus' }), 'cancel');
});

// ---- store idempotency + crash-safety ----
test('store: claimAction is once-only; survives reload (idempotency across restart)', () => {
  const f = path.join(os.tmpdir(), `intmax-store-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  try {
    const s = new Store(f);
    assert.equal(s.claimAction('A1'), true);
    assert.equal(s.claimAction('A1'), false); // second time = no
    s.completeAction('A1', 'ok');
    // reload (simulated restart)
    const s2 = new Store(f);
    assert.equal(s2.hasAction('A1'), true);
    assert.equal(s2.claimAction('A1'), false); // still claimed after restart
    assert.equal(s2.state.actions.A1.result, 'ok');
  } finally { fs.rmSync(f, { force: true }); fs.rmSync(f + '.tmp', { force: true }); }
});

test('store: cursor advances monotonically', () => {
  const f = path.join(os.tmpdir(), `intmax-cursor-${Date.now()}.json`);
  try {
    const s = new Store(f);
    s.setCursor(10); assert.equal(s.get('cursor'), 10);
    s.setCursor(5); assert.equal(s.get('cursor'), 10); // no regression
    s.setCursor(11); assert.equal(s.get('cursor'), 11);
  } finally { fs.rmSync(f, { force: true }); }
});

// ---- delegate verifyCosigned gate ----
const PREV = { digest: '0xhead', epoch: 1, stateVersion: 4 };
function goodResp() {
  return { state: { member_signatures: ['s0', 's1', 's2'], prev_digest: '0xhead', balance_state: { state_version: 5 } } };
}

test('verify: accepts a well-formed, head-extending, +1 version response', () => {
  assert.equal(verifyCosignedStructural({}, goodResp(), PREV).ok, true);
});

test('verify: rejects missing signatures', () => {
  const r = goodResp(); r.state.member_signatures = [];
  assert.equal(verifyCosignedStructural({}, r, PREV).ok, false);
});

test('verify: rejects head that does not extend ours (prev_digest mismatch)', () => {
  const r = goodResp(); r.state.prev_digest = '0xWRONG';
  const v = verifyCosignedStructural({}, r, PREV);
  assert.equal(v.ok, false); assert.match(v.reason, /extend/);
});

test('verify: rejects version that does not advance by exactly 1', () => {
  const r = goodResp(); r.state.balance_state.state_version = 7;
  assert.equal(verifyCosignedStructural({}, r, PREV).ok, false);
});

test('verify: rejects empty/garbage response (fail-closed)', () => {
  assert.equal(verifyCosignedStructural({}, null, PREV).ok, false);
  assert.equal(verifyCosignedStructural({}, {}, PREV).ok, false);
});

test('verify: recipient mismatch is rejected when tx echoed', () => {
  const sent = { channel_tx: { recipient_pk_g: '0xRECIP' } };
  const r = goodResp(); r.channel_tx = { recipient_pk_g: '0xOTHER' };
  assert.equal(verifyCosignedStructural(sent, r, PREV).ok, false);
});

// ---- head monotonicity / equivocation ----
test('verify: head regression and same-version-different-digest are equivocation', () => {
  const prev = { epoch: 1, stateVersion: 5, digest: '0xA' };
  assert.equal(checkHeadMonotonic(prev, { epoch: 1, stateVersion: 4, digest: '0xB' }).ok, false); // regress
  assert.equal(checkHeadMonotonic(prev, { epoch: 1, stateVersion: 5, digest: '0xB' }).ok, false); // conflict
  assert.equal(checkHeadMonotonic(prev, { epoch: 1, stateVersion: 6, digest: '0xC' }).ok, true); // forward ok
  assert.equal(checkHeadMonotonic(null, { epoch: 0, stateVersion: 0, digest: '0xZ' }).ok, true); // first head ok
});
