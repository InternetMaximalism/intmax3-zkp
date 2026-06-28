'use strict';
const test = require('node:test');
const assert = require('node:assert');
const cosm = require('../cosigner/state-machine');
const desm = require('../delegate/state-machine');

test('cosigner SM: cooperative close path', () => {
  let n = cosm.NODES.ACTIVE;
  n = cosm.next(n, cosm.SIGNALS.CLOSE_REQUESTED); assert.equal(n, cosm.NODES.CLOSE_PENDING);
  n = cosm.next(n, cosm.SIGNALS.CLOSE_SUBMITTED); assert.equal(n, cosm.NODES.CLOSE_SUBMITTED);
  n = cosm.next(n, cosm.SIGNALS.CHALLENGE_OPEN); assert.equal(n, cosm.NODES.CHALLENGE_WINDOW);
  n = cosm.next(n, cosm.SIGNALS.FINALIZED); assert.equal(n, cosm.NODES.CLOSED);
  n = cosm.next(n, cosm.SIGNALS.CLAIMED_ALL); assert.equal(n, cosm.NODES.SETTLED);
});

test('cosigner SM: cancel returns to ACTIVE from any close node', () => {
  assert.equal(cosm.next(cosm.NODES.CLOSE_PENDING, cosm.SIGNALS.CANCELLED), cosm.NODES.ACTIVE);
  assert.equal(cosm.next(cosm.NODES.CLOSE_SUBMITTED, cosm.SIGNALS.CANCELLED), cosm.NODES.ACTIVE);
  assert.equal(cosm.next(cosm.NODES.CHALLENGE_WINDOW, cosm.SIGNALS.CANCELLED), cosm.NODES.ACTIVE);
});

test('cosigner SM: ATTACK reaches DEFENSIVE from every node; only ALL_CLEAR exits', () => {
  for (const n of Object.values(cosm.NODES)) {
    if (n === cosm.NODES.DEFENSIVE) continue;
    assert.equal(cosm.next(n, cosm.SIGNALS.ATTACK), cosm.NODES.DEFENSIVE, n);
  }
  assert.equal(cosm.next(cosm.NODES.DEFENSIVE, cosm.SIGNALS.ALL_CLEAR), cosm.NODES.ACTIVE);
  // unknown signal in defensive = stays defensive (sticky)
  assert.equal(cosm.next(cosm.NODES.DEFENSIVE, cosm.SIGNALS.CLOSE_REQUESTED), cosm.NODES.DEFENSIVE);
});

test('cosigner SM: unknown signal is a no-op', () => {
  assert.equal(cosm.next(cosm.NODES.ACTIVE, 'nonsense'), cosm.NODES.ACTIVE);
});

test('delegate SM: happy send cycle', () => {
  let n = desm.NODES.SYNCED;
  n = desm.next(n, desm.SIGNALS.START_PROVE); assert.equal(n, desm.NODES.PROVING);
  n = desm.next(n, desm.SIGNALS.SENT); assert.equal(n, desm.NODES.AWAIT_COSIGN);
  n = desm.next(n, desm.SIGNALS.COSIGN_OK); assert.equal(n, desm.NODES.FINALIZED);
  n = desm.next(n, desm.SIGNALS.SYNCED); assert.equal(n, desm.NODES.SYNCED);
});

test('delegate SM: EXIT is sticky — no path back to SYNCED', () => {
  for (const n of [desm.NODES.SYNCED, desm.NODES.PROVING, desm.NODES.AWAIT_COSIGN, desm.NODES.FINALIZED, desm.NODES.NEEDS_REFRESH]) {
    assert.equal(desm.next(n, desm.SIGNALS.EXIT), desm.NODES.EXITING, n);
  }
  // From EXITING, only EXIT_DONE moves (to EXITED); SYNCED signal is ignored.
  assert.equal(desm.next(desm.NODES.EXITING, desm.SIGNALS.SYNCED), desm.NODES.EXITING);
  assert.equal(desm.next(desm.NODES.EXITING, desm.SIGNALS.EXIT_DONE), desm.NODES.EXITED);
});
