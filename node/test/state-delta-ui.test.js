'use strict';
// Browser SLIM DOWNLINK: rebuilding the channel head state from a relay-served DELTA.
//
// WHAT THESE TESTS ARE MEANT TO PROVE ABOUT SECURITY
//
//   The delta is a TRANSPORT optimization with no trust component. The rebuilt state is handed to
//   `wallet_finalize` unchanged, and `verify_all_signatures` (src/wallet_core.rs:856) RECOMPUTES
//   `ChannelState::signing_digest()` over it, rejects unless it equals the `digest` field, and
//   verifies every cosigner signature against the RECOMPUTED digest. `encBalances`,
//   `regevPkDigests`, `recipients` and `pendingAdds` all enter that digest through
//   `balanceState.h1()`'s slot-tree root. So a misdescribed delta yields a state the members did
//   not sign, and finalize FAILS — it can never silently pass.
//
//   What the logic under test must therefore guarantee is FAIL-CLOSED REJECTION, so that anything
//   the relay could not have meant becomes a clean full re-fetch instead of a confusing signature
//   failure downstream. Specifically:
//
//   * base identity — a delta may only be applied on top of the EXACT state this wallet already
//     verified. A different digest or stateVersion in `delta.base` must be refused, because
//     carrying rows from a different state would mean rebuilding a state nobody signed.
//
//   * head identity — the head the delta claims must be the head the co-sign ACK named. Without
//     this a relay could answer a post-send fetch with some OTHER (validly signed) state and the
//     wallet would adopt a head it never asked for.
//
//   * no ambiguity — a delta that both omits AND inlines a carried field, or whose changed/
//     unchanged index sets overlap or leave a gap, has two readings. Refusing beats picking.
//
//   * a CHANGED row is never carried — if the relay says row i changed, a null/absent/malformed
//     row i must be REJECTED, never quietly replaced by the base's copy. The base's copy is
//     precisely the stale value the relay just said is wrong; silently substituting it would
//     rebuild a wrong state on a path the user believes succeeded.
//
//   * membership pinning — carried rows and carried per-slot arrays are POSITIONAL. A join
//     changes what slot i means, so any memberCount/delegateCount change must force a full fetch.
//
// HOW IT LOADS THE CODE UNDER TEST
//   Same extraction trick as deposit-ui.test.js / send-ui.test.js: `wallet-live.html` ships as ONE
//   file, so the pure logic lives in a marked region of its inline module and is evaluated here in
//   a `node:vm` sandbox. The assertions run against the bytes that ship.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const HTML = path.join(__dirname, '..', '..', 'hosting', 'wallet', 'wallet-live.html');
const BEGIN = '// TESTABLE-BEGIN: deposit-ui';
const END = '// TESTABLE-END: deposit-ui';

const EXPORTS = [
  'DELTA_FORMAT', 'DELTA_CARRY_FIELDS',
  'isPlainObject', 'parseIndexKey', 'isCiphertextRow',
  'deltaCarryMaterial', 'deltaBaseOf',
  'reconcileStateDelta', 'applyStateDelta', 'reconstructedMatchesAck',
];

function loadRegion() {
  const html = fs.readFileSync(HTML, 'utf8');
  const i = html.indexOf(BEGIN);
  const j = html.indexOf(END);
  assert.ok(i >= 0, 'wallet-live.html has no ' + BEGIN + ' marker');
  assert.ok(j > i, 'wallet-live.html has no ' + END + ' marker after the begin marker');
  const src = html.slice(i + BEGIN.length, j);
  for (const forbidden of ['document.', 'window.', 'fetch(', 'localStorage', 'walletProvider']) {
    assert.ok(!src.includes(forbidden),
      'the TESTABLE region must stay pure, but it references ' + forbidden);
  }
  return vm.runInThisContext(
    '(function () {' + src + '\n;return {' + EXPORTS.join(',') + '};})()',
    { filename: 'wallet-live.html#state-delta' });
}

const M = loadRegion();
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---- Fixtures --------------------------------------------------------------------------------
// Shapes mirror the real ch7 snapshot (5 active slots = 3 cosigners + 2 delegates, 2 tokens);
// the Regev vectors are shortened, since nothing under test reads their contents.
const ct = (tag) => ({ c1: [tag, tag + 1], c2: [tag + 2, tag + 3] });
const row = (tag, tokens) => {
  const r = {};
  for (const t of tokens) r[String(t)] = ct(tag * 100 + t);
  return r;
};

function makeState(version, digest, rows, opts) {
  const o = opts || {};
  return {
    channelId: 7,
    epoch: 0,
    smallBlockNumber: 3,
    closeFreezeNonce: 0,
    channelFund: { channelId: 7, amounts: ['1', '2', '0', '0', '0', '0', '0', '0', '0', '0'], intmaxStateRoot: '0x' + 'aa'.repeat(32) },
    balanceState: {
      channelId: 7,
      memberCount: o.memberCount === undefined ? 3 : o.memberCount,
      delegateCount: o.delegateCount === undefined ? 2 : o.delegateCount,
      encBalances: rows,
      regevPkDigests: ['0x' + '11'.repeat(32), '0x' + '22'.repeat(32)],
      recipients: ['0x' + '33'.repeat(20), '0x' + '44'.repeat(20)],
      settledTxChain: '0x' + '55'.repeat(32),
      settledTxAccumulatorRoot: '0x' + '66'.repeat(32),
      stateVersion: version,
      pendingAdds: [{}, { 1: 2 }, {}, {}, {}],
      tokenRegistry: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
      tokenCount: 2,
    },
    h2Tag: '0x' + '77'.repeat(32),
    sharedNativeNullifierRoot: '0x' + '88'.repeat(32),
    unallocatedConfirmedIncoming: '0',
    prevDigest: '0x' + '99'.repeat(32),
    digest: digest,
    memberSignatures: [{ memberSlot: 0, pkG: '0x' + 'ab'.repeat(32), signature: [1, 2, 3] }],
  };
}

const BASE_DIGEST = '0x' + 'b1'.repeat(32);
const HEAD_DIGEST = '0x' + 'h1'.replace('h', 'c').repeat(32);

const BASE_ROWS = [row(1, [0]), row(2, [0, 1]), row(3, [0, 1]), row(4, [0]), row(5, [0, 1])];
// A send from slot 1 to slot 2: exactly those two rows change.
const HEAD_ROWS = BASE_ROWS.slice();
HEAD_ROWS[1] = row(20, [0, 1]);
HEAD_ROWS[2] = row(30, [0, 1]);

const baseState = makeState(18, BASE_DIGEST, BASE_ROWS);
const headState = makeState(19, HEAD_DIGEST, HEAD_ROWS);
const BASE = M.deltaBaseOf(baseState);
const ACK = { ok: true, applied: 1, stateVersion: 19, digest: HEAD_DIGEST };

// The relay's response for the transition above.
function makeDelta(over) {
  const bs = Object.assign({}, headState.balanceState);
  delete bs.encBalances;
  for (const f of M.DELTA_CARRY_FIELDS) delete bs[f];
  const d = {
    deltaFormat: 1,
    channel: 7,
    base: { stateVersion: 18, digest: BASE_DIGEST },
    head: { stateVersion: 19, digest: HEAD_DIGEST },
    rowCount: 5,
    changedRows: { 1: HEAD_ROWS[1], 2: HEAD_ROWS[2] },
    unchangedRows: [0, 3, 4],
    carry: M.DELTA_CARRY_FIELDS.slice(),
    carryHash: sha256hex(M.deltaCarryMaterial(headState, M.DELTA_CARRY_FIELDS, [0, 3, 4])),
    state: Object.assign({}, headState, { balanceState: bs }),
  };
  return Object.assign(d, over || {});
}

const rejects = (delta, base, ack) => {
  const r = M.reconcileStateDelta(delta, base === undefined ? BASE : base, ack === undefined ? ACK : ack);
  assert.strictEqual(r.ok, false, 'expected rejection, got ok with plan ' + JSON.stringify(r.plan && r.plan.rowCount));
  return r.reason;
};

// ---- 1. The happy path: a delta applies cleanly and rebuilds the head EXACTLY -----------------

test('a well-formed delta applies and rebuilds the head state byte-for-byte', () => {
  const d = makeDelta();
  const r = M.reconcileStateDelta(d, BASE, ACK);
  assert.strictEqual(r.ok, true, 'reason: ' + r.reason);
  const rebuilt = M.applyStateDelta(d, BASE, r.plan);
  // The whole point: the rebuilt object must equal the state the members actually signed. If this
  // ever drifts, `signing_digest()` recomputes differently and finalize rejects the state.
  assert.deepStrictEqual(rebuilt, headState);
  assert.strictEqual(M.reconstructedMatchesAck(rebuilt, ACK), true);
});

test('the rebuilt state carries the UNTOUCHED rows through unchanged, and the changed ones from the delta', () => {
  const d = makeDelta();
  const r = M.reconcileStateDelta(d, BASE, ACK);
  const rebuilt = M.applyStateDelta(d, BASE, r.plan);
  for (const i of [0, 3, 4]) assert.deepStrictEqual(rebuilt.balanceState.encBalances[i], BASE_ROWS[i]);
  for (const i of [1, 2]) assert.deepStrictEqual(rebuilt.balanceState.encBalances[i], HEAD_ROWS[i]);
  for (const f of M.DELTA_CARRY_FIELDS) {
    assert.deepStrictEqual(rebuilt.balanceState[f], baseState.balanceState[f]);
  }
});

test('the carry commitment matches only when the base holds the SAME carried material', () => {
  const d = makeDelta();
  assert.strictEqual(sha256hex(M.deltaCarryMaterial(BASE, d.carry, d.unchangedRows)), d.carryHash);
  // A base whose carried material differs (a join the client has not seen) must not match.
  const other = M.deltaBaseOf(makeState(18, BASE_DIGEST, BASE_ROWS));
  other.balanceState.recipients = other.balanceState.recipients.concat(['0x' + 'ee'.repeat(20)]);
  assert.notStrictEqual(sha256hex(M.deltaCarryMaterial(other, d.carry, d.unchangedRows)), d.carryHash);
});

test('deltaBaseOf keeps exactly the reconstruction inputs and drops the signature blob', () => {
  assert.strictEqual(BASE.digest, BASE_DIGEST);
  assert.strictEqual(BASE.memberSignatures, undefined, 'the 833KB signature blob must not be retained');
  assert.deepStrictEqual(Object.keys(BASE).sort(), ['balanceState', 'digest']);
  assert.deepStrictEqual(Object.keys(BASE.balanceState).sort(),
    ['delegateCount', 'encBalances', 'memberCount', 'recipients', 'regevPkDigests', 'stateVersion'].sort());
  assert.strictEqual(M.deltaBaseOf(null), null);
  assert.strictEqual(M.deltaBaseOf({}), null);
  assert.strictEqual(M.deltaBaseOf({ balanceState: 5 }), null);
});

// ---- 2. Unknown / stale base falls back to full ----------------------------------------------

test('a delta anchored to a DIFFERENT base digest is refused (never rebuild on a state we did not verify)', () => {
  assert.strictEqual(rejects(makeDelta({ base: { stateVersion: 18, digest: '0x' + 'ff'.repeat(32) } })),
    'base-digest-mismatch');
});

test('a delta anchored to a different base VERSION is refused', () => {
  assert.strictEqual(rejects(makeDelta({ base: { stateVersion: 17, digest: BASE_DIGEST } })),
    'base-version-mismatch');
});

test('a stale client base (right digest field, older rows) is caught by the carry commitment, not by shape', () => {
  // Shape-wise this reconciles — which is exactly why the carryHash gate exists. The client hashes
  // ITS carried material; a base that is not what the relay committed to fails that comparison and
  // the caller re-fetches in full.
  const d = makeDelta();
  const stale = M.deltaBaseOf(makeState(18, BASE_DIGEST, BASE_ROWS));
  stale.balanceState.regevPkDigests = ['0x' + 'de'.repeat(32)];
  assert.strictEqual(M.reconcileStateDelta(d, stale, ACK).ok, true);
  assert.notStrictEqual(sha256hex(M.deltaCarryMaterial(stale, d.carry, d.unchangedRows)), d.carryHash);
});

test('a relay reply that is not a delta at all is refused (old relay, or a full snapshot)', () => {
  assert.strictEqual(rejects({}), 'delta-format');
  assert.strictEqual(rejects({ deltaFormat: 2 }), 'delta-format');
  assert.strictEqual(rejects(null), 'delta-not-object');
  assert.strictEqual(rejects([makeDelta()]), 'delta-not-object');
  assert.strictEqual(rejects('nope'), 'delta-not-object');
  // The "head has not advanced yet" reply is a delta, but carries no state to apply.
  assert.strictEqual(rejects({ deltaFormat: 1, unchanged: true, head: { stateVersion: 18, digest: BASE_DIGEST } }),
    'head-not-advanced');
});

test('a missing or malformed base makes reconciliation fail closed', () => {
  assert.strictEqual(rejects(makeDelta(), null), 'base-malformed');
  assert.strictEqual(rejects(makeDelta(), {}), 'base-malformed');
  assert.strictEqual(rejects(makeDelta(), { digest: BASE_DIGEST }), 'base-malformed');
});

// ---- 3. Membership change falls back to full --------------------------------------------------

test('a memberCount change forces a full fetch (carried rows are POSITIONAL)', () => {
  const d = makeDelta();
  d.state.balanceState.memberCount = 4;
  assert.strictEqual(rejects(d), 'memberCount-changed');
});

test('a delegateCount change forces a full fetch (a join re-points every carried slot)', () => {
  const d = makeDelta();
  d.state.balanceState.delegateCount = 3;
  assert.strictEqual(rejects(d), 'delegateCount-changed');
});

// ---- 4. Digest mismatch falls back to full and does NOT finalize -------------------------------

test('a head that is not the one the co-sign ACK named is refused', () => {
  assert.strictEqual(rejects(makeDelta({ head: { stateVersion: 19, digest: '0x' + 'ee'.repeat(32) } })),
    'head-digest-not-ack');
  assert.strictEqual(rejects(makeDelta({ head: { stateVersion: 21, digest: HEAD_DIGEST } })),
    'head-version-not-ack');
});

test('a state whose own digest/version disagrees with the claimed head is refused', () => {
  const d = makeDelta();
  d.state.digest = '0x' + 'cd'.repeat(32);
  assert.strictEqual(rejects(d), 'state-digest-not-head');
  const d2 = makeDelta();
  d2.state.balanceState.stateVersion = 25;
  assert.strictEqual(rejects(d2), 'state-version-not-head');
});

test('reconstructedMatchesAck refuses to finalize anything but the ACKed head', () => {
  const d = makeDelta();
  const rebuilt = M.applyStateDelta(d, BASE, M.reconcileStateDelta(d, BASE, ACK).plan);
  assert.strictEqual(M.reconstructedMatchesAck(rebuilt, ACK), true);
  assert.strictEqual(M.reconstructedMatchesAck(rebuilt, { stateVersion: 19, digest: '0x' + '00'.repeat(32) }), false);
  assert.strictEqual(M.reconstructedMatchesAck(rebuilt, { stateVersion: 20, digest: HEAD_DIGEST }), false);
  assert.strictEqual(M.reconstructedMatchesAck(null, ACK), false);
  assert.strictEqual(M.reconstructedMatchesAck({ digest: HEAD_DIGEST }, ACK), false);
});

test('a delta claiming our own base as the new head is refused (a send always advances the head)', () => {
  const selfAck = { stateVersion: 18, digest: BASE_DIGEST };
  assert.strictEqual(rejects(makeDelta({ head: { stateVersion: 18, digest: BASE_DIGEST } }), BASE, selfAck),
    'head-equals-base');
});

// ---- 5. A tampered / absent CHANGED row is rejected, never silently carried over ---------------

test('a changed row that is null/absent is REJECTED rather than carried from the base', () => {
  for (const bad of [null, undefined, 0, '', 'x', [], [ct(1)]]) {
    const d = makeDelta();
    d.changedRows[1] = bad;
    assert.strictEqual(rejects(d), 'changed-row-malformed', 'bad row: ' + JSON.stringify(bad));
  }
  // ...and specifically: the base's stale row must NOT end up in a rebuilt state.
  const d = makeDelta();
  d.changedRows[1] = null;
  const r = M.reconcileStateDelta(d, BASE, ACK);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.plan, undefined, 'a rejected delta must not hand back an applicable plan');
});

test('a changed row with a malformed ciphertext is rejected', () => {
  for (const bad of [{ 0: {} }, { 0: { c1: [1] } }, { 0: { c1: 'x', c2: [1] } }, { 0: null },
                     { '-1': ct(1) }, { '01': ct(1) }, { 10: ct(1) }, { x: ct(1) }]) {
    const d = makeDelta();
    d.changedRows[2] = bad;
    assert.strictEqual(rejects(d), 'changed-row-malformed', 'bad row: ' + JSON.stringify(bad));
  }
});

test('an empty row IS legal — it is how the Rust serde encodes an all-canonical-zero slot', () => {
  assert.strictEqual(M.isCiphertextRow({}), true);
  const d = makeDelta();
  d.changedRows[1] = {};
  const r = M.reconcileStateDelta(d, BASE, ACK);
  assert.strictEqual(r.ok, true, 'reason: ' + r.reason);
  assert.deepStrictEqual(M.applyStateDelta(d, BASE, r.plan).balanceState.encBalances[1], {});
});

test('a row MISLABELLED as unchanged is caught by the carry commitment (it hashes the carried rows)', () => {
  // The relay claims row 1 did not change, when it did. Structurally this is a perfectly legal
  // delta — the client cannot tell from shape alone — so the commitment is what catches it: the
  // relay hashed the HEAD's row 1, we hash our BASE's row 1, and they differ.
  //
  // Soundness never depended on catching it here: applying it would rebuild a state whose
  // recomputed signing_digest() is not the one the members signed, so `wallet_finalize` would
  // reject it. This check makes it a clean full re-fetch instead of a late signature failure.
  const d = makeDelta();
  d.unchangedRows = [0, 1, 3, 4];
  delete d.changedRows[1];
  const r = M.reconcileStateDelta(d, BASE, ACK);
  assert.strictEqual(r.ok, true, 'shape alone cannot catch this — that is the point of carryHash');
  const rebuilt = M.applyStateDelta(d, BASE, r.plan);
  assert.notDeepStrictEqual(rebuilt, headState, 'the rebuilt state is NOT the signed head');
  // ...and the commitment check rejects it before it can be finalized.
  assert.notStrictEqual(sha256hex(M.deltaCarryMaterial(BASE, d.carry, d.unchangedRows)), d.carryHash);
  // The relay cannot repair the lie by re-hashing over its own head rows either: that is exactly
  // the hash it would have to produce, and it still does not match what the client computes.
  assert.strictEqual(sha256hex(M.deltaCarryMaterial(headState, d.carry, d.unchangedRows)),
    sha256hex(M.deltaCarryMaterial(headState, d.carry, d.unchangedRows)));
  assert.notStrictEqual(sha256hex(M.deltaCarryMaterial(headState, d.carry, d.unchangedRows)),
    sha256hex(M.deltaCarryMaterial(BASE, d.carry, d.unchangedRows)));
});

test('the carry commitment covers EVERY carried row, not just the first', () => {
  const d = makeDelta();
  const good = sha256hex(M.deltaCarryMaterial(BASE, d.carry, d.unchangedRows));
  for (const i of d.unchangedRows) {
    const tweaked = M.deltaBaseOf(baseState);
    tweaked.balanceState.encBalances = BASE_ROWS.slice();
    tweaked.balanceState.encBalances[i] = row(77, [0, 1]);
    assert.notStrictEqual(sha256hex(M.deltaCarryMaterial(tweaked, d.carry, d.unchangedRows)), good,
      'a change to carried row ' + i + ' must move the commitment');
  }
});

// ---- 6. The index partition must be exact -----------------------------------------------------

test('an index left uncovered by both sets is refused (a dropped row is a different state)', () => {
  assert.strictEqual(rejects(makeDelta({ unchangedRows: [0, 3] })), 'index-uncovered');
  assert.strictEqual(rejects(makeDelta({ changedRows: { 1: HEAD_ROWS[1] } })), 'index-uncovered');
});

test('an index claimed by BOTH sets is refused (ambiguous source)', () => {
  assert.strictEqual(rejects(makeDelta({ unchangedRows: [0, 1, 3, 4] })), 'index-duplicate');
});

test('out-of-range indices are refused', () => {
  assert.strictEqual(rejects(makeDelta({ unchangedRows: [0, 3, 4, 5] })), 'unchanged-index-range');
  assert.strictEqual(rejects(makeDelta({ unchangedRows: [0, 3, -1] })), 'unchanged-index-range');
  assert.strictEqual(rejects(makeDelta({ unchangedRows: [0, 3, 1.5] })), 'unchanged-index-range');
  const d = makeDelta();
  d.changedRows[9] = HEAD_ROWS[1];
  assert.strictEqual(rejects(d), 'changed-index-range');
});

test('a non-canonical index key is refused (no "01", no "1.0", no negatives)', () => {
  assert.strictEqual(M.parseIndexKey('0'), 0);
  assert.strictEqual(M.parseIndexKey('12'), 12);
  for (const k of ['01', '1.0', '-1', '', ' 1', '1 ', '0x1', '1e3', 'a', null, 3]) {
    assert.strictEqual(M.parseIndexKey(k), null, 'key: ' + JSON.stringify(k));
  }
  const d = makeDelta();
  delete d.changedRows[1];
  d.changedRows['01'] = HEAD_ROWS[1];
  assert.strictEqual(rejects(d), 'changed-index-range');
});

test('an unchanged index the base cannot supply is refused (rowCount may exceed the base row count)', () => {
  const shortBase = M.deltaBaseOf(makeState(18, BASE_DIGEST, BASE_ROWS.slice(0, 3)));
  assert.strictEqual(rejects(makeDelta(), shortBase), 'unchanged-row-absent-in-base');
});

test('a bad rowCount is refused', () => {
  for (const rc of [undefined, null, -1, 1.5, 1025, '5']) {
    assert.strictEqual(rejects(makeDelta({ rowCount: rc })), 'rowCount', 'rowCount: ' + rc);
  }
});

// ---- 7. No ambiguity: the delta must not both omit and inline a field --------------------------

test('a delta that ALSO inlines an omitted field is refused rather than resolved', () => {
  const d = makeDelta();
  d.state.balanceState.encBalances = HEAD_ROWS;
  assert.strictEqual(rejects(d), 'state-inlines-encBalances');
  for (const f of M.DELTA_CARRY_FIELDS) {
    const d2 = makeDelta();
    d2.state.balanceState[f] = headState.balanceState[f];
    assert.strictEqual(rejects(d2), 'state-inlines-' + f);
  }
  // Even an explicit null counts as inlining — `in` is the test, not truthiness.
  const d3 = makeDelta();
  d3.state.balanceState.encBalances = null;
  assert.strictEqual(rejects(d3), 'state-inlines-encBalances');
});

test('the carry list must be exactly the fields we know how to carry', () => {
  assert.strictEqual(rejects(makeDelta({ carry: [] })), 'carry-shape');
  assert.strictEqual(rejects(makeDelta({ carry: ['regevPkDigests'] })), 'carry-shape');
  assert.strictEqual(rejects(makeDelta({ carry: ['recipients', 'regevPkDigests'] })), 'carry-shape');
  assert.strictEqual(rejects(makeDelta({ carry: ['regevPkDigests', 'memberSignatures'] })), 'carry-shape');
  assert.strictEqual(rejects(makeDelta({ carry: 'regevPkDigests' })), 'carry-shape');
});

test('a missing carry commitment is refused (we would have nothing to check the base against)', () => {
  assert.strictEqual(rejects(makeDelta({ carryHash: undefined })), 'carryHash-missing');
  assert.strictEqual(rejects(makeDelta({ carryHash: '' })), 'carryHash-missing');
  assert.strictEqual(rejects(makeDelta({ carryHash: 12345 })), 'carryHash-missing');
});

test('a base missing a field the delta wants carried is refused', () => {
  for (const f of M.DELTA_CARRY_FIELDS) {
    const b = M.deltaBaseOf(baseState);
    delete b.balanceState[f];
    assert.strictEqual(rejects(makeDelta(), b), 'carry-absent-in-base');
  }
});

test('structural pieces missing from the delta are refused', () => {
  assert.strictEqual(rejects(makeDelta({ base: undefined })), 'base-missing');
  assert.strictEqual(rejects(makeDelta({ head: undefined })), 'head-missing');
  assert.strictEqual(rejects(makeDelta({ state: undefined })), 'state-missing');
  assert.strictEqual(rejects(makeDelta({ state: { digest: HEAD_DIGEST } })), 'state-missing');
  assert.strictEqual(rejects(makeDelta({ changedRows: undefined })), 'changedRows-missing');
  assert.strictEqual(rejects(makeDelta({ changedRows: [] })), 'changedRows-missing');
  assert.strictEqual(rejects(makeDelta({ unchangedRows: undefined })), 'unchangedRows-missing');
  assert.strictEqual(rejects(makeDelta({ unchangedRows: {} })), 'unchangedRows-missing');
  const b = M.deltaBaseOf(baseState);
  b.balanceState.encBalances = 'nope';
  assert.strictEqual(rejects(makeDelta(), b), 'base-rows-missing');
});

// ---- 8. Property test: only the exact head survives --------------------------------------------

test('corruption sweep: the delta mechanism never contributes an error the client cannot see', () => {
  // THE PROPERTY THIS PINS, stated precisely.
  //
  // The delta splits the head state into two kinds of bytes:
  //   (T) TRANSMITTED — sent verbatim by the relay (scalars, memberSignatures, changed rows). The
  //       trust surface here is EXACTLY the pre-existing one: a full snapshot ships the same bytes
  //       from the same relay, and they are checked in exactly the same place — the
  //       `signing_digest()` recomputation in `verify_all_signatures`. The delta neither adds nor
  //       removes any check on them, so this test does NOT assert the client catches them locally.
  //       It cannot, and a full snapshot never did either.
  //   (C) CARRIED — reconstructed locally from our own base (unchanged rows + carry fields). This
  //       is the ONLY thing the delta mechanism introduces, so it is what must be verifiable.
  //
  // The claim: whenever every client-side gate passes, the CARRIED bytes equal the true head's.
  // In other words the reconstruction contributes no error of its own; any residual divergence
  // lies entirely in (T), where the Rust digest check has always been the enforcing gate.
  const mutators = [
    ['irrelevant field', (d) => { d.channel = 999; }],
    ['short rowCount', (d) => { d.rowCount = 4; }],
    ['unchangedRows reordered', (d) => { d.unchangedRows = [4, 3, 0]; }],
    ['changedRows reordered', (d) => { d.changedRows = { 2: HEAD_ROWS[2], 1: HEAD_ROWS[1] }; }],
    ['extra changed row', (d) => { d.changedRows[3] = row(9, [0]); }],
    ['row mislabelled unchanged', (d) => { d.unchangedRows = [0, 1, 3, 4]; delete d.changedRows[1]; }],
    ['bogus carryHash', (d) => { d.carryHash = sha256hex('nope'); }],
    ['tampered transmitted scalar', (d) => { d.state.balanceState.tokenCount = 9; }],
    ['tampered transmitted signature', (d) => { d.state.memberSignatures = [{ memberSlot: 0, pkG: '0x00', signature: [9] }]; }],
    ['tampered changed row', (d) => { d.changedRows[1] = row(66, [0, 1]); }],
    ['base version moved', (d) => { d.base.stateVersion = 19; }],
    ['head version moved', (d) => { d.head.stateVersion = 18; }],
  ];
  let finalizable = 0;
  for (const [name, mut] of mutators) {
    const d = makeDelta();
    mut(d);
    const r = M.reconcileStateDelta(d, BASE, ACK);
    if (!r.ok) continue;
    const rebuilt = M.applyStateDelta(d, BASE, r.plan);
    const carryOk = sha256hex(M.deltaCarryMaterial(BASE, d.carry, d.unchangedRows)) === d.carryHash;
    if (!carryOk || !M.reconstructedMatchesAck(rebuilt, ACK)) continue;
    // Every client-side gate passed → this state WILL be handed to wallet_finalize.
    finalizable++;
    for (const i of d.unchangedRows) {
      assert.deepStrictEqual(rebuilt.balanceState.encBalances[i], headState.balanceState.encBalances[i],
        name + ': a CARRIED row diverged from the signed head undetected');
    }
    for (const f of M.DELTA_CARRY_FIELDS) {
      assert.deepStrictEqual(rebuilt.balanceState[f], headState.balanceState[f],
        name + ': a CARRIED field diverged from the signed head undetected');
    }
  }
  assert.ok(finalizable >= 3, 'the sweep should exercise the accept path too (got ' + finalizable + ')');
});

test('a tampered TRANSMITTED field is the pre-existing trust surface, not a delta regression', () => {
  // Documents the boundary deliberately: the client does NOT locally re-derive relay-sent scalars,
  // signatures or changed rows — it never did, for a full snapshot either. `wallet_finalize`
  // recomputes `signing_digest()` over whatever it is handed and verifies the N-of-N signatures
  // against the RECOMPUTED value (src/wallet_core.rs:856), so a tampered field here yields a state
  // the members did not sign and finalize FAILS. Nothing about the delta changes that.
  const d = makeDelta();
  d.state.balanceState.tokenCount = 9;
  const r = M.reconcileStateDelta(d, BASE, ACK);
  assert.strictEqual(r.ok, true, 'transmitted fields are not shape-checked here (by design)');
  const rebuilt = M.applyStateDelta(d, BASE, r.plan);
  assert.strictEqual(rebuilt.balanceState.tokenCount, 9, 'the tampered value is passed through verbatim');
  // But the CARRIED parts are still exactly the head's — the delta added no error of its own.
  for (const i of d.unchangedRows) {
    assert.deepStrictEqual(rebuilt.balanceState.encBalances[i], headState.balanceState.encBalances[i]);
  }
});

test('isPlainObject / isCiphertextRow do not treat arrays or null as objects', () => {
  assert.strictEqual(M.isPlainObject({}), true);
  for (const v of [null, undefined, [], 'x', 1, true]) assert.strictEqual(M.isPlainObject(v), false, String(v));
  for (const v of [null, undefined, [], 'x', 1]) assert.strictEqual(M.isCiphertextRow(v), false, String(v));
  assert.strictEqual(M.isCiphertextRow({ 0: ct(1), 9: ct(2) }), true);
  assert.strictEqual(M.isCiphertextRow({ 0: ct(1), 10: ct(2) }), false);
});
