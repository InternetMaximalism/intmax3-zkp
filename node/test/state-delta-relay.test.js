'use strict';
// SLIM DOWNLINK, relay half: `buildStateDelta` in wallet-relay.js / wallet-relay-ec2.js, driven
// against the REAL ch7 channel snapshot when one is present in the working tree.
//
// WHAT THESE TESTS ARE MEANT TO PROVE
//
//   * the two relays cannot drift — the delta block is byte-identical in both files. The dev relay
//     is what a change gets tested against; the EC2 relay is what the live site runs. A delta
//     format that differed between them would be a live-only failure mode.
//
//   * round-trip fidelity on REAL data — the relay's delta, applied by the page's own
//     reconstruction code, must reproduce the head state EXACTLY. Both halves are loaded from the
//     shipped files, so this is the real wire format, not a restatement of it.
//
//   * fallback is total — an unknown base, a membership change or a changed carry field must
//     produce the FULL snapshot, never a partial answer. Correctness first, bandwidth second.
//
// The size assertions are deliberately loose (a ratio, not a byte count): they exist to catch the
// optimization silently regressing to "sends everything", not to pin a number that legitimately
// moves with channel shape.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const REPO = path.join(__dirname, '..', '..');
const DEV_RELAY = path.join(REPO, 'hosting', 'wallet', 'wallet-relay.js');
const EC2_RELAY = path.join(REPO, 'hosting', 'wallet', 'wallet-relay-ec2.js');
const HTML = path.join(REPO, 'hosting', 'wallet', 'wallet-live.html');
const SNAP = path.join(REPO, 'wallet-live-work', 'ch7', 'channel_snapshot.json');

const BLOCK_BEGIN = '// ---- SLIM DOWNLINK: state deltas for /api/snapshot';
const BLOCK_END = "app.get('/api/snapshot'";

function relayBlock(file) {
  const s = fs.readFileSync(file, 'utf8');
  const i = s.indexOf(BLOCK_BEGIN);
  const j = s.indexOf(BLOCK_END, i);
  assert.ok(i >= 0 && j > i, 'no SLIM DOWNLINK block in ' + path.basename(file));
  return s.slice(i, j);
}

// The relay half, evaluated straight out of the shipped file.
function loadRelay() {
  const src = relayBlock(DEV_RELAY);
  return vm.runInThisContext(
    '(function (crypto) {' + src +
    '\n;return {buildStateDelta, fingerprintState, recordFingerprint, findFingerprint, deltaCarryMaterial, DELTA_CARRY_FIELDS};})',
    { filename: 'wallet-relay.js#slim-downlink' })(crypto);
}

// The page half (same extraction the other *-ui tests use).
function loadPage() {
  const html = fs.readFileSync(HTML, 'utf8');
  const i = html.indexOf('// TESTABLE-BEGIN: deposit-ui');
  const j = html.indexOf('// TESTABLE-END: deposit-ui');
  const src = html.slice(i, j);
  return vm.runInThisContext(
    '(function () {' + src +
    '\n;return {reconcileStateDelta, applyStateDelta, deltaBaseOf, deltaCarryMaterial, reconstructedMatchesAck, DELTA_CARRY_FIELDS};})()',
    { filename: 'wallet-live.html#slim-downlink' });
}

const R = loadRelay();
const P = loadPage();
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

test('the delta block is byte-identical in the dev and EC2 relays (they must not drift)', () => {
  assert.strictEqual(relayBlock(DEV_RELAY), relayBlock(EC2_RELAY),
    'wallet-relay.js and wallet-relay-ec2.js SLIM DOWNLINK blocks differ');
});

// ---- Real-snapshot round trip -----------------------------------------------------------------

const haveSnap = fs.existsSync(SNAP);
const withSnap = { skip: haveSnap ? false : 'no wallet-live-work/ch7/channel_snapshot.json in this tree' };

// Derive a plausible NEXT snapshot: a send between two slots changes exactly their balance rows.
function nextSnapshot(base, senderSlot, recipientSlot) {
  const snap = JSON.parse(JSON.stringify(base));
  const bs = snap.state.balanceState;
  for (const slot of [senderSlot, recipientSlot]) {
    const rowKeys = Object.keys(bs.encBalances[slot]);
    for (const k of rowKeys) {
      bs.encBalances[slot][k].c1 = bs.encBalances[slot][k].c1.map((v) => (v ^ 0x5a5a5a) >>> 0);
      bs.encBalances[slot][k].c2 = bs.encBalances[slot][k].c2.map((v) => (v ^ 0x3c3c3c) >>> 0);
    }
  }
  bs.stateVersion = base.state.balanceState.stateVersion + 1;
  snap.state.prevDigest = base.state.digest;
  snap.state.digest = '0x' + crypto.createHash('sha256')
    .update(JSON.stringify(bs.encBalances)).digest('hex');
  return snap;
}

test('REAL ch7 snapshot: a delta round-trips to the exact head state', withSnap, () => {
  const baseSnap = JSON.parse(fs.readFileSync(SNAP, 'utf8'));
  const headSnap = nextSnapshot(baseSnap, 1, 2);
  const baseSv = baseSnap.state.balanceState.stateVersion;

  // The relay learns the base by serving it once (exactly what the real route does).
  R.recordFingerprint(7, R.fingerprintState(baseSnap.state));
  const out = R.buildStateDelta(7, headSnap, baseSv, baseSnap.state.digest);
  assert.ok(out.body, 'expected a delta, got fallback: ' + out.fallback);
  const delta = out.body;

  assert.deepStrictEqual(Object.keys(delta.changedRows).sort(), ['1', '2']);
  assert.deepStrictEqual(delta.unchangedRows, [0, 3, 4]);
  assert.strictEqual(delta.rowCount, headSnap.state.balanceState.encBalances.length);

  // The page half rebuilds it.
  const clientBase = P.deltaBaseOf(baseSnap.state);
  const ack = { stateVersion: headSnap.state.balanceState.stateVersion, digest: headSnap.state.digest };
  const rec = P.reconcileStateDelta(delta, clientBase, ack);
  assert.strictEqual(rec.ok, true, 'reason: ' + rec.reason);
  assert.strictEqual(sha256hex(P.deltaCarryMaterial(clientBase, delta.carry, delta.unchangedRows)),
    delta.carryHash, 'the carry commitment must verify against the real base');
  const rebuilt = P.applyStateDelta(delta, clientBase, rec.plan);
  assert.strictEqual(P.reconstructedMatchesAck(rebuilt, ack), true);

  // THE point: what the wallet hands to `wallet_finalize` is VALUE-identical to the state the
  // members signed. Anything less and the digest recomputation in verify_all_signatures rejects it.
  //
  // Value-identical, not byte-identical: reconstruction re-adds `encBalances` and the carry fields
  // at the END of `balanceState`, so the JSON key ORDER differs from the original. That is
  // immaterial — `ChannelState` deserializes by field NAME (plain serde camelCase derive, no
  // order dependency) and `signing_digest()` hashes the deserialized STRUCT fields in a fixed
  // order, never the JSON bytes. So key order cannot move the digest.
  assert.deepStrictEqual(rebuilt, headSnap.state);
  // Belt and braces: the two really do differ only in key order, nothing else.
  assert.strictEqual(
    JSON.stringify(rebuilt, Object.keys(rebuilt).concat(Object.keys(rebuilt.balanceState)).sort()),
    JSON.stringify(headSnap.state, Object.keys(headSnap.state).concat(Object.keys(headSnap.state.balanceState)).sort()));
});

test('REAL ch7 snapshot: the delta is materially smaller than the full snapshot', withSnap, () => {
  const baseSnap = JSON.parse(fs.readFileSync(SNAP, 'utf8'));
  const headSnap = nextSnapshot(baseSnap, 1, 2);
  R.recordFingerprint(7, R.fingerprintState(baseSnap.state));
  const delta = R.buildStateDelta(7, headSnap, baseSnap.state.balanceState.stateVersion, baseSnap.state.digest).body;

  const fullBytes = JSON.stringify(headSnap).length;
  const deltaBytes = JSON.stringify(delta).length;
  const sigBytes = JSON.stringify(headSnap.state.memberSignatures).length;
  const kb = (n) => (n / 1024).toFixed(0) + ' KB';
  console.log('    full snapshot        ' + kb(fullBytes));
  console.log('    delta                ' + kb(deltaBytes) +
    '  (' + (100 * (1 - deltaBytes / fullBytes)).toFixed(1) + '% smaller)');
  console.log('    of which signatures  ' + kb(sigBytes) +
    '  (' + (100 * sigBytes / deltaBytes).toFixed(1) + '% of the delta — irreducible)');

  assert.ok(deltaBytes < fullBytes * 0.75,
    'the delta should be well under the full snapshot (got ' + kb(deltaBytes) + ' vs ' + kb(fullBytes) + ')');
  // The floor: member signatures are fresh every transition and cannot be elided. Anything
  // meaningfully below that would mean we dropped something we must send.
  assert.ok(deltaBytes > sigBytes, 'the delta must still carry the full signature set');
});

// ---- Fallback is total ------------------------------------------------------------------------

test('an unknown base falls back to the FULL snapshot, never a partial answer', withSnap, () => {
  const snap = JSON.parse(fs.readFileSync(SNAP, 'utf8'));
  assert.strictEqual(R.buildStateDelta(7, snap, 999, '0x' + 'ab'.repeat(32)).fallback, 'unknown-base');
  assert.strictEqual(R.buildStateDelta(7, snap, NaN, 'x').fallback, 'bad-since');
  assert.strictEqual(R.buildStateDelta(7, snap, 5, '').fallback, 'bad-since');
  assert.strictEqual(R.buildStateDelta(7, snap, 5, null).fallback, 'bad-since');
  assert.strictEqual(R.buildStateDelta(9, {}, 5, '0xab').fallback, 'no-state');
});

test('a membership change falls back to the full snapshot (carried slots would re-point)', withSnap, () => {
  const baseSnap = JSON.parse(fs.readFileSync(SNAP, 'utf8'));
  const headSnap = nextSnapshot(baseSnap, 1, 2);
  headSnap.state.balanceState.delegateCount = baseSnap.state.balanceState.delegateCount + 1;
  R.recordFingerprint(7, R.fingerprintState(baseSnap.state));
  assert.strictEqual(R.buildStateDelta(7, headSnap, baseSnap.state.balanceState.stateVersion,
    baseSnap.state.digest).fallback, 'membership-changed');
});

test('a changed carry field falls back to the full snapshot', withSnap, () => {
  const baseSnap = JSON.parse(fs.readFileSync(SNAP, 'utf8'));
  const headSnap = nextSnapshot(baseSnap, 1, 2);
  headSnap.state.balanceState.regevPkDigests[7] = '0x' + 'de'.repeat(32);
  R.recordFingerprint(7, R.fingerprintState(baseSnap.state));
  assert.strictEqual(R.buildStateDelta(7, headSnap, baseSnap.state.balanceState.stateVersion,
    baseSnap.state.digest).fallback, 'carry-changed');
});

test('a client already holding the head gets a tiny "unchanged" reply, not 1.6MB again', withSnap, () => {
  const snap = JSON.parse(fs.readFileSync(SNAP, 'utf8'));
  R.recordFingerprint(7, R.fingerprintState(snap.state));
  const out = R.buildStateDelta(7, snap, snap.state.balanceState.stateVersion, snap.state.digest);
  assert.ok(out.body && out.body.unchanged === true);
  assert.ok(JSON.stringify(out.body).length < 300);
  // ...and the page refuses to treat it as an applicable delta.
  const rec = P.reconcileStateDelta(out.body, P.deltaBaseOf(snap.state), null);
  assert.strictEqual(rec.ok, false);
  assert.strictEqual(rec.reason, 'head-not-advanced');
});

test('every row changing falls back rather than shipping a delta with no savings', withSnap, () => {
  const baseSnap = JSON.parse(fs.readFileSync(SNAP, 'utf8'));
  const n = baseSnap.state.balanceState.encBalances.length;
  const headSnap = nextSnapshot(baseSnap, 0, 1);
  for (let i = 0; i < n; i++) {
    for (const k of Object.keys(headSnap.state.balanceState.encBalances[i])) {
      headSnap.state.balanceState.encBalances[i][k].c1[0] = (i + 1) * 7919;
    }
  }
  R.recordFingerprint(7, R.fingerprintState(baseSnap.state));
  assert.strictEqual(R.buildStateDelta(7, headSnap, baseSnap.state.balanceState.stateVersion,
    baseSnap.state.digest).fallback, 'all-rows-changed');
});

test('the base index is bounded, so an old base eventually falls back instead of growing forever', withSnap, () => {
  const snap = JSON.parse(fs.readFileSync(SNAP, 'utf8'));
  const first = R.fingerprintState(snap.state);
  R.recordFingerprint(4242, first);
  assert.ok(R.findFingerprint(4242, first.digest, first.stateVersion));
  for (let i = 0; i < 12; i++) {
    R.recordFingerprint(4242, { digest: '0x' + String(i).padStart(4, '0'), stateVersion: 1000 + i, rowHashes: [], rowCount: 0 });
  }
  assert.strictEqual(R.findFingerprint(4242, first.digest, first.stateVersion), null,
    'the oldest base must be evicted, not retained without bound');
});
