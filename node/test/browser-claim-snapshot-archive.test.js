'use strict';

// The browser's claim snapshot archive (IndexedDB `intmax3-claim-snapshots-v1`) is what lets a
// wallet reconstruct the exact finalized head the Manager settled on, after a restart. Its entries
// are keyed `channelId:state.digest`, so the only integrity claim a key can make is "this digest
// holds this state".
//
// It used to compare the WHOLE snapshot and hard-fail on any difference. `record` moves during a
// channel's normal life while the head does not (`status`/`closeFreezeNonce` on requestClose,
// `setVersion`/member roots on a join), so an ordinary user could reach a state where every
// re-archive threw `refusing to replace a different verified snapshot under the same digest` with
// no in-app recovery — the only escape was clearing browser storage by hand. It also bought no
// protection: the store is trust-on-first-use, so a hostile first writer was never refused.
//
// These tests pin both halves of the corrected rule: a moved `record` under an unchanged head is
// absorbed (and the newest envelope is kept), while a genuinely different STATE under the same
// digest is still refused.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const DIGEST = '0x' + '11'.repeat(32);

function snapshot({ status = 'Open', closeFreezeNonce = 0, stateVersion = 5, sig = 'aa' } = {}) {
  return {
    record: { channelId: 7, status, closeFreezeNonce, memberCount: 3 },
    members: [{ slot: 0 }, { slot: 1 }, { slot: 2 }],
    state: {
      digest: DIGEST,
      channelId: 7,
      balanceState: { stateVersion },
      // Signatures OVER the digest, not inputs to it. Falcon is randomized, so a re-signed head
      // legitimately carries different bytes.
      memberSignatures: [{ slot: 0, signature: '0x' + sig.repeat(32) }],
    },
  };
}

// Minimal IndexedDB stand-in: callback-style requests, and writes that only land when the
// transaction completes (an aborted transaction must leave the store untouched).
function fakeIndexedDb(rows = new Map()) {
  const db = {
    close() {},
    transaction() {
      const staged = [];
      let aborted = false;
      let settled = false;
      const tx = {
        abort() { aborted = true; },
        objectStore() {
          return {
            get(key) {
              const request = {};
              queueMicrotask(() => {
                request.result = rows.get(key);
                if (request.onsuccess) request.onsuccess();
                if (settled) return;
                settled = true;
                if (aborted) {
                  if (tx.onabort) tx.onabort();
                  return;
                }
                for (const row of staged) rows.set(row.key, row);
                if (tx.oncomplete) tx.oncomplete();
              });
              return request;
            },
            add(row) { staged.push(row); },
            put(row) { staged.push(row); },
          };
        },
      };
      return tx;
    },
  };
  return { db, rows };
}

function loadArchiver(rows) {
  const html = fs.readFileSync(
    path.join(__dirname, '../../hosting/wallet/wallet-live.html'),
    'utf8',
  );
  // Start at the helper so the test runs the page's REAL notion of "what the digest commits to",
  // not a copy that could drift from it.
  const begin = html.indexOf('function digestCommittedStateJson');
  const end = html.indexOf('async function loadVerifiedClaimSnapshot', begin);
  assert.ok(begin >= 0 && end > begin, 'wallet-live.html must still define the archive function');
  assert.ok(
    html.indexOf('async function archiveVerifiedClaimSnapshot', begin) < end,
    'the archive function must follow its digest-scoping helper',
  );
  const source = html.slice(begin, end);

  const store = fakeIndexedDb(rows);
  const sandbox = {
    TextEncoder,
    queueMicrotask,
    JSON,
    HEX32_RE: /^0x[0-9a-fA-F]{64}$/,
    MAX_CLAIM_SNAPSHOT_BYTES: 32 * 1024 * 1024,
    CLAIM_SNAPSHOT_STORE: 'snapshots',
    openClaimSnapshotDb: async () => store.db,
    // The page's own canonicalizer, kept byte-identical in spirit: stable key order.
    claimCanonicalJson: function canonical(value) {
      if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
      if (value && typeof value === 'object') {
        return '{' + Object.keys(value).sort()
          .map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
      }
      return JSON.stringify(value);
    },
  };
  const archive = vm.runInNewContext(
    `${source}; archiveVerifiedClaimSnapshot`,
    sandbox,
    { filename: 'wallet-live.html#claim-snapshot-archive' },
  );
  return { archive, rows: store.rows };
}

test('a record that moved under an unchanged head is absorbed, and the newest envelope wins', async () => {
  const { archive, rows } = loadArchiver();

  // First archive: the channel is Open.
  await archive(JSON.stringify(snapshot()));
  assert.equal(rows.size, 1);

  // Same head, but the channel has since entered its close flow: `record.status` and
  // `closeFreezeNonce` moved while `state` (and therefore `state.digest`) did not. This is the
  // ordinary requestClose path, and it must not poison the archive.
  const closing = snapshot({ status: 'ClosePending', closeFreezeNonce: 1 });
  await assert.doesNotReject(() => archive(JSON.stringify(closing)));

  // The stored entry is the REFRESHED one, so restart recovery imports a snapshot that still
  // matches the live channel rather than a stale pre-close record.
  const stored = JSON.parse(rows.get('7:' + DIGEST).snapshotJson);
  assert.equal(stored.record.status, 'ClosePending');
  assert.equal(stored.record.closeFreezeNonce, 1);
});

test('a re-signed head (different Falcon signature bytes) is absorbed', async () => {
  const { archive, rows } = loadArchiver();
  await archive(JSON.stringify(snapshot({ sig: 'aa' })));

  // The same head co-signed again: `memberSignatures` differ byte-for-byte because Falcon is
  // randomized. This is what a channel re-creation (or any fresh co-signing session) produces,
  // and it is the case that actually bricked the wallet in practice.
  const resigned = snapshot({ sig: 'bb' });
  await assert.doesNotReject(() => archive(JSON.stringify(resigned)));

  const stored = JSON.parse(rows.get('7:' + DIGEST).snapshotJson);
  assert.equal(stored.state.memberSignatures[0].signature, '0x' + 'bb'.repeat(32));
});

test('a different state under the same digest is still refused', async () => {
  const { archive, rows } = loadArchiver();
  await archive(JSON.stringify(snapshot()));

  // Same key, genuinely different head: a digest collision or a tampered archive. This is the
  // case the guard exists for, and it must stay fail-closed.
  const forged = snapshot({ stateVersion: 99 });
  await assert.rejects(
    () => archive(JSON.stringify(forged)),
    /refusing to replace a different verified snapshot under the same digest/,
  );

  // The abort left the original entry untouched.
  const stored = JSON.parse(rows.get('7:' + DIGEST).snapshotJson);
  assert.equal(stored.state.balanceState.stateVersion, 5);
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Input-validation and corruption error cases for the archive. Every one of these must fail
// closed with a specific message rather than write a malformed or mis-keyed entry that later
// recovery would trust.
// ─────────────────────────────────────────────────────────────────────────────────────────────

test('a snapshot with no canonical state digest is refused', async () => {
  const { archive } = loadArchiver();
  const bad = snapshot();
  bad.state.digest = '0xnothex';
  await assert.rejects(() => archive(JSON.stringify(bad)), /no canonical digest/);
});

test('a snapshot with no channel id is refused', async () => {
  const { archive } = loadArchiver();
  const bad = snapshot();
  delete bad.record.channelId;
  await assert.rejects(() => archive(JSON.stringify(bad)), /no channel id/);
});

test('an oversized payload is refused before it touches the store', async () => {
  const { archive, rows } = loadArchiver();
  const bad = snapshot();
  bad.padding = 'x'.repeat(33 * 1024 * 1024); // > MAX_CLAIM_SNAPSHOT_BYTES
  await assert.rejects(() => archive(JSON.stringify(bad)), /exceeds the browser archive limit/);
  assert.equal(rows.size, 0, 'an oversized payload must not be stored');
});

test('a non-string argument is refused', async () => {
  const { archive } = loadArchiver();
  await assert.rejects(() => archive({ not: 'a string' }), /exceeds the browser archive limit/);
});

test('a malformed prior archive under the same key is a hard conflict, not a silent overwrite', async () => {
  const rows = new Map();
  // Seed a corrupt existing entry at the key the next archive will use.
  rows.set('7:' + DIGEST, { key: '7:' + DIGEST, channelId: 7, digest: DIGEST, snapshotJson: '{not json' });
  const { archive } = loadArchiver(rows);
  await assert.rejects(
    () => archive(JSON.stringify(snapshot())),
    /refusing to replace a different verified snapshot under the same digest/,
    'a prior entry that cannot be parsed must never be assumed equal to the new one',
  );
});

test('two channels with the same state digest do not collide (channel is part of the key)', async () => {
  const { archive, rows } = loadArchiver();
  const a = snapshot();               // channel 7
  const b = snapshot();
  b.record.channelId = 8;             // same digest, different channel
  await archive(JSON.stringify(a));
  await assert.doesNotReject(() => archive(JSON.stringify(b)));
  assert.ok(rows.has('7:' + DIGEST) && rows.has('8:' + DIGEST), 'both channels keep their own entry');
});
