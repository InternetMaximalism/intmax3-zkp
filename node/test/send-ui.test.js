'use strict';
// Browser SEND path: which token positions may be spent, how the amount is denominated, and the
// per-(member, token) sendability predicate that decides whether a refresh must run first.
//
// WHAT THESE TESTS ARE MEANT TO PROVE ABOUT SECURITY
//
//   * the selector gate — `sendableTokens` decides what the user can spend. It reuses
//     `depositableTokens` (chain-verified metadata only) for exactly one reason: an unverified
//     token has `decimals: null`, so an amount typed into the box CANNOT be denominated. Offering
//     it would mean signing an amount at a guessed scale. Holding a balance in such a position is
//     not sufficient to make it sendable; the raw balance row is the disclosure instead.
//
//   * slot authority — the LOCAL token slot is what `wallet_send` actually debits. It must come
//     from the wallet's OWN decrypted balance report, never from the relay-supplied token list; a
//     relay that mislabelled the slot must not be able to turn "send ITX" into a debit of the ETH
//     position. These tests pin that precedence explicitly.
//
//   * denomination — a 6-dp $ITX amount scaled by 18 is a 10^12 error. `parseSendAmount` must use
//     the selected token's verified decimals, refuse an amount more precise than the token can
//     represent (rounding would sign a different number than the one displayed), and refuse a
//     non-positive or u64-overflowing amount before anything is proved.
//
//   * the sendable predicate — the wallet holds at most ONE send witness, for the position named by
//     `witnessTokenSlot`; `canSend` refers to THAT position only. `witnessBacksTokenSlot` must
//     answer true only when the witness backs the exact position being spent, and must treat
//     missing/malformed state as NOT sendable (an extra refresh is cheap; skipping a mandatory one
//     is not). The page's behaviour must match `witnessBacks` in
//     node/delegate/branches/owntx.js — the reference semantics — so the last test compares the two
//     implementations over a matrix of states.
//
// HOW IT LOADS THE CODE UNDER TEST
//   Same extraction trick as deposit-ui.test.js: `wallet-live.html` ships as ONE file, so the pure
//   logic lives in a marked region of its inline module and is evaluated here in a `node:vm`
//   sandbox. The assertions run against the bytes that ship.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const { witnessBacks } = require('../delegate/branches/owntx');

const HTML = path.join(__dirname, '..', '..', 'hosting', 'wallet', 'wallet-live.html');
const BEGIN = '// TESTABLE-BEGIN: deposit-ui';
const END = '// TESTABLE-END: deposit-ui';

const EXPORTS = [
  'TOKEN_DECIMALS', 'NATIVE_TOKEN_INDEX', 'MAX_U64',
  'fmtUnits', 'toUnits', 'parseSendAmount',
  'depositableTokens', 'sendableTokens', 'witnessBacksTokenSlot',
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
    { filename: 'wallet-live.html#send-ui' });
}

const M = loadRegion();

const ITX_DP = 6;
const ETH_DP = 18;
const ITX_ADDR = '0xa513e6e4b8f2a923d98304ec87f64353c4d5c853';

// The live dev stack's channel 7: ETH at index/position 0, verified $ITX (6 dp) at 1, and an
// UNREGISTERED/unverified token at 2 — the exact shape this feature was written against.
const LIVE_TOKENS = {
  tokenCount: 3,
  tokens: [
    { tokenSlot: 0, tokenIndex: 0, symbol: 'ETH', name: 'Ether', decimals: 18, address: null, native: true, verified: true },
    { tokenSlot: 1, tokenIndex: 1, symbol: 'ITX', name: 'Intmax Test Token', decimals: ITX_DP, address: ITX_ADDR, native: false, verified: true },
    { tokenSlot: 2, tokenIndex: 2, symbol: null, name: null, decimals: null, address: null, native: false, verified: false },
  ],
};

// What `activePositions(report)` yields for a member of that channel (the wallet's OWN decrypted
// view: local slot + base index + balance).
const LIVE_POSITIONS = [
  { tokenSlot: 0, tokenIndex: 0, balance: 50000000000000000n },
  { tokenSlot: 1, tokenIndex: 1, balance: 100000000n },
  { tokenSlot: 2, tokenIndex: 2, balance: 7n },
];

// ───────────────────────── selector gate ─────────────────────────

test('sendableTokens offers native ETH and the verified token, never the unverified one', () => {
  const out = M.sendableTokens(LIVE_TOKENS, LIVE_POSITIONS);
  assert.deepStrictEqual(out.map((t) => t.tokenIndex), [0, 1]);
  assert.deepStrictEqual(out.map((t) => t.tokenSlot), [0, 1]);
  assert.deepStrictEqual(out.map((t) => t.decimals), [ETH_DP, ITX_DP]);
  assert.deepStrictEqual(out.map((t) => t.label), ['ETH', 'ITX']);
  // The whole point: index 2 is held (balance 7) but cannot be denominated, so it is not sendable.
  assert.ok(!out.some((t) => t.tokenIndex === 2));
});

test('sendableTokens excludes an entry the relay marks verified but leaves without decimals', () => {
  const tokens = { tokens: [
    LIVE_TOKENS.tokens[0],
    { tokenSlot: 1, tokenIndex: 1, symbol: 'ITX', decimals: null, address: ITX_ADDR, native: false, verified: true },
  ] };
  const out = M.sendableTokens(tokens, LIVE_POSITIONS.slice(0, 2));
  assert.deepStrictEqual(out.map((t) => t.tokenIndex), [0]);
});

test('sendableTokens excludes a verified token the wallet holds no position in', () => {
  // Verified metadata for index 1, but this member's report has only the genesis position.
  const out = M.sendableTokens(LIVE_TOKENS, [LIVE_POSITIONS[0]]);
  assert.deepStrictEqual(out.map((t) => t.tokenIndex), [0]);
});

test('the LOCAL slot comes from the wallet report, not from the relay token list', () => {
  // A relay that claims $ITX sits at position 0 must not be able to make "send ITX" debit the ETH
  // position: the offered slot is the one in the wallet's own decrypted report.
  const lying = { tokens: [
    LIVE_TOKENS.tokens[0],
    Object.assign({}, LIVE_TOKENS.tokens[1], { tokenSlot: 0 }),
  ] };
  const out = M.sendableTokens(lying, LIVE_POSITIONS);
  const itx = out.find((t) => t.tokenIndex === 1);
  assert.strictEqual(itx.tokenSlot, 1);
  assert.strictEqual(out.find((t) => t.tokenIndex === 0).tokenSlot, 0);
});

test('sendableTokens drops malformed positions and duplicate slots', () => {
  const out = M.sendableTokens(LIVE_TOKENS, [
    { tokenSlot: null, tokenIndex: 0, balance: 1n },      // no local slot ⇒ nothing to send
    { tokenSlot: -1, tokenIndex: 0, balance: 1n },
    { tokenSlot: 1.5, tokenIndex: 1, balance: 1n },
    { tokenSlot: 1, tokenIndex: 1, balance: 1n },
    { tokenSlot: 1, tokenIndex: 0, balance: 1n },         // duplicate slot, contradictory index
    null,
  ]);
  assert.deepStrictEqual(out.map((t) => [t.tokenSlot, t.tokenIndex]), [[1, 1]]);
});

test('sendableTokens falls back to native ETH exactly where the old page did', () => {
  // No token list at all (older relay / offline) and no per-token report (older wasm build).
  for (const positions of [[], null, undefined]) {
    const out = M.sendableTokens(null, positions);
    assert.deepStrictEqual(out, [{ tokenSlot: 0, tokenIndex: 0, label: 'ETH', decimals: ETH_DP, native: true }]);
  }
  // No token list, but the report says the genesis position IS the native asset: still ETH, and
  // that is protocol construction, not a metadata guess.
  const out = M.sendableTokens(null, [{ tokenSlot: 0, tokenIndex: 0, balance: 5n }]);
  assert.deepStrictEqual(out.map((t) => [t.tokenSlot, t.decimals]), [[0, ETH_DP]]);
});

test('sendableTokens refuses to invent ETH for a NON-native genesis position', () => {
  // registry[0] is some unverified token — the old 18-dp assumption would be wrong, so nothing is
  // sendable and the Send button reports that rather than signing a guessed amount.
  const out = M.sendableTokens(null, [{ tokenSlot: 0, tokenIndex: 9, balance: 5n }]);
  assert.deepStrictEqual(out, []);
});

// ───────────────────────── per-token denomination ─────────────────────────

test('parseSendAmount denominates with the SELECTED token decimals', () => {
  assert.strictEqual(M.parseSendAmount('12.5', ITX_DP), '12500000');
  assert.strictEqual(M.parseSendAmount('100', ITX_DP), '100000000');
  assert.strictEqual(M.parseSendAmount('0.005', ETH_DP), '5000000000000000');
  // The bug this feature exists to prevent: 12.5 $ITX must never become 12.5e18.
  assert.notStrictEqual(M.parseSendAmount('12.5', ITX_DP), M.parseSendAmount('12.5', ETH_DP));
});

test('parseSendAmount refuses excess precision instead of truncating it', () => {
  assert.throws(() => M.parseSendAmount('0.0000001', ITX_DP), /6 decimals/);
  assert.throws(() => M.parseSendAmount('1.2345678', ITX_DP), /6 decimals/);
  assert.strictEqual(M.parseSendAmount('1.234567', ITX_DP), '1234567');
});

test('parseSendAmount refuses non-positive, malformed, and unverified-decimals amounts', () => {
  assert.throws(() => M.parseSendAmount('0', ITX_DP), /positive/);
  assert.throws(() => M.parseSendAmount('-1', ITX_DP), /negative/);
  assert.throws(() => M.parseSendAmount('', ITX_DP), /invalid amount/);
  assert.throws(() => M.parseSendAmount('abc', ITX_DP), /invalid amount/);
  for (const bad of [null, undefined, 6.5, -1, '6']) {
    assert.throws(() => M.parseSendAmount('1', bad), /verified token decimals/);
  }
});

test('parseSendAmount refuses an amount beyond the u64 in-channel limit', () => {
  const overflow = M.fmtUnits(M.MAX_U64 + 1n, ITX_DP);
  assert.throws(() => M.parseSendAmount(overflow, ITX_DP), /u64 in-channel limit/);
  assert.strictEqual(M.parseSendAmount(M.fmtUnits(M.MAX_U64, ITX_DP), ITX_DP), M.MAX_U64.toString());
});

// ───────────────────────── sendability predicate ─────────────────────────

const REPORT = (over) => Object.assign({ slot: 5, canSend: true, witnessTokenSlot: 0, stateVersion: 3 }, over);

test('witnessBacksTokenSlot: true only for the position the witness actually backs', () => {
  assert.strictEqual(M.witnessBacksTokenSlot(REPORT({ witnessTokenSlot: 1 }), 1), true);
  assert.strictEqual(M.witnessBacksTokenSlot(REPORT({ witnessTokenSlot: 0 }), 0), true);
});

test('witnessBacksTokenSlot: a genesis witness never authorizes spending token 1', () => {
  // This is the live gap: canSend === true with the witness at position 0 while the user tries to
  // send $ITX (position 1). Answering true would skip the mandatory refresh.
  assert.strictEqual(M.witnessBacksTokenSlot(REPORT({ witnessTokenSlot: 0 }), 1), false);
  assert.strictEqual(M.witnessBacksTokenSlot(REPORT({ witnessTokenSlot: 1 }), 0), false);
});

test('witnessBacksTokenSlot: missing / malformed state is NOT sendable', () => {
  assert.strictEqual(M.witnessBacksTokenSlot(REPORT({ canSend: false }), 0), false);
  assert.strictEqual(M.witnessBacksTokenSlot(REPORT({ canSend: 'true' }), 0), false);
  assert.strictEqual(M.witnessBacksTokenSlot(REPORT({ witnessTokenSlot: null }), 0), false);
  assert.strictEqual(M.witnessBacksTokenSlot(REPORT({ witnessTokenSlot: undefined }), 0), false);
  assert.strictEqual(M.witnessBacksTokenSlot(REPORT({ witnessTokenSlot: '0' }), 0), false);
  assert.strictEqual(M.witnessBacksTokenSlot(REPORT({ witnessTokenSlot: 0.0000001 }), 0), false);
  assert.strictEqual(M.witnessBacksTokenSlot(null, 0), false);
  assert.strictEqual(M.witnessBacksTokenSlot(undefined, 0), false);
  assert.strictEqual(M.witnessBacksTokenSlot('canSend', 0), false);
  // A malformed REQUESTED slot is refused too, rather than defaulting to genesis.
  for (const bad of [null, undefined, -1, 1.5, '1']) {
    assert.strictEqual(M.witnessBacksTokenSlot(REPORT({ witnessTokenSlot: 1 }), bad), false);
  }
});

test('witnessBacksTokenSlot agrees with the delegate reference implementation (owntx.witnessBacks)', () => {
  // Same rule, two code bases: the page must not drift from node/delegate/branches/owntx.js. The
  // delegate stores the report's fields in its store, so the store view is built from the same
  // values. Only well-formed integer slots are compared — the page is deliberately STRICTER on
  // malformed input (owntx's normTokenSlot maps undefined ⇒ genesis for its own callers).
  for (const canSend of [true, false]) {
    for (const witness of [0, 1, 2, null]) {
      for (const want of [0, 1, 2]) {
        const report = { canSend, witnessTokenSlot: witness };
        const store = { get: (k) => (k === 'canSend' ? canSend : witness) };
        assert.strictEqual(
          M.witnessBacksTokenSlot(report, want), witnessBacks(store, want),
          `mismatch for canSend=${canSend} witness=${witness} want=${want}`);
      }
    }
  }
});
