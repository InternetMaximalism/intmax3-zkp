'use strict';
// Browser deposit path: per-token amount denomination, the depositable-token gate, ERC-20 call
// encoding, and the confirmation-retry predicate.
//
// WHAT THESE TESTS ARE MEANT TO PROVE ABOUT SECURITY
//   The browser is the only place in the deposit flow that decides WHICH asset and HOW MUCH the
//   user signs for. Everything after that point is chain-verified (`cosign-l1-deposit-import`
//   reads amount/depositor/token_index out of the `Deposited` log), so the browser cannot lie to
//   the protocol — but it can lie to the USER. These tests attack exactly that surface:
//
//     * denomination  — an amount denominated with the WRONG decimals is a silent 10^12 error for
//                       $ITX (6 dp) rendered as if it were ETH (18 dp). `toUnits` must refuse an
//                       unknown/unverified `decimals` outright, and must REFUSE rather than round
//                       an amount more precise than the token can represent (rounding would sign a
//                       different number than the one displayed).
//     * the gate      — `depositableTokens` is the single filter deciding what can be selected. It
//                       must admit tokenIndex 0 (native by protocol construction) and NOTHING else
//                       that is not chain-verified with a well-formed symbol, integer decimals and
//                       a non-zero contract address. `verified === true` alone is NOT sufficient:
//                       TokenRegistry.metadataFor can return verified with `decimals: null`.
//     * encoding      — `approve`'s spender and `allowance`'s arguments must be real 20-byte
//                       addresses; a malformed one must throw rather than be zero-padded into a
//                       different address by `padHex`.
//     * retry gating  — the import is retried ONLY on the CLI's specific under-confirmation
//                       refusal. A loose match would turn any failure into an endless "pending"
//                       spinner, hiding a real refusal to credit.
//
// HOW IT LOADS THE CODE UNDER TEST
//   `wallet-live.html` ships as ONE file (see doc/docs/deploy-runbook.md), so the pure logic lives
//   in a marked region inside its inline module rather than in a separate importable file. This
//   test EXTRACTS that exact region and evaluates it in a `node:vm` sandbox — the assertions
//   therefore run against the bytes that ship, not against a copy that can drift.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const HTML = path.join(__dirname, '..', '..', 'hosting', 'wallet', 'wallet-live.html');
const BEGIN = '// TESTABLE-BEGIN: deposit-ui';
const END = '// TESTABLE-END: deposit-ui';

const EXPORTS = [
  'TOKEN_DECIMALS', 'NATIVE_TOKEN_INDEX', 'MAX_U64', 'ZERO_B32',
  'DEPOSIT_SELECTOR', 'APPROVE_SELECTOR', 'ALLOWANCE_SELECTOR',
  'fmtUnits', 'fmtAmt', 'clampLabel',
  'normalizeDecimalString', 'toUnits', 'toBase', 'parseDepositAmount',
  'depositableTokens',
  'padHex', 'encodeDepositCall', 'encodeApproveCall', 'encodeAllowanceCall',
  'decodeUint256Word', 'allowanceSufficient', 'parseConfirmationProgress',
];

function loadRegion() {
  const html = fs.readFileSync(HTML, 'utf8');
  const i = html.indexOf(BEGIN);
  const j = html.indexOf(END);
  assert.ok(i >= 0, 'wallet-live.html has no ' + BEGIN + ' marker');
  assert.ok(j > i, 'wallet-live.html has no ' + END + ' marker after the begin marker');
  const src = html.slice(i + BEGIN.length, j);
  // The region must stay pure: no DOM, no fetch, no page state. A violation would both break this
  // sandbox and mean the shipped helpers are no longer independently reviewable.
  for (const forbidden of ['document.', 'window.', 'fetch(', 'localStorage', 'walletProvider']) {
    assert.ok(!src.includes(forbidden),
      'the TESTABLE region must stay pure, but it references ' + forbidden);
  }
  // Evaluated in THIS realm (inside an IIFE, so nothing leaks into the global scope): the helpers
  // return plain objects/arrays and throw Errors that the assert helpers can compare directly.
  return vm.runInThisContext(
    '(function () {' + src + '\n;return {' + EXPORTS.join(',') + '};})()',
    { filename: 'wallet-live.html#deposit-ui' });
}

const M = loadRegion();

const ITX = 6;   // $ITX decimals — the whole reason this file exists
const ETH = 18;
const ROLLUP = '0x5FbDB2315678afecb367f032d93F642f64180aa3';
const TOKEN = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238';
const OWNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const ZERO20 = '0x0000000000000000000000000000000000000000';

function verifiedEntry(over) {
  return Object.assign({
    tokenSlot: 1, tokenIndex: 5, symbol: 'ITX', name: 'Intmax Test Token',
    decimals: ITX, address: TOKEN, native: false, verified: true, fundAmount: '0',
  }, over || {});
}
const nativeEntry = () => ({
  tokenSlot: 0, tokenIndex: 0, symbol: 'ETH', name: 'Ether',
  decimals: 18, address: null, native: true, verified: true, fundAmount: '0',
});
const payload = (tokens) => ({ tokenCount: tokens.length, tokens });

// ══════════════════════════════════════════════════════════════════════════════════════════════
// Amount denomination
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('toUnits denominates with the TOKEN\'s decimals — the 10^12 $ITX trap', () => {
  assert.strictEqual(M.toUnits('1', ITX), '1000000');
  assert.strictEqual(M.toUnits('1', ETH), '1000000000000000000');
  // The whole hazard in one assertion: the same typed amount must NOT produce the same base units.
  assert.notStrictEqual(M.toUnits('1', ITX), M.toBase('1'));
  assert.strictEqual(M.toUnits('1.5', ITX), '1500000');
  assert.strictEqual(M.toUnits('0.000001', ITX), '1');
  assert.strictEqual(M.toUnits('0.05', ETH), '50000000000000000');
});

test('toUnits REFUSES an unverified/absent decimals rather than assuming 18', () => {
  // This is the path an unverified relay entry would take if the gate ever leaked.
  for (const bad of [null, undefined, '18', 18.5, -1, 37, NaN]) {
    assert.throws(() => M.toUnits('1', bad), /verified token decimals/,
      'decimals ' + String(bad) + ' must be refused');
  }
});

test('toUnits REFUSES excess precision instead of truncating it', () => {
  // Truncating would sign a DIFFERENT amount than the one shown to the user.
  assert.throws(() => M.toUnits('1.1234567', ITX), /6 decimals/);
  assert.throws(() => M.toUnits('0.0000001', ITX), /6 decimals/);
  // trailing zeros are not precision
  assert.strictEqual(M.toUnits('1.5000000000', ITX), '1500000');
  assert.strictEqual(M.toUnits('1.000000000000000000000', ETH), '1000000000000000000');
});

test('toUnits refuses negatives and junk', () => {
  assert.throws(() => M.toUnits('-1', ITX), /negative/);
  for (const bad of ['', '   ', '.', 'abc', '1.2.3', '0x10', '1,5', '1 2', '--1', 'Infinity', 'NaN']) {
    assert.throws(() => M.toUnits(bad, ITX), /invalid amount|negative/, JSON.stringify(bad));
  }
});

test('normalizeDecimalString shifts the point EXACTLY (no Number() rounding)', () => {
  assert.strictEqual(M.normalizeDecimalString('1e-7'), '0.0000001');
  assert.strictEqual(M.normalizeDecimalString('1.5e3'), '1500');
  assert.strictEqual(M.normalizeDecimalString('1.5E+3'), '1500');
  assert.strictEqual(M.normalizeDecimalString('.5'), '0.5');
  assert.strictEqual(M.normalizeDecimalString('007.500'), '7.5');
  assert.strictEqual(M.normalizeDecimalString('-0'), '0');
  assert.strictEqual(M.normalizeDecimalString('-0.5'), '-0.5');
  // 20 significant digits: a Number() round-trip would corrupt this, string math must not.
  assert.strictEqual(M.normalizeDecimalString('12345678901234567890'), '12345678901234567890');
  assert.strictEqual(M.toUnits('12345678901234567890e-18', ETH), '12345678901234567890');
  assert.strictEqual(M.normalizeDecimalString('1e99999'), null); // absurd exponent, refused
});

test('parseDepositAmount enforces the range a deposit can actually be credited in', () => {
  assert.strictEqual(M.parseDepositAmount('1.5', ITX), '1500000');
  assert.throws(() => M.parseDepositAmount('0', ITX), /positive/);
  assert.throws(() => M.parseDepositAmount('0.0', ETH), /positive/);
  // u64 boundary: in-channel balances are u64 base units and the import REFUSES a wider
  // Deposited.amount, which would strand the L1 escrow. Refuse before anything is signed.
  const maxU64 = M.MAX_U64.toString();
  assert.strictEqual(M.parseDepositAmount(M.fmtUnits(maxU64, ITX), ITX), maxU64);
  assert.throws(() => M.parseDepositAmount(M.fmtUnits((M.MAX_U64 + 1n).toString(), ITX), ITX),
    /u64 in-channel limit/);
  // 1 ETH is fine; 100 ETH at 18 dp already exceeds u64 and must be refused, not silently sent.
  assert.throws(() => M.parseDepositAmount('100', ETH), /u64 in-channel limit/);
});

test('property: fmtUnits ∘ toUnits is the identity on base units, for many decimals', () => {
  // Randomized: a subtle off-by-one in the padding logic survives hand-picked cases.
  let seed = 0x243f6a88;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (let i = 0; i < 800; i++) {
    const decimals = Math.floor(rnd() * 25);        // 0..24
    const digits = 1 + Math.floor(rnd() * 19);
    let v = '';
    for (let k = 0; k < digits; k++) v += String(Math.floor(rnd() * 10));
    const base = BigInt(v).toString();
    const shown = M.fmtUnits(base, decimals);
    assert.strictEqual(M.toUnits(shown, decimals), base,
      'roundtrip failed for base=' + base + ' decimals=' + decimals + ' shown=' + shown);
  }
});

// ══════════════════════════════════════════════════════════════════════════════════════════════
// The depositable-token gate
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('gate: a chain-verified ERC-20 is depositable, with ITS decimals and ITS address', () => {
  const out = M.depositableTokens(payload([nativeEntry(), verifiedEntry()]));
  assert.strictEqual(out.length, 2);
  assert.deepStrictEqual(out[0], { tokenIndex: 0, tokenSlot: 0, label: 'ETH', name: null, decimals: 18, address: null, native: true });
  assert.strictEqual(out[1].tokenIndex, 5);
  assert.strictEqual(out[1].decimals, ITX);
  assert.strictEqual(out[1].address, TOKEN);
  assert.strictEqual(out[1].label, 'ITX');
});

test('gate: UNVERIFIED entries never become depositable', () => {
  // The relay serves `verified:false` for anything whose manifest address was not read back equal
  // from the rollup's set-once tokenAddressOf. Offering it would invite depositing the wrong asset.
  for (const v of [false, undefined, null, 'true', 1, {}]) {
    const out = M.depositableTokens(payload([verifiedEntry({ verified: v })]));
    assert.deepStrictEqual(out, [], 'verified=' + JSON.stringify(v) + ' must not be depositable');
  }
});

test('gate: verified BUT with unusable decimals is still refused', () => {
  // TokenRegistry.metadataFor returns { verified: true, decimals: null } when the ERC-20
  // decimals() read-back failed. `verified` alone is NOT a licence to denominate an amount.
  for (const d of [null, undefined, '6', 6.5, -1, 37, NaN]) {
    assert.deepStrictEqual(M.depositableTokens(payload([verifiedEntry({ decimals: d })])), [],
      'decimals=' + String(d) + ' must not be depositable');
  }
});

test('gate: a missing / malformed / zero token address is refused', () => {
  for (const a of [null, undefined, '', ZERO20, ZERO20.toUpperCase().replace('0X', '0x'),
    '0x1234', TOKEN.slice(0, -1), TOKEN + '00', 'not-an-address', ' ' + TOKEN.slice(2), 123]) {
    assert.deepStrictEqual(M.depositableTokens(payload([verifiedEntry({ address: a })])), [],
      'address=' + String(a) + ' must not be depositable');
  }
  // …but surrounding whitespace on an otherwise good address is tolerated and trimmed.
  const ok = M.depositableTokens(payload([verifiedEntry({ address: '  ' + TOKEN + '  ' })]));
  assert.strictEqual(ok.length, 1);
  assert.strictEqual(ok[0].address, TOKEN);
});

test('gate: a symbol that is empty after sanitization is refused, and spoofing chars are stripped', () => {
  assert.deepStrictEqual(M.depositableTokens(payload([verifiedEntry({ symbol: '' })])), []);
  assert.deepStrictEqual(M.depositableTokens(payload([verifiedEntry({ symbol: '‮‏' })])), []);
  assert.deepStrictEqual(M.depositableTokens(payload([verifiedEntry({ symbol: 42 })])), []);
  const out = M.depositableTokens(payload([verifiedEntry({ symbol: 'IT‮X ' })]));
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].label, 'ITX', 'bidi/control characters must be stripped from the label');
  // Length is hard-capped so a long symbol cannot push the authoritative #index out of view.
  const long = M.depositableTokens(payload([verifiedEntry({ symbol: 'A'.repeat(64) })]));
  assert.ok(long[0].label.length <= 13, 'symbol must be clamped, got ' + long[0].label.length);
});

test('gate: tokenIndex 0 is depositable by PROTOCOL construction, with no metadata trust', () => {
  // Even a hostile/absent native entry yields ETH/18: the contract pays index 0 from msg.value.
  const hostile = { tokenSlot: 0, tokenIndex: 0, symbol: 'USDC', name: 'USD Coin', decimals: 6, address: TOKEN, native: false, verified: false };
  const out = M.depositableTokens(payload([hostile]));
  assert.deepStrictEqual(out, [{ tokenIndex: 0, tokenSlot: 0, label: 'ETH', name: null, decimals: 18, address: null, native: true }]);
});

test('gate: "native" claimed at a NON-zero index is a contradiction and is refused', () => {
  assert.deepStrictEqual(M.depositableTokens(payload([verifiedEntry({ native: true })])), []);
});

test('gate: malformed shapes are dropped, never partially accepted', () => {
  assert.deepStrictEqual(M.depositableTokens(null), []);
  assert.deepStrictEqual(M.depositableTokens(undefined), []);
  assert.deepStrictEqual(M.depositableTokens({}), []);
  assert.deepStrictEqual(M.depositableTokens({ tokens: 'nope' }), []);
  assert.deepStrictEqual(M.depositableTokens(payload([null, 7, 'x', {}, { tokenIndex: -1 }, { tokenIndex: 1.5 }])), []);
  // one bad entry must not take a good one down with it
  const mixed = M.depositableTokens(payload([null, verifiedEntry(), { tokenIndex: 'x' }]));
  assert.strictEqual(mixed.length, 1);
  assert.strictEqual(mixed[0].tokenIndex, 5);
});

test('gate: duplicate base indices collapse to one option', () => {
  const out = M.depositableTokens(payload([
    verifiedEntry({ tokenSlot: 1 }),
    verifiedEntry({ tokenSlot: 2, symbol: 'EVIL' }),
  ]));
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].label, 'ITX', 'the first registry position wins; a duplicate cannot relabel it');
});

test('gate: a bare array payload is accepted too (defensive, same rules)', () => {
  const out = M.depositableTokens([verifiedEntry()]);
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].tokenIndex, 5);
});

// ══════════════════════════════════════════════════════════════════════════════════════════════
// Call encoding
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('encodeDepositCall: selector + 4 words, tokenIndex is NOT hardcoded to 0', () => {
  const d = M.encodeDepositCall(M.ZERO_B32, 5, '1500000', M.ZERO_B32);
  assert.ok(d.startsWith(M.DEPOSIT_SELECTOR));
  assert.strictEqual(d.length, 10 + 4 * 64);
  const word = (n) => d.slice(10 + n * 64, 10 + (n + 1) * 64);
  assert.strictEqual(BigInt('0x' + word(1)), 5n, 'tokenIndex word');
  assert.strictEqual(BigInt('0x' + word(2)), 1500000n, 'amount word');
  assert.strictEqual(BigInt('0x' + M.encodeDepositCall(M.ZERO_B32, 0, '1', M.ZERO_B32).slice(74, 138)), 0n);
});

test('encodeApproveCall: right selector, right words, and a bad spender THROWS', () => {
  const d = M.encodeApproveCall(ROLLUP, '1500000');
  assert.ok(d.startsWith(M.APPROVE_SELECTOR));
  assert.strictEqual(d.length, 10 + 2 * 64);
  // calldata hex is case-insensitive; compare case-folded.
  assert.strictEqual(d.slice(10, 74).toLowerCase(), '0'.repeat(24) + ROLLUP.slice(2).toLowerCase(),
    'spender must be left-padded into the first word');
  assert.strictEqual(BigInt('0x' + d.slice(74)), 1500000n);
  // A malformed spender must not be zero-padded into some OTHER address by padHex.
  for (const bad of ['0x1234', '', null, undefined, 'rollup', ROLLUP + 'ff', 42]) {
    assert.throws(() => M.encodeApproveCall(bad, '1'), /spender is not a 20-byte address/,
      'spender ' + String(bad));
  }
});

test('encodeAllowanceCall: owner and spender are both address-checked', () => {
  const d = M.encodeAllowanceCall(OWNER, ROLLUP);
  assert.ok(d.startsWith(M.ALLOWANCE_SELECTOR));
  assert.strictEqual(d.length, 10 + 2 * 64);
  assert.strictEqual(d.slice(10, 74).toLowerCase(), '0'.repeat(24) + OWNER.slice(2).toLowerCase());
  assert.strictEqual(d.slice(74).toLowerCase(), '0'.repeat(24) + ROLLUP.slice(2).toLowerCase());
  assert.throws(() => M.encodeAllowanceCall('0x00', ROLLUP), /owner is not a 20-byte address/);
  assert.throws(() => M.encodeAllowanceCall(OWNER, '0x00'), /spender is not a 20-byte address/);
});

test('the approve selector is NOT the deposit selector (cross-call confusion)', () => {
  const s = new Set([M.DEPOSIT_SELECTOR, M.APPROVE_SELECTOR, M.ALLOWANCE_SELECTOR]);
  assert.strictEqual(s.size, 3);
  assert.strictEqual(M.APPROVE_SELECTOR, '0x095ea7b3');   // cast sig "approve(address,uint256)"
  assert.strictEqual(M.ALLOWANCE_SELECTOR, '0xdd62ed3e'); // cast sig "allowance(address,address)"
  assert.strictEqual(M.DEPOSIT_SELECTOR, '0x48b8027b');   // cast sig "deposit(bytes32,uint32,uint256,bytes32)"
});

// ══════════════════════════════════════════════════════════════════════════════════════════════
// Allowance sufficiency (fail closed)
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('decodeUint256Word accepts exactly one word and nothing else', () => {
  assert.strictEqual(M.decodeUint256Word('0x' + '0'.repeat(63) + '5'), '5');
  assert.strictEqual(M.decodeUint256Word('0x' + 'f'.repeat(64)), (2n ** 256n - 1n).toString());
  for (const bad of ['0x', '0x1', '0x' + '0'.repeat(65), '', null, undefined, 'zzz', 5]) {
    assert.strictEqual(M.decodeUint256Word(bad), null, 'must refuse ' + String(bad));
  }
});

test('allowanceSufficient FAILS CLOSED on anything it cannot read', () => {
  // "unknown" must mean "approve first", never "already approved".
  for (const bad of [null, undefined, 'garbage', '-1', {}, []]) {
    assert.strictEqual(M.allowanceSufficient(bad, '1'), false, 'allowance ' + String(bad));
  }
  assert.strictEqual(M.allowanceSufficient('0', '1'), false);
  assert.strictEqual(M.allowanceSufficient('1499999', '1500000'), false);
  assert.strictEqual(M.allowanceSufficient('1500000', '1500000'), true, 'exact allowance is enough');
  assert.strictEqual(M.allowanceSufficient('1500001', '1500000'), true);
  assert.strictEqual(M.allowanceSufficient('0x' + '0'.repeat(58) + '16e360', '1500000'), true,
    'a raw eth_call word must be read as hex, not decimal');
  // Precision: a 2^53+ allowance must compare exactly (a Number path would round).
  assert.strictEqual(M.allowanceSufficient('9007199254740993', '9007199254740992'), true);
  assert.strictEqual(M.allowanceSufficient('9007199254740992', '9007199254740993'), false);
});

// ══════════════════════════════════════════════════════════════════════════════════════════════
// Confirmation-retry gating
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('parseConfirmationProgress matches the CLI\'s ACTUAL refusal text', () => {
  // Verbatim shape from src/bin/channel_member.rs `fetch_onchain_deposit`.
  const msg = 'relay /api/import-deposit: {"error":"deposit tx 0xabc has 3 confirmation(s), '
    + 'need 12 on chain 11155111 (reorg safety) — refusing\\n"}';
  assert.deepStrictEqual(M.parseConfirmationProgress(msg), { have: 3, need: 12 });
  assert.deepStrictEqual(M.parseConfirmationProgress('has 0 confirmation(s), need 1'), { have: 0, need: 1 });
});

test('parseConfirmationProgress returns null for every OTHER refusal — retry must not swallow them', () => {
  // Each of these is a genuine refusal to credit. Treating one as "still confirming" would hide it
  // behind an endless progress spinner instead of telling the user.
  for (const other of [
    'CREDIT MISDIRECTION REFUSED: the on-chain depositor 0x… is the bound (B-1b) recipient of ACTIVE slot 2',
    'REPLAY REFUSED: L1 deposit 31337:abc:4 has already been imported into this channel.',
    'tx 0xabc contains no `Deposited` log from rollup 0x… — refusing',
    'REFUSING: this is the channel\'s BACKING deposit',
    'deposit tx 0xabc did not succeed (status 0x0)',
    'reorg safety — refusing',            // the tail alone must NOT match
    'confirmations', 'confirmation(s)', '', null, undefined, 42, {},
  ]) {
    assert.strictEqual(M.parseConfirmationProgress(other), null,
      'must NOT be treated as an under-confirmation: ' + String(other));
  }
});

// ══════════════════════════════════════════════════════════════════════════════════════════════
// Shipped-source guards
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('the shipped page no longer hardcodes tokenIndex 0 into the deposit call', () => {
  const html = fs.readFileSync(HTML, 'utf8');
  assert.ok(!/encodeDepositCall\(\s*info\.depositRecipient\s*,\s*0\s*,/.test(html),
    'sendDepositViaWallet must pass the SELECTED tokenIndex, not a literal 0');
  assert.ok(html.includes('token.tokenIndex === NATIVE_TOKEN_INDEX'),
    'the native/ERC-20 split must be made on the token index');
});

test('the import request body stays exactly { recipientSlot, txHash }', () => {
  // Re-adding caller-supplied economics here would restore the "mint unbacked balance" bug that
  // commit bc3b6bf removed. Pin it as a negative on the shipped source.
  const html = fs.readFileSync(HTML, 'utf8');
  const calls = html.match(/'\/api\/import-deposit',\s*JSON\.stringify\(\{[^}]*\}\)/g) || [];
  for (const c of calls) {
    for (const banned of ['amount', 'depositor', 'tokenIndex']) {
      assert.ok(!c.includes(banned), 'import-deposit body must not carry ' + banned + ': ' + c);
    }
  }
});
