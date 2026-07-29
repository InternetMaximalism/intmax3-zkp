'use strict';
// In-channel $ITX testnet faucet — configuration + eligibility policy.
//
// WHAT THESE TESTS ARE MEANT TO PROVE ABOUT SECURITY
//   The faucet endpoint is unauthenticated and hands out REAL escrowed value, so the only thing
//   standing between it and a drain is this policy module. Each group below attacks one leg:
//     * config tests      — the faucet cannot be live by ACCIDENT. Absent, malformed, or
//                           incoherent knobs must all produce `enabled: false`, never a
//                           permissive default. In particular base token index 0 (native ETH,
//                           the channel's deposit backing) must never be dispensable.
//     * slot tests        — the recipient is the ONLY caller-supplied value. Non-integers,
//                           out-of-range slots, slots outside the channel's signed membership,
//                           and the faucet's own slot must all be refused — the body is never
//                           trusted about who exists.
//     * limit tests       — once-per-slot, per-channel cap and cooldown each independently
//                           refuse, and the cap is compared as BigInt (an 18-decimal cap is far
//                           past Number.MAX_SAFE_INTEGER, where float comparison silently
//                           mis-orders).
//     * ledger tests      — the reservation is written BEFORE the value moves and is never
//                           released, so a crash mid-transfer costs a drip instead of paying it
//                           twice; and a CORRUPT ledger throws instead of resetting to empty
//                           (a reset would re-open the faucet to everyone who already drank).

const test = require('node:test');
const assert = require('node:assert');

const {
  faucetConfig,
  checkEligibility,
  emptyState,
  normalizeState,
  reserveDrip,
  settleDrip,
  publicInfo,
  DEFAULT_DRIP,
  DEFAULT_CAP,
  MAX_U64,
  MAX_DRIP,
  MAX_CHANNEL_CAP,
} = require('../common/faucet-policy');

const ENV = {
  FAUCET_ENABLED: '1',
  FAUCET_SLOT: '2',
  ITX_TOKEN_INDEX: '7',
  FAUCET_DRIP: '100000000',        // 100 ITX at 6 decimals
  FAUCET_CHANNEL_CAP: '300000000',  // exactly 3 drips
  FAUCET_COOLDOWN_MS: '1000',
};
const env = (o) => Object.assign({}, ENV, o || {});
const cfg = (o) => faucetConfig(env(o));

// A channel with 3 co-signing members + 2 delegates: active balance slots are 0..4.
const ACTIVE = 5;
const base = (o) => Object.assign({
  config: cfg(),
  slot: 3,
  activeSlots: ACTIVE,
  localTokenSlot: 1,
  state: emptyState(),
  now: 1_000_000,
}, o || {});

// ── configuration: disabled is the default, every knob fails closed ─────────────────────────

test('faucet is disabled unless FAUCET_ENABLED is exactly 1', () => {
  for (const v of [undefined, '', '0', 'true', 'yes', '1 ', 'on']) {
    const c = faucetConfig(env({ FAUCET_ENABLED: v }));
    assert.strictEqual(c.enabled, false, `FAUCET_ENABLED=${JSON.stringify(v)} must not enable the faucet`);
    assert.ok(c.reason, 'a disabled config must say why');
  }
  assert.strictEqual(cfg().enabled, true);
});

test('an empty environment yields a disabled faucet (never a permissive default)', () => {
  assert.strictEqual(faucetConfig({}).enabled, false);
  assert.strictEqual(faucetConfig(undefined).enabled, false);
});

test('FAUCET_SLOT must be a plain slot index', () => {
  for (const v of [undefined, '', '-1', '1.5', 'two', '0x2', '1024']) {
    assert.strictEqual(faucetConfig(env({ FAUCET_SLOT: v })).enabled, false, `FAUCET_SLOT=${JSON.stringify(v)}`);
  }
  assert.strictEqual(faucetConfig(env({ FAUCET_SLOT: '0' })).enabled, true);
  // Surrounding whitespace in an env var is an operator typo, not an attack surface (the
  // environment is trusted config), so it is trimmed rather than treated as a disable.
  assert.strictEqual(faucetConfig(env({ FAUCET_SLOT: ' 2 ' })).enabled, true);
});

test('base token index 0 (native ETH) can never be the faucet token', () => {
  const c = faucetConfig(env({ ITX_TOKEN_INDEX: '0' }));
  assert.strictEqual(c.enabled, false);
  assert.match(c.reason, /native ETH/);
});

test('a malformed token index / drip / cap disables the faucet', () => {
  assert.strictEqual(faucetConfig(env({ ITX_TOKEN_INDEX: 'abc' })).enabled, false);
  assert.strictEqual(faucetConfig(env({ ITX_TOKEN_INDEX: '4294967296' })).enabled, false);
  assert.strictEqual(faucetConfig(env({ FAUCET_DRIP: '0' })).enabled, false);
  assert.strictEqual(faucetConfig(env({ FAUCET_DRIP: '-5' })).enabled, false);
  assert.strictEqual(faucetConfig(env({ FAUCET_DRIP: '1e18' })).enabled, false);
  assert.strictEqual(faucetConfig(env({ FAUCET_CHANNEL_CAP: '0' })).enabled, false);
  assert.strictEqual(faucetConfig(env({ FAUCET_COOLDOWN_MS: '-1' })).enabled, false);
});

test('a cap smaller than one drip is incoherent and disables the faucet', () => {
  const c = faucetConfig(env({ FAUCET_DRIP: '10', FAUCET_CHANNEL_CAP: '9' }));
  assert.strictEqual(c.enabled, false);
});

test('amounts above the u64 in-channel ceiling are refused at CONFIG time', () => {
  // In-channel balances are u64 base units, so an over-u64 amount could not be expressed in the
  // transfer at all: it must fail HERE rather than as an opaque CLI parse error after the ledger
  // reservation has already been written.
  const over = (MAX_U64 + 1n).toString();
  assert.strictEqual(faucetConfig(env({ FAUCET_DRIP: over, FAUCET_CHANNEL_CAP: over })).enabled, false);
  assert.strictEqual(faucetConfig(env({ FAUCET_CHANNEL_CAP: over })).enabled, false);
  // u64 is only an EXPRESSIBILITY bound. A u64-sized drip is ~18.4 trillion ITX and is now refused
  // by the tighter POLICY ceiling — u64 must never be the only thing standing between a mistyped
  // digit and the whole supply.
  assert.strictEqual(faucetConfig(env({ FAUCET_DRIP: MAX_U64.toString(), FAUCET_CHANNEL_CAP: MAX_U64.toString() })).enabled, false);
});

test('the hard per-claim ceiling bounds FAUCET_DRIP (a mistyped digit cannot drain the faucet)', () => {
  const capHigh = MAX_CHANNEL_CAP.toString();
  // The realistic accident: one extra zero-group on the default 100 ITX drip.
  const fatFinger = (BigInt(DEFAULT_DRIP) * 1000n).toString();
  assert.ok(BigInt(fatFinger) > MAX_DRIP, 'the scenario must actually cross the ceiling');
  const c = faucetConfig(env({ FAUCET_DRIP: fatFinger, FAUCET_CHANNEL_CAP: capHigh }));
  assert.strictEqual(c.enabled, false);
  assert.match(c.reason, /per-claim ceiling/);
  // Exactly at the ceiling is allowed; one base unit over is not.
  assert.strictEqual(faucetConfig(env({ FAUCET_DRIP: MAX_DRIP.toString(), FAUCET_CHANNEL_CAP: capHigh })).enabled, true);
  assert.strictEqual(faucetConfig(env({ FAUCET_DRIP: (MAX_DRIP + 1n).toString(), FAUCET_CHANNEL_CAP: capHigh })).enabled, false);
});

test('the hard per-channel ceiling bounds FAUCET_CHANNEL_CAP', () => {
  const c = faucetConfig(env({ FAUCET_CHANNEL_CAP: (MAX_CHANNEL_CAP + 1n).toString() }));
  assert.strictEqual(c.enabled, false);
  assert.match(c.reason, /per-channel ceiling/);
  assert.strictEqual(faucetConfig(env({ FAUCET_CHANNEL_CAP: MAX_CHANNEL_CAP.toString() })).enabled, true);
});

test('both hard ceilings sit strictly inside the u64 expressibility bound', () => {
  // If a future edit raised a ceiling past u64, the policy check would start passing amounts the
  // transfer cannot carry, and the u64 guard below it would become load-bearing again by accident.
  assert.ok(MAX_DRIP <= MAX_U64);
  assert.ok(MAX_CHANNEL_CAP <= MAX_U64);
  assert.ok(MAX_DRIP <= MAX_CHANNEL_CAP, 'a single claim must never exceed the whole-channel cap');
  assert.ok(BigInt(DEFAULT_DRIP) <= MAX_DRIP && BigInt(DEFAULT_CAP) <= MAX_CHANNEL_CAP,
    'the shipped defaults must themselves satisfy the ceilings');
});

test('omitted drip/cap/cooldown fall back to the documented defaults', () => {
  const c = faucetConfig({ FAUCET_ENABLED: '1', FAUCET_SLOT: '2', ITX_TOKEN_INDEX: '7' });
  assert.strictEqual(c.enabled, true);
  assert.strictEqual(c.dripAmount.toString(), DEFAULT_DRIP);
  assert.ok(c.channelCap >= c.dripAmount);
});

test('publicInfo never leaks anything but the advertised grant', () => {
  assert.deepStrictEqual(publicInfo(faucetConfig({})), { enabled: false });
  const info = publicInfo(cfg());
  assert.deepStrictEqual(Object.keys(info).sort(), ['amount', 'cooldownMs', 'enabled', 'tokenIndex']);
  assert.strictEqual(info.amount, ENV.FAUCET_DRIP);
});

// ── the recipient slot is never trusted ──────────────────────────────────────────────────────

test('a disabled faucet refuses every request', () => {
  const r = checkEligibility(base({ config: faucetConfig({}) }));
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.code, 'disabled');
});

test('a non-integer slot is refused', () => {
  for (const slot of ['3', 3.5, -1, null, undefined, {}, [], NaN, Infinity, true]) {
    const r = checkEligibility(base({ slot }));
    assert.strictEqual(r.ok, false, `slot ${JSON.stringify(slot)} must be refused`);
    assert.strictEqual(r.code, 'bad_slot');
  }
});

test('a slot outside the channel signed membership is refused', () => {
  assert.strictEqual(checkEligibility(base({ slot: ACTIVE })).code, 'bad_slot');
  assert.strictEqual(checkEligibility(base({ slot: 999 })).code, 'bad_slot');
  // A caller cannot widen the membership either: activeSlots comes from the signed snapshot.
  assert.strictEqual(checkEligibility(base({ activeSlots: 0 })).code, 'bad_slot');
  assert.strictEqual(checkEligibility(base({ activeSlots: undefined })).code, 'bad_slot');
});

test('the faucet may never drip to itself', () => {
  const r = checkEligibility(base({ slot: 2 })); // FAUCET_SLOT
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.code, 'bad_slot');
});

test('an unregistered faucet token refuses the drip', () => {
  for (const localTokenSlot of [null, undefined, -1, '1', 1.5]) {
    const r = checkEligibility(base({ localTokenSlot }));
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.code, 'token_not_registered');
  }
});

test('a well-formed request against a fresh ledger is allowed', () => {
  assert.deepStrictEqual(checkEligibility(base()), { ok: true, code: 'ok' });
});

// ── limits ───────────────────────────────────────────────────────────────────────────────────

test('one drip per slot, for ever — including after a FAILED transfer', () => {
  for (const status of ['pending', 'done', 'failed']) {
    const state = { drips: { 3: { amount: ENV.FAUCET_DRIP, at: 1, status } }, totalDripped: ENV.FAUCET_DRIP, lastDripAt: 1 };
    const r = checkEligibility(base({ state }));
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.code, 'already_funded');
    assert.strictEqual(r.alreadyFunded, true);
  }
});

test('a different slot is unaffected by another slot record', () => {
  const state = { drips: { 3: { amount: ENV.FAUCET_DRIP, at: 1, status: 'done' } }, totalDripped: ENV.FAUCET_DRIP, lastDripAt: 1 };
  assert.strictEqual(checkEligibility(base({ slot: 4, state })).ok, true);
});

test('the per-channel cap is enforced as BigInt, not float', () => {
  // 3 drips fit exactly; the 4th does not. All values are past Number.MAX_SAFE_INTEGER, so a
  // Number-based comparison would compare equal here and let the 4th through.
  const at = 1;
  const state = normalizeState({
    drips: { 0: { amount: ENV.FAUCET_DRIP, at, status: 'done' } },
    totalDripped: (3n * BigInt(ENV.FAUCET_DRIP)).toString(),
    lastDripAt: at,
  });
  const r = checkEligibility(base({ state }));
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.code, 'cap_reached');

  const justUnder = normalizeState(Object.assign({}, state, { totalDripped: (2n * BigInt(ENV.FAUCET_DRIP)).toString() }));
  assert.strictEqual(checkEligibility(base({ state: justUnder })).ok, true);
});

test('the cooldown refuses and reports how long is left', () => {
  const state = normalizeState({ drips: {}, totalDripped: '0', lastDripAt: 999_500 });
  const r = checkEligibility(base({ state, now: 1_000_000 })); // 500ms elapsed, 1000ms cooldown
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.code, 'cooldown');
  assert.strictEqual(r.retryAfterMs, 500);
  assert.strictEqual(checkEligibility(base({ state, now: 1_000_500 })).ok, true);
});

test('a malformed ledger total refuses rather than defaulting to zero', () => {
  const r = checkEligibility(base({ state: { drips: {}, totalDripped: 'lots', lastDripAt: 0 } }));
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.code, 'bad_state');
});

// ── ledger ───────────────────────────────────────────────────────────────────────────────────

test('reserveDrip records the slot and advances the total BEFORE any transfer', () => {
  const st = reserveDrip(emptyState(), 3, ENV.FAUCET_DRIP, 5000);
  assert.strictEqual(st.drips['3'].status, 'pending');
  assert.strictEqual(st.drips['3'].amount, ENV.FAUCET_DRIP);
  assert.strictEqual(st.totalDripped, ENV.FAUCET_DRIP);
  assert.strictEqual(st.lastDripAt, 5000);
  // The reservation alone already blocks a second attempt, before the CLI has run.
  assert.strictEqual(checkEligibility(base({ state: st, now: 9_000_000 })).code, 'already_funded');
});

test('reserveDrip refuses to double-reserve a slot', () => {
  const st = reserveDrip(emptyState(), 3, ENV.FAUCET_DRIP, 5000);
  assert.throws(() => reserveDrip(st, 3, ENV.FAUCET_DRIP, 6000), /already has a drip record/);
});

test('reserveDrip refuses a non-positive or malformed amount', () => {
  assert.throws(() => reserveDrip(emptyState(), 3, '0', 1));
  assert.throws(() => reserveDrip(emptyState(), 3, '-1', 1));
  assert.throws(() => reserveDrip(emptyState(), 3, '1.5', 1));
});

test('settleDrip records the outcome but never releases the reservation', () => {
  let st = reserveDrip(emptyState(), 3, ENV.FAUCET_DRIP, 5000);
  st = settleDrip(st, 3, 'failed');
  assert.strictEqual(st.drips['3'].status, 'failed');
  assert.strictEqual(st.totalDripped, ENV.FAUCET_DRIP, 'a failure must not refund the cap');
  assert.strictEqual(checkEligibility(base({ state: st, now: 9_000_000 })).code, 'already_funded');
});

test('normalizeState accepts an absent ledger but THROWS on a corrupt one', () => {
  // ONLY `undefined` (no file) is "absent".
  assert.deepStrictEqual(normalizeState(undefined), emptyState());
  // A file containing the literal `null` parses fine and MUST NOT be read as an empty ledger:
  // that would wipe the once-per-slot records and re-open the faucet to everyone who drank.
  assert.throws(() => normalizeState(null), /corrupt/);
  for (const bad of [
    [],
    'x',
    { totalDripped: '0', lastDripAt: 0 },                                  // missing drips
    { drips: [], totalDripped: '0', lastDripAt: 0 },                        // drips not an object
    { drips: {}, totalDripped: -1, lastDripAt: 0 },                         // negative total
    { drips: {}, totalDripped: '0', lastDripAt: -1 },                       // bad timestamp
    { drips: { abc: { amount: '1' } }, totalDripped: '0', lastDripAt: 0 },  // key is not a slot
    { drips: { 1: { amount: 'x' } }, totalDripped: '0', lastDripAt: 0 },    // bad amount
    { drips: { 1: 5 }, totalDripped: '0', lastDripAt: 0 },                  // entry not an object
  ]) {
    assert.throws(() => normalizeState(bad), `corrupt ledger ${JSON.stringify(bad)} must throw`);
  }
});
