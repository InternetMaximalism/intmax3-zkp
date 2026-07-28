'use strict';
// In-channel $ITX testnet faucet — CONFIGURATION + ELIGIBILITY (pure, no I/O).
//
// ══════════════════════════════════════════════════════════════════════════════════════════════
// SECURITY CONTRACT (read before changing anything in this file)
//
//   The faucet hands out REAL escrowed value. Its supply is a single ERC-20 deposit that was made
//   on L1 and imported once, so it can never MINT — every dripped balance stays backed by
//   `channel_fund.amounts[t]` and remains claimable. The only realistic attack is DRAINING it,
//   and the only defence is this policy. Therefore:
//
//     * DISABLED IS THE DEFAULT. The faucet is live only when the operator sets FAUCET_ENABLED=1
//       AND supplies a faucet slot AND a NON-ZERO base token index. A missing / malformed knob
//       never "falls back to a default that is on" — it produces `enabled: false` plus a reason.
//     * NOTHING ABOUT THE PAYOUT COMES FROM THE REQUEST. The recipient slot is the only
//       caller-supplied value, and it is checked against the channel's own signed membership.
//       The amount, the token and every limit are server-side config.
//     * EVERY CHECK FAILS CLOSED. An unparseable limit, a corrupt state file, an unregistered
//       token: all of them refuse the drip rather than allowing it.
//     * ONE DRIP PER SLOT, FOR EVER. Idempotency is keyed on the recipient slot and is recorded
//       BEFORE the value moves (see `reserveDrip`), so a crash mid-transfer can only ever cost a
//       user their drip — never pay it twice.
//
//   Amounts are BASE UNITS as decimal strings and are compared as BigInt. Never Number: 1 ITX at
//   18 decimals is far past Number.MAX_SAFE_INTEGER, and a float comparison would silently
//   mis-order the cap.
// ══════════════════════════════════════════════════════════════════════════════════════════════

// Base token index 0 is native ETH by CONTRACT CONSTRUCTION (`IntmaxRollup.registerToken` reverts
// `TokenIndexZeroReservedForEth`). The faucet exists to hand out a test ERC-20, so index 0 is
// refused outright — it would mean dripping the channel's ETH backing.
const ETH_TOKEN_INDEX = 0;
const MAX_U32 = 0xffffffff;
// Same balance-slot ceiling as the protocol (`MAX_CHANNEL_MEMBERS`); the authoritative bound is
// the channel's own `member_count + delegate_count`, which the caller passes in. This is only a
// sanity ceiling on the configured faucet slot.
const MAX_SLOTS = 1024;

// Defaults, all overridable by env. Chosen for a demo testnet: enough to try a transfer, far too
// little to be worth farming, and a per-channel ceiling that bounds the total exposure of one
// deposit no matter how many joins arrive.
//
// SCALE NOTE: in-channel balances are u64 BASE UNITS (`ChannelFund.amounts`, the CLI's `<amount>`
// argument), so a channel position tops out at `u64::MAX / 10**decimals` whole tokens. $ITX uses
// 6 decimals precisely so that ceiling is ~18.4 TRILLION tokens rather than the ~18.44 that 18
// decimals would allow — these defaults sit many orders of magnitude inside it. `MAX_U64` is still
// enforced below so a mis-set env fails HERE rather than as an opaque CLI parse error mid-drip.
// The decimals themselves are read back from the token contract and compared against the manifest
// at relay/node startup (`node/common/token-registry.js`), so these numbers cannot silently come
// to mean something else.
const DEFAULT_DRIP = '100000000'; // 100 ITX (6 decimals)
const DEFAULT_CAP = '100000000000'; // 100,000 ITX per channel (= 1,000 drips)
const DEFAULT_COOLDOWN_MS = 5000; // one drip per channel per 5s (the CLI leg is far slower anyway)
const MAX_U64 = (1n << 64n) - 1n;

// ── HARD AMOUNT CEILINGS ─────────────────────────────────────────────────────────────────────
// DELIBERATELY NOT env-overridable. A ceiling an operator can raise from the environment is not a
// ceiling; crossing these requires a code change, and therefore review.
//
// `MAX_U64` is an EXPRESSIBILITY bound (a larger amount cannot be carried in the u64 transfer),
// NOT a policy bound: at 6 decimals it admits ~18.4 TRILLION ITX, so on its own a single mistyped
// digit — `FAUCET_DRIP=100000000000` instead of `100000000` — validates happily and hands out
// 100,000 ITX in ONE call. These constants are the policy bound that stops that.
//
// The genuinely correct bound would be the faucet member's live balance, but this module is pure
// (no I/O) by contract, so it enforces a static ceiling here; running past the real balance still
// fails closed at the CLI leg.
const MAX_DRIP = 1000000000n; // 1,000 ITX per claim — 10x the default
const MAX_CHANNEL_CAP = 10000000000000n; // 10,000,000 ITX per channel — 100x the default
// Invariant asserted in the tests: both ceilings sit strictly inside the u64 expressibility bound,
// so the checks below can never be reordered into a state where u64 is the only guard.

/** Strict decimal-string -> BigInt. Returns null for anything that is not a plain non-negative integer. */
function parseAmount(v) {
  if (typeof v === 'bigint') return v >= 0n ? v : null;
  const s = String(v === undefined || v === null ? '' : v).trim();
  if (!/^\d+$/.test(s)) return null;
  try { return BigInt(s); } catch (e) { return null; }
}

function parseIntStrict(v) {
  const s = String(v === undefined || v === null ? '' : v).trim();
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) ? n : null;
}

/**
 * Build the faucet configuration from an env-like object.
 *
 * Returns `{ enabled: false, reason }` for every misconfiguration — the caller serves 404 and
 * logs `reason`. Returns `{ enabled: true, faucetSlot, tokenIndex, dripAmount, channelCap,
 * cooldownMs }` only when the whole configuration is coherent.
 */
function faucetConfig(env) {
  const e = env || {};
  const off = (reason) => ({ enabled: false, reason });

  if (String(e.FAUCET_ENABLED || '') !== '1') return off('FAUCET_ENABLED is not 1');

  const faucetSlot = parseIntStrict(e.FAUCET_SLOT);
  if (faucetSlot === null || faucetSlot >= MAX_SLOTS) {
    return off('FAUCET_SLOT must be a balance slot index (integer, 0..1023) of a CLI-controlled co-signing member');
  }
  const tokenIndex = parseIntStrict(e.ITX_TOKEN_INDEX);
  if (tokenIndex === null || tokenIndex > MAX_U32) {
    return off('ITX_TOKEN_INDEX must be an integer in [0, 2^32-1]');
  }
  if (tokenIndex === ETH_TOKEN_INDEX) {
    return off('ITX_TOKEN_INDEX must not be 0 — index 0 is native ETH (the channel deposit backing), not a test token');
  }

  const dripAmount = parseAmount(e.FAUCET_DRIP === undefined ? DEFAULT_DRIP : e.FAUCET_DRIP);
  if (dripAmount === null || dripAmount <= 0n) return off('FAUCET_DRIP must be a positive integer in base units');
  // Policy ceiling FIRST: it is strictly tighter than u64, and it is the one that catches a
  // mistyped digit handing out orders of magnitude more than intended.
  if (dripAmount > MAX_DRIP) {
    return off(`FAUCET_DRIP exceeds the hard per-claim ceiling of ${MAX_DRIP} base units (raising it requires a code change)`);
  }
  // In-channel balances are u64 base units; a larger drip could not be expressed in the transfer.
  // Unreachable while MAX_DRIP <= MAX_U64 (asserted in the tests) — kept as defence in depth.
  if (dripAmount > MAX_U64) return off('FAUCET_DRIP exceeds the u64 in-channel base-unit ceiling');

  const channelCap = parseAmount(e.FAUCET_CHANNEL_CAP === undefined ? DEFAULT_CAP : e.FAUCET_CHANNEL_CAP);
  if (channelCap === null || channelCap <= 0n) return off('FAUCET_CHANNEL_CAP must be a positive integer in base units');
  if (channelCap > MAX_CHANNEL_CAP) {
    return off(`FAUCET_CHANNEL_CAP exceeds the hard per-channel ceiling of ${MAX_CHANNEL_CAP} base units (raising it requires a code change)`);
  }
  // Unreachable while MAX_CHANNEL_CAP <= MAX_U64 (asserted in the tests) — defence in depth.
  if (channelCap > MAX_U64) return off('FAUCET_CHANNEL_CAP exceeds the u64 in-channel base-unit ceiling');
  if (channelCap < dripAmount) return off('FAUCET_CHANNEL_CAP is smaller than one FAUCET_DRIP');

  const cooldownMs = e.FAUCET_COOLDOWN_MS === undefined ? DEFAULT_COOLDOWN_MS : parseIntStrict(e.FAUCET_COOLDOWN_MS);
  if (cooldownMs === null) return off('FAUCET_COOLDOWN_MS must be a non-negative integer (milliseconds)');

  return { enabled: true, faucetSlot, tokenIndex, dripAmount, channelCap, cooldownMs };
}

/** The persisted per-channel faucet ledger, empty. */
function emptyState() {
  return { drips: {}, totalDripped: '0', lastDripAt: 0 };
}

/**
 * Validate a ledger loaded from disk.
 *
 * THROWS on anything malformed. Fail-closed on purpose: a corrupt ledger that we "helpfully"
 * reset to empty would wipe the once-per-slot record and re-open the faucet to everyone who
 * already drank. An operator must look at it.
 *
 * SECURITY (the `null` case specifically): ONLY `undefined` means "no ledger yet". A file whose
 * contents are the literal `null` — a truncated/clobbered write, or an operator "clearing" it —
 * parses as valid JSON and would otherwise take the absent branch and hand back an EMPTY ledger,
 * silently re-opening the faucet to every slot that already drank. It is corruption, and it
 * throws. Callers pass `undefined` (never a parsed value) for a genuinely missing file.
 */
function normalizeState(raw) {
  if (raw === undefined) return emptyState();
  if (raw === null) throw new Error('faucet ledger: contents are null (corrupt); refusing to treat as an empty ledger');
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new Error('faucet ledger: root must be an object');
  const drips = raw.drips;
  if (drips === undefined) throw new Error('faucet ledger: missing drips');
  if (typeof drips !== 'object' || drips === null || Array.isArray(drips)) throw new Error('faucet ledger: drips must be an object');
  const total = parseAmount(raw.totalDripped);
  if (total === null) throw new Error('faucet ledger: totalDripped must be a decimal integer string');
  const lastDripAt = Number(raw.lastDripAt);
  if (!Number.isFinite(lastDripAt) || lastDripAt < 0) throw new Error('faucet ledger: lastDripAt must be a timestamp');
  const out = { drips: {}, totalDripped: total.toString(), lastDripAt };
  for (const [k, v] of Object.entries(drips)) {
    if (!/^\d+$/.test(k)) throw new Error(`faucet ledger: drip key "${k}" is not a slot index`);
    if (typeof v !== 'object' || v === null) throw new Error(`faucet ledger: drip ${k} must be an object`);
    if (parseAmount(v.amount) === null) throw new Error(`faucet ledger: drip ${k} has a malformed amount`);
    out.drips[k] = { amount: String(v.amount), at: Number(v.at) || 0, status: String(v.status || 'done') };
  }
  return out;
}

/**
 * Decide whether `slot` may receive a drip right now.
 *
 * @param {object} p
 * @param {object} p.config         from `faucetConfig`
 * @param {*}      p.slot           the RAW request value — validated here, never trusted
 * @param {number} p.activeSlots    `member_count + delegate_count` from the channel's SIGNED snapshot
 * @param {*}      p.localTokenSlot the ITX position resolved from the channel's SIGNED registry,
 *                                  or null/undefined when the token is not registered there
 * @param {object} p.state          the normalized ledger
 * @param {number} p.now            Date.now()
 * @returns {{ok: boolean, code: string, reason?: string, alreadyFunded?: boolean, retryAfterMs?: number}}
 */
function checkEligibility(p) {
  const { config, slot, activeSlots, localTokenSlot, state, now } = p || {};
  if (!config || !config.enabled) return { ok: false, code: 'disabled', reason: 'faucet is not enabled' };

  // The recipient slot is the ONLY caller-controlled input. It must be an integer (not a numeric
  // string, not a float, not an object) and it must name a slot the channel's own signed state
  // says is active.
  if (typeof slot !== 'number' || !Number.isInteger(slot) || slot < 0) {
    return { ok: false, code: 'bad_slot', reason: 'slot must be a non-negative integer' };
  }
  if (!Number.isInteger(activeSlots) || activeSlots <= 0 || slot >= activeSlots) {
    return { ok: false, code: 'bad_slot', reason: 'slot is not an active member/delegate of this channel' };
  }
  // Never let the faucet pay itself: that would be a no-op transfer at best and, if the CLI ever
  // accepted it, a way to churn the faucet position for free.
  if (slot === config.faucetSlot) {
    return { ok: false, code: 'bad_slot', reason: 'slot is the faucet member itself' };
  }
  if (!Number.isInteger(localTokenSlot) || localTokenSlot < 0) {
    return {
      ok: false,
      code: 'token_not_registered',
      reason: `base token index ${config.tokenIndex} has no position in this channel's signed registry`,
    };
  }

  const st = state || emptyState();
  const prior = st.drips ? st.drips[String(slot)] : undefined;
  if (prior) {
    // Idempotent, and deliberately terminal: a prior record — even one whose transfer FAILED —
    // consumes the slot's single drip. Re-running a failed drip is an operator action, not a
    // retry loop an anonymous caller can drive.
    return { ok: false, code: 'already_funded', alreadyFunded: true, reason: 'this slot already received its drip' };
  }

  const total = parseAmount(st.totalDripped);
  if (total === null) return { ok: false, code: 'bad_state', reason: 'faucet ledger total is malformed' };
  if (total + config.dripAmount > config.channelCap) {
    return { ok: false, code: 'cap_reached', reason: 'this channel has dispensed its faucet allowance' };
  }

  const last = Number(st.lastDripAt) || 0;
  const elapsed = (Number.isFinite(now) ? now : Date.now()) - last;
  if (elapsed < config.cooldownMs) {
    return { ok: false, code: 'cooldown', reason: 'faucet is cooling down', retryAfterMs: config.cooldownMs - elapsed };
  }

  return { ok: true, code: 'ok' };
}

/**
 * Record `slot`'s drip in the ledger BEFORE the value moves.
 *
 * Reserve-then-transfer is the fail-closed ordering: if the process dies between the reservation
 * and the co-signed transfer, the slot is marked and no second drip can be issued. The reverse
 * ordering (transfer, then record) loses the record on exactly the same crash and pays twice.
 * Returns a NEW state object; the caller persists it and only then runs the CLI.
 */
function reserveDrip(state, slot, amount, now) {
  const st = normalizeState(state);
  const amt = parseAmount(amount);
  if (amt === null || amt <= 0n) throw new Error('reserveDrip: amount must be a positive integer in base units');
  const key = String(slot);
  if (st.drips[key]) throw new Error(`reserveDrip: slot ${key} already has a drip record`);
  st.drips[key] = { amount: amt.toString(), at: now, status: 'pending' };
  st.totalDripped = (parseAmount(st.totalDripped) + amt).toString();
  st.lastDripAt = now;
  return st;
}

/** Mark a reserved drip's outcome. Never releases the reservation (see `reserveDrip`). */
function settleDrip(state, slot, status) {
  const st = normalizeState(state);
  const key = String(slot);
  if (st.drips[key]) st.drips[key].status = status === 'done' ? 'done' : 'failed';
  return st;
}

/** Public, non-sensitive view for `GET /api/faucet` (never leaks slot-level history). */
function publicInfo(config) {
  if (!config || !config.enabled) return { enabled: false };
  return {
    enabled: true,
    tokenIndex: config.tokenIndex,
    amount: config.dripAmount.toString(),
    cooldownMs: config.cooldownMs,
  };
}

module.exports = {
  faucetConfig,
  checkEligibility,
  emptyState,
  normalizeState,
  reserveDrip,
  settleDrip,
  publicInfo,
  parseAmount,
  ETH_TOKEN_INDEX,
  DEFAULT_DRIP,
  DEFAULT_CAP,
  DEFAULT_COOLDOWN_MS,
  MAX_DRIP,
  MAX_CHANNEL_CAP,
  MAX_U64,
  MAX_U64,
};
