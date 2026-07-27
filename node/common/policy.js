'use strict';
// Pure decision functions consulted by loop branches (DESIGN.md §2.2/§3.6/§4.6).
// These are anti-griefing / liveness policy, NOT soundness controls — soundness is the CLI/WASM/
// on-chain gate. All functions are pure (state passed in, decision returned) so they unit-test
// without I/O.

const DEFAULTS = {
  maxInFlightPerChannel: 8,
  invalidScoreThreshold: 5,
  invalidScoreWindowMs: 60_000,
  maxCosignRetries: 3,
  cosignTimeoutMs: 600_000,
  amountCapWei: '100000000000000000000', // 100 ETH sanity cap (the default / token-0 cap)
  // Multi-token (detail2 §N): optional per-BASE-token caps, keyed by decimal token_index
  // string, e.g. { '0': '100000000000000000000', '55': '5000000000000000000000' }. A token
  // without an entry falls back to amountCapWei (so existing configs keep exactly their old
  // behavior).
  amountCapWeiByToken: {},
  staleCloseResponse: 'cancel', // 'cancel' (A30) | 'challenge' (A29)
};

function withDefaults(policy = {}) {
  return { ...DEFAULTS, ...policy };
}

// Amount sanity (NOT a balance check — the circuit proves solvency). Rejects absurd/overflow
// values. `tokenIndex` (optional, default 0) selects the per-token cap when the policy defines
// one (amountCapWeiByToken), else the global amountCapWei — so 2-arg callers keep exactly the
// pre-multi-token behavior.
function amountWithinCap(amountWei, policy, tokenIndex) {
  const p = withDefaults(policy);
  try {
    const key = tokenIndex === undefined || tokenIndex === null ? '0' : String(tokenIndex);
    const byToken = p.amountCapWeiByToken || {};
    const cap = Object.prototype.hasOwnProperty.call(byToken, key) ? byToken[key] : p.amountCapWei;
    return BigInt(amountWei) > 0n && BigInt(amountWei) <= BigInt(cap);
  } catch (e) {
    return false;
  }
}

// Per-sender invalid-request scoring with a sliding window. Returns the updated score record and
// whether the sender is now back-pressured (temporarily refused). Pure: caller persists the record.
function scoreInvalid(prev, now, policy) {
  const p = withDefaults(policy);
  let rec = prev && now - prev.windowStart < p.invalidScoreWindowMs
    ? { count: prev.count + 1, windowStart: prev.windowStart }
    : { count: 1, windowStart: now };
  return { rec, backPressured: rec.count >= p.invalidScoreThreshold };
}

function isBackPressured(rec, now, policy) {
  const p = withDefaults(policy);
  if (!rec) return false;
  if (now - rec.windowStart >= p.invalidScoreWindowMs) return false; // window expired
  return rec.count >= p.invalidScoreThreshold;
}

function inFlightOk(currentInFlight, policy) {
  const p = withDefaults(policy);
  return currentInFlight < p.maxInFlightPerChannel;
}

// Which lawful response to a stale on-chain close this operator prefers (DESIGN.md §3.7).
function staleCloseResponse(policy) {
  return withDefaults(policy).staleCloseResponse === 'challenge' ? 'challenge' : 'cancel';
}

// Lexicographic (epoch, state_version) ordering — mirrors the on-chain _isNewer gate. Returns
// 1 if a>b, -1 if a<b, 0 if equal. Used to classify a pending close as stale/newer/equal.
function compareVersion(a, b) {
  const ae = BigInt(a.epoch), be = BigInt(b.epoch);
  if (ae !== be) return ae > be ? 1 : -1;
  const av = BigInt(a.stateVersion), bv = BigInt(b.stateVersion);
  if (av !== bv) return av > bv ? 1 : -1;
  return 0;
}

module.exports = {
  DEFAULTS,
  withDefaults,
  amountWithinCap,
  scoreInvalid,
  isBackPressured,
  inFlightOk,
  staleCloseResponse,
  compareVersion,
};
