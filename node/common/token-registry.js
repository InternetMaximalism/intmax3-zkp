'use strict';
// Token DISPLAY metadata registry (multi-token channels, detail2 §N-1/§N-7, threat model TM-10b).
//
// ══════════════════════════════════════════════════════════════════════════════════════════════
// SECURITY CONTRACT (non-negotiable — read before changing anything in this file)
//
//   Token display metadata (symbol / name / decimals) carries ZERO authority.
//
//   The AUTHORITATIVE token identity is the BASE `token_index`:
//     * proof-bound in the circuits (the channel's H1-signed `token_registry`, §N-1/TM-9), and
//     * set-once on-chain in `IntmaxRollup.tokenAddressOf(uint32)` (§N-7/TM-10b).
//
//   A wrong or attacker-supplied symbol must NEVER be shown as if trusted: labelling a worthless
//   token "USDC" is a user-funds attack, not a cosmetic bug. Therefore this module serves
//   metadata ONLY for entries whose manifest address has been VERIFIED equal to the on-chain
//   `tokenAddressOf(tokenIndex)`. Unverified / unknown / contradicted entries are served with
//   NULL metadata so the UI falls back to the raw base index.
//
//   Consequence for every caller: `metadataFor()` is the ONLY way to expose symbol/name/decimals.
//   Never read `entry.symbol` directly for a response body.
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// The manifest (`tokens.json`) is a per-DEPLOYMENT operator artifact that ships alongside
// `channel_backing.json`. It is treated as UNTRUSTED-ISH input (an operator file whose strings end
// up rendered in a browser): validation is fail-closed and rejects the WHOLE FILE on any
// structural violation, never "skips the bad entry" (a partially-accepted file is exactly how a
// mislabelled token slips through).

const fs = require('fs');
const path = require('path');

// ── manifest limits (all fail-closed) ────────────────────────────────────────────────────────
const MAX_TOKENS = 64; // generous vs MAX_CHANNEL_TOKENS = 10; a per-deployment file, not per-channel
const MAX_U32 = 0xffffffff;
const MAX_DECIMALS = 36;
const SYMBOL_MAX = 16;
const NAME_MAX = 64;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

// ALLOWLIST, not a denylist: printable ASCII, no control characters, no whitespace-only, no
// leading/trailing space, and none of < > & " ' ` \ / (HTML/JS-injection and homoglyph/RTL
// spoofing vectors — these strings are rendered in the wallet UI).
const SYMBOL_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,15}$/;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._+()-]{0,63}$/;
const HEX20_RE = /^0x[0-9a-fA-F]{40}$/;

const ENTRY_KEYS = new Set(['tokenIndex', 'symbol', 'name', 'decimals', 'address', 'native']);
const ROOT_KEYS = new Set(['chainId', 'rollup', 'tokens']);

// SECURITY: base token index 0 is native ETH by CONTRACT CONSTRUCTION, not by convention —
// `IntmaxRollup.registerToken` reverts `TokenIndexZeroReservedForEth` for index 0 and
// `withdrawNative` is gated on `tokenIndex == 0`. So index 0 needs (and admits) no registry read.
const ETH_TOKEN_INDEX = 0;
// ETH's decimals are fixed by the protocol, so the native entry cannot claim anything else — see
// the pin in `validateManifest` (there is no contract at index 0 to verify it against).
const ETH_DECIMALS = 18;

// The ONLY authoritative getter. Kept as an ethers-style human-readable fragment mirroring
// `chain-watcher.js`'s `MANAGER_GETTER_ABI` discipline (a fragment that disagrees with the
// contract silently decodes garbage), plus the raw 4-byte selector for the dependency-free
// `eth_call` reader used by the relay (which has no ethers on the deployed box).
// INVARIANT: `TOKEN_ADDRESS_OF_SELECTOR === ethers.id(TOKEN_ADDRESS_OF_SIG).slice(0, 10)` —
// asserted in node/test/token-registry.test.js so the two readers can never drift.
const TOKEN_ADDRESS_OF_SIG = 'tokenAddressOf(uint32)';
const TOKEN_ADDRESS_OF_SELECTOR = '0x4b55982f';
const ROLLUP_TOKEN_GETTER_ABI = ['function tokenAddressOf(uint32) view returns (address)'];

// `decimals()` on the TOKEN itself (not the rollup).
//
// SECURITY: verifying the ADDRESS does not constrain `decimals` at all, yet a wrong `decimals`
// misrenders a balance by orders of magnitude — the exact user-funds failure this whole module
// exists to prevent. So the manifest's claimed `decimals` is read back from the token contract and
// held to the same standard as the address: a CONTRADICTION is fatal, ABSENCE of information only
// degrades to `decimals: null` (the wallet then shows raw base units, never a guessed 18).
// Same drift guard as above: the raw selector is pinned against the ethers fragment in
// node/test/token-registry.test.js.
const DECIMALS_SIG = 'decimals()';
const DECIMALS_SELECTOR = '0x313ce567';
const ERC20_DECIMALS_ABI = ['function decimals() view returns (uint8)'];

/** Structural / fail-closed manifest rejection. The FILE is rejected, never a single entry. */
class TokenManifestError extends Error {
  constructor(msg) { super(msg); this.name = 'TokenManifestError'; }
}

/**
 * The manifest contradicts a LIVE deployment (address mismatch, wrong rollup, wrong chain).
 * This is the mislabelling hazard itself: the operator's file is wrong about a deployment that
 * already holds funds. Callers must refuse to start.
 */
class TokenChainMismatchError extends Error {
  constructor(msg, detail) { super(msg); this.name = 'TokenChainMismatchError'; this.detail = detail || {}; }
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (v) => typeof v === 'number' && Number.isInteger(v);
const lc = (a) => String(a).toLowerCase();

/**
 * Validate + normalize a parsed manifest object. Throws TokenManifestError on ANY violation.
 * Returns `{ chainId, rollup, entries }` with `entries` normalized and frozen-shaped.
 */
function validateManifest(raw, source) {
  const where = source ? ` (${source})` : '';
  const bad = (m) => { throw new TokenManifestError(`invalid tokens manifest${where}: ${m}`); };

  if (!isPlainObject(raw)) bad('root must be a JSON object');
  for (const k of Object.keys(raw)) if (!ROOT_KEYS.has(k)) bad(`unknown root key "${k}"`);

  if (!isInt(raw.chainId) || raw.chainId <= 0) bad('chainId must be a positive integer');
  if (typeof raw.rollup !== 'string' || !HEX20_RE.test(raw.rollup)) {
    bad('rollup must be a 20-byte hex address (the deployment this manifest describes)');
  }
  if (lc(raw.rollup) === ZERO_ADDRESS) bad('rollup must not be the zero address');
  if (!Array.isArray(raw.tokens)) bad('tokens must be an array');
  if (raw.tokens.length === 0) bad('tokens must not be empty');
  if (raw.tokens.length > MAX_TOKENS) bad(`tokens length ${raw.tokens.length} exceeds ${MAX_TOKENS}`);

  const entries = [];
  const seenIndex = new Set();
  const seenSymbol = new Set();
  const seenAddress = new Set();
  let nativeCount = 0;

  raw.tokens.forEach((t, i) => {
    const at = (m) => bad(`tokens[${i}]: ${m}`);
    if (!isPlainObject(t)) at('must be an object');
    for (const k of Object.keys(t)) if (!ENTRY_KEYS.has(k)) at(`unknown key "${k}"`);

    // -- tokenIndex: u32, unique. This is the ONLY field with authority.
    if (!isInt(t.tokenIndex) || t.tokenIndex < 0 || t.tokenIndex > MAX_U32) {
      at('tokenIndex must be an integer in [0, 2^32-1]');
    }
    if (seenIndex.has(t.tokenIndex)) at(`duplicate tokenIndex ${t.tokenIndex}`);
    seenIndex.add(t.tokenIndex);

    // -- native: at most one, and it is exactly tokenIndex 0 with address null. Both directions
    //    are enforced: index 0 MUST be native (never an ERC-20 label on the ETH index), and a
    //    native entry MUST be index 0 (mirrors the contract's ETH_TOKEN_INDEX reservation).
    if (t.native !== undefined && typeof t.native !== 'boolean') at('native must be a boolean when present');
    const native = t.native === true;
    if (native) {
      nativeCount += 1;
      if (nativeCount > 1) at('more than one entry has native: true (exactly one is allowed)');
      if (t.tokenIndex !== ETH_TOKEN_INDEX) at(`native entry must be tokenIndex ${ETH_TOKEN_INDEX}`);
      if (t.address !== null && t.address !== undefined) at('native entry must have address: null');
      // SECURITY: the native entry is marked `decimalsVerified` WITHOUT a chain read (there is no
      // contract at index 0 to ask), so its decimals must be pinned here or it would be served as
      // verified on the operator's word alone — the one metadata field this file is not allowed to
      // take on trust. ETH is 18 by protocol, not by declaration.
      if (t.decimals !== ETH_DECIMALS) at(`native entry must declare decimals: ${ETH_DECIMALS}`);
    } else if (t.tokenIndex === ETH_TOKEN_INDEX) {
      at('tokenIndex 0 is native ETH on-chain and MUST be declared native: true with address: null');
    }

    // -- address: non-native requires a 20-byte hex address. Checksummed-or-lowercase accepted;
    //    comparisons are always lowercased (case carries no authority). The ZERO address is
    //    rejected: `tokenAddressOf` returns zero for an UNREGISTERED index, so a zero manifest
    //    address would spuriously "match" an unregistered index and be served as verified.
    let address = null;
    if (!native) {
      if (typeof t.address !== 'string' || !HEX20_RE.test(t.address)) {
        at('non-native entry needs a 20-byte hex address (checksummed or lowercase)');
      }
      if (lc(t.address) === ZERO_ADDRESS) at('address must not be the zero address');
      address = lc(t.address);
      if (seenAddress.has(address)) at(`duplicate address ${address}`);
      seenAddress.add(address);
    }

    // -- decimals: display-only, but a wrong value misrenders an amount by orders of magnitude.
    if (!isInt(t.decimals) || t.decimals < 0 || t.decimals > MAX_DECIMALS) {
      at(`decimals must be an integer in [0, ${MAX_DECIMALS}]`);
    }

    // -- symbol / name: strict allowlist (see SYMBOL_RE / NAME_RE above).
    if (typeof t.symbol !== 'string' || !SYMBOL_RE.test(t.symbol)) {
      at(`symbol must be 1..${SYMBOL_MAX} printable ASCII chars from [A-Za-z0-9._+-] starting alphanumeric`);
    }
    if (typeof t.name !== 'string' || !NAME_RE.test(t.name) || t.name !== t.name.trim()) {
      at(`name must be 1..${NAME_MAX} printable ASCII chars from [A-Za-z0-9 ._+()-], no leading/trailing space`);
    }
    // Two entries claiming the same symbol is a spoof surface ("USDC" vs "USDC"): reject the file.
    const sym = t.symbol.toLowerCase();
    if (seenSymbol.has(sym)) at(`duplicate symbol "${t.symbol}"`);
    seenSymbol.add(sym);

    entries.push({
      tokenIndex: t.tokenIndex,
      symbol: t.symbol,
      name: t.name,
      decimals: t.decimals,
      address,
      native,
      // Verification state — NOT from the file. `verified` starts false and only
      // `verifyAgainstChain` / `observeTokenRegistered` may set it true.
      verified: false,
      onChainAddress: null,
      verifyNote: 'not yet verified against chain',
      // Decimals verification is SEPARATE from address verification: the address read-back says
      // nothing about `decimals`, and a token may not implement `decimals()` at all. Only
      // `verifyAgainstChain` may set this true; a merely address-verified entry keeps
      // `decimals: null`, which the wallet renders as raw base units.
      decimalsVerified: false,
      onChainDecimals: null,
    });
  });

  return { chainId: raw.chainId, rollup: lc(raw.rollup), entries };
}

/** Read + parse + validate a manifest file. Throws TokenManifestError on anything malformed. */
function loadManifest(filePath) {
  let text;
  try { text = fs.readFileSync(filePath, 'utf8'); }
  catch (e) { throw new TokenManifestError(`cannot read tokens manifest ${filePath}: ${e.message}`); }
  let raw;
  try { raw = JSON.parse(text); }
  catch (e) { throw new TokenManifestError(`tokens manifest ${filePath} is not valid JSON: ${e.message}`); }
  return validateManifest(raw, filePath);
}

// ── chain reader (dependency-free) ───────────────────────────────────────────────────────────
// Raw `eth_call` over JSON-RPC via global fetch, so this module works unchanged in the api
// service and on the deployed relay box (which has express only — no ethers). The node passes its
// ethers-backed `ChainWatcher.getTokenAddress` reader instead; a unit test pins the selector
// against ethers so the two paths cannot drift.
async function rpcCall(rpcUrl, method, params) {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`${method}: HTTP ${res.status}`);
  const j = await res.json();
  if (j && j.error) throw new Error(`${method}: ${j.error.message || JSON.stringify(j.error)}`);
  if (!j || typeof j.result !== 'string') throw new Error(`${method}: malformed JSON-RPC result`);
  return j.result;
}

/** Encode `tokenAddressOf(uint32)` calldata; uint32 is right-aligned in a 32-byte word. */
function encodeTokenAddressOf(tokenIndex) {
  if (!isInt(tokenIndex) || tokenIndex < 0 || tokenIndex > MAX_U32) throw new Error('tokenIndex out of u32 range');
  return TOKEN_ADDRESS_OF_SELECTOR + tokenIndex.toString(16).padStart(64, '0');
}

/** Decode a 32-byte ABI word into a lowercase address; rejects a short/garbage return. */
function decodeAddressWord(hex) {
  const h = String(hex || '').replace(/^0x/, '');
  if (h.length !== 64) throw new Error(`tokenAddressOf: expected a 32-byte return, got ${h.length / 2} bytes`);
  if (!/^0{24}[0-9a-fA-F]{40}$/.test(h)) throw new Error('tokenAddressOf: return word is not a clean address');
  return '0x' + h.slice(24).toLowerCase();
}

function makeRpcReader(rpcUrl, rollupAddress) {
  return async (tokenIndex) => {
    const out = await rpcCall(rpcUrl, 'eth_call', [{ to: rollupAddress, data: encodeTokenAddressOf(tokenIndex) }, 'latest']);
    return decodeAddressWord(out);
  };
}

/**
 * Decode a `decimals()` return.
 *
 * Returns an integer in [0, 255] for a well-formed uint8-in-a-word, or NULL for anything else:
 * an empty return (the token has no `decimals()` and the call fell through), a short/odd-length
 * return, or a value that cannot be a uint8. NULL means "no information", which the caller turns
 * into `decimals: null` — it must NEVER be turned into a guess. A value out of uint8 range is
 * also NULL rather than a contradiction: it means the thing we called is not an ERC-20 `decimals`,
 * not that the operator lied.
 */
function decodeDecimalsWord(hex) {
  const h = String(hex || '').replace(/^0x/, '');
  if (h.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(h)) return null;
  let v;
  try { v = BigInt('0x' + h); } catch (e) { return null; }
  if (v > 255n) return null;
  return Number(v);
}

function makeDecimalsReader(rpcUrl) {
  return async (tokenAddress) => {
    const out = await rpcCall(rpcUrl, 'eth_call', [{ to: tokenAddress, data: DECIMALS_SELECTOR }, 'latest']);
    return decodeDecimalsWord(out);
  };
}

const noopLog = { info() {}, warn() {}, error() {} };

/**
 * Holds one deployment's token metadata and its verification state.
 *
 * SECURITY: instances are the single source of truth for "may this metadata be shown". Nothing
 * outside this class may set `verified`.
 */
class TokenRegistry {
  constructor(manifest, source) {
    this.chainId = manifest.chainId;
    this.rollup = manifest.rollup; // lowercase; pins WHICH deployment this manifest describes
    this.source = source || null;
    this._byIndex = new Map();
    for (const e of manifest.entries) this._byIndex.set(e.tokenIndex, e);
    this.verifiedAt = null;
  }

  static fromFile(filePath) {
    return new TokenRegistry(loadManifest(filePath), filePath);
  }

  entries() { return [...this._byIndex.values()]; }
  byIndex(tokenIndex) { return this._byIndex.get(tokenIndex) || null; }

  /**
   * THE ONLY sanctioned way to expose token metadata in a response body.
   *
   * SECURITY: `symbol`/`name` are non-null ONLY when `verified === true` (the manifest address was
   * read back equal from the on-chain set-once registry). `address` may be non-null while
   * unverified — reporting what the manifest/chain said is fine; asserting a NAME for it is not.
   * `native` is true only for base index 0 (contract-reserved ETH).
   *
   * `decimals` carries its OWN gate (`decimalsVerified`) on top of that: the address read-back
   * says nothing about the decimal place, and a wrong one misrenders a balance by orders of
   * magnitude. So an entry whose token has no readable `decimals()` is served with a symbol but
   * `decimals: null`; consumers must then show raw base units. (The wallet's `sanitizeTokenMeta`
   * already treats a null/malformed `decimals` as "not verified" and falls back to the raw base
   * index — so this degrades safely with no client change.)
   */
  metadataFor(tokenIndex) {
    const e = this._byIndex.get(tokenIndex);
    const native = tokenIndex === ETH_TOKEN_INDEX;
    if (!e || !e.verified) {
      return {
        symbol: null,
        name: null,
        decimals: null,
        address: e ? (e.onChainAddress || e.address) : null,
        native,
        verified: false,
      };
    }
    return {
      symbol: e.symbol,
      name: e.name,
      decimals: e.decimalsVerified ? e.decimals : null,
      address: e.address,
      native,
      verified: true,
    };
  }

  /** Fail-safe kill switch: drop every entry back to unverified (metadata stops being served). */
  markAllUnverified(reason) {
    for (const e of this._byIndex.values()) {
      e.verified = false;
      e.decimalsVerified = false;
      e.verifyNote = reason || 'unverified';
    }
    this.verifiedAt = null;
  }

  /**
   * Verify every non-native entry against `IntmaxRollup.tokenAddressOf(tokenIndex)`.
   *
   * POLICY (fail-closed where a contradiction exists, tolerant where information is merely absent):
   *   manifest rollup !== the rollup we are verifying against  → THROW  (wrong deployment)
   *   manifest chainId !== eth_chainId                          → THROW  (wrong network)
   *   on-chain address === manifest address                     → verified: true
   *   on-chain address !== manifest address (both non-zero)     → THROW  (mislabelling hazard)
   *   on-chain address === 0 (index not registered yet)         → verified: false + warn
   *   read failed (RPC down / bad response)                     → verified: false + warn
   *
   * DECIMALS (only reached once the address verified — same contradiction/absence split):
   *   token decimals() === manifest decimals                    → decimalsVerified: true
   *   token decimals() !== manifest decimals                    → THROW  (a 10^k misrender is the
   *                                                                       very hazard this gates)
   *   decimals() reverts / absent / not a uint8                 → decimalsVerified: false + warn
   *                                                               (served as null, NEVER guessed)
   *   read failed (RPC down)                                    → decimalsVerified: false + warn
   *   native index 0                                            → exempt (no contract to read)
   *
   * @param {string} rpcUrl
   * @param {string} rollupAddress  the rollup this node/relay actually talks to
   * @param {{ logger?: object, readTokenAddress?: (i:number)=>Promise<string>, readDecimals?: (a:string)=>Promise<number|null>, readChainId?: ()=>Promise<number> }} [opts]
   */
  async verifyAgainstChain(rpcUrl, rollupAddress, opts) {
    const o = opts || {};
    const log = o.logger || noopLog;

    // (1) Deployment pin — a pure local comparison, so a mismatch is unconditional.
    if (!rollupAddress || !HEX20_RE.test(String(rollupAddress))) {
      throw new TokenChainMismatchError('token manifest verification needs a rollup address', { rollupAddress });
    }
    if (lc(rollupAddress) !== this.rollup) {
      throw new TokenChainMismatchError(
        `tokens manifest describes rollup ${this.rollup} but this node talks to ${lc(rollupAddress)}`,
        { manifestRollup: this.rollup, actual: lc(rollupAddress), source: this.source }
      );
    }

    // (2) Network pin. A READ FAILURE here is "information absent" (warn, stay unverified); a
    //     successful read that DISAGREES is a contradiction (throw).
    const readChainId = o.readChainId || (async () => parseInt(await rpcCall(rpcUrl, 'eth_chainId', []), 16));
    try {
      const onChainId = await readChainId();
      if (Number.isFinite(onChainId) && onChainId !== this.chainId) {
        throw new TokenChainMismatchError(
          `tokens manifest chainId ${this.chainId} != node chain ${onChainId}`,
          { manifestChainId: this.chainId, actual: onChainId, source: this.source }
        );
      }
    } catch (e) {
      if (e instanceof TokenChainMismatchError) throw e;
      log.warn({ event: 'TOKEN_CHAINID_READ_FAILED', error: String((e && e.message) || e), note: 'metadata stays unverified' });
      this.markAllUnverified('chainId read failed');
      return this.summary();
    }

    // (3) Per-entry set-once registry read.
    const read = o.readTokenAddress || makeRpcReader(rpcUrl, rollupAddress);
    const readDecimals = o.readDecimals || makeDecimalsReader(rpcUrl);
    for (const e of this._byIndex.values()) {
      if (e.native) {
        // Index 0 is native ETH by contract construction (registerToken rejects it) — nothing to
        // read, and nothing an operator file could contradict. There is likewise no contract to
        // ask for `decimals()`; ETH's 18 is protocol-fixed, not an operator claim.
        e.verified = true;
        e.decimalsVerified = true;
        e.onChainAddress = null;
        e.onChainDecimals = e.decimals;
        e.verifyNote = 'native ETH (base token index 0, contract-reserved)';
        continue;
      }
      let onChain;
      try {
        onChain = await read(e.tokenIndex);
      } catch (err) {
        e.verified = false;
        e.decimalsVerified = false;
        e.onChainAddress = null;
        e.verifyNote = `read failed: ${String((err && err.message) || err)}`;
        log.warn({ event: 'TOKEN_VERIFY_READ_FAILED', tokenIndex: e.tokenIndex, error: e.verifyNote, note: 'served without metadata' });
        continue;
      }
      onChain = lc(onChain);
      if (onChain === ZERO_ADDRESS) {
        e.verified = false;
        e.decimalsVerified = false;
        e.onChainAddress = null;
        e.verifyNote = 'tokenIndex not registered on-chain yet';
        log.warn({ event: 'TOKEN_UNREGISTERED', tokenIndex: e.tokenIndex, manifestAddress: e.address, note: 'served without metadata until registerToken lands' });
        continue;
      }
      if (onChain !== e.address) {
        throw new TokenChainMismatchError(
          `tokens manifest says token ${e.tokenIndex} is ${e.address} but the rollup's set-once registry says ${onChain}`,
          { tokenIndex: e.tokenIndex, manifestAddress: e.address, onChainAddress: onChain, source: this.source }
        );
      }
      e.verified = true;
      e.onChainAddress = onChain;
      e.verifyNote = 'address read back equal from tokenAddressOf';

      // (4) DECIMALS read-back against the TOKEN. Verifying the address constrains nothing about
      // the decimal place, and a wrong one misrenders a balance by 10^k — the same class of
      // user-funds attack as a wrong symbol. A CONTRADICTION is therefore fatal, exactly like an
      // address mismatch; ABSENCE (no `decimals()`, revert, RPC down, non-uint8 return) keeps the
      // address verification but serves `decimals: null`. We never invent 18.
      let onChainDecimals;
      try {
        onChainDecimals = await readDecimals(e.address);
      } catch (err) {
        e.decimalsVerified = false;
        e.onChainDecimals = null;
        e.verifyNote = `address verified; decimals() read failed: ${String((err && err.message) || err)}`;
        log.warn({ event: 'TOKEN_DECIMALS_READ_FAILED', tokenIndex: e.tokenIndex, address: e.address, error: String((err && err.message) || err), note: 'decimals served as null (raw base units)' });
        continue;
      }
      if (onChainDecimals === null || onChainDecimals === undefined) {
        e.decimalsVerified = false;
        e.onChainDecimals = null;
        e.verifyNote = 'address verified; token exposes no readable decimals()';
        log.warn({ event: 'TOKEN_DECIMALS_ABSENT', tokenIndex: e.tokenIndex, address: e.address, manifestDecimals: e.decimals, note: 'decimals served as null (raw base units) — never guessed' });
        continue;
      }
      if (onChainDecimals !== e.decimals) {
        throw new TokenChainMismatchError(
          `tokens manifest says token ${e.tokenIndex} (${e.address}) has ${e.decimals} decimals but the token reports ${onChainDecimals}`,
          { tokenIndex: e.tokenIndex, address: e.address, manifestDecimals: e.decimals, onChainDecimals, source: this.source }
        );
      }
      e.decimalsVerified = true;
      e.onChainDecimals = onChainDecimals;
      e.verifyNote = 'address and decimals read back equal from chain';
    }
    this.verifiedAt = Date.now();
    return this.summary();
  }

  /**
   * Consume an observed `TokenRegistered(uint32 indexed tokenIndex, address indexed token)`.
   *
   * OBSERVATIONAL ONLY — never a write path, never adds entries, never throws (it runs inside the
   * chain-event dispatch, where a throw would wedge the watcher cursor).
   *
   *   different rollup                    → ignored (each channel has its OWN IntmaxRollup here)
   *   matches an unverified manifest entry → promoted to verified (the registration we waited for)
   *   contradicts a VERIFIED entry         → log.error + DOWNGRADE to unverified. A verified entry
   *       contradicted by a live event means either a set-once violation on-chain or that we are
   *       watching the wrong rollup; either way we must stop serving that label immediately.
   *   contradicts an unverified entry      → log.error, stays unverified
   *   unknown index                        → info, ignored
   */
  observeTokenRegistered(ev, opts) {
    const log = (opts && opts.logger) || noopLog;
    const tokenIndex = Number(ev && ev.tokenIndex);
    const token = ev && ev.token ? lc(ev.token) : null;
    const from = ev && ev.rollupAddress ? lc(ev.rollupAddress) : null;
    if (!Number.isInteger(tokenIndex) || !token || !HEX20_RE.test(token)) {
      log.warn({ event: 'TOKEN_REGISTERED_MALFORMED', tokenIndex: ev && ev.tokenIndex, token: ev && ev.token });
      return 'ignored';
    }
    if (from && from !== this.rollup) {
      log.info({ event: 'TOKEN_REGISTERED_OTHER_ROLLUP', rollup: from, manifestRollup: this.rollup, tokenIndex });
      return 'ignored';
    }
    const e = this._byIndex.get(tokenIndex);
    if (!e) {
      log.info({ event: 'TOKEN_REGISTERED_UNKNOWN_INDEX', tokenIndex, token, note: 'no manifest entry; served without metadata' });
      return 'unknown';
    }
    if (e.native) {
      // The contract cannot emit this for index 0; if it did, our world model is wrong.
      log.error({ event: 'TOKEN_REGISTRY_CONTRADICTION', tokenIndex, token, reason: 'TokenRegistered for the native ETH index' });
      e.verified = false;
      e.decimalsVerified = false;
      e.verifyNote = 'contradicted: TokenRegistered emitted for the native index';
      return 'contradiction';
    }
    if (token !== e.address) {
      log.error({
        event: 'TOKEN_REGISTRY_CONTRADICTION',
        tokenIndex,
        manifestAddress: e.address,
        observedAddress: token,
        wasVerified: e.verified,
        note: 'set-once violation or wrong rollup — metadata for this index is now withheld',
      });
      e.verified = false;
      e.decimalsVerified = false;
      e.onChainAddress = token;
      e.verifyNote = `contradicted by TokenRegistered(${token})`;
      return 'contradiction';
    }
    if (!e.verified) {
      // Address confirmed by the event. `decimalsVerified` deliberately stays FALSE: this path is
      // observational and cannot make an RPC call, so the decimal place is still unattested and
      // must be served as null until a `verifyAgainstChain` pass reads it back.
      e.verified = true;
      e.onChainAddress = token;
      e.verifyNote = 'address confirmed by observed TokenRegistered (decimals still unverified)';
      log.info({ event: 'TOKEN_REGISTERED_CONFIRMED', tokenIndex, token, note: 'decimals remain unverified until the next chain verification' });
      return 'confirmed';
    }
    return 'match';
  }

  /** Compact operator view (safe to log — no secrets, and it states WHAT is trusted and why). */
  summary() {
    return {
      source: this.source,
      chainId: this.chainId,
      rollup: this.rollup,
      tokens: this.entries().map((e) => ({
        tokenIndex: e.tokenIndex,
        symbol: e.symbol,
        address: e.address,
        native: e.native,
        verified: e.verified,
        decimals: e.decimals,
        decimalsVerified: e.decimalsVerified,
        note: e.verifyNote,
      })),
    };
  }
}

/**
 * Resolve a manifest path from a config value / env var, relative to `baseDir` when relative.
 * Returns null when nothing is configured (metadata is then simply absent — a valid state).
 */
function resolveManifestPath(configured, baseDir) {
  if (!configured) return null;
  return path.isAbsolute(configured) ? configured : path.resolve(baseDir || process.cwd(), configured);
}

/**
 * Node startup path (co-signer + delegate): load the configured manifest and verify it against
 * the chain BEFORE the program starts serving.
 *
 * Config surface: `cfg.tokensManifest` (path, relative to `baseDir`) or `cfg.tokens` (the same
 * manifest object inline). `TOKENS_MANIFEST` in the env overrides both. Nothing configured is a
 * VALID state — the node simply holds no display metadata (raw base indices everywhere).
 *
 * THROWS (caller must refuse to start) on: a structurally invalid manifest, a manifest whose
 * `rollup` is not one this node talks to, a chainId disagreement, or an address that contradicts
 * the on-chain set-once registry. Absent information (unregistered index, RPC down) only warns.
 */
async function bootstrapTokenRegistry(cfg, opts) {
  const o = opts || {};
  const log = o.logger || noopLog;
  const channels = o.channels || [];

  const configuredPath = process.env.TOKENS_MANIFEST || (cfg && cfg.tokensManifest) || null;
  let registry = null;
  if (configuredPath) {
    const p = resolveManifestPath(configuredPath, o.baseDir);
    registry = TokenRegistry.fromFile(p);
  } else if (cfg && cfg.tokens) {
    registry = new TokenRegistry(validateManifest(cfg.tokens, 'config.tokens'), 'config.tokens');
  } else {
    log.info({ event: 'TOKEN_MANIFEST_ABSENT', note: 'no tokensManifest/tokens configured; token metadata is served as null (raw base indices)' });
    return null;
  }

  // The manifest pins ONE deployment. Refuse to hold a manifest for a rollup this node does not
  // talk to (each channel here has its own IntmaxRollup, so a stale file is a live hazard).
  const known = channels.map((c) => (c && c.rollup ? lc(c.rollup) : null)).filter(Boolean);
  if (known.length && !known.includes(registry.rollup)) {
    throw new TokenChainMismatchError(
      `tokens manifest describes rollup ${registry.rollup}, which none of this node's channels use`,
      { manifestRollup: registry.rollup, configuredRollups: known, source: registry.source }
    );
  }
  for (const c of channels) {
    if (c && c.rollup && lc(c.rollup) !== registry.rollup) {
      log.warn({ event: 'TOKEN_MANIFEST_NOT_COVERING_CHANNEL', channel: c.id, rollup: lc(c.rollup), manifestRollup: registry.rollup, note: 'that channel serves raw base indices' });
    }
  }

  const readTokenAddress = o.readTokenAddress ? (i) => o.readTokenAddress(registry.rollup, i) : undefined;
  // `readDecimals` is left to the default raw-eth_call reader even when the caller supplied an
  // ethers-backed address reader: the decimals call targets the TOKEN, not the rollup, so the
  // node's rollup-scoped ChainWatcher getter does not cover it.
  await registry.verifyAgainstChain(o.rpcUrl, registry.rollup, { logger: log, readTokenAddress, readDecimals: o.readDecimals });
  log.info({ event: 'TOKEN_REGISTRY_READY', ...registry.summary() });
  return registry;
}

module.exports = {
  TokenRegistry,
  bootstrapTokenRegistry,
  TokenManifestError,
  TokenChainMismatchError,
  validateManifest,
  loadManifest,
  resolveManifestPath,
  makeRpcReader,
  makeDecimalsReader,
  encodeTokenAddressOf,
  decodeAddressWord,
  decodeDecimalsWord,
  ETH_TOKEN_INDEX,
  ROLLUP_TOKEN_GETTER_ABI,
  TOKEN_ADDRESS_OF_SIG,
  TOKEN_ADDRESS_OF_SELECTOR,
  ERC20_DECIMALS_ABI,
  DECIMALS_SIG,
  DECIMALS_SELECTOR,
  MAX_TOKENS,
  MAX_DECIMALS,
};
