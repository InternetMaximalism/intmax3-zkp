// Local relay so the browser wallet can run a real send with just clicks: it serves the wallet
// static files (with COEP/COOP for SharedArrayBuffer / threads) AND exposes /api endpoints that
// invoke the CLI companion (channel_member) for the "other members". The browser does the proving;
// the relay does the native co-signing. Dev-only: localhost, self-signed TLS.
//
// TWO CHANNELS: the relay runs channels 7 and 8 side by side, each in its OWN working directory and
// each backed by its OWN real on-chain deposit (its own IntmaxRollup deployment, so every deposit is
// the first on its chain — prev hash 0 — keeping the deposit-hash keystone simple). The browser picks
// which channel to join; every /api call carries `?channel=N` so the relay routes to that channel's
// directory and runs the CLI with INTMAX_CHANNEL=N. Two channels is what makes an inter-channel
// transfer (debit channel 7 → credit channel 8) demonstrable end to end.
const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawn } = require('child_process');
const { createBatchWindow, projectToSlim, partitionByAnchor } = require('./batch-window');
const { publicBacking, baseHead } = require('./public-backing');

const ROOT = __dirname; // hosting/wallet/ — serves wallet-live.html + wallet-worker.js
const REPO = path.join(ROOT, '..', '..'); // repo root — target/, self_certs/, contracts/, pkg/, wallet-live-work/ live here (two levels up from hosting/wallet/)
const WORK = path.join(REPO, 'wallet-live-work');
const CLI = path.join(REPO, 'target', 'release', 'channel_member');
// Dev port. Defaults to 8000 (HTTPS) + 8001 (HTTP); override with RELAY_PORT to run a second relay
// alongside an existing one. Validated: a malformed/out-of-range value is a hard startup error
// rather than a silent fall back to a port another process may already own.
const PORT = (() => {
  const raw = process.env.RELAY_PORT;
  if (raw === undefined || raw === '') return 8000;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 65534) {
    console.error(`RELAY_PORT must be an integer in 1..65534 (got ${JSON.stringify(raw)})`);
    process.exit(1);
  }
  return n;
})();
const CHANNELS = [7, 8];

fs.mkdirSync(WORK, { recursive: true });
const chDir = (ch) => path.join(WORK, 'ch' + ch);
const wc = (ch, n) => path.join(chDir(ch), n);
// Validate the channel from the request against the known set (never trust a raw query value as a
// path component). Defaults to the first channel.
function reqChannel(req) {
  const c = parseInt((req.query && req.query.channel) || '', 10);
  return CHANNELS.includes(c) ? c : CHANNELS[0];
}
function cli(ch, args, extraEnv) {
  console.log(`  $ INTMAX_CHANNEL=${ch} channel_member ${args.join(' ')}`);
  return execFileSync(CLI, args, {
    cwd: chDir(ch),
    encoding: 'utf8',
    timeout: 600_000,
    env: { ...process.env, INTMAX_CHANNEL: String(ch), ...(extraEnv || {}) },
  });
}

// Per-channel mutex: serialize all mutating CLI calls to prevent concurrent state corruption.
const _chLocks = {};
function withLock(ch, fn) {
  if (!_chLocks[ch]) _chLocks[ch] = Promise.resolve();
  const prev = _chLocks[ch];
  const next = prev.then(fn, fn);
  _chLocks[ch] = next.catch(() => {});
  return next;
}

// ---- Ticket persistence (one JSON array per channel) ----------------------------------------
// tickets.json     = ACTIVE tickets (+ terminal ones for a short TTL, so an in-flight UI can react).
// ticket_history.json = DURABLE log of every ticket that reached its terminal state (deposits AND
//                       withdrawals), never TTL-pruned, capped at HISTORY_CAP. This is what the
//                       "Processed" list reads.
const TICKET_FILE = 'tickets.json';
const HISTORY_FILE = 'ticket_history.json';
const TICKET_TTL = 3600_000;
const HISTORY_CAP = 200;
const TERMINAL = { partial_withdrawal: 'settle_done', deposit: 'import_done', full_withdrawal: 'claim_done' };
const isTerminal = (t) => TERMINAL[t.type] === t.status;

function readTickets(ch) {
  try { return JSON.parse(fs.readFileSync(wc(ch, TICKET_FILE), 'utf8')); }
  catch (e) { return []; }
}
function writeTickets(ch, tickets) {
  fs.writeFileSync(wc(ch, TICKET_FILE), JSON.stringify(tickets, null, 2));
}
function readHistory(ch) {
  try { return JSON.parse(fs.readFileSync(wc(ch, HISTORY_FILE), 'utf8')); }
  catch (e) { return []; }
}
// Record a terminal ticket in the durable history (upsert by id so re-terminal writes don't dup).
function archiveTicket(ch, ticket) {
  const hist = readHistory(ch);
  const idx = hist.findIndex(t => t.id === ticket.id);
  const entry = { ...ticket, archivedAt: Date.now() };
  if (idx >= 0) hist[idx] = entry; else hist.push(entry);
  fs.writeFileSync(wc(ch, HISTORY_FILE), JSON.stringify(hist.slice(-HISTORY_CAP), null, 2));
}
function findActiveTicket(ch, type) {
  return readTickets(ch).find(t => t.type === type && t.status !== TERMINAL[type]);
}
function upsertTicket(ch, ticket) {
  const tickets = readTickets(ch);
  const idx = tickets.findIndex(t => t.id === ticket.id);
  ticket.updatedAt = Date.now();
  if (idx >= 0) tickets[idx] = ticket; else tickets.push(ticket);
  const now = Date.now();
  const kept = tickets.filter(t =>
    !Object.values(TERMINAL).includes(t.status) || (now - t.updatedAt) < TICKET_TTL
  );
  writeTickets(ch, kept);
  if (isTerminal(ticket)) archiveTicket(ch, ticket); // durable "processed" record (deposits + withdrawals)
  return ticket;
}

// The rollup address backing channel `ch` (recorded by setup-backing in channel_backing.json).
function rollupOf(ch) {
  const b = JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'));
  if (!b.rollup) throw new Error('channel has no rollup in channel_backing.json (run setup-backing)');
  return b.rollup;
}

// ── Token DISPLAY metadata (multi-token detail2 §N-1/§N-7, threat model TM-10b) ───────────────
//
// SECURITY CONTRACT: symbol / name / decimals carry ZERO authority. The authoritative token
// identity is the base `token_index` — proof-bound in the circuits and set-once on-chain in
// `IntmaxRollup.tokenAddressOf(uint32)`. Showing "USDC" over a worthless token is a user-funds
// attack, so metadata is served ONLY for entries whose manifest address was read back EQUAL from
// the on-chain registry. Everything else is served as null and the wallet falls back to the raw
// base index. Dev twin of the same block in wallet-relay-ec2.js; both share ONE implementation
// (node/common/token-registry.js) so the validation rules cannot drift between them.
let tokenRegistryModule = null;
(function loadTokenRegistryModule() {
  const candidates = [
    process.env.TOKEN_REGISTRY_MODULE,
    path.join(REPO, 'node', 'common', 'token-registry.js'),
    path.join(ROOT, 'token-registry.js'),
  ].filter(Boolean);
  for (const c of candidates) {
    try { if (fs.existsSync(c)) { tokenRegistryModule = require(c); return; } } catch (e) { /* try next */ }
  }
  console.warn('⚠ token-registry module not found — /api/tokens serves raw base indices with null metadata');
})();

const TOKEN_REGISTRIES = {}; // ch -> TokenRegistry (verified asynchronously at startup)
function loadTokenManifests(rpcUrl) {
  if (!tokenRegistryModule) return;
  for (const ch of CHANNELS) {
    const p = process.env.TOKENS_MANIFEST || wc(ch, 'tokens.json');
    if (!fs.existsSync(p)) continue; // no manifest is a valid state: raw base indices
    let reg;
    try {
      reg = tokenRegistryModule.TokenRegistry.fromFile(p);
    } catch (e) {
      console.error(`channel ${ch}: invalid token manifest ${p}: ${e.message}`);
      process.exit(1); // fail closed, same as the EC2 relay
    }
    TOKEN_REGISTRIES[ch] = reg;
    (async () => {
      try {
        await reg.verifyAgainstChain(rpcUrl, rollupOf(ch), { logger: console });
        console.log(`channel ${ch}: tokens ${JSON.stringify(reg.summary())}`);
      } catch (e) {
        // A CONTRADICTION (manifest address != the set-once on-chain value) is the mislabelling
        // hazard itself — refuse to keep running with it.
        console.error(`channel ${ch}: token manifest contradicts the chain: ${e.message}`);
        process.exit(1);
      }
    })();
  }
}

// Per-token channel view for the wallet. The slots and their base indices come from the CHANNEL's
// OWN signed registry (the cosigned snapshot) — the manifest only answers "what may this base
// index be CALLED", and only when chain-verified.
function channelTokens(ch) {
  const snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
  const st = (snap && (snap.state || snap.State)) || {};
  const bs = st.balanceState || st.balance_state || {};
  const fund = st.channelFund || st.channel_fund || {};
  const tokenCount = bs.tokenCount != null ? bs.tokenCount : (bs.token_count != null ? bs.token_count : 1);
  const registry = bs.tokenRegistry || bs.token_registry || [];
  const amounts = fund.amounts || [];
  const meta = TOKEN_REGISTRIES[ch] || null;
  const tokens = [];
  for (let t = 0; t < tokenCount; t++) {
    const tokenIndex = registry[t] !== undefined ? registry[t] : 0;
    const md = meta
      ? meta.metadataFor(tokenIndex)
      : { symbol: null, name: null, decimals: null, address: null, native: tokenIndex === 0, verified: false };
    tokens.push({
      tokenSlot: t,
      tokenIndex,
      symbol: md.symbol,
      name: md.name,
      decimals: md.decimals,
      address: md.address,
      native: md.native,
      verified: md.verified,
      fundAmount: amounts[t] !== undefined ? String(amounts[t]) : '0',
    });
  }
  return { tokenCount, tokens };
}

// ── Testnet $ITX faucet (multi-token §N) ─────────────────────────────────────────────────────
//
// SECURITY CONTRACT. `POST /api/faucet` is UNAUTHENTICATED and moves REAL escrowed value: the
// faucet member holds an in-channel balance backed by one ERC-20 deposit made on L1 and imported
// once. It therefore cannot MINT (every dripped balance stays covered by
// `channel_fund.amounts[t]` and stays claimable) — the realistic attack is DRAINING it. Defences:
//   1. OFF BY DEFAULT — live only with FAUCET_ENABLED=1 + FAUCET_SLOT + a NON-ZERO
//      ITX_TOKEN_INDEX; anything missing/malformed leaves it disabled and POST answers 404.
//   2. NOTHING FROM THE REQUEST BUT THE RECIPIENT SLOT — amount, token and limits are config, and
//      the slot is checked against the CHANNEL'S OWN SIGNED membership + registry.
//   3. ONE DRIP PER SLOT FOR EVER, plus a per-channel cap and a cooldown.
//   4. RESERVE BEFORE TRANSFER — a crash mid-transfer costs a drip, it never pays one twice.
// DEPLOYMENT INVARIANT: exactly ONE relay process per channel directory — `withLock` is in-process
// JS state, not an flock (see the EC2 twin for the full note).
// Dev twin of the same block in wallet-relay-ec2.js; both share ONE implementation
// (node/common/faucet-policy.js) so the policy cannot drift between them. If the module cannot be
// loaded the faucet stays DISABLED — it is never re-implemented inline.
let faucetPolicy = null;
(function loadFaucetPolicy() {
  const candidates = [
    process.env.FAUCET_POLICY_MODULE,
    path.join(REPO, 'node', 'common', 'faucet-policy.js'),
    path.join(ROOT, 'faucet-policy.js'),
  ].filter(Boolean);
  for (const c of candidates) {
    try { if (fs.existsSync(c)) { faucetPolicy = require(c); return; } } catch (e) { /* try next */ }
  }
})();
const FAUCET = faucetPolicy
  ? faucetPolicy.faucetConfig(process.env)
  : { enabled: false, reason: 'faucet-policy module not found' };
if (FAUCET.enabled) {
  console.log(`faucet ENABLED: slot ${FAUCET.faucetSlot} drips ${FAUCET.dripAmount} of base token ${FAUCET.tokenIndex} (channel cap ${FAUCET.channelCap}, cooldown ${FAUCET.cooldownMs}ms)`);
} else if (String(process.env.FAUCET_ENABLED || '') === '1') {
  console.warn(`⚠ faucet requested but DISABLED: ${FAUCET.reason}`);
}

const FAUCET_FILE = 'faucet_state.json';
/**
 * Read the per-channel faucet ledger. THROWS on a corrupt file (fail closed — see the module).
 *
 * SECURITY: only a MISSING file is an absent ledger. A file that parses to `null` or to any
 * non-object is CORRUPTION and must not be read as "nobody has drunk yet" — that would re-open
 * the faucet to every slot already recorded. Deliberately unlike the sibling `readTickets`, which
 * swallows errors: tickets are display state, this is the drain guard.
 */
function readFaucetState(ch) {
  const p = wc(ch, FAUCET_FILE);
  if (!fs.existsSync(p)) return faucetPolicy.emptyState();
  const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`faucet ledger ${p} is corrupt (not a JSON object) — refusing to start from empty`);
  }
  return faucetPolicy.normalizeState(parsed);
}
/**
 * Persist the ledger ATOMICALLY: temp file + rename (same crash-safety pattern as
 * node/common/store.js). A bare writeFileSync that is interrupted mid-write leaves a truncated
 * ledger, which `readFaucetState` correctly refuses — safe, but it bricks that channel's faucet
 * until an operator intervenes. Rename on the same filesystem is atomic, so a reader ever only
 * sees the whole old file or the whole new one.
 */
function writeFaucetState(ch, st) {
  const p = wc(ch, FAUCET_FILE);
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(st, null, 2));
  fs.renameSync(tmp, p);
}
/**
 * The LOCAL position of the faucet's base token in THIS channel, from the channel's own COSIGNED
 * registry (`channelTokens` reads the signed snapshot) — never the tokens.json manifest, whose
 * display metadata carries zero authority.
 */
function faucetLocalTokenSlot(ch) {
  const t = channelTokens(ch).tokens.find((x) => x.tokenIndex === FAUCET.tokenIndex);
  return t ? t.tokenSlot : null;
}
/** `member_count + delegate_count` from the SIGNED snapshot — the only authority on who exists. */
function activeSlotCount(ch) {
  const snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
  const st = (snap && (snap.state || snap.State)) || {};
  const bs = st.balanceState || st.balance_state || {};
  const mc = bs.memberCount != null ? bs.memberCount : bs.member_count;
  const dc = bs.delegateCount != null ? bs.delegateCount : bs.delegate_count;
  return Number.isInteger(mc) && Number.isInteger(dc) ? mc + dc : null;
}

const app = express();
app.use(express.json({ limit: '64mb' }));
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid JSON: ' + err.message });
  next(err);
});
// Cross-origin isolation (SharedArrayBuffer) + correct wasm mime.
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (req.path.endsWith('.wasm')) res.setHeader('Content-Type', 'application/wasm');
  // Dev: never let the browser cache the wallet HTML/JS/wasm — a stale cached wasm silently runs
  // old code (e.g. a pre-migration build), so always serve fresh.
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// Which channels the relay is serving (the browser lists/validates against this).
app.get('/api/channels', (req, res) => res.json({ channels: CHANNELS }));

// Step 1 (delegate demo): browser sends its DELEGATE genesis contribution → CLI builds the channel
// with 3 co-signing members + the browser delegate, the 3 members sign the genesis, and the CLI
// returns the FULLY-SIGNED snapshot for the browser to import directly (the delegate does NOT sign
// the genesis). CREATE-OR-JOIN: the first browser creates channel N; each later browser JOINS the
// SAME channel N as a distinct delegate. cli_state.json is reset only on relay startup.
app.post('/api/init', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, () => {
    fs.mkdirSync(chDir(ch), { recursive: true });
    fs.writeFileSync(wc(ch, 'contribution.json'), JSON.stringify(req.body));
    cli(ch, ['init', 'contribution.json', 'channel_snapshot.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')));
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// Latest fully-signed channel snapshot — browsers re-import this before sending so they pick up any
// newly-joined delegates (and the current head).
// ---- SLIM DOWNLINK: state deltas for /api/snapshot ------------------------------------------
// The uplink is already slim (detail2 §M-1, SlimSendPayload). The DOWNLINK was not: after every
// send the browser re-downloaded the whole ~1.6MB snapshot just to hand `snapshot.state` to
// `wallet_finalize`. Most of those bytes are things the client already holds byte-for-byte.
//
// Measured on the live ch7 snapshot (5 active slots, 2 tokens), UNCOMPRESSED bytes of JSON. The
// route is behind `compression`, so what actually crosses the wire is ~1/3 of these figures and the
// saving must be judged gzipped: measured end-to-end, 560,996 B full vs ~360,804 B for a two-row
// send delta (-37%). `fmtKB` in the browser log prints the DECOMPRESSED length, so it reads high.
// Measured, bytes of JSON:
//     members              214,899   NEVER used by finalize (it keeps its own verified copy)
//     record                70,974   likewise
//     state.memberSignatures 833,416 fresh every transition — MUST be sent
//     state...encBalances   342,607  only the rows the tx touched actually change
//     state...regevPkDigests 70,657  changes only on join
//     state...recipients     46,081  changes only on join
//
// SIGNATURE SIZE UPDATE (falcon-sig Phase 4). Those 833,416 bytes were 3 co-signers x a ~76 KB
// plonky2 proof-as-signature. A co-signature is now a 1,690-byte native Falcon-512 blob
// (666 B signature + the 1,024 B public polynomial the verifier needs), i.e. ~5 KB of JSON for
// the whole set instead of ~833 KB — a ~165x drop, and the signature set stops being the
// dominant term. Every other row above is unchanged, so `encBalances` is now what the delta is
// actually saving. The optimization remains CORRECT and still worth keeping (encBalances alone
// is ~343 KB and grows with slots x tokens); it is simply no longer load-bearing for the
// signature blob. Nothing about the security argument below depends on any of these sizes.
//
// So a delta sends `state` minus {encBalances, regevPkDigests, recipients}, plus ONLY the changed
// encBalances rows, and names the rest as "carry these from your base".
//
// SECURITY. This is a TRANSPORT optimization with no trust component. The client rebuilds the full
// state and hands it to `wallet_finalize` UNCHANGED, which calls `verify_snapshot` →
// `verify_all_signatures` (src/wallet_core.rs:856): that RECOMPUTES `ChannelState::signing_digest()`
// over the reconstructed state and rejects unless it equals `state.digest`, then verifies every
// cosigner's real signature against the RECOMPUTED digest. `encBalances`, `regevPkDigests`,
// `recipients` and `pendingAdds` are all bound into that digest through `balance_state.h1()`'s
// slot-tree root (src/common/balance_state.rs:537). A delta that misdescribes ANY carried byte
// therefore produces a state whose recomputed digest differs from what the members signed, and
// finalize FAILS. The relay cannot use a delta to get a state accepted that it could not have got
// accepted by sending it in full.
//
// `carryHash` below is NOT that security gate — it is a cheap liveness/diagnosability gate, so a
// stale base turns into a clean full re-fetch instead of a confusing signature failure.
const DELTA_FORMAT = 1;
// Fields the client is told to carry from its base. Order is part of the hashed material.
const DELTA_CARRY_FIELDS = ['regevPkDigests', 'recipients'];
// How many recent heads stay eligible as a delta base, per channel. In-memory only: a relay
// restart just means the next request falls back to a full snapshot (correct, only slower).
const DELTA_HISTORY = 8;
const _deltaIdx = {}; // ch -> [fingerprint, ...] oldest first

const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

// The exact string whose hash `carryHash` commits to: the carry FIELDS, plus the encBalances rows
// the delta declares unchanged, in the order they are listed. Hashing the carried ROWS is what
// makes "these rows are byte-identical" a CHECKED claim rather than a promise -- the relay hashes
// the HEAD's rows at those indices, the client hashes ITS BASE's, so a relay that mislabels a
// changed row as unchanged produces a mismatch and the client re-fetches in full. (Soundness does
// not rest on this: a mislabelled row would also fail the digest recomputation in
// verify_all_signatures. This turns that late, confusing failure into a clean early fallback.)
// Both sides stringify values parsed from the SAME relay-produced JSON bytes, so key order and
// number formatting round-trip identically.
function deltaCarryMaterial(bs, carryFields, unchangedRows) {
  const rows = Array.isArray(bs && bs.encBalances) ? bs.encBalances : [];
  return JSON.stringify([
    carryFields.map((f) => ((bs && bs[f]) !== undefined ? bs[f] : null)),
    unchangedRows.map((i) => (rows[i] !== undefined ? rows[i] : null)),
  ]);
}

// Per-row / per-carry-field content hashes of one state. Cheap (~1ms over ~460KB of balanceState).
function fingerprintState(st) {
  const bs = (st && st.balanceState) || {};
  const rows = Array.isArray(bs.encBalances) ? bs.encBalances : [];
  return {
    digest: st && st.digest,
    stateVersion: bs.stateVersion,
    memberCount: bs.memberCount,
    delegateCount: bs.delegateCount,
    rowCount: rows.length,
    rowHashes: rows.map((r) => sha256hex(JSON.stringify(r))),
    // Carry-FIELDS only: used to notice a join/field change between base and head. The response's
    // `carryHash` is a different, wider commitment (fields + the carried rows).
    carryFieldsHash: sha256hex(deltaCarryMaterial(bs, DELTA_CARRY_FIELDS, [])),
  };
}
// PERF, OPEN: fingerprinting is O(state) — it JSON.stringify+SHA-256s every balance row. Measured
// at ~1.4ms for 5 slots, but the 1024-slot target puts it near ~150ms of BLOCKING event-loop time
// per GET, on the same single thread that serves /api/cosign2. It runs on every snapshot request,
// including repeat GETs of an unchanged state.
//
// The obvious memo — key the cache on `st.digest` — was tried and REVERTED. It makes the structural
// checks below (memberCount/delegateCount, carryFieldsHash, per-row hashes) inherit their integrity
// from the digest field instead of computing them locally. That holds for the real
// `ChannelState::signing_digest()`, which covers every field, but it converts a check that works
// unconditionally into one that works because of a cryptographic property elsewhere — and it made
// the membership-change and carry-change fallback tests pass vacuously. If this needs to be fast
// before the 1024-slot cutover, key the cache on the SNAPSHOT FILE's (mtimeMs, size) instead: that
// is a local fact about bytes on disk and assumes nothing about the digest.
function fingerprintCached(ch, st) {
  const fp = fingerprintState(st || {});
  recordFingerprint(ch, fp);
  return fp;
}
function recordFingerprint(ch, fp) {
  if (!fp || typeof fp.digest !== 'string' || !Number.isInteger(fp.stateVersion)) return;
  const list = (_deltaIdx[ch] = _deltaIdx[ch] || []);
  if (list.some((e) => e.digest === fp.digest)) return;
  list.push(fp);
  while (list.length > DELTA_HISTORY) list.shift();
}
function findFingerprint(ch, digest, stateVersion) {
  return (_deltaIdx[ch] || []).find(
    (e) => e.digest === digest && e.stateVersion === stateVersion) || null;
}

// Build the delta response, or null when the client's base cannot be reconciled (caller then sends
// the FULL snapshot — correctness first, bandwidth second).
function buildStateDelta(ch, snap, sinceVersion, sinceDigest) {
  const st = snap && snap.state;
  if (!st || !st.balanceState) return { fallback: 'no-state' };
  const head = fingerprintCached(ch, st); // also indexes it, so the NEXT request can use it as a base
  if (!Number.isInteger(sinceVersion) || typeof sinceDigest !== 'string' || !sinceDigest) {
    return { fallback: 'bad-since' };
  }
  const base = findFingerprint(ch, sinceDigest, sinceVersion);
  if (!base) return { fallback: 'unknown-base' };
  // Client already holds the head — tell it so in ~100 bytes instead of resending 1.6MB. Its
  // retry loop is waiting for the head to advance past the co-sign ACK's version.
  if (base.digest === head.digest) {
    return { body: { deltaFormat: DELTA_FORMAT, unchanged: true, head: { stateVersion: head.stateVersion, digest: head.digest } } };
  }
  // A join changes the slot layout: every carried index would mean a different participant.
  if (base.memberCount !== head.memberCount || base.delegateCount !== head.delegateCount) {
    return { fallback: 'membership-changed' };
  }
  if (base.carryFieldsHash !== head.carryFieldsHash) return { fallback: 'carry-changed' };

  const changedRows = {};
  const unchangedRows = [];
  for (let i = 0; i < head.rowCount; i++) {
    if (i < base.rowCount && base.rowHashes[i] === head.rowHashes[i]) unchangedRows.push(i);
    else changedRows[String(i)] = st.balanceState.encBalances[i];
  }
  if (!unchangedRows.length) return { fallback: 'all-rows-changed' };

  // Shallow clones — the on-disk snapshot object is never mutated.
  const bs = { ...st.balanceState };
  delete bs.encBalances;
  for (const f of DELTA_CARRY_FIELDS) delete bs[f];
  return {
    body: {
      deltaFormat: DELTA_FORMAT,
      channel: ch,
      base: { stateVersion: sinceVersion, digest: sinceDigest },
      head: { stateVersion: head.stateVersion, digest: head.digest },
      rowCount: head.rowCount,
      changedRows,
      unchangedRows,
      carry: DELTA_CARRY_FIELDS,
      carryHash: sha256hex(deltaCarryMaterial(st.balanceState, DELTA_CARRY_FIELDS, unchangedRows)),
      state: { ...st, balanceState: bs },
    },
  };
}

app.get('/api/snapshot', (req, res) => {
  let ch, snap;
  try {
    ch = reqChannel(req);
    snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
  } catch (e) { return res.status(404).json({ error: 'no channel yet' }); }
  // No `since`/`sinceDigest` -> byte-identical to the pre-delta response, so OLD CLIENTS (and every
  // non-send call site) are untouched. The head is still fingerprinted, so this snapshot can serve
  // as the base of the client's NEXT delta request.
  const since = req.query && req.query.since;
  const sinceDigest = req.query && req.query.sinceDigest;
  if (since === undefined || sinceDigest === undefined) {
    try { fingerprintCached(ch, snap.state); } catch (e) { /* never fail a snapshot read over the index */ }
    return res.json(snap);
  }
  const out = buildStateDelta(ch, snap, parseInt(String(since), 10), String(sinceDigest));
  if (out.body) return res.json(out.body);
  res.setHeader('X-Delta-Fallback', out.fallback);   // observability only; the body is the full snapshot
  res.json(snap);
});

// GET /api/poll?channel=N&since=<stateVersion>
// Cheap change-check for the browser's balance poller. Reads the channel state_version WITHOUT any
// decryption/proving and returns the full snapshot ONLY if the channel advanced past `since` (a
// deposit/send/receive changed balances); otherwise 204 (no body). The browser then re-decrypts
// ONLY when a snapshot comes back. Deliberately NOT withLock: a poll must never queue behind a
// minutes-long proving CLI call, and a transient read during a CLI write just returns 204 (the next
// tick succeeds). Any balance change bumps state_version, so `since === current` ⇒ balance unchanged.
app.get('/api/poll', (req, res) => {
  const ch = reqChannel(req);
  const since = parseInt((req.query && req.query.since) || '', 10);
  let snap;
  try {
    snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
  } catch (e) {
    return res.status(204).end(); // no channel yet / mid-write → treat as "no change"
  }
  const st = snap && (snap.state || snap.State) || {};
  const bs = st.balanceState || st.balance_state || {};
  const sv = (bs.stateVersion != null) ? bs.stateVersion : bs.state_version;
  if (Number.isInteger(since) && sv === since) return res.status(204).end();
  // The balance poller adopts this snapshot as the wallet's verified head, so it is the base the
  // NEXT send will ask a delta against. Without indexing it here, any channel activity between two
  // of a user's own sends leaves the client holding a head the relay cannot recognise
  // (`unknown-base`) and the send pays a full download -- i.e. on a live channel the delta would
  // almost never fire. Cheap: fingerprintCached re-uses the index when the digest is already known.
  try { fingerprintCached(ch, snap.state || snap.State); } catch (e) { /* never fail a poll over the index */ }
  res.json(snap);
});

// The channel's REAL Intmax deposit backing (detail2 §F-1): { fund, settledTxChain,
// intmaxStateRoot } produced once by `setup-backing`. The browser shows this so the user can see the
// channel is genuinely backed by a deposited Intmax balance (not a self-minted number).
app.get('/api/backing', (req, res) => {
  try {
    const ch = reqChannel(req);
    res.json(publicBacking(JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'))));
  } catch (e) { res.status(404).json({ error: 'no deposit backing yet' }); }
});

app.get('/api/base-head', (req, res) => {
  try {
    const ch = reqChannel(req);
    res.json(baseHead(JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'))));
  } catch (e) { res.status(409).json({ error: String(e.message || e) }); }
});

// GET /api/tokens?channel=N — per-token channel view + VERIFIED display metadata (§N).
// symbol/name/decimals are non-null ONLY when `verified` is true; `address` may be reported while
// unverified, a NAME may not. 404 while the channel has no snapshot (matches /api/snapshot).
app.get('/api/tokens', (req, res) => {
  try { res.json(channelTokens(reqChannel(req))); }
  catch (e) { res.status(404).json({ error: 'no channel yet' }); }
});

// (Legacy member-mode genesis co-signing — unused by the delegate demo, where the browser does not
// sign the genesis. Kept for the member-mode wallet.)
app.post('/api/add-genesis-sig', (req, res) => {
  try {
    const ch = reqChannel(req);
    fs.writeFileSync(wc(ch, 'browser_sig.json'), JSON.stringify(req.body));
    cli(ch, ['add-genesis-sig', 'browser_sig.json', 'channel_snapshot.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')));
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});

// Step 3: browser sends a transfer payload → CLI co-signs (other members) → returns the
// fully-signed next state for the browser to finalize.
//
// detail2 §M-7: payloads are coalesced into a per-channel window (BATCH_WINDOW_MS, cap
// BATCH_WINDOW_MAX) and the channel co-signs ONE state transition per window via `cosign-batch`.
// K = 1 windows take the exact legacy solo path. Stale-anchored payloads are rejected per-tx
// (409, client re-signs); a rejected batch replays sequentially so one bad tx cannot DoS its
// window. All K waiters of a batch window receive the same fully-signed batch state.
const BATCH_WINDOW_MS = Math.max(1, parseInt(process.env.BATCH_WINDOW_MS || '1000', 10) || 1000);
const BATCH_WINDOW_MAX = Math.max(1, Math.min(1024, parseInt(process.env.BATCH_WINDOW_MAX || '200', 10) || 200));

function drainCosignWindow(ch, entries) {
  return withLock(ch, () => {
    const snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
    const { fresh, stale } = partitionByAnchor(entries, snap.state.digest);
    for (const en of stale) {
      const err = new Error('staleAnchor: payload does not extend the current head — re-sign against the latest snapshot');
      err.staleAnchor = true;
      en.reject(err);
    }
    if (fresh.length === 0) return;
    const soloOne = (en) => {
      try {
        fs.writeFileSync(wc(ch, 'payload.json'), JSON.stringify(en.payload));
        cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
        en.resolve(JSON.parse(fs.readFileSync(wc(ch, 'cosigned.json'), 'utf8')));
      } catch (e) { en.reject(e); }
    };
    if (fresh.length === 1) { soloOne(fresh[0]); return; }
    // K > 1: project fat→slim (§M-4), spool one file per tx, hand a §M-1 manifest to cosign-batch.
    const spoolDir = wc(ch, 'batch_spool');
    fs.mkdirSync(spoolDir, { recursive: true });
    const files = [];
    try {
      fresh.forEach((en, i) => {
        const f = path.join('batch_spool', `tx_${Date.now()}_${i}.json`);
        fs.writeFileSync(wc(ch, f), JSON.stringify(projectToSlim(en.payload)));
        files.push(f);
      });
      fs.writeFileSync(wc(ch, 'batch_manifest.json'), JSON.stringify({ files }));
      console.log(`[batch] channel ${ch}: window of ${fresh.length} tx → cosign-batch`);
      cli(ch, ['cosign-batch', 'batch_manifest.json', 'batch_cosigned.json']);
      const result = JSON.parse(fs.readFileSync(wc(ch, 'batch_cosigned.json'), 'utf8'));
      for (const en of fresh) en.resolve(result);
    } catch (e) {
      // Fail-whole batch rejected (one invalid proof, §M-2): replay solo so honest txs land and
      // only the invalid tx errors. Bounded: runs only on rejection, window ≤ BATCH_WINDOW_MAX.
      console.error(`[batch] channel ${ch}: batch rejected (${String(e.stderr || e.message || e).slice(0, 200)}); replaying window solo`);
      for (const en of fresh) if (!en.settled) soloOne(en);
    } finally {
      for (const f of files) { try { fs.unlinkSync(wc(ch, f)); } catch (_) {} }
    }
  });
}

const cosignBatcher = createBatchWindow({
  windowMs: BATCH_WINDOW_MS,
  maxK: BATCH_WINDOW_MAX,
  drain: drainCosignWindow,
});

app.post('/api/cosign', (req, res) => {
  const ch = reqChannel(req);
  cosignBatcher.enqueue(ch, req.body).then(
    (result) => res.json(result),
    (e) => {
      console.error(e.stderr ? String(e.stderr) : (e.message || e));
      res.status(e.staleAnchor ? 409 : 500).json({ error: String(e.stderr || e.message || e) });
    }
  );
});

// Balance-refresh: browser re-encrypts its own slot (RefreshPayload) → CLI members co-sign → returns
// the fully-signed next state for the browser to finalize. Lets a delegate send again after receiving.
app.post('/api/refresh-cosign', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, () => {
    fs.writeFileSync(wc(ch, 'refresh_payload.json'), JSON.stringify(req.body));
    cli(ch, ['cosign-refresh', 'refresh_payload.json', 'refresh_cosigned.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'refresh_cosigned.json'), 'utf8')));
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// Inter-channel send (SINGLE atomic endpoint). `?channel=A` = the SOURCE channel; the relay OWNS both
// channels, so this one command debits A and credits B atomically — there is NO standalone credit
// endpoint that would trust a request-body signed state (CRITICAL-1).
// Body = { debitPayload, transferDescriptor }. Both are written into A's dir; the combined
// `cosign-inter-transfer` co-signs A's debit (extending A's COMMITTED head), validates + credits B
// (resolved as ../ch<dest>/), and persists both only if both legs pass. Returns { aHead, bSnapshot }.
app.post('/api/inter/send', (req, res) => {
  const ch = reqChannel(req); // = source channel A
  withLock(ch, () => {
    const debitPayload = req.body && req.body.debitPayload;
    const descriptor = req.body && req.body.transferDescriptor;
    if (!debitPayload || !descriptor) throw new Error('inter/send needs { debitPayload, transferDescriptor }');
    fs.writeFileSync(wc(ch, 'inter_debit_payload.json'), JSON.stringify(debitPayload));
    fs.writeFileSync(wc(ch, 'inter_descriptor.json'), JSON.stringify(descriptor));
    cli(ch, ['cosign-inter-transfer', 'inter_debit_payload.json', 'inter_descriptor.json', 'inter_transfer.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'inter_transfer.json'), 'utf8')));
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// ─── A-3 close lifecycle (close → settle → withdraw → claim) ────────────────────────────────────
// Thin wrappers over the CLI, same shape as /api/inter/send: the relay owns all members, so `close`
// aggregates the N-of-N co-signature in ONE command. The caller supplies the channel's deployed
// settlement-manager address (and, for close, the settlement-verifier `sv`); the rollup address is
// taken from the channel's own channel_backing.json. Heavy (real proving) — these block for minutes.
// SECURITY: wiring only. Soundness is in-circuit + on-chain (the CLI builds real proofs; the manager
// /rollup gate every payout). The manager/sv/recipient are passed straight to the CLI/forge.

// POST /api/close?channel=N  body: { manager, sv }
app.post('/api/close', (req, res) => {
  try {
    const ch = reqChannel(req);
    const manager = req.body && req.body.manager;
    const sv = (req.body && req.body.sv) || '';
    if (!manager) throw new Error('close needs { manager }');
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) { ticket.status = 'close_pending'; upsertTicket(ch, ticket); }
    const out = cli(ch, ['close', manager, RPC], { CLOSE_SV: sv });
    if (ticket) { ticket.status = 'close_done'; ticket.steps.close = { completedAt: Date.now() }; upsertTicket(ch, ticket); }
    res.json({ ok: true, log: out });
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});

// POST /api/settle?channel=N  body: { manager }
app.post('/api/settle', (req, res) => {
  try {
    const ch = reqChannel(req);
    const manager = req.body && req.body.manager;
    if (!manager) throw new Error('settle needs { manager }');
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) { ticket.status = 'settle_pending'; upsertTicket(ch, ticket); }
    const out = cli(ch, ['settle', manager, RPC]);
    if (ticket) { ticket.status = 'settle_done'; ticket.steps.settle = { completedAt: Date.now() }; upsertTicket(ch, ticket); }
    res.json({ ok: true, log: out });
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});

// POST /api/withdraw?channel=N  body: { manager }  (rollup→manager via the full withdrawal pipeline)
app.post('/api/withdraw', (req, res) => {
  try {
    const ch = reqChannel(req);
    const manager = req.body && req.body.manager;
    if (!manager) throw new Error('withdraw needs { manager }');
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) { ticket.status = 'withdraw_pending'; upsertTicket(ch, ticket); }
    const out = cli(ch, ['withdraw', manager, RPC], { ROLLUP: rollupOf(ch) });
    if (ticket) { ticket.status = 'withdraw_done'; ticket.steps.withdraw = { completedAt: Date.now() }; upsertTicket(ch, ticket); }
    res.json({ ok: true, log: out });
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});

// POST /api/claim?channel=N  body: { manager, slot, recipient }  (per-member payout)
app.post('/api/claim', (req, res) => {
  try {
    const ch = reqChannel(req);
    const manager = req.body && req.body.manager;
    const slot = req.body && req.body.slot;
    const recipient = req.body && req.body.recipient;
    if (!manager || slot === undefined || !recipient) throw new Error('claim needs { manager, slot, recipient }');
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) { ticket.status = 'claim_pending'; upsertTicket(ch, ticket); }
    const out = cli(ch, ['claim', manager, String(slot), RPC], { CLAIM_RECIPIENT: recipient });
    if (ticket) { ticket.status = 'claim_done'; ticket.steps.claim = { completedAt: Date.now() }; upsertTicket(ch, ticket); }
    res.json({ ok: true, log: out });
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});

// ─── L1 deposit + mid-channel import + partial withdrawal ─────────────────────────────────────

// The reorg depth `cosign-l1-deposit-import` will require for a deposit on `chainId`.
//
// SECURITY: DISPLAY ONLY, and deliberately a MIRROR rather than a control. The enforcing check is
// `min_confirmations_for` in src/bin/channel_member.rs (floor/default 0 on anvil 31337, floor 1 and
// default 12 elsewhere), which reads the chain itself. This relay never passes a
// `min_confirmations` argument to the CLI, and the CLI clamps any explicit value UP to the floor —
// so nothing served here can lower the depth actually enforced. It exists only so the wallet can
// render "confirming (n/12)" instead of an error while a fresh deposit matures.
// Keep in sync with wallet-relay-ec2.js.
function minConfirmationsForDisplay(chainId) {
  return chainId === 31337 ? 0 : 12;
}

// GET /api/deposit-info?channel=N
// Returns the on-chain addresses and ABI info needed for the browser to send a deposit tx via
// MetaMask (native ETH or any L1-registered ERC-20 — `rollup` is both the deposit target and the
// ERC-20 approve spender).
app.get('/api/deposit-info', (req, res) => {
  try {
    const ch = reqChannel(req);
    const backing = JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'));
    if (!backing.rollup) throw new Error('no rollup in channel_backing.json');
    if (!backing.deposit_recipient) throw new Error('no deposit_recipient in channel_backing.json');
    res.json({
      rollup: backing.rollup,
      depositRecipient: backing.deposit_recipient,
      rpc: RPC,
      chainId: 31337,
      minConfirmations: minConfirmationsForDisplay(31337),
    });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// POST /api/l1-deposit?channel=N  body: { amount } (base units)
// Fallback: sends a deposit via the relay's anvil dev key (for non-MetaMask testing).
app.post('/api/l1-deposit', (req, res) => {
  try {
    const ch = reqChannel(req);
    const amount = req.body && req.body.amount;
    if (!amount) throw new Error('l1-deposit needs { amount }');
    const backing = JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'));
    if (!backing.rollup) throw new Error('no rollup in channel_backing.json');
    if (!backing.deposit_recipient) throw new Error('no deposit_recipient in channel_backing.json');
    const out = sh('cast', [
      'send', backing.rollup,
      'deposit(bytes32,uint32,uint256,bytes32)',
      backing.deposit_recipient, '0', String(amount),
      '0x0000000000000000000000000000000000000000000000000000000000000000',
      '--value', String(amount),
      '--private-key', ANVIL0, '--rpc-url', RPC, '--json',
    ], { stdio: 'pipe' });
    const txHash = (out.match(/"transactionHash"\s*:\s*"(0x[0-9a-fA-F]+)"/) || [])[1] || '';
    const depositor = sh('cast', ['wallet', 'address', '--private-key', ANVIL0], { stdio: 'pipe' }).trim();
    fs.writeFileSync(wc(ch, 'pending_deposit.json'), JSON.stringify({
      depositor, amount: String(amount), txHash,
    }));
    res.json({ ok: true, txHash, depositor });
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});

// POST /api/import-deposit?channel=N  body: { recipientSlot, depositor?, amount? }
// Fold a pending L1 deposit into the channel's balance (mid-channel deposit).
// If depositor+amount are provided (MetaMask flow), uses those directly.
// Otherwise reads from pending_deposit.json (fallback relay-deposit flow).
// SECURITY: mirrors the EC2 relay — `depositor`/`amount` are no longer accepted; the CLI reads
// them from the on-chain `Deposited` log. See doc/tasks/deposit-import-threat-model.md.
app.post('/api/import-deposit', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, () => {
    const b = req.body || {};
    if (b.depositor !== undefined || b.amount !== undefined || b.tokenIndex !== undefined) {
      throw new Error('import-deposit no longer accepts { depositor, amount, tokenIndex }: they are read from the on-chain Deposited log. Send { recipientSlot, txHash }.');
    }
    const slot = b.recipientSlot !== undefined ? b.recipientSlot : 0;
    let txHash = b.txHash;
    // The browser (MetaMask) path always sends its own txHash: that deposit is signed by the user's
    // wallet, whose address IS the slot's bound B-1b recipient, so the CLI's depositor<->slot
    // binding must hold and NO flag is passed. The fallback file is written only by the
    // server-key `/api/l1-deposit` route, where the depositor is the operator and bound to no slot.
    let operatorFunded = false;
    if (txHash === undefined) {
      const dep = JSON.parse(fs.readFileSync(wc(ch, 'pending_deposit.json'), 'utf8'));
      if (!dep.txHash) throw new Error('pending_deposit.json has no txHash — cannot verify the deposit on-chain');
      txHash = dep.txHash;
      operatorFunded = true;
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(String(txHash))) throw new Error('txHash must be 0x + 64 hex chars');
    if (!/^[0-9]{1,4}$/.test(String(slot))) throw new Error('recipientSlot must be a small decimal integer');
    const args = ['cosign-l1-deposit-import', String(slot), String(txHash), RPC, 'l1_import_cosigned.json'];
    if (operatorFunded) args.push('--allow-unbound-depositor');
    cli(ch, args);
    const depTicket = findActiveTicket(ch, 'deposit');
    if (depTicket) { depTicket.status = 'import_done'; depTicket.steps.import = { completedAt: Date.now() }; upsertTicket(ch, depTicket); }
    const snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
    res.json(snap);
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// ─── Testnet $ITX faucet ───────────────────────────────────────────────────────────────────
// GET  /api/faucet            → { enabled } (+ tokenIndex/amount/cooldownMs when enabled).
//                               Always 200 so the wallet can ask without generating errors.
// POST /api/faucet { slot }   → the fresh snapshot (+ `_faucet`), or 404 when disabled.
app.get('/api/faucet', (req, res) => {
  res.json(faucetPolicy ? faucetPolicy.publicInfo(FAUCET) : { enabled: false });
});

app.post('/api/faucet', (req, res) => {
  // Disabled ⇒ the endpoint does not exist. No hints, no partial behaviour.
  if (!FAUCET.enabled) return res.status(404).json({ error: 'faucet not available' });
  const ch = reqChannel(req);
  withLock(ch, () => {
    const slot = req.body && req.body.slot;
    const amount = FAUCET.dripAmount.toString();
    const localTokenSlot = faucetLocalTokenSlot(ch);
    // A corrupt ledger THROWS here and the request 500s — never "start from empty", which would
    // re-open the faucet to every slot that already drank.
    const state = readFaucetState(ch);
    const verdict = faucetPolicy.checkEligibility({
      config: FAUCET,
      slot,
      activeSlots: activeSlotCount(ch),
      localTokenSlot,
      state,
      now: Date.now(),
    });
    if (!verdict.ok) {
      if (verdict.alreadyFunded) {
        const snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
        return res.json({ ...snap, _faucet: { funded: true, alreadyFunded: true, amount, tokenIndex: FAUCET.tokenIndex, tokenSlot: localTokenSlot } });
      }
      const status = verdict.code === 'cooldown' || verdict.code === 'cap_reached' ? 429 : 400;
      return res.status(status).json({ error: verdict.reason, code: verdict.code, retryAfterMs: verdict.retryAfterMs });
    }

    // RESERVE FIRST (see the security contract above), then move the value.
    writeFaucetState(ch, faucetPolicy.reserveDrip(state, slot, amount, Date.now()));
    console.log(`[faucet] channel ${ch}: drip reserved — ${amount} of base token ${FAUCET.tokenIndex} (local slot ${localTokenSlot}) from slot ${FAUCET.faucetSlot} → slot ${slot}`);
    try {
      // `refresh` re-encrypts the faucet's own position to a locally-witnessed ciphertext and
      // clears its `pending_adds`. A position credited homomorphically (the L1 deposit import
      // that seeded the faucet) or just spent by the previous drip is otherwise UNSPENDABLE —
      // the refresh proof is value-preserving (RefreshAir) and every co-signer re-verifies it.
      cli(ch, ['refresh', String(FAUCET.faucetSlot), String(localTokenSlot), 'faucet_refresh.json']);
      cli(ch, ['send', String(FAUCET.faucetSlot), String(slot), amount, 'faucet_payload.json', String(localTokenSlot)]);
      cli(ch, ['cosign', 'faucet_payload.json', 'faucet_cosigned.json']);
    } catch (e) {
      writeFaucetState(ch, faucetPolicy.settleDrip(readFaucetState(ch), slot, 'failed'));
      console.error(`[faucet] channel ${ch}: drip to slot ${slot} FAILED (reservation kept): ${String(e.stderr || e.message || e).slice(0, 200)}`);
      throw e;
    }
    writeFaucetState(ch, faucetPolicy.settleDrip(readFaucetState(ch), slot, 'done'));
    console.log(`[faucet] channel ${ch}: DRIPPED ${amount} of base token ${FAUCET.tokenIndex} to slot ${slot}`);
    const snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
    res.json({ ...snap, _faucet: { funded: true, alreadyFunded: false, amount, tokenIndex: FAUCET.tokenIndex, tokenSlot: localTokenSlot } });
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// POST /api/cosign-burn?channel=N  body: { debitPayload, transferDescriptor, amount?, recipient? }
// Co-sign a burn send (partial withdrawal debit leg).
app.post('/api/cosign-burn', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, () => {
    const active = findActiveTicket(ch, 'partial_withdrawal');
    // Every non-terminal PW ticket owns last_burn.json; settle_pending/settle_blocked are just as
    // unsafe to overwrite as burn_done.
    if (active) {
      res.status(409).json({ error: 'resolve the active partial withdrawal before burning again', ticket: active });
      return;
    }
    const { debitPayload, transferDescriptor } = req.body || {};
    if (!debitPayload || !transferDescriptor) throw new Error('cosign-burn needs { debitPayload, transferDescriptor }');
    fs.writeFileSync(wc(ch, 'burn_payload.json'), JSON.stringify(debitPayload));
    fs.writeFileSync(wc(ch, 'burn_descriptor.json'), JSON.stringify(transferDescriptor));
    cli(ch, ['cosign-burn-send', 'burn_payload.json', 'burn_descriptor.json', 'burn_cosigned.json']);
    const ticket = upsertTicket(ch, {
      id: 'pw_' + Date.now(),
      type: 'partial_withdrawal',
      status: 'burn_done',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      params: { amount: String(req.body.amount || ''), recipient: req.body.recipient || '' },
      steps: { burn: { completedAt: Date.now() }, settle: null },
    });
    const cosigned = JSON.parse(fs.readFileSync(wc(ch, 'burn_cosigned.json'), 'utf8'));
    res.json({ ...cosigned, _ticket: ticket });
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// POST /api/deploy-settlement?channel=N   (idempotent)
// Deploy ChannelSettlementManager + ChannelSettlementVerifier on anvil for this channel.
app.post('/api/deploy-settlement', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, () => {
    if (fs.existsSync(wc(ch, 'settlement.json'))) {
      return res.json(JSON.parse(fs.readFileSync(wc(ch, 'settlement.json'), 'utf8')));
    }
    cli(ch, ['deploy-settlement', RPC]);
    const s = JSON.parse(fs.readFileSync(wc(ch, 'settlement.json'), 'utf8'));
    let ticket = findActiveTicket(ch, 'full_withdrawal');
    if (!ticket) {
      ticket = { id: 'fw_' + Date.now(), type: 'full_withdrawal', status: 'deploy_done', createdAt: Date.now(), updatedAt: Date.now(),
        params: { manager: s.manager, verifier: s.verifier },
        steps: { deploy: { completedAt: Date.now(), manager: s.manager, verifier: s.verifier }, close: null, settle: null, withdraw: null, claim: null } };
    } else {
      ticket.status = 'deploy_done'; ticket.params.manager = s.manager; ticket.params.verifier = s.verifier;
      ticket.steps.deploy = { completedAt: Date.now(), manager: s.manager, verifier: s.verifier };
    }
    upsertTicket(ch, ticket);
    res.json(s);
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// GET /api/settlement?channel=N
app.get('/api/settlement', (req, res) => {
  try {
    const ch = reqChannel(req);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'settlement.json'), 'utf8')));
  } catch (e) { res.status(404).json({ error: 'no settlement deployed yet' }); }
});

// POST /api/pw-submit?channel=N
// Submit partial withdrawal intent on-chain.
app.post('/api/pw-submit', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, () => {
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (ticket) { ticket.status = 'settle_pending'; upsertTicket(ch, ticket); }
    if (!fs.existsSync(wc(ch, 'settlement.json'))) {
      cli(ch, ['deploy-settlement', RPC]);
    }
    const pwRecipient = (req.body && req.body.recipient) || (ticket && ticket.params.recipient) || '';
    const extra = pwRecipient ? { PW_RECIPIENT: pwRecipient } : {};
    cli(ch, ['pw-submit', RPC], extra);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'pw_auth.json'), 'utf8')));
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// POST /api/pw-finalize?channel=N
// Finalize partial withdrawal (advance time + finalize on-chain).
app.post('/api/pw-finalize', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, () => {
    cli(ch, ['pw-finalize', RPC]);
    const auth = JSON.parse(fs.readFileSync(wc(ch, 'pw_auth.json'), 'utf8'));
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (ticket) { ticket.status = 'settle_done'; ticket.steps.settle = { completedAt: Date.now(), authDigest: auth.auth_digest }; upsertTicket(ch, ticket); }
    res.json({ ok: true, authDigest: auth.auth_digest });
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// ─── Ticket endpoints ────────────────────────────────────────────────────────────────────────

app.get('/api/tickets', (req, res) => {
  const ch = reqChannel(req);
  res.json(readTickets(ch));
});

// Processed (terminal) tickets — deposits AND withdrawals — most recent first. Merges the durable
// history log with any terminal tickets still lingering in tickets.json (within TTL), deduped by id.
app.get('/api/tickets/history', (req, res) => {
  const ch = reqChannel(req);
  const hist = readHistory(ch);
  const seen = new Set(hist.map(t => t.id));
  const recent = readTickets(ch).filter(t => isTerminal(t) && !seen.has(t.id));
  const merged = hist.concat(recent).sort((a, b) => (a.archivedAt || a.updatedAt || 0) - (b.archivedAt || b.updatedAt || 0));
  res.json(merged.reverse());
});

// A deposit TICKET is a client-side recovery note, not an authority. Its `amount`/`depositor`/
// `tokenIndex` are DISPLAY ONLY and are never forwarded anywhere: `/api/import-deposit` accepts
// exactly { recipientSlot, txHash } and the CLI reads the real economics from the transaction's
// on-chain `Deposited` log. `tokenIndex` is normalized to a small non-negative integer (or dropped)
// purely so the pending/history UI can label an ERC-20 deposit instead of assuming ETH.
app.post('/api/ticket/deposit', (req, res) => {
  const ch = reqChannel(req);
  const { amount, depositor, txHash, recipientSlot, tokenIndex } = req.body || {};
  if (!amount || !depositor || !txHash) return res.status(400).json({ error: 'needs { amount, depositor, txHash, recipientSlot }' });
  const existing = findActiveTicket(ch, 'deposit');
  if (existing) return res.status(409).json({ error: 'deposit already pending', ticket: existing });
  const params = { amount: String(amount), depositor, recipientSlot: recipientSlot || 0, txHash };
  if (Number.isInteger(tokenIndex) && tokenIndex >= 0 && tokenIndex <= 0xffffffff) params.tokenIndex = tokenIndex;
  const ticket = upsertTicket(ch, {
    id: 'dep_' + Date.now(),
    type: 'deposit',
    status: 'l1_done',
    createdAt: Date.now(),
    updatedAt: Date.now(),
    params,
    steps: { l1: { completedAt: Date.now(), txHash }, import: null },
  });
  res.json(ticket);
});

// Static wallet files: wallet-live.html + wallet-worker.js from wallet/ (ROOT), and the built
// wasm under /pkg from the repo root (pkg/ is produced by build-wallet-wasm.sh at the repo root).
app.use('/pkg', express.static(path.join(REPO, 'pkg')));
app.use(express.static(ROOT));

const opts = {
  key: fs.readFileSync(path.join(REPO, 'self_certs', 'key.pem')),
  cert: fs.readFileSync(path.join(REPO, 'self_certs', 'cert.pem')),
};
// DURABLE membership across restarts (matches the EC2 relay): a restart does NOT wipe registered
// delegates / their slots. Pass RESET_CHANNELS=1 to deliberately start brand-new channels.
const RESET = process.env.RESET_CHANNELS === '1';
for (const ch of CHANNELS) {
  fs.mkdirSync(chDir(ch), { recursive: true });
  if (RESET) {
    fs.rmSync(wc(ch, 'cli_state.json'), { force: true });
    fs.rmSync(wc(ch, 'channel_snapshot.json'), { force: true });
    fs.rmSync(wc(ch, 'settlement.json'), { force: true });
    fs.rmSync(wc(ch, 'last_burn.json'), { force: true });
    fs.rmSync(wc(ch, 'pw_auth.json'), { force: true });
    fs.rmSync(wc(ch, 'pw_submit.json'), { force: true });
    fs.rmSync(wc(ch, TICKET_FILE), { force: true });
  }
}

// detail2 §F-1 deposit backing, REAL on-chain (no simulation): a local anvil chain really escrows
// each channel's deposit, the Rust witness is reconciled against the on-chain depositHashChain, and
// the channel's balance proof is built from THAT deposit. Each channel gets its OWN IntmaxRollup so
// its deposit is the first on that contract (prev hash 0). Done ONCE per channel (~40s each); the
// cached backing persists across relay restarts, so this only runs on the very first launch.
const RPC = 'http://127.0.0.1:8545';
const ANVIL0 = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const sh = (bin, args, o) => execFileSync(bin, args, { encoding: 'utf8', ...o });
const rpcUp = () => { try { sh('cast', ['block-number', '--rpc-url', RPC], { stdio: 'pipe' }); return true; } catch (e) { return false; } };

function ensureAnvil() {
  if (rpcUp()) return;
  console.log('  starting local anvil (Prague)…');
  spawn('anvil', ['--hardfork', 'prague', '--code-size-limit', '50000'], { stdio: 'ignore', detached: true }).unref();
  for (let i = 0; i < 60 && !rpcUp(); i++) { try { sh('sleep', ['0.5']); } catch (e) {} }
  if (!rpcUp()) { console.error('anvil did not come up on ' + RPC); process.exit(1); }
}
function deployRollup() {
  const out = sh('forge', ['script', 'script/Deploy.s.sol', '--rpc-url', RPC, '--private-key', ANVIL0, '--broadcast', '--code-size-limit', '50000'], { cwd: path.join(REPO, 'contracts') });
  const m = out.match(/IntmaxRollup\s*:\s*(0x[0-9a-fA-F]{40})/);
  if (!m) { console.error('could not parse IntmaxRollup address from forge output'); process.exit(1); }
  return m[1];
}

const needBacking = CHANNELS.filter((ch) =>
  !['channel_backing.json', 'channel_attestation.bin', 'balance_vd.bin'].every((f) => fs.existsSync(wc(ch, f)))
);
if (needBacking.length) {
  console.log(`Setting up REAL on-chain deposit backing (one-time) for channels: ${needBacking.join(', ')}…`);
  ensureAnvil();
  for (const ch of needBacking) {
    console.log(`  channel ${ch}: deploying its own IntmaxRollup…`);
    const addr = deployRollup();
    console.log(`  channel ${ch}: IntmaxRollup @ ${addr} — setup-backing (real ETH deposit + balance proof, ~30s)…`);
    cli(ch, ['setup-backing', RPC, addr]);
  }
}

// After backing exists (verification reads channel_backing.json's rollup).
loadTokenManifests(RPC);

https.createServer(opts, app).listen(PORT, '0.0.0.0', () => {
  console.log(`wallet relay on https://localhost:${PORT}/wallet-live.html  (channels ${CHANNELS.join(', ')})`);
});
const http = require('http');
const HTTP_PORT = PORT + 1;
http.createServer(app).listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(`wallet relay (HTTP) on http://localhost:${HTTP_PORT}/wallet-live.html`);
});
