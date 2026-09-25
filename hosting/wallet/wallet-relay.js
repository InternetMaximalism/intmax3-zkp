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
const {readTicketsFile, writeTicketsFile} = require('./wallet-ticket-store');
const sendReceipts = require('./send-receipts');
const burnOperations = require('../../api/lib/burn-operation').createBurnOperations();
// Signer-independent exit: any asset-moving CLI command (L1 deposit import included) refuses to
// sign until the resident block-producer/live-balance daemon has proved an exit kit for the exact
// successor. It lazily spawns target/release/block_producer_service on first use, against the same
// wallet-live-work/ch<N> directories this relay already writes to. `importL1Deposit` is the
// complete, crash-recoverable orchestration api/server.js already wires up (inspect -> post to the
// producer journal -> advance the live balance proof -> CLI cosign with its exit kit -> bind the
// signed snapshot -> sync off-chain heads); a bare `cli(ch, ['cosign-l1-deposit-import', ...])`
// only does the CLI step, and `liveBindSnapshot` alone fails because the live-balance proof was
// never advanced past genesis to include this deposit in the first place.
const { importL1Deposit, journalBackingDeposit } = require('../../api/lib/deposit-pipeline');
const { createCluster } = require('../../api/lib/cluster');
const producer = require('../../api/lib/block-producer');
const { flushPublishedHead } = require('../../api/lib/producer-head');
const { installHeadExitKit, cliWithPreparedExitKit, acknowledgePreparedExitKit, debitRequestId, OPERATION_FILE: EXIT_KIT_OPERATION_FILE } = require('../../api/lib/exit-kit');
const { interChannelSend, pendingInterTransfer, resumePendingInterTransfer } = require('../../api/lib/inter-channel-send');

// A `channel_member` failure prints its real diagnosis to STDOUT and only the persistent insecure-
// keys banner to STDERR, so reporting `e.stderr` alone hides the cause. Combine message, stdout and
// stderr (stripping the banner noise) into one readable error string for API responses and logs.
// The insecure-test-keys banner the CLI prints on stderr is an operator notice, not part of the
// error: strip it from every stream, including the `Command failed:` message execFileSync builds
// from stderr, and keep each distinct line once.
const stripBanner = (text) => String(text)
  .split('\n')
  .filter((l) => l.trim() && !l.startsWith('!!') && !/INSECURE DETERMINISTIC KEYS/.test(l))
  .join('\n');
function fullCliError(e) {
  const parts = [];
  if (e && e.message) parts.push(stripBanner(e.message));
  for (const stream of [e && e.stdout, e && e.stderr]) {
    if (!stream) continue;
    const text = stripBanner(stream);
    if (text.trim()) parts.push(text);
  }
  const seen = new Set();
  return parts.join('\n').split('\n').filter((l) => (seen.has(l) ? false : seen.add(l))).join('\n') || String(e);
}
const { execFileSync, spawn } = require('child_process');
const { createBatchWindow, projectToSlim, partitionByAnchor } = require('./batch-window');
const { publicBacking } = require('./public-backing');
const { installBrowserClaimRoutes } = require('./browser-claim-routes');

const ROOT = __dirname; // hosting/wallet/ — serves wallet-live.html + wallet-worker.js
const REPO = path.join(ROOT, '..', '..'); // repo root — target/, self_certs/, contracts/, pkg/, wallet-live-work/ live here (two levels up from hosting/wallet/)
const WORK = process.env.INTMAX_WORK_DIR || path.join(REPO, 'wallet-live-work');
const CLI = process.env.CHANNEL_MEMBER_BIN || path.join(REPO, 'target', 'release', 'channel_member');
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
const CHANNELS = (process.env.INTMAX_CHANNELS || '7,8,9,10').split(',').map(Number);
if (!CHANNELS.length || CHANNELS.some(ch => !Number.isSafeInteger(ch) || ch <= 0)) throw new Error('invalid INTMAX_CHANNELS');

fs.mkdirSync(WORK, { recursive: true });
const chDir = (ch) => path.join(WORK, 'ch' + ch);
const wc = (ch, n) => path.join(chDir(ch), n);
// Validate the channel from the request against the known set (never trust a raw query value as a
// path component). Defaults to the first channel.
// `?channel=` is REQUIRED on every channel route. An unknown/missing channel used to fall back to
// CHANNELS[0] silently, so a typo (`?channel=8x`) joined, co-signed or imported into channel 7.
function reqChannel(req) {
  const raw = req.query && req.query.channel;
  const c = /^\d+$/.test(String(raw ?? '')) ? Number(raw) : NaN;
  if (!CHANNELS.includes(c)) {
    throw Object.assign(new Error(`unknown channel ${JSON.stringify(raw ?? null)}; this relay serves channels ${CHANNELS.join(', ')}`), { status: 400 });
  }
  return c;
}
// Answer a route error: 400 for a bad request, 409 for a stale anchor, 500 otherwise.
function sendRouteError(res, e) {
  const error = fullCliError(e);
  console.error(error);
  const status = e && Number.isInteger(e.status) && e.status >= 400 && e.status <= 599
    ? e.status : (e && e.staleAnchor ? 409 : 500);
  res.status(status).json({ error });
}
// The CLI prints the insecure-test-keys notice on stderr on every run. It is an operator notice
// for the relay log, never part of a wallet-facing error: strip it (and the blank lines around
// it) from every stream of a failed command at the source, so no route can leak it to a browser.
const BANNER_LINE = /^!!|INSECURE DETERMINISTIC KEYS/;
function stripCliBanner(text) {
  return String(text).split('\n').filter((l) => !BANNER_LINE.test(l)).join('\n').replace(/\n{3,}/g, '\n\n').trim();
}
function sanitizeCliError(e) {
  if (!e || typeof e !== 'object') return e;
  for (const k of ['message', 'stderr', 'stdout']) if (typeof e[k] === 'string') e[k] = stripCliBanner(e[k]);
  return e;
}
function cli(ch, args, extraEnv) {
  console.log(`  $ INTMAX_CHANNEL=${ch} channel_member ${args.join(' ')}`);
  try {
    return execFileSync(CLI, args, {
      cwd: chDir(ch),
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      timeout: Number(process.env.INTMAX_CLI_TIMEOUT_MS || 1_200_000),
      env: { ...process.env, INTMAX_CHANNEL: String(ch), ...(extraEnv || {}) },
    });
  } catch (e) { throw sanitizeCliError(e); }
}

// Per-channel mutex: serialize all mutating CLI calls to prevent concurrent state corruption.
const _chLocks = {};
function withLock(ch, fn) {
  if (!_chLocks[ch]) _chLocks[ch] = Promise.resolve();
  const prev = _chLocks[ch];
  const run = async () => {
    // A pending burn owns this head. Finish its exact request before any later mutation can
    // invalidate the saved proof, including an incoming transfer targeting this channel.
    if (burnOperations.pending(ch)) await burnOperations.run(ch, {}, {
      findActiveTicket, upsertTicket,
      getTicket: (channel,id) => readTickets(channel).concat(readHistory(channel)).find(t => t.id === id),
    });
    return fn();
  };
  const next = prev.then(run, run);
  _chLocks[ch] = next.catch(() => {});
  return next;
}

// ─── Cluster co-signing (N <= 8 hosts, N-to-N signature exchange; api/lib/cluster.js) ────────
// Enabled by INTMAX_CLUSTER_SELF_URL (this relay's URL as the peers reach it) and
// INTMAX_CLUSTER_PEERS (JSON: [{"url":"http://host:8001","slots":[1]}, ...]). This host signs the
// slots in INTMAX_CLUSTER_SIGN_SLOTS (default: every slot its cli_state controls) with
// `cosign-partial`, exchanges signatures with the peers over /api/cluster/*, and adopts the N-of-N
// head with `cosign-merge`. Timings (ms, overridable for tests): INTMAX_CLUSTER_WARN_MS (60 s
// CLOSE WARNING naming the missing slots — holders supply them), INTMAX_CLUSTER_HALT_MS (5 min →
// channel HALTED, mutating routes answer 503), INTMAX_CLUSTER_CLOSE_MS (24 h halted → close at the
// last fully signed state through `close` with the ACTIVE settlement binding). Unset → the
// single-host `cosign` path, unchanged.
const clusterSelfUrl = process.env.INTMAX_CLUSTER_SELF_URL || '';
const clusterPeers = (() => {
  const raw = process.env.INTMAX_CLUSTER_PEERS;
  if (!raw) return null;
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error('INTMAX_CLUSTER_PEERS must be a JSON array');
  return parsed.map((p) => ({ url: String(p.url), slots: (p.slots || []).map(Number) }));
})();
const clusterSignSlots = (process.env.INTMAX_CLUSTER_SIGN_SLOTS || '').split(',').map((t) => t.trim()).filter(Boolean).map(Number);
const clusterMs = (name, dflt) => { const v = parseInt(process.env[name] || '', 10); return Number.isFinite(v) && v > 0 ? v : dflt; };

function readCliState(ch) { return JSON.parse(fs.readFileSync(wc(ch, 'cli_state.json'), 'utf8')); }
function readSnapshot(ch) { return JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')); }

const cluster = (clusterSelfUrl && clusterPeers) ? createCluster({
  self: { url: clusterSelfUrl, slots: clusterSignSlots },
  peers: clusterPeers,
  memberCount: (ch) => Number(readSnapshot(ch).record.memberCount),
  warnMs: clusterMs('INTMAX_CLUSTER_WARN_MS', 60_000),
  haltMs: clusterMs('INTMAX_CLUSTER_HALT_MS', 300_000),
  closeMs: clusterMs('INTMAX_CLUSTER_CLOSE_MS', 86_400_000),
  watchdogMs: clusterMs('INTMAX_CLUSTER_WATCHDOG_MS', 60_000),
  // This host's slot signatures over the gated successor (head NOT advanced).
  signPartial: (ch, payload) => withLock(ch, () => {
    fs.writeFileSync(wc(ch, 'payload.json'), JSON.stringify(payload));
    const env = clusterSignSlots.length ? { INTMAX_CLUSTER_SIGN_SLOTS: clusterSignSlots.join(',') } : {};
    cli(ch, ['cosign-partial', 'payload.json', 'partial_cosign.json'], env);
    return JSON.parse(fs.readFileSync(wc(ch, 'partial_cosign.json'), 'utf8'));
  }),
  // Verify every pooled signature and adopt the N-of-N head; exit 3 = still incomplete.
  merge: (ch, payload, signatures) => withLock(ch, async () => {
    fs.writeFileSync(wc(ch, 'payload.json'), JSON.stringify(payload));
    fs.writeFileSync(wc(ch, 'cluster_signatures.json'), JSON.stringify(signatures));
    try {
      cli(ch, ['cosign-merge', 'payload.json', 'cluster_signatures.json', 'cosigned.json']);
    } catch (e) {
      if (e && e.status === 3) {
        const line = String(e.stdout || '').trim().split('\n').pop();
        try { return JSON.parse(line); } catch (_) { /* fall through */ }
      }
      throw e;
    }
    // The live balance must follow EVERY signed head one step at a time (it refuses a bind that
    // skips a version), so bind + sync the producer head right after the N-of-N is adopted.
    await flushPublishedHead(ch);
    return { complete: true, state: JSON.parse(fs.readFileSync(wc(ch, 'cosigned.json'), 'utf8')) };
  }),
  post: async (url, path, body) => {
    const r = await fetch(url.replace(/\/$/, '') + path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    const text = await r.text();
    if (!r.ok) throw new Error(`${path} -> ${r.status} ${text.slice(0, 300)}`);
    return text ? JSON.parse(text) : null;
  },
  persistHalt: (ch, info) => {
    const f = wc(ch, 'cluster_halt.json');
    if (info) fs.writeFileSync(f, JSON.stringify(info)); else if (fs.existsSync(f)) fs.unlinkSync(f);
  },
  loadHalt: (ch) => { try { return JSON.parse(fs.readFileSync(wc(ch, 'cluster_halt.json'), 'utf8')); } catch (_) { return null; } },
  // Node-program rule: a channel halted for 24 h is closed at its LAST fully signed state (the
  // head every host adopted) through the ACTIVE settlement binding; never at the stalled proposal.
  onAutoClose: (ch, info) => withLock(ch, () => {
    const st = readCliState(ch);
    const manager = process.env.INTMAX_CLUSTER_CLOSE_MANAGER
      || (st.settlement_binding && st.settlement_binding.manager) || '';
    if (!manager) throw new Error('no ACTIVE settlement binding / INTMAX_CLUSTER_CLOSE_MANAGER to close against');
    const head = readSnapshot(ch).state;
    console.error(`[cluster] channel ${ch}: auto-closing at v${head.balanceState.stateVersion} (halted since ${new Date(info.since).toISOString()}, missing ${JSON.stringify(info.missing)})`);
    const out = cli(ch, ['close', manager, RPC], { CLOSE_SV: String(head.balanceState.stateVersion) });
    return { manager, stateVersion: head.balanceState.stateVersion, log: String(out).slice(-2000) };
  }),
}) : null;
if (cluster) console.log(`[cluster] enabled: self ${clusterSelfUrl} slots ${JSON.stringify(clusterSignSlots)}, peers ${JSON.stringify(clusterPeers)}`);

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
  const tickets = readTicketsFile(wc(ch, TICKET_FILE));
  const completed = new Map(readHistory(ch).filter(isTerminal).map(t => [t.id, t]));
  return tickets.map(t => completed.get(t.id) || t);
}
function writeTickets(ch, tickets) {
  writeTicketsFile(wc(ch, TICKET_FILE), tickets);
}
function readHistory(ch) {
  return readTicketsFile(wc(ch, HISTORY_FILE));
}
// Record a terminal ticket in the durable history (upsert by id so re-terminal writes don't dup).
function archiveTicket(ch, ticket) {
  const hist = readHistory(ch);
  const idx = hist.findIndex(t => t.id === ticket.id);
  const entry = { ...ticket, archivedAt: Date.now() };
  if (idx >= 0) hist[idx] = entry; else hist.push(entry);
  writeTicketsFile(wc(ch, HISTORY_FILE), hist.slice(-HISTORY_CAP));
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
    !isTerminal(t) || (now - t.updatedAt) < TICKET_TTL
  );
  if (isTerminal(ticket)) archiveTicket(ch, ticket);
  writeTickets(ch, kept); // durable "processed" record (deposits + withdrawals)
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
app.get('/api/channels', (req, res) => res.json({
  channels: CHANNELS,
  availableForJoin: CHANNELS.filter(ch => !fs.existsSync(wc(ch, 'cli_state.json'))),
}));

// Step 1 (delegate demo): browser sends its DELEGATE genesis contribution → CLI builds the channel
// with 3 co-signing members + the browser delegate, the 3 members sign the genesis, and the CLI
// returns the FULLY-SIGNED snapshot for the browser to import directly (the delegate does NOT sign
// the genesis). CREATE-OR-JOIN: the first browser creates channel N; each later browser JOINS the
// SAME channel N as a distinct delegate. cli_state.json is reset only on relay startup.
// While a channel is HALTED (cluster protocol), every mutating route answers 503 — except the
// close/settle/withdraw family, which is exactly what a halted channel is allowed to do.
const HALT_EXEMPT = new Set(['/api/close', '/api/settle', '/api/withdraw', '/api/deploy-settlement', '/api/cancel-close', '/api/claim', '/api/exit-kit/install']);
app.use((req, res, next) => {
  if (!cluster || req.method !== 'POST' || req.path.startsWith('/api/cluster/') || HALT_EXEMPT.has(req.path) || req.path.startsWith('/api/browser-claim/')) return next();
  let ch;
  try { ch = reqChannel(req); } catch (e) { return next(); } // the route reports the bad channel itself
  const h = cluster.halted(ch);
  if (h) return res.status(503).json({ error: `channel ${reqChannel(req)} is HALTED since ${new Date(h.since).toISOString()}: cosigner slots ${JSON.stringify(h.missing)} did not sign round ${h.nextDigest}`, halted: h });
  return next();
});

// Cluster peer endpoints (bodies carry `channel`). Only meaningful with INTMAX_CLUSTER_*.
const clusterRoute = (handler) => (req, res) => {
  if (!cluster) return res.status(404).json({ error: 'cluster co-signing is not enabled on this relay' });
  Promise.resolve().then(() => handler(req.body || {})).then(
    (out) => res.json(out),
    (e) => { console.error(e.stderr ? String(e.stderr) : (e.message || e)); res.status(e.halted ? 503 : 500).json({ error: String(e.stderr || e.message || e) }); },
  );
};
app.post('/api/cluster/propose', clusterRoute((b) => cluster.onPropose(b)));
app.post('/api/cluster/signature', clusterRoute((b) => cluster.onSignature(b)));
app.post('/api/cluster/missing', clusterRoute((b) => cluster.onMissing(b)));
app.post('/api/cluster/halt', clusterRoute((b) => cluster.onHalt(b)));
app.get('/api/cluster/status', (req, res) => {
  if (!cluster) return res.json({ enabled: false });
  res.json({ enabled: true, ...cluster.status(reqChannel(req)), constants: cluster.constants });
});

app.post('/api/init', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
    fs.mkdirSync(chDir(ch), { recursive: true });
    const stateFile = wc(ch, 'cli_state.json');
    if (fs.existsSync(stateFile)) {
      const existing = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      require('../../node/common/wallet-join-identity').assertJoinIdentity(existing.snapshot, req.body, !!existing.settlement_binding);
    }
    fs.writeFileSync(wc(ch, 'contribution.json'), JSON.stringify(req.body));
    cli(ch, ['init', 'contribution.json', 'channel_snapshot.json']);
    const snapshot = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
    require('../../api/lib/cli').ensureSettlement(ch);
    // `init` is create OR join. A delegate JOIN advances the signed head (a new zero-balance
    // delegate at the boundary, H2=0, epoch+1) while leaving every asset cursor untouched. That
    // new head must be propagated to the daemon's THREE durable stores or the channel is left
    // inconsistent: a later deposit's bind fails "settle chain differs"/"record changed", and a
    // refresh/send fails "SIGNER-INDEPENDENT EXIT REQUIRED: predecessor has no exit-kit receipt".
    // Only propagate once the channel actually has a bound live balance (a funded/adopted channel);
    // an unbound genesis has nothing to advance and the first deposit's adoption binds it fresh.
    // liveBindSnapshot is idempotent, so the initial create and idempotent re-joins are no-ops here.
    if (producer.liveSnapshotExists(ch)) {
      const st = await producer.liveStatus(ch);
      if (Number(st.appliedTransitionCount) > 0 && !st.awaitingChannelBinding) {
        await producer.liveBindSnapshot(ch, snapshot); // live balance follows (delegate-add gate)
        await flushPublishedHead(ch);                  // producer public head follows
        await installHeadExitKit(ch);                  // install the exit-kit receipt for the new head
      }
    } else {
      // An EMPTY-genesis channel (`setup-backing` with SETUP_BACKING_EMPTY_GENESIS — every local
      // channel after the first, see bootstrapBacking) has no backing deposit to adopt, so the
      // durable live-balance spine starts HERE, exactly as `api/routes/channel-init.js` does:
      // create the balance on the channel's base account, bind the signed genesis (an empty proof
      // matches it) and register the channel. A funded genesis is adopted lazily by the first
      // import instead (`ensureLiveBackingAdopted`).
      const backing = JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'));
      if (!backing.deposit_tx) {
        const accountSalt = backing.base_private_state && backing.base_private_state.salt;
        if (accountSalt) await producer.liveInitWithAccountSalt(ch, accountSalt);
        else await producer.liveInit(ch);
        await producer.liveBindSnapshot(ch, snapshot);
        await require('../../api/lib/live-registration').ensureLiveRegistration(ch, snapshot);
        // The empty genesis is a signed head like any other: without its signer-independent
        // exit-kit receipt the co-signer refuses the channel's FIRST inter-channel credit
        // ("destination signer exit-kit verification: ... no signer exit-kit receipt is installed").
        await installHeadExitKit(ch);
      }
    }
    // Optional operator-provisioned tokens use the same real exit-kit/signing pipeline as
    // the authenticated API. Never derive registry identities from browser input or labels.
    const initialTokens = (process.env.INTMAX_INITIAL_TOKEN_INDICES || '').split(',').filter(Boolean).map(Number);
    if (initialTokens.some(t => !Number.isInteger(t) || t < 1 || t > 0xffffffff)) throw new Error('invalid initial token indices');
    if (initialTokens.length) {
      const registry = TOKEN_REGISTRIES[ch];
      if (!registry) throw new Error('initial tokens require a chain-verified token manifest');
      await registry.verifyAgainstChain(RPC, rollupOf(ch), { logger: console });
      await require('../../api/lib/deposit-pipeline').ensureLiveBackingAdopted(ch);
      await flushPublishedHead(ch);
      await installHeadExitKit(ch);
      for (const tokenIndex of initialTokens) {
        if (!registry.metadataFor(tokenIndex).verified) throw new Error('initial token is not chain-verified');
        if (channelTokens(ch).tokens.some(t => t.tokenIndex === tokenIndex)) continue;
        await cliWithPreparedExitKit(ch, ['register-token', String(tokenIndex), 'token_register_cosigned.json']);
        const registered = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
        await require('../../api/lib/producer-head').publishOffchainSnapshot(ch, registered.state);
        // Replace the pre-sign envelope with the actual N-of-N signed head archive.
        await installHeadExitKit(ch);
      }
    }
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')));
  }).catch((e) => {
    const detail = fullCliError(e);
    console.error(detail);
    // Forge traces contain thousands of lines. Keep the actual final diagnosis visible,
    // with the complete trace retained in the operator log instead of flooding the wallet.
    const diagnosis = detail.split('\n').filter(line => /^(?:error:|Error: script failed:)/i.test(line.trim())).pop();
    const message = diagnosis || detail;
    res.status(e.status === 409 ? 409 : 500).json({ code: e.code || 'JOIN_FAILED', error: message.length > 1200
      ? message.slice(0, 1200) + '… (full details in relay log)' : message });
  });
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
  } catch (e) {
    if (e && e.status) return sendRouteError(res, e); // unknown channel is a 400, not "no channel yet"
    return res.status(404).json({ error: 'no channel yet' });
  }
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
  const ch = reqChannel(req);
  // Serve the daemon's LIVE base cursor (not the frozen setup-time channel_backing.json): an
  // inter-channel/burn/withdrawal debit MUST be built at the authoritative nonce the co-sign will
  // enforce, or it is debited-then-stranded. The relay now has daemon access, so it can. On any
  // daemon error, 409 rather than fall back to the frozen file (that fallback is the strand bug).
  producer.liveBaseHead(ch).then((live) => {
    const nonce = live && live.baseNonce;
    if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff) {
      throw new Error('live base nonce is unavailable from the producer');
    }
    res.json({ schemaVersion: 1, nonce, settledTxChain: (live && live.settledTxChain) ?? null, source: 'liveBaseHead' });
  }).catch((e) => { res.status(409).json({ error: String(e.message || e) }); });
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
  let ch;
  try { ch = reqChannel(req); } catch (e) { return sendRouteError(res, e); }
  withLock(ch, () => {
    fs.writeFileSync(wc(ch, 'browser_sig.json'), JSON.stringify(req.body));
    cli(ch, ['add-genesis-sig', 'browser_sig.json', 'channel_snapshot.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')));
  }).catch((e) => sendRouteError(res, e));
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
// Cluster mode co-signs one proposal per round (cosign-partial / cosign-merge have no batch form
// yet), so the window cap is forced to 1 there.
const BATCH_WINDOW_MAX = cluster ? 1 : Math.max(1, Math.min(1024, parseInt(process.env.BATCH_WINDOW_MAX || '200', 10) || 200));

function drainCosignWindow(ch, entries) {
  return withLock(ch, async () => {
    const accepted = [], rejected = new Set();
    for (const en of entries) {
      try {
        const prior = sendReceipts.accepted(chDir(ch), sendReceipts.fatId(en.payload));
        if (prior) accepted.push({en,prior});
      } catch (error) { rejected.add(en); en.reject(error); }
    }
    if (accepted.length) {
      await flushPublishedHead(ch);
      for (const {en,prior} of accepted) en.resolve(prior);
    }
    entries = entries.filter(en => !rejected.has(en) && !accepted.some(x => x.en === en));
    if (!entries.length) return;
    const snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
    // Lost-response retry of an exact solo transition. Reconcile its committed head before
    // answering; never re-sign against a later head merely because the browser retried.
    const replayed = entries.filter(en => /^0x0{64}$/i.test(String(snap.state.h2Tag))
      && en.payload?.proposedNextState?.digest === snap.state.digest
      && en.payload.proposedNextState.channelId === snap.state.channelId);
    if (replayed.length) {
      await flushPublishedHead(ch);
      for (const en of replayed) en.resolve(snap.state);
    }
    const { fresh, stale } = partitionByAnchor(entries.filter(en => !replayed.includes(en)), snap.state.digest);
    for (const en of stale) {
      const err = new Error('staleAnchor: payload does not extend the current head — re-sign against the latest snapshot');
      err.staleAnchor = true;
      en.reject(err);
    }
    if (fresh.length === 0) return;
    // Every co-signed in-channel head is bound to the resident live balance and synced to the
    // producer head at once (`flushPublishedHead`): the live service refuses a bind that skips a
    // version, so two sends before the next deposit import used to leave the channel
    // unimportable ("ordinary signed head skips, forks, rolls back, or changes close era").
    const soloOne = async (en) => {
      try {
        fs.writeFileSync(wc(ch, 'payload.json'), JSON.stringify(en.payload));
        cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
        await flushPublishedHead(ch);
        en.resolve(JSON.parse(fs.readFileSync(wc(ch, 'cosigned.json'), 'utf8')));
      } catch (e) { en.reject(e); }
    };
    if (cluster) {
      // The protocol takes the channel lock itself per CLI step (signPartial / merge run on every
      // host, including this one, from peer callbacks), so the round must NOT run under this
      // drain's lock: kick it off and return, releasing the lock at once.
      const en = fresh[0];
      cluster.cosign(ch, en.payload).then(en.resolve, en.reject);
      return;
    }
    if (fresh.length === 1) return soloOne(fresh[0]);
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
      await flushPublishedHead(ch);
      const result = JSON.parse(fs.readFileSync(wc(ch, 'batch_cosigned.json'), 'utf8'));
      for (const en of fresh) en.resolve(result);
    } catch (e) {
      // A failed call may already have committed. Resolve acceptance first; only genuinely
      // unaccepted requests may fall back to solo signing (bounded by BATCH_WINDOW_MAX).
      console.error(`[batch] channel ${ch}: batch processing interrupted (${String(e.stderr || e.message || e).slice(0, 200)}); checking receipts before solo fallback`);
      // Sequentially: `soloOne` awaits the head flush, and each solo cosign advances the head, so a
      // later payload that still extends the OLD head is a stale anchor (409 → the wallet re-signs)
      // rather than a generic CLI failure. Parallel replay overwrote payload.json/cosigned.json and
      // released this lock with flushes still in flight.
      for (const en of fresh) {
        if (en.settled) continue;
        // Signing can commit before publication/backing fails. Never turn that ambiguity into
        // staleAnchor (which authorizes the wallet to create a different payment).
        try {
          const committed = sendReceipts.accepted(chDir(ch), sendReceipts.fatId(en.payload));
          if (committed) {
            await flushPublishedHead(ch);
            en.resolve(committed);
            continue;
          }
        } catch (recoveryError) { en.reject(recoveryError); continue; }
        const head = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')).state.digest;
        if (String(en.payload.proposedNextState.prevDigest).toLowerCase() !== String(head).toLowerCase()) {
          const err = new Error('staleAnchor: payload does not extend the current head — re-sign against the latest snapshot');
          err.staleAnchor = true; en.reject(err); continue;
        }
        await soloOne(en);
      }
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
      const error = fullCliError(e);
      console.error(error);
      // A KIT-PENDING head is a channel condition, not a relay failure: say which transition is
      // holding the channel (an inter-channel credit still pending on its source channel).
      const kitPending = /KIT-PENDING/.test(error) ? kitPendingHint(ch) : null;
      res.status(e.staleAnchor || kitPending ? 409 : 500).json(kitPending ? { error, ...kitPending } : { error });
    }
  );
});

// Inter-channel transfers still pending on any source channel whose destination is `ch`: these
// are the transitions that advanced `ch`'s signed head without an exit kit yet.
function kitPendingHint(ch) {
  const blocking = [];
  for (const source of CHANNELS) {
    let p = null;
    try { p = pendingInterTransfer(source); } catch (e) { continue; }
    if (p && p.destination === ch) blocking.push({ sourceChannel: source, producerRequestId: p.producerRequestId, signed: p.signed, createdAt: p.createdAt });
  }
  return {
    kitPending: true,
    hint: blocking.length
      ? `channel ${ch} is waiting for ${blocking.length} pending inter-channel credit(s) to be accepted by the live balance service; until then it cannot sign sends`
      : `channel ${ch}'s head has no exit-kit receipt; try POST /api/exit-kit/install?channel=${ch}`,
    blockingTransfers: blocking,
  };
}

// Balance-refresh: browser re-encrypts its own slot (RefreshPayload) → CLI members co-sign → returns
// the fully-signed next state for the browser to finalize. Lets a delegate send again after receiving.
app.post('/api/refresh-cosign', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
    fs.writeFileSync(wc(ch, 'refresh_payload.json'), JSON.stringify(req.body));
    cli(ch, ['cosign-refresh', 'refresh_payload.json', 'refresh_cosigned.json']);
    await flushPublishedHead(ch); // the live balance refuses a later bind that skips this version
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'refresh_cosigned.json'), 'utf8')));
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// Inter-channel send (SINGLE atomic endpoint). `?channel=A` = the SOURCE channel; the relay OWNS both
// channels, so this one command debits A and credits B atomically — there is NO standalone credit
// endpoint that would trust a request-body signed state (CRITICAL-1).
// Body = { debitPayload, transferDescriptor }. Both are written into A's dir; the combined
// `cosign-inter-transfer` co-signs A's debit (extending A's COMMITTED head), validates + credits B
// (resolved as ../ch<dest>/), and persists both only if both legs pass. Returns { aHead, bSnapshot }.
// Lock BOTH channels of an inter-channel transfer in sorted order so a concurrent B→A transfer
// can never deadlock against an A→B one.
function withInterLocks(a, b, fn) {
  if (!Number.isSafeInteger(b) || b === a) return withLock(a, fn);
  return a < b ? withLock(a, () => withLock(b, fn)) : withLock(b, () => withLock(a, fn));
}

// Sender-independent completion of an inter-channel transfer. Once `cosign-inter-transfer` has
// committed the debit, the transfer MUST land on the destination even if the browser that started
// it is gone: the relay retains the exact request and resumes it (a) before any new inter-channel
// send on that source channel, (b) at startup, and (c) on a periodic sweep. A resume that still
// fails (destination rejecting, daemon down) is logged and retried on the next occasion; the
// source channel keeps refusing a DIFFERENT transfer until it lands (409 from the shared module).
async function resumePendingInterTransferLocked(ch) {
  const pending = pendingInterTransfer(ch);
  if (!pending) return null;
  console.log(`[inter] channel ${ch}: resuming pending transfer ${pending.producerRequestId} → channel ${pending.destination} (signed=${pending.signed})`);
  return withInterLocks(ch, pending.destination, () => resumePendingInterTransfer(ch));
}
const INTER_RESUME_MS = Math.max(5000, parseInt(process.env.INTMAX_INTER_RESUME_MS || '30000', 10) || 30000);
async function sweepPendingInterTransfers() {
  for (const ch of CHANNELS) {
    try {
      if (burnOperations.pending(ch)) await withLock(ch, () => burnOperations.run(ch, {}, {findActiveTicket,upsertTicket,getTicket:(ch,id)=>readTickets(ch).concat(readHistory(ch)).find(t=>t.id===id)}));
    } catch (error) { console.error('[burn recovery]', ch, String(error.message || error).slice(0,300)); }
    try {
      const r = await resumePendingInterTransferLocked(ch);
      if (r) console.log(`[inter] channel ${ch}: pending transfer resumed → ${r.status}`);
    } catch (e) {
      console.error(`[inter] channel ${ch}: pending transfer resume failed (will retry): ${String(e.stderr || e.message || e).slice(0, 300)}`);
    }
  }
}

// Ops: (re)archive the live balance service's exit kit for a channel's CURRENT head into the CLI
// state (`install-exit-kit`). Repairs a channel whose signer receipt is stale or unverifiable.
app.post('/api/exit-kit/install', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, () => installHeadExitKit(ch)).then(
    (out) => res.json({ ok: true, channel: ch, log: String(out || '').slice(-400) }),
    (e) => { const full = fullCliError(e); console.error(full); res.status(500).json({ error: full }); },
  );
});

app.get('/api/inter/pending', (req, res) => {
  const ch = reqChannel(req);
  const p = pendingInterTransfer(ch);
  res.json(p ? { pending: true, channel: ch, destination: p.destination, signed: p.signed, producerRequestId: p.producerRequestId, createdAt: p.createdAt } : { pending: false, channel: ch });
});

app.post('/api/inter/send', (req, res) => {
  const ch = reqChannel(req); // = source channel A
  const descriptor = req.body && req.body.transferDescriptor;
  const destination = descriptor && Number(descriptor.destinationChannelId);
  if (!CHANNELS.includes(destination)) {
    return res.status(400).json({ error: `destination channel ${JSON.stringify(descriptor && descriptor.destinationChannelId)} is not served by this relay (channels ${CHANNELS.join(', ')})` });
  }
  // The daemon-backed shared module supplies the resident base-state nonce the legacy relay used
  // to lack (hence the old 503). Any transfer left pending on this source channel is completed
  // FIRST, so an abandoned sender never blocks the next one.
  const runLocked = () => interChannelSend(ch, {
    debitPayload: req.body && req.body.debitPayload,
    transferDescriptor: descriptor,
    tokenIndex: req.body && req.body.tokenIndex,
  }).then(({ status, body }) => res.status(status).json(body));
  resumePendingInterTransferLocked(ch)
    .catch((e) => console.error(`[inter] channel ${ch}: pending transfer resume failed before a new send: ${String(e.stderr || e.message || e).slice(0, 300)}`))
    .then(() => withInterLocks(ch, destination, runLocked))
    .catch((e) => sendRouteError(res, e));
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
  let ch;
  try { ch = reqChannel(req); } catch (e) { return sendRouteError(res, e); }
  withLock(ch, () => {
    const manager = req.body && req.body.manager;
    const sv = (req.body && req.body.sv) || '';
    if (!manager) throw new Error('close needs { manager }');
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) { ticket.status = 'close_pending'; upsertTicket(ch, ticket); }
    const out = cli(ch, ['close', manager, RPC], { CLOSE_SV: sv });
    if (ticket) { ticket.status = 'close_done'; ticket.steps.close = { completedAt: Date.now() }; upsertTicket(ch, ticket); }
    res.json({ ok: true, log: out });
  }).catch((e) => sendRouteError(res, e));
});

// POST /api/settle?channel=N  body: { manager }
app.post('/api/settle', (req, res) => {
  let ch;
  try { ch = reqChannel(req); } catch (e) { return sendRouteError(res, e); }
  withLock(ch, () => {
    const manager = req.body && req.body.manager;
    if (!manager) throw new Error('settle needs { manager }');
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) { ticket.status = 'settle_pending'; upsertTicket(ch, ticket); }
    const out = cli(ch, ['settle', manager, RPC]);
    if (ticket) { ticket.status = 'settle_done'; ticket.steps.settle = { completedAt: Date.now() }; upsertTicket(ch, ticket); }
    res.json({ ok: true, log: out });
  }).catch((e) => sendRouteError(res, e));
});

// POST /api/withdraw?channel=N  body: { manager }  (rollup→manager via the full withdrawal pipeline)
app.post('/api/withdraw', (req, res) => {
  let ch;
  try { ch = reqChannel(req); } catch (e) { return sendRouteError(res, e); }
  withLock(ch, () => {
    const manager = req.body && req.body.manager;
    if (!manager) throw new Error('withdraw needs { manager }');
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) { ticket.status = 'withdraw_pending'; upsertTicket(ch, ticket); }
    const out = cli(ch, ['withdraw', manager, RPC], { ROLLUP: rollupOf(ch) });
    if (ticket) { ticket.status = 'withdraw_done'; ticket.steps.withdraw = { completedAt: Date.now() }; upsertTicket(ch, ticket); }
    res.json({ ok: true, log: out });
  }).catch((e) => sendRouteError(res, e));
});

// Retired: this let the caller choose manager/slot/recipient and moved the Regev witness into the
// relay-owned CLI. Browser claims now use /api/browser-claim/*: the browser WASM owns the witness,
// while the relay derives every public authority from its durable settlement binding.
app.post('/api/claim', (req, res) => {
  void req;
  res.status(410).json({ error: 'legacy relay-owned claim is retired; use /api/browser-claim/*' });
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
  let ch;
  try { ch = reqChannel(req); } catch (e) { return sendRouteError(res, e); }
  withLock(ch, () => {
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
  }).catch((e) => sendRouteError(res, e));
});

// POST /api/import-deposit?channel=N  body: { recipientSlot, depositor?, amount? }
// Fold a pending L1 deposit into the channel's balance (mid-channel deposit).
// If depositor+amount are provided (MetaMask flow), uses those directly.
// Otherwise reads from pending_deposit.json (fallback relay-deposit flow).
// SECURITY: mirrors the EC2 relay — `depositor`/`amount` are no longer accepted; the CLI reads
// them from the on-chain `Deposited` log. See doc/tasks/deposit-import-threat-model.md.
app.post('/api/import-deposit', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
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
    await importL1Deposit(ch, slot, txHash, { allowUnboundDepositor: operatorFunded });
    const depTicket = findActiveTicket(ch, 'deposit');
    if (depTicket && String(depTicket.params?.txHash).toLowerCase() === txHash.toLowerCase()) { depTicket.status = 'import_done'; depTicket.steps.import = { completedAt: Date.now() }; upsertTicket(ch, depTicket); }
    const snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
    res.json(snap);
    // A failing `channel_member` step writes its real diagnosis to STDOUT and only its persistent
    // key-safety banner to STDERR, so `e.stderr` alone hides the actual cause (a CLI exit surfaced
    // as just the banner). Surface message + stdout + stderr so the wallet shows why an import
    // failed instead of an opaque warning.
  }).catch((e) => { const full = fullCliError(e); console.error(full); res.status(500).json({ error: full }); });
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
  withLock(ch, async () => {
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
      // No refresh leg: `send` opens the faucet's position by DECRYPTION (refresh-free
      // decrypted-send proof), so the L1-deposit-imported supply and every previous drip's
      // `after` are spendable directly; every co-signer re-verifies the proof before signing.
      cli(ch, ['send', String(FAUCET.faucetSlot), String(slot), amount, 'faucet_payload.json', String(localTokenSlot)]);
      cli(ch, ['cosign', 'faucet_payload.json', 'faucet_cosigned.json']);
      await flushPublishedHead(ch); // same one-version-at-a-time rule as every other cosign
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
  withLock(ch, async () => {
    const cosignedHead = await burnOperations.run(ch, req.body, {findActiveTicket,upsertTicket,getTicket:(ch,id)=>readTickets(ch).concat(readHistory(ch)).find(t=>t.id===id)});
    res.json(cosignedHead);
  }).catch((e) => sendRouteError(res, e));
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
      ticket = { id: 'fw_' + crypto.randomUUID(), type: 'full_withdrawal', status: 'deploy_done', createdAt: Date.now(), updatedAt: Date.now(),
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
  withLock(ch, async () => {
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (ticket && ticket.status === 'claim_pending') {
      return res.json(JSON.parse(fs.readFileSync(wc(ch, 'pw_auth.json'), 'utf8')));
    }
    const submitted = require('../../api/lib/partial-withdrawal-live').resumeSubmittedAuth(ch);
    if (submitted) return res.json(submitted);
    const before = ticket && ticket.status;
    if (ticket) { ticket.status = 'settle_pending'; upsertTicket(ch, ticket); }
    try {
      if (!fs.existsSync(wc(ch, 'settlement.json'))) {
        cli(ch, ['deploy-settlement', RPC]);
      }
      const pwRecipient = (req.body && req.body.recipient) || (ticket && ticket.params.recipient) || '';
      const extra = pwRecipient ? { PW_RECIPIENT: pwRecipient } : {};
      await require('../../api/lib/wallet-l1').publish(ch);
      const proofEnv = await require('../../api/lib/partial-withdrawal-live').stageSubmitProof(ch);
      await require('../../api/lib/wallet-l1').attest(ch, await producer.liveBackingArtifact(ch));
      cli(ch, ['pw-submit', RPC], { ...extra, ...proofEnv, INTMAX_WALLET_ANVIL_MINE: '1' });
    } catch (e) {
      // A failed submit is retryable: put the ticket back instead of leaving it settle_pending.
      if (ticket) { ticket.status = before; upsertTicket(ch, ticket); }
      throw e;
    }
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'pw_auth.json'), 'utf8')));
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(Number.isInteger(e.status) && e.status >= 400 && e.status <= 599 ? e.status : 500).json({ error: String(e.stderr || e.message || e) }); });
});

// POST /api/pw-finalize?channel=N
// Finalize partial withdrawal (advance time + finalize on-chain).
app.post('/api/pw-finalize', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
    const existing = findActiveTicket(ch, 'partial_withdrawal');
    if (existing && existing.status === 'claim_pending') {
      const auth = JSON.parse(fs.readFileSync(wc(ch, 'pw_auth.json'), 'utf8'));
      return res.json({ ok: true, authDigest: auth.auth_digest, claim: existing.params.claim });
    }
    await require('../../api/lib/partial-withdrawal-live').stagePayoutArtifacts(ch);
    await require('../../api/lib/partial-withdrawal-live').finalizeSavedPayout(ch, {
      rpc: RPC, run: cli, env: { INTMAX_WALLET_ANVIL_MINE: '1' },
    });
    const auth = JSON.parse(fs.readFileSync(wc(ch, 'pw_auth.json'), 'utf8'));
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    let claim = ticket && ticket.params.claim || null;
    const helper = require('../../api/lib/cli');
    if (!claim && helper.l1SignerAddress().toLowerCase() !== auth.withdrawal_recipient.toLowerCase()) {
      claim = require('../../node/common/partial-withdrawal-pull').pullTransaction(auth, rollupOf(ch));
      claim.afterBlock = helper.sh('cast', ['rpc', 'eth_blockNumber', '--rpc-url', RPC]).trim().replace(/"/g, '');
    }
    if (ticket) { ticket.status = claim ? 'claim_pending' : 'settle_done'; ticket.params.claim = claim; ticket.steps.settle = { completedAt: Date.now(), authDigest: auth.auth_digest }; upsertTicket(ch, ticket); }
    res.json({ ok: true, authDigest: auth.auth_digest, claim });
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// The receiver pulls the credited amount through MetaMask; verify that exact mined call.
app.post('/api/pw-claim-confirm', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, () => {
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    const hash = String(req.body && req.body.txHash || '');
    // A successful confirmation can lose its response. A retry must return that same completion,
    // even if a subsequent withdrawal has started, without modifying the new ticket.
    const done = readTickets(ch).concat(readHistory(ch)).find(t => t.type === 'partial_withdrawal'
      && t.status === 'settle_done' && t.steps && t.steps.claim
      && String(t.steps.claim.txHash).toLowerCase() === hash.toLowerCase());
    if (done && /^0x[0-9a-fA-F]{64}$/.test(hash)) return res.json({ok:true});
    if (!ticket || ticket.status !== 'claim_pending' || !ticket.params.claim) throw new Error('no pending wallet payout');
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error('invalid payout transaction hash');
    const { sh } = require('../../api/lib/cli');
    const rpc = (method, arg) => JSON.parse(sh('cast', ['rpc', method, arg, '--rpc-url', RPC]));
    const tx = rpc('eth_getTransactionByHash', hash), receipt = rpc('eth_getTransactionReceipt', hash);
    if (!receipt) throw new Error('wallet payout is not mined yet');
    const block = JSON.parse(sh('cast', ['rpc', 'eth_getBlockByNumber', receipt.blockNumber, 'false', '--rpc-url', RPC]));
    require('../../node/common/partial-withdrawal-pull').verifyPull(ticket.params.claim, tx, receipt, block);
    ticket.status = 'settle_done'; ticket.steps.claim = { completedAt: Date.now(), txHash: hash }; upsertTicket(ch, ticket);
    res.json({ ok: true });
  }).catch(e => res.status(409).json({ error: e.message }));
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
  const known = readTickets(ch).concat(readHistory(ch)).find(t => t.type === 'deposit'
    && t.params && String(t.params.txHash).toLowerCase() === String(txHash).toLowerCase());
  if (known) return res.json(known);
  const existing = findActiveTicket(ch, 'deposit');
  if (existing) return res.status(409).json({ error: 'deposit already pending', ticket: existing });
  const params = { amount: String(amount), depositor, recipientSlot: recipientSlot || 0, txHash };
  if (Number.isInteger(tokenIndex) && tokenIndex >= 0 && tokenIndex <= 0xffffffff) params.tokenIndex = tokenIndex;
  const ticket = upsertTicket(ch, {
    id: 'dep_' + crypto.randomUUID(),
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
const RPC = process.env.RPC || 'http://127.0.0.1:8545';
installBrowserClaimRoutes(app, { reqChannel, wc, rollupOf, cli, rpc: RPC });
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
  // --slow: concurrent tx submission hangs forge's broadcaster indefinitely against a local
  // anvil in this environment (observed: it stalls forever right after the local simulation,
  // before sending anything, regardless of anvil's mining mode). Sending and confirming one
  // transaction at a time avoids it.
  const out = sh('forge', ['script', 'script/Deploy.s.sol', '--rpc-url', RPC, '--private-key', ANVIL0, '--broadcast', '--slow', '--code-size-limit', '50000'], { cwd: process.env.CONTRACTS_DIR || path.join(REPO, 'contracts'), env: { ...process.env, WALLET_VALIDITY_CONFIG: require('../../api/lib/wallet-l1').deploymentConfig() } });
  const m = out.match(/IntmaxRollup\s*:\s*(0x[0-9a-fA-F]{40})/);
  if (!m) { console.error('could not parse IntmaxRollup address from forge output'); process.exit(1); }
  return m[1];
}

const needBacking = CHANNELS.filter((ch) =>
  !['channel_backing.json', 'channel_attestation.bin', 'balance_vd.bin'].every((f) => fs.existsSync(wc(ch, f)))
);
async function bootstrapBacking() {
  if (!needBacking.length) {
    require('../../api/lib/wallet-l1').configure(rollupOf(CHANNELS[0]));
    return;
  }
  console.log(`Setting up REAL on-chain deposit backing (one-time) for channels: ${needBacking.join(', ')}…`);
  ensureAnvil();
  // ONE IntmaxRollup shared by every channel. The block producer is shared too and journals ONE
  // L1 deposit sequence (`deposit_index` must be consecutive), so per-channel rollups — each
  // restarting its on-chain deposit index at 0 — could never all be adopted: the second channel's
  // backing deposit (on-chain index 0) was refused with "producer expects N". A shared rollup
  // keeps the on-chain and producer sequences identical; reuse the address an already-backed
  // channel recorded so a partial bootstrap resumes onto the same contract.
  let addr = null;
  for (const ch of CHANNELS) {
    const f = wc(ch, 'channel_backing.json');
    if (fs.existsSync(f)) { addr = JSON.parse(fs.readFileSync(f, 'utf8')).rollup || null; if (addr) break; }
  }
  if (!addr) {
    const binding = path.join(WORK, 'producer', 'wallet-l1.json');
    if (fs.existsSync(binding)) addr = JSON.parse(fs.readFileSync(binding, 'utf8')).rollup;
  }
  if (!addr) { console.log('  deploying the shared IntmaxRollup…'); addr = deployRollup(); }
  require('../../api/lib/wallet-l1').configure(addr);
  // The genesis deposit must be proved with the SAME identity the block producer will journal
  // for it: `Deposit::nullifier()` hashes the deposit index and the INTMAX block number, and
  // that nullifier is the leaf pushed onto `settled_tx_chain`. Read both from the producer
  // before the deposit exists — `add_deposit` assigns `deposit_counts` and `block_number + 1`.
  // `setup-backing` proves its genesis against a FRESH witness generator, i.e. as the
  // producer's very first block, so only ONE channel per producer can carry a funded genesis
  // deposit: it is journaled right after it is proved (`journalBackingDeposit`), before anything
  // else can consume that slot. Every further channel gets an EMPTY genesis (no deposit, fund 0,
  // settle chain 0 — the bare initial proof, which the live balance binds to trivially) and is
  // funded through ordinary deposit imports, whose indices then follow the shared sequence.
  const producerStatus = await producer.status();
  const fundedGenesisDone = CHANNELS.some((ch) => {
    const f = wc(ch, 'channel_backing.json');
    return fs.existsSync(f) && !!JSON.parse(fs.readFileSync(f, 'utf8')).deposit_tx;
  });
  for (const [i, ch] of needBacking.entries()) {
    const deferred = fundedGenesisDone || i > 0;
    const env = deferred ? { SETUP_BACKING_EMPTY_GENESIS: '1' } : {
      SETUP_BACKING_DEPOSIT_INDEX: String(producerStatus.nextDepositIndex),
      SETUP_BACKING_INTMAX_BLOCK_NUMBER: String(Number(producerStatus.blockNumber) + 1),
    };
    console.log(`  channel ${ch}: IntmaxRollup @ ${addr} — setup-backing (${deferred ? 'empty genesis, funded by imports' : 'real ETH deposit + balance proof, ~30s'})…`);
    cli(ch, ['setup-backing', RPC, addr], env);
    if (!deferred) await journalBackingDeposit(ch);
  }
}

const http = require('http');
const HTTP_PORT = PORT + 1;

// Sync throws inside a handler (e.g. `reqChannel` on an unknown channel) answer as JSON with the
// error's status instead of Express's HTML 500 page.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  console.error(err && err.message ? err.message : err);
  res.status(err && err.status ? err.status : 500).json({ error: String((err && err.message) || err) });
});

bootstrapBacking().then(() => {
  // After backing exists (verification reads channel_backing.json's rollup).
  loadTokenManifests(RPC);
  https.createServer(opts, app).listen(PORT, '0.0.0.0', () => {
    console.log(`wallet relay on https://localhost:${PORT}/wallet-live.html  (channels ${CHANNELS.join(', ')})`);
  });
  http.createServer(app).listen(HTTP_PORT, '0.0.0.0', () => {
    console.log(`wallet relay (HTTP) on http://localhost:${HTTP_PORT}/wallet-live.html`);
  });
  if (cluster) {
    for (const ch of CHANNELS) cluster.watch(ch);
    cluster.startWatchdog();
  }
  // Land any inter-channel transfer whose sender vanished: once at startup, then periodically.
  sweepPendingInterTransfers().finally(() => setInterval(() => { sweepPendingInterTransfers(); }, INTER_RESUME_MS).unref());
}).catch((e) => {
  console.error('backing bootstrap failed:', e.stderr ? String(e.stderr) : (e.message || e));
  process.exit(1);
});
