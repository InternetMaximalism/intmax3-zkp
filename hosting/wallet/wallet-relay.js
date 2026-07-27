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
const { execFileSync, spawn } = require('child_process');

const ROOT = __dirname; // hosting/wallet/ — serves wallet-live.html + wallet-worker.js
const REPO = path.join(ROOT, '..', '..'); // repo root — target/, self_certs/, contracts/, pkg/, wallet-live-work/ live here (two levels up from hosting/wallet/)
const WORK = path.join(REPO, 'wallet-live-work');
const CLI = path.join(REPO, 'target', 'release', 'channel_member');
const PORT = 8000;
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
app.get('/api/snapshot', (req, res) => {
  try {
    const ch = reqChannel(req);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')));
  } catch (e) { res.status(404).json({ error: 'no channel yet' }); }
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
  res.json(snap);
});

// The channel's REAL Intmax deposit backing (detail2 §F-1): { fund, settledTxChain,
// intmaxStateRoot } produced once by `setup-backing`. The browser shows this so the user can see the
// channel is genuinely backed by a deposited Intmax balance (not a self-minted number).
app.get('/api/backing', (req, res) => {
  try {
    const ch = reqChannel(req);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8')));
  } catch (e) { res.status(404).json({ error: 'no deposit backing yet' }); }
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
app.post('/api/cosign', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, () => {
    fs.writeFileSync(wc(ch, 'payload.json'), JSON.stringify(req.body));
    cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'cosigned.json'), 'utf8')));
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
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

// GET /api/deposit-info?channel=N
// Returns the on-chain addresses and ABI info needed for the browser to send a deposit tx via MetaMask.
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
app.post('/api/import-deposit', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, () => {
    const slot = (req.body && req.body.recipientSlot) || 0;
    let depositor, amount;
    if (req.body && req.body.depositor && req.body.amount) {
      depositor = req.body.depositor;
      amount = req.body.amount;
    } else {
      const dep = JSON.parse(fs.readFileSync(wc(ch, 'pending_deposit.json'), 'utf8'));
      depositor = dep.depositor;
      amount = dep.amount;
    }
    cli(ch, ['cosign-l1-deposit-import', String(slot), String(amount), depositor, 'l1_import_cosigned.json']);
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
    if (active && active.status === 'burn_done') {
      res.status(409).json({ error: 'settle pending burn first', ticket: active });
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

app.post('/api/ticket/deposit', (req, res) => {
  const ch = reqChannel(req);
  const { amount, depositor, txHash, recipientSlot } = req.body || {};
  if (!amount || !depositor || !txHash) return res.status(400).json({ error: 'needs { amount, depositor, txHash, recipientSlot }' });
  const existing = findActiveTicket(ch, 'deposit');
  if (existing) return res.status(409).json({ error: 'deposit already pending', ticket: existing });
  const ticket = upsertTicket(ch, {
    id: 'dep_' + Date.now(),
    type: 'deposit',
    status: 'l1_done',
    createdAt: Date.now(),
    updatedAt: Date.now(),
    params: { amount: String(amount), depositor, recipientSlot: recipientSlot || 0, txHash },
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
