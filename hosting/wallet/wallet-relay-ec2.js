// EC2 all-in-one host for the two-channel payment-channel demo: serves the static frontend
// (wallet-live.html + worker + wasm) AND the /api co-signing endpoints from a SINGLE origin, over
// HTTPS, with the COEP/COOP headers that the multi-threaded wasm proving needs (SharedArrayBuffer
// requires a secure context + cross-origin isolation). The two channels' deposit backing is
// pre-built locally against Sepolia and shipped here, so there is NO anvil/forge/setup-backing on
// this box — it only co-signs.
const express = require('express');
const compression = require('compression');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');
const pExecFile = promisify(execFile);

const ROOT = __dirname;
const WORK = path.join(ROOT, 'wallet-live-work');
const PUBLIC = path.join(ROOT, 'public');
const CLI = process.env.CHANNEL_MEMBER_BIN || path.join(ROOT, 'bin', 'channel_member');
// Channel list is env-overridable (stress boxes run many channels); default = the live pair.
const CHANNELS = (process.env.CHANNELS || '7,8').split(',').map((s) => parseInt(s, 10));
// STRESS-ONLY knob: force every CLI invocation's INTMAX_CHANNEL to one fixed id, so N channel
// DIRS can share copies of one channel's deposit backing (the backing attestation is bound to the
// channel id — see verify_channel_backing). NEVER set on a live box: all channels would produce
// states claiming the same channel_id.
const FORCE_CHANNEL_ID = process.env.FORCE_CHANNEL_ID || null;
if (FORCE_CHANNEL_ID) console.warn(`⚠ FORCE_CHANNEL_ID=${FORCE_CHANNEL_ID} — every channel dir runs as channel ${FORCE_CHANNEL_ID} (stress mode)`);
const TLS_CERT = process.env.TLS_CERT; // fullchain.pem
const TLS_KEY = process.env.TLS_KEY;   // privkey.pem
const PORT = parseInt(process.env.PORT || (TLS_CERT ? '443' : '8000'), 10);

const chDir = (ch) => path.join(WORK, 'ch' + ch);
const wc = (ch, n) => path.join(chDir(ch), n);
function reqChannel(req) {
  const c = parseInt((req.query && req.query.channel) || '', 10);
  return CHANNELS.includes(c) ? c : CHANNELS[0];
}
async function cli(ch, args, extraEnv) {
  console.log(`  $ INTMAX_CHANNEL=${FORCE_CHANNEL_ID || ch} channel_member ${args.join(' ')}`);
  // ASYNC exec: execFileSync blocked the WHOLE node event loop for the duration of every proving
  // call, serializing even independent channels (measured: throughput pinned at ~1.6 req/s flat
  // from conc=1..8 while CPU sat ~65% idle). execFile keeps the loop free; per-channel ordering
  // is still enforced by withLock.
  const { stdout } = await pExecFile(CLI, args, { cwd: chDir(ch), encoding: 'utf8', timeout: 600_000, maxBuffer: 256 * 1024 * 1024, env: { ...process.env, INTMAX_CHANNEL: String(FORCE_CHANNEL_ID || ch), ...(extraEnv || {}) } });
  return stdout;
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

// ---- Batched co-sign queue (abstract2-1 §3.2b, slim wire detail2 §M) -------------------------
// Concurrent cosign requests for the SAME channel coalesce into ONE `cosign-batch` CLI call.
// Two ingest paths feed one queue:
//   /api/cosign  (legacy, browser): fat SendPayload parsed by express.json. K = 1 keeps the exact
//                old solo path (incl. the sender-state-sig carry-over); inside a K > 1 batch the
//                fat payload is CONVERTED to slim at drain time.
//   /api/cosign2 (slim, scalable): the body streams straight to a per-request SPOOL FILE — the
//                relay never buffers or parses it (the 2026-07-22 storm core-dumped the relay at
//                ~1000 buffered 16.8MB bodies). The anchor digest is extracted from the first
//                bytes (slim serializes anchorDigest FIRST). Responds with a compact ACK, not the
//                full state (browsers poll /api/poll anyway).
// The batch handoff to the CLI is a tiny MANIFEST of spool file paths — no K-sized JSON string is
// ever built (V8's ~512MB max-string killed K > 30 at fat sizes).
const COALESCE_MS = parseInt(process.env.COSIGN_COALESCE_MS || '150', 10);
const MAX_BATCH_K = parseInt(process.env.MAX_BATCH_K || '1024', 10);
const _sendQueues = {};   // ch -> [{ kind:'fat', payload } | { kind:'slim', file, anchor }, resolve, reject]
const _draining = {};
function enqueueCosign(ch, entry) {
  return new Promise((resolve, reject) => {
    (_sendQueues[ch] = _sendQueues[ch] || []).push({ ...entry, resolve, reject });
    drainCosigns(ch);
  });
}
function headDigestOf(ch) {
  try { return JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')).state.digest; }
  catch (e) { return null; }
}
function spoolDir(ch) { const d = wc(ch, 'spool'); fs.mkdirSync(d, { recursive: true }); return d; }
let _spoolSeq = 0;
function spoolPath(ch) { return path.join(spoolDir(ch), `s_${process.pid}_${++_spoolSeq}.json`); }
function entryAnchor(item) {
  return item.kind === 'slim'
    ? item.anchor
    : item.payload && item.payload.proposedNextState && item.payload.proposedNextState.prevDigest;
}
function drainCosigns(ch) {
  if (_draining[ch]) return;
  _draining[ch] = true;
  withLock(ch, async () => {
    while ((_sendQueues[ch] || []).length) {
      // COALESCE window: requests arriving within this window (or during the previous proving)
      // fold into one batch. With slim spooled ingest the arrival stagger is network-bound, not
      // parse-bound, so the default window catches genuinely-simultaneous senders.
      await new Promise((r) => setTimeout(r, COALESCE_MS));
      const taken = _sendQueues[ch].splice(0, MAX_BATCH_K);
      // Pre-filter stale anchors (ChannelState serializes camelCase: prevDigest / digest).
      const head = headDigestOf(ch);
      const batch = [];
      for (const item of taken) {
        const anchor = entryAnchor(item);
        if (head && anchor && anchor !== head) {
          if (item.kind === 'slim') fs.rm(item.file, { force: true }, () => {});
          item.reject(new Error('stale anchor: channel head advanced; re-import the snapshot and rebuild the send'));
        } else batch.push(item);
      }
      if (!batch.length) continue;
      const spooled = [];   // conversion files owned by this round (cleaned up after)
      try {
        let outFile;
        if (batch.length === 1 && batch[0].kind === 'fat') {
          // Legacy solo path — byte-identical behavior (sender state-sig carry-over intact).
          fs.writeFileSync(wc(ch, 'payload.json'), JSON.stringify(batch[0].payload));
          await cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
          outFile = 'cosigned.json';
        } else {
          console.log(`  batch co-sign: ${batch.length} sends in ONE transition (channel ${ch})`);
          const files = [];
          for (const b of batch) {
            if (b.kind === 'slim') { files.push(path.relative(chDir(ch), b.file)); continue; }
            // fat -> slim conversion (detail2 §M-1): keep only what the fold needs.
            const p = b.payload;
            const slim = {
              anchorDigest: p.proposedNextState.prevDigest,
              senderIndex: p.senderIndex,
              recipientIndex: p.recipientIndex,
              channelTx: p.channelTx,
              afterCt: p.proposedNextState.balanceState.encBalances[p.senderIndex],
            };
            const f = spoolPath(ch);
            fs.writeFileSync(f, JSON.stringify(slim));
            spooled.push(f);
            files.push(path.relative(chDir(ch), f));
          }
          fs.writeFileSync(wc(ch, 'batch_manifest.json'), JSON.stringify({ files }));
          await cli(ch, ['cosign-batch', 'batch_manifest.json', 'batch_cosigned.json']);
          outFile = 'batch_cosigned.json';
        }
        const out = fs.readFileSync(wc(ch, outFile), 'utf8');
        // Slim clients get a compact ACK; fat (browser) clients get the full co-signed state.
        let ack = null;
        for (const b of batch) {
          if (b.kind === 'slim') {
            if (!ack) {
              const st = JSON.parse(out);
              ack = JSON.stringify({ ok: true, applied: batch.length, stateVersion: st.balanceState.stateVersion, digest: st.digest });
            }
            b.resolve(ack);
          } else b.resolve(out);
        }
      } catch (e) {
        console.error(`batch of ${batch.length} rejected (${String(e.stderr || e.message || e).slice(0, 200)})${batch.some(b => b.kind === 'fat') ? '; falling back to solo cosigns for fat payloads' : ''}`);
        for (const b of batch) {
          if (b.kind !== 'fat') { b.reject(e); continue; }
          // Fat fallback: honest solo txs survive a poisoned batch (legacy behavior).
          try {
            fs.writeFileSync(wc(ch, 'payload.json'), JSON.stringify(b.payload));
            await cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
            b.resolve(fs.readFileSync(wc(ch, 'cosigned.json'), 'utf8'));
          } catch (e2) { b.reject(e2); }
        }
      } finally {
        for (const b of batch) if (b.kind === 'slim') fs.rm(b.file, { force: true }, () => {});
        for (const f of spooled) fs.rm(f, { force: true }, () => {});
      }
    }
  }).finally(() => {
    _draining[ch] = false;
    if ((_sendQueues[ch] || []).length) drainCosigns(ch);
  });
}

// ---- Ticket persistence (one JSON array per channel) ----------------------------------------
// tickets.json     = ACTIVE tickets (+ terminal ones for a short TTL). ticket_history.json =
// DURABLE log of every ticket that reached terminal (deposits AND withdrawals), TTL-exempt, capped.
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
  if (isTerminal(ticket)) archiveTicket(ch, ticket); // durable "processed" record
  return ticket;
}

// RPC the close-lifecycle commands talk to (this box targets a real chain — set RPC in the env).
const RPC = process.env.RPC || 'http://127.0.0.1:8545';
function rollupOf(ch) {
  const b = JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'));
  if (!b.rollup) throw new Error('channel has no rollup in channel_backing.json');
  return b.rollup;
}

// ── Token DISPLAY metadata (multi-token detail2 §N-1/§N-7, threat model TM-10b) ───────────────
//
// SECURITY CONTRACT: symbol / name / decimals carry ZERO authority. The authoritative token
// identity is the base `token_index` — proof-bound in the circuits and set-once on-chain in
// `IntmaxRollup.tokenAddressOf(uint32)`. Showing "USDC" over a worthless token is a user-funds
// attack, so metadata is served ONLY for entries whose manifest address was read back EQUAL from
// the on-chain registry. Everything else is served as null and the wallet falls back to the raw
// base index.
//
// The validation + verification logic is SHARED with the node programs (one implementation, one
// place to review). This box ships only the relay, so the module is resolved from a few known
// locations; if it cannot be loaded, metadata is disabled entirely — never re-implemented inline.
let tokenRegistryModule = null;
(function loadTokenRegistryModule() {
  const candidates = [
    process.env.TOKEN_REGISTRY_MODULE,
    path.join(ROOT, 'token-registry.js'),                              // shipped next to the relay
    path.join(ROOT, '..', '..', 'node', 'common', 'token-registry.js'), // repo layout
  ].filter(Boolean);
  for (const c of candidates) {
    try { if (fs.existsSync(c)) { tokenRegistryModule = require(c); return; } } catch (e) { /* try next */ }
  }
  console.warn('⚠ token-registry module not found — /api/tokens serves raw base indices with null metadata');
})();

const TOKEN_REGISTRIES = {}; // ch -> TokenRegistry (verified asynchronously at startup)
function loadTokenManifests() {
  if (!tokenRegistryModule) return;
  for (const ch of CHANNELS) {
    const p = process.env.TOKENS_MANIFEST || wc(ch, 'tokens.json');
    if (!fs.existsSync(p)) { console.log(`channel ${ch}: no tokens.json — raw base indices`); continue; }
    let reg;
    try {
      reg = tokenRegistryModule.TokenRegistry.fromFile(p);
    } catch (e) {
      // Fail closed and LOUD: a malformed manifest is an operator error on a live box, and this
      // box already refuses to start without its deposit backing.
      console.error(`channel ${ch}: invalid token manifest ${p}: ${e.message}`);
      process.exit(1);
    }
    TOKEN_REGISTRIES[ch] = reg;
    // Verify against the rollup's set-once registry. A CONTRADICTION (manifest address != chain)
    // is fatal — that is exactly the mislabelling hazard. Absent information (unregistered index,
    // RPC down) only warns and leaves those entries without metadata.
    (async () => {
      try {
        await reg.verifyAgainstChain(RPC, rollupOf(ch), { logger: console });
        console.log(`channel ${ch}: tokens ${JSON.stringify(reg.summary())}`);
      } catch (e) {
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
// faucet member holds an in-channel balance backed by one ERC-20 deposit that was made on L1 and
// imported once. It therefore cannot MINT (every dripped balance stays covered by
// `channel_fund.amounts[t]` and remains claimable) — the realistic attack is DRAINING it. The
// defences, in order:
//   1. OFF BY DEFAULT. Live only with FAUCET_ENABLED=1 + FAUCET_SLOT + a NON-ZERO
//      ITX_TOKEN_INDEX; anything missing/malformed leaves it disabled and POST answers 404. A
//      production box that simply does not set these can never dispense.
//   2. NOTHING FROM THE REQUEST BUT THE RECIPIENT SLOT — amount, token and limits are config, and
//      the slot is checked against the CHANNEL'S OWN SIGNED membership + registry, never a body.
//   3. ONE DRIP PER SLOT FOR EVER, plus a per-channel cap and a cooldown, recorded per channel.
//   4. RESERVE BEFORE TRANSFER: a crash between the ledger write and the co-signed transfer costs
//      a drip, it never pays one twice.
// DEPLOYMENT INVARIANT: exactly ONE relay process per channel directory. `withLock` is in-process
// JS state, not an flock, so two processes sharing one wallet-live-work/ch<N>/ could both pass the
// eligibility check before either reserves. No clustering exists today (and every other mutating
// endpoint already relies on the same mutex); if the relay is ever clustered, the ledger needs a
// real file lock BEFORE the faucet is re-enabled.
// The eligibility policy itself lives in ONE shared, unit-tested module (node/common/
// faucet-policy.js) so the dev relay and this box cannot drift; if it cannot be loaded the faucet
// stays disabled rather than being re-implemented inline.
let faucetPolicy = null;
(function loadFaucetPolicy() {
  const candidates = [
    process.env.FAUCET_POLICY_MODULE,
    path.join(ROOT, 'faucet-policy.js'),                              // shipped next to the relay
    path.join(ROOT, '..', '..', 'node', 'common', 'faucet-policy.js'), // repo layout
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
  // Requested but not coherent — say so loudly. Never "best effort enable".
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
 * registry (`channelTokens` reads the signed snapshot). Deliberately NOT the tokens.json manifest:
 * display metadata carries zero authority, and the position is what the transfer is signed over.
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

// Fail fast if the deposit backing was not shipped — this box must never fabricate a channel.
// DURABLE membership: the channel state (registered delegates, their slots) PERSISTS across relay
// restarts so a deploy/restart never churns slot assignments or collides re-joining users — the
// cosigner is the durable member registry. Pass RESET_CHANNELS=1 to deliberately start fresh.
const RESET = process.env.RESET_CHANNELS === '1';
for (const ch of CHANNELS) {
  const ok = ['channel_backing.json', 'channel_attestation.bin', 'balance_vd.bin'].every((f) => fs.existsSync(wc(ch, f)));
  if (!ok) { console.error(`channel ${ch}: missing deposit backing in ${chDir(ch)}`); process.exit(1); }
  if (RESET) {
    fs.rmSync(wc(ch, 'cli_state.json'), { force: true });
    fs.rmSync(wc(ch, 'channel_snapshot.json'), { force: true });
    fs.rmSync(wc(ch, 'last_burn.json'), { force: true });
    fs.rmSync(wc(ch, 'pw_auth.json'), { force: true });
    fs.rmSync(wc(ch, 'pw_submit.json'), { force: true });
    fs.rmSync(wc(ch, TICKET_FILE), { force: true });
    console.log(`channel ${ch}: RESET_CHANNELS=1 → cleared prior membership`);
  }
}
loadTokenManifests(); // after the backing check (verification needs channel_backing.json's rollup)

const app = express();
app.use((req, res, next) => {
  console.log(`REQ ${req.method} ${req.url} len=${req.headers['content-length'] || 0}`);
  next();
});

// SLIM co-sign ingest (detail2 §M-4). Registered BEFORE express.json so the multi-MB body is
// NEVER buffered or parsed in relay heap — it streams straight to a per-request spool file
// (the 2026-07-22 storm core-dumped the relay at ~1000 buffered fat bodies). The anchor digest
// is read from the first bytes (SlimSendPayload serializes anchorDigest FIRST). Responds with a
// compact ACK {ok, applied, stateVersion, digest} — NOT the multi-MB state (poll /api/poll).
const MAX_SLIM_BODY = 64 * 1024 * 1024;
app.post('/api/cosign2', (req, res) => {
  const ch = reqChannel(req);
  const file = spoolPath(ch);
  const ws = fs.createWriteStream(file);
  let bytes = 0; let firstChunk = null; let aborted = false;
  req.on('data', (c) => {
    bytes += c.length;
    if (!firstChunk) firstChunk = c;
    if (bytes > MAX_SLIM_BODY && !aborted) {
      aborted = true; ws.destroy(); fs.rm(file, { force: true }, () => {});
      res.status(413).json({ error: 'body too large' }); req.destroy();
    }
  });
  req.pipe(ws);
  ws.on('error', (e) => { if (!aborted) { aborted = true; fs.rm(file, { force: true }, () => {}); res.status(500).json({ error: 'spool: ' + e.message }); } });
  ws.on('finish', () => {
    if (aborted) return;
    const m = /"anchorDigest"\s*:\s*"([^"]+)"/.exec(String(firstChunk).slice(0, 4096));
    if (!m) {
      fs.rm(file, { force: true }, () => {});
      return res.status(400).json({ error: 'anchorDigest not found at head of body (SlimSendPayload required)' });
    }
    enqueueCosign(ch, { kind: 'slim', file, anchor: m[1] })
      .then((ackJson) => res.type('application/json').send(ackJson))
      .catch((e) => {
        const msg = String(e.stderr || e.message || e);
        res.status(/stale anchor/.test(msg) ? 409 : 500).json({ error: msg });
      });
  });
});

app.use(compression({
  filter: (req, res) => {
    const ct = String(res.getHeader('Content-Type') || '');
    if (/wasm|javascript|json|html|text|octet-stream/.test(ct)) return true;
    return compression.filter(req, res);
  },
}));
app.use(express.json({ limit: '64mb' }));
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid JSON: ' + err.message });
  next(err);
});
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (req.path.endsWith('.wasm')) res.setHeader('Content-Type', 'application/wasm');
  // `no-cache` = the browser MAY cache but MUST revalidate (conditional GET) every load. After a
  // redeploy the wasm's ETag changes, so the browser fetches the new bytes; when unchanged it gets a
  // cheap 304 (no re-download). This avoids the stale-wasm/worker mismatch that `max-age=3600` caused
  // (an old 1-arg genesis wasm vs a new recipient-requiring CLI → "missing field `recipient`").
  if (req.path.startsWith('/pkg/')) res.setHeader('Cache-Control', 'no-cache');
  else res.setHeader('Cache-Control', 'no-store');
  next();
});

app.get('/api/health', (req, res) => res.json({ ok: true, channels: CHANNELS }));
app.get('/api/channels', (req, res) => res.json({ channels: CHANNELS }));

app.post('/api/init', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
    fs.mkdirSync(chDir(ch), { recursive: true });
    fs.writeFileSync(wc(ch, 'contribution.json'), JSON.stringify(req.body));
    await cli(ch, ['init', 'contribution.json', 'channel_snapshot.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')));
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

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

// GET /api/poll?channel=N&since=<stateVersion> — cheap change-check for the browser balance poller.
// 204 (no body) when the channel state_version is unchanged; the snapshot when it advanced. No lock
// (must not queue behind proving); a mid-write read falls through to 204 and the next tick succeeds.
app.get('/api/poll', (req, res) => {
  const ch = reqChannel(req);
  const since = parseInt((req.query && req.query.since) || '', 10);
  let snap;
  try { snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')); }
  catch (e) { return res.status(204).end(); }
  const st = (snap && (snap.state || snap.State)) || {};
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

app.get('/api/backing', (req, res) => {
  try { const ch = reqChannel(req); res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'))); }
  catch (e) { res.status(404).json({ error: 'no deposit backing yet' }); }
});

// GET /api/tokens?channel=N — per-token channel view + VERIFIED display metadata (§N).
// symbol/name/decimals are non-null ONLY when `verified` is true; `address` may be reported while
// unverified, a NAME may not. 404 while the channel has no snapshot (matches /api/snapshot).
app.get('/api/tokens', (req, res) => {
  try { res.json(channelTokens(reqChannel(req))); }
  catch (e) { res.status(404).json({ error: 'no channel yet' }); }
});

// The reorg depth `cosign-l1-deposit-import` will require for a deposit on `chainId`.
//
// SECURITY: DISPLAY ONLY, and deliberately a MIRROR rather than a control. The enforcing check is
// `min_confirmations_for` in src/bin/channel_member.rs (floor/default 0 on anvil 31337, floor 1 and
// default 12 elsewhere), which reads the chain itself. This relay never passes a
// `min_confirmations` argument to the CLI, and the CLI clamps any explicit value UP to the floor —
// so nothing served here can lower the depth actually enforced. It exists only so the wallet can
// render "confirming (n/12)" instead of an error while a fresh deposit matures.
// Keep in sync with wallet-relay.js.
function minConfirmationsForDisplay(chainId) {
  return chainId === 31337 ? 0 : 12;
}

// `rollup` is both the deposit target and the ERC-20 approve spender the browser must use.
app.get('/api/deposit-info', (req, res) => {
  try {
    const ch = reqChannel(req);
    const b = JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'));
    const chainId = parseInt(process.env.CHAIN_ID || '31337', 10);
    res.json({
      rollup: b.rollup,
      depositRecipient: b.deposit_recipient || b.rollup,
      rpc: RPC,
      chainId,
      minConfirmations: minConfirmationsForDisplay(chainId),
    });
  } catch (e) { res.status(404).json({ error: 'no deposit backing yet' }); }
});

app.post('/api/cosign', (req, res) => {
  const ch = reqChannel(req);
  enqueueCosign(ch, { kind: 'fat', payload: req.body })
    .then((finalStateJson) => res.type('application/json').send(finalStateJson))
    .catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

app.post('/api/refresh-cosign', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
    fs.writeFileSync(wc(ch, 'refresh_payload.json'), JSON.stringify(req.body));
    await cli(ch, ['cosign-refresh', 'refresh_payload.json', 'refresh_cosigned.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'refresh_cosigned.json'), 'utf8')));
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

app.post('/api/inter/send', (req, res) => {
  const ch = reqChannel(req);
  // Previously an unlocked handler — safe only because execFileSync serialized the whole process.
  // With async exec the per-channel lock must be explicit (cosign-inter-transfer mutates BOTH
  // channels' state from channel A's dir; A's lock serializes it against A's other mutations,
  // matching the old effective ordering).
  withLock(ch, async () => {
    const debitPayload = req.body && req.body.debitPayload;
    const descriptor = req.body && req.body.transferDescriptor;
    if (!debitPayload || !descriptor) throw new Error('inter/send needs { debitPayload, transferDescriptor }');
    fs.writeFileSync(wc(ch, 'inter_debit_payload.json'), JSON.stringify(debitPayload));
    fs.writeFileSync(wc(ch, 'inter_descriptor.json'), JSON.stringify(descriptor));
    await cli(ch, ['cosign-inter-transfer', 'inter_debit_payload.json', 'inter_descriptor.json', 'inter_transfer.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'inter_transfer.json'), 'utf8')));
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// ─── Deposit import ────────────────────────────────────────────────────────────────────────
// SECURITY: `depositor` and `amount` are NO LONGER accepted. The CLI reads them from the
// transaction's on-chain `Deposited` log, so this endpoint only needs to say WHICH transaction.
// A body carrying the old fields is REJECTED (not ignored) so a stale client fails loudly rather
// than silently having its numbers dropped. See doc/tasks/deposit-import-threat-model.md.
app.post('/api/import-deposit', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
    const b = req.body || {};
    if (b.depositor !== undefined || b.amount !== undefined || b.tokenIndex !== undefined) {
      throw new Error('import-deposit no longer accepts { depositor, amount, tokenIndex }: they are read from the on-chain Deposited log. Send { recipientSlot, txHash }.');
    }
    let slot = b.recipientSlot;
    let txHash = b.txHash;
    // The browser (MetaMask) path always sends its own txHash: that deposit is signed by the user's
    // wallet, whose address IS the slot's bound B-1b recipient, so the CLI's depositor<->slot
    // binding must hold and --allow-unbound-depositor is deliberately NOT passed. Only the
    // server-written fallback file (an operator-key deposit) opts out of that binding.
    let operatorFunded = false;
    if (txHash === undefined) {
      const pf = wc(ch, 'pending_deposit.json');
      if (!fs.existsSync(pf)) throw new Error('import-deposit needs { recipientSlot, txHash }');
      const dep = JSON.parse(fs.readFileSync(pf, 'utf8'));
      if (!dep.txHash) throw new Error('pending_deposit.json has no txHash — cannot verify the deposit on-chain');
      txHash = dep.txHash;
      if (slot === undefined) slot = dep.recipientSlot;
      operatorFunded = true;
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(String(txHash))) throw new Error('txHash must be 0x + 64 hex chars');
    if (slot === undefined) throw new Error('import-deposit needs { recipientSlot }');
    if (!/^[0-9]{1,4}$/.test(String(slot))) throw new Error('recipientSlot must be a small decimal integer');
    const args = ['cosign-l1-deposit-import', String(slot), String(txHash), RPC, 'l1_import_cosigned.json'];
    if (operatorFunded) args.push('--allow-unbound-depositor');
    await cli(ch, args);
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
        // Idempotent: same answer, no value moved.
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
      await cli(ch, ['refresh', String(FAUCET.faucetSlot), String(localTokenSlot), 'faucet_refresh.json']);
      await cli(ch, ['send', String(FAUCET.faucetSlot), String(slot), amount, 'faucet_payload.json', String(localTokenSlot)]);
      await cli(ch, ['cosign', 'faucet_payload.json', 'faucet_cosigned.json']);
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

// ─── Partial withdrawal (burn + settle) ────────────────────────────────────────────────────
app.post('/api/cosign-burn', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
    const active = findActiveTicket(ch, 'partial_withdrawal');
    if (active && active.status === 'burn_done') {
      res.status(409).json({ error: 'settle pending burn first', ticket: active });
      return;
    }
    const { debitPayload, transferDescriptor } = req.body || {};
    if (!debitPayload || !transferDescriptor) throw new Error('cosign-burn needs { debitPayload, transferDescriptor }');
    fs.writeFileSync(wc(ch, 'burn_payload.json'), JSON.stringify(debitPayload));
    fs.writeFileSync(wc(ch, 'burn_descriptor.json'), JSON.stringify(transferDescriptor));
    await cli(ch, ['cosign-burn-send', 'burn_payload.json', 'burn_descriptor.json', 'burn_cosigned.json']);
    const ticket = upsertTicket(ch, {
      id: 'pw_' + Date.now(), type: 'partial_withdrawal', status: 'burn_done',
      createdAt: Date.now(), updatedAt: Date.now(),
      params: { amount: String(req.body.amount || ''), recipient: req.body.recipient || '' },
      steps: { burn: { completedAt: Date.now() }, settle: null },
    });
    const cosigned = JSON.parse(fs.readFileSync(wc(ch, 'burn_cosigned.json'), 'utf8'));
    res.json({ ...cosigned, _ticket: ticket });
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

app.post('/api/deploy-settlement', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
    if (fs.existsSync(wc(ch, 'settlement.json'))) {
      return res.json(JSON.parse(fs.readFileSync(wc(ch, 'settlement.json'), 'utf8')));
    }
    await cli(ch, ['deploy-settlement', RPC]);
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

app.get('/api/settlement', (req, res) => {
  try {
    const ch = reqChannel(req);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'settlement.json'), 'utf8')));
  } catch (e) { res.status(404).json({ error: 'no settlement deployed' }); }
});

app.post('/api/pw-submit', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (ticket) { ticket.status = 'settle_pending'; upsertTicket(ch, ticket); }
    if (!fs.existsSync(wc(ch, 'settlement.json'))) {
      await cli(ch, ['deploy-settlement', RPC]);
    }
    const pwRecipient = (req.body && req.body.recipient) || (ticket && ticket.params.recipient) || '';
    const extra = pwRecipient ? { PW_RECIPIENT: pwRecipient } : {};
    await cli(ch, ['pw-submit', RPC], extra);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'pw_auth.json'), 'utf8')));
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

app.post('/api/pw-finalize', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
    await cli(ch, ['pw-finalize', RPC]);
    const auth = JSON.parse(fs.readFileSync(wc(ch, 'pw_auth.json'), 'utf8'));
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (ticket) { ticket.status = 'settle_done'; ticket.steps.settle = { completedAt: Date.now(), authDigest: auth.auth_digest }; upsertTicket(ch, ticket); }
    res.json({ ok: true, authDigest: auth.auth_digest });
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// ─── Close lifecycle (close → settle → withdraw → claim) ──────────────────────────────────
app.post('/api/close', (req, res) => {
  const ch = reqChannel(req);
  // Locked + async (was an unlocked sync handler; execFileSync used to serialize implicitly).
  withLock(ch, async () => {
 const manager = req.body && req.body.manager; const sv = (req.body && req.body.sv) || '';
    if (!manager) throw new Error('close needs { manager }');
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) { ticket.status = 'close_pending'; upsertTicket(ch, ticket); }
    const out = await cli(ch, ['close', manager, RPC], { CLOSE_SV: sv });
    if (ticket) { ticket.status = 'close_done'; ticket.steps.close = { completedAt: Date.now() }; upsertTicket(ch, ticket); }
    res.json({ ok: true, log: out });
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});
app.post('/api/settle', (req, res) => {
  const ch = reqChannel(req);
  // Locked + async (was an unlocked sync handler; execFileSync used to serialize implicitly).
  withLock(ch, async () => {
 const manager = req.body && req.body.manager;
    if (!manager) throw new Error('settle needs { manager }');
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) { ticket.status = 'settle_pending'; upsertTicket(ch, ticket); }
    const out = await cli(ch, ['settle', manager, RPC]);
    if (ticket) { ticket.status = 'settle_done'; ticket.steps.settle = { completedAt: Date.now() }; upsertTicket(ch, ticket); }
    res.json({ ok: true, log: out });
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});
app.post('/api/withdraw', (req, res) => {
  const ch = reqChannel(req);
  // Locked + async (was an unlocked sync handler; execFileSync used to serialize implicitly).
  withLock(ch, async () => {
 const manager = req.body && req.body.manager;
    if (!manager) throw new Error('withdraw needs { manager }');
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) { ticket.status = 'withdraw_pending'; upsertTicket(ch, ticket); }
    const out = await cli(ch, ['withdraw', manager, RPC], { ROLLUP: rollupOf(ch) });
    if (ticket) { ticket.status = 'withdraw_done'; ticket.steps.withdraw = { completedAt: Date.now() }; upsertTicket(ch, ticket); }
    res.json({ ok: true, log: out });
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});
app.post('/api/claim', (req, res) => {
  const ch = reqChannel(req);
  // Locked + async (was an unlocked sync handler; execFileSync used to serialize implicitly).
  withLock(ch, async () => {
 const manager = req.body && req.body.manager; const slot = req.body && req.body.slot; const recipient = req.body && req.body.recipient;
    if (!manager || slot === undefined || !recipient) throw new Error('claim needs { manager, slot, recipient }');
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) { ticket.status = 'claim_pending'; upsertTicket(ch, ticket); }
    const out = await cli(ch, ['claim', manager, String(slot), RPC], { CLAIM_RECIPIENT: recipient });
    if (ticket) { ticket.status = 'claim_done'; ticket.steps.claim = { completedAt: Date.now() }; upsertTicket(ch, ticket); }
    res.json({ ok: true, log: out });
  }).catch((e) => { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); });
});

// ─── Ticket endpoints ────────────────────────────────────────────────────────────────────────
app.get('/api/tickets', (req, res) => {
  const ch = reqChannel(req);
  res.json(readTickets(ch));
});

// Processed (terminal) tickets — deposits AND withdrawals — most recent first. Merges durable history
// with terminal tickets still in tickets.json (within TTL), deduped by id.
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
    id: 'dep_' + Date.now(), type: 'deposit', status: 'l1_done',
    createdAt: Date.now(), updatedAt: Date.now(),
    params,
    steps: { l1: { completedAt: Date.now(), txHash }, import: null },
  });
  res.json(ticket);
});

// Static frontend (index.html = wallet-live.html, wallet-worker.js, /pkg/...), same origin as /api.
app.use(express.static(PUBLIC));

// Listen BACKLOG: node's default 511 dropped ~5% of 10,000 truly-simultaneous connects
// (2026-07-22 join storm — instant client-side resets). 8192 covers the bursts we test; the
// kernel caps it at net.core.somaxconn (raise via sysctl on stress boxes if needed).
const BACKLOG = parseInt(process.env.LISTEN_BACKLOG || '8192', 10);
if (TLS_CERT && TLS_KEY) {
  const opts = { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) };
  https.createServer(opts, app).listen(PORT, '0.0.0.0', BACKLOG, () =>
    console.log(`intmax demo (HTTPS) on :${PORT}  channels ${CHANNELS.join(', ')}`));
  http.createServer((req, res) => { res.writeHead(301, { Location: 'https://' + req.headers.host + req.url }); res.end(); }).listen(80, '0.0.0.0');
} else {
  http.createServer(app).listen(PORT, '0.0.0.0', BACKLOG, () =>
    console.log(`intmax demo (HTTP) on :${PORT}  channels ${CHANNELS.join(', ')}`));
}
