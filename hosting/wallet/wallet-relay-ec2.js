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
const { execFile } = require('child_process');
const { promisify } = require('util');
const pExecFile = promisify(execFile);

const ROOT = __dirname;
const WORK = path.join(ROOT, 'wallet-live-work');
const PUBLIC = path.join(ROOT, 'public');
const CLI = process.env.CHANNEL_MEMBER_BIN || path.join(ROOT, 'bin', 'channel_member');
const CHANNELS = [7, 8];
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
  console.log(`  $ INTMAX_CHANNEL=${ch} channel_member ${args.join(' ')}`);
  // ASYNC exec: execFileSync blocked the WHOLE node event loop for the duration of every proving
  // call, serializing even independent channels (measured: throughput pinned at ~1.6 req/s flat
  // from conc=1..8 while CPU sat ~65% idle). execFile keeps the loop free; per-channel ordering
  // is still enforced by withLock.
  const { stdout } = await pExecFile(CLI, args, { cwd: chDir(ch), encoding: 'utf8', timeout: 600_000, maxBuffer: 256 * 1024 * 1024, env: { ...process.env, INTMAX_CHANNEL: String(ch), ...(extraEnv || {}) } });
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

// ---- Batched co-sign queue (abstract2-1 §3.2b) -----------------------------------------------
// Concurrent /api/cosign requests for the SAME channel coalesce into ONE `cosign-batch` CLI call:
// K solo-built SendPayloads anchored at the same head are verified in parallel by the CLI (rayon)
// and folded into ONE co-signed state transition. Payloads anchored at a stale head are rejected
// up-front (they could never co-sign — same as today's behavior for the 2nd of two racing sends).
// If a batch fails (one bad payload poisons it), fall back to solo cosigns so honest txs survive.
const COALESCE_MS = parseInt(process.env.COSIGN_COALESCE_MS || '150', 10);
const _sendQueues = {};   // ch -> [{ payload, resolve, reject }]
const _draining = {};
function enqueueCosign(ch, payload) {
  return new Promise((resolve, reject) => {
    (_sendQueues[ch] = _sendQueues[ch] || []).push({ payload, resolve, reject });
    drainCosigns(ch);
  });
}
function headDigestOf(ch) {
  try { return JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')).state.digest; }
  catch (e) { return null; }
}
function drainCosigns(ch) {
  if (_draining[ch]) return;
  _draining[ch] = true;
  withLock(ch, async () => {
    while ((_sendQueues[ch] || []).length) {
      // COALESCE window: requests that arrive within this window (or during the previous
      // proving) fold into one batch. Negligible vs 1-8s proving, but it turns "K simultaneous
      // sends on an idle channel" into a real batch. 150ms default: multi-MB payloads take tens
      // of ms each just to upload+JSON-parse, so 40ms proved too tight for 3 concurrent senders
      // (measured on the stress clone: 40ms → batch of 2 + 1 stale; 150ms → batch of 3).
      await new Promise((r) => setTimeout(r, COALESCE_MS));
      const taken = _sendQueues[ch].splice(0);
      // Pre-filter stale anchors (ChannelState serializes camelCase: prevDigest / digest).
      const head = headDigestOf(ch);
      const batch = [];
      for (const item of taken) {
        const anchor = item.payload && item.payload.proposedNextState && item.payload.proposedNextState.prevDigest;
        if (head && anchor && anchor !== head) {
          item.reject(new Error('stale anchor: channel head advanced; re-import the snapshot and rebuild the send'));
        } else batch.push(item);
      }
      if (!batch.length) continue;
      try {
        let outFile;
        if (batch.length === 1) {
          fs.writeFileSync(wc(ch, 'payload.json'), JSON.stringify(batch[0].payload));
          await cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
          outFile = 'cosigned.json';
        } else {
          console.log(`  batch co-sign: ${batch.length} sends in ONE transition (channel ${ch})`);
          fs.writeFileSync(wc(ch, 'batch_payloads.json'), JSON.stringify(batch.map(b => b.payload)));
          await cli(ch, ['cosign-batch', 'batch_payloads.json', 'batch_cosigned.json']);
          outFile = 'batch_cosigned.json';
        }
        const out = fs.readFileSync(wc(ch, outFile), 'utf8');
        for (const b of batch) b.resolve(out);
      } catch (e) {
        if (batch.length === 1) { batch[0].reject(e); continue; }
        console.error(`batch of ${batch.length} rejected (${String(e.stderr || e.message || e).slice(0, 200)}); falling back to solo cosigns`);
        for (const b of batch) {
          try {
            fs.writeFileSync(wc(ch, 'payload.json'), JSON.stringify(b.payload));
            await cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
            b.resolve(fs.readFileSync(wc(ch, 'cosigned.json'), 'utf8'));
          } catch (e2) { b.reject(e2); }
        }
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

const app = express();
app.use((req, res, next) => {
  console.log(`REQ ${req.method} ${req.url} len=${req.headers['content-length'] || 0}`);
  next();
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

app.get('/api/snapshot', (req, res) => {
  try { const ch = reqChannel(req); res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'))); }
  catch (e) { res.status(404).json({ error: 'no channel yet' }); }
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
  res.json(snap);
});

app.get('/api/backing', (req, res) => {
  try { const ch = reqChannel(req); res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'))); }
  catch (e) { res.status(404).json({ error: 'no deposit backing yet' }); }
});

app.get('/api/deposit-info', (req, res) => {
  try {
    const ch = reqChannel(req);
    const b = JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'));
    const chainId = parseInt(process.env.CHAIN_ID || '31337', 10);
    res.json({ rollup: b.rollup, depositRecipient: b.deposit_recipient || b.rollup, rpc: RPC, chainId });
  } catch (e) { res.status(404).json({ error: 'no deposit backing yet' }); }
});

app.post('/api/cosign', (req, res) => {
  const ch = reqChannel(req);
  enqueueCosign(ch, req.body)
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
app.post('/api/import-deposit', (req, res) => {
  const ch = reqChannel(req);
  withLock(ch, async () => {
    let slot = req.body && req.body.recipientSlot;
    let depositor = req.body && req.body.depositor;
    let amount = req.body && req.body.amount;
    if (slot === undefined || depositor === undefined || amount === undefined) {
      const pf = wc(ch, 'pending_deposit.json');
      if (!fs.existsSync(pf)) throw new Error('import-deposit needs { recipientSlot, depositor, amount }');
      const dep = JSON.parse(fs.readFileSync(pf, 'utf8'));
      slot = dep.recipientSlot; depositor = dep.depositor; amount = dep.amount;
    }
    await cli(ch, ['cosign-l1-deposit-import', String(slot), String(amount), depositor, 'l1_import_cosigned.json']);
    const depTicket = findActiveTicket(ch, 'deposit');
    if (depTicket) { depTicket.status = 'import_done'; depTicket.steps.import = { completedAt: Date.now() }; upsertTicket(ch, depTicket); }
    const snap = JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'));
    res.json(snap);
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

app.post('/api/ticket/deposit', (req, res) => {
  const ch = reqChannel(req);
  const { amount, depositor, txHash, recipientSlot } = req.body || {};
  if (!amount || !depositor || !txHash) return res.status(400).json({ error: 'needs { amount, depositor, txHash, recipientSlot }' });
  const existing = findActiveTicket(ch, 'deposit');
  if (existing) return res.status(409).json({ error: 'deposit already pending', ticket: existing });
  const ticket = upsertTicket(ch, {
    id: 'dep_' + Date.now(), type: 'deposit', status: 'l1_done',
    createdAt: Date.now(), updatedAt: Date.now(),
    params: { amount: String(amount), depositor, recipientSlot: recipientSlot || 0, txHash },
    steps: { l1: { completedAt: Date.now(), txHash }, import: null },
  });
  res.json(ticket);
});

// Static frontend (index.html = wallet-live.html, wallet-worker.js, /pkg/...), same origin as /api.
app.use(express.static(PUBLIC));

if (TLS_CERT && TLS_KEY) {
  const opts = { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) };
  https.createServer(opts, app).listen(PORT, '0.0.0.0', () =>
    console.log(`intmax demo (HTTPS) on :${PORT}  channels ${CHANNELS.join(', ')}`));
  http.createServer((req, res) => { res.writeHead(301, { Location: 'https://' + req.headers.host + req.url }); res.end(); }).listen(80, '0.0.0.0');
} else {
  http.createServer(app).listen(PORT, '0.0.0.0', () =>
    console.log(`intmax demo (HTTP) on :${PORT}  channels ${CHANNELS.join(', ')}`));
}
