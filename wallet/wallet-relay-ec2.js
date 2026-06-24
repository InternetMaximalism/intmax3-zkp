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
const { execFileSync } = require('child_process');

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
function cli(ch, args, extraEnv) {
  console.log(`  $ INTMAX_CHANNEL=${ch} channel_member ${args.join(' ')}`);
  return execFileSync(CLI, args, { cwd: chDir(ch), encoding: 'utf8', env: { ...process.env, INTMAX_CHANNEL: String(ch), ...(extraEnv || {}) } });
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
    console.log(`channel ${ch}: RESET_CHANNELS=1 → cleared prior membership`);
  }
}

const app = express();
// Lightweight request log (method + path + content-length) — so a failing POST is visible in the
// journal. Kept intentionally minimal (no bodies).
app.use((req, res, next) => {
  console.log(`REQ ${req.method} ${req.url} len=${req.headers['content-length'] || 0}`);
  next();
});
// gzip the big static assets (the 2.5MB wasm → ~1.2MB) — a real win on mobile networks where the
// download dominates "initializing". Compress wasm/js/html/json regardless of the default heuristic.
app.use(compression({
  filter: (req, res) => {
    const ct = String(res.getHeader('Content-Type') || '');
    if (/wasm|javascript|json|html|text|octet-stream/.test(ct)) return true;
    return compression.filter(req, res);
  },
}));
app.use(express.json({ limit: '64mb' }));
// Cross-origin isolation (SharedArrayBuffer / wasm threads) + correct wasm mime + no caching.
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (req.path.endsWith('.wasm')) res.setHeader('Content-Type', 'application/wasm');
  // Cache the immutable prover assets so a reload doesn't re-download the 2.5MB wasm; never cache the
  // HTML/JS shell or the dynamic /api responses.
  if (req.path.startsWith('/pkg/')) res.setHeader('Cache-Control', 'public, max-age=3600');
  else res.setHeader('Cache-Control', 'no-store');
  next();
});

app.get('/api/health', (req, res) => res.json({ ok: true, channels: CHANNELS }));
app.get('/api/channels', (req, res) => res.json({ channels: CHANNELS }));

app.post('/api/init', (req, res) => {
  try {
    const ch = reqChannel(req);
    fs.writeFileSync(wc(ch, 'contribution.json'), JSON.stringify(req.body));
    cli(ch, ['init', 'contribution.json', 'channel_snapshot.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8')));
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});

app.get('/api/snapshot', (req, res) => {
  try { const ch = reqChannel(req); res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_snapshot.json'), 'utf8'))); }
  catch (e) { res.status(404).json({ error: 'no channel yet' }); }
});

app.get('/api/backing', (req, res) => {
  try { const ch = reqChannel(req); res.json(JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'))); }
  catch (e) { res.status(404).json({ error: 'no deposit backing yet' }); }
});

app.post('/api/cosign', (req, res) => {
  try {
    const ch = reqChannel(req);
    fs.writeFileSync(wc(ch, 'payload.json'), JSON.stringify(req.body));
    cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'cosigned.json'), 'utf8')));
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});

app.post('/api/refresh-cosign', (req, res) => {
  try {
    const ch = reqChannel(req);
    fs.writeFileSync(wc(ch, 'refresh_payload.json'), JSON.stringify(req.body));
    cli(ch, ['cosign-refresh', 'refresh_payload.json', 'refresh_cosigned.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'refresh_cosigned.json'), 'utf8')));
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});

// Inter-channel send (SINGLE atomic endpoint). `?channel=A` = the SOURCE channel; this box co-signs
// BOTH channels, so this one command debits A and credits B atomically. There is NO standalone credit
// endpoint trusting a request-body signed state (CRITICAL-1 value-creation hole, now closed): the only
// `a_signed_state` the credit gate sees is the debit this command just co-signed by extending A's
// COMMITTED on-disk head.
// Body = { debitPayload: InterChannelDebitPayload, transferDescriptor: InterChannelTransferDescriptor }.
// Returns { aHead: <A's co-signed new state>, bSnapshot: <B's credited snapshot> }.
app.post('/api/inter/send', (req, res) => {
  try {
    const ch = reqChannel(req); // = source channel A
    const debitPayload = req.body && req.body.debitPayload;
    const descriptor = req.body && req.body.transferDescriptor;
    if (!debitPayload || !descriptor) throw new Error('inter/send needs { debitPayload, transferDescriptor }');
    fs.writeFileSync(wc(ch, 'inter_debit_payload.json'), JSON.stringify(debitPayload));
    fs.writeFileSync(wc(ch, 'inter_descriptor.json'), JSON.stringify(descriptor));
    cli(ch, ['cosign-inter-transfer', 'inter_debit_payload.json', 'inter_descriptor.json', 'inter_transfer.json']);
    res.json(JSON.parse(fs.readFileSync(wc(ch, 'inter_transfer.json'), 'utf8')));
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});

// ─── A-3 close lifecycle (close → settle → withdraw → claim) ────────────────────────────────────
// Same thin wrappers as the local relay. Heavy (real proving); the caller supplies the channel's
// deployed manager (+ sv for close); the rollup comes from channel_backing.json; RPC from the env.
app.post('/api/close', (req, res) => {
  try {
    const ch = reqChannel(req); const manager = req.body && req.body.manager; const sv = (req.body && req.body.sv) || '';
    if (!manager) throw new Error('close needs { manager }');
    res.json({ ok: true, log: cli(ch, ['close', manager, RPC], { CLOSE_SV: sv }) });
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});
app.post('/api/settle', (req, res) => {
  try {
    const ch = reqChannel(req); const manager = req.body && req.body.manager;
    if (!manager) throw new Error('settle needs { manager }');
    res.json({ ok: true, log: cli(ch, ['settle', manager, RPC]) });
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});
app.post('/api/withdraw', (req, res) => {
  try {
    const ch = reqChannel(req); const manager = req.body && req.body.manager;
    if (!manager) throw new Error('withdraw needs { manager }');
    res.json({ ok: true, log: cli(ch, ['withdraw', manager, RPC], { ROLLUP: rollupOf(ch) }) });
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});
app.post('/api/claim', (req, res) => {
  try {
    const ch = reqChannel(req); const manager = req.body && req.body.manager; const slot = req.body && req.body.slot; const recipient = req.body && req.body.recipient;
    if (!manager || slot === undefined || !recipient) throw new Error('claim needs { manager, slot, recipient }');
    res.json({ ok: true, log: cli(ch, ['claim', manager, String(slot), RPC], { CLAIM_RECIPIENT: recipient }) });
  } catch (e) { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); }
});

// Static frontend (index.html = wallet-live.html, wallet-worker.js, /pkg/...), same origin as /api.
app.use(express.static(PUBLIC));

if (TLS_CERT && TLS_KEY) {
  const opts = { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) };
  https.createServer(opts, app).listen(PORT, '0.0.0.0', () =>
    console.log(`intmax demo (HTTPS) on :${PORT}  channels ${CHANNELS.join(', ')}`));
  // Redirect plain HTTP :80 → HTTPS so the bare host works.
  http.createServer((req, res) => { res.writeHead(301, { Location: 'https://' + req.headers.host + req.url }); res.end(); }).listen(80, '0.0.0.0');
} else {
  http.createServer(app).listen(PORT, '0.0.0.0', () =>
    console.log(`intmax demo (HTTP) on :${PORT}  channels ${CHANNELS.join(', ')}`));
}
