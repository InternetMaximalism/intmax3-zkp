// EC2 all-in-one host for the two-channel payment-channel demo: serves the static frontend
// (wallet-live.html + worker + wasm) AND the /api co-signing endpoints from a SINGLE origin, over
// HTTPS, with the COEP/COOP headers that the multi-threaded wasm proving needs (SharedArrayBuffer
// requires a secure context + cross-origin isolation). The two channels' deposit backing is
// pre-built locally against Sepolia and shipped here, so there is NO anvil/forge/setup-backing on
// this box — it only co-signs.
const express = require('express');
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
function cli(ch, args) {
  console.log(`  $ INTMAX_CHANNEL=${ch} channel_member ${args.join(' ')}`);
  return execFileSync(CLI, args, { cwd: chDir(ch), encoding: 'utf8', env: { ...process.env, INTMAX_CHANNEL: String(ch) } });
}

// Fail fast if the deposit backing was not shipped — this box must never fabricate a channel.
for (const ch of CHANNELS) {
  const ok = ['channel_backing.json', 'channel_attestation.bin', 'balance_vd.bin'].every((f) => fs.existsSync(wc(ch, f)));
  if (!ok) { console.error(`channel ${ch}: missing deposit backing in ${chDir(ch)}`); process.exit(1); }
  fs.rmSync(wc(ch, 'cli_state.json'), { force: true });
  fs.rmSync(wc(ch, 'channel_snapshot.json'), { force: true });
}

const app = express();
app.use(express.json({ limit: '64mb' }));
// Cross-origin isolation (SharedArrayBuffer / wasm threads) + correct wasm mime + no caching.
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (req.path.endsWith('.wasm')) res.setHeader('Content-Type', 'application/wasm');
  res.setHeader('Cache-Control', 'no-store');
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
