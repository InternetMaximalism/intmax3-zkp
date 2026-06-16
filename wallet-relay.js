// Local relay so the browser wallet can run a real send with just clicks: it serves the wallet
// static files (with COEP/COOP for SharedArrayBuffer / threads) AND exposes /api endpoints that
// invoke the CLI companion (channel_member) for the "other members". The browser does the proving;
// the relay does the native co-signing. Dev-only: localhost, self-signed TLS.
const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = __dirname;
const WORK = path.join(ROOT, 'wallet-live-work');
const CLI = path.join(ROOT, 'target', 'release', 'channel_member');
const PORT = 8000;

fs.mkdirSync(WORK, { recursive: true });
const w = (n) => path.join(WORK, n);
function cli(args) {
  console.log('  $ channel_member', args.join(' '));
  return execFileSync(CLI, args, { cwd: WORK, encoding: 'utf8' });
}

const app = express();
app.use(express.json({ limit: '64mb' }));
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

// Step 1 (delegate demo): browser sends its DELEGATE genesis contribution → CLI builds the channel
// with 3 co-signing members + the browser delegate, the 3 members sign the genesis, and the CLI
// returns the FULLY-SIGNED snapshot for the browser to import directly (the delegate does NOT sign
// the genesis).
app.post('/api/init', (req, res) => {
  try {
    // CREATE-OR-JOIN: the first browser creates the channel (3 members + delegate slot 3); each
    // later browser JOINS the SAME channel as a distinct delegate (slot 4, 5, …). cli_state.json is
    // NOT reset here (only on relay startup) so existing delegates are preserved.
    fs.mkdirSync(WORK, { recursive: true });
    fs.writeFileSync(w('contribution.json'), JSON.stringify(req.body));
    cli(['init', 'contribution.json', 'channel_snapshot.json']);
    res.json(JSON.parse(fs.readFileSync(w('channel_snapshot.json'), 'utf8')));
  } catch (e) { { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); } }
});

// Latest fully-signed channel snapshot — browsers re-import this before sending so they pick up any
// newly-joined delegates (and the current head).
app.get('/api/snapshot', (req, res) => {
  try {
    res.json(JSON.parse(fs.readFileSync(w('channel_snapshot.json'), 'utf8')));
  } catch (e) { res.status(404).json({ error: 'no channel yet' }); }
});

// (Legacy member-mode genesis co-signing — unused by the delegate demo, where the browser does not
// sign the genesis. Kept for the member-mode wallet.)
app.post('/api/add-genesis-sig', (req, res) => {
  try {
    fs.writeFileSync(w('browser_sig.json'), JSON.stringify(req.body));
    cli(['add-genesis-sig', 'browser_sig.json', 'channel_snapshot.json']);
    res.json(JSON.parse(fs.readFileSync(w('channel_snapshot.json'), 'utf8')));
  } catch (e) { { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); } }
});

// Step 3: browser sends a transfer payload → CLI co-signs (other members) → returns the
// fully-signed next state for the browser to finalize.
app.post('/api/cosign', (req, res) => {
  try {
    fs.writeFileSync(w('payload.json'), JSON.stringify(req.body));
    cli(['cosign', 'payload.json', 'cosigned.json']);
    res.json(JSON.parse(fs.readFileSync(w('cosigned.json'), 'utf8')));
  } catch (e) { { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); } }
});

// Balance-refresh: browser re-encrypts its own slot (RefreshPayload) → CLI members co-sign → returns
// the fully-signed next state for the browser to finalize. Lets a delegate send again after receiving.
app.post('/api/refresh-cosign', (req, res) => {
  try {
    fs.writeFileSync(w('refresh_payload.json'), JSON.stringify(req.body));
    cli(['cosign-refresh', 'refresh_payload.json', 'refresh_cosigned.json']);
    res.json(JSON.parse(fs.readFileSync(w('refresh_cosigned.json'), 'utf8')));
  } catch (e) { { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); } }
});

// Static wallet files (wallet-live.html, wallet-worker.js, /pkg/...).
app.use(express.static(ROOT));

const opts = {
  key: fs.readFileSync(path.join(ROOT, 'self_certs', 'key.pem')),
  cert: fs.readFileSync(path.join(ROOT, 'self_certs', 'cert.pem')),
};
// Fresh channel per relay process: clear any prior channel on startup (restart the relay to start a
// brand-new channel). During a run, the channel persists so delegates accumulate (create-or-join).
fs.rmSync(w('cli_state.json'), { force: true });
fs.rmSync(w('channel_snapshot.json'), { force: true });

// detail2 §F-1 deposit backing: the channel must be backed by a REAL base-layer balance proof
// before any member co-signs (the CLI gate refuses an unbacked channel). Produce it ONCE here
// (~30s); it persists across relay restarts (the per-process reset above clears only the channel
// state, not the backing files), so this runs only on the very first launch.
const backed = ['channel_backing.json', 'channel_attestation.bin', 'balance_vd.bin'].every((f) =>
  fs.existsSync(w(f))
);
if (!backed) {
  console.log('No deposit backing yet — running `channel_member setup-backing` (one-time, ~30s)…');
  cli(['setup-backing']);
}

https.createServer(opts, app).listen(PORT, '0.0.0.0', () => {
  console.log(`wallet relay on https://localhost:${PORT}/wallet-live.html`);
});
