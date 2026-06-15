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
  next();
});

// Step 1: browser sends its genesis contribution → CLI builds the channel → returns the genesis
// state for the browser to sign.
app.post('/api/init', (req, res) => {
  try {
    // Fresh channel each time.
    fs.mkdirSync(WORK, { recursive: true });
    fs.rmSync(w('cli_state.json'), { force: true });
    fs.writeFileSync(w('contribution.json'), JSON.stringify(req.body));
    cli(['init', 'contribution.json', 'genesis_to_sign.json']);
    res.json(JSON.parse(fs.readFileSync(w('genesis_to_sign.json'), 'utf8')));
  } catch (e) { { console.error(e.stderr ? String(e.stderr) : (e.message||e)); res.status(500).json({ error: String(e.stderr || e.message || e) }); } }
});

// Step 2: browser returns its genesis signature → CLI assembles the fully-signed snapshot.
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

// Static wallet files (wallet-live.html, wallet-worker.js, /pkg/...).
app.use(express.static(ROOT));

const opts = {
  key: fs.readFileSync(path.join(ROOT, 'self_certs', 'key.pem')),
  cert: fs.readFileSync(path.join(ROOT, 'self_certs', 'cert.pem')),
};
https.createServer(opts, app).listen(PORT, '0.0.0.0', () => {
  console.log(`wallet relay on https://localhost:${PORT}/wallet-live.html`);
});
