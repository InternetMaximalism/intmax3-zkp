'use strict';
// Co-signer node entry point (DESIGN.md §3). Boots per-channel runtimes, serves peer cosign requests
// over HTTP, polls the chain for events, and ticks timers for co-signer-driven close/PW steps.
// Resumable: loads cursors/tickets, backfills chain events, then accepts requests.

const http = require('http');
const path = require('path');
const fs = require('fs');

const { makeCli } = require('../common/cli');
const { ApiClient } = require('../common/api-client');
const { ChainWatcher } = require('../common/chain-watcher');
const { Store } = require('../common/store');
const log = require('../common/log');
const alert = require('../common/alert');
const { makeRuntime, makeLock } = require('./loop');

function loadConfig() {
  const p = process.env.INTMAX_NODE_CONFIG || path.join(__dirname, '..', 'config.json');
  if (!fs.existsSync(p)) {
    log.error({ event: 'NO_CONFIG', path: p, hint: 'copy node/config.example.json to node/config.json' });
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

async function main() {
  const cfg = loadConfig();
  const repoRoot = path.join(__dirname, '..', '..');
  const cli = makeCli({ binPath: process.env.CHANNEL_MEMBER_BIN, repoRoot });
  const api = new ApiClient({ baseUrl: cfg.apiBaseUrl || 'http://127.0.0.1:8100' });
  alert.configure({ webhook: cfg.alertWebhook });

  // Authoritative on-chain pending-close reader for the defensive close game (review C1).
  const watcher = new ChainWatcher({ rpcUrl: cfg.rpcUrl, channels: cfg.channels, confirmations: cfg.confirmations, pollIntervalMs: cfg.pollIntervalMs });
  const getPendingClose = (managerAddr) => watcher.getPendingClose(managerAddr);

  const runtimes = new Map(); // channelId -> { runtime, lock }
  for (const ch of cfg.channels) {
    fs.mkdirSync(ch.workDir, { recursive: true });
    const store = new Store(path.join(ch.workDir, 'node-cosigner-state.json'));
    const runtime = makeRuntime(ch, { cli, api, store, log, alert, rpc: cfg.rpcUrl, policyCfg: cfg.policy || {}, getPendingClose });
    runtimes.set(ch.id, { runtime, lock: makeLock(), ch, store });
  }

  // --- HTTP server for peer requests (delegate → co-signer) ---
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const m = req.url.match(/^\/api\/v1\/channel\/(\d+)\/(cosign|cosign-refresh|inter-channel\/send|burn\/cosign|snapshot)$/);
      if (!m) { res.writeHead(404).end(JSON.stringify({ error: 'not found' })); return; }
      const chId = Number(m[1]);
      const rt = runtimes.get(chId);
      if (!rt) { res.writeHead(404).end(JSON.stringify({ error: 'unknown channel' })); return; }
      let body = {};
      try { body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}; }
      catch (e) { res.writeHead(400).end(JSON.stringify({ error: 'invalid JSON' })); return; }
      const kindMap = { cosign: 'cosign', 'cosign-refresh': 'cosign-refresh', 'inter-channel/send': 'inter', 'burn/cosign': 'burn', snapshot: 'snapshot' };
      const event = { source: 'api', kind: kindMap[m[2]], body, sender: body && body.sender };
      const result = await rt.lock(() => rt.runtime.dispatch(event));
      const out = result || { ok: true, status: 200, body: {} };
      res.writeHead(out.status || 200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(out.body || {}));
    });
  });
  const port = cfg.cosignerPort || 8200;
  server.listen(port, () => log.info({ event: 'COSIGNER_HTTP_UP', port, channels: cfg.channels.map((c) => c.id) }));

  // --- chain watcher poll loop (watcher constructed above for getPendingClose) ---
  const pollFailures = new Map(); // channelId -> consecutive failure count
  async function pollChain() {
    for (const { runtime, lock, ch, store } of runtimes.values()) {
      try {
        const from = store.get('cursor') || 0;
        await watcher.pollOnce(
          from,
          (ev) => lock(() => runtime.dispatch({ source: 'chain', ...ev })),
          (cursor) => store.setCursor(cursor)
        );
        pollFailures.set(ch.id, 0);
      } catch (e) {
        const n = (pollFailures.get(ch.id) || 0) + 1;
        pollFailures.set(ch.id, n);
        log.warn({ event: 'CHAIN_POLL_ERROR', channel: ch.id, consecutive: n, error: String(e && e.message || e) });
        // A wedged cursor (same block failing every tick) is a silent liveness halt — escalate to
        // an ALERT after a few consecutive failures (review MED-3), not just a warn.
        if (n === 3 || n % 20 === 0) {
          await alert.raise('fault', ch.id, 'CHAIN_WATCHER_WEDGED',
            `chain poll failed ${n}x consecutively at cursor ${store.get('cursor')}; later blocks are not being processed`,
            { cursor: store.get('cursor'), error: String(e && e.message || e) });
        }
      }
    }
  }

  // --- timer tick: derive settle_due / pw_finalize_due from tickets + on-chain deadlines ---
  async function tick() {
    for (const { runtime, lock, store } of runtimes.values()) {
      const fw = store.findTicket((t) => t.type === 'full_withdrawal' && t.status === 'close_submitted_finalizable');
      if (fw) await lock(() => runtime.dispatch({ source: 'timer', kind: 'settle_due', closeIntentDigest: fw.params && fw.params.closeIntentDigest }));
      const pw = store.findTicket((t) => t.type === 'partial_withdrawal' && t.status === 'settle_finalizable');
      if (pw) await lock(() => runtime.dispatch({ source: 'timer', kind: 'pw_finalize_due', authDigest: pw.params && pw.params.authDigest }));
    }
  }

  const interval = cfg.pollIntervalMs || 4000;
  const loop = async () => { await pollChain(); await tick(); };
  await loop();
  setInterval(() => { loop().catch((e) => log.error({ event: 'LOOP_ERROR', error: String(e && e.message || e) })); }, interval);
  log.info({ event: 'COSIGNER_READY', interval });
}

if (require.main === module) {
  main().catch((e) => { log.error({ event: 'FATAL', error: String(e && e.stack || e) }); process.exit(1); });
}

module.exports = { main };
