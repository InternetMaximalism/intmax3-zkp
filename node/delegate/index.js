'use strict';
// Delegate account entry point (DESIGN.md §4). Boots the WASM wallet session, syncs the channel,
// watches the chain, and accepts user intents (send/inter/burn/refresh) over a small local HTTP
// control interface. Resumable: loads accepted head + tickets before accepting intents.

const http = require('http');
const path = require('path');
const fs = require('fs');

const { ApiClient } = require('../common/api-client');
const { ChainWatcher } = require('../common/chain-watcher');
const { Wallet } = require('../common/wallet');
const { Store } = require('../common/store');
const log = require('../common/log');
const alert = require('../common/alert');
const { makeRuntime } = require('./loop');

function loadConfig() {
  const p = process.env.INTMAX_NODE_CONFIG || path.join(__dirname, '..', 'config.json');
  if (!fs.existsSync(p)) { log.error({ event: 'NO_CONFIG', path: p }); process.exit(1); }
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

async function main() {
  const cfg = loadConfig();
  const account = cfg.account || (cfg.channels && cfg.channels[0]);
  if (!account) { log.error({ event: 'NO_ACCOUNT', hint: 'config.account = { id, slot, recipient, manager, rollup }' }); process.exit(1); }
  account.slot = account.slot != null ? account.slot : 3; // delegates default to slot 3+
  account.recipient = account.recipient || process.env.CLAIM_RECIPIENT;

  const api = new ApiClient({ baseUrl: cfg.apiBaseUrl || 'http://127.0.0.1:8200' });
  const wallet = new Wallet({ pkgDir: cfg.pkgDir });
  alert.configure({ webhook: cfg.alertWebhook });
  fs.mkdirSync(account.workDir || '.', { recursive: true });
  const store = new Store(path.join(account.workDir || '.', `node-delegate-${account.id}.json`));

  // Derive identity from the seed (env, never config). The WASM session holds the secret.
  const seed = process.env.DELEGATE_SEED_HEX || null;
  if (wallet.available()) {
    try { wallet.keygen(seed); log.info({ event: 'KEYGEN_OK', channel: account.id, slot: account.slot }); }
    catch (e) { log.warn({ event: 'KEYGEN_FAILED', error: String(e && e.message || e) }); }
  } else {
    log.warn({ event: 'WASM_UNAVAILABLE', note: 'build pkg-node to enable proving; control loop still runs' });
  }

  const rt = makeRuntime(account, { api, wallet, store, log, alert, policyCfg: cfg.policy || {} });

  // Initial sync.
  try { await rt.submit({ source: 'api', kind: 'snapshot' }); } catch (e) { log.warn({ event: 'INITIAL_SYNC_FAILED', error: String(e && e.message || e) }); }

  // --- chain watcher ---
  const watcher = new ChainWatcher({ rpcUrl: cfg.rpcUrl, channels: [account], confirmations: cfg.confirmations, pollIntervalMs: cfg.pollIntervalMs });
  let pollFailures = 0;
  async function pollChain() {
    try {
      const from = store.get('cursor') || 0;
      await watcher.pollOnce(from, (ev) => rt.submit({ source: 'chain', ...ev }), (cursor) => store.setCursor(cursor));
      pollFailures = 0;
    } catch (e) {
      pollFailures += 1;
      log.warn({ event: 'CHAIN_POLL_ERROR', consecutive: pollFailures, error: String(e && e.message || e) });
      if (pollFailures === 3 || pollFailures % 20 === 0) {
        await alert.raise('fault', account.id, 'CHAIN_WATCHER_WEDGED',
          `delegate chain poll failed ${pollFailures}x at cursor ${store.get('cursor')}`,
          { cursor: store.get('cursor'), error: String(e && e.message || e) });
      }
    }
  }

  // --- local control HTTP interface for user intents ---
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      let body = {};
      try { body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}; } catch (e) {}
      const route = req.url.replace(/\?.*$/, '');
      const map = {
        '/intent/send': { kind: 'send' }, '/intent/inter': { kind: 'inter' },
        '/intent/burn': { kind: 'burn' }, '/intent/refresh': { kind: 'refresh' },
        '/balance': { kind: 'balance' }, '/sync': { kind: 'snapshot' },
      };
      const spec = map[route];
      if (!spec) { res.writeHead(404).end(JSON.stringify({ error: 'not found' })); return; }
      try {
        await rt.submit({ source: 'api', ...spec, ...body });
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, smNode: store.get('smNode'), mode: store.get('mode'), balance: store.get('balance') }));
      } catch (e) {
        res.writeHead(500).end(JSON.stringify({ error: String(e && e.message || e) }));
      }
    });
  });
  const port = cfg.delegatePort || 8300;
  server.listen(port, () => log.info({ event: 'DELEGATE_HTTP_UP', port, channel: account.id, slot: account.slot }));

  const interval = cfg.pollIntervalMs || 4000;
  await pollChain();
  setInterval(() => { pollChain().catch((e) => log.error({ event: 'LOOP_ERROR', error: String(e && e.message || e) })); }, interval);
  log.info({ event: 'DELEGATE_READY', channel: account.id, interval });
}

if (require.main === module) {
  main().catch((e) => { log.error({ event: 'FATAL', error: String(e && e.stack || e) }); process.exit(1); });
}

module.exports = { main };
