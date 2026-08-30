'use strict';
// Co-signer node entry point (DESIGN.md §3). Boots per-channel runtimes, serves peer cosign requests
// over HTTP, polls the chain for events, and ticks timers for co-signer-driven close/PW steps.
// Resumable: loads cursors/tickets, backfills chain events, then accepts requests.

const http = require('http');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const { makeCli } = require('../common/cli');
const { ApiClient } = require('../common/api-client');
const { ChainWatcher } = require('../common/chain-watcher');
const { Store } = require('../common/store');
const { bootstrapTokenRegistry } = require('../common/token-registry');
const log = require('../common/log');
const alert = require('../common/alert');
const { makeRuntime, makeLock } = require('./loop');

const DEFAULT_COSIGNER_BODY_LIMIT = 1024 * 1024;

function isLoopbackHost(host) {
  const normalized = String(host || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  return normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost';
}

function resolveHttpSecurity(cfg, env = process.env) {
  const host = cfg.cosignerHost || '127.0.0.1';
  const bearerToken = env.INTMAX_COSIGNER_BEARER_TOKEN || '';
  const maxBodyBytes = cfg.cosignerMaxBodyBytes == null
    ? DEFAULT_COSIGNER_BODY_LIMIT
    : Number(cfg.cosignerMaxBodyBytes);
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1024 || maxBodyBytes > 16 * 1024 * 1024) {
    throw new Error('cosignerMaxBodyBytes must be an integer between 1024 and 16777216');
  }
  // `server.listen(port)` binds all interfaces on many platforms. A remotely reachable signing
  // oracle must never come up unauthenticated; keep the secret out of config and require enough
  // entropy to resist online guessing. TLS/VPN or a trusted local reverse proxy remains required
  // to protect this bearer token in transit.
  if (!isLoopbackHost(host) && bearerToken.length < 32) {
    throw new Error('non-loopback cosignerHost requires INTMAX_COSIGNER_BEARER_TOKEN (>= 32 chars)');
  }
  return { host, bearerToken, maxBodyBytes };
}

function bearerAuthorized(header, expectedToken) {
  if (!expectedToken) return true;
  const actual = Buffer.from(String(header || ''), 'utf8');
  const expected = Buffer.from(`Bearer ${expectedToken}`, 'utf8');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function targetRuntimeIds(event, runtimes) {
  const requested = Array.isArray(event && event.channelIds)
    ? event.channelIds
    : (event && event.channelId !== undefined && event.channelId !== null ? [event.channelId] : []);
  return [...new Set(requested)].filter(id => runtimes.has(id));
}

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
  const httpSecurity = resolveHttpSecurity(cfg);
  const repoRoot = path.join(__dirname, '..', '..');
  const cli = makeCli({ binPath: process.env.CHANNEL_MEMBER_BIN, repoRoot });
  const api = new ApiClient({ baseUrl: cfg.apiBaseUrl || 'http://127.0.0.1:8100' });
  alert.configure({ webhook: cfg.alertWebhook });

  // Authoritative on-chain pending-close reader for the defensive close game (review C1).
  const watcher = new ChainWatcher({ rpcUrl: cfg.rpcUrl, channels: cfg.channels, confirmations: cfg.confirmations, pollIntervalMs: cfg.pollIntervalMs });
  const getPendingClose = (managerAddr) => watcher.getPendingClose(managerAddr);

  // Token DISPLAY metadata (multi-token §N-1/§N-7). The mapping is HELD by the running node and
  // verified against the rollup's set-once `tokenAddressOf` registry before anything is served.
  // SECURITY: a manifest that CONTRADICTS a live deployment is a hard startup failure — showing a
  // wrong symbol for a real token is a user-funds attack (TM-10b), so we refuse to run instead.
  // Absent information (index not registered yet, RPC unreachable) only warns: those entries stay
  // unverified and are served with null metadata.
  let tokenRegistry = null;
  try {
    tokenRegistry = await bootstrapTokenRegistry(cfg, {
      baseDir: path.join(__dirname, '..'),
      rpcUrl: cfg.rpcUrl,
      channels: cfg.channels,
      readTokenAddress: (rollup, idx) => watcher.getTokenAddress(rollup, idx),
      logger: log,
    });
  } catch (e) {
    log.error({ event: 'TOKEN_MANIFEST_FATAL', error: String((e && e.message) || e), note: 'refusing to start: the token manifest is invalid or contradicts the chain' });
    process.exit(1);
  }

  const runtimes = new Map(); // channelId -> { runtime, lock }
  for (const ch of cfg.channels) {
    fs.mkdirSync(ch.workDir, { recursive: true });
    const store = new Store(path.join(ch.workDir, 'node-cosigner-state.json'));
    const runtime = makeRuntime(ch, { cli, api, store, log, alert, rpc: cfg.rpcUrl, policyCfg: cfg.policy || {}, getPendingClose, tokenRegistry });
    runtimes.set(ch.id, { runtime, lock: makeLock(), ch, store });
  }

  // --- HTTP server for peer requests (delegate → co-signer) ---
  const server = http.createServer((req, res) => {
    const route = String(req.url || '').replace(/\?.*$/, '');
    const m = route.match(/^\/api\/v1\/channel\/(\d+)\/(cosign|cosign-refresh|inter-channel\/send|burn\/cosign|snapshot)$/);
    if (!m) { res.writeHead(404).end(JSON.stringify({ error: 'not found' })); req.resume(); return; }
    const expectedMethod = m[2] === 'snapshot' ? 'GET' : 'POST';
    if (req.method !== expectedMethod) {
      res.writeHead(405, { allow: expectedMethod }).end(JSON.stringify({ error: 'method not allowed' }));
      req.resume();
      return;
    }
    if (!bearerAuthorized(req.headers.authorization, httpSecurity.bearerToken)) {
      res.writeHead(401).end(JSON.stringify({ error: 'unauthorized' }));
      req.resume();
      return;
    }
    const declaredLength = Number(req.headers['content-length']);
    if (Number.isFinite(declaredLength) && declaredLength > httpSecurity.maxBodyBytes) {
      res.writeHead(413).end(JSON.stringify({ error: 'request body too large' }));
      req.resume();
      return;
    }
    const chunks = [];
    let bodyBytes = 0;
    let tooLarge = false;
    req.on('data', (c) => {
      bodyBytes += c.length;
      if (bodyBytes > httpSecurity.maxBodyBytes) {
        tooLarge = true;
        chunks.length = 0;
      } else if (!tooLarge) {
        chunks.push(c);
      }
    });
    req.on('end', async () => {
      if (tooLarge) { res.writeHead(413).end(JSON.stringify({ error: 'request body too large' })); return; }
      const chId = Number(m[1]);
      const rt = runtimes.get(chId);
      if (!rt) { res.writeHead(404).end(JSON.stringify({ error: 'unknown channel' })); return; }
      let body = {};
      try { body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}; }
      catch (e) { res.writeHead(400).end(JSON.stringify({ error: 'invalid JSON' })); return; }
      const kindMap = { cosign: 'cosign', 'cosign-refresh': 'cosign-refresh', 'inter-channel/send': 'inter', 'burn/cosign': 'burn', snapshot: 'snapshot' };
      const event = { source: 'api', kind: kindMap[m[2]], body, sender: body && body.sender };
      try {
        const result = await rt.lock(() => rt.runtime.dispatch(event));
        const out = result || { ok: true, status: 200, body: {} };
        res.writeHead(out.status || 200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(out.body || {}));
      } catch (e) {
        log.error({ event: 'COSIGNER_HTTP_DISPATCH_ERROR', channel: chId, error: String(e && e.message || e) });
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal dispatch failure' }));
      }
    });
  });
  const port = cfg.cosignerPort || 8200;
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.listen(port, httpSecurity.host, () => log.info({
    event: 'COSIGNER_HTTP_UP',
    host: httpSecurity.host,
    port,
    authenticated: Boolean(httpSecurity.bearerToken),
    channels: cfg.channels.map((c) => c.id),
  }));

  // --- chain watcher poll loop (watcher constructed above for getPendingClose) ---
  const pollFailures = new Map(); // channelId -> consecutive failure count
  async function pollChain() {
    const entries = [...runtimes.values()];
    if (entries.length === 0) return;
    // One RPC scan covers all configured addresses. The previous per-runtime loop scanned the same
    // logs N times and dispatched every decoded event into whichever runtime happened to own that
    // iteration, so one manager's close could freeze every channel. Start at the least-advanced
    // per-channel cursor and skip already-consumed events for runtimes that are further ahead.
    const from = Math.min(...entries.map(({ store }) => Number(store.get('cursor') || 0)));
    try {
      await watcher.pollOnce(
        from,
        async (ev) => {
          for (const id of targetRuntimeIds(ev, runtimes)) {
            const target = runtimes.get(id);
            if (Number(target.store.get('cursor') || 0) > Number(ev.blockNumber)) continue;
            try {
              await target.lock(() => target.runtime.dispatch({ source: 'chain', ...ev }));
            } catch (e) {
              const routedError = e instanceof Error ? e : new Error(String(e));
              routedError.chainChannelId = id;
              throw routedError;
            }
          }
        },
        (cursor) => {
          for (const { store } of entries) store.setCursor(cursor);
        },
      );
      for (const { ch } of entries) pollFailures.set(ch.id, 0);
    } catch (e) {
      const affected = e && e.chainChannelId !== undefined
        ? entries.filter(({ ch }) => String(ch.id) === String(e.chainChannelId))
        : entries;
      for (const { ch, store } of affected) {
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

module.exports = {
  main,
  targetRuntimeIds,
  isLoopbackHost,
  resolveHttpSecurity,
  bearerAuthorized,
  DEFAULT_COSIGNER_BODY_LIMIT,
};
