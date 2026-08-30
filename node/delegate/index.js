'use strict';
// Delegate account entry point (DESIGN.md §4). Boots the WASM wallet session, syncs the channel,
// watches the chain, and accepts user intents (send/inter/burn/refresh) over a small local HTTP
// control interface. Resumable: loads accepted head + tickets before accepting intents.

const http = require('http');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const { ApiClient } = require('../common/api-client');
const {
  ChainWatcher,
  ChainSafetyError,
  isTransientChainSafetyError,
} = require('../common/chain-watcher');
const { Wallet } = require('../common/wallet');
const { Store } = require('../common/store');
const { bootstrapTokenRegistry } = require('../common/token-registry');
const { makeParticipantCloser } = require('./participant-close');
const { makeClaimSettlement } = require('./claim-settlement');
const { SnapshotVault } = require('./snapshot-vault');
const log = require('../common/log');
const alert = require('../common/alert');
const { makeRuntime } = require('./loop');

const DEFAULT_DELEGATE_BODY_LIMIT = 64 * 1024;

function isLoopbackHost(host) {
  const normalized = String(host || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  return normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost';
}

function resolveHttpSecurity(cfg, env = process.env) {
  const host = cfg.delegateHost || '127.0.0.1';
  const bearerToken = env.INTMAX_DELEGATE_BEARER_TOKEN || '';
  const maxBodyBytes = cfg.delegateMaxBodyBytes == null
    ? DEFAULT_DELEGATE_BODY_LIMIT
    : Number(cfg.delegateMaxBodyBytes);
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1024 || maxBodyBytes > 1024 * 1024) {
    throw new Error('delegateMaxBodyBytes must be an integer between 1024 and 1048576');
  }
  // The delegate endpoints authorize transfers and refreshes. They may only be remotely reachable
  // when the operator supplies a high-entropy secret through the environment. TLS/VPN or a trusted
  // local reverse proxy is still required to keep that bearer token confidential in transit.
  if (!isLoopbackHost(host) && Buffer.byteLength(bearerToken, 'utf8') < 32) {
    throw new Error('non-loopback delegateHost requires INTMAX_DELEGATE_BEARER_TOKEN (>= 32 bytes)');
  }
  return { host, bearerToken, maxBodyBytes };
}

function bearerAuthorized(header, expectedToken) {
  if (!expectedToken) return true;
  const actual = Buffer.from(String(header || ''), 'utf8');
  const expected = Buffer.from(`Bearer ${expectedToken}`, 'utf8');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function createChainReadiness() {
  let phase = 'startup';
  return {
    beginPoll() { phase = 'polling'; },
    markReady() { phase = 'ready'; },
    markUnavailable() { phase = 'unavailable'; },
    isReady() { return phase === 'ready'; },
    phase() { return phase; },
  };
}

function makeSingleFlight(task) {
  let inFlight = null;
  return function runSingleFlight() {
    if (inFlight) return inFlight;
    inFlight = Promise.resolve()
      .then(task)
      .finally(() => { inFlight = null; });
    return inFlight;
  };
}

function resolveDelegateSeed(env = process.env) {
  const supplied = String(env.DELEGATE_SEED_HEX || '').trim();
  const raw = supplied.startsWith('0x') ? supplied.slice(2) : supplied;
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error('DELEGATE_SEED_HEX must be a persistent 32-byte hex secret');
  }
  if (/^0{64}$/.test(raw)) throw new Error('DELEGATE_SEED_HEX must not be the all-zero placeholder');
  return raw.toLowerCase();
}

async function startAfterInitialSync(pollChain, sync, startHttpServer, readiness) {
  const ready = await pollChain();
  if (!ready) {
    const error = new Error('initial finalized chain scan did not complete; refusing to expose delegate HTTP');
    error.code = 'CHAIN_STARTUP_UNAVAILABLE';
    throw error;
  }
  try {
    await sync();
  } catch (cause) {
    if (readiness) readiness.markUnavailable();
    const error = new Error(`initial delegate sync failed; refusing to expose HTTP: ${cause && cause.message || cause}`);
    error.code = 'INITIAL_SYNC_FAILED';
    error.cause = cause;
    throw error;
  }
  startHttpServer();
}

function writeJson(res, status, body, headers = {}) {
  if (res.writableEnded) return;
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

function createDelegateHttpHandler({ runtime, store, account, httpSecurity, logger = log }) {
  const routes = new Map([
    ['/intent/send', { method: 'POST', kind: 'send' }],
    ['/intent/inter', { method: 'POST', kind: 'inter' }],
    ['/intent/burn', { method: 'POST', kind: 'burn' }],
    ['/intent/refresh', { method: 'POST', kind: 'refresh' }],
    ['/balance', { method: 'GET', kind: 'balance' }],
    ['/sync', { method: 'POST', kind: 'snapshot' }],
  ]);
  return (req, res) => {
    const route = String(req.url || '').replace(/\?.*$/, '');
    const spec = routes.get(route);
    if (!spec) { writeJson(res, 404, { error: 'not found' }); req.resume(); return; }
    if (req.method !== spec.method) {
      writeJson(res, 405, { error: 'method not allowed' }, { allow: spec.method });
      req.resume();
      return;
    }
    if (!bearerAuthorized(req.headers.authorization, httpSecurity.bearerToken)) {
      writeJson(res, 401, { error: 'unauthorized' });
      req.resume();
      return;
    }
    if (spec.method === 'POST'
        && !/^application\/json(?:\s*;|$)/i.test(String(req.headers['content-type'] || ''))) {
      writeJson(res, 415, { error: 'content-type must be application/json' });
      req.resume();
      return;
    }
    const declaredLength = Number(req.headers['content-length']);
    if (Number.isFinite(declaredLength) && declaredLength > httpSecurity.maxBodyBytes) {
      writeJson(res, 413, { error: 'request body too large' });
      req.resume();
      return;
    }
    const chunks = [];
    let bodyBytes = 0;
    let tooLarge = false;
    req.on('data', (chunk) => {
      bodyBytes += chunk.length;
      if (bodyBytes > httpSecurity.maxBodyBytes) {
        tooLarge = true;
        chunks.length = 0;
      } else if (!tooLarge) {
        chunks.push(chunk);
      }
    });
    req.on('end', async () => {
      if (tooLarge) { writeJson(res, 413, { error: 'request body too large' }); return; }
      let body = {};
      if (chunks.length) {
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
        catch (e) { writeJson(res, 400, { error: 'invalid JSON' }); return; }
      }
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        writeJson(res, 400, { error: 'JSON body must be an object' });
        return;
      }
      // Security-critical routing fields are assigned last so request JSON cannot forge a chain
      // event or redirect one route to another branch.
      const event = { ...body, source: 'api', kind: spec.kind };
      try {
        await runtime.submit(event);
        writeJson(res, 200, {
          ok: true,
          smNode: store.get('smNode'),
          mode: store.get('mode'),
          balance: store.get('balance'),
        });
      } catch (error) {
        const code = String(error && error.code || 'DELEGATE_ACTION_FAILED');
        const unavailable = code === 'CHAIN_TRANSIENT_UNAVAILABLE' || Boolean(store.get('chainSafetyHalt'));
        logger.error({
          event: 'DELEGATE_HTTP_DISPATCH_ERROR',
          channel: account.id,
          code,
          error: String(error && error.message || error),
        });
        writeJson(res, unavailable ? 503 : 500, {
          error: unavailable ? 'chain view unavailable' : 'delegate action failed',
          code,
        });
      }
    });
  };
}

function createDelegateHttpServer(options) {
  const server = http.createServer(createDelegateHttpHandler(options));
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.maxHeadersCount = 64;
  server.maxRequestsPerSocket = 100;
  return server;
}

function loadConfig() {
  const p = process.env.INTMAX_NODE_CONFIG || path.join(__dirname, '..', 'config.json');
  if (!fs.existsSync(p)) { log.error({ event: 'NO_CONFIG', path: p }); process.exit(1); }
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

async function main() {
  const cfg = loadConfig();
  const httpSecurity = resolveHttpSecurity(cfg);
  const account = cfg.account || (cfg.channels && cfg.channels[0]);
  if (!account) { log.error({ event: 'NO_ACCOUNT', hint: 'config.account = { id, slot, recipient, manager, rollup }' }); process.exit(1); }
  account.slot = account.slot != null ? account.slot : 3; // delegates default to slot 3+
  account.recipient = account.recipient || process.env.CLAIM_RECIPIENT;

  const api = new ApiClient({
    baseUrl: cfg.cosignerApiBaseUrl || cfg.apiBaseUrl || 'http://127.0.0.1:8200',
    // Secrets stay in the environment, never in the checked-in JSON config. A co-signer bound to
    // a non-loopback interface refuses to start without this token.
    bearerToken: process.env.INTMAX_COSIGNER_BEARER_TOKEN || '',
  });
  const wallet = new Wallet({ pkgDir: cfg.pkgDir });
  alert.configure({ webhook: cfg.alertWebhook });
  fs.mkdirSync(account.workDir || '.', { recursive: true });
  const store = new Store(path.join(account.workDir || '.', `node-delegate-${account.id}.json`));
  const snapshotVault = new SnapshotVault(account.workDir || '.', account.id);

  // Derive identity from the seed (env, never config). The WASM session holds the secret.
  // A daemon must reproduce the same Regev/Falcon identity after every restart; generating a
  // fresh random session here would make the configured slot and its archived exit witness
  // permanently unreachable. Keep the recovery seed outside config/store and fail closed when it
  // is absent or a placeholder. wallet_keygen_seeded expands it only inside WASM.
  const seed = resolveDelegateSeed();
  if (!wallet.available()) {
    throw new Error('WASM wallet unavailable: refusing to start a delegate that cannot verify or prove');
  }
  await wallet.initialize(cfg.wasmThreads);
  wallet.keygen(seed);
  log.info({ event: 'KEYGEN_OK', channel: account.id, slot: account.slot });

  // requestCloseAsParticipant must be signed by the exact recipient committed in the signed slot
  // leaf. Keep that key in the environment (never config/store); the constructor rejects a key
  // for any other address before the node starts acting. Absence is observable and leaves the
  // node operational for sends, but exit mode will raise a sticky liveness fault instead of
  // pretending it can initiate a close.
  const delegateL1Key = process.env.INTMAX_DELEGATE_L1_PRIVATE_KEY || '';
  const participantCloser = delegateL1Key
    ? makeParticipantCloser({
      rpcUrl: cfg.rpcUrl,
      chainId: cfg.chainId,
      recipient: account.recipient,
      privateKey: delegateL1Key,
    })
    : null;
  const claimSettlement = delegateL1Key
    ? makeClaimSettlement({
      rpcUrl: cfg.rpcUrl,
      chainId: cfg.chainId,
      recipient: account.recipient,
      privateKey: delegateL1Key,
      confirmations: cfg.l1TxConfirmations == null ? 1 : cfg.l1TxConfirmations,
    })
    : null;
  if (!participantCloser) {
    log.warn({
      event: 'UNILATERAL_CLOSE_NOT_CONFIGURED',
      channel: account.id,
      note: 'set INTMAX_DELEGATE_L1_PRIVATE_KEY for the signed recipient address',
    });
  }

  // --- chain watcher (constructed early: the token-manifest verification reads through it) ---
  const watcher = new ChainWatcher({
    rpcUrl: cfg.rpcUrl,
    channels: [account],
    chainId: cfg.chainId,
    confirmations: cfg.confirmations,
    pollIntervalMs: cfg.pollIntervalMs,
    allowUnfinalizedDevnet: cfg.allowUnfinalizedDevnet === true,
  });

  // Token DISPLAY metadata (multi-token §N-1/§N-7), verified against the rollup's set-once
  // `tokenAddressOf` registry. SECURITY: a manifest contradicting a live deployment is fatal —
  // a wrong symbol on a real token is a user-funds attack (TM-10b). Absent information
  // (unregistered index, RPC down) only warns and leaves that entry without metadata.
  let tokenRegistry = null;
  try {
    tokenRegistry = await bootstrapTokenRegistry(cfg, {
      baseDir: path.join(__dirname, '..'),
      rpcUrl: cfg.rpcUrl,
      channels: [account],
      readTokenAddress: (rollup, idx) => watcher.getTokenAddress(rollup, idx),
      logger: log,
    });
  } catch (e) {
    log.error({ event: 'TOKEN_MANIFEST_FATAL', error: String((e && e.message) || e), note: 'refusing to start: the token manifest is invalid or contradicts the chain' });
    process.exit(1);
  }

  const chainReadiness = createChainReadiness();
  const rt = makeRuntime(account, {
    api,
    wallet,
    store,
    log,
    alert,
    policyCfg: cfg.policy || {},
    tokenRegistry,
    participantCloser,
    claimSettlement,
    snapshotVault,
    isChainReady: () => chainReadiness.isReady(),
  });
  const recoverExit = makeSingleFlight(
    () => rt.submit({ source: 'timer', kind: 'recovery' }),
  );

  let pollFailures = 0;
  async function runPollChain() {
    chainReadiness.beginPoll();
    if (store.get('chainSafetyHalt')) {
      chainReadiness.markUnavailable();
      return false;
    }
    try {
      const checked = await watcher.validateCheckpoint(
        Number(store.get('cursor') || 0),
        store.get('chainCheckpoint'),
      );
      const from = Number(store.get('cursor') || 0);
      await watcher.pollOnce(
        from,
        (ev) => rt.submit({ source: 'chain', ...ev }),
        (cursor, checkpoint) => store.setChainProgress(cursor, checkpoint),
      );
      pollFailures = 0;
      chainReadiness.markReady();
      return true;
    } catch (e) {
      chainReadiness.markUnavailable();
      if (e instanceof ChainSafetyError && !isTransientChainSafetyError(e)) {
        const halt = store.haltChainSafety(e);
        log.error({ event: 'CHAIN_SAFETY_HALT', channel: account.id, code: halt.code, error: halt.message });
        await alert.raise(
          'attack',
          account.id,
          'CHAIN_SAFETY_HALT',
          `durable chain processing halted: ${halt.code}: ${halt.message}`,
          halt.evidence,
        );
        return false;
      }
      pollFailures += 1;
      log.warn({ event: 'CHAIN_POLL_ERROR', consecutive: pollFailures, error: String(e && e.message || e) });
      if (pollFailures === 3 || pollFailures % 20 === 0) {
        await alert.raise('fault', account.id, 'CHAIN_WATCHER_WEDGED',
          `delegate chain poll failed ${pollFailures}x at cursor ${store.get('cursor')}`,
          { cursor: store.get('cursor'), error: String(e && e.message || e) });
      }
      return false;
    }
  }

  // A slow RPC request must not create overlapping scans/readiness transitions. Every caller
  // observes the same in-flight verdict; the latch clears only after that scan has settled.
  const pollChain = makeSingleFlight(runPollChain);

  // --- local control HTTP interface for user intents ---
  const server = createDelegateHttpServer({ runtime: rt, store, account, httpSecurity });
  const port = cfg.delegatePort || 8300;
  const startHttpServer = () => server.listen(
    port,
    httpSecurity.host,
    () => log.info({
      event: 'DELEGATE_HTTP_UP',
      host: httpSecurity.host,
      port,
      authenticated: Boolean(httpSecurity.bearerToken),
      channel: account.id,
      slot: account.slot,
    }),
  );

  const interval = cfg.pollIntervalMs || 4000;
  // Authenticate the finalized chain cursor before importing or serving a remote snapshot.
  await startAfterInitialSync(
    pollChain,
    () => rt.submit({ source: 'api', kind: 'snapshot' }),
    startHttpServer,
    chainReadiness,
  );
  setInterval(() => {
    pollChain()
      .then((ready) => {
        if (ready && store.get('mode') === 'exiting') {
          return recoverExit();
        }
        return undefined;
      })
      .catch((e) => log.error({ event: 'LOOP_ERROR', error: String(e && e.message || e) }));
  }, interval);
  log.info({ event: 'DELEGATE_READY', channel: account.id, interval });
}

if (require.main === module) {
  main().catch((e) => { log.error({ event: 'FATAL', error: String(e && e.stack || e) }); process.exit(1); });
}

module.exports = {
  main,
  isLoopbackHost,
  resolveHttpSecurity,
  bearerAuthorized,
  createChainReadiness,
  makeSingleFlight,
  startAfterInitialSync,
  isTransientChainSafetyError,
  createDelegateHttpHandler,
  createDelegateHttpServer,
  resolveDelegateSeed,
  DEFAULT_DELEGATE_BODY_LIMIT,
};
