'use strict';
// On a public chain the relay must refuse, before taking any lock or signing anything:
//  * a burn (partial withdrawal Step 1): its L1 settlement is not wired for a public chain, and a
//    burn without settlement stranded a user's 0.005 ETH on the v3 testnet;
//  * close / settle / withdraw / settlement deploy: the relay signs them with every co-signer key,
//    so a browser request would close the SHARED channel for everyone;
//  * a deposit target, unless the rollup is verified to finalize the producer's blocks: the first
//    Sepolia rollup could not, had no refund path, and locked every deposit for good.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-relay.js'), 'utf8');
const slice = (from, to) => source.slice(source.indexOf(from), source.indexOf(to, source.indexOf(from)));
const helpers = slice('let depositReadiness', 'fs.mkdirSync(WORK');
const ROUTES = {
  '/api/cosign-burn': slice("app.post('/api/cosign-burn'", '// POST /api/deploy-settlement'),
  '/api/deploy-settlement': slice("app.post('/api/deploy-settlement'", '\n});\n') + '\n});\n',
  '/api/close': slice("app.post('/api/close'", '// POST /api/settle'),
  '/api/settle': slice("app.post('/api/settle'", '// POST /api/withdraw'),
  '/api/withdraw': slice("app.post('/api/withdraw'", '// Retired:'),
};

function call(route, devnet) {
  const handlers = {}, touched = [];
  const ctx = {
    isDevnet: () => devnet, relayChainId: () => (devnet ? 31337 : 11155111),
    app: { post: (p, h) => { handlers[p] = h; } }, CHANNELS: [7], validityDeployment: {}, setTimeout,
    reqChannel: () => { touched.push('reqChannel'); return 7; },
    withLock: () => { touched.push('withLock'); return Promise.resolve(); },
    burnOperations: { run: () => { touched.push('burn'); } },
    sendRouteError() {}, console: { error() {} },
  };
  vm.createContext(ctx);
  vm.runInContext(helpers + ROUTES[route], ctx);
  let status = 200, body = null;
  handlers[route]({ body: {} }, { status(n) { status = n; return this; }, json(b) { body = b; } });
  return { status, body, touched };
}

for (const route of Object.keys(ROUTES)) {
  test(`${route} is refused on a public chain before any lock or signature`, () => {
    const r = call(route, false);
    assert.equal(r.status, 501);
    assert.equal(r.body.code, 'NOT_AVAILABLE');
    assert.deepEqual(r.touched, []);
  });
  test(`${route} still runs on the local devnet`, () => {
    const r = call(route, true);
    assert.ok(r.touched.includes('withLock'));
  });
}

// ── deposits: offered only into a rollup verified to finalize the producer's blocks ─────────────
const depositRoutes = slice('function deploymentOf(ch)', '// POST /api/l1-deposit');
const health = slice("app.get('/api/health'", '// GET /api/deployment');
const ROLLUP = '0x' + '3c'.repeat(20), RECIPIENT = '0x' + '07'.repeat(32);

function relay({ devnet = false, readiness } = {}) {
  const handlers = {}, touched = [], logged = [], retries = [];
  const ctx = {
    isDevnet: () => devnet, relayChainId: () => (devnet ? 31337 : 11155111), CHANNELS: [7, 8],
    app: { get: (p, h) => { handlers[p] = h; }, post() {} },
    reqChannel: () => { touched.push('reqChannel'); return 7; },
    wc: (_ch, name) => name, RPC: 'https://rpc.example', minConfirmationsForDisplay: () => 12,
    fs: { readFileSync: () => { touched.push('read'); return JSON.stringify({ rollup: ROLLUP, deposit_recipient: RECIPIENT }); } },
    validityDeployment: {
      servedRollup: () => ROLLUP,
      readiness: (rollup) => { touched.push('readiness:' + rollup); return readiness(); },
    },
    setTimeout: (fn, ms) => { retries.push(ms); return { unref() {} }; },
    console: { log: (m) => logged.push(m), error: (m) => logged.push(m) },
  };
  vm.createContext(ctx);
  vm.runInContext(helpers + health + depositRoutes, ctx);
  const get = (route) => {
    let status = 200, body = null;
    handlers[route]({ query: { channel: '7' } }, { status(n) { status = n; return this; }, json(b) { body = b; } });
    return { status, body };
  };
  return { ctx, get, touched, logged, retries };
}

test('before the startup check, a public-chain relay offers no deposit target and touches nothing', () => {
  const r = relay({ readiness: () => assert.fail('not checked yet') });
  const info = r.get('/api/deposit-info');
  assert.equal(info.status, 501);
  assert.equal(info.body.code, 'NOT_AVAILABLE');
  assert.equal(info.body.capability, 'deposit');
  assert.match(info.body.error, /still checking/);
  assert.deepEqual(r.touched, []);
  const h = r.get('/api/health').body;
  assert.equal(h.capabilities.deposit, false);
  assert.match(h.unavailable.deposit, /still checking/);
});

test('an unverified or mismatched rollup keeps deposits off, with the reason, and is not retried', () => {
  const reason = "rollup cannot finalize this producer's blocks";
  const r = relay({ readiness: () => ({ ok: false, reason }) });
  r.ctx.checkDepositReadiness();
  const info = r.get('/api/deposit-info');
  assert.equal(info.status, 501);
  assert.ok(info.body.error.includes(reason));
  assert.equal(r.get('/api/health').body.unavailable.deposit, reason);
  assert.deepEqual(r.retries, [], 'an operator must act; polling would not change the record');
  assert.ok(r.logged.some(m => /deposits disabled/.test(m)));
});

test('a transient chain-read failure keeps deposits off and re-checks a minute later', () => {
  const r = relay({ readiness: () => ({ ok: false, reason: 'could not read', transient: true }) });
  r.ctx.checkDepositReadiness();
  assert.equal(r.get('/api/deposit-info').status, 501);
  assert.deepEqual(r.retries, [60 * 1000]);
});

test('a verified rollup serves the deposit target', () => {
  const r = relay({ readiness: () => ({ ok: true, record: { rollup: ROLLUP } }) });
  r.ctx.checkDepositReadiness();
  const info = r.get('/api/deposit-info');
  assert.equal(info.status, 200);
  assert.deepEqual(JSON.parse(JSON.stringify(info.body)),
    { rollup: ROLLUP, rpc: 'https://rpc.example', chainId: 11155111, minConfirmations: 12, depositRecipient: RECIPIENT });
  const h = r.get('/api/health').body;
  assert.equal(h.capabilities.deposit, true);
  assert.deepEqual(JSON.parse(JSON.stringify(h.unavailable)), {});
});

test('the deployment (chain and rollup) is served whatever the deposit capability, without a deposit target', () => {
  const r = relay({ readiness: () => ({ ok: false, reason: 'unverified' }) });
  r.ctx.checkDepositReadiness();
  const d = r.get('/api/deployment');
  assert.equal(d.status, 200);
  assert.deepEqual(JSON.parse(JSON.stringify(d.body)), { rollup: ROLLUP, rpc: 'https://rpc.example', chainId: 11155111, minConfirmations: 12 });
});

test('the local devnet offers deposits without a validity deployment record', () => {
  const r = relay({ devnet: true, readiness: () => assert.fail('devnet is not checked') });
  assert.equal(r.get('/api/deposit-info').status, 200);
  assert.equal(r.get('/api/health').body.capabilities.deposit, true);
});
