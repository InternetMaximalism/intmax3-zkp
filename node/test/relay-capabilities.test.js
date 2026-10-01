'use strict';
// On a public chain the relay must refuse, before taking any lock or signing anything:
//  * a burn (partial withdrawal Step 1): its L1 settlement is not wired for a public chain, and a
//    burn without settlement stranded a user's 0.005 ETH on the v3 testnet;
//  * close / settle / withdraw / settlement deploy: the relay signs them with every co-signer key,
//    so a browser request would close the SHARED channel for everyone.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-relay.js'), 'utf8');
const slice = (from, to) => source.slice(source.indexOf(from), source.indexOf(to, source.indexOf(from)));
const helpers = slice('const capabilities = () =>', 'fs.mkdirSync(WORK');
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
    app: { post: (p, h) => { handlers[p] = h; } },
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
