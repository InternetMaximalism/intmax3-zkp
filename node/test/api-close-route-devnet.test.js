'use strict';
// Signer-independent exit, Round 2 §6: `api/routes/close.js` forwards a caller-supplied
// `manager` to the CLI argv under one shared bearer token. Public-chain close/finalize/claim run
// through the delegate's native publisher against its pinned deployment manifest, so this legacy
// router must be devnet-only (like the legacy routes in `full-withdrawal.js`) and must validate
// the address shape before it reaches argv.
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');

const MANAGER = '0x2222222222222222222222222222222222222222';
const RECIPIENT = '0x3333333333333333333333333333333333333333';

function loadRouter(chainId) {
  const handlers = new Map();
  const cliCalls = [];
  const original = Module._load;
  Module._load = function patched(request, parent, ...rest) {
    if (request === 'express') {
      return { Router: () => ({ post(route, handler) { handlers.set(route, handler); } }) };
    }
    if (request === '../lib/cli') {
      return {
        cli(ch, argv, env) { cliCalls.push({ ch, argv, env }); return 'ok'; },
        wc() {}, RPC: 'http://rpc.invalid', rollupOf() {}, readJson() {},
        chainId() { return chainId; },
        DEVNET_CHAIN_ID: 31337,
      };
    }
    if (request === '../lib/lock') return { withLock: (_ch, fn) => Promise.resolve().then(fn) };
    if (request === '../lib/tickets') return { findActiveTicket() { return null; }, upsertTicket() {} };
    return original.call(this, request, parent, ...rest);
  };
  const routerPath = require.resolve('../../api/routes/close.js');
  delete require.cache[routerPath];
  try { require(routerPath); } finally { Module._load = original; delete require.cache[routerPath]; }
  return {
    async invoke(route, body) {
      const handler = handlers.get(route);
      assert.ok(handler, `route ${route} registered`);
      const res = {
        statusCode: 200,
        body: null,
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; return this; },
      };
      handler({ params: { ch: '7' }, body }, res);
      for (let i = 0; i < 4; i += 1) await new Promise((resolve) => setImmediate(resolve));
      return res;
    },
    cliCalls,
    routes: [...handlers.keys()],
  };
}

const BODIES = [
  ['/request', { manager: MANAGER }],
  ['/submit-intent', { manager: MANAGER }],
  ['/challenge', { manager: MANAGER }],
  ['/cancel', { manager: MANAGER }],
  ['/finalize', { manager: MANAGER }],
  ['/claim', { manager: MANAGER, slot: 0, recipient: RECIPIENT }],
  ['/pull-credit', { manager: MANAGER, recipient: RECIPIENT }],
  ['/post-close-claim', { manager: MANAGER, slot: 0, recipient: RECIPIENT, incomingTxIndex: 0 }],
];

test('every legacy close route is disabled on public chains before any CLI call', async () => {
  const production = loadRouter(1);
  assert.equal(production.routes.length, BODIES.length, 'every registered route is covered');
  for (const [route, body] of BODIES) {
    const response = await production.invoke(route, body);
    assert.equal(response.statusCode, 409, route);
    assert.match(response.body.error, /disabled on public chains/, route);
  }
  assert.equal(production.cliCalls.length, 0);
});

test('on devnet a malformed manager never reaches argv and a well-formed one does', async () => {
  const devnet = loadRouter(31337);
  for (const bad of [undefined, 42, 'manager', '0x1234', `0x${'zz'.repeat(20)}`, `${MANAGER}00`]) {
    const response = await devnet.invoke('/request', { manager: bad });
    assert.equal(response.statusCode, 400, String(bad));
  }
  assert.equal(devnet.cliCalls.length, 0);
  const ok = await devnet.invoke('/request', { manager: MANAGER, advanceTime: 5 });
  assert.equal(ok.statusCode, 200);
  assert.deepEqual(devnet.cliCalls[0].argv, ['close', MANAGER, 'http://rpc.invalid']);
  assert.equal(devnet.cliCalls[0].env.CLOSE_REQUEST_ONLY, '1');
  const claim = await devnet.invoke('/claim', { manager: MANAGER, slot: 1, recipient: RECIPIENT, tokenSlot: 2 });
  assert.equal(claim.statusCode, 200);
  assert.deepEqual(devnet.cliCalls[1].argv, ['claim', MANAGER, '1', 'http://rpc.invalid', '2']);
});
