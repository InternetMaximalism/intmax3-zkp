'use strict';
// Step 2 of a partial withdrawal is the single route /api/pw-finalize: on the devnet it settles the
// burn inside the request (prove, publish, pay); on a verified public rollup the relay settles it
// in the background and the route answers where it is. Nothing freezes the channel meanwhile.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-relay.js'), 'utf8');
const slice = (from, to) => {
  const start = source.indexOf(from), end = source.indexOf(to, start);
  assert.ok(start >= 0 && end > start, `relay source has ${from}`);
  return source.slice(start, end);
};
const sendRouteError = slice('function sendRouteError(', '\n}\n') + '\n}\n';
const route = slice("app.post('/api/pw-finalize'", '// The receiver pulls the credited amount');

function finalize({ devnet = true, verified = false, ticket = { id: 'pw_1', status: 'burn_done', params: { recipient: 'recipient' }, steps: {} },
  settleNow = async () => { throw new Error('must not settle'); } } = {}) {
  let handler, done;
  const started = [], settled = [];
  const completed = new Promise(r => { done = r; });
  const ctx = {
    requireCapability: (res, name, what) => {
      if (devnet || verified) return true;
      res.status(501).json({ code: 'NOT_AVAILABLE', capability: name, error: `${what} is not available` });
      return false;
    },
    isDevnet: () => devnet, app: { post: (url, h) => { assert.equal(url, '/api/pw-finalize'); handler = h; } },
    reqChannel: () => 7, findActiveTicket: (ch, type) => { assert.equal(type, 'partial_withdrawal'); return ticket; },
    pwSettlement: { start: ch => started.push(ch), settleNow: ch => { settled.push(ch); return settleNow(ch); } },
    fullCliError: e => [e.message, e.stderr].filter(Boolean).join('\n'), console: { error() {} },
  };
  vm.createContext(ctx); vm.runInContext(sendRouteError + route, ctx);
  let status = 200;
  handler({ body: {} }, { status(n) { status = n; return this; }, json(body) { done(body); } });
  return completed.then(body => ({ status, body: JSON.parse(JSON.stringify(body)), started, settled, ticket }));
}

test('the relay has no pw-submit route and no channel freeze', () => {
  assert.equal(source.includes("'/api/pw-submit'"), false);
  assert.doesNotMatch(source, /refuseIfSettling|SETTLING_WITHDRAWAL|pwSettlement\.frozen/);
});

test('on the devnet Step 2 settles in the request and answers the claim to receive', async () => {
  const claim = { to: '0xrollup', recipient: '0xr', amount: '5', tokenIndex: 0 };
  const r = await finalize({ settleNow: async () => ({ status: 'claim_pending', params: { claim } }) });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true, claim });
  assert.deepEqual(r.settled, [7]);
  assert.deepEqual(r.started, []);
});

test('on the devnet a payout to the operator itself answers no claim', async () => {
  const r = await finalize({ settleNow: async () => ({ status: 'settle_done', params: { claim: null } }) });
  assert.deepEqual(r.body, { ok: true, claim: null });
});

test('native process exit status 1 becomes HTTP 500 with its reason, without crashing the relay', async () => {
  const r = await finalize({ settleNow: async () => { throw Object.assign(new Error('exit status 1'), { status: 1, stderr: 'native proof failed' }); } });
  assert.equal(r.status, 500);
  assert.match(r.body.error, /native proof failed/);
  assert.equal(r.ticket.status, 'burn_done', 'the request does not touch the ticket; the driver records the failure');
});

test('a workflow conflict remains HTTP 409', async () => {
  const r = await finalize({ settleNow: async () => { throw Object.assign(new Error('finalization pending'), { status: 409 }); } });
  assert.equal(r.status, 409);
  assert.match(r.body.error, /finalization pending/);
});

test('shared relay error responder maps CLI exit codes to valid HTTP errors', () => {
  const context = { fullCliError: e => e.message, console: { error: () => {} } };
  vm.createContext(context); vm.runInContext(sendRouteError, context);
  for (const [status, expected] of [[1, 500], [409, 409], [0, 500], [999, 500]]) {
    let actual; const res = { status(n) { actual = n; return this; }, json(body) { assert.equal(body.error, 'failure'); } };
    context.sendRouteError(res, { status, message: 'failure' }); assert.equal(actual, expected);
  }
  let body;
  const res = { status() { return this; }, json(b) { body = b; } };
  context.sendRouteError(res, { status: 501, code: 'NOT_AVAILABLE', message: 'off' });
  assert.equal(body.code, 'NOT_AVAILABLE');
  context.sendRouteError(res, { status: 409, code: 'SETTLING_WITHDRAWAL', message: 'legacy' });
  assert.equal(body.code, undefined, 'no settling-freeze code is ever sent');
});

for (const devnet of [true, false]) {
  test(`a credited payout answers its claim at once (${devnet ? 'devnet' : 'public chain'})`, async () => {
    const claim = { to: '0xrollup', recipient: '0xr' };
    const r = await finalize({ devnet, verified: true, ticket: { id: 'pw_1', status: 'claim_pending', params: { claim }, steps: {} } });
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { ok: true, claim });
    assert.deepEqual(r.started, []); assert.deepEqual(r.settled, []);
  });
}

test('on an unverified public rollup partial withdrawal is refused up front with 501 and nothing is touched', async () => {
  const r = await finalize({ devnet: false });
  assert.equal(r.status, 501); assert.equal(r.body.code, 'NOT_AVAILABLE'); assert.equal(r.ticket.status, 'burn_done');
  assert.deepEqual(r.started, []); assert.deepEqual(r.settled, []);
});

test('on a verified public rollup the burn is settled in the background and the request answers 202', async () => {
  const r = await finalize({ devnet: false, verified: true });
  assert.equal(r.status, 202); assert.equal(r.body.settling, true); assert.equal(r.body.ticket.id, 'pw_1');
  assert.deepEqual(r.started, [7]); assert.deepEqual(r.settled, []);
  assert.equal(r.ticket.status, 'burn_done', 'the background driver, not the request, advances the ticket');
});

test('on a public rollup without a withdrawal Step 2 answers 404 and starts nothing', async () => {
  const r = await finalize({ devnet: false, verified: true, ticket: null });
  assert.equal(r.status, 404); assert.match(r.body.error, /no partial withdrawal/);
  assert.deepEqual(r.started, []);
});

// ── no freeze: the channel keeps advancing while its burn is settled on L1 ──────────────────────
const SETTLING = { id: 'pw_1', type: 'partial_withdrawal', status: 'settle_pending', params: {}, steps: { settle: { phase: 'proving' } } };

test('a cosign while a withdrawal is settling is batched and answered, not refused', async () => {
  const enqueued = [];
  let handler;
  const ctx = {
    app: { post: (_url, h) => { handler = h; } }, reqChannel: () => 7,
    findActiveTicket: () => SETTLING, pwSettlement: { start() {}, settleNow() {} },
    cosignBatcher: { enqueue: async (ch, body) => { enqueued.push([ch, body]); return { digest: 'next-head' }; } },
    fullCliError: e => e.message, kitPendingHint: () => null, console: { error() {} },
  };
  vm.createContext(ctx);
  vm.runInContext(slice("app.post('/api/cosign', (req, res) => {", '// Inter-channel transfers still pending'), ctx);
  let status = 200;
  const body = await new Promise(resolve => handler({ query: { channel: '7' }, body: { proposedNextState: {} } },
    { status(n) { status = n; return this; }, json: resolve }));
  assert.equal(status, 200);
  assert.deepEqual(JSON.parse(JSON.stringify(body)), { digest: 'next-head' });
  assert.equal(enqueued.length, 1);
});

test('the channel lock runs every operation while a withdrawal is settling, in any phase', async () => {
  const ctx = {
    burnOperations: { pending: () => false, run: async () => { throw new Error('no pending burn'); } },
    findActiveTicket: () => SETTLING, upsertTicket() {}, readTickets: () => [], readHistory: () => [],
    pwSettlement: { start() {}, settleNow() {} }, Promise,
  };
  vm.createContext(ctx);
  vm.runInContext(slice('const _chLocks = {};', '// ─── Cluster co-signing'), ctx);
  for (const phase of ['proving', 'publishing', 'paying']) {
    SETTLING.steps.settle.phase = phase;
    assert.equal(await ctx.withLock(7, () => 'ran ' + phase), 'ran ' + phase);
  }
  for (const status of ['burn_done', 'settle_pending']) {
    SETTLING.status = status;
    assert.equal(await ctx.withLock(7, () => 'ran'), 'ran', status);
  }
});
