'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-relay.js'), 'utf8');
const start = source.indexOf("app.post('/api/cosign-burn'");
const end = source.indexOf('// POST /api/deploy-settlement', start);
// The relay's own helper: a delegate is answered with the head's acknowledgement, never the state.
const helper = name => { const i = source.indexOf('function ' + name + '('); return source.slice(i, source.indexOf('\n}\n', i) + 3); };

test('relay burn answers the signed head acknowledgement while durably retaining its recovery ticket', async () => {
  const state = { channelId: 7, digest: 'signed', balanceState: { stateVersion: 9 }, memberSignatures: [] };
  const events = [];
  let handler, ticket;
  const context = {
    app: { post(_url, fn) { handler = fn; } },
    // The devnet path: the public-chain refusal is covered by relay-capabilities.test.js.
    requireCapability: () => true,
    reqChannel: () => 7,
    withLock: (_ch, fn) => Promise.resolve().then(fn),
    findActiveTicket: () => null,
    burnOperations: {run: async (ch, input, store) => {
      events.push('run');store.upsertTicket(ch,{status:'burn_done',params:{amount:input.amount}});return state;
    }},
    readTickets: () => [], readHistory: () => [],
    pwSettlement: { start: () => events.push('settle') }, isDevnet: () => true,
    upsertTicket: (_ch, value) => {ticket=value;return value;},
    sendRouteError: (_res, error) => { throw error; },
    fullDebitPayload: (_ch, payload) => payload,
    console,
  };
  vm.createContext(context); vm.runInContext(helper('headAck') + source.slice(start, end), context);
  const response = await new Promise(resolve => handler({ body: {
    debitPayload: {}, transferDescriptor: {}, amount: '5000000000000000', recipient: 'recipient',
  } }, { json: resolve }));
  assert.deepEqual(JSON.parse(JSON.stringify(response)), { stateVersion: 9, digest: 'signed' },
    'a delegate learns only the head it must fetch its own slot view of');
  assert.equal(ticket.status, 'burn_done');
  assert.equal(ticket.params.amount, '5000000000000000');
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(events, ['run', 'settle'], 'a public-chain burn starts its L1 settlement');
});

// C25/G16: a burn on a head whose block is not finalized yet is a wait, not a failure. Like
// /api/cosign, the relay answers 409 with backingPending and publishes the pending candidate
// (rh1123, 2026-11-23: answering 500 left the channel waiting on a publish nothing retried).
test('relay burn on an unfinalized head answers 409 and publishes the pending candidate', async () => {
  let handler; const published = [];
  const refusal = Object.assign(new Error('Command failed: channel_member cosign-burn-send'), {
    stderr: "error: HEAD BACKING NOT FINALIZED: refusing BurnDebit because channel 7's durable head ... has not finalized yet" });
  const context = {
    app: { post(_url, fn) { handler = fn; } },
    requireCapability: () => true, reqChannel: () => 7,
    withLock: (_ch, fn) => Promise.resolve().then(fn),
    findActiveTicket: () => null,
    burnOperations: { run: async () => { throw refusal; } },
    readTickets: () => [], readHistory: () => [],
    pwSettlement: { start: () => { throw new Error('a refused burn must not start settlement'); } }, isDevnet: () => true,
    upsertTicket: () => { throw new Error('a refused burn writes no ticket'); },
    sendRouteError: () => { throw new Error('a backing refusal is not a route error'); },
    fullCliError: e => [e.message, e.stderr].filter(Boolean).join('\n'),
    backingPendingHint: ch => { published.push(ch); return { kitPending: true, backingPending: true, hint: 'retry shortly' }; },
    fullDebitPayload: (_ch, payload) => payload,
    console: { error() {}, log() {} },
  };
  vm.createContext(context); vm.runInContext(helper('headAck') + helper('sendSigningError') + source.slice(start, end), context);
  const reply = await new Promise(resolve => handler({ body: { debitPayload: {}, transferDescriptor: {} } },
    { status(code) { return { json: body => resolve({ code, body }) }; }, json: body => resolve({ code: 200, body }) }));
  assert.equal(reply.code, 409);
  assert.equal(reply.body.backingPending, true);
  assert.match(reply.body.error, /HEAD BACKING NOT FINALIZED/);
  assert.deepEqual(published, [7], 'the refusal itself starts the publication nothing else would retry');
});

// A slim debit built on a head the channel has since left (a second burn sent after the first
// one moved the head, rh1123 2026-11-23) is a stale anchor the wallet must rebuild from: 409 via
// staleAnchor, as for /api/cosign, and nothing is cached for it.
test('a slim debit on a superseded head is a stale anchor, not a relay failure', () => {
  const os = require('node:os');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-slim-'));
  try {
    const context = {
      fs, path, require, JSON,
      wc: (_ch, name) => path.join(dir, name),
      cli: () => { throw Object.assign(new Error('Command failed: channel_member inflate-debit'), {
        stderr: 'error: slim inter-channel debit: stale inter-channel debit: the anchor is not the channel head' }); },
      fullCliError: e => [e.message, e.stderr].filter(Boolean).join('\n'),
    };
    vm.createContext(context); vm.runInContext(helper('fullDebitPayload'), context);
    let thrown;
    try { context.fullDebitPayload(7, { anchorDigest: '0xold', proposedDigest: '0xnext' }); } catch (e) { thrown = e; }
    assert.ok(thrown && thrown.staleAnchor, 'the route answers 409 (sendRouteError maps staleAnchor)');
    assert.deepEqual(fs.readdirSync(path.join(dir, 'slim_debits')).filter(n => !n.endsWith('.slim.json')), [],
      'no inflated payload is cached for a stale debit');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// The inter-channel send route answers a backing refusal the same way (rh1123 UI run, 2026-11-23:
// a send right after a deposit import answered 500 and the wallet gave up instead of waiting).
test('relay inter-channel send on an unfinalized head answers 409 and publishes the pending candidate', async () => {
  const s = source.indexOf("app.post('/api/inter/send'"), e = source.indexOf('// ─── A-3 close lifecycle', s);
  let handler; const published = [];
  const refusal = Object.assign(new Error('Command failed: channel_member cosign-inter-transfer'), {
    stderr: "error: HEAD BACKING NOT FINALIZED: refusing InterChannelDebit because channel 7's durable head ... has not finalized yet" });
  const context = {
    app: { post(_url, fn) { handler = fn; } }, CHANNELS: [7, 8], reqChannel: () => 7,
    fullDebitPayload: (_ch, payload) => payload,
    interChannelSend: async () => { throw refusal; },
    resumePendingInterTransferLocked: async () => null,
    withInterLocks: (_a, _b, fn) => Promise.resolve().then(fn),
    delegateInterBody: body => body,
    sendRouteError: () => { throw new Error('a backing refusal is not a route error'); },
    fullCliError: e => [e.message, e.stderr].filter(Boolean).join('\n'),
    backingPendingHint: ch => { published.push(ch); return { kitPending: true, backingPending: true, hint: 'retry shortly' }; },
    console: { error() {}, log() {} },
  };
  vm.createContext(context); vm.runInContext(helper('sendSigningError') + source.slice(s, e), context);
  const reply = await new Promise(resolve => handler({ body: { debitPayload: {}, transferDescriptor: { destinationChannelId: 8 } } },
    { status(code) { return { json: body => resolve({ code, body }) }; } }));
  assert.equal(reply.code, 409);
  assert.equal(reply.body.backingPending, true);
  assert.deepEqual(published, [7]);
});
