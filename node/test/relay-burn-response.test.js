'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-relay.js'), 'utf8');
const start = source.indexOf("app.post('/api/cosign-burn'");
const end = source.indexOf('// POST /api/deploy-settlement', start);

test('relay burn returns exactly the signed state while durably retaining its recovery ticket', async () => {
  const state = { channelId: 7, digest: 'signed', balanceState: { stateVersion: 9 }, memberSignatures: [] };
  const events = [];
  let handler, ticket;
  const context = {
    app: { post(_url, fn) { handler = fn; } },
    reqChannel: () => 7,
    withLock: (_ch, fn) => Promise.resolve().then(fn),
    findActiveTicket: () => null,
    producer: {
      stableRequestId: () => 'burn:recovery-id',
      authoritativeBaseNonceEnv: async () => ({}),
      postInterChannel: async () => { events.push('post'); return { requestId: 'block' }; },
      liveSettleInterChannel: async () => { events.push('settle'); return { baseNonce: 1 }; },
    },
    wc: (_ch, file) => file,
    fs: { writeFileSync() {}, rmSync() {}, readFileSync: () => JSON.stringify(state) },
    cliWithPreparedExitKit: async () => events.push('sign'),
    acknowledgePreparedExitKit: () => events.push('acknowledge'),
    upsertTicket: (_ch, value) => { ticket = value; events.push('ticket'); return value; },
    sendRouteError: (_res, error) => { throw error; },
    console,
  };
  vm.createContext(context); vm.runInContext(source.slice(start, end), context);
  const response = await new Promise(resolve => handler({ body: {
    debitPayload: {}, transferDescriptor: {}, amount: '5000000000000000', recipient: 'recipient',
  } }, { json: resolve }));
  assert.deepEqual(JSON.parse(JSON.stringify(response)), state,
    'extra response fields break the exact WASM-finalized snapshot archive check');
  assert.equal(ticket.status, 'burn_done');
  assert.equal(ticket.params.amount, '5000000000000000');
  assert.deepEqual(events, ['sign', 'post', 'settle', 'acknowledge', 'ticket']);
});
