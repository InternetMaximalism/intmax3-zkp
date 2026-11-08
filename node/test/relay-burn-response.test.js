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
