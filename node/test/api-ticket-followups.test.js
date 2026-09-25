'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

function loadRoute(name, journal) {
  const handlers = new Map();
  const router = { get() {}, post(path, fn) { handlers.set(path, fn); } };
  const original = Module._load;
  Module._load = function(request, parent, isMain) {
    if (request === 'express') return { Router: () => router };
    if (request === '../lib/tickets') return {
      readTickets: () => journal,
      findActiveTicket: () => journal.find(t => t.status !== 'import_done'),
      upsertTicket: (_ch, ticket) => {
        const index = journal.findIndex(t => t.id === ticket.id);
        if (index < 0) journal.push(ticket); else journal[index] = ticket;
        return ticket;
      },
    };
    if (request === '../lib/lock') return { withLock: (_ch, fn) => Promise.resolve().then(fn) };
    if (request === '../lib/cli') return { wc: () => 'unused', readJson: () => ({ imported: true }) };
    if (request === '../lib/deposit-pipeline') return { importL1Deposit: async () => {} };
    if (request === '../lib/deposit-preflight') return { recipientSlot: n => n };
    if (request === '../lib/deposit-spend') return {
      readOptional: () => null,
      failDeposit: (_res, error) => { throw error; },
    };
    return original.call(this, request, parent, isMain);
  };
  try {
    const path = require.resolve(`../../api/routes/${name}`);
    delete require.cache[path];
    require(path);
    delete require.cache[path];
  } finally { Module._load = original; }
  return (path, body) => new Promise(resolve => {
    const res = { statusCode: 200, status(n) { this.statusCode = n; return this; },
      json(value) { resolve({ status: this.statusCode, value }); } };
    handlers.get(path)({ params: { ch: '7' }, body }, res);
  });
}

const hash = digit => `0x${digit.repeat(64)}`;
test('completed deposit and new deposit in one millisecond retain distinct tickets', async () => {
  const journal = [];
  const request = loadRoute('tickets', journal);
  const originalNow = Date.now;
  Date.now = () => 123456;
  try {
    const first = await request('/', { type: 'deposit', amount: '1', depositor: 'alice', txHash: hash('a') });
    assert.equal(first.status, 200);
    first.value.status = 'import_done';
    const second = await request('/', { type: 'deposit', amount: '2', depositor: 'alice', txHash: hash('b') });
    assert.equal(second.status, 200);
    assert.notEqual(first.value.id, second.value.id);
    assert.equal(journal.length, 2);
    assert.equal(journal[0].params.txHash, hash('a'));
  } finally { Date.now = originalNow; }
});

test('import only completes the ticket for its transaction, with case-insensitive hash matching', async () => {
  const journal = [{ id: 'dep_existing', type: 'deposit', status: 'l1_done',
    params: { txHash: hash('A') }, steps: { import: null } }];
  const request = loadRoute('deposit', journal);
  assert.equal((await request('/import', { recipientSlot: 0, txHash: hash('b') })).status, 200);
  assert.equal(journal[0].status, 'l1_done');
  assert.equal(journal[0].steps.import, null);
  assert.equal((await request('/import', { recipientSlot: 0, txHash: hash('a') })).status, 200);
  assert.equal(journal[0].status, 'import_done');
  assert.ok(journal[0].steps.import.completedAt);
});
