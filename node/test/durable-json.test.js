'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-durable-json-'));
process.env.INTMAX_WORK_DIR = root;
process.env.INTMAX_CHANNELS = '7';

const tickets = require('../../api/lib/tickets');
const { Store } = require('../common/store');

test.after(() => fs.rmSync(root, { recursive: true, force: true }));

test('ticket journal is atomic/private and only ENOENT means no tickets', () => {
  assert.deepEqual(tickets.readTickets(7), []);
  tickets.writeTickets(7, [{ id: 'pw1', type: 'partial_withdrawal', status: 'burn_pending' }]);
  const file = path.join(root, 'ch7', 'tickets.json');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(tickets.findActiveTicket(7, 'partial_withdrawal').id, 'pw1');

  fs.writeFileSync(file, '{torn', { mode: 0o600 });
  assert.throws(() => tickets.readTickets(7), /cannot read durable ticket journal/);
  assert.throws(() => tickets.findActiveTicket(7, 'partial_withdrawal'), /cannot read durable ticket journal/);
});

test('valid non-array ticket JSON fails closed', () => {
  const file = path.join(root, 'ch7', 'tickets.json');
  fs.writeFileSync(file, '{}', { mode: 0o600 });
  assert.throws(() => tickets.readTickets(7), /not a JSON array/);
});

test('corrupt node cursor/action store is not reset to an empty state', () => {
  const file = path.join(root, 'node-state.json');
  fs.writeFileSync(file, '{bad', { mode: 0o600 });
  assert.throws(() => new Store(file), /cannot read durable node store/);
});
