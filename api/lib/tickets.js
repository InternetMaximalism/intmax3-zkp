const fs = require('fs');
const { wc, writeJson } = require('./cli');

const TICKET_FILE = 'tickets.json';
const TICKET_TTL = 3600_000;
const TERMINAL = {
  partial_withdrawal: 'settle_done',
  deposit: 'import_done',
  full_withdrawal: 'claim_done',
};

function readTickets(ch) {
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(wc(ch, TICKET_FILE), 'utf8'));
  } catch (e) {
    if (e && e.code === 'ENOENT') return [];
    // A malformed or unreadable journal may contain an active burn/settlement exclusion lock.
    // Treating it as empty authorizes conflicting work, so startup/request handling must fail shut.
    throw new Error(`cannot read durable ticket journal for channel ${ch}: ${e.message}`, { cause: e });
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`durable ticket journal for channel ${ch} is not a JSON array`);
  }
  return parsed;
}

function writeTickets(ch, tickets) {
  if (!Array.isArray(tickets)) throw new TypeError('tickets must be an array');
  writeJson(wc(ch, TICKET_FILE), tickets);
}

function findActiveTicket(ch, type) {
  return readTickets(ch).find(t => t.type === type && t.status !== TERMINAL[type]);
}

function upsertTicket(ch, ticket) {
  const tickets = readTickets(ch);
  const idx = tickets.findIndex(t => t.id === ticket.id);
  ticket.updatedAt = Date.now();
  if (idx >= 0) tickets[idx] = ticket;
  else tickets.push(ticket);
  const now = Date.now();
  const kept = tickets.filter(t =>
    !Object.values(TERMINAL).includes(t.status) || (now - t.updatedAt) < TICKET_TTL
  );
  writeTickets(ch, kept);
  return ticket;
}

module.exports = { TERMINAL, readTickets, writeTickets, findActiveTicket, upsertTicket };
