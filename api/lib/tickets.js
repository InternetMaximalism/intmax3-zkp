const fs = require('fs');
const { wc } = require('./cli');

const TICKET_FILE = 'tickets.json';
const TICKET_TTL = 3600_000;
const TERMINAL = {
  partial_withdrawal: 'settle_done',
  deposit: 'import_done',
  full_withdrawal: 'claim_done',
};

function readTickets(ch) {
  try {
    return JSON.parse(fs.readFileSync(wc(ch, TICKET_FILE), 'utf8'));
  } catch (e) {
    return [];
  }
}

function writeTickets(ch, tickets) {
  fs.writeFileSync(wc(ch, TICKET_FILE), JSON.stringify(tickets, null, 2));
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
