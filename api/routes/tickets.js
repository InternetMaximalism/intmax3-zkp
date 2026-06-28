const { Router } = require('express');
const { readTickets, upsertTicket } = require('../lib/tickets');

const router = Router({ mergeParams: true });

// GET /api/v1/channel/:ch/tickets (A41)
router.get('/', (req, res) => {
  const ch = Number(req.params.ch);
  res.json(readTickets(ch));
});

// POST /api/v1/channel/:ch/tickets — create a ticket manually
router.post('/', (req, res) => {
  const ch = Number(req.params.ch);
  const { type, amount, depositor, txHash, recipientSlot } = req.body || {};
  if (!type) {
    return res.status(400).json({ error: 'needs { type, ... }' });
  }
  if (type === 'deposit') {
    if (!amount || !depositor || !txHash) {
      return res.status(400).json({ error: 'deposit ticket needs { type, amount, depositor, txHash, recipientSlot }' });
    }
    const { findActiveTicket } = require('../lib/tickets');
    const existing = findActiveTicket(ch, 'deposit');
    if (existing) {
      return res.status(409).json({ error: 'deposit already pending', ticket: existing });
    }
    const ticket = upsertTicket(ch, {
      id: 'dep_' + Date.now(),
      type: 'deposit',
      status: 'l1_done',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      params: { amount: String(amount), depositor, recipientSlot: recipientSlot || 0, txHash },
      steps: { l1: { completedAt: Date.now(), txHash }, import: null },
    });
    return res.json(ticket);
  }
  res.status(400).json({ error: 'unsupported ticket type: ' + type });
});

module.exports = router;
