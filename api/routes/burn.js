const { Router } = require('express');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket, readTickets } = require('../lib/tickets');

const burnOperations = require('../lib/burn-operation').createBurnOperations();

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/burn/cosign (A22)
router.post('/cosign', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    const state = await burnOperations.run(ch, req.body || {}, {
      findActiveTicket, upsertTicket,
      getTicket: (channel, id) => readTickets(channel).find(ticket => ticket.id === id),
    });
    const operation = burnOperations.result(ch, req.body || {});
    const ticket = readTickets(ch).find(ticket => ticket.params?.producerRequestId === operation.id);
    const receipts = operation;
    res.json({ state, ticket, blockReceipt: receipts.blockReceipt, liveReceipt: receipts.liveReceipt });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(Number.isInteger(e && e.status) ? e.status : 500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
