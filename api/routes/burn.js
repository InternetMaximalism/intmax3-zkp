const { Router } = require('express');
const { cli, wc, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/burn/cosign (A22)
router.post('/cosign', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const active = findActiveTicket(ch, 'partial_withdrawal');
    if (active && active.status === 'burn_done') {
      res.status(409).json({ error: 'settle pending burn first', ticket: active });
      return;
    }
    const { debitPayload, transferDescriptor } = req.body || {};
    if (!debitPayload || !transferDescriptor) {
      res.status(400).json({ error: 'needs { debitPayload, transferDescriptor }' });
      return;
    }
    writeJson(wc(ch, 'burn_payload.json'), debitPayload);
    writeJson(wc(ch, 'burn_descriptor.json'), transferDescriptor);
    cli(ch, ['cosign-burn-send', 'burn_payload.json', 'burn_descriptor.json', 'burn_cosigned.json']);
    const ticket = upsertTicket(ch, {
      id: 'pw_' + Date.now(),
      type: 'partial_withdrawal',
      status: 'burn_done',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      params: { amount: String(req.body.amount || ''), recipient: req.body.recipient || '' },
      steps: { burn: { completedAt: Date.now() }, settle: null },
    });
    const cosigned = readJson(wc(ch, 'burn_cosigned.json'));
    res.json({ state: cosigned, ticket });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
