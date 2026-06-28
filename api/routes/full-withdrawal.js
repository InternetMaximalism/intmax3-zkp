const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, rollupOf, readJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/full-withdrawal/start (W10 — returns ticket for tracking)
router.post('/start', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    let ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) {
      return res.json({ ticketId: ticket.id, ticket });
    }
    ticket = upsertTicket(ch, {
      id: 'fw_' + Date.now(),
      type: 'full_withdrawal',
      status: 'started',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      params: {},
      steps: { deploy: null, close: null, settle: null, withdraw: null, claim: null },
    });
    res.json({ ticketId: ticket.id, ticket });
  }).catch(e => {
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// GET /api/v1/channel/:ch/full-withdrawal/status (W10)
router.get('/status', (req, res) => {
  const ch = Number(req.params.ch);
  const ticket = findActiveTicket(ch, 'full_withdrawal');
  if (!ticket) {
    return res.status(404).json({ error: 'no active full withdrawal' });
  }
  res.json({ step: ticket.status, canProceed: true, ticket });
});

// POST /api/v1/channel/:ch/full-withdrawal/deploy (W10 step 1)
router.post('/deploy', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    if (fs.existsSync(wc(ch, 'settlement.json'))) {
      const s = readJson(wc(ch, 'settlement.json'));
      let ticket = findActiveTicket(ch, 'full_withdrawal');
      if (ticket) {
        ticket.status = 'deploy_done';
        ticket.params.manager = s.manager;
        ticket.params.verifier = s.verifier;
        ticket.steps.deploy = { completedAt: Date.now(), manager: s.manager, verifier: s.verifier };
        upsertTicket(ch, ticket);
      }
      return res.json({ manager: s.manager, verifier: s.verifier });
    }
    cli(ch, ['deploy-settlement', RPC]);
    const s = readJson(wc(ch, 'settlement.json'));
    let ticket = findActiveTicket(ch, 'full_withdrawal');
    if (!ticket) {
      ticket = {
        id: 'fw_' + Date.now(),
        type: 'full_withdrawal',
        status: 'deploy_done',
        createdAt: Date.now(),
        updatedAt: Date.now(),
        params: { manager: s.manager, verifier: s.verifier },
        steps: { deploy: { completedAt: Date.now(), manager: s.manager, verifier: s.verifier }, close: null, settle: null, withdraw: null, claim: null },
      };
    } else {
      ticket.status = 'deploy_done';
      ticket.params.manager = s.manager;
      ticket.params.verifier = s.verifier;
      ticket.steps.deploy = { completedAt: Date.now(), manager: s.manager, verifier: s.verifier };
    }
    upsertTicket(ch, ticket);
    res.json({ manager: s.manager, verifier: s.verifier });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/full-withdrawal/request (W10 step 2 — close request + submit intent)
router.post('/request', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    const manager = (req.body && req.body.manager) || (ticket && ticket.params.manager);
    const sv = (req.body && req.body.verifier) || (ticket && ticket.params.verifier) || '';
    if (!manager) {
      res.status(400).json({ error: 'needs { manager } or active ticket with manager' });
      return;
    }
    if (ticket) {
      ticket.status = 'close_pending';
      upsertTicket(ch, ticket);
    }
    const out = cli(ch, ['close', manager, RPC], { CLOSE_SV: sv });
    if (ticket) {
      ticket.status = 'close_done';
      ticket.steps.close = { completedAt: Date.now() };
      upsertTicket(ch, ticket);
    }
    res.json({ ok: true, log: out });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/full-withdrawal/submit (W10 step 3 — withdraw pipeline)
router.post('/submit', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    const manager = (req.body && req.body.manager) || (ticket && ticket.params.manager);
    if (!manager) {
      res.status(400).json({ error: 'needs { manager }' });
      return;
    }
    if (ticket) {
      ticket.status = 'withdraw_pending';
      upsertTicket(ch, ticket);
    }
    const out = cli(ch, ['withdraw', manager, RPC], { ROLLUP: rollupOf(ch) });
    if (ticket) {
      ticket.status = 'withdraw_done';
      ticket.steps.withdraw = { completedAt: Date.now() };
      upsertTicket(ch, ticket);
    }
    res.json({ ok: true, log: out });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/full-withdrawal/finalize (W10 step 4 — settle)
router.post('/finalize', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    const manager = (req.body && req.body.manager) || (ticket && ticket.params.manager);
    if (!manager) {
      res.status(400).json({ error: 'needs { manager }' });
      return;
    }
    if (ticket) {
      ticket.status = 'settle_pending';
      upsertTicket(ch, ticket);
    }
    const out = cli(ch, ['settle', manager, RPC]);
    if (ticket) {
      ticket.status = 'settle_done';
      ticket.steps.settle = { completedAt: Date.now() };
      upsertTicket(ch, ticket);
    }
    res.json({ ok: true, log: out });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/full-withdrawal/claim (W10 step 5)
router.post('/claim', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    const { manager, slot, recipient } = req.body || {};
    const mgr = manager || (ticket && ticket.params.manager);
    if (!mgr || slot === undefined || !recipient) {
      res.status(400).json({ error: 'needs { manager, slot, recipient }' });
      return;
    }
    if (ticket) {
      ticket.status = 'claim_pending';
      upsertTicket(ch, ticket);
    }
    const out = cli(ch, ['claim', mgr, String(slot), RPC], { CLAIM_RECIPIENT: recipient });
    if (ticket) {
      ticket.status = 'claim_done';
      ticket.steps.claim = { completedAt: Date.now() };
      upsertTicket(ch, ticket);
    }
    res.json({ ok: true, log: out });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
