const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, readJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/settlement/deploy (A27)
router.post('/deploy', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    if (fs.existsSync(wc(ch, 'settlement.json'))) {
      return res.json(readJson(wc(ch, 'settlement.json')));
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
        steps: {
          deploy: { completedAt: Date.now(), manager: s.manager, verifier: s.verifier },
          close: null, settle: null, withdraw: null, claim: null,
        },
      };
    } else {
      ticket.status = 'deploy_done';
      ticket.params.manager = s.manager;
      ticket.params.verifier = s.verifier;
      ticket.steps.deploy = { completedAt: Date.now(), manager: s.manager, verifier: s.verifier };
    }
    upsertTicket(ch, ticket);
    res.json(s);
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// GET /api/v1/channel/:ch/settlement
router.get('/', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    res.json(readJson(wc(ch, 'settlement.json')));
  } catch (e) {
    res.status(404).json({ error: 'no settlement deployed yet' });
  }
});

module.exports = router;
