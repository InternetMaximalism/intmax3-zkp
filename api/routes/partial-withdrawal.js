const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/partial-withdrawal/burn (W8 phase 1)
// Same as burn/cosign but under partial-withdrawal namespace for workflow clarity.
router.post('/burn', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const active = findActiveTicket(ch, 'partial_withdrawal');
    if (active && active.status === 'burn_done') {
      res.status(409).json({ error: 'settle pending burn first', ticket: active });
      return;
    }
    const { debitPayload, transferDescriptor } = req.body || {};
    if (!debitPayload || !transferDescriptor) {
      res.status(400).json({ error: 'needs { debitPayload, transferDescriptor, amount, recipient }' });
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

// POST /api/v1/channel/:ch/partial-withdrawal/submit (A24)
router.post('/submit', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (ticket) {
      ticket.status = 'settle_pending';
      upsertTicket(ch, ticket);
    }
    if (!fs.existsSync(wc(ch, 'settlement.json'))) {
      cli(ch, ['deploy-settlement', RPC]);
    }
    const pwRecipient = (req.body && req.body.recipient) || (ticket && ticket.params.recipient) || '';
    const extra = pwRecipient ? { PW_RECIPIENT: pwRecipient } : {};
    cli(ch, ['pw-submit', RPC], extra);
    const auth = readJson(wc(ch, 'pw_auth.json'));
    res.json({ authDigest: auth.auth_digest });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/partial-withdrawal/finalize (A25)
router.post('/finalize', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    cli(ch, ['pw-finalize', RPC]);
    const auth = readJson(wc(ch, 'pw_auth.json'));
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (ticket) {
      ticket.status = 'settle_done';
      ticket.steps.settle = { completedAt: Date.now(), authDigest: auth.auth_digest };
      upsertTicket(ch, ticket);
    }
    res.json({ ok: true, authDigest: auth.auth_digest });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/partial-withdrawal/settle (W8 phase 2 — submit + finalize combined)
router.post('/settle', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (ticket) {
      ticket.status = 'settle_pending';
      upsertTicket(ch, ticket);
    }
    if (!fs.existsSync(wc(ch, 'settlement.json'))) {
      cli(ch, ['deploy-settlement', RPC]);
    }
    const pwRecipient = (req.body && req.body.recipient) || (ticket && ticket.params.recipient) || '';
    const extra = pwRecipient ? { PW_RECIPIENT: pwRecipient } : {};
    cli(ch, ['pw-submit', RPC], extra);
    cli(ch, ['pw-finalize', RPC]);
    const auth = readJson(wc(ch, 'pw_auth.json'));
    if (ticket) {
      ticket.status = 'settle_done';
      ticket.steps.settle = { completedAt: Date.now(), authDigest: auth.auth_digest };
      upsertTicket(ch, ticket);
    }
    res.json({ authDigest: auth.auth_digest });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/partial-withdrawal/cancel (A45)
// NOT YET ENABLED. Correction to the design doc: NO new prover is needed — the contract
// `cancelPartialWithdrawal(CancelCloseRequest, MleProof)` reuses the EXACT same
// `verifier.verifyCancelClose(...)` and `CancelCloseProver` proof as A30 cancelClose (only the
// on-chain pending digest it matches differs). The blocker is a SOUNDNESS question, not missing
// machinery: cmd_pw_submit builds the partial-withdrawal CloseIntent with close_freeze_nonce = 0,
// but the cancel circuit's era fence requires revived.close_freeze_nonce + 1 == intent.close_freeze_nonce,
// which is unsatisfiable at nonce 0. Enabling A45 requires verifying/resolving that era-fence
// interaction (its own threat model + independent review) before wiring the CLI cancel path —
// shipping it unverified would be unsound money-cancel code. Deferred deliberately.
router.post('/cancel', (req, res) => {
  res.status(501).json({
    error: 'cancel partial withdrawal not yet enabled',
    detail: 'CancelCloseProver + verifyCancelClose are reusable (no new prover), but the partial-withdrawal era-fence (close_freeze_nonce=0 vs revived+1==intent) must be resolved before the cancel path is sound (A45).',
  });
});

module.exports = router;
