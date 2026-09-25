'use strict';
const { Router } = require('express');
const { wc, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');
const { importL1Deposit } = require('../lib/deposit-pipeline');
const { recipientSlot } = require('../lib/deposit-preflight');
const { spendDeposit, importTrackedDeposit, readOptional, depositResponse, failDeposit } = require('../lib/deposit-spend');

const router = Router({ mergeParams: true });

// Every operator-funded spend reserves admissible credit, then fsyncs the exact signed L1
// transaction before broadcast. A new identical payment MUST provide a new requestId; an
// ambiguous retry keeps the old id. No retry automatically authorizes another payment.
router.post('/l1-send', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    const operation = await spendDeposit(ch, req.body || {});
    res.json(depositResponse(operation));
  }).catch(error => failDeposit(res, error));
});

// Receipt facts remain authoritative. Legacy/external imports cannot create a new L1 payment.
router.post('/import', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    const body = req.body || {};
    if (body.depositor !== undefined || body.amount !== undefined || body.tokenIndex !== undefined) {
      return res.status(400).json({ error: 'Send { recipientSlot, txHash }; depositor/amount/tokenIndex come from the verified on-chain Deposited log.' });
    }
    const pendingPath = wc(ch, 'pending_deposit.json');
    const pending = readOptional(pendingPath);
    const txHash = body.txHash ?? (pending && pending.txHash);
    if (!/^0x[0-9a-fA-F]{64}$/.test(String(txHash || ''))) {
      return res.status(400).json({ error: 'needs a txHash (0x + 64 hex); retry the same deposit request if broadcast is unresolved' });
    }
    const matchesPending = pending && String(pending.txHash).toLowerCase() === txHash.toLowerCase();
    if (matchesPending && pending.actionId) {
      await importTrackedDeposit(ch, pending, body.recipientSlot);
    } else {
      const slot = recipientSlot(body.recipientSlot ?? 0);
      // Native import refuses a depositor bound to another participant even with this flag.
      await importL1Deposit(ch, slot, txHash, { allowUnboundDepositor: true });
      if (matchesPending) writeJson(pendingPath, { ...pending, status: 'imported' });
    }
    const ticket = findActiveTicket(ch, 'deposit');
    if (ticket && String(ticket.params?.txHash).toLowerCase() === txHash.toLowerCase()) {
      ticket.status = 'import_done';
      ticket.steps.import = { completedAt: Date.now() };
      upsertTicket(ch, ticket);
    }
    res.json(readJson(wc(ch, 'channel_snapshot.json')));
  }).catch(error => failDeposit(res, error));
});

router.post('/', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    const body = req.body || {};
    if (body.depositor !== undefined) {
      return res.status(400).json({ error: 'depositor is read from the operator-funded transaction, not request input' });
    }
    const operation = await spendDeposit(ch, { ...body, recipientSlot: body.recipientSlot ?? 0 });
    const completed = await importTrackedDeposit(ch, operation, body.recipientSlot);
    const pipeline = completed.pipeline || {};
    res.json({ snapshot: readJson(wc(ch, 'channel_snapshot.json')), balance: operation.amount,
      ...depositResponse(completed.operation),
      producerReceipt: pipeline.producerReceipt, liveReceipt: pipeline.liveReceipt,
      liveStatus: pipeline.liveStatus, headSyncReceipt: pipeline.headSyncReceipt });
  }).catch(error => failDeposit(res, error));
});

module.exports = router;
