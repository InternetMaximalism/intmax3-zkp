const { Router } = require('express');
const { cli, RPC, failRoute } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket, readTickets } = require('../lib/tickets');

const burnOperations = require('../lib/burn-operation').createBurnOperations();

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/partial-withdrawal/burn (W8 phase 1)
// Same as burn/cosign but under partial-withdrawal namespace for workflow clarity.
router.post('/burn', (req, res) => {
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

// A partial withdrawal is paid on L1 by its base withdrawal proof alone, as an inter-channel
// transfer is consumed by a receive proof: there is no settlement-manager submission, challenge or
// cancellation. Settling it = prove the payout (anchored at the head a validity batch ends at),
// publish that batch, pay.
async function settle(ch) {
  const live = require('../lib/partial-withdrawal-live');
  const walletL1 = require('../lib/wallet-l1');
  let artifacts;
  try { artifacts = await live.stagePayoutArtifacts(ch); }
  catch (e) {
    if (!/validity candidate pending L1 acknowledgement/.test(String(e.stderr || e.message || e))) throw e;
    await walletL1.publish(ch, { prove: false });
    artifacts = await live.stagePayoutArtifacts(ch);
  }
  await walletL1.publish(ch, { prove: false });
  cli(ch, ['pw-finalize', RPC]);
  const ticket = findActiveTicket(ch, 'partial_withdrawal');
  if (ticket) {
    ticket.status = 'settle_done';
    ticket.steps.settle = { completedAt: Date.now(), nullifier: artifacts.withdrawal.nullifier };
    upsertTicket(ch, ticket);
  }
  return { nullifier: artifacts.withdrawal.nullifier, paidOut: true };
}

// POST /api/v1/channel/:ch/partial-withdrawal/settle (W8 phase 2); /finalize is its alias.
for (const route of ['/settle', '/finalize']) {
  router.post(route, (req, res) => {
    const ch = Number(req.params.ch);
    withLock(ch, async () => res.json(await settle(ch))).catch(e => failRoute(res, e));
  });
}

// The settlement-manager submission and its cancellation no longer exist.
for (const route of ['/submit', '/cancel']) {
  router.post(route, (req, res) => res.status(410).json({
    error: 'a partial withdrawal is paid by its withdrawal proof alone; use /settle',
  }));
}

module.exports = router;
