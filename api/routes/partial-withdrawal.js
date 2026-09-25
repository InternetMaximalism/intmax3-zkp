const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, readJson, writeJson, ensureSettlement, failRoute } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket, readTickets, writeTickets } = require('../lib/tickets');
const producer = require('../lib/block-producer');

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

// POST /api/v1/channel/:ch/partial-withdrawal/submit (A24)
router.post('/submit', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    const submitted = require('../lib/partial-withdrawal-live').resumeSubmittedAuth(ch);
    if (submitted) return res.json({ authDigest: submitted.auth_digest });
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    const before = ticket && ticket.status;
    if (ticket) {
      ticket.status = 'settle_pending';
      upsertTicket(ch, ticket);
    }
    // anvil: deploys the devnet stack on demand, as before. Real chain: a structured 409 naming
    // the operator task, because the real-VK deployer brings its own rollup and so must run
    // BEFORE the channel is funded (lib/cli.ensureSettlement).
    try {
      ensureSettlement(ch);
      const pwRecipient = (req.body && req.body.recipient) || (ticket && ticket.params.recipient) || '';
      const extra = pwRecipient ? { PW_RECIPIENT: pwRecipient } : {};
      const proofEnv = await require('../lib/partial-withdrawal-live').stageSubmitProof(ch);
      cli(ch, ['pw-submit', RPC], { ...extra, ...proofEnv });
    } catch (e) {
      if (ticket) { ticket.status = before; upsertTicket(ch, ticket); }
      throw e;
    }
    const auth = readJson(wc(ch, 'pw_auth.json'));
    res.json({ authDigest: auth.auth_digest });
  }).catch(e => failRoute(res, e));
});

// Prove + wrap the burn's payout artifacts in the resident daemon and stage them in the channel
// workdir for the CLI payout driver. The daemon proves against ITS journaled live base history;
// the route only ferries the result. The withdrawal prover address is the operator's L1 signer
// (any address is sound — it is committed into the proof's public inputs).
async function stagePayoutArtifacts(ch) {
  return require('../lib/partial-withdrawal-live').stagePayoutArtifacts(ch);
}

// POST /api/v1/channel/:ch/partial-withdrawal/finalize (A25)
router.post('/finalize', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    await stagePayoutArtifacts(ch);
    cli(ch, ['pw-finalize', RPC]);
    const auth = readJson(wc(ch, 'pw_auth.json'));
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (ticket) {
      ticket.status = 'settle_done';
      ticket.steps.settle = { completedAt: Date.now(), authDigest: auth.auth_digest };
      upsertTicket(ch, ticket);
    }
    res.json({ ok: true, authDigest: auth.auth_digest, paidOut: true });
  }).catch(e => failRoute(res, e));
});

// POST /api/v1/channel/:ch/partial-withdrawal/settle (W8 phase 2 — submit + finalize combined)
router.post('/settle', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (ticket) {
      ticket.status = 'settle_pending';
      upsertTicket(ch, ticket);
    }
    ensureSettlement(ch);
    const pwRecipient = (req.body && req.body.recipient) || (ticket && ticket.params.recipient) || '';
    const extra = pwRecipient ? { PW_RECIPIENT: pwRecipient } : {};
    if (!require('../lib/partial-withdrawal-live').resumeSubmittedAuth(ch)) {
      const proofEnv = await require('../lib/partial-withdrawal-live').stageSubmitProof(ch);
      cli(ch, ['pw-submit', RPC], { ...extra, ...proofEnv });
    }
    await stagePayoutArtifacts(ch);
    cli(ch, ['pw-finalize', RPC]);
    const auth = readJson(wc(ch, 'pw_auth.json'));
    if (ticket) {
      ticket.status = 'settle_done';
      ticket.steps.settle = { completedAt: Date.now(), authDigest: auth.auth_digest };
      upsertTicket(ch, ticket);
    }
    res.json({ authDigest: auth.auth_digest, paidOut: true });
  }).catch(e => failRoute(res, e));
});

// POST /api/v1/channel/:ch/partial-withdrawal/cancel (A45)
// NOT YET ENABLED. Correction to the design doc: NO new prover is needed — the contract
// `cancelPartialWithdrawal(CancelCloseRequest, MleProof)` reuses the EXACT same
// `verifier.verifyCancelClose(...)` and `CancelCloseProver` proof as A30 cancelClose (only the
// on-chain pending digest it matches differs). The blocker is a SOUNDNESS question, not missing
// machinery. `pw-submit` now uses the real close proof's next-era nonce and P0-9 provides the
// supported unilateral veto through `requestClose()`; a direct cancel route still needs a proof
// that its revived-state era relation is equivalent for the partial-withdrawal lifecycle. Enabling
// A45 requires that separate threat-model/review before wiring the CLI path. Deferred deliberately.
router.post('/cancel', (req, res) => {
  res.status(501).json({
    error: 'cancel partial withdrawal not yet enabled',
    detail: 'Use requestClose() for the P0-9 unilateral veto. A direct partial-withdrawal cancel route still needs its revived-state era relation reviewed before it can reuse CancelCloseProver safely (A45).',
  });
});

module.exports = router;
