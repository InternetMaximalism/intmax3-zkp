const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, readJson, writeJson, ensureSettlement, failRoute } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');
const producer = require('../lib/block-producer');
const { cliWithPreparedExitKit } = require('../lib/exit-kit');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/partial-withdrawal/burn (W8 phase 1)
// Same as burn/cosign but under partial-withdrawal namespace for workflow clarity.
router.post('/burn', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    const active = findActiveTicket(ch, 'partial_withdrawal');
    const { debitPayload, transferDescriptor, tokenIndex } = req.body || {};
    if (!debitPayload || !transferDescriptor) {
      res.status(400).json({ error: 'needs { debitPayload, transferDescriptor, amount, recipient, tokenIndex? }' });
      return;
    }
    // Multi-token (§N): the burned BASE token rides inside the signed descriptor
    // (interChannelTx.tokenIndex → last_burn.json → the pw-submit Withdrawal/IMPW authDigest);
    // an optional top-level tokenIndex is a client-intent cross-check (fail-closed on
    // mismatch).
    const descTok = transferDescriptor.interChannelTx && transferDescriptor.interChannelTx.tokenIndex;
    if (tokenIndex !== undefined && tokenIndex !== null && String(tokenIndex) !== String(descTok)) {
      res.status(400).json({ error: `tokenIndex mismatch: body says ${tokenIndex}, signed descriptor says ${descTok}` });
      return;
    }
    const producerRequestId = producer.stableRequestId('burn', {
      ch, debitPayload, transferDescriptor,
    });
    // `burn_pending` is a durable two-phase marker written before signing. A retry of the exact
    // same request resumes; every other non-terminal PW state remains an exclusion lock. This
    // prevents a crash after N-of-N signing from letting the next HTTP request overwrite the only
    // artifacts capable of settling that already-advanced channel head.
    let ticket = active;
    if (active) {
      const resumable = active.status === 'burn_pending'
        && active.params
        && active.params.producerRequestId === producerRequestId;
      if (!resumable) {
        res.status(409).json({ error: 'resolve the active partial withdrawal before burning again', ticket: active });
        return;
      }
    } else {
      writeJson(wc(ch, 'burn_payload.json'), debitPayload);
      writeJson(wc(ch, 'burn_descriptor.json'), transferDescriptor);
      fs.rmSync(wc(ch, 'burn_cosigned.json'), { force: true });
      ticket = upsertTicket(ch, {
        id: `pw_${producerRequestId.slice('burn:'.length)}`,
        type: 'partial_withdrawal',
        status: 'burn_pending',
        createdAt: Date.now(),
        updatedAt: Date.now(),
        params: {
          producerRequestId,
          amount: String(req.body.amount || ''),
          recipient: req.body.recipient || '',
          tokenIndex: descTok !== undefined ? String(descTok) : '0',
        },
        steps: { burn: null, settle: null },
      });
    }
    // This route owns the channel lock through cosign -> producer admission -> live settle. Bind the
    // CLI to the daemon cursor read inside that critical section; never fall back to frozen setup
    // state when the live authority is unavailable.
    const liveNonceEnv = await producer.authoritativeBaseNonceEnv(ch);
    if (!fs.existsSync(wc(ch, 'burn_cosigned.json'))) {
      // Signer-independent exit: the burn debits the fund vector and pushes the settle chain, so
      // the exit kit for the exact post-burn state is proved against the staged producer block
      // BEFORE the co-signers release their signatures; `postInterChannel` then commits that
      // very block.
      await cliWithPreparedExitKit(
        ch,
        ['cosign-burn-send', 'burn_payload.json', 'burn_descriptor.json', 'burn_cosigned.json'],
        liveNonceEnv,
        { requestId: producerRequestId },
      );
    }
    // The burn is an inter-channel send to BURN_CHANNEL_ID: admit it durably at the producer and
    // settle it in the live base-state authority, exactly like a normal send. The journaled
    // producer request id is what the payout leg later proves against.
    const cosignedHead = readJson(wc(ch, 'burn_cosigned.json'));
    const blockReceipt = await producer.postInterChannel(
      cosignedHead, debitPayload, transferDescriptor, producerRequestId,
    );
    // Persist the public admission before the second phase. A crash here is recoverable by
    // idempotently replaying the same post + live settle from the burn_pending ticket/artifacts.
    writeJson(wc(ch, 'pw_producer.json'), { producerRequestId, blockReceipt, liveReceipt: null });
    const liveReceipt = await producer.liveSettleInterChannel(
      ch, blockReceipt, cosignedHead, debitPayload, transferDescriptor,
    );
    writeJson(wc(ch, 'pw_producer.json'), { producerRequestId, blockReceipt, liveReceipt });
    ticket.status = 'burn_done';
    ticket.steps = { ...(ticket.steps || {}), burn: { completedAt: Date.now() }, settle: null };
    ticket = upsertTicket(ch, ticket);
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
    // anvil: deploys the devnet stack on demand, as before. Real chain: a structured 409 naming
    // the operator task, because the real-VK deployer brings its own rollup and so must run
    // BEFORE the channel is funded (lib/cli.ensureSettlement).
    ensureSettlement(ch);
    const pwRecipient = (req.body && req.body.recipient) || (ticket && ticket.params.recipient) || '';
    const extra = pwRecipient ? { PW_RECIPIENT: pwRecipient } : {};
    cli(ch, ['pw-submit', RPC], extra);
    const auth = readJson(wc(ch, 'pw_auth.json'));
    res.json({ authDigest: auth.auth_digest });
  }).catch(e => failRoute(res, e));
});

// Prove + wrap the burn's payout artifacts in the resident daemon and stage them in the channel
// workdir for the CLI payout driver. The daemon proves against ITS journaled live base history;
// the route only ferries the result. The withdrawal prover address is the operator's L1 signer
// (any address is sound — it is committed into the proof's public inputs).
async function stagePayoutArtifacts(ch) {
  const { l1SignerAddress } = require('../lib/cli');
  const pw = readJson(wc(ch, 'pw_producer.json'));
  const descriptor = readJson(wc(ch, 'burn_descriptor.json'));
  const artifacts = await producer.liveBurnPayoutArtifacts(
    ch, pw.producerRequestId, descriptor, l1SignerAddress(),
  );
  writeJson(wc(ch, 'pw_artifacts.json'), artifacts);
  return artifacts;
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
    cli(ch, ['pw-submit', RPC], extra);
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
