const { Router } = require('express');
const { cli, wc, RPC, readJson, writeJson, ensureSettlement, failRoute } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');

const router = Router({ mergeParams: true });

// The marker `channel_member pw-finalize` prints when it deliberately stops after recording the
// on-chain authorization. See `cmd_pw_finalize` (src/bin/channel_member.rs): the proof-free payout
// door `IntmaxRollup.claimAuthorizedWithdrawal` was REMOVED (it paid the global escrow against an
// authorization that binds neither amount nor recipient, so one valid close proof for one's OWN
// channel could drain every channel), and its replacement needs a base-layer withdrawal proof
// built by a command — `cmd_partial_withdraw` — that does not exist yet (doc/tasks/todo.md:90).
const PW_PAYOUT_MISSING = 'STOPPING BEFORE PAYOUT';

/// Report the payout gap as the deliberate, permanent-for-now state it is (501), instead of the
/// opaque 500 an operator cannot distinguish from a broken node or a reverted transaction.
///
/// HONESTY over convenience: `pw-finalize` exits NON-ZERO on this path on EVERY chain, anvil
/// included, so the `{ ok: true }` these two routes used to promise after it was unreachable — the
/// request always landed in the catch. Nothing here converts a failure into a success: the
/// authorization it reports (`authorized: true`) is the one the CLI verified on-chain before
/// stopping, and the withdrawal itself is explicitly reported as NOT paid out.
function reportPwPayoutGap(res, ch, e) {
  let auth = {};
  try { auth = readJson(wc(ch, 'pw_auth.json')); } catch (_) { /* nothing recorded */ }
  const ticket = findActiveTicket(ch, 'partial_withdrawal');
  if (ticket) {
    // NOT `settle_done`: the money has not moved. Marking it terminal would tell every later
    // poller the withdrawal completed.
    ticket.status = 'settle_blocked';
    ticket.steps.settle = { blockedAt: Date.now(), authDigest: auth.auth_digest, paidOut: false };
    upsertTicket(ch, ticket);
  }
  return res.status(501).json({
    error: 'partial withdrawal cannot pay out: the payout leg is not implemented',
    authorized: true,
    paidOut: false,
    authDigest: auth.auth_digest,
    recipient: auth.withdrawal_recipient,
    amount: auth.withdrawal_amount,
    detail:
      'The on-chain authorization IS finalized (nothing was lost), but payout must go through ' +
      'withdrawNative/withdrawERC20, which require a verified base-layer withdrawal proof. The ' +
      'command that builds it (cmd_partial_withdraw) is not implemented — doc/tasks/todo.md:90, ' +
      'doc/tasks/pw-auth-threat-model.md. This is a deliberate fail-closed state on every chain.',
    log: String((e && e.stderr) || (e && e.message) || ''),
  });
}

/// True when a failed CLI run failed for that reason rather than for a real one.
function isPwPayoutGap(e) {
  return String((e && e.stderr) || '').includes(PW_PAYOUT_MISSING)
    || String((e && e.stdout) || '').includes(PW_PAYOUT_MISSING);
}

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
    writeJson(wc(ch, 'burn_payload.json'), debitPayload);
    writeJson(wc(ch, 'burn_descriptor.json'), transferDescriptor);
    cli(ch, ['cosign-burn-send', 'burn_payload.json', 'burn_descriptor.json', 'burn_cosigned.json']);
    const ticket = upsertTicket(ch, {
      id: 'pw_' + Date.now(),
      type: 'partial_withdrawal',
      status: 'burn_done',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      params: { amount: String(req.body.amount || ''), recipient: req.body.recipient || '', tokenIndex: descTok !== undefined ? String(descTok) : '0' },
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

// POST /api/v1/channel/:ch/partial-withdrawal/finalize (A25)
router.post('/finalize', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    // NOTE: on today's code this line always throws — `pw-finalize` records the authorization and
    // then exits non-zero because the payout leg does not exist (see PW_PAYOUT_MISSING above).
    // The success branch below is kept, and is correct, for when `cmd_partial_withdraw` lands.
    cli(ch, ['pw-finalize', RPC]);
    const auth = readJson(wc(ch, 'pw_auth.json'));
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (ticket) {
      ticket.status = 'settle_done';
      ticket.steps.settle = { completedAt: Date.now(), authDigest: auth.auth_digest };
      upsertTicket(ch, ticket);
    }
    res.json({ ok: true, authDigest: auth.auth_digest, paidOut: true });
  }).catch(e => {
    if (isPwPayoutGap(e)) return reportPwPayoutGap(res, ch, e);
    return failRoute(res, e);
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
    ensureSettlement(ch);
    const pwRecipient = (req.body && req.body.recipient) || (ticket && ticket.params.recipient) || '';
    const extra = pwRecipient ? { PW_RECIPIENT: pwRecipient } : {};
    cli(ch, ['pw-submit', RPC], extra);
    // As in /finalize: this throws today, deliberately, and the gap is reported as 501 rather
    // than as an anonymous 500.
    cli(ch, ['pw-finalize', RPC]);
    const auth = readJson(wc(ch, 'pw_auth.json'));
    if (ticket) {
      ticket.status = 'settle_done';
      ticket.steps.settle = { completedAt: Date.now(), authDigest: auth.auth_digest };
      upsertTicket(ch, ticket);
    }
    res.json({ authDigest: auth.auth_digest, paidOut: true });
  }).catch(e => {
    if (isPwPayoutGap(e)) return reportPwPayoutGap(res, ch, e);
    return failRoute(res, e);
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
