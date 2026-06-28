const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, rollupOf, readJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/close/request (A26)
// requestClose-only phase: freeze the channel (ClosePending, start grace) WITHOUT building the
// (heavy) close proof, so the caller controls timing. Pass { advanceTime } on a dev chain to
// fast-forward past the grace window via evm_increaseTime.
router.post('/request', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const manager = req.body && req.body.manager;
    if (!manager) {
      res.status(400).json({ error: 'needs { manager }' });
      return;
    }
    const env = { CLOSE_REQUEST_ONLY: '1' };
    if (req.body && req.body.advanceTime) env.CLOSE_ADVANCE_TIME = String(req.body.advanceTime);
    const out = cli(ch, ['close', manager, RPC], env);
    res.json({ ok: true, log: out });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/close/submit-intent (A28)
// Submit the close intent on an ALREADY-pending close (requestClose done via A26). Builds the heavy
// close proof and submits it; CLOSE_SKIP_REQUEST avoids re-calling requestClose (which would revert).
router.post('/submit-intent', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const manager = req.body && req.body.manager;
    const sv = (req.body && req.body.verifier) || '';
    if (!manager) {
      res.status(400).json({ error: 'needs { manager }' });
      return;
    }
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) {
      ticket.status = 'close_pending';
      upsertTicket(ch, ticket);
    }
    const out = cli(ch, ['close', manager, RPC], { CLOSE_SV: sv, CLOSE_SKIP_REQUEST: '1' });
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

// POST /api/v1/channel/:ch/close/challenge (A29)
// Replace a pending close with a newer signed state during the challenge period. Mechanically this
// is submitCloseIntent on an already-pending close with a strictly higher (epoch, state_version) —
// the SAME machinery as submit-intent (CLOSE_SKIP_REQUEST). The on-chain manager enforces the
// monotonic (epoch, version) ordering, so a non-newer challenge fails closed. PRECONDITION: this
// channel's head has advanced to a higher state_version than the pending close.
router.post('/challenge', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const manager = req.body && req.body.manager;
    const sv = (req.body && req.body.verifier) || '';
    if (!manager) {
      res.status(400).json({ error: 'needs { manager }' });
      return;
    }
    const out = cli(ch, ['close', manager, RPC], { CLOSE_SV: sv, CLOSE_SKIP_REQUEST: '1' });
    res.json({ ok: true, log: out });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/close/cancel (A30)
// Cancel a pending close by proving the members kept operating at a higher state_version.
// Heavy (real MLE/WHIR proving). The CLI reconstructs the pending CloseIntent from the persisted
// close_intent_full.json and proves over the current (revived) head; soundness is in-circuit +
// on-chain (the manager injects the registered member-set commitment and matches the digest).
router.post('/cancel', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const manager = req.body && req.body.manager;
    const sv = (req.body && req.body.verifier) || '';
    if (!manager) {
      res.status(400).json({ error: 'needs { manager }' });
      return;
    }
    const out = cli(ch, ['cancel-close', manager, RPC], sv ? { CANCEL_SV: sv } : {});
    res.json({ ok: true, log: out });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/close/finalize (A31)
router.post('/finalize', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const manager = req.body && req.body.manager;
    if (!manager) {
      res.status(400).json({ error: 'needs { manager }' });
      return;
    }
    const ticket = findActiveTicket(ch, 'full_withdrawal');
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

// POST /api/v1/channel/:ch/close/claim (A32)
router.post('/claim', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const { manager, slot, recipient } = req.body || {};
    if (!manager || slot === undefined || !recipient) {
      res.status(400).json({ error: 'needs { manager, slot, recipient }' });
      return;
    }
    const ticket = findActiveTicket(ch, 'full_withdrawal');
    if (ticket) {
      ticket.status = 'claim_pending';
      upsertTicket(ch, ticket);
    }
    const out = cli(ch, ['claim', manager, String(slot), RPC], { CLAIM_RECIPIENT: recipient });
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

// POST /api/v1/channel/:ch/close/pull-credit (A33)
// Pull a previously-submitted withdrawal claim's ETH credit to the member's registered recipient
// (claimWithdrawalCredit). No proving. The recipient is the caller the contract requires.
router.post('/pull-credit', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const { manager, recipient } = req.body || {};
    if (!manager || !recipient) {
      res.status(400).json({ error: 'needs { manager, recipient }' });
      return;
    }
    const out = cli(ch, ['claim', manager, '0', RPC], { CLAIM_PULL_ONLY: '1', CLAIM_RECIPIENT: recipient });
    res.json({ ok: true, log: out });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/close/post-close-claim (A34)
// Claim a late inter-channel delta that landed after the channel was finalized. Heavy (real
// MLE/WHIR proving). The receiver decrypts its own delta from the persisted source InterChannelTx;
// the circuit proves the tx's inclusion in the finalized settled-tx accumulator. Soundness is
// in-circuit + on-chain (the manager recomputes the shared-native nullifier and caps the fund).
router.post('/post-close-claim', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const { manager, slot, recipient, incomingTxIndex, sourceTx } = req.body || {};
    if (!manager || slot === undefined || !recipient || incomingTxIndex === undefined) {
      res.status(400).json({ error: 'needs { manager, slot, recipient, incomingTxIndex }' });
      return;
    }
    const env = { CLAIM_RECIPIENT: recipient };
    if (sourceTx) env.POST_CLOSE_SOURCE_TX = sourceTx;
    const out = cli(ch, ['post-close-claim', manager, String(slot), String(incomingTxIndex), RPC], env);
    res.json({ ok: true, log: out });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
