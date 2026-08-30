const { Router } = require('express');
const fs = require('fs');
const { cli, wc, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');
const producer = require('../lib/block-producer');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/burn/cosign (A22)
router.post('/cosign', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    const active = findActiveTicket(ch, 'partial_withdrawal');
    const { debitPayload, transferDescriptor, tokenIndex } = req.body || {};
    if (!debitPayload || !transferDescriptor) {
      res.status(400).json({ error: 'needs { debitPayload, transferDescriptor, tokenIndex? }' });
      return;
    }
    // Multi-token (§N): the burned BASE token rides inside the signed descriptor; an optional
    // top-level tokenIndex is a client-intent cross-check (fail-closed on mismatch).
    const descTok = transferDescriptor.interChannelTx && transferDescriptor.interChannelTx.tokenIndex;
    if (tokenIndex !== undefined && tokenIndex !== null && String(tokenIndex) !== String(descTok)) {
      res.status(400).json({ error: `tokenIndex mismatch: body says ${tokenIndex}, signed descriptor says ${descTok}` });
      return;
    }
    const producerRequestId = producer.stableRequestId('burn', {
      ch, debitPayload, transferDescriptor,
    });
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
    const liveNonceEnv = await producer.authoritativeBaseNonceEnv(ch);
    if (!fs.existsSync(wc(ch, 'burn_cosigned.json'))) {
      cli(ch, ['cosign-burn-send', 'burn_payload.json', 'burn_descriptor.json', 'burn_cosigned.json'], liveNonceEnv);
    }
    // This legacy alias must have the same atomic security semantics as
    // `/partial-withdrawal/burn`. Merely co-signing would leave the resident base nonce unchanged,
    // allowing an inter-channel send through the other route to be co-signed at the same cursor
    // after this lock is released. Admit and settle the burn before returning instead.
    const cosignedHead = readJson(wc(ch, 'burn_cosigned.json'));
    const blockReceipt = await producer.postInterChannel(
      cosignedHead, debitPayload, transferDescriptor, producerRequestId,
    );
    writeJson(wc(ch, 'pw_producer.json'), { producerRequestId, blockReceipt, liveReceipt: null });
    const liveReceipt = await producer.liveSettleInterChannel(
      ch, blockReceipt, cosignedHead, debitPayload, transferDescriptor,
    );
    writeJson(wc(ch, 'pw_producer.json'), { producerRequestId, blockReceipt, liveReceipt });
    ticket.status = 'burn_done';
    ticket.steps = { ...(ticket.steps || {}), burn: { completedAt: Date.now() }, settle: null };
    ticket = upsertTicket(ch, ticket);
    res.json({ state: cosignedHead, ticket, blockReceipt, liveReceipt });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
