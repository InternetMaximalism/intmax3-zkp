const { Router } = require('express');
const { cli, wc, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { flushPublishedHead, publishOffchainSnapshot } = require('../lib/producer-head');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/cosign (A8)
router.post('/cosign', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    await flushPublishedHead(ch);
    writeJson(wc(ch, 'payload.json'), req.body);
    cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
    const state = readJson(wc(ch, 'cosigned.json'));
    await publishOffchainSnapshot(ch, state);
    res.json(state);
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/cosign-refresh (A11)
router.post('/cosign-refresh', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    await flushPublishedHead(ch);
    writeJson(wc(ch, 'refresh_payload.json'), req.body);
    cli(ch, ['cosign-refresh', 'refresh_payload.json', 'refresh_cosigned.json']);
    const state = readJson(wc(ch, 'refresh_cosigned.json'));
    await publishOffchainSnapshot(ch, state);
    res.json(state);
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/send (W3)
// Orchestrated intra-channel send: client sends the pre-built payload, server cosigns.
// Multi-token (§N-3): the moved token position rides INSIDE the signed payload
// (payload.channelTx.tokenSlot, IMPA-v2-bound) — the cosign CLI takes no token argv; an
// optional body.tokenSlot is accepted as a client-intent cross-check against the signed field.
router.post('/send', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    await flushPublishedHead(ch);
    const payload = req.body.payload || req.body;
    const tokenSlot = req.body.tokenSlot;
    const signedSlot = payload && payload.channelTx && payload.channelTx.tokenSlot;
    if (tokenSlot !== undefined && tokenSlot !== null && String(tokenSlot) !== String(signedSlot !== undefined ? signedSlot : 0)) {
      res.status(400).json({ error: `tokenSlot mismatch: body says ${tokenSlot}, signed payload says ${signedSlot}` });
      return;
    }
    writeJson(wc(ch, 'payload.json'), payload);
    cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
    const snapshot = readJson(wc(ch, 'cosigned.json'));
    const { headSyncReceipt } = await publishOffchainSnapshot(ch, snapshot);
    res.json({ snapshot, headSyncReceipt });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
