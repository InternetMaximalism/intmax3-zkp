const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, readJson } = require('../lib/cli');

const router = Router({ mergeParams: true });

// GET /api/v1/channel/:ch/snapshot (A6/A39)
router.get('/snapshot', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    res.json(readJson(wc(ch, 'channel_snapshot.json')));
  } catch (e) {
    res.status(404).json({ error: 'no channel yet' });
  }
});

// GET /api/v1/channel/:ch/status (A40)
router.get('/status', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    const record = snapshot.record || {};
    const status = record.status || 'active';
    const result = { status };
    if (record.closeRequestedAt) result.closeRequestedAt = record.closeRequestedAt;
    if (record.challengeDeadline) result.challengeDeadline = record.challengeDeadline;
    if (record.finalizedAt) result.finalizedAt = record.finalizedAt;
    res.json(result);
  } catch (e) {
    res.status(404).json({ error: 'no channel yet' });
  }
});

// GET /api/v1/channel/:ch/backing (A43)
router.get('/backing', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    res.json(readJson(wc(ch, 'channel_backing.json')));
  } catch (e) {
    res.status(404).json({ error: 'no deposit backing yet' });
  }
});

// GET /api/v1/channel/:ch/registration-record (A3)
router.get('/registration-record', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    cli(ch, ['export-reg-record']);
    const record = readJson(wc(ch, 'cli_reg_record.json'));
    res.json(record);
  } catch (e) {
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  }
});

// GET /api/v1/channel/:ch/deposit/info (A42)
router.get('/deposit/info', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    const backing = readJson(wc(ch, 'channel_backing.json'));
    if (!backing.rollup) throw new Error('no rollup in channel_backing.json');
    if (!backing.deposit_recipient) throw new Error('no deposit_recipient in channel_backing.json');
    res.json({
      rollup: backing.rollup,
      depositRecipient: backing.deposit_recipient,
      rpc: RPC,
      chainId: parseInt(process.env.CHAIN_ID || '31337', 10),
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

module.exports = router;
