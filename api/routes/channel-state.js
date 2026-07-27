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

// GET /api/v1/channel/:ch/tokens (multi-token §N)
// Per-token channel view derived from the cosigned snapshot: the active registry
// (local slot -> base tokenIndex) and the per-token channel-fund amounts. Balance-bearing
// responses stay backward compatible elsewhere (scalar = token 0); this route is the additive
// per-token surface. Hidden per-member balances are NOT here — they only decrypt client-side
// (wallet_balance returns a per-token `balances` array).
router.get('/tokens', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    const bs = (snapshot.state && snapshot.state.balanceState) || {};
    const fund = (snapshot.state && snapshot.state.channelFund) || {};
    const tokenCount = bs.tokenCount || 1;
    const registry = bs.tokenRegistry || [];
    const amounts = fund.amounts || [];
    const tokens = [];
    for (let t = 0; t < tokenCount; t++) {
      tokens.push({
        tokenSlot: t,
        tokenIndex: registry[t] !== undefined ? registry[t] : 0,
        fundAmount: amounts[t] !== undefined ? String(amounts[t]) : '0',
      });
    }
    res.json({ tokenCount, tokens });
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
