const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, ANVIL0, sh, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/deposit/l1-send (A18)
router.post('/l1-send', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    const amount = req.body && req.body.amount;
    if (!amount) {
      return res.status(400).json({ error: 'needs { amount }' });
    }
    const backing = readJson(wc(ch, 'channel_backing.json'));
    if (!backing.rollup || !backing.deposit_recipient) {
      throw new Error('no rollup/deposit_recipient in channel_backing.json');
    }
    const out = sh('cast', [
      'send', backing.rollup,
      'deposit(bytes32,uint32,uint256,bytes32)',
      backing.deposit_recipient, '0', String(amount),
      '0x0000000000000000000000000000000000000000000000000000000000000000',
      '--value', String(amount),
      '--private-key', ANVIL0, '--rpc-url', RPC, '--json',
    ], { stdio: 'pipe' });
    const txHash = (out.match(/"transactionHash"\s*:\s*"(0x[0-9a-fA-F]+)"/) || [])[1] || '';
    const depositor = sh('cast', ['wallet', 'address', '--private-key', ANVIL0], { stdio: 'pipe' }).trim();
    writeJson(wc(ch, 'pending_deposit.json'), { depositor, amount: String(amount), txHash });
    res.json({ txHash, depositor });
  } catch (e) {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  }
});

// POST /api/v1/channel/:ch/deposit/import (A20)
router.post('/import', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const slot = (req.body && req.body.recipientSlot) || 0;
    let depositor, amount;
    if (req.body && req.body.depositor && req.body.amount) {
      depositor = req.body.depositor;
      amount = req.body.amount;
    } else {
      const dep = readJson(wc(ch, 'pending_deposit.json'));
      depositor = dep.depositor;
      amount = dep.amount;
    }
    cli(ch, ['cosign-l1-deposit-import', String(slot), String(amount), depositor, 'l1_import_cosigned.json']);
    const depTicket = findActiveTicket(ch, 'deposit');
    if (depTicket) {
      depTicket.status = 'import_done';
      depTicket.steps.import = { completedAt: Date.now() };
      upsertTicket(ch, depTicket);
    }
    res.json(readJson(wc(ch, 'channel_snapshot.json')));
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/deposit (W7 — combined deposit flow)
router.post('/', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const { recipientSlot, depositor, amount } = req.body || {};
    if (!amount) {
      res.status(400).json({ error: 'needs { recipientSlot, depositor, amount }' });
      return;
    }
    const slot = recipientSlot || 0;
    let dep = depositor;
    let amt = amount;

    if (!dep) {
      const backing = readJson(wc(ch, 'channel_backing.json'));
      const out = sh('cast', [
        'send', backing.rollup,
        'deposit(bytes32,uint32,uint256,bytes32)',
        backing.deposit_recipient, '0', String(amt),
        '0x0000000000000000000000000000000000000000000000000000000000000000',
        '--value', String(amt),
        '--private-key', ANVIL0, '--rpc-url', RPC, '--json',
      ], { stdio: 'pipe' });
      dep = sh('cast', ['wallet', 'address', '--private-key', ANVIL0], { stdio: 'pipe' }).trim();
    }

    cli(ch, ['cosign-l1-deposit-import', String(slot), String(amt), dep, 'l1_import_cosigned.json']);
    const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    res.json({ snapshot, balance: String(amt) });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
