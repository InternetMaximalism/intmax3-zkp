const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, depositKey, sh, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');

const router = Router({ mergeParams: true });

// Multi-token (detail2 §N): validate an optional tokenIndex body param (default '0' = native
// ETH). Must be a plain non-negative decimal u32 — it becomes L1 calldata AND a positional CLI
// argv (never allow flag-like values through).
function parseTokenIndex(v) {
  if (v === undefined || v === null || v === '') return '0';
  const s = String(v);
  if (!/^[0-9]{1,10}$/.test(s) || Number(s) > 0xFFFFFFFF) return null;
  return s;
}

// Build the `cast send ... deposit(...)` argv for a deposit of `amount` at `tokenIndex`.
// tokenIndex 0 = native ETH (msg.value == amount); a nonzero index is a REGISTERED ERC-20
// (msg.value MUST be 0 — IntmaxRollup pulls the tokens via safeTransferFrom, which requires a
// prior approve(rollup, amount) by the depositor; §N-7).
function depositCastArgs(backing, tokenIndex, amount) {
  const args = [
    'send', backing.rollup,
    'deposit(bytes32,uint32,uint256,bytes32)',
    backing.deposit_recipient, tokenIndex, String(amount),
    '0x0000000000000000000000000000000000000000000000000000000000000000',
  ];
  if (tokenIndex === '0') args.push('--value', String(amount));
  args.push('--private-key', depositKey(), '--rpc-url', RPC, '--json');
  return args;
}

// POST /api/v1/channel/:ch/deposit/l1-send (A18)
// body: { amount, tokenIndex? } — tokenIndex optional, default '0' (ETH).
router.post('/l1-send', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    const amount = req.body && req.body.amount;
    if (!amount) {
      return res.status(400).json({ error: 'needs { amount, tokenIndex? }' });
    }
    const tokenIndex = parseTokenIndex(req.body && req.body.tokenIndex);
    if (tokenIndex === null) {
      return res.status(400).json({ error: 'tokenIndex must be a decimal u32' });
    }
    const backing = readJson(wc(ch, 'channel_backing.json'));
    if (!backing.rollup || !backing.deposit_recipient) {
      throw new Error('no rollup/deposit_recipient in channel_backing.json');
    }
    const out = sh('cast', depositCastArgs(backing, tokenIndex, amount), { stdio: 'pipe' });
    const txHash = (out.match(/"transactionHash"\s*:\s*"(0x[0-9a-fA-F]+)"/) || [])[1] || '';
    const depositor = sh('cast', ['wallet', 'address', '--private-key', depositKey()], { stdio: 'pipe' }).trim();
    writeJson(wc(ch, 'pending_deposit.json'), { depositor, amount: String(amount), tokenIndex, txHash });
    res.json({ txHash, depositor, tokenIndex });
  } catch (e) {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  }
});

// POST /api/v1/channel/:ch/deposit/import (A20)
// body: { recipientSlot?, depositor?, amount?, tokenIndex? } — tokenIndex optional, default:
// the pending deposit's recorded index, else '0'. Forwarded to the CLI, which resolves it
// against the channel's cosigned registry (unregistered ⇒ fail-closed, TM-7).
router.post('/import', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const slot = (req.body && req.body.recipientSlot) || 0;
    let depositor, amount, tokenIndex;
    if (req.body && req.body.depositor && req.body.amount) {
      depositor = req.body.depositor;
      amount = req.body.amount;
      tokenIndex = parseTokenIndex(req.body.tokenIndex);
    } else {
      const dep = readJson(wc(ch, 'pending_deposit.json'));
      depositor = dep.depositor;
      amount = dep.amount;
      tokenIndex = parseTokenIndex((req.body && req.body.tokenIndex) !== undefined ? req.body.tokenIndex : dep.tokenIndex);
    }
    if (tokenIndex === null) {
      res.status(400).json({ error: 'tokenIndex must be a decimal u32' });
      return;
    }
    cli(ch, ['cosign-l1-deposit-import', String(slot), String(amount), depositor, 'l1_import_cosigned.json', tokenIndex]);
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
// body: { recipientSlot?, depositor?, amount, tokenIndex? } — tokenIndex optional, default '0'.
router.post('/', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const { recipientSlot, depositor, amount } = req.body || {};
    if (!amount) {
      res.status(400).json({ error: 'needs { recipientSlot, depositor, amount, tokenIndex? }' });
      return;
    }
    const tokenIndex = parseTokenIndex(req.body && req.body.tokenIndex);
    if (tokenIndex === null) {
      res.status(400).json({ error: 'tokenIndex must be a decimal u32' });
      return;
    }
    const slot = recipientSlot || 0;
    let dep = depositor;
    let amt = amount;

    if (!dep) {
      const backing = readJson(wc(ch, 'channel_backing.json'));
      const out = sh('cast', depositCastArgs(backing, tokenIndex, amt), { stdio: 'pipe' });
      dep = sh('cast', ['wallet', 'address', '--private-key', depositKey()], { stdio: 'pipe' }).trim();
    }

    cli(ch, ['cosign-l1-deposit-import', String(slot), String(amt), dep, 'l1_import_cosigned.json', tokenIndex]);
    const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    res.json({ snapshot, balance: String(amt), tokenIndex });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
