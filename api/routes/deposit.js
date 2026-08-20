const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, l1SignerArgs, l1SignerAddress, sh, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');
const { importL1Deposit } = require('../lib/deposit-pipeline');

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
  args.push(...l1SignerArgs(), '--rpc-url', RPC, '--json');
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
    const depositor = l1SignerAddress();
    writeJson(wc(ch, 'pending_deposit.json'), { depositor, amount: String(amount), tokenIndex, txHash });
    res.json({ txHash, depositor, tokenIndex });
  } catch (e) {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  }
});

// POST /api/v1/channel/:ch/deposit/import (A20)
// body: { recipientSlot?, txHash? } — txHash defaults to the server-written pending deposit's.
//
// SECURITY: `depositor`, `amount` and `tokenIndex` are NO LONGER accepted. They are read from the
// transaction's on-chain `Deposited` log by the CLI, which also resolves the token index against
// the channel's cosigned registry (unregistered ⇒ fail-closed, TM-7). This closes the body-trust
// bypass of the tx-tied `pending_deposit.json`. See doc/tasks/deposit-import-threat-model.md.
router.post('/import', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    const b = req.body || {};
    if (b.depositor !== undefined || b.amount !== undefined || b.tokenIndex !== undefined) {
      res.status(400).json({ error: 'depositor/amount/tokenIndex are no longer accepted: they are read from the on-chain Deposited log. Send { recipientSlot, txHash }.' });
      return;
    }
    const slot = b.recipientSlot !== undefined ? b.recipientSlot : 0;
    let txHash = b.txHash;
    if (txHash === undefined) {
      const dep = readJson(wc(ch, 'pending_deposit.json'));
      txHash = dep.txHash;
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(String(txHash || ''))) {
      res.status(400).json({ error: 'needs a txHash (0x + 64 hex) — the deposit is verified on-chain' });
      return;
    }
    if (!/^[0-9]{1,4}$/.test(String(slot))) {
      res.status(400).json({ error: 'recipientSlot must be a small decimal integer' });
      return;
    }
    // OPERATOR-FUNDED: every deposit path in THIS service signs with the server's own
    // the configured server L1 signer (see /l1-send above and POST / below) — there is no user-signed deposit here,
    // that is the wallet relay's MetaMask flow. So the on-chain depositor is by construction the
    // operator, which is bound to no balance slot, and the CLI's default depositor<->slot binding
    // cannot hold. The flag relaxes ONLY that leg: if the depositor were some member's bound exit
    // address, the CLI's misdirection refusal still fires unconditionally, flag or not.
    await importL1Deposit(ch, slot, txHash, { allowUnboundDepositor: true });
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
// body: { recipientSlot?, amount, tokenIndex? } — tokenIndex optional, default '0'.
//
// SECURITY: this endpoint MAKES the deposit itself (with the server's own key) and then imports
// the transaction it just broadcast. A caller-supplied `depositor` is no longer accepted: it was
// the body-trust bypass that let a caller claim a deposit it never made. The credited amount is
// whatever the on-chain `Deposited` log says, not `amount` — `amount` only sizes the deposit tx.
router.post('/', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    const { recipientSlot, amount } = req.body || {};
    if (req.body && req.body.depositor !== undefined) {
      res.status(400).json({ error: 'depositor is no longer accepted: the deposit is made by this endpoint and read back from its on-chain Deposited log.' });
      return;
    }
    if (!amount) {
      res.status(400).json({ error: 'needs { recipientSlot, amount, tokenIndex? }' });
      return;
    }
    const tokenIndex = parseTokenIndex(req.body && req.body.tokenIndex);
    if (tokenIndex === null) {
      res.status(400).json({ error: 'tokenIndex must be a decimal u32' });
      return;
    }
    const slot = recipientSlot || 0;
    if (!/^[0-9]{1,4}$/.test(String(slot))) {
      res.status(400).json({ error: 'recipientSlot must be a small decimal integer' });
      return;
    }
    const amt = amount;

    const backing = readJson(wc(ch, 'channel_backing.json'));
    const out = sh('cast', depositCastArgs(backing, tokenIndex, amt), { stdio: 'pipe' });
    const txHash = (out.match(/"transactionHash"\s*:\s*"(0x[0-9a-fA-F]{64})"/) || [])[1];
    if (!txHash) {
      res.status(500).json({ error: 'could not read the deposit transactionHash from cast output' });
      return;
    }

    // OPERATOR-FUNDED (same rationale as /import above): this route just broadcast the deposit
    // with the server's own key, so the depositor is the operator and is bound to no slot.
    const pipeline = await importL1Deposit(ch, slot, txHash, { allowUnboundDepositor: true });
    const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    res.json({
      snapshot,
      balance: String(amt),
      tokenIndex,
      txHash,
      producerReceipt: pipeline.producerReceipt,
      headSyncReceipt: pipeline.headSyncReceipt,
    });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
