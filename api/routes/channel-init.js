const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, depositKey, sh, rollupOf, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/init (A5)
router.post('/init', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    fs.mkdirSync(require('../lib/cli').chDir(ch), { recursive: true });
    writeJson(wc(ch, 'contribution.json'), req.body);
    cli(ch, ['init', 'contribution.json', 'channel_snapshot.json']);
    res.json(readJson(wc(ch, 'channel_snapshot.json')));
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/join (W1)
// Alias for init — the client sends a GenesisContribution, gets back a snapshot.
router.post('/join', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    fs.mkdirSync(require('../lib/cli').chDir(ch), { recursive: true });
    const contribution = req.body.contribution || req.body;
    writeJson(wc(ch, 'contribution.json'), contribution);
    cli(ch, ['init', 'contribution.json', 'channel_snapshot.json']);
    const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    const slot = snapshot.members ? snapshot.members.length - 1 : 0;
    res.json({ snapshot, slot, balance: '0' });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// Multi-token (detail2 §N): optional tokenIndex body param, default '0' (ETH). Decimal u32
// only — it becomes L1 calldata AND a positional CLI argv.
function parseTokenIndex(v) {
  if (v === undefined || v === null || v === '') return '0';
  const s = String(v);
  if (!/^[0-9]{1,10}$/.test(s) || Number(s) > 0xFFFFFFFF) return null;
  return s;
}

// POST /api/v1/channel/:ch/join-and-deposit (W2)
// body: { contribution, depositAmount?, tokenIndex? } — tokenIndex optional, default '0'.
router.post('/join-and-deposit', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    fs.mkdirSync(require('../lib/cli').chDir(ch), { recursive: true });
    const contribution = req.body.contribution || req.body;
    const depositAmount = req.body.depositAmount || '0';
    const tokenIndex = parseTokenIndex(req.body.tokenIndex);
    if (tokenIndex === null) {
      res.status(400).json({ error: 'tokenIndex must be a decimal u32' });
      return;
    }

    writeJson(wc(ch, 'contribution.json'), contribution);
    cli(ch, ['init', 'contribution.json', 'channel_snapshot.json']);
    let snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    const slot = snapshot.members ? snapshot.members.length - 1 : 0;
    let depositTxHash;

    if (depositAmount && depositAmount !== '0') {
      try {
        const backing = readJson(wc(ch, 'channel_backing.json'));
        // tokenIndex 0 = ETH (msg.value == amount); nonzero = registered ERC-20 (msg.value 0;
        // requires a prior approve(rollup, amount) by the depositor — §N-7).
        const castArgs = [
          'send', backing.rollup,
          'deposit(bytes32,uint32,uint256,bytes32)',
          backing.deposit_recipient, tokenIndex, String(depositAmount),
          '0x0000000000000000000000000000000000000000000000000000000000000000',
        ];
        if (tokenIndex === '0') castArgs.push('--value', String(depositAmount));
        castArgs.push('--private-key', depositKey(), '--rpc-url', RPC, '--json');
        const out = sh('cast', castArgs, { stdio: 'pipe' });
        depositTxHash = (out.match(/"transactionHash"\s*:\s*"(0x[0-9a-fA-F]+)"/) || [])[1] || '';
        const depositor = sh('cast', ['wallet', 'address', '--private-key', depositKey()], { stdio: 'pipe' }).trim();

        cli(ch, ['cosign-l1-deposit-import', String(slot), String(depositAmount), depositor, 'l1_import_cosigned.json', tokenIndex]);
        snapshot = readJson(wc(ch, 'channel_snapshot.json'));
      } catch (depErr) {
        console.error('deposit failed (channel joined with 0 balance):', depErr.message);
      }
    }

    res.json({ snapshot, slot, balance: depositAmount !== '0' ? depositAmount : '0', depositTxHash });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/register-token (multi-token §N-1)
// body: { tokenIndex } — appends the BASE token index to the channel's cosigned registry via
// the CLI `register-token` subcommand (N-of-N cosigned, append-only, fail-closed on duplicates
// or a full registry — TM-1). Returns the advanced snapshot.
router.post('/register-token', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const tokenIndex = parseTokenIndex(req.body && req.body.tokenIndex);
    if (tokenIndex === null || tokenIndex === undefined || (req.body && req.body.tokenIndex === undefined)) {
      res.status(400).json({ error: 'needs { tokenIndex } (decimal u32)' });
      return;
    }
    cli(ch, ['register-token', tokenIndex, 'token_register_cosigned.json']);
    res.json(readJson(wc(ch, 'channel_snapshot.json')));
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
