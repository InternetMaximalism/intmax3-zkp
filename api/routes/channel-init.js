const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, ANVIL0, sh, rollupOf, readJson, writeJson } = require('../lib/cli');
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

// POST /api/v1/channel/:ch/join-and-deposit (W2)
router.post('/join-and-deposit', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    fs.mkdirSync(require('../lib/cli').chDir(ch), { recursive: true });
    const contribution = req.body.contribution || req.body;
    const depositAmount = req.body.depositAmount || '0';

    writeJson(wc(ch, 'contribution.json'), contribution);
    cli(ch, ['init', 'contribution.json', 'channel_snapshot.json']);
    let snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    const slot = snapshot.members ? snapshot.members.length - 1 : 0;
    let depositTxHash;

    if (depositAmount && depositAmount !== '0') {
      try {
        const backing = readJson(wc(ch, 'channel_backing.json'));
        const out = sh('cast', [
          'send', backing.rollup,
          'deposit(bytes32,uint32,uint256,bytes32)',
          backing.deposit_recipient, '0', String(depositAmount),
          '0x0000000000000000000000000000000000000000000000000000000000000000',
          '--value', String(depositAmount),
          '--private-key', ANVIL0, '--rpc-url', RPC, '--json',
        ], { stdio: 'pipe' });
        depositTxHash = (out.match(/"transactionHash"\s*:\s*"(0x[0-9a-fA-F]+)"/) || [])[1] || '';
        const depositor = sh('cast', ['wallet', 'address', '--private-key', ANVIL0], { stdio: 'pipe' }).trim();

        cli(ch, ['cosign-l1-deposit-import', String(slot), String(depositAmount), depositor, 'l1_import_cosigned.json']);
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

module.exports = router;
