const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, l1SignerArgs, sh, rollupOf, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { findActiveTicket, upsertTicket } = require('../lib/tickets');
const { cliWithPreparedExitKit } = require('../lib/exit-kit');
const producer = require('../lib/block-producer');
const { importL1Deposit } = require('../lib/deposit-pipeline');
const { flushPublishedHead, publishOffchainSnapshot } = require('../lib/producer-head');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/init (A5)
router.post('/init', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    fs.mkdirSync(require('../lib/cli').chDir(ch), { recursive: true });
    writeJson(wc(ch, 'contribution.json'), req.body);
    cli(ch, ['init', 'contribution.json', 'channel_snapshot.json']);
    const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    // The durable live-balance spine starts HERE (sole base-state authority): the daemon derives
    // and owns the account/deposit salts; the API only ever learns the deposit recipient.
    // Idempotent across restarts — an existing snapshot returns its configured recipient.
    const live = await producer.liveInit(ch);
    await producer.liveBindSnapshot(ch, snapshot);
    await producer.register(snapshot);
    res.json({ ...snapshot, liveDepositRecipient: live.depositRecipient });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/join (W1)
// Alias for init — the client sends a GenesisContribution, gets back a snapshot.
router.post('/join', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    fs.mkdirSync(require('../lib/cli').chDir(ch), { recursive: true });
    const contribution = req.body.contribution || req.body;
    writeJson(wc(ch, 'contribution.json'), contribution);
    cli(ch, ['init', 'contribution.json', 'channel_snapshot.json']);
    const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    const live = await producer.liveInit(ch);
    await producer.liveBindSnapshot(ch, snapshot);
    await producer.register(snapshot);
    const slot = snapshot.members ? snapshot.members.length - 1 : 0;
    res.json({ snapshot, slot, balance: '0', liveDepositRecipient: live.depositRecipient });
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
  withLock(ch, async () => {
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
    const live = await producer.liveInit(ch);
    await producer.liveBindSnapshot(ch, snapshot);
    await producer.register(snapshot);
    const slot = snapshot.members ? snapshot.members.length - 1 : 0;
    let depositTxHash;
    let depositSucceeded = false;

    if (depositAmount && depositAmount !== '0') {
      try {
        const backing = readJson(wc(ch, 'channel_backing.json'));
        if (!backing.rollup) throw new Error('no rollup in channel_backing.json');
        // tokenIndex 0 = ETH (msg.value == amount); nonzero = registered ERC-20 (msg.value 0;
        // requires a prior approve(rollup, amount) by the depositor — §N-7).
        const castArgs = [
          'send', backing.rollup,
          'deposit(bytes32,uint32,uint256,bytes32)',
          live.depositRecipient, tokenIndex, String(depositAmount),
          '0x0000000000000000000000000000000000000000000000000000000000000000',
        ];
        if (tokenIndex === '0') castArgs.push('--value', String(depositAmount));
        castArgs.push(...l1SignerArgs(), '--rpc-url', RPC, '--json');
        const out = sh('cast', castArgs, { stdio: 'pipe' });
        depositTxHash = (out.match(/"transactionHash"\s*:\s*"(0x[0-9a-fA-F]{64})"/) || [])[1] || '';
        if (!depositTxHash) throw new Error('could not read the deposit transactionHash from cast output');

        // SECURITY: import by TX HASH — the CLI reads depositor/amount/tokenIndex from the
        // on-chain `Deposited` log.
        // OPERATOR-FUNDED: the deposit above is signed with the server's configured L1 signer, NOT the
        // joining delegate's wallet, so the on-chain depositor is the operator and is bound to no
        // slot. The flag relaxes only that leg; crediting a slot bound to a DIFFERENT member is
        // still refused unconditionally by the CLI.
        await importL1Deposit(ch, slot, depositTxHash, { allowUnboundDepositor: true });
        snapshot = readJson(wc(ch, 'channel_snapshot.json'));
        depositSucceeded = true;
      } catch (depErr) {
        console.error('deposit failed (channel joined with 0 balance):', depErr.message);
      }
    }

    res.json({
      snapshot,
      slot,
      balance: depositSucceeded ? String(depositAmount) : '0',
      depositSucceeded,
      depositTxHash,
      liveDepositRecipient: live.depositRecipient,
    });
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
  withLock(ch, async () => {
    await flushPublishedHead(ch);
    const tokenIndex = parseTokenIndex(req.body && req.body.tokenIndex);
    if (tokenIndex === null || tokenIndex === undefined || (req.body && req.body.tokenIndex === undefined)) {
      res.status(400).json({ error: 'needs { tokenIndex } (decimal u32)' });
      return;
    }
    // Signer-independent exit: the registration changes the token-funds digest, so its exit kit
    // is proved for the exact proposal before any member signature is released.
    await cliWithPreparedExitKit(ch, ['register-token', String(tokenIndex), 'token_register_cosigned.json']);
    const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    await publishOffchainSnapshot(ch, snapshot.state);
    res.json(snapshot);
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
