const { Router } = require('express');
const fs = require('fs');
const { cli, wc, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');
const { cliWithPreparedExitKit, installHeadExitKit } = require('../lib/exit-kit');
const producer = require('../lib/block-producer');
const preflight = require('../lib/deposit-preflight');
const { spendDeposit, importTrackedDeposit, depositResponse, failDeposit } = require('../lib/deposit-spend');
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
    preflight.resolveContributionSlot(snapshot, req.body);
    // The durable live-balance spine starts HERE (sole base-state authority): the daemon derives
    // and owns the account/deposit salts; the API only ever learns the deposit recipient.
    // Idempotent across restarts — an existing snapshot returns its configured recipient.
    const live = await producer.liveInit(ch);
    await producer.liveBindSnapshot(ch, snapshot);
    await require('../lib/live-registration').ensureLiveRegistration(ch, snapshot);
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
    await require('../lib/live-registration').ensureLiveRegistration(ch, snapshot);
    const slot = preflight.resolveContributionSlot(snapshot, contribution);
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
    const requestedAmount = req.body.depositAmount ?? '0';
    const depositAmount = String(requestedAmount) === '0' ? '0' : preflight.depositAmount(requestedAmount);
    const tokenIndex = preflight.tokenIndex(req.body.tokenIndex ?? 0);

    writeJson(wc(ch, 'contribution.json'), contribution);
    cli(ch, ['init', 'contribution.json', 'channel_snapshot.json']);
    let snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    const live = await producer.liveInit(ch);
    await producer.liveBindSnapshot(ch, snapshot);
    await require('../lib/live-registration').ensureLiveRegistration(ch, snapshot);
    const slot = preflight.resolveContributionSlot(snapshot, contribution);
    let completed = null;

    if (depositAmount && depositAmount !== '0') {
      const operation = await spendDeposit(ch, { recipientSlot: slot, amount: depositAmount,
        tokenIndex, requestId: req.body.requestId });
      completed = await importTrackedDeposit(ch, operation, slot);
      snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    }

    res.json({
      snapshot,
      slot,
      balance: completed ? depositAmount : '0',
      depositSucceeded: Boolean(completed),
      depositTxHash: completed && completed.operation.txHash,
      ...(completed ? depositResponse(completed.operation) : {}),
      liveDepositRecipient: live.depositRecipient,
    });
  }).catch(error => failDeposit(res, error));
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
    await installHeadExitKit(ch);
    res.json(snapshot);
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
