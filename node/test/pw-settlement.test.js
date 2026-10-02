'use strict';
// A partial withdrawal on a public chain is settled by the relay in the background: publish the
// producer history, submit the intent from the post-burn head, wait out the manager's challenge
// period, finalize the payout. Until the intent is on L1 the burn owns the channel head.
const test = require('node:test'), assert = require('node:assert/strict');
const { createPwSettlement } = require('../../hosting/wallet/pw-settlement');

function harness({ chainId = 11155111, failPublishOnce = false, timestamps = [500, 1000, 1001], recipient = '0xR' } = {}) {
  const calls = [], sleeps = [], locks = [];
  const tickets = { 7: { id: 'pw_1', type: 'partial_withdrawal', status: 'burn_done', params: { recipient: '0xr', amount: '5' }, steps: { burn: {} } } };
  let publishFailures = failPublishOnce ? 1 : 0, clock = 0;
  const auth = { manager: '0xm', auth_digest: '0xa', withdrawal_recipient: recipient };
  const cli = {
    DEVNET_CHAIN_ID: 31337, RPC: 'rpc', chainId: () => chainId, wc: (_ch, name) => name,
    readJson: (name) => { assert.equal(name, 'pw_auth.json'); return auth; },
    rollupOf: () => '0xrollup', l1SignerAddress: () => '0xoperator',
    cliAsync: async (ch, args, env) => { calls.push(['cli', ch, args[0], env]); },
    sh: (_bin, args) => {
      if (args[2] === 'pendingPartialWithdrawalDeadline()(uint64)') return '1000 [1e3]\n';
      if (args[0] === 'block') return String(timestamps[Math.min(clock++, timestamps.length - 1)]);
      if (args[1] === 'eth_blockNumber') return '"0x10"';
      throw new Error('unexpected cast ' + args.join(' '));
    },
  };
  const settlement = createPwSettlement({
    cli,
    producer: { liveBackingArtifact: async () => ({ signedHead: { digest: '0xh' } }) },
    walletL1: {
      publish: async (ch) => { calls.push(['publish', ch]); if (publishFailures-- > 0) throw new Error('rpc unavailable'); },
      attest: async (ch) => { calls.push(['attest', ch]); },
    },
    live: {
      resumeSubmittedAuth: () => null,
      stageSubmitProof: async () => ({ PW_BALANCE_PROOF_FILE: 'proof.bin' }),
      stagePayoutArtifacts: async () => { calls.push(['payout-artifacts']); },
      finalizeSavedPayout: async (ch, { run, env }) => run(ch, ['pw-finalize', 'rpc'], env),
    },
    pull: { pullTransaction: (a, rollup) => ({ to: rollup, recipient: a.withdrawal_recipient }) },
    withLock: (ch, fn, opts) => { locks.push([ch, opts && opts.owner]); return Promise.resolve().then(fn); },
    findActiveTicket: (ch) => (tickets[ch] && !['settle_done'].includes(tickets[ch].status) ? tickets[ch] : null),
    upsertTicket: (ch, t) => { tickets[ch] = JSON.parse(JSON.stringify(t)); return t; },
    sleep: async (ms) => { sleeps.push(ms); }, log: { error() {} }, retryMs: 300000, pollMs: 60000,
  });
  return { settlement, tickets, calls, sleeps, locks };
}

test('the burn owns the channel until its intent is submitted, then only the payout remains', () => {
  const h = harness();
  const frozen = () => h.settlement.frozen(7);
  assert.equal(frozen().id, 'pw_1', 'burned, not yet settling');
  for (const [phase, held] of [['publishing', true], ['submitting', true], ['challenge', false], ['finalizing', false]]) {
    h.tickets[7].status = 'settle_pending';
    h.tickets[7].steps.settle = { phase };
    assert.equal(!!frozen(), held, phase);
  }
  h.tickets[7].status = 'claim_pending';
  assert.equal(frozen(), null);
  assert.equal(h.settlement.frozen(8), null);
});

test('a deployment that cannot settle withdrawals never freezes or settles a saved burn', () => {
  const h = harness();
  const disabled = createPwSettlement({ cli: {}, findActiveTicket: () => h.tickets[7], enabled: () => false });
  assert.equal(disabled.frozen(7), null);
  assert.equal(disabled.start(7), null);
});

test('the background settlement runs every phase to a receivable payout', async () => {
  const h = harness();
  await h.settlement.start(7);
  const t = h.tickets[7];
  assert.equal(t.status, 'claim_pending');
  assert.deepEqual(t.params.claim, { to: '0xrollup', recipient: '0xR', afterBlock: '0x10' });
  assert.equal(t.steps.settle.phase, 'done');
  assert.equal(t.steps.settle.deadline, 1000);
  assert.deepEqual(h.calls.map(c => c.slice(0, 3)), [
    ['publish', 7], ['attest', 7], ['cli', 7, 'pw-submit'], ['payout-artifacts'], ['cli', 7, 'pw-finalize']]);
  const submit = h.calls.find(c => c[2] === 'pw-submit')[3];
  assert.deepEqual(submit, { PW_RECIPIENT: '0xr', PW_BALANCE_PROOF_FILE: 'proof.bin' }, 'no Anvil mining off the devnet');
  assert.deepEqual(h.locks, [[7, 'pw_1'], [7, 'pw_1']], 'submit and finalize hold the channel as the burn owner');
  // The challenge period is waited on L1 block time: 500 and 1000 are not past the deadline.
  assert.deepEqual(h.sleeps, [60000, 1000]);
});

test('a failed step is recorded on the ticket and retried, never dropped', async () => {
  const h = harness({ failPublishOnce: true });
  await h.settlement.start(7);
  assert.equal(h.tickets[7].status, 'claim_pending');
  assert.equal(h.calls.filter(c => c[0] === 'publish').length, 2);
  assert.equal(h.sleeps[0], 300000, 'retried after the retry interval');
  assert.equal(h.tickets[7].steps.settle.attempts, 1);
});

test('an interrupted settlement resumes at its recorded phase', async () => {
  const h = harness({ timestamps: [2000] });
  h.tickets[7].status = 'settle_pending';
  h.tickets[7].steps.settle = { phase: 'challenge', deadline: 1000 };
  h.settlement.resumeAll([7, 8]);
  assert.equal(h.settlement.running(7), true);
  await h.settlement.start(7);
  assert.deepEqual(h.calls.map(c => c[0] === 'cli' ? c[2] : c[0]), ['payout-artifacts', 'pw-finalize']);
  assert.equal(h.tickets[7].status, 'claim_pending');
});

test('the operator paid directly ends settled, with nothing for a wallet to pull', async () => {
  const h = harness({ recipient: '0xOPERATOR' });
  h.tickets[7].status = 'settle_pending';
  h.tickets[7].steps.settle = { phase: 'finalizing' };
  await h.settlement.start(7);
  assert.equal(h.tickets[7].status, 'settle_done');
  assert.equal(h.tickets[7].params.claim, null);
});

test('on the devnet the CLI mines its own finality', async () => {
  const h = harness({ chainId: 31337 });
  await h.settlement.publish(7);
  await h.settlement.submit(7, h.tickets[7]);
  assert.equal(h.calls.find(c => c[2] === 'pw-submit')[3].INTMAX_WALLET_ANVIL_MINE, '1');
});

test('a step waiting for L1 finality is retried a poll later and is not reported as a failure', async () => {
  const tickets = { 7: { id: 'pw_1', type: 'partial_withdrawal', status: 'burn_done', params: {}, steps: {} } };
  const sleeps = [];
  let seen = null;
  const settlement = createPwSettlement({
    cli: { DEVNET_CHAIN_ID: 31337, RPC: 'rpc', chainId: () => 11155111 },
    // The CLI stops, journal intact, while its transaction is above the finalized head.
    walletL1: { publish: async () => { throw Object.assign(new Error('exit status 1'), { stderr: 'error: transaction 0xab is canonical but not finalized yet: retry after the finalized head advances' }); } },
    findActiveTicket: (ch) => (tickets[ch].status === 'settle_done' ? null : tickets[ch]),
    upsertTicket: (ch, t) => { tickets[ch] = JSON.parse(JSON.stringify(t)); return t; },
    // Inspect the ticket at the wait, then end the run.
    sleep: async (ms) => { sleeps.push(ms); seen = tickets[7].steps.settle; tickets[7].status = 'settle_done'; },
    log: { error() { throw new Error('a finality wait was logged as a failure'); } },
    retryMs: 300000, pollMs: 60000,
  });
  await settlement.start(7);
  assert.deepEqual(sleeps, [60000], 'retried after a poll, not the failure retry interval');
  assert.equal(seen.waiting, 'L1 finality');
  assert.equal(seen.error, null);
  assert.equal(seen.phase, 'publishing');
});
