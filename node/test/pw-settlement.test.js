'use strict';
// A partial withdrawal (burn) is paid on L1 by its base withdrawal proof alone. The relay settles
// it in three phases: `proving` (the payout proof, anchored at the head a validity candidate ends
// at), `publishing` (that candidate, until the anchor's root is finalized on the rollup) and
// `paying` (the native payout). The channel is never held meanwhile.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { createPwSettlement } = require('../../hosting/wallet/pw-settlement');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-settlement-'));
test.after(() => fs.rmSync(root, { recursive: true, force: true }));
let dirs = 0;

const RECIPIENT = '0x00000000000000000000000000000000000000Ab';
const OPERATOR = '0x00000000000000000000000000000000000000Ef';
const ANCHOR_ROOT = '0x' + '5a'.repeat(32);
const CANDIDATE_PENDING = Object.assign(new Error('exit status 1'),
  { stderr: 'error: validity candidate pending L1 acknowledgement (candidate 0x12): publish it first' });
const NOT_FINAL = Object.assign(new Error('exit status 1'),
  { stderr: 'error: transaction 0xab is canonical but not finalized yet: retry after the finalized head advances' });

// The daemon's payout artifacts: the claim is built from THEIR withdrawal, never the ticket.
function payoutArtifacts(recipient = RECIPIENT.toLowerCase()) {
  return { withdrawal: { amount: '18446744073709551615', tokenIndex: 55, recipient, nullifier: '0xnf', auxData: '0xaux' },
    withdrawalProver: OPERATOR.toLowerCase(), producerAnchor: { blockNumber: 9, generation: 10, extendedStateCommitment: ANCHOR_ROOT } };
}

// `stage`, `publish`: per-call behaviors (a function, or an Error to throw), the last one repeats.
// `finalized`: the successive answers of isFinalizedStateRoot, the last one repeats.
function harness({ chainId = 11155111, operator = OPERATOR, artifacts = payoutArtifacts(), ticket = {},
  stage = [], publish = [], finalized = [true], pay = [], savedArtifacts = false, background, onSleep, onPublish } = {}) {
  const dir = path.join(root, String(++dirs));
  const calls = [], sleeps = [], errors = [], phases = [];
  let lockDepth = 0;
  const tickets = { 7: { id: 'pw_1', type: 'partial_withdrawal', status: 'burn_done',
    params: { recipient: '0xticket-recipient', amount: '5', tokenIndex: '0' }, steps: { burn: {}, settle: null }, ...ticket } };
  const nth = (list, i) => list[Math.min(i, list.length - 1)];
  const behave = (list, i) => { const b = list.length ? nth(list, i) : null; if (b instanceof Error) throw b; if (typeof b === 'function') b(); };
  let stages = 0, publishes = 0, reads = 0, pays = 0;
  const cli = {
    DEVNET_CHAIN_ID: 31337, RPC: 'rpc', chainId: () => chainId,
    wc: (ch, name) => path.join(dir, String(ch), name),
    readJson: file => JSON.parse(fs.readFileSync(file, 'utf8')),
    rollupOf: ch => '0xrollup' + ch, l1SignerAddress: () => operator,
    cliAsync: async (ch, args, env) => { calls.push(['cli', ch, args[0], env]); },
    sh: (bin, args) => {
      assert.equal(bin, 'cast');
      if (args[0] === 'call' && args[2] === 'isFinalizedStateRoot(bytes32)(bool)') {
        assert.deepEqual(args, ['call', '0xrollup7', 'isFinalizedStateRoot(bytes32)(bool)', ANCHOR_ROOT, '--rpc-url', 'rpc']);
        calls.push(['finalized?']);
        return String(nth(finalized, reads++)) + '\n';
      }
      if (args[0] === 'rpc' && args[1] === 'eth_blockNumber') return '"0x10"\n';
      throw new Error('unexpected cast ' + args.join(' '));
    },
  };
  const writeArtifacts = ch => {
    fs.mkdirSync(path.join(dir, String(ch)), { recursive: true });
    fs.writeFileSync(cli.wc(ch, 'pw_artifacts.json'), JSON.stringify(artifacts));
  };
  if (savedArtifacts) writeArtifacts(7);
  const settlement = createPwSettlement({
    cli,
    walletL1: { publish: async (ch, opts) => {
      calls.push(['publish', ch, opts]);
      if (onPublish) onPublish(tickets[ch]);
      behave(publish, publishes++);
    } },
    live: {
      stagePayoutArtifacts: async ch => {
        calls.push(['stage', ch, { locked: lockDepth > 0 }]);
        behave(stage, stages++);
        writeArtifacts(ch);
        return artifacts;
      },
      // The saved proof of THIS burn (the relay never trusts a file left by an earlier burn).
      savedPayoutArtifacts: ch => (fs.existsSync(cli.wc(ch, 'pw_artifacts.json'))
        ? JSON.parse(fs.readFileSync(cli.wc(ch, 'pw_artifacts.json'), 'utf8')) : null),
      finalizeSavedPayout: async (ch, { rpc, run, env }) => {
        calls.push(['payout', ch, { locked: lockDepth > 0 }]);
        behave(pay, pays++);
        return run(ch, ['pw-finalize', rpc], env);
      },
    },
    pull: { pullTransaction: (withdrawal, rollup) => {
      calls.push(['pull', withdrawal, rollup]);
      return { to: rollup, recipient: withdrawal.withdrawal_recipient, amount: withdrawal.withdrawal_amount, tokenIndex: withdrawal.withdrawal_token_index };
    } },
    withLock: async (ch, fn) => { lockDepth++; try { return await fn(); } finally { lockDepth--; } },
    findActiveTicket: (ch, type) => {
      assert.equal(type, 'partial_withdrawal');
      const t = tickets[ch];
      return t && !['settle_done', 'abandoned'].includes(t.status) ? t : null;
    },
    upsertTicket: (ch, t) => {
      const phase = t.steps && t.steps.settle && t.steps.settle.phase;
      if (phase && phases[phases.length - 1] !== phase) phases.push(phase);
      tickets[ch] = JSON.parse(JSON.stringify(t));
      return t;
    },
    sleep: async ms => { sleeps.push(ms); if (onSleep) onSleep(tickets[7]); },
    log: { error: message => errors.push(message) },
    retryMs: 300000, pollMs: 60000,
    ...(background ? { background } : {}),
  });
  return { settlement, tickets, calls, sleeps, errors, phases, kinds: () => calls.map(c => c[0]) };
}

test('the settlement exposes no channel freeze, and a deployment that cannot settle withdrawals settles nothing', () => {
  const h = harness();
  assert.deepEqual(Object.keys(h.settlement).sort(), ['resumeAll', 'running', 'settleNow', 'start']);
  const disabled = createPwSettlement({ cli: {}, findActiveTicket: () => h.tickets[7], enabled: () => false });
  assert.equal(disabled.start(7), null);
  disabled.resumeAll([7]);
  assert.equal(disabled.running(7), false);
});

test('the background settlement proves, publishes and pays, in that order, to a receivable payout', async () => {
  const h = harness();
  await h.settlement.start(7);
  assert.deepEqual(h.calls, [
    ['stage', 7, { locked: true }],
    ['publish', 7, { prove: false }],
    ['finalized?'],
    ['payout', 7, { locked: true }],
    ['cli', 7, 'pw-finalize', {}],
    ['pull', { withdrawal_amount: '18446744073709551615', withdrawal_token_index: 55, withdrawal_recipient: RECIPIENT.toLowerCase() }, '0xrollup7'],
  ]);
  assert.deepEqual(h.phases, ['proving', 'publishing', 'paying', 'done']);
  const t = h.tickets[7];
  assert.equal(t.status, 'claim_pending');
  assert.deepEqual(t.params.claim, { to: '0xrollup7', recipient: RECIPIENT.toLowerCase(), amount: '18446744073709551615', tokenIndex: 55, afterBlock: '0x10' },
    'the claim pays the proof\'s withdrawal (amount, token, recipient), not the ticket\'s');
  assert.equal(t.steps.settle.phase, 'done');
  assert.equal(t.steps.settle.nullifier, '0xnf');
  assert.equal(t.steps.settle.error, null);
  assert.equal(t.steps.settle.waiting, null);
  assert.ok(t.steps.settle.startedAt && t.steps.settle.completedAt);
  assert.deepEqual(h.sleeps, []);
  assert.deepEqual(h.errors, []);
  assert.equal(h.settlement.running(7), false);
});

test('the operator paid directly ends settle_done, with nothing for a wallet to pull', async () => {
  // The proof pays the operator's own address (any case): the payout credits it directly.
  const h = harness({ artifacts: payoutArtifacts(OPERATOR.toUpperCase().replace('0X', '0x')) });
  await h.settlement.start(7);
  assert.equal(h.tickets[7].status, 'settle_done');
  assert.equal(h.tickets[7].params.claim, null);
  assert.equal(h.tickets[7].steps.settle.phase, 'done');
  assert.equal(h.tickets[7].steps.settle.nullifier, '0xnf');
  assert.equal(h.kinds().includes('pull'), false);
});

test('a claim already built is kept, not pulled again', async () => {
  const claim = { to: '0xrollup7', recipient: 'saved' };
  const h = harness({ ticket: { status: 'settle_pending', params: { claim }, steps: { settle: { phase: 'paying' } } }, savedArtifacts: true });
  await h.settlement.start(7);
  assert.equal(h.tickets[7].status, 'claim_pending');
  assert.deepEqual(h.tickets[7].params.claim, claim);
  assert.equal(h.kinds().includes('pull'), false);
});

test('an older validity candidate pending on L1 is published without proving a new one, then the payout is proven again', async () => {
  let seen = null;
  // Inspect the ticket while that older candidate is being published.
  const h = harness({ stage: [CANDIDATE_PENDING, null], onPublish: t => { if (!seen) seen = { ...t.steps.settle }; } });
  await h.settlement.start(7);
  assert.deepEqual(h.calls.map(c => c[0] === 'publish' ? ['publish', c[2]] : [c[0]]).slice(0, 5), [
    ['stage'], ['publish', { prove: false }], ['stage'], ['publish', { prove: false }], ['finalized?']]);
  assert.equal(seen.phase, 'proving');
  assert.equal(seen.waiting, 'an earlier validity batch on L1');
  assert.equal(seen.error, null);
  assert.equal(h.tickets[7].status, 'claim_pending');
  assert.deepEqual(h.sleeps, [], 'not a failure: no retry interval');
  assert.deepEqual(h.errors, []);
  assert.equal(h.tickets[7].steps.settle.attempts, undefined);
});

test('a candidate still pending right after it was published is waited for a poll, not spun on', async () => {
  const h = harness({ stage: [CANDIDATE_PENDING, CANDIDATE_PENDING, CANDIDATE_PENDING, null] });
  await h.settlement.start(7);
  assert.equal(h.calls.filter(c => c[0] === 'publish' && c[2].prove === false).length >= 3, true);
  assert.deepEqual(h.sleeps, [60000, 60000], 'the first pending publishes at once; each later one waits a poll');
  assert.equal(h.tickets[7].status, 'claim_pending');
});

test('two Step 2 requests on the devnet join one settlement rather than paying twice', async () => {
  const h = harness({ chainId: 31337 });
  const [a, b] = await Promise.all([h.settlement.settleNow(7), h.settlement.settleNow(7)]);
  assert.equal(a, b);
  assert.equal(h.calls.filter(c => c[0] === 'payout').length, 1);
});

test('publishing waits, a poll at a time, until the payout anchor\'s root is finalized on the rollup', async () => {
  const seen = [];
  const h = harness({ finalized: [false, false, true], onSleep: t => seen.push({ ...t.steps.settle }) });
  await h.settlement.start(7);
  assert.deepEqual(h.kinds(), ['stage', 'publish', 'finalized?', 'publish', 'finalized?', 'publish', 'finalized?', 'payout', 'cli', 'pull']);
  assert.ok(h.calls.filter(c => c[0] === 'publish').every(c => c[2].prove === false), 'publishing never proves a new candidate');
  assert.deepEqual(h.sleeps, [60000, 60000]);
  for (const s of seen) {
    assert.equal(s.phase, 'publishing');
    assert.equal(s.waiting, 'L1 finality');
    assert.equal(s.error, null);
  }
  assert.deepEqual(h.errors, []);
  assert.equal(h.tickets[7].status, 'claim_pending');
});

test('a step waiting for L1 finality is retried a poll later and is not reported as a failure', async () => {
  let seen = null;
  const h = harness({ ticket: { status: 'settle_pending', steps: { settle: { phase: 'publishing' } } }, savedArtifacts: true,
    publish: [NOT_FINAL, null], onSleep: t => { seen = { ...t.steps.settle }; } });
  await h.settlement.start(7);
  assert.deepEqual(h.sleeps, [60000], 'retried after a poll, not the failure retry interval');
  assert.equal(seen.waiting, 'L1 finality');
  assert.equal(seen.error, null);
  assert.equal(seen.phase, 'publishing');
  assert.deepEqual(h.errors, []);
  assert.equal(h.tickets[7].status, 'claim_pending');
});

test('a failed step is recorded on the ticket and retried after the retry interval, never dropped', async () => {
  let seen = null;
  const h = harness({ stage: [new Error('rpc unavailable'), null], onSleep: t => { seen = { ...t.steps.settle }; } });
  await h.settlement.start(7);
  assert.deepEqual(h.sleeps, [300000]);
  assert.equal(seen.phase, 'proving');
  assert.equal(seen.error, 'rpc unavailable');
  assert.equal(seen.attempts, 1);
  assert.equal(h.errors.length, 1);
  assert.match(h.errors[0], /channel 7 proving: rpc unavailable/);
  assert.equal(h.kinds().filter(k => k === 'stage').length, 2);
  assert.equal(h.tickets[7].status, 'claim_pending');
  assert.equal(h.tickets[7].steps.settle.error, null);
});

test('an interrupted settlement resumes at its recorded phase', async () => {
  for (const [phase, expected] of [
    ['publishing', ['publish', 'finalized?', 'payout', 'cli', 'pull']],
    ['paying', ['payout', 'cli', 'pull']],
  ]) {
    const h = harness({ ticket: { status: 'settle_pending', steps: { settle: { phase } } }, savedArtifacts: true });
    h.settlement.resumeAll([7, 8]);
    assert.equal(h.settlement.running(7), true, phase);
    assert.equal(h.settlement.running(8), false, 'a channel without a withdrawal is not driven');
    await h.settlement.start(7);
    assert.deepEqual(h.kinds(), expected, phase);
    assert.equal(h.tickets[7].status, 'claim_pending', phase);
  }
});

test('a ticket recorded by the earlier settlement flow restarts at proving', async () => {
  // submitting / challenge / finalizing were the manager flow's phases; undefined is a ticket
  // whose settlement never started.
  for (const settle of [{ phase: 'submitting' }, { phase: 'challenge', deadline: 1000, authDigest: '0xa' }, { phase: 'finalizing' }, { phase: 'starting' }, {}]) {
    const h = harness({ ticket: { status: 'settle_pending', steps: { settle } }, savedArtifacts: true });
    await h.settlement.start(7);
    assert.equal(h.kinds()[0], 'stage', JSON.stringify(settle));
    assert.deepEqual(h.phases, ['proving', 'publishing', 'paying', 'done'], JSON.stringify(settle));
    assert.equal(h.tickets[7].status, 'claim_pending');
  }
});

test('a later phase without its saved payout proof restarts at proving', async () => {
  for (const phase of ['publishing', 'paying']) {
    const h = harness({ ticket: { status: 'settle_pending', steps: { settle: { phase } } } });
    await h.settlement.start(7);
    assert.equal(h.kinds()[0], 'stage', phase);
    assert.equal(h.tickets[7].status, 'claim_pending');
  }
});

test('a ticket that is not settling is left alone', async () => {
  for (const status of ['burn_pending', 'claim_pending']) {
    const h = harness({ ticket: { status } });
    assert.equal((await h.settlement.settleNow(7)).status, status);
    await h.settlement.start(7);
    assert.deepEqual(h.calls, [], status);
  }
  const none = harness();
  delete none.tickets[7];
  assert.equal(await none.settlement.settleNow(7), null);
  assert.deepEqual(none.calls, []);
});

test('start is idempotent per channel', async () => {
  const h = harness();
  const first = h.settlement.start(7);
  assert.equal(h.settlement.start(7), first);
  assert.equal(h.settlement.running(7), true);
  await first;
  assert.equal(h.settlement.running(7), false);
  assert.equal(h.kinds().filter(k => k === 'stage').length, 1);
});

test('on the devnet Step 2 settles in the request: the same phases, the CLI mining its own finality', async () => {
  const h = harness({ chainId: 31337, background: () => false });
  assert.equal(h.settlement.start(7), null, 'no background driver on the devnet');
  const ticket = await h.settlement.settleNow(7);
  assert.equal(ticket.status, 'claim_pending');
  assert.deepEqual(ticket.params.claim, h.tickets[7].params.claim);
  assert.deepEqual(h.kinds(), ['stage', 'publish', 'finalized?', 'payout', 'cli', 'pull']);
  assert.deepEqual(h.calls.find(c => c[0] === 'cli')[3], { INTMAX_WALLET_ANVIL_MINE: '1' });
});

test('on the devnet the first failure is reported to the request, recorded, and not retried', async () => {
  const h = harness({ chainId: 31337, background: () => false, stage: [Object.assign(new Error('exit status 1'), { stderr: 'native proof failed' }), null] });
  await assert.rejects(h.settlement.settleNow(7), e => /native proof failed/.test(e.stderr));
  assert.deepEqual(h.sleeps, []);
  assert.equal(h.tickets[7].status, 'settle_pending');
  assert.equal(h.tickets[7].steps.settle.error, 'native proof failed');
  assert.equal(h.tickets[7].steps.settle.attempts, 1);
  // Step 2 again resumes the saved ticket.
  const ticket = await h.settlement.settleNow(7);
  assert.equal(ticket.status, 'claim_pending');
  assert.equal(h.tickets[7].steps.settle.error, null);
});

test('a payout failure keeps the ticket in paying with its saved proof, for the retry', async () => {
  const h = harness({ chainId: 31337, background: () => false, pay: [new Error('payout reverted'), null] });
  await assert.rejects(h.settlement.settleNow(7), /payout reverted/);
  assert.equal(h.tickets[7].steps.settle.phase, 'paying');
  assert.equal(h.tickets[7].status, 'settle_pending');
  await h.settlement.settleNow(7);
  assert.deepEqual(h.kinds().filter(k => k === 'stage'), ['stage'], 'the saved payout proof is not proven again');
  assert.equal(h.tickets[7].status, 'claim_pending');
});
