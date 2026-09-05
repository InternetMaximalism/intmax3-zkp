'use strict';
// Pre-sign exit-kit orchestration (api/lib/exit-kit.js): every asset-moving CLI signature is
// preceded by an exact proposal, a daemon-proved kit, and a signing run bound to that envelope;
// ambiguous signing failures retain the exact staged block for recovery.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-exit-kit-'));
process.env.INTMAX_WORK_DIR = work;

const cliModule = require('../../api/lib/cli');
const producer = require('../../api/lib/block-producer');
const events = [];

function write(ch, name, value) {
  const directory = path.join(work, `ch${ch}`);
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, name), JSON.stringify(value));
}
function read(ch, name) {
  return JSON.parse(fs.readFileSync(path.join(work, `ch${ch}`, name), 'utf8'));
}

let refuseSigning = false;
cliModule.chainId = () => 31337;
cliModule.cli = (ch, args, env) => {
  const proposing = args.includes('--propose-exit-kit');
  events.push({ cmd: args[0], args, proposing, env: env || null });
  if (proposing) {
    write(ch, 'exit_kit_proposal.json', {
      kind: args[0] === 'register-token' ? 'tokenRegister' : 'interChannelDebit',
      successor: { channelId: ch, digest: 'next' },
      proposedState: { channelId: ch, digest: 'next' },
      debitPayload: { proposedNextState: { digest: 'next' } },
      descriptor: { txHash: '0x' + '05'.repeat(32) },
    });
    return '';
  }
  if (refuseSigning) throw new Error('SIGNER-INDEPENDENT EXIT REQUIRED: injected refusal');
  return 'signed';
};
producer.livePrepareExitKit = async (ch, proposal) => {
  events.push({ prepare: proposal });
  return { signedHead: { channelId: ch, digest: 'next' }, signedHeadExitKit: { schemaVersion: 1 } };
};
producer.liveAbandonPreparedExitKit = async (ch, requestId) => {
  events.push({ abandon: requestId });
  return { ok: true };
};
producer.liveBackingArtifact = async (ch) => {
  events.push({ backing: ch });
  return { signedHead: { channelId: ch, digest: 'head' }, signedHeadExitKit: { schemaVersion: 1 } };
};

delete require.cache[require.resolve('../../api/lib/exit-kit')];
const exitKit = require('../../api/lib/exit-kit');

test.after(() => fs.rmSync(work, { recursive: true, force: true }));

test('a token registration is proposed, proved, then signed with the envelope bound', async () => {
  events.length = 0;
  write(7, 'channel_backing.json', { rollup: '0x' + '44'.repeat(20) });
  const out = await exitKit.cliWithPreparedExitKit(7, ['register-token', '7', 'out.json'], { X: '1' });
  assert.equal(out, 'signed');
  assert.equal(events[0].proposing, true);
  assert.deepEqual(events[0].env, { X: '1' });
  assert.equal(events[1].prepare.kind, 'tokenRegister');
  assert.equal(events[1].prepare.requestId, undefined, 'only debits stage a producer block');
  assert.equal(events[2].proposing, false);
  assert.equal(events[2].env.INTMAX_PREPARED_EXIT_KIT, 'prepared_exit_kit.json');
  assert.equal(events[2].env.X, '1');
  const envelope = read(7, 'prepared_exit_kit.json');
  assert.equal(envelope.schemaVersion, 3);
  assert.equal(envelope.source, 'liveBalanceService');
  assert.equal(envelope.chainId, 31337);
  assert.equal(envelope.rollup, '0x' + '44'.repeat(20));
  assert.equal(envelope.signedHead.digest, 'next');
});

test('a debit retains its exact kit and base nonce after an ambiguous signing failure', async () => {
  events.length = 0;
  write(8, 'channel_backing.json', { rollup: '0x' + '44'.repeat(20) });
  write(8, 'p.json', { proposedNextState: { digest: 'next' } });
  write(8, 'd.json', { txHash: 'burn' });
  await assert.rejects(
    exitKit.cliWithPreparedExitKit(8, ['cosign-burn-send', 'p.json', 'd.json', 'o.json'], null),
    /needs the producer request id/,
  );
  events.length = 0;
  refuseSigning = true;
  try {
    await assert.rejects(
      exitKit.cliWithPreparedExitKit(8, ['cosign-burn-send', 'p.json', 'd.json', 'o.json'], { CLI_BASE_TX_NONCE: '12' }, { requestId: 'burn:9' }),
      /injected refusal/,
    );
  } finally {
    refuseSigning = false;
  }
  assert.equal(events[1].prepare.kind, 'interChannelDebit');
  assert.equal(events[1].prepare.requestId, 'burn:9:exit-kit');
  assert.equal(events.length, 3);
  assert.ok(!events.some(e => e.abandon));
  assert.equal(read(8, exitKit.OPERATION_FILE).status, 'signing');
  await assert.rejects(
    exitKit.cliWithPreparedExitKit(8, ['cosign-burn-send', 'p.json', 'd.json', 'o.json'], null, { requestId: 'burn:10' }),
    /different pre-sign operation/,
  );

  events.length = 0;
  const out = await exitKit.cliWithPreparedExitKit(8, ['cosign-burn-send', 'p.json', 'd.json', 'o.json'], { CLI_BASE_TX_NONCE: '13' }, { requestId: 'burn:9' });
  assert.equal(out, 'signed');
  assert.equal(events.length, 1, 'exact retry neither reproposes nor reproves');
  assert.equal(events[0].env.CLI_BASE_TX_NONCE, '12', 'recovery keeps the original transaction nonce');
  assert.equal(read(8, exitKit.OPERATION_FILE).status, 'complete');
  assert.ok(!events.some((e) => e.abandon), 'a signed debit keeps its staged block for postInterChannel');
});

test('installHeadExitKit archives the live kit for the current head', async () => {
  events.length = 0;
  write(9, 'channel_backing.json', { rollup: '0x' + '44'.repeat(20) });
  await exitKit.installHeadExitKit(9);
  assert.deepEqual(events[0], { backing: 9 });
  assert.deepEqual(events[1].env, null);
  assert.equal(events[1].cmd, 'install-exit-kit');
  assert.equal(read(9, 'installed_exit_kit.json').signedHead.digest, 'head');
});

test('producer-accepted output closes a lost local signing acknowledgement without reproving', () => {
  write(10, exitKit.OPERATION_FILE, { schemaVersion: 1, status: 'signing',
    envelope: { signedHead: { channelId: 10, digest: 'accepted' } } });
  assert.equal(exitKit.acknowledgePreparedExitKit(10, { channelId: 10, digest: 'other' }), false);
  assert.equal(read(10, exitKit.OPERATION_FILE).status, 'signing');
  assert.equal(exitKit.acknowledgePreparedExitKit(10, { channelId: 10, digest: 'accepted' }), true);
  assert.equal(read(10, exitKit.OPERATION_FILE).status, 'complete');
});

test('an exact pre-upgrade pending inter transfer resumes its original argv without reproving or abandoning', async () => {
  const ch = 11;
  const legacyArgs = ['cosign-inter-transfer', 'p.json', 'd.json', 'o.json'];
  const requestId = 'inter:legacy';
  const upgradedArgs = [...legacyArgs, `--producer-request-id=${requestId}`];
  write(ch, 'channel_backing.json', { rollup: '0x' + '44'.repeat(20) });
  write(ch, 'p.json', { proposedNextState: { digest: 'next' } });
  write(ch, 'd.json', { txHash: 'inter' });
  refuseSigning = true;
  try {
    await assert.rejects(exitKit.cliWithPreparedExitKit(ch, legacyArgs,
      { INTMAX_LIVE_BASE_NONCE: '12' }, { requestId }), /injected refusal/);
  } finally {
    refuseSigning = false;
  }
  const pending = read(ch, exitKit.OPERATION_FILE);
  assert.equal(pending.status, 'signing');
  events.length = 0;
  write(ch, 'd.json', { txHash: 'different-intent' });
  await assert.rejects(exitKit.cliWithPreparedExitKit(ch, upgradedArgs, null, { requestId }), /different pre-sign operation/);
  write(ch, 'd.json', { txHash: 'inter' });
  await assert.rejects(exitKit.cliWithPreparedExitKit(ch,
    [...legacyArgs, '--producer-request-id=inter:other'], null, { requestId: 'inter:other' }), /different pre-sign operation/);
  assert.deepEqual(events, [], 'changed inputs or request id never reach the child');
  assert.equal(await exitKit.cliWithPreparedExitKit(ch, upgradedArgs,
    { INTMAX_LIVE_BASE_NONCE: '13' }, { requestId }), 'signed');
  assert.equal(events.length, 1, 'legacy exact retry does not re-propose, prove or abandon');
  assert.deepEqual(events[0].args, legacyArgs);
  assert.equal(events[0].env.INTMAX_LIVE_BASE_NONCE, '12');
  assert.equal(read(ch, exitKit.OPERATION_FILE).binding, pending.binding);
  assert.equal(read(ch, exitKit.OPERATION_FILE).status, 'complete');
});
