'use strict';

// `setup-backing` funds a channel's genesis BEFORE the live balance service exists: it derives its
// own deposit salt/recipient, sends the L1 deposit and proves the balance itself. The live service
// then initializes at an EMPTY proof, so its settle chain and the signed snapshot's disagree —
// and `bind_signed_snapshot` compares exactly those two. Without adopting the backing deposit
// first, that pair is rejected for ever ("signed snapshot settle chain differs from the pending
// live balance proof"), which in turn means no exit kit can ever be proved and every deposit
// import fails closed.
//
// These tests pin the adoption step and, crucially, its ORDER: the backing deposit must be
// inspected, journaled and consumed into the live proof, then bound, before the import proceeds.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-backing-adoption-'));
process.env.INTMAX_WORK_DIR = work;

const cliModule = require('../../api/lib/cli');
const producer = require('../../api/lib/block-producer');
const producerHead = require('../../api/lib/producer-head');
const exitKit = require('../../api/lib/exit-kit');
// The registration boundary itself is exercised by l1-registration tests.
require('../../api/lib/live-registration').ensureLiveRegistration = async (_ch, snapshot) => producer.register(snapshot);

const CH = 7;
const TX = '0x' + 'ab'.repeat(32);
const BACKING_TX = '0x' + 'cd'.repeat(32);
const BACKING_SALT = '0x' + 'ee'.repeat(32);
const BACKING_CHAIN = '0x' + '77'.repeat(32);
const ACCOUNT_SALT = '0x' + '99'.repeat(32);

function write(ch, name, value) {
  const directory = path.join(work, `ch${ch}`);
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, name), JSON.stringify(value));
}

// `events` records the exact sequence the pipeline drives, across both the CLI and the daemon.
let events = [];
let liveSettled = '';

// Stubs are installed BEFORE deposit-pipeline is required: it destructures `cli`/`flushPublishedHead`
// at require time, so a later assignment would not be seen (same reason the existing
// api-deposit-live-binding test re-requires the module).
cliModule.chainId = () => 31337;
cliModule.cli = (ch, args) => {
  events.push(args[0] === 'inspect-l1-deposit' ? `inspect:${args[1]}` : args[0]);
  if (args[0] === 'inspect-l1-deposit') write(ch, args[3], { depositIndex: 1, tx: args[1] });
  if (args[0] === 'cosign-l1-deposit-import') {
    write(ch, 'l1_import_cosigned.json', {
      txHash: TX, intmaxBlockNumber: 11,
      fundImportState: { digest: 'fund' }, bundleApplyState: { digest: 'bundle' },
    });
  }
  return '';
};
let liveExists = false;
producer.liveSnapshotExists = () => liveExists;
producer.liveInit = async () => { events.push('liveInit'); liveExists = true; return { depositRecipient: '0x00' }; };
producer.liveInitWithAccountSalt = async (ch, salt) => {
  events.push('liveInitWithAccountSalt');
  assert.equal(salt, ACCOUNT_SALT, 'the live balance must be put on the account setup-backing made');
  liveExists = true;
  return {};
};
let liveApplied = 0;
let liveAwaitingBind = false;
producer.liveStatus = async () => ({ settledTxChain: liveSettled, appliedTransitionCount: liveApplied, awaitingChannelBinding: liveAwaitingBind });
let registeredChannels = [];
producer.status = async () => ({ channelHeads: registeredChannels.map((c) => ({ channelId: c })) });
producer.register = async () => { events.push('register'); registeredChannels.push(CH); return {}; };
producer.postDeposit = async (deposit) => {
  events.push(`postDeposit:${deposit.tx === BACKING_TX ? 'backing' : 'user'}`);
  return { blockNumber: 11, requestId: 'r', generation: 1 };
};
// One account, one deposit recipient: the backing deposit AND every browser deposit land on it,
// so both are received by naming that salt.
producer.liveReceiveBackingDeposit = async (ch, receipt, deposit, salt) => {
  const which = deposit.tx === BACKING_TX ? 'backing' : 'user';
  events.push(`liveReceive:${which}`);
  assert.equal(salt, BACKING_SALT, 'receives must name the salt setup-backing recorded');
  // Consuming the backing deposit is what walks the live proof to the snapshot's settle chain.
  if (which === 'backing') liveSettled = BACKING_CHAIN;
  liveApplied += 1;
  liveAwaitingBind = true;
  return { ok: true };
};
producer.liveReceiveConfiguredDeposit = async () => { events.push('liveReceiveConfiguredDeposit'); return {}; };
producer.liveBindSnapshot = async () => { events.push('liveBindSnapshot'); liveAwaitingBind = false; return {}; };
producer.syncOffchainHeads = async () => { events.push('syncOffchainHeads'); return {}; };
producerHead.flushPublishedHead = async () => {};
// The exit-kit dance itself is covered by api-exit-kit.test.js; keep it out of the way here.
exitKit.cliWithPreparedExitKit = async (ch, args) => cliModule.cli(ch, args);
exitKit.acknowledgePreparedExitKit = () => false;
// importL1Deposit installs the new head's exit-kit receipt at the end (so a later refresh/send can
// spend). Stub it: the real one calls producer.liveBackingArtifact + `install-exit-kit`, which would
// otherwise spawn a real daemon here.
exitKit.installHeadExitKit = async () => { events.push('installHeadExitKit'); };

delete require.cache[require.resolve('../../api/lib/deposit-pipeline')];
const { importL1Deposit } = require('../../api/lib/deposit-pipeline');

function reset(backing) {
  events = [];
  liveSettled = '';
  liveExists = false;
  liveApplied = 0;
  liveAwaitingBind = false;
  registeredChannels = [];
  fs.rmSync(path.join(work, `ch${CH}`), { recursive: true, force: true });
  write(CH, 'channel_backing.json', backing);
  write(CH, 'channel_snapshot.json', { record: { channelId: CH }, state: { digest: 'head' } });
}

const FUNDED = {
  rollup: '0x' + '44'.repeat(20),
  settled_tx_chain: BACKING_CHAIN,
  deposit_salt: BACKING_SALT,
  deposit_tx: BACKING_TX,
  base_private_state: { salt: ACCOUNT_SALT },
};

test('a funded genesis is adopted into the live proof, and bound, before the import proceeds', async () => {
  reset(FUNDED);

  await importL1Deposit(CH, 3, TX, { allowUnboundDepositor: false });

  // The backing deposit is inspected, journaled and consumed, then bound — and all of that
  // happens BEFORE the user's own deposit, or the live service refuses the transition.
  const adopt = events.indexOf('liveReceive:backing');
  const bind = events.indexOf('liveBindSnapshot');
  const userInspect = events.indexOf(`inspect:${TX}`);
  assert.ok(adopt >= 0, `the backing deposit must be adopted; saw ${events.join(' -> ')}`);
  assert.ok(events.indexOf(`inspect:${BACKING_TX}`) < adopt, 'the backing deposit is inspected first');
  assert.ok(events.indexOf('postDeposit:backing') < adopt, 'it is journaled before it is consumed');
  assert.ok(bind > adopt, 'adoption is only complete once the proof is bound');
  assert.ok(userInspect > bind, 'the user import runs after the live proof is ready');
});

test('an existing live balance is never re-created: liveInit is a CREATE, not an ensure', async () => {
  reset(FUNDED);
  liveExists = true;   // a live balance is already on disk from an earlier import
  liveSettled = BACKING_CHAIN;

  await importL1Deposit(CH, 3, TX, { allowUnboundDepositor: false });

  // `liveInit`'s idempotent branch demands an UNCONSUMED configured deposit recipient, and
  // adopting a deposit consumes exactly that — so calling it again fails with "live balance
  // exists but has no configured deposit recipient" and bricks every subsequent import.
  assert.ok(!events.includes('liveInitWithAccountSalt') && !events.includes('liveInit'),
    `the live balance must not be re-created; saw ${events.join(' -> ')}`);
});

test('the backing deposit is journaled BEFORE the channel is registered', async () => {
  reset(FUNDED);

  await importL1Deposit(CH, 3, TX, { allowUnboundDepositor: false });

  // This order is load-bearing, not cosmetic. The producer stamps a journaled deposit with
  // `block_number = block_number + 1`, and that number is hashed into `Deposit::nullifier()`,
  // which is the leaf pushed onto `settled_tx_chain`. `setup-backing` proves the genesis against
  // a fresh generator, so its deposit sits in block 1 — registering the channel first consumes
  // block 1 and pushes the deposit to block 2, giving a different nullifier and a settle chain
  // that can never match the signed snapshot. Measured while fixing it: CLI index 0/block 1 vs
  // producer index 0/block 2, which is exactly one registration block of drift.
  const journaled = events.indexOf('postDeposit:backing');
  const registered = events.indexOf('register');
  assert.ok(journaled >= 0, `the backing deposit must be journaled; saw ${events.join(' -> ')}`);
  assert.ok(registered >= 0, 'an unregistered channel must still end up registered');
  assert.ok(journaled < registered,
    `the deposit must take the producer's first block; saw ${events.join(' -> ')}`);
});

test('a consumed-but-unbound channel is RESUMED (register + bind), not re-journaled', async () => {
  reset(FUNDED);
  // Simulate the exact crash that bricked a real run: an earlier import consumed the backing
  // deposit into the live balance, then died before binding (its channel_snapshot was missing).
  liveExists = true;
  liveApplied = 1;
  liveAwaitingBind = true;
  liveSettled = BACKING_CHAIN;

  await importL1Deposit(CH, 3, TX, { allowUnboundDepositor: false });

  // It must NOT re-journal the backing deposit (that would double it)...
  assert.ok(!events.includes('liveReceive:backing'), 'must not re-consume the backing deposit');
  assert.ok(!events.includes(`inspect:${BACKING_TX}`), 'must not re-inspect it');
  // ...but it MUST finish the job: register the channel and bind. The old code returned early on
  // appliedTransitionCount>0 alone, leaving the channel unregistered for ever.
  assert.ok(events.includes('register'), `must register the resumed channel; saw ${events.join(' -> ')}`);
  assert.ok(events.includes('liveBindSnapshot'), 'must bind the resumed channel');
});

test('a fully-adopted channel whose producer journal lacks the registration is re-registered', async () => {
  reset(FUNDED);
  liveExists = true;
  liveApplied = 1;
  liveAwaitingBind = false;   // fully adopted + bound in the live balance...
  liveSettled = BACKING_CHAIN;
  // ...but the producer journal has NO registration (the two are separate durable stores and can
  // drift). Registration is ensured on every path, or later imports die "not registered".
  registeredChannels = [];

  await importL1Deposit(CH, 3, TX, { allowUnboundDepositor: false });

  assert.ok(!events.includes('liveReceive:backing'), 'must not re-consume the backing deposit');
  assert.ok(events.includes('register'), `must register the drifted channel; saw ${events.join(' -> ')}`);
});

test('adoption is idempotent once anything has been consumed, even after the chain moves on', async () => {
  reset(FUNDED);
  liveExists = true;
  liveApplied = 1;                      // fully adopted by an earlier import...
  liveAwaitingBind = false;             // ...and bound
  liveSettled = '0x' + 'be'.repeat(32); // later imports have since moved the chain past it
  registeredChannels = [CH];            // and already registered in the producer journal

  await importL1Deposit(CH, 3, TX, { allowUnboundDepositor: false });

  // Keying idempotence on "settle chain == genesis backing chain" looked equivalent but broke
  // exactly here: the first import moves the chain, so every later one re-adopted an
  // already-consumed deposit and died at the bind.
  assert.ok(!events.includes('liveReceive:backing'), 'must not re-consume the backing deposit');
  assert.ok(!events.includes(`inspect:${BACKING_TX}`), 'must not re-inspect it either');
});

test('an unfunded genesis needs no adoption', async () => {
  reset({ rollup: '0x' + '44'.repeat(20) });

  await importL1Deposit(CH, 3, TX, { allowUnboundDepositor: false });

  assert.ok(!events.includes('liveReceive:backing'));
  // Creation is skipped too: there is nothing to adopt, and /init already owns that call.
  assert.ok(!events.includes('liveInitWithAccountSalt'));
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Error cases. The adoption step reads several fields out of channel_backing.json and drives the
// daemon; each of these is a way a real deployment can be misconfigured or a daemon call can fail,
// and every one must surface a clear error rather than silently skip adoption (which would later
// manifest as an opaque "settle chain differs" or "not registered" downstream).
// ─────────────────────────────────────────────────────────────────────────────────────────────

test('a funded backing with no base account salt fails closed with a clear message', async () => {
  const b = { ...FUNDED };
  delete b.base_private_state;   // salt that names the one account is gone
  reset(b);

  await assert.rejects(
    () => importL1Deposit(CH, 3, TX, { allowUnboundDepositor: false }),
    /no base account salt/,
    'a funded genesis without its account salt must not silently mint a second account',
  );
  assert.ok(!events.includes('liveReceive:backing'), 'nothing should be consumed on a config error');
});

test('a partial backing (settled chain but no deposit tx) is treated as unfunded, not half-adopted', async () => {
  // settled_tx_chain present but deposit_salt/deposit_tx missing -> the three-field guard must
  // treat it as "nothing to adopt" rather than reaching for a deposit that was never recorded.
  reset({
    rollup: '0x' + '44'.repeat(20),
    settled_tx_chain: BACKING_CHAIN,
    base_private_state: { salt: ACCOUNT_SALT },
  });

  await importL1Deposit(CH, 3, TX, { allowUnboundDepositor: false });

  assert.ok(!events.includes('liveReceive:backing'), 'must not try to adopt without a deposit tx');
  assert.ok(!events.includes('liveInitWithAccountSalt'), 'must not create an account either');
});

test('a producer register failure during adoption propagates (no silent success)', async () => {
  reset(FUNDED);
  producer.register = async () => { events.push('register'); throw new Error('journal is locked'); };

  await assert.rejects(
    () => importL1Deposit(CH, 3, TX, { allowUnboundDepositor: false }),
    /journal is locked/,
    'a failed registration must abort the import, not proceed to a bind that will fail obscurely',
  );
  // restore for later tests in this file
  producer.register = async () => { events.push('register'); registeredChannels.push(CH); return {}; };
});

test('a daemon receive failure during a fresh adoption propagates', async () => {
  reset(FUNDED);
  const realReceive = producer.liveReceiveBackingDeposit;
  producer.liveReceiveBackingDeposit = async () => { throw new Error('live balance poisoned'); };

  await assert.rejects(
    () => importL1Deposit(CH, 3, TX, { allowUnboundDepositor: false }),
    /live balance poisoned/,
  );
  producer.liveReceiveBackingDeposit = realReceive;
});
