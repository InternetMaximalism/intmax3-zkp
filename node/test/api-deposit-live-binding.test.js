'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-live-deposit-pipeline-'));
process.env.INTMAX_WORK_DIR = work;

const cliModule = require('../../api/lib/cli');
const producer = require('../../api/lib/block-producer');
const producerHead = require('../../api/lib/producer-head');
const events = [];

function write(ch, name, value) {
  const directory = path.join(work, `ch${ch}`);
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, name), JSON.stringify(value));
}

cliModule.chainId = () => 31337;
cliModule.cli = (ch, args, env) => {
  const proposing = args.includes('--propose-exit-kit');
  events.push(proposing ? `${args[0]} --propose-exit-kit` : args[0]);
  if (proposing) {
    // The propose run signs nothing: it emits the exact successor the daemon must prove for.
    write(ch, 'exit_kit_proposal.json', {
      kind: 'l1DepositImport',
      record: { channelId: ch },
      members: [],
      fundImportState: { channelId: ch, digest: 'fund' },
    });
    return '';
  }
  if (args[0] === 'cosign-l1-deposit-import') {
    assert.equal(env && env.INTMAX_PREPARED_EXIT_KIT, 'prepared_exit_kit.json',
      'the signing run must be bound to the prepared exit kit');
    const envelope = JSON.parse(fs.readFileSync(path.join(work, `ch${ch}`, 'prepared_exit_kit.json'), 'utf8'));
    assert.equal(envelope.chainId, 31337);
    assert.equal(envelope.rollup, '0x' + '44'.repeat(20));
    assert.equal(envelope.signedHead.digest, 'fund');
  }
  if (args[0] === 'inspect-l1-deposit') {
    write(ch, 'producer_deposit.json', {
      depositIndex: 4,
      depositor: '0x' + '01'.repeat(20),
      recipient: '0x' + '02'.repeat(32),
      tokenIndex: 0,
      amount: '9',
      auxData: '0x' + '00'.repeat(32),
      expectedDepositHashChain: '0x' + '03'.repeat(32),
    });
  } else if (args[0] === 'cosign-l1-deposit-import') {
    write(ch, 'l1_import_cosigned.json', {
      txHash: args[2],
      intmaxBlockNumber: 11,
      fundImportState: { channelId: ch, digest: 'fund' },
      bundleApplyState: { channelId: ch, digest: 'bundle' },
    });
    write(ch, 'channel_snapshot.json', {
      record: { channelId: ch },
      state: { channelId: ch, digest: 'bundle' },
      members: [],
    });
  }
};
producerHead.flushPublishedHead = async () => { events.push('flushPublishedHead'); };
producer.livePrepareExitKit = async (ch, proposal) => {
  events.push('livePrepareExitKit');
  assert.equal(proposal.kind, 'l1DepositImport');
  assert.equal(proposal.fundImportState.digest, 'fund');
  return { signedHead: proposal.fundImportState, signedHeadExitKit: { schemaVersion: 1 } };
};
producer.postDeposit = async deposit => {
  events.push('postDeposit');
  return { requestId: 'deposit:4', blockNumber: 11, deposit };
};
producer.liveReceiveConfiguredDeposit = async (ch, receipt, deposit) => {
  events.push('liveReceiveConfiguredDeposit');
  return { channelId: ch, producerRequestId: receipt.requestId, depositIndex: deposit.depositIndex };
};
producer.liveBindSnapshot = async (ch, snapshot) => {
  events.push('liveBindSnapshot');
  return { channelId: ch, signedHeadDigest: snapshot.state.digest };
};
producer.syncOffchainHeads = async states => {
  events.push('syncOffchainHeads');
  return { count: states.length };
};

// Load only after replacing the collaborators that it destructures at module initialization.
delete require.cache[require.resolve('../../api/lib/deposit-pipeline')];
const { importL1Deposit } = require('../../api/lib/deposit-pipeline');

test.after(() => fs.rmSync(work, { recursive: true, force: true }));

test('deposit head is never published before durable live receive and N-of-N bind', async () => {
  events.length = 0;
  const txHash = '0x' + 'ab'.repeat(32);
  write(7, 'channel_backing.json', { rollup: '0x' + '44'.repeat(20) });
  const result = await importL1Deposit(7, 0, txHash);

  assert.deepEqual(events, [
    'flushPublishedHead',
    'inspect-l1-deposit',
    'postDeposit',
    'liveReceiveConfiguredDeposit',
    // Signer-independent exit: propose -> prove the pre-sign kit -> sign with it bound.
    'cosign-l1-deposit-import --propose-exit-kit',
    'livePrepareExitKit',
    'cosign-l1-deposit-import',
    'liveBindSnapshot',
    'syncOffchainHeads',
  ]);
  assert.equal(result.liveReceipt.producerRequestId, 'deposit:4');
  assert.equal(result.liveStatus.signedHeadDigest, 'bundle');
});
test('restart completes an old receive/bind before inspecting the next deposit', async () => {
  events.length = 0;
  const oldHash = '0x' + 'cd'.repeat(32);
  write(8, 'producer_deposit.json', { depositIndex: 3 });
  write(8, 'channel_backing.json', { rollup: '0x' + '44'.repeat(20) });
  write(8, 'channel_snapshot.json', {
    record: { channelId: 8 }, state: { channelId: 8, digest: 'old-bundle' }, members: [],
  });
  write(8, 'l1_import_cosigned.json', {
    txHash: oldHash,
    intmaxBlockNumber: 11,
    fundImportState: { channelId: 8, digest: 'old-fund' },
    bundleApplyState: { channelId: 8, digest: 'old-bundle' },
  });

  await importL1Deposit(8, 0, '0x' + 'ef'.repeat(32));
  assert.deepEqual(events.slice(0, 4), [
    'postDeposit',
    'liveReceiveConfiguredDeposit',
    'liveBindSnapshot',
    'syncOffchainHeads',
  ]);
  assert.equal(events[4], 'flushPublishedHead');
  assert.equal(events[5], 'inspect-l1-deposit');
});
