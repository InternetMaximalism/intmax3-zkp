'use strict';
// The deposit sequencer consumes a public rollup's deposits in the producer's index order, whoever
// is online. Two defects reproduced on the public-chain rehearsal motivate it: one unimported
// deposit stalled every later import on the rollup ("producer expects N"), and a deposit the
// channel could not credit must still be journaled or the sequence stalls for good.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'deposit-sequencer-'));
process.env.INTMAX_WORK_DIR = work;
process.env.INTMAX_CHANNELS = '7,8';
process.env.L1_LOG_WINDOW_BLOCKS = '1000';

const cli = require('../../api/lib/cli');
const producer = require('../../api/lib/block-producer');
const ROLLUP = '0x' + '3c'.repeat(20);
const TOPIC0 = '0x35cffad0c6ce159deaf160c503b69a374a9751e480083db7e6849e00f1a2c4fe';
const RECIPIENT = { 7: '0x' + '07'.repeat(32), 8: '0x' + '08'.repeat(32), foreign: '0x' + 'ff'.repeat(32) };
const OPERATOR = '0x' + 'aa'.repeat(20), ALICE = '0x' + 'a1'.repeat(20), STRANGER = '0x' + '5e'.repeat(20);

// ── chain, producer and import stubs ──────────────────────────────────────────────────────────
let chain, nextIndex, liveAwaiting, imports, journaled, importBehaviour;
function reset({ head = 5000, deployedAt = 100, cap = 1000, retention = Infinity } = {}) {
  chain = { head, deployedAt, cap, retention, deposits: [] };
  delete process.env.DEPOSIT_SCAN_FROM_BLOCK;
  delete process.env.CONTRACTS_DIR;
  nextIndex = 0; liveAwaiting = {}; imports = []; journaled = []; importBehaviour = () => {};
  fs.rmSync(path.join(work, 'producer'), { recursive: true, force: true });
  for (const ch of [7, 8]) {
    fs.mkdirSync(cli.wc(ch, ''), { recursive: true });
    fs.writeFileSync(cli.wc(ch, 'channel_backing.json'), JSON.stringify({ rollup: ROLLUP, deposit_recipient: RECIPIENT[ch] }));
    // 3 co-signers (all the operator's exit address), the operator delegate, then Alice on ch7.
    const recipients = [OPERATOR, OPERATOR, OPERATOR, '0x' + '0d'.repeat(20)].concat(ch === 7 ? [ALICE] : []);
    fs.writeFileSync(cli.wc(ch, 'channel_snapshot.json'), JSON.stringify({ state: { balanceState: { memberCount: 3, delegateCount: recipients.length - 3, recipients } } }));
  }
}
function deposit(index, { recipient, depositor, block }) {
  chain.deposits.push({ index, recipient, depositor, block, txHash: '0x' + String(index).padStart(64, '0') });
}
const word = hex => hex.replace(/^0x/, '').padStart(64, '0');
cli.sh = (_bin, args) => {
  const method = args[1];
  const params = args.slice(2, args.indexOf('--rpc-url')).map(p => (p.startsWith('{') || p.startsWith('[') ? JSON.parse(p) : p));
  if (method === 'eth_blockNumber') return JSON.stringify('0x' + chain.head.toString(16));
  if (method === 'eth_getCode') {
    const block = parseInt(params[1], 16);
    if (block < chain.head - chain.retention) throw Object.assign(new Error('cast rpc failed'), { stderr: `error code -32603: state at block #${block} is pruned` });
    return JSON.stringify(block >= chain.deployedAt ? '0x60' : '0x');
  }
  if (method === 'eth_getLogs') {
    const from = parseInt(params[0].fromBlock, 16), to = parseInt(params[0].toBlock, 16);
    if (to - from + 1 > chain.cap) throw Object.assign(new Error('cast rpc failed'), { stderr: `error code -32701: exceed maximum block range: ${chain.cap}` });
    return JSON.stringify(chain.deposits.filter(d => d.block >= from && d.block <= to).map(d => ({
      address: ROLLUP, transactionHash: d.txHash, blockNumber: '0x' + d.block.toString(16),
      topics: [TOPIC0, '0x' + word(d.index.toString(16))], data: '0x' + word(d.depositor) + word(d.recipient) + '00'.repeat(32 * 4),
    })));
  }
  if (method === 'eth_getTransactionReceipt') {
    const d = chain.deposits.find(x => x.txHash === params[0]);
    return JSON.stringify(d ? { status: '0x1', blockNumber: '0x' + d.block.toString(16), logs: [{ address: ROLLUP, topics: [TOPIC0, '0x' + word(d.index.toString(16))] }] } : null);
  }
  throw new Error('unexpected rpc ' + method);
};
cli.chainId = () => 11155111;
cli.cli = (ch, args) => {
  assert.equal(args[0], 'inspect-l1-deposit');
  assert.ok(args.includes('--journal-only'));
  const index = Number(args[args.indexOf('--journal-only') + 1]);
  fs.writeFileSync(cli.wc(ch, args[3]), JSON.stringify({ depositIndex: index }));
  return '';
};
producer.status = async () => ({ nextDepositIndex: nextIndex });
producer.postDeposit = async request => {
  if (request.depositIndex !== nextIndex) throw new Error(`L1 deposit index ${request.depositIndex} is stale or skipped; producer expects ${nextIndex}`);
  journaled.push(request.depositIndex); nextIndex += 1;
};
producer.liveStatus = async ch => ({ awaitingChannelBinding: !!liveAwaiting[ch] });
require.cache[require.resolve('../../api/lib/deposit-pipeline')] = {
  exports: {
    importL1Deposit: async (ch, slot, txHash, opts) => {
      const d = chain.deposits.find(x => x.txHash === txHash);
      importBehaviour(d, 'before-post');
      nextIndex += 1;                                  // the pipeline journals it...
      importBehaviour(d, 'after-post');
      imports.push({ ch, slot, index: d.index, custody: opts.allowUnboundDepositor });
    },
  },
};
const sequencer = require('../../api/lib/deposit-sequencer');
const withLock = (_ch, fn) => fn();

test('deposits are consumed in index order, each credited to its depositor\'s bound slot', async () => {
  reset();
  deposit(0, { recipient: RECIPIENT[7], depositor: ALICE, block: 900 });
  deposit(1, { recipient: RECIPIENT[7], depositor: ALICE, block: 3500 });
  await sequencer.run(withLock);
  assert.deepEqual(imports.map(i => [i.ch, i.slot, i.index, i.custody]), [[7, 4, 0, false], [7, 4, 1, false]]);
  assert.equal(nextIndex, 2);
});

test('an abandoned deposit no longer blocks a later one: both are consumed without their browsers', async () => {
  reset();
  deposit(0, { recipient: RECIPIENT[8], depositor: STRANGER, block: 1200 });   // never imported by anyone
  deposit(1, { recipient: RECIPIENT[7], depositor: ALICE, block: 1300 });
  const outcome = await sequencer.importThrough(7, chain.deposits[1].txHash, withLock);
  assert.equal(outcome.slot, 4);
  assert.equal(nextIndex, 2);
});

test('a depositor bound to no slot is held in the operator delegate slot, and reported as such', async () => {
  reset();
  deposit(0, { recipient: RECIPIENT[8], depositor: STRANGER, block: 1200 });
  await sequencer.run(withLock);
  assert.deepEqual(imports, [{ ch: 8, slot: 3, index: 0, custody: true }]);
  await assert.rejects(sequencer.importThrough(8, chain.deposits[0].txHash, withLock), /held by the channel operator/);
});

test('a deposit to another recipient is only journaled', async () => {
  reset();
  deposit(0, { recipient: RECIPIENT.foreign, depositor: STRANGER, block: 1200 });
  deposit(1, { recipient: RECIPIENT[7], depositor: ALICE, block: 1201 });
  await sequencer.run(withLock);
  assert.deepEqual(journaled, [0]);
  assert.deepEqual(imports.map(i => i.index), [1]);
});

test('a depositor that is several slots\' exit address is not credited, but the sequence goes on', async () => {
  reset();
  deposit(0, { recipient: RECIPIENT[7], depositor: OPERATOR, block: 1200 });   // the 3 co-signer slots
  deposit(1, { recipient: RECIPIENT[7], depositor: ALICE, block: 1201 });
  await sequencer.run(withLock);
  assert.deepEqual(journaled, [0]);
  assert.deepEqual(imports.map(i => i.index), [1]);
  await assert.rejects(sequencer.importThrough(7, chain.deposits[0].txHash, withLock), /several slots/);
});

test('a transient failure before the deposit is journaled is retried, never skipped', async () => {
  reset();
  deposit(0, { recipient: RECIPIENT[7], depositor: ALICE, block: 1200 });
  importBehaviour = (_d, phase) => { if (phase === 'before-post') throw new Error('RPC timeout'); };
  await assert.rejects(sequencer.run(withLock), /RPC timeout/);
  assert.equal(nextIndex, 0, 'nothing journaled: the user deposit is not given up');
  importBehaviour = () => {};
  await sequencer.run(withLock);
  assert.deepEqual(imports.map(i => [i.index, i.slot]), [[0, 4]]);
});

test('a deterministic refusal of the deposit itself is journaled so later deposits proceed', async () => {
  reset();
  deposit(0, { recipient: RECIPIENT[7], depositor: ALICE, block: 1200 });
  deposit(1, { recipient: RECIPIENT[7], depositor: ALICE, block: 1201 });
  importBehaviour = (d, phase) => { if (d.index === 0 && phase === 'before-post') throw new Error('Deposited.amount exceeds u64 (0x..) — refusing rather than truncating'); };
  await sequencer.run(withLock);
  assert.deepEqual(journaled, [0]);
  assert.deepEqual(imports.map(i => i.index), [1]);
});

test('an import refused after journaling but before the channel received it does not stall the sequence', async () => {
  reset();
  deposit(0, { recipient: RECIPIENT[7], depositor: ALICE, block: 1200 });
  deposit(1, { recipient: RECIPIENT[7], depositor: ALICE, block: 1201 });
  importBehaviour = (d, phase) => { if (d.index === 0 && phase === 'after-post') throw new Error('credit-safety refusal'); };
  await sequencer.run(withLock);
  assert.deepEqual(imports.map(i => i.index), [1]);
  await assert.rejects(sequencer.importThrough(7, chain.deposits[0].txHash, withLock), /not credited: credit-safety/);
});

test('an import that failed after the channel received the deposit is resumed, not abandoned', async () => {
  reset();
  deposit(0, { recipient: RECIPIENT[7], depositor: ALICE, block: 1200 });
  importBehaviour = (_d, phase) => { if (phase === 'after-post') { liveAwaiting[7] = true; throw new Error('signing interrupted'); } };
  await assert.rejects(sequencer.run(withLock), /signing interrupted/);
});

test('the browser is told to keep waiting while its deposit is not reorg-safe', async () => {
  reset();
  deposit(0, { recipient: RECIPIENT[7], depositor: ALICE, block: 4995 });
  await assert.rejects(sequencer.importThrough(7, chain.deposits[0].txHash, withLock), /has 6 confirmation\(s\), need 12/);
  assert.equal(nextIndex, 0);
});

test('the log scan pages within any RPC range cap', async () => {
  reset({ head: 20000, deployedAt: 10, cap: 300 });
  deposit(0, { recipient: RECIPIENT[7], depositor: ALICE, block: 50 });
  deposit(1, { recipient: RECIPIENT[7], depositor: ALICE, block: 19000 });
  await sequencer.run(withLock);
  assert.deepEqual(imports.map(i => i.index), [0, 1]);
});

// Public RPCs prune historical state (publicnode keeps a few thousand blocks): the rollup's
// deployment block cannot be probed once it is old, which is exactly how the first testnet
// deployment of this sequencer failed.
function broadcastArtifact(block) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'contracts-'));
  const runs = path.join(dir, 'broadcast', 'Deploy.s.sol', '11155111');
  fs.mkdirSync(runs, { recursive: true });
  fs.writeFileSync(path.join(runs, 'run-latest.json'), JSON.stringify({
    transactions: [{ transactionType: 'CREATE', contractName: 'IntmaxRollup', contractAddress: ROLLUP, hash: '0xaa' }],
    receipts: [{ transactionHash: '0xaa', blockNumber: '0x' + block.toString(16) }],
  }));
  return dir;
}

test('with old state pruned, the scan starts at the deployment the forge broadcast recorded', async () => {
  reset({ head: 50000, deployedAt: 100, retention: 10000 });
  process.env.CONTRACTS_DIR = broadcastArtifact(100);
  deposit(0, { recipient: RECIPIENT[7], depositor: ALICE, block: 150 });
  await sequencer.run(withLock);
  assert.deepEqual(imports.map(i => i.index), [0]);
});

test('an explicit DEPOSIT_SCAN_FROM_BLOCK is used first', async () => {
  reset({ head: 50000, deployedAt: 100, retention: 10000 });
  process.env.DEPOSIT_SCAN_FROM_BLOCK = '120';
  deposit(0, { recipient: RECIPIENT[7], depositor: ALICE, block: 150 });
  await sequencer.run(withLock);
  assert.deepEqual(imports.map(i => i.index), [0]);
});

test('with old state pruned and no record, the operator is told what to configure', async () => {
  reset({ head: 50000, deployedAt: 100, retention: 10000 });
  await assert.rejects(sequencer.run(withLock), /set DEPOSIT_SCAN_FROM_BLOCK/);
});
