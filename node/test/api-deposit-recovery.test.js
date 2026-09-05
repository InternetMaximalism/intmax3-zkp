'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-deposit-recovery-'));
process.env.INTMAX_WORK_DIR = work;
const cli = require('../../api/lib/cli');
const producer = require('../../api/lib/block-producer');
const deposits = require('../../api/lib/deposit-spend');
const hash = n => `0x${n.repeat(32)}`;
const address = n => `0x${n.repeat(20)}`;
test.after(() => fs.rmSync(work, { recursive: true, force: true }));

function harness(ch) {
  const events = [];
  const transactions = new Map();
  let failBroadcast = false;
  let signatures = 0;
  cli.writeJson(cli.wc(ch, 'channel_backing.json'), { rollup: address('44') });
  cli.cli = (channel, args) => { assert.equal(channel, ch); events.push(args); };
  producer.livePrepareDepositRecipient = async channel => {
    assert.equal(channel, ch); events.push(['prepare-recipient']); return hash('55');
  };
  const dependencies = {
    sender: { chainId: 31337, address: address('11'), instance: {
      status(id) { return transactions.get(id) || null; },
      async send(intent) {
        events.push(['send', intent.actionId]);
        if (!transactions.has(intent.actionId)) {
          signatures += 1;
          transactions.set(intent.actionId, { transactionHash: hash(String(signatures).padStart(2, '0')) });
        }
        if (failBroadcast) throw new Error('response lost after raw bytes were persisted');
        return transactions.get(intent.actionId);
      },
      async confirm(intent, txHash) { events.push(['confirm', intent.actionId, txHash]); },
    } },
    preflight(channel, slot, tokenIndex, amount, depositor, reservation) {
      assert.equal(channel, ch); events.push(['preflight', slot, reservation]);
      return { recipientSlots: slot == null ? [0, 1] : [slot], stateDigest: hash('aa'), tokenIndex, amount };
    },
    async importL1Deposit(channel, slot, txHash, options) {
      events.push(['import', slot, txHash, options]);
      return { liveStatus: { channelId: channel } };
    },
  };
  return { dependencies, events, setFailure(value) { failBroadcast = value; }, signatures() { return signatures; } };
}

test('admissibility and capacity reservation precede an exact recoverable L1 payment', async () => {
  const h = harness(7);
  const request = { recipientSlot: 0, tokenIndex: 0, amount: '9', requestId: 'payment-1' };
  h.setFailure(true);
  let uncertain;
  await assert.rejects(deposits.spendDeposit(7, request, h.dependencies), error => {
    uncertain = error.deposit;
    return error.message.includes('response lost');
  });
  assert.equal(h.signatures(), 1);
  assert.equal(uncertain.txHash, hash('01'));
  assert.equal(cli.readJson(cli.wc(7, 'pending_deposit.json')).txHash, hash('01'));
  assert.ok(h.events.findIndex(e => e[0] === 'reserve-l1-deposit') < h.events.findIndex(e => e[0] === 'send'));
  assert.equal(h.events.find(e => e[0] === 'reserve-l1-deposit')[6], `--recipient=${hash('55')}`);
  assert.deepEqual(h.events.filter(e => e[0] === 'preflight').map(e => e[2]), [undefined, uncertain.actionId]);
  h.setFailure(false);
  const resumed = await deposits.spendDeposit(7, request, h.dependencies);
  assert.equal(resumed.txHash, uncertain.txHash);
  assert.equal(h.signatures(), 1, 'retry does not sign another transaction');
  assert.equal(h.events.filter(e => e[0] === 'prepare-recipient').length, 1);
  const done = await deposits.importTrackedDeposit(7, resumed, 0, h.dependencies);
  assert.equal(done.operation.status, 'imported');
  const invocation = h.events.find(e => e[0] === 'import');
  assert.equal(invocation[3].depositReservation, resumed.actionId);
  const beforeImport = h.events.slice(0, h.events.indexOf(invocation));
  assert.ok(beforeImport.some(e => e[0] === 'bind-l1-deposit-reservation' && e[2] === hash('01')));
  assert.equal((await deposits.spendDeposit(7, request, h.dependencies)).status, 'imported');
  // Restore the old pointer only, as if process death interrupted the two local replacements.
  cli.writeJson(cli.wc(7, 'pending_deposit.json'), resumed);
  await deposits.spendDeposit(7, request, h.dependencies);
  assert.equal(cli.readJson(cli.wc(7, 'pending_deposit.json')).status, 'imported');
  assert.equal(h.signatures(), 1, 'lost final HTTP response cannot become another payment');
  assert.match(deposits.depositResponse(done.operation).retry, /new requestId/);
  const next = await deposits.spendDeposit(7, { ...request, requestId: 'payment-2' }, h.dependencies);
  assert.notEqual(next.txHash, resumed.txHash, 'a deliberate new request may make an identical payment');
  assert.equal(h.signatures(), 2);
});

test('an import failure keeps the chosen candidate and exact payment available for retry', async () => {
  const h = harness(8);
  const request = { amount: '5', requestId: 'auto-credit' };
  const operation = await deposits.spendDeposit(8, request, h.dependencies);
  h.dependencies.importL1Deposit = async () => { throw new Error('temporary head publication unavailable'); };
  await assert.rejects(deposits.importTrackedDeposit(8, operation, 1, h.dependencies), /temporary/);
  const pending = cli.readJson(cli.wc(8, 'pending_deposit.json'));
  assert.equal(pending.importSlot, 1);
  await assert.rejects(deposits.importTrackedDeposit(8, pending, 0, h.dependencies), /different recipient slot/);
  h.dependencies.importL1Deposit = async () => ({ recovered: true });
  const recovered = await deposits.importTrackedDeposit(8, pending, undefined, h.dependencies);
  assert.equal(recovered.operation.recipientSlot, 1);
  assert.equal(h.signatures(), 1);
});

test('preflight refusal and conflicting id reuse cannot reach a new payment', async () => {
  const h = harness(9);
  const original = h.dependencies.preflight;
  h.dependencies.preflight = () => { throw new Error('registered token has no remaining capacity'); };
  await assert.rejects(deposits.spendDeposit(9, { amount: '9' }, h.dependencies), /remaining capacity/);
  assert.equal(h.events.length, 0);
  assert.equal(h.signatures(), 0);
  h.dependencies.preflight = original;
  await deposits.spendDeposit(9, { amount: '9', requestId: 'stable' }, h.dependencies);
  await assert.rejects(deposits.spendDeposit(9, { amount: '10', requestId: 'stable' }, h.dependencies), /different amount/);
  await assert.rejects(deposits.spendDeposit(9, { amount: '9', requestId: 'next' }, h.dependencies), /earlier L1 deposit/);
  assert.equal(h.signatures(), 1);
});

test('completed native import resumes publication without treating consumed capacity as a new credit', async () => {
  const h = harness(10);
  const operation = await deposits.spendDeposit(10, { amount: '5', recipientSlot: 0 }, h.dependencies);
  cli.writeJson(cli.wc(10, 'l1_import_cosigned.json'), { txHash: operation.txHash,
    fundImportState: { digest: hash('aa') }, bundleApplyState: { digest: hash('bb') } });
  h.dependencies.preflight = () => { throw new Error('must not charge completed credit capacity twice'); };
  const completed = await deposits.importTrackedDeposit(10, operation, 0, h.dependencies);
  assert.equal(completed.operation.status, 'imported');
  assert.equal(h.signatures(), 1);
});
