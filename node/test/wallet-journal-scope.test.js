'use strict';
// Saved Deposit/Send records are scoped to their deployment (chain id + rollup) and channel.
// Keyed by channel number alone, a record an earlier deployment left in the browser (an abandoned
// rollup) was read by the next deployment's channel 7, refused as "another wallet or deployment",
// and — Clear refusing while a saved operation exists — blocked Deposit for good. Reported on the
// v3 testnet: "deposit failed: A saved transaction belongs to another wallet or deployment".
const test = require('node:test'), assert = require('node:assert/strict');
const vm = require('vm'), fs = require('fs'), path = require('path');
const { WalletTransactions } = require('../../hosting/wallet/wallet-transactions');

const html = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-live.html'), 'utf8');
const start = html.indexOf('let deploymentScopePromise = null;');
const end = html.indexOf('const SEED_KEY', start);
const OLD_ROLLUP = '0xb7649e2db417bb5195b2bb1f9d64c0ec2d90c271';
const NEW_ROLLUP = '0x3c9d21c388a0ac5430c0cd9b1bacd19044be9ae8';

function harness() {
  const data = new Map();
  const storage = { getItem: k => (data.has(k) ? data.get(k) : null), setItem: (k, v) => data.set(k, v), removeItem: k => data.delete(k) };
  const outbox = new Map();
  const context = {
    myChannel: 7, activeCh: 7, String,
    fetchDeploymentInfo: async () => ({ chainId: 11155111, rollup: NEW_ROLLUP }),
    walletTransactions: new WalletTransactions(storage),
    walletOutbox: {
      read: async k => outbox.get(k),
      save: async (k, v) => { if (outbox.has(k)) throw new Error('exists'); outbox.set(k, v); },
      clear: async k => { outbox.delete(k); },
    },
  };
  vm.createContext(context);
  vm.runInContext(html.slice(start, end), context);
  return { context, storage, data, outbox };
}
const record = rollup => ({ version: 1, context: { chainId: 11155111, rollup, account: '0x9d4f' }, request: { from: '0x9d4f', nonce: '0x1' }, txHash: '0x' + 'ab'.repeat(32), details: {}, nextBlock: 1 });

test('a record left by an earlier deployment is neither read nor able to block this one', async () => {
  const h = harness();
  h.data.set('intmax-wallet-tx:deposit:7', JSON.stringify(record(OLD_ROLLUP)));
  const key = await h.context.depositJournalKey();
  assert.equal(key, `deposit:11155111:${NEW_ROLLUP}:7`);
  assert.equal(h.context.walletTransactions.read(key), null, 'this deployment has no saved deposit');
  assert.ok(h.data.has('intmax-wallet-tx:deposit:7'), 'the earlier deployment\'s record is kept, untouched');
});

test('a record of THIS deployment saved under the old key is adopted, so it still resumes', async () => {
  const h = harness();
  h.data.set('intmax-wallet-tx:deposit:7', JSON.stringify(record(NEW_ROLLUP)));
  const key = await h.context.depositJournalKey();
  assert.equal(h.context.walletTransactions.read(key).txHash, '0x' + 'ab'.repeat(32));
  assert.ok(!h.data.has('intmax-wallet-tx:deposit:7'));
});

test('saved transfers follow the same rule', async () => {
  const h = harness();
  h.outbox.set('inter:7', { version: 1, channel: 7, chainId: 11155111, rollup: OLD_ROLLUP });
  const key = await h.context.sendOutboxKey();
  assert.equal(await h.context.walletOutbox.read(key), undefined);
  assert.ok(h.outbox.has('inter:7'));
  h.outbox.set('inter:7', { version: 1, channel: 7, chainId: 11155111, rollup: NEW_ROLLUP });
  assert.equal((await h.context.walletOutbox.read(await h.context.sendOutboxKey())).rollup, NEW_ROLLUP);
  assert.ok(!h.outbox.has('inter:7'));
});
