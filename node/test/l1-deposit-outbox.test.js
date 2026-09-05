'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Interface } = require('ethers');
const { Transaction } = require('ethers');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { makeDepositSender, DEPOSIT_ABI } = require('../common/l1-deposit-outbox');
const hash = n => `0x${n.repeat(32)}`;
const address = n => `0x${n.repeat(20)}`;

test('deposit adapter pins exact native/ERC20 economics and finalizes only the matching event', async () => {
  const iface = new Interface(DEPOSIT_ABI);
  const sent = [];
  let receipt = null;
  let finalized = 0;
  const outbox = {
    status() { return { transactionHash: hash('88') }; },
    async send(tx) { sent.push(tx); return { transactionHash: hash('88') }; },
    async markFinalized(action, observation, predicate) {
      assert.equal(action, 'deposit:normal');
      assert.equal(observation.transactionHash, hash('88'));
      assert.equal(await predicate({ receipt }), true);
      finalized += 1;
    },
  };
  const sender = makeDepositSender({ chainId: 31337, signer: { address: address('11') },
    provider: { async getTransactionReceipt() { return receipt; } }, outbox });
  const intent = { actionId: 'deposit:normal', rollup: address('44'), depositRecipient: hash('55'),
    tokenIndex: 0, amount: '9' };
  await sender.send(intent);
  assert.equal(sent[0].value, 9n);
  const nativeCall = iface.parseTransaction(sent[0]);
  assert.equal(nativeCall.args.recipient, hash('55'));
  assert.equal(nativeCall.args.tokenIndex, 0n);
  assert.equal(nativeCall.args.amount, 9n);
  await sender.send({ ...intent, tokenIndex: 5 });
  assert.equal(sent[1].value, 0n);
  assert.equal(iface.parseTransaction(sent[1]).args.tokenIndex, 5n);
  await assert.rejects(sender.confirm(intent, hash('88')), error => error.code === 'DEPOSIT_PENDING');
  assert.equal(finalized, 0);
  const event = iface.encodeEventLog(iface.getEvent('Deposited'), [1, address('11'), hash('55'), 0, 9, hash('00'), hash('66')]);
  receipt = { status: 1, hash: hash('88'), blockNumber: 11, blockHash: hash('aa'),
    logs: [{ address: address('44'), ...event }] };
  await sender.confirm(intent, hash('88'));
  assert.equal(finalized, 1);
});

test('cast mktx --json returns the raw offline type-2 transaction expected by the outbox', t => {
  const binary = process.env.CAST_BIN || 'cast';
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-offline-mktx-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let raw;
  try {
    // Public dummy key, zero value, no live RPC and every transaction field fixed. This command
    // constructs bytes only, never broadcasts; any attempted RPC would fail at unused port 1.
    raw = execFileSync(binary, ['mktx', address('00').slice(0, -1) + '1', '0x',
      '--chain', '31337', '--nonce', '0', '--value', '0', '--gas-limit', '21000',
      '--gas-price', '2', '--priority-gas-price', '1', '--private-key', hash('00').slice(0, -1) + '1',
      '--rpc-url', 'http://127.0.0.1:1', '--rpc-timeout', '1', '--json'], {
      cwd: directory, encoding: 'utf8', timeout: 10000,
      env: { PATH: process.env.PATH, RAYON_NUM_THREADS: '1' },
    }).trim();
  } catch (error) {
    if (error.code === 'ENOENT') return t.skip('cast not installed; set CAST_BIN to enable the offline CLI fixture');
    throw error;
  }
  assert.match(raw, /^0x[0-9a-fA-F]+$/);
  const transaction = Transaction.from(raw);
  assert.equal(transaction.type, 2);
  assert.equal(transaction.chainId, 31337n);
  assert.equal(transaction.nonce, 0);
  assert.equal(transaction.value, 0n);
  assert.equal(transaction.data, '0x');
  assert.equal(transaction.gasLimit, 21000n);
  assert.equal(transaction.maxFeePerGas, 2n);
  assert.equal(transaction.maxPriorityFeePerGas, 1n);
});
