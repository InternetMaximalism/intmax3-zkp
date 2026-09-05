'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Wallet } = require('../common/wallet');
const recipient = '0x0000000000000000000000000000000000000001';

function harness() {
  const wallet = new Wallet();
  const calls = [];
  let loads = 0;
  wallet._load = () => {
    loads += 1;
    return new Proxy({}, { get: (_, method) => (...args) => {
      calls.push({ method, args });
      return '{}';
    } });
  };
  return { wallet, calls, loads: () => loads };
}

test('valid wallet intent reaches WASM with exact bounded numbers and full u64 amount', () => {
  const h = harness();
  const maximum = '18446744073709551615';
  h.wallet.send(0, 1023, maximum, undefined, 9);
  assert.deepEqual(h.calls.pop(), { method: 'wallet_send', args: [1023, BigInt(maximum), 9] });
  h.wallet.sendInterChannel(0xfffffffe, 1023, maximum, { pkG: 'public' }, 0xffffffff, 0xffffffff);
  assert.deepEqual(h.calls.pop(), { method: 'wallet_send_inter_channel',
    args: [0xfffffffe, 1023, BigInt(maximum), '{"pkG":"public"}', 0xffffffff, 0xffffffff] });
  h.wallet.burnSend(9007199254740993n, recipient, 0, 0);
  assert.deepEqual(h.calls.pop(), { method: 'wallet_burn_send', args: [9007199254740993n, recipient, 0, 0] });
  h.wallet.genesisContribution('0', recipient);
  assert.deepEqual(h.calls.pop(), { method: 'wallet_genesis_contribution', args: [0n, recipient] });
  h.wallet.withdrawalClaim({ exact: true }, 9);
  assert.deepEqual(h.calls.pop(), { method: 'wallet_withdrawal_claim', args: ['{"exact":true}', 9] });
});

test('optional token defaults remain genesis without coercing explicit token values', () => {
  const h = harness();
  for (const omitted of [undefined, null]) {
    h.wallet.send(0, 1, 5, undefined, omitted);
    assert.deepEqual(h.calls.pop().args, [1, 5n, undefined]);
    h.wallet.refresh(0, omitted);
    assert.deepEqual(h.calls.pop().args, [undefined]);
    h.wallet.sendInterChannel(8, 1, 5, {}, omitted, 0);
    assert.equal(h.calls.pop().args[4], undefined);
    h.wallet.burnSend(5, recipient, omitted, 0);
    assert.equal(h.calls.pop().args[2], undefined);
  }
});

test('all amount-bearing wrappers reject noncanonical, unsafe or oversized values before loading WASM', () => {
  const h = harness();
  const bad = [undefined, null, false, true, [], {}, '', '01', ' 1', '+1', '1.0', '1e3', '0x10',
    -0, -1, -1n, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '18446744073709551616', 1n << 64n];
  for (const value of bad) {
    for (const invoke of [
      () => h.wallet.genesisContribution(value, recipient),
      () => h.wallet.send(0, 1, value, undefined, 0),
      () => h.wallet.sendInterChannel(8, 1, value, {}, 0, 0),
      () => h.wallet.burnSend(value, recipient, 0, 0),
    ]) assert.throws(invoke, /amount/);
  }
  assert.equal(h.loads(), 0);
});

test('recipient/local-token/base-token/destination/nonce inputs cannot be truncated or coerced by WASM glue', () => {
  const h = harness();
  for (const value of [false, true, '', '1', '01', '0x1', [], {}, -0, -1, 0.5, NaN, Infinity, 1n]) {
    assert.throws(() => h.wallet.send(0, value, '1', undefined, 0), /recipientSlot/);
    assert.throws(() => h.wallet.send(0, 1, '1', undefined, value), /tokenSlot/);
    assert.throws(() => h.wallet.refresh(0, value), /tokenSlot/);
    assert.throws(() => h.wallet.sendInterChannel(value, 1, '1', {}, 0, 0), /toChannel/);
    assert.throws(() => h.wallet.sendInterChannel(8, value, '1', {}, 0, 0), /toSlot/);
    assert.throws(() => h.wallet.sendInterChannel(8, 1, '1', {}, value, 0), /tokenIndex/);
    assert.throws(() => h.wallet.burnSend('1', recipient, value, 0), /tokenIndex/);
    assert.throws(() => h.wallet.burnSend('1', recipient, 0, value), /base nonce/);
  }
  for (const value of [1024, 65536]) {
    assert.throws(() => h.wallet.send(0, value, '1'), /recipientSlot/);
    assert.throws(() => h.wallet.sendInterChannel(8, value, '1', {}, 0, 0), /toSlot/);
  }
  for (const value of [10, 256]) {
    assert.throws(() => h.wallet.refresh(0, value), /tokenSlot/);
    assert.throws(() => h.wallet.withdrawalClaim({}, value), /tokenSlot/);
  }
  for (const value of [0, 0xffffffff, 0x100000000]) {
    assert.throws(() => h.wallet.sendInterChannel(value, 1, '1', {}, 0, 0), /toChannel/);
  }
  assert.throws(() => h.wallet.burnSend('1', recipient, 0x100000000, 0), /tokenIndex/);
  assert.throws(() => h.wallet.burnSend('1', recipient, 0, 0x100000000), /base nonce/);
  assert.equal(h.loads(), 0);
});
