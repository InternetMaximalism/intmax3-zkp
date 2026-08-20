'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  DEVNET_CHAIN_ID,
  l1SignerArgsForChain,
} = require('../../api/lib/cli');

const ANVIL_DEV_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const SECRET =
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';

test('local Anvil may use only the explicit/local throwaway raw-key path', () => {
  assert.deepEqual(l1SignerArgsForChain(DEVNET_CHAIN_ID, {}), [
    '--private-key',
    ANVIL_DEV_KEY,
  ]);
  assert.deepEqual(
    l1SignerArgsForChain(DEVNET_CHAIN_ID, { INTMAX_DEPOSIT_KEY: SECRET }),
    ['--private-key', SECRET],
  );
});

test('a real chain emits an account selector and never emits key material', () => {
  const argv = l1SignerArgsForChain(11155111, {
    INTMAX_L1_ACCOUNT: 'sepolia-operator_1',
    ETH_PASSWORD: 'not-an-argv-value',
  });
  assert.deepEqual(argv, ['--account', 'sepolia-operator_1']);
  assert.equal(argv.includes('not-an-argv-value'), false);
  assert.equal(argv.some((v) => v.includes('private-key')), false);
});

test('a real chain refuses both a raw key and a missing keystore account', () => {
  assert.throws(
    () => l1SignerArgsForChain(1, { INTMAX_DEPOSIT_KEY: SECRET }),
    /INTMAX_DEPOSIT_KEY is forbidden.*process argv/,
  );
  assert.throws(
    () => l1SignerArgsForChain(1, {}),
    /INTMAX_L1_ACCOUNT is required.*process argv/,
  );
});

test('account names cannot be parsed as flags or paths', () => {
  for (const bad of ['--aws', '../key', '/tmp/key', '', 'name with spaces']) {
    if (bad === '') continue; // Empty is covered by the missing-account assertion above.
    assert.throws(
      () => l1SignerArgsForChain(11155111, { INTMAX_L1_ACCOUNT: bad }),
      /keystore filename/,
    );
  }
});
