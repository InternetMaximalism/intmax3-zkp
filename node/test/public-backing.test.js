'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { publicBacking, baseHead } = require('../common/public-backing');

test('publicBacking is an allowlist and never returns base private state or salts', () => {
  const raw = {
    fund: 9,
    rollup: '0xrollup',
    settled_tx_chain: '0xchain',
    intmax_state_root: '0xroot',
    deposit_recipient: '0xrecipient',
    deposit_salt: { value: 'secret' },
    base_private_state: { nonce: 7, asset_tree: ['secret'], salt: 'secret' },
    unexpected_future_secret: 'secret',
  };
  assert.deepEqual(publicBacking(raw), {
    settled_tx_chain: '0xchain',
    intmax_state_root: '0xroot',
    fund: 9,
    rollup: '0xrollup',
    deposit_recipient: '0xrecipient',
  });
});

test('baseHead exposes only the public cursor and roots', () => {
  const raw = {
    settled_tx_chain: '0xchain',
    intmax_state_root: '0xroot',
    base_private_state: { nonce: 7, asset_tree: ['secret'], salt: 'secret' },
  };
  assert.deepEqual(baseHead(raw), {
    schemaVersion: 1,
    nonce: 7,
    settledTxChain: '0xchain',
    intmaxStateRoot: '0xroot',
  });
  assert.doesNotMatch(JSON.stringify(baseHead(raw)), /secret|asset_tree|salt/);
});

test('baseHead fails closed for legacy backing without a private cursor', () => {
  assert.throws(() => baseHead({ fund: 1 }), /migrate the channel backing/);
  assert.throws(() => baseHead({ basePrivateState: { nonce: -1 } }), /migrate/);
});
