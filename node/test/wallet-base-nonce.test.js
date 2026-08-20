'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Wallet } = require('../common/wallet');

test('inter-channel wrapper requires and forwards the persisted base nonce', () => {
  const wallet = new Wallet();
  let args;
  wallet._load = () => ({
    wallet_send_inter_channel(...values) { args = values; return '{}'; },
  });
  assert.throws(
    () => wallet.sendInterChannel(8, 0, 5, { pkG: 'x' }, 3),
    /current uint32 base nonce is required/,
  );
  wallet.sendInterChannel(8, 0, 5, { pkG: 'x' }, 3, 17);
  assert.equal(args[5], 17);
});

test('burn wrapper requires and forwards the persisted base nonce', () => {
  const wallet = new Wallet();
  let args;
  wallet._load = () => ({
    wallet_burn_send(...values) { args = values; return '{}'; },
  });
  assert.throws(
    () => wallet.burnSend(5, '0x0000000000000000000000000000000000000001', 0),
    /current uint32 base nonce is required/,
  );
  wallet.burnSend(5, '0x0000000000000000000000000000000000000001', 0, 23);
  assert.equal(args[3], 23);
});
