'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { routeEventChannelIds } = require('../common/chain-watcher');
const { targetRuntimeIds } = require('../cosigner/index');

const ROLLUP_A = '0x00000000000000000000000000000000000000a1';
const ROLLUP_B = '0x00000000000000000000000000000000000000b1';
const MANAGER_7 = '0x0000000000000000000000000000000000000007';
const MANAGER_8 = '0x0000000000000000000000000000000000000008';
const MANAGER_9 = '0x0000000000000000000000000000000000000009';
const RECIPIENT_7 = '0x' + '07'.repeat(32);
const RECIPIENT_8 = '0x' + '08'.repeat(32);

const channels = [
  { id: 7, rollup: ROLLUP_A, manager: MANAGER_7, depositRecipient: RECIPIENT_7 },
  { id: 8, rollup: ROLLUP_A, manager: MANAGER_8, depositRecipient: RECIPIENT_8 },
  { id: 9, rollup: ROLLUP_B, manager: MANAGER_9 },
];

test('manager events route only to the manager owner', () => {
  assert.deepEqual(routeEventChannelIds(channels, {
    contract: 'manager', address: MANAGER_8, kind: 'CloseSubmitted', args: {},
  }), [8]);
});

test('shared-rollup channel events use their decoded channelId', () => {
  assert.deepEqual(routeEventChannelIds(channels, {
    contract: 'rollup', address: ROLLUP_A, kind: 'BlockPosted', args: { channelId: '8' },
  }), [8]);
  assert.deepEqual(routeEventChannelIds(channels, {
    contract: 'rollup', address: ROLLUP_A, kind: 'BlockPosted', args: { channelId: '9' },
  }), []);
});

test('rollup manager events and configured deposit recipients route exactly', () => {
  assert.deepEqual(routeEventChannelIds(channels, {
    contract: 'rollup', address: ROLLUP_A, kind: 'PartialWithdrawalAuthorized',
    args: { manager: MANAGER_7 },
  }), [7]);
  assert.deepEqual(routeEventChannelIds(channels, {
    contract: 'rollup', address: ROLLUP_A, kind: 'Deposited', args: { recipient: RECIPIENT_8 },
  }), [8]);
});

test('genuinely global rollup events broadcast only within that rollup', () => {
  assert.deepEqual(routeEventChannelIds(channels, {
    contract: 'rollup', address: ROLLUP_A, kind: 'TokenRegistered', args: { tokenIndex: '1' },
  }), [7, 8]);
});

test('cosigner dispatch honors the normalized target set', () => {
  const runtimes = new Map([[7, {}], [8, {}], [9, {}]]);
  assert.deepEqual(targetRuntimeIds({ channelIds: [8, 8, 404], channelId: 7 }, runtimes), [8]);
  assert.deepEqual(targetRuntimeIds({ channelId: 9 }, runtimes), [9]);
  assert.deepEqual(targetRuntimeIds({}, runtimes), []);
});
