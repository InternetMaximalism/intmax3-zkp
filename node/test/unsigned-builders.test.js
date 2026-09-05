'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

// A cheap source sentinel, not a substitute for the Rust happy-path tests: proposal
// construction must never release a channel-state signature before host admission.
const source = fs.readFileSync(path.join(__dirname, '../../src/wallet_core.rs'), 'utf8');

function publicFunction(name) {
  const start = source.indexOf(`pub fn ${name}(`);
  assert.notEqual(start, -1, `missing proposal builder ${name}`);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `missing top-level function end for ${name}`);
  return source.slice(start, end + 2);
}

const builders = [
  'build_send_token',
  'build_refresh',
  'build_inter_channel_send_token_at_base_nonce',
  'build_inter_channel_credit',
  'build_l1_deposit_import',
  'build_token_register',
];

for (const name of builders) {
  test(`${name} does not sign a channel-state proposal`, () => {
    assert.doesNotMatch(
      publicFunction(name),
      /\b(?:sign_state|sign_state_if_backed|sign_member_if_present|add_signature)\s*\(/,
      'state signing belongs to the explicit checked co-signing boundary',
    );
  });
}

for (const name of ['build_send_token', 'build_inter_channel_send_token_at_base_nonce']) {
  test(`${name} retains the sender's separate A11 transaction authorization`, () => {
    assert.match(publicFunction(name), /\bsign_channel_tx_sender\s*\(/);
  });
}
