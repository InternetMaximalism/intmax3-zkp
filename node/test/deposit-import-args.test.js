'use strict';
// L1 deposit-import argv construction (cosigner NORMAL branch).
//
// WHAT THESE TESTS ARE MEANT TO PROVE ABOUT SECURITY
//   Before the fix, this branch forwarded the DECODED ECONOMIC FIELDS (depositor, amount,
//   tokenIndex) as positional CLI argv, and the CLI trusted them. Any caller that could reach the
//   CLI could therefore mint unbacked in-channel balance. The fix removes those fields from the
//   interface entirely: the handler now forwards only the observed TRANSACTION HASH, and the CLI
//   reads the economics from that transaction's on-chain `Deposited` log.
//
//   So these tests assert two different kinds of property:
//     * shape tests      — the txHash and rpc become positional argv, so anything flag-like or
//                          malformed must be REFUSED rather than passed through (a leading '-'
//                          would otherwise be read by the CLI as an option, and
//                          `--allow-unbound-depositor` in particular must never be injectable
//                          from chain-observed or file-sourced data).
//     * absence tests    — the built argv must contain NO amount, NO depositor and NO token
//                          index. This is the actual fix: a field that is not in the command
//                          cannot be lied about. A regression that re-adds them would restore the
//                          vulnerability, so it is pinned as a negative here.
//
//   `recipientSlot` defaults to the string 'auto' because the chain's `Deposited` event carries
//   no slot. 'auto' makes the CLI resolve the credited slot from the depositor's B-1b bound exit
//   address (refusing when unbound/ambiguous). The OLD code silently defaulted to slot 0, which
//   credited the wrong member.

const test = require('node:test');
const assert = require('node:assert');

const { depositImportArgs } = require('../cosigner/branches/deposit');

const TX = '0x' + 'ab'.repeat(32);
const RPC = 'http://127.0.0.1:8545';

test('happy path builds argv from the tx hash alone', () => {
  const { args, error } = depositImportArgs({ txHash: TX, rpc: RPC });
  assert.strictEqual(error, undefined);
  assert.deepStrictEqual(args, [
    'cosign-l1-deposit-import', 'auto', TX, RPC, 'l1_import_cosigned.json',
  ]);
});

test('THE FIX: no economic field is ever forwarded', () => {
  // Even when the observed event carries them, they must not reach the CLI.
  const { args } = depositImportArgs({
    txHash: TX, rpc: RPC, recipientSlot: 2,
    depositor: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', amount: '999999', tokenIndex: '1',
  });
  const joined = args.join(' ');
  assert.ok(!joined.includes('999999'), 'amount must not appear in argv');
  assert.ok(!joined.includes('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'), 'depositor must not appear in argv');
  assert.strictEqual(args.length, 5, 'argv is exactly <cmd> <slot> <tx> <rpc> <out>');
});

test('an explicit recipientSlot is used instead of auto', () => {
  const { args } = depositImportArgs({ txHash: TX, rpc: RPC, recipientSlot: 3 });
  assert.strictEqual(args[1], '3');
});

test('the escape-hatch flag can never be injected', () => {
  // No input combination may produce --allow-unbound-depositor: only a human operator passes it.
  for (const recipientSlot of ['--allow-unbound-depositor', '-1', 'auto', 1e9, NaN]) {
    const { args } = depositImportArgs({ txHash: TX, rpc: RPC, recipientSlot });
    if (args) assert.ok(!args.includes('--allow-unbound-depositor'), `injected via slot ${recipientSlot}`);
  }
  const { args } = depositImportArgs({ txHash: TX, rpc: RPC });
  assert.ok(!args.includes('--allow-unbound-depositor'));
});

test('malformed tx hashes are refused', () => {
  for (const txHash of [undefined, null, '', '0x', 'not-a-hash', '0x' + 'ab'.repeat(31),
    '0x' + 'ab'.repeat(33), '-' + TX, TX + ' --allow-unbound-depositor', 'ab'.repeat(32)]) {
    const r = depositImportArgs({ txHash, rpc: RPC });
    assert.ok(r.error, `must refuse txHash ${JSON.stringify(txHash)}`);
    assert.strictEqual(r.args, undefined);
  }
});

test('out-of-range or non-integer slots are refused', () => {
  for (const recipientSlot of [-1, 1024, 99999, 1.5, 'abc']) {
    const r = depositImportArgs({ txHash: TX, rpc: RPC, recipientSlot });
    assert.ok(r.error, `must refuse slot ${recipientSlot}`);
  }
});

test('slot boundaries: 0 and 1023 are accepted', () => {
  assert.strictEqual(depositImportArgs({ txHash: TX, rpc: RPC, recipientSlot: 0 }).args[1], '0');
  assert.strictEqual(depositImportArgs({ txHash: TX, rpc: RPC, recipientSlot: 1023 }).args[1], '1023');
});

test('a flag-like or missing rpc url is refused', () => {
  for (const rpc of [undefined, '', '--rpc-url', '-x', 'http://h/ ;rm -rf']) {
    const r = depositImportArgs({ txHash: TX, rpc });
    assert.ok(r.error, `must refuse rpc ${JSON.stringify(rpc)}`);
  }
});

test('a hash differing only in case is still accepted (hex is case-insensitive)', () => {
  const upper = '0x' + 'AB'.repeat(32);
  assert.strictEqual(depositImportArgs({ txHash: upper, rpc: RPC }).args[2], upper);
});
