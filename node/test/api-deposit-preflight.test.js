'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-deposit-preflight-'));
process.env.INTMAX_WORK_DIR = work;
const cli = require('../../api/lib/cli');
const checks = require('../../api/lib/deposit-preflight');
const bytes = n => `0x${n.repeat(32)}`;
const recipient = n => `0x${n.repeat(20)}`;
function fixture() {
  const members = [0, 1, 2].map(slot => ({ slot, pkG: bytes(String(slot + 1).padStart(2, '0')),
    pkB: bytes(String(slot + 4).padStart(2, '0')), regevPk: { b: [slot + 1] } }));
  const recipients = ['11', '22', '33'].map(recipient);
  return { members, record: { memberPkGs: members.map(m => m.pkG) }, state: { digest: bytes('aa'),
    balanceState: { memberCount: 2, delegateCount: 1, recipients } } };
}
test.after(() => fs.rmSync(work, { recursive: true, force: true }));
test('deposit numbers are exact canonical protocol values before any spend', () => {
  assert.equal(checks.depositAmount('18446744073709551615'), '18446744073709551615');
  assert.equal(checks.tokenIndex('4294967295'), 4294967295);
  assert.equal(checks.recipientSlot('1023'), 1023);
  for (const amount of ['0', '-1', '01', '1.5', '18446744073709551616', Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => checks.depositAmount(amount));
  }
  for (const token of ['-1', '0.5', '4294967296']) assert.throws(() => checks.tokenIndex(token));
  assert.throws(() => checks.recipientSlot('1024'));
});
test('rejoin resolves the original exact identity, not the last participant', () => {
  const snapshot = fixture();
  const contribution = { ...snapshot.members[0], recipient: snapshot.state.balanceState.recipients[0] };
  assert.equal(checks.resolveContributionSlot(snapshot, contribution), 0);
  const reordered = { ...snapshot, members: [snapshot.members[2], snapshot.members[0], snapshot.members[1]] };
  assert.equal(checks.resolveContributionSlot(reordered, contribution), 0);
  for (const changed of [{ pkB: bytes('09') }, { regevPk: { b: [99] } }, { recipient: recipient('44') }]) {
    assert.throws(() => checks.resolveContributionSlot(snapshot, { ...contribution, ...changed }), /exact signed slot/);
  }
  assert.throws(() => checks.resolveContributionSlot({ ...snapshot, members: [...snapshot.members, snapshot.members[0]] }, contribution), /ambiguous/);
});
test('native preflight uses a fresh head and restricts a bound depositor to its own slot', () => {
  const snapshot = fixture();
  const calls = [];
  cli.cli = (ch, args) => {
    calls.push(args);
    if (args[0] === 'publish-snapshot') cli.writeJson(cli.wc(ch, args[1]), snapshot);
    else cli.writeJson(cli.wc(ch, 'l1_deposit_preflight.json'), { schemaVersion: 1, channelId: ch,
      stateDigest: snapshot.state.digest, recipientSlots: [0, 1, 2], tokenIndex: 0, amount: '9' });
  };
  const result = checks.preflightDeposit(7, null, 0, '9', recipient('22'), 'deposit:test');
  assert.deepEqual(result.recipientSlots, [1]);
  assert.equal(calls[0][0], 'publish-snapshot');
  assert.deepEqual(calls[1].slice(-2), ['--reservation', 'deposit:test']);
  assert.throws(() => checks.preflightDeposit(7, 0, 0, '9', recipient('22')), /requested recipient slot/);
});
