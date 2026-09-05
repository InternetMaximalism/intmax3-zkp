'use strict';

const wire = require('../../node/common/wire');
const cliModule = require('./cli');

function uint(value, maximum, label) {
  if ((typeof value !== 'string' && typeof value !== 'number')
      || (typeof value === 'number' && !Number.isSafeInteger(value))
      || !/^(0|[1-9][0-9]*)$/.test(String(value))) {
    throw new Error(`${label} must be a canonical unsigned integer`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) throw new Error(`${label} is out of range`);
  return parsed;
}

function depositAmount(value) {
  const amount = uint(value, (1n << 64n) - 1n, 'deposit amount');
  if (amount === 0n) throw new Error('deposit amount must be positive');
  return amount.toString();
}

function tokenIndex(value = 0) {
  return Number(uint(value, 0xffffffffn, 'tokenIndex'));
}

function recipientSlot(value) {
  return Number(uint(value, 1023n, 'recipientSlot'));
}

function address(value, label) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)
      || /^0x0{40}$/i.test(value)) throw new Error(`${label} must be a nonzero address`);
  return value.toLowerCase();
}

// A rejoin keeps its original slot. Match every public identity component, never the last
// array element, and check the recipient before the operator can spend any L1 funds.
function resolveContributionSlot(snapshot, contribution) {
  const pkG = wire.bytes32(wire.field(contribution, 'pkG', 'pk_g'));
  const pkB = wire.bytes32(wire.field(contribution, 'pkB', 'pk_b'));
  const regevPk = wire.field(contribution, 'regevPk', 'regev_pk');
  const recipient = address(contribution && contribution.recipient, 'contribution recipient');
  if (!pkG || !pkB || !regevPk || typeof regevPk !== 'object') {
    throw new Error('contribution must carry its complete public identity');
  }
  const balance = wire.balanceState(snapshot && snapshot.state);
  const active = Number(uint(wire.field(balance, 'memberCount', 'member_count'), 1024n, 'memberCount'))
    + Number(uint(wire.field(balance, 'delegateCount', 'delegate_count'), 1024n, 'delegateCount'));
  if (active < 1 || active > 1024 || !Array.isArray(snapshot.members)) {
    throw new Error('snapshot has no valid active participant set');
  }
  const matches = snapshot.members.filter(member => (
    wire.bytes32(wire.field(member, 'pkG', 'pk_g')) === pkG
  ));
  if (matches.length !== 1) throw new Error('contribution identity is missing or ambiguous in snapshot');
  const member = matches[0];
  const slot = recipientSlot(member.slot);
  const recordPkGs = wire.field(snapshot.record, 'memberPkGs', 'member_pk_gs');
  if (slot >= active
      || wire.bytes32(wire.field(member, 'pkB', 'pk_b')) !== pkB
      || wire.canonical(wire.field(member, 'regevPk', 'regev_pk')) !== wire.canonical(regevPk)
      || !Array.isArray(recordPkGs) || wire.bytes32(recordPkGs[slot]) !== pkG
      || !Array.isArray(balance.recipients)
      || address(balance.recipients[slot], 'signed recipient') !== recipient) {
    throw new Error('rejoined contribution identity or recipient differs from its exact signed slot');
  }
  return slot;
}

function preflightDeposit(ch, slot, index, amount, depositor, reservation = null) {
  const requestedSlot = slot == null ? null : recipientSlot(slot);
  const token = tokenIndex(index);
  const value = depositAmount(amount);
  const file = 'l1_deposit_preflight.json';
  // Refresh the public projection from the locked native wallet, not a caller-supplied snapshot.
  cliModule.cli(ch, ['publish-snapshot', 'channel_snapshot.json']);
  const args = ['preflight-l1-deposit', requestedSlot == null ? 'auto' : String(requestedSlot),
    String(token), value, file];
  if (reservation) args.push('--reservation', reservation);
  cliModule.cli(ch, args);
  const checked = cliModule.readJson(cliModule.wc(ch, file));
  if (!checked || checked.schemaVersion !== 1 || Number(checked.channelId) !== ch
      || !wire.bytes32(checked.stateDigest) || checked.tokenIndex !== token || checked.amount !== value
      || !Array.isArray(checked.recipientSlots) || checked.recipientSlots.length === 0) {
    throw new Error('native deposit preflight returned a mismatched acceptance decision');
  }
  let slots = checked.recipientSlots.map(recipientSlot);
  if (new Set(slots).size !== slots.length
      || (requestedSlot != null && (slots.length !== 1 || slots[0] !== requestedSlot))) {
    throw new Error('native deposit preflight changed the requested recipient slot');
  }
  // Native import binds a participant depositor to that participant, even on operator routes.
  // Apply the same rule before spending; the allow-unbound option relaxes only an unbound payer.
  const snapshot = cliModule.readJson(cliModule.wc(ch, 'channel_snapshot.json'));
  if (wire.bytes32(snapshot && snapshot.state && snapshot.state.digest) !== checked.stateDigest.toLowerCase()) {
    throw new Error('deposit preflight no longer names the canonical signed head');
  }
  const balance = wire.balanceState(snapshot.state);
  const active = Number(wire.field(balance, 'memberCount', 'member_count'))
    + Number(wire.field(balance, 'delegateCount', 'delegate_count'));
  const payer = address(depositor, 'L1 depositor');
  const bound = balance.recipients.slice(0, active)
    .flatMap((recipient, i) => String(recipient).toLowerCase() === payer ? [i] : []);
  if (bound.length > 1) throw new Error('L1 depositor is bound to more than one participant');
  if (bound.length === 1) slots = slots.filter(i => i === bound[0]);
  if (slots.length === 0) throw new Error('L1 depositor binding has no safe requested recipient slot');
  return { ...checked, recipientSlots: slots };
}

module.exports = { depositAmount, tokenIndex, recipientSlot, resolveContributionSlot, preflightDeposit };
