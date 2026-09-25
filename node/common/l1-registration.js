'use strict';
const { keccak256, concat, toBeHex, zeroPadValue, Interface } = require('ethers');
const abi = new Interface(['event ChannelRegistered(uint64 indexed regIndex,uint32 indexed channelId,uint8 bpMemberSlot,bytes32[] memberPkGs,bytes32[] regevPkDigests,address[] recipients,bytes32 memberPubkeysRoot,bytes32 regevPkRoot,bytes32 newChannelRegHashChain)']);
function registrationHash(snapshot, previous) {
  const r = snapshot.record, b = snapshot.state.balanceState;
  if (r.memberCount < 2 || r.memberCount > 8) throw new Error('unsupported registration member count');
  const parts = [previous, toBeHex(r.channelId, 4), toBeHex(r.bpMemberSlot, 4), toBeHex(r.memberCount, 4), toBeHex(0, 4)];
  for (let slot = 0; slot < 8; slot++) {
    if (slot >= r.memberCount) { parts.push(new Uint8Array(116)); continue; }
    const member = snapshot.members.find(m => m.slot === slot);
    if (!member) throw new Error(`missing registration member ${slot}`);
    parts.push(member.pkG, member.pkB, b.regevPkDigests[slot], b.recipients[slot]);
  }
  return keccak256(concat(parts));
}
function verifyRegistration(snapshot, status, logs) {
  const expected = registrationHash(snapshot, status.channelRegHashChain);
  const matches = logs.filter(l => !l.removed).map(l => abi.parseLog(l))
    .filter(l => Number(l.args.channelId) === snapshot.record.channelId);
  if (matches.length !== 1 || matches[0].args.newChannelRegHashChain.toLowerCase() !== expected.toLowerCase()
      || Number(matches[0].args.regIndex) !== Number(status.registeredChannelCount)) {
    throw new Error('L1 channel registration does not match the producer history; refusing local registration');
  }
  return expected;
}
function topics(ch) { return [abi.getEvent('ChannelRegistered').topicHash, null, zeroPadValue(toBeHex(ch), 32)]; }
module.exports = { registrationHash, verifyRegistration, topics, abi };
