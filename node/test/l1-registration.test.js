'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { toBeHex, ZeroHash, ZeroAddress } = require('ethers');
const { abi, registrationHash, verifyRegistration } = require('../common/l1-registration');
function fixture() {
  const snapshot = { record: { channelId: 7, bpMemberSlot: 0, memberCount: 2 }, members: [0, 1].map(slot => ({ slot, pkG: toBeHex(slot+1,32), pkB: toBeHex(slot+3,32) })), state: { balanceState: { regevPkDigests: [toBeHex(5,32),toBeHex(6,32)], recipients: [toBeHex(7,20),toBeHex(8,20)] } } };
  const status = { channelRegHashChain: ZeroHash, registeredChannelCount: 0 };
  const hash = registrationHash(snapshot, ZeroHash);
  const event = abi.encodeEventLog(abi.getEvent('ChannelRegistered'), [0,7,0,[],[],[],ZeroHash,ZeroHash,hash]);
  return {snapshot,status,logs:[event],hash};
}
test('accepts the exact L1 registration before admitting the local record', () => {
  const f=fixture(); assert.equal(verifyRegistration(f.snapshot,f.status,f.logs),f.hash);
});
test('different key hash, recipient, or previous registration cannot enter producer history', () => {
  for (const change of [f=>f.snapshot.state.balanceState.regevPkDigests[0]=toBeHex(99,32),f=>f.snapshot.state.balanceState.recipients[0]=ZeroAddress,f=>f.status.channelRegHashChain=toBeHex(99,32),f=>f.status.registeredChannelCount=1]) {
    const f=fixture();change(f);assert.throws(()=>verifyRegistration(f.snapshot,f.status,f.logs),/does not match/);
  }
});
test('missing, duplicate and removed registration events fail closed', () => {
  const f=fixture();
  for(const logs of [[],[...f.logs,...f.logs],[{...f.logs[0],removed:true}]]) assert.throws(()=>verifyRegistration(f.snapshot,f.status,logs),/does not match/);
});
