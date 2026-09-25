'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),os=require('os'),path=require('path');
const {fatId,accepted}=require('../../hosting/wallet/send-receipts');
function payload(){return {senderIndex:0,recipientIndex:1,channelTx:{tokenSlot:1,nonce:3,proof:{b:2,a:1}},proposedNextState:{prevDigest:'anchor',balanceState:{encBalances:[['other-token','after-ciphertext']]}}};}
test('acceptance identity binds exactly the signed token, nonce, proof and anchor',()=>{
 const p=payload(),id=fatId(p);const reordered=payload();reordered.channelTx.proof={a:1,b:2};assert.equal(fatId(reordered),id);
 for(const mutate of [p=>p.channelTx.tokenSlot=0,p=>p.channelTx.nonce++,p=>p.channelTx.proof.a++,p=>p.proposedNextState.prevDigest='changed',p=>p.recipientIndex=2,p=>p.proposedNextState.balanceState.encBalances[0][1]='changed']){const q=payload();mutate(q);assert.notEqual(fatId(q),id);}
});
test('historical batch acknowledgement survives later heads and rejects corrupt archive',t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'send-receipt-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const id=fatId(payload()),digest='0x'+'12'.repeat(32),state={digest,balanceState:{stateVersion:4}};
 assert.equal(accepted(dir,id),null);fs.mkdirSync(path.join(dir,'accepted_send_states'));
 const archive=path.join(dir,'accepted_send_states',digest+'.json');fs.writeFileSync(archive,JSON.stringify(state));
 assert.equal(accepted(dir,id),null,'uncommitted archive must not acknowledge payment');
 fs.writeFileSync(path.join(dir,'cli_state.json'),JSON.stringify({snapshot:{state:{digest:'later'}},accepted_send_receipts:{[id]:digest}}));
 assert.deepEqual(accepted(dir,id),state);assert.equal(accepted(dir,'ab'.repeat(32)),null);
 fs.writeFileSync(archive,JSON.stringify({...state,digest:'wrong'}));assert.throws(()=>accepted(dir,id),/differs/);
 fs.unlinkSync(archive);assert.throws(()=>accepted(dir,id),/ENOENT/);
});
