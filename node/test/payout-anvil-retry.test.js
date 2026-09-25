'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {finalizeSavedPayout}=require('../../api/lib/partial-withdrawal-live');
const transient='error: cast ["call", "manager", "partialWithdrawalPending()", "--block", "0x36b"] failed: BlockOutOfRangeError';
test('Anvil historical read lag resumes the same journaled payout command',async()=>{
 const calls=[],waits=[];
 const result=await finalizeSavedPayout(7,{rpc:'http://localhost:8560',env:{INTMAX_WALLET_ANVIL_MINE:'1'},wait:async ms=>waits.push(ms),run:(...args)=>{calls.push(args);if(calls.length===1)throw Error(transient);return 'done';}});
 assert.equal(result,'done');assert.deepEqual(calls[0],calls[1]);assert.deepEqual(waits,[1000]);
});
for(const [label,env,message] of [
 ['public network',{},transient],
 ['transaction error',{INTMAX_WALLET_ANVIL_MINE:'1'},'cast ["send", "manager"] failed: BlockOutOfRangeError'],
 ['proof failure',{INTMAX_WALLET_ANVIL_MINE:'1'},'invalid payout proof'],
]) test(`payout retries do not hide ${label}`,async()=>{
 let calls=0;await assert.rejects(finalizeSavedPayout(7,{env,run:()=>{calls++;throw Error(message);},wait:async()=>{throw Error('unexpected wait');}}));assert.equal(calls,1);
});
test('persistent historical failure has a bounded retry budget',async()=>{
 let calls=0;await assert.rejects(finalizeSavedPayout(7,{env:{INTMAX_WALLET_ANVIL_MINE:'1'},run:()=>{calls++;throw Error(transient);},wait:async()=>{}}),/BlockOutOfRangeError/);assert.equal(calls,3);
});
