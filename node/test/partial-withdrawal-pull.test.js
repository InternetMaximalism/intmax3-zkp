'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {pullTransaction,verifyPull}=require('../common/partial-withdrawal-pull');
const recipient='0x0000000000000000000000000000000000000001',rollup='0x0000000000000000000000000000000000000002';
function fixture() {
 const claim={...pullTransaction({withdrawal_amount:'5000000000000000',withdrawal_token_index:0,withdrawal_recipient:recipient},rollup),afterBlock:'0x10'};
 const tx={hash:'0xabc',from:recipient,to:rollup,input:claim.data,value:'0x0',blockHash:'0xdef'};
 const receipt={transactionHash:tx.hash,status:'0x1',blockHash:tx.blockHash,blockNumber:'0x11'};
 return {claim,tx,receipt,block:{hash:tx.blockHash}};
}
test('a settled native payout is received only by its exact successful wallet call',()=>{
 const f=fixture();assert.doesNotThrow(()=>verifyPull(f.claim,f.tx,f.receipt,f.block));
 assert.equal(f.claim.data.slice(0,10),'0x2e1a7d4d');
});
test('wrong recipient, amount, rollup, reverted/reorged/old receipts are rejected',()=>{
 for(const change of [f=>f.tx.from=rollup,f=>f.tx.to=recipient,f=>f.tx.input='0x',f=>f.receipt.status='0x0',f=>f.block.hash='0xother',f=>f.receipt.blockNumber='0x9']){
  const f=fixture();change(f);assert.throws(()=>verifyPull(f.claim,f.tx,f.receipt,f.block),/does not match/);
 }
});
test('token withdrawals use the token-specific call with exact base units',()=>{
 const c=pullTransaction({withdrawal_amount:'10000000',withdrawal_token_index:1,withdrawal_recipient:recipient},rollup);
 assert.equal(c.data.slice(0,10),'0xcf2cd298');assert.equal(c.amount,'10000000');
 assert.throws(()=>pullTransaction({withdrawal_amount:1e18,withdrawal_token_index:0,withdrawal_recipient:recipient},rollup),/inexact/);
});
