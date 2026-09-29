'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {assertJoinIdentity}=require('../common/wallet-join-identity');
const snapshot={record:{channelId:17,memberCount:1},members:[{slot:0,pkG:'operator'},{slot:1,pkG:'saved-key'}],state:{balanceState:{recipients:['operator-address','0x4760']}}};
test('the registered channel key and recipient may resume a join while a deployment is in flight',()=>{
 assert.doesNotThrow(()=>assertJoinIdentity(snapshot,{pkG:'saved-key',recipient:'0x4760'},true));
});
test('same MetaMask address never authorizes replacement channel keys',()=>{
 assert.throws(()=>assertJoinIdentity(snapshot,{pkG:'new-key',recipient:'0x4760'},true),e=>e.status===409&&e.code==='CHANNEL_KEY_MISMATCH');
});
test('a new delegate key is paused only while a settlement deployment is in flight',()=>{
 assert.throws(()=>assertJoinIdentity(snapshot,{pkG:'new-key',recipient:'0x9d4f'},true),e=>e.status===409&&e.code==='SETTLEMENT_DEPLOYING');
});
test('a matching channel key still requires the intended connected recipient',()=>{
 assert.throws(()=>assertJoinIdentity(snapshot,{pkG:'saved-key',recipient:'0x9d4f'},true),e=>e.code==='WALLET_ACCOUNT_MISMATCH');
});
test('a new delegate joins whenever no deployment is in flight — before or after settlement',()=>{
 assert.doesNotThrow(()=>assertJoinIdentity(snapshot,{pkG:'new-key',recipient:'0x9d4f'},false));
});
