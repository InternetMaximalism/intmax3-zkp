'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {assertJoinIdentity}=require('../common/wallet-join-identity');
const snapshot={record:{channelId:17,memberCount:1},members:[{slot:0,pkG:'operator'},{slot:1,pkG:'saved-key'}],state:{balanceState:{recipients:['operator-address','0x4760']}}};
test('the registered channel key and recipient may resume a frozen join',()=>{
 assert.doesNotThrow(()=>assertJoinIdentity(snapshot,{pkG:'saved-key',recipient:'0x4760'},true));
});
test('same MetaMask address never authorizes replacement channel keys',()=>{
 assert.throws(()=>assertJoinIdentity(snapshot,{pkG:'new-key',recipient:'0x4760'},true),e=>e.status===409&&e.code==='CHANNEL_KEY_MISMATCH');
});
test('a different connected wallet gets the registered address instead of a native trace',()=>{
 assert.throws(()=>assertJoinIdentity(snapshot,{pkG:'new-key',recipient:'0x9d4f'},true),e=>e.code==='CHANNEL_MEMBERSHIP_FROZEN'&&e.message.includes('0x4760')&&e.message.includes('0x9d4f'));
});
test('a matching channel key still requires the intended connected recipient',()=>{
 assert.throws(()=>assertJoinIdentity(snapshot,{pkG:'saved-key',recipient:'0x9d4f'},true),e=>e.code==='WALLET_ACCOUNT_MISMATCH');
});
test('uncommitted channels still allow normal delegate joins',()=>{
 assert.doesNotThrow(()=>assertJoinIdentity(snapshot,{pkG:'new-key',recipient:'0x9d4f'},false));
});
