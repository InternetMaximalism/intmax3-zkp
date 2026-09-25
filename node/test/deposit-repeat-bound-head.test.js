'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),path=require('path'),vm=require('vm');
const source=fs.readFileSync(path.join(__dirname,'../../api/lib/deposit-pipeline.js'),'utf8');
const helper=source.slice(source.indexOf('async function bindDepositSnapshot('),source.indexOf('async function flushLastDepositImport('));
for(const [name,status,binds] of [
 ['already bound burn head',{signedHeadDigest:'0xab',awaitingChannelBinding:false},0],
 ['different signed head',{signedHeadDigest:'0xcd',awaitingChannelBinding:false},1],
 ['head still awaiting binding',{signedHeadDigest:'0xab',awaitingChannelBinding:true},1],
 ['no signed head',{signedHeadDigest:null,awaitingChannelBinding:false},1],
])test(name,async()=>{let calls=0;const c={producer:{liveStatus:async()=>status,liveBindSnapshot:async()=>{calls++;return {};}}};vm.createContext(c);vm.runInContext(helper,c);await c.bindDepositSnapshot(7,{state:{digest:'0xab',h2Tag:'nonzero'}});assert.equal(calls,binds);});
test('unavailable live authority never authorizes skipping validation',async()=>{let called=false;const c={producer:{liveStatus:async()=>{throw Error('unavailable');},liveBindSnapshot:async()=>called=true}};vm.createContext(c);vm.runInContext(helper,c);await assert.rejects(c.bindDepositSnapshot(7,{state:{digest:'0xab'}}),/unavailable/);assert.equal(called,false);});
