'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('vm'),fs=require('fs'),path=require('path');
const html=fs.readFileSync(path.join(__dirname,'../../hosting/wallet/wallet-live.html'),'utf8');
const start=html.indexOf('async function resumeInterSend('),end=html.indexOf('// ---- SEND token selector',start);
// The page's relay-refusal helpers (relayError, untilBacked) that the resume paths run through.
const helpers=html.slice(html.indexOf('// A relay refusal, keeping what the wallet acts on'),html.indexOf('// ---- UI updates'));
function harness({failed=false,wrong=false,verifyFailed=false,backingPending=0}={}){
 const saved={version:1,channel:7,chainId:31337,rollup:'rollup',identity:'identity',body:'exact original proof'};let requests=0,cleared=0,verified=0;
 const context={fetchDeploymentInfo:async()=>({chainId:31337,rollup:'rollup'}),myChannel:7,activeCh:7,sha256Hex:async()=>wrong?'wrong':'identity',localStorage:{getItem:()=>''},SEED_KEY:'seed',log(){},sendOutboxKey:()=>7,
 fetch:async(_,options)=>{requests++;assert.equal(options.body,saved.body);
  if(backingPending-->0)return {ok:false,status:409,text:async()=>JSON.stringify({error:'HEAD BACKING NOT FINALIZED',backingPending:true,kitPending:true})};
  return {ok:!failed,status:failed?500:200,text:async()=>JSON.stringify(failed?{error:'lost'}:{sourceHead:{digest:'accepted'}})};},
 setTimeout:fn=>setImmediate(fn),
 api:async()=>JSON.stringify({state:{digest:'verified'}}),call:async()=>{if(verifyFailed)throw Error('signature failed');verified++;return JSON.stringify({slot:3});},setChannelFrom(){},walletOutbox:{clear:async()=>{assert.equal(verified,1);cleared++;}}};
 // The page's own-slot import: fetch our view and verify it in WASM (here: the mocked call).
 context.importMyView=async()=>JSON.parse(await context.call('importView',{viewJson:'own slot view'}));
 vm.createContext(context);vm.runInContext(helpers + html.slice(html.indexOf('async function validateSavedSend('),html.indexOf('async function resumeSoloSend(')) + html.slice(start,end),context);return {run:()=>context.resumeInterSend(saved),counts:()=>({requests,cleared})};
}
test('retry replays the exact persisted proof and clears only after verified state import',async()=>{const h=harness();await h.run();assert.deepEqual(h.counts(),{requests:1,cleared:1});});
test('uncertain send response retains its request for the same Send button',async()=>{const h=harness({failed:true});await assert.rejects(h.run(),/lost/);assert.equal(h.counts().cleared,0);});
test('changed channel identity cannot submit a saved request',async()=>{const h=harness({wrong:true});await assert.rejects(h.run(),/another account/);assert.equal(h.counts().requests,0);});
test('unverified snapshot never clears an accepted send recovery record',async()=>{const h=harness({verifyFailed:true});await assert.rejects(h.run(),/signature failed/);assert.equal(h.counts().cleared,0);});

// C25/G16: a transfer refused because the channel's head is not finalized on L1 yet was not
// signed; the wallet re-sends the SAME saved request until the relay accepts it.
test('a transfer waiting for L1 finality re-sends the same saved request until it is accepted',async()=>{
 const h=harness({backingPending:2});await h.run();assert.deepEqual(h.counts(),{requests:3,cleared:1});
});
