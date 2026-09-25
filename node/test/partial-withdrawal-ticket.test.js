'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('module'),path=require('path');
// Recovery semantics are exercised against real durable files in burn-operation.test.js.
// Both API aliases must use that same owner, including the empty-body resume request.
for (const [file,endpoint] of [['burn','/cosign'],['partial-withdrawal','/burn']]) {
 test(`${file}: routes fresh and resumed burns through the durable owner`,async()=>{
  let handler,seen,active={id:'pw_test',params:{producerRequestId:'burn:test'}};
  const owner={run:async(ch,input,store)=>{seen={ch,input};assert.equal(store.getTicket(ch,'pw_test'),active);return {digest:'signed'};},result:()=>({id:'burn:test',blockReceipt:{block:1},liveReceipt:{baseNonce:2}})};
  const load=Module._load;
  Module._load=function(request,parent,isMain){
   if(request==='express')return {Router:()=>({post:(url,fn)=>{if(url===endpoint)handler=fn;}})};
   if(request==='../lib/burn-operation')return {createBurnOperations:()=>owner};
   if(request==='../lib/lock')return {withLock:(_,fn)=>Promise.resolve().then(fn)};
   if(request==='../lib/tickets')return {findActiveTicket:()=>active,readTickets:()=>[active],upsertTicket:()=>{}};
   return load.call(this,request,parent,isMain);
  };
  try {const absolute=path.resolve(__dirname,`../../api/routes/${file}.js`);delete require.cache[absolute];require(absolute);}finally{Module._load=load;}
  for(const body of [{debitPayload:{proof:'original'},transferDescriptor:{}},{}]) {
   let response;handler({params:{ch:'7'},body},{json:value=>{response=value;},status:()=>{throw Error('unexpected error');}});
   await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(seen,{ch:7,input:body});assert.deepEqual(response,{state:{digest:'signed'},ticket:active,blockReceipt:{block:1},liveReceipt:{baseNonce:2}});
  }
 });
}
