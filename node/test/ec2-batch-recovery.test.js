'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), path = require('path'), vm = require('vm');
const source = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-relay-ec2.js'), 'utf8');
const functions = source.slice(source.indexOf('const COALESCE_MS'), source.indexOf('// ---- Ticket persistence'));

for (const failPublication of [false, true]) test(`EC2 batch output loss recovers fat and slim without another signature (${failPublication})`, async () => {
  let committed = false, signatures = 0;
  const signed = {digest:'batch',balanceState:{stateVersion:9}};
  const context = {
    process:{pid:1,env:{COSIGN_COALESCE_MS:'1'}},setTimeout,path,
    console:{log(){},error(){}},chDir:()=>'/ch',wc:(_,file)=>'/ch/'+file,
    require:()=>({projectToSlim:p=>p}),
    withLock:(_,fn)=>fn(),
    sendReceipts:{fatId:p=>p.id,accepted:()=>committed?signed:null},
    fs:{mkdirSync(){},writeFileSync(){},rm(){},readFileSync:file=>{
      if(file.endsWith('channel_snapshot.json')) return JSON.stringify({state:{digest:committed?'batch':'old'}});
      throw Error('output missing after committed signature');
    }},
    cli:async(_,args)=>{
      if(args[0]==='publish-snapshot') {if(failPublication)throw Error('publication unavailable');return;}
      signatures++;committed=true;
    },
  };
  vm.createContext(context);vm.runInContext(functions,context);
  const results=await Promise.allSettled([
    context.enqueueCosign(7,{kind:'fat',payload:{id:'fat',proposedNextState:{prevDigest:'old'}}}),
    context.enqueueCosign(7,{kind:'slim',anchor:'old',file:'/ch/slim.json',requestId:'slim'}),
  ]);
  assert.equal(signatures,1);
  for(const result of results) {
    if(failPublication) {assert.equal(result.status,'rejected');assert.match(result.reason.message,/publication unavailable/);}
    else {assert.equal(result.status,'fulfilled');assert.equal(JSON.parse(result.value).digest,'batch');}
  }
});
