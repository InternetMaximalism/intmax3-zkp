'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),os=require('os'),path=require('path'),crypto=require('crypto');
const {createBurnOperations}=require('../../api/lib/burn-operation');
function fixture(t) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'burn-recovery-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const input={debitPayload:{proposedNextState:{channelId:7,digest:'signed',balanceState:{stateVersion:3}}},transferDescriptor:{proof:'original'},amount:'5',recipient:'recipient'};
  const calls={sign:0,producer:new Set(),live:new Set(),recover:0};
  const read=file=>JSON.parse(fs.readFileSync(file,'utf8'));
  const write=(file,value)=>{fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,JSON.stringify(value));};
  const cli={wc:(_,file)=>path.join(dir,file),readJson:read,writeJson:write,cli:()=>{
    calls.recover++; const wal=path.join(dir,'native-wal.json');if(fs.existsSync(wal))write(path.join(dir,'burn_cosigned.json'),read(wal));
  }};
  const bp={stableRequestId:(kind,value)=>kind+':'+crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex'),authoritativeBaseNonceEnv:async()=>({}),
    postInterChannel:async(_head,_payload,_descriptor,id)=>{calls.producer.add(id);return {id};},liveSettleInterChannel:async(_ch,receipt)=>calls.live.add(receipt.id)};
  let loseSign=false;
  const kit={cliWithPreparedExitKit:async()=>{calls.sign++;write(path.join(dir,'native-wal.json'),input.debitPayload.proposedNextState);if(loseSign)throw Error('process lost after native signature commit');write(path.join(dir,'burn_cosigned.json'),input.debitPayload.proposedNextState);},acknowledgePreparedExitKit:()=>{}};
  const tickets={findActiveTicket:()=>{try{return read(path.join(dir,'ticket.json'));}catch(e){if(e.code==='ENOENT')return null;throw e;}},upsertTicket:(_,ticket)=>write(path.join(dir,'ticket.json'),ticket),getTicket:()=>tickets.findActiveTicket()};
  return {dir,input,calls,tickets,cli,loseSign:()=>{loseSign=true;},create:checkpoint=>createBurnOperations({cli,bp,kit,checkpoint})};
}
for(const point of ['prepared','signed','producer','live','ticket']) test(`burn resumes from ${point} without replacing proof or duplicating debit`,async t=>{
 const f=fixture(t);await assert.rejects(f.create(async phase=>{if(phase===point)throw Error('crash');}).run(7,f.input,f.tickets),/crash/);
 const recovered=await f.create().run(7,{},f.tickets);assert.equal(recovered.digest,'signed');assert.equal(f.calls.sign,1);assert.equal(f.calls.producer.size,1);assert.equal(f.calls.live.size,1);assert.equal(f.tickets.findActiveTicket().status,'burn_done');
 assert.deepEqual(await f.create().run(7,f.input,f.tickets),recovered);assert.equal(f.calls.sign,1);
});
test('native signed WAL recovers when the signing process dies before relay records output',async t=>{
 const f=fixture(t);f.loseSign();await assert.rejects(f.create().run(7,f.input,f.tickets),/process lost/);
 assert.equal(f.tickets.findActiveTicket().status,'burn_pending');await f.create().run(7,{},f.tickets);assert.equal(f.calls.sign,1);assert.equal(f.tickets.findActiveTicket().status,'burn_done');
});
test('pending burn rejects a changed request without replacing its recovery owner',async t=>{
 const f=fixture(t);await assert.rejects(f.create(async()=>{throw Error('crash');}).run(7,f.input,f.tickets));
 await assert.rejects(f.create().run(7,{...f.input,transferDescriptor:{proof:'different'}},f.tickets),/saved burn must finish/);assert.equal(f.calls.sign,0);await f.create().run(7,{},f.tickets);assert.equal(f.calls.sign,1);
});
test('ticket persisted before crash is not downgraded after settlement progresses',async t=>{
 const f=fixture(t);await assert.rejects(f.create(async phase=>{if(phase==='ticket')throw Error('crash');}).run(7,f.input,f.tickets));
 const ticket=f.tickets.findActiveTicket();ticket.status='settle_pending';f.tickets.upsertTicket(7,ticket);await f.create().run(7,{},f.tickets);assert.equal(f.tickets.findActiveTicket().status,'settle_pending');assert.equal(f.calls.sign,1);
});
test('corrupt journal fails closed and retains the original signed artifact',async t=>{
 const f=fixture(t);f.loseSign();await assert.rejects(f.create().run(7,f.input,f.tickets));const file=path.join(f.dir,'burn_operation.json');const journal=JSON.parse(fs.readFileSync(file));journal.input.transferDescriptor.proof='modified';fs.writeFileSync(file,JSON.stringify(journal));await assert.rejects(f.create().run(7,{},f.tickets),/invalid/);assert.equal(f.calls.sign,1);
});
for(const boundary of ['prepared','native-signed','signed','producer','live','ticket']) test(`SIGKILL at ${boundary}: fresh process resumes the durable request`,t=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'burn-kill-'));t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 const {spawnSync}=require('child_process'),worker=path.join(__dirname,'fixtures/burn-crash-worker.js');
 const crashed=spawnSync(process.execPath,[worker,directory,boundary],{encoding:'utf8'});assert.equal(crashed.signal,'SIGKILL',crashed.stderr);
 const recovered=spawnSync(process.execPath,[worker,directory],{encoding:'utf8'});assert.equal(recovered.status,0,recovered.stderr);
 const read=file=>JSON.parse(fs.readFileSync(path.join(directory,file)));assert.equal(read('sign-count.json'),1);assert.equal(read('ticket.json').status,'burn_done');assert.equal(read('producer-id.json'),read('live-id.json'));assert.equal(read('burn_operation.json').phase,'complete');
});
test('every existing withdrawal phase excludes a different burn',async t=>{
 const f=fixture(t);
 for(const status of ['burn_pending','burn_done','settle_pending','settle_blocked','payout_pending','future_nonterminal']){
  f.tickets.upsertTicket(7,{id:'another',type:'partial_withdrawal',status,params:{producerRequestId:'burn:'+'ff'.repeat(32)}});
  await assert.rejects(f.create().run(7,f.input,f.tickets),/active partial withdrawal/);assert.equal(f.tickets.findActiveTicket().id,'another');
 }
 assert.equal(f.calls.sign,0);
});
test('token mismatch and incomplete proof cannot create a burn owner',async t=>{
 const f=fixture(t);await assert.rejects(f.create().run(7,{...f.input,tokenIndex:1},f.tickets),/tokenIndex mismatch/);await assert.rejects(f.create().run(7,{debitPayload:f.input.debitPayload},f.tickets),/both proof and descriptor/);assert.equal(f.create().pending(7),null);assert.equal(f.calls.sign,0);
});
test('pre-journal completed burn replay preserves its terminal ticket',async t=>{
 const f=fixture(t);await f.create().run(7,f.input,f.tickets);
 fs.rmSync(path.join(f.dir,'burn_operation.json'));fs.rmSync(path.join(f.dir,'burn_results'),{recursive:true});
 const ticket=f.tickets.findActiveTicket();ticket.status='settle_done';f.tickets.upsertTicket(7,ticket);
 await f.create().run(7,f.input,f.tickets);assert.equal(f.tickets.findActiveTicket().status,'settle_done');assert.equal(f.calls.sign,1);
});
test('a stale or invalid new proof is rejected before acquiring durable burn ownership',async t=>{
 const f=fixture(t),original=f.cli.cli;
 f.cli.cli=(_ch,args)=>{if(args.includes('--propose-exit-kit'))throw Error('stale or invalid native proof');return original(_ch,args);};
 await assert.rejects(f.create().run(7,f.input,f.tickets),/invalid native proof/);
 assert.equal(f.create().pending(7),null);assert.equal(f.tickets.findActiveTicket(),null);assert.equal(f.calls.sign,0);
 f.cli.cli=original;await f.create().run(7,f.input,f.tickets);assert.equal(f.calls.sign,1);
});
test('an old signed digest with changed proof inputs cannot acquire a new owner',async t=>{
 const f=fixture(t);await f.create().run(7,f.input,f.tickets);f.tickets.findActiveTicket=()=>null;
 const changed={...f.input,transferDescriptor:{proof:'changed'}};
 await assert.rejects(f.create().run(7,changed,f.tickets),/different proof inputs/);assert.equal(f.create().pending(7),null);assert.equal(f.calls.sign,1);
});
