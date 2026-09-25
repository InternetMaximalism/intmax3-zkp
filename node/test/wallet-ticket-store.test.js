'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('fs'),os=require('os'),path=require('path'),{spawn}=require('child_process');
const {readTicketsFile,writeTicketsFile}=require('../../hosting/wallet/wallet-ticket-store');
const ticket={id:'t',type:'deposit',status:'l1_done',params:{txHash:'hash'}};
function fixture(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wallet-ticket-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));return path.join(dir,'tickets.json');}
test('only a missing ticket file means no pending operations',t=>{
 const file=fixture(t);assert.deepEqual(readTicketsFile(file),[]);
 for(const raw of ['{','{}','[{}]','null']){fs.writeFileSync(file,raw);assert.throws(()=>readTicketsFile(file));}
});
test('ticket updates preserve complete records and leave no temp files',t=>{
 const file=fixture(t);writeTicketsFile(file,[ticket]);assert.deepEqual(readTicketsFile(file),[ticket]);
 writeTicketsFile(file,[{...ticket,status:'import_done'}]);assert.equal(readTicketsFile(file)[0].status,'import_done');assert.equal(fs.readdirSync(path.dirname(file)).length,1);
});
test('killing a writer during repeated updates retains a complete old or new record',async t=>{
 const file=fixture(t);writeTicketsFile(file,[ticket]);
 const modulePath=require.resolve('../../hosting/wallet/wallet-ticket-store');
 const child=spawn(process.execPath,['-e',`const {writeTicketsFile}=require(${JSON.stringify(modulePath)});let n=0;for(;;){writeTicketsFile(process.argv[1],[{id:'t',type:'deposit',status:'l1_done',params:{n:n++}}]);if(n===3)process.stdout.write('ready');}`,file],{stdio:['ignore','pipe','pipe']});
 await new Promise((resolve,reject)=>{child.stdout.once('data',resolve);child.once('error',reject);child.once('exit',()=>reject(Error('writer exited early')));});
 const exited=new Promise(resolve=>child.once('exit',resolve));child.kill('SIGKILL');await exited;
 const saved=readTicketsFile(file);assert.equal(saved[0].id,'t');assert.equal(saved[0].status,'l1_done');assert.ok(Number.isInteger(saved[0].params.n));
});

test('forced termination at each persistence boundary never exposes partial JSON',async t=>{
 const modulePath=require.resolve('../../hosting/wallet/wallet-ticket-store');
 for(const phase of ['partial-temp','after-file-sync','before-rename','after-rename']){
  const file=fixture(t);writeTicketsFile(file,[ticket]);
  const code=`const fs=require('fs');const phase=process.argv[2];const kill=()=>process.kill(process.pid,'SIGKILL');const write=fs.writeFileSync,sync=fs.fsyncSync,rename=fs.renameSync;
fs.writeFileSync=function(fd,body,...args){if(phase==='partial-temp'){write(fd,body.slice(0,5),...args);kill();}return write(fd,body,...args);};
fs.fsyncSync=function(fd){sync(fd);if(phase==='after-file-sync')kill();};
fs.renameSync=function(a,b){if(phase==='before-rename')kill();rename(a,b);if(phase==='after-rename')kill();};
require(${JSON.stringify(modulePath)}).writeTicketsFile(process.argv[1],[{id:'t',type:'deposit',status:'import_done',params:{}}]);`;
  const child=spawn(process.execPath,['-e',code,file,phase],{stdio:'ignore'});
  const result=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>resolve({code,signal}));});
  assert.equal(result.signal,'SIGKILL',phase);
  assert.equal(readTicketsFile(file)[0].status,phase==='after-rename'?'import_done':'l1_done',phase);
 }
});
