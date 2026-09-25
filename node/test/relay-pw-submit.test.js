'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../../hosting/wallet/wallet-relay.js'),'utf8');
const route=source.slice(source.indexOf("app.post('/api/pw-submit'"),source.indexOf('// POST /api/pw-finalize'));
async function fail(error){
 let handler,done;
 const completed=new Promise(r=>done=r),ticket={status:'burn_done',params:{recipient:'recipient'}};
 const ctx={app:{post:(_,h)=>handler=h},reqChannel:()=>7,withLock:(_,fn)=>Promise.resolve().then(fn),
 findActiveTicket:()=>ticket,upsertTicket:()=>{},fs:{existsSync:()=>true},wc:()=>'',RPC:'rpc',
 require:()=>({resumeSubmittedAuth:()=>null,publish:async()=>{throw error;}}),console:{error:()=>{}},cli:()=>{throw new Error('must not reach CLI');}};
 vm.createContext(ctx);vm.runInContext(route,ctx);
 let status;
 handler({body:{}},{status(n){assert.ok(n>=400&&n<=599);status=n;return this;},json(body){done(body);}});
 const body=await completed;return {status,body,ticket};
}
test('native process exit status 1 becomes HTTP 500 without crashing relay or stranding ticket',async()=>{
 const result=await fail(Object.assign(new Error('native proof failed'),{status:1}));
 assert.equal(result.status,500);assert.equal(result.ticket.status,'burn_done');assert.match(result.body.error,/native proof failed/);
});
test('a workflow conflict remains HTTP 409 and preserves saved burn',async()=>{
 const result=await fail(Object.assign(new Error('finalization pending'),{status:409}));
 assert.equal(result.status,409);assert.equal(result.ticket.status,'burn_done');
});

test('shared relay error responder maps CLI exit codes to valid HTTP errors',()=>{
 const start=source.indexOf('function sendRouteError('),end=source.indexOf('\n}',start)+2;
 const context={fullCliError:e=>e.message,console:{error:()=>{}}};
 vm.createContext(context);vm.runInContext(source.slice(start,end),context);
 for(const [status,expected] of [[1,500],[409,409],[0,500],[999,500]]){
   let actual;const res={status(n){actual=n;return this;},json(body){assert.equal(body.error,'failure');}};
   context.sendRouteError(res,{status,message:'failure'});assert.equal(actual,expected);
 }
});
