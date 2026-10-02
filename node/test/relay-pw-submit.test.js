'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../../hosting/wallet/wallet-relay.js'),'utf8');
const route=source.slice(source.indexOf("app.post('/api/pw-submit'"),source.indexOf('// POST /api/pw-finalize'));
// devnet: settled inside the request. public: in the background, on a verified rollup only.
async function fail(error,devnet=true,verified=false){
 let handler,done;const started=[];
 const completed=new Promise(r=>done=r),ticket={id:'pw_1',status:'burn_done',params:{recipient:'recipient'},steps:{}};
 const requireCapability=(res,name,what)=>{if(devnet||verified)return true;res.status(501).json({code:'NOT_AVAILABLE',capability:name,error:`${what} is not available`});return false;};
 const ctx={requireCapability,isDevnet:()=>devnet,app:{post:(_,h)=>handler=h},reqChannel:()=>7,withLock:(_,fn)=>Promise.resolve().then(fn),
 findActiveTicket:()=>ticket,upsertTicket:()=>{},fs:{existsSync:()=>true},wc:()=>'',RPC:'rpc',
 pwSettlement:{publish:async()=>{throw error;},submit:async()=>{throw new Error('must not submit');},start:ch=>started.push(ch)},
 require:()=>({resumeSubmittedAuth:()=>null}),console:{error:()=>{}},cli:()=>{throw new Error('must not reach CLI');}};
 vm.createContext(ctx);vm.runInContext(route,ctx);
 let status=200;
 handler({body:{}},{status(n){status=n;return this;},json(body){done(body);}});
 const body=await completed;return {status,body,ticket,started};
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

test('on an unverified public rollup partial withdrawal is refused up front with 501 and nothing is touched',async()=>{
 const result=await fail(new Error('must not be reached'),false);
 assert.equal(result.status,501);assert.equal(result.body.code,'NOT_AVAILABLE');assert.equal(result.ticket.status,'burn_done');
 assert.deepEqual(result.started,[]);
});
test('on a verified public rollup the burn is settled in the background and the request answers 202',async()=>{
 const result=await fail(new Error('must not be reached'),false,true);
 assert.equal(result.status,202);assert.equal(result.body.settling,true);assert.deepEqual(result.started,[7]);
 assert.equal(result.ticket.status,'burn_done','the background driver, not the request, advances the ticket');
});
