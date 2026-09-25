'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),vm=require('vm'),path=require('path');
const source=fs.readFileSync(path.join(__dirname,'../../hosting/wallet/wallet-relay.js'),'utf8');
const hash='0x'+'ab'.repeat(32);
function route(name,end,extra){let handler;const context={app:{post:(_,fn)=>handler=fn},reqChannel:()=>7,withLock:(_,fn)=>Promise.resolve().then(fn),...extra};vm.createContext(context);vm.runInContext(source.slice(source.indexOf(`app.post('${name}'`),source.indexOf(end,source.indexOf(`app.post('${name}'`))),context);return body=>new Promise(resolve=>handler({body},{status(n){this.code=n;return this;},json(value){resolve({status:this.code||200,value});}}));}
test('lost claim-confirm response retries the archived exact transaction without touching a later withdrawal',async()=>{
 const newer={id:'new',status:'claim_pending'},done={id:'old',type:'partial_withdrawal',status:'settle_done',steps:{claim:{txHash:hash}}};
 let writes=0;
 const request=route('/api/pw-claim-confirm','// ─── Ticket endpoints',{findActiveTicket:()=>newer,readTickets:()=>[newer],readHistory:()=>[done],upsertTicket:()=>writes++});
 for(let i=0;i<3;i++){const result=await request({txHash:hash.toUpperCase().replace('0X','0x')});assert.equal(result.status,200);assert.equal(result.value.ok,true);}
 assert.equal(writes,0);assert.equal(newer.status,'claim_pending');
 assert.equal((await request({txHash:'0x'+'cd'.repeat(32)})).status,409);
});
test('completed deposit ticket replay returns the original and never creates another pending ticket',async()=>{
 let writes=0;const done={id:'old',type:'deposit',status:'import_done',params:{txHash:hash}};
 const request=route('/api/ticket/deposit','// Static wallet files',{readTickets:()=>[],readHistory:()=>[done],findActiveTicket:()=>({id:'new'}),upsertTicket:()=>writes++});
 for(let i=0;i<3;i++){const result=await request({txHash:hash,amount:'1',depositor:'sender',recipientSlot:0});assert.equal(result.status,200);assert.equal(result.value.id,'old');assert.equal(result.value.status,'import_done');}
 assert.equal(writes,0);
});

test('completed archive repairs a crash between archive and active ticket writes; full settlement is retained beyond TTL',()=>{
 const files=new Map(),context={wc:(_,f)=>f,readTicketsFile:f=>structuredClone(files.get(f)||[]),writeTicketsFile:(f,v)=>files.set(f,structuredClone(v))};
 vm.createContext(context);const start=source.indexOf('const TICKET_FILE'),end=source.indexOf('// The rollup address',start);vm.runInContext(source.slice(start,end),context);
 const pending={id:'a',type:'deposit',status:'l1_done',params:{},updatedAt:0};
 context.upsertTicket(7,pending);
 const done={...pending,status:'import_done'};context.archiveTicket(7,done);
 assert.equal(context.readTickets(7)[0].status,'import_done');
 assert.equal(context.findActiveTicket(7,'deposit'),undefined);
 context.upsertTicket(7,{id:'full',type:'full_withdrawal',status:'settle_done',params:{}});
 for(const values of files.values())for(const t of values)t.updatedAt=0;
 context.upsertTicket(7,{id:'b',type:'deposit',status:'l1_done',params:{}});
 assert.equal(context.findActiveTicket(7,'full_withdrawal').id,'full');
});
