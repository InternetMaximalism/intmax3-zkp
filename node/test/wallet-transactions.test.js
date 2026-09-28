'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {WalletTransactions}=require('../../hosting/wallet/wallet-transactions');
const from='0x'+'11'.repeat(20),to='0x'+'22'.repeat(20),hash='0x'+'ab'.repeat(32),request={from,to,data:'0x1234',value:'0x10'},context={chainId:31337,rollup:to,account:from};
// The account nonce is modelled the way a wallet reports it: a broadcast consumes the pending
// nonce, a request that fails before broadcasting does not. That difference is what separates a
// lost wallet response (must be located, never paid twice) from a request that never left the
// wallet (safe to send afresh), so a constant nonce here would hide exactly the case under test.
function setup(mode){
 const data=new Map();let sends=0,broadcasts=0,nonce=2,tx;
 const storage={getItem:k=>data.get(k)||null,setItem:(k,v)=>data.set(k,v),removeItem:k=>data.delete(k)};
 const provider={request:async({method,params})=>{
  if(method==='eth_getTransactionCount')return '0x'+nonce.toString(16);if(method==='eth_blockNumber')return '0xa';
  if(method==='eth_sendTransaction'){sends++;
   if(mode==='reject')throw Object.assign(Error('rejected'),{code:4001});
   // A broken injected provider fails the signing request before anything is broadcast.
   if(mode==='nobroadcast-once'&&sends===1)throw TypeError('e.startsWith is not a function');
   tx={...params[0],input:params[0].data,hash};nonce++;broadcasts++;
   if(mode==='lost')throw Error('lost response');return hash;}
  if(method==='eth_getBlockByNumber')return {transactions:tx?[tx]:[]};throw Error(method);
 }};
 // Another transaction (a second tab, another dapp) consumes the next nonce outside this journal.
 const external=t=>{tx={from,nonce:'0x'+nonce.toString(16),...t};nonce++;};
 return {storage,provider,j:new WalletTransactions(storage),sends:()=>sends,broadcasts:()=>broadcasts,external};
}
test('lost wallet response is reconciled by exact nonce/call after reload without sending twice',async()=>{
 const h=setup('lost');await assert.rejects(h.j.send(h.provider,'deposit:1',request,context,{}),/lost/);
 const reload=new WalletTransactions(h.storage);const r=await reload.send(h.provider,'deposit:1',{...request,value:'0xff'},context,{});
 assert.equal(r.txHash,hash);assert.equal(r.request.value,'0x10');assert.equal(h.sends(),1);assert.equal(h.broadcasts(),1);
});
test('known tx hash resumes after receipt/network failure without another wallet approval',async()=>{
 const h=setup();await h.j.send(h.provider,'d',request,context,{});await h.j.send(h.provider,'d',request,context,{});assert.equal(h.sends(),1);
});
test('explicit wallet rejection releases intent for a later user retry',async()=>{
 const h=setup('reject');await assert.rejects(h.j.send(h.provider,'d',request,context,{}));assert.equal(h.j.read('d'),null);
});
test('storage failure prevents any wallet spend',async()=>{
 const h=setup();h.storage.setItem=()=>{throw Error('quota');};await assert.rejects(h.j.send(h.provider,'d',request,context,{}),/quota/);assert.equal(h.sends(),0);
});
test('changed deployment or connected wallet cannot reuse a pending intent',async()=>{
 const h=setup();await h.j.send(h.provider,'d',request,context,{});await assert.rejects(h.j.recover(h.provider,'d',{...context,account:to}),/another wallet/);assert.equal(h.sends(),1);
});
test('corrupt pending journal fails closed instead of permitting a new payment',async()=>{
 const h=setup();h.storage.setItem('intmax-wallet-tx:d','{');await assert.rejects(h.j.send(h.provider,'d',request,context,{}));assert.equal(h.sends(),0);
});
test('a signing request that failed before broadcasting does not wedge the next attempt',async()=>{
 const h=setup('nobroadcast-once');
 await assert.rejects(h.j.send(h.provider,'d',request,context,{}),/startsWith/);
 assert.ok(h.j.read('d'),'a non-rejection failure keeps the intent (it may have been broadcast)');assert.equal(h.broadcasts(),0);
 const r=await new WalletTransactions(h.storage).send(h.provider,'d',request,context,{});
 assert.equal(r.txHash,hash);assert.equal(r.request.nonce,'0x2','the unused pinned nonce is the one paid');assert.equal(h.broadcasts(),1);
});
test('recover discards a never-broadcast intent and reports it absent (the Deposit resume path)',async()=>{
 const h=setup('nobroadcast-once');await assert.rejects(h.j.send(h.provider,'d',request,context,{}));
 assert.equal(await h.j.recover(h.provider,'d',context),null);assert.equal(h.j.read('d'),null);assert.equal(h.broadcasts(),0);
});
test('a pinned nonce consumed by another transaction is never paid again',async()=>{
 const h=setup('nobroadcast-once');await assert.rejects(h.j.send(h.provider,'d',request,context,{}));
 h.external({to,input:'0xdead',value:'0x0',hash:'0x'+'cd'.repeat(32)});
 await assert.rejects(new WalletTransactions(h.storage).send(h.provider,'d',request,context,{}),/different wallet transaction/);
 assert.equal(h.broadcasts(),0);assert.ok(h.j.read('d'),'the intent is kept: fail closed');
});
test('a saved intent without a pinned nonce is never discarded',async()=>{
 const h=setup();h.storage.setItem('intmax-wallet-tx:d',JSON.stringify({version:1,context,request,details:{},nextBlock:10}));
 await assert.rejects(h.j.recover(h.provider,'d',context),/Waiting to locate/);assert.ok(h.j.read('d'));assert.equal(h.sends(),0);
});
