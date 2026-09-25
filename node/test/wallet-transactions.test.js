'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {WalletTransactions}=require('../../hosting/wallet/wallet-transactions');
const from='0x'+'11'.repeat(20),to='0x'+'22'.repeat(20),hash='0x'+'ab'.repeat(32),request={from,to,data:'0x1234',value:'0x10'},context={chainId:31337,rollup:to,account:from};
function setup(mode){
 const data=new Map();let sends=0,tx;
 const storage={getItem:k=>data.get(k)||null,setItem:(k,v)=>data.set(k,v),removeItem:k=>data.delete(k)};
 const provider={request:async({method,params})=>{
  if(method==='eth_getTransactionCount')return '0x2';if(method==='eth_blockNumber')return '0xa';
  if(method==='eth_sendTransaction'){sends++;if(mode==='reject')throw Object.assign(Error('rejected'),{code:4001});tx={...params[0],input:params[0].data,hash};if(mode==='lost')throw Error('lost response');return hash;}
  if(method==='eth_getBlockByNumber')return {transactions:tx?[tx]:[]};throw Error(method);
 }};
 return {storage,provider,j:new WalletTransactions(storage),sends:()=>sends};
}
test('lost wallet response is reconciled by exact nonce/call after reload without sending twice',async()=>{
 const h=setup('lost');await assert.rejects(h.j.send(h.provider,'deposit:1',request,context,{}),/lost/);
 const reload=new WalletTransactions(h.storage);const r=await reload.send(h.provider,'deposit:1',{...request,value:'0xff'},context,{});
 assert.equal(r.txHash,hash);assert.equal(r.request.value,'0x10');assert.equal(h.sends(),1);
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
