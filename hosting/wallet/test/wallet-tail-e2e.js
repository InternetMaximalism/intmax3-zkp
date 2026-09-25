'use strict';
// Real WASM + isolated Anvil acceptance for the authenticated-tail protocol deployment.
// Never clears state. Every external operation keeps its original payload/transaction for retry.
const fs=require('fs'),path=require('path'),cp=require('child_process'),crypto=require('crypto');
const {Wallet}=require('../../../node/common/wallet');
const directory=process.env.WALLET_TAIL_DIR,rpc=process.env.RPC,base=process.env.WALLET_TAIL_URL;
if(!directory || !rpc || !base || ![rpc,base].every(u=>['localhost','127.0.0.1'].includes(new URL(u).hostname)))throw Error('explicit isolated directory and loopback RPC/relay required');
const addresses=['0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266','0x70997970c51812dc3a010c7d01b50e0d17dc79c8'];
const wallet=new Wallet();
const file=name=>path.join(directory,name+'.json');
const read=name=>JSON.parse(fs.readFileSync(file(name)));
function save(name,value){const dest=file(name),temp=dest+'.tmp';fs.writeFileSync(temp,JSON.stringify(value),{mode:0o600});fs.renameSync(temp,dest);return value;}
async function once(name,fn){return fs.existsSync(file(name))?read(name):save(name,await fn());}
function cast(...args){return cp.execFileSync('cast',[...args,'--rpc-url',rpc],{encoding:'utf8',maxBuffer:32*1024*1024}).trim();}
async function api(ch,route,body){return new Promise((resolve,reject)=>{
 const bytes=body==null?null:JSON.stringify(body);const request=require('http').request(base+route+'?channel='+ch,{agent:false,method:bytes?'POST':'GET',headers:{'Content-Type':'application/json',...(bytes?{'Content-Length':Buffer.byteLength(bytes)}:{})}},response=>{let text='';response.on('data',c=>text+=c);response.on('end',()=>{try{const result=JSON.parse(text);if(response.statusCode>=400)throw Error(route+': '+JSON.stringify(result).slice(-4000));resolve(result);}catch(error){reject(error);}});});request.setTimeout(7200000,()=>request.destroy(Error('timeout')));request.on('error',reject);request.end(bytes);
});}
async function load(ch){wallet.keygen(read('seed-'+ch));wallet.importChannel(await api(ch,'/api/snapshot'));return wallet.balance();}
async function deposit(ch,amount,tag){
 const report=await load(ch),info=await api(ch,'/api/deposit-info');
 const tx=await once(tag+'-tx',async()=>JSON.parse(cast('send',info.rollup,'deposit(bytes32,uint32,uint256,bytes32)',info.depositRecipient,'0',amount,'0x'+'00'.repeat(32),'--value',amount,'--unlocked','--from',addresses[ch-7],'--json')));
 cast('rpc','anvil_mine','0x4');await once(tag+'-import',()=>api(ch,'/api/import-deposit',{recipientSlot:report.slot,txHash:tx.transactionHash}));
}
async function send(from,to,amount,tag){
 const payload=await once(tag+'-payload',async()=>{
  await load(from);const destination=await api(to,'/api/snapshot');const seed=read('seed-'+to);wallet.keygen(seed);wallet.importChannel(destination);const slot=wallet.balance().slot;await load(from);
  const member=destination.members.find(m=>m.slot===slot),head=await api(from,'/api/base-head');
  return wallet.sendInterChannel(to,slot,amount,{regevPk:member.regevPk,pkG:member.pkG},0,head.nonce);
 });
 const result=await once(tag+'-result',()=>api(from,'/api/inter/send',payload));
 const before=(await api(to,'/api/snapshot')).state.digest;
 await api(from,'/api/inter/send',payload);
 if((await api(to,'/api/snapshot')).state.digest!==before)throw Error('duplicate receive advanced destination twice');
 return result;
}
(async()=>{
 fs.mkdirSync(directory,{recursive:true,mode:0o700});if(cast('chain-id')!=='31337')throw Error('Anvil chain required');await wallet.initialize();
 for(const ch of [7,8]){
  await once('seed-'+ch,async()=>crypto.randomBytes(32).toString('hex'));wallet.keygen(read('seed-'+ch));
  const contribution=await once('join-input-'+ch,async()=>wallet.genesisContribution('0',addresses[ch-7]));
  await once('join-'+ch,()=>api(ch,'/api/init',contribution));
  console.log('deposit',ch);await deposit(ch,'10000000000000000','deposit-'+ch);
 }
 console.log('send A -> B');await send(7,8,'2000000000000000','a-b');
 console.log('send B -> A: A has no future send');await send(8,7,'1000000000000000','b-a');
 console.log('deposit after A sent');await deposit(7,'1000000000000000','tail-deposit');
 const a=await load(7),b=await load(8);
 if(a.balance!=='10000000000000000'||b.balance!=='11000000000000000')throw Error('roundtrip/deposit balances differ from conservation');
 save('roundtrip-success',{a,b});console.log('SUCCESS: receive-after-send, spend received credit, repeated delivery, tail deposit');
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
