'use strict';
// UI-only fault fixture. Serves the actual wallet components with simulated crypto/RPC boundaries.
// Never connects to Anvil, MetaMask, or a real relay. Read /test/state for side-effect counts.
const http=require('http'),fs=require('fs'),path=require('path');
const root=path.resolve(__dirname,'..'),port=Number(process.env.WALLET_UI_TEST_PORT||8090);
const account='0x'+'11'.repeat(20),rollup='0x'+'22'.repeat(20),pk='0x'+'33'.repeat(32);
let scenario='',joined=false,version=0,payments=0,imports=0,tx=null,tickets=[],burns=0,sends=0,sendRequests=new Map();
const snapshot=()=>({record:{channelId:37,memberCount:3,delegateCount:1},members:[0,1,2,3].map(slot=>({slot,pkG:pk,pkB:pk,regevPk:{}})),state:{channelId:37,digest:'0x'+(version+1).toString(16).padStart(64,'0'),h2Tag:'0x'+'00'.repeat(32),balanceState:{stateVersion:version,memberCount:3,delegateCount:1,tokenCount:1,tokenRegistry:[0],encBalances:[[],[],[],[]],recipients:[account,account,account,account],regevPkDigests:[]},memberSignatures:[]},_uiBalance:String(10000000000000000n+BigInt(imports)*1000000000000000n)});
const worker=`onmessage=e=>{const a=e.data;if(a.action==='init'){postMessage({type:'ready',threads:1});return;}let result='{}';if(a.action==='keygenSeeded')result=JSON.stringify({pkG:'${pk}'});if(a.action==='genesisContribution')result=JSON.stringify({pkG:'${pk}',recipient:a.recipient});if(a.action==='importChannel'||a.action==='finalize'){const s=JSON.parse(a.snapshotJson||a.stateJson||'{}');result=JSON.stringify({slot:3,balance:s._uiBalance||'10000000000000000',stateVersion:s.state?.balanceState.stateVersion||s.balanceState?.stateVersion||0,canSend:true,balances:[{tokenSlot:0,tokenIndex:0,balance:s._uiBalance||'10000000000000000'}],witnessTokenSlot:0});}if(a.action==='sendInterChannel')result=JSON.stringify({debitPayload:{id:Date.now()},transferDescriptor:{destinationChannelId:a.toChannel}});if(a.action==='burnSend')result=JSON.stringify({debitPayload:{},transferDescriptor:{}});postMessage({type:'result',_callId:a._callId,result});};`;
const provider=`window.ethereum={isMetaMask:true,on(){},async request(a){const r=await fetch('/test/rpc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(a)});const j=await r.json();if(j.error)throw Object.assign(new Error(j.error),{code:j.code});return j.result;}};`;
function json(res,value,status=200){res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(value));}
http.createServer(async(req,res)=>{
 const u=new URL(req.url,'http://localhost');let body='';for await(const c of req)body+=c;let data;try{data=body?JSON.parse(body):{};}catch{data={};}
 if(u.pathname==='/test/scenario'){scenario=data.name||'';return json(res,{scenario});}
 if(u.pathname==='/test/state')return json(res,{scenario,joined,version,payments,imports,burns,sends,tickets});
 if(u.pathname==='/test/rpc'){
  const m=data.method;let result='0x0';
  if(m==='eth_accounts'||m==='eth_requestAccounts')result=[account];
  if(m==='eth_chainId')result='0x7a69';
  if(m==='eth_getBalance')result='0xde0b6b3a7640000';
  if(m==='eth_blockNumber')result='0xa';
  if(m==='eth_getTransactionCount')result='0x'+payments.toString(16);
  if(m==='eth_getBlockByNumber')result={transactions:tx?[tx]:[]};
  if(m==='eth_getTransactionReceipt')result={status:'0x1',blockNumber:'0xa'};
  if(m==='eth_sendTransaction'){
   if(scenario==='reject-wallet'){scenario='';return json(res,{error:'User rejected the request',code:4001});}
   payments++;tx={...data.params[0],input:data.params[0].data,hash:'0x'+payments.toString(16).padStart(64,'0')};result=tx.hash;
   if(scenario==='lose-wallet-response'){scenario='';return json(res,{error:'Connection lost after broadcast'});}
  }
  return json(res,{result});
 }
 if(u.pathname==='/api/cosign-burn'){
  if(tickets.some(t=>t.type==='partial_withdrawal'&&t.status!=='settle_done'))return json(res,{error:'already burned'},409);
  burns++;version++;tickets.push({id:'burn-'+burns,type:'partial_withdrawal',status:'burn_done',params:{amount:data.amount,recipient:data.recipient},steps:{}});
  if(scenario==='lose-burn-response'){scenario='';return json(res,{error:'response lost after burn'},503);}
  return json(res,snapshot().state);
 }
 if(u.pathname==='/api/pw-submit')return json(res,{auth_digest:'fixture-auth',withdrawal_token_index:0});
 if(u.pathname==='/api/pw-finalize'){
  if(scenario==='settle-offline'){scenario='';return json(res,{error:'settlement temporarily unavailable'},503);}
  const t=tickets.find(t=>t.type==='partial_withdrawal'&&t.status!=='settle_done');if(t)t.status='settle_done';return json(res,{authDigest:'fixture-auth'});
 }
 if(u.pathname==='/api/inter/send'){
  const key=JSON.stringify(data);if(!sendRequests.has(key)){sends++;version++;sendRequests.set(key,{sourceHead:snapshot().state});}
  if(scenario==='lose-send-response'){scenario='';return json(res,{error:'response lost after committing transfer'},503);}
  return json(res,sendRequests.get(key));
 }
 if(u.pathname==='/api/channels')return json(res,{channels:[37]});
 if(u.pathname==='/api/backing')return json(res,{fund:'0',rollup});
 if(u.pathname==='/api/deposit-info')return json(res,{rollup,depositRecipient:pk,chainId:31337,minConfirmations:0,rpc:'http://localhost:'+port});
 if(u.pathname==='/api/tokens')return json(res,{tokenCount:1,tokens:[{tokenSlot:0,tokenIndex:0,symbol:'ETH',name:'Ether',decimals:18,address:null,native:true,verified:true,fundAmount:'10000000000000000'}]});
 if(u.pathname==='/api/faucet')return json(res,{enabled:false});
 if(u.pathname==='/api/init'){joined=true;return json(res,snapshot());}
 if(u.pathname==='/api/snapshot')return json(res,joined?snapshot():{error:'no channel yet'},joined?200:404);
 if(u.pathname==='/api/poll'){res.writeHead(204);return res.end();}
 if(u.pathname==='/api/base-head')return json(res,{nonce:0});
 if(u.pathname==='/api/tickets'){
  if(scenario==='tickets-offline'){scenario='';return json(res,{error:'offline'},503);}
  if(scenario==='tickets-malformed'){scenario='';return json(res,[{}]);}
  return json(res,tickets);
 }
 if(u.pathname==='/api/ticket/deposit'){
  if(!tickets.some(t=>t.params.txHash===data.txHash))tickets.push({id:'deposit-'+data.txHash,type:'deposit',status:'l1_done',params:data,steps:{}});
  return json(res,tickets.find(t=>t.params.txHash===data.txHash));
 }
 if(u.pathname==='/api/import-deposit'){
  const t=tickets.find(t=>t.params.txHash===data.txHash);
  if(!t)return json(res,{error:'unknown deposit'},409);
  if(t.status!=='import_done'){imports++;version++;t.status='import_done';}
  if(scenario==='lose-import-response'){scenario='';return json(res,{error:'response lost after committing import'},503);}
  return json(res,snapshot());
 }
 if(u.pathname==='/wallet-worker.js'){res.writeHead(200,{'Content-Type':'text/javascript'});return res.end(worker);}
 if(u.pathname==='/test/provider.js'){res.writeHead(200,{'Content-Type':'text/javascript'});return res.end(provider);}
 const name=u.pathname==='/'?'wallet-live.html':u.pathname.slice(1);
 if(['wallet-live.html','wallet-transactions.js','wallet-outbox.js','wallet.css'].includes(name)&&fs.existsSync(path.join(root,name))){
  let text=fs.readFileSync(path.join(root,name),'utf8');if(name.endsWith('.html'))text=text.replace('<script src="./wallet-transactions.js">','<script src="/test/provider.js"></script><script src="./wallet-transactions.js">');
  res.writeHead(200,{'Content-Type':name.endsWith('.html')?'text/html':name.endsWith('.css')?'text/css':'text/javascript','Cache-Control':'no-store'});return res.end(text);
 }
 json(res,{error:'fixture endpoint unavailable'},404);
}).listen(port,'127.0.0.1',()=>console.log('UI fault fixture http://localhost:'+port+'/wallet-live.html'));
