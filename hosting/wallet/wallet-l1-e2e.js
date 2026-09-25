// Real WASM + relay + Anvil withdrawal regression. Uses only disposable test accounts.
const fs=require('fs'),path=require('path'),cp=require('child_process'),crypto=require('crypto');
const root=path.resolve(__dirname, '../..'),dir=process.env.WALLET_E2E_DIR;
if (!dir) throw new Error('WALLET_E2E_DIR must name a dedicated isolated relay test directory');
const {Wallet}=require(path.join(root,'node/common/wallet'));
const wallet=new Wallet();
const rpc=process.env.RPC,base=process.env.WALLET_E2E_URL;
if (!rpc || !base || ![rpc,base].every(u=>['localhost','127.0.0.1'].includes(new URL(u).hostname))) throw new Error('explicit loopback RPC and WALLET_E2E_URL are required');
const recipient=process.env.WALLET_E2E_RECIPIENT || '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
function save(name,v){fs.writeFileSync(path.join(dir,name),JSON.stringify(v),{mode:0o600});}
function read(name){return JSON.parse(fs.readFileSync(path.join(dir,name)));}
function exists(name){return fs.existsSync(path.join(dir,name));}
function cast(...args){return cp.execFileSync('cast',[...args,'--rpc-url',rpc],{encoding:'utf8',maxBuffer:20*1024*1024}).trim();}
async function api(route,body){return new Promise((resolve,reject)=>{
 const payload=body===undefined?null:JSON.stringify(body);
 const req=require('http').request(base+route+'?channel=7',{agent:false,method:payload?'POST':'GET',headers:{'Content-Type':'application/json',...(payload?{'Content-Length':Buffer.byteLength(payload)}:{})}},res=>{
 let data='';res.on('data',c=>data+=c);res.on('end',()=>{try{const j=JSON.parse(data);if(res.statusCode>=400)reject(new Error(route+': '+JSON.stringify(j).slice(-6000)));else resolve(j);}catch(e){reject(e);}});
 });req.on('error',reject);req.setTimeout(7200000,()=>req.destroy(new Error('request timeout')));req.end(payload);
});}

(async()=>{
 if(cast('chain-id')!=='31337')throw new Error('isolated Anvil chain required');
 await wallet.initialize();
 if(process.env.WALLET_E2E_CONTINUE==='1' && !exists('seed.json'))throw new Error('continuation needs the existing disposable wallet seed');
 if(!exists('seed.json'))save('seed.json',crypto.randomBytes(32).toString('hex'));
 wallet.keygen(read('seed.json'));
 const continuing=process.env.WALLET_E2E_CONTINUE==='1';
 if(!exists('joined.json')){console.log(continuing?'Loading existing test wallet':'Joining');save('joined.json',continuing?await api('/api/snapshot'):await api('/api/init',wallet.genesisContribution('0',recipient)));}
 let snapshot=read('joined.json');wallet.importChannel(snapshot);console.log('Joined',wallet.balance());
 if(!continuing && !exists('deposit.json')){
  const b=read('work/ch7/channel_backing.json');
  console.log('Depositing 0.01 ETH');
  const tx=JSON.parse(cast('send',b.rollup,'deposit(bytes32,uint32,uint256,bytes32)',b.deposit_recipient,'0','10000000000000000','0x'+'00'.repeat(32),'--value','10000000000000000','--unlocked','--from',recipient,'--json'));
  save('deposit.json',tx);
 }
 if(continuing && !exists('imported.json'))save('imported.json',snapshot);
 if(!exists('imported.json')){
  cast('rpc','anvil_mine','0x4');
  console.log('Importing');save('imported.json',await api('/api/import-deposit',{recipientSlot:wallet.balance().slot,txHash:read('deposit.json').transactionHash}));
 }
 wallet.importChannel(read('imported.json')); console.log('Funded',wallet.balance());
 if(!exists('burn-payload.json')){console.log('Proving burn');const h=await api('/api/base-head');save('burn-payload.json',wallet.burnSend('5000000000000000',recipient,0,h.nonce));}
 if(!exists('burned.json')){console.log('Co-signing burn');const b=read('burn-payload.json');save('burned.json',await api('/api/cosign-burn',{...b,amount:'5000000000000000',recipient}));}
 console.log('Burned',wallet.finalize(read('burned.json')));
 if(!exists('submitted.json')){console.log('Submitting, with real L1 validity publication');save('submitted.json',await api('/api/pw-submit',{recipient}));}
 if(process.env.WALLET_E2E_VERIFY_RESUME==='1' && !exists('resumed.json')){
  const operator='0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
  const before=cast('rpc','eth_getTransactionCount',operator,'latest');
  const resumed=await api('/api/pw-submit',{recipient});
  if(resumed.auth_digest!==read('submitted.json').auth_digest || cast('rpc','eth_getTransactionCount',operator,'latest')!==before)throw new Error('submit retry did not resume the exact existing authorization');
  save('resumed.json',resumed);console.log('Submit retry resumed without another transaction');
 }
 console.log('Finalizing payout');save('finalized.json',await api('/api/pw-finalize',{}));
 const claim=read('finalized.json').claim;
 if(claim){
  if(claim.recipient.toLowerCase()!==recipient.toLowerCase() || claim.amount!=='5000000000000000')throw new Error('unexpected recipient claim');
  if(!exists('pull.json')){
   const before=BigInt(cast('balance',recipient));
   const receipt=JSON.parse(cast('send',claim.to,claim.data,'--unlocked','--from',recipient,'--json'));
   const after=BigInt(cast('balance',recipient));
   if(after-before+BigInt(receipt.gasUsed)*BigInt(receipt.effectiveGasPrice)!==BigInt(claim.amount))throw new Error('recipient did not receive exact payout');
   save('pull.json',receipt);
  }
  save('claim-confirmed.json',await api('/api/pw-claim-confirm',{txHash:read('pull.json').transactionHash}));
 }
 const auth=read('work/ch7/pw_auth.json'),backing=read('work/ch7/channel_backing.json');
 if(cast('call',backing.rollup,'withdrawalNullifierUsed(bytes32)(bool)',auth.withdrawal_nullifier)!=='true')throw new Error('payout nullifier was not consumed on L1');
 console.log('SUCCESS',read('finalized.json'));
})().catch(e=>{console.error(e.stack);process.exit(1)});
