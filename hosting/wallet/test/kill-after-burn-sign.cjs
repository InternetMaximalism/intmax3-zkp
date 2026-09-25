'use strict';
// Explicit test preload only: `node --require ./hosting/wallet/test/kill-after-burn-sign.cjs ...`.
// Kill the actual relay after the native signer returns, BEFORE the relay saves its signed head.
// The one-shot marker is supplied only for a dedicated disposable Anvil directory.
const fs=require('fs');
if(!process.env.WALLET_FAULT_MARKER || !process.env.RPC || !['localhost','127.0.0.1'].includes(new URL(process.env.RPC).hostname))throw Error('explicit loopback fault-injection environment required');
const kit=require('../../../api/lib/exit-kit'),original=kit.cliWithPreparedExitKit;
kit.cliWithPreparedExitKit=async function(ch,args,...rest){
 const result=await original(ch,args,...rest);
 if(args[0]==='cosign-burn-send' && fs.existsSync(process.env.WALLET_FAULT_MARKER)){
  fs.unlinkSync(process.env.WALLET_FAULT_MARKER);
  process.kill(process.pid,'SIGKILL');
 }
 return result;
};
