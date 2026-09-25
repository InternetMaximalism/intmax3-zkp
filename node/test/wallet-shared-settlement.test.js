'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../../api/lib/cli.js'), 'utf8');
const start = source.indexOf('function ensureSettlement(ch) {');
const end = source.indexOf('\nfunction ', start + 1);
function harness(bindings) {
  const calls = [];
  const context = {
    CHANNELS: [17,18,19], DEVNET_CHAIN_ID:31337, RPC:'local-rpc',
    wc:(ch,file)=>`${ch}/${file}`, fs:{existsSync:p=>bindings.has(p)}, readJson:p=>bindings.get(p),
    chainId:()=>31337, rollupOf:()=> '0xAAAA',
    cli:(ch,args,env)=>{calls.push({ch,args,env});bindings.set(`${ch}/settlement.json`,{manager:'new'});},
  };
  vm.createContext(context);vm.runInContext(source.slice(start,end),context);
  return {context,calls};
}
test('second channel deployment reuses a manager on the same rollup only',()=>{
  const h=harness(new Map([['18/settlement.json',{rollup:'0xbbbb',manager:'wrong'}],['19/settlement.json',{rollup:'0xaaaa',manager:'shared'}]]));
  h.context.ensureSettlement(17);
  assert.equal(h.calls[0].env.WALLET_EXISTING_SETTLEMENT_MANAGER,'shared');
});
test('first manager deployment explicitly clears any inherited existing-manager override',()=>{
  const h=harness(new Map());h.context.ensureSettlement(17);
  assert.equal(h.calls[0].env.WALLET_EXISTING_SETTLEMENT_MANAGER,'0x0000000000000000000000000000000000000000');
});
test('already deployed channel does not redeploy its manager',()=>{
  const h=harness(new Map([['17/settlement.json',{manager:'existing'}]]));
  assert.equal(h.context.ensureSettlement(17).manager,'existing');assert.equal(h.calls.length,0);
});
