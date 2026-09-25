'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),path=require('path'),vm=require('vm');
const source=fs.readFileSync(path.join(__dirname,'../../hosting/wallet/wallet-relay.js'),'utf8');
const fn=source.slice(source.indexOf('function drainCosignWindow('),source.indexOf('const cosignBatcher'));
const {partitionByAnchor}=require('../../hosting/wallet/batch-window');
function setup(fail){const calls=[],state={channelId:7,digest:'accepted',h2Tag:'0x'+'00'.repeat(32)};const context={sendReceipts:{accepted:()=>null,fatId:()=>''},chDir:()=>'',withLock:(_,fn)=>fn(),fs:{readFileSync:()=>JSON.stringify({state})},wc:()=>'',partitionByAnchor,flushPublishedHead:async()=>{calls.push('flush');if(fail)throw Error('unbound');}};vm.createContext(context);vm.runInContext(fn,context);return {run:context.drainCosignWindow,calls,state};}
test('exact solo replay flushes its committed state and returns without signing again',async()=>{const h=setup();let result;await h.run(7,[{payload:{proposedNextState:{channelId:7,digest:'accepted'}},resolve:r=>result=r}]);assert.equal(result.digest,'accepted');assert.deepEqual(h.calls,['flush']);});
test('replay cannot acknowledge a committed head whose backing is still unavailable',async()=>{const h=setup(true);let resolved=false;await assert.rejects(h.run(7,[{payload:{proposedNextState:{channelId:7,digest:'accepted'}},resolve:()=>resolved=true}]),/unbound/);assert.equal(resolved,false);});
test('different or cross-channel requests are not mistaken for a completed replay',async()=>{const h=setup();for(const proposedNextState of [{channelId:8,digest:'accepted'},{channelId:7,digest:'other'}]){let rejected=false;await h.run(7,[{payload:{proposedNextState},reject:()=>rejected=true}]);assert.equal(rejected,true);}assert.deepEqual(h.calls,[]);});
test('lost batch response resolves each original request after a newer head without re-signing',async()=>{
 const older={channelId:7,digest:'batch-accepted',balanceState:{stateVersion:4}},latest={channelId:7,digest:'later',h2Tag:'0x'+'00'.repeat(32)};
 let flushes=0;const context={withLock:(_,fn)=>fn(),chDir:()=>'',wc:()=>'',fs:{readFileSync:()=>JSON.stringify({state:latest})},partitionByAnchor,sendReceipts:{fatId:p=>p.id,accepted:(_,id)=>['a','b'].includes(id)?older:null},flushPublishedHead:async()=>{flushes++;}};
 vm.createContext(context);vm.runInContext(fn,context);const results=[];
 await context.drainCosignWindow(7,['a','b'].map(id=>({payload:{id,proposedNextState:{prevDigest:'old-anchor',digest:'solo-'+id}},resolve:r=>results.push(r),reject:e=>{throw e;}})));
 assert.deepEqual(results,[older,older]);assert.equal(flushes,1);
});
