'use strict';
// Process-death test for the relay journal. Crypto/L1 boundaries are simulated, never real funds.
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const {createBurnOperations}=require('../../../api/lib/burn-operation');
const [directory,stop]=process.argv.slice(2);
function read(file){return JSON.parse(fs.readFileSync(path.join(directory,file),'utf8'));}
function write(file,value){const dest=path.join(directory,file);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,JSON.stringify(value));}
const head={channelId:7,digest:'signed'},input={debitPayload:{proposedNextState:head},transferDescriptor:{proof:'same'}};
const checkpoint=async name=>{if(stop===name)process.kill(process.pid,'SIGKILL');};
const cli={wc:(_,file)=>path.join(directory,file),readJson:file=>JSON.parse(fs.readFileSync(file)),writeJson:(file,value)=>{fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,JSON.stringify(value));},cli:()=>{if(fs.existsSync(path.join(directory,'native-wal.json')))write('burn_cosigned.json',read('native-wal.json'));}};
const bp={stableRequestId:(kind,value)=>kind+':'+crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex'),authoritativeBaseNonceEnv:async()=>({}),postInterChannel:async(_h,_p,_d,id)=>{write('producer-id.json',id);return {id};},liveSettleInterChannel:async(_ch,r)=>write('live-id.json',r.id)};
const kit={cliWithPreparedExitKit:async()=>{let count=0;try{count=read('sign-count.json');}catch{}write('sign-count.json',count+1);write('native-wal.json',head);await checkpoint('native-signed');write('burn_cosigned.json',head);},acknowledgePreparedExitKit:()=>{}};
const tickets={findActiveTicket:()=>{try{return read('ticket.json');}catch(e){if(e.code==='ENOENT')return null;throw e;}},upsertTicket:(_,ticket)=>write('ticket.json',ticket)};
createBurnOperations({cli,bp,kit,checkpoint}).run(7,stop?input:{},tickets).catch(error=>{console.error(error);process.exitCode=1;});
