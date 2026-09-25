'use strict';
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const {projectToSlim}=require('./batch-window');
function canonical(value) {
  if(value===null || typeof value!=='object')return JSON.stringify(value);
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
}
function fatId(payload) { return crypto.createHash('sha256').update(canonical(projectToSlim(payload))).digest('hex'); }
function accepted(directory,id) {
  if(!/^[a-f0-9]{64}$/.test(id))throw Error('invalid send receipt identity');
  let state;
  try {state=JSON.parse(fs.readFileSync(path.join(directory,'cli_state.json'),'utf8'));}
  catch(error){if(error.code==='ENOENT')return null;throw error;}
  const digest=state.accepted_send_receipts?.[id];
  if(!digest)return null;
  if(!/^0x[a-f0-9]{64}$/i.test(digest))throw Error('invalid accepted send head');
  const result=JSON.parse(fs.readFileSync(path.join(directory,'accepted_send_states',digest+'.json'),'utf8'));
  if(result.digest!==digest || !Number.isInteger(result.balanceState?.stateVersion))throw Error('accepted send archive differs from receipt');
  return result;
}
module.exports={fatId,accepted};
