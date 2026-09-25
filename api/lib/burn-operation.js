'use strict';
// A burn must acquire a durable recovery owner BEFORE it can release any signature.
// Native burn_recovery owns the signing WAL; this journal owns producer/ticket completion.
const fs = require('fs');
const {isDeepStrictEqual} = require('node:util');
const cliModule = require('./cli');
const producer = require('./block-producer');
const exitKit = require('./exit-kit');
const FILE = 'burn_operation.json';
function createBurnOperations({cli=cliModule, bp=producer, kit=exitKit, checkpoint=async()=>{}}={}) {
  function read(ch, name=FILE) {
    try { return cli.readJson(cli.wc(ch,name)); }
    catch(e) { if(e.code==='ENOENT') return null; throw e; }
  }
  function save(ch,op) { cli.writeJson(cli.wc(ch,FILE),op); }
  function completedFile(id) { return `burn_results/${id.slice('burn:'.length)}.json`; }
  function pending(ch) { const op=read(ch);return op && op.phase!=='complete' ? op : null; }
  async function run(ch, input, {findActiveTicket,upsertTicket,getTicket=()=>null}) {
    let op=read(ch);
    const hasInput=!!(input && input.debitPayload && input.transferDescriptor);
    if (input && (!!input.debitPayload !== !!input.transferDescriptor)) throw Object.assign(Error('Burn needs both proof and descriptor'),{status:400});
    const descTok=input?.transferDescriptor?.interChannelTx?.tokenIndex;
    if(hasInput && input.tokenIndex!=null && String(input.tokenIndex)!==String(descTok)) throw Object.assign(Error('tokenIndex mismatch with signed descriptor'),{status:400});
    const id=hasInput ? bp.stableRequestId('burn',{ch,debitPayload:input.debitPayload,transferDescriptor:input.transferDescriptor}) : op?.id;
    if (!id) throw Object.assign(Error('No saved burn to resume'),{status:400});
    if (!/^burn:[0-9a-f]{64}$/.test(id)) throw Error('Invalid saved burn identity');
    const done=read(ch,completedFile(id));
    if(done) {
      if(done.schemaVersion!==1 || done.id!==id || done.phase!=='complete' || !done.head || done.head.digest!==done.input?.debitPayload?.proposedNextState?.digest) throw Error('Invalid completed burn record');
      return done.head;
    }
    if(op && op.phase!=='complete' && op.id!==id) throw Object.assign(Error('A saved burn must finish before another burn'),{status:409});
    const active=findActiveTicket(ch,'partial_withdrawal');
    if(active && active.params?.producerRequestId!==id) {
      throw Object.assign(Error('resolve the active partial withdrawal before burning again'),{status:409});
    }
    const previousTicket=getTicket(ch,`pw_${id.slice('burn:'.length)}`) || active;
    if(previousTicket?.params?.producerRequestId===id && previousTicket.steps?.burn && (!op || op.id!==id)) {
      const legacyHead=read(ch,'burn_cosigned.json');
      if(!legacyHead || legacyHead.digest!==input?.debitPayload?.proposedNextState?.digest || legacyHead.channelId!==ch) {
        throw Object.assign(Error('This burn already completed; its historical signed result is unavailable. Do not burn again.'),{status:409});
      }
    }
    if(!op || op.id!==id) {
      if(!hasInput) throw Object.assign(Error('Burn needs its original proof and descriptor'),{status:400});
      // Reject stale/invalid new proofs BEFORE they can become a durable exclusion owner.
      // This native mode can only propose; it never releases signatures or stages a producer
      // block. Once ownership exists, all failures retain the exact request for recovery.
      cli.cli(ch,['recover-inter-transfers']);
      const recovered=read(ch,'burn_cosigned.json');
      const recoveredMatches=recovered && recovered.digest===input.debitPayload.proposedNextState?.digest && recovered.channelId===ch;
      if(recoveredMatches && (!isDeepStrictEqual(read(ch,'burn_payload.json'),input.debitPayload)
          || !isDeepStrictEqual(read(ch,'burn_descriptor.json'),input.transferDescriptor))) {
        throw Object.assign(Error('Saved signed burn belongs to different proof inputs; no new burn was started'),{status:409});
      }
      if(!recoveredMatches) {
        const args=['cosign-burn-send','burn_payload.json','burn_descriptor.json','burn_cosigned.json'];
        const inputs=[{name:args[1],value:input.debitPayload},{name:args[2],value:input.transferDescriptor}];
        const priorKit=read(ch,'exit_kit_operation.json');
        if(priorKit && priorKit.status!=='complete') {
          const binding=bp.stableRequestId('presign',{ch,args,inputs,requestId:id});
          if(priorKit.binding!==binding) throw Object.assign(Error('An earlier signing operation must recover before another burn'),{status:409});
        } else {
          cli.writeJson(cli.wc(ch,args[1]),input.debitPayload);
          cli.writeJson(cli.wc(ch,args[2]),input.transferDescriptor);
          const env=await bp.authoritativeBaseNonceEnv(ch);
          cli.cli(ch,[...args,'--propose-exit-kit'],env);
        }
      }
      op={schemaVersion:1,id,phase:'prepared',createdAt:Date.now(),input};
      save(ch,op);
    }
    if(op.schemaVersion!==1 || !op.input?.debitPayload || !op.input?.transferDescriptor
       || bp.stableRequestId('burn',{ch,debitPayload:op.input.debitPayload,transferDescriptor:op.input.transferDescriptor})!==id) {
      throw Error('Saved burn operation is invalid; recovery inputs retained');
    }
    const ticket={id:`pw_${id.slice('burn:'.length)}`,type:'partial_withdrawal',status:'burn_pending',createdAt:op.createdAt,
      params:{producerRequestId:id,amount:String(op.input.amount||''),recipient:op.input.recipient||'',tokenIndex:String(op.input.transferDescriptor.interChannelTx?.tokenIndex ?? 0)},steps:{burn:null,settle:null}};
    const savedTicket=previousTicket;
    if(savedTicket?.params?.producerRequestId===id && savedTicket.steps?.burn && op.head && ['live','complete'].includes(op.phase)) {
      op.phase='complete';
      fs.mkdirSync(require('path').dirname(cli.wc(ch,completedFile(id))),{recursive:true});
      cli.writeJson(cli.wc(ch,completedFile(id)),op);save(ch,op);
      return op.head;
    }
    if(!savedTicket?.steps?.burn) upsertTicket(ch,ticket);
    await checkpoint('prepared',op);
    // Roll forward the native fsynced signing transaction before inspecting convenience outputs.
    cli.cli(ch,['recover-inter-transfers']);
    if(!op.head) {
      const proposed=op.input.debitPayload.proposedNextState;
      const existing=read(ch,'burn_cosigned.json');
      if(existing && proposed && existing.digest===proposed.digest && existing.channelId===ch) {
        op.head=existing;
      } else {
        cli.writeJson(cli.wc(ch,'burn_payload.json'),op.input.debitPayload);
        cli.writeJson(cli.wc(ch,'burn_descriptor.json'),op.input.transferDescriptor);
        const env=await bp.authoritativeBaseNonceEnv(ch);
        await kit.cliWithPreparedExitKit(ch,['cosign-burn-send','burn_payload.json','burn_descriptor.json','burn_cosigned.json'],env,{requestId:id});
        op.head=read(ch,'burn_cosigned.json');
      }
      if(!op.head || op.head.digest!==proposed?.digest || op.head.channelId!==ch) throw Error('Saved signed burn differs from its original request');
      op.phase='signed';save(ch,op);
    }
    if(!isDeepStrictEqual(op.input.debitPayload.proposedNextState.digest,op.head.digest)) throw Error('Burn head binding changed');
    await checkpoint('signed',op);
    const receipt=await bp.postInterChannel(op.head,op.input.debitPayload,op.input.transferDescriptor,id);
    cli.writeJson(cli.wc(ch,'pw_producer.json'),{producerRequestId:id,blockReceipt:receipt,liveReceipt:null});
    await checkpoint('producer',op);
    const liveReceipt=await bp.liveSettleInterChannel(ch,receipt,op.head,op.input.debitPayload,op.input.transferDescriptor);
    cli.writeJson(cli.wc(ch,'pw_producer.json'),{producerRequestId:id,blockReceipt:receipt,liveReceipt});
    kit.acknowledgePreparedExitKit(ch,op.head);
    op.blockReceipt=receipt;op.liveReceipt=liveReceipt;op.phase='live';save(ch,op);
    await checkpoint('live',op);
    ticket.status='burn_done';ticket.steps.burn={completedAt:Date.now()};
    if(!savedTicket?.steps?.burn) upsertTicket(ch,ticket);
    await checkpoint('ticket',op);
    op.phase='complete';
    fs.mkdirSync(require('path').dirname(cli.wc(ch,completedFile(id))),{recursive:true});
    cli.writeJson(cli.wc(ch,completedFile(id)),op);
    save(ch,op);
    return op.head;
  }
  function result(ch,input) {
    const id=input?.debitPayload && input?.transferDescriptor
      ? bp.stableRequestId('burn',{ch,debitPayload:input.debitPayload,transferDescriptor:input.transferDescriptor}) : read(ch)?.id;
    if(!/^burn:[0-9a-f]{64}$/.test(id||'')) throw Error('No saved burn result');
    const op=read(ch,completedFile(id));
    if(!op || op.phase!=='complete') throw Error('Burn result is not complete');
    return {id:op.id,blockReceipt:op.blockReceipt,liveReceipt:op.liveReceipt};
  }
  return {run,pending,result};
}
module.exports={createBurnOperations,FILE};
