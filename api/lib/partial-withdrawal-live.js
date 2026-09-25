'use strict';
const fs = require('fs');
const cli = require('./cli');
const producer = require('./block-producer');

// Caller holds the channel lock. Replay the exact already-signed burn, never sign another one.
// This also recovers legacy relay burns which omitted pw_producer.json.
async function prepareLiveBurn(ch) {
  const head = cli.readJson(cli.wc(ch, 'burn_cosigned.json'));
  const payload = cli.readJson(cli.wc(ch, 'burn_payload.json'));
  const descriptor = cli.readJson(cli.wc(ch, 'burn_descriptor.json'));
  const current = cli.readJson(cli.wc(ch, 'channel_snapshot.json'));
  if (head.channelId !== ch || head.digest !== current.state.digest
      || head.digest !== payload.proposedNextState.digest) {
    throw new Error('partial withdrawal must resume its exact signed burn head');
  }
  const producerRequestId = producer.stableRequestId('burn', { ch, debitPayload: payload, transferDescriptor: descriptor });
  const blockReceipt = await producer.postInterChannel(head, payload, descriptor, producerRequestId);
  cli.writeJson(cli.wc(ch, 'pw_producer.json'), { producerRequestId, blockReceipt, liveReceipt: null });
  const liveReceipt = await producer.liveSettleInterChannel(ch, blockReceipt, head, payload, descriptor);
  cli.writeJson(cli.wc(ch, 'pw_producer.json'), { producerRequestId, blockReceipt, liveReceipt });
  return { head, descriptor, producerRequestId, blockReceipt };
}

async function stageSubmitProof(ch) {
  const { head } = await prepareLiveBurn(ch);
  const backing = await producer.liveBackingArtifact(ch);
  if (backing.signedHead.digest !== head.digest
      || backing.baseHead.channelId !== ch
      || backing.baseHead.settledTxChain !== head.balanceState.settledTxChain) {
    throw new Error('live backing is not the exact post-burn head');
  }
  const verifier = Buffer.from(backing.balanceVerifierData);
  if (!verifier.equals(fs.readFileSync(cli.wc(ch, 'balance_vd.bin')))) {
    throw new Error('live balance verifier differs from the pinned channel verifier');
  }
  // Keep genesis attestation/private-state files paired and untouched. Only pw-submit consumes
  // this separately staged public proof, verified against the existing channel verifier.
  const kit = backing.signedHeadExitKit && backing.signedHeadExitKit.backingPublicInputs;
  if (!kit || kit.channelId !== ch || kit.settledTxChain !== head.balanceState.settledTxChain) {
    throw new Error('live backing has no matching signed-head exit proof');
  }
  const rollup = cli.rollupOf(ch);
  const finalized = cli.sh('cast', ['call', rollup, 'isFinalizedStateRoot(bytes32)(bool)',
    kit.finalizedExtendedStateCommitment, '--rpc-url', cli.RPC]).trim();
  const heightText = cli.sh('cast', ['call', rollup, 'latestFinalizedBlockNumber()(uint64)',
    '--rpc-url', cli.RPC]).trim().split(/\s+/)[0];
  const height = BigInt(heightText);
  if (finalized !== 'true' || height < BigInt(kit.anchorBlockNumber)) {
    throw Object.assign(new Error(`Withdrawal is waiting for L1 finalization: burn block ${kit.anchorBlockNumber}, `
      + `L1 finalized block ${height}. The operator must publish and finalize the existing producer history, `
      + 'then attest its signed-head backing before settlement. Your burn is saved; do not burn again.'),
    { status: 409 });
  }
  const file = 'pw_balance_attestation.bin';
  fs.writeFileSync(cli.wc(ch, file), Buffer.from(backing.balanceAttestation.balanceProof), { mode: 0o600 });
  return { PW_BALANCE_PROOF_FILE: file };
}

async function stagePayoutArtifacts(ch) {
  const { producerRequestId, descriptor, blockReceipt } = await prepareLiveBurn(ch);
  const auth = cli.readJson(cli.wc(ch, 'pw_auth.json'));
  const prover = cli.l1SignerAddress();
  const matches = artifacts => {
    const w = artifacts.withdrawal, a = artifacts.producerAnchor;
    return w && a && artifacts.withdrawalProver === prover.toLowerCase()
      && String(w.amount) === String(auth.withdrawal_amount)
      && w.recipient === auth.withdrawal_recipient.toLowerCase()
      && w.tokenIndex === auth.withdrawal_token_index && w.nullifier === auth.withdrawal_nullifier
      && w.auxData === auth.withdrawal_aux_data
      && ['blockNumber', 'bpSigChain', 'entryHash', 'extendedStateCommitment', 'generation', 'timestamp']
        .every(key => a[key] !== undefined && a[key] === blockReceipt[key]);
  };
  const file = cli.wc(ch, 'pw_artifacts.json');
  // The native payout journal pins the randomized MLE bytes in its candidate identity.
  // Retain them on retries, while refusing to reuse a different burn or producer anchor.
  if (fs.existsSync(file)) {
    const saved = cli.readJson(file);
    if (matches(saved)) return saved;
  }
  const artifacts = await producer.liveBurnPayoutArtifacts(ch, producerRequestId, descriptor, prover);
  if (!matches(artifacts)) throw new Error('payout proof does not match the authorized burn and producer anchor');
  cli.writeJson(file, artifacts);
  return artifacts;
}
function resumeSubmittedAuth(ch) {
  const file = cli.wc(ch, 'pw_auth.json');
  if (!fs.existsSync(file)) return null;
  const auth = cli.readJson(file), burn = cli.readJson(cli.wc(ch, 'last_burn.json'));
  const settlement = cli.readJson(cli.wc(ch, 'settlement.json'));
  // The burn nullifier and aux-data commitment identify the exact amount without rounding
  // the legacy u64 JSON number in last_burn.json through JavaScript's numeric representation.
  if (auth.manager !== settlement.manager || auth.withdrawal_nullifier !== burn.withdrawal_nullifier
      || auth.withdrawal_aux_data !== burn.aux_data || auth.withdrawal_recipient !== burn.withdrawal_recipient
      || auth.withdrawal_token_index !== burn.token_index) return null;
  const view = (address, signature, ...args) => cli.sh('cast', ['call', address, signature, ...args, '--rpc-url', cli.RPC]).trim();
  const pending = view(auth.manager, 'partialWithdrawalPending()(bool)') === 'true'
    && view(auth.manager, 'pendingPartialWithdrawalAuthDigest()(bytes32)') === auth.auth_digest;
  const rollup = cli.rollupOf(ch);
  if (pending || view(rollup, 'partialWithdrawalAuthorized(bytes32)(bool)', auth.auth_digest) === 'true'
      || view(rollup, 'withdrawalNullifierUsed(bytes32)(bool)', auth.withdrawal_nullifier) === 'true') return auth;
  return null;
}
// Anvil may briefly reject a historical state immediately after mining finality blocks.
// Re-enter ONLY the journaled payout driver, with unchanged proof files and authorization.
// Never retry arbitrary CLI errors or downgrade the native finalized-checkpoint requirement.
async function finalizeSavedPayout(ch, {rpc=cli.RPC, run=cli.cli, env={}, wait=ms=>new Promise(r=>setTimeout(r,ms))}={}) {
  for (let attempt=0; ; attempt++) {
    try { return run(ch, ['pw-finalize', rpc], env); }
    catch (error) {
      const detail=String(error.stderr || error.message || error);
      if (attempt>=2 || env.INTMAX_WALLET_ANVIL_MINE!=='1'
          || !detail.includes('BlockOutOfRangeError')
          || !/cast \["call",[^\n]*"--block"/.test(detail)) throw error;
      await wait(1000*(attempt+1));
    }
  }
}
module.exports = { prepareLiveBurn, stageSubmitProof, stagePayoutArtifacts, resumeSubmittedAuth, finalizeSavedPayout };
