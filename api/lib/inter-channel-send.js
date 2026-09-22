'use strict';
const path = require('path');

// Shared daemon-backed inter-channel transfer (source debit A + destination credit B, atomic).
//
// Extracted so BOTH the production api/ service (routes/inter-channel.js) and the legacy browser
// relay (hosting/wallet/wallet-relay.js) drive the EXACT same crash-recoverable sequence instead
// of the relay re-implementing (and drifting from) this security-critical flow. The legacy relay
// used to 503 inter-channel sends because it signed against the frozen setup-time nonce; this uses
// the resident base-state authority (`authoritativeBaseNonceEnv`) the daemon exposes, so the source
// debit and its base settlement stay consistent across sends.
//
// LOCKING: the caller MUST already hold the per-channel locks for BOTH `ch` (source A) and the
// descriptor's `destinationChannelId` (B) for the whole call — the cursor read
// (`authoritativeBaseNonceEnv`), the in-process co-sign, producer admission and live settlement
// must not interleave with another request on either channel.

const fs = require('fs');
const { isDeepStrictEqual } = require('node:util');
const { cli, wc, readJson, writeJson } = require('./cli');
const producer = require('./block-producer');
const { cliWithPreparedExitKit, installHeadExitKit, acknowledgePreparedExitKit, debitRequestId, OPERATION_FILE: EXIT_KIT_OPERATION_FILE } = require('./exit-kit');
const { flushPublishedHead } = require('./producer-head');

// Only the current destination recovery copy is eligible: a source's older completed send must
// never replace B's later incoming transfer sidecar. This is also the legacy migration trigger.
function matchingDestinationRecovery(destination, result) {
  const incomingPath = wc(destination, 'incoming_inter_transfer.json');
  if (!fs.existsSync(incomingPath) || !result.bBundleApplyState) return false;
  const incoming = readJson(incomingPath);
  return incoming.bBundleApplyState
    && incoming.bBundleApplyState.channelId === destination
    && incoming.bBundleApplyState.digest === result.bBundleApplyState.digest;
}

function archiveVerifiedDestinationRecovery(ch, destination, result, debitPayload, descriptor, producerRequestId) {
  if (!matchingDestinationRecovery(destination, result)) return;
  const recoveryPath = wc(destination, 'incoming_inter_transfer_recovery.json');
  const expected = { sourceChannelId: ch, producerRequestId, debitPayload, descriptor };
  if (fs.existsSync(recoveryPath)) {
    const saved = readJson(recoveryPath);
    // Native sidecars predating the API request-id flag use its deterministic source fallback.
    const savedId = saved.producerRequestId
      ?? producer.stableRequestId('inter', { ch, debitPayload: saved.debitPayload, transferDescriptor: saved.descriptor });
    if (saved.sourceChannelId !== ch || savedId !== producerRequestId
        || !isDeepStrictEqual(saved.debitPayload, debitPayload)
        || !isDeepStrictEqual(saved.descriptor, descriptor)) {
      throw new Error('destination recovery sidecar differs from the verified source transfer; retain both copies for recovery');
    }
    return;
  }
  // Called as soon as the signed result exists, while this exact source/destination pair is
  // locked. The CLI wrote the original signed incoming copy; the daemon phases re-verify.
  writeJson(recoveryPath, expected);
}

async function flushLastProducerBlock(ch, lockedDestination) {
  const debitPath = wc(ch, 'inter_debit_payload.json');
  const descriptorPath = wc(ch, 'inter_descriptor.json');
  const resultPath = wc(ch, 'inter_transfer.json');
  if (!(fs.existsSync(debitPath) && fs.existsSync(descriptorPath) && fs.existsSync(resultPath))) {
    return null;
  }
  const debitPayload = readJson(debitPath);
  const descriptor = readJson(descriptorPath);
  const result = readJson(resultPath);
  const signedState = result.aHead || result.sourceHead || result;
  const destination = Number(descriptor.destinationChannelId);
  if (!Number.isSafeInteger(destination) || !result.bFundImportState || !result.bSnapshot) {
    throw new Error('signed inter-channel result is missing destination binding/fund-import snapshot');
  }
  let operation = null;
  try { operation = readJson(wc(ch, 'inter_operation.json')); } catch (e) { /* pre-journal artifact */ }
  const producerRequestId = operation && operation.producerRequestId
    ? operation.producerRequestId
    : producer.stableRequestId('inter', { ch, debitPayload, transferDescriptor: descriptor });
  const blockReceipt = await producer.postInterChannel(
    signedState, debitPayload, descriptor, producerRequestId,
  );
  let destinationHeadReceipt = null;
  if (result.bFundImportState && result.bBundleApplyState) {
    destinationHeadReceipt = await producer.syncOffchainHeads([
      result.bFundImportState,
      result.bBundleApplyState,
    ]);
  }
  const liveReceipt = await producer.liveSettleInterChannel(
    ch,
    blockReceipt,
    signedState,
    debitPayload,
    descriptor,
  );
  acknowledgePreparedExitKit(ch, signedState);
  // The prepared debit kit was proved for the UNSIGNED successor; once the debit head is settled
  // the CLI must hold the kit for the SIGNED head (the archive it re-verifies before it can sign
  // anything else, or accept a later credit as a destination). Archive the live service's kit for
  // the current source head, exactly as the destination does below.
  await installHeadExitKit(ch);
  // The destination side is touched ONLY under the destination's lock. A previous transfer to a
  // THIRD channel D is not replayed here (the caller holds A and B, not D): D finishes its own
  // credit from its recovery sidecar the next time D itself is flushed (`recoverIncomingHead`).
  if (lockedDestination !== destination) {
    return { blockReceipt, destinationHeadReceipt, liveReceipt, destinationLiveReceipt: null };
  }
  const sourceArtifact = await producer.liveSendArtifact(ch, producerRequestId);
  const destinationLiveReceipt = await producer.liveReceiveInterChannel(destination, {
    producerReceipt: blockReceipt,
    debitPayload,
    descriptor,
    sourceArtifact,
    fundImportState: result.bFundImportState,
    destinationSnapshot: result.bSnapshot,
  });
  // The credited head was signed kit-pending; archive its exit kit into B's CLI state.
  await installHeadExitKit(destination);
  archiveVerifiedDestinationRecovery(ch, destination, result, debitPayload, descriptor, producerRequestId);
  return { blockReceipt, destinationHeadReceipt, liveReceipt, destinationLiveReceipt };
}

// The moved BASE token rides INSIDE the signed descriptor (interChannelTx.tokenIndex); an optional
// top-level `tokenIndex` is a client-intent cross-check only. Returns { status, body } so the HTTP
// caller can map it; throws on internal failure. The caller MUST hold locks on ch AND destination.
async function interChannelSend(ch, { debitPayload, transferDescriptor, tokenIndex }) {
  if (!debitPayload || !transferDescriptor) {
    return { status: 400, body: { error: 'needs { debitPayload, transferDescriptor, tokenIndex? }' } };
  }
  const destination = Number(transferDescriptor.destinationChannelId);
  if (!Number.isSafeInteger(destination) || destination < 0 || destination > 0xffffffff || destination === ch) {
    return { status: 400, body: { error: 'inter-channel destination must be a different valid channel' } };
  }
  const descTok = transferDescriptor.interChannelTx && transferDescriptor.interChannelTx.tokenIndex;
  if (tokenIndex !== undefined && tokenIndex !== null && String(tokenIndex) !== String(descTok)) {
    return { status: 400, body: { error: `tokenIndex mismatch: body says ${tokenIndex}, signed descriptor says ${descTok}` } };
  }
  const producerRequestId = producer.stableRequestId('inter', { ch, debitPayload, transferDescriptor });
  let operation = null;
  try { operation = readJson(wc(ch, 'inter_operation.json')); } catch (e) { /* first request */ }

  // Completed HTTP retries are content-addressed and return the already-settled response. An
  // in-flight operation may likewise be resumed only by the identical request; otherwise a caller
  // could overwrite the sole recovery inputs after the channel signature was committed.
  if (operation && operation.producerRequestId === producerRequestId && operation.status === 'completed') {
    if (!fs.existsSync(wc(destination, 'incoming_inter_transfer_recovery.json'))
        && fs.existsSync(wc(ch, 'inter_transfer.json'))
        && matchingDestinationRecovery(destination, readJson(wc(ch, 'inter_transfer.json')))) {
      await flushLastProducerBlock(ch, destination);
    }
    return { status: 200, body: operation.response };
  }
  if (operation && operation.status === 'prepared' && operation.producerRequestId !== producerRequestId) {
    return { status: 409, body: { error: 'a different inter-channel transition is signed or pending recovery' } };
  }
  if (operation && operation.status === 'prepared' && operation.producerRequestId === producerRequestId
      && !fs.existsSync(wc(ch, 'inter_transfer.json'))) {
    // The signing command may have died after committing its two-channel PREPARED journal but
    // before this route saw the result (e.g. the INTMAX_TEST_FAIL_INTER_TRANSFER_AFTER_SOURCE
    // failpoint, a kill -9). The CLI roll-forward is idempotent and re-creates the exact
    // `inter_transfer.json` (+ B's incoming copy) from the journal, so the daemon phases below can
    // resume without re-signing. If nothing was journaled it is a no-op and we sign afresh.
    cli(ch, ['recover-inter-transfers']);
  }
  if (operation
      && operation.status === 'prepared'
      && operation.producerRequestId === producerRequestId
      && fs.existsSync(wc(ch, 'inter_transfer.json'))) {
    const recovered = await flushLastProducerBlock(ch, destination);
    const recoveredResult = readJson(wc(ch, 'inter_transfer.json'));
    const response = {
      sourceHead: recoveredResult.aHead || recoveredResult.sourceHead || recoveredResult,
      destSnapshot: recoveredResult.bSnapshot || recoveredResult.destSnapshot || null,
      ...recovered,
    };
    writeJson(wc(ch, 'inter_operation.json'), {
      ...operation, status: 'completed', completedAt: Date.now(), response,
    });
    return { status: 200, body: response };
  }
  // Crash recovery: `cosign-inter-transfer` commits the N-of-N channel head before this route can
  // durably admit its producer block. The three artifacts are retained, so every later mutation
  // first idempotently flushes that exact signed head. A structurally rejected pending block stops
  // the channel here instead of letting its state outrun the base chain.
  if (!operation || operation.status !== 'prepared') {
    await flushLastProducerBlock(ch, destination);
    await flushPublishedHead(ch);
    fs.rmSync(wc(ch, 'inter_transfer.json'), { force: true });
    writeJson(wc(ch, 'inter_debit_payload.json'), debitPayload);
    writeJson(wc(ch, 'inter_descriptor.json'), transferDescriptor);
    operation = { producerRequestId, status: 'prepared', createdAt: Date.now() };
    writeJson(wc(ch, 'inter_operation.json'), operation);
  }
  // Both channel locks are held. Roll B's pending native deposit/state WAL and backing/head
  // publication forward before A's signing command reads that sibling wallet from disk — unless
  // THIS transfer's pre-sign exit kit is already staged (a retry after the signing command died):
  // the staged block freezes every other producer mutation, and B's head cannot have moved since
  // the kit was proved against it, so the flush would only collide with the freeze.
  let exitKitOperation = null;
  try { exitKitOperation = readJson(wc(ch, EXIT_KIT_OPERATION_FILE)); } catch (e) { /* none */ }
  const exitKitInFlight = exitKitOperation && exitKitOperation.status !== 'complete';
  if (!exitKitInFlight) await flushPublishedHead(destination);
  // Read under the same lock that encloses signing + producer admission + live settlement, so a
  // second request cannot observe/reuse this cursor before the first advances.
  const liveNonceEnv = await producer.authoritativeBaseNonceEnv(ch);
  // Signer-independent exit: the source debit's exit kit is proved against the staged producer
  // block before any A-side signature; B signs its pure credit against its durable head receipt.
  try {
    await cliWithPreparedExitKit(
      ch,
      ['cosign-inter-transfer', 'inter_debit_payload.json', 'inter_descriptor.json', 'inter_transfer.json',
        `--producer-request-id=${producerRequestId}`],
      liveNonceEnv,
      { requestId: producerRequestId },
    );
  } catch (e) {
    // The signing command failed. If the source leg did NOT commit (no CLI roll-forward journal for
    // this tx and no signed result), nothing is pending: a deterministic refusal (stale head, bad
    // proof, insufficient balance) must not leave the channel in `prepared` forever — that made
    // every later transfer from it a 409 and re-ran the same failing command on each sweep — nor
    // leave the staged exit-kit block freezing every producer mutation on every channel. Only a
    // commit that did happen (journal present) stays pending for `resumePendingInterTransfer`.
    if (!sourceLegCommitted(ch, transferDescriptor)) {
      await abandonUncommittedTransfer(ch, producerRequestId, e);
      throw Object.assign(e, { status: e.status || 409 });
    }
    throw e;
  }
  const result = readJson(wc(ch, 'inter_transfer.json'));
  const sourceHead = result.aHead || result.sourceHead || result;
  if (!result.bFundImportState || !result.bSnapshot) {
    throw new Error('cosign-inter-transfer omitted destination binding/fund-import snapshot');
  }
  // Write B's recovery sidecar NOW, under both locks: it holds only the signed inputs, and
  // `recoverIncomingHead` re-verifies everything against the daemon. Written only at the end, a
  // crash between the head sync below and completion left B's public head credited with no way
  // for B to finish its own receive (every B flush and its /snapshot failed until A resumed).
  archiveVerifiedDestinationRecovery(ch, destination, result, debitPayload, transferDescriptor, producerRequestId);
  const blockReceipt = await producer.postInterChannel(
    sourceHead, debitPayload, transferDescriptor, producerRequestId,
  );
  const destinationHeadReceipt = result.bFundImportState && result.bBundleApplyState
    ? await producer.syncOffchainHeads([result.bFundImportState, result.bBundleApplyState])
    : null;
  // The authoritative nonce above can only come from the resident base-state service, so its
  // matching settle is mandatory: skipping would commit the channel debit while leaving that
  // authority at the old nonce, recreating the next-send strand this route prevents.
  const liveReceipt = await producer.liveSettleInterChannel(
    ch, blockReceipt, sourceHead, debitPayload, transferDescriptor,
  );
  acknowledgePreparedExitKit(ch, sourceHead);
  // Replace the promoted prepared kit (proved for the unsigned successor) with the live service's
  // kit for the now fully signed debit head — see flushLastProducerBlock.
  await installHeadExitKit(ch);
  // Source settlement alone advances only the sender's private base state. The destination must
  // consume the source proof + both N-of-N credit states before this completes, or the credited
  // snapshot cannot be spent from the resident destination balance proof.
  const sourceArtifact = await producer.liveSendArtifact(ch, producerRequestId);
  const destinationLiveReceipt = await producer.liveReceiveInterChannel(destination, {
    producerReceipt: blockReceipt,
    debitPayload,
    descriptor: transferDescriptor,
    sourceArtifact,
    fundImportState: result.bFundImportState,
    destinationSnapshot: result.bSnapshot,
  });
  // The credited head was signed kit-pending; archive its exit kit into B's CLI state now so B's
  // next H2=0 signature has a receipt for its durable head.
  await installHeadExitKit(destination);
  archiveVerifiedDestinationRecovery(ch, destination, result, debitPayload, transferDescriptor, producerRequestId);
  const response = {
    sourceHead,
    destSnapshot: result.bSnapshot || result.destSnapshot || null,
    blockReceipt,
    destinationHeadReceipt,
    liveReceipt,
    destinationLiveReceipt,
  };
  writeJson(wc(ch, 'inter_operation.json'), {
    ...operation, status: 'completed', completedAt: Date.now(), response,
  });
  return { status: 200, body: response };
}

// True once `cosign-inter-transfer` has committed the source leg: it writes its roll-forward
// journal `<work>/.inter-transfer-journal/<txHash>.json` before anything durable changes, and the
// signed result once both legs are applied.
function sourceLegCommitted(ch, transferDescriptor) {
  if (fs.existsSync(wc(ch, 'inter_transfer.json'))) return true;
  const txHash = transferDescriptor && transferDescriptor.txHash;
  if (typeof txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) return false;
  const journal = path.join(path.dirname(wc(ch, 'inter_operation.json')), '..', '.inter-transfer-journal', `${txHash.slice(2).toLowerCase()}.json`);
  return fs.existsSync(journal);
}

// Drop a transfer whose signing was refused before the source committed: release the producer's
// staged exit-kit block (it freezes every other mutation until committed or abandoned), clear the
// pre-sign operation and the pending request journal. Best effort on the daemon call — a daemon
// that is down leaves the staged block, which `livePrepareExitKit`'s own failure path or the next
// identical retry resolves.
async function abandonUncommittedTransfer(ch, producerRequestId, cause) {
  try { await producer.liveAbandonPreparedExitKit(ch, debitRequestId(producerRequestId)); }
  catch (e) { console.error(`[inter] channel ${ch}: abandon staged exit kit ${producerRequestId}: ${String(e.message || e).slice(0, 200)}`); }
  for (const f of ['inter_operation.json', EXIT_KIT_OPERATION_FILE, 'exit_kit_proposal.json', 'prepared_exit_kit.json']) {
    fs.rmSync(wc(ch, f), { force: true });
  }
  console.error(`[inter] channel ${ch}: transfer ${producerRequestId} refused before the source committed, nothing pending: ${String(cause.message || cause).split('\n').find((l) => /^error:/.test(l)) || String(cause.message || cause).slice(0, 200)}`);
}

// A PREPARED operation whose client went away — the browser closed after the debit was signed,
// the relay crashed between the two daemon phases, or the destination rejected a credit that a
// later fix now accepts — is resumable by the RELAY ALONE: the exact request is retained in
// `inter_debit_payload.json` / `inter_descriptor.json` / `inter_operation.json`, and
// `interChannelSend` keys its idempotent resume on that request id. The sender never has to
// come back, and a new sender on the same source channel is not blocked forever behind it.
function pendingInterTransfer(ch) {
  let operation = null;
  try { operation = readJson(wc(ch, 'inter_operation.json')); } catch (e) { return null; }
  if (!operation || operation.status !== 'prepared') return null;
  const debitPath = wc(ch, 'inter_debit_payload.json');
  const descriptorPath = wc(ch, 'inter_descriptor.json');
  if (!fs.existsSync(debitPath) || !fs.existsSync(descriptorPath)) return null;
  const debitPayload = readJson(debitPath);
  const transferDescriptor = readJson(descriptorPath);
  const destination = Number(transferDescriptor && transferDescriptor.destinationChannelId);
  return {
    operation, debitPayload, transferDescriptor, destination,
    signed: fs.existsSync(wc(ch, 'inter_transfer.json')),
    producerRequestId: operation.producerRequestId,
    createdAt: operation.createdAt,
  };
}

// Resume the pending transfer of `ch` with its retained request. The caller MUST hold the locks
// of `ch` and of the pending destination (see `pendingInterTransfer(ch).destination`). Returns
// null when nothing is pending, otherwise `interChannelSend`'s { status, body }.
async function resumePendingInterTransfer(ch) {
  const pending = pendingInterTransfer(ch);
  if (!pending) return null;
  return interChannelSend(ch, {
    debitPayload: pending.debitPayload,
    transferDescriptor: pending.transferDescriptor,
  });
}

module.exports = {
  interChannelSend, flushLastProducerBlock, matchingDestinationRecovery,
  pendingInterTransfer, resumePendingInterTransfer,
};
