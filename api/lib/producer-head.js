const fs = require('fs');
const { cli, wc, readJson } = require('./cli');
const producer = require('./block-producer');
const { acknowledgePreparedExitKit, installHeadExitKit } = require('./exit-kit');

function sameJsonValue(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function isZeroH2Tag(value) {
  return typeof value === 'string' && /^0x0{64}$/i.test(value);
}

// B's immutable 2PC recovery copy is sufficient to finish a signed credit without another
// signature or A's mutable convenience files. Complete the private receive and exact-head kit
// before exposing B's credited public head. Every daemon phase reuses the original request id.
async function recoverIncomingHead(ch, incoming) {
  const recoveryPath = wc(ch, 'incoming_inter_transfer_recovery.json');
  if (!fs.existsSync(recoveryPath)) {
    throw new Error('incoming inter-channel credit has no destination recovery sidecar; retry the original source transfer to finish its live receive and exit kit');
  }
  const recovery = readJson(recoveryPath);
  const source = recovery && recovery.sourceChannelId;
  const descriptor = recovery && recovery.descriptor;
  const debitPayload = recovery && recovery.debitPayload;
  const sourceHead = incoming.aHead;
  const fund = incoming.bFundImportState;
  const bundle = incoming.bBundleApplyState;
  const destinationSnapshot = incoming.bSnapshot;
  if (!Number.isSafeInteger(source) || source <= 0 || source >= 0xffffffff || source === ch
      || !sourceHead || sourceHead.channelId !== source
      || !descriptor || descriptor.sourceChannelId !== source || descriptor.destinationChannelId !== ch
      || !debitPayload || !debitPayload.proposedNextState
      || !sameJsonValue(debitPayload.proposedNextState.digest, sourceHead.digest)
      || fund.channelId !== ch || bundle.channelId !== ch
      || !sameJsonValue(bundle.prevDigest, fund.digest)
      || !destinationSnapshot || !destinationSnapshot.state
      || destinationSnapshot.state.channelId !== ch
      || !sameJsonValue(destinationSnapshot.state.digest, bundle.digest)) {
    throw new Error('incoming inter-channel recovery inputs do not match the signed channel pair; retain the artifacts and retry the original source transfer');
  }
  const savedRequestId = recovery.producerRequestId;
  if (savedRequestId != null && (typeof savedRequestId !== 'string' || savedRequestId.length === 0)) {
    throw new Error('incoming inter-channel recovery has an invalid producer request id');
  }
  const producerRequestId = savedRequestId
    ?? producer.stableRequestId('inter', { ch: source, debitPayload, transferDescriptor: descriptor });
  const producerReceipt = await producer.postInterChannel(
    sourceHead, debitPayload, descriptor, producerRequestId,
  );
  await producer.liveSettleInterChannel(source, producerReceipt, sourceHead, debitPayload, descriptor);
  const sourceArtifact = await producer.liveSendArtifact(source, producerRequestId);
  await producer.liveReceiveInterChannel(ch, {
    producerReceipt, debitPayload, descriptor, sourceArtifact,
    fundImportState: fund, destinationSnapshot,
  });
  await installHeadExitKit(ch);
}

// Reconcile one CLI-committed H2=0 state with the durable producer. Stable request ids inside the
// producer client make retries idempotent. H2-bearing source debits deliberately fail here: those
// must be replayed with their debit payload + descriptor through postInterChannel.
async function syncStateIfNeeded(state) {
  const status = await producer.status();
  const channelHead = (status.channelHeads || []).find(
    head => sameJsonValue(head.channelId, state.channelId),
  );
  if (!channelHead) {
    throw new Error('channel is not registered in the production block producer');
  }
  if (sameJsonValue(channelHead.stateDigest, state.digest)) return null;
  return producer.syncOffchainHeads([state]);
}

// Publish one ordinary N-of-N H2=0 state in the only safe order:
//   durable resident backing -> durable public producer head.
// A crash after phase one is harmless (the live bind is exact-idempotent); a live-bind failure
// cannot leave `/snapshot` ahead of `/backing`.  The full ChannelSnapshot is always re-read from
// the CLI's canonical file instead of manufacturing a record/member wrapper around response data.
async function publishOffchainSnapshot(ch, expectedState) {
  const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
  if (!snapshot || !snapshot.state || !expectedState
      || !sameJsonValue(snapshot.state.channelId, expectedState.channelId)
      || !sameJsonValue(snapshot.state.digest, expectedState.digest)) {
    throw new Error('canonical channel snapshot differs from the just-cosigned state');
  }
  if (!isZeroH2Tag(snapshot.state.h2Tag)) {
    throw new Error('ordinary off-chain publication requires an exact H2=0 signed head');
  }
  const liveStatus = await producer.liveBindSnapshot(ch, snapshot);
  const headSyncReceipt = await syncStateIfNeeded(snapshot.state);
  acknowledgePreparedExitKit(ch, snapshot.state);
  return { snapshot, liveStatus, headSyncReceipt };
}

async function flushPublishedHead(ch) {
  // Repair a crash between the two local channel-state replacements before looking at either
  // published snapshot or producer artifact. The CLI command is an idempotent 2PC roll-forward.
  cli(ch, ['recover-inter-transfers']);
  // The private CLI snapshot is authoritative. If the prior process died after committing it but
  // before atomically replacing the convenience public file, roll that publication forward now.
  cli(ch, ['publish-snapshot', 'channel_snapshot.json']);
  const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
  const deferredHeadStates = [];

  // Source-side H2 transition. The CLI may have committed its channel state immediately before
  // the API crashed; the retained public payload/descriptor/result reproduce the exact producer
  // admission. Only use an artifact whose final digest is the currently published head.
  const interResultPath = wc(ch, 'inter_transfer.json');
  const interDebitPath = wc(ch, 'inter_debit_payload.json');
  const interDescriptorPath = wc(ch, 'inter_descriptor.json');
  if (
    fs.existsSync(interResultPath)
    && fs.existsSync(interDebitPath)
    && fs.existsSync(interDescriptorPath)
  ) {
    const result = readJson(interResultPath);
    const sourceHead = result.aHead || result.sourceHead;
    if (sourceHead && sameJsonValue(sourceHead.digest, snapshot.state.digest)) {
      const debitPayload = readJson(interDebitPath);
      const descriptor = readJson(interDescriptorPath);
      let operation = null;
      try { operation = readJson(wc(ch, 'inter_operation.json')); } catch (e) { /* pre-journal */ }
      const producerRequestId = operation && operation.producerRequestId
        ? operation.producerRequestId
        : producer.stableRequestId('inter', { ch, debitPayload, transferDescriptor: descriptor });
      const producerReceipt = await producer.postInterChannel(
        sourceHead,
        debitPayload,
        descriptor,
        producerRequestId,
      );
      if (result.bFundImportState && result.bBundleApplyState) {
        await producer.syncOffchainHeads([
          result.bFundImportState,
          result.bBundleApplyState,
        ]);
      }
      // Producer admission and the resident private/base proof are two durable phases. Replaying
      // only the first after a crash leaves the public channel head advanced while /base-head still
      // exposes the old nonce; the next request can then be signed at a duplicate cursor. The live
      // service keys idempotence by the producer request id, so this replay is safe both before and
      // after a successful prior settlement.
      await producer.liveSettleInterChannel(
        ch,
        producerReceipt,
        sourceHead,
        debitPayload,
        descriptor,
      );
      acknowledgePreparedExitKit(ch, sourceHead);
    }
  }

  // Destination-side recovery copies written by the atomic inter-channel CLI. Replaying only
  // the public credit states would leave B without its private receive proof or latest-head kit.
  const incomingPath = wc(ch, 'incoming_inter_transfer.json');
  if (fs.existsSync(incomingPath)) {
    const incoming = readJson(incomingPath);
    if (
      incoming.bFundImportState
      && incoming.bBundleApplyState
      && sameJsonValue(incoming.bBundleApplyState.digest, snapshot.state.digest)
    ) {
      await recoverIncomingHead(ch, incoming);
      deferredHeadStates.push(
        incoming.bFundImportState,
        incoming.bBundleApplyState,
      );
    }
  }

  // L1 deposits have the same two-step receive shape.
  const depositPath = wc(ch, 'l1_import_cosigned.json');
  if (fs.existsSync(depositPath)) {
    const deposit = readJson(depositPath);
    if (
      deposit.fundImportState
      && deposit.bundleApplyState
      && sameJsonValue(deposit.bundleApplyState.digest, snapshot.state.digest)
    ) {
      deferredHeadStates.push(
        deposit.fundImportState,
        deposit.bundleApplyState,
      );
    }
  }

  // H2=0 heads are not public until the exact full signed snapshot is durably archived with the
  // resident balance proof.  Deposit/destination recovery states are deliberately deferred until
  // after this bind, closing the crash window where the public producer could outrun backing.
  if (isZeroH2Tag(snapshot.state && snapshot.state.h2Tag)) {
    await producer.liveBindSnapshot(ch, snapshot);
  }
  if (deferredHeadStates.length > 0) {
    await producer.syncOffchainHeads(deferredHeadStates);
    for (const state of deferredHeadStates) acknowledgePreparedExitKit(ch, state);
  }

  const receipt = await syncStateIfNeeded(snapshot.state);
  acknowledgePreparedExitKit(ch, snapshot.state);
  return receipt;
}

module.exports = {
  flushPublishedHead,
  isZeroH2Tag,
  publishOffchainSnapshot,
  sameJsonValue,
  syncStateIfNeeded,
};
