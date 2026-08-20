const fs = require('fs');
const { cli, wc, readJson } = require('./cli');
const producer = require('./block-producer');

function sameJsonValue(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
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

async function flushPublishedHead(ch) {
  // Repair a crash between the two local channel-state replacements before looking at either
  // published snapshot or producer artifact. The CLI command is an idempotent 2PC roll-forward.
  cli(ch, ['recover-inter-transfers']);
  const snapshot = readJson(wc(ch, 'channel_snapshot.json'));

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
      await producer.postInterChannel(
        sourceHead,
        readJson(interDebitPath),
        readJson(interDescriptorPath),
      );
      if (result.bFundImportState && result.bBundleApplyState) {
        await producer.syncOffchainHeads([
          result.bFundImportState,
          result.bBundleApplyState,
        ]);
      }
    }
  }

  // Destination-side recovery copy written by the atomic inter-channel CLI.
  const incomingPath = wc(ch, 'incoming_inter_transfer.json');
  if (fs.existsSync(incomingPath)) {
    const incoming = readJson(incomingPath);
    if (
      incoming.bFundImportState
      && incoming.bBundleApplyState
      && sameJsonValue(incoming.bBundleApplyState.digest, snapshot.state.digest)
    ) {
      await producer.syncOffchainHeads([
        incoming.bFundImportState,
        incoming.bBundleApplyState,
      ]);
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
      await producer.syncOffchainHeads([
        deposit.fundImportState,
        deposit.bundleApplyState,
      ]);
    }
  }

  return syncStateIfNeeded(snapshot.state);
}

module.exports = { flushPublishedHead, sameJsonValue, syncStateIfNeeded };
