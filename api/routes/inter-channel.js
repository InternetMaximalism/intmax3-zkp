const { Router } = require('express');
const fs = require('fs');
const { cli, wc, readJson, writeJson } = require('../lib/cli');
const { withLocks } = require('../lib/lock');
const producer = require('../lib/block-producer');
const { cliWithPreparedExitKit, installHeadExitKit } = require('../lib/exit-kit');
const { flushPublishedHead } = require('../lib/producer-head');

const router = Router({ mergeParams: true });

async function flushLastProducerBlock(ch) {
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
  return { blockReceipt, destinationHeadReceipt, liveReceipt, destinationLiveReceipt };
}

// POST /api/v1/channel/:ch/inter-channel/send (A16/W4)
// body: { debitPayload, transferDescriptor, tokenIndex? } — the moved BASE token rides INSIDE
// the signed descriptor (interChannelTx.tokenIndex, multi-token §N-4); the optional top-level
// tokenIndex is a client-intent cross-check only: when present it must match the descriptor
// (fail-closed 400 on mismatch — catches a client wiring bug before any proving/cosigning).
router.post('/send', (req, res) => {
  const ch = Number(req.params.ch);
  const requestedDescriptor = req.body && req.body.transferDescriptor;
  const destination = requestedDescriptor && Number(requestedDescriptor.destinationChannelId);
  const lockSet = Number.isSafeInteger(destination) ? [ch, destination] : [ch];
  withLocks(lockSet, async () => {
    const { debitPayload, transferDescriptor, tokenIndex } = req.body || {};
    if (!debitPayload || !transferDescriptor) {
      res.status(400).json({ error: 'needs { debitPayload, transferDescriptor, tokenIndex? }' });
      return;
    }
    const descTok = transferDescriptor.interChannelTx && transferDescriptor.interChannelTx.tokenIndex;
    if (tokenIndex !== undefined && tokenIndex !== null && String(tokenIndex) !== String(descTok)) {
      res.status(400).json({ error: `tokenIndex mismatch: body says ${tokenIndex}, signed descriptor says ${descTok}` });
      return;
    }
    const producerRequestId = producer.stableRequestId('inter', {
      ch, debitPayload, transferDescriptor,
    });
    let operation = null;
    try { operation = readJson(wc(ch, 'inter_operation.json')); } catch (e) { /* first request */ }

    // Completed HTTP retries are content-addressed and return the already-settled response. An
    // in-flight operation may likewise be resumed only by the identical request; otherwise a
    // caller could overwrite the sole recovery inputs after the channel signature was committed.
    if (operation && operation.producerRequestId === producerRequestId && operation.status === 'completed') {
      res.json(operation.response);
      return;
    }
    if (operation && operation.status === 'prepared' && operation.producerRequestId !== producerRequestId) {
      res.status(409).json({ error: 'a different inter-channel transition is signed or pending recovery' });
      return;
    }
    if (
      operation
      && operation.status === 'prepared'
      && operation.producerRequestId === producerRequestId
      && fs.existsSync(wc(ch, 'inter_transfer.json'))
    ) {
      const recovered = await flushLastProducerBlock(ch);
      const recoveredResult = readJson(wc(ch, 'inter_transfer.json'));
      const response = {
        sourceHead: recoveredResult.aHead || recoveredResult.sourceHead || recoveredResult,
        destSnapshot: recoveredResult.bSnapshot || recoveredResult.destSnapshot || null,
        ...recovered,
      };
      writeJson(wc(ch, 'inter_operation.json'), {
        ...operation, status: 'completed', completedAt: Date.now(), response,
      });
      res.json(response);
      return;
    }
    // Crash recovery: `cosign-inter-transfer` commits the N-of-N channel head before this route
    // can durably admit its producer block. The three artifacts are retained, so every later
    // mutation first idempotently flushes that exact signed head. A structurally rejected pending
    // block stops the channel here instead of letting its state outrun the base chain.
    if (!operation || operation.status !== 'prepared') {
      await flushLastProducerBlock(ch);
      await flushPublishedHead(ch);
      fs.rmSync(wc(ch, 'inter_transfer.json'), { force: true });
      writeJson(wc(ch, 'inter_debit_payload.json'), debitPayload);
      writeJson(wc(ch, 'inter_descriptor.json'), transferDescriptor);
      operation = {
        producerRequestId,
        status: 'prepared',
        createdAt: Date.now(),
      };
      writeJson(wc(ch, 'inter_operation.json'), operation);
    }
    // Read under the same per-channel lock that encloses signing + producer admission + live
    // settlement. A second API request cannot observe/reuse this cursor before the first advances.
    const liveNonceEnv = await producer.authoritativeBaseNonceEnv(ch);
    // Signer-independent exit: the source debit's exit kit is proved against the staged producer
    // block before any A-side signature; B signs its pure credit against its durable head receipt
    // and receives its own kit below.
    await cliWithPreparedExitKit(
      ch,
      ['cosign-inter-transfer', 'inter_debit_payload.json', 'inter_descriptor.json', 'inter_transfer.json'],
      liveNonceEnv,
      { requestId: producerRequestId },
    );
    const result = readJson(wc(ch, 'inter_transfer.json'));
    const sourceHead = result.aHead || result.sourceHead || result;
    if (!Number.isSafeInteger(destination) || !result.bFundImportState || !result.bSnapshot) {
      throw new Error('cosign-inter-transfer omitted destination binding/fund-import snapshot');
    }
    const blockReceipt = await producer.postInterChannel(
      sourceHead,
      debitPayload,
      transferDescriptor,
      producerRequestId,
    );
    const destinationHeadReceipt = result.bFundImportState && result.bBundleApplyState
      ? await producer.syncOffchainHeads([
        result.bFundImportState,
        result.bBundleApplyState,
      ])
      : null;
    // The authoritative nonce above can only come from the resident base-state service, so its
    // matching settle is mandatory. Silently skipping here would commit the channel debit while
    // leaving that authority at the old nonce, recreating the next-send strand this route is meant
    // to prevent.
    const liveReceipt = await producer.liveSettleInterChannel(
      ch,
      blockReceipt,
      sourceHead,
      debitPayload,
      transferDescriptor,
    );
    // Source settlement alone advances only the sender's private base state. The destination must
    // consume the source proof artifact and both N-of-N credit states before this operation is
    // marked complete; otherwise the credited snapshot cannot be spent or withdrawn from the
    // resident destination balance proof.
    const sourceArtifact = await producer.liveSendArtifact(ch, producerRequestId);
    const destinationLiveReceipt = await producer.liveReceiveInterChannel(destination, {
      producerReceipt: blockReceipt,
      debitPayload,
      descriptor: transferDescriptor,
      sourceArtifact,
      fundImportState: result.bFundImportState,
      destinationSnapshot: result.bSnapshot,
    });
    // The credited head was signed kit-pending; archive its exit kit into B's CLI state now so
    // B's next H2=0 signature has a receipt for its durable head.
    await installHeadExitKit(destination);
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
    res.json(response);
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/inter-channel/send-bulk (W5)
// NOT IMPLEMENTED: requires an E-2 circuit redesign, NOT a wallet_core wrapper.
// The ChannelUpdateAir STARK (src/regev/transfer_stark.rs) is hardcoded single-sender/
// single-recipient (4 ciphertexts, one conservation eq `before = after + sender_delta`), and
// InterChannelSendUpdateWitness::verify enforces receiver_deltas.len() == 1
// (src/circuits/channel/state_update_verifier.rs). Bulk needs the circuit to prove total
// solvency across M recipient deltas (sum(receiver_delta) == sender_delta) in one statement.
router.post('/send-bulk', (req, res) => {
  res.status(501).json({
    error: 'bulk inter-channel send not yet implemented',
    detail: 'Requires a multi-recipient E-2 STARK circuit change (ChannelUpdateAir), not just a wallet_core wrapper (A15). The current circuit and witness verifier are hardcoded to a single recipient.',
  });
});

// POST /api/v1/channel/:ch/inter-channel/receive (A17)
// Currently handled implicitly inside cosignInterTransfer. Future: separate endpoint for multi-co-signer.
router.post('/receive', (req, res) => {
  res.status(501).json({
    error: 'standalone inter-channel receive not yet implemented',
    detail: 'Currently handled implicitly inside cosign-inter-transfer. For multi-co-signer architecture.',
  });
});

module.exports = router;
