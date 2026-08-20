const { Router } = require('express');
const { cli, wc, readJson, writeJson } = require('../lib/cli');
const { withLocks } = require('../lib/lock');
const producer = require('../lib/block-producer');
const { flushPublishedHead } = require('../lib/producer-head');

const router = Router({ mergeParams: true });

async function flushLastProducerBlock(ch) {
  const debitPath = wc(ch, 'inter_debit_payload.json');
  const descriptorPath = wc(ch, 'inter_descriptor.json');
  const resultPath = wc(ch, 'inter_transfer.json');
  const fs = require('fs');
  if (!(fs.existsSync(debitPath) && fs.existsSync(descriptorPath) && fs.existsSync(resultPath))) {
    return null;
  }
  const debitPayload = readJson(debitPath);
  const descriptor = readJson(descriptorPath);
  const result = readJson(resultPath);
  const signedState = result.aHead || result.sourceHead || result;
  const blockReceipt = await producer.postInterChannel(signedState, debitPayload, descriptor);
  let destinationHeadReceipt = null;
  if (result.bFundImportState && result.bBundleApplyState) {
    destinationHeadReceipt = await producer.syncOffchainHeads([
      result.bFundImportState,
      result.bBundleApplyState,
    ]);
  }
  return { blockReceipt, destinationHeadReceipt };
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
    // Crash recovery: `cosign-inter-transfer` commits the N-of-N channel head before this route
    // can durably admit its producer block. The three artifacts are retained, so every later
    // mutation first idempotently flushes that exact signed head. A structurally rejected pending
    // block stops the channel here instead of letting its state outrun the base chain.
    await flushLastProducerBlock(ch);
    await flushPublishedHead(ch);
    writeJson(wc(ch, 'inter_debit_payload.json'), debitPayload);
    writeJson(wc(ch, 'inter_descriptor.json'), transferDescriptor);
    cli(ch, ['cosign-inter-transfer', 'inter_debit_payload.json', 'inter_descriptor.json', 'inter_transfer.json']);
    const result = readJson(wc(ch, 'inter_transfer.json'));
    const sourceHead = result.aHead || result.sourceHead || result;
    const blockReceipt = await producer.postInterChannel(
      sourceHead,
      debitPayload,
      transferDescriptor,
    );
    const destinationHeadReceipt = result.bFundImportState && result.bBundleApplyState
      ? await producer.syncOffchainHeads([
        result.bFundImportState,
        result.bBundleApplyState,
      ])
      : null;
    res.json({
      sourceHead,
      destSnapshot: result.bSnapshot || result.destSnapshot || null,
      blockReceipt,
      destinationHeadReceipt,
    });
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
