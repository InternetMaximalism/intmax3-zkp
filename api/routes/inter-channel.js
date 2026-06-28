const { Router } = require('express');
const { cli, wc, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/inter-channel/send (A16/W4)
router.post('/send', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const { debitPayload, transferDescriptor } = req.body || {};
    if (!debitPayload || !transferDescriptor) {
      res.status(400).json({ error: 'needs { debitPayload, transferDescriptor }' });
      return;
    }
    writeJson(wc(ch, 'inter_debit_payload.json'), debitPayload);
    writeJson(wc(ch, 'inter_descriptor.json'), transferDescriptor);
    cli(ch, ['cosign-inter-transfer', 'inter_debit_payload.json', 'inter_descriptor.json', 'inter_transfer.json']);
    const result = readJson(wc(ch, 'inter_transfer.json'));
    res.json({
      sourceHead: result.aHead || result.sourceHead || result,
      destSnapshot: result.bSnapshot || result.destSnapshot || null,
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
