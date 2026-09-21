const { Router } = require('express');
const { withLocks } = require('../lib/lock');
const { interChannelSend } = require('../lib/inter-channel-send');

const router = Router({ mergeParams: true });

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
    // The full crash-recoverable debit+credit sequence lives in the shared module so the legacy
    // browser relay drives the identical flow.
    const { status, body } = await interChannelSend(ch, { debitPayload, transferDescriptor, tokenIndex });
    res.status(status).json(body);
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
