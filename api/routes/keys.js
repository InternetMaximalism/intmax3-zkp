const { Router } = require('express');
const { cli } = require('../lib/cli');

const router = Router();

// POST /api/v1/keys/generate (A1)
// Client-side helper: generate member keys. In production the private key MUST NOT leave the client.
// This endpoint is provided for server-side testing/tooling only.
router.post('/generate', (req, res) => {
  // `channel_member gen-contribution 0 <seed>` does NOT generate a fresh identity: `seed` is a u64
  // slot LABEL and the keys come from the operator's master key (`keys_for`), so this route used to
  // hand every caller the operator's own co-signer public keys. Identity generation is client-side
  // (WASM `wallet_keygen` / `wallet_keygen_seeded`); there is no server-side keygen to expose.
  void cli;
  res.status(501).json({ error: 'server-side keygen is not available: generate the member identity in the wallet (wallet_keygen / wallet_keygen_seeded); the CLI has no fresh-identity command' });
});

module.exports = router;
