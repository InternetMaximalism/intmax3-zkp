const { Router } = require('express');
const producer = require('../lib/block-producer');

const router = Router();

function fail(res, error) {
  console.error(error && error.stack ? error.stack : error);
  const status = error && error.code === 'conflict' ? 409 : 500;
  res.status(status).json({
    error: error && error.message ? error.message : String(error),
    code: error && error.code ? error.code : 'block_producer_error',
  });
}

function internalMutationOnly(res) {
  return res.status(410).json({
    error: 'raw block-producer mutation endpoints are not part of the production API',
    code: 'verified_pipeline_required',
    detail:
      'Use the per-channel deposit/inter-channel routes. They derive deposits from an L1 receipt ' +
      'and retain the exact N-of-N transition artifacts for crash recovery.',
  });
}

// Read-only health/head endpoint. `holdsLocalSigningKeys` must always be false; the Rust service
// refuses startup/replay otherwise.
router.get('/status', async (_req, res) => {
  try {
    res.json(await producer.status());
  } catch (error) {
    fail(res, error);
  }
});

// Register a wallet-verified public channel snapshot. No member secret is accepted by the schema.
router.post('/register', async (req, res) => {
  return internalMutationOnly(res);
});

// Admit one L1 receipt-reconciled deposit and seal a deposit-only block. `depositIndex` and
// `expectedDepositHashChain` are checked against the producer's monotone head in Rust.
router.post('/deposit', async (req, res) => {
  return internalMutationOnly(res);
});

// Persist a contiguous N-of-N authorized sequence that has H2=0 and therefore creates no base
// block. This keeps the producer's replay fence aligned across intra-channel/import transitions.
router.post('/sync', async (req, res) => {
  return internalMutationOnly(res);
});

// POST /api/v1/blocks/post (A35). The old arbitrary `SubBlock[]` stub is deliberately not
// resurrected: production admits only a canonical E-2 debit descriptor and the exact N-of-N
// co-signed state it extends. The durable Rust journal performs native verification before commit.
router.post('/post', async (req, res) => {
  return internalMutationOnly(res);
});

module.exports = router;
