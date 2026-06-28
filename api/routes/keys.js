const { Router } = require('express');
const { cli } = require('../lib/cli');

const router = Router();

// POST /api/v1/keys/generate (A1)
// Client-side helper: generate member keys. In production the private key MUST NOT leave the client.
// This endpoint is provided for server-side testing/tooling only.
router.post('/generate', (req, res) => {
  try {
    const seed = req.body && req.body.seed;
    const args = ['gen-contribution', '0'];
    if (seed) args.push(seed);
    args.push('keygen_out.json');
    // Use channel 7 as scratch — gen-contribution is stateless
    cli(7, args);
    const { readJson, wc } = require('../lib/cli');
    const out = readJson(wc(7, 'keygen_out.json'));
    res.json({
      regev_pk: out.regev_pk || out.regevPk,
      pk_g: out.pk_g || out.pkG,
      pk_b: out.pk_b || out.pkB,
    });
  } catch (e) {
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  }
});

module.exports = router;
