const { Router } = require('express');

const router = Router();

// POST /api/v1/blocks/post (A35)
// BP-facing endpoint. In current architecture the relay IS the BP.
// This is a stub for future BP service separation.
router.post('/post', (req, res) => {
  res.status(501).json({
    error: 'block posting not yet exposed as a standalone API',
    detail: 'Currently handled internally by the CLI withdraw and pw-submit commands (A35).',
  });
});

module.exports = router;
