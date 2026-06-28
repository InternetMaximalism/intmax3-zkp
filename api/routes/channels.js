const { Router } = require('express');
const { CHANNELS } = require('../lib/cli');

const router = Router();

// GET /api/v1/channels — list available channels
router.get('/', (req, res) => {
  res.json({ channels: CHANNELS });
});

module.exports = router;
