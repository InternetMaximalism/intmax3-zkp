const { Router } = require('express');
const { cli, wc, readJson, writeJson } = require('../lib/cli');
const { withLock } = require('../lib/lock');

const router = Router({ mergeParams: true });

// POST /api/v1/channel/:ch/cosign (A8)
router.post('/cosign', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    writeJson(wc(ch, 'payload.json'), req.body);
    cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
    res.json(readJson(wc(ch, 'cosigned.json')));
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/cosign-refresh (A11)
router.post('/cosign-refresh', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    writeJson(wc(ch, 'refresh_payload.json'), req.body);
    cli(ch, ['cosign-refresh', 'refresh_payload.json', 'refresh_cosigned.json']);
    res.json(readJson(wc(ch, 'refresh_cosigned.json')));
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

// POST /api/v1/channel/:ch/send (W3)
// Orchestrated intra-channel send: client sends the pre-built payload, server cosigns.
router.post('/send', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, () => {
    const payload = req.body.payload || req.body;
    writeJson(wc(ch, 'payload.json'), payload);
    cli(ch, ['cosign', 'payload.json', 'cosigned.json']);
    const snapshot = readJson(wc(ch, 'cosigned.json'));
    res.json({ snapshot });
  }).catch(e => {
    console.error(e.stderr ? String(e.stderr) : (e.message || e));
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  });
});

module.exports = router;
