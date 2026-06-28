const express = require('express');
const fs = require('fs');
const { CHANNELS, WORK, chDir, validChannel } = require('./lib/cli');

const app = express();
const PORT = parseInt(process.env.API_PORT || '8100', 10);

app.use(express.json({ limit: '64mb' }));

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'invalid JSON: ' + err.message });
  }
  next(err);
});

// CORS isolation headers (SharedArrayBuffer support for WASM clients)
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Channel ID validation middleware for /api/v1/channel/:ch/*
function validateChannel(req, res, next) {
  const ch = validChannel(req.params.ch);
  if (ch === null) {
    return res.status(404).json({
      error: `unknown channel ${req.params.ch}`,
      available: CHANNELS,
    });
  }
  req.params.ch = String(ch);
  fs.mkdirSync(chDir(ch), { recursive: true });
  next();
}

// --- Mount routes ---

// Top-level
app.use('/api/v1/channels', require('./routes/channels'));
app.use('/api/v1/keys', require('./routes/keys'));
app.use('/api/v1/blocks', require('./routes/blocks'));

// Per-channel routes (all require channel validation)
app.use('/api/v1/channel/:ch', validateChannel, require('./routes/channel-init'));
app.use('/api/v1/channel/:ch', validateChannel, require('./routes/channel-state'));
app.use('/api/v1/channel/:ch', validateChannel, require('./routes/channel-send'));
app.use('/api/v1/channel/:ch/inter-channel', validateChannel, require('./routes/inter-channel'));
app.use('/api/v1/channel/:ch/deposit', validateChannel, require('./routes/deposit'));
app.use('/api/v1/channel/:ch/burn', validateChannel, require('./routes/burn'));
app.use('/api/v1/channel/:ch/partial-withdrawal', validateChannel, require('./routes/partial-withdrawal'));
app.use('/api/v1/channel/:ch/settlement', validateChannel, require('./routes/settlement'));
app.use('/api/v1/channel/:ch/close', validateChannel, require('./routes/close'));
app.use('/api/v1/channel/:ch/full-withdrawal', validateChannel, require('./routes/full-withdrawal'));
app.use('/api/v1/channel/:ch/tickets', validateChannel, require('./routes/tickets'));

// Ensure work directories exist
for (const ch of CHANNELS) {
  fs.mkdirSync(chDir(ch), { recursive: true });
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`INTMAX3 Channel API on http://localhost:${PORT}  (channels: ${CHANNELS.join(', ')})`);
  console.log('Endpoints:');
  console.log('  GET  /api/v1/channels');
  console.log('  POST /api/v1/keys/generate');
  console.log('  POST /api/v1/channel/:ch/init');
  console.log('  POST /api/v1/channel/:ch/join');
  console.log('  POST /api/v1/channel/:ch/join-and-deposit');
  console.log('  GET  /api/v1/channel/:ch/snapshot');
  console.log('  GET  /api/v1/channel/:ch/status');
  console.log('  GET  /api/v1/channel/:ch/backing');
  console.log('  GET  /api/v1/channel/:ch/registration-record');
  console.log('  GET  /api/v1/channel/:ch/deposit/info');
  console.log('  POST /api/v1/channel/:ch/cosign');
  console.log('  POST /api/v1/channel/:ch/cosign-refresh');
  console.log('  POST /api/v1/channel/:ch/send');
  console.log('  POST /api/v1/channel/:ch/inter-channel/send');
  console.log('  POST /api/v1/channel/:ch/inter-channel/send-bulk');
  console.log('  POST /api/v1/channel/:ch/inter-channel/receive');
  console.log('  POST /api/v1/channel/:ch/deposit/l1-send');
  console.log('  POST /api/v1/channel/:ch/deposit/import');
  console.log('  POST /api/v1/channel/:ch/deposit');
  console.log('  POST /api/v1/channel/:ch/burn/cosign');
  console.log('  POST /api/v1/channel/:ch/partial-withdrawal/burn');
  console.log('  POST /api/v1/channel/:ch/partial-withdrawal/submit');
  console.log('  POST /api/v1/channel/:ch/partial-withdrawal/finalize');
  console.log('  POST /api/v1/channel/:ch/partial-withdrawal/settle');
  console.log('  POST /api/v1/channel/:ch/partial-withdrawal/cancel');
  console.log('  POST /api/v1/channel/:ch/settlement/deploy');
  console.log('  GET  /api/v1/channel/:ch/settlement');
  console.log('  POST /api/v1/channel/:ch/close/request');
  console.log('  POST /api/v1/channel/:ch/close/submit-intent');
  console.log('  POST /api/v1/channel/:ch/close/challenge');
  console.log('  POST /api/v1/channel/:ch/close/cancel');
  console.log('  POST /api/v1/channel/:ch/close/finalize');
  console.log('  POST /api/v1/channel/:ch/close/claim');
  console.log('  POST /api/v1/channel/:ch/close/pull-credit');
  console.log('  POST /api/v1/channel/:ch/close/post-close-claim');
  console.log('  POST /api/v1/channel/:ch/full-withdrawal/start');
  console.log('  GET  /api/v1/channel/:ch/full-withdrawal/status');
  console.log('  POST /api/v1/channel/:ch/full-withdrawal/deploy');
  console.log('  POST /api/v1/channel/:ch/full-withdrawal/request');
  console.log('  POST /api/v1/channel/:ch/full-withdrawal/submit');
  console.log('  POST /api/v1/channel/:ch/full-withdrawal/finalize');
  console.log('  POST /api/v1/channel/:ch/full-withdrawal/claim');
  console.log('  GET  /api/v1/channel/:ch/tickets');
  console.log('  POST /api/v1/channel/:ch/tickets');
  console.log('  POST /api/v1/blocks/post');
});
