const express = require('express');
const https = require('https');
const fs = require('fs');
const app = express();

// Required headers for SharedArrayBuffer support
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');

  if (req.url.endsWith('.wasm')) {
    res.setHeader('Content-Type', 'application/wasm');
  }
  if (req.url.endsWith('.js')) {
    res.setHeader('Content-Type', 'application/javascript');
  }

  next();
});

// Serve static files
app.use(express.static('.', {
  setHeaders: (res, path) => {
    if (path.endsWith('.wasm')) {
      res.setHeader('Content-Type', 'application/wasm');
    }
    if (path.endsWith('.js')) {
      res.setHeader('Content-Type', 'application/javascript');
    }
  }
}));

// Handle 404s
app.use((req, res) => {
  console.log(`404 - File not found: ${req.url}`);
  res.status(404).send(`File not found: ${req.url}`);
});

// HTTPS server
const options = {
  key: fs.readFileSync('self_certs/key.pem'),
  cert: fs.readFileSync('self_certs/cert.pem')
};

const PORT = 8000;

https.createServer(options, app).listen(PORT, '0.0.0.0', () => {
  console.log(`HTTPS Server running on https://localhost:${PORT}`);
});
