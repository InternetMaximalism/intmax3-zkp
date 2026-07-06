// Security middleware for the channel API: CORS allowlist, bearer-token auth on
// state-mutating requests, and a simple in-memory per-IP rate limiter.
//
// One switch gates all local-dev relaxations: INTMAX_DEV=1. In DEV the auth token
// and CORS allowlist may be omitted (open, with a startup warning). In production
// (INTMAX_DEV unset) missing config FAILS CLOSED: writes are rejected until an API
// token is set, and cross-origin browser calls are blocked until origins are listed.
const crypto = require('crypto');

const DEV = process.env.INTMAX_DEV === '1';

function timingSafeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  // Length leak is acceptable; compare equal-length buffers in constant time.
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// ── CORS: echo the request Origin only when it is on the allowlist ──────────────
const ALLOWED_ORIGINS = (process.env.INTMAX_ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

function cors(req, res, next) {
  // WASM SharedArrayBuffer isolation headers (unchanged — required by the client).
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Vary', 'Origin');

  const origin = req.headers.origin;
  if (DEV && ALLOWED_ORIGINS.length === 0) {
    // Local-dev convenience ONLY: reflect whatever origin called (or allow no-origin tools).
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  } else if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  // else: no Access-Control-Allow-Origin → the browser blocks the cross-origin response.

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

// ── Auth: bearer token required for state-mutating requests ─────────────────────
const API_TOKEN = process.env.INTMAX_API_TOKEN || '';

function auth(req, res, next) {
  const isRead = req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS';
  // Read-only requests are open by default (they can still leak info — see #13/#16);
  // set INTMAX_AUTH_READS=1 to require the token on reads too.
  if (isRead && process.env.INTMAX_AUTH_READS !== '1') return next();

  if (!API_TOKEN) {
    if (DEV) return next(); // dev convenience; warned at startup
    return res
      .status(503)
      .json({ error: 'API auth not configured (set INTMAX_API_TOKEN)' });
  }
  const m = /^Bearer\s+(.+)$/.exec(req.headers.authorization || '');
  if (!m || !timingSafeEqual(m[1], API_TOKEN)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// ── Rate limiting: in-memory fixed window per IP ────────────────────────────────
// NOTE: per-process only. Behind a load balancer / multiple instances this must be
// replaced with a shared store (Redis, etc.) — tracked as an operational item.
const RL_WINDOW_MS = parseInt(process.env.INTMAX_RL_WINDOW_MS || '60000', 10);
const RL_MAX = parseInt(process.env.INTMAX_RL_MAX || '120', 10);
const buckets = new Map();

function rateLimit(req, res, next) {
  const now = Date.now();
  const ip = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
  let b = buckets.get(ip);
  if (!b || now >= b.reset) {
    b = { count: 0, reset: now + RL_WINDOW_MS };
    buckets.set(ip, b);
  }
  b.count++;
  if (b.count > RL_MAX) {
    const retry = Math.ceil((b.reset - now) / 1000);
    res.setHeader('Retry-After', String(retry));
    return res.status(429).json({ error: 'rate limit exceeded', retryAfterSeconds: retry });
  }
  next();
}

// Drop stale buckets periodically so the map does not grow unbounded.
setInterval(() => {
  const now = Date.now();
  for (const [ip, b] of buckets) if (now >= b.reset) buckets.delete(ip);
}, 5 * 60 * 1000).unref();

function startupWarnings() {
  if (DEV) {
    console.warn('[security] INTMAX_DEV=1 — relaxed auth/CORS/dev-key. NEVER use in production.');
  } else {
    if (!API_TOKEN) {
      console.warn('[security] INTMAX_API_TOKEN unset — state-mutating endpoints will return 503.');
    }
    if (ALLOWED_ORIGINS.length === 0) {
      console.warn('[security] INTMAX_ALLOWED_ORIGINS unset — browser cross-origin calls are blocked.');
    }
  }
}

module.exports = { cors, auth, rateLimit, startupWarnings, DEV };
