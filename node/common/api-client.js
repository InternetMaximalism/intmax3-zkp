'use strict';
// Typed client over the api/ REST surface (DESIGN.md §2.2). Used by the delegate to reach the
// co-signer, and by the co-signer's own self-checks. Adds retries with backoff and timeouts.
// Uses Node's built-in fetch (Node 18+); no extra dependency.

const MAX_BACKING_RESPONSE_BYTES = 64 * 1024 * 1024;

async function responseText(res, maximumBytes = null) {
  if (maximumBytes == null) return res.text();
  const declaredRaw = res.headers && typeof res.headers.get === 'function'
    ? res.headers.get('content-length') : null;
  if (declaredRaw != null && /^\d+$/.test(declaredRaw)
      && Number(declaredRaw) > maximumBytes) {
    const error = new Error(`HTTP response exceeds the ${maximumBytes}-byte safety limit`);
    error.code = 'RESPONSE_TOO_LARGE';
    throw error;
  }
  // Test doubles and older fetch shims may expose only text(). Production Node fetch exposes a
  // Web ReadableStream, which is consumed incrementally so a hostile coordinator cannot force an
  // unbounded allocation before BackingVault sees the envelope.
  if (!res.body || typeof res.body.getReader !== 'function') {
    const text = await res.text();
    if (Buffer.byteLength(text, 'utf8') > maximumBytes) {
      const error = new Error(`HTTP response exceeds the ${maximumBytes}-byte safety limit`);
      error.code = 'RESPONSE_TOO_LARGE';
      throw error;
    }
    return text;
  }
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      total += chunk.length;
      if (total > maximumBytes) {
        const error = new Error(`HTTP response exceeds the ${maximumBytes}-byte safety limit`);
        error.code = 'RESPONSE_TOO_LARGE';
        throw error;
      }
      chunks.push(chunk);
    }
  } catch (error) {
    try { await reader.cancel(error); } catch (_) { /* keep the bounded-read failure */ }
    throw error;
  }
  return Buffer.concat(chunks, total).toString('utf8');
}

class ApiClient {
  constructor({ baseUrl, timeoutMs = 600_000, maxRetries = 3, bearerToken = '' }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
    this.maxRetries = maxRetries;
    this.bearerToken = bearerToken;
  }

  async _req(method, pathname, body, { maxResponseBytes = null } = {}) {
    let lastErr;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
      try {
        const headers = body ? { 'content-type': 'application/json' } : {};
        if (this.bearerToken) headers.authorization = `Bearer ${this.bearerToken}`;
        const res = await fetch(this.baseUrl + pathname, {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
          signal: ctrl.signal,
        });
        const text = await responseText(res, maxResponseBytes);
        clearTimeout(t);
        let json;
        try { json = text ? JSON.parse(text) : {}; } catch (e) { json = { raw: text }; }
        if (!res.ok) {
          const err = new Error(json.error || `HTTP ${res.status}`);
          err.status = res.status;
          err.body = json;
          // 4xx are deterministic rejections — do not retry.
          if (res.status >= 400 && res.status < 500) throw err;
          lastErr = err;
        } else {
          return json;
        }
      } catch (e) {
        clearTimeout(t);
        if (e && e.code === 'RESPONSE_TOO_LARGE') throw e;
        if (e.status && e.status >= 400 && e.status < 500) throw e;
        lastErr = e;
      }
      // backoff before retry (skip after the last attempt)
      if (attempt < this.maxRetries) await new Promise((r) => setTimeout(r, 250 * 2 ** attempt));
    }
    throw lastErr || new Error('request failed');
  }

  ch(id, suffix) {
    return `/api/v1/channel/${id}${suffix}`;
  }

  // --- read ---
  getSnapshot(id) { return this._req('GET', this.ch(id, '/snapshot')); }
  getStatus(id) { return this._req('GET', this.ch(id, '/status')); }
  getBacking(id) {
    return this._req('GET', this.ch(id, '/backing'), undefined, {
      maxResponseBytes: MAX_BACKING_RESPONSE_BYTES,
    });
  }
  getBaseHead(id) { return this._req('GET', this.ch(id, '/base-head')); }
  getTickets(id) { return this._req('GET', this.ch(id, '/tickets')); }

  // --- co-sign (delegate → co-signer) ---
  cosign(id, payload) { return this._req('POST', this.ch(id, '/cosign'), payload); }
  cosignRefresh(id, payload) { return this._req('POST', this.ch(id, '/cosign-refresh'), payload); }
  interChannelSend(id, body) { return this._req('POST', this.ch(id, '/inter-channel/send'), body); }
  burnCosign(id, body) { return this._req('POST', this.ch(id, '/burn/cosign'), body); }

  // --- partial withdrawal ---
  pwBurn(id, body) { return this._req('POST', this.ch(id, '/partial-withdrawal/burn'), body); }
  pwSettle(id, body) { return this._req('POST', this.ch(id, '/partial-withdrawal/settle'), body); }

  // --- close lifecycle ---
  closeRequest(id, body) { return this._req('POST', this.ch(id, '/close/request'), body); }
  closeSubmitIntent(id, body) { return this._req('POST', this.ch(id, '/close/submit-intent'), body); }
  closeChallenge(id, body) { return this._req('POST', this.ch(id, '/close/challenge'), body); }
  closeCancel(id, body) { return this._req('POST', this.ch(id, '/close/cancel'), body); }
  closeFinalize(id, body) { return this._req('POST', this.ch(id, '/close/finalize'), body); }
  closeClaim(id, body) { return this._req('POST', this.ch(id, '/close/claim'), body); }
  closePullCredit(id, body) { return this._req('POST', this.ch(id, '/close/pull-credit'), body); }
  postCloseClaim(id, body) { return this._req('POST', this.ch(id, '/close/post-close-claim'), body); }
}

module.exports = { ApiClient, MAX_BACKING_RESPONSE_BYTES, responseText };
