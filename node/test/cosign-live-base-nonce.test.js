'use strict';

// D4a: the cosigner must gate an outgoing send against the daemon's LIVE base nonce, not the frozen
// channel_backing.json. `liveBaseNonceEnv` fetches it from /base-head and turns it into the
// INTMAX_LIVE_BASE_NONCE the CLI co-sign guard reads. The safety-critical property is FAIL-CLOSED:
// if the live nonce cannot be obtained, co-signing must stop. The frozen backing witness is a
// setup-time snapshot and is not an authoritative fallback after any outgoing send.

const test = require('node:test');
const assert = require('node:assert');
const { liveBaseNonceEnv } = require('../cosigner/branches/cosign');

const ch = { id: 7 };
const log = { warn() {}, info() {}, debug() {} };

test('live nonce present → INTMAX_LIVE_BASE_NONCE is set to it', async () => {
  const api = { getBaseHead: async () => ({ schemaVersion: 1, nonce: 3, source: 'liveBaseHead' }) };
  const env = await liveBaseNonceEnv(api, ch, log);
  assert.deepEqual(env, { INTMAX_LIVE_BASE_NONCE: '3' });
});

test('nonce 0 is a valid live cursor, not falsy-dropped', async () => {
  const api = { getBaseHead: async () => ({ nonce: 0 }) };
  const env = await liveBaseNonceEnv(api, ch, log);
  assert.deepEqual(env, { INTMAX_LIVE_BASE_NONCE: '0' });
});

test('fetch throws → hard refusal (never fall back to the frozen witness)', async () => {
  const api = { getBaseHead: async () => { throw new Error('daemon unreachable'); } };
  await assert.rejects(() => liveBaseNonceEnv(api, ch, log), /refusing to co-sign/);
});

test('invalid / missing nonce → hard refusal (never pass a bogus override to the guard)', async () => {
  for (const bad of [{ nonce: '3' }, { nonce: null }, { nonce: -1 }, { nonce: 0x1_0000_0000 }, {}, null]) {
    const api = { getBaseHead: async () => bad };
    await assert.rejects(
      () => liveBaseNonceEnv(api, ch, log),
      /refusing to co-sign/,
      `bad head ${JSON.stringify(bad)} must stop co-signing`,
    );
  }
});
