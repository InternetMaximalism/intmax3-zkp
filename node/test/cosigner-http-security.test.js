'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  isLoopbackHost,
  resolveHttpSecurity,
  bearerAuthorized,
  DEFAULT_COSIGNER_BODY_LIMIT,
} = require('../cosigner');
const { actionIdFrom, actionFile } = require('../cosigner/branches/cosign');
const { ApiClient } = require('../common/api-client');

test('co-signer HTTP defaults to loopback with a bounded body', () => {
  const resolved = resolveHttpSecurity({}, {});
  assert.equal(resolved.host, '127.0.0.1');
  assert.equal(resolved.bearerToken, '');
  assert.equal(resolved.maxBodyBytes, DEFAULT_COSIGNER_BODY_LIMIT);
  assert.equal(isLoopbackHost('::1'), true);
  assert.equal(isLoopbackHost('[::1]'), true);
  assert.equal(isLoopbackHost('0.0.0.0'), false);
});

test('a remotely bound signing oracle refuses to start without a strong bearer token', () => {
  assert.throws(
    () => resolveHttpSecurity({ cosignerHost: '0.0.0.0' }, {}),
    /requires INTMAX_COSIGNER_BEARER_TOKEN/,
  );
  assert.throws(
    () => resolveHttpSecurity({ cosignerHost: '10.0.0.8' }, { INTMAX_COSIGNER_BEARER_TOKEN: 'short' }),
    /requires INTMAX_COSIGNER_BEARER_TOKEN/,
  );
  const token = 't'.repeat(32);
  assert.equal(
    resolveHttpSecurity(
      { cosignerHost: '10.0.0.8', cosignerMaxBodyBytes: 4096 },
      { INTMAX_COSIGNER_BEARER_TOKEN: token },
    ).bearerToken,
    token,
  );
});

test('bearer comparison is exact and action artifacts are request-scoped', () => {
  const token = 's'.repeat(32);
  assert.equal(bearerAuthorized(`Bearer ${token}`, token), true);
  assert.equal(bearerAuthorized(`Bearer ${token}x`, token), false);
  assert.equal(bearerAuthorized('', token), false);

  const a = actionIdFrom('inter', `0x${'11'.repeat(32)}`);
  const b = actionIdFrom('inter', `0x${'22'.repeat(32)}`);
  const aFile = actionFile(a, 'inter-descriptor');
  const bFile = actionFile(b, 'inter-descriptor');
  assert.notEqual(aFile, bFile);
  assert.match(aFile, /^inter-descriptor-[0-9a-f]{32}\.json$/);
  assert.throws(() => actionFile(a, '../escape'), /invalid action-scoped artifact/);
});

test('ApiClient sends the configured co-signer bearer without putting it in the URL/body', async () => {
  const oldFetch = global.fetch;
  let observed;
  global.fetch = async (url, options) => {
    observed = { url, options };
    return { ok: true, status: 200, text: async () => '{}' };
  };
  try {
    const client = new ApiClient({
      baseUrl: 'http://127.0.0.1:8200',
      bearerToken: 'z'.repeat(32),
      maxRetries: 0,
    });
    await client.cosign(7, { value: 1 });
    assert.equal(observed.options.headers.authorization, `Bearer ${'z'.repeat(32)}`);
    assert.equal(observed.url.includes('zzzz'), false);
    assert.deepEqual(JSON.parse(observed.options.body), { value: 1 });
  } finally {
    global.fetch = oldFetch;
  }
});

