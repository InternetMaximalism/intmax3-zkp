'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { PassThrough } = require('stream');

const { ChainSafetyError } = require('../common/chain-watcher');
const ownTx = require('../delegate/branches/owntx');
const { makeRuntime } = require('../delegate/loop');
const {
  resolveHttpSecurity,
  bearerAuthorized,
  createChainReadiness,
  makeSingleFlight,
  startAfterInitialSync,
  isTransientChainSafetyError,
  createDelegateHttpHandler,
} = require('../delegate');

const quietLog = { debug() {}, info() {}, warn() {}, error() {} };

function fakeStore(initial = {}) {
  const state = { mode: 'normal', smNode: 'SYNCED', balance: {}, chainSafetyHalt: null, ...initial };
  return {
    get(key) { return state[key]; },
    setSmNode(value) { state.smNode = value; },
    state,
  };
}

function request(handler, { method, path, token, body, contentType = 'application/json' }) {
  const encoded = body === undefined
    ? null
    : (typeof body === 'string' ? Buffer.from(body) : Buffer.from(JSON.stringify(body)));
  const headers = {};
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  if (encoded) {
    headers['content-type'] = contentType;
    headers['content-length'] = encoded.length;
  }
  return new Promise((resolve) => {
    const req = new PassThrough();
    req.method = method;
    req.url = path;
    req.headers = headers;
    const response = {
      writableEnded: false,
      status: null,
      headers: {},
      writeHead(status, responseHeaders = {}) {
        this.status = status;
        this.headers = responseHeaders;
        return this;
      },
      end(payload = '') {
        if (this.writableEnded) return;
        this.writableEnded = true;
        const raw = String(payload || '');
        let parsed = null;
        try { parsed = raw ? JSON.parse(raw) : null; } catch (error) { parsed = raw; }
        resolve({ status: this.status, headers: this.headers, body: parsed });
      },
    };
    handler(req, response);
    req.end(encoded || undefined);
  });
}

test('delegate control interface defaults to loopback and requires a strong remote bearer', () => {
  assert.deepEqual(resolveHttpSecurity({}, {}), {
    host: '127.0.0.1',
    bearerToken: '',
    maxBodyBytes: 64 * 1024,
  });
  assert.throws(
    () => resolveHttpSecurity({ delegateHost: '0.0.0.0' }, {}),
    /INTMAX_DELEGATE_BEARER_TOKEN/,
  );
  assert.throws(
    () => resolveHttpSecurity({ delegateHost: '192.0.2.10' }, { INTMAX_DELEGATE_BEARER_TOKEN: 'short' }),
    />= 32 bytes/,
  );
  const token = 't'.repeat(32);
  assert.equal(
    resolveHttpSecurity({ delegateHost: '0.0.0.0' }, { INTMAX_DELEGATE_BEARER_TOKEN: token }).bearerToken,
    token,
  );
  assert.equal(bearerAuthorized(`Bearer ${token}`, token), true);
  assert.equal(bearerAuthorized(`Bearer ${'x'.repeat(32)}`, token), false);
  assert.equal(bearerAuthorized('Bearer short', token), false);
});

test('delegate HTTP authenticates, constrains methods and bodies, and pins routing fields', async () => {
  const token = 's'.repeat(32);
  const submitted = [];
  const store = fakeStore();
  const runtime = {
    async submit(event) {
      submitted.push(event);
      if (event.failTransient) {
        const error = new Error('RPC offline');
        error.code = 'CHAIN_TRANSIENT_UNAVAILABLE';
        throw error;
      }
    },
  };
  const handler = createDelegateHttpHandler({
    runtime,
    store,
    account: { id: 7 },
    httpSecurity: { host: '127.0.0.1', bearerToken: token, maxBodyBytes: 1024 },
    logger: quietLog,
  });
  assert.equal((await request(handler, {
      method: 'POST', path: '/intent/send', body: {},
    })).status, 401);
    assert.equal((await request(handler, {
      method: 'GET', path: '/intent/send', token,
    })).status, 405);
    assert.equal((await request(handler, {
      method: 'POST', path: '/intent/send', token, body: '{}', contentType: 'text/plain',
    })).status, 415);
    assert.equal((await request(handler, {
      method: 'POST', path: '/intent/send', token, body: '{broken',
    })).status, 400);
    assert.equal((await request(handler, {
      method: 'POST', path: '/intent/send', token, body: { padding: 'x'.repeat(1100) },
    })).status, 413);

    const accepted = await request(handler, {
      method: 'POST',
      path: '/intent/send?ignored=true',
      token,
      body: { source: 'chain', kind: 'CloseFinalized', amount: 9 },
    });
    assert.equal(accepted.status, 200);
    assert.equal(submitted.at(-1).source, 'api');
    assert.equal(submitted.at(-1).kind, 'send');
    assert.equal(submitted.at(-1).amount, 9);

    const balance = await request(handler, { method: 'GET', path: '/balance', token });
    assert.equal(balance.status, 200);
    assert.equal(submitted.at(-1).source, 'api');
    assert.equal(submitted.at(-1).kind, 'balance');

    const unavailable = await request(handler, {
      method: 'POST', path: '/intent/refresh', token, body: { failTransient: true },
    });
    assert.equal(unavailable.status, 503);
    assert.equal(unavailable.body.code, 'CHAIN_TRANSIENT_UNAVAILABLE');
});

test('each delegate submit promise waits for its own handler completion and failure', async () => {
  const original = ownTx.doSend;
  const gates = new Map();
  const started = [];
  ownTx.doSend = event => new Promise((resolve, reject) => {
    started.push(event.id);
    gates.set(event.id, { resolve, reject });
  });
  try {
    const readiness = createChainReadiness();
    const store = fakeStore();
    const runtime = makeRuntime(
      { id: 7, slot: 3 },
      {
        api: {}, wallet: {}, store, log: quietLog, alert: {}, policyCfg: {},
        isChainReady: () => readiness.isReady(),
      },
    );
    await assert.rejects(
      runtime.submit({ source: 'api', kind: 'send', id: 'gated' }),
      error => error.code === 'CHAIN_TRANSIENT_UNAVAILABLE',
    );
    assert.deepEqual(started, []);

    readiness.markReady();
    const first = runtime.submit({ source: 'api', kind: 'send', id: 'first' });
    const second = runtime.submit({ source: 'api', kind: 'send', id: 'second' });
    const secondObserved = second.then(
      () => ({ resolved: true }),
      error => ({ resolved: false, error }),
    );
    assert.notEqual(first, second);
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(started, ['first']);

    let firstSettled = false;
    first.finally(() => { firstSettled = true; });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(firstSettled, false);
    gates.get('first').resolve('first-ok');
    assert.equal(await first, 'first-ok');
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(started, ['first', 'second']);

    gates.get('second').reject(new Error('second failed'));
    const secondResult = await secondObserved;
    assert.equal(secondResult.resolved, false);
    assert.match(secondResult.error.message, /second failed/);
  } finally {
    ownTx.doSend = original;
  }
});

test('delegate polls are single-flight and startup never publishes HTTP before sync', async () => {
  let calls = 0;
  let release;
  const task = makeSingleFlight(() => {
    calls += 1;
    return new Promise(resolve => { release = resolve; });
  });
  const first = task();
  const second = task();
  assert.equal(first, second);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls, 1);
  release(true);
  assert.equal(await first, true);
  assert.equal(await second, true);

  const third = task();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls, 2);
  release(false);
  assert.equal(await third, false);

  let starts = 0;
  let syncs = 0;
  await assert.rejects(
    startAfterInitialSync(async () => false, async () => { syncs += 1; }, () => { starts += 1; }),
    error => error.code === 'CHAIN_STARTUP_UNAVAILABLE',
  );
  assert.equal(syncs, 0);
  assert.equal(starts, 0);

  const readiness = createChainReadiness();
  readiness.markReady();
  await assert.rejects(
    startAfterInitialSync(
      async () => true,
      async () => { syncs += 1; throw new Error('snapshot rejected'); },
      () => { starts += 1; },
      readiness,
    ),
    error => error.code === 'INITIAL_SYNC_FAILED',
  );
  assert.equal(readiness.isReady(), false);
  assert.equal(starts, 0);

  await startAfterInitialSync(async () => true, async () => { syncs += 1; }, () => { starts += 1; });
  assert.equal(starts, 1);
});

test('only RPC availability errors are transient; contradictions remain sticky candidates', () => {
  for (const code of [
    'RPC_NETWORK_UNAVAILABLE',
    'CANONICAL_BLOCK_UNAVAILABLE',
    'FINALIZED_HEAD_UNAVAILABLE',
    'DURABLE_HEAD_BEHIND_CURSOR',
  ]) {
    assert.equal(isTransientChainSafetyError(new ChainSafetyError(code, 'temporary')), true);
  }
  for (const code of [
    'CHAIN_ID_MISMATCH',
    'FINALIZED_HEAD_INVALID',
    'FINALIZED_CHECKPOINT_MISMATCH',
    'LOG_BLOCK_HASH_MISMATCH',
    'LEGACY_CURSOR_UNAUTHENTICATED',
  ]) {
    assert.equal(isTransientChainSafetyError(new ChainSafetyError(code, 'contradiction')), false);
  }
});
