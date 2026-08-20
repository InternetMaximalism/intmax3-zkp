'use strict';

// Route-level regression for the partial-withdrawal ticket exclusion policy.
//
// These tests load the real route modules with only their process/Express boundaries stubbed.
// Before the fix, both routes rejected `burn_done` but allowed `settle_pending` and
// `settle_blocked`, overwriting last_burn.json while the first withdrawal was still live.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const Module = require('module');

function loadBurnRoute(relativeRoute, endpoint) {
  const handlers = new Map();
  const router = {
    post(route, handler) { handlers.set(route, handler); },
  };
  let activeTicket = null;
  let cliCalls = 0;

  const originalLoad = Module._load;
  Module._load = function mockedLoad(request, parent, isMain) {
    if (request === 'express') {
      return { Router: () => router };
    }
    if (request === '../lib/lock') {
      return {
        withLock(_channel, fn) {
          try {
            return Promise.resolve(fn());
          } catch (error) {
            return Promise.reject(error);
          }
        },
      };
    }
    if (request === '../lib/tickets') {
      return {
        findActiveTicket(_channel, type) {
          assert.equal(type, 'partial_withdrawal');
          return activeTicket;
        },
        upsertTicket(_channel, ticket) { return ticket; },
      };
    }
    if (request === '../lib/cli') {
      return {
        RPC: 'http://127.0.0.1:8545',
        wc(_channel, filename) { return filename; },
        cli() { cliCalls += 1; },
        readJson() { return {}; },
        writeJson() {},
        ensureSettlement() {},
        failRoute(res, error) {
          return res.status(500).json({ error: String(error) });
        },
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };

  try {
    const absolute = path.resolve(__dirname, relativeRoute);
    delete require.cache[absolute];
    require(absolute);
  } finally {
    Module._load = originalLoad;
  }

  const handler = handlers.get(endpoint);
  assert.equal(typeof handler, 'function', `${relativeRoute} must register ${endpoint}`);

  return {
    setActive(ticket) { activeTicket = ticket; },
    cliCalls() { return cliCalls; },
    async invoke() {
      const response = {
        statusCode: 200,
        body: undefined,
        status(code) { this.statusCode = code; return this; },
        json(body) { this.body = body; return this; },
      };
      handler(
        {
          params: { ch: '7' },
          body: {
            debitPayload: { proposedNextState: {} },
            transferDescriptor: { interChannelTx: { tokenIndex: 0 } },
            amount: '5',
            recipient: '0x0000000000000000000000000000000000000001',
          },
        },
        response,
      );
      await new Promise(resolve => setImmediate(resolve));
      return response;
    },
  };
}

for (const route of [
  { file: '../../api/routes/partial-withdrawal.js', endpoint: '/burn' },
  { file: '../../api/routes/burn.js', endpoint: '/cosign' },
]) {
  test(`${route.file}: every non-terminal PW state rejects a second burn`, async () => {
    const harness = loadBurnRoute(route.file, route.endpoint);
    for (const status of [
      'burn_done',
      'settle_pending',
      'settle_blocked',
      'payout_pending',
      'future_nonterminal',
    ]) {
      const ticket = { id: `pw-${status}`, type: 'partial_withdrawal', status };
      harness.setActive(ticket);
      const response = await harness.invoke();
      assert.equal(response.statusCode, 409, status);
      assert.equal(response.body.ticket, ticket, status);
      assert.match(response.body.error, /active partial withdrawal/, status);
    }
    assert.equal(harness.cliCalls(), 0, 'a conflicting request must not reach the CLI');
  });

  test(`${route.file}: no active PW ticket allows a new burn`, async () => {
    const harness = loadBurnRoute(route.file, route.endpoint);
    harness.setActive(null);
    const response = await harness.invoke();
    assert.equal(response.statusCode, 200);
    assert.equal(harness.cliCalls(), 1);
  });
}

for (const relay of [
  '../../hosting/wallet/wallet-relay.js',
  '../../hosting/wallet/wallet-relay-ec2.js',
]) {
  test(`${relay}: hosting mirror rejects every active PW ticket before writing burn files`, () => {
    const source = fs.readFileSync(path.resolve(__dirname, relay), 'utf8');
    const routeStart = source.indexOf("app.post('/api/cosign-burn'");
    assert.notEqual(routeStart, -1, 'hosting relay must expose the burn alias');
    const nextRoute = source.indexOf('\napp.post(', routeStart + 1);
    const routeBlock = source.slice(routeStart, nextRoute === -1 ? source.length : nextRoute);

    assert.match(routeBlock, /const active = findActiveTicket\(ch, 'partial_withdrawal'\);/);
    assert.match(routeBlock, /if \(active\) \{/);
    assert.doesNotMatch(routeBlock, /active\.status/);
    assert.match(routeBlock, /res\.status\(409\)/);
    assert.ok(
      routeBlock.indexOf('if (active)') < routeBlock.indexOf('burn_payload.json'),
      'the exclusion guard must run before last_burn inputs can be overwritten',
    );
  });
}
