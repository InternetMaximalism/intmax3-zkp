'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

function harness() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-inter-route-'));
  const handlers = new Map();
  const calls = { cli: 0, post: 0, settle: 0, sync: 0, artifact: 0, receive: 0 };
  const router = { post(route, handler) { handlers.set(route, handler); } };
  const wc = (_ch, name) => path.join(work, name);
  const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
  const writeJson = (file, value) => fs.writeFileSync(file, JSON.stringify(value));
  const stableRequestId = (_kind, body) => `inter:${JSON.stringify(body)}`;

  const originalLoad = Module._load;
  Module._load = function mockedLoad(request, parent, isMain) {
    if (request === 'express') return { Router: () => router };
    if (request === '../lib/lock') return { withLocks: (_channels, fn) => Promise.resolve().then(fn) };
    if (request === '../lib/producer-head') return { flushPublishedHead: async () => null };
    if (request === '../lib/cli') {
      return {
        wc,
        readJson,
        writeJson,
        cli() {
          calls.cli += 1;
          writeJson(wc(7, 'inter_transfer.json'), {
            aHead: { channelId: 7, digest: 'after' },
            bFundImportState: { channelId: 8, digest: 'dest-import' },
            bBundleApplyState: { channelId: 8, digest: 'dest-apply' },
            bSnapshot: { channelId: 8, digest: 'dest' },
          });
        },
      };
    }
    if (request === '../lib/block-producer') {
      return {
        stableRequestId,
        authoritativeBaseNonceEnv: async () => ({ INTMAX_LIVE_BASE_NONCE: '0' }),
        postInterChannel: async (_state, _debit, _descriptor, requestId) => {
          calls.post += 1;
          return { requestId, blockNumber: 1 };
        },
        syncOffchainHeads: async () => { calls.sync += 1; return { ok: true }; },
        liveSettleInterChannel: async () => { calls.settle += 1; return { baseNonce: 1 }; },
        liveSendArtifact: async () => { calls.artifact += 1; return { proof: 'source' }; },
        liveReceiveInterChannel: async (channelId, body) => {
          calls.receive += 1;
          assert.equal(channelId, 8);
          assert.equal(body.fundImportState.digest, 'dest-import');
          assert.equal(body.destinationSnapshot.digest, 'dest');
          return { baseNonce: 1, destination: true };
        },
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    const routePath = path.resolve(__dirname, '../../api/routes/inter-channel.js');
    delete require.cache[routePath];
    require(routePath);
  } finally {
    Module._load = originalLoad;
  }

  const body = {
    debitPayload: { proposedNextState: { digest: 'after' } },
    transferDescriptor: {
      destinationChannelId: 8,
      interChannelTx: { tokenIndex: 0, baseNonce: 0 },
    },
    tokenIndex: 0,
  };
  const requestId = stableRequestId('inter', {
    ch: 7, debitPayload: body.debitPayload, transferDescriptor: body.transferDescriptor,
  });

  async function invoke(requestBody = body) {
    const response = {
      statusCode: 200,
      body: null,
      status(code) { this.statusCode = code; return this; },
      json(value) { this.body = value; return this; },
    };
    handlers.get('/send')({ params: { ch: '7' }, body: requestBody }, response);
    await new Promise(resolve => setImmediate(resolve));
    return response;
  }

  return { work, calls, wc, writeJson, body, requestId, invoke };
}

test('completed inter-channel HTTP retries return the journaled response without re-signing', async t => {
  const h = harness();
  t.after(() => fs.rmSync(h.work, { recursive: true, force: true }));
  const first = await h.invoke();
  assert.equal(first.statusCode, 200);
  assert.deepEqual(h.calls, { cli: 1, post: 1, settle: 1, sync: 1, artifact: 1, receive: 1 });
  const second = await h.invoke();
  assert.equal(second.statusCode, 200);
  assert.deepEqual(second.body, first.body);
  assert.deepEqual(h.calls, { cli: 1, post: 1, settle: 1, sync: 1, artifact: 1, receive: 1 });
});

test('a signed prepared operation resumes producer admission and live settlement', async t => {
  const h = harness();
  t.after(() => fs.rmSync(h.work, { recursive: true, force: true }));
  h.writeJson(h.wc(7, 'inter_operation.json'), {
    producerRequestId: h.requestId, status: 'prepared', createdAt: 1,
  });
  h.writeJson(h.wc(7, 'inter_debit_payload.json'), h.body.debitPayload);
  h.writeJson(h.wc(7, 'inter_descriptor.json'), h.body.transferDescriptor);
  h.writeJson(h.wc(7, 'inter_transfer.json'), {
    aHead: { channelId: 7, digest: 'after' },
    bFundImportState: { channelId: 8, digest: 'dest-import' },
    bBundleApplyState: { channelId: 8, digest: 'dest-apply' },
    bSnapshot: { channelId: 8, digest: 'dest' },
  });
  const response = await h.invoke();
  assert.equal(response.statusCode, 200);
  assert.deepEqual(h.calls, { cli: 0, post: 1, settle: 1, sync: 1, artifact: 1, receive: 1 });
  assert.equal(JSON.parse(fs.readFileSync(h.wc(7, 'inter_operation.json'))).status, 'completed');
});

test('a different request cannot overwrite a prepared signed operation', async t => {
  const h = harness();
  t.after(() => fs.rmSync(h.work, { recursive: true, force: true }));
  h.writeJson(h.wc(7, 'inter_operation.json'), {
    producerRequestId: 'inter:different', status: 'prepared', createdAt: 1,
  });
  const response = await h.invoke();
  assert.equal(response.statusCode, 409);
  assert.deepEqual(h.calls, { cli: 0, post: 0, settle: 0, sync: 0, artifact: 0, receive: 0 });
});
