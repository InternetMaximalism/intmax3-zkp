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
  const calls = { cli: 0, post: 0, settle: 0, sync: 0, artifact: 0, receive: 0, install: 0 };
  const flushed = [];
  const router = { post(route, handler) { handlers.set(route, handler); } };
  const wc = (ch, name) => path.join(work, `ch${ch}`, name);
  const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
  const writeJson = (file, value) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(value));
  };
  const stableRequestId = (_kind, body) => `inter:${JSON.stringify(body)}`;

  const cliMock = {
    wc,
    readJson,
    writeJson,
    refuseNext: null, // set to an Error to make the next signing command fail before it commits
    cli(ch, args) {
      if (args[0] === 'recover-inter-transfers') { calls.recover = (calls.recover || 0) + 1; return; }
      if (cliMock.refuseNext && args[0] === 'cosign-inter-transfer') { const e = cliMock.refuseNext; cliMock.refuseNext = null; calls.cli += 1; throw e; }
      assert.ok(flushed.includes(8), 'destination WAL/head recovery precedes cross-channel signing');
      assert.equal(ch, 7);
      assert.ok(args.some(a => a.startsWith('--producer-request-id=')),
        'the native destination sidecar retains the exact producer request identity');
      calls.cli += 1;
      const result = {
        aHead: { channelId: 7, digest: 'after' },
        bFundImportState: { channelId: 8, digest: 'dest-import' },
        bBundleApplyState: { channelId: 8, digest: 'dest-apply' },
        bSnapshot: { channelId: 8, digest: 'dest' },
      };
      writeJson(wc(7, 'inter_transfer.json'), result);
      writeJson(wc(8, 'incoming_inter_transfer.json'), result);
    },
  };

  const originalLoad = Module._load;
  Module._load = function mockedLoad(request, parent, isMain) {
    if (request === 'express') return { Router: () => router };
    if (request === '../lib/lock') return { withLocks: (_channels, fn) => Promise.resolve().then(fn) };
    if (request === '../lib/producer-head' || request === './producer-head') return { flushPublishedHead: async ch => { flushed.push(ch); return null; } };
    if (request === '../lib/exit-kit' || request === './exit-kit') {
      // The pre-sign exit-kit wrapper is one CLI signing round from the route's point of view;
      // the destination's kit install happens exactly once per completed transfer.
      return {
        cliWithPreparedExitKit: async (ch, args, env) => cliMock.cli(ch, args, env),
        acknowledgePreparedExitKit: () => {},
        debitRequestId: (id) => `${id}:exit-kit`,
        OPERATION_FILE: 'exit_kit_operation.json',
        installHeadExitKit: async (channelId) => {
          // Source (7) after its debit settles, destination (8) after its credit lands.
          assert.ok(channelId === 7 || channelId === 8, `unexpected kit install for channel ${channelId}`);
          calls.install += 1;
          if (channelId === 7) calls.installSource = (calls.installSource || 0) + 1;
        },
      };
    }
    if (request === '../lib/cli' || request === './cli') return cliMock;
    if (request === '../lib/block-producer' || request === './block-producer') {
      return {
        stableRequestId,
        authoritativeBaseNonceEnv: async () => ({ INTMAX_LIVE_BASE_NONCE: '0' }),
        postInterChannel: async (_state, _debit, _descriptor, requestId) => {
          calls.post += 1;
          return { requestId, blockNumber: 1 };
        },
        syncOffchainHeads: async () => { calls.sync += 1; return { ok: true }; },
        liveSettleInterChannel: async () => { calls.settle += 1; return { baseNonce: 1 }; },
        liveAbandonPreparedExitKit: async (_ch, requestId) => { calls.abandon = (calls.abandon || 0) + 1; calls.abandoned = requestId; },
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
  let lib = null;
  try {
    const routePath = path.resolve(__dirname, '../../api/routes/inter-channel.js');
    // The route now delegates to api/lib/inter-channel-send.js. Clear BOTH from the module cache so
    // re-requiring the route re-runs the shared module's requires under THIS harness's Module._load
    // mock — otherwise the cached shared module keeps the previous harness's mocked wc/producer and
    // reads a stale (empty) work dir.
    const sharedPath = path.resolve(__dirname, '../../api/lib/inter-channel-send.js');
    delete require.cache[sharedPath];
    delete require.cache[routePath];
    require(routePath);
    lib = require(sharedPath);
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

  return { work, calls, wc, writeJson, body, requestId, invoke, lib, cliMock };
}

test('completed inter-channel HTTP retries return the journaled response without re-signing', async t => {
  const h = harness();
  t.after(() => fs.rmSync(h.work, { recursive: true, force: true }));
  const first = await h.invoke();
  assert.equal(first.statusCode, 200);
  assert.deepEqual(h.calls, { cli: 1, post: 1, settle: 1, sync: 1, artifact: 1, receive: 1, install: 2, installSource: 1 });
  const second = await h.invoke();
  assert.equal(second.statusCode, 200);
  assert.deepEqual(second.body, first.body);
  assert.deepEqual(h.calls, { cli: 1, post: 1, settle: 1, sync: 1, artifact: 1, receive: 1, install: 2, installSource: 1 });
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
  assert.deepEqual(h.calls, { cli: 0, post: 1, settle: 1, sync: 1, artifact: 1, receive: 1, install: 2, installSource: 1 });
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
  assert.deepEqual(h.calls, { cli: 0, post: 0, settle: 0, sync: 0, artifact: 0, receive: 0, install: 0 });
});

test('successful source recovery archives the exact missing legacy destination sidecar', async t => {
  const h = harness();
  t.after(() => fs.rmSync(h.work, { recursive: true, force: true }));
  const first = await h.invoke();
  assert.equal(first.statusCode, 200);
  const sidecarPath = h.wc(8, 'incoming_inter_transfer_recovery.json');
  assert.deepEqual(JSON.parse(fs.readFileSync(sidecarPath)), {
    sourceChannelId: 7, producerRequestId: h.requestId,
    debitPayload: h.body.debitPayload, descriptor: h.body.transferDescriptor,
  });
  // A completed pre-sidecar source operation must still finish this one-time migration on retry.
  fs.rmSync(sidecarPath);
  const recovered = await h.invoke();
  assert.equal(recovered.statusCode, 200);
  assert.deepEqual(recovered.body, first.body);
  assert.equal(h.calls.cli, 1, 'source retry does not request another channel signature');
  assert.equal(h.calls.receive, 2);
  assert.equal(h.calls.install, 4, 'source + destination kit per landed transfer');
  assert.equal(JSON.parse(fs.readFileSync(sidecarPath)).producerRequestId, h.requestId);
  await h.invoke();
  assert.equal(h.calls.receive, 2, 'subsequent HTTP retry uses the completed operation');
});

// ---- sender-independent completion (the sender walks away after the debit is signed) ----------

test('nothing pending: resume is a no-op that touches nothing', async t => {
  const h = harness();
  t.after(() => fs.rmSync(h.work, { recursive: true, force: true }));
  assert.equal(h.lib.pendingInterTransfer(7), null);
  assert.equal(await h.lib.resumePendingInterTransfer(7), null);
  assert.deepEqual([h.calls.cli, h.calls.post, h.calls.receive], [0, 0, 0]);
});

test('sender vanishes after the signed commit: the relay resumes from the retained request alone', async t => {
  const h = harness();
  t.after(() => fs.rmSync(h.work, { recursive: true, force: true }));
  // What a crash between `cosign-inter-transfer` and the daemon phases leaves behind — no client.
  h.writeJson(h.wc(7, 'inter_operation.json'), { producerRequestId: h.requestId, status: 'prepared', createdAt: 1 });
  h.writeJson(h.wc(7, 'inter_debit_payload.json'), h.body.debitPayload);
  h.writeJson(h.wc(7, 'inter_descriptor.json'), h.body.transferDescriptor);
  h.writeJson(h.wc(7, 'inter_transfer.json'), {
    aHead: { channelId: 7, digest: 'after' },
    bFundImportState: { channelId: 8, digest: 'dest-import' },
    bBundleApplyState: { channelId: 8, digest: 'dest-apply' },
    bSnapshot: { channelId: 8, digest: 'dest' },
  });
  const pending = h.lib.pendingInterTransfer(7);
  assert.equal(pending.destination, 8);
  assert.equal(pending.signed, true);
  const r = await h.lib.resumePendingInterTransfer(7);
  assert.equal(r.status, 200);
  assert.equal(r.body.sourceHead.digest, 'after');
  assert.deepEqual([h.calls.cli, h.calls.post, h.calls.settle, h.calls.receive, h.calls.install], [0, 1, 1, 1, 2],
    'no re-signing; producer admission, live settle, destination receive run once; the SOURCE kit and the destination kit are each archived once');
  assert.equal(h.calls.installSource, 1, 'the source head gets its signed-head kit after the debit settles');
  assert.equal(JSON.parse(fs.readFileSync(h.wc(7, 'inter_operation.json'))).status, 'completed');
  assert.equal(h.lib.pendingInterTransfer(7), null);
  // A later resume is idempotent (journaled response, no daemon calls).
  assert.equal(await h.lib.resumePendingInterTransfer(7), null);
  assert.equal(h.calls.receive, 1);
});

test('signing command died with its PREPARED journal retained: resume rolls the CLI forward, then finishes', async t => {
  const h = harness();
  t.after(() => fs.rmSync(h.work, { recursive: true, force: true }));
  h.writeJson(h.wc(7, 'inter_operation.json'), { producerRequestId: h.requestId, status: 'prepared', createdAt: 1 });
  h.writeJson(h.wc(7, 'inter_debit_payload.json'), h.body.debitPayload);
  h.writeJson(h.wc(7, 'inter_descriptor.json'), h.body.transferDescriptor);
  // No inter_transfer.json: the CLI's own roll-forward must run (it recreates the result); here
  // nothing was journaled, so the module signs afresh exactly once.
  const r = await h.lib.resumePendingInterTransfer(7);
  assert.equal(r.status, 200);
  assert.equal(h.calls.recover, 1, 'recover-inter-transfers runs before re-signing');
  assert.deepEqual([h.calls.cli, h.calls.post, h.calls.receive, h.calls.install], [1, 1, 1, 2]);
  assert.equal(JSON.parse(fs.readFileSync(h.wc(7, 'inter_operation.json'))).status, 'completed');
});

test('a new sender after an abandoned transfer: resume first, then the new transfer proceeds (no 409)', async t => {
  const h = harness();
  t.after(() => fs.rmSync(h.work, { recursive: true, force: true }));
  h.writeJson(h.wc(7, 'inter_operation.json'), { producerRequestId: h.requestId, status: 'prepared', createdAt: 1 });
  h.writeJson(h.wc(7, 'inter_debit_payload.json'), h.body.debitPayload);
  h.writeJson(h.wc(7, 'inter_descriptor.json'), h.body.transferDescriptor);
  h.writeJson(h.wc(7, 'inter_transfer.json'), {
    aHead: { channelId: 7, digest: 'after' },
    bFundImportState: { channelId: 8, digest: 'dest-import' },
    bBundleApplyState: { channelId: 8, digest: 'dest-apply' },
    bSnapshot: { channelId: 8, digest: 'dest' },
  });
  const other = {
    ...h.body,
    debitPayload: { proposedNextState: { digest: 'after-2' } },
  };
  // Without the resume the different request is refused.
  const blocked = await h.invoke(other);
  assert.equal(blocked.statusCode, 409);
  // The relay's pre-send hook: land the abandoned one, then the new one goes through.
  assert.equal((await h.lib.resumePendingInterTransfer(7)).status, 200);
  const ok = await h.invoke(other);
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.body.sourceHead.digest, 'after');
  assert.equal(h.calls.cli, 1, 'only the new transfer is signed');
  // The landed transfer's daemon phases are replayed idempotently once more before the new one
  // (the pre-existing crash-window flush keyed by request id), then the new transfer lands.
  assert.equal(h.calls.receive, 3, 'the abandoned transfer landed, was re-flushed idempotently, and the new one landed');
});

test('a signing refusal before the source commits leaves nothing pending: staged kit abandoned, 409, the next transfer proceeds', async t => {
  const h = harness();
  t.after(() => fs.rmSync(h.work, { recursive: true, force: true }));
  h.writeJson(h.wc(7, 'exit_kit_operation.json'), { schemaVersion: 1, status: 'signing' });
  h.cliMock.refuseNext = Object.assign(new Error('Command failed\nerror: insufficient balance'), { stderr: 'error: insufficient balance', status: 1 });
  const refused = await h.invoke(h.body);
  assert.equal(refused.statusCode, 409);
  assert.equal(h.calls.abandon, 1, 'the staged exit-kit block is released');
  assert.equal(h.calls.abandoned, `${h.requestId}:exit-kit`);
  assert.equal(fs.existsSync(h.wc(7, 'inter_operation.json')), false, 'no prepared journal survives a refusal');
  assert.equal(fs.existsSync(h.wc(7, 'exit_kit_operation.json')), false, 'no pre-sign operation survives a refusal');
  assert.equal(h.lib.pendingInterTransfer(7), null);
  // A different transfer from the same channel is not blocked by the refused one.
  const ok = await h.invoke({ ...h.body, debitPayload: { proposedNextState: { digest: 'after-2' } } });
  assert.equal(ok.statusCode, 200);
});
