'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const modulePromise = import('../../hosting/wallet/signature-release-ledger.mjs');
const hash = n => `0x${n.repeat(32)}`;
const signerPkG = hash('11');
function state(signature = [1, 2, 3]) {
  return { channelId: 7, prevDigest: hash('aa'), digest: hash('bb'), memberSignatures: [
    { memberSlot: 0, pkG: signerPkG, signature },
    { memberSlot: 1, pkG: hash('22'), signature: [4, 5, 6] },
  ] };
}
async function memoryLedger() {
  const { signatureDecision } = await modulePromise;
  const records = new Map();
  let tail = Promise.resolve();
  let persistence = async () => {};
  return {
    records,
    setPersistence(fn) { persistence = fn; },
    remember(candidate) {
      const result = tail.catch(() => {}).then(async () => {
        const decision = signatureDecision(candidate, records.get(candidate.key));
        await persistence();
        records.set(candidate.key, structuredClone(decision));
        return structuredClone(decision);
      });
      tail = result;
      return result;
    },
  };
}

test('own co-signature is released only after persistence, with exact bytes reused after restart', async () => {
  const { createSignatureReleaseGate } = await modulePromise;
  const ledger = await memoryLedger();
  let commit;
  ledger.setPersistence(() => new Promise(resolve => { commit = resolve; }));
  const gate = createSignatureReleaseGate(ledger);
  let released = false;
  const pending = gate.release({ action: 'cosign', result: JSON.stringify(state()), signerPkG })
    .then(result => { released = true; return result; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(released, false);
  assert.equal(ledger.records.size, 0);
  commit();
  const first = JSON.parse(await pending);
  ledger.setPersistence(async () => {});
  const restarted = createSignatureReleaseGate(ledger);
  const retry = JSON.parse(await restarted.release({ action: 'cosign', result: JSON.stringify(state([9, 9, 9])), signerPkG }));
  assert.deepEqual(retry.memberSignatures[0], first.memberSignatures[0]);
  assert.deepEqual(retry.memberSignatures[1], state().memberSignatures[1]);
  assert.equal(ledger.records.size, 1);
});

test('concurrent release decisions serialize by identity/channel/predecessor', async () => {
  const { createSignatureReleaseGate } = await modulePromise;
  const ledger = await memoryLedger();
  const gates = [createSignatureReleaseGate(ledger), createSignatureReleaseGate(ledger)];
  const results = await Promise.all(gates.map((gate, index) => gate.release({ action: 'cosign',
    signerPkG, result: JSON.stringify(state([index + 1])) })));
  assert.deepEqual(JSON.parse(results[0]).memberSignatures[0], JSON.parse(results[1]).memberSignatures[0]);
  const different = { ...state(), digest: hash('cc') };
  await assert.rejects(gates[1].release({ action: 'cosign', signerPkG, result: JSON.stringify(different) }), /different successor/);
  assert.equal(ledger.records.size, 1);
});

test('signature replay preserves exact u64 state wire without a lossy whole-state JSON roundtrip', async () => {
  const { createSignatureReleaseGate } = await modulePromise;
  const ledger = await memoryLedger();
  const gate = createSignatureReleaseGate(ledger);
  const wire = JSON.stringify({ ...state(), epoch: 1, smallBlockNumber: 1 })
    .replace('"epoch":1', '"epoch":18446744073709551615')
    .replace('"smallBlockNumber":1', '"smallBlockNumber":9007199254740993');
  assert.equal(await gate.release({ action: 'cosign', signerPkG, result: wire }), wire);
  const retry = wire.replace('"signature":[1,2,3]', '"signature":[9,9,9]');
  assert.equal(await gate.release({ action: 'cosign', signerPkG, result: retry }), wire);
});

test('genesis uses the zero-predecessor decision and verifies the session signature identity', async () => {
  const { createSignatureReleaseGate } = await modulePromise;
  const ledger = await memoryLedger();
  const gate = createSignatureReleaseGate(ledger);
  const genesis = { ...state(), prevDigest: hash('00') };
  const result = await gate.release({ action: 'signState', signerPkG,
    input: { slot: 0, stateJson: JSON.stringify(genesis) }, result: JSON.stringify(genesis.memberSignatures[0]) });
  assert.deepEqual(JSON.parse(result), genesis.memberSignatures[0]);
  assert.equal([...ledger.records.values()][0].prevDigest, hash('00'));
  await assert.rejects(gate.release({ action: 'signState', signerPkG,
    input: { slot: 1, stateJson: JSON.stringify(genesis) }, result }), /slot differs/);
});

test('storage failures release no signature and unsigned delegate proposals do not need storage', async () => {
  const { createSignatureReleaseGate, createIndexedDbSignatureLedger } = await modulePromise;
  const unavailable = createSignatureReleaseGate(createIndexedDbSignatureLedger(null));
  await assert.rejects(unavailable.release({ action: 'cosign', signerPkG, result: JSON.stringify(state()) }), /requires IndexedDB/);
  const unsigned = JSON.stringify({ proposedNextState: { ...state(), memberSignatures: [] },
    channelTx: { senderSignature: [1, 2, 3] } });
  assert.equal(await unavailable.release({ action: 'send', result: unsigned }), unsigned);
  const slim = new Uint8Array([1, 2, 3]);
  assert.equal(await unavailable.release({ action: 'slimWire', result: slim }), slim);
  await assert.rejects(unavailable.release({ action: 'send', result: JSON.stringify({ proposedNextState: state() }) }), /unexpectedly contains/);
  const ledger = await memoryLedger();
  ledger.setPersistence(async () => { throw new Error('storage unavailable'); });
  const gate = createSignatureReleaseGate(ledger);
  await assert.rejects(gate.release({ action: 'cosign', signerPkG, result: JSON.stringify(state()) }), /storage unavailable/);
  assert.equal(ledger.records.size, 0);
  await assert.rejects(createSignatureReleaseGate({ async remember() {} }).release({
    action: 'cosign', signerPkG, result: JSON.stringify(state()),
  }), /did not acknowledge/);
});

test('all explicit WASM state-signing exports stay behind the worker release fence', () => {
  const rust = fs.readFileSync(path.join(__dirname, '../../src/wasm_wallet.rs'), 'utf8');
  const signingExports = [];
  for (const match of rust.matchAll(/pub fn (wallet_[a-z_]+)\(/g)) {
    const end = rust.indexOf('\n}\n', match.index);
    const body = rust.slice(match.index, end);
    if (/\bsign_state(?:_if_backed)?\s*\(/.test(body)) signingExports.push(match[1]);
  }
  assert.deepEqual(signingExports.sort(), ['wallet_cosign', 'wallet_sign_state']);
  const worker = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-worker.js'), 'utf8');
  assert.match(worker, /signState:.*wasm\.wallet_sign_state/);
  assert.match(worker, /cosign:.*wasm\.wallet_cosign/);
  assert.equal([...worker.matchAll(/post\('result'/g)].length, 1);
  assert.ok(worker.indexOf('await signatureRelease.release(') < worker.indexOf("post('result'"));
  assert.match(worker, /operationQueue = operationQueue\.then\(\(\) => dispatch\(e\)\)/);
});

test('storage-disabled origins do not prevent unsigned delegate operation', async () => {
  const { createSignatureReleaseGate } = await modulePromise;
  const old = Object.getOwnPropertyDescriptor(globalThis, 'indexedDB');
  Object.defineProperty(globalThis, 'indexedDB', { configurable: true, get() { throw new Error('storage is disabled'); } });
  try {
    const gate = createSignatureReleaseGate();
    const proposal = JSON.stringify({ proposedNextState: { memberSignatures: [] } });
    assert.equal(await gate.release({ action: 'send', result: proposal }), proposal);
    await assert.rejects(gate.release({ action: 'cosign', signerPkG, result: JSON.stringify(state()) }), /storage is disabled/);
  } finally {
    if (old) Object.defineProperty(globalThis, 'indexedDB', old);
    else delete globalThis.indexedDB;
  }
});

test('IndexedDB adapter requests strict atomic read/write and waits for transaction completion', async () => {
  const { createSignatureReleaseGate, createIndexedDbSignatureLedger } = await modulePromise;
  const records = new Map();
  const transactions = [];
  const db = { objectStoreNames: { contains: () => true }, close() {},
    transaction(store, mode, options) {
      assert.equal(store, 'decisions');
      assert.equal(mode, 'readwrite');
      assert.deepEqual(options, { durability: 'strict' });
      let staged;
      const tx = { durability: 'strict', abort() { queueMicrotask(() => tx.onabort && tx.onabort()); },
        objectStore() { return {
          get(key) {
            const request = {};
            queueMicrotask(() => { request.result = records.get(key); request.onsuccess(); });
            return request;
          },
          add(value) { staged = structuredClone(value); },
        }; },
        complete() { if (staged) records.set(staged.key, staged); tx.oncomplete(); },
      };
      transactions.push(tx);
      return tx;
    },
  };
  const indexedDB = { open() {
    const request = {};
    queueMicrotask(() => { request.result = db; request.onsuccess(); });
    return request;
  } };
  const gate = createSignatureReleaseGate(createIndexedDbSignatureLedger(indexedDB));
  let returned = false;
  const pending = gate.release({ action: 'cosign', signerPkG, result: JSON.stringify(state()) })
    .then(result => { returned = true; return result; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(returned, false, 'request success is not durable transaction completion');
  assert.equal(records.size, 0);
  transactions[0].complete();
  await pending;
  assert.equal(records.size, 1);
  assert.equal(returned, true);
});
