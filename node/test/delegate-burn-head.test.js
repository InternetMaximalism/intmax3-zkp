'use strict';
// Signer-independent exit, Round 2 §2: a partial-withdrawal burn is authorized on-chain at the
// post-burn head. The delegate must adopt exactly that head (and archive its backing) before it
// can ever request a close, otherwise the Manager refuses the close forever with
// `CloseOlderThanAuthorizedBurn`. These tests pin the burn branch's fail-closed handling.
const test = require('node:test');
const assert = require('node:assert/strict');

const H1 = { digest: `0x${'a1'.repeat(32)}`, epoch: 4, stateVersion: 9 };
const H2 = { digest: `0x${'a2'.repeat(32)}`, epoch: 4, stateVersion: 10 };

function cosignedState(prev, next) {
  return {
    digest: next.digest,
    prevDigest: prev.digest,
    epoch: next.epoch,
    memberSignatures: [{ memberSlot: 0, signature: '0x01' }, { memberSlot: 1, signature: '0x02' }],
    balanceState: { stateVersion: next.stateVersion },
  };
}

function load(importBehaviour) {
  const imports = [];
  const syncPath = require.resolve('../delegate/branches/sync');
  const owntxPath = require.resolve('../delegate/branches/owntx');
  const saved = require.cache[syncPath];
  delete require.cache[owntxPath];
  require.cache[syncPath] = {
    id: syncPath,
    filename: syncPath,
    loaded: true,
    exports: {
      async importPublishedState(state, ctx) {
        imports.push(state);
        return importBehaviour(state, ctx);
      },
    },
  };
  try {
    return { owntx: require(owntxPath), imports };
  } finally {
    if (saved) require.cache[syncPath] = saved; else delete require.cache[syncPath];
    delete require.cache[owntxPath];
  }
}

function harness(resp, importBehaviour) {
  const { owntx, imports } = load(importBehaviour);
  const state = { acceptedHead: H1, canSend: true, witnessTokenSlot: 0 };
  const tickets = [];
  const signals = [];
  const raised = [];
  const store = {
    get(key) { return state[key]; },
    set(key, value) { state[key] = value; return value; },
    upsertTicket(ticket) { tickets.push(ticket); },
  };
  const ctx = {
    api: {
      async getBaseHead() { return { nonce: 1 }; },
      async pwBurn() { return resp; },
    },
    wallet: {
      available() { return true; },
      burnSend() { return { debit_payload: { x: 1 }, transfer_descriptor: { y: 2 } }; },
    },
    ch: { id: 7 },
    store,
    log: { info() {}, warn() {}, error() {} },
    sm: { signal(name) { signals.push(name); } },
    raiseSignal(signal) { raised.push(signal); },
  };
  return { owntx, imports, state, tickets, signals, raised, ctx };
}

test('a burn response without a nested cosigned state is a cosign fault, never a silent burn', async () => {
  // The permissive top-level fallback used to pass structural verification while the import was
  // skipped, leaving acceptedHead behind the on-chain burn authorization.
  const h = harness(cosignedState(H1, H2), async () => { throw new Error('must not import'); });
  await h.owntx.doBurn({ amount: 5, l1Address: `0x${'11'.repeat(20)}` }, h.ctx);
  assert.equal(h.imports.length, 0);
  assert.equal(h.tickets.length, 0, 'no burn_done ticket without an adopted burn head');
  assert.match(h.state.cosignFault.reason, /nested cosigned state/);
  assert.deepEqual(h.raised.map((s) => s.kind), ['cosign_invalid']);
  assert.deepEqual(h.state.acceptedHead, H1);
});

test('a nested cosigned burn state is imported unconditionally and the burn head is recorded', async () => {
  const h = harness({ state: cosignedState(H1, H2) }, async (_state, ctx) => {
    ctx.store.set('acceptedHead', H2);
  });
  await h.owntx.doBurn({ amount: 5, l1Address: `0x${'11'.repeat(20)}`, tokenIndex: undefined }, h.ctx);
  assert.equal(h.imports.length, 1);
  assert.equal(h.imports[0].digest, H2.digest);
  assert.equal(h.raised.length, 0);
  assert.equal(h.tickets.length, 1);
  assert.equal(h.tickets[0].status, 'burn_done');
  assert.deepEqual(h.tickets[0].params.burnHead, {
    digest: H2.digest,
    epoch: 4,
    stateVersion: 10,
  });
  assert.ok(h.signals.includes('cosign_ok') || h.signals.some((s) => /cosign/i.test(String(s))));
});

test('a burn whose head is not adopted after import is a cosign fault', async () => {
  const h = harness({ state: cosignedState(H1, H2) }, async () => { /* acceptedHead unchanged */ });
  await h.owntx.doBurn({ amount: 5, l1Address: `0x${'11'.repeat(20)}` }, h.ctx);
  assert.equal(h.imports.length, 1);
  assert.equal(h.tickets.length, 0);
  assert.match(h.state.cosignFault.reason, /not adopted/);
  assert.deepEqual(h.raised.map((s) => s.kind), ['cosign_invalid']);
});

test('a burn response that does not extend the accepted head is refused before import', async () => {
  const forked = cosignedState({ digest: `0x${'ff'.repeat(32)}` }, H2);
  const h = harness({ state: forked }, async () => { throw new Error('must not import'); });
  await h.owntx.doBurn({ amount: 5, l1Address: `0x${'11'.repeat(20)}` }, h.ctx);
  assert.equal(h.imports.length, 0);
  assert.equal(h.tickets.length, 0);
  assert.match(h.state.cosignFault.reason, /prevDigest mismatch/);
});

test('an import failure after the co-signer settled the burn propagates instead of logging burn_done', async () => {
  const h = harness({ state: cosignedState(H1, H2) }, async () => { throw new Error('backing withheld'); });
  await assert.rejects(
    h.owntx.doBurn({ amount: 5, l1Address: `0x${'11'.repeat(20)}` }, h.ctx),
    /backing withheld/,
  );
  assert.equal(h.tickets.length, 0);
});
