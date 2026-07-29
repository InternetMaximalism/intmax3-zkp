'use strict';
// Delegate sendability: the `canSend` flag and its per-token witness binding (§N, TM-13).
//
// Regression context: `sync.js` used to derive the flag from `bal.pending_adds`, a field the WASM
// `BalanceReport` has never had, so it evaluated to `!(undefined > 0)` === true unconditionally.
// The mandatory pre-send refresh (`ensureSendable`) therefore never ran and a stale witness
// surfaced as a hard WASM error instead of an automatic refresh.

const test = require('node:test');
const assert = require('node:assert');

const { recordBalance } = require('../delegate/branches/sync');
const { ensureSendable, witnessBacks, localSlotForTokenIndex } = require('../delegate/branches/owntx');

function fakeStore(init = {}) {
  const m = new Map(Object.entries(init));
  return { get: (k) => m.get(k), set: (k, v) => m.set(k, v) };
}

// A ctx just rich enough to drive doRefresh's success path (verifyCosignedStructural skips its
// optional checks when there is no prior head and the payload carries no channel_tx).
function fakeCtx({ store, available = true, refreshOk = true } = {}) {
  const calls = { refresh: [] };
  const ctx = {
    slot: 3,
    ch: { id: 7 },
    store,
    policy: {},
    log: { info() {}, warn() {}, error() {} },
    sm: { signal() {} },
    raiseSignal: () => { calls.raised = true; },
    wallet: {
      available: () => available,
      refresh: (slot, tokenSlot) => { calls.refresh.push({ slot, tokenSlot }); return { kind: 'refresh-payload' }; },
      cosignVerify() {},
      finalize() {},
    },
    api: {
      cosignRefresh: async () => {
        if (!refreshOk) throw new Error('withheld');
        return { state: { member_signatures: ['s0'], digest: '0xnew', balance_state: { state_version: 1 } } };
      },
    },
  };
  return { ctx, calls };
}

const report = (canSend, witnessTokenSlot, balances) => ({
  slot: 3,
  balance: '100',
  canSend,
  stateVersion: 5,
  balances: balances || [{ tokenSlot: 0, tokenIndex: 0, balance: '100' }],
  witnessTokenSlot,
});

// ---- recordBalance: the flag comes from the report's OWN canSend ----

test('recordBalance: canSend follows the report (true) and records the witness position', () => {
  const store = fakeStore();
  recordBalance(store, report(true, 1));
  assert.equal(store.get('canSend'), true);
  assert.equal(store.get('witnessTokenSlot'), 1);
});

test('recordBalance: REGRESSION — canSend:false must not be stored as sendable', () => {
  const store = fakeStore();
  const bal = report(false, null);
  // The old expression read a field BalanceReport never had, so it was always true.
  assert.equal(bal.pending_adds, undefined);
  assert.equal(!(bal && bal.pending_adds > 0), true, 'the old derivation was unconditionally true');
  recordBalance(store, bal);
  assert.equal(store.get('canSend'), false);
  assert.equal(store.get('witnessTokenSlot'), null);
});

test('recordBalance: a missing/absent report is not sendable', () => {
  const store = fakeStore();
  recordBalance(store, null);
  assert.equal(store.get('canSend'), false);
  assert.equal(store.get('witnessTokenSlot'), null);
});

// ---- witnessBacks: sendability is per (member, token) ----

test('witnessBacks: only when canSend AND the witness backs the requested position', () => {
  assert.equal(witnessBacks(fakeStore({ canSend: true, witnessTokenSlot: 0 }), 0), true);
  assert.equal(witnessBacks(fakeStore({ canSend: true, witnessTokenSlot: 0 }), undefined), true, 'undefined ⇒ genesis');
  assert.equal(witnessBacks(fakeStore({ canSend: true, witnessTokenSlot: 1 }), 1), true);
  // A genesis witness must NOT authorize sending another token.
  assert.equal(witnessBacks(fakeStore({ canSend: true, witnessTokenSlot: 0 }), 1), false);
  assert.equal(witnessBacks(fakeStore({ canSend: true, witnessTokenSlot: 1 }), 0), false);
  assert.equal(witnessBacks(fakeStore({ canSend: false, witnessTokenSlot: 0 }), 0), false);
  // Missing / legacy store state fails closed.
  assert.equal(witnessBacks(fakeStore({ canSend: true }), 0), false);
  assert.equal(witnessBacks(fakeStore({ canSend: true, witnessTokenSlot: null }), 0), false);
  assert.equal(witnessBacks(fakeStore({}), 0), false);
});

// ---- localSlotForTokenIndex: BASE index -> LOCAL position ----

test('localSlotForTokenIndex: resolves via the report registry, unknown falls back to genesis', () => {
  const store = fakeStore({
    balance: report(true, 0, [
      { tokenSlot: 0, tokenIndex: 0, balance: '1' },
      { tokenSlot: 1, tokenIndex: 55, balance: '2' },
    ]),
  });
  assert.equal(localSlotForTokenIndex(store, 55), 1);
  assert.equal(localSlotForTokenIndex(store, 0), 0);
  assert.equal(localSlotForTokenIndex(store, undefined), 0);
  assert.equal(localSlotForTokenIndex(store, 999), 0, 'unregistered ⇒ genesis; the WASM fails closed');
  assert.equal(localSlotForTokenIndex(fakeStore({}), 55), 0, 'no report ⇒ genesis');
});

// ---- ensureSendable ----

test('ensureSendable: a backing witness sends without a refresh round-trip', async () => {
  const store = fakeStore({ canSend: true, witnessTokenSlot: 0 });
  const { ctx, calls } = fakeCtx({ store });
  assert.equal(await ensureSendable(ctx, 0), true);
  assert.equal(calls.refresh.length, 0, 'no refresh should be needed');
});

test('ensureSendable: canSend:false triggers a refresh and then permits the send', async () => {
  const store = fakeStore({ canSend: false, witnessTokenSlot: null });
  const { ctx, calls } = fakeCtx({ store });
  assert.equal(await ensureSendable(ctx, undefined), true);
  assert.equal(calls.refresh.length, 1);
  assert.equal(calls.refresh[0].tokenSlot, undefined, 'genesis refresh');
  assert.equal(store.get('witnessTokenSlot'), 0, 'refresh records the position it backs');
});

test('ensureSendable: a genesis witness does not satisfy a token-1 send — refresh targets token 1', async () => {
  const store = fakeStore({ canSend: true, witnessTokenSlot: 0 });
  const { ctx, calls } = fakeCtx({ store });
  assert.equal(await ensureSendable(ctx, 1), true);
  assert.equal(calls.refresh.length, 1, 'the cross-token case must refresh');
  assert.equal(calls.refresh[0].tokenSlot, 1, 'refresh the position being sent');
  assert.equal(store.get('witnessTokenSlot'), 1);
});

test('ensureSendable: fails closed when the refresh cannot run', async () => {
  const store = fakeStore({ canSend: false });
  const { ctx } = fakeCtx({ store, available: false });
  assert.equal(await ensureSendable(ctx, 0), false, 'no witness ⇒ no send');
});

test('ensureSendable: a withheld refresh leaves the delegate not sendable', async () => {
  const store = fakeStore({ canSend: false });
  const { ctx } = fakeCtx({ store, refreshOk: false });
  assert.equal(await ensureSendable(ctx, 0), false);
  assert.notEqual(store.get('canSend'), true);
});
