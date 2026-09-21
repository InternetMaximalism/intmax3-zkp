'use strict';
// Cluster co-signing protocol (api/lib/cluster.js): N hosts (<= 8), each holding its own slot(s),
// exchange signatures N-to-N; a 1-minute CLOSE WARNING names the missing slots and any holder
// supplies them; a 5-minute silence HALTS the channel; a channel halted for 24 h is auto-closed
// at its last fully signed state. Transport and clock are injected: every host runs in-process
// against a manual clock, so the timing rules are tested exactly.

const test = require('node:test');
const assert = require('node:assert');
const { createCluster } = require('../../api/lib/cluster');

const WARN = 60_000, HALT = 300_000, CLOSE = 86_400_000;

// ---- manual clock ----------------------------------------------------------------------------
function makeClock() {
  let now = 1_000_000;
  const timers = new Map();
  let id = 0;
  return {
    now: () => now,
    setTimeout: (fn, ms) => { const t = ++id; timers.set(t, { at: now + ms, fn }); return t; },
    clearTimeout: (t) => { timers.delete(t); },
    // Advance time, firing due timers in order and letting promise chains settle between them.
    async advance(ms) {
      const target = now + ms;
      for (;;) {
        let next = null;
        for (const [t, e] of timers) if (e.at <= target && (!next || e.at < next.e.at)) next = { t, e };
        if (!next) break;
        now = next.e.at; timers.delete(next.t);
        await next.e.fn();
        await settle();
      }
      now = target;
      await settle();
    },
  };
}
const settle = () => new Promise((r) => setImmediate(r));

// ---- in-memory N-host fabric -------------------------------------------------------------------
function makeFabric({ hosts, memberCount, clock, drops = new Set(), signDelay = {}, refuse = null }) {
  const registry = new Map();
  const merges = [];      // { url, ch, slots }
  const closes = [];      // { url, ch }
  const halts = new Map(); // url -> { ch -> info }
  const sig = (slot, digest) => ({ memberSlot: slot, pkG: `pk${slot}`, signature: `sig:${slot}:${digest}` });
  const post = async (url, path, body) => {
    const key = `${body.from || '?'}->${url}${path}`;
    if (drops.has(key)) throw new Error(`dropped ${key}`);
    const target = registry.get(url);
    if (!target) throw new Error(`no host ${url}`);
    return target.route(path, body);
  };
  const clusters = hosts.map((h) => {
    const store = {};
    halts.set(h.url, store);
    const cluster = createCluster({
      self: h, peers: hosts.filter((o) => o.url !== h.url), memberCount: () => memberCount,
      signPartial: async (ch, payload) => {
        if (signDelay[h.url]) await signDelay[h.url]();
        const d = payload.proposedNextState.digest;
        if (refuse && refuse(d)) throw new Error('SIGNER-INDEPENDENT EXIT REQUIRED: head is KIT-PENDING');
        return { prevDigest: payload.proposedNextState.prevDigest, nextDigest: d, signatures: h.slots.map((s) => sig(s, d)) };
      },
      merge: async (ch, payload, signatures) => {
        const slots = signatures.map((s) => s.memberSlot).sort();
        merges.push({ url: h.url, ch, slots });
        const missing = [];
        for (let s = 0; s < memberCount; s++) if (!slots.includes(s)) missing.push(s);
        return missing.length ? { complete: false, missing } : { complete: true, state: { digest: payload.proposedNextState.digest, signed: slots } };
      },
      post, clock, warnMs: WARN, haltMs: HALT, closeMs: CLOSE, watchdogMs: 60_000,
      persistHalt: (ch, info) => { if (info) store[ch] = info; else delete store[ch]; },
      loadHalt: (ch) => store[ch] || null,
      onAutoClose: async (ch) => { closes.push({ url: h.url, ch }); if (h.closeFails) throw new Error('manager unavailable'); return 'closed'; },
      log: { info() {}, warn() {}, error() {} },
    });
    const route = (path, body) => {
      switch (path) {
        case '/api/cluster/propose': return cluster.onPropose(body);
        case '/api/cluster/signature': return cluster.onSignature(body);
        case '/api/cluster/missing': return cluster.onMissing(body);
        case '/api/cluster/halt': return cluster.onHalt(body);
        default: throw new Error(`unknown route ${path}`);
      }
    };
    registry.set(h.url, { cluster, route });
    return cluster;
  });
  return { clusters, merges, closes, halts, post };
}

const payload = (digest, prev = '0xprev') => ({ proposedNextState: { digest, prevDigest: prev }, channelTx: {} });
const hostsN = (n) => Array.from({ length: n }, (_, i) => ({ url: `http://h${i}`, slots: [i] }));

test('happy path: 3 hosts, every host assembles the same N-of-N head', async () => {
  const clock = makeClock();
  const f = makeFabric({ hosts: hostsN(3), memberCount: 3, clock });
  const state = await f.clusters[0].cosign(7, payload('0xd1'));
  assert.deepStrictEqual(state.signed, [0, 1, 2]);
  await settle();
  // Each host merged exactly once with all three signatures.
  const byHost = Object.fromEntries(f.merges.map((m) => [m.url, m.slots]));
  assert.deepStrictEqual(byHost, { 'http://h0': [0, 1, 2], 'http://h1': [0, 1, 2], 'http://h2': [0, 1, 2] });
  assert.strictEqual(f.merges.length, 3);
  for (const c of f.clusters) assert.strictEqual(c.halted(7), null);
});

test('happy path at the cap: 8 hosts, one slot each', async () => {
  const clock = makeClock();
  const f = makeFabric({ hosts: hostsN(8), memberCount: 8, clock });
  const state = await f.clusters[5].cosign(7, payload('0xd8'));
  assert.deepStrictEqual(state.signed, [0, 1, 2, 3, 4, 5, 6, 7]);
  await settle();
  assert.strictEqual(f.merges.length, 8);
});

test('a host holding several slots signs all of them', async () => {
  const clock = makeClock();
  const hosts = [{ url: 'http://a', slots: [0, 1] }, { url: 'http://b', slots: [2] }];
  const f = makeFabric({ hosts, memberCount: 3, clock });
  const state = await f.clusters[1].cosign(7, payload('0xd2'));
  assert.deepStrictEqual(state.signed, [0, 1, 2]);
});

test('9 hosts or a doubly assigned slot are refused at construction', () => {
  assert.throws(() => makeFabric({ hosts: hostsN(9), memberCount: 9, clock: makeClock() }), /at most 8/);
  assert.throws(() => makeFabric({ hosts: [{ url: 'http://a', slots: [0] }, { url: 'http://b', slots: [0] }], memberCount: 1, clock: makeClock() }), /slot 0 is assigned to two hosts/);
});

test('CLOSE WARNING at 1 min: a third host that holds the lost signature supplies it to the warner', async () => {
  const clock = makeClock();
  // h2's signature reaches h1 but the delivery h2 -> h0 is lost.
  const drops = new Set(['http://h2->http://h0/api/cluster/signature']);
  const f = makeFabric({ hosts: hostsN(3), memberCount: 3, clock, drops });
  let settled = false;
  const p = f.clusters[0].cosign(7, payload('0xd3')).then((s) => { settled = true; return s; });
  await settle();
  assert.strictEqual(settled, false, 'h0 lacks slot 2 and must not complete yet');
  assert.deepStrictEqual(f.clusters[0].status(7).rounds[0].missing, [2]);
  // h1 assembled already (it has all three).
  assert.ok(f.merges.some((m) => m.url === 'http://h1' && m.slots.length === 3));
  await clock.advance(WARN);           // h0 warns; h1 (and h2) answer with slot 2
  const state = await p;
  assert.deepStrictEqual(state.signed, [0, 1, 2]);
  assert.strictEqual(f.clusters[0].status(7).rounds[0].warned, true);
  assert.strictEqual(f.clusters[0].halted(7), null);
});

test('warning is answered by the holder even when the signer itself stays silent', async () => {
  const clock = makeClock();
  // h2 never talks to h0 directly; h1 got h2's signature and forwards it on the warning.
  const drops = new Set(['http://h2->http://h0/api/cluster/signature', 'http://h2->http://h0/api/cluster/propose']);
  const f = makeFabric({ hosts: hostsN(3), memberCount: 3, clock, drops });
  const p = f.clusters[0].cosign(7, payload('0xd4'));
  await settle();
  await clock.advance(WARN);
  const state = await p;
  assert.deepStrictEqual(state.signed, [0, 1, 2]);
});

test('HALT at 5 min when nobody can supply the missing signature; late arrival completes and lifts the halt; new proposals are refused while halted', async () => {
  const clock = makeClock();
  let releaseH2;
  const gate = new Promise((r) => { releaseH2 = r; });
  const f = makeFabric({ hosts: hostsN(3), memberCount: 3, clock, signDelay: { 'http://h2': () => gate } });
  const p = f.clusters[0].cosign(7, payload('0xd5'));
  p.catch(() => {});
  await clock.advance(WARN);
  assert.strictEqual(f.clusters[0].halted(7), null, 'warning alone does not halt');
  await clock.advance(HALT - WARN);
  await assert.rejects(p, /halted/);
  const h = f.clusters[0].halted(7);
  assert.ok(h && h.nextDigest === '0xd5' && h.missing.includes(2));
  // Every host halted (own timer or the broadcast).
  for (const c of f.clusters) assert.ok(c.halted(7), 'all hosts halted');
  // A new proposal is refused while halted.
  await assert.rejects(f.clusters[1].cosign(7, payload('0xd6', '0xprev')), /halted/);
  // The straggler finally signs: the round completes everywhere and the halt is lifted.
  releaseH2();
  await settle(); await settle();
  assert.strictEqual(f.clusters[0].halted(7), null);
  assert.ok(f.merges.some((m) => m.url === 'http://h0' && m.slots.length === 3));
  // Channel usable again.
  const s2 = await f.clusters[1].cosign(7, payload('0xd7', '0xd5'));
  assert.deepStrictEqual(s2.signed, [0, 1, 2]);
});

test('AUTO-CLOSE after 24 h halted: closes once at the last signed state, retries on failure, never for a lifted halt', async () => {
  const clock = makeClock();
  const hosts = hostsN(3);
  hosts[0].closeFails = true; // first attempt on h0 fails, later succeeds
  const f = makeFabric({ hosts, memberCount: 3, clock, signDelay: { 'http://h2': () => new Promise(() => {}) } });
  for (const c of f.clusters) { c.watch(7); c.startWatchdog(); }
  const p = f.clusters[0].cosign(7, payload('0xd9'));
  p.catch(() => {});
  await clock.advance(HALT);
  assert.ok(f.clusters[0].halted(7));
  await clock.advance(CLOSE - 60_000);   // 24 h counts from the HALT, not from the proposal
  assert.strictEqual(f.closes.length, 0, 'not yet 24 h');
  await clock.advance(2 * 60_000);
  // h1 and h2 closed; h0's first attempt failed and is retried.
  assert.ok(f.closes.some((c) => c.url === 'http://h1'));
  assert.ok(f.closes.some((c) => c.url === 'http://h2'));
  assert.ok(f.halts.get('http://h1')[7].closedAt, 'h1 recorded the close');
  hosts[0].closeFails = false;
  await clock.advance(60_000);
  assert.ok(f.halts.get('http://h0')[7].closedAt, 'h0 closed on retry');
  const before = f.closes.length;
  await clock.advance(10 * 60_000);
  assert.strictEqual(f.closes.length, before, 'a closed channel is not closed again');
  for (const c of f.clusters) c.stopWatchdog();
});

test('halt survives a restart through persistHalt/loadHalt', async () => {
  const clock = makeClock();
  const f = makeFabric({ hosts: hostsN(2), memberCount: 2, clock, signDelay: { 'http://h1': () => new Promise(() => {}) } });
  const p = f.clusters[0].cosign(7, payload('0xda'));
  p.catch(() => {});
  await clock.advance(HALT);
  const persisted = f.halts.get('http://h0')[7];
  assert.ok(persisted && persisted.since);
  // A fresh cluster instance on the same store sees the halt.
  const again = createCluster({
    self: { url: 'http://h0', slots: [0] }, peers: [], memberCount: () => 2,
    signPartial: async () => ({ signatures: [] }), merge: async () => ({ complete: false, missing: [1] }),
    post: async () => {}, clock, loadHalt: () => persisted, log: { info() {}, warn() {}, error() {} },
  });
  assert.deepStrictEqual(again.halted(7), persisted);
});

test('a proposal the local gate refuses is dropped at once: error to the caller, no warning, no halt, channel stays usable', async () => {
  const clock = makeClock();
  const f = makeFabric({ hosts: hostsN(3), memberCount: 3, clock, refuse: (d) => d === '0xbad' });
  await assert.rejects(f.clusters[0].cosign(7, payload('0xbad')), /KIT-PENDING/);
  assert.strictEqual(f.clusters[0].status(7).rounds.length, 0, 'round dropped on the proposer');
  await clock.advance(HALT + 60_000);
  for (const c of f.clusters) {
    assert.strictEqual(c.halted(7), null, 'a refused proposal never halts');
    assert.strictEqual(c.status(7).rounds.length, 0, 'round dropped on every peer');
  }
  const s = await f.clusters[1].cosign(7, payload('0xgood'));
  assert.deepStrictEqual(s.signed, [0, 1, 2]);
});
