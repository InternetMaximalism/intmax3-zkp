'use strict';
// Cluster co-signing protocol (sig-cluster, N <= MAX_SIG_CLUSTER = 8 hosts, one or more cosigner
// slots per host). Replaces the single-host `cosign` (one process signing every slot) with an
// N-to-N signature exchange:
//
//   1. PROPOSE. The host that receives a wallet's SendPayload runs `cosign-partial` (full co-sign
//      gate + its own slot signatures) and broadcasts the payload to every peer. Each peer runs the
//      same gate, signs with ITS slots, and broadcasts its signatures to every host (N-to-N: every
//      host ends up holding every signature it has been sent, not just its own).
//   2. ASSEMBLE. Any host holding all `memberCount` signatures runs `cosign-merge`, which verifies
//      each pooled signature individually and adopts the N-of-N head. The coordinator answers the
//      wallet with that head.
//   3. WARN (warnMs = 1 min). A host whose round is still incomplete broadcasts a CLOSE WARNING
//      naming the missing slots. Every host that holds any of the missing signatures — its own or
//      one it received from a third host — sends them to the warner.
//   4. HALT (haltMs = 5 min). Still incomplete: the channel enters the HALTED state (persisted,
//      broadcast). Mutating requests are refused while halted. A late complete set still finishes
//      the round and lifts the halt.
//   5. AUTO-CLOSE (closeMs = 24 h). A channel halted for `closeMs` is closed at its LAST fully
//      signed state (the head; never the stalled proposal) through `onAutoClose`; a failed close
//      is retried on every watchdog tick.
//
// The module is transport- and clock-agnostic (injected `post`/`clock`) so the protocol is unit
// tested with N in-process hosts and a manual clock; the relay wires HTTP routes and the CLI.
//
// SECURITY: signatures are never trusted by this module — `cosign-merge` re-verifies each one
// against the registered member set over the recomputed digest before adopting anything, and
// `cosign-partial` re-runs the full transition gate before this host signs. Pooling here only
// decides WHEN to attempt the merge and WHOM to ask for missing pieces.

const DEFAULT_WARN_MS = 60 * 1000;
const DEFAULT_HALT_MS = 5 * 60 * 1000;
const DEFAULT_CLOSE_MS = 24 * 60 * 60 * 1000;
const DEFAULT_WATCHDOG_MS = 60 * 1000;
const MAX_SIG_CLUSTER = 8;

function normSlot(s) {
  const n = Number(s);
  if (!Number.isInteger(n) || n < 0 || n >= MAX_SIG_CLUSTER) throw new Error(`invalid cosigner slot ${s}`);
  return n;
}

function createCluster(opts) {
  const {
    self,                 // { url, slots: [..] }
    peers = [],           // [{ url, slots: [..] }]
    memberCount,          // (ch) => N
    signPartial,          // async (ch, payload) => { prevDigest, nextDigest, signatures: [MemberSignature] }
    merge,                // async (ch, payload, signatures) => { complete: true, state } | { complete: false, missing }
    post,                 // async (url, path, body) => any
    persistHalt = () => {}, // (ch, info | null)
    loadHalt = () => null,  // (ch) => info | null
    onAutoClose = async () => { throw new Error('auto-close is not configured'); },
    log = console,
  } = opts;
  const clock = opts.clock || { now: Date.now, setTimeout, clearTimeout };
  const warnMs = opts.warnMs ?? DEFAULT_WARN_MS;
  const haltMs = opts.haltMs ?? DEFAULT_HALT_MS;
  const closeMs = opts.closeMs ?? DEFAULT_CLOSE_MS;
  const watchdogMs = opts.watchdogMs ?? DEFAULT_WATCHDOG_MS;

  if (!self || !self.url) throw new Error('cluster: self.url is required');
  const hosts = [self, ...peers];
  if (hosts.length > MAX_SIG_CLUSTER) throw new Error(`cluster: at most ${MAX_SIG_CLUSTER} hosts`);
  const seen = new Set();
  for (const h of hosts) {
    if (!h.url) throw new Error('cluster: every host needs a url');
    for (const s of (h.slots || [])) {
      const n = normSlot(s);
      if (seen.has(n)) throw new Error(`cluster: slot ${n} is assigned to two hosts`);
      seen.add(n);
    }
  }

  const rounds = {};   // rounds[ch][nextDigest] = round
  const halted = {};   // halted[ch] = { nextDigest, since, missing, closedAt? }

  const memberCountOf = (ch) => Number(memberCount(ch));
  const digestOf = (payload) => payload && payload.proposedNextState && payload.proposedNextState.digest;
  const prevOf = (payload) => payload && payload.proposedNextState && payload.proposedNextState.prevDigest;

  function haltInfo(ch) {
    if (halted[ch] === undefined) halted[ch] = loadHalt(ch) || null;
    return halted[ch];
  }
  function setHalt(ch, info) {
    halted[ch] = info;
    persistHalt(ch, info);
  }

  function getRound(ch, nextDigest) {
    rounds[ch] = rounds[ch] || {};
    return rounds[ch][nextDigest] || null;
  }
  function openRound(ch, payload) {
    const nextDigest = digestOf(payload);
    if (!nextDigest) throw new Error('payload has no proposedNextState.digest');
    rounds[ch] = rounds[ch] || {};
    let r = rounds[ch][nextDigest];
    if (r) {
      if (!r.payload) r.payload = payload;
      return r;
    }
    r = {
      ch, nextDigest, prevDigest: prevOf(payload), payload,
      sigs: new Map(),          // slot -> MemberSignature
      startedAt: clock.now(),
      signed: false,            // this host produced its partial
      completed: false, state: null,
      waiters: [], warned: false, merging: null,
      warnTimer: null, haltTimer: null,
    };
    rounds[ch][nextDigest] = r;
    armWarn(r);
    // A timer callback must never throw: an unreadable snapshot or a failed halt persist would
    // otherwise be an uncaught exception that takes the whole relay down.
    r.haltTimer = clock.setTimeout(() => { try { halt(r); } catch (e) { log.error(`[cluster] channel ${r.ch}: halt failed: ${e.message || e}`); } }, haltMs);
    return r;
  }
  // The CLOSE WARNING repeats every `warnMs` until the round completes or halts: a signature that
  // was in flight (or a host that was briefly unreachable) at the first warning is asked for
  // again instead of being written off until the halt.
  function armWarn(r) {
    r.warnTimer = clock.setTimeout(() => {
      r.warnTimer = null;
      warn(r).catch((e) => log.error(`[cluster] warn failed: ${e.message || e}`)).finally(() => {
        if (!r.completed && !haltInfo(r.ch)) armWarn(r);
      });
    }, warnMs);
  }
  function clearTimers(r) {
    if (r.warnTimer) { clock.clearTimeout(r.warnTimer); r.warnTimer = null; }
    if (r.haltTimer) { clock.clearTimeout(r.haltTimer); r.haltTimer = null; }
  }
  // A proposal this host's own gate REFUSED is not a stalled round: nobody is missing, the
  // successor is simply not signable. Drop it at once — no CLOSE WARNING, no HALT, no auto-close —
  // and hand the gate's error to every waiter. (A silent or unreachable signer is the only thing
  // the warning/halt timers are for.)
  function abortRound(r, err) {
    if (r.completed) return;
    clearTimers(r);
    if (rounds[r.ch] && rounds[r.ch][r.nextDigest] === r) delete rounds[r.ch][r.nextDigest];
    for (const w of r.waiters) w.reject(err);
    r.waiters = [];
  }
  function missingSlots(r) {
    const n = memberCountOf(r.ch);
    const missing = [];
    for (let s = 0; s < n; s++) if (!r.sigs.has(s)) missing.push(s);
    return missing;
  }
  function addSignatures(r, signatures) {
    let added = 0;
    for (const sig of signatures || []) {
      const slot = normSlot(sig.memberSlot ?? sig.member_slot);
      if (!r.sigs.has(slot)) { r.sigs.set(slot, sig); added++; }
    }
    return added;
  }

  async function broadcast(path, body, targets = peers) {
    await Promise.all(targets.map((h) => post(h.url, path, body).catch((e) => {
      log.error(`[cluster] ${path} -> ${h.url} failed: ${e.message || e}`);
    })));
  }

  // Sign with this host's slots (once per round) and tell everyone.
  async function signOwn(r) {
    if (r.signed) return;
    r.signed = true;
    const partial = await signPartial(r.ch, r.payload);
    if (partial.nextDigest && partial.nextDigest !== r.nextDigest) {
      throw new Error(`cosign-partial signed ${partial.nextDigest}, expected ${r.nextDigest}`);
    }
    addSignatures(r, partial.signatures);
    await broadcast('/api/cluster/signature', {
      channel: r.ch, nextDigest: r.nextDigest, prevDigest: r.prevDigest,
      from: self.url, signatures: partial.signatures,
    });
  }

  async function tryComplete(r) {
    if (r.completed || !r.payload) return false;
    if (missingSlots(r).length > 0) return false;
    if (r.merging) return r.merging;
    r.merging = (async () => {
      const result = await merge(r.ch, r.payload, [...r.sigs.values()]);
      if (!result || !result.complete) {
        log.error(`[cluster] channel ${r.ch}: merge incomplete, missing ${JSON.stringify(result && result.missing)}`);
        return false;
      }
      r.completed = true;
      r.state = result.state;
      clearTimers(r);
      const h = haltInfo(r.ch);
      if (h && h.nextDigest === r.nextDigest && !h.closedAt) {
        setHalt(r.ch, null);
        log.warn(`[cluster] channel ${r.ch}: halt lifted — round ${r.nextDigest} completed late`);
      }
      for (const w of r.waiters) w.resolve(result.state);
      r.waiters = [];
      log.info(`[cluster] channel ${r.ch}: N-of-N assembled for ${r.nextDigest}`);
      return true;
    })().finally(() => { r.merging = null; });
    return r.merging;
  }

  // CLOSE WARNING: name the missing slots to every host; holders answer to `from`.
  async function warn(r) {
    if (r.completed) return;
    const missing = missingSlots(r);
    if (missing.length === 0) { await tryComplete(r); return; }
    r.warned = true;
    log.warn(`[cluster] channel ${r.ch}: CLOSE WARNING — signatures missing for slots ${JSON.stringify(missing)} after ${warnMs} ms (round ${r.nextDigest})`);
    await broadcast('/api/cluster/missing', {
      channel: r.ch, nextDigest: r.nextDigest, prevDigest: r.prevDigest, missing, from: self.url,
    });
  }

  function halt(r) {
    if (r.completed) return;
    const missing = missingSlots(r);
    if (missing.length === 0) { tryComplete(r).catch(() => {}); return; }
    const info = { nextDigest: r.nextDigest, since: clock.now(), missing };
    setHalt(r.ch, info);
    log.error(`[cluster] channel ${r.ch}: HALTED — slots ${JSON.stringify(missing)} never signed round ${r.nextDigest} within ${haltMs} ms`);
    const err = new Error(`channel ${r.ch} halted: cosigner slots ${JSON.stringify(missing)} did not sign within ${haltMs} ms`);
    err.halted = true;
    for (const w of r.waiters) w.reject(err);
    r.waiters = [];
    broadcast('/api/cluster/halt', { channel: r.ch, ...info, from: self.url }).catch(() => {});
  }

  // ---- public API -------------------------------------------------------------------------

  // Coordinator entry: a wallet's proposal. Resolves with the N-of-N state; rejects on halt.
  async function cosign(ch, payload) {
    const h = haltInfo(ch);
    if (h) {
      const err = new Error(`channel ${ch} is halted since ${new Date(h.since).toISOString()} (missing slots ${JSON.stringify(h.missing)})`);
      err.halted = true;
      throw err;
    }
    const r = openRound(ch, payload);
    const done = new Promise((resolve, reject) => r.waiters.push({ resolve, reject }));
    done.catch(() => {}); // the caller gets the rejection below; never an unhandled one
    if (r.completed) return r.state;
    try {
      await broadcast('/api/cluster/propose', { channel: ch, payload, from: self.url });
      await signOwn(r);
      await tryComplete(r);
    } catch (e) {
      abortRound(r, e);
      throw e;
    }
    return done;
  }

  // Peer entry: a proposal from another host.
  async function onPropose({ channel, payload }) {
    const ch = Number(channel);
    if (haltInfo(ch)) throw Object.assign(new Error(`channel ${ch} is halted`), { halted: true });
    const r = openRound(ch, payload);
    // Acknowledge at once; sign and assemble asynchronously. The proposer's broadcast must never
    // block on a slow or silent signer — that is exactly the case the warning/halt timers cover.
    signOwn(r).then(() => tryComplete(r)).catch((e) => {
      log.error(`[cluster] channel ${ch}: partial sign refused, round ${r.nextDigest} dropped: ${e.message || e}`);
      abortRound(r, e);
    });
    return { ok: true, nextDigest: r.nextDigest, held: [...r.sigs.keys()] };
  }

  // Peer entry: signatures from any host (own or forwarded). A signature may arrive before its
  // proposal; it is pooled and merged once the payload is known.
  async function onSignature({ channel, nextDigest, prevDigest, signatures }) {
    const ch = Number(channel);
    rounds[ch] = rounds[ch] || {};
    let r = rounds[ch][nextDigest];
    if (!r) {
      r = rounds[ch][nextDigest] = {
        ch, nextDigest, prevDigest, payload: null, sigs: new Map(), startedAt: clock.now(),
        signed: false, completed: false, state: null, waiters: [], warned: false, merging: null,
        warnTimer: null, haltTimer: null,
      };
    }
    const added = addSignatures(r, signatures);
    await tryComplete(r);
    return { ok: true, added, held: [...r.sigs.keys()] };
  }

  // Peer entry: a CLOSE WARNING. Hand the warner every missing signature we hold.
  async function onMissing({ channel, nextDigest, missing, from }) {
    const ch = Number(channel);
    const r = getRound(ch, nextDigest);
    const have = [];
    if (r) for (const s of missing || []) { const n = normSlot(s); if (r.sigs.has(n)) have.push(r.sigs.get(n)); }
    if (have.length && from && from !== self.url) {
      await post(from, '/api/cluster/signature', {
        channel: ch, nextDigest, prevDigest: r.prevDigest, from: self.url, signatures: have,
      });
    }
    return { ok: true, supplied: have.map((s) => s.memberSlot ?? s.member_slot) };
  }

  // Peer entry: a halt announced by another host. Idempotent; our own timer would fire too.
  async function onHalt({ channel, nextDigest, since, missing }) {
    const ch = Number(channel);
    const r = getRound(ch, nextDigest);
    if (r && r.completed) return { ok: true, ignored: 'round already completed here' };
    if (!haltInfo(ch)) setHalt(ch, { nextDigest, since: Number(since) || clock.now(), missing: missing || [] });
    return { ok: true };
  }

  function status(ch) {
    const out = { self: self.url, peers: peers.map((p) => p.url), halted: haltInfo(ch), rounds: [] };
    for (const r of Object.values(rounds[ch] || {})) {
      out.rounds.push({ nextDigest: r.nextDigest, held: [...r.sigs.keys()], missing: missingSlots(r), completed: r.completed, warned: r.warned, startedAt: r.startedAt });
    }
    return out;
  }

  // ---- 24 h auto-close watchdog (node-program rule) --------------------------------------
  const watched = new Set();
  function watch(ch) { watched.add(Number(ch)); haltInfo(Number(ch)); }
  async function tick() {
    for (const ch of watched) {
      const h = haltInfo(ch);
      if (!h || h.closedAt) continue;
      if (clock.now() - h.since < closeMs) continue;
      try {
        log.error(`[cluster] channel ${ch}: halted for ${closeMs} ms — closing at the last fully signed state`);
        const result = await onAutoClose(ch, h);
        setHalt(ch, { ...h, closedAt: clock.now(), close: result === undefined ? true : result });
      } catch (e) {
        log.error(`[cluster] channel ${ch}: auto-close failed (will retry): ${e.message || e}`);
      }
    }
  }
  let watchdog = null;
  function startWatchdog() {
    if (watchdog) return;
    const loop = () => { watchdog = clock.setTimeout(() => { tick().catch(() => {}).finally(loop); }, watchdogMs); };
    loop();
  }
  function stopWatchdog() { if (watchdog) { clock.clearTimeout(watchdog); watchdog = null; } }

  return {
    cosign, onPropose, onSignature, onMissing, onHalt,
    halted: haltInfo, status, watch, tick, startWatchdog, stopWatchdog,
    hosts: () => hosts.map((h) => ({ url: h.url, slots: [...(h.slots || [])] })),
    constants: { warnMs, haltMs, closeMs, MAX_SIG_CLUSTER },
  };
}

module.exports = { createCluster, MAX_SIG_CLUSTER, DEFAULT_WARN_MS, DEFAULT_HALT_MS, DEFAULT_CLOSE_MS };
