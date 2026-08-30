'use strict';
// Durable per-channel orchestration state (DESIGN.md §2.2/§2.3/§5.2).
// Crash-safe: write to a temp file then atomic rename. Holds ONLY loop/orchestration metadata
// (cursor, tickets, seen action-ids, scores, alerts, state-machine node). The authoritative channel
// state lives in the CLI's cli_state.json (co-signer) or the WASM session (delegate) — never here.

const fs = require('fs');
const path = require('path');

function emptyState() {
  return {
    // Next durable L1 block to scan. Every nonzero cursor must carry the authenticated cursor-1
    // checkpoint. A legacy number-only cursor fails stop; the current fork cannot retroactively
    // authenticate state that may have been derived on another fork.
    cursor: 0,
    chainCheckpoint: null, // { number: cursor-1, hash, parentHash }
    // Sticky fail-stop for structural/cryptographic contradictions (chain id, hashes, malformed
    // finalized data). Ordinary RPC transport unavailability uses a volatile readiness gate and
    // auto-recovers after a complete successful poll.
    chainSafetyHalt: null, // { at, code, message, evidence }
    smNode: null, // current state-machine node string
    tickets: {}, // id -> ticket object
    actions: {}, // actionId -> { at, result } (idempotency ledger)
    scores: {}, // senderId -> { count, windowStart }
    alerts: [], // bounded ring of recent alerts (forensics)
    // A successful outgoing inter-channel/burn co-sign reserves the live base nonce until the
    // authoritative daemon advances past it. This survives process restarts: an in-memory mutex
    // alone cannot stop two different requests from being signed against the same base cursor.
    outgoingBaseNonceReservation: null, // { nonce, actionId, at }
    mode: 'normal', // 'normal' | 'defensive' | 'exiting'
  };
}

function fsyncDirectorySync(directory) {
  // `rename` is atomic but not necessarily durable across sudden power loss until the containing
  // directory entry is fsynced. Cursor/checkpoint loss can replay an external action, so treat a
  // directory fsync failure exactly like a state persistence failure.
  const fd = fs.openSync(directory, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

class Store {
  constructor(filePath) {
    this.filePath = filePath;
    this.reservationPath = `${filePath}.outgoing-base-nonce`;
    this.reservationLockPath = `${this.reservationPath}.lock`;
    this.state = emptyState();
    this._load();
    const reservation = this._readOutgoingReservation();
    if (reservation !== undefined) this.state.outgoingBaseNonceReservation = reservation;
  }

  _load() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      this.state = { ...emptyState(), ...JSON.parse(raw) };
    } catch (e) {
      if (e && e.code === 'ENOENT') {
        this.state = emptyState();
        return;
      }
      // Cursor/action loss can suppress chain events or authorize a duplicate signature. A corrupt
      // journal is therefore not equivalent to a fresh node; refuse to start until reconciled.
      throw new Error(`cannot read durable node store ${this.filePath}: ${e.message}`, { cause: e });
    }
  }

  // Crash-durable persist: temp fd write+fsync, atomic same-directory rename, parent-directory
  // fsync. The last step is what makes the renamed cursor/checkpoint survive a power loss.
  flush() {
    const directory = path.dirname(this.filePath);
    fs.mkdirSync(directory, { recursive: true });
    const tmp = `${this.filePath}.tmp-${process.pid}-${Date.now()}-${Store.flushSequence++}`;
    let fd;
    try {
      fd = fs.openSync(tmp, 'wx', 0o600);
      fs.writeFileSync(fd, JSON.stringify(this.state, null, 2));
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(tmp, this.filePath);
      fsyncDirectorySync(directory);
    } catch (e) {
      if (fd !== undefined) fs.closeSync(fd);
      try { fs.rmSync(tmp, { force: true }); } catch (_) { /* keep original error */ }
      throw e;
    }
  }

  get(key) {
    if (key === 'outgoingBaseNonceReservation') {
      const reservation = this._readOutgoingReservation();
      if (reservation !== undefined) this.state.outgoingBaseNonceReservation = reservation;
    }
    return this.state[key];
  }

  _readOutgoingReservation() {
    try {
      return JSON.parse(fs.readFileSync(this.reservationPath, 'utf8'));
    } catch (e) {
      if (e && e.code === 'ENOENT') return undefined;
      throw e;
    }
  }

  _withReservationLock(fn) {
    fs.mkdirSync(path.dirname(this.reservationLockPath), { recursive: true });
    let fd = null;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        fd = fs.openSync(this.reservationLockPath, 'wx', 0o600);
        break;
      } catch (e) {
        if (!e || e.code !== 'EEXIST') throw e;
        // A process can die after acquiring the tiny critical section. Reap only a clearly stale
        // lock; a healthy holder normally releases it within a few synchronous filesystem calls.
        try {
          const ageMs = Date.now() - fs.statSync(this.reservationLockPath).mtimeMs;
          if (ageMs > 30_000) {
            fs.rmSync(this.reservationLockPath, { force: true });
            continue;
          }
        } catch (statError) {
          if (statError && statError.code === 'ENOENT') continue;
          throw statError;
        }
        // Synchronous store APIs cannot yield a Promise; Atomics.wait provides a bounded 5ms
        // backoff without burning CPU while another local process owns the lock.
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
      }
    }
    if (fd === null) throw new Error('timed out acquiring outgoing base nonce reservation lock');
    try {
      return fn();
    } finally {
      fs.closeSync(fd);
      fs.rmSync(this.reservationLockPath, { force: true });
    }
  }

  _writeOutgoingReservation(reservation) {
    const directory = path.dirname(this.reservationPath);
    fs.mkdirSync(directory, { recursive: true });
    const tmp = `${this.reservationPath}.tmp-${process.pid}-${Date.now()}-${Store.flushSequence++}`;
    let fd;
    try {
      fd = fs.openSync(tmp, 'wx', 0o600);
      fs.writeFileSync(fd, JSON.stringify(reservation));
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(tmp, this.reservationPath);
      fsyncDirectorySync(directory);
    } catch (error) {
      if (fd !== undefined) fs.closeSync(fd);
      try { fs.rmSync(tmp, { force: true }); } catch (_) { /* preserve original error */ }
      throw error;
    }
  }

  set(key, value) {
    this.state[key] = value;
    this.flush();
    return value;
  }

  setCursor(block) {
    if (block > this.state.cursor) {
      this.state.cursor = block;
      // Compatibility API for old callers/tests only. This deliberately leaves a nonzero cursor
      // unauthenticated: the watcher will fail stop and require operator reconciliation. Production
      // chain consumers must call setChainProgress(cursor, checkpoint) instead.
      this.state.chainCheckpoint = null;
      this.flush();
    }
    return this.state.cursor;
  }

  setChainProgress(nextBlock, checkpoint) {
    if (!Number.isSafeInteger(nextBlock) || nextBlock < 0) {
      throw new Error(`invalid next chain block ${nextBlock}`);
    }
    if (nextBlock < this.state.cursor) {
      throw new Error(`refusing implicit chain cursor rollback ${this.state.cursor} -> ${nextBlock}`);
    }
    if (nextBlock === 0) {
      if (checkpoint != null) throw new Error('genesis cursor must not carry a prior-block checkpoint');
    } else {
      if (!checkpoint || checkpoint.number !== nextBlock - 1
          || !/^0x[0-9a-f]{64}$/.test(String(checkpoint.hash || '').toLowerCase())
          || !/^0x[0-9a-f]{64}$/.test(String(checkpoint.parentHash || '').toLowerCase())) {
        throw new Error('chain checkpoint must authenticate exactly nextBlock - 1');
      }
    }
    const normalized = checkpoint == null ? null : {
      number: checkpoint.number,
      hash: checkpoint.hash.toLowerCase(),
      parentHash: checkpoint.parentHash.toLowerCase(),
    };
    const unchanged = nextBlock === this.state.cursor
      && JSON.stringify(normalized) === JSON.stringify(this.state.chainCheckpoint);
    if (!unchanged) {
      this.state.cursor = nextBlock;
      this.state.chainCheckpoint = normalized;
      this.flush();
    }
    return { cursor: this.state.cursor, checkpoint: this.state.chainCheckpoint };
  }

  bootstrapChainProgress(nextBlock, checkpoint) {
    void nextBlock;
    void checkpoint;
    // Do not turn a current-fork observation into retroactive authentication for derived state
    // produced by a legacy cursor. Keeping this formerly public helper fail-stop also prevents a
    // future caller from accidentally reintroducing the unsafe migration path.
    throw new Error('legacy number-only chain cursors require operator reconciliation');
  }

  haltChainSafety(error) {
    const rec = {
      at: Date.now(),
      code: String(error && error.code || 'CHAIN_SAFETY_FAILURE'),
      message: String(error && error.message || error || 'chain safety failure'),
      evidence: error && error.evidence && typeof error.evidence === 'object'
        ? error.evidence
        : {},
    };
    // Preserve the first failure as the forensic root cause. Repeated poll attempts must not erase
    // it or make a catastrophic finalized-checkpoint mismatch look transient.
    if (!this.state.chainSafetyHalt) {
      this.state.chainSafetyHalt = rec;
      this.flush();
    }
    return this.state.chainSafetyHalt;
  }

  // Idempotency: returns true the FIRST time an actionId is seen (and records it), false after.
  // Callers gate externally-visible effects on this so a crash-replay never double-acts.
  claimAction(actionId, options = {}) {
    const existing = this.state.actions[actionId];
    if (existing) {
      // Chain/justice handlers are idempotent on-chain and must resume a `pending` claim left by a
      // process death. Outgoing co-sign handlers deliberately keep the default once-only behavior
      // because a signature may have escaped before the crash.
      if (options.retryPending === true && existing.result === 'pending') return true;
      return false;
    }
    this.state.actions[actionId] = { at: Date.now(), result: 'pending' };
    this.flush();
    return true;
  }

  hasAction(actionId) {
    return Boolean(this.state.actions[actionId]);
  }

  completeAction(actionId, result) {
    if (!this.state.actions[actionId]) this.state.actions[actionId] = { at: Date.now() };
    this.state.actions[actionId].result = result;
    this.state.actions[actionId].doneAt = Date.now();
    this.flush();
  }

  // Release a claimed action so it can be retried (use on a transient/failed attempt that produced
  // NO externally-visible effect). A SUCCESSFUL action must use completeAction (permanent dedup).
  releaseAction(actionId) {
    if (this.state.actions[actionId] && this.state.actions[actionId].result === 'pending') {
      delete this.state.actions[actionId];
      this.flush();
    }
  }

  // Reserve one authoritative base nonce for one outgoing action. A later nonce proves the daemon
  // consumed the old cursor and may replace the reservation. The same/older nonce remains fenced.
  reserveOutgoingBaseNonce(nonce, actionId) {
    if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff) {
      throw new Error(`invalid outgoing base nonce ${nonce}`);
    }
    return this._withReservationLock(() => {
      const disk = this._readOutgoingReservation();
      const current = disk === undefined ? this.state.outgoingBaseNonceReservation : disk;
      if (current && nonce <= current.nonce) {
        this.state.outgoingBaseNonceReservation = current;
        return false;
      }
      const next = { nonce, actionId, at: Date.now() };
      this._writeOutgoingReservation(next);
      this.state.outgoingBaseNonceReservation = next;
      this.flush();
      return true;
    });
  }

  // Release only the exact reservation, and only when the CLI never completed signing. Once a
  // signature may exist, the reservation is deliberately sticky until the live nonce advances.
  releaseOutgoingBaseNonce(nonce, actionId) {
    return this._withReservationLock(() => {
      const disk = this._readOutgoingReservation();
      const current = disk === undefined ? this.state.outgoingBaseNonceReservation : disk;
      if (!current || current.nonce !== nonce || current.actionId !== actionId) {
        this.state.outgoingBaseNonceReservation = current || null;
        return false;
      }
      this._writeOutgoingReservation(null);
      this.state.outgoingBaseNonceReservation = null;
      this.flush();
      return true;
    });
  }

  upsertTicket(ticket) {
    this.state.tickets[ticket.id] = { ...ticket, updatedAt: Date.now() };
    this.flush();
    return this.state.tickets[ticket.id];
  }

  findTicket(predicate) {
    return Object.values(this.state.tickets).find(predicate);
  }

  setMode(mode) {
    this.state.mode = mode;
    this.flush();
    return mode;
  }

  setSmNode(node) {
    this.state.smNode = node;
    this.flush();
    return node;
  }

  pushAlert(rec) {
    this.state.alerts.push({ at: Date.now(), ...rec });
    if (this.state.alerts.length > 200) this.state.alerts.shift();
    this.flush();
  }
}

Store.flushSequence = 0;

module.exports = { Store, emptyState, fsyncDirectorySync };
