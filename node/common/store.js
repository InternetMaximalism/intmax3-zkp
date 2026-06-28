'use strict';
// Durable per-channel orchestration state (DESIGN.md §2.2/§2.3/§5.2).
// Crash-safe: write to a temp file then atomic rename. Holds ONLY loop/orchestration metadata
// (cursor, tickets, seen action-ids, scores, alerts, state-machine node). The authoritative channel
// state lives in the CLI's cli_state.json (co-signer) or the WASM session (delegate) — never here.

const fs = require('fs');
const path = require('path');

function emptyState() {
  return {
    cursor: 0, // last fully-processed (confirmed) block number
    smNode: null, // current state-machine node string
    tickets: {}, // id -> ticket object
    actions: {}, // actionId -> { at, result } (idempotency ledger)
    scores: {}, // senderId -> { count, windowStart }
    alerts: [], // bounded ring of recent alerts (forensics)
    mode: 'normal', // 'normal' | 'defensive' | 'exiting'
  };
}

class Store {
  constructor(filePath) {
    this.filePath = filePath;
    this.state = emptyState();
    this._load();
  }

  _load() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      this.state = { ...emptyState(), ...JSON.parse(raw) };
    } catch (e) {
      this.state = emptyState();
    }
  }

  // Atomic persist: tmp file + rename (rename is atomic on the same filesystem).
  flush() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = this.filePath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.state, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  get(key) {
    return this.state[key];
  }

  set(key, value) {
    this.state[key] = value;
    this.flush();
    return value;
  }

  setCursor(block) {
    if (block > this.state.cursor) {
      this.state.cursor = block;
      this.flush();
    }
    return this.state.cursor;
  }

  // Idempotency: returns true the FIRST time an actionId is seen (and records it), false after.
  // Callers gate externally-visible effects on this so a crash-replay never double-acts.
  claimAction(actionId) {
    if (this.state.actions[actionId]) return false;
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

module.exports = { Store, emptyState };
