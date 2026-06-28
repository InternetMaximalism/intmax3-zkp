'use strict';
// Pure delegate account state machine (DESIGN.md §4.9). EXITING is sticky: once entered (on
// equivocation, an invalid cosign, withholding, or a close against a stale state) the account
// pursues recovery and does not return to SYNCED until funds are confirmed on L1 (EXITED).

const NODES = {
  SYNCED: 'SYNCED',
  NEEDS_REFRESH: 'NEEDS_REFRESH',
  PROVING: 'PROVING',
  AWAIT_COSIGN: 'AWAIT_COSIGN',
  FINALIZED: 'FINALIZED',
  EXITING: 'EXITING',
  EXITED: 'EXITED',
};

const SIGNALS = {
  NEED_REFRESH: 'need_refresh',
  REFRESHED: 'refreshed',
  START_PROVE: 'start_prove',
  SENT: 'sent',
  COSIGN_OK: 'cosign_ok',
  FINALIZED: 'finalized',
  SYNCED: 'synced',
  EXIT: 'exit', // any fault → exit mode (sticky)
  EXIT_DONE: 'exit_done',
};

const TABLE = {
  SYNCED: {
    [SIGNALS.NEED_REFRESH]: NODES.NEEDS_REFRESH,
    [SIGNALS.START_PROVE]: NODES.PROVING,
    [SIGNALS.EXIT]: NODES.EXITING,
  },
  NEEDS_REFRESH: {
    [SIGNALS.START_PROVE]: NODES.PROVING, // refresh is itself a prove→cosign cycle
    [SIGNALS.REFRESHED]: NODES.SYNCED,
    [SIGNALS.EXIT]: NODES.EXITING,
  },
  PROVING: {
    [SIGNALS.SENT]: NODES.AWAIT_COSIGN,
    [SIGNALS.EXIT]: NODES.EXITING,
  },
  AWAIT_COSIGN: {
    [SIGNALS.COSIGN_OK]: NODES.FINALIZED,
    [SIGNALS.EXIT]: NODES.EXITING, // verify fail / withhold
  },
  FINALIZED: {
    [SIGNALS.SYNCED]: NODES.SYNCED,
    [SIGNALS.EXIT]: NODES.EXITING,
  },
  EXITING: {
    [SIGNALS.EXIT_DONE]: NODES.EXITED,
    // no path back to SYNCED — sticky until funds recovered
  },
  EXITED: {},
};

function next(node, signal) {
  const from = TABLE[node] ? node : NODES.SYNCED;
  return TABLE[from][signal] || from;
}

module.exports = { NODES, SIGNALS, next };
