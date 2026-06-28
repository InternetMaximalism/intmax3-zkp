'use strict';
// Pure per-channel state machine for the co-signer (DESIGN.md §3.9). Transition is a total function:
// unknown (node, signal) pairs return the node unchanged (no silent illegal jumps). DEFENSIVE is a
// sink reachable from any node on an attack signal; recovery is operator-driven via 'all_clear'.

const NODES = {
  ACTIVE: 'ACTIVE',
  CLOSE_PENDING: 'CLOSE_PENDING',
  CLOSE_SUBMITTED: 'CLOSE_SUBMITTED',
  CHALLENGE_WINDOW: 'CHALLENGE_WINDOW',
  CLOSED: 'CLOSED',
  SETTLED: 'SETTLED',
  DEFENSIVE: 'DEFENSIVE',
};

const SIGNALS = {
  CLOSE_REQUESTED: 'close_requested',
  CLOSE_SUBMITTED: 'close_submitted',
  CHALLENGE_OPEN: 'challenge_open',
  CANCELLED: 'cancelled', // cancelClose succeeded → back to ACTIVE
  FINALIZED: 'finalized', // finalizeClose → CLOSED
  CLAIMED_ALL: 'claimed_all', // all member claims pulled → SETTLED
  ATTACK: 'attack',
  ALL_CLEAR: 'all_clear', // operator clears defensive mode
};

const TABLE = {
  ACTIVE: {
    [SIGNALS.CLOSE_REQUESTED]: NODES.CLOSE_PENDING,
    [SIGNALS.CLOSE_SUBMITTED]: NODES.CLOSE_SUBMITTED, // a close can be observed already-submitted
    [SIGNALS.ATTACK]: NODES.DEFENSIVE,
  },
  CLOSE_PENDING: {
    [SIGNALS.CLOSE_SUBMITTED]: NODES.CLOSE_SUBMITTED,
    [SIGNALS.CANCELLED]: NODES.ACTIVE,
    [SIGNALS.ATTACK]: NODES.DEFENSIVE,
  },
  CLOSE_SUBMITTED: {
    [SIGNALS.CHALLENGE_OPEN]: NODES.CHALLENGE_WINDOW,
    [SIGNALS.CLOSE_SUBMITTED]: NODES.CLOSE_SUBMITTED, // replacement (challenge) re-submit
    [SIGNALS.CANCELLED]: NODES.ACTIVE,
    [SIGNALS.FINALIZED]: NODES.CLOSED,
    [SIGNALS.ATTACK]: NODES.DEFENSIVE,
  },
  CHALLENGE_WINDOW: {
    [SIGNALS.CLOSE_SUBMITTED]: NODES.CLOSE_SUBMITTED, // a newer challenge restarts the window
    [SIGNALS.CANCELLED]: NODES.ACTIVE,
    [SIGNALS.FINALIZED]: NODES.CLOSED,
    [SIGNALS.ATTACK]: NODES.DEFENSIVE,
  },
  CLOSED: {
    [SIGNALS.CLAIMED_ALL]: NODES.SETTLED,
    [SIGNALS.ATTACK]: NODES.DEFENSIVE,
  },
  SETTLED: {
    [SIGNALS.ATTACK]: NODES.DEFENSIVE,
  },
  DEFENSIVE: {
    [SIGNALS.ALL_CLEAR]: NODES.ACTIVE,
  },
};

function next(node, signal) {
  const from = TABLE[node] ? node : NODES.ACTIVE;
  const to = TABLE[from][signal];
  return to || from; // unknown signal = no transition
}

module.exports = { NODES, SIGNALS, next };
