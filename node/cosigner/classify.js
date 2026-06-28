'use strict';
// Pure event classifier for the co-signer loop (DESIGN.md §3.2). Maps (event, channel-context) to
// exactly one branch label. FAIL-CLOSED: ambiguous/unknown inputs route to ATTACK_SUSPECTED, and
// peer requests are refused (INVALID_REQUEST) whenever the channel is not Active or the loop is in
// defensive mode. This function performs NO I/O so it is exhaustively unit-testable.

const BRANCHES = {
  // normal
  PEER_TX_REQUEST: 'PEER_TX_REQUEST',
  PEER_REFRESH_REQUEST: 'PEER_REFRESH_REQUEST',
  PEER_INTER_REQUEST: 'PEER_INTER_REQUEST',
  PEER_BURN_REQUEST: 'PEER_BURN_REQUEST',
  CHAIN_DEPOSITED: 'CHAIN_DEPOSITED',
  CHAIN_BLOCK_FINALIZED: 'CHAIN_BLOCK_FINALIZED',
  CHAIN_OBSERVE: 'CHAIN_OBSERVE',
  SNAPSHOT_POLL: 'SNAPSHOT_POLL',
  // own actions
  TIMER_SETTLE_DUE: 'TIMER_SETTLE_DUE',
  TIMER_PW_FINALIZE_DUE: 'TIMER_PW_FINALIZE_DUE',
  // abnormal
  INVALID_REQUEST: 'INVALID_REQUEST',
  CHAIN_CLOSE_REQUESTED: 'CHAIN_CLOSE_REQUESTED',
  CHAIN_CLOSE_SUBMITTED: 'CHAIN_CLOSE_SUBMITTED',
  CHAIN_PW_SUBMITTED: 'CHAIN_PW_SUBMITTED',
  ATTACK_SUSPECTED: 'ATTACK_SUSPECTED',
};

const API_KIND_TO_BRANCH = {
  cosign: BRANCHES.PEER_TX_REQUEST,
  'cosign-refresh': BRANCHES.PEER_REFRESH_REQUEST,
  inter: BRANCHES.PEER_INTER_REQUEST,
  burn: BRANCHES.PEER_BURN_REQUEST,
  snapshot: BRANCHES.SNAPSHOT_POLL,
};

const COSIGN_FAMILY = new Set([
  BRANCHES.PEER_TX_REQUEST,
  BRANCHES.PEER_REFRESH_REQUEST,
  BRANCHES.PEER_INTER_REQUEST,
  BRANCHES.PEER_BURN_REQUEST,
]);

const TIMER_KIND_TO_BRANCH = {
  settle_due: BRANCHES.TIMER_SETTLE_DUE,
  pw_finalize_due: BRANCHES.TIMER_PW_FINALIZE_DUE,
};

const CHAIN_KIND_TO_BRANCH = {
  Deposited: BRANCHES.CHAIN_DEPOSITED,
  Finalized: BRANCHES.CHAIN_BLOCK_FINALIZED,
  CloseRequested: BRANCHES.CHAIN_CLOSE_REQUESTED,
  CloseSubmitted: BRANCHES.CHAIN_CLOSE_SUBMITTED,
  SpecialCloseSubmitted: BRANCHES.CHAIN_CLOSE_SUBMITTED,
  PartialWithdrawalSubmitted: BRANCHES.CHAIN_PW_SUBMITTED,
  FraudConfirmed: BRANCHES.ATTACK_SUSPECTED,
  // benign / informational — observed for reconciliation, no defensive action by themselves
  BlockPosted: BRANCHES.CHAIN_OBSERVE,
  ChannelRegistered: BRANCHES.CHAIN_OBSERVE,
  Submitted: BRANCHES.CHAIN_OBSERVE,
  WithdrawalCredited: BRANCHES.CHAIN_OBSERVE,
  PartialWithdrawalAuthorized: BRANCHES.CHAIN_OBSERVE,
  NativeWithdrawn: BRANCHES.CHAIN_OBSERVE,
  CloseCancelled: BRANCHES.CHAIN_OBSERVE,
  CloseFinalized: BRANCHES.CHAIN_OBSERVE,
  WithdrawalClaimAccepted: BRANCHES.CHAIN_OBSERVE,
  PostCloseClaimAccepted: BRANCHES.CHAIN_OBSERVE,
  WithdrawalClaimed: BRANCHES.CHAIN_OBSERVE,
  PartialWithdrawalFinalized: BRANCHES.CHAIN_OBSERVE,
  PartialWithdrawalCancelled: BRANCHES.CHAIN_OBSERVE,
};

// event: { source: 'api'|'chain'|'timer', kind, invalid? }
// ctx: { status: 'active'|'close_pending'|'close_submitted'|'closed'|'settled', mode: 'normal'|'defensive'|'exiting' }
function classify(event, ctx = {}) {
  const status = ctx.status || 'active';
  const mode = ctx.mode || 'normal';

  if (!event || typeof event !== 'object' || !event.source) return BRANCHES.ATTACK_SUSPECTED;

  if (event.source === 'timer') {
    return TIMER_KIND_TO_BRANCH[event.kind] || BRANCHES.ATTACK_SUSPECTED;
  }

  if (event.source === 'api') {
    const branch = API_KIND_TO_BRANCH[event.kind];
    if (!branch) return BRANCHES.ATTACK_SUSPECTED; // unknown API kind = suspicious
    if (branch === BRANCHES.SNAPSHOT_POLL) return branch; // read-only, always allowed
    // explicit invalidity flag (failed pre-policy upstream)
    if (event.invalid) return BRANCHES.INVALID_REQUEST;
    // defensive mode refuses all co-signing for this channel
    if (mode === 'defensive') return BRANCHES.INVALID_REQUEST;
    // cannot co-sign a channel that is not Active
    if (COSIGN_FAMILY.has(branch) && status !== 'active') return BRANCHES.INVALID_REQUEST;
    return branch;
  }

  if (event.source === 'chain') {
    // The watcher only emits events from OUR contracts (decoded by their ABI), so an unmapped kind
    // is a benign/new contract event, NOT an attack — observe it (review M2: do not freeze the
    // channel on an unrecognized-but-legitimate event). Only non-chain malformed input is attack.
    return CHAIN_KIND_TO_BRANCH[event.kind] || BRANCHES.CHAIN_OBSERVE;
  }

  return BRANCHES.ATTACK_SUSPECTED;
}

module.exports = { classify, BRANCHES };
