'use strict';
// Pure event classifier for the delegate loop (DESIGN.md §4.2). Maps (event, account-context) to one
// branch. FAIL-CLOSED: once in exit mode the delegate stops normal sends and only pursues recovery;
// equivocation/close-against-us always routes to the exit branch regardless of prior state.

const BRANCHES = {
  // normal
  SNAPSHOT_UPDATED: 'SNAPSHOT_UPDATED',
  CHAIN_DEPOSITED: 'CHAIN_DEPOSITED',
  BALANCE_POLL: 'BALANCE_POLL',
  // own tx
  INTENT_SEND: 'INTENT_SEND',
  INTENT_INTER_SEND: 'INTENT_INTER_SEND',
  INTENT_BURN: 'INTENT_BURN',
  NEED_REFRESH: 'NEED_REFRESH',
  // abnormal
  COSIGN_INVALID: 'COSIGN_INVALID',
  COSIGNER_WITHHOLDING: 'COSIGNER_WITHHOLDING',
  CHAIN_CLOSE_SEEN: 'CHAIN_CLOSE_SEEN',
  CHAIN_FINALIZED: 'CHAIN_FINALIZED',
  CHAIN_CREDIT: 'CHAIN_CREDIT',
  EQUIVOCATION: 'EQUIVOCATION',
  IGNORE: 'IGNORE',
};

const INTENT_TO_BRANCH = {
  send: BRANCHES.INTENT_SEND,
  inter: BRANCHES.INTENT_INTER_SEND,
  burn: BRANCHES.INTENT_BURN,
  refresh: BRANCHES.NEED_REFRESH,
};

const CHAIN_TO_BRANCH = {
  Deposited: BRANCHES.CHAIN_DEPOSITED,
  CloseRequested: BRANCHES.CHAIN_CLOSE_SEEN,
  CloseSubmitted: BRANCHES.CHAIN_CLOSE_SEEN,
  SpecialCloseSubmitted: BRANCHES.CHAIN_CLOSE_SEEN,
  CloseFinalized: BRANCHES.CHAIN_FINALIZED,
  WithdrawalClaimed: BRANCHES.CHAIN_CREDIT,
  NativeWithdrawn: BRANCHES.CHAIN_CREDIT,
  WithdrawalCredited: BRANCHES.CHAIN_CREDIT,
  FraudConfirmed: BRANCHES.EQUIVOCATION,
};

// event: { source: 'api'|'chain'|'timer'|'signal', kind, ... }
// ctx: { mode: 'normal'|'exiting' }
function classify(event, ctx = {}) {
  const mode = ctx.mode || 'normal';
  if (!event || typeof event !== 'object' || !event.source) return BRANCHES.EQUIVOCATION; // fail-closed

  // Hard signals from within the loop (the own-tx flow raises these) — honored in any mode.
  if (event.source === 'signal') {
    switch (event.kind) {
      case 'cosign_invalid': return BRANCHES.COSIGN_INVALID;
      case 'withholding': return BRANCHES.COSIGNER_WITHHOLDING;
      case 'equivocation': return BRANCHES.EQUIVOCATION;
      default: return BRANCHES.EQUIVOCATION;
    }
  }

  if (event.source === 'chain') {
    const b = CHAIN_TO_BRANCH[event.kind];
    return b || BRANCHES.IGNORE; // benign/unrelated chain events are ignored by the delegate
  }

  // In exit mode the delegate refuses new outbound intents; only sync/poll/abnormal proceed.
  if (mode === 'exiting' && event.source === 'api') {
    if (event.kind === 'snapshot') return BRANCHES.SNAPSHOT_UPDATED;
    if (event.kind === 'balance') return BRANCHES.BALANCE_POLL;
    return BRANCHES.IGNORE; // drop send/inter/burn intents while exiting
  }

  if (event.source === 'api' || event.source === 'timer') {
    if (event.kind === 'snapshot') return BRANCHES.SNAPSHOT_UPDATED;
    if (event.kind === 'balance') return BRANCHES.BALANCE_POLL;
    const b = INTENT_TO_BRANCH[event.kind];
    return b || BRANCHES.IGNORE;
  }

  return BRANCHES.EQUIVOCATION;
}

module.exports = { classify, BRANCHES };
