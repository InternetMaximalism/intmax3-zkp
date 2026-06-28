'use strict';
// Delegate supervisory loop (DESIGN.md §4.2). classify(event) → branch handler, serialized per
// account. Own-tx branches raise in-loop 'signal' events (cosign_invalid / withholding /
// equivocation) which re-enter dispatch and route to exit mode (sticky).

const { classify, BRANCHES } = require('./classify');
const dsm = require('./state-machine');
const sync = require('./branches/sync');
const owntx = require('./branches/owntx');
const exitB = require('./branches/exit');

function makeSm(store) {
  return {
    node() { return store.get('smNode') || dsm.NODES.SYNCED; },
    signal(signal) {
      const to = dsm.next(this.node(), signal);
      if (to !== this.node()) store.setSmNode(to);
      return to;
    },
  };
}

function makeRuntime(account, deps) {
  const { api, wallet, store, log, alert, policyCfg } = deps;
  const smW = makeSm(store);
  const queue = [];
  let draining = false;

  const ctx = {
    ch: account, slot: account.slot, recipient: account.recipient,
    api, wallet, store, log, alert, policy: policyCfg, sm: smW,
    // Lets own-tx branches inject a hard signal that re-enters dispatch.
    raiseSignal: (sig) => { queue.push(sig); return { signalled: sig.kind }; },
  };

  async function dispatch(event) {
    const branch = classify(event, { mode: store.get('mode') });
    log.debug({ event: 'CLASSIFY', channel: account.id, source: event.source, kind: event.kind, branch });
    try {
      switch (branch) {
        case BRANCHES.SNAPSHOT_UPDATED: return await sync.importAndVerify(event, ctx);
        case BRANCHES.CHAIN_DEPOSITED: return await sync.awaitImportThenSync(event, ctx);
        case BRANCHES.BALANCE_POLL: return await sync.decryptAndReport(event, ctx);
        case BRANCHES.INTENT_SEND: return await owntx.doSend(event, ctx);
        case BRANCHES.INTENT_INTER_SEND: return await owntx.doInterChannelSend(event, ctx);
        case BRANCHES.INTENT_BURN: return await owntx.doBurn(event, ctx);
        case BRANCHES.NEED_REFRESH: return await owntx.doRefresh(event, ctx);
        case BRANCHES.COSIGN_INVALID: return await exitB.onCosignInvalid(event, ctx);
        case BRANCHES.COSIGNER_WITHHOLDING: return await exitB.onWithholding(event, ctx);
        case BRANCHES.CHAIN_CLOSE_SEEN: return await exitB.onCloseSeen(event, ctx);
        case BRANCHES.CHAIN_FINALIZED: return await exitB.onChannelFinalized(event, ctx);
        case BRANCHES.CHAIN_CREDIT: return await exitB.onCreditConfirmed(event, ctx);
        case BRANCHES.EQUIVOCATION: return await exitB.enterExitMode(event, ctx);
        case BRANCHES.IGNORE: return;
        default: return await exitB.enterExitMode(event, ctx);
      }
    } catch (e) {
      log.error({ event: 'BRANCH_ERROR', channel: account.id, branch, error: String(e && e.message || e) });
      // Chain-sourced errors rethrow so the watcher does not advance the cursor past the event.
      if (event.source === 'chain') throw e;
    }
  }

  // Process an event and any signals its branch raised (drain to fixpoint).
  async function submit(event) {
    queue.push(event);
    if (draining) return;
    draining = true;
    try {
      while (queue.length) {
        const ev = queue.shift();
        // eslint-disable-next-line no-await-in-loop
        await dispatch(ev);
      }
    } finally {
      draining = false;
    }
  }

  return { account, ctx, sm: smW, store, dispatch, submit };
}

module.exports = { makeRuntime };
