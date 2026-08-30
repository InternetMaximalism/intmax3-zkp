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
  const {
    api, wallet, store, log, alert, policyCfg, tokenRegistry,
    participantCloser = null,
    claimSettlement = null,
    snapshotVault = null,
    isChainReady = () => true,
  } = deps;
  const smW = makeSm(store);
  const queue = [];
  let draining = false;
  let activeGroup = null;

  const ctx = {
    ch: account, slot: account.slot, recipient: account.recipient,
    api, wallet, store, log, alert, policy: policyCfg, sm: smW, tokenRegistry,
    participantCloser,
    claimSettlement,
    snapshotVault,
    // Lets own-tx branches inject a hard signal that re-enters dispatch.
    raiseSignal: (sig) => {
      if (!activeGroup) throw new Error('delegate signal raised outside serialized dispatch');
      activeGroup.events.push(sig);
      return { signalled: sig.kind };
    },
  };

  async function dispatch(event) {
    const chainHalt = store.get('chainSafetyHalt');
    if (chainHalt) {
      // Never send, import, claim, or mark an exit complete from a chain view whose finalized
      // checkpoint changed. Read-only recovery is operator-driven after the forensic halt.
      const error = new Error(`chain safety halt: ${chainHalt.code}: ${chainHalt.message}`);
      error.code = chainHalt.code;
      throw error;
    }
    if (event.source !== 'chain' && !isChainReady()) {
      const error = new Error('finalized chain view is temporarily unavailable; action gated');
      error.code = 'CHAIN_TRANSIENT_UNAVAILABLE';
      throw error;
    }
    const branch = classify(event, { mode: store.get('mode') });
    log.debug({ event: 'CLASSIFY', channel: account.id, source: event.source, kind: event.kind, branch });
    // Multi-token DISPLAY metadata (§N-7): keep the held registry in step with the rollup's
    // set-once token registry. The delegate CLASSIFIES this event as IGNORE (it drives no
    // behaviour), so the observation is taken here, before the branch switch. Observational only:
    // no write path, never throws, and a contradiction against a verified entry withdraws that
    // entry's metadata (see common/token-registry.js).
    if (event.source === 'chain' && event.kind === 'TokenRegistered' && tokenRegistry) {
      tokenRegistry.observeTokenRegistered(
        { tokenIndex: Number(event.args && event.args.tokenIndex), token: event.args && event.args.token, rollupAddress: event.address },
        { logger: log }
      );
    }
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
        case BRANCHES.CHAIN_CLAIM_ACCEPTED: return await exitB.onClaimAccepted(event, ctx);
        case BRANCHES.CHAIN_FUNDS_PULLED: return await exitB.onFundsPulled(event, ctx);
        case BRANCHES.CHAIN_CREDIT: return await exitB.onCreditConfirmed(event, ctx);
        case BRANCHES.RECOVERY_TICK: return await exitB.onRecoveryTick(event, ctx);
        case BRANCHES.EQUIVOCATION: return await exitB.enterExitMode(event, ctx);
        case BRANCHES.IGNORE: return;
        default: return await exitB.enterExitMode(event, ctx);
      }
    } catch (e) {
      log.error({ event: 'BRANCH_ERROR', channel: account.id, branch, error: String(e && e.message || e) });
      // Every caller receives the handler verdict. In particular HTTP must not return success while
      // a queued funds action is still pending or has failed; chain errors also keep the cursor on
      // the failed block.
      throw e;
    }
  }

  async function drain() {
    if (draining) return;
    draining = true;
    try {
      while (queue.length) {
        const group = queue.shift();
        activeGroup = group;
        try {
          while (group.events.length) {
            const ev = group.events.shift();
            // eslint-disable-next-line no-await-in-loop
            group.result = await dispatch(ev);
          }
          group.resolve(group.result);
        } catch (error) {
          group.reject(error);
        } finally {
          activeGroup = null;
        }
      }
    } finally {
      draining = false;
      // A submit can arrive after the last `queue.length` check but before `draining = false`.
      if (queue.length) void drain();
    }
  }

  // Every submit owns a distinct Promise and settles only after its branch plus all signals raised
  // by that branch have drained to a fixpoint. No concurrent caller can observe a cursor/action
  // response merely because another submission happened to own the drain loop.
  function submit(event) {
    return new Promise((resolve, reject) => {
      queue.push({ events: [event], resolve, reject, result: undefined });
      void drain();
    });
  }

  return { account, ctx, sm: smW, store, dispatch, submit };
}

module.exports = { makeRuntime };
