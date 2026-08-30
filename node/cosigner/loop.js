'use strict';
// Co-signer supervisory loop (DESIGN.md §3.2). Builds a per-channel runtime and a single dispatch
// function: classify(event) → branch handler, serialized per channel. Pure routing; the branches do
// the work. Unknown/ambiguous events fail closed to the defensive branch.

const { classify, BRANCHES } = require('./classify');
const sm = require('./state-machine');
const cosignB = require('./branches/cosign');
const depositB = require('./branches/deposit');
const closeB = require('./branches/close');
const abnormalB = require('./branches/abnormal');

const NODE_TO_STATUS = {
  ACTIVE: 'active', CLOSE_PENDING: 'close_pending', CLOSE_SUBMITTED: 'close_submitted',
  CHALLENGE_WINDOW: 'close_submitted', CLOSED: 'closed', SETTLED: 'settled', DEFENSIVE: 'active',
};

function makeSm(store) {
  return {
    node() { return store.get('smNode') || sm.NODES.ACTIVE; },
    status() { return NODE_TO_STATUS[this.node()] || 'active'; },
    signal(signal) {
      const to = sm.next(this.node(), signal);
      if (to !== this.node()) store.setSmNode(to);
      return to;
    },
  };
}

function makeRuntime(ch, deps) {
  const {
    cli,
    api,
    store,
    log,
    alert,
    rpc,
    policyCfg,
    getPendingClose,
    tokenRegistry,
    isChainReady = () => true,
  } = deps;
  const smW = makeSm(store);
  const ctx = { ch, cli, api, store, log, alert, rpc, policy: policyCfg, sm: smW, getPendingClose, tokenRegistry };

  async function dispatch(event) {
    const chainHalt = store.get('chainSafetyHalt');
    if (chainHalt) {
      // A changed finalized checkpoint means neither the cached lifecycle nor any chain-derived
      // action is authoritative. Keep the process observable, but never sign, settle, import, or
      // serve a snapshot that another wallet could mistake for a current head.
      if (event && event.source === 'api') {
        return {
          ok: false,
          status: 503,
          body: { error: 'chain safety halt; operator reconciliation required', code: chainHalt.code },
        };
      }
      const error = new Error(`chain safety halt: ${chainHalt.code}: ${chainHalt.message}`);
      error.code = chainHalt.code;
      throw error;
    }
    if (event && (event.source === 'api' || event.source === 'timer') && !isChainReady()) {
      // A transient RPC/getLogs failure is not forensic evidence of a reorg, so it is not written
      // as a sticky halt. It is still unsafe to sign or drive a deadline action while the process
      // cannot prove that its finalized cursor is current. Chain-sourced dispatch remains allowed
      // because it is how the in-progress authenticated scan reaches readiness.
      if (event.source === 'api') {
        return {
          ok: false,
          status: 503,
          body: { error: 'finalized chain view unavailable; retry later', code: 'CHAIN_UNAVAILABLE' },
        };
      }
      const error = new Error('finalized chain view unavailable; timer action inhibited');
      error.code = 'CHAIN_UNAVAILABLE';
      throw error;
    }
    const branch = classify(event, {
      status: smW.status(),
      mode: store.get('mode'),
      closeFinalized: store.get('closeFinalizedObserved') === true,
    });
    log.debug({ event: 'CLASSIFY', channel: ch.id, source: event.source, kind: event.kind, branch });
    try {
      switch (branch) {
        case BRANCHES.PEER_TX_REQUEST: return await cosignB.handleCosign(event, ctx);
        case BRANCHES.PEER_REFRESH_REQUEST: return await cosignB.handleCosignRefresh(event, ctx);
        case BRANCHES.PEER_INTER_REQUEST: return await cosignB.handleInterChannel(event, ctx);
        case BRANCHES.PEER_BURN_REQUEST: return await cosignB.handleCosignBurn(event, ctx);
        case BRANCHES.PEER_CLOSE_CLAIM: return await closeB.proxyCloseClaim(event, ctx);
        case BRANCHES.SNAPSHOT_POLL: return await cosignB.publishSnapshot(event, ctx);
        case BRANCHES.CHAIN_DEPOSITED: return await depositB.handleDepositImport(event, ctx);
        case BRANCHES.CHAIN_BLOCK_FINALIZED: return await depositB.refreshAnchors(event, ctx);
        // Multi-token (§N): surface the decoded tokenIndex on observed events that carry one
        // (WithdrawalClaimAccepted / WithdrawalClaimed / ChannelFundsPulled / TokenRegistered /
        // Erc20Withdrawn / TokenWithdrawalClaimed), so operator reconciliation sees WHICH asset.
        case BRANCHES.CHAIN_OBSERVE: {
          log.info({ event: 'CHAIN_OBSERVE', channel: ch.id, kind: event.kind, tokenIndex: event.args && event.args.tokenIndex != null ? String(event.args.tokenIndex) : undefined, txHash: event.txHash });
          // `TokenRegistered` is the on-chain half of the DISPLAY-metadata contract: it tells the
          // held registry that a base index just became authoritative (or that our manifest is
          // wrong about it). OBSERVATIONAL ONLY — no write path, no new entries, and it never
          // throws (a throw here would wedge the watcher cursor). A contradiction against a
          // VERIFIED entry is logged at error level and withdraws that entry's metadata.
          if (event.kind === 'TokenRegistered' && tokenRegistry) {
            tokenRegistry.observeTokenRegistered(
              { tokenIndex: Number(event.args && event.args.tokenIndex), token: event.args && event.args.token, rollupAddress: event.address },
              { logger: log }
            );
          }
          return;
        }
        case BRANCHES.TIMER_SETTLE_DUE: return await closeB.driveCloseStep(event, ctx);
        case BRANCHES.TIMER_PW_FINALIZE_DUE: return await closeB.drivePwFinalize(event, ctx);
        case BRANCHES.INVALID_REQUEST: return await abnormalB.rejectAndScore({ ...event, reason: event.reason || 'classified invalid' }, ctx);
        case BRANCHES.CHAIN_CLOSE_REQUESTED: return await closeB.onCloseObserved(event, ctx);
        case BRANCHES.CHAIN_CLOSE_SUBMITTED: return await closeB.onCloseIntentObserved(event, ctx);
        case BRANCHES.CHAIN_CLOSE_CANCELLED: return await closeB.onCloseCancelled(event, ctx);
        case BRANCHES.CHAIN_CLOSE_FINALIZED: return await closeB.onCloseFinalized(event, ctx);
        case BRANCHES.CHAIN_PW_SUBMITTED: return await closeB.onPartialWithdrawalObserved(event, ctx);
        case BRANCHES.ATTACK_SUSPECTED:
        default:
          return await abnormalB.enterDefensiveMode(event, ctx);
      }
    } catch (e) {
      log.error({ event: 'BRANCH_ERROR', channel: ch.id, branch, error: String(e && e.message || e) });
      // api errors are answered to the caller; chain/timer errors are RETHROWN so the watcher does
      // NOT advance the cursor past an unprocessed event (no silent event loss — review H3).
      if (event.source === 'api') return { ok: false, status: 500, body: { error: 'internal error' } };
      throw e;
    }
  }

  return { ch, ctx, sm: smW, store, dispatch };
}

// Per-channel serialization (matches the relay's per-channel mutex).
function makeLock() {
  let chain = Promise.resolve();
  return function withLock(fn) {
    const next = chain.then(fn, fn);
    chain = next.catch(() => {});
    return next;
  };
}

module.exports = { makeRuntime, makeLock, NODE_TO_STATUS };
