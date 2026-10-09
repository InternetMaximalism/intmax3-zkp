'use strict';
// Settles a partial withdrawal on L1, from the burn to the recipient's payout.
//
// A burn is an inter-channel send to the reserved burn channel. It is paid on L1 by the base
// withdrawal proof alone, as an inter-channel transfer is consumed by a receive proof: the
// validity circuit already binds every member's signature to the block that carries the burn.
// Nothing holds the channel; it keeps advancing after the burn. The rollup pays only against a
// FINALIZED validity root, so the payout proof is anchored at the head a validity candidate ends
// at. The phases, recorded in the partial_withdrawal ticket as `steps.settle.phase`:
//
//   proving     the producer daemon builds the payout proof, anchored at the head a validity
//               candidate ends at (proving that candidate in the same command when none is
//               pending); an older candidate still being published is published first
//   publishing  that candidate is posted and finalized on the rollup (api/lib/wallet-l1.js)
//   paying      the rollup credits the payout on the withdrawal proof (pw-finalize)
//
// after which the ticket is claim_pending (the recipient pulls the credit with its own wallet,
// /api/pw-claim-confirm) or settle_done (the operator's own address was paid directly). On a
// public chain every L1 transaction waits for the RPC's finalized head (minutes), so the relay
// drives the phases in the background and the wallet follows the ticket; on the devnet the same
// phases run inside the wallet's Step 2 request (/api/pw-finalize).

// The CLI stops, journal intact, while its transaction is not yet covered by the RPC's finalized
// head (minutes on a public chain): a wait to retry, not a failure.
const AWAITING_FINALITY = /not finalized yet|retry after the finalized head advances|durable L1 head advanced|retry against one stable finalized block|payout anchor is not L1-finalized/;
// The daemon refuses to anchor a payout while an older validity candidate awaits L1: publish it.
const CANDIDATE_PENDING = /validity candidate pending L1 acknowledgement/;
// ...or for the seconds a co-signed head is staged and not yet committed: retry a poll later.
const HEAD_STAGED = /staged producer block/;
const RESUMABLE = new Set(['burn_done', 'settle_pending']);
const PHASES = new Set(['proving', 'publishing', 'paying']);

function createPwSettlement({
  cli, walletL1, live, pull, withLock, findActiveTicket, upsertTicket,
  enabled = () => true, background = () => true, log = console,
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  retryMs = 5 * 60 * 1000, pollMs = 60 * 1000,
}) {
  const running = new Map();
  const devnet = () => cli.chainId() === cli.DEVNET_CHAIN_ID;
  const detailOf = e => String((e && (e.stderr || e.message)) || e);

  function record(ch, ticket, patch) {
    ticket.steps = ticket.steps || {};
    ticket.steps.settle = { ...(ticket.steps.settle || {}), ...patch };
    return upsertTicket(ch, ticket);
  }

  // The saved payout proof of this burn (never one left by an earlier burn), or null.
  const savedArtifacts = ch => live.savedPayoutArtifacts(ch);

  // Phase `publishing` is done once the payout anchor's root is finalized on the rollup.
  function anchorFinalized(ch, artifacts) {
    const root = artifacts.producerAnchor.extendedStateCommitment;
    return cli.sh('cast', ['call', cli.rollupOf(ch), 'isFinalizedStateRoot(bytes32)(bool)', root,
      '--rpc-url', cli.RPC]).trim() === 'true';
  }

  // Phase `paying`. Caller holds the channel lock. Ends the ticket in claim_pending or settle_done.
  async function pay(ch, ticket) {
    await live.finalizeSavedPayout(ch, {
      rpc: cli.RPC, run: cli.cliAsync, env: devnet() ? { INTMAX_WALLET_ANVIL_MINE: '1' } : {},
    });
    const w = savedArtifacts(ch).withdrawal;
    let claim = ticket.params.claim || null;
    if (!claim && cli.l1SignerAddress().toLowerCase() !== String(w.recipient).toLowerCase()) {
      claim = pull.pullTransaction({ withdrawal_amount: String(w.amount), withdrawal_token_index: w.tokenIndex,
        withdrawal_recipient: w.recipient }, cli.rollupOf(ch));
      claim.afterBlock = cli.sh('cast', ['rpc', 'eth_blockNumber', '--rpc-url', cli.RPC]).trim().replace(/"/g, '');
    }
    ticket.status = claim ? 'claim_pending' : 'settle_done';
    ticket.params.claim = claim;
    ticket.steps.settle = { ...(ticket.steps.settle || {}), phase: 'done', completedAt: Date.now(),
      nullifier: w.nullifier, error: null, waiting: null };
    upsertTicket(ch, ticket);
    return { nullifier: w.nullifier, claim };
  }

  // Runs the ticket's phases until it ends (or, with `once`, until a failure is recorded).
  async function drive(ch, { once = false } = {}) {
    let candidatePending = false;
    for (;;) {
      const ticket = findActiveTicket(ch, 'partial_withdrawal');
      if (!ticket || !RESUMABLE.has(ticket.status)) return ticket || null;
      const settle = (ticket.steps && ticket.steps.settle) || {};
      // A ticket recorded by an earlier settlement flow restarts from the payout proof.
      let phase = PHASES.has(settle.phase) ? settle.phase : 'proving';
      if (phase !== 'proving' && !savedArtifacts(ch)) phase = 'proving';
      try {
        if (phase === 'proving') {
          ticket.status = 'settle_pending';
          record(ch, ticket, { phase: 'proving', startedAt: settle.startedAt || Date.now(), error: null });
          try {
            await withLock(ch, () => live.stagePayoutArtifacts(ch));
          } catch (e) {
            if (!CANDIDATE_PENDING.test(detailOf(e))) throw e;
            record(ch, ticket, { waiting: 'an earlier validity batch on L1', error: null });
            // Publishing it is minutes of L1 finality; a candidate still pending right after a
            // publish is waited for, never polled in a tight loop.
            if (candidatePending) await sleep(pollMs);
            candidatePending = true;
            await walletL1.publish(ch, { prove: false });
            continue;
          }
          candidatePending = false;
          record(ch, ticket, { phase: 'publishing', error: null, waiting: null });
        } else if (phase === 'publishing') {
          await walletL1.publish(ch, { prove: false });
          if (!anchorFinalized(ch, savedArtifacts(ch))) {
            record(ch, ticket, { waiting: 'L1 finality', error: null });
            await sleep(pollMs);
            continue;
          }
          record(ch, ticket, { phase: 'paying', error: null, waiting: null });
        } else {
          await withLock(ch, () => pay(ch, ticket));
          return ticket;
        }
      } catch (e) {
        const detail = detailOf(e);
        if (AWAITING_FINALITY.test(detail) || HEAD_STAGED.test(detail)) {
          record(ch, ticket, { waiting: HEAD_STAGED.test(detail) ? 'the channel head to commit' : 'L1 finality', error: null });
          await sleep(pollMs);
          continue;
        }
        const message = detail.trim().split('\n').slice(-3).join(' ').slice(0, 600);
        log.error(`[pw-settlement] channel ${ch} ${phase}: ${message}`);
        record(ch, ticket, { error: message, waiting: null, failedAt: Date.now(), attempts: (settle.attempts || 0) + 1 });
        if (once) throw e;
        await sleep(retryMs);
      }
    }
  }

  // Background settlement of the channel's partial withdrawal (public chain), idempotent.
  function start(ch) {
    if (!enabled() || !background()) return null;
    if (running.has(ch)) return running.get(ch);
    const run = drive(ch).catch(e => log.error(`[pw-settlement] channel ${ch}: ${(e && e.message) || e}`))
      .finally(() => running.delete(ch));
    running.set(ch, run);
    return run;
  }

  // Devnet: the wallet's Step 2 request settles in place and reports the first failure. A second
  // request while one runs joins it rather than paying twice.
  function settleNow(ch) {
    if (running.has(ch)) return running.get(ch);
    const run = drive(ch, { once: true }).finally(() => running.delete(ch));
    running.set(ch, run);
    return run;
  }

  function resumeAll(channels) {
    for (const ch of channels) {
      const ticket = findActiveTicket(ch, 'partial_withdrawal');
      if (ticket && RESUMABLE.has(ticket.status)) start(ch);
    }
  }

  return { start, settleNow, resumeAll, running: ch => running.has(ch) };
}

module.exports = { createPwSettlement };
