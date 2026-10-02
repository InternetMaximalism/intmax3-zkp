'use strict';
// Settles a partial withdrawal on L1, from the burn to the recipient's payout.
//
// On the devnet every L1 step completes in seconds inside the /api/pw-submit and /api/pw-finalize
// requests (the wallet's Step 2). On a public chain the same steps take from minutes (each L1
// transaction waits for the RPC's finalized head) to a day (the manager's challenge period), so
// the relay drives them in the background and the wallet follows the ticket. The phases, recorded
// in the partial_withdrawal ticket as `steps.settle.phase`:
//
//   publishing  the producer's validity history up to its head (which includes the burn block) is
//               posted and finalized on the rollup (api/lib/wallet-l1.js publish)
//   submitting  the post-burn head's backing is attested and the withdrawal intent is submitted to
//               the channel's manager with a close proof of that head (pw-submit)
//   challenge   the manager's challenge period runs until `deadline` (L1 block time)
//   finalizing  the manager authorizes the burn and the payout is credited on the rollup
//
// after which the ticket is claim_pending (the recipient pulls the credit with its own wallet,
// /api/pw-claim-confirm) or settle_done (the operator's own address was paid directly).
//
// A burn can only be submitted with ITS post-burn signed state, and that state's backing can be
// proven only while it is the channel head: any other transition of the channel before the intent
// is submitted would strand the burned funds. `frozen(ch)` therefore holds the channel from the
// burn until the intent is on L1; the relay refuses every other channel operation meanwhile.

const PRE_SUBMIT = new Set(['publishing', 'submitting']);
// The CLI stops, journal intact, while its transaction is not yet covered by the RPC's finalized
// head (minutes on a public chain): a wait to retry, not a failure.
const AWAITING_FINALITY = /not finalized yet|retry after the finalized head advances|durable L1 head advanced|retry against one stable finalized block/;
const RESUMABLE = new Set(['burn_done', 'settle_pending']);

function createPwSettlement({
  cli, producer, walletL1, live, pull, withLock, findActiveTicket, upsertTicket,
  enabled = () => true, background = () => true, log = console,
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  retryMs = 5 * 60 * 1000, pollMs = 60 * 1000,
}) {
  const running = new Map();
  const devnet = () => cli.chainId() === cli.DEVNET_CHAIN_ID;

  // The ticket whose burn owns the channel head, or null.
  function frozen(ch) {
    if (!enabled()) return null;
    const ticket = findActiveTicket(ch, 'partial_withdrawal');
    if (!ticket) return null;
    if (ticket.status === 'burn_done') return ticket;
    const settle = ticket.steps && ticket.steps.settle;
    if (ticket.status === 'settle_pending' && (!settle || !settle.phase || PRE_SUBMIT.has(settle.phase))) return ticket;
    return null;
  }

  function record(ch, ticket, patch) {
    ticket.steps = ticket.steps || {};
    ticket.steps.settle = { ...(ticket.steps.settle || {}), ...patch };
    return upsertTicket(ch, ticket);
  }

  // Phase `publishing`: validity history through the producer head, finalized on L1.
  async function publish(ch) {
    await walletL1.publish(ch);
  }

  // Phase `submitting`. Caller holds the channel lock. Returns the manager's challenge deadline.
  async function submit(ch, ticket) {
    const submitted = live.resumeSubmittedAuth(ch);
    if (!submitted) {
      const recipient = ticket.params && ticket.params.recipient;
      const proofEnv = await live.stageSubmitProof(ch);
      await walletL1.attest(ch, await producer.liveBackingArtifact(ch));
      await cli.cliAsync(ch, ['pw-submit', cli.RPC], {
        ...(recipient ? { PW_RECIPIENT: recipient } : {}), ...proofEnv,
        ...(devnet() ? { INTMAX_WALLET_ANVIL_MINE: '1' } : {}),
      });
    }
    const auth = cli.readJson(cli.wc(ch, 'pw_auth.json'));
    const raw = cli.sh('cast', ['call', auth.manager, 'pendingPartialWithdrawalDeadline()(uint64)',
      '--rpc-url', cli.RPC]).trim().split(/\s+/)[0];
    return { authDigest: auth.auth_digest, deadline: Number(raw) };
  }

  // Phase `finalizing`. Caller holds the channel lock. Ends the ticket in claim_pending or
  // settle_done.
  async function finalize(ch, ticket) {
    await live.stagePayoutArtifacts(ch);
    await live.finalizeSavedPayout(ch, {
      rpc: cli.RPC, run: cli.cliAsync, env: devnet() ? { INTMAX_WALLET_ANVIL_MINE: '1' } : {},
    });
    const auth = cli.readJson(cli.wc(ch, 'pw_auth.json'));
    let claim = ticket.params.claim || null;
    if (!claim && cli.l1SignerAddress().toLowerCase() !== auth.withdrawal_recipient.toLowerCase()) {
      claim = pull.pullTransaction(auth, cli.rollupOf(ch));
      claim.afterBlock = cli.sh('cast', ['rpc', 'eth_blockNumber', '--rpc-url', cli.RPC]).trim().replace(/"/g, '');
    }
    ticket.status = claim ? 'claim_pending' : 'settle_done';
    ticket.params.claim = claim;
    ticket.steps.settle = { ...(ticket.steps.settle || {}), phase: 'done', completedAt: Date.now(), authDigest: auth.auth_digest,
      error: null, waiting: null };
    upsertTicket(ch, ticket);
    return { authDigest: auth.auth_digest, claim };
  }

  function latestTimestamp() {
    return Number(cli.sh('cast', ['block', 'latest', '-f', 'timestamp', '--rpc-url', cli.RPC]).trim());
  }

  // One pass of the background driver: runs phases until the ticket needs time (challenge) or ends.
  async function drive(ch) {
    for (;;) {
      const ticket = findActiveTicket(ch, 'partial_withdrawal');
      if (!ticket || !RESUMABLE.has(ticket.status)) return;
      const settle = (ticket.steps && ticket.steps.settle) || {};
      const phase = ticket.status === 'burn_done' || !settle.phase ? 'publishing' : settle.phase;
      try {
        if (phase === 'publishing') {
          ticket.status = 'settle_pending';
          record(ch, ticket, { phase: 'publishing', startedAt: settle.startedAt || Date.now(), error: null });
          await publish(ch);
          record(ch, ticket, { phase: 'submitting', error: null, waiting: null });
        } else if (phase === 'submitting') {
          const out = await withLock(ch, () => submit(ch, ticket), { owner: ticket.id });
          record(ch, ticket, { phase: 'challenge', deadline: out.deadline, authDigest: out.authDigest, error: null, waiting: null });
        } else if (phase === 'challenge') {
          const now = latestTimestamp();
          if (!(now > Number(settle.deadline))) {
            await sleep(Math.min(pollMs, Math.max(1000, (Number(settle.deadline) - now + 1) * 1000)));
            continue;
          }
          record(ch, ticket, { phase: 'finalizing', error: null, waiting: null });
        } else if (phase === 'finalizing') {
          await withLock(ch, () => finalize(ch, ticket), { owner: ticket.id });
          return;
        } else {
          return;
        }
      } catch (e) {
        const detail = String((e && (e.stderr || e.message)) || e);
        if (AWAITING_FINALITY.test(detail)) {
          record(ch, ticket, { waiting: 'L1 finality', error: null });
          await sleep(pollMs);
          continue;
        }
        const message = detail.trim().split('\n').slice(-3).join(' ').slice(0, 600);
        log.error(`[pw-settlement] channel ${ch} ${phase}: ${message}`);
        record(ch, ticket, { error: message, waiting: null, failedAt: Date.now(), attempts: (settle.attempts || 0) + 1 });
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

  function resumeAll(channels) {
    for (const ch of channels) {
      const ticket = findActiveTicket(ch, 'partial_withdrawal');
      if (ticket && RESUMABLE.has(ticket.status)) start(ch);
    }
  }

  return { frozen, start, resumeAll, publish, submit, finalize, running: ch => running.has(ch) };
}

module.exports = { createPwSettlement };
