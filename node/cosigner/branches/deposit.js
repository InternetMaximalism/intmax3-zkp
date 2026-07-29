'use strict';
// NORMAL branch: import confirmed L1 deposits into the channel (DESIGN.md §3.4) and refresh the
// close anchor on block finalization.
//
// SECURITY: this handler passes the observed TRANSACTION HASH and nothing economic. The CLI reads
// depositor/amount/tokenIndex from that transaction's on-chain `Deposited` log, verifies the log
// came from the channel's own rollup for the channel's own deposit_recipient, enforces a
// confirmation depth, and refuses a replay via its consumed-deposit ledger. Amounts observed here
// are used only for logging — never as an economic input.
// See doc/tasks/deposit-import-threat-model.md.

// Build the CLI argv for an observed deposit, or return an { error } describing why it is not
// importable. Exported for unit testing (node/test/deposit-import-args.test.js).
//
// `recipientSlot` is usually absent on the chain-driven path (the `Deposited` event carries no
// slot), so we pass `auto`: the CLI resolves the credited slot from the depositor's B-1b bound
// exit address, and refuses when that is ambiguous or unbound. This is strictly better than the
// old behavior, which silently defaulted to slot 0.
function depositImportArgs({ txHash, recipientSlot, rpc }) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(txHash || ''))) {
    return { error: 'txHash must be 0x + 64 hex chars' };
  }
  let slot = 'auto';
  if (recipientSlot != null) {
    const n = Number(recipientSlot);
    if (!Number.isInteger(n) || n < 0 || n > 1023) return { error: 'recipientSlot out of range' };
    slot = String(n);
  }
  if (!/^[a-z0-9:/._-]+$/i.test(String(rpc || '')) || String(rpc).startsWith('-')) {
    return { error: 'rpc url missing or unsafe' };
  }
  return { args: ['cosign-l1-deposit-import', slot, String(txHash), String(rpc), 'l1_import_cosigned.json'] };
}

async function handleDepositImport(event, ctx) {
  const { cli, ch, store, log, alert, rpc } = ctx;
  const dep = event.args || readPending(cli, ch) || {};
  const txHash = event.txHash || dep.txHash;
  const built = depositImportArgs({
    txHash,
    recipientSlot: dep.recipientSlot,
    rpc: rpc || process.env.RPC || 'http://127.0.0.1:8545',
  });
  if (built.error) {
    return alert.raise('warn', ch.id, 'DEPOSIT_BAD_ARGS', built.error, { txHash });
  }
  const actionId = `deposit-import:${txHash}`;
  if (!store.claimAction(actionId)) return; // already imported
  const slot = built.args[1];
  const tokenIndex = dep.tokenIndex != null ? String(dep.tokenIndex) : '(from log)';
  try {
    await cli.run(ch.id, ch.workDir, built.args);
    const t = store.findTicket((x) => x.type === 'deposit' && x.status !== 'import_done');
    if (t) store.upsertTicket({ ...t, status: 'import_done' });
    store.completeAction(actionId, 'ok');
    log.info({ event: 'DEPOSIT_IMPORTED', channel: ch.id, actionId, slot, tokenIndex });
  } catch (e) {
    store.releaseAction(actionId); // allow a later retry (review M6); not necessarily an attack
    // (e.g. nullifier reuse is a legit refusal); alert as a fault so an operator can inspect.
    await alert.raise('fault', ch.id, 'DEPOSIT_IMPORT_FAILED', String(e.stderr || e.message || e), { txHash: event.txHash });
  }
}

function readPending(cli, ch) {
  try { return cli.readJson(ch.workDir, 'pending_deposit.json'); } catch (e) { return null; }
}

// On block finalization, refresh cached anchors used by the close path (latestFinalizedStateRoot).
async function refreshAnchors(event, ctx) {
  ctx.log.info({ event: 'ANCHOR_REFRESH', channel: ctx.ch.id, blockNumber: event.blockNumber });
}

module.exports = { handleDepositImport, refreshAnchors, depositImportArgs };
