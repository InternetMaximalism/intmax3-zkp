'use strict';
// NORMAL branch: import confirmed L1 deposits into the channel (DESIGN.md §3.4) and refresh the
// close anchor on block finalization. The CLI reconciles the deposit against the on-chain
// depositHashChain and enforces nullifier-unused (fail-closed); this handler only orchestrates.

async function handleDepositImport(event, ctx) {
  const { cli, ch, store, log, alert } = ctx;
  // event.args carries the decoded Deposited fields once the watcher decodes them; for v1 we read
  // the depositor/amount from the recorded pending_deposit (relay/browser path) or the event args.
  const dep = event.args || readPending(cli, ch);
  if (!dep || dep.amount == null) {
    return log.warn({ event: 'DEPOSIT_NO_DATA', channel: ch.id, txHash: event.txHash });
  }
  // Defense-in-depth (review L1): these become positional CLI argv. Validate shapes and reject any
  // value that could be read as a flag (leading '-'), even though chain args are ABI-decoded/trusted.
  const slot = dep.recipientSlot != null ? Number(dep.recipientSlot) : 0;
  const amount = String(dep.amount);
  const depositor = String(dep.depositor);
  if (!Number.isInteger(slot) || slot < 0 || slot > 255 ||
      !/^[0-9]+$/.test(amount) || !/^0x[0-9a-fA-F]{40}$/.test(depositor)) {
    return alert.raise('warn', ch.id, 'DEPOSIT_BAD_ARGS', 'deposit args failed shape validation', { slot, amount, depositor });
  }
  const actionId = `deposit-import:${event.txHash || dep.txHash || ''}`;
  if (!store.claimAction(actionId)) return; // already imported
  try {
    await cli.run(ch.id, ch.workDir, [
      'cosign-l1-deposit-import', String(slot), amount, depositor, 'l1_import_cosigned.json',
    ]);
    const t = store.findTicket((x) => x.type === 'deposit' && x.status !== 'import_done');
    if (t) store.upsertTicket({ ...t, status: 'import_done' });
    store.completeAction(actionId, 'ok');
    log.info({ event: 'DEPOSIT_IMPORTED', channel: ch.id, actionId, slot });
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

module.exports = { handleDepositImport, refreshAnchors };
