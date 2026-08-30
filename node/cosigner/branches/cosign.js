'use strict';
// NORMAL branch: validate peers' txs and co-sign (DESIGN.md §3.3). The CLI is the real fail-closed
// gate (re-verifies E-1/E-2 STARK + transition + replay ledgers + N-of-N). These handlers add
// policy, idempotency, post-checks, and snapshot publication. They NEVER sign anything themselves.

const { BRANCHES } = require('../classify');
const crypto = require('crypto');
const wire = require('../../common/wire');

// Content-addressed action id: a stable hash over the mandatory bytes32 wire binding. NEVER a
// length or an arbitrary-payload fallback (review H2: either would collapse unrelated actions or
// hide a Rust/JS schema mismatch). Returns null unless the binding is exact.
function actionIdFrom(prefix, bindingField) {
  const basis = wire.bytes32(bindingField);
  if (!basis) return null;
  return prefix + ':' + crypto.createHash('sha256').update(basis).digest('hex').slice(0, 32);
}

// Never let two requests share the CLI's input/output paths. The durable action id is already
// bound to the signed digest/tx hash, so its fixed-size hex suffix is a safe filename component
// and makes crash reconciliation unambiguous without accepting request-controlled paths.
function actionFile(actionId, label) {
  const tag = String(actionId || '').split(':').pop();
  if (!/^[0-9a-f]{32}$/.test(tag) || !/^[a-z0-9_-]+$/.test(label)) {
    throw new Error('invalid action-scoped artifact name');
  }
  return `${label}-${tag}.json`;
}

// Each handler returns { ok, status, body } so the loop can answer the HTTP caller.

async function handleCosign(event, ctx) {
  return cosignFamily(event, ctx, {
    payloadFile: 'payload.json',
    outFile: 'cosigned.json',
    cliArgs: (p, o) => ['cosign', p, o],
    label: 'cosign',
  });
}

async function handleCosignRefresh(event, ctx) {
  return cosignFamily(event, ctx, {
    payloadFile: 'refresh_payload.json',
    outFile: 'refresh_cosigned.json',
    cliArgs: (p, o) => ['cosign-refresh', p, o],
    label: 'cosign-refresh',
  });
}

async function handleInterChannel(event, ctx) {
  const { cli, api, ch, store, log } = ctx;
  const body = event.body || {};
  const debit = body.debitPayload;
  const descriptor = body.transferDescriptor;
  if (!debit || !descriptor) return { ok: false, status: 400, body: { error: 'needs { debitPayload, transferDescriptor }' } };
  let txHash;
  try { txHash = wire.descriptorTxHash(descriptor); }
  catch (e) { return { ok: false, status: 400, body: { error: e.message } }; }
  const actionId = actionIdFrom('inter', txHash);
  if (!actionId) return { ok: false, status: 400, body: { error: 'transferDescriptor.txHash must be 0x + 64 hex chars' } };
  if (!store.claimAction(actionId)) return { ok: true, status: 200, body: { dedup: true } };
  let reservedNonce = null;
  let invocationStarted = false;
  try {
    const debitFile = actionFile(actionId, 'inter-debit-payload');
    const descriptorFile = actionFile(actionId, 'inter-descriptor');
    const outFile = actionFile(actionId, 'inter-transfer');
    cli.writeJson(ch.workDir, debitFile, debit);
    cli.writeJson(ch.workDir, descriptorFile, descriptor);
    const interEnv = await liveBaseNonceEnv(api, ch, log);
    reservedNonce = Number(interEnv.INTMAX_LIVE_BASE_NONCE);
    if (!store.reserveOutgoingBaseNonce(reservedNonce, actionId)) {
      store.releaseAction(actionId);
      return { ok: false, status: 409, body: { error: `base nonce ${reservedNonce} is already reserved by another outgoing request` } };
    }
    // Once the child is launched, a timeout/kill/ENOSPC is ambiguous: channel_member can durably
    // commit the signed state before writing its final output/exit status. Never interpret an
    // unknown child outcome as proof that no signature exists.
    invocationStarted = true;
    await cli.run(ch.id, ch.workDir, ['cosign-inter-transfer', debitFile, descriptorFile, outFile], interEnv);
    const result = cli.readJson(ch.workDir, outFile);
    store.completeAction(actionId, 'ok');
    log.info({ event: 'COSIGN_OK', branch: BRANCHES.PEER_INTER_REQUEST, channel: ch.id, actionId });
    return { ok: true, status: 200, body: { sourceHead: result.aHead || result, destSnapshot: result.bSnapshot || null } };
  } catch (e) {
    if (!invocationStarted) {
      if (reservedNonce != null) store.releaseOutgoingBaseNonce(reservedNonce, actionId);
      store.releaseAction(actionId); // no signature exists — retry is safe
    } else {
      // The child started, so a signature/state may already be externally observable even when it
      // returned an error. Keep both fences until the live authority advances or an operator
      // reconciles the CLI journal; retrying at this nonce could double-sign.
      store.completeAction(actionId, 'invocation_outcome_ambiguous');
    }
    return { ok: false, status: 500, body: { error: String(e.stderr || e.message || e) } };
  }
}

// Fetch the daemon's authoritative live base nonce (served by /base-head → liveBaseHead) so the CLI
// co-sign guard checks the outgoing send against the ADVANCED cursor, not the frozen
// channel_backing.json. The setup-time backing witness never advances, so falling back to it after
// a daemon failure can sign a stale second send and strand the debit. Missing/malformed live state
// is therefore a hard refusal; callers must never invoke the CLI without this override.
async function liveBaseNonceEnv(api, ch, log) {
  try {
    const head = await api.getBaseHead(ch.id);
    if (head && Number.isInteger(head.nonce) && head.nonce >= 0 && head.nonce <= 0xffffffff) {
      return { INTMAX_LIVE_BASE_NONCE: String(head.nonce) };
    }
    log.warn({ event: 'LIVE_BASE_NONCE_UNAVAILABLE', channel: ch.id, head });
    throw new Error(`authoritative live base nonce unavailable for channel ${ch.id}`);
  } catch (e) {
    log.warn({ event: 'LIVE_BASE_NONCE_FETCH_FAILED', channel: ch.id, error: String(e.message || e) });
    throw new Error(`refusing to co-sign without authoritative live base nonce for channel ${ch.id}: ${String(e.message || e)}`);
  }
}

async function handleCosignBurn(event, ctx) {
  const { cli, api, ch, store, log } = ctx;
  const body = event.body || {};
  const debit = body.debitPayload;
  const descriptor = body.transferDescriptor;
  if (!debit || !descriptor) return { ok: false, status: 400, body: { error: 'needs { debitPayload, transferDescriptor }' } };
  // 409: refuse a new burn while one is pending settle (matches api/ semantics).
  const pending = store.findTicket((t) => t.type === 'partial_withdrawal' && t.status === 'burn_done');
  if (pending) return { ok: false, status: 409, body: { error: 'settle pending burn first', ticket: pending } };
  let txHash;
  try { txHash = wire.descriptorTxHash(descriptor); }
  catch (e) { return { ok: false, status: 400, body: { error: e.message } }; }
  const actionId = actionIdFrom('burn', txHash);
  if (!actionId) return { ok: false, status: 400, body: { error: 'transferDescriptor.txHash must be 0x + 64 hex chars' } };
  if (!store.claimAction(actionId)) return { ok: true, status: 200, body: { dedup: true } };
  let reservedNonce = null;
  let invocationStarted = false;
  try {
    const debitFile = actionFile(actionId, 'burn-payload');
    const descriptorFile = actionFile(actionId, 'burn-descriptor');
    const outFile = actionFile(actionId, 'burn-cosigned');
    cli.writeJson(ch.workDir, debitFile, debit);
    cli.writeJson(ch.workDir, descriptorFile, descriptor);
    const burnEnv = await liveBaseNonceEnv(api, ch, log);
    reservedNonce = Number(burnEnv.INTMAX_LIVE_BASE_NONCE);
    if (!store.reserveOutgoingBaseNonce(reservedNonce, actionId)) {
      store.releaseAction(actionId);
      return { ok: false, status: 409, body: { error: `base nonce ${reservedNonce} is already reserved by another outgoing request` } };
    }
    invocationStarted = true;
    await cli.run(ch.id, ch.workDir, ['cosign-burn-send', debitFile, descriptorFile, outFile], burnEnv);
    const cosigned = cli.readJson(ch.workDir, outFile);
    const ticket = store.upsertTicket({
      id: 'pw_' + Date.now(), type: 'partial_withdrawal', status: 'burn_done',
      params: { amount: String(body.amount || ''), recipient: body.recipient || '' },
    });
    store.completeAction(actionId, 'ok');
    log.info({ event: 'COSIGN_OK', branch: BRANCHES.PEER_BURN_REQUEST, channel: ch.id, actionId });
    return { ok: true, status: 200, body: { state: cosigned, ticket } };
  } catch (e) {
    if (!invocationStarted) {
      if (reservedNonce != null) store.releaseOutgoingBaseNonce(reservedNonce, actionId);
      store.releaseAction(actionId);
    } else {
      store.completeAction(actionId, 'invocation_outcome_ambiguous');
    }
    return { ok: false, status: 500, body: { error: String(e.stderr || e.message || e) } };
  }
}

async function cosignFamily(event, ctx, spec) {
  const { cli, ch, store, log } = ctx;
  const payload = event.body && (event.body.payload || event.body);
  if (!payload || typeof payload !== 'object') {
    return { ok: false, status: 400, body: { error: 'missing payload' } };
  }
  // Idempotency must use the exact Rust-wire proposed-state digest. Falling back to an arbitrary
  // payload hash hides schema mismatches and can collapse unrelated nested objects.
  let nextState;
  try { nextState = wire.proposedState(payload); }
  catch (e) { return { ok: false, status: 400, body: { error: e.message } }; }
  const actionId = actionIdFrom(spec.label, nextState && nextState.digest);
  if (!actionId) return { ok: false, status: 400, body: { error: 'payload.proposedNextState.digest must be 0x + 64 hex chars' } };
  if (!store.claimAction(actionId)) return { ok: true, status: 200, body: { dedup: true } };
  try {
    const payloadFile = actionFile(actionId, spec.payloadFile.replace(/\.json$/, '').replace(/_/g, '-'));
    const outFile = actionFile(actionId, spec.outFile.replace(/\.json$/, '').replace(/_/g, '-'));
    cli.writeJson(ch.workDir, payloadFile, payload);
    await cli.run(ch.id, ch.workDir, spec.cliArgs(payloadFile, outFile));
    const cosigned = cli.readJson(ch.workDir, outFile);
    // Post-check: the returned state must carry signatures (the CLI guarantees N-of-N; we assert
    // the structural presence as defense-in-depth). A bare/half-signed state must never publish.
    const sigs = wire.memberSignatures(wire.stateFromResponse(cosigned));
    if (!sigs || sigs.length === 0) {
      store.completeAction(actionId, 'no_sigs');
      return { ok: false, status: 500, body: { error: 'cosigned state missing member signatures (not published)' }, suspicious: true };
    }
    store.completeAction(actionId, 'ok');
    log.info({ event: 'COSIGN_OK', branch: spec.label, channel: ch.id, actionId });
    return { ok: true, status: 200, body: cosigned };
  } catch (e) {
    store.releaseAction(actionId);
    return { ok: false, status: 500, body: { error: String(e.stderr || e.message || e) } };
  }
}

async function publishSnapshot(event, ctx) {
  const { cli, ch } = ctx;
  try {
    const snap = cli.readJson(ch.workDir, 'channel_snapshot.json');
    return { ok: true, status: 200, body: snap };
  } catch (e) {
    return { ok: false, status: 404, body: { error: 'no channel yet' } };
  }
}

module.exports = {
  handleCosign,
  handleCosignRefresh,
  handleInterChannel,
  handleCosignBurn,
  publishSnapshot,
  liveBaseNonceEnv,
  actionIdFrom,
  actionFile,
};
