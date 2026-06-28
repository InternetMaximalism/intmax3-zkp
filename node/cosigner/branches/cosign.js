'use strict';
// NORMAL branch: validate peers' txs and co-sign (DESIGN.md §3.3). The CLI is the real fail-closed
// gate (re-verifies E-1/E-2 STARK + transition + replay ledgers + N-of-N). These handlers add
// policy, idempotency, post-checks, and snapshot publication. They NEVER sign anything themselves.

const { BRANCHES } = require('../classify');
const crypto = require('crypto');

// Content-addressed action id: a stable hash over the binding field if present, else over the whole
// canonical payload. NEVER a length (review H2: lengths collide and split, enabling censorship and
// double-cosign). Returns null if no payload — the caller refuses rather than fabricating an id.
function actionIdFrom(prefix, bindingField, payload) {
  const basis = bindingField != null ? String(bindingField) : (payload ? canonical(payload) : null);
  if (basis == null) return null;
  return prefix + ':' + crypto.createHash('sha256').update(basis).digest('hex').slice(0, 32);
}

function canonical(obj) {
  // Deterministic JSON (sorted keys) so the same payload always hashes the same.
  return JSON.stringify(obj, Object.keys(flatten(obj)).sort());
}
function flatten(o, acc = {}, p = '') {
  if (o && typeof o === 'object' && !Array.isArray(o)) {
    for (const k of Object.keys(o)) flatten(o[k], acc, p + k + '.');
  } else { acc[p] = o; }
  return acc;
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
  const { cli, ch, store, log } = ctx;
  const body = event.body || {};
  const debit = body.debitPayload;
  const descriptor = body.transferDescriptor;
  if (!debit || !descriptor) return { ok: false, status: 400, body: { error: 'needs { debitPayload, transferDescriptor }' } };
  const actionId = actionIdFrom('inter', descriptor.tx_hash, descriptor);
  if (!actionId) return { ok: false, status: 400, body: { error: 'transferDescriptor missing binding (tx_hash)' } };
  if (!store.claimAction(actionId)) return { ok: true, status: 200, body: { dedup: true } };
  try {
    cli.writeJson(ch.workDir, 'inter_debit_payload.json', debit);
    cli.writeJson(ch.workDir, 'inter_descriptor.json', descriptor);
    await cli.run(ch.id, ch.workDir, ['cosign-inter-transfer', 'inter_debit_payload.json', 'inter_descriptor.json', 'inter_transfer.json']);
    const result = cli.readJson(ch.workDir, 'inter_transfer.json');
    store.completeAction(actionId, 'ok');
    log.info({ event: 'COSIGN_OK', branch: BRANCHES.PEER_INTER_REQUEST, channel: ch.id, actionId });
    return { ok: true, status: 200, body: { sourceHead: result.aHead || result, destSnapshot: result.bSnapshot || null } };
  } catch (e) {
    store.releaseAction(actionId); // transient/failed — allow retry of the same tx
    return { ok: false, status: 500, body: { error: String(e.stderr || e.message || e) } };
  }
}

async function handleCosignBurn(event, ctx) {
  const { cli, ch, store, log } = ctx;
  const body = event.body || {};
  const debit = body.debitPayload;
  const descriptor = body.transferDescriptor;
  if (!debit || !descriptor) return { ok: false, status: 400, body: { error: 'needs { debitPayload, transferDescriptor }' } };
  // 409: refuse a new burn while one is pending settle (matches api/ semantics).
  const pending = store.findTicket((t) => t.type === 'partial_withdrawal' && t.status === 'burn_done');
  if (pending) return { ok: false, status: 409, body: { error: 'settle pending burn first', ticket: pending } };
  const actionId = actionIdFrom('burn', descriptor.tx_hash, descriptor);
  if (!actionId) return { ok: false, status: 400, body: { error: 'transferDescriptor missing binding (tx_hash)' } };
  if (!store.claimAction(actionId)) return { ok: true, status: 200, body: { dedup: true } };
  try {
    cli.writeJson(ch.workDir, 'burn_payload.json', debit);
    cli.writeJson(ch.workDir, 'burn_descriptor.json', descriptor);
    await cli.run(ch.id, ch.workDir, ['cosign-burn-send', 'burn_payload.json', 'burn_descriptor.json', 'burn_cosigned.json']);
    const cosigned = cli.readJson(ch.workDir, 'burn_cosigned.json');
    const ticket = store.upsertTicket({
      id: 'pw_' + Date.now(), type: 'partial_withdrawal', status: 'burn_done',
      params: { amount: String(body.amount || ''), recipient: body.recipient || '' },
    });
    store.completeAction(actionId, 'ok');
    log.info({ event: 'COSIGN_OK', branch: BRANCHES.PEER_BURN_REQUEST, channel: ch.id, actionId });
    return { ok: true, status: 200, body: { state: cosigned, ticket } };
  } catch (e) {
    store.releaseAction(actionId);
    return { ok: false, status: 500, body: { error: String(e.stderr || e.message || e) } };
  }
}

async function cosignFamily(event, ctx, spec) {
  const { cli, ch, store, log } = ctx;
  const payload = event.body && (event.body.payload || event.body);
  if (!payload || typeof payload !== 'object') {
    return { ok: false, status: 400, body: { error: 'missing payload' } };
  }
  // Idempotency: content-addressed id from the proposed next state's digest (the binding field) or
  // a canonical hash of the whole payload. Never a length (review H2).
  const nextState = payload.proposed_next_state || payload.refreshed_state || {};
  const actionId = actionIdFrom(spec.label, nextState.digest, payload);
  if (!actionId) return { ok: false, status: 400, body: { error: 'payload missing binding digest' } };
  if (!store.claimAction(actionId)) return { ok: true, status: 200, body: { dedup: true } };
  try {
    cli.writeJson(ch.workDir, spec.payloadFile, payload);
    await cli.run(ch.id, ch.workDir, spec.cliArgs(spec.payloadFile, spec.outFile));
    const cosigned = cli.readJson(ch.workDir, spec.outFile);
    // Post-check: the returned state must carry signatures (the CLI guarantees N-of-N; we assert
    // the structural presence as defense-in-depth). A bare/half-signed state must never publish.
    const sigs = (cosigned.state && cosigned.state.member_signatures) || cosigned.member_signatures;
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

module.exports = { handleCosign, handleCosignRefresh, handleInterChannel, handleCosignBurn, publishSnapshot };
