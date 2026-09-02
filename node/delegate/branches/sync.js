'use strict';
// NORMAL branches for the delegate (DESIGN.md §4.3): import + verify the head, decrypt balance,
// and react to deposits. Head monotonicity is enforced — a regression/equivocation routes to exit.

const { checkHeadMonotonic } = require('../verify');
const dsm = require('../state-machine');
const wire = require('../../common/wire');
const { buildParticipantCloseProof } = require('../participant-close');
const { isDeepStrictEqual } = require('util');

function headOf(snapshot) {
  const st = (snapshot && snapshot.state) || {};
  const version = wire.stateVersion(st);
  return { digest: st.digest, epoch: st.epoch || 0, stateVersion: version == null ? 0 : version };
}

// Record a decrypted BalanceReport into the store.
//
// SECURITY: sendability comes from the report's OWN `canSend`. The previous code derived it from
// `bal.pending_adds`, a field `BalanceReport` has never had (it serializes slot / balance /
// canSend / stateVersion / balances[] / witnessTokenSlot) — so the flag was `!(undefined > 0)`,
// i.e. unconditionally true. The mandatory pre-send refresh (owntx.js `ensureSendable`) therefore
// never ran, and a stale witness surfaced as a hard WASM error instead of an automatic refresh.
// The wasm's own `can_send` already encodes the D3 rule that was being reached for: it requires
// `pending_adds[slot][token] == 0` for the witness position (src/wasm_wallet.rs `balance_report`).
//
// Multi-token (§N): the wallet holds at most ONE send witness, for the position named by
// `witnessTokenSlot`, and `canSend` refers to THAT position only — a genesis-token witness does
// not authorize sending token 1. Both fields are stored so sendability can be checked per token.
function recordBalance(store, bal) {
  store.set('balance', bal);
  store.set('canSend', !!(bal && bal.canSend === true));
  const w = bal && bal.witnessTokenSlot;
  store.set('witnessTokenSlot', w === undefined || w === null ? null : Number(w));
}

async function importAndVerify(event, ctx) {
  const {
    api, wallet, ch, store, log, raiseSignal, snapshotVault, backingVault, backingVerifier,
  } = ctx;
  let snapshot = event.snapshot;
  if (!snapshot) snapshot = await api.getSnapshot(ch.id);
  const incoming = headOf(snapshot);

  const prevAccepted = store.get('acceptedHead');
  const mono = checkHeadMonotonic(prevAccepted, incoming);
  if (!mono.ok) {
    // Two conflicting signed heads / regression = member equivocation. Capture evidence + exit.
    store.set('equivocationEvidence', { prevAccepted, incoming, conflicting: snapshot });
    log.error({ event: 'EQUIVOCATION_DETECTED', channel: ch.id, reason: mono.reason });
    return raiseSignal({ source: 'signal', kind: 'equivocation', reason: mono.reason });
  }

  // A snapshot is not accepted unless its exact public close backing is already retrievable and
  // can be durably archived. Fetch and fully context-check it BEFORE the WASM session adopts the
  // head. The artifact is only published into the immutable vault AFTER WASM has authenticated
  // every signature/root in the same snapshot.
  if (!wallet.available()) {
    throw new Error('WASM wallet unavailable: refusing to accept an unverifiable signed head');
  }
  if (!snapshotVault || !backingVault || !backingVerifier) {
    throw new Error('durable snapshot/backing archives and native backing verification are required before accepting a signed head');
  }
  const backing = await api.getBacking(ch.id);
  const stagedBacking = backingVault.prepare(backing, snapshot);
  try {
    // Verify the exact fsynced JSON file that will become the archive.  The compact native
    // --verify-only path checks the N-of-N signatures, pinned VD and BalanceProcessor proof but
    // deliberately avoids close-proof construction.  A durable receipt can be reused for an
    // idempotent replay of the same content-addressed archive.
    if (backingVault.requiresVerification(stagedBacking)) {
      const receipt = await backingVerifier.verify(
        backingVault.verificationInput(stagedBacking),
        backingVault.authority,
      );
      backingVault.acceptVerification(stagedBacking, receipt);
    }
    wallet.importChannel(snapshot, ctx.slot);
    const bal = wallet.balance(ctx.slot);
    if (!bal || Number(bal.slot) !== Number(ctx.slot)) {
      throw new Error(`WASM wallet owns slot ${bal && bal.slot}, not configured delegate slot ${ctx.slot}`);
    }
    if (!ctx.recipient) throw new Error('delegate recipient is required for unilateral close recovery');
    // Only derive/store this proof AFTER the WASM importer has authenticated the N-of-N snapshot
    // and located our own key. The proof contains no secret; it is the immutable L1 authentication
    // path the recipient will use for requestCloseAsParticipant.
    const participantCloseProof = buildParticipantCloseProof(snapshot, ctx.slot, ctx.recipient);
    // Publish the already-fsynced backing stage first, then the snapshot. acceptedHead is written
    // last, so a crash can leave extra immutable recovery material but can never leave an accepted
    // head whose backing was not durable.
    backingVault.commit(stagedBacking);
    snapshotVault.save(snapshot);
    store.set('participantCloseProof', participantCloseProof);
    recordBalance(store, bal);
    log.info({ event: 'SNAPSHOT_IMPORTED', channel: ch.id, head: incoming, balance: bal && bal.balance });
  } catch (error) {
    backingVault.abort(stagedBacking);
    throw error;
  }
  store.set('acceptedHead', incoming);
}

// Own-transaction endpoints return a bare ChannelState. Before accepting it, recover the complete
// public snapshot and demand byte-for-byte JSON value equality with that response. This funnels
// local send/refresh/inter/burn heads through the same WASM + backing archive gate as poll sync.
async function importPublishedState(expectedState, ctx) {
  const snapshot = await ctx.api.getSnapshot(ctx.ch.id);
  if (!snapshot || !isDeepStrictEqual(snapshot.state, expectedState)) {
    throw new Error('published snapshot differs from the exact co-signed response state');
  }
  return importAndVerify({ source: 'api', kind: 'snapshot', snapshot }, ctx);
}

async function decryptAndReport(event, ctx) {
  const { wallet, store, log, ch } = ctx;
  if (!wallet.available()) return log.warn({ event: 'WASM_UNAVAILABLE', channel: ch.id });
  const bal = wallet.balance(ctx.slot);
  recordBalance(store, bal);
  log.info({ event: 'BALANCE', channel: ch.id, slot: ctx.slot, balance: bal && bal.balance, canSend: store.get('canSend') });
  return bal;
}

async function awaitImportThenSync(event, ctx) {
  // A deposit landed; the co-signer imports it. Re-sync the snapshot so we pick up the credit.
  ctx.log.info({ event: 'DEPOSIT_SEEN', channel: ctx.ch.id, txHash: event.txHash });
  return importAndVerify({ source: 'api', kind: 'snapshot' }, ctx);
}

module.exports = {
  importAndVerify,
  importPublishedState,
  decryptAndReport,
  awaitImportThenSync,
  headOf,
  recordBalance,
};
