'use strict';
// The delegate's verifyCosigned gate — STRUCTURAL/binding checks (DESIGN.md §4.4/§4.6). Pure and
// exhaustively unit-testable. The cryptographic signature check is done separately by the WASM
// wallet (wallet.cosignVerify); this function enforces that the co-signed result is the one we
// asked for and lawfully extends our head. A failure here ⇒ the delegate must NOT finalize and must
// enter exit mode (the co-signer is faulty). Fail-closed: any missing field ⇒ reject.

const wire = require('../common/wire');

// sent: the payload we built (intra send / refresh). resp: the co-signer's response. prevHead:
// { digest, epoch, stateVersion } of the head we proved against.
function verifyCosignedStructural(sent, resp, prevHead) {
  if (!resp || typeof resp !== 'object') return { ok: false, reason: 'empty response' };
  let state;
  try { state = wire.stateFromResponse(resp); }
  catch (e) { return { ok: false, reason: e.message }; }
  if (!state || typeof state !== 'object') return { ok: false, reason: 'no state in response' };

  // 1) N-of-N signatures must be present (crypto-verified separately by WASM).
  let sigs;
  try { sigs = wire.memberSignatures(state); }
  catch (e) { return { ok: false, reason: e.message }; }
  if (!Array.isArray(sigs) || sigs.length === 0) return { ok: false, reason: 'missing member signatures' };

  // 2) Must extend the EXACT head we sent against.
  if (prevHead && prevHead.digest != null) {
    let previous;
    try { previous = wire.prevDigest(state); }
    catch (e) { return { ok: false, reason: e.message }; }
    if (previous !== prevHead.digest) return { ok: false, reason: 'does not extend our head (prevDigest mismatch)' };
  }

  // 3) state_version must advance by exactly 1.
  if (prevHead && prevHead.stateVersion != null) {
    let rawVersion;
    try { rawVersion = wire.stateVersion(state); }
    catch (e) { return { ok: false, reason: e.message }; }
    const got = Number(rawVersion);
    if (!Number.isFinite(got) || got !== Number(prevHead.stateVersion) + 1) {
      return { ok: false, reason: `stateVersion did not advance by 1 (got ${rawVersion}, prev ${prevHead.stateVersion})` };
    }
  }

  // 4) Bind the response to the exact state the local wallet built. Rust's cosign CLI returns a
  // bare ChannelState (it does not echo ChannelTx), so requiring an invented `channel_tx` field
  // made every real response fail. The proposed-state digest commits the complete transition and
  // is the value the N-of-N signatures cover; equality is the correct wire-level binding.
  if (sent) {
    let proposed;
    try { proposed = wire.proposedState(sent); }
    catch (e) { return { ok: false, reason: e.message }; }
    if (proposed && proposed.digest != null && state.digest !== proposed.digest) {
      return { ok: false, reason: 'co-signed state digest differs from proposedNextState.digest' };
    }

    // If a transport does echo the tx, verify it exactly as defense in depth. Absence is normal for
    // the canonical Rust ChannelState response and is covered by the digest equality above.
    let tx;
    let carried;
    try {
      tx = wire.channelTx(sent);
      carried = wire.channelTx(resp) || wire.lastChannelTx(state) || wire.channelTx(state);
    } catch (e) { return { ok: false, reason: e.message }; }
    if (tx && carried && wire.canonical(carried) !== wire.canonical(tx)) {
      return { ok: false, reason: 'echoed channelTx mismatch' };
    }
  }

  return { ok: true };
}

// Monotonicity guard for imported heads (DESIGN.md §4.3). A regression in (epoch, state_version)
// of a head the members signed is equivocation. Returns { ok, reason, regression }.
function checkHeadMonotonic(prevAccepted, incoming) {
  if (!prevAccepted) return { ok: true };
  const pe = BigInt(prevAccepted.epoch || 0), ie = BigInt(incoming.epoch || 0);
  const pv = BigInt(prevAccepted.stateVersion || 0), iv = BigInt(incoming.stateVersion || 0);
  if (ie < pe || (ie === pe && iv < pv)) {
    return { ok: false, regression: true, reason: `head regressed (epoch,version) ${incoming.epoch},${incoming.stateVersion} < ${prevAccepted.epoch},${prevAccepted.stateVersion}` };
  }
  // Same (epoch,version) but a DIFFERENT digest = two conflicting signed heads = equivocation.
  if (ie === pe && iv === pv && incoming.digest && prevAccepted.digest && incoming.digest !== prevAccepted.digest) {
    return { ok: false, regression: true, reason: 'two conflicting signed heads at the same (epoch,version)' };
  }
  return { ok: true };
}

module.exports = { verifyCosignedStructural, checkHeadMonotonic };
