'use strict';
// The delegate's verifyCosigned gate — STRUCTURAL/binding checks (DESIGN.md §4.4/§4.6). Pure and
// exhaustively unit-testable. The cryptographic signature check is done separately by the WASM
// wallet (wallet.cosignVerify); this function enforces that the co-signed result is the one we
// asked for and lawfully extends our head. A failure here ⇒ the delegate must NOT finalize and must
// enter exit mode (the co-signer is faulty). Fail-closed: any missing field ⇒ reject.

// sent: the payload we built (intra send / refresh). resp: the co-signer's response. prevHead:
// { digest, epoch, stateVersion } of the head we proved against.
function verifyCosignedStructural(sent, resp, prevHead) {
  if (!resp || typeof resp !== 'object') return { ok: false, reason: 'empty response' };
  const state = resp.state || resp.proposed_next_state || resp;
  if (!state || typeof state !== 'object') return { ok: false, reason: 'no state in response' };

  // 1) N-of-N signatures must be present (crypto-verified separately by WASM).
  const sigs = state.member_signatures;
  if (!Array.isArray(sigs) || sigs.length === 0) return { ok: false, reason: 'missing member signatures' };

  // 2) Must extend the EXACT head we sent against.
  if (prevHead && prevHead.digest != null) {
    if (state.prev_digest !== prevHead.digest) return { ok: false, reason: 'does not extend our head (prev_digest mismatch)' };
  }

  // 3) state_version must advance by exactly 1.
  const bs = state.balance_state || {};
  if (prevHead && prevHead.stateVersion != null) {
    const got = Number(bs.state_version);
    if (!Number.isFinite(got) || got !== Number(prevHead.stateVersion) + 1) {
      return { ok: false, reason: `state_version did not advance by 1 (got ${bs.state_version}, prev ${prevHead.stateVersion})` };
    }
  }

  // 4) The transfer we asked for must be the one carried. This binding is MANDATORY when we sent a
  //    channel_tx: a faulty co-signer must not be able to bypass it by omitting the echo (review
  //    H4). The co-signed state MUST carry the tx, and recipient/amount/nonce MUST equal what we
  //    built. Fail closed if the echo is absent or any field differs.
  if (sent && sent.channel_tx) {
    const tx = sent.channel_tx;
    const carried = resp.channel_tx || state.last_channel_tx || state.channel_tx;
    if (!carried) return { ok: false, reason: 'co-signed state did not echo the channel_tx (binding unverifiable)' };
    if (carried.recipient_pk_g !== tx.recipient_pk_g) return { ok: false, reason: 'recipient mismatch' };
    // Amount + nonce binding is MANDATORY when we sent them: a faulty co-signer must not bypass the
    // check by OMITTING the sub-field (review N1 — the weaker version of the H4 hole). If we sent
    // the field, the echo MUST contain it AND match.
    if (tx.enc_amount !== undefined) {
      if (carried.enc_amount === undefined) return { ok: false, reason: 'amount (enc) missing from echo' };
      if (JSON.stringify(carried.enc_amount) !== JSON.stringify(tx.enc_amount)) return { ok: false, reason: 'amount (enc) mismatch' };
    }
    if (tx.amount !== undefined) {
      if (carried.amount === undefined) return { ok: false, reason: 'amount missing from echo' };
      if (String(carried.amount) !== String(tx.amount)) return { ok: false, reason: 'amount mismatch' };
    }
    if (tx.nonce !== undefined) {
      if (carried.nonce === undefined) return { ok: false, reason: 'nonce missing from echo' };
      if (carried.nonce !== tx.nonce) return { ok: false, reason: 'nonce mismatch' };
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
