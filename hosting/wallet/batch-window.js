'use strict';
// detail2 §M-7: the relay-side co-sign batch window.
//
// Collects /api/cosign payloads per channel into a window of at most `windowMs` milliseconds and
// `maxK` transactions (defaults 1000 ms / 200 — the "up to 200 tx per second per co-signed
// transition" requirement), then hands the whole window to `drain` at once. The window mechanics
// live here, dependency-free, so they are unit-testable without express or the CLI; the relay
// supplies `drain(ch, entries)` (lock + stale filter + CLI invocation).
//
// Lifecycle: the first enqueue for a channel opens its window and arms the timer; the window
// closes on the timer OR on hitting maxK, whichever is first. A closed window is removed from the
// map BEFORE its drain runs, so requests arriving during a drain open the NEXT window (drains
// themselves serialize behind the relay's per-channel lock). Each entry settles exactly once —
// `drain` resolves/rejects entries individually (per-tx stale rejection, §M-7); anything drain
// throws settles every still-unsettled entry of that window.

function createBatchWindow({ windowMs = 1000, maxK = 200, drain }) {
  if (typeof drain !== 'function') throw new Error('createBatchWindow: drain function required');
  if (!(windowMs > 0) || !(maxK >= 1)) throw new Error('createBatchWindow: bad windowMs/maxK');
  const windows = new Map(); // ch -> { entries, timer }

  function close(ch, w) {
    if (windows.get(ch) === w) windows.delete(ch);
    clearTimeout(w.timer);
    Promise.resolve()
      .then(() => drain(ch, w.entries))
      .catch((e) => {
        for (const en of w.entries) if (!en.settled) en.reject(e);
      });
  }

  function enqueue(ch, payload) {
    return new Promise((resolve, reject) => {
      let w = windows.get(ch);
      if (!w) {
        w = { entries: [], timer: null };
        windows.set(ch, w);
        w.timer = setTimeout(() => close(ch, w), windowMs);
        // Don't hold the process open for an idle window (tests, graceful shutdown).
        if (w.timer.unref) w.timer.unref();
      }
      const entry = {
        payload,
        settled: false,
        resolve: (v) => { entry.settled = true; resolve(v); },
        reject: (e) => { entry.settled = true; reject(e); },
      };
      w.entries.push(entry);
      if (w.entries.length >= maxK) close(ch, w);
    });
  }

  return { enqueue };
}

// detail2 §M-4 fat→slim projection (field-for-field the Rust `SendPayload::to_slim`):
// everything dropped is data the co-signer re-derives from its own snapshot; `afterCt` is the
// sender row's ciphertext at the tx's SIGNED tokenSlot. Key order matters: `anchorDigest` first
// (§M-1 — transports may read it from the head of the byte stream).
function projectToSlim(fat) {
  const next = fat && fat.proposedNextState;
  if (!next || !next.prevDigest || !next.balanceState) {
    throw new Error('cosign payload missing proposedNextState.{prevDigest,balanceState}');
  }
  const row = next.balanceState.encBalances && next.balanceState.encBalances[fat.senderIndex];
  if (!row) throw new Error(`senderIndex ${fat.senderIndex} out of encBalances range`);
  const afterCt = row[fat.channelTx && fat.channelTx.tokenSlot];
  if (!afterCt) throw new Error(`tokenSlot ${fat.channelTx && fat.channelTx.tokenSlot} out of row range`);
  return {
    anchorDigest: next.prevDigest,
    senderIndex: fat.senderIndex,
    recipientIndex: fat.recipientIndex,
    channelTx: fat.channelTx,
    afterCt,
  };
}

// §M-7 anchor pre-filter: a stale payload is a PER-TX error (client re-signs, §M-3), never batch
// poison. Returns { fresh, stale } partitions of the window's entries.
function partitionByAnchor(entries, headDigest) {
  const fresh = [];
  const stale = [];
  for (const en of entries) {
    const anchor = en.payload && en.payload.proposedNextState && en.payload.proposedNextState.prevDigest;
    (anchor === headDigest ? fresh : stale).push(en);
  }
  return { fresh, stale };
}

module.exports = { createBatchWindow, projectToSlim, partitionByAnchor };
