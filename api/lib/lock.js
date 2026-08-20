const _chLocks = {};

// Acquire every named channel in deterministic order. An inter-channel mutation writes BOTH local
// state files; serializing only by its source allows A->B and C->B to race and lose one credit.
// Registration is synchronous before any predecessor runs, so two overlapping calls always see
// at least one shared tail and queue rather than deadlock.
function withLocks(channels, fn) {
  const ids = [...new Set(channels.map(Number))]
    .filter(Number.isSafeInteger)
    .sort((a, b) => a - b);
  if (ids.length === 0) return Promise.reject(new Error('withLocks requires a channel id'));
  const previous = ids.map(id => _chLocks[id] || Promise.resolve());
  const ready = Promise.all(previous.map(promise => promise.catch(() => {})));
  const next = ready.then(fn);
  const tail = next.catch(() => {});
  for (const id of ids) _chLocks[id] = tail;
  return next;
}

function withLock(ch, fn) {
  return withLocks([ch], fn);
}

module.exports = { withLock, withLocks };
