const test = require('node:test');
const assert = require('node:assert/strict');

const { withLock, withLocks } = require('../../api/lib/lock');

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, reject, resolve };
}

test('two transfers sharing a destination are serialized', async () => {
  const firstEntered = deferred();
  const releaseFirst = deferred();
  const events = [];

  const first = withLocks([101, 103], async () => {
    events.push('first-enter');
    firstEntered.resolve();
    await releaseFirst.promise;
    events.push('first-exit');
  });
  await firstEntered.promise;

  const second = withLocks([102, 103], async () => {
    events.push('second-enter');
  });
  await Promise.resolve();
  await Promise.resolve();
  assert.deepEqual(events, ['first-enter']);

  releaseFirst.resolve();
  await Promise.all([first, second]);
  assert.deepEqual(events, ['first-enter', 'first-exit', 'second-enter']);
});
test('a rejected mutation releases every channel tail', async () => {
  await assert.rejects(
    withLocks([201, 202], async () => { throw new Error('expected'); }),
    /expected/,
  );
  assert.equal(await withLock(202, async () => 'recovered'), 'recovered');
});
