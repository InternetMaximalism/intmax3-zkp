// REAL-daemon integration test for the live-balance wrappers: spawns the actual
// `block_producer_service` binary through api/lib/block-producer.js (no mocks) and drives the
// `live*` JSONL surface end to end against a fresh journal + live root.
//
// The first liveInit constructs the resident balance prover and proves the genesis snapshot
// (~1-3 min cold); every later command reuses the resident circuits. Skipped when the release
// binary is absent (fixture-skip convention, same as the suites the checkpoint counted).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const repo = path.resolve(__dirname, '..', '..');
const bin = process.env.BLOCK_PRODUCER_BIN ||
  path.join(repo, 'target', 'release', 'block_producer_service');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-live-balance-'));
process.env.INTMAX_WORK_DIR = work;
delete process.env.BLOCK_PRODUCER_JOURNAL;
delete process.env.LIVE_BALANCE_ROOT;
delete process.env.VALIDITY_SNAPSHOT;

const producer = require('../../api/lib/block-producer');

// Without this the spawned daemon keeps the runner's event loop alive forever after the last
// assertion — the tests pass and the process never exits.
test.after(() => producer.stop());

const missing = !fs.existsSync(bin);

test('live-balance daemon surface (real binary)', { skip: missing && 'release daemon binary not built' }, async t => {
  await t.test('unknown channel fails closed before any state exists', async () => {
    await assert.rejects(producer.liveStatus(7), /live_snapshot|does not exist/);
  });

  let recipient;
  await t.test('liveInit derives and returns only the deposit recipient', async () => {
    const init = await producer.liveInit(7);
    assert.equal(Number(init.channelId ?? 7), 7);
    recipient = init.depositRecipient;
    assert.match(recipient, /^0x[0-9a-f]{64}$/);
    // No salt material may ever cross the wire: the daemon owns it.
    assert.equal(init.accountSalt, undefined);
    assert.equal(init.depositSalt, undefined);
  });

  await t.test('liveInit is idempotent across calls (never re-randomizes salts)', async () => {
    const again = await producer.liveInit(7);
    assert.equal(again.depositRecipient, recipient);
  });

  await t.test('liveStatus reports the genesis base head', async () => {
    const status = await producer.liveStatus(7);
    assert.equal(status.baseNonce, 0);
    assert.equal(status.balanceGeneration, 0);
    assert.equal(status.awaitingChannelBinding, false);
    assert.ok(status.proofSize > 100000, 'a real genesis balance proof is journaled');
  });

  await t.test('liveBaseHead exposes the authenticated public cursor', async () => {
    const head = await producer.liveBaseHead(7);
    assert.equal(head.baseNonce, 0);
    assert.match(String(head.settledTxChain), /^0x0{64}$/);
  });

  await t.test('the producer surface still works on the same daemon', async () => {
    const status = await producer.status();
    assert.ok(status);
  });
});
