'use strict';
// A burn is an inter-channel send to the reserved burn channel, paid on L1 by its base withdrawal
// proof alone. The channel keeps advancing after the burn, so the live staging resumes the exact
// signed burn (never the current head) and accepts only the payout proof of THAT burn, anchored at
// a producer head at or after the burn's block.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-live-'));
process.env.INTMAX_WORK_DIR = root;
const cli = require('../../api/lib/cli'), producer = require('../../api/lib/block-producer');
const live = require('../../api/lib/partial-withdrawal-live');
test.after(() => fs.rmSync(root, { recursive: true, force: true }));

// The burn's producer block: the earliest head a payout proof may be anchored at.
const BURN_BLOCK = { requestId: 'receipt', blockNumber: 5, generation: 6, extendedStateCommitment: '0xburnroot' };
// last_burn.json as the CLI writes it at co-sign time (mixed-case hex, as serialized).
const BURN = { withdrawal_nullifier: '0xABCDEF01', aux_data: '0xA0B1C2', withdrawal_recipient: '0x00000000000000000000000000000000000000Ab', token_index: 55 };

function fixture(ch) {
  const head = { channelId: ch, digest: 'burn', balanceState: { settledTxChain: 'post-burn' } };
  cli.writeJson(cli.wc(ch, 'burn_cosigned.json'), head);
  cli.writeJson(cli.wc(ch, 'burn_payload.json'), { proposedNextState: head });
  cli.writeJson(cli.wc(ch, 'burn_descriptor.json'), { token: 'descriptor' });
  cli.writeJson(cli.wc(ch, 'channel_snapshot.json'), { state: head });
  cli.writeJson(cli.wc(ch, 'last_burn.json'), BURN);
  const events = [], requests = [];
  producer.postInterChannel = async (_head, _payload, _descriptor, id) => { events.push('post'); requests.push(id); return { ...BURN_BLOCK }; };
  producer.liveSettleInterChannel = async () => { events.push('settle'); return { baseNonce: 1 }; };
  producer.liveBurnPayoutArtifacts = async () => { throw new Error('no payout proof expected'); };
  cli.l1SignerAddress = () => '0x00000000000000000000000000000000000000Ef';
  return { events, requests, head };
}

// The daemon's payout artifacts for the fixture's burn (lower-case hex, as the daemon serializes).
function payout({ anchor = {}, withdrawal = {}, ...rest } = {}) {
  return {
    withdrawal: { amount: '18446744073709551615', recipient: BURN.withdrawal_recipient.toLowerCase(), tokenIndex: 55,
      nullifier: BURN.withdrawal_nullifier.toLowerCase(), auxData: BURN.aux_data.toLowerCase(), ...withdrawal },
    withdrawalProver: '0x00000000000000000000000000000000000000ef',
    producerAnchor: { blockNumber: 9, generation: 10, bpSigChain: 'bp', entryHash: 'entry', extendedStateCommitment: '0xanchorroot', timestamp: 100, ...anchor },
    proof: 'verified-artifacts', ...rest,
  };
}

// ── prepareLiveBurn: the burn's own block and live settlement ───────────────────────────────────
test('the burn block and its live settlement are recorded once; a complete pw_producer.json is never replayed', async () => {
  const h = fixture(7);
  const first = await live.prepareLiveBurn(7);
  assert.deepEqual(first.blockReceipt, BURN_BLOCK);
  assert.ok(first.producerRequestId.startsWith('burn:'));
  const saved = cli.readJson(cli.wc(7, 'pw_producer.json'));
  assert.equal(saved.producerRequestId, first.producerRequestId);
  assert.equal(saved.liveReceipt.baseNonce, 1);
  const again = await live.prepareLiveBurn(7);
  assert.deepEqual(h.events, ['post', 'settle'], 'the recorded burn is resumed, not posted or settled again');
  assert.deepEqual(again.blockReceipt, BURN_BLOCK);
  assert.equal(again.producerRequestId, first.producerRequestId);
  assert.equal(again.head.digest, 'burn');
});

test('a burn recorded by the burn operation itself is resumed without any producer call', async () => {
  const h = fixture(8);
  // burn-operation.js writes pw_producer.json with both receipts as it completes the burn.
  const id = producer.stableRequestId('burn', { ch: 8, debitPayload: cli.readJson(cli.wc(8, 'burn_payload.json')),
    transferDescriptor: cli.readJson(cli.wc(8, 'burn_descriptor.json')) });
  cli.writeJson(cli.wc(8, 'pw_producer.json'), { producerRequestId: id, blockReceipt: { ...BURN_BLOCK, blockNumber: 3 }, liveReceipt: { baseNonce: 4 } });
  const out = await live.prepareLiveBurn(8);
  assert.deepEqual(h.events, []);
  assert.equal(out.producerRequestId, id);
  assert.equal(out.blockReceipt.blockNumber, 3, 'the recorded burn block, not a new one');
});

test('the exact signed burn is resumed after the channel advanced past it', async () => {
  const h = fixture(9);
  // Later sends moved the channel head on; the burn is no longer the head.
  cli.writeJson(cli.wc(9, 'channel_snapshot.json'), { state: { channelId: 9, digest: 'later-head' } });
  const out = await live.prepareLiveBurn(9);
  assert.equal(out.head.digest, 'burn');
  assert.deepEqual(h.events, ['post', 'settle']);
});

for (const [name, change] of [
  ['a signed head that is not its payload\'s next state', ch => cli.writeJson(cli.wc(ch, 'burn_cosigned.json'), { channelId: ch, digest: 'other' })],
  ['a signed head of another channel', ch => cli.writeJson(cli.wc(ch, 'burn_cosigned.json'), { channelId: ch + 1, digest: 'burn' })],
]) {
  test(`${name} is refused before any producer call`, async () => {
    const h = fixture(10);
    change(10);
    await assert.rejects(live.prepareLiveBurn(10), /exact signed burn/);
    await assert.rejects(live.stagePayoutArtifacts(10), /exact signed burn/);
    assert.deepEqual(h.events, []);
  });
}

test('an interrupted live settlement retries the identical producer request, then is not replayed', async () => {
  const h = fixture(11);
  let fail = true;
  producer.liveSettleInterChannel = async () => {
    h.events.push('settle');
    if (fail) throw new Error('injected settlement interruption');
    return { baseNonce: 2 };
  };
  await assert.rejects(live.prepareLiveBurn(11), /injected settlement/);
  assert.equal(cli.readJson(cli.wc(11, 'pw_producer.json')).liveReceipt, null, 'the block receipt is kept, the settlement is not');
  fail = false;
  await live.prepareLiveBurn(11);
  assert.equal(h.requests.length, 2);
  assert.equal(h.requests[0], h.requests[1], 'the same idempotent producer request id');
  assert.equal(cli.readJson(cli.wc(11, 'pw_producer.json')).liveReceipt.baseNonce, 2);
  await live.prepareLiveBurn(11);
  assert.equal(h.requests.length, 2, 'complete now: nothing is replayed');
});

test('a pw_producer.json of another burn is never taken for this one', async () => {
  const h = fixture(12);
  cli.writeJson(cli.wc(12, 'pw_producer.json'), { producerRequestId: 'burn:an-earlier-burn', blockReceipt: { blockNumber: 1 }, liveReceipt: { baseNonce: 0 } });
  const out = await live.prepareLiveBurn(12);
  assert.deepEqual(h.events, ['post', 'settle']);
  assert.notEqual(out.producerRequestId, 'burn:an-earlier-burn');
  assert.deepEqual(out.blockReceipt, BURN_BLOCK);
});

// ── stagePayoutArtifacts: the payout proof of exactly this burn ─────────────────────────────────
test('the payout proof is written for the native driver and reused on retry', async () => {
  fixture(20);
  let generated = 0;
  producer.liveBurnPayoutArtifacts = async (ch, id, desc, signer) => {
    generated++;
    assert.equal(ch, 20); assert.ok(id.startsWith('burn:')); assert.equal(desc.token, 'descriptor');
    assert.equal(signer, '0x00000000000000000000000000000000000000Ef', 'the L1 signer proves the payout');
    return payout();
  };
  assert.deepEqual(await live.stagePayoutArtifacts(20), payout());
  assert.deepEqual(cli.readJson(cli.wc(20, 'pw_artifacts.json')), payout());
  assert.deepEqual(await live.stagePayoutArtifacts(20), payout());
  assert.equal(generated, 1, 'a retry reuses the exact proof pinned by the native payout journal');
});

test('a payout anchored after the burn block is accepted (the channel kept advancing)', async () => {
  fixture(21);
  // Anchored well after the burn block, at the head a validity candidate ends at.
  const later = payout({ anchor: { blockNumber: 40, generation: 41 } });
  producer.liveBurnPayoutArtifacts = async () => later;
  assert.deepEqual(await live.stagePayoutArtifacts(21), later);
  assert.deepEqual(cli.readJson(cli.wc(21, 'pw_artifacts.json')), later);
});

test('a payout anchored exactly at the burn block is accepted', async () => {
  fixture(22);
  const atBurn = payout({ anchor: { blockNumber: BURN_BLOCK.blockNumber, generation: BURN_BLOCK.generation } });
  producer.liveBurnPayoutArtifacts = async () => atBurn;
  assert.deepEqual(await live.stagePayoutArtifacts(22), atBurn);
});

for (const [name, change] of [
  ['an anchor block before the burn block', p => { p.producerAnchor.blockNumber = BURN_BLOCK.blockNumber - 1; }],
  ['an anchor generation before the burn', p => { p.producerAnchor.generation = BURN_BLOCK.generation - 1; }],
  ['a different nullifier', p => { p.withdrawal.nullifier = '0xabcdef02'; }],
  ['a different aux commitment', p => { p.withdrawal.auxData = '0xa0b1c3'; }],
  ['a different recipient', p => { p.withdrawal.recipient = '0x00000000000000000000000000000000000000ac'; }],
  ['a different token', p => { p.withdrawal.tokenIndex = 0; }],
  ['a different prover', p => { p.withdrawalProver = '0x00000000000000000000000000000000000000aa'; }],
  ['a zero amount', p => { p.withdrawal.amount = '0'; }],
  ['a non-decimal amount', p => { p.withdrawal.amount = '0x10'; }],
  ['a negative amount', p => { p.withdrawal.amount = '-5'; }],
  ['no producer anchor', p => { delete p.producerAnchor; }],
]) {
  test(`a payout proof with ${name} is refused and the saved evidence is kept`, async () => {
    fixture(23);
    const file = cli.wc(23, 'pw_artifacts.json');
    // A saved, non-matching proof (an earlier prover): regenerated, never reused.
    const stale = payout({ withdrawalProver: 'old-operator' });
    cli.writeJson(file, stale);
    const changed = payout();
    change(changed);
    producer.liveBurnPayoutArtifacts = async () => changed;
    await assert.rejects(live.stagePayoutArtifacts(23), /payout proof does not match the burn/);
    assert.deepEqual(cli.readJson(file), stale, 'a refused proof never overwrites the saved file');
    producer.liveBurnPayoutArtifacts = async () => payout();
    assert.deepEqual(await live.stagePayoutArtifacts(23), payout());
    assert.deepEqual(cli.readJson(file), payout());
  });
}

test('a saved payout proof of an earlier burn is not reused for a new burn', async () => {
  fixture(24);
  cli.writeJson(cli.wc(24, 'pw_artifacts.json'), payout({ withdrawal: { nullifier: '0x01d' } }));
  let generated = 0;
  producer.liveBurnPayoutArtifacts = async () => { generated++; return payout(); };
  assert.deepEqual(await live.stagePayoutArtifacts(24), payout());
  assert.equal(generated, 1);
});

test('only the saved payout proof of the current burn is reported as saved, without proving', async () => {
  fixture(125);
  producer.liveBurnPayoutArtifacts = async () => { throw new Error('savedPayoutArtifacts must never prove'); };
  assert.equal(live.savedPayoutArtifacts(125), null, 'nothing saved yet');
  cli.writeJson(cli.wc(125, 'pw_producer.json'), { producerRequestId: 'x', blockReceipt: { ...BURN_BLOCK }, liveReceipt: { baseNonce: 1 } });
  cli.writeJson(cli.wc(125, 'pw_artifacts.json'), payout({ withdrawal: { nullifier: '0x01d' } }));
  assert.equal(live.savedPayoutArtifacts(125), null, 'a proof left by an earlier burn');
  cli.writeJson(cli.wc(125, 'pw_artifacts.json'), payout({ anchor: { blockNumber: 4 } }));
  assert.equal(live.savedPayoutArtifacts(125), null, 'anchored before the burn block');
  cli.writeJson(cli.wc(125, 'pw_artifacts.json'), payout());
  assert.deepEqual(live.savedPayoutArtifacts(125), payout());
});

test('hex fields match the burn whatever their case', async () => {
  fixture(25);
  const upper = payout({ withdrawal: { nullifier: BURN.withdrawal_nullifier, auxData: BURN.aux_data.toUpperCase().replace('0X', '0x'),
    recipient: BURN.withdrawal_recipient } });
  producer.liveBurnPayoutArtifacts = async () => upper;
  assert.deepEqual(await live.stagePayoutArtifacts(25), upper);
});

test('the daemon\'s refusal while an older validity candidate awaits L1 reaches the caller and stages nothing', async () => {
  fixture(26);
  producer.liveBurnPayoutArtifacts = async () => {
    throw Object.assign(new Error('exit status 1'), { stderr: 'validity candidate pending L1 acknowledgement' });
  };
  await assert.rejects(live.stagePayoutArtifacts(26), e => /validity candidate pending L1 acknowledgement/.test(e.stderr));
  assert.equal(fs.existsSync(cli.wc(26, 'pw_artifacts.json')), false);
});

test('the removed manager settlement entry points are gone', () => {
  assert.deepEqual(Object.keys(live).sort(), ['finalizeSavedPayout', 'prepareLiveBurn', 'savedPayoutArtifacts', 'stagePayoutArtifacts']);
});

// ── finalizeSavedPayout: the journaled native payout driver ─────────────────────────────────────
test('historical-state retry is bounded and preserves calldata arguments and environment', async () => {
  const historical = new Error('cast ["call","contract","--block","10"] BlockOutOfRangeError');
  const calls = [], waits = [], env = { INTMAX_WALLET_ANVIL_MINE: '1', PROOF: 'unchanged' };
  const result = await live.finalizeSavedPayout(7, { rpc: 'local-rpc', env,
    run: (...args) => { calls.push(args); if (calls.length < 3) throw historical; return 'landed'; },
    wait: async ms => waits.push(ms) });
  assert.equal(result, 'landed');
  assert.deepEqual(waits, [1000, 2000]);
  for (const args of calls) assert.deepEqual(args, [7, ['pw-finalize', 'local-rpc'], env]);
  let attempts = 0;
  await assert.rejects(live.finalizeSavedPayout(7, { env,
    run: () => { attempts++; throw historical; }, wait: async () => {} }), error => error === historical);
  assert.equal(attempts, 3);
});

for (const [name, env, message] of [
  ['production environment', {}, 'cast ["call","contract","--block","10"] BlockOutOfRangeError'],
  ['unrelated failure', { INTMAX_WALLET_ANVIL_MINE: '1' }, 'transaction rejected'],
  ['nonhistorical RPC call', { INTMAX_WALLET_ANVIL_MINE: '1' }, 'cast ["send"] BlockOutOfRangeError'],
]) {
  test(`payout never automatically retries ${name}`, async () => {
    let calls = 0, waits = 0;
    await assert.rejects(live.finalizeSavedPayout(7, { env,
      run: () => { calls++; throw new Error(message); }, wait: async () => { waits++; } }));
    assert.equal(calls, 1); assert.equal(waits, 0);
  });
}
