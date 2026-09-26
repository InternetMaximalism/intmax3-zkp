'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-live-'));
process.env.INTMAX_WORK_DIR = root;
const cli = require('../../api/lib/cli'), producer = require('../../api/lib/block-producer');
const live = require('../../api/lib/partial-withdrawal-live');
test.after(() => fs.rmSync(root, { recursive: true, force: true }));
function fixture(ch) {
  const head = { channelId: ch, digest: 'burn', balanceState: { settledTxChain: 'post-burn' } };
  cli.writeJson(cli.wc(ch, 'burn_cosigned.json'), head);
  cli.writeJson(cli.wc(ch, 'burn_payload.json'), { proposedNextState: head });
  cli.writeJson(cli.wc(ch, 'burn_descriptor.json'), { token: 'descriptor' });
  cli.writeJson(cli.wc(ch, 'channel_snapshot.json'), { state: head });
  fs.writeFileSync(cli.wc(ch, 'balance_vd.bin'), Buffer.from([1, 2]));
  fs.writeFileSync(cli.wc(ch, 'channel_attestation.bin'), Buffer.from([9]));
  const events = [];
  producer.postInterChannel = async () => { events.push('post'); return { requestId: 'receipt' }; };
  producer.liveSettleInterChannel = async () => { events.push('settle'); return { baseNonce: 1 }; };
  const backing = { signedHead: head, baseHead: { channelId: ch, settledTxChain: 'post-burn' },
    signedHeadExitKit: { backingPublicInputs: { channelId: ch, settledTxChain: 'post-burn', anchorBlockNumber: 5, finalizedExtendedStateCommitment: 'root' } },
    balanceVerifierData: [1, 2], balanceAttestation: { balanceProof: [3, 4] } };
  producer.liveBackingArtifact = async () => backing;
  cli.rollupOf = () => 'rollup';
  cli.sh = (_, args) => args[2].startsWith('isFinalized') ? 'true' : '5';
  return { events, backing };
}
test('stages the exact live proof without replacing genesis; restores producer receipt on retry', async () => {
  const h = fixture(7);
  const env = await live.stageSubmitProof(7);
  assert.equal(env.PW_BALANCE_PROOF_FILE, 'pw_balance_attestation.bin');
  assert.equal(env.PW_BACKING_ARTIFACT_FILE, 'pw_live_backing.json');
  assert.deepEqual(cli.readJson(cli.wc(7, env.PW_BACKING_ARTIFACT_FILE)), h.backing);
  assert.deepEqual([...fs.readFileSync(cli.wc(7, env.PW_BALANCE_PROOF_FILE))], [3, 4]);
  assert.deepEqual([...fs.readFileSync(cli.wc(7, 'channel_attestation.bin'))], [9]);
  assert.equal(cli.readJson(cli.wc(7, 'pw_producer.json')).liveReceipt.baseNonce, 1);
  await live.stageSubmitProof(7);
  assert.deepEqual(h.events, ['post', 'settle', 'post', 'settle']);
});
test('a later signed head cannot silently replace the burn', async () => {
  const h = fixture(8);
  cli.writeJson(cli.wc(8, 'channel_snapshot.json'), { state: { digest: 'other' } });
  await assert.rejects(live.stageSubmitProof(8), /exact signed burn/);
  assert.deepEqual(h.events, []);
});
test('wrong live chain or verifier is rejected before staging proof bytes', async () => {
  const h = fixture(9);
  h.backing.baseHead.settledTxChain = 'genesis';
  await assert.rejects(live.stageSubmitProof(9), /post-burn head/);
  h.backing.baseHead.settledTxChain = 'post-burn';
  h.backing.balanceVerifierData = [8];
  await assert.rejects(live.stageSubmitProof(9), /pinned channel verifier/);
  assert.equal(fs.existsSync(cli.wc(9, 'pw_balance_attestation.bin')), false);
});
test('payout uses recovered exact producer identity and writes artifacts for the native driver', async () => {
  fixture(10);
  const anchor = { blockNumber: 5, bpSigChain: 'bp', entryHash: 'entry', extendedStateCommitment: 'root', generation: 6, timestamp: 100 };
  producer.postInterChannel = async () => ({ ...anchor, requestId: 'receipt' });
  const withdrawal = { amount: '5', recipient: 'recipient', tokenIndex: 0, nullifier: 'nullifier', auxData: 'aux' };
  cli.writeJson(cli.wc(10, 'pw_auth.json'), { withdrawal_amount: '5', withdrawal_recipient: 'recipient',
    withdrawal_token_index: 0, withdrawal_nullifier: 'nullifier', withdrawal_aux_data: 'aux' });
  cli.l1SignerAddress = () => 'operator';
  let generated = 0;
  producer.liveBurnPayoutArtifacts = async (ch, id, desc, signer) => {
    generated++;
    assert.equal(ch, 10); assert.ok(id.startsWith('burn:')); assert.equal(desc.token, 'descriptor');
    assert.equal(signer, 'operator'); return { withdrawal, withdrawalProver: signer, producerAnchor: anchor, proof: 'verified-artifacts' };
  };
  await live.stagePayoutArtifacts(10);
  assert.equal(cli.readJson(cli.wc(10, 'pw_artifacts.json')).proof, 'verified-artifacts');
  await live.stagePayoutArtifacts(10);
  assert.equal(generated, 1, 'retry must reuse the exact proof pinned by the native payout journal');
  anchor.entryHash = 'different-entry';
  await live.stagePayoutArtifacts(10);
  assert.equal(generated, 2, 'a different producer anchor must not reuse the saved proof');
});

test('unfinalized burn fails before expensive close proving and remains retryable', async () => {
  fixture(11);
  cli.sh = (_, args) => args[2].startsWith('isFinalized') ? 'false' : '0';
  await assert.rejects(live.stageSubmitProof(11), e => e.status === 409 && /burn block 5, L1 finalized block 0/.test(e.message));
  assert.equal(fs.existsSync(cli.wc(11, 'pw_balance_attestation.bin')), false);
});

test('submit resumes the same on-chain pending, authorized or paid burn; never a different burn', () => {
  const ch = 12;
  const auth = { manager: 'manager', auth_digest: 'auth', withdrawal_nullifier: 'nullifier',
    withdrawal_aux_data: 'aux', withdrawal_recipient: 'recipient', withdrawal_token_index: 0 };
  const burn = { withdrawal_nullifier: 'nullifier', aux_data: 'aux', withdrawal_recipient: 'recipient', token_index: 0 };
  cli.writeJson(cli.wc(ch, 'pw_auth.json'), auth);
  cli.writeJson(cli.wc(ch, 'last_burn.json'), burn);
  cli.writeJson(cli.wc(ch, 'settlement.json'), { manager: 'manager' });
  cli.rollupOf = () => 'rollup';
  let phase = 'pending', reads = 0;
  cli.sh = (_, args) => {
    reads++;
    if (args[2].startsWith('pendingPartialWithdrawalAuthDigest')) return 'auth';
    return String((phase === 'pending' && args[2].startsWith('partialWithdrawalPending'))
      || (phase === 'authorized' && args[2].startsWith('partialWithdrawalAuthorized'))
      || (phase === 'paid' && args[2].startsWith('withdrawalNullifierUsed')));
  };
  for (phase of ['pending', 'authorized', 'paid']) assert.deepEqual(live.resumeSubmittedAuth(ch), auth);
  phase = 'absent'; assert.equal(live.resumeSubmittedAuth(ch), null);
  cli.writeJson(cli.wc(ch, 'last_burn.json'), { ...burn, withdrawal_nullifier: 'new-burn' });
  reads = 0; assert.equal(live.resumeSubmittedAuth(ch), null); assert.equal(reads, 0);
});

test('settlement interruption preserves receipt and retries the identical producer request', async () => {
  fixture(20);
  const requests = [];
  let fail = true;
  producer.postInterChannel = async (_head, _payload, _descriptor, id) => {
    requests.push(id); return { requestId: id, blockNumber: 5 };
  };
  producer.liveSettleInterChannel = async () => {
    if (fail) throw new Error('injected settlement interruption');
    return { baseNonce: 2 };
  };
  await assert.rejects(live.stageSubmitProof(20), /injected settlement/);
  assert.equal(cli.readJson(cli.wc(20, 'pw_producer.json')).liveReceipt, null);
  assert.equal(fs.existsSync(cli.wc(20, 'pw_balance_attestation.bin')), false);
  fail = false;
  await live.stageSubmitProof(20);
  assert.equal(requests.length, 2);
  assert.equal(requests[0], requests[1]);
  assert.equal(cli.readJson(cli.wc(20, 'pw_producer.json')).liveReceipt.baseNonce, 2);
});

for (const [name, change] of [
  ['missing exit kit', backing => { delete backing.signedHeadExitKit; }],
  ['wrong exit channel', backing => { backing.signedHeadExitKit.backingPublicInputs.channelId++; }],
  ['wrong exit chain', backing => { backing.signedHeadExitKit.backingPublicInputs.settledTxChain = 'other'; }],
  ['wrong signed head', backing => { backing.signedHead = { ...backing.signedHead, digest: 'other' }; }],
  ['wrong base channel', backing => { backing.baseHead.channelId++; }],
]) {
  test(`submit rejects ${name} without replacing already staged artifacts`, async () => {
    const { backing } = fixture(21);
    const proofPath = cli.wc(21, 'pw_balance_attestation.bin');
    const backingPath = cli.wc(21, 'pw_live_backing.json');
    fs.writeFileSync(proofPath, Buffer.from([91, 92]));
    cli.writeJson(backingPath, { previous: true });
    change(backing);
    await assert.rejects(live.stageSubmitProof(21));
    assert.deepEqual([...fs.readFileSync(proofPath)], [91, 92]);
    assert.deepEqual(cli.readJson(backingPath), { previous: true });
  });
}

test('finalized root alone is insufficient until its anchor height is finalized', async () => {
  fixture(22);
  cli.sh = (_, args) => args[2].startsWith('isFinalized') ? 'true' : '4';
  await assert.rejects(live.stageSubmitProof(22), error => error.status === 409);
  assert.equal(fs.existsSync(cli.wc(22, 'pw_balance_attestation.bin')), false);
  cli.sh = (_, args) => args[2].startsWith('isFinalized') ? 'true' : '5';
  await live.stageSubmitProof(22);
  assert.deepEqual([...fs.readFileSync(cli.wc(22, 'pw_balance_attestation.bin'))], [3, 4]);
});

function payoutFixture(ch) {
  fixture(ch);
  const anchor = { blockNumber: 5, bpSigChain: 'bp', entryHash: 'entry', extendedStateCommitment: 'root', generation: 6, timestamp: 100 };
  producer.postInterChannel = async () => ({ ...anchor });
  cli.l1SignerAddress = () => 'operator';
  const withdrawal = { amount: '18446744073709551615', recipient: 'recipient', tokenIndex: 55, nullifier: 'nf', auxData: 'aux' };
  cli.writeJson(cli.wc(ch, 'pw_auth.json'), { withdrawal_amount: withdrawal.amount, withdrawal_recipient: withdrawal.recipient,
    withdrawal_token_index: withdrawal.tokenIndex, withdrawal_nullifier: withdrawal.nullifier, withdrawal_aux_data: withdrawal.auxData });
  return { withdrawal, producerAnchor: anchor, withdrawalProver: 'operator' };
}
for (const field of ['amount', 'recipient', 'tokenIndex', 'nullifier', 'auxData', 'withdrawalProver', 'entryHash', 'generation']) {
  test(`payout rejects a regenerated artifact with changed ${field} and retains saved evidence`, async () => {
    const correct = payoutFixture(23);
    const file = cli.wc(23, 'pw_artifacts.json');
    const stale = { ...structuredClone(correct), withdrawalProver: 'old-operator' };
    cli.writeJson(file, stale);
    const changed = structuredClone(correct);
    if (field === 'withdrawalProver') changed.withdrawalProver = 'attacker';
    else if (field === 'entryHash' || field === 'generation') changed.producerAnchor[field] = 'other';
    else changed.withdrawal[field] = field === 'amount' ? '18446744073709551614' : 'other';
    producer.liveBurnPayoutArtifacts = async () => changed;
    await assert.rejects(live.stagePayoutArtifacts(23), /does not match/);
    assert.deepEqual(cli.readJson(file), stale);
    producer.liveBurnPayoutArtifacts = async () => correct;
    assert.deepEqual(await live.stagePayoutArtifacts(23), correct);
  });
}

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
