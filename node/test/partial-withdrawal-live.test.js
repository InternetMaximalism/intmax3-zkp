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
