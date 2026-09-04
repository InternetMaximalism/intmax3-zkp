const fs = require('fs');
const { cli, wc, RPC, readJson } = require('./cli');
const producer = require('./block-producer');
const { flushPublishedHead } = require('./producer-head');
const { cliWithPreparedExitKit } = require('./exit-kit');

async function flushLastDepositImport(ch) {
  const artifactPath = wc(ch, 'l1_import_cosigned.json');
  if (!fs.existsSync(artifactPath)) return null;
  const artifact = readJson(artifactPath);
  if (!artifact.fundImportState || !artifact.bundleApplyState) return null;
  const depositPath = wc(ch, 'producer_deposit.json');
  const snapshotPath = wc(ch, 'channel_snapshot.json');
  if (!fs.existsSync(depositPath) || !fs.existsSync(snapshotPath)) {
    throw new Error('deposit recovery is missing producer_deposit.json or channel_snapshot.json');
  }
  const deposit = readJson(depositPath);
  const producerReceipt = await producer.postDeposit(deposit);
  const liveReceipt = await producer.liveReceiveConfiguredDeposit(ch, producerReceipt, deposit);
  const snapshot = readJson(snapshotPath);
  const liveStatus = await producer.liveBindSnapshot(ch, snapshot);
  const headSyncReceipt = await producer.syncOffchainHeads([
    artifact.fundImportState,
    artifact.bundleApplyState,
  ]);
  return { deposit, producerReceipt, liveReceipt, liveStatus, headSyncReceipt, artifact };
}

// One crash-recoverable production ordering for every API deposit import:
//   verified L1 receipt -> durable producer deposit block -> channel N-of-N import -> durable
//   off-chain head sync. The Rust inspector owns ABI parsing and emits the exact producer schema.
async function importL1Deposit(ch, recipientSlot, txHash, { allowUnboundDepositor = true } = {}) {
  // Complete a prior crash window before posting another L1 deposit. The two import states must be
  // replayed together because the final bundle head extends the intermediate fund-import digest.
  await flushLastDepositImport(ch);
  await flushPublishedHead(ch);
  cli(ch, ['inspect-l1-deposit', String(txHash), RPC, 'producer_deposit.json']);
  const deposit = readJson(wc(ch, 'producer_deposit.json'));
  const producerReceipt = await producer.postDeposit(deposit);
  // Phase 1 is durable before the N-of-N channel import. This consumes the exact journaled L1
  // leaf into the resident balance proof, but deliberately withholds public head adoption until
  // the resulting proof is bound to the signed channel snapshot below.
  const liveReceipt = await producer.liveReceiveConfiguredDeposit(ch, producerReceipt, deposit);

  const artifactPath = wc(ch, 'l1_import_cosigned.json');
  let artifact = null;
  if (fs.existsSync(artifactPath)) {
    const existing = readJson(artifactPath);
    if (
      String(existing.txHash || '').toLowerCase() === String(txHash).toLowerCase() &&
      Number(existing.intmaxBlockNumber) === Number(producerReceipt.blockNumber)
    ) {
      artifact = existing;
    }
  }

  if (!artifact) {
    const args = [
      'cosign-l1-deposit-import',
      String(recipientSlot),
      String(txHash),
      RPC,
      'l1_import_cosigned.json',
      `--intmax-block-number=${producerReceipt.blockNumber}`,
    ];
    if (allowUnboundDepositor) args.push('--allow-unbound-depositor');
    // Signer-independent exit: the deposit moves the channel's fund vector and settle chain, so
    // the co-signers' exit kit for the exact import state is proved BEFORE they sign it.
    await cliWithPreparedExitKit(ch, args);
    artifact = readJson(artifactPath);
  }

  if (!artifact.fundImportState || !artifact.bundleApplyState) {
    throw new Error('l1_import_cosigned.json lacks the two N-of-N signed import states');
  }
  const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
  const liveStatus = await producer.liveBindSnapshot(ch, snapshot);
  const headSyncReceipt = await producer.syncOffchainHeads([
    artifact.fundImportState,
    artifact.bundleApplyState,
  ]);
  return { deposit, producerReceipt, liveReceipt, liveStatus, headSyncReceipt, artifact };
}

module.exports = { importL1Deposit };
