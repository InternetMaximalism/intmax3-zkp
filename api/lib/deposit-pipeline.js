const fs = require('fs');
const { cli, wc, RPC, readJson } = require('./cli');
const producer = require('./block-producer');
const { flushPublishedHead } = require('./producer-head');

async function flushLastDepositImport(ch) {
  const artifactPath = wc(ch, 'l1_import_cosigned.json');
  if (!fs.existsSync(artifactPath)) return null;
  const artifact = readJson(artifactPath);
  if (!artifact.fundImportState || !artifact.bundleApplyState) return null;
  return producer.syncOffchainHeads([
    artifact.fundImportState,
    artifact.bundleApplyState,
  ]);
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
    cli(ch, args);
    artifact = readJson(artifactPath);
  }

  if (!artifact.fundImportState || !artifact.bundleApplyState) {
    throw new Error('l1_import_cosigned.json lacks the two N-of-N signed import states');
  }
  const headSyncReceipt = await producer.syncOffchainHeads([
    artifact.fundImportState,
    artifact.bundleApplyState,
  ]);
  return { deposit, producerReceipt, headSyncReceipt, artifact };
}

module.exports = { importL1Deposit };
