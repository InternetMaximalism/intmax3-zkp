'use strict';

// Cross-process lock fixture. It prints safe metadata only; neither the raw bytes nor key are sent
// over stdout. The fixed key is test-only and has no value outside this isolated fake provider.
const { Transaction, Wallet } = require('ethers');
const { SignedTransactionOutbox } = require('../../delegate/signed-transaction-outbox');

const [directory, lockRoot, actionId, data] = process.argv.slice(2);
const transactions = new Map();
const provider = {
  async getNetwork() { return { chainId: 31337n }; },
  async getTransactionCount() { return 4; },
  async getFeeData() { return { maxFeePerGas: 100n, maxPriorityFeePerGas: 10n }; },
  async estimateGas() { return 50_000n; },
  async getTransactionReceipt() { return null; },
  async getTransaction(hash) { return transactions.get(String(hash).toLowerCase()) || null; },
  async broadcastTransaction(raw) {
    const decoded = Transaction.from(raw);
    transactions.set(decoded.hash.toLowerCase(), { hash: decoded.hash });
    return { hash: decoded.hash };
  },
};

async function main() {
  const outbox = new SignedTransactionOutbox({
    directory,
    lockRoot,
    chainId: 31337,
    signer: new Wallet(`0x${'11'.repeat(32)}`),
    provider,
    allowUnfinalizedDevnet: true,
  });
  try {
    const result = await outbox.send({
      actionId,
      to: '0x1000000000000000000000000000000000000001',
      data,
      value: 0,
    });
    process.stdout.write(`${JSON.stringify({ nonce: result.nonce, transactionHash: result.transactionHash })}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ code: error && error.code, message: error && error.message })}\n`);
  }
}

main().catch((error) => {
  process.stderr.write(`${String(error && error.stack || error)}\n`);
  process.exitCode = 1;
});
