'use strict';

const path = require('node:path');
const { Interface, JsonRpcProvider, getAddress } = require('ethers');
const { SignedTransactionOutbox } = require('../delegate/signed-transaction-outbox');

const DEPOSIT_ABI = [
  'function deposit(bytes32 recipient,uint32 tokenIndex,uint256 amount,bytes32 auxData)',
  'event Deposited(uint64 indexed depositIndex,address depositor,bytes32 recipient,uint32 tokenIndex,uint256 amount,bytes32 auxData,bytes32 newDepositHashChain)',
];
const iface = new Interface(DEPOSIT_ABI);
const ZERO = `0x${'00'.repeat(32)}`;

function makeDepositSender({ rpcUrl, chainId, root, signer, provider = null, outbox = null, confirmations = 1 }) {
  const authority = getAddress(signer.address);
  const chain = BigInt(chainId);
  const rpc = provider || new JsonRpcProvider(rpcUrl);
  const journal = outbox || new SignedTransactionOutbox({
    directory: path.join(root, 'api-deposit-outbox', `${chain}-${authority.slice(2).toLowerCase()}`),
    lockRoot: root,
    chainId: chain,
    signer,
    provider: rpc,
    confirmations,
    allowUnfinalizedDevnet: chain === 31337n,
  });
  function calldata(intent) {
    return iface.encodeFunctionData('deposit', [intent.depositRecipient, intent.tokenIndex, intent.amount, ZERO]);
  }
  function exactDeposit(receipt, intent) {
    const matching = [];
    for (const log of receipt.logs || []) {
      if (String(log.address).toLowerCase() !== intent.rollup.toLowerCase()) continue;
      let decoded;
      try { decoded = iface.parseLog(log); } catch (_) { continue; }
      if (decoded && decoded.name === 'Deposited') matching.push(decoded.args);
    }
    return matching.length === 1
      && getAddress(matching[0].depositor) === authority
      && matching[0].recipient.toLowerCase() === intent.depositRecipient.toLowerCase()
      && matching[0].tokenIndex === BigInt(intent.tokenIndex)
      && matching[0].amount === BigInt(intent.amount)
      && matching[0].auxData.toLowerCase() === ZERO;
  }
  return {
    status(actionId) { return journal.status(actionId); },
    async send(intent, replacement = null) {
      return journal.send({ actionId: intent.actionId, to: getAddress(intent.rollup),
        data: calldata(intent), value: intent.tokenIndex === 0 ? BigInt(intent.amount) : 0n, replacement });
    },
    async confirm(intent, transactionHash) {
      const receipt = await rpc.getTransactionReceipt(transactionHash);
      if (!receipt || Number(receipt.status) !== 1) {
        const error = new Error(receipt ? 'deposit transaction reverted; reconcile or explicitly replace this exact intent'
          : 'deposit transaction is pending; retry the same request');
        error.code = receipt ? 'DEPOSIT_REVERTED' : 'DEPOSIT_PENDING';
        throw error;
      }
      if (!exactDeposit(receipt, intent)) throw new Error('deposit receipt differs from the exact operator-funded intent');
      await journal.markFinalized(intent.actionId, {
        transactionHash, blockNumber: receipt.blockNumber, blockHash: receipt.blockHash,
      }, ({ receipt: canonicalReceipt }) => exactDeposit(canonicalReceipt, intent));
      return receipt;
    },
  };
}

module.exports = { makeDepositSender, DEPOSIT_ABI };
