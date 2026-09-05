'use strict';

const path = require('node:path');
const cliModule = require('./cli');
const producer = require('./block-producer');
const preflight = require('./deposit-preflight');
const { makeDepositSender } = require('../../node/common/l1-deposit-outbox');

function readOptional(file) {
  try { return cliModule.readJson(file); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

function operationFile(ch, actionId) {
  return cliModule.wc(ch, path.join('l1-deposits', `${actionId.slice('deposit:'.length)}.json`));
}

function sender() {
  const chainId = cliModule.chainId();
  const address = cliModule.l1SignerAddress();
  const root = process.env.INTMAX_L1_SIGNER_LOCK_ROOT || path.join(cliModule.WORK, 'l1-signer-locks');
  const signer = {
    address,
    // cast mktx signs only; the shared outbox persists/decodes the raw transaction before any
    // network broadcast. The encrypted keystore password never enters argv or a JS journal.
    async signTransaction(transaction) {
      return cliModule.sh('cast', ['mktx', transaction.to, transaction.data,
        '--chain', String(transaction.chainId), '--nonce', String(transaction.nonce),
        '--value', String(transaction.value), '--gas-limit', String(transaction.gasLimit),
        '--gas-price', String(transaction.maxFeePerGas),
        '--priority-gas-price', String(transaction.maxPriorityFeePerGas),
        ...cliModule.l1SignerArgs(), '--rpc-url', cliModule.RPC, '--json'], { stdio: 'pipe' }).trim();
    },
  };
  return { address, chainId, instance: makeDepositSender({ rpcUrl: cliModule.RPC, chainId, root, signer }) };
}

function requestBinding(ch, { recipientSlot, tokenIndex, amount, requestId }) {
  const slot = recipientSlot == null ? null : preflight.recipientSlot(recipientSlot);
  const index = preflight.tokenIndex(tokenIndex == null ? 0 : tokenIndex);
  const value = preflight.depositAmount(amount);
  if (requestId != null && (typeof requestId !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(requestId))) {
    throw new Error('deposit requestId must be 1..128 alphanumeric/._:- characters');
  }
  // Without an explicit client id, repeating the same request replays the same deposit even after
  // import. A new identical payment uses a new requestId; an HTTP timeout never authorizes it.
  const intent = { ch, recipientSlot: slot, tokenIndex: index, amount: value };
  const actionId = producer.stableRequestId('deposit', requestId == null ? intent : { ch, requestId });
  return { intent, actionId };
}

async function spendDeposit(ch, request, dependencies = {}) {
  const { intent, actionId } = requestBinding(ch, request);
  const file = operationFile(ch, actionId);
  const pendingPath = cliModule.wc(ch, 'pending_deposit.json');
  const pending = readOptional(pendingPath);
  let operation = readOptional(file);
  if (operation && producer.canonicalJson(operation.intent) !== producer.canonicalJson(intent)) {
    throw new Error('deposit requestId already belongs to a different amount, token, or recipient');
  }
  if (pending && pending.status !== 'imported' && pending.actionId !== actionId) {
    throw new Error(`an earlier L1 deposit needs import/reconciliation before a new payment (${pending.txHash || pending.actionId || 'legacy pending deposit'})`);
  }
  const configured = dependencies.sender || sender();
  const depositor = configured.address.toLowerCase();
  if (!operation) {
    const checked = (dependencies.preflight || preflight.preflightDeposit)(
      ch, intent.recipientSlot, intent.tokenIndex, intent.amount, depositor,
    );
    const backing = cliModule.readJson(cliModule.wc(ch, 'channel_backing.json'));
    if (!/^0x[0-9a-fA-F]{40}$/.test(backing.rollup || '') || /^0x0{40}$/i.test(backing.rollup)) {
      throw new Error('channel backing has no valid rollup');
    }
    const depositRecipient = await producer.livePrepareDepositRecipient(ch);
    if (typeof depositRecipient !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(depositRecipient)
        || /^0x0{64}$/i.test(depositRecipient)) throw new Error('live service returned an invalid deposit recipient');
    operation = { schemaVersion: 1, actionId, intent, status: 'prepared',
      chainId: configured.chainId, depositor, rollup: backing.rollup.toLowerCase(),
      depositRecipient, tokenIndex: intent.tokenIndex, amount: intent.amount,
      recipientSlots: checked.recipientSlots, stateDigest: checked.stateDigest, txHash: null };
    cliModule.writeJson(file, operation);
    cliModule.writeJson(pendingPath, operation);
  }
  if (operation.chainId !== configured.chainId || operation.depositor !== depositor) {
    throw new Error('saved deposit belongs to a different L1 chain or signer');
  }
  if (operation.status === 'imported') {
    repairCompletedPointer(ch, operation);
    return operation;
  }
  try {
    // The native reservation is durable and idempotent. It protects the selected credit capacity
    // from other local signing paths while this exact L1 payment is in flight.
    cliModule.cli(ch, ['reserve-l1-deposit', actionId, String(operation.tokenIndex), operation.amount,
      operation.recipientSlots.join(','), 'l1_deposit_reservation.json', `--recipient=${operation.depositRecipient}`]);
    if (!configured.instance.status(actionId)) {
      const checked = (dependencies.preflight || preflight.preflightDeposit)(ch,
        intent.recipientSlot, operation.tokenIndex, operation.amount, depositor, actionId);
      if (!operation.recipientSlots.every(slot => checked.recipientSlots.includes(slot))) {
        throw new Error('reserved deposit recipient is no longer admissible; no L1 payment was signed');
      }
    }
    const sent = await configured.instance.send(operation);
    operation = { ...operation, status: 'broadcast', txHash: sent.transactionHash };
    cliModule.writeJson(file, operation);
    cliModule.writeJson(pendingPath, operation);
    cliModule.cli(ch, ['bind-l1-deposit-reservation', actionId, operation.txHash]);
    return operation;
  } catch (error) {
    // Raw bytes may already be durable even if broadcast or the caller's journal write failed.
    const saved = configured.instance.status(actionId);
    if (saved && saved.transactionHash) {
      operation = { ...operation, status: 'broadcast', txHash: saved.transactionHash };
      cliModule.writeJson(file, operation);
      cliModule.writeJson(pendingPath, operation);
      // If binding itself failed, retain the exact hash for an explicit retry; never substitute
      // a newly signed payment for it. Import performs this binding again before consuming credit.
    }
    if (error && typeof error === 'object') error.deposit = operation;
    throw error;
  }
}

async function confirmDeposit(ch, operation, slot, dependencies = {}) {
  const selected = preflight.recipientSlot(slot);
  if (!operation.recipientSlots.includes(selected)) throw new Error('recipient slot differs from the pre-spend acceptance decision');
  const configured = dependencies.sender || sender();
  if (operation.chainId !== configured.chainId || operation.depositor !== configured.address.toLowerCase()) {
    throw new Error('saved deposit belongs to a different L1 chain or signer');
  }
  cliModule.cli(ch, ['bind-l1-deposit-reservation', operation.actionId, operation.txHash]);
  await configured.instance.confirm(operation, operation.txHash);
  // A channel can advance while an L1 deposit is pending. Recheck the exact credited slot before
  // proof generation/import; never turn a refusal here into another L1 payment.
  const artifact = readOptional(cliModule.wc(ch, 'l1_import_cosigned.json'));
  const locallyImported = artifact && artifact.fundImportState && artifact.bundleApplyState
    && String(artifact.txHash).toLowerCase() === operation.txHash.toLowerCase();
  if (operation.status !== 'imported' && !locallyImported) {
    (dependencies.preflight || preflight.preflightDeposit)(ch, selected, operation.tokenIndex,
      operation.amount, operation.depositor, operation.actionId);
  }
  return selected;
}

async function importTrackedDeposit(ch, operation, slot, dependencies = {}) {
  const selected = preflight.recipientSlot(slot == null
    ? (operation.importSlot ?? operation.intent.recipientSlot ?? operation.recipientSlots[0]) : slot);
  if (operation.importSlot != null && selected !== operation.importSlot) {
    throw new Error('this deposit import already names a different recipient slot; resume that exact import');
  }
  if (!operation.recipientSlots.includes(selected)) throw new Error('recipient slot differs from the pre-spend acceptance decision');
  if (operation.status === 'imported') {
    repairCompletedPointer(ch, operation);
    return { operation, pipeline: null };
  }
  operation = { ...operation, importSlot: selected };
  cliModule.writeJson(operationFile(ch, operation.actionId), operation);
  cliModule.writeJson(cliModule.wc(ch, 'pending_deposit.json'), operation);
  try {
    await confirmDeposit(ch, operation, selected, dependencies);
    const pipeline = await (dependencies.importL1Deposit || require('./deposit-pipeline').importL1Deposit)(
      ch, selected, operation.txHash, { allowUnboundDepositor: true, depositReservation: operation.actionId },
    );
    return { operation: markImported(ch, operation, selected), pipeline };
  } catch (error) {
    if (error && typeof error === 'object') error.deposit = operation;
    throw error;
  }
}

function depositResponse(operation) {
  return { txHash: operation.txHash, depositor: operation.depositor, tokenIndex: operation.tokenIndex,
    depositRecipient: operation.depositRecipient, actionId: operation.actionId,
    recipientSlots: operation.recipientSlots, depositStatus: operation.status,
    retry: 'Retry with the same requestId and fields, or import this txHash. A new identical payment requires a new requestId.' };
}

function failDeposit(res, error) {
  const pending = error && ['DEPOSIT_PENDING', 'OUTBOX_RECEIPT_NOT_FINALIZED'].includes(error.code);
  return res.status(pending ? 202 : 409).json({ error: String(error.stderr || error.message || error),
    ...(error.deposit ? depositResponse(error.deposit) : {}) });
}

function markImported(ch, operation, slot) {
  const completed = { ...operation, status: 'imported', recipientSlot: slot };
  cliModule.writeJson(operationFile(ch, operation.actionId), completed);
  repairCompletedPointer(ch, completed);
  return completed;
}

function repairCompletedPointer(ch, completed) {
  const pendingPath = cliModule.wc(ch, 'pending_deposit.json');
  const current = readOptional(pendingPath);
  if (current && current.actionId === completed.actionId) cliModule.writeJson(pendingPath, completed);
}

module.exports = { spendDeposit, confirmDeposit, importTrackedDeposit, markImported,
  requestBinding, readOptional, sender, depositResponse, failDeposit };
