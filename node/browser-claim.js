'use strict';

// Public/browser withdrawal-claim transaction builder and reconciler.
//
// The browser keeps the Regev witness inside wallet WASM and signs the L1 transactions with the
// leaf-bound recipient account.  This module is deliberately keyless: it re-reads one immutable
// Manager/Rollup/Verifier/close-funding-materializer authority, validates the exported public
// artifact with the same strict decoder used by the delegate, and returns exact calldata. Reconciliation validates that local
// transaction body when it exists, while allowing a permissionless sibling/wrapper only when one
// exact finalized Manager event and receipt-block state prove the same semantic action. A web relay
// can therefore help an untrusted browser without ever learning either private key or accepting
// economic/contract authority in a request body.

const {
  Contract,
  Interface,
  JsonRpcProvider,
  ZeroAddress,
  ZeroHash,
  getAddress,
  isHexString,
  keccak256,
  solidityPacked,
} = require('ethers');

const {
  MANAGER_CLAIM_ABI,
  SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR,
  SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR,
  validateClaimArtifact,
} = require('./delegate/claim-settlement');

const NULLIFIER_PAYOUT_FUNCTION = 'claimWithdrawalCredit(bytes32)';
const NULLIFIER_PAYOUT_EVENT = 'WithdrawalClaimed(bytes32,address,uint32,uint256)';

// Deliberately remove every legacy aggregate payout fragment inherited from the delegate ABI.
// A browser must never accidentally resolve an old overload after a rolling deployment.
const BROWSER_MANAGER_ABI = [
  ...MANAGER_CLAIM_ABI.filter((fragment) => (
    fragment.name !== 'claimWithdrawalCredit'
      && fragment.name !== 'WithdrawalClaimed'
      && fragment.name !== 'withdrawalPayouts'
  )),
  { type: 'function', name: 'registry', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'verifier', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  {
    type: 'event', name: 'WithdrawalClaimAccepted', anonymous: false,
    inputs: [
      { name: 'closeIntentDigest', type: 'bytes32', indexed: true },
      { name: 'withdrawalNullifier', type: 'bytes32', indexed: true },
      { name: 'memberPkG', type: 'bytes32', indexed: true },
      { name: 'recipient', type: 'address', indexed: false },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'tokenIndex', type: 'uint32', indexed: false },
    ],
  },
  {
    type: 'event', name: 'WithdrawalClaimed', anonymous: false,
    inputs: [
      { name: 'withdrawalNullifier', type: 'bytes32', indexed: true },
      { name: 'recipient', type: 'address', indexed: true },
      { name: 'tokenIndex', type: 'uint32', indexed: true },
      { name: 'amount', type: 'uint256', indexed: false },
    ],
  },
  {
    type: 'function', name: 'withdrawalPayouts', stateMutability: 'view',
    inputs: [{ name: 'withdrawalNullifier', type: 'bytes32' }],
    outputs: [
      { name: 'recipient', type: 'address' },
      { name: 'tokenIndex', type: 'uint32' },
      { name: 'amount', type: 'uint256' },
    ],
  },
  {
    type: 'function', name: 'claimWithdrawalCredit', stateMutability: 'nonpayable',
    inputs: [{ name: 'withdrawalNullifier', type: 'bytes32' }],
    outputs: [{ name: 'amount', type: 'uint256' }],
  },
  {
    type: 'event', name: 'ChannelFundsPulled', anonymous: false,
    inputs: [
      { name: 'tokenIndex', type: 'uint32', indexed: true },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'totalReceived', type: 'uint256', indexed: false },
    ],
  },
];

const MANAGER_INTERFACE = new Interface(BROWSER_MANAGER_ABI);
const DEVNET_CHAIN_ID = 31337;
const OPERATION_DOMAIN = '0x494d4243'; // "IMBC" — INTMAX browser claim.

function canonicalAddress(value, label) {
  let address;
  try { address = getAddress(value); } catch (_) { throw new Error(`${label} must be a 20-byte address`); }
  if (address === ZeroAddress) throw new Error(`${label} must not be the zero address`);
  return address.toLowerCase();
}

function canonicalTokenSlot(value) {
  if (typeof value === 'string' && !/^(0|[1-9])$/.test(value)) {
    throw new Error('tokenSlot must be a canonical integer in 0..9');
  }
  const slot = Number(value);
  if (!Number.isSafeInteger(slot) || slot < 0 || slot > 9) {
    throw new Error('tokenSlot must be a canonical integer in 0..9');
  }
  return slot;
}

function canonicalTxHash(value, label = 'transaction hash') {
  if (!isHexString(value, 32)) throw new Error(`${label} must be 32 bytes`);
  return String(value).toLowerCase();
}

function sameHex(left, right) {
  return String(left || '').toLowerCase() === String(right || '').toLowerCase();
}

function requireSafeChainId(value) {
  const chainId = Number(value);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error('chainId must be a positive safe integer');
  return chainId;
}

function requireChannelId(value) {
  const channelId = Number(value);
  if (!Number.isSafeInteger(channelId) || channelId < 0 || channelId > 0xffffffff) {
    throw new Error('channelId must be uint32');
  }
  return channelId;
}

function browserClaimOperationId(authority, nullifier) {
  return keccak256(solidityPacked(
    ['bytes4', 'uint256', 'address', 'address', 'uint32', 'bytes32'],
    [
      OPERATION_DOMAIN,
      authority.chainId,
      authority.manager,
      canonicalAddress(authority.closeFundingMaterializer, 'close-funding materializer'),
      authority.channelId,
      canonicalTxHash(nullifier, 'withdrawal nullifier'),
    ],
  ));
}

function claimPublicRecord(authority, claim, mleAbiVersion, submitWithdrawalClaimSelector) {
  return {
    schemaVersion: 1,
    operationId: browserClaimOperationId(authority, claim.withdrawalNullifier),
    authority: { ...authority },
    mleAbiVersion,
    submitWithdrawalClaimSelector,
    claim: {
      closeIntentDigest: String(claim.closeIntentDigest).toLowerCase(),
      memberPkG: String(claim.memberPkG).toLowerCase(),
      recipient: canonicalAddress(claim.recipient, 'claim recipient'),
      userAmountDigest: String(claim.userAmountDigest).toLowerCase(),
      amount: String(claim.amount),
      tokenSlot: Number(claim.tokenSlot),
      tokenIndex: Number(claim.tokenIndex),
      withdrawalNullifier: String(claim.withdrawalNullifier).toLowerCase(),
    },
  };
}

function validateExactTransaction(tx, expected, expectedSender) {
  if (!tx) return false;
  if (!sameHex(tx.to, expected.to)) throw new Error('observed transaction targets a different manager');
  if (!sameHex(tx.data, expected.data)) throw new Error('observed transaction calldata differs from the prepared action');
  if (BigInt(tx.value || 0) !== BigInt(expected.value || 0)) throw new Error('observed transaction carries an unexpected value');
  if (expectedSender && !sameHex(tx.from, expectedSender)) {
    throw new Error('observed transaction was not signed by the leaf-bound recipient');
  }
  return true;
}

function exactManagerEventEntries(logs, managerAddress, eventName, predicate) {
  const expectedEvent = MANAGER_INTERFACE.getEvent(eventName);
  const matches = [];
  for (const log of logs || []) {
    if (!sameHex(log.address, managerAddress)) continue;
    if (!Array.isArray(log.topics) || !sameHex(log.topics[0], expectedEvent.topicHash)) continue;
    let parsed;
    try { parsed = MANAGER_INTERFACE.parseLog(log); } catch (_) {
      throw new Error(`pinned Manager emitted malformed ${expectedEvent.name} evidence`);
    }
    if (parsed && parsed.fragment.topicHash === expectedEvent.topicHash
        && (!predicate || predicate(parsed.args))) matches.push({ log, parsed });
  }
  return matches;
}

function eventFromReceipt(receipt, managerAddress, eventName, expectedTxHash, predicate) {
  const expectedEvent = MANAGER_INTERFACE.getEvent(eventName);
  const txHash = canonicalTxHash(expectedTxHash);
  const matches = exactManagerEventEntries(
    (receipt && receipt.logs) || [], managerAddress, eventName, predicate,
  );
  for (const { log } of matches) {
    if (log.removed
        || !sameHex(log.transactionHash, txHash)
        || !sameHex(log.blockHash, receipt.blockHash)
        || Number(log.blockNumber) !== Number(receipt.blockNumber)) {
      throw new Error(`Manager ${expectedEvent.name} log is not bound to the reconciled receipt`);
    }
  }
  if (matches.length !== 1) throw new Error(`finalized transaction must emit exactly one matching ${expectedEvent.name}`);
  return matches[0].parsed;
}

function receiptEvidence(receipt) {
  return JSON.stringify({
    hash: String(receipt && (receipt.hash || receipt.transactionHash) || '').toLowerCase(),
    blockHash: String(receipt && receipt.blockHash || '').toLowerCase(),
    blockNumber: receipt && receipt.blockNumber == null ? null : Number(receipt.blockNumber),
    status: receipt && receipt.status == null ? null : Number(receipt.status),
    logs: ((receipt && receipt.logs) || []).map((log) => ({
      address: String(log.address || '').toLowerCase(),
      topics: Array.isArray(log.topics) ? log.topics.map((topic) => String(topic).toLowerCase()) : null,
      data: String(log.data || '').toLowerCase(),
      transactionHash: String(log.transactionHash || '').toLowerCase(),
      blockHash: String(log.blockHash || '').toLowerCase(),
      blockNumber: log.blockNumber == null ? null : Number(log.blockNumber),
      index: log.index == null && log.logIndex == null ? null : Number(log.index ?? log.logIndex),
      removed: Boolean(log.removed),
    })),
  });
}

function transactionEvidence(transaction) {
  if (!transaction) return null;
  return JSON.stringify({
    hash: String(transaction.hash || '').toLowerCase(),
    blockHash: String(transaction.blockHash || '').toLowerCase(),
    blockNumber: transaction.blockNumber == null ? null : Number(transaction.blockNumber),
    index: transaction.index == null && transaction.transactionIndex == null
      ? null : Number(transaction.index ?? transaction.transactionIndex),
    nonce: transaction.nonce == null ? null : Number(transaction.nonce),
    from: String(transaction.from || '').toLowerCase(),
    to: String(transaction.to || '').toLowerCase(),
    data: String(transaction.data || '').toLowerCase(),
    value: BigInt(transaction.value || 0).toString(),
  });
}

function acceptedEventMatches(args, claim) {
  return sameHex(args.closeIntentDigest, claim.closeIntentDigest)
    && sameHex(args.withdrawalNullifier, claim.withdrawalNullifier)
    && sameHex(args.memberPkG, claim.memberPkG)
    && sameHex(args.recipient, claim.recipient)
    && BigInt(args.amount) === BigInt(claim.amount)
    && Number(args.tokenIndex) === Number(claim.tokenIndex);
}

class BrowserClaimCoordinator {
  constructor({ rpcUrl, authority, provider, contractFactory } = {}) {
    if (!authority || typeof authority !== 'object') throw new Error('browser claim authority is required');
    this.authority = {
      chainId: requireSafeChainId(authority.chainId),
      channelId: requireChannelId(authority.channelId),
      manager: canonicalAddress(authority.manager, 'settlement manager'),
      rollup: canonicalAddress(authority.rollup, 'settlement rollup'),
      verifier: canonicalAddress(authority.verifier, 'settlement verifier'),
      closeFundingMaterializer: canonicalAddress(
        authority.closeFundingMaterializer,
        'close-funding materializer',
      ),
      startBlock: authority.startBlock == null ? 0 : Number(authority.startBlock),
    };
    if (!Number.isSafeInteger(this.authority.startBlock) || this.authority.startBlock < 0) {
      throw new Error('settlement authority startBlock must be a non-negative safe integer');
    }
    this.provider = provider || new JsonRpcProvider(rpcUrl);
    this.contractFactory = contractFactory || ((address) => new Contract(address, BROWSER_MANAGER_ABI, this.provider));
  }

  async durableBlock() {
    const network = await this.provider.getNetwork();
    if (BigInt(network.chainId) !== BigInt(this.authority.chainId)) {
      throw new Error(`claim RPC chain id ${network.chainId} differs from bound ${this.authority.chainId}`);
    }
    const tag = this.authority.chainId === DEVNET_CHAIN_ID ? 'latest' : 'finalized';
    const block = await this.provider.getBlock(tag);
    if (!block || !Number.isSafeInteger(Number(block.number)) || !isHexString(block.hash, 32)) {
      throw new Error(`claim RPC has no canonical ${tag} block`);
    }
    if (Number(block.number) < this.authority.startBlock) {
      throw new Error('durable claim head predates the settlement activation block');
    }
    return { number: Number(block.number), hash: String(block.hash).toLowerCase(), source: tag };
  }

  requireSameDurableBlock(expected, observed, label = 'claim RPC read') {
    if (!expected || !observed
        || Number(observed.number) !== Number(expected.number)
        || !sameHex(observed.hash, expected.hash)
        || observed.source !== expected.source) {
      throw new Error(`${label} crossed a changed durable chain head`);
    }
    return observed;
  }

  async assertDurableBlockUnchanged(expected, label) {
    return this.requireSameDurableBlock(expected, await this.durableBlock(), label);
  }

  async readContext() {
    const durable = await this.durableBlock();
    const manager = this.contractFactory(this.authority.manager);
    const at = { blockTag: durable.number };
    const [
      channelIdRaw, statusRaw, registryRaw, verifierRaw,
      closeIntentDigest, finalChannelStateDigest, finalBalanceStateH1, tokenCountRaw,
    ] = await Promise.all([
      manager.channelId(at), manager.channelStatus(at), manager.registry(at), manager.verifier(at),
      manager.finalizedCloseIntentDigest(at), manager.finalizedChannelStateDigest(at),
      manager.finalizedBalanceStateH1(at), manager.finalizedTokenCount(at),
    ]);
    if (Number(channelIdRaw) !== this.authority.channelId) throw new Error('manager channel id differs from durable authority');
    if (Number(statusRaw) !== 2) throw new Error('settlement manager is not Closed at the durable head');
    if (canonicalAddress(registryRaw, 'manager registry') !== this.authority.rollup) {
      throw new Error('manager registry differs from the backed rollup');
    }
    if (canonicalAddress(verifierRaw, 'manager verifier') !== this.authority.verifier) {
      throw new Error('manager verifier differs from the durable settlement verifier');
    }
    for (const [value, label] of [
      [closeIntentDigest, 'finalized close digest'],
      [finalChannelStateDigest, 'finalized channel-state digest'],
      [finalBalanceStateH1, 'finalized balance H1'],
    ]) {
      if (!isHexString(value, 32) || sameHex(value, ZeroHash)) throw new Error(`${label} is incomplete`);
    }
    const tokenCount = Number(tokenCountRaw);
    if (!Number.isSafeInteger(tokenCount) || tokenCount < 1 || tokenCount > 10) {
      throw new Error('manager finalized token count is outside 1..10');
    }
    const tokenRegistry = (await Promise.all(
      Array.from({ length: tokenCount }, (_, i) => manager.finalizedTokenRegistry(i, at)),
    )).map((value) => Number(value));
    if (tokenRegistry.some((value) => !Number.isSafeInteger(value) || value < 0 || value > 0xffffffff)
        || new Set(tokenRegistry).size !== tokenRegistry.length) {
      throw new Error('manager finalized token registry is malformed or duplicated');
    }
    await this.assertDurableBlockUnchanged(durable, 'manager close-context read');
    return {
      authority: { ...this.authority },
      durable,
      finalized: {
        channelId: this.authority.channelId,
        closeIntentDigest: String(closeIntentDigest).toLowerCase(),
        finalChannelStateDigest: String(finalChannelStateDigest).toLowerCase(),
        finalBalanceStateH1: String(finalBalanceStateH1).toLowerCase(),
        tokenCount,
        tokenRegistry,
      },
    };
  }

  async finalizedEventFromLog(log, durable, eventName, predicate, label) {
    const blockNumber = Number(log && log.blockNumber);
    if (!Number.isSafeInteger(blockNumber)
        || blockNumber < this.authority.startBlock || blockNumber > durable.number
        || !isHexString(log && log.blockHash, 32) || log.removed) {
      throw new Error(`${label} event is outside the canonical durable range`);
    }
    const txHash = canonicalTxHash(log.transactionHash);
    const observed = await this.finalizedReceipt(txHash);
    this.requireSameDurableBlock(durable, observed.durable, `${label} receipt`);
    if (observed.status !== 'finalized'
        || Number(observed.receipt.blockNumber) !== blockNumber
        || !sameHex(observed.receipt.blockHash, log.blockHash)) {
      throw new Error(`${label} event is not bound to one finalized canonical receipt`);
    }
    eventFromReceipt(
      observed.receipt,
      this.authority.manager,
      eventName,
      txHash,
      predicate,
    );
    return { observed, txHash };
  }

  async validateAcceptedSemanticReceipt(claim, observed, txHash) {
    if (observed.status !== 'finalized') {
      throw new Error('withdrawal acceptance receipt is not finalized');
    }
    eventFromReceipt(
      observed.receipt,
      this.authority.manager,
      'WithdrawalClaimAccepted',
      txHash,
      (args) => acceptedEventMatches(args, claim),
    );
    const blockTag = Number(observed.receipt.blockNumber);
    const manager = this.contractFactory(this.authority.manager);
    const [used, payoutRaw] = await Promise.all([
      manager.usedWithdrawalNullifiers(claim.withdrawalNullifier, { blockTag }),
      manager.withdrawalPayouts(claim.withdrawalNullifier, { blockTag }),
    ]);
    if (!used) throw new Error('acceptance receipt block did not consume the exact withdrawal nullifier');
    const payoutAmount = BigInt(payoutRaw && (payoutRaw.amount ?? payoutRaw[2]) || 0);
    if (payoutAmount !== 0n) {
      const payoutRecipient = payoutRaw && (payoutRaw.recipient ?? payoutRaw[0]);
      const payoutTokenIndex = Number(payoutRaw && (payoutRaw.tokenIndex ?? payoutRaw[1]));
      if (!sameHex(payoutRecipient, claim.recipient)
          || payoutTokenIndex !== Number(claim.tokenIndex)
          || payoutAmount !== BigInt(claim.amount)) {
        throw new Error('acceptance receipt-block payout economics differ from the exact claim');
      }
    }
    await this.assertDurableBlockUnchanged(observed.durable, 'acceptance receipt-block getter reconciliation');
  }

  async validatePayoutSemanticReceipt(claim, observed, txHash) {
    if (observed.status !== 'finalized') throw new Error('withdrawal payout receipt is not finalized');
    eventFromReceipt(
      observed.receipt,
      this.authority.manager,
      NULLIFIER_PAYOUT_EVENT,
      txHash,
      (args) => sameHex(args.withdrawalNullifier, claim.withdrawalNullifier)
        && sameHex(args.recipient, claim.recipient)
        && Number(args.tokenIndex) === Number(claim.tokenIndex)
        && BigInt(args.amount) === BigInt(claim.amount),
    );
    const blockTag = Number(observed.receipt.blockNumber);
    const manager = this.contractFactory(this.authority.manager);
    const [used, payoutRaw] = await Promise.all([
      manager.usedWithdrawalNullifiers(claim.withdrawalNullifier, { blockTag }),
      manager.withdrawalPayouts(claim.withdrawalNullifier, { blockTag }),
    ]);
    if (!used) throw new Error('payout receipt block does not retain the consumed withdrawal nullifier');
    if (BigInt(payoutRaw && (payoutRaw.amount ?? payoutRaw[2]) || 0) !== 0n) {
      throw new Error('finalized nullifier-scoped payout remains live at its payout receipt block');
    }
    await this.assertDurableBlockUnchanged(observed.durable, 'payout receipt-block getter reconciliation');
  }

  async findAccepted(claim, durable) {
    const manager = this.contractFactory(this.authority.manager);
    if (!await manager.usedWithdrawalNullifiers(claim.withdrawalNullifier, { blockTag: durable.number })) {
      await this.assertDurableBlockUnchanged(durable, 'withdrawal-nullifier read');
      return null;
    }
    const topics = MANAGER_INTERFACE.encodeFilterTopics('WithdrawalClaimAccepted', [
      claim.closeIntentDigest, claim.withdrawalNullifier, claim.memberPkG,
    ]);
    const logs = await this.provider.getLogs({
      address: this.authority.manager,
      topics,
      fromBlock: this.authority.startBlock,
      toBlock: durable.number,
    });
    const exact = exactManagerEventEntries(
      logs,
      this.authority.manager,
      'WithdrawalClaimAccepted',
      (args) => acceptedEventMatches(args, claim),
    );
    if (exact.length !== 1) {
      throw new Error('used withdrawal nullifier has no unique exact finalized acceptance event');
    }
    const { observed, txHash } = await this.finalizedEventFromLog(
      exact[0].log,
      durable,
      'WithdrawalClaimAccepted',
      (args) => acceptedEventMatches(args, claim),
      'withdrawal acceptance',
    );
    await this.validateAcceptedSemanticReceipt(claim, observed, txHash);
    await this.assertDurableBlockUnchanged(durable, 'withdrawal-acceptance reconciliation');
    return {
      txHash,
      blockNumber: Number(observed.receipt.blockNumber),
      blockHash: String(observed.receipt.blockHash).toLowerCase(),
    };
  }

  async findPayout(claim, durable) {
    const topics = MANAGER_INTERFACE.encodeFilterTopics(NULLIFIER_PAYOUT_EVENT, [
      claim.withdrawalNullifier,
      claim.recipient,
      claim.tokenIndex,
    ]);
    const logs = await this.provider.getLogs({
      address: this.authority.manager,
      topics,
      fromBlock: this.authority.startBlock,
      toBlock: durable.number,
    });
    const payoutMatches = (args) => sameHex(args.withdrawalNullifier, claim.withdrawalNullifier)
      && sameHex(args.recipient, claim.recipient)
      && Number(args.tokenIndex) === Number(claim.tokenIndex)
      && BigInt(args.amount) === BigInt(claim.amount);
    const exact = exactManagerEventEntries(
      logs, this.authority.manager, NULLIFIER_PAYOUT_EVENT, payoutMatches,
    );
    if (exact.length > 1) throw new Error('withdrawal nullifier has multiple exact finalized payout events');
    if (exact.length === 0) {
      await this.assertDurableBlockUnchanged(durable, 'withdrawal-payout log scan');
      return null;
    }
    const { observed, txHash } = await this.finalizedEventFromLog(
      exact[0].log,
      durable,
      NULLIFIER_PAYOUT_EVENT,
      payoutMatches,
      'withdrawal payout',
    );
    await this.validatePayoutSemanticReceipt(claim, observed, txHash);
    await this.assertDurableBlockUnchanged(durable, 'withdrawal-payout reconciliation');
    return {
      txHash,
      blockNumber: Number(observed.receipt.blockNumber),
      blockHash: String(observed.receipt.blockHash).toLowerCase(),
      amount: String(claim.amount),
      tokenIndex: Number(claim.tokenIndex),
      recipient: canonicalAddress(claim.recipient, 'claim recipient'),
      withdrawalNullifier: canonicalTxHash(claim.withdrawalNullifier, 'withdrawal nullifier'),
    };
  }

  async prepare(artifact, tokenSlot) {
    const slot = canonicalTokenSlot(tokenSlot);
    const context = await this.readContext();
    const claimedRecipient = artifact && artifact.claim && artifact.claim.recipient;
    const {
      claim, proof, mleAbiVersion, submitWithdrawalClaimSelector,
    } = validateClaimArtifact(
      artifact,
      context.finalized,
      claimedRecipient,
      slot,
      { allowLegacyMle: this.authority.chainId === DEVNET_CHAIN_ID },
    );
    if (canonicalAddress(claim.recipient, 'claim recipient') === ZeroAddress) throw new Error('claim recipient is zero');
    const record = claimPublicRecord(
      this.authority,
      claim,
      mleAbiVersion,
      submitWithdrawalClaimSelector,
    );
    const data = MANAGER_INTERFACE.encodeFunctionData(submitWithdrawalClaimSelector, [claim, proof]);
    const transaction = { to: this.authority.manager, data, value: '0x0' };
    const accepted = await this.findAccepted(record.claim, context.durable);
    if (!accepted) {
      // Run the exact verifier at the same durable state before asking a wallet to sign.  This is
      // intentionally an eth_call; it cannot consume the nullifier or mutate Manager state.
      const manager = this.contractFactory(this.authority.manager);
      await manager.getFunction(submitWithdrawalClaimSelector).staticCall(claim, proof, {
        from: record.claim.recipient,
        blockTag: context.durable.number,
      });
    }
    await this.assertDurableBlockUnchanged(context.durable, 'withdrawal-claim preparation');
    return {
      ...record,
      finalized: context.finalized,
      durable: context.durable,
      submitDataHash: keccak256(data),
      status: accepted ? 'accepted' : 'prepared',
      accepted,
      ...(accepted ? {} : { transaction }),
    };
  }

  async finalizedReceipt(txHash) {
    const hash = canonicalTxHash(txHash);
    const [receipt, transaction, durable] = await Promise.all([
      this.provider.getTransactionReceipt(hash),
      this.provider.getTransaction(hash),
      this.durableBlock(),
    ]);
    if (transaction && canonicalTxHash(transaction.hash, 'observed transaction hash') !== hash) {
      throw new Error('RPC returned a different transaction than the requested hash');
    }
    if (!receipt) {
      await this.assertDurableBlockUnchanged(durable, 'transaction lookup');
      return { status: transaction ? 'pending' : 'missing', transaction, durable };
    }
    if (canonicalTxHash(receipt.hash || receipt.transactionHash, 'receipt transaction hash') !== hash) {
      throw new Error('RPC returned a receipt for a different transaction hash');
    }
    if (!transaction) throw new Error('mined transaction body is unavailable for exact reconciliation');
    if (Number(receipt.blockNumber) > durable.number) {
      await this.assertDurableBlockUnchanged(durable, 'non-final transaction lookup');
      return { status: 'mined', receipt, transaction, durable };
    }
    const canonical = await this.provider.getBlock(Number(receipt.blockNumber));
    if (!canonical || !sameHex(canonical.hash, receipt.blockHash)) {
      throw new Error('transaction receipt is not in the canonical chain');
    }
    // Re-read after the canonicality check so a moving/reorged finalized view cannot be stitched.
    const [second, secondTransaction] = await Promise.all([
      this.provider.getTransactionReceipt(hash),
      this.provider.getTransaction(hash),
    ]);
    if (!second || !secondTransaction
        || canonicalTxHash(second.hash || second.transactionHash, 'second receipt transaction hash') !== hash
        || canonicalTxHash(secondTransaction.hash, 'second observed transaction hash') !== hash
        || receiptEvidence(second) !== receiptEvidence(receipt)
        || transactionEvidence(secondTransaction) !== transactionEvidence(transaction)) {
      throw new Error('transaction or receipt evidence changed during finalized reconciliation');
    }
    await this.assertDurableBlockUnchanged(durable, 'finalized transaction reconciliation');
    if (Number(second.status) !== 1) {
      return { status: 'failed', receipt: second, transaction: secondTransaction, durable };
    }
    return { status: 'finalized', receipt: second, transaction: secondTransaction, durable };
  }

  async reconcileSubmission(record, txHash) {
    const observed = await this.finalizedReceipt(txHash);
    if (observed.transaction) {
      if (!sameHex(keccak256(observed.transaction.data), record.submitDataHash)) {
        throw new Error('claim transaction calldata hash differs from the durable prepared claim');
      }
      validateExactTransaction(observed.transaction, {
        to: record.authority.manager,
        data: record.transaction && record.transaction.data,
        value: '0x0',
      }, record.claim.recipient);
    }
    if (observed.status !== 'finalized') {
      const adopted = await this.findAccepted(record.claim, observed.durable);
      if (adopted) return { status: 'accepted', ...adopted };
      return { status: observed.status, txHash: canonicalTxHash(txHash) };
    }
    const hash = canonicalTxHash(txHash);
    await this.validateAcceptedSemanticReceipt(record.claim, observed, hash);
    return {
      status: 'accepted',
      txHash: hash,
      blockNumber: Number(observed.receipt.blockNumber),
      blockHash: String(observed.receipt.blockHash).toLowerCase(),
    };
  }

  async nextPayout(record) {
    const context = await this.readContext();
    const accepted = await this.findAccepted(record.claim, context.durable);
    if (!accepted) throw new Error('withdrawal claim is not accepted at the durable head');
    const manager = this.contractFactory(this.authority.manager);
    const at = { blockTag: context.durable.number };
    const tokenIndex = Number(record.claim.tokenIndex);
    const [payoutRaw, creditRaw, receivedRaw, paidRaw] = await Promise.all([
      manager.withdrawalPayouts(record.claim.withdrawalNullifier, at),
      manager.withdrawalCredits(tokenIndex, record.claim.recipient, at),
      manager.receivedChannelFunds(tokenIndex, at),
      manager.totalCreditedOut(tokenIndex, at),
    ]);
    const credit = BigInt(creditRaw);
    const received = BigInt(receivedRaw);
    const paid = BigInt(paidRaw);
    if (paid > received) throw new Error('manager payout accounting exceeds received backing');
    const exactAmount = BigInt(record.claim.amount);
    const payoutRecipient = payoutRaw && (payoutRaw.recipient ?? payoutRaw[0]);
    const payoutTokenIndex = Number(payoutRaw && (payoutRaw.tokenIndex ?? payoutRaw[1]));
    const payoutAmount = BigInt(payoutRaw && (payoutRaw.amount ?? payoutRaw[2]));
    if (payoutAmount === 0n) {
      const payout = await this.findPayout(record.claim, context.durable);
      if (!payout) {
        throw new Error('accepted withdrawal has no live nullifier-scoped payout and no finalized payout event');
      }
      return { status: 'paid', accepted, payout };
    }
    if (!sameHex(payoutRecipient, record.claim.recipient)
        || payoutTokenIndex !== tokenIndex || payoutAmount !== exactAmount) {
      throw new Error('manager nullifier-scoped payout differs from the accepted browser claim');
    }
    if (credit < exactAmount) throw new Error('manager credit is smaller than this exact accepted browser claim');
    let kind;
    let data;
    let amount;
    if (received - paid < exactAmount) {
      kind = 'funding';
      data = tokenIndex === 0
        ? MANAGER_INTERFACE.encodeFunctionData('pullChannelFunds', [])
        : MANAGER_INTERFACE.encodeFunctionData('pullChannelTokenFunds', [tokenIndex]);
      amount = null;
    } else {
      kind = 'payout';
      data = MANAGER_INTERFACE.encodeFunctionData(NULLIFIER_PAYOUT_FUNCTION, [record.claim.withdrawalNullifier]);
      amount = exactAmount.toString();
      // Nullifier-scoped no-mutation simulation from the leaf-bound recipient at the durable state.
      // Old aggregate/exact-amount overloads are intentionally absent from this interface.
      await manager[NULLIFIER_PAYOUT_FUNCTION].staticCall(record.claim.withdrawalNullifier, {
        from: record.claim.recipient,
        blockTag: context.durable.number,
      });
    }
    await this.assertDurableBlockUnchanged(context.durable, 'next payout action read');
    return {
      status: 'action-required',
      kind,
      amount,
      accepted,
      durable: context.durable,
      transaction: { to: this.authority.manager, data, value: '0x0' },
      dataHash: keccak256(data),
    };
  }

  async reconcileAction(record, action, txHash) {
    if (!action || !['funding', 'payout'].includes(action.kind) || !isHexString(action.dataHash, 32)) {
      throw new Error('durable browser claim has no prepared action');
    }
    const observed = await this.finalizedReceipt(txHash);
    if (observed.transaction) {
      if (!sameHex(keccak256(observed.transaction.data), action.dataHash)) {
        throw new Error('browser action calldata hash differs from the durable prepared action');
      }
      validateExactTransaction(observed.transaction, {
        to: record.authority.manager,
        data: action.data,
        value: '0x0',
      }, record.claim.recipient);
    }
    if (action.kind === 'payout' && BigInt(action.amount) !== BigInt(record.claim.amount)) {
      throw new Error('durable payout action amount differs from the exact accepted claim');
    }
    if (observed.status !== 'finalized') {
      if (action.kind === 'payout') {
        const adopted = await this.findPayout(record.claim, observed.durable);
        if (adopted) return { status: 'paid', ...adopted };
      }
      return { status: observed.status, txHash: canonicalTxHash(txHash) };
    }
    if (action.kind === 'funding') {
      eventFromReceipt(observed.receipt, this.authority.manager, 'ChannelFundsPulled', canonicalTxHash(txHash), (args) => (
        Number(args.tokenIndex) === Number(record.claim.tokenIndex) && BigInt(args.amount) > 0n
      ));
      return { status: 'funded', txHash: canonicalTxHash(txHash) };
    }
    const hash = canonicalTxHash(txHash);
    await this.validatePayoutSemanticReceipt(record.claim, observed, hash);
    return {
      status: 'paid',
      txHash: hash,
      amount: String(action.amount),
      tokenIndex: Number(record.claim.tokenIndex),
      recipient: record.claim.recipient,
      withdrawalNullifier: record.claim.withdrawalNullifier,
      blockNumber: Number(observed.receipt.blockNumber),
      blockHash: String(observed.receipt.blockHash).toLowerCase(),
    };
  }

  /// Revalidate a journaled `paid` record against the current stable durable chain before a
  /// relay short-circuits. A local terminal marker is a cache, never payout authority.
  async revalidatePaid(record) {
    if (!record || record.status !== 'paid' || !record.payout) {
      throw new Error('durable paid claim record is incomplete');
    }
    const context = await this.readContext();
    const payout = await this.findPayout(record.claim, context.durable);
    if (!payout) throw new Error('journaled browser payout is absent from the durable chain');
    for (const [field, normalize = String] of [
      ['txHash', (value) => canonicalTxHash(value)],
      ['blockHash', (value) => canonicalTxHash(value, 'payout block hash')],
      ['blockNumber', Number],
      ['amount', String],
      ['tokenIndex', Number],
      ['recipient', (value) => canonicalAddress(value, 'payout recipient')],
      ['withdrawalNullifier', (value) => canonicalTxHash(value, 'withdrawal nullifier')],
    ]) {
      if (normalize(record.payout[field]) !== normalize(payout[field])) {
        throw new Error(`journaled browser payout ${field} differs from the durable chain`);
      }
    }
    return payout;
  }
}

module.exports = {
  BROWSER_MANAGER_ABI,
  MANAGER_INTERFACE,
  BrowserClaimCoordinator,
  NULLIFIER_PAYOUT_EVENT,
  NULLIFIER_PAYOUT_FUNCTION,
  SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR,
  SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR,
  browserClaimOperationId,
  canonicalAddress,
  canonicalTokenSlot,
  validateExactTransaction,
};
