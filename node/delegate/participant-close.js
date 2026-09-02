'use strict';
// Delegate-owned L1 close initiation. The settlement manager authenticates a delegate through a
// fixed-depth Merkle proof of (slot, pkG, recipient); this module derives that proof from the
// already WASM-verified signed snapshot and submits it with the recipient's own EVM key.

const crypto = require('crypto');

const {
  Contract,
  JsonRpcProvider,
  Wallet: EthersWallet,
  ZeroHash,
  getAddress,
  isHexString,
  solidityPackedKeccak256,
} = require('ethers');
const { SignedTransactionOutbox } = require('./signed-transaction-outbox');

const PARTICIPANT_TREE_DEPTH = 10;
const MAX_PARTICIPANTS = 1 << PARTICIPANT_TREE_DEPTH;
const PARTICIPANT_LEAF_DOMAIN = '0x494d5052'; // "IMPR"
const PARTICIPANT_NODE_DOMAIN = '0x494d504e'; // "IMPN"
const MANAGER_PARTICIPANT_ABI = [
  'event CloseRequested(address indexed requester, uint64 closeRequestedAt, uint64 closeFreezeNonce)',
  'event CloseSubmitted(bytes32 indexed closeIntentDigest, bytes32 indexed burnTxHash, uint64 indexed closeNonce, uint64 finalEpoch, uint64 closeFreezeNonce, uint256 channelFundAmount, uint64 challengeDeadline, uint64 finalStateVersion, bytes32 finalSettledTxChain)',
  'event CloseCancelled(bytes32 indexed closeIntentDigest, bytes32 indexed revivedChannelStateDigest, uint64 revivedStateVersion)',
  'event CloseFinalized(bytes32 indexed closeIntentDigest, bytes32 indexed burnTxHash, uint64 indexed finalEpoch, uint256 channelFundAmount, uint64 finalStateVersion, bytes32 finalSettledTxChain)',
  'function participantRoot() view returns (bytes32)',
  'function activeParticipantCount() view returns (uint16)',
  'function channelStatus() view returns (uint8)',
  'function currentCloseFreezeNonce() view returns (uint64)',
  'function closeRequestGeneration() view returns (uint64)',
  'function highestCancelledRevivedStateVersion() view returns (uint64)',
  'function finalizedCloseIntentDigest() view returns (bytes32)',
  'function getPendingClose() view returns (tuple(bool active,uint64 closeNonce,uint64 finalEpoch,uint64 finalSmallBlockNumber,uint64 closeFreezeNonce,uint64 challengeDeadline,bytes32 closeIntentDigest,bytes32 finalChannelStateDigest,bytes32 finalBalanceStateH1,uint256[10] channelFundAmounts,uint32[10] tokenRegistry,uint8 tokenCount,bytes32 channelFundIntmaxStateRoot,bytes32 burnTxHash,bytes32 closeWithdrawalDigest,uint64 snapshotMediumBlockNumber,uint64 finalStateVersion,bytes32 finalSettledTxChain,bytes32 finalSettledTxAccumulatorRoot))',
  'function requestCloseAsParticipant(uint16 slot, bytes32 pkG, bytes32[10] siblings, uint64 expectedCurrentCloseFreezeNonce, uint64 expectedHighestCancelledRevivedStateVersion)',
  // Permissionless by contract.  The delegate reuses its recipient signer only as the gas-paying
  // account; no participant authority is implied by this call.
  'function finalizeCloseGuarded(bytes32 expectedCloseIntentDigest, uint64 expectedCloseRequestGeneration)',
];

function aliased(object, camel, snake, label) {
  if (!object || typeof object !== 'object') throw new Error(`snapshot missing ${label}`);
  const a = object[camel];
  const b = object[snake];
  if (a !== undefined && b !== undefined && JSON.stringify(a) !== JSON.stringify(b)) {
    throw new Error(`snapshot has conflicting ${camel}/${snake}`);
  }
  const value = a !== undefined ? a : b;
  if (value === undefined) throw new Error(`snapshot missing ${label}`);
  return value;
}

function boundedCount(value, label) {
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 0 || count > MAX_PARTICIPANTS) {
    throw new Error(`invalid ${label} ${value}`);
  }
  return count;
}

function participantLeaf(slot, pkG, recipient) {
  return solidityPackedKeccak256(
    ['bytes4', 'uint16', 'bytes32', 'address'],
    [PARTICIPANT_LEAF_DOMAIN, slot, pkG, recipient],
  );
}

function participantNode(left, right) {
  return solidityPackedKeccak256(
    ['bytes4', 'bytes32', 'bytes32'],
    [PARTICIPANT_NODE_DOMAIN, left, right],
  );
}

function canonicalExactUint(value, label) {
  const raw = String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error(`${label} must be a canonical unsigned integer`);
  return BigInt(raw).toString();
}

function participantCloseActionId({ chainId, manager, channelId, slot, era }) {
  if (!era || typeof era !== 'object') throw new Error('participant close era is required');
  const checkpoint = era.checkpoint;
  if (!checkpoint || !isHexString(checkpoint.hash, 32)) {
    throw new Error('participant close era requires a hash-authenticated durable checkpoint');
  }
  const cancellation = era.cancelObservation == null ? null : {
    txHash: isHexString(era.cancelObservation.txHash, 32)
      ? String(era.cancelObservation.txHash).toLowerCase()
      : (() => { throw new Error('cancel observation transaction hash must be bytes32'); })(),
    blockNumber: canonicalExactUint(era.cancelObservation.blockNumber, 'cancel observation block number'),
    blockHash: isHexString(era.cancelObservation.blockHash, 32)
      ? String(era.cancelObservation.blockHash).toLowerCase()
      : (() => { throw new Error('cancel observation block hash must be bytes32'); })(),
    logIndex: canonicalExactUint(era.cancelObservation.logIndex, 'cancel observation log index'),
  };
  const restoration = era.restorationCheckpoint == null ? null : {
    blockNumber: canonicalExactUint(
      era.restorationCheckpoint.blockNumber,
      'restoration checkpoint block number',
    ),
    blockHash: isHexString(era.restorationCheckpoint.blockHash, 32)
      ? String(era.restorationCheckpoint.blockHash).toLowerCase()
      : (() => { throw new Error('restoration checkpoint block hash must be bytes32'); })(),
  };
  const identity = {
    schemaVersion: 1,
    chainId: canonicalExactUint(chainId, 'chain id'),
    manager: getAddress(manager).toLowerCase(),
    channelId: canonicalExactUint(channelId, 'channel id'),
    slot: canonicalExactUint(slot, 'participant slot'),
    expectedCurrentCloseFreezeNonce: canonicalExactUint(
      era.expectedCurrentCloseFreezeNonce,
      'expected current close freeze nonce',
    ),
    expectedHighestCancelledRevivedStateVersion: canonicalExactUint(
      era.expectedHighestCancelledRevivedStateVersion,
      'expected highest cancelled revived state version',
    ),
    checkpoint: {
      number: canonicalExactUint(checkpoint.number, 'checkpoint block number'),
      hash: String(checkpoint.hash).toLowerCase(),
    },
    cancelObservation: cancellation,
    restorationCheckpoint: restoration,
  };
  const digest = crypto.createHash('sha256').update(JSON.stringify(identity), 'utf8').digest('hex');
  return `participant-close:${identity.channelId}:${identity.slot}:${digest}`;
}

function buildParticipantCloseProof(snapshot, configuredSlot, configuredRecipient) {
  const state = snapshot && snapshot.state;
  const record = snapshot && snapshot.record;
  const balance = state && aliased(state, 'balanceState', 'balance_state', 'state.balanceState');
  const slot = boundedCount(configuredSlot, 'delegate slot');
  if (slot >= MAX_PARTICIPANTS) throw new Error(`delegate slot ${slot} exceeds participant tree`);

  const recordMembers = boundedCount(aliased(record, 'memberCount', 'member_count', 'record.memberCount'), 'record memberCount');
  const recordDelegates = boundedCount(aliased(record, 'delegateCount', 'delegate_count', 'record.delegateCount'), 'record delegateCount');
  const balanceMembers = boundedCount(aliased(balance, 'memberCount', 'member_count', 'balanceState.memberCount'), 'balance memberCount');
  const balanceDelegates = boundedCount(aliased(balance, 'delegateCount', 'delegate_count', 'balanceState.delegateCount'), 'balance delegateCount');
  if (recordMembers !== balanceMembers || recordDelegates !== balanceDelegates) {
    throw new Error('signed record/balance participant counts disagree');
  }
  const activeParticipantCount = recordMembers + recordDelegates;
  if (activeParticipantCount < 2 || activeParticipantCount > MAX_PARTICIPANTS) {
    throw new Error(`invalid active participant count ${activeParticipantCount}`);
  }
  if (slot >= activeParticipantCount) {
    throw new Error(`delegate slot ${slot} is outside active participant prefix ${activeParticipantCount}`);
  }

  const pkGs = aliased(record, 'memberPkGs', 'member_pk_gs', 'record.memberPkGs');
  const recipients = aliased(balance, 'recipients', 'recipients', 'balanceState.recipients');
  if (!Array.isArray(pkGs) || pkGs.length < activeParticipantCount) {
    throw new Error('signed record does not carry every active participant pkG');
  }
  if (!Array.isArray(recipients) || recipients.length < activeParticipantCount) {
    throw new Error('signed balance state does not carry every active participant recipient');
  }

  const expectedRecipient = getAddress(configuredRecipient);
  const nodes = Array(MAX_PARTICIPANTS).fill(ZeroHash);
  for (let i = 0; i < activeParticipantCount; i += 1) {
    const pkG = String(pkGs[i]);
    if (!isHexString(pkG, 32) || pkG.toLowerCase() === ZeroHash) {
      throw new Error(`invalid active participant pkG at slot ${i}`);
    }
    const recipient = getAddress(recipients[i]);
    if (recipient === getAddress('0x0000000000000000000000000000000000000000')) {
      throw new Error(`zero active participant recipient at slot ${i}`);
    }
    nodes[i] = participantLeaf(i, pkG, recipient);
  }
  const recipient = getAddress(recipients[slot]);
  if (recipient !== expectedRecipient) {
    throw new Error(`configured recipient ${expectedRecipient} differs from signed slot ${slot} recipient ${recipient}`);
  }

  const pkG = String(pkGs[slot]).toLowerCase();
  const siblings = [];
  let index = slot;
  let width = MAX_PARTICIPANTS;
  while (width > 1) {
    siblings.push(nodes[index ^ 1]);
    for (let i = 0; i < width; i += 2) nodes[i >> 1] = participantNode(nodes[i], nodes[i + 1]);
    index >>= 1;
    width >>= 1;
  }
  if (siblings.length !== PARTICIPANT_TREE_DEPTH) throw new Error('participant proof depth mismatch');
  return {
    slot,
    pkG,
    recipient,
    siblings,
    participantRoot: nodes[0],
    activeParticipantCount,
    stateDigest: state && state.digest,
  };
}

function makeParticipantCloser({
  rpcUrl,
  chainId,
  recipient,
  privateKey,
  provider: injectedProvider = null,
  signer: injectedSigner = null,
  outbox: injectedOutbox = null,
  outboxDirectory = null,
  signerLockRoot = null,
  confirmations = 1,
  allowUnfinalizedDevnet = false,
  channelId = null,
  participantSlot = null,
}) {
  if (!privateKey && !injectedSigner && !injectedOutbox) return null;
  const provider = injectedProvider || (injectedOutbox && injectedOutbox.provider) || new JsonRpcProvider(rpcUrl);
  // Never connect this Wallet to a provider. All sends must pass through the raw-byte outbox.
  const signer = injectedSigner || (privateKey ? new EthersWallet(privateKey) : null);
  const signerAddress = injectedOutbox ? injectedOutbox.signerAddress : signer && signer.address;
  const expectedRecipient = getAddress(recipient);
  if (!signerAddress || getAddress(signerAddress) !== expectedRecipient) {
    throw new Error(
      `INTMAX_DELEGATE_L1_PRIVATE_KEY controls ${signerAddress || 'no address'}, not configured recipient ${expectedRecipient}`,
    );
  }
  const expectedChainId = BigInt(chainId);
  const outbox = injectedOutbox || new SignedTransactionOutbox({
    directory: outboxDirectory,
    lockRoot: signerLockRoot,
    chainId: expectedChainId,
    signer,
    provider,
    confirmations,
    allowUnfinalizedDevnet,
  });
  if (getAddress(outbox.signerAddress) !== expectedRecipient) {
    throw new Error('delegate transaction outbox signer differs from the configured recipient');
  }
  async function assertNetwork() {
    const network = await provider.getNetwork();
    if (network.chainId !== expectedChainId) {
      throw new Error(`delegate L1 RPC chain id ${network.chainId} differs from configured ${expectedChainId}`);
    }
  }
  function markDefinitelyNotBroadcast(error) {
    if (error && typeof error === 'object') error.definitelyNotBroadcast = true;
    return error;
  }
  async function recordBroadcast(txHash, onBroadcast, metadata = {}) {
    if (!onBroadcast) return;
    try {
      await onBroadcast(txHash, metadata);
    } catch (error) {
      // The exact raw bytes already exist in the private fsynced outbox. Preserve their hash when
      // the ordinary orchestration Store callback fails; restart never allocates another nonce.
      if (error && typeof error === 'object' && !error.transactionHash) error.transactionHash = txHash;
      throw error;
    }
  }
  async function submitOutbox(actionId, transaction, replacement = null, resumeOnly = false) {
    try {
      return await outbox.send({
        actionId,
        to: transaction.to,
        data: transaction.data,
        value: transaction.value == null ? 0n : transaction.value,
        replacement,
        resumeOnly,
      });
    } catch (error) {
      // A persist/broadcast callback crash is no longer a journal gap: the private outbox has the
      // deterministic hash even if the normal Store did not receive it yet.
      const saved = outbox.status(actionId);
      if (saved && error && typeof error === 'object' && !error.transactionHash) {
        error.transactionHash = saved.transactionHash;
      }
      throw error;
    }
  }
  async function reconcileOneShot(
    actionId,
    semanticObservation,
    expectedOwnTransition,
    expectedSemanticState,
  ) {
    return outbox.settleSuperseded(
      actionId,
      semanticObservation,
      expectedOwnTransition,
      expectedSemanticState,
    );
  }

  function exactManagerEvent(
    managerAddress,
    manager,
    receipt,
    transactionHash,
    eventName,
    expectedLogIndex = null,
  ) {
    const matches = [];
    for (const entry of Array.isArray(receipt && receipt.logs) ? receipt.logs : []) {
      let parsed;
      try {
        if (getAddress(entry.address) !== getAddress(managerAddress)
            || !isHexString(entry.transactionHash, 32)
            || String(entry.transactionHash).toLowerCase() !== String(transactionHash).toLowerCase()) {
          continue;
        }
        parsed = manager.interface.parseLog({ topics: entry.topics, data: entry.data });
      } catch (_) { continue; }
      const index = entry.index == null ? entry.logIndex : entry.index;
      if (parsed && parsed.name === eventName
          && (expectedLogIndex == null || Number(index) === Number(expectedLogIndex))) {
        matches.push(parsed);
      }
    }
    return matches.length === 1 ? matches[0] : null;
  }

  function exactCloseRequestedReceipt(
    managerAddress,
    manager,
    receipt,
    transactionHash,
    expectedNonce = null,
    expectedRequester = signerAddress,
    expectedLogIndex = null,
  ) {
    const parsed = exactManagerEvent(
      managerAddress,
      manager,
      receipt,
      transactionHash,
      'CloseRequested',
      expectedLogIndex,
    );
    if (!parsed || (expectedRequester != null
        && getAddress(parsed.args.requester) !== getAddress(expectedRequester))) return false;
    return expectedNonce == null || BigInt(parsed.args.closeFreezeNonce) === BigInt(expectedNonce);
  }
  return {
    signerAddress,
    chainId: expectedChainId.toString(),
    durableOutbox: true,
    outbox,
    async readRequestEra(managerAddress, checkpoint) {
      await assertNetwork();
      if (!checkpoint || checkpoint.number == null || !isHexString(checkpoint.hash, 32)) {
        throw new Error('participant close requires the delegate durable chain checkpoint');
      }
      const number = Number(canonicalExactUint(checkpoint.number, 'checkpoint block number'));
      if (!Number.isSafeInteger(number)) throw new Error('checkpoint block number is outside exact range');
      const expectedHash = String(checkpoint.hash).toLowerCase();
      const before = await provider.getBlock(number);
      if (!before || String(before.hash).toLowerCase() !== expectedHash) {
        throw new Error('participant close checkpoint is no longer canonical');
      }
      const manager = new Contract(getAddress(managerAddress), MANAGER_PARTICIPANT_ABI, provider);
      const [status, freezeNonce, cancellationFloor] = await Promise.all([
        manager.channelStatus({ blockTag: number }),
        manager.currentCloseFreezeNonce({ blockTag: number }),
        manager.highestCancelledRevivedStateVersion({ blockTag: number }),
      ]);
      const after = await provider.getBlock(number);
      if (!after || String(after.hash).toLowerCase() !== expectedHash) {
        throw new Error('participant close checkpoint changed during era read');
      }
      if (Number(status) !== 0) throw new Error('participant close era is not Active at the durable checkpoint');
      return {
        expectedCurrentCloseFreezeNonce: String(freezeNonce),
        expectedHighestCancelledRevivedStateVersion: String(cancellationFloor),
        checkpoint: { number, hash: expectedHash },
      };
    },
    async requestClose(managerAddress, proof, onBroadcast = null, txOptions = {}) {
      let manager;
      let transaction;
      if (channelId == null || participantSlot == null || !txOptions.era || !txOptions.actionId) {
        throw markDefinitelyNotBroadcast(new Error(
          'participant close requires an explicit channel/slot era and era-specific action id',
        ));
      }
      const actionId = participantCloseActionId({
        chainId: expectedChainId,
        manager: managerAddress,
        channelId,
        slot: participantSlot,
        era: txOptions.era,
      });
      if (txOptions.actionId !== actionId) {
        throw markDefinitelyNotBroadcast(new Error('participant close action id does not match its canonical era'));
      }
      try {
        await assertNetwork();
        if (Number(proof.slot) !== Number(participantSlot)) {
          throw new Error('participant close proof slot differs from configured participant slot');
        }
        manager = new Contract(getAddress(managerAddress), MANAGER_PARTICIPANT_ABI, provider);
        transaction = await manager.requestCloseAsParticipant.populateTransaction(
          proof.slot,
          proof.pkG,
          proof.siblings,
          txOptions.era.expectedCurrentCloseFreezeNonce,
          txOptions.era.expectedHighestCancelledRevivedStateVersion,
        );
        // Preflight is only for a new action. Once raw bytes exist, a restart must reconcile them
        // even when their prior execution has already changed manager state and staticCall reverts.
        if (!outbox.status(actionId)) {
          const [onChainRoot, onChainCount] = await Promise.all([
            manager.participantRoot(),
            manager.activeParticipantCount(),
          ]);
          if (String(onChainRoot).toLowerCase() !== String(proof.participantRoot).toLowerCase()) {
            throw new Error('signed snapshot participant root differs from settlement manager');
          }
          if (Number(onChainCount) !== proof.activeParticipantCount) {
            throw new Error('signed snapshot participant count differs from settlement manager');
          }
          const currentFreezeNonce = await manager.currentCloseFreezeNonce();
          if (String(currentFreezeNonce) !== String(txOptions.era.expectedCurrentCloseFreezeNonce)) {
            throw new Error('participant close freeze nonce changed after the durable era snapshot');
          }
          const cancellationFloor = await manager.highestCancelledRevivedStateVersion();
          if (String(cancellationFloor)
              !== String(txOptions.era.expectedHighestCancelledRevivedStateVersion)) {
            throw new Error('participant close cancellation floor changed after the durable era snapshot');
          }
          await manager.requestCloseAsParticipant.staticCall(
            proof.slot,
            proof.pkG,
            proof.siblings,
            txOptions.era.expectedCurrentCloseFreezeNonce,
            txOptions.era.expectedHighestCancelledRevivedStateVersion,
          );
        }
      } catch (error) {
        throw markDefinitelyNotBroadcast(error);
      }
      const submitted = await submitOutbox(actionId, transaction, txOptions.replacement || null);
      await recordBroadcast(submitted.transactionHash, onBroadcast, { actionId });
      return { txHash: submitted.transactionHash, outboxActionId: actionId, phase: submitted.phase };
    },
    async finalizeCloseGuarded(managerAddress, expectedCloseIntentDigest, onBroadcast = null, txOptions = {}) {
      let manager;
      let transaction;
      if (!txOptions.actionId) {
        throw markDefinitelyNotBroadcast(new Error(
          'guarded finalize requires the exact Store close-era action id',
        ));
      }
      const actionId = txOptions.actionId;
      let expectedCloseRequestGeneration;
      try {
        expectedCloseRequestGeneration = canonicalExactUint(
          txOptions.expectedCloseRequestGeneration,
          'expected close request generation',
        );
      } catch (error) {
        throw markDefinitelyNotBroadcast(error);
      }
      const requiredPrefix = `close-finalize:${channelId}:`;
      if (channelId == null || !actionId.startsWith(requiredPrefix)
          || !actionId.endsWith(`:generation:${expectedCloseRequestGeneration}`)) {
        throw markDefinitelyNotBroadcast(new Error(
          'guarded finalize action id must include the exact Store close observation and generation',
        ));
      }
      try {
        await assertNetwork();
        if (!isHexString(expectedCloseIntentDigest, 32)) {
          throw new Error('expected close-intent digest must be bytes32');
        }
        manager = new Contract(getAddress(managerAddress), MANAGER_PARTICIPANT_ABI, provider);
        transaction = await manager.finalizeCloseGuarded.populateTransaction(
          expectedCloseIntentDigest,
          expectedCloseRequestGeneration,
        );
        // The state machine invokes this only after an authenticated durable block timestamp is
        // strictly greater than the observed deadline.  staticCall catches a same-block
        // replacement/cancel before spending gas; the contract re-checks the current pending close
        // and its own deadline atomically when the transaction executes.
        if (!outbox.status(actionId)) {
          const generation = await manager.closeRequestGeneration();
          if (String(generation) !== expectedCloseRequestGeneration) {
            throw new Error('close request generation changed after the durable close snapshot');
          }
          await manager.finalizeCloseGuarded.staticCall(
            expectedCloseIntentDigest,
            expectedCloseRequestGeneration,
          );
        }
      } catch (error) {
        throw markDefinitelyNotBroadcast(error);
      }
      const submitted = await submitOutbox(actionId, transaction, txOptions.replacement || null);
      await recordBroadcast(submitted.transactionHash, onBroadcast, { actionId });
      return { txHash: submitted.transactionHash, outboxActionId: actionId, phase: submitted.phase };
    },
    async markRequestFinalized(managerAddress, actionId, observation, era) {
      if (!era || era.expectedCurrentCloseFreezeNonce == null) {
        throw new Error('participant request finalization requires its exact guarded era');
      }
      const manager = new Contract(getAddress(managerAddress), MANAGER_PARTICIPANT_ABI, provider);
      return outbox.markFinalized(
        actionId,
        observation,
        async ({ blockTag, receipt, transactionHash }) => {
          if (!exactCloseRequestedReceipt(
            managerAddress,
            manager,
            receipt,
            transactionHash,
            BigInt(era.expectedCurrentCloseFreezeNonce) + 1n,
            signerAddress,
          )) return false;
          // This monotone getter remains meaningful even if submit/cancel follows later in the
          // same block and restores currentCloseFreezeNonce. The exact receipt event above proves
          // our request; the getter rules out reading a state older than its guarded era.
          const cancellationFloor = await manager.highestCancelledRevivedStateVersion({ blockTag });
          return BigInt(cancellationFloor)
            >= BigInt(era.expectedHighestCancelledRevivedStateVersion);
        },
      );
    },
    async reconcileRequest(managerAddress, proof, actionId, era, semanticObservation) {
      await assertNetwork();
      if (channelId == null || participantSlot == null
          || !String(actionId).startsWith(`participant-close:${channelId}:${participantSlot}:`)) {
        throw new Error('participant request reconciliation requires its exact durable action id');
      }
      if (Number(proof && proof.slot) !== Number(participantSlot)) {
        throw new Error('participant close proof slot differs from configured participant slot');
      }
      const canonicalActionId = participantCloseActionId({
        chainId: expectedChainId,
        manager: managerAddress,
        channelId,
        slot: participantSlot,
        era,
      });
      if (actionId !== canonicalActionId) {
        throw new Error('persisted participant close action id does not match its guarded era');
      }
      const semanticStatus = Number(semanticObservation && semanticObservation.channelStatus);
      if (![0, 1, 2].includes(semanticStatus)) {
        throw new Error('participant request reconciliation requires a canonical manager status');
      }
      const manager = new Contract(getAddress(managerAddress), MANAGER_PARTICIPANT_ABI, provider);
      return reconcileOneShot(
        actionId,
        semanticObservation,
        async ({ blockTag, receipt, transactionHash }) => {
          if (!exactCloseRequestedReceipt(
            managerAddress,
            manager,
            receipt,
            transactionHash,
            BigInt(era.expectedCurrentCloseFreezeNonce) + 1n,
          )) return false;
          const cancellationFloor = await manager.highestCancelledRevivedStateVersion({ blockTag });
          return BigInt(cancellationFloor)
            >= BigInt(era.expectedHighestCancelledRevivedStateVersion);
        },
        async ({ blockTag, receipt, transactionHash, logIndex }) => {
          if (semanticObservation && semanticObservation.kind === 'CloseRequested') {
            const exactEvent = exactCloseRequestedReceipt(
              managerAddress,
              manager,
              receipt,
              transactionHash,
              semanticObservation.closeFreezeNonce,
              semanticObservation.requester,
              logIndex,
            );
            if (!exactEvent
                || BigInt(semanticObservation.closeFreezeNonce)
                  !== BigInt(era.expectedCurrentCloseFreezeNonce) + 1n) return false;
            // The canonical event is the exact winner. Its end-of-block state may already be
            // Active again if a later transaction cancelled it in the same block.
            const cancellationFloor = await manager.highestCancelledRevivedStateVersion({ blockTag });
            return BigInt(cancellationFloor)
              >= BigInt(era.expectedHighestCancelledRevivedStateVersion);
          }
          if (semanticObservation && semanticObservation.kind === 'CloseCancelled') {
            const cancelled = exactManagerEvent(
              managerAddress,
              manager,
              receipt,
              transactionHash,
              'CloseCancelled',
              logIndex,
            );
            if (!cancelled
                || String(cancelled.args.closeIntentDigest).toLowerCase()
                  !== String(semanticObservation.closeIntentDigest).toLowerCase()) return false;
            const cancellationFloor = await manager.highestCancelledRevivedStateVersion({ blockTag });
            return BigInt(cancellationFloor)
              > BigInt(era.expectedHighestCancelledRevivedStateVersion);
          }
          // Getter-only state is deliberately insufficient. The watcher must preserve the exact
          // successful CloseRequested/CloseCancelled transaction and log identity; otherwise a
          // local revert for an unrelated reason could be mistaken for semantic completion.
          return false;
        },
      );
    },
    async reconcileFinalize(
      managerAddress,
      actionId,
      expectedCloseIntentDigest,
      expectedCloseRequestGeneration,
      semanticObservation,
    ) {
      await assertNetwork();
      const requiredPrefix = `close-finalize:${channelId}:`;
      if (channelId == null || !String(actionId).startsWith(requiredPrefix)) {
        throw new Error('finalize reconciliation requires its exact durable action id');
      }
      if (!isHexString(expectedCloseIntentDigest, 32)) {
        throw new Error('persisted finalize close-intent digest must be bytes32');
      }
      const expectedGeneration = canonicalExactUint(
        expectedCloseRequestGeneration,
        'persisted finalize close request generation',
      );
      if (!String(actionId).endsWith(`:generation:${expectedGeneration}`)) {
        throw new Error('persisted finalize action id does not match its close request generation');
      }
      const semanticStatus = Number(semanticObservation && semanticObservation.channelStatus);
      if (![0, 1, 2].includes(semanticStatus)) {
        throw new Error('finalize reconciliation requires a canonical manager status');
      }
      const manager = new Contract(getAddress(managerAddress), MANAGER_PARTICIPANT_ABI, provider);
      return reconcileOneShot(
        actionId,
        semanticObservation,
        async ({ blockTag, receipt, transactionHash }) => {
          const [status, digest, generation] = await Promise.all([
            manager.channelStatus({ blockTag }),
            manager.finalizedCloseIntentDigest({ blockTag }),
            manager.closeRequestGeneration({ blockTag }),
          ]);
          const event = exactManagerEvent(
            managerAddress,
            manager,
            receipt,
            transactionHash,
            'CloseFinalized',
          );
          return Number(status) === 2
            && BigInt(generation) === BigInt(expectedGeneration)
            && String(digest).toLowerCase() === String(expectedCloseIntentDigest).toLowerCase()
            && event !== null
            && String(event.args.closeIntentDigest).toLowerCase()
              === String(expectedCloseIntentDigest).toLowerCase();
        },
        async ({ blockTag, receipt, transactionHash, logIndex }) => {
          if (!semanticObservation || !semanticObservation.kind) return false;
          const [statusRaw, generationRaw] = await Promise.all([
            manager.channelStatus({ blockTag }),
            manager.closeRequestGeneration({ blockTag }),
          ]);
          const status = Number(statusRaw);
          if (BigInt(generationRaw) < BigInt(expectedGeneration)) return false;
          if (semanticObservation.kind === 'CloseFinalized') {
            const event = exactManagerEvent(
              managerAddress,
              manager,
              receipt,
              transactionHash,
              'CloseFinalized',
              logIndex,
            );
            if (!event || !isHexString(semanticObservation.closeIntentDigest, 32)
                || String(event.args.closeIntentDigest).toLowerCase()
                  !== String(semanticObservation.closeIntentDigest).toLowerCase()) return false;
            const digest = await manager.finalizedCloseIntentDigest({ blockTag });
            return status === 2
              && String(digest).toLowerCase()
                === String(semanticObservation.closeIntentDigest).toLowerCase();
          }
          if (semanticObservation.kind === 'CloseCancelled') {
            const event = exactManagerEvent(
              managerAddress,
              manager,
              receipt,
              transactionHash,
              'CloseCancelled',
              logIndex,
            );
            if (!event
                || String(event.args.closeIntentDigest).toLowerCase()
                  !== String(semanticObservation.closeIntentDigest).toLowerCase()
                || String(event.args.closeIntentDigest).toLowerCase()
                  !== String(expectedCloseIntentDigest).toLowerCase()) return false;
            // A cancel followed by a fresh request/identical intent in this same canonical block
            // may leave the end-of-block pending digest unchanged. The monotone generation still
            // proves the old raw can never succeed.
            if (BigInt(generationRaw) > BigInt(expectedGeneration)) return true;
            if (status === 0 || status === 2) return true;
            const pendingAfterCancel = await manager.getPendingClose({ blockTag });
            return !pendingAfterCancel.active
              || String(pendingAfterCancel.closeIntentDigest).toLowerCase()
                !== String(expectedCloseIntentDigest).toLowerCase();
          }
          if (semanticObservation.kind !== 'CloseSubmitted') return false;
          const replacement = exactManagerEvent(
            managerAddress,
            manager,
            receipt,
            transactionHash,
            'CloseSubmitted',
            logIndex,
          );
          if (!replacement
              || String(replacement.args.closeIntentDigest).toLowerCase()
                !== String(semanticObservation.closeIntentDigest).toLowerCase()
              || String(replacement.args.closeIntentDigest).toLowerCase()
                === String(expectedCloseIntentDigest).toLowerCase()) return false;
          if (status === 0 || status === 2) return true;
          if (status !== 1) return false;
          const pending = await manager.getPendingClose({ blockTag });
          return pending.active
            && String(pending.closeIntentDigest).toLowerCase()
              === String(replacement.args.closeIntentDigest).toLowerCase();
        },
      );
    },
    async markFinalizeFinalized(
      managerAddress,
      actionId,
      expectedCloseIntentDigest,
      expectedCloseRequestGeneration,
      observation,
    ) {
      const expectedGeneration = canonicalExactUint(
        expectedCloseRequestGeneration,
        'finalized close request generation',
      );
      if (!String(actionId).endsWith(`:generation:${expectedGeneration}`)) {
        throw new Error('finalized action id does not match its close request generation');
      }
      const manager = new Contract(getAddress(managerAddress), MANAGER_PARTICIPANT_ABI, provider);
      return outbox.markFinalized(actionId, observation, async ({ blockTag, receipt, transactionHash }) => {
        const [status, digest, generation] = await Promise.all([
          manager.channelStatus({ blockTag }),
          manager.finalizedCloseIntentDigest({ blockTag }),
          manager.closeRequestGeneration({ blockTag }),
        ]);
        const event = exactManagerEvent(
          managerAddress,
          manager,
          receipt,
          transactionHash,
          'CloseFinalized',
        );
        return Number(status) === 2
          && BigInt(generation) === BigInt(expectedGeneration)
          && String(digest).toLowerCase() === String(expectedCloseIntentDigest).toLowerCase()
          && event !== null
          && String(event.args.closeIntentDigest).toLowerCase()
            === String(expectedCloseIntentDigest).toLowerCase();
      });
    },
    async transactionStatus(txHash) {
      return outbox.transactionStatus(txHash);
    },
    ownsTransaction(actionId, txHash) {
      return outbox.hasAttempt(actionId, txHash);
    },
  };
}

module.exports = {
  PARTICIPANT_TREE_DEPTH,
  MAX_PARTICIPANTS,
  buildParticipantCloseProof,
  makeParticipantCloser,
  participantCloseActionId,
  participantLeaf,
  participantNode,
};
