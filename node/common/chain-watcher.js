'use strict';
// Chain event watcher (DESIGN.md §2.2). Builds an ethers Interface from the EXACT contract event
// fragments (verified against contracts/src/IntmaxRollup.sol + ChannelSettlementManager.sol), so
// topic0 matching AND argument decoding are correct (a hand-written signature that disagrees with
// the contract silently never matches — the original bug found in review C1/M3/H3). Polls with a
// confirmation depth and advances the cursor PER BLOCK (a block is only marked done once all its
// events handled — no silent event loss on a mid-batch failure). ethers is lazy-required so
// pure-logic unit tests do not need it.
//
// ChainEvent: { kind, contract, channelId, args:{...decoded}, blockNumber, txHash, logIndex }

// EXACT event fragments (human-readable; ethers derives topic0 + decodes args by name).
const ROLLUP_FRAGMENTS = [
  'event BlockPosted(uint64 indexed blockNumber, uint32 channelId, uint32[] keyIds, bytes32 txTreeRoot, bytes32 newBlockHashChain)',
  'event Deposited(uint64 indexed depositIndex, address depositor, bytes32 recipient, uint32 tokenIndex, uint256 amount, bytes32 auxData, bytes32 newDepositHashChain)',
  'event ChannelRegistered(uint64 indexed regIndex, uint32 indexed channelId, uint8 bpMemberSlot, bytes32[] memberPkGs, bytes32[] regevPkDigests, address[] recipients, bytes32 memberPubkeysRoot, bytes32 regevPkRoot, bytes32 newChannelRegHashChain)',
  'event Submitted(uint256 indexed id, address indexed submitter, bytes32 blobVersionedHash, bytes32 proofHash, uint32 proofLength, bytes32 stateRoot)',
  'event Finalized(uint256 indexed id, bytes32 stateRoot)',
  'event FraudConfirmed(uint256 indexed id, address indexed prover)',
  'event WithdrawalCredited(address indexed recipient, uint256 amount)',
  'event PartialWithdrawalAuthorized(bytes32 indexed authDigest, address indexed manager)',
  'event SettlementManagerRegistered(address indexed manager)',
  'event NativeWithdrawn(address indexed recipient, uint256 amount, bytes32 indexed nullifier, uint64 blockNumber)',
];

const MANAGER_FRAGMENTS = [
  'event CloseRequested(address indexed requester, uint64 closeRequestedAt, uint64 closeFreezeNonce)',
  'event CloseSubmitted(bytes32 indexed closeIntentDigest, bytes32 indexed burnTxHash, uint64 indexed closeNonce, uint64 finalEpoch, uint64 closeFreezeNonce, uint256 channelFundAmount, uint64 challengeDeadline, uint64 finalStateVersion, bytes32 finalSettledTxChain)',
  'event SpecialCloseSubmitted(bytes32 indexed specialCloseDigest, bytes32 indexed offendingBpPkG, bytes32 indexed fullySignedSmallBlockRoot, uint8 offendingBpMemberSlot, uint64 smallBlockNumber, uint256 slashedAmount, uint64 closeFreezeNonce)',
  'event CloseCancelled(bytes32 indexed closeIntentDigest, bytes32 indexed revivedChannelStateDigest, uint64 revivedStateVersion)',
  'event LateOutgoingDebitAccepted(bytes32 indexed closeIntentDigest, bytes32 indexed sourceTxHash, bytes32 indexed debitNullifier, uint64 amount)',
  'event CloseFinalized(bytes32 indexed closeIntentDigest, bytes32 indexed burnTxHash, uint64 indexed finalEpoch, uint256 channelFundAmount, uint64 finalStateVersion, bytes32 finalSettledTxChain)',
  'event WithdrawalClaimAccepted(bytes32 indexed closeIntentDigest, bytes32 indexed withdrawalNullifier, bytes32 indexed memberPkG, address recipient, uint256 amount)',
  'event PostCloseClaimAccepted(bytes32 indexed closeIntentDigest, bytes32 indexed sharedNativeNullifier, bytes32 indexed receiverPkG, address recipient, uint256 amount)',
  'event WithdrawalClaimed(address indexed recipient, uint256 amount)',
  'event PartialWithdrawalSubmitted(bytes32 indexed authDigest, bytes32 indexed chainKey, uint64 challengeDeadline, uint64 finalStateVersion)',
  'event PartialWithdrawalFinalized(bytes32 indexed authDigest, bytes32 indexed chainKey)',
  'event PartialWithdrawalCancelled(bytes32 indexed authDigest, bytes32 indexed revivedChannelStateDigest, uint64 revivedStateVersion)',
  'event ChannelFundsPulled(uint256 amount, uint256 totalReceived)',
];

// Getter ABI for authoritative reconciliation (DESIGN.md §3.7). MUST match the EXACT PendingClose
// struct field order in ChannelSettlementManager.sol (review MED-1: a wrong tuple decodes
// positionally → garbage values → C1 silently degrades). Verified field-by-field against the
// contract's `struct PendingClose`.
const MANAGER_GETTER_ABI = [
  'function getPendingClose() view returns (tuple(' +
    'bool active,' +
    'uint64 closeNonce,' +
    'uint64 finalEpoch,' +
    'uint64 finalSmallBlockNumber,' +
    'uint64 closeFreezeNonce,' +
    'uint64 challengeDeadline,' +
    'bytes32 closeIntentDigest,' +
    'bytes32 finalChannelStateDigest,' +
    'bytes32 finalBalanceStateH1,' +
    'uint256 channelFundAmount,' +
    'bytes32 channelFundIntmaxStateRoot,' +
    'bytes32 burnTxHash,' +
    'bytes32 closeWithdrawalDigest,' +
    'uint64 snapshotMediumBlockNumber,' +
    'uint64 finalStateVersion,' +
    'bytes32 finalSettledTxChain,' +
    'bytes32 finalSettledTxAccumulatorRoot' +
  '))',
];

function decodedArgs(parsed) {
  const out = {};
  for (const f of parsed.fragment.inputs) {
    const v = parsed.args[f.name];
    out[f.name] = typeof v === 'bigint' ? v.toString() : (Array.isArray(v) ? v.map(String) : v);
  }
  return out;
}

class ChainWatcher {
  constructor({ rpcUrl, channels, confirmations = 2, pollIntervalMs = 4000 }) {
    this.rpcUrl = rpcUrl;
    this.channels = channels;
    this.confirmations = confirmations;
    this.pollIntervalMs = pollIntervalMs;
    this._ethers = null;
    this._provider = null;
    this._iface = null;
  }

  _init() {
    if (this._provider) return;
    // eslint-disable-next-line global-require
    const ethers = require('ethers');
    this._ethers = ethers;
    this._provider = new ethers.JsonRpcProvider(this.rpcUrl);
    this._iface = new ethers.Interface([...ROLLUP_FRAGMENTS, ...MANAGER_FRAGMENTS]);
  }

  _channelForAddress(addr) {
    const a = addr.toLowerCase();
    for (const c of this.channels) {
      if ((c.rollup && c.rollup.toLowerCase() === a) || (c.manager && c.manager.toLowerCase() === a)) return c.id;
    }
    return null;
  }

  _contractKindForAddress(addr) {
    const a = addr.toLowerCase();
    for (const c of this.channels) {
      if (c.rollup && c.rollup.toLowerCase() === a) return 'rollup';
      if (c.manager && c.manager.toLowerCase() === a) return 'manager';
    }
    return null;
  }

  _normalize(logEntry) {
    let parsed;
    try { parsed = this._iface.parseLog({ topics: logEntry.topics, data: logEntry.data }); }
    catch (e) { return null; } // not one of our events
    if (!parsed) return null;
    return {
      kind: parsed.name,
      contract: this._contractKindForAddress(logEntry.address),
      channelId: this._channelForAddress(logEntry.address),
      address: logEntry.address,
      args: decodedArgs(parsed),
      blockNumber: logEntry.blockNumber,
      txHash: logEntry.transactionHash,
      logIndex: logEntry.index != null ? logEntry.index : logEntry.logIndex,
    };
  }

  // One poll pass: [fromBlock, head-confirmations]. Advances the cursor PER BLOCK: a block is only
  // marked done once ALL its events were handled without throwing, so a mid-batch handler failure
  // leaves the cursor at the last fully-done block (the failed block is retried next tick — no
  // silent loss). onEvent MUST throw to signal failure (the co-signer's dispatch rethrows for
  // chain-sourced events). Returns the new cursor.
  async pollOnce(fromBlock, onEvent, onCursor) {
    this._init();
    const head = await this._provider.getBlockNumber();
    const safeHead = head - this.confirmations;
    if (safeHead < fromBlock) return fromBlock;
    const addresses = [];
    for (const c of this.channels) { if (c.rollup) addresses.push(c.rollup); if (c.manager) addresses.push(c.manager); }
    if (addresses.length === 0) return safeHead + 1;

    const logs = await this._provider.getLogs({ fromBlock, toBlock: safeHead, address: addresses });
    logs.sort((a, b) => a.blockNumber - b.blockNumber || (a.index ?? a.logIndex) - (b.index ?? b.logIndex));

    // Group by block, process each block fully before advancing the cursor past it.
    const byBlock = new Map();
    for (const l of logs) { if (!byBlock.has(l.blockNumber)) byBlock.set(l.blockNumber, []); byBlock.get(l.blockNumber).push(l); }

    let doneThrough = fromBlock - 1;
    for (const b of [...byBlock.keys()].sort((x, y) => x - y)) {
      try {
        for (const l of byBlock.get(b)) {
          const ev = this._normalize(l);
          if (ev) await onEvent(ev);
        }
        doneThrough = b;
      } catch (e) {
        if (onCursor) await onCursor(doneThrough + 1); // persist progress up to the last good block
        throw e; // surface so the caller logs + retries this block next tick
      }
    }
    const next = Math.max(doneThrough + 1, safeHead + 1);
    if (onCursor) await onCursor(next);
    return next;
  }

  async getPendingClose(managerAddr) {
    this._init();
    const c = new this._ethers.Contract(managerAddr, MANAGER_GETTER_ABI, this._provider);
    const r = await c.getPendingClose();
    const epoch = Number(r.finalEpoch);
    const stateVersion = Number(r.finalStateVersion);
    // Guard against a decode mismatch yielding non-finite values (review MED-2): a caller comparing
    // NaN would throw; return null so the branch treats it as "could not reconcile" (warn) rather
    // than crash the watcher.
    if (!Number.isFinite(epoch) || !Number.isFinite(stateVersion)) return null;
    return {
      active: Boolean(r.active),
      closeIntentDigest: r.closeIntentDigest,
      epoch,
      stateVersion,
      challengeDeadline: Number(r.challengeDeadline) || 0,
      closeFreezeNonce: Number(r.closeFreezeNonce) || 0,
    };
  }

  provider() { this._init(); return this._provider; }
}

module.exports = { ChainWatcher, ROLLUP_FRAGMENTS, MANAGER_FRAGMENTS };
