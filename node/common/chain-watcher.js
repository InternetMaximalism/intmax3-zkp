'use strict';
// Chain event watcher (DESIGN.md §2.2). Builds an ethers Interface from the EXACT contract event
// fragments (verified against contracts/src/IntmaxRollup.sol + ChannelSettlementManager.sol), so
// topic0 matching AND argument decoding are correct (a hand-written signature that disagrees with
// the contract silently never matches — the original bug found in review C1/M3/H3). Polls with a
// finalized head and advances the cursor PER BLOCK (a block is only marked done once all its
// events handled — no silent event loss on a mid-batch failure). Public-chain durable actions are
// NEVER driven from a merely-confirmed block: a fixed confirmation count is not finality, and an
// orphaned deposit/close/credit cannot in general be undone after the CLI has acted. A shallow
// confirmation mode exists only as an explicit chain-31337 devnet escape hatch. Every durable
// cursor is paired with the canonical block hash and parent hash; a changed finalized checkpoint is
// a fail-stop condition, not something this process silently rewinds past. ethers is lazy-required
// so pure-logic unit tests do not need it.
//
// ChainEvent: { kind, contract, channelId, channelIds, args:{...decoded}, blockNumber, txHash,
// logIndex }. `channelId` is populated only for a uniquely-routed event; `channelIds` is the
// authoritative target set. Shared-rollup events that are genuinely global are intentionally
// broadcast only to channels configured for that rollup, never to unrelated runtimes.

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
  // Multi-token (detail2 §N-7) — verified against contracts/src/IntmaxRollup.sol:
  'event TokenRegistered(uint32 indexed tokenIndex, address indexed token)',
  'event Erc20Withdrawn(address indexed recipient, uint32 indexed tokenIndex, uint256 amount, bytes32 indexed nullifier, uint64 blockNumber)',
  'event TokenWithdrawalClaimed(address indexed recipient, uint32 indexed tokenIndex, uint256 amount)',
];

// Multi-token (§N-6, Phase 3): WithdrawalClaimAccepted gained a trailing `uint32 tokenIndex`,
// WithdrawalClaimed gained `uint32 indexed tokenIndex` (2nd, indexed), and ChannelFundsPulled
// gained a LEADING `uint32 indexed tokenIndex` — a stale fragment changes topic0 and silently
// never matches (the exact failure class this file's header warns about), so each fragment
// below was re-verified field-for-field (indexed-ness included) against the committed
// ChannelSettlementManager.sol.
const MANAGER_FRAGMENTS = [
  'event CloseRequested(address indexed requester, uint64 closeRequestedAt, uint64 closeFreezeNonce)',
  'event CloseSubmitted(bytes32 indexed closeIntentDigest, bytes32 indexed burnTxHash, uint64 indexed closeNonce, uint64 finalEpoch, uint64 closeFreezeNonce, uint256 channelFundAmount, uint64 challengeDeadline, uint64 finalStateVersion, bytes32 finalSettledTxChain)',
  'event SpecialCloseSubmitted(bytes32 indexed specialCloseDigest, bytes32 indexed offendingBpPkG, bytes32 indexed fullySignedSmallBlockRoot, uint8 offendingBpMemberSlot, uint64 smallBlockNumber, uint256 slashedAmount, uint64 closeFreezeNonce)',
  'event CloseCancelled(bytes32 indexed closeIntentDigest, bytes32 indexed revivedChannelStateDigest, uint64 revivedStateVersion)',
  'event LateOutgoingDebitAccepted(bytes32 indexed closeIntentDigest, bytes32 indexed sourceTxHash, bytes32 indexed debitNullifier, uint64 amount)',
  'event CloseFinalized(bytes32 indexed closeIntentDigest, bytes32 indexed burnTxHash, uint64 indexed finalEpoch, uint256 channelFundAmount, uint64 finalStateVersion, bytes32 finalSettledTxChain)',
  'event WithdrawalClaimAccepted(bytes32 indexed closeIntentDigest, bytes32 indexed withdrawalNullifier, bytes32 indexed memberPkG, address recipient, uint256 amount, uint32 tokenIndex)',
  // TM-16 (multitoken Phase 5a): trailing `uint32 tokenIndex` — MUST stay field-for-field
  // identical to ChannelSettlementManager.sol (a stale fragment silently never matches).
  'event PostCloseClaimAccepted(bytes32 indexed closeIntentDigest, bytes32 indexed sharedNativeNullifier, bytes32 indexed receiverPkG, address recipient, uint256 amount, uint32 tokenIndex)',
  'event WithdrawalClaimed(address indexed recipient, uint32 indexed tokenIndex, uint256 amount)',
  'event PartialWithdrawalSubmitted(bytes32 indexed authDigest, bytes32 indexed chainKey, uint64 challengeDeadline, uint64 finalStateVersion)',
  'event PartialWithdrawalFinalized(bytes32 indexed authDigest, bytes32 indexed chainKey)',
  'event PartialWithdrawalCancelled(bytes32 indexed authDigest, bytes32 indexed revivedChannelStateDigest, uint64 revivedStateVersion)',
  'event ChannelFundsPulled(uint32 indexed tokenIndex, uint256 amount, uint256 totalReceived)',
];

// Rollup getter ABI. `tokenAddressOf` is the AUTHORITATIVE, set-once base-token registry
// (detail2 §N-7 / TM-10b) — the only thing a display symbol may ever be verified against. Same
// discipline as MANAGER_GETTER_ABI: a fragment that disagrees with the contract decodes garbage.
// Verified against contracts/src/IntmaxRollup.sol (`mapping(uint32 => IERC20) public tokenAddressOf`).
const ROLLUP_GETTER_ABI = [
  'function tokenAddressOf(uint32) view returns (address)',
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
    'uint256[10] channelFundAmounts,' +
    'uint32[10] tokenRegistry,' +
    'uint8 tokenCount,' +
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

function sameAddress(a, b) {
  return typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
}

function parseBlockNumber(value, what = 'block number') {
  if (typeof value === 'bigint') {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${what} is out of range`);
    return Number(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${what} is invalid`);
    return value;
  }
  if (typeof value === 'string' && value.length) {
    const parsed = value.startsWith('0x') ? Number.parseInt(value.slice(2), 16) : Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(`${what} is invalid`);
    return parsed;
  }
  throw new Error(`${what} is missing`);
}

function canonicalHash(value, what) {
  const hash = String(value || '').toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(hash)) throw new Error(`${what} is missing or malformed`);
  return hash;
}

function checkpointFromBlock(block, expectedNumber = null) {
  if (!block) throw new Error('canonical block is unavailable');
  const number = parseBlockNumber(block.number, 'canonical block number');
  if (expectedNumber !== null && number !== expectedNumber) {
    throw new Error(`canonical block number ${number} differs from requested ${expectedNumber}`);
  }
  return {
    number,
    hash: canonicalHash(block.hash, 'canonical block hash'),
    parentHash: canonicalHash(block.parentHash, 'canonical parent hash'),
  };
}

class ChainSafetyError extends Error {
  constructor(code, message, evidence = {}) {
    super(message);
    this.name = 'ChainSafetyError';
    this.code = code;
    this.evidence = evidence;
  }
}

const TRANSIENT_CHAIN_AVAILABILITY_CODES = new Set([
  'RPC_NETWORK_UNAVAILABLE',
  'CANONICAL_BLOCK_UNAVAILABLE',
  'FINALIZED_HEAD_UNAVAILABLE',
  'DURABLE_HEAD_BEHIND_CURSOR',
]);

// Availability is not forensic evidence. These errors close the volatile action gate until a
// complete poll succeeds, while chain-id/hash/malformed-data contradictions remain sticky.
function isTransientChainSafetyError(error) {
  return error instanceof ChainSafetyError && TRANSIENT_CHAIN_AVAILABILITY_CODES.has(error.code);
}

// Resolve an already-decoded event to the configured channel runtimes that own it. Manager events
// are address-scoped. Shared-rollup events use their explicit channelId/manager/recipient whenever
// the event exposes one; only events with no channel discriminator are broadcast to that rollup's
// channels. This helper is pure so multi-channel routing can be regression-tested without RPC.
function routeEventChannelIds(channels, { contract, address, kind, args = {} }) {
  const configured = Array.isArray(channels) ? channels : [];
  if (contract === 'manager') {
    return [...new Set(configured.filter(c => sameAddress(c.manager, address)).map(c => c.id))];
  }
  if (contract !== 'rollup') return [];

  const candidates = configured.filter(c => sameAddress(c.rollup, address));
  if (args.channelId !== undefined && args.channelId !== null) {
    return [...new Set(candidates.filter(c => String(c.id) === String(args.channelId)).map(c => c.id))];
  }

  if (
    (kind === 'PartialWithdrawalAuthorized' || kind === 'SettlementManagerRegistered')
    && typeof args.manager === 'string'
  ) {
    return [...new Set(candidates.filter(c => sameAddress(c.manager, args.manager)).map(c => c.id))];
  }

  // A deployment may publish each channel's deposit recipient in config. When it does, a deposit
  // is routed exactly; channels lacking that metadata remain candidates because the CLI performs
  // the authoritative on-chain recipient check. Known non-matches are never needlessly invoked.
  if (kind === 'Deposited' && typeof args.recipient === 'string') {
    const matches = candidates.filter(c => sameAddress(c.depositRecipient || c.deposit_recipient, args.recipient));
    const unknown = candidates.filter(c => !(c.depositRecipient || c.deposit_recipient));
    if (matches.length || unknown.length !== candidates.length) {
      return [...new Set([...matches, ...unknown].map(c => c.id))];
    }
  }

  return [...new Set(candidates.map(c => c.id))];
}

class ChainWatcher {
  constructor({
    rpcUrl,
    channels,
    chainId = null,
    confirmations = 2,
    pollIntervalMs = 4000,
    allowUnfinalizedDevnet = false,
    provider = null,
  }) {
    this.rpcUrl = rpcUrl;
    this.channels = channels;
    if (chainId == null) throw new Error('chainId is required to authenticate the RPC network');
    this.chainId = parseBlockNumber(chainId, 'configured chain id');
    if (this.chainId === 0) throw new Error('configured chain id must be positive');
    this.confirmations = parseBlockNumber(confirmations, 'confirmation depth');
    this.pollIntervalMs = pollIntervalMs;
    this.allowUnfinalizedDevnet = allowUnfinalizedDevnet === true;
    if (this.allowUnfinalizedDevnet && this.chainId !== 31337) {
      throw new Error('allowUnfinalizedDevnet is permitted only for explicit chainId 31337');
    }
    this._ethers = null;
    this._provider = provider;
    this._iface = null;
    this._networkChecked = false;
  }

  _init() {
    if (this._provider) return;
    // eslint-disable-next-line global-require
    const ethers = require('ethers');
    this._ethers = ethers;
    this._provider = new ethers.JsonRpcProvider(this.rpcUrl);
    this._iface = new ethers.Interface([...ROLLUP_FRAGMENTS, ...MANAGER_FRAGMENTS]);
  }

  async _assertNetwork() {
    this._init();
    if (this._networkChecked || this.chainId == null) return;
    let network;
    try {
      network = await this._provider.getNetwork();
    } catch (cause) {
      throw new ChainSafetyError(
        'RPC_NETWORK_UNAVAILABLE',
        `cannot authenticate the RPC network: ${cause && cause.message || cause}`,
      );
    }
    let actual;
    try {
      actual = parseBlockNumber(network && network.chainId, 'RPC chain id');
    } catch (cause) {
      throw new ChainSafetyError(
        'RPC_CHAIN_ID_INVALID',
        `RPC returned an invalid chain id: ${cause.message}`,
      );
    }
    if (actual !== this.chainId) {
      throw new ChainSafetyError(
        'CHAIN_ID_MISMATCH',
        `RPC chain id ${actual} differs from configured ${this.chainId}`,
        { expectedChainId: this.chainId, actualChainId: actual },
      );
    }
    this._networkChecked = true;
  }

  async _blockCheckpoint(number) {
    this._init();
    let block;
    try {
      block = await this._provider.getBlock(number);
    } catch (cause) {
      throw new ChainSafetyError(
        'CANONICAL_BLOCK_UNAVAILABLE',
        `cannot read canonical block ${number}: ${cause && cause.message || cause}`,
        { number },
      );
    }
    try {
      return checkpointFromBlock(block, number);
    } catch (cause) {
      throw new ChainSafetyError(
        'CANONICAL_BLOCK_INVALID',
        `canonical block ${number} is invalid: ${cause.message}`,
        { number },
      );
    }
  }

  async _durableHead() {
    await this._assertNetwork();
    if (this.allowUnfinalizedDevnet) {
      const latest = parseBlockNumber(await this._provider.getBlockNumber(), 'latest block number');
      const number = latest - this.confirmations;
      return number < 0 ? null : this._blockCheckpoint(number);
    }

    let finalized;
    try {
      finalized = await this._provider.getBlock('finalized');
    } catch (cause) {
      throw new ChainSafetyError(
        'FINALIZED_HEAD_UNAVAILABLE',
        `RPC does not provide a finalized head: ${cause && cause.message || cause}`,
      );
    }
    if (!finalized) {
      throw new ChainSafetyError(
        'FINALIZED_HEAD_UNAVAILABLE',
        'RPC returned no finalized head; refusing durable chain actions',
      );
    }
    try {
      return checkpointFromBlock(finalized);
    } catch (cause) {
      throw new ChainSafetyError(
        'FINALIZED_HEAD_INVALID',
        `RPC finalized head is invalid: ${cause.message}`,
      );
    }
  }

  // Validate the durable checkpoint before any new event is dispatched. A number-only legacy
  // cursor cannot be authenticated after the fact: derived state may already contain effects from
  // a different fork, while reading the current hash at cursor-1 would merely bless that state.
  // Such stores require explicit operator reconciliation and never auto-bootstrap.
  async validateCheckpoint(cursor, storedCheckpoint) {
    let next;
    try {
      next = parseBlockNumber(cursor, 'stored chain cursor');
    } catch (cause) {
      throw new ChainSafetyError(
        'STORED_CURSOR_INVALID',
        `stored chain cursor is invalid: ${cause.message}`,
        { cursor },
      );
    }
    if (next > 0 && storedCheckpoint == null) {
      throw new ChainSafetyError(
        'LEGACY_CURSOR_UNAUTHENTICATED',
        `legacy cursor ${next} has no authenticated prior-block checkpoint; operator reconciliation is required`,
        { cursor: next },
      );
    }
    await this._assertNetwork();
    if (next === 0) {
      if (storedCheckpoint != null) {
        throw new ChainSafetyError(
          'STORED_CHECKPOINT_INVALID',
          'genesis cursor cannot carry a prior-block checkpoint',
          { cursor: next, storedCheckpoint },
        );
      }
      return { cursor: next, checkpoint: null, bootstrapped: false, rewound: false };
    }
    const durableHead = await this._durableHead();
    if (!durableHead) {
      throw new ChainSafetyError(
        'DURABLE_HEAD_BEHIND_CURSOR',
        `no durable head exists for stored cursor ${next}`,
        { cursor: next },
      );
    }
    if (next - 1 > durableHead.number) {
      throw new ChainSafetyError(
        'FINALIZED_HEAD_REGRESSION',
        `stored checkpoint ${next - 1} is ahead of finalized head ${durableHead.number}`,
        { cursor: next, storedCheckpoint, durableHead },
      );
    }
    const actual = await this._blockCheckpoint(next - 1);

    let expected;
    try {
      expected = checkpointFromBlock(storedCheckpoint, next - 1);
    } catch (cause) {
      throw new ChainSafetyError(
        'STORED_CHECKPOINT_INVALID',
        `stored chain checkpoint is invalid: ${cause.message}`,
        { cursor: next, storedCheckpoint },
      );
    }
    if (expected.hash !== actual.hash || expected.parentHash !== actual.parentHash) {
      throw new ChainSafetyError(
        'FINALIZED_CHECKPOINT_MISMATCH',
        `finalized checkpoint ${expected.number} changed; refusing signing and durable actions`,
        { cursor: next, expected, actual },
      );
    }
    return { cursor: next, checkpoint: actual, bootstrapped: false, rewound: false };
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
    const contract = this._contractKindForAddress(logEntry.address);
    const args = decodedArgs(parsed);
    const channelIds = routeEventChannelIds(this.channels, {
      contract,
      address: logEntry.address,
      kind: parsed.name,
      args,
    });
    return {
      kind: parsed.name,
      contract,
      channelId: channelIds.length === 1 ? channelIds[0] : null,
      channelIds,
      address: logEntry.address,
      args,
      blockNumber: logEntry.blockNumber,
      blockHash: logEntry.blockHash,
      txHash: logEntry.transactionHash,
      logIndex: logEntry.index != null ? logEntry.index : logEntry.logIndex,
    };
  }

  // One poll pass: [fromBlock, finalizedHead] (or the explicit 31337 devnet confirmation head).
  // Advances the cursor PER BLOCK: a block is only
  // marked done once ALL its events were handled without throwing, so a mid-batch handler failure
  // leaves the cursor at the last fully-done block (the failed block is retried next tick — no
  // silent loss). onEvent MUST throw to signal failure (the co-signer's dispatch rethrows for
  // chain-sourced events). Returns the new cursor.
  // `onCursor(nextBlock, checkpoint)` MUST persist both values atomically. A callback accepting only
  // the historical first argument remains source-compatible, but production callers use Store's
  // paired progress API.
  async pollOnce(fromBlock, onEvent, onCursor) {
    this._init();
    let firstBlock;
    try {
      firstBlock = parseBlockNumber(fromBlock, 'poll cursor');
    } catch (cause) {
      throw new ChainSafetyError('POLL_CURSOR_INVALID', cause.message, { fromBlock });
    }
    const durableHead = await this._durableHead();
    if (!durableHead) return firstBlock;
    const safeHead = durableHead.number;
    if (safeHead < firstBlock) return firstBlock;
    const addresses = [];
    for (const c of this.channels) { if (c.rollup) addresses.push(c.rollup); if (c.manager) addresses.push(c.manager); }
    if (addresses.length === 0) {
      if (onCursor) await onCursor(safeHead + 1, durableHead);
      return safeHead + 1;
    }

    const logs = await this._provider.getLogs({
      fromBlock: firstBlock,
      toBlock: safeHead,
      address: [...new Set(addresses.map(a => a.toLowerCase()))],
    });
    logs.sort((a, b) => a.blockNumber - b.blockNumber || (a.index ?? a.logIndex) - (b.index ?? b.logIndex));

    // Group by block, process each block fully before advancing the cursor past it.
    const byBlock = new Map();
    for (const logEntry of logs) {
      if (logEntry.removed === true) {
        throw new ChainSafetyError(
          'REMOVED_LOG_IN_DURABLE_RANGE',
          'RPC returned a removed log inside the durable range',
          { blockNumber: logEntry.blockNumber, blockHash: logEntry.blockHash },
        );
      }
      let blockNumber;
      try {
        blockNumber = parseBlockNumber(logEntry.blockNumber, 'log block number');
      } catch (cause) {
        throw new ChainSafetyError(
          'LOG_BLOCK_NUMBER_INVALID',
          cause.message,
          { blockNumber: logEntry.blockNumber },
        );
      }
      if (blockNumber < firstBlock || blockNumber > safeHead) {
        throw new ChainSafetyError(
          'LOG_OUTSIDE_DURABLE_RANGE',
          `RPC returned log block ${blockNumber} outside [${firstBlock}, ${safeHead}]`,
          { blockNumber, fromBlock: firstBlock, safeHead },
        );
      }
      if (!byBlock.has(blockNumber)) byBlock.set(blockNumber, []);
      // Provider Log objects are not guaranteed to be mutable. Normalize into our own object
      // rather than assigning to a potentially read-only `blockNumber` property.
      byBlock.get(blockNumber).push({ ...logEntry, blockNumber });
    }

    // Validate the complete fetched batch before dispatching its first event. Otherwise a malformed
    // or fork-mixed later log could be discovered only after an earlier block already caused an
    // irreversible CLI action. `getLogs` blockHash and the canonical block query must agree.
    const blockCheckpoints = new Map();
    for (const b of [...byBlock.keys()].sort((x, y) => x - y)) {
      const checkpoint = await this._blockCheckpoint(b);
      for (const logEntry of byBlock.get(b)) {
        let logHash;
        try {
          logHash = canonicalHash(logEntry.blockHash, 'log block hash');
        } catch (cause) {
          throw new ChainSafetyError(
            'LOG_BLOCK_HASH_INVALID',
            `log in block ${b} has no canonical block hash: ${cause.message}`,
            { blockNumber: b },
          );
        }
        if (logHash !== checkpoint.hash) {
          throw new ChainSafetyError(
            'LOG_BLOCK_HASH_MISMATCH',
            `log block hash at ${b} differs from the canonical block`,
            { blockNumber: b, logHash, canonicalHash: checkpoint.hash },
          );
        }
      }
      blockCheckpoints.set(b, checkpoint);
    }

    let doneThrough = firstBlock - 1;
    for (const b of [...byBlock.keys()].sort((x, y) => x - y)) {
      try {
        for (const l of byBlock.get(b)) {
          const ev = this._normalize(l);
          if (ev) await onEvent(ev);
        }
        doneThrough = b;
      } catch (e) {
        if (onCursor && doneThrough >= firstBlock) {
          const checkpoint = blockCheckpoints.get(doneThrough) || await this._blockCheckpoint(doneThrough);
          await onCursor(doneThrough + 1, checkpoint); // persist progress through the last good block
        }
        throw e; // surface so the caller logs + retries this block next tick
      }
    }
    const next = Math.max(doneThrough + 1, safeHead + 1);
    // Re-read finality and the exact finalized height after handlers complete. A public-chain
    // finalized block changing/regressing is a consensus/RPC safety violation and must be noticed
    // before progress is persisted.
    const durableHeadAfter = await this._durableHead();
    if (!durableHeadAfter || durableHeadAfter.number < safeHead) {
      throw new ChainSafetyError(
        'FINALIZED_HEAD_REGRESSION',
        `durable head regressed below processed block ${safeHead}`,
        { before: durableHead, after: durableHeadAfter },
      );
    }
    const finalCheckpoint = await this._blockCheckpoint(safeHead);
    if (finalCheckpoint.hash !== durableHead.hash || finalCheckpoint.parentHash !== durableHead.parentHash) {
      throw new ChainSafetyError(
        'FINALIZED_HEAD_CHANGED_DURING_POLL',
        `finalized block ${safeHead} changed while processing`,
        { before: durableHead, after: finalCheckpoint },
      );
    }
    if (onCursor) await onCursor(next, finalCheckpoint);
    return next;
  }

  async getPendingClose(managerAddr, blockTag = 'finalized') {
    this._init();
    const c = new this._ethers.Contract(managerAddr, MANAGER_GETTER_ABI, this._provider);
    // Reconciliation is part of a chain-triggered durable decision. Pin it to that finalized event
    // block (or the finalized tag for standalone callers), never to the provider's moving `latest`.
    const r = await c.getPendingClose({ blockTag });
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

  // Read the set-once base-token registry entry (detail2 §N-7). Returns a lowercase address;
  // the zero address means "index not registered". SECURITY: this is the ONLY authority a token
  // DISPLAY symbol may be verified against (see common/token-registry.js).
  async getTokenAddress(rollupAddr, tokenIndex) {
    this._init();
    const c = new this._ethers.Contract(rollupAddr, ROLLUP_GETTER_ABI, this._provider);
    const a = await c.tokenAddressOf(tokenIndex);
    return String(a).toLowerCase();
  }

  provider() { this._init(); return this._provider; }
}

module.exports = {
  ChainWatcher,
  ChainSafetyError,
  ROLLUP_FRAGMENTS,
  MANAGER_FRAGMENTS,
  ROLLUP_GETTER_ABI,
  MANAGER_GETTER_ABI,
  routeEventChannelIds,
  checkpointFromBlock,
  isTransientChainSafetyError,
};
