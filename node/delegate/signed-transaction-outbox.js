'use strict';
// Crash-safe EIP-1559 transaction outbox for every delegate-owned L1 write.
//
// The JSON orchestration Store must never contain signing keys or raw transactions. This private
// outbox is deliberately separate: it reserves a nonce under a per-(chain, signer) process lock,
// signs offline, fsyncs the exact raw bytes, and only then permits a broadcast. A restart can
// therefore reconcile or rebroadcast one byte-identical transaction instead of guessing what may
// have escaped before the ordinary Store recorded a hash.

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  JsonRpcProvider,
  Transaction,
  Wallet: EthersWallet,
  getAddress,
  isHexString,
  keccak256,
} = require('ethers');

const SCHEMA_VERSION = 1;
const RESERVATION_SCHEMA_VERSION = 2;
const MAX_RECORD_BYTES = 16 * 1024 * 1024;
const ZERO_HASH = `0x${'00'.repeat(32)}`;

function codedError(code, message, details = null) {
  const error = new Error(message);
  error.code = code;
  if (details) error.details = details;
  return error;
}

function canonicalUint(value, label) {
  let parsed;
  try {
    if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) throw new Error();
    parsed = BigInt(value);
  } catch (_) {
    throw codedError('OUTBOX_INVALID_TRANSACTION', `${label} must be an unsigned integer`);
  }
  if (parsed < 0n || parsed >= (1n << 256n)) {
    throw codedError('OUTBOX_INVALID_TRANSACTION', `${label} is outside uint256`);
  }
  return parsed;
}

function canonicalNonce(value, label = 'nonce') {
  const parsed = canonicalUint(value, label);
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw codedError('OUTBOX_INVALID_NONCE', `${label} exceeds the exact JavaScript integer range`);
  }
  return Number(parsed);
}

function canonicalHash(value, label) {
  if (!isHexString(value, 32) || String(value).toLowerCase() === ZERO_HASH) {
    throw codedError('OUTBOX_INVALID_CHAIN_DATA', `${label} must be a nonzero bytes32 value`);
  }
  return String(value).toLowerCase();
}

function canonicalData(value) {
  if (!isHexString(value)) {
    throw codedError('OUTBOX_INVALID_TRANSACTION', 'transaction calldata must be hex bytes');
  }
  return String(value).toLowerCase();
}

function canonicalActionId(value) {
  const actionId = String(value || '');
  if (!actionId || Buffer.byteLength(actionId, 'utf8') > 512 || /[\u0000-\u001f]/.test(actionId)) {
    throw codedError('OUTBOX_INVALID_ACTION', 'outbox action id must be 1..512 printable bytes');
  }
  return actionId;
}

function actionFileName(actionId) {
  return `${crypto.createHash('sha256').update(actionId, 'utf8').digest('hex')}.json`;
}

function leaseIdFor(directory, actionId) {
  const identity = JSON.stringify({
    kind: 'delegate-signed-transaction-outbox',
    journal: path.join(directory, actionFileName(actionId)),
  });
  return `0x${crypto.createHash('sha256').update(identity, 'utf8').digest('hex')}`;
}

function intentHashFor(binding) {
  const canonical = JSON.stringify({
    chainId: String(binding.chainId),
    signer: getAddress(binding.signer).toLowerCase(),
    to: getAddress(binding.to).toLowerCase(),
    calldataHash: canonicalHash(binding.calldataHash, 'intent calldata hash'),
    value: canonicalUint(binding.value, 'intent value').toString(),
  });
  return `0x${crypto.createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}

function ensurePrivateDirectory(directory, label) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const metadata = fs.lstatSync(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw codedError('OUTBOX_UNSAFE_PATH', `${label} is not a trusted directory`);
  }
  if ((metadata.mode & 0o077) !== 0) {
    throw codedError('OUTBOX_UNSAFE_PERMISSIONS', `${label} must not be accessible by group or other users`);
  }
  return fs.realpathSync(directory);
}

function fsyncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function safeReadJson(filePath, label) {
  const metadata = fs.lstatSync(filePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw codedError('OUTBOX_UNSAFE_PATH', `${label} is not a trusted regular file`);
  }
  if ((metadata.mode & 0o077) !== 0) {
    throw codedError('OUTBOX_UNSAFE_PERMISSIONS', `${label} must have mode 0600`);
  }
  if (metadata.size > MAX_RECORD_BYTES) {
    throw codedError('OUTBOX_RECORD_TOO_LARGE', `${label} exceeds the outbox record size limit`);
  }
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (cause) {
    throw codedError('OUTBOX_CORRUPT_RECORD', `cannot parse ${label}: ${cause && cause.message || cause}`);
  }
  return parsed;
}

let writeSequence = 0;
function durableWriteJson(filePath, value) {
  const directory = path.dirname(filePath);
  const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}-${writeSequence++}`;
  let fd;
  try {
    fd = fs.openSync(tmp, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(value, null, 2));
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, filePath);
    fs.chmodSync(filePath, 0o600);
    fsyncDirectory(directory);
  } catch (error) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch (_) { /* preserve the original failure */ }
    }
    try { fs.rmSync(tmp, { force: true }); } catch (_) { /* preserve the original failure */ }
    throw error;
  }
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !error || error.code !== 'ESRCH';
  }
}

function readLockOwner(lockPath) {
  const metadata = fs.lstatSync(lockPath);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    throw codedError(
      'OUTBOX_AMBIGUOUS_LOCK',
      'delegate signer lock must be a private non-symlink directory',
    );
  }
  const names = fs.readdirSync(lockPath);
  if (names.length !== 1 || names[0] !== 'owner.json') {
    throw codedError(
      'OUTBOX_AMBIGUOUS_LOCK',
      'delegate signer lock has unexpected contents; refusing unsafe recovery',
    );
  }
  const owner = safeReadJson(path.join(lockPath, 'owner.json'), 'delegate signer lock owner');
  if (!owner || owner.schemaVersion !== 1 || owner.hostname !== os.hostname()
      || !Number.isSafeInteger(owner.pid) || owner.pid <= 0
      || !/^0x[0-9a-f]{64}$/.test(String(owner.token || ''))) {
    throw codedError(
      'OUTBOX_AMBIGUOUS_LOCK',
      'delegate signer lock has no recoverable same-host owner; refusing unsafe recovery',
    );
  }
  return owner;
}

function removeOwnedLockDirectory(directory, expected) {
  const owner = readLockOwner(directory);
  if (owner.pid !== expected.pid || owner.hostname !== expected.hostname || owner.token !== expected.token) {
    throw codedError('OUTBOX_LOCK_OWNERSHIP_CHANGED', 'delegate signer lock ownership changed');
  }
  fs.unlinkSync(path.join(directory, 'owner.json'));
  fs.rmdirSync(directory);
}

function buildLockClaim(lockPath, owner) {
  const staging = `${lockPath}.claim-${owner.pid}-${owner.token.slice(2, 18)}`;
  fs.mkdirSync(staging, { mode: 0o700 });
  let ownerFd;
  try {
    ownerFd = fs.openSync(path.join(staging, 'owner.json'), 'wx', 0o600);
    fs.writeFileSync(ownerFd, JSON.stringify(owner));
    fs.fsyncSync(ownerFd);
    fs.closeSync(ownerFd);
    ownerFd = undefined;
    fsyncDirectory(staging);
    return staging;
  } catch (error) {
    if (ownerFd !== undefined) {
      try { fs.closeSync(ownerFd); } catch (_) { /* preserve original */ }
    }
    try { fs.unlinkSync(path.join(staging, 'owner.json')); } catch (_) { /* preserve original */ }
    try { fs.rmdirSync(staging); } catch (_) { /* preserve original */ }
    throw error;
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function withSignerLock(lockPath, timeoutMs, fn) {
  const token = `0x${crypto.randomBytes(32).toString('hex')}`;
  const owner = { schemaVersion: 1, hostname: os.hostname(), pid: process.pid, token };
  const started = Date.now();
  let held = false;
  while (!held) {
    const staging = buildLockClaim(lockPath, owner);
    try {
      // The fully-fsynced staging directory becomes visible atomically. There is no recoverable
      // state in which the canonical lock exists without a complete owner.json.
      fs.renameSync(staging, lockPath);
      fsyncDirectory(path.dirname(lockPath));
      held = true;
    } catch (error) {
      try { removeOwnedLockDirectory(staging, owner); } catch (cleanupError) {
        if (!cleanupError || cleanupError.code !== 'ENOENT') throw cleanupError;
      }
      if (!error || !['EEXIST', 'ENOTEMPTY', 'ENOTDIR', 'EISDIR'].includes(error.code)) throw error;
      let incumbent;
      try {
        incumbent = readLockOwner(lockPath);
      } catch (readError) {
        // The prior owner may have atomically renamed its lock to the release path after our
        // rename observed EEXIST.  That is ordinary contention, not a malformed lock.
        if (readError && readError.code === 'ENOENT') continue;
        throw readError;
      }
      if (!processIsAlive(incumbent.pid)) {
        const abandoned = `${lockPath}.abandoned-${process.pid}-${token.slice(2, 18)}`;
        try {
          fs.renameSync(lockPath, abandoned);
          removeOwnedLockDirectory(abandoned, incumbent);
          fsyncDirectory(path.dirname(lockPath));
          continue;
        } catch (reclaimError) {
          if (reclaimError && ['ENOENT', 'EEXIST'].includes(reclaimError.code)) continue;
          throw reclaimError;
        }
      }
      if (Date.now() - started >= timeoutMs) {
        throw codedError('OUTBOX_LOCK_BUSY', 'timed out acquiring the delegate signer nonce lock');
      }
      // eslint-disable-next-line no-await-in-loop
      await delay(10);
    }
  }

  try {
    return await fn();
  } finally {
    const current = readLockOwner(lockPath);
    if (current.pid !== process.pid || current.token !== token) {
      throw codedError('OUTBOX_LOCK_OWNERSHIP_CHANGED', 'delegate signer lock ownership changed while held');
    }
    const releasing = `${lockPath}.release-${process.pid}-${token.slice(2, 18)}`;
    fs.renameSync(lockPath, releasing);
    removeOwnedLockDirectory(releasing, owner);
    fsyncDirectory(path.dirname(lockPath));
  }
}

function safeRecordView(record, preferredTransactionHash = null) {
  const selectedHash = preferredTransactionHash
    || (record.terminal && record.terminal.transactionHash)
    || record.attempts[record.attempts.length - 1].transactionHash;
  const attempt = record.attempts.find((item) => item.transactionHash === selectedHash)
    || record.attempts[record.attempts.length - 1];
  return {
    actionId: record.actionId,
    intent: { ...record.intent },
    nonce: attempt.nonce,
    transactionHash: attempt.transactionHash,
    transactionHashes: record.attempts.map((item) => item.transactionHash),
    phase: record.terminal ? 'terminal' : (attempt.receipt && attempt.receipt.status === 0 ? 'failed' : 'prepared'),
    attemptCount: record.attempts.length,
    terminal: record.terminal ? { ...record.terminal } : null,
  };
}

function blockNumber(value, label) {
  return canonicalNonce(value, label);
}

class SignedTransactionOutbox {
  constructor({
    directory,
    lockRoot,
    chainId,
    signer,
    provider,
    confirmations = 1,
    allowUnfinalizedDevnet = false,
    hooks = {},
    lockTimeoutMs = 30_000,
  }) {
    if (!signer || typeof signer.signTransaction !== 'function' || !signer.address) {
      throw codedError('OUTBOX_SIGNER_REQUIRED', 'offline EIP-1559 signer is required');
    }
    if (!provider || typeof provider.getNetwork !== 'function') {
      throw codedError('OUTBOX_PROVIDER_REQUIRED', 'L1 provider is required');
    }
    this.chainId = canonicalUint(chainId, 'chain id');
    if (this.chainId === 0n) throw codedError('OUTBOX_INVALID_CHAIN', 'chain id must be nonzero');
    this.signer = signer;
    this.signerAddress = getAddress(signer.address);
    this.provider = provider;
    this.confirmations = canonicalNonce(confirmations, 'confirmations');
    if (this.confirmations < 1 || this.confirmations > 64) {
      throw codedError('OUTBOX_INVALID_CONFIRMATIONS', 'confirmations must be in 1..64');
    }
    this.allowUnfinalizedDevnet = allowUnfinalizedDevnet === true;
    if (this.allowUnfinalizedDevnet && this.chainId !== 31337n) {
      throw codedError('OUTBOX_UNSAFE_FINALITY', 'unfinalized fallback is restricted to chain 31337');
    }
    this.directory = ensurePrivateDirectory(path.resolve(directory), 'delegate transaction outbox');
    this.lockRoot = ensurePrivateDirectory(path.resolve(lockRoot), 'delegate signer lock directory');
    this.lockPath = path.join(
      this.lockRoot,
      `.intmax-l1-signer-${this.chainId}-${this.signerAddress.slice(2).toLowerCase()}.lock`,
    );
    this.reservationPath = path.join(
      this.lockRoot,
      `.intmax-l1-signer-${this.chainId}-${this.signerAddress.slice(2).toLowerCase()}.reservation.json`,
    );
    this.hooks = hooks && typeof hooks === 'object' ? hooks : {};
    this.lockTimeoutMs = canonicalNonce(lockTimeoutMs, 'lock timeout');
  }

  static create({ rpcUrl, privateKey, provider = null, signer = null, ...options }) {
    const rpcProvider = provider || new JsonRpcProvider(rpcUrl);
    const offlineSigner = signer || new EthersWallet(privateKey);
    return new SignedTransactionOutbox({ ...options, provider: rpcProvider, signer: offlineSigner });
  }

  _recordPath(actionId) {
    return path.join(this.directory, actionFileName(actionId));
  }

  async _hook(name, details) {
    if (typeof this.hooks[name] === 'function') await this.hooks[name](details);
  }

  async _assertNetwork() {
    const network = await this.provider.getNetwork();
    const actual = canonicalUint(network && network.chainId, 'RPC chain id');
    if (actual !== this.chainId) {
      throw codedError(
        'OUTBOX_CHAIN_MISMATCH',
        `delegate L1 RPC chain id ${actual} differs from configured ${this.chainId}`,
      );
    }
  }

  _validateRecord(record, expectedActionId = null) {
    if (!record || record.schemaVersion !== SCHEMA_VERSION || typeof record.actionId !== 'string'
        || !record.intent || !Array.isArray(record.attempts) || record.attempts.length < 1) {
      throw codedError('OUTBOX_CORRUPT_RECORD', 'delegate transaction outbox record has an unsupported shape');
    }
    if (expectedActionId !== null && record.actionId !== expectedActionId) {
      throw codedError('OUTBOX_ACTION_COLLISION', 'outbox action id hash collision detected');
    }
    if (record.intent.chainId !== this.chainId.toString()
        || getAddress(record.intent.signer) !== this.signerAddress) {
      throw codedError('OUTBOX_IDENTITY_MISMATCH', 'outbox record belongs to another chain or signer');
    }
    if (record.signerLockRoot !== this.lockRoot) {
      throw codedError(
        'OUTBOX_LOCK_ROOT_MISMATCH',
        'outbox record is bound to a different canonical signer lock root',
      );
    }
    if (record.leaseId !== leaseIdFor(this.directory, record.actionId)) {
      throw codedError('OUTBOX_LEASE_ID_MISMATCH', 'outbox record has a non-canonical signer lease id');
    }
    for (const attempt of record.attempts) this._validateAttempt(record, attempt);
    return record;
  }

  _validateAttempt(record, attempt) {
    if (!attempt || attempt.type !== 2 || !isHexString(attempt.rawSignedTransaction)
        || !isHexString(attempt.transactionHash, 32)) {
      throw codedError('OUTBOX_CORRUPT_RECORD', 'outbox signed transaction attempt is malformed');
    }
    let decoded;
    try {
      decoded = Transaction.from(attempt.rawSignedTransaction);
    } catch (cause) {
      throw codedError('OUTBOX_CORRUPT_RECORD', `cannot decode journaled transaction: ${cause && cause.message || cause}`);
    }
    const expectedTo = getAddress(record.intent.to);
    if (decoded.type !== 2 || decoded.chainId !== this.chainId
        || getAddress(decoded.from) !== this.signerAddress
        || canonicalNonce(decoded.nonce) !== canonicalNonce(attempt.nonce)
        || getAddress(decoded.to) !== expectedTo
        || keccak256(decoded.data).toLowerCase() !== record.intent.calldataHash
        || decoded.value.toString() !== record.intent.value
        || decoded.gasLimit.toString() !== String(attempt.gasLimit)
        || decoded.maxFeePerGas.toString() !== String(attempt.maxFeePerGas)
        || decoded.maxPriorityFeePerGas.toString() !== String(attempt.maxPriorityFeePerGas)
        || String(decoded.hash).toLowerCase() !== String(attempt.transactionHash).toLowerCase()
        || decoded.serialized.toLowerCase() !== String(attempt.rawSignedTransaction).toLowerCase()) {
      throw codedError('OUTBOX_TAMPERED_TRANSACTION', 'journaled raw transaction does not match its immutable binding');
    }
  }

  _load(actionId) {
    const filePath = this._recordPath(actionId);
    try {
      return this._validateRecord(safeReadJson(filePath, `outbox action ${actionId}`), actionId);
    } catch (error) {
      if (error && error.code === 'ENOENT') return null;
      throw error;
    }
  }

  _allRecords() {
    const records = [];
    for (const name of fs.readdirSync(this.directory)) {
      if (!/^[0-9a-f]{64}\.json$/.test(name)) continue;
      records.push(this._validateRecord(safeReadJson(path.join(this.directory, name), `outbox record ${name}`)));
    }
    return records;
  }

  _write(record) {
    this._validateRecord(record, record.actionId);
    durableWriteJson(this._recordPath(record.actionId), record);
  }

  _loadReservation() {
    let reservation;
    try {
      reservation = safeReadJson(this.reservationPath, 'persistent signer nonce reservation');
    } catch (error) {
      if (error && error.code === 'ENOENT') return null;
      throw error;
    }
    const legacy = reservation && reservation.schemaVersion === SCHEMA_VERSION;
    const current = reservation && reservation.schemaVersion === RESERVATION_SCHEMA_VERSION;
    if (!reservation || (!legacy && !current)
        || reservation.chainId !== this.chainId.toString()
        || getAddress(reservation.signer) !== this.signerAddress
        || reservation.signerLockRoot !== this.lockRoot
        || !/^0x[0-9a-f]{64}$/.test(String(reservation.leaseId || ''))
        || typeof reservation.journalIdentity !== 'string'
        || !path.isAbsolute(reservation.journalIdentity)) {
      throw codedError(
        'OUTBOX_CORRUPT_RESERVATION',
        'persistent signer reservation has an invalid chain/signer/lease/journal binding',
      );
    }
    canonicalNonce(reservation.nonce, 'reserved nonce');
    if (legacy) {
      if (!/^0x[0-9a-f]{64}$/.test(String(reservation.transactionHash || ''))) {
        throw codedError(
          'OUTBOX_CORRUPT_RESERVATION',
          'legacy persistent signer reservation has no exact transaction hash',
        );
      }
      return { ...reservation, stage: 'transaction', intentHash: null, previousTransactionHash: null };
    }
    if (!['intent', 'transaction'].includes(reservation.stage)
        || !/^0x[0-9a-f]{64}$/.test(String(reservation.intentHash || ''))
        || (reservation.stage === 'transaction'
          && !/^0x[0-9a-f]{64}$/.test(String(reservation.transactionHash || '')))
        || (reservation.stage === 'intent' && reservation.transactionHash !== null)
        || (reservation.previousTransactionHash !== null
          && !/^0x[0-9a-f]{64}$/.test(String(reservation.previousTransactionHash || '')))) {
      throw codedError(
        'OUTBOX_CORRUPT_RESERVATION',
        'persistent signer reservation has an invalid intent/transaction stage',
      );
    }
    return reservation;
  }

  _writeReservation(record, attempt) {
    const reservation = {
      schemaVersion: RESERVATION_SCHEMA_VERSION,
      stage: 'transaction',
      leaseId: record.leaseId,
      journalIdentity: this._recordPath(record.actionId),
      chainId: this.chainId.toString(),
      signer: this.signerAddress,
      signerLockRoot: this.lockRoot,
      nonce: canonicalNonce(attempt.nonce),
      intentHash: intentHashFor(record.intent),
      previousTransactionHash: null,
      transactionHash: canonicalHash(attempt.transactionHash, 'reserved transaction hash'),
      updatedAt: new Date().toISOString(),
    };
    durableWriteJson(this.reservationPath, reservation);
    return reservation;
  }

  _writeIntentReservation(actionId, binding, nonce, previousTransactionHash = null) {
    const reservation = {
      schemaVersion: RESERVATION_SCHEMA_VERSION,
      stage: 'intent',
      leaseId: leaseIdFor(this.directory, actionId),
      journalIdentity: this._recordPath(actionId),
      chainId: this.chainId.toString(),
      signer: this.signerAddress,
      signerLockRoot: this.lockRoot,
      nonce: canonicalNonce(nonce),
      intentHash: intentHashFor(binding),
      previousTransactionHash: previousTransactionHash == null
        ? null : canonicalHash(previousTransactionHash, 'prior transaction hash'),
      transactionHash: null,
      updatedAt: new Date().toISOString(),
    };
    durableWriteJson(this.reservationPath, reservation);
    return reservation;
  }

  _assertReservationIntent(reservation, actionId, binding) {
    this._assertReservationAction(reservation, actionId);
    if (reservation.intentHash !== null && reservation.intentHash !== intentHashFor(binding)) {
      throw codedError(
        'OUTBOX_SIGNER_RESERVED',
        `signer nonce lane is reserved by another semantic action (${reservation.leaseId})`,
        { leaseId: reservation.leaseId, transactionHash: reservation.transactionHash },
      );
    }
  }

  _assertReservationAction(reservation, actionId) {
    if (reservation.leaseId !== leaseIdFor(this.directory, actionId)
        || reservation.journalIdentity !== this._recordPath(actionId)) {
      throw codedError(
        'OUTBOX_SIGNER_RESERVED',
        `signer nonce lane is reserved by another semantic action (${reservation.leaseId})`,
        { leaseId: reservation.leaseId, transactionHash: reservation.transactionHash },
      );
    }
  }

  async _ensureReservation(record, replacementRequested = false) {
    const existing = this._loadReservation();
    if (existing && existing.leaseId !== record.leaseId) {
      throw codedError(
        'OUTBOX_SIGNER_RESERVED',
        `signer nonce lane is reserved by another semantic action (${existing.leaseId})`,
        { leaseId: existing.leaseId, transactionHash: existing.transactionHash },
      );
    }
    const last = record.attempts[record.attempts.length - 1];
    if (existing) {
      this._assertReservationIntent(existing, record.actionId, record.intent);
      if (existing.stage === 'intent') {
        const prior = existing.previousTransactionHash;
        const committed = record.attempts.find((attempt) => (
          canonicalNonce(attempt.nonce) === canonicalNonce(existing.nonce)
            && (prior === null || attempt.transactionHash !== prior)
        ));
        if (committed) {
          // Crash after the action WAL fsync but before the intent reservation was advanced to
          // the exact transaction hash. The intent lease kept every sibling action excluded.
          this._writeReservation(record, committed);
          return;
        }
        if (replacementRequested && prior === last.transactionHash) return;
        throw codedError(
          'OUTBOX_INCOMPLETE_INTENT_RESERVATION',
          'signer lane holds an interrupted pre-sign replacement; retry the same explicit replacement request',
          { leaseId: existing.leaseId, nonce: existing.nonce },
        );
      }
      const referenced = record.attempts.find((attempt) => (
        attempt.transactionHash === existing.transactionHash
        && canonicalNonce(attempt.nonce) === canonicalNonce(existing.nonce)
      ));
      if (!referenced || existing.journalIdentity !== this._recordPath(record.actionId)) {
        throw codedError(
          'OUTBOX_RESERVATION_MISMATCH',
          'persistent signer reservation does not match its canonical outbox journal',
        );
      }
      // An explicit replacement is written to the action journal before this pointer is advanced.
      // A crash in that tiny interval leaves the same lease in control and is repaired here.
      if (existing.transactionHash !== last.transactionHash) this._writeReservation(record, last);
      return;
    }

    // The reservation is installed before every broadcast. If it is absent, a journaled raw tx
    // should never have escaped. Refuse to resurrect it if the RPC proves otherwise or proves that
    // another transaction has already consumed its nonce.
    const [receipt, known, latestNonce] = await Promise.all([
      this.provider.getTransactionReceipt(last.transactionHash),
      this.provider.getTransaction(last.transactionHash),
      this.provider.getTransactionCount(this.signerAddress, 'latest'),
    ]);
    if (receipt || known || canonicalNonce(latestNonce, 'RPC latest nonce') > canonicalNonce(last.nonce)) {
      throw codedError(
        'OUTBOX_RESERVATION_LOST',
        'journaled transaction may have escaped but its persistent signer reservation is missing',
        { transactionHash: last.transactionHash, nonce: last.nonce },
      );
    }
    this._writeReservation(record, last);
  }

  _releaseReservation(record, requireOwned = false) {
    const existing = this._loadReservation();
    if (!existing) return;
    if (existing.leaseId !== record.leaseId
        || existing.journalIdentity !== this._recordPath(record.actionId)) {
      if (requireOwned) {
        throw codedError('OUTBOX_SIGNER_RESERVED', 'cannot release another semantic action\'s signer reservation');
      }
      return;
    }
    // A terminal action may release only the nonce actually consumed by its durable terminal
    // receipt.  This also covers an older same-nonce fee version winning, while refusing to drop
    // a lease for a newer fresh-nonce attempt.
    if (record.terminal) {
      const terminalAttempt = record.attempts.find(
        (attempt) => attempt.transactionHash === record.terminal.transactionHash,
      );
      const reservedAttempt = record.attempts.find(
        (attempt) => attempt.transactionHash === existing.transactionHash,
      );
      const exactTerminalNonce = terminalAttempt && reservedAttempt
        && existing.stage === 'transaction'
        && canonicalNonce(existing.nonce) === canonicalNonce(terminalAttempt.nonce)
        && canonicalNonce(reservedAttempt.nonce) === canonicalNonce(terminalAttempt.nonce);
      if (!exactTerminalNonce) {
        if (requireOwned) {
          throw codedError(
            'OUTBOX_RESERVATION_MISMATCH',
            'terminal evidence does not consume the exact durably reserved signer nonce',
          );
        }
        return;
      }
    }
    fs.unlinkSync(this.reservationPath);
    fsyncDirectory(this.lockRoot);
  }

  _intent({ actionId, to, data, value = 0n }) {
    const canonicalId = canonicalActionId(actionId);
    const calldata = canonicalData(data);
    return {
      actionId: canonicalId,
      data: calldata,
      binding: {
        chainId: this.chainId.toString(),
        signer: this.signerAddress,
        to: getAddress(to),
        calldataHash: keccak256(calldata).toLowerCase(),
        value: canonicalUint(value, 'transaction value').toString(),
      },
    };
  }

  _assertSameIntent(record, binding) {
    const current = record.intent;
    if (current.chainId !== binding.chainId
        || getAddress(current.signer) !== getAddress(binding.signer)
        || getAddress(current.to) !== getAddress(binding.to)
        || String(current.calldataHash).toLowerCase() !== binding.calldataHash
        || String(current.value) !== binding.value) {
      throw codedError(
        'OUTBOX_INTENT_MISMATCH',
        'refusing to reuse an outbox action for a different target, calldata, value, chain, or signer',
      );
    }
  }

  async _reserveNonce() {
    const pending = canonicalNonce(
      await this.provider.getTransactionCount(this.signerAddress, 'pending'),
      'RPC pending nonce',
    );
    let highest = -1;
    for (const record of this._allRecords()) {
      for (const attempt of record.attempts) highest = Math.max(highest, canonicalNonce(attempt.nonce));
    }
    return Math.max(pending, highest + 1);
  }

  async _feeAndGas(binding, data, feeOverride = null, priorAttempt = null) {
    const feeData = feeOverride || await this.provider.getFeeData();
    const maxFeePerGas = canonicalUint(feeData && feeData.maxFeePerGas, 'maxFeePerGas');
    const maxPriorityFeePerGas = canonicalUint(
      feeData && feeData.maxPriorityFeePerGas,
      'maxPriorityFeePerGas',
    );
    if (maxFeePerGas === 0n || maxPriorityFeePerGas === 0n || maxFeePerGas < maxPriorityFeePerGas) {
      throw codedError('OUTBOX_INVALID_FEE', 'EIP-1559 fee caps must be positive and maxFee must cover priority fee');
    }
    if (priorAttempt) {
      const minimumMax = (BigInt(priorAttempt.maxFeePerGas) * 110n + 99n) / 100n;
      const minimumPriority = (BigInt(priorAttempt.maxPriorityFeePerGas) * 110n + 99n) / 100n;
      if (maxFeePerGas < minimumMax || maxPriorityFeePerGas < minimumPriority) {
        throw codedError('OUTBOX_REPLACEMENT_FEE_TOO_LOW', 'explicit replacement must bump both EIP-1559 fee caps by at least 10%');
      }
    }
    const estimate = canonicalUint(await this.provider.estimateGas({
      from: this.signerAddress,
      to: binding.to,
      data,
      value: BigInt(binding.value),
    }), 'estimated gas');
    if (estimate === 0n) throw codedError('OUTBOX_INVALID_GAS', 'estimated gas must be positive');
    const gasLimit = priorAttempt
      ? BigInt(priorAttempt.gasLimit)
      : estimate + ((estimate + 4n) / 5n); // fixed 20% execution-race margin
    return { gasLimit, maxFeePerGas, maxPriorityFeePerGas };
  }

  _replacementFee(replacement) {
    if (!replacement || typeof replacement !== 'object'
        || typeof replacement.reason !== 'string' || !replacement.reason.trim()) {
      throw codedError('OUTBOX_REPLACEMENT_NOT_EXPLICIT', 'failed transaction replacement requires a nonempty operator reason');
    }
    return {
      maxFeePerGas: replacement.maxFeePerGas,
      maxPriorityFeePerGas: replacement.maxPriorityFeePerGas,
    };
  }

  async _newAttempt(record, request, priorAttempt = null, replacement = null, forcedNonce = null) {
    const nonce = forcedNonce == null ? await this._reserveNonce() : canonicalNonce(forcedNonce);
    const previousTransactionHash = priorAttempt ? priorAttempt.transactionHash : null;
    const existingReservation = this._loadReservation();
    if (existingReservation) {
      this._assertReservationIntent(existingReservation, request.actionId, request.binding);
      // A stage-intent record is the durable nonce decision made immediately before an
      // interrupted signing attempt.  Recomputing a different nonce after restart (for example
      // because an out-of-band signer consumed the old nonce) must not silently overwrite that
      // decision: the first process may already have produced raw bytes for the reserved nonce.
      if (existingReservation.stage === 'intent'
          && canonicalNonce(existingReservation.nonce) !== nonce) {
        throw codedError(
          'OUTBOX_RESERVATION_NONCE_MISMATCH',
          'interrupted signer reservation nonce differs from the newly computed nonce; operator reconciliation is required',
          { reservedNonce: existingReservation.nonce, computedNonce: nonce },
        );
      }
    }
    // Durable intent ownership precedes offline signing. A crash at any later line leaves a
    // signer-global lease which only this exact action/intent can resume; sibling actions cannot
    // allocate or sign the same nonce after reclaiming the process lock.
    this._writeIntentReservation(
      request.actionId,
      request.binding,
      nonce,
      previousTransactionHash,
    );
    await this._hook('afterReservation', {
      actionId: request.actionId,
      nonce,
      replacement: Boolean(priorAttempt),
    });
    const fee = await this._feeAndGas(
      request.binding,
      request.data,
      priorAttempt ? this._replacementFee(replacement) : null,
      priorAttempt,
    );
    const transaction = {
      type: 2,
      chainId: this.chainId,
      nonce,
      to: request.binding.to,
      data: request.data,
      value: BigInt(request.binding.value),
      gasLimit: fee.gasLimit,
      maxFeePerGas: fee.maxFeePerGas,
      maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
    };
    const rawSignedTransaction = await this.signer.signTransaction(transaction);
    const decoded = Transaction.from(rawSignedTransaction);
    const attempt = {
      type: 2,
      nonce,
      gasLimit: fee.gasLimit.toString(),
      maxFeePerGas: fee.maxFeePerGas.toString(),
      maxPriorityFeePerGas: fee.maxPriorityFeePerGas.toString(),
      rawSignedTransaction: String(rawSignedTransaction).toLowerCase(),
      transactionHash: canonicalHash(decoded.hash, 'signed transaction hash'),
      preparedAt: new Date().toISOString(),
      broadcastCount: 0,
      receipt: null,
      replacementReason: priorAttempt ? replacement.reason.trim() : null,
    };
    await this._hook('afterSign', {
      actionId: request.actionId,
      nonce,
      transactionHash: attempt.transactionHash,
      replacement: Boolean(priorAttempt),
    });
    const next = record || {
      schemaVersion: SCHEMA_VERSION,
      actionId: request.actionId,
      signerLockRoot: this.lockRoot,
      leaseId: leaseIdFor(this.directory, request.actionId),
      intent: request.binding,
      attempts: [],
      terminal: null,
    };
    next.attempts.push(attempt);
    this._write(next);
    // This signer-wide durable lease is the cross-publisher hand-off point. It exists before the
    // mutex is released and before broadcast, and remains until a finalized expected transition.
    this._writeReservation(next, attempt);
    await this._hook('afterPersist', {
      actionId: request.actionId,
      nonce,
      transactionHash: attempt.transactionHash,
      replacement: Boolean(priorAttempt),
    });
    return next;
  }

  async _observeReceipt(record, attempt) {
    const receipt = await this.provider.getTransactionReceipt(attempt.transactionHash);
    if (!receipt) return null;
    const receiptHash = receipt.hash || receipt.transactionHash;
    if (receiptHash && canonicalHash(receiptHash, 'receipt transaction hash') !== attempt.transactionHash) {
      throw codedError('OUTBOX_INVALID_RECEIPT', 'RPC returned a receipt for a different transaction');
    }
    const status = Number(receipt.status);
    if (status !== 0 && status !== 1) {
      throw codedError('OUTBOX_INVALID_RECEIPT', 'transaction receipt has no canonical status');
    }
    const observation = {
      status,
      blockNumber: blockNumber(receipt.blockNumber, 'receipt block number'),
      blockHash: canonicalHash(receipt.blockHash, 'receipt block hash'),
    };
    await this._hook('afterReceipt', {
      actionId: record.actionId,
      transactionHash: attempt.transactionHash,
      ...observation,
    });
    return { receipt, observation };
  }

  async _refreshAttemptReceipts(record) {
    const successful = [];
    const failed = [];
    let changed = false;
    for (const attempt of record.attempts) {
      // Every same-nonce fee replacement remains a candidate until one version is mined.  Looking
      // only at the newest raw transaction can miss an older version that won the race.
      // eslint-disable-next-line no-await-in-loop
      const observed = await this._observeReceipt(record, attempt);
      const next = observed ? observed.observation : null;
      if (JSON.stringify(attempt.receipt) !== JSON.stringify(next)) {
        attempt.receipt = next;
        changed = true;
      }
      if (observed && observed.observation.status === 1) successful.push({ attempt, ...observed });
      if (observed && observed.observation.status === 0) failed.push({ attempt, ...observed });
    }
    if (changed) this._write(record);
    const receiptsByNonce = new Map();
    for (const mined of [...successful, ...failed]) {
      const nonce = canonicalNonce(mined.attempt.nonce);
      if (receiptsByNonce.has(nonce)) {
        throw codedError(
          'OUTBOX_NONCE_RECEIPT_CONFLICT',
          'RPC returned mined receipts for multiple raw transactions with the same signer nonce',
        );
      }
      receiptsByNonce.set(nonce, mined.attempt.transactionHash);
    }
    if (successful.length > 1) {
      throw codedError(
        'OUTBOX_MULTIPLE_SUCCESSES',
        'more than one attempt for one semantic action succeeded; refusing ambiguous reconciliation',
      );
    }
    return { successful, failed };
  }

  async _persistReceipt(actionId, transactionHash, observation) {
    await withSignerLock(this.lockPath, this.lockTimeoutMs, async () => {
      const current = this._load(actionId);
      if (!current) throw codedError('OUTBOX_RECORD_MISSING', 'outbox record disappeared during receipt reconciliation');
      const attempt = current.attempts.find((item) => item.transactionHash === transactionHash);
      if (!attempt) throw codedError('OUTBOX_TRANSACTION_MISMATCH', 'receipt does not belong to a journaled attempt');
      attempt.receipt = observation;
      this._write(current);
    });
  }

  async send({ actionId, to, data, value = 0n, replacement = null, resumeOnly = false }) {
    await this._assertNetwork();
    const request = this._intent({ actionId, to, data, value });
    let minedTransactionHash = null;
    let record = await withSignerLock(this.lockPath, this.lockTimeoutMs, async () => {
      let current = this._load(request.actionId);
      if (current) {
        this._assertSameIntent(current, request.binding);
        if (current.terminal) {
          this._releaseReservation(current);
          return current;
        }
        await this._ensureReservation(current, Boolean(replacement));
        const last = current.attempts[current.attempts.length - 1];
        const observations = await this._refreshAttemptReceipts(current);
        if (observations.successful.length === 1) {
          if (replacement) {
            throw codedError('OUTBOX_REPLACEMENT_FORBIDDEN', 'a successful transaction cannot be replaced');
          }
          minedTransactionHash = observations.successful[0].attempt.transactionHash;
        } else {
          // A receipt for any version at the active nonce consumes that nonce. In particular, an
          // older same-nonce raw tx can be mined after a newer fee bump was journaled.
          const activeFailure = observations.failed.find(({ attempt }) => (
            canonicalNonce(attempt.nonce) === canonicalNonce(last.nonce)
          ));
          if (activeFailure) {
            if (!replacement) {
              throw codedError(
                'OUTBOX_REPLACEMENT_REQUIRED',
                `journaled transaction ${activeFailure.attempt.transactionHash} failed; an explicit fresh-nonce attempt is required`,
                { transactionHash: activeFailure.attempt.transactionHash },
              );
            }
            await this._assertReceiptFinalized(activeFailure.receipt);
            current = await this._newAttempt(current, request, last, replacement);
          } else if (replacement) {
            // Pending/dropped replacement keeps the exact semantic effect and nonce. It is never
            // automatic; the caller must provide a reason and a >=10% bump for both fee caps.
            current = await this._newAttempt(current, request, last, replacement, last.nonce);
          }
        }
        return current;
      }
      const incumbent = this._loadReservation();
      if (incumbent) {
        this._assertReservationIntent(incumbent, request.actionId, request.binding);
        if (incumbent.stage !== 'intent' || incumbent.previousTransactionHash !== null) {
          throw codedError(
            'OUTBOX_SIGNER_RESERVED',
            `signer nonce lane is reserved by another semantic action (${incumbent.leaseId})`,
            { leaseId: incumbent.leaseId, transactionHash: incumbent.transactionHash },
          );
        }
        if (replacement) {
          throw codedError('OUTBOX_REPLACEMENT_FORBIDDEN', 'there is no failed journaled transaction to replace');
        }
        return this._newAttempt(null, request, null, null, incumbent.nonce);
      }
      if (replacement) {
        throw codedError('OUTBOX_REPLACEMENT_FORBIDDEN', 'there is no failed journaled transaction to replace');
      }
      if (resumeOnly === true) {
        throw codedError(
          'OUTBOX_DURABLE_SUBMISSION_MISSING',
          'resume-only send found neither a journaled raw transaction nor an interrupted intent reservation',
        );
      }
      return this._newAttempt(null, request);
    });

    if (record.terminal) return { ...safeRecordView(record), alreadyTerminal: true };
    if (minedTransactionHash) {
      return { ...safeRecordView(record, minedTransactionHash), phase: 'mined' };
    }
    const attempt = record.attempts[record.attempts.length - 1];
    if (attempt.receipt && attempt.receipt.status === 0) {
      throw codedError('OUTBOX_REPLACEMENT_REQUIRED', 'failed journaled transaction requires explicit replacement');
    }
    if (attempt.receipt && attempt.receipt.status === 1) return { ...safeRecordView(record), phase: 'mined' };

    const known = await this.provider.getTransaction(attempt.transactionHash);
    if (!known) {
      let response;
      try {
        response = await this.provider.broadcastTransaction(attempt.rawSignedTransaction);
      } catch (error) {
        // The raw bytes were durable before this call. Preserve the deterministic hash so callers
        // can report/reconcile uncertainty without ever fabricating a new transaction.
        if (error && typeof error === 'object' && !error.transactionHash) {
          error.transactionHash = attempt.transactionHash;
        }
        throw error;
      }
      if (!response || String(response.hash).toLowerCase() !== attempt.transactionHash) {
        throw codedError('OUTBOX_BROADCAST_HASH_MISMATCH', 'RPC returned a hash different from the journaled raw transaction');
      }
      await this._hook('afterBroadcast', {
        actionId: record.actionId,
        nonce: attempt.nonce,
        transactionHash: attempt.transactionHash,
      });
      await withSignerLock(this.lockPath, this.lockTimeoutMs, async () => {
        const current = this._load(record.actionId);
        const currentAttempt = current.attempts.find((item) => item.transactionHash === attempt.transactionHash);
        if (!currentAttempt) throw codedError('OUTBOX_TRANSACTION_MISMATCH', 'broadcast attempt disappeared from outbox');
        currentAttempt.broadcastCount = canonicalNonce(currentAttempt.broadcastCount || 0, 'broadcast count') + 1;
        currentAttempt.lastBroadcastAt = new Date().toISOString();
        this._write(current);
        record = current;
      });
    }
    return { ...safeRecordView(record), phase: 'broadcast' };
  }

  async waitForReceipt(actionId, confirmations = this.confirmations) {
    const canonicalId = canonicalActionId(actionId);
    const record = this._load(canonicalId);
    if (!record) throw codedError('OUTBOX_RECORD_MISSING', `no outbox transaction exists for ${canonicalId}`);
    const attempt = record.attempts[record.attempts.length - 1];
    let successful = null;
    let activeFailure = null;
    for (const candidate of record.attempts) {
      // eslint-disable-next-line no-await-in-loop
      const observed = await this._observeReceipt(record, candidate);
      if (!observed) continue;
      if (observed.observation.status === 1) {
        if (successful) {
          throw codedError(
            'OUTBOX_MULTIPLE_SUCCESSES',
            'more than one attempt for one semantic action succeeded; refusing ambiguous reconciliation',
          );
        }
        successful = { receipt: observed.receipt, attempt: candidate };
      } else if (canonicalNonce(candidate.nonce) === canonicalNonce(attempt.nonce)) {
        if (activeFailure) {
          throw codedError(
            'OUTBOX_NONCE_RECEIPT_CONFLICT',
            'RPC returned mined receipts for multiple raw transactions with the same signer nonce',
          );
        }
        activeFailure = { receipt: observed.receipt, attempt: candidate };
      }
    }
    if (successful && activeFailure
        && canonicalNonce(successful.attempt.nonce) === canonicalNonce(activeFailure.attempt.nonce)) {
      throw codedError(
        'OUTBOX_NONCE_RECEIPT_CONFLICT',
        'RPC returned success and failure receipts for one signer nonce',
      );
    }
    let selected = successful || activeFailure;
    let receipt = selected && selected.receipt;
    let receiptAttempt = selected && selected.attempt;
    if (!receipt && typeof this.provider.waitForTransaction === 'function') {
      receipt = await this.provider.waitForTransaction(
        attempt.transactionHash,
        canonicalNonce(confirmations, 'confirmations'),
      );
      receiptAttempt = receipt ? attempt : null;
    }
    if (!receipt) return null;
    const receiptHash = receipt.hash || receipt.transactionHash;
    if (receiptHash && canonicalHash(receiptHash, 'receipt transaction hash') !== receiptAttempt.transactionHash) {
      throw codedError('OUTBOX_INVALID_RECEIPT', 'RPC returned a receipt for a different transaction');
    }
    const status = Number(receipt.status);
    if (status !== 0 && status !== 1) throw codedError('OUTBOX_INVALID_RECEIPT', 'transaction receipt status is invalid');
    const observation = {
      status,
      blockNumber: blockNumber(receipt.blockNumber, 'receipt block number'),
      blockHash: canonicalHash(receipt.blockHash, 'receipt block hash'),
    };
    await this._hook('afterReceipt', {
      actionId: canonicalId,
      transactionHash: receiptAttempt.transactionHash,
      ...observation,
    });
    await this._persistReceipt(canonicalId, receiptAttempt.transactionHash, observation);
    if (status === 0) {
      throw codedError(
        'OUTBOX_REPLACEMENT_REQUIRED',
        `journaled transaction ${receiptAttempt.transactionHash} failed; an explicit fresh-nonce attempt is required`,
        { transactionHash: receiptAttempt.transactionHash },
      );
    }
    return receipt;
  }

  async _durableHead() {
    if (this.allowUnfinalizedDevnet) {
      const latest = blockNumber(await this.provider.getBlockNumber(), 'latest block number');
      const durable = latest - this.confirmations;
      if (durable < 0) return null;
      return this.provider.getBlock(durable);
    }
    let finalized;
    try {
      finalized = await this.provider.getBlock('finalized');
    } catch (cause) {
      throw codedError('OUTBOX_FINALIZED_HEAD_UNAVAILABLE', `RPC finalized head unavailable: ${cause && cause.message || cause}`);
    }
    if (!finalized) throw codedError('OUTBOX_FINALIZED_HEAD_UNAVAILABLE', 'RPC returned no finalized head');
    return finalized;
  }

  async _assertReceiptFinalized(receipt) {
    const receiptNumber = blockNumber(receipt && receipt.blockNumber, 'receipt block number');
    const receiptHash = canonicalHash(receipt && receipt.blockHash, 'receipt block hash');
    const durable = await this._durableHead();
    if (!durable || blockNumber(durable.number, 'durable head number') < receiptNumber) {
      throw codedError(
        'OUTBOX_FAILED_RECEIPT_NOT_FINALIZED',
        'failed receipt is not durable; refusing to allocate a replacement nonce',
      );
    }
    const canonical = await this.provider.getBlock(receiptNumber);
    if (!canonical || canonicalHash(canonical.hash, 'canonical receipt block hash') !== receiptHash) {
      throw codedError('OUTBOX_RECEIPT_REORGED', 'failed receipt block is not canonical');
    }
  }

  async markFinalized(actionId, observation, expectedTransition) {
    await this._assertNetwork();
    const canonicalId = canonicalActionId(actionId);
    const record = this._load(canonicalId);
    if (!record) throw codedError('OUTBOX_RECORD_MISSING', `no outbox transaction exists for ${canonicalId}`);
    if (record.terminal) {
      // Complete a crash interrupted between the terminal journal fsync and lease unlink.
      await withSignerLock(this.lockPath, this.lockTimeoutMs, async () => {
        const current = this._load(canonicalId);
        if (!current || !current.terminal) {
          throw codedError('OUTBOX_TERMINAL_CONFLICT', 'terminal outbox record changed during lease cleanup');
        }
        this._releaseReservation(current);
      });
      return this.status(canonicalId);
    }
    const transactionHash = canonicalHash(observation && observation.transactionHash, 'finalized transaction hash');
    const attempt = record.attempts.find((item) => item.transactionHash === transactionHash);
    if (!attempt) {
      throw codedError('OUTBOX_TRANSACTION_MISMATCH', 'finalized transition was not emitted by a journaled transaction');
    }
    const receipt = await this.provider.getTransactionReceipt(transactionHash);
    if (!receipt || Number(receipt.status) !== 1) {
      throw codedError('OUTBOX_RECEIPT_NOT_SUCCESSFUL', 'journaled transaction has no successful receipt');
    }
    const observedBlockNumber = blockNumber(observation && observation.blockNumber, 'finalized observation block number');
    const observedBlockHash = canonicalHash(observation && observation.blockHash, 'finalized observation block hash');
    if (blockNumber(receipt.blockNumber, 'receipt block number') !== observedBlockNumber
        || canonicalHash(receipt.blockHash, 'receipt block hash') !== observedBlockHash) {
      throw codedError('OUTBOX_OBSERVATION_MISMATCH', 'finalized transition does not match the transaction receipt block');
    }

    const durableBefore = await this._durableHead();
    if (!durableBefore) throw codedError('OUTBOX_FINALIZED_HEAD_UNAVAILABLE', 'durable head is not available yet');
    const durableNumber = blockNumber(durableBefore.number, 'durable head number');
    const durableHash = canonicalHash(durableBefore.hash, 'durable head hash');
    if (durableNumber < observedBlockNumber) {
      throw codedError('OUTBOX_RECEIPT_NOT_FINALIZED', 'transaction receipt is newer than the durable head');
    }
    const canonicalBefore = await this.provider.getBlock(observedBlockNumber);
    if (!canonicalBefore || canonicalHash(canonicalBefore.hash, 'canonical receipt block hash') !== observedBlockHash) {
      throw codedError('OUTBOX_RECEIPT_REORGED', 'receipt block is not canonical at the durable checkpoint');
    }
    if (typeof expectedTransition !== 'function') {
      throw codedError('OUTBOX_EXPECTED_TRANSITION_REQUIRED', 'terminalization requires an expected-transition verifier');
    }
    const transitionAccepted = await expectedTransition({
      blockTag: observedBlockNumber,
      receipt,
      transactionHash,
    });
    if (transitionAccepted !== true) {
      throw codedError('OUTBOX_EXPECTED_TRANSITION_MISSING', 'finalized transaction did not produce the expected protocol transition');
    }

    // Pin both the receipt block and the original finalized checkpoint around the transition read.
    // The head may advance, but the block that authorized this decision must remain byte-identical.
    const [canonicalAfter, durableCheckpointAfter, durableAfter] = await Promise.all([
      this.provider.getBlock(observedBlockNumber),
      this.provider.getBlock(durableNumber),
      this._durableHead(),
    ]);
    if (!canonicalAfter || canonicalHash(canonicalAfter.hash, 'canonical receipt block hash') !== observedBlockHash
        || !durableCheckpointAfter
        || canonicalHash(durableCheckpointAfter.hash, 'durable checkpoint hash') !== durableHash
        || !durableAfter
        || blockNumber(durableAfter.number, 'durable head number') < durableNumber) {
      throw codedError('OUTBOX_FINALIZED_HEAD_CHANGED', 'durable chain view changed while verifying the expected transition');
    }

    const terminal = {
      transactionHash,
      blockNumber: observedBlockNumber,
      blockHash: observedBlockHash,
      durableCheckpointNumber: durableNumber,
      durableCheckpointHash: durableHash,
      finalizedAt: new Date().toISOString(),
    };
    await withSignerLock(this.lockPath, this.lockTimeoutMs, async () => {
      const current = this._load(canonicalId);
      if (!current) throw codedError('OUTBOX_RECORD_MISSING', 'outbox record disappeared before terminalization');
      this._assertSameIntent(current, record.intent);
      const currentAttempt = current.attempts.find((item) => item.transactionHash === transactionHash);
      if (!currentAttempt) throw codedError('OUTBOX_TRANSACTION_MISMATCH', 'journaled attempt changed before terminalization');
      if (current.terminal && (current.terminal.transactionHash !== transactionHash
          || current.terminal.blockHash !== observedBlockHash)) {
        throw codedError('OUTBOX_TERMINAL_CONFLICT', 'outbox action already has a different terminal observation');
      }
      const [commitReceiptBlock, commitDurableBlock] = await Promise.all([
        this.provider.getBlock(observedBlockNumber),
        this.provider.getBlock(durableNumber),
      ]);
      if (!commitReceiptBlock
          || canonicalHash(commitReceiptBlock.hash, 'terminal receipt block hash') !== observedBlockHash
          || !commitDurableBlock
          || canonicalHash(commitDurableBlock.hash, 'terminal durable checkpoint hash') !== durableHash) {
        throw codedError(
          'OUTBOX_FINALIZED_HEAD_CHANGED',
          'durable chain view changed before the terminal journal commit',
        );
      }
      currentAttempt.receipt = { status: 1, blockNumber: observedBlockNumber, blockHash: observedBlockHash };
      current.terminal = current.terminal || terminal;
      this._write(current);
      await this._hook('afterTerminalPersist', {
        actionId: canonicalId,
        transactionHash,
        blockNumber: observedBlockNumber,
        blockHash: observedBlockHash,
      });
      this._releaseReservation(current, true);
    });
    return this.status(canonicalId);
  }

  // Resume an existing durable action without its original high-level artifact. This path never
  // signs or estimates gas: it either proves that only an unjournaled intent existed, or
  // rebroadcasts the byte-identical latest raw transaction already fsynced in the action WAL.
  async resumeExact(actionId) {
    await this._assertNetwork();
    const canonicalId = canonicalActionId(actionId);
    const inspected = await withSignerLock(this.lockPath, this.lockTimeoutMs, async () => {
      const current = this._load(canonicalId);
      if (!current) {
        const reservation = this._loadReservation();
        if (!reservation) return { phase: 'absent', record: null, observations: null };
        if (reservation.leaseId !== leaseIdFor(this.directory, canonicalId)
            || reservation.journalIdentity !== this._recordPath(canonicalId)) {
          // Another action owns the signer lane. This action is genuinely absent; do not mutate
          // the incumbent lease. A later send will still fail closed on that signer-wide fence.
          return { phase: 'absent', record: null, observations: null };
        }
        if (reservation.stage !== 'intent' || reservation.previousTransactionHash !== null
            || reservation.transactionHash !== null) {
          throw codedError(
            'OUTBOX_RESERVATION_MISMATCH',
            'reservation without an action WAL is not an abandonable initial intent',
          );
        }
        fs.unlinkSync(this.reservationPath);
        fsyncDirectory(this.lockRoot);
        return { phase: 'absent', record: null, observations: null };
      }
      if (current.terminal) {
        this._releaseReservation(current);
        return { phase: 'terminal', record: current, observations: null };
      }
      await this._ensureReservation(current, false);
      const observations = await this._refreshAttemptReceipts(current);
      return { phase: 'active', record: current, observations };
    });
    if (inspected.phase === 'absent') return { actionId: canonicalId, phase: 'absent' };
    if (inspected.phase === 'terminal') return safeRecordView(inspected.record);
    const { record, observations } = inspected;
    if (observations.successful.length > 0 || observations.failed.length > 0) {
      return {
        ...safeRecordView(record),
        phase: observations.successful.length > 0 ? 'mined' : 'failed',
      };
    }

    const attempt = record.attempts[record.attempts.length - 1];
    if (!await this.provider.getTransaction(attempt.transactionHash)) {
      let response;
      try {
        response = await this.provider.broadcastTransaction(attempt.rawSignedTransaction);
      } catch (error) {
        if (error && typeof error === 'object' && !error.transactionHash) {
          error.transactionHash = attempt.transactionHash;
        }
        throw error;
      }
      if (!response || String(response.hash).toLowerCase() !== attempt.transactionHash) {
        throw codedError(
          'OUTBOX_BROADCAST_HASH_MISMATCH',
          'RPC returned a hash different from the journaled raw transaction',
        );
      }
      await this._hook('afterBroadcast', {
        actionId: canonicalId,
        nonce: attempt.nonce,
        transactionHash: attempt.transactionHash,
      });
      await withSignerLock(this.lockPath, this.lockTimeoutMs, async () => {
        const current = this._load(canonicalId);
        const currentAttempt = current && current.attempts.find(
          (item) => item.transactionHash === attempt.transactionHash,
        );
        if (!currentAttempt) {
          throw codedError('OUTBOX_TRANSACTION_MISMATCH', 'replayed attempt disappeared from outbox');
        }
        currentAttempt.broadcastCount = canonicalNonce(
          currentAttempt.broadcastCount || 0,
          'broadcast count',
        ) + 1;
        currentAttempt.lastBroadcastAt = new Date().toISOString();
        this._write(current);
      });
    }
    return { ...safeRecordView(record), phase: 'broadcast' };
  }

  // Authenticate a permissionless semantic winner independently of a local signer nonce. This is
  // used after an intent-only crash was conclusively abandoned: there are no raw bytes (and hence
  // no local nonce to settle), but protocol progress still requires the exact successful event,
  // its canonical block, the event-specific getter state, and a durable checkpoint covering it.
  async verifyFinalizedSemantic(semanticObservation, expectedSemanticState) {
    await this._assertNetwork();
    if (typeof expectedSemanticState !== 'function') {
      throw codedError(
        'OUTBOX_SEMANTIC_EVIDENCE_REQUIRED',
        'semantic terminalization requires an exact durable semantic-state verifier',
      );
    }
    const semanticBlockNumber = blockNumber(
      semanticObservation && semanticObservation.blockNumber,
      'semantic evidence block number',
    );
    const semanticBlockHash = canonicalHash(
      semanticObservation && semanticObservation.blockHash,
      'semantic evidence block hash',
    );
    const semanticTransactionHash = canonicalHash(
      semanticObservation && semanticObservation.transactionHash,
      'semantic evidence transaction hash',
    );
    const semanticLogIndex = blockNumber(
      semanticObservation && semanticObservation.logIndex,
      'semantic evidence log index',
    );
    const durableBefore = await this._durableHead();
    if (!durableBefore) {
      throw codedError('OUTBOX_FINALIZED_HEAD_UNAVAILABLE', 'durable head is not available yet');
    }
    const durableNumber = blockNumber(durableBefore.number, 'durable head number');
    const durableHash = canonicalHash(durableBefore.hash, 'durable head hash');
    if (durableNumber < semanticBlockNumber) {
      throw codedError(
        'OUTBOX_SEMANTIC_EVIDENCE_NOT_FINALIZED',
        'external semantic evidence must be covered by the durable head',
      );
    }
    const [semanticBlockBefore, semanticReceiptBefore] = await Promise.all([
      this.provider.getBlock(semanticBlockNumber),
      this.provider.getTransactionReceipt(semanticTransactionHash),
    ]);
    if (!semanticBlockBefore
        || canonicalHash(semanticBlockBefore.hash, 'canonical semantic evidence block hash')
          !== semanticBlockHash) {
      throw codedError(
        'OUTBOX_SUPERSEDED_EVIDENCE_REORGED',
        'external semantic evidence is not canonical',
      );
    }
    if (!semanticReceiptBefore
        || Number(semanticReceiptBefore.status) !== 1
        || blockNumber(semanticReceiptBefore.blockNumber, 'semantic receipt block number')
          !== semanticBlockNumber
        || canonicalHash(semanticReceiptBefore.blockHash, 'semantic receipt block hash')
          !== semanticBlockHash) {
      throw codedError(
        'OUTBOX_SEMANTIC_RECEIPT_MISMATCH',
        'external semantic event transaction has no successful receipt in its claimed canonical block',
      );
    }
    if (await expectedSemanticState({
      blockTag: semanticBlockNumber,
      receipt: semanticReceiptBefore,
      transactionHash: semanticTransactionHash,
      logIndex: semanticLogIndex,
    }) !== true) {
      throw codedError(
        'OUTBOX_SEMANTIC_EVIDENCE_MISSING',
        'the pinned external block does not contain the expected semantic event and state',
      );
    }
    const [semanticBlockAfter, durableCheckpointAfter, durableAfter] = await Promise.all([
      this.provider.getBlock(semanticBlockNumber),
      this.provider.getBlock(durableNumber),
      this._durableHead(),
    ]);
    if (!semanticBlockAfter
        || canonicalHash(semanticBlockAfter.hash, 'rechecked semantic evidence block hash')
          !== semanticBlockHash
        || !durableCheckpointAfter
        || canonicalHash(durableCheckpointAfter.hash, 'rechecked durable checkpoint hash')
          !== durableHash
        || !durableAfter
        || blockNumber(durableAfter.number, 'rechecked durable head number') < durableNumber) {
      throw codedError(
        'OUTBOX_FINALIZED_HEAD_CHANGED',
        'durable chain view changed while verifying semantic evidence',
      );
    }
    return {
      semanticBlockNumber,
      semanticBlockHash,
      semanticTransactionHash,
      semanticLogIndex,
      durableCheckpointNumber: durableNumber,
      durableCheckpointHash: durableHash,
    };
  }

  // An intent-stage lease with no action WAL cannot have reached broadcast: signing is offline and
  // `send` never exposes raw bytes before the action file fsync.  Once the previous process lock is
  // gone, this exact (action, intent) absence is conclusive and may be abandoned without inventing
  // a transaction merely to burn its nonce after a semantic front-run.
  async abandonUnjournaledIntent({ actionId, to, data, value = 0n }) {
    await this._assertNetwork();
    const request = this._intent({ actionId, to, data, value });
    return withSignerLock(this.lockPath, this.lockTimeoutMs, async () => {
      if (this._load(request.actionId)) return false;
      const reservation = this._loadReservation();
      if (!reservation) return false;
      this._assertReservationIntent(reservation, request.actionId, request.binding);
      if (reservation.stage !== 'intent' || reservation.previousTransactionHash !== null
          || reservation.transactionHash !== null) {
        throw codedError(
          'OUTBOX_RESERVATION_MISMATCH',
          'only an initial intent-stage lease without a journaled transaction can be abandoned',
        );
      }
      fs.unlinkSync(this.reservationPath);
      fsyncDirectory(this.lockRoot);
      return true;
    });
  }

  // Settle a locally signed one-shot call after a permissionless sibling changed the same
  // semantic state.  The sibling is not nonce evidence: we keep the signer-wide lease, rebroadcast
  // only the already-journaled raw bytes at the caller, and release here only after this action's
  // active nonce has a canonical-finalized revert.  If our raw succeeded, it follows the ordinary
  // markFinalized expected-transition path instead.
  async settleSuperseded(actionId, semanticObservation, expectedOwnTransition, expectedSemanticState) {
    const canonicalId = canonicalActionId(actionId);
    const resumed = await this.resumeExact(canonicalId);
    if (resumed.phase === 'terminal') return resumed;
    if (resumed.phase === 'absent') {
      if (!semanticObservation || semanticObservation.transactionHash == null
          || semanticObservation.logIndex == null) return resumed;
      const semanticEvidence = await this.verifyFinalizedSemantic(
        semanticObservation,
        expectedSemanticState,
      );
      return { ...resumed, semanticVerified: true, semanticEvidence };
    }
    await this._assertNetwork();
    const inspected = await withSignerLock(this.lockPath, this.lockTimeoutMs, async () => {
      const current = this._load(canonicalId);
      if (!current) {
        throw codedError('OUTBOX_RECORD_MISSING', `no outbox transaction exists for ${canonicalId}`);
      }
      if (current.terminal) {
        this._releaseReservation(current);
        return { terminal: true, record: current, observations: null };
      }
      await this._ensureReservation(current, false);
      const observations = await this._refreshAttemptReceipts(current);
      return { terminal: false, record: current, observations };
    });
    if (inspected.terminal) return this.status(canonicalId);

    const { record, observations } = inspected;
    const activeAttempt = record.attempts[record.attempts.length - 1];
    if (observations.successful.length === 1) {
      const own = observations.successful[0];
      if (canonicalNonce(own.attempt.nonce) !== canonicalNonce(activeAttempt.nonce)) {
        throw codedError(
          'OUTBOX_STALE_SUCCESS_CONFLICT',
          'an older fresh nonce succeeded while a newer signer nonce remains reserved',
        );
      }
      return this.markFinalized(
        canonicalId,
        {
          transactionHash: own.attempt.transactionHash,
          blockNumber: own.observation.blockNumber,
          blockHash: own.observation.blockHash,
        },
        expectedOwnTransition,
      );
    }
    const failed = observations.failed.find(({ attempt }) => (
      canonicalNonce(attempt.nonce) === canonicalNonce(activeAttempt.nonce)
    ));
    if (!failed) return { ...safeRecordView(record), phase: 'awaiting-superseded-receipt' };

    if (typeof expectedSemanticState !== 'function') {
      throw codedError(
        'OUTBOX_SEMANTIC_EVIDENCE_REQUIRED',
        'superseded failure terminalization requires a durable semantic-state verifier',
      );
    }
    const semanticBlockNumber = blockNumber(
      semanticObservation && semanticObservation.blockNumber,
      'semantic evidence block number',
    );
    const semanticBlockHash = canonicalHash(
      semanticObservation && semanticObservation.blockHash,
      'semantic evidence block hash',
    );
    const semanticTransactionHash = canonicalHash(
      semanticObservation && semanticObservation.transactionHash,
      'semantic evidence transaction hash',
    );
    const semanticLogIndex = blockNumber(
      semanticObservation && semanticObservation.logIndex,
      'semantic evidence log index',
    );
    const receiptBlockNumber = blockNumber(failed.receipt.blockNumber, 'failed receipt block number');
    const receiptBlockHash = canonicalHash(failed.receipt.blockHash, 'failed receipt block hash');
    const durableBefore = await this._durableHead();
    if (!durableBefore) {
      throw codedError('OUTBOX_FINALIZED_HEAD_UNAVAILABLE', 'durable head is not available yet');
    }
    const durableNumber = blockNumber(durableBefore.number, 'durable head number');
    const durableHash = canonicalHash(durableBefore.hash, 'durable head hash');
    if (durableNumber < Math.max(receiptBlockNumber, semanticBlockNumber)) {
      throw codedError(
        'OUTBOX_SUPERSEDED_EVIDENCE_NOT_FINALIZED',
        'local revert and external semantic evidence must both be covered by the durable head',
      );
    }
    const [receiptBlockBefore, semanticBlockBefore, semanticReceiptBefore] = await Promise.all([
      this.provider.getBlock(receiptBlockNumber),
      this.provider.getBlock(semanticBlockNumber),
      this.provider.getTransactionReceipt(semanticTransactionHash),
    ]);
    if (!receiptBlockBefore
        || canonicalHash(receiptBlockBefore.hash, 'canonical failed receipt block hash') !== receiptBlockHash
        || !semanticBlockBefore
        || canonicalHash(semanticBlockBefore.hash, 'canonical semantic evidence block hash') !== semanticBlockHash) {
      throw codedError(
        'OUTBOX_SUPERSEDED_EVIDENCE_REORGED',
        'local revert or external semantic evidence is not canonical',
      );
    }
    if (!semanticReceiptBefore
      || Number(semanticReceiptBefore.status) !== 1
      || blockNumber(semanticReceiptBefore.blockNumber, 'semantic receipt block number')
        !== semanticBlockNumber
      || canonicalHash(semanticReceiptBefore.blockHash, 'semantic receipt block hash')
        !== semanticBlockHash
    ) {
      throw codedError(
        'OUTBOX_SEMANTIC_RECEIPT_MISMATCH',
        'external semantic event transaction has no successful receipt in its claimed canonical block',
      );
    }
    if (await expectedSemanticState({
      blockTag: semanticBlockNumber,
      receipt: semanticReceiptBefore,
      transactionHash: semanticTransactionHash,
      logIndex: semanticLogIndex,
    }) !== true) {
      throw codedError(
        'OUTBOX_SEMANTIC_EVIDENCE_MISSING',
        'the pinned external block does not contain the expected semantic state',
      );
    }
    const [receiptBlockAfter, semanticBlockAfter, durableCheckpointAfter, durableAfter] = await Promise.all([
      this.provider.getBlock(receiptBlockNumber),
      this.provider.getBlock(semanticBlockNumber),
      this.provider.getBlock(durableNumber),
      this._durableHead(),
    ]);
    if (!receiptBlockAfter
        || canonicalHash(receiptBlockAfter.hash, 'rechecked failed receipt block hash') !== receiptBlockHash
        || !semanticBlockAfter
        || canonicalHash(semanticBlockAfter.hash, 'rechecked semantic evidence block hash') !== semanticBlockHash
        || !durableCheckpointAfter
        || canonicalHash(durableCheckpointAfter.hash, 'rechecked durable checkpoint hash') !== durableHash
        || !durableAfter
        || blockNumber(durableAfter.number, 'rechecked durable head number') < durableNumber) {
      throw codedError(
        'OUTBOX_FINALIZED_HEAD_CHANGED',
        'durable chain view changed while settling the superseded signer nonce',
      );
    }

    const terminal = {
      outcome: 'superseded-revert',
      transactionHash: failed.attempt.transactionHash,
      blockNumber: receiptBlockNumber,
      blockHash: receiptBlockHash,
      semanticBlockNumber,
      semanticBlockHash,
      semanticTransactionHash,
      semanticLogIndex,
      durableCheckpointNumber: durableNumber,
      durableCheckpointHash: durableHash,
      finalizedAt: new Date().toISOString(),
    };
    await withSignerLock(this.lockPath, this.lockTimeoutMs, async () => {
      const current = this._load(canonicalId);
      if (!current) {
        throw codedError('OUTBOX_RECORD_MISSING', 'outbox record disappeared before superseded terminalization');
      }
      this._assertSameIntent(current, record.intent);
      if (current.terminal) {
        if (current.terminal.outcome !== terminal.outcome
            || current.terminal.transactionHash !== terminal.transactionHash
            || current.terminal.blockHash !== terminal.blockHash
            || current.terminal.semanticBlockHash !== terminal.semanticBlockHash
            || current.terminal.semanticTransactionHash !== terminal.semanticTransactionHash
            || current.terminal.semanticLogIndex !== terminal.semanticLogIndex) {
          throw codedError('OUTBOX_TERMINAL_CONFLICT', 'outbox action has different terminal evidence');
        }
        this._releaseReservation(current, true);
        return;
      }
      const currentActive = current.attempts[current.attempts.length - 1];
      const currentFailed = current.attempts.find(
        (attempt) => attempt.transactionHash === failed.attempt.transactionHash,
      );
      if (!currentFailed
          || canonicalNonce(currentFailed.nonce) !== canonicalNonce(currentActive.nonce)
          || canonicalNonce(currentActive.nonce) !== canonicalNonce(activeAttempt.nonce)) {
        throw codedError(
          'OUTBOX_TERMINAL_CONFLICT',
          'active signer nonce changed before superseded terminalization',
        );
      }
      const [
        commitReceipt,
        commitReceiptBlock,
        commitSemanticBlock,
        commitDurableBlock,
        commitSemanticReceipt,
      ] = await Promise.all([
        this.provider.getTransactionReceipt(failed.attempt.transactionHash),
        this.provider.getBlock(receiptBlockNumber),
        this.provider.getBlock(semanticBlockNumber),
        this.provider.getBlock(durableNumber),
        this.provider.getTransactionReceipt(semanticTransactionHash),
      ]);
      if (!commitReceipt || Number(commitReceipt.status) !== 0
          || blockNumber(commitReceipt.blockNumber, 'commit failed receipt block number') !== receiptBlockNumber
          || canonicalHash(commitReceipt.blockHash, 'commit failed receipt block hash') !== receiptBlockHash
          || !commitReceiptBlock
          || canonicalHash(commitReceiptBlock.hash, 'commit canonical receipt block hash') !== receiptBlockHash
          || !commitSemanticBlock
          || canonicalHash(commitSemanticBlock.hash, 'commit semantic block hash') !== semanticBlockHash
          || !commitDurableBlock
          || canonicalHash(commitDurableBlock.hash, 'commit durable checkpoint hash') !== durableHash
          || !commitSemanticReceipt
            || Number(commitSemanticReceipt.status) !== 1
            || blockNumber(commitSemanticReceipt.blockNumber, 'commit semantic receipt block number')
              !== semanticBlockNumber
            || canonicalHash(commitSemanticReceipt.blockHash, 'commit semantic receipt block hash')
              !== semanticBlockHash
          ) {
        throw codedError(
          'OUTBOX_FINALIZED_HEAD_CHANGED',
          'superseded evidence changed before the terminal journal commit',
        );
      }
      currentFailed.receipt = { status: 0, blockNumber: receiptBlockNumber, blockHash: receiptBlockHash };
      current.terminal = terminal;
      this._write(current);
      await this._hook('afterTerminalPersist', {
        actionId: canonicalId,
        outcome: terminal.outcome,
        transactionHash: terminal.transactionHash,
        blockNumber: terminal.blockNumber,
        blockHash: terminal.blockHash,
      });
      this._releaseReservation(current, true);
    });
    return this.status(canonicalId);
  }

  status(actionId) {
    const record = this._load(canonicalActionId(actionId));
    return record ? safeRecordView(record) : null;
  }

  hasAttempt(actionId, transactionHash) {
    if (!isHexString(transactionHash, 32)) return false;
    const record = this._load(canonicalActionId(actionId));
    const expected = String(transactionHash).toLowerCase();
    return Boolean(record && record.attempts.some((attempt) => attempt.transactionHash === expected));
  }

  async transactionStatus(transactionHash) {
    if (!isHexString(transactionHash, 32)) return 'missing';
    const hash = String(transactionHash).toLowerCase();
    const receipt = await this.provider.getTransactionReceipt(hash);
    if (receipt) return Number(receipt.status) === 1 ? 'mined' : 'failed';
    return (await this.provider.getTransaction(hash)) ? 'pending' : 'missing';
  }
}

module.exports = {
  SCHEMA_VERSION,
  SignedTransactionOutbox,
  actionFileName,
  durableWriteJson,
  ensurePrivateDirectory,
};
