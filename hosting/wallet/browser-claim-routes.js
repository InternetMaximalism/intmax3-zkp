'use strict';

// Same-origin, keyless browser-claim handoff.  Both wallet relays install these routes.  The
// request may select only a token *slot* and carry the public proof produced by browser WASM;
// chain, rollup, manager, verifier, recipient, base-token index and finalized close context are
// re-derived from durable local/RPC authorities and proof public inputs.

const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const path = require('path');
const {
  BrowserClaimCoordinator,
  canonicalAddress,
} = require('../../node/browser-claim');

const JOURNAL_FILE = 'browser_claim_journal.json';
const JOURNAL_SCHEMA = 1;
const JOURNAL_LOCK_OWNER = 'owner.json';

function workflowError(status, message) {
  const error = new Error(message);
  error.httpStatus = status;
  return error;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sameJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function canonicalRuntimeCodeHashes(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw workflowError(409, `${label} runtime code hashes are absent`);
  }
  const keys = Object.keys(value).sort();
  if (!sameJson(keys, ['manager', 'materializer', 'rollup', 'verifier'])) {
    throw workflowError(409, `${label} runtime code hashes have an unexpected schema`);
  }
  const normalized = {};
  for (const key of ['rollup', 'verifier', 'manager', 'materializer']) {
    const hash = String(value[key] || '').toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(hash) || /^0x0{64}$/.test(hash)) {
      throw workflowError(409, `${label} ${key} runtime code hash is invalid`);
    }
    normalized[key] = hash;
  }
  return normalized;
}

function strictBody(body, allowed, required = allowed) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw workflowError(400, 'JSON object body required');
  const unknown = Object.keys(body).filter((key) => !allowed.includes(key));
  if (unknown.length) {
    throw workflowError(400, `caller-supplied browser-claim authority/field is forbidden: ${unknown.join(', ')}`);
  }
  const missing = required.filter((key) => !Object.prototype.hasOwnProperty.call(body, key));
  if (missing.length) throw workflowError(400, `missing browser-claim field: ${missing.join(', ')}`);
  return body;
}

function readJson(file, label) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (_) { throw workflowError(409, `browser claim requires a valid durable ${label}`); }
}

function writePrivateJsonAtomic(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}-${Date.now()}-${writePrivateJsonAtomic.sequence++}`;
  let fd;
  try {
    fd = fs.openSync(tmp, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(value, null, 2));
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, file);
    try {
      const dirFd = fs.openSync(path.dirname(file), 'r');
      try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
    } catch (error) {
      if (!error || !['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error.code)) throw error;
    }
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.rmSync(tmp, { force: true }); } catch (_) { /* preserve original */ }
    throw error;
  }
}
writePrivateJsonAtomic.sequence = 0;

function readJournal(file) {
  if (!fs.existsSync(file)) return { schemaVersion: JOURNAL_SCHEMA, operations: {} };
  const journal = readJson(file, JOURNAL_FILE);
  if (!journal || journal.schemaVersion !== JOURNAL_SCHEMA
      || !journal.operations || typeof journal.operations !== 'object' || Array.isArray(journal.operations)) {
    throw workflowError(409, 'browser claim journal has an unsupported or malformed schema');
  }
  return journal;
}

function operation(journal, operationId) {
  if (!/^0x[0-9a-f]{64}$/.test(String(operationId || ''))) {
    throw workflowError(400, 'operationId must be a canonical 32-byte lowercase hex value');
  }
  const record = journal.operations[operationId];
  if (!record) throw workflowError(404, 'unknown browser claim operation');
  return record;
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means that the process exists but this user cannot signal it.  Only ESRCH proves
    // that a same-host owner is gone; every other result must fail closed.
    return !error || error.code !== 'ESRCH';
  }
}

function readClaimLockOwner(lockDirectory) {
  let metadata;
  try {
    metadata = fs.lstatSync(lockDirectory);
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw error;
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw workflowError(409, 'browser claim journal lock is not a trusted local directory');
  }
  const owner = readJson(path.join(lockDirectory, JOURNAL_LOCK_OWNER), 'browser claim journal lock owner');
  if (!owner || owner.schemaVersion !== 1 || owner.hostname !== os.hostname()
      || !Number.isSafeInteger(owner.pid) || owner.pid <= 0
      || !/^0x[0-9a-f]{64}$/.test(String(owner.token || ''))) {
    throw workflowError(409, 'browser claim journal lock has no recoverable same-host owner');
  }
  return owner;
}

/// Acquire a filesystem-visible journal mutex.  The relay's ordinary `withLock` protects only one
/// JavaScript process; browser claims have their own WAL and therefore also need an inter-process
/// boundary before a read/modify/atomic-rename cycle.  A crashed same-host owner is reclaimed only
/// when the kernel says its PID no longer exists.  Ambiguous/malformed/foreign-host locks are never
/// guessed stale: an operator must resolve them rather than risk two writers.
function acquireClaimJournalLock(journalFile) {
  const lockDirectory = `${journalFile}.lock`;
  const token = `0x${crypto.randomBytes(32).toString('hex')}`;
  const owner = { schemaVersion: 1, hostname: os.hostname(), pid: process.pid, token };

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      fs.mkdirSync(lockDirectory, { mode: 0o700 });
      try {
        writePrivateJsonAtomic(path.join(lockDirectory, JOURNAL_LOCK_OWNER), owner);
      } catch (error) {
        fs.rmSync(lockDirectory, { recursive: true, force: true });
        throw error;
      }
      return () => {
        const current = readClaimLockOwner(lockDirectory);
        if (!current || current.token !== token || current.pid !== process.pid) {
          throw workflowError(409, 'browser claim journal lock ownership changed while held');
        }
        fs.rmSync(lockDirectory, { recursive: true });
      };
    } catch (error) {
      if (!error || error.code !== 'EEXIST') throw error;
      const incumbent = readClaimLockOwner(lockDirectory);
      if (incumbent && !processIsAlive(incumbent.pid)) {
        const abandoned = `${lockDirectory}.abandoned-${process.pid}-${token.slice(2, 18)}`;
        try {
          fs.renameSync(lockDirectory, abandoned);
          fs.rmSync(abandoned, { recursive: true });
          continue;
        } catch (reclaimError) {
          if (reclaimError && ['ENOENT', 'EEXIST', 'ENOTEMPTY'].includes(reclaimError.code)) {
            throw workflowError(409, 'browser claim journal is locked by another relay process');
          }
          throw reclaimError;
        }
      }
      throw workflowError(409, 'browser claim journal is locked by another relay process');
    }
  }
  throw workflowError(409, 'browser claim journal lock could not be acquired');
}

function publicRecord(record) {
  return {
    schemaVersion: JOURNAL_SCHEMA,
    operationId: record.operationId,
    authority: record.authority,
    mleAbiVersion: record.mleAbiVersion,
    submitWithdrawalClaimSelector: record.submitWithdrawalClaimSelector,
    claim: record.claim,
    status: record.status,
    submitTxHash: record.submitTxHash || null,
    accepted: record.accepted || null,
    action: record.action ? {
      kind: record.action.kind,
      amount: record.action.amount,
      txHash: record.action.txHash || null,
      status: record.action.status || 'prepared',
    } : null,
    payout: record.payout || null,
  };
}

function pinnedPart(prepared) {
  return {
    operationId: prepared.operationId,
    authority: prepared.authority,
    mleAbiVersion: prepared.mleAbiVersion,
    submitWithdrawalClaimSelector: prepared.submitWithdrawalClaimSelector,
    claim: prepared.claim,
  };
}

function samePinnedRecord(record, prepared) {
  return sameJson(pinnedPart(record), pinnedPart(prepared));
}

function installBrowserClaimRoutes(app, {
  reqChannel,
  wc,
  rollupOf,
  cli,
  rpc,
  coordinatorFactory = (authority) => new BrowserClaimCoordinator({ rpcUrl: rpc, authority }),
} = {}) {
  if (!app || typeof app.get !== 'function' || typeof app.post !== 'function') {
    throw new Error('an Express-compatible app is required');
  }
  const locks = new Map();

  function withClaimLock(ch, work) {
    const previous = locks.get(ch) || Promise.resolve();
    const run = async () => {
      const release = acquireClaimJournalLock(wc(ch, JOURNAL_FILE));
      try {
        return await work();
      } finally {
        release();
      }
    };
    const current = previous.then(run, run);
    locks.set(ch, current.catch(() => {}));
    return current;
  }

  async function trustedAuthority(ch) {
    const settlement = readJson(wc(ch, 'settlement.json'), 'settlement.json');
    const backingRollup = canonicalAddress(rollupOf(ch), 'channel backing rollup');
    const manager = canonicalAddress(settlement.manager, 'settlement manager');
    const verifier = canonicalAddress(settlement.verifier, 'settlement verifier');
    const closeFundingMaterializer = canonicalAddress(
      settlement.close_funding_materializer,
      'settlement close-funding materializer',
    );
    const settlementRollup = canonicalAddress(settlement.rollup, 'settlement rollup');
    if (settlementRollup !== backingRollup) throw workflowError(409, 'settlement rollup differs from channel backing');
    let durable;
    try {
      const output = await Promise.resolve(cli(ch, [
        'verify-settlement-binding', manager, rpc, backingRollup, verifier,
      ]));
      durable = JSON.parse(output);
    } catch (error) {
      throw workflowError(409, `durable ACTIVE settlement binding failed: ${String(error.stderr || error.message || error)}`);
    }
    const chainId = Number(durable && durable.chainId);
    const startBlock = durable && durable.activationCheckpoint
      ? Number(durable.activationCheckpoint.blockNumber) : 0;
    const authority = {
      chainId,
      channelId: ch,
      manager,
      rollup: backingRollup,
      verifier,
      closeFundingMaterializer,
      startBlock,
    };
    if (!durable || durable.schemaVersion !== 1 || durable.status !== 'active'
        || Number(durable.channelId) !== ch || !Number.isSafeInteger(chainId) || chainId <= 0
        || !Number.isSafeInteger(startBlock) || startBlock < 0
        || canonicalAddress(durable.manager, 'durable manager') !== manager
        || canonicalAddress(durable.rollup, 'durable rollup') !== backingRollup
        || canonicalAddress(durable.verifier, 'durable verifier') !== verifier
        || canonicalAddress(
          durable.closeFundingMaterializer,
          'durable close-funding materializer',
        ) !== closeFundingMaterializer) {
      throw workflowError(409, 'durable ACTIVE settlement authority differs from disk/RPC/channel binding');
    }
    if (chainId !== 31337) {
      const checkpoint = settlement.activation_checkpoint || settlement.activationCheckpoint;
      if (!checkpoint || checkpoint.source !== 'rpcFinalized' || Number(checkpoint.chainId) !== chainId
          || !sameJson(checkpoint, durable.activationCheckpoint)) {
        throw workflowError(409, 'production settlement activation checkpoint is absent or differs from durable authority');
      }
      const durableHashes = canonicalRuntimeCodeHashes(durable.runtimeCodeHashes, 'durable settlement');
      const diskHashes = canonicalRuntimeCodeHashes(
        settlement.runtime_code_hashes || settlement.runtimeCodeHashes,
        'settlement address record',
      );
      if (!sameJson(durableHashes, diskHashes)) {
        throw workflowError(409, 'production settlement runtime code hashes differ across durable authorities');
      }
    }
    return authority;
  }

  async function boundRecord(ch, operationId) {
    const file = wc(ch, JOURNAL_FILE);
    const journal = readJournal(file);
    const record = operation(journal, operationId);
    const authority = await trustedAuthority(ch);
    if (!sameJson(record.authority, authority)) {
      throw workflowError(409, 'browser claim authority changed after operation preparation');
    }
    return { file, journal, record, coordinator: coordinatorFactory(authority) };
  }

  async function revalidatePaid(bound) {
    try {
      const payout = await bound.coordinator.revalidatePaid(bound.record);
      if (!sameJson(payout, bound.record.payout)) {
        throw new Error('journaled payout differs from durable payout evidence');
      }
    } catch (error) {
      throw workflowError(
        409,
        `journaled browser payout failed durable revalidation: ${String(error && error.message || error)}`,
      );
    }
  }

  function handle(handler, locked = false) {
    return (req, res) => Promise.resolve(
      locked ? withClaimLock(reqChannel(req), () => handler(req, res)) : handler(req, res),
    ).catch((error) => {
      console.error(error && (error.stderr || error.message) || error);
      res.status(error.httpStatus || 500).json({ error: String(error && (error.stderr || error.message) || error) });
    });
  }

  app.get('/api/browser-claim/context', handle(async (req, res) => {
    const ch = reqChannel(req);
    const authority = await trustedAuthority(ch);
    const context = await coordinatorFactory(authority).readContext();
    res.json({ schemaVersion: JOURNAL_SCHEMA, ...context });
  }));

  app.post('/api/browser-claim/prepare', handle(async (req, res) => {
    const ch = reqChannel(req);
    const body = strictBody(req.body, ['artifact', 'tokenSlot']);
    const authority = await trustedAuthority(ch);
    const coordinator = coordinatorFactory(authority);
    const prepared = await coordinator.prepare(body.artifact, body.tokenSlot);
    if (BigInt(prepared.claim.amount) <= 0n) throw workflowError(409, 'zero-value withdrawal claims are not submitted');
    const file = wc(ch, JOURNAL_FILE);
    const journal = readJournal(file);
    const prior = journal.operations[prepared.operationId];
    if (prior && !samePinnedRecord(prior, prepared)) {
      throw workflowError(409, 'withdrawal nullifier collides with a different durable browser claim');
    }
    if (prior && prior.status === 'paid') {
      await revalidatePaid({ record: prior, coordinator });
      return res.json(publicRecord(prior));
    }
    if (prior && prior.status === 'accepted' && prepared.status !== 'accepted') {
      throw workflowError(409, 'durable finalized claim acceptance disappeared from the RPC view');
    }
    const record = prior || {
      schemaVersion: JOURNAL_SCHEMA,
      ...pinnedPart(prepared),
      submitDataHash: prepared.submitDataHash,
      transaction: prepared.transaction,
      preparedAt: new Date().toISOString(),
      submitTxHash: null,
      accepted: null,
      action: null,
      payout: null,
    };
    if (prepared.status === 'accepted') {
      record.status = 'accepted';
      record.accepted = prepared.accepted;
      // `prepare` can itself discover that a permissionless sibling beat a previously journaled
      // local transaction. Store the canonical semantic winner rather than retaining the loser.
      record.submitTxHash = prepared.accepted.txHash;
    } else if (!record.status) {
      record.status = 'prepared';
    }
    journal.operations[record.operationId] = record;
    writePrivateJsonAtomic(file, journal);
    res.json({
      ...publicRecord(record),
      finalized: prepared.finalized,
      durable: prepared.durable,
      ...(record.status === 'accepted' ? {} : { transaction: record.transaction }),
    });
  }, true));

  app.post('/api/browser-claim/reconcile-submit', handle(async (req, res) => {
    const ch = reqChannel(req);
    const body = strictBody(req.body, ['operationId', 'txHash']);
    const bound = await boundRecord(ch, body.operationId);
    if (bound.record.status === 'paid' || bound.record.status === 'accepted') {
      if (bound.record.submitTxHash && !sameJson(bound.record.submitTxHash, String(body.txHash).toLowerCase())) {
        throw workflowError(409, 'claim operation is already bound to another exact transaction');
      }
      if (bound.record.status === 'paid') await revalidatePaid(bound);
      return res.json(publicRecord(bound.record));
    }
    if (bound.record.submitTxHash && bound.record.submitTxHash !== String(body.txHash).toLowerCase()) {
      throw workflowError(409, 'claim operation already has a different pending transaction');
    }
    const result = await bound.coordinator.reconcileSubmission(bound.record, body.txHash);
    if (result.status === 'missing') throw workflowError(409, 'claim transaction is not known to the bound RPC');
    bound.record.submitTxHash = result.txHash;
    if (result.status === 'accepted') {
      bound.record.status = 'accepted';
      bound.record.accepted = result;
    } else if (result.status === 'failed') {
      // A finalized revert consumed no nullifier. Clear only the tx binding; the immutable
      // operation/calldata fingerprint remains and may be signed again with a fresh account nonce.
      bound.record.status = 'prepared';
      bound.record.submitTxHash = null;
    } else {
      bound.record.status = 'submit-pending';
    }
    writePrivateJsonAtomic(bound.file, bound.journal);
    res.json(publicRecord(bound.record));
  }, true));

  app.post('/api/browser-claim/status', handle(async (req, res) => {
    const ch = reqChannel(req);
    const body = strictBody(req.body, ['operationId']);
    const bound = await boundRecord(ch, body.operationId);
    if (bound.record.status === 'paid') {
      await revalidatePaid(bound);
    } else if (bound.record.action && bound.record.action.txHash) {
      const result = await bound.coordinator.reconcileAction(bound.record, bound.record.action, bound.record.action.txHash);
      // A permissionless exact action may have won through another transaction (including a
      // wrapper) while our locally prepared transaction reverted. Persist the canonical semantic
      // transaction selected by the coordinator, not the losing local hash.
      if (result.txHash) bound.record.action.txHash = result.txHash;
      if (result.status === 'funded') {
        bound.record.status = 'accepted';
        bound.record.action = null;
      } else if (result.status === 'paid') {
        bound.record.status = 'paid';
        bound.record.action = { ...bound.record.action, status: 'finalized' };
        bound.record.payout = result;
      } else {
        bound.record.action.status = result.status;
      }
      writePrivateJsonAtomic(bound.file, bound.journal);
    } else if (!['accepted', 'paid'].includes(bound.record.status) && bound.record.submitTxHash) {
      const result = await bound.coordinator.reconcileSubmission(bound.record, bound.record.submitTxHash);
      if (result.status === 'accepted') {
        bound.record.status = 'accepted';
        bound.record.accepted = result;
        bound.record.submitTxHash = result.txHash;
      } else if (result.status === 'failed') {
        bound.record.status = 'prepared';
        bound.record.submitTxHash = null;
      } else {
        bound.record.status = 'submit-pending';
      }
      writePrivateJsonAtomic(bound.file, bound.journal);
    } else if (!['accepted', 'paid'].includes(bound.record.status)) {
      const context = await bound.coordinator.readContext();
      const accepted = await bound.coordinator.findAccepted(bound.record.claim, context.durable);
      if (accepted) {
        bound.record.status = 'accepted';
        bound.record.accepted = accepted;
        bound.record.submitTxHash = bound.record.submitTxHash || accepted.txHash;
        writePrivateJsonAtomic(bound.file, bound.journal);
      }
    }
    res.json(publicRecord(bound.record));
  }, true));

  app.post('/api/browser-claim/next', handle(async (req, res) => {
    const ch = reqChannel(req);
    const body = strictBody(req.body, ['operationId']);
    const bound = await boundRecord(ch, body.operationId);
    if (bound.record.status === 'paid') {
      await revalidatePaid(bound);
      return res.json(publicRecord(bound.record));
    }
    if (bound.record.action && bound.record.action.txHash
        && ['pending', 'mined'].includes(bound.record.action.status)) {
      return res.json(publicRecord(bound.record));
    }
    const next = await bound.coordinator.nextPayout(bound.record);
    if (next.status === 'paid') {
      bound.record.status = 'paid';
      bound.record.action = null;
      bound.record.payout = next.payout;
      writePrivateJsonAtomic(bound.file, bound.journal);
      return res.json(publicRecord(bound.record));
    }
    if (next.status === 'no-credit') {
      throw workflowError(409, 'claim credit is zero without an exactly reconciled browser payout');
    }
    bound.record.status = 'action-ready';
    bound.record.action = {
      kind: next.kind,
      amount: next.amount,
      data: next.transaction.data,
      dataHash: next.dataHash,
      status: 'prepared',
      txHash: null,
    };
    writePrivateJsonAtomic(bound.file, bound.journal);
    res.json({ ...publicRecord(bound.record), transaction: next.transaction, durable: next.durable });
  }, true));

  app.post('/api/browser-claim/reconcile-action', handle(async (req, res) => {
    const ch = reqChannel(req);
    const body = strictBody(req.body, ['operationId', 'txHash']);
    const bound = await boundRecord(ch, body.operationId);
    if (bound.record.status === 'paid') {
      if (bound.record.action && bound.record.action.txHash !== String(body.txHash).toLowerCase()) {
        throw workflowError(409, 'payout is already bound to another exact transaction');
      }
      await revalidatePaid(bound);
      return res.json(publicRecord(bound.record));
    }
    if (!bound.record.action) throw workflowError(409, 'prepare the next browser claim action first');
    if (bound.record.action.txHash && bound.record.action.txHash !== String(body.txHash).toLowerCase()) {
      throw workflowError(409, 'browser claim action already has a different pending transaction');
    }
    const result = await bound.coordinator.reconcileAction(bound.record, bound.record.action, body.txHash);
    if (result.status === 'missing') throw workflowError(409, 'browser claim action is not known to the bound RPC');
    bound.record.action.txHash = result.txHash;
    bound.record.action.status = result.status;
    if (result.status === 'funded') {
      bound.record.status = 'accepted';
      bound.record.action = null;
    } else if (result.status === 'paid') {
      bound.record.status = 'paid';
      bound.record.payout = result;
    } else if (result.status === 'failed') {
      // Reverted actions moved no funds. Keep the exact action but release its transaction hash so
      // a later finalized-state re-read can either rebuild it or retry it safely.
      bound.record.status = 'action-ready';
      bound.record.action.txHash = null;
      bound.record.action.status = 'prepared';
    } else {
      bound.record.status = 'action-pending';
    }
    writePrivateJsonAtomic(bound.file, bound.journal);
    res.json(publicRecord(bound.record));
  }, true));

  return { trustedAuthority };
}

module.exports = {
  JOURNAL_FILE,
  acquireClaimJournalLock,
  installBrowserClaimRoutes,
  strictBody,
  writePrivateJsonAtomic,
};
