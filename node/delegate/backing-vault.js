'use strict';

// Durable, immutable archive of the public live-balance artifact paired with each signed head a
// delegate accepts.  The artifact contains no wallet secret, but it is the only proof material a
// participant can use to construct a close if the coordinator later withholds `/backing`.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { isDeepStrictEqual } = require('util');

const PUBLIC_BACKING_SCHEMA_VERSION = 3;
const LIVE_BALANCE_SNAPSHOT_VERSION = 4;
const SIGNED_HEAD_EXIT_KIT_SCHEMA_VERSION = 1;
const CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN = 26;
const DEVELOPMENT_CHAIN_ID = 31_337;
const MAX_BACKING_BYTES = 64 * 1024 * 1024;
const MAX_BALANCE_COMPONENT_BYTES = 16 * 1024 * 1024;
const MAX_BACKING_PROOF_BYTES = 16 * 1024 * 1024;
const MAX_VERIFICATION_METADATA_BYTES = 64 * 1024;
const PUBLIC_BACKING_VERIFICATION_SCHEMA_VERSION = 2;
const VERIFICATION_METADATA_SCHEMA_VERSION = 2;
const VERIFICATION_SOURCE = 'public_close_prover --verify-only';
const STAGED_BY = Symbol('BackingVault staged artifact');

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function canonicalDigest(value, label = 'state digest') {
  const digest = String(value || '').toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(digest)) throw new Error(`${label} must be bytes32`);
  return digest;
}

function canonicalAddress(value, label) {
  const address = String(value || '').toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address) || /^0x0{40}$/.test(address)) {
    throw new Error(`${label} must be a nonzero address`);
  }
  return address;
}

function uint(value, maximum, label) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${label} must be a canonical unsigned integer`);
  }
  return value;
}

function bytes(value, maximum, label) {
  if (!Array.isArray(value) || value.length === 0 || value.length > maximum) {
    throw new Error(`${label} must be a nonempty byte array no larger than ${maximum} bytes`);
  }
  for (let index = 0; index < value.length; index += 1) {
    if (typeof value[index] !== 'number' || !Number.isInteger(value[index])
        || value[index] < 0 || value[index] > 255) {
      throw new Error(`${label}[${index}] is not a byte`);
    }
  }
  return value;
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (!isDeepStrictEqual(actual, wanted)) {
    throw new Error(`${label} has an unexpected schema`);
  }
}

function bytes32Limbs(value) {
  const hex = value.slice(2);
  return Array.from(
    { length: 8 },
    (_, index) => Number.parseInt(hex.slice(index * 8, index * 8 + 8), 16),
  );
}

// The live source persists the inner Plonky2 proof, not an MLE wrapper. The five semantic fields
// below expand to the exact 26-limb CloseAssetBacking public-input vector that a participant can
// later wrap without any channel signer. Keeping the schema exact also prevents an unverified
// `backingMleJson` look-alike from being mistaken for durable source material.
function validateSignedHeadExitKit(value, expectedChannelId, expectedSettledTxChain) {
  const expectedChannel = uint(expectedChannelId, 0xffffffff, 'expected exit-kit channelId');
  const expectedSettled = canonicalDigest(
    expectedSettledTxChain,
    'expected exit-kit settledTxChain',
  );
  const kit = plainObject(value, 'backing.signedHeadExitKit');
  exactKeys(
    kit,
    ['schemaVersion', 'backingPublicInputs', 'backingProof'],
    'backing.signedHeadExitKit',
  );
  if (uint(kit.schemaVersion, 0xffffffff, 'signed-head exit kit schemaVersion')
      !== SIGNED_HEAD_EXIT_KIT_SCHEMA_VERSION) {
    throw new Error(
      `signed-head exit kit schemaVersion must be ${SIGNED_HEAD_EXIT_KIT_SCHEMA_VERSION}`,
    );
  }
  const proof = bytes(
    kit.backingProof,
    MAX_BACKING_PROOF_BYTES,
    'signed-head exit backing proof',
  );
  const inputs = plainObject(
    kit.backingPublicInputs,
    'backing.signedHeadExitKit.backingPublicInputs',
  );
  exactKeys(
    inputs,
    [
      'channelId',
      'settledTxChain',
      'tokenFundsDigest',
      'finalizedExtendedStateCommitment',
      'anchorBlockNumber',
    ],
    'backing.signedHeadExitKit.backingPublicInputs',
  );
  const channelId = uint(inputs.channelId, 0xffffffff, 'exit backing channelId');
  if (channelId !== expectedChannel) {
    throw new Error('signed-head exit backing channelId differs from the accepted signed head');
  }
  const settledTxChain = canonicalDigest(
    inputs.settledTxChain,
    'exit backing settledTxChain',
  );
  if (settledTxChain !== expectedSettled) {
    throw new Error('signed-head exit backing settled chain differs from the accepted signed head');
  }
  const tokenFundsDigest = canonicalDigest(
    inputs.tokenFundsDigest,
    'exit backing tokenFundsDigest',
  );
  const finalizedExtendedStateCommitment = canonicalDigest(
    inputs.finalizedExtendedStateCommitment,
    'exit backing finalizedExtendedStateCommitment',
  );
  // JSON numbers above 2^53 cannot be authenticated losslessly by this process. Real L1 block
  // numbers are far below that ceiling; reject rather than round a future oversized U63 anchor.
  const anchorBlockNumber = uint(
    inputs.anchorBlockNumber,
    Number.MAX_SAFE_INTEGER,
    'exit backing anchorBlockNumber',
  );
  const publicInputs = [
    channelId,
    ...bytes32Limbs(settledTxChain),
    ...bytes32Limbs(tokenFundsDigest),
    ...bytes32Limbs(finalizedExtendedStateCommitment),
    anchorBlockNumber,
  ];
  if (publicInputs.length !== CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN) {
    throw new Error('signed-head exit backing public inputs do not contain exactly 26 limbs');
  }
  return {
    schemaVersion: SIGNED_HEAD_EXIT_KIT_SCHEMA_VERSION,
    proof,
    publicInputs,
    finalizedExtendedStateCommitment,
    anchorBlockNumber,
  };
}

function sha256Hex(value) {
  return `0x${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function normalizeVerifierDataPin(value, required) {
  if (value == null || value === '') {
    if (required) throw new Error('production delegate requires balanceVerifierDataSha256');
    return null;
  }
  const pin = String(value).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(pin)) {
    throw new Error('balanceVerifierDataSha256 must be a 32-byte 0x SHA-256 digest');
  }
  return pin;
}

function validateBackingEnvelope(backing, snapshot, authority, maximumBytes = MAX_BACKING_BYTES) {
  plainObject(backing, 'public backing');
  plainObject(snapshot, 'signed snapshot');
  const expected = plainObject(authority, 'backing authority');
  const expectedChannelId = uint(expected.channelId, 0xffffffff, 'expected channelId');
  const expectedChainId = uint(expected.chainId, Number.MAX_SAFE_INTEGER, 'expected chainId');
  if (expectedChannelId === 0 || expectedChainId === 0) {
    throw new Error('backing authority channelId and chainId must be nonzero');
  }
  const expectedRollup = canonicalAddress(expected.rollup, 'expected rollup');
  const expectedVdPin = normalizeVerifierDataPin(
    expected.balanceVerifierDataSha256,
    expectedChainId !== DEVELOPMENT_CHAIN_ID,
  );

  let serialized;
  try { serialized = JSON.stringify(backing); }
  catch (error) { throw new Error(`public backing is not JSON serializable: ${error.message}`); }
  const serializedBytes = Buffer.byteLength(serialized, 'utf8');
  if (serializedBytes > maximumBytes) {
    throw new Error(`public backing is ${serializedBytes} bytes, above the ${maximumBytes}-byte limit`);
  }
  if (backing.schemaVersion !== PUBLIC_BACKING_SCHEMA_VERSION
      || backing.source !== 'liveBalanceService') {
    throw new Error(`public backing must be liveBalanceService schema version ${PUBLIC_BACKING_SCHEMA_VERSION}`);
  }
  if (uint(backing.chainId, Number.MAX_SAFE_INTEGER, 'backing chainId') !== expectedChainId) {
    throw new Error('public backing chainId differs from configured chain');
  }
  if (canonicalAddress(backing.rollup, 'backing rollup') !== expectedRollup) {
    throw new Error('public backing rollup differs from configured rollup');
  }

  const state = plainObject(snapshot.state, 'snapshot.state');
  const record = plainObject(snapshot.record, 'snapshot.record');
  const signedHead = plainObject(backing.signedHead, 'backing.signedHead');
  const backingRecord = plainObject(backing.channelRecord, 'backing.channelRecord');
  const baseHead = plainObject(backing.baseHead, 'backing.baseHead');
  const balanceState = plainObject(state.balanceState, 'snapshot.state.balanceState');
  const signedBalanceState = plainObject(signedHead.balanceState, 'backing.signedHead.balanceState');
  const channelFund = plainObject(signedHead.channelFund, 'backing.signedHead.channelFund');

  const digest = canonicalDigest(state.digest, 'snapshot state digest');
  if (canonicalDigest(signedHead.digest, 'backing signed-head digest') !== digest
      || canonicalDigest(baseHead.signedHeadDigest, 'backing base signed-head digest') !== digest) {
    throw new Error('public backing is not bound to the exact accepted signed-head digest');
  }
  for (const [value, label] of [
    [record.channelId, 'snapshot record channelId'],
    [state.channelId, 'snapshot state channelId'],
    [balanceState.channelId, 'snapshot balance channelId'],
    [backingRecord.channelId, 'backing record channelId'],
    [signedHead.channelId, 'backing signed-head channelId'],
    [signedBalanceState.channelId, 'backing balance channelId'],
    [channelFund.channelId, 'backing fund channelId'],
    [baseHead.channelId, 'backing base channelId'],
  ]) {
    if (uint(value, 0xffffffff, label) !== expectedChannelId) {
      throw new Error(`${label} differs from configured channel`);
    }
  }
  if (baseHead.snapshotVersion !== LIVE_BALANCE_SNAPSHOT_VERSION) {
    throw new Error(`backing live snapshot version must be ${LIVE_BALANCE_SNAPSHOT_VERSION}`);
  }
  if (baseHead.awaitingChannelBinding !== false) {
    throw new Error('public backing is still awaiting N-of-N channel binding');
  }
  const settled = canonicalDigest(balanceState.settledTxChain, 'snapshot settledTxChain');
  if (canonicalDigest(signedBalanceState.settledTxChain, 'backing signed settledTxChain') !== settled
      || canonicalDigest(baseHead.settledTxChain, 'backing base settledTxChain') !== settled) {
    throw new Error('public backing settled chain differs from the accepted signed head');
  }
  // Digest equality is the cryptographic identity; complete object equality additionally rejects
  // a malformed transport that copies the digest while changing signatures, the record, fund
  // vector, or any state field before it reaches the immutable archive.
  if (!isDeepStrictEqual(signedHead, state) || !isDeepStrictEqual(backingRecord, record)) {
    throw new Error('public backing signed head/record differs from the WASM-authenticated snapshot');
  }

  const attestation = plainObject(backing.balanceAttestation, 'backing.balanceAttestation');
  const proof = bytes(attestation.balanceProof, MAX_BALANCE_COMPONENT_BYTES, 'balance proof');
  const verifierData = bytes(
    backing.balanceVerifierData,
    MAX_BALANCE_COMPONENT_BYTES,
    'balance verifier data',
  );
  if (uint(baseHead.proofSize, MAX_BALANCE_COMPONENT_BYTES, 'backing proofSize') !== proof.length) {
    throw new Error('backing proofSize differs from the supplied balance proof');
  }
  const verifierDataSha256 = sha256Hex(Buffer.from(verifierData));
  if (expectedVdPin && verifierDataSha256 !== expectedVdPin) {
    throw new Error('public backing balance verifier data differs from the configured SHA-256 pin');
  }
  const exitKit = validateSignedHeadExitKit(backing.signedHeadExitKit, expectedChannelId, settled);
  return {
    digest,
    settledTxChain: settled,
    serialized,
    serializedBytes,
    backingSha256: sha256Hex(Buffer.from(serialized, 'utf8')),
    verifierDataSha256,
    balanceProofBytes: proof.length,
    signedHeadExitKitSchemaVersion: exitKit.schemaVersion,
    backingProofBytes: exitKit.proof.length,
    backingPublicInputs: exitKit.publicInputs,
    backingFinalizedExtendedStateCommitment: exitKit.finalizedExtendedStateCommitment,
    backingAnchorBlockNumber: exitKit.anchorBlockNumber,
  };
}

function validateVerificationReceipt(receipt, checked, authority) {
  const value = plainObject(receipt, 'public backing verification receipt');
  const expectedKeys = [
    'backingAnchorBlockNumber',
    'backingFinalizedExtendedStateCommitment',
    'backingProofBytes',
    'backingPublicInputs',
    'balanceProofBytes',
    'balanceVerifierDataSha256',
    'chainId',
    'channelId',
    'rollup',
    'schemaVersion',
    'selfVerified',
    'signedHeadDigest',
    'signedHeadExitKitSchemaVersion',
  ];
  const actualKeys = Object.keys(value).sort();
  if (!isDeepStrictEqual(actualKeys, expectedKeys)) {
    throw new Error('public backing verification receipt has an unexpected schema');
  }
  if (uint(value.schemaVersion, 0xffffffff, 'verification receipt schemaVersion')
      !== PUBLIC_BACKING_VERIFICATION_SCHEMA_VERSION) {
    throw new Error(`verification receipt schemaVersion must be ${PUBLIC_BACKING_VERIFICATION_SCHEMA_VERSION}`);
  }
  if (value.selfVerified !== true) {
    throw new Error('public backing verification receipt is not self-verified');
  }
  const normalized = {
    schemaVersion: PUBLIC_BACKING_VERIFICATION_SCHEMA_VERSION,
    chainId: uint(value.chainId, Number.MAX_SAFE_INTEGER, 'verification receipt chainId'),
    rollup: canonicalAddress(value.rollup, 'verification receipt rollup'),
    channelId: uint(value.channelId, 0xffffffff, 'verification receipt channelId'),
    signedHeadDigest: canonicalDigest(value.signedHeadDigest, 'verification receipt signed-head digest'),
    balanceVerifierDataSha256: canonicalDigest(
      value.balanceVerifierDataSha256,
      'verification receipt balance verifier-data SHA-256',
    ),
    balanceProofBytes: uint(
      value.balanceProofBytes,
      MAX_BALANCE_COMPONENT_BYTES,
      'verification receipt balance proof bytes',
    ),
    signedHeadExitKitSchemaVersion: uint(
      value.signedHeadExitKitSchemaVersion,
      0xffffffff,
      'verification receipt signed-head exit kit schemaVersion',
    ),
    backingProofBytes: uint(
      value.backingProofBytes,
      MAX_BACKING_PROOF_BYTES,
      'verification receipt backing proof bytes',
    ),
    backingPublicInputs: (() => {
      if (!Array.isArray(value.backingPublicInputs)
          || value.backingPublicInputs.length !== CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN) {
        throw new Error('verification receipt backing public inputs must contain exactly 26 limbs');
      }
      return value.backingPublicInputs.map((input, index) => uint(
        input,
        index === CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN - 1
          ? Number.MAX_SAFE_INTEGER
          : 0xffffffff,
        `verification receipt backing publicInputs[${index}]`,
      ));
    })(),
    backingFinalizedExtendedStateCommitment: canonicalDigest(
      value.backingFinalizedExtendedStateCommitment,
      'verification receipt backing finalized extended-state commitment',
    ),
    backingAnchorBlockNumber: uint(
      value.backingAnchorBlockNumber,
      Number.MAX_SAFE_INTEGER,
      'verification receipt backing anchor block number',
    ),
    selfVerified: true,
  };
  const expected = {
    chainId: uint(authority.chainId, Number.MAX_SAFE_INTEGER, 'expected chainId'),
    rollup: canonicalAddress(authority.rollup, 'expected rollup'),
    channelId: uint(authority.channelId, 0xffffffff, 'expected channelId'),
  };
  if (normalized.chainId !== expected.chainId
      || normalized.rollup !== expected.rollup
      || normalized.channelId !== expected.channelId) {
    throw new Error('public backing verification receipt differs from archive authority');
  }
  if (normalized.signedHeadDigest !== checked.digest
      || normalized.balanceVerifierDataSha256 !== checked.verifierDataSha256
      || normalized.balanceProofBytes !== checked.balanceProofBytes
      || normalized.signedHeadExitKitSchemaVersion !== checked.signedHeadExitKitSchemaVersion
      || normalized.backingProofBytes !== checked.backingProofBytes
      || !isDeepStrictEqual(normalized.backingPublicInputs, checked.backingPublicInputs)
      || normalized.backingFinalizedExtendedStateCommitment
        !== checked.backingFinalizedExtendedStateCommitment
      || normalized.backingAnchorBlockNumber !== checked.backingAnchorBlockNumber) {
    throw new Error('public backing verification receipt differs from the canonical backing file');
  }
  return normalized;
}

function verificationMetadata(receipt, checked, authority) {
  const normalizedReceipt = validateVerificationReceipt(receipt, checked, authority);
  return {
    schemaVersion: VERIFICATION_METADATA_SCHEMA_VERSION,
    source: VERIFICATION_SOURCE,
    backingSha256: checked.backingSha256,
    backingBytes: checked.serializedBytes,
    chainId: normalizedReceipt.chainId,
    rollup: normalizedReceipt.rollup,
    channelId: normalizedReceipt.channelId,
    signedHeadDigest: normalizedReceipt.signedHeadDigest,
    settledTxChain: checked.settledTxChain,
    balanceVerifierDataSha256: normalizedReceipt.balanceVerifierDataSha256,
    balanceProofBytes: normalizedReceipt.balanceProofBytes,
    signedHeadExitKitSchemaVersion: normalizedReceipt.signedHeadExitKitSchemaVersion,
    backingProofBytes: normalizedReceipt.backingProofBytes,
    backingPublicInputs: normalizedReceipt.backingPublicInputs,
    backingFinalizedExtendedStateCommitment:
      normalizedReceipt.backingFinalizedExtendedStateCommitment,
    backingAnchorBlockNumber: normalizedReceipt.backingAnchorBlockNumber,
    verification: normalizedReceipt,
  };
}

function validateVerificationMetadata(metadata, checked, authority) {
  const value = plainObject(metadata, 'public backing verification metadata');
  const expected = verificationMetadata(value.verification, checked, authority);
  if (!isDeepStrictEqual(value, expected)) {
    throw new Error('public backing verification metadata differs from its canonical backing/receipt');
  }
  return expected;
}

function fsyncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

class BackingVault {
  constructor(workDir, channelId, authority = {}, options = {}) {
    const id = uint(Number(channelId), 0xffffffff, 'channel id');
    if (id === 0) throw new Error('channel id must be nonzero');
    this.authority = {
      channelId: id,
      chainId: authority.chainId,
      rollup: authority.rollup,
      balanceVerifierDataSha256: authority.balanceVerifierDataSha256,
    };
    this.maximumBytes = options.maximumBytes == null ? MAX_BACKING_BYTES : Number(options.maximumBytes);
    if (!Number.isSafeInteger(this.maximumBytes) || this.maximumBytes < 1
        || this.maximumBytes > MAX_BACKING_BYTES) {
      throw new Error(`backing archive maximumBytes must be in 1..${MAX_BACKING_BYTES}`);
    }
    // Validate immutable authority at construction, not on the first network response.
    uint(this.authority.chainId, Number.MAX_SAFE_INTEGER, 'expected chainId');
    canonicalAddress(this.authority.rollup, 'expected rollup');
    normalizeVerifierDataPin(
      this.authority.balanceVerifierDataSha256,
      this.authority.chainId !== DEVELOPMENT_CHAIN_ID,
    );
    this.directory = path.join(path.resolve(workDir || '.'), 'delegate-backings', String(id));
  }

  fileFor(digest) {
    return path.join(this.directory, `${canonicalDigest(digest).slice(2)}.json`);
  }

  metadataFor(digest) {
    return path.join(this.directory, `${canonicalDigest(digest).slice(2)}.verified.json`);
  }

  validate(backing, snapshot) {
    return validateBackingEnvelope(backing, snapshot, this.authority, this.maximumBytes);
  }

  prepare(backing, snapshot) {
    const checked = this.validate(backing, snapshot);
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    const destination = this.fileFor(checked.digest);
    const metadataDestination = this.metadataFor(checked.digest);
    let existing = false;
    if (fs.existsSync(destination)) {
      const archived = this.load(checked.digest, snapshot);
      if (!isDeepStrictEqual(archived, backing)) {
        throw new Error(`refusing to overwrite different backing for signed head ${checked.digest}`);
      }
      existing = true;
    }

    // A verification marker is the archive commit record.  It is reusable only because the
    // backing filename is content-bound by both the signed-head digest and backing SHA-256.
    const verifiedMetadata = this.loadVerification(checked.digest, checked);
    if (existing) {
      return {
        [STAGED_BY]: this,
        existing,
        destination,
        metadataDestination,
        backing,
        snapshot,
        checked,
        verificationMetadata: verifiedMetadata,
      };
    }

    const tmp = `${destination}.tmp-${process.pid}-${Date.now()}-${BackingVault.sequence++}`;
    let fd;
    try {
      fd = fs.openSync(tmp, 'wx', 0o600);
      fs.writeFileSync(fd, checked.serialized);
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      return {
        [STAGED_BY]: this,
        existing,
        destination,
        metadataDestination,
        tmp,
        backing,
        snapshot,
        checked,
        verificationMetadata: verifiedMetadata,
      };
    } catch (error) {
      if (fd !== undefined) fs.closeSync(fd);
      try { fs.rmSync(tmp, { force: true }); } catch (_) { /* preserve the primary failure */ }
      throw error;
    }
  }

  requiresVerification(staged) {
    if (!staged || staged[STAGED_BY] !== this) throw new Error('backing archive stage belongs to another vault');
    return !staged.verificationMetadata;
  }

  verificationInput(staged) {
    if (!staged || staged[STAGED_BY] !== this) throw new Error('backing archive stage belongs to another vault');
    const input = staged.existing ? staged.destination : staged.tmp;
    const stat = fs.lstatSync(input);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error('staged backing is not a regular non-symlink file');
    }
    if (stat.size !== staged.checked.serializedBytes) {
      throw new Error('staged backing size changed before cryptographic verification');
    }
    const serialized = fs.readFileSync(input, 'utf8');
    if (serialized !== staged.checked.serialized
        || sha256Hex(Buffer.from(serialized, 'utf8')) !== staged.checked.backingSha256) {
      throw new Error('staged backing changed before cryptographic verification');
    }
    return input;
  }

  acceptVerification(staged, receipt) {
    if (!staged || staged[STAGED_BY] !== this) throw new Error('backing archive stage belongs to another vault');
    // Hash the exact on-disk bytes both before invoking the native verifier and when accepting its
    // receipt.  This makes a path/TOCTOU substitution fail before the archive marker is created.
    this.verificationInput(staged);
    staged.verificationMetadata = verificationMetadata(receipt, staged.checked, this.authority);
    return staged.verificationMetadata;
  }

  commit(staged) {
    if (!staged || staged[STAGED_BY] !== this) throw new Error('backing archive stage belongs to another vault');
    if (!staged.verificationMetadata) {
      throw new Error('refusing to publish backing without native cryptographic verification');
    }
    this.verificationInput(staged);
    const metadata = validateVerificationMetadata(
      staged.verificationMetadata,
      staged.checked,
      this.authority,
    );
    const metadataSerialized = JSON.stringify(metadata);
    if (Buffer.byteLength(metadataSerialized, 'utf8') > MAX_VERIFICATION_METADATA_BYTES) {
      throw new Error('public backing verification metadata exceeds its safety limit');
    }
    const metadataTmp = `${staged.metadataDestination}.tmp-${process.pid}-${Date.now()}-${BackingVault.sequence++}`;
    let metadataFd;
    let linkedMetadata = false;
    let linkedBacking = false;
    try {
      metadataFd = fs.openSync(metadataTmp, 'wx', 0o600);
      fs.writeFileSync(metadataFd, metadataSerialized);
      fs.fsyncSync(metadataFd);
      fs.closeSync(metadataFd);
      metadataFd = undefined;

      // Publish the verification marker first and the canonical backing path last.  The latter is
      // the archive commit point; acceptedHead is still persisted only after directory fsync.
      try {
        fs.linkSync(metadataTmp, staged.metadataDestination);
        linkedMetadata = true;
      } catch (error) {
        if (!error || error.code !== 'EEXIST') throw error;
        const existingMetadata = this.loadVerification(staged.checked.digest, staged.checked);
        if (!isDeepStrictEqual(existingMetadata, metadata)) {
          throw new Error(`concurrent verification metadata differs for signed head ${staged.checked.digest}`);
        }
      }

      if (!staged.existing) {
        try {
          fs.linkSync(staged.tmp, staged.destination);
          linkedBacking = true;
        } catch (error) {
          if (!error || error.code !== 'EEXIST') throw error;
          const existingBacking = this.load(staged.checked.digest, staged.snapshot);
          if (!isDeepStrictEqual(existingBacking, staged.backing)) {
            throw new Error(`concurrent backing differs for signed head ${staged.checked.digest}`);
          }
        }
      }
      fsyncDirectory(this.directory);
      // Re-read both visible files after publication; a marker without its exact backing never
      // counts as an archived head.
      this.loadVerified(staged.checked.digest, staged.snapshot);
    } catch (error) {
      // Best-effort rollback for an error in this process.  Crash recovery also treats an orphan
      // marker or backing as uncommitted until both exact files validate.
      if (linkedBacking) {
        try { fs.unlinkSync(staged.destination); } catch (_) { /* preserve the primary failure */ }
      }
      if (linkedMetadata) {
        try { fs.unlinkSync(staged.metadataDestination); } catch (_) { /* preserve the primary failure */ }
      }
      throw error;
    } finally {
      if (metadataFd !== undefined) fs.closeSync(metadataFd);
      try { fs.rmSync(metadataTmp, { force: true }); } catch (_) { /* preserve the primary failure */ }
      if (!staged.existing) {
        try { fs.rmSync(staged.tmp, { force: true }); } catch (_) { /* preserve the primary failure */ }
      }
    }
    return staged.destination;
  }

  abort(staged) {
    if (!staged || staged[STAGED_BY] !== this || staged.existing) return;
    fs.rmSync(staged.tmp, { force: true });
  }

  save(backing, snapshot, receipt) {
    const staged = this.prepare(backing, snapshot);
    if (this.requiresVerification(staged)) this.acceptVerification(staged, receipt);
    return this.commit(staged);
  }

  load(digest, snapshot) {
    const file = this.fileFor(digest);
    try {
      const stat = fs.lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('archived backing is not a regular file');
      if (stat.size > this.maximumBytes) throw new Error('archived backing exceeds the configured size limit');
      const backing = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (snapshot) {
        const checked = this.validate(backing, snapshot);
        if (checked.digest !== canonicalDigest(digest)) throw new Error('archived backing digest mismatch');
      } else if (canonicalDigest(backing && backing.signedHead && backing.signedHead.digest)
          !== canonicalDigest(digest)) {
        throw new Error('archived backing digest mismatch');
      }
      return backing;
    } catch (error) {
      if (error && error.code === 'ENOENT') return null;
      throw error;
    }
  }

  loadVerification(digest, checked) {
    const file = this.metadataFor(digest);
    try {
      const stat = fs.lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        throw new Error('archived backing verification metadata is not a regular file');
      }
      if (stat.size > MAX_VERIFICATION_METADATA_BYTES) {
        throw new Error('archived backing verification metadata exceeds its safety limit');
      }
      const metadata = JSON.parse(fs.readFileSync(file, 'utf8'));
      return validateVerificationMetadata(metadata, checked, this.authority);
    } catch (error) {
      if (error && error.code === 'ENOENT') return null;
      throw error;
    }
  }

  loadVerified(digest, snapshot) {
    const backing = this.load(digest, snapshot);
    if (!backing) return null;
    if (!snapshot) throw new Error('signed snapshot is required to load a verified backing archive');
    const checked = this.validate(backing, snapshot);
    const verification = this.loadVerification(digest, checked);
    if (!verification) throw new Error('archived backing has no native verification metadata');
    return { backing, verification };
  }
}
BackingVault.sequence = 0;

module.exports = {
  BackingVault,
  DEVELOPMENT_CHAIN_ID,
  LIVE_BALANCE_SNAPSHOT_VERSION,
  MAX_BACKING_BYTES,
  MAX_BACKING_PROOF_BYTES,
  MAX_BALANCE_COMPONENT_BYTES,
  MAX_VERIFICATION_METADATA_BYTES,
  PUBLIC_BACKING_SCHEMA_VERSION,
  PUBLIC_BACKING_VERIFICATION_SCHEMA_VERSION,
  SIGNED_HEAD_EXIT_KIT_SCHEMA_VERSION,
  validateBackingEnvelope,
  validateSignedHeadExitKit,
  validateVerificationMetadata,
  validateVerificationReceipt,
};
