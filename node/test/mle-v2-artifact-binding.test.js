'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { keccak256 } = require('ethers');

const { normalizeMleProof } = require('../delegate/claim-settlement');

const FIXTURE = path.join(
  __dirname,
  '../../contracts/lib/polygon-plonky2/mle/contracts/test/fixtures/v2_max_resource.json',
);

function fixture() {
  return JSON.parse(fs.readFileSync(FIXTURE));
}

function mutateHexByte(hex, byteOffset) {
  const bytes = Buffer.from(hex.slice(2), 'hex');
  bytes[byteOffset] ^= 1;
  return `0x${bytes.toString('hex')}`;
}

test('strict Node consumer accepts the canonical full/compact/ABI MLE-WHIR wire-v3 cross-view fixture', () => {
  const normalized = normalizeMleProof(fixture());
  assert.equal(normalized.publicInputs.length, 1);
  assert.equal(normalized.proof.publicInputs[0], normalized.publicInputs[0]);
  assert.equal(normalized.compactProof.slice(2, 18), '4d4c455748495233');
  assert.equal(
    normalized.compactLayoutHash,
    '0xe3d01532fb72b31d049076afef24b96863866a91a0bb3f66ae90ee39a62e4b97',
  );
});

test('human-readable public inputs cannot diverge from the compact proof sent on chain', () => {
  const value = fixture();
  value.proof.publicInputs[0] = '0x0000000000000001';
  assert.throws(
    () => normalizeMleProof(value),
    /full proof object disagrees with canonical compact bytes/,
  );
});

test('compact public-input mutations remain rejected even with attacker-updated length/hash views', () => {
  const value = fixture();
  // 8-byte magic + u64 version + u32 width + four 8-byte circuit-digest limbs.
  value.compactProof.bytes = mutateHexByte(value.compactProof.bytes, 52);
  value.compactProof.keccak256 = keccak256(value.compactProof.bytes);
  assert.throws(
    () => normalizeMleProof(value),
    /full proof object disagrees with canonical compact bytes/,
  );
});

test('unknown, partial, legacy, and mixed-version fixture schemas fail closed', () => {
  const unknown = fixture();
  unknown.compatibilityProof = unknown.proof;
  assert.throws(() => normalizeMleProof(unknown), /keys do not match/);

  const nestedUnknown = fixture();
  nestedUnknown.proof.publicInputsHash = nestedUnknown.proof.circuitDigest;
  assert.throws(() => normalizeMleProof(nestedUnknown), /keys do not match/);

  const configUnknown = fixture();
  configUnknown.verificationConfig.whir.legacyEvaluationPoint = [];
  assert.throws(() => normalizeMleProof(configUnknown), /keys do not match/);

  const partial = fixture();
  delete partial.compactProof;
  assert.throws(() => normalizeMleProof(partial), /keys do not match/);

  const mixed = fixture();
  mixed.proof.protocolVersion = 1;
  assert.throws(() => normalizeMleProof(mixed), /protocol\/width/);

  const legacy = {
    circuitDigest: fixture().proof.circuitDigest,
    publicInputs: fixture().proof.publicInputs,
    whirTranscript: fixture().proof.whirTranscript,
  };
  assert.throws(() => normalizeMleProof(legacy), /canonical plonky2-mle-v3-solidity full fixture/);
});

test('layout identifiers and all duplicate pinned views are authenticated', () => {
  const layout = fixture();
  layout.proofLayoutHash = `0x${'00'.repeat(32)}`;
  assert.throws(() => normalizeMleProof(layout), /generated v2 layout/);

  const pinnedRoot = fixture();
  pinnedRoot.pinnedVerifier.preprocessedCommitmentRoot = `0x${'11'.repeat(32)}`;
  assert.throws(() => normalizeMleProof(pinnedRoot), /proof\/VK\/pinned-verifier views disagree/);

  const protocol = fixture();
  protocol.pinnedVerifier.whirProtocolId = `0x${'22'.repeat(64)}`;
  protocol.verificationKey.whirProtocolId = protocol.pinnedVerifier.whirProtocolId;
  assert.throws(() => normalizeMleProof(protocol), /canonical packed-21 withdrawal profile/);

  const openingBound = fixture();
  openingBound.sizeUpperBound.whir.openings[0].maxBytes += 1;
  assert.throws(() => normalizeMleProof(openingBound), /size upper-bound views disagree/);

  const abiBound = fixture();
  abiBound.sizeUpperBound.maxSolidityAbiBytes += 32;
  assert.throws(() => normalizeMleProof(abiBound), /size upper-bound views disagree/);

  const vkWireMap = fixture();
  vkWireMap.verificationKey.publicInputWireMap = mutateHexByte(
    vkWireMap.verificationKey.publicInputWireMap,
    0,
  );
  assert.throws(() => normalizeMleProof(vkWireMap), /VK and complete verification config disagree/);
});

test('Solidity proof and verification-config ABI byte records are exact re-encodings', () => {
  const proofAbi = fixture();
  proofAbi.solidityAbiProof.bytes = mutateHexByte(proofAbi.solidityAbiProof.bytes, 64);
  proofAbi.solidityAbiProof.keccak256 = keccak256(proofAbi.solidityAbiProof.bytes);
  assert.throws(() => normalizeMleProof(proofAbi), /canonical full-proof encoding/);

  const configAbi = fixture();
  configAbi.solidityAbiVerificationConfig.bytes = mutateHexByte(
    configAbi.solidityAbiVerificationConfig.bytes,
    64,
  );
  configAbi.solidityAbiVerificationConfig.keccak256 = keccak256(
    configAbi.solidityAbiVerificationConfig.bytes,
  );
  configAbi.pinnedVerifier.verificationConfigDigest =
    configAbi.solidityAbiVerificationConfig.keccak256;
  assert.throws(() => normalizeMleProof(configAbi), /verification-config bytes are not canonical/);
});

test('non-canonical and adversarial compact hex encodings fail before calldata construction', () => {
  const uppercase = fixture();
  uppercase.compactProof.bytes = `0x${uppercase.compactProof.bytes.slice(2).toUpperCase()}`;
  assert.throws(() => normalizeMleProof(uppercase), /canonical lowercase 0x hex/);

  const odd = fixture();
  odd.compactProof.bytes = odd.compactProof.bytes.slice(0, -1);
  assert.throws(() => normalizeMleProof(odd), /must be hex bytes/);

  const trailing = fixture();
  trailing.compactProof.bytes += '00';
  trailing.compactProof.byteLength += 1;
  trailing.compactProof.keccak256 = keccak256(trailing.compactProof.bytes);
  trailing.stats.compactBytes += 1;
  assert.throws(() => normalizeMleProof(trailing), /trailing bytes/);

  const oversized = fixture();
  oversized.compactProof.bytes = `0x${'00'.repeat(253922)}`;
  oversized.compactProof.byteLength = 253922;
  oversized.compactProof.keccak256 = keccak256(oversized.compactProof.bytes);
  oversized.stats.compactBytes = 253922;
  assert.throws(() => normalizeMleProof(oversized), /exceeds the release-reviewed (?:byte )?cap/);
});

test('fixture integers and Goldilocks limbs have one canonical spelling and type', () => {
  const numericSchema = fixture();
  numericSchema.schemaVersion = '3';
  assert.throws(() => normalizeMleProof(numericSchema), /canonical JSON unsigned integer/);

  const decimalField = fixture();
  decimalField.proof.publicInputs[0] = BigInt(decimalField.proof.publicInputs[0]).toString();
  assert.throws(() => normalizeMleProof(decimalField), /canonical lowercase 8-byte Goldilocks hex limb/);

  const nonCanonicalField = fixture();
  nonCanonicalField.proof.publicInputs[0] = '0xffffffff00000001';
  assert.throws(() => normalizeMleProof(nonCanonicalField), /outside the Goldilocks field/);

  const oversizedDecimal = fixture();
  oversizedDecimal.verificationConfig.whir.finalPowThreshold = '9'.repeat(100000);
  assert.throws(() => normalizeMleProof(oversizedDecimal), /out of range/);
});
