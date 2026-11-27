'use strict';

// The Node delegate and the browser wallet each carry a hand-written COPY of a few MLE/WHIR
// envelope constants (they cannot import Solidity or Rust). When the pinned plonky2 profile
// changed (WHIR PoW 22 -> 28, 2026-11-26) those copies were left at the old values and every
// PoW-28 proof was rejected as "differs from the release-reviewed v2 envelope". This test reads
// the single source of truth — the protocol JSON and the generated Solidity profile table in the
// pinned submodule — and fails with the exact constant to update.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const MLE = path.join(ROOT, 'contracts', 'lib', 'polygon-plonky2', 'mle');
const PROTOCOL = path.join(MLE, 'protocol', 'mle_whir_v2.json');
const PROFILES = path.join(MLE, 'contracts', 'src', 'generated', 'WhirProfilesV2.sol');

const COPIES = [
  path.join(ROOT, 'node', 'delegate', 'claim-settlement.js'),
  path.join(ROOT, 'hosting', 'wallet', 'wallet-live.html'),
];

function readPinned(file) {
  assert.ok(
    fs.existsSync(file),
    `${path.relative(ROOT, file)} is missing: the polygon-plonky2 submodule is not checked out. `
      + 'Run: git submodule update --init --recursive',
  );
  return fs.readFileSync(file, 'utf8');
}

function constant(source, name, file) {
  const match = source.match(new RegExp(`^const ${name} = '?(0x[0-9a-f]+|\\d+)n?'?;`, 'm'));
  assert.ok(match, `${path.relative(ROOT, file)} no longer declares ${name}`);
  return match[1];
}

test('hand-written WHIR envelope copies equal the pinned plonky2 protocol', () => {
  const protocol = JSON.parse(readPinned(PROTOCOL));
  const expected = {
    MAX_WHIR_NARG_BYTES_V2: protocol.maxWhirNargBytes,
    MAX_WHIR_HINT_BYTES_V2: protocol.maxWhirHintBytes,
    MAX_COMPACT_PROOF_BYTES_V2: protocol.maxCompactProofBytes,
  };
  for (const [name, value] of Object.entries(expected)) {
    assert.equal(typeof value, 'number', `mle_whir_v2.json lost the field behind ${name}`);
  }
  for (const file of COPIES) {
    const source = fs.readFileSync(file, 'utf8');
    for (const [name, value] of Object.entries(expected)) {
      assert.equal(
        Number(constant(source, name, file)),
        value,
        `${path.relative(ROOT, file)}: ${name} must equal the pinned protocol value ${value} `
          + '(contracts/lib/polygon-plonky2/mle/protocol/mle_whir_v2.json); update the copy.',
      );
    }
  }
});

test('the delegate pins the packed-21 WHIR profile that the generated Solidity table ships', () => {
  const profiles = readPinned(PROFILES);
  const file = COPIES[0];
  const source = fs.readFileSync(file, 'utf8');
  const digest = constant(source, 'CANONICAL_WHIR_21_PARAMETERS_DIGEST_V2', file);
  const protocolId = constant(source, 'CANONICAL_WHIR_21_PROTOCOL_ID_V2', file);
  // WhirProfilesV2.sol stores each profile as parametersDigest || protocolId in one hex table.
  assert.ok(
    profiles.includes(digest.slice(2) + protocolId.slice(2)),
    'node/delegate/claim-settlement.js: CANONICAL_WHIR_21_PARAMETERS_DIGEST_V2 / _PROTOCOL_ID_V2 are '
      + 'not a profile of the pinned WhirProfilesV2.sol; copy them from a regenerated withdrawal '
      + 'fixture (pinnedVerifier.whirParametersDigest / whirProtocolId).',
  );
});
