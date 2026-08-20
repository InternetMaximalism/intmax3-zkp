'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { extractSlimAnchor } = require(path.join(__dirname, '..', '..', 'hosting', 'wallet', 'slim-wire'));

test('IMSW v1 exposes the raw anchor in its fixed header', () => {
  const anchor = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
  const header = Buffer.concat([Buffer.from('IMSW'), Buffer.from([1, 0, 0, 0]), anchor]);
  assert.equal(extractSlimAnchor(header), '0x' + anchor.toString('hex'));
});

test('IMSW never falls back to JSON after a binary-header error', () => {
  const anchor = Buffer.alloc(32, 7);
  const badVersion = Buffer.concat([Buffer.from('IMSW'), Buffer.from([2, 0, 0, 0]), anchor]);
  const badReserved = Buffer.concat([Buffer.from('IMSW'), Buffer.from([1, 0, 1, 0]), anchor]);
  assert.throws(() => extractSlimAnchor(Buffer.from('IMSW')), /truncated/);
  assert.throws(() => extractSlimAnchor(badVersion), /unsupported or non-canonical/);
  assert.throws(() => extractSlimAnchor(badReserved), /unsupported or non-canonical/);
});

test('rolling upgrade keeps legacy slim JSON anchors readable', () => {
  const digest = '0x' + 'ab'.repeat(32);
  assert.equal(extractSlimAnchor(Buffer.from(JSON.stringify({ anchorDigest: digest, senderIndex: 0 }))), digest);
  assert.throws(() => extractSlimAnchor(Buffer.from('{"senderIndex":0}')), /anchorDigest not found/);
});
