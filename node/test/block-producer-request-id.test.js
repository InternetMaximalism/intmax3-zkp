'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { stableRequestId } = require('../../api/lib/block-producer');

test('producer request ids ignore object key insertion order but preserve array order', () => {
  const a = { z: 1, nested: { b: 2, a: 3 }, list: [{ y: 4, x: 5 }, 6] };
  const b = { list: [{ x: 5, y: 4 }, 6], nested: { a: 3, b: 2 }, z: 1 };
  assert.equal(stableRequestId('burn', a), stableRequestId('burn', b));
  assert.notEqual(stableRequestId('burn', a), stableRequestId('burn', { ...b, list: [6, b.list[0]] }));
});
