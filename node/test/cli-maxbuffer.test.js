'use strict';

// `channel_member` prints large JSON artifacts (N-of-N signed import states, exit-kit envelopes) to
// STDOUT, and their size scales with the channel's slot × token count — each co-signer's Falcon
// signature alone is ~76 KB. Node's execFileSync defaults to a 1 MB stdout cap, so once a channel
// grew past a couple of joined delegates a deposit/refresh/send died `spawnSync ... ENOBUFS`
// mid-flight, surfacing to the wallet as an opaque failure. cli()/sh() must therefore pass a
// generous maxBuffer. This test pins that: without it, the multi-slot channel regressions return.

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

// Intercept child_process.execFileSync BEFORE api/lib/cli.js is required, so we capture the exact
// options it passes. cli.js destructures execFileSync at require time.
const realLoad = Module._load;
const calls = [];
Module._load = function patched(request, parent, isMain) {
  const mod = realLoad.call(this, request, parent, isMain);
  if (request === 'child_process') {
    return {
      ...mod,
      execFileSync(bin, args, options) {
        calls.push({ bin, args, options });
        return '{}'; // enough for callers that JSON.parse the result
      },
    };
  }
  return mod;
};

let cli;
try {
  delete require.cache[require.resolve('../../api/lib/cli')];
  cli = require('../../api/lib/cli');
} finally {
  Module._load = realLoad;
}

const MIN = 64 * 1024 * 1024; // comfortably above any realistic single-channel artifact

test('cli() passes a large maxBuffer so multi-slot channel output is never truncated', () => {
  calls.length = 0;
  cli.cli(7, ['status']);
  assert.equal(calls.length, 1);
  assert.ok(
    Number(calls[0].options.maxBuffer) >= MIN,
    `cli() maxBuffer ${calls[0].options.maxBuffer} must be >= ${MIN} (ENOBUFS guard)`,
  );
});

test('sh() also raises maxBuffer for large tool output', () => {
  calls.length = 0;
  cli.sh('cast', ['--version'], { stdio: 'pipe' });
  assert.equal(calls.length, 1);
  assert.ok(
    Number(calls[0].options.maxBuffer) >= MIN,
    `sh() maxBuffer ${calls[0].options.maxBuffer} must be >= ${MIN}`,
  );
});

test('an explicit sh() maxBuffer override is still honored', () => {
  calls.length = 0;
  cli.sh('cast', ['--version'], { stdio: 'pipe', maxBuffer: 123 });
  assert.equal(calls[0].options.maxBuffer, 123);
});
