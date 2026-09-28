'use strict';

// Needs express (resolved like the relays do, e.g. NODE_PATH=<repo>/api/node_modules).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const express = require('express');
const { pkgAssets, createPkgVersion, IMMUTABLE } = require('../../hosting/wallet/pkg-assets');

const HELPER = 'snippets/wasm-bindgen-rayon-0/src/workerHelpers.no-bundler.js';

function makePkg() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-pkg-assets-'));
  const pkg = path.join(root, 'pkg');
  fs.mkdirSync(path.join(pkg, path.dirname(HELPER)), { recursive: true });
  fs.writeFileSync(path.join(pkg, 'intmax3_zkp.js'), 'export default 1;');
  fs.writeFileSync(path.join(pkg, 'intmax3_zkp_bg.wasm'), Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
  fs.writeFileSync(path.join(pkg, HELPER), 'export const helper = 1;');
  fs.writeFileSync(path.join(root, 'index.html'), '<html></html>');
  return { root, pkg };
}

// The same order as wallet-relay-ec2.js: the global header layer marks every /pkg path `no-cache`,
// then the versioned mount, then plain static serving of the public directory.
async function start(root, pkg) {
  const app = express();
  app.use((req, res, next) => {
    if (req.path.startsWith('/pkg/')) res.setHeader('Cache-Control', 'no-cache');
    else res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use('/pkg', pkgAssets(pkg, express.static));
  app.use(express.static(root));
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, close: () => new Promise((resolve) => server.close(resolve)) };
}

const get = (url) => fetch(url, { redirect: 'manual' });

test('the entry module is a no-store alias that redirects to its content-addressed copy', async (t) => {
  const { root, pkg } = makePkg();
  const s = await start(root, pkg); t.after(s.close);
  const alias = await get(s.base + '/pkg/intmax3_zkp.js');
  assert.equal(alias.status, 302);
  assert.equal(alias.headers.get('cache-control'), 'no-store');
  assert.match(alias.headers.get('location'), /^\/pkg\/[0-9a-f]{16}\/intmax3_zkp\.js$/);
  const entry = await get(s.base + alias.headers.get('location'));
  assert.equal(entry.status, 200);
  assert.equal(entry.headers.get('cache-control'), IMMUTABLE);
  assert.equal(await entry.text(), 'export default 1;');
});

test('everything a prover thread derives from the entry URL is immutable under the same id', async (t) => {
  const { root, pkg } = makePkg();
  const s = await start(root, pkg); t.after(s.close);
  const dir = path.posix.dirname((await get(s.base + '/pkg/intmax3_zkp.js')).headers.get('location'));
  const helper = await get(`${s.base}${dir}/${HELPER}`);
  assert.equal(helper.status, 200);
  assert.equal(helper.headers.get('cache-control'), IMMUTABLE);
  const wasm = await get(`${s.base}${dir}/intmax3_zkp_bg.wasm`);
  assert.equal(wasm.status, 200);
  assert.equal(wasm.headers.get('cache-control'), IMMUTABLE);
  assert.equal(wasm.headers.get('content-type'), 'application/wasm');
});

test('a redeploy moves the alias to a new id and the old id is refused, never re-served', async (t) => {
  const { root, pkg } = makePkg();
  const s = await start(root, pkg); t.after(s.close);
  const before = (await get(s.base + '/pkg/intmax3_zkp.js')).headers.get('location');
  fs.writeFileSync(path.join(pkg, 'intmax3_zkp_bg.wasm'), Buffer.from([0, 97, 115, 109, 1, 0, 0, 0, 1]));
  const after = (await get(s.base + '/pkg/intmax3_zkp.js')).headers.get('location');
  assert.notEqual(after, before);
  const stale = await get(s.base + before);
  assert.equal(stale.status, 404);
  assert.equal(stale.headers.get('cache-control'), 'no-store');
  assert.equal((await get(s.base + after)).status, 200);
});

test('a same-size in-place rewrite is still detected', async () => {
  const { pkg } = makePkg();
  const id = createPkgVersion(pkg);
  const first = id();
  const file = path.join(pkg, HELPER);
  fs.writeFileSync(file, 'export const helper = 2;');
  const later = new Date(fs.statSync(file).mtimeMs + 5000);
  fs.utimesSync(file, later, later);
  assert.notEqual(id(), first);
});

test('the id is a pure function of the package contents', () => {
  const a = makePkg();
  const b = makePkg();
  assert.equal(createPkgVersion(a.pkg)(), createPkgVersion(b.pkg)());
  assert.match(createPkgVersion(a.pkg)(), /^[0-9a-f]{16}$/);
});

test('a missing file under the current id is a 404 that is not cached as immutable', async (t) => {
  const { root, pkg } = makePkg();
  const s = await start(root, pkg); t.after(s.close);
  const dir = path.posix.dirname((await get(s.base + '/pkg/intmax3_zkp.js')).headers.get('location'));
  const missing = await get(`${s.base}${dir}/nope.js`);
  assert.equal(missing.status, 404);
  assert.notEqual(missing.headers.get('cache-control'), IMMUTABLE);
});

test('the versioned path cannot reach outside the package directory', async (t) => {
  const { root, pkg } = makePkg();
  const s = await start(root, pkg); t.after(s.close);
  const dir = path.posix.dirname((await get(s.base + '/pkg/intmax3_zkp.js')).headers.get('location'));
  const escaped = await get(`${s.base}${dir}/..%2F..%2Findex.html`);
  assert.notEqual(escaped.status, 200);
  assert.notEqual(escaped.headers.get('cache-control'), IMMUTABLE);
});

test('other unversioned /pkg paths fall through to the existing static serving', async (t) => {
  const { root, pkg } = makePkg();
  const s = await start(root, pkg); t.after(s.close);
  const wasm = await get(s.base + '/pkg/intmax3_zkp_bg.wasm');
  assert.equal(wasm.status, 200);
  assert.equal(wasm.headers.get('cache-control'), 'no-cache');
});

test('without a deployed package the alias fails clearly instead of redirecting', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-pkg-assets-empty-'));
  const s = await start(root, path.join(root, 'pkg')); t.after(s.close);
  const alias = await get(s.base + '/pkg/intmax3_zkp.js');
  assert.equal(alias.status, 503);
  assert.equal(alias.headers.get('cache-control'), 'no-store');
});
