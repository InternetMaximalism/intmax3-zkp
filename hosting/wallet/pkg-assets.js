'use strict';
// Content-addressed delivery of the wasm-bindgen package (`pkg/`).
//
// The wallet worker imports the entry module once, but wasm-bindgen-rayon then starts one Web
// Worker per prover thread, and every one of them fetches the rayon helper script, imports the
// entry module and (through it) the helper again — three requests per thread, all derived from the
// entry module's `import.meta.url`. Served with `Cache-Control: no-cache`, each of those is a
// conditional request that must reach the relay, so thread-pool start-up costs a network round trip
// per request (measured: 18 threads → 54 revalidations → ~21 s; the same 54 from cache → 25 ms), and
// the page cannot be used until the pool is up.
//
// `no-cache` was there for a real reason: a long `max-age` on fixed URLs let a browser run a stale
// wasm against a newer relay. Content addressing removes both problems at once. Every file is served
// under `/pkg/<id>/…`, where <id> is a hash of the whole package, with an immutable cache policy: a
// given URL can only ever name one set of bytes, so caching it forever is safe, and a redeploy
// changes the id, so nothing stale can be picked up. The entry module keeps its unversioned URL as a
// `no-store` alias that redirects to the current id; a module's `import.meta.url` is its final
// (post-redirect) URL, so the wasm, the helper and every thread's imports resolve inside the
// versioned tree without any change to the worker or the generated glue.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ENTRY = 'intmax3_zkp.js';
const IMMUTABLE = 'public, max-age=31536000, immutable';
const VERSIONED = /^\/([0-9a-f]{16})(\/.+)$/;

function listFiles(dir, prefix = '') {
  const out = [];
  for (const entry of fs.readdirSync(path.join(dir, prefix), { withFileTypes: true })) {
    const rel = prefix ? prefix + '/' + entry.name : entry.name;
    if (entry.isDirectory()) out.push(...listFiles(dir, rel));
    else if (entry.isFile()) out.push(rel);
  }
  return out.sort();
}

// The id is a hash over every file's relative path and bytes, so it changes whenever anything the
// browser could load changes. It is recomputed whenever a file's size, mtime or inode changes (a
// file added, removed, overwritten in place or replaced), so a redeploy that swaps files without a
// relay restart never serves new bytes under an id derived from the old ones.
function createPkgVersion(pkgDir) {
  let signature = null;
  let id = null;
  return function currentId() {
    let files;
    try { files = listFiles(pkgDir); } catch (error) { return null; }
    if (!files.includes(ENTRY)) return null;
    const next = JSON.stringify(files.map((f) => {
      const s = fs.statSync(path.join(pkgDir, f));
      return [f, s.size, s.mtimeMs, s.ino];
    }));
    if (next !== signature) {
      const hash = crypto.createHash('sha256');
      for (const f of files) {
        hash.update(f); hash.update('\0');
        hash.update(fs.readFileSync(path.join(pkgDir, f))); hash.update('\0');
      }
      id = hash.digest('hex').slice(0, 16);
      signature = next;
    }
    return id;
  };
}

// Middleware to mount at `/pkg`. `serveStatic` is the static-file middleware factory (express.static)
// so this module has no dependency of its own. Requests that are neither the entry alias nor a
// versioned path fall through untouched to whatever serves `/pkg` today.
function pkgAssets(pkgDir, serveStatic) {
  const currentId = createPkgVersion(pkgDir);
  const serve = serveStatic(pkgDir, {
    index: false,
    redirect: false,
    fallthrough: false,
    // Only a file that is actually being sent is marked immutable; a 404 keeps the caller's policy.
    setHeaders: (res) => res.setHeader('Cache-Control', IMMUTABLE),
  });
  return function pkgAssetsMiddleware(req, res, next) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    if (req.path === '/' + ENTRY) {
      const id = currentId();
      res.setHeader('Cache-Control', 'no-store');
      if (!id) return res.status(503).json({ error: 'wallet package is not deployed' });
      return res.redirect(302, '/pkg/' + id + '/' + ENTRY);
    }
    const match = VERSIONED.exec(req.path);
    if (!match) return next();
    if (match[1] !== currentId()) {
      // An id this relay no longer serves (a redeploy happened): never answer it with other bytes.
      res.setHeader('Cache-Control', 'no-store');
      return res.status(404).end();
    }
    const query = req.url.indexOf('?');
    req.url = match[2] + (query === -1 ? '' : req.url.slice(query));
    return serve(req, res, next);
  };
}

module.exports = { pkgAssets, createPkgVersion, ENTRY, IMMUTABLE };
