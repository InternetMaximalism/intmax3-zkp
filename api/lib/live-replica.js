'use strict';
// Standby replica of a channel's PRIVATE base state on every cluster host (design rule of
// 2026-11-10: the whole sig-cluster holds the Balance state, not one daemon).
//
// The resident live-balance daemon of the host that drives a deposit import, an inter-channel
// send or a burn is the only process that advances the channel's `FullPrivateState` (asset,
// nullifier and sent-tx trees, salts, nonce). A burn payout proof, a post-close late-incoming or
// late-deposit claim all need that state, so a channel whose driver host vanished could not
// finish them. After every such operation the driver now ships the SEALED files to every cluster
// peer, which keeps them as a passive replica it never opens while the driver is alive:
//
//   producer/journal.json                       the producer journal (the live snapshot's
//                                               `applied[]` receipts are reconciled against it on
//                                               open, and its timestamps cannot be reproduced)
//   producer/live/channel-<N>/balance.snapshot  the sealed live snapshot (magic, version, keccak)
//   ch<N>/<sidecars>                            channel_backing/channel_snapshot and the burn
//                                               ticket files a payout resumes from
//
// Transport: POST /api/cluster/live-replica on the peers' plain-HTTP listener, authenticated with
// an HMAC-SHA256 over the bundle digest under INTMAX_CLUSTER_SECRET (the cluster listener has no
// other authentication; the bundle carries salts, so replication REFUSES to run without the
// secret). A peer stores a bundle under INTMAX_REPLICA_ROOT/<host-key>/ only if its journal
// generation does not go backwards and the snapshot header is well-formed; the full cryptographic
// check (proof verification, private-commitment equality, receipt reconciliation) is the Rust
// `verify_live_replica` binary, which opens the replica with the daemon's own `open()` paths.
//
// Failover (an operator action, never automatic — two live authorities would fork the nonce):
//   node api/lib/live-replica.js promote <channel> <host-key>
// copies the replica into this host's producer/live directories, after which this relay's daemon
// is the channel's base-state authority.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const producer = require('./block-producer');
const cli = require('./cli');

const SECRET = process.env.INTMAX_CLUSTER_SECRET || '';
const REPLICA_ROOT = process.env.INTMAX_REPLICA_ROOT || path.join(cli.WORK, 'replica');
const SNAPSHOT_MAGIC = Buffer.from('IMLIVEBALANCE001', 'ascii');
const MAX_SKEW_MS = 5 * 60 * 1000;
// Channel-directory files a resumed burn payout / close reads (api/lib/partial-withdrawal-live.js,
// pw-settlement.js) besides the daemon's own state. Absent files are simply not shipped.
const SIDECARS = [
  'channel_backing.json', 'channel_snapshot.json', 'burn_operation.json', 'burn_payload.json',
  'burn_descriptor.json', 'burn_cosigned.json', 'pw_producer.json', 'last_burn.json',
  'pw_artifacts.json', 'inter_operation.json',
];

let transport = null; // { selfUrl, peers: [{ url }], log }
const inflight = new Map(); // channel -> Promise
const acked = new Map();    // channel -> bundle key last acknowledged by >= 1 peer

function configure(t) { transport = t; }
function configured() { return !!(transport && transport.peers && transport.peers.length); }
function enabled() { return configured() && !!SECRET; }
function hostKey(url) { return crypto.createHash('sha256').update(String(url)).digest('hex').slice(0, 16); }
function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

function journalRel() { return path.posix.join('producer', 'journal.json'); }
function snapshotRel(ch) { return path.posix.join('producer', 'live', `channel-${ch}`, 'balance.snapshot'); }
function sidecarRel(ch, name) { return path.posix.join(`ch${ch}`, name); }

// The files of channel `ch` as they are on disk right now. Returns null when the channel has no
// live snapshot yet (nothing private exists to replicate).
function collect(ch) {
  const snapshotPath = producer.liveSnapshotPath(ch);
  if (!fs.existsSync(snapshotPath)) return null;
  const files = {};
  const add = (rel, abs) => {
    if (!fs.existsSync(abs)) return;
    const bytes = fs.readFileSync(abs);
    files[rel] = { sha256: sha256(bytes), base64: bytes.toString('base64') };
  };
  add(journalRel(), producer.JOURNAL);
  add(snapshotRel(ch), snapshotPath);
  for (const name of SIDECARS) add(sidecarRel(ch, name), cli.wc(ch, name));
  const journal = JSON.parse(fs.readFileSync(producer.JOURNAL, 'utf8'));
  return {
    schemaVersion: 1,
    channel: ch,
    from: transport ? transport.selfUrl : '',
    sentAt: Date.now(),
    journalGeneration: Number(journal.generation),
    files,
  };
}

// Content key of a bundle: what the peers already hold is keyed by it, so an unchanged state is
// not shipped twice (deposit-info polls this on every call).
function digestOf(files) {
  const h = crypto.createHash('sha256');
  for (const rel of Object.keys(files).sort()) h.update(rel).update('\0').update(files[rel].sha256).update('\n');
  return h.digest('hex');
}
function sign(bundle) {
  return crypto.createHmac('sha256', SECRET)
    .update(`${bundle.channel}|${bundle.sentAt}|${bundle.journalGeneration}|${digestOf(bundle.files)}`)
    .digest('hex');
}

// Ship channel `ch` to every peer. `sync` waits for the peers and resolves with the acknowledgement
// list ({ acked, failed }); without it the shipment runs in the background and only logs. With
// the cluster configured but no INTMAX_CLUSTER_SECRET, nothing is shipped and that is logged once
// per channel, so an operator sees that the standby rule is NOT in force.
function replicate(ch, why, { sync = false } = {}) {
  const log = (transport && transport.log) || console;
  if (!configured()) return Promise.resolve({ skipped: 'no cluster' });
  if (!SECRET) {
    if (!acked.has(`nosecret:${ch}`)) {
      acked.set(`nosecret:${ch}`, true);
      log.error(`[live-replica] channel ${ch}: INTMAX_CLUSTER_SECRET is unset; the private base state is NOT replicated to the cluster (${why})`);
    }
    return Promise.resolve({ skipped: 'no secret' });
  }
  const run = (async () => {
    if (inflight.has(ch)) await inflight.get(ch).catch(() => {});
    const bundle = collect(ch);
    if (!bundle) return { skipped: 'no live snapshot' };
    const key = `${bundle.journalGeneration}:${digestOf(bundle.files)}`;
    if (acked.get(ch) === key) return { skipped: 'already replicated', key };
    const body = JSON.stringify(bundle);
    const signature = sign(bundle);
    const results = await Promise.all(transport.peers.map(async (peer) => {
      try {
        const r = await fetch(String(peer.url).replace(/\/$/, '') + '/api/cluster/live-replica', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-intmax-replica-signature': signature },
          body,
        });
        const text = await r.text();
        if (!r.ok) throw new Error(`${r.status} ${text.slice(0, 300)}`);
        return { url: peer.url, ok: true };
      } catch (e) {
        log.error(`[live-replica] channel ${ch} -> ${peer.url}: ${(e && e.message) || e}`);
        return { url: peer.url, ok: false, error: String((e && e.message) || e) };
      }
    }));
    const out = {
      key,
      acked: results.filter((r) => r.ok).map((r) => r.url),
      failed: results.filter((r) => !r.ok).map((r) => ({ url: r.url, error: r.error })),
    };
    if (out.acked.length) acked.set(ch, key);
    else log.error(`[live-replica] channel ${ch}: no peer holds the private base state after ${why}`);
    return out;
  })();
  const tracked = run.finally(() => { if (inflight.get(ch) === tracked) inflight.delete(ch); });
  inflight.set(ch, tracked);
  if (sync) return tracked;
  tracked.catch((e) => log.error(`[live-replica] channel ${ch} (${why}): ${(e && e.message) || e}`));
  return Promise.resolve({ scheduled: true });
}

// A secret-bearing recipient must exist on a peer before it is handed out: a deposit made to a
// recipient whose salt lived on one lost host could never be received. Resolves to true when at
// least one peer acknowledged the current state (or replication is not configured at all).
async function ensureReplicated(ch, why) {
  if (!enabled()) return !configured();
  const r = await replicate(ch, why, { sync: true });
  if (r.skipped === 'already replicated' || r.skipped === 'no live snapshot') return true;
  return !!(r.acked && r.acked.length);
}

function writePrivate(abs, bytes) {
  fs.mkdirSync(path.dirname(abs), { recursive: true, mode: 0o700 });
  const tmp = `${abs}.tmp-${process.pid}-${Date.now()}`;
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try { fs.writeSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, abs);
}

function replicaDir(fromUrl) { return path.join(REPLICA_ROOT, hostKey(fromUrl)); }
function manifestPath(fromUrl, ch) { return path.join(replicaDir(fromUrl), `manifest-ch${ch}.json`); }

// Peer side: verify the signature and the bundle's shape, refuse a generation rollback, store.
function receive(bundle, signature) {
  if (!SECRET) throw status(503, 'INTMAX_CLUSTER_SECRET is unset on this host');
  if (!bundle || bundle.schemaVersion !== 1 || !bundle.files || typeof bundle.from !== 'string') {
    throw status(400, 'malformed replica bundle');
  }
  const ch = Number(bundle.channel);
  if (!Number.isInteger(ch) || ch < 0) throw status(400, 'malformed replica channel');
  if (!transport || !transport.peers.some((p) => String(p.url).replace(/\/$/, '') === bundle.from.replace(/\/$/, ''))) {
    throw status(403, `replica from ${bundle.from} is not a configured peer`);
  }
  const expected = sign(bundle);
  const given = Buffer.from(String(signature || ''), 'utf8');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, Buffer.from(expected, 'utf8'))) {
    throw status(403, 'replica signature mismatch');
  }
  if (Math.abs(Date.now() - Number(bundle.sentAt)) > MAX_SKEW_MS) throw status(403, 'replica timestamp outside the accepted window');
  const files = {};
  for (const [rel, entry] of Object.entries(bundle.files)) {
    if (rel.includes('..') || path.posix.isAbsolute(rel)) throw status(400, `bad replica path ${rel}`);
    const bytes = Buffer.from(String(entry.base64 || ''), 'base64');
    if (sha256(bytes) !== entry.sha256) throw status(400, `replica file ${rel} does not match its digest`);
    files[rel] = bytes;
  }
  const journal = files[journalRel()];
  const snapshot = files[snapshotRel(ch)];
  if (!journal || !snapshot) throw status(400, 'replica bundle lacks the journal or the live snapshot');
  const generation = Number(JSON.parse(journal.toString('utf8')).generation);
  if (!Number.isInteger(generation) || generation !== Number(bundle.journalGeneration)) throw status(400, 'replica journal generation mismatch');
  if (snapshot.length < 48 || !snapshot.subarray(0, 16).equals(SNAPSHOT_MAGIC)) throw status(400, 'replica live snapshot has no valid header');
  const dir = replicaDir(bundle.from);
  let previous = null;
  try { previous = JSON.parse(fs.readFileSync(manifestPath(bundle.from, ch), 'utf8')); } catch (e) { /* first bundle */ }
  if (previous && Number(previous.journalGeneration) > generation) {
    throw status(409, `replica journal generation ${generation} is behind the held ${previous.journalGeneration}`);
  }
  for (const [rel, bytes] of Object.entries(files)) writePrivate(path.join(dir, ...rel.split('/')), bytes);
  const manifest = {
    from: bundle.from, channel: ch, receivedAt: Date.now(), sentAt: bundle.sentAt,
    journalGeneration: generation,
    files: Object.fromEntries(Object.entries(bundle.files).map(([rel, e]) => [rel, e.sha256])),
    verify: `${path.join(cli.REPO, 'target', 'release', 'verify_live_replica')} ${path.join(dir, 'producer', 'journal.json')} ${path.join(dir, 'producer', 'live', `channel-${ch}`, 'balance.snapshot')}`,
  };
  writePrivate(manifestPath(bundle.from, ch), Buffer.from(JSON.stringify(manifest, null, 2)));
  return { stored: true, hostKey: hostKey(bundle.from), channel: ch, journalGeneration: generation, files: Object.keys(files).length };
}

// What this host holds, for GET /api/cluster/replica-status.
function held() {
  const out = [];
  if (!fs.existsSync(REPLICA_ROOT)) return out;
  for (const key of fs.readdirSync(REPLICA_ROOT)) {
    const dir = path.join(REPLICA_ROOT, key);
    for (const name of fs.readdirSync(dir)) {
      const m = /^manifest-ch(\d+)\.json$/.exec(name);
      if (!m) continue;
      try {
        const manifest = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
        out.push({ hostKey: key, channel: Number(m[1]), from: manifest.from, journalGeneration: manifest.journalGeneration, receivedAt: manifest.receivedAt });
      } catch (e) { out.push({ hostKey: key, channel: Number(m[1]), error: String(e.message || e) }); }
    }
  }
  return out;
}

// Operator failover: install the replica of `fromKey` as THIS host's live state for channel `ch`.
// Refuses while this host already has a live snapshot or a journal of its own (that authority
// must be retired deliberately, not overwritten), and refuses a replica that does not open.
function promote(ch, fromKey) {
  const dir = path.join(REPLICA_ROOT, fromKey);
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, `manifest-ch${ch}.json`), 'utf8'));
  if (fs.existsSync(producer.liveSnapshotPath(ch))) throw new Error(`channel ${ch} already has a live snapshot on this host: ${producer.liveSnapshotPath(ch)}`);
  if (fs.existsSync(producer.JOURNAL)) throw new Error(`this host already has a producer journal: ${producer.JOURNAL}`);
  const verifier = path.join(cli.REPO, 'target', 'release', 'verify_live_replica');
  const r = require('child_process').spawnSync(verifier, [
    path.join(dir, 'producer', 'journal.json'),
    path.join(dir, 'producer', 'live', `channel-${ch}`, 'balance.snapshot'),
  ], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`replica verification failed: ${r.stderr || r.stdout}`);
  for (const rel of Object.keys(manifest.files)) {
    const src = path.join(dir, ...rel.split('/'));
    const dst = rel.startsWith('producer/')
      ? (rel === journalRel() ? producer.JOURNAL : producer.liveSnapshotPath(ch))
      : cli.wc(ch, path.posix.basename(rel));
    writePrivate(dst, fs.readFileSync(src));
  }
  return { promoted: true, channel: ch, from: manifest.from, journalGeneration: manifest.journalGeneration, verified: r.stdout.trim() };
}

function status(code, message) { const e = new Error(message); e.status = code; return e; }

module.exports = { configure, configured, enabled, replicate, ensureReplicated, receive, held, promote, hostKey, REPLICA_ROOT };

if (require.main === module) {
  const [cmd, ch, key] = process.argv.slice(2);
  if (cmd !== 'promote' || !ch || !key) {
    console.error('usage: node api/lib/live-replica.js promote <channel> <host-key>');
    process.exit(2);
  }
  console.log(JSON.stringify(promote(Number(ch), key), null, 2));
}
