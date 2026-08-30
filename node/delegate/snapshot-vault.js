'use strict';
// Durable archive of every WASM-authenticated signed snapshot. A hostile member set can finalize
// an older state; keeping only the newest in-memory snapshot would then leave a delegate unable to
// open the finalized H1 even though it observed that state earlier. Snapshots contain ciphertexts
// and public signatures, never the delegate's Regev secret.

const fs = require('fs');
const path = require('path');

function canonicalDigest(value) {
  const digest = String(value || '').toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(digest)) throw new Error('snapshot state digest must be bytes32');
  return digest;
}

function snapshotDigest(snapshot) {
  return canonicalDigest(snapshot && snapshot.state && snapshot.state.digest);
}

class SnapshotVault {
  constructor(workDir, channelId) {
    const id = String(channelId);
    if (!/^\d+$/.test(id)) throw new Error('channel id must be an unsigned integer');
    this.directory = path.join(path.resolve(workDir || '.'), 'delegate-snapshots', id);
  }

  fileFor(digest) {
    return path.join(this.directory, `${canonicalDigest(digest).slice(2)}.json`);
  }

  save(snapshot) {
    const digest = snapshotDigest(snapshot);
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    const destination = this.fileFor(digest);
    const serialized = JSON.stringify(snapshot);
    if (fs.existsSync(destination)) {
      // The state digest is the lookup key; valid aggregate/signature encodings may differ while
      // opening the same state. Preserve the first already-authenticated witness immutably.
      return destination;
    }
    const tmp = `${destination}.tmp-${process.pid}-${Date.now()}`;
    let fd;
    try {
      fd = fs.openSync(tmp, 'wx', 0o600);
      fs.writeFileSync(fd, serialized);
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(tmp, destination);
      const dirFd = fs.openSync(this.directory, fs.constants.O_RDONLY);
      try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
    } catch (error) {
      if (fd !== undefined) fs.closeSync(fd);
      try { fs.rmSync(tmp, { force: true }); } catch (_) { /* preserve root cause */ }
      throw error;
    }
    return destination;
  }

  load(digest) {
    const file = this.fileFor(digest);
    try {
      const snapshot = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (snapshotDigest(snapshot) !== canonicalDigest(digest)) {
        throw new Error(`archived snapshot digest mismatch for ${digest}`);
      }
      return snapshot;
    } catch (error) {
      if (error && error.code === 'ENOENT') return null;
      throw error;
    }
  }
}

module.exports = { SnapshotVault, canonicalDigest, snapshotDigest };
