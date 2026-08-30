'use strict';
// channel_member CLI wrapper (co-signer side, DESIGN.md §2.2). execFile with an ARGV ARRAY — never
// a shell string — so request-derived values cannot inject (matches api/lib/cli.js). The CLI is the
// real fail-closed verification + proving gate; this module only invokes it.

const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');

function makeCli({ binPath, repoRoot, defaultTimeoutMs = 600_000 }) {
  const CLI = binPath || path.join(repoRoot, 'target', 'release', 'channel_member');

  function run(channelId, cwd, args, extraEnv = {}, timeoutMs = defaultTimeoutMs) {
    return new Promise((resolve, reject) => {
      execFile(
        CLI,
        args,
        {
          cwd,
          encoding: 'utf8',
          timeout: timeoutMs,
          maxBuffer: 256 * 1024 * 1024,
          env: { ...process.env, INTMAX_CHANNEL: String(channelId), ...extraEnv },
        },
        (err, stdout, stderr) => {
          if (err) {
            const e = new Error(String(stderr || err.message || err));
            e.stderr = stderr;
            e.code = err.code;
            return reject(e);
          }
          resolve(stdout);
        }
      );
    });
  }

  function readJson(cwd, name) {
    return JSON.parse(fs.readFileSync(path.join(cwd, name), 'utf8'));
  }

  function writeJson(cwd, name, value) {
    fs.mkdirSync(cwd, { recursive: true });
    const target = path.join(cwd, name);
    const tmp = `${target}.tmp-${process.pid}-${Date.now()}-${writeJson.sequence++}`;
    let fd;
    try {
      fd = fs.openSync(tmp, 'wx', 0o600);
      fs.writeFileSync(fd, JSON.stringify(value));
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(tmp, target);
      // Persist the directory entry as well as the file contents. Some filesystems can otherwise
      // lose the rename after a host crash even though fsync(file) succeeded.
      let dirFd;
      try {
        dirFd = fs.openSync(cwd, 'r');
        fs.fsyncSync(dirFd);
      } catch (_) {
        // Directory fsync is not supported on every platform; atomic rename still prevents a
        // reader from observing partial JSON.
      } finally {
        if (dirFd !== undefined) fs.closeSync(dirFd);
      }
    } catch (e) {
      if (fd !== undefined) fs.closeSync(fd);
      try { fs.rmSync(tmp, { force: true }); } catch (_) { /* keep original error */ }
      throw e;
    }
  }

  writeJson.sequence = 0;

  return { CLI, run, readJson, writeJson };
}

module.exports = { makeCli };
