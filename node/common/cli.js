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
    fs.writeFileSync(path.join(cwd, name), JSON.stringify(value));
  }

  return { CLI, run, readJson, writeJson };
}

module.exports = { makeCli };
