const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const REPO = path.resolve(__dirname, '..', '..');
const WORK = process.env.INTMAX_WORK_DIR || path.join(REPO, 'wallet-live-work');
const CLI = process.env.CHANNEL_MEMBER_BIN || path.join(REPO, 'target', 'release', 'channel_member');
const RPC = process.env.RPC || 'http://127.0.0.1:8545';
const CHANNELS = (process.env.INTMAX_CHANNELS || '7,8').split(',').map(Number);
const ANVIL0 = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

function chDir(ch) {
  return path.join(WORK, 'ch' + ch);
}

function wc(ch, name) {
  return path.join(chDir(ch), name);
}

function validChannel(ch) {
  const n = parseInt(ch, 10);
  return CHANNELS.includes(n) ? n : null;
}

function cli(ch, args, extraEnv) {
  console.log(`  $ INTMAX_CHANNEL=${ch} channel_member ${args.join(' ')}`);
  return execFileSync(CLI, args, {
    cwd: chDir(ch),
    encoding: 'utf8',
    timeout: 600_000,
    env: { ...process.env, INTMAX_CHANNEL: String(ch), ...(extraEnv || {}) },
  });
}

function sh(bin, args, opts) {
  return execFileSync(bin, args, { encoding: 'utf8', ...opts });
}

function rollupOf(ch) {
  const b = JSON.parse(fs.readFileSync(wc(ch, 'channel_backing.json'), 'utf8'));
  if (!b.rollup) throw new Error('channel has no rollup in channel_backing.json');
  return b.rollup;
}

function readJson(filepath) {
  return JSON.parse(fs.readFileSync(filepath, 'utf8'));
}

function writeJson(filepath, data) {
  fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
}

module.exports = { REPO, WORK, CLI, RPC, CHANNELS, ANVIL0, chDir, wc, validChannel, cli, sh, rollupOf, readJson, writeJson };
