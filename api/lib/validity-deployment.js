'use strict';
// Money goes into a rollup only where it can come out again.
//
// Every exit from the rollup — a partial withdrawal's payout, a closed channel's funding, a late
// incoming claim — needs a validity proof FINALIZED by the rollup, and the rollup verifies validity
// proofs only against the circuit configuration pinned in its immutable validity verifier. It has
// no refund path. A rollup pinned to any configuration other than the producer's can therefore
// never finalize a producer block, and every deposit into it is locked for good: the first Sepolia
// deployment pinned the arity-[2] test fixture while the producer proves arities 2,4,8,16.
//
// `verify` compares the deployed validity verifier with the configuration exported from the SAME
// circuits the resident producer builds, and records the result bound to the exact binaries that
// exported it. `readiness` re-checks that record without building any circuit (relay startup): the
// chain, the rollup, the producer's arities and both binaries must be unchanged, and the deployed
// verifier must still report the recorded digests. Anything else fails closed.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cli = require('./cli');

const SCHEMA = 1;
const PIN_NAMES = ['verificationConfigDigest', 'circuitConfigDigest', 'whirParametersDigest'];
const HEX32 = /^0x[0-9a-f]{64}$/;
const HEX20 = /^0x[0-9a-fA-F]{40}$/;

function arities() {
  const value = process.env.BLOCK_PRODUCER_ARITIES || '2,4,8,16';
  if (!/^[0-9]+(,[0-9]+)*$/.test(value)) throw new Error('invalid producer arities');
  return value;
}
function producerBinary() {
  return process.env.BLOCK_PRODUCER_BIN || path.join(cli.REPO, 'target', 'release', 'block_producer_service');
}
const sha256File = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const recordPath = () => path.join(cli.WORK, 'producer', 'validity-deployment.json');
const binaries = () => ({ channelMember: sha256File(cli.CLI), blockProducer: sha256File(producerBinary()) });

// The validity verifier configuration of the circuits this build's producer proves with, exported
// proof-free from the same constructor. Building those circuits takes minutes and ~15 GB, so the
// export is cached per build and arity set. It lives in proof-da-output/, which Foundry may read
// (contracts/foundry.toml fs_permissions), so a deployment pins exactly this file.
function exportedConfig() {
  const list = arities();
  const dir = path.join(cli.REPO, 'proof-da-output');
  fs.mkdirSync(dir, { recursive: true });
  const build = sha256File(cli.CLI).slice(0, 16);
  const file = path.join(dir, 'wallet-validity-config-' + list.replaceAll(',', '_') + '-' + build + '.json');
  if (!fs.existsSync(file)) cli.sh(cli.CLI, ['export-wallet-validity-config', file, list],
    { timeout: Math.max(3_600_000, Number(process.env.INTMAX_CLI_TIMEOUT_MS || 0)) });
  return file;
}

function pinsOf(file) {
  const pinned = cli.readJson(file).pinnedVerifier || {};
  const pins = {};
  for (const name of PIN_NAMES) {
    const value = String(pinned[name] || '').toLowerCase();
    if (!HEX32.test(value)) throw new Error(`${file} has no ${name}`);
    pins[name] = value;
  }
  return pins;
}

function deployedVerifier(rollup) {
  const view = (address, sig) => cli.sh('cast', ['call', address, sig, '--rpc-url', cli.RPC], { stdio: 'pipe' }).trim();
  const adapter = view(rollup, 'validityMleVerifier()(address)').toLowerCase();
  const core = view(adapter, 'core()(address)').toLowerCase();
  const pins = {};
  for (const name of PIN_NAMES) pins[name] = view(core, name + '()(bytes32)').toLowerCase();
  return { adapter, core, pins };
}

const differences = (expected, deployed) => PIN_NAMES.filter(name => expected[name] !== deployed[name])
  .map(name => `${name}: rollup ${deployed[name]}, producer ${expected[name]}`);

// The one rollup the served channels deposit into (their channel_backing.json), or null before any
// channel is backed.
function servedRollup(channels = cli.CHANNELS) {
  const rollups = new Set(channels.filter(ch => fs.existsSync(cli.wc(ch, 'channel_backing.json')))
    .map(ch => String(cli.rollupOf(ch)).toLowerCase()));
  if (rollups.size > 1) throw new Error(`the served channels deposit into ${rollups.size} different rollups`);
  return rollups.size ? [...rollups][0] : null;
}

// Throws unless the rollup's validity verifier verifies this producer's proofs; on success writes
// and returns the record `readiness` checks.
function verify(rollup) {
  if (!HEX20.test(String(rollup))) throw new Error('verify needs the rollup address');
  const config = exportedConfig();
  const expected = pinsOf(config);
  const deployed = deployedVerifier(rollup);
  const mismatch = differences(expected, deployed.pins);
  if (mismatch.length) {
    throw new Error(`rollup ${rollup} cannot finalize this producer's blocks: its validity verifier pins ` +
      `another circuit configuration (${mismatch.join('; ')}). Every exit needs a finalized validity ` +
      `proof and the rollup has no refund path, so deposits into it could never be withdrawn. Deploy a ` +
      `rollup pinned to ${config}.`);
  }
  const record = {
    schema: SCHEMA, chainId: cli.chainId(), rollup: rollup.toLowerCase(), adapter: deployed.adapter,
    core: deployed.core, arities: arities(), pins: expected, binaries: binaries(),
    config: path.basename(config), verifiedAt: new Date().toISOString(),
  };
  cli.writeJson(recordPath(), record);
  return record;
}

// { ok: true, record } when deposits into `rollup` can be withdrawn by this deployment; otherwise
// { ok: false, reason, transient } — `transient` only when the chain could not be read.
function readiness(rollup) {
  const fail = (reason, transient = false) => ({ ok: false, reason, transient });
  if (!fs.existsSync(recordPath())) {
    return fail("this rollup has not been verified to finalize the producer's blocks (no validity deployment record)");
  }
  let record;
  try { record = cli.readJson(recordPath()); } catch (e) { return fail('the validity deployment record is unreadable'); }
  if (record.schema !== SCHEMA || !record.pins || !record.binaries) return fail('the validity deployment record has an unknown format');
  if (record.chainId !== cli.chainId()) return fail(`the validity deployment record is for chain ${record.chainId}`);
  if (record.rollup !== String(rollup).toLowerCase()) return fail(`the validity deployment record is for rollup ${record.rollup}`);
  if (record.arities !== arities()) return fail(`the producer proves arities ${arities()}, the record was verified for ${record.arities}`);
  const now = binaries();
  if (now.channelMember !== record.binaries.channelMember || now.blockProducer !== record.binaries.blockProducer) {
    return fail('the binaries changed since the validity deployment was verified (run hosting/wallet/verify-validity-deployment.js)');
  }
  let deployed;
  try { deployed = deployedVerifier(rollup); } catch (e) {
    return fail('could not read the rollup\'s validity verifier: ' + String(e.message || e).split('\n')[0], true);
  }
  const mismatch = differences(record.pins, deployed.pins);
  if (deployed.adapter !== record.adapter || deployed.core !== record.core || mismatch.length) {
    return fail(`the rollup's validity verifier no longer matches the record (${mismatch.join('; ') || 'adapter/core moved'})`);
  }
  return { ok: true, record };
}

module.exports = { exportedConfig, pinsOf, deployedVerifier, servedRollup, verify, readiness, recordPath, PIN_NAMES };
