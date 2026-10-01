'use strict';
// Deposits are offered only into a rollup whose validity verifier pins the producer's own circuit
// configuration. The first Sepolia rollup pinned the arity-[2] test fixture under a 2,4,8,16
// producer: it can never finalize a producer block, has no refund path, and locked every deposit.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'validity-deployment-'));
process.env.INTMAX_WORK_DIR = path.join(root, 'work');
process.env.INTMAX_CHANNELS = '7,8';
process.env.CHANNEL_MEMBER_BIN = path.join(root, 'channel_member');
process.env.BLOCK_PRODUCER_BIN = path.join(root, 'block_producer_service');
delete process.env.BLOCK_PRODUCER_ARITIES;

const cli = require('../../api/lib/cli');
const deployment = require('../../api/lib/validity-deployment');

const ROLLUP = '0x' + '3C'.repeat(20), ADAPTER = '0x' + 'ad'.repeat(20), CORE = '0x' + 'c0'.repeat(20);
const PRODUCER = {
  verificationConfigDigest: '0x' + 'aa'.repeat(32),
  circuitConfigDigest: '0x' + '43'.repeat(32), // arities 2,4,8,16
  whirParametersDigest: '0x' + '96'.repeat(32),
};
const FIXTURE = { ...PRODUCER, circuitConfigDigest: '0x' + 'c8'.repeat(32) }; // the arity-[2] fixture

let onchain, exported, readFails;
function reset() {
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(process.env.CHANNEL_MEMBER_BIN, 'channel_member build A');
  fs.writeFileSync(process.env.BLOCK_PRODUCER_BIN, 'block_producer_service build A');
  cli.REPO = root;
  delete process.env.BLOCK_PRODUCER_ARITIES;
  onchain = { ...PRODUCER };
  exported = [];
  readFails = false;
}
cli.chainId = () => 11155111;
cli.sh = (bin, args) => {
  if (bin === cli.CLI && args[0] === 'export-wallet-validity-config') {
    exported.push(args[2]);
    fs.writeFileSync(args[1], JSON.stringify({ pinnedVerifier: { ...PRODUCER } }));
    return '';
  }
  assert.equal(bin, 'cast');
  if (readFails) throw Object.assign(new Error('cast call failed'), { stderr: 'connection refused' });
  const [, address, sig] = args;
  if (sig === 'validityMleVerifier()(address)') { assert.equal(address, ROLLUP); return ADAPTER + '\n'; }
  if (sig === 'core()(address)') { assert.equal(address, ADAPTER); return CORE + '\n'; }
  assert.equal(address, CORE);
  return onchain[sig.split('(')[0]] + '\n';
};

test('a rollup pinned to another circuit configuration is refused and nothing is recorded', () => {
  reset();
  onchain = { ...FIXTURE };
  assert.throws(() => deployment.verify(ROLLUP),
    /cannot finalize this producer's blocks.*circuitConfigDigest: rollup 0xc8c8.*producer 0x4343.*could never be withdrawn/s);
  assert.equal(fs.existsSync(deployment.recordPath()), false);
  assert.match(deployment.readiness(ROLLUP).reason, /not been verified/);
});

test("a rollup pinned to the producer's configuration is recorded and ready", () => {
  reset();
  const record = deployment.verify(ROLLUP);
  assert.equal(record.rollup, ROLLUP.toLowerCase());
  assert.equal(record.arities, '2,4,8,16');
  assert.deepEqual(record.pins, PRODUCER);
  assert.deepEqual(exported, ['2,4,8,16']);
  const ready = deployment.readiness(ROLLUP);
  assert.equal(ready.ok, true);
  // The export is cached per build and arity set: verifying again does not rebuild the circuits.
  deployment.verify(ROLLUP);
  assert.equal(exported.length, 1);
});

test('the record holds only for the chain, rollup, arities and binaries it was made with', () => {
  reset();
  deployment.verify(ROLLUP);
  assert.match(deployment.readiness('0x' + '11'.repeat(20)).reason, /record is for rollup/);
  cli.chainId = () => 1;
  try { assert.match(deployment.readiness(ROLLUP).reason, /record is for chain 11155111/); }
  finally { cli.chainId = () => 11155111; }
  process.env.BLOCK_PRODUCER_ARITIES = '2,4';
  assert.match(deployment.readiness(ROLLUP).reason, /proves arities 2,4/);
  delete process.env.BLOCK_PRODUCER_ARITIES;
  fs.writeFileSync(process.env.BLOCK_PRODUCER_BIN, 'block_producer_service build B');
  assert.match(deployment.readiness(ROLLUP).reason, /binaries changed/);
  fs.writeFileSync(process.env.BLOCK_PRODUCER_BIN, 'block_producer_service build A');
  fs.writeFileSync(process.env.CHANNEL_MEMBER_BIN, 'channel_member build B');
  assert.match(deployment.readiness(ROLLUP).reason, /binaries changed/);
});

test('the deployed verifier is re-read: a different answer fails closed, an unreadable chain is transient', () => {
  reset();
  deployment.verify(ROLLUP);
  onchain.whirParametersDigest = '0x' + '00'.repeat(32);
  const moved = deployment.readiness(ROLLUP);
  assert.equal(moved.ok, false);
  assert.equal(moved.transient, false);
  assert.match(moved.reason, /no longer matches the record \(whirParametersDigest/);
  onchain = { ...PRODUCER };
  readFails = true;
  const unreadable = deployment.readiness(ROLLUP);
  assert.equal(unreadable.ok, false);
  assert.equal(unreadable.transient, true);
  assert.match(unreadable.reason, /could not read/);
});

test('the served rollup is the one every backed channel names', () => {
  reset();
  assert.equal(deployment.servedRollup([7, 8]), null);
  for (const ch of [7, 8]) {
    fs.mkdirSync(cli.wc(ch, ''), { recursive: true });
    fs.writeFileSync(cli.wc(ch, 'channel_backing.json'), JSON.stringify({ rollup: ROLLUP }));
  }
  assert.equal(deployment.servedRollup([7, 8]), ROLLUP.toLowerCase());
  fs.writeFileSync(cli.wc(8, 'channel_backing.json'), JSON.stringify({ rollup: '0x' + '22'.repeat(20) }));
  assert.throws(() => deployment.servedRollup([7, 8]), /2 different rollups/);
});
