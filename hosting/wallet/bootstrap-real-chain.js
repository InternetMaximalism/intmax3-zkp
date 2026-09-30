'use strict';
// Operator bootstrap of wallet channels on a PUBLIC chain.
//
// The wallet relay (wallet-relay.js) creates a channel on the first browser join and, on the local
// devnet, deploys its settlement stack on demand. A public chain cannot do that inside a browser
// request: the settlement stack must be deployed and the channel registered on L1 before any join,
// and that deployment needs a close-backing proof of the channel's own signed head. This script
// performs that sequence once per channel, run by the operator while the relay is stopped (one
// writer per channel directory):
//
//   1. genesis   — `init` with an operator-owned delegate contribution. The channel's first slot
//                  after the sig-cluster is the operator's; browser users join after it as further
//                  delegates. Its exit recipient is an operator-controlled address.
//   2. live      — the producer's live balance for the channel, bound to the signed genesis.
//   3. envelope  — the public backing envelope of that head (the signer-independent exit kit),
//                  which public_close_prover consumes. It is not installed yet: the CLI installs a
//                  kit only under an ACTIVE settlement binding, which step 5 creates.
//   4. bundle    — public_close_prover turns the envelope into the close-backing bundle.
//   5. settlement— `deploy-settlement` attaches the settlement stack to the channel's rollup and
//                  registers the channel on L1 (cosigners only; delegates keep joining afterwards).
//   6. register  — the producer admits the channel after verifying the on-chain registration.
//   7. exit kit  — installed for the registered head.
//
// Every step is skipped when its result already exists, so the script can be re-run after a
// failure. Prerequisites: the rollup is deployed and each channel dir holds its `setup-backing`
// artifacts; the late-incoming verifier is deployed (contracts/script/DeployLateIncomingVerifier.s.sol).
//
// Usage: node hosting/wallet/bootstrap-real-chain.js <channel> [<channel> ...]
// Environment (in addition to the relay's CLI/L1 environment):
//   BOOTSTRAP_DELEGATE_RECIPIENT_<ch>  operator-controlled L1 exit address of the operator delegate
//   LATE_INCOMING_VERIFIER, LATE_MLE_CONFIG_PATH   the deployed late-incoming adapter and its config
//   PUBLIC_CLOSE_PROVER_BIN   default target/release/public_close_prover
//   BOOTSTRAP_STOP_AFTER=envelope   stop after step 3 (to run the prover on another machine and
//                             place the bundle at <channel dir>/public_close_bundle)
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const cliModule = require('../../api/lib/cli');
const producer = require('../../api/lib/block-producer');
const { installHeadExitKit, writeHeadExitKitEnvelope } = require('../../api/lib/exit-kit');
const { ensureLiveRegistration } = require('../../api/lib/live-registration');

const { cli, wc, readJson, writeJson, RPC } = cliModule;
const REPO = path.resolve(__dirname, '..', '..');
const PROVER = process.env.PUBLIC_CLOSE_PROVER_BIN || path.join(REPO, 'target', 'release', 'public_close_prover');
const STOP_AFTER = process.env.BOOTSTRAP_STOP_AFTER || '';
const HEX20 = /^0x[0-9a-fA-F]{40}$/;
// Public slot label for the operator delegate's key derivation (not key material; see
// `gen-contribution`). Distinct per channel so the delegates never share an identity.
const OPERATOR_DELEGATE_LABEL = ch => String(900000 + ch);
const FINALITY_RETRY_MS = 60 * 1000;
const FINALITY_RETRIES = 60;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function step(ch, name, message) { console.log(`[ch${ch}] ${name}: ${message}`); }

function genesis(ch) {
  if (fs.existsSync(wc(ch, 'cli_state.json'))) return step(ch, 'genesis', 'exists');
  const recipient = process.env[`BOOTSTRAP_DELEGATE_RECIPIENT_${ch}`] || '';
  if (!HEX20.test(recipient)) throw new Error(`BOOTSTRAP_DELEGATE_RECIPIENT_${ch} must be the operator-controlled exit address of this channel's operator delegate`);
  cli(ch, ['gen-contribution', '0', OPERATOR_DELEGATE_LABEL(ch), 'operator_contribution.json']);
  const contribution = readJson(wc(ch, 'operator_contribution.json'));
  contribution.recipient = recipient; // the simulated recipient is synthetic; the operator's is recoverable
  writeJson(wc(ch, 'operator_contribution.json'), contribution);
  cli(ch, ['init', 'operator_contribution.json', 'channel_snapshot.json']);
  step(ch, 'genesis', 'created with the operator delegate');
}

async function live(ch) {
  if (producer.liveSnapshotExists(ch)) return step(ch, 'live', 'exists');
  const backing = readJson(wc(ch, 'channel_backing.json'));
  const salt = backing.base_private_state && backing.base_private_state.salt;
  if (salt) await producer.liveInitWithAccountSalt(ch, salt);
  else await producer.liveInit(ch);
  await producer.liveBindSnapshot(ch, readJson(wc(ch, 'channel_snapshot.json')));
  step(ch, 'live', 'initialized and bound to the signed genesis');
}

function sha256File(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }

function bundle(ch) {
  const dir = wc(ch, 'public_close_bundle');
  if (fs.existsSync(path.join(dir, 'public_close_manifest.json'))) return step(ch, 'bundle', 'exists'), dir;
  const backing = readJson(wc(ch, 'channel_backing.json'));
  step(ch, 'bundle', 'proving (public_close_prover)…');
  execFileSync(PROVER, [
    '--input', wc(ch, 'installed_exit_kit.json'),
    '--output-dir', dir,
    '--expected-channel-id', String(ch),
    '--expected-chain-id', String(cliModule.chainId()),
    '--expected-rollup', backing.rollup,
    '--expected-balance-vd-sha256', sha256File(wc(ch, 'balance_vd.bin')),
  ], { stdio: 'inherit', timeout: 4 * 3600 * 1000 });
  return dir;
}

async function settlement(ch, bundleDir) {
  if (fs.existsSync(wc(ch, 'settlement.json'))) return step(ch, 'settlement', 'exists');
  for (const name of ['LATE_INCOMING_VERIFIER', 'LATE_MLE_CONFIG_PATH']) {
    if (!process.env[name]) throw new Error(`${name} is required to deploy the settlement stack`);
  }
  // Broadcasts ~15 transactions and waits for the finalized read-back: far beyond the CLI default.
  const previous = process.env.INTMAX_CLI_TIMEOUT_MS;
  process.env.INTMAX_CLI_TIMEOUT_MS = String(3 * 3600 * 1000);
  try {
    // The CLI activates the binding only from FINALIZED reads and exits, journal intact, while its
    // transactions are still above the finalized head (~13 min on Sepolia after the broadcast).
    // That one refusal is a wait, not a failure: retry the same command until finality catches up.
    for (let attempt = 1; ; attempt++) {
      try {
        cli(ch, ['deploy-settlement', RPC], { INTMAX_PUBLIC_CLOSE_BUNDLE: bundleDir });
        break;
      } catch (e) {
        const text = String((e && (e.stderr || e.message)) || e);
        if (!/not finalized yet|retry after the finalized head advances/.test(text) || attempt >= FINALITY_RETRIES) throw e;
        step(ch, 'settlement', `waiting for L1 finality (attempt ${attempt})`);
        await sleep(FINALITY_RETRY_MS);
      }
    }
  } finally {
    if (previous === undefined) delete process.env.INTMAX_CLI_TIMEOUT_MS; else process.env.INTMAX_CLI_TIMEOUT_MS = previous;
  }
  step(ch, 'settlement', `deployed: ${JSON.stringify(readJson(wc(ch, 'settlement.json')))}`);
}

async function bootstrap(ch) {
  if (cliModule.chainId() === 31337) throw new Error('the devnet relay bootstraps its own channels; this script is for public chains');
  for (const f of ['channel_backing.json', 'channel_attestation.bin', 'balance_vd.bin']) {
    if (!fs.existsSync(wc(ch, f))) throw new Error(`ch${ch}: ${f} is missing — run setup-backing first`);
  }
  genesis(ch);
  await live(ch);
  if (!fs.existsSync(wc(ch, 'settlement.json'))) {
    if (!fs.existsSync(path.join(wc(ch, 'public_close_bundle'), 'public_close_manifest.json'))) {
      step(ch, 'envelope', `written to ${await writeHeadExitKitEnvelope(ch)}`);
    }
    if (STOP_AFTER === 'envelope') return step(ch, 'stop', 'BOOTSTRAP_STOP_AFTER=envelope');
    await settlement(ch, bundle(ch));
  }
  await ensureLiveRegistration(ch, readJson(wc(ch, 'channel_snapshot.json')));
  step(ch, 'register', 'the producer admitted the L1-registered channel');
  await installHeadExitKit(ch);
  step(ch, 'exit kit', 'installed for the registered head — ready for delegate joins');
}

(async () => {
  const channels = process.argv.slice(2).map(Number);
  if (!channels.length || channels.some(ch => !Number.isSafeInteger(ch) || ch <= 0)) {
    throw new Error('usage: bootstrap-real-chain.js <channel> [<channel> ...]');
  }
  for (const ch of channels) await bootstrap(ch);
})().then(() => { producer.stop(); process.exit(0); }, (e) => {
  console.error(e && (e.stderr ? String(e.stderr) : (e.stack || e.message)) || e);
  try { producer.stop(); } catch (_) { /* already down */ }
  process.exit(1);
});
