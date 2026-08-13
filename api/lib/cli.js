const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const REPO = path.resolve(__dirname, '..', '..');
const WORK = process.env.INTMAX_WORK_DIR || path.join(REPO, 'wallet-live-work');
const CLI = process.env.CHANNEL_MEMBER_BIN || path.join(REPO, 'target', 'release', 'channel_member');
const RPC = process.env.RPC || 'http://127.0.0.1:8545';
const CHANNELS = (process.env.INTMAX_CHANNELS || '7,8').split(',').map(Number);

// The public Foundry/anvil dev key. Used ONLY as a local-dev fallback (INTMAX_DEV=1);
// it is famous and worthless — never sign a real-network tx with it.
const ANVIL_DEV_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

// The L1 signing key used by deposit/registration txs. Read from INTMAX_DEPOSIT_KEY
// (same var the CLI uses). No hardcoded default: production must set it. Only when
// INTMAX_DEV=1 (local anvil) do we fall back to the throwaway anvil dev key, loudly.
function depositKey() {
  const k = process.env.INTMAX_DEPOSIT_KEY;
  if (k) return k;
  if (process.env.INTMAX_DEV === '1') {
    console.warn('[security] INTMAX_DEPOSIT_KEY unset — using the public anvil dev key (INTMAX_DEV=1). NEVER on a real network.');
    return ANVIL_DEV_KEY;
  }
  throw new Error('INTMAX_DEPOSIT_KEY not set: refusing to sign L1 txs with a default key (set INTMAX_DEV=1 for local anvil only)');
}

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

// ─── Settlement stack: which chain are we on, and can this deployment produce one? ───────────
//
// SECURITY: `channel_member deploy-settlement` picks its forge script from the chain id the RPC
// reports. On 31337 that is `DeployWalletSettlement.s.sol`, which installs an ALWAYS-TRUE mock MLE
// verifier — fine on anvil, catastrophic anywhere else (a vacuous close-proof check means anyone
// can close any channel to any state). The CLI refuses to install it off-devnet; this module must
// therefore not pretend the deploy is a routine step on a real network. It is an OPERATOR action
// with an ordering constraint (below), so the routes surface that instead of a raw forge failure.
const DEVNET_CHAIN_ID = 31337;

let _chainId; // cached: a fixed RPC cannot change chain id mid-process.
function chainId() {
  if (_chainId === undefined) {
    const raw = execFileSync('cast', ['chain-id', '--rpc-url', RPC], { encoding: 'utf8' }).trim();
    const n = Number(raw);
    if (!Number.isInteger(n) || n <= 0) {
      // Fail closed: an unreadable chain id must never be resolved as "probably devnet".
      throw new Error(`cannot read the chain id from ${RPC} (got ${JSON.stringify(raw)})`);
    }
    _chainId = n;
  }
  return _chainId;
}

/// A refusal the routes report verbatim, with an HTTP status that says "your deployment is not
/// provisioned for this", not "something broke".
class SettlementUnavailable extends Error {
  constructor(payload, status) {
    super(payload.error);
    this.name = 'SettlementUnavailable';
    this.httpStatus = status || 409;
    this.payload = payload;
  }
}

/// Return this channel's settlement stack, deploying it ONLY where deploying it is correct.
///
/// anvil (31337): unchanged — deploy on demand, exactly as the wallet demo has always done.
///
/// Any real chain: NO deploy on demand. `DeployCloseCli.s.sol` — the only script that installs
/// real MLE/WHIR verifier data for the four settlement statements — deploys its OWN IntmaxRollup,
/// so it can only be run BEFORE the channel is funded. By the time an API route needs a settlement
/// stack the channel is already backed (the runbook ships `channel_backing.json` in), so deploying
/// now would put the registration, the manager and the exit path on a NEW rollup while the money
/// stayed on the old one. The CLI refuses that; this returns the same refusal as structured JSON
/// so a client sees an actionable operator task rather than a 500.
function ensureSettlement(ch) {
  const p = wc(ch, 'settlement.json');
  if (fs.existsSync(p)) return readJson(p);
  if (chainId() === DEVNET_CHAIN_ID) {
    cli(ch, ['deploy-settlement', RPC]);
    return readJson(p);
  }
  let backedRollup = '';
  try {
    backedRollup = readJson(wc(ch, 'channel_backing.json')).rollup || '';
  } catch (e) { /* unbacked channel: the ordering advice below is exactly what it needs */ }
  throw new SettlementUnavailable({
    error: 'no settlement stack for this channel, and one cannot be deployed now',
    chainId: chainId(),
    backingRollup: backedRollup,
    detail:
      'On a real chain the settlement stack must be deployed BEFORE the channel is funded: the ' +
      'only script with real (non-mock) settlement VKs, DeployCloseCli.s.sol, deploys its own ' +
      'IntmaxRollup. Deploying it now would register the channel and its ChannelSettlementManager ' +
      'on a new rollup while the deposit stayed on ' + (backedRollup || 'the existing rollup') + '.',
    operatorAction:
      'In a fresh per-channel work dir, before setup-backing: ' +
      'INTMAX_CHANNEL=<ch> INTMAX_DEPOSIT_KEY=<funded key> FRAUD_TREASURY=<addr> ' +
      'INTMAX_COSIGNER_KEYFILE=<0600 file> channel_member deploy-settlement <rpc>, then ' +
      'setup-backing <rpc> <the rollup it prints>, then init. See doc/docs/deploy-runbook.md.',
    missingCapability:
      'Attaching a real settlement stack to an ALREADY-DEPLOYED rollup (registerChannel + ' +
      'ChannelSettlementVerifier with the four real VKs + ChannelSettlementManager + ' +
      'registerSettlementManager, against an existing rollup address) has no forge script yet.',
  });
}

/// Route error handler: reports a `SettlementUnavailable` (or any error carrying a payload) as the
/// structured refusal it is, and everything else as it did before. INTENTIONALLY SIMPLE — one
/// helper so no route can forget to distinguish "not provisioned" from "broke".
function failRoute(res, e) {
  console.error(e.stderr ? String(e.stderr) : (e.message || e));
  if (e && e.payload) return res.status(e.httpStatus || 409).json(e.payload);
  return res.status(500).json({ error: String((e && e.stderr) || (e && e.message) || e) });
}

function readJson(filepath) {
  return JSON.parse(fs.readFileSync(filepath, 'utf8'));
}

function writeJson(filepath, data) {
  fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
}

module.exports = {
  REPO, WORK, CLI, RPC, CHANNELS, DEVNET_CHAIN_ID, depositKey, chDir, wc, validChannel, cli, sh,
  rollupOf, readJson, writeJson, chainId, ensureSettlement, failRoute, SettlementUnavailable,
};
