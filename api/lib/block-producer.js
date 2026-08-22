const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { spawn } = require('child_process');

const REPO = path.resolve(__dirname, '..', '..');
const WORK = process.env.INTMAX_WORK_DIR || path.join(REPO, 'wallet-live-work');
const BIN = process.env.BLOCK_PRODUCER_BIN ||
  path.join(REPO, 'target', 'release', 'block_producer_service');
const JOURNAL = process.env.BLOCK_PRODUCER_JOURNAL ||
  path.join(WORK, 'producer', 'journal.json');
const ARITIES = process.env.BLOCK_PRODUCER_ARITIES || '2,4,8,16';
// Durable per-channel live-balance snapshots. Always on: the daemon is the sole base-state
// authority (checkpoint handoff), so the API never runs without the live spine.
const LIVE_ROOT = process.env.LIVE_BALANCE_ROOT || path.join(WORK, 'producer', 'live');
// Resident validity prover + L1 read-back. All-or-nothing per the daemon's own `requires`
// contract; enabled by setting VALIDITY_SNAPSHOT (plus the L1 vars) in the environment.
const VALIDITY_SNAPSHOT = process.env.VALIDITY_SNAPSHOT || '';
const VALIDITY_PROVER = process.env.VALIDITY_PROVER || '';
const L1_ROLLUP = process.env.L1_ROLLUP || '';
const L1_CHAIN_ID = process.env.L1_CHAIN_ID || '';
const L1_CONFIRMATIONS = process.env.L1_CONFIRMATIONS || '';

function daemonArgs() {
  const args = ['--journal', JOURNAL, '--supported-user-counts', ARITIES, '--live-root', LIVE_ROOT];
  if (process.env.INTMAX_REGEV_TEST_PROOFS === '1') args.push('--regev-test-proofs');
  if (VALIDITY_SNAPSHOT) {
    if (!VALIDITY_PROVER || !L1_ROLLUP || !L1_CHAIN_ID) {
      throw new Error(
        'VALIDITY_SNAPSHOT requires VALIDITY_PROVER, L1_ROLLUP and L1_CHAIN_ID (the daemon ' +
        'refuses a partial validity/L1 configuration)'
      );
    }
    args.push(
      '--validity-snapshot', VALIDITY_SNAPSHOT,
      '--validity-prover', VALIDITY_PROVER,
      '--l1-rpc-url', process.env.RPC || 'http://127.0.0.1:8545',
      '--l1-chain-id', L1_CHAIN_ID,
      '--l1-rollup', L1_ROLLUP,
    );
    if (L1_CONFIRMATIONS) args.push('--l1-confirmations', L1_CONFIRMATIONS);
  }
  return args;
}

function liveSnapshotPath(channelId) {
  return path.join(LIVE_ROOT, `channel-${channelId}`, 'balance.snapshot');
}

function liveSnapshotExists(channelId) {
  return fs.existsSync(liveSnapshotPath(channelId));
}

let child = null;
let pending = [];

function failPending(error) {
  const waiters = pending;
  pending = [];
  for (const waiter of waiters) waiter.reject(error);
}

function start() {
  if (child && child.exitCode === null && !child.killed) return child;
  fs.mkdirSync(path.dirname(JOURNAL), { recursive: true, mode: 0o700 });
  child = spawn(BIN, daemonArgs(), {
    stdio: ['pipe', 'pipe', 'pipe'],
    // The keyless producer needs no L1 wallet environment. In particular, do not copy keystore
    // passwords or legacy raw-key variables into a process that cannot use them.
    env: {
      PATH: process.env.PATH || '',
      RUST_BACKTRACE: process.env.RUST_BACKTRACE || '0',
    },
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => process.stderr.write(`[block-producer] ${chunk}`));
  child.on('error', error => {
    failPending(error);
    child = null;
  });
  child.on('exit', (code, signal) => {
    failPending(new Error(`block producer exited (code=${code}, signal=${signal || 'none'})`));
    child = null;
  });

  const lines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
  lines.on('line', line => {
    const waiter = pending.shift();
    if (!waiter) {
      failPending(new Error('block producer emitted an unsolicited response'));
      return;
    }
    let response;
    try {
      response = JSON.parse(line);
    } catch (error) {
      waiter.reject(new Error(`invalid block-producer JSON response: ${error.message}`));
      return;
    }
    if (!response || response.ok !== true) {
      const code = response && response.error && response.error.code;
      const message = response && response.error && response.error.message;
      const error = new Error(`block producer rejected request${code ? ` [${code}]` : ''}: ${message || line}`);
      error.code = code || 'producer_error';
      waiter.reject(error);
      return;
    }
    waiter.resolve(response.result);
  });
  return child;
}

function execute(command) {
  return new Promise((resolve, reject) => {
    const process = start();
    pending.push({ resolve, reject });
    process.stdin.write(`${JSON.stringify(command)}\n`, error => {
      if (!error) return;
      const index = pending.findIndex(waiter => waiter.resolve === resolve);
      if (index !== -1) pending.splice(index, 1);
      reject(error);
    });
  });
}

function stableRequestId(kind, body) {
  const digest = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
  return `${kind}:${digest}`;
}

function status() {
  return execute({ command: 'status' });
}

function register(snapshot, requestId) {
  return execute({
    command: 'register',
    requestId: requestId || stableRequestId('register', snapshot),
    snapshot,
  });
}

function postDeposit(deposit, requestId) {
  return execute({
    command: 'postDeposit',
    requestId: requestId || stableRequestId('deposit', deposit),
    deposit,
  });
}

function postInterChannel(signedState, debitPayload, descriptor, requestId) {
  const body = { signedState, debitPayload, descriptor };
  return execute({
    command: 'postInterChannel',
    requestId: requestId || stableRequestId('inter', body),
    ...body,
  });
}

function syncOffchainHeads(signedStates, requestId) {
  return execute({
    command: 'syncOffchainHeads',
    requestId: requestId || stableRequestId('sync', signedStates),
    signedStates,
  });
}

// ---- validity (exposed per the handoff: the launcher passes config, the API can drive it) ----

function validityStatus() {
  return execute({ command: 'validityStatus' });
}

function proveValidity(requestId) {
  return execute({ command: 'proveValidity', requestId });
}

function validityArtifact() {
  return execute({ command: 'validityArtifact' });
}

function acknowledgeValidity(requestId, candidateId, transactionHash) {
  return execute({ command: 'acknowledgeValidity', requestId, candidateId, transactionHash });
}

// ---- live balance (the durable base-state authority) ----

function liveStatus(channelId) {
  return execute({ command: 'liveStatus', channelId });
}

function liveInit(channelId) {
  return execute({ command: 'liveInit', channelId });
}

function livePrepareDepositRecipient(channelId) {
  return execute({ command: 'livePrepareDepositRecipient', channelId });
}

function liveReceiveConfiguredDeposit(channelId, producerReceipt, deposit) {
  return execute({ command: 'liveReceiveConfiguredDeposit', channelId, producerReceipt, deposit });
}

function liveBindSnapshot(channelId, signedSnapshot) {
  return execute({ command: 'liveBindSnapshot', channelId, signedSnapshot });
}

function liveSettleInterChannel(channelId, producerReceipt, signedState, debitPayload, descriptor) {
  return execute({
    command: 'liveSettleInterChannel',
    channelId, producerReceipt, signedState, debitPayload, descriptor,
  });
}

function liveSendArtifact(channelId, producerRequestId) {
  return execute({ command: 'liveSendArtifact', channelId, producerRequestId });
}

function liveBackingArtifact(channelId) {
  return execute({ command: 'liveBackingArtifact', channelId });
}

function liveBaseHead(channelId) {
  return execute({ command: 'liveBaseHead', channelId });
}

function liveReceiveInterChannel(channelId, body) {
  return execute({ command: 'liveReceiveInterChannel', channelId, ...body });
}

/// Terminate the resident daemon (server shutdown / test teardown). In-flight waiters are
/// rejected by the child's exit handler; a later command restarts the daemon, which recovers
/// from its durable journal + live snapshots.
function stop() {
  if (!child) return;
  const target = child;
  child = null;
  target.kill();
}

module.exports = {
  execute,
  postDeposit,
  postInterChannel,
  register,
  stableRequestId,
  status,
  syncOffchainHeads,
  validityStatus,
  proveValidity,
  validityArtifact,
  acknowledgeValidity,
  liveStatus,
  liveInit,
  livePrepareDepositRecipient,
  liveReceiveConfiguredDeposit,
  liveBindSnapshot,
  liveSettleInterChannel,
  liveSendArtifact,
  liveBackingArtifact,
  liveBaseHead,
  liveReceiveInterChannel,
  liveSnapshotExists,
  liveSnapshotPath,
  stop,
};
