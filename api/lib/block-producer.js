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
  child = spawn(BIN, ['--journal', JOURNAL, '--supported-user-counts', ARITIES], {
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

module.exports = {
  execute,
  postDeposit,
  postInterChannel,
  register,
  stableRequestId,
  status,
  syncOffchainHeads,
};
