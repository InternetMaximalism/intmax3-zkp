'use strict';

const assert = require('assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');

const { Transaction, Wallet, getAddress } = require('ethers');
const {
  SignedTransactionOutbox,
  actionFileName,
} = require('../delegate/signed-transaction-outbox');
const {
  assertDelegateSignerIsolation,
  resolveDelegateOutboxPaths,
} = require('../delegate');

const PRIVATE_KEY = `0x${'11'.repeat(32)}`;
const RECIPIENT = '0x1000000000000000000000000000000000000001';
const OTHER_RECIPIENT = '0x2000000000000000000000000000000000000002';
const BLOCK_10 = `0x${'10'.repeat(32)}`;
const BLOCK_12 = `0x${'12'.repeat(32)}`;
const BLOCK_9 = `0x${'09'.repeat(32)}`;

class FakeProvider {
  constructor() {
    this.chainId = 31337n;
    this.pendingNonce = 7;
    this.broadcasts = [];
    this.transactions = new Map();
    this.receipts = new Map();
    this.blocks = new Map([
      [9, { number: 9, hash: BLOCK_9, parentHash: `0x${'08'.repeat(32)}` }],
      [10, { number: 10, hash: BLOCK_10, parentHash: BLOCK_9 }],
      [12, { number: 12, hash: BLOCK_12, parentHash: `0x${'11'.repeat(32)}` }],
    ]);
    this.finalizedNumber = 12;
    // The production devnet fallback mirrors ChainWatcher: durable = latest - confirmations.
    this.latestNumber = 13;
  }

  async getNetwork() { return { chainId: this.chainId }; }
  async getTransactionCount() { return this.pendingNonce; }
  async getFeeData() { return { maxFeePerGas: 100n, maxPriorityFeePerGas: 10n }; }
  async estimateGas() { return 50_000n; }
  async getTransactionReceipt(hash) { return this.receipts.get(String(hash).toLowerCase()) || null; }
  async getTransaction(hash) { return this.transactions.get(String(hash).toLowerCase()) || null; }
  async getBlockNumber() { return this.latestNumber; }
  async getBlock(tag) {
    if (tag === 'finalized') return this.blocks.get(this.finalizedNumber) || null;
    if (tag === 'latest') return this.blocks.get(this.latestNumber) || null;
    return this.blocks.get(Number(tag)) || null;
  }

  async broadcastTransaction(raw) {
    const transaction = Transaction.from(raw);
    const normalized = String(raw).toLowerCase();
    this.broadcasts.push(normalized);
    this.transactions.set(transaction.hash.toLowerCase(), {
      hash: transaction.hash,
      raw: normalized,
      nonce: transaction.nonce,
    });
    return { hash: transaction.hash };
  }

  async waitForTransaction(hash) {
    return this.getTransactionReceipt(hash);
  }

  successfulReceipt(hash, blockNumber = 10, blockHash = BLOCK_10) {
    const receipt = {
      status: 1,
      blockNumber,
      blockHash,
      transactionHash: hash,
      logs: [],
    };
    this.receipts.set(String(hash).toLowerCase(), receipt);
    return receipt;
  }

  failedReceipt(hash, blockNumber = 10, blockHash = BLOCK_10) {
    const receipt = {
      status: 0,
      blockNumber,
      blockHash,
      transactionHash: hash,
      logs: [],
    };
    this.receipts.set(String(hash).toLowerCase(), receipt);
    return receipt;
  }
}

function fixture(t, { provider = new FakeProvider(), hooks = {} } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'intmax-delegate-outbox-test-'));
  fs.chmodSync(root, 0o700);
  const directory = path.join(root, 'outbox');
  const lockRoot = path.join(root, 'locks');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const signer = new Wallet(PRIVATE_KEY);
  const make = (nextHooks = hooks) => new SignedTransactionOutbox({
    directory,
    lockRoot,
    chainId: 31337,
    signer,
    provider,
    confirmations: 1,
    allowUnfinalizedDevnet: true,
    hooks: nextHooks,
  });
  return { root, directory, lockRoot, provider, signer, make, outbox: make() };
}

const request = (actionId = 'action:one') => ({
  actionId,
  to: RECIPIENT,
  data: '0x12345678aabbccdd',
  value: 9n,
});

function recordFor(directory, actionId) {
  return JSON.parse(fs.readFileSync(path.join(directory, actionFileName(actionId)), 'utf8'));
}

function runWorker(directory, lockRoot, actionId, data) {
  const worker = path.join(__dirname, 'fixtures', 'delegate-outbox-worker.js');
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [worker, directory, lockRoot, actionId, data], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code !== 0) { reject(new Error(`outbox worker exited ${code}: ${stderr}`)); return; }
      try { resolve(JSON.parse(stdout.trim())); } catch (error) { reject(error); }
    });
  });
}

test('delegate startup derives both outbox paths and requires explicit Rust-signer isolation', () => {
  const delegate = new Wallet(PRIVATE_KEY).address;
  assert.throws(
    () => resolveDelegateOutboxPaths({ chainId: 31337 }, delegate),
    /l1SignerLockRoot is required/,
  );
  const paths = resolveDelegateOutboxPaths({ chainId: 31337, l1SignerLockRoot: 'private/test-locks' }, delegate);
  assert.ok(path.isAbsolute(paths.lockRoot));
  assert.ok(paths.outboxDirectory.startsWith(`${paths.lockRoot}${path.sep}`));

  assert.throws(
    () => assertDelegateSignerIsolation({}, delegate),
    /rustPublisherSignerAddresses/,
  );
  const peers = {
    publicValidity: RECIPIENT,
    publicClose: OTHER_RECIPIENT,
    closeFunding: '0x3000000000000000000000000000000000000003',
  };
  assert.equal(assertDelegateSignerIsolation({ rustPublisherSignerAddresses: peers }, delegate).publicClose, getAddress(OTHER_RECIPIENT));
  for (const role of Object.keys(peers)) {
    assert.throws(
      () => assertDelegateSignerIsolation({
        rustPublisherSignerAddresses: { ...peers, [role]: delegate },
      }, delegate),
      /must be distinct from Rust/,
    );
  }
});

test('reservation and signing crash boundaries cannot leak an unjournaled broadcast', async (t) => {
  for (const boundary of ['afterReservation', 'afterSign']) {
    // eslint-disable-next-line no-await-in-loop
    await t.test(boundary, async (st) => {
      const marker = new Error(`crash:${boundary}`);
      const f = fixture(st, { hooks: { [boundary]: () => { throw marker; } } });
      await assert.rejects(f.outbox.send(request()), marker);
      assert.equal(f.provider.broadcasts.length, 0);
      assert.equal(fs.readdirSync(f.directory).filter((name) => name.endsWith('.json')).length, 0);

      const reservation = JSON.parse(fs.readFileSync(f.outbox.reservationPath, 'utf8'));
      assert.equal(reservation.schemaVersion, 2);
      assert.equal(reservation.stage, 'intent');
      assert.equal(reservation.transactionHash, null);
      assert.equal(reservation.nonce, 7);
      await assert.rejects(
        f.make({}).send({ ...request('action:sibling'), data: '0xabcdef01' }),
        (error) => error.code === 'OUTBOX_SIGNER_RESERVED',
      );

      const resumed = await f.make({}).send(request());
      assert.equal(resumed.nonce, 7);
      assert.equal(f.provider.broadcasts.length, 1);
    });
  }
});

test('fsync crash leaves mode-0600 exact raw bytes which are the only bytes broadcast on restart', async (t) => {
  const crash = new Error('crash:afterPersist');
  const f = fixture(t, { hooks: { afterPersist: () => { throw crash; } } });
  await assert.rejects(f.outbox.send(request()), crash);
  assert.equal(f.provider.broadcasts.length, 0);

  const file = path.join(f.directory, actionFileName('action:one'));
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  const saved = recordFor(f.directory, 'action:one');
  const raw = saved.attempts[0].rawSignedTransaction;
  const resumed = await f.make({}).send(request());
  assert.equal(f.provider.broadcasts.length, 1);
  assert.equal(f.provider.broadcasts[0], raw);
  assert.equal(resumed.transactionHash, Transaction.from(raw).hash.toLowerCase());
});

test('broadcast crash can only rebroadcast the byte-identical journaled transaction', async (t) => {
  let failOnce = true;
  const f = fixture(t, {
    hooks: {
      afterBroadcast: () => {
        if (failOnce) {
          failOnce = false;
          throw new Error('crash:afterBroadcast');
        }
      },
    },
  });
  await assert.rejects(f.outbox.send(request()), /crash:afterBroadcast/);
  assert.equal(f.provider.broadcasts.length, 1);
  const firstRaw = f.provider.broadcasts[0];

  // Model an RPC that forgot its mempool after the delegate died. The restart may rebroadcast,
  // but it has no signing path for a different transaction at this action/nonce.
  f.provider.transactions.clear();
  const resumed = await f.make({}).send(request());
  assert.equal(f.provider.broadcasts.length, 2);
  assert.equal(f.provider.broadcasts[1], firstRaw);
  assert.equal(resumed.nonce, 7);
  assert.equal(recordFor(f.directory, 'action:one').attempts.length, 1);
});

test('receipt crash is reconciled under the same hash and terminalizes only after expected finalized state', async (t) => {
  const f = fixture(t);
  const sent = await f.outbox.send(request());
  f.provider.successfulReceipt(sent.transactionHash);
  const crashing = f.make({ afterReceipt: () => { throw new Error('crash:afterReceipt'); } });
  await assert.rejects(crashing.waitForReceipt('action:one'), /crash:afterReceipt/);
  assert.equal(recordFor(f.directory, 'action:one').terminal, null);

  const receipt = await f.make({}).waitForReceipt('action:one');
  assert.equal(receipt.transactionHash, sent.transactionHash);
  const status = await f.make({}).markFinalized(
    'action:one',
    { transactionHash: sent.transactionHash, blockNumber: 10, blockHash: BLOCK_10 },
    async ({ blockTag, transactionHash }) => blockTag === 10 && transactionHash === sent.transactionHash,
  );
  assert.equal(status.phase, 'terminal');
  assert.equal(status.transactionHash, sent.transactionHash);
  assert.equal(Object.prototype.hasOwnProperty.call(status, 'rawSignedTransaction'), false);
});

test('restart completes a crash between terminal journal fsync and signer-lease release', async (t) => {
  const f = fixture(t);
  const sent = await f.outbox.send(request());
  f.provider.successfulReceipt(sent.transactionHash);
  const observation = { transactionHash: sent.transactionHash, blockNumber: 10, blockHash: BLOCK_10 };
  const crashing = f.make({ afterTerminalPersist: () => { throw new Error('crash:terminal-fsync'); } });
  await assert.rejects(
    crashing.markFinalized('action:one', observation, async () => true),
    /crash:terminal-fsync/,
  );
  assert.equal(f.outbox.status('action:one').phase, 'terminal');
  assert.ok(fs.existsSync(f.outbox.reservationPath));

  await f.make({}).markFinalized('action:one', observation, async () => true);
  assert.equal(fs.existsSync(f.outbox.reservationPath), false);
});

test('one action is permanently bound to chain, signer, target, calldata hash and value', async (t) => {
  const f = fixture(t);
  const sent = await f.outbox.send(request());
  const variants = [
    { ...request(), to: OTHER_RECIPIENT },
    { ...request(), data: '0x12345678aabbccde' },
    { ...request(), value: 10n },
  ];
  for (const variant of variants) {
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(f.outbox.send(variant), (error) => error.code === 'OUTBOX_INTENT_MISMATCH');
  }
  assert.equal(f.provider.broadcasts.length, 1);
  assert.equal(f.outbox.status('action:one').transactionHash, sent.transactionHash);
});

test('persistent signer lease blocks a second semantic action until finalized terminal state', async (t) => {
  const f = fixture(t);
  const sibling = f.make({});
  const attempts = await Promise.allSettled([
    f.outbox.send(request('action:a')),
    sibling.send({ ...request('action:b'), data: '0xabcdef01' }),
  ]);
  const succeeded = attempts.filter((result) => result.status === 'fulfilled');
  const blocked = attempts.filter((result) => result.status === 'rejected');
  assert.equal(succeeded.length, 1);
  assert.equal(blocked.length, 1);
  assert.equal(blocked[0].reason.code, 'OUTBOX_SIGNER_RESERVED');
  assert.equal(f.provider.broadcasts.length, 1);

  const winner = succeeded[0].value;
  const winnerAction = attempts[0].status === 'fulfilled' ? 'action:a' : 'action:b';
  const loserRequest = winnerAction === 'action:a'
    ? { ...request('action:b'), data: '0xabcdef01' }
    : request('action:a');
  f.provider.successfulReceipt(winner.transactionHash);
  await f.outbox.markFinalized(
    winnerAction,
    { transactionHash: winner.transactionHash, blockNumber: 10, blockHash: BLOCK_10 },
    async () => true,
  );
  const resumed = await sibling.send(loserRequest);
  assert.equal(resumed.nonce, 8);
  assert.equal(f.provider.broadcasts.length, 2);
});

test('separate Node processes contend on the same signer mutex and persistent lease', async (t) => {
  const f = fixture(t);
  const [a, b] = await Promise.all([
    runWorker(f.directory, f.lockRoot, 'process:a', '0xaaaaaaaa'),
    runWorker(f.directory, f.lockRoot, 'process:b', '0xbbbbbbbb'),
  ]);
  const sent = [a, b].filter((result) => result.transactionHash);
  const blocked = [a, b].filter((result) => result.code === 'OUTBOX_SIGNER_RESERVED');
  assert.equal(sent.length, 1, JSON.stringify([a, b]));
  assert.equal(sent[0].nonce, 4);
  assert.equal(blocked.length, 1);
});

test('canonical signer lock namespace is shared and the journal rejects a different lock root', async (t) => {
  let inspected = false;
  const f = fixture(t, {
    hooks: {
      afterReservation: () => {
        const expected = path.join(
          f.lockRoot,
          `.intmax-l1-signer-31337-${f.signer.address.slice(2).toLowerCase()}.lock`,
        );
        const metadata = fs.lstatSync(expected);
        assert.ok(metadata.isDirectory());
        assert.equal(metadata.mode & 0o777, 0o700);
        assert.equal(fs.statSync(path.join(expected, 'owner.json')).mode & 0o777, 0o600);
        inspected = true;
      },
    },
  });
  const sent = await f.outbox.send(request());
  assert.equal(inspected, true);
  const reservation = path.join(
    f.lockRoot,
    `.intmax-l1-signer-31337-${f.signer.address.slice(2).toLowerCase()}.reservation.json`,
  );
  const lease = JSON.parse(fs.readFileSync(reservation, 'utf8'));
  assert.equal(fs.statSync(reservation).mode & 0o777, 0o600);
  assert.equal(lease.chainId, '31337');
  assert.equal(getAddress(lease.signer), getAddress(f.signer.address));
  assert.equal(lease.transactionHash, sent.transactionHash);
  assert.equal(Object.prototype.hasOwnProperty.call(lease, 'rawSignedTransaction'), false);

  const otherRoot = path.join(f.root, 'other-lock-root');
  const wrongRoot = new SignedTransactionOutbox({
    directory: f.directory,
    lockRoot: otherRoot,
    chainId: 31337,
    signer: f.signer,
    provider: f.provider,
    allowUnfinalizedDevnet: true,
  });
  await assert.rejects(
    wrongRoot.send(request()),
    (error) => error.code === 'OUTBOX_LOCK_ROOT_MISMATCH',
  );
  assert.equal(f.outbox.status('action:one').transactionHash, sent.transactionHash);
  assert.equal(f.provider.broadcasts.length, 1);
});

test('signer lock reclaims only a well-formed same-host dead owner', async (t) => {
  const f = fixture(t);
  const lockPath = path.join(
    f.lockRoot,
    `.intmax-l1-signer-31337-${f.signer.address.slice(2).toLowerCase()}.lock`,
  );
  fs.mkdirSync(lockPath, { mode: 0o700 });
  fs.writeFileSync(path.join(lockPath, 'owner.json'), JSON.stringify({
    schemaVersion: 1,
    hostname: os.hostname(),
    pid: 2_000_000_000,
    token: `0x${'ab'.repeat(32)}`,
  }), { mode: 0o600 });
  const sent = await f.outbox.send(request());
  assert.equal(sent.nonce, 7);
  assert.equal(fs.existsSync(lockPath), false);

  const malformedAction = request('action:malformed-lock');
  fs.mkdirSync(lockPath, { mode: 0o700 });
  fs.writeFileSync(path.join(lockPath, 'owner.json'), '{not-json', { mode: 0o600 });
  await assert.rejects(
    f.outbox.send(malformedAction),
    (error) => error.code === 'OUTBOX_CORRUPT_RECORD',
  );
  assert.equal(f.provider.broadcasts.length, 1);
});

test('remote-owner, symlink, and non-Node signer locks fail closed', async (t) => {
  await t.test('remote owner', async (st) => {
    const f = fixture(st);
    const lockPath = path.join(
      f.lockRoot,
      `.intmax-l1-signer-31337-${f.signer.address.slice(2).toLowerCase()}.lock`,
    );
    fs.mkdirSync(lockPath, { mode: 0o700 });
    fs.writeFileSync(path.join(lockPath, 'owner.json'), JSON.stringify({
      schemaVersion: 1,
      hostname: 'different-host.invalid',
      pid: 2_000_000_000,
      token: `0x${'cd'.repeat(32)}`,
    }), { mode: 0o600 });
    await assert.rejects(
      f.outbox.send(request()),
      (error) => error.code === 'OUTBOX_AMBIGUOUS_LOCK',
    );
    assert.equal(f.provider.broadcasts.length, 0);
  });

  await t.test('symlink', async (st) => {
    const f = fixture(st);
    const lockPath = path.join(
      f.lockRoot,
      `.intmax-l1-signer-31337-${f.signer.address.slice(2).toLowerCase()}.lock`,
    );
    const target = path.join(f.root, 'foreign-lock');
    fs.mkdirSync(target, { mode: 0o700 });
    fs.writeFileSync(path.join(target, 'owner.json'), JSON.stringify({
      schemaVersion: 1,
      hostname: os.hostname(),
      pid: process.pid,
      token: `0x${'ef'.repeat(32)}`,
    }), { mode: 0o600 });
    fs.symlinkSync(target, lockPath);
    await assert.rejects(
      f.outbox.send(request()),
      (error) => error.code === 'OUTBOX_AMBIGUOUS_LOCK',
    );
    assert.equal(f.provider.broadcasts.length, 0);
  });

  await t.test('regular file used by a non-Node locker', async (st) => {
    const f = fixture(st);
    const lockPath = path.join(
      f.lockRoot,
      `.intmax-l1-signer-31337-${f.signer.address.slice(2).toLowerCase()}.lock`,
    );
    fs.writeFileSync(lockPath, '', { mode: 0o600 });
    await assert.rejects(
      f.outbox.send(request()),
      (error) => error.code === 'OUTBOX_AMBIGUOUS_LOCK',
    );
    assert.equal(f.provider.broadcasts.length, 0);
  });
});

test('an incompatible cross-language reservation is detected rather than treated as shared', async (t) => {
  const f = fixture(t);
  const reservationPath = path.join(
    f.lockRoot,
    `.intmax-l1-signer-31337-${f.signer.address.slice(2).toLowerCase()}.reservation.json`,
  );
  // Current Rust publisher reservations deliberately have a distinct schema. Production prevents
  // this collision with signer isolation; if configuration is wrong, Node must stop, not guess.
  fs.writeFileSync(reservationPath, JSON.stringify({
    schemaVersion: 1,
    chainId: 31337,
    signer: f.signer.address.toLowerCase(),
    ownerKind: 'public-validity',
    journalPath: '/private/rust-journal.json',
    phase: 'broadcast',
    intentHash: `0x${'22'.repeat(32)}`,
  }), { mode: 0o600 });
  await assert.rejects(
    f.outbox.send(request()),
    (error) => error.code === 'OUTBOX_CORRUPT_RESERVATION',
  );
  assert.equal(f.provider.broadcasts.length, 0);
});

test('failed receipt replacement is explicit, same-effect, and bumps both fee caps', async (t) => {
  const f = fixture(t);
  const first = await f.outbox.send(request());
  f.provider.failedReceipt(first.transactionHash);
  await assert.rejects(
    f.outbox.send(request()),
    (error) => error.code === 'OUTBOX_REPLACEMENT_REQUIRED',
  );
  await assert.rejects(
    f.outbox.send({
      ...request(),
      replacement: { reason: 'operator reviewed revert', maxFeePerGas: 109n, maxPriorityFeePerGas: 11n },
    }),
    (error) => error.code === 'OUTBOX_REPLACEMENT_FEE_TOO_LOW',
  );
  const replacement = await f.outbox.send({
    ...request(),
    replacement: { reason: 'operator reviewed revert', maxFeePerGas: 110n, maxPriorityFeePerGas: 11n },
  });
  const saved = recordFor(f.directory, 'action:one');
  assert.equal(saved.attempts.length, 2);
  assert.equal(replacement.nonce, 8);
  const oldTx = Transaction.from(saved.attempts[0].rawSignedTransaction);
  const newTx = Transaction.from(saved.attempts[1].rawSignedTransaction);
  assert.equal(getAddress(newTx.to), getAddress(oldTx.to));
  assert.equal(newTx.data, oldTx.data);
  assert.equal(newTx.value, oldTx.value);
  assert.equal(newTx.gasLimit, oldTx.gasLimit);
  assert.ok(newTx.maxFeePerGas >= oldTx.maxFeePerGas * 110n / 100n);
  assert.ok(newTx.maxPriorityFeePerGas >= oldTx.maxPriorityFeePerGas * 110n / 100n);
});

test('interrupted fresh-nonce replacement cannot overwrite its durable nonce after external consumption', async (t) => {
  const f = fixture(t);
  const first = await f.outbox.send(request());
  f.provider.failedReceipt(first.transactionHash);
  const replacement = {
    reason: 'operator reviewed finalized revert',
    maxFeePerGas: 110n,
    maxPriorityFeePerGas: 11n,
  };
  let crashOnce = true;
  const crashing = f.make({
    afterReservation: ({ replacement: isReplacement }) => {
      if (isReplacement && crashOnce) {
        crashOnce = false;
        throw new Error('crash:fresh-nonce-reservation');
      }
    },
  });
  await assert.rejects(
    crashing.send({ ...request(), replacement }),
    /crash:fresh-nonce-reservation/,
  );

  const before = fs.readFileSync(crashing.reservationPath, 'utf8');
  const reservation = JSON.parse(before);
  assert.equal(reservation.stage, 'intent');
  assert.equal(reservation.nonce, 8);
  assert.equal(reservation.previousTransactionHash, first.transactionHash);

  // Simulate a nonconforming/out-of-band signer advancing the RPC pending nonce while this
  // process was down.  There may already be unjournaled raw bytes at nonce 8, so nonce 9 is not a
  // safe automatic substitute and the original reservation must remain byte-identical.
  f.provider.pendingNonce = 9;
  await assert.rejects(
    f.make({}).send({ ...request(), replacement }),
    (error) => error.code === 'OUTBOX_RESERVATION_NONCE_MISMATCH'
      && error.details.reservedNonce === 8
      && error.details.computedNonce === 9,
  );
  assert.equal(fs.readFileSync(crashing.reservationPath, 'utf8'), before);
  assert.equal(recordFor(f.directory, 'action:one').attempts.length, 1);
  assert.equal(f.provider.broadcasts.length, 1);
});

test('explicit pending/drop replacement preserves nonce while finalized revert replacement advances it', async (t) => {
  const f = fixture(t);
  const first = await f.outbox.send(request());
  const pendingReplacement = await f.outbox.send({
    ...request(),
    replacement: { reason: 'operator fee bump for dropped tx', maxFeePerGas: 110n, maxPriorityFeePerGas: 11n },
  });
  assert.equal(pendingReplacement.nonce, first.nonce);
  let saved = recordFor(f.directory, 'action:one');
  assert.equal(saved.attempts.length, 2);
  assert.equal(saved.attempts[0].nonce, saved.attempts[1].nonce);

  f.provider.failedReceipt(pendingReplacement.transactionHash, 13, `0x${'13'.repeat(32)}`);
  await assert.rejects(
    f.outbox.send({
      ...request(),
      replacement: { reason: 'unfinalized revert', maxFeePerGas: 121n, maxPriorityFeePerGas: 13n },
    }),
    (error) => error.code === 'OUTBOX_FAILED_RECEIPT_NOT_FINALIZED',
  );

  f.provider.blocks.set(13, { number: 13, hash: `0x${'13'.repeat(32)}`, parentHash: BLOCK_12 });
  f.provider.latestNumber = 14;
  const postRevert = await f.outbox.send({
    ...request(),
    replacement: { reason: 'finalized revert reviewed', maxFeePerGas: 121n, maxPriorityFeePerGas: 13n },
  });
  assert.equal(postRevert.nonce, first.nonce + 1);
  saved = recordFor(f.directory, 'action:one');
  assert.equal(saved.attempts.length, 3);
});

test('an older same-nonce raw transaction that wins after a fee bump is reconciled and terminalized', async (t) => {
  const f = fixture(t);
  const first = await f.outbox.send(request());
  const replacement = await f.outbox.send({
    ...request(),
    replacement: { reason: 'operator fee bump for pending tx', maxFeePerGas: 110n, maxPriorityFeePerGas: 11n },
  });
  assert.equal(replacement.nonce, first.nonce);
  assert.notEqual(replacement.transactionHash, first.transactionHash);

  // The original raw bytes can still beat the replacement into a block. Restart/retry must select
  // that exact journaled attempt and must not rebroadcast or manufacture another transaction.
  f.provider.successfulReceipt(first.transactionHash);
  const resumed = await f.make().send(request());
  assert.equal(resumed.phase, 'mined');
  assert.equal(resumed.transactionHash, first.transactionHash);
  assert.deepEqual(resumed.transactionHashes, [first.transactionHash, replacement.transactionHash]);
  assert.equal(f.provider.broadcasts.length, 2);
  assert.equal(f.outbox.hasAttempt('action:one', first.transactionHash), true);
  assert.equal(f.outbox.hasAttempt('action:one', `0x${'ff'.repeat(32)}`), false);

  const receipt = await f.outbox.waitForReceipt('action:one');
  assert.equal(receipt.transactionHash, first.transactionHash);
  const terminal = await f.outbox.markFinalized(
    'action:one',
    { transactionHash: first.transactionHash, blockNumber: 10, blockHash: BLOCK_10 },
    async () => true,
  );
  assert.equal(terminal.transactionHash, first.transactionHash);
  assert.equal(terminal.phase, 'terminal');
});

test('resumeExact abandons only an initial intent with no raw WAL and unblocks the sibling nonce lane', async (t) => {
  const f = fixture(t, {
    hooks: { afterReservation: () => { throw new Error('crash:before-raw-wal'); } },
  });
  await assert.rejects(f.outbox.send(request()), /crash:before-raw-wal/);
  assert.equal(f.outbox.status('action:one'), null);
  assert.ok(fs.existsSync(f.outbox.reservationPath));

  const resumed = await f.make({}).resumeExact('action:one');
  assert.equal(resumed.phase, 'absent');
  assert.equal(fs.existsSync(f.outbox.reservationPath), false);
  const sibling = await f.make({}).send({ ...request('action:sibling'), data: '0xaabbccdd' });
  assert.equal(sibling.nonce, 7);
});

test('intent-only crash accepts protocol progress only from an exact finalized semantic receipt', async (t) => {
  const f = fixture(t, {
    hooks: { afterReservation: () => { throw new Error('crash:before-raw-wal'); } },
  });
  await assert.rejects(f.outbox.send(request()), /crash:before-raw-wal/);
  const foreignHash = `0x${'ac'.repeat(32)}`;
  f.provider.receipts.set(foreignHash, {
    status: 1,
    blockNumber: 10,
    blockHash: BLOCK_10,
    transactionHash: foreignHash,
    logs: [{ index: 6, marker: 'semantic-only-winner' }],
  });
  const recovered = f.make({});
  let checked = 0;
  const result = await recovered.settleSuperseded(
    'action:one',
    { transactionHash: foreignHash, blockNumber: 10, blockHash: BLOCK_10, logIndex: 6 },
    async () => { throw new Error('there is no local raw receipt'); },
    async ({ blockTag, receipt, transactionHash, logIndex }) => {
      checked += 1;
      return blockTag === 10
        && receipt.logs[0].marker === 'semantic-only-winner'
        && transactionHash === foreignHash
        && logIndex === 6;
    },
  );
  assert.equal(result.phase, 'absent');
  assert.equal(result.semanticVerified, true);
  assert.equal(result.semanticEvidence.semanticTransactionHash, foreignHash);
  assert.equal(checked, 1);
  assert.equal(fs.existsSync(recovered.reservationPath), false);
});

test('superseded action releases its signer lease only after exact local revert and canonical event evidence', async (t) => {
  const f = fixture(t);
  const sent = await f.outbox.send(request());
  f.provider.failedReceipt(sent.transactionHash);
  const foreignHash = `0x${'ab'.repeat(32)}`;
  f.provider.receipts.set(foreignHash, {
    status: 1,
    blockNumber: 10,
    blockHash: BLOCK_10,
    transactionHash: foreignHash,
    logs: [{ index: 4, marker: 'exact-foreign-event' }],
  });
  const semantic = {
    transactionHash: foreignHash,
    blockNumber: 10,
    blockHash: BLOCK_10,
    logIndex: 4,
  };
  let checked = 0;
  const terminal = await f.outbox.settleSuperseded(
    'action:one',
    semantic,
    async () => false,
    async ({ blockTag, receipt, transactionHash, logIndex }) => {
      checked += 1;
      return blockTag === 10
        && receipt.logs[0].marker === 'exact-foreign-event'
        && transactionHash === foreignHash
        && logIndex === 4;
    },
  );
  assert.equal(checked, 1);
  assert.equal(terminal.phase, 'terminal');
  assert.equal(terminal.terminal.outcome, 'superseded-revert');
  assert.equal(terminal.terminal.semanticTransactionHash, foreignHash);
  assert.equal(terminal.terminal.semanticLogIndex, 4);
  assert.equal(fs.existsSync(f.outbox.reservationPath), false);

  const sibling = await f.outbox.send({ ...request('action:sibling'), data: '0x01020304' });
  assert.equal(sibling.nonce, 8);
});

test('reorged semantic evidence and terminal-WAL crash both preserve exact nonce safety', async (t) => {
  await t.test('same-height semantic reorg keeps the lease and replays only the old raw', async (st) => {
    const f = fixture(st);
    const sent = await f.outbox.send(request());
    f.provider.failedReceipt(sent.transactionHash);
    const foreignHash = `0x${'bc'.repeat(32)}`;
    f.provider.receipts.set(foreignHash, {
      status: 1,
      blockNumber: 10,
      blockHash: BLOCK_10,
      transactionHash: foreignHash,
      logs: [],
    });
    f.provider.blocks.set(10, { number: 10, hash: `0x${'ef'.repeat(32)}`, parentHash: BLOCK_9 });
    await assert.rejects(
      f.outbox.settleSuperseded(
        'action:one',
        { transactionHash: foreignHash, blockNumber: 10, blockHash: BLOCK_10, logIndex: 1 },
        async () => false,
        async () => true,
      ),
      (error) => error.code === 'OUTBOX_SUPERSEDED_EVIDENCE_REORGED',
    );
    assert.ok(fs.existsSync(f.outbox.reservationPath));
    await assert.rejects(
      f.outbox.send({ ...request('action:sibling'), data: '0x01020304' }),
      (error) => error.code === 'OUTBOX_SIGNER_RESERVED',
    );
  });

  await t.test('restart finishes lease cleanup after superseded terminal fsync', async (st) => {
    let crash = true;
    const f = fixture(st, {
      hooks: {
        afterTerminalPersist: ({ outcome }) => {
          if (outcome === 'superseded-revert' && crash) {
            crash = false;
            throw new Error('crash:after-superseded-terminal');
          }
        },
      },
    });
    const sent = await f.outbox.send(request());
    f.provider.failedReceipt(sent.transactionHash);
    const foreignHash = `0x${'cd'.repeat(32)}`;
    f.provider.receipts.set(foreignHash, {
      status: 1,
      blockNumber: 10,
      blockHash: BLOCK_10,
      transactionHash: foreignHash,
      logs: [],
    });
    await assert.rejects(
      f.outbox.settleSuperseded(
        'action:one',
        { transactionHash: foreignHash, blockNumber: 10, blockHash: BLOCK_10, logIndex: 0 },
        async () => false,
        async () => true,
      ),
      /crash:after-superseded-terminal/,
    );
    assert.equal(f.outbox.status('action:one').phase, 'terminal');
    assert.ok(fs.existsSync(f.outbox.reservationPath));
    const recovered = await f.make({}).resumeExact('action:one');
    assert.equal(recovered.phase, 'terminal');
    assert.equal(fs.existsSync(f.outbox.reservationPath), false);
  });
});

test('terminalization rejects wrong receipt blocks, missing effects, and reorged durable checkpoints', async (t) => {
  await t.test('wrong observation', async (st) => {
    const f = fixture(st);
    const sent = await f.outbox.send(request());
    f.provider.successfulReceipt(sent.transactionHash);
    await assert.rejects(
      f.outbox.markFinalized(
        'action:one',
        { transactionHash: sent.transactionHash, blockNumber: 10, blockHash: BLOCK_12 },
        async () => true,
      ),
      (error) => error.code === 'OUTBOX_OBSERVATION_MISMATCH',
    );
  });

  await t.test('expected transition missing', async (st) => {
    const f = fixture(st);
    const sent = await f.outbox.send(request());
    f.provider.successfulReceipt(sent.transactionHash);
    await assert.rejects(
      f.outbox.markFinalized(
        'action:one',
        { transactionHash: sent.transactionHash, blockNumber: 10, blockHash: BLOCK_10 },
        async () => false,
      ),
      (error) => error.code === 'OUTBOX_EXPECTED_TRANSITION_MISSING',
    );
  });

  await t.test('durable checkpoint changes during verification', async (st) => {
    const f = fixture(st);
    const sent = await f.outbox.send(request());
    f.provider.successfulReceipt(sent.transactionHash);
    await assert.rejects(
      f.outbox.markFinalized(
        'action:one',
        { transactionHash: sent.transactionHash, blockNumber: 10, blockHash: BLOCK_10 },
        async () => {
          f.provider.blocks.set(12, { number: 12, hash: `0x${'ff'.repeat(32)}`, parentHash: `0x${'11'.repeat(32)}` });
          return true;
        },
      ),
      (error) => error.code === 'OUTBOX_FINALIZED_HEAD_CHANGED',
    );
    assert.equal(f.outbox.status('action:one').terminal, null);
  });
});
