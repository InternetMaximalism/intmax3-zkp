'use strict';
// L1 deposit sequencer for a relay on a PUBLIC chain.
//
// WHY. The block producer consumes the rollup's L1 deposits strictly in deposit-index order
// ("L1 deposit index k is stale or skipped; producer expects j"), for every channel on the rollup
// at once, and a channel's live balance accepts a producer receipt only if it is newer than the
// last transition it applied. Leaving each import to the depositor's own browser therefore broke
// a multi-user deployment twice over: one deposit whose browser went away blocked every later
// import on the rollup, and a deposit journaled but not received by its channel before that
// channel moved on could never be credited at all. Both were reproduced on the public-chain
// rehearsal before this module existed.
//
// WHAT. Deposits are consumed here, in index order, as soon as they are reorg-safe, regardless of
// who is online:
//   * a deposit to one of this relay's channels is imported into that channel at once, crediting
//     the slot whose bound (B-1b) exit address is the depositor — the same rule as the CLI's
//     `auto` slot. A depositor bound to no slot cannot be credited to anyone's slot; its deposit is
//     held in the channel's OPERATOR delegate slot (the delegate bootstrap-real-chain.js creates
//     with the genesis) so the funds stay recoverable, and the outcome records it for a refund.
//   * a deposit to any other recipient is only journaled into the producer's sequence.
// The browser's import request just runs the sequencer through its own deposit and reports the
// recorded outcome. Every economic value still comes from the CLI's on-chain verification.
const fs = require('fs');
const path = require('path');
const cli = require('./cli');
const producer = require('./block-producer');
const { importL1Deposit } = require('./deposit-pipeline');

const DEPOSITED_TOPIC0 = '0x35cffad0c6ce159deaf160c503b69a374a9751e480083db7e6849e00f1a2c4fe';
// The CLI's reorg-safety depth off the local devnet (`DEFAULT_MIN_CONFIRMATIONS`).
const MIN_CONFIRMATIONS = 12;
const LOG_WINDOW = Number(process.env.L1_LOG_WINDOW_BLOCKS || 50000);
const RANGE_REFUSAL = /block range|range.*(exceed|too (large|wide|big))|exceed.*range|too many (blocks|results)|more than \d+ results|response size|limit exceeded/i;

const STATE_FILE = () => path.join(cli.WORK, 'producer', 'deposit-sequencer.json');

function rpc(method, params) {
  return JSON.parse(cli.sh('cast', ['rpc', method, ...params.map(p => (typeof p === 'string' ? p : JSON.stringify(p))), '--rpc-url', cli.RPC], { stdio: 'pipe' }));
}
const hex = n => '0x' + n.toString(16);
const num = value => Number(BigInt(value));

function readState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE(), 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; return null; }
}
function writeState(state) {
  fs.mkdirSync(path.dirname(STATE_FILE()), { recursive: true, mode: 0o700 });
  const temp = STATE_FILE() + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(state), { mode: 0o600 });
  fs.renameSync(temp, STATE_FILE());
}

// The first block holding the rollup's code: no Deposited log can be older.
function deploymentBlock(rollup, head) {
  let low = 0, high = head;
  while (low < high) {
    const mid = Math.floor((low + high) / 2);
    if (rpc('eth_getCode', [rollup, hex(mid)]) === '0x') low = mid + 1; else high = mid;
  }
  return low;
}

function channelsByRecipient() {
  const map = new Map();
  for (const ch of cli.CHANNELS) {
    const file = cli.wc(ch, 'channel_backing.json');
    if (!fs.existsSync(file)) continue;
    const backing = cli.readJson(file);
    if (backing.deposit_recipient) map.set(String(backing.deposit_recipient).toLowerCase(), ch);
  }
  return map;
}

function rollupAddress() {
  const rollups = new Set(cli.CHANNELS.filter(ch => fs.existsSync(cli.wc(ch, 'channel_backing.json')))
    .map(ch => String(cli.rollupOf(ch)).toLowerCase()));
  if (rollups.size !== 1) throw new Error(`the relay's channels must share one rollup (found ${rollups.size})`);
  return [...rollups][0];
}

// Record every reorg-safe Deposited log from the cursor on, paging within the RPC's range cap.
function scan(state, head) {
  const safeHead = head - (MIN_CONFIRMATIONS - 1);
  let window = LOG_WINDOW;
  while (state.scanFrom <= safeHead) {
    const to = Math.min(safeHead, state.scanFrom + window - 1);
    let logs;
    try {
      logs = rpc('eth_getLogs', [{ address: state.rollup, fromBlock: hex(state.scanFrom), toBlock: hex(to), topics: [DEPOSITED_TOPIC0] }]);
    } catch (error) {
      const text = String((error && (error.stderr || error.message)) || error);
      if (window === 1 || !RANGE_REFUSAL.test(text)) throw error;
      window = Math.max(1, Math.floor(window / 2));
      continue;
    }
    for (const log of logs) {
      if (log.removed) throw new Error('RPC returned a removed Deposited log inside the reorg-safe range');
      const body = String(log.data).replace(/^0x/, '');
      const index = num(log.topics[1]);
      state.pending[index] = {
        index,
        txHash: log.transactionHash,
        blockNumber: num(log.blockNumber),
        depositor: '0x' + body.slice(24, 64).toLowerCase(),
        recipient: '0x' + body.slice(64, 128).toLowerCase(),
      };
    }
    state.scanFrom = to + 1;
  }
}

// Slots whose bound exit address is the depositor, among the ACTIVE participants.
function boundSlots(snapshot, depositor) {
  const balance = snapshot.state.balanceState;
  const active = Number(balance.memberCount) + Number(balance.delegateCount);
  const recipients = balance.recipients || [];
  const slots = [];
  for (let slot = 0; slot < active; slot++) {
    if (String(recipients[slot] || '').toLowerCase() === depositor) slots.push(slot);
  }
  return slots;
}

// Journal one deposit into the producer's sequence without crediting any channel. Every
// deposit must end up journaled, credited or not, or every later deposit on the rollup stalls.
async function journal(entry, withLock) {
  const ch = cli.CHANNELS.find(c => fs.existsSync(cli.wc(c, 'channel_backing.json')));
  await withLock(ch, async () => {
    cli.cli(ch, ['inspect-l1-deposit', entry.txHash, cli.RPC, 'sequencer_deposit.json', '--journal-only', String(entry.index)]);
    await producer.postDeposit(cli.readJson(cli.wc(ch, 'sequencer_deposit.json')));
  });
}

async function consumed(index) {
  return Number((await producer.status()).nextDepositIndex) > index;
}

// Refusals by the CLI's inspection of the deposit itself: retrying cannot change them. Everything
// else (RPC, confirmations seen through a lagging node, a busy daemon) is retried, so a transient
// failure never leaves a user's deposit journaled without its credit.
const DETERMINISTIC_REFUSAL = /refusing to guess which one to import|exceeds u64|exceeds u32/;

// Credit a deposit to one of this relay's channels. Returns the outcome, or throws to retry.
async function credit(ch, entry, withLock) {
  return withLock(ch, async () => {
    const snapshot = cli.readJson(cli.wc(ch, 'channel_snapshot.json'));
    const slots = boundSlots(snapshot, entry.depositor);
    if (slots.length > 1) {
      // A duplicated exit address makes the owner ambiguous; the CLI refuses it too.
      return { index: entry.index, channel: ch, error: `depositor ${entry.depositor} is the exit address of several slots (${slots.join(',')})` };
    }
    let slot = slots[0], custody = false;
    if (slots.length === 0) {
      const balance = snapshot.state.balanceState;
      if (Number(balance.delegateCount) < 1) {
        return { index: entry.index, channel: ch, error: `depositor ${entry.depositor} is bound to no slot and the channel has no operator delegate` };
      }
      slot = Number(balance.memberCount);
      custody = true;
      console.error(`[deposit-sequencer] deposit #${entry.index} ${entry.txHash} to channel ${ch} is from `
        + `${entry.depositor}, bound to no slot: held in the operator delegate slot ${slot} for a refund`);
    }
    try {
      await importL1Deposit(ch, slot, entry.txHash, { allowUnboundDepositor: custody });
      return { index: entry.index, channel: ch, slot, custody };
    } catch (error) {
      const text = String((error && (error.stderr || error.message)) || error);
      if (!(await consumed(entry.index))) {
        if (!DETERMINISTIC_REFUSAL.test(text)) throw error;
      } else {
        // Journaled. If the channel already received it, the import must be finished, never
        // abandoned: its live balance is ahead of the signed head until then.
        if ((await producer.liveStatus(ch)).awaitingChannelBinding) throw error;
      }
      return { index: entry.index, channel: ch, error: text.slice(0, 2000) };
    }
  });
}

let running = Promise.resolve();

// Consume every reorg-safe deposit the producer is waiting for, in order. Serialized.
function run(withLock) {
  const pass = running.then(async () => {
    let state = readState();
    const rollup = rollupAddress();
    const head = num(rpc('eth_blockNumber', []));
    if (!state || state.rollup !== rollup) {
      state = { rollup, scanFrom: deploymentBlock(rollup, head), pending: {}, outcomes: {} };
    }
    scan(state, head);
    writeState(state);
    const recipients = channelsByRecipient();
    for (;;) {
      const next = Number((await producer.status()).nextDepositIndex);
      for (const index of Object.keys(state.pending)) if (Number(index) < next) delete state.pending[index];
      const entry = state.pending[next];
      if (!entry) break;
      const ch = recipients.get(entry.recipient);
      const outcome = ch === undefined ? { index: next, journaled: true } : await credit(ch, entry, withLock);
      if (outcome.error) {
        console.error(`[deposit-sequencer] deposit #${next} ${entry.txHash} is not credited: ${outcome.error}`);
      }
      if (!(await consumed(next))) await journal(entry, withLock);
      if (!(await consumed(next))) throw new Error(`deposit #${next} was processed but the producer did not consume it`);
      state.outcomes[entry.txHash.toLowerCase()] = { ...outcome, at: Date.now() };
      delete state.pending[next];
      writeState(state);
    }
    return state;
  });
  running = pass.catch(() => {});
  return pass;
}

// The browser's import: consume the sequence through this deposit, then report what happened
// to it. While it is not yet reorg-safe, answer with the CLI's own confirmation refusal so the
// wallet keeps waiting instead of failing.
async function importThrough(ch, txHash, withLock) {
  const key = String(txHash).toLowerCase();
  const receipt = rpc('eth_getTransactionReceipt', [txHash]);
  if (!receipt) throw new Error(`deposit tx ${txHash} is not mined yet (no blockNumber)`);
  if (receipt.status !== '0x1') throw new Error(`deposit tx ${txHash} did not succeed (status ${receipt.status})`);
  const head = num(rpc('eth_blockNumber', []));
  const confirmations = head - num(receipt.blockNumber) + 1;
  if (confirmations < MIN_CONFIRMATIONS) {
    throw new Error(`deposit tx ${txHash} has ${confirmations} confirmation(s), need ${MIN_CONFIRMATIONS} on chain ${cli.chainId()} (reorg safety) — refusing`);
  }
  const state = await run(withLock);
  const outcome = state.outcomes[key];
  if (!outcome) {
    const log = (receipt.logs || []).find(l => String(l.address).toLowerCase() === state.rollup
      && String(l.topics && l.topics[0]).toLowerCase() === DEPOSITED_TOPIC0);
    if (!log) throw new Error(`tx ${txHash} is not a deposit to this relay's rollup`);
    const index = num(log.topics[1]);
    if (index >= Number((await producer.status()).nextDepositIndex)) {
      throw new Error(`deposit #${index} is queued behind earlier deposits; retry shortly`);
    }
    // Consumed before this relay recorded outcomes (an earlier import path): the channel state
    // is the authority.
    return { channel: ch, legacy: true };
  }
  if (outcome.error) throw new Error(`deposit ${txHash} was not credited: ${outcome.error}`);
  if (outcome.journaled || outcome.channel !== ch) {
    throw new Error(`deposit ${txHash} is not for channel ${ch}`);
  }
  if (outcome.custody) {
    throw new Error(`deposit ${txHash} came from an address that did not join this channel; it is held `
      + `by the channel operator for a refund. Deposit from the wallet you joined with.`);
  }
  return outcome;
}

function start(withLock, periodMs = Number(process.env.DEPOSIT_SEQUENCER_MS || 20000)) {
  const tick = () => run(withLock).catch(error => console.error('[deposit-sequencer]', (error && (error.stderr || error.message)) || error));
  tick();
  return setInterval(tick, periodMs).unref();
}

module.exports = { run, importThrough, start, boundSlots, MIN_CONFIRMATIONS };
