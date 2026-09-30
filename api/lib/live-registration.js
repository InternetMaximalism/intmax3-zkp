'use strict';
const fs = require('fs');
const cli = require('./cli');
const producer = require('./block-producer');
const { verifyRegistration, topics } = require('../../node/common/l1-registration');
let queue = Promise.resolve();

// Public RPCs cap eth_getLogs by block range, and the cap is the provider's choice (publicnode
// 50 000, others 10 000 or less), so one 0..latest query fails on any real chain. Scan backwards in
// windows from the settlement's finalized activation block (the registration is at or below it)
// and stop at the first window holding this channel's log. That is complete, not a sample: the
// rollup accepts ONE registration per channel id (`ChannelAlreadyRegistered`), and once a window
// starts before the rollup's own deployment (no code at its first block) nothing earlier can hold
// a log. verifyRegistration still refuses anything but exactly one matching log.
// The window starts at L1_LOG_WINDOW_BLOCKS and halves whenever the RPC refuses the range, so no
// provider's cap has to be known in advance.
const LOG_WINDOW = Number(process.env.L1_LOG_WINDOW_BLOCKS || 50000);
const RANGE_REFUSAL = /block range|range.*(exceed|too (large|wide|big))|exceed.*range|too many (blocks|results)|more than \d+ results|response size|limit exceeded/i;

function rpc(method, params) {
  // stderr is captured, not inherited: a range refusal is an expected step of the scan below.
  return JSON.parse(cli.sh('cast', ['rpc', method, ...params.map(p => typeof p === 'string' ? p : JSON.stringify(p)), '--rpc-url', cli.RPC], { stdio: 'pipe' }));
}

function registrationLogs(ch) {
  const settlement = cli.readJson(cli.wc(ch, 'settlement.json'));
  const checkpoint = settlement.activation_checkpoint;
  // settlement.json serializes the checkpoint camelCase (`L1FinalizedCheckpoint`).
  const head = checkpoint ? Number(checkpoint.blockNumber) : Number(BigInt(rpc('eth_blockNumber', [])));
  if (!Number.isSafeInteger(head) || head < 0) throw new Error(`channel ${ch} settlement has no valid activation block`);
  const address = cli.rollupOf(ch);
  let window = LOG_WINDOW;
  for (let to = head; to >= 0;) {
    const from = Math.max(0, to - window + 1);
    let logs;
    try {
      logs = rpc('eth_getLogs', [{ address, fromBlock: '0x' + from.toString(16), toBlock: '0x' + to.toString(16), topics: topics(ch) }]);
    } catch (error) {
      const text = String((error && (error.stderr || error.message)) || error);
      if (window === 1 || !RANGE_REFUSAL.test(text)) throw error;
      window = Math.max(1, Math.floor(window / 2));
      continue;
    }
    if (logs.length) return logs;
    if (from === 0 || rpc('eth_getCode', [address, '0x' + from.toString(16)]) === '0x') return [];
    to = from - 1;
  }
  return [];
}

// Registration is shared producer state: serialize across channels, not only within one channel.
function ensureLiveRegistration(ch, snapshot) {
  const run = queue.then(async () => {
    const status = await producer.status();
    if ((status.channelHeads || []).some(h => Number(h.channelId) === ch)) return;
    cli.ensureSettlement(ch); // Local devnet deploys BEFORE the registration enters the producer.
    if (!fs.existsSync(cli.wc(ch, 'settlement.json'))) throw new Error(`channel ${ch} has no settlement deployment`);
    verifyRegistration(snapshot, status, registrationLogs(ch));
    return producer.register(snapshot);
  });
  queue = run.catch(() => {});
  return run;
}
module.exports = { ensureLiveRegistration, registrationLogs };
