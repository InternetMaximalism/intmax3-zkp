'use strict';
const fs = require('fs');
const cli = require('./cli');
const producer = require('./block-producer');
const { verifyRegistration, topics } = require('../../node/common/l1-registration');
let queue = Promise.resolve();

// Public RPCs cap eth_getLogs by block range (publicnode: 50 000), so one 0..latest query fails on
// any real chain. Scan backwards in windows from the settlement's finalized activation block (the
// registration is at or below it) and stop at the first window holding this channel's log. That
// is complete, not a sample: the rollup accepts ONE registration per channel id
// (`ChannelAlreadyRegistered`), and once a window starts before the rollup's own deployment (no
// code at its first block) nothing earlier can hold a log. verifyRegistration still refuses
// anything but exactly one matching log.
const LOG_WINDOW = Number(process.env.L1_LOG_WINDOW_BLOCKS || 50000);

function rpc(method, params) {
  return JSON.parse(cli.sh('cast', ['rpc', method, ...params.map(p => typeof p === 'string' ? p : JSON.stringify(p)), '--rpc-url', cli.RPC]));
}

function registrationLogs(ch) {
  const settlement = cli.readJson(cli.wc(ch, 'settlement.json'));
  const checkpoint = settlement.activation_checkpoint;
  const head = checkpoint ? Number(checkpoint.block_number) : Number(BigInt(rpc('eth_blockNumber', [])));
  const address = cli.rollupOf(ch);
  for (let to = head; to >= 0; to -= LOG_WINDOW) {
    const from = Math.max(0, to - LOG_WINDOW + 1);
    const logs = rpc('eth_getLogs', [{ address, fromBlock: '0x' + from.toString(16), toBlock: '0x' + to.toString(16), topics: topics(ch) }]);
    if (logs.length) return logs;
    if (from === 0 || rpc('eth_getCode', [address, '0x' + from.toString(16)]) === '0x') return [];
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
