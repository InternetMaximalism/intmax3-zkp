'use strict';
// The registration log search must work against public RPCs that cap eth_getLogs by block range.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'live-reg-'));
process.env.INTMAX_WORK_DIR = work;
process.env.L1_LOG_WINDOW_BLOCKS = '1000';
const cli = require('../../api/lib/cli');
const { registrationLogs } = require('../../api/lib/live-registration');
const ROLLUP = '0x' + '3c'.repeat(20);
function channel(ch, settlement) {
  fs.mkdirSync(cli.wc(ch, ''), { recursive: true });
  fs.writeFileSync(cli.wc(ch, 'channel_backing.json'), JSON.stringify({ rollup: ROLLUP }));
  fs.writeFileSync(cli.wc(ch, 'settlement.json'), JSON.stringify(settlement));
}
// A chain whose RPC refuses any eth_getLogs range wider than 1000 blocks, with the rollup deployed
// at `deployedAt` and the channel's registration log at `registeredAt`.
function chain({ head, deployedAt, registeredAt }) {
  const calls = [];
  cli.sh = (_bin, args) => {
    const method = args[1]; calls.push(method);
    if (method === 'eth_blockNumber') return JSON.stringify('0x' + head.toString(16));
    if (method === 'eth_getCode') return JSON.stringify(parseInt(args[3], 16) >= deployedAt ? '0x60' : '0x');
    if (method === 'eth_getLogs') {
      const f = JSON.parse(args[2]), from = parseInt(f.fromBlock, 16), to = parseInt(f.toBlock, 16);
      if (to - from + 1 > 1000) throw new Error('exceed maximum block range: 1000');
      return JSON.stringify(registeredAt !== null && registeredAt >= from && registeredAt <= to ? [{ blockNumber: registeredAt }] : []);
    }
    throw new Error(method);
  };
  return calls;
}
test('finds a registration far below the finalized activation block within the RPC range cap', () => {
  channel(7, { activation_checkpoint: { blockNumber: 9_000_000, chainId: 11155111 } });
  const calls = chain({ head: 9_000_100, deployedAt: 8_990_000, registeredAt: 8_994_321 });
  assert.deepEqual(registrationLogs(7), [{ blockNumber: 8_994_321 }]);
  assert.ok(calls.filter(m => m === 'eth_getLogs').length <= 6);
});
test('stops at the rollup deployment instead of scanning to genesis when nothing was registered', () => {
  channel(8, { activation_checkpoint: { blockNumber: 9_000_000, chainId: 11155111 } });
  const calls = chain({ head: 9_000_000, deployedAt: 8_997_500, registeredAt: null });
  assert.deepEqual(registrationLogs(8), []);
  assert.equal(calls.filter(m => m === 'eth_getLogs').length, 3);
});
test('a settlement.json without a readable activation block fails instead of scanning nothing', () => {
  channel(10, { activation_checkpoint: { block_number: 9_000_000 } });
  chain({ head: 9_000_000, deployedAt: 0, registeredAt: 8_999_000 });
  assert.throws(() => registrationLogs(10), /no valid activation block/);
});
test('a devnet settlement without a checkpoint scans back from the current head to block 0', () => {
  channel(9, {});
  chain({ head: 2500, deployedAt: 0, registeredAt: 5 });
  assert.deepEqual(registrationLogs(9), [{ blockNumber: 5 }]);
});
