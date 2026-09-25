'use strict';
const cli = require('./cli');
const producer = require('./block-producer');
const { verifyRegistration, topics } = require('../../node/common/l1-registration');
let queue = Promise.resolve();
// Registration is shared producer state: serialize across channels, not only within one channel.
function ensureLiveRegistration(ch, snapshot) {
  const run = queue.then(async () => {
    const status = await producer.status();
    if ((status.channelHeads || []).some(h => Number(h.channelId) === ch)) return;
    cli.ensureSettlement(ch); // Local devnet deploys BEFORE the registration enters the producer.
    const filter = { address: cli.rollupOf(ch), fromBlock: '0x0', toBlock: 'latest', topics: topics(ch) };
    const logs = JSON.parse(cli.sh('cast', ['rpc', 'eth_getLogs', JSON.stringify(filter), '--rpc-url', cli.RPC]));
    verifyRegistration(snapshot, status, logs);
    return producer.register(snapshot);
  });
  queue = run.catch(() => {});
  return run;
}
module.exports = { ensureLiveRegistration };
