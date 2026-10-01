'use strict';
// Verify that the rollup the served channels deposit into can finalize this producer's blocks, and
// record it for the relay (api/lib/validity-deployment.js). The relay offers deposits only while
// that record matches: the chain, the rollup, the producer's arities and the exact binaries.
//
// Run with the relay's environment (RPC, INTMAX_CHANNELS, INTMAX_WORK_DIR, CHANNEL_MEMBER_BIN,
// BLOCK_PRODUCER_BIN, BLOCK_PRODUCER_ARITIES): after deploying a rollup, before any channel is
// bootstrapped (bootstrap-real-chain.js runs it first), and after every build, because the record is
// bound to the binaries (deploy-relay-host.sh runs it before swapping them in). The first run of a
// build exports the producer's validity configuration: minutes and ~15 GB of memory.
//
// Usage: node hosting/wallet/verify-validity-deployment.js [<rollup>]
//   default rollup: the one every served channel's channel_backing.json names
const { servedRollup, verify } = require('../../api/lib/validity-deployment');

try {
  const rollup = process.argv[2] || servedRollup();
  if (!rollup) throw new Error('no served channel is backed yet: pass the rollup address');
  console.log(JSON.stringify(verify(rollup), null, 2));
} catch (e) {
  console.error(e && e.stderr ? String(e.stderr) : (e && e.message) || e);
  process.exit(1);
}
