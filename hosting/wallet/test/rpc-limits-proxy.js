'use strict';
// JSON-RPC proxy that puts a public RPC's limits in front of a local anvil, so the public-chain
// rehearsal (public-chain-rehearsal.sh) meets what Sepolia's publicnode endpoint does instead of
// anvil's permissive defaults. The first Sepolia deployment failed on exactly this difference:
// anvil answers eth_getLogs over any range, publicnode refuses more than 50 000 blocks.
//
// Enforced:
//   * eth_getLogs block range <= RPC_LOGS_MAX_RANGE (default 50 000), error -32701 as publicnode;
//   * eth_getLogs without an explicit range ("latest"/omitted bounds count from block 0);
//   * `finalized` / `safe` advance an EPOCH at a time (RPC_EPOCH_BLOCKS, default 32) and lag the
//     head by two epochs, as on a proof-of-stake chain. Anvil moves them every block, which hides
//     both the long finality wait and a read straddling a finality step;
//   * historical STATE is pruned: a state read at a block older than head - RPC_STATE_RETENTION
//     (default 10 000; publicnode keeps a few thousand to ~20 000) fails as publicnode's does.
//     Anvil keeps every state, which hid a deployment-block probe that failed on the testnet.
// Anvil itself is started with the public chain's id and gas limit (see the rehearsal script).
//
// Usage: node rpc-limits-proxy.js <listen port> <upstream url>
const http = require('http');

const [listenPort, upstream] = process.argv.slice(2);
if (!listenPort || !upstream) throw new Error('usage: rpc-limits-proxy.js <listen port> <upstream url>');
const MAX_RANGE = Number(process.env.RPC_LOGS_MAX_RANGE || 50000);
const EPOCH = Number(process.env.RPC_EPOCH_BLOCKS || 32);

// The last block of the epoch two epochs behind the head's epoch.
function finalizedFor(head) {
  return Math.max(0, (Math.floor(head / EPOCH) - 1) * EPOCH - 1);
}

// Pin `finalized`/`safe` block tags to the epoch-stepped height before forwarding.
async function rewriteFinality(call) {
  const params = call.params || [];
  const tagIndex = { eth_getBlockByNumber: 0, eth_call: 1, eth_getBalance: 1, eth_getCode: 1,
    eth_getTransactionCount: 1, eth_getStorageAt: 2 }[call.method];
  if (tagIndex === undefined || !['finalized', 'safe'].includes(params[tagIndex])) return call;
  const pinned = [...params];
  pinned[tagIndex] = '0x' + finalizedFor(await blockNumber()).toString(16);
  return { ...call, params: pinned };
}

function post(body) {
  return new Promise((resolve, reject) => {
    const request = http.request(upstream, { method: 'POST', headers: { 'content-type': 'application/json' } }, response => {
      let text = '';
      response.on('data', chunk => { text += chunk; });
      response.on('end', () => resolve(text));
    });
    request.on('error', reject);
    request.end(body);
  });
}

async function blockNumber() {
  const reply = JSON.parse(await post(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] })));
  return Number(BigInt(reply.result));
}

async function resolveTag(tag, head) {
  if (tag === undefined || tag === 'earliest') return 0;
  if (['safe', 'finalized'].includes(tag)) return finalizedFor(head);
  if (['latest', 'pending'].includes(tag)) return head;
  return Number(BigInt(tag));
}

const RETENTION = Number(process.env.RPC_STATE_RETENTION || 10000);
const STATE_TAG_INDEX = { eth_call: 1, eth_getBalance: 1, eth_getCode: 1, eth_getTransactionCount: 1, eth_getStorageAt: 2, eth_getProof: 2 };

// Returns an error object to answer with, or null to forward.
async function refusal(call) {
  const tagIndex = STATE_TAG_INDEX[call.method];
  if (tagIndex !== undefined) {
    const tag = (call.params || [])[tagIndex];
    if (typeof tag === 'string' && /^0x[0-9a-f]+$/i.test(tag)) {
      const block = Number(BigInt(tag));
      if (block < (await blockNumber()) - RETENTION) return { code: -32603, message: `state at block #${block} is pruned` };
    }
    return null;
  }
  if (call.method !== 'eth_getLogs') return null;
  const filter = (call.params && call.params[0]) || {};
  if (filter.blockHash) return null;
  const head = await blockNumber();
  const from = await resolveTag(filter.fromBlock, head);
  const to = await resolveTag(filter.toBlock, head);
  if (to - from + 1 > MAX_RANGE) {
    return { code: -32701, message: `exceed maximum block range: ${MAX_RANGE}` };
  }
  return null;
}

http.createServer((req, res) => {
  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', async () => {
    try {
      const parsed = JSON.parse(body);
      const calls = await Promise.all((Array.isArray(parsed) ? parsed : [parsed]).map(rewriteFinality));
      const refusals = await Promise.all(calls.map(refusal));
      if (refusals.every(r => r === null)) {
        const text = await post(JSON.stringify(Array.isArray(parsed) ? calls : calls[0]));
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(text);
      }
      // Answer refused calls locally and forward the rest one by one (order preserved).
      const replies = await Promise.all(calls.map(async (call, i) => refusals[i]
        ? { jsonrpc: '2.0', id: call.id, error: refusals[i] }
        : JSON.parse(await post(JSON.stringify(call)))));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(Array.isArray(parsed) ? replies : replies[0]));
    } catch (error) {
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32000, message: String(error.message || error) } }));
    }
  });
}).listen(Number(listenPort), '127.0.0.1', () => console.log(`rpc-limits-proxy :${listenPort} -> ${upstream} (logs range <= ${MAX_RANGE})`));
