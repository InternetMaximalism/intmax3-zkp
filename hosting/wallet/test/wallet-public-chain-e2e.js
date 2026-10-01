'use strict';
// Production-topology acceptance for a PUBLIC-CHAIN wallet relay, run against the rehearsal chain
// (public-chain-rehearsal.sh: anvil with Sepolia's chain id behind the public-RPC limits proxy).
//
// It differs from wallet-tail-e2e.js (the devnet acceptance) in the ways production differs:
//   * channels are bootstrapped by the operator (bootstrap-real-chain.js): genesis with an
//     operator delegate, settlement ACTIVE, L1-registered. Users never create a channel; every
//     user JOINS an existing, bound channel. (On devnet the first user creates the genesis, so a
//     join onto a bound genesis never happened there and its propagation bug shipped.)
//   * several users per channel, joining before AND after the channel's first deposit;
//   * deposits come from ordinary accounts and wait for the chain's own confirmation depth; the
//     relay's devnet-only deposit helper is not used;
//   * the relay is restarted mid-run and the flow continues.
// It follows the browser's API sequence (wallet-live.html): init → deposit-info → L1 deposit →
// ticket → import-deposit (retrying only on the confirmation refusal) → cosign / inter/send.
//
// Env: WALLET_E2E_DIR (state, resumable), RPC (the proxy), WALLET_E2E_URL (relay HTTP base),
//      REHEARSAL_RESTART (command that restarts the relay; optional).
const fs = require('fs'), path = require('path'), cp = require('child_process'), crypto = require('crypto');
const { Wallet } = require('../../../node/common/wallet');

const directory = process.env.WALLET_E2E_DIR, rpc = process.env.RPC, base = process.env.WALLET_E2E_URL;
if (!directory || !rpc || !base || ![rpc, base].every(u => ['localhost', '127.0.0.1'].includes(new URL(u).hostname))) {
  throw Error('explicit state directory and loopback RPC/relay required');
}
// anvil's public dev accounts 1..4 (account 0 is the operator; 4 never joins).
const OUTSIDER = '0x15d34aaf54267db7d7c367839aaf71a00a2c6a65';
const USERS = {
  A: { ch: 7, address: '0x70997970c51812dc3a010c7d01b50e0d17dc79c8' },
  B: { ch: 8, address: '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc' },
  C: { ch: 7, address: '0x90f79bf6eb2c4f870365e785982e1f101e93b906' },
};
const ETH = n => (BigInt(Math.round(n * 1e6)) * 10n ** 12n).toString();
const wallet = new Wallet();
const file = name => path.join(directory, name + '.json');
const read = name => JSON.parse(fs.readFileSync(file(name)));
function save(name, value) { const dest = file(name), temp = dest + '.tmp'; fs.writeFileSync(temp, JSON.stringify(value), { mode: 0o600 }); fs.renameSync(temp, dest); return value; }
async function once(name, fn) { return fs.existsSync(file(name)) ? read(name) : save(name, await fn()); }
function cast(...args) { return cp.execFileSync('cast', [...args, '--rpc-url', rpc], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }).trim(); }
const sleep = ms => new Promise(r => setTimeout(r, ms));
function log(...args) { console.log(new Date().toISOString().slice(11, 19), ...args); }

function api(ch, route, body, { raw = false } = {}) {
  return new Promise((resolve, reject) => {
    const bytes = body == null ? null : JSON.stringify(body);
    const url = base + route + (route.includes('?') ? '&' : '?') + 'channel=' + ch;
    const request = require('http').request(url, { agent: false, method: bytes ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json', ...(bytes ? { 'Content-Length': Buffer.byteLength(bytes) } : {}) } }, response => {
      let text = ''; response.on('data', c => { text += c; });
      response.on('end', () => {
        if (response.statusCode >= 400) { const e = Error(`${route} ${response.statusCode}: ${text.slice(-3000)}`); e.status = response.statusCode; e.body = text; return reject(e); }
        try { resolve(raw ? text : JSON.parse(text)); } catch (error) { reject(Error(`${route}: non-JSON ${text.slice(0, 200)}`)); }
      });
    });
    request.setTimeout(3 * 3600 * 1000, () => request.destroy(Error('timeout ' + route)));
    request.on('error', reject); request.end(bytes);
  });
}

async function load(user) {
  const u = USERS[user];
  wallet.keygen(read('seed-' + user));
  wallet.importChannel(await api(u.ch, '/api/snapshot'));
  return wallet.balance();
}

async function join(user) {
  const u = USERS[user];
  await once('seed-' + user, async () => crypto.randomBytes(32).toString('hex'));
  wallet.keygen(read('seed-' + user));
  const contribution = await once('join-input-' + user, async () => wallet.genesisContribution('0', u.address));
  const t0 = Date.now();
  await once('join-' + user, () => api(u.ch, '/api/init', contribution));
  const report = await load(user);
  log(`join ${user} -> ch${u.ch} slot ${report.slot} (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
  return report;
}

async function deposit(user, amount, tag) {
  const u = USERS[user];
  const report = await load(user);
  const info = await api(u.ch, '/api/deposit-info');
  if (Number(info.chainId) !== Number(cast('chain-id'))) throw Error('deposit-info chainId differs from the chain');
  const tx = await once(tag + '-tx', async () => JSON.parse(cast('send', info.rollup, 'deposit(bytes32,uint32,uint256,bytes32)',
    info.depositRecipient, '0', amount, '0x' + '00'.repeat(32), '--value', amount, '--unlocked', '--from', u.address, '--json')));
  if (tx.status !== '0x1') throw Error(`${tag}: L1 deposit reverted`);
  await once(tag + '-ticket', () => api(u.ch, '/api/ticket/deposit', { amount, depositor: u.address, txHash: tx.transactionHash, recipientSlot: report.slot, tokenIndex: 0 }).catch(e => ({ ticketError: e.message })));
  const t0 = Date.now();
  await once(tag + '-import', async () => {
    for (;;) {
      try { return await api(u.ch, '/api/import-deposit', { recipientSlot: report.slot, txHash: tx.transactionHash }); }
      catch (e) {
        if (!/confirmation/i.test(e.message)) throw e;
        if (Date.now() - t0 > 20 * 60 * 1000) throw e;
        await sleep(3000);
      }
    }
  });
  log(`deposit ${tag}: ${user} ${amount} imported (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
}

// An L1 deposit whose sender never asks the relay to import it (a closed browser, a stranger,
// an account that never joined). The relay must still consume it in order.
async function depositWithoutImport(from, recipient, amount, tag) {
  const info = await api(7, '/api/deposit-info');
  const tx = await once(tag + '-tx', async () => JSON.parse(cast('send', info.rollup, 'deposit(bytes32,uint32,uint256,bytes32)',
    recipient, '0', amount, '0x' + '00'.repeat(32), '--value', amount, '--unlocked', '--from', from, '--json')));
  if (tx.status !== '0x1') throw Error(`${tag}: L1 deposit reverted`);
  log(`deposit ${tag}: ${amount} to ${recipient.slice(0, 10)}… from ${from.slice(0, 10)}… (no import request)`);
  return tx.transactionHash;
}

async function sendIntra(from, to, amount, tag) {
  const f = USERS[from], t = USERS[to];
  if (f.ch !== t.ch) throw Error('intra-channel send needs one channel');
  const toSlot = (await load(to)).slot;
  const payload = await once(tag + '-payload', async () => { await load(from); return wallet.send(null, toSlot, amount); });
  const t0 = Date.now();
  await once(tag + '-result', () => api(f.ch, '/api/cosign', payload));
  log(`send ${tag}: ${from} -> ${to} ${amount} (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
}

async function sendInter(from, to, amount, tag) {
  const f = USERS[from], t = USERS[to];
  const payload = await once(tag + '-payload', async () => {
    const toSlot = (await load(to)).slot;
    const destination = await api(t.ch, '/api/snapshot');
    const member = destination.members.find(m => m.slot === toSlot);
    await load(from);
    const head = await api(f.ch, '/api/base-head');
    const built = wallet.sendInterChannel(t.ch, toSlot, amount, { regevPk: member.regevPk, pkG: member.pkG }, 0, head.nonce);
    return { debitPayload: built.debitPayload, transferDescriptor: built.transferDescriptor };
  });
  const t0 = Date.now();
  await once(tag + '-result', () => api(f.ch, '/api/inter/send', payload));
  // A repeated delivery of the same transfer must not credit twice.
  const before = (await api(t.ch, '/api/snapshot')).state.digest;
  await api(f.ch, '/api/inter/send', payload);
  if ((await api(t.ch, '/api/snapshot')).state.digest !== before) throw Error('duplicate delivery advanced the destination');
  log(`send ${tag}: ${from}(ch${f.ch}) -> ${to}(ch${t.ch}) ${amount} (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
}

// Checkpointed like every other step: a resumed run does not re-check a stage it has passed.
async function expectBalances(expected, tag) {
  await once(tag, async () => {
    for (const [user, amount] of Object.entries(expected)) {
      const report = await load(user);
      if (report.balance !== amount) throw Error(`${user} balance ${report.balance} != expected ${amount}`);
    }
    log('balances ok', JSON.stringify(expected));
    return expected;
  });
}

async function restartRelay() {
  if (!process.env.REHEARSAL_RESTART) return;
  await once('restart', async () => {
    log('restarting the relay');
    cp.execSync(process.env.REHEARSAL_RESTART, { stdio: 'inherit' });
    for (let i = 0; i < 600; i++) {
      try { await api(7, '/api/health'); return { at: Date.now() }; } catch (_) { await sleep(1000); }
    }
    throw Error('relay did not come back');
  });
}

(async () => {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (cast('chain-id') === '31337') throw Error('this acceptance is for the public-chain path; use wallet-tail-e2e.js on devnet');
  const health = await api(7, '/api/health');
  log('relay', JSON.stringify(health));
  await wallet.initialize();

  // Users join operator-bootstrapped, settlement-ACTIVE channels (none creates one).
  await join('A');
  await join('B');
  await deposit('A', ETH(0.01), 'dep-A');
  await deposit('B', ETH(0.01), 'dep-B');
  // A second user joins channel 7 after its first deposit.
  await join('C');
  // Three deposits nobody imports sit in the rollup's sequence ahead of C's: B's own (a closed
  // browser), one to a recipient that is no channel of this relay, and one to channel 7 from an
  // account that never joined. None may block C, and B's must reach B without B asking.
  const info8 = await api(8, '/api/deposit-info');
  await depositWithoutImport(USERS.B.address, info8.depositRecipient, ETH(0.001), 'abandoned-B');
  await depositWithoutImport(OUTSIDER, '0x' + '5e'.repeat(32), ETH(0.001), 'foreign');
  const info7 = await api(7, '/api/deposit-info');
  const outsiderTx = await depositWithoutImport(OUTSIDER, info7.depositRecipient, ETH(0.001), 'outsider-7');
  await deposit('C', ETH(0.005), 'dep-C');
  await expectBalances({ A: ETH(0.01), B: ETH(0.011), C: ETH(0.005) }, 'balances-1');
  // The outsider's deposit is not credited to any joined user; the relay says it is held.
  await once('outsider-7-import', async () => {
    try { await api(7, '/api/import-deposit', { recipientSlot: 4, txHash: outsiderTx }); }
    catch (e) { if (/held by the channel operator/.test(e.message)) return { held: true }; throw e; }
    throw Error('an outsider deposit must not be credited to a joined slot');
  });

  await sendIntra('A', 'C', ETH(0.002), 'a-c');
  await sendInter('A', 'B', ETH(0.003), 'a-b');
  // A has sent; it must still receive a transfer and a deposit (the receive-after-send window).
  await sendInter('B', 'A', ETH(0.001), 'b-a');
  await deposit('A', ETH(0.001), 'dep-A2');
  await expectBalances({ A: ETH(0.007), B: ETH(0.013), C: ETH(0.007) }, 'balances-2');

  await restartRelay();
  await sendIntra('C', 'A', ETH(0.001), 'c-a');
  await sendInter('B', 'C', ETH(0.002), 'b-c');
  await expectBalances({ A: ETH(0.008), B: ETH(0.011), C: ETH(0.008) }, 'balances-3');
  // Withdraw is not offered on a public chain until its L1 settlement exists: the burn is refused
  // before anything is signed, and the balances above are untouched.
  await once('withdraw-refused', async () => {
    const health = await api(7, '/api/health');
    if (!health.capabilities || health.capabilities.partialWithdrawal !== false) throw Error('health must report partialWithdrawal: false');
    const before = (await api(7, '/api/snapshot')).state.digest;
    try { await api(7, '/api/cosign-burn', { debitPayload: {}, transferDescriptor: {} }); throw Error('a burn was accepted'); }
    catch (e) { if (e.status !== 501 || !/NOT_AVAILABLE/.test(e.body || '')) throw e; }
    if ((await api(7, '/api/snapshot')).state.digest !== before) throw Error('a refused burn changed the channel');
    return { refused: true };
  });
  await expectBalances({ A: ETH(0.008), B: ETH(0.011), C: ETH(0.008) }, 'balances-4');
  save('success', { at: new Date().toISOString() });
  log('SUCCESS: joins onto bound channels, in-order deposits with abandoned/foreign/outsider ones, intra/inter sends, receive-after-send, restart');
})().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
