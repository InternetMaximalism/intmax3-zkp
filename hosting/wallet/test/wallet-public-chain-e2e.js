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
//   * the relay is restarted mid-run and the flow continues;
//   * a partial withdrawal is settled on L1 by the relay in the background: the producer history
//     is published and finalized, the intent is submitted from the post-burn head (the channel is
//     refused other operations until then), the manager's one-day challenge period passes, and
//     the recipient pulls the payout with its own account. Advancing anvil's clock past the
//     challenge deadline is this harness's only shortcut (REHEARSAL_ANVIL_RPC).
// It follows the browser's API sequence (wallet-live.html): init → deposit-info → L1 deposit →
// ticket → import-deposit (retrying only on the confirmation refusal) → cosign / inter/send.
//
// Env: WALLET_E2E_DIR (state, resumable), RPC (the proxy), WALLET_E2E_URL (relay HTTP base),
//      REHEARSAL_RESTART (command that restarts the relay; optional), REHEARSAL_ANVIL_RPC (anvil
//      itself, for advancing its clock; default http://127.0.0.1:8597).
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

// Poll the user's channel tickets until `done` holds for its partial withdrawal; log each phase.
async function waitWithdrawal(ch, done, what) {
  let last = '';
  for (const t0 = Date.now(); Date.now() - t0 < 4 * 3600 * 1000;) {
    let tickets;
    // The settlement outlives relay restarts; keep following it across one.
    try { tickets = (await api(ch, '/api/tickets')).concat(await api(ch, '/api/tickets/history')); }
    catch (e) { if (e.status) throw e; await sleep(10 * 1000); continue; }
    const ticket = tickets.find(t => t.type === 'partial_withdrawal' && !t.retired);
    const settle = (ticket && ticket.steps && ticket.steps.settle) || {};
    const now = ticket ? `${ticket.status}/${settle.phase || '-'}${settle.error ? ' (retrying: ' + settle.error.slice(0, 160) + ')' : ''}` : 'none';
    if (now !== last) { log(`withdrawal ${now}`); last = now; }
    if (ticket && done(ticket)) return ticket;
    await sleep(10 * 1000);
  }
  throw Error('withdrawal did not reach ' + what);
}

async function withdraw(user, amount, tag) {
  const u = USERS[user], anvil = process.env.REHEARSAL_ANVIL_RPC || 'http://127.0.0.1:8597';
  const t0 = Date.now();
  await once(tag + '-burn', async () => {
    await load(user);
    const head = await api(u.ch, '/api/base-head');
    const payload = wallet.burnSend(amount, u.address, 0, head.nonce);
    wallet.finalize(await api(u.ch, '/api/cosign-burn', { ...payload, amount, recipient: u.address }));
    log(`withdraw ${tag}: ${user} burned ${amount} to ${u.address}`);
    return { at: Date.now() };
  });
  // Until the intent is on L1 the burn owns the channel: anything else is refused at once.
  await once(tag + '-frozen', async () => {
    const ticket = (await api(u.ch, '/api/tickets')).find(t => t.type === 'partial_withdrawal');
    const phase = ticket && ticket.steps && ticket.steps.settle && ticket.steps.settle.phase;
    if (ticket && ['challenge', 'finalizing'].includes(phase)) return { skipped: phase };
    const t1 = Date.now();
    try { await api(u.ch, '/api/cosign', {}); throw Error('a send was accepted while the burn owns the channel'); }
    catch (e) { if (e.status !== 409 || !/SETTLING_WITHDRAWAL/.test(e.body || '')) throw e; }
    if (Date.now() - t1 > 5000) throw Error('the refusal waited behind the settlement instead of answering at once');
    return { refused: true };
  });
  const submitted = await waitWithdrawal(u.ch, t => t.steps && t.steps.settle && ['challenge', 'finalizing', 'done'].includes(t.steps.settle.phase), 'its L1 intent');
  log(`withdraw ${tag}: intent on L1 after ${((Date.now() - t0) / 60000).toFixed(1)} min, deadline ${submitted.steps.settle.deadline}`);
  // The manager's challenge period is a day of L1 time; pass it on the local chain.
  await once(tag + '-challenge-passed', async () => {
    const deadline = Number(submitted.steps.settle.deadline);
    const now = Number(cp.execFileSync('cast', ['block', 'latest', '-f', 'timestamp', '--rpc-url', anvil], { encoding: 'utf8' }).trim());
    if (now <= deadline) {
      cp.execFileSync('cast', ['rpc', 'evm_increaseTime', String(deadline - now + 1), '--rpc-url', anvil]);
      cp.execFileSync('cast', ['rpc', 'evm_mine', '--rpc-url', anvil]);
    }
    return { deadline, advancedFrom: now };
  });
  const ready = await waitWithdrawal(u.ch, t => ['claim_pending', 'settle_done'].includes(t.status), 'its payout');
  const claim = ready.params.claim;
  if (!claim || claim.recipient.toLowerCase() !== u.address || claim.amount !== amount) throw Error('unexpected payout claim ' + JSON.stringify(claim));
  // The recipient pulls the credited payout with its own account.
  const pull = await once(tag + '-pull', async () => {
    const before = BigInt(cast('balance', u.address));
    const receipt = JSON.parse(cast('send', claim.to, claim.data, '--unlocked', '--from', u.address, '--json'));
    if (receipt.status !== '0x1') throw Error('payout pull reverted');
    const after = BigInt(cast('balance', u.address));
    if (after - before + BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice) !== BigInt(amount)) throw Error('recipient did not receive the exact payout');
    return receipt;
  });
  await once(tag + '-confirmed', () => api(u.ch, '/api/pw-claim-confirm', { txHash: pull.transactionHash }));
  await waitWithdrawal(u.ch, t => t.status === 'settle_done', 'settled');
  // Every blob post locked 1 ETH of the operator's; all of it must be back in its account.
  const rollup = (await api(u.ch, '/api/deployment')).rollup.toLowerCase();
  // The CLI journals its L1 publications in proof-da-output/ beside the contracts directory.
  const outputs = process.env.REHEARSAL_PROOF_DA_DIR || path.join(directory, '..', 'proof-da-output');
  const journals = fs.readdirSync(outputs).filter(d => d.startsWith('wallet-validity-0x'))
    .map(d => path.join(outputs, d, 'posts.json')).filter(f => fs.existsSync(f))
    .map(f => JSON.parse(fs.readFileSync(f))).filter(j => j.rollup.toLowerCase() === rollup);
  if (!journals.length) throw Error('no validity posting journal for this rollup');
  for (const j of journals) {
    for (const round of j.rounds) {
      const submitter = cast('call', rollup, 'stakeInfo(uint256)(address,bool)', String(BigInt(round.submissionId))).split(/\s+/)[0];
      if (!/^0x0{40}$/i.test(submitter)) throw Error(`stake of submission ${round.submissionId} was not released`);
    }
    const credit = cast('call', rollup, 'pendingWithdrawals(address)(uint256)', j.submitter).split(/\s+/)[0];
    if (credit !== '0') throw Error('the operator\'s reclaimed stakes were not pulled back: ' + credit);
  }
  log(`withdraw ${tag}: ${user} received ${amount} on L1 (${((Date.now() - t0) / 60000).toFixed(1)} min); `
    + `${journals.reduce((n, j) => n + j.rounds.length, 0)} posting stakes released`);
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
  // A repeated delivery of the same transfer must not credit twice (checked once, right after it
  // landed: a resumed run may meet the channel paused by a later withdrawal).
  await once(tag + '-replayed', async () => {
    const before = (await api(t.ch, '/api/snapshot')).state.digest;
    await api(f.ch, '/api/inter/send', payload);
    if ((await api(t.ch, '/api/snapshot')).state.digest !== before) throw Error('duplicate delivery advanced the destination');
    return { at: Date.now() };
  });
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
  // The relay checks at startup that its rollup can finalize the producer's blocks, and offers a
  // deposit target only then: a rollup that cannot would lock every deposit (no refund path).
  let health = await api(7, '/api/health');
  for (let i = 0; i < 60 && !health.capabilities.deposit && /still checking/.test(health.unavailable.deposit || ''); i++) {
    await sleep(1000);
    health = await api(7, '/api/health');
  }
  log('relay', JSON.stringify(health));
  if (health.capabilities.deposit !== true) throw Error('the relay offers no deposits on a verified rollup: ' + health.unavailable.deposit);
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
  await withdraw('A', ETH(0.002), 'pw-A');
  await expectBalances({ A: ETH(0.006), B: ETH(0.011), C: ETH(0.008) }, 'balances-4');
  // The channel is free again once the intent is on L1.
  await sendIntra('C', 'A', ETH(0.001), 'c-a-2');
  await expectBalances({ A: ETH(0.007), B: ETH(0.011), C: ETH(0.007) }, 'balances-5');
  save('success', { at: new Date().toISOString() });
  log('SUCCESS: joins onto bound channels, in-order deposits with abandoned/foreign/outsider ones, intra/inter sends, receive-after-send, restart, partial withdrawal settled on L1');
})().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
