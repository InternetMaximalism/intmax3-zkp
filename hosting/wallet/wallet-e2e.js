// End-to-end: browser wallet (Playwright) + CLI companion (channel_member) complete an in-channel
// SEND (browser → CLI member) and a RECEIVE (CLI member → browser), with real in-browser Regev /
// plonky3 E-1 proofs. Asserts balances reconcile. Run: node wallet-e2e.js
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname; // hosting/wallet/
const REPO = path.join(ROOT, '..', '..'); // repo root — target/, wallet-e2e-work/ live here (two levels up from hosting/wallet/)
const WORK = path.join(REPO, 'wallet-e2e-work');
const CLI = path.join(REPO, 'target', 'release', 'channel_member');
const URL = 'https://localhost:8000/wallet.html';

const w = (name) => path.join(WORK, name);
const readJson = (name) => fs.readFileSync(w(name), 'utf8');
const writeJson = (name, s) => fs.writeFileSync(w(name), s);
const cli = (...args) => {
  process.stdout.write(`  $ channel_member ${args.join(' ')}\n`);
  const out = execFileSync(CLI, args, { cwd: WORK, encoding: 'utf8' });
  process.stdout.write(out.split('\n').map(l => '    ' + l).join('\n') + '\n');
  return out;
};

function mergeSigs(stateAJson, stateBJson) {
  // Both states share the same proposed next state (identical digest); union their signatures.
  const a = JSON.parse(stateAJson), b = JSON.parse(stateBJson);
  if (a.digest !== b.digest) throw new Error('cannot merge: different state digests');
  const bySlot = new Map();
  for (const s of [...a.memberSignatures, ...b.memberSignatures]) bySlot.set(s.memberSlot, s);
  a.memberSignatures = [...bySlot.values()].sort((x, y) => x.memberSlot - y.memberSlot);
  return JSON.stringify(a);
}

(async () => {
  fs.rmSync(WORK, { recursive: true, force: true });
  fs.mkdirSync(WORK, { recursive: true });

  const browser = await chromium.launch({ args: ['--ignore-certificate-errors'] });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  page.setDefaultTimeout(600000);
  page.on('console', (m) => { if (m.type() === 'error') console.log('[page err]', m.text()); });
  page.on('pageerror', (e) => console.log('[pageerror]', e.message));

  const W = (action, payload) => page.evaluate(([a, p]) => window.walletCall(a, p), [action, payload]);

  console.log('→ loading wallet, initializing wasm + threads…');
  await page.goto(URL, { waitUntil: 'load' });
  await page.waitForFunction(() => window.walletCall && document.getElementById('status').dataset.ready === '1', null, { timeout: 120000 });

  console.log('→ [browser] keygen');
  await W('keygen', {});
  console.log('→ [browser] genesis contribution (balance 50)');
  writeJson('contribution.json', await W('genesisContribution', { balance: '50', recipient: '0x00000000000000000000000000000000deadbeef' })); // B-1b: nonzero dev exit address

  console.log('→ [CLI] init channel');
  cli('init', 'contribution.json', 'genesis_to_sign.json');

  console.log('→ [browser] sign genesis (slot 0)');
  writeJson('browser_sig.json', await W('signState', { slot: 0, stateJson: readJson('genesis_to_sign.json') }));

  console.log('→ [CLI] add browser signature → final snapshot');
  cli('add-genesis-sig', 'browser_sig.json', 'channel_snapshot.json');

  console.log('→ [browser] import channel');
  let r = JSON.parse(await W('importChannel', { snapshotJson: readJson('channel_snapshot.json') }));
  assert(r.balance === 50, `import balance ${r.balance} != 50`);
  console.log(`   browser balance = ${r.balance} ✓`);

  // ---- ROUND 1: browser (slot 0) sends 7 to CLI member (slot 1) ----
  console.log('\n=== ROUND 1: browser SENDS 7 to slot 1 (in-browser E-1 proof)… ===');
  writeJson('payload1.json', await W('send', { recipientSlot: 1, amount: '7' }));
  console.log('→ [CLI] cosign (slot 1 recipient decrypts + slots 1,2 sign)');
  cli('cosign', 'payload1.json', 'cosigned1.json');
  console.log('→ [browser] finalize');
  r = JSON.parse(await W('finalize', { stateJson: readJson('cosigned1.json') }));
  assert(r.balance === 43, `after send balance ${r.balance} != 43`);
  console.log(`   browser balance = ${r.balance} ✓ (sent 7)`);
  cli('finalize', 'cosigned1.json'); // advance CLI head

  // ---- ROUND 2: CLI member (slot 2) sends 5 to browser (slot 0) ----
  console.log('\n=== ROUND 2: slot 2 SENDS 5 to browser (browser RECEIVES)… ===');
  cli('send', '2', '0', '5', 'payload2.json');
  console.log('→ [browser] cosign as recipient (decrypts incoming amount, signs slot 0)');
  const browserCosign2 = await W('cosign', { payloadJson: readJson('payload2.json') });
  writeJson('browser_cosign2.json', browserCosign2);
  console.log('→ [CLI] cosign (slot 1 signs)');
  cli('cosign', 'payload2.json', 'cli_cosign2.json');
  console.log('→ merge signatures → fully-signed state');
  writeJson('final2.json', mergeSigs(browserCosign2, readJson('cli_cosign2.json')));
  console.log('→ [browser] finalize (receive)');
  r = JSON.parse(await W('finalize', { stateJson: readJson('final2.json') }));
  assert(r.balance === 48, `after receive balance ${r.balance} != 48`);
  console.log(`   browser balance = ${r.balance} ✓ (received 5)`);
  cli('finalize', 'final2.json');

  await browser.close();
  console.log('\n✅ E2E PASSED: browser sent 7 and received 5; balance 50 → 43 → 48.');
  process.exit(0);
})().catch((e) => { console.error('\n❌ E2E FAILED:', e.message); process.exit(1); });

function assert(cond, msg) { if (!cond) throw new Error(msg); }
