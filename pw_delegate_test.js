// Playwright: drive TWO independent browser sessions through the wallet-live delegate demo and
// verify real in-browser sends between delegates. Throwaway test harness.
const { chromium } = require('playwright');
const URL = 'https://localhost:8000/wallet-live.html';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const sessions = {};
  async function session(name) {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    page.on('pageerror', e => console.log(`[${name} PAGEERROR] ${e.message}`));
    page.on('console', m => { const t = m.text(); if (/error|fail|panic|exception/i.test(t)) console.log(`[${name} con] ${t}`); });
    await page.goto(URL, { waitUntil: 'load' });
    sessions[name] = { ctx, page, name };
    return sessions[name];
  }
  const logTail = async (s, n=1) => (await s.page.evaluate(() => document.getElementById('log').innerText)).split('\n').filter(x=>x.trim()).slice(-n).join(' | ');
  const bal = async (s) => s.page.evaluate(() => document.getElementById('balance').textContent + ' ' + document.getElementById('balMeta').textContent);

  async function waitReady(s) {
    await s.page.waitForFunction(() => document.getElementById('status').textContent === 'ready', { timeout: 90000 });
    const coi = await s.page.evaluate(() => self.crossOriginIsolated);
    const threads = await s.page.evaluate(() => document.getElementById('threads').textContent);
    console.log(`[${s.name}] ready (crossOriginIsolated=${coi}, threads=${threads})`);
  }
  async function open(s) {
    await s.page.click('#btnOpen');
    await s.page.waitForFunction(() => /joined as delegate slot|open failed/.test(document.getElementById('log').innerText), { timeout: 180000 });
    console.log(`[${s.name}] OPEN -> ${await bal(s)}  ::  ${await logTail(s,1)}`);
  }
  async function send(s, to, amt) {
    await s.page.fill('#toSlot', String(to));
    await s.page.fill('#amount', String(amt));
    const before = (await s.page.evaluate(() => document.getElementById('log').innerText)).length;
    await s.page.click('#btnSend');
    await s.page.waitForFunction((b) => { const t = document.getElementById('log').innerText.slice(b); return /sent \d+ to slot|send failed/.test(t); }, before, { timeout: 180000 });
    console.log(`[${s.name}] SEND ${amt}->slot${to} -> ${await bal(s)}  ::  ${await logTail(s,2)}`);
  }
  async function refresh(s) {
    const before = (await s.page.evaluate(() => document.getElementById('log').innerText)).length;
    await s.page.click('#btnRefresh');
    await s.page.waitForFunction((b) => /refreshed:|refresh failed/.test(document.getElementById('log').innerText.slice(b)), before, { timeout: 60000 });
    console.log(`[${s.name}] REFRESH -> ${await bal(s)}  ::  ${await logTail(s,1)}`);
  }

  try {
    const A = await session('A');
    const B = await session('B');
    await waitReady(A); await waitReady(B);
    console.log('\n=== Scenario: 2 delegates, sends ===');
    await open(A);                 // A -> delegate slot 3, balance 50
    await open(B);                 // B -> delegate slot 4, balance 50 (joins, A preserved)
    console.log('-- A re-checks after B joined --'); await refresh(A);
    console.log('-- A sends 7 to slot 4 (B) --'); await send(A, 4, 7);
    console.log('-- B refreshes, should see 57 --'); await refresh(B);
    console.log('-- A sends 5 to member slot 1 (sequential, A still can_send) --'); await send(A, 1, 5);
    console.log('-- A sends 3 to slot 4 again --'); await send(A, 4, 3);
    console.log('-- B refreshes again --'); await refresh(B);
    console.log('\n=== DONE ===');
  } catch (e) {
    console.error('FATAL', e.message);
    for (const n of Object.keys(sessions)) { try { console.log(`[${n}] final log:\n` + await sessions[n].page.evaluate(()=>document.getElementById('log').innerText)); } catch {} }
    await browser.close(); process.exit(1);
  }
  await browser.close();
})();
