const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch({ args:['--ignore-certificate-errors'] });
  const p = await (await b.newContext({ ignoreHTTPSErrors:true })).newPage();
  p.setDefaultTimeout(300000);
  p.on('console', m => console.log('[console.'+m.type()+']', m.text()));
  p.on('pageerror', e => console.log('[pageerror]', e.message));
  await p.goto('https://localhost:8000/wallet-live.html', { waitUntil:'load' });
  await p.waitForSelector('#btnOpen:not([disabled])', { timeout:120000 });
  await p.click('#btnOpen');
  await p.waitForFunction(() => document.getElementById('balance').textContent === '50', null, { timeout:180000 });
  console.log('--- opened, balance 50; sending ---');
  await p.fill('#toSlot','1'); await p.fill('#amount','7');
  await p.click('#btnSend');
  // wait up to 120s for either balance change or an error in the log
  await p.waitForFunction(() => { const l=document.getElementById('log').textContent; return l.includes('new balance') || l.includes('failed'); }, null, { timeout:160000 }).catch(()=>{});
  console.log('--- LOG ---\n' + await p.$eval('#log', e=>e.textContent));
  console.log('--- balance:', await p.$eval('#balance', e=>e.textContent));
  await b.close();
})().catch(e => { console.error('DEBUG ERR:', e.message); process.exit(1); });
