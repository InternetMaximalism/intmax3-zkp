// Throwaway Phase-0 runner: load the feasibility page headlessly and report the probe result.
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ args: ['--ignore-certificate-errors'] });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  page.on('console', (m) => console.log('[page]', m.text()));
  page.on('pageerror', (e) => console.log('[pageerror]', e.message));
  await page.goto('https://localhost:8000/wallet-feasibility.html', { waitUntil: 'load' });
  try {
    await page.waitForFunction(() => {
      const el = document.getElementById('out');
      return el && (el.dataset.status === 'ok' || el.dataset.status === 'error');
    }, { timeout: 180000 });
  } catch (e) {
    console.log('TIMEOUT waiting for probe result');
  }
  const status = await page.$eval('#out', (el) => el.dataset.status || 'pending');
  const text = await page.$eval('#out', (el) => el.textContent);
  console.log('--- STATUS:', status, '---');
  console.log(text);
  await browser.close();
  process.exit(status === 'ok' ? 0 : 1);
})();
