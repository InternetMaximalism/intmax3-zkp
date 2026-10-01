'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-live.html'), 'utf8');
const source = html.slice(html.indexOf('function guard(key, fn)'), html.indexOf('function applyTicketState()'));
function render(ticket, failed = false, capabilities = { partialWithdrawal: true, channelClose: true }) {
  const elements = new Map();
  const $ = id => {
    if (!elements.has(id)) {
      const el = { disabled: false, value: '', textContent: '', hidden: true };
      el.classList = { toggle: (_name, hidden) => { el.hidden = hidden; } };
      elements.set(id, el);
    }
    return elements.get(id);
  };
  const ctx = { $, mySlot: 3, ticketLoadFailed: failed, _inflight: new Set(),
    ticketOfType: () => ticket, ticketAmountLabel: () => '0.005 ETH' };
  vm.createContext(ctx);vm.runInContext(source, ctx);
  ctx.__capabilities = capabilities; vm.runInContext('relayCapabilities = __capabilities;', ctx);
  ctx.restorePartialWithdrawalControls();
  return Object.assign($, { context: ctx });
}
test('a saved burn enables settlement directly in Withdraw and prevents another burn', () => {
  const $ = render({ status: 'burn_done', params: { recipient: '0xrecipient' } });
  assert.equal($('pwRecoveryStatus').hidden, false);
  assert.match($('pwRecoveryStatus').textContent, /Step 2/);
  assert.equal($('btnBurnSend').disabled, true);
  assert.equal($('btnPwSettle').disabled, false);
  assert.equal($('pwAddress').value, '0xrecipient');
  assert.equal($('pwAddress').disabled, true);
});
test('unavailable ticket state does not authorize a new burn or settlement', () => {
  const $ = render(null, true);
  assert.equal($('pwRecoveryStatus').hidden, false);
  assert.equal($('btnBurnSend').disabled, true);
  assert.equal($('btnPwSettle').disabled, true);
});
test('no pending withdrawal returns to normal burn controls', () => {
  const $ = render(null);
  assert.equal($('pwRecoveryStatus').hidden, true);
  assert.equal($('btnBurnSend').disabled, false);
  assert.equal($('btnPwSettle').disabled, true);
  assert.equal($('pwAddress').disabled, false);
});
test('a finalized payout still awaits wallet receipt and does not permit a new burn', () => {
  const $ = render({ status: 'claim_pending', params: { recipient: '0xrecipient' } });
  assert.equal($('btnBurnSend').disabled, true);
  assert.equal($('btnPwSettle').disabled, false);
  assert.match($('pwRecoveryStatus').textContent, /receive the funds/);
});
test('settlement completion releases controls after the in-flight guard is cleared', async () => {
  const $ = render({ status: 'burn_done', params: {} }), ctx = $.context;
  await ctx.guard('settle', async () => {
    ctx.ticketOfType = () => null;
    ctx.restorePartialWithdrawalControls();
    assert.equal($('btnBurnSend').disabled, true);
  })();
  assert.equal($('btnBurnSend').disabled, false);
  assert.equal($('btnPwSettle').disabled, true);
});
test('settlement failure enables a retry without allowing another burn', async () => {
  const $ = render({ status: 'burn_done', params: {} }), ctx = $.context;
  await assert.rejects(ctx.guard('settle', async () => { ctx.restorePartialWithdrawalControls(); throw new Error('retry'); })(), /retry/);
  assert.equal($('btnBurnSend').disabled, true);
  assert.equal($('btnPwSettle').disabled, false);
});

test('a second mutation cannot enter the worker session while another is awaiting',async()=>{
 const $=render(null),ctx=$.context;let release,calls=0;
 const first=ctx.guard('deposit',async()=>{await new Promise(r=>release=r);})();
 await ctx.guard('send',async()=>calls++)();await ctx.guard('clear',async()=>calls++)();
 assert.equal(calls,0);release();await first;
 await ctx.guard('send',async()=>calls++)();assert.equal(calls,1);
});
test('full withdrawal remains pending after L1 settlement until recipient claim',()=>{
 const start=html.indexOf('function isTerminalTicket('),end=html.indexOf('function guard(',start);
 const context={activeTickets:[{type:'full_withdrawal',status:'settle_done'}]};vm.createContext(context);vm.runInContext(html.slice(start,end),context);
 assert.equal(context.ticketOfType('full_withdrawal').status,'settle_done');
 assert.equal(context.isTerminalTicket({type:'partial_withdrawal',status:'settle_done'}),true);
 assert.equal(context.isTerminalTicket({type:'full_withdrawal',status:'claim_done'}),true);
});

// A public-chain relay cannot settle a burn on L1 yet: Withdraw must not offer a burn whose Step 2
// cannot run (that stranded a real 0.005 ETH burn on the v3 testnet), nor a settle that will fail.
test('without the withdrawal capability no burn and no settlement is offered', () => {
  const $ = render(null, false, { partialWithdrawal: false, channelClose: false });
  assert.equal($('btnBurnSend').disabled, true);
  assert.equal($('btnPwSettle').disabled, true);
  assert.match($('pwRecoveryStatus').textContent, /not available on this testnet/);
});
test('a saved burn on such a deployment is reported as kept, and nothing can be burned again', () => {
  const $ = render({ status: 'burn_done', params: { recipient: '0xrecipient' } }, false, { partialWithdrawal: false });
  assert.equal($('btnBurnSend').disabled, true);
  assert.equal($('btnPwSettle').disabled, true);
  assert.match($('pwRecoveryStatus').textContent, /Your burn of 0.005 ETH is saved/);
});
test('unknown capabilities (health not loaded) fail closed', () => {
  const $ = render(null, false, null);
  assert.equal($('btnBurnSend').disabled, true);
});
