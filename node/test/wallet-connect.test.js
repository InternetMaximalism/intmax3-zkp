'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../../hosting/wallet/wallet-live.html'), 'utf8');
const source = html.split('// ---- Connect existing account ')[1].split('// ---- JOIN ')[0];
// Drop the remainder of the first comment line, then exercise the actual shipped functions.
const script = source.slice(source.indexOf('\n') + 1);

function harness({ seed = 'test-existing-key', saved = 8, failure, metadataFailure = false, returnedChannel = 10 } = {}) {
  const elements = new Map();
  const events = [];
  const storage = new Map(seed ? [['seed', seed]] : []);
  const context = {
    activeCh: 7, mySlot: null, SEED_KEY: 'seed',
    $: id => {
      if (!elements.has(id)) elements.set(id, { value: id === 'joinChannel' ? '10' : '', disabled: false, textContent: '' });
      return elements.get(id);
    },
    localStorage: { getItem: key => storage.get(key) || null },
    hasSavedAccount: () => !!storage.get('seed'), savedChannel: () => saved,
    saveChannel: channel => events.push(['saveChannel', channel]),
    guard: (_key, fn) => fn,
    call: async (action, payload) => {
      events.push([action, payload]);
      if (action === 'keygenSeeded') return '{}';
      assert.equal(action, 'importChannel');
      if (failure) throw new Error(failure);
      return JSON.stringify({ slot: 3, balance: '123', stateVersion: 4 });
    },
    api: async (url, body, method) => {
      events.push(['api', url, body, method]);
      assert.equal(url, '/api/snapshot'); assert.equal(method, 'GET');
      return JSON.stringify({ record: { channelId: returnedChannel } });
    },
    setChannelFrom: () => events.push(['adopt']),
    showBalance: r => events.push(['balance', r.balance]),
    showJoined: () => events.push(['showJoined']),
    formatAddr: (ch, slot) => `${ch}-${slot}`, fmtAmt: String,
    log: message => events.push(['log', message]),
    loadTokenMeta: async () => { if (metadataFailure) throw new Error('metadata offline'); },
    loadFaucetInfo: async () => {}, renderFaucetUi: () => {},
    fetchTickets: async () => {}, applyTicketState: () => {},
  };
  vm.createContext(context); vm.runInContext(script, context);
  return { context, events, elements, storage };
}

test('Connect opens the selected channel with the saved key, without init or a deposit', async () => {
  const h = harness();
  assert.equal(await h.context.connectExistingChannel(), true);
  assert.equal(h.context.activeCh, 10);
  assert.equal(h.context.mySlot, 3);
  assert.equal(h.events.find(e => e[0] === 'keygenSeeded')[1].seed, 'test-existing-key');
  assert.ok(h.events.some(e => e[0] === 'showJoined'));
  assert.ok(h.events.some(e => e[0] === 'saveChannel' && e[1] === 10));
  assert.deepEqual(h.events.filter(e => e[0] === 'api').map(e => e[1]), ['/api/snapshot']);
  assert.equal(h.elements.get('btnOpen').disabled, false);
});

test('Connect without a saved key never creates keys or invokes a relay request', async () => {
  const h = harness({ seed: null });
  assert.equal(await h.context.connectExistingChannel(), false);
  assert.equal(h.events.some(e => ['keygenSeeded', 'api', 'saveChannel', 'showJoined'].includes(e[0])), false);
  assert.match(h.elements.get('connectStatus').textContent, /No channel key/);
  assert.equal(h.storage.size, 0);
});

test('wrong-key restoration preserves identity and gives recovery guidance instead of Join', async () => {
  const h = harness({ failure: "this wallet's key is not a member of the imported channel" });
  assert.equal(await h.context.connectExistingChannel(), false);
  assert.equal(h.storage.get('seed'), 'test-existing-key');
  assert.equal(h.events.some(e => ['adopt', 'saveChannel', 'showJoined'].includes(e[0])), false);
  assert.match(h.elements.get('connectStatus').textContent, /does not match a member/);
});

test('snapshot failures stay visible and do not change the saved channel', async () => {
  const h = harness();
  h.context.api = async () => { throw new Error('relay unavailable'); };
  assert.equal(await h.context.connectExistingChannel(), false);
  assert.match(h.elements.get('connectStatus').textContent, /relay unavailable/);
  assert.equal(h.events.some(e => e[0] === 'saveChannel'), false);
});

test('a snapshot for another channel cannot establish a connection', async () => {
  const h = harness({ returnedChannel: 9 });
  assert.equal(await h.context.connectExistingChannel(), false);
  assert.equal(h.events.some(e => ['importChannel', 'showJoined', 'saveChannel'].includes(e[0])), false);
});

test('ancillary metadata failure does not undo verified account connection', async () => {
  const h = harness({ metadataFailure: true });
  assert.equal(await h.context.connectExistingChannel(), true);
  assert.ok(h.events.some(e => e[0] === 'showJoined'));
  assert.ok(h.events.some(e => e[0] === 'log' && /additional account information/.test(e[1])));
});

test('automatic restoration uses the saved channel through the same connect path', async () => {
  const h = harness({ saved: 8, returnedChannel: 8 });
  assert.equal(await h.context.tryRestore(), true);
  assert.equal(h.context.activeCh, 8);
  assert.ok(h.events.some(e => e[0] === 'saveChannel' && e[1] === 8));
});

function depositHarness(balances) {
  const h = harness();
  const requests = [];
  let opens = 0;
  Object.assign(h.context, {
    fetchDepositInfo: async () => ({ chainId: 31337 }),
    ensureChain: async () => {},
    renderDepositTokens: () => {},
    depositTokenOptions: [
      { native: true, tokenIndex: 0, label: 'ETH' },
      { native: false, tokenIndex: 2, label: 'TEST', address: '0x' + '22'.repeat(20) },
    ],
    walletAccount: '0x' + '11'.repeat(20),
    padHex: (hex, bytes) => hex.slice(2).padStart(bytes * 2, '0'),
    walletProvider: { request: async request => {
      requests.push(request);
      const value = balances[request.method];
      if (value instanceof Error) throw value;
      return value;
    } },
    openDeposit: async () => { opens++; },
    renderDepositPreview: () => {},
  });
  return { ...h, requests, opens: () => opens };
}

test('join offers Deposit for a funded ETH wallet without sending a transaction', async () => {
  const h = depositHarness({ eth_getBalance: '0x1' });
  await h.context.offerDepositAfterJoin();
  assert.equal(h.opens(), 1);
  assert.equal(h.context.$('depositToken').value, '0');
  assert.deepEqual(h.requests.map(r => r.method), ['eth_getBalance']);
});

test('join offers the ERC-20 selector when ETH is zero but an accepted token has balance', async () => {
  const h = depositHarness({ eth_getBalance: '0x0', eth_call: '0x5' });
  await h.context.offerDepositAfterJoin();
  assert.equal(h.opens(), 1);
  assert.equal(h.context.$('depositToken').value, '2');
  assert.equal(h.requests[1].params[0].data, '0x70a08231' + '0'.repeat(24) + '11'.repeat(20));
  assert.equal(h.requests[1].params[0].to, '0x' + '22'.repeat(20));
});

test('zero balances do not open Deposit; failed reads are not reported as zero', async () => {
  const h = depositHarness({ eth_getBalance: '0x0', eth_call: '0x0' });
  await h.context.offerDepositAfterJoin();
  assert.equal(h.opens(), 0);
  const failed = depositHarness({ eth_getBalance: new Error('offline'), eth_call: '0x0' });
  await failed.context.offerDepositAfterJoin();
  assert.equal(failed.opens(), 0);
  assert.ok(failed.events.some(e => e[0] === 'log' && /incomplete/.test(e[1])));
});

const selectionSource = html.split('// ---- Select channels served by this relay ')[1].split('// ---- Connect existing account ')[0];
function selectionHarness(channels, saved) {
  const events = [], elements = {btnOpen: {}, joinChannel: {}, connectStatus: {}};
  const context = { activeCh: 7, $: id => elements[id],
    fetch: async () => ({ok: true, json: async () => ({channels})}),
    savedChannel: () => saved, showBacking: () => events.push('backing'),
    guard: (_key, fn) => fn, tryRestore: async () => events.push('restore'),
  };
  vm.createContext(context);vm.runInContext(selectionSource.slice(selectionSource.indexOf('\n') + 1), context);
  return {context, events, elements};
}
test('replacement relay selects its first channel and preserves the old saved identity', async () => {
  const h = selectionHarness([17,18],7);
  await h.context.initializeChannelSelection();
  assert.equal(h.context.activeCh,17);
  assert.equal(h.elements.joinChannel.value,17);
  assert.equal(h.elements.btnOpen.disabled,false);
  assert.deepEqual(h.events,['backing']);
  assert.match(h.elements.connectStatus.textContent,/Channel 7 is preserved/);
});
test('relay channel selection restores a saved channel only when it is served', async () => {
  const h = selectionHarness([17,18],18);
  await h.context.initializeChannelSelection();
  assert.equal(h.context.activeCh,18);
  assert.deepEqual(h.events,['backing','restore']);
});
test('invalid relay channel list leaves Join disabled', async () => {
  const h = selectionHarness([17,'18'],7);
  await assert.rejects(h.context.initializeChannelSelection(),/invalid available channels/);
  assert.equal(h.elements.btnOpen.disabled,true);
  assert.deepEqual(h.events,[]);
});
