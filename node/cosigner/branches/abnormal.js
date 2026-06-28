'use strict';
// ABNORMAL branches: reject + score invalid requests, and enter defensive mode on attack
// (DESIGN.md §3.6, §3.8). Scoring is anti-griefing back-pressure, NOT a soundness control.

const { SIGNALS } = require('../state-machine');
const policy = require('../../common/policy');

async function rejectAndScore(event, ctx) {
  const { ch, store, log, alert } = ctx;
  const sender = (event.body && event.body.sender) || event.sender || 'unknown';
  const now = Date.now();
  const scores = store.get('scores') || {};
  const { rec, backPressured } = policy.scoreInvalid(scores[sender], now, ctx.policy);
  scores[sender] = rec;
  store.set('scores', scores);
  log.warn({ event: 'REQUEST_REJECTED', channel: ch.id, sender, count: rec.count, reason: event.reason || 'invalid' });
  if (backPressured) {
    await alert.raise('warn', ch.id, 'SENDER_BACKPRESSURED', `sender ${sender} exceeded invalid-request threshold`, { count: rec.count });
  }
  return { ok: false, status: 400, body: { error: event.reason || 'invalid request', backPressured } };
}

async function enterDefensiveMode(event, ctx) {
  const { ch, store, alert, sm } = ctx;
  store.setMode('defensive');
  sm.signal(SIGNALS.ATTACK);
  const rec = await alert.raise('attack', ch.id, event.code || 'ATTACK_SUSPECTED',
    event.message || 'entering defensive mode: co-signing paused for this channel',
    event.evidence || { kind: event.kind, txHash: event.txHash });
  store.pushAlert(rec);
  // For api-sourced events, refuse the request.
  if (event.source === 'api') return { ok: false, status: 503, body: { error: 'channel in defensive mode' } };
}

module.exports = { rejectAndScore, enterDefensiveMode };
