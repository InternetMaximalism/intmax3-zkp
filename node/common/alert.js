'use strict';
// Alert sink for abnormal-flow escalations (DESIGN.md §3.6-3.8, §4.6-4.8, §5.3).
// Security alerts are MANDATORY and never silently swallowed (CLAUDE.md). They go to stderr and,
// if configured, an HTTP webhook (best-effort, non-blocking). An alert is also appended to the
// channel store's alert log by the caller for durable forensics.

const log = require('./log');

let webhookUrl = process.env.INTMAX_ALERT_WEBHOOK || null;

function configure({ webhook } = {}) {
  if (webhook) webhookUrl = webhook;
}

// severity: 'attack' | 'fault' | 'warn'. `evidence` is a small JSON-safe object (digests, ids).
async function raise(severity, channel, code, message, evidence = {}) {
  const rec = log.error({ event: 'ALERT', severity, channel, code, message, evidence });
  if (webhookUrl) {
    try {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(rec),
      });
    } catch (e) {
      // Webhook failure must not crash the loop; the stderr alert above is the durable record.
      log.warn({ event: 'ALERT_WEBHOOK_FAILED', error: String(e && e.message || e) });
    }
  }
  return rec;
}

module.exports = { configure, raise };
