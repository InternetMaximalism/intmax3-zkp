'use strict';

// Rust serde uses `rename_all = "camelCase"` for every channel wire object. During a rolling
// upgrade we still accept the historical snake_case aliases, but never let conflicting aliases
// choose different security-critical values silently.
function field(obj, camel, snake) {
  if (!obj || typeof obj !== 'object') return undefined;
  const hasCamel = Object.prototype.hasOwnProperty.call(obj, camel);
  const hasSnake = snake && Object.prototype.hasOwnProperty.call(obj, snake);
  if (hasCamel && hasSnake) {
    if (canonical(obj[camel]) !== canonical(obj[snake])) {
      throw new Error(`conflicting wire aliases ${camel}/${snake}`);
    }
    return obj[camel];
  }
  if (hasCamel) return obj[camel];
  return hasSnake ? obj[snake] : undefined;
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function bytes32(value) {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value)
    ? value.toLowerCase()
    : null;
}

function descriptorTxHash(descriptor) {
  return bytes32(field(descriptor, 'txHash', 'tx_hash'));
}

function proposedState(payload) {
  return field(payload, 'proposedNextState', 'proposed_next_state');
}

function stateFromResponse(resp) {
  if (!resp || typeof resp !== 'object') return null;
  return resp.state || proposedState(resp) || field(resp, 'refreshedState', 'refreshed_state') || resp;
}

function balanceState(state) {
  return field(state, 'balanceState', 'balance_state') || {};
}

function memberSignatures(state) {
  return field(state, 'memberSignatures', 'member_signatures');
}

function stateVersion(state) {
  return field(balanceState(state), 'stateVersion', 'state_version');
}

function prevDigest(state) {
  return field(state, 'prevDigest', 'prev_digest');
}

function channelTx(obj) {
  return field(obj, 'channelTx', 'channel_tx');
}

function lastChannelTx(obj) {
  return field(obj, 'lastChannelTx', 'last_channel_tx');
}

module.exports = {
  field,
  canonical,
  bytes32,
  descriptorTxHash,
  proposedState,
  stateFromResponse,
  balanceState,
  memberSignatures,
  stateVersion,
  prevDigest,
  channelTx,
  lastChannelTx,
};
