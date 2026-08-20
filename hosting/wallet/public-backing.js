'use strict';

// `channel_backing.json` is an operator-side persistence record, not a public response object. In
// particular it contains `FullPrivateState` (asset/nullifier/sent-tx trees and the blinding salt).
// Public routes use this explicit allowlist so a future private field is withheld by default.
const PUBLIC_FIELDS = Object.freeze([
  'settled_tx_chain', 'settledTxChain',
  'intmax_state_root', 'intmaxStateRoot',
  'fund', 'rollup',
  'deposit_tx', 'depositTx',
  'backing_deposit_txs', 'backingDepositTxs',
  'backing_deposit_status', 'backingDepositStatus',
  'deposit_recipient', 'depositRecipient',
]);

function publicBacking(backing) {
  if (!backing || typeof backing !== 'object' || Array.isArray(backing)) {
    throw new Error('invalid channel backing record');
  }
  const out = {};
  for (const key of PUBLIC_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(backing, key)) out[key] = backing[key];
  }
  return out;
}

function baseHead(backing) {
  if (!backing || typeof backing !== 'object' || Array.isArray(backing)) {
    throw new Error('invalid channel backing record');
  }
  const privateState = backing.base_private_state || backing.basePrivateState;
  const nonce = privateState && privateState.nonce;
  if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff) {
    throw new Error('live base state is unavailable; migrate the channel backing before sending');
  }
  return {
    schemaVersion: 1,
    nonce,
    settledTxChain: backing.settled_tx_chain ?? backing.settledTxChain ?? null,
    intmaxStateRoot: backing.intmax_state_root ?? backing.intmaxStateRoot ?? null,
  };
}

module.exports = { publicBacking, baseHead };
