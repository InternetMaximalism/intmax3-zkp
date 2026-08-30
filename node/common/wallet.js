'use strict';
// Delegate proving backend (DESIGN.md §2.2/§4). Wraps the WASM wallet built with
// `hosting/build-wallet-node-wasm.sh` (output dir `pkg-node/`). Secrets live
// only in the in-process WASM session and are never serialized (matches wasm_wallet.rs).
//
// The WASM module is LAZY-loaded so this file imports without the build present (pure-logic unit
// tests do not need it). If the module is missing, methods throw a clear, actionable error.

const path = require('path');

class Wallet {
  constructor({ pkgDir } = {}) {
    this.pkgDir = pkgDir || path.join(__dirname, '..', '..', 'pkg-node');
    this.wasm = null;
    this.initialized = false;
  }

  _load() {
    if (this.wasm) return this.wasm;
    let mod;
    try {
      // eslint-disable-next-line import/no-dynamic-require, global-require
      mod = require(path.join(this.pkgDir, 'intmax3_zkp.js'));
    } catch (e) {
      throw new Error(
        `WASM wallet not found at ${this.pkgDir}. Build it with: ` +
          `hosting/build-wallet-node-wasm.sh  (cause: ${e.message})`
      );
    }
    this.wasm = mod;
    return mod;
  }

  // Browser builds expose a wasm-bindgen-rayon pool. The CommonJS Node build deliberately uses
  // sequential fallbacks because wasm-bindgen-rayon's worker helper supports `web`, not `nodejs`.
  // Keep this conditional so the wrapper remains compatible with either packaging target.
  async initialize(numThreads) {
    if (this.initialized) return;
    const w = this._load();
    if (typeof w.initThreadPool === 'function') {
      const requested = numThreads == null ? 2 : Number(numThreads);
      if (!Number.isSafeInteger(requested) || requested < 1 || requested > 64) {
        throw new Error('wasmThreads must be an integer in 1..64');
      }
      await w.initThreadPool(requested);
    }
    this.initialized = true;
  }

  // Identity / session
  keygen(seedHex) {
    const w = this._load();
    return JSON.parse(seedHex ? w.wallet_keygen_seeded(seedHex) : w.wallet_keygen());
  }
  // B-1b: `recipient` (the user's L1 address, 0x-hex) is REQUIRED - it becomes the slot's
  // cosigner-signed leaf-bound exit address (the delegate's only payout binding).
  genesisContribution(balance, recipient) {
    return JSON.parse(this._load().wallet_genesis_contribution(BigInt(balance), recipient));
  }
  importChannel(snapshotJson, slot) {
    void slot; // the WASM wallet locates its own slot by key match
    this._load().wallet_import_channel(JSON.stringify(snapshotJson));
  }
  // Returns { slot, balance (token-0 scalar, wire compat), balances: [{tokenSlot, tokenIndex,
  // balance}], canSend, witnessTokenSlot, stateVersion } (multi-token §N).
  balance(slot) {
    void slot; // session-internal
    return JSON.parse(this._load().wallet_balance());
  }

  // Build the exact public claim + MLE/WHIR proof inside WASM. The Regev secret key never appears
  // in the returned artifact; finalizedContext is public manager state used to pin the proof to
  // the exact closed snapshot.
  withdrawalClaim(finalizedContext, tokenSlot = 0) {
    if (!Number.isSafeInteger(tokenSlot) || tokenSlot < 0 || tokenSlot > 9) {
      throw new Error('tokenSlot must be an integer in 0..9');
    }
    return JSON.parse(
      this._load().wallet_withdrawal_claim(JSON.stringify(finalizedContext), tokenSlot)
    );
  }

  // Own-tx proving (returns payloads to POST to the co-signer).
  // Multi-token (detail2 §N): every send-family wrapper takes an OPTIONAL trailing token
  // argument (undefined = the genesis token). Argument mapping FIXED to the actual
  // wasm-bindgen signatures (the previous wrappers passed extra positional args — senderSlot /
  // nonce / slot — that the generated JS silently dropped or, worse, shifted into the wrong
  // parameter): the sender slot and nonce are session-internal in wasm_wallet.rs.
  // wallet_send(recipient_slot: u16, amount: u64, token_slot?: u8)
  send(senderSlot, recipientSlot, amount, nonceHex, tokenSlot) {
    void senderSlot; void nonceHex; // session-internal in the WASM wallet (kept for API compat)
    return JSON.parse(this._load().wallet_send(recipientSlot, BigInt(amount), tokenSlot));
  }
  // wallet_refresh(token_slot?: u8) — refreshes THIS session's own slot at the token position.
  refresh(slot, tokenSlot) {
    void slot; // session-internal
    return JSON.parse(this._load().wallet_refresh(tokenSlot));
  }
  // wallet_send_inter_channel(..., token_index?: u32, base_nonce: u32)
  sendInterChannel(toChannel, toSlot, amount, destRecipientJson, tokenIndex, baseNonce) {
    if (!Number.isInteger(baseNonce) || baseNonce < 0 || baseNonce > 0xffffffff) {
      throw new Error('a current uint32 base nonce is required for an inter-channel send');
    }
    return JSON.parse(
      this._load().wallet_send_inter_channel(
        toChannel, toSlot, BigInt(amount), JSON.stringify(destRecipientJson), tokenIndex, baseNonce
      )
    );
  }
  // wallet_burn_send(amount, withdrawal_address_hex, token_index?: u32, base_nonce: u32)
  burnSend(amount, withdrawalAddrHex, tokenIndex, baseNonce) {
    if (!Number.isInteger(baseNonce) || baseNonce < 0 || baseNonce > 0xffffffff) {
      throw new Error('a current uint32 base nonce is required for a burn');
    }
    return JSON.parse(
      this._load().wallet_burn_send(BigInt(amount), withdrawalAddrHex, tokenIndex, baseNonce)
    );
  }

  // Verify every real member signature, verify/decrypt this wallet's own slot, and atomically
  // adopt the new head. wallet_finalize accepts a raw ChannelState (not an API response envelope)
  // and returns the new multi-token balance report.
  finalize(stateJson) {
    return JSON.parse(this._load().wallet_finalize(JSON.stringify(stateJson)));
  }

  available() {
    try { this._load(); return true; } catch (e) { return false; }
  }
}

module.exports = { Wallet };
