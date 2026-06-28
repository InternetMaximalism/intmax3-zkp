'use strict';
// Delegate proving backend (DESIGN.md §2.2/§4). Wraps the WASM wallet built with
// `wasm-pack build --release --target nodejs` (output dir `pkg-node/` by convention). Secrets live
// only in the in-process WASM session and are never serialized (matches wasm_wallet.rs).
//
// The WASM module is LAZY-loaded so this file imports without the build present (pure-logic unit
// tests do not need it). If the module is missing, methods throw a clear, actionable error.

const path = require('path');

class Wallet {
  constructor({ pkgDir } = {}) {
    this.pkgDir = pkgDir || path.join(__dirname, '..', '..', 'pkg-node');
    this.wasm = null;
  }

  _load() {
    if (this.wasm) return this.wasm;
    let mod;
    try {
      // eslint-disable-next-line import/no-dynamic-require, global-require
      mod = require(this.pkgDir);
    } catch (e) {
      throw new Error(
        `WASM wallet not found at ${this.pkgDir}. Build it with: ` +
          `wasm-pack build --release --target nodejs --out-dir pkg-node  (cause: ${e.message})`
      );
    }
    this.wasm = mod;
    return mod;
  }

  // Identity / session
  keygen(seedHex) {
    const w = this._load();
    return JSON.parse(seedHex ? w.wallet_keygen_seeded(seedHex) : w.wallet_keygen());
  }
  genesisContribution(balance) {
    return JSON.parse(this._load().wallet_genesis_contribution(BigInt(balance)));
  }
  importChannel(snapshotJson, slot) {
    this._load().wallet_import_channel(JSON.stringify(snapshotJson), slot);
  }
  balance(slot) {
    return JSON.parse(this._load().wallet_balance(slot));
  }

  // Own-tx proving (returns payloads to POST to the co-signer)
  send(senderSlot, recipientSlot, amount, nonceHex) {
    return JSON.parse(this._load().wallet_send(senderSlot, recipientSlot, BigInt(amount), nonceHex));
  }
  refresh(slot) {
    return JSON.parse(this._load().wallet_refresh(slot));
  }
  sendInterChannel(toChannel, toSlot, amount, destRecipientJson) {
    return JSON.parse(
      this._load().wallet_send_inter_channel(toChannel, toSlot, BigInt(amount), JSON.stringify(destRecipientJson))
    );
  }
  burnSend(amount, withdrawalAddrHex) {
    return JSON.parse(this._load().wallet_burn_send(BigInt(amount), withdrawalAddrHex));
  }

  // Verification + commit of a co-signed result (the delegate's verifyCosigned gate, DESIGN.md §4.4)
  cosignVerify(slot, proposedStateJson) {
    // wallet_cosign re-verifies the proposed state transition and returns this member's signature;
    // for a delegate we use it purely to validate the co-signed state structure/signatures.
    return JSON.parse(this._load().wallet_cosign(slot, JSON.stringify(proposedStateJson)));
  }
  finalize(finalizationJson) {
    this._load().wallet_finalize(JSON.stringify(finalizationJson));
  }

  available() {
    try { this._load(); return true; } catch (e) { return false; }
  }
}

module.exports = { Wallet };
