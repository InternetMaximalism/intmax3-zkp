# Threat model — browser wallet + CLI companion (Regev channel send/receive)

Status: drafted 2026-06-14, before Phase 1 implementation. Source: dedicated attacker subagent
review of the Regev channel model + existing browser stack. The crypto-circuit layer (E-1/E-2
STARK Fiat–Shamir, domain separation, Regev canonicality) is strong; residual risk is concentrated
in the **application layer** (what the wallet/CLI must enforce that the library leaves to the caller)
and **browser key handling**.

## Architecture recap
- One channel member runs in the browser (real SPHINCS+ + Regev keys, real funds). Other members
  run via the CLI companion (`src/bin/channel_member.rs`).
- In-channel transfer: sender builds a `ChannelTx` with an E-1 `prove_channel_tx` proof; the new
  `ChannelState` (with homomorphically updated `enc_balances`) is co-signed N-of-N via SPHINCS+ over
  `ChannelState::signing_digest()`. Off-chain co-signing is an agreement step; final enforcement is
  the validity proof + L1 (in-circuit SPHINCS+ verification).

## Must-do wallet/CLI requirements (priority order)
1. **Verify real SPHINCS+ signatures** on every `ChannelState` and `ChannelTx` the wallet signs or
   accepts. The repo's `validate_all_member_signatures` (`src/common/channel.rs`) only checks slot
   ordering + non-empty bytes — it does NOT run SLH-DSA verify. A native verifier DOES exist:
   `sphincsplus-poseidon::verify::crypto_sign_verify(sig, msg, pk)`. The wallet/CLI MUST call it.
   (Finding A-1 / E-1 / G-2 — the #1 requirement.)
2. **Decrypt own balance slot** on every state the wallet signs and confirm the plaintext matches
   expectation; for non-recipient slots, confirm the ciphertext is byte-identical to the previous
   state. Prevents a coordinator from quietly altering the wallet's own slot. (E-1.)
3. **Rebuild E-1/E-2 statements from the wallet's own authenticated prev/next `BalanceState`**, never
   from the tx carrier; **re-derive and match `regev_pk_root`** before encrypting to any recipient
   (`regev_pk_root(pks) == record.regev_pk_root`, order-sensitive). Never encrypt to a pk not under
   the signed root. (C-1 / F-1 — encryption-side key substitution = CRITICAL if skipped.)
4. **Anchor `ChannelRecord` provenance**: do not trust peer-supplied JSON as the channel's real
   record. Pin it against L1 registration (or a record digest captured at channel creation). Run all
   import re-verifications: `ChannelRecord::validate()`, `BalanceState::validate()`, member SPHINCS+
   sigs over the record + state digests, root match, own-slot decrypt, `digest == signing_digest()`,
   and `(epoch, state_version)` strictly extends the wallet's head by +1. (G.)
5. **Use `RegevSecurityLevel::Production`** for real funds — never `Test` (8 FRI queries ≈ no
   soundness). The Phase-0 probe uses `Test` and is clearly labelled probe-only. Draw the `ChannelTx`
   `nonce` from the CSPRNG per tx, never deterministically. (D / I-2.)
6. **Browser key hygiene** (defense in depth):
   - SharedArrayBuffer (wasm-bindgen-rayon + `+atomics`) means WASM linear memory is shared across all
     rayon worker threads — secrets are visible to every worker. Never load untrusted code into the
     proving workers; assume SAB = no in-process secret isolation. (H-1.)
   - COEP/COOP enables SAB but does not stop same-origin XSS. Ship a strict CSP, no inline scripts,
     SRI on all served JS/WASM, real TLS in production. (H-2 / H-5.)
   - Persistence: if keys are persisted, encrypt at rest under a passphrase-derived key (Argon2id /
     memory-hard KDF) using a non-extractable WebCrypto wrapping key; never store raw SPHINCS+ seed /
     Regev SK in cleartext localStorage. **Decide persistence model with the user before implementing.**
     (H-3.)
   - RNG: `rand010::rng()` → getrandom 0.4 `wasm_js` → `crypto.getRandomValues` (CSPRNG). Acceptable.
     Confirm the production build selects the wasm_js backend (done: Cargo.toml wasm-only feature) and
     that NO seeded/deterministic RNG path is reachable for real keygen/encryption. (H-4.)
   - Never log `AmountWitness` / `RegevSk` / seeds / witnesses across the worker boundary. (H-6.)

## Defended by the library (verify, then rely)
- Replay: `ChannelTx` binds `prev_state_digest`; linkage checks enforce `next.prev_digest ==
  prev.digest`, `epoch += 1`, `state_version += 1`. Wallet must still track its own head and refuse
  proposals that don't extend it by +1. (B.)
- Amount conservation / non-canonical ciphertext: enforced in-circuit + natively
  (`check_amount_witness`, `RegevCiphertext::validate`, `add_ciphertexts` mod-q reduce). (C.)
- E-1/E-2 substitution: purpose domain bound as public value #0, verifier rebuilds domain, published
  evals checked. Wallet must select Production level. (D.)

## Privacy boundaries (UX disclosure, not bugs)
- In-channel transfer amount is hidden; the recipient identity (pubkey hash) is visible to all
  co-signers (detail2 §A-1, dummy-delta obfuscation retired in v2). Surface this to the user. (I-1.)

## Post-implementation security review (2026-06-14)

A separate security-review subagent audited `src/wallet_core.rs`, `src/wasm_wallet.rs`,
`src/bin/channel_member.rs`. Verdict: core posture sound — real SLH-DSA verify over the correct
digest for every member, E-1 statement rebuilt from authenticated state, `regev_pk_root` re-derived
on import, recipient own-slot decryption, head/+1 (prev_digest + state_version) enforcement,
Production level everywhere funds move, secrets never serialized. No signature-bypass, replay, or
key-substitution hole. Findings to fix (tracked):
- **HIGH-1/HIGH-2/LOW-3 (DoS):** attacker-controlled `slot`/`member.slot` `u8` indices array
  `[_; 16]` without bound checks → wasm OOB trap. Fix: bound-check `slot < MAX_CHANNEL_MEMBERS`
  (and `< member_count`) before every index, in `wallet_sign_state`, `verify_snapshot`/import,
  `build_send`, `decrypt_balance`.
- **HIGH-1 (sign_state generality):** `wallet_sign_state` signs any digest-consistent state without
  head/linkage checks → restrict to genesis (`epoch==1 && state_version==0 && no sigs`).
- **MEDIUM-2:** CLI `cosign` bare-`ChannelState` branch signs a transition it never E-1-verified →
  require a `SendPayload` (carry the tx) so every cosigner verifies the transition.
- **MEDIUM-1:** validate `members` covers `0..member_count` bijectively on import.
Status: fixes applied in the hardening pass after the happy-path e2e (see doc/tasks/wallet-lessons.md).

## Open decision for the user
- **Key persistence**: session-only (keys vanish on reload; safest) vs passphrase-encrypted IndexedDB
  (convenience). Default to session-only unless the user wants persistence.
