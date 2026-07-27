# Threat model — in-channel $ITX testnet faucet

Scope: the `POST /api/faucet` relay endpoint, the CLI `refresh` command it depends on, the
`$ITX` testnet ERC-20, and the wallet UI that calls the endpoint. Implemented 2026-07-28 on
`feat/multitoken-channels`.

Out of scope (unchanged by this work): the circuits, the Lean models, the settlement contracts,
and every existing proof/verification path. The faucet introduces **no new protocol path** — a drip
is an ordinary in-channel transfer at a non-genesis token position, built and co-signed by exactly
the same `build_send_token` / `verify_send_transition` machinery as any other transfer.

---

## 1. Asset and adversary

**Asset.** A CLI co-signing member (the *faucet member*) holds an in-channel `$ITX` balance whose
supply is ONE real L1 ERC-20 deposit, escrowed in `IntmaxRollup` and imported once via
`cosign-l1-deposit-import`.

**Adversary.** Anyone on the internet. `POST /api/faucet` is unauthenticated and there is no
identity layer — a browser account is a locally generated key that joins as a delegate, so
"one per user" is not enforceable. The realistic goal is **draining the faucet**, plus the usual
"make the relay do something expensive or corrupt its state".

**What is NOT reachable, and why.** The faucet cannot MINT. In-channel balances at token position
`t` are constrained by `channel_fund.amounts[t]`, and that fund is written ONLY by the deposit
import (`build_l1_deposit_import`) — an in-channel transfer leaves it bit-identical
(`solo_next_state`), which `BalanceState::validate()` and every transition verifier enforce. So the
worst outcome of a total drain is that the faucet runs dry: every dripped balance stays fully
backed and claimable, and the L1 escrow is untouched. This is asserted end to end in
`tests/itx_faucet_cli_e2e.rs` (fund amount and `balanceOf(rollup)` both invariant across drips).

---

## 2. Attack surface and mitigations

| # | Attack | Mitigation | Where |
|---|--------|-----------|-------|
| F-1 | Faucet is live on a deployment that never meant to dispense | OFF unless `FAUCET_ENABLED=1` **and** a valid `FAUCET_SLOT` **and** a non-zero `ITX_TOKEN_INDEX`; every knob fails closed with a logged reason; `POST` answers 404 when off | `faucetConfig`, both relays |
| F-2 | Repeat drips to the same account | Once-per-slot record persisted per channel (`faucet_state.json`), **terminal** — a prior record in ANY status (`pending`/`done`/`failed`) refuses | `checkEligibility`, `reserveDrip` |
| F-3 | Sybil: many joins, many drips | Per-channel total cap (`FAUCET_CHANNEL_CAP`) + cooldown (`FAUCET_COOLDOWN_MS`); the cap bounds total exposure of one deposit regardless of join volume | `checkEligibility` |
| F-4 | Crash/kill between the ledger write and the transfer replays the drip | **Reserve before transfer**: the record and the cap increment are persisted BEFORE the CLI runs, and are never released on failure. A crash costs a drip; it cannot pay one twice | `reserveDrip`, endpoint ordering |
| F-5 | Caller asks for a bigger amount, another token, or another recipient | The request body supplies ONLY `slot`. Amount and token are server-side config; `localTokenSlot` is resolved from the channel's **cosigned** registry, never the `tokens.json` manifest | endpoint, `faucetLocalTokenSlot` |
| F-6 | Caller names a slot that does not exist, is padding, or is the faucet's own | `slot` must be an integer in `[0, member_count + delegate_count)` read from the SIGNED snapshot, and `!== FAUCET_SLOT`. Non-integers, numeric strings, floats, `NaN`, objects all refused | `checkEligibility` + tests |
| | **NOT claimed: slot OWNERSHIP.** The endpoint is unauthenticated and there is no signature challenge, so an anonymous caller may name ANY active slot — see residual risk R-1 | — | — |
| F-7 | Drip the channel's ETH backing | `ITX_TOKEN_INDEX = 0` is rejected at config time (index 0 is contract-reserved native ETH); the wallet also refuses to advertise a native-index faucet | `faucetConfig`, `loadFaucetInfo` |
| F-8 | Delete/corrupt `faucet_state.json` to reset idempotency | A corrupt ledger **throws** (500) instead of resetting to empty. Deletion still re-opens the faucet — documented in both runbooks as operator state, not cache. (Accepted: filesystem write access to the relay already implies full control of the co-signing keys.) | `normalizeState` + runbooks |
| F-9 | Concurrency: two simultaneous requests for one slot | The whole check→reserve→transfer sequence runs inside the existing per-channel `withLock` mutex, the same one that serializes every mutating CLI call. **`withLock` is in-process JS state, not a file lock** — see deployment invariant D-1 | endpoint |
| F-10 | Amount overflow / float mis-comparison at the cap | Amounts are decimal strings compared as `BigInt` (an 18-decimal cap is past `Number.MAX_SAFE_INTEGER`); drip and cap are additionally rejected above the u64 in-channel base-unit ceiling at config time | `parseAmount`, `faucetConfig` |
| F-11 | Two relay implementations drift apart | ONE shared policy module (`node/common/faucet-policy.js`) required by both relays; if it cannot be loaded the faucet stays disabled — it is never re-implemented inline (same discipline as `token-registry.js`) | both relays |
| F-12 | Metadata spoofing in the faucet notice ("get 1 USDC!") | The advertised grant is rendered under the existing rules: raw base units and `#index` unless that token's metadata is chain-verified against `tokenAddressOf` | `faucetGrantText` → `describeToken` |
| F-13 | A wrong `decimals` misrenders the grant/balance by 10^k (address verification constrains it not at all) | `decimals()` is now READ BACK from the token and compared to the manifest: a mismatch is fatal at startup, an unreadable/absent `decimals()` serves `decimals: null` (raw base units) — never a guessed 18 | `verifyAgainstChain` §3.4 |

---

## 3. Cryptographic changes and their justification

The faucet needed one genuinely new CLI capability, and one fix that the new usage pattern exposed.

### 3.1 `channel_member refresh <slot> [token_slot]` (new)

A position credited **homomorphically** — which is exactly what a deposit import produces
(`enc_balances[r][t] += delta`, `pending_adds[r][t] += 1`) — is unspendable twice over:
`build_send_token` refuses on the D3/TM-13 `pending_adds != 0` gate, and the CLI holds no
encryption witness for the accumulated ciphertext. `refresh` is the value-preserving way out and is
the exact CLI twin of the browser's `wallet_refresh`.

Soundness argument:
- It calls the **existing** `build_refresh` / `verify_refresh_transition` pair. `RefreshAir` proves
  `old_ct` and `new_ct` encrypt the SAME hidden value; the structural witness proves only this
  `(slot, token)` position changed and its counter reset. Nothing new is trusted.
- Every CLI-controlled member re-runs the adversarial gate before signing (check-and-sign), and the
  head advances only after `verify_all_signatures` — the same pattern as `register-token`.
- Only a CLI-**controlled** slot can be refreshed: the refresh proof needs that slot's Regev secret
  key, so this cannot touch a delegate's position.

### 3.2 Witness reproducibility (new persisted state)

`cli_state.json` gains `ControlledMember.token_witnesses[]`, each `{token_slot, amount, seed_hex,
has_witness}`. `seed_hex` is **32 bytes from the OS CSPRNG**, and re-seeding a `StdRng` with it
reproduces the refreshed ciphertext because `prove_balance_refresh_witnessed`'s first and only RNG
consumption is the `encrypt_amount` that produces `new_ct`.

That invariant is **not assumed**: `cmd_refresh` replays the seed and compares against the
ciphertext the co-signed state actually installs, and `die()`s rather than recording an unusable
witness. It is also pinned as a unit test
(`wallet_core::delegate_send_tests::refresh_unblocks_a_homomorphically_credited_token_position`),
so an upstream change in RNG consumption fails loudly instead of surfacing as a confusing E-1
failure on a later send.

The legacy genesis triple (`balance_seed`, u64) is untouched for token position 0, so every
pre-existing flow is byte-identical; a refresh record always wins over it for the same position,
and a token-0 refresh explicitly retires it.

### 3.3 `send` encryption randomness (FIX)

`cmd_send` previously seeded its RNG with the constant `0x5E_0000 + from`. That was safe only
because *"each CLI member sends at most once from its fresh genesis balance"* (the module header).
A faucet member sends repeatedly, and reusing one Regev `r` across two different plaintexts under
one key reveals their difference (`c2 - c2' = Δ·(m - m')`) — for balances, the balance itself.
`cmd_send` now draws 32 bytes from the OS CSPRNG per invocation. Sends become nondeterministic;
nothing downstream depended on byte-identical payloads (the co-sign path re-verifies the proof).

`gen-send` (the stateless browser simulator) had the SAME defect and is fixed the same way. Its
genesis guard — refuse unless the position is still its untouched genesis ciphertext — only stops
reuse ACROSS co-signed states; it does NOT stop two `gen-send` calls made against the same,
still-untouched genesis state, because neither has been co-signed, so both pass the guard and both
replay the same `r`. Anyone who sees both drafted payloads then learns the difference of the two
amounts (and, since `balance` is a CLI argument, the second amount outright). `seed` still selects
the delegate IDENTITY and its genesis witness, which is the only thing that simulator needs to be
deterministic about.

### 3.4 Token `decimals` verification (metadata layer, surfaced by this feature)

`node/common/token-registry.js` previously read back only `tokenAddressOf` and `eth_chainId`, so a
`verified: true` entry's `decimals` rested on the operator's word alone — while the module's own
security contract names a misplaced decimal point as a user-funds attack, and address verification
constrains it not at all. `decimals()` is now read from the TOKEN with the same raw `eth_call` +
pinned-selector pattern (drift-guarded against the ethers fragment in the test suite):

| observation | outcome |
|---|---|
| `decimals()` == manifest | `decimalsVerified: true`, decimals served |
| `decimals()` != manifest | **THROW** — same as an address mismatch; relay/node refuse to start |
| `decimals()` reverts / absent / not a uint8 | address verification STANDS, `decimals: null` + warn — never a guessed 18 |
| RPC read failure | as above (`decimals: null` + warn) |
| native base index 0 | exempt (no contract to read; ETH's 18 is protocol-fixed) |
| `observeTokenRegistered` promotion | address only — `decimalsVerified` stays false (that path cannot make an RPC call) |

This degrades safely with NO client change: the wallet's `sanitizeTokenMeta` already treats a
null/malformed `decimals` as unverified and falls back to the raw base index + raw base units.

### 3.5 `$ITX` uses 6 decimals, not 18

In-channel balances are u64 base units, so a channel position tops out at `u64::MAX / 10**decimals`
whole tokens: ~18.44 at 18 decimals versus ~18.4 trillion at 6. The original 18 put a 10 ITX faucet
supply at 0.54 of `u64::MAX` (1.8x headroom) and forced unnatural 0.01/5/10 defaults. Nothing
depends on the constant — it is a lone value in the contract, escrow/deposit accounting is raw base
units, and `fmtUnits(base, decimals)` is generic (the hardcoded 18 applies only to native ETH at
index 0). The contract constant, the manifest entry, the faucet defaults and the E2E constants are
changed together, and §3.4's read-back is exactly what catches them drifting apart.

### 3.6 Other fixed-seed RNG sites in the CLI (audited, not all bugs)

- `build_inter_channel_credit` call site: the callee opens with `let _ = rng;` (which MOVES the
  `&mut`, so the borrow checker forbids any later use) and encrypts nothing — the credit is a
  deterministic homomorphic add of the descriptor's `receiver_deltas`, which the SOURCE channel
  already encrypted. The old `0xC2_0000 + recipient_slot` seed was therefore DEAD, not reused. It
  was still a trap, so the call site now seeds from the OS CSPRNG; the change cannot alter
  behaviour because the value is discarded.
- `cosign-l1-deposit-import`: the fixed `0xDE_0517 ^ channel_id` seed is SAFE and load-bearing. It
  encrypts `amount`, a PUBLIC L1 deposit value (an argument of the `deposit()` transaction, in the
  deposit hash chain, and in `channel_fund` in the clear), so reuse can leak only the difference of
  two already-public numbers. Its determinism is required by the TM-7 co-signer gate, which
  REBUILDS the same `recipient_delta` and demands digest equality. Documented inline; unchanged.

### 3.7 Post-send state

The send's `after_ct` randomness is not recorded, so the sent position is marked witness-less and
must be refreshed before the next drip. That is why the relay runs `refresh` → `send` → `cosign`
per drip. Cost: one extra (small) STARK per drip. Benefit: exactly one code path, no second
witness-reconstruction scheme, and no stale witness can survive a send.

---

## 4. Deployment invariants (enforced by the operator, not by code)

- **D-1: exactly ONE relay process per channel directory.** The per-channel mutex that makes
  check→reserve→transfer atomic is in-process JavaScript state, not an `flock`. Two processes
  sharing one `wallet-live-work/ch<N>/` (cluster mode, an accidental second launch, a blue/green
  overlap) could both pass the eligibility check before either reserves, and double-drip a slot.
  No clustering exists today — the relay is a single process on a single box, and every other
  mutating endpoint already depends on the same mutex — so this is DOCUMENTED rather than locked.
  Stated in both runbooks' faucet sections. If the relay is ever clustered, the ledger needs a real
  file lock before the faucet is re-enabled.

## 5. Residual risks / accepted limitations

- **R-1: an anonymous caller can walk every active slot and exhaust `FAUCET_CHANNEL_CAP`.** There
  is no ownership proof on `slot` (F-6): the endpoint validates only that the slot exists, is
  active, and is not the faucet's. So one caller can request a drip for every joined account.
  Value LANDS WITH THE LEGITIMATE SLOT OWNERS — the recipient is a balance slot in the channel's
  own signed membership, so nothing is stolen and nothing is unbacked — but the channel's faucet
  allowance is consumed and other users get nothing. This is the same exhaustion outcome as R-2
  and is bounded by the same cap. Accepted for a testnet faucet; closing it properly needs a
  signature challenge against the slot's `pk_g`, which is a separate change.
- **R-2: a determined Sybil can exhaust the channel cap** by joining many accounts. Accepted: the
  cap bounds the loss to a configured slice of one deposit, and a dry faucet degrades to the
  pre-faucet UX (join with balance 0).
- **R-3: a transient failure consumes the caller's single drip.** Deliberate (F-4). Re-opening a
  slot is an operator action on `faucet_state.json`, not something an anonymous caller can drive.
- **R-4: deleting `faucet_state.json` re-opens the faucet** to everyone who already drank (F-8).
  Documented in both runbooks. A file that merely parses to `null` no longer counts as "absent" —
  that is corruption and fails closed.
- **R-5: faucet-member balance is not confidential.** The CLI cosigners derive their keys from
  PUBLIC seeds, so their in-channel balances were never private against anyone reading the source.
  The faucet does not change this; the OS-CSPRNG seeds in §3 are about randomness REUSE, not
  secrecy.
- **R-6: the drip is one transaction per request**, serialized by the per-channel lock, so a burst
  of joins queues behind proving. Not a safety issue; a throughput one. The cooldown makes it
  explicit.
