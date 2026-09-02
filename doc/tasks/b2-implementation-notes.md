# B-2 implementation notes — delegate-close fence (close PI limb 94) + A-1 join backing

Branch: `feat/falcon-poseidon-sig` (base HEAD e3a4500). **Nothing committed.**
Spec implemented: `doc/tasks/b2-delegate-close-threat-model.md`, **option (d)**, plus the
owner-approved A-1 join-time conservation control.

---

## 1. What changed (option (d))

### `contracts/src/ChannelSettlementVerifier.sol`

- New constants: `MAX_CHANNEL_PARTICIPANTS = 1024` (mirror of Rust `MAX_CHANNEL_MEMBERS`,
  `src/constants.rs:96` — the balance-slot capacity, distinct from the pre-existing
  `MAX_CHANNEL_MEMBERS = 16` cosigner cap) and `CLOSE_PI_DELEGATE_COUNT_INDEX = 94`.
- New error `CloseDelegateCountOutOfRange()`, deliberately distinct from `"close limb mismatch"`.
- `verifyCloseIntent`:
  1. **hoisted** `require(pi.length == CLOSE_PI_LEN, "close pi len")` out of `_bindCloseLimbsStrict`
     (A-4: `pi[94]` is now read before the loop, so a short calldata array would be an OOB read);
  2. **hoisted** `require(delegateCount < LIMB_BOUND, "close limb range")` for limb 94 only (A-5:
     canonicality before any arithmetic, so the failure mode is the explicit error, never a panic);
  3. floor: `delegateCount >= fields.minDelegateCount` → `CloseDelegateCountOutOfRange`;
  4. ceiling: `fields.memberCount + delegateCount <= 1024` → same error;
  5. the validated value is passed explicitly into `_expectedCloseLimbs`.
- `_expectedCloseLimbs(fields, uint256 delegateCount)` — limb 93 is still written from
  `fields.memberCount` (strict, A-6); limb 94 is written from the validated argument. The strict
  103-limb loop and `_bindCloseLimbsStrict` are **otherwise unchanged**; **no limb is left free.**
- `expectedCloseLimbs` (test-introspection view) gained an explicit `uint32 delegateCount`
  parameter and documents that it does not apply the predicate.

### `contracts/src/ChannelSettlementManager.sol`

- `CloseProofFields.memberAndDelegateCount (uint16)` → `uint8 memberCount` + `uint32
  minDelegateCount` (A-10: counts above 255 are now representable in the close path at all).
- `_runCloseVerify` passes `minDelegateCount = activeDelegateCount`.
- The `SECURITY:` block on `_checkCloseProof` rewritten to state the actual trust model: the member
  half of the boundary is L1-rooted (limb 93 + IMCM + registry cross-check), the delegate half is
  cosigner-rooted (the signed H1 at limbs 17..24) by the Option B decision, and L1 enforces only
  monotonicity + capacity. `activeDelegateCount`'s doc comment now says it is a FLOOR.
- **ABI**: the struct change means Manager and Verifier must be deployed as a pair. Confirmed side
  effect: the Manager's creation code changed, so its CREATE2 address moved (see §4, fixtures).

### Call sites updated (all of them; `forge build` is the check)

`contracts/test/CloseSettlementBase.sol`, `contracts/test/ChannelSettlementManager.t.sol`,
`contracts/test/PartialWithdrawal.t.sol`, `contracts/script/SubmitPartialWithdrawal.s.sol`.
`contracts/script/DeployCloseCli.s.sol` got a comment that `delegateCount` is now a floor (no
semantic change). The other deploy scripts pass the count straight through and needed nothing.

### Rust (no circuit, no PI layout, no VK, no witness change)

- `tests/two_token_cli_e2e.rs`: the pinned EXPECTED-NEGATIVE close (`!close_ok` +
  `"close limb mismatch"`) is now a pinned POSITIVE (close accepted, channel `ClosePending`), with
  an in-place comment explaining why this is not a weakened assertion (see §3). Header doc and the
  final `eprintln!` updated. `cli_allow_fail` is now unused — **kept**, marked `#[allow(dead_code)]`
  with a note, not deleted.
- `tests/close_lifecycle_cli_e2e.rs`: header note that this lifecycle's `close` step was
  unreachable before B-2 and is expected to land now. No assertion changed (it already expected
  success).
- `src/bin/channel_member.rs:1712` fence comment retired; `cmd_export_reg_record` keeps
  `delegate_count = 0`, now documented as correct-by-design rather than tolerated.

---

## 2. A-1 — the outcome, and the argument

**Outcome: fixed, within the Solidity + Rust-CLI radius. No circuit change, no new VK, no fixture
regeneration for it.** The control is in `src/bin/channel_member.rs`:

- `join_delegate` no longer takes the joiner-supplied `RegevCiphertext` at all (the parameter is
  gone from the signature, and `cmd_init` passes it only to the genesis `create_channel` path);
- the new delegate's slot opens at `zero_token_row()` — the canonical all-zero Regev ciphertext —
  in **every** token position, including position 0 which previously received `contrib.genesis_ct`.

### Why the obvious fix does not exist

A joining delegate's contribution is Regev-encrypted, so the cosigners cannot see the amount they
are attesting to. "Does this ciphertext encrypt zero?" is **undecidable** for them: Regev is
semantically secure, the contribution payload (`BrowserContribution`,
`src/bin/channel_member.rs:290`; `GenesisContribution`, `src/wasm_wallet.rs:144`) carries neither a
declared amount nor the encryption randomness, and `AmountWitness` is deliberately not
`Serialize`. `sign_state_if_backed` cannot help either: `verify_channel_backing`
(`src/wallet_core.rs:425`) checks the balance proof, the circuit-digest binding, the channel id and
`settled_tx_chain` — it explicitly does **not** re-check amount equivalence
(`src/wallet_core.rs:422-424`), so reusing it would have added a false rejection (genesis backing
is frozen and `settled_tx_chain` has advanced) without adding any conservation.

A declared-amount + seed *rebuild-equality* scheme would work — it is the shipped TM-7 pattern at
`src/wallet_core.rs:3134-3142` — but it needs a schema change across ten files
(`src/wasm_wallet.rs`, `hosting/wallet/wallet-worker.js`, `hosting/wallet/wallet-live.html`,
`node/common/wallet.js`, `api/routes/channel-init.js`, …), it publishes the opening balance, and it
still needs new plaintext bookkeeping because `BalanceState` carries no running total.

### The argument for what was done instead

The control **removes the untrusted input rather than validating it**, which is strictly stronger
than any check the cosigners could perform:

1. **Soundness.** The all-zero ciphertext decrypts to 0 under *every* Regev key
   (`src/common/balance_state.rs:64-74`). A join therefore changes no slot's balance: `Σ balances`
   is provably invariant across it. The genesis-anchored backing that `cmd_setup_backing` computed
   (`Σ cosigner genesis amounts + DELEGATE_GENESIS`, and `DELEGATE_GENESIS == 0`,
   `src/bin/channel_member.rs:185`) therefore still holds after any number of joins. A joining
   stranger can no longer introduce balance that is not backed by the channel fund — not because a
   check rejects a bad value, but because no joiner-chosen value reaches the state.
2. **Completeness — it cannot wrongly reject a legitimate join.** There is no rejection path at
   all: every join is accepted, it just opens at zero. Nothing legitimate is lost, because the two
   lanes by which a delegate actually receives value both work from a zero slot and are themselves
   conservation-preserving:
   - the L1 deposit import (`cosign-l1-deposit-import`) reads amount/depositor/token **from the
     chain** and moves `channel_fund` and the slot leaf together
     (`src/wallet_core.rs:2933-2942`), and `add_ciphertexts(zero, x) == x`;
   - an in-channel transfer, whose E-1/E-2 STARK proves `before == after + amount`.
   The delegate needs no encryption witness for the zero ciphertext: sending goes through a refresh
   that needs only its **secret key** (`wallet_refresh`), and withdrawal / post-close claims
   decrypt in-circuit under the secret key. The genesis-backing objection at the old
   `src/bin/channel_member.rs:2501-2505` is untouched and irrelevant here — this control does not
   re-check backing, it makes re-checking unnecessary for the join.
3. **Blast radius.** The production browser flow already contributes `0`
   (`hosting/wallet/wallet-live.html`), and every `init` call site in `tests/` and `api/` is a
   first-init (genesis `create_channel`), so no existing test or demo path passes a nonzero
   contribution *through `join_delegate`*. `join_delegate` had no E2E coverage with a nonzero
   contribution at all.

### A-1 residuals, stated plainly

- **R3 is NOT fixed.** There is still no in-circuit `Σ slot balances <= channel fund`. This closes
  the join lane into R3, not R3 itself.
- ~~**The same unbacked-contribution lane still exists at GENESIS.** `create_channel` still writes
  the creator-supplied delegate ciphertext, and two heavy E2Es pass `"50"` there against a fund
  that does not account for it. Genesis is a creation-time choice by the channel creator rather
  than a post-hoc join by a stranger, and closing it would change heavy CLI fixtures — so it is
  **reported here, not silently fixed**. Recommend tracking it as its own item.~~
  **CLOSED in round 2 — see §7.** The framing above was also wrong on the facts: genesis is NOT a
  creation-time choice by the channel creator. The relay forwards the browser's body verbatim and
  the FIRST browser CREATES the channel, so `create_channel` is the path the shipped product takes
  and `join_delegate` is never reached for a standard single-delegate channel. The first pass
  therefore closed the unused lane and left the used one open.
- **DLG-2 unchanged**: fully-colluding cosigners can still sign any delegate balance. Accepted.
- ~~One sharp edge worth knowing: the WASM wallet retains its own encryption witness after a
  plaintext-only comparison (`src/wasm_wallet.rs:357-372`), so a browser that contributed a
  *nonzero* balance would now hold a witness that does not open the installed (zero) ciphertext. It
  recovers via `wallet_refresh`, and the production flow contributes 0, so this is inert today.~~
  **CORRECTED (review finding 4) — this stated the direction BACKWARDS; see §10.** The nonzero
  contributor is the SAFE case (`50 != 0` fails the plaintext compare, so the witness is dropped).
  It is the ZERO contributor — the production flow — that PASSES the compare and retains a witness
  for `encrypt_amount(rng, pk, 0)`, which does not open the installed canonical zero. It was inert
  while only `join_delegate` was affected; once §7 extended A-1 to genesis it became the live path,
  so it is now fixed in code (`wallet_import_channel` adopts the public zero witness), not merely
  documented.

---

## 3. Assertions that flipped, and why that is not a weakening

`tests/two_token_cli_e2e.rs` pinned the close as an EXPECTED NEGATIVE (`"close limb mismatch"` at
limb 94). It now pins a POSITIVE. That refusal was a **false negative, not a caught attack**:

- limb 94 remains **proof-bound** — the close circuit `connect`s the recomputed H1 to the PI
  (`close_circuit.rs:609-620`), so limb 94 decommits a field of the H1 that every cosigner's Falcon
  signature covers; a prover without the N-of-N keys cannot move it by one;
- the signer set producing those signatures is still pinned by limb 93 + `memberSetCommitment` +
  the constructor registry cross-check, all unchanged strict equality;
- the reference the old equality compared against (`activeDelegateCount`) is a deployer assertion
  cross-checked against nothing — a check cannot be more trustworthy than its reference;
- the negative directions are **preserved and now asserted on-chain** (floor, ceiling,
  limb-93-still-strict, ordering guard, and the same matrix on the partial-withdrawal lane).

No assertion was deleted anywhere. `cli_allow_fail` was kept and annotated rather than removed.

---

## 4. Test results

`cd contracts && forge build` — **Compiler run successful** (warnings only, all pre-existing).

`cd contracts && forge test` — **258 passed, 0 failed, 0 skipped** across 17 suites:

| suite | result |
|---|---|
| ChannelSettlementManager.t.sol | ok — 73 passed (was 70; +3 net new B-2 tests, several extended) |
| PartialWithdrawal.t.sol | ok — 30 passed (was 27; +3 B-2 lane tests) |
| MultiTokenSettlement.t.sol | ok — 20 |
| ChannelSettlementAdversarial.t.sol | ok — 10 |
| ChannelSettlementInvariant.t.sol | ok — 6 |
| CloseLifecycleE2E.t.sol | ok — 2 (see the fixture note below) |
| IntmaxRollup.t.sol | ok — 54 |
| MleE2E.t.sol / MleFinalizeE2E.t.sol | ok — 6 / 2 |
| C2CFullE2E / C2CBlockHash | ok — 2 / 1 |
| WithdrawNativeE2E / PartialWithdrawalPayout / ReclaimStake | ok — 6 / 7 / 7 |
| MultiTokenEscrow / RegisterTokens / IntmaxTestTokenITX | ok — 13 / 8 / 11 |

`cargo check --release --lib --tests --bins` — **0 errors** (warnings pre-existing).
`cargo fmt` — clean. It also normalized one pre-existing formatting drift in
`tests/itx_faucet_cli_e2e.rs:1062` that is unrelated to this change.

### §8 test list — coverage

| § | test | where | status |
|---|---|---|---|
| 8.1 | `delegateCount` above the registered count ⇒ accepted | `test_verifyClose_delegateCountAboveFloor_accepted` | PASS |
| 8.2 | `delegateCount < activeDelegateCount` ⇒ `CloseDelegateCountOutOfRange` (+ at-floor accepted) | `test_verifyClose_delegateCountBelowFloor_reverts` | PASS |
| 8.3 | `memberCount + delegateCount > 1024` ⇒ same error (+ ==1024 accepted, + `2**32-1` hits the ceiling not a panic) | `test_verifyClose_delegateCountAboveCeiling_reverts` | PASS |
| 8.4 | limb 93 tampered ⇒ still `"close limb mismatch"` (both directions) | `test_verifyClose_tamperedMemberCountLimb_stillStrict` | PASS |
| 8.5 | `pi.length != 103` and non-canonical `pi[94]` revert BEFORE any use of limb 94 (94-limb, empty, `2**32`, `2**256-1`) | `test_verifyClose_limb94_lengthAndCanonicalityCheckedFirst` | PASS |
| 8.6 | the same matrix through `submitPartialWithdrawalIntent` | `PartialWithdrawal.t.sol::test_b2_partialWithdrawal_{delegateCountAboveFloor_accepted, delegateCountAboveCeiling_reverts, delegateCountBelowFloor_reverts}` | PASS |
| 8.7 | delegate joins AFTER manager deployment ⇒ channel closes and the delegate claims | `test_b2_postDeployDelegateJoin_closesAndClaims` | PASS |
| — | layout guard: limb 94 follows the validated argument, limb 93 does not; counts > 255 representable | `test_expectedCloseLimbs_limb94FollowsValidatedArgument` | PASS |

### Fixture regeneration (NOT anticipated by the threat model §8)

The threat model states "no fixture regeneration". That is true for **proof** fixtures and VKs, but
it missed one: `CloseLifecycleE2E.t.sol` asserts that the deployed Manager's **CREATE2 address**
equals the recipient baked into `close_withdrawal_payout.json`. Changing `CloseProofFields` changes
the Manager's creation code, hence its CREATE2 address, so that fixture went stale and the suite
failed with the intended `"stale fixtures -- regenerate"` hard error. Verified this test PASSES at
base HEAD, so the failure was caused by this change.

Regenerated per the in-file runbook:

```
forge test --match-test test_printCloseManagerAddress -vv          # → 0xc6eBDC5de4a8AFE0231a602D2aa40F7e71B897Ff
WD_RECIPIENT=0xc6eBDC5de4a8AFE0231a602D2aa40F7e71B897Ff WD_OUT_PREFIX=close_ \
  cargo run --release --bin generate_withdrawal_fixture
```

Touched: `contracts/test/data/close_withdrawal_payout.json`, `close_withdrawal_mle.json`,
`close_lifecycle_validity_mle.json`, `close_lifecycle.json`. The close-INTENT fixtures
(`close_intent.json`, `close_intent_mle.json`) are member-set-derived, not address-derived, and
were **not** regenerated. No VK changed.

---

## 5. Deviations from the spec

1. **Field naming.** §4d step 5 suggested `uint8 memberCount` + `uint32 delegateCount`; the field
   is named `minDelegateCount` instead, matching step 2's own predicate text and making it
   impossible to misread as an exact expected value.
2. **`expectedCloseLimbs` gained a parameter.** The test-introspection view now takes the limb-94
   value explicitly rather than deriving it from the struct, so a test can build a vector for a
   count the predicate would reject. Its doc says it applies no predicate.
3. **Fixture regeneration was required** (§4) — the spec said none would be.
4. **A-1's fix is a removal, not a check.** The spec's §9 A-1 note suggested "a contribution-backing
   check at join". A *check* is cryptographically impossible on the current payload (§2), so the
   untrusted input was removed instead.
5. Out of scope, untouched, as the spec directs: the constructor cosigner/participant cap split
   (A-10 / §10.4), the stale "DEFERRED to B-2" paragraph in `h1-poseidon-root-threat-model.md`
   (§6.1), A-11 (VK deploy-window race), A-12 (native `delegate_count` monotonicity assertion).

---

## 6. STOP points / things the owner should decide or know

- **Nothing was committed**, per instructions.
- **A-1 at GENESIS is still open** (§2 residuals). This is the one place I deliberately did not
  extend the fix; it needs an owner decision because closing it changes heavy CLI E2E fixtures.
- **The monotone floor presumes delegates never leave** (spec §10.2, A-12). It holds only
  *emergently* today (`join_delegate` only increments; `recipients` immutability plus the
  nonzero-active / zero-padding rule in `BalanceState::validate()`). If a delegate-exit path is
  ever added, the floor must be revisited or every close of a shrunken channel bricks — the same
  class of bug just fixed. A native assertion of that invariant is recommended (A-12).
- **`verifyCloseIntent` is a verification service, not the authority.** A caller that invokes it
  directly can pass any `minDelegateCount`/`memberCount` it likes; the authority is the Manager,
  which supplies its own immutables. This is unchanged from before (the same was already true of
  `memberSetCommitment`), but it is now load-bearing for the floor and worth stating.
- **UNVERIFIED (not run):** the heavy CLI E2Es `tests/two_token_cli_e2e.rs` and
  `tests/close_lifecycle_cli_e2e.rs` (`#[ignore]`, anvil + several real MLE/WHIR proofs, ~10 GB
  each). Their assertions were updated by reasoning about the new on-chain semantics; the two-token
  test's downstream section is unaffected because it never finalizes the close (status stays
  `ClosePending` either way, so the "no accrual / nothing credited / pools intact" block holds for
  the same reason as before). They should be run once before merge.
- `src/circuits/channel/close_pis.rs:183` still narrows limb 94 to `u16` on decode. That matches
  the Rust `BalanceState.delegate_count: u16` state field and is not a build breaker, but it is now
  narrower than the on-chain `uint32`. Noted, not changed.

---

# A-1 remediation round 2 (independent security review response)

Appended 2026-08-08. **Still nothing committed.** B-2's Solidity *logic* was NOT touched (review
verdict: FIT). The only Solidity edits in this round are COMMENT TEXT for finding 6 — see §12 for
the fixture consequence that had.

Scope: findings 1-6 from the review of the first A-1 pass. Findings 1 and 2 were code fixes;
3 turned into a code fix once 2 landed; 4 turned into a code fix for the same reason; 5 and 6 are
documentation corrections.

---

## 7. FINDING 2 (the important one) — A-1 extended to GENESIS

### What changed

`src/bin/channel_member.rs`:

- `create_channel(nd, new_ct, new_recipient)` → `create_channel(nd, new_recipient)`. The delegate's
  genesis slot is now installed as `balance_state::zero_ciphertext().clone()` instead of the
  caller-supplied `contrib.genesis_ct`.
- `cmd_init` no longer binds `new_ct` at all. `BrowserContribution.genesis_ct` is kept as a
  **required** wire field (so no browser/relay/API change is needed) and is explicitly marked
  `#[allow(dead_code)]` with a `// SECURITY:` note saying it is read and discarded.
- The comment that asserted `Σ(genesis balances) == fund` was upgraded from a claim to a statement
  of construction.

### Why the review was right that the first pass missed the product

The first pass reasoned that genesis was "a creation-time choice by the channel creator". It is not.
`hosting/wallet/wallet-relay.js:312-323` writes `req.body` verbatim to `contribution.json` and runs
`init`; its own comment says the FIRST browser creates channel N and each later browser JOINS. For
the standard single-delegate channel the product actually creates, **`join_delegate` is never
entered** — so the first A-1 pass closed a lane the shipped flow does not use, and left the lane it
does use open. `create_channel` installed the ciphertext, nothing checked it, and
`cmd_setup_backing`'s `fund` (`Σ genesis_amount(cosigner slots) + DELEGATE_GENESIS`, with
`DELEGATE_GENESIS == 0`, `channel_member.rs:185`, `:516-518`) excluded it.

### The argument for the genesis extension

1. **The loss is real and is not hypothetical minting.** With `Σ slot balances > channel_fund` and
   no in-circuit `Σ balances <= fund` (R3), the surplus is claimed out of the REAL pot after close,
   first-come-first-served, capped by `finalizedChannelFundAmount` / `receivedChannelFunds`. That is
   theft from co-participants, not inflation of the rollup — which is precisely why no on-chain cap
   catches it.
2. **A check is impossible on the current payload, at genesis for exactly the same reason as at
   join.** Regev is semantically secure; the cosigners cannot decide "does this ciphertext encrypt
   zero?" without the joiner's secret key or its encryption witness, and `BrowserContribution` /
   `GenesisContribution` carry neither (`AmountWitness` is deliberately not `Serialize`). So the
   untrusted input is REMOVED, not validated — strictly stronger than any check they could run.
3. **Soundness after the change.** `zero_ciphertext()` is `RegevCiphertext::padding()` (c1 = c2 = 0),
   which decrypts to 0 under every key (`balance_state.rs:63-81`, TM-8). The delegate therefore
   contributes exactly `DELEGATE_GENESIS`, the amount `setup-backing` actually deposited. `Σ genesis
   balances == fund` now holds by construction.
4. **Completeness — this MATCHES PRODUCTION.** `hosting/wallet/wallet-live.html:1864` already passes
   `balance: toBase('0')`. The live browser flow installs today exactly what the new code installs,
   so nothing legitimate is lost. The delegate's real funding lanes are untouched and are the
   conservation-preserving ones: `cosign-l1-deposit-import` (amount/depositor/token read from the
   chain; `channel_fund` and the slot leaf move together) and an in-channel transfer proven by the
   E-1/E-2 STARK. `add_ciphertexts(zero, x) == x`, so a zero opening composes cleanly with both.
5. **No legitimate flow was found that needs a nonzero genesis contribution.** Surveyed every
   `gen-contribution` / `init` caller in `tests/`, `api/`, `node/`, `hosting/`, `doc/benches/`: the
   live browser passes 0; `itx_faucet_cli_e2e` passes 0; the two that passed "50"
   (`close_lifecycle_cli_e2e`, `two_token_cli_e2e`) **never send, withdraw or claim that delegate's
   balance**; `api/routes/keys.js` uses `gen-contribution` purely as a keygen helper and discards the
   ciphertext; `hosting/wallet/wallet-e2e.js` and `wallet.html` are stale demo pages on the legacy
   `add-genesis-sig` flow. So the STOP condition in the brief ("if some legitimate flow genuinely
   requires a nonzero genesis contribution, STOP") was not triggered.

### Test updates (funding, not relaxation)

- `tests/close_lifecycle_cli_e2e.rs`, `tests/two_token_cli_e2e.rs`: `gen-contribution 50` → `0`, each
  with an in-place comment stating why. **No assertion was weakened or removed** — these tests never
  depended on the delegate holding a balance, so the correct "real lane" for them is *no funding at
  all*; the comment names `cosign-l1-deposit-import` as the lane a test that DID need a funded
  delegate would use, and points at `itx_faucet_cli_e2e` where that lane is already covered
  end-to-end (honest import + 9 negative cases).
- `tests/inter_channel_cli.rs`: comment only — that case takes the idempotent-re-join branch and
  never reaches either constructor.

---

## 8. FINDING 1 (MAJOR) — the joined delegate's slot was permanently unclaimable

**Fixed by writing the digest** (the review's preferred option), not by correcting the docstring.

`join_delegate` never wrote `state.balance_state.regev_pk_digests[new_slot]`, so it stayed at the
padding zero on a fully ACTIVE slot. Confirmed the review's reachability argument end to end:

- `BalanceState::validate()` (`balance_state.rs:662-674`) constrains only PADDING slots to the zero
  digest and treats active-slot digests as arbitrary — it cannot catch this.
- `verify_snapshot` checks `record.regev_pk_root`, never `balance_state.regev_pk_digests`.
- `withdrawal_claim_circuit.rs:441-442` derives `pk_digest = poseidon(a, b)` from the witnessed key
  and hashes it into the slot leaf that must Merkle-verify against the H1-committed
  `slot_tree_root` (`:468`). A leaf built over a zero digest is reproducible only by a key whose
  Poseidon digest is zero.

So any value that ever landed in a joined delegate's slot — an honest L1 deposit import, an honest
in-channel transfer — was unclaimable at close. That is exactly the exit lane the A-1 completeness
argument leans on, so it had to be fixed rather than documented.

**The correct value and where the joiner supplies it.** `Bytes32::from(nd.regev_pk.poseidon_digest())`
— the digest of the `regev_pk` the joiner sends in its `BrowserContribution`, i.e. the SAME key
`build_record` already folded into the record's `regev_pk_root` a few lines above. Captured before
`nd` is moved into `members`. This mirrors `create_channel`'s genesis digest vector exactly.

**Why the write cannot itself become an unbacked-value lane.** The digest decides only WHO can
decrypt/claim the slot, never HOW MUCH it holds — the amount is the slot ciphertext, which the
adjacent line pins to the canonical zero. Naming a victim's public key gives the joiner a slot it
cannot decrypt (claiming needs `s` with `b = a·s + e`) over a provably-zero balance, so it can only
harm itself; and the pre-existing recipient-uniqueness guard at the top of `join_delegate` is what
stops a duplicate-identity join from capturing another slot's L1 deposits. A fail-closed refusal was
added for a zero digest (the reserved padding value) so the bug cannot recur silently.

Residual, reported not fixed: `BalanceState::validate()` still permits a zero `regev_pk_digest` on an
ACTIVE slot. The systemic fix is to mirror the B-1b recipient split (active ⇒ nonzero, padding ⇒
zero) directly above it in `validate()`. Not done here because several in-tree circuit/unit fixtures
construct active states with `pad_regev_pk_digests(&[])` (e.g. `close_circuit.rs:1268`, `:1383`,
`:1506`, `cancel_close_pis.rs:230`, `wallet_core.rs:5963`) and changing a shared validator is beyond
an A-1 remediation. **Recommended as its own item.**

---

## 9. FINDING 3 (MINOR) — `gen-send`, promoted to a real fix by finding 2

The review expected shipped tests to be unaffected. That held for join-only A-1; it does **not** hold
once genesis opens at the canonical zero, because `itx_faucet_cli_e2e.rs:343-358` drives
`gen-send 0 1 0 0 …` against a slot that is now `padding()` rather than `encrypt_amount(seed, pk, 0)`.
So **the guard was fixed** (and the runbook corrected as well — both, not either).

- New `regev::encrypt::zero_amount_witness()` — the public all-zero `AmountWitness`
  (`r = e1 = e2 = m = k1 = k2 = 0`, `amount = 0`). Substituting zeros into the two ring identities
  that `transfer_stark::check_amount_witness` enforces gives `0 = 0` for EVERY key, so it opens
  `padding()` under any key — the witness-level twin of "the all-zero ciphertext decrypts to 0 under
  any key". It satisfies every range predicate and, because `m` must equal `encode_amount(amount)`,
  it cannot open any nonzero amount.
- `cmd_gen_send` now has two admissible openings, checked fail-closed in order: (a) the slot holds
  the canonical zero ⇒ `balance` MUST be 0 (asserted, not silently coerced) and the zero witness is
  used; (b) otherwise the legacy deterministic `(balance, seed)` rebuild, unchanged.
- **Runbook** `doc/benches/batch-cosign-throughput.md` §4 got a CHANGED-by-A-1 block: `<bal>` must be
  0, a funded delegate cannot be driven from `gen-send` at all (its ciphertext is not reproducible
  from `(bal, seed)` — it fail-closes rather than guessing), and a join-storm must either keep every
  simulated send at amount 0 (fine — the numbers in §2/§3 time `verify_slim_send_tx` and the batch
  cosign, neither of which is amount-dependent) or grow its own witness-carrying payload builder.

New test `regev::transfer_stark::tests::canonical_zero_ciphertext_opens_under_zero_witness`: one
positive (opens under two independent keys) + two negatives (the same witness must not open a
NONZERO claimed amount; must not open a real encryption) + a full E-1 prove/verify of a 0-spend out
of a canonically-zero balance — the exact shape `gen-send` now builds.

---

## 10. FINDING 4 — the WASM note was inverted, AND the production case now needs a code fix

The direction in §2 of these notes was backwards and is corrected here. `src/wasm_wallet.rs`
compares PLAINTEXTS (`*amt == bal_at`), which is a heuristic, not a proof that the held witness
opens the installed ciphertext:

- a wallet that contributed NONZERO is the SAFE case (`50 != 0` ⇒ witness dropped ⇒ refresh);
- a wallet that contributed ZERO — **the production flow** — passes the compare and retained a
  witness for its own `encrypt_amount(rng, pk, 0)`, which does not open the installed canonical zero.

The review classified this as inert-but-misdescribed. That was correct under join-only A-1. Under the
genesis extension it becomes the LIVE path: the browser contributes 0, creates the channel, imports,
keeps a stale witness, and its first send would fail fail-closed inside `check_amount_witness`
(`transfer_stark.rs`) — sound, but a dead end for the user until `wallet_refresh`. So beyond fixing
the wording, `wallet_import_channel` now **adopts the public zero witness** when the installed
ciphertext is literally the canonical zero and the position has no pending homomorphic adds. That is
exact, not defensive: the zero witness provably opens that ciphertext and can only open amount 0.
`wallet_genesis_contribution` gained a `// SECURITY:` note that its `genesis_ct` is wire-compat only.

---

## 11. FINDINGS 5 and 6 (docs)

- **A-7 narrowed** in `doc/tasks/b2-delegate-close-threat-model.md`. The "no cross-path interaction"
  claim is withdrawn. `revived_delegate_count` (`cancel_close_circuit.rs:280`) is a free 32-bit
  witness constrained only through `recompute_h1`; once a FLOOR exists, a revive with a smaller count
  makes every subsequent close fail the floor **permanently** (stuck funds, not a one-off rejection —
  nothing raises the count back on L1 and nothing lowers `activeDelegateCount`). Requires cosigner
  collusion, so it is not a new unilateral capability, but it converts *sign-a-bad-balance* into
  *brick-the-close-path*. Filed with A-12, whose recommended monotonicity assertion is extended to
  cover the revive path and not just `join_delegate`.
- **Limb 94's floor reworded as a CARDINALITY bound** at all sites: L1 binds no delegate to a balance
  SLOT INDEX, so the floor cannot deliver "no delegate registered here may be EXCLUDED" — only "the
  active region was not shrunk below the registered count". Per-delegate protection comes from the
  leaf-bound recipient / pk_digest / amount bindings in the claim circuits. No regression (the old
  strict equality had the same property). Sites: `ChannelSettlementVerifier.sol`
  (`CloseDelegateCountOutOfRange` doc + the floor comment), `ChannelSettlementManager.sol`
  (`activeDelegateCount` doc + `_checkCloseProof` + `_runCloseVerify`), `DeployCloseCli.s.sol`, plus
  the threat model's A-12 entry.

---

## 12. DEVIATION: the finding-6 COMMENT edits forced a second fixture regeneration

`foundry.toml` sets no `bytecode_hash`, so Solidity's default `ipfs` metadata hash is appended to the
creation code. The metadata hash covers source content **including comments**, so a comment-only edit
to `ChannelSettlementManager.sol` changed its creation code and therefore its CREATE2 address —
`0xc6eBDC5de4a8AFE0231a602D2aa40F7e71B897Ff` → `0x25d5bc1896075D974f3713BbA04Cae60Fa003B08` — and
`CloseLifecycleE2E.t.sol` failed with the intended `"stale fixtures -- regenerate"` hard error.

Regenerated per the in-file runbook (the same one §4 used):

```
forge test --match-test test_printCloseManagerAddress -vv   # → 0x25d5bc1896075D974f3713BbA04Cae60Fa003B08
WD_RECIPIENT=0x25d5bc1896075D974f3713BbA04Cae60Fa003B08 WD_OUT_PREFIX=close_ \
  cargo run --release --bin generate_withdrawal_fixture
```

Touched (again): `close_withdrawal_payout.json`, `close_withdrawal_mle.json`,
`close_lifecycle_validity_mle.json`, `close_lifecycle.json`. No VK changed; the close-INTENT fixtures
are member-set-derived and were not regenerated. Note (per the MLE/WHIR non-determinism record) these
proofs are ZK-blinded and are not byte-reproducible — verify them semantically, not by diff.

**This is a real cost of the finding-6 wording fix and the owner may prefer to revert it.** Reverting
the three `ChannelSettlementManager.sol` comment hunks and regenerating once more would restore the
previous address; the wording correction would then live only in the threat model. Flagged rather
than decided.

---

## 13. Test results (this round)

| what | command | result |
|---|---|---|
| Solidity, full suite | `cd contracts && forge test` | **258 passed, 0 failed, 0 skipped** (after the §12 regeneration; 257/1 before it, the 1 being the CREATE2 staleness guard) |
| Rust, whole-workspace typecheck | `cargo check --release --lib --tests --bins` | **0 errors**; no new warnings in any touched file |
| formatting | `cargo fmt` | clean |
| zero-witness soundness + E-1 round trip (NEW) | `cargo test --release -p intmax3-zkp --lib canonical_zero_ciphertext_opens_under_zero_witness` | **PASS** |
| whole Regev module (E-1/E-2/refresh/claim/purpose-binding) | `cargo test --release -p intmax3-zkp --lib regev::` | **51 passed, 0 failed** |
| A-1 join regression (NEW, drives the real binary) | `cargo test --release --test inter_channel_cli cli_join_delegate_opens_at_canonical_zero_and_binds_pk_digest` | **PASS** |
| inter-channel CLI suite | `cargo test --release --test inter_channel_cli -- --test-threads=1` | **6 passed, 1 failed** — the failure is PRE-EXISTING, see §14 |

New test `cli_join_delegate_opens_at_canonical_zero_and_binds_pk_digest`
(`tests/inter_channel_cli.rs`) drives the real `channel_member` binary through a genuine
`join_delegate` with a contribution that DECLARES 50, and asserts, on the state actually re-signed by
the cosigners (`verify_snapshot`): the declared ciphertext is not installed; every token position of
the joined slot is `RegevCiphertext::padding()`; every pre-existing slot ciphertext and the channel
fund are byte-identical (Σ balances invariant); `regev_pk_digests[3]` equals the joiner's own
`poseidon(a, b)` and is nonzero (finding 1); and the B-1b recipient is bound.

### UNVERIFIED (not run)

- `tests/close_lifecycle_cli_e2e.rs`, `tests/two_token_cli_e2e.rs`, `tests/itx_faucet_cli_e2e.rs` —
  all `#[ignore]`, anvil + multiple real MLE/WHIR proofs, ~10 GB each. These are the ONLY coverage of
  the `create_channel` (genesis) half of finding 2 and of the new `gen-send` canonical-zero branch.
  Reasoning for why each should pass: (a) the two "50" tests never spend/withdraw/claim the delegate
  slot, and nothing anywhere asserts `Σ balances` against `fund`, so a smaller delegate balance
  cannot fail them; (b) `itx_faucet`'s `gen-send 0 …` now takes the canonical-zero branch, whose
  prove/verify shape is exactly what the new unit test exercises, and its randomness-freshness
  assertion still holds because `enc_amount`/`after_ct` still come from `fresh_seed32()`. **They must
  be run once before merge.**
- The browser/WASM path (`wallet_import_channel`'s zero-witness adoption) is typechecked but not
  executed — there is no wasm test harness in CI. Manual browser verification recommended.

---

## 14. STOP points / owner decisions

1. **Nothing was committed.**
2. **PRE-EXISTING test failure, unrelated to A-1/B-2, not fixed here.**
   `inter_channel_cli_end_to_end` fails at `tests/inter_channel_cli.rs:506` ("tx_hash must be
   recorded in A's persisted SPENT ledger"). Reproduced identically with a **completely clean working
   tree at HEAD e3a4500**. Root cause: the test's private mirror of `CliState`
   (`tests/inter_channel_cli.rs:81-89`) still uses the old field names `applied_tx_hashes` /
   `spent_tx_hashes`, both `#[serde(default)]`; commit **d28559f** renamed them to
   `applied_tx_identities` / `spent_tx_identities` (`channel_member.rs:253`, `:262`) when the ledgers
   were re-keyed onto the token-free replay identity for TM-16. The mirror therefore always
   deserializes empty vectors. **Not a runtime replay-protection gap** — inspecting the on-disk state
   after a failing run shows both ledgers written correctly and atomically on the correct sides, and
   the guards (`channel_member.rs:3429`, `:3609`, `:3689`, `:3753`) are unchanged and reachable. It
   IS a coverage loss: the `is_empty()` assertions at `:672` and `:756` are currently VACUOUS and
   would pass even if the atomicity/forgery guards regressed. Repair: rename the mirror fields and
   compare against `InterChannelTransferDescriptor::replay_identity()` rather than `tx_hash` (they
   coincide only for token index 0). Left alone deliberately — outside the A-1 mandate.
3. **§12 — the finding-6 comment edits cost a fixture regeneration.** Owner may prefer to revert the
   `ChannelSettlementManager.sol` comment hunks and keep the correction in the threat model only.
4. **`BalanceState::validate()` still allows a zero `regev_pk_digest` on an ACTIVE slot** (§8
   residual). The finding-1 class of bug is now blocked at both CLI construction sites, but not at the
   validator. Recommended as its own item, because it touches shared circuit/unit fixtures.
5. **R3 is still not fixed.** There is no in-circuit `Σ slot balances <= channel fund`. Both
   injection lanes are now removed, so the CLI/browser flow never *creates* a violating state — but
   that is not a proof that no violating state can be signed. DLG-2 (fully-colluding cosigners can
   sign any delegate balance) is unchanged and accepted.
6. **A-7 / A-12 (§11).** The monotone floor now has a second dependency: the cancel-close revive path.
   The recommended native `delegate_count` monotonicity assertion should cover it.

---

## 15. Claim-path recipient inconsistency (follow-up to the B-2 fence fix)

With the B-2 fence in place, `close_lifecycle_cli_e2e` gets past close/settle/withdraw and fails at
the CLAIM step:

```
error: build withdrawal claim: withdrawal claim: public-input build failed: RecipientMismatch
```

### 15.1 Diagnosis — CONFIRMED, with one material correction

Confirmed as handed over:

| Claim | Verified at | Status |
| --- | --- | --- |
| The claim witness requires `member.l1_withdrawal_recipient == final_balance_state.recipients[member_index]` (B-1b leaf binding) | `src/circuits/channel/withdrawal_claim_pis.rs:182-186` | CONFIRMED |
| The CLI genesis assigns non-delegate slots `test_recipient_for(channel_id, slot)`; channel 7 slot 0 = `0x3333007033330070333300703333007033330070` | `src/bin/channel_member.rs` `create_channel`; `src/circuits/test_utils/block_witness_generator.rs:391` | CONFIRMED |
| The test passed `CLAIM_RECIPIENT = ANVIL0_ADDR` ⇒ mismatch | `tests/close_lifecycle_cli_e2e.rs` claim step | CONFIRMED |
| The credit accrues to the PROOF-BOUND recipient | `ChannelSettlementManager.sol:1313` — `withdrawalCredits[claim.tokenIndex][claim.recipient] += claim.amount` | CONFIRMED |
| `claimWithdrawalCredit` pays `msg.sender` | `ChannelSettlementManager.sol:1460-1477` | CONFIRMED |
| `registeredRecipientOf` has ZERO runtime reads | written only at `:746` / `:806`; the only other occurrences repo-wide are the `:1273` comment and two `.t.sol` assertions | CONFIRMED |
| Therefore the Manager's `MemberBinding.recipient` does not affect claim PAYOUT ROUTING | as above | CONFIRMED |

**CORRECTION (important — the handover called the deploy-script override "vestigial"; it is
vestigial FOR CLAIMS ONLY, and dropping it would have broken the lifecycle):**
the constructor also writes `isMemberRecipient[binding.recipient] = true`
(`ChannelSettlementManager.sol:751`, `:809`), and that map IS read at runtime in two places:

- `requestClose(uint64,uint64)` — validates the exact durable freeze nonce / monotone cancellation
  floor and then enforces `isMemberRecipient[msg.sender]`.
  The CLI sends this guarded request from `deposit_key_env()`, which defaults to the anvil dev key
  (`channel_member.rs:487`) — i.e. exactly the EOA `DeployCloseCli` routes slot 0 to. Without the
  override the E2E could not even OPEN the close.
- `submitPartialWithdrawal` — "the payout address must be a registered participant" (`:1151`).

So `DeployCloseCli.s.sol:137` was NOT removed. It was kept and its comment rewritten to say
precisely what it does (`isMemberRecipient` authority for `requestClose` / partial withdrawal) and
what it does NOT do (claim payout routing). Registration recipients fed to `registerChannel` are
deliberately left unchanged — they are hashed into the reg chain the validity proof reproduces, so
they are not a place to express payout routing.

### 15.2 The real defect

Claim routing lives in the CHANNEL STATE (the cosigner-signed balance-slot leaf, B-1b), and the CLI
had no way to put a controllable address there: every non-delegate slot got the synthetic
`test_recipient_for` address, for which **no key exists**. A slot-0 claim therefore credits an
address that can never call `claimWithdrawalCredit` — the payout would be permanently stranded even
if every proof verified. The deploy script's Manager-binding override was an attempt to route the
payout in the wrong layer; post-B-1b that layer is not consulted for claims.

### 15.3 Fix

1. `src/bin/channel_member.rs` — new `cosigner_leaf_recipient(channel_id, slot)`, consumed by
   `create_channel` for every non-delegate slot. Default is unchanged (`test_recipient_for`);
   opt-in override `CLI_RECIPIENT_SLOT_<slot>=0x<20-byte address>` sets THAT slot's genesis leaf.
   Fail-closed: set-but-unparsable or zero aborts (a silent fallback would strand the payout, which
   is the very failure being removed). Every other slot keeps the synthetic default; no real address
   is baked into library code.
   `// SECURITY:` on the helper records why the override weakens nothing: it moves the recipient in
   the one place B-1b makes authoritative, every cosigner signs the genesis carrying it, the witness
   check and the in-circuit leaf opening still force `claim.recipient == signed leaf`, and payout
   still requires the recipient's own key.
2. `contracts/script/DeployCloseCli.s.sol` — slot-0 binding override KEPT, comment rewritten (see
   15.1) so there is exactly one source of truth per property: claim routing = channel-state leaf;
   `requestClose`/partial-withdrawal participant authority = Manager binding; validity reg chain =
   registration record.
3. `tests/close_lifecycle_cli_e2e.rs` — `init` now runs with `CLI_RECIPIENT_SLOT_0 = ANVIL0_ADDR`,
   matching the `CLAIM_RECIPIENT` the claim step already used. New assertions make a stranded payout
   impossible to pass silently:
   - claimant credit is 0 BEFORE the claim;
   - `totalCreditedOut(0) == the amount the claim CLI actually PROVED` (parsed from its output, not
     re-derived) — this can only hold if the proof-bound credit accrued to an address the test
     controls, since `claimWithdrawalCredit` pays `msg.sender`;
   - claimant credit is 0 after (fully pulled);
   - `withdrawalCredits(0, test_recipient_for(7,0)) == 0` — nothing parked at the unclaimable
     synthetic default.
   No assertion was weakened or removed; the claim circuit and its PI contract are untouched.

### 15.4 Verification

| What | Command | Result |
| --- | --- | --- |
| Solidity suite | `cd contracts && forge test` | **258 passed, 0 failed** |
| Rust typecheck | `cargo check --release --lib --tests --bins` | **0 errors** |
| formatting | `cargo fmt` | clean |
| live close lifecycle | `cargo test --release --test close_lifecycle_cli_e2e -- --ignored --nocapture` | **FAILED after 1153s — but PAST the claim-recipient bug; a NEW, unrelated, PRE-EXISTING blocker (see 15.5)** |

Progress made by the fix, from the run's own output:

- `RecipientMismatch` is GONE. The claim witness built, the E-3 claim proof verified natively, and
  the withdrawal-claim MLE proof was produced (`[claim] wrote withdrawal_claim.json … (amount
  40000000000000000)` — 0.04 ETH, slot 0, token 0).
- The submitted claim carries `recipient: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` (the anvil
  EOA), i.e. the leaf routing works end to end.
- close / settle / withdraw are unchanged and still pass.

### 15.5 NEW blocker (pre-existing, NOT caused by this fix): the claim circuit uses a gate the on-chain verifier does not implement

`submitWithdrawalClaim` reverts inside the MLE verifier:

```
MleVerifier::verify → Plonky2GateEvaluator.evalCombinedFlat
  └─ ← [Revert] unsupported gate with non-zero filter
```

`contracts/lib/polygon-plonky2/mle/contracts/src/Plonky2GateEvaluator.sol:225` — the evaluator
implements 12 gate types and reverts (deliberately, fail-closed) on anything else, naming
`ExponentiationGate` and the lookup gates as the unsupported set.

Gate lists read out of the checked-in VK fixtures:

| circuit | gate set | on-chain verify |
| --- | --- | --- |
| close intent / close withdrawal / validity | Noop, PublicInput, Constant, Arithmetic(+Ext), MulExt, BaseSum, Reducing(+Ext), Poseidon, PoseidonMds, RandomAccess, CosetInterpolation | PASSES (this run) |
| **withdrawal claim** | the same **plus `ExponentiationGate { num_power_bits: 66 }`** | **REVERTS** |

Why this is NOT caused by the recipient fix, and not by the uncommitted B-2/A-1 work:

1. A gate's presence is fixed when the circuit is BUILT — it cannot depend on a witness value such
   as an address. The selector polynomial is preprocessed; its evaluation at the transcript point is
   nonzero whenever the gate is in the circuit, for every witness.
2. `MleVerifier.verify` calls `_requireGatesDigest(proof, vk.gatesDigest)` BEFORE evaluation
   (`MleVerifier.sol:175`, `:649`). It PASSED — so the CLI's freshly built circuit has exactly the
   gate list of the deployed VK, which comes from the checked-in `withdrawal_claim_mle.json`.
3. That fixture is untouched by the working tree, and `git show HEAD:contracts/test/data/
   withdrawal_claim_mle.json` already lists `ExponentiationGate` (last regenerated in 2e418f6, and
   before that 89cd044 "regenerate all VKs and fixtures for Regev n=2048"). The gap predates this
   branch's uncommitted work.
4. The uncommitted Rust diff outside the CLI is `src/regev/{encrypt,transfer_stark}.rs`, and both
   hunks are NATIVE helpers (`zero_amount_witness` + checks) — no circuit construction.

Why it was never seen before: **no Foundry test verifies a real withdrawal-claim MLE proof.** Every
`submitWithdrawalClaim` call in `contracts/test/` uses a mock/limbs proof
(`CloseTestLib.proofWithLimbs` + the mock verifier), and `CloseLifecycleE2E.t.sol:244-252` documents
that it deliberately STOPS before the claim ("would require a withdrawal-claim MLE fixture + VK
co-generated with THIS lifecycle's member set"). `close_lifecycle_cli_e2e` is the only path that
attempts it, and it was previously blocked earlier in the lifecycle — first by the close delegate
fence (B-2), then by `RecipientMismatch`. Fixing those two exposed the third.

Origin of the gate: the claim circuit embeds a recursive plonky2 verification (the E-3
`claim_proof`), and plonky2's recursive FRI verifier emits `ExponentiationGate` via
`exp_from_bits_const_base` (`plonky2/src/fri/recursive_verifier.rs:48`, `:416`, `:547`). The close /
withdrawal / validity circuits' FRI parameters keep that path on the cheap `square`-chain branch
(`exp_power_of_2`), which is why only the claim circuit carries the gate.

**ESCALATED, NOT PATCHED.** Both candidate fixes are outside this task's mandate and are
security-critical:
  (a) implement `ExponentiationGate` in `Plonky2GateEvaluator.sol` — a constraint-system change in
      the upstream `polygon-plonky2` submodule's on-chain verifier; or
  (b) rebuild the claim circuit so the gate is not emitted (FRI/recursion shape) — explicitly
      excluded here, since the claim circuit and its PI contract were not to be touched.
Under no circumstances should the evaluator's `revert` be relaxed: it is the fail-closed signal that
a constraint would otherwise go UNCHECKED on-chain. Owner decision required.


## Follow-up closed: `inter_channel_cli` was failing on a VACUOUS assertion (2026-08-09)

The known-open item recorded at commit time is now FIXED, and the diagnosis was confirmed rather
than assumed: the replay ledgers ARE populated on disk (`spent_tx_identities` on the debit side,
`applied_tx_identities` on the credit side, read out of a real failing run's `cli_state.json`), and
the runtime guards are correctly ordered — the spent-ledger check fires BEFORE the head-extension
check. So this was a pure test defect, NOT a replay-protection hole. Had the ledgers been empty in
reality it would have been a security finding, so it was checked before anything was edited.

The test's hand-rolled serde mirror had drifted from the binary's private `CliState` after the
d28559f rename, and serde silently defaulted the renamed fields to empty vectors — so two
`is_empty()` assertions passed unconditionally.

Fix: `#[serde(deny_unknown_fields)]` on the mirrors AND removal of every `#[serde(default)]`, which
makes the key set exact in BOTH directions (an added/renamed field in the binary errors; a
removed/renamed field in the mirror errors). Verified by deliberately deleting a mirror field and
observing the loud failure. The assertions now key on `replay_identity()` (what the binary actually
keys on, not the coincidentally-equal `tx_hash`), assert the ledgers are NON-empty and side-specific,
and no longer accept the head-extension error as evidence of replay protection — that disjunct would
have passed even with the spent ledger deleted outright. 7 passed / 0 failed.

### The same vacuity class, second instance (fixed here)

`tests/itx_faucet_cli_e2e.rs:661` used `v["deposit_tx"].as_str().unwrap_or("")` and then wrapped the
assertion in `if !backing_tx.is_empty()`. A missing, renamed or empty field would SILENTLY SKIP the
check that a channel's own backing deposit cannot be re-imported — i.e. the double-credit-against-
one-L1-escrow defence — leaving the suite green while proving nothing. Now `.expect(...)` plus an
explicit non-empty assertion, and the check is unconditional.

**Pattern worth naming:** both instances are "a test that cannot fail". Neither was found by running
the suite, because a vacuous assertion is indistinguishable from a passing one in the output. The
generalisable rule: any `unwrap_or`/`default`/`if let`/`is_empty()` guard placed UPSTREAM of a
security assertion converts that assertion into a no-op the moment the upstream shape drifts.
