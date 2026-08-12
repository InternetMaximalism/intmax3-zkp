# falcon-sig Phase 5 — fixtures, end-to-end, deploy prep

Branch `feat/falcon-poseidon-sig`, on top of `2436aa1` (Phase 4). **Not committed.**

Scope: enumerate and regenerate the fixture set invalidated by Phases 2/2.6/3/4, validate it
SEMANTICALLY (MLE/WHIR proofs are non-deterministic — never by byte comparison), run every suite to
green, decide the Phase-4 INFO-7 carried item, and register the new domain constants in
`detail2.md`.

---

## 1. Fixture regeneration set — ENUMERATED (not assumed)

### 1.1 What invalidates what

Two independent invalidation vectors:

- **VK-derived** — the Falcon migration changed the list VK (Phase 3), therefore the validity chain
  VK, and swapped the close/cancel aggregation VK (Phases 2/2.6). Every wrapper proof that bakes one
  of those inner VKs has a new `circuitDigest`.
- **Key-derived** — every member `pk_g` VALUE changed TWICE: once in Phase 3
  (`pk_g = Poseidon(IMFK‖encode(h))` instead of `Poseidon(IMPG‖sk_g)`) and again in Phase 4, when the
  CLI/fixture cosigner identities moved from the dedicated `falcon_seed_for` (tag `0xfc`) derivation
  onto `MemberKeys::generate`'s RNG stream. Everything that folds a `pk_g` — the registration keccak
  chain, `MemberTree` roots, the IMCM member-set commitment, the validity block chain, close/cancel
  PIs — moves with it.

### 1.2 Producer → file map (evidence: `fs::write` sites in `src/bin/generate_*.rs`)

`contracts/test/data/` holds **31** JSON files. **27** are generator output; **4** are not.

| generator (`src/bin/…`) | files written | invalidated by |
|---|---|---|
| `generate_e2e_fixture.rs` | `mle_fixture.json`, `vpi_fixture.json`, `block_fixture.json` | VK (validity) |
| `generate_withdrawal_fixture.rs` (no prefix) | `withdrawal_mle.json`, `lifecycle_validity_mle.json`, `lifecycle.json`, `withdrawal_payout.json` | VK + KEY |
| …same binary, `WD_OUT_PREFIX=close_` | `close_withdrawal_mle.json`, `close_lifecycle_validity_mle.json`, `close_lifecycle.json`, `close_withdrawal_payout.json` | VK + KEY |
| …same binary, `WD_OUT_PREFIX=sepolia_` | `sepolia_*` (4) | VK + KEY — **NOT regenerated, see §1.4** |
| `generate_c2c_fixture.rs` | `c2c_lifecycle.json`, `c2c_lifecycle_validity_mle.json`, `c2c_withdrawal_mle.json`, `c2c_withdrawal_payout.json` | VK + KEY |
| `generate_close_fixture.rs` (feat `close-fixture-bin`) | `close_intent_mle.json`, `close_intent.json` | VK (agg) + KEY |
| `generate_cancel_close_fixture.rs` (feat `cancel-close-fixture-bin`) | `cancel_close_mle.json`, `cancel_close.json` | VK (agg) + KEY |
| `generate_withdrawal_claim_fixture.rs` (feat `withdrawal-claim-fixture-bin`) | `withdrawal_claim_mle.json`, `withdrawal_claim.json` | VK (wrapper only) |
| `generate_post_close_claim_fixture.rs` (feat `post-close-claim-fixture-bin`) | `post_close_claim_mle.json`, `post_close_claim.json` | VK (wrapper only) |
| `generate_wasm_fixtures.rs` | `tests/fixtures/*` (NOT under `contracts/test/data/`) | VK |

The **4 non-generator** files, with evidence:

| file | what it is | disposition |
|---|---|---|
| `e2e_fixture.json` | Groth16 proof + VK (`groth16_proof`/`verifying_key`/`pi_hash`) | **DEAD.** `grep` over `*.sol`/`*.rs`/`*.js` finds ZERO consumers and ZERO producers — the gnark fixture test was removed with the MLE-only switch (CLAUDE.md). Not regenerated; nothing can regenerate it. |
| `e2e_groth16.json` | ditto | **DEAD**, same evidence. `generate_e2e_fixture.rs:94` explicitly says Groth16 fixtures are "managed separately"; no code path reads it. |
| `pw_reg.json` | `member_pk_gs`/`member_pk_bs`/`recipients` for the partial-withdrawal deploy script | **KEY-derived and stale, but self-refreshing**: written at RUN TIME by `tests/partial_withdrawal_e2e.rs:308` and by `bin/channel_member.rs:3950`, read only by `script/DeployPartialWithdrawalE2E.s.sol` / `DeployWalletSettlement.s.sol` (never by `forge test`). The committed copy is a stale by-product; running the Rust E2E rewrites it. |
| `pw_submit.json` | close/withdrawal fields for `SubmitPartialWithdrawal.s.sol` | same — written by `tests/partial_withdrawal_e2e.rs:491` / `channel_member.rs:4657`. |

### 1.3 Which files carry key-derived vs VK-derived values (evidence: JSON key structure)

- **KEY-derived**: `lifecycle*.json` → `registration.member_pk_gs` (+ everything folding it:
  `final_state_root`, `vpis.final_block_chain`, `vpis.final_ext_commitment`, `proof_hash`);
  `close_intent.json` → `member_pk_gs`, `member_set_commitment`, `close_intent_digest`,
  `final_channel_state_digest`, `final_balance_state_h1`; `cancel_close.json` → same family;
  `pw_reg.json` → `member_pk_gs`.
- **VK-derived**: every `*_mle.json` → `circuitDigest` (+ `preprocessedCommitmentRoot`, `gates`,
  `whirParams`, and the whole proof body).
- **NEITHER (synthetic vectors)**: `withdrawal_claim.json` (`member_pk_g =
  0x0000000a0000000b…`) and `post_close_claim.json` (`receiver_pk_g = 0x0000000b0000000c…`) are
  ARBITRARY pinned 32-byte digests — the claim circuits consume `pk_g` as an opaque digest and
  verify no signature. Their descriptors are correctly UNCHANGED by the migration; only their
  wrapper proofs regenerate. (Confirmed empirically: both files are byte-identical after
  regeneration while their `*_mle.json` siblings changed.)

### 1.4 `sepolia_*` — deliberately NOT regenerated

The four committed `sepolia_*` files are read **only by `contracts/script/`** (`DeployClose.s.sol`,
`RunClose.s.sol`) — `grep` over `contracts/test/**.sol` finds zero references. They are the LIVE
DEPLOYMENT artifact set, and eight more `sepolia_*` files the scripts reference do not exist in the
tree at all (the CLI stages them at deploy time). Regenerating them requires a target-network
`WD_RECIPIENT` (the manager CREATE2 address on that chain), i.e. a deploy decision, not a test
input. `tests/close_lifecycle_cli_e2e.rs` and `tests/two_token_cli_e2e.rs` overwrite them during a
run and restore them via a Drop guard.

**They are STALE and must be regenerated as part of the v3 reset/redeploy** —
`doc/tasks/regen-and-redeploy-runbook.md` Step 1 + Step 3. Recorded as STOP point 1.

### 1.5 What was regenerated (runbook order, one heavy process at a time)

| step | command | wall | peak RSS |
|---|---|---|---|
| 1 | `generate_e2e_fixture` | 50 s | 5.97 GB |
| 2 | `generate_withdrawal_fixture` (plain) | 134 s | 7.16 GB |
| 3 | `forge test --match-test test_printCloseManagerAddress -vv` → `CLOSE_MANAGER_ADDRESS = 0x0B193Ed789C50C205A19E265eA4F78C6c331ABAC` | — | — |
| 4 | `WD_RECIPIENT=0x0B19…ABAC WD_OUT_PREFIX=close_ generate_withdrawal_fixture` | 128 s | 9.05 GB |
| 5 | `generate_close_fixture` | 77 s | 7.91 GB |
| 6 | `generate_withdrawal_claim_fixture` | ~170 s | (peak footprint 39 GB — see STOP 4) |
| 7 | `generate_post_close_claim_fixture` | 168 s | 26.29 GB |
| 8 | `generate_cancel_close_fixture` | 35 s | 5.45 GB |
| 9 | `generate_c2c_fixture` | 119 s | 11.92 GB |
| 10 | `generate_wasm_fixtures` | 36 s | 9.03 GB |

Total 27 files rewritten; 20 changed content, 3 (`vpi_fixture.json`, `withdrawal_claim.json`,
`post_close_claim.json`) are legitimately byte-identical (§1.3 and §2.2), and the 4 `sepolia_*` were
not touched.

---

## 2. Semantic validation (never byte comparison)

Per `project_mle_whir_nondeterministic`: MLE/WHIR proofs carry ZK blinding, so a regenerated fixture
is NEVER byte-reproducible. Validation is by MEANING.

### 2.1 The VK cascade landed exactly where the design predicts

`circuitDigest` before vs after, per wrapper fixture:

| fixture | circuitDigest | publicInputs | reading |
|---|---|---|---|
| `lifecycle_validity_mle.json`, `close_lifecycle_validity_mle.json`, `c2c_lifecycle_validity_mle.json`, `mle_fixture.json` | **CHANGED** | changed (except `mle_fixture`, §2.2) | list VK → validity VK → wrapper digest. As designed. |
| `close_intent_mle.json`, `cancel_close_mle.json` | **CHANGED** | same length (103 / 27) | the `FalconAggCircuit` VK replaced `AggLevelCircuit`'s inside the close/cancel circuits. As designed. |
| `withdrawal_mle.json`, `close_withdrawal_mle.json`, `c2c_withdrawal_mle.json` | **same** | **CHANGED** | correct: the withdrawal circuit family verifies no signature, so its VK is untouched; only its PI values move because the block chain / ext commitment fold the new `pk_g`. |
| `withdrawal_claim_mle.json`, `post_close_claim_mle.json` | same | same | correct: the claim circuits are signature-free AND driven by synthetic `pk_g` vectors (§1.3). Only the (blinded) proof body differs. |

No PI **length** changed anywhere — the migration is value-only, layouts stable (TM-C7). This is the
falsifiable form of "layouts do not change, only values".

### 2.2 The key change is visible and correctly scoped

`git diff contracts/test/data/lifecycle.json`:

- `registration.member_pk_gs` — all three CHANGED (new Falcon identities);
- `registration.member_pk_bs` — **UNCHANGED** (BabyBear `pk_b` is out of scope — exactly the
  designed blast radius);
- `final_state_root`, `vpis.final_block_chain`, `vpis.final_ext_commitment` — CHANGED (they fold
  `pk_g`);
- `genesis_state_root` — UNCHANGED (pre-registration).

`block_fixture.json` / `vpi_fixture.json` / `mle_fixture.json` PIs are unchanged because the e2e
chain that produces them contains **no channel registration**, so it folds no `pk_g`; only the proof
body changed. That is a consistency check, not an omission: `block_fixture.initial/final_block_chain`
and `vpi_fixture` agree with each other and with `mle_fixture.publicInputs`, all unchanged, while
`proof_hash`/`proof_length` moved.

### 2.3 The strongest semantic gate: the on-chain close lifecycle

`CloseLifecycleE2ETest.test_closeLifecycle_endToEnd` **PASSED and did NOT skip** (80.0 M gas). It
hard-asserts (`CloseLifecycleE2E.t.sol:181`) that the close fixture's `member_set_commitment` equals
the manager's `registeredMemberSetCommitment` derived from `close_lifecycle.json`'s registration.
That single assertion closes the loop Rust `MemberKeys` → Falcon `h` → `Poseidon(IMFK‖encode(h))` →
registration keccak → Solidity, over independently generated fixtures — a stale or mixed-run set
fails it. It also asserts `address(manager) == bakedRecipient`, validating step 3/4 of §1.5.

---

## 3. Phase-5 resumption (session 2) — independent re-validation

The prior session's regenerated fixture set is committed at HEAD `2e418f6` (amended onto the Phase-4
commit); the tree is clean. Rather than trust §1–§2, the fixture set was re-validated from scratch
offline, then handed to the suites.

### 3.1 Offline structural checks

- All **31** `contracts/test/data/*.json` parse as well-formed JSON.
- `forge build` — exit 0.

### 3.2 Offline SEMANTIC checks (recomputed independently, not byte comparison)

| # | check | method | result |
|---|---|---|---|
| S1 | `close_intent.json.member_set_commitment` | recomputed `keccak(IMCM ‖ member_count ‖ pad-to-16 pk_g)` in Python over the fixture's OWN `member_pk_gs` | **MATCH** |
| S2 | `cancel_close.json.member_set_commitment` | same | **MATCH** |
| S3 | close fixture ↔ lifecycle fixture agreement | `close_lifecycle.json.registration.member_pk_gs` == `close_intent.json.member_pk_gs` (produced by two DIFFERENT generator binaries in separate runs) | **IDENTICAL** |
| S4 | descriptor ↔ proof binding | `close_intent.json`'s `member_set_commitment` / `close_intent_digest` / `final_channel_state_digest` / `final_balance_state_h1` all located as 8-limb runs inside `close_intent_mle.json.publicInputs` (103 limbs) at offsets 85 / 57 / 9 / 17 | **FOUND** |
| S5 | validity proof PI binding | recomputed `keccak256(ValidityPublicInputs)` (164-byte preimage: u64 block numbers ‖ chains ‖ ext commitments ‖ prover) from each `*lifecycle.json.vpis`, compared to the 8 PI limbs of the paired `*_validity_mle.json` | **MATCH ×3** (`lifecycle`, `close_lifecycle`, `c2c_lifecycle`) |
| S6 | withdrawal ↔ validity cross-proof binding | `withdrawal_payout.json.ext_commitment` == `lifecycle.json.vpis.final_ext_commitment`, and that same digest is embedded at `withdrawal_mle.json.publicInputs[8..16]` | **MATCH** |
| S7 | close recipient pinning | `close_withdrawal_payout.json.recipient` == `0x0b193ed789c50c205a19e265ea4f78c6c331abac` == the `CLOSE_MANAGER_ADDRESS` used at generation (§1.5 steps 3–4) | **MATCH** |

S5 is the decisive one: it independently reproduces the exact digest the on-chain `_computeValidityPIHash`
re-derives, from the descriptor JSON alone, and finds it verbatim in the separately-generated proof's
public inputs. A stale, mixed-run, or partially-regenerated set cannot satisfy it.

METHOD NOTE (recorded because it first read as a failure): S5 initially MISMATCHED on all three
fixtures. The cause was the CHECK, not the fixtures — `ValidityPublicInputs` block numbers are **u64
(2 u32 limbs each, 164-byte preimage)**, per `IntmaxRollup.sol:297-311`; the first attempt packed
them as 4 bytes. Fixing the checker's encoding produced a 3/3 match. Per the security-first protocol
the fixtures were NOT touched while this was being diagnosed.

## 4. Foundry — `forge build` + `forge test`

`forge build` exit **0**. `forge test` exit **0**: **17 suites, 248 tests passed, 0 failed, 0 SKIPPED.**

The `0 skipped` is the load-bearing number, not the `248 passed`. Every fixture-gated Solidity test
in this repo skips gracefully when its `*_mle.json` is absent or unparseable (see
`generate_close_fixture.rs:29`). A zero skip count therefore proves each regenerated fixture was
actually loaded and verified on-chain, not silently stepped over.

| suite | tests | result |
|---|---|---|
| `C2CBlockHashTest` | 1 | 1 passed, 0 failed, 0 skipped |
| `C2CFullE2ETest` | 2 | 2 passed, 0 failed, 0 skipped |
| `ChannelSettlementAdversarialTest` | 10 | 10 passed, 0 failed, 0 skipped |
| `ChannelSettlementInvariantTest` | 6 | 6 passed, 0 failed, 0 skipped |
| `ChannelSettlementManagerTest` | 66 | 66 passed, 0 failed, 0 skipped |
| `CloseLifecycleE2ETest` | 2 | 2 passed, 0 failed, 0 skipped |
| `IntmaxRollupTest` | 54 | 54 passed, 0 failed, 0 skipped |
| `IntmaxTestTokenITXTest` | 11 | 11 passed, 0 failed, 0 skipped |
| `MleE2ETest` | 6 | 6 passed, 0 failed, 0 skipped |
| `MleFinalizeE2ETest` | 2 | 2 passed, 0 failed, 0 skipped |
| `MultiTokenEscrowTest` | 13 | 13 passed, 0 failed, 0 skipped |
| `MultiTokenSettlementTest` | 20 | 20 passed, 0 failed, 0 skipped |
| `PartialWithdrawalPayoutTest` | 7 | 7 passed, 0 failed, 0 skipped |
| `PartialWithdrawalTest` | 27 | 27 passed, 0 failed, 0 skipped |
| `ReclaimStakeTest` | 7 | 7 passed, 0 failed, 0 skipped |
| `RegisterTokensTest` | 8 | 8 passed, 0 failed, 0 skipped |
| `WithdrawNativeE2ETest` | 6 | 6 passed, 0 failed, 0 skipped |

No failures to classify — there is no (a) stale-fixture, (b) logic-break, or (c) invalidated-premise
bucket to report for Foundry. No assertion was weakened and no test was skipped, disabled, or
modified at any point in this phase.

Highlights that specifically exercise the migrated material:
- `CloseLifecycleE2ETest` (2/2) — the on-chain member-set-commitment equality gate of §2.3.
- `MleE2ETest` (6/6) — verifies the regenerated `mle_fixture.json` against the real
  `MleVerifier`, INCLUDING the three negative tests (`rejects_tamperedTranscript`,
  `rejects_flippedWitnessEval`, `rejects_wrongGatesDigest`), so the new VK still rejects forgeries.
- `MleFinalizeE2ETest`, `C2CFullE2ETest`, `WithdrawNativeE2ETest` — the finalize / c2c / native
  withdrawal rails over the regenerated validity+withdrawal proof pairs.
- `IntmaxRollupTest::test_finalize_tamperedValidityPIs_rejected` and `test_finalize_unboundMlePublicInputs`
  — confirm the keccak(VPI) ↔ MLE-PI binding validated offline in S5 is still ENFORCED, not merely satisfied.

## 5. Rust integration tests (one process at a time)

| # | target | tests | result | wall | peak RSS |
|---|---|---|---|---|---|
| 1 | `--test small_block_sig_validity` | 1 passed, 0 failed, **0 ignored** | **PASS** | 63.1 s | 6.45 GB |
| 2 | `--test wallet_core_e2e` | 3 passed, 0 failed, **0 ignored** | **PASS** | 2.0 s | 0.07 GB |
| 3 | `--test e2e` | 1 passed, 0 failed, **0 ignored** | **PASS** | 146.3 s | 14.28 GB |

Test 1 is the one that matters most for Phases 2/3: `inter_channel_small_block_sig_is_validity_proven`
drives a real inter-channel small block through the validity list step, which is precisely where
Phase 3 put in-circuit Falcon verification.

### 5.1 SCOPE CORRECTION — `wallet_core_e2e` does NOT cover the close provers

`wallet_core_e2e` finished in **2.0 seconds at 72 MB**. That is far too cheap for a suite that builds
a `FalconAggCircuit`, so it was checked rather than accepted: it contains exactly 3 tests
(`wallet_core_in_channel_send_receive`, `p4_1_attacker_pk_b_swap_is_rejected`,
`p4_1_foreign_self_consistent_record_is_rejected`), 0 ignored, and none of them constructs a
`CloseProver`.

The REAL Falcon close-path Rust tests are **lib unit tests in `src/wallet_core.rs`**, not integration
targets:

- `a3_close_prover_builds_and_verifies_real_close_proof` (`:5686`)
- `a3_cancel_close_prover_builds_and_verifies` (`:5922`)
- `a3_post_close_claim_prover_builds_and_verifies` (`:6022`)
- `a3_withdraw_registration_matches_close_member_set` (`:6295`)
- `two_token_close_intent_builds_per_token_claims` (`:7115`)

Naming `wallet_core_e2e` in the target list and stopping there would have left the Rust-side close
path UNTESTED while looking green. Those lib tests are therefore run explicitly as step 5b.

### 5.2 Step 5b — the close-prover lib tests (run because §5.1 found the gap)

| # | test (`-p intmax3-zkp --lib`) | result | wall | peak RSS |
|---|---|---|---|---|
| 4 | `a3_close_prover_builds_and_verifies_real_close_proof` | **PASS** | 79.3 s | 10.52 GB |
| 5 | `a3_cancel_close_prover_builds_and_verifies` | **PASS** | 36.0 s | 5.97 GB |
| 6 | `a3_withdraw_registration_matches_close_member_set` | **PASS** | 1.5 s | 0.08 GB |

Each reported `0 ignored`, so none was silently skipped by the `debug_assertions` gate. Test 4 is the
real-input close path with no `test_fixture`: member Falcon signatures over the IMCH digest, the
`FalconAggCircuit` recursion, the balance-proof binding and the in-circuit soundness gates. Test 6 is
the Rust-side twin of the on-chain assertion in §2.3 — registration member set ≡ close member set.

All runs were sequential, one heavy process at a time. Highest peak observed: **14.28 GB**
(`--test e2e`), well inside the 36 GB budget.

---

## 6. Carry-in from the Phase-4 review (INFO-7): close provers RE-SIGN instead of consuming blobs

**Confirmed, and NOT fixed in this phase.** Evidence:

- `src/wallet_core.rs:3364` `falcon_member_auth_for_digest(member_keys, digest)` calls
  `keys.sign(digest)` per member and builds the `FalconAggWitness` from freshly minted signatures.
- `src/wallet_core.rs:3478` (`CloseProver::build_full_witness`) and `src/wallet_core.rs:3809`
  (`CancelCloseProver::build_full_witness`) are its only two callers. Both take
  `member_keys: &[K] where K: Borrow<FalconKeys>` — i.e. **the caller must hold every member's
  SECRET key**.
- `ChannelState.member_signatures: Vec<MemberSignature>` (`src/common/channel.rs:558`) already
  carries the collected blobs, and `build_full_witness` **ignores that field entirely**.

So production close currently presumes one party holds all member secrets. This is a real
architectural gap, not a cosmetic one.

### 6.1 Why it is SMALLER than it looks — the transport and the digest already line up

Two facts make the core conversion genuinely contained:

1. **The message is already identical.** `build_full_witness` uses `let digest = state.digest;`
   (`wallet_core.rs:3477`) — the IMCH state signing digest. That is *exactly* the digest the cosign
   flow signs (`wallet_core.rs:247` `sign_digest` → `encode_cosign_blob`, over the same
   `state.digest`), and the collected results are stored back into `state.member_signatures` in slot
   order (`wallet_core.rs:857-860`, sorted by `member_slot`). No new round trip, no new message
   format, no protocol step needs inventing.
2. **The `h` transport and its verifier already exist.** `decode_cosign_blob`
   (`src/falcon_sig/mod.rs:428`) recovers `(FalconSignature, [u16; FALCON_N])`, and
   `verify_cosign_blob` (`:462`) is documented as *"the only sanctioned entry point for verifying a
   `MemberSignature.signature`"* because it binds the transported `h` to the authenticated `pk_g`
   via `falcon_pk_digest(h) == pk_g` INSIDE the call (review F-2). `FalconAggWitness::for_signatures`
   (`src/falcon_sig/agg.rs:212`) already takes exactly `&[(&[u16; FALCON_N], &FalconSignature)]` —
   the precise tuple `decode_cosign_blob` yields.

### 6.2 Concrete sketch (NOT applied)

Add a sibling of `falcon_member_auth_for_digest` in `src/wallet_core.rs`:

```rust
/// Build the agg witness from COLLECTED member blobs instead of held secrets.
/// SECURITY: slot coverage is enforced fail-closed (exactly member_count sigs, slots a
/// permutation of 0..member_count) so a repeated slot cannot stand in for a missing signer;
/// `verify_with_pk_g` binds the transported `h` to the claimed `pk_g` (F-2) BEFORE proving.
fn falcon_member_auth_from_blobs(
    sigs: &[MemberSignature],   // state.member_signatures, slot order
    digest: Bytes32,            // state.digest
    member_count: usize,
) -> WResult<(Vec<Bytes32>, FalconAggWitness)>
```

body: reject `sigs.len() != member_count`; reject unless `member_slot` values are a permutation of
`0..member_count`; per slot `decode_cosign_blob(&ms.signature)?` then
`verify_with_pk_g(ms.pk_g, &h, digest, &sig)` (fail closed); reject duplicate `pk_g`; then
`FalconAggWitness::for_signatures(digest, &signers)`. Roughly 45 lines. Then give each prover a
`build_full_witness_from_state_signatures(...)` that drops the `member_keys` parameter and calls it.

### 6.3 Why it was NOT done here — three independent reasons

1. **Out of the stated scope.** This phase is fixture regeneration; the instruction is explicit that
   circuit and protocol logic must not change. This changes what production close TRUSTS (held
   secrets → verified transported blobs), which is a protocol-trust change even though no circuit
   moves.
2. **Blast radius is not contained even if the helper is.** `build_full_witness` has ~12 call sites
   (`src/wallet_core.rs` ×10 including tests, `src/bin/channel_member.rs:823` and `:1122`). Every
   one currently passes held keys. Some — the fixture generators and the CLI demo — legitimately DO
   hold all keys, so the old entry point cannot simply be deleted; both must coexist, and deciding
   which one production takes is a design call.
3. **It needs an adversarial review it cannot get from me.** CLAUDE.md §2 forbids the implementing
   agent from security-reviewing its own work, and this change is squarely soundness-relevant: the
   new path accepts ATTACKER-SUPPLIED bytes where the old path accepted only locally generated
   signatures. Slot-coverage, duplicate-`pk_g`, blob-version-downgrade, and digest-substitution
   (signatures collected for a DIFFERENT `state.digest` being replayed into a close) all become live
   attack surface and need a dedicated attacker subagent.

**RECOMMENDATION:** separate PR, with its own threat model, an attacker subagent, and a negative-test
matrix (wrong digest, replayed slot, duplicate `pk_g`, `h` not matching `pk_g`, legacy-version blob,
short/long blob, `member_count` mismatch). Recorded as STOP point 2.

## 7. Final status

**Steps 1–5 complete and green. No code, circuit, protocol, fixture, or test file was modified in
this session** — `git status` shows exactly one modified path, `doc/tasks/falcon-sig-phase5-notes.md`.
Nothing was committed.

The regenerated fixture set from the prior session (committed at `2e418f6`) is **validated, not
merely present**: 7 independent offline semantic checks (§3.2), 248/248 Foundry tests with **0
skipped** (§4), and 6/6 Rust proving tests (§5). No assertion was weakened and no test was skipped,
disabled, or relaxed at any point.

### 7.1 STOP points / UNVERIFIED

| # | item | status |
|---|---|---|
| **STOP 1** | The four `sepolia_*` fixtures are STALE (not regenerated). Re-confirmed this session: `grep` finds **zero** references under `contracts/test/`, only `script/DeployClose.s.sol` and `script/RunClose.s.sol`. `forge test` therefore never reads them and cannot detect their staleness. They need a target-network `WD_RECIPIENT` (a deploy decision), so they must be regenerated as part of the v3 reset/redeploy per `doc/tasks/regen-and-redeploy-runbook.md`. | **DEFERRED — deploy-time** |
| **STOP 2** | `CloseProver`/`CancelCloseProver` re-sign locally instead of consuming collected `MemberSignature` blobs (§6). Assessed as NOT contained: ~12 call sites, both entry points must coexist, and it newly accepts attacker-supplied bytes, so it needs its own threat model + attacker subagent. | **NOT DONE — separate PR (sketch in §6.2)** |
| **UNVERIFIED** | Test targets requiring a live chain / anvil (`onchain_deposit_keystone`, `close_lifecycle_cli_e2e`, `two_token_cli_e2e`, `partial_withdrawal_e2e`, `inter_channel_live`) and the WASM browser path (`wasm-pack` + HTTPS browser run) were **NOT executed** this session. Their status after the migration is unknown — not claimed green. | **UNVERIFIED** |
| **UNVERIFIED** | `e2e_fixture.json` / `e2e_groth16.json` remain in-tree with zero producers and zero consumers (§1.2). Dead, but not deleted this phase. | **UNVERIFIED / dead** |

---
