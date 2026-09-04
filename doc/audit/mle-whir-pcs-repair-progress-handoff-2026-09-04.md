# MLE/WHIR PCS repair: proof cohort completed (2026-09-04)

> **Superseded later the same day** by `mle-whir-gas-envelope-2026-09-04.md`: the target-133 /
> inverse-rate-4 profile described below was replaced by target-105 / inverse-rate-6 and the
> verifier was optimized so the cold close path fits a 20,000,000-gas envelope. The proof cohort,
> fixture and gas numbers in this file describe the retired profile.

Continues `mle-whir-pcs-repair-progress-handoff-2026-09-03.md`. That checkpoint had all 15
proof-free target-133 configs but only 7 of the 16 parent full wire-v3 proofs.

## Status

**Release status: still NO-GO**, for the reasons that code generation cannot close (see the end).
Everything the previous handoff listed as "required next steps" that a machine can do is now done:
all 16 full proofs are wire v3 / target-133, the canonical partial-withdrawal proof was produced on a
fresh 30 M-gas Anvil, both WASM packages were rebuilt from the final source, and the complete Step 4
acceptance matrix was run. One real blocker surfaced and was fixed in the submodule (gas, below).

Parent branch: `codex/release-blockers-2-5-20260831` lineage (this worktree branch fast-forwards it).
Submodule branch: `codex/whir-leaf-consistency-20260830`, now at `96b5836c` (was `5b1c28ae`).
Parent commit: see `git log -1` on the branch this file lands on.

## What was done, in order

1. Step 0 preconditions: `cargo build --release --locked --offline`, `forge build --offline`, and the
   three submodule codegen drift tests (`protocol_schema_codegen`, `protocol_schema_v2_codegen`,
   `whir_profile_v2_codegen`) all passed before any artifact was written.
2. Regenerated the nine stale full proofs sequentially from the documented generators
   (`burn`, `close`, `withdrawal_claim`, `post_close_claim`, `cancel_close`, `c2c`, `wasm`):

   | generator | wall | max RSS |
   |---|---:|---:|
   | generate_burn_withdrawal_fixture | 2m15s | 15.6 GB |
   | generate_close_fixture | 3m02s | 11.9 GB |
   | generate_withdrawal_claim_fixture | 4m48s | 31.6 GB |
   | generate_post_close_claim_fixture | 4m51s | 31.8 GB |
   | generate_cancel_close_fixture | 2m31s | 6.7 GB |
   | generate_c2c_fixture | 2m47s | 16.3 GB |
   | generate_wasm_fixtures | 0m28s | 11.3 GB |

   The `close_` family and the Manager address were not touched; the printer test still reports
   `0xFE7cb59C300218C04aE5360f77cDa771019eabb7` after every change in this session, equal to the
   recipient baked into `close_withdrawal_payout.json`. Companions whose content is deterministic
   (`close_intent.json`, `withdrawal_claim.json`, `post_close_claim.json`, `cancel_close.json`,
   `burn_withdrawal_payout.json`, `c2c_withdrawal_payout.json`, `pw_reg.json`, `pw_submit.json`)
   were rewritten byte-identically and therefore show no diff.
3. First run of `partial_withdrawal_e2e_anvil` **failed**: `submitPartialWithdrawalIntent` reverted
   on the 30,000,000-gas Anvil. `ManagerCloseGas` reproduced it: the cold Manager path needed a
   transaction budget between 30.20 M and 30.25 M (execution 26,767,981 at an unbounded budget plus
   3,002,476 intrinsic calldata gas; the innermost `OutOfGas` lands in the gate evaluator, the last
   phase). Per-call breakdown at that point: WHIR 11.69 M, gate evaluator 4.24 M, outer logup
   3.06 M, Poseidon 103-PI hash 1.74 M, core-internal ~3.6 M, adapter decode/ABI ~1.89 M, Manager
   ~0.49 M.
4. Fix (submodule `96b5836c`): `PinnedMleVerifierV2` kept its 7,456-byte `VerificationConfig` in
   ~170 storage slots and re-read them cold on every verification (~366 k gas). It now stores the
   exact ABI encoding in an immutable `STOP`-prefixed data contract created by its constructor and
   loads it with one `EXTCODECOPY` + `abi.decode`, with the byte length pinned as an immutable.
   Constructor validation, the absence of any mutator, the external ABI, and all core checks are
   unchanged. Cold Manager execution gas: 26,767,981 -> 26,401,683 (first proof); the harness now
   passes at 30 M and fails at 29.85 M. Also fixed in the same commit: the packed-v1
   `TranscriptE2ETrace` test hard-coded a terminal digest from an older `small_mul.json`; the Rust
   golden regenerated from the current fixture (`MLE_WRITE_TRANSCRIPT_TRACE=1` yields no diff) ends at
   `0x0852dd5c...a298`, the Solidity replay reaches the same state, and the constant now matches.
   That test was failing on the pristine `5b1c28ae` tree as well.
5. Second `partial_withdrawal_e2e_anvil` run: PASS. Real on-chain submit used **29,436,498** gas of
   the 30,000,000 block/transaction limit (margin 563,502). It rewrote `pw_close_intent_mle.json`
   (wire v3, 195,556 compact bytes); `pw_reg.json`/`pw_submit.json` came out byte-identical.
   `ManagerCloseGas` against that exact proof: cold execution 26,422,385, PASS at 30 M.
6. WASM packages rebuilt from the final source (`pkg/`, `pkg-node/` did not exist beforehand):

   | file | sha256 |
   |---|---|
   | pkg-node/intmax3_zkp_bg.wasm | 58a3f896d7a2fd6d5cfda4dc13151da994aeeccb962f9dc0402459441e63a421 |
   | pkg-node/intmax3_zkp.js | bbe513a2963f86c944bcda9f93e5312ee3a39189a9b0459402c1131bd0e9baf4 |
   | pkg/intmax3_zkp_bg.wasm | 88f30ca8490955e6d440680b48cf449feb1dccfc0f151e6553fb147aa66ada96 |
   | pkg/intmax3_zkp.js | f621535134fb154bfac41eb738c784dd568b18021aaa5099cfcbd6ff2074a142 |

   `wasm-opt` is not installed on this machine, so the browser package is un-optimized
   (the build script documents this as acceptable).
7. First Step 4 acceptance run: four gates failed. None was a proof defect; each is fixed below and
   the matrix was rerun over the final cohort (table below).
   - `mle_v2_fixture_release::all_companions_bind_to_their_proofs_and_release_relationships`
     recomputed the partial-withdrawal settled-tx chain as `push(prev, burn_tx_leaf)`. The wallet,
     the Manager (`keccak("IMTC" || prev || withdrawal.auxData)`) and the E2E all push the IMD2
     descriptor (`withdrawal_aux_data`); the test, added in the 2026-09-03 checkpoint and never run
     against a real partial-withdrawal proof, was corrected to the protocol formula.
   - `ProofDaCodec` / `BlobKzgPairing` pinned the submodule's `v2_max_resource.json` at 194,244
     bytes and an old keccak; the regenerated fixture is 195,012 bytes (as the submodule README
     already stated) with keccak `0xf1094bb2...ced0f`, which the fixture records itself and an
     independent keccak confirms. Both test constants now match.
   - `forge build --sizes`: `FixtureParsingHarness` (test-only) had grown to 66,489 bytes because
     its `deployPinnedMleV2` helper embeds the creation code of both verifier contracts. The
     helper moved onto the test contract (excluded from the EIP-170 gate); the harness is 9,588
     bytes and every production contract is unchanged and within limit.
   - `node` tests: `api/node_modules` was absent in this worktree (several suites import express
     from there); `npm ci --ignore-scripts` in `api/` fixed it. 438 pass, 0 fail, 8 skipped.
   - `CloseLifecycleE2E.test_closeLifecycle_endToEnd` (forge guard) failed three times in a row,
     each one Manager check deeper. The 2026-09-02 release-blocker commit added Manager-side
     bindings that the fixture generators and the E2E deploy base did not yet satisfy:
     1. `ChannelFundStateRootNotFinalized`: the close fixture proved a synthetic
        `channel_fund_intmax_state_root` (`0x00000001_00000002_...`). `generate_close_fixture`
        now proves over `close_lifecycle.json.final_state_root`, via a new
        `build_close_full_witness_two_token_with_state_root` builder (in-tree circuit tests keep
        the synthetic default).
     2. `CloseFundingAuxMismatch`: the close payout carried `aux_data = 0`. In `close_` mode
        `generate_withdrawal_fixture` now computes `close_funding_aux_data(31337, rollup,
        manager, channel 1, freeze nonce 1, token-funds digest)` from `close_intent.json` (digest
        recomputed and cross-checked) and requires `WD_CLOSE_FUNDING_ROLLUP`; the printer test
        also emits `CLOSE_ROLLUP_ADDRESS`. Because the withdrawal is part of the finalized chain,
        the lifecycle root changes with the aux, so the order is: aux-bound `close_` pass, then
        the close intent over the new root (runbook Step 3 updated). Manager
        `0xFE7cb59C300218C04aE5360f77cDa771019eabb7` and Rollup
        `0xc2e78F7a2D2ABFaEA7bd9F3A158E1FA82d3b1E2b` were stable across every pass.
     3. `NotRegisteredSettlementManager`: `CloseE2EBase._deployAll` never called
        `rollup.registerSettlementManager(manager)`, which every broadcast script does and the
        runbook's Step 2 lists. Added (pranked from the CREATE2 factory, the Rollup's deployer).
     The E2E now runs registration -> finalize -> requestClose -> submitCloseIntent ->
     finalizeCloseGuarded -> withdrawNative -> pullChannelFunds end to end with real proofs.
   - Note: `tests/mle_onchain_e2e.rs` runs `generate_e2e_fixture` itself, so every acceptance run
     rewrites `mle_fixture.json` and `block_fixture.json` (proof bytes are not deterministic across
     runs). The committed pair is the one produced by the final acceptance run; the release test
     was rerun after it.
8. Second Step 4 acceptance run over the final cohort: see the table below.

## Acceptance matrix (Step 4)

| gate | result |
|---|---|
| submodule `cargo test -p plonky2_mle --all-targets --locked --offline` | PASS (26 test binaries, 0 failures; conformance test 367 s) |
| submodule `forge test --offline` | PASS 347/347, 27 suites |
| parent `cargo test --release --test mle_onchain_e2e` | PASS (regenerates `mle_fixture.json`; committed pair is from this run) |
| parent `cargo test --release --test mle_v2_fixture_release` | PASS 10/10 |
| parent `cargo check --all-targets --locked --offline` | PASS |
| `node`: `npm ci --ignore-scripts && npm test` (with `api/` deps installed) | PASS 438, fail 0, skipped 8 |
| `forge test --match-contract V2FixtureCompletenessTest` | PASS 17/17 |
| `FORGE_TEST_ARGS=--offline .github/ci/forge-test-guard.sh` | PASS: 578 tests, 45 suites, 0 skipped, all floors met |
| `forge build --sizes --offline` (parent) | PASS; production runtime bytes: `ChannelSettlementManager` 22,502 (margin 2,074), `IntmaxRollup` 15,971, `ChannelSettlementVerifier` 7,318, `CloseFundingMaterializer` 4,592, `MleVerifierV2` 20,782 (3,794), `PinnedMleVerifierV2` 12,570 (12,006), `SpongefishWhirVerify` 23,771 (805) |
| `forge build --sizes --offline` (submodule) | PASS |
| `git diff --check` | PASS |
| `git submodule status` | `96b5836c` on `codex/whir-leaf-consistency-20260830` |

Two guard floors were below their pinned minimum after the 2026-09-03 checkpoint retired
packed-v1 tests without re-baselining: `MleE2ETest` (5 < 6) and `FixtureParsingGuardsTest`
(12 < 17). Rather than lower the floors, both suites regained coverage of the wire-v3 surface:
`MleE2E` gained truncated-stream and cross-statement (validity proof against the max-resource
adapter, and vice versa) rejection tests (7 tests); `FixtureParsingGuards` gained schema, layout-
hash, recorded-length, recorded-keccak and empty-bytes drift rejections plus a positive parse of
the checked-in max-resource fixture (18 tests). The printer/CloseLifecycleE2E pair was re-run after
every `.t.sol` edit; the Manager and Rollup addresses did not move.

## Gas margin: a decision for the release owner

The 30,000,000-gas envelope is a repository policy (`ManagerCloseGas`, `SubmitPartialWithdrawal`,
`partial_withdrawal_e2e`, the forge guard). With target-133 the close statement now uses about 98 %
of it on the conservative cold harness (~150 k spare) and about 98.1 % on real Anvil (~560 k spare).
Proof-to-proof variance observed for the close statement is small (two proofs: 25,904,586 vs
25,899,517 PI-return execution gas; compact size 194,788 vs 195,556 bytes), so the gate is
expected to hold, but the margin is thin. Options, none taken here:

- Accept the margin as is (current state; gates pass).
- Recover another ~0.5 M by transcoding compact bytes directly into the core's ABI layout inside
  the adapter, avoiding the decoded `MleProof` memory image plus a second `abi.encode` (memory
  expansion is quadratic; the adapter's remaining overhead is ~1.5 M). Larger, riskier change to
  audited code; availability-only failure mode since the core still verifies everything.
- Revisit the 30 M policy against the target chain's actual block limit.

## Outstanding release blockers that code generation cannot close (unchanged)

- The 128.356-bit figure is a generic-work-factor bound, not a literal random-oracle failure
  probability; the protocol-specific Fiat-Shamir/grinding reduction and composition proof are
  still required.
- The independent external cryptographic review has not been obtained.
- Parent Goldilocks/Poseidon recursion is independently estimated near 95-bit security.
- Separate final-audit operational blockers remain (public close-proof availability, live
  withdrawal producer, channel-scoped Manager backing, browser/public-claim E2E, atomic MSU).
