# Fixes for audit findings (A-2–A-5, B-1–B-5)

Branch: `fix/audit-soundness-and-tests` (branched from main)
Plan: `/Users/plasma/.claude/plans/sleepy-questing-creek.md`

## Phase 1: A-2 + B-2 — on-chain enforcement of validity VK degreeBits==0
- [x] `IntmaxRollup.sol`: `error ValidityVkDegreeBitsZero`, `bool immutable allowMleDisabled`, constructor guard, `_verifyMle` double guard
- [x] Added the argument to every `new IntmaxRollup(...)` / `BlockHashHarness` call site (production scripts=false, tests=true, close CREATE2=false)
- [x] B-2: deleted the empty placeholder `test_finalize_realE2E_PENDS_F6` and documented in a comment where the real coverage lives; added a note to `test_finalize_success` that it is limited to PI binding
- [x] New tests: revert with an empty VK in production mode, allowed with the test opt-in → 2 tests PASS
- [x] forge build OK / IntmaxRollup suite 48 PASS
- [x] **A-2 fully resolved**: regenerated the close-lifecycle fixture with the new manager address (`0x219Bb8e259Ec550aE8Ea9B9cc250149812b5C7Ca`) (`WD_RECIPIENT=... WD_OUT_PREFIX=close_ cargo run --release --bin generate_withdrawal_fixture`). CloseLifecycleE2E PASS. **All forge: 140/140 PASS, 0 failed**.
  - Caution (fragility of the existing design): the baked CREATE2 address reacts even to comment changes in the IntmaxRollup-family sources, via the Solidity metadata hash. From now on, if IntmaxRollup.sol / BlobKZGVerifier.sol etc. are edited, the close-lifecycle fixture must be regenerated (this is not caused by A-2).

## Phase 2: A-3 — making the close lifecycle stubs safe (the real implementation is a separate PR)
- [x] Turned the all-zero anchor in `channel_member.rs` into a named constant with an explicit OPEN marker, and made `close`/`withdraw`/`settle` fail-closed stubs
- [x] Created the follow-up ticket `doc/tasks/a3-close-lifecycle-followup.md`

## Phase 3: A-4 — ticket update only (doc)
- [x] Marked CRITICAL-1 in `doc/tasks/inter-channel-live.md` as CLOSED (with rationale)

## Phase 4: A-5 — comment reinforcement only (no bug)
- [x] Added a SECURITY comment to the `BlobKZGVerifier.sol` fast path

## Phase 5: B-1 — turn mle_onchain_e2e into real on-chain verification
- [x] In `tests/mle_onchain_e2e.rs`, launch forge (MleE2E/MleFinalize) after fixture generation and assert real verification; skip explicitly when forge is absent

## Phase 6: B-3 / B-4 — add negatives against the real verifier/manager
- [x] B-4: `MleE2E.t.sol` (baseline+3 negatives) / `MleFinalizeE2E.t.sol` (tamper→false) → PASS
- [x] B-3: added a verdict=false reject negative to `ChannelSettlementManager.t.sol` → PASS

## Phase 7: B-5 — eliminating sham Rust tests
- [x] B-5a `verify_wasm_proof.rs` vacuous skip → `#[ignore]`+doc, panic when absent (eliminating vacuous green)
- [x] B-5b added `.verify()` for the sender/receive proofs in `wasm_proofs.rs::wasm_balance_processor_flow`
- [x] B-5c added a lightweight negative (rejecting an empty transport) to `inter_channel_e2e.rs` + made its smoke-test positioning explicit
- [x] B-5d renamed `inter_channel_validity_b2.rs` → `small_block_sig_validity.rs` + added a scope note, updated the detail2.md reference
- [x] B-5e added a state-preserving transition-invariant assertion to the join in `wallet_delegate_demo.rs`

## Heavy computation (needs permission, not yet done)
- [ ] close_lifecycle fixture regeneration (caused by A-2; updating the baked manager address in CloseLifecycleE2E setUp)
- [ ] Rust compilation + running the relevant Rust tests (mle_onchain_e2e, wasm_proofs, inter_channel_e2e, wallet_delegate_demo, small_block_sig_validity) — heavy because of proof generation

## Solidity verification status (complete)
- forge build OK / IntmaxRollup 48 / ChannelSettlementManager 66 / MleE2E 6 / MleFinalizeE2E 2 PASS
- All forge: 133/134 PASS, the only outstanding one is CloseLifecycleE2E awaiting fixture regeneration (above)

## Findings log
- Approach adopted for A-2: an explicit deploy flag (constructor `_allowMleDisabled`). Production is false, so degreeBits==0 reverts; `_verifyMle` is also double-guarded by the flag.
- Gotcha re-confirmed: changing IntmaxRollup's bytecode invalidates the baked CREATE2 address of the close-family fixtures (consistent with the memory project_delegate_account.md). A-2 inherently triggers this, so fixture regeneration is unavoidable.
