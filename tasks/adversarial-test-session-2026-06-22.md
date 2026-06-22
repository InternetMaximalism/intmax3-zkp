# Close-settlement adversarial test session — outcomes (2026-06-22)

Goal (user): write many adversarial tests WITHOUT changing implementation; find problems in the
real code; tests need not pass; report results. Focus: fast layers (Solidity mock-MLE + native
Rust); avoid the 16-min anvil path.

## Handoff staleness correction
- The handoff's "single biggest blocker" (no `generate_withdrawal_claim_fixture`) is STALE: that
  binary + `generate_post_close_claim_fixture` + their fixtures already landed in commit `1031f38`.
- The genuine A1/A2 gap remains: the checked-in `withdrawal_claim.json` is synthetic (channel 3,
  `member_pk_g 0x0000000a…`), not co-generated against the lifecycle (channel 1). So
  `CloseLifecycleE2E.t.sol:191-201` still stops at `finalizeClose`. (Not addressed — needs heavy
  proving / the anvil path the user deferred.)

## New test files (all ADDED; zero edits to implementation or existing tests)
- `contracts/test/CloseSettlementBase.sol` — shared abstract harness (no tests; existing suite not re-run).
- `contracts/test/ChannelSettlementAdversarial.t.sol` — 10 tests (unit + bounded fuzz).
- `contracts/test/ChannelSettlementInvariant.t.sol` — handler + 6 stateful invariants.
- `tests/withdrawal_nullifier_canonicality.rs` — 4 native canonicality tests (C14).

## Results
- Solidity `ChannelSettlement*`: 82 passed / 0 failed (existing 66 + new 10 + new 6).
  Invariant run: 256 runs × 500 calls = 128k calls, 0 violations.
- Rust C14: 4 passed.

## Findings
1. **Manager payout accounting is SOUND** under arbitrary sequences (invariant fuzz, 128k calls):
   I1 solvency `totalCreditedOut ≤ receivedChannelFunds`; I2 conservation
   `totalWithdrawn == totalCreditedOut + Σcredits`; I3 accrual cap `≤ finalizedChannelFundAmount`;
   I4 ETH backing `balance == received − creditedOut`; I5 terminal-Closed. No violation.
   Composed cases hold: C17 ordering, C18 over-declare (received cap wins), shared withdrawal+
   post-close budget, multi-member received cap.
2. **C14 (nullifier double-claim) — NOT exploitable.** Withdrawal nullifier is computed in-circuit as
   `settled_transfer.nullifier()` (src/circuits/withdraw/single_withdrawal_circuit.rs:512), a
   Poseidon hash over the full economic identity + position (channel, transfer_index, block_number),
   aux_data included. Every binding field is load-bearing (pinned by the Rust tests). Two valid
   proofs for "one payment" require two distinct positions = two legitimate payments.
3. **A6 — `bpBondCredits` INERT + `fundBpBondCredits` footgun (LOW).** Setter is non-payable,
   ungated, value feeds no payout/cap path → freely inflatable for free but harmless while
   special-close (C2) is disabled. Pinned by test.
4. **Over-pull surplus LOCKED (LOW / defense-in-depth).** If `receivedChannelFunds` ever exceeds
   `finalizedChannelFundAmount`, the surplus ETH is unrecoverable (accrual capped at the declared
   fund; no sweep/admin). Should not occur with honest proof-bound intents; pinned so a regression
   turning surplus into over-payout would be caught.

## Heavy-compute continuation (branch `test/heavy-close-scenarios`, compute authorized)
Run in an ISOLATED worktree from a92335b (clean tree, MAX_CHANNEL_MEMBERS=16) because an external
branch-switch tool (`epitaxy`) had applied another branch's work (MAX_CHANNEL_MEMBERS 16->1024 +
an unmerged file) onto the main working tree mid-session; fixtures must not be built against that.

- **Live baseline E2E GREEN** (handoff §7): `close_lifecycle_cli_e2e --ignored` passed in 1006s — full
  deposit→finalize→withdrawNative→pull→close→finalize→REAL withdrawal-claim→claim; a member received
  40000000 wei real ETH. Worktree clean afterward (WorkspaceGuard). Validates the A1 circuit→on-chain
  real-claim path live.
- **C15 (in-proof double deposit) — NOT exploitable.** `tests/deposit_nullifier_canonicality.rs` (4
  tests): the deposit nullifier IS the deposit-tree leaf hash (poseidon over the full deposit incl.
  deposit_index + block_number), Merkle-proven at deposit_index against public_state.deposit_tree_root.
  One on-chain deposit => one nullifier; re-fold at a different block/index needs a leaf absent from the
  tree. (Note: `hash_with_prev_hash` excludes block/index but is the chain hash, not the tree leaf — the
  test pins leaf==nullifier so a regression decoupling them is caught.)
- **A1/A3/A4 (withdrawal-claim) real-MLE on-chain — `contracts/test/WithdrawalClaimRealProof.t.sol`**
  (7 tests): A1 the real withdrawal_claim_mle.json proof verifies on-chain via the REAL MleVerifier
  (~22M gas = real WHIR ran); A3 wrong finalized H1 rejected; A4 wrong member/recipient rejected; plus
  wrong amount/channel/nullifier. Direct verifier call supplies expected limbs => no co-generation.
- **A2/A5 (post-close-claim) real-MLE on-chain — `contracts/test/PostCloseClaimRealProof.t.sol`**
  (6 tests): A2 real 56-limb proof verifies on-chain; A5 wrong accumulator root rejected; plus wrong
  H1/receiver/nullifier/amount. H1 + accumulator root reconstructed from the proof publicInputs
  (limbs 40..48 / 48..56) because the descriptor omits them (see finding below).
- Full close suite: **95 passed / 0 failed** (66 existing + 10 + 6 + 7 + 6). Rust native: C14 4 + C15 4.

### Additional finding (LOW, fixture tooling)
`generate_post_close_claim_fixture`'s descriptor (`post_close_claim.json`) OMITS
`final_balance_state_h1` and `final_settled_tx_accumulator_root`, both required by `verifyPostCloseClaim`.
Worked around by reconstructing from the proof publicInputs; cleaner fix is to add the two fields to the
descriptor struct in `src/bin/generate_post_close_claim_fixture.rs`.

### Handoff "biggest blocker" fully retired
A real-proof Solidity claim test (A1) was the handoff's #1 priority; the existing real fixtures suffice
for a DIRECT verifier test (positive + negatives), so no lifecycle co-generation was needed. The
lifecycle-bound fixture (so the FULL manager path runs `submitWithdrawalClaim` with a real proof inside
`CloseLifecycleE2E`) remains a separate, lower-value follow-up (the live CLI E2E already proves that path).

## Still not done (deferred)
- C16 (demo-mode setup-backing × withdraw fold mismatch) — needs the heavy CLI demo path on anvil.
- B/D/E heavy Rust+anvil scenarios; G heavy Rust generators.
- Lifecycle-bound (co-generated) withdrawal-claim fixture so `submitWithdrawalClaim` runs real inside
  `CloseLifecycleE2E.t.sol` (currently stops at finalizeClose).
