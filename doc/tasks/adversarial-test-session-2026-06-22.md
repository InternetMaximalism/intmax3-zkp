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

## Not done (deferred — need heavy proving / anvil, user deferred)
- A1/A2 lifecycle-bound real-proof claim fixture + Solidity real-proof negatives (A3/A4/A5).
- C15 (in-proof double deposit), C16 (demo-mode fold), B/D/E heavy Rust+anvil scenarios.
- Possible follow-up: G heavy Rust generators.
