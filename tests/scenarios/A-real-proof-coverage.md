# Category A — real-MLE/WHIR coverage gaps (currently mock-only on-chain)

Today `submitWithdrawalClaim` / `submitPostCloseClaim` are verified on-chain ONLY with the mock
`MleVerifier` (`ChannelSettlementManager.t.sol` via `CloseTestLib.dummyStatementVkArgs()`). The Rust
circuit self-verify tests exist, and the CLI E2E drives a real claim, but there is no Solidity
real-proof fixture coverage nor real-proof NEGATIVE tests. **Prerequisite for most of A: a
`generate_withdrawal_claim_fixture` binary** (see README "single biggest blocker").

---

### A1 — withdrawal-claim verified on-chain with a REAL proof
- **Severity**: high (largest blind spot; payout path).
- **Layer**: Solidity real-MLE (extend `CloseLifecycleE2E.t.sol`) and/or Rust+anvil.
- **Setup**: a lifecycle whose finalized H1 + member set match a co-generated withdrawal-claim proof.
  Requires a new `generate_withdrawal_claim_fixture` that proves a member's slot claim bound to the
  SAME `finalBalanceStateH1`/members as `close_*`/`withdrawal_*`.
- **Steps**: deploy + init close/withdrawal-claim VKs from the real fixtures → finalizeClose →
  pullChannelFunds → `submitWithdrawalClaim(real proof)` → `claimWithdrawalCredit`.
- **Assert**: member receives exactly its slot amount in real ETH; `totalCreditedOut` increments;
  nullifier marked used; `totalCreditedOut ≤ receivedChannelFunds`.
- **Model-on**: `WithdrawNativeE2E.t.sol` (real fixture deploy/init), `CloseLifecycleE2E._initRealCloseVk`.
- **Notes**: the CLI E2E (`tests/close_lifecycle_cli_e2e.rs`) already does this through the CLI; A1 is
  the FIXTURE/Solidity-unit version + the foundation for A3.

### A2 — post-close-claim verified on-chain with a REAL proof
- **Severity**: high.
- **Layer**: Solidity real-MLE.
- **Setup**: a real post-close-claim proof (56-limb, Stage-3) bound to the finalized H1 + settled-tx
  accumulator root of the SAME lifecycle, for an incoming inter-channel tx.
- **Steps**: finalizeClose → pullChannelFunds → `submitPostCloseClaim(real proof)` → credit paid.
- **Assert**: receiver gets the shared-native amount; `usedSharedNativeNullifiers` set; combined with
  any withdrawal-claims stays under `receivedChannelFunds`.
- **Model-on**: `PostCloseClaimProver` (Rust) for fixture gen; `CloseLifecycleE2E` for on-chain.

### A3 — real-proof NEGATIVE: stale / wrong-H1 withdrawal-claim rejected
- **Severity**: high (fund-loss prevention).
- **Layer**: Solidity real-MLE.
- **Setup**: a real claim proof bound to a DIFFERENT `finalBalanceStateH1` than the channel's finalized
  one (the manager injects the finalized H1 into the expected limbs).
- **Steps**: submit the mismatched real proof.
- **Assert**: revert `claim limb mismatch` (NOT a mock verdict — a genuinely wrong-H1 real proof).
- **Notes**: today only the mock helper (always-correct H1) is exercised; this proves the injection
  actually binds a real proof.

### A4 — real-proof NEGATIVE: member claims another member's slot
- **Severity**: high.
- **Layer**: Solidity real-MLE + Rust (build a claim for slot i but submit as member j / recipient j).
- **Assert**: rejected (member_pk_g / recipient binding); no payout to the wrong recipient.

### A5 — real-proof NEGATIVE: wrong accumulator root post-close-claim
- **Severity**: high.
- **Layer**: Solidity real-MLE.
- **Setup**: real post-close proof with an accumulator root ≠ the finalized one the manager injects.
- **Assert**: revert `claim limb mismatch`.

### A6 — `fundBpBondCredits` exercised (currently ZERO coverage)
- **Severity**: low-medium (dead-ish with C2 disabled, but still callable).
- **Layer**: Solidity mock.
- **Steps**: fund the BP bond, read `bpBondCredits`; confirm it is NOT consumable by any live path
  (C2 disabled) and does not affect the solvency cap / member claims.
- **Assert**: bond accounting is isolated; no path lets it inflate `receivedChannelFunds` / payouts.
- **Notes**: documents that the bond pot is inert while C2 is reverted (see B10).
