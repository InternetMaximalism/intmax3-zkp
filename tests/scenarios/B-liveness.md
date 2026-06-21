# Category B — liveness loss (party refuses / offline / out-of-order)

Funds or the channel get STUCK (not stolen) when a required actor doesn't act, or acts in the wrong
order. Most are testable at the Solidity-mock layer (state machine) + a few need the Rust/anvil E2E.
For each, the test should assert the stuck state AND the available recourse (or document that there is
none — that itself is the finding).

---

### B6 — nobody calls `requestClose()` → channel never exits
- **Severity**: liveness (funds trapped in-channel).
- **Layer**: Solidity mock (assert no non-`requestClose` path leaves Active) + doc.
- **Setup**: Active channel, members idle.
- **Assert**: no function transitions Active→ClosePending except `requestClose` (member-gated); confirm
  a non-member cannot start it and a member CAN. Document: if all members refuse, there is no exit.
- **Model-on**: `test_request_close_*` in `ChannelSettlementManager.t.sol`.

### B7 — `withdrawNative` credited the manager but `pullChannelFunds` never called
- **Severity**: liveness (funds in manager's `pendingWithdrawals`/balance, members can't claim).
- **Layer**: Solidity mock + Rust E2E.
- **Setup**: finalize + withdrawNative done; skip `pullChannelFunds`.
- **Steps**: a member calls `claimWithdrawalCredit`.
- **Assert**: reverts (`receivedChannelFunds == 0` → cap). Then call `pullChannelFunds` (permissionless)
  and re-claim → succeeds. Proves the recourse is "anyone pulls", and that without it everything blocks.

### B8 — grace/challenge clock never advances (low-traffic / stalled L1)
- **Severity**: liveness (local/low-traffic only).
- **Layer**: Rust+anvil (control time via `evm_increaseTime`/`evm_mine`).
- **Setup**: requestClose, then do NOT advance time.
- **Assert**: `submitCloseIntent` reverts `GracePeriodNotElapsed`; `finalizeClose` reverts
  `ChallengeWindowOpen`; both succeed once time is advanced. Documents the time-liveness dependency.

### B9 — all members lose keys / off-chain state → close proof unforgeable
- **Severity**: fund-loss (permanent lock).
- **Layer**: doc/spec test (no key → no proof). Optionally a Rust test asserting `CloseProver`
  cannot build a witness without the member signing keys.
- **Assert**: there is no recovery path; funds are permanently locked. Capture as an explicit
  acknowledged-risk test (so it can't silently regress into a worse failure).

### B10 — BP censorship grief (C2 special-close DISABLED) ★ key liveness gap
- **Severity**: liveness/fund-loss (a member can lose its fair share).
- **Layer**: Rust+anvil E2E (scenario walk) + doc.
- **Background**: `submitSpecialClose` now reverts (`SpecialCloseDisabled`), so there is NO on-chain
  remedy for a censoring block proposer. (`submitLateOutgoingDebitCorrection` also disabled.)
- **Attack to encode**: BP posts blocks excluding member A's settle tx → A's newer state can't be
  gossiped/included → A `requestClose()`s but cannot prove a higher state before the deadline → a
  STALE state finalizes → A loses funds. 
- **Assert (the recourse that DOES exist)**: a member can still bypass BP inclusion by submitting a
  fresh N-of-N-signed state directly via `submitCloseIntent` (it does not require BP inclusion). Encode
  BOTH: (a) the grief (stale finalize when A is passive), and (b) the manual recourse (A's direct
  submit wins on higher epoch/version). The test documents that the recourse is manual/reactive.
- **Notes**: do NOT re-enable C2; the test exists to PIN the residual liveness model + the workaround.

### B11 — challenge-deadline boundary recourse for the finalize caller
- **Severity**: liveness (low — `finalizeClose` is permissionless).
- **Layer**: Solidity mock.
- **Assert**: any address (not just the operator) can `finalizeClose` once
  `block.timestamp > challengeDeadline`; before that it reverts `ChallengeWindowOpen`. Confirms no
  operator-monopoly on finalize.

### B12 — operating before VK initialization → whole flow blocked
- **Severity**: liveness (operator setup error).
- **Layer**: Solidity mock (already-have unit reverts) + a Rust E2E that runs the flow on a deploy that
  SKIPPED a VK init.
- **Assert**: the corresponding step reverts (`CloseVkNotSet` / `WithdrawalClaimVkNotSet` /
  `WithdrawalVkNotSet`); document that the deployer must init all 4 VKs before the channel can exit.
