# Category F — close state-machine transition combinations

Combinations of the manager's lifecycle transitions not currently exercised. Mostly Solidity mock-MLE
(`ChannelSettlementManager.t.sol` style; fast, no proving). These pin that illegal/odd orderings revert
and legal ones preserve invariants. Good candidates to ALSO express as Foundry invariant tests (see G).

Status: `Active(0) → ClosePending(1) → Closed(2)`. Mutators: `requestClose`, `submitCloseIntent`,
`cancelClose`, `finalizeClose`. Terminal: `Closed`.

---

### F30 — actions after `Closed` (terminality)
- **Setup**: drive to Closed (request→grace→submit→challenge→finalize).
- **Assert**: `requestClose` reverts `ChannelClosed`; `submitCloseIntent` reverts `ChannelClosed`;
  `cancelClose` reverts (CloseNotActive / ChannelClosed); `finalizeClose` again reverts
  (CloseAlreadyFinalized / not active). Pin Closed is absorbing; only the payout path (withdrawal/
  post-close claim + claimWithdrawalCredit) remains.

### F31 — post-close-claim vs withdrawal-claim ordering & multiplicity
- **Setup**: after finalize+pull, submit them in both orders and submit MULTIPLE post-close claims for
  DIFFERENT receiver slots.
- **Assert**: order-independent; each receiver paid once; combined sum capped by `receivedChannelFunds`;
  each nullifier (`usedWithdrawalNullifiers` / `usedSharedNativeNullifiers`) used once. (Today only a
  single post-close claim is tested.)

### F32 — replace/challenge submitted AFTER the deadline
- **Setup**: pendingClose v1; warp past `challengeDeadline`; submit a higher v2.
- **Assert**: rejected (replacement only before deadline); v1 remains finalizable. (Distinct from the
  before-deadline tiebreaker that IS tested.)

### F33 — same member claims twice (different claim data, same slot)
- **Setup**: member submits a withdrawal-claim; then a second claim for the same slot with different data.
- **Assert**: nullifier (keyed by member identity + close digest) blocks the second; no double payout.

### F34 — cancelClose → reclose → cancelClose … (freeze-era cycling)
- **Setup**: repeat requestClose/cancelClose K times, then close+finalize.
- **Assert**: `currentCloseFreezeNonce` increases monotonically; each fresh close needs a fresh
  requestClose + grace; a close intent proved at an OLD freeze nonce is rejected (`InvalidFreezeNonce`);
  the final close binds the current nonce. Pin the era accounting across cycles.

### F35 — multi-level reentrancy on the payout paths
- **Setup**: a malicious recipient contract that re-enters `claimWithdrawalCredit` / `pullChannelFunds`
  / `withdraw()` from its `receive()`/fallback, including nested 3+ levels.
- **Assert**: `nonReentrant` blocks all re-entries; credit/escrow accounting unchanged; no double pay.
  (Today only a simple 2-level claim reentry is tested.)

### F36 — submitCloseIntent with a freeze nonce that doesn't match the post-request nonce
- **Setup**: prove a close at `close_freeze_nonce = N` but submit when the manager's
  `currentCloseFreezeNonce = M ≠ N` (e.g., after an extra cancel/request cycle).
- **Assert**: reverts `InvalidFreezeNonce`. (The healthy path is `state+1 == post-request nonce`; pin the
  mismatch is rejected — guards against the freeze-era confusion explored this session.)

### F37 — challenge with EQUAL epoch AND equal version (exact tie)
- **Setup**: submit v with (epoch e, version s); challenge with identical (e, s).
- **Assert**: reverts `CloseNotNewer` (strict-greater required). (Tiebreaker is tested; pin the exact
  equality boundary.)
