# Category C — fund-loss-risk close situations

Situations where funds could be lost, double-paid, or misbound. Several of these are SUSPECTED-safe
(guarded by caps/nullifiers/fail-closed) but UNTESTED at the boundary; a few (C14, C15) are potential
real findings — if a test shows a payout where it shouldn't, STOP and escalate (do not "fix the test").

---

### C13 — challenge race: stale (lower-balance) state finalizes
- **Severity**: fund-loss within the accepted challenge model — but the boundary is untested.
- **Layer**: Solidity mock (control timestamps) + Rust E2E.
- **Setup**: submit close-intent for state v1; an honest higher state v2 exists but its `submitCloseIntent`
  arrives AFTER `challengeDeadline`.
- **Steps**: try to replace with v2 after the deadline.
- **Assert**: v2 replacement is rejected after the deadline (only-before-deadline replace); v1 finalizes;
  the member bound to v2's extra balance cannot claim it. Document this as the accepted liveness/fairness
  boundary (so a regression that makes it WORSE — e.g. accepting an even-lower state — is caught).

### C14 — nullifier serialization divergence → double claim ★ potential real finding
- **Severity**: fund-loss (critical IF exploitable).
- **Layer**: Rust (nullifier determinism) first; then Solidity if reproducible.
- **Hypothesis (from adversarial map)**: if the SAME economic settle tx can be serialized into two
  withdrawal leaves with DIFFERENT `aux_data`/field order, their Poseidon nullifiers differ →
  `withdrawalNullifierUsed` does not catch the second → paid twice.
- **Steps**: construct two leaves for one logical payout with differing aux/order; compute nullifiers;
  if distinct, attempt both `withdrawNative`/`claimWithdrawalCredit`.
- **Assert (desired)**: the nullifier is canonical over the economically-binding fields so the two
  collide and the second reverts. **If they don't collide and both pay → ESCALATE (real bug).**
- **Notes**: verify the nullifier preimage (`Withdrawal::nullifier` / the in-circuit derivation) covers
  exactly the binding fields; this is a soundness check, not just a test.

### C15 — in-proof double deposit → channel mints 2× funds
- **Severity**: fund-loss (operator fraud / honest over-credit).
- **Layer**: Rust+anvil (build a withdrawal/validity proof that folds the SAME deposit twice).
- **Steps**: generate a proof where one deposit is folded into two blocks; post matching blocks; finalize.
- **Assert (desired)**: either the circuit/`deposit` indexing forbids re-folding the same deposit_index,
  OR `totalEscrowed` underflow stops the over-withdraw at the rollup. Confirm the channel CANNOT realize
  more than was actually deposited. **If it can → ESCALATE.**
- **Notes**: pairs with E (block/deposit folding); the global `totalEscrowed` cap should backstop, but
  intra-/inter-channel fairness is the concern.

### C16 — demo-mode (real setup-backing deposit) × withdraw fold mismatch ★ known surface
- **Severity**: fund-loss-adjacent (finalize fails → funds stuck) — the exact bug found this session.
- **Layer**: Rust+anvil E2E.
- **Setup**: run `setup-backing` WITHOUT `SETUP_BACKING_NO_ONCHAIN_DEPOSIT` (i.e. it makes the real
  on-chain deposit, the browser-demo default), then run `withdraw` (integrated).
- **Assert**: characterize the outcome — the pre-existing pending deposit folds into the FIRST posted
  block, so the withdrawal proof's deposit-in-block-2 model mismatches → `finalize returned false`.
  The test should PIN that this combination fails fail-closed (no fund movement), and document that the
  supported integrated path requires the deferred-deposit (案B) mode. This guards against silently
  shipping a demo path that bricks withdraw.

### C17 — `claimWithdrawalCredit` before `pullChannelFunds`
- **Severity**: liveness/ordering (no loss expected).
- **Layer**: Solidity mock.
- **Assert**: reverts (cap = 0); after `pullChannelFunds`, succeeds. (Overlaps B7 — here the focus is the
  exact ordering revert.)

### C18 — intent over-declares fund vs actually-received
- **Severity**: fund-safety (cap should win).
- **Layer**: Solidity mock (real-ish via mock) + ideally real.
- **Setup**: finalized intent `channelFundAmount = 100`, but `pullChannelFunds` only pulled 50.
- **Assert**: members can claim at most 50 in aggregate (`receivedChannelFunds`), regardless of the
  100 in the intent; the (members'+post-close) claims hitting the 50 cap revert `WithdrawalCapExceeded`.

### C19 — finalize records a different version/chain than the close proof
- **Severity**: fund-safety (binding).
- **Layer**: Solidity (close limb tampering already covered for some fields) — extend to
  `finalStateVersion` / `finalSettledTxChain` / `finalSettledTxAccumulatorRoot` boundary values and
  confirm `close limb mismatch` on each. Some fields are covered (`test_tampered_version_or_chain_fails_close_proof`);
  fill the remaining fields + the accumulator root.

### C20 — withdrawNative paid before the close is finalized (sequencing)
- **Severity**: fund-safety.
- **Layer**: Rust+anvil.
- **Setup**: withdraw (deposit→finalize→withdrawNative→pull) BEFORE the manager's `finalizeClose`.
- **Assert**: withdrawNative depends only on rollup `finalizedStateRoots` (not the manager status), so
  it can succeed; but `claimWithdrawalCredit` still requires a finalized close on the manager. Pin the
  invariant: manager never pays a member before its own `finalizeClose` (status==Closed gate on claim).
