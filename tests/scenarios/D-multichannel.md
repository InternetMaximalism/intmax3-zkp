# Category D — multi-channel / shared-rollup interference

The relay runs several channels on ONE rollup. `totalEscrowed`, `blockHashChain`/`depositHashChain`/
`blockNumber`, `finalizedStateRoots`, and the nullifier maps are rollup-GLOBAL. The only cross-channel
fund guarantee is `Σ per-channel receivedChannelFunds ≤ totalEscrowed` (rollup underflow) + per-channel
`totalCreditedOut ≤ receivedChannelFunds`. These need explicit two-channel tests.

Layer for all D: Rust+anvil (two managers + two channel dirs on one rollup), unless noted. Reuse the
`tests/close_lifecycle_cli_e2e.rs` harness; deploy TWO managers (distinct channel ids), or use the
mock-MLE Solidity layer with two `ChannelSettlementManager`s sharing one mock registry for the cap math.

---

### D20 — two channels over-commit vs `totalEscrowed` ★
- **Severity**: liveness/fund (one channel starves another).
- **Setup**: deposit A=50, B=50 (total escrow 100); generate independent valid withdrawal proofs each
  claiming 60.
- **Steps**: A `withdrawNative(60)` succeeds (escrow→40); B `withdrawNative(60)`.
- **Assert**: B reverts on `totalEscrowed` underflow (SAFE globally) — B is STUCK though valid. Pin:
  the contract does NOT prevent operator over-commitment; only the global cap backstops. Document the
  off-protocol invariant the operator must hold (`Σ per-channel max ≤ totalEscrowed`).

### D21 — cross-channel deposit/block order mistake bricks BOTH channels
- **Severity**: liveness (cascade).
- **Setup**: proofs generated for deposits posted as [A, B]; operator posts on-chain as [B, A].
- **Assert**: block-hash chain diverges from both proofs → `finalize` reverts → NEITHER channel can
  exit. Pin that the failure is fail-closed (no misbinding) and global (one operator error stalls all).

### D22 — operator mis-assigns deposited funds to the wrong channel
- **Severity**: intra-/inter-channel fairness (NOT protected on-chain).
- **Setup**: only 50 ETH deposited "for A", but A's `receivedChannelFunds` ends up 100 (operator credits
  a deposit meant for B).
- **Assert**: A's members can claim up to 100 (per-channel cap honors the lie); B is short. Global
  solvency (`totalEscrowed`) still holds, but relative fairness does not. Encode as an explicit
  acknowledged-risk test so a regression that breaks even GLOBAL solvency is caught.

### D23 — finalize lag: channel B's newer root not yet finalized
- **Severity**: liveness.
- **Setup**: A withdraws against finalized root S1; B's proof is anchored to a newer S2 not yet finalized.
- **Assert**: B's `withdrawNative` reverts `WithdrawalExtCommitmentMismatch` until S2 is finalized; A is
  unaffected. Pin the per-root dependency.

### D24 — cross-channel nullifier / root isolation (positive isolation test)
- **Severity**: fund-safety (must hold).
- **Setup**: two channels, two distinct withdrawals.
- **Assert**: a nullifier used by A's withdrawal cannot be reused by B (global `withdrawalNullifierUsed`);
  A's finalized root does not let B withdraw B's funds; each manager's cap is independent. Confirms the
  shared global maps isolate correctly rather than leak.

### D25 — same leaf claimable in two channels (should be blocked by global nullifier)
- **Severity**: fund-safety.
- **Setup**: contrive two channels whose close/withdrawal proofs reference the SAME settled leaf (rare).
- **Assert**: the second `withdrawNative`/claim reverts on the global nullifier. (Related to C14 — if the
  serialization differs the nullifiers differ; verify they canonically collide → ESCALATE if not.)
