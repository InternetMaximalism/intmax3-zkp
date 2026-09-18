# A-3 P6-A: making specialClose (C2) / lateOutgoingDebit (C3) revert — plan + threat model

Base documents: `doc/tasks/a3-p5-plus-plan.md`, detail2 §H-3 (the approved disposition).

## 0. What and why
Resolve the live divergence found in the conformance audit: detail2 §H-3 explicitly states that C2/C3 are "forgeable stubs, so the entries must revert",
yet today `submitSpecialClose` (C2) / `submitLateOutgoingDebitCorrection` (C3) in `ChannelSettlementManager.sol`
are **live** (anyone can construct a trivially-true `_matches` stub proof and call them).

- **C2 risk**: freeze a channel with a bogus censorship accusation (`channelStatus=ClosePending`) + slash the BP bond.
  No loss of funds (the slash destination `bpBondCredits` is a separate pot, and is 0 if unfunded), but **freeze-grief** is possible.
- **C3 risk**: redundant. Double withdrawal is already prevented by the nullifier used-set on each payout path (§H-3 (1)-(5)).

## 1. Threat model (safety of the disposition)
**What functionality is lost by making these revert, and why that is safe:**
- Disabling C2 → only means BP censorship slashing can no longer be used. Member funds do not move. The footgun of a healthy BP being falsely slashed disappears (an improvement).
  A sound non-inclusion proof requires a cross-layer commitment at the validity/IntmaxRollup layer (not implemented) → until then, disabled is the correct state.
- Disabling C3 → double-withdrawal prevention is **fully** covered by the nullifier used-sets (`withdrawalNullifierUsed` / `usedWithdrawalNullifiers` /
  `usedSharedNativeNullifiers`, in-circuit derivation + check-then-set CEI) plus stale-close rejection (cancelClose C1).
  C3 is redundant. Time-difference grief is accepted as out-of-scope.

**Does making them revert create a new attack surface:**
- The functions revert immediately (zero state change) → the attack surface only shrinks.
- The ABI selector is unchanged since the types are unchanged (calling them fails deterministically with a dedicated error = fail-closed).
- There are no internal calls from other paths (external only; only tests call them) → no regressions.
- The stub verifiers (`verifySpecialClose`/`verifyLateOutgoingDebit`) may be left in place (unreachable once the entries are closed off).

## 2. Implementation
- [ ] `ChannelSettlementManager.sol`: add errors `SpecialCloseDisabled()` / `LateOutgoingDebitDisabled()`.
- [ ] Make the bodies of `submitSpecialClose` / `submitLateOutgoingDebitCorrection` **revert immediately** (omit the argument names to avoid unused warnings, keep the selector).
  Reference the detail2 §H-3 disposition in a `// SECURITY:` comment.
- [ ] Replace the affected tests (3 of them in `ChannelSettlementManager.t.sol`) with "disabled→revert" assertions
  (the positive-path scenarios disappear because of the spec change. This is not altering tests to make them pass, but **reflecting a spec change**).

## 3. Fixture regeneration (Manager bytecode change → CREATE2 manager drift)
- [ ] forge build → compute the new manager CREATE2 address (`CloseManagerAddr.t.sol` etc.).
- [ ] Regenerate close_withdrawal_*/close_lifecycle* with `WD_RECIPIENT=<new manager> WD_OUT_PREFIX=close_ generate_withdrawal_fixture` (heavy).
  close_intent* (generate_close_fixture) is manager-independent = not needed.
- [ ] `forge test --match-contract CloseLifecycleE2E` + `ChannelSettlementManager` green.

## 4. Review + cleanup
- [ ] **Have a separate agent (attacker's perspective) review the revert change** (separate from the implementation).
- [ ] Update detail2 §H-3 to "implemented (disposition applied)".

## 5. Iron rules
Do not change any other IntmaxRollup/Manager bytecode. Soundness is in-circuit + on-chain. Do not touch private keys.

## Findings log
- **Implementation complete**: both entries now `revert SpecialCloseDisabled()` / `revert LateOutgoingDebitDisabled()` (signature preserved = selector unchanged, `external pure`). 2 new errors added.
- **Tests**: the 3 affected tests replaced with disabled→revert assertions (reflecting the spec change). All 66 Manager tests PASS.
- **Fixture regeneration**: Manager bytecode change → new CREATE2 manager `0xED5e1c643d4726735cC564EfFA5D6AC2cC1A8FA8`.
  Regenerated the close_ fixtures with `WD_RECIPIENT=<new> WD_OUT_PREFIX=close_ generate_withdrawal_fixture`. CloseLifecycleE2E PASS.
  (The skip of the close-intent section is **pre-existing** behavior stemming from the member-set comparison. The registration was confirmed byte-identical to git.)
- **Separate-agent attacker review**: **no critical defects**. Confirmed that forgery is made impossible, freeze liveness is preserved via cancelClose (C1), funds do not move, and this matches the spec.
- **Deferred follow-up (non-security)**: the dead code (`latestSpecialCloseDigest` / `usedLateOutgoingDebitNullifiers` /
  2 events / `computeSpecialCloseDigest`) is harmless. Removing it would again mean a bytecode change = fixture regeneration, so it is left to a future PR. Noted in detail2 §H-3.
- Updated detail2 §H-3 to "IMPLEMENTED 2026-06, P6-A".

## Completion summary
P6-A complete. The forgeable stub entries for C2/C3 now revert (removing the freeze-grief footgun). Fund safety is unchanged
(soundness comes from the nullifier used-sets + cancelClose + in-circuit checks, independent of C2/C3). Attacker review: GO.
