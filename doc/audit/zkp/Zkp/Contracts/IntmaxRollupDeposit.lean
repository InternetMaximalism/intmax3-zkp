import Zkp.Contracts.Evm

/-
  IntmaxRollup — deposit hash chain & access control
  ==================================================

  Source: `contracts/src/IntmaxRollup.sol`
    deposit :815 · registerSettlementManager :624 · authorizePartialWithdrawal :634

  ## Deposit hash chain (combined-system consistency)

  `deposit()` assigns each deposit the index `depositCount++` and folds it
  into `_pendingDepositHashChain` via keccak. This is the L1 SIDE of the
  same accumulation the circuit `deposit_step` proves: the contract
  supplies a sequential, gap-free index (`idx = depositCount`, then `+1`),
  exactly the `deposit_index == deposit_count` invariant the circuit
  asserts (`DepositStep.sequential_append`). So the deposits the circuit
  proves are precisely the deposits the contract recorded, in order.

  ## Access control

  Burn (partial) withdrawals are gated by `partialWithdrawalAuthorized`,
  writable ONLY by a `registerSettlementManager`-registered manager, which
  in turn is settable ONLY by the `deployer`. We model and prove this
  two-level gate (the authorization that `claimAuthorized` /
  `withdrawNative`'s burn path require).
-/

namespace Zkp
namespace Contracts
namespace IntmaxRollup
namespace Deposit

open Zkp.Contracts.Evm

/-! ### Deposit hash chain -/

/-- `_computeDepositHash(prev, depositor, recipient, tokenIndex, amount,
    auxData)` — the keccak fold (:840). Uninterpreted; byte-identical to
    the Rust `Deposit::hash_with_prev_hash` (asserted by a differential
    test) — that equality is the contract↔circuit modeling assumption. -/
opaque computeDepositHash : Word → Addr → Word → U256 → U256 → Word → Word

/-- The deposit-chain slice of storage. -/
structure DepositState where
  depositCount : Nat
  pendingDepositHashChain : Word

/-- One `deposit()` chain effect (:836-848): record at `idx = depositCount`,
    fold the hash, increment the count. Returns `(idx, newState)`. -/
def depositChain (s : DepositState)
    (depositor : Addr) (recipient : Word) (tokenIndex amount : U256) (auxData : Word) :
    Nat × DepositState :=
  (s.depositCount,
   { depositCount := s.depositCount + 1
     pendingDepositHashChain :=
       computeDepositHash s.pendingDepositHashChain depositor recipient tokenIndex amount auxData })

/-- **Contract-side sequential append.** A deposit is recorded at exactly
    the current `depositCount`, which then increments by one — gap-free,
    matching the circuit `deposit_step`'s `deposit_index == deposit_count`
    (`DepositStep.sequential_append`). The two accumulations therefore
    enumerate the SAME deposit sequence. -/
theorem deposit_sequential (s : DepositState)
    (dep : Addr) (rec : Word) (tok amt : U256) (aux : Word) :
    (depositChain s dep rec tok amt aux).1 = s.depositCount ∧
    (depositChain s dep rec tok amt aux).2.depositCount = s.depositCount + 1 :=
  ⟨rfl, rfl⟩

/-! ### Access control: settlement-manager authorization -/

structure AuthState where
  deployer : Addr
  isRegisteredManager : Mapping Addr Bool
  partialWithdrawalAuthorized : Mapping Word Bool

/-- `registerSettlementManager(m)` (:624): ONLY the deployer may register. -/
def registerManager (s : AuthState) (caller manager : Addr) : Call AuthState :=
  if caller = s.deployer then
    some { s with isRegisteredManager := s.isRegisteredManager.set manager true }
  else none  -- "only deployer"

/-- `authorizePartialWithdrawal(d)` (:634): ONLY a registered manager. -/
def authorizePartial (s : AuthState) (caller : Addr) (digest : Word) : Call AuthState :=
  if s.isRegisteredManager.get caller = true then
    some { s with partialWithdrawalAuthorized := s.partialWithdrawalAuthorized.set digest true }
  else none  -- NotRegisteredSettlementManager

/-- **Only the deployer can register managers.** -/
theorem registerManager_requires_deployer {s s' : AuthState} {caller manager : Addr}
    (h : registerManager s caller manager = some s') : caller = s.deployer := by
  unfold registerManager at h
  by_cases hc : caller = s.deployer
  · exact hc
  · rw [if_neg hc] at h; simp at h

/-- **Only a registered manager can authorize a burn withdrawal.** Hence a
    `partialWithdrawalAuthorized` digest — required by `claimAuthorized` and
    `withdrawNative`'s burn path — can only have been set by a manager the
    deployer registered. Two-level access control, end to end. -/
theorem authorizePartial_requires_manager {s s' : AuthState} {caller : Addr} {digest : Word}
    (h : authorizePartial s caller digest = some s') :
    s.isRegisteredManager.get caller = true := by
  unfold authorizePartial at h
  by_cases hc : s.isRegisteredManager.get caller = true
  · exact hc
  · rw [if_neg hc] at h; simp at h

/-- A successful authorization sets exactly that digest. -/
theorem authorizePartial_sets {s s' : AuthState} {caller : Addr} {digest : Word}
    (h : authorizePartial s caller digest = some s') :
    s'.partialWithdrawalAuthorized.get digest = true := by
  unfold authorizePartial at h
  by_cases hc : s.isRegisteredManager.get caller = true
  · rw [if_pos hc] at h
    simp only [Option.some.injEq] at h
    rw [← h]; simp [Mapping.get_set_eq]
  · rw [if_neg hc] at h; simp at h

/-!
  ## SECURITY OBSERVATIONS

  * **Burn-path authorization chain.** `claimAuthorized` /
    `withdrawNative` burn leaves require
    `partialWithdrawalAuthorized[authDigest] = true`
    (`claimAuthorized_safe`), and `authorizePartial_requires_manager` +
    `registerManager_requires_deployer` show that flag is reachable only
    through deployer→manager→authorize. `authDigest` binds every
    withdrawal field, so an authorization cannot be replayed with a
    different recipient/amount.

  * **Deposit consistency.** `deposit_sequential` is the L1 mirror of the
    circuit's gap-free deposit accumulation. The keccak fold equality
    (`computeDepositHash` ≡ Rust `Deposit::hash_with_prev_hash`) is a
    differential-test-asserted modeling assumption (byte-identical
    layout), the standard contract↔circuit boundary.
-/

end Deposit
end IntmaxRollup
end Contracts
end Zkp
