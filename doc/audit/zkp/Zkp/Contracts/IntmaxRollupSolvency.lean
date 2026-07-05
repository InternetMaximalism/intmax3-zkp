import Zkp.Contracts.IntmaxRollupWithdraw

/-
  IntmaxRollup — global solvency invariant
  ========================================

  Source: `contracts/src/IntmaxRollup.sol` (`deposit` :815,
  `withdrawNative` :1307, `claimAuthorizedWithdrawal` :642)

  The headline system-safety property: over ANY sequence of `deposit` /
  `withdrawNative` / `claimAuthorizedWithdrawal` operations — i.e. ALL
  the escrow-moving entry points; `claimAuthorizedWithdrawal` is a real
  outflow (`totalEscrowed -= w.amount` :660 + ETH push :662) and must be
  in the trace universe — the rollup never pays out more native ETH than
  was deposited. We prove the conservation law

      finalEscrow + Σ withdrawn = initialEscrow + Σ deposited

  and conclude `Σ withdrawn ≤ initialEscrow + Σ deposited` (so, from a
  zero genesis, `Σ withdrawn ≤ Σ deposited`). The proof rests only on the
  per-operation effects: `deposit` adds (checked), `withdrawNative` and
  `claimAuthorizedWithdrawal` subtract with the Solidity-0.8 underflow
  revert. The validity/MLE proofs gate WHICH withdrawals are allowed
  (and that the `withdrawNative` ones are circuit-backed; the burn path
  instead rests on `Assumptions.BurnAuthorizationsLegitimate`) but are
  irrelevant to this accounting bound — solvency holds unconditionally.
-/

namespace Zkp
namespace Contracts
namespace IntmaxRollup

open Zkp.Contracts.Evm

/-- `deposit` (escrow effect, :829) increases escrow by exactly `amount`
    (the deposit-hash-chain / record effects are accounting-neutral). -/
theorem deposit_escrow {s s' : RollupState} {amount : U256}
    (h : deposit s amount = some s') :
    s'.totalEscrowed = s.totalEscrowed + amount := by
  unfold deposit at h
  cases hadd : checkedAdd s.totalEscrowed amount with
  | none => rw [hadd] at h; simp at h
  | some te =>
      rw [hadd] at h
      simp only [Option.some.injEq] at h
      have : s'.totalEscrowed = te := by rw [← h]
      rw [this]; exact checkedAdd_eq_some hadd

/-- A native-fund operation: deposit `amount`, `withdrawNative` paying
    leaves `ws`, or `claimAuthorizedWithdrawal` (:642) paying the single
    burn leaf `w` (proof/authorization preconditions are orthogonal to
    escrow accounting). These are ALL the `totalEscrowed`-moving entry
    points of IntmaxRollup.sol. -/
inductive Op where
  | dep   (amount : U256)
  | wd    (ws : List Withdrawal)
  | claim (w : Withdrawal)

/-- Escrow added by an op. -/
def depDelta : Op → U256 | .dep a => a | .wd _ => 0 | .claim _ => 0
/-- Escrow removed by an op. -/
def wdDelta : Op → U256 | .dep _ => 0 | .wd ws => totalAmount ws | .claim w => w.amount

/-- Escrow-affecting semantics of one op (revert ⇒ none). -/
def step (s : RollupState) : Op → Call RollupState
  | .dep amount => deposit s amount
  | .wd ws      => withdrawLoop s ws
  | .claim w    => claimAuthorized s w

/-- Run a trace, threading state, atomic on any revert. -/
def run (s : RollupState) : List Op → Call RollupState
  | [] => some s
  | op :: ops => (step s op).bind (fun s' => run s' ops)

/-- Total ETH deposited / withdrawn by a trace. -/
def deposited : List Op → U256
  | [] => 0
  | op :: ops => depDelta op + deposited ops
def withdrawn : List Op → U256
  | [] => 0
  | op :: ops => wdDelta op + withdrawn ops

/-- One step's escrow conservation: `post + wdΔ = pre + depΔ`. -/
theorem step_conservation {s s' : RollupState} {op : Op} (h : step s op = some s') :
    s'.totalEscrowed + wdDelta op = s.totalEscrowed + depDelta op := by
  cases op with
  | dep a =>
      simp only [step] at h
      simp only [wdDelta, depDelta, Nat.add_zero]
      exact deposit_escrow h
  | wd ws =>
      simp only [step] at h
      simp only [wdDelta, depDelta, Nat.add_zero]
      exact (withdrawLoop_solvency h).2
  | claim w =>
      simp only [step] at h
      simp only [wdDelta, depDelta, Nat.add_zero]
      exact (claimAuthorized_safe h).2.1

/-- **Global conservation.** For any successful trace,
    `finalEscrow + Σ withdrawn = initialEscrow + Σ deposited`. -/
theorem run_conservation {s s' : RollupState} :
    ∀ {ops : List Op}, run s ops = some s' →
      s'.totalEscrowed + withdrawn ops = s.totalEscrowed + deposited ops := by
  intro ops
  induction ops generalizing s with
  | nil =>
      intro h; simp only [run] at h
      rw [Option.some.injEq] at h; subst h
      simp [withdrawn, deposited]
  | cons op ops ih =>
      intro h
      simp only [run, Option.bind] at h
      cases hstep : step s op with
      | none => rw [hstep] at h; simp at h
      | some smid =>
          rw [hstep] at h
          have hc := step_conservation hstep
          have hrest := ih h
          simp only [withdrawn, deposited]
          calc s'.totalEscrowed + (wdDelta op + withdrawn ops)
              = (s'.totalEscrowed + withdrawn ops) + wdDelta op := by
                  rw [Nat.add_comm (wdDelta op), ← Nat.add_assoc]
            _ = (smid.totalEscrowed + deposited ops) + wdDelta op := by rw [hrest]
            _ = (smid.totalEscrowed + wdDelta op) + deposited ops := by
                  rw [Nat.add_right_comm]
            _ = (s.totalEscrowed + depDelta op) + deposited ops := by rw [hc]
            _ = s.totalEscrowed + (depDelta op + deposited ops) := by rw [Nat.add_assoc]

/-- **Global solvency.** Total ETH withdrawn never exceeds initial escrow
    plus total ETH deposited — over traces of ALL THREE escrow-moving
    ops, including the burn claims (`Op.claim`). From a zero-escrow
    genesis this is exactly `Σ withdrawn ≤ Σ deposited`: the rollup
    cannot pay out more than was put in — unconditionally, independent
    of the proofs (and independent of the burn path's
    `Assumptions.BurnAuthorizationsLegitimate` trust assumption, which
    governs WHO may be paid, not HOW MUCH in total). -/
theorem global_solvency {s s' : RollupState} {ops : List Op}
    (h : run s ops = some s') :
    withdrawn ops ≤ s.totalEscrowed + deposited ops := by
  calc withdrawn ops
      ≤ s'.totalEscrowed + withdrawn ops := Nat.le_add_left _ _
    _ = s.totalEscrowed + deposited ops := run_conservation h

/-- From genesis (escrow 0): `Σ withdrawn ≤ Σ deposited`. -/
theorem solvent_from_genesis {s s' : RollupState} {ops : List Op}
    (h : run s ops = some s') (hgen : s.totalEscrowed = 0) :
    withdrawn ops ≤ deposited ops := by
  have hg := global_solvency h
  rw [hgen, Nat.zero_add] at hg
  exact hg

/-! ### Satisfiability of the extended trace universe -/

/-- A state holding 1 wei of escrow with every burn digest authorized
    (as a rogue manager could arrange — see
    `Assumptions.burn_drain_satisfiable`). INTENTIONALLY SIMPLE: exists
    only to witness `claim_trace_satisfiable`. -/
def escrow1State : RollupState :=
  { totalEscrowed := 1
    nullifierUsed := fun _ => false
    pendingWithdrawals := fun _ => 0
    finalizedStateRoots := fun _ => false
    partialWithdrawalAuthorized := fun _ => true }

/-- A concrete ETH burn leaf for the witness trace. -/
def burnLeaf : Withdrawal :=
  { recipient := 0, amount := 1, nullifier := 0, auxData := 1, isEth := true }

/-- **Inhabitation (D6).** The 3-op trace universe is not vacuous on its
    new constructor: a trace containing an `Op.claim` actually RUNS (so
    `run_conservation`/`global_solvency` quantify over non-empty
    behavior including burn claims, not vacuously). -/
theorem claim_trace_satisfiable :
    ∃ s', run escrow1State [Op.claim burnLeaf] = some s' := by
  exact ⟨_, rfl⟩

end IntmaxRollup
end Contracts
end Zkp
