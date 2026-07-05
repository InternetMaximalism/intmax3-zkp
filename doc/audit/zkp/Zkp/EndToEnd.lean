import Zkp.Contracts.Assumptions
import Zkp.Contracts.IntmaxRollupSolvency
import Zkp.Contracts.Coverage
import Zkp.Circuits.Withdraw.SingleWithdrawalCircuit
import Zkp.Circuits.Withdraw.WithdrawalCircuit
import Zkp.Circuits.Withdraw.WithdrawalStep
import Zkp.Circuits.Balance.SpendCircuit
import Zkp.Circuits.Balance.BalanceCircuit
import Zkp.Circuits.Balance.Common.UpdatePrivateState
import Zkp.Circuits.Validity.ValidityCircuit
import Zkp.Circuits.Validity.UpdateUser

/-
  End-to-end composition: every `withdrawNative` payout is
  backed → deducted → anchored → single-use → bounded
  ==========================================================

  Until this module, the headline claim of the audit — "every L1
  payout through `withdrawNative` corresponds to a circuit-proven,
  solvently-deducted, validity-anchored, single-use withdrawal" —
  existed only as PROSE (the COMBINED-SYSTEM block in
  `IntmaxRollupWithdraw.lean`). The per-layer theorems are strong, but
  the layers never met in one Lean statement:

    * the contract modules import only `Zkp.Contracts.Evm` — no
      circuit import anywhere;
    * proof verification is a free `Prop` at every recursion boundary;
    * sibling modules re-declare the same Rust primitive as DISTINCT
      opaques (e.g. `ValidityCircuit.zeroChain` vs
      `UpdateUser.zeroBytes`, both `Bytes32::default()`);
    * the contract world hashes `List Nat` (`Coverage.keccak`,
      `Word := Nat`) while circuits hash `List F` / `Bytes32 F`.

  This module turns every one of those English arrows into a NAMED
  Lean hypothesis (`BridgeAssumptions`, each field carrying a
  docstring that says exactly which real-world mechanism justifies
  it) and proves ONE composed theorem, `end_to_end_payout_sound`,
  whose value is that the composition TYPE-CHECKS: every remaining
  gap between the machine-checked layers is a visible field, not an
  implicit leap.

  ## Composition map (which proved theorem carries which arrow)

    L1 call            `withdrawNative_requires_proof`   (proved, Contracts)
      → anchored root  `erun_finalized_provenance`       (proved HERE — trace
                        lemma over the extended op universe, lifting
                        `finalize_only_on_valid` to all reachable states)
      → validity proof `BridgeAssumptions.validity_oracle` (NAMED)
      → per-block fold `BridgeAssumptions.update_user_recursion` (NAMED)
                        + `signing_block_advances` /
                        `account_update_forces_fold`     (proved, UpdateUser)
      → sig gating     `signatures_not_skippable`        (proved, Validity)
    L1 leaf            `BridgeAssumptions.withdrawal_proof_oracle` (NAMED)
      → PI layout      `BridgeAssumptions.pi_layout_faithful`      (NAMED)
      → provenance     `withdrawal_sound`                (proved, SingleWithdrawal)
      → spend backing  `BridgeAssumptions.balance_recursion`       (NAMED)
      → solvency       `deducts_solvent`                 (proved, Spend)
    nullifier          `withdrawLeaf_consumes` / `_nullifier_once` (proved,
                        Contracts) + `nullifierInsert_reachable_chain`
                        (proved, UpdatePrivateState, under the named
                        `NullifierRootBinding`)
    escrow bound       `erun_conservation`               (proved HERE, extending
                        `IntmaxRollupSolvency.run_conservation` with `finalize`)

  ## What is deliberately NOT composed

  The burn path (`claimAuthorizedWithdrawal`) has NO rollup-side proof
  check; its legitimacy is `Assumptions.BurnAuthorizationsLegitimate`
  and it is carved out of this theorem exactly as it is carved out of
  the prose. See the RESIDUAL TRUST SURFACE block at the end of this
  file for the full list of what remains outside even this
  composition.
-/

namespace Zkp
namespace EndToEnd

open CField Builder Bytes Merkle
open Zkp.Contracts.Evm
open Zkp.Contracts.IntmaxRollup

/-!
## Part 1 — Contract trace machinery (extended op universe)

`IntmaxRollupSolvency.Op` covers the three escrow movers but not
`finalize`, so "every finalized root was written by a verified
validity proof" could not be stated over its traces. `EOp` extends
the universe with `finalize` (and threads `withdrawNative`'s
call-level preconditions through `wd`, as `Bool` gate outputs so the
step function stays decidable). Everything proved about the smaller
universe is re-proved here by the same one-step-conservation
induction; nothing is assumed.
-/

/-- An `IntmaxRollup` external call affecting escrow or finalization:
    `deposit` (:815), `withdrawNative` (:1307, with its gate outputs
    `mleOk`/`pisOk` as booleans — the Props they stand for are
    reintroduced at the composed call under scrutiny), `claimAuthorized`
    (:642, the burn path — present so the trace universe is the full
    set of escrow movers, exactly as in `IntmaxRollupSolvency`), and
    `finalize` (:1102, the ONLY writer of `finalizedStateRoots`).

    MODELING NOTE (`fin`): the real `finalize` also calls
    `_refundStake(submissionId)` (:1126) — returning the submitter's
    bond via the pull-payment `pendingWithdrawals` ledger. `EOp.fin`
    abstracts that side-effect away: stake bonds are NOT part of
    either quantity this module tracks (`totalEscrowed` — user
    deposits only — and `finalizedStateRoots`), so eliding the refund
    changes no theorem here; stake accounting has its own module
    (`IntmaxRollupStake.lean`). -/
inductive EOp where
  | dep   (amount : U256)
  | wd    (ws : List Withdrawal) (mleOk pisOk : Bool) (extC : Word)
  | claim (w : Withdrawal)
  | fin   (root : Word) (valid : Bool)

/-- One-step semantics (revert ⇒ `none`), reusing the audited
    transition functions verbatim. -/
def estep (s : RollupState) : EOp → Call RollupState
  | .dep a => deposit s a
  | .wd ws m p e => withdrawNative s ws (m = true) (p = true) e
  | .claim w => claimAuthorized s w
  | .fin r v => finalize s r v

/-- Run a trace, threading state, atomic on any revert. -/
def erun (s : RollupState) : List EOp → Call RollupState
  | [] => some s
  | op :: ops => (estep s op).bind (fun s' => erun s' ops)

/-- Escrow added by an op. -/
def edepDelta : EOp → U256
  | .dep a => a
  | .wd _ _ _ _ => 0
  | .claim _ => 0
  | .fin _ _ => 0

/-- Escrow removed by an op. -/
def ewdDelta : EOp → U256
  | .dep _ => 0
  | .wd ws _ _ _ => totalAmount ws
  | .claim w => w.amount
  | .fin _ _ => 0

/-- Total ETH deposited by a trace. -/
def edeposited : List EOp → U256
  | [] => 0
  | op :: ops => edepDelta op + edeposited ops

/-- Total ETH withdrawn by a trace. -/
def ewithdrawn : List EOp → U256
  | [] => 0
  | op :: ops => ewdDelta op + ewithdrawn ops

/-! ### finalizedStateRoots is written ONLY by `finalize` — as theorems -/

/-- `deposit` never touches `finalizedStateRoots`. -/
theorem deposit_finalized {s s' : RollupState} {a : U256}
    (h : deposit s a = some s') :
    s'.finalizedStateRoots = s.finalizedStateRoots := by
  unfold deposit at h
  cases hadd : checkedAdd s.totalEscrowed a with
  | none => rw [hadd] at h; simp at h
  | some te =>
      rw [hadd] at h
      rw [Option.some.injEq] at h
      subst h
      rfl

/-- A withdrawal leaf never touches `finalizedStateRoots`. -/
theorem withdrawLeaf_finalized {s s' : RollupState} {w : Withdrawal}
    (h : withdrawLeaf s w = some s') :
    s'.finalizedStateRoots = s.finalizedStateRoots := by
  obtain ⟨te, _, hs'⟩ := withdrawLeaf_some h
  subst hs'
  rfl

/-- The withdrawal loop never touches `finalizedStateRoots`. -/
theorem withdrawLoop_finalized {s s' : RollupState} :
    ∀ {ws : List Withdrawal}, withdrawLoop s ws = some s' →
      s'.finalizedStateRoots = s.finalizedStateRoots := by
  intro ws
  induction ws generalizing s with
  | nil =>
      intro h
      simp only [withdrawLoop] at h
      rw [Option.some.injEq] at h
      subst h
      rfl
  | cons w ws ih =>
      intro h
      simp only [withdrawLoop, Option.bind] at h
      cases hleaf : withdrawLeaf s w with
      | none => rw [hleaf] at h; simp at h
      | some smid =>
          rw [hleaf] at h
          rw [ih h, withdrawLeaf_finalized hleaf]

/-- `withdrawNative` never touches `finalizedStateRoots`. -/
theorem withdrawNative_finalized {s s' : RollupState} {ws : List Withdrawal}
    {mleVerified pisBound : Prop} [Decidable mleVerified] [Decidable pisBound]
    {extC : Word}
    (h : withdrawNative s ws mleVerified pisBound extC = some s') :
    s'.finalizedStateRoots = s.finalizedStateRoots := by
  unfold withdrawNative at h
  by_cases hpre : mleVerified ∧ s.finalizedStateRoots.get extC = true ∧ pisBound
  · rw [if_pos hpre] at h
    exact withdrawLoop_finalized h
  · rw [if_neg hpre] at h; simp at h

/-- A burn claim never touches `finalizedStateRoots`. -/
theorem claimAuthorized_finalized {s s' : RollupState} {w : Withdrawal}
    (h : claimAuthorized s w = some s') :
    s'.finalizedStateRoots = s.finalizedStateRoots := by
  obtain ⟨_, te, _, hs'⟩ := claimAuthorized_some h
  subst hs'
  rfl

/-- Decompose a successful `finalize`: either the gate output was
    `true` and exactly the given root was set, or it was `false` and
    the state is untouched. -/
theorem finalize_some {s s' : RollupState} {root : Word} {valid : Bool}
    (h : finalize s root valid = some s') :
    (valid = true
      ∧ s' = { s with finalizedStateRoots := s.finalizedStateRoots.set root true })
    ∨ (valid = false ∧ s' = s) := by
  cases valid with
  | true =>
      left
      refine ⟨rfl, ?_⟩
      unfold finalize at h
      rw [if_pos rfl] at h
      rw [Option.some.injEq] at h
      exact h.symm
  | false =>
      right
      refine ⟨rfl, ?_⟩
      unfold finalize at h
      simp only [Bool.false_eq_true, if_false] at h
      rw [Option.some.injEq] at h
      exact h.symm

/-- **One-step finalization provenance.** If a step turns a root from
    un-finalized to finalized, that step IS `finalize` on that root
    with a `true` verification-gate output — via the already-proved
    `finalize_only_on_valid`. -/
theorem estep_finalized_provenance {s s' : RollupState} {op : EOp} {r : Word}
    (h : estep s op = some s')
    (hnew : s'.finalizedStateRoots.get r = true)
    (hold : s.finalizedStateRoots.get r = false) :
    op = EOp.fin r true := by
  cases op with
  | dep a =>
      exfalso
      simp only [estep] at h
      rw [deposit_finalized h, hold] at hnew
      exact absurd hnew (by decide)
  | wd ws m p e =>
      exfalso
      simp only [estep] at h
      rw [withdrawNative_finalized h, hold] at hnew
      exact absurd hnew (by decide)
  | claim w =>
      exfalso
      simp only [estep] at h
      rw [claimAuthorized_finalized h, hold] at hnew
      exact absurd hnew (by decide)
  | fin root v =>
      simp only [estep] at h
      by_cases hr : r = root
      · subst hr
        have hv : v = true := finalize_only_on_valid h hnew hold
        rw [hv]
      · exfalso
        rcases finalize_some h with ⟨_, hs⟩ | ⟨_, hs⟩
        · subst hs
          have hnew' : (s.finalizedStateRoots.set root true).get r = true := hnew
          rw [Mapping.get_set_ne s.finalizedStateRoots true hr] at hnew'
          rw [hold] at hnew'
          exact absurd hnew' (by decide)
        · subst hs
          rw [hold] at hnew
          exact absurd hnew (by decide)

/-- **Trace-level finalization provenance (the lifted
    `finalize_only_on_valid`).** In any state reachable by a trace,
    every finalized root was either finalized already at the start, or
    was written by a `finalize` step whose verification gate returned
    `true`. This is a THEOREM over the contract state machine, not an
    assumption — the meta-audit's "anchoring" arrow, discharged. -/
theorem erun_finalized_provenance {s s' : RollupState} {r : Word} :
    ∀ {ops : List EOp}, erun s ops = some s' →
      s'.finalizedStateRoots.get r = true →
      s.finalizedStateRoots.get r = true ∨ EOp.fin r true ∈ ops := by
  intro ops
  induction ops generalizing s with
  | nil =>
      intro h hnew
      simp only [erun] at h
      rw [Option.some.injEq] at h
      subst h
      exact Or.inl hnew
  | cons op ops ih =>
      intro h hnew
      simp only [erun, Option.bind] at h
      cases hstep : estep s op with
      | none => rw [hstep] at h; simp at h
      | some smid =>
          rw [hstep] at h
          rcases ih h hnew with hmid | hmem
          · cases hbool : s.finalizedStateRoots.get r with
            | true => exact Or.inl rfl
            | false =>
                right
                have hop := estep_finalized_provenance hstep hmid hbool
                rw [hop]
                exact List.mem_cons_self _ _
          · exact Or.inr (List.mem_cons_of_mem _ hmem)

/-! ### Escrow conservation over the extended universe -/

/-- One extended step's escrow conservation (`finalize` moves no
    escrow; the other three inherit the audited per-op theorems). -/
theorem estep_conservation {s s' : RollupState} {op : EOp}
    (h : estep s op = some s') :
    s'.totalEscrowed + ewdDelta op = s.totalEscrowed + edepDelta op := by
  cases op with
  | dep a =>
      simp only [estep] at h
      simp only [ewdDelta, edepDelta, Nat.add_zero]
      exact deposit_escrow h
  | wd ws m p e =>
      simp only [estep] at h
      simp only [ewdDelta, edepDelta, Nat.add_zero]
      exact (withdrawNative_solvency h).2
  | claim w =>
      simp only [estep] at h
      simp only [ewdDelta, edepDelta, Nat.add_zero]
      exact (claimAuthorized_safe h).2.1
  | fin r v =>
      simp only [estep] at h
      simp only [ewdDelta, edepDelta, Nat.add_zero]
      rcases finalize_some h with ⟨_, hs⟩ | ⟨_, hs⟩ <;> subst hs <;> rfl

/-- Global conservation over extended traces:
    `finalEscrow + Σ withdrawn = initialEscrow + Σ deposited`. -/
theorem erun_conservation {s s' : RollupState} :
    ∀ {ops : List EOp}, erun s ops = some s' →
      s'.totalEscrowed + ewithdrawn ops = s.totalEscrowed + edeposited ops := by
  intro ops
  induction ops generalizing s with
  | nil =>
      intro h
      simp only [erun] at h
      rw [Option.some.injEq] at h
      subst h
      simp [ewithdrawn, edeposited]
  | cons op ops ih =>
      intro h
      simp only [erun, Option.bind] at h
      cases hstep : estep s op with
      | none => rw [hstep] at h; simp at h
      | some smid =>
          rw [hstep] at h
          have hc := estep_conservation hstep
          have hrest := ih h
          simp only [ewithdrawn, edeposited]
          calc s'.totalEscrowed + (ewdDelta op + ewithdrawn ops)
              = (s'.totalEscrowed + ewithdrawn ops) + ewdDelta op := by
                  rw [Nat.add_comm (ewdDelta op), ← Nat.add_assoc]
            _ = (smid.totalEscrowed + edeposited ops) + ewdDelta op := by rw [hrest]
            _ = (smid.totalEscrowed + ewdDelta op) + edeposited ops := by
                  rw [Nat.add_right_comm]
            _ = (s.totalEscrowed + edepDelta op) + edeposited ops := by rw [hc]
            _ = s.totalEscrowed + (edepDelta op + edeposited ops) := by
                  rw [Nat.add_assoc]

/-! ### Nullifier consumption through the withdrawal loop -/

/-- Consumed nullifiers stay consumed across a leaf (the map is only
    ever written with `true`). -/
theorem withdrawLeaf_nullifier_mono {s s' : RollupState} {w : Withdrawal} {n : Word}
    (h : withdrawLeaf s w = some s')
    (hn : s.nullifierUsed.get n = true) :
    s'.nullifierUsed.get n = true := by
  obtain ⟨te, _, hs'⟩ := withdrawLeaf_some h
  subst hs'
  show (s.nullifierUsed.set w.nullifier true).get n = true
  by_cases hne : n = w.nullifier
  · subst hne
    exact Mapping.get_set_eq _ _ _
  · rw [Mapping.get_set_ne s.nullifierUsed true hne]
    exact hn

/-- Consumed nullifiers stay consumed across the whole loop. -/
theorem withdrawLoop_nullifier_mono {s s' : RollupState} {n : Word} :
    ∀ {ws : List Withdrawal}, withdrawLoop s ws = some s' →
      s.nullifierUsed.get n = true → s'.nullifierUsed.get n = true := by
  intro ws
  induction ws generalizing s with
  | nil =>
      intro h hn
      simp only [withdrawLoop] at h
      rw [Option.some.injEq] at h
      subst h
      exact hn
  | cons w ws ih =>
      intro h hn
      simp only [withdrawLoop, Option.bind] at h
      cases hleaf : withdrawLeaf s w with
      | none => rw [hleaf] at h; simp at h
      | some smid =>
          rw [hleaf] at h
          exact ih h (withdrawLeaf_nullifier_mono hleaf hn)

/-- A successful loop consumes EVERY paid leaf's nullifier. -/
theorem withdrawLoop_consumes {s s' : RollupState} :
    ∀ {ws : List Withdrawal}, withdrawLoop s ws = some s' →
      ∀ w ∈ ws, s'.nullifierUsed.get w.nullifier = true := by
  intro ws
  induction ws generalizing s with
  | nil => intro _ w hw; cases hw
  | cons w0 ws ih =>
      intro h w hw
      simp only [withdrawLoop, Option.bind] at h
      cases hleaf : withdrawLeaf s w0 with
      | none => rw [hleaf] at h; simp at h
      | some smid =>
          rw [hleaf] at h
          rcases List.mem_cons.mp hw with rfl | htl
          · exact withdrawLoop_nullifier_mono h (withdrawLeaf_consumes hleaf)
          · exact ih h w htl

/-- A successful `withdrawNative` consumes every paid leaf's
    nullifier. -/
theorem withdrawNative_consumes {s s' : RollupState} {ws : List Withdrawal}
    {mleVerified pisBound : Prop} [Decidable mleVerified] [Decidable pisBound]
    {extC : Word}
    (h : withdrawNative s ws mleVerified pisBound extC = some s') :
    ∀ w ∈ ws, s'.nullifierUsed.get w.nullifier = true := by
  unfold withdrawNative at h
  by_cases hpre : mleVerified ∧ s.finalizedStateRoots.get extC = true ∧ pisBound
  · rw [if_pos hpre] at h
    exact withdrawLoop_consumes h
  · rw [if_neg hpre] at h; simp at h

/-!
## Part 2 — Circuit-witness bundles

The composed theorem quantifies over witnesses of the ALREADY-MODELED
constraint systems. Bundling the (large) argument lists into
structures changes nothing semantically — each `ok` field is exactly
the existing `Constraints` applied to the bundled wires.
-/

variable {F : Type} [CField F]

/-- A satisfying witness of the single-withdrawal constraint system
    (`Circuits.SingleWithdrawalCircuit.Constraints`), wires bundled.
    `ok` is the exact constraint predicate — nothing added, nothing
    dropped. -/
structure SingleWitness (F : Type) [CField F] where
  balancePrivCommit : HashOut F
  balancePublicState : Circuits.SingleWithdrawalCircuit.PublicState F
  channelId : F
  priv : Circuits.SingleWithdrawalCircuit.PrivateState F
  updNew : Circuits.SingleWithdrawalCircuit.PublicState F
  updOld : Circuits.SingleWithdrawalCircuit.PublicState F
  updEqWire : F
  updSib : List (HashOut F)
  accChannelId : F
  accAccountTreeRoot : HashOut F
  sendLeaf : Circuits.SingleWithdrawalCircuit.SendLeaf F
  sendLeafIndex : F
  sendSib : List (HashOut F)
  chanLeaf : Circuits.SingleWithdrawalCircuit.ChannelLeaf F
  userSib : List (HashOut F)
  tx : Circuits.SingleWithdrawalCircuit.Tx F
  txv2 : Circuits.SingleWithdrawalCircuit.TxV2 F
  useTxV2 : F
  sentSib : List (HashOut F)
  txSib : List (HashOut F)
  txv2Sib : List (HashOut F)
  transfer : Circuits.SingleWithdrawalCircuit.Transfer F
  transferIndex : F
  transferSib : List (HashOut F)
  twRoot : HashOut F
  w : Circuits.SingleWithdrawalCircuit.Withdrawal F
  ok : Circuits.SingleWithdrawalCircuit.Constraints balancePrivCommit
        balancePublicState channelId priv updNew updOld updEqWire updSib
        accChannelId accAccountTreeRoot sendLeaf sendLeafIndex sendSib
        chanLeaf userSib tx txv2 useTxV2 sentSib txSib txv2Sib transfer
        transferIndex transferSib twRoot w

/-- A satisfying witness of the top-level validity constraint system
    (`Circuits.ValidityCircuit.Constraints`), wires bundled. -/
structure ValidityWitness (F : Type) [CField F] where
  initialBpSigChain : Bytes32 F
  finalBpSigChain : Bytes32 F
  chainIsZero : F
  shouldVerify : F
  listCommitment : Bytes32 F
  listVerified : Prop
  ok : Circuits.ValidityCircuit.Constraints initialBpSigChain finalBpSigChain
        chainIsZero shouldVerify listCommitment listVerified

/-- A satisfying witness of one per-block `UpdateUserCircuit` instance
    (`Circuits.UpdateUser.Constraints`). -/
structure BlockWitness (F : Type) [CField F] where
  p : Circuits.UpdateUser.BlockParams F
  io : Circuits.UpdateUser.BlockIO F
  ok : Circuits.UpdateUser.Constraints p io

/-- The `bp_sig_chain` threading across a span of per-block witnesses
    (the cross-block continuity `BlockStep.bp_sig_chain_threaded`
    establishes on the Rust side): block `i+1` starts where block `i`
    ended, and the span's endpoints are `cIn`/`cOut`. -/
def ChainedBlocks : Bytes32 F → List (BlockWitness F) → Bytes32 F → Prop
  | cIn, [], cOut => cOut = cIn
  | cIn, b :: bs, cOut =>
      b.io.prevBpSigChain = cIn ∧ ChainedBlocks b.io.newBpSigChain bs cOut

/-- Every accepted block either preserves the accumulator or advances
    it by exactly one fold — the dichotomy `UpdateUser` proves
    (`non_signing_block_preserves` / `signing_block_advances`). -/
theorem block_chain_cases (hinj : Builder.NatLitInj F (2 ^ 63)) (b : BlockWitness F) :
    b.io.newBpSigChain = b.io.prevBpSigChain
    ∨ b.io.newBpSigChain
        = Circuits.UpdateUser.accumulate b.io.prevBpSigChain b.p.digest
            b.p.msg.bpPkG := by
  rcases Classical.em (∃ sl, sl ∈ b.io.slots ∧ sl.shouldUpdate = 1) with hex | hno
  · exact Or.inr (Circuits.UpdateUser.signing_block_advances hinj b.ok hex).1
  · left
    have hall : ∀ sl, sl ∈ b.io.slots → sl.shouldUpdate = 0 := by
      intro sl hs
      obtain ⟨j, hsc⟩ := Circuits.UpdateUser.threaded_slot_constraints b.ok.threaded hs
      rcases Circuits.UpdateUser.shouldUpdate_bool hsc with h0 | h1
      · exact h0
      · exact absurd ⟨sl, hs, h1⟩ hno
    exact (Circuits.UpdateUser.non_signing_block_preserves b.ok hall).1

/-- If every block in a span preserves the accumulator, the span's
    output equals its input. -/
theorem chained_preserved :
    ∀ {blocks : List (BlockWitness F)} {cIn cOut : Bytes32 F},
      ChainedBlocks cIn blocks cOut →
      (∀ b, b ∈ blocks → b.io.newBpSigChain = b.io.prevBpSigChain) →
      cOut = cIn := by
  intro blocks
  induction blocks with
  | nil =>
      intro cIn cOut h _
      simp only [ChainedBlocks] at h
      exact h
  | cons b bs ih =>
      intro cIn cOut h hall
      simp only [ChainedBlocks] at h
      obtain ⟨hprev, hrest⟩ := h
      have h2 := ih hrest (fun b' hb' => hall b' (List.mem_cons_of_mem _ hb'))
      rw [h2, hall b (List.mem_cons_self _ _), hprev]

/-- A span ending in the EMPTY accumulator contains no fold: a fold's
    output is never the zero chain (`AccumulateNeverEmpty`), and once
    folded the value survives every later preserve step. -/
theorem chained_zero_no_fold (hinj : Builder.NatLitInj F (2 ^ 63))
    (hne : Circuits.UpdateUser.AccumulateNeverEmpty F) :
    ∀ {blocks : List (BlockWitness F)} {cIn cOut : Bytes32 F},
      ChainedBlocks cIn blocks cOut →
      cOut = Circuits.UpdateUser.zeroBytes F →
      ∀ b, b ∈ blocks → b.io.newBpSigChain = b.io.prevBpSigChain := by
  intro blocks
  induction blocks with
  | nil =>
      intro cIn cOut _ _ b hb
      exact absurd hb (List.not_mem_nil b)
  | cons b0 bs ih =>
      intro cIn cOut h hzero b hb
      simp only [ChainedBlocks] at h
      obtain ⟨hprev, hrest⟩ := h
      have htail : ∀ b', b' ∈ bs → b'.io.newBpSigChain = b'.io.prevBpSigChain :=
        fun b' hb' => ih hrest hzero b' hb'
      have hout : cOut = b0.io.newBpSigChain := chained_preserved hrest htail
      have hb0 : b0.io.newBpSigChain = b0.io.prevBpSigChain := by
        rcases block_chain_cases hinj b0 with hp | hf
        · exact hp
        · exfalso
          apply hne b0.io.prevBpSigChain b0.p.digest b0.p.msg.bpPkG
          rw [← hf, ← hout]
          exact hzero
      rcases List.mem_cons.mp hb with rfl | htl
      · exact hb0
      · exact htail b htl

/-- **Cross-module composition (UpdateUser × threading).** If ANY block
    in a chained span changed the account tree root, the span's final
    accumulator is NOT the empty chain: the root select and the chain
    select share one `should_update` wire (`account_update_forces_fold`),
    a fold is never a fixed point (`AccumulateNoFixpoint`), and a fold's
    output is never zero (`AccumulateNeverEmpty`). -/
theorem chained_account_change_nonzero (hinj : Builder.NatLitInj F (2 ^ 63))
    (hnofix : Circuits.UpdateUser.AccumulateNoFixpoint F)
    (hne : Circuits.UpdateUser.AccumulateNeverEmpty F)
    {blocks : List (BlockWitness F)} {cIn cOut : Bytes32 F}
    (h : ChainedBlocks cIn blocks cOut)
    (hchg : ∃ b, b ∈ blocks ∧ b.io.newAccountRoot ≠ b.io.prevAccountRoot) :
    cOut ≠ Circuits.UpdateUser.zeroBytes F := by
  intro hzero
  obtain ⟨b, hb, hroot⟩ := hchg
  have hpres := chained_zero_no_fold hinj hne h hzero b hb
  have hfold := Circuits.UpdateUser.account_update_forces_fold hinj b.ok hroot
  rw [hpres] at hfold
  exact hnofix _ _ _ hfold.symm

/-! ### The repaired provenance chain, bundled -/

/-- Exactly the conclusion of
    `SingleWithdrawalCircuit.withdrawal_sound`, restated over a bundled
    witness (definitionally equal — see `singleWitness_provenance`). -/
def WithdrawalProvenance (sw : SingleWitness F) : Prop :=
  Circuits.SingleWithdrawalCircuit.privateCommitment sw.priv = sw.balancePrivCommit
  ∧ MerkleVerify Circuits.SingleWithdrawalCircuit.SENT_TX_TREE_HEIGHT
      (Circuits.SingleWithdrawalCircuit.txLeafHash sw.tx.transferTreeRoot sw.tx.nonce)
      sw.tx.nonce sw.sentSib sw.priv.sentTxTreeRoot
  ∧ MerkleVerify Circuits.SingleWithdrawalCircuit.TRANSFER_TREE_HEIGHT
      (Circuits.SingleWithdrawalCircuit.transferLeaf sw.transfer)
      sw.transferIndex sw.transferSib sw.tx.transferTreeRoot
  ∧ (MerkleVerify Circuits.SingleWithdrawalCircuit.TX_TREE_HEIGHT
       (Circuits.SingleWithdrawalCircuit.txLeafHash sw.tx.transferTreeRoot sw.tx.nonce)
       sw.channelId sw.txSib
       (Circuits.SingleWithdrawalCircuit.reduceToHashOut sw.sendLeaf.txTreeRoot)
     ∨ (MerkleVerify Circuits.SingleWithdrawalCircuit.TX_TREE_HEIGHT
          (Circuits.SingleWithdrawalCircuit.txv2Leaf sw.txv2)
          sw.channelId sw.txv2Sib
          (Circuits.SingleWithdrawalCircuit.reduceToHashOut sw.sendLeaf.txTreeRoot)
        ∧ sw.txv2.transferTreeRoot = sw.tx.transferTreeRoot
        ∧ sw.txv2.nonce = sw.tx.nonce
        ∧ sw.txv2.txClass = Circuits.SingleWithdrawalCircuit.USER_TRANSFER F
        ∧ sw.txv2.channelActionRoot = Circuits.SingleWithdrawalCircuit.zeroHash F))
  ∧ MerkleVerify Circuits.SingleWithdrawalCircuit.SEND_TREE_HEIGHT
      (Circuits.SingleWithdrawalCircuit.sendLeafHash sw.sendLeaf)
      sw.sendLeafIndex sw.sendSib sw.chanLeaf.sendTreeRoot
  ∧ MerkleVerify Circuits.SingleWithdrawalCircuit.CHANNEL_TREE_HEIGHT
      (Circuits.SingleWithdrawalCircuit.channelLeafHash sw.chanLeaf)
      sw.channelId sw.userSib sw.updNew.accountTreeRoot
  ∧ (sw.updNew = sw.balancePublicState
     ∨ MerkleVerify Circuits.SingleWithdrawalCircuit.PUBLIC_STATE_TREE_HEIGHT
         (Circuits.SingleWithdrawalCircuit.psLeaf sw.balancePublicState)
         sw.balancePublicState.blockNumber sw.updSib sw.updNew.prevPublicStateRoot)
  ∧ sw.w.recipient
      = Circuits.SingleWithdrawalCircuit.extractAddress sw.transfer.recipient
  ∧ sw.w.tokenIndex = sw.transfer.tokenIndex
  ∧ sw.w.amount = sw.transfer.amount
  ∧ sw.w.nullifier = Circuits.SingleWithdrawalCircuit.settledNullifier
      sw.transfer sw.channelId sw.transferIndex sw.tx.nonce
  ∧ sw.w.auxData = sw.transfer.auxData

/-- Every bundled witness carries the full repaired provenance chain —
    a direct instance of the existing `withdrawal_sound` (Wave 1). -/
theorem singleWitness_provenance (sw : SingleWitness F) :
    WithdrawalProvenance sw :=
  Circuits.SingleWithdrawalCircuit.withdrawal_sound sw.ok

/-- Projection: the withdrawn transfer is committed in the tx's
    transfer tree. -/
theorem WithdrawalProvenance.transferIncluded {sw : SingleWitness F}
    (h : WithdrawalProvenance sw) :
    MerkleVerify Circuits.SingleWithdrawalCircuit.TRANSFER_TREE_HEIGHT
      (Circuits.SingleWithdrawalCircuit.transferLeaf sw.transfer)
      sw.transferIndex sw.transferSib sw.tx.transferTreeRoot :=
  h.2.2.1

/-- Projection: the emitted amount is the transfer's amount. -/
theorem WithdrawalProvenance.amountFromTransfer {sw : SingleWitness F}
    (h : WithdrawalProvenance sw) : sw.w.amount = sw.transfer.amount :=
  h.2.2.2.2.2.2.2.2.2.1

/-!
## Part 3 — The circuit ↔ contract type boundary (named decoders)

The contract model computes over `Word/U256/Addr := Nat`; circuits
over `F`-valued wires. The functions below are the byte-level
re-interpretations the REAL system performs (u32-limb big-endian
layouts on both sides, `_toFieldElements` on the contract side); they
are opaque here because their limb arithmetic is not the subject of
this composition — what matters is that BOTH worlds apply the SAME
deterministic layout, which is a differential-tested fact
(`mle_onchain_e2e` drives the Rust encoder against the Solidity
decoder), named in `BridgeAssumptions.pi_layout_faithful`.
-/

/-- Contract-side encoding of one `withdrawNative` calldata leaf: the
    exact word list `_foldWithdrawalLeaf` (IntmaxRollup.sol:1385)
    hashes for this leaf inside the `pisHash` re-computation (:1345). -/
opaque encodeLeaf : Withdrawal → List Word

/-- Circuit-side encoding of one emitted `Withdrawal` PI record
    (single_withdrawal_circuit.rs:522-525 registration order), reduced
    to the contract's word view. Same Rust byte layout as `encodeLeaf`
    — transcribed once per world, identified by
    `BridgeAssumptions.pi_layout_faithful`. -/
opaque encodeWithdrawal {F : Type} [CField F] :
  Circuits.SingleWithdrawalCircuit.Withdrawal F → List Word

/-- The ℕ (U256) value of the circuit's abstracted amount wire. The
    `SingleWithdrawalCircuit` model keeps the 8-limb U256 amount as one
    `F` value; `SpendCircuit` keeps it as `U256.uval` of a limb vector.
    Both are the SAME Rust `U256Target`; `amountVal` is its canonical
    value. -/
opaque amountVal {F : Type} [CField F] : F → U256

/-- The contract `Addr` decoded from a circuit `Bytes32` recipient
    (low-20-byte address view, matching `extract_address`). -/
opaque addrVal {F : Type} [CField F] : Bytes32 F → Addr

/-- The contract `Word` decoded from a circuit `Bytes32` (nullifiers,
    aux data, commitments — the 32-byte big-endian value both sides
    hash). -/
opaque wordVal {F : Type} [CField F] : Bytes32 F → Word

/-- The contract `Word` value of a single field wire (used for the
    token index: the contract's ETH check :1350 is `tokenIndex == 0`,
    modeled as `isEth` on the contract side). -/
opaque fieldVal {F : Type} [CField F] : F → Word

/-- The `HashOut` digest of an emitted `PublicState`, as parsed by the
    chain/wrapper circuits (`withdrawal_circuit.rs:187-189` reads the
    chain proof's public state as a digest). Same wires, transcribed at
    two abstraction levels — an intra-Rust identification, not a new
    hash. -/
opaque psDigest {F : Type} [CField F] :
  Circuits.SingleWithdrawalCircuit.PublicState F → HashOut F

/-- `keccak256(ValidityPublicInputs)` of an accepted validity proof,
    reduced to the contract word `finalize` records
    (IntmaxRollup.sol:1122 / `_computeValidityPIHash` :1757). -/
opaque validityRootOf {F : Type} [CField F] : ValidityWitness F → Word

/-- Field-by-field correspondence between a circuit-side withdrawal PI
    record and a contract-side calldata leaf. Each field cites the
    contract consumption point. -/
structure DecodesTo (cw : Circuits.SingleWithdrawalCircuit.Withdrawal F)
    (w : Withdrawal) : Prop where
  /-- :1374 — the credited recipient is the circuit's extracted address. -/
  recipient : w.recipient = addrVal cw.recipient
  /-- :1373 — the escrow decrement is the circuit's amount value. -/
  amount : w.amount = amountVal cw.amount
  /-- :1351/:1371 — the consumed nullifier is the circuit's settled
      nullifier. -/
  nullifier : w.nullifier = wordVal cw.nullifier
  /-- :1357-1368 — the burn discriminant is the circuit's aux data. -/
  auxData : w.auxData = wordVal cw.auxData
  /-- :1350 — the model's `isEth` stands for `tokenIndex == 0`. -/
  eth : w.isEth = true → fieldVal cw.tokenIndex = 0

/-!
## Part 4 — The named bridge assumptions

Every English arrow between layers, as a field. A field is TRUST
(justified by an out-of-model mechanism, stated in its docstring) —
never a theorem smuggled in: everything provable inside the model is
proved in Parts 1–2 or in the imported modules and merely COMPOSED in
Part 5.
-/

/-- **The bridge-assumption record** for one `withdrawNative` call
    (`ws`, `mleVerified`, `pisBound`, `extC`) in a contract history
    `ops`, deployed with flag `allowMleDisabled`.

    `Accepted` / `AcceptedValidity` are semantic markers — "this
    witness bundle was extracted from a proof object the on-chain
    verifier actually accepted". They exist so that the recursion
    oracles below quantify ONLY over proof-extracted witnesses: a
    universally-quantified version (over every constraint-satisfying
    tuple) would be dishonestly strong, since a raw tuple with a
    fabricated `balancePrivCommit` has no verified balance proof
    behind it. -/
structure BridgeAssumptions (F : Type) [CField F] (allowMleDisabled : Bool)
    (ops : List EOp) (ws : List Withdrawal)
    (mleVerified pisBound : Prop) (extC : Word) where
  /-- Marker: extracted from an accepted withdrawal-pipeline proof. -/
  Accepted : SingleWitness F → Prop
  /-- Marker: extracted from an accepted validity proof. -/
  AcceptedValidity : ValidityWitness F → Prop
  /-- **Proof-system oracle (withdrawal pipeline).** If the contract's
      `_verifyMleWithdrawal` gate accepted (`mleVerified`, :1316) and
      the recomputed `pisHash` matched the proof's PI (`pisBound`,
      :1345), then there EXIST circuit witnesses behind the proof: a
      wrapper witness (`WithdrawalCircuit.Constraints`) whose
      ext-state commitment word is the `extCommitment` argument, and —
      for EVERY calldata leaf — an accepted single-withdrawal witness
      whose emitted PI record has the SAME word encoding as that leaf
      and whose emitted public state digests to the wrapper's chain
      state.

      Justified by, in order: (i) MLE/WHIR verifier soundness
      (`@mle/MleVerifier.sol`, uninterpreted crypto oracle — same
      status as Poseidon); (ii) plonky2 recursive verification: the
      wrapper verifies the chain proof
      (`add_proof_target_and_verify_cyclic`, withdrawal_circuit.rs:183)
      and each chain step verifies one single-withdrawal proof with
      cyclic vd binding (withdrawal_step.rs:346-353 — the
      `check_cyclic_proof_verifier_data` pattern proved sound at the
      balance fixed point, `BalanceCircuit.cyclic_sound`); (iii)
      `KeccakCR` (`keccak_cr` below) + the differential-tested
      `_withdrawalPisHash`/`_foldWithdrawalLeaf` byte layout: the :1345
      hash equality forces the calldata leaf words to equal the proof's
      PI words leaf-by-leaf; (iv) WDR-CRIT-001
      (`WithdrawalStep.state_threaded`): every aggregated
      single-withdrawal was proven against the ONE threaded public
      state the wrapper commits (`inner_bound`), giving the
      `psDigest`-equality per leaf. -/
  withdrawal_proof_oracle : mleVerified → pisBound →
    ∃ (cext : Circuits.WithdrawalCircuit.ExtendedPublicState F)
      (chainPS : HashOut F),
      Circuits.WithdrawalCircuit.Constraints cext chainPS
      ∧ wordVal (Circuits.WithdrawalCircuit.extCommitment cext) = extC
      ∧ ∀ w, w ∈ ws → ∃ sw : SingleWitness F,
          Accepted sw
          ∧ encodeWithdrawal sw.w = encodeLeaf w
          ∧ psDigest sw.updNew = chainPS
  /-- **PI layout faithfulness.** Equal word encodings decode to
      field-matching records. Justified by the byte-identical
      `Withdrawal` layout on both sides (Rust `to_u32_vec` /
      registration order vs `_foldWithdrawalLeaf`), asserted by the
      differential fixture tests (`mle_onchain_e2e` drives Forge with
      Rust-generated proofs). A layout divergence would break the E2E
      test before it broke this assumption. -/
  pi_layout_faithful :
    ∀ (cw : Circuits.SingleWithdrawalCircuit.Withdrawal F) (w : Withdrawal),
      encodeWithdrawal cw = encodeLeaf w → DecodesTo cw w
  /-- **Recursion oracle: withdrawal → balance → spend.** For every
      proof-extracted single-withdrawal witness, the tx that
      `withdrawal_sound` locates in the committed sent-tx tree was
      RECORDED by an accepted `SpendCircuit` run: there is a deduction
      chain (`Deducts`) one of whose steps subtracts exactly this
      withdrawal's transfer amount.

      Justified by: the balance proof is verified cyclically at
      single_withdrawal_circuit.rs:422 against the fixed balance vd
      (`BalanceCircuit.cyclic_sound` — `proofVd = selfVd`, closing
      C-M3); `SwitchBoard.routing_sound` routes each balance transition
      to exactly one sub-circuit; the ONLY writer of the sent-tx tree
      across all four routes is `SpendCircuit`'s `SentTxRecord`
      (empty-slot replay guard), whose deduction chain is `Deducts`.
      The full IVC induction over the balance chain ("every entry of
      every reachable sent-tx tree originates in a spend") is NOT
      machine-checked — this field is precisely that boundary, named. -/
  balance_recursion : ∀ sw : SingleWitness F, Accepted sw →
    ∃ (rootIn rootOut : HashOut F)
      (steps : List (Circuits.SpendCircuit.TransferStep F))
      (st : Circuits.SpendCircuit.TransferStep F),
      Circuits.SpendCircuit.Deducts rootIn steps rootOut
      ∧ st ∈ steps
      ∧ U256.uval st.amount = amountVal sw.transfer.amount
  /-- **Proof-system oracle (validity pipeline).** Every root the trace
      finalized with a `true` gate output has an accepted validity
      witness whose `keccak256(ValidityPublicInputs)` word is that
      root.

      Justified by: `finalize_only_on_valid` (proved — the trace lemma
      `erun_finalized_provenance` lifts it to all reachable states, so
      the `EOp.fin root true ∈ ops` premise here is itself DERIVED, not
      assumed); `mle_enabled` below (with `allowMleDisabled = false`
      the :1584 short-circuit is dead — `mle_gate_real_when_enabled` —
      so `valid = true` means the MLE/WHIR validity verification really
      ran); MLE/WHIR verifier soundness; and the
      `_computeValidityPIHash` layout (differential-tested like the
      withdrawal layout). -/
  validity_oracle : ∀ root : Word, EOp.fin root true ∈ ops →
    ∃ vw : ValidityWitness F, AcceptedValidity vw ∧ validityRootOf vw = root
  /-- **Recursion oracle: validity → update_user.** Behind every
      accepted validity witness stands a span of accepted per-block
      `UpdateUserCircuit` witnesses whose `bp_sig_chain` threads
      unbroken from the span's initial accumulator to its final one.

      Justified by: the validity circuit cyclically verifies the
      block-hash-chain proof (validity_circuit.rs:197-198); each block
      step verifies one update proof against a pinned VK and threads
      `bp_sig_chain` (`BlockStep.bp_sig_chain_threaded` on the Rust
      side of this audit); plonky2 recursion soundness turns "verified"
      into "a satisfying witness exists". What the span DOES once it
      exists is then proved, not assumed: `block_chain_cases`,
      `chained_account_change_nonzero`. -/
  update_user_recursion : ∀ vw : ValidityWitness F, AcceptedValidity vw →
    ∃ blocks : List (BlockWitness F),
      ChainedBlocks vw.initialBpSigChain blocks vw.finalBpSigChain
  /-- **Cross-module opaque identification.** `ValidityCircuit.zeroChain`
      (opaque) and `UpdateUser.zeroBytes` (`List.replicate 32 0`) both
      transcribe Rust's `Bytes32::default()` — the same value modeled
      twice in sibling modules. Needed to let the validity circuit's
      computed `is_zero` gate see the update-circuit span's
      accumulator. -/
  zero_chain_eq :
    Circuits.ValidityCircuit.zeroChain F = Circuits.UpdateUser.zeroBytes F
  /-- Production deployment flag (`Contracts.Assumptions`): with
      `allowMleDisabled = false` the `_verifyMle` short-circuit (:1584)
      is dead and `finalize`'s gate output is the real verification
      result — the precondition for `validity_oracle` to be sound. -/
  mle_enabled : Contracts.Assumptions.MleVerificationEnabled allowMleDisabled
  /-- Modeling assumption (`Contracts.Assumptions`): calls are atomic —
      `nonReentrant` + CEI ordering in the Solidity source. The `erun`
      trace semantics (and hence every trace lemma here) quantifies
      over exactly the interleaving-free behaviors this guarantees. -/
  atomicity : Contracts.Assumptions.SingleCallAtomicity
  /-- Modeling assumption (`Contracts.Assumptions`): a failed ETH push
      reverts the whole call, so "paid" in the model means paid. -/
  eth_send_reverts : Contracts.Assumptions.EthSendFailureReverts
  /-- CR of the 2-to-1 Merkle compression (`Core/Merkle.lean`), consumed
      here by the transfer-leaf binding conjunct
      (`LeafFacts.transferBound`). -/
  compress_cr : Merkle.CompressCR F
  /-- CR of the list-input Poseidon leaf hash (`Core/Bytes.lean`).
      Justificatory for this composition: it is what turns the Merkle
      digest facts of `WithdrawalProvenance` into "unique real
      transfer/tx/leaf" at the preimage level (see the
      SingleWithdrawalCircuit SECURITY OBSERVATIONS). -/
  poseidon_cr : Bytes.PoseidonCR F
  /-- CR of the contract-side keccak (`Contracts/Coverage.lean`).
      Justificatory for `withdrawal_proof_oracle` (iii): the :1345
      single hash equality binds the whole `ws`/`extC` preimage. -/
  keccak_cr : Contracts.Coverage.KeccakCR
  /-- Characteristic hypothesis (`Core/Merkle.lean`): `k`-bit index
      decompositions are unique for every `k ≤ 63` — true in Goldilocks
      (`p > 2^63`). Consumed by `LeafFacts.transferBound` (at height
      6) and by every imported theorem that identifies the two
      per-call `split_le` decompositions of one index wire
      (heights 32, 63; see the Core/Merkle.lean header). -/
  pow_two_inj : ∀ k : Nat, k ≤ 63 → Merkle.PowTwoInj F k
  /-- Root ↔ leaf-map binding of the nullifier tree
      (`UpdatePrivateState.NullifierRootBinding`), stated honestly over
      the height-32 root's `2^32`-slot support: `binds` (equal roots ⇒
      slot agreement below `2^32`, the CR idealization at the root
      level) + `supp` (the root reads only those slots — true of the
      real height-32 root unconditionally). Consumed by
      `LeafFacts.spendOnce` via `nullifierInsert_reachable_chain`. -/
  nullifier_root_binding : Circuits.UpdatePrivateState.NullifierRootBinding F
  /-- BOUNDED injectivity of the numeral embedding below `2^63`
      (`Core/Builder.lean`) — genuinely true in Goldilocks
      (`p > 2^63`; derivable from `ReprFaithful`); the unbounded form
      is pigeonhole-false at any finite field and is never assumed.
      Applied only to slot indices `< MAX_CHANNEL_MEMBERS = 16`, whose
      bounds come from `UpdateUser.Constraints.slotCount`; consumed by
      the single-fold-per-block argument. -/
  nat_lit_inj : Builder.NatLitInj F (2 ^ 63)
  /-- The Poseidon accumulator step has no fixed point
      (`UpdateUser.AccumulateNoFixpoint`) — a fixed point would be a
      structured Poseidon PREIMAGE relation (not a collision). NOTE
      the idealization caveat at its definition: literally
      false-by-counting for real Poseidon, read symbolically as "no
      fixed-point instance exhibited". Consumed by
      `chained_account_change_nonzero`. -/
  accumulate_no_fixpoint : Circuits.UpdateUser.AccumulateNoFixpoint F
  /-- The accumulator step never outputs the empty chain
      (`UpdateUser.AccumulateNeverEmpty`) — a zero output would be a
      Poseidon preimage of the fixed zero digest. Same idealization
      caveat as `accumulate_no_fixpoint` (see its definition); consumed
      by `chained_zero_no_fold`. -/
  accumulate_never_empty : Circuits.UpdateUser.AccumulateNeverEmpty F

/-!
## Part 5 — The composed theorem
-/

/-- Everything the composition establishes about ONE paid leaf `w`
    through a given proof-extracted single-withdrawal witness `sw`,
    anchored at the wrapper's threaded chain state `anchor`.
    (`LeafBacking` below existentially closes over `sw`.) -/
structure LeafFacts (F : Type) [CField F]
    (Accepted : SingleWitness F → Prop) (anchor : HashOut F)
    (w : Withdrawal) (sw : SingleWitness F) : Prop where
  accepted : Accepted sw
  /-- (a) BACKED — the paid calldata leaf is byte-identical to the
      proof's emitted PI record. -/
  piBytes : encodeWithdrawal sw.w = encodeLeaf w
  /-- (a) BACKED — hence field-identical under the tested layout. -/
  decodes : DecodesTo sw.w w
  /-- (b) SENT — the full repaired provenance chain of
      `withdrawal_sound`: the withdrawn transfer sits in a tx the user
      committed in the balance proof's private state AND in a block tx
      tree under the emitted state's account root, with all emitted
      fields copied from that transfer. -/
  provenance : WithdrawalProvenance sw
  /-- (c) ANCHORED (per leaf) — the emitted public state this leaf's
      provenance hangs off is the ONE chain state the wrapper committed
      into the finalized ext commitment (WDR-CRIT-001 + `inner_bound`). -/
  anchored : psDigest sw.updNew = anchor
  /-- Binding: under `CompressCR` + `PowTwoInj 6`, the transfer tree
      root opens at `transferIndex` ONLY to this transfer's digest —
      no second leaf can claim the same slot. -/
  transferBound : ∀ (l : HashOut F) (osib : List (HashOut F)),
      MerkleVerify Circuits.SingleWithdrawalCircuit.TRANSFER_TREE_HEIGHT l
        sw.transferIndex osib sw.tx.transferTreeRoot →
      l = Circuits.SingleWithdrawalCircuit.transferLeaf sw.transfer
  /-- (b') DEDUCTED — an accepted spend deducted EXACTLY the paid
      amount, and solvently (`deducts_solvent`): the on-chain payout
      never exceeds the balance the sender provably held. -/
  deducted : ∃ (rootIn rootOut : HashOut F)
      (steps : List (Circuits.SpendCircuit.TransferStep F))
      (st : Circuits.SpendCircuit.TransferStep F),
      Circuits.SpendCircuit.Deducts rootIn steps rootOut
      ∧ st ∈ steps
      ∧ U256.uval st.amount = w.amount
      ∧ U256.uval st.amount ≤ U256.uval st.before
  /-- (d) SINGLE-USE, circuit side — receive-crediting of THIS leaf's
      nullifier on any reachable nullifier tree proves prior absence
      (`nullifierInsert_reachable_chain` under `NullifierRootBinding`):
      the same settled transfer can never be credited twice either. -/
  spendOnce : ∀ (Tr : IndexedMerkle.Tree), IndexedMerkle.Reachable Tr →
      ∀ (newRoot : HashOut F),
        Circuits.UpdatePrivateState.NullifierInsert
          (Circuits.UpdatePrivateState.nullifierRoot Tr) sw.w.nullifier newRoot →
        ¬ IndexedMerkle.present Tr
          (Circuits.UpdatePrivateState.nullifierKey sw.w.nullifier)

/-- The per-leaf backing claim: SOME proof-extracted single-withdrawal
    witness carries all of `LeafFacts` for this paid leaf. -/
def LeafBacking (F : Type) [CField F]
    (Accepted : SingleWitness F → Prop) (anchor : HashOut F)
    (w : Withdrawal) : Prop :=
  ∃ sw : SingleWitness F, LeafFacts F Accepted anchor w sw

/-- Everything the composition establishes about the anchoring
    commitment `extC` of the call, through a given accepted validity
    witness `vw` and its per-block span `blocks`. (`AnchorBacking`
    below existentially closes over both.) -/
structure AnchorFacts (F : Type) [CField F]
    (AcceptedValidity : ValidityWitness F → Prop)
    (ops : List EOp) (extC : Word)
    (vw : ValidityWitness F) (blocks : List (BlockWitness F)) : Prop where
  /-- (c) — the trace wrote this root through `finalize` on a `true`
      gate output (proved by `erun_finalized_provenance`, not assumed). -/
  finalizedByTrace : EOp.fin extC true ∈ ops
  /-- The validity witness behind that finalization is accepted … -/
  accepted : AcceptedValidity vw
  /-- … and its statement digest is the anchored word. -/
  root : validityRootOf vw = extC
  /-- The per-block update span threads the accumulator unbroken. -/
  chained : ChainedBlocks vw.initialBpSigChain blocks vw.finalBpSigChain
  /-- The span starts from the empty accumulator (validity_circuit.rs
      :222-224 — a constraint, hence proved from `vw.ok`). -/
  spanStartsEmpty : vw.initialBpSigChain = Circuits.ValidityCircuit.zeroChain F
  /-- (c) teeth — if ANY block in the anchored span changed the account
      tree root (i.e. any user state this call's provenance can hang
      off was written), the signature-list proof was VERIFIED and its
      commitment equals the accumulator: no forged-signature block can
      anchor a payout (`account_update_forces_fold` ×
      `signatures_not_skippable`). -/
  sigGated : (∃ b, b ∈ blocks ∧ b.io.newAccountRoot ≠ b.io.prevAccountRoot) →
      vw.listVerified ∧ vw.listCommitment = vw.finalBpSigChain

/-- The anchoring claim: SOME accepted validity witness and per-block
    span carry all of `AnchorFacts` for the anchored commitment. -/
def AnchorBacking (F : Type) [CField F]
    (AcceptedValidity : ValidityWitness F → Prop)
    (ops : List EOp) (extC : Word) : Prop :=
  ∃ (vw : ValidityWitness F) (blocks : List (BlockWitness F)),
    AnchorFacts F AcceptedValidity ops extC vw blocks

/-- **END-TO-END PAYOUT SOUNDNESS (the composed theorem).**

    For every accepted `withdrawNative` call in a contract state
    reachable from a genesis with no pre-finalized roots and zero
    escrow, under the NAMED `BridgeAssumptions`:

      (a) **backed** — each paid leaf has a proof-extracted
          single-withdrawal witness whose PI record encodes it, all
          hanging off ONE wrapper witness whose ext commitment is the
          anchored word (`LeafFacts.piBytes/.decodes`);
      (b) **sent + deducted** — via the repaired `withdrawal_sound`
          chain, each leaf reflects a transfer the user committed in
          their balance proof, and an accepted spend solvently deducted
          exactly the paid amount (`LeafFacts.provenance/.deducted`).
          NOTE (amount-only binding): SAME-SENDER LINEAGE IS NOT
          ESTABLISHED by `balance_recursion` — its conclusion equates
          only the deducted step's AMOUNT with the withdrawal's; it
          does not identify the spend's tx / sender / private state
          with the withdrawal witness's. "The very user whose balance
          proof anchors this leaf is the one whose spend was deducted"
          is part of the unformalized IVC induction that field names
          (see its docstring), not a consequence of this theorem;
      (c) **anchored** — the ext commitment passed the on-chain
          `finalizedStateRoots` check, was written by a `true`-gated
          `finalize` in the trace (proved), and is backed by a validity
          witness whose block span cannot contain an account-root
          change without a verified signature list (`AnchorBacking`);
      (d) **single-use** — every paid nullifier is consumed in the
          post-state, so any later leaf with the same nullifier reverts
          (`withdrawLeaf_nullifier_once`); circuit-side, crediting the
          same nullifier twice is impossible on reachable trees
          (`LeafFacts.spendOnce`). CROSS-PATH NOTE: the contract's
          `nullifierUsed` map is ONE set shared by `withdrawNative`
          (read :1351 / write :1371) and `claimAuthorizedWithdrawal`
          (read :645 / write :659), so a nullifier paid via either path
          cannot be replayed via the other — the claim-side consumption
          is `claimAuthorized_safe` (IntmaxRollupWithdraw.lean);
      (e) **bounded** — the call paid at most the escrow it found, and
          over the whole history including this call,
          `Σ withdrawn ≤ Σ deposited` (the trace-level
          `solvent_from_genesis` bound, extended over `finalize`).

    Every arrow that is not one of the imported per-layer theorems is a
    named field of `A` — the composition itself introduces no unstated
    trust. -/
theorem end_to_end_payout_sound
    {F : Type} [CField F] {allowMleDisabled : Bool}
    {s0 s s' : RollupState} {ops : List EOp}
    {ws : List Withdrawal}
    {mleVerified pisBound : Prop} [Decidable mleVerified] [Decidable pisBound]
    {extC : Word}
    (hgenFin : ∀ r, s0.finalizedStateRoots.get r = false)
    (hgenEsc : s0.totalEscrowed = 0)
    (hreach : erun s0 ops = some s)
    (hcall : withdrawNative s ws mleVerified pisBound extC = some s')
    (A : BridgeAssumptions F allowMleDisabled ops ws mleVerified pisBound extC) :
    -- (a)+(b): one wrapper witness, per-leaf backing anchored at its inner state
    (∃ (cext : Circuits.WithdrawalCircuit.ExtendedPublicState F)
       (chainPS : HashOut F),
       Circuits.WithdrawalCircuit.Constraints cext chainPS
       ∧ cext.inner = chainPS
       ∧ wordVal (Circuits.WithdrawalCircuit.extCommitment cext) = extC
       ∧ ∀ w, w ∈ ws → LeafBacking F A.Accepted cext.inner w)
    -- (c): anchored on-chain …
    ∧ s.finalizedStateRoots.get extC = true
    -- … with trace-proved finalization provenance and validity backing
    ∧ AnchorBacking F A.AcceptedValidity ops extC
    -- (d): single-use on-chain
    ∧ (∀ w, w ∈ ws →
        s'.nullifierUsed.get w.nullifier = true
        ∧ ∀ w2 : Withdrawal, w2.nullifier = w.nullifier →
            withdrawLeaf s' w2 = none)
    -- (e): bounded — per call and over the whole history
    ∧ totalAmount ws ≤ s.totalEscrowed
    ∧ totalAmount ws + ewithdrawn ops ≤ edeposited ops := by
  obtain ⟨hmle, hanch, hpis⟩ := withdrawNative_requires_proof hcall
  obtain ⟨cext, chainPS, hwc, hextw, hleaves⟩ := A.withdrawal_proof_oracle hmle hpis
  -- (c) finalization provenance is PROVED from the trace, not assumed
  have hfinMem : EOp.fin extC true ∈ ops := by
    rcases erun_finalized_provenance hreach hanch with hg | hmem
    · rw [hgenFin extC] at hg
      exact absurd hg (by decide)
    · exact hmem
  obtain ⟨vw, hvacc, hvroot⟩ := A.validity_oracle extC hfinMem
  obtain ⟨blocks, hchain⟩ := A.update_user_recursion vw hvacc
  refine ⟨⟨cext, chainPS, hwc, hwc.bindInner, hextw, ?_⟩, hanch,
    ⟨vw, blocks, hfinMem, hvacc, hvroot, hchain, vw.ok.initialZero, ?_⟩,
    ?_, (withdrawNative_solvency hcall).1, ?_⟩
  · -- per-leaf backing
    intro w hw
    obtain ⟨sw, hacc, henc, hpsd⟩ := hleaves w hw
    have hdec : DecodesTo sw.w w := A.pi_layout_faithful sw.w w henc
    have hprov := singleWitness_provenance sw
    obtain ⟨rootIn, rootOut, steps, st, hded, hstm, hamtv⟩ :=
      A.balance_recursion sw hacc
    have hwamt : w.amount = amountVal sw.transfer.amount := by
      rw [hdec.amount, hprov.amountFromTransfer]
    refine ⟨sw, hacc, henc, hdec, hprov, ?_, ?_, ?_, ?_⟩
    · -- anchored at the wrapper's inner chain state
      rw [hwc.bindInner]
      exact hpsd
    · -- transfer-leaf binding under CompressCR + PowTwoInj 6
      intro l osib hincl
      exact (merkleVerify_binding A.compress_cr
        (A.pow_two_inj Circuits.SingleWithdrawalCircuit.TRANSFER_TREE_HEIGHT
          (by decide))
        hincl hprov.transferIncluded).1
    · -- deducted, solvently
      refine ⟨rootIn, rootOut, steps, st, hded, hstm, ?_,
        Circuits.SpendCircuit.deducts_solvent hded st hstm⟩
      rw [hwamt]
      exact hamtv
    · -- circuit-side spend-once for this leaf's nullifier
      intro Tr hr newRoot hins
      exact (Circuits.UpdatePrivateState.nullifierInsert_reachable_chain
        A.nullifier_root_binding hr rfl hins).1
  · -- (c) teeth: account change in the anchored span ⇒ verified signatures
    intro hchg
    have hnz := chained_account_change_nonzero A.nat_lit_inj
      A.accumulate_no_fixpoint A.accumulate_never_empty hchain hchg
    exact Circuits.ValidityCircuit.signatures_not_skippable vw.ok
      (fun hEq => hnz (A.zero_chain_eq ▸ hEq))
  · -- (d) single-use on-chain
    intro w hw
    have hcons := withdrawNative_consumes hcall w hw
    exact ⟨hcons, fun w2 hw2 =>
      withdrawLeaf_nullifier_once (by rw [hw2]; exact hcons)⟩
  · -- (e) whole-history bound
    have hc := erun_conservation hreach
    rw [hgenEsc, Nat.zero_add] at hc
    have hle := (withdrawNative_solvency hcall).1
    calc totalAmount ws + ewithdrawn ops
        ≤ s.totalEscrowed + ewithdrawn ops := Nat.add_le_add_right hle _
      _ = edeposited ops := hc

/-!
## RESIDUAL TRUST SURFACE — what remains OUTSIDE even this composition

The composed theorem closes the layer gaps the meta-audit flagged, but
the following remain, deliberately and visibly, outside it:

  1. **F-UPDU-1 (channel_reg residual, base-layer fund risk).** On a
     registration block the account tree root is REPLACED by the
     channel-reg chain proof's `channel_tree_root`
     (`UpdateUser.RegBranch.registration_root_swap_anchored` proves
     everything block_step binds). The relation between that root and
     the keccak reg chain lives inside the still-excluded
     `channel_reg_step.rs`. Every `LeafFacts.provenance` anchored to
     a post-registration account root is therefore sound only
     conditional on that circuit — this dependency threads through
     `BridgeAssumptions.update_user_recursion` unnamed because it is a
     property of the WITNESSES, not of the recursion; it is named at
     its own finding site (Zkp/Circuits/Validity/UpdateUser.lean,
     F-UPDU-1 block).

  2. **Burn-path trust.** `claimAuthorizedWithdrawal` pays escrow with
     NO rollup-side proof; its legitimacy is
     `Contracts.Assumptions.BurnAuthorizationsLegitimate` (deployer +
     registered settlement managers), with the in-model drain witness
     `burn_drain_satisfiable`. This theorem's claims (a)-(d) do NOT
     cover `EOp.claim` payouts; only the solvency bound (e) does —
     a rogue manager can steal escrow but cannot mint it.

  3. **Primitive soundness.** Poseidon (`Bytes.poseidon`,
     `Merkle.compress`), keccak (`Coverage.keccak`), the MLE/WHIR
     verifier, plonky2's FRI verifier, and the Poseidon2-preimage
     signature scheme are uninterpreted. Their required properties
     appear ONLY as the named CR/no-fixpoint fields of
     `BridgeAssumptions`; anything beyond those (e.g. Fiat-Shamir
     soundness of the WHIR transcript binding) is trusted at the level
     of the upstream audits.

  4. **The `Accepted` markers.** "The on-chain verifier accepted ⇒ a
     constraint-satisfying witness exists with these PIs" is knowledge
     soundness of the proof system plus the faithfulness of this
     audit's line-by-line constraint transcription. The transcription
     is citation-checked per conjunct (see each circuit file's
     constraint inventory); it is not, and cannot be, internally
     verified by Lean.

  5. **F-SPEND-1 (nonce-ordering flag).** `SpendCircuit`'s `is_valid`
     is computed but not asserted in-circuit; `balance_recursion` does
     not claim nonce ordering, only solvent deduction and the
     empty-slot replay guard. Impact remains bounded as adjudicated at
     the finding site.

  6. **F-WITHDRAW-1 closure is contract-conditional in one direction.**
     The wrapper's 5 extended ext-state fields are free witnesses
     (`WithdrawalCircuit` — only `inner` is bound). The composition
     uses ONLY `wordVal (extCommitment cext) = extC` plus the on-chain
     `finalizedStateRoots[extC]` re-pin, which is exactly the closure
     pattern; no extended field is consumed as ground truth anywhere in
     the composed claims.

  7. **F-WD-2 (settle-twice nullifier) — CLOSED by Option B, NO LONGER
     a residual.** The single-withdrawal nullifier preimage no longer
     carries the settling block number; its 4th field is now `tx.nonce`
     (transfer.rs SettledTransfer, Option B). `WithdrawalProvenance`
     accordingly proves `sw.w.nullifier = settledNullifier sw.transfer
     sw.channelId sw.transferIndex sw.tx.nonce`, a function of ONLY
     deduction-bound inputs: `channelId` (balance-PI bound),
     `transfer`/`transferIndex` (transfer-tree membership), and
     `tx.nonce` (sent-tx membership at index=nonce under the balance
     proof's committed private state — `SingleWithdrawalCircuit`'s
     `sentTx`; sender-side, `spend_circuit` writes at index=nonce with
     an empty-slot check and sequential nonce, so `(from, nonce,
     transfer_index)` is a one-time deduction id). Since NOTHING
     settlement-varying remains in the preimage, settling ONE deduction
     into two blocks yields the SAME nullifier. The one-shot argument of
     clause (d) therefore rests on NONCE-uniqueness, not on any
     validity-side settlement-uniqueness induction: two settlements of a
     deduction collide on one key, so the on-chain `nullifierUsed`
     consumption (`withdrawNative_consumes` / `withdrawLeaf_nullifier_once`)
     and the circuit-side `LeafFacts.spendOnce` — both keyed on the
     nullifier — SUFFICE to block the pair. The nonce-binding fact
     backing this is NOT a new trust assumption: it is PROVED per
     witness by `withdrawal_sound`'s `wNul` and surfaced at the
     composition boundary as the nullifier conjunct of
     `WithdrawalProvenance` (`LeafFacts.provenance`), whose only
     external input is the Rust preimage transcription (audited like
     every other conjunct). See the F-WD-2 finding block (now CLOSED) in
     Zkp/Circuits/Withdraw/SingleWithdrawalCircuit.lean. Option A
     (settlement-side settled-nonce set) remains an OPTIONAL
     defense-in-depth follow-up, NOT required for this closure.
-/

end EndToEnd
end Zkp
