import Zkp.Implementation.CloseFunding
import Zkp.Implementation.RollupValue
import Zkp.Implementation.ManagerValue

/-!
# Composition of current, source-oriented accounting transitions

This module connects the existing implementations' definitions, rather than
assuming that successful proof verification already implies solvency.

`credit_projection` identifies the materializer's expanded Rollup call with the
Rollup implementation's native/ERC20 dispatch. `credit_call_projection` also
checks its chain, caller, underflow and overflow guards, including error results.
`AccountingStep` uses those actual credit, pull and payout definitions. Induction
preserves the per-token accounted total through any finite sequence of them.

The pull coupling is an EXPLICIT call-boundary obligation: the Manager's external
pull must correspond to the Rollup debit, with the exact requested amount and
recipient. This is not established by a model function returning `.ok ()`.
Likewise paid/received are accounting counters, not a proof that arbitrary ERC20
contracts implement honest balances or that an EVM/compiler realizes this model.
Ownership of pooled escrow, recursive proof soundness, signatures, allocation
entitlement, deposits, stake, rollback, liveness and arbitrary unguarded callbacks
are not consequences of the conservation theorem. Source-language/bytecode
refinement and these environment obligations remain separately open.
-/

namespace Zkp.Implementation.FundFlow


def projectLedger (s : RollupValue.State) : CloseFunding.Ledger :=
  { escrow := fun token => s.escrow (RollupValue.assetOfToken token)
    pending := fun token => s.pending (RollupValue.assetOfToken token) }

theorem asset_dispatch_injective (a b : Nat) :
    RollupValue.assetOfToken a = RollupValue.assetOfToken b ↔ a = b := by
  by_cases ha : a = 0 <;> by_cases hb : b = 0 <;>
    simp [RollupValue.assetOfToken, ha, hb, eq_comm]

theorem credit_projection (s : RollupValue.State) (manager : Nat) (c : CloseFunding.Credit) :
    projectLedger (RollupValue.creditState s (RollupValue.assetOfToken c.token) manager c.amount) =
      CloseFunding.creditState (projectLedger s) manager c := by
  unfold projectLedger RollupValue.creditState CloseFunding.creditState
  congr 1
  · funext token
    simp [projectLedger, RollupValue.creditState, CloseFunding.creditState, RollupValue.put, CloseFunding.put,
      asset_dispatch_injective]
  · funext token recipient
    by_cases same : token = c.token <;>
      simp [projectLedger, RollupValue.creditState, CloseFunding.creditState, RollupValue.put, CloseFunding.put,
        asset_dispatch_injective, same]

/-- Exact errors of creditChannelExit. External calls cannot arise in that
    helper; its external-error fallback is not a general-purpose ABI codec. -/
def creditError : RollupValue.Error → CloseFunding.Error
  | .revert name => .revert name
  | .revertArgs name args => .revert name args
  | .panic name => .panic name
  | .external _ => .revert "external call outside creditChannelExit"

def projectResult : RollupValue.Result RollupValue.State → CloseFunding.Result CloseFunding.Ledger
  | .ok s => .ok (projectLedger s)
  | .error e => .error (creditError e)

structure CreditCallContext (ce : CloseFunding.Environment) (re : RollupValue.Environment) (s : RollupValue.State) : Prop where
  chain : ce.chainId = re.chainId
  deployment : ce.rollupDeploymentChain = re.deploymentChainId
  caller : ce.self = re.caller
  installed : ce.installedMaterializer = s.materializer

theorem projected_escrow (s : RollupValue.State) (token : Nat) :
    (projectLedger s).escrow token = s.escrow (RollupValue.assetOfToken token) := rfl

theorem projected_pending (s : RollupValue.State) (token manager : Nat) :
    (projectLedger s).pending token manager = s.pending (RollupValue.assetOfToken token) manager := rfl

theorem rollup_credit_dispatch (re : RollupValue.Environment) (s : RollupValue.State)
    (manager token amount : Nat) :
    RollupValue.creditChannelExit re s manager token amount = (do
      RollupValue.releaseRuntime re
      RollupValue.require (re.caller == s.materializer) (.revert "InvalidChannelExitManager")
      RollupValue.creditEscrow s (RollupValue.assetOfToken token) manager amount) := by
  by_cases zero : token = 0 <;> simp [RollupValue.creditChannelExit, RollupValue.assetOfToken,
    RollupValue.creditNativeEscrow, RollupValue.creditTokenEscrow, zero]

theorem credit_call_projection (ce : CloseFunding.Environment) (re : RollupValue.Environment)
    (s : RollupValue.State) (manager : Nat) (c : CloseFunding.Credit) (h : CreditCallContext ce re s) :
    CloseFunding.creditChannelExit ce (projectLedger s) manager c =
      projectResult (RollupValue.creditChannelExit re s manager c.token c.amount) := by
  rcases h with ⟨hc, hd, hm, hi⟩
  rw [rollup_credit_dispatch]
  by_cases chain : re.chainId = re.deploymentChainId <;>
    by_cases caller : re.caller = s.materializer <;>
    by_cases enough : c.amount ≤ s.escrow (RollupValue.assetOfToken c.token) <;>
    by_cases fits : s.pending (RollupValue.assetOfToken c.token) manager + c.amount < RollupValue.u256Limit <;>
    simp [CloseFunding.creditChannelExit, RollupValue.releaseRuntime, RollupValue.creditEscrow,
      CloseFunding.require, RollupValue.require, projectResult, creditError,
      projected_escrow, projected_pending, credit_projection, hc, hd, hm, hi,
      chain, caller, enough, fits, show CloseFunding.u256Limit = RollupValue.u256Limit from rfl]

theorem materializer_credit_is_actual_rollup_credit (ce : CloseFunding.Environment) (re : RollupValue.Environment)
    (before after : RollupValue.State) (manager : Nat) (c : CloseFunding.Credit)
    (context : CreditCallContext ce re before)
    (call : RollupValue.creditChannelExit re before manager c.token c.amount = .ok after) :
    CloseFunding.creditChannelExit ce (projectLedger before) manager c = .ok (projectLedger after) := by
  rw [credit_call_projection ce re before manager c context, call]
  rfl

structure Accounts where
  rollup : RollupValue.State
  manager : ManagerValue.State

/-- Counter conservation, not an observed arbitrary-token balance. -/
def accounted (s : Accounts) (manager token : Nat) : Nat :=
  s.rollup.escrow (RollupValue.assetOfToken token) +
    s.rollup.pending (RollupValue.assetOfToken token) manager + s.manager.received token

def unspent (s : ManagerValue.State) (token : Nat) : Nat := s.received token - s.paid token

theorem accounted_splits_paid_and_unspent (s : Accounts) (manager token : Nat)
    (bounded : s.manager.paid token ≤ s.manager.received token) :
    accounted s manager token = s.rollup.escrow (RollupValue.assetOfToken token) +
      s.rollup.pending (RollupValue.assetOfToken token) manager + unspent s.manager token +
        s.manager.paid token := by
  simp only [accounted, unspent]
  rw [Nat.add_assoc _ (s.manager.received token - s.manager.paid token),
    Nat.sub_add_cancel bounded]

/-- Exact source `pullCore` success exposes its pre-counter bound, without
    assuming a successful callback already satisfies the desired conservation. -/
theorem manager_pull_has_room (cfg : ManagerValue.Config) (ext : ManagerValue.External) (s out : ManagerValue.State)
    (token : Nat) (h : ManagerValue.pullCore cfg ext s token = .ok out) :
    s.received token < s.cap token := by
  dsimp only [ManagerValue.pullCore] at h
  split at h <;> try contradiction
  cases er : ManagerValue.resolveToken ext token <;> simp only [er] at h <;> try contradiction
  split at h <;> try contradiction
  exact Nat.lt_of_not_ge (by assumption)

/-- Each constructor is tied to an actual modeled helper. Pull is deliberately
    conditional on dispatch/callback coupling, not an EVM refinement claim. -/
inductive AccountingStep (cfg : ManagerValue.Config) : Accounts → Accounts → Prop where
  | credit (re : RollupValue.Environment) (s : Accounts) (out : RollupValue.State) (token amount : Nat)
      (call : RollupValue.creditChannelExit re s.rollup cfg.manager token amount = .ok out) :
      AccountingStep cfg s ⟨out, s.manager⟩
  | pull (ext : ManagerValue.External) (s : Accounts) (out : ManagerValue.State) (token : Nat)
      (call : ManagerValue.pullCore cfg ext s.manager token = .ok out)
      (rollupCredit : s.manager.cap token - s.manager.received token ≤
        s.rollup.pending (RollupValue.assetOfToken token) cfg.manager) :
      AccountingStep cfg s
        ⟨RollupValue.pullState s.rollup (RollupValue.assetOfToken token) cfg.manager
          (s.manager.cap token - s.manager.received token), out⟩
  | payout (ext : ManagerValue.External) (s : Accounts) (out : ManagerValue.State) (sender nullifier : Nat)
      (call : ManagerValue.claimCreditCore ext s.manager sender nullifier = .ok out) :
      AccountingStep cfg s ⟨s.rollup, out⟩
  | submitClaim (ext : ManagerValue.External) (s : Accounts) (out : ManagerValue.State)
      (claim : ManagerValue.Claim) (proof : ManagerValue.Proof)
      (call : ManagerValue.submitClaimCore cfg ext s.manager claim proof = .ok out) :
      AccountingStep cfg s ⟨s.rollup, out⟩

theorem accounting_step_conserves (cfg : ManagerValue.Config) {before after : Accounts}
    (step : AccountingStep cfg before after) (token : Nat) :
    accounted after cfg.manager token = accounted before cfg.manager token := by
  cases step with
  | credit re _ out index amount call =>
    by_cases eqToken : token = index
    · subst token
      have eqs := RollupValue.successful_close_credit_conserves re before.rollup out cfg.manager index amount call
      dsimp only [accounted]
      omega
    · have different : RollupValue.assetOfToken token ≠ RollupValue.assetOfToken index := by
        intro eqAsset
        exact eqToken ((asset_dispatch_injective token index).mp eqAsset)
      have frame := RollupValue.successful_close_credit_frames_other_asset re before.rollup out
        cfg.manager index amount (RollupValue.assetOfToken token) different call
      simp only [accounted, frame.1, frame.2]
  | pull ext _ out index call enough =>
    obtain ⟨received, _⟩ := ManagerValue.pull_success_exact_cap cfg ext before.manager out index call
    have room := manager_pull_has_room cfg ext before.manager out index call
    by_cases eqToken : token = index
    · subst token
      simp only [accounted, RollupValue.pullState, RollupValue.put, received, ManagerValue.put, ite_true]
      have budget := Nat.sub_add_cancel enough
      have delta := Nat.sub_add_cancel (Nat.le_of_lt room)
      omega
    · have different : RollupValue.assetOfToken token ≠ RollupValue.assetOfToken index := by
        intro eqAsset
        exact eqToken ((asset_dispatch_injective token index).mp eqAsset)
      simp [accounted, RollupValue.pullState, RollupValue.put, received, ManagerValue.put, eqToken, different]
  | payout ext _ out sender nullifier call =>
    obtain ⟨effects, _, _⟩ := ManagerValue.payout_success_exact_effects ext before.manager out sender nullifier call
    simp [accounted, effects, ManagerValue.payoutEffects]
  | submitClaim ext _ out claim proof call =>
    have effects := ManagerValue.submit_success_effects cfg ext before.manager out claim proof call
    simp [accounted, effects, ManagerValue.claimEffects]

inductive AccountingTrace (cfg : ManagerValue.Config) : Accounts → Accounts → Prop where
  | refl (s : Accounts) : AccountingTrace cfg s s
  | next {s middle last : Accounts} (prior : AccountingTrace cfg s middle)
      (step : AccountingStep cfg middle last) : AccountingTrace cfg s last

theorem every_accounting_trace_conserves (cfg : ManagerValue.Config) {before after : Accounts}
    (trace : AccountingTrace cfg before after) (token : Nat) :
    accounted after cfg.manager token = accounted before cfg.manager token := by
  induction trace with
  | refl => rfl
  | next _ step ih => exact (accounting_step_conserves cfg step token).trans ih

def PaidBounded (s : ManagerValue.State) : Prop := ∀ token, s.paid token ≤ s.received token

theorem accounting_step_preserves_paid_bound (cfg : ManagerValue.Config) {before after : Accounts}
    (step : AccountingStep cfg before after) (bounded : PaidBounded before.manager) :
    PaidBounded after.manager := by
  intro token
  cases step with
  | credit => exact bounded token
  | pull ext _ out index call _ =>
    obtain ⟨received, paid⟩ := ManagerValue.pull_success_exact_cap cfg ext before.manager out index call
    have room := manager_pull_has_room cfg ext before.manager out index call
    by_cases same : token = index
    · subst token
      simpa only [received, paid, ManagerValue.put, ite_true] using
        Nat.le_trans (bounded index) (Nat.le_of_lt room)
    · simpa only [received, paid, ManagerValue.put, if_neg same] using bounded token
  | payout ext _ out sender nullifier call =>
    obtain ⟨effects, _, cap⟩ := ManagerValue.payout_success_exact_effects ext before.manager out sender nullifier call
    by_cases same : token = (before.manager.payouts nullifier).token
    · subst token
      simpa only [effects, ManagerValue.payoutEffects, ManagerValue.put, ite_true] using cap
    · simpa only [effects, ManagerValue.payoutEffects, ManagerValue.put, if_neg same] using bounded token
  | submitClaim ext _ out claim proof call =>
    have effects := ManagerValue.submit_success_effects cfg ext before.manager out claim proof call
    simpa only [effects, ManagerValue.claimEffects] using bounded token

theorem every_accounting_trace_preserves_paid_bound (cfg : ManagerValue.Config) {before after : Accounts}
    (trace : AccountingTrace cfg before after) (bounded : PaidBounded before.manager) :
    PaidBounded after.manager := by
  induction trace with
  | refl => exact bounded
  | next _ step ih => exact accounting_step_preserves_paid_bound cfg step ih

theorem every_accounting_trace_splits_paid_and_unspent (cfg : ManagerValue.Config)
    {before after : Accounts} (trace : AccountingTrace cfg before after)
    (bounded : PaidBounded before.manager) (token : Nat) :
    after.rollup.escrow (RollupValue.assetOfToken token) +
      after.rollup.pending (RollupValue.assetOfToken token) cfg.manager +
      unspent after.manager token + after.manager.paid token = accounted before cfg.manager token := by
  rw [← accounted_splits_paid_and_unspent after cfg.manager token
    (every_accounting_trace_preserves_paid_bound cfg trace bounded token)]
  exact every_accounting_trace_conserves cfg trace token

theorem manager_pull_exact_state (cfg : ManagerValue.Config) (ext : ManagerValue.External)
    (s out : ManagerValue.State) (token : Nat)
    (call : ManagerValue.pullCore cfg ext s token = .ok out) :
    out = { s with received := ManagerValue.put s.received token (s.cap token) } := by
  dsimp only [ManagerValue.pullCore] at call
  split at call <;> try contradiction
  cases er : ManagerValue.resolveToken ext token <;> simp only [er] at call <;> try contradiction
  rename_i asset
  split at call <;> try contradiction
  cases em : ext.materialized cfg.materializer cfg.channel <;> simp only [em] at call <;> try contradiction
  split at call <;> try contradiction
  cases eb : ext.balance .before s token asset cfg.manager <;> simp only [eb] at call <;> try contradiction
  cases ep : ext.pull s token (s.cap token - s.received token) <;> simp only [ep] at call <;> try contradiction
  cases ea : ext.balance .after s token asset cfg.manager <;> simp only [ea] at call <;> try contradiction
  split at call <;> try contradiction
  split at call <;> try contradiction
  exact (Except.ok.inj call).symm

theorem submitted_claim_nullifier_was_unused (cfg : ManagerValue.Config) (ext : ManagerValue.External)
    (s out : ManagerValue.State) (claim : ManagerValue.Claim) (proof : ManagerValue.Proof)
    (call : ManagerValue.submitClaimCore cfg ext s claim proof = .ok out) :
    s.used claim.nullifier = false := by
  dsimp only [ManagerValue.submitClaimCore] at call
  split at call <;> try contradiction
  split at call <;> try contradiction
  split at call <;> try contradiction
  split at call <;> try contradiction
  split at call <;> try contradiction
  split at call <;> try contradiction
  simp_all

/-- A live payout record must have a permanent used-nullifier marker. -/
def PayoutIndexed (s : ManagerValue.State) : Prop :=
  ∀ nullifier, (s.payouts nullifier).amount ≠ 0 → s.used nullifier = true

theorem successful_claim_does_not_overwrite_a_live_payout (cfg : ManagerValue.Config)
    (ext : ManagerValue.External) (s out : ManagerValue.State) (claim : ManagerValue.Claim)
    (proof : ManagerValue.Proof) (indexed : PayoutIndexed s)
    (call : ManagerValue.submitClaimCore cfg ext s claim proof = .ok out) :
    (s.payouts claim.nullifier).amount = 0 := by
  have unused := submitted_claim_nullifier_was_unused cfg ext s out claim proof call
  by_cases live : (s.payouts claim.nullifier).amount = 0
  · exact live
  · have used := indexed claim.nullifier live
    simp [unused] at used

theorem accounting_step_preserves_nullifier_and_payout_index (cfg : ManagerValue.Config)
    {before after : Accounts} (step : AccountingStep cfg before after)
    (indexed : PayoutIndexed before.manager) :
    PayoutIndexed after.manager ∧
      (∀ n, before.manager.used n = true → after.manager.used n = true) := by
  cases step with
  | credit => exact ⟨indexed, fun _ h => h⟩
  | pull ext _ out token call _ =>
    have effects := manager_pull_exact_state cfg ext before.manager out token call
    simpa only [effects, PayoutIndexed] using And.intro indexed (fun _ h => h)
  | payout ext _ out sender nullifier call =>
    obtain ⟨effects, _, _⟩ := ManagerValue.payout_success_exact_effects ext before.manager out sender nullifier call
    constructor
    · intro n live
      by_cases same : n = nullifier
      · simp [effects, ManagerValue.payoutEffects, ManagerValue.put, same, ManagerValue.emptyPayout] at live
      · simp only [effects, ManagerValue.payoutEffects, ManagerValue.put, if_neg same] at live ⊢
        exact indexed n live
    · intro n used
      simpa only [effects, ManagerValue.payoutEffects] using used
  | submitClaim ext _ out claim proof call =>
    have effects := ManagerValue.submit_success_effects cfg ext before.manager out claim proof call
    constructor
    · intro n live
      by_cases same : n = claim.nullifier
      · simp [effects, ManagerValue.claimEffects, ManagerValue.put, same]
      · simp only [effects, ManagerValue.claimEffects, ManagerValue.put, if_neg same] at live ⊢
        exact indexed n live
    · intro n used
      by_cases same : n = claim.nullifier <;>
        simp [effects, ManagerValue.claimEffects, ManagerValue.put, same, used]

theorem every_accounting_trace_preserves_nullifier_and_payout_index (cfg : ManagerValue.Config)
    {before after : Accounts} (trace : AccountingTrace cfg before after)
    (indexed : PayoutIndexed before.manager) :
    PayoutIndexed after.manager ∧
      (∀ n, before.manager.used n = true → after.manager.used n = true) := by
  induction trace with
  | refl => exact ⟨indexed, fun _ h => h⟩
  | next _ step ih =>
    obtain ⟨previousIndex, previousUsed⟩ := ih
    obtain ⟨nextIndex, nextUsed⟩ := accounting_step_preserves_nullifier_and_payout_index cfg step previousIndex
    exact ⟨nextIndex, fun n used => nextUsed n (previousUsed n used)⟩

/-- Per-call storage framing is a separate environment obligation. It does not
    assert ownership, validity of proofs, or that money was actually received. -/
def NativePullCallbackFrame (e : RollupValue.Environment) : Prop :=
  ∀ state amount after, e.sendNative state e.caller amount = .ok after →
    after.pending = state.pending ∧ after.escrow = state.escrow

theorem native_pull_body_debits_actual_rollup_credit (e : RollupValue.Environment)
    (s after : RollupValue.State) (amount : Nat) (events : List RollupValue.Event)
    (frame : NativePullCallbackFrame e)
    (call : RollupValue.withdrawBody e s amount = .ok (after, events)) :
    amount ≠ 0 ∧ amount ≤ s.pending .native e.caller ∧
      after.pending = (RollupValue.pullState s .native e.caller amount).pending ∧
      after.escrow = s.escrow := by
  simp only [RollupValue.withdrawBody, RollupValue.require] at call
  split at call <;> simp only [RollupValue.result_bind_ok, RollupValue.result_bind_error] at call
  · rename_i guard
    have guarded : amount ≠ 0 ∧ amount ≤ s.pending .native e.caller := by simpa using guard
    cases external : e.sendNative (RollupValue.pullState s .native e.caller amount) e.caller amount with
    | error err => simp [external, Except.mapError] at call
    | ok callback =>
      simp [external, Except.mapError] at call
      rcases call with ⟨equal, _⟩
      cases equal
      obtain ⟨pending, escrow⟩ := frame _ _ _ external
      exact ⟨guarded.1, guarded.2, pending, escrow⟩

theorem native_pull_call_debits_actual_rollup_credit (e : RollupValue.Environment)
    (s after : RollupValue.State) (amount : Nat) (events : List RollupValue.Event)
    (frame : NativePullCallbackFrame e)
    (call : RollupValue.withdraw e s amount = .ok (after, events)) :
    amount ≠ 0 ∧ amount ≤ s.pending .native e.caller ∧
      after.pending = (RollupValue.pullState s .native e.caller amount).pending ∧
      after.escrow = s.escrow := by
  unfold RollupValue.withdraw RollupValue.releaseRuntime RollupValue.guarded at call
  simp only [RollupValue.require] at call
  split at call <;> simp only [RollupValue.result_bind_ok, RollupValue.result_bind_error] at call
  · cases lock : RollupValue.nonReentrantBefore s with
    | error err => simp [lock] at call
    | ok locked =>
      cases body : RollupValue.withdrawBody e locked amount with
      | error err => simp [lock, body] at call
      | ok result =>
        rcases result with ⟨out, logs⟩
        have effects := native_pull_body_debits_actual_rollup_credit e locked out amount logs frame body
        simp [lock, body] at call
        rcases call with ⟨equal, _⟩
        cases equal
        unfold RollupValue.nonReentrantBefore at lock
        split at lock <;> try contradiction
        cases lock
        exact effects

/-- Nonempty positive trace through the SAME credit/pull/claim/payout definitions.
    This is a model witness, not a proof that a deployment's verifier or token
    callbacks have the required semantics. Unused environment fields stay free. -/
def normalRollup (base : RollupValue.Environment) : RollupValue.Environment :=
  { base with caller := 60, chainId := 31337, deploymentChainId := 31337 }

def normalBefore : Accounts :=
  { rollup := { RollupValue.empty with
      materializer := 60
      escrow := fun a => if a = .native then 100 else 0 }
    manager := { ManagerValue.sampleState with received := fun _ => 0 } }

def normalCredited : Accounts :=
  ⟨RollupValue.creditState normalBefore.rollup .native 42 100, normalBefore.manager⟩

def normalPulled : Accounts :=
  ⟨RollupValue.pullState normalCredited.rollup .native 42 100,
    { normalBefore.manager with received := ManagerValue.put normalBefore.manager.received 0 100 }⟩

def normalClaimed : Accounts :=
  ⟨normalPulled.rollup, ManagerValue.claimEffects normalPulled.manager ManagerValue.sampleClaim⟩

def normalPaid : Accounts :=
  ⟨normalClaimed.rollup, ManagerValue.payoutEffects normalClaimed.manager 91⟩

theorem normal_credit_pull_claim_payout_trace (base : RollupValue.Environment) :
    AccountingTrace ManagerValue.sampleConfig normalBefore normalPaid := by
  have credited : AccountingStep ManagerValue.sampleConfig normalBefore normalCredited := by
    apply AccountingStep.credit (normalRollup base) normalBefore normalCredited.rollup 0 100
    apply (RollupValue.successful_close_credit_characterization _ _ _ _ _ _).mpr
    refine ⟨rfl, rfl, ?_⟩
    apply (RollupValue.successful_credit_characterization _ _ _ _ _).mpr
    exact ⟨by decide, by decide, rfl⟩
  have pulled : AccountingStep ManagerValue.sampleConfig normalCredited normalPulled := by
    apply AccountingStep.pull ManagerValue.sampleExternal normalCredited normalPulled.manager 0
    · rfl
    · decide
  have claimed : AccountingStep ManagerValue.sampleConfig normalPulled normalClaimed :=
    AccountingStep.submitClaim ManagerValue.sampleExternal _ _ ManagerValue.sampleClaim [] (by rfl)
  have paid : AccountingStep ManagerValue.sampleConfig normalClaimed normalPaid :=
    AccountingStep.payout ManagerValue.sampleExternal _ _ 23 91 (by rfl)
  exact .next (.next (.next (.next (.refl normalBefore) credited) pulled) claimed) paid

theorem normal_trace_pays_five_and_retains_ninety_five :
    normalPaid.manager.paid 0 = 5 ∧ unspent normalPaid.manager 0 = 95 ∧
      normalPaid.rollup.escrow .native = 0 ∧ normalPaid.rollup.pending .native 42 = 0 ∧
      normalPaid.manager.used 91 = true ∧ (normalPaid.manager.payouts 91).amount = 0 := by decide

end Zkp.Implementation.FundFlow
