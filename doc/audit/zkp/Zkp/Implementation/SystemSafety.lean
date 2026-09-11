import Zkp.Implementation.TrustBoundary

/-!
# System-level fund safety of the composed implementation models

This module is a COMPOSITION of the handwritten models in this directory under
the named premises of `Zkp.Implementation.TrustBoundary`. It is NOT an
end-to-end cryptographic proof, NOT a refinement of the Rust/plonky2 prover, the
Solidity sources or the EVM, and NOT a claim that a deployment is safe. Every
model it composes is itself a manual reading of source text.

The combined state pairs the Rollup value ledger (`RollupValue.State`), a
per-manager Settlement Manager value state (`ManagerValue.State`) and the
materializer's storage (`CloseFunding.State`). `Step` ranges over the modeled
money and authorization entrypoints, reusing `FundFlow.AccountingStep` for the
four transitions it already covers (materializer/Rollup channel-exit credit,
Manager pull, `submitClaim`, `claimCredit` payout — `FundFlow.credit_call_projection`
already identifies the materializer's expanded call with the Rollup dispatch) and
reusing `FundFlow.NativePullCallbackFrame` as the native call-frame condition.
No accounting is re-derived here that `RollupValue`, `ManagerValue`,
`CloseFunding` or `FundFlow` already proves.

Each `Step` carries the per-token inflow and outflow it is responsible for, so
the conservation theorem is an exact identity rather than a conditional slogan:
value only enters through a Rollup deposit and only leaves through a proof-backed
withdrawal set, a direct pending pull, or another Manager's materialization
draining the POOLED escrow. That last case is the reason a single-manager
`accounted` total is not conserved in general, and it is visible in the theorem
rather than hidden by a hypothesis.

Explicitly NOT proved here: that an accepted proof means anything (premise a0
together with the three statement-lowering premises a, b1, b2 — the acceptance
step and the lowering step are separate named premises, and
`TrustBoundary.closeProofSoundness`, `.withdrawalProofSoundness` and
`.postCloseProofSoundness` are exactly their composition, still borrowed and
still not proved), that a finalized close vector is backed by the channel's own deposits
(premise c), that a passing aggregate check means signatures exist (premise d),
that hashes bind (premises e1, e2), that the finality getters observe the
canonical L1 head (premises f1, f2), that storage survives unmodeled entrypoints
(premises g1, g2), or that any deployed artifact behaves like these definitions
(premise h). Liveness, censorship, gas, ordering and ERC20 token honesty are not
represented at all.

Premise (a0) — the operator's explicit decision to ACCEPT the pinned MLE/WHIR
submodule as trusted rather than translate it — is likewise borrowed, not proved.
The last section of this module measures it: `mle_assumption_does_not_imply_fund_safety`
and `mle_assumption_alone_does_not_yield_close_gate_soundness` exhibit
environments in which (a0) holds and the conclusion of interest fails anyway, so
the acceptance cannot be read as closing this audit.
-/

namespace Zkp.Implementation.SystemSafety

/-! ## Generic success peeling -/

/-- Success of a bound computation exposes the intermediate success. -/
theorem bind_success {ε α β : Type} {x : Except ε α} {f : α → Except ε β} {y : β}
    (h : (x >>= f) = .ok y) : ∃ z, x = .ok z ∧ f z = .ok y := by
  cases x with
  | error err => exact absurd h (by simp [Bind.bind, Except.bind])
  | ok z => exact ⟨z, rfl, h⟩

theorem rollup_require_ok {c : Bool} {err : RollupValue.Error} {u : Unit}
    (h : RollupValue.require c err = .ok u) : c = true := by
  cases c
  · exact absurd h (by simp [RollupValue.require])
  · rfl

/-! ## Combined state -/

/-- Rollup value ledger, one Manager value state per Manager address, and the
materializer storage. Non-monetary Rollup chain state travels inside
`RollupValue.State.chain`; nothing here duplicates it. -/
structure State where
  rollup : RollupValue.State
  managers : Nat → ManagerValue.State
  funding : CloseFunding.State

/-- The Manager projection used by the `TrustBoundary` durability premises. -/
def managerOf (cfg : ManagerValue.Config) (s : State) : ManagerValue.State := s.managers cfg.manager

/-- The materializer projection used by the `TrustBoundary` durability premises. -/
def fundingOf (s : State) : CloseFunding.State := s.funding

/-- The `FundFlow.Accounts` view of one Manager inside the combined state. -/
def accountsOf (cfg : ManagerValue.Config) (s : State) : FundFlow.Accounts :=
  ⟨s.rollup, s.managers cfg.manager⟩

/-- `FundFlow.accounted` for one Manager: pooled escrow, that Manager's Rollup
pending credit, and what it has already received. A counter total, not an
observed ERC20 balance. -/
def measure (cfg : ManagerValue.Config) (s : State) (token : Nat) : Nat :=
  FundFlow.accounted (accountsOf cfg s) cfg.manager token

/-- Per-token quantity attached to a step. -/
abbrev Flow := Nat → Nat

def zeroFlow : Flow := fun _ => 0

def addFlow (a b : Flow) : Flow := fun t => a t + b t

/-- Thin selector over the two source proof-backed withdrawal endpoints. It adds
no semantics: see `withdrawal_set_is_source_endpoints`. -/
def withdrawalSet (native : Bool) (e : RollupValue.Environment) (s : RollupValue.State)
    (ws : List RollupValue.Withdrawal) (prover : Nat) (proof : RollupValue.Bytes) :
    RollupValue.Result (RollupValue.State × List RollupValue.Event) :=
  if native then RollupValue.withdrawNative e s ws prover proof
  else RollupValue.withdrawERC20 e s ws prover proof

theorem withdrawal_set_is_source_endpoints (e : RollupValue.Environment) (s : RollupValue.State)
    (ws : List RollupValue.Withdrawal) (prover : Nat) (proof : RollupValue.Bytes) :
    withdrawalSet true e s ws prover proof = RollupValue.withdrawNative e s ws prover proof ∧
    withdrawalSet false e s ws prover proof = RollupValue.withdrawERC20 e s ws prover proof :=
  ⟨rfl, rfl⟩

/-- ERC20 analogue of `FundFlow.NativePullCallbackFrame`: an explicit call-frame
obligation on the token callback, NOT a claim that ERC20 contracts are honest. -/
def TokenCallFrame (e : RollupValue.Environment) : Prop :=
  ∀ s call out, e.tokenCall s call = .ok out → out.escrow = s.escrow ∧ out.pending = s.pending

/-! ## Reusable shapes of the Rollup entrypoints -/

theorem guarded_ok_shape {s after : RollupValue.State}
    {body : RollupValue.State → RollupValue.Result (RollupValue.State × List RollupValue.Event)}
    {events : List RollupValue.Event}
    (h : RollupValue.guarded s body = .ok (after, events)) :
    ∃ mid, body { s with status := 2 } = .ok (mid, events) ∧
      after.escrow = mid.escrow ∧ after.pending = mid.pending := by
  simp only [RollupValue.guarded] at h
  obtain ⟨locked, hlock, h⟩ := bind_success h
  have lockedEq : locked = { s with status := 2 } := by
    simp only [RollupValue.nonReentrantBefore] at hlock
    split at hlock
    · exact absurd hlock (by simp)
    · exact (Except.ok.inj hlock).symm
  subst lockedEq
  obtain ⟨pair, hbody, h⟩ := bind_success h
  obtain ⟨mid, logs⟩ := pair
  have hpair : (RollupValue.nonReentrantAfter mid, logs) = (after, events) := Except.ok.inj h
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj hpair
  exact ⟨mid, hbody, rfl, rfl⟩

theorem release_then_guarded {e : RollupValue.Environment} {s after : RollupValue.State}
    {body : RollupValue.State → RollupValue.Result (RollupValue.State × List RollupValue.Event)}
    {events : List RollupValue.Event}
    (h : (do RollupValue.releaseRuntime e; RollupValue.guarded s body) = .ok (after, events)) :
    ∃ mid, body { s with status := 2 } = .ok (mid, events) ∧
      after.escrow = mid.escrow ∧ after.pending = mid.pending := by
  obtain ⟨_, _, h⟩ := bind_success h
  exact guarded_ok_shape h

theorem finish_deposit_frames_ledger {e : RollupValue.Environment} {s after : RollupValue.State}
    {d : RollupValue.DepositRecord} {events : List RollupValue.Event}
    (h : RollupValue.finishDeposit e s d = .ok (after, events)) :
    after.escrow = s.escrow ∧ after.pending = s.pending := by
  simp only [RollupValue.finishDeposit] at h
  obtain ⟨_, _, h⟩ := bind_success h
  have hpair := Except.ok.inj h
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj hpair
  exact ⟨rfl, rfl⟩

theorem deposit_escrow_state_effect (t : RollupValue.State) (asset : RollupValue.Asset)
    (amount : Nat) :
    (RollupValue.depositEscrowState t asset amount).escrow asset = t.escrow asset + amount ∧
      (∀ a, a ≠ asset → (RollupValue.depositEscrowState t asset amount).escrow a = t.escrow a) ∧
      (RollupValue.depositEscrowState t asset amount).pending = t.pending := by
  refine ⟨by simp [RollupValue.depositEscrowState, RollupValue.put], ?_, rfl⟩
  intro a different
  simp [RollupValue.depositEscrowState, RollupValue.put, different]

theorem asset_of_zero : RollupValue.assetOfToken 0 = RollupValue.Asset.native := rfl

/-- Exact ledger effect of a successful deposit on both source branches. The
ERC20 branch is conditional on the explicit token call-frame obligation, which is
not a claim about real ERC20 contracts. -/
theorem deposit_accounts {e : RollupValue.Environment} {s after : RollupValue.State}
    {recipient index amount aux : Nat} {events : List RollupValue.Event}
    (frame : TokenCallFrame e)
    (h : RollupValue.deposit e s recipient index amount aux = .ok (after, events)) :
    after.escrow (RollupValue.assetOfToken index) =
        s.escrow (RollupValue.assetOfToken index) + amount ∧
      (∀ a, a ≠ RollupValue.assetOfToken index → after.escrow a = s.escrow a) ∧
      after.pending = s.pending := by
  simp only [RollupValue.deposit] at h
  obtain ⟨mid, hbody, hescrow, hpending⟩ := release_then_guarded h
  simp only [RollupValue.depositBody] at hbody
  have midEffect : mid.escrow (RollupValue.assetOfToken index) =
      s.escrow (RollupValue.assetOfToken index) + amount ∧
      (∀ a, a ≠ RollupValue.assetOfToken index → mid.escrow a = s.escrow a) ∧
      mid.pending = s.pending := by
    split at hbody
    · rename_i zero
      subst zero
      obtain ⟨_, _, hbody⟩ := bind_success hbody
      obtain ⟨_, _, hbody⟩ := bind_success hbody
      obtain ⟨pre, hpre, hfin⟩ := bind_success hbody
      have preEq : RollupValue.depositEscrowState { s with status := 2 } .native amount = pre :=
        Except.ok.inj hpre
      subst preEq
      obtain ⟨fescrow, fpending⟩ := finish_deposit_frames_ledger hfin
      obtain ⟨exactHit, exactMiss, exactPending⟩ :=
        deposit_escrow_state_effect { s with status := 2 } .native amount
      refine ⟨?_, ?_, ?_⟩
      · rw [asset_of_zero, fescrow, exactHit]
      · intro a different
        rw [asset_of_zero] at different
        rw [fescrow]
        exact exactMiss a different
      · rw [fpending, exactPending]
    · rename_i nonzero
      obtain ⟨_, _, hbody⟩ := bind_success hbody
      obtain ⟨_, _, hbody⟩ := bind_success hbody
      obtain ⟨_, _, hbody⟩ := bind_success hbody
      obtain ⟨callback, hcall, hbody⟩ := bind_success hbody
      obtain ⟨frameEscrow, framePending⟩ := frame _ _ _ hcall
      obtain ⟨_, _, hbody⟩ := bind_success hbody
      obtain ⟨_, _, hbody⟩ := bind_success hbody
      obtain ⟨_, _, hbody⟩ := bind_success hbody
      obtain ⟨_, _, hbody⟩ := bind_success hbody
      obtain ⟨pre, hpre, hfin⟩ := bind_success hbody
      have preEq : RollupValue.depositEscrowState callback (.erc20 index) amount = pre :=
        Except.ok.inj hpre
      subst preEq
      obtain ⟨fescrow, fpending⟩ := finish_deposit_frames_ledger hfin
      obtain ⟨exactHit, exactMiss, exactPending⟩ :=
        deposit_escrow_state_effect callback (.erc20 index) amount
      have asset : RollupValue.assetOfToken index = RollupValue.Asset.erc20 index := by
        simp [RollupValue.assetOfToken, nonzero]
      refine ⟨?_, ?_, ?_⟩
      · rw [asset, fescrow, exactHit, frameEscrow]
      · intro a different
        rw [asset] at different
        rw [fescrow, exactMiss a different, frameEscrow]
      · rw [fpending, exactPending, framePending]
  refine ⟨?_, ?_, ?_⟩
  · rw [hescrow, midEffect.1]
  · intro a different
    rw [hescrow]
    exact midEffect.2.1 a different
  · rw [hpending, midEffect.2.2]

/-- Exact per-asset accounting of a proof-backed withdrawal set, reusing the
Rollup loop theorem. The verifier stage is peeled but its soundness is NOT used;
only the ledger writes matter here. -/
theorem withdrawal_set_accounts {e : RollupValue.Environment} {native : Bool}
    {s after : RollupValue.State} {ws : List RollupValue.Withdrawal} {prover : Nat}
    {proof : RollupValue.Bytes} {events : List RollupValue.Event}
    (h : withdrawalSet native e s ws prover proof = .ok (after, events))
    (asset : RollupValue.Asset) (recipient : Nat) :
    after.escrow asset + RollupValue.setAmount native asset ws = s.escrow asset ∧
    after.pending asset recipient = s.pending asset recipient +
      RollupValue.setCredit native asset recipient ws := by
  have guardedCall : RollupValue.guarded s (fun locked => do
      let block ← RollupValue.verifyWithdrawalSet e locked ws prover proof
      RollupValue.withdrawLeaves e native block locked ws) = .ok (after, events) := by
    cases native <;> simpa [withdrawalSet, RollupValue.withdrawNative,
      RollupValue.withdrawERC20] using h
  obtain ⟨mid, hbody, hescrow, hpending⟩ := guarded_ok_shape guardedCall
  obtain ⟨block, _, hloop⟩ := bind_success hbody
  have accounting := RollupValue.withdrawal_loop_conserves_each_token e native block
    { s with status := 2 } mid ws events asset recipient hloop
  rw [hescrow, hpending]
  exact accounting

/-- Exact ledger effect of the direct ERC20 pending pull, under the token
call-frame obligation. -/
theorem token_pull_debits_actual_rollup_credit {e : RollupValue.Environment}
    {s after : RollupValue.State} {index amount : Nat} {events : List RollupValue.Event}
    (frame : TokenCallFrame e)
    (h : RollupValue.withdrawToken e s index amount = .ok (after, events)) :
    after.escrow = s.escrow ∧
      after.pending = (RollupValue.pullState s (.erc20 index) e.caller amount).pending := by
  simp only [RollupValue.withdrawToken] at h
  obtain ⟨mid, hbody, hescrow, hpending⟩ := release_then_guarded h
  simp only [RollupValue.withdrawTokenBody] at hbody
  obtain ⟨_, _, hbody⟩ := bind_success hbody
  obtain ⟨_, _, hbody⟩ := bind_success hbody
  obtain ⟨_, _, hbody⟩ := bind_success hbody
  obtain ⟨callback, hcall, hbody⟩ := bind_success hbody
  obtain ⟨frameEscrow, framePending⟩ := frame _ _ _ hcall
  obtain ⟨_, _, hbody⟩ := bind_success hbody
  obtain ⟨_, _, hbody⟩ := bind_success hbody
  obtain ⟨_, _, hbody⟩ := bind_success hbody
  have midEq : (callback, [RollupValue.Event.tokenWithdrawalClaimed e.caller index amount]) =
      (mid, events) := Except.ok.inj hbody
  obtain ⟨rfl, _⟩ := Prod.mk.inj midEq
  refine ⟨?_, ?_⟩
  · rw [hescrow, frameEscrow]
    rfl
  · rw [hpending, framePending]
    rfl

/-! ## Reusable shapes of the materializer and Manager entrypoints -/

theorem funding_credit_success_is_exact {e : CloseFunding.Environment}
    {l after : CloseFunding.Ledger} {manager : Nat} {c : CloseFunding.Credit}
    (h : CloseFunding.creditChannelExit e l manager c = .ok after) :
    after = CloseFunding.creditState l manager c := by
  simp only [CloseFunding.creditChannelExit] at h
  obtain ⟨_, _, h⟩ := bind_success h
  obtain ⟨_, _, h⟩ := bind_success h
  obtain ⟨_, _, h⟩ := bind_success h
  obtain ⟨_, _, h⟩ := bind_success h
  exact (Except.ok.inj h).symm

/-- Another Manager's materialization cannot move this Manager's pending credit;
only the pooled escrow is shared. -/
theorem funding_vector_frames_other_manager {e : CloseFunding.Environment}
    {before after : CloseFunding.Ledger} {manager other : Nat} {cs : List CloseFunding.Credit}
    (different : other ≠ manager)
    (h : CloseFunding.creditVector e manager before cs = .ok after) (token : Nat) :
    after.pending token other = before.pending token other := by
  induction cs generalizing before with
  | nil =>
    simp only [CloseFunding.creditVector] at h
    rw [← Except.ok.inj h]
  | cons c cs ih =>
    simp only [CloseFunding.creditVector] at h
    split at h
    · exact ih h
    · obtain ⟨middle, hstep, h⟩ := bind_success h
      rw [ih h, funding_credit_success_is_exact hstep]
      by_cases sameToken : token = c.token
      · subst sameToken
        exact CloseFunding.credit_other_manager_framed before manager other c different
      · exact congrFun (CloseFunding.credit_other_token_framed before manager c token
          sameToken).2 other

theorem materialize_call_shape {e : CloseFunding.Environment} {before after : CloseFunding.World}
    {manager : Nat} {proof : CloseFunding.Bytes} {events : List CloseFunding.Event}
    (h : CloseFunding.materializeSignedHead e before manager proof = .ok (after, events)) :
    ∃ p, CloseFunding.prepareSignedHead e before.storage manager proof = .ok p ∧
      after.storage = CloseFunding.latchState before.storage p ∧
      CloseFunding.creditVector e manager before.ledger p.credits = .ok after.ledger := by
  simp only [CloseFunding.materializeSignedHead] at h
  obtain ⟨p, hplan, h⟩ := bind_success h
  obtain ⟨ledger, hcredit, h⟩ := bind_success h
  have hpair := Except.ok.inj h
  obtain ⟨rfl, _⟩ := Prod.mk.inj hpair
  exact ⟨p, hplan, rfl, hcredit⟩

theorem request_close_frames_value {cfg : ManagerValue.Config} {ext : ManagerValue.External}
    {now : Nat} {s out : ManagerValue.State}
    (call : ManagerValue.requestCloseCore cfg ext now s = .ok out) :
    out.received = s.received ∧ out.paid = s.paid ∧ out.cap = s.cap ∧ out.used = s.used ∧
      out.payouts = s.payouts := by
  simp only [ManagerValue.requestCloseCore] at call
  split at call
  · exact absurd call (by simp)
  · split at call
    · exact absurd call (by simp)
    · split at call
      · exact absurd call (by simp)
      · split at call
        · exact absurd call (by simp)
        · split at call
          · exact absurd call (by simp)
          · rw [← Except.ok.inj call]
            exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-! ## The modeled step relation -/

/-- One transition of a modeled money or authorization entrypoint, carrying the
per-token value it lets in and the per-token value it lets out. Constructors that
carry `zeroFlow` on both sides are exactly the value-neutral ones. -/
inductive Step (cfg : ManagerValue.Config) : State → State → Flow → Flow → Prop where
  /-- The four transitions `FundFlow.AccountingStep` already models: the Rollup
  channel-exit credit (the materializer's expanded call, by
  `FundFlow.credit_call_projection`), the Manager pull, `submitClaim` and the
  `claimCredit` payout. -/
  | accounting (s : State) (out : FundFlow.Accounts)
      (step : FundFlow.AccountingStep cfg (accountsOf cfg s) out) :
      Step cfg s { s with rollup := out.rollup,
                          managers := ManagerValue.put s.managers cfg.manager out.manager }
        zeroFlow zeroFlow
  /-- `IntmaxRollup.deposit`: the only modeled way value enters. -/
  | deposit (e : RollupValue.Environment) (s : State) (out : RollupValue.State)
      (recipient index amount aux : Nat) (events : List RollupValue.Event)
      (frame : TokenCallFrame e)
      (call : RollupValue.deposit e s.rollup recipient index amount aux = .ok (out, events)) :
      Step cfg s { s with rollup := out } (fun t => if t = index then amount else 0) zeroFlow
  /-- `withdrawNative` / `withdrawERC20`: escrow leaves, some of it as this
  Manager's pending credit. -/
  | withdrawalSet (e : RollupValue.Environment) (native : Bool) (s : State)
      (out : RollupValue.State) (ws : List RollupValue.Withdrawal) (prover : Nat)
      (proof : RollupValue.Bytes) (events : List RollupValue.Event)
      (call : withdrawalSet native e s.rollup ws prover proof = .ok (out, events)) :
      Step cfg s { s with rollup := out }
        (fun t => RollupValue.setCredit native (RollupValue.assetOfToken t) cfg.manager ws)
        (fun t => RollupValue.setAmount native (RollupValue.assetOfToken t) ws)
  /-- Direct native pending pull, under `FundFlow.NativePullCallbackFrame`. -/
  | userWithdrawNative (e : RollupValue.Environment) (s : State) (out : RollupValue.State)
      (amount : Nat) (events : List RollupValue.Event)
      (frame : FundFlow.NativePullCallbackFrame e)
      (call : RollupValue.withdraw e s.rollup amount = .ok (out, events)) :
      Step cfg s { s with rollup := out } zeroFlow
        (fun t => if RollupValue.assetOfToken t = RollupValue.Asset.native ∧ e.caller = cfg.manager
          then amount else 0)
  /-- Direct ERC20 pending pull, under `TokenCallFrame`. -/
  | userWithdrawToken (e : RollupValue.Environment) (s : State) (out : RollupValue.State)
      (index amount : Nat) (events : List RollupValue.Event) (frame : TokenCallFrame e)
      (call : RollupValue.withdrawToken e s.rollup index amount = .ok (out, events)) :
      Step cfg s { s with rollup := out } zeroFlow
        (fun t => if RollupValue.assetOfToken t = RollupValue.Asset.erc20 index ∧
          e.caller = cfg.manager then amount else 0)
  /-- Close finalization on chain: the materializer latches the channel and
  credits the whole close vector out of pooled escrow. When the crediting Manager
  is another channel's, this Manager's total strictly drops by the credited
  amount — pooled escrow is shared, and that is what the outflow records. -/
  | materialize (fe : CloseFunding.Environment) (s : State) (fundingAfter : CloseFunding.State)
      (out : RollupValue.State) (manager : Nat) (proof : CloseFunding.Bytes)
      (p : CloseFunding.MaterializationPlan) (events : List CloseFunding.Event)
      (plan : CloseFunding.prepareSignedHead fe s.funding manager proof = .ok p)
      (call : CloseFunding.materializeSignedHead fe ⟨s.funding, FundFlow.projectLedger s.rollup⟩
        manager proof = .ok (⟨fundingAfter, FundFlow.projectLedger out⟩, events)) :
      Step cfg s { s with rollup := out, funding := fundingAfter } zeroFlow
        (fun t => if manager = cfg.manager then 0 else CloseFunding.transferred p.credits t)
  /-- Close request on the Manager: freezes the channel, moves no value. -/
  | requestClose (ext : ManagerValue.External) (s : State) (out : ManagerValue.State) (now : Nat)
      (call : ManagerValue.requestCloseCore cfg ext now (s.managers cfg.manager) = .ok out) :
      Step cfg s { s with managers := ManagerValue.put s.managers cfg.manager out }
        zeroFlow zeroFlow
  /-- Materializer freeze (close request seen by the satellite). -/
  | fundingFreeze (fe : CloseFunding.Environment) (s : State) (out : CloseFunding.State)
      (caller channel generation : Nat) (events : List CloseFunding.Event)
      (call : CloseFunding.freezeFromManager fe s.funding caller channel generation =
        .ok (out, events)) :
      Step cfg s { s with funding := out } zeroFlow zeroFlow
  /-- Materializer unfreeze (close cancellation seen by the satellite). -/
  | fundingUnfreeze (s : State) (out : CloseFunding.State) (caller channel generation : Nat)
      (events : List CloseFunding.Event)
      (call : CloseFunding.unfreezeFromManager s.funding caller channel generation =
        .ok (out, events)) :
      Step cfg s { s with funding := out } zeroFlow zeroFlow
  /-- Materializer post journal. -/
  | fundingRecordPost (fe : CloseFunding.Environment) (s : State) (out : CloseFunding.State)
      (caller channel block : Nat) (events : List CloseFunding.Event)
      (call : CloseFunding.recordPost fe s.funding caller channel block = .ok (out, events)) :
      Step cfg s { s with funding := out } zeroFlow zeroFlow
  /-- Materializer post rollback. -/
  | fundingRollbackPost (fe : CloseFunding.Environment) (s : State) (out : CloseFunding.State)
      (caller block : Nat) (events : List CloseFunding.Event)
      (call : CloseFunding.rollbackPost fe s.funding caller block = .ok (out, events)) :
      Step cfg s { s with funding := out } zeroFlow zeroFlow
  /-- Rollup batch rollback, under the Rollup's own callback frame condition. -/
  | rollupRollback (e : RollupValue.Environment) (s : State) (out : RollupValue.State) (id : Nat)
      (frame : RollupValue.RollbackCallbackFrame e)
      (call : RollupValue.rollbackBatch e s.rollup id = .ok out) :
      Step cfg s { s with rollup := out } zeroFlow zeroFlow

/-- Finite sequence of modeled steps, accumulating inflow and outflow. -/
inductive Trace (cfg : ManagerValue.Config) : State → State → Flow → Flow → Prop where
  | refl (s : State) : Trace cfg s s zeroFlow zeroFlow
  | next {s middle last : State} {inA outA inB outB : Flow}
      (prior : Trace cfg s middle inA outA) (step : Step cfg middle last inB outB) :
      Trace cfg s last (addFlow inA inB) (addFlow outA outB)

theorem trace_flow_congr {cfg : ManagerValue.Config} {a b : State} {i i' o o' : Flow}
    (t : Trace cfg a b i o) (hi : ∀ x, i x = i' x) (ho : ∀ x, o x = o' x) :
    Trace cfg a b i' o' := by
  have ei : i = i' := funext hi
  have eo : o = o' := funext ho
  subst ei
  subst eo
  exact t

/-! ## Conservation -/

theorem step_conserves (cfg : ManagerValue.Config) {before after : State} {inflow outflow : Flow}
    (step : Step cfg before after inflow outflow) (token : Nat) :
    measure cfg after token + outflow token = measure cfg before token + inflow token := by
  cases step with
  | accounting _ out st =>
    have conserved := FundFlow.accounting_step_conserves cfg st token
    simp only [measure, accountsOf, FundFlow.accounted] at conserved
    simp [measure, accountsOf, FundFlow.accounted, ManagerValue.put, zeroFlow]
    omega
  | deposit e _ out recipient index amount aux events frame call =>
    obtain ⟨hit, miss, pending⟩ := deposit_accounts frame call
    by_cases same : token = index
    · subst same
      simp [measure, accountsOf, FundFlow.accounted, zeroFlow, hit, pending]
      omega
    · have different : RollupValue.assetOfToken token ≠ RollupValue.assetOfToken index := by
        intro eq
        exact same ((FundFlow.asset_dispatch_injective token index).mp eq)
      simp [measure, accountsOf, FundFlow.accounted, zeroFlow, same,
        miss _ different, pending]
  | withdrawalSet e native _ out ws prover proof events call =>
    obtain ⟨escrow, pending⟩ := withdrawal_set_accounts call (RollupValue.assetOfToken token)
      cfg.manager
    simp only [measure, accountsOf, FundFlow.accounted, pending]
    omega
  | userWithdrawNative e _ out amount events frame call =>
    obtain ⟨_, enough, pending, escrow⟩ :=
      FundFlow.native_pull_call_debits_actual_rollup_credit e before.rollup out amount events frame call
    simp only [measure, accountsOf, FundFlow.accounted, zeroFlow, escrow]
    by_cases hit : RollupValue.assetOfToken token = RollupValue.Asset.native ∧
        e.caller = cfg.manager
    · obtain ⟨asset, caller⟩ := hit
      have debit := RollupValue.pull_debits_exact_amount before.rollup .native e.caller amount enough
      rw [if_pos ⟨asset, caller⟩, asset, congrFun (congrFun pending .native) cfg.manager, ← caller]
      omega
    · rw [if_neg hit, Nat.add_zero]
      have framed : out.pending (RollupValue.assetOfToken token) cfg.manager =
          before.rollup.pending (RollupValue.assetOfToken token) cfg.manager := by
        rw [congrFun (congrFun pending _) cfg.manager]
        by_cases asset : RollupValue.assetOfToken token = RollupValue.Asset.native
        · have caller : cfg.manager ≠ e.caller := by
            intro eq
            exact hit ⟨asset, eq.symm⟩
          rw [asset]
          exact RollupValue.pull_frames_other_recipient before.rollup .native e.caller cfg.manager
            amount caller
        · exact congrFun (RollupValue.pull_frames_other_asset before.rollup .native
            (RollupValue.assetOfToken token) e.caller amount asset) cfg.manager
      rw [framed]
      omega
  | userWithdrawToken e _ out index amount events frame call =>
    obtain ⟨escrow, pending⟩ := token_pull_debits_actual_rollup_credit frame call
    simp only [measure, accountsOf, FundFlow.accounted, zeroFlow, escrow]
    by_cases hit : RollupValue.assetOfToken token = RollupValue.Asset.erc20 index ∧
        e.caller = cfg.manager
    · obtain ⟨asset, caller⟩ := hit
      have enough : amount ≤ before.rollup.pending (.erc20 index) e.caller := by
        simp only [RollupValue.withdrawToken] at call
        obtain ⟨mid, hbody, _, _⟩ := release_then_guarded call
        simp only [RollupValue.withdrawTokenBody] at hbody
        obtain ⟨_, _, hbody⟩ := bind_success hbody
        obtain ⟨_, guard, _⟩ := bind_success hbody
        have guarded := rollup_require_ok guard
        simp only [Bool.and_eq_true, decide_eq_true_eq] at guarded
        exact guarded.2
      have debit := RollupValue.pull_debits_exact_amount before.rollup (.erc20 index) e.caller amount
        enough
      rw [if_pos ⟨asset, caller⟩, asset, congrFun (congrFun pending (.erc20 index)) cfg.manager,
        ← caller]
      omega
    · rw [if_neg hit, Nat.add_zero]
      have framed : out.pending (RollupValue.assetOfToken token) cfg.manager =
          before.rollup.pending (RollupValue.assetOfToken token) cfg.manager := by
        rw [congrFun (congrFun pending _) cfg.manager]
        by_cases asset : RollupValue.assetOfToken token = RollupValue.Asset.erc20 index
        · have caller : cfg.manager ≠ e.caller := by
            intro eq
            exact hit ⟨asset, eq.symm⟩
          rw [asset]
          exact RollupValue.pull_frames_other_recipient before.rollup (.erc20 index) e.caller
            cfg.manager amount caller
        · exact congrFun (RollupValue.pull_frames_other_asset before.rollup (.erc20 index)
            (RollupValue.assetOfToken token) e.caller amount asset) cfg.manager
      rw [framed]
      omega
  | materialize fe _ fundingAfter out manager proof p events plan call =>
    obtain ⟨q, hplan, _, hcredit⟩ := materialize_call_shape call
    have same : q = p := Except.ok.inj (hplan.symm.trans plan)
    subst same
    have accounting := CloseFunding.successful_vector_accounting hcredit token
    simp only [FundFlow.projected_escrow, FundFlow.projected_pending] at accounting
    obtain ⟨escrow, pending⟩ := accounting
    simp only [measure, accountsOf, FundFlow.accounted, zeroFlow]
    by_cases mine : manager = cfg.manager
    · subst mine
      rw [if_pos rfl]
      omega
    · rw [if_neg mine]
      have framed : out.pending (RollupValue.assetOfToken token) cfg.manager =
          before.rollup.pending (RollupValue.assetOfToken token) cfg.manager := by
        have := funding_vector_frames_other_manager (other := cfg.manager)
          (fun eq => mine eq.symm) hcredit token
        simpa only [FundFlow.projected_pending] using this
      rw [framed]
      omega
  | requestClose ext _ out now call =>
    obtain ⟨received, _, _, _, _⟩ := request_close_frames_value call
    simp [measure, accountsOf, FundFlow.accounted, ManagerValue.put, zeroFlow, received]
  | fundingFreeze => rfl
  | fundingUnfreeze => rfl
  | fundingRecordPost => rfl
  | fundingRollbackPost => rfl
  | rollupRollback e _ out id frame call =>
    have framed := RollupValue.rollback_batch_preserves_protected_state e frame before.rollup out id call
    have escrow := congrArg RollupValue.State.escrow framed
    have pending := congrArg RollupValue.State.pending framed
    simp only [RollupValue.protectedView] at escrow pending
    simp only [measure, accountsOf, FundFlow.accounted, zeroFlow, escrow, pending]

/-- **Exact per-token accounting identity.** Along any finite sequence of modeled
steps, this Manager's accounted total changes by exactly the recorded inflow
minus the recorded outflow. Template: `FundFlow.every_accounting_trace_conserves`,
which is the special case where every step is value-neutral. -/
theorem trace_conserves_per_token (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow) (token : Nat) :
    measure cfg after token + outflow token = measure cfg before token + inflow token := by
  induction trace with
  | refl => simp [zeroFlow]
  | next _ step ih =>
    have single := step_conserves cfg step token
    simp only [addFlow] at *
    omega

/-! ## Attribution to the Manager's own channel -/

/-- Cap framing and the received ceiling for the four `FundFlow` transitions. -/
theorem accounting_step_received_within_cap (cfg : ManagerValue.Config)
    {before after : FundFlow.Accounts} (step : FundFlow.AccountingStep cfg before after)
    (bounded : ∀ t, before.manager.received t ≤ before.manager.cap t) :
    (∀ t, after.manager.received t ≤ after.manager.cap t) ∧
      after.manager.cap = before.manager.cap := by
  cases step with
  | credit => exact ⟨bounded, rfl⟩
  | pull ext _ next token pull _ =>
    have exactState := FundFlow.manager_pull_exact_state cfg ext before.manager next token pull
    refine ⟨fun t => ?_, by rw [exactState]⟩
    by_cases same : t = token
    · subst same
      simp [exactState, ManagerValue.put]
    · simpa [exactState, ManagerValue.put, same] using bounded t
  | payout ext _ next sender nullifier payout =>
    obtain ⟨effects, _, _⟩ := ManagerValue.payout_success_exact_effects ext before.manager next
      sender nullifier payout
    refine ⟨fun t => ?_, by rw [effects]; rfl⟩
    simpa [effects, ManagerValue.payoutEffects] using bounded t
  | submitClaim ext _ next claim proof submit =>
    have effects := ManagerValue.submit_success_effects cfg ext before.manager next claim proof
      submit
    refine ⟨fun t => ?_, by rw [effects]; rfl⟩
    simpa [effects, ManagerValue.claimEffects] using bounded t

theorem step_received_within_cap (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (step : Step cfg before after inflow outflow)
    (bounded : ∀ t, (before.managers cfg.manager).received t ≤
      (before.managers cfg.manager).cap t) :
    (∀ t, (after.managers cfg.manager).received t ≤ (after.managers cfg.manager).cap t) ∧
      (after.managers cfg.manager).cap = (before.managers cfg.manager).cap := by
  cases step with
  | accounting _ out st =>
    obtain ⟨nextBounded, nextCap⟩ := accounting_step_received_within_cap cfg st bounded
    refine ⟨fun t => ?_, ?_⟩
    · simpa [ManagerValue.put] using nextBounded t
    · simpa [ManagerValue.put] using nextCap
  | requestClose ext _ out now call =>
    obtain ⟨received, _, cap, _, _⟩ := request_close_frames_value call
    refine ⟨fun t => ?_, by simp [ManagerValue.put, cap]⟩
    simpa [ManagerValue.put, received, cap] using bounded t
  | deposit => exact ⟨bounded, rfl⟩
  | withdrawalSet => exact ⟨bounded, rfl⟩
  | userWithdrawNative => exact ⟨bounded, rfl⟩
  | userWithdrawToken => exact ⟨bounded, rfl⟩
  | materialize => exact ⟨bounded, rfl⟩
  | fundingFreeze => exact ⟨bounded, rfl⟩
  | fundingUnfreeze => exact ⟨bounded, rfl⟩
  | fundingRecordPost => exact ⟨bounded, rfl⟩
  | fundingRollbackPost => exact ⟨bounded, rfl⟩
  | rollupRollback => exact ⟨bounded, rfl⟩

theorem step_preserves_materialization_latch (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (step : Step cfg before after inflow outflow)
    (c : CloseFunding.Channel) (d : CloseFunding.Hash) (nonzero : d ≠ 0)
    (latched : before.funding.materializedChannelExit c = d) :
    after.funding.materializedChannelExit c = d := by
  cases step with
  | materialize fe _ fundingAfter out manager proof p events plan call =>
    obtain ⟨q, hplan, storage, _⟩ := materialize_call_shape call
    have same : q = p := Except.ok.inj (hplan.symm.trans plan)
    subst same
    obtain ⟨_, anchor, localChecks⟩ :=
      CloseFunding.prepared_signed_head_requires_receipt_and_local_checks plan
    obtain ⟨_, _, _, _, exited, _⟩ := CloseFunding.prepared_materialization_guards localChecks
    have different : c ≠ q.channel := by
      intro eq
      rw [eq, exited] at latched
      exact nonzero latched.symm
    have latch : fundingAfter = CloseFunding.latchState before.funding q := storage
    rw [latch, CloseFunding.latch_other_channel_framed before.funding q c different]
    exact latched
  | accounting => exact latched
  | deposit => exact latched
  | withdrawalSet => exact latched
  | userWithdrawNative => exact latched
  | userWithdrawToken => exact latched
  | requestClose => exact latched
  | fundingFreeze fe _ out caller channel generation events call =>
    simp only [CloseFunding.freezeFromManager] at call
    obtain ⟨_, _, call⟩ := bind_success call
    obtain ⟨_, _, call⟩ := bind_success call
    obtain ⟨_, _, call⟩ := bind_success call
    obtain ⟨_, _, call⟩ := bind_success call
    obtain ⟨_, _, call⟩ := bind_success call
    obtain ⟨_, _, call⟩ := bind_success call
    obtain ⟨_, _, call⟩ := bind_success call
    obtain ⟨_, _, call⟩ := bind_success call
    obtain ⟨_, _, call⟩ := bind_success call
    have pair := Except.ok.inj call
    obtain ⟨rfl, _⟩ := Prod.mk.inj pair
    exact latched
  | fundingUnfreeze _ out caller channel generation events call =>
    simp only [CloseFunding.unfreezeFromManager] at call
    obtain ⟨_, _, call⟩ := bind_success call
    obtain ⟨_, _, call⟩ := bind_success call
    obtain ⟨_, _, call⟩ := bind_success call
    obtain ⟨_, _, call⟩ := bind_success call
    have pair := Except.ok.inj call
    obtain ⟨rfl, _⟩ := Prod.mk.inj pair
    exact latched
  | fundingRecordPost fe _ out caller channel block events call =>
    simp only [CloseFunding.recordPost] at call
    obtain ⟨_, _, call⟩ := bind_success call
    split at call
    · have pair := Except.ok.inj call
      obtain ⟨rfl, _⟩ := Prod.mk.inj pair
      exact latched
    · obtain ⟨_, _, call⟩ := bind_success call
      obtain ⟨_, _, call⟩ := bind_success call
      have pair := Except.ok.inj call
      obtain ⟨rfl, _⟩ := Prod.mk.inj pair
      exact latched
  | fundingRollbackPost fe _ out caller block events call =>
    simp only [CloseFunding.rollbackPost] at call
    obtain ⟨_, _, call⟩ := bind_success call
    split at call
    · have pair := Except.ok.inj call
      obtain ⟨rfl, _⟩ := Prod.mk.inj pair
      exact latched
    · obtain ⟨_, _, call⟩ := bind_success call
      have pair := Except.ok.inj call
      obtain ⟨rfl, _⟩ := Prod.mk.inj pair
      exact latched
  | rollupRollback => exact latched

/-- **Attribution.** Along any modeled trace: (i) the Manager's received counter
never passes its own close-vector cap and that cap is never rewritten by a
modeled step, and (ii) once a channel is materialized, the latch survives every
later modeled step, so the channel's close vector is credited at most once.
`materialization_credits_are_the_managers_own_vector` below adds that the credited
amounts are precisely the Manager's own getter values.

What is NOT proved, and remains exactly premise (c): that the cap itself — the
finalized close vector — is bounded by what this channel deposited. Nothing in
`RollupValue`, `ManagerValue` or `CloseFunding` relates the vector to deposits;
escrow is pooled, and `RollupValue`'s header says so. -/
theorem trace_channel_attribution (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow)
    (bounded : ∀ t, (before.managers cfg.manager).received t ≤
      (before.managers cfg.manager).cap t) :
    (∀ t, (after.managers cfg.manager).received t ≤ (after.managers cfg.manager).cap t) ∧
      (after.managers cfg.manager).cap = (before.managers cfg.manager).cap ∧
      (∀ (c : CloseFunding.Channel) (d : CloseFunding.Hash), d ≠ 0 →
        before.funding.materializedChannelExit c = d →
        after.funding.materializedChannelExit c = d) := by
  induction trace with
  | refl => exact ⟨bounded, rfl, fun _ _ _ h => h⟩
  | next _ step ih =>
    obtain ⟨midBounded, midCap, midLatch⟩ := ih
    obtain ⟨nextBounded, nextCap⟩ := step_received_within_cap cfg step midBounded
    exact ⟨nextBounded, nextCap.trans midCap, fun c d nonzero latched =>
      step_preserves_materialization_latch cfg step c d nonzero (midLatch c d nonzero latched)⟩

/-- Every amount the materializer credits is the Manager's own token-vector
getter value, the vector has no duplicate token, and the channel is latched.
Direct consequence of `CloseFunding.materialization_call_complete_vector`; it
carries no claim that those getter values are legitimate. -/
theorem materialization_credits_are_the_managers_own_vector {fe : CloseFunding.Environment}
    {before after : CloseFunding.World} {manager : Nat} {proof : CloseFunding.Bytes}
    {events : List CloseFunding.Event}
    (call : CloseFunding.materializeSignedHead fe before manager proof = .ok (after, events)) :
    ∃ p : CloseFunding.MaterializationPlan, p.manager = manager ∧
      p.credits.length = p.tokenCount ∧ CloseFunding.TokensUnique p.credits ∧
      (∀ c ∈ p.credits, (fe.manager manager).amountAt c.token = .ok c.amount) ∧
      after.storage.materializedChannelExit p.channel = p.digest ∧ p.digest ≠ 0 ∧
      (∀ token, after.ledger.escrow token + CloseFunding.transferred p.credits token =
          before.ledger.escrow token ∧
        after.ledger.pending token manager =
          before.ledger.pending token manager + CloseFunding.transferred p.credits token) :=
  CloseFunding.materialization_call_complete_vector call

/-- The remaining gap of premise (c), stated in full: the accepted close
statement's own token amounts are within what that channel deposited. This is the
obligation the Balance/validity circuit family must discharge. -/
theorem close_vector_backing_is_exactly_premise_c
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : TrustBoundary.Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerProjection : σ → ManagerValue.State} {fundingProjection : σ → CloseFunding.State}
    (tb : TrustBoundary.TrustBoundary m Deployed Modeled Unmodeled managerProjection
      fundingProjection)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true)
    (i : Fin 10) (live : i.val < f.tokenCount.val) :
    (f.channelFundAmounts i).val ≤ m.deposits f.channelId.val (f.tokenRegistry i).val :=
  tb.closeVectorBacked f proof accepted i live

/-! ## Replay protection and payout bound -/

/-- **Nullifier single use.** Along any modeled trace the payout index stays
coherent, used markers are never cleared, and no already-used nullifier can be
claimed again at the end of the trace. Lifted from
`FundFlow.every_accounting_trace_preserves_nullifier_and_payout_index` and
`FundFlow.submitted_claim_nullifier_was_unused`. Durability against transitions
OUTSIDE this step relation is premise (g1), not a theorem. -/
theorem trace_nullifier_single_use (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow)
    (indexed : FundFlow.PayoutIndexed (before.managers cfg.manager)) :
    FundFlow.PayoutIndexed (after.managers cfg.manager) ∧
      (∀ n, (before.managers cfg.manager).used n = true →
        (after.managers cfg.manager).used n = true) ∧
      (∀ (ext : ManagerValue.External) (claim : ManagerValue.Claim)
        (proof : ManagerValue.Proof) (out : ManagerValue.State),
        (before.managers cfg.manager).used claim.nullifier = true →
        ManagerValue.submitClaimCore cfg ext (after.managers cfg.manager) claim proof ≠ .ok out) := by
  have core : FundFlow.PayoutIndexed (after.managers cfg.manager) ∧
      (∀ n, (before.managers cfg.manager).used n = true →
        (after.managers cfg.manager).used n = true) := by
    induction trace with
    | refl => exact ⟨indexed, fun _ h => h⟩
    | next _ step ih =>
      obtain ⟨midIndexed, midUsed⟩ := ih
      cases step with
      | accounting _ out st =>
        obtain ⟨nextIndexed, nextUsed⟩ :=
          FundFlow.accounting_step_preserves_nullifier_and_payout_index cfg st midIndexed
        refine ⟨?_, fun n used => ?_⟩
        · simpa [ManagerValue.put] using nextIndexed
        · simpa [ManagerValue.put] using nextUsed n (midUsed n used)
      | requestClose ext _ out now call =>
        obtain ⟨_, _, _, used, payouts⟩ := request_close_frames_value call
        refine ⟨?_, fun n live => ?_⟩
        · simpa [FundFlow.PayoutIndexed, ManagerValue.put, payouts, used] using midIndexed
        · simpa [ManagerValue.put, used] using midUsed n live
      | deposit => exact ⟨midIndexed, midUsed⟩
      | withdrawalSet => exact ⟨midIndexed, midUsed⟩
      | userWithdrawNative => exact ⟨midIndexed, midUsed⟩
      | userWithdrawToken => exact ⟨midIndexed, midUsed⟩
      | materialize => exact ⟨midIndexed, midUsed⟩
      | fundingFreeze => exact ⟨midIndexed, midUsed⟩
      | fundingUnfreeze => exact ⟨midIndexed, midUsed⟩
      | fundingRecordPost => exact ⟨midIndexed, midUsed⟩
      | fundingRollbackPost => exact ⟨midIndexed, midUsed⟩
      | rollupRollback => exact ⟨midIndexed, midUsed⟩
  refine ⟨core.1, core.2, fun ext claim proof out used submit => ?_⟩
  have unused := FundFlow.submitted_claim_nullifier_was_unused cfg ext
    (after.managers cfg.manager) out claim proof submit
  rw [core.2 claim.nullifier used] at unused
  exact Bool.noConfusion unused

/-- **Payout bound.** Along any modeled trace the Manager never pays out more per
token than it received, and the pooled-escrow split of
`FundFlow.accounted_splits_paid_and_unspent` continues to hold. -/
theorem trace_paid_bounded (cfg : ManagerValue.Config) {before after : State}
    {inflow outflow : Flow} (trace : Trace cfg before after inflow outflow)
    (bounded : FundFlow.PaidBounded (before.managers cfg.manager)) :
    FundFlow.PaidBounded (after.managers cfg.manager) ∧
      ∀ token, after.rollup.escrow (RollupValue.assetOfToken token) +
          after.rollup.pending (RollupValue.assetOfToken token) cfg.manager +
          FundFlow.unspent (after.managers cfg.manager) token +
          (after.managers cfg.manager).paid token + outflow token =
        measure cfg before token + inflow token := by
  have core : FundFlow.PaidBounded (after.managers cfg.manager) := by
    induction trace with
    | refl => exact bounded
    | next _ step ih =>
      cases step with
      | accounting _ out st =>
        have next := FundFlow.accounting_step_preserves_paid_bound cfg st ih
        intro t
        simpa [ManagerValue.put] using next t
      | requestClose ext _ out now call =>
        obtain ⟨received, paid, _, _, _⟩ := request_close_frames_value call
        intro t
        simpa [ManagerValue.put, received, paid] using ih t
      | deposit => exact ih
      | withdrawalSet => exact ih
      | userWithdrawNative => exact ih
      | userWithdrawToken => exact ih
      | materialize => exact ih
      | fundingFreeze => exact ih
      | fundingUnfreeze => exact ih
      | fundingRecordPost => exact ih
      | fundingRollbackPost => exact ih
      | rollupRollback => exact ih
  refine ⟨core, fun token => ?_⟩
  have split := FundFlow.accounted_splits_paid_and_unspent (accountsOf cfg after) cfg.manager token
    (core token)
  have conserved := trace_conserves_per_token cfg trace token
  simp only [measure, accountsOf, FundFlow.accounted] at split conserved ⊢
  omega

/-! ## Close acceptance -/

/-- **Close acceptance binds the statement.** Unconditionally, a successful
modeled Solidity close verification pins the exact 103-word record the pinned
adapter returned (`SettlementCloseBridge`). Only the third conjunct — that some
witness satisfies the circuit's local gate equations for that same record — uses
premises (a0) and (a), through the derived `TrustBoundary.closeProofSoundness`;
acceptance alone establishes nothing about truth, funding or authorization. -/
theorem close_acceptance_binds_statement
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : TrustBoundary.Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerProjection : σ → ManagerValue.State} {fundingProjection : σ → CloseFunding.State}
    (tb : TrustBoundary.TrustBoundary m Deployed Modeled Unmodeled managerProjection
      fundingProjection)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyCloseIntent m.evm m.installed m.keccak f proof = .ok true) :
    m.evm.verifyCompactPublicInputs m.installed.adapters.close proof =
        .ok (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val).words ∧
      (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val).words.length =
        CloseCircuit.publicInputsLength ∧
      ∃ w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path,
        CloseCircuit.CircuitGates m.closeEnv
          (SettlementCloseBridge.statement m.keccak f f.minDelegateCount.val) w :=
  ⟨SettlementCloseBridge.accepted_verification_has_exact_adapter_receipt m.evm m.installed
      m.keccak f proof accepted,
    CloseCircuit.public_input_word_count _,
    tb.closeProofSoundness f proof accepted⟩

/-- The claim endpoints have the same shape: the statement is pinned
unconditionally, the witness only under premises (a0)+(b1) (respectively
(a0)+(b2)), through the derived `TrustBoundary.withdrawalProofSoundness`. -/
theorem claim_acceptance_binds_statement
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    {m : TrustBoundary.Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore}
    {Deployed Modeled Unmodeled : σ → σ → Prop}
    {managerProjection : σ → ManagerValue.State} {fundingProjection : σ → CloseFunding.State}
    (tb : TrustBoundary.TrustBoundary m Deployed Modeled Unmodeled managerProjection
      fundingProjection)
    (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyWithdrawalClaim m.evm m.installed f proof = .ok true) :
    m.evm.verifyCompactPublicInputs m.installed.adapters.withdrawal proof =
        .ok (ClaimSettlementBridge.withdrawalStatement f).words ∧
      ∃ w : WithdrawalClaimCircuit.Witness ClaimPath ClaimCore,
        WithdrawalClaimCircuit.CircuitGates m.claimEnv
          (ClaimSettlementBridge.withdrawalStatement f) w :=
  ⟨ClaimSettlementBridge.accepted_withdrawal_has_exact_adapter_receipt m.evm m.installed f proof
      accepted,
    tb.withdrawalProofSoundness f proof accepted⟩

/-! ## Non-vacuous instantiation

The concrete trace below reuses `FundFlow.normal*`: a channel-exit credit of 100
native units, the Manager pull of the same 100, a claim of 5 and the payout of
those 5. Every conclusion above is instantiated on it. These are model
evaluations, not transactions against any deployment. -/

def stepState (cfg : ManagerValue.Config) (s : State) (out : FundFlow.Accounts) : State :=
  { s with rollup := out.rollup, managers := ManagerValue.put s.managers cfg.manager out.manager }

theorem accounts_of_step_state (cfg : ManagerValue.Config) (s : State) (out : FundFlow.Accounts) :
    accountsOf cfg (stepState cfg s out) = out := by
  simp [accountsOf, stepState, ManagerValue.put]

def normalStart : State :=
  ⟨FundFlow.normalBefore.rollup, fun _ => FundFlow.normalBefore.manager, CloseFunding.empty⟩

def normalCredited : State := stepState ManagerValue.sampleConfig normalStart FundFlow.normalCredited
def normalPulled : State := stepState ManagerValue.sampleConfig normalCredited FundFlow.normalPulled
def normalClaimed : State := stepState ManagerValue.sampleConfig normalPulled FundFlow.normalClaimed
def normalPaid : State := stepState ManagerValue.sampleConfig normalClaimed FundFlow.normalPaid

theorem accounts_of_normal_start :
    accountsOf ManagerValue.sampleConfig normalStart = FundFlow.normalBefore := rfl

theorem accounts_of_normal_credited :
    accountsOf ManagerValue.sampleConfig normalCredited = FundFlow.normalCredited :=
  accounts_of_step_state ManagerValue.sampleConfig normalStart FundFlow.normalCredited

theorem accounts_of_normal_pulled :
    accountsOf ManagerValue.sampleConfig normalPulled = FundFlow.normalPulled :=
  accounts_of_step_state ManagerValue.sampleConfig normalCredited FundFlow.normalPulled

theorem accounts_of_normal_claimed :
    accountsOf ManagerValue.sampleConfig normalClaimed = FundFlow.normalClaimed :=
  accounts_of_step_state ManagerValue.sampleConfig normalPulled FundFlow.normalClaimed

theorem normal_accounting_step (s : State) (out : FundFlow.Accounts)
    (step : FundFlow.AccountingStep ManagerValue.sampleConfig (accountsOf ManagerValue.sampleConfig s) out) :
    Step ManagerValue.sampleConfig s (stepState ManagerValue.sampleConfig s out) zeroFlow zeroFlow :=
  Step.accounting s out step

/-- A nonempty modeled trace through the same credit/pull/claim/payout
definitions, with zero inflow and zero outflow. -/
theorem normal_credit_pull_claim_payout_trace (base : RollupValue.Environment) :
    Trace ManagerValue.sampleConfig normalStart normalPaid zeroFlow zeroFlow := by
  have startAccounts : accountsOf ManagerValue.sampleConfig normalStart = FundFlow.normalBefore := rfl
  have credited : Step ManagerValue.sampleConfig normalStart normalCredited zeroFlow zeroFlow := by
    apply Step.accounting
    rw [startAccounts]
    apply FundFlow.AccountingStep.credit (FundFlow.normalRollup base) FundFlow.normalBefore
      FundFlow.normalCredited.rollup 0 100
    apply (RollupValue.successful_close_credit_characterization _ _ _ _ _ _).mpr
    refine ⟨rfl, rfl, ?_⟩
    apply (RollupValue.successful_credit_characterization _ _ _ _ _).mpr
    exact ⟨by decide, by decide, rfl⟩
  have pulled : Step ManagerValue.sampleConfig normalCredited normalPulled zeroFlow zeroFlow := by
    apply Step.accounting
    rw [accounts_of_normal_credited]
    apply FundFlow.AccountingStep.pull ManagerValue.sampleExternal FundFlow.normalCredited
      FundFlow.normalPulled.manager 0
    · rfl
    · decide
  have claimed : Step ManagerValue.sampleConfig normalPulled normalClaimed zeroFlow zeroFlow := by
    apply Step.accounting
    rw [accounts_of_normal_pulled]
    exact FundFlow.AccountingStep.submitClaim ManagerValue.sampleExternal _ _
      ManagerValue.sampleClaim [] (by rfl)
  have paid : Step ManagerValue.sampleConfig normalClaimed normalPaid zeroFlow zeroFlow := by
    apply Step.accounting
    rw [accounts_of_normal_claimed]
    exact FundFlow.AccountingStep.payout ManagerValue.sampleExternal _ _ 23 91 (by rfl)
  refine trace_flow_congr
    (Trace.next (Trace.next (Trace.next (Trace.next (Trace.refl normalStart) credited) pulled)
      claimed) paid) ?_ ?_ <;>
    intro x <;> rfl

/-- The trace is not vacuous: value really moved, the nullifier was consumed, and
every conclusion above holds on it with concrete numbers. -/
theorem normal_trace_witnesses_every_conclusion (base : RollupValue.Environment) :
    measure ManagerValue.sampleConfig normalPaid 0 =
        measure ManagerValue.sampleConfig normalStart 0 ∧
      (normalPaid.managers ManagerValue.sampleConfig.manager).paid 0 = 5 ∧
      FundFlow.unspent (normalPaid.managers ManagerValue.sampleConfig.manager) 0 = 95 ∧
      normalPaid.rollup.escrow .native = 0 ∧
      normalPaid.rollup.pending .native 42 = 0 ∧
      (normalPaid.managers ManagerValue.sampleConfig.manager).used 91 = true := by
  refine ⟨?_, by decide, by decide, by decide, by decide, by decide⟩
  have conserved := trace_conserves_per_token ManagerValue.sampleConfig
    (normal_credit_pull_claim_payout_trace base) 0
  simpa [zeroFlow] using conserved

theorem normal_start_paid_bounded : FundFlow.PaidBounded (normalStart.managers ManagerValue.sampleConfig.manager) :=
  fun _ => Nat.le_refl 0

theorem normal_start_payout_index :
    FundFlow.PayoutIndexed (normalStart.managers ManagerValue.sampleConfig.manager) :=
  fun _ live => absurd rfl live

theorem normal_start_received_within_cap :
    ∀ t, (normalStart.managers ManagerValue.sampleConfig.manager).received t ≤
      (normalStart.managers ManagerValue.sampleConfig.manager).cap t :=
  fun _ => Nat.zero_le 100

theorem normal_trace_paid_bounded (base : RollupValue.Environment) :
    FundFlow.PaidBounded (normalPaid.managers ManagerValue.sampleConfig.manager) :=
  (trace_paid_bounded ManagerValue.sampleConfig (normal_credit_pull_claim_payout_trace base)
    normal_start_paid_bounded).1

theorem normal_trace_received_within_cap (base : RollupValue.Environment) :
    ∀ t, (normalPaid.managers ManagerValue.sampleConfig.manager).received t ≤
      (normalPaid.managers ManagerValue.sampleConfig.manager).cap t :=
  (trace_channel_attribution ManagerValue.sampleConfig
    (normal_credit_pull_claim_payout_trace base) normal_start_received_within_cap).1

theorem normal_trace_preserves_used_marker (base : RollupValue.Environment) :
    ∀ n, (normalStart.managers ManagerValue.sampleConfig.manager).used n = true →
      (normalPaid.managers ManagerValue.sampleConfig.manager).used n = true :=
  (trace_nullifier_single_use ManagerValue.sampleConfig
    (normal_credit_pull_claim_payout_trace base) normal_start_payout_index).2.1

/-- The payout leg on its own, used to instantiate the replay-protection
conclusion from a state where the nullifier is already consumed. -/
theorem normal_payout_trace :
    Trace ManagerValue.sampleConfig normalClaimed normalPaid zeroFlow zeroFlow := by
  have paid : Step ManagerValue.sampleConfig normalClaimed normalPaid zeroFlow zeroFlow := by
    apply Step.accounting
    rw [accounts_of_normal_claimed]
    exact FundFlow.AccountingStep.payout ManagerValue.sampleExternal _ _ 23 91 (by rfl)
  refine trace_flow_congr (Trace.next (Trace.refl normalClaimed) paid) ?_ ?_ <;> intro x <;> rfl

theorem normal_claimed_payout_index :
    FundFlow.PayoutIndexed (normalClaimed.managers ManagerValue.sampleConfig.manager) := by
  intro n live
  by_cases same : n = 91
  · subst same
    decide
  · exact absurd (by
      simp [normalClaimed, stepState, ManagerValue.put, FundFlow.normalClaimed,
        ManagerValue.claimEffects, ManagerValue.sampleClaim, ManagerValue.emptyPayout,
        normalPulled, FundFlow.normalPulled, FundFlow.normalBefore, ManagerValue.sampleState,
        same] : ((normalClaimed.managers ManagerValue.sampleConfig.manager).payouts n).amount = 0)
      live

/-- The consumed nullifier cannot be claimed a second time from the paid state. -/
theorem normal_trace_nullifier_cannot_be_reused (ext : ManagerValue.External)
    (proof : ManagerValue.Proof) (out : ManagerValue.State) :
    ManagerValue.submitClaimCore ManagerValue.sampleConfig ext
      (normalPaid.managers ManagerValue.sampleConfig.manager) ManagerValue.sampleClaim proof
      ≠ .ok out :=
  (trace_nullifier_single_use ManagerValue.sampleConfig normal_payout_trace
    normal_claimed_payout_index).2.2 ext ManagerValue.sampleClaim proof out (by decide)

/-! ### The latch conjunct is not degenerate

`normalStart` has no materialized channel, so the third conjunct of
`trace_channel_attribution` holds vacuously there. The witness below runs a
modeled step from a state that DOES have a latched channel and reads the latch
back through the theorem. -/

def latchedFunding : CloseFunding.State :=
  { CloseFunding.empty with
    materializedChannelExit := CloseFunding.put CloseFunding.empty.materializedChannelExit 7 99 }

def latchedStart : State := { normalStart with funding := latchedFunding }

def latchedCredited : State := stepState ManagerValue.sampleConfig latchedStart FundFlow.normalCredited

theorem accounts_of_latched_start :
    accountsOf ManagerValue.sampleConfig latchedStart = FundFlow.normalBefore := rfl

theorem latched_credit_step (base : RollupValue.Environment) :
    Step ManagerValue.sampleConfig latchedStart latchedCredited zeroFlow zeroFlow := by
  apply Step.accounting
  rw [accounts_of_latched_start]
  apply FundFlow.AccountingStep.credit (FundFlow.normalRollup base) FundFlow.normalBefore
    FundFlow.normalCredited.rollup 0 100
  apply (RollupValue.successful_close_credit_characterization _ _ _ _ _ _).mpr
  refine ⟨rfl, rfl, ?_⟩
  apply (RollupValue.successful_credit_characterization _ _ _ _ _).mpr
  exact ⟨by decide, by decide, rfl⟩

theorem latched_channel_survives_a_modeled_step (base : RollupValue.Environment) :
    latchedCredited.funding.materializedChannelExit 7 = 99 :=
  step_preserves_materialization_latch ManagerValue.sampleConfig (latched_credit_step base) 7 99
    (by decide) (by rfl)

/-! ### Acceptance is reachable

`close_acceptance_binds_statement` and `claim_acceptance_binds_statement` are
conditional on a successful modeled verification. The witnesses below show that
hypothesis is satisfiable, so neither statement is vacuous: a concrete adapter
view returning the encoded statement is accepted, and the unconditional half then
pins exactly that word list. The premise-dependent half stays
uninstantiated on purpose — premises (a) and (b1) are precisely what no model in
this project can discharge. -/

def sampleKeccak : SettlementVerifier.Keccak := fun _ => 0

def sampleCloseFields : SettlementVerifier.CloseFields where
  channelId := 1
  closeNonce := 0
  finalEpoch := 0
  finalSmallBlockNumber := 0
  closeFreezeNonce := 0
  finalChannelStateDigest := 0
  finalBalanceStateH1 := 0
  channelFundAmounts := fun _ => 0
  channelFundIntmaxStateRoot := 0
  burnTxHash := 0
  closeWithdrawalDigest := 0
  snapshotMediumBlockNumber := 0
  finalStateVersion := 0
  finalSettledTxChain := 0
  finalSettledTxAccumulatorRoot := 0
  memberSetCommitment := 0
  memberCount := 2
  minDelegateCount := 0
  tokenRegistry := fun _ => 0
  tokenCount := 1

def sampleWithdrawalFields : SettlementVerifier.WithdrawalFields where
  channelId := 1
  closeIntentDigest := 0
  finalBalanceStateH1 := 0
  memberPkG := 0
  recipient := 0
  userAmountDigest := 0
  withdrawalNullifier := 0
  amount := 0
  tokenSlot := 0
  tokenIndex := 0

def sampleInstalled : SettlementVerifier.Installed := ⟨⟨0, 0, 0, 0⟩, ⟨0, 0, 0, 0⟩⟩

/-- An adapter view that returns the encoded close statement. It is a model
value, not a proof system: nothing here says the returned words are true. -/
def closeAcceptingEvm : SettlementVerifier.EvmView where
  chainId := 0
  codeSize := fun _ => 0
  allowedChainId := fun _ => .error []
  core := fun _ => .error []
  verifyCompactPublicInputs := fun _ _ =>
    .ok (SettlementCloseBridge.statement sampleKeccak sampleCloseFields 0).words

/-- The same for the withdrawal-claim endpoint. -/
def withdrawalAcceptingEvm : SettlementVerifier.EvmView where
  chainId := 0
  codeSize := fun _ => 0
  allowedChainId := fun _ => .error []
  core := fun _ => .error []
  verifyCompactPublicInputs := fun _ _ =>
    .ok (ClaimSettlementBridge.withdrawalStatement sampleWithdrawalFields).words

theorem sample_close_is_accepted :
    SettlementVerifier.verifyCloseIntent closeAcceptingEvm sampleInstalled sampleKeccak
      sampleCloseFields [] = .ok true := by rfl

theorem sample_withdrawal_claim_is_accepted :
    SettlementVerifier.verifyWithdrawalClaim withdrawalAcceptingEvm sampleInstalled
      sampleWithdrawalFields [] = .ok true := by rfl

/-- Non-vacuous instantiation of the unconditional half of
`close_acceptance_binds_statement`. -/
theorem sample_close_acceptance_pins_the_exact_statement :
    closeAcceptingEvm.verifyCompactPublicInputs sampleInstalled.adapters.close [] =
      .ok (SettlementCloseBridge.statement sampleKeccak sampleCloseFields
        sampleCloseFields.minDelegateCount.val).words ∧
    (SettlementCloseBridge.statement sampleKeccak sampleCloseFields
        sampleCloseFields.minDelegateCount.val).words.length = CloseCircuit.publicInputsLength :=
  ⟨SettlementCloseBridge.accepted_verification_has_exact_adapter_receipt closeAcceptingEvm
      sampleInstalled sampleKeccak sampleCloseFields [] sample_close_is_accepted,
    CloseCircuit.public_input_word_count _⟩

/-- Non-vacuous instantiation of the unconditional half of
`claim_acceptance_binds_statement`. -/
theorem sample_withdrawal_acceptance_pins_the_exact_statement :
    withdrawalAcceptingEvm.verifyCompactPublicInputs sampleInstalled.adapters.withdrawal [] =
      .ok (ClaimSettlementBridge.withdrawalStatement sampleWithdrawalFields).words :=
  ClaimSettlementBridge.accepted_withdrawal_has_exact_adapter_receipt withdrawalAcceptingEvm
    sampleInstalled sampleWithdrawalFields [] sample_withdrawal_claim_is_accepted

/-! ## The accepted MLE/WHIR premise does not close the audit

`TrustBoundary.mleVerifierSoundness` is an accepted trust assumption about the
pinned `contracts/lib/polygon-plonky2` verifier, not a proof, and accepting it
leaves the rest of the boundary exactly where it was. The two theorems below make
that non-implication a kernel-checked fact rather than a comment: each exhibits an
environment in which the accepted premise holds — vacuously in the strongest
possible way, because every proof is accepted and every accepted statement is
declared satisfiable — while the conclusion people might hope it delivers fails.

The environments are built by overriding only the fields the counterexample needs
(`plonky2Satisfiable`, the adapter view, the installed adapters, the hash, and the
deposit attribution) on an arbitrary `Models`, so no other premise is disturbed. -/

/-- The `sampleCloseFields` channel, but claiming one raw unit of the single live
token. Everything else, including `tokenCount = 1` and `minDelegateCount = 0`, is
unchanged, so the same acceptance computation goes through. -/
def unbackedCloseFields : SettlementVerifier.CloseFields :=
  { sampleCloseFields with channelFundAmounts := fun _ => 1 }

/-- An adapter view that accepts every proof and returns the close statement of
`unbackedCloseFields`. It is a model value, not a proof system. -/
def unbackedAcceptingEvm : SettlementVerifier.EvmView where
  chainId := 0
  codeSize := fun _ => 0
  allowedChainId := fun _ => .error []
  core := fun _ => .error []
  verifyCompactPublicInputs := fun _ _ =>
    .ok (SettlementCloseBridge.statement sampleKeccak unbackedCloseFields 0).words

/-- The counterexample environment: the pinned adapter accepts everything, every
accepted word vector is declared to be a satisfiable plonky2 statement of the
pinned circuit, and the channel deposited nothing. -/
def unbackedModels {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : TrustBoundary.Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore) :
    TrustBoundary.Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore :=
  { m with
    evm := unbackedAcceptingEvm
    installed := sampleInstalled
    keccak := sampleKeccak
    deposits := fun _ _ => 0
    plonky2Satisfiable := fun _ _ => True }

/-- The close endpoint really does accept in that environment, so the theorems
below are not vacuous: they refute premises on an actual acceptance. -/
theorem unbacked_close_is_accepted {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : TrustBoundary.Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore) :
    SettlementVerifier.verifyCloseIntent (unbackedModels m).evm (unbackedModels m).installed
      (unbackedModels m).keccak unbackedCloseFields [] = .ok true := by
  show SettlementVerifier.verifyCloseIntent unbackedAcceptingEvm sampleInstalled sampleKeccak
    unbackedCloseFields [] = .ok true
  rfl

/-- The accepted MLE/WHIR premise holds in that environment, trivially. -/
theorem unbacked_environment_satisfies_the_mle_premise
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : TrustBoundary.Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore) :
    TrustBoundary.MleAcceptedStatementsAreSatisfiable (unbackedModels m) := by
  intro _ _ _ _ _
  trivial

/-- **Accepting the submodule does not buy fund safety.** In an environment where
`mleVerifierSoundness` holds — every proof accepted, every accepted statement
declared satisfiable — no `TrustBoundary` instance exists at all, because the
channel is credited a token amount it never deposited and premise (c)
`closeVectorBacked` is refuted on a genuine acceptance. So the new field cannot
be read as closing the audit: a satisfiable statement of the pinned circuit is
not by itself a legitimate fund movement, and premises (c), (d), (e1), (e2),
(f1), (f2), (g1), (g2) and (h) remain exactly as unproved as before. -/
theorem mle_assumption_does_not_imply_fund_safety
    {BalanceProof AggregateProof Path Root ClaimPath ClaimCore σ : Type}
    (m : TrustBoundary.Models BalanceProof AggregateProof Path Root ClaimPath ClaimCore)
    (Deployed Modeled Unmodeled : σ → σ → Prop)
    (managerProjection : σ → ManagerValue.State) (fundingProjection : σ → CloseFunding.State) :
    TrustBoundary.MleAcceptedStatementsAreSatisfiable (unbackedModels m) ∧
      ¬ TrustBoundary.TrustBoundary (unbackedModels m) Deployed Modeled Unmodeled
          managerProjection fundingProjection := by
  refine ⟨unbacked_environment_satisfies_the_mle_premise m, ?_⟩
  intro tb
  have violated := tb.closeVectorBacked unbackedCloseFields [] (unbacked_close_is_accepted m)
    (0 : Fin 10) (by decide)
  have credited : (unbackedCloseFields.channelFundAmounts 0).val = 1 := rfl
  have deposited : (unbackedModels m).deposits unbackedCloseFields.channelId.val
      (unbackedCloseFields.tokenRegistry 0).val = 0 := rfl
  rw [credited, deposited] at violated
  exact absurd violated (by decide)

/-- **Accepting the submodule does not by itself discharge the close soundness
conclusion either.** With no balance proofs available at all, the conclusion of
`TrustBoundary.closeProofSoundness` — some witness satisfies
`CloseCircuit.CircuitGates` — is false for the accepted close, while
`mleVerifierSoundness` still holds. This is a logical independence witness,
deliberately degenerate: it shows only that the statement-to-gates lowering
premise (a) `TrustBoundary.CloseStatementLowering` is a genuinely separate
obligation, which
`TrustBoundary.mle_assumption_reduces_close_soundness_to_gate_lowering` must be
handed before that conclusion follows. Since (a) is now a field in its own right,
this also witnesses that the field cannot be dropped: in this environment the
structure's (a0) holds and its (a) fails. -/
theorem mle_assumption_alone_does_not_yield_close_gate_soundness
    {AggregateProof Path Root ClaimPath ClaimCore : Type}
    (m : TrustBoundary.Models Empty AggregateProof Path Root ClaimPath ClaimCore) :
    TrustBoundary.MleAcceptedStatementsAreSatisfiable (unbackedModels m) ∧
      ¬ (∀ (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes),
          SettlementVerifier.verifyCloseIntent (unbackedModels m).evm (unbackedModels m).installed
              (unbackedModels m).keccak f proof = .ok true →
            ∃ w : CloseCircuit.ProofWitness Empty AggregateProof Path,
              CloseCircuit.CircuitGates (unbackedModels m).closeEnv
                (SettlementCloseBridge.statement (unbackedModels m).keccak f
                  f.minDelegateCount.val) w) := by
  refine ⟨unbacked_environment_satisfies_the_mle_premise m, ?_⟩
  intro lowered
  obtain ⟨w, _⟩ := lowered unbackedCloseFields [] (unbacked_close_is_accepted m)
  exact w.balanceProof.elim

end Zkp.Implementation.SystemSafety
