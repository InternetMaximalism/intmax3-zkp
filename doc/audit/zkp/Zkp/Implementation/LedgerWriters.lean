/-
# `Zkp.Implementation.LedgerWriters` — who may move the replay ledger and the exit latch

**What this module establishes.** Two things, both at the level of the handwritten
models in `ManagerValue` and `CloseFunding`:

1. *A pinned Solidity write-site inventory.* `flaggedWriteSites` lists every place the
   deployed sources assign to one of the five storage variables the durability premises
   of `TrustBoundary` talk about — `usedWithdrawalNullifiers`, `receivedChannelFunds`,
   `totalCreditedOut`, `finalizedChannelFundAmount` and
   `CloseFundingMaterializer.materializedChannelExit`. Each entry carries the contract,
   the variable, the source line, the enclosing Solidity function, the Lean definition
   that models it, and the `SystemSafety.Step` constructor that covers it (or `none`).
   The inventory is re-derived from the Solidity text on every CI run by
   `.github/ci/check-ledger-writers.py`, which also fails if any other `.sol` file under
   `contracts/src` writes one of the five.
2. *Model-level frame theorems.* `ManagerEntrypoint` and `MaterializerEntrypoint`
   enumerate every state-mutating entrypoint the two models define, and `run` gives each
   one the same `State → Option State` shape. Over that enumeration:
   `manager_entrypoints_are_ledger_monotone` (no modeled entrypoint ever clears a used
   nullifier or lowers a per-token cap), `non_step_manager_entrypoints_are_ledger_neutral_except_cap`
   (only the three accounting entrypoints move `received`/`paid`),
   `finalize_close_only_raises_cap` (the exact cap increment), and
   `materializer_entrypoints_keep_the_latch` (no modeled entrypoint clears a latched
   channel exit).

**What this module does NOT establish.** Nothing here says the deployed bytecode has no
other writer. The step from "these are the write sites in the reviewed Solidity text" to
"these are the only transitions the deployed contracts accept" is the source-refinement
premise (h) of `TrustBoundary`, strengthened to the inventory premise (g1'). This module
supplies the model half of (g1)/(g2); the EVM half stays a named premise. The CI check is
a text scan of the reviewed sources, not a bytecode analysis: it cannot see an inline
`sstore` written through an inherited library, a proxy upgrade, or a compiler bug.

**Finding (2026-09-11).** The former (g1) clause `cap t = cap s` for transitions outside
the modeled step relation is refuted by the deployed contract.
`ChannelSettlementManager._finalizeClose` (:1681, reached from `finalizeCloseGuarded`) does
`finalizedChannelFundAmount[baseToken] += ...`, and `finalizeCloseGuarded` is modeled by
`ManagerValue.finalizeCloseCore` but is NOT a `SystemSafety.Step` constructor. The correct
clause is monotonicity, `cap s ≤ cap t`, which is what `manager_entrypoints_are_ledger_monotone`
proves and what `only_cap_writer_is_outside_step` pins as the single exception.
-/
import Zkp.Implementation.ManagerValue
import Zkp.Implementation.CloseFunding

namespace Zkp.Implementation.LedgerWriters

-- The modeled entrypoints are large `Except` `do` blocks; peeling them structurally
-- needs more elaboration depth than the default.
set_option maxRecDepth 100000

/-! ## Peeling helpers for the two `Except` monads

Copied (specialised to any error type) from `ChannelStateUpdate`; the entrypoint bodies
are large `do` blocks and these keep the proofs structural instead of `simp`-driven. -/

theorem bind_ok_iff {ε α β : Type} (r : Except ε α) (f : α → Except ε β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩

theorem throw_ok_iff_false {ε α : Type} (e : ε) (v : α) :
    ((throw e : Except ε α) = .ok v) ↔ False :=
  ⟨fun h => (by cases h), fun h => h.elim⟩

theorem error_ok_iff_false {ε α : Type} (e : ε) (v : α) :
    ((Except.error e : Except ε α) = .ok v) ↔ False :=
  ⟨fun h => (by cases h), fun h => h.elim⟩

theorem ite_ok_iff {ε α : Type} (c : Prop) [Decidable c] (x y : Except ε α) (v : α) :
    ((if c then x else y) = .ok v) ↔ (if c then x = .ok v else y = .ok v) := by
  by_cases hc : c <;> simp [hc]

theorem pure_ok_iff {ε α : Type} (x v : α) : ((pure x : Except ε α) = .ok v) ↔ x = v :=
  ⟨fun h => Except.ok.inj h, fun h => by rw [h]; rfl⟩

theorem ite_false_left {c : Prop} [Decidable c] (p : Prop) :
    (if c then False else p) ↔ (¬c ∧ p) := by
  by_cases hc : c <;> simp [hc]

/-! ## 1. The pinned Solidity write-site inventory -/

/-- One Solidity assignment to a ledger variable the durability premises depend on.
`entrypoint` is the *enclosing* Solidity function (which is what the CI check
re-derives); `modeledBy` names the Lean definition that models the transition and
`stepConstructor` the `SystemSafety.Step` constructor that covers it, if any. -/
structure WriteSite where
  contract : String
  «variable» : String
  line : Nat
  entrypoint : String
  modeledBy : String
  stepConstructor : Option String
  deriving DecidableEq, Repr

/-- The complete write-site inventory of the five flagged variables, as read from the
reviewed Solidity sources. `.github/ci/check-ledger-writers.py` parses this literal and
re-derives it from `contracts/src/ChannelSettlementManager.sol` and
`contracts/src/CloseFundingMaterializer.sol`, so the list cannot rot silently.

* `usedWithdrawalNullifiers` :2231, set-only (`= true`), guarded by the `:2208` read.
* `receivedChannelFunds` :2364, written by the internal `_pullChannelFunds`, reached from
  the external `pullChannelFunds` / `pullChannelTokenFunds`.
* `totalCreditedOut` :2398, `+=` only, guarded by the `:2386` cap check.
* `finalizedChannelFundAmount` :1681, `+=` only, written by the internal `_finalizeClose`,
  reached from the external `finalizeCloseGuarded`.
* `materializedChannelExit` :461, set-only, guarded by the `== 0` check at :434, written by
  the internal `_materialize`, reached from the external `materializeSignedHead`. -/
def flaggedWriteSites : List WriteSite := [
  ⟨"ChannelSettlementManager.sol", "usedWithdrawalNullifiers", 2231, "submitWithdrawalClaim",
    "ManagerValue.submitClaimCore", some "accounting/submitClaim"⟩,
  ⟨"ChannelSettlementManager.sol", "receivedChannelFunds", 2364, "_pullChannelFunds",
    "ManagerValue.pullCore", some "accounting/pull"⟩,
  ⟨"ChannelSettlementManager.sol", "totalCreditedOut", 2398, "claimWithdrawalCredit",
    "ManagerValue.claimCreditCore", some "accounting/payout"⟩,
  ⟨"ChannelSettlementManager.sol", "finalizedChannelFundAmount", 1681, "_finalizeClose",
    "ManagerValue.finalizeCloseCore", none⟩,
  ⟨"CloseFundingMaterializer.sol", "materializedChannelExit", 461, "_materialize",
    "CloseFunding.materializeSignedHead", some "materialize"⟩]

/-- The five storage variables behind the (g1)/(g2) durability premises. -/
def flaggedVariables : List String :=
  ["usedWithdrawalNullifiers", "receivedChannelFunds", "totalCreditedOut",
   "finalizedChannelFundAmount", "materializedChannelExit"]

theorem flagged_write_sites_count : flaggedWriteSites.length = 5 := by decide

theorem flagged_write_sites_cover_every_variable :
    flaggedWriteSites.map (fun w => w.«variable») = flaggedVariables := by decide

theorem each_flagged_variable_has_one_writer :
    flaggedVariables.map
        (fun v => (flaggedWriteSites.filter (fun w => w.«variable» == v)).length) =
      [1, 1, 1, 1, 1] := by decide

/-- The only inventoried write that is not covered by a `SystemSafety.Step` constructor is
the `finalizedChannelFundAmount` cap accrual. This is the refutation of the former (g1)
clause `cap t = cap s`: the deployed contract does raise `cap` outside the step relation. -/
theorem only_cap_writer_is_outside_step :
    (flaggedWriteSites.filter (fun w => w.stepConstructor.isNone)).map (fun w => w.«variable») =
      ["finalizedChannelFundAmount"] := by decide

/-! ## 2. The replay-ledger orders -/

/-- The replay ledger never regresses: no used nullifier is cleared and no per-token
funding cap is lowered. -/
def LedgerMonotone (s t : ManagerValue.State) : Prop :=
  (∀ n, s.used n = true → t.used n = true) ∧ (∀ tok, s.cap tok ≤ t.cap tok)

/-- Monotone *and* value-neutral: the accounted counters and the cap are untouched. -/
def LedgerNeutral (s t : ManagerValue.State) : Prop :=
  LedgerMonotone s t ∧ t.received = s.received ∧ t.paid = s.paid ∧ t.cap = s.cap

/-- The strongest per-entrypoint frame: all four ledger fields are preserved exactly. -/
def FramesLedger (s t : ManagerValue.State) : Prop :=
  t.used = s.used ∧ t.cap = s.cap ∧ t.received = s.received ∧ t.paid = s.paid

theorem ledger_monotone_refl (s : ManagerValue.State) : LedgerMonotone s s :=
  ⟨fun _ h => h, fun _ => Nat.le_refl _⟩

theorem frames_ledger_of_eq {s t : ManagerValue.State} (h : t = s) : FramesLedger s t := by
  subst h; exact ⟨rfl, rfl, rfl, rfl⟩

theorem frames_ledger_is_neutral {s t : ManagerValue.State} (h : FramesLedger s t) :
    LedgerNeutral s t :=
  ⟨⟨fun n hn => by rw [h.1]; exact hn, fun tok => Nat.le_of_eq (congrFun h.2.1.symm tok)⟩,
   h.2.2.1, h.2.2.2, h.2.1⟩

/-! ## 3. Per-definition frame lemmas for `ManagerValue`

Each lemma peels the modeled entrypoint's `Except` block and reports what it does to
`used` / `cap` / `received` / `paid`. Where `ManagerValue` already proves the frame, the
lemma is a projection of the existing theorem. -/

theorem request_full_core_frames_ledger (ext : ManagerValue.FullExternal)
    (b : ManagerValue.Binding) (sender now : Nat) (s t : ManagerValue.FullState)
    (h : ManagerValue.requestFullCore ext b sender now s = .ok t) :
    FramesLedger s.value t.value := by
  simp only [ManagerValue.requestFullCore, Bind.bind, Except.bind, Pure.pure, Except.pure] at h
  repeat' (split at h <;> try contradiction)
  all_goals (cases h; exact ⟨rfl, rfl, rfl, rfl⟩)

theorem request_close_frames_ledger (ext : ManagerValue.FullExternal)
    (b : ManagerValue.Binding) (sender now expectedNonce expectedCancelled : Nat)
    (s t : ManagerValue.FullState)
    (h : ManagerValue.requestClose ext b sender now expectedNonce expectedCancelled s = .ok t) :
    FramesLedger s.value t.value := by
  simp only [ManagerValue.requestClose, Bind.bind, Except.bind, Pure.pure, Except.pure] at h
  repeat' (split at h <;> try contradiction)
  all_goals exact request_full_core_frames_ledger ext b sender now s t h

theorem request_close_as_participant_frames_ledger (ext : ManagerValue.FullExternal)
    (b : ManagerValue.Binding) (sender now slot key : Nat)
    (siblings : Fin 10 → ManagerValue.Digest) (expectedNonce expectedCancelled : Nat)
    (s t : ManagerValue.FullState)
    (h : ManagerValue.requestCloseAsParticipant ext b sender now slot key siblings
      expectedNonce expectedCancelled s = .ok t) :
    FramesLedger s.value t.value := by
  simp only [ManagerValue.requestCloseAsParticipant, Bind.bind, Except.bind, Pure.pure,
    Except.pure] at h
  repeat' (split at h <;> try contradiction)
  all_goals exact request_full_core_frames_ledger ext b sender now s t h

theorem store_pending_frames_value (b : ManagerValue.Binding) (now : Nat)
    (s t : ManagerValue.FullState) (intent : ManagerValue.CloseIntent)
    (digest : ManagerValue.Digest)
    (h : ManagerValue.storePending b now s intent digest = .ok t) : t.value = s.value :=
  (ManagerValue.pending_stores_one_complete_intent b now s t intent digest h).2.2.1

theorem submit_close_intent_frames_ledger (ext : ManagerValue.FullExternal)
    (b : ManagerValue.Binding) (now : Nat) (s t : ManagerValue.FullState)
    (intent : ManagerValue.CloseIntent) (proof : ManagerValue.Proof)
    (h : ManagerValue.submitCloseIntent ext b now s intent proof = .ok t) :
    FramesLedger s.value t.value := by
  simp only [ManagerValue.submitCloseIntent, bind_ok_iff, exists_unit, ite_ok_iff,
    throw_ok_iff_false, error_ok_iff_false, false_and, and_false, true_and, and_true,
    ite_false_left, pure_ok_iff] at h
  split at h
  all_goals (
    repeat' (first | obtain ⟨stored, h⟩ := (h : _ ∧ _) | obtain ⟨_, h⟩ := (h : ∃ _, _))
    subst h
    have framed := store_pending_frames_value _ _ _ _ _ _ stored
    exact frames_ledger_of_eq framed)

theorem cancel_close_frames_ledger (ext : ManagerValue.FullExternal) (b : ManagerValue.Binding)
    (s t : ManagerValue.FullState) (request : ManagerValue.CancelRequest)
    (proof : ManagerValue.Proof)
    (h : ManagerValue.cancelClose ext b s request proof = .ok t) :
    FramesLedger s.value t.value := by
  simp only [ManagerValue.cancelClose, Bind.bind, Except.bind, Pure.pure, Except.pure] at h
  repeat' (split at h <;> try contradiction)
  all_goals (cases h; exact ⟨rfl, rfl, rfl, rfl⟩)

theorem submit_partial_withdrawal_intent_frames_ledger (ext : ManagerValue.FullExternal)
    (b : ManagerValue.Binding) (now : Nat) (s t : ManagerValue.FullState)
    (intent : ManagerValue.CloseIntent) (proof : ManagerValue.Proof)
    (previousChain : ManagerValue.Digest) (burn : ManagerValue.AuthorizedWithdrawal)
    (h : ManagerValue.submitPartialWithdrawalIntent ext b now s intent proof previousChain burn
      = .ok t) :
    FramesLedger s.value t.value := by
  simp only [ManagerValue.submitPartialWithdrawalIntent, bind_ok_iff, exists_unit, ite_ok_iff,
    throw_ok_iff_false, error_ok_iff_false, false_and, and_false, true_and, and_true,
    ite_false_left, pure_ok_iff] at h
  split at h
  all_goals (
    repeat' (first | obtain ⟨_, h⟩ := (h : _ ∧ _) | obtain ⟨_, h⟩ := (h : ∃ _, _))
    subst h
    exact ⟨rfl, rfl, rfl, rfl⟩)

theorem finalize_partial_withdrawal_frames_ledger (ext : ManagerValue.FullExternal)
    (b : ManagerValue.Binding) (now : Nat) (s t : ManagerValue.FullState)
    (h : ManagerValue.finalizePartialWithdrawal ext b now s = .ok t) :
    FramesLedger s.value t.value :=
  frames_ledger_of_eq
    (ManagerValue.partial_withdrawal_finalization_consumes_pending ext b now s t h).2.2.1

theorem cancel_partial_withdrawal_frames_ledger (ext : ManagerValue.FullExternal)
    (b : ManagerValue.Binding) (now : Nat) (s t : ManagerValue.FullState)
    (request : ManagerValue.CancelRequest) (proof : ManagerValue.Proof)
    (h : ManagerValue.cancelPartialWithdrawal ext b now s request proof = .ok t) :
    FramesLedger s.value t.value :=
  frames_ledger_of_eq
    (ManagerValue.cancelled_partial_withdrawal_retains_vectors ext b now s t request proof h).2.2.2.2.2

/-! ### The three accounting entrypoints and the cap accrual

`submitWithdrawalClaim` is the only writer of `used`, `pullChannelFunds` /
`pullChannelTokenFunds` the only writers of `received`, `claimWithdrawalCredit` the only
writer of `paid`, and `finalizeCloseGuarded` the only writer of `cap` — matching
`flaggedWriteSites` one for one. -/

theorem reentrant_before_ok (s locked : ManagerValue.State)
    (h : ManagerValue.reentrantBefore s = .ok locked) : locked = {s with status := 2} := by
  simp only [ManagerValue.reentrantBefore] at h
  split at h
  · exact absurd h (by simp)
  · exact (Except.ok.inj h).symm

theorem with_value_modifiers_ok (cfg : ManagerValue.Config) (s next : ManagerValue.State)
    (body : ManagerValue.State → ManagerValue.Result ManagerValue.State)
    (h : ManagerValue.withValueModifiers cfg s body = .ok next) :
    ∃ done, body {s with status := 2} = .ok done ∧ next = {done with status := 1} := by
  simp only [ManagerValue.withValueModifiers, ManagerValue.withRuntime] at h
  split at h
  · exact absurd h (by simp)
  · split at h
    · exact absurd h (by simp)
    · rename_i locked hb
      rw [reentrant_before_ok s locked hb] at h
      split at h
      · exact absurd h (by simp)
      · rename_i done hd
        exact ⟨done, hd, (Except.ok.inj h).symm⟩

theorem submit_claim_core_of_submit_claim (cfg : ManagerValue.Config)
    (ext : ManagerValue.External) (s v : ManagerValue.State) (c : ManagerValue.Claim)
    (proof : ManagerValue.Proof) (h : ManagerValue.submitClaim cfg ext s c proof = .ok v) :
    ManagerValue.submitClaimCore cfg ext s c proof = .ok v := by
  simp only [ManagerValue.submitClaim, ManagerValue.withRuntime] at h
  split at h
  · exact absurd h (by simp)
  · exact h

theorem pull_core_exact (cfg : ManagerValue.Config) (ext : ManagerValue.External)
    (s next : ManagerValue.State) (token : ManagerValue.Token)
    (h : ManagerValue.pullCore cfg ext s token = .ok next) :
    next = {s with received := ManagerValue.put s.received token (s.cap token)} := by
  dsimp only [ManagerValue.pullCore] at h
  split at h <;> try contradiction
  cases er : ManagerValue.resolveToken ext token with
  | error e => simp only [er] at h
  | ok asset =>
    simp only [er] at h
    split at h <;> try contradiction
    cases em : ext.materialized cfg.materializer cfg.channel <;>
      simp only [em] at h <;> try contradiction
    split at h <;> try contradiction
    cases eb : ext.balance .before s token asset cfg.manager <;>
      simp only [eb] at h <;> try contradiction
    cases ep : ext.pull s token (s.cap token - s.received token) <;>
      simp only [ep] at h <;> try contradiction
    cases ea : ext.balance .after s token asset cfg.manager <;>
      simp only [ea] at h <;> try contradiction
    split at h <;> try contradiction
    split at h <;> try contradiction
    cases h
    rfl

theorem pull_native_frames (cfg : ManagerValue.Config) (ext : ManagerValue.External)
    (s next : ManagerValue.State) (h : ManagerValue.pullNative cfg ext s = .ok next) :
    next.used = s.used ∧ next.cap = s.cap ∧ next.paid = s.paid := by
  simp only [ManagerValue.pullNative] at h
  obtain ⟨done, hd, rfl⟩ := with_value_modifiers_ok cfg s next _ h
  rw [pull_core_exact cfg ext _ done 0 hd]
  exact ⟨rfl, rfl, rfl⟩

theorem pull_token_frames (cfg : ManagerValue.Config) (ext : ManagerValue.External)
    (s next : ManagerValue.State) (token : ManagerValue.Token)
    (h : ManagerValue.pullToken cfg ext s token = .ok next) :
    next.used = s.used ∧ next.cap = s.cap ∧ next.paid = s.paid := by
  simp only [ManagerValue.pullToken] at h
  obtain ⟨done, hd, rfl⟩ := with_value_modifiers_ok cfg s next _ h
  split at hd
  · exact absurd hd (by simp)
  · rw [pull_core_exact cfg ext _ done token hd]
    exact ⟨rfl, rfl, rfl⟩

theorem claim_credit_frames (cfg : ManagerValue.Config) (ext : ManagerValue.External)
    (s next : ManagerValue.State) (sender nullifier : Nat)
    (h : ManagerValue.claimCredit cfg ext s sender nullifier = .ok next) :
    next.used = s.used ∧ next.cap = s.cap ∧ next.received = s.received := by
  simp only [ManagerValue.claimCredit] at h
  obtain ⟨done, hd, rfl⟩ := with_value_modifiers_ok cfg s next _ h
  rw [(ManagerValue.payout_success_exact_effects ext _ done sender nullifier hd).1]
  exact ⟨rfl, rfl, rfl⟩

theorem submit_withdrawal_claim_effects (b : ManagerValue.Binding) (ext : ManagerValue.External)
    (s t : ManagerValue.FullState) (c : ManagerValue.Claim) (proof : ManagerValue.Proof)
    (h : ManagerValue.submitWithdrawalClaim b ext s c proof = .ok t) :
    t.value = ManagerValue.claimEffects s.value c := by
  simp only [ManagerValue.submitWithdrawalClaim, bind_ok_iff, pure_ok_iff] at h
  obtain ⟨value, hv, rfl⟩ := h
  exact ManagerValue.submit_success_effects b.config ext s.value value c proof
    (submit_claim_core_of_submit_claim b.config ext s.value value c proof hv)

theorem claim_effects_keep_used (s : ManagerValue.State) (c : ManagerValue.Claim)
    (n : ManagerValue.Digest) (live : s.used n = true) :
    (ManagerValue.claimEffects s c).used n = true := by
  simp only [ManagerValue.claimEffects, ManagerValue.put]
  split
  · rfl
  · exact live

theorem pull_channel_funds_frames (b : ManagerValue.Binding) (ext : ManagerValue.External)
    (s t : ManagerValue.FullState) (amount : Nat)
    (h : ManagerValue.pullChannelFunds b ext s = .ok (t, amount)) :
    t.value.used = s.value.used ∧ t.value.cap = s.value.cap ∧ t.value.paid = s.value.paid := by
  simp only [ManagerValue.pullChannelFunds, bind_ok_iff, pure_ok_iff] at h
  obtain ⟨value, hv, hpair⟩ := h
  injection hpair with hstate _
  subst hstate
  exact pull_native_frames b.config ext s.value value hv

theorem pull_channel_token_funds_frames (b : ManagerValue.Binding) (ext : ManagerValue.External)
    (s t : ManagerValue.FullState) (token amount : Nat)
    (h : ManagerValue.pullChannelTokenFunds b ext s token = .ok (t, amount)) :
    t.value.used = s.value.used ∧ t.value.cap = s.value.cap ∧ t.value.paid = s.value.paid := by
  simp only [ManagerValue.pullChannelTokenFunds, bind_ok_iff, pure_ok_iff] at h
  obtain ⟨value, hv, hpair⟩ := h
  injection hpair with hstate _
  subst hstate
  exact pull_token_frames b.config ext s.value value token hv

theorem claim_withdrawal_credit_frames (b : ManagerValue.Binding) (ext : ManagerValue.External)
    (s t : ManagerValue.FullState) (sender nullifier amount : Nat)
    (h : ManagerValue.claimWithdrawalCredit b ext s sender nullifier = .ok (t, amount)) :
    t.value.used = s.value.used ∧ t.value.cap = s.value.cap ∧
      t.value.received = s.value.received := by
  simp only [ManagerValue.claimWithdrawalCredit, bind_ok_iff, pure_ok_iff] at h
  obtain ⟨value, hv, hpair⟩ := h
  injection hpair with hstate _
  subst hstate
  exact claim_credit_frames b.config ext s.value value sender nullifier hv

theorem finalize_close_core_frames_replay (ext : ManagerValue.FullExternal)
    (b : ManagerValue.Binding) (now : Nat) (s t : ManagerValue.FullState)
    (h : ManagerValue.finalizeCloseCore ext b now s = .ok t) :
    t.value.used = s.value.used ∧ t.value.received = s.value.received ∧
      t.value.paid = s.value.paid := by
  simp only [ManagerValue.finalizeCloseCore, bind_ok_iff, exists_unit, ite_ok_iff,
    throw_ok_iff_false, error_ok_iff_false, false_and, and_false, true_and, and_true,
    ite_false_left, pure_ok_iff] at h
  repeat' (first | obtain ⟨_, h⟩ := (h : _ ∧ _) | obtain ⟨_, h⟩ := (h : ∃ _, _))
  subst h
  exact ⟨rfl, rfl, rfl⟩

theorem finalize_close_core_of_guarded (ext : ManagerValue.FullExternal)
    (b : ManagerValue.Binding) (now expectedDigest expectedGeneration : Nat)
    (s t : ManagerValue.FullState)
    (h : ManagerValue.finalizeCloseGuarded ext b now expectedDigest expectedGeneration s = .ok t) :
    ManagerValue.finalizeCloseCore ext b now s = .ok t := by
  simp only [ManagerValue.finalizeCloseGuarded, bind_ok_iff, exists_unit, ite_ok_iff,
    throw_ok_iff_false, error_ok_iff_false, false_and, and_false, true_and, and_true,
    ite_false_left] at h
  repeat' (first | obtain ⟨_, h⟩ := (h : _ ∧ _) | obtain ⟨_, h⟩ := (h : ∃ _, _))
  exact h

/-! ## 4. The `ManagerValue` entrypoint enumeration

Every state-mutating entrypoint `ManagerValue` models, at the outermost (externally
callable) level, so that `run` has one uniform shape. `requestCloseCore`, `requestFullCore`,
`submitClaimCore`, `pullCore`, `claimCreditCore` and `finalizeCloseCore` are the inner
bodies of these constructors and are reached through them. -/
inductive ManagerEntrypoint where
  /-- `receive()` — refuses any sender but the Rollup and changes no storage. -/
  | receiveNative (cfg : ManagerValue.Config) (sender : ManagerValue.Address)
  | requestClose (ext : ManagerValue.FullExternal) (b : ManagerValue.Binding)
      (sender now expectedNonce expectedCancelled : Nat)
  | requestCloseAsParticipant (ext : ManagerValue.FullExternal) (b : ManagerValue.Binding)
      (sender now slot key : Nat) (siblings : Fin 10 → ManagerValue.Digest)
      (expectedNonce expectedCancelled : Nat)
  | submitCloseIntent (ext : ManagerValue.FullExternal) (b : ManagerValue.Binding) (now : Nat)
      (intent : ManagerValue.CloseIntent) (proof : ManagerValue.Proof)
  | cancelClose (ext : ManagerValue.FullExternal) (b : ManagerValue.Binding)
      (request : ManagerValue.CancelRequest) (proof : ManagerValue.Proof)
  /-- The single `cap` writer: `_finalizeClose` :1681. -/
  | finalizeCloseGuarded (ext : ManagerValue.FullExternal) (b : ManagerValue.Binding)
      (now expectedDigest expectedGeneration : Nat)
  | submitPartialWithdrawalIntent (ext : ManagerValue.FullExternal) (b : ManagerValue.Binding)
      (now : Nat) (intent : ManagerValue.CloseIntent) (proof : ManagerValue.Proof)
      (previousChain : ManagerValue.Digest) (burn : ManagerValue.AuthorizedWithdrawal)
  | finalizePartialWithdrawal (ext : ManagerValue.FullExternal) (b : ManagerValue.Binding)
      (now : Nat)
  | cancelPartialWithdrawal (ext : ManagerValue.FullExternal) (b : ManagerValue.Binding)
      (now : Nat) (request : ManagerValue.CancelRequest) (proof : ManagerValue.Proof)
  /-- The single `usedWithdrawalNullifiers` writer: :2231. -/
  | submitWithdrawalClaim (b : ManagerValue.Binding) (ext : ManagerValue.External)
      (claim : ManagerValue.Claim) (proof : ManagerValue.Proof)
  /-- `receivedChannelFunds` writer :2364, native lane. -/
  | pullChannelFunds (b : ManagerValue.Binding) (ext : ManagerValue.External)
  /-- `receivedChannelFunds` writer :2364, token lane. -/
  | pullChannelTokenFunds (b : ManagerValue.Binding) (ext : ManagerValue.External) (token : Nat)
  /-- The single `totalCreditedOut` writer: :2398. -/
  | claimWithdrawalCredit (b : ManagerValue.Binding) (ext : ManagerValue.External)
      (sender nullifier : Nat)

def optionOfResult (r : ManagerValue.Result ManagerValue.FullState) :
    Option ManagerValue.FullState :=
  match r with
  | .ok t => some t
  | .error _ => none

def optionOfPair (r : ManagerValue.Result (ManagerValue.FullState × Nat)) :
    Option ManagerValue.FullState :=
  match r with
  | .ok p => some p.1
  | .error _ => none

theorem option_of_result_some (r : ManagerValue.Result ManagerValue.FullState)
    (t : ManagerValue.FullState) (h : optionOfResult r = some t) : r = .ok t := by
  cases r with
  | error e => simp only [optionOfResult] at h
  | ok u => simp only [optionOfResult, Option.some.injEq] at h; exact congrArg Except.ok h

theorem option_of_pair_some (r : ManagerValue.Result (ManagerValue.FullState × Nat))
    (t : ManagerValue.FullState) (h : optionOfPair r = some t) : ∃ n, r = .ok (t, n) := by
  cases r with
  | error e => simp only [optionOfPair] at h
  | ok p =>
    simp only [optionOfPair, Option.some.injEq] at h
    exact ⟨p.2, by rw [← h]⟩

/-- The state projection of one modeled Manager call. The pair-returning entrypoints keep
their returned amount out of the state, so only the `FullState` component is projected. -/
def ManagerEntrypoint.run :
    ManagerEntrypoint → ManagerValue.FullState → Option ManagerValue.FullState
  | .receiveNative cfg sender, s =>
      match ManagerValue.receiveNative cfg sender with
      | .ok _ => some s
      | .error _ => none
  | .requestClose ext b sender now expectedNonce expectedCancelled, s =>
      optionOfResult (ManagerValue.requestClose ext b sender now expectedNonce expectedCancelled s)
  | .requestCloseAsParticipant ext b sender now slot key siblings expectedNonce expectedCancelled, s =>
      optionOfResult (ManagerValue.requestCloseAsParticipant ext b sender now slot key siblings
        expectedNonce expectedCancelled s)
  | .submitCloseIntent ext b now intent proof, s =>
      optionOfResult (ManagerValue.submitCloseIntent ext b now s intent proof)
  | .cancelClose ext b request proof, s =>
      optionOfResult (ManagerValue.cancelClose ext b s request proof)
  | .finalizeCloseGuarded ext b now expectedDigest expectedGeneration, s =>
      optionOfResult (ManagerValue.finalizeCloseGuarded ext b now expectedDigest
        expectedGeneration s)
  | .submitPartialWithdrawalIntent ext b now intent proof previousChain burn, s =>
      optionOfResult (ManagerValue.submitPartialWithdrawalIntent ext b now s intent proof
        previousChain burn)
  | .finalizePartialWithdrawal ext b now, s =>
      optionOfResult (ManagerValue.finalizePartialWithdrawal ext b now s)
  | .cancelPartialWithdrawal ext b now request proof, s =>
      optionOfResult (ManagerValue.cancelPartialWithdrawal ext b now s request proof)
  | .submitWithdrawalClaim b ext claim proof, s =>
      optionOfResult (ManagerValue.submitWithdrawalClaim b ext s claim proof)
  | .pullChannelFunds b ext, s => optionOfPair (ManagerValue.pullChannelFunds b ext s)
  | .pullChannelTokenFunds b ext token, s =>
      optionOfPair (ManagerValue.pullChannelTokenFunds b ext s token)
  | .claimWithdrawalCredit b ext sender nullifier, s =>
      optionOfPair (ManagerValue.claimWithdrawalCredit b ext s sender nullifier)

/-- The three entrypoints `SystemSafety.Step.accounting` covers, i.e. exactly the
`submitClaim` / `pull` / `payout` rows of `flaggedWriteSites`. -/
def ManagerEntrypoint.stepCovered : ManagerEntrypoint → Bool
  | .submitWithdrawalClaim _ _ _ _ => true
  | .pullChannelFunds _ _ => true
  | .pullChannelTokenFunds _ _ _ => true
  | .claimWithdrawalCredit _ _ _ _ => true
  | _ => false

/-- The one entrypoint that raises `cap`: the `finalizedChannelFundAmount` accrual. It is
NOT a `Step` constructor, which is what refutes (g1)'s former `cap t = cap s` clause. -/
def ManagerEntrypoint.raisesCap : ManagerEntrypoint → Bool
  | .finalizeCloseGuarded _ _ _ _ _ => true
  | _ => false

/-- The classification every modeled Manager entrypoint satisfies. -/
def Classified (covered raises : Bool) (s t : ManagerValue.State) : Prop :=
  (∀ n, s.used n = true → t.used n = true) ∧ (∀ tok, s.cap tok ≤ t.cap tok) ∧
  (covered = false → t.received = s.received ∧ t.paid = s.paid) ∧
  (raises = false → t.cap = s.cap)

theorem classified_of_frames {covered raises : Bool} {s t : ManagerValue.State}
    (h : FramesLedger s t) : Classified covered raises s t :=
  ⟨fun n hn => by rw [h.1]; exact hn, fun tok => Nat.le_of_eq (congrFun h.2.1.symm tok),
   fun _ => ⟨h.2.2.1, h.2.2.2⟩, fun _ => h.2.1⟩

/-- **Headline classification.** Every modeled Manager entrypoint keeps the replay ledger
monotone; only the three `Step`-covered accounting entrypoints touch `received`/`paid`; and
only `finalizeCloseGuarded` touches `cap`. -/
theorem manager_entrypoints_are_classified (call : ManagerEntrypoint)
    (s t : ManagerValue.FullState) (h : call.run s = some t) :
    Classified call.stepCovered call.raisesCap s.value t.value := by
  cases call with
  | receiveNative cfg sender =>
    simp only [ManagerEntrypoint.run] at h
    split at h
    · cases h
      exact ⟨fun _ hn => hn, fun _ => Nat.le_refl _, fun _ => ⟨rfl, rfl⟩, fun _ => rfl⟩
    · exact absurd h (by simp)
  | requestClose ext b sender now expectedNonce expectedCancelled =>
    exact classified_of_frames (request_close_frames_ledger ext b sender now expectedNonce
      expectedCancelled s t (option_of_result_some _ t h))
  | requestCloseAsParticipant ext b sender now slot key siblings expectedNonce expectedCancelled =>
    exact classified_of_frames (request_close_as_participant_frames_ledger ext b sender now slot
      key siblings expectedNonce expectedCancelled s t (option_of_result_some _ t h))
  | submitCloseIntent ext b now intent proof =>
    exact classified_of_frames (submit_close_intent_frames_ledger ext b now s t intent proof
      (option_of_result_some _ t h))
  | cancelClose ext b request proof =>
    exact classified_of_frames (cancel_close_frames_ledger ext b s t request proof
      (option_of_result_some _ t h))
  | finalizeCloseGuarded ext b now expectedDigest expectedGeneration =>
    have core := finalize_close_core_of_guarded ext b now expectedDigest expectedGeneration s t
      (option_of_result_some _ t h)
    have replay := finalize_close_core_frames_replay ext b now s t core
    refine ⟨fun n hn => by rw [replay.1]; exact hn, fun tok => ?_, fun _ => ⟨replay.2.1, replay.2.2⟩,
      fun raises => absurd raises (by simp [ManagerEntrypoint.raisesCap])⟩
    rw [ManagerValue.finalize_full_token_vector ext b now s t core tok]
    exact Nat.le_add_right _ _
  | submitPartialWithdrawalIntent ext b now intent proof previousChain burn =>
    exact classified_of_frames (submit_partial_withdrawal_intent_frames_ledger ext b now s t
      intent proof previousChain burn (option_of_result_some _ t h))
  | finalizePartialWithdrawal ext b now =>
    exact classified_of_frames (finalize_partial_withdrawal_frames_ledger ext b now s t
      (option_of_result_some _ t h))
  | cancelPartialWithdrawal ext b now request proof =>
    exact classified_of_frames (cancel_partial_withdrawal_frames_ledger ext b now s t request
      proof (option_of_result_some _ t h))
  | submitWithdrawalClaim b ext claim proof =>
    have effects := submit_withdrawal_claim_effects b ext s t claim proof
      (option_of_result_some _ t h)
    refine ⟨fun n hn => ?_, fun tok => ?_,
      fun covered => absurd covered (by simp [ManagerEntrypoint.stepCovered]), fun _ => ?_⟩
    · rw [effects]; exact claim_effects_keep_used s.value claim n hn
    · rw [effects]; exact Nat.le_refl _
    · rw [effects]; rfl
  | pullChannelFunds b ext =>
    obtain ⟨amount, call⟩ := option_of_pair_some _ t h
    have framed := pull_channel_funds_frames b ext s t amount call
    exact ⟨fun n hn => by rw [framed.1]; exact hn,
      fun tok => Nat.le_of_eq (congrFun framed.2.1.symm tok),
      fun covered => absurd covered (by simp [ManagerEntrypoint.stepCovered]),
      fun _ => framed.2.1⟩
  | pullChannelTokenFunds b ext token =>
    obtain ⟨amount, call⟩ := option_of_pair_some _ t h
    have framed := pull_channel_token_funds_frames b ext s t token amount call
    exact ⟨fun n hn => by rw [framed.1]; exact hn,
      fun tok => Nat.le_of_eq (congrFun framed.2.1.symm tok),
      fun covered => absurd covered (by simp [ManagerEntrypoint.stepCovered]),
      fun _ => framed.2.1⟩
  | claimWithdrawalCredit b ext sender nullifier =>
    obtain ⟨amount, call⟩ := option_of_pair_some _ t h
    have framed := claim_withdrawal_credit_frames b ext s t sender nullifier amount call
    exact ⟨fun n hn => by rw [framed.1]; exact hn,
      fun tok => Nat.le_of_eq (congrFun framed.2.1.symm tok),
      fun covered => absurd covered (by simp [ManagerEntrypoint.stepCovered]),
      fun _ => framed.2.1⟩

/-- **(g1), model half.** No modeled Manager entrypoint clears a used withdrawal nullifier
and none lowers a per-token funding cap. -/
theorem manager_entrypoints_are_ledger_monotone (call : ManagerEntrypoint)
    (s t : ManagerValue.FullState) (h : call.run s = some t) :
    LedgerMonotone s.value t.value :=
  ⟨(manager_entrypoints_are_classified call s t h).1,
   (manager_entrypoints_are_classified call s t h).2.1⟩

/-- **(g1), frame half.** Outside the three `Step`-covered accounting entrypoints the
accounted counters do not move; `cap` is excluded because `finalizeCloseGuarded` raises it. -/
theorem non_step_manager_entrypoints_are_ledger_neutral_except_cap (call : ManagerEntrypoint)
    (s t : ManagerValue.FullState) (outside : call.stepCovered = false)
    (h : call.run s = some t) :
    (∀ n, s.value.used n = true → t.value.used n = true) ∧
      t.value.received = s.value.received ∧ t.value.paid = s.value.paid :=
  ⟨(manager_entrypoints_are_classified call s t h).1,
   ((manager_entrypoints_are_classified call s t h).2.2.1 outside).1,
   ((manager_entrypoints_are_classified call s t h).2.2.1 outside).2⟩

/-- The entrypoints that are neither `Step`-covered nor the cap accrual are fully
value-neutral. -/
theorem lifecycle_manager_entrypoints_are_ledger_neutral (call : ManagerEntrypoint)
    (s t : ManagerValue.FullState) (outside : call.stepCovered = false)
    (still : call.raisesCap = false) (h : call.run s = some t) :
    LedgerNeutral s.value t.value :=
  ⟨manager_entrypoints_are_ledger_monotone call s t h,
   ((manager_entrypoints_are_classified call s t h).2.2.1 outside).1,
   ((manager_entrypoints_are_classified call s t h).2.2.1 outside).2,
   (manager_entrypoints_are_classified call s t h).2.2.2 still⟩

/-- **The exact cap accrual of the one writer outside the step relation.** Solidity :1681
adds `pendingClose.channelFundAmounts[t]` into `finalizedChannelFundAmount[baseToken]` for
each active registry slot; `ManagerValue.vectorContribution` is that sum. -/
theorem finalize_close_only_raises_cap (ext : ManagerValue.FullExternal)
    (b : ManagerValue.Binding) (now expectedDigest expectedGeneration : Nat)
    (s t : ManagerValue.FullState)
    (h : (ManagerEntrypoint.finalizeCloseGuarded ext b now expectedDigest
      expectedGeneration).run s = some t) (token : Nat) :
    t.value.cap token = s.value.cap token +
      ManagerValue.vectorContribution s.pending.intent.registry s.pending.intent.funds token
        s.pending.intent.tokenCount 0 :=
  ManagerValue.finalize_full_token_vector ext b now s t
    (finalize_close_core_of_guarded ext b now expectedDigest expectedGeneration s t
      (option_of_result_some _ t h)) token

/-! ## 5. The `CloseFunding` entrypoint enumeration and the exit latch

`materializedChannelExit` is written in exactly one place (`_materialize` :461, guarded by
the `== 0` read at :434). The five other state-mutating entrypoints of the materializer do
not touch it at all, and `_materialize` itself can only write a channel whose latch is
still zero — so a latched channel exit is never rewritten. -/

theorem bind_manager_frames_latch (e : CloseFunding.Environment) (s : CloseFunding.State)
    (caller manager : CloseFunding.Address) (u : CloseFunding.Update)
    (h : CloseFunding.bindManager e s caller manager = .ok u) :
    u.1.materializedChannelExit = s.materializedChannelExit := by
  simp only [CloseFunding.bindManager, CloseFunding.onlyRollup, CloseFunding.require,
    bind_ok_iff, exists_unit, ite_ok_iff, throw_ok_iff_false, error_ok_iff_false,
    false_and, and_false, true_and, and_true, ite_false_left, pure_ok_iff] at h
  repeat' (first | obtain ⟨_, h⟩ := (h : _ ∧ _) | obtain ⟨_, h⟩ := (h : ∃ _, _) | split at h)
  all_goals (subst h; rfl)

theorem freeze_from_manager_frames_latch (e : CloseFunding.Environment) (s : CloseFunding.State)
    (caller : CloseFunding.Address) (channel generation : Nat) (u : CloseFunding.Update)
    (h : CloseFunding.freezeFromManager e s caller channel generation = .ok u) :
    u.1.materializedChannelExit = s.materializedChannelExit := by
  simp only [CloseFunding.freezeFromManager, CloseFunding.require, bind_ok_iff, exists_unit,
    ite_ok_iff, throw_ok_iff_false, error_ok_iff_false, false_and, and_false, true_and,
    and_true, ite_false_left, pure_ok_iff] at h
  repeat' (first | obtain ⟨_, h⟩ := (h : _ ∧ _) | obtain ⟨_, h⟩ := (h : ∃ _, _) | split at h)
  all_goals (subst h; rfl)

theorem unfreeze_from_manager_frames_latch (s : CloseFunding.State)
    (caller : CloseFunding.Address) (channel generation : Nat) (u : CloseFunding.Update)
    (h : CloseFunding.unfreezeFromManager s caller channel generation = .ok u) :
    u.1.materializedChannelExit = s.materializedChannelExit := by
  simp only [CloseFunding.unfreezeFromManager, CloseFunding.require, bind_ok_iff, exists_unit,
    ite_ok_iff, throw_ok_iff_false, error_ok_iff_false, false_and, and_false, true_and,
    and_true, ite_false_left, pure_ok_iff] at h
  repeat' (first | obtain ⟨_, h⟩ := (h : _ ∧ _) | obtain ⟨_, h⟩ := (h : ∃ _, _) | split at h)
  all_goals (subst h; rfl)

theorem record_post_frames_latch (e : CloseFunding.Environment) (s : CloseFunding.State)
    (caller : CloseFunding.Address) (channel block : Nat) (u : CloseFunding.Update)
    (h : CloseFunding.recordPost e s caller channel block = .ok u) :
    u.1.materializedChannelExit = s.materializedChannelExit := by
  simp only [CloseFunding.recordPost, CloseFunding.onlyRollup, CloseFunding.require,
    bind_ok_iff, exists_unit, ite_ok_iff, throw_ok_iff_false, error_ok_iff_false,
    false_and, and_false, true_and, and_true, ite_false_left, pure_ok_iff] at h
  repeat' (first | obtain ⟨_, h⟩ := (h : _ ∧ _) | obtain ⟨_, h⟩ := (h : ∃ _, _) | split at h)
  all_goals (subst h; rfl)

theorem rollback_post_frames_latch (e : CloseFunding.Environment) (s : CloseFunding.State)
    (caller : CloseFunding.Address) (block : Nat) (u : CloseFunding.Update)
    (h : CloseFunding.rollbackPost e s caller block = .ok u) :
    u.1.materializedChannelExit = s.materializedChannelExit := by
  simp only [CloseFunding.rollbackPost, CloseFunding.onlyRollup, CloseFunding.require,
    bind_ok_iff, exists_unit, ite_ok_iff, throw_ok_iff_false, error_ok_iff_false,
    false_and, and_false, true_and, and_true, ite_false_left, pure_ok_iff] at h
  repeat' (first | obtain ⟨_, h⟩ := (h : _ ∧ _) | obtain ⟨_, h⟩ := (h : ∃ _, _) | split at h)
  all_goals (subst h; rfl)

theorem attest_frames_latch (e : CloseFunding.Environment) (s : CloseFunding.State)
    (manager : CloseFunding.Address) (proof : CloseFunding.Bytes) (u : CloseFunding.Update)
    (h : CloseFunding.attestSignedHeadBacking e s manager proof = .ok u) :
    u.1.materializedChannelExit = s.materializedChannelExit := by
  simp only [CloseFunding.attestSignedHeadBacking, bind_ok_iff, exists_unit, ite_ok_iff,
    throw_ok_iff_false, error_ok_iff_false, false_and, and_false, true_and, and_true,
    ite_false_left, pure_ok_iff] at h
  repeat' (first | obtain ⟨_, h⟩ := (h : _ ∧ _) | obtain ⟨_, h⟩ := (h : ∃ _, _) | split at h)
  all_goals (subst h; rfl)

/-- The one-shot property of the single latch writer: `_materialize` can only latch a
channel whose `materializedChannelExit` is still zero (:434), so an already-latched channel
keeps its digest. This is the model half of (g2). -/
theorem materialize_frames_live_latches (e : CloseFunding.Environment)
    (before after : CloseFunding.World) (manager : CloseFunding.Address)
    (proof : CloseFunding.Bytes) (events : List CloseFunding.Event)
    (h : CloseFunding.materializeSignedHead e before manager proof = .ok (after, events))
    (c : CloseFunding.Channel) (live : before.storage.materializedChannelExit c ≠ 0) :
    after.storage.materializedChannelExit c = before.storage.materializedChannelExit c := by
  obtain ⟨p, prepared, latched, _⟩ := CloseFunding.materialization_call_exact_accounting h
  obtain ⟨_, anchor, checks⟩ :=
    CloseFunding.prepared_signed_head_requires_receipt_and_local_checks prepared
  have zero := (CloseFunding.prepared_materialization_guards checks).2.2.2.2.1
  have distinct : ¬ c = p.channel := by
    intro same
    rw [same] at live
    exact live zero
  rw [latched]
  simp only [CloseFunding.latchState, CloseFunding.put, if_neg distinct]

inductive MaterializerEntrypoint where
  | bindManager (e : CloseFunding.Environment) (caller manager : CloseFunding.Address)
  | freezeFromManager (e : CloseFunding.Environment) (caller : CloseFunding.Address)
      (channel generation : Nat)
  | unfreezeFromManager (caller : CloseFunding.Address) (channel generation : Nat)
  | recordPost (e : CloseFunding.Environment) (caller : CloseFunding.Address)
      (channel block : Nat)
  | rollbackPost (e : CloseFunding.Environment) (caller : CloseFunding.Address) (block : Nat)
  | attestSignedHeadBacking (e : CloseFunding.Environment) (manager : CloseFunding.Address)
      (proof : CloseFunding.Bytes)
  /-- The single `materializedChannelExit` writer: `_materialize` :461. -/
  | materializeSignedHead (e : CloseFunding.Environment) (manager : CloseFunding.Address)
      (proof : CloseFunding.Bytes)

def optionOfUpdate (w : CloseFunding.World) (r : CloseFunding.Result CloseFunding.Update) :
    Option CloseFunding.World :=
  match r with
  | .ok u => some ⟨u.1, w.ledger⟩
  | .error _ => none

def optionOfWorld (r : CloseFunding.Result (CloseFunding.World × List CloseFunding.Event)) :
    Option CloseFunding.World :=
  match r with
  | .ok u => some u.1
  | .error _ => none

theorem option_of_update_some (w v : CloseFunding.World)
    (r : CloseFunding.Result CloseFunding.Update) (h : optionOfUpdate w r = some v) :
    ∃ u, r = .ok u ∧ v.storage = u.1 := by
  cases r with
  | error e => simp only [optionOfUpdate] at h
  | ok u =>
    simp only [optionOfUpdate, Option.some.injEq] at h
    exact ⟨u, rfl, by rw [← h]⟩

theorem option_of_world_some (r : CloseFunding.Result (CloseFunding.World × List CloseFunding.Event))
    (v : CloseFunding.World) (h : optionOfWorld r = some v) : ∃ events, r = .ok (v, events) := by
  cases r with
  | error e => simp only [optionOfWorld] at h
  | ok u =>
    simp only [optionOfWorld, Option.some.injEq] at h
    exact ⟨u.2, by rw [← h]⟩

/-- The world projection of one modeled materializer call. The five journalling
entrypoints do not touch the Rollup ledger, so they carry it through unchanged. -/
def MaterializerEntrypoint.run :
    MaterializerEntrypoint → CloseFunding.World → Option CloseFunding.World
  | .bindManager e caller manager, w =>
      optionOfUpdate w (CloseFunding.bindManager e w.storage caller manager)
  | .freezeFromManager e caller channel generation, w =>
      optionOfUpdate w (CloseFunding.freezeFromManager e w.storage caller channel generation)
  | .unfreezeFromManager caller channel generation, w =>
      optionOfUpdate w (CloseFunding.unfreezeFromManager w.storage caller channel generation)
  | .recordPost e caller channel block, w =>
      optionOfUpdate w (CloseFunding.recordPost e w.storage caller channel block)
  | .rollbackPost e caller block, w =>
      optionOfUpdate w (CloseFunding.rollbackPost e w.storage caller block)
  | .attestSignedHeadBacking e manager proof, w =>
      optionOfUpdate w (CloseFunding.attestSignedHeadBacking e w.storage manager proof)
  | .materializeSignedHead e manager proof, w =>
      optionOfWorld (CloseFunding.materializeSignedHead e w manager proof)

/-- **(g2), model half.** No modeled materializer entrypoint clears or rewrites a channel
exit that has already been latched. -/
theorem materializer_entrypoints_keep_the_latch (call : MaterializerEntrypoint)
    (w v : CloseFunding.World) (h : call.run w = some v) (c : CloseFunding.Channel)
    (live : w.storage.materializedChannelExit c ≠ 0) :
    v.storage.materializedChannelExit c = w.storage.materializedChannelExit c := by
  cases call with
  | bindManager e caller manager =>
    simp only [MaterializerEntrypoint.run] at h
    obtain ⟨u, accepted, storage⟩ := option_of_update_some w v _ h
    rw [storage]
    exact congrFun (bind_manager_frames_latch e w.storage caller manager u accepted) c
  | freezeFromManager e caller channel generation =>
    simp only [MaterializerEntrypoint.run] at h
    obtain ⟨u, accepted, storage⟩ := option_of_update_some w v _ h
    rw [storage]
    exact congrFun
      (freeze_from_manager_frames_latch e w.storage caller channel generation u accepted) c
  | unfreezeFromManager caller channel generation =>
    simp only [MaterializerEntrypoint.run] at h
    obtain ⟨u, accepted, storage⟩ := option_of_update_some w v _ h
    rw [storage]
    exact congrFun
      (unfreeze_from_manager_frames_latch w.storage caller channel generation u accepted) c
  | recordPost e caller channel block =>
    simp only [MaterializerEntrypoint.run] at h
    obtain ⟨u, accepted, storage⟩ := option_of_update_some w v _ h
    rw [storage]
    exact congrFun (record_post_frames_latch e w.storage caller channel block u accepted) c
  | rollbackPost e caller block =>
    simp only [MaterializerEntrypoint.run] at h
    obtain ⟨u, accepted, storage⟩ := option_of_update_some w v _ h
    rw [storage]
    exact congrFun (rollback_post_frames_latch e w.storage caller block u accepted) c
  | attestSignedHeadBacking e manager proof =>
    simp only [MaterializerEntrypoint.run] at h
    obtain ⟨u, accepted, storage⟩ := option_of_update_some w v _ h
    rw [storage]
    exact congrFun (attest_frames_latch e w.storage manager proof u accepted) c
  | materializeSignedHead e manager proof =>
    simp only [MaterializerEntrypoint.run] at h
    obtain ⟨events, accepted⟩ := option_of_world_some _ v h
    exact materialize_frames_live_latches e w v manager proof events accepted c live

/-! ## 6. Non-vacuity

Both enumerations contain entrypoints that actually run: the frame theorems above are not
vacuously true for lack of a successful call. -/

def sampleLedger : CloseFunding.Ledger := ⟨fun _ => 0, fun _ _ => 0⟩

/-- Channel 7 bound to manager 9 at block 12, then frozen at generation 5. -/
def sampleFundingWorld : CloseFunding.World :=
  ⟨CloseFunding.freezeState (CloseFunding.bindState CloseFunding.empty 7 9 12) 7 5, sampleLedger⟩

theorem sample_materializer_entrypoint_runs :
    ((MaterializerEntrypoint.unfreezeFromManager 9 7 5).run sampleFundingWorld).map
      (fun v => v.storage.frozenGeneration 7) = some 0 := by rfl

theorem sample_manager_entrypoint_runs :
    (match ManagerValue.normalFullSetup with
      | .error _ => none
      | .ok (b, s) =>
        ((ManagerEntrypoint.requestClose ManagerValue.normalFullExternal b 23 0 0 0).run s).map
          (fun t => t.value.lifecycle)) = some ManagerValue.Lifecycle.pending := by rfl

end Zkp.Implementation.LedgerWriters
