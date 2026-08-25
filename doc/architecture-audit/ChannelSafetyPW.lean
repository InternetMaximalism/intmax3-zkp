/-
# ChannelSafetyPW.lean — partial withdrawal, channel-state side (audit25-08-2026 Part 3 V3)

The implementation Lean models partial withdrawal ONLY as an L1 gate
(`Contracts/ChannelSettlementManager.lean:125-166`: submit requires a close-shaped proof, finalize
mints only pending, chain-key single-use) — and its `cancelPartial` is DEFINED WITHOUT A THEOREM.
The spec-side corpus has zero partial-withdrawal modeling (`audit25-08-2026` Part 1(b)). A cancel
with no theorem is where an honest-exit failure or a restore-arithmetic bug hides.

This file models the CHANNEL-STATE accounting of the partial-withdrawal lifecycle — burn intent →
(cancel | finalize) → claim — and proves the conservation, single-use, and R1 availability
properties, both directions.

## Trust base

  (A2) The burn's solvency side condition (`amount ≤ fund`) is the balance-proof obligation; it
       appears as the `burn` step's guard, exactly where `close_no_overdraw` places it.
  (A4) L1 enforces the guards — this file IS the guard model, as in ChannelSafetyClose.

## Not modeled (honest)

  * The close-shaped proof content of `submitPartialWithdrawalIntent` (implementation-Lean's
    `submitPartialIntent_requires_proof` covers the gate); here the burn step ABSTRACTS a
    co-signed, proof-backed debit.
  * Multi-token: single-token fund, as the v1/v2 lineage; the MT frame lemmas live in
    ChannelSafetyMT.
  * L1 inclusion/censorship — the standing liveness exclusion of this corpus.
-/

namespace ChannelSafetyPW

/-! ## §1 The partial-withdrawal lifecycle -/

/-- Lifecycle status. `intent amt` and `settled amt` carry the in-flight withdrawal amount. -/
inductive Status
  | idle
  | intent (amt : Int)
  | settled (amt : Int)
  | claimed (amt : Int)
  deriving DecidableEq

/-- Channel-state accounting view: the channel fund, the lifecycle status, and the cumulative
    amount ALREADY PAID OUT on L1 through this lane. -/
structure PWState where
  fund : Int
  status : Status
  paid : Int
  deriving DecidableEq

/-- The lifecycle actions. -/
inductive Action
  | burnIntent (amt : Int)  -- co-signed burn debit + `submitPartialWithdrawalIntent`
  | cancel                  -- `cancelPartialWithdrawal`
  | finalize                -- `finalizePartialWithdrawal` (challenge window elapsed)
  | claim                   -- the L1 credit claim paying the settled amount

/-- Guarded transitions. The burn debits the fund EXACTLY once at intent time (that is when the
    channel's co-signed state moves); cancel RESTORES it; finalize moves the debited amount to
    settled; claim pays it exactly once. -/
inductive Step : PWState → Action → PWState → Prop
  /-- Burn intent: positive amount, solvent (A2), channel idle. Debits the fund. -/
  | burn {s : PWState} {amt : Int} :
      s.status = .idle → 0 < amt → amt ≤ s.fund →
      Step s (.burnIntent amt) ⟨s.fund - amt, .intent amt, s.paid⟩
  /-- Cancel: only from intent; RESTORES the debited amount (the theorem `cancelPartial` lacked). -/
  | canc {s : PWState} {amt : Int} :
      s.status = .intent amt →
      Step s .cancel ⟨s.fund + amt, .idle, s.paid⟩
  /-- Finalize: only from intent; the debit stands, the amount becomes claimable. -/
  | fin {s : PWState} {amt : Int} :
      s.status = .intent amt →
      Step s .finalize ⟨s.fund, .settled amt, s.paid⟩
  /-- Claim: only from settled; pays the amount exactly once. -/
  | clm {s : PWState} {amt : Int} :
      s.status = .settled amt →
      Step s .claim ⟨s.fund, .claimed amt, s.paid + amt⟩

/-! ## §2 Soundness -/

/-- **T1 (the burn debits exactly the amount, exactly once, and stays solvent).** -/
theorem burn_debits_exactly
    {s s' : PWState} {amt : Int} (h : Step s (.burnIntent amt) s') :
    s'.fund = s.fund - amt ∧ 0 ≤ s'.fund ∧ s'.paid = s.paid := by
  cases h with
  | burn _ _hpos hsolv => exact ⟨rfl, by simp; omega, rfl⟩

/-- **T2 (cancel restores the pre-intent fund).** THE missing `cancelPartial` theorem: a
    burn-intent followed by a cancel is fund-identical to never having burned. -/
theorem cancel_restores
    {s s1 s2 : PWState} {amt : Int}
    (hb : Step s (.burnIntent amt) s1) (hc : Step s1 .cancel s2) :
    s2.fund = s.fund ∧ s2.paid = s.paid ∧ s2.status = .idle := by
  cases hb with
  | burn _ _ _ =>
    cases hc with
    | canc hi =>
      -- the cancelled amount is the SAME amount the intent carried (status carries it)
      cases hi
      refine ⟨?_, rfl, rfl⟩
      show s.fund - amt + amt = s.fund
      omega

/-- **T3 (claimed is terminal — the settled burn pays at most once).** No transition leaves
    `claimed`: no second claim, no re-finalize, no re-burn without a fresh lifecycle. The
    single-use property as a sink lemma (mirrors the L1 `partial_chain_key_single_use`, now tied
    to the channel-state lifecycle). -/
theorem claimed_is_terminal
    {s : PWState} {amt : Int} (hcl : s.status = .claimed amt)
    {a : Action} {s' : PWState} :
    ¬ Step s a s' := by
  intro h
  cases h <;> simp_all

/-- **T4 (lane conservation).** Along every step, `fund + inFlight + paid` is invariant, where
    `inFlight` is the amount carried by an intent/settled status. So the lane can NEVER pay out
    more than was debited from the fund: no path mints value. -/
def inFlight : Status → Int
  | .idle => 0
  | .intent a => a
  | .settled a => a
  | .claimed _ => 0

theorem lane_conserves
    {s s' : PWState} {a : Action} (h : Step s a s') :
    s'.fund + inFlight s'.status + s'.paid = s.fund + inFlight s.status + s.paid := by
  cases h <;> simp_all [inFlight] <;> omega

/-- **T4b (paid is bounded by the initial fund).** Composing T4 over a lifecycle from an idle
    state: after burn → finalize → claim, the cumulative payout increase equals the burn amount —
    never more. -/
theorem full_lifecycle_pays_exactly
    {s s1 s2 s3 : PWState} {amt : Int}
    (hb : Step s (.burnIntent amt) s1)
    (hf : Step s1 .finalize s2)
    (hc : Step s2 .claim s3) :
    s3.paid = s.paid + amt ∧ s3.fund = s.fund - amt := by
  cases hb with
  | burn _ _ _ =>
    cases hf with
    | fin hi =>
      cases hi
      cases hc with
      | clm hs =>
        cases hs
        exact ⟨rfl, rfl⟩

/-! ## §3 Liveness (R1) -/

/-- **T5 (cancel is available from intent).** An honest party who wants out of a pending partial
    withdrawal is never fail-closed: the cancel step exists. -/
theorem cancel_available
    {s : PWState} {amt : Int} (hi : s.status = .intent amt) :
    ∃ s', Step s .cancel s' :=
  ⟨_, .canc hi⟩

/-- **T6 (the honest partial withdrawal PAYS).** From an idle, solvent channel the full
    burn → finalize → claim chain exists and pays exactly the requested amount. The R1 honest-exit
    obligation for this lane — the property whose absence let the "deliberate 501" payout stub and
    the unreachable-nullifier defect sit green. -/
theorem honest_partial_withdraw_pays
    (s : PWState) (amt : Int) (hidle : s.status = .idle)
    (hpos : 0 < amt) (hsolv : amt ≤ s.fund) :
    ∃ s1 s2 s3 : PWState,
      Step s (.burnIntent amt) s1 ∧
      Step s1 .finalize s2 ∧
      Step s2 .claim s3 ∧
      s3.paid = s.paid + amt ∧ s3.fund = s.fund - amt := by
  refine ⟨⟨s.fund - amt, .intent amt, s.paid⟩,
          ⟨s.fund - amt, .settled amt, s.paid⟩,
          ⟨s.fund - amt, .claimed amt, s.paid + amt⟩,
          .burn hidle hpos hsolv, .fin rfl, .clm rfl, rfl, rfl⟩

end ChannelSafetyPW
