import Zkp.Contracts.Evm

/-
  ChannelSettlementManagerMT — PER-BASE-TOKEN channel-path payout cap
  ===================================================================

  Multi-token generalization of `ChannelSettlementManager.lean` (which
  models the single-asset manager as deployed). Reviewers should diff the
  two files side by side: this is the SAME state machine with every
  modeled accounting variable indexed by a base `Token`. In particular
  the AUTHORITATIVE per-token cap sits exactly where the deployed
  contract puts it — at PAYOUT time (`claimWithdrawalCredit` :1168-1170)
  — and `totalCreditedOut t` keeps its deployed meaning: Σ PAID OUT in
  token t (bumped at :1172, i.e. in `pullCreditMT` here).

  Source design: `doc/architecture-audit/detail2.md` §N-6 —

    "`ChannelSettlementManager`: EVERY accounting variable becomes
     per-base-token — `finalizedChannelFundAmount[t]`,
     `totalWithdrawn[t]`, `receivedChannelFunds[t]`,
     `totalCreditedOut[t]`, `withdrawalCredits[t][addr]` — with
     per-token CapInv `totalCreditedOut[t] + amount <=
     receivedChannelFunds[t]` and payout dispatch by t. Token-t claims
     are paid ONLY from token-t funds (TM-3)."

  Threat-model obligations discharged here
  (`doc/tasks/multitoken-threat-model.md`):

  * TM-1 (FUNDS): all L1 accounting keys on the BASE `token_index`
    (never a channel-local slot), with a per-base-token ceiling. Here
    `Token` IS the base index; every op takes it explicitly and the
    frame theorems (`*_no_cross_token`) prove no op touches any other
    token's books.
  * TM-3 (FUNDS): no residual single-asset variable AMONG THE MODELED
    payout-cap variables — the per-token `CapInvMT` is preserved by
    every operation, and the trace theorem `execMT_payout_ceiling`
    machine-checks `Σ token-t payouts ≤ receivedChannelFunds t` per
    token, so token-t claims can never draw on token-t' funds (t' ≠ t)
    nor on the sum of all tokens.

  ## SCOPE: which of §N-6's five variables are modeled here

  This file models the PAYOUT-CAP slice only: `receivedChannelFunds[t]`,
  `totalCreditedOut[t]`, `withdrawalCredits[t][addr]`.

  `finalizedChannelFundAmount[t]` and `totalWithdrawn[t]` — the
  pending-close/finalization pair behind the NON-authoritative
  mint-time check `totalWithdrawn + amount ≤ finalizedChannelFundAmount`
  (Manager :1067/:1129) — are explicitly UNMODELED here; their
  per-token conversion is tracked for the Phase 3 Solidity work in
  `doc/tasks/multitoken-todo.md`. This file is therefore NOT the
  exhaustive TM-3 conversion proof for all five variables; it is the
  solvency-critical payout-ceiling half. Credit minting is modeled
  CONSERVATIVELY (adversarially, unguarded — see `claimMT`), which
  makes the payout-ceiling theorems strictly stronger: they hold even
  if every mint-time check is bypassed.
-/

namespace Zkp
namespace Contracts
namespace ChannelSettlementManagerMT

open Zkp.Contracts.Evm

/-- BASE token index (L1 `tokenIndex`; 0 = native ETH). SECURITY (TM-1):
    accounting is keyed by the base index, NEVER by a channel-local slot —
    duplicate local slots mapping to one base token therefore share ONE
    ceiling and cannot double-drain an escrow. -/
abbrev Token := Nat

/-- The payout-cap slice of the manager's storage, per base token
    (detail2 §N-6; see the SCOPE note above for the two unmodeled
    variables). `totalCreditedOut t` = Σ paid out in token t, exactly as
    in the deployed contract (bumped at payout, :1172). -/
structure MgrStateMT where
  withdrawalCredits : Mapping Token (Mapping Addr U256)
  totalCreditedOut : Mapping Token U256
  receivedChannelFunds : Mapping Token U256

/-- **Per-token solvency invariant (TM-3, detail2 §N-6).** For EVERY base
    token t, total PAID OUT in t never exceeds total pulled in t — the
    exact per-token transliteration of the single-asset `CapInv`
    ("total paid out never exceeds total pulled"). -/
def CapInvMT (s : MgrStateMT) : Prop :=
  ∀ t : Token, s.totalCreditedOut.get t ≤ s.receivedChannelFunds.get t

/-- The all-zero deployment state (induction basis for `CapInvMT`). -/
def initMT : MgrStateMT :=
  { withdrawalCredits := fun _ => fun _ => 0
    totalCreditedOut := fun _ => 0
    receivedChannelFunds := fun _ => 0 }

/-- Models `pullChannelFunds()` (:1152), per token: capacity for token t
    grows by `pulled` (real asset delta from the rollup's per-token
    escrow, detail2 §N-7); all other books untouched. -/
def pullMT (s : MgrStateMT) (t : Token) (pulled : U256) : MgrStateMT :=
  { s with receivedChannelFunds :=
      s.receivedChannelFunds.set t (s.receivedChannelFunds.get t + pulled) }

/-- Models the credit-WRITING effect of the submit-claim paths
    (`submitWithdrawalClaim` :1051-:1073, `submitPostCloseClaim`
    :1107-:1136), per token. NOT authoritative for solvency: the real
    mint-time check at :1067/:1129 is `totalWithdrawn + amount ≤
    finalizedChannelFundAmount`, over the two variables UNMODELED here
    (see SCOPE). We therefore model minting conservatively as
    ADVERSARIAL — no cap guard at all — so every payout-ceiling theorem
    below holds even against a prover that mints arbitrary credits. The
    authoritative per-token cap is enforced downstream in
    `pullCreditMT` (:1170), exactly as deployed. -/
def claimMT (s : MgrStateMT) (t : Token) (sender : Addr) (amount : U256) :
    Call MgrStateMT :=
  if amount = 0 then none
  else
    some { s with
      withdrawalCredits := s.withdrawalCredits.set t
        ((s.withdrawalCredits.get t).set sender
          ((s.withdrawalCredits.get t).get sender + amount)) }

/-- Models `claimWithdrawalCredit()` (:1167-1176), per token — the
    AUTHORITATIVE solvency check (payout dispatch by t: t = 0 → ETH,
    else the L1-registered ERC-20, detail2 §N-6). Line-by-line
    transliteration of the single-asset `claimWithdrawalCredit`:
    nonzero credit (:1169), the per-token cap `totalCreditedOut t +
    credit ≤ receivedChannelFunds t` (:1170), CEI zero-before-send
    (:1171), and the Σ-paid ledger bump `totalCreditedOut t += credit`
    (:1172). Returns `(state, amountSent)`. -/
def pullCreditMT (s : MgrStateMT) (t : Token) (sender : Addr) :
    Call (MgrStateMT × U256) :=
  if (s.withdrawalCredits.get t).get sender = 0 then none               -- :1169
  else if s.receivedChannelFunds.get t <
          s.totalCreditedOut.get t + (s.withdrawalCredits.get t).get sender
       then none                                          -- :1170 per-token cap exceeded
  else
    some ({ s with
            withdrawalCredits := s.withdrawalCredits.set t
              ((s.withdrawalCredits.get t).set sender 0)                -- :1171
            totalCreditedOut := s.totalCreditedOut.set t
              (s.totalCreditedOut.get t + (s.withdrawalCredits.get t).get sender) }, -- :1172
          (s.withdrawalCredits.get t).get sender)

/-- Decompose a successful credit mint. -/
theorem claimMT_some {s s' : MgrStateMT} {t : Token} {sender : Addr} {amount : U256}
    (h : claimMT s t sender amount = some s') :
    amount ≠ 0 ∧
    s' = { s with
      withdrawalCredits := s.withdrawalCredits.set t
        ((s.withdrawalCredits.get t).set sender
          ((s.withdrawalCredits.get t).get sender + amount)) } := by
  unfold claimMT at h
  by_cases h1 : amount = 0
  · rw [if_pos h1] at h; simp at h
  rw [if_neg h1] at h
  rw [Option.some.injEq] at h
  exact ⟨h1, h.symm⟩

/-- Decompose a successful payout (mirror of the single-asset
    `claim_some`): the credit was nonzero, the :1170 cap held, and the
    unique post-state zeroes the credit and bumps the Σ-paid ledger. -/
theorem pullCreditMT_some {s s' : MgrStateMT} {t : Token} {sender : Addr} {amt : U256}
    (h : pullCreditMT s t sender = some (s', amt)) :
    (s.withdrawalCredits.get t).get sender ≠ 0 ∧
    s.totalCreditedOut.get t + (s.withdrawalCredits.get t).get sender
      ≤ s.receivedChannelFunds.get t ∧
    amt = (s.withdrawalCredits.get t).get sender ∧
    s' = { s with
      withdrawalCredits := s.withdrawalCredits.set t
        ((s.withdrawalCredits.get t).set sender 0)
      totalCreditedOut := s.totalCreditedOut.set t
        (s.totalCreditedOut.get t + (s.withdrawalCredits.get t).get sender) } := by
  unfold pullCreditMT at h
  by_cases h1 : (s.withdrawalCredits.get t).get sender = 0
  · rw [if_pos h1] at h; simp at h
  rw [if_neg h1] at h
  by_cases h2 : s.receivedChannelFunds.get t <
      s.totalCreditedOut.get t + (s.withdrawalCredits.get t).get sender
  · rw [if_pos h2] at h; simp at h
  rw [if_neg h2] at h
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  exact ⟨h1, Nat.le_of_not_lt h2, h.2.symm, h.1.symm⟩

/-- **`pullMT` preserves the per-token cap (TM-3, detail2 §N-6).**
    Capacity for token t only grows; every other token's books are
    untouched. Per-token transliteration of `pull_preserves_cap`. -/
theorem pullMT_preserves_cap {s : MgrStateMT} {t : Token} {pulled : U256}
    (h : CapInvMT s) : CapInvMT (pullMT s t pulled) := by
  intro t'
  by_cases ht : t' = t
  · subst ht
    simp only [pullMT, Mapping.get_set_eq]
    exact Nat.le_trans (h t') (Nat.le_add_right _ _)
  · simp only [pullMT, Mapping.get_set_ne _ _ ht]
    exact h t'

/-- **`claimMT` preserves the per-token cap (TM-3).** Minting a credit
    touches neither `totalCreditedOut` nor `receivedChannelFunds` of ANY
    token — even an adversarial mint cannot move the Σ-paid ledger. -/
theorem claimMT_preserves_cap {s s' : MgrStateMT} {t : Token} {sender : Addr}
    {amount : U256} (hinv : CapInvMT s) (h : claimMT s t sender amount = some s') :
    CapInvMT s' := by
  obtain ⟨_, hs'⟩ := claimMT_some h
  subst hs'
  intro t'
  exact hinv t'

/-- **`pullCreditMT` preserves the per-token cap (TM-1/TM-3, detail2
    §N-6).** The AUTHORITATIVE per-step result: a successful payout in
    token t keeps `totalCreditedOut t ≤ receivedChannelFunds t` for
    EVERY token — the paid token by the :1170 cap guard, every other
    token because its books are untouched. `execMT_payout_ceiling`
    below turns the induction over op sequences into a theorem. -/
theorem pullCreditMT_preserves_cap {s s' : MgrStateMT} {t : Token} {sender : Addr}
    {amt : U256} (hinv : CapInvMT s) (h : pullCreditMT s t sender = some (s', amt)) :
    CapInvMT s' := by
  obtain ⟨_, hcap, _, hs'⟩ := pullCreditMT_some h
  subst hs'
  intro t'
  by_cases ht : t' = t
  · subst ht
    simp only [Mapping.get_set_eq]
    exact hcap
  · simp only [Mapping.get_set_ne _ _ ht]
    exact hinv t'

/-- **Per-token payout capacity (TM-3, detail2 §N-6).** Transliteration
    of the single-asset `claim_within_capacity` (whose op IS the payout,
    cap at :1170): any successful token-t payout fits under token t's
    OWN remaining capacity — `totalCreditedOut t + amt ≤
    receivedChannelFunds t`. -/
theorem pullCreditMT_within_capacity {s s' : MgrStateMT} {t : Token} {sender : Addr}
    {amt : U256} (_hinv : CapInvMT s) (h : pullCreditMT s t sender = some (s', amt)) :
    s.totalCreditedOut.get t + amt ≤ s.receivedChannelFunds.get t := by
  obtain ⟨_, hcap, hamt, _⟩ := pullCreditMT_some h
  rw [hamt]; exact hcap

/-- **Cross-token frame for credit mints (TM-1/TM-3, detail2 §N-6).** A
    successful mint in token t leaves ALL accounting of every other
    token t' ≠ t byte-identical: its capacity, its Σ-paid ledger, and
    every address's credit in it. -/
theorem claimMT_no_cross_token {s s' : MgrStateMT} {t t' : Token} {sender : Addr}
    {amount : U256} (h : claimMT s t sender amount = some s') (ht : t' ≠ t) :
    s'.receivedChannelFunds.get t' = s.receivedChannelFunds.get t' ∧
    s'.totalCreditedOut.get t' = s.totalCreditedOut.get t' ∧
    ∀ a : Addr, (s'.withdrawalCredits.get t').get a = (s.withdrawalCredits.get t').get a := by
  obtain ⟨_, hs'⟩ := claimMT_some h
  subst hs'
  refine ⟨rfl, rfl, fun a => ?_⟩
  simp only [Mapping.get_set_ne _ _ ht]

/-- **Cross-token frame for pulls (TM-1/TM-3).** Pulling token-t funds
    changes no accounting of any token t' ≠ t. -/
theorem pullMT_no_cross_token {s : MgrStateMT} {t t' : Token} {pulled : U256}
    (ht : t' ≠ t) :
    (pullMT s t pulled).receivedChannelFunds.get t' = s.receivedChannelFunds.get t' ∧
    (pullMT s t pulled).totalCreditedOut.get t' = s.totalCreditedOut.get t' ∧
    ∀ a : Addr, ((pullMT s t pulled).withdrawalCredits.get t').get a
                  = (s.withdrawalCredits.get t').get a := by
  refine ⟨?_, rfl, fun _ => rfl⟩
  simp only [pullMT, Mapping.get_set_ne _ _ ht]

/-- **Cross-token frame for payouts (THE key MT theorem; TM-1/TM-3,
    detail2 §N-6).** A successful token-t payout leaves ALL accounting
    of every other token t' ≠ t byte-identical — it can neither spend
    token-t' capacity, move token-t's ledger into token-t' books, nor
    zero a credit held in another token. Cross-asset theft is
    structurally impossible in this machine. -/
theorem pullCreditMT_no_cross_token {s s' : MgrStateMT} {t t' : Token} {sender : Addr}
    {amt : U256} (h : pullCreditMT s t sender = some (s', amt)) (ht : t' ≠ t) :
    s'.receivedChannelFunds.get t' = s.receivedChannelFunds.get t' ∧
    s'.totalCreditedOut.get t' = s.totalCreditedOut.get t' ∧
    ∀ a : Addr, (s'.withdrawalCredits.get t').get a = (s.withdrawalCredits.get t').get a := by
  obtain ⟨_, _, _, hs'⟩ := pullCreditMT_some h
  subst hs'
  refine ⟨rfl, ?_, fun a => ?_⟩
  · simp only [Mapping.get_set_ne _ _ ht]
  · simp only [Mapping.get_set_ne _ _ ht]

/-- **No double-payout (CEI), per token.** Transliteration of
    `claim_no_double`: a successful token-t payout zeroes the caller's
    token-t credit (:1171, before the external send), so an immediate
    second payout in the same token reverts. Other tokens' credits are
    untouched (`pullCreditMT_no_cross_token`), so nothing collapses
    across tokens (cf. the TM-5 nullifier discussion). -/
theorem pullCreditMT_no_double {s s' : MgrStateMT} {t : Token} {sender : Addr}
    {amt : U256} (h : pullCreditMT s t sender = some (s', amt)) :
    pullCreditMT s' t sender = none := by
  obtain ⟨_, _, _, hs'⟩ := pullCreditMT_some h
  have hz : (s'.withdrawalCredits.get t).get sender = 0 := by
    rw [hs']; simp [Mapping.get_set_eq]
  unfold pullCreditMT
  rw [if_pos hz]

/-- The deployment state satisfies the cap invariant. -/
theorem initMT_cap : CapInvMT initMT := fun _ => Nat.le_refl 0

/-!
  ## Trace semantics: the machine-checked per-token payout ceiling

  `CapInvMT` preservation is per-step; to state "Σ token-t payouts ≤
  `receivedChannelFunds t`" as a THEOREM (not a header argument) we run
  the machine over an arbitrary operation list from the deployment
  state, accumulate actual payouts per token, and prove the accumulated
  payout mapping is bounded by the final capacity. Reverting ops
  (`none`) leave the state unchanged and pay nothing — EVM atomicity.
-/

/-- One external manager call, chosen adversarially. -/
inductive OpMT where
  | pull (t : Token) (amount : U256)
  | claim (t : Token) (sender : Addr) (amount : U256)
  | payout (t : Token) (sender : Addr)

/-- Execute one call over `(state, Σ-paid-per-token accumulator)`. A
    reverting call is a no-op (atomic revert, `Evm.Call`). -/
def stepMT (sp : MgrStateMT × Mapping Token U256) (op : OpMT) :
    MgrStateMT × Mapping Token U256 :=
  match op with
  | .pull t amount => (pullMT sp.1 t amount, sp.2)
  | .claim t sender amount =>
    match claimMT sp.1 t sender amount with
    | none => sp
    | some s' => (s', sp.2)
  | .payout t sender =>
    match pullCreditMT sp.1 t sender with
    | none => sp
    | some (s', amt) => (s', sp.2.set t (sp.2.get t + amt))

/-- Run an arbitrary call sequence from the deployment state, starting
    from a zero payout accumulator. -/
def execMT (ops : List OpMT) : MgrStateMT × Mapping Token U256 :=
  ops.foldl stepMT (initMT, fun _ => 0)

/-- Trace invariant: the cap holds AND the accumulated payouts equal the
    on-chain Σ-paid ledger `totalCreditedOut` (the :1172 bump is the
    ONLY writer of either side). -/
def ExecInvMT (sp : MgrStateMT × Mapping Token U256) : Prop :=
  CapInvMT sp.1 ∧ ∀ t : Token, sp.2.get t = sp.1.totalCreditedOut.get t

/-- Every call — succeed or revert — preserves the trace invariant
    (TM-3): pulls only grow capacity, mints touch neither ledger nor
    accumulator, and a successful payout bumps BOTH by the same `amt`
    under the :1170 cap. -/
theorem stepMT_preserves_inv {sp : MgrStateMT × Mapping Token U256}
    (h : ExecInvMT sp) (op : OpMT) : ExecInvMT (stepMT sp op) := by
  obtain ⟨hcap, hpaid⟩ := h
  cases op with
  | pull t amount =>
    exact ⟨pullMT_preserves_cap hcap, fun t' => hpaid t'⟩
  | claim t sender amount =>
    cases hm : claimMT sp.1 t sender amount with
    | none =>
      simp only [stepMT, hm]
      exact ⟨hcap, hpaid⟩
    | some s' =>
      simp only [stepMT, hm]
      obtain ⟨_, hs'⟩ := claimMT_some hm
      refine ⟨claimMT_preserves_cap hcap hm, fun t' => ?_⟩
      rw [hs']
      exact hpaid t'
  | payout t sender =>
    cases hm : pullCreditMT sp.1 t sender with
    | none =>
      simp only [stepMT, hm]
      exact ⟨hcap, hpaid⟩
    | some pair =>
      obtain ⟨s', amt⟩ := pair
      simp only [stepMT, hm]
      obtain ⟨_, _, hamt, hs'⟩ := pullCreditMT_some hm
      refine ⟨pullCreditMT_preserves_cap hcap hm, fun t' => ?_⟩
      by_cases ht : t' = t
      · subst ht
        rw [Mapping.get_set_eq, hs']
        simp only [Mapping.get_set_eq]
        rw [hpaid t', hamt]
      · rw [Mapping.get_set_ne _ _ ht, hs']
        simp only [Mapping.get_set_ne _ _ ht]
        exact hpaid t'

/-- Folding any call list preserves the trace invariant. -/
theorem foldl_stepMT_inv {ops : List OpMT} :
    ∀ {sp : MgrStateMT × Mapping Token U256},
      ExecInvMT sp → ExecInvMT (ops.foldl stepMT sp) := by
  induction ops with
  | nil => intro _ h; exact h
  | cons op _rest ih => intro sp h; exact ih (stepMT_preserves_inv h op)

/-- The trace invariant holds after any call sequence from deployment. -/
theorem execMT_inv (ops : List OpMT) : ExecInvMT (execMT ops) :=
  foldl_stepMT_inv ⟨initMT_cap, fun _ => rfl⟩

/-- The accumulated per-token payouts equal the on-chain Σ-paid ledger:
    `totalCreditedOut t` IS Σ payouts in t (deployed :1172 semantics). -/
theorem execMT_ledger (ops : List OpMT) (t : Token) :
    (execMT ops).2.get t = (execMT ops).1.totalCreditedOut.get t :=
  (execMT_inv ops).2 t

/-- **THE machine-checked per-token payout ceiling (TM-1/TM-3, detail2
    §N-6).** After ANY sequence of pulls, adversarial credit mints, and
    payouts from the deployment state, for every base token t the SUM of
    all amounts actually paid out in t is bounded by
    `receivedChannelFunds t` — token-t claims are paid ONLY from
    token-t funds, with the authoritative check at payout (:1170)
    exactly as in the deployed single-asset contract. -/
theorem execMT_payout_ceiling (ops : List OpMT) (t : Token) :
    (execMT ops).2.get t ≤ (execMT ops).1.receivedChannelFunds.get t := by
  obtain ⟨hcap, hpaid⟩ := execMT_inv ops
  rw [hpaid t]
  exact hcap t

/-- **Inhabitation.** The per-token pipeline is satisfiable and really
    is token-local: pull 100 into token 5, mint a 30-credit, pay it out
    — the Σ-paid ledger of token 5 ends at 30 while token 7's books stay
    all-zero throughout. Guards are not vacuous. -/
theorem mt_pipeline_satisfiable :
    ∃ (s1 s2 : MgrStateMT) (amt : U256),
      claimMT (pullMT initMT 5 100) 5 42 30 = some s1 ∧
      pullCreditMT s1 5 42 = some (s2, amt) ∧
      amt = 30 ∧
      s2.totalCreditedOut.get 5 = 30 ∧
      s2.receivedChannelFunds.get 7 = 0 ∧
      (s2.withdrawalCredits.get 7).get 42 = 0 := by
  refine ⟨_, _, _, rfl, rfl, rfl, ?_, ?_, ?_⟩ <;> decide

/-!
  ## SECURITY OBSERVATIONS

  * **Per-token channel solvency (TM-3), machine-checked.**
    `execMT_payout_ceiling` proves, for ANY call sequence from
    deployment: `∀ t, Σ token-t payouts ≤ receivedChannelFunds t`. The
    authoritative check is at PAYOUT (`pullCreditMT`, transliterating
    :1168-1170/:1172) and `totalCreditedOut t` keeps its deployed
    meaning of Σ paid — the per-step engine is
    `pullCreditMT_preserves_cap` + `pullMT_preserves_cap` +
    `claimMT_preserves_cap`. Combined with the rollup's per-token
    escrow ceiling (`escrowed[t] -= amount` underflow-revert, detail2
    §N-7), token-t claims cannot drain token-t' escrow nor other
    channels' token-t escrow.

  * **Adversarial mints are harmless to solvency.** `claimMT` is
    deliberately UNGUARDED (over-approximating the :1067/:1129 submit
    paths, whose `totalWithdrawn + amount ≤ finalizedChannelFundAmount`
    check is over variables unmodeled here and is not the authoritative
    solvency check). The payout ceiling above therefore holds even if
    every mint-time check were bypassed — a strictly stronger claim
    than modeling well-behaved mints.

  * **No cross-token leakage (TM-1).** The three `*_no_cross_token`
    frame theorems prove every operation is token-local: NO modeled
    accounting variable of any other base token moves. This is the Lean
    witness that "no residual single-asset variable" holds among the
    payout-cap variables — a payout in token t literally cannot read or
    write token-t' capacity.

  * **Base-token keying (TM-1).** `Token` is the BASE `token_index`.
    Duplicate channel-local slots resolving to the same base token hit
    the SAME `receivedChannelFunds t` ceiling here, so the
    slot-duplication double-drain requires defeating this cap — which
    `execMT_payout_ceiling` rules out — independent of the in-circuit
    registry-injectivity check (both layers required per TM-1).

  * **No double-payout (CEI).** `pullCreditMT_no_double` is the
    per-token CEI guarantee: the credit is zeroed before the external
    send, backed by `nonReentrant` (`Assumptions.SingleCallAtomicity`,
    `Assumptions.EthSendFailureReverts`) — for ERC-20 payouts the same
    discipline plus the TM-10 hook-reentrancy rules apply.

  * **Scope.** Payout-cap accounting slice only. As stated in the
    header SCOPE note, `finalizedChannelFundAmount[t]` /
    `totalWithdrawn[t]` (the pending-close/finalization pair) are
    UNMODELED — their per-token conversion is Phase 3 Solidity work
    tracked in `doc/tasks/multitoken-todo.md` — and the
    partial-withdrawal pipeline is unchanged by the multi-token feature
    at this layer and remains modeled once in
    `ChannelSettlementManager.lean`.
-/

end ChannelSettlementManagerMT
end Contracts
end Zkp
