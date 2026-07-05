import Zkp.Contracts.Evm

/-
  ChannelSettlementManager — channel-path payout cap
  ==================================================

  Source: `contracts/src/ChannelSettlementManager.sol`
    pullChannelFunds :1152 · claimWithdrawalCredit :1167

  ## Protocol role

  The channel settlement path moves a channel's native ETH off the rollup
  and pays it to channel members. Capacity is `receivedChannelFunds` (Σ
  ETH actually pulled from the rollup via `pullChannelFunds`), and the
  authoritative ceiling is enforced at payout:

      claimWithdrawalCredit: require totalCreditedOut + amount ≤ receivedChannelFunds

  so `Σ payouts ≤ Σ pulled` — the manager can NEVER pay out more native ETH
  than it pulled (which the rollup's own solvency already bounds). Per
  claim, the credit is zeroed before the ETH send (CEI) ⇒ no double-claim.
  This is the channel-side mirror of the rollup `totalEscrowed` ceiling and
  the headline channel fund-safety property (audit622 Part A).

  ## Constraint inventory (claimWithdrawalCredit :1167-1176)

  | line   | check / effect                                       |
  |--------|------------------------------------------------------|
  | :1168  | `amount = withdrawalCredits[sender]`                 |
  | :1169  | `amount != 0`                                        |
  | :1170  | `totalCreditedOut + amount ≤ receivedChannelFunds` (cap) |
  | :1171  | `withdrawalCredits[sender] = 0` (CEI, no double-claim) |
  | :1172  | `totalCreditedOut += amount`                         |
  | :1174  | ETH transfer (after effects)                         |
-/

namespace Zkp
namespace Contracts
namespace ChannelSettlementManager

open Zkp.Contracts.Evm

/-- The payout-cap slice of the manager's storage. -/
structure MgrState where
  withdrawalCredits : Mapping Addr U256
  totalCreditedOut : U256
  receivedChannelFunds : U256

/-- The solvency invariant: total paid out never exceeds total pulled. -/
def CapInv (s : MgrState) : Prop := s.totalCreditedOut ≤ s.receivedChannelFunds

/-- `pullChannelFunds()` (:1152): increases capacity by `pulled` (real ETH
    delta from the rollup); `totalCreditedOut` unchanged. -/
def pullChannelFunds (s : MgrState) (pulled : U256) : MgrState :=
  { s with receivedChannelFunds := s.receivedChannelFunds + pulled }

/-- `claimWithdrawalCredit()` (:1167): pay the caller's credit if within
    the cap; zero it first (CEI). Returns `(state, amountSent)`. -/
def claimWithdrawalCredit (s : MgrState) (sender : Addr) : Call (MgrState × U256) :=
  if s.withdrawalCredits.get sender = 0 then none                          -- :1169
  else if s.receivedChannelFunds < s.totalCreditedOut + s.withdrawalCredits.get sender
       then none                                                          -- :1170 cap exceeded
  else
    some ({ s with
            withdrawalCredits := s.withdrawalCredits.set sender 0          -- :1171
            totalCreditedOut := s.totalCreditedOut + s.withdrawalCredits.get sender }, -- :1172
          s.withdrawalCredits.get sender)

/-- `pullChannelFunds` preserves the cap invariant (capacity only grows). -/
theorem pull_preserves_cap {s : MgrState} {pulled : U256} (h : CapInv s) :
    CapInv (pullChannelFunds s pulled) := by
  unfold CapInv pullChannelFunds at *
  simp only []
  exact Nat.le_trans h (Nat.le_add_right _ _)

/-- Decompose a successful claim. -/
theorem claim_some {s s' : MgrState} {sender : Addr} {amt : U256}
    (h : claimWithdrawalCredit s sender = some (s', amt)) :
    s.totalCreditedOut + s.withdrawalCredits.get sender ≤ s.receivedChannelFunds ∧
    amt = s.withdrawalCredits.get sender ∧
    s' = { s with withdrawalCredits := s.withdrawalCredits.set sender 0,
                  totalCreditedOut := s.totalCreditedOut + s.withdrawalCredits.get sender } := by
  unfold claimWithdrawalCredit at h
  by_cases h1 : s.withdrawalCredits.get sender = 0
  · rw [if_pos h1] at h; simp at h
  rw [if_neg h1] at h
  by_cases h2 : s.receivedChannelFunds < s.totalCreditedOut + s.withdrawalCredits.get sender
  · rw [if_pos h2] at h; simp at h
  rw [if_neg h2] at h
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  refine ⟨Nat.le_of_not_lt h2, h.2.symm, h.1.symm⟩

/-- **Cap invariant preserved by payouts.** A successful claim keeps
    `totalCreditedOut ≤ receivedChannelFunds`. By induction over any
    sequence of pulls and claims, `Σ payouts ≤ Σ pulled` always — the
    manager cannot over-pay. -/
theorem claim_preserves_cap {s s' : MgrState} {sender : Addr} {amt : U256}
    (_hinv : CapInv s) (h : claimWithdrawalCredit s sender = some (s', amt)) :
    CapInv s' := by
  obtain ⟨hcap, _, hs'⟩ := claim_some h
  unfold CapInv
  rw [hs']
  -- s'.totalCreditedOut = totalCreditedOut + credit ≤ receivedChannelFunds = s'.received
  exact hcap

/-- **No double-claim (CEI).** A successful claim zeroes the caller's
    credit, so an immediate second claim reverts. -/
theorem claim_no_double {s s' : MgrState} {sender : Addr} {amt : U256}
    (h : claimWithdrawalCredit s sender = some (s', amt)) :
    claimWithdrawalCredit s' sender = none := by
  obtain ⟨_, _, hs'⟩ := claim_some h
  have hz : s'.withdrawalCredits.get sender = 0 := by
    rw [hs']; simp [Mapping.get_set_eq]
  unfold claimWithdrawalCredit
  rw [if_pos hz]

/-- **Channel-path solvency (consequence).** Under the cap invariant, the
    amount any claim pays is bounded by the remaining capacity. -/
theorem claim_within_capacity {s s' : MgrState} {sender : Addr} {amt : U256}
    (_hinv : CapInv s) (h : claimWithdrawalCredit s sender = some (s', amt)) :
    s.totalCreditedOut + amt ≤ s.receivedChannelFunds := by
  obtain ⟨hcap, hamt, _⟩ := claim_some h
  rw [hamt]; exact hcap

/-!
  ## Partial withdrawal (GAP2): the mid-channel burn authorization path

  Source: `submitPartialWithdrawalIntent` :913-969,
  `finalizePartialWithdrawal` :971-993, `cancelPartialWithdrawal`
  :995-1033 (ChannelSettlementManager.sol).

  `finalizePartialWithdrawal` MINTS a rollup burn authorization —
  `registry.authorizePartialWithdrawal(authDigest)` at :990 — the exact
  flag `IntmaxRollup.claimAuthorizedWithdrawal` / `withdrawNative`'s
  burn leaves pay against. It is therefore ESCROW-AFFECTING DOWNSTREAM
  and is the honest flow that operationally discharges
  `Assumptions.BurnAuthorizationsLegitimate`.

  What the Solidity actually gates it on (NOT a finalized close — the
  channel is `Active` at submission, :919, and the channel STAYS OPEN;
  finalization deliberately has NO channelStatus check, :974-976):
    * submission requires a PROOF-VERIFIED close-intent state
      (`_checkCloseProof` :921 — real MLE/WHIR under the close VK, with
      the registered member-set commitment strict-bound), plus the burn
      tx_leaf being the LAST push of the signed settled-tx chain
      (:927-930), a NEVER-USED chain key (:932-933), and — if a pending
      intent exists — a strictly newer (epoch, stateVersion) (:937-941);
    * finalization requires the pending flag and the challenge deadline
      strictly passed (:972-973), then consumes the chain key (:978) and
      mints the authorization (:990);
    * `cancelPartialWithdrawal` (:995-1033) clears the pending intent on
      a verified strictly-newer-state proof (same shape as cancelClose).
-/

/-- The partial-withdrawal slice of the manager's storage plus the
    downstream rollup flag it mints (`partialWithdrawalAuthorized`, via
    the `registry.authorizePartialWithdrawal` call at :990). -/
structure PartialState where
  channelActive : Bool                    -- channelStatus == Active
  usedChains : Mapping Word Bool          -- usedPartialWithdrawalChains (:520)
  pending : Bool                          -- partialWithdrawalPending (:521)
  pendingAuthDigest : Word                -- (:522)
  pendingChainKey : Word                  -- (:523)
  pendingDeadline : U256                  -- (:525)
  authorizedOnRollup : Mapping Word Bool  -- rollup partialWithdrawalAuthorized

/-- `submitPartialWithdrawalIntent` (:913-969). `closeProofOk` is the
    uninterpreted `_checkCloseProof` oracle (:921 — member-set-bound
    MLE/WHIR); `chainBound` is the :927-930 keccak recompute ("the burn
    tx_leaf is the LAST push of the signed chain"); `newerOk` is the
    :937-941 strictly-newer replacement rule (vacuously true when no
    intent is pending). `authDigest`/`chainKey` are the :944/:932 keccak
    digests (opaque at this level). `now` is `block.timestamp`,
    `challengePeriod` the immutable period (:959). -/
def submitPartialIntent (s : PartialState)
    (closeProofOk chainBound newerOk : Prop)
    [Decidable closeProofOk] [Decidable chainBound] [Decidable newerOk]
    (authDigest chainKey : Word) (auxDataNonzero : Bool)
    (now challengePeriod : U256) : Call PartialState :=
  if s.channelActive = false then none                          -- :919 ChannelClosed
  else if ¬ closeProofOk then none                              -- :921 InvalidCloseProof
  else if auxDataNonzero = false then none                      -- :923 PartialWithdrawalAuxDataZero
  else if ¬ chainBound then none                                -- :930 PartialWithdrawalChainMismatch
  else if s.usedChains.get chainKey = true then none            -- :933 PartialWithdrawalChainUsed
  else if s.pending = true ∧ ¬ newerOk then none                -- :941 PartialWithdrawalNotNewer
  else some { s with                                            -- :955-961
    pending := true
    pendingAuthDigest := authDigest
    pendingChainKey := chainKey
    pendingDeadline := now + challengePeriod }

/-- `finalizePartialWithdrawal` (:971-993): pending + challenge window
    STRICTLY elapsed (`block.timestamp <= deadline` reverts, :973) ⇒
    consume the chain key (:978), clear the pending intent (:982-988),
    and mint the rollup authorization (:990). NO channelStatus check —
    deliberate (12B): a close racing the challenge window cannot strand
    the burn, and the burned amount is already excluded from the close's
    channelFundAmount. -/
def finalizePartial (s : PartialState) (now : U256) : Call PartialState :=
  if s.pending = false then none                                -- :972 PartialWithdrawalNotPending
  else if now ≤ s.pendingDeadline then none                     -- :973 ChallengeWindowOpen
  else some { s with
    usedChains := s.usedChains.set s.pendingChainKey true       -- :978
    pending := false                                            -- :982-988
    authorizedOnRollup := s.authorizedOnRollup.set s.pendingAuthDigest true }  -- :990

/-- `cancelPartialWithdrawal` (:995-1033): a verified strictly-newer
    state proof (`verifyCancelClose`, member-set-bound, :1007-1016)
    clears the pending intent — the chain key is NOT consumed and no
    authorization is minted. -/
def cancelPartial (s : PartialState) (cancelProofOk : Prop) [Decidable cancelProofOk] :
    Call PartialState :=
  if s.pending = false then none                                -- :999
  else if ¬ cancelProofOk then none                             -- :1016 InvalidCancelProof
  else some { s with pending := false }                         -- :1020-1026

/-- A pending intent is created ONLY through a verified close proof on
    an ACTIVE channel with a fresh chain key: if the submit succeeded,
    the proof oracle held (and the chain key was unused). -/
theorem submitPartialIntent_requires_proof {s s' : PartialState}
    {closeProofOk chainBound newerOk : Prop}
    [Decidable closeProofOk] [Decidable chainBound] [Decidable newerOk]
    {authDigest chainKey : Word} {aux : Bool} {now cp : U256}
    (h : submitPartialIntent s closeProofOk chainBound newerOk authDigest chainKey aux now cp
          = some s') :
    closeProofOk ∧ chainBound ∧ s.channelActive = true ∧
    s.usedChains.get chainKey = false := by
  unfold submitPartialIntent at h
  by_cases h1 : s.channelActive = false
  · rw [if_pos h1] at h; simp at h
  rw [if_neg h1] at h
  by_cases h2 : ¬ closeProofOk
  · rw [if_pos h2] at h; simp at h
  rw [if_neg h2] at h
  by_cases h3 : aux = false
  · rw [if_pos h3] at h; simp at h
  rw [if_neg h3] at h
  by_cases h4 : ¬ chainBound
  · rw [if_pos h4] at h; simp at h
  rw [if_neg h4] at h
  by_cases h5 : s.usedChains.get chainKey = true
  · rw [if_pos h5] at h; simp at h
  rw [if_neg h5] at h
  refine ⟨Decidable.of_not_not h2, Decidable.of_not_not h4, ?_, ?_⟩
  · cases hb : s.channelActive with
    | false => exact absurd hb h1
    | true => rfl
  · cases hb : s.usedChains.get chainKey with
    | false => rfl
    | true => exact absurd hb h5

/-- Decompose a successful finalize: the intent was pending, the window
    strictly elapsed, and the unique post-state consumes the chain key
    and authorizes exactly the pending digest. -/
theorem finalizePartial_some {s s' : PartialState} {now : U256}
    (h : finalizePartial s now = some s') :
    s.pending = true ∧ s.pendingDeadline < now ∧
    s' = { s with
      usedChains := s.usedChains.set s.pendingChainKey true
      pending := false
      authorizedOnRollup := s.authorizedOnRollup.set s.pendingAuthDigest true } := by
  unfold finalizePartial at h
  by_cases h1 : s.pending = false
  · rw [if_pos h1] at h; simp at h
  rw [if_neg h1] at h
  by_cases h2 : now ≤ s.pendingDeadline
  · rw [if_pos h2] at h; simp at h
  rw [if_neg h2] at h
  rw [Option.some.injEq] at h
  refine ⟨?_, Nat.lt_of_not_le h2, h.symm⟩
  cases hb : s.pending with
  | false => exact absurd hb h1
  | true => rfl

/-- **The mint is gated.** A successful finalize authorizes the PENDING
    digest (the one bound to the verified intent) and marks its chain
    key used. Composed with `submitPartialIntent_requires_proof`, every
    authorization minted by this manager traces back to a
    proof-verified, challenge-surviving close-intent state — the honest
    flow behind `Assumptions.BurnAuthorizationsLegitimate`. -/
theorem finalizePartial_authorizes {s s' : PartialState} {now : U256}
    (h : finalizePartial s now = some s') :
    s'.authorizedOnRollup.get s.pendingAuthDigest = true ∧
    s'.usedChains.get s.pendingChainKey = true ∧ s'.pending = false := by
  obtain ⟨_, _, hs'⟩ := finalizePartial_some h
  subst hs'
  refine ⟨by simp [Mapping.get_set_eq], by simp [Mapping.get_set_eq], rfl⟩

/-- **No digest is minted out of thin air.** If finalize newly set some
    digest `d` (false before, true after), then `d` IS the pending
    digest — the only write is :990 on `pendingPartialWithdrawalAuthDigest`. -/
theorem finalizePartial_mints_only_pending {s s' : PartialState} {now : U256} {d : Word}
    (h : finalizePartial s now = some s')
    (hnew : s'.authorizedOnRollup.get d = true)
    (hold : s.authorizedOnRollup.get d = false) :
    d = s.pendingAuthDigest := by
  obtain ⟨_, _, hs'⟩ := finalizePartial_some h
  subst hs'
  by_cases hd : d = s.pendingAuthDigest
  · exact hd
  · exfalso
    rw [show ((({ s with
          usedChains := s.usedChains.set s.pendingChainKey true,
          pending := false,
          authorizedOnRollup := s.authorizedOnRollup.set s.pendingAuthDigest true }
        : PartialState).authorizedOnRollup).get d)
        = s.authorizedOnRollup.get d from Mapping.get_set_ne _ _ hd] at hnew
    rw [hold] at hnew
    exact absurd hnew (by decide)

/-- **Chain-key single-use.** After a finalize, re-submitting an intent
    on the SAME chain key reverts (:933): the burn tx_leaf chain can
    authorize at most one withdrawal. -/
theorem partial_chain_key_single_use {s s' : PartialState} {now : U256}
    (h : finalizePartial s now = some s')
    {closeProofOk chainBound newerOk : Prop}
    [Decidable closeProofOk] [Decidable chainBound] [Decidable newerOk]
    {authDigest : Word} {aux : Bool} {now' cp : U256} :
    submitPartialIntent s' closeProofOk chainBound newerOk authDigest
      s.pendingChainKey aux now' cp = none := by
  have hused : s'.usedChains.get s.pendingChainKey = true :=
    (finalizePartial_authorizes h).2.1
  unfold submitPartialIntent
  by_cases h1 : s'.channelActive = false
  · rw [if_pos h1]
  rw [if_neg h1]
  by_cases h2 : ¬ closeProofOk
  · rw [if_pos h2]
  rw [if_neg h2]
  by_cases h3 : aux = false
  · rw [if_pos h3]
  rw [if_neg h3]
  by_cases h4 : ¬ chainBound
  · rw [if_pos h4]
  rw [if_neg h4]
  rw [if_pos hused]

/-- **Inhabitation (D6).** The submit → finalize pipeline is satisfiable:
    a verified intent on an active channel with a fresh chain key
    finalizes after the window and mints the authorization. -/
theorem partial_pipeline_satisfiable :
    ∃ (s1 s2 : PartialState),
      submitPartialIntent
        { channelActive := true, usedChains := fun _ => false, pending := false,
          pendingAuthDigest := 0, pendingChainKey := 0, pendingDeadline := 0,
          authorizedOnRollup := fun _ => false }
        True True True 7 3 true 0 5 = some s1 ∧
      finalizePartial s1 6 = some s2 ∧
      s2.authorizedOnRollup.get 7 = true := by
  refine ⟨_, _, rfl, rfl, ?_⟩
  simp [finalizePartial, submitPartialIntent, Mapping.get_set_eq]

/-!
  ## SECURITY OBSERVATIONS

  * **Channel solvency.** `claim_preserves_cap` + `pull_preserves_cap`
    inductively give `totalCreditedOut ≤ receivedChannelFunds` at all
    times, i.e. `Σ channel payouts ≤ Σ ETH pulled from the rollup`. Since
    `pullChannelFunds` pulls real ETH bounded by the rollup's own escrow
    (`IntmaxRollupSolvency.global_solvency`), the channel path cannot
    drain more than was deposited — cross-channel theft impossible.

  * **No double-claim.** `claim_no_double` is the CEI guarantee: the credit
    is zeroed before the external ETH send (:1171-1174), and
    `nonReentrant` backs it (`Assumptions.SingleCallAtomicity`,
    `Assumptions.EthSendFailureReverts`).

  * **Nullifier single-use.** The manager's claim intents
    (`submitWithdrawalClaim` :1051/:1073, `submitPostCloseClaim`
    :1107/:1136) check-then-set the per-claim nullifiers
    (`usedWithdrawalNullifiers`, `usedSharedNativeNullifiers`,
    `usedLateOutgoingDebitNullifiers` — MANAGER storage, CSM.sol:515-517)
    — same one-shot shape as the rollup nullifier (modeled in
    IntmaxRollupWithdraw / IndexedMerkle). The `ChannelSettlementVerifier`
    proof checks are crypto-oracle wrappers (out of scope as primitives)
    and STATELESS apart from set-once VK latches, so the
    fund-safety-critical accounting is the cap + CEI proved here.

  * **Burn authorization discipline.** `submitPartialIntent_requires_proof`
    + `finalizePartial_authorizes` + `finalizePartial_mints_only_pending`
    + `partial_chain_key_single_use` prove THIS manager only mints rollup
    burn authorizations from a proof-verified, challenge-surviving,
    single-use-chain intent. This is the honest-manager half of
    `Assumptions.BurnAuthorizationsLegitimate`; the rollup cannot verify
    it (any registered manager's `authorizePartialWithdrawal` call is
    accepted), which is exactly why it is a named trust assumption.
-/

end ChannelSettlementManager
end Contracts
end Zkp
