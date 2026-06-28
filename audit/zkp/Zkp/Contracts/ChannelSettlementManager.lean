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
  ## SECURITY OBSERVATIONS

  * **Channel solvency.** `claim_preserves_cap` + `pull_preserves_cap`
    inductively give `totalCreditedOut ≤ receivedChannelFunds` at all
    times, i.e. `Σ channel payouts ≤ Σ ETH pulled from the rollup`. Since
    `pullChannelFunds` pulls real ETH bounded by the rollup's own escrow
    (`IntmaxRollupSolvency.global_solvency`), the channel path cannot
    drain more than was deposited — cross-channel theft impossible.

  * **No double-claim.** `claim_no_double` is the CEI guarantee: the credit
    is zeroed before the external ETH send, and `nonReentrant` backs it.

  * **Nullifier single-use.** The manager's claim *intents*
    (verifyWithdrawalClaim / verifyPostCloseClaim) set per-claim
    nullifiers (`usedWithdrawalNullifiers`, `usedSharedNativeNullifiers`,
    `usedLateOutgoingDebitNullifiers`) check-then-set (CEI) — same
    one-shot shape as the rollup nullifier (modeled in
    IntmaxRollupWithdraw / IndexedMerkle). The `verify*` entry points and
    `ChannelSettlementVerifier` proof checks are crypto-oracle wrappers
    (out of scope as primitives), so the fund-safety-critical accounting
    is the cap + CEI proved here.
-/

end ChannelSettlementManager
end Contracts
end Zkp
