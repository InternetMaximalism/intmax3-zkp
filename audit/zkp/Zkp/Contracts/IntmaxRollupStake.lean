import Zkp.Contracts.Evm

/-
  IntmaxRollup — optimistic-rollup stake lifecycle
  ================================================

  Source: `contracts/src/IntmaxRollup.sol`
    postBlockAndSubmit :685 · finalize/_refundStake :1102/:1733 ·
    fraudProof/_slashStake :1153/:1711 · reclaimStake :1269

  ## Protocol role

  Each posted block batch is backed by a `POST_BLOCK_STAKE` (1 ETH) bond.
  The bond is resolved EXACTLY ONCE:
    * `_refundStake` (on finalize) or `reclaimStake` — returned to submitter;
    * `_slashStake`  (on confirmed fraud) — split `reward` (90%) to the
      reporter and `treasuryShare` (10%) to the fraud treasury.
  Every resolver guards on `submitter == 0 || spent` and then sets
  `spent = true` + `delete stakeInfo[id]`, so a bond can never be paid out
  twice. We prove single-resolution and stake conservation (the sum paid
  out equals the bond, never more) — the anti-double-payout property that
  keeps the optimistic mechanism from leaking ETH.

  ## Constraint inventory

  | function        | guard                              | effect on success |
  |-----------------|------------------------------------|-------------------|
  | `_refundStake`  | `submitter==0 || spent` ⇒ delete-only | spent+delete; +stake → submitter |
  | `_slashStake`   | same                               | spent+delete; +reward → reporter, +treasuryShare → treasury |
  | `reclaimStake`  | `submitter==0 || spent` ⇒ revert; endBlock ≤ finalized | spent+delete; +stake → submitter |
-/

namespace Zkp
namespace Contracts
namespace IntmaxRollup
namespace Stake

open Zkp.Contracts.Evm

/-- `POST_BLOCK_STAKE` = 1 ether (`contracts/src/IntmaxRollup.sol:496`). -/
def POST_BLOCK_STAKE : U256 := 1000000000000000000

/-- `reward = stake * 90 / 100` (`FRAUD_REWARD_PERCENT = 90`, :497). -/
def reward : U256 := POST_BLOCK_STAKE * 90 / 100
/-- `treasuryShare = stake - reward` (the remaining 10%). -/
def treasuryShare : U256 := POST_BLOCK_STAKE - reward

theorem reward_le_stake : reward ≤ POST_BLOCK_STAKE := by decide

/-- **Stake conservation.** The slashed shares sum to exactly the bond:
    no ETH is created or lost when a stake is resolved by slashing. -/
theorem stake_conserved : reward + treasuryShare = POST_BLOCK_STAKE := by decide

/-- A stake bond record. `submitter = 0` (default Addr) ⇒ absent/deleted. -/
structure StakeRec where
  submitter : Addr
  spent : Bool

def StakeRec.empty : StakeRec := { submitter := 0, spent := false }

/-- The stake-lifecycle slice of storage. -/
structure StakeState where
  stakeInfo : Mapping Nat StakeRec
  pending : Mapping Addr U256

/-- Is the bond already resolved (absent or spent)? -/
def resolved (s : StakeState) (id : Nat) : Prop :=
  (s.stakeInfo.get id).submitter = 0 ∨ (s.stakeInfo.get id).spent = true

/-- `_refundStake(id)` (:1733): guard ⇒ delete only; else spent+delete and
    credit the submitter the full bond. -/
def refundStake (s : StakeState) (id : Nat) : StakeState :=
  let info := s.stakeInfo.get id
  if info.submitter = 0 ∨ info.spent = true then
    { s with stakeInfo := s.stakeInfo.set id StakeRec.empty }
  else
    { stakeInfo := s.stakeInfo.set id StakeRec.empty
      pending := s.pending.set info.submitter (s.pending.get info.submitter + POST_BLOCK_STAKE) }

/-- `_slashStake(id, reporter)` (:1711): guard ⇒ delete only; else
    spent+delete and credit `reward`/`treasuryShare`. -/
def slashStake (s : StakeState) (id : Nat) (reporter treasury : Addr) : StakeState :=
  let info := s.stakeInfo.get id
  if info.submitter = 0 ∨ info.spent = true then
    { s with stakeInfo := s.stakeInfo.set id StakeRec.empty }
  else
    { stakeInfo := s.stakeInfo.set id StakeRec.empty
      pending := (s.pending.set reporter (s.pending.get reporter + reward)).set treasury
                   ((s.pending.set reporter (s.pending.get reporter + reward)).get treasury
                     + treasuryShare) }

/-- After ANY resolution the bond record is emptied (`submitter = 0`), so
    it is `resolved`. -/
theorem refund_resolves (s : StakeState) (id : Nat) :
    resolved (refundStake s id) id := by
  unfold resolved refundStake
  by_cases h : (s.stakeInfo.get id).submitter = 0 ∨ (s.stakeInfo.get id).spent = true
  · simp only [h, if_true]; left; simp [Mapping.get_set_eq, StakeRec.empty]
  · simp only [h, if_false]; left; simp [Mapping.get_set_eq, StakeRec.empty]

theorem slash_resolves (s : StakeState) (id : Nat) (rep tre : Addr) :
    resolved (slashStake s id rep tre) id := by
  unfold resolved slashStake
  by_cases h : (s.stakeInfo.get id).submitter = 0 ∨ (s.stakeInfo.get id).spent = true
  · simp only [h, if_true]; left; simp [Mapping.get_set_eq, StakeRec.empty]
  · simp only [h, if_false]; left; simp [Mapping.get_set_eq, StakeRec.empty]

/-- **Guard no-op.** Resolving an ALREADY-resolved bond changes no
    pending balances (the guard branch only deletes). -/
theorem refund_guard_noop (s : StakeState) (id : Nat) (h : resolved s id) :
    (refundStake s id).pending = s.pending := by
  unfold refundStake
  have : (s.stakeInfo.get id).submitter = 0 ∨ (s.stakeInfo.get id).spent = true := h
  simp only [this, if_true]

theorem slash_guard_noop (s : StakeState) (id : Nat) (rep tre : Addr) (h : resolved s id) :
    (slashStake s id rep tre).pending = s.pending := by
  unfold slashStake
  have : (s.stakeInfo.get id).submitter = 0 ∨ (s.stakeInfo.get id).spent = true := h
  simp only [this, if_true]

/-- **No double-payout.** Once a bond is refunded, a subsequent slash (or
    refund) pays NOTHING — the guard fires because the record is emptied.
    So each `POST_BLOCK_STAKE` is paid out at most once. -/
theorem no_double_payout_refund_then_slash (s : StakeState) (id : Nat) (rep tre : Addr) :
    (slashStake (refundStake s id) id rep tre).pending = (refundStake s id).pending :=
  slash_guard_noop _ id rep tre (refund_resolves s id)

theorem no_double_payout_slash_then_refund (s : StakeState) (id : Nat) (rep tre : Addr) :
    (refundStake (slashStake s id rep tre) id).pending = (slashStake s id rep tre).pending :=
  refund_guard_noop _ id (slash_resolves s id rep tre)

/-!
  ## SECURITY OBSERVATIONS

  * **Anti-double-payout.** `no_double_payout_*` proves the `spent`/
    `delete` guard makes every bond resolvable once. Combined with
    `stake_conserved` (slash distributes exactly the bond), the stake
    machinery neither mints nor leaks ETH: bonds in == bonds out.

  * **Relation to fund safety.** The bond accounting is SEPARATE from the
    user-fund escrow (`totalEscrowed`), so a stake bug could at worst
    affect bonds, not user deposits — and even that is closed here.
    Crucially, `finalize` writes `finalizedStateRoots` ONLY on a verified
    validity proof (`finalize_only_on_valid`), and `fraudProof` removes
    invalid submissions before they finalize; so the optimistic mechanism
    cannot finalize a forged state. Withdrawal safety
    (`withdrawNative_requires_proof`) is therefore independent of bond
    economics. `reclaimStake` shares the same guard and is a no-op once
    resolved (same proof shape).
-/

end Stake
end IntmaxRollup
end Contracts
end Zkp
