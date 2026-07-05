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

  `reclaimStake` (:1269-1283) is FUND-BEARING: it credits the full
  `POST_BLOCK_STAKE` to `pendingWithdrawals[submitter]` (:1281). Its guard
  shape deliberately DIFFERS from the internal resolvers:
    * on an already-resolved bond it REVERTS (`revert NothingToReclaim`,
      :1272), whereas `_refundStake`/`_slashStake` delete-and-return
      (no-op, :1735-1737 / :1713-1715) — internal callers must not have
      `finalize`/`fraudProof` fail on a missing bond;
    * it has the EXTRA finality guard
      `endBlockNumber ≤ latestFinalizedBlockNumber` (:1274), so only a
      bond whose whole batch is canonical finalized history can be
      reclaimed.
  Both orders of double-resolution are proved impossible below:
  refund/slash-then-reclaim REVERTS (the record was deleted, so
  `submitter == 0` trips :1272), and reclaim-then-refund/slash pays
  nothing (the deleted record hits the guard-delete no-op branch).

  ## Constraint inventory

  | function        | guard                              | effect on success |
  |-----------------|------------------------------------|-------------------|
  | `_refundStake`  | `submitter==0 || spent` ⇒ delete-only (:1735) | spent+delete (:1740-1742); +stake → submitter (:1744) |
  | `_slashStake`   | same (:1713)                       | spent+delete (:1718-1719); +reward → reporter, +treasuryShare → treasury (:1724-1725) |
  | `reclaimStake`  | `submitter==0 || spent` ⇒ REVERT (:1272); `endBlock > latestFinalized` ⇒ REVERT (:1274) | spent+delete (:1279-1280); +stake → submitter (:1281) |
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

/-- The stake-lifecycle slice of storage. `endBlock` models
    `_batchMetadata[id].endBlockNumber` (the LAST block of the batch) and
    `latestFinalizedBlock` models `latestFinalizedBlockNumber` — the two
    values `reclaimStake`'s finality guard (:1274) compares. -/
structure StakeState where
  stakeInfo : Mapping Nat StakeRec
  pending : Mapping Addr U256
  endBlock : Mapping Nat U256
  latestFinalizedBlock : U256

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
    { s with
      stakeInfo := s.stakeInfo.set id StakeRec.empty
      pending := s.pending.set info.submitter (s.pending.get info.submitter + POST_BLOCK_STAKE) }

/-- `_slashStake(id, reporter)` (:1711): guard ⇒ delete only; else
    spent+delete and credit `reward`/`treasuryShare`. -/
def slashStake (s : StakeState) (id : Nat) (reporter treasury : Addr) : StakeState :=
  let info := s.stakeInfo.get id
  if info.submitter = 0 ∨ info.spent = true then
    { s with stakeInfo := s.stakeInfo.set id StakeRec.empty }
  else
    { s with
      stakeInfo := s.stakeInfo.set id StakeRec.empty
      pending := (s.pending.set reporter (s.pending.get reporter + reward)).set treasury
                   ((s.pending.set reporter (s.pending.get reporter + reward)).get treasury
                     + treasuryShare) }

/-- `reclaimStake(id)` (:1269-1283) — an EXTERNAL, permissionless,
    fund-bearing entry point (the bond is always credited to the RECORDED
    submitter, :1281, so a third-party caller gains nothing). Guards, in
    Solidity order:
      1. `submitter == 0 || spent` ⇒ `revert NothingToReclaim` (:1272) —
         a REVERT, unlike the internal resolvers' delete-and-return;
      2. `endBlockNumber > latestFinalizedBlockNumber` ⇒
         `revert SubmissionNotYetFinalized` (:1274) — only a bond whose
         whole batch is finalized canonical history is no longer at risk.
    Effects (CEI, pull-payment, no external call): `spent = true` (:1279),
    `delete stakeInfo[id]` (:1280),
    `pendingWithdrawals[submitter] += POST_BLOCK_STAKE` (:1281). -/
def reclaimStake (s : StakeState) (id : Nat) : Call StakeState :=
  let info := s.stakeInfo.get id
  if info.submitter = 0 ∨ info.spent = true then none          -- :1272 revert NothingToReclaim
  else if s.latestFinalizedBlock < s.endBlock.get id then none -- :1274 revert SubmissionNotYetFinalized
  else some { s with
    stakeInfo := s.stakeInfo.set id StakeRec.empty             -- :1279-1280
    pending := s.pending.set info.submitter
      (s.pending.get info.submitter + POST_BLOCK_STAKE) }      -- :1281

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

/-! ### reclaimStake theorems -/

/-- Decompose a successful reclaim: the bond was live, the batch was
    fully finalized, and the unique post-state deletes the record and
    credits the recorded submitter the full bond. -/
theorem reclaim_some {s s' : StakeState} {id : Nat}
    (h : reclaimStake s id = some s') :
    ¬ resolved s id ∧
    s.endBlock.get id ≤ s.latestFinalizedBlock ∧
    s' = { s with
      stakeInfo := s.stakeInfo.set id StakeRec.empty
      pending := s.pending.set (s.stakeInfo.get id).submitter
        (s.pending.get (s.stakeInfo.get id).submitter + POST_BLOCK_STAKE) } := by
  unfold reclaimStake at h
  by_cases h1 : (s.stakeInfo.get id).submitter = 0 ∨ (s.stakeInfo.get id).spent = true
  · rw [if_pos h1] at h; simp at h
  rw [if_neg h1] at h
  by_cases h2 : s.latestFinalizedBlock < s.endBlock.get id
  · rw [if_pos h2] at h; simp at h
  rw [if_neg h2] at h
  rw [Option.some.injEq] at h
  exact ⟨h1, Nat.le_of_not_lt h2, h.symm⟩

/-- **Reclaim reverts on a resolved bond** (`revert NothingToReclaim`,
    :1272). This is the guard-shape DIFFERENCE from `_refundStake`/
    `_slashStake` (which delete-and-return): an already-refunded or
    already-slashed bond makes the whole reclaim call fail. -/
theorem reclaim_requires_unresolved {s : StakeState} {id : Nat}
    (h : resolved s id) : reclaimStake s id = none := by
  unfold reclaimStake
  have hg : (s.stakeInfo.get id).submitter = 0 ∨ (s.stakeInfo.get id).spent = true := h
  simp only [hg, if_true]

/-- **Reclaim requires full-batch finality** (:1274): a batch straddling
    the finalized boundary (`endBlock > latestFinalized`) reverts. -/
theorem reclaim_requires_finalized {s s' : StakeState} {id : Nat}
    (h : reclaimStake s id = some s') :
    s.endBlock.get id ≤ s.latestFinalizedBlock :=
  (reclaim_some h).2.1

/-- A successful reclaim empties the bond record, so the bond is
    `resolved` afterwards. -/
theorem reclaim_resolves {s s' : StakeState} {id : Nat}
    (h : reclaimStake s id = some s') : resolved s' id := by
  obtain ⟨_, _, hs'⟩ := reclaim_some h
  subst hs'
  left
  simp [Mapping.get_set_eq, StakeRec.empty]

/-- **Stake conservation for reclaim.** A successful reclaim credits the
    RECORDED submitter EXACTLY one `POST_BLOCK_STAKE` — never more, never
    to anyone else (Solidity :1281; the caller is irrelevant). -/
theorem reclaim_pays_bond {s s' : StakeState} {id : Nat}
    (h : reclaimStake s id = some s') :
    s'.pending.get (s.stakeInfo.get id).submitter
      = s.pending.get (s.stakeInfo.get id).submitter + POST_BLOCK_STAKE ∧
    ∀ a, a ≠ (s.stakeInfo.get id).submitter → s'.pending.get a = s.pending.get a := by
  obtain ⟨_, _, hs'⟩ := reclaim_some h
  subst hs'
  exact ⟨by simp [Mapping.get_set_eq], fun a ha => by simp [Mapping.get_set_ne _ _ ha]⟩

/-- **No double-payout: finalize-refund then reclaim.** `_refundStake`
    deletes the record (:1742), so a later reclaim REVERTS at the
    `submitter == 0` guard (:1272). -/
theorem no_double_payout_refund_then_reclaim (s : StakeState) (id : Nat) :
    reclaimStake (refundStake s id) id = none :=
  reclaim_requires_unresolved (refund_resolves s id)

/-- **No double-payout: slash then reclaim.** Same shape: `_slashStake`
    deletes the record (:1719) ⇒ reclaim reverts (:1272). -/
theorem no_double_payout_slash_then_reclaim (s : StakeState) (id : Nat) (rep tre : Addr) :
    reclaimStake (slashStake s id rep tre) id = none :=
  reclaim_requires_unresolved (slash_resolves s id rep tre)

/-- **No double-payout: reclaim then finalize-refund.** Reclaim deletes
    the record (:1280), so a later `_refundStake` hits the guard-delete
    branch (:1735-1737) and pays NOTHING. -/
theorem no_double_payout_reclaim_then_refund {s s' : StakeState} {id : Nat}
    (h : reclaimStake s id = some s') :
    (refundStake s' id).pending = s'.pending :=
  refund_guard_noop _ id (reclaim_resolves h)

/-- **No double-payout: reclaim then slash.** Same: the deleted record
    makes `_slashStake` a guard-delete no-op (:1713-1715). -/
theorem no_double_payout_reclaim_then_slash {s s' : StakeState} {id : Nat}
    (h : reclaimStake s id = some s') (rep tre : Addr) :
    (slashStake s' id rep tre).pending = s'.pending :=
  slash_guard_noop _ id rep tre (reclaim_resolves h)

/-- **Reclaim single-shot.** A successful reclaim cannot be replayed:
    the second call reverts (the record is deleted). -/
theorem reclaim_no_double {s s' : StakeState} {id : Nat}
    (h : reclaimStake s id = some s') : reclaimStake s' id = none :=
  reclaim_requires_unresolved (reclaim_resolves h)

/-- **Inhabitation (D6).** `reclaimStake` is satisfiable: a live bond on
    a fully-finalized batch reclaims successfully — the transition is not
    vacuously safe. -/
theorem reclaim_satisfiable :
    ∃ s' : StakeState,
      reclaimStake
        { stakeInfo := fun _ => { submitter := 1, spent := false }
          pending := fun _ => 0
          endBlock := fun _ => 0
          latestFinalizedBlock := 0 } 0 = some s' := by
  exact ⟨_, rfl⟩

/-!
  ## SECURITY OBSERVATIONS

  * **Anti-double-payout.** `no_double_payout_*` proves the `spent`/
    `delete` guard makes every bond resolvable once — across ALL THREE
    resolvers and in BOTH orders (refund/slash-then-reclaim reverts;
    reclaim-then-refund/slash pays nothing). Combined with
    `stake_conserved` (slash distributes exactly the bond) and
    `reclaim_pays_bond` (reclaim credits exactly the bond, to the
    recorded submitter only), the stake machinery neither mints nor
    leaks ETH: bonds in == bonds out.

  * **Reclaim soundness precondition.** `reclaim_requires_finalized`
    captures the :1274 guard: only a bond whose batch END block is
    finalized canonical history can exit early. The argument that a live
    stake at a finalized height is THE canonical batch (rollback floor +
    unique live batch per height) is contract-level machinery documented
    at IntmaxRollup.sol:1249-1267 and pinned by ReclaimStake.t.sol; the
    model takes `latestFinalizedBlock`/`endBlock` as the already-agreed
    heights.

  * **Relation to fund safety.** The bond accounting is SEPARATE from the
    user-fund escrow (`totalEscrowed`), so a stake bug could at worst
    affect bonds, not user deposits — and even that is closed here.
    Crucially, `finalize` writes `finalizedStateRoots` ONLY on a verified
    validity proof (`finalize_only_on_valid`), and `fraudProof` removes
    invalid submissions before they finalize; so the optimistic mechanism
    cannot finalize a forged state. Withdrawal safety
    (`withdrawNative_requires_proof`) is therefore independent of bond
    economics. `reclaimStake` guards on the same `submitter==0 || spent`
    condition but REVERTS (rather than no-ops) once resolved
    (`reclaim_requires_unresolved`, :1272) — either behavior blocks the
    double payout, and both orders are proved above.
-/

end Stake
end IntmaxRollup
end Contracts
end Zkp
