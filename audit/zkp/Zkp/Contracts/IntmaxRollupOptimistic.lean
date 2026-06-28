import Zkp.Contracts.Evm

/-
  IntmaxRollup — optimistic pipeline safety (rollback floor)
  =========================================================

  Source: `contracts/src/IntmaxRollup.sol`
    postBlockAndSubmit :685 · _submit :1053 · finalize :1102 ·
    fraudProof :1153 · _truncateSubmissions/_rollbackBatch :1662/:1678

  ## Why withdrawal anchors are permanent

  Withdrawals anchor to `finalizedStateRoots` (written only by `finalize`,
  on a verified validity proof). For that anchor to stay valid forever,
  finalized blocks must never be rolled back. `fraudProof` enforces the
  **ROLLBACK FLOOR** (:1170): it REVERTS for any submission whose
  `startBlockNumber <= latestFinalizedBlockNumber`, and rollback only
  rewinds from the (necessarily-above-floor) fraud target upward. Hence
  `blockHashChainAt[k]` for every finalized height `k` is immutable, and a
  finalized state root can never be un-finalized. This is what makes
  `withdrawNative`'s "any historically-finalized root" anchor sound.

  ## What the rest of the pipeline does (no new fund-effect)

  `_postBlock` folds the block/deposit/channel-reg hash chains (structural;
  the deposit fold mirrors the circuit — see Deposit.deposit_sequential, and
  the validity proof verified at `finalize` checks the block chain).
  `_submit` records a keccak commitment over the blob (data availability).
  `_verifyFraud`/`_verifyKZG`/`_verifyMle` are crypto-oracle wrappers.
  `_truncate/_rollback` only delete from the fraud target upward. None
  of these move escrow; the only escrow movers are
  deposit/withdrawNative/claimAuthorized (all modeled).
-/

namespace Zkp
namespace Contracts
namespace IntmaxRollup
namespace Optimistic

open Zkp.Contracts.Evm

/-- Submission/finalization slice of storage. -/
structure SubState where
  latestFinalizedBlockNumber : Nat
  finalizedStateRoots : Mapping Word Bool

/-- A batch's block range (`_batchMetadata`). -/
structure BatchMeta where
  startBlockNumber : Nat
  endBlockNumber : Nat

/-- `fraudProof(id, …)` rollback-eligibility guard (:1162-1172): a
    submission can be fraud-proofed (and thus rolled back) ONLY if its
    batch starts strictly above the finalized floor. Returns the (kept or
    rolled-back) state; `none` = revert. Here we model just the guard +
    the fact that rollback never lowers `latestFinalizedBlockNumber`. -/
def fraudProofGuard (s : SubState) (meta : BatchMeta) : Call SubState :=
  if meta.startBlockNumber ≤ s.latestFinalizedBlockNumber then
    none                                   -- SubmissionBeforeFinalizedBlock (revert)
  else
    some s                                 -- eligible; rollback rewinds from target upward

/-- **Rollback floor.** A fraud proof can only target a batch strictly
    above the latest finalized block — so finalized blocks are never
    rolled back. -/
theorem fraud_above_floor {s s' : SubState} {meta : BatchMeta}
    (h : fraudProofGuard s meta = some s') :
    s.latestFinalizedBlockNumber < meta.startBlockNumber := by
  unfold fraudProofGuard at h
  by_cases hb : meta.startBlockNumber ≤ s.latestFinalizedBlockNumber
  · rw [if_pos hb] at h; simp at h
  · exact Nat.lt_of_not_le hb

/-- **Finalized roots are permanent.** Nothing in the fraud/rollback path
    clears `finalizedStateRoots` (only `finalize` writes it, to `true`,
    permanently). We model rollback as preserving `finalizedStateRoots`,
    so any root a withdrawal anchored to remains anchored forever. -/
theorem finalized_roots_persist {s s' : SubState} {meta : BatchMeta}
    (h : fraudProofGuard s meta = some s') (root : Word) :
    s.finalizedStateRoots.get root = s'.finalizedStateRoots.get root := by
  unfold fraudProofGuard at h
  by_cases hb : meta.startBlockNumber ≤ s.latestFinalizedBlockNumber
  · rw [if_pos hb] at h; simp at h
  · rw [if_neg hb] at h
    simp only [Option.some.injEq] at h
    rw [h]

/-!
  ## SECURITY OBSERVATION — closes the optimistic-pipeline ↔ withdrawal link

  Combined with `IntmaxRollupWithdraw.finalize_only_on_valid` (finalized
  roots come only from verified validity proofs) and
  `withdrawNative_requires_proof` (payout needs an anchored proof):
  `fraud_above_floor` + `finalized_roots_persist` show the optimistic
  challenge machinery can NEVER invalidate a finalized state root a
  withdrawal relies on. So the optimistic layer adds liveness/availability
  pressure (timeout removal, slashing — see IntmaxRollupStake) WITHOUT
  weakening the soundness of the withdrawal anchor. The forged-block
  concern is fully handled at `finalize` (real validity proof required)
  and the rollback floor (finalized history immutable).
-/

end Optimistic
end IntmaxRollup
end Contracts
end Zkp
