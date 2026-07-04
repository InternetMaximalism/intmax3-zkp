import Zkp.Contracts.Evm

/-
  IntmaxRollup — native fund path (deposit / finalize / withdrawNative)
  ====================================================================

  Source: `contracts/src/IntmaxRollup.sol`

  ## Protocol role

  `IntmaxRollup` is the L1 settlement contract. ETH enters via
  `deposit()` (escrowed) and leaves via `withdrawNative()` against a
  finalized validity state and a verified WithdrawalCircuit proof. This
  file models the native-fund accounting — the heart of system-wide
  fund safety — and connects it to the proven circuit statements.

  ## The global solvency ceiling (the invariant)

  `totalEscrowed` is the single source of payable funds:
    * `deposit()`  : `totalEscrowed += amount`           (:829)
    * `withdrawNative()` per leaf: `totalEscrowed -= amount` (:1373)
  Solidity-0.8 makes the subtraction CHECKED, so a withdrawal that would
  drive `totalEscrowed` below zero REVERTS. Therefore, over any history,
  `Σ withdrawals ≤ Σ deposits` — the rollup can never pay out more ETH
  than was deposited. We prove this directly from the checked subtraction.

  ## withdrawNative checks (IntmaxRollup.sol:1307-1377)

  | step | line       | check                                                  |
  |------|------------|--------------------------------------------------------|
  | 1    | :1316      | `_verifyMleWithdrawal(mleProof)` — proof verifies      |
  | 2a   | :1331      | `finalizedStateRoots[extCommitment]` — anchored        |
  | 3    | :1345      | `pisHash` recomputed == proof PI — binds `ws` to proof |
  | 4a   | :1350      | per leaf: ETH token only                               |
  | 4b   | :1351      | per leaf: `!withdrawalNullifierUsed[nullifier]`        |
  | 4c   | :1357-1368 | per leaf: burn (auxData≠0) ⇒ authorized                |
  | 4d   | :1371-1374 | set nullifier; `totalEscrowed -= amount`; credit       |

  Named trust/modeling assumptions for the theorems below live in
  `Zkp.Contracts.Assumptions`: `BurnAuthorizationsLegitimate` (burn
  path), `MleVerificationEnabled` (finalize gate), `SingleCallAtomicity`
  and `EthSendFailureReverts` (model semantics).
-/

namespace Zkp
namespace Contracts
namespace IntmaxRollup

open Zkp.Contracts.Evm

/-- The native-fund slice of `IntmaxRollup` storage. -/
structure RollupState where
  totalEscrowed : U256
  nullifierUsed : Mapping Word Bool
  pendingWithdrawals : Mapping Addr U256
  finalizedStateRoots : Mapping Word Bool
  partialWithdrawalAuthorized : Mapping Word Bool

/-- One withdrawal leaf (the on-chain `Withdrawal` struct). -/
structure Withdrawal where
  recipient : Addr
  amount : U256
  nullifier : Word
  auxData : Word        -- 0 ⇒ normal; ≠0 ⇒ burn (needs authorization)
  isEth : Bool

/-- `keccak256("IMPW" || nullifier || recipient || tokenIndex || amount ||
    auxData)` — the partial-withdrawal authorization digest (:1362).
    Uninterpreted; binds ALL fields so an auth can't be reused with a
    different recipient/amount. -/
opaque authDigest : Withdrawal → Word

/-! ### deposit() — funds in -/

/-- `deposit()` escrow effect (:829): `totalEscrowed += amount`, with the
    0.8 overflow check. Reverts only on the (unreachable for real ETH)
    2^256 overflow. -/
def deposit (s : RollupState) (amount : U256) : Call RollupState :=
  match checkedAdd s.totalEscrowed amount with
  | none => none
  | some te => some { s with totalEscrowed := te }

/-! ### withdrawNative() — funds out -/

/-- One leaf of the `withdrawNative` loop (:1348-1376), AFTER the call-
    level checks (proof verified, anchored, pis-bound) have passed. -/
def withdrawLeaf (s : RollupState) (w : Withdrawal) : Call RollupState :=
  if w.isEth = false then none                                    -- :1350
  else if s.nullifierUsed.get w.nullifier = true then none        -- :1351 no double-withdraw
  else if w.auxData ≠ 0 ∧ s.partialWithdrawalAuthorized.get (authDigest w) = false
       then none                                                  -- :1357-1368 burn needs auth
  else (checkedSub s.totalEscrowed w.amount).map (fun te =>       -- :1373 solvency ceiling
         { s with
           nullifierUsed := s.nullifierUsed.set w.nullifier true  -- :1371
           totalEscrowed := te
           pendingWithdrawals :=
             s.pendingWithdrawals.set w.recipient
               (s.pendingWithdrawals.get w.recipient + w.amount) }) -- :1374

/-- The `withdrawNative` per-leaf loop, threading state, atomic on revert. -/
def withdrawLoop (s : RollupState) : List Withdrawal → Call RollupState
  | [] => some s
  | w :: ws => (withdrawLeaf s w).bind (fun s' => withdrawLoop s' ws)

/-- The call-level preconditions of `withdrawNative` before the loop:
    the MLE/WHIR proof verifies, the ext-commitment is a finalized state
    root, and the recomputed `pisHash` matches the proof's PI. -/
structure WithdrawPre (s : RollupState)
    (mleVerified pisBound : Prop) (extCommitment : Word) : Prop where
  proof   : mleVerified                                   -- :1316
  anchored : s.finalizedStateRoots.get extCommitment = true  -- :1331
  bound   : pisBound                                      -- :1345

/-! ### Sum of leaf amounts -/

def totalAmount : List Withdrawal → U256
  | [] => 0
  | w :: ws => w.amount + totalAmount ws

@[simp] theorem totalAmount_nil : totalAmount [] = 0 := rfl
@[simp] theorem totalAmount_cons (w : Withdrawal) (ws : List Withdrawal) :
    totalAmount (w :: ws) = w.amount + totalAmount ws := rfl

/-! ## Theorems -/

/-- Decompose a successful leaf: the three guards fail and `checkedSub`
    succeeds, giving the unique post-state. -/
theorem withdrawLeaf_some {s s' : RollupState} {w : Withdrawal}
    (h : withdrawLeaf s w = some s') :
    ∃ te, checkedSub s.totalEscrowed w.amount = some te ∧
      s' = { s with
        nullifierUsed := s.nullifierUsed.set w.nullifier true
        totalEscrowed := te
        pendingWithdrawals :=
          s.pendingWithdrawals.set w.recipient
            (s.pendingWithdrawals.get w.recipient + w.amount) } := by
  unfold withdrawLeaf at h
  by_cases h1 : w.isEth = false
  · rw [if_pos h1] at h; simp at h
  rw [if_neg h1] at h
  by_cases h2 : s.nullifierUsed.get w.nullifier = true
  · rw [if_pos h2] at h; simp at h
  rw [if_neg h2] at h
  by_cases h3 : w.auxData ≠ 0 ∧ s.partialWithdrawalAuthorized.get (authDigest w) = false
  · rw [if_pos h3] at h; simp at h
  rw [if_neg h3] at h
  cases hsub : checkedSub s.totalEscrowed w.amount with
  | none => rw [hsub] at h; simp at h
  | some te =>
      rw [hsub] at h
      simp only [Option.map_some', Option.some.injEq] at h
      exact ⟨te, rfl, h.symm⟩

/-- One leaf reduces escrow by exactly its amount, and requires the
    amount to be available (no underflow). -/
theorem withdrawLeaf_escrow {s s' : RollupState} {w : Withdrawal}
    (h : withdrawLeaf s w = some s') :
    w.amount ≤ s.totalEscrowed ∧ s'.totalEscrowed + w.amount = s.totalEscrowed := by
  obtain ⟨te, hsub, hs'⟩ := withdrawLeaf_some h
  obtain ⟨hle, hte⟩ := checkedSub_eq_some hsub
  have key : s'.totalEscrowed = te := by rw [hs']
  refine ⟨hle, ?_⟩
  rw [key, hte]
  exact Nat.sub_add_cancel hle

/-- **Per-call solvency.** A successful `withdrawNative` reduces escrow
    by EXACTLY the sum of paid amounts, and that sum is ≤ the escrow
    available before — the contract cannot pay out more than it holds. -/
theorem withdrawLoop_solvency {s s' : RollupState} :
    ∀ {ws : List Withdrawal}, withdrawLoop s ws = some s' →
      totalAmount ws ≤ s.totalEscrowed ∧
      s'.totalEscrowed + totalAmount ws = s.totalEscrowed := by
  intro ws
  induction ws generalizing s with
  | nil =>
      intro h; simp only [withdrawLoop] at h
      rw [Option.some.injEq] at h; subst h
      simp
  | cons w ws ih =>
      intro h
      simp only [withdrawLoop, Option.bind] at h
      cases hleaf : withdrawLeaf s w with
      | none => rw [hleaf] at h; simp at h
      | some smid =>
          rw [hleaf] at h
          obtain ⟨_hle1, heq1⟩ := withdrawLeaf_escrow hleaf
          obtain ⟨hle2, heq2⟩ := ih h
          simp only [totalAmount_cons]
          refine ⟨?_, ?_⟩
          · -- w.amount + Σws ≤ s.totalEscrowed
            calc w.amount + totalAmount ws
                ≤ w.amount + smid.totalEscrowed := Nat.add_le_add_left hle2 _
              _ = smid.totalEscrowed + w.amount := Nat.add_comm _ _
              _ = s.totalEscrowed := heq1
          · -- s'.totalEscrowed + (w.amount + Σws) = s.totalEscrowed
            calc s'.totalEscrowed + (w.amount + totalAmount ws)
                = s'.totalEscrowed + (totalAmount ws + w.amount) := by
                    rw [Nat.add_comm w.amount]
              _ = (s'.totalEscrowed + totalAmount ws) + w.amount := (Nat.add_assoc _ _ _).symm
              _ = smid.totalEscrowed + w.amount := by rw [heq2]
              _ = s.totalEscrowed := heq1

/-- **No double-withdrawal.** A leaf whose nullifier is already consumed
    REVERTS; and a successful leaf consumes its nullifier. So each
    nullifier pays out at most once across all `withdrawNative` calls. -/
theorem withdrawLeaf_nullifier_once {s : RollupState} {w : Withdrawal}
    (hused : s.nullifierUsed.get w.nullifier = true) :
    withdrawLeaf s w = none := by
  unfold withdrawLeaf
  by_cases h1 : w.isEth = false
  · rw [if_pos h1]
  · rw [if_neg h1, if_pos hused]

/-- A successful leaf marks its nullifier used (so a later attempt with
    the same nullifier hits `withdrawLeaf_nullifier_once` ⇒ revert). -/
theorem withdrawLeaf_consumes {s s' : RollupState} {w : Withdrawal}
    (h : withdrawLeaf s w = some s') :
    s'.nullifierUsed.get w.nullifier = true := by
  obtain ⟨te, _, hs'⟩ := withdrawLeaf_some h
  subst hs'
  show (s.nullifierUsed.set w.nullifier true).get w.nullifier = true
  simp [Mapping.get_set_eq]

/-! ### finalize() — the only writer of finalizedStateRoots -/

/-- `finalize()` (:1102-1128): on a verified validity proof
    (`fullVerify`), records the state root as permanently finalized
    (`finalizedStateRoots[stateRoot] = true`, :1122).
    Modeled: success requires `valid`, and the ONLY state change to
    `finalizedStateRoots` is setting `stateRoot ↦ true`. -/
def finalize (s : RollupState) (stateRoot : Word) (valid : Bool) : Call RollupState :=
  if valid then
    some { s with finalizedStateRoots := s.finalizedStateRoots.set stateRoot true }
  else
    some s  -- returns false; no state change to finalizedStateRoots

/-- `finalize` adds a root to `finalizedStateRoots` ONLY when the
    validity proof verified. So a value passing `withdrawNative`'s
    `anchored` check (`finalizedStateRoots[ext]=true`) must have been
    finalized by a verified validity proof — never set arbitrarily.

    ASSUMPTION: `valid` here is the OUTPUT of `_verifyMle`'s gate. That
    output means "an MLE/WHIR validity proof verified" only under
    `Assumptions.MleVerificationEnabled` (`allowMleDisabled = false`,
    constructor-enforced with a nonzero VK at IntmaxRollup.sol:532); on
    a test deployment with the :1584 short-circuit live, `valid = true`
    carries no cryptographic meaning (see
    `Assumptions.mle_gate_real_when_enabled`). -/
theorem finalize_only_on_valid {s s' : RollupState} {root : Word} {valid : Bool}
    (h : finalize s root valid = some s')
    (hnew : s'.finalizedStateRoots.get root = true)
    (hold : s.finalizedStateRoots.get root = false) :
    valid = true := by
  cases valid with
  | true => rfl
  | false =>
      exfalso
      unfold finalize at h
      simp only [Bool.false_eq_true, if_false] at h
      rw [Option.some.injEq] at h
      subst h
      rw [hold] at hnew
      exact absurd hnew (by decide)

/-! ### withdrawNative — full call (preconditions + loop) -/

/-- The complete `withdrawNative` (:1307): the call-level preconditions
    (proof verified, anchored, pis-bound) gate the per-leaf payout loop.
    Reverts (none) if a precondition fails or any leaf reverts. -/
def withdrawNative (s : RollupState) (ws : List Withdrawal)
    (mleVerified pisBound : Prop) [Decidable mleVerified] [Decidable pisBound]
    (extCommitment : Word) : Call RollupState :=
  if mleVerified ∧ s.finalizedStateRoots.get extCommitment = true ∧ pisBound
  then withdrawLoop s ws
  else none

/-- **System-wide solvency ceiling (the headline contract invariant).**
    A successful `withdrawNative` pays out at most the escrow it held, and
    reduces escrow by EXACTLY the sum paid. Composed over any history
    (deposits only add, withdrawals subtract-with-this-bound), it gives
    `Σ all payouts ≤ Σ all deposits`: the rollup can NEVER pay out more
    ETH than was deposited — backed by the Solidity-0.8 underflow revert
    on `totalEscrowed -= amount`. -/
theorem withdrawNative_solvency {s s' : RollupState} {ws : List Withdrawal}
    {mleVerified pisBound : Prop} [Decidable mleVerified] [Decidable pisBound]
    {extCommitment : Word}
    (h : withdrawNative s ws mleVerified pisBound extCommitment = some s') :
    totalAmount ws ≤ s.totalEscrowed ∧
    s'.totalEscrowed + totalAmount ws = s.totalEscrowed := by
  unfold withdrawNative at h
  by_cases hpre : mleVerified ∧ s.finalizedStateRoots.get extCommitment = true ∧ pisBound
  · rw [if_pos hpre] at h; exact withdrawLoop_solvency h
  · rw [if_neg hpre] at h; simp at h

/-- **Withdrawal anchoring (circuit ↔ contract bridge).** A successful
    payout REQUIRES the WithdrawalCircuit proof to verify, the `ws` set to
    be bound to that proof (`pisBound`), AND the proof's ext-commitment to
    be a finalized validity state. Together with the circuit theorems
    (`SingleWithdrawalCircuit.withdrawal_sound`: each withdrawal is a real
    sent transfer; `WithdrawalCircuit` + finalize re-pin the ext-state —
    F-WITHDRAW-1 closed), every payout THROUGH THIS PATH corresponds to a
    circuit-proven withdrawal of a genuinely-spent balance.

    SCOPE: "no payout without a proof" holds for `withdrawNative` only.
    The burn path (`claimAuthorized`) has no rollup-side proof check —
    see `Assumptions.BurnAuthorizationsLegitimate`. And `anchored` means
    "validity-proof-finalized" only under
    `Assumptions.MleVerificationEnabled` (via `finalize_only_on_valid`). -/
theorem withdrawNative_requires_proof {s s' : RollupState} {ws : List Withdrawal}
    {mleVerified pisBound : Prop} [Decidable mleVerified] [Decidable pisBound]
    {extCommitment : Word}
    (h : withdrawNative s ws mleVerified pisBound extCommitment = some s') :
    mleVerified ∧ s.finalizedStateRoots.get extCommitment = true ∧ pisBound := by
  unfold withdrawNative at h
  by_cases hpre : mleVerified ∧ s.finalizedStateRoots.get extCommitment = true ∧ pisBound
  · exact hpre
  · rw [if_neg hpre] at h; simp at h

/-! ### claimAuthorizedWithdrawal() — burn (partial) withdrawal payout -/

/-- `claimAuthorizedWithdrawal(w)` (:642-665): a direct-transfer payout
    for a burn withdrawal (auxData ≠ 0), gated by a settlement-manager
    authorization of `authDigest(w)`. Same single-use nullifier (CEI) and
    `totalEscrowed -= amount` solvency ceiling as `withdrawNative`.

    NOTE this is the ONE payout path with NO proof check on the rollup
    side: the authorization flag is its whole gate. Its legitimacy rests
    on `Assumptions.BurnAuthorizationsLegitimate` (deployer + registered
    settlement managers trusted); the ETH push failure reverts the call
    (`require(ok)`, :662-663 — `Assumptions.EthSendFailureReverts`). -/
def claimAuthorized (s : RollupState) (w : Withdrawal) : Call RollupState :=
  if w.isEth = false then none                                   -- :643
  else if w.auxData = 0 then none                                -- :644 must be a burn
  else if s.nullifierUsed.get w.nullifier = true then none       -- :645 single-use
  else if s.partialWithdrawalAuthorized.get (authDigest w) = false then none  -- :657 authorized
  else (checkedSub s.totalEscrowed w.amount).map (fun te =>      -- :660 solvency ceiling
         { s with
           nullifierUsed := s.nullifierUsed.set w.nullifier true -- :659
           totalEscrowed := te })

theorem claimAuthorized_some {s s' : RollupState} {w : Withdrawal}
    (h : claimAuthorized s w = some s') :
    s.partialWithdrawalAuthorized.get (authDigest w) = true ∧
    ∃ te, checkedSub s.totalEscrowed w.amount = some te ∧
      s' = { s with nullifierUsed := s.nullifierUsed.set w.nullifier true,
                    totalEscrowed := te } := by
  unfold claimAuthorized at h
  by_cases h1 : w.isEth = false
  · rw [if_pos h1] at h; simp at h
  rw [if_neg h1] at h
  by_cases h2 : w.auxData = 0
  · rw [if_pos h2] at h; simp at h
  rw [if_neg h2] at h
  by_cases h3 : s.nullifierUsed.get w.nullifier = true
  · rw [if_pos h3] at h; simp at h
  rw [if_neg h3] at h
  by_cases h4 : s.partialWithdrawalAuthorized.get (authDigest w) = false
  · rw [if_pos h4] at h; simp at h
  rw [if_neg h4] at h
  have hauth : s.partialWithdrawalAuthorized.get (authDigest w) = true := by
    cases hb : s.partialWithdrawalAuthorized.get (authDigest w) with
    | false => exact absurd hb h4
    | true => rfl
  cases hsub : checkedSub s.totalEscrowed w.amount with
  | none => rw [hsub] at h; simp at h
  | some te =>
      rw [hsub] at h
      simp only [Option.map_some', Option.some.injEq] at h
      exact ⟨hauth, te, rfl, h.symm⟩

/-- **Burn-withdrawal solvency + single-use + authorization-required.** A
    burn payout reduces escrow by exactly `amount` (≤ escrow), consumes
    the nullifier, and only succeeds with a manager authorization for
    `authDigest(w)` (which binds ALL fields, so it can't be reused with a
    different recipient/amount). Same global-solvency guarantee as the
    main path.

    HONESTY CARVE-OUT: "authorization-required" is an ACCESS-CONTROL
    property, not a proof property. Unlike `withdrawNative_requires_proof`,
    NOTHING here ties the authorization to a verified circuit proof — a
    deployer-registered manager can mint it at will
    (`Assumptions.burn_drain_satisfiable` exhibits the resulting drain).
    That every authorized digest comes from the proof-gated
    `finalizePartialWithdrawal` flow is exactly
    `Assumptions.BurnAuthorizationsLegitimate` (see
    `Assumptions.claim_backed_by_trust` for the composition). -/
theorem claimAuthorized_safe {s s' : RollupState} {w : Withdrawal}
    (h : claimAuthorized s w = some s') :
    w.amount ≤ s.totalEscrowed
    ∧ s'.totalEscrowed + w.amount = s.totalEscrowed
    ∧ s'.nullifierUsed.get w.nullifier = true
    ∧ s.partialWithdrawalAuthorized.get (authDigest w) = true := by
  obtain ⟨hauth, te, hsub, hs'⟩ := claimAuthorized_some h
  obtain ⟨hle, hte⟩ := checkedSub_eq_some hsub
  refine ⟨hle, ?_, ?_, hauth⟩
  · have key : s'.totalEscrowed = te := by rw [hs']
    rw [key, hte]; exact Nat.sub_add_cancel hle
  · have key : s'.nullifierUsed = s.nullifierUsed.set w.nullifier true := by rw [hs']
    rw [key]; simp [Mapping.get_set_eq]

/-! ### withdraw() — pull-payment claim (CEI, no double-claim) -/

/-- `withdraw()` (:1212): the caller claims their accrued
    `pendingWithdrawals`. CEI — the balance is ZEROED before the external
    ETH send, so a reentrant call sees 0. Returns `(newState, amountSent)`. -/
def claimWithdraw (s : RollupState) (sender : Addr) : Call (RollupState × U256) :=
  if s.pendingWithdrawals.get sender = 0 then none          -- NothingToWithdraw
  else
    some ({ s with pendingWithdrawals := s.pendingWithdrawals.set sender 0 },
          s.pendingWithdrawals.get sender)

/-- A claim sends EXACTLY the caller's prior pending balance and zeroes
    it. The zero-before-send (CEI) plus `nonReentrant` means a re-entrant
    call observes a zero balance ⇒ reverts: no double-claim. -/
theorem claimWithdraw_zeroes_and_pays {s s' : RollupState} {sender : Addr} {amt : U256}
    (h : claimWithdraw s sender = some (s', amt)) :
    amt = s.pendingWithdrawals.get sender ∧ s'.pendingWithdrawals.get sender = 0 := by
  unfold claimWithdraw at h
  by_cases hz : s.pendingWithdrawals.get sender = 0
  · rw [if_pos hz] at h; simp at h
  · rw [if_neg hz] at h
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨hs', hamt⟩ := h
    subst hs'
    exact ⟨hamt.symm, by simp [Mapping.get_set_eq]⟩

/-- After a claim, an immediate second claim by the same caller REVERTS
    (the pending balance is now 0).

    ASSUMPTIONS: "immediate second claim" is a second ATOMIC call — the
    model cannot represent a reentrant frame inside the first call; that
    is excluded in Solidity by `nonReentrant` + the zero-before-send CEI
    order (`Assumptions.SingleCallAtomicity`). A failed ETH send reverts
    the whole call including the zeroing (`require(ok)`, :1216-1217 —
    `Assumptions.EthSendFailureReverts`), so no credit is ever lost. -/
theorem claimWithdraw_no_double {s s' : RollupState} {sender : Addr} {amt : U256}
    (h : claimWithdraw s sender = some (s', amt)) :
    claimWithdraw s' sender = none := by
  have := (claimWithdraw_zeroes_and_pays h).2
  unfold claimWithdraw
  rw [if_pos this]

/-!
  ## COMBINED-SYSTEM SAFETY (circuits + contract)

  Putting the contract theorems together with the circuit theorems
  (audit/zkp/Zkp/Circuits/...) yields the end-to-end fund-safety story.
  The named assumptions each claim rests on are in
  `Zkp.Contracts.Assumptions`; the burn path is carved out explicitly.

  1. **No payout without a valid proof — `withdrawNative` path**
     (`withdrawNative_requires_proof`): every withdrawal through
     `withdrawNative` is bound (pisHash) to a verified WithdrawalCircuit
     proof, anchored to a finalized validity state. By the circuit's
     `SingleWithdrawalCircuit.withdrawal_sound`, that withdrawal is a real
     transfer the user actually SENT (in their sent-tx tree, in a settled
     block), and by `SpendCircuit.deducts_solvent` it was covered by a
     real balance deduction.

     **CARVE-OUT — the burn path is NOT proof-backed on the rollup.**
     `claimAuthorizedWithdrawal` (:642-665) pays escrow against a bare
     `partialWithdrawalAuthorized` flag (:657) that any
     deployer-registered settlement manager can set unconditionally
     (:634); `registerSettlementManager` (:624) is deployer-only but
     additive forever (no removal, no timelock). "Every burn payout is
     backed by a proof-verified, challenge-surviving channel close"
     is therefore a TRUST statement about the deployer and its
     registered managers — `Assumptions.BurnAuthorizationsLegitimate` —
     not a theorem; `Assumptions.burn_drain_satisfiable` shows the model
     admits a full-escrow drain when it is violated. The honest manager
     flow that discharges it operationally is modeled in
     `ChannelSettlementManager.lean` (`submitPartialIntent_requires_proof`
     + `finalizePartial_authorizes`).

  2. **No double payout** (`withdrawLeaf_nullifier_once` +
     `withdrawLeaf_consumes`; `claimAuthorized_safe` for the burn path —
     both paths share ONE `withdrawalNullifierUsed` set, so a leaf paid
     by either can never be paid again by either): the per-transfer
     nullifier (proved collision-distinct and one-shot in
     `IndexedMerkle.key_absent`) is consumed atomically (CEI, under
     `Assumptions.SingleCallAtomicity`).

  3. **Global solvency** (`withdrawNative_solvency`, and
     `IntmaxRollupSolvency.global_solvency` over full traces including
     burn claims): Σ payouts ≤ Σ deposits, enforced by the
     underflow-revert ceiling, independent of the proofs AND of the
     burn-path trust assumption — a rogue manager can steal escrow, but
     cannot mint it.

  4. **Genuine anchoring** (`finalize_only_on_valid`, under
     `Assumptions.MleVerificationEnabled`): the finalized
     ext-commitments a withdrawal anchors to are written ONLY by verified
     validity proofs (`signatures_not_skippable` ⇒ no forged blocks),
     closing F-WITHDRAW-1 inside the formal model.

  Net: L1 ETH out ≤ L1 ETH in unconditionally; every unit out through
  `withdrawNative` is backed by a circuit-proven, single-use,
  validly-finalized withdrawal; every unit out through the burn path is
  single-use and solvency-capped, with its LEGITIMACY resting on the
  named deployer/manager trust assumption rather than on a proof.
-/

end IntmaxRollup
end Contracts
end Zkp
