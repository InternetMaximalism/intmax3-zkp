import Zkp.Contracts.IntmaxRollupWithdraw

/-
  Trust & modeling assumptions of the contract formalization
  ==========================================================

  Source: `contracts/src/IntmaxRollup.sol`, `contracts/src/ChannelSettlementManager.sol`

  Every theorem in `Zkp/Contracts/` is proved WITHOUT `sorry` or `axiom`,
  but several of them are meaningful for the deployed system only under
  explicit trust / modeling assumptions that the Lean model cannot (or
  deliberately does not) discharge. This module NAMES each assumption as
  an ordinary `def`/`opaque` Prop with a full docstring, so that

    * no theorem docstring has to restate the fine print, and
    * an auditor can see at a glance exactly what is trusted vs proved.

  Summary table:

  | name                            | kind      | what breaks if violated              |
  |---------------------------------|-----------|--------------------------------------|
  | `BurnAuthorizationsLegitimate`  | TRUST     | full escrow drain, no proof needed   |
  | `MleVerificationEnabled`        | DEPLOY    | `finalize` accepts unverified roots  |
  | `SingleCallAtomicity`           | MODELING  | reentrancy invisible to the model    |
  | `EthSendFailureReverts`         | MODELING  | send-failure states unrepresentable  |
-/

namespace Zkp
namespace Contracts
namespace Assumptions

open Zkp.Contracts.Evm
open Zkp.Contracts.IntmaxRollup

/-! ## (i) Burn-path trust: deployer + registered settlement managers -/

/-- **TRUST ASSUMPTION (burn / partial-withdrawal path).**

    `claimAuthorizedWithdrawal` (IntmaxRollup.sol:642-665) pays escrow ETH
    directly to `w.recipient` and its ONLY rollup-side gate is
    `partialWithdrawalAuthorized[authDigest]` (:657). That flag is set by
    `authorizePartialWithdrawal` (:634), callable by ANY address the
    deployer registered via `registerSettlementManager` (:624) — which is
    deployer-only but ADDITIVE FOREVER: no removal, no timelock, no proof
    requirement on the rollup side.

    So the statement "every L1 payout is backed by a verified circuit
    proof" is TRUE for the `withdrawNative` path
    (`withdrawNative_requires_proof`) but FALSE for the burn path: the
    rollup itself never checks a proof there. The proof obligation (a
    finalized, challenge-surviving, N-of-N-signed channel close intent —
    `ChannelSettlementManager.finalizePartialWithdrawal`, CSM.sol:971-993)
    lives entirely in the settlement-manager contract the deployer chose
    to register.

    **Consequence if violated:** a malicious (or key-compromised) deployer
    registers an attacker contract as a settlement manager; that contract
    calls `authorizePartialWithdrawal(d)` for an arbitrary
    `authDigest d = authDigest(w)` of the attacker's choosing (any
    recipient, any amount); `claimAuthorizedWithdrawal(w)` then drains up
    to the WHOLE `totalEscrowed` with NO proof — see
    `burn_drain_satisfiable` below, which exhibits the drain inside the
    model. Solvency (`global_solvency`) still bounds the drain by Σ
    deposits; nothing bounds WHOSE deposits are taken.

    Formally the assumption is parameterized by a predicate `legit`
    ("this digest was minted by an honest, proof-gated settlement-manager
    flow"): it says every digest the rollup has marked authorized is
    legitimate. The honest flow that makes `legit` true is modeled in
    `ChannelSettlementManager.lean`
    (`submitPartialIntent_requires_proof` + `finalizePartial_authorizes`). -/
def BurnAuthorizationsLegitimate (legit : Word → Prop) (s : RollupState) : Prop :=
  ∀ d, s.partialWithdrawalAuthorized.get d = true → legit d

/-- Under `BurnAuthorizationsLegitimate`, every successful burn claim was
    for a legitimately-minted digest — this is exactly how the named
    trust assumption plugs into `claimAuthorized_safe`. -/
theorem claim_backed_by_trust {legit : Word → Prop} {s s' : RollupState} {w : Withdrawal}
    (hA : BurnAuthorizationsLegitimate legit s)
    (h : claimAuthorized s w = some s') : legit (authDigest w) :=
  hA _ (claimAuthorized_safe h).2.2.2

/-- The state reached after a rogue manager authorizes EVERY digest:
    escrow holds `w.amount`, nothing else is set. INTENTIONALLY SIMPLE:
    it only exists to witness `burn_drain_satisfiable`. -/
def rogueAuthState (w : Withdrawal) : RollupState :=
  { totalEscrowed := w.amount
    nullifierUsed := fun _ => false
    pendingWithdrawals := fun _ => 0
    finalizedStateRoots := fun _ => false
    partialWithdrawalAuthorized := fun _ => true }

/-- **The drain is real (satisfiability of the trust violation).** For any
    ETH burn leaf `w`, once `partialWithdrawalAuthorized[authDigest w]`
    is set (which a deployer-registered manager can do unconditionally,
    :634-:637), `claimAuthorizedWithdrawal` SUCCEEDS with no proof, no
    finalized root, no anything — paying `w.amount` (here: the whole
    escrow). This is why `BurnAuthorizationsLegitimate` must be assumed,
    not proved. -/
theorem burn_drain_satisfiable (w : Withdrawal)
    (hEth : w.isEth = true) (hburn : w.auxData ≠ 0) :
    ∃ s', claimAuthorized (rogueAuthState w) w = some s' := by
  unfold claimAuthorized
  rw [if_neg (by simp [hEth]),
      if_neg hburn,
      if_neg (by simp [rogueAuthState, Mapping.get]),
      if_neg (by simp [rogueAuthState, Mapping.get]),
      show (rogueAuthState w).totalEscrowed = w.amount from rfl,
      checkedSub_some (Nat.le_refl _)]
  exact ⟨_, rfl⟩

/-! ## (ii) Deployment assumption: MLE verification enabled -/

/-- The `_verifyMle` short-circuit seam (IntmaxRollup.sol:1584):
    `if (allowMleDisabled && mleVk.degreeBits == 0) return true;` —
    verification is skipped ONLY when both the constructor-latched
    test flag and a zero VK coincide; otherwise the real MLE/WHIR
    verification result is returned. -/
def verifyMleGate (allowMleDisabled : Bool) (degreeBits : Nat) (realVerify : Bool) : Bool :=
  if allowMleDisabled = true ∧ degreeBits = 0 then true else realVerify

/-- **DEPLOYMENT ASSUMPTION (production configuration).**

    `allowMleDisabled = false` on any value-bearing deployment. The flag
    is immutable (set once in the constructor) and the constructor
    REJECTS a zero validity VK unless the flag is explicitly true
    (IntmaxRollup.sol:532, `constructorAcceptsVk` below), so this is an
    auditable one-bit deploy-time check — but the Lean model cannot know
    which bit was deployed.

    **Consequence if violated:** with `allowMleDisabled = true` and a zero
    VK, `_verifyMle` returns true unconditionally (:1584), so `finalize`
    marks ANY state root finalized; `finalize_only_on_valid` still holds
    as stated (its `valid` parameter is the GATE OUTPUT), but the gate
    output no longer means "a validity proof verified", and with it every
    downstream anchor (`withdrawNative`'s `finalizedStateRoots` check)
    loses its meaning. The withdrawal VK has no such escape hatch at all
    (`initializeWithdrawalVk` reverts on `degreeBits == 0`, :606). -/
def MleVerificationEnabled (allowMleDisabled : Bool) : Prop :=
  allowMleDisabled = false

/-- The constructor guard (IntmaxRollup.sol:532): a zero-degree validity
    VK is accepted only with the explicit test-only opt-in. -/
def constructorAcceptsVk (allowMleDisabled : Bool) (degreeBits : Nat) : Prop :=
  allowMleDisabled = true ∨ degreeBits ≠ 0

/-- Under `MleVerificationEnabled`, the gate is HONEST: it returns exactly
    the real verification result, for every `degreeBits` — the
    defense-in-depth conjunct at :1584 makes the bypass dead even if a
    zero VK somehow reached storage. -/
theorem mle_gate_real_when_enabled {allow : Bool} (degreeBits : Nat) (realVerify : Bool)
    (h : MleVerificationEnabled allow) :
    verifyMleGate allow degreeBits realVerify = realVerify := by
  unfold MleVerificationEnabled at h
  subst h
  simp [verifyMleGate]

/-- In production (`allowMleDisabled = false`) the constructor guard
    forces a nonzero validity VK — the bypass precondition is doubly
    unreachable. -/
theorem production_vk_nonzero {allow : Bool} {d : Nat}
    (hc : constructorAcceptsVk allow d) (h : MleVerificationEnabled allow) : d ≠ 0 := by
  cases hc with
  | inl h' => rw [h] at h'; exact absurd h' (by decide)
  | inr h' => exact h'

/-! ## (iii) Modeling assumption: single-call atomicity -/

/-- **MODELING ASSUMPTION (no interleaving / reentrancy).**

    Every transition in this model (`deposit`, `withdrawNative`,
    `claimAuthorized`, `claimWithdraw`, `reclaimStake`,
    `claimWithdrawalCredit`, `pullChannelFunds`, …) is a TOTAL atomic
    step: it runs to completion (or reverts as `none`) with no other call
    interleaved. The model therefore CANNOT represent reentrancy — a
    reentrant execution is not a trace of `run`.

    In Solidity this atomicity is not free; it rests on:
      * `nonReentrant` guards on every external function that moves ETH:
        `claimAuthorizedWithdrawal` :642, `withdraw` :1212,
        `reclaimStake` :1269, `withdrawNative` :1311, `finalize` :1107,
        `fraudProof` :1161 (IntmaxRollup.sol); `pullChannelFunds` :1152
        and `claimWithdrawalCredit` :1167 (ChannelSettlementManager.sol,
        guard defined at :543-548);
      * checks-effects-interactions ordering: state writes (nullifier
        set :1371/:659, escrow decrement :1373/:660, credit zeroing
        :1215/:1171-1172) strictly precede the external `.call`
        (:1216/:662/:1174), so even a hypothetical reentrant frame
        observes the already-consumed state (this ordering IS captured by
        the model: e.g. `claimWithdraw_no_double`, `claim_no_double`).

    **Consequence if violated** (a `nonReentrant` guard removed AND CEI
    broken): the composed-trace theorems (`run_conservation`,
    `global_solvency`) would quantify over too few behaviors and a
    double-spend interleaving could exist outside the model. -/
opaque SingleCallAtomicity : Prop

/-! ## (iv) Modeling assumption: ETH send failure = whole-call revert -/

/-- **MODELING ASSUMPTION (send-failure handling).**

    Every native ETH push in the modeled functions is a low-level `.call`
    whose failure REVERTS the whole transaction:
      * `claimAuthorizedWithdrawal`: `require(ok, "ETH transfer failed")`
        (IntmaxRollup.sol:662-663);
      * `withdraw`: `require(ok, "Withdraw failed")` (:1216-1217);
      * `claimWithdrawalCredit`: `if (!ok) revert TransferFailed()`
        (ChannelSettlementManager.sol:1174-1175).
    The model folds this into the single `Call` result: a failed send is
    the SAME `none` as any guard revert, so no state where "effects
    applied but ETH not delivered" is representable — matching the EVM's
    all-or-nothing frame semantics.

    Note the design already minimizes reliance on pushes: `finalize` /
    `fraudProof` / `withdrawNative` / `reclaimStake` credit
    `pendingWithdrawals` (pull-payment) precisely so a reverting
    recipient cannot block protocol progress; the only pushes are the
    three claim endpoints above, where the caller/recipient hurts only
    itself by reverting. -/
opaque EthSendFailureReverts : Prop

end Assumptions
end Contracts
end Zkp
