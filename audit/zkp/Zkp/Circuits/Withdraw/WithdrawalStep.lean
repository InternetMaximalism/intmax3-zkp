import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes

/-
  Withdrawal aggregation step (hash-chain fold)
  =============================================

  Source: `src/circuits/withdraw/withdrawal_step.rs`
          `src/circuits/withdraw/withdrawal_chain_circuit.rs` (cyclic wrapper)
          `src/circuits/withdraw/withdrawal_processor.rs` (orchestration)

  ## Protocol role

  Folds N `single_withdrawal` proofs into one `withdrawal_hash_chain`,
  recursively chaining the previous step's proof. Each step verifies one
  single-withdrawal proof and one (conditional) previous chain proof,
  then pushes the new withdrawal hash onto the running chain.

  The flagged invariant **WDR-CRIT-001**: every non-initial step forces
  its `update_public_state.new` to equal the previous step's running
  `public_state`, and outputs `.new`. So the whole chain carries ONE
  fixed public_state; the L1 anchor on the final state cascades back
  through each step's `old → new` Merkle proof, forcing every
  `single_withdrawal.public_state` to be a real on-chain historical
  state. Without it, a prover could aggregate withdrawals proven against
  fabricated/divergent public states.

  ## Constraint inventory (withdrawal_step.rs:317-395)

  | line     | gate                                                       | meaning |
  |----------|------------------------------------------------------------|---------|
  | :328     | `is_initial = add_virtual_bool_target_safe`               | genesis vs continuation |
  | :338-343 | `conditionally_verify(not_initial, prev_chain_proof)`     | verify prev iff continuation |
  | :346-351 | `conditionally_connect_vd(not_initial, prev.vd, vd)`     | cyclic vd binding |
  | :353     | `add_proof_target_and_verify(single_withdrawal)`         | verify this withdrawal |
  | :358-360 | `update.old.connect(single_withdrawal.public_state)`     | step input state |
  | :369-374 | `update.new.conditional_assert_eq(prev.public_state, not_initial)` | **WDR-CRIT-001** |
  | :376-381 | `prev_hash = select(is_initial, 0, prev.withdrawal_hash_chain)` | genesis hash = 0 |
  | :383-385 | `chain = withdrawal.hash_with_prev_hash(prev_hash)`      | fold |
  | :387-393 | output `{chain, public_state = update.new, vd}`          | step output |
-/

namespace Zkp
namespace Circuits.WithdrawalStep

open CField Builder Bytes

variable {F : Type} [CField F]

/-- `withdrawal.hash_with_prev_hash(prev)` — fold one withdrawal's hash
    onto the running chain (Poseidon/keccak; determinism only). -/
opaque hashWithPrev {F : Type} [CField F] : Bytes32 F → Bytes32 F → Bytes32 F

structure StepIO (F : Type) where
  isInitial : F
  singleWithdrawalHash : Bytes32 F
  prevChainHash : Bytes32 F
  prevHashSelected : Bytes32 F
  newChainHash : Bytes32 F
  updateOld : HashOut F          -- update_public_state.old
  updateNew : HashOut F          -- update_public_state.new (= output public_state)
  singleWithdrawalState : HashOut F
  prevPublicState : HashOut F

structure Constraints (io : StepIO F) (zeroHash : Bytes32 F) : Prop where
  initBool : io.isInitial = 0 ∨ io.isInitial = 1
  -- :376-381  prev_hash = select(is_initial, 0, prev.chain)
  selPrev  : SelectSpec io.isInitial zeroHash io.prevChainHash io.prevHashSelected
  -- :383-385  chain = hash_with_prev_hash(withdrawal, prev_hash_selected)
  fold     : io.newChainHash = hashWithPrev io.singleWithdrawalHash io.prevHashSelected
  -- :358-360  update.old = single_withdrawal.public_state
  inState  : io.updateOld = io.singleWithdrawalState
  -- :369-374  WDR-CRIT-001: not_initial ⇒ update.new = prev.public_state
  critState : io.isInitial = 0 → io.updateNew = io.prevPublicState

/-- **Faithful fold.** The new chain hash is exactly this withdrawal
    folded onto the previous chain (or genesis `0` on the initial step):
    one withdrawal per step, none dropped or duplicated. -/
theorem fold_faithful {io : StepIO F} {zeroHash : Bytes32 F}
    (h : Constraints io zeroHash) :
    (io.isInitial = 1 → io.newChainHash = hashWithPrev io.singleWithdrawalHash zeroHash)
    ∧ (io.isInitial = 0 →
        io.newChainHash = hashWithPrev io.singleWithdrawalHash io.prevChainHash) := by
  constructor
  · intro hi
    rw [h.fold, h.selPrev.1 hi]
  · intro hi
    rw [h.fold, h.selPrev.2 hi]

/-- **WDR-CRIT-001 — single threaded public state.** On a continuation
    step, the step's input/output public states link the previous step's
    state to this single-withdrawal's state through one `old → new`
    transition: `update.old = single_withdrawal.public_state` and
    `update.new = prev.public_state`. Chained over all steps (with the
    final state L1-anchored), this forces every aggregated withdrawal to
    have been proven against a genuine on-chain historical state. -/
theorem state_threaded {io : StepIO F} {zeroHash : Bytes32 F}
    (h : Constraints io zeroHash) (hcont : io.isInitial = 0) :
    io.updateOld = io.singleWithdrawalState ∧ io.updateNew = io.prevPublicState :=
  ⟨h.inState, h.critState hcont⟩

/-!
  ## SECURITY OBSERVATIONS

  * **WDR-CRIT-001 is the anti-state-mixing guard.** `state_threaded`
    proves the mechanism: combined with `update_public_state`'s own
    soundness (each `old → new` is a real Merkle transition — see
    UpdatePublicState.updatePublicState_sound) and the final state being
    L1-anchored, the equality `update.new = prev.public_state` cascades
    a single public-state lineage backward through the chain. A prover
    cannot stitch together withdrawals proven against unrelated states.
    Removing the `conditional_assert_eq` (:369-374) would make
    `state_threaded`'s second conjunct unprovable — the precise gap the
    fix closes.

  * **Conditional prev-verify + cyclic vd** (`:338-351`) mirror the
    switch_board pattern: the prev chain proof is verified and its vd
    bound only on continuation steps (`not_initial`), with genesis
    seeding the chain from `0`. Same fixed-point trust anchor as
    BalanceCircuit.

  * **withdrawal_chain_circuit / withdrawal_processor** are the cyclic
    wrapper + orchestration around this step (no new leaf constraints);
    their soundness is the cyclic vd binding already modeled.
-/

end Circuits.WithdrawalStep
end Zkp
