import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes

/-
  Send-tx balance transition (IVC step)
  =====================================

  Source: `src/circuits/balance/send_tx_circuit.rs`

  ## Protocol role

  One recursive step of the SENDER's balance proof. It consumes the
  previous balance proof, an `update_public_state`, and a
  `tx_settlement` (which embeds a verified spend proof), and emits the
  NEW balance public inputs. It is where a validated spend actually
  advances the user's `block_r`, `private_commitment`, and
  `settled_tx_chain`.

  ## Constraint inventory (send_tx_circuit.rs:208-310)

  | line     | gate                                                    | meaning |
  |----------|---------------------------------------------------------|---------|
  | :225     | `verify_proof(prev_balance_proof, balance_vd)`          | recurse on prev balance (IVC) |
  | :236     | `prev.public_state.connect(update.old)`                 | chain old state |
  | :239-240 | `tx_settlement.public_state.connect(update.new)`        | chain new state |
  | :243     | `prev.channel_id.connect(tx_settlement.channel_id)`     | same user |
  | :247-248 | `prev.private_commitment.connect(spend.prev_private_commitment)` | spend builds on prev priv state |
  | :251-252 | `prev.block_r.enforce_ge(send_block_before_tx)`         | block_r ≥ send-before |
  | :255-257 | `tx_block_number.enforce_gt(prev.block_r)`              | tx_block > block_r |
  | :260-262 | `new_block_r = select(is_valid, tx_block, prev.block_r)`| advance iff valid |
  | :264-270 | `new_priv = select(is_valid, spend.new_priv, prev.priv)`| advance iff valid |
  | :274-276 | `transfer_witness.transfer_tree_root.connect(tx.transfer_tree_root)` | bind transfer to settled tx |
  | :277     | `assert_zero(transfer_witness.transfer_index)`          | inter-channel transfer at leaf 0 |
  | :293-298 | `do_push = and(is_valid, aux≠0)`; chain fold + select   | settled_tx_chain update |

  ## Resolves F-SPEND-1 (spend `is_valid` IS consumed)

  The earlier worry that `is_valid` is computed-but-unasserted in
  `spend_circuit` is answered HERE: `is_valid` gates `select` on
  `block_r`, `private_commitment`, AND the `settled_tx_chain` push. So
  an invalid spend (`tx_nonce ≠ prev_nonce` ⇒ `is_valid = 0`) is a
  NO-OP on the user's private state — it cannot corrupt balances. We
  prove exactly this below (`invalid_spend_is_noop`).
-/

namespace Zkp
namespace Circuits.SendTxCircuit

open CField Builder Bytes

variable {F : Type} [CField F]

/-- The mutable balance-state fields advanced (or not) by this step. -/
structure StepIO (F : Type) where
  isValid : F        -- spend_pis.is_valid (boolean)
  auxNonzero : F     -- not(aux_data == 0) (boolean)
  prevBlockR : F     -- block numbers (as field values)
  txBlock : F
  prevPriv : HashOut F        -- private commitments
  spendNewPriv : HashOut F
  prevChain : Bytes32 F       -- settled_tx_chain before / after push
  pushedChain : Bytes32 F
  newBlockR : F
  newPriv : HashOut F
  newChain : Bytes32 F

/-- Constraints emitted by `SendTxTarget::new` for the state-advance. -/
structure Constraints (io : StepIO F) : Prop where
  validBool : io.isValid = 0 ∨ io.isValid = 1
  auxBool   : io.auxNonzero = 0 ∨ io.auxNonzero = 1
  selR   : SelectSpec io.isValid io.txBlock io.prevBlockR io.newBlockR
  selP   : SelectSpec io.isValid io.spendNewPriv io.prevPriv io.newPriv
  -- do_push = and(is_valid, aux≠0); chain = select(do_push, pushed, prev)
  selC   : SelectSpec (andGate io.isValid io.auxNonzero) io.pushedChain io.prevChain io.newChain

/-- **F-SPEND-1 resolved — invalid spend is a no-op.** If `is_valid =
    0`, the new `block_r`, private commitment, and settled-tx chain ALL
    equal their previous values: an invalid (wrong-nonce) spend cannot
    advance or corrupt the sender's private state. -/
theorem invalid_spend_is_noop {io : StepIO F} (h : Constraints io)
    (hinv : io.isValid = 0) :
    io.newBlockR = io.prevBlockR ∧ io.newPriv = io.prevPriv
      ∧ io.newChain = io.prevChain := by
  refine ⟨h.selR.2 hinv, h.selP.2 hinv, ?_⟩
  -- do_push = and(0, aux) = 0 ⇒ chain unchanged
  have hpush : andGate io.isValid io.auxNonzero = 0 := by
    rw [hinv]; exact andGate_zero_left io.auxNonzero
  exact h.selC.2 hpush

/-- **Valid spend advances the state.** If `is_valid = 1`, the new
    `block_r` is the tx's block and the new private commitment is the
    spend's output; the chain is pushed iff `aux_data ≠ 0`. -/
theorem valid_spend_advances {io : StepIO F} (h : Constraints io)
    (hval : io.isValid = 1) :
    io.newBlockR = io.txBlock ∧ io.newPriv = io.spendNewPriv
      ∧ (io.auxNonzero = 1 → io.newChain = io.pushedChain)
      ∧ (io.auxNonzero = 0 → io.newChain = io.prevChain) := by
  refine ⟨h.selR.1 hval, h.selP.1 hval, ?_, ?_⟩
  · intro haux
    apply h.selC.1
    rw [(andGate_eq_one_iff h.validBool h.auxBool).mpr ⟨hval, haux⟩]
  · intro haux0
    apply h.selC.2
    rw [hval, haux0]; exact andGate_zero_right (1 : F)

/-!
  ## SECURITY OBSERVATIONS

  * **F-AUX-1 — confirmed off-circuit residual (matches audit622 C-M1).**
    `send_tx_circuit.rs:282-289` SECURITY comment is explicit:
    `aux_data` is Merkle-bound inside the transfer leaf the circuit
    verified against `tx.transfer_tree_root`, so the chain PI faithfully
    folds the leaf the settled tx carries — BUT
    `aux_data == tx_leaf_hash(inter_channel_tx)` is enforced OFF-CIRCUIT
    at co-sign time (threat model F3-A, layered with §E-2). This is a
    deliberate architectural boundary, not an in-circuit soundness bug.
    Downgrade F-AUX-1 to RESIDUAL (documented). The fold itself is
    faithful; the semantic equality is a trust assumption on co-signers.

  * **F-BLKR-1 — partially addressed here.** `block_r` ordering is
    constrained: `send_block_before_tx ≤ prev.block_r < tx_block_number`
    (`:251-257`), and `new_block_r ∈ {tx_block, prev.block_r}`. What is
    NOT visibly pinned in THIS file is `tx_block_number ≤
    update_public_state.new.block_number` (the balance_pis doc
    invariant `block_r ≤ public_state.block_number`). Check whether
    `tx_block_number` (= account_state.send_leaf.cur) is bound ≤ the new
    public state's block height inside `tx_settlement` / the account
    membership. Carry F-BLKR-1 forward.

  * **C-M3 (IVC wiring asymmetry).** `:225` uses `verify_proof` with
    `balance_vd` taken from the prev proof's own PIs (cyclic-by-PI),
    rather than `add_proof_target_and_verify_cyclic`. audit622 rates
    practical forgery unlikely with a fixed `balance_cd`; flagged for
    the switch_board / cyclic modeling pass.
-/

end Circuits.SendTxCircuit
end Zkp
