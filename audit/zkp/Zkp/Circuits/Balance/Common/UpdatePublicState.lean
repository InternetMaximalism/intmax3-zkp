import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle

/-
  Public-state transition validity
  ================================

  Source: `src/circuits/balance/common/update_public_state.rs`

  ## Protocol role

  A balance proof advances the user's view of the *public state*
  (the block-level rollup state: account root, deposit root, block
  number, …). `UpdatePublicState` proves that moving from `old` to
  `new` is legitimate w.r.t. the append-only public-state history:

    * either `new == old` (a no-op step — nothing changed), OR
    * `old` is included, at position `old.block_number`, under
      `new.prev_public_state_root` — i.e. the new state's history
      root commits the old state at the old block height.

  This is the inductive step that keeps each user's public-state
  view on the canonical chain without re-verifying the whole chain.

  ## Constraint inventory (update_public_state.rs:86-113)

  | line   | gate                               | meaning                              |
  |--------|------------------------------------|--------------------------------------|
  | :97    | `states_equal = new.is_equal(old)` | boolean: are the full records equal? |
  | :98    | `should_verify = not(states_equal)`| verify Merkle path iff they differ   |
  | :100-6 | `merkle_proof.conditional_verify`  | if should_verify: path(old)==new.prev |

  Native `verify()` (:69-83) mirrors this: skip when equal, else
  recompute the root and compare to `new.prev_public_state_root`.
-/

namespace Zkp
namespace Circuits.UpdatePublicState

open CField Builder Bytes Merkle

variable {F : Type} [CField F]

def PUBLIC_STATE_TREE_HEIGHT : Nat := 32

/-- The rollup public state, kept abstract: `is_equal` (:97) compares
    *all* fields, so faithful modeling demands an opaque record whose
    Lean equality is full structural equality — not a partial view. -/
opaque PublicState : Type → Type

/-- `new.prev_public_state_root` — the history root the transition
    must commit `old` under. -/
opaque psPrevRoot {F : Type} [CField F] : PublicState F → HashOut F

/-- `old.block_number.value` — Merkle index of `old` in the history. -/
opaque psBlockNumber {F : Type} [CField F] : PublicState F → F

/-- The leaf digest of a public state, as hashed into the history
    tree (Poseidon; determinism only). -/
opaque psLeaf {F : Type} [CField F] : PublicState F → HashOut F

/-- Constraints emitted by `UpdatePublicStateTarget::new`. `e` is the
    `is_equal` advice wire; `sib` the conditional Merkle siblings. -/
def Constraints (new old : PublicState F) (e : F) (sib : List (HashOut F)) : Prop :=
  IsEqualSpecG new old e
  ∧ (notGate e = 1 →
       MerkleVerify PUBLIC_STATE_TREE_HEIGHT (psLeaf old) (psBlockNumber old)
         sib (psPrevRoot new))

/-- **Soundness.** Every accepted transition is either a genuine
    no-op (`new = old`) or carries a Merkle inclusion of `old` at
    `block_number(old)` under `new.prev_public_state_root`. A prover
    cannot both change the state AND skip the inclusion check: forcing
    `should_verify = 0` requires `e = 1`, which (by `is_equal`
    soundness) forces `new = old`. -/
theorem updatePublicState_sound (new old : PublicState F) (e : F)
    (sib : List (HashOut F)) (h : Constraints new old e sib) :
    new = old ∨
      MerkleVerify PUBLIC_STATE_TREE_HEIGHT (psLeaf old) (psBlockNumber old)
        sib (psPrevRoot new) := by
  obtain ⟨⟨hbool, hiff⟩, hcond⟩ := h
  rcases hbool with h0 | h1
  · -- e = 0 ⇒ states differ ⇒ Merkle path verified
    right
    apply hcond
    rw [notGate_eq_one_iff (Or.inl h0)]
    exact h0
  · -- e = 1 ⇒ new = old
    left
    exact (hiff.mp h1)

/-!
  ## SECURITY OBSERVATION — the no-op branch is genuinely a no-op

  The `conditional_verify` skip is safe ONLY because `is_equal`
  (`:97`) compares the FULL record: `e = 1` ⟹ `new = old` on every
  field (`IsEqualSpecG`'s `e = 1 ↔ new = old`). If `is_equal` omitted
  any field, a prover could set `e = 1` with that field changed,
  skipping the Merkle check while mutating state — a transition
  forgery. So when modeling `PublicStateTarget::is_equal` (its own
  file), VERIFY it AND-s equalities of *all* public-state fields.
  Tracked as check item F-PUBST-1.
-/

end Circuits.UpdatePublicState
end Zkp
