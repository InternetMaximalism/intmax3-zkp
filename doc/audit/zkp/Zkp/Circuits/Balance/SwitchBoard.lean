import Zkp.Core.Field
import Zkp.Core.Builder

/-
  Balance switch board (IVC dispatch)  — CRITICAL (forged-route risk)
  ==================================================================

  Source: `src/circuits/balance/switch_board.rs`

  ## Protocol role

  The recursive balance proof is one of FOUR cases, chosen by a 4-wide
  one-hot selector:

    0. initial value (genesis PIs)
    1. receive_transfer proof
    2. receive_deposit proof
    3. send_tx proof

  The switch board (a) enforces the selector is one-hot, (b)
  *conditionally* verifies each branch's sub-proof (only the selected
  branch is actually verified — others may be dummy), and (c) outputs
  the selected branch's public inputs as its own.

  The soundness that matters: **the output PIs must come from a branch
  whose sub-proof was actually verified.** Otherwise a prover could
  route through an unverified (forged/dummy) branch and emit arbitrary
  balance PIs — minting balance from nothing.

  ## Constraint inventory (switch_board.rs:185-276)

  | line     | gate                                                  | meaning |
  |----------|-------------------------------------------------------|---------|
  | :190-195 | `one_hot[i] = add_virtual_bool_target_safe()`         | each selector ∈ {0,1} |
  | :198-200 | `sum = Σ one_hot[i]; assert_one(sum)`                 | exactly one set* |
  | :243     | `conditionally_verify(receive_transfer, one_hot[1])`  | verify iff selected |
  | :251     | `conditionally_verify(receive_deposit, one_hot[2])`   | verify iff selected |
  | :259     | `conditionally_verify(send_tx, one_hot[3])`           | verify iff selected |
  | :271     | `selected_vec = select_vec(candidates, one_hot)`      | pick active PIs |
  | :274-275 | `connect(selected_vec, new_pis)`                      | output = selected |

  *SECURITY (characteristic dependency): `assert_one(Σ_{i<4} b_i)` over
  booleans yields "exactly one is 1" ONLY because char(F) > 4 in
  Goldilocks (else two 1's could sum to 1). We surface this as the
  `OneHot` semantic predicate and note the dependency rather than
  re-deriving it from `Σ = 1` (which the deliberately char-agnostic
  field axioms cannot prove).

  CORRECTION (meta-audit): this is NOT the only place the Goldilocks
  characteristic is load-bearing in the balance stack. Rust runs an
  independent `split_le` per `verify`/`get_root` call
  (utils/trees/merkle_tree.rs:227); the read/write Merkle models —
  `SpendCircuit.DeductStep`, `SpendCircuit.SentTxRecord`,
  `UpdatePrivateState.AssetUpdate` (and `UpdateUser.treeUpdate` on the
  validity side) — carry the two decompositions as SEPARATE
  existential bit lists, and every "single leaf changed"
  identification of them is proved in the consumers from the named
  hypothesis `Merkle.PowTwoInj F 32` (uniqueness of 32-bit
  decompositions, i.e. char(F) > 2^32; Core/Merkle.lean,
  Goldilocks-true up to 63 bits). The IndexedMerkle splice shadows
  absorb the same identification into their documented root↔map
  boundary.

  FAITHFULNESS NOTE (genesis branch): `Constraints.condVerify`
  quantifies over ALL four branches, but Rust conditionally verifies
  only branches 1-3 (:243/:251/:259); branch 0 — the IVC base case —
  has NO sub-proof and no verification. The model is faithful only
  under the instantiation `Verified 0 := True`, made explicit below as
  `IntendedVerified` / `routing_sound_genesis`.
-/

namespace Zkp
namespace Circuits.SwitchBoard

open CField Builder

variable {F : Type} [CField F]

/-- Semantic one-hot over 4 selectors: each boolean, exactly one set.
    (What `assert_one(Σ b_i)` enforces under char(Goldilocks) > 4.)
    The active index is existential — a Prop can't expose it as data. -/
def OneHot (b : Fin 4 → F) : Prop :=
  (∀ i, b i = 0 ∨ b i = 1) ∧
  ∃ i, b i = 1 ∧ ∀ j, j ≠ i → b j = 0

/-- Constraints emitted by the switch board, over abstract PI vectors
    `α`. `candidates i` is branch `i`'s public-input vector;
    `Verified i` holds when branch `i`'s sub-proof was recursively
    verified; `output` is the registered PI vector. -/
structure Constraints {α : Type} (b : Fin 4 → F)
    (candidates : Fin 4 → α) (Verified : Fin 4 → Prop) (output : α) : Prop where
  oneHot : OneHot b
  -- :243/:251/:259 — a branch is verified when its selector is set.
  -- Rust verifies ONLY branches 1-3; the quantification over branch 0
  -- is faithful solely under `Verified 0 := True` (`IntendedVerified`).
  condVerify : ∀ i, b i = 1 → Verified i
  -- :271-275 — select_vec + connect: output equals the active candidate.
  outSel : ∀ i, b i = 1 → output = candidates i

/-- **Routing soundness.** The output public inputs equal the PIs of a
    UNIQUE branch, and that branch's sub-proof was actually verified.
    A prover cannot emit PIs from a branch whose proof was not checked,
    nor blend two branches. This is the core anti-forgery property of
    the balance IVC dispatch. -/
theorem routing_sound {α : Type} {b : Fin 4 → F}
    {candidates : Fin 4 → α} {Verified : Fin 4 → Prop} {output : α}
    (h : Constraints b candidates Verified output) :
    ∃ i, output = candidates i ∧ Verified i ∧ (∀ j, b j = 1 → j = i) := by
  obtain ⟨_hbool, active, hone, hother⟩ := h.oneHot
  refine ⟨active, h.outSel active hone, h.condVerify active hone, ?_⟩
  intro j hj
  by_cases heq : j = active
  · exact heq
  · -- if j ≠ active then b j = 0, contradicting b j = 1
    have hz : b j = 0 := hother j heq
    rw [hz] at hj
    exact absurd hj.symm one_ne_zero

/-- The INTENDED instantiation of `Verified`: branch 0 (genesis / IVC
    base) is `True` — Rust performs no verification there
    (switch_board.rs conditionally verifies only :243/:251/:259) —
    and branches 1-3 are the respective sub-proof verifications.
    Instantiating `Constraints` with anything stronger at index 0
    would over-constrain the prover and hide the real soundness
    shape of the genesis case. -/
def IntendedVerified (V₁ V₂ V₃ : Prop) (i : Fin 4) : Prop :=
  match i.val with
  | 0 => True
  | 1 => V₁
  | 2 => V₂
  | _ => V₃

/-- **Genesis routing gives ONLY the candidate PIs.** Under the
    intended instantiation, routing through branch 0 yields no
    verified sub-proof — `routing_sound`'s `Verified` conjunct is
    trivially `True` there. Genesis-case soundness therefore rests
    entirely on `candidates 0` being pinned to the genuine genesis
    public inputs (an obligation OUTSIDE this file, at the switch
    board's caller). Stated explicitly so the `Verified 0 := True`
    faithfulness choice cannot silently masquerade as a guarantee. -/
theorem routing_sound_genesis {α : Type} {b : Fin 4 → F}
    {candidates : Fin 4 → α} {V₁ V₂ V₃ : Prop} {output : α}
    (h : Constraints b candidates (IntendedVerified V₁ V₂ V₃) output)
    (h0 : b 0 = 1) : output = candidates 0 :=
  h.outSel 0 h0

/-!
  ## SECURITY OBSERVATIONS

  * **One-hot is the linchpin.** If `assert_one(Σ b_i)` were missing or
    the selectors were not range-checked to `{0,1}`, a prover could set
    multiple/zero selectors. With our model, dropping `OneHot.bool` or
    the exactly-one structure makes `routing_sound`'s uniqueness clause
    unprovable — pinpointing the gate that must not be removed.

  * **Conditional verify ↔ select share `one_hot`.** Both the
    conditional verification (`:243-259`) and `select_vec` (`:271`) are
    driven by the SAME `one_hot`. That shared driver is why `outSel`
    and `condVerify` agree on the active index — the output cannot come
    from a different branch than the one verified. Were they driven by
    independent selectors, routing soundness would break.

  * **Genesis branch carries no verification.** Rust never verifies a
    sub-proof for branch 0; `IntendedVerified` fixes `Verified 0 :=
    True` and `routing_sound_genesis` records that routing through it
    proves nothing beyond `output = candidates 0`. Any soundness story
    for the base case must come from the caller pinning `candidates 0`
    to the genuine genesis PIs — not from this dispatch.

  * **C-M3 (cyclic VD wiring).** audit622 notes balance sub-circuits use
    `verify_proof` / conditional verify with VD threaded from PIs rather
    than `add_proof_target_and_verify_cyclic`. The `Verified i`
    predicate here abstracts "branch i's proof checks against its vd";
    soundness of the cyclic VD binding (that `vd` is the genuine balance
    circuit's) is an orthogonal obligation tracked for the cyclic core.
-/

end Circuits.SwitchBoard
end Zkp
