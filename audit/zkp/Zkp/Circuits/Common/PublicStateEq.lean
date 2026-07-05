import Zkp.Core.Field
import Zkp.Core.Builder

/-
  PublicStateTarget::is_equal — full-record equality (discharges F-PUBST-1)
  =========================================================================

  Source: `src/common/public_state.rs:307-328` (`PublicStateTarget::is_equal`).

  ## Protocol role

  `UpdatePublicStateCircuit` (`update_public_state.rs:97`) skips the
  Merkle-transition check when `is_equal(new_state, old_state) = 1`
  (the "no-op branch"). Finding **F-PUBST-1** (tasks/todo.md) recorded
  the load-bearing assumption: this skip is sound *only if* `is_equal`
  compares EVERY field of the public state — if any field were omitted,
  a prover could mutate that field, still get `e = 1`, skip the Merkle
  check, and forge a state transition.

  ## What the Rust actually does (verified line-by-line)

  `PublicState` has exactly **5 fields** (`public_state.rs:71-77` native,
  `:92-98` target):

    1. `block_number`          — `BlockNumberTarget`, ONE wire (`u63.rs:111-113`)
    2. `timestamp`             — `U64Target`, 2 u32 limbs (`u64.rs:20,45`)
    3. `account_tree_root`     — `PoseidonHashOutTarget`, 4 limbs (`poseidon_hash_out.rs:36`)
    4. `deposit_tree_root`     — `PoseidonHashOutTarget`, 4 limbs
    5. `prev_public_state_root`— `PoseidonHashOutTarget`, 4 limbs

  `is_equal` (`public_state.rs:307-328`) computes a per-field equality
  bit for **all five** fields and ANDs them in a left-leaning tree:

    block_eq      := block_number.is_equal(..)             (:312)
    timestamp_eq  := timestamp.is_equal(..)                (:313)
    account_eq    := account_tree_root.is_equal(..)        (:314-316)
    deposit_eq    := deposit_tree_root.is_equal(..)        (:317-319)
    prev_state_eq := prev_public_state_root.is_equal(..)   (:320-322)
    tmp := and(block_eq, timestamp_eq)                     (:324)
    tmp := and(tmp, account_eq)                            (:325)
    tmp := and(tmp, deposit_eq)                            (:326)
    return and(tmp, prev_state_eq)                         (:327)

  Per-field gadgets:
    * `BlockNumberTarget::is_equal` (`u63.rs:209-215`) is a single
      `builder.is_equal(self.value, other.value)` — modeled by the
      trusted `Builder.IsEqualSpec` advice-gate semantics.
    * `U32LimbTargetTrait::is_equal` (`u32limb_trait.rs:178-189`, used
      by `U64Target`) and `PoseidonHashOutTarget::is_equal`
      (`poseidon_hash_out.rs:204-216`) both fold
      `acc := builder.and(acc, builder.is_equal(limbᵢ, otherᵢ))`
      starting from `builder._true()` (= constant 1) over ALL limbs.
      `builder.and` on boolean wires is field multiplication
      (`Builder.andGate`); both fold inputs are boolean by gate
      construction (`is_equal` output; constant 1), so the model is
      exact. Modeled here as the inductive `LimbsEqFold`.

  ## Verdict

  `publicStateEq_sound` proves: on ANY satisfying witness, the output
  wire is boolean and equals 1 **iff all five fields are equal**
  (`publicStateEq_iff_struct_eq`: iff the two records are equal).
  There is no sixth field and no omitted field. **F-PUBST-1 is
  discharged**: the `update_public_state.rs:97` no-op branch cannot be
  taken with any field mutated.
-/

namespace Zkp
namespace Circuits.PublicStateEq

open CField Builder

variable {F : Type} [CField F]

/-! ## Generic lemmas about the boolean gadgets -/

/-- `builder.and` of two boolean wires is boolean. -/
theorem andGate_bool {a b : F} (ha : a = 0 ∨ a = 1) (hb : b = 0 ∨ b = 1) :
    andGate a b = 0 ∨ andGate a b = 1 := by
  unfold andGate
  rcases ha with h | h <;> rcases hb with h' | h' <;> subst h <;> subst h' <;> simp

/-- The `is_equal` advice gate is always satisfiable (completeness of
    the gadget: the honest prover can supply the inverse advice wire
    for any pair of inputs). Uses classical case split because the
    abstract field has no decidable equality. -/
theorem isEqualSpec_exists (a b : F) : ∃ e, IsEqualSpec a b e := by
  by_cases h : a = b
  · exact ⟨1, Or.inr rfl, fun _ => h, fun _ => rfl⟩
  · exact ⟨0, Or.inl rfl, fun h01 => absurd h01.symm one_ne_zero, fun hab => absurd hab h⟩

/-! ## The multi-limb `is_equal` fold

  `U32LimbTargetTrait::is_equal` (`u32limb_trait.rs:178-189`) and
  `PoseidonHashOutTarget::is_equal` (`poseidon_hash_out.rs:204-216`):

      let mut result = builder._true();                 // acc₀ = 1
      for (a, b) in limbs.zip(other) {
          let eq = builder.is_equal(*a, *b);            // advice gate
          result = builder.and(result, eq);             // accᵢ₊₁ = accᵢ · eqᵢ
      }
      result

  Modeled as an inductive predicate: each constructor is exactly the
  constraint set of one loop iteration (the existential advice wire
  `e` appears as a constructor argument, never a function — the prover
  chooses it, the `IsEqualSpec` gate constrains it). -/
inductive LimbsEqFold : F → List F → List F → F → Prop where
  /-- Empty limb list: the fold returns the accumulator unchanged. -/
  | nil (acc : F) : LimbsEqFold acc [] [] acc
  /-- One iteration: advice wire `e` constrained by `is_equal(x, y)`,
      accumulator updated by `builder.and`. -/
  | cons {acc x y e out : F} {xs ys : List F}
      (he : IsEqualSpec x y e)
      (hrest : LimbsEqFold (andGate acc e) xs ys out) :
      LimbsEqFold acc (x :: xs) (y :: ys) out

/-- Soundness of the fold, generalized over the accumulator: the
    result is boolean, and equals 1 iff the accumulator was 1 AND all
    limb pairs are equal. (Note the fold also forces the two lists to
    have the same length — the loop zips fixed-width limb arrays, so
    length mismatch never occurs; the inductive has no constructor for
    it.) -/
theorem limbsEqFold_sound {acc : F} {xs ys : List F} {out : F}
    (h : LimbsEqFold acc xs ys out) :
    (acc = 0 ∨ acc = 1) →
    (out = 0 ∨ out = 1) ∧ (out = 1 ↔ (acc = 1 ∧ xs = ys)) := by
  induction h with
  | nil acc =>
    intro hacc
    refine ⟨hacc, ?_, ?_⟩
    · intro h1; exact ⟨h1, rfl⟩
    · rintro ⟨h1, -⟩; exact h1
  | cons he _hrest ih =>
    intro hacc
    have hebool := he.1
    have ih' := ih (andGate_bool hacc hebool)
    refine ⟨ih'.1, ?_⟩
    rw [ih'.2]
    constructor
    · rintro ⟨hand, hxs⟩
      obtain ⟨hacc1, he1⟩ := (andGate_eq_one_iff hacc hebool).mp hand
      exact ⟨hacc1, by rw [he.2.mp he1, hxs]⟩
    · rintro ⟨hacc1, hcons⟩
      injection hcons with hxy hxs
      exact ⟨(andGate_eq_one_iff hacc hebool).mpr ⟨hacc1, he.2.mpr hxy⟩, hxs⟩

/-- The fold as called in the Rust (`result = builder._true()`, i.e.
    initial accumulator 1): output is boolean and equals 1 iff the
    limb lists are equal. -/
theorem limbsEq_sound {xs ys : List F} {out : F}
    (h : LimbsEqFold 1 xs ys out) :
    (out = 0 ∨ out = 1) ∧ (out = 1 ↔ xs = ys) := by
  have h' := limbsEqFold_sound h (Or.inr rfl)
  refine ⟨h'.1, ?_⟩
  rw [h'.2]
  exact ⟨fun ⟨_, h⟩ => h, fun h => ⟨rfl, h⟩⟩

/-- Satisfiability of the fold for equal-length limb lists (the only
    shape the Rust ever produces: both sides are the same fixed-width
    target array). -/
theorem limbsEqFold_exists (xs : List F) :
    ∀ (ys : List F), xs.length = ys.length →
      ∀ acc : F, ∃ out, LimbsEqFold acc xs ys out := by
  induction xs with
  | nil =>
    intro ys hlen acc
    cases ys with
    | nil => exact ⟨acc, .nil acc⟩
    | cons y ys =>
      -- `hlen : 0 = ys.length + 1` is absurd; simp closes the goal.
      simp only [List.length_nil, List.length_cons] at hlen
  | cons x xs ih =>
    intro ys hlen acc
    cases ys with
    | nil =>
      simp only [List.length_nil, List.length_cons] at hlen
    | cons y ys =>
      simp only [List.length_cons] at hlen
      obtain ⟨e, he⟩ := isEqualSpec_exists x y
      obtain ⟨out, hout⟩ := ih ys (by omega) (andGate acc e)
      exact ⟨out, .cons he hout⟩

/-! ## The public-state record and its `is_equal` constraints -/

/-- Wire bundle of `PublicStateTarget` (`public_state.rs:92-98`).
    Exactly five fields — this mirrors the Rust struct 1:1; adding or
    removing a field here would desynchronize the model from
    `public_state.rs:71-77` and must not be done without re-checking
    the source. -/
structure PublicState (F : Type) where
  /-- `block_number : BlockNumberTarget` — one wire (`u63.rs:111-113`). -/
  blockNumber : F
  /-- `timestamp : U64Target` — 2 u32 limbs (`u64.rs:20,45`). -/
  timestamp : List F
  /-- `account_tree_root : PoseidonHashOutTarget` — 4 limbs. -/
  accountTreeRoot : List F
  /-- `deposit_tree_root : PoseidonHashOutTarget` — 4 limbs. -/
  depositTreeRoot : List F
  /-- `prev_public_state_root : PoseidonHashOutTarget` — 4 limbs. -/
  prevPublicStateRoot : List F

/-- Every constraint emitted by `PublicStateTarget::is_equal`
    (`public_state.rs:307-328`), on a satisfying witness:
    five per-field equality bits (all advice-gate constrained), then
    the four-`and` left-leaning tree (`:324-327`). Deterministic `and`
    gates appear as equations defining the output wire. -/
def IsEqualConstraints (a b : PublicState F) (out : F) : Prop :=
  ∃ blockEq timestampEq accountEq depositEq prevStateEq : F,
    -- :312  block_eq = is_equal(block_number)   (u63.rs:209-215)
    IsEqualSpec a.blockNumber b.blockNumber blockEq
    -- :313  timestamp_eq = is_equal(timestamp)  (u32limb_trait.rs:178-189)
    ∧ LimbsEqFold 1 a.timestamp b.timestamp timestampEq
    -- :314-316  account_eq                       (poseidon_hash_out.rs:204-216)
    ∧ LimbsEqFold 1 a.accountTreeRoot b.accountTreeRoot accountEq
    -- :317-319  deposit_eq
    ∧ LimbsEqFold 1 a.depositTreeRoot b.depositTreeRoot depositEq
    -- :320-322  prev_state_eq
    ∧ LimbsEqFold 1 a.prevPublicStateRoot b.prevPublicStateRoot prevStateEq
    -- :324-327  and-tree: and(and(and(and(block, ts), acct), dep), prev)
    ∧ out = andGate (andGate (andGate (andGate blockEq timestampEq) accountEq) depositEq)
        prevStateEq

/-- **Soundness (discharges F-PUBST-1).** On any witness the circuit
    accepts, the `is_equal` output is boolean, and it equals 1 iff
    ALL FIVE public-state fields are equal. No field is omitted from
    the conjunction — mutating any single field forces `out = 0`,
    so the `update_public_state.rs:97` no-op skip cannot fire on a
    mutated state. -/
theorem publicStateEq_sound (a b : PublicState F) (out : F)
    (h : IsEqualConstraints a b out) :
    (out = 0 ∨ out = 1) ∧
    (out = 1 ↔
      (a.blockNumber = b.blockNumber
        ∧ a.timestamp = b.timestamp
        ∧ a.accountTreeRoot = b.accountTreeRoot
        ∧ a.depositTreeRoot = b.depositTreeRoot
        ∧ a.prevPublicStateRoot = b.prevPublicStateRoot)) := by
  obtain ⟨be, te, ae, de, pe, hbe, hte, hae, hde, hpe, hout⟩ := h
  have hbeB := hbe.1
  have ht := limbsEq_sound hte
  have ha := limbsEq_sound hae
  have hd := limbsEq_sound hde
  have hp := limbsEq_sound hpe
  -- booleanness up the and-tree
  have b1 := andGate_bool hbeB ht.1
  have b2 := andGate_bool b1 ha.1
  have b3 := andGate_bool b2 hd.1
  have b4 := andGate_bool b3 hp.1
  subst hout
  refine ⟨b4, ?_⟩
  rw [andGate_eq_one_iff b3 hp.1, andGate_eq_one_iff b2 hd.1,
    andGate_eq_one_iff b1 ha.1, andGate_eq_one_iff hbeB ht.1,
    hbe.2, ht.2, ha.2, hd.2, hp.2]
  simp only [and_assoc]

/-- Restatement at the record level: `out = 1` iff the two
    `PublicState` records are EQUAL — the exact premise the
    F-PUBST-1 no-op-branch argument needs. -/
theorem publicStateEq_iff_struct_eq (a b : PublicState F) (out : F)
    (h : IsEqualConstraints a b out) : out = 1 ↔ a = b := by
  rw [(publicStateEq_sound a b out h).2]
  cases a; cases b
  simp only [PublicState.mk.injEq]

/-- Satisfiability: for any two states with matching limb widths (the
    Rust guarantees this — both sides are `U64Target`/4-limb hash
    targets), some witness satisfies every emitted constraint. The
    constraint set is not vacuous. -/
theorem publicStateEq_satisfiable (a b : PublicState F)
    (hts : a.timestamp.length = b.timestamp.length)
    (hac : a.accountTreeRoot.length = b.accountTreeRoot.length)
    (hdp : a.depositTreeRoot.length = b.depositTreeRoot.length)
    (hpv : a.prevPublicStateRoot.length = b.prevPublicStateRoot.length) :
    ∃ out, IsEqualConstraints a b out := by
  obtain ⟨be, hbe⟩ := isEqualSpec_exists a.blockNumber b.blockNumber
  obtain ⟨te, hte⟩ := limbsEqFold_exists a.timestamp b.timestamp hts 1
  obtain ⟨ae, hae⟩ := limbsEqFold_exists a.accountTreeRoot b.accountTreeRoot hac 1
  obtain ⟨de, hde⟩ := limbsEqFold_exists a.depositTreeRoot b.depositTreeRoot hdp 1
  obtain ⟨pe, hpe⟩ := limbsEqFold_exists a.prevPublicStateRoot b.prevPublicStateRoot hpv 1
  exact ⟨_, be, te, ae, de, pe, hbe, hte, hae, hde, hpe, rfl⟩

end Circuits.PublicStateEq
end Zkp
