import Zkp.Core.Field

/-
  Zkp.Core.Builder
  ================

  Semantics of the Plonky2 `CircuitBuilder` API, as used by the
  intmax3 circuits, expressed at the level of a *single satisfying
  witness*.

  Modeling choice (and why it is faithful):

  A Plonky2 circuit is a set of gate constraints over wires. A
  proof exists iff there is a wire assignment satisfying every
  constraint. For *soundness* we must show: for ANY assignment the
  verifier accepts, the intended statement holds. So we model a
  wire as the field value `F` it takes in an arbitrary-but-fixed
  satisfying assignment, and a `builder.*` call as either:

    * a deterministic gate that *defines* a new wire's value as a
      function of its inputs (`add`, `mul`, `sub`, `constant`,
      `select`) — modeled as a Lean function returning `F`; or

    * an *assertion* that constrains existing wires
      (`connect`, `assert_zero`, `assert_bool`, ...) — modeled as
      a `Prop` that the satisfying assignment must make true.

  A translated circuit is therefore a `Prop` (the conjunction of
  all its assertions) over the input/output wire values, and a
  soundness theorem has the shape

      Constraints inputs outputs → outputs = nativeSpec inputs.

  SECURITY: deterministic gates carry no `Prop` because the prover
  has *no freedom* in their output — the gate's own constraint
  pins it. Representing them as functions is exactly that pinning.
  Any place where the prover DOES have freedom (a witnessed
  advice wire, e.g. the inverse in `is_equal`, or a range hint)
  must appear as an explicit existential / relation, never as a
  function, or the model would over-constrain the prover and hide
  a real soundness gap.
-/

namespace Zkp
namespace Builder

open CField

variable {F : Type} [CField F]

/-! ### Assertion gates (produce constraints) -/

/-- `builder.connect(a, b)` — forces the two wires equal. -/
def connect (a b : F) : Prop := a = b

/-- `builder.assert_zero(a)`. -/
def assertZero (a : F) : Prop := a = 0

/-- `builder.assert_one(a)`. -/
def assertOne (a : F) : Prop := a = 1

/-- `builder.assert_bool(a)` — pins `a` to `{0,1}` via `a(a-1)=0`. -/
def assertBool (a : F) : Prop := a * (a - 1) = 0

/-! ### Deterministic gates (produce wire values) -/

/-- `builder.constant(c)`. -/
def constant (c : F) : F := c

/-- `F::from_canonical_u64(n)` — embed a small natural-number literal
    as a field element (domain tags, separators, fixed amounts).
    Uninterpreted: determinism is all the soundness logic needs. -/
opaque natLit (F : Type) [CField F] (n : Nat) : F

/-- `builder.add`. -/
def add (a b : F) : F := a + b

/-- `builder.sub`. -/
def sub (a b : F) : F := a - b

/-- `builder.mul`. -/
def mul (a b : F) : F := a * b

/-- `builder.mul_const` / scalar multiply by an in-circuit constant. -/
def mulConst (c a : F) : F := c * a

/-- `builder.select(c, x, y)` with `c` intended boolean: returns
    `c*x + (1-c)*y`. Correctness (it equals `x`/`y` for `c=1`/`0`)
    is a *lemma* that requires `c ∈ {0,1}` — see `select_eq_*`. -/
def select (c x y : F) : F := c * x + (1 - c) * y

/-! ### Witnessed-advice gates (produce value + constraint spec) -/

/-- `builder.is_equal(a, b)` returns a boolean wire `e`. The gate
    introduces a *witnessed* inverse advice wire, so `e` is not a
    function of `(a,b)` at the syntactic level; what the gate
    guarantees is captured by this relation. -/
def IsEqualSpec (a b e : F) : Prop :=
  (e = 0 ∨ e = 1) ∧ (e = 1 ↔ a = b)

/-- `builder.not(b)` on a boolean wire: `1 - b`. -/
def notGate (b : F) : F := 1 - b

/-- `not` of a boolean is `1 - b`, and stays boolean. -/
theorem notGate_bool {b : F} (h : b = 0 ∨ b = 1) :
    notGate b = 1 ∨ notGate b = 0 := by
  unfold notGate
  rcases h with h | h
  · left; rw [h]; simp
  · right; rw [h]; simp

/-- `not b = 1 ↔ b = 0`, for a boolean wire. -/
theorem notGate_eq_one_iff {b : F} (hb : b = 0 ∨ b = 1) :
    notGate b = 1 ↔ b = 0 := by
  unfold notGate
  constructor
  · intro h
    rcases hb with h0 | h1
    · exact h0
    · exfalso; rw [h1] at h
      -- 1 - 1 = 0 ≠ 1 would need 0 = 1
      simp at h
      exact one_ne_zero h.symm
  · intro h; rw [h]; simp

/-- `builder.and(a, b)` on booleans: `a * b`. -/
def andGate (a b : F) : F := a * b

/-- `and` of two booleans is `1` iff both are `1`. -/
theorem andGate_eq_one_iff {a b : F} (ha : a = 0 ∨ a = 1) (hb : b = 0 ∨ b = 1) :
    andGate a b = 1 ↔ a = 1 ∧ b = 1 := by
  unfold andGate
  constructor
  · intro h
    rcases ha with ha | ha
    · subst ha; rw [zero_mul'] at h; exact absurd h.symm one_ne_zero
    · rcases hb with hb | hb
      · subst hb; rw [mul_zero'] at h; exact absurd h.symm one_ne_zero
      · exact ⟨ha, hb⟩
  · rintro ⟨ha1, hb1⟩; subst ha1; subst hb1; rw [one_mul']

/-- `andGate a 0 = 0` and `andGate 0 b = 0`. -/
@[simp] theorem andGate_zero_right (a : F) : andGate a (0 : F) = 0 := by
  unfold andGate; simp
@[simp] theorem andGate_zero_left (b : F) : andGate (0 : F) b = 0 := by
  unfold andGate; simp

/-- Generic select specification over any wire-bundle type `α`:
    `Target::select(cond, x, y)` returns `x` when `cond = 1`, `y` when
    `cond = 0`. Composite types (HashOut, Bytes32, BlockNumber) select
    componentwise; this captures the guarantee uniformly. -/
def SelectSpec {α : Type} (cond : F) (x y r : α) : Prop :=
  (cond = 1 → r = x) ∧ (cond = 0 → r = y)

/-- `builder.conditional_assert_eq(cond, a, b)` — asserts `a = b`
    only when the boolean `cond` is `1`. -/
def condAssertEq (cond a b : F) : Prop := cond = 1 → a = b

/-- Generic `is_equal` advice gate over any wire-bundle type `α`:
    returns a boolean `e` that is `1` exactly when `a = b`. Used both
    for single field elements and for struct equality (which the Rust
    `is_equal` builds by AND-ing per-field equalities). -/
def IsEqualSpecG {α : Type} (a b : α) (e : F) : Prop :=
  (e = 0 ∨ e = 1) ∧ (e = 1 ↔ a = b)

/-- A range check `builder.range_check(a, bits)` asserts the wire's
    canonical representative is below `2^bits`. The actual bound is
    a property of the Goldilocks embedding into ℕ; we keep it
    abstract here and make any reliance explicit at the use site.
    `repr a` is the canonical ℕ representative of the field value. -/
opaque repr : F → Nat

/-- Range assertion: canonical representative fits in `bits` bits. -/
def rangeCheck (bits : Nat) (a : F) : Prop := repr a < 2 ^ bits

/-! ### Lemmas about deterministic gates -/

/-- `select` returns `x` when the selector is `1`. -/
theorem select_eq_left (x y : F) : select (1 : F) x y = x := by
  unfold select
  -- 1*x + (1-1)*y = x + 0*y = x
  rw [sub_self', zero_mul', add_zero', one_mul']

/-- `select` returns `y` when the selector is `0`. -/
theorem select_eq_right (x y : F) : select (0 : F) x y = y := by
  unfold select
  -- 0*x + (1-0)*y = 0 + 1*y = y
  rw [zero_mul', zero_add']
  -- (1 - 0) * y = y
  have : (1 : F) - 0 = 1 := by simp
  rw [this, one_mul']

/-- A satisfied `assertBool` constraint really does pin the wire to
    `{0,1}` — bridges the gate to the boolean reasoning lemma. -/
theorem assertBool_sound {a : F} (h : assertBool a) : a = 0 ∨ a = 1 :=
  bool_of_mul_sub_one_eq_zero a h

end Builder
end Zkp
