/-
  Zkp.Core.Field
  ==============

  Algebraic core for modeling Plonky2 circuit constraints.

  Plonky2 circuits operate over the Goldilocks prime field
  `F_p`, p = 2^64 - 2^32 + 1. A Plonky2 *gate* asserts that a
  polynomial relation over field elements vanishes; a *witness*
  is an assignment of field elements to the circuit's wires that
  satisfies every such relation.

  We model a field element of a *fixed but arbitrary satisfying
  assignment* as a value of an abstract type `F : Type` equipped
  with the field operations and exactly the axioms our soundness
  proofs use. Reasoning over an abstract `F` means a lemma proved
  here holds for *every* concrete field satisfying the axioms (in
  particular Goldilocks), and never accidentally relies on a
  property the real circuit cannot guarantee.

  SECURITY — the ACTUAL trusted base of this development. The
  `CField` axioms below are the trusted *algebraic* core (Goldilocks
  is a field, hence an integral domain, so `mul_eq_zero` holds), but
  they are NOT the whole trusted base. A reader auditing what is
  assumed rather than proved must also count:

    1. **Opaque primitives**, trusted for determinism only:
       `Bytes.poseidon`, `Merkle.compress`, `Builder.natLit`,
       `Builder.repr`, `Bytes.fromHashOut`, `U256.uval`/`u256Leaf`,
       the per-circuit commitment/root functions (`commitment`,
       `nullifierRoot`, `nullifierKey`, ...), and the contract-side
       `keccak` (Contracts/Coverage.lean).
    2. **Spec-level ℕ-arithmetic relations** standing in for verified
       gate chains: `U256.AddSpec` / `U256.SubSpec`. The limb/carry
       argument justifying them is Rust-side (u256.rs:277-292 add,
       :304-321 sub) and lives OUTSIDE Lean — see the trusted-base
       note in Core/U256.lean.
    3. **`Builder.rangeCheck` semantics**: `repr a < 2^bits` models
       `builder.range_check`; it carries force only together with the
       `Builder.ReprFaithful` facts.
    4. **Named hypothesis families** — never axioms, always explicit
       theorem parameters, so each use is visible in a signature:
         * collision resistance / binding: `Bytes.PoseidonCR`,
           `Merkle.CompressCR`, `Contracts.*` `KeccakCR`,
           `Circuits.UpdatePrivateState.NullifierRootBinding`;
         * numeral / representative faithfulness: `Builder.NatLitInj`
           (BOUNDED numeral injectivity — the unbounded form is
           pigeonhole-false at any finite field), `Builder.ReprFaithful`;
         * characteristic facts: `Merkle.PowTwoInj F k` (uniqueness of
           k-bit boolean decompositions — Goldilocks-true for k ≤ 63;
           load-bearing wherever the two independent per-call
           `split_le` decompositions of one index wire are identified,
           see Core/Merkle.lean), and the char(F) > 4 reading of the
           one-hot sum (Circuits/Balance/SwitchBoard.lean);
         * Poseidon accumulator idealizations `AccumulateNoFixpoint` /
           `AccumulateNeverEmpty` (Circuits/Validity/UpdateUser.lean) —
           NOT structural facts of the concrete hash: both are
           literally unsatisfiable-by-counting for real Poseidon and
           are read symbolically ("no such instance exhibited"), same
           status as the CR family; see their docstrings.

  We deliberately do NOT axiomatize the characteristic / specific
  prime here; any soundness argument that needs `2^32 < p`,
  canonical-form uniqueness, or range bounds must take the relevant
  NAMED hypothesis explicitly at its use site rather than smuggle it
  in through the field axioms.
-/

namespace Zkp

/-- A commutative field, modeled with just the operations and
    axioms the circuit-soundness proofs depend on. -/
class CField (F : Type) where
  zero : F
  one : F
  add : F → F → F
  mul : F → F → F
  neg : F → F
  -- Commutative ring axioms.
  add_assoc : ∀ a b c, add (add a b) c = add a (add b c)
  add_comm : ∀ a b, add a b = add b a
  add_zero : ∀ a, add a zero = a
  add_neg : ∀ a, add a (neg a) = zero
  mul_assoc : ∀ a b c, mul (mul a b) c = mul a (mul b c)
  mul_comm : ∀ a b, mul a b = mul b a
  mul_one : ∀ a, mul a one = a
  left_distrib : ∀ a b c, mul a (add b c) = add (mul a b) (mul a c)
  -- Field ⇒ integral domain (no nonzero zero-divisors).
  mul_eq_zero : ∀ a b, mul a b = zero → a = zero ∨ b = zero
  -- Nondegeneracy.
  one_ne_zero : one ≠ zero

namespace CField

variable {F : Type} [CField F]

instance : Inhabited F := ⟨zero⟩
instance : OfNat F 0 := ⟨zero⟩
instance : OfNat F 1 := ⟨one⟩
instance : Add F := ⟨add⟩
instance : Mul F := ⟨mul⟩
instance : Neg F := ⟨neg⟩
instance : Sub F := ⟨fun a b => add a (neg b)⟩

-- Notation-form restatements of the axioms, so `rw` can match the
-- `+`/`*`/`-` surface syntax (each holds definitionally).
@[simp] theorem sub_def (a b : F) : a - b = a + (-b) := rfl
theorem addA (a b c : F) : (a + b) + c = a + (b + c) := add_assoc a b c
theorem addC (a b : F) : a + b = b + a := add_comm a b
theorem mulA (a b c : F) : (a * b) * c = a * (b * c) := mul_assoc a b c
theorem mulC (a b : F) : a * b = b * a := mul_comm a b
theorem distribL (a b c : F) : a * (b + c) = a * b + a * c := left_distrib a b c
theorem mul_eq_zero' {a b : F} (h : a * b = 0) : a = 0 ∨ b = 0 := mul_eq_zero a b h

@[simp] theorem add_zero' (a : F) : a + (0 : F) = a := add_zero a

@[simp] theorem zero_add' (a : F) : (0 : F) + a = a := by
  rw [addC]; exact add_zero a

@[simp] theorem add_neg' (a : F) : a + (-a) = 0 := add_neg a

@[simp] theorem neg_add' (a : F) : (-a) + a = 0 := by
  rw [addC]; exact add_neg a

@[simp] theorem neg_zero' : (-(0 : F)) = 0 := by
  have h := neg_add' (0 : F)
  rw [add_zero'] at h
  exact h

@[simp] theorem mul_one' (a : F) : a * (1 : F) = a := mul_one a

@[simp] theorem one_mul' (a : F) : (1 : F) * a = a := by
  rw [mulC]; exact mul_one a

/-- Left cancellation for addition (standard ring fact). -/
theorem add_left_cancel {a b c : F} (h : a + b = a + c) : b = c := by
  have h2 := congrArg ((-a) + ·) h
  simp only at h2
  rw [← addA, neg_add', zero_add', ← addA, neg_add', zero_add'] at h2
  exact h2

/-- Right cancellation for addition. -/
theorem add_right_cancel {a b c : F} (h : a + c = b + c) : a = b := by
  have h2 := congrArg (· + (-c)) h
  simp only at h2
  rw [addA, add_neg', add_zero', addA, add_neg', add_zero'] at h2
  exact h2

@[simp] theorem mul_zero' (a : F) : a * (0 : F) = 0 := by
  have h : a * (0 : F) + a * 0 = a * 0 := by
    rw [← distribL, zero_add']
  have h3 : a * (0 : F) + a * 0 = a * 0 + 0 := by rw [add_zero']; exact h
  exact add_left_cancel h3

@[simp] theorem zero_mul' (a : F) : (0 : F) * a = 0 := by
  rw [mulC]; exact mul_zero' a

@[simp] theorem sub_self' (a : F) : a - a = 0 := by simp

/-- The boolean characterization used everywhere: a wire that
    satisfies `b*(b-1) = 0` takes value `0` or `1`. This is
    precisely what `builder.assert_bool` enforces, and its
    soundness rests on the integral-domain axiom. -/
theorem bool_of_mul_sub_one_eq_zero (b : F) (h : b * (b - 1) = 0) :
    b = 0 ∨ b = 1 := by
  rcases mul_eq_zero' h with h0 | h1
  · exact Or.inl h0
  · right
    have e : b + (-(1 : F)) = (1 : F) + (-(1 : F)) := by
      rw [add_neg']; exact h1
    exact add_right_cancel e

end CField
end Zkp
