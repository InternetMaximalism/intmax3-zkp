import Zkp.Core.Field
import Zkp.Core.Bytes

/-
  Zkp.Core.U256
  =============

  256-bit unsigned integers as used for token amounts / balances
  (`src/ethereum_types/u256.rs`): 8 × u32 limbs.

  We model a `U256` by its canonical integer value `uval : U256 → ℕ`.
  A range-checked `U256Target::new(is_checked=true)` constrains every
  limb to 32 bits, i.e. `uval a < 2^256` (`Is256`).

  The security-critical operation is **addition**. The circuit
  (`u256.rs:277-292`) propagates carries limb-by-limb and ends with
  `builder.connect_u32(carry, zero)` — forcing the carry-OUT of the
  top limb to zero. Native `add` (`:199-211`) likewise
  `assert_eq!(carry, 0, "U256 addition overflow occured")`.

  Consequence (modeled by `AddSpec`): the result equals the TRUE
  integer sum with NO modular wraparound. A prover therefore cannot
  exploit overflow to wrap a balance down to a small value — the only
  effect of an overflowing sum is that NO satisfying result wire
  exists (the receive becomes unprovable), which for 2^256-scale token
  amounts is unreachable in practice.

  SECURITY: `AddSpec a b r` deliberately states `uval r = uval a +
  uval b` over ℕ (not mod 2^256). Any downstream proof that balances
  only ever grow by exactly `amount` relies on this no-wrap form, and
  it is sound precisely because of the `connect_u32(carry, zero)` gate.

  TRUSTED-BASE STATUS (spec-level entries — read before trusting).
  `AddSpec` and `SubSpec` are ℕ-arithmetic AXIOMATIZATIONS-BY-
  DEFINITION of the add/sub gate chains: the step from "8×u32 limb
  wires with a carry/borrow chain and a final zero-pin" to the ℕ
  identities below is NOT formalized in Lean. It is justified by
  inspection of the Rust circuit, and that justification lives
  outside this development:

    * add — u256.rs:277-292: `add_many_u32` carry chain over the
      limbs (each limb 32-bit by `is_checked = true` construction),
      final `builder.connect_u32(carry, zero)` at :292 ⇒
      `uval r = uval a + uval b` over ℕ, no wraparound.
    * sub — u256.rs:304-321: `sub_u32` borrow chain, final
      `builder.connect_u32(borrow, zero)` at :320 ⇒
      `uval r + uval b = uval a` over ℕ, no underflow.

  Every theorem downstream of `AddSpec`/`SubSpec` inherits exactly
  this trust — they are part of the trusted base alongside the
  `CField` axioms (see the enumeration in Core/Field.lean). The
  completeness direction (a result wire EXISTS whenever the sum/
  difference is representable) is likewise unprovable here because
  `U256`/`uval` are opaque; it is recorded as the named totality
  hypotheses `AddTotal`/`SubTotal` with the satisfiability lemmas
  `addSpec_satisfiable`/`subSpec_satisfiable` showing the specs are
  not vacuous under them.
-/

namespace Zkp
namespace U256

open CField Bytes

variable {F : Type} [CField F]

/-- A 256-bit value (abstract); `uval` is its canonical ℕ value. -/
opaque U256 : Type → Type
opaque uval {F : Type} [CField F] : U256 F → Nat

/-- The leaf digest of a balance as placed in the asset tree. -/
opaque u256Leaf {F : Type} [CField F] : U256 F → HashOut F

/-- `U256Target::new(is_checked=true)` ⇒ all limbs 32-bit ⇒ < 2^256. -/
def Is256 (a : U256 F) : Prop := uval a < 2 ^ 256

/-- Constraint relating `U256Target::add(a,b)`'s output `r` to inputs:
    the carry-out gate forces the exact integer sum (no wraparound). -/
def AddSpec (a b r : U256 F) : Prop := uval r = uval a + uval b

/-- The no-wrap consequence, made explicit for downstream use. -/
theorem add_no_wrap {a b r : U256 F} (h : AddSpec a b r) :
    uval r = uval a + uval b := h

/-- Adding a nonzero amount strictly increases the balance — the
    monotonicity a credit must satisfy. -/
theorem add_strict_mono {a b r : U256 F} (h : AddSpec a b r)
    (hb : 0 < uval b) : uval a < uval r := by
  rw [h]; omega

/-- Constraint relating `U256Target::sub(a,b)`'s output `r` to inputs.
    The circuit (`u256.rs:304-321`) propagates borrows and ends with
    `builder.connect_u32(borrow, zero)` — forcing the borrow-OUT of the
    top limb to zero, i.e. NO underflow. We capture that as the ℕ
    identity `uval r + uval b = uval a`, which is satisfiable iff
    `uval a ≥ uval b`. A prover therefore cannot subtract more than
    `a` holds — the in-circuit insufficient-balance check. -/
def SubSpec (a b r : U256 F) : Prop := uval r + uval b = uval a

/-- **Solvency / no-underflow.** A satisfied `sub` proves the minuend
    was at least the subtrahend, and the result is the exact ℕ
    difference. A spender thus cannot underflow a balance into a huge
    value (the classic spend-more-than-you-have inflation). -/
theorem sub_no_underflow {a b r : U256 F} (h : SubSpec a b r) :
    uval b ≤ uval a ∧ uval r = uval a - uval b := by
  have h' : uval r + uval b = uval a := h
  omega

/-- Spending decreases the balance by exactly the amount. -/
theorem sub_decreases {a b r : U256 F} (h : SubSpec a b r) :
    uval r ≤ uval a := by
  have h' : uval r + uval b = uval a := h
  omega

/-! ### Non-vacuity (completeness side)

`U256`/`uval` are opaque, so "some `r` with `uval r = v` exists" is
not provable inside the model for any `v`. The Rust circuit DOES
always produce a result wire when the carry/borrow pin is satisfiable
(the gates are functional in their inputs), so totality is true of
the concrete instantiation; we record it as named hypotheses and
derive that the specs are satisfiable — i.e. `AddSpec`/`SubSpec` are
not vacuously sound. -/

/-- Totality of the add gate on non-overflowing inputs (named
    completeness hypothesis; Rust: u256.rs:277-292 always yields a
    result wire, the only rejecting gate is the carry pin). -/
def AddTotal (F : Type) [CField F] : Prop :=
  ∀ a b : U256 F, uval a + uval b < 2 ^ 256 → ∃ r, AddSpec a b r

/-- Totality of the sub gate when the minuend suffices (named
    completeness hypothesis; Rust: u256.rs:304-321). -/
def SubTotal (F : Type) [CField F] : Prop :=
  ∀ a b : U256 F, uval b ≤ uval a → ∃ r, SubSpec a b r

/-- **`AddSpec` is satisfiable** (not vacuous): under totality, every
    non-overflowing pair has a result, and the result is in range. -/
theorem addSpec_satisfiable (h : AddTotal F) (a b : U256 F)
    (hno : uval a + uval b < 2 ^ 256) :
    ∃ r, AddSpec a b r ∧ Is256 r := by
  obtain ⟨r, hr⟩ := h a b hno
  have hr' : uval r = uval a + uval b := hr
  refine ⟨r, hr, ?_⟩
  show uval r < 2 ^ 256
  rw [hr']
  exact hno

/-- **`SubSpec` is satisfiable** (not vacuous): under totality, every
    solvent pair has a result, and the result is in range whenever the
    minuend is. -/
theorem subSpec_satisfiable (h : SubTotal F) (a b : U256 F)
    (hle : uval b ≤ uval a) (ha : Is256 a) :
    ∃ r, SubSpec a b r ∧ Is256 r := by
  obtain ⟨r, hr⟩ := h a b hle
  have hr' : uval r + uval b = uval a := hr
  have ha' : uval a < 2 ^ 256 := ha
  refine ⟨r, hr, ?_⟩
  show uval r < 2 ^ 256
  exact Nat.lt_of_le_of_lt (by omega) ha'

end U256
end Zkp
