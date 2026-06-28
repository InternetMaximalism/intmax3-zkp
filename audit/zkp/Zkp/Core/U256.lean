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
    The circuit (`u256.rs:304-329`) propagates borrows and ends with
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

end U256
end Zkp
