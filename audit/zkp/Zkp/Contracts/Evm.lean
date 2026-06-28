import Zkp.Core.Bytes

/-
  Zkp.Contracts.Evm
  =================

  Modeling core for the Solidity (Foundry, Solidity 0.8.29) contracts,
  in the SAME spirit as `Core/Builder.lean` is for circuits.

  A Solidity external function is a STATE TRANSITION over contract
  storage that either commits a new state or REVERTS (atomically undoing
  all effects). We model storage as a record, a `require`/checked-math
  failure as a revert (`Option State = none`), and a successful call as
  `some State'`. Crypto verifiers (Groth16 / KZG / MLE-WHIR pairing math)
  are UNINTERPRETED oracles — exactly as Poseidon/keccak are in the
  circuit model — so contract-level reasoning is about the protocol
  logic (access control, accounting, replay, CEI), not the primitives.

  SECURITY: Solidity 0.8 arithmetic is CHECKED — `a - b` reverts on
  underflow, `a + b` on overflow. We model these as `checkedSub`/
  `checkedAdd` returning `none` on failure, because that revert is
  frequently load-bearing (e.g. the `totalEscrowed -= amount` global
  solvency ceiling). Using raw ℕ subtraction would silently saturate and
  HIDE the very property the EVM enforces.
-/

namespace Zkp
namespace Contracts
namespace Evm

open Zkp.Bytes

/-- Ethereum address. Modeled by an identifier with decidable equality
    (the only operation the protocol logic performs on addresses). -/
abbrev Addr := Nat

/-- A 256-bit word as a natural number. Concrete arithmetic facts use ℕ;
    the wrap-at-2^256 is modeled via `checkedAdd` (overflow ⇒ revert), so
    in-range values behave as true integers. -/
abbrev U256 := Nat

/-- A 32-byte word (hash / commitment / nullifier). Modeled by an
    identifier with decidable equality, matched against circuit-side
    `Bytes32` values at the interface. -/
abbrev Word := Nat

/-- A Solidity `mapping(K => V)` with the EVM default value for misses. -/
def Mapping (K V : Type) := K → V

namespace Mapping
variable {K V : Type} [DecidableEq K]
/-- Read (`m[k]`). -/
def get (m : Mapping K V) (k : K) : V := m k
/-- Write (`m[k] = v`). -/
def set (m : Mapping K V) (k : K) (v : V) : Mapping K V :=
  fun k' => if k' = k then v else m k'
@[simp] theorem get_set_eq (m : Mapping K V) (k : K) (v : V) :
    (m.set k v).get k = v := by simp [get, set]
@[simp] theorem get_set_ne (m : Mapping K V) {k k' : K} (v : V) (h : k' ≠ k) :
    (m.set k v).get k' = m.get k' := by simp [get, set, h]
end Mapping

/-- Solidity-0.8 checked subtraction: reverts (none) on underflow. -/
def checkedSub (a b : U256) : Option U256 := if b ≤ a then some (a - b) else none

/-- Solidity-0.8 checked addition under a 2^256 bound: reverts on overflow. -/
def checkedAdd (a b : U256) : Option U256 :=
  if a + b < 2 ^ 256 then some (a + b) else none

@[simp] theorem checkedSub_some {a b : U256} (h : b ≤ a) : checkedSub a b = some (a - b) := by
  simp [checkedSub, h]

theorem checkedSub_eq_some {a b r : U256} (h : checkedSub a b = some r) :
    b ≤ a ∧ r = a - b := by
  unfold checkedSub at h
  by_cases hb : b ≤ a
  · simp [hb] at h; exact ⟨hb, h.symm⟩
  · simp [hb] at h

theorem checkedAdd_eq_some {a b r : U256} (h : checkedAdd a b = some r) :
    r = a + b := by
  unfold checkedAdd at h
  by_cases hb : a + b < 2 ^ 256
  · simp [hb] at h; exact h.symm
  · simp [hb] at h

/-- A revert-or-commit result of an external call. `none` = revert. -/
abbrev Call (σ : Type) := Option σ

end Evm
end Contracts
end Zkp
