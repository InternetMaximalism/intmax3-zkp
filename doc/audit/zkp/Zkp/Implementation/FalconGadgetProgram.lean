import Zkp.Implementation.FalconCore

/-!
# The Falcon signature gadget as a per-primitive builder program

Handwritten semantic model of `FalconSigVerifyTarget::build` (`src/falcon_sig/gadget.rs`,
:651-736) and every helper it calls: `twiddle_tables` (:170-200),
`constrain_mod_q_decomposition` (:243-275), `reduce_mod_q` (:276-289),
`assert_canonical_coeff` (:290-310), `goldilocks_mod_q_block` (:311-352), `h2p_circuit`
(:353-400), `pk_digest_circuit` (:401-433), `ntt_forward` (:434-472), `ntt_inverse`
(:473-514), `pointwise_mul` (:515-539) and `centered_square` (:574-593). This is a MODEL,
not a refinement proof of the Rust, of plonky2 gate lowering, or of the vendored Falcon
math; nothing here certifies that the shipped circuit behaves as modelled.

## What this module derives

`FalconCore.CircuitSatisfied` states the gadget's gate set as ONE hand-written proposition
over a raw witness, with the polynomial product left as the opaque
`FalconCore.PolynomialProduct` callback. This module decomposes both halves:

* every builder call of `build` becomes one `GadgetOp`, carrying a LOCAL proposition
  (`OpHolds`) about the wires it touches, with the source line it comes from in its
  docstring. `gadget_program_satisfied_implies_circuit_satisfied` then derives EVERY field
  of `FalconCore.CircuitSatisfied` from those local propositions alone, with NO side
  hypothesis. The residual obligation is no longer "the gate predicate as a whole" but, per
  primitive, that plonky2's actual gate set implies that primitive's local proposition;
* the product is no longer opaque. `powModQ`, `bitReverse9`, `psiRev`, `psiInvRev`,
  `nttForward`, `pointwise` and `nttInverse` are CONCRETE Lean transcriptions of the
  source's loops, and `circuitProduct : FalconCore.PolynomialProduct` is built from them.
  The headline theorem is stated for `circuitProduct`, not for an arbitrary product.

So the product boundary moves: it used to be "some callback computes `s2 * h`"; it is now
exactly `NttComputesNegacyclicProduct` — "THIS transcribed NTT equals the negacyclic
schoolbook product of `Z_q[X]/(X^512+1)`" — with `negacyclicProduct` transcribed from the
test oracle `schoolbook_negacyclic` (gadget.rs:999-1022). That proposition is NAMED here
and deliberately NOT proved; it is the only remaining statement about the product.

## What is still opaque

* The Poseidon sponge. `h2p_circuit` and `pk_digest_circuit` are modelled through
  `FalconCore.HashEnvironment.hashToPoint` / `.poseidon`, exactly as
  `FalconCore.CircuitSatisfied` uses them. Neither the 65-permutation H2P sponge layout nor
  the 14-bit-lane `encode(h)` Horner packing is re-derived here; the model asserts that the
  wire vector `c` IS `e.hashToPoint salt messageDigest` and that the computed digest IS
  `FalconCore.falconPkDigest e h`.
* Per-op plonky2 faithfulness: that a `range_check`, a `connect`, a `select`, an
  `assert_bool`, an `add_many` or a `mul_const_add` row really enforces the local
  proposition this module attributes to it.
* `NttComputesNegacyclicProduct` (above), and everything `FalconCore` already names:
  lattice hardness, hash collision resistance, keygen, the consumer's obligation to bind
  `message_digest` and the `verify` wire.

## Field arithmetic

The source computes in Goldilocks (`FalconCore.fieldModulus`). Every value this module
states in `Nat` is kept below the modulus by the source's own range checks, and the
no-wrap margins are proved rather than assumed: `ntt_quotient_range_covers_butterflies`
plus `ntt_reductions_do_not_wrap` show that every NTT reduction input is below
`2^15 * q < p`, `FalconCore.mod_q_no_field_wrap` covers the decomposition, and
`FalconCore.canonical_coeff_gates_iff` turns the two 14-bit complement checks into `< q`
using only the fact that a wire carries a canonical field value.

## Reduction accounting

`reduce_mod_q` (:276-289) is the single reduction primitive; each call witnesses a quotient
`k` and a remainder `r` and constrains `t = k*q + r`, `k < 2^k_bits`, `r < q`
(`FalconCore.modQGates`). `FalconCore.mod_q_decomposition_unique` pins `k = t / q` and
`r = t % q`, so the conjunction of a batch of these gates is EQUIVALENT to the functional
equation the batch computes. That is why each transcribed loop's `holds` is stated as the
functional equation over the output wires TOGETHER with the length and range constraints on
the assignment's quotient wires: the two presentations carry the same information, and the
solved form is the one downstream fields need. Per gadget instance:

| site | reductions | `k_bits` |
| --- | --- | --- |
| `goldilocks_mod_q_block` inside `h2p_circuit` (64 rate blocks x 8) | 512 | 32 |
| `ntt_forward` on `h` (9 stages x 256 butterflies x 2) | 4608 | 14 |
| `ntt_forward` on `s2` | 4608 | 14 |
| `pointwise_mul` | 512 | 14 |
| `ntt_inverse` butterflies (2304 add, 2304 sub-then-scale) | 4608 | 1 / 15 |
| `ntt_inverse` final `n^-1` scaling | 512 | 14 |
| the `s1 = c + q - prod` loop (:689-698) | 512 | 1 |

15872 reductions in total.
-/

namespace Zkp.Implementation.FalconGadgetProgram

open Zkp.Implementation.FalconCore

set_option maxRecDepth 4000

/-! ## 1. Twiddle tables (`twiddle_tables`, gadget.rs:170-200)

`pow_mod_q` (:145-156) and `bit_reverse_9` (:158-165) transcribed literally; the `while`
loops are given an explicit fuel bound (64 squarings cover every `u64` exponent, 9
iterations are `LOG_N`). -/

/-- `pow_mod_q`, :145-156: square-and-multiply mod q, `fuel` bounding the `while exp > 0`
loop. -/
def powModQAux : Nat → Nat → Nat → Nat → Nat
  | 0, _, _, acc => acc
  | fuel + 1, base, exp, acc =>
      if exp = 0 then acc
      else
        powModQAux fuel (base * base % falconQ) (exp / 2)
          (if exp % 2 = 1 then acc * base % falconQ else acc)

/-- `pow_mod_q(base, exp)`, :145-156. 64 squarings cover every `u64` exponent. -/
def powModQ (base exp : Nat) : Nat := powModQAux 64 (base % falconQ) exp 1

/-- `bit_reverse_9`, :158-165: `r = (r << 1) | (x & 1); x >>= 1`, `LOG_N = 9` times. -/
def bitReverse9Aux : Nat → Nat → Nat → Nat
  | 0, _, r => r
  | fuel + 1, x, r => bitReverse9Aux fuel (x / 2) (r * 2 + x % 2)

/-- `bit_reverse_9(x)`, :158-165. -/
def bitReverse9 (x : Nat) : Nat := bitReverse9Aux 9 x 0

/-- `psi_inv = pow_mod_q(PSI, Q - 2)`, :175. -/
def psiInv : Nat := powModQ ntoPsi (falconQ - 2)

/-- `PSI_REV[j] = psi^{brv9(j)}`, :178-180. -/
def psiRev (j : Nat) : Nat := powModQ ntoPsi (bitReverse9 j)

/-- `PSI_INV_REV[j] = psi^{-brv9(j)}`, :181-183. -/
def psiInvRev (j : Nat) : Nat := powModQ psiInv (bitReverse9 j)

/-- The build-time assertion of :172, `psi^512 = -1 mod q`. -/
theorem psi_half_order_is_minus_one : powModQ ntoPsi 512 = falconQ - 1 := by decide

/-- The build-time assertion of :173, `psi^1024 = 1 mod q` (psi is a primitive 1024-th
root). -/
theorem psi_order : powModQ ntoPsi 1024 = 1 := by decide

/-- The build-time assertion of :176, `psi * psi^-1 = 1 mod q`. -/
theorem psi_inverse_pinned : ntoPsi * psiInv % falconQ = 1 := by decide

/-- The build-time assertion of :177, `n * n^-1 = 1 mod q`. -/
theorem n_inv_pinned : ntoNInv * 512 % falconQ = 1 := by decide

/-- `psi^-1` as a literal. -/
theorem psi_inv_value : psiInv = 1254 := by decide

/-- Spot checks of `bit_reverse_9` against the 9-bit reversal. -/
theorem bit_reverse_9_spot_checks :
    bitReverse9 0 = 0 ∧ bitReverse9 1 = 256 ∧ bitReverse9 2 = 128 ∧ bitReverse9 3 = 384 := by
  decide

/-- Spot checks of the two twiddle tables (:178-183). -/
theorem twiddle_table_spot_checks :
    psiRev 0 = 1 ∧ psiRev 1 = 10810 ∧ psiRev 2 = 7143 ∧ psiInvRev 0 = 1 ∧
      psiInvRev 1 = 1479 := by
  decide

/-- The tables are inverse at every spot-checked index. -/
theorem twiddle_tables_are_inverse_at_one : psiRev 1 * psiInvRev 1 % falconQ = 1 := by decide

/-- Why each transcribed loop's `holds` may be stated in solved form: ONE `reduce_mod_q`
gate (:276-289, constraining through `constrain_mod_q_decomposition`, :243-275) pins BOTH
of its witness wires, so a batch of such gates and the functional equation the batch
computes carry exactly the same information. -/
theorem reduction_gate_pins_both_wires (t k r kBits : Nat) (hg : modQGates t k r kBits) :
    k = t / falconQ ∧ r = t % falconQ :=
  mod_q_decomposition_unique t k r kBits hg

/-! ## 2. The transcribed NTT (`ntt_forward` :434-472, `ntt_inverse` :473-514,
`pointwise_mul` :515-539)

The mutable `Vec<Target> a` of the source is modelled as a total function `Nat → Nat`
(out-of-range indices read 0, exactly like the `wireOf` lift of a coefficient list). Each
`reduce_mod_q` result is written as `% q`, which `FalconCore.mod_q_decomposition_unique`
shows is the unique value the reduction's gates allow. The `while` loops carry an explicit
fuel of 10, one more than the 9 stages the source runs. -/

/-- `0, 1, ..., n-1` in ascending order — the iteration order of every `for` loop below. -/
def rangeList : Nat → List Nat
  | 0 => []
  | n + 1 => rangeList n ++ [n]

theorem range_list_length (n : Nat) : (rangeList n).length = n := by
  induction n with
  | zero => rfl
  | succ n ih =>
      simp only [rangeList, List.length_append, List.length_cons, List.length_nil, ih]

-- `rangeList falconN` is a 512-element list; nothing below ever expands it, so it is kept
-- opaque to the elaborator.
attribute [local irreducible] rangeList

/-- Coefficient list read as an indexed wire vector; out-of-range reads are 0. -/
def wireOf : List Nat → Nat → Nat
  | [], _ => 0
  | x :: _, 0 => x
  | _ :: xs, i + 1 => wireOf xs i

/-- Writing one wire of the working vector (`a[j] = v`). -/
def upd (a : Nat → Nat) (j v : Nat) : Nat → Nat := fun i => if i = j then v else a i

/-- Number of butterflies each transform performs: 9 stages of 256. -/
def nttButterflies : Nat := 2304

theorem ntt_butterfly_count_pinned : nttButterflies = 9 * 256 := by decide

/-- One Cooley-Tukey butterfly, :454-462. `u` and `v_raw = s * a[j+t]` are read from the
PRE-update vector (as in the source), `a[j]` gets `(u + v_raw) mod q` and `a[j+t]` gets
`(u + q^2 - v_raw) mod q`; the `q^2` offset keeps the value non-negative and is `0 mod q`. -/
def ctButterfly (s t j : Nat) (a : Nat → Nat) : Nat → Nat :=
  upd (upd a j ((a j + s * a (j + t)) % falconQ)) (j + t)
    ((a j + falconQ * falconQ - s * a (j + t)) % falconQ)

/-- The innermost `for j in j1..j1+t` loop, :453. -/
def ctInner (s t j1 : Nat) (a : Nat → Nat) : Nat → Nat :=
  (rangeList t).foldl (fun acc j => ctButterfly s t (j1 + j) acc) a

/-- The `for i in 0..m` loop, :449-452: block start `j1 = 2*i*t`, twiddle `psi_rev[m+i]`. -/
def ctStage (m t : Nat) (a : Nat → Nat) : Nat → Nat :=
  (rangeList m).foldl (fun acc i => ctInner (psiRev (m + i)) t (2 * i * t) acc) a

/-- The `while m < N` loop, :447-466; `t` is halved at the TOP of the body (:448). -/
def nttForwardLoop : Nat → Nat → Nat → (Nat → Nat) → (Nat → Nat)
  | 0, _, _, a => a
  | fuel + 1, m, t, a =>
      if m < falconN then nttForwardLoop fuel (m * 2) (t / 2) (ctStage m (t / 2) a) else a

/-- `ntt_forward`, :434-472: natural-order input, bit-reversed output, all values `< q`. -/
def nttForward (input : List Nat) : List Nat :=
  (rangeList falconN).map (nttForwardLoop 10 1 falconN (wireOf input))

/-- One Gentleman-Sande butterfly, :486-494: `a[j] = (u+v) mod q`,
`a[j+t] = ((u + q - v) * s) mod q` (the subtraction and the twiddle multiplication share a
single reduction). -/
def gsButterfly (s t j : Nat) (a : Nat → Nat) : Nat → Nat :=
  upd (upd a j ((a j + a (j + t)) % falconQ)) (j + t)
    ((a j + falconQ - a (j + t)) * s % falconQ)

/-- The innermost `for j in j1..j1+t` loop, :485. -/
def gsInner (s t j1 : Nat) (a : Nat → Nat) : Nat → Nat :=
  (rangeList t).foldl (fun acc j => gsButterfly s t (j1 + j) acc) a

/-- The `for i in 0..h` loop, :483-496: `j1` advances by `2*t` each iteration, so the `i`-th
block starts at `2*t*i` and uses twiddle `psi_inv_rev[h+i]`. -/
def gsStage (hh t : Nat) (a : Nat → Nat) : Nat → Nat :=
  (rangeList hh).foldl (fun acc i => gsInner (psiInvRev (hh + i)) t (2 * t * i) acc) a

/-- The `while m > 1` loop, :480-499. -/
def nttInverseLoop : Nat → Nat → Nat → (Nat → Nat) → (Nat → Nat)
  | 0, _, _, a => a
  | fuel + 1, m, t, a =>
      if 1 < m then nttInverseLoop fuel (m / 2) (t * 2) (gsStage (m / 2) t a) else a

/-- `ntt_inverse`, :473-514, including the final `n^-1` scaling of :500-508. -/
def nttInverse (input : List Nat) : List Nat :=
  (rangeList falconN).map fun i =>
    ntoNInv * nttInverseLoop 10 falconN 1 (wireOf input) i % falconQ

/-- `pointwise_mul`, :515-539. The source zips two length-512 vectors; modelled as an
indexed map so the result has length 512 by construction. -/
def pointwise (x y : List Nat) : List Nat :=
  (rangeList falconN).map fun i => wireOf x i * wireOf y i % falconQ

/-- The polynomial product the circuit actually computes, :684-687: forward-transform both
operands, multiply pointwise, inverse-transform. NOT an opaque callback. -/
def circuitProduct : FalconCore.PolynomialProduct where
  mul := fun s2 h => nttInverse (pointwise (nttForward s2) (nttForward h))

theorem circuit_product_mul (x y : List Nat) :
    circuitProduct.mul x y = nttInverse (pointwise (nttForward x) (nttForward y)) := rfl

theorem ntt_forward_length (l : List Nat) : (nttForward l).length = falconN := by
  simp only [nttForward, List.length_map, range_list_length]

theorem ntt_inverse_length (l : List Nat) : (nttInverse l).length = falconN := by
  simp only [nttInverse, List.length_map, range_list_length]

theorem pointwise_length (x y : List Nat) : (pointwise x y).length = falconN := by
  simp only [pointwise, List.length_map, range_list_length]

theorem circuit_product_length (x y : List Nat) :
    (circuitProduct.mul x y).length = falconN := by
  rw [circuit_product_mul]
  exact ntt_inverse_length _

/-! ### The reduction bounds the quotient ranges rest on -/

/-- Every `reduce_mod_q` input of the two transforms and of the pointwise product is below
the bound its declared quotient width covers (:437-441, :477-481, :515). -/
theorem ntt_quotient_range_covers_butterflies (u v s : Nat) (hu : u < falconQ)
    (hv : v < falconQ) (hs : s < falconQ) :
    u + s * v < 16384 * falconQ ∧
      u + falconQ * falconQ - s * v < 16384 * falconQ ∧
      (u + falconQ - v) * s < 32768 * falconQ ∧
      ntoNInv * u < 16384 * falconQ := by
  simp only [falconQ, ntoNInv] at *
  have h1 : s * v ≤ 12288 * 12288 := Nat.mul_le_mul (by omega) (by omega)
  have h2 : (u + 12289 - v) * s ≤ 24577 * 12288 := Nat.mul_le_mul (by omega) (by omega)
  have h4 : u + 12289 * 12289 - s * v ≤ u + 12289 * 12289 := Nat.sub_le _ _
  refine ⟨by omega, by omega, by omega, by omega⟩

/-- SECURITY (no field wrap): the widest quotient range the NTT uses still keeps `k*q + r`
far below the Goldilocks modulus, so each field recomposition IS the integer one. -/
theorem ntt_reductions_do_not_wrap : 32768 * falconQ < fieldModulus := by decide

/-- The `s1` loop's reduction input, :693-696: `c + q - prod` is in `[1, 2q-1]`, which a
1-bit quotient covers. -/
theorem s1_reduction_quotient_is_one_bit (c pr : Nat) (hc : c < falconQ) (hp : pr < falconQ) :
    0 < c + falconQ - pr ∧ c + falconQ - pr < 2 * falconQ := by
  simp only [falconQ] at *
  omega

/-- The `s1` loop's reduced value IS `FalconCore.subModQ`, which is what
`FalconCore.reconstructS1` uses. -/
theorem s1_reduce_is_sub_mod_q (c pr : Nat) (hp : pr < falconQ) :
    (c + falconQ - pr) % falconQ = subModQ c pr := by
  simp only [subModQ, Nat.mod_eq_of_lt hp]

/-! ## 3. The remaining product boundary

`schoolbook_negacyclic` (gadget.rs:999-1022) is the obviously-correct O(n^2) oracle the
Rust test suite validates the NTT against. Transcribed here so the residue can be stated
precisely. It is NOT proved. -/

def intSum : List Int → Int
  | [] => 0
  | x :: xs => x + intSum xs

/-- One term of `schoolbook_negacyclic`, :1001-1016: `a_i * b_j` lands at `i+j`, negated
when it wraps past degree `N` (the `X^512 = -1` fold). -/
def negacyclicTerm (a b : List Nat) (k i j : Nat) : Int :=
  if i + j = k then ((wireOf a i * wireOf b j : Nat) : Int)
  else if i + j = k + falconN then -((wireOf a i * wireOf b j : Nat) : Int)
  else 0

def negacyclicCoeff (a b : List Nat) (k : Nat) : Int :=
  intSum ((rangeList falconN).map fun i =>
    intSum ((rangeList falconN).map fun j => negacyclicTerm a b k i j))

/-- `schoolbook_negacyclic`, :999-1022, with the closing `rem_euclid(Q)` of :1017-1020. -/
def negacyclicProduct (a b : List Nat) : List Nat :=
  (rangeList falconN).map fun k => ((negacyclicCoeff a b k).emod (falconQ : Int)).toNat

/-- THE REMAINING PRODUCT BOUNDARY, and the only statement about the product this module
does not derive: the transcribed in-circuit NTT computes the negacyclic product of
`Z_q[X]/(X^512+1)` on canonical inputs. Named, never proved and never used as a hypothesis
below; `gadget_program_satisfied_implies_circuit_satisfied` holds without it. The Rust test
suite checks it on random inputs against `schoolbook_negacyclic` (:999-1022, and the native
mirror `ntt_product_native` at :1023-1066). -/
def NttComputesNegacyclicProduct : Prop :=
  ∀ a b : List Nat, a.length = falconN → b.length = falconN →
    (∀ c ∈ a, c < falconQ) → (∀ c ∈ b, c < falconQ) →
      circuitProduct.mul a b = negacyclicProduct a b

/-! ## 4. The assignment

Wire values of ONE `FalconSigVerifyTarget` instance, in source allocation order, extended
with every intermediate vector the builder names: the H2P sponge outputs and the 32/32
splits and quotients of their reduction, the pk-digest output, the two forward-NTT images,
the pointwise products, the inverse-NTT output, the quotient wires of every reduction, the
centering bits, the squares, the norm and the slack. The `HashEnvironment` is an index, not
data: it fixes the interpretation of the two Poseidon gadget calls, exactly as
`FalconCore.CircuitSatisfied` does. -/
structure GadgetAssignment (e : FalconCore.HashEnvironment) where
  /-- INPUT `pk_g` as a value, :659. -/
  pkG : Nat
  /-- INPUT `message_digest` as a value, :660. -/
  messageDigest : Nat
  /-- Witness `salt`, :663. -/
  salt : List Nat
  /-- Witness `h`, :664. -/
  h : List Nat
  /-- Witness `s2`, :665. -/
  s2 : List Nat
  /-- The `s1` vector of :689-698. -/
  s1 : List Nat
  /-- The prover-chosen centering bits of `centered_square` over `s1`, :574-593, :702-706. -/
  centerBitsS1 : List Nat
  /-- The prover-chosen centering bits over `s2`. -/
  centerBitsS2 : List Nat
  /-- The `new_conditional` gate wire, :646; `new` (:615-619) passes `None` and the wire is
  the constant 1. -/
  verifyBit : Nat
  /-- The 8 u32 limbs of the `pk_g` `Bytes32Target`, :659. -/
  pkGLimbs : List Nat
  /-- The 8 u32 limbs of the `message_digest` `Bytes32Target`, :660. -/
  messageLimbs : List Nat
  /-- Output of `pk_digest_circuit`, :675. -/
  pkComputed : Nat
  /-- The 512 H2P coefficients, :679. -/
  c : List Nat
  /-- High 32-bit halves of the 512 sponge outputs (`goldilocks_mod_q_block`, :327-334). -/
  h2pHi : List Nat
  /-- Low 32-bit halves of the same. -/
  h2pLo : List Nat
  /-- Quotient wires of the 512 sponge-output reductions (:339). -/
  h2pQuotients : List Nat
  /-- `ntt_forward(h)`, :684. -/
  hNtt : List Nat
  /-- Quotient wires of the 2304 `t_add` reductions of `ntt_forward(h)` (:457). -/
  hFwdAddQuotients : List Nat
  /-- Quotient wires of the 2304 `t_sub` reductions of `ntt_forward(h)` (:461). -/
  hFwdSubQuotients : List Nat
  /-- `ntt_forward(s2)`, :685. -/
  s2Ntt : List Nat
  /-- Quotient wires of the 2304 `t_add` reductions of `ntt_forward(s2)`. -/
  s2FwdAddQuotients : List Nat
  /-- Quotient wires of the 2304 `t_sub` reductions of `ntt_forward(s2)`. -/
  s2FwdSubQuotients : List Nat
  /-- `pointwise_mul(s2_ntt, h_ntt)`, :686. -/
  prodNtt : List Nat
  /-- Quotient wires of the 512 pointwise reductions (:534). -/
  pointwiseQuotients : List Nat
  /-- `ntt_inverse(prod_ntt)`, :687. -/
  prod : List Nat
  /-- Quotient wires of the 2304 `t_add` reductions of `ntt_inverse` (:489). -/
  invAddQuotients : List Nat
  /-- Quotient wires of the 2304 sub-then-scale reductions of `ntt_inverse` (:493). -/
  invSubQuotients : List Nat
  /-- Quotient wires of the 512 final `n^-1` scalings (:505). -/
  invScaleQuotients : List Nat
  /-- Quotient wires of the 512 `s1` reductions (:696). -/
  s1Quotients : List Nat
  /-- The 512 centered squares of `s1`, :702-706. -/
  squaresS1 : List Nat
  /-- The 512 centered squares of `s2`, :702-706. -/
  squaresS2 : List Nat
  /-- `add_many(squares)`, :707. -/
  norm : Nat
  /-- `beta^2 - norm`, :719. -/
  slack : Nat
  /-- `select(verify, slack, 0)`, :720-726. -/
  checkedSlack : Nat

/-- The `FalconCore.CircuitWitness` projection: the nine wire groups
`FalconCore.CircuitSatisfied` speaks about. -/
def readWitness {e : FalconCore.HashEnvironment} (a : GadgetAssignment e) :
    FalconCore.CircuitWitness where
  pkG := a.pkG
  messageDigest := a.messageDigest
  salt := a.salt
  h := a.h
  s2 := a.s2
  s1 := a.s1
  centerBitsS1 := a.centerBitsS1
  centerBitsS2 := a.centerBitsS2
  verifyBit := a.verifyBit

/-- Big-endian u32 limb packing of a `Bytes32Target` (`U32LimbTrait::to_u32_vec`); the same
packing Layer A models as `digestOfLimbs`. -/
def packLimbs (limbs : List Nat) : Nat := limbs.foldl (fun acc x => acc * 4294967296 + x) 0

/-! ## 5. The program -/

/-- One builder call of `FalconSigVerifyTarget::build` (gadget.rs:651-736). -/
inductive GadgetOp where
  /-- `twiddle_tables()`, :655. Build-time assertions on the tables only; emits NO
  constraint, so its `holds` is `True`. The assertions themselves are the `decide`d pins
  `psi_half_order_is_minus_one`, `psi_order`, `psi_inverse_pinned` and `n_inv_pinned`. -/
  | twiddleTables
  /-- `Bytes32Target::new(builder, true)` for `pk_g`, :659. -/
  | allocPkG
  /-- `Bytes32Target::new(builder, true)` for `message_digest`, :660. -/
  | allocMessageDigest
  /-- `core::array::from_fn(add_virtual_target)`, :663. Allocation emits no gate; the
  `[Target; 8]` TYPE fixes the vector's length, which is all `holds` states. -/
  | witnessSalt
  /-- `(0..N).map(add_virtual_target)` for `h`, :664. Allocation only; `holds` states the
  length the `(0..N)` range fixes. -/
  | witnessH
  /-- the same for `s2`, :665. Allocation only. -/
  | witnessS2
  /-- the `h.iter().chain(s2.iter())` canonicity loop, :670-672. -/
  | canonicalCoeffs
  /-- `pk_digest_circuit(builder, &h)`, :675. -/
  | pkDigest
  /-- `pk_g.connect(builder, pk_computed)`, :676. -/
  | connectPkG
  /-- `h2p_circuit(builder, &salt, &message_digest)`, :679. -/
  | hashToPoint
  /-- `ntt_forward(builder, &psi_rev, &h)`, :684. -/
  | nttFwdH
  /-- `ntt_forward(builder, &psi_rev, &s2)`, :685. -/
  | nttFwdS2
  /-- `pointwise_mul(builder, &s2_ntt, &h_ntt)`, :686. -/
  | pointwiseMul
  /-- `ntt_inverse(builder, &psi_inv_rev, n_inv, &prod_ntt)`, :687. -/
  | nttInv
  /-- the `s1 = reduce_mod_q(c + q - prod, 1)` loop, :689-698. -/
  | s1Reduce
  /-- the `s1` half of the `s1.chain(s2)` `centered_square` loop, :702-706. -/
  | centeredSquaresS1
  /-- the `s2` half of the same loop, :702-706. -/
  | centeredSquaresS2
  /-- `add_many(&squares)`, :707. -/
  | normSum
  /-- `builder.constant(FALCON_SIG_L2_BOUND)`, :716-718. A constant wire constrains
  nothing, so its `holds` is `True`; the literal is `FalconCore.falconSigL2Bound`. -/
  | betaConstant
  /-- `builder.sub(beta_sq, norm)`, :719. -/
  | slackSub
  /-- `select(verify, slack, zero)`, :720-726. -/
  | selectVerify
  /-- `range_check(checked_slack, 26)`, :727. -/
  | slackRange
  /-- the returned `Self { .. }`, :729-735. A struct literal emits NO constraint, so its
  `holds` is `True`. -/
  | buildTarget
  deriving DecidableEq, Repr

/-- `ntt_forward` (:434-472) on one operand. The 9 stages of 256 butterflies perform 4608
`reduce_mod_q` calls with a 14-bit quotient (2304 on `t_add = u + s*b`, :456-457, and 2304
on `t_sub = u + q^2 - s*b`, :459-461); by `FalconCore.mod_q_decomposition_unique` each such
gate pins its remainder to `t % q` and its quotient to `t / q`, so the conjunction of the
4608 gate propositions is exactly the functional equation below together with the quotient
range checks. `ntt_quotient_range_covers_butterflies` shows a 14-bit quotient really covers
both inputs on canonical wires. -/
def NttForwardHolds (input output addQ subQ : List Nat) : Prop :=
  output = nttForward input ∧
    addQ.length = nttButterflies ∧ (∀ k ∈ addQ, k < 16384) ∧
    subQ.length = nttButterflies ∧ (∀ k ∈ subQ, k < 16384)

/-- What ONE builder call enforces on the assignment's wires.

A `range_check(t, bits)` bounds exactly its own wire; an `add_virtual_target` allocation and
a typed `[Target; 8]` array fix a vector's LENGTH but emit no gate; a `connect` equates two
wires; the two Poseidon gadget calls are the `HashEnvironment` callbacks applied to their
argument lists, so nothing beyond that is asserted; `twiddle_tables`, the `beta^2` constant
and the returned struct literal constrain no wire at all and are `True`. -/
def OpHolds (e : FalconCore.HashEnvironment) (op : GadgetOp) (a : GadgetAssignment e) : Prop :=
  match op with
  | .twiddleTables => True
  | .allocPkG =>
      a.pkGLimbs.length = 8 ∧ (∀ x ∈ a.pkGLimbs, x < 4294967296) ∧
        a.pkG = packLimbs a.pkGLimbs
  | .allocMessageDigest =>
      a.messageLimbs.length = 8 ∧ (∀ x ∈ a.messageLimbs, x < 4294967296) ∧
        a.messageDigest = packLimbs a.messageLimbs
  | .witnessSalt => a.salt.length = 8
  | .witnessH => a.h.length = falconN
  | .witnessS2 => a.s2.length = falconN
  | .canonicalCoeffs =>
      ∀ v ∈ a.h ++ a.s2, v < fieldModulus ∧ canonicalCoeffGates v
  | .pkDigest => a.pkComputed = falconPkDigest e a.h
  | .connectPkG => a.pkG = a.pkComputed
  | .hashToPoint =>
      (∀ s ∈ a.salt, s < 1099511627776) ∧
        a.c = e.hashToPoint a.salt a.messageDigest ∧
        a.c.length = falconN ∧ (∀ x ∈ a.c, x < falconQ) ∧
        a.h2pHi.length = falconN ∧ a.h2pLo.length = falconN ∧
        (∀ x ∈ a.h2pHi ++ a.h2pLo, x < 4294967296) ∧
        a.h2pQuotients.length = falconN ∧ (∀ k ∈ a.h2pQuotients, k < 4294967296)
  | .nttFwdH => NttForwardHolds a.h a.hNtt a.hFwdAddQuotients a.hFwdSubQuotients
  | .nttFwdS2 => NttForwardHolds a.s2 a.s2Ntt a.s2FwdAddQuotients a.s2FwdSubQuotients
  | .pointwiseMul =>
      a.prodNtt = pointwise a.s2Ntt a.hNtt ∧
        a.pointwiseQuotients.length = falconN ∧ (∀ k ∈ a.pointwiseQuotients, k < 16384)
  | .nttInv =>
      a.prod = nttInverse a.prodNtt ∧
        a.invAddQuotients.length = nttButterflies ∧ (∀ k ∈ a.invAddQuotients, k < 2) ∧
        a.invSubQuotients.length = nttButterflies ∧ (∀ k ∈ a.invSubQuotients, k < 32768) ∧
        a.invScaleQuotients.length = falconN ∧ (∀ k ∈ a.invScaleQuotients, k < 16384)
  | .s1Reduce =>
      a.s1 = List.zipWith subModQ a.c a.prod ∧ a.s1.length = falconN ∧
        a.s1Quotients.length = falconN ∧ (∀ k ∈ a.s1Quotients, k < 2)
  | .centeredSquaresS1 =>
      a.centerBitsS1.length = falconN ∧ (∀ b ∈ a.centerBitsS1, b < 2) ∧
        a.squaresS1 = List.zipWith circuitCenteredSquare a.s1 a.centerBitsS1
  | .centeredSquaresS2 =>
      a.centerBitsS2.length = falconN ∧ (∀ b ∈ a.centerBitsS2, b < 2) ∧
        a.squaresS2 = List.zipWith circuitCenteredSquare a.s2 a.centerBitsS2
  | .normSum => a.norm = natSum a.squaresS1 + natSum a.squaresS2
  | .betaConstant => True
  | .slackSub => a.slack = fieldSub falconSigL2Bound a.norm
  | .selectVerify =>
      a.verifyBit < 2 ∧ a.checkedSlack = (if a.verifyBit = 1 then a.slack else 0)
  | .slackRange => a.checkedSlack < 67108864
  | .buildTarget => True

def GadgetOp.holds {e : FalconCore.HashEnvironment} (op : GadgetOp) (a : GadgetAssignment e) :
    Prop :=
  OpHolds e op a

def ProgramSatisfied {e : FalconCore.HashEnvironment} (prog : List GadgetOp)
    (a : GadgetAssignment e) : Prop :=
  ∀ op ∈ prog, GadgetOp.holds op a

/-- `FalconSigVerifyTarget::build`, gadget.rs:651-736, in source order. -/
def gadgetProgram : List GadgetOp :=
  [.twiddleTables, .allocPkG, .allocMessageDigest, .witnessSalt, .witnessH, .witnessS2,
   .canonicalCoeffs, .pkDigest, .connectPkG, .hashToPoint, .nttFwdH, .nttFwdS2,
   .pointwiseMul, .nttInv, .s1Reduce, .centeredSquaresS1, .centeredSquaresS2, .normSum,
   .betaConstant, .slackSub, .selectVerify, .slackRange, .buildTarget]

theorem gadget_program_length : gadgetProgram.length = 23 := by decide

/-- The three builder calls that constrain no wire; their `OpHolds` is `True`. -/
theorem constraint_free_ops_are_trivial (e : FalconCore.HashEnvironment)
    (a : GadgetAssignment e) :
    OpHolds e .twiddleTables a ∧ OpHolds e .betaConstant a ∧ OpHolds e .buildTarget a :=
  ⟨trivial, trivial, trivial⟩

/-- `new` (:615-619) and `new_conditional` (:644-649) both run the identical `build`; they
differ only in the `select` of :720-726, which is the `selectVerify` op. With `new` the
wire is absent and `checked_slack = slack`, i.e. exactly the `verifyBit = 1` branch. -/
theorem select_verify_with_active_wire_is_the_unconditional_slack
    (e : FalconCore.HashEnvironment) (a : GadgetAssignment e)
    (hop : OpHolds e .selectVerify a) (hact : a.verifyBit = 1) : a.checkedSlack = a.slack := by
  rw [hop.2, if_pos hact]

/-! ## 6. The lowering theorem -/

theorem mem_zip_with_sub_mod_q_lt :
    ∀ (xs ys : List Nat) (v : Nat), v ∈ List.zipWith subModQ xs ys → v < falconQ := by
  intro xs
  induction xs with
  | nil =>
      intro ys v hv
      cases ys <;> exact absurd hv (List.not_mem_nil v)
  | cons x xs ih =>
      intro ys v hv
      cases ys with
      | nil => exact absurd hv (List.not_mem_nil v)
      | cons y ys =>
          rw [List.zipWith_cons_cons] at hv
          rcases List.mem_cons.mp hv with hh | hh
          · rw [hh]; exact sub_mod_q_lt x y
          · exact ih ys v hh

/-- THE lowering reduction: every field of `FalconCore.CircuitSatisfied` for the CONCRETE
`circuitProduct` follows from the local propositions of the individual builder calls, with
NO side hypothesis and no premise about the NTT. What the gate set as a whole used to assert
is now the conjunction of 23 per-primitive statements. -/
theorem gadget_program_satisfied_implies_circuit_satisfied (e : FalconCore.HashEnvironment)
    (a : GadgetAssignment e) (h : ProgramSatisfied gadgetProgram a) :
    FalconCore.CircuitSatisfied e circuitProduct (readWitness a) := by
  have hSalt : a.salt.length = 8 := h GadgetOp.witnessSalt (by decide)
  have hH : a.h.length = falconN := h GadgetOp.witnessH (by decide)
  have hS2 : a.s2.length = falconN := h GadgetOp.witnessS2 (by decide)
  have hCanon : ∀ v ∈ a.h ++ a.s2, v < fieldModulus ∧ canonicalCoeffGates v :=
    h GadgetOp.canonicalCoeffs (by decide)
  have hPk : a.pkComputed = falconPkDigest e a.h := h GadgetOp.pkDigest (by decide)
  have hConnect : a.pkG = a.pkComputed := h GadgetOp.connectPkG (by decide)
  have hH2P : (∀ s ∈ a.salt, s < 1099511627776) ∧
      a.c = e.hashToPoint a.salt a.messageDigest ∧
      a.c.length = falconN ∧ (∀ x ∈ a.c, x < falconQ) ∧
      a.h2pHi.length = falconN ∧ a.h2pLo.length = falconN ∧
      (∀ x ∈ a.h2pHi ++ a.h2pLo, x < 4294967296) ∧
      a.h2pQuotients.length = falconN ∧ (∀ k ∈ a.h2pQuotients, k < 4294967296) :=
    h GadgetOp.hashToPoint (by decide)
  have hFwdH : NttForwardHolds a.h a.hNtt a.hFwdAddQuotients a.hFwdSubQuotients :=
    h GadgetOp.nttFwdH (by decide)
  have hFwdS2 : NttForwardHolds a.s2 a.s2Ntt a.s2FwdAddQuotients a.s2FwdSubQuotients :=
    h GadgetOp.nttFwdS2 (by decide)
  have hPw : a.prodNtt = pointwise a.s2Ntt a.hNtt ∧
      a.pointwiseQuotients.length = falconN ∧ (∀ k ∈ a.pointwiseQuotients, k < 16384) :=
    h GadgetOp.pointwiseMul (by decide)
  have hInv : a.prod = nttInverse a.prodNtt ∧
      a.invAddQuotients.length = nttButterflies ∧ (∀ k ∈ a.invAddQuotients, k < 2) ∧
      a.invSubQuotients.length = nttButterflies ∧ (∀ k ∈ a.invSubQuotients, k < 32768) ∧
      a.invScaleQuotients.length = falconN ∧ (∀ k ∈ a.invScaleQuotients, k < 16384) :=
    h GadgetOp.nttInv (by decide)
  have hS1 : a.s1 = List.zipWith subModQ a.c a.prod ∧ a.s1.length = falconN ∧
      a.s1Quotients.length = falconN ∧ (∀ k ∈ a.s1Quotients, k < 2) :=
    h GadgetOp.s1Reduce (by decide)
  have hSq1 : a.centerBitsS1.length = falconN ∧ (∀ b ∈ a.centerBitsS1, b < 2) ∧
      a.squaresS1 = List.zipWith circuitCenteredSquare a.s1 a.centerBitsS1 :=
    h GadgetOp.centeredSquaresS1 (by decide)
  have hSq2 : a.centerBitsS2.length = falconN ∧ (∀ b ∈ a.centerBitsS2, b < 2) ∧
      a.squaresS2 = List.zipWith circuitCenteredSquare a.s2 a.centerBitsS2 :=
    h GadgetOp.centeredSquaresS2 (by decide)
  have hNormSum : a.norm = natSum a.squaresS1 + natSum a.squaresS2 :=
    h GadgetOp.normSum (by decide)
  have hSlackSub : a.slack = fieldSub falconSigL2Bound a.norm :=
    h GadgetOp.slackSub (by decide)
  have hSel : a.verifyBit < 2 ∧
      a.checkedSlack = (if a.verifyBit = 1 then a.slack else 0) :=
    h GadgetOp.selectVerify (by decide)
  have hRange : a.checkedSlack < 67108864 := h GadgetOp.slackRange (by decide)
  have hCanonH : ∀ c ∈ a.h, c < falconQ := by
    intro c hc
    have hm := hCanon c (List.mem_append_left _ hc)
    exact (canonical_coeff_gates_iff c hm.1).mp hm.2
  have hCanonS2 : ∀ c ∈ a.s2, c < falconQ := by
    intro c hc
    have hm := hCanon c (List.mem_append_right _ hc)
    exact (canonical_coeff_gates_iff c hm.1).mp hm.2
  have hProd : a.prod = circuitProduct.mul a.s2 a.h := by
    rw [hInv.1, hPw.1, hFwdH.1, hFwdS2.1, circuit_product_mul]
  have hEq : a.s1 =
      reconstructS1 circuitProduct (e.hashToPoint a.salt a.messageDigest) a.s2 a.h := by
    rw [hS1.1, hH2P.2.1, hProd]
    rfl
  have hNormEq : a.norm = circuitNorm (readWitness a) := by
    rw [hNormSum, hSq1.2.2, hSq2.2.2]
    rfl
  refine ⟨hSalt, hH2P.1, hH, hS2, hCanonH, hCanonS2, hConnect.trans hPk, ?_, hS1.2.1, ?_,
    hSq1.1, hSq2.1, hSq1.2.1, hSq2.2.1, hSel.1, ?_⟩
  · exact hEq
  · intro c hc
    have hc0 : c ∈ a.s1 := hc
    have hc' : c ∈ List.zipWith subModQ a.c a.prod := by rwa [hS1.1] at hc0
    exact mem_zip_with_sub_mod_q_lt a.c a.prod c hc'
  · rw [hSel.2, hSlackSub, hNormEq] at hRange
    exact hRange

/-- The obligation that remains after the reduction: the actual plonky2 constraint system
accepts only assignments satisfying every primitive of `gadgetProgram`. Strictly
per-primitive; never instantiated here. -/
def PrimitiveLowering (e : FalconCore.HashEnvironment)
    (actual : GadgetAssignment e → Prop) : Prop :=
  ∀ a, actual a → ProgramSatisfied gadgetProgram a

theorem primitive_lowering_implies_circuit_satisfied (e : FalconCore.HashEnvironment)
    (actual : GadgetAssignment e → Prop) (hl : PrimitiveLowering e actual)
    (a : GadgetAssignment e) (ha : actual a) :
    FalconCore.CircuitSatisfied e circuitProduct (readWitness a) :=
  gadget_program_satisfied_implies_circuit_satisfied e a (hl a ha)

/-- An active slot of a program-satisfying assignment meets the native norm bound — the
`FalconCore` headline, now reachable from the per-primitive propositions alone. -/
theorem gadget_program_active_slot_implies_native_norm_bound (e : FalconCore.HashEnvironment)
    (a : GadgetAssignment e) (h : ProgramSatisfied gadgetProgram a) (hact : a.verifyBit = 1) :
    normSquared a.s1 a.s2 ≤ falconSigL2Bound :=
  circuit_active_slot_implies_native_norm_bound e circuitProduct (readWitness a)
    (gadget_program_satisfied_implies_circuit_satisfied e a h) hact

/-! ## 7. Non-vacuity: the all-zero padding slot

`FalconSigGadgetWitness::padding` (:847) with the degenerate `FalconCore.zeroEnvironment`.
The transcribed NTT maps the zero polynomial to itself, which is proved below rather than
computed, so nothing here evaluates a 512-element list. -/

/-- Every wire of the working vector is 0. -/
def AllZero (a : Nat → Nat) : Prop := ∀ i, a i = 0

theorem foldl_invariant {α β : Type} (P : β → Prop) (f : β → α → β)
    (hf : ∀ (b : β) (x : α), P b → P (f b x)) :
    ∀ (l : List α) (b : β), P b → P (l.foldl f b) := by
  intro l
  induction l with
  | nil => intro b hb; exact hb
  | cons x _xs ih => intro b hb; exact ih (f b x) (hf b x hb)

theorem upd_all_zero {a : Nat → Nat} (ha : AllZero a) (j : Nat) : AllZero (upd a j 0) := by
  intro i
  simp only [upd]
  split
  · rfl
  · exact ha i

theorem ct_butterfly_all_zero (s t j : Nat) {a : Nat → Nat} (ha : AllZero a) :
    AllZero (ctButterfly s t j a) := by
  have h1 : (a j + s * a (j + t)) % falconQ = 0 := by
    rw [ha j, ha (j + t), Nat.mul_zero, Nat.zero_add, Nat.zero_mod]
  have h2 : (a j + falconQ * falconQ - s * a (j + t)) % falconQ = 0 := by
    rw [ha j, ha (j + t), Nat.mul_zero, Nat.zero_add, Nat.sub_zero]
    exact Nat.mul_mod_left falconQ falconQ
  show AllZero (upd (upd a j ((a j + s * a (j + t)) % falconQ)) (j + t)
    ((a j + falconQ * falconQ - s * a (j + t)) % falconQ))
  rw [h1, h2]
  exact upd_all_zero (upd_all_zero ha j) (j + t)

theorem gs_butterfly_all_zero (s t j : Nat) {a : Nat → Nat} (ha : AllZero a) :
    AllZero (gsButterfly s t j a) := by
  have h1 : (a j + a (j + t)) % falconQ = 0 := by
    rw [ha j, ha (j + t), Nat.zero_add, Nat.zero_mod]
  have h2 : (a j + falconQ - a (j + t)) * s % falconQ = 0 := by
    rw [ha j, ha (j + t), Nat.zero_add, Nat.sub_zero]
    exact Nat.mul_mod_right falconQ s
  show AllZero (upd (upd a j ((a j + a (j + t)) % falconQ)) (j + t)
    ((a j + falconQ - a (j + t)) * s % falconQ))
  rw [h1, h2]
  exact upd_all_zero (upd_all_zero ha j) (j + t)

theorem ct_stage_all_zero (m t : Nat) {a : Nat → Nat} (ha : AllZero a) :
    AllZero (ctStage m t a) := by
  refine foldl_invariant AllZero _ (fun b i hb => ?_) (rangeList m) a ha
  exact foldl_invariant AllZero _ (fun b' j hb' => ct_butterfly_all_zero _ _ _ hb')
    (rangeList t) b hb

theorem gs_stage_all_zero (hh t : Nat) {a : Nat → Nat} (ha : AllZero a) :
    AllZero (gsStage hh t a) := by
  refine foldl_invariant AllZero _ (fun b i hb => ?_) (rangeList hh) a ha
  exact foldl_invariant AllZero _ (fun b' j hb' => gs_butterfly_all_zero _ _ _ hb')
    (rangeList t) b hb

theorem ntt_forward_loop_all_zero :
    ∀ (fuel m t : Nat) {a : Nat → Nat}, AllZero a → AllZero (nttForwardLoop fuel m t a) := by
  intro fuel
  induction fuel with
  | zero => intro _ _ _ ha; exact ha
  | succ n ih =>
      intro m t a ha
      simp only [nttForwardLoop]
      split
      · exact ih _ _ (ct_stage_all_zero m (t / 2) ha)
      · exact ha

theorem ntt_inverse_loop_all_zero :
    ∀ (fuel m t : Nat) {a : Nat → Nat}, AllZero a → AllZero (nttInverseLoop fuel m t a) := by
  intro fuel
  induction fuel with
  | zero => intro _ _ _ ha; exact ha
  | succ n ih =>
      intro m t a ha
      simp only [nttInverseLoop]
      split
      · exact ih _ _ (gs_stage_all_zero (m / 2) t ha)
      · exact ha

theorem wire_of_replicate_zero : ∀ (n i : Nat), wireOf (List.replicate n 0) i = 0 := by
  intro n
  induction n with
  | zero => intro i; rfl
  | succ n ih =>
      intro i
      simp only [List.replicate_succ]
      cases i with
      | zero => rfl
      | succ i => exact ih i

theorem map_range_eq_replicate_zero (n : Nat) (f : Nat → Nat) (hf : ∀ i, f i = 0) :
    (rangeList n).map f = List.replicate n 0 := by
  have hall : ∀ l : List Nat, l.map f = List.replicate l.length 0 := by
    intro l
    induction l with
    | nil => rfl
    | cons x _xs ih =>
        simp only [List.map_cons, List.length_cons, List.replicate_succ, hf x, ih]
  rw [hall, range_list_length]

theorem ntt_forward_zero :
    nttForward (List.replicate falconN 0) = List.replicate falconN 0 := by
  have hz : AllZero (wireOf (List.replicate falconN 0)) := fun i => wire_of_replicate_zero _ i
  exact map_range_eq_replicate_zero _ _ (ntt_forward_loop_all_zero 10 1 falconN hz)

theorem pointwise_zero :
    pointwise (List.replicate falconN 0) (List.replicate falconN 0) =
      List.replicate falconN 0 := by
  refine map_range_eq_replicate_zero _ _ (fun i => ?_)
  rw [wire_of_replicate_zero, Nat.zero_mul, Nat.zero_mod]

theorem ntt_inverse_zero :
    nttInverse (List.replicate falconN 0) = List.replicate falconN 0 := by
  have hz : AllZero (wireOf (List.replicate falconN 0)) := fun i => wire_of_replicate_zero _ i
  have hloop := ntt_inverse_loop_all_zero 10 falconN 1 hz
  refine map_range_eq_replicate_zero _ _ (fun i => ?_)
  rw [hloop i, Nat.mul_zero, Nat.zero_mod]

/-- The transcribed NTT product of the zero polynomial with itself is the zero polynomial:
the honest padding slot really satisfies the algebraic equation. -/
theorem circuit_product_zero :
    circuitProduct.mul (List.replicate falconN 0) (List.replicate falconN 0) =
      List.replicate falconN 0 := by
  rw [circuit_product_mul, ntt_forward_zero, pointwise_zero, ntt_inverse_zero]

theorem zip_with_sub_mod_q_zero :
    List.zipWith subModQ (List.replicate falconN 0) (List.replicate falconN 0) =
      List.replicate falconN 0 := by
  rw [zip_with_replicate]
  have : subModQ 0 0 = 0 := by decide
  rw [this]

theorem zip_with_centered_square_zero :
    List.zipWith circuitCenteredSquare (List.replicate falconN 0) (List.replicate falconN 0) =
      List.replicate falconN 0 := by
  rw [zip_with_replicate]
  have : circuitCenteredSquare 0 0 = 0 := by decide
  rw [this]

/-- The all-zero padding assignment: `FalconCore.zeroWitness` extended with zero
intermediates and zero quotient wires. -/
def zeroAssignment (b : Nat) : GadgetAssignment FalconCore.zeroEnvironment where
  pkG := 0
  messageDigest := 0
  salt := List.replicate 8 0
  h := List.replicate falconN 0
  s2 := List.replicate falconN 0
  s1 := List.replicate falconN 0
  centerBitsS1 := List.replicate falconN 0
  centerBitsS2 := List.replicate falconN 0
  verifyBit := b
  pkGLimbs := List.replicate 8 0
  messageLimbs := List.replicate 8 0
  pkComputed := 0
  c := List.replicate falconN 0
  h2pHi := List.replicate falconN 0
  h2pLo := List.replicate falconN 0
  h2pQuotients := List.replicate falconN 0
  hNtt := List.replicate falconN 0
  hFwdAddQuotients := List.replicate nttButterflies 0
  hFwdSubQuotients := List.replicate nttButterflies 0
  s2Ntt := List.replicate falconN 0
  s2FwdAddQuotients := List.replicate nttButterflies 0
  s2FwdSubQuotients := List.replicate nttButterflies 0
  prodNtt := List.replicate falconN 0
  pointwiseQuotients := List.replicate falconN 0
  prod := List.replicate falconN 0
  invAddQuotients := List.replicate nttButterflies 0
  invSubQuotients := List.replicate nttButterflies 0
  invScaleQuotients := List.replicate falconN 0
  s1Quotients := List.replicate falconN 0
  squaresS1 := List.replicate falconN 0
  squaresS2 := List.replicate falconN 0
  norm := 0
  slack := fieldSub falconSigL2Bound 0
  checkedSlack := if b = 1 then fieldSub falconSigL2Bound 0 else 0

theorem zero_assignment_reads_back (b : Nat) :
    readWitness (zeroAssignment b) = FalconCore.zeroWitness b 0 := by
  have hpk : falconPkDigest FalconCore.zeroEnvironment (List.replicate falconN 0) = 0 := rfl
  simp only [readWitness, zeroAssignment, FalconCore.zeroWitness, hpk]

theorem zero_assignment_satisfies_every_op (b : Nat) (hb : b < 2) (op : GadgetOp) :
    OpHolds FalconCore.zeroEnvironment op (zeroAssignment b) := by
  have hrep : ∀ (n : Nat) (v : Nat), v ∈ List.replicate n 0 → v = 0 :=
    fun _ _ hv => List.eq_of_mem_replicate hv
  have hlimb : ∀ x ∈ List.replicate 8 0, x < 4294967296 := by
    intro x hx; rw [hrep 8 x hx]; decide
  cases op with
  | twiddleTables => exact trivial
  | allocPkG =>
      refine ⟨List.length_replicate 8 0, hlimb, ?_⟩
      show (0 : Nat) = packLimbs (List.replicate 8 0)
      decide
  | allocMessageDigest =>
      refine ⟨List.length_replicate 8 0, hlimb, ?_⟩
      show (0 : Nat) = packLimbs (List.replicate 8 0)
      decide
  | witnessSalt => exact List.length_replicate 8 0
  | witnessH => exact List.length_replicate _ 0
  | witnessS2 => exact List.length_replicate _ 0
  | canonicalCoeffs =>
      intro v hv
      have hv0 : v = 0 := by
        rcases List.mem_append.mp hv with hm | hm
        · exact hrep _ v hm
        · exact hrep _ v hm
      rw [hv0]
      exact ⟨by decide, ⟨by decide, by decide⟩⟩
  | pkDigest => exact rfl
  | connectPkG => exact rfl
  | hashToPoint =>
      refine ⟨?_, rfl, List.length_replicate _ 0, ?_, List.length_replicate _ 0,
        List.length_replicate _ 0, ?_, List.length_replicate _ 0, ?_⟩
      · intro s hs; rw [hrep 8 s hs]; decide
      · intro x hx; rw [hrep _ x hx]; decide
      · intro x hx
        rcases List.mem_append.mp hx with hm | hm
        · rw [hrep _ x hm]; decide
        · rw [hrep _ x hm]; decide
      · intro k hk; rw [hrep _ k hk]; decide
  | nttFwdH =>
      refine ⟨ntt_forward_zero.symm, List.length_replicate _ 0, ?_,
        List.length_replicate _ 0, ?_⟩
      · intro k hk; rw [hrep _ k hk]; decide
      · intro k hk; rw [hrep _ k hk]; decide
  | nttFwdS2 =>
      refine ⟨ntt_forward_zero.symm, List.length_replicate _ 0, ?_,
        List.length_replicate _ 0, ?_⟩
      · intro k hk; rw [hrep _ k hk]; decide
      · intro k hk; rw [hrep _ k hk]; decide
  | pointwiseMul =>
      refine ⟨pointwise_zero.symm, List.length_replicate _ 0, ?_⟩
      · intro k hk; rw [hrep _ k hk]; decide
  | nttInv =>
      refine ⟨ntt_inverse_zero.symm, List.length_replicate _ 0, ?_,
        List.length_replicate _ 0, ?_, List.length_replicate _ 0, ?_⟩
      · intro k hk; rw [hrep _ k hk]; decide
      · intro k hk; rw [hrep _ k hk]; decide
      · intro k hk; rw [hrep _ k hk]; decide
  | s1Reduce =>
      refine ⟨zip_with_sub_mod_q_zero.symm, List.length_replicate _ 0,
        List.length_replicate _ 0, ?_⟩
      · intro k hk; rw [hrep _ k hk]; decide
  | centeredSquaresS1 =>
      refine ⟨List.length_replicate _ 0, ?_, zip_with_centered_square_zero.symm⟩
      · intro x hx; rw [hrep _ x hx]; decide
  | centeredSquaresS2 =>
      refine ⟨List.length_replicate _ 0, ?_, zip_with_centered_square_zero.symm⟩
      · intro x hx; rw [hrep _ x hx]; decide
  | normSum =>
      show (0 : Nat) = natSum (List.replicate falconN 0) + natSum (List.replicate falconN 0)
      rw [nat_sum_replicate_zero]
  | betaConstant => exact trivial
  | slackSub => exact rfl
  | selectVerify => exact ⟨hb, rfl⟩
  | slackRange =>
      show (if b = 1 then fieldSub falconSigL2Bound 0 else 0) < 67108864
      split
      · decide
      · decide
  | buildTarget => exact trivial

/-- NON-VACUITY: the program is satisfiable, by the all-zero padding slot with either value
of the gate wire. -/
theorem example_zero_program_satisfied (b : Nat) (hb : b < 2) :
    ProgramSatisfied gadgetProgram (zeroAssignment b) :=
  fun op _ => zero_assignment_satisfies_every_op b hb op

/-- NON-VACUITY, spelled out: the padding slot's `CircuitSatisfied` for the CONCRETE product
follows from the program, with the gate wire active. -/
theorem example_zero_circuit_satisfied :
    FalconCore.CircuitSatisfied FalconCore.zeroEnvironment circuitProduct
      (readWitness (zeroAssignment 1)) :=
  gadget_program_satisfied_implies_circuit_satisfied FalconCore.zeroEnvironment
    (zeroAssignment 1) (example_zero_program_satisfied 1 (by decide))

end Zkp.Implementation.FalconGadgetProgram
