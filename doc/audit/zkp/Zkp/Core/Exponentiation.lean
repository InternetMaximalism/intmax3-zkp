import Zkp.Core.Field

/-
  Zkp.Core.Exponentiation
  =======================

  Semantics of Plonky2's `ExponentiationGate` (gate id 8) — the
  square-and-multiply ladder — and of the on-chain Solidity port of
  its constraint evaluator.

  Rust source of truth:
    * `contracts/lib/polygon-plonky2/plonky2/src/gates/exponentiation.rs:94-127`
      (`eval_unfiltered`), cross-checked against `:210-243`
      (`eval_unfiltered_base_packed`) and `:141-180`
      (`eval_unfiltered_circuit`).
    * Wire layout `:60-77`, `num_wires` `:190-192`,
      `num_constants() == 0` `:194-196`, `num_constraints` `:202-204`.

  On-chain port:
    * `contracts/lib/polygon-plonky2/mle/contracts/src/Plonky2GateEvaluator.sol:599-676`
      (`_evalExponentiation`), dispatched at `:198-204`.

  The Rust evaluator is written with a DIRECT INDEX into the
  intermediate-value wires:

      prev_i = if i = 0 then 1 else intermediate[i-1]^2          (:109-113)
      cur    = power_bits[n - i - 1]                             (:115-116)
      c_i    = prev_i * (cur*base + (1 - cur)) - intermediate[i] (:118-121)
      c_n    = output - intermediate[n-1]                        (:124)

  The Solidity port is written as a LOOP CARRYING A REGISTER `prev`
  that is re-assigned at the bottom of each iteration
  (`Plonky2GateEvaluator.sol:633`, `:665`). Register-carrying and
  indexed formulations are the classic place a hand port drifts, so
  the equality of the two is proved here rather than asserted:
  `solEval_eq_rust`.

  Three properties of this gate are subtle enough to be stated as
  named theorems:

    1. **LE wires, BE ladder.** The power-bit wires are indexed
       little-endian (`exponentiation.rs:64-68`) but consumed most
       significant first (`:115-116`). `output_pow` shows the ladder
       therefore computes `base ^ (Σ_j bit_j · 2^j)` — the LE value —
       so the index flip is exactly right.

    2. **`prev` squares the intermediate-value WIRE, not the value the
       previous constraint computed.** On a satisfying witness the two
       coincide (`sat_iv_eq_ivOf`); as evaluators on arbitrary wires
       they are DIFFERENT functions (`prev_variants_differ`). This is
       why differential testing of this gate must include
       *unsatisfying* vectors: satisfying ones cannot separate them.

    3. **No booleanity constraint on the power bits.** The gate does
       not constrain `power_bits[j] ∈ {0,1}` — and adding one would
       reject honest proofs, since the Rust prover's quotient
       polynomial does not contain it. `sat_for_any_bits` proves the
       constraint system is satisfiable for EVERY power-bit
       assignment, boolean or not. Booleanity is therefore a
       hypothesis imported from elsewhere in the circuit, and it
       appears as an explicit hypothesis `hb` of `output_pow` — never
       as an axiom. In the real circuit it is discharged by
       `plonky2/src/gadgets/arithmetic.rs:248-268` (`exp_from_bits`),
       which `connect`s every slot `0..num_power_bits` either to a
       caller `BoolTarget` or to `_false()`; the resulting booleanity
       lives in `BaseSumGate<2>` (`plonky2/src/gates/base_sum.rs:68-81`)
       / `ConstantGate` plus the copy-constraint (permutation)
       argument.

  Everything below is over the abstract `CField` of `Core/Field.lean`:
  no characteristic assumption, no field inverse, no prime-specific
  fact is used. Per the house rule at `Core/Field.lean:62-66`, the one
  non-algebraic input (booleanity of the bit wires) is a named
  hypothesis at its use site.
-/

namespace Zkp
namespace Exponentiation

open CField

variable {F : Type} [CField F]

/-! ## Field exponentiation -/

/-- `fpow x k = x^k`. `CField` has no `^`, so it is defined here by
    the same recursion the ladder unrolls. -/
def fpow (x : F) : Nat → F
  | 0 => 1
  | k + 1 => fpow x k * x

theorem fpow_add (x : F) (m : Nat) :
    ∀ k, fpow x (m + k) = fpow x m * fpow x k := by
  intro k
  induction k with
  | zero => simp [fpow]
  | succ k ih =>
      show fpow x (m + k) * x = fpow x m * (fpow x k * x)
      rw [ih, mulA]

/-! ## The constraint system, transcribed -/

/-- `cur_bit * base + (1 - cur_bit)` (`exponentiation.rs:118-119`;
    `Plonky2GateEvaluator.sol:647-651`). Note it is NOT a `select`:
    for a non-boolean `c` it is the affine interpolant, which is what
    makes the gate satisfiable at non-boolean bits. -/
def mulBy (base c : F) : F := c * base + (1 - c)

/-- The `prev_intermediate_value` of `exponentiation.rs:109-113`:
    `1` at `i = 0`, else the SQUARE OF THE WIRE `intermediate[i-1]`.
    In Solidity this is the loop-carried register initialised at
    `Plonky2GateEvaluator.sol:633` and updated at `:665`. -/
def prev (iv : Nat → F) : Nat → F
  | 0 => 1
  | i + 1 => iv i * iv i

/-- `computed_intermediate_value` (`exponentiation.rs:118-120`).
    `n - i - 1` is the LE→BE index flip of `:115-116`, mirrored at
    `Plonky2GateEvaluator.sol:644`. -/
def computed (base : F) (b iv : Nat → F) (n i : Nat) : F :=
  prev iv i * mulBy base (b (n - i - 1))

/-- What it means for a witness to satisfy the gate: every ladder
    constraint vanishes and the output constraint vanishes. -/
structure Sat (n : Nat) (base : F) (b iv : Nat → F) (output : F) : Prop where
  ladder : ∀ i, i < n → computed base b iv n i = iv i
  out : output = iv (n - 1)

/-- The Rust constraint vector: `n` ladder constraints followed by the
    output constraint (`exponentiation.rs:108-124`). -/
def rustC (base : F) (b iv : Nat → F) (n : Nat) (output : F) (i : Nat) : F :=
  if i < n then computed base b iv n i - iv i else output - iv (n - 1)

/-! ## The Solidity evaluator, transcribed as written

    `Plonky2GateEvaluator.sol:638-666` is a loop over `i` carrying the
    register `pr`; `:668-674` appends the output constraint. `acc` is
    the shared per-constraint accumulator, written with `+=`
    (`:660`, `:674`), matching `evaluate_gate_constraints`. -/

/-- `k` remaining iterations, current index `i`, carried register `pr`,
    accumulator `acc`. -/
def solLoop (base filter : F) (b iv : Nat → F) (n : Nat) :
    Nat → Nat → F → (Nat → F) → (Nat → F)
  | 0, _, _, acc => acc
  | k + 1, i, pr, acc =>
      solLoop base filter b iv n k (i + 1) (iv i * iv i)
        (fun t =>
          if t = i then acc t + filter * (pr * mulBy base (b (n - i - 1)) - iv i)
          else acc t)

/-- The whole of `_evalExponentiation`: the loop, then the output slot. -/
def solEval (base filter : F) (b iv : Nat → F) (n : Nat) (output : F)
    (acc : Nat → F) : Nat → F :=
  fun t =>
    if t = n then solLoop base filter b iv n n 0 1 acc t + filter * (output - iv (n - 1))
    else solLoop base filter b iv n n 0 1 acc t

/-- **Port correctness of the loop.** The register-carrying loop agrees
    with the indexed Rust spec at every slot it touches, and leaves
    every other slot untouched.

    The induction hypothesis is precisely the invariant the Solidity
    loop maintains: on entry to iteration `i` the register holds
    `prev iv i`. -/
theorem solLoop_eq (base filter : F) (b iv : Nat → F) (n : Nat) :
    ∀ k i (acc : Nat → F), i + k = n →
      solLoop base filter b iv n k i (prev iv i) acc =
        fun t => if i ≤ t ∧ t < n then acc t + filter * (computed base b iv n t - iv t)
                 else acc t := by
  intro k
  induction k with
  | zero =>
      intro i acc hik
      funext t
      have hno : ¬ (i ≤ t ∧ t < n) := by omega
      show acc t = _
      rw [if_neg hno]
  | succ k ih =>
      intro i acc hik
      have hin : i < n := by omega
      have hstep : (i + 1) + k = n := by omega
      have hpr : iv i * iv i = prev iv (i + 1) := rfl
      show solLoop base filter b iv n k (i + 1) (iv i * iv i) _ = _
      rw [hpr, ih (i + 1) _ hstep]
      funext t
      by_cases ht : t = i
      · subst ht
        have h1 : ¬ (t + 1 ≤ t ∧ t < n) := by omega
        have h2 : t ≤ t ∧ t < n := ⟨Nat.le_refl t, hin⟩
        show (if t + 1 ≤ t ∧ t < n then _ else _) = _
        rw [if_neg h1, if_pos h2, if_pos (rfl : t = t)]
        rfl
      · -- `i ≤ t ↔ i + 1 ≤ t` once `t ≠ i`. Proved from the core `Nat` lemmas
        -- rather than by `omega`: in this context `omega` discharges the goal
        -- via a classical case split, and the proof term would then depend on
        -- `Classical.choice`, which no other theorem in this development does.
        have h3a : i + 1 ≤ t ∧ t < n → i ≤ t ∧ t < n :=
          fun h => ⟨Nat.le_of_succ_le h.1, h.2⟩
        have h3b : i ≤ t ∧ t < n → i + 1 ≤ t ∧ t < n :=
          fun h => ⟨Nat.lt_of_le_of_ne h.1 (fun e => ht e.symm), h.2⟩
        by_cases h4 : i + 1 ≤ t ∧ t < n
        · show (if i + 1 ≤ t ∧ t < n then _ else _) = _
          rw [if_pos h4, if_pos (h3a h4), if_neg ht]
        · have h5 : ¬ (i ≤ t ∧ t < n) := fun h => h4 (h3b h)
          show (if i + 1 ≤ t ∧ t < n then _ else _) = _
          rw [if_neg h4, if_neg h5, if_neg ht]

/-- **The port is the Rust evaluator.** Starting from a zero
    accumulator, `_evalExponentiation` writes exactly
    `filter · rustC i` into slot `i` for `i ≤ n`, and nothing
    anywhere else. -/
theorem solEval_eq_rust (base filter : F) (b iv : Nat → F) (n : Nat)
    (output : F) (hn : 0 < n) :
    solEval base filter b iv n output (fun _ => 0) =
      fun t => if t ≤ n then filter * rustC base b iv n output t else 0 := by
  have h1 : prev iv 0 = (1 : F) := rfl
  have hloop := solLoop_eq base filter b iv n n 0 (fun _ => 0) (by omega)
  rw [h1] at hloop
  have hpt : ∀ t, solLoop base filter b iv n n 0 1 (fun _ => 0) t
      = if 0 ≤ t ∧ t < n then (0 : F) + filter * (computed base b iv n t - iv t)
        else (0 : F) := fun t => congrFun hloop t
  funext t
  show (if t = n then solLoop base filter b iv n n 0 1 (fun _ => 0) t
          + filter * (output - iv (n - 1))
        else solLoop base filter b iv n n 0 1 (fun _ => 0) t) = _
  rw [hpt t]
  by_cases ht : t = n
  · subst ht
    have hno : ¬ (0 ≤ t ∧ t < t) := by omega
    rw [if_pos (rfl : t = t), if_neg hno, if_pos (Nat.le_refl t)]
    show (0 : F) + filter * (output - iv (t - 1)) = filter * rustC base b iv t output t
    rw [CField.zero_add']
    show _ = filter * (if t < t then _ else output - iv (t - 1))
    rw [if_neg (Nat.lt_irrefl t)]
  · by_cases hlt : t < n
    · have h0 : 0 ≤ t ∧ t < n := ⟨Nat.zero_le t, hlt⟩
      rw [if_neg ht, if_pos h0, if_pos (Nat.le_of_lt hlt)]
      show (0 : F) + filter * (computed base b iv n t - iv t)
        = filter * rustC base b iv n output t
      rw [CField.zero_add']
      show _ = filter * (if t < n then computed base b iv n t - iv t else _)
      rw [if_pos hlt]
    · have hgt : ¬ (t ≤ n) := by omega
      have h0 : ¬ (0 ≤ t ∧ t < n) := by omega
      rw [if_neg ht, if_neg h0, if_neg hgt]

/-- `filter = 0` is a no-op, which is what the dispatcher relies on
    when it skips a de-selected row (`Plonky2GateEvaluator.sol:147-149`). -/
theorem solEval_filter_zero (base : F) (b iv : Nat → F) (n : Nat)
    (output : F) (acc : Nat → F) :
    solEval base 0 b iv n output acc = acc := by
  have h : ∀ k i (pr : F) (a : Nat → F),
      solLoop base (0 : F) b iv n k i pr a = a := by
    intro k
    induction k with
    | zero => intro i pr a; rfl
    | succ k ih =>
        intro i pr a
        show solLoop base (0 : F) b iv n k (i + 1) (iv i * iv i) _ = a
        rw [ih]
        funext t
        by_cases ht : t = i <;> simp [ht]
  funext t
  by_cases ht : t = n <;> simp [solEval, ht, h]

/-! ## What the gate does and does not constrain -/

/-- The unique ladder value determined by `base` and the power-bit
    wires. Note it does not mention `iv`: the intermediate-value wires
    are fully pinned by the constraints. -/
def ivOf (base : F) (b : Nat → F) (n : Nat) : Nat → F
  | 0 => mulBy base (b (n - 1))
  | i + 1 => (ivOf base b n i * ivOf base b n i) * mulBy base (b (n - (i + 1) - 1))

/-- **The gate imposes no booleanity on the power bits.** For ANY
    assignment `b` of the power-bit wires — boolean or not — the
    constraint system is satisfiable. Equivalently: a Solidity
    evaluator that added `b j · (b j - 1) = 0` would reject witnesses
    the Rust prover produces, i.e. break completeness.

    (This is the Lean form of the `SECURITY` note at
    `Plonky2GateEvaluator.sol:576-583`.) -/
theorem sat_for_any_bits (n : Nat) (base : F) (b : Nat → F) :
    ∃ iv output, Sat n base b iv output := by
  refine ⟨ivOf base b n, ivOf base b n (n - 1), ⟨?_, rfl⟩⟩
  intro i _
  cases i with
  | zero => show prev (ivOf base b n) 0 * _ = _; simp [prev, ivOf, one_mul']
  | succ i => rfl

/-- The intermediate-value wires of ANY satisfying witness are the
    ladder values — the prover has no freedom. -/
theorem sat_iv_eq_ivOf {n : Nat} {base : F} {b iv : Nat → F} {output : F}
    (h : Sat n base b iv output) :
    ∀ i, i < n → iv i = ivOf base b n i := by
  intro i
  induction i with
  | zero =>
      intro h0
      have := h.ladder 0 h0
      rw [← this]
      show prev iv 0 * _ = _
      simp [prev, ivOf, one_mul']
  | succ i ih =>
      intro hlt
      have hi : i < n := by omega
      have hstep := h.ladder (i + 1) hlt
      rw [← hstep]
      show prev iv (i + 1) * _ = _
      show iv i * iv i * _ = _
      rw [ih hi]
      rfl

/-- Hence the output is determined by `(base, power bits)` alone. -/
theorem sat_output_determined {n : Nat} {base : F} {b iv : Nat → F} {output : F}
    (hn : 0 < n) (h : Sat n base b iv output) :
    output = ivOf base b n (n - 1) := by
  rw [h.out]
  exact sat_iv_eq_ivOf h (n - 1) (by omega)

/-- **`prev` squares the WIRE, not the previously computed value.**
    The two readings agree on satisfying witnesses (`sat_iv_eq_ivOf`
    plus `Sat.ladder`), but they are different functions of the wires:
    here is a witness separating them. It is the reason the
    differential vectors for this gate must include UNSATISFYING
    assignments — a satisfying vector cannot distinguish the correct
    port from this mutation. -/
theorem prev_variants_differ :
    ∃ (n : Nat) (base : F) (b iv : Nat → F) (i : Nat),
      computed base b iv n i ≠ ivOf base b n i := by
  refine ⟨2, 0, (fun _ => 0), (fun _ => 0), 1, ?_⟩
  show prev (fun _ => (0 : F)) 1 * mulBy 0 ((fun _ => (0 : F)) (2 - 1 - 1)) ≠ _
  have hmul : mulBy (0 : F) (0 : F) = 1 := by
    show (0 : F) * 0 + (1 - 0) = 1
    simp
  show ((0 : F) * 0) * mulBy 0 0 ≠ (ivOf (0 : F) (fun _ => 0) 2 0 * ivOf 0 (fun _ => 0) 2 0) * mulBy 0 0
  show ((0 : F) * 0) * mulBy 0 0 ≠ (mulBy (0:F) 0 * mulBy (0:F) 0) * mulBy 0 0
  rw [hmul]
  simp
  exact fun h => CField.one_ne_zero h.symm

/-! ## Ladder semantics under an imported booleanity hypothesis -/

/-- Little-endian value of the bits `bn s, bn (s+1), …, bn (s+k-1)`:
    `Σ_{j<k} bn (s+j) · 2^j`. At `s = 0` this is exactly the value the
    LE-wired power bits denote (`exponentiation.rs:64-68`). -/
def leValFrom (bn : Nat → Nat) (s : Nat) : Nat → Nat
  | 0 => 0
  | k + 1 => leValFrom bn s k + bn (s + k) * 2 ^ k

/-- Peel the LEAST significant bit. This is the arithmetic identity the
    BE ladder step realises: one squaring doubles the exponent, and the
    selected bit adds `0` or `1`. -/
theorem leValFrom_shift (bn : Nat → Nat) (s : Nat) :
    ∀ k, leValFrom bn s (k + 1) = bn s + 2 * leValFrom bn (s + 1) k := by
  intro k
  induction k with
  | zero => simp [leValFrom]
  | succ k ih =>
      show leValFrom bn s (k + 1) + bn (s + (k + 1)) * 2 ^ (k + 1)
        = bn s + 2 * (leValFrom bn (s + 1) k + bn (s + 1 + k) * 2 ^ k)
      rw [ih]
      have hidx : s + (k + 1) = s + 1 + k := by omega
      rw [hidx, Nat.pow_succ]
      have hterm : bn (s + 1 + k) * (2 ^ k * 2) = 2 * (bn (s + 1 + k) * 2 ^ k) := by
        rw [Nat.mul_comm (2 ^ k) 2, ← Nat.mul_assoc, Nat.mul_comm (bn (s + 1 + k)) 2,
          Nat.mul_assoc]
      rw [hterm, Nat.mul_add]
      omega

/-- The ladder value is `base ^ (LE value of the top `i+1` bits)`.

    The index bookkeeping is stated as `i + j + 1 = n` rather than with
    `Nat` subtraction, so the LE→BE flip `n - i - 1 = j` is discharged
    by `omega` at every step instead of being assumed. -/
theorem ivOf_pow (n : Nat) (base : F) (bn : Nat → Bool) (b : Nat → F)
    (hb : ∀ j, j < n → b j = (if bn j then (1 : F) else 0)) :
    ∀ i j, i + j + 1 = n →
      ivOf base b n i = fpow base (leValFrom (fun t => if bn t then 1 else 0) j (i + 1)) := by
  intro i
  induction i with
  | zero =>
      intro j hij
      have hj : n - 1 = j := by omega
      have hjn : j < n := by omega
      show mulBy base (b (n - 1)) = _
      rw [hj, hb j hjn]
      cases hbn : bn j with
      | false =>
          show (0 : F) * base + (1 - 0) = _
          simp [leValFrom, fpow, hbn]
      | true =>
          show (1 : F) * base + (1 - 1) = _
          simp [leValFrom, fpow, hbn, one_mul']
  | succ i ih =>
      intro j hij
      have hj : n - (i + 1) - 1 = j := by omega
      have hjn : j < n := by omega
      have hIH := ih (j + 1) (by omega)
      show (ivOf base b n i * ivOf base b n i) * mulBy base (b (n - (i + 1) - 1)) = _
      rw [hj, hIH, hb j hjn,
        leValFrom_shift (fun t => if bn t then 1 else 0) j (i + 1)]
      cases _hbn : bn j with
      | false =>
          have hm : mulBy base (if (false : Bool) then (1 : F) else 0) = 1 := by
            show (0 : F) * base + (1 - 0) = 1
            simp
          rw [hm, mul_one']
          have h2 : (if (false : Bool) then 1 else 0)
              + 2 * leValFrom (fun t => if bn t then 1 else 0) (j + 1) (i + 1)
              = leValFrom (fun t => if bn t then 1 else 0) (j + 1) (i + 1)
                + leValFrom (fun t => if bn t then 1 else 0) (j + 1) (i + 1) := by
            simp; omega
          rw [h2, fpow_add]
      | true =>
          have hm : mulBy base (if (true : Bool) then (1 : F) else 0) = base := by
            show (1 : F) * base + (1 - 1) = base
            simp [one_mul']
          rw [hm]
          have h2 : (if (true : Bool) then 1 else 0)
              + 2 * leValFrom (fun t => if bn t then 1 else 0) (j + 1) (i + 1)
              = (leValFrom (fun t => if bn t then 1 else 0) (j + 1) (i + 1)
                + leValFrom (fun t => if bn t then 1 else 0) (j + 1) (i + 1)) + 1 := by
            simp; omega
          rw [h2, fpow_add, fpow_add]
          show _ = _ * _ * (fpow base 0 * base)
          rw [show fpow base 0 = (1 : F) from rfl, one_mul']

/-- **Gate soundness.** Any witness satisfying the `ExponentiationGate`
    constraints, whose power-bit wires are boolean, has
    `output = base ^ (Σ_j bit_j · 2^j)` with the bits read
    little-endian — i.e. the gate computes the exponentiation it
    claims to, and the LE→BE index flip at
    `exponentiation.rs:115-116` / `Plonky2GateEvaluator.sol:644` is
    the flip that makes that true.

    `hb` is the imported booleanity hypothesis. It is NOT discharged
    by this gate (`sat_for_any_bits`); in the circuit it comes from
    `BaseSumGate<2>` / `ConstantGate` plus the copy constraints that
    `exp_from_bits` emits (`plonky2/src/gadgets/arithmetic.rs:253-266`). -/
theorem output_pow {n : Nat} {base : F} {b iv : Nat → F} {output : F}
    (bn : Nat → Bool) (hn : 0 < n)
    (hb : ∀ j, j < n → b j = (if bn j then (1 : F) else 0))
    (h : Sat n base b iv output) :
    output = fpow base (leValFrom (fun t => if bn t then 1 else 0) 0 n) := by
  rw [sat_output_determined hn h]
  have := ivOf_pow n base bn b hb (n - 1) 0 (by omega)
  rw [this]
  have : n - 1 + 1 = n := by omega
  rw [this]

end Exponentiation
end Zkp
