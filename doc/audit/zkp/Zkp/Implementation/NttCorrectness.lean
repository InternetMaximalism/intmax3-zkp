import Zkp.Implementation.FalconGadgetProgram

/-!
# The transcribed in-circuit NTT computes the negacyclic product

This module discharges `FalconGadgetProgram.NttComputesNegacyclicProduct`: the concrete
Lean transcription of `ntt_forward` / `pointwise_mul` / `ntt_inverse`
(`src/falcon_sig/gadget.rs`:434-539) computes exactly the schoolbook negacyclic product of
`Z_q[X]/(X^512+1)` transcribed as `FalconGadgetProgram.negacyclicProduct`
(`schoolbook_negacyclic`, :999-1022), for q = 12289 and psi = 49.

Like every module under `Zkp.Implementation`, this is a statement about the HANDWRITTEN
MODEL in `FalconGadgetProgram`, not a refinement proof of the Rust source, of plonky2 gate
lowering, or of the vendored Falcon math.

## Structure of the proof

1. `EqQ` — congruence mod q on `Nat`, with `eq_q_iff` turning it into a linear equation
   `omega` can discharge, and `sumTo` — a plain `Nat` sum over `[0, n)` with the usual
   swap / split / single-support lemmas.
2. `pow_mod_q_eq` — the transcribed square-and-multiply `powModQ b e = b ^ e % q`, and
   `rev_of_pow_add` — the 9-bit reversal `bitReverse9` in closed recursive form.
3. `ct_stage_low` / `ct_stage_high` / `ct_stage_fixed` — the exact pointwise action of one
   Cooley-Tukey stage (and `gs_stage_*` for Gentleman-Sande), proved from the `foldl`
   encoding of the source's two nested `for` loops.
4. `ntt_forward_loop_spec` — the stage invariant: after the stage with `2^s` blocks the
   array holds, blockwise, the residues of the input polynomial modulo `X^(2^h) - psi^e`.
   Unwound at `s = 9` this is `ntt_forward_eval`: output index `j` carries the evaluation
   of the input at `psi^(2*bitReverse9 j + 1)`, the negacyclic evaluation points.
5. `eval_negacyclic_product` — evaluation at those points is a ring homomorphism out of
   `Z_q[X]/(X^512+1)`, hence `pointwise_is_forward_of_product`.
6. `ntt_inverse_forward` — the Gentleman-Sande loop inverts the Cooley-Tukey loop
   butterfly by butterfly (each matched stage pair scales by 2; the nine stages contribute
   the `512` that the final `n^-1` scaling of :500-508 cancels). Only
   `FalconGadgetProgram.psi_inverse_pinned` and `FalconGadgetProgram.n_inv_pinned` are
   used; primality of q is never assumed.
7. `ntt_computes_negacyclic_product` — the target proposition, unchanged.
-/

namespace Zkp.Implementation.NttCorrectness

open Zkp.Implementation.FalconCore
open Zkp.Implementation.FalconGadgetProgram

set_option maxRecDepth 8000

/-! ## 1. Congruence mod q -/

/-- Congruence modulo the Falcon prime, as an equality of remainders. -/
def EqQ (x y : Nat) : Prop := x % falconQ = y % falconQ

theorem falcon_q_pos : 0 < falconQ := by decide

theorem mod_q_lt (x : Nat) : x % falconQ < falconQ := Nat.mod_lt _ falcon_q_pos

theorem mod_q_mod_q (x : Nat) : x % falconQ % falconQ = x % falconQ :=
  Nat.mod_eq_of_lt (mod_q_lt x)

theorem eq_q_refl (x : Nat) : EqQ x x := rfl

theorem eq_q_symm {x y : Nat} (h : EqQ x y) : EqQ y x := h.symm

theorem eq_q_trans {x y z : Nat} (h1 : EqQ x y) (h2 : EqQ y z) : EqQ x z := h1.trans h2

/-- `EqQ` as a linear equation over `Nat`, the form `omega` can work with. -/
theorem eq_q_iff (x y : Nat) : EqQ x y ↔ ∃ k l : Nat, x + falconQ * k = y + falconQ * l := by
  constructor
  · intro h
    refine ⟨y / falconQ, x / falconQ, ?_⟩
    have hx : falconQ * (x / falconQ) + x % falconQ = x := Nat.div_add_mod x falconQ
    have hy : falconQ * (y / falconQ) + y % falconQ = y := Nat.div_add_mod y falconQ
    simp only [EqQ] at h
    omega
  · rintro ⟨k, l, h⟩
    have h1 : (x + falconQ * k) % falconQ = x % falconQ := Nat.add_mul_mod_self_left _ _ _
    have h2 : (y + falconQ * l) % falconQ = y % falconQ := Nat.add_mul_mod_self_left _ _ _
    simp only [EqQ]
    rw [← h1, ← h2, h]

theorem eq_q_mod (x : Nat) : EqQ (x % falconQ) x := mod_q_mod_q x

theorem eq_q_add {a b c d : Nat} (h1 : EqQ a b) (h2 : EqQ c d) : EqQ (a + c) (b + d) := by
  obtain ⟨k1, l1, e1⟩ := (eq_q_iff a b).1 h1
  obtain ⟨k2, l2, e2⟩ := (eq_q_iff c d).1 h2
  refine (eq_q_iff _ _).2 ⟨k1 + k2, l1 + l2, ?_⟩
  simp only [Nat.mul_add]
  omega

theorem eq_q_mul {a b c d : Nat} (h1 : EqQ a b) (h2 : EqQ c d) : EqQ (a * c) (b * d) := by
  simp only [EqQ] at *
  rw [Nat.mul_mod, h1, h2, ← Nat.mul_mod]

theorem eq_q_mul_left (c : Nat) {a b : Nat} (h : EqQ a b) : EqQ (c * a) (c * b) :=
  eq_q_mul (eq_q_refl c) h

theorem eq_q_pow {a b : Nat} (h : EqQ a b) (n : Nat) : EqQ (a ^ n) (b ^ n) := by
  induction n with
  | zero => exact eq_q_refl 1
  | succ n ih =>
      simp only [Nat.pow_succ]
      exact eq_q_mul ih h

/-- Cancelling a common summand in a congruence. -/
theorem eq_q_cancel {a b c : Nat} (h : EqQ (a + c) (b + c)) : EqQ a b := by
  obtain ⟨k, l, e⟩ := (eq_q_iff _ _).1 h
  exact (eq_q_iff _ _).2 ⟨k, l, by omega⟩

/-- The source's `u + q^2 - v` shift: any multiple of q large enough to keep the
subtraction exact represents the same residue. -/
theorem sub_offset_mod (x y u v : Nat) (hu : y ≤ falconQ * u) (hv : y ≤ falconQ * v) :
    EqQ (x + falconQ * u - y) (x + falconQ * v - y) := by
  refine (eq_q_iff _ _).2 ⟨v, u, ?_⟩
  omega

/-- `x + q - y` is `x - y` as a residue, whenever `y < q`. -/
theorem eq_q_sub_add (x y z : Nat) (hy : y < falconQ) (h : EqQ (y + z) x) :
    EqQ (x + falconQ - y) z := by
  obtain ⟨k, l, e⟩ := (eq_q_iff _ _).1 h
  refine (eq_q_iff _ _).2 ⟨l, k + 1, ?_⟩
  simp only [Nat.mul_add, Nat.mul_one]
  omega

/-- Multiplication distributes over truncated subtraction. -/
theorem nat_mul_sub (k m n : Nat) : k * (m - n) = k * m - k * n := by
  rcases Nat.le_total n m with h | h
  · have h2 : k * (m - n) + k * n = k * m := by
      rw [← Nat.left_distrib, Nat.sub_add_cancel h]
    rw [← h2, Nat.add_sub_cancel]
  · rw [Nat.sub_eq_zero_of_le h, Nat.mul_zero, Nat.sub_eq_zero_of_le (Nat.mul_le_mul_left k h)]

/-! ## 2. Finite sums over `[0, n)` -/

/-- `f 0 + f 1 + ... + f (n-1)`. -/
def sumTo (f : Nat → Nat) : Nat → Nat
  | 0 => 0
  | n + 1 => sumTo f n + f n

theorem sum_to_zero (f : Nat → Nat) : sumTo f 0 = 0 := rfl

theorem sum_to_succ (f : Nat → Nat) (n : Nat) : sumTo f (n + 1) = sumTo f n + f n := rfl

theorem sum_to_congr {f g : Nat → Nat} {n : Nat} (h : ∀ i, i < n → f i = g i) :
    sumTo f n = sumTo g n := by
  induction n with
  | zero => rfl
  | succ n ih =>
      rw [sum_to_succ, sum_to_succ, ih (fun i hi => h i (Nat.lt_succ_of_lt hi)),
        h n (Nat.lt_succ_self n)]

theorem sum_to_eq_q_congr {f g : Nat → Nat} {n : Nat} (h : ∀ i, i < n → EqQ (f i) (g i)) :
    EqQ (sumTo f n) (sumTo g n) := by
  induction n with
  | zero => exact eq_q_refl 0
  | succ n ih =>
      rw [sum_to_succ, sum_to_succ]
      exact eq_q_add (ih (fun i hi => h i (Nat.lt_succ_of_lt hi))) (h n (Nat.lt_succ_self n))

theorem sum_to_zero_fun {f : Nat → Nat} {n : Nat} (h : ∀ i, i < n → f i = 0) :
    sumTo f n = 0 := by
  induction n with
  | zero => rfl
  | succ n ih =>
      rw [sum_to_succ, ih (fun i hi => h i (Nat.lt_succ_of_lt hi)), h n (Nat.lt_succ_self n)]

theorem sum_to_add (f g : Nat → Nat) (n : Nat) :
    sumTo (fun i => f i + g i) n = sumTo f n + sumTo g n := by
  induction n with
  | zero => rfl
  | succ n ih => simp only [sum_to_succ, ih]; omega

theorem sum_to_mul_left (c : Nat) (f : Nat → Nat) (n : Nat) :
    sumTo (fun i => c * f i) n = c * sumTo f n := by
  induction n with
  | zero => simp [sumTo]
  | succ n ih => simp only [sum_to_succ, ih, Nat.left_distrib]

theorem sum_to_mul_right (c : Nat) (f : Nat → Nat) (n : Nat) :
    sumTo (fun i => f i * c) n = sumTo f n * c := by
  induction n with
  | zero => simp [sumTo]
  | succ n ih => simp only [sum_to_succ, ih, Nat.right_distrib]

theorem sum_to_split (f : Nat → Nat) (m n : Nat) :
    sumTo f (m + n) = sumTo f m + sumTo (fun i => f (m + i)) n := by
  induction n with
  | zero => simp [sumTo]
  | succ n ih =>
      have : m + (n + 1) = (m + n) + 1 := by omega
      rw [this, sum_to_succ, ih, sum_to_succ]
      omega

theorem sum_to_swap (f : Nat → Nat → Nat) (m n : Nat) :
    sumTo (fun i => sumTo (fun j => f i j) n) m
      = sumTo (fun j => sumTo (fun i => f i j) m) n := by
  induction m with
  | zero => exact (sum_to_zero_fun (fun _ _ => rfl)).symm
  | succ m ih =>
      rw [sum_to_succ, ih, ← sum_to_add]
      exact sum_to_congr (fun j _ => (sum_to_succ (fun i => f i j) m))

/-- A sum whose summand vanishes away from one index collapses to that index. -/
theorem sum_to_single {f : Nat → Nat} {n k : Nat} (hk : k < n)
    (h : ∀ i, i < n → i ≠ k → f i = 0) : sumTo f n = f k := by
  induction n with
  | zero => exact absurd hk (Nat.not_lt_zero k)
  | succ n ih =>
      rcases Nat.lt_or_ge k n with hkn | hkn
      · rw [sum_to_succ, h n (Nat.lt_succ_self n) (by omega),
          ih hkn (fun i hi hne => h i (Nat.lt_succ_of_lt hi) hne), Nat.add_zero]
      · have hkn' : k = n := by omega
        subst hkn'
        rw [sum_to_succ, sum_to_zero_fun (fun i hi => h i (Nat.lt_succ_of_lt hi) (by omega))]
        omega

/-! ## 3. The transcribed `pow_mod_q` and `bit_reverse_9` -/

/-- `c ^ e mod q`, the value `powModQ` computes. -/
def powQ (c e : Nat) : Nat := c ^ e % falconQ

theorem pow_q_lt (c e : Nat) : powQ c e < falconQ := mod_q_lt _

theorem pow_q_eq_q (c e : Nat) : EqQ (powQ c e) (c ^ e) := eq_q_mod _

theorem pow_q_zero (c : Nat) : powQ c 0 = 1 := by
  simp only [powQ, Nat.pow_zero]
  rfl

theorem pow_mod_q_aux_eq : ∀ fuel base exp acc : Nat, exp < 2 ^ fuel → base < falconQ →
    acc < falconQ → powModQAux fuel base exp acc = acc * base ^ exp % falconQ := by
  intro fuel
  induction fuel with
  | zero =>
      intro base exp acc hf _ ha
      have he : exp = 0 := by simp only [Nat.pow_zero] at hf; omega
      subst he
      show acc = acc * base ^ 0 % falconQ
      rw [Nat.pow_zero, Nat.mul_one, Nat.mod_eq_of_lt ha]
  | succ fuel ih =>
      intro base exp acc hf hb ha
      by_cases he : exp = 0
      · subst he
        have hz : powModQAux (fuel + 1) base 0 acc = acc := by simp [powModQAux]
        rw [hz, Nat.pow_zero, Nat.mul_one, Nat.mod_eq_of_lt ha]
      · have hhalf : exp / 2 < 2 ^ fuel := by
          have : (2 : Nat) ^ (fuel + 1) = 2 ^ fuel * 2 := by rw [Nat.pow_succ]
          omega
        have hb2 : base * base % falconQ < falconQ := mod_q_lt _
        have ha2 : (if exp % 2 = 1 then acc * base % falconQ else acc) < falconQ := by
          split
          · exact mod_q_lt _
          · exact ha
        simp only [powModQAux, if_neg he]
        rw [ih _ _ _ hhalf hb2 ha2]
        -- `(base*base % q) ^ (exp/2)` is `base ^ (2 * (exp/2))` as a residue
        have hsplit : exp % 2 + 2 * (exp / 2) = exp := by omega
        have hbb : EqQ ((base * base % falconQ) ^ (exp / 2)) ((base * base) ^ (exp / 2)) :=
          eq_q_pow (eq_q_mod (base * base)) (exp / 2)
        have hacc : EqQ (if exp % 2 = 1 then acc * base % falconQ else acc)
            (acc * base ^ (exp % 2)) := by
          split
          · rename_i h1
            rw [h1, Nat.pow_one]
            exact eq_q_mod _
          · rename_i h1
            have h2 : exp % 2 = 0 := by omega
            rw [h2, Nat.pow_zero, Nat.mul_one]
            exact eq_q_refl acc
        have hmul : EqQ ((if exp % 2 = 1 then acc * base % falconQ else acc)
            * (base * base % falconQ) ^ (exp / 2))
            (acc * base ^ (exp % 2) * (base * base) ^ (exp / 2)) := eq_q_mul hacc hbb
        have hsq : base ^ 2 = base * base := by rw [Nat.pow_succ, Nat.pow_one]
        have hpp : (base * base) ^ (exp / 2) = base ^ (2 * (exp / 2)) := by
          rw [← hsq, ← Nat.pow_mul]
        have hfin : acc * base ^ (exp % 2) * (base * base) ^ (exp / 2) = acc * base ^ exp := by
          rw [hpp, Nat.mul_assoc, ← Nat.pow_add, hsplit]
        rw [hfin] at hmul
        exact hmul

theorem pow_mod_q_eq (base exp : Nat) (h : exp < 2 ^ 64) : powModQ base exp = powQ base exp := by
  have := pow_mod_q_aux_eq 64 (base % falconQ) exp 1 h (mod_q_lt _) (by decide)
  simp only [powModQ, powQ]
  rw [this, Nat.one_mul]
  exact eq_q_pow (eq_q_mod base) exp

/-- `bit_reverse_9` with an explicit bit budget: the reversal of the low `f` bits. -/
def revOf (f x : Nat) : Nat := bitReverse9Aux f x 0

theorem bit_reverse_aux_acc : ∀ f x r : Nat, bitReverse9Aux f x r = r * 2 ^ f + revOf f x := by
  intro f
  induction f with
  | zero => intro x r; simp [bitReverse9Aux, revOf]
  | succ f ih =>
      intro x r
      have e1 : bitReverse9Aux (f + 1) x r = (r * 2 + x % 2) * 2 ^ f + revOf f (x / 2) := by
        show bitReverse9Aux f (x / 2) (r * 2 + x % 2) = _
        exact ih (x / 2) (r * 2 + x % 2)
      have e2 : revOf (f + 1) x = (0 * 2 + x % 2) * 2 ^ f + revOf f (x / 2) := by
        show bitReverse9Aux f (x / 2) (0 * 2 + x % 2) = _
        exact ih (x / 2) (0 * 2 + x % 2)
      have e3 : r * 2 * 2 ^ f = r * (2 ^ f * 2) := by
        simp only [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm]
      rw [e1, e2, Nat.pow_succ, Nat.right_distrib]
      simp only [Nat.zero_mul, Nat.zero_add]
      omega

theorem rev_of_succ (f x : Nat) : revOf (f + 1) x = (x % 2) * 2 ^ f + revOf f (x / 2) := by
  show bitReverse9Aux f (x / 2) (0 * 2 + x % 2) = _
  rw [bit_reverse_aux_acc]
  simp only [Nat.zero_mul, Nat.zero_add]

theorem rev_of_zero_arg (f : Nat) : revOf f 0 = 0 := by
  induction f with
  | zero => rfl
  | succ f ih => rw [rev_of_succ]; simp [ih]

theorem rev_of_lt (f x : Nat) : revOf f x < 2 ^ f := by
  induction f generalizing x with
  | zero => simp only [revOf, bitReverse9Aux]; decide
  | succ f ih =>
      rw [rev_of_succ, Nat.pow_succ]
      have h1 := ih (x / 2)
      have h2 : x % 2 ≤ 1 := by omega
      have h3 : (x % 2) * 2 ^ f ≤ 1 * 2 ^ f := Nat.mul_le_mul_right _ h2
      omega

theorem bit_reverse_9_eq (x : Nat) : bitReverse9 x = revOf 9 x := rfl

theorem rev_of_double (s i : Nat) : revOf (s + 1) (2 * i) = revOf s i := by
  rw [rev_of_succ]
  have h1 : 2 * i % 2 = 0 := by omega
  have h2 : 2 * i / 2 = i := by omega
  rw [h1, h2]
  simp

theorem rev_of_double_succ (s i : Nat) : revOf (s + 1) (2 * i + 1) = 2 ^ s + revOf s i := by
  rw [rev_of_succ]
  have h1 : (2 * i + 1) % 2 = 1 := by omega
  have h2 : (2 * i + 1) / 2 = i := by omega
  rw [h1, h2, Nat.one_mul]

/-- The twiddle-index identity the stage invariant runs on: reversing `2^s + i` in `s+g+1`
bits splits off the leading bit and reverses `i` in `s` bits. -/
theorem rev_of_pow_add : ∀ s g i : Nat, i < 2 ^ s →
    revOf (s + g + 1) (2 ^ s + i) = 2 ^ g + 2 ^ (g + 1) * revOf s i := by
  intro s
  induction s with
  | zero =>
      intro g i hi
      have hi0 : i = 0 := by simp only [Nat.pow_zero] at hi; omega
      subst hi0
      rw [rev_of_succ]
      simp [rev_of_zero_arg]
  | succ s ih =>
      intro g i hi
      have hpow : (2 : Nat) ^ (s + 1) = 2 ^ s * 2 := Nat.pow_succ 2 s
      have hi2 : i / 2 < 2 ^ s := by omega
      have hmod : (2 ^ (s + 1) + i) % 2 = i % 2 := by
        rw [hpow, Nat.add_comm, Nat.add_mul_mod_self_right]
      have hdiv : (2 ^ (s + 1) + i) / 2 = 2 ^ s + i / 2 := by
        rw [hpow, Nat.add_comm, Nat.add_mul_div_right _ _ (by decide : 0 < 2)]
        omega
      have hstep : s + 1 + g + 1 = (s + g + 1) + 1 := by omega
      rw [hstep, rev_of_succ, hmod, hdiv, ih g (i / 2) hi2, rev_of_succ]
      have hpa : (2 : Nat) ^ (s + g + 1) = 2 ^ (g + 1) * 2 ^ s := by
        rw [← Nat.pow_add]
        congr 1
        omega
      rw [hpa, Nat.left_distrib]
      have : 2 ^ (g + 1) * ((i % 2) * 2 ^ s) = (i % 2) * (2 ^ (g + 1) * 2 ^ s) := by
        simp only [Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc]
      omega

/-! ## 4. `rangeList`, `wireOf` and the `foldl` encoding of the source's `for` loops -/

theorem range_list_zero : rangeList 0 = [] := rfl

theorem range_list_succ (n : Nat) : rangeList (n + 1) = rangeList n ++ [n] := rfl

theorem range_list_foldl_succ {α : Type} (f : α → Nat → α) (init : α) (n : Nat) :
    (rangeList (n + 1)).foldl f init = f ((rangeList n).foldl f init) n := by
  show (rangeList n ++ [n]).foldl f init = _
  rw [List.foldl_append]
  rfl

theorem mem_range_list (n j : Nat) : j ∈ rangeList n ↔ j < n := by
  induction n with
  | zero => simp [rangeList]
  | succ n ih =>
      rw [range_list_succ, List.mem_append]
      simp only [List.mem_singleton, ih]
      omega

theorem map_range_list_congr {f g : Nat → Nat} {n : Nat} (h : ∀ j, j < n → f j = g j) :
    (rangeList n).map f = (rangeList n).map g := by
  induction n with
  | zero => rfl
  | succ n ih =>
      rw [range_list_succ, List.map_append, List.map_append,
        ih (fun j hj => h j (Nat.lt_succ_of_lt hj))]
      simp only [List.map_cons, List.map_nil, h n (Nat.lt_succ_self n)]

theorem wire_of_append (l l' : List Nat) : ∀ j, j < l.length → wireOf (l ++ l') j = wireOf l j := by
  induction l with
  | nil => intro j hj; exact absurd hj (Nat.not_lt_zero j)
  | cons x xs ih =>
      intro j hj
      cases j with
      | zero => rfl
      | succ j =>
          simp only [List.length_cons] at hj
          exact ih j (by omega)

theorem wire_of_append_len (l : List Nat) (x : Nat) : wireOf (l ++ [x]) l.length = x := by
  induction l with
  | nil => rfl
  | cons y ys ih => exact ih

theorem wire_of_map_range (f : Nat → Nat) : ∀ n j : Nat, j < n →
    wireOf ((rangeList n).map f) j = f j := by
  intro n
  induction n with
  | zero => intro j hj; exact absurd hj (Nat.not_lt_zero j)
  | succ n ih =>
      intro j hj
      rw [range_list_succ, List.map_append]
      rcases Nat.lt_or_ge j n with hjn | hjn
      · rw [wire_of_append _ _ j (by simpa [range_list_length] using hjn)]
        exact ih j hjn
      · have hj' : j = n := by omega
        subst hj'
        have hlen : ((rangeList j).map f).length = j := by
          simp only [List.length_map, range_list_length]
        have hw := wire_of_append_len ((rangeList j).map f) (f j)
        rw [hlen] at hw
        simp only [List.map_cons, List.map_nil]
        exact hw

theorem wire_of_lt_q (l : List Nat) (h : ∀ c ∈ l, c < falconQ) : ∀ i, wireOf l i < falconQ := by
  induction l with
  | nil => intro i; cases i <;> exact falcon_q_pos
  | cons x xs ih =>
      intro i
      cases i with
      | zero => exact h x (by simp)
      | succ i => exact ih (fun c hc => h c (by simp [hc])) i

theorem wire_of_length (l : List Nat) : ∀ i, l.length ≤ i → wireOf l i = 0 := by
  induction l with
  | nil => intro i _; cases i <;> rfl
  | cons x xs ih =>
      intro i hi
      cases i with
      | zero => exact absurd hi (by simp)
      | succ i => exact ih i (by simpa using hi)

-- From here on the 512-element list is never expanded.
attribute [local irreducible] rangeList

/-! ## 5. One butterfly stage, pointwise

Both transforms run the same two nested `for` loops: an inner loop of `t` butterflies over a
block and an outer loop of `m` blocks of width `2t`. The two lemmas below are proved once,
for an arbitrary butterfly that touches only `j` and `j+t`. -/

/-- The inner `for j in j1..j1+t` loop, cut off after `k` butterflies. -/
def innerK (t : Nat) (bf : Nat → (Nat → Nat) → (Nat → Nat)) (j1 k : Nat) (a : Nat → Nat) :
    Nat → Nat :=
  (rangeList k).foldl (fun acc j => bf (j1 + j) acc) a

/-- The outer `for i in 0..m` loop, cut off after `k` blocks. -/
def stageK (blk : Nat → (Nat → Nat) → (Nat → Nat)) (k : Nat) (a : Nat → Nat) : Nat → Nat :=
  (rangeList k).foldl (fun acc i => blk i acc) a

theorem inner_k_succ (t : Nat) (bf : Nat → (Nat → Nat) → (Nat → Nat)) (j1 k : Nat)
    (a : Nat → Nat) : innerK t bf j1 (k + 1) a = bf (j1 + k) (innerK t bf j1 k a) :=
  range_list_foldl_succ _ _ _

theorem stage_k_succ (blk : Nat → (Nat → Nat) → (Nat → Nat)) (k : Nat) (a : Nat → Nat) :
    stageK blk (k + 1) a = blk k (stageK blk k a) :=
  range_list_foldl_succ _ _ _

theorem inner_k_spec (t j1 : Nat) (bf : Nat → (Nat → Nat) → (Nat → Nat))
    (hfix : ∀ j b i, i ≠ j → i ≠ j + t → bf j b i = b i)
    (hdep : ∀ j b c, b j = c j → b (j + t) = c (j + t) →
        bf j b j = bf j c j ∧ bf j b (j + t) = bf j c (j + t))
    (a : Nat → Nat) : ∀ k, k ≤ t →
      (∀ j, j < k → innerK t bf j1 k a (j1 + j) = bf (j1 + j) a (j1 + j)) ∧
      (∀ j, j < k → innerK t bf j1 k a (j1 + j + t) = bf (j1 + j) a (j1 + j + t)) ∧
      (∀ i, (∀ j, j < k → i ≠ j1 + j ∧ i ≠ j1 + j + t) → innerK t bf j1 k a i = a i) := by
  intro k
  induction k with
  | zero =>
      intro _
      refine ⟨fun j hj => absurd hj (Nat.not_lt_zero j), fun j hj => absurd hj (Nat.not_lt_zero j),
        fun i _ => by simp only [innerK, range_list_zero, List.foldl_nil]⟩
  | succ k ih =>
      intro hk
      obtain ⟨ih1, ih2, ih3⟩ := ih (by omega)
      have hb1 : innerK t bf j1 k a (j1 + k) = a (j1 + k) :=
        ih3 _ (fun j hj => ⟨by omega, by omega⟩)
      have hb2 : innerK t bf j1 k a (j1 + k + t) = a (j1 + k + t) :=
        ih3 _ (fun j hj => ⟨by omega, by omega⟩)
      obtain ⟨hd1, hd2⟩ := hdep (j1 + k) (innerK t bf j1 k a) a hb1 hb2
      refine ⟨?_, ?_, ?_⟩
      · intro j hj
        rw [inner_k_succ]
        rcases Nat.lt_or_ge j k with hjk | hjk
        · rw [hfix _ _ _ (by omega) (by omega)]
          exact ih1 j hjk
        · have : j = k := by omega
          subst this
          exact hd1
      · intro j hj
        rw [inner_k_succ]
        rcases Nat.lt_or_ge j k with hjk | hjk
        · rw [hfix _ _ _ (by omega) (by omega)]
          exact ih2 j hjk
        · have : j = k := by omega
          subst this
          exact hd2
      · intro i hi
        rw [inner_k_succ, hfix _ _ _ (hi k (Nat.lt_succ_self k)).1 (hi k (Nat.lt_succ_self k)).2]
        exact ih3 i (fun j hj => hi j (Nat.lt_succ_of_lt hj))

theorem two_block_mono (i k t : Nat) (h : i + 1 ≤ k) : 2 * i * t + 2 * t ≤ 2 * k * t := by
  have h1 : 2 * (i + 1) ≤ 2 * k := by omega
  have h2 : 2 * (i + 1) * t ≤ 2 * k * t := Nat.mul_le_mul_right t h1
  have h3 : 2 * (i + 1) * t = 2 * i * t + 2 * t := by
    have : 2 * (i + 1) = 2 * i + 2 := by omega
    rw [this, Nat.right_distrib]
  omega

theorem two_block_succ (k t : Nat) : 2 * (k + 1) * t = 2 * k * t + 2 * t := by
  have : 2 * (k + 1) = 2 * k + 2 := by omega
  rw [this, Nat.right_distrib]

theorem stage_k_spec (t : Nat) (blk : Nat → (Nat → Nat) → (Nat → Nat))
    (hfix : ∀ i b x, (x < 2 * i * t ∨ 2 * i * t + 2 * t ≤ x) → blk i b x = b x)
    (hdep : ∀ i b c, (∀ y, 2 * i * t ≤ y → y < 2 * i * t + 2 * t → b y = c y) →
        ∀ x, 2 * i * t ≤ x → x < 2 * i * t + 2 * t → blk i b x = blk i c x)
    (a : Nat → Nat) : ∀ k,
      (∀ i x, i < k → 2 * i * t ≤ x → x < 2 * i * t + 2 * t → stageK blk k a x = blk i a x) ∧
      (∀ x, 2 * k * t ≤ x → stageK blk k a x = a x) := by
  intro k
  induction k with
  | zero =>
      exact ⟨fun i _ hi => absurd hi (Nat.not_lt_zero i),
        fun _ _ => by simp only [stageK, range_list_zero, List.foldl_nil]⟩
  | succ k ih =>
      obtain ⟨ih1, ih2⟩ := ih
      refine ⟨?_, ?_⟩
      · intro i x hi hx1 hx2
        rw [stage_k_succ]
        rcases Nat.lt_or_ge i k with hik | hik
        · have hlt : x < 2 * k * t := by
            have := two_block_mono i k t (by omega)
            omega
          rw [hfix _ _ _ (Or.inl hlt)]
          exact ih1 i x hik hx1 hx2
        · have hik' : i = k := by omega
          subst hik'
          exact hdep i (stageK blk i a) a (fun y hy _ => ih2 y hy) x hx1 hx2
      · intro x hx
        rw [two_block_succ] at hx
        rw [stage_k_succ, hfix _ _ _ (Or.inr (by omega))]
        exact ih2 x (by omega)

/-! ## 6. The two concrete stages -/

theorem ct_butterfly_fixed (s t j : Nat) (b : Nat → Nat) (i : Nat) (h1 : i ≠ j) (h2 : i ≠ j + t) :
    ctButterfly s t j b i = b i := by
  simp only [ctButterfly, upd, if_neg h1, if_neg h2]

theorem ct_butterfly_dep (s t j : Nat) (b c : Nat → Nat) (e1 : b j = c j)
    (e2 : b (j + t) = c (j + t)) :
    ctButterfly s t j b j = ctButterfly s t j c j ∧
      ctButterfly s t j b (j + t) = ctButterfly s t j c (j + t) :=
  ⟨by simp only [ctButterfly, upd, e1, e2], by simp only [ctButterfly, upd, e1, e2]⟩

theorem ct_butterfly_low (s t j : Nat) (b : Nat → Nat) (ht : 0 < t) :
    ctButterfly s t j b j = (b j + s * b (j + t)) % falconQ := by
  simp only [ctButterfly, upd, if_neg (show ¬ j = j + t by omega), if_pos rfl, if_true]

theorem ct_butterfly_high (s t j : Nat) (b : Nat → Nat) :
    ctButterfly s t j b (j + t) = (b j + falconQ * falconQ - s * b (j + t)) % falconQ := by
  simp only [ctButterfly, upd, if_pos rfl, if_true]

theorem gs_butterfly_fixed (s t j : Nat) (b : Nat → Nat) (i : Nat) (h1 : i ≠ j) (h2 : i ≠ j + t) :
    gsButterfly s t j b i = b i := by
  simp only [gsButterfly, upd, if_neg h1, if_neg h2]

theorem gs_butterfly_dep (s t j : Nat) (b c : Nat → Nat) (e1 : b j = c j)
    (e2 : b (j + t) = c (j + t)) :
    gsButterfly s t j b j = gsButterfly s t j c j ∧
      gsButterfly s t j b (j + t) = gsButterfly s t j c (j + t) :=
  ⟨by simp only [gsButterfly, upd, e1, e2], by simp only [gsButterfly, upd, e1, e2]⟩

theorem gs_butterfly_low (s t j : Nat) (b : Nat → Nat) (ht : 0 < t) :
    gsButterfly s t j b j = (b j + b (j + t)) % falconQ := by
  simp only [gsButterfly, upd, if_neg (show ¬ j = j + t by omega), if_pos rfl, if_true]

theorem gs_butterfly_high (s t j : Nat) (b : Nat → Nat) :
    gsButterfly s t j b (j + t) = (b j + falconQ - b (j + t)) * s % falconQ := by
  simp only [gsButterfly, upd, if_pos rfl, if_true]

theorem ct_inner_spec (s t j1 : Nat) (ht : 0 < t) (a : Nat → Nat) :
    (∀ j, j < t → ctInner s t j1 a (j1 + j) = (a (j1 + j) + s * a (j1 + j + t)) % falconQ) ∧
      (∀ j, j < t → ctInner s t j1 a (j1 + j + t)
          = (a (j1 + j) + falconQ * falconQ - s * a (j1 + j + t)) % falconQ) ∧
      (∀ x, (x < j1 ∨ j1 + 2 * t ≤ x) → ctInner s t j1 a x = a x) := by
  have key := inner_k_spec t j1 (fun j b => ctButterfly s t j b)
    (fun j b i h1 h2 => ct_butterfly_fixed s t j b i h1 h2)
    (fun j b c e1 e2 => ct_butterfly_dep s t j b c e1 e2) a t (Nat.le_refl t)
  obtain ⟨k1, k2, k3⟩ := key
  refine ⟨fun j hj => ?_, fun j hj => ?_, fun x hx => ?_⟩
  · rw [show ctInner s t j1 a = innerK t (fun j b => ctButterfly s t j b) j1 t a from rfl, k1 j hj]
    exact ct_butterfly_low s t (j1 + j) a ht
  · rw [show ctInner s t j1 a = innerK t (fun j b => ctButterfly s t j b) j1 t a from rfl, k2 j hj]
    exact ct_butterfly_high s t (j1 + j) a
  · exact k3 x (fun j hj => ⟨by omega, by omega⟩)

theorem gs_inner_spec (s t j1 : Nat) (ht : 0 < t) (a : Nat → Nat) :
    (∀ j, j < t → gsInner s t j1 a (j1 + j) = (a (j1 + j) + a (j1 + j + t)) % falconQ) ∧
      (∀ j, j < t → gsInner s t j1 a (j1 + j + t)
          = (a (j1 + j) + falconQ - a (j1 + j + t)) * s % falconQ) ∧
      (∀ x, (x < j1 ∨ j1 + 2 * t ≤ x) → gsInner s t j1 a x = a x) := by
  have key := inner_k_spec t j1 (fun j b => gsButterfly s t j b)
    (fun j b i h1 h2 => gs_butterfly_fixed s t j b i h1 h2)
    (fun j b c e1 e2 => gs_butterfly_dep s t j b c e1 e2) a t (Nat.le_refl t)
  obtain ⟨k1, k2, k3⟩ := key
  refine ⟨fun j hj => ?_, fun j hj => ?_, fun x hx => ?_⟩
  · rw [show gsInner s t j1 a = innerK t (fun j b => gsButterfly s t j b) j1 t a from rfl, k1 j hj]
    exact gs_butterfly_low s t (j1 + j) a ht
  · rw [show gsInner s t j1 a = innerK t (fun j b => gsButterfly s t j b) j1 t a from rfl, k2 j hj]
    exact gs_butterfly_high s t (j1 + j) a
  · exact k3 x (fun j hj => ⟨by omega, by omega⟩)

theorem ct_inner_dep (s t : Nat) (ht : 0 < t) (j1 : Nat) (b c : Nat → Nat)
    (hbc : ∀ y, j1 ≤ y → y < j1 + 2 * t → b y = c y) (x : Nat)
    (hx1 : j1 ≤ x) (hx2 : x < j1 + 2 * t) :
    ctInner s t j1 b x = ctInner s t j1 c x := by
  obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le hx1
  obtain ⟨bs1, bs2, _⟩ := ct_inner_spec s t j1 ht b
  obtain ⟨cs1, cs2, _⟩ := ct_inner_spec s t j1 ht c
  rcases Nat.lt_or_ge d t with hd | hd
  · rw [bs1 d hd, cs1 d hd, hbc (j1 + d) (by omega) (by omega),
      hbc (j1 + d + t) (by omega) (by omega)]
  · have hsplit : j1 + d = j1 + (d - t) + t := by omega
    rw [hsplit, bs2 (d - t) (by omega), cs2 (d - t) (by omega),
      hbc (j1 + (d - t)) (by omega) (by omega),
      hbc (j1 + (d - t) + t) (by omega) (by omega)]

/-- The Cooley-Tukey stage, resolved blockwise. -/
theorem ct_stage_block (m t : Nat) (ht : 0 < t) (a : Nat → Nat) :
    (∀ i x, i < m → 2 * i * t ≤ x → x < 2 * i * t + 2 * t →
        ctStage m t a x = ctInner (psiRev (m + i)) t (2 * i * t) a x) ∧
      (∀ x, 2 * m * t ≤ x → ctStage m t a x = a x) :=
  stage_k_spec t (fun i b => ctInner (psiRev (m + i)) t (2 * i * t) b)
    (fun i b x hx => (ct_inner_spec (psiRev (m + i)) t (2 * i * t) ht b).2.2 x hx)
    (fun i b c hbc x hx1 hx2 =>
      ct_inner_dep (psiRev (m + i)) t ht (2 * i * t) b c hbc x hx1 hx2) a m

theorem gs_stage_alt (hh t : Nat) (a : Nat → Nat) :
    gsStage hh t a = stageK (fun i b => gsInner (psiInvRev (hh + i)) t (2 * i * t) b) hh a := by
  have hcomm : ∀ i : Nat, 2 * t * i = 2 * i * t := by
    intro i
    rw [Nat.mul_assoc, Nat.mul_comm t i, ← Nat.mul_assoc]
  simp only [gsStage, stageK, hcomm]

theorem gs_inner_dep (s t : Nat) (ht : 0 < t) (j1 : Nat) (b c : Nat → Nat)
    (hbc : ∀ y, j1 ≤ y → y < j1 + 2 * t → b y = c y) (x : Nat)
    (hx1 : j1 ≤ x) (hx2 : x < j1 + 2 * t) :
    gsInner s t j1 b x = gsInner s t j1 c x := by
  obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le hx1
  obtain ⟨bs1, bs2, _⟩ := gs_inner_spec s t j1 ht b
  obtain ⟨cs1, cs2, _⟩ := gs_inner_spec s t j1 ht c
  rcases Nat.lt_or_ge d t with hd | hd
  · rw [bs1 d hd, cs1 d hd, hbc (j1 + d) (by omega) (by omega),
      hbc (j1 + d + t) (by omega) (by omega)]
  · have hsplit : j1 + d = j1 + (d - t) + t := by omega
    rw [hsplit, bs2 (d - t) (by omega), cs2 (d - t) (by omega),
      hbc (j1 + (d - t)) (by omega) (by omega),
      hbc (j1 + (d - t) + t) (by omega) (by omega)]

/-- The Gentleman-Sande stage, resolved blockwise. -/
theorem gs_stage_block (hh t : Nat) (ht : 0 < t) (a : Nat → Nat) :
    (∀ i x, i < hh → 2 * i * t ≤ x → x < 2 * i * t + 2 * t →
        gsStage hh t a x = gsInner (psiInvRev (hh + i)) t (2 * i * t) a x) ∧
      (∀ x, 2 * hh * t ≤ x → gsStage hh t a x = a x) := by
  rw [gs_stage_alt]
  exact stage_k_spec t (fun i b => gsInner (psiInvRev (hh + i)) t (2 * i * t) b)
    (fun i b x hx => (gs_inner_spec (psiInvRev (hh + i)) t (2 * i * t) ht b).2.2 x hx)
    (fun i b c hbc x hx1 hx2 =>
      gs_inner_dep (psiInvRev (hh + i)) t ht (2 * i * t) b c hbc x hx1 hx2) a hh

theorem ct_stage_low (m t : Nat) (ht : 0 < t) (a : Nat → Nat) (i r : Nat) (hi : i < m)
    (hr : r < t) : ctStage m t a (2 * i * t + r)
      = (a (2 * i * t + r) + psiRev (m + i) * a (2 * i * t + r + t)) % falconQ := by
  rw [(ct_stage_block m t ht a).1 i (2 * i * t + r) hi (by omega) (by omega)]
  exact (ct_inner_spec (psiRev (m + i)) t (2 * i * t) ht a).1 r hr

theorem ct_stage_high (m t : Nat) (ht : 0 < t) (a : Nat → Nat) (i r : Nat) (hi : i < m)
    (hr : r < t) : ctStage m t a (2 * i * t + r + t)
      = (a (2 * i * t + r) + falconQ * falconQ - psiRev (m + i) * a (2 * i * t + r + t))
        % falconQ := by
  rw [(ct_stage_block m t ht a).1 i (2 * i * t + r + t) hi (by omega) (by omega)]
  exact (ct_inner_spec (psiRev (m + i)) t (2 * i * t) ht a).2.1 r hr

theorem ct_stage_fixed (m t : Nat) (ht : 0 < t) (a : Nat → Nat) (x : Nat) (hx : 2 * m * t ≤ x) :
    ctStage m t a x = a x :=
  (ct_stage_block m t ht a).2 x hx

theorem gs_stage_low (hh t : Nat) (ht : 0 < t) (a : Nat → Nat) (i r : Nat) (hi : i < hh)
    (hr : r < t) : gsStage hh t a (2 * i * t + r)
      = (a (2 * i * t + r) + a (2 * i * t + r + t)) % falconQ := by
  rw [(gs_stage_block hh t ht a).1 i (2 * i * t + r) hi (by omega) (by omega)]
  exact (gs_inner_spec (psiInvRev (hh + i)) t (2 * i * t) ht a).1 r hr

theorem gs_stage_high (hh t : Nat) (ht : 0 < t) (a : Nat → Nat) (i r : Nat) (hi : i < hh)
    (hr : r < t) : gsStage hh t a (2 * i * t + r + t)
      = (a (2 * i * t + r) + falconQ - a (2 * i * t + r + t)) * psiInvRev (hh + i) % falconQ := by
  rw [(gs_stage_block hh t ht a).1 i (2 * i * t + r + t) hi (by omega) (by omega)]
  exact (gs_inner_spec (psiInvRev (hh + i)) t (2 * i * t) ht a).2.1 r hr

theorem gs_stage_fixed (hh t : Nat) (ht : 0 < t) (a : Nat → Nat) (x : Nat) (hx : 2 * hh * t ≤ x) :
    gsStage hh t a x = a x :=
  (gs_stage_block hh t ht a).2 x hx

/-! ## 7. Twiddle factors and spectral sums -/

theorem one_mod_q : (1 : Nat) % falconQ = 1 := by decide

theorem q_sub_one_mod_q : (falconQ - 1) % falconQ = falconQ - 1 := by decide

theorem two_mul_assoc (m L : Nat) : 2 * m * L = m * (2 * L) := by
  rw [Nat.mul_assoc, Nat.mul_left_comm]

theorem psi_rev_eq (j : Nat) : psiRev j = powQ ntoPsi (revOf 9 j) := by
  have hb : revOf 9 j < 2 ^ 64 := by
    have h1 := rev_of_lt 9 j
    have h2 : (2 : Nat) ^ 9 ≤ 2 ^ 64 := Nat.pow_le_pow_right (by decide) (by decide)
    omega
  show powModQ ntoPsi (bitReverse9 j) = _
  rw [bit_reverse_9_eq]
  exact pow_mod_q_eq _ _ hb

theorem psi_inv_rev_eq (j : Nat) : psiInvRev j = powQ psiInv (revOf 9 j) := by
  have hb : revOf 9 j < 2 ^ 64 := by
    have h1 := rev_of_lt 9 j
    have h2 : (2 : Nat) ^ 9 ≤ 2 ^ 64 := Nat.pow_le_pow_right (by decide) (by decide)
    omega
  show powModQ psiInv (bitReverse9 j) = _
  rw [bit_reverse_9_eq]
  exact pow_mod_q_eq _ _ hb

theorem psi_rev_lt (j : Nat) : psiRev j < falconQ := by rw [psi_rev_eq]; exact pow_q_lt _ _

theorem psi_inv_rev_lt (j : Nat) : psiInvRev j < falconQ := by
  rw [psi_inv_rev_eq]; exact pow_q_lt _ _

/-- The two tables are inverse at every index: `psi_rev[j] * psi_inv_rev[j] = 1 mod q`.
Only the build-time assertion `psi * psi^-1 = 1` (:176) is used; q is never assumed prime. -/
theorem psi_rev_mul_inv (j : Nat) : psiRev j * psiInvRev j % falconQ = 1 := by
  have hone : EqQ (ntoPsi * psiInv) 1 := by
    show (ntoPsi * psiInv) % falconQ = 1 % falconQ
    rw [psi_inverse_pinned, one_mod_q]
  have hp : EqQ ((ntoPsi * psiInv) ^ revOf 9 j) (1 ^ revOf 9 j) := eq_q_pow hone _
  rw [Nat.one_pow, Nat.mul_pow] at hp
  have hmul : EqQ (psiRev j * psiInvRev j) (ntoPsi ^ revOf 9 j * psiInv ^ revOf 9 j) := by
    rw [psi_rev_eq, psi_inv_rev_eq]
    exact eq_q_mul (pow_q_eq_q _ _) (pow_q_eq_q _ _)
  have hfin : EqQ (psiRev j * psiInvRev j) 1 := eq_q_trans hmul hp
  show psiRev j * psiInvRev j % falconQ = 1
  rw [hfin, one_mod_q]

/-- `psi^512 = -1 mod q` (the build-time assertion of :172) as a congruence. -/
theorem psi_pow_half : EqQ (ntoPsi ^ 512) (falconQ - 1) := by
  have h : powQ ntoPsi 512 = falconQ - 1 := by
    rw [← pow_mod_q_eq ntoPsi 512 (by decide)]
    exact psi_half_order_is_minus_one
  show ntoPsi ^ 512 % falconQ = (falconQ - 1) % falconQ
  rw [show ntoPsi ^ 512 % falconQ = powQ ntoPsi 512 from rfl, h, q_sub_one_mod_q]

/-- `psi^1024 = 1 mod q` (the build-time assertion of :173) as a congruence. -/
theorem psi_pow_order : EqQ (ntoPsi ^ 1024) 1 := by
  have h : powQ ntoPsi 1024 = 1 := by
    rw [← pow_mod_q_eq ntoPsi 1024 (by decide)]
    exact psi_order
  show ntoPsi ^ 1024 % falconQ = 1 % falconQ
  rw [show ntoPsi ^ 1024 % falconQ = powQ ntoPsi 1024 from rfl, h, one_mod_q]

/-- `sum_{d < m} A(r + d*L) * c^d`: the `r`-th coefficient of the residue of `A` modulo
`X^L - c`, when `A` has `m*L` coefficients. -/
def specSum (A : Nat → Nat) (L c m r : Nat) : Nat := sumTo (fun d => A (r + d * L) * c ^ d) m

theorem spec_sum_zero (A : Nat → Nat) (L c r : Nat) : specSum A L c 0 r = 0 := rfl

theorem spec_sum_eq_q_c (A : Nat → Nat) (L : Nat) {c c' : Nat} (h : EqQ c c') (m r : Nat) :
    EqQ (specSum A L c m r) (specSum A L c' m r) :=
  sum_to_eq_q_congr (fun d _ => eq_q_mul_left _ (eq_q_pow h d))

/-- Splitting a residue modulo `X^L - c` into its even and odd parts: exactly the
Cooley-Tukey butterfly, before any reduction. -/
theorem spec_sum_even_odd (A : Nat → Nat) (L c : Nat) : ∀ m r : Nat,
    specSum A L c (2 * m) r
      = specSum A (2 * L) (c * c) m r + c * specSum A (2 * L) (c * c) m (r + L) := by
  intro m
  induction m with
  | zero => intro r; rfl
  | succ m ih =>
      intro r
      have hsq : c ^ (2 * m) = (c * c) ^ m := by
        rw [Nat.pow_mul, show c ^ 2 = c * c by rw [Nat.pow_succ, Nat.pow_one]]
      have hf0 : A (r + 2 * m * L) * c ^ (2 * m) = A (r + m * (2 * L)) * (c * c) ^ m := by
        rw [two_mul_assoc, hsq]
      have hidx1 : r + (2 * m + 1) * L = r + L + m * (2 * L) := by
        have e : (2 * m + 1) * L = m * (2 * L) + L := by
          rw [Nat.right_distrib, Nat.one_mul, two_mul_assoc]
        omega
      have hf1 : A (r + (2 * m + 1) * L) * c ^ (2 * m + 1)
          = c * (A (r + L + m * (2 * L)) * (c * c) ^ m) := by
        rw [hidx1, Nat.pow_succ, hsq]
        simp only [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm]
      simp only [specSum] at *
      rw [show 2 * (m + 1) = 2 * m + 1 + 1 from by omega]
      simp only [sum_to_succ]
      rw [ih r, hf0, hf1, Nat.left_distrib]
      omega

/-- The exponent of `psi` attached to block `i` of the `2^s` blocks of width `2^h`. -/
def blockExp (h s i : Nat) : Nat := 2 ^ h * (1 + 2 * revOf s i)

/-- The block's modulus constant: block `i` holds `A mod (X^(2^h) - blockC h s i)`. -/
def blockC (h s i : Nat) : Nat := powQ ntoPsi (blockExp h s i)

theorem block_c_lt (h s i : Nat) : blockC h s i < falconQ := pow_q_lt _ _

theorem block_exp_expand (h s i : Nat) : blockExp h s i = 2 ^ h + 2 ^ (h + 1) * revOf s i := by
  rw [blockExp, Nat.left_distrib, Nat.mul_one, ← Nat.mul_assoc, ← Nat.pow_succ]

theorem block_exp_even (h s i : Nat) : blockExp h (s + 1) (2 * i) = blockExp h s i := by
  simp only [blockExp, rev_of_double]

theorem block_exp_double (h s i : Nat) : blockExp (h + 1) s i = 2 * blockExp h s i := by
  simp only [blockExp, Nat.pow_succ, Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm]

theorem block_exp_odd (h s i : Nat) (hsh : s + h + 1 = 9) :
    blockExp h (s + 1) (2 * i + 1) = blockExp h s i + 512 := by
  have hp : (2 : Nat) ^ h * (2 * 2 ^ s) = 512 := by
    have e2 : h + 1 + s = 9 := by omega
    calc (2 : Nat) ^ h * (2 * 2 ^ s) = 2 ^ (h + 1 + s) := by
          rw [← Nat.mul_assoc, ← Nat.pow_succ, ← Nat.pow_add]
      _ = 2 ^ 9 := by rw [e2]
      _ = 512 := by decide
  have he : 1 + 2 * (2 ^ s + revOf s i) = (1 + 2 * revOf s i) + 2 * 2 ^ s := by omega
  simp only [blockExp, rev_of_double_succ]
  rw [he, Nat.left_distrib, hp]

/-- The stage twiddle `psi_rev[2^s + i]` is exactly the constant of the even child block. -/
theorem psi_rev_is_block_c (s h i : Nat) (hsh : s + h + 1 = 9) (hi : i < 2 ^ s) :
    psiRev (2 ^ s + i) = blockC h (s + 1) (2 * i) := by
  rw [psi_rev_eq, ← hsh, rev_of_pow_add s h i hi, blockC, block_exp_even, block_exp_expand]

theorem block_c_pow (h s i : Nat) : EqQ (blockC h s i) (ntoPsi ^ blockExp h s i) :=
  pow_q_eq_q _ _

theorem block_c_even_sq (s h i : Nat) : EqQ (blockC h (s + 1) (2 * i) * blockC h (s + 1) (2 * i))
    (blockC (h + 1) s i) := by
  have h1 : EqQ (blockC h (s + 1) (2 * i) * blockC h (s + 1) (2 * i))
      (ntoPsi ^ blockExp h (s + 1) (2 * i) * ntoPsi ^ blockExp h (s + 1) (2 * i)) :=
    eq_q_mul (block_c_pow _ _ _) (block_c_pow _ _ _)
  have h2 : ntoPsi ^ blockExp h (s + 1) (2 * i) * ntoPsi ^ blockExp h (s + 1) (2 * i)
      = ntoPsi ^ blockExp (h + 1) s i := by
    rw [← Nat.pow_add, block_exp_even, block_exp_double]
    congr 1
    omega
  rw [h2] at h1
  exact eq_q_trans h1 (eq_q_symm (block_c_pow _ _ _))

theorem block_c_odd (s h i : Nat) (hsh : s + h + 1 = 9) :
    EqQ (blockC h (s + 1) (2 * i + 1)) (blockC h (s + 1) (2 * i) * (falconQ - 1)) := by
  refine eq_q_trans (block_c_pow _ _ _) ?_
  rw [block_exp_odd h s i hsh, Nat.pow_add, ← block_exp_even h s i]
  exact eq_q_mul (eq_q_symm (block_c_pow _ _ _)) psi_pow_half

theorem block_c_odd_sq (s h i : Nat) (hsh : s + h + 1 = 9) :
    EqQ (blockC h (s + 1) (2 * i + 1) * blockC h (s + 1) (2 * i + 1)) (blockC (h + 1) s i) := by
  have h1 : EqQ (blockC h (s + 1) (2 * i + 1) * blockC h (s + 1) (2 * i + 1))
      (ntoPsi ^ blockExp h (s + 1) (2 * i + 1) * ntoPsi ^ blockExp h (s + 1) (2 * i + 1)) :=
    eq_q_mul (block_c_pow _ _ _) (block_c_pow _ _ _)
  have h2 : ntoPsi ^ blockExp h (s + 1) (2 * i + 1) * ntoPsi ^ blockExp h (s + 1) (2 * i + 1)
      = ntoPsi ^ blockExp (h + 1) s i * ntoPsi ^ 1024 := by
    rw [← Nat.pow_add, ← Nat.pow_add, block_exp_odd h s i hsh, block_exp_double]
    congr 1
    omega
  rw [h2] at h1
  refine eq_q_trans h1 (eq_q_trans (eq_q_mul (eq_q_symm (block_c_pow _ _ _)) psi_pow_order) ?_)
  rw [Nat.mul_one]
  exact eq_q_refl _

/-! ## 8. The forward stage invariant -/

theorem two_pow_pos (n : Nat) : 0 < 2 ^ n := by
  induction n with
  | zero => decide
  | succ n ih => rw [Nat.pow_succ]; omega

theorem two_pow_succ (n : Nat) : (2 : Nat) ^ (n + 1) = 2 * 2 ^ n := by
  rw [Nat.pow_succ]; omega

theorem nat_sub_mul (m n k : Nat) : (m - n) * k = m * k - n * k := by
  rw [Nat.mul_comm, nat_mul_sub, Nat.mul_comm k m, Nat.mul_comm k n]

theorem block_start_double (i h : Nat) : 2 * i * 2 ^ h = i * 2 ^ (h + 1) := by
  rw [two_pow_succ]
  simp only [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm]

/-- The residue computed by the additive half of a Cooley-Tukey butterfly. -/
theorem ct_low_residue (X Y g : Nat) : EqQ (X % falconQ + g * (Y % falconQ)) (X + g * Y) :=
  eq_q_add (eq_q_mod X) (eq_q_mul_left g (eq_q_mod Y))

/-- The residue computed by the subtractive half: the `q^2` offset of :459-461 is a
representative of `-1` times the twiddled operand. -/
theorem ct_high_residue (X Y g : Nat) (hg : g < falconQ) :
    EqQ (X % falconQ + falconQ * falconQ - g * (Y % falconQ)) (X + (falconQ - 1) * (g * Y)) := by
  have hy : Y % falconQ < falconQ := mod_q_lt Y
  have hP1 : g * (Y % falconQ) ≤ falconQ * falconQ :=
    Nat.mul_le_mul (by omega) (by omega)
  have hP2 : g * (Y % falconQ) ≤ falconQ * (g * (Y % falconQ)) :=
    Nat.le_mul_of_pos_left _ falcon_q_pos
  have step1 : EqQ (X % falconQ + falconQ * falconQ - g * (Y % falconQ))
      (X % falconQ + falconQ * (g * (Y % falconQ)) - g * (Y % falconQ)) :=
    sub_offset_mod (X % falconQ) (g * (Y % falconQ)) falconQ (g * (Y % falconQ)) hP1 hP2
  have e0 : (falconQ - 1) * (g * (Y % falconQ))
      = falconQ * (g * (Y % falconQ)) - g * (Y % falconQ) := by
    rw [nat_sub_mul, Nat.one_mul]
  have step2 : X % falconQ + falconQ * (g * (Y % falconQ)) - g * (Y % falconQ)
      = X % falconQ + (falconQ - 1) * (g * (Y % falconQ)) := by omega
  rw [step2] at step1
  exact eq_q_trans step1
    (eq_q_add (eq_q_mod X) (eq_q_mul_left _ (eq_q_mul_left g (eq_q_mod Y))))

/-- The stage invariant: after the stage that leaves `2^s` blocks of width `2^h`, block `i`
of the working vector holds the coefficients of `A mod (X^(2^h) - blockC h s i)`. -/
def Inv (A : Nat → Nat) (s h : Nat) (a : Nat → Nat) : Prop :=
  ∀ i r, i < 2 ^ s → r < 2 ^ h →
    a (i * 2 ^ h + r) = specSum A (2 ^ h) (blockC h s i) (2 ^ s) r % falconQ

theorem inv_step (A : Nat → Nat) (s h : Nat) (hsh : s + h + 1 = 9) (a : Nat → Nat)
    (hinv : Inv A s (h + 1) a) : Inv A (s + 1) h (ctStage (2 ^ s) (2 ^ h) a) := by
  intro i' r' hi' hr'
  have ht : 0 < 2 ^ h := two_pow_pos h
  have hps : (2 : Nat) ^ (s + 1) = 2 * 2 ^ s := two_pow_succ s
  have hph : (2 : Nat) ^ (h + 1) = 2 * 2 ^ h := two_pow_succ h
  obtain ⟨i, hcase⟩ : ∃ i, i' = 2 * i ∨ i' = 2 * i + 1 := ⟨i' / 2, by omega⟩
  have hi : i < 2 ^ s := by rcases hcase with h1 | h1 <;> omega
  have hb : 2 * i * 2 ^ h = i * 2 ^ (h + 1) := block_start_double i h
  have hgam : psiRev (2 ^ s + i) = blockC h (s + 1) (2 * i) := psi_rev_is_block_c s h i hsh hi
  have hA1 : a (2 * i * 2 ^ h + r')
      = specSum A (2 ^ (h + 1)) (blockC (h + 1) s i) (2 ^ s) r' % falconQ := by
    rw [show 2 * i * 2 ^ h + r' = i * 2 ^ (h + 1) + r' from by omega]
    exact hinv i r' hi (by omega)
  have hA2 : a (2 * i * 2 ^ h + r' + 2 ^ h)
      = specSum A (2 ^ (h + 1)) (blockC (h + 1) s i) (2 ^ s) (r' + 2 ^ h) % falconQ := by
    rw [show 2 * i * 2 ^ h + r' + 2 ^ h = i * 2 ^ (h + 1) + (r' + 2 ^ h) from by omega]
    exact hinv i (r' + 2 ^ h) hi (by omega)
  -- the two child spectra, before reduction
  have hsplit : ∀ c : Nat, specSum A (2 ^ h) c (2 ^ (s + 1)) r'
      = specSum A (2 ^ (h + 1)) (c * c) (2 ^ s) r'
        + c * specSum A (2 ^ (h + 1)) (c * c) (2 ^ s) (r' + 2 ^ h) := by
    intro c
    rw [hps, spec_sum_even_odd, ← hph]
  rcases hcase with hcase | hcase
  · subst hcase
    rw [ct_stage_low (2 ^ s) (2 ^ h) ht a i r' hi hr', hgam, hA1, hA2]
    refine eq_q_trans (ct_low_residue _ _ _) (eq_q_symm ?_)
    rw [hsplit (blockC h (s + 1) (2 * i))]
    exact eq_q_add (spec_sum_eq_q_c _ _ (block_c_even_sq s h i) _ _)
      (eq_q_mul_left _ (spec_sum_eq_q_c _ _ (block_c_even_sq s h i) _ _))
  · subst hcase
    have hidx : (2 * i + 1) * 2 ^ h + r' = 2 * i * 2 ^ h + r' + 2 ^ h := by
      rw [Nat.right_distrib, Nat.one_mul]; omega
    rw [hidx, ct_stage_high (2 ^ s) (2 ^ h) ht a i r' hi hr', hgam, hA1, hA2]
    refine eq_q_trans (ct_high_residue _ _ _ (block_c_lt _ _ _)) (eq_q_symm ?_)
    rw [hsplit (blockC h (s + 1) (2 * i + 1))]
    refine eq_q_trans (eq_q_add (spec_sum_eq_q_c _ _ (block_c_odd_sq s h i hsh) _ _)
      (eq_q_mul (block_c_odd s h i hsh)
        (spec_sum_eq_q_c _ _ (block_c_odd_sq s h i hsh) _ _))) ?_
    refine eq_q_add (eq_q_refl _) ?_
    simp only [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm]
    exact eq_q_refl _

/-! ## 9. The forward transform is evaluation at the negacyclic points -/

theorem ntt_forward_loop_unfold (a : Nat → Nat) :
    nttForwardLoop 10 1 falconN a
      = ctStage (2 ^ 8) (2 ^ 0) (ctStage (2 ^ 7) (2 ^ 1) (ctStage (2 ^ 6) (2 ^ 2)
          (ctStage (2 ^ 5) (2 ^ 3) (ctStage (2 ^ 4) (2 ^ 4) (ctStage (2 ^ 3) (2 ^ 5)
            (ctStage (2 ^ 2) (2 ^ 6) (ctStage (2 ^ 1) (2 ^ 7)
              (ctStage (2 ^ 0) (2 ^ 8) a)))))))) := by
  simp only [nttForwardLoop, falconN, Nat.reduceMul, Nat.reduceDiv, Nat.reduceLT,
    Nat.reducePow, reduceIte]

/-- Evaluation of the polynomial `A` (512 coefficients) at `c`, modulo nothing yet. -/
def evalAt (A : Nat → Nat) (c : Nat) : Nat := sumTo (fun d => A d * c ^ d) falconN

theorem inv_initial (A : Nat → Nat) (hc : ∀ i, A i < falconQ) : Inv A 0 9 A := by
  intro i r hi _
  have hi0 : i = 0 := by simp only [Nat.pow_zero] at hi; omega
  subst hi0
  have hs : specSum A (2 ^ 9) (blockC 9 0 0) (2 ^ 0) r = A r := by
    show sumTo (fun d => A (r + d * 2 ^ 9) * blockC 9 0 0 ^ d) 1 = _
    rw [sum_to_succ, sum_to_zero]
    simp only [Nat.zero_mul, Nat.add_zero, Nat.pow_zero, Nat.mul_one, Nat.zero_add]
  rw [hs, Nat.mod_eq_of_lt (hc r), Nat.zero_mul, Nat.zero_add]

theorem inv_chain_forward (A : Nat → Nat) (a : Nat → Nat) (h0 : Inv A 0 9 a) :
    Inv A 9 0 (nttForwardLoop 10 1 falconN a) := by
  rw [ntt_forward_loop_unfold]
  exact inv_step A 8 0 (by decide) _ (inv_step A 7 1 (by decide) _
    (inv_step A 6 2 (by decide) _ (inv_step A 5 3 (by decide) _
      (inv_step A 4 4 (by decide) _ (inv_step A 3 5 (by decide) _
        (inv_step A 2 6 (by decide) _ (inv_step A 1 7 (by decide) _
          (inv_step A 0 8 (by decide) _ h0))))))))

/-- The transcribed forward NTT evaluates its input at the odd powers of `psi`, in the
bit-reversed index order the Longa-Naehrig twiddle table imposes. -/
theorem ntt_forward_loop_eval (A : Nat → Nat) (hc : ∀ i, A i < falconQ) (j : Nat)
    (hj : j < falconN) :
    nttForwardLoop 10 1 falconN A j = evalAt A (powQ ntoPsi (1 + 2 * revOf 9 j)) % falconQ := by
  have hinv := inv_chain_forward A A (inv_initial A hc) j 0 (by simpa [falconN] using hj)
    (by decide)
  simp only [Nat.pow_zero, Nat.mul_one, Nat.add_zero] at hinv
  rw [hinv]
  have hc9 : blockC 0 9 j = powQ ntoPsi (1 + 2 * revOf 9 j) := by
    simp only [blockC, blockExp, Nat.pow_zero, Nat.one_mul]
  have hspec : specSum A 1 (blockC 0 9 j) (2 ^ 9) 0
      = evalAt A (powQ ntoPsi (1 + 2 * revOf 9 j)) := by
    rw [hc9]
    show sumTo (fun d => A (0 + d * 1) * powQ ntoPsi (1 + 2 * revOf 9 j) ^ d) (2 ^ 9) = _
    exact sum_to_congr (fun d _ => by rw [Nat.mul_one, Nat.zero_add])
  rw [hspec]

theorem ntt_forward_eval (l : List Nat) (hc : ∀ c ∈ l, c < falconQ) (j : Nat)
    (hj : j < falconN) :
    wireOf (nttForward l) j = evalAt (wireOf l) (powQ ntoPsi (1 + 2 * revOf 9 j)) % falconQ := by
  rw [show nttForward l = (rangeList falconN).map (nttForwardLoop 10 1 falconN (wireOf l)) from rfl,
    wire_of_map_range _ falconN j hj]
  exact ntt_forward_loop_eval (wireOf l) (wire_of_lt_q l hc) j hj

/-! ## 10. The Gentleman-Sande loop inverts the Cooley-Tukey loop -/

theorem two_pow_block (s h : Nat) (hsh : s + h + 1 = 9) : 2 * 2 ^ s * 2 ^ h = falconN := by
  have e : (2 : Nat) ^ s * 2 ^ h = 2 ^ (s + h) := (Nat.pow_add 2 s h).symm
  have e2 : s + h = 8 := by omega
  calc 2 * 2 ^ s * 2 ^ h = 2 * (2 ^ s * 2 ^ h) := by rw [Nat.mul_assoc]
    _ = 2 * 2 ^ (s + h) := by rw [e]
    _ = 2 * 2 ^ 8 := by rw [e2]
    _ = falconN := by decide

theorem block_decomp (m t x : Nat) (ht : 0 < t) (hx : x < 2 * m * t) :
    ∃ i r, i < m ∧ r < t ∧ (x = 2 * i * t + r ∨ x = 2 * i * t + r + t) := by
  have h2t : 0 < 2 * t := by omega
  have hdm : 2 * t * (x / (2 * t)) + x % (2 * t) = x := Nat.div_add_mod x (2 * t)
  have hd : x % (2 * t) < 2 * t := Nat.mod_lt _ h2t
  have hmt : 2 * m * t = 2 * t * m := by
    simp only [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm]
  have hi : x / (2 * t) < m := Nat.div_lt_of_lt_mul (by omega)
  have hblk : 2 * (x / (2 * t)) * t = 2 * t * (x / (2 * t)) := by
    simp only [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm]
  rcases Nat.lt_or_ge (x % (2 * t)) t with hlt | hge
  · exact ⟨x / (2 * t), x % (2 * t), hi, hlt, Or.inl (by omega)⟩
  · exact ⟨x / (2 * t), x % (2 * t) - t, hi, by omega, Or.inr (by omega)⟩

theorem ct_stage_canonical (m t : Nat) (ht : 0 < t) (b : Nat → Nat) (hb : ∀ y, b y < falconQ)
    (y : Nat) : ctStage m t b y < falconQ := by
  rcases Nat.lt_or_ge y (2 * m * t) with hy | hy
  · obtain ⟨i, r, hi, hr, hcase⟩ := block_decomp m t y ht hy
    rcases hcase with rfl | rfl
    · rw [ct_stage_low m t ht b i r hi hr]; exact mod_q_lt _
    · rw [ct_stage_high m t ht b i r hi hr]; exact mod_q_lt _
  · rw [ct_stage_fixed m t ht b y hy]; exact hb y

theorem scale_add (c u v : Nat) :
    (c * u % falconQ + c * v % falconQ) % falconQ = c * ((u + v) % falconQ) % falconQ := by
  refine eq_q_trans (eq_q_add (eq_q_mod _) (eq_q_mod _)) ?_
  rw [← Nat.left_distrib]
  exact eq_q_mul_left c (eq_q_symm (eq_q_mod _))

theorem scale_sub_mul (c u v sw : Nat) (hv : v < falconQ) :
    (c * u % falconQ + falconQ - c * v % falconQ) * sw % falconQ
      = c * ((u + falconQ - v) * sw % falconQ) % falconQ := by
  have hinner : EqQ (c * u % falconQ + falconQ - c * v % falconQ) (c * (u + falconQ - v)) := by
    refine eq_q_sub_add _ _ _ (mod_q_lt _) ?_
    have e1 : EqQ (c * v % falconQ + c * (u + falconQ - v)) (c * v + c * (u + falconQ - v)) :=
      eq_q_add (eq_q_mod _) (eq_q_refl _)
    have e2 : c * v + c * (u + falconQ - v) = c * (u + falconQ) := by
      rw [← Nat.left_distrib]
      congr 1
      omega
    have e3 : EqQ (c * (u + falconQ)) (c * u % falconQ) := by
      refine (eq_q_iff _ _).2 ⟨0, c + c * u / falconQ, ?_⟩
      rw [Nat.left_distrib falconQ c (c * u / falconQ)]
      have e4 : c * (u + falconQ) = c * u + falconQ * c := by
        rw [Nat.left_distrib, Nat.mul_comm c falconQ]
      have e5 : c * u % falconQ + falconQ * (c * u / falconQ) = c * u := by
        have := Nat.div_add_mod (c * u) falconQ
        omega
      omega
    rw [e2] at e1
    exact eq_q_trans e1 e3
  refine eq_q_trans (eq_q_mul hinner (eq_q_refl sw)) ?_
  rw [Nat.mul_assoc]
  exact eq_q_mul_left c (eq_q_symm (eq_q_mod _))

/-- Every Gentleman-Sande stage is linear over the residues. -/
theorem gs_stage_scale (m t c : Nat) (ht : 0 < t) (b : Nat → Nat) (hb : ∀ y, b y < falconQ)
    (x : Nat) : gsStage m t (fun y => c * b y % falconQ) x = c * gsStage m t b x % falconQ := by
  rcases Nat.lt_or_ge x (2 * m * t) with hx | hx
  · obtain ⟨i, r, hi, hr, hcase⟩ := block_decomp m t x ht hx
    rcases hcase with rfl | rfl
    · rw [gs_stage_low m t ht _ i r hi hr, gs_stage_low m t ht b i r hi hr]
      exact scale_add c _ _
    · rw [gs_stage_high m t ht _ i r hi hr, gs_stage_high m t ht b i r hi hr]
      exact scale_sub_mul c _ _ _ (hb _)
  · rw [gs_stage_fixed m t ht _ x hx, gs_stage_fixed m t ht b x hx]

/-- The two halves of a Cooley-Tukey butterfly add back to twice the low input. -/
theorem ct_pair_sum (B0 B1 g : Nat) (hg : g < falconQ) (h1 : B1 < falconQ) :
    ((B0 + g * B1) % falconQ + (B0 + falconQ * falconQ - g * B1) % falconQ) % falconQ
      = 2 * B0 % falconQ := by
  have hle : g * B1 ≤ falconQ * falconQ := Nat.mul_le_mul (by omega) (by omega)
  refine eq_q_trans (eq_q_add (eq_q_mod _) (eq_q_mod _)) ?_
  have e : B0 + g * B1 + (B0 + falconQ * falconQ - g * B1) = 2 * B0 + falconQ * falconQ := by
    omega
  rw [e]
  exact (eq_q_iff _ _).2 ⟨0, falconQ, by omega⟩

/-- Their difference, twiddled by the inverse table entry, gives back twice the high input. -/
theorem ct_pair_diff (B0 B1 g sw : Nat) (hg : g < falconQ) (h1 : B1 < falconQ)
    (hinv : g * sw % falconQ = 1) :
    (((B0 + g * B1) % falconQ + falconQ - (B0 + falconQ * falconQ - g * B1) % falconQ) * sw)
        % falconQ = 2 * B1 % falconQ := by
  have hle : g * B1 ≤ falconQ * falconQ := Nat.mul_le_mul (by omega) (by omega)
  have hdiff : EqQ ((B0 + g * B1) % falconQ + falconQ
      - (B0 + falconQ * falconQ - g * B1) % falconQ) (2 * (g * B1)) := by
    refine eq_q_sub_add _ _ _ (mod_q_lt _) ?_
    have e1 : EqQ ((B0 + falconQ * falconQ - g * B1) % falconQ + 2 * (g * B1))
        ((B0 + falconQ * falconQ - g * B1) + 2 * (g * B1)) := eq_q_add (eq_q_mod _) (eq_q_refl _)
    have e2 : (B0 + falconQ * falconQ - g * B1) + 2 * (g * B1)
        = (B0 + g * B1) + falconQ * falconQ := by omega
    rw [e2] at e1
    refine eq_q_trans e1 ?_
    refine eq_q_trans ((eq_q_iff _ _).2 ⟨0, falconQ, by omega⟩ :
      EqQ (B0 + g * B1 + falconQ * falconQ) (B0 + g * B1)) ?_
    exact eq_q_symm (eq_q_mod _)
  refine eq_q_trans (eq_q_mul hdiff (eq_q_refl sw)) ?_
  have e3 : 2 * (g * B1) * sw = 2 * B1 * (g * sw) := by
    simp only [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm]
  rw [e3]
  have hgs : EqQ (g * sw) 1 := by
    show g * sw % falconQ = 1 % falconQ
    rw [hinv, one_mod_q]
  have hfin : EqQ (2 * B1 * (g * sw)) (2 * B1 * 1) := eq_q_mul_left (2 * B1) hgs
  rw [Nat.mul_one] at hfin
  exact hfin

/-- One matched stage pair: Gentleman-Sande undoes Cooley-Tukey up to the factor 2 that the
final `n^-1` scaling of :500-508 accounts for. -/
theorem gs_ct_inverse (m t : Nat) (ht : 0 < t) (b : Nat → Nat) (hb : ∀ y, b y < falconQ)
    (x : Nat) (hx : x < 2 * m * t) :
    gsStage m t (ctStage m t b) x = 2 * b x % falconQ := by
  obtain ⟨i, r, hi, hr, hcase⟩ := block_decomp m t x ht hx
  have hct := ct_stage_canonical m t ht b hb
  rcases hcase with rfl | rfl
  · rw [gs_stage_low m t ht _ i r hi hr, ct_stage_low m t ht b i r hi hr,
      ct_stage_high m t ht b i r hi hr]
    exact ct_pair_sum _ _ _ (psi_rev_lt _) (hb _)
  · rw [gs_stage_high m t ht _ i r hi hr, ct_stage_low m t ht b i r hi hr,
      ct_stage_high m t ht b i r hi hr]
    exact ct_pair_diff _ _ _ _ (psi_rev_lt _) (hb _) (psi_rev_mul_inv _)

theorem inverse_chain_step (s h c : Nat) (hsh : s + h + 1 = 9) (Y X : Nat → Nat)
    (hY : ∀ y, Y y < falconQ) (hY0 : ∀ y, falconN ≤ y → Y y = 0)
    (hX : ∀ y, X y = c * ctStage (2 ^ s) (2 ^ h) Y y % falconQ) (y : Nat) :
    gsStage (2 ^ s) (2 ^ h) X y = 2 * c * Y y % falconQ := by
  have ht : 0 < 2 ^ h := two_pow_pos h
  have hblk : 2 * 2 ^ s * 2 ^ h = falconN := two_pow_block s h hsh
  have hfun : X = fun z => c * ctStage (2 ^ s) (2 ^ h) Y z % falconQ := funext hX
  subst hfun
  rcases Nat.lt_or_ge y (2 * 2 ^ s * 2 ^ h) with hy | hy
  · rw [gs_stage_scale _ _ c ht _ (ct_stage_canonical _ _ ht Y hY) y,
      gs_ct_inverse _ _ ht Y hY y hy]
    refine eq_q_trans (eq_q_mul_left c (eq_q_mod _)) ?_
    rw [← Nat.mul_assoc, Nat.mul_comm c 2]
    exact eq_q_refl _
  · rw [gs_stage_fixed _ _ ht _ y hy, ct_stage_fixed _ _ ht Y y hy,
      hY0 y (by omega), Nat.mul_zero, Nat.mul_zero]

/-- The nine Cooley-Tukey stages, outermost last. -/
def fwdRun : Nat → Nat → (Nat → Nat) → (Nat → Nat)
  | _, 0, a => a
  | s, h + 1, a => fwdRun (s + 1) h (ctStage (2 ^ s) (2 ^ h) a)

/-- The nine Gentleman-Sande stages, in the reverse order. -/
def invRun : Nat → Nat → (Nat → Nat) → (Nat → Nat)
  | _, 0, a => a
  | s, h + 1, a => gsStage (2 ^ s) (2 ^ h) (invRun (s + 1) h a)

theorem fwd_run_fixed : ∀ h s : Nat, s + h = 9 → ∀ (a : Nat → Nat) (i : Nat), falconN ≤ i →
    fwdRun s h a i = a i := by
  intro h
  induction h with
  | zero => intro s _ a i _; rfl
  | succ h ih =>
      intro s hsh a i hi
      have ht : 0 < 2 ^ h := two_pow_pos h
      have hblk : 2 * 2 ^ s * 2 ^ h = falconN := two_pow_block s h (by omega)
      show fwdRun (s + 1) h (ctStage (2 ^ s) (2 ^ h) a) i = a i
      rw [ih (s + 1) (by omega) _ i hi, ct_stage_fixed _ _ ht a i (by omega)]

theorem fwd_run_canonical : ∀ h s : Nat, s + h = 9 → ∀ a : Nat → Nat, (∀ y, a y < falconQ) →
    ∀ y, fwdRun s h a y < falconQ := by
  intro h
  induction h with
  | zero => intro s _ a ha y; exact ha y
  | succ h ih =>
      intro s hsh a ha y
      show fwdRun (s + 1) h (ctStage (2 ^ s) (2 ^ h) a) y < falconQ
      exact ih (s + 1) (by omega) _ (ct_stage_canonical _ _ (two_pow_pos h) a ha) y

theorem inv_run_fwd_run : ∀ h s : Nat, s + h = 9 → ∀ a : Nat → Nat, (∀ y, a y < falconQ) →
    (∀ y, falconN ≤ y → a y = 0) → ∀ x, invRun s h (fwdRun s h a) x = 2 ^ h * a x % falconQ := by
  intro h
  induction h with
  | zero =>
      intro s _ a ha _ x
      show a x = 2 ^ 0 * a x % falconQ
      rw [Nat.pow_zero, Nat.one_mul, Nat.mod_eq_of_lt (ha x)]
  | succ h ih =>
      intro s hsh a ha ha0 x
      have ht : 0 < 2 ^ h := two_pow_pos h
      have hblk : 2 * 2 ^ s * 2 ^ h = falconN := two_pow_block s h (by omega)
      have hb := ct_stage_canonical (2 ^ s) (2 ^ h) ht a ha
      have hb0 : ∀ y, falconN ≤ y → ctStage (2 ^ s) (2 ^ h) a y = 0 := by
        intro y hy
        rw [ct_stage_fixed _ _ ht a y (by omega)]
        exact ha0 y hy
      have hstep := ih (s + 1) (by omega) (ctStage (2 ^ s) (2 ^ h) a) hb hb0
      show gsStage (2 ^ s) (2 ^ h)
        (invRun (s + 1) h (fwdRun (s + 1) h (ctStage (2 ^ s) (2 ^ h) a))) x = _
      rw [inverse_chain_step s h (2 ^ h) (by omega) a _ ha ha0 hstep x, two_pow_succ h]

/-! ## 11. `ntt_inverse` inverts `ntt_forward` on canonical inputs -/

theorem ntt_inverse_loop_unfold (a : Nat → Nat) :
    nttInverseLoop 10 falconN 1 a
      = gsStage (2 ^ 0) (2 ^ 8) (gsStage (2 ^ 1) (2 ^ 7) (gsStage (2 ^ 2) (2 ^ 6)
          (gsStage (2 ^ 3) (2 ^ 5) (gsStage (2 ^ 4) (2 ^ 4) (gsStage (2 ^ 5) (2 ^ 3)
            (gsStage (2 ^ 6) (2 ^ 2) (gsStage (2 ^ 7) (2 ^ 1)
              (gsStage (2 ^ 8) (2 ^ 0) a)))))))) := by
  simp only [nttInverseLoop, falconN, Nat.reduceMul, Nat.reduceDiv, Nat.reduceLT,
    Nat.reducePow, reduceIte]

theorem fwd_run_eq (a : Nat → Nat) : fwdRun 0 9 a = nttForwardLoop 10 1 falconN a := by
  rw [ntt_forward_loop_unfold]
  rfl

theorem inv_run_eq (a : Nat → Nat) : invRun 0 9 a = nttInverseLoop 10 falconN 1 a := by
  rw [ntt_inverse_loop_unfold]
  rfl

theorem ntt_inverse_loop_forward (a : Nat → Nat) (ha : ∀ y, a y < falconQ)
    (ha0 : ∀ y, falconN ≤ y → a y = 0) (x : Nat) :
    nttInverseLoop 10 falconN 1 (nttForwardLoop 10 1 falconN a) x = 512 * a x % falconQ := by
  rw [← fwd_run_eq, ← inv_run_eq]
  exact inv_run_fwd_run 9 0 rfl a ha ha0 x

theorem wire_of_ext : ∀ l1 l2 : List Nat, l1.length = l2.length →
    (∀ i, i < l1.length → wireOf l1 i = wireOf l2 i) → l1 = l2 := by
  intro l1
  induction l1 with
  | nil => intro l2 hlen _; cases l2 with
    | nil => rfl
    | cons y ys => simp at hlen
  | cons x xs ih =>
      intro l2 hlen h
      cases l2 with
      | nil => simp at hlen
      | cons y ys =>
          have hx : x = y := h 0 (by simp)
          have htail : xs = ys := by
            refine ih ys (by simp only [List.length_cons] at hlen; omega) ?_
            intro i hi
            exact h (i + 1) (by simp only [List.length_cons]; omega)
          rw [hx, htail]

theorem map_range_wire_of (l : List Nat) (n : Nat) (hlen : l.length = n) :
    (rangeList n).map (wireOf l) = l := by
  refine wire_of_ext _ _ (by simp only [List.length_map, range_list_length, hlen]) ?_
  intro i hi
  have hi' : i < n := by
    simp only [List.length_map, range_list_length] at hi
    exact hi
  rw [wire_of_map_range _ n i hi']

theorem wire_of_vanishes (l : List Nat) (hlen : l.length = falconN) (y : Nat) (hy : falconN ≤ y) :
    wireOf l y = 0 := wire_of_length l y (by omega)

theorem wire_of_ntt_forward (l : List Nat) (hlen : l.length = falconN) :
    wireOf (nttForward l) = nttForwardLoop 10 1 falconN (wireOf l) := by
  funext i
  rw [show nttForward l = (rangeList falconN).map (nttForwardLoop 10 1 falconN (wireOf l))
    from rfl]
  rcases Nat.lt_or_ge i falconN with hi | hi
  · exact wire_of_map_range _ falconN i hi
  · rw [wire_of_length _ i (by simp only [List.length_map, range_list_length]; exact hi),
      ← fwd_run_eq, fwd_run_fixed 9 0 rfl (wireOf l) i hi]
    exact (wire_of_vanishes l hlen i hi).symm

/-- The final `n^-1` scaling of :500-508 cancels the `512` the nine stage pairs accumulate.
Only the build-time assertion `n * n^-1 = 1` (:177) is used. -/
theorem n_inv_cancel (v : Nat) (hv : v < falconQ) :
    ntoNInv * (512 * v % falconQ) % falconQ = v := by
  have h3 : EqQ (ntoNInv * 512) 1 := by
    show ntoNInv * 512 % falconQ = 1 % falconQ
    rw [n_inv_pinned, one_mod_q]
  have h1 : EqQ (ntoNInv * (512 * v % falconQ)) (ntoNInv * (512 * v)) :=
    eq_q_mul_left _ (eq_q_mod _)
  have h2 : ntoNInv * (512 * v) = ntoNInv * 512 * v := (Nat.mul_assoc _ _ _).symm
  have h4 : EqQ (ntoNInv * 512 * v) (1 * v) := eq_q_mul h3 (eq_q_refl v)
  rw [Nat.one_mul] at h4
  rw [h2] at h1
  have hfin : EqQ (ntoNInv * (512 * v % falconQ)) v := eq_q_trans h1 h4
  show ntoNInv * (512 * v % falconQ) % falconQ = v
  rw [hfin, Nat.mod_eq_of_lt hv]

/-- `ntt_inverse (ntt_forward l) = l` for every canonical coefficient vector. -/
theorem ntt_inverse_forward (l : List Nat) (hlen : l.length = falconN)
    (hc : ∀ c ∈ l, c < falconQ) : nttInverse (nttForward l) = l := by
  have hcanon : ∀ y, wireOf l y < falconQ := wire_of_lt_q l hc
  rw [show nttInverse (nttForward l) = (rangeList falconN).map
      (fun i => ntoNInv * nttInverseLoop 10 falconN 1 (wireOf (nttForward l)) i % falconQ)
    from rfl]
  rw [map_range_list_congr (g := wireOf l) ?_]
  · exact map_range_wire_of l falconN hlen
  · intro j _
    rw [wire_of_ntt_forward l hlen,
      ntt_inverse_loop_forward (wireOf l) hcanon (wire_of_vanishes l hlen) j]
    exact n_inv_cancel _ (hcanon j)

/-! ## 12. Evaluation at the negacyclic points is a ring homomorphism -/

/-- The `Int` sum of `schoolbook_negacyclic`, re-indexed. -/
def intSumTo (f : Nat → Int) : Nat → Int
  | 0 => 0
  | n + 1 => intSumTo f n + f n

theorem int_sum_append (l : List Int) (x : Int) : intSum (l ++ [x]) = intSum l + x := by
  induction l with
  | nil => show x + intSum ([] : List Int) = intSum ([] : List Int) + x; omega
  | cons y ys ih => show y + intSum (ys ++ [x]) = (y + intSum ys) + x; rw [ih]; omega

theorem int_sum_map_range (f : Nat → Int) : ∀ n, intSum ((rangeList n).map f) = intSumTo f n := by
  intro n
  induction n with
  | zero => rw [range_list_zero]; rfl
  | succ n ih =>
      rw [range_list_succ, List.map_append]
      simp only [List.map_cons, List.map_nil]
      rw [int_sum_append, ih]
      rfl

theorem int_sum_to_sub (f g : Nat → Nat) : ∀ n,
    intSumTo (fun i => (f i : Int) - (g i : Int)) n = (sumTo f n : Int) - (sumTo g n : Int) := by
  intro n
  induction n with
  | zero => rfl
  | succ n ih =>
      show intSumTo (fun i => (f i : Int) - (g i : Int)) n + ((f n : Int) - (g n : Int)) = _
      rw [ih]
      simp only [sum_to_succ]
      omega

theorem int_sum_to_congr {f g : Nat → Int} {n : Nat} (h : ∀ i, i < n → f i = g i) :
    intSumTo f n = intSumTo g n := by
  induction n with
  | zero => rfl
  | succ n ih =>
      show intSumTo f n + f n = intSumTo g n + g n
      rw [ih (fun i hi => h i (Nat.lt_succ_of_lt hi)), h n (Nat.lt_succ_self n)]

/-- The positive (non-wrapping) part of the schoolbook convolution. -/
def convPos (wa wb : Nat → Nat) (k : Nat) : Nat :=
  sumTo (fun i => sumTo (fun j => if i + j = k then wa i * wb j else 0) falconN) falconN

/-- The wrapping part, which `X^512 = -1` negates. -/
def convNeg (wa wb : Nat → Nat) (k : Nat) : Nat :=
  sumTo (fun i => sumTo (fun j => if i + j = k + falconN then wa i * wb j else 0) falconN) falconN

theorem negacyclic_term_split (a b : List Nat) (k i j : Nat) :
    negacyclicTerm a b k i j
      = ((if i + j = k then wireOf a i * wireOf b j else 0 : Nat) : Int)
        - ((if i + j = k + falconN then wireOf a i * wireOf b j else 0 : Nat) : Int) := by
  simp only [negacyclicTerm]
  by_cases h1 : i + j = k
  · rw [if_pos h1, if_pos h1, if_neg (show ¬ (i + j = k + falconN) by simp only [falconN]; omega)]
    simp
  · rw [if_neg h1, if_neg h1]
    by_cases h2 : i + j = k + falconN
    · rw [if_pos h2, if_pos h2]
      simp
    · rw [if_neg h2, if_neg h2]
      simp

theorem negacyclic_coeff_split (a b : List Nat) (k : Nat) :
    negacyclicCoeff a b k
      = (convPos (wireOf a) (wireOf b) k : Int) - (convNeg (wireOf a) (wireOf b) k : Int) := by
  show intSum ((rangeList falconN).map
    (fun i => intSum ((rangeList falconN).map fun j => negacyclicTerm a b k i j))) = _
  rw [int_sum_map_range]
  have hinner : ∀ i, intSum ((rangeList falconN).map fun j => negacyclicTerm a b k i j)
      = ((sumTo (fun j => if i + j = k then wireOf a i * wireOf b j else 0) falconN : Nat) : Int)
        - ((sumTo (fun j => if i + j = k + falconN then wireOf a i * wireOf b j else 0)
            falconN : Nat) : Int) := by
    intro i
    rw [int_sum_map_range, int_sum_to_congr (g := fun j =>
      ((if i + j = k then wireOf a i * wireOf b j else 0 : Nat) : Int)
        - ((if i + j = k + falconN then wireOf a i * wireOf b j else 0 : Nat) : Int))
      (fun j _ => negacyclic_term_split a b k i j)]
    exact int_sum_to_sub _ _ falconN
  rw [int_sum_to_congr (fun i _ => hinner i), int_sum_to_sub]
  simp only [convPos, convNeg]

theorem emod_to_nat_sub (x y : Nat) :
    (((x : Int) - (y : Int)).emod (falconQ : Int)).toNat = (x + (falconQ - 1) * y) % falconQ := by
  have hz : ((x + (falconQ - 1) * y : Nat) : Int)
      = ((x : Int) - (y : Int)) + (falconQ : Int) * (y : Int) := by
    simp only [falconQ]
    omega
  have h1 : ((x : Int) - (y : Int) + (falconQ : Int) * (y : Int)) % (falconQ : Int)
      = ((x : Int) - (y : Int)) % (falconQ : Int) := Int.add_mul_emod_self_left _ _ _
  show (((x : Int) - (y : Int)) % (falconQ : Int)).toNat = _
  rw [← h1, ← hz, ← Int.ofNat_emod]
  generalize (x + (falconQ - 1) * y) % falconQ = z
  omega

theorem sum_to_ind (X c k0 n : Nat) :
    sumTo (fun k => (if k0 = k then X else 0) * c ^ k) n = if k0 < n then X * c ^ k0 else 0 := by
  by_cases h : k0 < n
  · rw [if_pos h, sum_to_single h
      (fun i _ hne => by rw [if_neg (fun hh => hne hh.symm), Nat.zero_mul]), if_pos rfl]
  · rw [if_neg h, sum_to_zero_fun (fun i hi => by rw [if_neg (by omega), Nat.zero_mul])]

theorem sum_to_ind_shift (X c m n : Nat) (hm : m < 2 * n) :
    sumTo (fun k => (if m = k + n then X else 0) * c ^ k) n
      = if n ≤ m then X * c ^ (m - n) else 0 := by
  by_cases h : n ≤ m
  · rw [if_pos h, sum_to_single (show m - n < n by omega)
      (fun i _ hne => by rw [if_neg (by omega), Nat.zero_mul]), if_pos (by omega)]
  · rw [if_neg h, sum_to_zero_fun (fun i _ => by rw [if_neg (by omega), Nat.zero_mul])]

theorem eval_conv_pos (wa wb : Nat → Nat) (c : Nat) :
    sumTo (fun k => convPos wa wb k * c ^ k) falconN
      = sumTo (fun i => sumTo (fun j =>
          if i + j < falconN then wa i * wb j * c ^ (i + j) else 0) falconN) falconN := by
  have e1 : ∀ k, convPos wa wb k * c ^ k
      = sumTo (fun i => sumTo (fun j =>
          (if i + j = k then wa i * wb j else 0) * c ^ k) falconN) falconN := by
    intro k
    rw [convPos, ← sum_to_mul_right]
    exact sum_to_congr (fun i _ => (sum_to_mul_right _ _ _).symm)
  rw [sum_to_congr (fun k _ => e1 k),
    sum_to_swap (fun k i => sumTo (fun j =>
      (if i + j = k then wa i * wb j else 0) * c ^ k) falconN) falconN falconN]
  refine sum_to_congr (fun i _ => ?_)
  rw [sum_to_swap (fun k j => (if i + j = k then wa i * wb j else 0) * c ^ k) falconN falconN]
  exact sum_to_congr (fun j _ => sum_to_ind (wa i * wb j) c (i + j) falconN)

theorem eval_conv_neg (wa wb : Nat → Nat) (c : Nat) :
    sumTo (fun k => convNeg wa wb k * c ^ k) falconN
      = sumTo (fun i => sumTo (fun j =>
          if falconN ≤ i + j then wa i * wb j * c ^ (i + j - falconN) else 0) falconN)
          falconN := by
  have e1 : ∀ k, convNeg wa wb k * c ^ k
      = sumTo (fun i => sumTo (fun j =>
          (if i + j = k + falconN then wa i * wb j else 0) * c ^ k) falconN) falconN := by
    intro k
    rw [convNeg, ← sum_to_mul_right]
    exact sum_to_congr (fun i _ => (sum_to_mul_right _ _ _).symm)
  rw [sum_to_congr (fun k _ => e1 k),
    sum_to_swap (fun k i => sumTo (fun j =>
      (if i + j = k + falconN then wa i * wb j else 0) * c ^ k) falconN) falconN falconN]
  refine sum_to_congr (fun i hi => ?_)
  rw [sum_to_swap (fun k j => (if i + j = k + falconN then wa i * wb j else 0) * c ^ k)
    falconN falconN]
  exact sum_to_congr (fun j hj =>
    sum_to_ind_shift (wa i * wb j) c (i + j) falconN (by omega))

theorem eval_mul_expand (wa wb : Nat → Nat) (c : Nat) :
    evalAt wa c * evalAt wb c
      = sumTo (fun i => sumTo (fun j => wa i * wb j * c ^ (i + j)) falconN) falconN := by
  show sumTo (fun i => wa i * c ^ i) falconN * sumTo (fun j => wb j * c ^ j) falconN = _
  rw [← sum_to_mul_right]
  refine sum_to_congr (fun i _ => ?_)
  rw [← sum_to_mul_left]
  refine sum_to_congr (fun j _ => ?_)
  rw [Nat.pow_add]
  simp only [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm]

theorem eval_conv (wa wb : Nat → Nat) (c : Nat) (hc : EqQ (c ^ falconN) (falconQ - 1)) :
    EqQ (sumTo (fun k => (convPos wa wb k + (falconQ - 1) * convNeg wa wb k) * c ^ k) falconN)
        (evalAt wa c * evalAt wb c) := by
  have hsplit : sumTo (fun k => (convPos wa wb k + (falconQ - 1) * convNeg wa wb k) * c ^ k)
      falconN = sumTo (fun k => convPos wa wb k * c ^ k) falconN
        + (falconQ - 1) * sumTo (fun k => convNeg wa wb k * c ^ k) falconN := by
    rw [← sum_to_mul_left, ← sum_to_add]
    refine sum_to_congr (fun k _ => ?_)
    rw [Nat.right_distrib, Nat.mul_assoc]
  rw [hsplit, eval_conv_pos, eval_conv_neg, eval_mul_expand]
  rw [← sum_to_mul_left, ← sum_to_add]
  refine sum_to_eq_q_congr (fun i hi => ?_)
  rw [← sum_to_mul_left, ← sum_to_add]
  refine sum_to_eq_q_congr (fun j hj => ?_)
  by_cases hij : i + j < falconN
  · rw [if_pos hij, if_neg (by omega), Nat.mul_zero, Nat.add_zero]
    exact eq_q_refl _
  · rw [if_neg hij, if_pos (by omega), Nat.zero_add]
    have hpow : c ^ (i + j) = c ^ (i + j - falconN) * c ^ falconN := by
      rw [← Nat.pow_add]
      congr 1
      omega
    rw [hpow, ← Nat.mul_assoc]
    have hstep : EqQ ((falconQ - 1) * (wa i * wb j * c ^ (i + j - falconN)))
        (wa i * wb j * c ^ (i + j - falconN) * (falconQ - 1)) := by
      rw [Nat.mul_comm]
      exact eq_q_refl _
    refine eq_q_trans hstep ?_
    exact eq_q_mul_left _ (eq_q_symm hc)

theorem eval_point_pow (k : Nat) : EqQ ((powQ ntoPsi (1 + 2 * k)) ^ falconN) (falconQ - 1) := by
  have h1 : EqQ ((powQ ntoPsi (1 + 2 * k)) ^ falconN) ((ntoPsi ^ (1 + 2 * k)) ^ falconN) :=
    eq_q_pow (pow_q_eq_q _ _) falconN
  have h2 : (ntoPsi ^ (1 + 2 * k)) ^ falconN = ntoPsi ^ 512 * (ntoPsi ^ 1024) ^ k := by
    rw [← Nat.pow_mul, ← Nat.pow_mul, ← Nat.pow_add]
    congr 1
    simp only [falconN]
    omega
  rw [h2] at h1
  refine eq_q_trans h1 ?_
  refine eq_q_trans (eq_q_mul psi_pow_half (eq_q_pow psi_pow_order k)) ?_
  rw [Nat.one_pow, Nat.mul_one]
  exact eq_q_refl _

/-- Evaluation at `psi^(2k+1)` carries the negacyclic product to the pointwise product. -/
theorem eval_negacyclic_product (a b : List Nat) (k : Nat) :
    EqQ (evalAt (wireOf (negacyclicProduct a b)) (powQ ntoPsi (1 + 2 * k)))
        (evalAt (wireOf a) (powQ ntoPsi (1 + 2 * k))
          * evalAt (wireOf b) (powQ ntoPsi (1 + 2 * k))) := by
  have hcoef : ∀ d, d < falconN → wireOf (negacyclicProduct a b) d
      = (convPos (wireOf a) (wireOf b) d + (falconQ - 1) * convNeg (wireOf a) (wireOf b) d)
        % falconQ := by
    intro d hd
    rw [show negacyclicProduct a b = (rangeList falconN).map
        (fun k => ((negacyclicCoeff a b k).emod (falconQ : Int)).toNat) from rfl,
      wire_of_map_range _ falconN d hd, negacyclic_coeff_split, emod_to_nat_sub]
  have hstep : EqQ (evalAt (wireOf (negacyclicProduct a b)) (powQ ntoPsi (1 + 2 * k)))
      (sumTo (fun d => (convPos (wireOf a) (wireOf b) d
        + (falconQ - 1) * convNeg (wireOf a) (wireOf b) d)
        * powQ ntoPsi (1 + 2 * k) ^ d) falconN) := by
    refine sum_to_eq_q_congr (fun d hd => ?_)
    rw [hcoef d hd]
    exact eq_q_mul (eq_q_mod _) (eq_q_refl _)
  exact eq_q_trans hstep (eval_conv _ _ _ (eval_point_pow k))

end Zkp.Implementation.NttCorrectness
