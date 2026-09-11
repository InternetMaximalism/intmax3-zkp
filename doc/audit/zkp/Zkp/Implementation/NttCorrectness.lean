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

end Zkp.Implementation.NttCorrectness
