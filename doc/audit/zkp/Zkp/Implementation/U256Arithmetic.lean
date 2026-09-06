import Std

/-!
# Current U256 target carry/borrow composition

Source: src/ethereum_types/u256.rs, specifically target add/sub lines 276–331.
This manual translation follows reverse/zip, initial zero, one per-limb gadget,
final zero connection and reversal. It does not translate the imported u32
gate evaluator, field lifting, Rust signed shifts/casts, or EVM arithmetic.
The native implementations and other conversions stay explicit unmapped work.

AddTrace/SubTrace are the local u32 gadget contracts after field lowering,
NOT assumed whole-U256 no-wrap results. The full-width exact arithmetic is
derived by induction, for every finite limb sequence, including carries and
borrows between nonadjacent significant digits. A future gate refinement must
establish those local equations and canonical limb bounds for actual wires.
-/

namespace Zkp.Implementation.U256Arithmetic

def wordBase : Nat := 2 ^ 32
def limbCount : Nat := 8

theorem u256_width_is_exact : wordBase ^ limbCount = 2 ^ 256 := by decide

def valueLE (base : Nat) : List Nat → Nat
  | [] => 0
  | d :: ds => d + base * valueLE base ds

def valueBE (words : List Nat) : Nat := valueLE wordBase words.reverse

def Checked (base : Nat) (words : List Nat) : Prop := ∀ d ∈ words, d < base

inductive AddTrace (base : Nat) : List Nat → List Nat → List Nat → Nat → Nat → Prop
  | nil (carry : Nat) : AddTrace base [] [] [] carry carry
  | cons {a b r input next final : Nat} {as bs rs : List Nat}
      (limb : a + b + input = r + base * next)
      (tail : AddTrace base as bs rs next final) :
      AddTrace base (a :: as) (b :: bs) (r :: rs) input final

inductive SubTrace (base : Nat) : List Nat → List Nat → List Nat → Nat → Nat → Prop
  | nil (borrow : Nat) : SubTrace base [] [] [] borrow borrow
  | cons {a b r input next final : Nat} {as bs rs : List Nat}
      (limb : a + base * next = b + input + r)
      (tail : SubTrace base as bs rs next final) :
      SubTrace base (a :: as) (b :: bs) (r :: rs) input final

theorem add_trace_widths {base input final : Nat} {a b r : List Nat}
    (h : AddTrace base a b r input final) : a.length = b.length ∧ a.length = r.length := by
  induction h with
  | nil => exact ⟨rfl, rfl⟩
  | cons limb tail ih => simpa only [List.length_cons, Nat.add_right_cancel_iff] using ih

theorem sub_trace_widths {base input final : Nat} {a b r : List Nat}
    (h : SubTrace base a b r input final) : a.length = b.length ∧ a.length = r.length := by
  induction h with
  | nil => exact ⟨rfl, rfl⟩
  | cons limb tail ih => simpa only [List.length_cons, Nat.add_right_cancel_iff] using ih

theorem add_trace_integer_equation {base input final : Nat} {a b r : List Nat}
    (h : AddTrace base a b r input final) :
    valueLE base a + valueLE base b + input =
      valueLE base r + base ^ a.length * final := by
  induction h with
  | nil => simp [valueLE]
  | @cons a b r input next final as bs rs limb _tail ih =>
      have scaled := congrArg (fun n => base * n) ih
      simp only [Nat.mul_add] at scaled
      simp only [valueLE, List.length_cons, Nat.pow_succ]
      have reassoc : base * (base ^ as.length * final) =
          base ^ as.length * base * final := by simp [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm]
      rw [reassoc] at scaled
      omega

theorem sub_trace_integer_equation {base input final : Nat} {a b r : List Nat}
    (h : SubTrace base a b r input final) :
    valueLE base a + base ^ a.length * final =
      valueLE base b + input + valueLE base r := by
  induction h with
  | nil => simp [valueLE]
  | @cons a b r input next final as bs rs limb _tail ih =>
      have scaled := congrArg (fun n => base * n) ih
      simp only [Nat.mul_add] at scaled
      simp only [valueLE, List.length_cons, Nat.pow_succ]
      have reassoc : base * (base ^ as.length * final) =
          base ^ as.length * base * final := by simp [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm]
      rw [reassoc] at scaled
      omega

theorem checked_value_is_bounded {base : Nat} {words : List Nat}
    (h : Checked base words) : valueLE base words < base ^ words.length := by
  induction words with
  | nil => simp [valueLE]
  | cons d ds ih =>
      have hd := h d (by simp)
      have ht : Checked base ds := by intro x hx; exact h x (by simp [hx])
      have bound := ih ht
      have scaled := Nat.mul_le_mul_left base (Nat.succ_le_of_lt bound)
      simp only [Nat.mul_succ] at scaled
      simp only [valueLE, List.length_cons, Nat.pow_succ]
      rw [Nat.mul_comm (base ^ ds.length) base]
      omega

structure TargetShape (a b r : List Nat) : Prop where
  leftWidth : a.length = limbCount
  rightWidth : b.length = limbCount
  resultWidth : r.length = limbCount

/-- Source U256Target::add final connect_u32(carry, zero) is essential. -/
def AddGates (a b r : List Nat) : Prop :=
  TargetShape a b r ∧ AddTrace wordBase a.reverse b.reverse r.reverse 0 0

/-- Source U256Target::sub final connect_u32(borrow, zero) is essential. -/
def SubGates (a b r : List Nat) : Prop :=
  TargetShape a b r ∧ SubTrace wordBase a.reverse b.reverse r.reverse 0 0

theorem target_add_is_exact {a b r : List Nat} (h : AddGates a b r) :
    valueBE a + valueBE b = valueBE r := by
  simpa [valueBE] using add_trace_integer_equation h.2

theorem target_sub_is_exact {a b r : List Nat} (h : SubGates a b r) :
    valueBE a = valueBE b + valueBE r := by
  simpa [valueBE] using sub_trace_integer_equation h.2

theorem target_sub_cannot_underflow {a b r : List Nat} (h : SubGates a b r) :
    valueBE b ≤ valueBE a := by have := target_sub_is_exact h; omega

theorem target_sub_result_is_difference {a b r : List Nat} (h : SubGates a b r) :
    valueBE r = valueBE a - valueBE b := by have := target_sub_is_exact h; omega

theorem target_add_cannot_wrap {a b r : List Nat} (h : AddGates a b r)
    (checked : Checked wordBase r.reverse) :
    valueBE a + valueBE b < wordBase ^ limbCount := by
  rw [target_add_is_exact h]
  have bound := checked_value_is_bounded checked
  simpa [valueBE, h.1.resultWidth] using bound

theorem target_sub_does_not_increase_balance {a b r : List Nat} (h : SubGates a b r) :
    valueBE r ≤ valueBE a := by have := target_sub_is_exact h; omega

theorem target_add_committed_result_is_unique {a b r s : List Nat}
    (hr : AddGates a b r) (hs : AddGates a b s) : valueBE r = valueBE s := by
  rw [← target_add_is_exact hr, ← target_add_is_exact hs]

theorem target_sub_committed_result_is_unique {a b r s : List Nat}
    (hr : SubGates a b r) (hs : SubGates a b s) : valueBE r = valueBE s := by
  have := target_sub_is_exact hr
  have := target_sub_is_exact hs
  omega

inductive BuildOp where
  | zeroU32
  | addManyU32 (sourceIndex : Nat)
  | subU32 (sourceIndex : Nat)
  | connectFinalToZero
  | reverseResults
  deriving DecidableEq, Repr

def addProgram : List BuildOp := [.zeroU32] ++
  (List.range limbCount).reverse.map BuildOp.addManyU32 ++
  [.connectFinalToZero, .reverseResults]

def subProgram : List BuildOp := [.zeroU32] ++
  (List.range limbCount).reverse.map BuildOp.subU32 ++
  [.connectFinalToZero, .reverseResults]

theorem add_visits_every_limb_in_reverse : addProgram =
    [.zeroU32, .addManyU32 7, .addManyU32 6, .addManyU32 5, .addManyU32 4,
     .addManyU32 3, .addManyU32 2, .addManyU32 1, .addManyU32 0,
     .connectFinalToZero, .reverseResults] := by decide

theorem sub_visits_every_limb_in_reverse : subProgram =
    [.zeroU32, .subU32 7, .subU32 6, .subU32 5, .subU32 4,
     .subU32 3, .subU32 2, .subU32 1, .subU32 0,
     .connectFinalToZero, .reverseResults] := by decide

/-- Mathematical normal-flow witnesses, not native proof-generation tests. -/
theorem normal_add_with_inter_limb_carry :
    AddTrace 10 [9, 0] [1, 0] [0, 1] 0 0 := by
  exact .cons (next := 1) (by decide) (.cons (next := 0) (by decide) (.nil 0))

theorem normal_sub_with_inter_limb_borrow :
    SubTrace 10 [0, 1] [1, 0] [9, 0] 0 0 := by
  exact .cons (next := 1) (by decide) (.cons (next := 0) (by decide) (.nil 0))

theorem normal_u256_add :
    AddGates [0,0,0,0,0,0,0,7] [0,0,0,0,0,0,0,2] [0,0,0,0,0,0,0,9] := by
  refine ⟨⟨rfl, rfl, rfl⟩, ?_⟩
  apply AddTrace.cons (next := 0) (by decide)
  repeat' apply AddTrace.cons (next := 0) (by decide)
  exact AddTrace.nil 0

theorem normal_u256_sub :
    SubGates [0,0,0,0,0,0,0,9] [0,0,0,0,0,0,0,2] [0,0,0,0,0,0,0,7] := by
  refine ⟨⟨rfl, rfl, rfl⟩, ?_⟩
  apply SubTrace.cons (next := 0) (by decide)
  repeat' apply SubTrace.cons (next := 0) (by decide)
  exact SubTrace.nil 0

end Zkp.Implementation.U256Arithmetic
